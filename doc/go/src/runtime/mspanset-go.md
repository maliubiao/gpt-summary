Response:
Let's break down the thought process for analyzing the provided Go code for `mspanset.go`.

1. **Initial Scan and Identification of Key Data Structures:**

   - The first thing I look for is the primary data structure being defined. Here, it's `spanSet`. I note its core components: `spineLock`, `spine`, `spineLen`, `spineCap`, and `index`.
   - I also identify related structs like `spanSetBlock` and the constants `spanSetBlockEntries` and `spanSetInitSpineCap`. These likely define the internal organization.

2. **Understanding the Core Purpose (High-Level):**

   - The comment "// A spanSet is a set of *mspans." is the crucial starting point. This tells me the code is about managing a collection of `mspan` pointers.
   - The comment "// spanSet is safe for concurrent push and pop operations." immediately highlights the importance of concurrency control.

3. **Deconstructing the `spanSet` Structure:**

   - **`spine` and Related Fields:** The comments describe a "two-level data structure" with a "growable spine" and "fixed-sized blocks." This suggests a design similar to a dynamic array of arrays.
     - `spine`: Likely stores pointers to the `spanSetBlock`s. The type `atomicSpanSetSpinePointer` indicates atomic operations on this spine.
     - `spineLen`: Tracks the current length of the spine.
     - `spineCap`: Tracks the capacity of the spine.
     - `spineLock`:  Clearly used to protect the spine during growth or block addition.
   - **`index`:** The comment explains `index` as the "head and tail" of the set, using a single 64-bit field (`atomicHeadTailIndex`). This immediately suggests a queue-like structure. The comment about the 32-bit width limiting pushes is a crucial detail.

4. **Analyzing Key Functions:**

   - **`push(s *mspan)`:**  This function adds an `mspan` to the set.
     - The use of `b.index.incTail()` to get a "cursor" is a strong indicator of the queue implementation.
     - The logic for adding a new block when `top >= spineLen` and the spine growth mechanism is important to understand the dynamic nature of the `spanSet`. The locking around spine modifications is expected for concurrency safety.
     - The final `block.spans[bottom].StoreNoWB(s)` shows where the actual `mspan` is stored within a block. The `NoWB` suffix implies "No Write Barrier," a performance optimization related to garbage collection.
   - **`pop() *mspan`:** This function removes an `mspan` from the set.
     - The `claimLoop` with `b.index.cas()` (Compare And Swap) is a standard pattern for implementing concurrent queues/stacks.
     - The checks for `spineLen` ensure that we don't try to access blocks that haven't been allocated yet, especially during concurrent spine growth.
     - The logic for incrementing `block.popped` and freeing blocks back to `spanSetBlockPool` is important for memory management and reuse.
   - **`reset()`:** This function is for clearing the set when it's empty. The checks for emptiness and the logic for potentially freeing the last block used are crucial for correctness. The comments about potential errors if the set isn't empty highlight important usage constraints.

5. **Identifying Related Types and Mechanisms:**

   - **`spanSetBlock`:**  This structure holds a fixed-size array of `mspan` pointers (`spans`). The `popped` counter is directly related to the block recycling mechanism in `pop`. The `lfnode` suggests its use in a lock-free stack, which is later confirmed by `spanSetBlockPool`.
   - **`spanSetBlockPool`:** This confirms the suspicion that `spanSetBlock`s are managed in a pool for efficiency. The `alloc()` and `free()` methods are standard for such pools.
   - **`atomicHeadTailIndex`:**  Understanding how the head and tail are packed into a single 64-bit value is crucial for understanding the queue implementation. The `incTail()` function's overflow check is also noteworthy.
   - **Atomic Operations:** The pervasive use of `atomic.Uintptr`, `atomic.Uint32`, `atomic.Uint64`, and `atomic.UnsafePointer` underscores the concurrency-safe nature of the `spanSet`.

6. **Inferring Go Functionality:**

   - The presence of `mspan` strongly suggests this code is part of the Go runtime's memory management. `mspan`s are fundamental units of memory allocation in Go.
   - The concurrent push and pop operations suggest this `spanSet` is used in a scenario where multiple goroutines need to access and manage `mspan`s. A potential use case is tracking available or in-use spans.

7. **Crafting the Example:**

   - Based on the inference that this is used for memory management, the example I'd create would focus on the allocation and deallocation of `mspan`s. Since we don't have direct access to the internal `mspan` creation, a simplified example demonstrating the `push` and `pop` operations on a conceptually similar data structure would be appropriate. This helps illustrate the core functionality even without knowing the exact internal details of `mspan` creation.

8. **Considering Potential Mistakes:**

   - The `reset()` function's requirement for an empty set is a key point where users could make mistakes. Calling `reset()` on a non-empty set would lead to a panic.

9. **Review and Refinement:**

   - After drafting the explanation, I would review it to ensure clarity, accuracy, and completeness. I'd check if the example code effectively illustrates the functionality and if the explanation of potential errors is clear. I'd also confirm that all parts of the prompt have been addressed.

This systematic approach, starting with high-level understanding and gradually drilling down into details, is effective for analyzing complex code like this. Recognizing common patterns (like concurrent queues, memory pools, and atomic operations) significantly speeds up the comprehension process.
这段代码是 Go 语言运行时环境 (`runtime`) 中 `mspanset.go` 文件的一部分，它实现了一个用于存储和管理 `mspan` 结构体指针的并发安全集合，名为 `spanSet`。

**`spanSet` 的功能：**

1. **存储 `mspan` 指针:** `spanSet` 的主要目的是存储指向 `mspan` 结构体的指针。`mspan` 是 Go 内存管理中的核心概念，代表一段连续的内存页。

2. **并发安全地 Push 和 Pop 操作:**  `spanSet` 被设计为支持并发的 `push`（添加）和 `pop`（移除）操作，允许多个 goroutine 同时安全地访问和修改集合中的 `mspan` 指针。

3. **两级数据结构:** 为了高效地处理大量的 `mspan`，`spanSet` 使用了两级数据结构：
   - **Spine (脊柱):**  一个可增长的数组，存储指向 `spanSetBlock` 的指针。Spine 的访问是无锁的，但添加块或增长 Spine 需要获取 `spineLock`。
   - **Blocks (块):** 固定大小的 `spanSetBlock` 数组，实际存储 `mspan` 指针。这些 Block 从一个池中分配。

4. **高效的并发控制:**  使用了原子操作 (`atomic` 包) 和锁 (`mutex`) 来保证并发安全，尽量减少锁的竞争。

5. **内存管理优化:**  Spine 和 Block 的内存分配在堆外 (`off-heap`)，避免了写屏障的需求，并允许在内存管理器中使用。Block 被放入一个池中进行复用，而不是释放回操作系统。

6. **头尾索引 (`index`):** 使用一个原子 `headTailIndex` 字段来跟踪集合的头部和尾部，用于 `push` 和 `pop` 操作。这是一个优化的无锁队列实现的一部分。

7. **重置操作 (`reset`):**  提供了一个 `reset` 方法，用于在 `spanSet` 为空时将其重置，并清理遗留的 Block。

**`spanSet` 是 Go 语言内存管理功能的实现：**

`spanSet` 很可能是 Go 运行时环境用来跟踪和管理不同状态的 `mspan` 的一个重要组件。 例如，它可以用于：

* **空闲 `mspan` 列表:**  跟踪可用于分配的空闲 `mspan`。
* **特定大小类的 `mspan` 列表:**  根据大小类组织 `mspan`，以便快速找到合适大小的内存块。
* **垃圾回收相关的 `mspan` 跟踪:**  在垃圾回收过程中跟踪正在使用的 `mspan`。

**Go 代码举例说明 (假设场景：跟踪空闲 `mspan`)：**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// 假设的 mspan 结构体 (简化版)
type mspan struct {
	start uintptr
	npages uintptr
}

func main() {
	// 获取 runtime.spanSet (假设我们可以访问)
	// 在实际的 Go 代码中，你无法直接访问 runtime 包的私有成员
	// 这里只是为了演示 spanSet 的使用概念
	var freeSpans *runtime.SpanSet // 假设这是跟踪空闲 mspan 的 spanSet

	// 初始化 spanSet (在实际 runtime 中会有初始化过程)
	freeSpans = new(runtime.SpanSet)

	// 创建一些模拟的 mspan
	span1 := &mspan{start: 0x1000, npages: 1}
	span2 := &mspan{start: 0x2000, npages: 2}
	span3 := &mspan{start: 0x3000, npages: 1}

	// 使用多个 goroutine 并发地添加 mspan
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		freeSpans.Push(unsafe.Pointer(span1))
		wg.Done()
	}()
	go func() {
		freeSpans.Push(unsafe.Pointer(span2))
		wg.Done()
	}()
	go func() {
		freeSpans.Push(unsafe.Pointer(span3))
		wg.Done()
	}()
	wg.Wait()

	fmt.Println("添加 mspan 完成")

	// 并发地取出 mspan
	var retrievedSpans []*mspan
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			if s := freeSpans.Pop(); s != nil {
				retrievedSpans = append(retrievedSpans, (*mspan)(s))
			}
			wg.Done()
		}()
	}
	wg.Wait()

	fmt.Println("取出的 mspan:")
	for _, s := range retrievedSpans {
		fmt.Printf("Start: 0x%x, Pages: %d\n", s.start, s.npages)
	}

	// 清理 spanSet (假设在合适的时机)
	if freeSpans.Empty() {
		freeSpans.Reset()
		fmt.Println("spanSet 已重置")
	}
}

// 为了演示，需要添加 runtime.SpanSet 的简化定义
// 注意：这与实际 runtime 中的定义可能不完全一致
type SpanSet struct {
	index runtime.HeadTailIndex
	// ... 其他字段
}

func (b *SpanSet) Push(s unsafe.Pointer) {
	// ... 简化的 push 实现 ...
}

func (b *SpanSet) Pop() unsafe.Pointer {
	// ... 简化的 pop 实现 ...
	return nil
}

func (b *SpanSet) Empty() bool {
	head, tail := b.index.Split()
	return head >= tail
}

func (b *SpanSet) Reset() {
	// ... 简化的 reset 实现 ...
}

// 假设的 HeadTailIndex 结构体
type HeadTailIndex struct {
	u uint64
}

func (h HeadTailIndex) Split() (head uint32, tail uint32) {
	return uint32(h.u >> 32), uint32(h.u)
}
```

**假设的输入与输出：**

在上面的例子中，假设我们有三个 `mspan` (`span1`, `span2`, `span3`) 需要添加到 `freeSpans` 这个 `spanSet` 中。

**输入:** 三个 `*mspan` 类型的指针。

**输出:**  在 `pop` 操作后，`retrievedSpans` 可能会包含这三个 `mspan` 指针，但顺序不确定，因为 `pop` 操作是并发的。例如，可能的输出是：

```
添加 mspan 完成
取出的 mspan:
Start: 0x1000, Pages: 1
Start: 0x2000, Pages: 2
Start: 0x3000, Pages: 1
spanSet 已重置
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。 `spanSet` 是 Go 运行时环境内部使用的数据结构，它的行为由 Go 运行时的内存管理策略决定，而不是通过命令行参数配置。

**使用者易犯错的点：**

由于 `spanSet` 是 Go 运行时内部的实现细节，普通 Go 开发者不会直接使用它。 然而，如果开发者试图理解或修改 Go 运行时的相关代码，可能会犯以下错误：

1. **在非空时调用 `reset()`:** `reset()` 方法的注释明确指出，只能在 `spanSet` 为空时调用。 如果在 `spanSet` 中还有 `mspan` 没有被 `pop` 出来就调用 `reset()`，会导致 panic。

   ```go
   // 假设 freeSpans 不是空的
   // ... 添加了一些 mspan 到 freeSpans ...

   // 错误的做法
   // freeSpans.reset() // 会导致 panic
   ```

   **错误信息:** `attempt to clear non-empty span set`

2. **并发安全理解不足:**  虽然 `spanSet` 被设计为并发安全，但在使用涉及 `spanSet` 的更高级别的内存管理机制时，仍然需要理解其并发特性，避免出现竞态条件或其他并发问题。 这通常不是直接操作 `spanSet` 引起的，而是与围绕它的其他运行时机制的交互有关。

总而言之，`go/src/runtime/mspanset.go` 中的 `spanSet` 是 Go 运行时环境用于高效、并发安全地管理内存段 (`mspan`) 的一个关键数据结构，为 Go 语言的内存管理功能提供了基础支持。 普通 Go 开发者不需要直接操作它，但理解其原理有助于深入理解 Go 的内存管理机制。

Prompt: 
```
这是路径为go/src/runtime/mspanset.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/cpu"
	"internal/goarch"
	"internal/runtime/atomic"
	"unsafe"
)

// A spanSet is a set of *mspans.
//
// spanSet is safe for concurrent push and pop operations.
type spanSet struct {
	// A spanSet is a two-level data structure consisting of a
	// growable spine that points to fixed-sized blocks. The spine
	// can be accessed without locks, but adding a block or
	// growing it requires taking the spine lock.
	//
	// Because each mspan covers at least 8K of heap and takes at
	// most 8 bytes in the spanSet, the growth of the spine is
	// quite limited.
	//
	// The spine and all blocks are allocated off-heap, which
	// allows this to be used in the memory manager and avoids the
	// need for write barriers on all of these. spanSetBlocks are
	// managed in a pool, though never freed back to the operating
	// system. We never release spine memory because there could be
	// concurrent lock-free access and we're likely to reuse it
	// anyway. (In principle, we could do this during STW.)

	spineLock mutex
	spine     atomicSpanSetSpinePointer // *[N]atomic.Pointer[spanSetBlock]
	spineLen  atomic.Uintptr            // Spine array length
	spineCap  uintptr                   // Spine array cap, accessed under spineLock

	// index is the head and tail of the spanSet in a single field.
	// The head and the tail both represent an index into the logical
	// concatenation of all blocks, with the head always behind or
	// equal to the tail (indicating an empty set). This field is
	// always accessed atomically.
	//
	// The head and the tail are only 32 bits wide, which means we
	// can only support up to 2^32 pushes before a reset. If every
	// span in the heap were stored in this set, and each span were
	// the minimum size (1 runtime page, 8 KiB), then roughly the
	// smallest heap which would be unrepresentable is 32 TiB in size.
	index atomicHeadTailIndex
}

const (
	spanSetBlockEntries = 512 // 4KB on 64-bit
	spanSetInitSpineCap = 256 // Enough for 1GB heap on 64-bit
)

type spanSetBlock struct {
	// Free spanSetBlocks are managed via a lock-free stack.
	lfnode

	// popped is the number of pop operations that have occurred on
	// this block. This number is used to help determine when a block
	// may be safely recycled.
	popped atomic.Uint32

	// spans is the set of spans in this block.
	spans [spanSetBlockEntries]atomicMSpanPointer
}

// push adds span s to buffer b. push is safe to call concurrently
// with other push and pop operations.
func (b *spanSet) push(s *mspan) {
	// Obtain our slot.
	cursor := uintptr(b.index.incTail().tail() - 1)
	top, bottom := cursor/spanSetBlockEntries, cursor%spanSetBlockEntries

	// Do we need to add a block?
	spineLen := b.spineLen.Load()
	var block *spanSetBlock
retry:
	if top < spineLen {
		block = b.spine.Load().lookup(top).Load()
	} else {
		// Add a new block to the spine, potentially growing
		// the spine.
		lock(&b.spineLock)
		// spineLen cannot change until we release the lock,
		// but may have changed while we were waiting.
		spineLen = b.spineLen.Load()
		if top < spineLen {
			unlock(&b.spineLock)
			goto retry
		}

		spine := b.spine.Load()
		if spineLen == b.spineCap {
			// Grow the spine.
			newCap := b.spineCap * 2
			if newCap == 0 {
				newCap = spanSetInitSpineCap
			}
			newSpine := persistentalloc(newCap*goarch.PtrSize, cpu.CacheLineSize, &memstats.gcMiscSys)
			if b.spineCap != 0 {
				// Blocks are allocated off-heap, so
				// no write barriers.
				memmove(newSpine, spine.p, b.spineCap*goarch.PtrSize)
			}
			spine = spanSetSpinePointer{newSpine}

			// Spine is allocated off-heap, so no write barrier.
			b.spine.StoreNoWB(spine)
			b.spineCap = newCap
			// We can't immediately free the old spine
			// since a concurrent push with a lower index
			// could still be reading from it. We let it
			// leak because even a 1TB heap would waste
			// less than 2MB of memory on old spines. If
			// this is a problem, we could free old spines
			// during STW.
		}

		// Allocate a new block from the pool.
		block = spanSetBlockPool.alloc()

		// Add it to the spine.
		// Blocks are allocated off-heap, so no write barrier.
		spine.lookup(top).StoreNoWB(block)
		b.spineLen.Store(spineLen + 1)
		unlock(&b.spineLock)
	}

	// We have a block. Insert the span atomically, since there may be
	// concurrent readers via the block API.
	block.spans[bottom].StoreNoWB(s)
}

// pop removes and returns a span from buffer b, or nil if b is empty.
// pop is safe to call concurrently with other pop and push operations.
func (b *spanSet) pop() *mspan {
	var head, tail uint32
claimLoop:
	for {
		headtail := b.index.load()
		head, tail = headtail.split()
		if head >= tail {
			// The buf is empty, as far as we can tell.
			return nil
		}
		// Check if the head position we want to claim is actually
		// backed by a block.
		spineLen := b.spineLen.Load()
		if spineLen <= uintptr(head)/spanSetBlockEntries {
			// We're racing with a spine growth and the allocation of
			// a new block (and maybe a new spine!), and trying to grab
			// the span at the index which is currently being pushed.
			// Instead of spinning, let's just notify the caller that
			// there's nothing currently here. Spinning on this is
			// almost definitely not worth it.
			return nil
		}
		// Try to claim the current head by CASing in an updated head.
		// This may fail transiently due to a push which modifies the
		// tail, so keep trying while the head isn't changing.
		want := head
		for want == head {
			if b.index.cas(headtail, makeHeadTailIndex(want+1, tail)) {
				break claimLoop
			}
			headtail = b.index.load()
			head, tail = headtail.split()
		}
		// We failed to claim the spot we were after and the head changed,
		// meaning a popper got ahead of us. Try again from the top because
		// the buf may not be empty.
	}
	top, bottom := head/spanSetBlockEntries, head%spanSetBlockEntries

	// We may be reading a stale spine pointer, but because the length
	// grows monotonically and we've already verified it, we'll definitely
	// be reading from a valid block.
	blockp := b.spine.Load().lookup(uintptr(top))

	// Given that the spine length is correct, we know we will never
	// see a nil block here, since the length is always updated after
	// the block is set.
	block := blockp.Load()
	s := block.spans[bottom].Load()
	for s == nil {
		// We raced with the span actually being set, but given that we
		// know a block for this span exists, the race window here is
		// extremely small. Try again.
		s = block.spans[bottom].Load()
	}
	// Clear the pointer. This isn't strictly necessary, but defensively
	// avoids accidentally re-using blocks which could lead to memory
	// corruption. This way, we'll get a nil pointer access instead.
	block.spans[bottom].StoreNoWB(nil)

	// Increase the popped count. If we are the last possible popper
	// in the block (note that bottom need not equal spanSetBlockEntries-1
	// due to races) then it's our responsibility to free the block.
	//
	// If we increment popped to spanSetBlockEntries, we can be sure that
	// we're the last popper for this block, and it's thus safe to free it.
	// Every other popper must have crossed this barrier (and thus finished
	// popping its corresponding mspan) by the time we get here. Because
	// we're the last popper, we also don't have to worry about concurrent
	// pushers (there can't be any). Note that we may not be the popper
	// which claimed the last slot in the block, we're just the last one
	// to finish popping.
	if block.popped.Add(1) == spanSetBlockEntries {
		// Clear the block's pointer.
		blockp.StoreNoWB(nil)

		// Return the block to the block pool.
		spanSetBlockPool.free(block)
	}
	return s
}

// reset resets a spanSet which is empty. It will also clean up
// any left over blocks.
//
// Throws if the buf is not empty.
//
// reset may not be called concurrently with any other operations
// on the span set.
func (b *spanSet) reset() {
	head, tail := b.index.load().split()
	if head < tail {
		print("head = ", head, ", tail = ", tail, "\n")
		throw("attempt to clear non-empty span set")
	}
	top := head / spanSetBlockEntries
	if uintptr(top) < b.spineLen.Load() {
		// If the head catches up to the tail and the set is empty,
		// we may not clean up the block containing the head and tail
		// since it may be pushed into again. In order to avoid leaking
		// memory since we're going to reset the head and tail, clean
		// up such a block now, if it exists.
		blockp := b.spine.Load().lookup(uintptr(top))
		block := blockp.Load()
		if block != nil {
			// Check the popped value.
			if block.popped.Load() == 0 {
				// popped should never be zero because that means we have
				// pushed at least one value but not yet popped if this
				// block pointer is not nil.
				throw("span set block with unpopped elements found in reset")
			}
			if block.popped.Load() == spanSetBlockEntries {
				// popped should also never be equal to spanSetBlockEntries
				// because the last popper should have made the block pointer
				// in this slot nil.
				throw("fully empty unfreed span set block found in reset")
			}

			// Clear the pointer to the block.
			blockp.StoreNoWB(nil)

			// Return the block to the block pool.
			spanSetBlockPool.free(block)
		}
	}
	b.index.reset()
	b.spineLen.Store(0)
}

// atomicSpanSetSpinePointer is an atomically-accessed spanSetSpinePointer.
//
// It has the same semantics as atomic.UnsafePointer.
type atomicSpanSetSpinePointer struct {
	a atomic.UnsafePointer
}

// Loads the spanSetSpinePointer and returns it.
//
// It has the same semantics as atomic.UnsafePointer.
func (s *atomicSpanSetSpinePointer) Load() spanSetSpinePointer {
	return spanSetSpinePointer{s.a.Load()}
}

// Stores the spanSetSpinePointer.
//
// It has the same semantics as [atomic.UnsafePointer].
func (s *atomicSpanSetSpinePointer) StoreNoWB(p spanSetSpinePointer) {
	s.a.StoreNoWB(p.p)
}

// spanSetSpinePointer represents a pointer to a contiguous block of atomic.Pointer[spanSetBlock].
type spanSetSpinePointer struct {
	p unsafe.Pointer
}

// lookup returns &s[idx].
func (s spanSetSpinePointer) lookup(idx uintptr) *atomic.Pointer[spanSetBlock] {
	return (*atomic.Pointer[spanSetBlock])(add(s.p, goarch.PtrSize*idx))
}

// spanSetBlockPool is a global pool of spanSetBlocks.
var spanSetBlockPool spanSetBlockAlloc

// spanSetBlockAlloc represents a concurrent pool of spanSetBlocks.
type spanSetBlockAlloc struct {
	stack lfstack
}

// alloc tries to grab a spanSetBlock out of the pool, and if it fails
// persistentallocs a new one and returns it.
func (p *spanSetBlockAlloc) alloc() *spanSetBlock {
	if s := (*spanSetBlock)(p.stack.pop()); s != nil {
		return s
	}
	return (*spanSetBlock)(persistentalloc(unsafe.Sizeof(spanSetBlock{}), cpu.CacheLineSize, &memstats.gcMiscSys))
}

// free returns a spanSetBlock back to the pool.
func (p *spanSetBlockAlloc) free(block *spanSetBlock) {
	block.popped.Store(0)
	p.stack.push(&block.lfnode)
}

// headTailIndex represents a combined 32-bit head and 32-bit tail
// of a queue into a single 64-bit value.
type headTailIndex uint64

// makeHeadTailIndex creates a headTailIndex value from a separate
// head and tail.
func makeHeadTailIndex(head, tail uint32) headTailIndex {
	return headTailIndex(uint64(head)<<32 | uint64(tail))
}

// head returns the head of a headTailIndex value.
func (h headTailIndex) head() uint32 {
	return uint32(h >> 32)
}

// tail returns the tail of a headTailIndex value.
func (h headTailIndex) tail() uint32 {
	return uint32(h)
}

// split splits the headTailIndex value into its parts.
func (h headTailIndex) split() (head uint32, tail uint32) {
	return h.head(), h.tail()
}

// atomicHeadTailIndex is an atomically-accessed headTailIndex.
type atomicHeadTailIndex struct {
	u atomic.Uint64
}

// load atomically reads a headTailIndex value.
func (h *atomicHeadTailIndex) load() headTailIndex {
	return headTailIndex(h.u.Load())
}

// cas atomically compares-and-swaps a headTailIndex value.
func (h *atomicHeadTailIndex) cas(old, new headTailIndex) bool {
	return h.u.CompareAndSwap(uint64(old), uint64(new))
}

// incHead atomically increments the head of a headTailIndex.
func (h *atomicHeadTailIndex) incHead() headTailIndex {
	return headTailIndex(h.u.Add(1 << 32))
}

// decHead atomically decrements the head of a headTailIndex.
func (h *atomicHeadTailIndex) decHead() headTailIndex {
	return headTailIndex(h.u.Add(-(1 << 32)))
}

// incTail atomically increments the tail of a headTailIndex.
func (h *atomicHeadTailIndex) incTail() headTailIndex {
	ht := headTailIndex(h.u.Add(1))
	// Check for overflow.
	if ht.tail() == 0 {
		print("runtime: head = ", ht.head(), ", tail = ", ht.tail(), "\n")
		throw("headTailIndex overflow")
	}
	return ht
}

// reset clears the headTailIndex to (0, 0).
func (h *atomicHeadTailIndex) reset() {
	h.u.Store(0)
}

// atomicMSpanPointer is an atomic.Pointer[mspan]. Can't use generics because it's NotInHeap.
type atomicMSpanPointer struct {
	p atomic.UnsafePointer
}

// Load returns the *mspan.
func (p *atomicMSpanPointer) Load() *mspan {
	return (*mspan)(p.p.Load())
}

// Store stores an *mspan.
func (p *atomicMSpanPointer) StoreNoWB(s *mspan) {
	p.p.StoreNoWB(unsafe.Pointer(s))
}

"""



```