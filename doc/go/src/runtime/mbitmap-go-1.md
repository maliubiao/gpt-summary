Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of `go/src/runtime/mbitmap.go`. This is the second part of the code. I need to synthesize the functionality described in both parts.

Based on the code, the main functionalities are:

1. **Mark bits management:**  The code defines `markBits` struct and functions to get, set, and clear mark bits for objects in the heap. This is used by the garbage collector to track which objects are reachable.
2. **Allocation bits management:**  The code defines functions related to allocation bits within `mspan` structures, indicating which slots in a span are allocated. This includes `allocBitsForIndex`, `refillAllocCache`, and `nextFreeIndex`.
3. **Finding objects in the heap:** The `findObject` function helps locate the base address of an object given a pointer, along with its span and index within the span.
4. **Bulk write barriers:**  Functions like `bulkBarrierBitmap` and `typeBitsBulkBarrier` implement write barriers for bulk memory operations, ensuring the garbage collector is aware of pointer updates.
5. **GC program execution:** The code includes logic for interpreting and executing "GC programs" which are compact representations of pointer bitmaps for types. This is used for efficient scanning of data structures for pointers.
6. **Utilities for pointer arithmetic:** Functions like `addb`, `subtractb`, `add1`, and `subtract1` provide low-level byte pointer manipulation.
7. **Debugging and testing:** The `dumpTypePointers`, `dumpGCProg`, and `reflect_gcbits` functions seem to be for debugging and testing purposes, allowing inspection of internal data structures and GC bitmaps.

Considering this is the *second* part, I should focus on summarizing the functionalities introduced or emphasized in this specific chunk, while acknowledging the overall context.
这是 Go 语言运行时（runtime）中 `mbitmap.go` 文件的一部分，专门负责内存管理中的 **标记（mark）** 和 **分配（allocation）位图** 相关的功能。综合两部分的代码，其主要功能可以归纳如下：

1. **管理堆内存的标记位图 (Mark Bitmap)：**  这部分代码定义了 `markBits` 结构体以及相关的操作，用于跟踪堆上哪些对象已经被垃圾回收器标记为可达的。它提供了获取指定地址或索引对应标记位的方法，以及原子和非原子地设置和清除标记位的功能。这对于垃圾回收的标记阶段至关重要。

2. **管理 Span 的分配位图 (Allocation Bitmap)：** 代码中包含了与 `mspan` 结构体中分配位图相关的操作，例如 `allocBitsForIndex` 用于获取指定索引的分配位信息，`refillAllocCache` 通过优化手段加速查找空闲对象的过程，以及 `nextFreeIndex` 用于在 Span 中查找下一个空闲的对象的索引。这部分功能是内存分配器的核心组成部分。

3. **查找堆对象 (`findObject`)：**  `findObject` 函数接受一个指针地址作为输入，并在堆内存中查找包含该地址的对象。它返回对象的基地址、所在的 Span 以及对象在 Span 中的索引。这个函数在调试、错误报告以及某些需要了解指针指向对象信息的场景下非常有用。

4. **批量写屏障 (Bulk Write Barriers)：**  `bulkBarrierBitmap` 和 `typeBitsBulkBarrier` 函数实现了批量写屏障机制。当进行大块内存拷贝时，为了保证垃圾回收器的正确性，需要记录下可能存在的指针更新。`bulkBarrierBitmap` 使用一个外部的位图来指示哪些位置是指针，而 `typeBitsBulkBarrier` 则利用类型信息中的指针位图。

5. **执行 GC 程序 (`runGCProg`)：**  Go 语言为了节省内存，使用一种压缩的格式来存储类型信息中的指针位图，称为 GC 程序。`runGCProg` 函数负责解析和执行这些 GC 程序，将其展开成实际的指针位图。这对于在 GC 过程中快速识别对象内的指针非常重要。

6. **辅助性的指针操作函数：** 代码中定义了一些底层的指针运算函数，如 `addb`、`subtractb`、`add1` 和 `subtract1`，用于进行字节级别的指针加减操作，这些函数通常被标记为 `//go:nosplit`，表示它们不能被抢占，用于性能敏感的场景。

7. **调试和测试工具：**  `dumpTypePointers` 和 `dumpGCProg` 提供了打印内部数据结构和 GC 程序信息的功能，用于调试和理解内存布局。`reflect_gcbits` 则是一个用于测试的函数，它可以获取给定对象的 GC 位图信息。

**总结来说，这部分代码的核心职责是为 Go 语言的垃圾回收器和内存分配器提供底层的位图管理和指针操作支持。它负责追踪堆上对象的分配状态和可达性，并在内存操作过程中维护指针的完整性。**

由于这是第二部分，我们重点关注这里出现的功能：

*   **批量写屏障 (Bulk Write Barriers)**: 这部分代码详细展示了 `bulkBarrierBitmap` 和 `typeBitsBulkBarrier` 的实现。
*   **GC 程序执行 (`runGCProg`)**: 代码详细展示了 GC 程序的解析和执行过程，以及其指令集。
*   **调试和测试工具**: `dumpGCProg` 和 `reflect_gcbits` 的具体实现也在这里给出。

**代码推理示例 (基于 GC 程序执行):**

假设我们有以下简单的 GC 程序，用于描述一个包含两个指针的结构体：

```
prog := []byte{
	0x02, // emit 2 bits (pointer, pointer)
	0x03, 0x00, // 数据： 00000011 (反序，对应 11，即两个指针)
	0x00, // stop
}
```

输入： `prog` 如上所示，`size` 为结构体的大小，假设 `size` 为 16 字节（每个指针 8 字节）。

输出： 执行 `runGCProg(prog, dst)` 后，`dst` 指向的内存区域前两个字节将被设置为 `0x03`，表示前两个 8 字节的槽位是指针。`runGCProg` 返回 2。

**使用者易犯错的点 (以 `findObject` 为例，虽然第一部分有，但可以再次强调):**

*   **误用 `unsafe` 包创建了无效指针：** 如果通过 `unsafe` 包创建了一个指向未分配或已释放内存的指针，并将其传递给 `findObject`，可能会导致程序崩溃或产生未定义的行为（取决于 `debug.invalidptr` 的设置）。

    ```go
    package main

    import (
    	"fmt"
    	"runtime"
    	"unsafe"
    )

    func main() {
    	var x int
    	ptr := unsafe.Pointer(&x)

    	// 模拟释放内存 (实际场景中可能是其他操作导致)
    	// ...

    	// 此时 ptr 指向的内存可能已经失效
    	base, s, index := runtime.FindObject(uintptr(ptr), 0, 0)
    	fmt.Printf("Base: %v, Span: %v, Index: %v\n", base, s, index) // 可能输出 base 为 0 或导致 panic
    }
    ```

**归纳一下它的功能 (第二部分):**

这部分代码主要关注以下功能：

1. **实现了批量写屏障机制**:  通过 `bulkBarrierBitmap` 和 `typeBitsBulkBarrier` 高效地处理大块内存拷贝操作中的指针更新，确保 GC 的正确性。
2. **提供了 GC 程序的解析和执行能力**:  `runGCProg` 能够将压缩的类型指针信息展开，供 GC 使用，从而节省内存空间。
3. **包含了用于调试和测试的工具函数**: 如 `dumpGCProg` 和 `reflect_gcbits`，方便开发者理解和验证 GC 相关的功能。

总而言之，这部分代码进一步完善了 Go 语言运行时在内存管理和垃圾回收方面的底层支持，特别是针对大规模内存操作和高效类型信息表示的需求。

### 提示词
```
这是路径为go/src/runtime/mbitmap.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
ddr1), "\n")
			if addr0 == 0 && addr1 == 0 {
				break
			}
		}
		throw("mismatch between typePointersOfType and typePointersOf")
	}
}

func dumpTypePointers(tp typePointers) {
	print("runtime: tp.elem=", hex(tp.elem), " tp.typ=", unsafe.Pointer(tp.typ), "\n")
	print("runtime: tp.addr=", hex(tp.addr), " tp.mask=")
	for i := uintptr(0); i < ptrBits; i++ {
		if tp.mask&(uintptr(1)<<i) != 0 {
			print("1")
		} else {
			print("0")
		}
	}
	println()
}

// addb returns the byte pointer p+n.
//
//go:nowritebarrier
//go:nosplit
func addb(p *byte, n uintptr) *byte {
	// Note: wrote out full expression instead of calling add(p, n)
	// to reduce the number of temporaries generated by the
	// compiler for this trivial expression during inlining.
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + n))
}

// subtractb returns the byte pointer p-n.
//
//go:nowritebarrier
//go:nosplit
func subtractb(p *byte, n uintptr) *byte {
	// Note: wrote out full expression instead of calling add(p, -n)
	// to reduce the number of temporaries generated by the
	// compiler for this trivial expression during inlining.
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) - n))
}

// add1 returns the byte pointer p+1.
//
//go:nowritebarrier
//go:nosplit
func add1(p *byte) *byte {
	// Note: wrote out full expression instead of calling addb(p, 1)
	// to reduce the number of temporaries generated by the
	// compiler for this trivial expression during inlining.
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + 1))
}

// subtract1 returns the byte pointer p-1.
//
// nosplit because it is used during write barriers and must not be preempted.
//
//go:nowritebarrier
//go:nosplit
func subtract1(p *byte) *byte {
	// Note: wrote out full expression instead of calling subtractb(p, 1)
	// to reduce the number of temporaries generated by the
	// compiler for this trivial expression during inlining.
	return (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) - 1))
}

// markBits provides access to the mark bit for an object in the heap.
// bytep points to the byte holding the mark bit.
// mask is a byte with a single bit set that can be &ed with *bytep
// to see if the bit has been set.
// *m.byte&m.mask != 0 indicates the mark bit is set.
// index can be used along with span information to generate
// the address of the object in the heap.
// We maintain one set of mark bits for allocation and one for
// marking purposes.
type markBits struct {
	bytep *uint8
	mask  uint8
	index uintptr
}

//go:nosplit
func (s *mspan) allocBitsForIndex(allocBitIndex uintptr) markBits {
	bytep, mask := s.allocBits.bitp(allocBitIndex)
	return markBits{bytep, mask, allocBitIndex}
}

// refillAllocCache takes 8 bytes s.allocBits starting at whichByte
// and negates them so that ctz (count trailing zeros) instructions
// can be used. It then places these 8 bytes into the cached 64 bit
// s.allocCache.
func (s *mspan) refillAllocCache(whichByte uint16) {
	bytes := (*[8]uint8)(unsafe.Pointer(s.allocBits.bytep(uintptr(whichByte))))
	aCache := uint64(0)
	aCache |= uint64(bytes[0])
	aCache |= uint64(bytes[1]) << (1 * 8)
	aCache |= uint64(bytes[2]) << (2 * 8)
	aCache |= uint64(bytes[3]) << (3 * 8)
	aCache |= uint64(bytes[4]) << (4 * 8)
	aCache |= uint64(bytes[5]) << (5 * 8)
	aCache |= uint64(bytes[6]) << (6 * 8)
	aCache |= uint64(bytes[7]) << (7 * 8)
	s.allocCache = ^aCache
}

// nextFreeIndex returns the index of the next free object in s at
// or after s.freeindex.
// There are hardware instructions that can be used to make this
// faster if profiling warrants it.
func (s *mspan) nextFreeIndex() uint16 {
	sfreeindex := s.freeindex
	snelems := s.nelems
	if sfreeindex == snelems {
		return sfreeindex
	}
	if sfreeindex > snelems {
		throw("s.freeindex > s.nelems")
	}

	aCache := s.allocCache

	bitIndex := sys.TrailingZeros64(aCache)
	for bitIndex == 64 {
		// Move index to start of next cached bits.
		sfreeindex = (sfreeindex + 64) &^ (64 - 1)
		if sfreeindex >= snelems {
			s.freeindex = snelems
			return snelems
		}
		whichByte := sfreeindex / 8
		// Refill s.allocCache with the next 64 alloc bits.
		s.refillAllocCache(whichByte)
		aCache = s.allocCache
		bitIndex = sys.TrailingZeros64(aCache)
		// nothing available in cached bits
		// grab the next 8 bytes and try again.
	}
	result := sfreeindex + uint16(bitIndex)
	if result >= snelems {
		s.freeindex = snelems
		return snelems
	}

	s.allocCache >>= uint(bitIndex + 1)
	sfreeindex = result + 1

	if sfreeindex%64 == 0 && sfreeindex != snelems {
		// We just incremented s.freeindex so it isn't 0.
		// As each 1 in s.allocCache was encountered and used for allocation
		// it was shifted away. At this point s.allocCache contains all 0s.
		// Refill s.allocCache so that it corresponds
		// to the bits at s.allocBits starting at s.freeindex.
		whichByte := sfreeindex / 8
		s.refillAllocCache(whichByte)
	}
	s.freeindex = sfreeindex
	return result
}

// isFree reports whether the index'th object in s is unallocated.
//
// The caller must ensure s.state is mSpanInUse, and there must have
// been no preemption points since ensuring this (which could allow a
// GC transition, which would allow the state to change).
func (s *mspan) isFree(index uintptr) bool {
	if index < uintptr(s.freeIndexForScan) {
		return false
	}
	bytep, mask := s.allocBits.bitp(index)
	return *bytep&mask == 0
}

// divideByElemSize returns n/s.elemsize.
// n must be within [0, s.npages*_PageSize),
// or may be exactly s.npages*_PageSize
// if s.elemsize is from sizeclasses.go.
//
// nosplit, because it is called by objIndex, which is nosplit
//
//go:nosplit
func (s *mspan) divideByElemSize(n uintptr) uintptr {
	const doubleCheck = false

	// See explanation in mksizeclasses.go's computeDivMagic.
	q := uintptr((uint64(n) * uint64(s.divMul)) >> 32)

	if doubleCheck && q != n/s.elemsize {
		println(n, "/", s.elemsize, "should be", n/s.elemsize, "but got", q)
		throw("bad magic division")
	}
	return q
}

// nosplit, because it is called by other nosplit code like findObject
//
//go:nosplit
func (s *mspan) objIndex(p uintptr) uintptr {
	return s.divideByElemSize(p - s.base())
}

func markBitsForAddr(p uintptr) markBits {
	s := spanOf(p)
	objIndex := s.objIndex(p)
	return s.markBitsForIndex(objIndex)
}

func (s *mspan) markBitsForIndex(objIndex uintptr) markBits {
	bytep, mask := s.gcmarkBits.bitp(objIndex)
	return markBits{bytep, mask, objIndex}
}

func (s *mspan) markBitsForBase() markBits {
	return markBits{&s.gcmarkBits.x, uint8(1), 0}
}

// isMarked reports whether mark bit m is set.
func (m markBits) isMarked() bool {
	return *m.bytep&m.mask != 0
}

// setMarked sets the marked bit in the markbits, atomically.
func (m markBits) setMarked() {
	// Might be racing with other updates, so use atomic update always.
	// We used to be clever here and use a non-atomic update in certain
	// cases, but it's not worth the risk.
	atomic.Or8(m.bytep, m.mask)
}

// setMarkedNonAtomic sets the marked bit in the markbits, non-atomically.
func (m markBits) setMarkedNonAtomic() {
	*m.bytep |= m.mask
}

// clearMarked clears the marked bit in the markbits, atomically.
func (m markBits) clearMarked() {
	// Might be racing with other updates, so use atomic update always.
	// We used to be clever here and use a non-atomic update in certain
	// cases, but it's not worth the risk.
	atomic.And8(m.bytep, ^m.mask)
}

// markBitsForSpan returns the markBits for the span base address base.
func markBitsForSpan(base uintptr) (mbits markBits) {
	mbits = markBitsForAddr(base)
	if mbits.mask != 1 {
		throw("markBitsForSpan: unaligned start")
	}
	return mbits
}

// advance advances the markBits to the next object in the span.
func (m *markBits) advance() {
	if m.mask == 1<<7 {
		m.bytep = (*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(m.bytep)) + 1))
		m.mask = 1
	} else {
		m.mask = m.mask << 1
	}
	m.index++
}

// clobberdeadPtr is a special value that is used by the compiler to
// clobber dead stack slots, when -clobberdead flag is set.
const clobberdeadPtr = uintptr(0xdeaddead | 0xdeaddead<<((^uintptr(0)>>63)*32))

// badPointer throws bad pointer in heap panic.
func badPointer(s *mspan, p, refBase, refOff uintptr) {
	// Typically this indicates an incorrect use
	// of unsafe or cgo to store a bad pointer in
	// the Go heap. It may also indicate a runtime
	// bug.
	//
	// TODO(austin): We could be more aggressive
	// and detect pointers to unallocated objects
	// in allocated spans.
	printlock()
	print("runtime: pointer ", hex(p))
	if s != nil {
		state := s.state.get()
		if state != mSpanInUse {
			print(" to unallocated span")
		} else {
			print(" to unused region of span")
		}
		print(" span.base()=", hex(s.base()), " span.limit=", hex(s.limit), " span.state=", state)
	}
	print("\n")
	if refBase != 0 {
		print("runtime: found in object at *(", hex(refBase), "+", hex(refOff), ")\n")
		gcDumpObject("object", refBase, refOff)
	}
	getg().m.traceback = 2
	throw("found bad pointer in Go heap (incorrect use of unsafe or cgo?)")
}

// findObject returns the base address for the heap object containing
// the address p, the object's span, and the index of the object in s.
// If p does not point into a heap object, it returns base == 0.
//
// If p points is an invalid heap pointer and debug.invalidptr != 0,
// findObject panics.
//
// refBase and refOff optionally give the base address of the object
// in which the pointer p was found and the byte offset at which it
// was found. These are used for error reporting.
//
// It is nosplit so it is safe for p to be a pointer to the current goroutine's stack.
// Since p is a uintptr, it would not be adjusted if the stack were to move.
//
// findObject should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname findObject
//go:nosplit
func findObject(p, refBase, refOff uintptr) (base uintptr, s *mspan, objIndex uintptr) {
	s = spanOf(p)
	// If s is nil, the virtual address has never been part of the heap.
	// This pointer may be to some mmap'd region, so we allow it.
	if s == nil {
		if (GOARCH == "amd64" || GOARCH == "arm64") && p == clobberdeadPtr && debug.invalidptr != 0 {
			// Crash if clobberdeadPtr is seen. Only on AMD64 and ARM64 for now,
			// as they are the only platform where compiler's clobberdead mode is
			// implemented. On these platforms clobberdeadPtr cannot be a valid address.
			badPointer(s, p, refBase, refOff)
		}
		return
	}
	// If p is a bad pointer, it may not be in s's bounds.
	//
	// Check s.state to synchronize with span initialization
	// before checking other fields. See also spanOfHeap.
	if state := s.state.get(); state != mSpanInUse || p < s.base() || p >= s.limit {
		// Pointers into stacks are also ok, the runtime manages these explicitly.
		if state == mSpanManual {
			return
		}
		// The following ensures that we are rigorous about what data
		// structures hold valid pointers.
		if debug.invalidptr != 0 {
			badPointer(s, p, refBase, refOff)
		}
		return
	}

	objIndex = s.objIndex(p)
	base = s.base() + objIndex*s.elemsize
	return
}

// reflect_verifyNotInHeapPtr reports whether converting the not-in-heap pointer into a unsafe.Pointer is ok.
//
//go:linkname reflect_verifyNotInHeapPtr reflect.verifyNotInHeapPtr
func reflect_verifyNotInHeapPtr(p uintptr) bool {
	// Conversion to a pointer is ok as long as findObject above does not call badPointer.
	// Since we're already promised that p doesn't point into the heap, just disallow heap
	// pointers and the special clobbered pointer.
	return spanOf(p) == nil && p != clobberdeadPtr
}

const ptrBits = 8 * goarch.PtrSize

// bulkBarrierBitmap executes write barriers for copying from [src,
// src+size) to [dst, dst+size) using a 1-bit pointer bitmap. src is
// assumed to start maskOffset bytes into the data covered by the
// bitmap in bits (which may not be a multiple of 8).
//
// This is used by bulkBarrierPreWrite for writes to data and BSS.
//
//go:nosplit
func bulkBarrierBitmap(dst, src, size, maskOffset uintptr, bits *uint8) {
	word := maskOffset / goarch.PtrSize
	bits = addb(bits, word/8)
	mask := uint8(1) << (word % 8)

	buf := &getg().m.p.ptr().wbBuf
	for i := uintptr(0); i < size; i += goarch.PtrSize {
		if mask == 0 {
			bits = addb(bits, 1)
			if *bits == 0 {
				// Skip 8 words.
				i += 7 * goarch.PtrSize
				continue
			}
			mask = 1
		}
		if *bits&mask != 0 {
			dstx := (*uintptr)(unsafe.Pointer(dst + i))
			if src == 0 {
				p := buf.get1()
				p[0] = *dstx
			} else {
				srcx := (*uintptr)(unsafe.Pointer(src + i))
				p := buf.get2()
				p[0] = *dstx
				p[1] = *srcx
			}
		}
		mask <<= 1
	}
}

// typeBitsBulkBarrier executes a write barrier for every
// pointer that would be copied from [src, src+size) to [dst,
// dst+size) by a memmove using the type bitmap to locate those
// pointer slots.
//
// The type typ must correspond exactly to [src, src+size) and [dst, dst+size).
// dst, src, and size must be pointer-aligned.
//
// Must not be preempted because it typically runs right before memmove,
// and the GC must observe them as an atomic action.
//
// Callers must perform cgo checks if goexperiment.CgoCheck2.
//
//go:nosplit
func typeBitsBulkBarrier(typ *_type, dst, src, size uintptr) {
	if typ == nil {
		throw("runtime: typeBitsBulkBarrier without type")
	}
	if typ.Size_ != size {
		println("runtime: typeBitsBulkBarrier with type ", toRType(typ).string(), " of size ", typ.Size_, " but memory size", size)
		throw("runtime: invalid typeBitsBulkBarrier")
	}
	if !writeBarrier.enabled {
		return
	}
	ptrmask := getGCMask(typ)
	buf := &getg().m.p.ptr().wbBuf
	var bits uint32
	for i := uintptr(0); i < typ.PtrBytes; i += goarch.PtrSize {
		if i&(goarch.PtrSize*8-1) == 0 {
			bits = uint32(*ptrmask)
			ptrmask = addb(ptrmask, 1)
		} else {
			bits = bits >> 1
		}
		if bits&1 != 0 {
			dstx := (*uintptr)(unsafe.Pointer(dst + i))
			srcx := (*uintptr)(unsafe.Pointer(src + i))
			p := buf.get2()
			p[0] = *dstx
			p[1] = *srcx
		}
	}
}

// countAlloc returns the number of objects allocated in span s by
// scanning the mark bitmap.
func (s *mspan) countAlloc() int {
	count := 0
	bytes := divRoundUp(uintptr(s.nelems), 8)
	// Iterate over each 8-byte chunk and count allocations
	// with an intrinsic. Note that newMarkBits guarantees that
	// gcmarkBits will be 8-byte aligned, so we don't have to
	// worry about edge cases, irrelevant bits will simply be zero.
	for i := uintptr(0); i < bytes; i += 8 {
		// Extract 64 bits from the byte pointer and get a OnesCount.
		// Note that the unsafe cast here doesn't preserve endianness,
		// but that's OK. We only care about how many bits are 1, not
		// about the order we discover them in.
		mrkBits := *(*uint64)(unsafe.Pointer(s.gcmarkBits.bytep(i)))
		count += sys.OnesCount64(mrkBits)
	}
	return count
}

// Read the bytes starting at the aligned pointer p into a uintptr.
// Read is little-endian.
func readUintptr(p *byte) uintptr {
	x := *(*uintptr)(unsafe.Pointer(p))
	if goarch.BigEndian {
		if goarch.PtrSize == 8 {
			return uintptr(sys.Bswap64(uint64(x)))
		}
		return uintptr(sys.Bswap32(uint32(x)))
	}
	return x
}

var debugPtrmask struct {
	lock mutex
	data *byte
}

// progToPointerMask returns the 1-bit pointer mask output by the GC program prog.
// size the size of the region described by prog, in bytes.
// The resulting bitvector will have no more than size/goarch.PtrSize bits.
func progToPointerMask(prog *byte, size uintptr) bitvector {
	n := (size/goarch.PtrSize + 7) / 8
	x := (*[1 << 30]byte)(persistentalloc(n+1, 1, &memstats.buckhash_sys))[:n+1]
	x[len(x)-1] = 0xa1 // overflow check sentinel
	n = runGCProg(prog, &x[0])
	if x[len(x)-1] != 0xa1 {
		throw("progToPointerMask: overflow")
	}
	return bitvector{int32(n), &x[0]}
}

// Packed GC pointer bitmaps, aka GC programs.
//
// For large types containing arrays, the type information has a
// natural repetition that can be encoded to save space in the
// binary and in the memory representation of the type information.
//
// The encoding is a simple Lempel-Ziv style bytecode machine
// with the following instructions:
//
//	00000000: stop
//	0nnnnnnn: emit n bits copied from the next (n+7)/8 bytes
//	10000000 n c: repeat the previous n bits c times; n, c are varints
//	1nnnnnnn c: repeat the previous n bits c times; c is a varint
//
// Currently, gc programs are only used for describing data and bss
// sections of the binary.

// runGCProg returns the number of 1-bit entries written to memory.
func runGCProg(prog, dst *byte) uintptr {
	dstStart := dst

	// Bits waiting to be written to memory.
	var bits uintptr
	var nbits uintptr

	p := prog
Run:
	for {
		// Flush accumulated full bytes.
		// The rest of the loop assumes that nbits <= 7.
		for ; nbits >= 8; nbits -= 8 {
			*dst = uint8(bits)
			dst = add1(dst)
			bits >>= 8
		}

		// Process one instruction.
		inst := uintptr(*p)
		p = add1(p)
		n := inst & 0x7F
		if inst&0x80 == 0 {
			// Literal bits; n == 0 means end of program.
			if n == 0 {
				// Program is over.
				break Run
			}
			nbyte := n / 8
			for i := uintptr(0); i < nbyte; i++ {
				bits |= uintptr(*p) << nbits
				p = add1(p)
				*dst = uint8(bits)
				dst = add1(dst)
				bits >>= 8
			}
			if n %= 8; n > 0 {
				bits |= uintptr(*p) << nbits
				p = add1(p)
				nbits += n
			}
			continue Run
		}

		// Repeat. If n == 0, it is encoded in a varint in the next bytes.
		if n == 0 {
			for off := uint(0); ; off += 7 {
				x := uintptr(*p)
				p = add1(p)
				n |= (x & 0x7F) << off
				if x&0x80 == 0 {
					break
				}
			}
		}

		// Count is encoded in a varint in the next bytes.
		c := uintptr(0)
		for off := uint(0); ; off += 7 {
			x := uintptr(*p)
			p = add1(p)
			c |= (x & 0x7F) << off
			if x&0x80 == 0 {
				break
			}
		}
		c *= n // now total number of bits to copy

		// If the number of bits being repeated is small, load them
		// into a register and use that register for the entire loop
		// instead of repeatedly reading from memory.
		// Handling fewer than 8 bits here makes the general loop simpler.
		// The cutoff is goarch.PtrSize*8 - 7 to guarantee that when we add
		// the pattern to a bit buffer holding at most 7 bits (a partial byte)
		// it will not overflow.
		src := dst
		const maxBits = goarch.PtrSize*8 - 7
		if n <= maxBits {
			// Start with bits in output buffer.
			pattern := bits
			npattern := nbits

			// If we need more bits, fetch them from memory.
			src = subtract1(src)
			for npattern < n {
				pattern <<= 8
				pattern |= uintptr(*src)
				src = subtract1(src)
				npattern += 8
			}

			// We started with the whole bit output buffer,
			// and then we loaded bits from whole bytes.
			// Either way, we might now have too many instead of too few.
			// Discard the extra.
			if npattern > n {
				pattern >>= npattern - n
				npattern = n
			}

			// Replicate pattern to at most maxBits.
			if npattern == 1 {
				// One bit being repeated.
				// If the bit is 1, make the pattern all 1s.
				// If the bit is 0, the pattern is already all 0s,
				// but we can claim that the number of bits
				// in the word is equal to the number we need (c),
				// because right shift of bits will zero fill.
				if pattern == 1 {
					pattern = 1<<maxBits - 1
					npattern = maxBits
				} else {
					npattern = c
				}
			} else {
				b := pattern
				nb := npattern
				if nb+nb <= maxBits {
					// Double pattern until the whole uintptr is filled.
					for nb <= goarch.PtrSize*8 {
						b |= b << nb
						nb += nb
					}
					// Trim away incomplete copy of original pattern in high bits.
					// TODO(rsc): Replace with table lookup or loop on systems without divide?
					nb = maxBits / npattern * npattern
					b &= 1<<nb - 1
					pattern = b
					npattern = nb
				}
			}

			// Add pattern to bit buffer and flush bit buffer, c/npattern times.
			// Since pattern contains >8 bits, there will be full bytes to flush
			// on each iteration.
			for ; c >= npattern; c -= npattern {
				bits |= pattern << nbits
				nbits += npattern
				for nbits >= 8 {
					*dst = uint8(bits)
					dst = add1(dst)
					bits >>= 8
					nbits -= 8
				}
			}

			// Add final fragment to bit buffer.
			if c > 0 {
				pattern &= 1<<c - 1
				bits |= pattern << nbits
				nbits += c
			}
			continue Run
		}

		// Repeat; n too large to fit in a register.
		// Since nbits <= 7, we know the first few bytes of repeated data
		// are already written to memory.
		off := n - nbits // n > nbits because n > maxBits and nbits <= 7
		// Leading src fragment.
		src = subtractb(src, (off+7)/8)
		if frag := off & 7; frag != 0 {
			bits |= uintptr(*src) >> (8 - frag) << nbits
			src = add1(src)
			nbits += frag
			c -= frag
		}
		// Main loop: load one byte, write another.
		// The bits are rotating through the bit buffer.
		for i := c / 8; i > 0; i-- {
			bits |= uintptr(*src) << nbits
			src = add1(src)
			*dst = uint8(bits)
			dst = add1(dst)
			bits >>= 8
		}
		// Final src fragment.
		if c %= 8; c > 0 {
			bits |= (uintptr(*src) & (1<<c - 1)) << nbits
			nbits += c
		}
	}

	// Write any final bits out, using full-byte writes, even for the final byte.
	totalBits := (uintptr(unsafe.Pointer(dst))-uintptr(unsafe.Pointer(dstStart)))*8 + nbits
	nbits += -nbits & 7
	for ; nbits > 0; nbits -= 8 {
		*dst = uint8(bits)
		dst = add1(dst)
		bits >>= 8
	}
	return totalBits
}

func dumpGCProg(p *byte) {
	nptr := 0
	for {
		x := *p
		p = add1(p)
		if x == 0 {
			print("\t", nptr, " end\n")
			break
		}
		if x&0x80 == 0 {
			print("\t", nptr, " lit ", x, ":")
			n := int(x+7) / 8
			for i := 0; i < n; i++ {
				print(" ", hex(*p))
				p = add1(p)
			}
			print("\n")
			nptr += int(x)
		} else {
			nbit := int(x &^ 0x80)
			if nbit == 0 {
				for nb := uint(0); ; nb += 7 {
					x := *p
					p = add1(p)
					nbit |= int(x&0x7f) << nb
					if x&0x80 == 0 {
						break
					}
				}
			}
			count := 0
			for nb := uint(0); ; nb += 7 {
				x := *p
				p = add1(p)
				count |= int(x&0x7f) << nb
				if x&0x80 == 0 {
					break
				}
			}
			print("\t", nptr, " repeat ", nbit, " × ", count, "\n")
			nptr += nbit * count
		}
	}
}

// Testing.

// reflect_gcbits returns the GC type info for x, for testing.
// The result is the bitmap entries (0 or 1), one entry per byte.
//
//go:linkname reflect_gcbits reflect.gcbits
func reflect_gcbits(x any) []byte {
	return pointerMask(x)
}

// Returns GC type info for the pointer stored in ep for testing.
// If ep points to the stack, only static live information will be returned
// (i.e. not for objects which are only dynamically live stack objects).
func pointerMask(ep any) (mask []byte) {
	e := *efaceOf(&ep)
	p := e.data
	t := e._type

	var et *_type
	if t.Kind_&abi.KindMask != abi.Pointer {
		throw("bad argument to getgcmask: expected type to be a pointer to the value type whose mask is being queried")
	}
	et = (*ptrtype)(unsafe.Pointer(t)).Elem

	// data or bss
	for _, datap := range activeModules() {
		// data
		if datap.data <= uintptr(p) && uintptr(p) < datap.edata {
			bitmap := datap.gcdatamask.bytedata
			n := et.Size_
			mask = make([]byte, n/goarch.PtrSize)
			for i := uintptr(0); i < n; i += goarch.PtrSize {
				off := (uintptr(p) + i - datap.data) / goarch.PtrSize
				mask[i/goarch.PtrSize] = (*addb(bitmap, off/8) >> (off % 8)) & 1
			}
			return
		}

		// bss
		if datap.bss <= uintptr(p) && uintptr(p) < datap.ebss {
			bitmap := datap.gcbssmask.bytedata
			n := et.Size_
			mask = make([]byte, n/goarch.PtrSize)
			for i := uintptr(0); i < n; i += goarch.PtrSize {
				off := (uintptr(p) + i - datap.bss) / goarch.PtrSize
				mask[i/goarch.PtrSize] = (*addb(bitmap, off/8) >> (off % 8)) & 1
			}
			return
		}
	}

	// heap
	if base, s, _ := findObject(uintptr(p), 0, 0); base != 0 {
		if s.spanclass.noscan() {
			return nil
		}
		limit := base + s.elemsize

		// Move the base up to the iterator's start, because
		// we want to hide evidence of a malloc header from the
		// caller.
		tp := s.typePointersOfUnchecked(base)
		base = tp.addr

		// Unroll the full bitmap the GC would actually observe.
		maskFromHeap := make([]byte, (limit-base)/goarch.PtrSize)
		for {
			var addr uintptr
			if tp, addr = tp.next(limit); addr == 0 {
				break
			}
			maskFromHeap[(addr-base)/goarch.PtrSize] = 1
		}

		// Double-check that every part of the ptr/scalar we're not
		// showing the caller is zeroed. This keeps us honest that
		// that information is actually irrelevant.
		for i := limit; i < s.elemsize; i++ {
			if *(*byte)(unsafe.Pointer(i)) != 0 {
				throw("found non-zeroed tail of allocation")
			}
		}

		// Callers (and a check we're about to run) expects this mask
		// to end at the last pointer.
		for len(maskFromHeap) > 0 && maskFromHeap[len(maskFromHeap)-1] == 0 {
			maskFromHeap = maskFromHeap[:len(maskFromHeap)-1]
		}

		// Unroll again, but this time from the type information.
		maskFromType := make([]byte, (limit-base)/goarch.PtrSize)
		tp = s.typePointersOfType(et, base)
		for {
			var addr uintptr
			if tp, addr = tp.next(limit); addr == 0 {
				break
			}
			maskFromType[(addr-base)/goarch.PtrSize] = 1
		}

		// Validate that the prefix of maskFromType is equal to
		// maskFromHeap. maskFromType may contain more pointers than
		// maskFromHeap produces because maskFromHeap may be able to
		// get exact type information for certain classes of objects.
		// With maskFromType, we're always just tiling the type bitmap
		// through to the elemsize.
		//
		// It's OK if maskFromType has pointers in elemsize that extend
		// past the actual populated space; we checked above that all
		// that space is zeroed, so just the GC will just see nil pointers.
		differs := false
		for i := range maskFromHeap {
			if maskFromHeap[i] != maskFromType[i] {
				differs = true
				break
			}
		}

		if differs {
			print("runtime: heap mask=")
			for _, b := range maskFromHeap {
				print(b)
			}
			println()
			print("runtime: type mask=")
			for _, b := range maskFromType {
				print(b)
			}
			println()
			print("runtime: type=", toRType(et).string(), "\n")
			throw("found two different masks from two different methods")
		}

		// Select the heap mask to return. We may not have a type mask.
		mask = maskFromHeap

		// Make sure we keep ep alive. We may have stopped referencing
		// ep's data pointer sometime before this point and it's possible
		// for that memory to get freed.
		KeepAlive(ep)
		return
	}

	// stack
	if gp := getg(); gp.m.curg.stack.lo <= uintptr(p) && uintptr(p) < gp.m.curg.stack.hi {
		found := false
		var u unwinder
		for u.initAt(gp.m.curg.sched.pc, gp.m.curg.sched.sp, 0, gp.m.curg, 0); u.valid(); u.next() {
			if u.frame.sp <= uintptr(p) && uintptr(p) < u.frame.varp {
				found = true
				break
			}
		}
		if found {
			locals, _, _ := u.frame.getStackMap(false)
			if locals.n == 0 {
				return
			}
			size := uintptr(locals.n) * goarch.PtrSize
			n := (*ptrtype)(unsafe.Pointer(t)).Elem.Size_
			mask = make([]byte, n/goarch.PtrSize)
			for i := uintptr(0); i < n; i += goarch.PtrSize {
				off := (uintptr(p) + i - u.frame.varp + size) / goarch.PtrSize
				mask[i/goarch.PtrSize] = locals.ptrbit(off)
			}
		}
		return
	}

	// otherwise, not something the GC knows about.
	// possibly read-only data, like malloc(0).
	// must not have pointers
	return
}
```