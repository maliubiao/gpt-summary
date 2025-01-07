Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/runtime/malloc.go`.

My plan is to break down the code section by section, identify the core functionalities, and then summarize them.

Here's a breakdown of the functions in the snippet:

1. **`sysReserveAligned`**: This function seems responsible for reserving a block of memory from the operating system, ensuring it's aligned to a specific boundary. It handles platform-specific behaviors, especially for Windows and systems using `sbrk`.

2. **`enableMetadataHugePages`**: This function appears to enable the use of huge pages for storing heap metadata, potentially improving performance by reducing TLB misses.

3. **`nextFreeFast`**: This function tries to quickly find a free object within a memory span using a bitmask (`allocCache`).

4. **`nextFree`**: If `nextFreeFast` fails, this function searches for the next free object in a memory span. If the current span is full, it refills the cache with a new span.

5. **`mallocgc`**: This is the core allocation function. It handles allocation requests of different sizes, using different strategies for small and large objects. It also integrates with the garbage collector and memory profiling.

6. **`mallocgcTiny`**: Handles allocation of very small, "tiny" objects by combining multiple allocations into a single block.

7. **`mallocgcSmallNoscan`**: Handles allocation of small objects that do not contain pointers.

8. **`mallocgcSmallScanNoHeader`**: Handles allocation of small objects that contain pointers, without a separate header.

9. **`mallocgcSmallScanHeader`**: Handles allocation of small objects that contain pointers, with a separate header.

10. **`mallocgcLarge`**: Handles allocation of large objects directly from the heap.

11. **`preMallocgcDebug`**: A debug hook called before the actual allocation.

12. **`postMallocgcDebug`**: A debug hook called after the allocation.

13. **`deductAssistCredit`**: Manages the garbage collector's assist credit, potentially triggering GC if a goroutine consumes too much memory.

14. **`memclrNoHeapPointersChunked`**: Clears a block of memory in chunks, allowing for preemption during the process.

15. **`newobject`**: The implementation of the `new` built-in function in Go.

16. **`maps_newobject`**:  A linkname for `newobject`, used internally for maps.

17. **`reflect_unsafe_New`**: A linkname for `mallocgc`, used by the `reflect` package.

18. **`reflectlite_unsafe_New`**: A linkname for `mallocgc`, used internally by `reflectlite`.

19. **`newarray`**: The implementation of allocating an array.

20. **`reflect_unsafe_NewArray`**: A linkname for `newarray`, used by the `reflect` package.

21. **`maps_newarray`**: A linkname for `newarray`, used internally for maps.

22. **`profilealloc`**: Records a memory profile sample for an allocation.

23. **`nextSample`**: Calculates the next sampling point for memory profiling.

24. **`fastexprand`**: Generates a random number following an exponential distribution, used for memory profiling sampling.

Now, I need to synthesize this information into a concise summary.
这段代码是 Go 语言运行时（runtime）中内存分配器 `malloc.go` 文件的一部分，主要负责实现**堆内存的分配**功能。

具体来说，这段代码涵盖了以下几个核心功能：

1. **底层内存预留与对齐 (`sysReserveAligned`)**: 负责向操作系统预留一块指定大小和对齐方式的内存。它会根据不同的操作系统平台（特别是区分 `sbrk` 系统调用和非 `sbrk` 系统）采用不同的策略来完成内存的预留，并确保返回的内存地址满足指定的对齐要求。

2. **启用元数据大页 (`enableMetadataHugePages`)**:  这个功能旨在利用操作系统提供的“大页”（Huge Pages）特性来存储 Go 运行时的一些元数据，例如页表结构（`h.pages`）和 arena 的二级索引（`h.arenas`）。使用大页可以减少内存管理单元（MMU）的查找开销，提高性能。

3. **快速查找空闲对象 (`nextFreeFast`)**: 当需要分配一个小的对象时，这个函数会尝试在一个 `mspan` 中快速找到一个空闲的位置。它通过检查 `allocCache` 位图来实现，如果找到空闲位，则直接返回对应的内存地址。

4. **查找空闲对象并填充缓存 (`nextFree`)**: 如果 `nextFreeFast` 找不到空闲对象，这个函数会更进一步查找。如果当前的 `mspan` 已满，它会调用 `c.refill(spc)` 来获取一个新的包含空闲空间的 `mspan`。这个函数还会设置一个标志 `checkGCTrigger`，指示可能需要触发垃圾回收。

5. **核心的内存分配函数 (`mallocgc`)**: 这是 Go 语言中进行内存分配的主要入口点。它根据请求分配的大小来选择不同的分配策略：
    - **零大小对象**: 直接返回预先分配的 `zerobase` 地址。
    - **小对象 (<= 32KB)**: 从每个 P 的本地缓存 (`mcache`) 的空闲列表中分配。根据对象是否包含指针以及是否需要头部信息又细分为 `mallocgcTiny`, `mallocgcSmallNoscan`, `mallocgcSmallScanNoHeader`, `mallocgcSmallScanHeader` 等函数。
    - **大对象 (> 32KB)**: 直接从堆上分配 (`mallocgcLarge`)。
    `mallocgc` 还负责记录内存分配信息，处理 ASan/MSan 等内存检测工具，以及检查是否需要触发垃圾回收。

6. **特定大小的小对象分配 (`mallocgcTiny`, `mallocgcSmallNoscan`, `mallocgcSmallScanNoHeader`, `mallocgcSmallScanHeader`)**: 这些函数分别处理不同类型和大小的小对象分配。`mallocgcTiny` 用于极小的无指针对象，它会将多个小对象合并到一个块中以提高效率。`mallocgcSmallNoscan` 处理不包含指针的小对象。`mallocgcSmallScanNoHeader` 和 `mallocgcSmallScanHeader` 处理包含指针的小对象，区别在于是否需要额外的头部信息存储类型。

7. **大对象分配 (`mallocgcLarge`)**:  这个函数直接从堆上分配大块内存。对于包含指针的大对象，它会在稍后的安全点进行清零和类型信息设置。

8. **调试辅助函数 (`preMallocgcDebug`, `postMallocgcDebug`)**: 这两个函数是在内存分配前后调用的调试钩子，用于进行一些额外的检查或记录，例如在初始化追踪期间记录分配信息。

9. **垃圾回收辅助 (`deductAssistCredit`)**: 当 Goroutine 分配内存时，这个函数会减少其持有的 GC 辅助信用。如果信用不足，可能会触发 Goroutine 协助 GC。

10. **分块清零内存 (`memclrNoHeapPointersChunked`)**: 用于分块清零不包含指针的内存，允许在清零过程中发生抢占，避免长时间阻塞。

11. **`new` 内建函数的实现 (`newobject`)**: 这是 Go 语言中 `new` 关键字的底层实现，用于分配单个对象。

12. **`maps.newobject` 等链接名**:  这些是 `newobject` 或 `mallocgc` 的链接名，允许其他包（如 `internal/runtime/maps` 和 `reflect`) 通过链接直接调用这些底层的分配函数。

13. **数组分配 (`newarray`)**: 这是 Go 语言中分配数组的底层实现。

14. **内存分配性能分析 (`profilealloc`, `nextSample`, `fastexprand`)**:  这些函数用于支持内存分配的性能分析。`profilealloc` 记录分配事件，`nextSample` 和 `fastexprand` 用于确定采样的时机，实现泊松分布的采样。

**总结这段代码的功能：**

这段代码的核心功能是实现了 Go 语言的**堆内存分配器**。它负责响应内存分配请求，并根据对象的大小和类型，选择合适的策略从堆上分配内存。同时，它还集成了对大页的支持、快速空闲对象查找、垃圾回收辅助以及内存性能分析等功能，是 Go 运行时系统中至关重要的组成部分。

Prompt: 
```
这是路径为go/src/runtime/malloc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
fe.Pointer, uintptr) {
	if isSbrkPlatform {
		if v != nil {
			throw("unexpected heap arena hint on sbrk platform")
		}
		return sysReserveAlignedSbrk(size, align)
	}
	// Since the alignment is rather large in uses of this
	// function, we're not likely to get it by chance, so we ask
	// for a larger region and remove the parts we don't need.
	retries := 0
retry:
	p := uintptr(sysReserve(v, size+align))
	switch {
	case p == 0:
		return nil, 0
	case p&(align-1) == 0:
		return unsafe.Pointer(p), size + align
	case GOOS == "windows":
		// On Windows we can't release pieces of a
		// reservation, so we release the whole thing and
		// re-reserve the aligned sub-region. This may race,
		// so we may have to try again.
		sysFreeOS(unsafe.Pointer(p), size+align)
		p = alignUp(p, align)
		p2 := sysReserve(unsafe.Pointer(p), size)
		if p != uintptr(p2) {
			// Must have raced. Try again.
			sysFreeOS(p2, size)
			if retries++; retries == 100 {
				throw("failed to allocate aligned heap memory; too many retries")
			}
			goto retry
		}
		// Success.
		return p2, size
	default:
		// Trim off the unaligned parts.
		pAligned := alignUp(p, align)
		sysFreeOS(unsafe.Pointer(p), pAligned-p)
		end := pAligned + size
		endLen := (p + size + align) - end
		if endLen > 0 {
			sysFreeOS(unsafe.Pointer(end), endLen)
		}
		return unsafe.Pointer(pAligned), size
	}
}

// enableMetadataHugePages enables huge pages for various sources of heap metadata.
//
// A note on latency: for sufficiently small heaps (<10s of GiB) this function will take constant
// time, but may take time proportional to the size of the mapped heap beyond that.
//
// This function is idempotent.
//
// The heap lock must not be held over this operation, since it will briefly acquire
// the heap lock.
//
// Must be called on the system stack because it acquires the heap lock.
//
//go:systemstack
func (h *mheap) enableMetadataHugePages() {
	// Enable huge pages for page structure.
	h.pages.enableChunkHugePages()

	// Grab the lock and set arenasHugePages if it's not.
	//
	// Once arenasHugePages is set, all new L2 entries will be eligible for
	// huge pages. We'll set all the old entries after we release the lock.
	lock(&h.lock)
	if h.arenasHugePages {
		unlock(&h.lock)
		return
	}
	h.arenasHugePages = true
	unlock(&h.lock)

	// N.B. The arenas L1 map is quite small on all platforms, so it's fine to
	// just iterate over the whole thing.
	for i := range h.arenas {
		l2 := (*[1 << arenaL2Bits]*heapArena)(atomic.Loadp(unsafe.Pointer(&h.arenas[i])))
		if l2 == nil {
			continue
		}
		sysHugePage(unsafe.Pointer(l2), unsafe.Sizeof(*l2))
	}
}

// base address for all 0-byte allocations
var zerobase uintptr

// nextFreeFast returns the next free object if one is quickly available.
// Otherwise it returns 0.
func nextFreeFast(s *mspan) gclinkptr {
	theBit := sys.TrailingZeros64(s.allocCache) // Is there a free object in the allocCache?
	if theBit < 64 {
		result := s.freeindex + uint16(theBit)
		if result < s.nelems {
			freeidx := result + 1
			if freeidx%64 == 0 && freeidx != s.nelems {
				return 0
			}
			s.allocCache >>= uint(theBit + 1)
			s.freeindex = freeidx
			s.allocCount++
			return gclinkptr(uintptr(result)*s.elemsize + s.base())
		}
	}
	return 0
}

// nextFree returns the next free object from the cached span if one is available.
// Otherwise it refills the cache with a span with an available object and
// returns that object along with a flag indicating that this was a heavy
// weight allocation. If it is a heavy weight allocation the caller must
// determine whether a new GC cycle needs to be started or if the GC is active
// whether this goroutine needs to assist the GC.
//
// Must run in a non-preemptible context since otherwise the owner of
// c could change.
func (c *mcache) nextFree(spc spanClass) (v gclinkptr, s *mspan, checkGCTrigger bool) {
	s = c.alloc[spc]
	checkGCTrigger = false
	freeIndex := s.nextFreeIndex()
	if freeIndex == s.nelems {
		// The span is full.
		if s.allocCount != s.nelems {
			println("runtime: s.allocCount=", s.allocCount, "s.nelems=", s.nelems)
			throw("s.allocCount != s.nelems && freeIndex == s.nelems")
		}
		c.refill(spc)
		checkGCTrigger = true
		s = c.alloc[spc]

		freeIndex = s.nextFreeIndex()
	}

	if freeIndex >= s.nelems {
		throw("freeIndex is not valid")
	}

	v = gclinkptr(uintptr(freeIndex)*s.elemsize + s.base())
	s.allocCount++
	if s.allocCount > s.nelems {
		println("s.allocCount=", s.allocCount, "s.nelems=", s.nelems)
		throw("s.allocCount > s.nelems")
	}
	return
}

// doubleCheckMalloc enables a bunch of extra checks to malloc to double-check
// that various invariants are upheld.
//
// We might consider turning these on by default; many of them previously were.
// They account for a few % of mallocgc's cost though, which does matter somewhat
// at scale.
const doubleCheckMalloc = false

// Allocate an object of size bytes.
// Small objects are allocated from the per-P cache's free lists.
// Large objects (> 32 kB) are allocated straight from the heap.
//
// mallocgc should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/gopkg
//   - github.com/bytedance/sonic
//   - github.com/cloudwego/frugal
//   - github.com/cockroachdb/cockroach
//   - github.com/cockroachdb/pebble
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname mallocgc
func mallocgc(size uintptr, typ *_type, needzero bool) unsafe.Pointer {
	if doubleCheckMalloc {
		if gcphase == _GCmarktermination {
			throw("mallocgc called with gcphase == _GCmarktermination")
		}
	}

	// Short-circuit zero-sized allocation requests.
	if size == 0 {
		return unsafe.Pointer(&zerobase)
	}

	// It's possible for any malloc to trigger sweeping, which may in
	// turn queue finalizers. Record this dynamic lock edge.
	// N.B. Compiled away if lockrank experiment is not enabled.
	lockRankMayQueueFinalizer()

	// Pre-malloc debug hooks.
	if debug.malloc {
		if x := preMallocgcDebug(size, typ); x != nil {
			return x
		}
	}

	// For ASAN, we allocate extra memory around each allocation called the "redzone."
	// These "redzones" are marked as unaddressable.
	var asanRZ uintptr
	if asanenabled {
		asanRZ = redZoneSize(size)
		size += asanRZ
	}

	// Assist the GC if needed.
	if gcBlackenEnabled != 0 {
		deductAssistCredit(size)
	}

	// Actually do the allocation.
	var x unsafe.Pointer
	var elemsize uintptr
	if size <= maxSmallSize-mallocHeaderSize {
		if typ == nil || !typ.Pointers() {
			if size < maxTinySize {
				x, elemsize = mallocgcTiny(size, typ, needzero)
			} else {
				x, elemsize = mallocgcSmallNoscan(size, typ, needzero)
			}
		} else if heapBitsInSpan(size) {
			x, elemsize = mallocgcSmallScanNoHeader(size, typ, needzero)
		} else {
			x, elemsize = mallocgcSmallScanHeader(size, typ, needzero)
		}
	} else {
		x, elemsize = mallocgcLarge(size, typ, needzero)
	}

	// Notify sanitizers, if enabled.
	if raceenabled {
		racemalloc(x, size-asanRZ)
	}
	if msanenabled {
		msanmalloc(x, size-asanRZ)
	}
	if asanenabled {
		// Poison the space between the end of the requested size of x
		// and the end of the slot. Unpoison the requested allocation.
		frag := elemsize - size
		if typ != nil && typ.Pointers() && !heapBitsInSpan(elemsize) && size <= maxSmallSize-mallocHeaderSize {
			frag -= mallocHeaderSize
		}
		asanpoison(unsafe.Add(x, size-asanRZ), asanRZ)
		asanunpoison(x, size-asanRZ)
	}

	// Adjust our GC assist debt to account for internal fragmentation.
	if gcBlackenEnabled != 0 && elemsize != 0 {
		if assistG := getg().m.curg; assistG != nil {
			assistG.gcAssistBytes -= int64(elemsize - size)
		}
	}

	// Post-malloc debug hooks.
	if debug.malloc {
		postMallocgcDebug(x, elemsize, typ)
	}
	return x
}

func mallocgcTiny(size uintptr, typ *_type, needzero bool) (unsafe.Pointer, uintptr) {
	// Set mp.mallocing to keep from being preempted by GC.
	mp := acquirem()
	if doubleCheckMalloc {
		if mp.mallocing != 0 {
			throw("malloc deadlock")
		}
		if mp.gsignal == getg() {
			throw("malloc during signal")
		}
		if typ != nil && typ.Pointers() {
			throw("expected noscan for tiny alloc")
		}
	}
	mp.mallocing = 1

	// Tiny allocator.
	//
	// Tiny allocator combines several tiny allocation requests
	// into a single memory block. The resulting memory block
	// is freed when all subobjects are unreachable. The subobjects
	// must be noscan (don't have pointers), this ensures that
	// the amount of potentially wasted memory is bounded.
	//
	// Size of the memory block used for combining (maxTinySize) is tunable.
	// Current setting is 16 bytes, which relates to 2x worst case memory
	// wastage (when all but one subobjects are unreachable).
	// 8 bytes would result in no wastage at all, but provides less
	// opportunities for combining.
	// 32 bytes provides more opportunities for combining,
	// but can lead to 4x worst case wastage.
	// The best case winning is 8x regardless of block size.
	//
	// Objects obtained from tiny allocator must not be freed explicitly.
	// So when an object will be freed explicitly, we ensure that
	// its size >= maxTinySize.
	//
	// SetFinalizer has a special case for objects potentially coming
	// from tiny allocator, it such case it allows to set finalizers
	// for an inner byte of a memory block.
	//
	// The main targets of tiny allocator are small strings and
	// standalone escaping variables. On a json benchmark
	// the allocator reduces number of allocations by ~12% and
	// reduces heap size by ~20%.
	c := getMCache(mp)
	off := c.tinyoffset
	// Align tiny pointer for required (conservative) alignment.
	if size&7 == 0 {
		off = alignUp(off, 8)
	} else if goarch.PtrSize == 4 && size == 12 {
		// Conservatively align 12-byte objects to 8 bytes on 32-bit
		// systems so that objects whose first field is a 64-bit
		// value is aligned to 8 bytes and does not cause a fault on
		// atomic access. See issue 37262.
		// TODO(mknyszek): Remove this workaround if/when issue 36606
		// is resolved.
		off = alignUp(off, 8)
	} else if size&3 == 0 {
		off = alignUp(off, 4)
	} else if size&1 == 0 {
		off = alignUp(off, 2)
	}
	if off+size <= maxTinySize && c.tiny != 0 {
		// The object fits into existing tiny block.
		x := unsafe.Pointer(c.tiny + off)
		c.tinyoffset = off + size
		c.tinyAllocs++
		mp.mallocing = 0
		releasem(mp)
		return x, 0
	}
	// Allocate a new maxTinySize block.
	checkGCTrigger := false
	span := c.alloc[tinySpanClass]
	v := nextFreeFast(span)
	if v == 0 {
		v, span, checkGCTrigger = c.nextFree(tinySpanClass)
	}
	x := unsafe.Pointer(v)
	(*[2]uint64)(x)[0] = 0
	(*[2]uint64)(x)[1] = 0
	// See if we need to replace the existing tiny block with the new one
	// based on amount of remaining free space.
	if !raceenabled && (size < c.tinyoffset || c.tiny == 0) {
		// Note: disabled when race detector is on, see comment near end of this function.
		c.tiny = uintptr(x)
		c.tinyoffset = size
	}

	// Ensure that the stores above that initialize x to
	// type-safe memory and set the heap bits occur before
	// the caller can make x observable to the garbage
	// collector. Otherwise, on weakly ordered machines,
	// the garbage collector could follow a pointer to x,
	// but see uninitialized memory or stale heap bits.
	publicationBarrier()
	// As x and the heap bits are initialized, update
	// freeIndexForScan now so x is seen by the GC
	// (including conservative scan) as an allocated object.
	// While this pointer can't escape into user code as a
	// _live_ pointer until we return, conservative scanning
	// may find a dead pointer that happens to point into this
	// object. Delaying this update until now ensures that
	// conservative scanning considers this pointer dead until
	// this point.
	span.freeIndexForScan = span.freeindex

	// Allocate black during GC.
	// All slots hold nil so no scanning is needed.
	// This may be racing with GC so do it atomically if there can be
	// a race marking the bit.
	if writeBarrier.enabled {
		gcmarknewobject(span, uintptr(x))
	}

	// Note cache c only valid while m acquired; see #47302
	//
	// N.B. Use the full size because that matches how the GC
	// will update the mem profile on the "free" side.
	//
	// TODO(mknyszek): We should really count the header as part
	// of gc_sys or something. The code below just pretends it is
	// internal fragmentation and matches the GC's accounting by
	// using the whole allocation slot.
	c.nextSample -= int64(span.elemsize)
	if c.nextSample < 0 || MemProfileRate != c.memProfRate {
		profilealloc(mp, x, span.elemsize)
	}
	mp.mallocing = 0
	releasem(mp)

	if checkGCTrigger {
		if t := (gcTrigger{kind: gcTriggerHeap}); t.test() {
			gcStart(t)
		}
	}

	if raceenabled {
		// Pad tinysize allocations so they are aligned with the end
		// of the tinyalloc region. This ensures that any arithmetic
		// that goes off the top end of the object will be detectable
		// by checkptr (issue 38872).
		// Note that we disable tinyalloc when raceenabled for this to work.
		// TODO: This padding is only performed when the race detector
		// is enabled. It would be nice to enable it if any package
		// was compiled with checkptr, but there's no easy way to
		// detect that (especially at compile time).
		// TODO: enable this padding for all allocations, not just
		// tinyalloc ones. It's tricky because of pointer maps.
		// Maybe just all noscan objects?
		x = add(x, span.elemsize-size)
	}
	return x, span.elemsize
}

func mallocgcSmallNoscan(size uintptr, typ *_type, needzero bool) (unsafe.Pointer, uintptr) {
	// Set mp.mallocing to keep from being preempted by GC.
	mp := acquirem()
	if doubleCheckMalloc {
		if mp.mallocing != 0 {
			throw("malloc deadlock")
		}
		if mp.gsignal == getg() {
			throw("malloc during signal")
		}
		if typ != nil && typ.Pointers() {
			throw("expected noscan type for noscan alloc")
		}
	}
	mp.mallocing = 1

	checkGCTrigger := false
	c := getMCache(mp)
	var sizeclass uint8
	if size <= smallSizeMax-8 {
		sizeclass = size_to_class8[divRoundUp(size, smallSizeDiv)]
	} else {
		sizeclass = size_to_class128[divRoundUp(size-smallSizeMax, largeSizeDiv)]
	}
	size = uintptr(class_to_size[sizeclass])
	spc := makeSpanClass(sizeclass, true)
	span := c.alloc[spc]
	v := nextFreeFast(span)
	if v == 0 {
		v, span, checkGCTrigger = c.nextFree(spc)
	}
	x := unsafe.Pointer(v)
	if needzero && span.needzero != 0 {
		memclrNoHeapPointers(x, size)
	}

	// Ensure that the stores above that initialize x to
	// type-safe memory and set the heap bits occur before
	// the caller can make x observable to the garbage
	// collector. Otherwise, on weakly ordered machines,
	// the garbage collector could follow a pointer to x,
	// but see uninitialized memory or stale heap bits.
	publicationBarrier()
	// As x and the heap bits are initialized, update
	// freeIndexForScan now so x is seen by the GC
	// (including conservative scan) as an allocated object.
	// While this pointer can't escape into user code as a
	// _live_ pointer until we return, conservative scanning
	// may find a dead pointer that happens to point into this
	// object. Delaying this update until now ensures that
	// conservative scanning considers this pointer dead until
	// this point.
	span.freeIndexForScan = span.freeindex

	// Allocate black during GC.
	// All slots hold nil so no scanning is needed.
	// This may be racing with GC so do it atomically if there can be
	// a race marking the bit.
	if writeBarrier.enabled {
		gcmarknewobject(span, uintptr(x))
	}

	// Note cache c only valid while m acquired; see #47302
	//
	// N.B. Use the full size because that matches how the GC
	// will update the mem profile on the "free" side.
	//
	// TODO(mknyszek): We should really count the header as part
	// of gc_sys or something. The code below just pretends it is
	// internal fragmentation and matches the GC's accounting by
	// using the whole allocation slot.
	c.nextSample -= int64(size)
	if c.nextSample < 0 || MemProfileRate != c.memProfRate {
		profilealloc(mp, x, size)
	}
	mp.mallocing = 0
	releasem(mp)

	if checkGCTrigger {
		if t := (gcTrigger{kind: gcTriggerHeap}); t.test() {
			gcStart(t)
		}
	}
	return x, size
}

func mallocgcSmallScanNoHeader(size uintptr, typ *_type, needzero bool) (unsafe.Pointer, uintptr) {
	// Set mp.mallocing to keep from being preempted by GC.
	mp := acquirem()
	if doubleCheckMalloc {
		if mp.mallocing != 0 {
			throw("malloc deadlock")
		}
		if mp.gsignal == getg() {
			throw("malloc during signal")
		}
		if typ == nil || !typ.Pointers() {
			throw("noscan allocated in scan-only path")
		}
		if !heapBitsInSpan(size) {
			throw("heap bits in not in span for non-header-only path")
		}
	}
	mp.mallocing = 1

	checkGCTrigger := false
	c := getMCache(mp)
	sizeclass := size_to_class8[divRoundUp(size, smallSizeDiv)]
	spc := makeSpanClass(sizeclass, false)
	span := c.alloc[spc]
	v := nextFreeFast(span)
	if v == 0 {
		v, span, checkGCTrigger = c.nextFree(spc)
	}
	x := unsafe.Pointer(v)
	if needzero && span.needzero != 0 {
		memclrNoHeapPointers(x, size)
	}
	if goarch.PtrSize == 8 && sizeclass == 1 {
		// initHeapBits already set the pointer bits for the 8-byte sizeclass
		// on 64-bit platforms.
		c.scanAlloc += 8
	} else {
		c.scanAlloc += heapSetTypeNoHeader(uintptr(x), size, typ, span)
	}
	size = uintptr(class_to_size[sizeclass])

	// Ensure that the stores above that initialize x to
	// type-safe memory and set the heap bits occur before
	// the caller can make x observable to the garbage
	// collector. Otherwise, on weakly ordered machines,
	// the garbage collector could follow a pointer to x,
	// but see uninitialized memory or stale heap bits.
	publicationBarrier()
	// As x and the heap bits are initialized, update
	// freeIndexForScan now so x is seen by the GC
	// (including conservative scan) as an allocated object.
	// While this pointer can't escape into user code as a
	// _live_ pointer until we return, conservative scanning
	// may find a dead pointer that happens to point into this
	// object. Delaying this update until now ensures that
	// conservative scanning considers this pointer dead until
	// this point.
	span.freeIndexForScan = span.freeindex

	// Allocate black during GC.
	// All slots hold nil so no scanning is needed.
	// This may be racing with GC so do it atomically if there can be
	// a race marking the bit.
	if writeBarrier.enabled {
		gcmarknewobject(span, uintptr(x))
	}

	// Note cache c only valid while m acquired; see #47302
	//
	// N.B. Use the full size because that matches how the GC
	// will update the mem profile on the "free" side.
	//
	// TODO(mknyszek): We should really count the header as part
	// of gc_sys or something. The code below just pretends it is
	// internal fragmentation and matches the GC's accounting by
	// using the whole allocation slot.
	c.nextSample -= int64(size)
	if c.nextSample < 0 || MemProfileRate != c.memProfRate {
		profilealloc(mp, x, size)
	}
	mp.mallocing = 0
	releasem(mp)

	if checkGCTrigger {
		if t := (gcTrigger{kind: gcTriggerHeap}); t.test() {
			gcStart(t)
		}
	}
	return x, size
}

func mallocgcSmallScanHeader(size uintptr, typ *_type, needzero bool) (unsafe.Pointer, uintptr) {
	// Set mp.mallocing to keep from being preempted by GC.
	mp := acquirem()
	if doubleCheckMalloc {
		if mp.mallocing != 0 {
			throw("malloc deadlock")
		}
		if mp.gsignal == getg() {
			throw("malloc during signal")
		}
		if typ == nil || !typ.Pointers() {
			throw("noscan allocated in scan-only path")
		}
		if heapBitsInSpan(size) {
			throw("heap bits in span for header-only path")
		}
	}
	mp.mallocing = 1

	checkGCTrigger := false
	c := getMCache(mp)
	size += mallocHeaderSize
	var sizeclass uint8
	if size <= smallSizeMax-8 {
		sizeclass = size_to_class8[divRoundUp(size, smallSizeDiv)]
	} else {
		sizeclass = size_to_class128[divRoundUp(size-smallSizeMax, largeSizeDiv)]
	}
	size = uintptr(class_to_size[sizeclass])
	spc := makeSpanClass(sizeclass, false)
	span := c.alloc[spc]
	v := nextFreeFast(span)
	if v == 0 {
		v, span, checkGCTrigger = c.nextFree(spc)
	}
	x := unsafe.Pointer(v)
	if needzero && span.needzero != 0 {
		memclrNoHeapPointers(x, size)
	}
	header := (**_type)(x)
	x = add(x, mallocHeaderSize)
	c.scanAlloc += heapSetTypeSmallHeader(uintptr(x), size-mallocHeaderSize, typ, header, span)

	// Ensure that the stores above that initialize x to
	// type-safe memory and set the heap bits occur before
	// the caller can make x observable to the garbage
	// collector. Otherwise, on weakly ordered machines,
	// the garbage collector could follow a pointer to x,
	// but see uninitialized memory or stale heap bits.
	publicationBarrier()
	// As x and the heap bits are initialized, update
	// freeIndexForScan now so x is seen by the GC
	// (including conservative scan) as an allocated object.
	// While this pointer can't escape into user code as a
	// _live_ pointer until we return, conservative scanning
	// may find a dead pointer that happens to point into this
	// object. Delaying this update until now ensures that
	// conservative scanning considers this pointer dead until
	// this point.
	span.freeIndexForScan = span.freeindex

	// Allocate black during GC.
	// All slots hold nil so no scanning is needed.
	// This may be racing with GC so do it atomically if there can be
	// a race marking the bit.
	if writeBarrier.enabled {
		gcmarknewobject(span, uintptr(x))
	}

	// Note cache c only valid while m acquired; see #47302
	//
	// N.B. Use the full size because that matches how the GC
	// will update the mem profile on the "free" side.
	//
	// TODO(mknyszek): We should really count the header as part
	// of gc_sys or something. The code below just pretends it is
	// internal fragmentation and matches the GC's accounting by
	// using the whole allocation slot.
	c.nextSample -= int64(size)
	if c.nextSample < 0 || MemProfileRate != c.memProfRate {
		profilealloc(mp, x, size)
	}
	mp.mallocing = 0
	releasem(mp)

	if checkGCTrigger {
		if t := (gcTrigger{kind: gcTriggerHeap}); t.test() {
			gcStart(t)
		}
	}
	return x, size
}

func mallocgcLarge(size uintptr, typ *_type, needzero bool) (unsafe.Pointer, uintptr) {
	// Set mp.mallocing to keep from being preempted by GC.
	mp := acquirem()
	if doubleCheckMalloc {
		if mp.mallocing != 0 {
			throw("malloc deadlock")
		}
		if mp.gsignal == getg() {
			throw("malloc during signal")
		}
	}
	mp.mallocing = 1

	c := getMCache(mp)
	// For large allocations, keep track of zeroed state so that
	// bulk zeroing can be happen later in a preemptible context.
	span := c.allocLarge(size, typ == nil || !typ.Pointers())
	span.freeindex = 1
	span.allocCount = 1
	span.largeType = nil // Tell the GC not to look at this yet.
	size = span.elemsize
	x := unsafe.Pointer(span.base())

	// Ensure that the stores above that initialize x to
	// type-safe memory and set the heap bits occur before
	// the caller can make x observable to the garbage
	// collector. Otherwise, on weakly ordered machines,
	// the garbage collector could follow a pointer to x,
	// but see uninitialized memory or stale heap bits.
	publicationBarrier()
	// As x and the heap bits are initialized, update
	// freeIndexForScan now so x is seen by the GC
	// (including conservative scan) as an allocated object.
	// While this pointer can't escape into user code as a
	// _live_ pointer until we return, conservative scanning
	// may find a dead pointer that happens to point into this
	// object. Delaying this update until now ensures that
	// conservative scanning considers this pointer dead until
	// this point.
	span.freeIndexForScan = span.freeindex

	// Allocate black during GC.
	// All slots hold nil so no scanning is needed.
	// This may be racing with GC so do it atomically if there can be
	// a race marking the bit.
	if writeBarrier.enabled {
		gcmarknewobject(span, uintptr(x))
	}

	// Note cache c only valid while m acquired; see #47302
	//
	// N.B. Use the full size because that matches how the GC
	// will update the mem profile on the "free" side.
	//
	// TODO(mknyszek): We should really count the header as part
	// of gc_sys or something. The code below just pretends it is
	// internal fragmentation and matches the GC's accounting by
	// using the whole allocation slot.
	c.nextSample -= int64(size)
	if c.nextSample < 0 || MemProfileRate != c.memProfRate {
		profilealloc(mp, x, size)
	}
	mp.mallocing = 0
	releasem(mp)

	// Check to see if we need to trigger the GC.
	if t := (gcTrigger{kind: gcTriggerHeap}); t.test() {
		gcStart(t)
	}

	// Objects can be zeroed late in a context where preemption can occur.
	// If the object contains pointers, its pointer data must be cleared
	// or otherwise indicate that the GC shouldn't scan it.
	// x will keep the memory alive.
	if noscan := typ == nil || !typ.Pointers(); !noscan || (needzero && span.needzero != 0) {
		// N.B. size == fullSize always in this case.
		memclrNoHeapPointersChunked(size, x) // This is a possible preemption point: see #47302

		// Finish storing the type information for this case.
		mp := acquirem()
		if !noscan {
			getMCache(mp).scanAlloc += heapSetTypeLarge(uintptr(x), size, typ, span)
		}
		// Publish the object with the now-zeroed memory.
		publicationBarrier()
		releasem(mp)
	}
	return x, size
}

func preMallocgcDebug(size uintptr, typ *_type) unsafe.Pointer {
	if debug.sbrk != 0 {
		align := uintptr(16)
		if typ != nil {
			// TODO(austin): This should be just
			//   align = uintptr(typ.align)
			// but that's only 4 on 32-bit platforms,
			// even if there's a uint64 field in typ (see #599).
			// This causes 64-bit atomic accesses to panic.
			// Hence, we use stricter alignment that matches
			// the normal allocator better.
			if size&7 == 0 {
				align = 8
			} else if size&3 == 0 {
				align = 4
			} else if size&1 == 0 {
				align = 2
			} else {
				align = 1
			}
		}
		return persistentalloc(size, align, &memstats.other_sys)
	}
	if inittrace.active && inittrace.id == getg().goid {
		// Init functions are executed sequentially in a single goroutine.
		inittrace.allocs += 1
	}
	return nil
}

func postMallocgcDebug(x unsafe.Pointer, elemsize uintptr, typ *_type) {
	if inittrace.active && inittrace.id == getg().goid {
		// Init functions are executed sequentially in a single goroutine.
		inittrace.bytes += uint64(elemsize)
	}

	if traceAllocFreeEnabled() {
		trace := traceAcquire()
		if trace.ok() {
			trace.HeapObjectAlloc(uintptr(x), typ)
			traceRelease(trace)
		}
	}
}

// deductAssistCredit reduces the current G's assist credit
// by size bytes, and assists the GC if necessary.
//
// Caller must be preemptible.
//
// Returns the G for which the assist credit was accounted.
func deductAssistCredit(size uintptr) {
	// Charge the current user G for this allocation.
	assistG := getg()
	if assistG.m.curg != nil {
		assistG = assistG.m.curg
	}
	// Charge the allocation against the G. We'll account
	// for internal fragmentation at the end of mallocgc.
	assistG.gcAssistBytes -= int64(size)

	if assistG.gcAssistBytes < 0 {
		// This G is in debt. Assist the GC to correct
		// this before allocating. This must happen
		// before disabling preemption.
		gcAssistAlloc(assistG)
	}
}

// memclrNoHeapPointersChunked repeatedly calls memclrNoHeapPointers
// on chunks of the buffer to be zeroed, with opportunities for preemption
// along the way.  memclrNoHeapPointers contains no safepoints and also
// cannot be preemptively scheduled, so this provides a still-efficient
// block copy that can also be preempted on a reasonable granularity.
//
// Use this with care; if the data being cleared is tagged to contain
// pointers, this allows the GC to run before it is all cleared.
func memclrNoHeapPointersChunked(size uintptr, x unsafe.Pointer) {
	v := uintptr(x)
	// got this from benchmarking. 128k is too small, 512k is too large.
	const chunkBytes = 256 * 1024
	vsize := v + size
	for voff := v; voff < vsize; voff = voff + chunkBytes {
		if getg().preempt {
			// may hold locks, e.g., profiling
			goschedguarded()
		}
		// clear min(avail, lump) bytes
		n := vsize - voff
		if n > chunkBytes {
			n = chunkBytes
		}
		memclrNoHeapPointers(unsafe.Pointer(voff), n)
	}
}

// implementation of new builtin
// compiler (both frontend and SSA backend) knows the signature
// of this function.
func newobject(typ *_type) unsafe.Pointer {
	return mallocgc(typ.Size_, typ, true)
}

//go:linkname maps_newobject internal/runtime/maps.newobject
func maps_newobject(typ *_type) unsafe.Pointer {
	return newobject(typ)
}

// reflect_unsafe_New is meant for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/goccy/json
//   - github.com/modern-go/reflect2
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_unsafe_New reflect.unsafe_New
func reflect_unsafe_New(typ *_type) unsafe.Pointer {
	return mallocgc(typ.Size_, typ, true)
}

//go:linkname reflectlite_unsafe_New internal/reflectlite.unsafe_New
func reflectlite_unsafe_New(typ *_type) unsafe.Pointer {
	return mallocgc(typ.Size_, typ, true)
}

// newarray allocates an array of n elements of type typ.
//
// newarray should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/RomiChan/protobuf
//   - github.com/segmentio/encoding
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname newarray
func newarray(typ *_type, n int) unsafe.Pointer {
	if n == 1 {
		return mallocgc(typ.Size_, typ, true)
	}
	mem, overflow := math.MulUintptr(typ.Size_, uintptr(n))
	if overflow || mem > maxAlloc || n < 0 {
		panic(plainError("runtime: allocation size out of range"))
	}
	return mallocgc(mem, typ, true)
}

// reflect_unsafe_NewArray is meant for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/bytedance/sonic
//   - github.com/goccy/json
//   - github.com/modern-go/reflect2
//   - github.com/segmentio/encoding
//   - github.com/segmentio/kafka-go
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_unsafe_NewArray reflect.unsafe_NewArray
func reflect_unsafe_NewArray(typ *_type, n int) unsafe.Pointer {
	return newarray(typ, n)
}

//go:linkname maps_newarray internal/runtime/maps.newarray
func maps_newarray(typ *_type, n int) unsafe.Pointer {
	return newarray(typ, n)
}

// profilealloc resets the current mcache's nextSample counter and
// records a memory profile sample.
//
// The caller must be non-preemptible and have a P.
func profilealloc(mp *m, x unsafe.Pointer, size uintptr) {
	c := getMCache(mp)
	if c == nil {
		throw("profilealloc called without a P or outside bootstrapping")
	}
	c.memProfRate = MemProfileRate
	c.nextSample = nextSample()
	mProf_Malloc(mp, x, size)
}

// nextSample returns the next sampling point for heap profiling. The goal is
// to sample allocations on average every MemProfileRate bytes, but with a
// completely random distribution over the allocation timeline; this
// corresponds to a Poisson process with parameter MemProfileRate. In Poisson
// processes, the distance between two samples follows the exponential
// distribution (exp(MemProfileRate)), so the best return value is a random
// number taken from an exponential distribution whose mean is MemProfileRate.
func nextSample() int64 {
	if MemProfileRate == 0 {
		// Basically never sample.
		return maxInt64
	}
	if MemProfileRate == 1 {
		// Sample immediately.
		return 0
	}
	if GOOS == "plan9" {
		// Plan 9 doesn't support floating point in note handler.
		if gp := getg(); gp == gp.m.gsignal {
			return nextSampleNoFP()
		}
	}

	return int64(fastexprand(MemProfileRate))
}

// fastexprand returns a random number from an exponential distribution with
// the specified mean.
func fastexprand(mean int) int32 {
	// Avoid overflow. Maximum possible step is
	// -ln(1/(1<<randomBitCount)) * mean, approximately 20 * mean.
	switch {
	case mean > 0x7000000:
		mean = 0x7000000
	case mean == 0:
		return 0
	}

	// Take a random sample of the exponential distribution exp(-mean*x).
	// The probability distribution function is mean*exp(-mean*x), so the CDF is
	// p = 1 - exp(-mean*x), so
	// q = 1 - p == exp(-mean*x)
	// log_e(q) = -mean*x
	// -log_e(q)/mean = x
	// x = -log_e(q) * mean
	// x = log_2(q) * (-log_e(2)) * mean    ; Using log_2 for effic
"""




```