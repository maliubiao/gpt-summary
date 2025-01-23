Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part 2 of 3 from `go/src/runtime/mheap.go`.

I need to:
1. Read through the code and identify the key functions and their roles.
2. Summarize the overall purpose and interactions of these functions.
3. Focus on the functionality contained within this specific part of the file.
这段代码是 `go/src/runtime/mheap.go` 文件的一部分，主要负责**堆内存的分配和管理**，特别是针对 `mspan` 结构体的分配、初始化、以及与 `special` 记录相关的操作。

具体来说，它涵盖了以下几个关键功能：

1. **`mspan` 的分配与释放**:
    - 提供了从堆上分配和释放 `mspan` 的机制，包括普通堆分配 (`alloc`) 和手动管理分配 (`allocManual`)。
    - 实现了 `mspan` 对象的缓存机制，以提高分配效率 (`tryAllocMSpan`, `allocMSpanLocked`, `freeMSpanLocked`)。
    - 提供了底层的 `allocSpan` 函数，用于分配指定大小的内存页，并关联到一个 `mspan`。

2. **`mspan` 的初始化**:
    - `initSpan` 函数负责初始化新分配的 `mspan`，包括设置起始地址、页数、是否需要清零、以及管理普通堆分配的元数据（如 `spanclass`、对象大小、`allocBits`、`gcmarkBits` 等）。

3. **内存页的分配与管理**:
    - `alloc` 函数在分配 `mspan` 前，会进行必要的垃圾回收和内存回收 (`reclaim`)。
    - `allocSpan` 内部使用 `h.pages` 对象来管理实际的内存页分配，并处理物理页对齐的需求。
    - `grow` 函数负责在当前 arena 不足以分配时，向操作系统申请更多的内存。
    - `freeSpan` 和 `freeSpanLocked` 函数将 `mspan` 释放回堆，并更新相关的统计信息。

4. **内存清零管理**:
    - `allocNeedsZero` 函数用于检查新分配的内存区域是否需要清零，并更新相关的堆元数据。

5. **`mspan` 状态管理**:
    - 使用 `mSpanState` 来跟踪 `mspan` 的状态（如 `mSpanManual`, `mSpanInUse`, `mSpanDead`）。

6. **跨越 arena 的 `mspan` 管理**:
    - `setSpans` 函数用于更新 span map，将指定范围的地址映射到给定的 `mspan`，这可以处理跨越多个 arena 的 `mspan`。

7. **手动管理的 `mspan`**:
    - 提供了 `allocManual` 和 `freeManual` 用于分配和释放手动管理的 `mspan`，这些 `mspan` 不参与正常的垃圾回收。

8. **`special` 记录的管理**:
    - 提供了 `addspecial` 和 `removespecial` 函数，用于管理与特定对象关联的 `special` 记录（如 finalizer、weak handle 等）。
    - `specialFindSplicePoint` 用于在 `special` 列表中查找插入点或已存在的记录。
    - `spanHasSpecials` 和 `spanHasNoSpecials` 用于在 arena bitmap 中标记 span 是否包含 `special` 记录。

9. **垃圾回收辅助**:
    - `allocSpan` 中包含在分配后进行 scavenging 的逻辑，以满足内存限制或堆增长的需要。
    - `scavengeAll` 函数强制回收所有可回收的空闲内存页。

总而言之，这段代码是 Go 语言运行时系统中核心的内存管理模块的一部分，它负责管理堆内存的分配、释放、以及与垃圾回收相关的元数据。它通过 `mspan` 这一核心数据结构来组织和管理内存页，并提供了一系列函数来操作这些 `mspan`。此外，它还处理了手动管理的内存分配以及与对象关联的特殊记录的管理。

### 提示词
```
这是路径为go/src/runtime/mheap.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
anual returns true if the span allocation is manually managed.
func (s spanAllocType) manual() bool {
	return s != spanAllocHeap
}

// alloc allocates a new span of npage pages from the GC'd heap.
//
// spanclass indicates the span's size class and scannability.
//
// Returns a span that has been fully initialized. span.needzero indicates
// whether the span has been zeroed. Note that it may not be.
func (h *mheap) alloc(npages uintptr, spanclass spanClass) *mspan {
	// Don't do any operations that lock the heap on the G stack.
	// It might trigger stack growth, and the stack growth code needs
	// to be able to allocate heap.
	var s *mspan
	systemstack(func() {
		// To prevent excessive heap growth, before allocating n pages
		// we need to sweep and reclaim at least n pages.
		if !isSweepDone() {
			h.reclaim(npages)
		}
		s = h.allocSpan(npages, spanAllocHeap, spanclass)
	})
	return s
}

// allocManual allocates a manually-managed span of npage pages.
// allocManual returns nil if allocation fails.
//
// allocManual adds the bytes used to *stat, which should be a
// memstats in-use field. Unlike allocations in the GC'd heap, the
// allocation does *not* count toward heapInUse.
//
// The memory backing the returned span may not be zeroed if
// span.needzero is set.
//
// allocManual must be called on the system stack because it may
// acquire the heap lock via allocSpan. See mheap for details.
//
// If new code is written to call allocManual, do NOT use an
// existing spanAllocType value and instead declare a new one.
//
//go:systemstack
func (h *mheap) allocManual(npages uintptr, typ spanAllocType) *mspan {
	if !typ.manual() {
		throw("manual span allocation called with non-manually-managed type")
	}
	return h.allocSpan(npages, typ, 0)
}

// setSpans modifies the span map so [spanOf(base), spanOf(base+npage*pageSize))
// is s.
func (h *mheap) setSpans(base, npage uintptr, s *mspan) {
	p := base / pageSize
	ai := arenaIndex(base)
	ha := h.arenas[ai.l1()][ai.l2()]
	for n := uintptr(0); n < npage; n++ {
		i := (p + n) % pagesPerArena
		if i == 0 {
			ai = arenaIndex(base + n*pageSize)
			ha = h.arenas[ai.l1()][ai.l2()]
		}
		ha.spans[i] = s
	}
}

// allocNeedsZero checks if the region of address space [base, base+npage*pageSize),
// assumed to be allocated, needs to be zeroed, updating heap arena metadata for
// future allocations.
//
// This must be called each time pages are allocated from the heap, even if the page
// allocator can otherwise prove the memory it's allocating is already zero because
// they're fresh from the operating system. It updates heapArena metadata that is
// critical for future page allocations.
//
// There are no locking constraints on this method.
func (h *mheap) allocNeedsZero(base, npage uintptr) (needZero bool) {
	for npage > 0 {
		ai := arenaIndex(base)
		ha := h.arenas[ai.l1()][ai.l2()]

		zeroedBase := atomic.Loaduintptr(&ha.zeroedBase)
		arenaBase := base % heapArenaBytes
		if arenaBase < zeroedBase {
			// We extended into the non-zeroed part of the
			// arena, so this region needs to be zeroed before use.
			//
			// zeroedBase is monotonically increasing, so if we see this now then
			// we can be sure we need to zero this memory region.
			//
			// We still need to update zeroedBase for this arena, and
			// potentially more arenas.
			needZero = true
		}
		// We may observe arenaBase > zeroedBase if we're racing with one or more
		// allocations which are acquiring memory directly before us in the address
		// space. But, because we know no one else is acquiring *this* memory, it's
		// still safe to not zero.

		// Compute how far into the arena we extend into, capped
		// at heapArenaBytes.
		arenaLimit := arenaBase + npage*pageSize
		if arenaLimit > heapArenaBytes {
			arenaLimit = heapArenaBytes
		}
		// Increase ha.zeroedBase so it's >= arenaLimit.
		// We may be racing with other updates.
		for arenaLimit > zeroedBase {
			if atomic.Casuintptr(&ha.zeroedBase, zeroedBase, arenaLimit) {
				break
			}
			zeroedBase = atomic.Loaduintptr(&ha.zeroedBase)
			// Double check basic conditions of zeroedBase.
			if zeroedBase <= arenaLimit && zeroedBase > arenaBase {
				// The zeroedBase moved into the space we were trying to
				// claim. That's very bad, and indicates someone allocated
				// the same region we did.
				throw("potentially overlapping in-use allocations detected")
			}
		}

		// Move base forward and subtract from npage to move into
		// the next arena, or finish.
		base += arenaLimit - arenaBase
		npage -= (arenaLimit - arenaBase) / pageSize
	}
	return
}

// tryAllocMSpan attempts to allocate an mspan object from
// the P-local cache, but may fail.
//
// h.lock need not be held.
//
// This caller must ensure that its P won't change underneath
// it during this function. Currently to ensure that we enforce
// that the function is run on the system stack, because that's
// the only place it is used now. In the future, this requirement
// may be relaxed if its use is necessary elsewhere.
//
//go:systemstack
func (h *mheap) tryAllocMSpan() *mspan {
	pp := getg().m.p.ptr()
	// If we don't have a p or the cache is empty, we can't do
	// anything here.
	if pp == nil || pp.mspancache.len == 0 {
		return nil
	}
	// Pull off the last entry in the cache.
	s := pp.mspancache.buf[pp.mspancache.len-1]
	pp.mspancache.len--
	return s
}

// allocMSpanLocked allocates an mspan object.
//
// h.lock must be held.
//
// allocMSpanLocked must be called on the system stack because
// its caller holds the heap lock. See mheap for details.
// Running on the system stack also ensures that we won't
// switch Ps during this function. See tryAllocMSpan for details.
//
//go:systemstack
func (h *mheap) allocMSpanLocked() *mspan {
	assertLockHeld(&h.lock)

	pp := getg().m.p.ptr()
	if pp == nil {
		// We don't have a p so just do the normal thing.
		return (*mspan)(h.spanalloc.alloc())
	}
	// Refill the cache if necessary.
	if pp.mspancache.len == 0 {
		const refillCount = len(pp.mspancache.buf) / 2
		for i := 0; i < refillCount; i++ {
			pp.mspancache.buf[i] = (*mspan)(h.spanalloc.alloc())
		}
		pp.mspancache.len = refillCount
	}
	// Pull off the last entry in the cache.
	s := pp.mspancache.buf[pp.mspancache.len-1]
	pp.mspancache.len--
	return s
}

// freeMSpanLocked free an mspan object.
//
// h.lock must be held.
//
// freeMSpanLocked must be called on the system stack because
// its caller holds the heap lock. See mheap for details.
// Running on the system stack also ensures that we won't
// switch Ps during this function. See tryAllocMSpan for details.
//
//go:systemstack
func (h *mheap) freeMSpanLocked(s *mspan) {
	assertLockHeld(&h.lock)

	pp := getg().m.p.ptr()
	// First try to free the mspan directly to the cache.
	if pp != nil && pp.mspancache.len < len(pp.mspancache.buf) {
		pp.mspancache.buf[pp.mspancache.len] = s
		pp.mspancache.len++
		return
	}
	// Failing that (or if we don't have a p), just free it to
	// the heap.
	h.spanalloc.free(unsafe.Pointer(s))
}

// allocSpan allocates an mspan which owns npages worth of memory.
//
// If typ.manual() == false, allocSpan allocates a heap span of class spanclass
// and updates heap accounting. If manual == true, allocSpan allocates a
// manually-managed span (spanclass is ignored), and the caller is
// responsible for any accounting related to its use of the span. Either
// way, allocSpan will atomically add the bytes in the newly allocated
// span to *sysStat.
//
// The returned span is fully initialized.
//
// h.lock must not be held.
//
// allocSpan must be called on the system stack both because it acquires
// the heap lock and because it must block GC transitions.
//
//go:systemstack
func (h *mheap) allocSpan(npages uintptr, typ spanAllocType, spanclass spanClass) (s *mspan) {
	// Function-global state.
	gp := getg()
	base, scav := uintptr(0), uintptr(0)
	growth := uintptr(0)

	// On some platforms we need to provide physical page aligned stack
	// allocations. Where the page size is less than the physical page
	// size, we already manage to do this by default.
	needPhysPageAlign := physPageAlignedStacks && typ == spanAllocStack && pageSize < physPageSize

	// If the allocation is small enough, try the page cache!
	// The page cache does not support aligned allocations, so we cannot use
	// it if we need to provide a physical page aligned stack allocation.
	pp := gp.m.p.ptr()
	if !needPhysPageAlign && pp != nil && npages < pageCachePages/4 {
		c := &pp.pcache

		// If the cache is empty, refill it.
		if c.empty() {
			lock(&h.lock)
			*c = h.pages.allocToCache()
			unlock(&h.lock)
		}

		// Try to allocate from the cache.
		base, scav = c.alloc(npages)
		if base != 0 {
			s = h.tryAllocMSpan()
			if s != nil {
				goto HaveSpan
			}
			// We have a base but no mspan, so we need
			// to lock the heap.
		}
	}

	// For one reason or another, we couldn't get the
	// whole job done without the heap lock.
	lock(&h.lock)

	if needPhysPageAlign {
		// Overallocate by a physical page to allow for later alignment.
		extraPages := physPageSize / pageSize

		// Find a big enough region first, but then only allocate the
		// aligned portion. We can't just allocate and then free the
		// edges because we need to account for scavenged memory, and
		// that's difficult with alloc.
		//
		// Note that we skip updates to searchAddr here. It's OK if
		// it's stale and higher than normal; it'll operate correctly,
		// just come with a performance cost.
		base, _ = h.pages.find(npages + extraPages)
		if base == 0 {
			var ok bool
			growth, ok = h.grow(npages + extraPages)
			if !ok {
				unlock(&h.lock)
				return nil
			}
			base, _ = h.pages.find(npages + extraPages)
			if base == 0 {
				throw("grew heap, but no adequate free space found")
			}
		}
		base = alignUp(base, physPageSize)
		scav = h.pages.allocRange(base, npages)
	}

	if base == 0 {
		// Try to acquire a base address.
		base, scav = h.pages.alloc(npages)
		if base == 0 {
			var ok bool
			growth, ok = h.grow(npages)
			if !ok {
				unlock(&h.lock)
				return nil
			}
			base, scav = h.pages.alloc(npages)
			if base == 0 {
				throw("grew heap, but no adequate free space found")
			}
		}
	}
	if s == nil {
		// We failed to get an mspan earlier, so grab
		// one now that we have the heap lock.
		s = h.allocMSpanLocked()
	}
	unlock(&h.lock)

HaveSpan:
	// Decide if we need to scavenge in response to what we just allocated.
	// Specifically, we track the maximum amount of memory to scavenge of all
	// the alternatives below, assuming that the maximum satisfies *all*
	// conditions we check (e.g. if we need to scavenge X to satisfy the
	// memory limit and Y to satisfy heap-growth scavenging, and Y > X, then
	// it's fine to pick Y, because the memory limit is still satisfied).
	//
	// It's fine to do this after allocating because we expect any scavenged
	// pages not to get touched until we return. Simultaneously, it's important
	// to do this before calling sysUsed because that may commit address space.
	bytesToScavenge := uintptr(0)
	forceScavenge := false
	if limit := gcController.memoryLimit.Load(); !gcCPULimiter.limiting() {
		// Assist with scavenging to maintain the memory limit by the amount
		// that we expect to page in.
		inuse := gcController.mappedReady.Load()
		// Be careful about overflow, especially with uintptrs. Even on 32-bit platforms
		// someone can set a really big memory limit that isn't maxInt64.
		if uint64(scav)+inuse > uint64(limit) {
			bytesToScavenge = uintptr(uint64(scav) + inuse - uint64(limit))
			forceScavenge = true
		}
	}
	if goal := scavenge.gcPercentGoal.Load(); goal != ^uint64(0) && growth > 0 {
		// We just caused a heap growth, so scavenge down what will soon be used.
		// By scavenging inline we deal with the failure to allocate out of
		// memory fragments by scavenging the memory fragments that are least
		// likely to be re-used.
		//
		// Only bother with this because we're not using a memory limit. We don't
		// care about heap growths as long as we're under the memory limit, and the
		// previous check for scaving already handles that.
		if retained := heapRetained(); retained+uint64(growth) > goal {
			// The scavenging algorithm requires the heap lock to be dropped so it
			// can acquire it only sparingly. This is a potentially expensive operation
			// so it frees up other goroutines to allocate in the meanwhile. In fact,
			// they can make use of the growth we just created.
			todo := growth
			if overage := uintptr(retained + uint64(growth) - goal); todo > overage {
				todo = overage
			}
			if todo > bytesToScavenge {
				bytesToScavenge = todo
			}
		}
	}
	// There are a few very limited circumstances where we won't have a P here.
	// It's OK to simply skip scavenging in these cases. Something else will notice
	// and pick up the tab.
	var now int64
	if pp != nil && bytesToScavenge > 0 {
		// Measure how long we spent scavenging and add that measurement to the assist
		// time so we can track it for the GC CPU limiter.
		//
		// Limiter event tracking might be disabled if we end up here
		// while on a mark worker.
		start := nanotime()
		track := pp.limiterEvent.start(limiterEventScavengeAssist, start)

		// Scavenge, but back out if the limiter turns on.
		released := h.pages.scavenge(bytesToScavenge, func() bool {
			return gcCPULimiter.limiting()
		}, forceScavenge)

		mheap_.pages.scav.releasedEager.Add(released)

		// Finish up accounting.
		now = nanotime()
		if track {
			pp.limiterEvent.stop(limiterEventScavengeAssist, now)
		}
		scavenge.assistTime.Add(now - start)
	}

	// Initialize the span.
	h.initSpan(s, typ, spanclass, base, npages)

	// Commit and account for any scavenged memory that the span now owns.
	nbytes := npages * pageSize
	if scav != 0 {
		// sysUsed all the pages that are actually available
		// in the span since some of them might be scavenged.
		sysUsed(unsafe.Pointer(base), nbytes, scav)
		gcController.heapReleased.add(-int64(scav))
	}
	// Update stats.
	gcController.heapFree.add(-int64(nbytes - scav))
	if typ == spanAllocHeap {
		gcController.heapInUse.add(int64(nbytes))
	}
	// Update consistent stats.
	stats := memstats.heapStats.acquire()
	atomic.Xaddint64(&stats.committed, int64(scav))
	atomic.Xaddint64(&stats.released, -int64(scav))
	switch typ {
	case spanAllocHeap:
		atomic.Xaddint64(&stats.inHeap, int64(nbytes))
	case spanAllocStack:
		atomic.Xaddint64(&stats.inStacks, int64(nbytes))
	case spanAllocPtrScalarBits:
		atomic.Xaddint64(&stats.inPtrScalarBits, int64(nbytes))
	case spanAllocWorkBuf:
		atomic.Xaddint64(&stats.inWorkBufs, int64(nbytes))
	}
	memstats.heapStats.release()

	// Trace the span alloc.
	if traceAllocFreeEnabled() {
		trace := traceAcquire()
		if trace.ok() {
			trace.SpanAlloc(s)
			traceRelease(trace)
		}
	}
	return s
}

// initSpan initializes a blank span s which will represent the range
// [base, base+npages*pageSize). typ is the type of span being allocated.
func (h *mheap) initSpan(s *mspan, typ spanAllocType, spanclass spanClass, base, npages uintptr) {
	// At this point, both s != nil and base != 0, and the heap
	// lock is no longer held. Initialize the span.
	s.init(base, npages)
	if h.allocNeedsZero(base, npages) {
		s.needzero = 1
	}
	nbytes := npages * pageSize
	if typ.manual() {
		s.manualFreeList = 0
		s.nelems = 0
		s.limit = s.base() + s.npages*pageSize
		s.state.set(mSpanManual)
	} else {
		// We must set span properties before the span is published anywhere
		// since we're not holding the heap lock.
		s.spanclass = spanclass
		if sizeclass := spanclass.sizeclass(); sizeclass == 0 {
			s.elemsize = nbytes
			s.nelems = 1
			s.divMul = 0
		} else {
			s.elemsize = uintptr(class_to_size[sizeclass])
			if !s.spanclass.noscan() && heapBitsInSpan(s.elemsize) {
				// Reserve space for the pointer/scan bitmap at the end.
				s.nelems = uint16((nbytes - (nbytes / goarch.PtrSize / 8)) / s.elemsize)
			} else {
				s.nelems = uint16(nbytes / s.elemsize)
			}
			s.divMul = class_to_divmagic[sizeclass]
		}

		// Initialize mark and allocation structures.
		s.freeindex = 0
		s.freeIndexForScan = 0
		s.allocCache = ^uint64(0) // all 1s indicating all free.
		s.gcmarkBits = newMarkBits(uintptr(s.nelems))
		s.allocBits = newAllocBits(uintptr(s.nelems))

		// It's safe to access h.sweepgen without the heap lock because it's
		// only ever updated with the world stopped and we run on the
		// systemstack which blocks a STW transition.
		atomic.Store(&s.sweepgen, h.sweepgen)

		// Now that the span is filled in, set its state. This
		// is a publication barrier for the other fields in
		// the span. While valid pointers into this span
		// should never be visible until the span is returned,
		// if the garbage collector finds an invalid pointer,
		// access to the span may race with initialization of
		// the span. We resolve this race by atomically
		// setting the state after the span is fully
		// initialized, and atomically checking the state in
		// any situation where a pointer is suspect.
		s.state.set(mSpanInUse)
	}

	// Publish the span in various locations.

	// This is safe to call without the lock held because the slots
	// related to this span will only ever be read or modified by
	// this thread until pointers into the span are published (and
	// we execute a publication barrier at the end of this function
	// before that happens) or pageInUse is updated.
	h.setSpans(s.base(), npages, s)

	if !typ.manual() {
		// Mark in-use span in arena page bitmap.
		//
		// This publishes the span to the page sweeper, so
		// it's imperative that the span be completely initialized
		// prior to this line.
		arena, pageIdx, pageMask := pageIndexOf(s.base())
		atomic.Or8(&arena.pageInUse[pageIdx], pageMask)

		// Update related page sweeper stats.
		h.pagesInUse.Add(npages)
	}

	// Make sure the newly allocated span will be observed
	// by the GC before pointers into the span are published.
	publicationBarrier()
}

// Try to add at least npage pages of memory to the heap,
// returning how much the heap grew by and whether it worked.
//
// h.lock must be held.
func (h *mheap) grow(npage uintptr) (uintptr, bool) {
	assertLockHeld(&h.lock)

	// We must grow the heap in whole palloc chunks.
	// We call sysMap below but note that because we
	// round up to pallocChunkPages which is on the order
	// of MiB (generally >= to the huge page size) we
	// won't be calling it too much.
	ask := alignUp(npage, pallocChunkPages) * pageSize

	totalGrowth := uintptr(0)
	// This may overflow because ask could be very large
	// and is otherwise unrelated to h.curArena.base.
	end := h.curArena.base + ask
	nBase := alignUp(end, physPageSize)
	if nBase > h.curArena.end || /* overflow */ end < h.curArena.base {
		// Not enough room in the current arena. Allocate more
		// arena space. This may not be contiguous with the
		// current arena, so we have to request the full ask.
		av, asize := h.sysAlloc(ask, &h.arenaHints, true)
		if av == nil {
			inUse := gcController.heapFree.load() + gcController.heapReleased.load() + gcController.heapInUse.load()
			print("runtime: out of memory: cannot allocate ", ask, "-byte block (", inUse, " in use)\n")
			return 0, false
		}

		if uintptr(av) == h.curArena.end {
			// The new space is contiguous with the old
			// space, so just extend the current space.
			h.curArena.end = uintptr(av) + asize
		} else {
			// The new space is discontiguous. Track what
			// remains of the current space and switch to
			// the new space. This should be rare.
			if size := h.curArena.end - h.curArena.base; size != 0 {
				// Transition this space from Reserved to Prepared and mark it
				// as released since we'll be able to start using it after updating
				// the page allocator and releasing the lock at any time.
				sysMap(unsafe.Pointer(h.curArena.base), size, &gcController.heapReleased)
				// Update stats.
				stats := memstats.heapStats.acquire()
				atomic.Xaddint64(&stats.released, int64(size))
				memstats.heapStats.release()
				// Update the page allocator's structures to make this
				// space ready for allocation.
				h.pages.grow(h.curArena.base, size)
				totalGrowth += size
			}
			// Switch to the new space.
			h.curArena.base = uintptr(av)
			h.curArena.end = uintptr(av) + asize
		}

		// Recalculate nBase.
		// We know this won't overflow, because sysAlloc returned
		// a valid region starting at h.curArena.base which is at
		// least ask bytes in size.
		nBase = alignUp(h.curArena.base+ask, physPageSize)
	}

	// Grow into the current arena.
	v := h.curArena.base
	h.curArena.base = nBase

	// Transition the space we're going to use from Reserved to Prepared.
	//
	// The allocation is always aligned to the heap arena
	// size which is always > physPageSize, so its safe to
	// just add directly to heapReleased.
	sysMap(unsafe.Pointer(v), nBase-v, &gcController.heapReleased)

	// The memory just allocated counts as both released
	// and idle, even though it's not yet backed by spans.
	stats := memstats.heapStats.acquire()
	atomic.Xaddint64(&stats.released, int64(nBase-v))
	memstats.heapStats.release()

	// Update the page allocator's structures to make this
	// space ready for allocation.
	h.pages.grow(v, nBase-v)
	totalGrowth += nBase - v
	return totalGrowth, true
}

// Free the span back into the heap.
func (h *mheap) freeSpan(s *mspan) {
	systemstack(func() {
		// Trace the span free.
		if traceAllocFreeEnabled() {
			trace := traceAcquire()
			if trace.ok() {
				trace.SpanFree(s)
				traceRelease(trace)
			}
		}

		lock(&h.lock)
		if msanenabled {
			// Tell msan that this entire span is no longer in use.
			base := unsafe.Pointer(s.base())
			bytes := s.npages << _PageShift
			msanfree(base, bytes)
		}
		if asanenabled {
			// Tell asan that this entire span is no longer in use.
			base := unsafe.Pointer(s.base())
			bytes := s.npages << _PageShift
			asanpoison(base, bytes)
		}
		h.freeSpanLocked(s, spanAllocHeap)
		unlock(&h.lock)
	})
}

// freeManual frees a manually-managed span returned by allocManual.
// typ must be the same as the spanAllocType passed to the allocManual that
// allocated s.
//
// This must only be called when gcphase == _GCoff. See mSpanState for
// an explanation.
//
// freeManual must be called on the system stack because it acquires
// the heap lock. See mheap for details.
//
//go:systemstack
func (h *mheap) freeManual(s *mspan, typ spanAllocType) {
	// Trace the span free.
	if traceAllocFreeEnabled() {
		trace := traceAcquire()
		if trace.ok() {
			trace.SpanFree(s)
			traceRelease(trace)
		}
	}

	s.needzero = 1
	lock(&h.lock)
	h.freeSpanLocked(s, typ)
	unlock(&h.lock)
}

func (h *mheap) freeSpanLocked(s *mspan, typ spanAllocType) {
	assertLockHeld(&h.lock)

	switch s.state.get() {
	case mSpanManual:
		if s.allocCount != 0 {
			throw("mheap.freeSpanLocked - invalid stack free")
		}
	case mSpanInUse:
		if s.isUserArenaChunk {
			throw("mheap.freeSpanLocked - invalid free of user arena chunk")
		}
		if s.allocCount != 0 || s.sweepgen != h.sweepgen {
			print("mheap.freeSpanLocked - span ", s, " ptr ", hex(s.base()), " allocCount ", s.allocCount, " sweepgen ", s.sweepgen, "/", h.sweepgen, "\n")
			throw("mheap.freeSpanLocked - invalid free")
		}
		h.pagesInUse.Add(-s.npages)

		// Clear in-use bit in arena page bitmap.
		arena, pageIdx, pageMask := pageIndexOf(s.base())
		atomic.And8(&arena.pageInUse[pageIdx], ^pageMask)
	default:
		throw("mheap.freeSpanLocked - invalid span state")
	}

	// Update stats.
	//
	// Mirrors the code in allocSpan.
	nbytes := s.npages * pageSize
	gcController.heapFree.add(int64(nbytes))
	if typ == spanAllocHeap {
		gcController.heapInUse.add(-int64(nbytes))
	}
	// Update consistent stats.
	stats := memstats.heapStats.acquire()
	switch typ {
	case spanAllocHeap:
		atomic.Xaddint64(&stats.inHeap, -int64(nbytes))
	case spanAllocStack:
		atomic.Xaddint64(&stats.inStacks, -int64(nbytes))
	case spanAllocPtrScalarBits:
		atomic.Xaddint64(&stats.inPtrScalarBits, -int64(nbytes))
	case spanAllocWorkBuf:
		atomic.Xaddint64(&stats.inWorkBufs, -int64(nbytes))
	}
	memstats.heapStats.release()

	// Mark the space as free.
	h.pages.free(s.base(), s.npages)

	// Free the span structure. We no longer have a use for it.
	s.state.set(mSpanDead)
	h.freeMSpanLocked(s)
}

// scavengeAll acquires the heap lock (blocking any additional
// manipulation of the page allocator) and iterates over the whole
// heap, scavenging every free page available.
//
// Must run on the system stack because it acquires the heap lock.
//
//go:systemstack
func (h *mheap) scavengeAll() {
	// Disallow malloc or panic while holding the heap lock. We do
	// this here because this is a non-mallocgc entry-point to
	// the mheap API.
	gp := getg()
	gp.m.mallocing++

	// Force scavenge everything.
	released := h.pages.scavenge(^uintptr(0), nil, true)

	gp.m.mallocing--

	if debug.scavtrace > 0 {
		printScavTrace(0, released, true)
	}
}

//go:linkname runtime_debug_freeOSMemory runtime/debug.freeOSMemory
func runtime_debug_freeOSMemory() {
	GC()
	systemstack(func() { mheap_.scavengeAll() })
}

// Initialize a new span with the given start and npages.
func (span *mspan) init(base uintptr, npages uintptr) {
	// span is *not* zeroed.
	span.next = nil
	span.prev = nil
	span.list = nil
	span.startAddr = base
	span.npages = npages
	span.allocCount = 0
	span.spanclass = 0
	span.elemsize = 0
	span.speciallock.key = 0
	span.specials = nil
	span.needzero = 0
	span.freeindex = 0
	span.freeIndexForScan = 0
	span.allocBits = nil
	span.gcmarkBits = nil
	span.pinnerBits = nil
	span.state.set(mSpanDead)
	lockInit(&span.speciallock, lockRankMspanSpecial)
}

func (span *mspan) inList() bool {
	return span.list != nil
}

// Initialize an empty doubly-linked list.
func (list *mSpanList) init() {
	list.first = nil
	list.last = nil
}

func (list *mSpanList) remove(span *mspan) {
	if span.list != list {
		print("runtime: failed mSpanList.remove span.npages=", span.npages,
			" span=", span, " prev=", span.prev, " span.list=", span.list, " list=", list, "\n")
		throw("mSpanList.remove")
	}
	if list.first == span {
		list.first = span.next
	} else {
		span.prev.next = span.next
	}
	if list.last == span {
		list.last = span.prev
	} else {
		span.next.prev = span.prev
	}
	span.next = nil
	span.prev = nil
	span.list = nil
}

func (list *mSpanList) isEmpty() bool {
	return list.first == nil
}

func (list *mSpanList) insert(span *mspan) {
	if span.next != nil || span.prev != nil || span.list != nil {
		println("runtime: failed mSpanList.insert", span, span.next, span.prev, span.list)
		throw("mSpanList.insert")
	}
	span.next = list.first
	if list.first != nil {
		// The list contains at least one span; link it in.
		// The last span in the list doesn't change.
		list.first.prev = span
	} else {
		// The list contains no spans, so this is also the last span.
		list.last = span
	}
	list.first = span
	span.list = list
}

func (list *mSpanList) insertBack(span *mspan) {
	if span.next != nil || span.prev != nil || span.list != nil {
		println("runtime: failed mSpanList.insertBack", span, span.next, span.prev, span.list)
		throw("mSpanList.insertBack")
	}
	span.prev = list.last
	if list.last != nil {
		// The list contains at least one span.
		list.last.next = span
	} else {
		// The list contains no spans, so this is also the first span.
		list.first = span
	}
	list.last = span
	span.list = list
}

// takeAll removes all spans from other and inserts them at the front
// of list.
func (list *mSpanList) takeAll(other *mSpanList) {
	if other.isEmpty() {
		return
	}

	// Reparent everything in other to list.
	for s := other.first; s != nil; s = s.next {
		s.list = list
	}

	// Concatenate the lists.
	if list.isEmpty() {
		*list = *other
	} else {
		// Neither list is empty. Put other before list.
		other.last.next = list.first
		list.first.prev = other.last
		list.first = other.first
	}

	other.first, other.last = nil, nil
}

const (
	// _KindSpecialFinalizer is for tracking finalizers.
	_KindSpecialFinalizer = 1
	// _KindSpecialWeakHandle is used for creating weak pointers.
	_KindSpecialWeakHandle = 2
	// _KindSpecialProfile is for memory profiling.
	_KindSpecialProfile = 3
	// _KindSpecialReachable is a special used for tracking
	// reachability during testing.
	_KindSpecialReachable = 4
	// _KindSpecialPinCounter is a special used for objects that are pinned
	// multiple times
	_KindSpecialPinCounter = 5
	// _KindSpecialCleanup is for tracking cleanups.
	_KindSpecialCleanup = 6
)

type special struct {
	_      sys.NotInHeap
	next   *special // linked list in span
	offset uintptr  // span offset of object
	kind   byte     // kind of special
}

// spanHasSpecials marks a span as having specials in the arena bitmap.
func spanHasSpecials(s *mspan) {
	arenaPage := (s.base() / pageSize) % pagesPerArena
	ai := arenaIndex(s.base())
	ha := mheap_.arenas[ai.l1()][ai.l2()]
	atomic.Or8(&ha.pageSpecials[arenaPage/8], uint8(1)<<(arenaPage%8))
}

// spanHasNoSpecials marks a span as having no specials in the arena bitmap.
func spanHasNoSpecials(s *mspan) {
	arenaPage := (s.base() / pageSize) % pagesPerArena
	ai := arenaIndex(s.base())
	ha := mheap_.arenas[ai.l1()][ai.l2()]
	atomic.And8(&ha.pageSpecials[arenaPage/8], ^(uint8(1) << (arenaPage % 8)))
}

// addspecial adds the special record s to the list of special records for
// the object p. All fields of s should be filled in except for
// offset & next, which this routine will fill in.
// Returns true if the special was successfully added, false otherwise.
// (The add will fail only if a record with the same p and s->kind
// already exists unless force is set to true.)
func addspecial(p unsafe.Pointer, s *special, force bool) bool {
	span := spanOfHeap(uintptr(p))
	if span == nil {
		throw("addspecial on invalid pointer")
	}

	// Ensure that the span is swept.
	// Sweeping accesses the specials list w/o locks, so we have
	// to synchronize with it. And it's just much safer.
	mp := acquirem()
	span.ensureSwept()

	offset := uintptr(p) - span.base()
	kind := s.kind

	lock(&span.speciallock)

	// Find splice point, check for existing record.
	iter, exists := span.specialFindSplicePoint(offset, kind)
	if !exists || force {
		// Splice in record, fill in offset.
		s.offset = offset
		s.next = *iter
		*iter = s
		spanHasSpecials(span)
	}

	unlock(&span.speciallock)
	releasem(mp)
	// We're converting p to a uintptr and looking it up, and we
	// don't want it to die and get swept while we're doing so.
	KeepAlive(p)
	return !exists || force // already exists or addition was forced
}

// Removes the Special record of the given kind for the object p.
// Returns the record if the record existed, nil otherwise.
// The caller must FixAlloc_Free the result.
func removespecial(p unsafe.Pointer, kind uint8) *special {
	span := spanOfHeap(uintptr(p))
	if span == nil {
		throw("removespecial on invalid pointer")
	}

	// Ensure that the span is swept.
	// Sweeping accesses the specials list w/o locks, so we have
	// to synchronize with it. And it's just much safer.
	mp := acquirem()
	span.ensureSwept()

	offset := uintptr(p) - span.base()

	var result *special
	lock(&span.speciallock)

	iter, exists := span.specialFindSplicePoint(offset, kind)
	if exists {
		s := *iter
		*iter = s.next
		result = s
	}
	if span.specials == nil {
		spanHasNoSpecials(span)
	}
	unlock(&span.speciallock)
	releasem(mp)
	return result
}

// Find a splice point in the sorted list and check for an already existing
// record. Returns a pointer to the next-reference in the list predecessor.
// Returns true, if the referenced item is an exact match.
func (span *mspan) specialFindSplicePoint(offset uintptr, kind byte) (**special, bool) {
	// Find splice point, check for existing record.
	iter := &span.specials
	found := false
	for {
		s := *iter
		if s == nil {
			break
		}
		if offset == uintptr(s.offset) && kind == s.kind {
			found = true
			break
		}
		if offset < uintptr(s.offset) || (offset == uintptr(s.offset) && kind < s.kind) {
			break
		}
		iter = &s.next
	}
	return iter, found
}

// The described object has a finalizer set for it.
//
// specialfinalizer is allocated from non-GC'd memory, so any heap
// pointers must be specially handled.
type specialfinalizer struct {
	_       sys.NotInHeap
	special special
	fn      *funcval // May be a heap pointer.
	nret    uintptr
	fint    *_type   // May be a heap pointer, but always live.
	ot      *ptrtype // May be a heap pointer, but always live.
}

// Adds a finalizer to the object p. Returns true if it succeeded.
func addfinalizer(p unsafe.Pointer, f *funcval, nret uintptr, fint *_type, ot *ptrtype) bool {
	lock(&mheap_.speciallock)
	s := (*specialfinalizer)(mhe
```