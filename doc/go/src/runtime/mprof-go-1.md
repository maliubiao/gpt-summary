Response:
Let's break down the thought process for summarizing the provided Go code snippet, focusing on arriving at the key functionalities and their explanations.

1. **Initial Scan and Keyword Recognition:**  My first step is a quick skim to identify recurring keywords and function names. I see `MemProfile`, `BlockProfile`, `MutexProfile`, `ThreadCreateProfile`, `GoroutineProfile`, and `Stack`. The "Profile" suffix strongly suggests this code is about gathering performance-related data. I also notice mentions of `runtime/pprof` and `testing` packages, indicating this is low-level profiling functionality.

2. **Grouping by Profile Type:**  The function names clearly delineate different types of profiles: memory, blocking, mutex, thread creation, and goroutine. This forms the basis for structuring my summary.

3. **Analyzing Individual Profile Functions:**  For each profile type, I examine the corresponding `XProfile` and `XProfileInternal` functions. Key things I look for:
    * **Purpose:** What kind of data does this profile capture?  (e.g., memory allocation, blocking events, mutex contention, thread creation stacks, goroutine stacks).
    * **Input/Output:**  They all seem to take a slice as input (`p []XProfileRecord` or `[]StackRecord`). They return `n int, ok bool`, suggesting they copy profile data into the slice. The `size` parameter in the `Internal` functions hints at managing the provided buffer's capacity.
    * **Internal Mechanics (High-Level):**  I notice locking (`lock(&profMemActiveLock)`, `lock(&profBlockLock)`) which suggests concurrency control. The iteration over "buckets" (`for b := head; b != nil; b = b.allnext`) implies a data structure for storing profile information. The calls to `copyXProfileRecord` indicate data transformation.
    * **Relationship with `Internal` Functions:** The `XProfile` functions seem like wrappers around the `XProfileInternal` functions, often handling the copying of data using a closure (`func(r profilerecord.XProfileRecord) { ... }`). The `expandFrames` function in `BlockProfile` and `MutexProfile` catches my eye as a post-processing step.
    * **Special Cases/Considerations:**  The comments in `MemProfile` about garbage collection cycles and using `runtime/pprof` are important. The handling of `inuseZero` in `memProfileInternal` is also noteworthy. For `GoroutineProfile`, the `goroutineProfileWithLabelsConcurrent` function and the state machine involving `goroutineProfileState` are more complex, indicating a more sophisticated approach to collecting goroutine stacks.

4. **Analyzing `Stack` Function:**  This function is different. It takes a byte slice and a boolean (`all`). The comments clearly state its purpose: formatting stack traces. The `all` parameter indicates whether to include stacks of all goroutines. The internal use of `stopTheWorld` is a key detail, highlighting its impact on program execution.

5. **Inferring Overall Functionality:** By looking at the individual components, I can deduce the overall purpose of this code: to provide low-level mechanisms for profiling various aspects of Go program execution. This involves collecting data related to memory usage, blocking operations, mutex contention, thread creation, and goroutine stacks.

6. **Identifying Key Go Features Illustrated:**  The code heavily uses goroutines and concurrency primitives (locks, atomics). It demonstrates the use of slices and functions as parameters. The use of `//go:linkname` is a specific Go feature for aliasing functions for external use (like `pprof`). The `//go:noinline` directive is a performance-related hint to the compiler.

7. **Crafting the Examples (Conceptual):** I think about simple scenarios to demonstrate each profiling function. For memory, a basic allocation loop. For blocking, a channel send/receive. For mutex, locking and unlocking. For threads, `go func()`. For goroutines, just calling a function. For `Stack`, printing to a buffer. I don't need to write fully functional examples, but enough to illustrate the *intent* of the profiling.

8. **Inferring Command-Line Parameters:** The mentions of `-test.memprofile` and `-test.blockprofile` point to how these profiles are often used in testing. This leads to explaining these flags.

9. **Identifying Potential Pitfalls:**  The comment about the `MemProfile` result being up to two GC cycles old is a key point for potential errors. The need to provide a sufficiently large slice to the profile functions is another common mistake. The impact of `Stack(buf, true)` on performance due to `stopTheWorld` is crucial to mention.

10. **Structuring the Summary (Part 2):**  For the final summary, I reiterate the main purpose: providing low-level profiling tools. I emphasize the different types of profiles offered and their relationship to the `runtime/pprof` package. I also highlight the synchronization mechanisms used.

11. **Refinement and Clarity:** I review my explanations to ensure they are clear, concise, and accurate. I use precise language and avoid jargon where possible. I make sure to address all aspects of the prompt.

This iterative process of scanning, analyzing, grouping, inferring, and refining helps in systematically understanding and summarizing complex code like the provided snippet. The key is to break down the problem into smaller, manageable parts and then synthesize the information back into a coherent overview.
## 对go/src/runtime/mprof.go 第2部分的功能归纳

这是 `go/src/runtime/mprof.go` 代码的第二部分，主要功能是提供**运行时性能剖析**的底层实现，允许开发者获取程序运行时的各种状态信息，用于性能分析和问题排查。

具体来说，这部分代码提供了以下几种类型的性能剖析功能：

**1. 内存剖析 (Memory Profiling):**

* **功能:** 追踪内存分配和释放的情况，记录分配的字节数、对象数以及对应的调用栈。
* **实现函数:** `MemProfile`, `memProfileInternal`, `copyMemProfileRecord`, `pprof_memProfileInternal`, `iterate_memprof`
* **核心思想:** 通过维护一个全局的内存分配信息数据结构（基于 `mbuckets`），记录每个内存分配点的活跃分配和释放情况。为了避免分配操作对剖析结果的干扰，返回的剖析数据可能不是最新的，而是延迟了最多两个垃圾回收周期。
* **代码逻辑:**
    * `MemProfile` 是用户调用的入口，它调用 `memProfileInternal`，并提供一个将剖析记录拷贝到用户提供的切片的闭包函数。
    * `memProfileInternal` 负责核心的剖析逻辑，它遍历内存分配的 bucket，统计活跃的分配记录，并调用 `copyFn` 将信息传递给调用者。它会考虑 `inuseZero` 参数，决定是否包含当前没有活跃分配的记录。
    * 为了确保数据一致性，在访问和修改内存剖析数据时使用了锁 (`profMemActiveLock`, `profMemFutureLock`)。
    * 涉及到对未来垃圾回收周期的分配信息进行处理，以提供更准确的剖析结果。
* **与 `runtime/pprof` 的关系:** 注释明确指出，大多数用户应该使用 `runtime/pprof` 包或 `testing` 包的 `-test.memprofile` 标志，而不是直接调用 `MemProfile`。这表明 `mprof.go` 提供的是底层机制，而 `runtime/pprof` 提供了更方便易用的接口。

**2. 阻塞剖析 (Block Profiling):**

* **功能:** 记录 Goroutine 因为等待同步原语（例如互斥锁、通道）而阻塞的事件，包括阻塞的次数、总时长以及发生阻塞的调用栈。
* **实现函数:** `BlockProfile`, `blockProfileInternal`, `copyBlockProfileRecord`, `pprof_blockProfileInternal`, `expandFrames`
* **核心思想:**  当 Goroutine 尝试获取锁或者从通道接收数据时发生阻塞，会记录下相应的事件信息。
* **代码逻辑:**
    * `BlockProfile` 是用户入口，调用 `blockProfileInternal` 并提供拷贝闭包。
    * `blockProfileInternal` 遍历阻塞事件的 bucket (`bbuckets`)，统计阻塞信息，并调用 `copyFn`。
    * `expandFrames` 函数用于展开调用栈信息，将 "call PC" 转换为 "return PC"。
* **与 `runtime/pprof` 的关系:** 同样，建议使用 `runtime/pprof` 包或 `testing` 包的 `-test.blockprofile` 标志。

**3. 互斥锁剖析 (Mutex Profiling):**

* **功能:**  类似于阻塞剖析，专门记录 Goroutine 因为等待互斥锁而阻塞的事件。
* **实现函数:** `MutexProfile`, `mutexProfileInternal`, `copyBlockProfileRecord`, `pprof_mutexProfileInternal`, `expandFrames`
* **核心思想:**  与阻塞剖析类似，但更专注于互斥锁的争用情况。使用了与阻塞剖析相同的记录结构 (`BlockProfileRecord`) 和 bucket (`xbuckets`)。
* **代码逻辑:**  与阻塞剖析的逻辑基本一致，只是操作的 bucket 和入口函数不同。
* **与 `runtime/pprof` 的关系:** 建议使用 `runtime/pprof` 包。

**4. 线程创建剖析 (Thread Create Profiling):**

* **功能:** 记录 Go 程序中创建新操作系统线程的调用栈。
* **实现函数:** `ThreadCreateProfile`, `threadCreateProfileInternal`, `pprof_threadCreateInternal`
* **核心思想:** 遍历所有的 `m` (machine) 结构体，每个 `m` 代表一个操作系统线程，并记录创建该线程的调用栈。
* **代码逻辑:**
    * `ThreadCreateProfile` 是用户入口，调用 `threadCreateProfileInternal` 并提供拷贝闭包。
    * `threadCreateProfileInternal` 遍历全局的 `allm` 链表，获取每个 `m` 的创建栈信息。
* **与 `runtime/pprof` 的关系:** 建议使用 `runtime/pprof` 包。

**5. Goroutine 剖析 (Goroutine Profiling):**

* **功能:** 获取当前所有活跃 Goroutine 的调用栈信息。
* **实现函数:** `GoroutineProfile`, `goroutineProfileInternal`, `goroutineProfileWithLabels`, `goroutineProfileWithLabelsConcurrent`, `tryRecordGoroutineProfile`, `doRecordGoroutineProfile`, `goroutineProfileWithLabelsSync`, `pprof_goroutineProfileWithLabels`, `saveg`
* **核心思想:** 在安全地暂停所有其他 Goroutine 的情况下（Stop-The-World），遍历所有活跃的 Goroutine，并记录它们的调用栈。为了保证数据一致性，引入了 `goroutineProfileState` 状态机来协调 Goroutine 的栈信息采集。
* **代码逻辑:**
    * `GoroutineProfile` 是用户入口，调用 `goroutineProfileInternal`，最终调用 `goroutineProfileWithLabels`。
    * `goroutineProfileWithLabelsConcurrent` 是并发安全的版本，使用 `stopTheWorld` 来保证数据一致性。它还引入了 `goroutineProfileState` 来标记 Goroutine 的剖析状态，避免在剖析过程中 Goroutine 的状态发生变化。
    * `tryRecordGoroutineProfile` 和 `doRecordGoroutineProfile` 负责实际的 Goroutine 栈信息采集。
    * `goroutineProfileWithLabelsSync` 是一个同步版本，同样使用 `stopTheWorld`。
    * `saveg` 函数负责获取指定 Goroutine 的调用栈信息。
* **与 `runtime/pprof` 的关系:** 建议使用 `runtime/pprof` 包。

**6. 获取当前 Goroutine 调用栈 (Stack):**

* **功能:** 获取当前 Goroutine 或所有 Goroutine 的调用栈信息，并格式化为字符串。
* **实现函数:** `Stack`
* **核心思想:** 如果 `all` 参数为 `true`，则会暂停整个程序 (`stopTheWorld`)，然后遍历所有 Goroutine 并记录其调用栈。
* **代码逻辑:**
    * `Stack` 函数根据 `all` 参数决定是否需要暂停程序。
    * 它使用 `traceback` 和 `tracebackothers` 函数来生成调用栈信息，并将结果写入提供的 `buf` 切片中。
* **与 `runtime/pprof` 的关系:**  `runtime/pprof` 包内部也会使用 `Stack` 函数来生成 Goroutine 的栈信息。

**总结:**

`go/src/runtime/mprof.go` 的第二部分主要提供了 Go 运行时系统的底层性能剖析能力。它涵盖了内存分配、阻塞事件、互斥锁争用、线程创建和 Goroutine 状态等多个方面的监控。这些功能通常通过 `runtime/pprof` 包暴露给用户，提供了更方便的接口。直接使用这些底层函数需要对 Go 运行时的内部机制有深入的了解，并且需要谨慎处理并发安全和数据一致性问题。

总而言之，这部分代码是 Go 语言性能分析工具的基础，为开发者提供了深入了解程序运行时行为的能力。

### 提示词
```
这是路径为go/src/runtime/mprof.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
released back to the runtime.
//
// The returned profile may be up to two garbage collection cycles old.
// This is to avoid skewing the profile toward allocations; because
// allocations happen in real time but frees are delayed until the garbage
// collector performs sweeping, the profile only accounts for allocations
// that have had a chance to be freed by the garbage collector.
//
// Most clients should use the runtime/pprof package or
// the testing package's -test.memprofile flag instead
// of calling MemProfile directly.
func MemProfile(p []MemProfileRecord, inuseZero bool) (n int, ok bool) {
	return memProfileInternal(len(p), inuseZero, func(r profilerecord.MemProfileRecord) {
		copyMemProfileRecord(&p[0], r)
		p = p[1:]
	})
}

// memProfileInternal returns the number of records n in the profile. If there
// are less than size records, copyFn is invoked for each record, and ok returns
// true.
//
// The linker set disableMemoryProfiling to true to disable memory profiling
// if this function is not reachable. Mark it noinline to ensure the symbol exists.
// (This function is big and normally not inlined anyway.)
// See also disableMemoryProfiling above and cmd/link/internal/ld/lib.go:linksetup.
//
//go:noinline
func memProfileInternal(size int, inuseZero bool, copyFn func(profilerecord.MemProfileRecord)) (n int, ok bool) {
	cycle := mProfCycle.read()
	// If we're between mProf_NextCycle and mProf_Flush, take care
	// of flushing to the active profile so we only have to look
	// at the active profile below.
	index := cycle % uint32(len(memRecord{}.future))
	lock(&profMemActiveLock)
	lock(&profMemFutureLock[index])
	mProf_FlushLocked(index)
	unlock(&profMemFutureLock[index])
	clear := true
	head := (*bucket)(mbuckets.Load())
	for b := head; b != nil; b = b.allnext {
		mp := b.mp()
		if inuseZero || mp.active.alloc_bytes != mp.active.free_bytes {
			n++
		}
		if mp.active.allocs != 0 || mp.active.frees != 0 {
			clear = false
		}
	}
	if clear {
		// Absolutely no data, suggesting that a garbage collection
		// has not yet happened. In order to allow profiling when
		// garbage collection is disabled from the beginning of execution,
		// accumulate all of the cycles, and recount buckets.
		n = 0
		for b := head; b != nil; b = b.allnext {
			mp := b.mp()
			for c := range mp.future {
				lock(&profMemFutureLock[c])
				mp.active.add(&mp.future[c])
				mp.future[c] = memRecordCycle{}
				unlock(&profMemFutureLock[c])
			}
			if inuseZero || mp.active.alloc_bytes != mp.active.free_bytes {
				n++
			}
		}
	}
	if n <= size {
		ok = true
		for b := head; b != nil; b = b.allnext {
			mp := b.mp()
			if inuseZero || mp.active.alloc_bytes != mp.active.free_bytes {
				r := profilerecord.MemProfileRecord{
					AllocBytes:   int64(mp.active.alloc_bytes),
					FreeBytes:    int64(mp.active.free_bytes),
					AllocObjects: int64(mp.active.allocs),
					FreeObjects:  int64(mp.active.frees),
					Stack:        b.stk(),
				}
				copyFn(r)
			}
		}
	}
	unlock(&profMemActiveLock)
	return
}

func copyMemProfileRecord(dst *MemProfileRecord, src profilerecord.MemProfileRecord) {
	dst.AllocBytes = src.AllocBytes
	dst.FreeBytes = src.FreeBytes
	dst.AllocObjects = src.AllocObjects
	dst.FreeObjects = src.FreeObjects
	if raceenabled {
		racewriterangepc(unsafe.Pointer(&dst.Stack0[0]), unsafe.Sizeof(dst.Stack0), sys.GetCallerPC(), abi.FuncPCABIInternal(MemProfile))
	}
	if msanenabled {
		msanwrite(unsafe.Pointer(&dst.Stack0[0]), unsafe.Sizeof(dst.Stack0))
	}
	if asanenabled {
		asanwrite(unsafe.Pointer(&dst.Stack0[0]), unsafe.Sizeof(dst.Stack0))
	}
	i := copy(dst.Stack0[:], src.Stack)
	clear(dst.Stack0[i:])
}

//go:linkname pprof_memProfileInternal
func pprof_memProfileInternal(p []profilerecord.MemProfileRecord, inuseZero bool) (n int, ok bool) {
	return memProfileInternal(len(p), inuseZero, func(r profilerecord.MemProfileRecord) {
		p[0] = r
		p = p[1:]
	})
}

func iterate_memprof(fn func(*bucket, uintptr, *uintptr, uintptr, uintptr, uintptr)) {
	lock(&profMemActiveLock)
	head := (*bucket)(mbuckets.Load())
	for b := head; b != nil; b = b.allnext {
		mp := b.mp()
		fn(b, b.nstk, &b.stk()[0], b.size, mp.active.allocs, mp.active.frees)
	}
	unlock(&profMemActiveLock)
}

// BlockProfileRecord describes blocking events originated
// at a particular call sequence (stack trace).
type BlockProfileRecord struct {
	Count  int64
	Cycles int64
	StackRecord
}

// BlockProfile returns n, the number of records in the current blocking profile.
// If len(p) >= n, BlockProfile copies the profile into p and returns n, true.
// If len(p) < n, BlockProfile does not change p and returns n, false.
//
// Most clients should use the [runtime/pprof] package or
// the [testing] package's -test.blockprofile flag instead
// of calling BlockProfile directly.
func BlockProfile(p []BlockProfileRecord) (n int, ok bool) {
	var m int
	n, ok = blockProfileInternal(len(p), func(r profilerecord.BlockProfileRecord) {
		copyBlockProfileRecord(&p[m], r)
		m++
	})
	if ok {
		expandFrames(p[:n])
	}
	return
}

func expandFrames(p []BlockProfileRecord) {
	expandedStack := makeProfStack()
	for i := range p {
		cf := CallersFrames(p[i].Stack())
		j := 0
		for j < len(expandedStack) {
			f, more := cf.Next()
			// f.PC is a "call PC", but later consumers will expect
			// "return PCs"
			expandedStack[j] = f.PC + 1
			j++
			if !more {
				break
			}
		}
		k := copy(p[i].Stack0[:], expandedStack[:j])
		clear(p[i].Stack0[k:])
	}
}

// blockProfileInternal returns the number of records n in the profile. If there
// are less than size records, copyFn is invoked for each record, and ok returns
// true.
func blockProfileInternal(size int, copyFn func(profilerecord.BlockProfileRecord)) (n int, ok bool) {
	lock(&profBlockLock)
	head := (*bucket)(bbuckets.Load())
	for b := head; b != nil; b = b.allnext {
		n++
	}
	if n <= size {
		ok = true
		for b := head; b != nil; b = b.allnext {
			bp := b.bp()
			r := profilerecord.BlockProfileRecord{
				Count:  int64(bp.count),
				Cycles: bp.cycles,
				Stack:  b.stk(),
			}
			// Prevent callers from having to worry about division by zero errors.
			// See discussion on http://golang.org/cl/299991.
			if r.Count == 0 {
				r.Count = 1
			}
			copyFn(r)
		}
	}
	unlock(&profBlockLock)
	return
}

// copyBlockProfileRecord copies the sample values and call stack from src to dst.
// The call stack is copied as-is. The caller is responsible for handling inline
// expansion, needed when the call stack was collected with frame pointer unwinding.
func copyBlockProfileRecord(dst *BlockProfileRecord, src profilerecord.BlockProfileRecord) {
	dst.Count = src.Count
	dst.Cycles = src.Cycles
	if raceenabled {
		racewriterangepc(unsafe.Pointer(&dst.Stack0[0]), unsafe.Sizeof(dst.Stack0), sys.GetCallerPC(), abi.FuncPCABIInternal(BlockProfile))
	}
	if msanenabled {
		msanwrite(unsafe.Pointer(&dst.Stack0[0]), unsafe.Sizeof(dst.Stack0))
	}
	if asanenabled {
		asanwrite(unsafe.Pointer(&dst.Stack0[0]), unsafe.Sizeof(dst.Stack0))
	}
	// We just copy the stack here without inline expansion
	// (needed if frame pointer unwinding is used)
	// since this function is called under the profile lock,
	// and doing something that might allocate can violate lock ordering.
	i := copy(dst.Stack0[:], src.Stack)
	clear(dst.Stack0[i:])
}

//go:linkname pprof_blockProfileInternal
func pprof_blockProfileInternal(p []profilerecord.BlockProfileRecord) (n int, ok bool) {
	return blockProfileInternal(len(p), func(r profilerecord.BlockProfileRecord) {
		p[0] = r
		p = p[1:]
	})
}

// MutexProfile returns n, the number of records in the current mutex profile.
// If len(p) >= n, MutexProfile copies the profile into p and returns n, true.
// Otherwise, MutexProfile does not change p, and returns n, false.
//
// Most clients should use the [runtime/pprof] package
// instead of calling MutexProfile directly.
func MutexProfile(p []BlockProfileRecord) (n int, ok bool) {
	var m int
	n, ok = mutexProfileInternal(len(p), func(r profilerecord.BlockProfileRecord) {
		copyBlockProfileRecord(&p[m], r)
		m++
	})
	if ok {
		expandFrames(p[:n])
	}
	return
}

// mutexProfileInternal returns the number of records n in the profile. If there
// are less than size records, copyFn is invoked for each record, and ok returns
// true.
func mutexProfileInternal(size int, copyFn func(profilerecord.BlockProfileRecord)) (n int, ok bool) {
	lock(&profBlockLock)
	head := (*bucket)(xbuckets.Load())
	for b := head; b != nil; b = b.allnext {
		n++
	}
	if n <= size {
		ok = true
		for b := head; b != nil; b = b.allnext {
			bp := b.bp()
			r := profilerecord.BlockProfileRecord{
				Count:  int64(bp.count),
				Cycles: bp.cycles,
				Stack:  b.stk(),
			}
			copyFn(r)
		}
	}
	unlock(&profBlockLock)
	return
}

//go:linkname pprof_mutexProfileInternal
func pprof_mutexProfileInternal(p []profilerecord.BlockProfileRecord) (n int, ok bool) {
	return mutexProfileInternal(len(p), func(r profilerecord.BlockProfileRecord) {
		p[0] = r
		p = p[1:]
	})
}

// ThreadCreateProfile returns n, the number of records in the thread creation profile.
// If len(p) >= n, ThreadCreateProfile copies the profile into p and returns n, true.
// If len(p) < n, ThreadCreateProfile does not change p and returns n, false.
//
// Most clients should use the runtime/pprof package instead
// of calling ThreadCreateProfile directly.
func ThreadCreateProfile(p []StackRecord) (n int, ok bool) {
	return threadCreateProfileInternal(len(p), func(r profilerecord.StackRecord) {
		i := copy(p[0].Stack0[:], r.Stack)
		clear(p[0].Stack0[i:])
		p = p[1:]
	})
}

// threadCreateProfileInternal returns the number of records n in the profile.
// If there are less than size records, copyFn is invoked for each record, and
// ok returns true.
func threadCreateProfileInternal(size int, copyFn func(profilerecord.StackRecord)) (n int, ok bool) {
	first := (*m)(atomic.Loadp(unsafe.Pointer(&allm)))
	for mp := first; mp != nil; mp = mp.alllink {
		n++
	}
	if n <= size {
		ok = true
		for mp := first; mp != nil; mp = mp.alllink {
			r := profilerecord.StackRecord{Stack: mp.createstack[:]}
			copyFn(r)
		}
	}
	return
}

//go:linkname pprof_threadCreateInternal
func pprof_threadCreateInternal(p []profilerecord.StackRecord) (n int, ok bool) {
	return threadCreateProfileInternal(len(p), func(r profilerecord.StackRecord) {
		p[0] = r
		p = p[1:]
	})
}

//go:linkname pprof_goroutineProfileWithLabels
func pprof_goroutineProfileWithLabels(p []profilerecord.StackRecord, labels []unsafe.Pointer) (n int, ok bool) {
	return goroutineProfileWithLabels(p, labels)
}

// labels may be nil. If labels is non-nil, it must have the same length as p.
func goroutineProfileWithLabels(p []profilerecord.StackRecord, labels []unsafe.Pointer) (n int, ok bool) {
	if labels != nil && len(labels) != len(p) {
		labels = nil
	}

	return goroutineProfileWithLabelsConcurrent(p, labels)
}

var goroutineProfile = struct {
	sema    uint32
	active  bool
	offset  atomic.Int64
	records []profilerecord.StackRecord
	labels  []unsafe.Pointer
}{
	sema: 1,
}

// goroutineProfileState indicates the status of a goroutine's stack for the
// current in-progress goroutine profile. Goroutines' stacks are initially
// "Absent" from the profile, and end up "Satisfied" by the time the profile is
// complete. While a goroutine's stack is being captured, its
// goroutineProfileState will be "InProgress" and it will not be able to run
// until the capture completes and the state moves to "Satisfied".
//
// Some goroutines (the finalizer goroutine, which at various times can be
// either a "system" or a "user" goroutine, and the goroutine that is
// coordinating the profile, any goroutines created during the profile) move
// directly to the "Satisfied" state.
type goroutineProfileState uint32

const (
	goroutineProfileAbsent goroutineProfileState = iota
	goroutineProfileInProgress
	goroutineProfileSatisfied
)

type goroutineProfileStateHolder atomic.Uint32

func (p *goroutineProfileStateHolder) Load() goroutineProfileState {
	return goroutineProfileState((*atomic.Uint32)(p).Load())
}

func (p *goroutineProfileStateHolder) Store(value goroutineProfileState) {
	(*atomic.Uint32)(p).Store(uint32(value))
}

func (p *goroutineProfileStateHolder) CompareAndSwap(old, new goroutineProfileState) bool {
	return (*atomic.Uint32)(p).CompareAndSwap(uint32(old), uint32(new))
}

func goroutineProfileWithLabelsConcurrent(p []profilerecord.StackRecord, labels []unsafe.Pointer) (n int, ok bool) {
	if len(p) == 0 {
		// An empty slice is obviously too small. Return a rough
		// allocation estimate without bothering to STW. As long as
		// this is close, then we'll only need to STW once (on the next
		// call).
		return int(gcount()), false
	}

	semacquire(&goroutineProfile.sema)

	ourg := getg()

	pcbuf := makeProfStack() // see saveg() for explanation
	stw := stopTheWorld(stwGoroutineProfile)
	// Using gcount while the world is stopped should give us a consistent view
	// of the number of live goroutines, minus the number of goroutines that are
	// alive and permanently marked as "system". But to make this count agree
	// with what we'd get from isSystemGoroutine, we need special handling for
	// goroutines that can vary between user and system to ensure that the count
	// doesn't change during the collection. So, check the finalizer goroutine
	// in particular.
	n = int(gcount())
	if fingStatus.Load()&fingRunningFinalizer != 0 {
		n++
	}

	if n > len(p) {
		// There's not enough space in p to store the whole profile, so (per the
		// contract of runtime.GoroutineProfile) we're not allowed to write to p
		// at all and must return n, false.
		startTheWorld(stw)
		semrelease(&goroutineProfile.sema)
		return n, false
	}

	// Save current goroutine.
	sp := sys.GetCallerSP()
	pc := sys.GetCallerPC()
	systemstack(func() {
		saveg(pc, sp, ourg, &p[0], pcbuf)
	})
	if labels != nil {
		labels[0] = ourg.labels
	}
	ourg.goroutineProfiled.Store(goroutineProfileSatisfied)
	goroutineProfile.offset.Store(1)

	// Prepare for all other goroutines to enter the profile. Aside from ourg,
	// every goroutine struct in the allgs list has its goroutineProfiled field
	// cleared. Any goroutine created from this point on (while
	// goroutineProfile.active is set) will start with its goroutineProfiled
	// field set to goroutineProfileSatisfied.
	goroutineProfile.active = true
	goroutineProfile.records = p
	goroutineProfile.labels = labels
	// The finalizer goroutine needs special handling because it can vary over
	// time between being a user goroutine (eligible for this profile) and a
	// system goroutine (to be excluded). Pick one before restarting the world.
	if fing != nil {
		fing.goroutineProfiled.Store(goroutineProfileSatisfied)
		if readgstatus(fing) != _Gdead && !isSystemGoroutine(fing, false) {
			doRecordGoroutineProfile(fing, pcbuf)
		}
	}
	startTheWorld(stw)

	// Visit each goroutine that existed as of the startTheWorld call above.
	//
	// New goroutines may not be in this list, but we didn't want to know about
	// them anyway. If they do appear in this list (via reusing a dead goroutine
	// struct, or racing to launch between the world restarting and us getting
	// the list), they will already have their goroutineProfiled field set to
	// goroutineProfileSatisfied before their state transitions out of _Gdead.
	//
	// Any goroutine that the scheduler tries to execute concurrently with this
	// call will start by adding itself to the profile (before the act of
	// executing can cause any changes in its stack).
	forEachGRace(func(gp1 *g) {
		tryRecordGoroutineProfile(gp1, pcbuf, Gosched)
	})

	stw = stopTheWorld(stwGoroutineProfileCleanup)
	endOffset := goroutineProfile.offset.Swap(0)
	goroutineProfile.active = false
	goroutineProfile.records = nil
	goroutineProfile.labels = nil
	startTheWorld(stw)

	// Restore the invariant that every goroutine struct in allgs has its
	// goroutineProfiled field cleared.
	forEachGRace(func(gp1 *g) {
		gp1.goroutineProfiled.Store(goroutineProfileAbsent)
	})

	if raceenabled {
		raceacquire(unsafe.Pointer(&labelSync))
	}

	if n != int(endOffset) {
		// It's a big surprise that the number of goroutines changed while we
		// were collecting the profile. But probably better to return a
		// truncated profile than to crash the whole process.
		//
		// For instance, needm moves a goroutine out of the _Gdead state and so
		// might be able to change the goroutine count without interacting with
		// the scheduler. For code like that, the race windows are small and the
		// combination of features is uncommon, so it's hard to be (and remain)
		// sure we've caught them all.
	}

	semrelease(&goroutineProfile.sema)
	return n, true
}

// tryRecordGoroutineProfileWB asserts that write barriers are allowed and calls
// tryRecordGoroutineProfile.
//
//go:yeswritebarrierrec
func tryRecordGoroutineProfileWB(gp1 *g) {
	if getg().m.p.ptr() == nil {
		throw("no P available, write barriers are forbidden")
	}
	tryRecordGoroutineProfile(gp1, nil, osyield)
}

// tryRecordGoroutineProfile ensures that gp1 has the appropriate representation
// in the current goroutine profile: either that it should not be profiled, or
// that a snapshot of its call stack and labels are now in the profile.
func tryRecordGoroutineProfile(gp1 *g, pcbuf []uintptr, yield func()) {
	if readgstatus(gp1) == _Gdead {
		// Dead goroutines should not appear in the profile. Goroutines that
		// start while profile collection is active will get goroutineProfiled
		// set to goroutineProfileSatisfied before transitioning out of _Gdead,
		// so here we check _Gdead first.
		return
	}
	if isSystemGoroutine(gp1, true) {
		// System goroutines should not appear in the profile. (The finalizer
		// goroutine is marked as "already profiled".)
		return
	}

	for {
		prev := gp1.goroutineProfiled.Load()
		if prev == goroutineProfileSatisfied {
			// This goroutine is already in the profile (or is new since the
			// start of collection, so shouldn't appear in the profile).
			break
		}
		if prev == goroutineProfileInProgress {
			// Something else is adding gp1 to the goroutine profile right now.
			// Give that a moment to finish.
			yield()
			continue
		}

		// While we have gp1.goroutineProfiled set to
		// goroutineProfileInProgress, gp1 may appear _Grunnable but will not
		// actually be able to run. Disable preemption for ourselves, to make
		// sure we finish profiling gp1 right away instead of leaving it stuck
		// in this limbo.
		mp := acquirem()
		if gp1.goroutineProfiled.CompareAndSwap(goroutineProfileAbsent, goroutineProfileInProgress) {
			doRecordGoroutineProfile(gp1, pcbuf)
			gp1.goroutineProfiled.Store(goroutineProfileSatisfied)
		}
		releasem(mp)
	}
}

// doRecordGoroutineProfile writes gp1's call stack and labels to an in-progress
// goroutine profile. Preemption is disabled.
//
// This may be called via tryRecordGoroutineProfile in two ways: by the
// goroutine that is coordinating the goroutine profile (running on its own
// stack), or from the scheduler in preparation to execute gp1 (running on the
// system stack).
func doRecordGoroutineProfile(gp1 *g, pcbuf []uintptr) {
	if readgstatus(gp1) == _Grunning {
		print("doRecordGoroutineProfile gp1=", gp1.goid, "\n")
		throw("cannot read stack of running goroutine")
	}

	offset := int(goroutineProfile.offset.Add(1)) - 1

	if offset >= len(goroutineProfile.records) {
		// Should be impossible, but better to return a truncated profile than
		// to crash the entire process at this point. Instead, deal with it in
		// goroutineProfileWithLabelsConcurrent where we have more context.
		return
	}

	// saveg calls gentraceback, which may call cgo traceback functions. When
	// called from the scheduler, this is on the system stack already so
	// traceback.go:cgoContextPCs will avoid calling back into the scheduler.
	//
	// When called from the goroutine coordinating the profile, we still have
	// set gp1.goroutineProfiled to goroutineProfileInProgress and so are still
	// preventing it from being truly _Grunnable. So we'll use the system stack
	// to avoid schedule delays.
	systemstack(func() { saveg(^uintptr(0), ^uintptr(0), gp1, &goroutineProfile.records[offset], pcbuf) })

	if goroutineProfile.labels != nil {
		goroutineProfile.labels[offset] = gp1.labels
	}
}

func goroutineProfileWithLabelsSync(p []profilerecord.StackRecord, labels []unsafe.Pointer) (n int, ok bool) {
	gp := getg()

	isOK := func(gp1 *g) bool {
		// Checking isSystemGoroutine here makes GoroutineProfile
		// consistent with both NumGoroutine and Stack.
		return gp1 != gp && readgstatus(gp1) != _Gdead && !isSystemGoroutine(gp1, false)
	}

	pcbuf := makeProfStack() // see saveg() for explanation
	stw := stopTheWorld(stwGoroutineProfile)

	// World is stopped, no locking required.
	n = 1
	forEachGRace(func(gp1 *g) {
		if isOK(gp1) {
			n++
		}
	})

	if n <= len(p) {
		ok = true
		r, lbl := p, labels

		// Save current goroutine.
		sp := sys.GetCallerSP()
		pc := sys.GetCallerPC()
		systemstack(func() {
			saveg(pc, sp, gp, &r[0], pcbuf)
		})
		r = r[1:]

		// If we have a place to put our goroutine labelmap, insert it there.
		if labels != nil {
			lbl[0] = gp.labels
			lbl = lbl[1:]
		}

		// Save other goroutines.
		forEachGRace(func(gp1 *g) {
			if !isOK(gp1) {
				return
			}

			if len(r) == 0 {
				// Should be impossible, but better to return a
				// truncated profile than to crash the entire process.
				return
			}
			// saveg calls gentraceback, which may call cgo traceback functions.
			// The world is stopped, so it cannot use cgocall (which will be
			// blocked at exitsyscall). Do it on the system stack so it won't
			// call into the schedular (see traceback.go:cgoContextPCs).
			systemstack(func() { saveg(^uintptr(0), ^uintptr(0), gp1, &r[0], pcbuf) })
			if labels != nil {
				lbl[0] = gp1.labels
				lbl = lbl[1:]
			}
			r = r[1:]
		})
	}

	if raceenabled {
		raceacquire(unsafe.Pointer(&labelSync))
	}

	startTheWorld(stw)
	return n, ok
}

// GoroutineProfile returns n, the number of records in the active goroutine stack profile.
// If len(p) >= n, GoroutineProfile copies the profile into p and returns n, true.
// If len(p) < n, GoroutineProfile does not change p and returns n, false.
//
// Most clients should use the [runtime/pprof] package instead
// of calling GoroutineProfile directly.
func GoroutineProfile(p []StackRecord) (n int, ok bool) {
	records := make([]profilerecord.StackRecord, len(p))
	n, ok = goroutineProfileInternal(records)
	if !ok {
		return
	}
	for i, mr := range records[0:n] {
		l := copy(p[i].Stack0[:], mr.Stack)
		clear(p[i].Stack0[l:])
	}
	return
}

func goroutineProfileInternal(p []profilerecord.StackRecord) (n int, ok bool) {
	return goroutineProfileWithLabels(p, nil)
}

func saveg(pc, sp uintptr, gp *g, r *profilerecord.StackRecord, pcbuf []uintptr) {
	// To reduce memory usage, we want to allocate a r.Stack that is just big
	// enough to hold gp's stack trace. Naively we might achieve this by
	// recording our stack trace into mp.profStack, and then allocating a
	// r.Stack of the right size. However, mp.profStack is also used for
	// allocation profiling, so it could get overwritten if the slice allocation
	// gets profiled. So instead we record the stack trace into a temporary
	// pcbuf which is usually given to us by our caller. When it's not, we have
	// to allocate one here. This will only happen for goroutines that were in a
	// syscall when the goroutine profile started or for goroutines that manage
	// to execute before we finish iterating over all the goroutines.
	if pcbuf == nil {
		pcbuf = makeProfStack()
	}

	var u unwinder
	u.initAt(pc, sp, 0, gp, unwindSilentErrors)
	n := tracebackPCs(&u, 0, pcbuf)
	r.Stack = make([]uintptr, n)
	copy(r.Stack, pcbuf)
}

// Stack formats a stack trace of the calling goroutine into buf
// and returns the number of bytes written to buf.
// If all is true, Stack formats stack traces of all other goroutines
// into buf after the trace for the current goroutine.
func Stack(buf []byte, all bool) int {
	var stw worldStop
	if all {
		stw = stopTheWorld(stwAllGoroutinesStack)
	}

	n := 0
	if len(buf) > 0 {
		gp := getg()
		sp := sys.GetCallerSP()
		pc := sys.GetCallerPC()
		systemstack(func() {
			g0 := getg()
			// Force traceback=1 to override GOTRACEBACK setting,
			// so that Stack's results are consistent.
			// GOTRACEBACK is only about crash dumps.
			g0.m.traceback = 1
			g0.writebuf = buf[0:0:len(buf)]
			goroutineheader(gp)
			traceback(pc, sp, 0, gp)
			if all {
				tracebackothers(gp)
			}
			g0.m.traceback = 0
			n = len(g0.writebuf)
			g0.writebuf = nil
		})
	}

	if all {
		startTheWorld(stw)
	}
	return n
}
```