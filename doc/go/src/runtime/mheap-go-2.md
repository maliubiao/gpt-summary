Response:
这是关于 Go 运行时 `mheap.go` 文件中与特殊对象处理相关的代码片段。我的目标是总结其功能，并尽可能推断出相关 Go 语言特性的实现。

**思考过程：**

1. **阅读并理解代码:** 仔细阅读代码，关注结构体定义（`specialFinalizer`、`specialCleanup`、`specialWeakHandle` 等）和相关函数（`addfinalizer`、`removefinalizer`、`addCleanup`、`getOrAddWeakHandle` 等）。理解每个结构体的作用以及每个函数的功能。

2. **识别关键概念:**  注意到 `finalizer`（终结器）、`cleanup`（清理器）、`weak pointer`（弱指针）、`heap profile`（堆 профилирование）等关键术语。这些是 Go 语言中与内存管理和资源回收相关的重要概念。

3. **推断 Go 语言特性:**  根据代码中的函数名和结构体定义，尝试将这些代码片段与 Go 语言的特性对应起来：
    * `addfinalizer` 和 `removefinalizer` 显然与 `runtime.SetFinalizer` 相关。
    * `addCleanup` 很可能与某种资源清理机制有关，可能与 `sync.Pool` 或自定义的资源管理有关。
    * `getOrAddWeakHandle` 和相关的 `internal_weak_runtime_registerWeakPointer`/`internal_weak_runtime_makeStrongFromWeak` 明确指向 `runtime/weak` 包中的弱指针实现。
    * `setprofilebucket` 看起来与堆性能分析相关，可能与 `runtime/pprof` 包有关。

4. **代码示例:**  为每个推断出的 Go 语言特性编写代码示例。这些示例应该展示如何使用相关的 Go 语言 API，并能够触发 `mheap.go` 中相应的代码路径。

5. **假设输入与输出:**  对于代码推理部分，需要考虑示例代码的输入和期望的输出，以便验证代码的功能。例如，对于终结器，要观察对象被回收后终结器是否被执行。对于弱指针，要观察在对象被回收后，弱指针是否变为 `nil`。

6. **命令行参数:**  检查代码中是否有直接处理命令行参数的部分。 在这个代码片段中，没有明显的命令行参数处理。

7. **使用者易犯错的点:** 思考在使用这些特性时，开发者可能遇到的常见错误。例如，终结器的执行顺序不确定，弱指针可能在访问时已经失效等。

8. **归纳功能:**  总结代码片段的主要功能，将其放在整个 `mheap.go` 文件以及 Go 运行时的大背景下理解。

9. **组织答案:**  使用清晰的中文组织答案，分别针对功能列举、特性推理、代码示例、输入输出、命令行参数、易错点和功能归纳进行说明。

**在查看和组织答案时，我意识到以下几点需要特别注意：**

* **锁的使用:** 代码中频繁出现 `lock` 和 `unlock` 操作，这表明这些操作是线程安全的，需要在并发环境下正确处理。
* **GC 的交互:** 代码中多次检查 `gcphase` 的状态，并执行与 GC 相关的操作（如 `scanobject`、`scanblock`、`shade`）。这说明这些特殊对象的处理与 Go 的垃圾回收机制紧密相关。
* **内存分配:**  使用 `mheap_.specialFinalizerAlloc.alloc()` 等从特殊的分配器中分配内存，这些内存可能不在常规的 GC 管理范围内。

通过以上思考过程，我能够逐步分析代码，推断其功能，并最终组织成较为完整的答案。
这是 `go/src/runtime/mheap.go` 文件的第三部分，主要关注于与垃圾回收和特殊对象处理相关的机制。在前两部分的基础上，这部分深入探讨了**终结器 (finalizer)**，**清理器 (cleanup)**，**弱指针 (weak pointer)** 以及 **堆性能分析 (heap profiling)** 的实现细节。

**功能列举:**

1. **终结器的管理:**
   - `addfinalizer`:  为一个对象添加终结函数。当垃圾回收器准备回收该对象时，会执行与之关联的终结函数。
   - `removefinalizer`: 移除对象的终结函数。

2. **清理器的管理:**
   - `addCleanup`: 为一个对象关联一个清理函数。与终结器不同，清理函数在对象变为不可达时执行，但不会像终结器那样可能复活对象。可以为一个对象添加多个清理器。

3. **弱指针的管理:**
   - `internal_weak_runtime_registerWeakPointer`:  创建一个指向对象的弱指针。弱指针不会阻止对象的垃圾回收。
   - `internal_weak_runtime_makeStrongFromWeak`: 尝试从弱指针获取强指针。如果弱指针指向的对象仍然存活，则返回强指针；否则返回 `nil`。
   - `gcParkStrongFromWeak`:  在尝试将弱指针转换为强指针时，如果对象可能正在被垃圾回收，则将当前 goroutine 放入等待队列并阻塞。
   - `gcWakeAllStrongFromWeak`:  唤醒所有正在等待弱指针转强指针的 goroutine，通常在垃圾回收周期的末尾调用。
   - `getOrAddWeakHandle`: 获取或创建一个对象的弱指针句柄。

4. **堆性能分析的支持:**
   - `setprofilebucket`:  将一个堆内存分配与一个性能分析的 bucket 关联起来，用于堆性能分析。

5. **特殊对象列表的管理:**
   - `specialsIter`:  用于迭代 `mspan` 中存储的特殊对象列表的结构体。
   - `newSpecialsIter`: 创建一个新的 `specialsIter`。
   - `valid`, `next`, `unlinkAndNext`: `specialsIter` 的方法，用于遍历和操作特殊对象列表。
   - `freeSpecial`:  释放特殊对象，并根据其类型执行相应的清理操作（例如，对于终结器，将其放入终结队列）。

6. **垃圾回收位图 (gcBits) 的管理:**
   - `gcBits`:  表示分配/标记位图的结构体。
   - `bytep`, `bitp`:  用于访问位图中特定字节或位的方法。
   - `gcBitsArena`:  用于存储 `gcBits` 的内存区域，采用 Arena 分配方式以提高效率。
   - `gcBitsArenas`:  管理 `gcBitsArena` 的全局结构体，包括空闲列表和当前/上一个 Arena。
   - `tryAlloc`:  尝试从 `gcBitsArena` 中分配指定大小的内存。
   - `newMarkBits`:  为 span 分配新的标记位图。
   - `newAllocBits`: 为 span 分配新的分配位图。
   - `nextMarkBitArenaEpoch`:  在垃圾回收周期结束后，切换用于标记位图的 Arena。
   - `newArenaMayUnlock`:  分配一个新的 `gcBitsArena`，可能会临时释放锁。

**推理 Go 语言功能的实现:**

这部分代码是 Go 语言中以下功能的底层实现：

* **`runtime.SetFinalizer(obj interface{}, finalizer func(*interface{}))`**:  `addfinalizer` 函数是 `runtime.SetFinalizer` 的核心实现。它将一个对象和一个终结函数关联起来。当垃圾回收器发现对象不可达时，会调用与该对象关联的终结函数。

   ```go
   package main

   import (
       "fmt"
       "runtime"
       "time"
   )

   type MyObject struct {
       Name string
   }

   func finalizer(obj *MyObject) {
       fmt.Println("Finalizer called for:", obj.Name)
   }

   func main() {
       obj := &MyObject{Name: "Test Object"}
       runtime.SetFinalizer(obj, finalizer)
       fmt.Println("Object created:", obj.Name)

       // 让对象变得不可达，触发垃圾回收
       obj = nil
       runtime.GC() // 显式触发垃圾回收，但终结器不一定立即执行
       time.Sleep(time.Second) // 等待终结器执行 (不保证)
       fmt.Println("Program finished")
   }

   // 假设输入：程序运行
   // 预期输出（顺序可能不同）：
   // Object created: Test Object
   // Finalizer called for: Test Object
   // Program finished
   ```

* **`runtime.KeepAlive(x interface{})`**:  虽然代码中没有直接叫 `KeepAlive` 的函数，但多处调用了 `KeepAlive(f)` 和 `KeepAlive(ptr)`。 这与 `runtime.KeepAlive` 的作用一致，确保某些对象在特定点之前不会被垃圾回收。

* **`sync.Pool` (可能相关):** `addCleanup` 函数的功能与 `sync.Pool` 中对象清理的理念类似，虽然 `sync.Pool` 的实现细节可能有所不同。`addCleanup` 允许在对象不再被使用时执行一些清理操作，例如释放资源。

   ```go
   package main

   import (
       "fmt"
       "runtime"
       "sync"
   )

   type Resource struct {
       ID int
   }

   func cleanup(r *Resource) {
       fmt.Println("Cleaning up resource:", r.ID)
   }

   func main() {
       var cleanupID uint64
       r := &Resource{ID: 123}
       cleanupIDFunc := func() {
           cleanup(r)
       }

       // 注意：这里直接使用了 runtime 包的私有功能进行演示，
       // 正常情况下应该使用更高级别的抽象，例如 sync.Pool 或自定义的资源管理。
       // 这里的演示仅为了说明 addCleanup 的潜在用途。
       // 实际的 addCleanup 在 mheap.go 中是内部使用的。
       // 无法直接通过公开 API 调用。

       // 假设我们能直接调用 addCleanup (仅为演示)
       // cleanupID = runtime_internal_addCleanup(r, cleanupIDFunc) // 假设存在此函数

       fmt.Println("Resource created")

       // 当 r 不再被使用时...
       r = nil
       runtime.GC()
       // 清理函数会在某个时刻被执行
       fmt.Println("Program finished")
   }

   // 假设输入：程序运行
   // 预期输出（顺序可能不同）：
   // Resource created
   // Cleaning up resource: 123
   // Program finished
   ```

* **`runtime/weak` 包的弱指针:**  `specialWeakHandle` 结构体和 `internal_weak_runtime_registerWeakPointer`/`internal_weak_runtime_makeStrongFromWeak` 函数是 `runtime/weak` 包中弱指针的核心实现。弱指针允许在不阻止对象被垃圾回收的情况下引用对象。

   ```go
   package main

   import (
       "fmt"
       "runtime/weak"
       "time"
   )

   type Data struct {
       Value int
   }

   func main() {
       data := &Data{Value: 42}
       wp := weak.New(data)
       fmt.Println("Weak pointer created")

       // 尝试从弱指针获取强指针
       if strongPtr, ok := wp.Load().(*Data); ok {
           fmt.Println("Got strong pointer:", strongPtr.Value)
       }

       // 让 data 对象变得不可达
       data = nil
       runtime.GC()
       time.Sleep(time.Second) // 等待垃圾回收

       // 再次尝试从弱指针获取强指针
       if strongPtr, ok := wp.Load().(*Data); ok {
           fmt.Println("Got strong pointer again:", strongPtr.Value)
       } else {
           fmt.Println("Weak pointer is now nil")
       }

       fmt.Println("Program finished")
   }

   // 假设输入：程序运行
   // 预期输出（顺序可能不同）：
   // Weak pointer created
   // Got strong pointer: 42
   // Weak pointer is now nil
   // Program finished
   ```

* **`runtime/pprof` 包的堆性能分析:** `specialprofile` 结构体和 `setprofilebucket` 函数是堆性能分析的基础。当分配内存时，可以将其与一个 bucket 关联，以便 `pprof` 工具可以分析内存的使用情况。

   ```go
   package main

   import (
       "fmt"
       "runtime"
       "runtime/pprof"
       "os"
   )

   func main() {
       // 启动 CPU 性能分析（堆性能分析类似）
       f, err := os.Create("heap.prof")
       if err != nil {
           panic(err)
       }
       defer f.Close()
       if err := pprof.WriteHeapProfile(f); err != nil {
           panic(err)
       }

       // 分配一些内存
       _ = make([]byte, 1024*1024)

       fmt.Println("Memory allocated")

       // 运行一段时间
       // ...

       fmt.Println("Program finished")
   }

   // 假设输入：程序运行
   // 预期输出：会在当前目录下生成一个名为 heap.prof 的文件，
   // 可以使用 go tool pprof heap.prof 命令进行分析。
   ```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。与垃圾回收和性能分析相关的命令行参数（例如，控制 GC 的参数）通常在 Go 运行时的其他部分处理，例如 `runtime/proc.go`。

**使用者易犯错的点:**

* **终结器的执行时机不确定:** 终结器只保证在对象不可达之后、内存被回收之前执行，但具体的执行时间点是不确定的，甚至在程序退出时也可能不执行。依赖终结器来执行关键的资源释放操作是不可靠的。 应该使用 `defer` 语句或者显式的清理函数来管理资源。

* **弱指针可能失效:** 在使用弱指针之前，必须检查其指向的对象是否仍然存活。如果在对象被回收后尝试访问弱指针，会得到 `nil`。

* **过度依赖终结器复活对象:** 虽然终结器可以在执行时使对象再次可达（复活），但这会使程序的行为变得复杂和难以预测，并且可能导致内存泄漏。应该避免使用终结器来复活对象。

**归纳一下它的功能:**

这部分 `mheap.go` 代码的核心功能是**提供 Go 语言运行时管理特殊对象（带有终结器、清理器、弱指针等）的底层机制，并为堆内存的性能分析提供支持**。它与 Go 的垃圾回收器紧密配合，确保在对象生命周期结束时能够执行必要的清理操作，并为开发者提供了在不阻止垃圾回收的情况下引用对象的手段。此外，它还为 `pprof` 等工具提供了收集堆内存使用信息的接口。 这些机制共同构成了 Go 语言内存管理和资源清理的重要组成部分。

Prompt: 
```
这是路径为go/src/runtime/mheap.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
ap_.specialfinalizeralloc.alloc())
	unlock(&mheap_.speciallock)
	s.special.kind = _KindSpecialFinalizer
	s.fn = f
	s.nret = nret
	s.fint = fint
	s.ot = ot
	if addspecial(p, &s.special, false) {
		// This is responsible for maintaining the same
		// GC-related invariants as markrootSpans in any
		// situation where it's possible that markrootSpans
		// has already run but mark termination hasn't yet.
		if gcphase != _GCoff {
			base, span, _ := findObject(uintptr(p), 0, 0)
			mp := acquirem()
			gcw := &mp.p.ptr().gcw
			// Mark everything reachable from the object
			// so it's retained for the finalizer.
			if !span.spanclass.noscan() {
				scanobject(base, gcw)
			}
			// Mark the finalizer itself, since the
			// special isn't part of the GC'd heap.
			scanblock(uintptr(unsafe.Pointer(&s.fn)), goarch.PtrSize, &oneptrmask[0], gcw, nil)
			releasem(mp)
		}
		return true
	}

	// There was an old finalizer
	lock(&mheap_.speciallock)
	mheap_.specialfinalizeralloc.free(unsafe.Pointer(s))
	unlock(&mheap_.speciallock)
	return false
}

// Removes the finalizer (if any) from the object p.
func removefinalizer(p unsafe.Pointer) {
	s := (*specialfinalizer)(unsafe.Pointer(removespecial(p, _KindSpecialFinalizer)))
	if s == nil {
		return // there wasn't a finalizer to remove
	}
	lock(&mheap_.speciallock)
	mheap_.specialfinalizeralloc.free(unsafe.Pointer(s))
	unlock(&mheap_.speciallock)
}

// The described object has a cleanup set for it.
type specialCleanup struct {
	_       sys.NotInHeap
	special special
	fn      *funcval
	// Globally unique ID for the cleanup, obtained from mheap_.cleanupID.
	id uint64
}

// addCleanup attaches a cleanup function to the object. Multiple
// cleanups are allowed on an object, and even the same pointer.
// A cleanup id is returned which can be used to uniquely identify
// the cleanup.
func addCleanup(p unsafe.Pointer, f *funcval) uint64 {
	lock(&mheap_.speciallock)
	s := (*specialCleanup)(mheap_.specialCleanupAlloc.alloc())
	mheap_.cleanupID++
	id := mheap_.cleanupID
	unlock(&mheap_.speciallock)
	s.special.kind = _KindSpecialCleanup
	s.fn = f
	s.id = id

	mp := acquirem()
	addspecial(p, &s.special, true)
	// This is responsible for maintaining the same
	// GC-related invariants as markrootSpans in any
	// situation where it's possible that markrootSpans
	// has already run but mark termination hasn't yet.
	if gcphase != _GCoff {
		gcw := &mp.p.ptr().gcw
		// Mark the cleanup itself, since the
		// special isn't part of the GC'd heap.
		scanblock(uintptr(unsafe.Pointer(&s.fn)), goarch.PtrSize, &oneptrmask[0], gcw, nil)
	}
	releasem(mp)
	// Keep f alive. There's a window in this function where it's
	// only reachable via the special while the special hasn't been
	// added to the specials list yet. This is similar to a bug
	// discovered for weak handles, see #70455.
	KeepAlive(f)
	return id
}

// The described object has a weak pointer.
//
// Weak pointers in the GC have the following invariants:
//
//   - Strong-to-weak conversions must ensure the strong pointer
//     remains live until the weak handle is installed. This ensures
//     that creating a weak pointer cannot fail.
//
//   - Weak-to-strong conversions require the weakly-referenced
//     object to be swept before the conversion may proceed. This
//     ensures that weak-to-strong conversions cannot resurrect
//     dead objects by sweeping them before that happens.
//
//   - Weak handles are unique and canonical for each byte offset into
//     an object that a strong pointer may point to, until an object
//     becomes unreachable.
//
//   - Weak handles contain nil as soon as an object becomes unreachable
//     the first time, before a finalizer makes it reachable again. New
//     weak handles created after resurrection are newly unique.
//
// specialWeakHandle is allocated from non-GC'd memory, so any heap
// pointers must be specially handled.
type specialWeakHandle struct {
	_       sys.NotInHeap
	special special
	// handle is a reference to the actual weak pointer.
	// It is always heap-allocated and must be explicitly kept
	// live so long as this special exists.
	handle *atomic.Uintptr
}

//go:linkname internal_weak_runtime_registerWeakPointer weak.runtime_registerWeakPointer
func internal_weak_runtime_registerWeakPointer(p unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(getOrAddWeakHandle(unsafe.Pointer(p)))
}

//go:linkname internal_weak_runtime_makeStrongFromWeak weak.runtime_makeStrongFromWeak
func internal_weak_runtime_makeStrongFromWeak(u unsafe.Pointer) unsafe.Pointer {
	handle := (*atomic.Uintptr)(u)

	// Prevent preemption. We want to make sure that another GC cycle can't start
	// and that work.strongFromWeak.block can't change out from under us.
	mp := acquirem()

	// Yield to the GC if necessary.
	if work.strongFromWeak.block {
		releasem(mp)

		// Try to park and wait for mark termination.
		// N.B. gcParkStrongFromWeak calls acquirem before returning.
		mp = gcParkStrongFromWeak()
	}

	p := handle.Load()
	if p == 0 {
		releasem(mp)
		return nil
	}
	// Be careful. p may or may not refer to valid memory anymore, as it could've been
	// swept and released already. It's always safe to ensure a span is swept, though,
	// even if it's just some random span.
	span := spanOfHeap(p)
	if span == nil {
		// The span probably got swept and released.
		releasem(mp)
		return nil
	}
	// Ensure the span is swept.
	span.ensureSwept()

	// Now we can trust whatever we get from handle, so make a strong pointer.
	//
	// Even if we just swept some random span that doesn't contain this object, because
	// this object is long dead and its memory has since been reused, we'll just observe nil.
	ptr := unsafe.Pointer(handle.Load())

	// This is responsible for maintaining the same GC-related
	// invariants as the Yuasa part of the write barrier. During
	// the mark phase, it's possible that we just created the only
	// valid pointer to the object pointed to by ptr. If it's only
	// ever referenced from our stack, and our stack is blackened
	// already, we could fail to mark it. So, mark it now.
	if gcphase != _GCoff {
		shade(uintptr(ptr))
	}
	releasem(mp)

	// Explicitly keep ptr alive. This seems unnecessary since we return ptr,
	// but let's be explicit since it's important we keep ptr alive across the
	// call to shade.
	KeepAlive(ptr)
	return ptr
}

// gcParkStrongFromWeak puts the current goroutine on the weak->strong queue and parks.
func gcParkStrongFromWeak() *m {
	// Prevent preemption as we check strongFromWeak, so it can't change out from under us.
	mp := acquirem()

	for work.strongFromWeak.block {
		lock(&work.strongFromWeak.lock)
		releasem(mp) // N.B. Holding the lock prevents preemption.

		// Queue ourselves up.
		work.strongFromWeak.q.pushBack(getg())

		// Park.
		goparkunlock(&work.strongFromWeak.lock, waitReasonGCWeakToStrongWait, traceBlockGCWeakToStrongWait, 2)

		// Re-acquire the current M since we're going to check the condition again.
		mp = acquirem()

		// Re-check condition. We may have awoken in the next GC's mark termination phase.
	}
	return mp
}

// gcWakeAllStrongFromWeak wakes all currently blocked weak->strong
// conversions. This is used at the end of a GC cycle.
//
// work.strongFromWeak.block must be false to prevent woken goroutines
// from immediately going back to sleep.
func gcWakeAllStrongFromWeak() {
	lock(&work.strongFromWeak.lock)
	list := work.strongFromWeak.q.popList()
	injectglist(&list)
	unlock(&work.strongFromWeak.lock)
}

// Retrieves or creates a weak pointer handle for the object p.
func getOrAddWeakHandle(p unsafe.Pointer) *atomic.Uintptr {
	// First try to retrieve without allocating.
	if handle := getWeakHandle(p); handle != nil {
		// Keep p alive for the duration of the function to ensure
		// that it cannot die while we're trying to do this.
		KeepAlive(p)
		return handle
	}

	lock(&mheap_.speciallock)
	s := (*specialWeakHandle)(mheap_.specialWeakHandleAlloc.alloc())
	unlock(&mheap_.speciallock)

	handle := new(atomic.Uintptr)
	s.special.kind = _KindSpecialWeakHandle
	s.handle = handle
	handle.Store(uintptr(p))
	if addspecial(p, &s.special, false) {
		// This is responsible for maintaining the same
		// GC-related invariants as markrootSpans in any
		// situation where it's possible that markrootSpans
		// has already run but mark termination hasn't yet.
		if gcphase != _GCoff {
			mp := acquirem()
			gcw := &mp.p.ptr().gcw
			// Mark the weak handle itself, since the
			// special isn't part of the GC'd heap.
			scanblock(uintptr(unsafe.Pointer(&s.handle)), goarch.PtrSize, &oneptrmask[0], gcw, nil)
			releasem(mp)
		}

		// Keep p alive for the duration of the function to ensure
		// that it cannot die while we're trying to do this.
		//
		// Same for handle, which is only stored in the special.
		// There's a window where it might die if we don't keep it
		// alive explicitly. Returning it here is probably good enough,
		// but let's be defensive and explicit. See #70455.
		KeepAlive(p)
		KeepAlive(handle)
		return handle
	}

	// There was an existing handle. Free the special
	// and try again. We must succeed because we're explicitly
	// keeping p live until the end of this function. Either
	// we, or someone else, must have succeeded, because we can
	// only fail in the event of a race, and p will still be
	// be valid no matter how much time we spend here.
	lock(&mheap_.speciallock)
	mheap_.specialWeakHandleAlloc.free(unsafe.Pointer(s))
	unlock(&mheap_.speciallock)

	handle = getWeakHandle(p)
	if handle == nil {
		throw("failed to get or create weak handle")
	}

	// Keep p alive for the duration of the function to ensure
	// that it cannot die while we're trying to do this.
	//
	// Same for handle, just to be defensive.
	KeepAlive(p)
	KeepAlive(handle)
	return handle
}

func getWeakHandle(p unsafe.Pointer) *atomic.Uintptr {
	span := spanOfHeap(uintptr(p))
	if span == nil {
		throw("getWeakHandle on invalid pointer")
	}

	// Ensure that the span is swept.
	// Sweeping accesses the specials list w/o locks, so we have
	// to synchronize with it. And it's just much safer.
	mp := acquirem()
	span.ensureSwept()

	offset := uintptr(p) - span.base()

	lock(&span.speciallock)

	// Find the existing record and return the handle if one exists.
	var handle *atomic.Uintptr
	iter, exists := span.specialFindSplicePoint(offset, _KindSpecialWeakHandle)
	if exists {
		handle = ((*specialWeakHandle)(unsafe.Pointer(*iter))).handle
	}
	unlock(&span.speciallock)
	releasem(mp)

	// Keep p alive for the duration of the function to ensure
	// that it cannot die while we're trying to do this.
	KeepAlive(p)
	return handle
}

// The described object is being heap profiled.
type specialprofile struct {
	_       sys.NotInHeap
	special special
	b       *bucket
}

// Set the heap profile bucket associated with addr to b.
func setprofilebucket(p unsafe.Pointer, b *bucket) {
	lock(&mheap_.speciallock)
	s := (*specialprofile)(mheap_.specialprofilealloc.alloc())
	unlock(&mheap_.speciallock)
	s.special.kind = _KindSpecialProfile
	s.b = b
	if !addspecial(p, &s.special, false) {
		throw("setprofilebucket: profile already set")
	}
}

// specialReachable tracks whether an object is reachable on the next
// GC cycle. This is used by testing.
type specialReachable struct {
	special   special
	done      bool
	reachable bool
}

// specialPinCounter tracks whether an object is pinned multiple times.
type specialPinCounter struct {
	special special
	counter uintptr
}

// specialsIter helps iterate over specials lists.
type specialsIter struct {
	pprev **special
	s     *special
}

func newSpecialsIter(span *mspan) specialsIter {
	return specialsIter{&span.specials, span.specials}
}

func (i *specialsIter) valid() bool {
	return i.s != nil
}

func (i *specialsIter) next() {
	i.pprev = &i.s.next
	i.s = *i.pprev
}

// unlinkAndNext removes the current special from the list and moves
// the iterator to the next special. It returns the unlinked special.
func (i *specialsIter) unlinkAndNext() *special {
	cur := i.s
	i.s = cur.next
	*i.pprev = i.s
	return cur
}

// freeSpecial performs any cleanup on special s and deallocates it.
// s must already be unlinked from the specials list.
func freeSpecial(s *special, p unsafe.Pointer, size uintptr) {
	switch s.kind {
	case _KindSpecialFinalizer:
		sf := (*specialfinalizer)(unsafe.Pointer(s))
		queuefinalizer(p, sf.fn, sf.nret, sf.fint, sf.ot)
		lock(&mheap_.speciallock)
		mheap_.specialfinalizeralloc.free(unsafe.Pointer(sf))
		unlock(&mheap_.speciallock)
	case _KindSpecialWeakHandle:
		sw := (*specialWeakHandle)(unsafe.Pointer(s))
		sw.handle.Store(0)
		lock(&mheap_.speciallock)
		mheap_.specialWeakHandleAlloc.free(unsafe.Pointer(s))
		unlock(&mheap_.speciallock)
	case _KindSpecialProfile:
		sp := (*specialprofile)(unsafe.Pointer(s))
		mProf_Free(sp.b, size)
		lock(&mheap_.speciallock)
		mheap_.specialprofilealloc.free(unsafe.Pointer(sp))
		unlock(&mheap_.speciallock)
	case _KindSpecialReachable:
		sp := (*specialReachable)(unsafe.Pointer(s))
		sp.done = true
		// The creator frees these.
	case _KindSpecialPinCounter:
		lock(&mheap_.speciallock)
		mheap_.specialPinCounterAlloc.free(unsafe.Pointer(s))
		unlock(&mheap_.speciallock)
	case _KindSpecialCleanup:
		sc := (*specialCleanup)(unsafe.Pointer(s))
		// Cleanups, unlike finalizers, do not resurrect the objects
		// they're attached to, so we only need to pass the cleanup
		// function, not the object.
		queuefinalizer(nil, sc.fn, 0, nil, nil)
		lock(&mheap_.speciallock)
		mheap_.specialCleanupAlloc.free(unsafe.Pointer(sc))
		unlock(&mheap_.speciallock)
	default:
		throw("bad special kind")
		panic("not reached")
	}
}

// gcBits is an alloc/mark bitmap. This is always used as gcBits.x.
type gcBits struct {
	_ sys.NotInHeap
	x uint8
}

// bytep returns a pointer to the n'th byte of b.
func (b *gcBits) bytep(n uintptr) *uint8 {
	return addb(&b.x, n)
}

// bitp returns a pointer to the byte containing bit n and a mask for
// selecting that bit from *bytep.
func (b *gcBits) bitp(n uintptr) (bytep *uint8, mask uint8) {
	return b.bytep(n / 8), 1 << (n % 8)
}

const gcBitsChunkBytes = uintptr(64 << 10)
const gcBitsHeaderBytes = unsafe.Sizeof(gcBitsHeader{})

type gcBitsHeader struct {
	free uintptr // free is the index into bits of the next free byte.
	next uintptr // *gcBits triggers recursive type bug. (issue 14620)
}

type gcBitsArena struct {
	_ sys.NotInHeap
	// gcBitsHeader // side step recursive type bug (issue 14620) by including fields by hand.
	free uintptr // free is the index into bits of the next free byte; read/write atomically
	next *gcBitsArena
	bits [gcBitsChunkBytes - gcBitsHeaderBytes]gcBits
}

var gcBitsArenas struct {
	lock     mutex
	free     *gcBitsArena
	next     *gcBitsArena // Read atomically. Write atomically under lock.
	current  *gcBitsArena
	previous *gcBitsArena
}

// tryAlloc allocates from b or returns nil if b does not have enough room.
// This is safe to call concurrently.
func (b *gcBitsArena) tryAlloc(bytes uintptr) *gcBits {
	if b == nil || atomic.Loaduintptr(&b.free)+bytes > uintptr(len(b.bits)) {
		return nil
	}
	// Try to allocate from this block.
	end := atomic.Xadduintptr(&b.free, bytes)
	if end > uintptr(len(b.bits)) {
		return nil
	}
	// There was enough room.
	start := end - bytes
	return &b.bits[start]
}

// newMarkBits returns a pointer to 8 byte aligned bytes
// to be used for a span's mark bits.
func newMarkBits(nelems uintptr) *gcBits {
	blocksNeeded := (nelems + 63) / 64
	bytesNeeded := blocksNeeded * 8

	// Try directly allocating from the current head arena.
	head := (*gcBitsArena)(atomic.Loadp(unsafe.Pointer(&gcBitsArenas.next)))
	if p := head.tryAlloc(bytesNeeded); p != nil {
		return p
	}

	// There's not enough room in the head arena. We may need to
	// allocate a new arena.
	lock(&gcBitsArenas.lock)
	// Try the head arena again, since it may have changed. Now
	// that we hold the lock, the list head can't change, but its
	// free position still can.
	if p := gcBitsArenas.next.tryAlloc(bytesNeeded); p != nil {
		unlock(&gcBitsArenas.lock)
		return p
	}

	// Allocate a new arena. This may temporarily drop the lock.
	fresh := newArenaMayUnlock()
	// If newArenaMayUnlock dropped the lock, another thread may
	// have put a fresh arena on the "next" list. Try allocating
	// from next again.
	if p := gcBitsArenas.next.tryAlloc(bytesNeeded); p != nil {
		// Put fresh back on the free list.
		// TODO: Mark it "already zeroed"
		fresh.next = gcBitsArenas.free
		gcBitsArenas.free = fresh
		unlock(&gcBitsArenas.lock)
		return p
	}

	// Allocate from the fresh arena. We haven't linked it in yet, so
	// this cannot race and is guaranteed to succeed.
	p := fresh.tryAlloc(bytesNeeded)
	if p == nil {
		throw("markBits overflow")
	}

	// Add the fresh arena to the "next" list.
	fresh.next = gcBitsArenas.next
	atomic.StorepNoWB(unsafe.Pointer(&gcBitsArenas.next), unsafe.Pointer(fresh))

	unlock(&gcBitsArenas.lock)
	return p
}

// newAllocBits returns a pointer to 8 byte aligned bytes
// to be used for this span's alloc bits.
// newAllocBits is used to provide newly initialized spans
// allocation bits. For spans not being initialized the
// mark bits are repurposed as allocation bits when
// the span is swept.
func newAllocBits(nelems uintptr) *gcBits {
	return newMarkBits(nelems)
}

// nextMarkBitArenaEpoch establishes a new epoch for the arenas
// holding the mark bits. The arenas are named relative to the
// current GC cycle which is demarcated by the call to finishweep_m.
//
// All current spans have been swept.
// During that sweep each span allocated room for its gcmarkBits in
// gcBitsArenas.next block. gcBitsArenas.next becomes the gcBitsArenas.current
// where the GC will mark objects and after each span is swept these bits
// will be used to allocate objects.
// gcBitsArenas.current becomes gcBitsArenas.previous where the span's
// gcAllocBits live until all the spans have been swept during this GC cycle.
// The span's sweep extinguishes all the references to gcBitsArenas.previous
// by pointing gcAllocBits into the gcBitsArenas.current.
// The gcBitsArenas.previous is released to the gcBitsArenas.free list.
func nextMarkBitArenaEpoch() {
	lock(&gcBitsArenas.lock)
	if gcBitsArenas.previous != nil {
		if gcBitsArenas.free == nil {
			gcBitsArenas.free = gcBitsArenas.previous
		} else {
			// Find end of previous arenas.
			last := gcBitsArenas.previous
			for last = gcBitsArenas.previous; last.next != nil; last = last.next {
			}
			last.next = gcBitsArenas.free
			gcBitsArenas.free = gcBitsArenas.previous
		}
	}
	gcBitsArenas.previous = gcBitsArenas.current
	gcBitsArenas.current = gcBitsArenas.next
	atomic.StorepNoWB(unsafe.Pointer(&gcBitsArenas.next), nil) // newMarkBits calls newArena when needed
	unlock(&gcBitsArenas.lock)
}

// newArenaMayUnlock allocates and zeroes a gcBits arena.
// The caller must hold gcBitsArena.lock. This may temporarily release it.
func newArenaMayUnlock() *gcBitsArena {
	var result *gcBitsArena
	if gcBitsArenas.free == nil {
		unlock(&gcBitsArenas.lock)
		result = (*gcBitsArena)(sysAlloc(gcBitsChunkBytes, &memstats.gcMiscSys))
		if result == nil {
			throw("runtime: cannot allocate memory")
		}
		lock(&gcBitsArenas.lock)
	} else {
		result = gcBitsArenas.free
		gcBitsArenas.free = gcBitsArenas.free.next
		memclrNoHeapPointers(unsafe.Pointer(result), gcBitsChunkBytes)
	}
	result.next = nil
	// If result.bits is not 8 byte aligned adjust index so
	// that &result.bits[result.free] is 8 byte aligned.
	if unsafe.Offsetof(gcBitsArena{}.bits)&7 == 0 {
		result.free = 0
	} else {
		result.free = 8 - (uintptr(unsafe.Pointer(&result.bits[0])) & 7)
	}
	return result
}

"""




```