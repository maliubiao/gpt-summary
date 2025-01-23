Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/heap/heap.cc`. The summary should also consider the possibility of the file being a Torque file (which it isn't based on the `.cc` extension) and should connect the functionality to JavaScript where applicable. I also need to identify common user errors related to this code and handle potential code logic inferences with example inputs and outputs. Finally, I need to indicate this is part 5 of a 9-part series.

Here's a breakdown of the code and how to address the user's requests:

1. **LeftTrimArray Function:** This function reduces the size of an array by removing elements from the beginning. It creates a filler object for the trimmed portion and updates the array's metadata.
2. **RightTrimArray Function:**  Similar to `LeftTrimArray`, but it removes elements from the end of the array. It also handles filler object creation and metadata updates, with special handling for large objects and different GC states.
3. **MakeHeapIterable/MakeLinearAllocationAreasIterable/FreeLinearAllocationAreas/FreeMainThreadLinearAllocationAreas:** These functions control the iterability and freeing of linear allocation areas within the heap, involving different threads and isolates.
4. **MarkSharedLinearAllocationAreasBlack/UnmarkSharedLinearAllocationAreas/FreeSharedLinearAllocationAreasAndResetFreeLists:** These functions deal with marking and unmarking shared linear allocation areas, likely related to concurrent garbage collection.
5. **Unmark/DeactivateMajorGCInProgressFlag:** These functions seem related to resetting the marking state of the heap, possibly in preparation for a new garbage collection cycle.
6. **ComputeMutatorUtilization/HasLow[Young/Old/Embedder]AllocationRate/HasLowAllocationRate:** These functions calculate the efficiency of the mutator (the program executing JavaScript) versus the garbage collector, helping determine if the allocation rate is low.
7. **IsIneffectiveMarkCompact/CheckIneffectiveMarkCompact/ReportIneffectiveMarkCompactIfNeeded:** These functions identify and report situations where mark-compact garbage collection is not effectively reclaiming memory, potentially leading to out-of-memory errors.
8. **HasHighFragmentation/ShouldOptimizeForMemoryUsage:** These functions assess the heap's fragmentation and determine if memory usage optimization is needed.
9. **ActivateMemoryReducerIfNeeded/ActivateMemoryReducerIfNeededOnMainThread:**  These functions manage a memory reducer, which likely tries to free up memory when the system is under memory pressure.
10. **ShouldResizeNewSpace/ExpandNewSpaceSize/ReduceNewSpaceSize/NewSpaceSize/NewSpaceCapacity/NewSpaceTargetCapacity:** These functions manage the resizing of the new space (where young objects are initially allocated), aiming for efficient memory management.
11. **FinalizeIncrementalMarkingAtomically/InvokeIncrementalMarkingPrologueCallbacks/InvokeIncrementalMarkingEpilogueCallbacks:** These functions control the steps of incremental marking garbage collection, allowing the garbage collector to work in smaller steps without blocking the main thread for too long.
12. **NotifyObjectLayoutChange/NotifyObjectLayoutChangeDone:** These functions handle notifications when the layout of an object in the heap changes, ensuring consistency and updating related data structures (like remembered sets for garbage collection).
13. **NotifyObjectSizeChange:** This function handles the case where the size of an object changes, often by creating a "filler" object in the freed space.
14. **MonotonicallyIncreasingTimeInMs:**  A utility function to get the current time.
15. **VerifyNewSpaceTop:** A debug function to verify the state of the new space.
16. **MemoryPressureInterruptTask/CheckMemoryPressure/CollectGarbageOnMemoryPressure/MemoryPressureNotification:** These functions respond to memory pressure signals, triggering garbage collection to free up memory.
17. **EagerlyFreeExternalMemoryAndWasmCode:**  This function aggressively frees external memory and WebAssembly code to reduce memory usage.
18. **AddNearHeapLimitCallback/RemoveNearHeapLimitCallback/InvokeNearHeapLimitCallback:** These functions allow users to register callbacks that are invoked when the heap is nearing its limit, providing a chance to adjust the limit or take other actions.
19. **AppendArrayBufferExtension/ResizeArrayBufferExtension/DetachArrayBufferExtension:** These functions manage the extensions of ArrayBuffers, which are used to store raw binary data.
20. **AutomaticallyRestoreInitialHeapLimit:** This function sets up automatic restoration of the initial heap limit.
21. **MeasureMemory/CreateDefaultMeasureMemoryDelegate:** These functions allow for measuring the memory usage of JavaScript contexts.
22. **CollectCodeStatistics:** This function gathers statistics about the code in the heap.

**Connecting to JavaScript:** Many of these functions are internal workings of the V8 engine and don't have direct JavaScript equivalents. However, the effects are visible in JavaScript's memory management behavior. For example, `LeftTrimArray` and `RightTrimArray` are used internally when JavaScript array methods like `slice` or setting the `length` property effectively resize arrays. Memory pressure notifications affect when garbage collection runs, which in turn impacts JavaScript performance.

**Common Programming Errors:**  While developers don't directly call these C++ functions, understanding their purpose can help in avoiding memory-intensive JavaScript patterns that lead to frequent garbage collections or out-of-memory errors. Examples include creating very large arrays, leaking object references, or inefficiently managing external resources.

**Torque:** The code is in `.cc`, so it's C++, not Torque.

**Logic Inference:** I'll provide examples for the trimming functions.
这是 V8 引擎中 `v8/src/heap/heap.cc` 文件的一部分代码，主要涉及堆内存的管理和调整，以及与垃圾回收相关的操作。以下是其功能的归纳：

**功能归纳：**

这段代码主要实现了以下功能，专注于对堆中数组对象进行裁剪（trimming）以及与内存管理和垃圾回收相关的操作：

1. **数组裁剪 (Array Trimming):**
    *   **`LeftTrimArray`:**  实现了从数组的头部移除元素的功能。这通常发生在数组的某个部分不再需要被引用时。
    *   **`RightTrimArray`:** 实现了从数组的尾部移除元素的功能。这通常发生在数组的容量需要缩减时。
    *   这两个函数都会创建填充对象 (filler object) 来标记被裁剪掉的空间，并更新数组的元数据（例如长度、容量）。

2. **堆状态管理与迭代:**
    *   **`MakeHeapIterable` 和 `MakeLinearAllocationAreasIterable`:**  使得堆和线性分配区域可以被迭代访问，这在调试、分析或垃圾回收过程中很有用。
    *   **`FreeLinearAllocationAreas` 和 `FreeMainThreadLinearAllocationAreas`:** 释放线性分配区域的内存。
    *   **`MarkSharedLinearAllocationAreasBlack`，`UnmarkSharedLinearAllocationAreas`，`FreeSharedLinearAllocationAreasAndResetFreeLists`:**  管理共享线性分配区域的标记和释放，这与并发垃圾回收有关。

3. **垃圾回收相关操作:**
    *   **`Unmark` 和 `DeactivateMajorGCInProgressFlag`:**  用于重置堆的标记状态，为新的垃圾回收周期做准备。
    *   **`ComputeMutatorUtilization` 等一系列函数:**  计算 mutator（执行 JavaScript 代码的引擎）的利用率，并判断各种内存区域的分配速率是否过低。这些指标用于辅助垃圾回收策略的决策。
    *   **`IsIneffectiveMarkCompact`，`CheckIneffectiveMarkCompact`，`ReportIneffectiveMarkCompactIfNeeded`:**  检测和报告标记压缩 (Mark-Compact) 垃圾回收是否效率低下，这有助于诊断内存管理问题。
    *   **`HasHighFragmentation` 和 `ShouldOptimizeForMemoryUsage`:**  判断堆的碎片化程度，并决定是否应该优化内存使用。
    *   **`ActivateMemoryReducerIfNeeded` 和 `ActivateMemoryReducerIfNeededOnMainThread`:**  激活内存缩减器，尝试降低内存使用。
    *   **`ShouldResizeNewSpace`，`ExpandNewSpaceSize`，`ReduceNewSpaceSize`，`NewSpaceSize` 等:**  管理新生代 (New Space) 的大小，动态调整其容量以提高内存利用率和垃圾回收效率。
    *   **`FinalizeIncrementalMarkingAtomically`，`InvokeIncrementalMarkingPrologueCallbacks`，`InvokeIncrementalMarkingEpilogueCallbacks`:**  与增量标记 (Incremental Marking) 垃圾回收相关，允许垃圾回收分步进行，减少主线程的停顿时间。

4. **对象布局和大小变更通知:**
    *   **`NotifyObjectLayoutChange` 和 `NotifyObjectLayoutChangeDone`:**  当堆中对象的布局发生变化时发出通知，这通常发生在对象类型转换或调整内部结构时。
    *   **`NotifyObjectSizeChange`:**  当堆中对象的大小发生变化时发出通知，并可能创建填充对象来管理释放的空间。

5. **内存压力管理:**
    *   **`MemoryPressureInterruptTask`，`CheckMemoryPressure`，`CollectGarbageOnMemoryPressure`，`MemoryPressureNotification`:**  处理系统内存压力通知，并根据压力级别触发不同程度的垃圾回收操作。

6. **外部内存和 WebAssembly 代码管理:**
    *   **`EagerlyFreeExternalMemoryAndWasmCode`:**  尝试主动释放外部内存和 WebAssembly 代码占用的内存。

7. **堆限制回调:**
    *   **`AddNearHeapLimitCallback`，`RemoveNearHeapLimitCallback`，`InvokeNearHeapLimitCallback`:**  允许注册回调函数，当堆接近其容量限制时会被调用，这允许应用程序在内存耗尽前采取措施。

8. **ArrayBuffer 管理:**
    *   **`AppendArrayBufferExtension`，`ResizeArrayBufferExtension`，`DetachArrayBufferExtension`:**  管理 `ArrayBuffer` 对象的扩展内存。

9. **内存测量:**
    *   **`MeasureMemory` 和 `CreateDefaultMeasureMemoryDelegate`:**  提供测量 JavaScript 上下文内存使用情况的功能。

10. **代码统计:**
    *   **`CollectCodeStatistics`:**  收集关于堆中代码的统计信息。

**关于 `.tq` 结尾：**

如果 `v8/src/heap/heap.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是 V8 用于生成高效的运行时函数的领域特定语言。由于这里文件名为 `.cc`，它是一个标准的 C++ 源代码文件。

**与 JavaScript 的关系及示例：**

这些 C++ 代码的功能是 V8 引擎内部的核心机制，直接影响 JavaScript 的内存管理和性能。虽然开发者不能直接在 JavaScript 中调用这些函数，但它们的效果是可见的。

*   **数组裁剪 (Array Trimming):**
    ```javascript
    const arr = [1, 2, 3, 4, 5];
    const newArr = arr.slice(2); // 裁剪头部
    console.log(newArr); // 输出: [3, 4, 5]

    arr.length = 3; // 裁剪尾部
    console.log(arr); // 输出: [1, 2, 3]
    ```
    当你在 JavaScript 中使用 `slice()` 或修改数组的 `length` 属性来缩减数组大小时，V8 内部可能会调用类似 `LeftTrimArray` 或 `RightTrimArray` 的机制来释放不再使用的内存。

*   **内存压力管理和垃圾回收:**  JavaScript 的垃圾回收是自动进行的。当 V8 感知到内存压力时（通过 `MemoryPressureNotification` 等机制），会自动触发垃圾回收来回收不再使用的对象。
    ```javascript
    // 创建大量对象，可能导致内存压力
    for (let i = 0; i < 1000000; i++) {
      const obj = { data: new Array(1000) };
    }
    // 一段时间后，V8 的垃圾回收器会自动回收这些不再引用的对象。
    ```

*   **ArrayBuffer 管理:**
    ```javascript
    const buffer = new ArrayBuffer(16); // 创建一个 16 字节的 ArrayBuffer
    const uint8Array = new Uint8Array(buffer);

    // ArrayBuffer 的大小可以通过扩展来改变（取决于实现和上下文）
    // 在某些情况下，V8 内部会调用类似 AppendArrayBufferExtension 的机制
    ```

**代码逻辑推理及示例：**

让我们以 `LeftTrimArray` 为例进行代码逻辑推理：

**假设输入：**

*   `object`: 一个指向 `FixedArrayBase` 对象的指针，假设该数组起始地址为 `0x1000`，长度为 10，每个元素大小为 4 字节（`kTaggedSize`）。
*   `bytes_to_trim`: 8 字节，表示要从头部裁剪掉的空间。

**代码逻辑：**

1. `new_start = old_start + bytes_to_trim;`: 计算新数组的起始地址，`0x1000 + 8 = 0x1008`。
2. `CreateFillerObjectAtRaw(...)`: 在原数组的头部创建填充对象，从 `0x1000` 开始，大小为 8 字节。
3. 更新裁剪后数组的头部信息（从 `0x1008` 开始）：
    *   写入 `map`。
    *   写入新的长度 `len - elements_to_trim` (假设 `elements_to_trim` 为 2，则新长度为 8)。
4. 创建并返回指向新数组的指针 `new_object`，其地址为 `0x1008`。

**预期输出：**

*   在地址 `0x1000` 到 `0x1007` 的内存区域会创建一个填充对象。
*   `new_object` 指向的数组起始于地址 `0x1008`，长度为原数组长度减去裁剪掉的元素个数。

**用户常见的编程错误：**

虽然用户不能直接调用这些底层的 C++ 函数，但理解其原理可以帮助避免 JavaScript 中的一些常见内存相关的编程错误：

1. **意外持有不再需要的对象的引用:**  导致垃圾回收器无法回收这些对象，造成内存泄漏。例如，在闭包中引用了外部作用域中不再需要的变量。
    ```javascript
    function createLeakyArray() {
      let largeArray = new Array(1000000);
      return function() {
        // 即使 createLeakyArray 执行完毕，largeArray 仍然被内部函数引用，无法被回收
        console.log("Array still here:", largeArray.length);
      };
    }

    const leakyFunc = createLeakyArray();
    // ... 即使我们不再直接使用 leakyFunc，largeArray 的内存仍然可能被占用
    ```

2. **创建过大的数组或对象:**  消耗大量内存，可能导致频繁的垃圾回收或内存溢出错误。
    ```javascript
    const hugeArray = new Array(100000000); // 尝试创建一个巨大的数组
    // 这可能会导致性能问题或内存错误
    ```

3. **不当使用 ArrayBuffer 和 Typed Arrays:**  未能正确管理 `ArrayBuffer` 的生命周期或创建过大的 `ArrayBuffer`，可能导致内存泄漏。

4. **在循环中创建大量临时对象:**  导致频繁的内存分配和垃圾回收。
    ```javascript
    for (let i = 0; i < 100000; i++) {
      const tempObj = {}; // 每次循环都创建一个新的临时对象
      // ...
    }
    ```

**总结:**

这段 `v8/src/heap/heap.cc` 代码片段专注于 V8 引擎的堆内存管理，特别是针对数组对象的裁剪操作，以及与垃圾回收和内存压力管理相关的核心功能。理解这些内部机制有助于开发者更好地理解 JavaScript 的内存管理行为，并避免一些常见的内存相关的编程错误。这是第 5 部分，意味着还有 4 部分相关的代码会进一步深入介绍 V8 堆的实现细节。

### 提示词
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
ddress new_start = old_start + bytes_to_trim;

  // Technically in new space this write might be omitted (except for
  // debug mode which iterates through the heap), but to play safer
  // we still do it.
  CreateFillerObjectAtRaw(
      WritableFreeSpace::ForNonExecutableMemory(old_start, bytes_to_trim),
      ClearFreedMemoryMode::kClearFreedMemory,
      MayContainRecordedSlots(object) ? ClearRecordedSlots::kYes
                                      : ClearRecordedSlots::kNo,
      VerifyNoSlotsRecorded::kYes);

  // Initialize header of the trimmed array. Since left trimming is only
  // performed on pages which are not concurrently swept creating a filler
  // object does not require synchronization.
  RELAXED_WRITE_FIELD(object, bytes_to_trim,
                      Tagged<Object>(MapWord::FromMap(map).ptr()));
  RELAXED_WRITE_FIELD(object, bytes_to_trim + kTaggedSize,
                      Smi::FromInt(len - elements_to_trim));

  Tagged<FixedArrayBase> new_object =
      Cast<FixedArrayBase>(HeapObject::FromAddress(new_start));

  if (isolate()->log_object_relocation()) {
    // Notify the heap profiler of change in object layout.
    OnMoveEvent(object, new_object, new_object->Size());
  }

#ifdef ENABLE_SLOW_DCHECKS
  if (v8_flags.enable_slow_asserts) {
    // Make sure the stack or other roots (e.g., Handles) don't contain pointers
    // to the original FixedArray (which is now the filler object).
    std::optional<IsolateSafepointScope> safepoint_scope;

    {
      AllowGarbageCollection allow_gc;
      safepoint_scope.emplace(this);
    }

    LeftTrimmerVerifierRootVisitor root_visitor(object);
    ReadOnlyRoots(this).Iterate(&root_visitor);

    // Stale references are allowed in some locations. IterateRoots() uses
    // ClearStaleLeftTrimmedPointerVisitor internally to clear such references
    // beforehand.
    IterateRoots(&root_visitor,
                 base::EnumSet<SkipRoot>{SkipRoot::kConservativeStack});
  }
#endif  // ENABLE_SLOW_DCHECKS

  return new_object;
}

template <typename Array>
void Heap::RightTrimArray(Tagged<Array> object, int new_capacity,
                          int old_capacity) {
  DCHECK_EQ(old_capacity, object->capacity());
  DCHECK_LT(new_capacity, old_capacity);
  DCHECK_GE(new_capacity, 0);

  if constexpr (Array::kElementsAreMaybeObject) {
    // For MaybeObject elements, this function is safe to use only at the end
    // of the mark compact collection: When marking, we record the weak slots,
    // and shrinking invalidates them.
    DCHECK_EQ(gc_state(), MARK_COMPACT);
  }

  const int bytes_to_trim = (old_capacity - new_capacity) * Array::kElementSize;

  // Calculate location of new array end.
  const int old_size = Array::SizeFor(old_capacity);
  DCHECK_EQ(object->AllocatedSize(), old_size);
  Address old_end = object.address() + old_size;
  Address new_end = old_end - bytes_to_trim;

  const bool clear_slots = MayContainRecordedSlots(object);

  // Technically in new space this write might be omitted (except for debug
  // mode which iterates through the heap), but to play safer we still do it.
  // We do not create a filler for objects in a large object space.
  if (!IsLargeObject(object)) {
    NotifyObjectSizeChange(
        object, old_size, old_size - bytes_to_trim,
        clear_slots ? ClearRecordedSlots::kYes : ClearRecordedSlots::kNo);
    if (!v8_flags.black_allocated_pages) {
      Tagged<HeapObject> filler = HeapObject::FromAddress(new_end);
      // Clear the mark bits of the black area that belongs now to the filler.
      // This is an optimization. The sweeper will release black fillers anyway.
      if (incremental_marking()->black_allocation() &&
          marking_state()->IsMarked(filler)) {
        PageMetadata* page = PageMetadata::FromAddress(new_end);
        page->marking_bitmap()->ClearRange<AccessMode::ATOMIC>(
            MarkingBitmap::AddressToIndex(new_end),
            MarkingBitmap::LimitAddressToIndex(new_end + bytes_to_trim));
      }
    }
  } else if (clear_slots) {
    // Large objects are not swept, so it is not necessary to clear the
    // recorded slot.
    MemsetTagged(ObjectSlot(new_end), Tagged<Object>(kClearedFreeMemoryValue),
                 (old_end - new_end) / kTaggedSize);
  }

  // Initialize header of the trimmed array. We are storing the new capacity
  // using release store after creating a filler for the left-over space to
  // avoid races with the sweeper thread.
  object->set_capacity(new_capacity, kReleaseStore);

  // Notify the heap object allocation tracker of change in object layout. The
  // array may not be moved during GC, and size has to be adjusted nevertheless.
  for (auto& tracker : allocation_trackers_) {
    tracker->UpdateObjectSizeEvent(object.address(),
                                   Array::SizeFor(new_capacity));
  }
}

#define DEF_RIGHT_TRIM(T)                                     \
  template EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) void     \
  Heap::RightTrimArray<T>(Tagged<T> object, int new_capacity, \
                          int old_capacity);
RIGHT_TRIMMABLE_ARRAY_LIST(DEF_RIGHT_TRIM)
#undef DEF_RIGHT_TRIM

void Heap::MakeHeapIterable() {
  EnsureSweepingCompleted(SweepingForcedFinalizationMode::kV8Only);

  MakeLinearAllocationAreasIterable();
}

void Heap::MakeLinearAllocationAreasIterable() {
  allocator()->MakeLinearAllocationAreasIterable();

  safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
    local_heap->MakeLinearAllocationAreasIterable();
  });

  if (isolate()->is_shared_space_isolate()) {
    isolate()->global_safepoint()->IterateClientIsolates([](Isolate* client) {
      client->heap()->MakeLinearAllocationAreasIterable();
    });
  }
}

void Heap::FreeLinearAllocationAreas() {
  FreeMainThreadLinearAllocationAreas();

  safepoint()->IterateLocalHeaps(
      [](LocalHeap* local_heap) { local_heap->FreeLinearAllocationAreas(); });

  if (isolate()->is_shared_space_isolate()) {
    isolate()->global_safepoint()->IterateClientIsolates(
        [](Isolate* client) { client->heap()->FreeLinearAllocationAreas(); });
  }
}

void Heap::FreeMainThreadLinearAllocationAreas() {
  allocator()->FreeLinearAllocationAreas();
}

void Heap::MarkSharedLinearAllocationAreasBlack() {
  DCHECK(!v8_flags.black_allocated_pages);
  allocator()->MarkSharedLinearAllocationAreasBlack();
  main_thread_local_heap()->MarkSharedLinearAllocationAreasBlack();

  safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
    local_heap->MarkSharedLinearAllocationAreasBlack();
  });
}

void Heap::UnmarkSharedLinearAllocationAreas() {
  DCHECK(!v8_flags.black_allocated_pages);
  allocator()->UnmarkSharedLinearAllocationAreas();
  main_thread_local_heap()->UnmarkSharedLinearAllocationsArea();
  safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
    local_heap->UnmarkSharedLinearAllocationsArea();
  });
}

void Heap::FreeSharedLinearAllocationAreasAndResetFreeLists() {
  DCHECK(v8_flags.black_allocated_pages);
  allocator()->FreeSharedLinearAllocationAreasAndResetFreeLists();
  main_thread_local_heap()->FreeSharedLinearAllocationAreasAndResetFreeLists();

  safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
    local_heap->FreeSharedLinearAllocationAreasAndResetFreeLists();
  });
}

void Heap::Unmark() {
  DCHECK(v8_flags.sticky_mark_bits);
  DCHECK_NULL(new_space());

  auto unmark_space = [](auto& space) {
    for (auto* page : space) {
      page->marking_bitmap()->template Clear<AccessMode::NON_ATOMIC>();
      page->Chunk()->SetMajorGCInProgress();
      page->SetLiveBytes(0);
    }
  };

  unmark_space(*old_space());
  unmark_space(*lo_space());

  if (isolate()->is_shared_space_isolate()) {
    unmark_space(*shared_space());
    unmark_space(*shared_lo_space());
  }

  {
    RwxMemoryWriteScope scope("For writing flags.");
    unmark_space(*code_space());
    unmark_space(*code_lo_space());
  }

  unmark_space(*trusted_space());
  unmark_space(*trusted_lo_space());
}

void Heap::DeactivateMajorGCInProgressFlag() {
  DCHECK(v8_flags.sticky_mark_bits);
  DCHECK_NULL(new_space());

  auto deactivate_space = [](auto& space) {
    for (auto* metadata : space) {
      metadata->Chunk()->ResetMajorGCInProgress();
    }
  };

  deactivate_space(*old_space());
  deactivate_space(*lo_space());

  {
    RwxMemoryWriteScope scope("For writing flags.");
    deactivate_space(*code_space());
    deactivate_space(*code_lo_space());
  }

  if (isolate()->is_shared_space_isolate()) {
    deactivate_space(*shared_space());
    deactivate_space(*shared_lo_space());
  }

  deactivate_space(*trusted_space());
  deactivate_space(*trusted_lo_space());
}

namespace {

double ComputeMutatorUtilizationImpl(double mutator_speed, double gc_speed) {
  constexpr double kMinMutatorUtilization = 0.0;
  constexpr double kConservativeGcSpeedInBytesPerMillisecond = 200000;
  if (mutator_speed == 0) return kMinMutatorUtilization;
  if (gc_speed == 0) gc_speed = kConservativeGcSpeedInBytesPerMillisecond;
  // Derivation:
  // mutator_utilization = mutator_time / (mutator_time + gc_time)
  // mutator_time = 1 / mutator_speed
  // gc_time = 1 / gc_speed
  // mutator_utilization = (1 / mutator_speed) /
  //                       (1 / mutator_speed + 1 / gc_speed)
  // mutator_utilization = gc_speed / (mutator_speed + gc_speed)
  return gc_speed / (mutator_speed + gc_speed);
}

}  // namespace

double Heap::ComputeMutatorUtilization(const char* tag, double mutator_speed,
                                       double gc_speed) {
  double result = ComputeMutatorUtilizationImpl(mutator_speed, gc_speed);
  if (v8_flags.trace_mutator_utilization) {
    isolate()->PrintWithTimestamp(
        "%s mutator utilization = %.3f ("
        "mutator_speed=%.f, gc_speed=%.f)\n",
        tag, result, mutator_speed, gc_speed);
  }
  return result;
}

bool Heap::HasLowYoungGenerationAllocationRate() {
  double mu = ComputeMutatorUtilization(
      "Young generation",
      tracer()->NewSpaceAllocationThroughputInBytesPerMillisecond(),
      tracer()->YoungGenerationSpeedInBytesPerMillisecond(
          YoungGenerationSpeedMode::kOnlyAtomicPause));
  constexpr double kHighMutatorUtilization = 0.993;
  return mu > kHighMutatorUtilization;
}

bool Heap::HasLowOldGenerationAllocationRate() {
  double mu = ComputeMutatorUtilization(
      "Old generation",
      tracer()->OldGenerationAllocationThroughputInBytesPerMillisecond(),
      tracer()->OldGenerationSpeedInBytesPerMillisecond());
  const double kHighMutatorUtilization = 0.993;
  return mu > kHighMutatorUtilization;
}

bool Heap::HasLowEmbedderAllocationRate() {
  double mu = ComputeMutatorUtilization(
      "Embedder", tracer()->EmbedderAllocationThroughputInBytesPerMillisecond(),
      tracer()->EmbedderSpeedInBytesPerMillisecond());
  const double kHighMutatorUtilization = 0.993;
  return mu > kHighMutatorUtilization;
}

bool Heap::HasLowAllocationRate() {
  return HasLowYoungGenerationAllocationRate() &&
         HasLowOldGenerationAllocationRate() && HasLowEmbedderAllocationRate();
}

bool Heap::IsIneffectiveMarkCompact(size_t old_generation_size,
                                    double mutator_utilization) {
  const double kHighHeapPercentage = 0.8;
  const double kLowMutatorUtilization = 0.4;
  return old_generation_size >=
             kHighHeapPercentage * max_old_generation_size() &&
         mutator_utilization < kLowMutatorUtilization;
}

namespace {
static constexpr int kMaxConsecutiveIneffectiveMarkCompacts = 4;
}

void Heap::CheckIneffectiveMarkCompact(size_t old_generation_size,
                                       double mutator_utilization) {
  if (!v8_flags.detect_ineffective_gcs_near_heap_limit) return;
  if (!IsIneffectiveMarkCompact(old_generation_size, mutator_utilization)) {
    consecutive_ineffective_mark_compacts_ = 0;
    return;
  }
  ++consecutive_ineffective_mark_compacts_;
  if (consecutive_ineffective_mark_compacts_ ==
      kMaxConsecutiveIneffectiveMarkCompacts) {
    if (InvokeNearHeapLimitCallback()) {
      // The callback increased the heap limit.
      consecutive_ineffective_mark_compacts_ = 0;
      return;
    }
  }
}

void Heap::ReportIneffectiveMarkCompactIfNeeded() {
  DCHECK_IMPLIES(!v8_flags.detect_ineffective_gcs_near_heap_limit,
                 consecutive_ineffective_mark_compacts_ == 0);
  if (consecutive_ineffective_mark_compacts_ ==
      kMaxConsecutiveIneffectiveMarkCompacts) {
    if (v8_flags.heap_snapshot_on_oom) {
      isolate()->heap_profiler()->WriteSnapshotToDiskAfterGC();
    }
    FatalProcessOutOfMemory("Ineffective mark-compacts near heap limit");
  }
}

bool Heap::HasHighFragmentation() {
  const size_t used = OldGenerationSizeOfObjects();
  const size_t committed = CommittedOldGenerationMemory();

  // Background thread allocation could result in committed memory being less
  // than used memory in some situations.
  if (committed < used) return false;

  constexpr size_t kSlack = 16 * MB;

  // Fragmentation is high if committed > 2 * used + kSlack.
  // Rewrite the expression to avoid overflow.
  return committed - used > used + kSlack;
}

bool Heap::ShouldOptimizeForMemoryUsage() {
  const size_t kOldGenerationSlack = max_old_generation_size() / 8;
  return v8_flags.optimize_for_size ||
         isolate()->priority() == v8::Isolate::Priority::kBestEffort ||
         HighMemoryPressure() || !CanExpandOldGeneration(kOldGenerationSlack);
}

class ActivateMemoryReducerTask : public CancelableTask {
 public:
  explicit ActivateMemoryReducerTask(Heap* heap)
      : CancelableTask(heap->isolate()), heap_(heap) {}

  ~ActivateMemoryReducerTask() override = default;
  ActivateMemoryReducerTask(const ActivateMemoryReducerTask&) = delete;
  ActivateMemoryReducerTask& operator=(const ActivateMemoryReducerTask&) =
      delete;

 private:
  // v8::internal::CancelableTask overrides.
  void RunInternal() override {
    heap_->ActivateMemoryReducerIfNeededOnMainThread();
  }

  Heap* heap_;
};

void Heap::ActivateMemoryReducerIfNeeded() {
  if (memory_reducer_ == nullptr) return;
  // This method may be called from any thread. Post a task to run it on the
  // isolate's main thread to avoid synchronization.
  task_runner_->PostTask(std::make_unique<ActivateMemoryReducerTask>(this));
}

void Heap::ActivateMemoryReducerIfNeededOnMainThread() {
  // Activate memory reducer when switching to background if
  // - there was no mark compact since the start.
  // - the committed memory can be potentially reduced.
  // 2 pages for the old, code, and map space + 1 page for new space.
  const int kMinCommittedMemory = 7 * PageMetadata::kPageSize;
  if (ms_count_ == 0 && CommittedMemory() > kMinCommittedMemory &&
      isolate()->is_backgrounded()) {
    memory_reducer_->NotifyPossibleGarbage();
  }
}

Heap::ResizeNewSpaceMode Heap::ShouldResizeNewSpace() {
  if (ShouldReduceMemory()) {
    return (v8_flags.predictable) ? ResizeNewSpaceMode::kNone
                                  : ResizeNewSpaceMode::kShrink;
  }

  static const size_t kLowAllocationThroughput = 1000;
  const double allocation_throughput =
      tracer_->AllocationThroughputInBytesPerMillisecond();
  const bool should_shrink = !v8_flags.predictable &&
                             (allocation_throughput != 0) &&
                             (allocation_throughput < kLowAllocationThroughput);

  const bool should_grow =
      (new_space_->TotalCapacity() < new_space_->MaximumCapacity()) &&
      (survived_since_last_expansion_ > new_space_->TotalCapacity());

  if (should_grow) survived_since_last_expansion_ = 0;

  if (should_grow == should_shrink) return ResizeNewSpaceMode::kNone;
  return should_grow ? ResizeNewSpaceMode::kGrow : ResizeNewSpaceMode::kShrink;
}

void Heap::ExpandNewSpaceSize() {
  // Grow the size of new space if there is room to grow, and enough data
  // has survived scavenge since the last expansion.
  new_space_->Grow();
  new_lo_space()->SetCapacity(new_space()->TotalCapacity());
}

void Heap::ReduceNewSpaceSize() {
  // MinorMS shrinks new space as part of sweeping.
  if (!v8_flags.minor_ms) {
    SemiSpaceNewSpace::From(new_space())->Shrink();
  } else {
    paged_new_space()->FinishShrinking();
  }
  new_lo_space_->SetCapacity(new_space()->TotalCapacity());
}

size_t Heap::NewSpaceSize() {
  if (v8_flags.sticky_mark_bits) {
    return sticky_space()->young_objects_size();
  }
  return new_space() ? new_space()->Size() : 0;
}

size_t Heap::NewSpaceCapacity() const {
  if (v8_flags.sticky_mark_bits) {
    return sticky_space()->Capacity() - sticky_space()->young_objects_size();
  }
  return new_space() ? new_space()->Capacity() : 0;
}

size_t Heap::NewSpaceTargetCapacity() const {
  if (v8_flags.sticky_mark_bits) {
    // TODO(333906585): Adjust target capacity for new sticky-space.
    return sticky_space()->Capacity() - sticky_space()->young_objects_size();
  }
  return new_space() ? new_space()->TotalCapacity() : 0;
}

void Heap::FinalizeIncrementalMarkingAtomically(
    GarbageCollectionReason gc_reason) {
  DCHECK(!incremental_marking()->IsStopped());
  CollectAllGarbage(current_gc_flags_, gc_reason, current_gc_callback_flags_);
}

void Heap::InvokeIncrementalMarkingPrologueCallbacks() {
  AllowGarbageCollection allow_allocation;
  VMState<EXTERNAL> state(isolate_);
  CallGCPrologueCallbacks(kGCTypeIncrementalMarking, kNoGCCallbackFlags,
                          GCTracer::Scope::MC_INCREMENTAL_EXTERNAL_PROLOGUE);
}

void Heap::InvokeIncrementalMarkingEpilogueCallbacks() {
  AllowGarbageCollection allow_allocation;
  VMState<EXTERNAL> state(isolate_);
  CallGCEpilogueCallbacks(kGCTypeIncrementalMarking, kNoGCCallbackFlags,
                          GCTracer::Scope::MC_INCREMENTAL_EXTERNAL_EPILOGUE);
}

namespace {
thread_local Address pending_layout_change_object_address = kNullAddress;

#ifdef V8_ENABLE_SANDBOX
class ExternalPointerSlotInvalidator
    : public HeapVisitor<ExternalPointerSlotInvalidator> {
 public:
  explicit ExternalPointerSlotInvalidator(Isolate* isolate)
      : HeapVisitor(isolate), isolate_(isolate) {}

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {}
  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) override {}
  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {}
  void VisitMapPointer(Tagged<HeapObject> host) override {}

  void VisitExternalPointer(Tagged<HeapObject> host,
                            ExternalPointerSlot slot) override {
    DCHECK_EQ(target_, host);
    ExternalPointerTable::Space* space =
        IsolateForSandbox(isolate_).GetExternalPointerTableSpaceFor(
            slot.tag(), host.address());
    space->NotifyExternalPointerFieldInvalidated(slot.address(), slot.tag());
    num_invalidated_slots++;
  }

  int Visit(Tagged<HeapObject> target) {
    target_ = target;
    num_invalidated_slots = 0;
    HeapVisitor::Visit(target);
    return num_invalidated_slots;
  }

 private:
  Isolate* isolate_;
  Tagged<HeapObject> target_;
  int num_invalidated_slots = 0;
};
#endif  // V8_ENABLE_SANDBOX

}  // namespace

void Heap::NotifyObjectLayoutChange(
    Tagged<HeapObject> object, const DisallowGarbageCollection&,
    InvalidateRecordedSlots invalidate_recorded_slots,
    InvalidateExternalPointerSlots invalidate_external_pointer_slots,
    int new_size) {
  if (invalidate_recorded_slots == InvalidateRecordedSlots::kYes) {
    const bool may_contain_recorded_slots = MayContainRecordedSlots(object);
    MutablePageMetadata* const chunk =
        MutablePageMetadata::FromHeapObject(object);
    // Do not remove the recorded slot in the map word as this one can never be
    // invalidated.
    const Address clear_range_start = object.address() + kTaggedSize;
    // Only slots in the range of the new object size (which is potentially
    // smaller than the original one) can be invalidated. Clearing of recorded
    // slots up to the original object size even conflicts with concurrent
    // sweeping.
    const Address clear_range_end = object.address() + new_size;

    if (incremental_marking()->IsMarking()) {
      ExclusiveObjectLock::Lock(object);
      DCHECK_EQ(pending_layout_change_object_address, kNullAddress);
      pending_layout_change_object_address = object.address();
      if (may_contain_recorded_slots && incremental_marking()->IsCompacting()) {
        RememberedSet<OLD_TO_OLD>::RemoveRange(
            chunk, clear_range_start, clear_range_end,
            SlotSet::EmptyBucketMode::KEEP_EMPTY_BUCKETS);
      }
    }

    if (may_contain_recorded_slots) {
      RememberedSet<OLD_TO_NEW>::RemoveRange(
          chunk, clear_range_start, clear_range_end,
          SlotSet::EmptyBucketMode::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
          chunk, clear_range_start, clear_range_end,
          SlotSet::EmptyBucketMode::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_SHARED>::RemoveRange(
          chunk, clear_range_start, clear_range_end,
          SlotSet::EmptyBucketMode::KEEP_EMPTY_BUCKETS);
    }

    DCHECK(!chunk->InTrustedSpace());
  }

  // During external pointer table compaction, the external pointer table
  // records addresses of fields that index into the external pointer table. As
  // such, it needs to be informed when such a field is invalidated.
  if (invalidate_external_pointer_slots ==
      InvalidateExternalPointerSlots::kYes) {
    // Currently, the only time this function receives
    // InvalidateExternalPointerSlots::kYes is when an external string
    // transitions to a thin string.  If this ever changed to happen for array
    // buffer extension slots, we would have to run the invalidator in
    // pointer-compression-but-no-sandbox configurations as well.
    DCHECK(IsString(object));
#ifdef V8_ENABLE_SANDBOX
    if (V8_ENABLE_SANDBOX_BOOL) {
      ExternalPointerSlotInvalidator slot_invalidator(isolate());
      int num_invalidated_slots = slot_invalidator.Visit(object);
      USE(num_invalidated_slots);
      DCHECK_GT(num_invalidated_slots, 0);
    }

    // During concurrent marking for a minor GC, the heap also builds up a
    // RememberedSet of external pointer field locations, and uses that set to
    // evacuate external pointer table entries when promoting objects.  Here we
    // would need to invalidate that set too; until we do, assert that
    // NotifyObjectLayoutChange is never called on young objects.
    CHECK(!HeapLayout::InYoungGeneration(object));
#endif
  }

#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) {
    HeapVerifier::SetPendingLayoutChangeObject(this, object);
  }
#endif
}

// static
void Heap::NotifyObjectLayoutChangeDone(Tagged<HeapObject> object) {
  if (pending_layout_change_object_address != kNullAddress) {
    DCHECK_EQ(pending_layout_change_object_address, object.address());
    ExclusiveObjectLock::Unlock(object);
    pending_layout_change_object_address = kNullAddress;
  }
}

void Heap::NotifyObjectSizeChange(Tagged<HeapObject> object, int old_size,
                                  int new_size,
                                  ClearRecordedSlots clear_recorded_slots) {
  old_size = ALIGN_TO_ALLOCATION_ALIGNMENT(old_size);
  new_size = ALIGN_TO_ALLOCATION_ALIGNMENT(new_size);
  DCHECK_LE(new_size, old_size);
  DCHECK(!IsLargeObject(object));
  if (new_size == old_size) return;

  const bool is_main_thread = LocalHeap::Current() == nullptr;

  DCHECK_IMPLIES(!is_main_thread,
                 clear_recorded_slots == ClearRecordedSlots::kNo);

  const auto verify_no_slots_recorded =
      is_main_thread ? VerifyNoSlotsRecorded::kYes : VerifyNoSlotsRecorded::kNo;

  const auto clear_memory_mode = ClearFreedMemoryMode::kDontClearFreedMemory;

  const Address filler = object.address() + new_size;
  const int filler_size = old_size - new_size;
  CreateFillerObjectAtRaw(
      WritableFreeSpace::ForNonExecutableMemory(filler, filler_size),
      clear_memory_mode, clear_recorded_slots, verify_no_slots_recorded);
}

double Heap::MonotonicallyIncreasingTimeInMs() const {
  return V8::GetCurrentPlatform()->MonotonicallyIncreasingTime() *
         static_cast<double>(base::Time::kMillisecondsPerSecond);
}

#if DEBUG
void Heap::VerifyNewSpaceTop() {
  if (!new_space()) return;
  allocator()->new_space_allocator()->Verify();
}
#endif  // DEBUG

class MemoryPressureInterruptTask : public CancelableTask {
 public:
  explicit MemoryPressureInterruptTask(Heap* heap)
      : CancelableTask(heap->isolate()), heap_(heap) {}

  ~MemoryPressureInterruptTask() override = default;
  MemoryPressureInterruptTask(const MemoryPressureInterruptTask&) = delete;
  MemoryPressureInterruptTask& operator=(const MemoryPressureInterruptTask&) =
      delete;

 private:
  // v8::internal::CancelableTask overrides.
  void RunInternal() override { heap_->CheckMemoryPressure(); }

  Heap* heap_;
};

void Heap::CheckMemoryPressure() {
  if (HighMemoryPressure()) {
    // The optimizing compiler may be unnecessarily holding on to memory.
    isolate()->AbortConcurrentOptimization(BlockingBehavior::kDontBlock);
  }
  // Reset the memory pressure level to avoid recursive GCs triggered by
  // CheckMemoryPressure from AdjustAmountOfExternalMemory called by
  // the finalizers.
  MemoryPressureLevel memory_pressure_level = memory_pressure_level_.exchange(
      MemoryPressureLevel::kNone, std::memory_order_relaxed);
  if (memory_pressure_level == MemoryPressureLevel::kCritical) {
    TRACE_EVENT0("devtools.timeline,v8", "V8.CheckMemoryPressure");
    CollectGarbageOnMemoryPressure();
  } else if (memory_pressure_level == MemoryPressureLevel::kModerate) {
    if (v8_flags.incremental_marking && incremental_marking()->IsStopped()) {
      TRACE_EVENT0("devtools.timeline,v8", "V8.CheckMemoryPressure");
      StartIncrementalMarking(GCFlag::kReduceMemoryFootprint,
                              GarbageCollectionReason::kMemoryPressure);
    }
  }
}

void Heap::CollectGarbageOnMemoryPressure() {
  const int kGarbageThresholdInBytes = 8 * MB;
  const double kGarbageThresholdAsFractionOfTotalMemory = 0.1;
  // This constant is the maximum response time in RAIL performance model.
  const double kMaxMemoryPressurePauseMs = 100;

  double start = MonotonicallyIncreasingTimeInMs();
  CollectAllGarbage(GCFlag::kReduceMemoryFootprint,
                    GarbageCollectionReason::kMemoryPressure,
                    kGCCallbackFlagCollectAllAvailableGarbage);
  EagerlyFreeExternalMemoryAndWasmCode();
  double end = MonotonicallyIncreasingTimeInMs();

  // Estimate how much memory we can free.
  int64_t potential_garbage =
      (CommittedMemory() - SizeOfObjects()) + external_memory();
  // If we can potentially free large amount of memory, then start GC right
  // away instead of waiting for memory reducer.
  if (potential_garbage >= kGarbageThresholdInBytes &&
      potential_garbage >=
          CommittedMemory() * kGarbageThresholdAsFractionOfTotalMemory) {
    // If we spent less than half of the time budget, then perform full GC
    // Otherwise, start incremental marking.
    if (end - start < kMaxMemoryPressurePauseMs / 2) {
      CollectAllGarbage(GCFlag::kReduceMemoryFootprint,
                        GarbageCollectionReason::kMemoryPressure,
                        kGCCallbackFlagCollectAllAvailableGarbage);
    } else {
      if (v8_flags.incremental_marking && incremental_marking()->IsStopped()) {
        StartIncrementalMarking(GCFlag::kReduceMemoryFootprint,
                                GarbageCollectionReason::kMemoryPressure);
      }
    }
  }
}

void Heap::MemoryPressureNotification(MemoryPressureLevel level,
                                      bool is_isolate_locked) {
  TRACE_EVENT1("devtools.timeline,v8", "V8.MemoryPressureNotification", "level",
               static_cast<int>(level));
  MemoryPressureLevel previous =
      memory_pressure_level_.exchange(level, std::memory_order_relaxed);
  if ((previous != MemoryPressureLevel::kCritical &&
       level == MemoryPressureLevel::kCritical) ||
      (previous == MemoryPressureLevel::kNone &&
       level == MemoryPressureLevel::kModerate)) {
    if (is_isolate_locked) {
      CheckMemoryPressure();
    } else {
      ExecutionAccess access(isolate());
      isolate()->stack_guard()->RequestGC();
      task_runner_->PostTask(
          std::make_unique<MemoryPressureInterruptTask>(this));
    }
  }
}

void Heap::EagerlyFreeExternalMemoryAndWasmCode() {
#if V8_ENABLE_WEBASSEMBLY
  if (v8_flags.flush_liftoff_code) {
    // Flush Liftoff code and record the flushed code size.
    auto [code_size, metadata_size] = wasm::GetWasmEngine()->FlushLiftoffCode();
    isolate_->counters()->wasm_flushed_liftoff_code_size_bytes()->AddSample(
        static_cast<int>(code_size));
    isolate_->counters()->wasm_flushed_liftoff_metadata_size_bytes()->AddSample(
        static_cast<int>(metadata_size));
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  CompleteArrayBufferSweeping(this);
}

void Heap::AddNearHeapLimitCallback(v8::NearHeapLimitCallback callback,
                                    void* data) {
  const size_t kMaxCallbacks = 100;
  CHECK_LT(near_heap_limit_callbacks_.size(), kMaxCallbacks);
  for (auto callback_data : near_heap_limit_callbacks_) {
    CHECK_NE(callback_data.first, callback);
  }
  near_heap_limit_callbacks_.push_back(std::make_pair(callback, data));
}

void Heap::RemoveNearHeapLimitCallback(v8::NearHeapLimitCallback callback,
                                       size_t heap_limit) {
  for (size_t i = 0; i < near_heap_limit_callbacks_.size(); i++) {
    if (near_heap_limit_callbacks_[i].first == callback) {
      near_heap_limit_callbacks_.erase(near_heap_limit_callbacks_.begin() + i);
      if (heap_limit) {
        RestoreHeapLimit(heap_limit);
      }
      return;
    }
  }
  UNREACHABLE();
}

void Heap::AppendArrayBufferExtension(Tagged<JSArrayBuffer> object,
                                      ArrayBufferExtension* extension) {
  // ArrayBufferSweeper is managing all counters and updating Heap counters.
  array_buffer_sweeper_->Append(object, extension);
}

void Heap::ResizeArrayBufferExtension(ArrayBufferExtension* extension,
                                      int64_t delta) {
  // ArrayBufferSweeper is managing all counters and updating Heap counters.
  array_buffer_sweeper_->Resize(extension, delta);
}

void Heap::DetachArrayBufferExtension(ArrayBufferExtension* extension) {
  // ArrayBufferSweeper is managing all counters and updating Heap counters.
  return array_buffer_sweeper_->Detach(extension);
}

void Heap::AutomaticallyRestoreInitialHeapLimit(double threshold_percent) {
  initial_max_old_generation_size_threshold_ =
      initial_max_old_generation_size_ * threshold_percent;
}

bool Heap::InvokeNearHeapLimitCallback() {
  if (!near_heap_limit_callbacks_.empty()) {
    AllowGarbageCollection allow_gc;
    TRACE_GC(tracer(), GCTracer::Scope::HEAP_EXTERNAL_NEAR_HEAP_LIMIT);
    VMState<EXTERNAL> callback_state(isolate());
    HandleScope scope(isolate());
    v8::NearHeapLimitCallback callback =
        near_heap_limit_callbacks_.back().first;
    void* data = near_heap_limit_callbacks_.back().second;
    size_t heap_limit = callback(data, max_old_generation_size(),
                                 initial_max_old_generation_size_);
    if (heap_limit > max_old_generation_size()) {
      SetOldGenerationAndGlobalMaximumSize(
          std::min(heap_limit, AllocatorLimitOnMaxOldGenerationSize()));
      return true;
    }
  }
  return false;
}

bool Heap::MeasureMemory(std::unique_ptr<v8::MeasureMemoryDelegate> delegate,
                         v8::MeasureMemoryExecution execution) {
  HandleScope handle_scope(isolate());
  std::vector<Handle<NativeContext>> contexts = FindAllNativeContexts();
  std::vector<Handle<NativeContext>> to_measure;
  for (auto& current : contexts) {
    if (delegate->ShouldMeasure(v8::Utils::ToLocal(current))) {
      to_measure.push_back(current);
    }
  }
  return memory_measurement_->EnqueueRequest(std::move(delegate), execution,
                                             to_measure);
}

std::unique_ptr<v8::MeasureMemoryDelegate>
Heap::CreateDefaultMeasureMemoryDelegate(
    v8::Local<v8::Context> context, v8::Local<v8::Promise::Resolver> promise,
    v8::MeasureMemoryMode mode) {
  return i::MemoryMeasurement::DefaultDelegate(
      reinterpret_cast<v8::Isolate*>(isolate_), context, promise, mode);
}

void Heap::CollectCodeStatistics() {
  TRACE_EVENT0("v8", "Heap::CollectCodeStatistics");
  SafepointScope safepoint_scope(isolate(),
                                 kGlobalSafepointForSharedSpaceIsolate);
  MakeHea
```