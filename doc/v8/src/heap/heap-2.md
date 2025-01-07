Response: The user is asking for a summary of the functionality of the C++ code snippet provided, which is part 3 of a 5-part file. They also want an example in JavaScript to illustrate the relationship if any exists between the C++ code and JavaScript.

The code snippet focuses on several key heap management functionalities within the V8 JavaScript engine:

1. **Array Trimming:** It implements functions for both left and right trimming of arrays. This involves adjusting the boundaries of an array in memory, potentially freeing up space or moving the array's starting point.

2. **Making Heap Iterable:** It provides mechanisms to prepare the heap for iteration, which is often needed for operations like garbage collection and heap snapshots. This includes ensuring that linear allocation areas are also iterable.

3. **Freeing Linear Allocation Areas:**  It includes functions to release memory used for linear allocation, a strategy for fast object allocation.

4. **Marking and Unmarking Shared Linear Allocation Areas:**  It provides functions for managing the marking of shared memory regions used for linear allocation, which is relevant for garbage collection in multi-isolate scenarios.

5. **Unmarking Heap for Sticky Mark Bits:** It includes a function to clear the marking bits across the heap when using a "sticky mark bits" strategy.

6. **Calculating Mutator Utilization:** It defines functions to compute the efficiency of JavaScript execution (the "mutator") relative to garbage collection.

7. **Detecting Ineffective Mark-Compacts:** It implements logic to identify situations where mark-compact garbage collection is not yielding significant memory savings, potentially indicating memory pressure.

8. **Memory Reducer Activation:** It includes functions to trigger a memory reduction process when needed, often in response to low memory conditions.

9. **Resizing New Space:** It provides logic for deciding whether and how to resize the "new space" in the heap, where newly created objects are initially allocated.

10. **Finalizing Incremental Marking:** It includes a function to complete an ongoing incremental marking phase of garbage collection.

11. **Notifying Object Layout Changes:** It defines a function to inform the heap about changes in an object's structure or size, which is crucial for maintaining the integrity of the heap and related data structures like remembered sets and external pointer tables.

12. **Notifying Object Size Changes:**  It provides a function to update the heap about changes in the size of an object, creating filler objects for the freed space.

13. **Memory Pressure Handling:** It includes functions to respond to memory pressure notifications, potentially triggering garbage collection or incremental marking.

14. **External Memory Management:** It provides functions related to managing external memory associated with JavaScript objects, particularly ArrayBuffers.

15. **Near Heap Limit Callbacks:**  It includes mechanisms for registering and invoking callbacks when the heap approaches its limits.

16. **Memory Measurement:**  It provides functions to initiate and manage memory measurement processes, allowing developers to understand memory usage patterns.

17. **Code Statistics Collection:**  It defines functions to gather statistics about the code objects within the heap.

18. **Heap Containment Checks:** It includes functions to determine if a given memory address or object resides within the heap or specific spaces within the heap.

19. **Iterating Heap Roots:** It provides a comprehensive set of functions to iterate over different categories of "roots" in the heap, which are pointers that keep objects alive and are essential for garbage collection. This includes strong roots, weak roots, SMI roots, stack roots, and more. It also includes specific handling for left-trimmed objects during root iteration.

20. **Heap Configuration:** It includes a function to configure the heap based on resource constraints and flags.

21. **Ring Buffer for Tracing:** It provides a simple ring buffer mechanism for storing recent trace messages.

22. **Recording Heap Statistics:** It defines a function to collect and record various heap statistics.

**Relationship to JavaScript:**

Many of these C++ functions directly support JavaScript's memory management model. For instance:

* **Array Trimming:**  While JavaScript doesn't have direct methods to "trim" arrays in the same way, V8 might internally use these mechanisms when optimizing array storage or when resizing typed arrays.

* **Garbage Collection:**  All the functions related to marking, sweeping, and memory pressure are fundamental to V8's automatic garbage collection, which frees up memory used by objects that are no longer reachable in JavaScript.

* **Heap Iteration:**  This is used by V8 internally for garbage collection, debugging tools, and heap snapshots, which can be triggered by JavaScript profilers.

* **Memory Measurement:** The `v8::MeasureMemory` API exposed to JavaScript allows developers to trigger detailed memory usage analysis, which internally relies on these C++ functions.

**JavaScript Example:**

```javascript
// This example demonstrates how actions in JavaScript can trigger
// the underlying heap management mechanisms in V8.

// Creating a large array might eventually trigger garbage collection
const largeArray = new Array(1000000).fill(0);

// Resizing a typed array might involve internal trimming operations
const typedArray = new Uint32Array(100);
typedArray.subarray(0, 50); // Creating a view, might involve optimization

// Triggering a memory measurement (requires --expose-gc flag in Node.js)
if (global.gc) {
  global.gc(); // Force garbage collection (for demonstration purposes)
  // In a real application, you wouldn't force GC like this.
}

// Using the v8.getHeapStatistics() API to see heap information
const heapStats = v8.getHeapStatistics();
console.log(heapStats);

// Using the v8.getHeapSpaceStatistics() API to see details about heap spaces
const heapSpaceStats = v8.getHeapSpaceStatistics();
console.log(heapSpaceStats);

// Asynchronous memory measurement API
if (v8.hasOwnProperty('measureMemory')) {
  v8.measureMemory({ mode: 'detailed' })
    .then(measurement => {
      console.log(measurement);
    });
}
```

**Summary of Part 3:**

This part of the `heap.cc` file in V8's source code focuses on **memory management operations** related to **array manipulation (trimming), heap iteration, linear allocation, garbage collection control (marking, unmarking, finalization, memory pressure handling), object layout and size changes, memory measurement, code statistics, and heap integrity checks**. It provides the low-level mechanisms that enable V8 to efficiently manage memory for JavaScript execution.

这是目录为v8/src/heap/heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

**功能归纳:**

这段 C++ 代码主要负责 V8 堆的以下几个方面的管理和操作：

1. **数组的修剪 (Trimming Arrays):** 实现了对数组进行左修剪 (`LeftTrimFixedArray`) 和右修剪 (`RightTrimArray`) 的功能。这通常用于优化内存使用，例如当数组前端或后端有不再需要使用的空间时，可以将其释放。

2. **使堆可迭代 (Making Heap Iterable):**  提供了使堆内存区域（包括线性分配区域）可迭代的功能。这对于垃圾回收等需要遍历堆中所有对象的场景至关重要。

3. **释放线性分配区域 (Freeing Linear Allocation Areas):** 提供了释放用于快速对象分配的线性内存区域的功能。

4. **标记和取消标记共享线性分配区域 (Marking/Unmarking Shared Linear Allocation Areas):**  在多 Isolate 共享堆的场景下，提供了标记和取消标记共享线性分配区域的功能，用于垃圾回收过程。

5. **计算 Mutator 利用率 (Computing Mutator Utilization):**  定义了计算 JavaScript 代码执行（Mutator）相对于垃圾回收器效率的指标，用于辅助垃圾回收策略的制定。

6. **检测低效的 Mark-Compact (Detecting Ineffective Mark-Compacts):**  实现了检测 Mark-Compact 垃圾回收是否低效的逻辑，如果回收效果不佳，可能会触发额外的操作。

7. **激活内存缩减器 (Activating Memory Reducer):** 提供了激活内存缩减器的功能，用于在内存压力较大时主动释放内存。

8. **调整新生代空间大小 (Resizing New Space):**  包含了调整新生代空间大小的逻辑，根据内存使用情况决定是否需要扩展或收缩新生代空间。

9. **原子地完成增量标记 (Finalizing Incremental Marking Atomically):**  提供了原子地完成增量标记垃圾回收阶段的功能。

10. **通知对象布局改变 (Notifying Object Layout Change):**  提供了通知堆管理器对象布局发生变化的功能，例如当对象的 size 改变时，需要更新相关的元数据。

11. **通知对象大小改变 (Notifying Object Size Change):** 提供了通知堆管理器对象大小发生变化的功能，并创建填充对象来管理释放出来的空间。

12. **内存压力通知 (Memory Pressure Notification):**  实现了响应系统内存压力通知并采取相应措施（例如触发垃圾回收）的功能。

13. **外部内存管理 (External Memory Management):**  包含了一些管理外部内存（例如 ArrayBuffer 的外部内存）的功能。

14. **近堆限制回调 (Near Heap Limit Callbacks):**  提供了注册和调用近堆限制回调的机制，当堆内存使用接近限制时，可以通知应用程序。

15. **内存测量 (Memory Measurement):**  提供了进行内存测量的功能，可以用于分析内存使用情况。

16. **收集代码统计信息 (Collecting Code Statistics):**  提供了收集堆中代码对象统计信息的功能。

17. **堆包含判断 (Heap Containment Checks):**  提供了一些判断一个对象或地址是否在堆内存中的函数。

18. **迭代堆根 (Iterating Heap Roots):**  提供了多种迭代堆中不同类型根对象的函数，这是垃圾回收标记阶段的关键步骤。

19. **配置堆 (Configuring Heap):**  提供了配置堆大小和各种参数的功能。

20. **循环缓冲区 (Ring Buffer):**  实现了一个用于存储最近的跟踪信息的循环缓冲区。

21. **记录统计信息 (Recording Stats):**  提供了记录堆的各种统计信息的功能。

**与 JavaScript 的关系以及示例:**

这段 C++ 代码是 V8 引擎内部堆管理的核心部分，它直接支撑着 JavaScript 的内存分配和垃圾回收。许多 JavaScript 的行为都会触发这些底层的 C++ 代码：

* **创建和操作数组:**  JavaScript 中创建、扩展、收缩数组的操作，在 V8 内部可能就会用到 `LeftTrimFixedArray` 和 `RightTrimArray` 这类函数来管理内存。

```javascript
// JavaScript 示例

// 创建一个大数组
const arr = new Array(10000);

// 删除数组前面的一些元素 (可能会触发左修剪)
arr.splice(0, 5000);

// 缩小数组长度 (可能会触发右修剪)
arr.length = 2000;
```

* **垃圾回收:**  JavaScript 的垃圾回收机制完全依赖于 V8 堆的实现。当 JavaScript 对象不再被引用时，V8 的垃圾回收器会遍历堆（利用“使堆可迭代”的功能），标记不再使用的对象，并最终释放内存。内存压力通知、增量标记等概念在 JavaScript 中虽然不可直接控制，但其行为会影响 JavaScript 的执行性能。

```javascript
// JavaScript 示例 (通常不需要手动调用，V8 会自动进行垃圾回收)

// 创建大量对象，使得旧的对象变得不可达，触发垃圾回收
function createObjects() {
  for (let i = 0; i < 100000; i++) {
    let obj = { data: new Array(100) };
  }
}

createObjects();
// ... 一段时间后，V8 会自动进行垃圾回收
```

* **ArrayBuffer 和外部内存:**  JavaScript 的 `ArrayBuffer` 允许访问原始的二进制数据。V8 的 `heap.cc` 中的外部内存管理功能就用于跟踪和管理这些与 JavaScript 对象关联的外部内存。

```javascript
// JavaScript 示例

// 创建一个 ArrayBuffer，它会在 V8 堆外分配内存
const buffer = new ArrayBuffer(1024);
```

* **性能监控:**  JavaScript 的性能监控 API (如 `performance.measureMemory()`, 实验性功能) 可能会利用 V8 内部的内存测量功能来提供更详细的内存使用信息。

```javascript
// JavaScript 示例 (实验性 API)
if ('measureMemory' in performance) {
  performance.measureMemory()
    .then(measurement => {
      console.log(measurement);
    });
}
```

**总结第 3 部分的功能:**

第 3 部分的 `heap.cc` 代码主要关注 **V8 堆的内存管理和优化**。它提供了用于**调整数组大小、管理内存区域、响应内存压力、控制垃圾回收过程、跟踪对象布局和大小变化**以及**收集堆统计信息**的底层机制。这些机制是 V8 引擎高效运行 JavaScript 代码和管理内存的关键组成部分。虽然 JavaScript 开发者通常不需要直接操作这些底层功能，但了解这些机制有助于理解 JavaScript 引擎的工作原理和性能特征。

Prompt: 
```
这是目录为v8/src/heap/heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
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
  MakeHeapIterable();
  CodeStatistics::ResetCodeAndMetadataStatistics(isolate());
  // We do not look for code in new space, or map space.  If code
  // somehow ends up in those spaces, we would miss it here.
  CodeStatistics::CollectCodeStatistics(code_space_, isolate());
  CodeStatistics::CollectCodeStatistics(old_space_, isolate());
  CodeStatistics::CollectCodeStatistics(code_lo_space_, isolate());
  CodeStatistics::CollectCodeStatistics(trusted_space_, isolate());
  CodeStatistics::CollectCodeStatistics(trusted_lo_space_, isolate());
}

#ifdef DEBUG

void Heap::Print() {
  if (!HasBeenSetUp()) return;
  isolate()->PrintStack(stdout);

  for (SpaceIterator it(this); it.HasNext();) {
    it.Next()->Print();
  }
}

void Heap::ReportCodeStatistics(const char* title) {
  PrintF("###### Code Stats (%s) ######\n", title);
  CollectCodeStatistics();
  CodeStatistics::ReportCodeStatistics(isolate());
}

#endif  // DEBUG

bool Heap::Contains(Tagged<HeapObject> value) const {
  if (ReadOnlyHeap::Contains(value)) {
    return false;
  }
  if (memory_allocator()->IsOutsideAllocatedSpace(value.address())) {
    return false;
  }

  if (!HasBeenSetUp()) return false;

  return (new_space_ && new_space_->Contains(value)) ||
         old_space_->Contains(value) || code_space_->Contains(value) ||
         (shared_space_ && shared_space_->Contains(value)) ||
         (shared_trusted_space_ && shared_trusted_space_->Contains(value)) ||
         lo_space_->Contains(value) || code_lo_space_->Contains(value) ||
         (new_lo_space_ && new_lo_space_->Contains(value)) ||
         trusted_space_->Contains(value) ||
         trusted_lo_space_->Contains(value) ||
         (shared_lo_space_ && shared_lo_space_->Contains(value)) ||
         (shared_trusted_lo_space_ &&
          shared_trusted_lo_space_->Contains(value));
}

bool Heap::ContainsCode(Tagged<HeapObject> value) const {
  // TODO(v8:11880): support external code space.
  if (memory_allocator()->IsOutsideAllocatedSpace(value.address(),
                                                  EXECUTABLE)) {
    return false;
  }
  return HasBeenSetUp() &&
         (code_space_->Contains(value) || code_lo_space_->Contains(value));
}

bool Heap::SharedHeapContains(Tagged<HeapObject> value) const {
  if (shared_allocation_space_) {
    if (shared_allocation_space_->Contains(value)) return true;
    if (shared_lo_allocation_space_->Contains(value)) return true;
    if (shared_trusted_allocation_space_->Contains(value)) return true;
    if (shared_trusted_lo_allocation_space_->Contains(value)) return true;
  }

  return false;
}

bool Heap::MustBeInSharedOldSpace(Tagged<HeapObject> value) {
  if (isolate()->OwnsStringTables()) return false;
  if (ReadOnlyHeap::Contains(value)) return false;
  if (HeapLayout::InYoungGeneration(value)) return false;
  if (IsExternalString(value)) return false;
  if (IsInternalizedString(value)) return true;
  return false;
}

bool Heap::InSpace(Tagged<HeapObject> value, AllocationSpace space) const {
  if (memory_allocator()->IsOutsideAllocatedSpace(
          value.address(),
          IsAnyCodeSpace(space) ? EXECUTABLE : NOT_EXECUTABLE)) {
    return false;
  }
  if (!HasBeenSetUp()) return false;

  switch (space) {
    case NEW_SPACE:
      return new_space_->Contains(value);
    case OLD_SPACE:
      return old_space_->Contains(value);
    case CODE_SPACE:
      return code_space_->Contains(value);
    case SHARED_SPACE:
      return shared_space_->Contains(value);
    case TRUSTED_SPACE:
      return trusted_space_->Contains(value);
    case SHARED_TRUSTED_SPACE:
      return shared_trusted_space_->Contains(value);
    case LO_SPACE:
      return lo_space_->Contains(value);
    case CODE_LO_SPACE:
      return code_lo_space_->Contains(value);
    case NEW_LO_SPACE:
      return new_lo_space_->Contains(value);
    case SHARED_LO_SPACE:
      return shared_lo_space_->Contains(value);
    case SHARED_TRUSTED_LO_SPACE:
      return shared_trusted_lo_space_->Contains(value);
    case TRUSTED_LO_SPACE:
      return trusted_lo_space_->Contains(value);
    case RO_SPACE:
      return ReadOnlyHeap::Contains(value);
  }
  UNREACHABLE();
}

bool Heap::InSpaceSlow(Address addr, AllocationSpace space) const {
  if (memory_allocator()->IsOutsideAllocatedSpace(
          addr, IsAnyCodeSpace(space) ? EXECUTABLE : NOT_EXECUTABLE)) {
    return false;
  }
  if (!HasBeenSetUp()) return false;

  switch (space) {
    case NEW_SPACE:
      return new_space_->ContainsSlow(addr);
    case OLD_SPACE:
      return old_space_->ContainsSlow(addr);
    case CODE_SPACE:
      return code_space_->ContainsSlow(addr);
    case SHARED_SPACE:
      return shared_space_->ContainsSlow(addr);
    case TRUSTED_SPACE:
      return trusted_space_->ContainsSlow(addr);
    case SHARED_TRUSTED_SPACE:
      return shared_trusted_space_->ContainsSlow(addr);
    case LO_SPACE:
      return lo_space_->ContainsSlow(addr);
    case CODE_LO_SPACE:
      return code_lo_space_->ContainsSlow(addr);
    case NEW_LO_SPACE:
      return new_lo_space_->ContainsSlow(addr);
    case SHARED_LO_SPACE:
      return shared_lo_space_->ContainsSlow(addr);
    case SHARED_TRUSTED_LO_SPACE:
      return shared_trusted_lo_space_->ContainsSlow(addr);
    case TRUSTED_LO_SPACE:
      return trusted_lo_space_->ContainsSlow(addr);
    case RO_SPACE:
      return read_only_space_->ContainsSlow(addr);
  }
  UNREACHABLE();
}

bool Heap::IsValidAllocationSpace(AllocationSpace space) {
  switch (space) {
    case NEW_SPACE:
    case OLD_SPACE:
    case CODE_SPACE:
    case SHARED_SPACE:
    case LO_SPACE:
    case NEW_LO_SPACE:
    case CODE_LO_SPACE:
    case SHARED_LO_SPACE:
    case TRUSTED_SPACE:
    case SHARED_TRUSTED_SPACE:
    case TRUSTED_LO_SPACE:
    case SHARED_TRUSTED_LO_SPACE:
    case RO_SPACE:
      return true;
    default:
      return false;
  }
}

#ifdef DEBUG
void Heap::VerifyCountersAfterSweeping() {
  MakeHeapIterable();
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    space->VerifyCountersAfterSweeping(this);
  }
}

void Heap::VerifyCountersBeforeConcurrentSweeping(GarbageCollector collector) {
  if (v8_flags.minor_ms && new_space()) {
    PagedSpaceBase* space = paged_new_space()->paged_space();
    space->RefillFreeList();
    space->VerifyCountersBeforeConcurrentSweeping();
  }
  if (collector != GarbageCollector::MARK_COMPACTOR) return;
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    // We need to refine the counters on pages that are already swept and have
    // not been moved over to the actual space. Otherwise, the AccountingStats
    // are just an over approximation.
    space->RefillFreeList();
    space->VerifyCountersBeforeConcurrentSweeping();
  }
}

void Heap::VerifyCommittedPhysicalMemory() {
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    space->VerifyCommittedPhysicalMemory();
  }
  if (v8_flags.minor_ms && new_space()) {
    paged_new_space()->paged_space()->VerifyCommittedPhysicalMemory();
  }
}
#endif  // DEBUG

void Heap::IterateWeakRoots(RootVisitor* v, base::EnumSet<SkipRoot> options) {
  DCHECK(!options.contains(SkipRoot::kWeak));

  if (!options.contains(SkipRoot::kUnserializable)) {
    // Isolate::topmost_script_having_context_address is treated weakly.
    v->VisitRootPointer(
        Root::kWeakRoots, nullptr,
        FullObjectSlot(isolate()->topmost_script_having_context_address()));
  }

  if (!options.contains(SkipRoot::kOldGeneration) &&
      !options.contains(SkipRoot::kUnserializable) &&
      isolate()->OwnsStringTables()) {
    // Do not visit for the following reasons.
    // - Serialization, since the string table is custom serialized.
    // - If we are skipping old generation, since all internalized strings
    //   are in old space.
    // - If the string table is shared and this is not the shared heap,
    //   since all internalized strings are in the shared heap.
    isolate()->string_table()->IterateElements(v);
  }
  v->Synchronize(VisitorSynchronization::kStringTable);
  if (!options.contains(SkipRoot::kExternalStringTable) &&
      !options.contains(SkipRoot::kUnserializable)) {
    // Scavenge collections have special processing for this.
    // Do not visit for serialization, since the external string table will
    // be populated from scratch upon deserialization.
    external_string_table_.IterateAll(v);
  }
  v->Synchronize(VisitorSynchronization::kExternalStringsTable);
  if (!options.contains(SkipRoot::kOldGeneration) &&
      !options.contains(SkipRoot::kUnserializable) &&
      isolate()->is_shared_space_isolate() &&
      isolate()->shared_struct_type_registry()) {
    isolate()->shared_struct_type_registry()->IterateElements(isolate(), v);
  }
  v->Synchronize(VisitorSynchronization::kSharedStructTypeRegistry);
}

void Heap::IterateSmiRoots(RootVisitor* v) {
  // Acquire execution access since we are going to read stack limit values.
  ExecutionAccess access(isolate());
  v->VisitRootPointers(Root::kSmiRootList, nullptr,
                       roots_table().smi_roots_begin(),
                       roots_table().smi_roots_end());
  v->Synchronize(VisitorSynchronization::kSmiRootList);
}

// We cannot avoid stale handles to left-trimmed objects, but can only make
// sure all handles still needed are updated. Filter out a stale pointer
// and clear the slot to allow post processing of handles (needed because
// the sweeper might actually free the underlying page).
class ClearStaleLeftTrimmedPointerVisitor : public RootVisitor {
 public:
  ClearStaleLeftTrimmedPointerVisitor(Heap* heap, RootVisitor* visitor)
      : heap_(heap),
        visitor_(visitor)
#if V8_COMPRESS_POINTERS
        ,
        cage_base_(heap->isolate())
#endif  // V8_COMPRESS_POINTERS
  {
    USE(heap_);
  }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    ClearLeftTrimmedOrForward(root, description, p);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      ClearLeftTrimmedOrForward(root, description, p);
    }
  }

  void Synchronize(VisitorSynchronization::SyncTag tag) override {
    visitor_->Synchronize(tag);
  }

  void VisitRunningCode(FullObjectSlot code_slot,
                        FullObjectSlot istream_or_smi_zero_slot) override {
    // Directly forward to actualy visitor here. Code objects and instruction
    // stream will not be left-trimmed.
    DCHECK(!IsLeftTrimmed(code_slot));
    DCHECK(!IsLeftTrimmed(istream_or_smi_zero_slot));
    visitor_->VisitRunningCode(code_slot, istream_or_smi_zero_slot);
  }

  // The pointer compression cage base value used for decompression of all
  // tagged values except references to InstructionStream objects.
  PtrComprCageBase cage_base() const {
#if V8_COMPRESS_POINTERS
    return cage_base_;
#else
    return PtrComprCageBase{};
#endif  // V8_COMPRESS_POINTERS
  }

 private:
  inline void ClearLeftTrimmedOrForward(Root root, const char* description,
                                        FullObjectSlot p) {
    if (!IsHeapObject(*p)) return;

    if (IsLeftTrimmed(p)) {
      p.store(Smi::zero());
    } else {
      visitor_->VisitRootPointer(root, description, p);
    }
  }

  inline bool IsLeftTrimmed(FullObjectSlot p) {
    if (!IsHeapObject(*p)) return false;
    Tagged<HeapObject> current = Cast<HeapObject>(*p);
    if (!current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() &&
        IsFreeSpaceOrFiller(current, cage_base())) {
#ifdef DEBUG
      // We need to find a FixedArrayBase map after walking the fillers.
      while (
          !current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() &&
          IsFreeSpaceOrFiller(current, cage_base())) {
        Address next = current.ptr();
        if (current->map(cage_base()) ==
            ReadOnlyRoots(heap_).one_pointer_filler_map()) {
          next += kTaggedSize;
        } else if (current->map(cage_base()) ==
                   ReadOnlyRoots(heap_).two_pointer_filler_map()) {
          next += 2 * kTaggedSize;
        } else {
          next += current->Size();
        }
        current = Cast<HeapObject>(Tagged<Object>(next));
      }
      DCHECK(
          current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() ||
          IsFixedArrayBase(current, cage_base()));
#endif  // DEBUG
      return true;
    } else {
      return false;
    }
  }

  Heap* heap_;
  RootVisitor* visitor_;

#if V8_COMPRESS_POINTERS
  const PtrComprCageBase cage_base_;
#endif  // V8_COMPRESS_POINTERS
};

void Heap::IterateRoots(RootVisitor* v, base::EnumSet<SkipRoot> options,
                        IterateRootsMode roots_mode) {
  v->VisitRootPointers(Root::kStrongRootList, nullptr,
                       roots_table().strong_roots_begin(),
                       roots_table().strong_roots_end());
  v->Synchronize(VisitorSynchronization::kStrongRootList);

  isolate_->bootstrapper()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kBootstrapper);
  Relocatable::Iterate(isolate_, v);
  v->Synchronize(VisitorSynchronization::kRelocatable);
  isolate_->debug()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kDebug);

  isolate_->compilation_cache()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kCompilationCache);

  const bool skip_iterate_builtins =
      options.contains(SkipRoot::kOldGeneration) ||
      (Builtins::kCodeObjectsAreInROSpace &&
       options.contains(SkipRoot::kReadOnlyBuiltins) &&
       // Prior to ReadOnlyPromotion, builtins may be on the mutable heap.
       !isolate_->serializer_enabled());
  if (!skip_iterate_builtins) {
    IterateBuiltins(v);
    v->Synchronize(VisitorSynchronization::kBuiltins);
  }

  // Iterate over pointers being held by inactive threads.
  isolate_->thread_manager()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kThreadManager);

  // Visitors in this block only run when not serializing. These include:
  //
  // - Thread-local and stack.
  // - Handles.
  // - Microtasks.
  // - The startup object cache.
  //
  // When creating real startup snapshot, these areas are expected to be empty.
  // It is also possible to create a snapshot of a *running* isolate for testing
  // purposes. In this case, these areas are likely not empty and will simply be
  // skipped.
  //
  // The general guideline for adding visitors to this section vs. adding them
  // above is that non-transient heap state is always visited, transient heap
  // state is visited only when not serializing.
  if (!options.contains(SkipRoot::kUnserializable)) {
    if (!options.contains(SkipRoot::kTracedHandles)) {
      // Young GCs always skip traced handles and visit them manually.
      DCHECK(!options.contains(SkipRoot::kOldGeneration));

      isolate_->traced_handles()->Iterate(v);
    }

    if (!options.contains(SkipRoot::kGlobalHandles)) {
      // Young GCs always skip global handles and visit them manually.
      DCHECK(!options.contains(SkipRoot::kOldGeneration));

      if (options.contains(SkipRoot::kWeak)) {
        isolate_->global_handles()->IterateStrongRoots(v);
      } else {
        isolate_->global_handles()->IterateAllRoots(v);
      }
    }
    v->Synchronize(VisitorSynchronization::kGlobalHandles);

    if (!options.contains(SkipRoot::kStack)) {
      ClearStaleLeftTrimmedPointerVisitor left_trim_visitor(this, v);
      IterateStackRoots(&left_trim_visitor);
      if (!options.contains(SkipRoot::kConservativeStack)) {
        IterateConservativeStackRoots(v, roots_mode);
      }
      v->Synchronize(VisitorSynchronization::kStackRoots);
    }

    // Iterate over main thread handles in handle scopes.
    if (!options.contains(SkipRoot::kMainThreadHandles)) {
      // Clear main thread handles with stale references to left-trimmed
      // objects. The GC would crash on such stale references.
      ClearStaleLeftTrimmedPointerVisitor left_trim_visitor(this, v);
      isolate_->handle_scope_implementer()->Iterate(&left_trim_visitor);
    }
    // Iterate local handles for all local heaps.
    safepoint_->Iterate(v);
    // Iterates all persistent handles.
    isolate_->persistent_handles_list()->Iterate(v, isolate_);
    v->Synchronize(VisitorSynchronization::kHandleScope);

    if (options.contains(SkipRoot::kOldGeneration)) {
      isolate_->eternal_handles()->IterateYoungRoots(v);
    } else {
      isolate_->eternal_handles()->IterateAllRoots(v);
    }
    v->Synchronize(VisitorSynchronization::kEternalHandles);

    // Iterate over pending Microtasks stored in MicrotaskQueues.
    MicrotaskQueue* default_microtask_queue =
        isolate_->default_microtask_queue();
    if (default_microtask_queue) {
      MicrotaskQueue* microtask_queue = default_microtask_queue;
      do {
        microtask_queue->IterateMicrotasks(v);
        microtask_queue = microtask_queue->next();
      } while (microtask_queue != default_microtask_queue);
    }
    v->Synchronize(VisitorSynchronization::kMicroTasks);

    // Iterate over other strong roots (currently only identity maps and
    // deoptimization entries).
    for (StrongRootsEntry* current = strong_roots_head_; current;
         current = current->next) {
      v->VisitRootPointers(Root::kStrongRoots, current->label, current->start,
                           current->end);
    }
    v->Synchronize(VisitorSynchronization::kStrongRoots);

    // Iterate over the startup and shared heap object caches unless
    // serializing or deserializing.
    SerializerDeserializer::IterateStartupObjectCache(isolate_, v);
    v->Synchronize(VisitorSynchronization::kStartupObjectCache);

    // Iterate over shared heap object cache when the isolate owns this data
    // structure. Isolates which own the shared heap object cache are:
    //   * All isolates when not using --shared-string-table.
    //   * Shared space/main isolate with --shared-string-table.
    //
    // Isolates which do not own the shared heap object cache should not iterate
    // it.
    if (isolate_->OwnsStringTables()) {
      SerializerDeserializer::IterateSharedHeapObjectCache(isolate_, v);
      v->Synchronize(VisitorSynchronization::kSharedHeapObjectCache);
    }
  }

  if (!options.contains(SkipRoot::kWeak)) {
    IterateWeakRoots(v, options);
  }
}

void Heap::IterateRootsIncludingClients(RootVisitor* v,
                                        base::EnumSet<SkipRoot> options) {
  IterateRoots(v, options, IterateRootsMode::kMainIsolate);

  if (isolate()->is_shared_space_isolate()) {
    ClientRootVisitor<> client_root_visitor(v);
    isolate()->global_safepoint()->IterateClientIsolates(
        [v = &client_root_visitor, options](Isolate* client) {
          client->heap()->IterateRoots(v, options,
                                       IterateRootsMode::kClientIsolate);
        });
  }
}

void Heap::IterateWeakGlobalHandles(RootVisitor* v) {
  isolate_->global_handles()->IterateWeakRoots(v);
  isolate_->traced_handles()->Iterate(v);
}

void Heap::IterateBuiltins(RootVisitor* v) {
  Builtins* builtins = isolate()->builtins();
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const char* name = Builtins::name(builtin);
    v->VisitRootPointer(Root::kBuiltins, name, builtins->builtin_slot(builtin));
  }

  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLastTier0;
       ++builtin) {
    v->VisitRootPointer(Root::kBuiltins, Builtins::name(builtin),
                        builtins->builtin_tier0_slot(builtin));
  }

  // The entry table doesn't need to be updated since all builtins are embedded.
  static_assert(Builtins::AllBuiltinsAreIsolateIndependent());
}

void Heap::IterateStackRoots(RootVisitor* v) { isolate_->Iterate(v); }

void Heap::IterateConservativeStackRoots(RootVisitor* v,
                                         IterateRootsMode roots_mode) {
#ifdef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
  if (!IsGCWithStack()) return;

  // In case of a shared GC, we're interested in the main isolate for CSS.
  Isolate* main_isolate = roots_mode == IterateRootsMode::kClientIsolate
                              ? isolate()->shared_space_isolate()
                              : isolate();

  ConservativeStackVisitor stack_visitor(main_isolate, v);
  if (IsGCWithMainThreadStack()) {
    stack().IteratePointersUntilMarker(&stack_visitor);
  }
  stack().IterateBackgroundStacks(&stack_visitor);
#endif  // V8_ENABLE_CONSERVATIVE_STACK_SCANNING
}

// static
size_t Heap::DefaultMinSemiSpaceSize() {
#if ENABLE_HUGEPAGE
  static constexpr size_t kMinSemiSpaceSize =
      kHugePageSize * kPointerMultiplier;
#else
  static constexpr size_t kMinSemiSpaceSize = 512 * KB * kPointerMultiplier;
#endif
  static_assert(kMinSemiSpaceSize % (1 << kPageSizeBits) == 0);

  return kMinSemiSpaceSize;
}

// static
size_t Heap::DefaultMaxSemiSpaceSize() {
#if ENABLE_HUGEPAGE
  static constexpr size_t kMaxSemiSpaceCapacityBaseUnit =
      kHugePageSize * 2 * kPointerMultiplier;
#else
  static constexpr size_t kMaxSemiSpaceCapacityBaseUnit =
      MB * kPointerMultiplier;
#endif
  static_assert(kMaxSemiSpaceCapacityBaseUnit % (1 << kPageSizeBits) == 0);

  size_t max_semi_space_size =
      (v8_flags.minor_ms ? v8_flags.minor_ms_max_new_space_capacity_mb
                         : v8_flags.scavenger_max_new_space_capacity_mb) *
      kMaxSemiSpaceCapacityBaseUnit;
  DCHECK_EQ(0, max_semi_space_size % (1 << kPageSizeBits));
  return max_semi_space_size;
}

// static
size_t Heap::OldGenerationToSemiSpaceRatio() {
  DCHECK(!v8_flags.minor_ms);
  // Compute a ration such that when old gen max capacity is set to the highest
  // supported value, young gen max capacity would also be set to the max.
  static size_t kMaxOldGenSizeToMaxYoungGenSizeRatio =
      V8HeapTrait::kMaxSize /
      (v8_flags.scavenger_max_new_space_capacity_mb * MB);
  static size_t kOldGenerationToSemiSpaceRatio =
      kMaxOldGenSizeToMaxYoungGenSizeRatio * kHeapLimitMultiplier /
      kPointerMultiplier;
  return kOldGenerationToSemiSpaceRatio;
}

// static
size_t Heap::OldGenerationToSemiSpaceRatioLowMemory() {
  static constexpr size_t kOldGenerationToSemiSpaceRatioLowMemory =
      256 * kHeapLimitMultiplier / kPointerMultiplier;
  return kOldGenerationToSemiSpaceRatioLowMemory / (v8_flags.minor_ms ? 2 : 1);
}

void Heap::ConfigureHeap(const v8::ResourceConstraints& constraints,
                         v8::CppHeap* cpp_heap) {
  CHECK(!configured_);
  // Initialize max_semi_space_size_.
  {
    max_semi_space_size_ = DefaultMaxSemiSpaceSize();
    if (constraints.max_young_generation_size_in_bytes() > 0) {
      max_semi_space_size_ = SemiSpaceSizeFromYoungGenerationSize(
          constraints.max_young_generation_size_in_bytes());
    }
    if (v8_flags.max_semi_space_size > 0) {
      max_semi_space_size_ =
          static_cast<size_t>(v8_flags.max_semi_space_size) * MB;
    } else if (v8_flags.max_heap_size > 0) {
      size_t max_heap_size = static_cast<size_t>(v8_flags.max_heap_size) * MB;
      size_t young_generation_size, old_generation_size;
      if (v8_flags.max_old_space_size > 0) {
        old_generation_size =
            static_cast<size_t>(v8_flags.max_old_space_size) * MB;
        young_generation_size = max_heap_size > old_generation_size
                                    ? max_heap_size - old_generation_size
                                    : 0;
      } else {
        GenerationSizesFromHeapSize(max_heap_size, &young_generation_size,
                                    &old_generation_size);
      }
      max_semi_space_size_ =
          SemiSpaceSizeFromYoungGenerationSize(young_generation_size);
    }
    if (v8_flags.stress_compaction) {
      // This will cause more frequent GCs when stressing.
      max_semi_space_size_ = MB;
    }
    if (!v8_flags.minor_ms) {
      // TODO(dinfuehr): Rounding to a power of 2 is technically no longer
      // needed but yields best performance on Pixel2.
      max_semi_space_size_ =
          static_cast<size_t>(base::bits::RoundUpToPowerOfTwo64(
              static_cast<uint64_t>(max_semi_space_size_)));
    }
    max_semi_space_size_ =
        std::max(max_semi_space_size_, DefaultMinSemiSpaceSize());
    max_semi_space_size_ =
        RoundDown<PageMetadata::kPageSize>(max_semi_space_size_);
  }

  // Initialize max_old_generation_size_ and max_global_memory_.
  {
    size_t max_old_generation_size = 700ul * (kSystemPointerSize / 4) * MB;
    if (constraints.max_old_generation_size_in_bytes() > 0) {
      max_old_generation_size = constraints.max_old_generation_size_in_bytes();
    }
    if (v8_flags.max_old_space_size > 0) {
      max_old_generation_size =
          static_cast<size_t>(v8_flags.max_old_space_size) * MB;
    } else if (v8_flags.max_heap_size > 0) {
      size_t max_heap_size = static_cast<size_t>(v8_flags.max_heap_size) * MB;
      size_t young_generation_size =
          YoungGenerationSizeFromSemiSpaceSize(max_semi_space_size_);
      max_old_generation_size = max_heap_size > young_generation_size
                                    ? max_heap_size - young_generation_size
                                    : 0;
    }
    max_old_generation_size =
        std::max(max_old_generation_size, MinOldGenerationSize());
    max_old_generation_size = std::min(max_old_generation_size,
                                       AllocatorLimitOnMaxOldGenerationSize());
    max_old_generation_size =
        RoundDown<PageMetadata::kPageSize>(max_old_generation_size);

    SetOldGenerationAndGlobalMaximumSize(max_old_generation_size);
  }

  CHECK_IMPLIES(
      v8_flags.max_heap_size > 0,
      v8_flags.max_semi_space_size == 0 || v8_flags.max_old_space_size == 0);

  // Initialize initial_semispace_size_.
  {
    initial_semispace_size_ = DefaultMinSemiSpaceSize();
    if (!v8_flags.optimize_for_size) {
      // Start with at least 1*MB semi-space on machines with a lot of memory.
      initial_semispace_size_ =
          std::max(initial_semispace_size_, static_cast<size_t>(1 * MB));
    }
    DCHECK_GE(initial_semispace_size_, DefaultMinSemiSpaceSize());
    if (constraints.initial_young_generation_size_in_bytes() > 0) {
      initial_semispace_size_ = SemiSpaceSizeFromYoungGenerationSize(
          constraints.initial_young_generation_size_in_bytes());
    }
    if (v8_flags.initial_heap_size > 0) {
      size_t young_generation, old_generation;
      Heap::GenerationSizesFromHeapSize(
          static_cast<size_t>(v8_flags.initial_heap_size) * MB,
          &young_generation, &old_generation);
      initial_semispace_size_ =
          SemiSpaceSizeFromYoungGenerationSize(young_generation);
    }
    if (v8_flags.min_semi_space_size > 0) {
      initial_semispace_size_ =
          static_cast<size_t>(v8_flags.min_semi_space_size) * MB;
    }
    initial_semispace_size_ =
        std::min(initial_semispace_size_, max_semi_space_size_);
    initial_semispace_size_ =
        RoundDown<PageMetadata::kPageSize>(initial_semispace_size_);
  }

  if (v8_flags.lazy_new_space_shrinking) {
    initial_semispace_size_ = max_semi_space_size_;
  }

  // Initialize initial_old_space_size_.
  std::optional<size_t> initial_old_generation_size =
      [&]() -> std::optional<size_t> {
    if (v8_flags.initial_old_space_size > 0) {
      return static_cast<size_t>(v8_flags.initial_old_space_size) * MB;
    }
    if (v8_flags.initial_heap_size > 0) {
      size_t initial_heap_size =
          static_cast<size_t>(v8_flags.initial_heap_size) * MB;
      size_t young_generation_size =
          YoungGenerationSizeFromSemiSpaceSize(initial_semispace_size_);
      return initial_heap_size > young_generation_size
                 ? initial_heap_size - young_generation_size
                 : 0;
    }
    return std::nullopt;
  }();
  if (initial_old_generation_size.has_value()) {
    initial_limit_overwritten_ = true;
    initial_old_generation_size_ = *initial_old_generation_size;
  } else {
    initial_old_generation_size_ = kMaxInitialOldGenerationSize;
    if (constraints.initial_old_generation_size_in_bytes() > 0) {
      initial_old_generation_size_ =
          constraints.initial_old_generation_size_in_bytes();
    }
  }
  initial_old_generation_size_ =
      std::min(initial_old_generation_size_, max_old_generation_size() / 2);
  initial_old_generation_size_ =
      RoundDown<PageMetadata::kPageSize>(initial_old_generation_size_);
  if (initial_limit_overwritten_) {
    // If the embedder pre-configures the initial old generation size,
    // then allow V8 to skip full GCs below that threshold.
    min_old_generation_size_ = initial_old_generation_size_;
    min_global_memory_size_ =
        GlobalMemorySizeFromV8Size(min_old_generation_size_);
  }
  initial_max_old_generation_size_ = max_old_generation_size();
  ResetOldGenerationAndGlobalAllocationLimit();

  // We rely on being able to allocate new arrays in paged spaces.
  DCHECK(kMaxRegularHeapObjectSize >=
         (JSArray::kHeaderSize +
          FixedArray::SizeFor(JSArray::kInitialMaxFastElementArray) +
          ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize)));

  code_range_size_ = constraints.code_range_size_in_bytes();

  if (cpp_heap) {
    AttachCppHeap(cpp_heap);
    owning_cpp_heap_.reset(CppHeap::From(cpp_heap));
  }

  configured_ = true;
}

void Heap::AddToRingBuffer(const char* string) {
  size_t first_part =
      std::min(strlen(string), kTraceRingBufferSize - ring_buffer_end_);
  memcpy(trace_ring_buffer_ + ring_buffer_end_, string, first_part);
  ring_buffer_end_ += first_part;
  if (first_part < strlen(string)) {
    ring_buffer_full_ = true;
    size_t second_part = strlen(string) - first_part;
    memcpy(trace_ring_buffer_, string + first_part, second_part);
    ring_buffer_end_ = second_part;
  }
}

void Heap::GetFromRingBuffer(char* buffer) {
  size_t copied = 0;
  if (ring_buffer_full_) {
    copied = kTraceRingBufferSize - ring_buffer_end_;
    memcpy(buffer, trace_ring_buffer_ + ring_buffer_end_, copied);
  }
  memcpy(buffer + copied, trace_ring_buffer_, ring_buffer_end_);
}

void Heap::ConfigureHeapDefault() {
  v8::ResourceConstraints constraints;
  ConfigureHeap(constraints, nullptr);
}

void Heap::RecordStats(HeapStats* stats, bool take_snapshot) {
  *stats->start_marker = HeapStats::kStartMarker;
  *stats->end_marker = HeapStats::kEndMarker;
  *stats->ro_space_size = read_only_space_->Size();
  *stats->ro_space_capacity = read_only_space_->Capacity();
  *stats->new_space_size = NewSpaceSize();
  *stats->new_space_capacity = NewSpaceCapacity();
  *stats->old_space_size = old_space_->SizeOfObjects();
  *stats->old_space_capacity = old_space_->Capacity();
  *stats->code_space_size = code_space_->SizeOfObjects();
  *stats->code_space_capacity = code_space_->Capacity();
  *stats->map_space_size = 0;
  *stats->map_space_capacity = 0;
  *stats->lo_space_size = lo_space_->Size();
  *stats->code_lo_space_size = code_lo_space_->Size();
  isolate_->global_handles()->RecordStats(stats);
  *stats->memory_allocator_size = memory_allocator()->Size();
  *stats->memory_allocator_capacity =
      memory_allocator()->Size() + memory_allocator()->Available();
  *stats->os_error = base::OS::GetLastError();
  // TODO(leszeks): Include the string table in both current and peak usage.
  *stats->malloced_memory = isolate_->allocator()->GetCurrentMemoryUsage();
  *stats->malloced_peak_memory = isolate_->allocator()->GetMaxMemoryUsage();
  if (take_snapshot) {
    HeapObjectIterator iterator(this);
    for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
         obj = iterator.Next()) {
      InstanceType type = obj->map()->instance_type();
      DCHECK(0 <= type && type <= LAST_TYPE);
      stats->objects_per_type[type]++;
      stats->size_per_type[type] += obj->Size();
    }
  }
  if (stats->last_few_messages != nullptr)
    GetFromRingBuffer(stats->last_few_messages);
}

size_t Heap::OldGenerationSizeOfObjects() const {
  size_t total = 0;
  if (v8_flags.sticky_mark_bits)
    total += sticky_space()->old_objects_size();
  else
    total += old_space()->SizeOfObjects();
  total += lo_space()->SizeOfObjects();
  total += code_space()->SizeOfObjects();
  total += code_lo_space()->SizeOfObjects();
  if (shared_space()) {
    total += shared_space()->SizeOfObjects();
  }
  if (shared_lo_space()) {
    total += shared_lo_space()->SizeOfObjects();
  }
  total += trusted_space()->SizeOfObjects();
  total += trusted_lo_
"""


```