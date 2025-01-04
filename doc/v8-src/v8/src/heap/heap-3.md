Response: The user wants me to summarize the functionality of the C++ code snippet provided. This is the fourth part of a five-part file, so I need to consider that context. The code deals with memory management within the V8 JavaScript engine's heap. I also need to identify any relationships to JavaScript and provide illustrative examples.

Here's a breakdown of the code and my thought process:

1. **Identify Key Functionality Areas:** The code primarily deals with querying the size and usage of different parts of the V8 heap. I see functions for:
    * Old generation size (objects, wasted, consumed)
    * Young generation size (objects, wasted, consumed)
    * Embedder size
    * Global size (objects, wasted, consumed)
    * Tracking sizes at the last GC
    * External memory accounting
    * Determining allocation limits and whether they have been exceeded.
    * Deciding when to expand different generations based on memory pressure and GC state.
    * Determining the current heap growing mode.
    * Calculating the percentage of the heap limit reached.
    * Deciding when to trigger incremental marking.
    * Enabling/disabling inline allocation.
    * Setting up heap structures.
    * Handling concurrent allocation stress testing.
    * Managing spaces (Old, New, Code, LO, etc.).
    * Setting up garbage collection components (sweeper, collectors, incremental marking).
    * Handling read-only heaps.
    * Managing weak references and retained maps.
    * Handling finalization registries.
    * Tracking object counts.
    * Iterating over heap objects.
    * Managing external strings.
    * Remembering unmapped pages.
    * Managing strong roots.

2. **Connect to JavaScript:** The heap is fundamental to JavaScript's memory management. JavaScript objects are allocated on the heap. Garbage collection reclaims memory from objects that are no longer reachable from JavaScript code. The sizes and limits calculated in this code directly influence when and how garbage collection occurs.

3. **Develop JavaScript Examples:**
    * **Object Allocation:** Create JavaScript objects to demonstrate how they consume heap space.
    * **Memory Pressure/GC:** Show how creating many objects can trigger garbage collection.
    * **Weak References/Finalization:**  Illustrate how `WeakRef` and `FinalizationRegistry` interact with the underlying heap management.

4. **Structure the Summary:** I'll organize the summary by grouping related functions and explaining their purpose in the context of V8's heap management and its connection to JavaScript. I'll make sure to mention this is part 4 of 5.

5. **Refine and Review:** I'll reread the code and my summary to ensure accuracy and clarity. I'll check if the JavaScript examples are relevant and easy to understand. I'll also consider the "part 4 of 5" constraint and try to avoid repeating information that might have been covered in earlier parts (though without seeing the other parts, this is somewhat speculative). I need to emphasize the "querying and decision-making" nature of this part of the code.
这个C++源代码文件（v8/src/heap/heap.cc）的第4部分主要负责**查询和决策 V8 堆的各种状态和行为，特别是在内存使用和垃圾回收 (GC) 方面**。 它包含了一系列方法，用于：

**核心功能归纳：**

* **查询堆内存使用情况：**  提供了多种方法来获取堆中不同区域（老生代、新生代、嵌入器、全局等）的对象大小、浪费空间和已用空间。这些信息对于监控内存使用和触发 GC 非常重要。
* **查询 GC 相关状态：**  可以获取上次 GC 时的内存使用情况，以及自上次 Mark-Compact GC 以来分配的外部内存量。
* **判断是否超出分配限制：**  `AllocationLimitOvershotByLargeMargin()` 方法用于判断当前内存使用是否远超分配限制，这会影响 GC 的触发时机。
* **判断是否应该为加载时间优化：** `ShouldOptimizeForLoadTime()` 方法根据加载状态和内存压力来决定是否应该优先考虑加载速度而不是内存占用。
* **决策是否应该扩展堆空间：**
    * `ShouldExpandOldGenerationOnSlowAllocation()` 和 `ShouldExpandYoungGenerationOnSlowAllocation()` 这两个方法在分配失败时被调用，用于判断是否应该通过增加新的内存页来扩展相应的堆空间，或者应该触发一次 GC。这些决策会考虑当前的 GC 状态、内存限制、是否正在进行增量标记等因素。
* **获取当前的堆增长模式：** `CurrentHeapGrowingMode()` 方法返回当前的堆增长策略（例如：最小、保守、慢速、默认），这会影响堆的扩展速度。
* **计算可用内存：** `GlobalMemoryAvailable()` 方法计算当前可用的全局内存量。
* **计算内存使用百分比：**  `PercentToOldGenerationLimit()` 和 `PercentToGlobalMemoryLimit()` 方法计算当前内存使用分别占老生代和全局内存限制的百分比，这些百分比是触发增量标记的重要依据。
* **判断是否达到增量标记的限制：** `IncrementalMarkingLimitReached()` 方法根据内存使用情况、压力等因素，判断是否应该启动增量标记。
* **判断是否应该进行压力压缩：** `ShouldStressCompaction()` 方法用于在开启压力压缩标志时，决定是否在当前 GC 周期进行压缩。
* **控制内联分配：**  `EnableInlineAllocation()` 和 `DisableInlineAllocation()` 方法用于控制是否启用内联分配。
* **堆的初始化和配置：**  `SetUp()` 方法负责初始化堆的各个组成部分，包括内存分配器、空间、GC 收集器等。`SetUpFromReadOnlyHeap()` 和 `ReplaceReadOnlySpace()` 处理只读堆的设置。
* **并发分配压力测试：**  `StressConcurrentAllocationTask` 和 `StressConcurrentAllocationObserver` 用于模拟和触发并发分配，用于压力测试。
* **空间的设置：** `SetUpSpaces()` 初始化堆中的各种内存空间。
* **哈希种子的初始化：** `InitializeHashSeed()` 用于设置随机的哈希种子。
* **获取前台任务运行器：** `GetForegroundTaskRunner()` 获取用于执行前台任务的运行器。
* **进程级别的初始化：** `InitializeOncePerProcess()` 执行进程级别的初始化操作。
* **打印调试信息：** `PrintMaxMarkingLimitReached()` 和 `PrintMaxNewSpaceSizeReached()` 用于打印调试信息。
* **弱化描述符数组：** `WeakenDescriptorArrays()` 将强引用的描述符数组转换为弱引用，用于 GC 优化。
* **通知反序列化完成：** `NotifyDeserializationComplete()` 在反序列化完成后进行一些堆的清理和设置。
* **通知引导完成：** `NotifyBootstrapComplete()` 在引导过程完成后记录老生代的容量。
* **通知老生代扩展：** `NotifyOldGenerationExpansion()` 在老生代扩展时进行通知，用于记录和触发内存优化。
* **设置和获取嵌入器根处理器：** `SetEmbedderRootsHandler()` 和 `GetEmbedderRootsHandler()` 用于处理嵌入器自定义的根对象。
* **连接和断开 C++ 堆：** `AttachCppHeap()` 和 `DetachCppHeap()` 用于连接和断开外部 C++ 堆。
* **设置栈起始地址：** `SetStackStart()` 设置当前线程的栈起始地址。
* **堆的销毁和清理：** `StartTearDown()` 和 `TearDown()` 负责堆的清理和销毁过程。
* **检查空闲空间是否有效：** `IsFreeSpaceValid()` 用于调试时检查空闲空间对象的有效性。
* **添加和移除 GC 回调：** `AddGCPrologueCallback()` 和 `RemoveGCPrologueCallback()`, `AddGCEpilogueCallback()` 和 `RemoveGCEpilogueCallback()` 用于添加和移除 GC 开始和结束时的回调函数。
* **压缩弱引用数组列表：** `CompactWeakArrayLists()` 用于清理和压缩存储弱引用的数组列表。
* **管理保留的 Map 对象：** `AddRetainedMaps()` 和 `CompactRetainedMaps()` 用于管理需要保留一段时间的 Map 对象。
* **处理内存溢出：** `FatalProcessOutOfMemory()` 用于报告致命的内存溢出错误。
* **打印句柄信息：** `PrintHandles()` 用于打印当前所有的句柄（仅限 Debug 版本）。
* **检查句柄数量：** `CheckHandleCount()` 用于检查句柄数量是否超过阈值。
* **从代码中插入到 Remembered Set：** `InsertIntoRememberedSetFromCode()`  允许在运行时从生成的代码中插入到 Remembered Set，用于记录老生代到新生代的指针引用。
* **清理记录的 slot 范围：** `ClearRecordedSlotRange()` 清理 Remembered Set 中记录的指定范围的 slot。
* **迭代 PagedSpace：** `PagedSpaceIterator` 用于迭代堆中的所有分页空间。
* **迭代堆对象：** `HeapObjectIterator` 用于遍历堆中的所有存活对象。
* **更新总 GC 时间：** `UpdateTotalGCTime()` 更新累积的 GC 时间。
* **管理外部字符串表：** `ExternalStringTable` 负责跟踪和清理外部字符串。
* **记录未映射的页：** `RememberUnmappedPage()` 记录被取消映射的内存页地址。
* **获取新生代 ArrayBuffer 字节数：** `YoungArrayBufferBytes()` 获取新生代 ArrayBuffer 占用的字节数。
* **更新外部内存：** `UpdateExternalMemory()` 更新 V8 堆外部的内存使用量。
* **获取老生代 ArrayBuffer 字节数：** `OldArrayBufferBytes()` 获取老生代 ArrayBuffer 占用的字节数。
* **管理强根：** `RegisterStrongRoots()`, `UpdateStrongRoots()`, `UnregisterStrongRoots()` 用于注册、更新和取消注册强根对象。
* **设置内置常量表：** `SetBuiltinsConstantsTable()` 设置内置常量的缓存。
* **设置分离的上下文：** `SetDetachedContexts()` 设置已分离的上下文列表。
* **管理脏的 JSFinalizationRegistry：** `HasDirtyJSFinalizationRegistries()`, `PostFinalizationRegistryCleanupTaskIfNeeded()`, `EnqueueDirtyJSFinalizationRegistry()`, `DequeueDirtyJSFinalizationRegistry()`, `RemoveDirtyFinalizationRegistriesOnContext()`  用于管理需要清理的 `FinalizationRegistry` 对象。
* **在 Job 期间保留对象：** `KeepDuringJob()` 用于在异步任务执行期间临时保留某些对象不被 GC 回收。
* **清除保留的对象：** `ClearKeptObjects()` 清除 Job 期间保留的对象列表。
* **获取跟踪的堆对象类型数量：** `NumberOfTrackedHeapObjectTypes()` 返回被跟踪的堆对象类型数量。
* **获取上次 GC 时的对象数量和大小：** `ObjectCountAtLastGC()` 和 `ObjectSizeAtLastGC()` 返回上次 GC 时的对象数量和大小。
* **获取对象类型名称：** `GetObjectTypeName()` 获取指定索引的对象类型名称。
* **获取 NativeContext 的数量和列表：** `NumberOfNativeContexts()` 和 `FindAllNativeContexts()` 获取 NativeContext 的数量和列表。
* **查找所有保留的 Map：** `FindAllRetainedMaps()` 查找所有被保留的 Map 对象列表。

**与 JavaScript 的关系和示例：**

这些 C++ 代码直接支撑着 JavaScript 的内存管理。当你在 JavaScript 中创建对象、使用弱引用、注册 finalizers 等操作时，V8 引擎会在底层调用这些 C++ 方法来管理内存。

**JavaScript 示例：**

```javascript
// 对象分配会影响堆的内存使用
let obj1 = {};
let obj2 = { name: "example" };
let arr = new Array(10000); // 创建一个较大的数组

// 弱引用和 FinalizationRegistry 会与底层的管理机制交互
let weakRef = new WeakRef(obj1);
let registry = new FinalizationRegistry(heldValue => {
  console.log("对象被回收了:", heldValue);
});
registry.register(obj2, "obj2");

// 手动触发 GC (通常不需要手动触发，V8 会自动管理)
// global.gc();

// 查询堆的统计信息（可以通过 V8 的 API 获取，但底层依赖这些 C++ 方法）
// performance.measureMemory(); // 实验性 API，可能需要特定 flag
```

**解释：**

* 当你在 JavaScript 中创建 `obj1`、`obj2` 和 `arr` 时，V8 会在堆上分配内存。这些 C++ 代码中的方法（如 `YoungGenerationSizeOfObjects()`, `OldGenerationConsumedBytes()` 等）会跟踪这些对象的内存占用。
* `WeakRef` 和 `FinalizationRegistry` 的工作依赖于 V8 的弱引用管理和终结器队列，这些机制在 C++ 层实现。 `EnqueueDirtyJSFinalizationRegistry()` 等方法会参与 `FinalizationRegistry` 的管理。
* 虽然 JavaScript 代码通常不需要手动触发 GC，但 V8 内部会根据这些 C++ 代码中计算的内存使用情况和各种策略（例如 `IncrementalMarkingLimitReached()`, `ShouldExpandOldGenerationOnSlowAllocation()`）来自动决定何时进行垃圾回收。
* 诸如 `performance.measureMemory()` (实验性 API) 的 JavaScript API，如果存在，最终也会调用底层的 C++ 代码来获取堆的统计信息，这些信息正是由本文件中定义的方法计算出来的。

**总结来说，这个代码片段是 V8 引擎核心的内存管理和垃圾回收机制的重要组成部分，它负责监控堆的状态，做出关键的内存分配和 GC 决策，并直接影响着 JavaScript 代码的内存使用和性能。** 这部分代码偏向于 **查询状态和决策判断**，而不是实际的内存分配或垃圾回收的具体执行过程，那些部分可能在其他文件中。

Prompt: 
```
这是目录为v8/src/heap/heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
space()->SizeOfObjects();
  return total;
}

size_t Heap::OldGenerationWastedBytes() const {
  PagedSpaceIterator spaces(this);
  size_t total = 0;
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    total += space->Waste();
  }
  return total;
}

size_t Heap::OldGenerationConsumedBytes() const {
  return OldGenerationSizeOfObjects() + OldGenerationWastedBytes();
}

size_t Heap::YoungGenerationSizeOfObjects() const {
  DCHECK_NOT_NULL(new_space());
  DCHECK_NOT_NULL(new_lo_space());
  if (v8_flags.sticky_mark_bits) {
    return sticky_space()->young_objects_size() +
           new_lo_space()->SizeOfObjects();
  }
  DCHECK_NOT_NULL(new_lo_space());
  return new_space()->SizeOfObjects() + new_lo_space()->SizeOfObjects();
}

size_t Heap::YoungGenerationWastedBytes() const {
  DCHECK_NOT_NULL(new_space());
  DCHECK(v8_flags.minor_ms);
  return paged_new_space()->paged_space()->Waste();
}

size_t Heap::YoungGenerationConsumedBytes() const {
  if (!new_space()) {
    return 0;
  }
  DCHECK_NOT_NULL(new_lo_space());
  if (v8_flags.minor_ms) {
    return YoungGenerationSizeOfObjects() + YoungGenerationWastedBytes();
  }
  // When using Scavenger, memory is compacted. Thus wasted space is always 0.
  // The diff between `new_space()->SizeOfObjects()` and
  // `new_space()->CurrentCapacitySafe()` is less than one page. Using capacity
  // here is also easier for concurrency since this method is reachable from
  // background old allocations.
  return semi_space_new_space()->CurrentCapacitySafe() +
         new_lo_space()->SizeOfObjects();
}

size_t Heap::EmbedderSizeOfObjects() const {
  return cpp_heap_ ? CppHeap::From(cpp_heap_)->used_size() : 0;
}

size_t Heap::GlobalSizeOfObjects() const {
  return OldGenerationSizeOfObjects() + EmbedderSizeOfObjects() +
         (v8_flags.external_memory_accounted_in_global_limit ? external_memory()
                                                             : 0);
}

size_t Heap::GlobalWastedBytes() const { return OldGenerationWastedBytes(); }

size_t Heap::GlobalConsumedBytes() const {
  return GlobalSizeOfObjects() + GlobalWastedBytes();
}

size_t Heap::OldGenerationConsumedBytesAtLastGC() const {
  return old_generation_size_at_last_gc_ + old_generation_wasted_at_last_gc_;
}

size_t Heap::GlobalConsumedBytesAtLastGC() const {
  return OldGenerationConsumedBytesAtLastGC() + embedder_size_at_last_gc_ +
         (v8_flags.external_memory_accounted_in_global_limit
              ? external_memory_.low_since_mark_compact()
              : 0);
}

uint64_t Heap::AllocatedExternalMemorySinceMarkCompact() const {
  return external_memory_.AllocatedSinceMarkCompact();
}

bool Heap::AllocationLimitOvershotByLargeMargin() const {
  // This guards against too eager finalization in small heaps.
  // The number is chosen based on v8.browsing_mobile on Nexus 7v2.
  constexpr size_t kMarginForSmallHeaps = 32u * MB;

  uint64_t size_now = OldGenerationConsumedBytes();
  if (!v8_flags.external_memory_accounted_in_global_limit) {
    size_now += AllocatedExternalMemorySinceMarkCompact();
  }
  if (v8_flags.separate_gc_phases && incremental_marking()->IsMajorMarking()) {
    // No interleaved GCs, so we count young gen as part of old gen.
    size_now += YoungGenerationConsumedBytes();
  }

  const size_t v8_overshoot = old_generation_allocation_limit() < size_now
                                  ? size_now - old_generation_allocation_limit()
                                  : 0;
  const size_t global_limit = global_allocation_limit();
  const size_t global_size = GlobalConsumedBytes();
  const size_t global_overshoot =
      global_limit < global_size ? global_size - global_limit : 0;

  // Bail out if the V8 and global sizes are still below their respective
  // limits.
  if (v8_overshoot == 0 && global_overshoot == 0) {
    return false;
  }

  // Overshoot margin is 50% of allocation limit or half-way to the max heap
  // with special handling of small heaps.
  const size_t v8_margin = std::min(
      std::max(old_generation_allocation_limit() / 2, kMarginForSmallHeaps),
      (max_old_generation_size() - old_generation_allocation_limit()) / 2);
  const size_t global_margin =
      std::min(std::max(global_limit / 2, kMarginForSmallHeaps),
               (max_global_memory_size_ - global_limit) / 2);

  return v8_overshoot >= v8_margin || global_overshoot >= global_margin;
}

bool Heap::ShouldOptimizeForLoadTime() const {
  return isolate()->is_loading() && !AllocationLimitOvershotByLargeMargin() &&
         MonotonicallyIncreasingTimeInMs() <
             (load_start_time_ms_.load(std::memory_order_relaxed) +
              kMaxLoadTimeMs);
}

// This predicate is called when an old generation space cannot allocated from
// the free list and is about to add a new page. Returning false will cause a
// major GC. It happens when the old generation allocation limit is reached and
// - either we need to optimize for memory usage,
// - or the incremental marking is not in progress and we cannot start it.
bool Heap::ShouldExpandOldGenerationOnSlowAllocation(LocalHeap* local_heap,
                                                     AllocationOrigin origin) {
  if (always_allocate() || OldGenerationSpaceAvailable() > 0) return true;
  // We reached the old generation allocation limit.

  // Allocations in the GC should always succeed if possible.
  if (origin == AllocationOrigin::kGC) return true;

  // Background threads need to be allowed to allocate without GC after teardown
  // was initiated.
  if (gc_state() == TEAR_DOWN) return true;

  // Allocations need to succeed during isolate deserialization. With shared
  // heap allocations, a client isolate may perform shared heap allocations
  // during isolate deserialization as well.
  if (!deserialization_complete() ||
      !local_heap->heap()->deserialization_complete()) {
    return true;
  }

  // Make it more likely that retry of allocations succeeds.
  if (local_heap->IsRetryOfFailedAllocation()) return true;

  // Background thread requested GC, allocation should fail
  if (CollectionRequested()) return false;

  if (ShouldOptimizeForMemoryUsage()) return false;

  if (ShouldOptimizeForLoadTime()) return true;

  if (incremental_marking()->IsMajorMarking() &&
      AllocationLimitOvershotByLargeMargin()) {
    return false;
  }

  if (incremental_marking()->IsStopped() &&
      IncrementalMarkingLimitReached() == IncrementalMarkingLimit::kNoLimit) {
    // We cannot start incremental marking.
    return false;
  }
  return true;
}

// This predicate is called when an young generation space cannot allocated
// from the free list and is about to add a new page. Returning false will
// cause a GC.
bool Heap::ShouldExpandYoungGenerationOnSlowAllocation(size_t allocation_size) {
  DCHECK(deserialization_complete());

  if (always_allocate()) return true;

  if (gc_state() == TEAR_DOWN) return true;

  if (!CanPromoteYoungAndExpandOldGeneration(allocation_size)) {
    // Assuming all of new space is alive, doing a full GC and promoting all
    // objects should still succeed. Don't let new space grow if it means it
    // will exceed the available size of old space.
    return false;
  }

  if (incremental_marking()->IsMajorMarking() &&
      !AllocationLimitOvershotByLargeMargin()) {
    // Allocate a new page during full GC incremental marking to avoid
    // prematurely finalizing the incremental GC. Once the full GC is over, new
    // space will be empty and capacity will be reset.
    return true;
  }

  return false;
}

Heap::HeapGrowingMode Heap::CurrentHeapGrowingMode() {
  if (ShouldReduceMemory() || v8_flags.stress_compaction) {
    return Heap::HeapGrowingMode::kMinimal;
  }

  if (ShouldOptimizeForMemoryUsage()) {
    return Heap::HeapGrowingMode::kConservative;
  }

  if (memory_reducer() != nullptr && memory_reducer()->ShouldGrowHeapSlowly()) {
    return Heap::HeapGrowingMode::kSlow;
  }

  return Heap::HeapGrowingMode::kDefault;
}

size_t Heap::GlobalMemoryAvailable() {
  size_t global_size = GlobalConsumedBytes();
  size_t global_limit = global_allocation_limit();

  if (global_size < global_limit) {
    return global_limit - global_size;
  } else {
    return 0;
  }
}

namespace {

double PercentToLimit(size_t size_at_gc, size_t size_now, size_t limit) {
  if (size_now < size_at_gc) {
    return 0.0;
  }
  if (size_now > limit) {
    return 100.0;
  }
  const size_t current_bytes = size_now - size_at_gc;
  const size_t total_bytes = limit - size_at_gc;
  DCHECK_LE(current_bytes, total_bytes);
  return static_cast<double>(current_bytes) * 100 / total_bytes;
}

}  // namespace

double Heap::PercentToOldGenerationLimit() const {
  return PercentToLimit(OldGenerationConsumedBytesAtLastGC(),
                        OldGenerationConsumedBytes(),
                        old_generation_allocation_limit());
}

double Heap::PercentToGlobalMemoryLimit() const {
  return PercentToLimit(GlobalConsumedBytesAtLastGC(), GlobalConsumedBytes(),
                        global_allocation_limit());
}

// - kNoLimit means that either incremental marking is disabled or it is too
// early to start incremental marking.
// - kSoftLimit means that incremental marking should be started soon.
// - kHardLimit means that incremental marking should be started immediately.
// - kFallbackForEmbedderLimit means that incremental marking should be
// started as soon as the embedder does not allocate with high throughput
// anymore.
Heap::IncrementalMarkingLimit Heap::IncrementalMarkingLimitReached() {
  // InstructionStream using an AlwaysAllocateScope assumes that the GC state
  // does not change; that implies that no marking steps must be performed.
  if (!incremental_marking()->CanAndShouldBeStarted() || always_allocate()) {
    // Incremental marking is disabled or it is too early to start.
    return IncrementalMarkingLimit::kNoLimit;
  }
  if (v8_flags.stress_incremental_marking) {
    return IncrementalMarkingLimit::kHardLimit;
  }
  if (incremental_marking()->IsBelowActivationThresholds()) {
    // Incremental marking is disabled or it is too early to start.
    return IncrementalMarkingLimit::kNoLimit;
  }
  if (ShouldStressCompaction() || HighMemoryPressure()) {
    // If there is high memory pressure or stress testing is enabled, then
    // start marking immediately.
    return IncrementalMarkingLimit::kHardLimit;
  }

  if (v8_flags.stress_marking > 0) {
    int current_percent = static_cast<int>(
        std::max(PercentToOldGenerationLimit(), PercentToGlobalMemoryLimit()));
    if (current_percent > 0) {
      if (v8_flags.trace_stress_marking) {
        isolate()->PrintWithTimestamp(
            "[IncrementalMarking] %d%% of the memory limit reached\n",
            current_percent);
      }
      if (v8_flags.fuzzer_gc_analysis) {
        // Skips values >=100% since they already trigger marking.
        if (current_percent < 100) {
          double max_marking_limit_reached =
              max_marking_limit_reached_.load(std::memory_order_relaxed);
          while (current_percent > max_marking_limit_reached) {
            max_marking_limit_reached_.compare_exchange_weak(
                max_marking_limit_reached, current_percent,
                std::memory_order_relaxed);
          }
        }
      } else if (current_percent >= stress_marking_percentage_) {
        return IncrementalMarkingLimit::kHardLimit;
      }
    }
  }

  if (v8_flags.incremental_marking_soft_trigger > 0 ||
      v8_flags.incremental_marking_hard_trigger > 0) {
    int current_percent = static_cast<int>(
        std::max(PercentToOldGenerationLimit(), PercentToGlobalMemoryLimit()));
    if (current_percent > v8_flags.incremental_marking_hard_trigger &&
        v8_flags.incremental_marking_hard_trigger > 0) {
      return IncrementalMarkingLimit::kHardLimit;
    }
    if (current_percent > v8_flags.incremental_marking_soft_trigger &&
        v8_flags.incremental_marking_soft_trigger > 0) {
      return IncrementalMarkingLimit::kSoftLimit;
    }
    return IncrementalMarkingLimit::kNoLimit;
  }

#if defined(V8_USE_PERFETTO)
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
                "OldGenerationConsumedBytes", OldGenerationConsumedBytes());
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), "GlobalConsumedBytes",
                GlobalConsumedBytes());
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), "ExternalMemoryBytes",
                external_memory());
#endif
  size_t old_generation_space_available = OldGenerationSpaceAvailable();
  size_t global_memory_available = GlobalMemoryAvailable();

  if (old_generation_space_available > NewSpaceTargetCapacity() &&
      (global_memory_available > NewSpaceTargetCapacity())) {
    if (cpp_heap() && gc_count_ == 0 && using_initial_limit()) {
      // At this point the embedder memory is above the activation
      // threshold. No GC happened so far and it's thus unlikely to get a
      // configured heap any time soon. Start a memory reducer in this case
      // which will wait until the allocation rate is low to trigger garbage
      // collection.
      return IncrementalMarkingLimit::kFallbackForEmbedderLimit;
    }
    return IncrementalMarkingLimit::kNoLimit;
  }
  if (ShouldOptimizeForMemoryUsage()) {
    return IncrementalMarkingLimit::kHardLimit;
  }
  if (ShouldOptimizeForLoadTime()) {
    return IncrementalMarkingLimit::kNoLimit;
  }
  if (old_generation_space_available == 0) {
    return IncrementalMarkingLimit::kHardLimit;
  }
  if (global_memory_available == 0) {
    return IncrementalMarkingLimit::kHardLimit;
  }
  return IncrementalMarkingLimit::kSoftLimit;
}

bool Heap::ShouldStressCompaction() const {
  return v8_flags.stress_compaction && (gc_count_ & 1) != 0;
}

void Heap::EnableInlineAllocation() { inline_allocation_enabled_ = true; }

void Heap::DisableInlineAllocation() {
  inline_allocation_enabled_ = false;
  FreeMainThreadLinearAllocationAreas();
}

void Heap::SetUp(LocalHeap* main_thread_local_heap) {
  DCHECK_NULL(main_thread_local_heap_);
  DCHECK_NULL(heap_allocator_);
  main_thread_local_heap_ = main_thread_local_heap;
  heap_allocator_ = &main_thread_local_heap->heap_allocator_;
  DCHECK_NOT_NULL(heap_allocator_);

  // Set the stack start for the main thread that sets up the heap.
  SetStackStart();

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  heap_allocator_->UpdateAllocationTimeout();
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

  // Initialize heap spaces and initial maps and objects.
  //
  // If the heap is not yet configured (e.g. through the API), configure it.
  // Configuration is based on the flags new-space-size (really the semispace
  // size) and old-space-size if set or the initial values of semispace_size_
  // and old_generation_size_ otherwise.
  if (!configured_) ConfigureHeapDefault();

  mmap_region_base_ =
      reinterpret_cast<uintptr_t>(v8::internal::GetRandomMmapAddr()) &
      ~kMmapRegionMask;

  v8::PageAllocator* code_page_allocator;
  if (isolate_->RequiresCodeRange() || code_range_size_ != 0) {
    const size_t requested_size =
        code_range_size_ == 0 ? kMaximalCodeRangeSize : code_range_size_;
    // When a target requires the code range feature, we put all code objects in
    // a contiguous range of virtual address space, so that they can call each
    // other with near calls.
#ifdef V8_COMPRESS_POINTERS
    // When pointer compression is enabled, isolates in the same group share the
    // same CodeRange, owned by the IsolateGroup.
    code_range_ = isolate_->isolate_group()->EnsureCodeRange(requested_size);
#else
    // Otherwise, each isolate has its own CodeRange, owned by the heap.
    code_range_ = std::make_unique<CodeRange>();
    if (!code_range_->InitReservation(isolate_->page_allocator(),
                                      requested_size, false)) {
      V8::FatalProcessOutOfMemory(
          isolate_, "Failed to reserve virtual memory for CodeRange");
    }
#endif  // V8_COMPRESS_POINTERS_IN_SHARED_CAGE

    LOG(isolate_,
        NewEvent("CodeRange",
                 reinterpret_cast<void*>(code_range_->reservation()->address()),
                 code_range_size_));

    isolate_->AddCodeRange(code_range_->reservation()->region().begin(),
                           code_range_->reservation()->region().size());
    code_page_allocator = code_range_->page_allocator();
  } else {
    code_page_allocator = isolate_->page_allocator();
  }

  v8::PageAllocator* trusted_page_allocator;
#ifdef V8_ENABLE_SANDBOX
  trusted_range_ = TrustedRange::GetProcessWideTrustedRange();
  trusted_page_allocator = trusted_range_->page_allocator();
#else
  trusted_page_allocator = isolate_->page_allocator();
#endif

  task_runner_ = V8::GetCurrentPlatform()->GetForegroundTaskRunner(
      reinterpret_cast<v8::Isolate*>(isolate()));

  collection_barrier_.reset(new CollectionBarrier(this, this->task_runner_));

  // Set up memory allocator.
  memory_allocator_.reset(new MemoryAllocator(
      isolate_, code_page_allocator, trusted_page_allocator, MaxReserved()));

  sweeper_.reset(new Sweeper(this));

  mark_compact_collector_.reset(new MarkCompactCollector(this));

  scavenger_collector_.reset(new ScavengerCollector(this));
  minor_mark_sweep_collector_.reset(new MinorMarkSweepCollector(this));
  ephemeron_remembered_set_.reset(new EphemeronRememberedSet());

  incremental_marking_.reset(
      new IncrementalMarking(this, mark_compact_collector_->weak_objects()));

  if (v8_flags.concurrent_marking || v8_flags.parallel_marking) {
    concurrent_marking_.reset(
        new ConcurrentMarking(this, mark_compact_collector_->weak_objects()));
  } else {
    concurrent_marking_.reset(new ConcurrentMarking(this, nullptr));
  }

  // Set up layout tracing callback.
  if (V8_UNLIKELY(v8_flags.trace_gc_heap_layout)) {
    v8::GCType gc_type = kGCTypeMarkSweepCompact;
    if (V8_UNLIKELY(!v8_flags.trace_gc_heap_layout_ignore_minor_gc)) {
      gc_type = static_cast<v8::GCType>(gc_type | kGCTypeScavenge |
                                        kGCTypeMinorMarkSweep);
    }
    AddGCPrologueCallback(HeapLayoutTracer::GCProloguePrintHeapLayout, gc_type,
                          nullptr);
    AddGCEpilogueCallback(HeapLayoutTracer::GCEpiloguePrintHeapLayout, gc_type,
                          nullptr);
  }
}

void Heap::SetUpFromReadOnlyHeap(ReadOnlyHeap* ro_heap) {
  DCHECK_NOT_NULL(ro_heap);
  DCHECK_IMPLIES(read_only_space_ != nullptr,
                 read_only_space_ == ro_heap->read_only_space());
  DCHECK_NULL(space_[RO_SPACE].get());
  read_only_space_ = ro_heap->read_only_space();
  heap_allocator_->SetReadOnlySpace(read_only_space_);
}

void Heap::ReplaceReadOnlySpace(SharedReadOnlySpace* space) {
  CHECK(V8_SHARED_RO_HEAP_BOOL);
  if (read_only_space_) {
    read_only_space_->TearDown(memory_allocator());
    delete read_only_space_;
  }

  read_only_space_ = space;
  heap_allocator_->SetReadOnlySpace(read_only_space_);
}

class StressConcurrentAllocationTask : public CancelableTask {
 public:
  explicit StressConcurrentAllocationTask(Isolate* isolate)
      : CancelableTask(isolate), isolate_(isolate) {}

  void RunInternal() override {
    Heap* heap = isolate_->heap();
    LocalHeap local_heap(heap, ThreadKind::kBackground);
    UnparkedScope unparked_scope(&local_heap);

    const int kNumIterations = 2000;
    const int kSmallObjectSize = 10 * kTaggedSize;
    const int kMediumObjectSize = 8 * KB;
    const int kLargeObjectSize =
        static_cast<int>(MutablePageMetadata::kPageSize -
                         MemoryChunkLayout::ObjectStartOffsetInDataPage());

    for (int i = 0; i < kNumIterations; i++) {
      // Isolate tear down started, stop allocation...
      if (heap->gc_state() == Heap::TEAR_DOWN) return;

      AllocationResult result = local_heap.AllocateRaw(
          kSmallObjectSize, AllocationType::kOld, AllocationOrigin::kRuntime,
          AllocationAlignment::kTaggedAligned);
      if (!result.IsFailure()) {
        heap->CreateFillerObjectAtBackground(
            WritableFreeSpace::ForNonExecutableMemory(result.ToAddress(),
                                                      kSmallObjectSize));
      } else {
        heap->CollectGarbageFromAnyThread(&local_heap);
      }

      result = local_heap.AllocateRaw(kMediumObjectSize, AllocationType::kOld,
                                      AllocationOrigin::kRuntime,
                                      AllocationAlignment::kTaggedAligned);
      if (!result.IsFailure()) {
        heap->CreateFillerObjectAtBackground(
            WritableFreeSpace::ForNonExecutableMemory(result.ToAddress(),
                                                      kMediumObjectSize));
      } else {
        heap->CollectGarbageFromAnyThread(&local_heap);
      }

      result = local_heap.AllocateRaw(kLargeObjectSize, AllocationType::kOld,
                                      AllocationOrigin::kRuntime,
                                      AllocationAlignment::kTaggedAligned);
      if (!result.IsFailure()) {
        heap->CreateFillerObjectAtBackground(
            WritableFreeSpace::ForNonExecutableMemory(result.ToAddress(),
                                                      kLargeObjectSize));
      } else {
        heap->CollectGarbageFromAnyThread(&local_heap);
      }
      local_heap.Safepoint();
    }

    Schedule(isolate_);
  }

  // Schedules task on background thread
  static void Schedule(Isolate* isolate) {
    auto task = std::make_unique<StressConcurrentAllocationTask>(isolate);
    const double kDelayInSeconds = 0.1;
    V8::GetCurrentPlatform()->CallDelayedOnWorkerThread(std::move(task),
                                                        kDelayInSeconds);
  }

 private:
  Isolate* isolate_;
};

class StressConcurrentAllocationObserver : public AllocationObserver {
 public:
  explicit StressConcurrentAllocationObserver(Heap* heap)
      : AllocationObserver(1024), heap_(heap) {}

  void Step(int bytes_allocated, Address, size_t) override {
    DCHECK(heap_->deserialization_complete());
    if (v8_flags.stress_concurrent_allocation) {
      // Only schedule task if --stress-concurrent-allocation is enabled. This
      // allows tests to disable flag even when Isolate was already initialized.
      StressConcurrentAllocationTask::Schedule(heap_->isolate());
    }
    heap_->RemoveAllocationObserversFromAllSpaces(this, this);
    heap_->need_to_remove_stress_concurrent_allocation_observer_ = false;
  }

 private:
  Heap* heap_;
};

namespace {

size_t ReturnNull() { return 0; }

}  // namespace

void Heap::SetUpSpaces(LinearAllocationArea& new_allocation_info,
                       LinearAllocationArea& old_allocation_info) {
  // Ensure SetUpFromReadOnlySpace has been ran.
  DCHECK_NOT_NULL(read_only_space_);

  if (v8_flags.sticky_mark_bits) {
    space_[OLD_SPACE] = std::make_unique<StickySpace>(this);
    old_space_ = static_cast<OldSpace*>(space_[OLD_SPACE].get());
  } else {
    space_[OLD_SPACE] = std::make_unique<OldSpace>(this);
    old_space_ = static_cast<OldSpace*>(space_[OLD_SPACE].get());
  }

  if (!v8_flags.single_generation) {
    if (!v8_flags.sticky_mark_bits) {
      if (v8_flags.minor_ms) {
        space_[NEW_SPACE] = std::make_unique<PagedNewSpace>(
            this, initial_semispace_size_, max_semi_space_size_);
      } else {
        space_[NEW_SPACE] = std::make_unique<SemiSpaceNewSpace>(
            this, initial_semispace_size_, max_semi_space_size_);
      }
      new_space_ = static_cast<NewSpace*>(space_[NEW_SPACE].get());
    }

    space_[NEW_LO_SPACE] =
        std::make_unique<NewLargeObjectSpace>(this, NewSpaceCapacity());
    new_lo_space_ =
        static_cast<NewLargeObjectSpace*>(space_[NEW_LO_SPACE].get());
  }

  space_[CODE_SPACE] = std::make_unique<CodeSpace>(this);
  code_space_ = static_cast<CodeSpace*>(space_[CODE_SPACE].get());

  if (isolate()->is_shared_space_isolate()) {
    space_[SHARED_SPACE] = std::make_unique<SharedSpace>(this);
    shared_space_ = static_cast<SharedSpace*>(space_[SHARED_SPACE].get());
  }

  space_[LO_SPACE] = std::make_unique<OldLargeObjectSpace>(this);
  lo_space_ = static_cast<OldLargeObjectSpace*>(space_[LO_SPACE].get());

  space_[CODE_LO_SPACE] = std::make_unique<CodeLargeObjectSpace>(this);
  code_lo_space_ =
      static_cast<CodeLargeObjectSpace*>(space_[CODE_LO_SPACE].get());

  space_[TRUSTED_SPACE] = std::make_unique<TrustedSpace>(this);
  trusted_space_ = static_cast<TrustedSpace*>(space_[TRUSTED_SPACE].get());

  space_[TRUSTED_LO_SPACE] = std::make_unique<TrustedLargeObjectSpace>(this);
  trusted_lo_space_ =
      static_cast<TrustedLargeObjectSpace*>(space_[TRUSTED_LO_SPACE].get());

  if (isolate()->is_shared_space_isolate()) {
    DCHECK(!v8_flags.sticky_mark_bits);
    space_[SHARED_LO_SPACE] = std::make_unique<SharedLargeObjectSpace>(this);
    shared_lo_space_ =
        static_cast<SharedLargeObjectSpace*>(space_[SHARED_LO_SPACE].get());

    space_[SHARED_TRUSTED_SPACE] = std::make_unique<SharedTrustedSpace>(this);
    shared_trusted_space_ =
        static_cast<SharedTrustedSpace*>(space_[SHARED_TRUSTED_SPACE].get());

    space_[SHARED_TRUSTED_LO_SPACE] =
        std::make_unique<SharedTrustedLargeObjectSpace>(this);
    shared_trusted_lo_space_ = static_cast<SharedTrustedLargeObjectSpace*>(
        space_[SHARED_TRUSTED_LO_SPACE].get());
  }

  if (isolate()->has_shared_space()) {
    Heap* heap = isolate()->shared_space_isolate()->heap();
    shared_allocation_space_ = heap->shared_space_;
    shared_lo_allocation_space_ = heap->shared_lo_space_;

    shared_trusted_allocation_space_ = heap->shared_trusted_space_;
    shared_trusted_lo_allocation_space_ = heap->shared_trusted_lo_space_;
  }

  main_thread_local_heap()->SetUpMainThread(new_allocation_info,
                                            old_allocation_info);

  base::TimeTicks startup_time = base::TimeTicks::Now();

  tracer_.reset(new GCTracer(this, startup_time));
  array_buffer_sweeper_.reset(new ArrayBufferSweeper(this));
  memory_measurement_.reset(new MemoryMeasurement(isolate()));
  if (v8_flags.memory_reducer) memory_reducer_.reset(new MemoryReducer(this));
  if (V8_UNLIKELY(TracingFlags::is_gc_stats_enabled())) {
    live_object_stats_.reset(new ObjectStats(this));
    dead_object_stats_.reset(new ObjectStats(this));
  }
  if (Heap::AllocationTrackerForDebugging::IsNeeded()) {
    allocation_tracker_for_debugging_ =
        std::make_unique<Heap::AllocationTrackerForDebugging>(this);
  }

  LOG(isolate_, IntPtrTEvent("heap-capacity", Capacity()));
  LOG(isolate_, IntPtrTEvent("heap-available", Available()));

  SetGetExternallyAllocatedMemoryInBytesCallback(ReturnNull);

  if (new_space() || v8_flags.sticky_mark_bits) {
    minor_gc_job_.reset(new MinorGCJob(this));
    minor_gc_task_observer_.reset(new ScheduleMinorGCTaskObserver(this));
  }

  if (v8_flags.stress_marking > 0) {
    stress_marking_percentage_ = NextStressMarkingLimit();
  }
  if (IsStressingScavenge()) {
    stress_scavenge_observer_ = new StressScavengeObserver(this);
    allocator()->new_space_allocator()->AddAllocationObserver(
        stress_scavenge_observer_);
  }

  if (v8_flags.memory_balancer) {
    mb_.reset(new MemoryBalancer(this, startup_time));
  }
}

void Heap::InitializeHashSeed() {
  DCHECK(!deserialization_complete_);
  uint64_t new_hash_seed;
  if (v8_flags.hash_seed == 0) {
    int64_t rnd = isolate()->random_number_generator()->NextInt64();
    new_hash_seed = static_cast<uint64_t>(rnd);
  } else {
    new_hash_seed = static_cast<uint64_t>(v8_flags.hash_seed);
  }
  Tagged<ByteArray> hash_seed = ReadOnlyRoots(this).hash_seed();
  MemCopy(hash_seed->begin(), reinterpret_cast<uint8_t*>(&new_hash_seed),
          kInt64Size);
}

std::shared_ptr<v8::TaskRunner> Heap::GetForegroundTaskRunner(
    TaskPriority priority) const {
  return V8::GetCurrentPlatform()->GetForegroundTaskRunner(
      reinterpret_cast<v8::Isolate*>(isolate()), priority);
}

// static
void Heap::InitializeOncePerProcess() {
#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  HeapAllocator::InitializeOncePerProcess();
#endif
  MemoryAllocator::InitializeOncePerProcess();
  if (v8_flags.predictable) {
    ::heap::base::WorklistBase::EnforcePredictableOrder();
  }
}

void Heap::PrintMaxMarkingLimitReached() {
  PrintF("\n### Maximum marking limit reached = %.02lf\n",
         max_marking_limit_reached_.load(std::memory_order_relaxed));
}

void Heap::PrintMaxNewSpaceSizeReached() {
  PrintF("\n### Maximum new space size reached = %.02lf\n",
         stress_scavenge_observer_->MaxNewSpaceSizeReached());
}

int Heap::NextStressMarkingLimit() {
  return isolate()->fuzzer_rng()->NextInt(v8_flags.stress_marking + 1);
}

void Heap::WeakenDescriptorArrays(
    GlobalHandleVector<DescriptorArray> strong_descriptor_arrays) {
  if (incremental_marking()->IsMajorMarking()) {
    // During incremental/concurrent marking regular DescriptorArray objects are
    // treated with custom weakness. This weakness depends on
    // DescriptorArray::raw_gc_state() which is not set up properly upon
    // deserialization. The strong arrays are transitioned to weak ones at the
    // end of the GC.
    mark_compact_collector()->RecordStrongDescriptorArraysForWeakening(
        std::move(strong_descriptor_arrays));
    return;
  }

  // No GC is running, weaken the arrays right away.
  DisallowGarbageCollection no_gc;
  Tagged<Map> descriptor_array_map =
      ReadOnlyRoots(isolate()).descriptor_array_map();
  for (auto it = strong_descriptor_arrays.begin();
       it != strong_descriptor_arrays.end(); ++it) {
    Tagged<DescriptorArray> array = it.raw();
    DCHECK(IsStrongDescriptorArray(array));
    array->set_map_safe_transition_no_write_barrier(isolate(),
                                                    descriptor_array_map);
    DCHECK_EQ(array->raw_gc_state(kRelaxedLoad), 0);
  }
}

void Heap::NotifyDeserializationComplete() {
  // There are no concurrent/background threads yet.
  safepoint()->AssertMainThreadIsOnlyThread();

  FreeMainThreadLinearAllocationAreas();

  PagedSpaceIterator spaces(this);
  for (PagedSpace* s = spaces.Next(); s != nullptr; s = spaces.Next()) {
    // Shared space is used concurrently and cannot be shrunk.
    if (s->identity() == SHARED_SPACE) continue;
    if (isolate()->snapshot_available()) s->ShrinkImmortalImmovablePages();
#ifdef DEBUG
    // All pages right after bootstrapping must be marked as never-evacuate.
    for (PageMetadata* p : *s) {
      DCHECK(p->Chunk()->NeverEvacuate());
    }
#endif  // DEBUG
  }

  if (v8_flags.stress_concurrent_allocation) {
    stress_concurrent_allocation_observer_.reset(
        new StressConcurrentAllocationObserver(this));
    AddAllocationObserversToAllSpaces(
        stress_concurrent_allocation_observer_.get(),
        stress_concurrent_allocation_observer_.get());
    need_to_remove_stress_concurrent_allocation_observer_ = true;
  }

  // Deserialization will never create objects in new space.
  DCHECK_IMPLIES(new_space(), new_space()->Size() == 0);
  DCHECK_IMPLIES(new_lo_space(), new_lo_space()->Size() == 0);

  deserialization_complete_ = true;
}

void Heap::NotifyBootstrapComplete() {
  // This function is invoked for each native context creation. We are
  // interested only in the first native context.
  if (old_generation_capacity_after_bootstrap_ == 0) {
    old_generation_capacity_after_bootstrap_ = OldGenerationCapacity();
  }
}

void Heap::NotifyOldGenerationExpansion(
    LocalHeap* local_heap, AllocationSpace space,
    MutablePageMetadata* chunk_metadata,
    OldGenerationExpansionNotificationOrigin notification_origin) {
  // Pages created during bootstrapping may contain immortal immovable objects.
  if (!deserialization_complete()) {
    DCHECK_NE(NEW_SPACE, chunk_metadata->owner()->identity());
    chunk_metadata->Chunk()->MarkNeverEvacuate();
  }
  if (IsAnyCodeSpace(space)) {
    isolate()->AddCodeMemoryChunk(chunk_metadata);
  }

  // Don't notify MemoryReducer when calling from client heap as otherwise not
  // thread safe.
  const size_t kMemoryReducerActivationThreshold = 1 * MB;
  if (local_heap->is_main_thread_for(this) && memory_reducer() != nullptr &&
      old_generation_capacity_after_bootstrap_ && ms_count_ == 0 &&
      OldGenerationCapacity() >= old_generation_capacity_after_bootstrap_ +
                                     kMemoryReducerActivationThreshold &&
      (notification_origin ==
       OldGenerationExpansionNotificationOrigin::kFromSameHeap) &&
      v8_flags.memory_reducer_for_small_heaps) {
    memory_reducer()->NotifyPossibleGarbage();
  }
}

void Heap::SetEmbedderRootsHandler(EmbedderRootsHandler* handler) {
  embedder_roots_handler_ = handler;
}

EmbedderRootsHandler* Heap::GetEmbedderRootsHandler() const {
  return embedder_roots_handler_;
}

void Heap::AttachCppHeap(v8::CppHeap* cpp_heap) {
  // The API function should be a noop in case a CppHeap was passed on Isolate
  // creation.
  if (owning_cpp_heap_) {
    return;
  }

  CHECK_IMPLIES(incremental_marking(), !incremental_marking()->IsMarking());
  CppHeap::From(cpp_heap)->AttachIsolate(isolate());
  cpp_heap_ = cpp_heap;
}

void Heap::DetachCppHeap() {
  // The API function should be a noop in case a CppHeap was passed on Isolate
  // creation.
  if (owning_cpp_heap_) {
    return;
  }

  CppHeap::From(cpp_heap_)->DetachIsolate();
  cpp_heap_ = nullptr;
}

std::optional<StackState> Heap::overridden_stack_state() const {
  if (!embedder_stack_state_origin_) return {};
  return embedder_stack_state_;
}

void Heap::SetStackStart() {
  // If no main thread local heap has been set up (we're still in the
  // deserialization process), we don't need to set the stack start.
  if (main_thread_local_heap_ == nullptr) return;
  stack().SetStackStart();
}

::heap::base::Stack& Heap::stack() {
  CHECK_NOT_NULL(main_thread_local_heap_);
  return main_thread_local_heap_->stack_;
}

const ::heap::base::Stack& Heap::stack() const {
  CHECK_NOT_NULL(main_thread_local_heap_);
  return main_thread_local_heap_->stack_;
}

void Heap::StartTearDown() {
  if (owning_cpp_heap_) {
    // Release the pointer. The non-owning pointer is still set which allows
    // DetachCppHeap() to work properly.
    auto* cpp_heap = owning_cpp_heap_.release();
    DetachCppHeap();
    // Termination will free up all managed C++ memory and invoke destructors.
    cpp_heap->Terminate();
  }

  // Finish any ongoing sweeping to avoid stray background tasks still accessing
  // the heap during teardown.
  CompleteSweepingFull();

  if (v8_flags.concurrent_marking) {
    concurrent_marking()->Pause();
  }

  SetGCState(TEAR_DOWN);

  // Background threads may allocate and block until GC is performed. However
  // this might never happen when the main thread tries to quit and doesn't
  // process the event queue anymore. Avoid this deadlock by allowing all
  // allocations after tear down was requested to make sure all background
  // threads finish.
  collection_barrier_->NotifyShutdownRequested();

  // Main thread isn't going to allocate anymore.
  main_thread_local_heap()->FreeLinearAllocationAreas();

  FreeMainThreadLinearAllocationAreas();
}

void Heap::TearDownWithSharedHeap() {
  DCHECK_EQ(gc_state(), TEAR_DOWN);

  // Assert that there are no background threads left and no executable memory
  // chunks are unprotected.
  safepoint()->AssertMainThreadIsOnlyThread();

  // Now that all threads are stopped, verify the heap before tearing down the
  // heap/isolate.
  HeapVerifier::VerifyHeapIfEnabled(this);

  // Might use the external pointer which might be in the shared heap.
  external_string_table_.TearDown();

  // Publish shared object worklist for the main thread if incremental marking
  // is enabled for the shared heap.
  main_thread_local_heap()->marking_barrier()->PublishSharedIfNeeded();
}

void Heap::TearDown() {
  DCHECK_EQ(gc_state(), TEAR_DOWN);

  // Assert that there are no background threads left and no executable memory
  // chunks are unprotected.
  safepoint()->AssertMainThreadIsOnlyThread();

  DCHECK(concurrent_marking()->IsStopped());

  // It's too late for Heap::Verify() here, as parts of the Isolate are
  // already gone by the time this is called.

  UpdateMaximumCommitted();

  if (v8_flags.fuzzer_gc_analysis) {
    if (v8_flags.stress_marking > 0) {
      PrintMaxMarkingLimitReached();
    }
    if (IsStressingScavenge()) {
      PrintMaxNewSpaceSizeReached();
    }
  }

  minor_gc_task_observer_.reset();
  minor_gc_job_.reset();

  if (need_to_remove_stress_concurrent_allocation_observer_) {
    RemoveAllocationObserversFromAllSpaces(
        stress_concurrent_allocation_observer_.get(),
        stress_concurrent_allocation_observer_.get());
  }
  stress_concurrent_allocation_observer_.reset();

  if (IsStressingScavenge()) {
    allocator()->new_space_allocator()->RemoveAllocationObserver(
        stress_scavenge_observer_);
    delete stress_scavenge_observer_;
    stress_scavenge_observer_ = nullptr;
  }

  if (mark_compact_collector_) {
    mark_compact_collector_->TearDown();
    mark_compact_collector_.reset();
  }

  if (minor_mark_sweep_collector_) {
    minor_mark_sweep_collector_->TearDown();
    minor_mark_sweep_collector_.reset();
  }

  sweeper_->TearDown();
  sweeper_.reset();

  scavenger_collector_.reset();
  array_buffer_sweeper_.reset();
  incremental_marking_.reset();
  concurrent_marking_.reset();

  memory_measurement_.reset();
  allocation_tracker_for_debugging_.reset();
  ephemeron_remembered_set_.reset();

  if (memory_reducer_ != nullptr) {
    memory_reducer_->TearDown();
    memory_reducer_.reset();
  }

  live_object_stats_.reset();
  dead_object_stats_.reset();

  embedder_roots_handler_ = nullptr;

  if (cpp_heap_) {
    CppHeap::From(cpp_heap_)->DetachIsolate();
    cpp_heap_ = nullptr;
  }

  tracer_.reset();

  pretenuring_handler_.reset();

  for (int i = FIRST_MUTABLE_SPACE; i <= LAST_MUTABLE_SPACE; i++) {
    space_[i].reset();
  }

  read_only_space_ = nullptr;

  memory_allocator()->TearDown();

  StrongRootsEntry* next = nullptr;
  for (StrongRootsEntry* current = strong_roots_head_; current;
       current = next) {
    next = current->next;
    delete current;
  }
  strong_roots_head_ = nullptr;

  memory_allocator_.reset();
}

// static
bool Heap::IsFreeSpaceValid(FreeSpace object) {
  Heap* heap = HeapUtils::GetOwnerHeap(object);
  Tagged<Object> free_space_map =
      heap->isolate()->root(RootIndex::kFreeSpaceMap);
  CHECK(!heap->deserialization_complete() ||
        object.map_slot().contains_map_value(free_space_map.ptr()));
  CHECK_LE(FreeSpace::kNextOffset + kTaggedSize, object.size(kRelaxedLoad));
  return true;
}

void Heap::AddGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                                 GCType gc_type, void* data) {
  gc_prologue_callbacks_.Add(
      callback, reinterpret_cast<v8::Isolate*>(isolate()), gc_type, data);
}

void Heap::RemoveGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                                    void* data) {
  gc_prologue_callbacks_.Remove(callback, data);
}

void Heap::AddGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                                 GCType gc_type, void* data) {
  gc_epilogue_callbacks_.Add(
      callback, reinterpret_cast<v8::Isolate*>(isolate()), gc_type, data);
}

void Heap::RemoveGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                                    void* data) {
  gc_epilogue_callbacks_.Remove(callback, data);
}

namespace {
Handle<WeakArrayList> CompactWeakArrayList(Heap* heap,
                                           Handle<WeakArrayList> array,
                                           AllocationType allocation) {
  if (array->length() == 0) {
    return array;
  }
  int new_length = array->CountLiveWeakReferences();
  if (new_length == array->length()) {
    return array;
  }

  Handle<WeakArrayList> new_array = WeakArrayList::EnsureSpace(
      heap->isolate(),
      handle(ReadOnlyRoots(heap).empty_weak_array_list(), heap->isolate()),
      new_length, allocation);
  // Allocation might have caused GC and turned some of the elements into
  // cleared weak heap objects. Count the number of live references again and
  // fill in the new array.
  int copy_to = 0;
  for (int i = 0; i < array->length(); i++) {
    Tagged<MaybeObject> element = array->Get(i);
    if (element.IsCleared()) continue;
    new_array->Set(copy_to++, element);
  }
  new_array->set_length(copy_to);
  return new_array;
}

}  // anonymous namespace

void Heap::CompactWeakArrayLists() {
  // Find known PrototypeUsers and compact them.
  std::vector<Handle<PrototypeInfo>> prototype_infos;
  {
    HeapObjectIterator iterator(this);
    for (Tagged<HeapObject> o = iterator.Next(); !o.is_null();
         o = iterator.Next()) {
      if (IsPrototypeInfo(*o)) {
        Tagged<PrototypeInfo> prototype_info = Cast<PrototypeInfo>(o);
        if (IsWeakArrayList(prototype_info->prototype_users())) {
          prototype_infos.emplace_back(handle(prototype_info, isolate()));
        }
      }
    }
  }
  for (auto& prototype_info : prototype_infos) {
    DirectHandle<WeakArrayList> array(
        Cast<WeakArrayList>(prototype_info->prototype_users()), isolate());
    DCHECK(InOldSpace(*array) ||
           *array == ReadOnlyRoots(this).empty_weak_array_list());
    Tagged<WeakArrayList> new_array = PrototypeUsers::Compact(
        array, this, JSObject::PrototypeRegistryCompactionCallback,
        AllocationType::kOld);
    prototype_info->set_prototype_users(new_array);
  }

  // Find known WeakArrayLists and compact them.
  Handle<WeakArrayList> scripts(script_list(), isolate());
  DCHECK(InOldSpace(*scripts));
  scripts = CompactWeakArrayList(this, scripts, AllocationType::kOld);
  set_script_list(*scripts);
}

void Heap::AddRetainedMaps(DirectHandle<NativeContext> context,
                           GlobalHandleVector<Map> maps) {
  Handle<WeakArrayList> array(Cast<WeakArrayList>(context->retained_maps()),
                              isolate());
  if (array->IsFull()) {
    CompactRetainedMaps(*array);
  }
  int cur_length = array->length();
  array = WeakArrayList::EnsureSpace(
      isolate(), array, cur_length + static_cast<int>(maps.size()) * 2);
  if (*array != context->retained_maps()) {
    context->set_retained_maps(*array);
  }

  {
    DisallowGarbageCollection no_gc;
    Tagged<WeakArrayList> raw_array = *array;
    for (DirectHandle<Map> map : maps) {
      DCHECK(!HeapLayout::InAnySharedSpace(*map));

      if (map->is_in_retained_map_list()) {
        continue;
      }

      raw_array->Set(cur_length, MakeWeak(*map));
      raw_array->Set(cur_length + 1,
                     Smi::FromInt(v8_flags.retain_maps_for_n_gc));
      cur_length += 2;
      raw_array->set_length(cur_length);

      map->set_is_in_retained_map_list(true);
    }
  }
}

void Heap::CompactRetainedMaps(Tagged<WeakArrayList> retained_maps) {
  int length = retained_maps->length();
  int new_length = 0;
  // This loop compacts the array by removing cleared weak cells.
  for (int i = 0; i < length; i += 2) {
    Tagged<MaybeObject> maybe_object = retained_maps->Get(i);
    if (maybe_object.IsCleared()) {
      continue;
    }

    DCHECK(maybe_object.IsWeak());

    Tagged<MaybeObject> age = retained_maps->Get(i + 1);
    DCHECK(IsSmi(age));
    if (i != new_length) {
      retained_maps->Set(new_length, maybe_object);
      retained_maps->Set(new_length + 1, age);
    }
    new_length += 2;
  }
  Tagged<HeapObject> undefined = ReadOnlyRoots(this).undefined_value();
  for (int i = new_length; i < length; i++) {
    retained_maps->Set(i, undefined);
  }
  if (new_length != length) retained_maps->set_length(new_length);
}

void Heap::FatalProcessOutOfMemory(const char* location) {
  V8::FatalProcessOutOfMemory(isolate(), location, V8::kHeapOOM);
}

#ifdef DEBUG

class PrintHandleVisitor : public RootVisitor {
 public:
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p)
      PrintF("  handle %p to %p\n", p.ToVoidPtr(),
             reinterpret_cast<void*>((*p).ptr()));
  }
};

void Heap::PrintHandles() {
  PrintF("Handles:\n");
  PrintHandleVisitor v;
  isolate_->handle_scope_implementer()->Iterate(&v);
}

#endif

class CheckHandleCountVisitor : public RootVisitor {
 public:
  CheckHandleCountVisitor() : handle_count_(0) {}
  ~CheckHandleCountVisitor() override {
    CHECK_GT(HandleScope::kCheckHandleThreshold, handle_count_);
  }
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    handle_count_ += end - start;
  }

 private:
  ptrdiff_t handle_count_;
};

void Heap::CheckHandleCount() {
  CheckHandleCountVisitor v;
  isolate_->handle_scope_implementer()->Iterate(&v);
}

// static
int Heap::InsertIntoRememberedSetFromCode(MutablePageMetadata* chunk,
                                          size_t slot_offset) {
  // This is called during runtime by a builtin, therefore it is run in the main
  // thread.
  DCHECK_NULL(LocalHeap::Current());
  RememberedSet<OLD_TO_NEW>::Insert<AccessMode::NON_ATOMIC>(chunk, slot_offset);
  return 0;
}

#ifdef DEBUG
void Heap::VerifySlotRangeHasNoRecordedSlots(Address start, Address end) {
#ifndef V8_DISABLE_WRITE_BARRIERS
  PageMetadata* page = PageMetadata::FromAddress(start);
  RememberedSet<OLD_TO_NEW>::CheckNoneInRange(page, start, end);
  RememberedSet<OLD_TO_NEW_BACKGROUND>::CheckNoneInRange(page, start, end);
  RememberedSet<OLD_TO_SHARED>::CheckNoneInRange(page, start, end);
#endif
}
#endif

void Heap::ClearRecordedSlotRange(Address start, Address end) {
#ifndef V8_DISABLE_WRITE_BARRIERS
  MemoryChunk* chunk = MemoryChunk::FromAddress(start);
  DCHECK(!chunk->IsLargePage());
#if !V8_ENABLE_STICKY_MARK_BITS_BOOL
  if (!chunk->InYoungGeneration())
#endif
  {
    PageMetadata* page = PageMetadata::cast(chunk->Metadata());
    // This method will be invoked on objects in shared space for
    // internalization and string forwarding during GC.
    DCHECK(page->owner_identity() == OLD_SPACE ||
           page->owner_identity() == TRUSTED_SPACE ||
           page->owner_identity() == SHARED_SPACE);

    if (!page->SweepingDone()) {
      RememberedSet<OLD_TO_NEW>::RemoveRange(page, start, end,
                                             SlotSet::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
          page, start, end, SlotSet::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_SHARED>::RemoveRange(page, start, end,
                                                SlotSet::KEEP_EMPTY_BUCKETS);
    }
  }
#endif
}

PagedSpace* PagedSpaceIterator::Next() {
  DCHECK_GE(counter_, FIRST_GROWABLE_PAGED_SPACE);
  while (counter_ <= LAST_GROWABLE_PAGED_SPACE) {
    PagedSpace* space = heap_->paged_space(counter_++);
    if (space) return space;
  }
  return nullptr;
}

class HeapObjectsFilter {
 public:
  virtual ~HeapObjectsFilter() = default;
  virtual bool SkipObject(Tagged<HeapObject> object) = 0;
};

class UnreachableObjectsFilter : public HeapObjectsFilter {
 public:
  explicit UnreachableObjectsFilter(Heap* heap) : heap_(heap) {
    MarkReachableObjects();
  }

  ~UnreachableObjectsFilter() override = default;

  bool SkipObject(Tagged<HeapObject> object) override {
    // Space object iterators should skip free space or filler objects.
    DCHECK(!IsFreeSpaceOrFiller(object));
    // If the bucket corresponding to the object's chunk does not exist, or the
    // object is not found in the bucket, return true.
    MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);
    if (reachable_.count(chunk) == 0) return true;
    return reachable_[chunk]->count(object) == 0;
  }

 private:
  using BucketType = std::unordered_set<Tagged<HeapObject>, Object::Hasher>;

  bool MarkAsReachable(Tagged<HeapObject> object) {
    // If the bucket corresponding to the object's chunk does not exist, then
    // create an empty bucket.
    MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);
    if (reachable_.count(chunk) == 0) {
      reachable_[chunk] = std::make_unique<BucketType>();
    }
    // Insert the object if not present; return whether it was indeed inserted.
    if (reachable_[chunk]->count(object)) return false;
    reachable_[chunk]->insert(object);
    return true;
  }

  class MarkingVisitor : public ObjectVisitorWithCageBases, public RootVisitor {
   public:
    explicit MarkingVisitor(UnreachableObjectsFilter* filter)
        : ObjectVisitorWithCageBases(filter->heap_), filter_(filter) {}

    void VisitMapPointer(Tagged<HeapObject> object) override {
      MarkHeapObject(UncheckedCast<Map>(object->map(cage_base())));
    }
    void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                       ObjectSlot end) override {
      MarkPointersImpl(start, end);
    }

    void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                       MaybeObjectSlot end) final {
      MarkPointersImpl(start, end);
    }

    void VisitInstructionStreamPointer(Tagged<Code> host,
                                       InstructionStreamSlot slot) override {
      Tagged<Object> maybe_code = slot.load(code_cage_base());
      Tagged<HeapObject> heap_object;
      if (maybe_code.GetHeapObject(&heap_object)) {
        MarkHeapObject(heap_object);
      }
    }

    void VisitCodeTarget(Tagged<InstructionStream> host,
                         RelocInfo* rinfo) final {
      Tagged<InstructionStream> target =
          InstructionStream::FromTargetAddress(rinfo->target_address());
      MarkHeapObject(target);
    }
    void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) final {
      MarkHeapObject(rinfo->target_object(cage_base()));
    }

    void VisitRootPointers(Root root, const char* description,
                           FullObjectSlot start, FullObjectSlot end) override {
      MarkPointersImpl(start, end);
    }
    void VisitRootPointers(Root root, const char* description,
                           OffHeapObjectSlot start,
                           OffHeapObjectSlot end) override {
      MarkPointersImpl(start, end);
    }

    void TransitiveClosure() {
      while (!marking_stack_.empty()) {
        Tagged<HeapObject> obj = marking_stack_.back();
        marking_stack_.pop_back();
        VisitObject(filter_->heap_->isolate(), obj, this);
      }
    }

   private:
    template <typename TSlot>
    V8_INLINE void MarkPointersImpl(TSlot start, TSlot end) {
      // Treat weak references as strong.
      for (TSlot p = start; p < end; ++p) {
        typename TSlot::TObject object = p.load(cage_base());
#ifdef V8_ENABLE_DIRECT_HANDLE
        if (object.ptr() == kTaggedNullAddress) continue;
#endif
        Tagged<HeapObject> heap_object;
        if (object.GetHeapObject(&heap_object)) {
          MarkHeapObject(heap_object);
        }
      }
    }

    V8_INLINE void MarkHeapObject(Tagged<HeapObject> heap_object) {
      if (filter_->MarkAsReachable(heap_object)) {
        marking_stack_.push_back(heap_object);
      }
    }

    UnreachableObjectsFilter* filter_;
    std::vector<Tagged<HeapObject>> marking_stack_;
  };

  friend class MarkingVisitor;

  void MarkReachableObjects() {
    MarkingVisitor visitor(this);
    heap_->stack().SetMarkerIfNeededAndCallback(
        [this, &visitor]() { heap_->IterateRoots(&visitor, {}); });
    visitor.TransitiveClosure();
  }

  Heap* heap_;
  DISALLOW_GARBAGE_COLLECTION(no_gc_)
  std::unordered_map<MemoryChunkMetadata*, std::unique_ptr<BucketType>,
                     base::hash<MemoryChunkMetadata*>>
      reachable_;
};

HeapObjectIterator::HeapObjectIterator(
    Heap* heap, HeapObjectIterator::HeapObjectsFiltering filtering)
    : HeapObjectIterator(
          heap,
          new SafepointScope(heap->isolate(),
                             kGlobalSafepointForSharedSpaceIsolate),
          filtering) {}

HeapObjectIterator::HeapObjectIterator(Heap* heap,
                                       const SafepointScope& safepoint_scope,
                                       HeapObjectsFiltering filtering)
    : HeapObjectIterator(heap, nullptr, filtering) {}

HeapObjectIterator::HeapObjectIterator(
    Heap* heap, SafepointScope* safepoint_scope_or_nullptr,
    HeapObjectsFiltering filtering)
    : heap_(heap),
      safepoint_scope_(safepoint_scope_or_nullptr),
      space_iterator_(heap_) {
  heap_->MakeHeapIterable();
  switch (filtering) {
    case kFilterUnreachable:
      filter_ = std::make_unique<UnreachableObjectsFilter>(heap_);
      break;
    default:
      break;
  }
  // Start the iteration.
  CHECK(space_iterator_.HasNext());
  object_iterator_ = space_iterator_.Next()->GetObjectIterator(heap_);
}

HeapObjectIterator::~HeapObjectIterator() = default;

Tagged<HeapObject> HeapObjectIterator::Next() {
  if (!filter_) return NextObject();

  Tagged<HeapObject> obj = NextObject();
  while (!obj.is_null() && filter_->SkipObject(obj)) obj = NextObject();
  return obj;
}

Tagged<HeapObject> HeapObjectIterator::NextObject() {
  // No iterator means we are done.
  if (!object_iterator_) return Tagged<HeapObject>();

  Tagged<HeapObject> obj = object_iterator_->Next();
  // If the current iterator has more objects we are fine.
  if (!obj.is_null()) return obj;
  // Go though the spaces looking for one that has objects.
  while (space_iterator_.HasNext()) {
    object_iterator_ = space_iterator_.Next()->GetObjectIterator(heap_);
    obj = object_iterator_->Next();
    if (!obj.is_null()) return obj;
  }
  // Done with the last space.
  object_iterator_.reset();
  return Tagged<HeapObject>();
}

void Heap::UpdateTotalGCTime(base::TimeDelta duration) {
  total_gc_time_ms_ += duration;
}

void Heap::ExternalStringTable::CleanUpYoung() {
  int last = 0;
  Isolate* isolate = heap_->isolate();
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<Object> o = young_strings_[i];
    if (IsTheHole(o, isolate)) {
      continue;
    }
    // The real external string is already in one of these vectors and was or
    // will be processed. Re-processing it will add a duplicate to the vector.
    if (IsThinString(o)) continue;
    DCHECK(IsExternalString(o));
    if (HeapLayout::InYoungGeneration(o)) {
      young_strings_[last++] = o;
    } else {
      old_strings_.push_back(o);
    }
  }
  young_strings_.resize(last);
}

void Heap::ExternalStringTable::CleanUpAll() {
  CleanUpYoung();
  int last = 0;
  Isolate* isolate = heap_->isolate();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<Object> o = old_strings_[i];
    if (IsTheHole(o, isolate)) {
      continue;
    }
    // The real external string is already in one of these vectors and was or
    // will be processed. Re-processing it will add a duplicate to the vector.
    if (IsThinString(o)) continue;
    DCHECK(IsExternalString(o));
    DCHECK(!HeapLayout::InYoungGeneration(o));
    old_strings_[last++] = o;
  }
  old_strings_.resize(last);
  if (v8_flags.verify_heap) {
    Verify();
  }
}

void Heap::ExternalStringTable::TearDown() {
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<Object> o = young_strings_[i];
    // Dont finalize thin strings.
    if (IsThinString(o)) continue;
    heap_->FinalizeExternalString(Cast<ExternalString>(o));
  }
  young_strings_.clear();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<Object> o = old_strings_[i];
    // Dont finalize thin strings.
    if (IsThinString(o)) continue;
    heap_->FinalizeExternalString(Cast<ExternalString>(o));
  }
  old_strings_.clear();
}

void Heap::RememberUnmappedPage(Address page, bool compacted) {
  // Tag the page pointer to make it findable in the dump file.
  if (compacted) {
    page ^= 0xC1EAD & (PageMetadata::kPageSize - 1);  // Cleared.
  } else {
    page ^= 0x1D1ED & (PageMetadata::kPageSize - 1);  // I died.
  }
  remembered_unmapped_pages_[remembered_unmapped_pages_index_] = page;
  remembered_unmapped_pages_index_++;
  remembered_unmapped_pages_index_ %= kRememberedUnmappedPages;
}

size_t Heap::YoungArrayBufferBytes() {
  return array_buffer_sweeper()->YoungBytes();
}

uint64_t Heap::UpdateExternalMemory(int64_t delta) {
  uint64_t amount = external_memory_.UpdateAmount(delta);
  uint64_t low_since_mark_compact = external_memory_.low_since_mark_compact();
  if (amount < low_since_mark_compact) {
    external_memory_.UpdateLowSinceMarkCompact(amount);
  }
  return amount;
}

size_t Heap::OldArrayBufferBytes() {
  return array_buffer_sweeper()->OldBytes();
}

StrongRootsEntry* Heap::RegisterStrongRoots(const char* label,
                                            FullObjectSlot start,
                                            FullObjectSlot end) {
  // We're either on the main thread, or in a background thread with an active
  // local heap.
  DCHECK(isolate()->CurrentLocalHeap()->IsRunning());

  base::MutexGuard guard(&strong_roots_mutex_);

  StrongRootsEntry* entry = new StrongRootsEntry(label);
  entry->start = start;
  entry->end = end;
  entry->prev = nullptr;
  entry->next = strong_roots_head_;

  if (strong_roots_head_) {
    DCHECK_NULL(strong_roots_head_->prev);
    strong_roots_head_->prev = entry;
  }
  strong_roots_head_ = entry;

  return entry;
}

void Heap::UpdateStrongRoots(StrongRootsEntry* entry, FullObjectSlot start,
                             FullObjectSlot end) {
  entry->start = start;
  entry->end = end;
}

void Heap::UnregisterStrongRoots(StrongRootsEntry* entry) {
  // We're either on the main thread, or in a background thread with an active
  // local heap.
  DCHECK(isolate()->CurrentLocalHeap()->IsRunning());

  base::MutexGuard guard(&strong_roots_mutex_);

  StrongRootsEntry* prev = entry->prev;
  StrongRootsEntry* next = entry->next;

  if (prev) prev->next = next;
  if (next) next->prev = prev;

  if (strong_roots_head_ == entry) {
    DCHECK_NULL(prev);
    strong_roots_head_ = next;
  }

  delete entry;
}

void Heap::SetBuiltinsConstantsTable(Tagged<FixedArray> cache) {
  set_builtins_constants_table(cache);
}

void Heap::SetDetachedContexts(Tagged<WeakArrayList> detached_contexts) {
  set_detached_contexts(detached_contexts);
}

bool Heap::HasDirtyJSFinalizationRegistries() {
  return !IsUndefined(dirty_js_finalization_registries_list(), isolate());
}

void Heap::PostFinalizationRegistryCleanupTaskIfNeeded() {
  // Only one cleanup task is posted at a time.
  if (!HasDirtyJSFinalizationRegistries() ||
      is_finalization_registry_cleanup_task_posted_) {
    return;
  }
  auto task = std::make_unique<FinalizationRegistryCleanupTask>(this);
  task_runner_->PostNonNestableTask(std::move(task));
  is_finalization_registry_cleanup_task_posted_ = true;
}

void Heap::EnqueueDirtyJSFinalizationRegistry(
    Tagged<JSFinalizationRegistry> finalization_registry,
    std::function<void(Tagged<HeapObject> object, ObjectSlot slot,
                       Tagged<Object> target)>
        gc_notify_updated_slot) {
  // Add a FinalizationRegistry to the tail of the dirty list.
  DCHECK(!HasDirtyJSFinalizationRegistries() ||
         IsJSFinalizationRegistry(dirty_js_finalization_registries_list()));
  DCHECK(IsUndefined(finalization_registry->next_dirty(), isolate()));
  DCHECK(!finalization_registry->scheduled_for_cleanup());
  finalization_registry->set_scheduled_for_cleanup(true);
  if (IsUndefined(dirty_js_finalization_registries_list_tail(), isolate())) {
    DCHECK(IsUndefined(dirty_js_finalization_registries_list(), isolate()));
    set_dirty_js_finalization_registries_list(finalization_registry);
    // dirty_js_finalization_registries_list_ is rescanned by
    // ProcessWeakListRoots.
  } else {
    Tagged<JSFinalizationRegistry> tail = Cast<JSFinalizationRegistry>(
        dirty_js_finalization_registries_list_tail());
    tail->set_next_dirty(finalization_registry);
    gc_notify_updated_slot(
        tail, tail->RawField(JSFinalizationRegistry::kNextDirtyOffset),
        finalization_registry);
  }
  set_dirty_js_finalization_registries_list_tail(finalization_registry);
  // dirty_js_finalization_registries_list_tail_ is rescanned by
  // ProcessWeakListRoots.
}

MaybeHandle<JSFinalizationRegistry> Heap::DequeueDirtyJSFinalizationRegistry() {
  // Take a FinalizationRegistry from the head of the dirty list for fairness.
  if (HasDirtyJSFinalizationRegistries()) {
    Handle<JSFinalizationRegistry> head(
        Cast<JSFinalizationRegistry>(dirty_js_finalization_registries_list()),
        isolate());
    set_dirty_js_finalization_registries_list(head->next_dirty());
    head->set_next_dirty(ReadOnlyRoots(this).undefined_value());
    if (*head == dirty_js_finalization_registries_list_tail()) {
      set_dirty_js_finalization_registries_list_tail(
          ReadOnlyRoots(this).undefined_value());
    }
    return head;
  }
  return {};
}

void Heap::RemoveDirtyFinalizationRegistriesOnContext(
    Tagged<NativeContext> context) {
  DisallowGarbageCollection no_gc;

  Isolate* isolate = this->isolate();
  Tagged<Object> prev = ReadOnlyRoots(isolate).undefined_value();
  Tagged<Object> current = dirty_js_finalization_registries_list();
  while (!IsUndefined(current, isolate)) {
    Tagged<JSFinalizationRegistry> finalization_registry =
        Cast<JSFinalizationRegistry>(current);
    if (finalization_registry->native_context() == context) {
      if (IsUndefined(prev, isolate)) {
        set_dirty_js_finalization_registries_list(
            finalization_registry->next_dirty());
      } else {
        Cast<JSFinalizationRegistry>(prev)->set_next_dirty(
            finalization_registry->next_dirty());
      }
      finalization_registry->set_scheduled_for_cleanup(false);
      current = finalization_registry->next_dirty();
      finalization_registry->set_next_dirty(
          ReadOnlyRoots(isolate).undefined_value());
    } else {
      prev = current;
      current = finalization_registry->next_dirty();
    }
  }
  set_dirty_js_finalization_registries_list_tail(prev);
}

void Heap::KeepDuringJob(DirectHandle<HeapObject> target) {
  DCHECK(IsUndefined(weak_refs_keep_during_job()) ||
         IsOrderedHashSet(weak_refs_keep_during_job()));
  Handle<OrderedHashSet> table;
  if (IsUndefined(weak_refs_keep_during_job(), isolate())) {
    table = isolate()->factory()->NewOrderedHashSet();
  } else {
    table =
        handle(Cast<OrderedHashSet>(weak_refs_keep_during_job()), isolate());
  }
  MaybeHandle<OrderedHashSet> maybe_table =
      OrderedHashSet::Add(isolate(), table, target);
  if (!maybe_table.ToHandle(&table)) {
    FATAL(
        "Fatal JavaScript error: Too many distinct WeakRef objects "
        "created or dereferenced during single event loop turn.");
  }
  set_weak_refs_keep_during_job(*table);
}

void Heap::ClearKeptObjects() {
  set_weak_refs_keep_during_job(ReadOnlyRoots(isolate()).undefined_value());
}

size_t Heap::NumberOfTrackedHeapObjectTypes() {
  return ObjectStats::OBJECT_STATS_COUNT;
}

size_t Heap::ObjectCountAtLastGC(size_t index) {
  if (live_object_stats_ == nullptr || index >= ObjectStats::OBJECT_STATS_COUNT)
    return 0;
  return live_object_stats_->object_count_last_gc(index);
}

size_t Heap::ObjectSizeAtLastGC(size_t index) {
  if (live_object_stats_ == nullptr || index >= ObjectStats::OBJECT_STATS_COUNT)
    return 0;
  return live_object_stats_->object_size_last_gc(index);
}

bool Heap::GetObjectTypeName(size_t index, const char** object_type,
                             const char** object_sub_type) {
  if (index >= ObjectStats::OBJECT_STATS_COUNT) return false;

  switch (static_cast<int>(index)) {
#define COMPARE_AND_RETURN_NAME(name) \
  case name:                          \
    *object_type = #name;             \
    *object_sub_type = "";            \
    return true;
    INSTANCE_TYPE_LIST(COMPARE_AND_RETURN_NAME)
#undef COMPARE_AND_RETURN_NAME

#define COMPARE_AND_RETURN_NAME(name)                       \
  case ObjectStats::FIRST_VIRTUAL_TYPE + ObjectStats::name: \
    *object_type = #name;                                   \
    *object_sub_type = "";                                  \
    return true;
    VIRTUAL_INSTANCE_TYPE_LIST(COMPARE_AND_RETURN_NAME)
#undef COMPARE_AND_RETURN_NAME
  }
  return false;
}

size_t Heap::NumberOfNativeContexts() {
  int result = 0;
  Tagged<Object> context = native_contexts_list();
  while (!IsUndefined(context, isolate())) {
    ++result;
    Tagged<Context> native_context = Cast<Context>(context);
    context = native_context->next_context_link();
  }
  return result;
}

std::vector<Handle<NativeContext>> Heap::FindAllNativeContexts() {
  std::vector<Handle<NativeContext>> result;
  Tagged<Object> context = native_contexts_list();
  while (!IsUndefined(context, isolate())) {
    Tagged<NativeContext> native_context = Cast<NativeContext>(context);
    result.push_back(handle(native_context, isolate()));
    context = native_context->next_context_link();
  }
  return result;
}

std::vector<Tagged<WeakArrayList>> Heap::FindAllRetainedMaps() {
  std::vector<Tagged<WeakArrayList>> result;
  Tagged<Object> context = native_contexts_list();
  while (!IsUndefined(context, isolate())) {
    Tagged<NativeContext> native_context = Cast<NativeC
"""


```