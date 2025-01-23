Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Context:** The prompt clearly states this is a part of `v8/src/heap/heap.cc`. This immediately tells us we're dealing with the core memory management within the V8 JavaScript engine. The `.cc` extension signifies C++ source code. The part number "7 of 9" suggests we're looking at a chunk of a larger file, and thus the functionality might be related to a subset of heap management.

2. **Initial Scan for Keywords and Patterns:**  Quickly scan the code for recurring terms. Words like "SizeOfObjects", "WastedBytes", "ConsumedBytes", "Generation", "Limit", "Allocation", "GC", "IncrementalMarking" jump out. The presence of `v8_flags` suggests the behavior is configurable via command-line flags. Functions like `ShouldExpandOldGenerationOnSlowAllocation`, `IncrementalMarkingLimitReached`, `PercentToOldGenerationLimit` hint at decision-making processes related to memory management strategies.

3. **Group Related Functions:** Notice patterns in function naming. Functions starting with `OldGeneration...` clearly deal with the old generation heap space. Similarly, `YoungGeneration...` relates to the young generation. This suggests a logical division of responsibilities within the code.

4. **Analyze Individual Functions/Blocks:** Start examining individual functions or small groups of related functions.

   * **`OldGenerationSizeOfObjects()`:**  Looks like it's calculating the size of live objects in the old generation. It iterates through `PagedSpace` and sums the `SizeOfObjects()` for each.

   * **`OldGenerationWastedBytes()`:** Calculates wasted space in the old generation, again by iterating through `PagedSpace` and summing `Waste()`.

   * **`OldGenerationConsumedBytes()`:**  Simple addition of the previous two, representing the total memory used by the old generation.

   * **Repeat for `YoungGeneration...`:** Similar logic but for the young generation, handling different space types (`new_space`, `new_lo_space`, `paged_new_space`, `semi_space_new_space`). The conditional logic based on `v8_flags.sticky_mark_bits` and `v8_flags.minor_ms` indicates different memory management strategies being employed.

   * **`EmbedderSizeOfObjects()`:**  Deals with memory managed by the embedder (the application using V8).

   * **`GlobalSizeOfObjects()`:** Sums up the object sizes across old generation, embedder, and potentially external memory.

   * **`GlobalWastedBytes()` and `GlobalConsumedBytes()`:** Similar logic as for the old generation, but at a global level.

   * **`...AtLastGC()` functions:**  Store memory usage snapshots from the last garbage collection cycle.

   * **`AllocationLimitOvershotByLargeMargin()`:** This function is more complex. It checks if the current memory usage has significantly exceeded the allocation limits, taking into account both V8's internal limits and global limits. The `kMarginForSmallHeaps` constant suggests special handling for smaller heaps. This function seems crucial for triggering or delaying garbage collection.

   * **`ShouldOptimizeForLoadTime()`:** Checks if the engine is still in the loading phase and hasn't overshot allocation limits. This suggests V8 might adjust its memory management during startup for faster loading.

   * **`ShouldExpandOldGenerationOnSlowAllocation()` and `ShouldExpandYoungGenerationOnSlowAllocation()`:** These are crucial decision points. They determine whether to allocate more memory when a request fails, or to trigger a garbage collection instead. The logic involves checking flags, GC state, deserialization status, and whether allocation limits have been reached.

   * **`CurrentHeapGrowingMode()`:** Selects the heap growing strategy based on flags and memory pressure.

   * **`GlobalMemoryAvailable()`:** Calculates the remaining allocatable memory within the global limit.

   * **`PercentToOldGenerationLimit()` and `PercentToGlobalMemoryLimit()`:**  Calculate the percentage of memory used relative to the allocation limits.

   * **`IncrementalMarkingLimitReached()`:**  This is another complex function determining when to start incremental marking (a garbage collection technique). It considers various flags, memory pressure, and the percentage of memory used. The different return values (`kNoLimit`, `kSoftLimit`, `kHardLimit`, `kFallbackForEmbedderLimit`) indicate different urgency levels.

   * **`ShouldStressCompaction()`:**  Used for testing, it forces compaction during garbage collection.

5. **Identify Key Themes:** Based on the analysis of individual functions, several key themes emerge:

   * **Memory Accounting:** Tracking the size of objects, wasted space, and consumed space in different generations and at a global level.
   * **Allocation Limits:** Managing and checking against allocation limits for both old and global generations.
   * **Garbage Collection Triggering:**  Deciding when to initiate garbage collection based on memory usage, limits, and various flags. The logic for incremental marking is particularly prominent.
   * **Heap Expansion:** Determining whether to expand the heap when allocation fails, or to trigger garbage collection instead.
   * **Configuration and Optimization:** The use of `v8_flags` indicates configurability and different optimization strategies for memory usage, load time, etc.

6. **Address Specific Prompts:** Now go back to the prompt and address each point directly:

   * **Functionality:** Summarize the identified key themes.
   * **`.tq` extension:** Explain that the provided code is `.cc`, not `.tq`, and therefore not Torque.
   * **Relationship to JavaScript:** Explain how these functions relate to JavaScript's automatic memory management. Provide a simple JavaScript example demonstrating the creation of objects that would be managed by this C++ code.
   * **Code Logic Reasoning:** Choose a function with conditional logic (like `AllocationLimitOvershotByLargeMargin` or `ShouldExpandOldGenerationOnSlowAllocation`) and provide example inputs and expected outputs based on the code's behavior.
   * **Common Programming Errors:** Relate the memory management concepts to potential JavaScript errors like memory leaks (although the C++ code tries to prevent them).
   * **Summary:** Concisely summarize the main purpose of this code snippet within the larger context of V8's heap management.

7. **Refine and Organize:**  Review the analysis and make sure it's clear, concise, and well-organized. Use headings and bullet points to improve readability. Double-check for accuracy and consistency. For example, ensure the JavaScript example directly relates to the C++ concepts discussed.

This systematic approach, combining high-level scanning with detailed analysis of specific functions, allows for a comprehensive understanding of the code's purpose and its role within the larger system.
这是 V8 源代码 `v8/src/heap/heap.cc` 的第七部分，主要负责 V8 堆的内存使用情况统计、限制管理、以及与垃圾回收 (GC) 相关的决策逻辑。

**功能归纳：**

这部分代码主要关注以下几个核心功能：

1. **内存使用量统计:**  它提供了多种方法来获取堆中不同部分的内存使用情况，包括：
    *  老生代 (Old Generation) 中对象的大小、浪费的字节数、以及总消耗字节数。
    *  新生代 (Young Generation) 中对象的大小、浪费的字节数、以及总消耗字节数。
    *  嵌入器 (Embedder) 分配的对象大小。
    *  全局的对象大小、浪费的字节数、以及总消耗字节数。
    *  上次垃圾回收时的老生代和全局消耗字节数。
    *  自上次主要 GC 以来分配的外部内存大小。

2. **堆内存限制管理和判断:**  它包含一些关键的判断逻辑，用于确定堆是否接近或超过其分配限制，这对于触发垃圾回收至关重要。
    *  `AllocationLimitOvershotByLargeMargin()`: 判断分配是否大幅超出限制。
    *  `ShouldOptimizeForLoadTime()`: 判断是否应该为了加载速度而优化内存分配。
    *  `ShouldExpandOldGenerationOnSlowAllocation()`:  决定在老生代分配缓慢时是否应该扩展老生代空间，否则可能触发 major GC。
    *  `ShouldExpandYoungGenerationOnSlowAllocation()`: 决定在新生代分配缓慢时是否应该扩展新生代空间，否则可能触发 minor GC。
    *  `CurrentHeapGrowingMode()`:  确定当前的堆增长模式（例如，最小、保守、缓慢、默认）。
    *  `GlobalMemoryAvailable()`: 计算全局可用的内存。
    *  `PercentToOldGenerationLimit()` 和 `PercentToGlobalMemoryLimit()`:  计算当前内存使用量占各自限制的百分比。
    *  `IncrementalMarkingLimitReached()`:  判断是否达到了触发增量标记的限制。

3. **垃圾回收触发决策:**  这部分代码包含决定何时以及如何触发垃圾回收的关键逻辑。 `IncrementalMarkingLimitReached()` 是一个核心函数，它根据多种因素（例如内存压力、配置标志等）来决定是否应该开始增量标记。

4. **初始化和设置:**  `SetUp()` 函数负责堆的初始化，包括空间分配、内存分配器设置、垃圾回收器初始化等。 `SetUpFromReadOnlyHeap()` 和 `ReplaceReadOnlySpace()` 用于处理只读堆的设置。

5. **并发相关:**  `StressConcurrentAllocationTask` 和 `StressConcurrentAllocationObserver` 用于压力测试并发分配的场景。

**关于 .tq 结尾：**

代码片段是 C++ 代码 (`.cc`)，不是 Torque 代码 (`.tq`)。 Torque 是一种 V8 特定的领域特定语言，用于生成高效的运行时代码。如果 `v8/src/heap/heap.cc` 文件以 `.tq` 结尾，那么它的内容将会是 Torque 代码，并且需要 Torque 编译器来生成 C++ 代码。

**与 JavaScript 的功能关系 (示例)：**

这部分 C++ 代码直接支持着 JavaScript 的内存管理。当我们用 JavaScript 创建对象时，V8 引擎会在其堆中分配内存。这里列举的函数就是用来跟踪这些内存的分配和使用情况，并决定何时进行垃圾回收以释放不再使用的内存。

```javascript
// JavaScript 示例

// 创建一些对象
let obj1 = { name: "Object 1" };
let obj2 = { data: [1, 2, 3, 4, 5] };
let str = "A long string";

// 当这些对象不再被引用时，垃圾回收器会回收它们占用的内存。

// 我们可以通过 V8 的 API (通常在 Node.js 中) 观察一些堆的统计信息
// 但直接访问这里列出的 C++ 函数是不可能的。

// 在 Node.js 中，可以使用 process.memoryUsage() 来查看一些内存使用情况
// console.log(process.memoryUsage()); // 这会输出 RSS、heapTotal、heapUsed 等信息，
                                    // 这些信息背后就与这里的 C++ 代码相关。
```

当 JavaScript 引擎执行上述代码时，`Heap::YoungGenerationSizeOfObjects()` 和 `Heap::OldGenerationSizeOfObjects()` 等函数的值会相应增加。当 JavaScript 引擎决定进行垃圾回收时，`IncrementalMarkingLimitReached()` 等函数会参与决策过程。

**代码逻辑推理 (假设输入与输出)：**

假设以下情况：

* **输入:** 老生代当前已用对象大小为 100MB，浪费的字节数为 10MB。
* **调用:** `heap->OldGenerationConsumedBytes()`

**输出:** 110MB (100MB + 10MB)

假设以下情况：

* **输入:**  `v8_flags.incremental_marking_soft_trigger` 设置为 60， `v8_flags.incremental_marking_hard_trigger` 设置为 80。
* **输入:**  `PercentToOldGenerationLimit()` 返回 65， `PercentToGlobalMemoryLimit()` 返回 55。
* **调用:** `heap->IncrementalMarkingLimitReached()`

**输出:** `IncrementalMarkingLimit::kSoftLimit`  (因为老生代内存使用百分比超过了软触发阈值 60，但未超过硬触发阈值 80)。

**用户常见的编程错误 (与此部分代码相关)：**

虽然用户无法直接与这部分 C++ 代码交互，但 JavaScript 中的某些编程错误会导致堆的压力增加，最终触发这里定义的垃圾回收机制。

* **内存泄漏:**  在 JavaScript 中忘记释放对象的引用，导致对象无法被垃圾回收，长期累积会耗尽堆内存。

```javascript
// JavaScript 内存泄漏示例
let leakyArray = [];
function leakMemory() {
  let obj = { largeData: new Array(1000000) };
  leakyArray.push(obj); // 每次调用都向数组添加一个大对象，但从未移除
}

setInterval(leakMemory, 100); // 每 100 毫秒泄漏一些内存
```

这种情况下，`Heap::OldGenerationConsumedBytes()` 的值会持续增长，最终可能导致 `AllocationLimitOvershotByLargeMargin()` 返回 `true`，并触发垃圾回收。

* **创建大量临时对象:**  在循环或高频操作中创建大量生命周期很短的对象，会给新生代带来很大压力，导致频繁的 minor GC。

```javascript
// JavaScript 创建大量临时对象示例
for (let i = 0; i < 1000000; i++) {
  let tempObj = { value: i }; // 每次循环都创建一个新对象
  // 对 tempObj 进行一些操作，然后它就变得不可达
}
```

在这种情况下，`Heap::YoungGenerationSizeOfObjects()` 会快速增长，并且可能导致 `ShouldExpandYoungGenerationOnSlowAllocation()` 返回 `false`，触发 minor GC。

**总结第 7 部分的功能：**

`v8/src/heap/heap.cc` 的第七部分主要负责 **监控和管理 V8 堆的内存使用情况，并基于这些信息和配置参数，做出是否需要进行垃圾回收以及如何扩展堆空间的决策。** 它是 V8 引擎进行有效内存管理的关键组成部分，确保 JavaScript 代码能够高效运行并避免因内存耗尽而崩溃。 这部分代码的核心在于平衡内存使用效率、程序运行性能和启动速度。

### 提示词
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  embedder_roots_handler_ = hand
```