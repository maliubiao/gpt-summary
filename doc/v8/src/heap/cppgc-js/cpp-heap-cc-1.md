Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the summary.

**1. Initial Understanding of the Request:**

The request asks for a functional summary of a V8 source code file (`v8/src/heap/cppgc-js/cpp-heap.cc`). It specifically requests noting if the file were a Torque file (it's not), if it relates to JavaScript (it does), and asks for examples, logic, and potential errors. It also specifies this is part 2 of 2, implying we need to summarize the functionality presented in this particular snippet.

**2. High-Level Skim and Keyword Spotting:**

I started by quickly skimming the code, looking for keywords and function names that indicate the purpose of different sections. Keywords like `GC`, `Marking`, `Sweeping`, `Allocation`, `Compact`, `PreFinalizers`, `RememberedSet`, `Isolate`, `Heap`, and `Testing` immediately jump out. These give a general idea of the code's focus: memory management and garbage collection within the V8 JavaScript engine's C++ heap.

**3. Section-by-Section Analysis (and Initial Thoughts):**

I then went through the code more deliberately, section by section, mentally noting the functions and their likely roles:

* **`CompactAndSweep()`:** This is clearly about garbage collection. The name suggests two main phases: compacting the heap and then sweeping away unused memory. The presence of `ExecutePreFinalizers()` hints at a process for running finalization logic before the main GC. The `#if CPPGC_VERIFY_HEAP` section indicates a debug/verification step. The `ResetRememberedSet()` sections suggest handling of inter-generational or cross-heap references. The use of `cppgc::subtle::NoGarbageCollectionScope` shows parts of the process where GC is explicitly disabled. The interaction with `compactor_` and `sweeper()` is central.

* **`AllocatedObjectSizeIncreased()` and `AllocatedObjectSizeDecreased()`:** These functions manage tracking changes in allocated memory. The `buffered_allocated_bytes_` variable suggests a mechanism to batch updates before reporting them to the main V8 heap.

* **`ReportBufferedAllocationSizeIfPossible()`:** This function handles the actual reporting of memory changes to V8. The check `if (!IsGCAllowed())` is important for avoiding re-entrant GC issues. The logic with `allocated_size_limit_for_check_` suggests triggering incremental marking based on allocation thresholds.

* **`CollectGarbageForTesting()`:**  This function provides a way to manually trigger garbage collection, primarily for testing purposes. It handles both attached (with a V8 isolate) and detached scenarios. The logic within the detached case outlines the steps of a full GC cycle (marking, final pause, sweeping).

* **`EnableDetachedGarbageCollectionsForTesting()`:**  Another testing-related function to enable specific GC scenarios without a full V8 isolate.

* **`StartIncrementalGarbageCollectionForTesting()` and `FinalizeIncrementalGarbageCollectionForTesting()`:** These clearly control the incremental garbage collection process in testing.

* **`CollectCustomSpaceStatisticsAtLastGC()` and related helper functions:** This section deals with collecting statistics for custom memory spaces, likely for debugging or performance analysis. The use of `v8::Task` suggests asynchronous execution.

* **`GetMetricRecorder()`:**  A simple accessor for a metric recorder.

* **`FinishSweepingIfRunning()` and `FinishAtomicSweepingIfRunning()`:** Functions to ensure sweeping is completed, with some conditional logic related to memory reduction and atomic sweeping.

* **`FinishSweepingIfOutOfWork()`:** Another sweeping-related function.

* **`CreateCppMarkingState()` and `CreateCppMarkingStateForMutatorThread()`:** These functions create state objects needed for the marking phase of garbage collection. The distinction between mutator thread and general marking suggests different contexts for marking.

* **`PauseConcurrentMarkingScope`:**  A utility class to temporarily pause concurrent marking.

* **`CollectGarbage(cppgc::internal::GCConfig)`:**  This function integrates with V8's main garbage collection mechanism, allowing CppGC to trigger a full GC.

* **`overridden_stack_state()`, `set_override_stack_state()`, `clear_overridden_stack_state()`:** These functions allow overriding the stack state used during GC, potentially for testing or specific scenarios.

* **`StartIncrementalGarbageCollection(cppgc::internal::GCConfig)` and `epoch()`:** Marked as `UNIMPLEMENTED()`, indicating these features aren't fully realized in this code.

* **`UpdateAllocationTimeout()`:**  Related to triggering GC based on allocation timeouts, likely for testing or simulation.

* **`ResetCrossHeapRememberedSet()`:**  Handles resetting the cross-heap remembered set, relevant for generational GC.

* **`UpdateGCCapabilitiesFromFlagsForTesting()`:** Another testing-related function to adjust GC capabilities.

* **`IsDetachedGCAllowed()`, `IsGCAllowed()`, `IsGCForbidden()`, `IsCurrentThread()`:**  These functions provide checks for the current GC state and thread context.

**4. Identifying JavaScript Relevance:**

The presence of `isolate_`, interaction with `v8::Isolate` and `v8::Heap`, and the overall context of memory management strongly indicate a connection to JavaScript. The examples of object creation and potential memory leaks are standard JavaScript concepts that CppGC helps manage.

**5. Developing Examples and Logic/Error Scenarios:**

Based on the function names and their purpose, I formulated simple JavaScript examples to illustrate how the C++ code's actions would impact JavaScript execution. The memory leak example highlights a common programming error that GC is designed to address. The incremental marking example demonstrates the gradual nature of that GC strategy.

**6. Structuring the Summary:**

Finally, I organized the findings into the requested format:

* **Functionality Summary:** A high-level overview of the code's purpose.
* **Torque Check:** Explicitly stated that it's not a Torque file.
* **JavaScript Relationship:** Explained the connection and provided illustrative JavaScript examples.
* **Logic Inference:**  Used the `ReportBufferedAllocationSizeIfPossible()` function to demonstrate how the code reacts to different inputs (positive and negative byte changes).
* **Common Programming Errors:** Provided the memory leak example.
* **Overall Functionality (Part 2):** Summarized the key actions in this specific snippet, focusing on the GC cycle, allocation tracking, and testing utilities.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on individual function details. I then shifted to grouping related functionalities to create a more cohesive summary.
* I ensured the JavaScript examples were simple and directly related to the C++ code's actions.
* I double-checked the request to ensure all aspects were addressed (Torque, JavaScript, logic, errors, part 2 summary).

This systematic approach, combining high-level understanding with detailed analysis and relevant examples, allows for a comprehensive and accurate summary of the given C++ code snippet.
好的，我们来归纳一下 `v8/src/heap/cppgc-js/cpp-heap.cc` 这部分代码的功能。

**功能归纳（第 2 部分）：**

这部分 `CppHeap` 类的代码主要集中在以下几个核心功能：

1. **完成垃圾回收的各个阶段：**
   - **压缩与清理 (`CompactAndSweep`)**:  这是垃圾回收的关键步骤，负责整理堆内存（压缩）并释放不再使用的对象（清理）。它涉及以下子步骤：
     - **执行预终结器 (`ExecutePreFinalizers`)**:  在真正清理内存之前，运行一些预先定义的清理逻辑。
     - **堆验证 (`UnifiedHeapMarkingVerifier`)**:  在 `#if CPPGC_VERIFY_HEAP` 条件下，执行堆的标记验证，确保垃圾回收的正确性。
     - **重置记忆集 (`ResetRememberedSet`, `ResetCrossHeapRememberedSet`)**:  对于支持分代垃圾回收的场景，重置用于记录跨代或跨堆引用的记忆集。
     - **执行压缩 (`compactor_.CompactSpacesIfEnabled()`)**: 如果启用了堆压缩，则执行压缩操作。
     - **启动清理 (`sweeper().Start()`)**:  根据配置（例如是否需要减少内存占用）启动清理器。

2. **管理对象大小变化并触发增量标记：**
   - **记录分配大小变化 (`AllocatedObjectSizeIncreased`, `AllocatedObjectSizeDecreased`)**:  当 CppGC 管理的对象大小发生变化时，记录这些变化。
   - **缓冲分配大小 (`buffered_allocated_bytes_`)**:  缓冲这些变化，避免频繁地向 V8 报告。
   - **报告缓冲的分配大小 (`ReportBufferedAllocationSizeIfPossible`)**:  在合适的时机（允许垃圾回收时）将缓冲的分配大小变化报告给 V8。这可能会触发 V8 的垃圾回收机制，特别是增量标记。
   - **触发增量标记**: 当分配的大小超过预设的限制 (`allocated_size_limit_for_check_`) 时，会尝试启动 V8 的增量标记。

3. **提供测试用的垃圾回收机制：**
   - **强制垃圾回收 (`CollectGarbageForTesting`)**: 提供一个用于测试的接口，可以强制执行特定类型的垃圾回收（Major 或 Minor），并指定堆栈状态。它可以模拟在附加到 V8 的情况下进行 GC，也可以在分离的情况下进行（模拟完整的原子 GC 过程）。
   - **启用分离的垃圾回收测试 (`EnableDetachedGarbageCollectionsForTesting`)**:  允许在没有 V8 `Isolate` 的情况下进行垃圾回收测试。
   - **启动和完成增量垃圾回收测试 (`StartIncrementalGarbageCollectionForTesting`, `FinalizeIncrementalGarbageCollectionForTesting`)**: 提供用于测试增量垃圾回收的接口。

4. **收集自定义内存空间的统计信息：**
   - **`CollectCustomSpaceStatisticsAtLastGC` 和相关的辅助函数**:  允许收集上次垃圾回收后自定义内存空间的使用统计信息。这通常用于调试和性能分析。它支持异步收集，如果清理正在进行，则会延迟执行。

5. **管理清理过程：**
   - **`FinishSweepingIfRunning` 和 `FinishAtomicSweepingIfRunning`**:  确保清理过程完成，尤其是在需要减少内存占用或进行原子清理时。
   - **`FinishSweepingIfOutOfWork`**:  在清理器完成当前工作后，确保其最终完成。

6. **创建标记状态：**
   - **`CreateCppMarkingState` 和 `CreateCppMarkingStateForMutatorThread`**:  创建用于垃圾回收标记阶段的状态对象。区分了 mutator 线程和通用标记的状态。

7. **暂停并发标记：**
   - **`PauseConcurrentMarkingScope`**: 提供一个作用域，用于临时暂停并发标记过程。

8. **与 V8 的垃圾回收集成：**
   - **`CollectGarbage(cppgc::internal::GCConfig)`**:  允许 CppGC 通过 V8 的接口触发 V8 的垃圾回收。

9. **覆盖堆栈状态：**
   - **`overridden_stack_state`, `set_override_stack_state`, `clear_overridden_stack_state`**:  允许在特定情况下覆盖垃圾回收时使用的堆栈状态，主要用于测试或特殊场景。

10. **处理分配超时（如果启用）：**
    - **`UpdateAllocationTimeout`**:  如果启用了分配超时功能（`V8_ENABLE_ALLOCATION_TIMEOUT`），并且设置了随机 GC 间隔，则会更新分配超时时间。

11. **重置跨堆记忆集：**
    - **`ResetCrossHeapRememberedSet`**:  用于重置跨堆记忆集，这对于分代垃圾回收非常重要。

12. **测试相关的辅助函数：**
    - **`UpdateGCCapabilitiesFromFlagsForTesting`**:  允许在测试中根据标志更新 GC 的能力。
    - **`IsDetachedGCAllowed`, `IsGCAllowed`, `IsGCForbidden`, `IsCurrentThread`**: 提供用于检查 GC 状态和线程上下文的辅助函数。

**如果 `v8/src/heap/cppgc-js/cpp-heap.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种用于编写 V8 内部函数的领域特定语言，旨在提高性能和安全性。

**与 JavaScript 的功能关系及示例：**

`cpp-heap.cc` 中实现的功能直接影响 JavaScript 的内存管理和垃圾回收。以下是一些与 JavaScript 相关的示例：

```javascript
// JavaScript 代码示例

// 1. 创建对象，CppHeap 会跟踪这些对象的分配
let myObject = {};
let myString = "hello";
let myArray = [1, 2, 3];

// 2. 当对象不再被引用时，CppHeap 的垃圾回收机制会回收它们占用的内存
myObject = null;
myString = null;
myArray = null;

// 3. CppHeap 的增量标记会逐渐回收不再使用的内存，不会阻塞主线程太久
// (在 JavaScript 中，这通常是透明的，开发者不需要显式调用)

// 4. 如果出现内存泄漏（对象不再使用但仍然被引用），CppHeap 的垃圾回收可能无法回收这部分内存
let leakedObject = {};
globalThis.leakedReference = leakedObject; // 意外地将对象保存在全局作用域
// ... 即使 leakedObject 不再使用，由于 globalThis.leakedReference 的存在，
//     CppHeap 也无法回收它，导致内存泄漏。

// 5. CppHeap 还会处理 V8 堆之外的 C++ 对象的生命周期。
//     例如，当 JavaScript 调用某些 Native 代码创建 C++ 对象时，
//     CppHeap 可以管理这些 C++ 对象的回收。
```

**代码逻辑推理示例：**

**假设输入：**

1. `buffered_allocated_bytes_` 的当前值为 100。
2. 调用 `AllocatedObjectSizeIncreased(50)`。
3. 垃圾回收当前是允许的 (`IsGCAllowed()` 返回 true)。

**输出：**

1. `buffered_allocated_bytes_` 的值变为 150。
2. 在后续某个时间点，当 `ReportBufferedAllocationSizeIfPossible` 被调用时，`used_size_` 会增加 150，`allocated_size_` 也会增加 150。
3. 如果 `allocated_size_` 超过了 `allocated_size_limit_for_check_`，并且启用了增量标记，则可能会触发 V8 的增量标记。

**用户常见的编程错误示例：**

1. **内存泄漏：**  JavaScript 开发者可能会意外地持有不再需要的对象的引用，导致垃圾回收器无法回收这些对象占用的内存。

    ```javascript
    function createLeakyClosure() {
      let largeData = new Array(1000000).fill(0);
      return function() {
        console.log(largeData.length); // 闭包意外地引用了 largeData
      };
    }

    let leak = createLeakyClosure();
    // 即使不再需要 leak，由于 leak 仍然持有对 largeData 的引用，
    // largeData 占用的内存无法被回收。
    ```

2. **循环引用：**  当两个或多个对象相互引用，形成一个环状结构，但这些对象不再被程序其他部分引用时，垃圾回收器可能无法立即回收它们（尽管现代的 V8 垃圾回收器可以处理这种情况）。

    ```javascript
    let objA = {};
    let objB = {};
    objA.ref = objB;
    objB.ref = objA;

    // objA 和 objB 形成循环引用，但程序可能已经不再需要它们
    // 如果没有其他引用指向 objA 或 objB，V8 的垃圾回收器最终会回收它们。
    ```

希望这个归纳能够帮助你理解 `v8/src/heap/cppgc-js/cpp-heap.cc` 这部分代码的功能。

### 提示词
```
这是目录为v8/src/heap/cppgc-js/cpp-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc-js/cpp-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
increased memory is reported. This allows for
    // setting limits close to actual heap sizes.
    allocated_size_limit_for_check_ = 0;

    RecordEmbedderMarkingSpeed(isolate_->heap()->tracer(),
                               stats_collector_->marking_time(), used_size_);
  }
}

void CppHeap::CompactAndSweep() {
  if (!TracingInitialized()) {
    return;
  }

  // The allocated bytes counter in v8 was reset to the current marked bytes, so
  // any pending allocated bytes updates should be discarded.
  buffered_allocated_bytes_ = 0;
  const size_t bytes_allocated_in_prefinalizers = ExecutePreFinalizers();
#if CPPGC_VERIFY_HEAP
  UnifiedHeapMarkingVerifier verifier(*this, *collection_type_);
  verifier.Run(stack_state_of_prev_gc(),
               stats_collector()->marked_bytes_on_current_cycle() +
                   bytes_allocated_in_prefinalizers);
#endif  // CPPGC_VERIFY_HEAP
  USE(bytes_allocated_in_prefinalizers);

#if defined(CPPGC_YOUNG_GENERATION)
  ResetRememberedSet();
  // We can reset the remembered set on each GC because surviving Oilpan objects
  // are immediately considered old.
  ResetCrossHeapRememberedSet();
#endif  // defined(CPPGC_YOUNG_GENERATION)

  {
    cppgc::subtle::NoGarbageCollectionScope no_gc(*this);
    cppgc::internal::SweepingConfig::CompactableSpaceHandling
        compactable_space_handling;
    {
      std::optional<SweepingOnMutatorThreadForGlobalHandlesScope>
          global_handles_scope;
      if (isolate_) {
        global_handles_scope.emplace(*isolate_->traced_handles());
      }
      compactable_space_handling = compactor_.CompactSpacesIfEnabled();
    }
    const cppgc::internal::SweepingConfig sweeping_config{
        SelectSweepingType(), compactable_space_handling,
        ShouldReduceMemory(current_gc_flags_)
            ? cppgc::internal::SweepingConfig::FreeMemoryHandling::
                  kDiscardWherePossible
            : cppgc::internal::SweepingConfig::FreeMemoryHandling::
                  kDoNotDiscard};
    DCHECK_IMPLIES(!isolate_,
                   SweepingType::kAtomic == sweeping_config.sweeping_type);
    sweeper().Start(sweeping_config);
  }

  in_atomic_pause_ = false;
  collection_type_.reset();
}

void CppHeap::AllocatedObjectSizeIncreased(size_t bytes) {
  buffered_allocated_bytes_ += static_cast<int64_t>(bytes);
  ReportBufferedAllocationSizeIfPossible();
}

void CppHeap::AllocatedObjectSizeDecreased(size_t bytes) {
  buffered_allocated_bytes_ -= static_cast<int64_t>(bytes);
  ReportBufferedAllocationSizeIfPossible();
}

void CppHeap::ReportBufferedAllocationSizeIfPossible() {
  // Reporting memory to V8 may trigger GC.
  if (!IsGCAllowed()) {
    return;
  }

  // We are in attached state.
  DCHECK_NOT_NULL(isolate_);

  // The calls below may trigger full GCs that are synchronous and also execute
  // epilogue callbacks. Since such callbacks may allocate, the counter must
  // already be zeroed by that time.
  const int64_t bytes_to_report = buffered_allocated_bytes_;
  buffered_allocated_bytes_ = 0;

  if (bytes_to_report < 0) {
    DCHECK_GE(used_size_.load(std::memory_order_relaxed), bytes_to_report);
    used_size_.fetch_sub(static_cast<size_t>(-bytes_to_report),
                         std::memory_order_relaxed);
  } else {
    used_size_.fetch_add(static_cast<size_t>(bytes_to_report),
                         std::memory_order_relaxed);
    allocated_size_ += bytes_to_report;

    if (v8_flags.incremental_marking) {
      if (allocated_size_ > allocated_size_limit_for_check_) {
        Heap* heap = isolate_->heap();
        heap->StartIncrementalMarkingIfAllocationLimitIsReached(
            heap->main_thread_local_heap(),
            heap->GCFlagsForIncrementalMarking(),
            kGCCallbackScheduleIdleGarbageCollection);
        if (heap->incremental_marking()->IsMajorMarking()) {
          if (heap->AllocationLimitOvershotByLargeMargin()) {
            heap->FinalizeIncrementalMarkingAtomically(
                i::GarbageCollectionReason::kExternalFinalize);
          } else {
            heap->incremental_marking()->AdvanceOnAllocation();
          }
        }
        allocated_size_limit_for_check_ =
            allocated_size_ + kIncrementalMarkingCheckInterval;
      }
    }
  }
}

void CppHeap::CollectGarbageForTesting(CollectionType collection_type,
                                       StackState stack_state) {
  if (!IsDetachedGCAllowed()) {
    return;
  }

  // Finish sweeping in case it is still running.
  sweeper().FinishIfRunning();

  if (isolate_) {
    reinterpret_cast<v8::Isolate*>(isolate_)
        ->RequestGarbageCollectionForTesting(
            v8::Isolate::kFullGarbageCollection, stack_state);
    return;
  }

  stack()->SetMarkerIfNeededAndCallback([this, collection_type, stack_state]() {
    // Perform an atomic GC, with starting incremental/concurrent marking and
    // immediately finalizing the garbage collection.
    if (!IsMarking()) {
      InitializeMarking(collection_type, GarbageCollectionFlagValues::kForced);
      StartMarking();
    }
    EnterFinalPause(stack_state);
    EnterProcessGlobalAtomicPause();
    CHECK(AdvanceTracing(v8::base::TimeDelta::Max()));
    if (FinishConcurrentMarkingIfNeeded()) {
      CHECK(AdvanceTracing(v8::base::TimeDelta::Max()));
    }
    FinishMarkingAndProcessWeakness();
    CompactAndSweep();
    FinishAtomicSweepingIfRunning();
  });
}

void CppHeap::EnableDetachedGarbageCollectionsForTesting() {
  CHECK(!in_detached_testing_mode_);
  CHECK_NULL(isolate_);
  no_gc_scope_--;
  in_detached_testing_mode_ = true;
  static_cast<CppgcPlatformAdapter*>(platform())
      ->EnableDetachedModeForTesting();
}

void CppHeap::StartIncrementalGarbageCollectionForTesting() {
  DCHECK(!in_no_gc_scope());
  DCHECK_NULL(isolate_);
  if (IsMarking()) return;
  force_incremental_marking_for_testing_ = true;
  InitializeMarking(CollectionType::kMajor,
                    GarbageCollectionFlagValues::kForced);
  StartMarking();
  force_incremental_marking_for_testing_ = false;
}

void CppHeap::FinalizeIncrementalGarbageCollectionForTesting(
    cppgc::EmbedderStackState stack_state) {
  DCHECK(!in_no_gc_scope());
  DCHECK_NULL(isolate_);
  DCHECK(IsMarking());
  if (IsMarking()) {
    CollectGarbageForTesting(CollectionType::kMajor, stack_state);
  }
  sweeper_.FinishIfRunning();
}

namespace {

void ReportCustomSpaceStatistics(
    cppgc::internal::RawHeap& raw_heap,
    std::vector<cppgc::CustomSpaceIndex> custom_spaces,
    std::unique_ptr<CustomSpaceStatisticsReceiver> receiver) {
  for (auto custom_space_index : custom_spaces) {
    const cppgc::internal::BaseSpace* space =
        raw_heap.CustomSpace(custom_space_index);
    size_t allocated_bytes = std::accumulate(
        space->begin(), space->end(), 0, [](size_t sum, auto* page) {
          return sum + page->AllocatedBytesAtLastGC();
        });
    receiver->AllocatedBytes(custom_space_index, allocated_bytes);
  }
}

class CollectCustomSpaceStatisticsAtLastGCTask final : public v8::Task {
 public:
  static constexpr v8::base::TimeDelta kTaskDelayMs =
      v8::base::TimeDelta::FromMilliseconds(10);

  CollectCustomSpaceStatisticsAtLastGCTask(
      cppgc::internal::HeapBase& heap,
      std::vector<cppgc::CustomSpaceIndex> custom_spaces,
      std::unique_ptr<CustomSpaceStatisticsReceiver> receiver)
      : heap_(heap),
        custom_spaces_(std::move(custom_spaces)),
        receiver_(std::move(receiver)) {}

  void Run() final {
    cppgc::internal::Sweeper& sweeper = heap_.sweeper();
    if (sweeper.PerformSweepOnMutatorThread(
            kStepSizeMs,
            cppgc::internal::StatsCollector::kSweepInTaskForStatistics)) {
      // Sweeping is done.
      DCHECK(!sweeper.IsSweepingInProgress());
      ReportCustomSpaceStatistics(heap_.raw_heap(), std::move(custom_spaces_),
                                  std::move(receiver_));
    } else {
      heap_.platform()->GetForegroundTaskRunner()->PostDelayedTask(
          std::make_unique<CollectCustomSpaceStatisticsAtLastGCTask>(
              heap_, std::move(custom_spaces_), std::move(receiver_)),
          kTaskDelayMs.InSecondsF());
    }
  }

 private:
  static constexpr v8::base::TimeDelta kStepSizeMs =
      v8::base::TimeDelta::FromMilliseconds(5);

  cppgc::internal::HeapBase& heap_;
  std::vector<cppgc::CustomSpaceIndex> custom_spaces_;
  std::unique_ptr<CustomSpaceStatisticsReceiver> receiver_;
};

constexpr v8::base::TimeDelta
    CollectCustomSpaceStatisticsAtLastGCTask::kTaskDelayMs;
constexpr v8::base::TimeDelta
    CollectCustomSpaceStatisticsAtLastGCTask::kStepSizeMs;

}  // namespace

void CppHeap::CollectCustomSpaceStatisticsAtLastGC(
    std::vector<cppgc::CustomSpaceIndex> custom_spaces,
    std::unique_ptr<CustomSpaceStatisticsReceiver> receiver) {
  if (sweeper().IsSweepingInProgress()) {
    platform()->GetForegroundTaskRunner()->PostDelayedTask(
        std::make_unique<CollectCustomSpaceStatisticsAtLastGCTask>(
            AsBase(), std::move(custom_spaces), std::move(receiver)),
        CollectCustomSpaceStatisticsAtLastGCTask::kTaskDelayMs.InSecondsF());
    return;
  }
  ReportCustomSpaceStatistics(raw_heap(), std::move(custom_spaces),
                              std::move(receiver));
}

CppHeap::MetricRecorderAdapter* CppHeap::GetMetricRecorder() const {
  return static_cast<MetricRecorderAdapter*>(
      stats_collector_->GetMetricRecorder());
}

void CppHeap::FinishSweepingIfRunning() {
  sweeper_.FinishIfRunning();
  if (isolate_ && ShouldReduceMemory(current_gc_flags_)) {
    isolate_->traced_handles()->DeleteEmptyBlocks();
  }
}

void CppHeap::FinishAtomicSweepingIfRunning() {
  // Young generation GCs are optional and as such sweeping is not necessarily
  // running.
  if (sweeper_.IsSweepingInProgress() &&
      SelectSweepingType() == SweepingType::kAtomic) {
    FinishSweepingIfRunning();
  }
}

void CppHeap::FinishSweepingIfOutOfWork() { sweeper_.FinishIfOutOfWork(); }

std::unique_ptr<CppMarkingState> CppHeap::CreateCppMarkingState() {
  if (!TracingInitialized()) return {};
  DCHECK(IsMarking());
  return std::make_unique<CppMarkingState>(
      std::make_unique<cppgc::internal::MarkingStateBase>(
          AsBase(), marker()->To<UnifiedHeapMarker>().GetMarkingWorklists()));
}

std::unique_ptr<CppMarkingState>
CppHeap::CreateCppMarkingStateForMutatorThread() {
  if (!TracingInitialized()) return {};
  DCHECK(IsMarking());
  return std::make_unique<CppMarkingState>(
      marker()->To<UnifiedHeapMarker>().GetMutatorMarkingState());
}

CppHeap::PauseConcurrentMarkingScope::PauseConcurrentMarkingScope(
    CppHeap* cpp_heap) {
  if (cpp_heap && cpp_heap->marker()) {
    pause_scope_.emplace(*cpp_heap->marker());
  }
}

void CppHeap::CollectGarbage(cppgc::internal::GCConfig config) {
  if (!IsGCAllowed()) {
    return;
  }
  // TODO(mlippautz): Respect full config.
  const auto flags =
      (config.free_memory_handling ==
       cppgc::internal::GCConfig::FreeMemoryHandling::kDiscardWherePossible)
          ? GCFlag::kReduceMemoryFootprint
          : GCFlag::kNoFlags;
  isolate_->heap()->CollectAllGarbage(
      flags, GarbageCollectionReason::kCppHeapAllocationFailure);
  DCHECK_IMPLIES(
      config.sweeping_type == cppgc::internal::GCConfig::SweepingType::kAtomic,
      !sweeper_.IsSweepingInProgress());
}

std::optional<cppgc::EmbedderStackState> CppHeap::overridden_stack_state()
    const {
  return heap_ ? heap_->overridden_stack_state()
               : detached_override_stack_state_;
}

void CppHeap::set_override_stack_state(cppgc::EmbedderStackState state) {
  CHECK(!detached_override_stack_state_);
  CHECK(!override_stack_state_scope_);
  if (heap_) {
    override_stack_state_scope_ = std::make_unique<EmbedderStackStateScope>(
        heap_, EmbedderStackStateOrigin::kExplicitInvocation, state);
  } else {
    detached_override_stack_state_ = state;
  }
}

void CppHeap::clear_overridden_stack_state() {
  if (heap_) {
    CHECK(!detached_override_stack_state_);
    CHECK(override_stack_state_scope_);
    override_stack_state_scope_.reset();
  } else {
    CHECK(detached_override_stack_state_);
    CHECK(!override_stack_state_scope_);
    detached_override_stack_state_.reset();
  }
}

void CppHeap::StartIncrementalGarbageCollection(cppgc::internal::GCConfig) {
  UNIMPLEMENTED();
}

size_t CppHeap::epoch() const { UNIMPLEMENTED(); }

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
std::optional<int> CppHeap::UpdateAllocationTimeout() {
  if (!v8_flags.cppgc_random_gc_interval) {
    return std::nullopt;
  }
  if (!allocation_timeout_rng_) {
    allocation_timeout_rng_.emplace(v8_flags.fuzzer_random_seed);
  }
  return allocation_timeout_rng_->NextInt(v8_flags.cppgc_random_gc_interval) +
         1;
}
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

void CppHeap::ResetCrossHeapRememberedSet() {
  if (!generational_gc_supported()) {
    DCHECK(cross_heap_remembered_set_.IsEmpty());
    return;
  }
  DCHECK(isolate_);
  cross_heap_remembered_set_.Reset(*isolate_);
}

void CppHeap::UpdateGCCapabilitiesFromFlagsForTesting() {
  UpdateGCCapabilitiesFromFlags();
}

bool CppHeap::IsDetachedGCAllowed() const {
  return (isolate_ || in_detached_testing_mode_) && HeapBase::IsGCAllowed();
}

bool CppHeap::IsGCAllowed() const {
  return isolate_ && HeapBase::IsGCAllowed();
}

bool CppHeap::IsGCForbidden() const {
  return (isolate_ && isolate_->InFastCCall() &&
          !v8_flags.allow_allocation_in_fast_api_call) ||
         HeapBase::IsGCForbidden();
}

bool CppHeap::IsCurrentThread(int thread_id) const {
  if (isolate_ && V8_UNLIKELY(isolate_->was_locker_ever_used())) {
    // If v8::Locker has been used, we only check if the isolate is now locked
    // by the current thread.
    return isolate_->thread_manager()->IsLockedByCurrentThread();
  }
  return HeapBase::IsCurrentThread(thread_id);
}

}  // namespace internal
}  // namespace v8
```