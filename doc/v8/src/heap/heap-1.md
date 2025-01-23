Response: The user wants me to summarize the functionality of a C++ source code file related to V8's heap management. This is the second part of a five-part file. I need to focus on the code provided in this snippet. If the functionality is related to Javascript, I should provide a Javascript example.

Looking at the code, it seems to be focused on:

1. **Garbage Collection Epilogue and Related Actions:**  The `GarbageCollectionEpilogue` function handles tasks after a garbage collection cycle completes, including:
    *   Notifying memory reducers.
    *   Adjusting old generation size based on usage.
    *   Stopping tracing of pauses.
    *   Triggering callbacks.
    *   Potentially initiating incremental marking for the next cycle.
    *   Handling out-of-memory scenarios.
2. **Idle Time Garbage Collection:** The `IdleTaskOnContextDispose` class manages garbage collection during idle time, specifically when a context is disposed. It attempts to run a minor GC if there's enough idle time.
3. **Context Disposal Notifications:** The `NotifyContextDisposed` function handles actions when a Javascript context is disposed, including triggering idle GCs and resetting allocation limits.
4. **Starting Incremental Marking:** The `StartIncrementalMarking` function initiates incremental garbage collection.
5. **Completing Sweeping:** The `CompleteSweepingFull` and `CompleteSweepingYoung` functions ensure that the sweeping phase of garbage collection is finished.
6. **Managing Allocation Limits and Requesting GC:** Functions like `StartIncrementalMarkingIfAllocationLimitIsReached` and `CollectionRequested` deal with managing memory pressure and triggering garbage collection when limits are reached.
7. **Moving Memory Ranges:** The `MoveRange` and `CopyRange` functions handle moving blocks of memory, potentially with write barriers.
8. **Collecting Garbage in Background:** The `CollectGarbageForBackground` function explicitly triggers a full garbage collection.
9. **Updating Survival Statistics:** The `UpdateSurvivalStatistics` function tracks how many objects survive garbage collection.
10. **Performing Garbage Collection:** The `PerformGarbageCollection` function orchestrates the different types of garbage collection (Mark-Compact, Minor Mark-Sweep, Scavenge).
11. **Heap Verification:** The `PerformHeapVerification` function checks the integrity of the heap.
12. **Pausing and Resuming Concurrent Threads:** Functions `PauseConcurrentThreadsInClients` and `ResumeConcurrentThreadsInClients` manage concurrent garbage collection activities.
13. **Collecting Garbage from Different Threads:** The `CollectGarbageShared` and `CollectGarbageFromAnyThread` functions allow triggering garbage collection from various threads.
14. **Managing External Strings:** The `ExternalStringTable` class and related methods handle external strings (strings whose content is not directly stored in the V8 heap).
15. **Processing Weak References:** Functions like `ProcessNativeContexts` and `ProcessAllocationSites` handle weak references, which are crucial for garbage collection.
16. **Handling Allocation Sites:** The `ForeachAllocationSite` and `ResetAllAllocationSitesDependentCode` functions manage information about where objects are allocated.
17. **Evaluating Old Space Pretenuring:** The `EvaluateOldSpaceLocalPretenuring` function is related to optimizing object allocation by predicting whether objects should be placed in the old generation directly.
18. **Visiting External Resources:** The `VisitExternalResources` function allows external tools to inspect resources managed by the heap.
19. **Memory Alignment and Fillers:** Several functions deal with aligning objects in memory and creating filler objects to occupy unused space.
20. **External Backing Store Allocation:** The `AllocateExternalBackingStore` function handles allocating memory outside the V8 heap.
21. **Flushing the Number String Cache:** The `FlushNumberStringCache` clears a cache of number-to-string conversions.
22. **Moving Objects in Memory:** The `OnMoveEvent` and `LeftTrimFixedArray` functions deal with moving objects and parts of objects within the heap.
23. **Checking Object Immutability and Size:** The `CanMoveObjectStart`, `IsImmovable`, and `IsLargeObject` functions check properties of heap objects.

Many of these functionalities directly impact how Javascript code interacts with memory and garbage collection.

For example, the **idle time garbage collection** feature tries to optimize performance by cleaning up memory when the browser or Node.js process is not busy. This reduces the impact of garbage collection pauses on the user experience.

The **context disposal notifications** are important because when a Javascript context (like a web page's environment) is no longer needed, V8 needs to clean up the memory associated with it.

The **external string handling** is relevant when Javascript code interacts with data outside the V8 heap, for example, when reading files or fetching data from the network.

**Example of Javascript related to garbage collection:**

```javascript
// This example demonstrates how garbage collection works implicitly
// and how external resources can be managed.

// Create an object that holds a reference to a large external resource (like a file handle).
let externalDataHolder = {
  data: new ArrayBuffer(1024 * 1024 * 100), // 100MB buffer
  cleanup: function() {
    console.log("Cleaning up external data");
    this.data = null; // Release the reference to the buffer
    // In a real scenario, you might close a file handle or release other resources here.
  }
};

// Assign the object to a global variable.
globalThis.myExternalData = externalDataHolder;

// Later, when the object is no longer needed, remove the global reference.
globalThis.myExternalData = null;

// The garbage collector will eventually reclaim the memory used by externalDataHolder
// when it's no longer reachable. The 'cleanup' function is a manual way to
// manage external resources associated with the object.

// V8 also provides APIs for triggering garbage collection (though generally not recommended):
// if (global.gc) {
//   global.gc();
// }
```

This Javascript example highlights how the V8 garbage collector implicitly manages memory. The C++ code in this file is part of the underlying mechanism that makes this possible. The `ExternalStringTable` functionality in the C++ code would be relevant if the `ArrayBuffer` in the Javascript example was backed by external memory. The `NotifyContextDisposed` would be called when the scope containing `externalDataHolder` is no longer active.

这是 `v8/src/heap/heap.cc` 源代码文件的第二部分，主要负责以下功能：

**1. 完成垃圾回收周期后的操作 (Garbage Collection Epilogue):**

*   **通知内存缩减器 (Memory Reducer Notification):**  如果配置了内存缩减器，会通知它 Mark-Compact 垃圾回收器的执行情况。
*   **调整老生代大小 (Old Generation Size Adjustment):**  如果老生代的对象大小低于某个阈值，并且还没有达到最大值，会将其大小设置为初始的最大值。
*   **停止追踪 (Stop Tracing):** 停止追踪原子暂停和可观察的暂停。
*   **触发回调 (Invoke Callbacks):**  执行垃圾回收周期的后续回调函数。
*   **启动增量标记 (Start Incremental Marking):**  对于新生代垃圾回收，会尝试启动下一次的增量标记。对于老生代垃圾回收，会报告是否需要进行低效的 Mark-Compact。
*   **执行外部回调 (Invoke External Callbacks):** 执行在 Heap 中注册的外部回调函数，以及全局句柄的垃圾回收后处理。
*   **触发快照 (Trigger Heap Snapshot):**  在满足特定条件（例如强制 GC 或达到指定 GC 次数）时，生成堆快照。
*   **处理内存不足 (Handle Out of Memory):**  如果垃圾回收后仍然无法扩展老生代，会触发近堆限制回调，并在极端情况下终止进程。

**2. 空闲时间任务处理 (Idle Task Handling):**

*   **`IdleTaskOnContextDispose` 类:**  定义了一个在上下文销毁时运行的空闲任务。
*   **尝试执行次要 GC (Try Run Minor GC):**  在空闲时间内，如果预估的次要 GC 时间小于剩余的空闲时间，并且新生代大小超过一定阈值，则会执行一次新生代垃圾回收。

**3. 上下文销毁通知 (Context Disposed Notification):**

*   **`NotifyContextDisposed` 函数:**  当一个 JavaScript 上下文被销毁时调用。
*   **重置生存事件和分配限制 (Reset Survival Events and Allocation Limit):**  对于顶层上下文的销毁，会重置生存事件和老生代的分配限制。
*   **触发空闲 GC (Trigger Idle GC):**  对于嵌套上下文的销毁，如果启用了 `idle_gc_on_context_disposal` 标志，并且不是单代模式，则会尝试发布一个空闲 GC 任务。
*   **取消并发优化 (Abort Concurrent Optimization):**  取消与该上下文相关的并发优化。
*   **清理 FinalizationRegistry (Remove Dirty Finalization Registries):**  清理与该上下文相关的待处理的 FinalizationRegistry。

**4. 启动增量标记 (Start Incremental Marking):**

*   **`StartIncrementalMarking` 函数:**  启动增量垃圾回收过程。
*   **完成 Sweeping (Complete Sweeping):**  在开始标记之前，需要完成之前的 Sweeping 阶段。
*   **暂停并发线程 (Pause Concurrent Threads):**  暂停其他客户端 Isolate 的并发线程。
*   **启动新的 GC 周期 (Start New GC Cycle):**  记录新的垃圾回收周期开始。

**5. 完成 Sweeping 阶段 (Complete Sweeping):**

*   **`CompleteSweepingFull` 函数:**  确保完整的 Sweeping 阶段完成。
*   **`CompleteSweepingYoung` 函数:**  确保新生代的 Sweeping 阶段完成，并处理 ArrayBuffer 的 Sweeping。

**6. 根据中断启动增量标记 (Start Incremental Marking on Interrupt):**

*   **`StartIncrementalMarkingOnInterrupt` 函数:**  在接收到中断信号时，如果达到分配限制，则启动增量标记。
*   **`StartIncrementalMarkingIfAllocationLimitIsReached` 函数:**  检查是否达到分配限制，并根据情况启动增量标记或通知内存缩减器。

**7. 移动和复制内存区域 (Move and Copy Memory Ranges):**

*   **`MoveRange` 和 `CopyRange` 函数:**  用于在堆内存中移动或复制指定长度的数据，并考虑写屏障。

**8. 后台垃圾回收 (Garbage Collection for Background):**

*   **`CollectGarbageForBackground` 函数:**  在后台执行完整的垃圾回收。
*   **`CheckCollectionRequested` 函数:**  检查是否请求了垃圾回收，如果请求了则执行。

**9. 更新生存统计信息 (Update Survival Statistics):**

*   **`UpdateSurvivalStatistics` 函数:**  计算并更新对象在垃圾回收后的存活率和晋升率等统计信息。

**10. 执行垃圾回收 (Perform Garbage Collection):**

*   **`PerformGarbageCollection` 函数:**  根据指定的垃圾回收器类型 (Mark-Compact, Minor Mark-Sweep, Scavenger) 执行相应的垃圾回收操作。
*   **执行 Heap 验证 (Perform Heap Verification):**  在垃圾回收前后进行堆的完整性验证。
*   **暂停/恢复并发线程 (Pause/Resume Concurrent Threads):**  在垃圾回收的原子暂停阶段暂停并发线程，并在结束后恢复。

**11. 共享堆的垃圾回收 (Garbage Collection for Shared Heap):**

*   **`CollectGarbageShared` 函数:**  用于在共享堆上触发垃圾回收。
*   **`CollectGarbageFromAnyThread` 函数:**  允许从任何线程触发垃圾回收。

**12. 外部 String 表 (External String Table):**

*   定义了 `ExternalStringTable` 类，用于管理内容存储在 V8 堆外部的字符串。
*   包含添加、删除、更新和遍历外部字符串的方法。
*   在垃圾回收过程中需要特殊处理，例如更新年轻代的引用或晋升到老年代。

**13. 处理弱引用 (Process Weak References):**

*   提供 `ProcessNativeContexts`, `ProcessAllocationSites`, `ProcessDirtyJSFinalizationRegistries` 等函数，用于遍历和处理各种类型的弱引用，这是垃圾回收的关键步骤。

**14. 处理 AllocationSite (Handle Allocation Sites):**

*   `ForeachAllocationSite` 函数用于遍历 AllocationSite 链表。
*   `ResetAllAllocationSitesDependentCode` 函数用于重置特定 AllocationType 的预分配决策。

**15. 评估老年代局部预分配 (Evaluate Old Space Local Pretenuring):**

*   `EvaluateOldSpaceLocalPretenuring` 函数用于根据老年代的存活率来调整预分配策略。

**16. 访问外部资源 (Visit External Resources):**

*   `VisitExternalResources` 函数允许外部访问者遍历堆中的外部资源，例如外部字符串。

**17. 内存对齐和填充 (Memory Alignment and Fillers):**

*   提供了 `GetMaximumFillToAlign`, `GetFillToAlign`, `PrecedeWithFiller`, `AlignWithFillerBackground` 等函数，用于在内存分配时进行对齐和填充操作。

**18. 外部 Backing Store 的分配 (Allocate External Backing Store):**

*   `AllocateExternalBackingStore` 函数用于分配 V8 堆外部的内存，并可能在分配前触发垃圾回收以释放内存压力。

**19. 收缩老年代分配限制 (Shrink Old Generation Allocation Limit):**

*   `ShrinkOldGenerationAllocationLimitIfNotConfigured` 函数用于在未配置老年代分配限制时，根据生存率动态调整限制。

**20. 清空数字字符串缓存 (Flush Number String Cache):**

*   `FlushNumberStringCache` 函数用于清空用于缓存数字到字符串转换结果的缓存。

**21. 创建填充对象 (Create Filler Object):**

*   `CreateFillerObjectAt` 和 `CreateFillerObjectAtBackground` 等函数用于在空闲内存区域创建填充对象，以便垃圾回收器识别和管理这些区域。

**22. 移动对象 (Move Object):**

*   `OnMoveEvent` 函数在对象移动时触发事件，用于性能分析和调试。
*   `LeftTrimFixedArray` 函数用于裁剪 `FixedArray` 的头部。
*   `CanMoveObjectStart` 和 `IsImmovable` 函数用于判断对象是否可以移动。
*   `IsLargeObject` 函数判断对象是否为大对象。

**与 JavaScript 的关系:**

这些 C++ 代码是 V8 引擎的核心部分，直接支撑着 JavaScript 的内存管理和垃圾回收机制。

*   **垃圾回收:**  JavaScript 的垃圾回收是自动进行的，开发者无需手动管理内存。这部分 C++ 代码实现了不同的垃圾回收算法 (Mark-Compact, Scavenger 等)，负责识别和回收不再使用的 JavaScript 对象。
*   **内存分配:**  当 JavaScript 代码创建对象、数组或字符串时，V8 引擎会调用底层的内存分配机制。这部分代码涉及到内存的组织、分配策略和限制。
*   **外部资源:**  当 JavaScript 代码与外部资源交互 (例如，`ArrayBuffer`，`File` 等) 时，V8 需要跟踪和管理这些资源。`ExternalStringTable` 就是一个例子，用于管理内容不在 V8 堆中的字符串。
*   **性能优化:**  空闲时间垃圾回收、增量标记、预分配等机制都是为了优化 JavaScript 的执行性能，减少垃圾回收造成的卡顿。

**JavaScript 示例:**

```javascript
// 当一个作用域结束时，其中的对象可能会被垃圾回收
function createObject() {
  let obj = { data: new Array(1000000) }; // 创建一个大对象
  return obj; // obj 在函数执行结束后仍然可访问，不会立即被回收
}

let myObject = createObject();
myObject = null; // 现在 createObject 中创建的对象变得不可访问，等待垃圾回收

// 外部资源示例
let buffer = new ArrayBuffer(1024 * 1024); // 创建一个 1MB 的外部 ArrayBuffer

// 当 buffer 不再被引用时，其占用的外部内存最终会被回收

// 手动触发垃圾回收 (通常不推荐，V8 会自动管理)
if (global.gc) {
  global.gc();
}
```

总而言之，这部分 C++ 代码是 V8 引擎中负责内存管理和垃圾回收的关键组成部分，它直接影响着 JavaScript 代码的执行效率和内存使用情况。

### 提示词
```
这是目录为v8/src/heap/heap.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```
arbageCollector::MARK_COMPACTOR) {
      if (memory_reducer_ != nullptr) {
        memory_reducer_->NotifyMarkCompact(committed_memory_before);
      }
      if (initial_max_old_generation_size_ < max_old_generation_size() &&
          OldGenerationSizeOfObjects() <
              initial_max_old_generation_size_threshold_) {
        SetOldGenerationAndGlobalMaximumSize(initial_max_old_generation_size_);
      }
    }

    tracer()->StopAtomicPause();
    tracer()->StopObservablePause(collector, base::TimeTicks::Now());
    // Young generation cycles finish atomically. It is important that
    // StopObservablePause, and StopCycle are called in this
    // order; the latter may replace the current event with that of an
    // interrupted full cycle.
    if (IsYoungGenerationCollector(collector)) {
      tracer()->StopYoungCycleIfNeeded();
    } else {
      tracer()->StopFullCycleIfNeeded();
      ReportIneffectiveMarkCompactIfNeeded();
    }
  });

  // Epilogue callbacks. These callbacks may trigger GC themselves and thus
  // cannot be related exactly to garbage collection cycles.
  //
  // GCTracer scopes are managed by callees.
  InvokeExternalCallbacks(isolate(), [this, gc_callback_flags, gc_type]() {
    // Epilogue callbacks registered with Heap.
    CallGCEpilogueCallbacks(gc_type, gc_callback_flags,
                            GCTracer::Scope::HEAP_EXTERNAL_EPILOGUE);

    isolate()->global_handles()->PostGarbageCollectionProcessing(
        gc_callback_flags);
  });

  if (collector == GarbageCollector::MARK_COMPACTOR) {
    if ((gc_callback_flags &
         (kGCCallbackFlagForced | kGCCallbackFlagCollectAllAvailableGarbage))) {
      isolate()->CountUsage(v8::Isolate::kForcedGC);
    }
    if (v8_flags.heap_snapshot_on_gc > 0 &&
        static_cast<size_t>(v8_flags.heap_snapshot_on_gc) == ms_count_) {
      isolate()->heap_profiler()->WriteSnapshotToDiskAfterGC();
    }
  } else {
    // Start incremental marking for the next cycle. We do this only for
    // minor GCs to avoid a loop where mark-compact causes another mark-compact.
    StartIncrementalMarkingIfAllocationLimitIsReached(
        main_thread_local_heap(), GCFlagsForIncrementalMarking(),
        kGCCallbackScheduleIdleGarbageCollection);
  }

  if (!CanExpandOldGeneration(0)) {
    InvokeNearHeapLimitCallback();
    if (!CanExpandOldGeneration(0)) {
      if (v8_flags.heap_snapshot_on_oom) {
        isolate()->heap_profiler()->WriteSnapshotToDiskAfterGC();
      }
      FatalProcessOutOfMemory("Reached heap limit");
    }
  }

  if (collector == GarbageCollector::MARK_COMPACTOR) {
    current_gc_flags_ = GCFlag::kNoFlags;
  }
}

class IdleTaskOnContextDispose : public CancelableIdleTask {
 public:
  static void TryPostJob(Heap* heap) {
    const auto runner = heap->GetForegroundTaskRunner();
    if (runner->IdleTasksEnabled()) {
      runner->PostIdleTask(
          std::make_unique<IdleTaskOnContextDispose>(heap->isolate()));
    }
  }

  explicit IdleTaskOnContextDispose(Isolate* isolate)
      : CancelableIdleTask(isolate), isolate_(isolate) {}

  void RunInternal(double deadline_in_seconds) override {
    auto* heap = isolate_->heap();
    const base::TimeDelta time_to_run = base::TimeTicks::Now() - creation_time_;
    // The provided delta uses embedder timestamps.
    const base::TimeDelta idle_time = base::TimeDelta::FromMillisecondsD(
        (deadline_in_seconds * 1000) - heap->MonotonicallyIncreasingTimeInMs());
    const bool time_to_run_exceeded = time_to_run > kMaxTimeToRun;
    if (V8_UNLIKELY(v8_flags.trace_context_disposal)) {
      isolate_->PrintWithTimestamp(
          "[context-disposal/idle task] time-to-run: %fms (max delay: %fms), "
          "idle time: %fms%s\n",
          time_to_run.InMillisecondsF(), kMaxTimeToRun.InMillisecondsF(),
          idle_time.InMillisecondsF(),
          time_to_run_exceeded ? ", not starting any action" : "");
    }
    if (time_to_run_exceeded) {
      return;
    }
    TryRunMinorGC(idle_time);
  }

 private:
  static constexpr base::TimeDelta kFrameTime =
      base::TimeDelta::FromMillisecondsD(16);

  // We limit any idle time actions here by a maximum time to run of a single
  // frame. This avoids that these tasks are executed too late and causes
  // (unpredictable) side effects with e.g. promotion of newly allocated
  // objects.
  static constexpr base::TimeDelta kMaxTimeToRun = kFrameTime + kFrameTime;

  void TryRunMinorGC(const base::TimeDelta idle_time) {
    // The following logic estimates whether a young generation GC would fit in
    // `idle_time.` We bail out for a young gen below 1MB to avoid executing GC
    // when the mutator is not actually active.
    static constexpr size_t kMinYounGenSize = 1 * MB;

    auto* heap = isolate_->heap();
    const double young_gen_gc_speed =
        heap->tracer()->YoungGenerationSpeedInBytesPerMillisecond(
            YoungGenerationSpeedMode::kUpToAndIncludingAtomicPause);
    const size_t young_gen_bytes = heap->YoungGenerationSizeOfObjects();
    const base::TimeDelta young_gen_estimate =
        base::TimeDelta::FromMillisecondsD(young_gen_bytes /
                                           young_gen_gc_speed);
    const bool run_young_gen_gc =
        young_gen_estimate < idle_time && young_gen_bytes > kMinYounGenSize;
    if (V8_UNLIKELY(v8_flags.trace_context_disposal)) {
      isolate_->PrintWithTimestamp(
          "[context-disposal/idle task] young generation size: %zuKB (min: "
          "%zuKB), GC speed: %fKB/ms, estimated time: %fms%s\n",
          young_gen_bytes / KB, kMinYounGenSize / KB, young_gen_gc_speed / KB,
          young_gen_estimate.InMillisecondsF(),
          run_young_gen_gc ? ", performing young gen GC"
                           : ", not starting young gen GC");
    }
    if (run_young_gen_gc) {
      heap->CollectGarbage(NEW_SPACE, GarbageCollectionReason::kTesting);
    }
  }

  Isolate* isolate_;
  const base::TimeTicks creation_time_ = base::TimeTicks::Now();
};

int Heap::NotifyContextDisposed(bool has_dependent_context) {
  if (V8_UNLIKELY(v8_flags.trace_context_disposal)) {
    isolate()->PrintWithTimestamp(
        "[context-disposal] Disposing %s context\n",
        has_dependent_context ? "nested" : "top-level");
  }
  if (!has_dependent_context) {
    tracer()->ResetSurvivalEvents();
    ResetOldGenerationAndGlobalAllocationLimit();
    if (memory_reducer_) {
      memory_reducer_->NotifyPossibleGarbage();
    }
  } else if (v8_flags.idle_gc_on_context_disposal &&
             !v8_flags.single_generation) {
    DCHECK_NOT_NULL(new_space());
    IdleTaskOnContextDispose::TryPostJob(this);
  }
  isolate()->AbortConcurrentOptimization(BlockingBehavior::kDontBlock);
  if (!isolate()->context().is_null()) {
    RemoveDirtyFinalizationRegistriesOnContext(isolate()->raw_native_context());
    isolate()->raw_native_context()->set_retained_maps(
        ReadOnlyRoots(this).empty_weak_array_list());
  }

  return ++contexts_disposed_;
}

void Heap::StartIncrementalMarking(GCFlags gc_flags,
                                   GarbageCollectionReason gc_reason,
                                   GCCallbackFlags gc_callback_flags,
                                   GarbageCollector collector) {
  DCHECK(incremental_marking()->IsStopped());
  CHECK_IMPLIES(!v8_flags.allow_allocation_in_fast_api_call,
                !isolate()->InFastCCall());

  if (v8_flags.separate_gc_phases && gc_callbacks_depth_ > 0) {
    // Do not start incremental marking while invoking GC callbacks.
    // Heap::CollectGarbage already decided which GC is going to be
    // invoked. In case it chose a young-gen GC, starting an incremental
    // full GC during callbacks would break the separate GC phases
    // guarantee.
    return;
  }

  if (IsYoungGenerationCollector(collector)) {
    CompleteSweepingYoung();
  } else {
    // Sweeping needs to be completed such that markbits are all cleared before
    // starting marking again.
    CompleteSweepingFull();
  }

  std::optional<SafepointScope> safepoint_scope;

  {
    AllowGarbageCollection allow_shared_gc;
    safepoint_scope.emplace(isolate(), kGlobalSafepointForSharedSpaceIsolate);
  }

#ifdef DEBUG
  VerifyCountersAfterSweeping();
#endif

  std::vector<Isolate*> paused_clients =
      PauseConcurrentThreadsInClients(collector);

  // Now that sweeping is completed, we can start the next full GC cycle.
  tracer()->StartCycle(collector, gc_reason, nullptr,
                       GCTracer::MarkingType::kIncremental);

  current_gc_flags_ = gc_flags;
  current_gc_callback_flags_ = gc_callback_flags;

  incremental_marking()->Start(collector, gc_reason);

  if (collector == GarbageCollector::MARK_COMPACTOR) {
    DCHECK(incremental_marking()->IsMajorMarking());
    is_full_gc_during_loading_ = update_allocation_limits_after_loading_;
    RecomputeLimitsAfterLoadingIfNeeded();
    DCHECK(!update_allocation_limits_after_loading_);
  }

  if (isolate()->is_shared_space_isolate()) {
    for (Isolate* client : paused_clients) {
      client->heap()->concurrent_marking()->Resume();
    }
  } else {
    DCHECK(paused_clients.empty());
  }
}

namespace {
void CompleteArrayBufferSweeping(Heap* heap) {
  auto* array_buffer_sweeper = heap->array_buffer_sweeper();
  if (array_buffer_sweeper->sweeping_in_progress()) {
    auto* tracer = heap->tracer();
    GCTracer::Scope::ScopeId scope_id;

    switch (tracer->GetCurrentCollector()) {
      case GarbageCollector::MINOR_MARK_SWEEPER:
        scope_id = GCTracer::Scope::MINOR_MS_COMPLETE_SWEEP_ARRAY_BUFFERS;
        break;
      case GarbageCollector::SCAVENGER:
        scope_id = GCTracer::Scope::SCAVENGER_COMPLETE_SWEEP_ARRAY_BUFFERS;
        break;
      case GarbageCollector::MARK_COMPACTOR:
        scope_id = GCTracer::Scope::MC_COMPLETE_SWEEP_ARRAY_BUFFERS;
    }

    TRACE_GC_EPOCH_WITH_FLOW(
        tracer, scope_id, ThreadKind::kMain,
        array_buffer_sweeper->GetTraceIdForFlowEvent(scope_id),
        TRACE_EVENT_FLAG_FLOW_IN);
    array_buffer_sweeper->EnsureFinished();
  }
}
}  // namespace

void Heap::CompleteSweepingFull() {
  EnsureSweepingCompleted(SweepingForcedFinalizationMode::kUnifiedHeap);

  DCHECK(!sweeping_in_progress());
  DCHECK_IMPLIES(cpp_heap(),
                 !CppHeap::From(cpp_heap())->sweeper().IsSweepingInProgress());
  DCHECK(!tracer()->IsSweepingInProgress());
}

void Heap::StartIncrementalMarkingOnInterrupt() {
  StartIncrementalMarkingIfAllocationLimitIsReached(
      main_thread_local_heap(), GCFlagsForIncrementalMarking(),
      kGCCallbackScheduleIdleGarbageCollection);
}

void Heap::StartIncrementalMarkingIfAllocationLimitIsReached(
    LocalHeap* local_heap, GCFlags gc_flags,
    const GCCallbackFlags gc_callback_flags) {
  if (incremental_marking()->IsStopped() &&
      incremental_marking()->CanAndShouldBeStarted()) {
    switch (IncrementalMarkingLimitReached()) {
      case IncrementalMarkingLimit::kHardLimit:
        if (local_heap->is_main_thread_for(this)) {
          StartIncrementalMarking(
              gc_flags,
              OldGenerationSpaceAvailable() <= NewSpaceTargetCapacity()
                  ? GarbageCollectionReason::kAllocationLimit
                  : GarbageCollectionReason::kGlobalAllocationLimit,
              gc_callback_flags);
        } else {
          ExecutionAccess access(isolate());
          isolate()->stack_guard()->RequestStartIncrementalMarking();
          if (auto* job = incremental_marking()->incremental_marking_job()) {
            job->ScheduleTask();
          }
        }
        break;
      case IncrementalMarkingLimit::kSoftLimit:
        if (auto* job = incremental_marking()->incremental_marking_job()) {
          job->ScheduleTask(TaskPriority::kUserVisible);
        }
        break;
      case IncrementalMarkingLimit::kFallbackForEmbedderLimit:
        // This is a fallback case where no appropriate limits have been
        // configured yet.
        if (local_heap->is_main_thread_for(this) &&
            memory_reducer() != nullptr) {
          memory_reducer()->NotifyPossibleGarbage();
        }
        break;
      case IncrementalMarkingLimit::kNoLimit:
        break;
    }
  }
}

void Heap::MoveRange(Tagged<HeapObject> dst_object, const ObjectSlot dst_slot,
                     const ObjectSlot src_slot, int len,
                     WriteBarrierMode mode) {
  DCHECK_NE(len, 0);
  DCHECK_NE(dst_object->map(), ReadOnlyRoots(this).fixed_cow_array_map());
  const ObjectSlot dst_end(dst_slot + len);
  // Ensure no range overflow.
  DCHECK(dst_slot < dst_end);
  DCHECK(src_slot < src_slot + len);

  if ((v8_flags.concurrent_marking && incremental_marking()->IsMarking()) ||
      (v8_flags.minor_ms && sweeper()->IsIteratingPromotedPages())) {
    if (dst_slot < src_slot) {
      // Copy tagged values forward using relaxed load/stores that do not
      // involve value decompression.
      const AtomicSlot atomic_dst_end(dst_end);
      AtomicSlot dst(dst_slot);
      AtomicSlot src(src_slot);
      while (dst < atomic_dst_end) {
        *dst = *src;
        ++dst;
        ++src;
      }
    } else {
      // Copy tagged values backwards using relaxed load/stores that do not
      // involve value decompression.
      const AtomicSlot atomic_dst_begin(dst_slot);
      AtomicSlot dst(dst_slot + len - 1);
      AtomicSlot src(src_slot + len - 1);
      while (dst >= atomic_dst_begin) {
        *dst = *src;
        --dst;
        --src;
      }
    }
  } else {
    MemMove(dst_slot.ToVoidPtr(), src_slot.ToVoidPtr(), len * kTaggedSize);
  }
  if (mode == SKIP_WRITE_BARRIER) {
    return;
  }
  WriteBarrier::ForRange(this, dst_object, dst_slot, dst_end);
}

// Instantiate Heap::CopyRange().
template V8_EXPORT_PRIVATE void Heap::CopyRange<ObjectSlot>(
    Tagged<HeapObject> dst_object, ObjectSlot dst_slot, ObjectSlot src_slot,
    int len, WriteBarrierMode mode);
template V8_EXPORT_PRIVATE void Heap::CopyRange<MaybeObjectSlot>(
    Tagged<HeapObject> dst_object, MaybeObjectSlot dst_slot,
    MaybeObjectSlot src_slot, int len, WriteBarrierMode mode);

template <typename TSlot>
void Heap::CopyRange(Tagged<HeapObject> dst_object, const TSlot dst_slot,
                     const TSlot src_slot, int len, WriteBarrierMode mode) {
  DCHECK_NE(len, 0);

  DCHECK_NE(dst_object->map(), ReadOnlyRoots(this).fixed_cow_array_map());
  const TSlot dst_end(dst_slot + len);
  // Ensure ranges do not overlap.
  DCHECK(dst_end <= src_slot || (src_slot + len) <= dst_slot);

  if ((v8_flags.concurrent_marking && incremental_marking()->IsMarking()) ||
      (v8_flags.minor_ms && sweeper()->IsIteratingPromotedPages())) {
    // Copy tagged values using relaxed load/stores that do not involve value
    // decompression.
    const AtomicSlot atomic_dst_end(dst_end);
    AtomicSlot dst(dst_slot);
    AtomicSlot src(src_slot);
    while (dst < atomic_dst_end) {
      *dst = *src;
      ++dst;
      ++src;
    }
  } else {
    MemCopy(dst_slot.ToVoidPtr(), src_slot.ToVoidPtr(), len * kTaggedSize);
  }
  if (mode == SKIP_WRITE_BARRIER) {
    return;
  }
  WriteBarrier::ForRange(this, dst_object, dst_slot, dst_end);
}

bool Heap::CollectionRequested() {
  return collection_barrier_->WasGCRequested();
}

void Heap::CollectGarbageForBackground(LocalHeap* local_heap) {
  CHECK(local_heap->is_main_thread());
  CollectAllGarbage(current_gc_flags_,
                    GarbageCollectionReason::kBackgroundAllocationFailure,
                    current_gc_callback_flags_);
}

void Heap::CheckCollectionRequested() {
  if (!CollectionRequested()) return;

  CollectAllGarbage(current_gc_flags_,
                    GarbageCollectionReason::kBackgroundAllocationFailure,
                    current_gc_callback_flags_);
}

void Heap::UpdateSurvivalStatistics(int start_new_space_size) {
  if (start_new_space_size == 0) return;

  promotion_ratio_ = (static_cast<double>(promoted_objects_size_) /
                      static_cast<double>(start_new_space_size) * 100);

  if (previous_new_space_surviving_object_size_ > 0) {
    promotion_rate_ =
        (static_cast<double>(promoted_objects_size_) /
         static_cast<double>(previous_new_space_surviving_object_size_) * 100);
  } else {
    promotion_rate_ = 0;
  }

  new_space_surviving_rate_ =
      (static_cast<double>(new_space_surviving_object_size_) /
       static_cast<double>(start_new_space_size) * 100);

  double survival_rate = promotion_ratio_ + new_space_surviving_rate_;
  tracer()->AddSurvivalRatio(survival_rate);
}

namespace {

GCTracer::Scope::ScopeId CollectorScopeId(GarbageCollector collector) {
  switch (collector) {
    case GarbageCollector::MARK_COMPACTOR:
      return GCTracer::Scope::ScopeId::MARK_COMPACTOR;
    case GarbageCollector::MINOR_MARK_SWEEPER:
      return GCTracer::Scope::ScopeId::MINOR_MARK_SWEEPER;
    case GarbageCollector::SCAVENGER:
      return GCTracer::Scope::ScopeId::SCAVENGER;
  }
  UNREACHABLE();
}

void ClearStubCaches(Isolate* isolate) {
  isolate->load_stub_cache()->Clear();
  isolate->store_stub_cache()->Clear();
  isolate->define_own_stub_cache()->Clear();

  if (isolate->is_shared_space_isolate()) {
    isolate->global_safepoint()->IterateClientIsolates([](Isolate* client) {
      client->load_stub_cache()->Clear();
      client->store_stub_cache()->Clear();
      client->define_own_stub_cache()->Clear();
    });
  }
}

}  // namespace

void Heap::PerformGarbageCollection(GarbageCollector collector,
                                    GarbageCollectionReason gc_reason,
                                    const char* collector_reason) {
  if (IsYoungGenerationCollector(collector)) {
    if (v8_flags.sticky_mark_bits) {
      DCHECK_EQ(GarbageCollector::MINOR_MARK_SWEEPER, collector);
      // TODO(333906585): It's not necessary to complete full sweeping here.
      // Make sure that only the OLD_SPACE is swept.
      CompleteSweepingFull();
    } else {
      CompleteSweepingYoung();
      if (v8_flags.verify_heap) {
        // If heap verification is enabled, we want to ensure that sweeping is
        // completed here, as it will be triggered from Heap::Verify anyway.
        // In this way, sweeping finalization is accounted to the corresponding
        // full GC cycle.
        CompleteSweepingFull();
      }
    }
  } else {
    DCHECK_EQ(GarbageCollector::MARK_COMPACTOR, collector);
    CompleteSweepingFull();
  }

  const base::TimeTicks atomic_pause_start_time = base::TimeTicks::Now();

  std::optional<SafepointScope> safepoint_scope;
  {
    AllowGarbageCollection allow_shared_gc;
    safepoint_scope.emplace(isolate(), kGlobalSafepointForSharedSpaceIsolate);
  }

  if (!incremental_marking_->IsMarking() ||
      (collector == GarbageCollector::SCAVENGER)) {
    tracer()->StartCycle(collector, gc_reason, collector_reason,
                         GCTracer::MarkingType::kAtomic);
  }

  tracer()->StartAtomicPause();
  if ((!Heap::IsYoungGenerationCollector(collector) || v8_flags.minor_ms) &&
      incremental_marking_->IsMarking()) {
    DCHECK_IMPLIES(Heap::IsYoungGenerationCollector(collector),
                   incremental_marking_->IsMinorMarking());
    tracer()->UpdateCurrentEvent(gc_reason, collector_reason);
  }

  DCHECK(tracer()->IsConsistentWithCollector(collector));
  TRACE_GC_EPOCH(tracer(), CollectorScopeId(collector), ThreadKind::kMain);

  collection_barrier_->StopTimeToCollectionTimer();

  std::vector<Isolate*> paused_clients =
      PauseConcurrentThreadsInClients(collector);

  FreeLinearAllocationAreas();

  tracer()->StartInSafepoint(atomic_pause_start_time);

  GarbageCollectionPrologueInSafepoint();

  PerformHeapVerification();

  const size_t start_young_generation_size =
      NewSpaceSize() + (new_lo_space() ? new_lo_space()->SizeOfObjects() : 0);

  // Make sure allocation observers are disabled until the new new space
  // capacity is set in the epilogue.
  PauseAllocationObserversScope pause_observers(this);

  const size_t new_space_capacity_before_gc = NewSpaceTargetCapacity();

  if (collector == GarbageCollector::MARK_COMPACTOR) {
    MarkCompact();
  } else if (collector == GarbageCollector::MINOR_MARK_SWEEPER) {
    MinorMarkSweep();
  } else {
    DCHECK_EQ(GarbageCollector::SCAVENGER, collector);
    Scavenge();
  }

  // We don't want growing or shrinking of the current cycle to affect
  // pretenuring decisions. The numbers collected in the GC will be for the
  // capacity that was set before the GC.
  pretenuring_handler_.ProcessPretenuringFeedback(new_space_capacity_before_gc);

  UpdateSurvivalStatistics(static_cast<int>(start_young_generation_size));
  ShrinkOldGenerationAllocationLimitIfNotConfigured();

  if (collector == GarbageCollector::SCAVENGER) {
    // Objects that died in the new space might have been accounted
    // as bytes marked ahead of schedule by the incremental marker.
    incremental_marking()->UpdateMarkedBytesAfterScavenge(
        start_young_generation_size - SurvivedYoungObjectSize());
  }

  isolate_->counters()->objs_since_last_young()->Set(0);

  isolate_->eternal_handles()->PostGarbageCollectionProcessing();

  // Update relocatables.
  Relocatable::PostGarbageCollectionProcessing(isolate_);

  if (isolate_->is_shared_space_isolate()) {
    // Allows handle derefs for all threads/isolates from this thread.
    AllowHandleUsageOnAllThreads allow_all_handle_derefs;
    isolate()->global_safepoint()->IterateClientIsolates([](Isolate* client) {
      Relocatable::PostGarbageCollectionProcessing(client);
    });
  }

  // First round weak callbacks are not supposed to allocate and trigger
  // nested GCs.
  isolate_->global_handles()->InvokeFirstPassWeakCallbacks();

  if (cpp_heap() && (collector == GarbageCollector::MARK_COMPACTOR ||
                     collector == GarbageCollector::MINOR_MARK_SWEEPER)) {
    // TraceEpilogue may trigger operations that invalidate global handles. It
    // has to be called *after* all other operations that potentially touch
    // and reset global handles. It is also still part of the main garbage
    // collection pause and thus needs to be called *before* any operation
    // that can potentially trigger recursive garbage collections.
    TRACE_GC(tracer(), GCTracer::Scope::HEAP_EMBEDDER_TRACING_EPILOGUE);
    CppHeap::From(cpp_heap())->CompactAndSweep();
  }

  if (collector == GarbageCollector::MARK_COMPACTOR) {
    ClearStubCaches(isolate());
  }

  PerformHeapVerification();

  GarbageCollectionEpilogueInSafepoint(collector);

  const base::TimeTicks atomic_pause_end_time = base::TimeTicks::Now();
  tracer()->StopInSafepoint(atomic_pause_end_time);

  ResumeConcurrentThreadsInClients(std::move(paused_clients));

  RecomputeLimits(collector, atomic_pause_end_time);
  if ((collector == GarbageCollector::MARK_COMPACTOR) &&
      is_full_gc_during_loading_) {
    if (ShouldOptimizeForLoadTime() &&
        v8_flags.update_allocation_limits_after_loading) {
      update_allocation_limits_after_loading_ = true;
    }
    is_full_gc_during_loading_ = false;
  }

  // After every full GC the old generation allocation limit should be
  // configured.
  DCHECK_IMPLIES(!IsYoungGenerationCollector(collector),
                 !using_initial_limit());
}

void Heap::PerformHeapVerification() {
  HeapVerifier::VerifyHeapIfEnabled(this);

  if (isolate()->is_shared_space_isolate()) {
    // Allow handle creation for client isolates even if they are parked. This
    // is because some object verification methods create handles.
    AllowHandleUsageOnAllThreads allow_handle_creation;
    isolate()->global_safepoint()->IterateClientIsolates([](Isolate* client) {
      HeapVerifier::VerifyHeapIfEnabled(client->heap());
    });
  }
}

std::vector<Isolate*> Heap::PauseConcurrentThreadsInClients(
    GarbageCollector collector) {
  std::vector<Isolate*> paused_clients;

  if (isolate()->is_shared_space_isolate()) {
    isolate()->global_safepoint()->IterateClientIsolates(
        [collector, &paused_clients](Isolate* client) {
          CHECK(client->heap()->deserialization_complete());

          if (v8_flags.concurrent_marking &&
              client->heap()->concurrent_marking()->Pause()) {
            paused_clients.push_back(client);
          }

          if (collector == GarbageCollector::MARK_COMPACTOR) {
            Sweeper* const client_sweeper = client->heap()->sweeper();
            client_sweeper->ContributeAndWaitForPromotedPagesIteration();
          }
        });
  }

  return paused_clients;
}

void Heap::ResumeConcurrentThreadsInClients(
    std::vector<Isolate*> paused_clients) {
  if (isolate()->is_shared_space_isolate()) {
    for (Isolate* client : paused_clients) {
      client->heap()->concurrent_marking()->Resume();
    }
  } else {
    DCHECK(paused_clients.empty());
  }
}

bool Heap::CollectGarbageShared(LocalHeap* local_heap,
                                GarbageCollectionReason gc_reason) {
  CHECK(deserialization_complete());
  DCHECK(isolate()->has_shared_space());

  Isolate* shared_space_isolate = isolate()->shared_space_isolate();
  return shared_space_isolate->heap()->CollectGarbageFromAnyThread(local_heap,
                                                                   gc_reason);
}

bool Heap::CollectGarbageFromAnyThread(LocalHeap* local_heap,
                                       GarbageCollectionReason gc_reason) {
  DCHECK(local_heap->IsRunning());

  if (isolate() == local_heap->heap()->isolate() &&
      local_heap->is_main_thread()) {
    CollectAllGarbage(current_gc_flags_, gc_reason, current_gc_callback_flags_);
    return true;
  } else {
    if (!collection_barrier_->TryRequestGC()) return false;

    const LocalHeap::ThreadState old_state =
        main_thread_local_heap()->state_.SetCollectionRequested();

    if (old_state.IsRunning()) {
      const bool performed_gc =
          collection_barrier_->AwaitCollectionBackground(local_heap);
      return performed_gc;
    } else {
      DCHECK(old_state.IsParked());
      return false;
    }
  }
}

void Heap::CompleteSweepingYoung() {
  DCHECK(!v8_flags.sticky_mark_bits);
  CompleteArrayBufferSweeping(this);

  // If sweeping is in progress and there are no sweeper tasks running, finish
  // the sweeping here, to avoid having to pause and resume during the young
  // generation GC.
  FinishSweepingIfOutOfWork();

  if (v8_flags.minor_ms) {
    EnsureYoungSweepingCompleted();
  }

#if defined(CPPGC_YOUNG_GENERATION)
  // Always complete sweeping if young generation is enabled.
  if (cpp_heap()) {
    if (auto* iheap = CppHeap::From(cpp_heap());
        iheap->generational_gc_supported())
      iheap->FinishSweepingIfRunning();
  }
#endif  // defined(CPPGC_YOUNG_GENERATION)
}

void Heap::EnsureSweepingCompletedForObject(Tagged<HeapObject> object) {
  if (!sweeping_in_progress()) return;

  MemoryChunk* chunk = MemoryChunk::FromHeapObject(object);
  if (chunk->InReadOnlySpace()) return;

  MutablePageMetadata* mutable_page =
      MutablePageMetadata::cast(chunk->Metadata());
  if (mutable_page->SweepingDone()) return;

  // SweepingDone() is always true for large pages.
  DCHECK(!chunk->IsLargePage());

  PageMetadata* page = PageMetadata::cast(mutable_page);
  sweeper()->EnsurePageIsSwept(page);
}

// static
Heap::LimitsCompuatationResult Heap::ComputeNewAllocationLimits(Heap* heap) {
  DCHECK(!heap->using_initial_limit());
#if defined(V8_USE_PERFETTO)
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
                "OldGenerationConsumedBytes",
                heap->OldGenerationConsumedBytes());
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), "GlobalConsumedBytes",
                heap->GlobalConsumedBytes());
  TRACE_COUNTER(TRACE_DISABLED_BY_DEFAULT("v8.gc"), "ExternalMemoryBytes",
                heap->external_memory());
#endif
  const HeapGrowingMode mode = heap->CurrentHeapGrowingMode();
  double v8_gc_speed =
      heap->tracer()->OldGenerationSpeedInBytesPerMillisecond();
  double v8_mutator_speed =
      heap->tracer()->OldGenerationAllocationThroughputInBytesPerMillisecond();
  double v8_growing_factor = MemoryController<V8HeapTrait>::GrowingFactor(
      heap, heap->max_old_generation_size(), v8_gc_speed, v8_mutator_speed,
      mode);
  double embedder_gc_speed =
      heap->tracer()->EmbedderSpeedInBytesPerMillisecond();
  double embedder_speed =
      heap->tracer()->EmbedderAllocationThroughputInBytesPerMillisecond();
  double embedder_growing_factor =
      (embedder_gc_speed > 0 && embedder_speed > 0)
          ? MemoryController<GlobalMemoryTrait>::GrowingFactor(
                heap, heap->max_global_memory_size_, embedder_gc_speed,
                embedder_speed, mode)
          : 0;
  double global_growing_factor =
      std::max(v8_growing_factor, embedder_growing_factor);

  size_t new_space_capacity = heap->NewSpaceTargetCapacity();

  size_t new_old_generation_allocation_limit =
      MemoryController<V8HeapTrait>::BoundAllocationLimit(
          heap, heap->OldGenerationConsumedBytesAtLastGC(),
          heap->OldGenerationConsumedBytesAtLastGC() * v8_growing_factor,
          heap->min_old_generation_size_, heap->max_old_generation_size(),
          new_space_capacity, mode);

  DCHECK_GT(global_growing_factor, 0);
  size_t new_global_allocation_limit =
      MemoryController<GlobalMemoryTrait>::BoundAllocationLimit(
          heap, heap->GlobalConsumedBytesAtLastGC(),
          heap->GlobalConsumedBytesAtLastGC() * global_growing_factor,
          heap->min_global_memory_size_, heap->max_global_memory_size_,
          new_space_capacity, mode);

  return {new_old_generation_allocation_limit, new_global_allocation_limit};
}

void Heap::RecomputeLimits(GarbageCollector collector, base::TimeTicks time) {
  if (IsYoungGenerationCollector(collector) &&
      !HasLowYoungGenerationAllocationRate()) {
    return;
  }
  if (using_initial_limit()) {
    DCHECK(IsYoungGenerationCollector(collector));
    return;
  }

  auto new_limits = ComputeNewAllocationLimits(this);
  size_t new_old_generation_allocation_limit =
      new_limits.old_generation_allocation_limit;
  size_t new_global_allocation_limit = new_limits.global_allocation_limit;

  if (collector == GarbageCollector::MARK_COMPACTOR) {
    if (v8_flags.memory_balancer) {
      // Now recompute the new allocation limit.
      mb_->RecomputeLimits(new_limits.global_allocation_limit -
                               new_limits.old_generation_allocation_limit,
                           time);
    } else {
      SetOldGenerationAndGlobalAllocationLimit(
          new_limits.old_generation_allocation_limit,
          new_limits.global_allocation_limit);
    }

    CheckIneffectiveMarkCompact(
        OldGenerationConsumedBytes(),
        tracer()->AverageMarkCompactMutatorUtilization());
  } else {
    DCHECK(HasLowYoungGenerationAllocationRate());
    new_old_generation_allocation_limit = std::min(
        new_old_generation_allocation_limit, old_generation_allocation_limit());
    new_global_allocation_limit =
        std::min(new_global_allocation_limit, global_allocation_limit());
    SetOldGenerationAndGlobalAllocationLimit(
        new_old_generation_allocation_limit, new_global_allocation_limit);
  }

  CHECK_EQ(max_global_memory_size_,
           GlobalMemorySizeFromV8Size(max_old_generation_size_));
  CHECK_GE(global_allocation_limit(), old_generation_allocation_limit_);
}

void Heap::RecomputeLimitsAfterLoadingIfNeeded() {
  if (!v8_flags.update_allocation_limits_after_loading) {
    DCHECK(!update_allocation_limits_after_loading_);
    return;
  }

  if (!update_allocation_limits_after_loading_) {
    return;
  }

  if ((OldGenerationSpaceAvailable() > 0) && (GlobalMemoryAvailable() > 0)) {
    // Only recompute limits if memory accumulated during loading may lead to
    // atomic GC. If there is still room to allocate, keep the current limits.
    DCHECK(!AllocationLimitOvershotByLargeMargin());
    update_allocation_limits_after_loading_ = false;
    return;
  }

  if (!incremental_marking()->IsMajorMarking()) {
    // Incremental marking should have started already but was delayed. Don't
    // update the limits yet to not delay starting incremental marking any
    // further. Limits will be updated on incremental marking start, with the
    // intention to give more slack and avoid an immediate large finalization
    // pause.
    return;
  }

  update_allocation_limits_after_loading_ = false;

  UpdateOldGenerationAllocationCounter();
  old_generation_size_at_last_gc_ = OldGenerationSizeOfObjects();
  old_generation_wasted_at_last_gc_ = OldGenerationWastedBytes();
  external_memory_.UpdateLowSinceMarkCompact(external_memory_.total());
  embedder_size_at_last_gc_ = EmbedderSizeOfObjects();
  set_using_initial_limit(false);

  auto new_limits = ComputeNewAllocationLimits(this);
  size_t new_old_generation_allocation_limit =
      new_limits.old_generation_allocation_limit;
  size_t new_global_allocation_limit = new_limits.global_allocation_limit;

  new_old_generation_allocation_limit = std::max(
      new_old_generation_allocation_limit, old_generation_allocation_limit());
  new_global_allocation_limit =
      std::max(new_global_allocation_limit, global_allocation_limit());
  SetOldGenerationAndGlobalAllocationLimit(new_old_generation_allocation_limit,
                                           new_global_allocation_limit);

  CHECK_EQ(max_global_memory_size_,
           GlobalMemorySizeFromV8Size(max_old_generation_size_));
  CHECK_GE(global_allocation_limit(), old_generation_allocation_limit_);
}

void Heap::CallGCPrologueCallbacks(GCType gc_type, GCCallbackFlags flags,
                                   GCTracer::Scope::ScopeId scope_id) {
  if (gc_prologue_callbacks_.IsEmpty()) return;

  GCCallbacksScope scope(this);
  if (scope.CheckReenter()) {
    RCS_SCOPE(isolate(), RuntimeCallCounterId::kGCPrologueCallback);
    TRACE_GC(tracer(), scope_id);
    HandleScope handle_scope(isolate());
    gc_prologue_callbacks_.Invoke(gc_type, flags);
  }
}

void Heap::CallGCEpilogueCallbacks(GCType gc_type, GCCallbackFlags flags,
                                   GCTracer::Scope::ScopeId scope_id) {
  if (gc_epilogue_callbacks_.IsEmpty()) return;

  GCCallbacksScope scope(this);
  if (scope.CheckReenter()) {
    RCS_SCOPE(isolate(), RuntimeCallCounterId::kGCEpilogueCallback);
    TRACE_GC(tracer(), scope_id);
    HandleScope handle_scope(isolate());
    gc_epilogue_callbacks_.Invoke(gc_type, flags);
  }
}

void Heap::MarkCompact() {
  SetGCState(MARK_COMPACT);

  PROFILE(isolate_, CodeMovingGCEvent());

  UpdateOldGenerationAllocationCounter();
  uint64_t size_of_objects_before_gc = SizeOfObjects();

  mark_compact_collector()->Prepare();

  ms_count_++;
  contexts_disposed_ = 0;

  MarkCompactPrologue();

  mark_compact_collector()->CollectGarbage();

  MarkCompactEpilogue();

  if (v8_flags.allocation_site_pretenuring) {
    EvaluateOldSpaceLocalPretenuring(size_of_objects_before_gc);
  }
  // This should be updated before PostGarbageCollectionProcessing, which
  // can cause another GC. Take into account the objects promoted during
  // GC.
  old_generation_allocation_counter_at_last_gc_ +=
      static_cast<size_t>(promoted_objects_size_);
  old_generation_size_at_last_gc_ = OldGenerationSizeOfObjects();
  old_generation_wasted_at_last_gc_ = OldGenerationWastedBytes();
  external_memory_.UpdateLowSinceMarkCompact(external_memory_.total());
  embedder_size_at_last_gc_ = EmbedderSizeOfObjects();
  // Limits can now be computed based on estimate from MARK_COMPACT.
  set_using_initial_limit(false);
}

void Heap::MinorMarkSweep() {
  DCHECK(v8_flags.minor_ms);
  CHECK_EQ(NOT_IN_GC, gc_state());
  DCHECK(use_new_space());
  DCHECK(!incremental_marking()->IsMajorMarking());

  TRACE_GC(tracer(), GCTracer::Scope::MINOR_MS);

  SetGCState(MINOR_MARK_SWEEP);
  minor_mark_sweep_collector_->CollectGarbage();
  SetGCState(NOT_IN_GC);
}

void Heap::MarkCompactEpilogue() {
  TRACE_GC(tracer(), GCTracer::Scope::MC_EPILOGUE);
  SetGCState(NOT_IN_GC);

  isolate_->counters()->objs_since_last_full()->Set(0);
}

void Heap::MarkCompactPrologue() {
  TRACE_GC(tracer(), GCTracer::Scope::MC_PROLOGUE);
  isolate_->descriptor_lookup_cache()->Clear();
  RegExpResultsCache::Clear(string_split_cache());
  RegExpResultsCache::Clear(regexp_multiple_cache());
  RegExpResultsCache_MatchGlobalAtom::Clear(this);

  FlushNumberStringCache();
}

void Heap::Scavenge() {
  DCHECK_NOT_NULL(new_space());
  DCHECK_IMPLIES(v8_flags.separate_gc_phases,
                 !incremental_marking()->IsMarking());

  if (v8_flags.trace_incremental_marking &&
      !incremental_marking()->IsStopped()) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Scavenge during marking.\n");
  }

  TRACE_GC(tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE);
  base::MutexGuard guard(relocation_mutex());
  // Young generation garbage collection is orthogonal from full GC marking. It
  // is possible that objects that are currently being processed for marking are
  // reclaimed in the young generation GC that interleaves concurrent marking.
  // Pause concurrent markers to allow processing them using
  // `UpdateMarkingWorklistAfterYoungGenGC()`.
  ConcurrentMarking::PauseScope pause_js_marking(concurrent_marking());
  CppHeap::PauseConcurrentMarkingScope pause_cpp_marking(
      CppHeap::From(cpp_heap_));

  // Bump-pointer allocations done during scavenge are not real allocations.
  // Pause the inline allocation steps.
  IncrementalMarking::PauseBlackAllocationScope pause_black_allocation(
      incremental_marking());

  SetGCState(SCAVENGE);

  // Implements Cheney's copying algorithm
  scavenger_collector_->CollectGarbage();

  SetGCState(NOT_IN_GC);
}

bool Heap::ExternalStringTable::Contains(Tagged<String> string) {
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    if (young_strings_[i] == string) return true;
  }
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    if (old_strings_[i] == string) return true;
  }
  return false;
}

void Heap::UpdateExternalString(Tagged<String> string, size_t old_payload,
                                size_t new_payload) {
  DCHECK(IsExternalString(string));

  PageMetadata* page = PageMetadata::FromHeapObject(string);

  if (old_payload > new_payload) {
    page->DecrementExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString, old_payload - new_payload);
  } else {
    page->IncrementExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString, new_payload - old_payload);
  }
}

Tagged<String> Heap::UpdateYoungReferenceInExternalStringTableEntry(
    Heap* heap, FullObjectSlot p) {
  // This is only used for Scavenger.
  DCHECK(!v8_flags.minor_ms);

  PtrComprCageBase cage_base(heap->isolate());
  Tagged<HeapObject> obj = Cast<HeapObject>(*p);
  MapWord first_word = obj->map_word(cage_base, kRelaxedLoad);

  Tagged<String> new_string;

  if (InFromPage(obj)) {
    if (!first_word.IsForwardingAddress()) {
      // Unreachable external string can be finalized.
      Tagged<String> string = Cast<String>(obj);
      if (!IsExternalString(string, cage_base)) {
        // Original external string has been internalized.
        DCHECK(IsThinString(string, cage_base));
        return Tagged<String>();
      }
      heap->FinalizeExternalString(string);
      return Tagged<String>();
    }
    new_string = Cast<String>(first_word.ToForwardingAddress(obj));
  } else {
    new_string = Cast<String>(obj);
  }

  // String is still reachable.
  if (IsThinString(new_string, cage_base)) {
    // Filtering Thin strings out of the external string table.
    return Tagged<String>();
  } else if (IsExternalString(new_string, cage_base)) {
    MutablePageMetadata::MoveExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString,
        PageMetadata::FromAddress((*p).ptr()),
        PageMetadata::FromHeapObject(new_string),
        Cast<ExternalString>(new_string)->ExternalPayloadSize());
    return new_string;
  }

  // Internalization can replace external strings with non-external strings.
  return IsExternalString(new_string, cage_base) ? new_string
                                                 : Tagged<String>();
}

void Heap::ExternalStringTable::VerifyYoung() {
#ifdef DEBUG
  std::set<Tagged<String>> visited_map;
  std::map<MutablePageMetadata*, size_t> size_map;
  ExternalBackingStoreType type = ExternalBackingStoreType::kExternalString;
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<String> obj = Cast<String>(Tagged<Object>(young_strings_[i]));
    MutablePageMetadata* mc = MutablePageMetadata::FromHeapObject(obj);
    DCHECK_IMPLIES(!v8_flags.sticky_mark_bits,
                   mc->Chunk()->InYoungGeneration());
    DCHECK(HeapLayout::InYoungGeneration(obj));
    DCHECK(!IsTheHole(obj, heap_->isolate()));
    DCHECK(IsExternalString(obj));
    // Note: we can have repeated elements in the table.
    DCHECK_EQ(0, visited_map.count(obj));
    visited_map.insert(obj);
    size_map[mc] += Cast<ExternalString>(obj)->ExternalPayloadSize();
  }
  for (std::map<MutablePageMetadata*, size_t>::iterator it = size_map.begin();
       it != size_map.end(); it++)
    DCHECK_EQ(it->first->ExternalBackingStoreBytes(type), it->second);
#endif
}

void Heap::ExternalStringTable::Verify() {
#ifdef DEBUG
  std::set<Tagged<String>> visited_map;
  std::map<MutablePageMetadata*, size_t> size_map;
  ExternalBackingStoreType type = ExternalBackingStoreType::kExternalString;
  VerifyYoung();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<String> obj = Cast<String>(Tagged<Object>(old_strings_[i]));
    MutablePageMetadata* mc = MutablePageMetadata::FromHeapObject(obj);
    DCHECK_IMPLIES(!v8_flags.sticky_mark_bits,
                   !mc->Chunk()->InYoungGeneration());
    DCHECK(!HeapLayout::InYoungGeneration(obj));
    DCHECK(!IsTheHole(obj, heap_->isolate()));
    DCHECK(IsExternalString(obj));
    // Note: we can have repeated elements in the table.
    DCHECK_EQ(0, visited_map.count(obj));
    visited_map.insert(obj);
    size_map[mc] += Cast<ExternalString>(obj)->ExternalPayloadSize();
  }
  for (std::map<MutablePageMetadata*, size_t>::iterator it = size_map.begin();
       it != size_map.end(); it++)
    DCHECK_EQ(it->first->ExternalBackingStoreBytes(type), it->second);
#endif
}

void Heap::ExternalStringTable::UpdateYoungReferences(
    Heap::ExternalStringTableUpdaterCallback updater_func) {
  if (young_strings_.empty()) return;

  FullObjectSlot start(young_strings_.data());
  FullObjectSlot end(young_strings_.data() + young_strings_.size());
  FullObjectSlot last = start;

  for (FullObjectSlot p = start; p < end; ++p) {
    Tagged<String> target = updater_func(heap_, p);

    if (target.is_null()) continue;

    DCHECK(IsExternalString(target));

    if (HeapLayout::InYoungGeneration(target)) {
      // String is still in new space. Update the table entry.
      last.store(target);
      ++last;
    } else {
      // String got promoted. Move it to the old string list.
      old_strings_.push_back(target);
    }
  }

  DCHECK(last <= end);
  young_strings_.resize(last - start);
  if (v8_flags.verify_heap) {
    VerifyYoung();
  }
}

void Heap::ExternalStringTable::PromoteYoung() {
  old_strings_.reserve(old_strings_.size() + young_strings_.size());
  std::move(std::begin(young_strings_), std::end(young_strings_),
            std::back_inserter(old_strings_));
  young_strings_.clear();
}

void Heap::ExternalStringTable::IterateYoung(RootVisitor* v) {
  if (!young_strings_.empty()) {
    v->VisitRootPointers(
        Root::kExternalStringsTable, nullptr,
        FullObjectSlot(young_strings_.data()),
        FullObjectSlot(young_strings_.data() + young_strings_.size()));
  }
}

void Heap::ExternalStringTable::IterateAll(RootVisitor* v) {
  IterateYoung(v);
  if (!old_strings_.empty()) {
    v->VisitRootPointers(
        Root::kExternalStringsTable, nullptr,
        FullObjectSlot(old_strings_.data()),
        FullObjectSlot(old_strings_.data() + old_strings_.size()));
  }
}

void Heap::UpdateYoungReferencesInExternalStringTable(
    ExternalStringTableUpdaterCallback updater_func) {
  external_string_table_.UpdateYoungReferences(updater_func);
}

void Heap::ExternalStringTable::UpdateReferences(
    Heap::ExternalStringTableUpdaterCallback updater_func) {
  if (!old_strings_.empty()) {
    FullObjectSlot start(old_strings_.data());
    FullObjectSlot end(old_strings_.data() + old_strings_.size());
    for (FullObjectSlot p = start; p < end; ++p)
      p.store(updater_func(heap_, p));
  }

  UpdateYoungReferences(updater_func);
}

void Heap::UpdateReferencesInExternalStringTable(
    ExternalStringTableUpdaterCallback updater_func) {
  external_string_table_.UpdateReferences(updater_func);
}

void Heap::ProcessAllWeakReferences(WeakObjectRetainer* retainer) {
  ProcessNativeContexts(retainer);
  ProcessAllocationSites(retainer);
  ProcessDirtyJSFinalizationRegistries(retainer);
}

void Heap::ProcessNativeContexts(WeakObjectRetainer* retainer) {
  Tagged<Object> head =
      VisitWeakList<Context>(this, native_contexts_list(), retainer);
  // Update the head of the list of contexts.
  set_native_contexts_list(head);
}

void Heap::ProcessAllocationSites(WeakObjectRetainer* retainer) {
  Tagged<Object> allocation_site_obj =
      VisitWeakList<AllocationSite>(this, allocation_sites_list(), retainer);
  set_allocation_sites_list(allocation_site_obj);
}

void Heap::ProcessDirtyJSFinalizationRegistries(WeakObjectRetainer* retainer) {
  Tagged<Object> head = VisitWeakList<JSFinalizationRegistry>(
      this, dirty_js_finalization_registries_list(), retainer);
  set_dirty_js_finalization_registries_list(head);
  // If the list is empty, set the tail to undefined. Otherwise the tail is set
  // by WeakListVisitor<JSFinalizationRegistry>::VisitLiveObject.
  if (IsUndefined(head, isolate())) {
    set_dirty_js_finalization_registries_list_tail(head);
  }
}

void Heap::ProcessWeakListRoots(WeakObjectRetainer* retainer) {
  set_native_contexts_list(retainer->RetainAs(native_contexts_list()));
  set_allocation_sites_list(retainer->RetainAs(allocation_sites_list()));
  set_dirty_js_finalization_registries_list(
      retainer->RetainAs(dirty_js_finalization_registries_list()));
  set_dirty_js_finalization_registries_list_tail(
      retainer->RetainAs(dirty_js_finalization_registries_list_tail()));
}

void Heap::ForeachAllocationSite(
    Tagged<Object> list,
    const std::function<void(Tagged<AllocationSite>)>& visitor) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> current = list;
  while (IsAllocationSite(current)) {
    Tagged<AllocationSite> site = Cast<AllocationSite>(current);
    visitor(site);
    Tagged<Object> current_nested = site->nested_site();
    while (IsAllocationSite(current_nested)) {
      Tagged<AllocationSite> nested_site = Cast<AllocationSite>(current_nested);
      visitor(nested_site);
      current_nested = nested_site->nested_site();
    }
    current = site->weak_next();
  }
}

void Heap::ResetAllAllocationSitesDependentCode(AllocationType allocation) {
  DisallowGarbageCollection no_gc_scope;
  bool marked = false;

  ForeachAllocationSite(
      allocation_sites_list(),
      [&marked, allocation, this](Tagged<AllocationSite> site) {
        if (site->GetAllocationType() == allocation) {
          site->ResetPretenureDecision();
          site->set_deopt_dependent_code(true);
          marked = true;
          pretenuring_handler_.RemoveAllocationSitePretenuringFeedback(site);
          return;
        }
      });
  if (marked) isolate_->stack_guard()->RequestDeoptMarkedAllocationSites();
}

void Heap::EvaluateOldSpaceLocalPretenuring(
    uint64_t size_of_objects_before_gc) {
  uint64_t size_of_objects_after_gc = SizeOfObjects();
  double old_generation_survival_rate =
      (static_cast<double>(size_of_objects_after_gc) * 100) /
      static_cast<double>(size_of_objects_before_gc);

  if (old_generation_survival_rate < kOldSurvivalRateLowThreshold) {
    // Too many objects died in the old generation, pretenuring of wrong
    // allocation sites may be the cause for that. We have to deopt all
    // dependent code registered in the allocation sites to re-evaluate
    // our pretenuring decisions.
    ResetAllAllocationSitesDependentCode(AllocationType::kOld);
    if (v8_flags.trace_pretenuring) {
      PrintF(
          "Deopt all allocation sites dependent code due to low survival "
          "rate in the old generation %f\n",
          old_generation_survival_rate);
    }
  }
}

void Heap::VisitExternalResources(v8::ExternalResourceVisitor* visitor) {
  DisallowGarbageCollection no_gc;
  // All external strings are listed in the external string table.

  class ExternalStringTableVisitorAdapter : public RootVisitor {
   public:
    explicit ExternalStringTableVisitorAdapter(
        Isolate* isolate, v8::ExternalResourceVisitor* visitor)
        : isolate_(isolate), visitor_(visitor) {}
    void VisitRootPointers(Root root, const char* description,
                           FullObjectSlot start, FullObjectSlot end) override {
      for (FullObjectSlot p = start; p < end; ++p) {
        DCHECK(IsExternalString(*p));
        visitor_->VisitExternalString(
            Utils::ToLocal(Handle<String>(Cast<String>(*p), isolate_)));
      }
    }

   private:
    Isolate* isolate_;
    v8::ExternalResourceVisitor* visitor_;
  } external_string_table_visitor(isolate(), visitor);

  external_string_table_.IterateAll(&external_string_table_visitor);
}

static_assert(IsAligned(OFFSET_OF_DATA_START(FixedDoubleArray),
                        kDoubleAlignment));

#ifdef V8_COMPRESS_POINTERS
// TODO(ishell, v8:8875): When pointer compression is enabled the kHeaderSize
// is only kTaggedSize aligned but we can keep using unaligned access since
// both x64 and arm64 architectures (where pointer compression supported)
// allow unaligned access to doubles.
static_assert(IsAligned(OFFSET_OF_DATA_START(ByteArray), kTaggedSize));
#else
static_assert(IsAligned(OFFSET_OF_DATA_START(ByteArray), kDoubleAlignment));
#endif

int Heap::GetMaximumFillToAlign(AllocationAlignment alignment) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return 0;
  switch (alignment) {
    case kTaggedAligned:
      return 0;
    case kDoubleAligned:
    case kDoubleUnaligned:
      return kDoubleSize - kTaggedSize;
    default:
      UNREACHABLE();
  }
}

// static
int Heap::GetFillToAlign(Address address, AllocationAlignment alignment) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return 0;
  if (alignment == kDoubleAligned && (address & kDoubleAlignmentMask) != 0)
    return kTaggedSize;
  if (alignment == kDoubleUnaligned && (address & kDoubleAlignmentMask) == 0) {
    return kDoubleSize - kTaggedSize;  // No fill if double is always aligned.
  }
  return 0;
}

size_t Heap::GetCodeRangeReservedAreaSize() {
  return CodeRange::GetWritableReservedAreaSize();
}

Tagged<HeapObject> Heap::PrecedeWithFiller(Tagged<HeapObject> object,
                                           int filler_size) {
  CreateFillerObjectAt(object.address(), filler_size);
  return HeapObject::FromAddress(object.address() + filler_size);
}

Tagged<HeapObject> Heap::PrecedeWithFillerBackground(Tagged<HeapObject> object,
                                                     int filler_size) {
  CreateFillerObjectAtBackground(
      WritableFreeSpace::ForNonExecutableMemory(object.address(), filler_size));
  return HeapObject::FromAddress(object.address() + filler_size);
}

Tagged<HeapObject> Heap::AlignWithFillerBackground(
    Tagged<HeapObject> object, int object_size, int allocation_size,
    AllocationAlignment alignment) {
  const int filler_size = allocation_size - object_size;
  DCHECK_LT(0, filler_size);
  const int pre_filler = GetFillToAlign(object.address(), alignment);
  if (pre_filler) {
    object = PrecedeWithFillerBackground(object, pre_filler);
  }
  DCHECK_LE(0, filler_size - pre_filler);
  const int post_filler = filler_size - pre_filler;
  if (post_filler) {
    CreateFillerObjectAtBackground(WritableFreeSpace::ForNonExecutableMemory(
        object.address() + object_size, post_filler));
  }
  return object;
}

void* Heap::AllocateExternalBackingStore(
    const std::function<void*(size_t)>& allocate, size_t byte_length) {
  if (!always_allocate() && new_space()) {
    size_t new_space_backing_store_bytes =
        new_space()->ExternalBackingStoreOverallBytes();
    if ((!v8_flags.separate_gc_phases ||
         !incremental_marking()->IsMajorMarking()) &&
        new_space_backing_store_bytes >= 2 * DefaultMaxSemiSpaceSize() &&
        new_space_backing_store_bytes >= byte_length) {
      // Performing a young generation GC amortizes over the allocated backing
      // store bytes and may free enough external bytes for this allocation.
      CollectGarbage(NEW_SPACE,
                     GarbageCollectionReason::kExternalMemoryPressure);
    }
  }
  void* result = allocate(byte_length);
  if (result) return result;
  if (!always_allocate()) {
    for (int i = 0; i < 2; i++) {
      CollectGarbage(OLD_SPACE,
                     GarbageCollectionReason::kExternalMemoryPressure);
      result = allocate(byte_length);
      if (result) return result;
    }
    CollectAllAvailableGarbage(
        GarbageCollectionReason::kExternalMemoryPressure);
  }
  return allocate(byte_length);
}

// When old generation allocation limit is not configured (before the first full
// GC), this method shrinks the initial very large old generation size. This
// method can only shrink allocation limits but not increase it again.
void Heap::ShrinkOldGenerationAllocationLimitIfNotConfigured() {
  if (using_initial_limit() && !initial_limit_overwritten_ &&
      tracer()->SurvivalEventsRecorded()) {
    const size_t minimum_growing_step =
        MemoryController<V8HeapTrait>::MinimumAllocationLimitGrowingStep(
            CurrentHeapGrowingMode());
    size_t new_old_generation_allocation_limit =
        std::max(OldGenerationConsumedBytes() + minimum_growing_step,
                 static_cast<size_t>(
                     static_cast<double>(old_generation_allocation_limit()) *
                     (tracer()->AverageSurvivalRatio() / 100)));
    new_old_generation_allocation_limit = std::min(
        new_old_generation_allocation_limit, old_generation_allocation_limit());
    size_t new_global_allocation_limit = std::max(
        GlobalConsumedBytes() + minimum_growing_step,
        static_cast<size_t>(static_cast<double>(global_allocation_limit()) *
                            (tracer()->AverageSurvivalRatio() / 100)));
    new_global_allocation_limit =
        std::min(new_global_allocation_limit, global_allocation_limit());
    SetOldGenerationAndGlobalAllocationLimit(
        new_old_generation_allocation_limit, new_global_allocation_limit);
  }
}

void Heap::FlushNumberStringCache() {
  // Flush the number to string cache.
  int len = number_string_cache()->length();
  ReadOnlyRoots roots{isolate()};
  for (int i = 0; i < len; i++) {
    number_string_cache()->set(i, roots.undefined_value(), SKIP_WRITE_BARRIER);
  }
}

namespace {

void CreateFillerObjectAtImpl(const WritableFreeSpace& free_space, Heap* heap,
                              ClearFreedMemoryMode clear_memory_mode) {
  int size = free_space.Size();
  if (size == 0) return;
  DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                 IsAligned(free_space.Address(), kObjectAlignment8GbHeap));
  DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                 IsAligned(size, kObjectAlignment8GbHeap));

  // TODO(v8:13070): Filler sizes are irrelevant for 8GB+ heaps. Adding them
  // should be avoided in this mode.
  ReadOnlyRoots roots(heap);
  if (size == kTaggedSize) {
    HeapObject::SetFillerMap(free_space,
                             roots.unchecked_one_pointer_filler_map());
    // Ensure the filler map is properly initialized.
    DCHECK(IsMap(
        HeapObject::FromAddress(free_space.Address())->map(heap->isolate())));
  } else if (size == 2 * kTaggedSize) {
    HeapObject::SetFillerMap(free_space,
                             roots.unchecked_two_pointer_filler_map());
    if (clear_memory_mode == ClearFreedMemoryMode::kClearFreedMemory) {
      free_space.ClearTagged<kTaggedSize>((size / kTaggedSize) - 1);
    }
    // Ensure the filler map is properly initialized.
    DCHECK(IsMap(
        HeapObject::FromAddress(free_space.Address())->map(heap->isolate())));
  } else {
    DCHECK_GT(size, 2 * kTaggedSize);
    HeapObject::SetFillerMap(free_space, roots.unchecked_free_space_map());
    FreeSpace::SetSize(free_space, size, kRelaxedStore);
    if (clear_memory_mode == ClearFreedMemoryMode::kClearFreedMemory) {
      free_space.ClearTagged<2 * kTaggedSize>((size / kTaggedSize) - 2);
    }

    // During bootstrapping we need to create a free space object before its
    // map is initialized. In this case we cannot access the map yet, as it
    // might be null, or not set up properly yet.
    DCHECK_IMPLIES(roots.is_initialized(RootIndex::kFreeSpaceMap),
                   IsMap(HeapObject::FromAddress(free_space.Address())
                             ->map(heap->isolate())));
  }
}

#ifdef DEBUG
void VerifyNoNeedToClearSlots(Address start, Address end) {
  MemoryChunk* chunk = MemoryChunk::FromAddress(start);
  if (chunk->InReadOnlySpace()) return;
  if (!v8_flags.sticky_mark_bits && chunk->InYoungGeneration()) return;
  MutablePageMetadata* mutable_page =
      MutablePageMetadata::cast(chunk->Metadata());
  BaseSpace* space = mutable_page->owner();
  space->heap()->VerifySlotRangeHasNoRecordedSlots(start, end);
}
#else
void VerifyNoNeedToClearSlots(Address start, Address end) {}
#endif  // DEBUG

}  // namespace

void Heap::CreateFillerObjectAtBackground(const WritableFreeSpace& free_space) {
  // TODO(leszeks): Verify that no slots need to be recorded.
  // Do not verify whether slots are cleared here: the concurrent thread is not
  // allowed to access the main thread's remembered set.
  CreateFillerObjectAtRaw(free_space,
                          ClearFreedMemoryMode::kDontClearFreedMemory,
                          ClearRecordedSlots::kNo, VerifyNoSlotsRecorded::kNo);
}

void Heap::CreateFillerObjectAt(Address addr, int size,
                                ClearFreedMemoryMode clear_memory_mode) {
  if (size == 0) return;
  if (MemoryChunk::FromAddress(addr)->executable()) {
    WritableJitPage jit_page(addr, size);
    WritableFreeSpace free_space = jit_page.FreeRange(addr, size);
    CreateFillerObjectAtRaw(free_space, clear_memory_mode,
                            ClearRecordedSlots::kNo,
                            VerifyNoSlotsRecorded::kYes);
  } else {
    WritableFreeSpace free_space =
        WritableFreeSpace::ForNonExecutableMemory(addr, size);
    CreateFillerObjectAtRaw(free_space, clear_memory_mode,
                            ClearRecordedSlots::kNo,
                            VerifyNoSlotsRecorded::kYes);
  }
}

void Heap::CreateFillerObjectAtRaw(
    const WritableFreeSpace& free_space, ClearFreedMemoryMode clear_memory_mode,
    ClearRecordedSlots clear_slots_mode,
    VerifyNoSlotsRecorded verify_no_slots_recorded) {
  // TODO(mlippautz): It would be nice to DCHECK that we never call this
  // with {addr} pointing into large object space; however we currently do,
  // see, e.g., Factory::NewFillerObject and in many tests.
  size_t size = free_space.Size();
  if (size == 0) return;
  CreateFillerObjectAtImpl(free_space, this, clear_memory_mode);
  Address addr = free_space.Address();
  if (clear_slots_mode == ClearRecordedSlots::kYes) {
    ClearRecordedSlotRange(addr, addr + size);
  } else if (verify_no_slots_recorded == VerifyNoSlotsRecorded::kYes) {
    VerifyNoNeedToClearSlots(addr, addr + size);
  }
}

bool Heap::CanMoveObjectStart(Tagged<HeapObject> object) {
  if (!v8_flags.move_object_start) return false;

  // Sampling heap profiler may have a reference to the object.
  if (isolate()->heap_profiler()->is_sampling_allocations()) return false;

  if (IsLargeObject(object)) return false;

  // Compilation jobs may have references to the object.
  if (isolate()->concurrent_recompilation_enabled() &&
      isolate()->optimizing_compile_dispatcher()->HasJobs()) {
    return false;
  }

  // Concurrent marking does not support moving object starts without snapshot
  // protocol.
  //
  // TODO(v8:13726): This can be improved via concurrently reading the contents
  // in the marker at the cost of some complexity.
  if (incremental_marking()->IsMarking()) return false;

  // Concurrent sweeper does not support moving object starts. It assumes that
  // markbits (black regions) and object starts are matching up.
  if (!PageMetadata::FromHeapObject(object)->SweepingDone()) return false;

  return true;
}

bool Heap::IsImmovable(Tagged<HeapObject> object) {
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(object);
  return chunk->NeverEvacuate() || chunk->IsLargePage();
}

bool Heap::IsLargeObject(Tagged<HeapObject> object) {
  return MemoryChunk::FromHeapObject(object)->IsLargePage();
}

#ifdef ENABLE_SLOW_DCHECKS
namespace {

class LeftTrimmerVerifierRootVisitor : public RootVisitor {
 public:
  explicit LeftTrimmerVerifierRootVisitor(Tagged<FixedArrayBase> to_check)
      : to_check_(to_check) {}

  LeftTrimmerVerifierRootVisitor(const LeftTrimmerVerifierRootVisitor&) =
      delete;
  LeftTrimmerVerifierRootVisitor& operator=(
      const LeftTrimmerVerifierRootVisitor&) = delete;

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      // V8_EXTERNAL_CODE_SPACE specific: we might be comparing
      // InstructionStream object with non-InstructionStream object here and it
      // might produce false positives because operator== for tagged values
      // compares only lower 32 bits when pointer compression is enabled.
      DCHECK_NE((*p).ptr(), to_check_.ptr());
    }
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK(root == Root::kStringTable ||
           root == Root::kSharedStructTypeRegistry);
    // We can skip iterating the string table and shared struct type registry,
    // they don't point to any fixed arrays.
  }

 private:
  Tagged<FixedArrayBase> to_check_;
};
}  // namespace
#endif  // ENABLE_SLOW_DCHECKS

namespace {
bool MayContainRecordedSlots(Tagged<HeapObject> object) {
  // New space object do not have recorded slots.
  if (HeapLayout::InYoungGeneration(object)) {
    return false;
  }
  // Allowlist objects that definitely do not have pointers.
  if (IsByteArray(object) || IsFixedDoubleArray(object)) return false;
  // Conservatively return true for other objects.
  return true;
}
}  // namespace

void Heap::OnMoveEvent(Tagged<HeapObject> source, Tagged<HeapObject> target,
                       int size_in_bytes) {
  HeapProfiler* heap_profiler = isolate_->heap_profiler();
  if (heap_profiler->is_tracking_object_moves()) {
    heap_profiler->ObjectMoveEvent(source.address(), target.address(),
                                   size_in_bytes, /*is_embedder_object=*/false);
  }
  for (auto& tracker : allocation_trackers_) {
    tracker->MoveEvent(source.address(), target.address(), size_in_bytes);
  }
  if (IsSharedFunctionInfo(target, isolate_)) {
    LOG_CODE_EVENT(isolate_, SharedFunctionInfoMoveEvent(source.address(),
                                                         target.address()));
  } else if (IsNativeContext(target, isolate_)) {
    if (isolate_->current_embedder_state() != nullptr) {
      isolate_->current_embedder_state()->OnMoveEvent(source.address(),
                                                      target.address());
    }
    PROFILE(isolate_,
            NativeContextMoveEvent(source.address(), target.address()));
  } else if (IsMap(target, isolate_)) {
    LOG(isolate_, MapMoveEvent(Cast<Map>(source), Cast<Map>(target)));
  }
}

Tagged<FixedArrayBase> Heap::LeftTrimFixedArray(Tagged<FixedArrayBase> object,
                                                int elements_to_trim) {
  if (elements_to_trim == 0) {
    // This simplifies reasoning in the rest of the function.
    return object;
  }
  CHECK(!object.is_null());
  DCHECK(CanMoveObjectStart(object));
  // Add custom visitor to concurrent marker if new left-trimmable type
  // is added.
  DCHECK(IsFixedArray(object) || IsFixedDoubleArray(object));
  const int element_size = IsFixedArray(object) ? kTaggedSize : kDoubleSize;
  const int bytes_to_trim = elements_to_trim * element_size;
  Tagged<Map> map = object->map();

  // For now this trick is only applied to fixed arrays which may be in new
  // space or old space. In a large object space the object's start must
  // coincide with chunk and thus the trick is just not applicable.
  DCHECK(!IsLargeObject(object));
  DCHECK(object->map() != ReadOnlyRoots(this).fixed_cow_array_map());

  static_assert(offsetof(FixedArrayBase, map_) == 0);
  static_assert(offsetof(FixedArrayBase, length_) == kTaggedSize);
  static_assert(sizeof(FixedArrayBase) == 2 * kTaggedSize);

  const int len = object->length();
  DCHECK(elements_to_trim <= len);

  // Calculate location of new array start.
  Address old_start = object.address();
  A
```