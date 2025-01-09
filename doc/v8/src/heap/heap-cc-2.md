Response:
Let's break down the thought process for analyzing this V8 heap.cc code snippet.

1. **Initial Understanding - Context is Key:** The first and most important thing is recognizing the context: `v8/src/heap/heap.cc`. This immediately tells us we're dealing with the core memory management within the V8 JavaScript engine. The filename `heap.cc` is a strong indicator of its primary responsibility.

2. **Scanning for Keywords and Patterns:**  I'd quickly scan the code for recurring keywords and patterns. Some obvious ones jump out:

    * **`GarbageCollector::`**:  This is a huge clue. It indicates that the code deals with different types of garbage collection (MARK_COMPACTOR, MINOR_MARK_SWEEPER, SCAVENGER).
    * **`tracer()`**:  This suggests performance monitoring and instrumentation, likely related to GC events.
    * **`incremental_marking()`**: This points to an optimization technique for reducing GC pauses.
    * **`allocation_limit`**:  This signifies memory management strategies to control heap size.
    * **`CompleteSweeping...`**:  This relates to the cleanup phase after marking.
    * **`WriteBarrier`**: This is a standard term in garbage collection, used to track object mutations.
    * **`IdleTask`**:  This suggests background tasks related to GC.
    * **`ContextDisposed`**: This points to handling the cleanup of JavaScript execution environments.
    * **`SafepointScope`**:  This is crucial for understanding how V8 coordinates GC with JavaScript execution. It signifies points where it's safe to perform GC.

3. **Analyzing Individual Code Blocks:** Now, let's examine the key code blocks and their purpose.

    * **`GarbageCollectionEpilogueInSafepoint` block:**  This is a post-GC cleanup phase. I'd note the actions taken: notifying the memory reducer, potentially adjusting the old generation size, stopping tracers, and handling young vs. full GC scenarios. The epilogue callbacks and snapshot creation are also important.

    * **`IdleTaskOnContextDispose` class:**  The name is very descriptive. This task is executed when a JavaScript context is no longer in use. The code attempts to perform a minor GC if there's enough idle time and the young generation is large enough. The time calculations are interesting – it tries to fit the GC within a frame's worth of time to avoid jank.

    * **`Heap::NotifyContextDisposed`:** This function triggers when a context is disposed of. It resets some limits, potentially schedules the idle GC task, and updates a counter.

    * **`Heap::StartIncrementalMarking`:** This is a key function in the incremental GC process. It prepares for and starts the marking phase, coordinating with concurrent threads.

    * **`Heap::CompleteSweepingFull/Young`:** These functions ensure the cleanup phase after marking is finished.

    * **`Heap::MoveRange/CopyRange`:**  These are low-level memory manipulation functions. The conditional logic based on `concurrent_marking` and `minor_ms` is important – it indicates different strategies for moving memory depending on the GC phase. The `WriteBarrier` call is also noteworthy.

    * **`Heap::PerformGarbageCollection`:** This is the core GC execution function. It orchestrates the different phases (sweeping, marking, compaction/scavenging), handles safepoints, and updates statistics.

    * **`Heap::RecomputeLimits`:** This function is responsible for adjusting the memory allocation limits based on GC performance and other factors.

4. **Connecting the Dots and Inferring Functionality:**  After analyzing the individual blocks, the overall functionality starts to become clear. This `heap.cc` file is responsible for:

    * **Garbage Collection Management:**  Implementing different GC algorithms (mark-compact, minor mark-sweep, scavenger) and managing their execution.
    * **Memory Allocation Control:**  Setting and adjusting allocation limits to prevent out-of-memory errors and optimize performance.
    * **Incremental Garbage Collection:**  Using techniques like incremental marking to reduce GC pause times.
    * **Handling Context Disposal:** Cleaning up memory associated with discarded JavaScript execution environments.
    * **Performance Monitoring:** Tracking GC statistics and using them to make decisions about when and how to perform garbage collection.
    * **Concurrency Control:**  Coordinating GC activities with JavaScript execution using safepoints and pausing/resuming concurrent threads.

5. **Considering the "If .tq" Question:** The mention of `.tq` points to Torque, V8's internal type system and code generation language. If this file *were* a `.tq` file, it would likely contain type definitions and potentially some higher-level logic that gets compiled into C++. Since it's `.cc`, it's the actual C++ implementation.

6. **Thinking about JavaScript Relevance:**  The core purpose of this code is to enable JavaScript execution. Without effective garbage collection, JavaScript programs would quickly run out of memory. The examples of memory leaks and performance issues illustrate the consequences of poor memory management in JavaScript.

7. **Anticipating Common Errors:**  Knowing how garbage collection works helps in understanding common JavaScript memory-related errors. Forgetting to dereference objects, creating circular references, and holding onto unnecessary data are all classic examples that can lead to memory leaks and trigger GC more often.

8. **Structuring the Output:** Finally, I'd organize the findings into a structured format, covering the requested aspects: general functions, .tq explanation, JavaScript connection with examples, potential logic/assumptions, common errors, and a concise summary. The breakdown into numbered sections (as in the prompt) makes the information easier to digest.
Let's break down the functionality of the provided C++ code snippet from `v8/src/heap/heap.cc`. This is part 3 of 9, so it likely focuses on a specific aspect of the heap management.

**General Functionality of the Code Snippet:**

This code snippet primarily deals with the **epilogue and interrupt handling of garbage collection cycles**, along with some related tasks like context disposal and incremental marking. Here's a more detailed breakdown:

1. **Garbage Collection Epilogue (`GarbageCollectionEpilogueInSafepoint`)**:
   - **Post-GC Adjustments:** It performs actions immediately after a garbage collection cycle completes, while the JavaScript execution is paused (in a "safepoint").
   - **Memory Reducer Notification:** If a memory reducer is active, it informs it about the completed GC.
   - **Old Generation Size Adjustment:** It checks if the old generation size needs to be reset to its initial maximum if it has shrunk significantly and is below a certain threshold. This is likely an optimization to reclaim potentially wasted space.
   - **Tracing:** It stops the atomic and observable pause timers of the garbage collection tracer, recording the duration of the pause.
   - **Cycle Completion:** It signals the completion of the current GC cycle (young or full) to the tracer.
   - **Ineffective GC Reporting:** For full garbage collections, it checks and potentially reports if the garbage collection was not effective enough (didn't reclaim much memory).

2. **External Callbacks:**
   - It invokes callbacks registered by the embedder (the application using V8) to notify them about the garbage collection event.

3. **Heap Profiling and Usage Counting:**
   - For full garbage collections (Mark-Compactor), it checks flags to potentially trigger:
     - Counting the usage of forced garbage collections.
     - Writing a heap snapshot to disk if configured.

4. **Starting Incremental Marking:**
   - After a minor garbage collection (Scavenger or Minor Mark-Sweep), it attempts to start incremental marking for the next major garbage collection cycle (Mark-Compactor). This is an optimization to spread the work of marking objects over time, reducing long pauses.

5. **Handling Near Heap Limit:**
   - It checks if the heap can be expanded further. If not, it invokes a callback to notify the embedder. If expansion is still not possible, and a flag is set, it writes a heap snapshot before terminating the process due to an out-of-memory condition.

6. **Idle Task on Context Dispose (`IdleTaskOnContextDispose`)**:
   - This class defines an idle-time task that can be scheduled when a JavaScript context is disposed of.
   - **Purpose:** To potentially perform a minor garbage collection in the background if there's enough idle time. This aims to clean up memory associated with the disposed context without impacting foreground performance.
   - **Time Estimation:** It carefully estimates the time required for a minor GC and only proceeds if it fits within the available idle time (constrained by frame time to avoid jank).

7. **Notifying Context Disposal (`Heap::NotifyContextDisposed`)**:
   - When a JavaScript context is disposed of, this function is called.
   - **Actions:**
     - Resets survival events and old generation allocation limits for top-level contexts.
     - If idle garbage collection on context disposal is enabled, it schedules the `IdleTaskOnContextDispose`.
     - Aborts any ongoing concurrent optimization.
     - Clears finalization registries and retained maps associated with the context.
     - Increments a counter tracking disposed contexts.

8. **Starting Incremental Marking (`Heap::StartIncrementalMarking`)**:
   - This function initiates an incremental marking phase for garbage collection.
   - **Prerequisites:** It checks if incremental marking is currently stopped and should be started.
   - **Sweeping Completion:** Ensures that any ongoing sweeping from the previous GC cycle is completed.
   - **Pausing Concurrent Threads:** Pauses concurrent threads that might be accessing the heap.
   - **Tracer Notification:**  Notifies the garbage collection tracer about the start of the cycle.
   - **Flag Setting:** Sets internal flags indicating the current GC flags and callback flags.
   - **Client Isolate Handling:**  Resumes concurrent marking on client isolates in a shared space setup.

9. **Completing Sweeping (`Heap::CompleteSweepingFull`, `Heap::CompleteSweepingYoung`)**:
   - These functions ensure that the sweeping phase of garbage collection (reclaiming memory occupied by dead objects) is finished. `CompleteSweepingFull` handles major GC, and `CompleteSweepingYoung` handles minor GC.

10. **Starting Incremental Marking on Interrupt (`Heap::StartIncrementalMarkingOnInterrupt`, `Heap::StartIncrementalMarkingIfAllocationLimitIsReached`)**:
    - These functions handle situations where incremental marking needs to be triggered based on allocation pressure or interrupt signals. They check if the allocation limit has been reached and initiate the incremental marking process if necessary.

11. **Moving and Copying Memory (`Heap::MoveRange`, `Heap::CopyRange`)**:
    - These are low-level utility functions for moving blocks of memory within the heap.
    - **Write Barriers:** They include logic for write barriers, which are crucial for garbage collection correctness. When an object pointer is modified, the write barrier ensures the garbage collector is aware of the change so it can track object reachability. The behavior differs depending on whether concurrent marking is in progress.

12. **Collection Request Handling (`Heap::CollectionRequested`, `Heap::CollectGarbageForBackground`, `Heap::CheckCollectionRequested`)**:
    - These functions manage requests for garbage collection, potentially triggered by background processes or allocation failures.

13. **Survival Statistics (`Heap::UpdateSurvivalStatistics`)**:
    - This function calculates and updates statistics about how many objects survived a young generation garbage collection. This information is used to tune the garbage collector.

14. **Performing Garbage Collection (`Heap::PerformGarbageCollection`)**:
    - This is the core function that orchestrates the actual garbage collection process.
    - **Phases:** It manages the different phases of GC (sweeping, marking, compaction/scavenging) based on the chosen collector.
    - **Safepoints:** It operates within safepoints to ensure consistency.
    - **Tracing:** It uses the garbage collection tracer to record events and performance data.
    - **Verification:** It can trigger heap verification to check for inconsistencies.
    - **Stub Cache Clearing:**  For full garbage collections, it clears the stub caches, which store compiled code snippets.

15. **Heap Verification (`Heap::PerformHeapVerification`)**:
    - This function initiates a verification pass over the heap to detect potential errors and inconsistencies.

16. **Pausing and Resuming Concurrent Threads (`Heap::PauseConcurrentThreadsInClients`, `Heap::ResumeConcurrentThreadsInClients`)**:
    - These functions are essential for coordinating garbage collection with other threads that might be accessing the heap, especially in a multi-isolate environment.

17. **Collecting Garbage from Different Threads (`Heap::CollectGarbageShared`, `Heap::CollectGarbageFromAnyThread`)**:
    - These functions handle requests for garbage collection originating from different threads, ensuring proper synchronization.

18. **Ensuring Sweeping Completion for Specific Objects (`Heap::EnsureSweepingCompletedForObject`)**:
    - This function ensures that the sweeping phase has completed for the memory page containing a specific object.

19. **Computing New Allocation Limits (`Heap::ComputeNewAllocationLimits`, `Heap::RecomputeLimits`, `Heap::RecomputeLimitsAfterLoadingIfNeeded`)**:
    - These functions are responsible for dynamically adjusting the heap's allocation limits based on various factors like garbage collection performance, mutator (JavaScript code) behavior, and available memory. They aim to balance performance and memory usage.

**If `v8/src/heap/heap.cc` ended with `.tq`:**

If the file ended with `.tq`, it would be a **V8 Torque source file**. Torque is V8's internal language for defining types and implementing some performance-critical runtime functions. Torque code is compiled into C++.

In this specific case, if `heap.tq` existed, it might contain:

- **Type definitions:** Definitions of the various classes and structs related to heap management (e.g., `Heap`, `MemoryChunk`, `GarbageCollector`).
- **Declarations of functions:** Declarations of the C++ functions defined in `heap.cc`.
- **Implementations of some runtime functions:** Potentially implementations of some of the simpler or more type-sensitive heap operations.

**Relationship with Javascript and Javascript Examples:**

This code is fundamental to how JavaScript's memory management works in V8. Here's how it relates and some examples:

- **Garbage Collection is Invisible to Most Javascript:**  JavaScript has automatic garbage collection. Developers don't explicitly free memory like in C or C++. V8's `heap.cc` implements this automatic process.
- **Memory Leaks:** If there are errors in the logic of `heap.cc` or if JavaScript code creates patterns that the garbage collector can't handle (e.g., circular references without breaking them), it can lead to **memory leaks**. The garbage collector might fail to reclaim memory that is no longer needed.

```javascript
// Javascript example illustrating a potential memory leak (circular reference)

function createNodes() {
  let node1 = {};
  let node2 = {};
  node1.next = node2;
  node2.prev = node1;
  // Even if node1 and node2 go out of scope, the circular reference
  // prevents them from being garbage collected if the collector isn't
  // sophisticated enough to detect such cycles (V8's is).
}

createNodes(); // These nodes might linger if not handled correctly.

// Another example: Holding onto large data unnecessarily
let largeData = new Array(1000000).fill({}); // Creates a large array
// ... some operations with largeData ...
// If largeData is still in scope but no longer needed, it consumes memory.
```

- **Performance Impacts:** Frequent or long garbage collection pauses can negatively impact the performance of JavaScript applications, causing stuttering or freezes. The incremental marking techniques in `heap.cc` aim to mitigate this.

```javascript
// Javascript operation that might trigger garbage collection
let lotsOfObjects = [];
for (let i = 0; i < 100000; i++) {
  lotsOfObjects.push({ data: i }); // Creating many objects
}
// As `lotsOfObjects` grows, the garbage collector will eventually need to run.
```

**Code Logic Inference (Hypothetical Input and Output):**

Let's consider the `GarbageCollectionEpilogueInSafepoint` function with a hypothetical scenario:

**Hypothetical Input:**

- `collector`: `GarbageCollector::MARK_COMPACTOR` (a full garbage collection)
- `committed_memory_before`: 100 MB
- `initial_max_old_generation_size_`: 80 MB
- `max_old_generation_size()`: 120 MB
- `OldGenerationSizeOfObjects()`: 70 MB
- `initial_max_old_generation_size_threshold_`: 75 MB

**Expected Output/Logic:**

1. **Memory Reducer Notification:**  `memory_reducer_->NotifyMarkCompact(100 MB)` would be called.
2. **Old Generation Size Adjustment:**
   - `initial_max_old_generation_size_ < max_old_generation_size()` (80 < 120) is true.
   - `OldGenerationSizeOfObjects() < initial_max_old_generation_size_threshold_` (70 < 75) is true.
   - Therefore, `SetOldGenerationAndGlobalMaximumSize(80 MB)` would be called, potentially reducing the maximum size of the old generation back to its initial value since it has shrunk significantly.
3. **Tracing:** The `StopAtomicPause()` and `StopObservablePause()` methods of the tracer would be called to record the pause duration.
4. **Full Cycle Stop:** `tracer()->StopFullCycleIfNeeded()` would be called.
5. **Ineffective Report:** `ReportIneffectiveMarkCompactIfNeeded()` would be called to check if the GC was worthwhile.
6. **External Callbacks:** Registered epilogue callbacks would be invoked.
7. **Heap Profiling/Usage:** Depending on the flags, usage might be counted, and a heap snapshot might be written.
8. **Incremental Marking:**  Since it's a full GC, incremental marking wouldn't be started immediately.

**Common Programming Errors Related to This Code:**

While developers don't directly interact with this C++ code, understanding its behavior helps avoid common JavaScript memory-related errors:

1. **Creating Unnecessary Global Variables:** Global variables persist throughout the application's lifecycle, making them less likely to be garbage collected. This can lead to increased memory usage.
2. **Forgetting to Dereference Objects:** If an object is no longer needed, ensure that all references to it are removed. If references persist, the garbage collector won't be able to reclaim the memory.
3. **Closures Holding onto Large Scopes:** Closures can inadvertently capture variables from their surrounding scope. If the surrounding scope contains large objects, the closure will keep those objects alive even if they are no longer actively used elsewhere.
4. **Event Listeners Not Being Removed:** If event listeners are attached to DOM elements or other objects, they create references. Failing to remove these listeners when they are no longer needed can prevent the associated objects from being garbage collected.
5. **Circular References (as mentioned before):** Although V8's garbage collector can handle many simple circular references, complex or deeply nested cycles might still pose challenges in some scenarios.

**Summary of Functionality (Part 3 of 9):**

This section of `v8/src/heap/heap.cc` primarily focuses on the **post-processing and interrupt handling of garbage collection cycles**. It includes logic for:

- **Finalizing a GC cycle:**  Notifying components, adjusting memory limits, and recording tracing information.
- **Handling context disposal:**  Releasing resources associated with discarded JavaScript execution environments, potentially triggering idle-time garbage collection.
- **Initiating incremental marking:** Starting the process of marking live objects in the background to reduce GC pauses.
- **Managing memory allocation limits:** Dynamically adjusting the heap size based on performance and memory pressure.
- **Providing low-level memory manipulation utilities with write barrier support.**

Essentially, it deals with the book-keeping, optimization, and resource management aspects that occur *around* the core garbage collection algorithms themselves.

Prompt: 
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共9部分，请归纳一下它的功能

"""
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


"""


```