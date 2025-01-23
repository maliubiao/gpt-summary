Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is the second part of a larger file. I need to combine the understanding from the first part (if available) and this part to provide a complete overview.

Here's a breakdown of the thought process:

1. **Identify the core class:** The primary class in this snippet is `Sweeper::SweeperImpl`. This strongly suggests that this class implements the main logic for the sweeping functionality.

2. **Analyze the member functions of `SweeperImpl`:**  Each public member function likely represents a distinct action or state change related to sweeping. I will go through them one by one:
    * `SweeperImpl` (constructor): Initializes the sweeper.
    * `~SweeperImpl` (destructor):  Cleans up resources, specifically canceling sweeping tasks.
    * `Start`: Begins the sweeping process based on a configuration. This involves preparing data structures, scheduling tasks, and handling different sweeping types (incremental, concurrent).
    * `SweepForTask`: Performs a portion of the sweeping work within a foreground task, respecting a time limit. It handles both regular and low-priority sweeping.
    * `SweepForLowPriorityTask`: Similar to `SweepForTask`, but specifically for low-priority tasks.
    * `SweepForLargeAllocation`: Attempts to sweep and finalize large pages to make space for a large allocation.
    * `SweepForNormalAllocation`:  Attempts to sweep and finalize normal pages to make space for a normal allocation.
    * `SweepForAllocationIfRunning`:  Conditionally triggers sweeping for allocation if a sweeping cycle is already active.
    * `FinishIfRunning`: Completes the sweeping process if it's currently active.
    * `IsConcurrentSweepingDone`: Checks if the concurrent sweeping phase is finished.
    * `FinishIfOutOfWork`:  Finishes sweeping if the concurrent sweeper has completed all its work.
    * `Finish`: Forces the completion of the sweeping process.
    * `FinalizeSweep`:  Performs the finalization steps after sweeping.
    * `NotifyDone`: Signals that the sweeping process is complete.
    * `WaitForConcurrentSweepingForTesting`: A testing-specific function to wait for the concurrent sweeper to finish.
    * `IsSweepingOnMutatorThread`: Indicates if sweeping is currently executing on the main thread.
    * `IsSweepingInProgress`: Indicates if a sweeping cycle is active.
    * `PerformSweepOnMutatorThread`: Executes a sweep operation directly on the main thread, respecting a time limit and a sweeping mode.
    * `AddMutatorThreadSweepingObserver`, `RemoveMutatorThreadSweepingObserver`:  Mechanisms for observing when sweeping starts and ends on the main thread.

3. **Analyze the private members of `SweeperImpl`:** These members represent the internal state and dependencies of the sweeper.
    * `heap_`: A reference to the heap.
    * `page_pool_`: Manages the pool of pages.
    * `stats_collector_`: Collects statistics related to sweeping.
    * `space_states_`: Tracks the sweeping state of each space.
    * `empty_normal_pages_`, `empty_large_pages_`: Track empty pages for different sizes.
    * `unused_destroyed_normal_pages_`: Counts destroyed pages not yet reused.
    * `platform_`:  Provides platform-specific functionalities, like task scheduling.
    * Task runners (`foreground_task_runner_`, `low_priority_foreground_task_runner_`): Used for scheduling sweeping tasks.
    * Configuration (`config_`): Stores the sweeping configuration.
    * Task handles (`incremental_sweeper_handle_`, `incremental_sweeper_low_priority_handle_`, `concurrent_sweeper_handle_`):  Used to manage scheduled tasks.
    * Observers (`mutator_thread_sweeping_observers_`):  List of observers for main-thread sweeping.
    * Flags (`low_priority_task_ran_`, `is_in_progress_`, `notify_done_pending_`, `is_sweeping_on_mutator_thread_`): Track the current state of the sweeper.

4. **Identify key concepts and mechanisms:**  The code utilizes several important concepts:
    * **Incremental Sweeping:** Performing sweeping in smaller chunks to avoid long pauses.
    * **Concurrent Sweeping:** Performing sweeping in a separate background thread.
    * **Finalization:**  Running finalizers on objects that are no longer needed.
    * **Task Scheduling:** Using platform-specific task runners to manage sweeping work.
    * **Sweeping States:**  Keeping track of the state of pages (unswept, swept, finalized).
    * **Empty Page Handling:**  Special handling for empty pages to quickly reuse them.
    * **Large Object Handling:** Separate handling for large objects.

5. **Consider the surrounding context:** The `Sweeper` class acts as a facade for the `SweeperImpl`. The code interacts with other heap management components like `HeapBase`, `PagePool`, `StatsCollector`, and the platform.

6. **Address the specific questions:**
    * **Functionality:** Summarize the actions and responsibilities identified in steps 2 and 4.
    * **Torque:** Check if the filename ends with `.tq`. It doesn't, so it's not Torque code.
    * **JavaScript relation:**  Sweeping is a memory management technique, analogous to garbage collection in JavaScript. Provide a simple JavaScript example of garbage collection.
    * **Code logic inference:** Choose a function with clear logic (e.g., `SweepForLargeAllocation`) and explain its input, steps, and potential output.
    * **Common programming errors:** Relate sweeping to memory leaks, a common problem if memory is not reclaimed properly.
    * **Overall functionality (part 2):**  Focus on the aspects covered in this specific snippet, like the `SweeperImpl` and its methods for managing the sweeping process.

By following these steps, I can generate a comprehensive and accurate summary of the provided code.
这是 `v8/src/heap/cppgc/sweeper.cc` 的第二部分代码，它延续了第一部分中定义的辅助类和结构体，并实现了 `Sweeper` 类的核心功能。以下是这部分代码功能的归纳：

**核心功能：`Sweeper::SweeperImpl` 类**

`SweeperImpl` 类是 `Sweeper` 类的实际实现，负责执行垃圾回收的清理（sweeping）阶段。其主要功能包括：

1. **启动清理 (`Start`)**:
   - 接收 `SweepingConfig` 对象，配置清理的类型（原子、增量、并发等）和行为。
   - 初始化清理所需的状态，例如 `space_states_`（记录每个内存空间的清理状态）以及 `empty_normal_pages_` 和 `empty_large_pages_`（记录空闲页面的状态）。
   - 根据配置安排不同类型的清理任务：
     - **低优先级增量清理 (`ScheduleLowPriorityIncrementalSweeping`)**: 在后台以较低优先级逐步清理。
     - **增量清理 (`ScheduleIncrementalSweeping`)**:  在前景任务中逐步清理。
     - **并发清理 (`ScheduleConcurrentSweeping`)**:  在独立的后台任务中并行清理。

2. **执行清理任务 (`SweepForTask`, `SweepForLowPriorityTask`)**:
   - 在指定的最大时间内执行一部分清理工作。
   - `SweepForTask` 用于普通优先级的前景任务，`SweepForLowPriorityTask` 用于低优先级的前景任务。
   - 根据并发清理的状态调整清理策略。

3. **响应内存分配请求时的清理 (`SweepForLargeAllocation`, `SweepForNormalAllocation`, `SweepForAllocationIfRunning`)**:
   - 当分配内存时，如果正在进行清理，可以尝试快速清理或释放一些页面以满足分配需求。
   - `SweepForLargeAllocation` 专门处理大型对象的分配。
   - `SweepForNormalAllocation` 处理普通大小对象的分配。
   - `SweepForAllocationIfRunning` 只有在清理正在进行时才会触发。

4. **完成清理 (`FinishIfRunning`, `FinishIfOutOfWork`, `Finish`, `FinalizeSweep`)**:
   - 提供多种方式来完成清理过程：
     - `FinishIfRunning`: 如果清理正在进行，则完成它。
     - `FinishIfOutOfWork`: 如果并发清理已完成所有工作，则完成清理。
     - `Finish`: 强制完成清理过程，包括同步并发清理器并调用终结器。
     - `FinalizeSweep`: 执行清理的最终步骤，例如同步并发清理器、调用终结器和清除清理元数据。

5. **通知清理完成 (`NotifyDone`)**:
   - 在清理完成后，通知统计收集器，并可能释放池化的页面。

6. **管理并发清理任务 (`ScheduleConcurrentSweeping`, `CancelAllSweepingTasks`, `SynchronizeAndFinalizeConcurrentAndIncrementalSweeping`, `WaitForConcurrentSweepingForTesting`, `IsConcurrentSweepingDone`)**:
   - 启动、取消和同步并发清理任务。
   - `WaitForConcurrentSweepingForTesting` 是用于测试的，等待并发清理完成。
   - `IsConcurrentSweepingDone` 检查并发清理是否已完成。

7. **管理在主线程上执行的清理 (`PerformSweepOnMutatorThread`, `MutatorThreadSweepingScope`)**:
   - 允许在主线程上执行清理操作，通常用于增量清理的步骤。
   - `MutatorThreadSweepingScope` 用于标记在主线程上执行清理的范围，并通知观察者。

8. **观察者模式 (`AddMutatorThreadSweepingObserver`, `RemoveMutatorThreadSweepingObserver`, `SweepingOnMutatorThreadObserver`)**:
   - 允许其他组件观察主线程上清理的开始和结束。

**与 JavaScript 功能的关系**

`v8/src/heap/cppgc/sweeper.cc` 中实现的清理功能类似于 JavaScript 引擎中的垃圾回收机制。当 JavaScript 代码执行时，会创建各种对象。不再使用的对象需要被回收以释放内存。`sweeper.cc` 负责执行这个回收过程中的一个重要阶段：清理。

在 JavaScript 中，你无法直接控制或观察到清理过程的细节。但是，当 JavaScript 代码创建大量临时对象或存在内存泄漏时，你可能会观察到性能下降，这与垃圾回收（包括清理阶段）有关。

**JavaScript 示例 (概念性)**

虽然不能直接映射到 C++ 的 `sweeper.cc`，但可以想象以下 JavaScript 代码执行后，V8 的垃圾回收器会进行清理操作：

```javascript
function createLotsOfObjects() {
  for (let i = 0; i < 100000; i++) {
    let obj = { data: new Array(1000) }; // 创建大量对象
  }
}

createLotsOfObjects(); // 执行后，这些对象可能不再被引用，需要被垃圾回收
```

在这个例子中，`createLotsOfObjects` 函数创建了大量的临时对象。一旦函数执行完毕，这些对象如果没有被其他地方引用，就成为了垃圾。V8 的垃圾回收器，包括 `sweeper.cc` 中实现的清理阶段，会负责回收这些不再使用的内存。

**代码逻辑推理**

假设输入：一个 `LargePage` 对象 `page`，其 `marked_bytes()` 为非零值。

```c++
    for (Page* page : unswept_pages_) {
#ifdef DEBUG
      ObjectHeader* header = BasePage::From(page)->ObjectHeader();
      DCHECK_IMPLIES(page->marked_bytes() == 0, !header->IsMarked());
      DCHECK_IMPLIES(page->marked_bytes() != 0, header->IsMarked());
#endif  // DEBUG
      if (page->marked_bytes() != 0) {
        MutatorThreadSweeper::SweepLiveLargePage(*LargePage::From(page),
                                                 heap_->sticky_bits());
      } else {
        empty_large_pages_->unswept_pages.Push(page);
      }
    }
```

输出：`MutatorThreadSweeper::SweepLiveLargePage` 函数被调用，对该 `LargePage` 进行清理。

推理：代码遍历未清理的页面。如果一个大型页面 (`page->marked_bytes() != 0`) 上有标记的字节（意味着其中存在存活的对象），则调用 `SweepLiveLargePage` 来清理该页面上的存活对象。

**用户常见的编程错误**

清理阶段的目标是回收不再使用的内存。用户常见的编程错误可能导致内存无法被正确回收，从而影响清理效率甚至导致内存泄漏：

1. **忘记取消事件监听器或回调函数**: 如果对象持有对其他对象的引用（例如通过事件监听器），即使该对象本身不再被使用，它引用的对象也可能无法被回收。
   ```javascript
   let element = document.getElementById('myButton');
   let handler = function() { console.log('Clicked!'); };
   element.addEventListener('click', handler);

   // ... 稍后，如果 element 被移除，但 handler 仍然持有对外部作用域的引用，可能导致内存泄漏
   // 应该移除事件监听器: element.removeEventListener('click', handler);
   ```

2. **闭包中的意外引用**: 闭包可以捕获外部作用域的变量。如果闭包的生命周期比外部作用域长，可能导致外部作用域的变量无法被回收。
   ```javascript
   function createClosure() {
     let largeData = new Array(1000000);
     return function() {
       console.log(largeData.length); // 闭包引用了 largeData
     };
   }

   let myClosure = createClosure();
   // 即使 createClosure 执行完毕，myClosure 仍然持有对 largeData 的引用
   ```

3. **循环引用**: 对象之间相互引用，导致垃圾回收器无法判断它们是否可回收。
   ```javascript
   let obj1 = {};
   let obj2 = {};
   obj1.ref = obj2;
   obj2.ref = obj1;
   // obj1 和 obj2 相互引用，即使没有其他引用指向它们，也可能难以回收（取决于垃圾回收器的实现）
   ```

**总结 `v8/src/heap/cppgc/sweeper.cc` 的功能 (第二部分)**

第二部分的代码主要实现了 `Sweeper::SweeperImpl` 类，该类负责执行 cppgc 垃圾回收器的清理（sweeping）阶段。它管理清理任务的启动、执行和完成，并处理不同类型的清理（增量、并发）。此外，它还负责在内存分配时触发清理，以尽可能地重用空闲内存。该部分代码与 JavaScript 的垃圾回收功能紧密相关，负责回收不再使用的 C++ 对象所占用的内存，类似于 JavaScript 垃圾回收器回收不再使用的 JavaScript 对象。 代码中还包含了用于测试和观察清理过程的机制。

### 提示词
```
这是目录为v8/src/heap/cppgc/sweeper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/sweeper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
:From(page)->ObjectHeader();
      DCHECK_IMPLIES(page->marked_bytes() == 0, !header->IsMarked());
      DCHECK_IMPLIES(page->marked_bytes() != 0, header->IsMarked());
#endif  // DEBUG
      if (page->marked_bytes() != 0) {
        MutatorThreadSweeper::SweepLiveLargePage(*LargePage::From(page),
                                                 heap_->sticky_bits());
      } else {
        empty_large_pages_->unswept_pages.Push(page);
      }
    }

    return true;
  }

 private:
  HeapBase* const heap_;
  SpaceStates* const space_states_;
  SweepingState* const empty_normal_pages_;
  SweepingState* const empty_large_pages_;
  CompactableSpaceHandling compactable_space_handling_;
};

}  // namespace

class Sweeper::SweeperImpl final {
  using FreeMemoryHandling = SweepingConfig::FreeMemoryHandling;

 public:
  explicit SweeperImpl(HeapBase& heap)
      : heap_(heap.raw_heap()),
        page_pool_(heap.page_backend()->page_pool()),
        stats_collector_(heap.stats_collector()),
        platform_(heap.platform()) {
    CHECK_NOT_NULL(platform_);
  }

  ~SweeperImpl() { CancelAllSweepingTasks(); }

  void Start(SweepingConfig config) {
    StatsCollector::EnabledScope stats_scope(stats_collector_,
                                             StatsCollector::kAtomicSweep);
    is_in_progress_ = true;
    config_ = config;

    if (!foreground_task_runner_) {
      // The sweeper is already initialized when the platform may not be able to
      // return a foreground task runner. Lazily initialize the runners on first
      // sweep.
      foreground_task_runner_ =
          platform_->GetForegroundTaskRunner(kForegroundRegularPriority);
      low_priority_foreground_task_runner_ =
          platform_->GetForegroundTaskRunner(kForegroundLowPriority);
      // Having a low priority runner implies having a regular runner as well.
      CHECK_IMPLIES(low_priority_foreground_task_runner_.get(),
                    foreground_task_runner_.get());
    }

    // Verify bitmap for all spaces regardless of |compactable_space_handling|.
    ObjectStartBitmapVerifier().Verify(heap_);

    // If inaccessible memory is touched to check whether it is set up
    // correctly it cannot be discarded.
    if (!CanDiscardMemory()) {
      config_.free_memory_handling = FreeMemoryHandling::kDoNotDiscard;
    }
    if (config_.free_memory_handling ==
        FreeMemoryHandling::kDiscardWherePossible) {
      // The discarded counter will be recomputed.
      heap_.heap()->stats_collector()->ResetDiscardedMemory();
    }

    PrepareForSweepVisitor(heap_.heap(), &space_states_, &empty_normal_pages_,
                           &empty_large_pages_,
                           config.compactable_space_handling)
        .Run(heap_);

    if (config.sweeping_type >= SweepingConfig::SweepingType::kIncremental) {
      ScheduleLowPriorityIncrementalSweeping();
      ScheduleIncrementalSweeping(kDelayWhileLowPrioritySweepingMakesProgress);
    }
    if (config.sweeping_type >=
        SweepingConfig::SweepingType::kIncrementalAndConcurrent) {
      ScheduleConcurrentSweeping();
    }
  }

  void SweepForTask(v8::base::TimeDelta max_duration) {
    // Before sweeping in a task, handle low priority sweeping cases. These are
    // no-ops if low priority sweeping is not running.
    if (low_priority_task_ran_) {
      // Low priority task made progress. Reschedule with delay.
      ScheduleIncrementalSweeping(kDelayWhileLowPrioritySweepingMakesProgress);
      return;
    }

    // Low priority sweeping is not running or not being invoked on time.
    switch (
        SweepInForegroundTaskImpl(max_duration, StatsCollector::kSweepInTask)) {
      case SweepResult::kFullyDone:
        return;
      case SweepResult::kInProgress:
        ScheduleIncrementalSweeping(kDelayForRegularPrioritySweeping);
        return;
      case SweepResult::kMainThreadDoneConcurrentInProgress:
        // Throttle incremental sweeping while the concurrent Job is still
        // making progress.
        ScheduleIncrementalSweeping(kDelayWhileConcurrentSweepingMakesProgress);
        return;
    }
    UNREACHABLE();
  }

  void SweepForLowPriorityTask(v8::base::TimeDelta max_duration) {
    low_priority_task_ran_ = true;
    switch (SweepInForegroundTaskImpl(
        max_duration, StatsCollector::kSweepInLowPriorityTask)) {
      case SweepResult::kFullyDone:
        return;
      case SweepResult::kInProgress:
        // More work to do. Continue sweeping with low priority.
        ScheduleLowPriorityIncrementalSweeping();
        return;
      case SweepResult::kMainThreadDoneConcurrentInProgress:
        ScheduleLowPriorityIncrementalSweeping(
            kDelayWhileLowPrioritySweepingMakesProgress);
        return;
    }
    UNREACHABLE();
  }

  bool SweepForLargeAllocation(BaseSpace* space, size_t size,
                               v8::base::TimeDelta max_duration) {
    DCHECK(space->is_large());
#ifdef DEBUG
    // SpaceState for large objects is emtpy as those objects are put directly
    // on `empty_large_pages_`.
    SweepingState& space_state = space_states_[space->index()];
    DCHECK(space_state.unswept_pages.IsEmpty());
    DCHECK(space_state.swept_unfinalized_pages.IsEmpty());
#endif  // DEBUG
    // Bail out if there's no empty large pages that could be freed and be
    // reused for a large allocation.
    if (empty_large_pages_.swept_unfinalized_pages.IsEmpty() &&
        empty_large_pages_.unswept_pages.IsEmpty()) {
      return false;
    }

    StatsCollector::EnabledScope incremental_sweep_scope(
        stats_collector_, StatsCollector::kIncrementalSweep);
    StatsCollector::DisabledScope sweep_on_allocation_scope(
        stats_collector_, StatsCollector::kSweepOnAllocation);
    MutatorThreadSweepingScope sweeping_in_progress(*this);

    const auto deadline = v8::base::TimeTicks::Now() + max_duration;

    SweepFinalizer finalizer(
        platform_, stats_collector_, space, &unused_destroyed_normal_pages_,
        config_.free_memory_handling, EmptyPageHandling::kDestroy);
    // Check empty pages first. Try to just finalize a page without sweeping.
    // If there's a single page in there we will use it.
    if (finalizer.FinalizeWithDeadlineAndSize(
            StatsCollector::kSweepFinalizeEmptyPages, empty_large_pages_,
            deadline, size)) {
      return true;
    }
    MutatorThreadSweeper sweeper(heap_.heap(), platform_, stats_collector_,
                                 space, &unused_destroyed_normal_pages_,
                                 config_.free_memory_handling,
                                 EmptyPageHandling::kDestroy);
    // Sweeping an empty page in case there's nothing with finalizers. If
    // there's a single page in there we will use it.
    if (sweeper.SweepWithDeadlineAndSize(StatsCollector::kSweepEmptyPages,
                                         empty_large_pages_, deadline, size)) {
      return true;
    }

    return false;
  }

  bool SweepForNormalAllocation(BaseSpace* space, size_t size,
                                v8::base::TimeDelta max_duration) {
    DCHECK(!space->is_large());

    if (unused_destroyed_normal_pages_ > 0 && page_pool_.pooled() > 0) {
      unused_destroyed_normal_pages_--;
      // Destroyed pages during sweeping in tasks are generally sitting in the
      // page pool and can be reused without increasing memory footprint.
      return false;
    }

    SweepingState& space_state = space_states_[space->index()];

    // Bail out if there's no empty pages and no pages to be processed for the
    // specific space at this moment.
    if (empty_normal_pages_.swept_unfinalized_pages.IsEmpty() &&
        empty_normal_pages_.unswept_pages.IsEmpty() &&
        space_state.swept_unfinalized_pages.IsEmpty() &&
        space_state.unswept_pages.IsEmpty()) {
      return false;
    }

    StatsCollector::EnabledScope incremental_sweep_scope(
        stats_collector_, StatsCollector::kIncrementalSweep);
    StatsCollector::DisabledScope sweep_on_allocation_scope(
        stats_collector_, StatsCollector::kSweepOnAllocation);
    MutatorThreadSweepingScope sweeping_in_progress(*this);

    const auto deadline = v8::base::TimeTicks::Now() + max_duration;

    SweepFinalizer finalizer(
        platform_, stats_collector_, space, &unused_destroyed_normal_pages_,
        config_.free_memory_handling, EmptyPageHandling::kReturn);
    // Check empty pages first. Try to just finalize a page without sweeping.
    // If there's a single page in there we will use it.
    if (finalizer.FinalizeWithDeadlineAndSize(
            StatsCollector::kSweepFinalizeEmptyPages, empty_normal_pages_,
            deadline, size)) {
      return true;
    }
    MutatorThreadSweeper sweeper(heap_.heap(), platform_, stats_collector_,
                                 space, &unused_destroyed_normal_pages_,
                                 config_.free_memory_handling,
                                 EmptyPageHandling::kReturn);
    // Sweeping an empty page in case there's nothing with finalizers. If
    // there's a single page in there we will use it.
    if (sweeper.SweepWithDeadlineAndSize(StatsCollector::kSweepEmptyPages,
                                         empty_normal_pages_, deadline, size)) {
      return true;
    }

    // Process unfinalized non-empty pages as finalizing a page is generally
    // faster than sweeping.
    if (finalizer.FinalizeWithDeadlineAndSize(
            StatsCollector::kSweepFinalizeSweptPages, space_state, deadline,
            size)) {
      return true;
    }
    // Then, if no matching slot is found in the unfinalized pages, search the
    // unswept page. This also helps out the concurrent sweeper.
    if (sweeper.SweepWithDeadlineAndSize(StatsCollector::kSweepPages,
                                         space_state, deadline, size)) {
      return true;
    }
    return false;
  }

  bool SweepForAllocationIfRunning(BaseSpace* space, size_t size,
                                   v8::base::TimeDelta max_duration) {
    if (!is_in_progress_) {
      return false;
    }

    // Bail out for recursive sweeping calls. This can happen when finalizers
    // allocate new memory.
    if (is_sweeping_on_mutator_thread_) {
      return false;
    }

    return space->is_large()
               ? SweepForLargeAllocation(space, size, max_duration)
               : SweepForNormalAllocation(space, size, max_duration);
  }

  bool FinishIfRunning() {
    if (!is_in_progress_) {
      return false;
    }

    // Bail out for recursive sweeping calls. This can happen when finalizers
    // allocate new memory.
    if (is_sweeping_on_mutator_thread_) {
      return false;
    }

    {
      std::optional<StatsCollector::EnabledScope> stats_scope;
      if (config_.sweeping_type != SweepingConfig::SweepingType::kAtomic) {
        stats_scope.emplace(stats_collector_,
                            StatsCollector::kIncrementalSweep);
      }
      StatsCollector::EnabledScope inner_scope(stats_collector_,
                                               StatsCollector::kSweepFinish);
      if (concurrent_sweeper_handle_ && concurrent_sweeper_handle_->IsValid() &&
          concurrent_sweeper_handle_->UpdatePriorityEnabled()) {
        concurrent_sweeper_handle_->UpdatePriority(kBackgroundBoostedPriority);
      }
      Finish();
    }
    NotifyDone();
    return true;
  }

  bool IsConcurrentSweepingDone() const {
    return !concurrent_sweeper_handle_ ||
           !concurrent_sweeper_handle_->IsValid() ||
           !concurrent_sweeper_handle_->IsActive();
  }

  void FinishIfOutOfWork() {
    if (!is_in_progress_ || is_sweeping_on_mutator_thread_) {
      return;
    }
    // We only finish through this method if concurrent sweeping is enabled but
    // not running anymore. All other paths finish sweeping through incremental
    // steps.
    if (!concurrent_sweeper_handle_ || !concurrent_sweeper_handle_->IsValid() ||
        concurrent_sweeper_handle_->IsActive()) {
      return;
    }
    // At this point we know that the concurrent sweeping task has run
    // out-of-work: all pages are swept. The main thread still needs to finalize
    // swept pages.
    DCHECK(std::all_of(space_states_.begin(), space_states_.end(),
                       [](const SweepingState& state) {
                         return state.unswept_pages.IsEmpty();
                       }));
    DCHECK(empty_normal_pages_.unswept_pages.IsEmpty());
    DCHECK(empty_large_pages_.unswept_pages.IsEmpty());
    if (std::any_of(space_states_.begin(), space_states_.end(),
                    [](const SweepingState& state) {
                      return !state.swept_unfinalized_pages.IsEmpty();
                    })) {
      return;
    }
    if (!empty_normal_pages_.swept_unfinalized_pages.IsEmpty() ||
        !empty_large_pages_.swept_unfinalized_pages.IsEmpty()) {
      return;
    }
    // All pages have also been finalized. Finalizing pages likely occured on
    // allocation, in which sweeping is not finalized even though all work is
    // done.
    {
      StatsCollector::EnabledScope stats_scope(
          stats_collector_, StatsCollector::kSweepFinishIfOutOfWork);
      FinalizeSweep();
    }
    NotifyDone();
  }

  void Finish() {
    DCHECK(is_in_progress_);

    MutatorThreadSweepingScope sweeping_in_progress(*this);

    // First, call finalizers on the mutator thread. This is just an
    // optimization as we need to call finalizers after sweeping as well. It
    // allows to spend the time in the concurrent sweeper for actual sweeping.
    SweepFinalizer finalizer(
        platform_, stats_collector_, kSweepWithoutSpaceAssignment,
        &unused_destroyed_normal_pages_, config_.free_memory_handling,
        EmptyPageHandling::kDestroy);
    finalizer.Finalize(space_states_);
    finalizer.Finalize(empty_normal_pages_);
    finalizer.Finalize(empty_large_pages_);

    // Then, help out the concurrent thread.
    MutatorThreadSweeper sweeper(
        heap_.heap(), platform_, stats_collector_, kSweepWithoutSpaceAssignment,
        &unused_destroyed_normal_pages_, config_.free_memory_handling,
        EmptyPageHandling::kDestroy);
    sweeper.Sweep(space_states_);
    sweeper.Sweep(empty_normal_pages_);
    sweeper.Sweep(empty_large_pages_);

    // There's nothing left to sweep here for the main thread. The concurrent
    // sweeper may still sweep pages and create pages to be finalized after
    // joining the the job.
    FinalizeSweep();
  }

  void FinalizeSweep() {
    // Synchronize with the concurrent sweeper and call remaining finalizers.
    SynchronizeAndFinalizeConcurrentAndIncrementalSweeping();

    // Clear space taken up by sweeper metadata.
    space_states_.clear();

    is_in_progress_ = false;
    notify_done_pending_ = true;
    unused_destroyed_normal_pages_ = 0;
  }

  void NotifyDone() {
    DCHECK(!is_in_progress_);
    DCHECK(notify_done_pending_);
    notify_done_pending_ = false;
    stats_collector_->NotifySweepingCompleted(config_.sweeping_type);
    if (config_.free_memory_handling ==
        FreeMemoryHandling::kDiscardWherePossible)
      heap_.heap()->page_backend()->DiscardPooledPages();
  }

  void WaitForConcurrentSweepingForTesting() {
    if (concurrent_sweeper_handle_) concurrent_sweeper_handle_->Join();
  }

  bool IsSweepingOnMutatorThread() const {
    return is_sweeping_on_mutator_thread_;
  }

  bool IsSweepingInProgress() const { return is_in_progress_; }

  bool PerformSweepOnMutatorThread(v8::base::TimeDelta max_duration,
                                   StatsCollector::ScopeId internal_scope_id,
                                   MutatorThreadSweepingMode sweeping_mode) {
    if (!is_in_progress_) return true;

    MutatorThreadSweepingScope sweeping_in_progress(*this);

    {
      StatsCollector::EnabledScope stats_scope(
          stats_collector_, StatsCollector::kIncrementalSweep);

      MutatorThreadSweeper sweeper(
          heap_.heap(), platform_, stats_collector_,
          kSweepWithoutSpaceAssignment, &unused_destroyed_normal_pages_,
          config_.free_memory_handling, EmptyPageHandling::kDestroy);
      {
        StatsCollector::EnabledScope inner_stats_scope(
            stats_collector_, internal_scope_id, "max_duration_ms",
            max_duration.InMillisecondsF(), "sweeping_mode",
            ToString(sweeping_mode));
        const auto deadline = v8::base::TimeTicks::Now() + max_duration;
        if (!sweeper.FinalizeAndSweepWithDeadline(
                StatsCollector::kSweepFinalizeEmptyPages, empty_normal_pages_,
                deadline, sweeping_mode)) {
          return false;
        }
        for (auto& state : space_states_) {
          if (!sweeper.FinalizeAndSweepWithDeadline(
                  StatsCollector::kSweepFinalizeSweptPages, state, deadline,
                  sweeping_mode)) {
            return false;
          }
        }
        if (!sweeper.FinalizeAndSweepWithDeadline(
                StatsCollector::kSweepFinalizeEmptyPages, empty_large_pages_,
                deadline, sweeping_mode)) {
          return false;
        }
        if (sweeping_mode != MutatorThreadSweepingMode::kAll) {
          return false;
        }
      }
      FinalizeSweep();
    }
    NotifyDone();
    return true;
  }

  void AddMutatorThreadSweepingObserver(
      Sweeper::SweepingOnMutatorThreadObserver* observer) {
    DCHECK_EQ(mutator_thread_sweeping_observers_.end(),
              std::find(mutator_thread_sweeping_observers_.begin(),
                        mutator_thread_sweeping_observers_.end(), observer));
    mutator_thread_sweeping_observers_.push_back(observer);
  }

  void RemoveMutatorThreadSweepingObserver(
      Sweeper::SweepingOnMutatorThreadObserver* observer) {
    const auto it =
        std::find(mutator_thread_sweeping_observers_.begin(),
                  mutator_thread_sweeping_observers_.end(), observer);
    DCHECK_NE(mutator_thread_sweeping_observers_.end(), it);
    mutator_thread_sweeping_observers_.erase(it);
  }

 private:
  class MutatorThreadSweepingScope final {
   public:
    explicit MutatorThreadSweepingScope(SweeperImpl& sweeper)
        : sweeper_(sweeper) {
      DCHECK(!sweeper_.is_sweeping_on_mutator_thread_);
      sweeper_.is_sweeping_on_mutator_thread_ = true;
      for (auto* observer : sweeper_.mutator_thread_sweeping_observers_) {
        observer->Start();
      }
    }
    ~MutatorThreadSweepingScope() {
      sweeper_.is_sweeping_on_mutator_thread_ = false;
      for (auto* observer : sweeper_.mutator_thread_sweeping_observers_) {
        observer->End();
      }
    }

    MutatorThreadSweepingScope(const MutatorThreadSweepingScope&) = delete;
    MutatorThreadSweepingScope& operator=(const MutatorThreadSweepingScope&) =
        delete;

   private:
    SweeperImpl& sweeper_;
  };

  class IncrementalSweepTask final : public cppgc::Task {
   public:
    using Handle = SingleThreadedHandle;

    static constexpr auto kMaxSweepDuration =
        v8::base::TimeDelta::FromMilliseconds(5);

    IncrementalSweepTask(SweeperImpl& sweeper, cppgc::TaskPriority priority)
        : sweeper_(sweeper),
          handle_(Handle::NonEmptyTag{}),
          priority_(priority) {}

    static Handle Post(SweeperImpl& sweeper,
                       const std::shared_ptr<cppgc::TaskRunner>& runner,
                       cppgc::TaskPriority priority,
                       std::optional<v8::base::TimeDelta> delay = {}) {
      auto task = std::make_unique<IncrementalSweepTask>(sweeper, priority);
      auto handle = task->handle_;
      if (delay.has_value()) {
        runner->PostDelayedTask(std::move(task), delay->InSecondsF());
      } else {
        runner->PostTask(std::move(task));
      }
      return handle;
    }

    void Run() override {
      if (handle_.IsCanceled()) {
        return;
      }
      switch (priority_) {
        case kForegroundRegularPriority:
          sweeper_.SweepForTask(kMaxSweepDuration);
          return;
        case kForegroundLowPriority:
          sweeper_.SweepForLowPriorityTask(kMaxSweepDuration);
          return;
        default:
          UNREACHABLE();
      }
    }

   private:
    SweeperImpl& sweeper_;
    // TODO(chromium:1056170): Change to CancelableTask.
    Handle handle_;
    cppgc::TaskPriority priority_;
  };

  enum class SweepResult {
    // Sweeping is fully done.
    kFullyDone,
    // Sweeping is still in progress.
    kInProgress,
    // Sweeping on the main thread is done but concurrent sweepers are still
    // making progress. This may be temporary.
    kMainThreadDoneConcurrentInProgress,
  };

  static constexpr double kMaxHeapPercentageForNoSweeping = 50;

  static constexpr auto kDelayWhileLowPrioritySweepingMakesProgress =
      v8::base::TimeDelta::FromMilliseconds(100);

  static constexpr auto kDelayWhileConcurrentSweepingMakesProgress =
      v8::base::TimeDelta::FromMilliseconds(5);

  // We use a small delay here to allow lower priority tasks to interrupt
  // sweeping and take over.
  static constexpr auto kDelayForRegularPrioritySweeping =
      v8::base::TimeDelta::FromMilliseconds(1);

  SweepResult SweepInForegroundTaskImpl(v8::base::TimeDelta max_duration,
                                        StatsCollector::ScopeId scope) {
    // First round of sweeping.
    bool concurrent_sweep_complete = IsConcurrentSweepingDone();
    const auto start = v8::base::TimeTicks::Now();
    bool main_thread_sweep_complete = PerformSweepOnMutatorThread(
        max_duration, scope,
        concurrent_sweep_complete ? MutatorThreadSweepingMode::kAll
                                  : MutatorThreadSweepingMode::kOnlyFinalizers);
    if (main_thread_sweep_complete && !concurrent_sweep_complete &&
        IsConcurrentSweepingDone()) {
      // Concurrent sweeping finished while processing the first round. Use the
      // left over time for a second round to avoid scheduling another task.
      max_duration -= (v8::base::TimeTicks::Now() - start);
      if (max_duration > v8::base::TimeDelta::FromMilliseconds(0)) {
        concurrent_sweep_complete = true;
        main_thread_sweep_complete = PerformSweepOnMutatorThread(
            max_duration, scope, MutatorThreadSweepingMode::kAll);
      }
    }
    if (main_thread_sweep_complete) {
      if (!concurrent_sweep_complete) {
        return SweepResult::kMainThreadDoneConcurrentInProgress;
      } else {
        CHECK(!is_in_progress_);
        return SweepResult::kFullyDone;
      }
    }
    return SweepResult::kInProgress;
  }

  void ScheduleIncrementalSweeping(
      std::optional<v8::base::TimeDelta> delay = {}) {
    DCHECK_GE(config_.sweeping_type,
              SweepingConfig::SweepingType::kIncremental);

    if (!foreground_task_runner_) {
      return;
    }

    low_priority_task_ran_ = false;
    incremental_sweeper_handle_.CancelIfNonEmpty();
    incremental_sweeper_handle_ = IncrementalSweepTask::Post(
        *this, foreground_task_runner_, kForegroundRegularPriority, delay);
  }

  void ScheduleLowPriorityIncrementalSweeping(
      std::optional<v8::base::TimeDelta> delay = {}) {
    DCHECK_GE(config_.sweeping_type,
              SweepingConfig::SweepingType::kIncremental);

    if (!low_priority_foreground_task_runner_) {
      return;
    }

    incremental_sweeper_low_priority_handle_.CancelIfNonEmpty();
    incremental_sweeper_low_priority_handle_ =
        IncrementalSweepTask::Post(*this, low_priority_foreground_task_runner_,
                                   kForegroundLowPriority, delay);
  }

  void ScheduleConcurrentSweeping() {
    DCHECK_GE(config_.sweeping_type,
              SweepingConfig::SweepingType::kIncrementalAndConcurrent);

    concurrent_sweeper_handle_ = platform_->PostJob(
        kBackgroundRegularPriority,
        std::make_unique<ConcurrentSweepTask>(
            platform_, *heap_.heap(), &space_states_, &empty_normal_pages_,
            &empty_large_pages_, config_.free_memory_handling));
  }

  void CancelAllSweepingTasks() {
    if (incremental_sweeper_handle_) {
      incremental_sweeper_handle_.Cancel();
    }
    if (incremental_sweeper_low_priority_handle_) {
      incremental_sweeper_low_priority_handle_.Cancel();
    }
    if (concurrent_sweeper_handle_ && concurrent_sweeper_handle_->IsValid()) {
      concurrent_sweeper_handle_->Cancel();
    }
  }

  void SynchronizeAndFinalizeConcurrentAndIncrementalSweeping() {
    // The precondition for this call is that actual sweeping is done. So all
    // that's left is potentially invoking finalizers.

    CancelAllSweepingTasks();

    DCHECK(std::all_of(space_states_.begin(), space_states_.end(),
                       [](const SweepingState& state) {
                         return state.unswept_pages.IsEmpty();
                       }));
    DCHECK(empty_normal_pages_.unswept_pages.IsEmpty());
    DCHECK(empty_large_pages_.unswept_pages.IsEmpty());

    SweepFinalizer finalizer(
        platform_, stats_collector_, kSweepWithoutSpaceAssignment,
        &unused_destroyed_normal_pages_, config_.free_memory_handling,
        EmptyPageHandling::kDestroy);
    finalizer.Finalize(space_states_);
    finalizer.Finalize(empty_normal_pages_);
    finalizer.Finalize(empty_large_pages_);
  }

  RawHeap& heap_;
  NormalPageMemoryPool& page_pool_;
  StatsCollector* const stats_collector_;
  SpaceStates space_states_;
  // States for empty normal pages. These pages do have a space as owner which
  // is updated as soon as the page is reused for a specific space.
  SweepingState empty_normal_pages_;
  // States for empty large pages.
  // TODO(372512096): This can be further split into LO pages that are less than
  // a regular page size and those that are multiple, where larger sizes can
  // contribute to `unused_destroyed_normal_pages_`.
  SweepingState empty_large_pages_;
  // Number of pages that have been destroyed and have not been reused by the
  // allocator yet. We assume that returning early on
  // SweepForAllocationIfRunning() causes such pages to be picked up.
  size_t unused_destroyed_normal_pages_ = 0;
  cppgc::Platform* platform_;
  std::shared_ptr<cppgc::TaskRunner> foreground_task_runner_;
  std::shared_ptr<cppgc::TaskRunner> low_priority_foreground_task_runner_;
  SweepingConfig config_;
  IncrementalSweepTask::Handle incremental_sweeper_handle_;
  IncrementalSweepTask::Handle incremental_sweeper_low_priority_handle_;
  std::unique_ptr<cppgc::JobHandle> concurrent_sweeper_handle_;
  std::vector<Sweeper::SweepingOnMutatorThreadObserver*>
      mutator_thread_sweeping_observers_;
  // Indicates whether a low priority task has been invoked since the last
  // scheduling of an incremental task.
  bool low_priority_task_ran_ = false;
  // Indicates whether the sweeping phase is in progress.
  bool is_in_progress_ = false;
  bool notify_done_pending_ = false;
  // Indicates whether whether the sweeper (or its finalization) is currently
  // running on the main thread.
  bool is_sweeping_on_mutator_thread_ = false;
};

Sweeper::Sweeper(HeapBase& heap)
    : heap_(heap), impl_(std::make_unique<SweeperImpl>(heap)) {}

Sweeper::~Sweeper() = default;

void Sweeper::Start(SweepingConfig config) { impl_->Start(config); }

bool Sweeper::FinishIfRunning() { return impl_->FinishIfRunning(); }

void Sweeper::FinishIfOutOfWork() { impl_->FinishIfOutOfWork(); }

void Sweeper::WaitForConcurrentSweepingForTesting() {
  impl_->WaitForConcurrentSweepingForTesting();
}

bool Sweeper::SweepForAllocationIfRunning(BaseSpace* space, size_t size,
                                          v8::base::TimeDelta max_duration) {
  return impl_->SweepForAllocationIfRunning(space, size, max_duration);
}

bool Sweeper::IsSweepingOnMutatorThread() const {
  return impl_->IsSweepingOnMutatorThread();
}

bool Sweeper::IsSweepingInProgress() const {
  return impl_->IsSweepingInProgress();
}

bool Sweeper::PerformSweepOnMutatorThread(v8::base::TimeDelta max_duration,
                                          StatsCollector::ScopeId scope_id) {
  return impl_->PerformSweepOnMutatorThread(max_duration, scope_id,
                                            MutatorThreadSweepingMode::kAll);
}

Sweeper::SweepingOnMutatorThreadObserver::SweepingOnMutatorThreadObserver(
    Sweeper& sweeper)
    : sweeper_(sweeper) {
  sweeper_.impl_->AddMutatorThreadSweepingObserver(this);
}

Sweeper::SweepingOnMutatorThreadObserver::~SweepingOnMutatorThreadObserver() {
  sweeper_.impl_->RemoveMutatorThreadSweepingObserver(this);
}

}  // namespace cppgc::internal
```