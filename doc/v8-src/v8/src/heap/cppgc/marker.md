Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript example.

1. **Understand the Request:** The core request is to summarize the functionality of `marker.cc` within the v8/src/heap/cppgc directory and explain its relation to JavaScript with a JavaScript example.

2. **Initial Scan for Keywords and Purpose:**  Quickly scan the file for important keywords related to garbage collection and memory management. Terms like "marking," "heap," "incremental," "concurrent," "worklist," "roots," "weak," "ephemeron," "allocation," "atomic pause," "stack," "write barrier," and "finalize" stand out. These suggest the file is central to the marking phase of the garbage collector.

3. **Identify Core Responsibilities:** Based on the keywords, deduce the main responsibilities:
    * **Marking:** The central theme. The code appears to be about identifying live objects in the heap.
    * **Incremental Marking:**  The presence of "IncrementalMarkingTask" and related logic indicates support for breaking down the marking process into smaller steps.
    * **Concurrent Marking:**  The "ConcurrentMarker" and related logic points to the ability to perform marking concurrently with JavaScript execution.
    * **Worklists:**  The numerous "worklist" mentions suggest the use of data structures to manage objects needing processing during marking.
    * **Root Finding:** "VisitLocalRoots" and "VisitCrossThreadRoots" suggest identifying the starting points for marking.
    * **Weak References:** "ProcessWeakness," "WeakCallback," and "Ephemeron" indicate handling of objects that don't prevent garbage collection.
    * **Atomic Pauses:**  "EnterAtomicPause" and "LeaveAtomicPause" suggest points where JavaScript execution needs to be paused for critical marking operations.
    * **Write Barriers:** The mention of "WriteBarrier" suggests handling updates to object pointers.

4. **Structure the Summary:**  Organize the identified responsibilities into a coherent summary. Start with a high-level description of the file's purpose. Then, detail the key aspects of the marking process:
    * **Core Function:** What is the primary goal? (Marking live objects)
    * **Marking Types:**  What different approaches are supported? (Atomic, Incremental, Concurrent)
    * **Key Mechanisms:** What are the main tools and techniques used? (Worklists, Visitors)
    * **Lifecycle Management:** How does marking interact with the overall GC process? (Starting, Stepping, Finishing)
    * **Handling Special Cases:**  What specific types of objects or references are handled? (Weak, Ephemeron, NotFullyConstructed)
    * **Integration Points:** How does it interact with other parts of the system? (Heap, Platform, Stack)

5. **Explain the JavaScript Relationship:**  Think about how the concepts in the C++ code manifest in JavaScript. JavaScript's automatic garbage collection is the direct result of this underlying C++ implementation. Focus on the *user-observable* effects:
    * **Automatic Memory Management:**  JavaScript developers don't manually free memory.
    * **Reachability:** Objects that are still accessible are kept alive.
    * **Performance:**  Incremental and concurrent marking aim to reduce pauses and improve responsiveness.
    * **Weak References (Advanced):** While not a core concept for all JS developers, `WeakRef` and `FinalizationRegistry` provide explicit access to weak reference functionality.

6. **Craft the JavaScript Example:**  Create a simple, illustrative JavaScript example that connects to the concepts in the C++ code. The example should demonstrate:
    * **Object Creation:** Creating objects that will be managed by the GC.
    * **Strong References:** Demonstrating how normal variables keep objects alive.
    * **Weak References (`WeakRef`):**  Illustrating a weak reference and how it doesn't prevent garbage collection.
    * **Finalization (`FinalizationRegistry`):** Showing how to be notified when an object is garbage collected.

7. **Refine and Review:** Read through the summary and example, ensuring clarity, accuracy, and consistency. Check for any jargon that needs explanation. Ensure the JavaScript example is easy to understand and directly relates to the C++ concepts. For instance, initially, I might have just focused on the automatic nature of GC. However, explicitly showing `WeakRef` and `FinalizationRegistry` provides a stronger, more concrete link to the "weakness" handling in the C++ code. Also, ensuring the example demonstrates the *impact* of marking (what gets collected, what doesn't) is crucial.

8. **Address Specific Instructions:** Double-check if the response fulfills all parts of the request, including providing a JavaScript example *and* explaining the relationship.

This iterative process of scanning, identifying key concepts, structuring, explaining, and illustrating helps to produce a comprehensive and understandable summary of complex C++ code and its connection to a higher-level language like JavaScript.
这个C++源代码文件 `marker.cc`，位于 V8 引擎的 `heap/cppgc` 目录下，主要负责 **实现 cppgc (C++ Garbage Collector) 的标记阶段 (Marking Phase)**。

**功能归纳:**

`marker.cc` 中 `MarkerBase` 类及其派生类 `Marker` 是 cppgc 垃圾回收器的核心组件之一，其主要功能包括：

1. **启动和管理标记过程:**  负责启动不同类型的标记（原子标记、增量标记、并发标记），并管理标记过程的状态。
2. **可达性分析 (Reachability Analysis):**  核心任务是通过遍历对象图来识别哪些对象是活跃的（可达的），哪些是垃圾（不可达的）。这涉及到：
    * **根对象扫描 (Root Scanning):**  从一组已知的根对象（例如全局变量、栈上的局部变量等）开始遍历。
    * **对象遍历 (Object Traversal):**  递归地访问已标记对象的引用，标记被引用的对象。
    * **支持不同类型的引用:** 处理强引用、弱引用、以及特殊的引用类型（如 Ephemeron，用于处理键值对，当键不可达时，值也变得不可达）。
3. **支持多种标记模式:**
    * **原子标记 (Atomic Marking):**  在单次暂停中完成整个标记过程，期间 JavaScript 执行会被暂停。
    * **增量标记 (Incremental Marking):**  将标记过程分解成多个小步骤，允许 JavaScript 执行和标记交替进行，减少长暂停。
    * **并发标记 (Concurrent Marking):**  部分标记工作在后台线程与 JavaScript 执行并行进行，进一步减少主线程的暂停时间。
4. **管理标记工作队列 (Marking Worklists):** 使用工作队列来存储待标记的对象，以及其他需要在标记过程中处理的任务，例如处理未完全构造的对象、处理写屏障事件等。
5. **处理弱引用和终结器 (Weak References and Finalizers):**  识别和处理弱引用，当弱引用指向的对象变为不可达时，执行相关的回调。
6. **与并发标记器 (Concurrent Marker) 协作:**  如果启用了并发标记，则与 `ConcurrentMarker` 类协作，将部分标记任务移交到后台线程执行。
7. **性能优化:**  包含一些针对性能的优化，例如设置标记截止时间、根据分配速率动态调整增量标记的步长等。
8. **与写屏障 (Write Barrier) 交互:**  处理在并发或增量标记期间，mutator (JavaScript 执行器) 对对象图的修改，以确保标记的正确性。
9. **统计信息收集:**  收集标记过程中的各种统计信息，用于性能分析和监控。

**与 JavaScript 的功能关系及 JavaScript 示例:**

`marker.cc` 的功能是支撑 JavaScript 自动内存管理的核心。JavaScript 开发者无需手动管理内存的分配和释放，这背后的机制就是垃圾回收器。标记阶段是垃圾回收的关键步骤，它决定了哪些对象是“活着的”，应该被保留，哪些是“死去的”，可以被回收。

虽然 JavaScript 代码本身不直接调用 `marker.cc` 中的函数，但 JavaScript 的行为受到其工作方式的深刻影响。

**JavaScript 示例:**

```javascript
// 创建一些对象，形成引用关系
let obj1 = { data: "Hello" };
let obj2 = { ref: obj1 };
let obj3 = { anotherRef: obj1 };

// 此时 obj1, obj2, obj3 都是可达的，因为它们被变量引用着。

// 断开 obj2 的引用
obj2 = null;
// obj2 指向的对象现在可能变为垃圾，但 obj1 仍然被 obj3 引用，所以仍然是可达的。

// 断开 obj3 的引用
obj3 = null;
// 现在 obj1 没有被任何变量直接引用，如果垃圾回收器运行，obj1 指向的对象可能被标记为不可达，并最终被回收。

// 使用 WeakRef 创建一个弱引用
let weakRef = new WeakRef(obj1);

// 强制执行一次垃圾回收 (这是一个非标准的方法，不同环境可能有不同的实现或根本不支持)
// 在 Node.js 中，可以使用 --expose-gc 启动，然后调用 global.gc();
// 在浏览器中，通常无法直接触发 GC。
// console.log("执行垃圾回收...");
// if (global.gc) {
//   global.gc();
// }

// 检查弱引用是否仍然有效
// console.log("弱引用是否有效:", weakRef.deref() !== undefined); // 如果 obj1 被回收，则 deref() 返回 undefined

// 使用 FinalizationRegistry 注册一个清理回调
let registry = new FinalizationRegistry(heldValue => {
  console.log("对象被回收了，携带的值是:", heldValue);
});
registry.register(obj1, "obj1 的值");

obj1 = null; // 断开最后一个强引用

// 再次尝试垃圾回收
// console.log("再次执行垃圾回收...");
// if (global.gc) {
//   global.gc();
// }

// 在垃圾回收发生后，FinalizationRegistry 的回调函数会被调用。
```

**这个 JavaScript 示例说明了以下与 `marker.cc` 功能相关的概念:**

* **可达性:**  JavaScript 对象的生命周期取决于其是否可以从根对象访问到。`marker.cc` 中的标记阶段就是负责确定这种可达性。
* **垃圾回收:** 当对象不再可达时，垃圾回收器会识别并回收它们占用的内存。
* **弱引用 (`WeakRef`):** `WeakRef` 创建的引用不会阻止垃圾回收器回收对象。这与 `marker.cc` 中处理弱引用的逻辑相关。
* **终结器 (`FinalizationRegistry`):**  允许在对象被垃圾回收后执行清理操作。这与 `marker.cc` 中处理终结器的机制相关。

总而言之，`marker.cc` 文件中的代码是 V8 引擎实现自动内存管理的关键基础设施，虽然 JavaScript 开发者不直接操作它，但其功能直接影响了 JavaScript 程序的内存行为和性能。理解 `marker.cc` 的功能有助于深入理解 JavaScript 垃圾回收的工作原理。

Prompt: 
```
这是目录为v8/src/heap/cppgc/marker.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/marker.h"

#include <cstddef>
#include <cstdint>
#include <memory>

#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/platform.h"
#include "src/base/platform/time.h"
#include "src/heap/base/incremental-marking-schedule.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap-config.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/heap-page.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/heap.h"
#include "src/heap/cppgc/liveness-broker.h"
#include "src/heap/cppgc/marking-state.h"
#include "src/heap/cppgc/marking-visitor.h"
#include "src/heap/cppgc/marking-worklists.h"
#include "src/heap/cppgc/process-heap.h"
#include "src/heap/cppgc/stats-collector.h"
#include "src/heap/cppgc/write-barrier.h"

#if defined(CPPGC_CAGED_HEAP)
#include "include/cppgc/internal/caged-heap-local-data.h"
#endif

namespace cppgc {
namespace internal {

namespace {

bool EnterIncrementalMarkingIfNeeded(MarkingConfig config, HeapBase& heap) {
  if (config.marking_type == MarkingConfig::MarkingType::kIncremental ||
      config.marking_type ==
          MarkingConfig::MarkingType::kIncrementalAndConcurrent) {
    WriteBarrier::FlagUpdater::Enter();
    heap.set_incremental_marking_in_progress(true);
    return true;
  }
  return false;
}

bool ExitIncrementalMarkingIfNeeded(MarkingConfig config, HeapBase& heap) {
  if (config.marking_type == MarkingConfig::MarkingType::kIncremental ||
      config.marking_type ==
          MarkingConfig::MarkingType::kIncrementalAndConcurrent) {
    WriteBarrier::FlagUpdater::Exit();
    heap.set_incremental_marking_in_progress(false);
    return true;
  }
  return false;
}

static constexpr size_t kDefaultDeadlineCheckInterval = 150u;

template <size_t kDeadlineCheckInterval = kDefaultDeadlineCheckInterval,
          typename WorklistLocal, typename Callback>
bool DrainWorklistWithBytesAndTimeDeadline(BasicMarkingState& marking_state,
                                           size_t marked_bytes_deadline,
                                           v8::base::TimeTicks time_deadline,
                                           WorklistLocal& worklist_local,
                                           Callback callback) {
  return DrainWorklistWithPredicate<kDeadlineCheckInterval>(
      [&marking_state, marked_bytes_deadline, time_deadline]() {
        return (marked_bytes_deadline <= marking_state.marked_bytes()) ||
               (time_deadline <= v8::base::TimeTicks::Now());
      },
      worklist_local, callback);
}

size_t GetNextIncrementalStepDuration(
    heap::base::IncrementalMarkingSchedule& schedule, HeapBase& heap) {
  return schedule.GetNextIncrementalStepDuration(
      heap.stats_collector()->allocated_object_size());
}

}  // namespace

constexpr v8::base::TimeDelta MarkerBase::kMaximumIncrementalStepDuration;

class MarkerBase::IncrementalMarkingTask final : public cppgc::Task {
 public:
  using Handle = SingleThreadedHandle;

  IncrementalMarkingTask(MarkerBase*, StackState);

  static Handle Post(cppgc::TaskRunner*, MarkerBase*);

 private:
  void Run() final;

  MarkerBase* const marker_;
  StackState stack_state_;
  // TODO(chromium:1056170): Change to CancelableTask.
  Handle handle_;
};

MarkerBase::IncrementalMarkingTask::IncrementalMarkingTask(
    MarkerBase* marker, StackState stack_state)
    : marker_(marker),
      stack_state_(stack_state),
      handle_(Handle::NonEmptyTag{}) {}

// static
MarkerBase::IncrementalMarkingTask::Handle
MarkerBase::IncrementalMarkingTask::Post(cppgc::TaskRunner* runner,
                                         MarkerBase* marker) {
  // Incremental GC is possible only via the GCInvoker, so getting here
  // guarantees that either non-nestable tasks or conservative stack
  // scanning are supported. This is required so that the incremental
  // task can safely finalize GC if needed.
  DCHECK_IMPLIES(marker->heap().stack_support() !=
                     HeapBase::StackSupport::kSupportsConservativeStackScan,
                 runner->NonNestableTasksEnabled());

  const bool non_nestable_tasks_enabled = runner->NonNestableTasksEnabled();

  auto task = std::make_unique<IncrementalMarkingTask>(
      marker, non_nestable_tasks_enabled ? StackState::kNoHeapPointers
                                         : StackState::kMayContainHeapPointers);
  auto handle = task->handle_;
  if (non_nestable_tasks_enabled) {
    runner->PostNonNestableTask(std::move(task));
  } else {
    runner->PostTask(std::move(task));
  }
  return handle;
}

void MarkerBase::IncrementalMarkingTask::Run() {
  if (handle_.IsCanceled()) return;

  StatsCollector::EnabledScope stats_scope(marker_->heap().stats_collector(),
                                           StatsCollector::kIncrementalMark);

  if (marker_->IncrementalMarkingStep(stack_state_)) {
    // Incremental marking is done so should finalize GC.
    marker_->heap().FinalizeIncrementalGarbageCollectionIfNeeded(stack_state_);
  }
}

MarkerBase::MarkerBase(HeapBase& heap, cppgc::Platform* platform,
                       MarkingConfig config)
    : heap_(heap),
      config_(config),
      platform_(platform),
      foreground_task_runner_(platform_->GetForegroundTaskRunner()),
      mutator_marking_state_(heap, marking_worklists_,
                             heap.compactor().compaction_worklists()),
      schedule_(config.bailout_of_marking_when_ahead_of_schedule
                    ? ::heap::base::IncrementalMarkingSchedule::
                          CreateWithZeroMinimumMarkedBytesPerStep()
                    : ::heap::base::IncrementalMarkingSchedule::
                          CreateWithDefaultMinimumMarkedBytesPerStep()) {
  DCHECK_IMPLIES(config_.collection_type == CollectionType::kMinor,
                 heap_.generational_gc_supported());
}

MarkerBase::~MarkerBase() {
  // The fixed point iteration may have found not-fully-constructed objects.
  // Such objects should have already been found through the stack scan though
  // and should thus already be marked.
  if (!marking_worklists_.not_fully_constructed_worklist()->IsEmpty()) {
#if DEBUG
    DCHECK_NE(StackState::kNoHeapPointers, config_.stack_state);
    std::unordered_set<HeapObjectHeader*> objects =
        mutator_marking_state_.not_fully_constructed_worklist().Extract();
    for (HeapObjectHeader* object : objects) DCHECK(object->IsMarked());
#else
    marking_worklists_.not_fully_constructed_worklist()->Clear();
#endif
  }

  // |discovered_ephemeron_pairs_worklist_| may still hold ephemeron pairs with
  // dead keys.
  if (!marking_worklists_.discovered_ephemeron_pairs_worklist()->IsEmpty()) {
#if DEBUG
    MarkingWorklists::EphemeronPairItem item;
    while (mutator_marking_state_.discovered_ephemeron_pairs_worklist().Pop(
        &item)) {
      DCHECK(!HeapObjectHeader::FromObject(item.key).IsMarked());
    }
#else
    marking_worklists_.discovered_ephemeron_pairs_worklist()->Clear();
#endif
  }

  marking_worklists_.weak_containers_worklist()->Clear();
}

class MarkerBase::IncrementalMarkingAllocationObserver final
    : public StatsCollector::AllocationObserver {
 public:
  static constexpr size_t kMinAllocatedBytesPerStep = 256 * kKB;

  explicit IncrementalMarkingAllocationObserver(MarkerBase& marker)
      : marker_(marker) {}

  void AllocatedObjectSizeIncreased(size_t delta) final {
    current_allocated_size_ += delta;
    if (current_allocated_size_ > kMinAllocatedBytesPerStep) {
      marker_.AdvanceMarkingOnAllocation();
      current_allocated_size_ = 0;
    }
  }

 private:
  MarkerBase& marker_;
  size_t current_allocated_size_ = 0;
};

void MarkerBase::StartMarking() {
  DCHECK(!is_marking_);
  StatsCollector::EnabledScope stats_scope(
      heap().stats_collector(),
      config_.marking_type == MarkingConfig::MarkingType::kAtomic
          ? StatsCollector::kAtomicMark
          : StatsCollector::kIncrementalMark);

  heap().stats_collector()->NotifyMarkingStarted(
      config_.collection_type, config_.marking_type, config_.is_forced_gc);

  is_marking_ = true;
  if (EnterIncrementalMarkingIfNeeded(config_, heap())) {
    StatsCollector::EnabledScope inner_stats_scope(
        heap().stats_collector(), StatsCollector::kMarkIncrementalStart);

    // Performing incremental or concurrent marking.
    schedule_->NotifyIncrementalMarkingStart();
    // Scanning the stack is expensive so we only do it at the atomic pause.
    VisitLocalRoots(StackState::kNoHeapPointers);
    ScheduleIncrementalMarkingTask();
    if (config_.marking_type ==
        MarkingConfig::MarkingType::kIncrementalAndConcurrent) {
      mutator_marking_state_.Publish();
      concurrent_marker_->Start();
    }
    incremental_marking_allocation_observer_ =
        std::make_unique<IncrementalMarkingAllocationObserver>(*this);
    heap().stats_collector()->RegisterObserver(
        incremental_marking_allocation_observer_.get());
  }
}

void MarkerBase::HandleNotFullyConstructedObjects() {
  if (config_.stack_state == StackState::kNoHeapPointers) {
    mutator_marking_state_.FlushNotFullyConstructedObjects();
  } else {
    MarkNotFullyConstructedObjects();
  }
}

void MarkerBase::EnterAtomicPause(StackState stack_state) {
  StatsCollector::EnabledScope top_stats_scope(heap().stats_collector(),
                                               StatsCollector::kAtomicMark);
  StatsCollector::EnabledScope stats_scope(heap().stats_collector(),
                                           StatsCollector::kMarkAtomicPrologue);

  const MarkingConfig::MarkingType old_marking_type = config_.marking_type;

  if (ExitIncrementalMarkingIfNeeded(config_, heap())) {
    // Cancel remaining incremental tasks. Concurrent marking jobs are left to
    // run in parallel with the atomic pause until the mutator thread runs out
    // of work.
    incremental_marking_handle_.Cancel();
    heap().stats_collector()->UnregisterObserver(
        incremental_marking_allocation_observer_.get());
    incremental_marking_allocation_observer_.reset();
  }
  config_.stack_state = stack_state;
  config_.marking_type = MarkingConfig::MarkingType::kAtomic;
  mutator_marking_state_.set_in_atomic_pause();

  {
    // VisitLocalRoots() also resets the LABs.
    VisitLocalRoots(config_.stack_state);
    HandleNotFullyConstructedObjects();
  }
  if (old_marking_type ==
      MarkingConfig::MarkingType::kIncrementalAndConcurrent) {
    // Start parallel marking.
    mutator_marking_state_.Publish();
    if (concurrent_marker_->IsActive()) {
      concurrent_marker_->NotifyIncrementalMutatorStepCompleted();
    } else {
      concurrent_marker_->Start();
    }
  }
}

void MarkerBase::ReEnableConcurrentMarking() {
  CHECK(is_marking_);

  if (config_.marking_type == MarkingConfig::MarkingType::kAtomic) {
    return;
  }

  CHECK_EQ(config_.marking_type, MarkingConfig::MarkingType::kIncremental);
  config_.marking_type = MarkingConfig::MarkingType::kIncrementalAndConcurrent;
  mutator_marking_state_.Publish();
  CHECK(!concurrent_marker_->IsActive());
  concurrent_marker_->Start();
  CHECK(concurrent_marker_->IsActive());
}

void MarkerBase::LeaveAtomicPause() {
  {
    StatsCollector::EnabledScope top_stats_scope(heap().stats_collector(),
                                                 StatsCollector::kAtomicMark);
    StatsCollector::EnabledScope stats_scope(
        heap().stats_collector(), StatsCollector::kMarkAtomicEpilogue);
    DCHECK(!incremental_marking_handle_);
    heap().stats_collector()->NotifyMarkingCompleted(
        // GetOverallMarkedBytes also includes concurrently marked bytes.
        schedule_->GetOverallMarkedBytes());
    is_marking_ = false;
  }
  {
    // Weakness callbacks are forbidden from allocating objects.
    cppgc::subtle::DisallowGarbageCollectionScope disallow_gc_scope(heap_);
    ProcessWeakness();
  }
  heap().SetStackStateOfPrevGC(config_.stack_state);
}

void MarkerBase::EnterProcessGlobalAtomicPause() { VisitCrossThreadRoots(); }

void MarkerBase::FinishMarking(StackState stack_state) {
  DCHECK(is_marking_);
  EnterAtomicPause(stack_state);
  EnterProcessGlobalAtomicPause();
  {
    StatsCollector::EnabledScope stats_scope(heap().stats_collector(),
                                             StatsCollector::kAtomicMark);
    CHECK(AdvanceMarkingWithLimits(v8::base::TimeDelta::Max(), SIZE_MAX));
    if (JoinConcurrentMarkingIfNeeded()) {
      CHECK(AdvanceMarkingWithLimits(v8::base::TimeDelta::Max(), SIZE_MAX));
    }
    mutator_marking_state_.Publish();
  }
  LeaveAtomicPause();
}

class WeakCallbackJobTask final : public cppgc::JobTask {
 public:
  WeakCallbackJobTask(MarkerBase* marker,
                      MarkingWorklists::WeakCallbackWorklist* callback_worklist,
                      LivenessBroker& broker)
      : marker_(marker),
        callback_worklist_(callback_worklist),
        broker_(broker) {}

  void Run(JobDelegate* delegate) override {
    StatsCollector::EnabledConcurrentScope stats_scope(
        marker_->heap().stats_collector(),
        StatsCollector::kConcurrentWeakCallback);
    MarkingWorklists::WeakCallbackWorklist::Local local(*callback_worklist_);
    MarkingWorklists::WeakCallbackItem item;
    while (local.Pop(&item)) {
      item.callback(broker_, item.parameter);
    }
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    return std::min(static_cast<size_t>(1),
                    callback_worklist_->Size() + worker_count);
  }

 private:
  MarkerBase* marker_;
  MarkingWorklists::WeakCallbackWorklist* callback_worklist_;
  LivenessBroker& broker_;
};

void MarkerBase::ProcessWeakness() {
  DCHECK_EQ(MarkingConfig::MarkingType::kAtomic, config_.marking_type);

  StatsCollector::EnabledScope stats_scope(heap().stats_collector(),
                                           StatsCollector::kAtomicWeak);

  RootMarkingVisitor root_marking_visitor(mutator_marking_state_);

  // Processing cross-thread roots requires taking the global process lock.
  // Process these weak roots first to minimize the time the lock is held.
  g_process_mutex.Get().AssertHeld();
  CHECK(visited_cross_thread_persistents_in_atomic_pause_);
  heap().GetWeakCrossThreadPersistentRegion().Iterate(root_marking_visitor);
  g_process_mutex.Pointer()->Unlock();

  // Launch the parallel job before anything else to provide the maximum time
  // slice for processing.
  LivenessBroker broker = LivenessBrokerFactory::Create();
  std::unique_ptr<cppgc::JobHandle> job_handle{nullptr};
  if (heap().marking_support() ==
      cppgc::Heap::MarkingType::kIncrementalAndConcurrent) {
    job_handle = platform_->PostJob(
        cppgc::TaskPriority::kUserBlocking,
        std::make_unique<WeakCallbackJobTask>(
            this, marking_worklists_.parallel_weak_callback_worklist(),
            broker));
  }

  // Process same-thread roots.
  heap().GetWeakPersistentRegion().Iterate(root_marking_visitor);

  // Call weak callbacks on objects that may now be pointing to dead objects.
#if defined(CPPGC_YOUNG_GENERATION)
  if (heap().generational_gc_supported()) {
    auto& remembered_set = heap().remembered_set();
    if (config_.collection_type == CollectionType::kMinor) {
      // Custom callbacks assume that untraced pointers point to not yet freed
      // objects. They must make sure that upon callback completion no
      // UntracedMember points to a freed object. This may not hold true if a
      // custom callback for an old object operates with a reference to a young
      // object that was freed on a minor collection cycle. To maintain the
      // invariant that UntracedMembers always point to valid objects, execute
      // custom callbacks for old objects on each minor collection cycle.
      remembered_set.ExecuteCustomCallbacks(broker);
    } else {
      // For major GCs, just release all the remembered weak callbacks.
      remembered_set.ReleaseCustomCallbacks();
    }
  }
#endif  // defined(CPPGC_YOUNG_GENERATION)

  {
    // First, process weak container callbacks.
    StatsCollector::EnabledScope stats_scope(
        heap().stats_collector(),
        StatsCollector::kWeakContainerCallbacksProcessing);
    MarkingWorklists::WeakCallbackItem item;
    MarkingWorklists::WeakCallbackWorklist::Local& collections_local =
        mutator_marking_state_.weak_container_callback_worklist();
    while (collections_local.Pop(&item)) {
      item.callback(broker, item.parameter);
    }
  }
  {
    // Then, process custom weak callbacks.
    StatsCollector::EnabledScope stats_scope(
        heap().stats_collector(), StatsCollector::kCustomCallbacksProcessing);
    MarkingWorklists::WeakCallbackItem item;
    MarkingWorklists::WeakCustomCallbackWorklist::Local& custom_callbacks =
        mutator_marking_state_.weak_custom_callback_worklist();
    while (custom_callbacks.Pop(&item)) {
      item.callback(broker, item.parameter);
#if defined(CPPGC_YOUNG_GENERATION)
      if (heap().generational_gc_supported())
        heap().remembered_set().AddWeakCallback(item);
#endif  // defined(CPPGC_YOUNG_GENERATION)
    }
  }

  if (job_handle) {
    job_handle->Join();
  } else {
    MarkingWorklists::WeakCallbackItem item;
    MarkingWorklists::WeakCallbackWorklist::Local& local =
        mutator_marking_state_.parallel_weak_callback_worklist();
    while (local.Pop(&item)) {
      item.callback(broker, item.parameter);
    }
  }

  // Weak callbacks should not add any new objects for marking.
  DCHECK(marking_worklists_.marking_worklist()->IsEmpty());
}

void MarkerBase::VisitLocalRoots(StackState stack_state) {
  StatsCollector::EnabledScope stats_scope(heap().stats_collector(),
                                           StatsCollector::kMarkVisitRoots);

  // Reset LABs before scanning roots. LABs are cleared to allow
  // ObjectStartBitmap handling without considering LABs.
  heap().object_allocator().ResetLinearAllocationBuffers();

  {
    StatsCollector::DisabledScope inner_stats_scope(
        heap().stats_collector(), StatsCollector::kMarkVisitPersistents);
    RootMarkingVisitor root_marking_visitor(mutator_marking_state_);
    heap().GetStrongPersistentRegion().Iterate(root_marking_visitor);
  }

  if (stack_state != StackState::kNoHeapPointers) {
    StatsCollector::DisabledScope stack_stats_scope(
        heap().stats_collector(), StatsCollector::kMarkVisitStack);
    heap().stack()->SetMarkerIfNeededAndCallback([this]() {
      heap().stack()->IteratePointersUntilMarker(&stack_visitor());
    });
  }

#if defined(CPPGC_YOUNG_GENERATION)
  if (config_.collection_type == CollectionType::kMinor) {
    StatsCollector::EnabledScope stats_scope(
        heap().stats_collector(), StatsCollector::kMarkVisitRememberedSets);
    heap().remembered_set().Visit(visitor(), conservative_visitor(),
                                  mutator_marking_state_);
  }
#endif  // defined(CPPGC_YOUNG_GENERATION)
}

void MarkerBase::VisitCrossThreadRoots() {
  StatsCollector::DisabledScope inner_stats_scope(
      heap().stats_collector(),
      StatsCollector::kMarkVisitCrossThreadPersistents);
  CHECK_EQ(config_.marking_type, MarkingConfig::MarkingType::kAtomic);
  CHECK(!visited_cross_thread_persistents_in_atomic_pause_);
  // Lock guards against changes to {Weak}CrossThreadPersistent handles, that
  // may conflict with marking. E.g., a WeakCrossThreadPersistent may be
  // converted into a CrossThreadPersistent which requires that the handle
  // is either cleared or the object is retained.
  g_process_mutex.Pointer()->Lock();
  RootMarkingVisitor root_marking_visitor(mutator_marking_state_);
  heap().GetStrongCrossThreadPersistentRegion().Iterate(root_marking_visitor);
  visited_cross_thread_persistents_in_atomic_pause_ = true;
}

void MarkerBase::ScheduleIncrementalMarkingTask() {
  DCHECK(platform_);
  if (!foreground_task_runner_ || incremental_marking_handle_) return;
  incremental_marking_handle_ =
      IncrementalMarkingTask::Post(foreground_task_runner_.get(), this);
}

bool MarkerBase::IncrementalMarkingStepForTesting(StackState stack_state) {
  return IncrementalMarkingStep(stack_state);
}

bool MarkerBase::IncrementalMarkingStep(StackState stack_state) {
  if (stack_state == StackState::kNoHeapPointers) {
    mutator_marking_state_.FlushNotFullyConstructedObjects();
  }
  config_.stack_state = stack_state;

  return AdvanceMarkingWithLimits();
}

void MarkerBase::AdvanceMarkingOnAllocation() {
  StatsCollector::EnabledScope stats_scope(heap().stats_collector(),
                                           StatsCollector::kIncrementalMark);
  StatsCollector::EnabledScope nested_scope(heap().stats_collector(),
                                            StatsCollector::kMarkOnAllocation);
  if (AdvanceMarkingWithLimits()) {
    // Schedule another incremental task for finalizing without a stack.
    ScheduleIncrementalMarkingTask();
  }
}

bool MarkerBase::JoinConcurrentMarkingIfNeeded() {
  if (config_.marking_type != MarkingConfig::MarkingType::kAtomic ||
      !concurrent_marker_->Join())
    return false;

  // Concurrent markers may have pushed some "leftover" in-construction objects
  // after flushing in EnterAtomicPause.
  HandleNotFullyConstructedObjects();
  DCHECK(marking_worklists_.not_fully_constructed_worklist()->IsEmpty());
  return true;
}

void MarkerBase::NotifyConcurrentMarkingOfWorkIfNeeded(
    cppgc::TaskPriority priority) {
  if (concurrent_marker_->IsActive()) {
    concurrent_marker_->NotifyOfWorkIfNeeded(priority);
  }
}

bool MarkerBase::AdvanceMarkingWithLimits(v8::base::TimeDelta max_duration,
                                          size_t marked_bytes_limit) {
  bool is_done = false;
  if (!main_marking_disabled_for_testing_) {
    if (marked_bytes_limit == 0) {
      marked_bytes_limit = mutator_marking_state_.marked_bytes() +
                           GetNextIncrementalStepDuration(*schedule_, heap_);
    }
    StatsCollector::EnabledScope deadline_scope(
        heap().stats_collector(),
        StatsCollector::kMarkTransitiveClosureWithDeadline, "deadline_ms",
        max_duration.InMillisecondsF());
    const auto deadline = v8::base::TimeTicks::Now() + max_duration;
    is_done = ProcessWorklistsWithDeadline(marked_bytes_limit, deadline);
    schedule_->UpdateMutatorThreadMarkedBytes(
        mutator_marking_state_.marked_bytes());
  }
  mutator_marking_state_.Publish();
  if (!is_done) {
    // If marking is atomic, |is_done| should always be true.
    DCHECK_NE(MarkingConfig::MarkingType::kAtomic, config_.marking_type);
    ScheduleIncrementalMarkingTask();
    if (config_.marking_type ==
        MarkingConfig::MarkingType::kIncrementalAndConcurrent) {
      concurrent_marker_->NotifyIncrementalMutatorStepCompleted();
    }
  }
  return is_done;
}

bool MarkerBase::ProcessWorklistsWithDeadline(
    size_t marked_bytes_deadline, v8::base::TimeTicks time_deadline) {
  StatsCollector::EnabledScope stats_scope(
      heap().stats_collector(), StatsCollector::kMarkTransitiveClosure);
  bool saved_did_discover_new_ephemeron_pairs;
  do {
    mutator_marking_state_.ResetDidDiscoverNewEphemeronPairs();
    if ((config_.marking_type == MarkingConfig::MarkingType::kAtomic) ||
        schedule_->ShouldFlushEphemeronPairs()) {
      mutator_marking_state_.FlushDiscoveredEphemeronPairs();
    }

    // Bailout objects may be complicated to trace and thus might take longer
    // than other objects. Therefore we reduce the interval between deadline
    // checks to guarantee the deadline is not exceeded.
    {
      StatsCollector::DisabledScope inner_scope(
          heap().stats_collector(), StatsCollector::kMarkProcessBailOutObjects);
      if (!DrainWorklistWithBytesAndTimeDeadline<kDefaultDeadlineCheckInterval /
                                                 5>(
              mutator_marking_state_, SIZE_MAX, time_deadline,
              mutator_marking_state_.concurrent_marking_bailout_worklist(),
              [this](
                  const MarkingWorklists::ConcurrentMarkingBailoutItem& item) {
                mutator_marking_state_.AccountMarkedBytes(
                    BasePage::FromPayload(const_cast<void*>(item.parameter)),
                    item.bailedout_size);
                item.callback(&visitor(), item.parameter);
              })) {
        return false;
      }
    }

    {
      StatsCollector::DisabledScope inner_scope(
          heap().stats_collector(),
          StatsCollector::kMarkProcessNotFullyconstructedWorklist);
      if (!DrainWorklistWithBytesAndTimeDeadline(
              mutator_marking_state_, marked_bytes_deadline, time_deadline,
              mutator_marking_state_
                  .previously_not_fully_constructed_worklist(),
              [this](HeapObjectHeader* header) {
                mutator_marking_state_.AccountMarkedBytes(*header);
                DynamicallyTraceMarkedObject<AccessMode::kNonAtomic>(visitor(),
                                                                     *header);
              })) {
        return false;
      }
    }

    {
      StatsCollector::DisabledScope inner_scope(
          heap().stats_collector(),
          StatsCollector::kMarkProcessMarkingWorklist);
      if (!DrainWorklistWithBytesAndTimeDeadline(
              mutator_marking_state_, marked_bytes_deadline, time_deadline,
              mutator_marking_state_.marking_worklist(),
              [this](const MarkingWorklists::MarkingItem& item) {
                const HeapObjectHeader& header =
                    HeapObjectHeader::FromObject(item.base_object_payload);
                DCHECK(!header.IsInConstruction<AccessMode::kNonAtomic>());
                DCHECK(header.IsMarked<AccessMode::kAtomic>());
                mutator_marking_state_.AccountMarkedBytes(header);
                item.callback(&visitor(), item.base_object_payload);
              })) {
        return false;
      }
    }

    {
      StatsCollector::DisabledScope inner_scope(
          heap().stats_collector(),
          StatsCollector::kMarkProcessWriteBarrierWorklist);
      if (!DrainWorklistWithBytesAndTimeDeadline(
              mutator_marking_state_, marked_bytes_deadline, time_deadline,
              mutator_marking_state_.write_barrier_worklist(),
              [this](HeapObjectHeader* header) {
                mutator_marking_state_.AccountMarkedBytes(*header);
                DynamicallyTraceMarkedObject<AccessMode::kNonAtomic>(visitor(),
                                                                     *header);
              })) {
        return false;
      }
      if (!DrainWorklistWithBytesAndTimeDeadline(
              mutator_marking_state_, marked_bytes_deadline, time_deadline,
              mutator_marking_state_.retrace_marked_objects_worklist(),
              [this](HeapObjectHeader* header) {
                // Retracing does not increment marked bytes as the object has
                // already been processed before.
                DynamicallyTraceMarkedObject<AccessMode::kNonAtomic>(visitor(),
                                                                     *header);
              })) {
        return false;
      }
    }

    saved_did_discover_new_ephemeron_pairs =
        mutator_marking_state_.DidDiscoverNewEphemeronPairs();
    {
      StatsCollector::DisabledScope inner_stats_scope(
          heap().stats_collector(), StatsCollector::kMarkProcessEphemerons);
      if (!DrainWorklistWithBytesAndTimeDeadline(
              mutator_marking_state_, marked_bytes_deadline, time_deadline,
              mutator_marking_state_.ephemeron_pairs_for_processing_worklist(),
              [this](const MarkingWorklists::EphemeronPairItem& item) {
                mutator_marking_state_.ProcessEphemeron(
                    item.key, item.value, item.value_desc, visitor());
              })) {
        return false;
      }
    }
  } while (!mutator_marking_state_.marking_worklist().IsLocalAndGlobalEmpty() ||
           saved_did_discover_new_ephemeron_pairs);
  return true;
}

void MarkerBase::MarkNotFullyConstructedObjects() {
  // Parallel marking may still be running which is why atomic extraction is
  // required.
  std::unordered_set<HeapObjectHeader*> objects =
      mutator_marking_state_.not_fully_constructed_worklist()
          .Extract<AccessMode::kAtomic>();
  if (objects.empty()) {
    return;
  }
  StatsCollector::DisabledScope stats_scope(
      heap().stats_collector(),
      StatsCollector::kMarkVisitNotFullyConstructedObjects);
  for (HeapObjectHeader* object : objects) {
    DCHECK(object);
    // TraceConservativelyIfNeeded delegates to either in-construction or
    // fully constructed handling. Both handlers have their own marked bytes
    // accounting and markbit handling (bailout).
    conservative_visitor().TraceConservativelyIfNeeded(*object);
  }
}

bool MarkerBase::IsAheadOfSchedule() const {
  static constexpr size_t kNumOfBailoutObjectsForNormalTask = 512;
  if (marking_worklists_.concurrent_marking_bailout_worklist()->Size() *
          MarkingWorklists::ConcurrentMarkingBailoutWorklist::kMinSegmentSize >
      kNumOfBailoutObjectsForNormalTask) {
    return false;
  }
  if (schedule_->GetCurrentStepInfo().is_behind_expectation()) {
    return false;
  }
  return true;
}

void MarkerBase::ClearAllWorklistsForTesting() {
  marking_worklists_.ClearForTesting();
  auto* compaction_worklists = heap_.compactor().compaction_worklists();
  if (compaction_worklists) compaction_worklists->ClearForTesting();
}

void MarkerBase::SetMainThreadMarkingDisabledForTesting(bool value) {
  main_marking_disabled_for_testing_ = value;
}

void MarkerBase::WaitForConcurrentMarkingForTesting() {
  concurrent_marker_->Join();
}

MarkerBase::PauseConcurrentMarkingScope::PauseConcurrentMarkingScope(
    MarkerBase& marker)
    : marker_(marker), resume_on_exit_(marker_.concurrent_marker_->Cancel()) {}

MarkerBase::PauseConcurrentMarkingScope::~PauseConcurrentMarkingScope() {
  if (resume_on_exit_) {
    marker_.concurrent_marker_->Start();
  }
}

Marker::Marker(HeapBase& heap, cppgc::Platform* platform, MarkingConfig config)
    : MarkerBase(heap, platform, config),
      marking_visitor_(heap, mutator_marking_state_),
      conservative_marking_visitor_(heap, mutator_marking_state_,
                                    marking_visitor_) {
  concurrent_marker_ = std::make_unique<ConcurrentMarker>(
      heap_, marking_worklists_, *schedule_, platform_);
}

}  // namespace internal
}  // namespace cppgc

"""

```