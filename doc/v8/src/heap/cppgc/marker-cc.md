Response:
Let's break down the thought process for analyzing the `marker.cc` file.

**1. Initial Scan and Keyword Recognition:**

First, I'd quickly scan the code for familiar keywords and structures. This gives a high-level idea of what's going on. I'd look for:

* **Includes:**  `#include ...`  These reveal dependencies and hint at core functionalities. Seeing things like `cppgc/heap.h`, `cppgc/marker.h`, `cppgc/marking-state.h`, `cppgc/marking-worklists.h`, `cppgc/platform.h` strongly suggests this file is central to the marking phase of garbage collection.
* **Namespaces:** `namespace cppgc`, `namespace internal`. This indicates the code belongs to the `cppgc` (C++ Garbage Collection) library within V8 and likely deals with internal implementation details.
* **Class Declarations:** `class MarkerBase`, `class Marker`. These are the main actors in the file. Noticing inheritance (`Marker : MarkerBase`) is important.
* **Method Names:**  `StartMarking`, `IncrementalMarkingStep`, `EnterAtomicPause`, `ProcessWeakness`, `VisitLocalRoots`, `AdvanceMarkingWithLimits`. These names are very descriptive and provide strong clues about the file's purpose. Terms like "incremental," "atomic," "weak," and "roots" are common GC concepts.
* **Data Structures:**  `MarkingWorklists`, `MarkingConfig`, `StatsCollector`. Recognizing these as components of a GC system is key.
* **Conditional Compilation:** `#if defined(CPPGC_CAGED_HEAP)`, `#if defined(CPPGC_YOUNG_GENERATION)`. This suggests the code has variations depending on compile-time configurations.
* **Task-Related Structures:** `class IncrementalMarkingTask`, `cppgc::TaskRunner`, `cppgc::JobTask`. This indicates asynchronous operations and parallel processing.

**2. Focus on the Core Class: `MarkerBase`:**

Since `MarkerBase` seems to be the foundational class, I'd focus on understanding its key methods and their interactions. I'd try to trace the lifecycle of a marking operation:

* **`StartMarking()`:**  This is clearly the entry point. I'd note how it initializes marking state, handles incremental marking, and potentially starts concurrent marking.
* **`EnterAtomicPause()` and `LeaveAtomicPause()`:** The names suggest a pause in normal execution. I'd observe what actions are performed during this pause, particularly the `VisitLocalRoots()` call and the handling of not-fully-constructed objects. The interaction with concurrent marking during the pause is also important.
* **`IncrementalMarkingStep()`:** This indicates a step-by-step approach to marking. I'd pay attention to how it interacts with worklists and deadlines.
* **`ProcessWeakness()`:**  This clearly deals with weak references, which are crucial for garbage collection. I'd note the use of callbacks and the handling of different types of weak references.
* **`VisitLocalRoots()` and `VisitCrossThreadRoots()`:** These are fundamental steps in marking, identifying the starting points of the object graph.
* **`AdvanceMarkingWithLimits()`:** This method seems responsible for processing the worklists within time and memory constraints.

**3. Understanding the "Why":**

As I analyze the methods, I'd try to understand the *reason* behind each action. For example:

* Why is there an incremental marking mode? (To reduce pause times).
* Why are there different worklists? (To manage different types of marking tasks).
* Why is there an atomic pause? (To ensure consistency while processing roots and performing certain critical actions).
* What is the purpose of weak references and why do they need special handling? (To allow objects to be collected when they are only referenced weakly).

**4. Connecting to JavaScript (if applicable):**

Since the prompt asks about the relationship to JavaScript, I'd consider the high-level concepts. While this C++ code doesn't directly *execute* JavaScript, it's a crucial part of the engine that *manages the memory* for JavaScript objects. I'd think about:

* How JavaScript objects are created and how they relate to the C++ heap.
* How garbage collection affects the lifecycle of JavaScript objects.
* The concept of strong and weak references in JavaScript and how they might correspond to the C++ implementation.

**5. Considering Edge Cases and Potential Errors:**

I'd look for patterns that might lead to common programming errors. For instance:

* Incorrectly handling weak references can lead to dangling pointers or memory leaks.
* Performance issues can arise from inefficient marking algorithms or excessively long pauses.

**6. Structuring the Output:**

Finally, I'd organize my findings in a clear and structured manner, as shown in the initial good answer. This involves:

* Summarizing the core functionality.
* Listing specific features.
* Explaining the relationship to JavaScript with examples.
* Providing code logic examples with inputs and outputs (even if simplified).
* Highlighting potential programming errors.

**Self-Correction/Refinement during Analysis:**

* **Initial Misconceptions:**  I might initially misunderstand the role of a particular worklist or the exact timing of certain operations. As I read more closely and cross-reference with other parts of the code (even mentally), I would refine my understanding.
* **Missing Details:** I might realize I haven't fully grasped the significance of a particular flag or variable. I'd go back and look for where it's set and used.
* **Overly Technical Jargon:** If I find myself using too much internal GC terminology, I'd try to explain concepts in a more accessible way, especially when relating to JavaScript.

By following this systematic approach, combining a broad overview with focused analysis of key components, and constantly trying to connect the code to the bigger picture of garbage collection and JavaScript execution, I can arrive at a comprehensive understanding of the `marker.cc` file.
The provided C++ source code `v8/src/heap/cppgc/marker.cc` is a core component of the **cppgc** (C++ garbage collection) library within the V8 JavaScript engine. It implements the **marking phase** of the garbage collection process for C++ objects managed by cppgc.

Here's a breakdown of its functionality:

**Core Functionality: Marking Reachable Objects**

The primary responsibility of `marker.cc` is to identify and mark all **live** (reachable) C++ objects in the heap. This is a crucial step in garbage collection, as any object *not* marked will be considered garbage and eligible for reclamation.

**Key Features and Responsibilities:**

1. **Starting and Stopping Marking:**
   - `StartMarking()`: Initiates the marking process. It handles setting up the marking state and potentially starting concurrent marking tasks.
   - `FinishMarking()`:  Completes the marking process, including entering an atomic pause to finalize marking and process weak references.

2. **Incremental Marking:**
   - Implements **incremental garbage collection**, allowing the marking process to be broken down into smaller steps interleaved with normal program execution. This reduces long pauses that can cause jank in applications.
   - `IncrementalMarkingStep()`: Performs a single step of the incremental marking process.
   - `ScheduleIncrementalMarkingTask()`: Schedules asynchronous tasks to continue incremental marking.
   - `AdvanceMarkingOnAllocation()`:  Triggers marking work when new objects are allocated.

3. **Atomic Pause Marking:**
   - `EnterAtomicPause()`:  Handles the transition to an **atomic pause**, a short period where the mutator (JavaScript execution) is paused to perform critical marking operations. This is necessary for consistency.
   - `LeaveAtomicPause()`:  Resumes normal execution after the atomic pause.
   - `EnterProcessGlobalAtomicPause()`: Handles cross-thread root visiting during the atomic pause.

4. **Root Set Scanning:**
   - `VisitLocalRoots()`: Scans the **root set** (objects directly accessible by the program, e.g., from the stack, global variables, persistent handles) in the current thread and marks them.
   - `VisitCrossThreadRoots()`: Scans the root set accessible from other threads.

5. **Worklist Management:**
   - Uses various **worklists** (queues) to manage objects that need to be visited and processed during marking. These include:
     - `marking_worklist_`: Objects to be traced for their references.
     - `write_barrier_worklist_`: Objects modified since the last marking, requiring a re-scan.
     - `not_fully_constructed_worklist_`: Objects that were being constructed during the last GC cycle.
     - `discovered_ephemeron_pairs_worklist_`:  Pairs of objects in weak maps that need special handling.
     - `weak_containers_worklist_`: Weak containers (like WeakSet, WeakMap) that need to be processed.
     - `weak_custom_callback_worklist_`, `parallel_weak_callback_worklist_`:  Objects with custom weak callbacks.

6. **Concurrent Marking:**
   - Supports **concurrent marking**, where a background thread performs marking work in parallel with the mutator.
   - `concurrent_marker_`: Manages the concurrent marking process.
   - `JoinConcurrentMarkingIfNeeded()`: Waits for the concurrent marker to finish its work.
   - `NotifyConcurrentMarkingOfWorkIfNeeded()`:  Informs the concurrent marker about available work.

7. **Weak Reference Processing:**
   - `ProcessWeakness()`: Handles **weak references**. If an object is only reachable through weak references, and the referent object is not otherwise reachable, the weak reference is cleared. This also involves executing callbacks associated with weak references.

8. **Conservative Scanning:**
   - Employs conservative scanning for objects that might contain pointers but the exact layout is unknown.

9. **Statistics Collection:**
   - Integrates with `StatsCollector` to track metrics related to the marking process, aiding in performance analysis and debugging.

10. **Configuration:**
    - Takes a `MarkingConfig` object to customize the marking behavior (e.g., marking type, collection type).

**Relationship to JavaScript:**

While `marker.cc` is C++ code, it's directly related to the memory management of JavaScript objects in V8. Here's how:

- **cppgc manages C++ objects:** V8 uses cppgc to manage the lifecycle of many internal C++ objects that implement JavaScript features (e.g., objects representing JavaScript objects, functions, arrays, etc.).
- **Marking identifies live JavaScript objects:** The marking process in `marker.cc` indirectly helps determine which JavaScript objects are still in use. When a JavaScript object is reachable from the root set, the corresponding C++ objects managing it will be marked as live.
- **Garbage Collection enables memory reclamation:** After marking, the sweeper phase (not in this file) reclaims the memory of unmarked objects, which can include C++ objects representing unreachable JavaScript objects.

**JavaScript Example:**

Consider a simple JavaScript scenario:

```javascript
let obj1 = { data: "important" };
let obj2 = { ref: obj1 };
let weakRef = new WeakRef(obj1);

// At this point, obj1 is strongly reachable through obj2.ref and weakly reachable through weakRef.

obj2 = null; // Now obj1 is only weakly reachable.

// After a garbage collection cycle, if no other strong references to obj1 exist:
// - The C++ object representing obj1 might be unmarked.
// - `weakRef.deref()` would return `undefined`.
```

In the background, the `marker.cc` code would be involved in tracing the reachability of the C++ objects representing `obj1`, `obj2`, and the `WeakRef`. When `obj2` is set to `null`, the strong path to `obj1` is broken. During the marking phase, if no other strong references exist, the C++ object for `obj1` will likely remain unmarked (or only marked as weakly reachable). The `ProcessWeakness()` function would then handle the `WeakRef`, potentially clearing it.

**Code Logic Reasoning (Hypothetical Example):**

Let's imagine a simplified part of `ProcessWorklistsWithDeadline`:

**Hypothetical Input:**

- `marking_worklist_` contains two `MarkingItem`s, representing objects `A` and `B`.
- Object `A` has a reference to object `C`.
- Object `B` has no references.
- `marked_bytes_deadline` is sufficiently high.
- `time_deadline` is in the future.

**Simplified Code Snippet (Conceptual):**

```c++
// Inside ProcessWorklistsWithDeadline
while (!mutator_marking_state_.marking_worklist().IsLocalAndGlobalEmpty()) {
  MarkingWorklists::MarkingItem item;
  if (mutator_marking_state_.marking_worklist().Pop(&item)) {
    HeapObjectHeader& header = HeapObjectHeader::FromObject(item.base_object_payload);
    mutator_marking_state_.AccountMarkedBytes(header);
    item.callback(&visitor(), item.base_object_payload); // Trace references
  }
}
```

**Hypothetical Output and Reasoning:**

1. **Iteration 1:**
   - `item` represents object `A`.
   - `AccountMarkedBytes` marks the memory occupied by `A`.
   - `item.callback` is executed, which traces the reference from `A` to `C`. This adds `C` to the `marking_worklist_` (if it wasn't already there and marked).

2. **Iteration 2:**
   - `item` represents object `B`.
   - `AccountMarkedBytes` marks the memory occupied by `B`.
   - `item.callback` is executed, but `B` has no outgoing references, so nothing new is added to the worklist.

3. **Iteration 3 (if C wasn't already marked):**
   - `item` represents object `C`.
   - `AccountMarkedBytes` marks the memory occupied by `C`.
   - `item.callback` is executed, tracing references from `C`.

The loop continues until the `marking_worklist_` is empty, ensuring all reachable objects are visited and marked.

**User-Common Programming Errors (Related Concepts):**

While users don't directly interact with `marker.cc`, understanding its concepts helps avoid memory leaks in C++ code managed by cppgc:

1. **Forgetting to register roots:** If a C++ object intended to be kept alive is not reachable from the root set (e.g., a persistent handle is not properly registered), it will be incorrectly marked as garbage and potentially freed prematurely.

2. **Incorrectly implementing `Trace()` methods:** cppgc relies on `Trace()` methods within managed classes to discover references to other managed objects. If these methods are implemented incorrectly (e.g., missing a member variable), the referenced objects might not be marked, leading to memory leaks or use-after-free errors.

3. **Circular dependencies with finalizers:** While not directly related to marking, complex object graphs with circular dependencies and finalizers can sometimes create issues where objects are kept alive longer than expected, delaying garbage collection.

**In Summary:**

`v8/src/heap/cppgc/marker.cc` is a critical piece of V8's memory management system. It implements the marking phase of garbage collection for C++ objects, identifying live objects and enabling the reclamation of unused memory. This process directly impacts the lifecycle and memory management of JavaScript objects in the V8 engine.

### 提示词
```
这是目录为v8/src/heap/cppgc/marker.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/marker.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```