Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding of the Request:**

The request asks for a summary of the functionality of the `incremental-marking.cc` file in the V8 JavaScript engine. It also asks for specific information like:

* Is it a Torque file? (Easy check: does it end in `.tq`?)
* Relationship to JavaScript (this requires deeper understanding).
* Code logic examples (needs assumptions for input/output).
* Common programming errors it helps avoid (requires knowledge of GC concepts).
* A general summary.

**2. High-Level Scan and Keywords:**

My first step is to quickly scan the code for recognizable keywords and structures. This gives a general idea of the domain. I look for:

* `#include`:  Indicates dependencies and areas the code interacts with (e.g., `heap`, `flags`, `logging`).
* `namespace v8::internal`:  Confirms it's part of V8's internal implementation.
* Class names like `IncrementalMarking`, `Observer`, `IncrementalMarkingJob`.
* Function names like `Start`, `Step`, `MarkRoots`, `Stop`, `AdvanceOnAllocation`.
* Constants like `kMajorGCYoungGenerationAllocationObserverStep`.
* Conditional compilation directives like `#ifdef DEBUG`.
* Logging and tracing statements (`TRACE_EVENT`, `isolate()->PrintWithTimestamp`).
* GC-related terms like "marking," "sweeping," "compaction," "scavenge," "allocation."

This initial scan immediately tells me this code is deeply involved in garbage collection, specifically an *incremental* form of marking.

**3. Dissecting Key Classes and Functions:**

Next, I focus on the core classes and their key methods:

* **`IncrementalMarking`:** This is the central class. I look at its constructor and major functions to understand its lifecycle and responsibilities.
    * Constructor: Takes `Heap` and `WeakObjects` as arguments, suggesting it operates on the heap. Initializes observers and potentially a job.
    * `Start()`:  Initiates the incremental marking process. Handles different GC types (major/minor). Includes logging and tracing.
    * `Step()`:  Performs a step of the incremental marking process, likely driven by allocation or tasks.
    * `MarkRoots()`: Marks objects directly reachable from the roots.
    * `Stop()`: Terminates the incremental marking process.
    * `AdvanceOnAllocation()`:  Triggers a marking step when memory is allocated.
    * `StartBlackAllocation()`, `PauseBlackAllocation()`, `FinishBlackAllocation()`: These methods strongly suggest a technique for handling concurrent allocation during marking (black allocation).
    * `UpdateMarkingWorklistAfterScavenge()`: Indicates interaction with the Scavenger (young generation GC).

* **`Observer`:** Seems to be an allocation observer that triggers `IncrementalMarking::AdvanceOnAllocation()` when a certain amount of memory is allocated.

* **`IncrementalMarkingJob`:**  Suggests that some of the marking work can be done on a separate thread or as a task.

**4. Understanding the Incremental Nature:**

The term "incremental" is crucial. I look for clues about how the marking is done in small steps rather than all at once. The `Step()` function and the allocation observers are key indicators. The `schedule_` member further suggests a controlled process.

**5. Connecting to JavaScript:**

To understand the JavaScript relationship, I consider the purpose of garbage collection. It's about managing memory used by JavaScript objects. Therefore, this code *directly* impacts how JavaScript's memory is reclaimed.

* **Example:** When a JavaScript object becomes unreachable (no longer referenced), this incremental marking process will eventually identify it as garbage and make it eligible for collection.

**6. Code Logic and Assumptions:**

For the input/output examples, I need to make reasonable assumptions based on my understanding of GC.

* **Assumption:**  `AdvanceOnAllocation()` is called after a certain amount of memory allocation.
* **Input:**  A JavaScript program allocates a significant number of objects.
* **Output:** The incremental marker will be triggered periodically, marking live objects. The `main_thread_marked_bytes_` counter would increase.

**7. Identifying Potential Programming Errors:**

I think about common JavaScript memory-related errors and how incremental marking helps.

* **Memory Leaks:**  While incremental marking can't *prevent* leaks (where objects are unintentionally kept alive), it efficiently reclaims memory from *true* garbage.
* **Long Pauses:** Traditional stop-the-world garbage collection can cause noticeable pauses in JavaScript execution. Incremental marking aims to reduce these pauses by doing the work in smaller increments.

**8. Putting it All Together (Summary):**

Finally, I synthesize the information gathered into a concise summary, highlighting the key functionalities and their significance. I focus on the "why" and "how" of incremental marking.

**Self-Correction/Refinement:**

During this process, I might encounter things I'm not entirely sure about. For example, the details of "black allocation" might require looking up V8 documentation or related code. I would refine my understanding and adjust the summary accordingly. The provided comments in the code are also extremely helpful for clarifying specific behaviors. For instance, the comments explaining the purpose of `UpdateMarkingWorklistAfterScavenge()` are invaluable.
好的，这是对 `v8/src/heap/incremental-marking.cc` 代码的功能归纳：

**核心功能：V8 的增量标记垃圾回收机制**

`v8/src/heap/incremental-marking.cc` 文件实现了 V8 JavaScript 引擎中用于主垃圾回收器（Major GC，也称为 Mark-Compact）和次垃圾回收器（Minor GC，也称为 Minor Mark-Sweep）的增量标记功能。

**主要功能点:**

1. **启动和停止增量标记：**
   - `Start()` 函数负责启动增量标记过程，可以针对主 GC 或次 GC。启动时会设置相应的标记状态，激活写屏障（Write Barrier），并根据配置安排后台标记任务。
   - `Stop()` 函数负责停止增量标记过程，清理标记状态，并移除分配观察者。

2. **增量标记步骤（Stepping）：**
   - 通过 `Step()` 函数执行增量标记的一个小步骤。这个步骤可以在主线程分配内存时 (`AdvanceOnAllocation()`) 或在后台任务中执行。
   - 增量步骤的大小受时间限制 (`kMaxStepSizeOnTask`, `kMaxStepSizeOnAllocation`) 和调度的影响 (`schedule_`)。

3. **根对象标记：**
   - `MarkRoots()` 函数负责标记从根对象可达的对象。根据是主 GC 还是次 GC，标记的根对象范围有所不同。

4. **黑分配（Black Allocation）：**
   - `StartBlackAllocation()`、`PauseBlackAllocation()` 和 `FinishBlackAllocation()`  实现了黑分配机制。在增量标记期间，新分配的对象会被直接标记为黑色，以简化并发标记过程。

5. **与并发标记协作：**
   - 代码中包含了与并发标记器 (`concurrent-marking.h`) 协作的逻辑，可以在后台线程执行部分的标记工作。

6. **与 Scavenge (新生代垃圾回收) 协作：**
   - `UpdateMarkingWorklistAfterScavenge()` 和 `UpdateExternalPointerTableAfterScavenge()` 函数处理在新生代垃圾回收（Scavenge）后更新标记工作列表和外部指针表。这是因为 Scavenge 会移动新生代的对象，需要同步更新标记信息。

7. **分配观察者（Allocation Observer）：**
   - `Observer` 类实现了分配观察者，当分配了一定量的内存后，会触发增量标记的 `AdvanceOnAllocation()` 方法，推动标记过程。

8. **调度（Scheduling）：**
   - `schedule_` 成员 (类型为 `::heap::base::IncrementalMarkingSchedule`) 负责决定每次增量标记步骤需要处理的字节数，以平衡性能和内存回收效率。

9. **性能追踪和调试：**
   - 代码中包含大量的 `TRACE_EVENT` 和条件编译的日志输出，用于追踪增量标记的执行过程和进行性能分析。

**关于问题的回答：**

* **`.tq` 结尾：**  `v8/src/heap/incremental-marking.cc` 以 `.cc` 结尾，**不是** V8 Torque 源代码。Torque 源代码通常以 `.tq` 结尾。

* **与 JavaScript 的关系：**  增量标记垃圾回收直接管理着 JavaScript 对象的内存。当 JavaScript 代码创建对象、操作对象，导致某些对象不再被引用时，增量标记负责识别这些不再使用的对象，以便后续的垃圾回收阶段进行回收，释放内存。

   **JavaScript 示例：**

   ```javascript
   function createObject() {
     let obj = { data: new Array(1000000) }; // 创建一个大对象
     return obj;
   }

   let myObject = createObject();
   // ... 一些使用 myObject 的代码 ...
   myObject = null; // myObject 不再被引用，成为垃圾
   ```

   在这个例子中，当 `myObject` 被赋值为 `null` 后，之前 `createObject()` 创建的对象变得不可达，成为垃圾。增量标记会逐步标记仍然存活的对象，最终识别出这个垃圾对象，为后续的内存回收做准备。如果没有增量标记，V8 可能需要在某个时刻暂停 JavaScript 执行，进行一次完整的标记，这会导致明显的卡顿。增量标记的目标就是减少这种卡顿。

* **代码逻辑推理（假设输入与输出）：**

   **假设输入：**
   - 已经启动了主 GC 的增量标记。
   - JavaScript 代码在短时间内分配了 1MB 的新对象。
   - `kMajorGCOldGenerationAllocationObserverStep` 设置为 256KB。

   **输出：**
   - 由于分配超过了 `kMajorGCOldGenerationAllocationObserverStep` 的阈值，`old_generation_observer_` 会多次触发 `AdvanceOnAllocation()`。
   - 每次 `AdvanceOnAllocation()` 调用会执行一次增量标记步骤，处理一定量的对象，增加 `main_thread_marked_bytes_` 的值。
   - 如果后台并发标记任务也在运行，`bytes_marked_concurrently_` 的值也会增加。

* **用户常见的编程错误：**

   增量标记本身是 V8 引擎的内部实现，用户一般不会直接操作它。但是，增量标记的存在是为了解决与垃圾回收相关的性能问题，这些问题通常由用户的编程错误导致，例如：

   - **内存泄漏：** 用户创建了对象，但忘记释放引用，导致对象一直存活，无法被垃圾回收。增量标记虽然不能阻止内存泄漏的发生，但可以有效地回收那些真正不再使用的对象，减轻内存压力。

     ```javascript
     let leakedObjects = [];
     function createAndLeak() {
       let obj = { data: new Array(1000) };
       leakedObjects.push(obj); // 将对象添加到全局数组，阻止被回收
     }

     for (let i = 0; i < 10000; i++) {
       createAndLeak();
     }
     ```
     在这个例子中，`leakedObjects` 数组会一直持有对创建的对象的引用，即使这些对象可能不再被程序的其他部分使用，导致内存泄漏。

   - **长时间运行的操作导致垃圾堆积：** 如果 JavaScript 代码执行长时间的同步操作，可能会导致新生代快速填满，触发多次 Scavenge，如果旧生代也持续分配，也会推动增量标记的进行。虽然这不是错误，但低效的代码可能加剧垃圾回收的压力。

**功能归纳 (第 1 部分):**

`v8/src/heap/incremental-marking.cc` 的主要功能是实现 V8 引擎的增量标记垃圾回收机制。它允许垃圾回收器逐步标记堆中的存活对象，而不是一次性暂停整个程序进行标记。这有助于减少垃圾回收带来的卡顿，提高 JavaScript 应用的性能和响应速度。该文件定义了启动、执行、停止增量标记的逻辑，并与并发标记和新生代垃圾回收机制协同工作，同时利用分配观察者来触发标记步骤。  它还包含了黑分配等优化技术来提高并发标记的效率。

Prompt: 
```
这是目录为v8/src/heap/incremental-marking.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/incremental-marking.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/incremental-marking.h"

#include <inttypes.h>

#include <cmath>
#include <optional>

#include "src/base/logging.h"
#include "src/base/platform/time.h"
#include "src/common/globals.h"
#include "src/execution/vm-state-inl.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles.h"
#include "src/heap/base/incremental-marking-schedule.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-visitor-inl.h"
#include "src/heap/heap-visitor.h"
#include "src/heap/heap.h"
#include "src/heap/incremental-marking-job.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-barrier.h"
#include "src/heap/marking-visitor-inl.h"
#include "src/heap/marking-visitor.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/minor-mark-sweep.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/safepoint.h"
#include "src/init/v8.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/numbers/conversions.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/slots-inl.h"
#include "src/objects/visitors.h"
#include "src/tracing/trace-event.h"
#include "src/utils/utils.h"

namespace v8 {
namespace internal {

namespace {

static constexpr size_t kMajorGCYoungGenerationAllocationObserverStep = 64 * KB;
static constexpr size_t kMajorGCOldGenerationAllocationObserverStep = 256 * KB;

static constexpr v8::base::TimeDelta kMaxStepSizeOnTask =
    v8::base::TimeDelta::FromMilliseconds(1);
static constexpr v8::base::TimeDelta kMaxStepSizeOnAllocation =
    v8::base::TimeDelta::FromMilliseconds(5);

#ifndef DEBUG
static constexpr size_t kV8ActivationThreshold = 8 * MB;
static constexpr size_t kEmbedderActivationThreshold = 8 * MB;
#else
static constexpr size_t kV8ActivationThreshold = 0;
static constexpr size_t kEmbedderActivationThreshold = 0;
#endif  // DEBUG

base::TimeDelta GetMaxDuration(StepOrigin step_origin) {
  if (v8_flags.predictable) {
    return base::TimeDelta::Max();
  }
  switch (step_origin) {
    case StepOrigin::kTask:
      return kMaxStepSizeOnTask;
    case StepOrigin::kV8:
      return kMaxStepSizeOnAllocation;
  }
}

}  // namespace

IncrementalMarking::Observer::Observer(IncrementalMarking* incremental_marking,
                                       intptr_t step_size)
    : AllocationObserver(step_size),
      incremental_marking_(incremental_marking) {}

void IncrementalMarking::Observer::Step(int, Address, size_t) {
  Heap* heap = incremental_marking_->heap();
  VMState<GC> state(heap->isolate());
  RCS_SCOPE(heap->isolate(),
            RuntimeCallCounterId::kGC_Custom_IncrementalMarkingObserver);
  incremental_marking_->AdvanceOnAllocation();
}

IncrementalMarking::IncrementalMarking(Heap* heap, WeakObjects* weak_objects)
    : heap_(heap),
      major_collector_(heap->mark_compact_collector()),
      minor_collector_(heap->minor_mark_sweep_collector()),
      weak_objects_(weak_objects),
      marking_state_(heap->marking_state()),
      incremental_marking_job_(
          v8_flags.incremental_marking_task
              ? std::make_unique<IncrementalMarkingJob>(heap)
              : nullptr),
      new_generation_observer_(this,
                               kMajorGCYoungGenerationAllocationObserverStep),
      old_generation_observer_(this,
                               kMajorGCOldGenerationAllocationObserverStep) {}

void IncrementalMarking::MarkBlackBackground(Tagged<HeapObject> obj,
                                             int object_size) {
  CHECK(marking_state()->TryMark(obj));
  base::MutexGuard guard(&background_live_bytes_mutex_);
  background_live_bytes_[MutablePageMetadata::FromHeapObject(obj)] +=
      static_cast<intptr_t>(object_size);
}

bool IncrementalMarking::CanAndShouldBeStarted() const {
  return CanBeStarted() && heap_->ShouldUseIncrementalMarking();
}

bool IncrementalMarking::CanBeStarted() const {
  // Only start incremental marking in a safe state:
  //   1) when incremental marking is turned on
  //   2) when we are currently not in a GC, and
  //   3) when we are currently not serializing or deserializing the heap, and
  //   4) not a shared heap.
  return v8_flags.incremental_marking && heap_->gc_state() == Heap::NOT_IN_GC &&
         heap_->deserialization_complete() && !isolate()->serializer_enabled();
}

bool IncrementalMarking::IsBelowActivationThresholds() const {
  return heap_->OldGenerationSizeOfObjects() <= kV8ActivationThreshold &&
         heap_->EmbedderSizeOfObjects() <= kEmbedderActivationThreshold;
}

void IncrementalMarking::Start(GarbageCollector garbage_collector,
                               GarbageCollectionReason gc_reason) {
  CHECK(IsStopped());
  CHECK_IMPLIES(garbage_collector == GarbageCollector::MARK_COMPACTOR,
                !heap_->sweeping_in_progress());
  CHECK_IMPLIES(garbage_collector == GarbageCollector::MINOR_MARK_SWEEPER,
                !heap_->minor_sweeping_in_progress());
  // Do not invoke CanAndShouldBeStarted() here again because its return value
  // might change across multiple invocations (its internal state could be
  // updated concurrently from another thread between invocations).
  CHECK(CanBeStarted());

  if (V8_UNLIKELY(v8_flags.trace_incremental_marking)) {
    const size_t old_generation_size_mb =
        heap()->OldGenerationSizeOfObjects() / MB;
    const size_t old_generation_waste_mb =
        heap()->OldGenerationWastedBytes() / MB;
    const size_t old_generation_limit_mb =
        heap()->old_generation_allocation_limit() / MB;
    const size_t global_size_mb = heap()->GlobalSizeOfObjects() / MB;
    const size_t global_waste_mb = heap()->GlobalWastedBytes() / MB;
    const size_t global_limit_mb = heap()->global_allocation_limit() / MB;
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Start (%s): (size/waste/limit/slack) v8: %zuMB / "
        "%zuMB / %zuMB "
        "/ %zuMB global: %zuMB / %zuMB / %zuMB / %zuMB\n",
        ToString(gc_reason), old_generation_size_mb, old_generation_waste_mb,
        old_generation_limit_mb,
        old_generation_size_mb + old_generation_waste_mb >
                old_generation_limit_mb
            ? 0
            : old_generation_limit_mb - old_generation_size_mb,
        global_size_mb, global_waste_mb, global_limit_mb,
        global_size_mb + global_waste_mb > global_limit_mb
            ? 0
            : global_limit_mb - global_size_mb);
  }

  Counters* counters = isolate()->counters();
  const bool is_major = garbage_collector == GarbageCollector::MARK_COMPACTOR;
  if (is_major) {
    // Reasons are only reported for major GCs
    counters->incremental_marking_reason()->AddSample(
        static_cast<int>(gc_reason));
  }
  NestedTimedHistogramScope incremental_marking_scope(
      is_major ? counters->gc_incremental_marking_start()
               : counters->gc_minor_incremental_marking_start());
  const auto scope_id = is_major ? GCTracer::Scope::MC_INCREMENTAL_START
                                 : GCTracer::Scope::MINOR_MS_INCREMENTAL_START;
  DCHECK(!current_trace_id_.has_value());
  current_trace_id_.emplace(reinterpret_cast<uint64_t>(this) ^
                            heap_->tracer()->CurrentEpoch(scope_id));
  TRACE_EVENT2("v8",
               is_major ? "V8.GCIncrementalMarkingStart"
                        : "V8.GCMinorIncrementalMarkingStart",
               "epoch", heap_->tracer()->CurrentEpoch(scope_id), "reason",
               ToString(gc_reason));
  TRACE_GC_EPOCH_WITH_FLOW(heap()->tracer(), scope_id, ThreadKind::kMain,
                           current_trace_id_.value(),
                           TRACE_EVENT_FLAG_FLOW_OUT);
  heap_->tracer()->NotifyIncrementalMarkingStart();

  start_time_ = v8::base::TimeTicks::Now();
  completion_task_scheduled_ = false;
  completion_task_timeout_ = v8::base::TimeTicks();
  main_thread_marked_bytes_ = 0;
  bytes_marked_concurrently_ = 0;

  if (is_major) {
    StartMarkingMajor();
    heap_->allocator()->AddAllocationObserver(&old_generation_observer_,
                                              &new_generation_observer_);
    if (incremental_marking_job()) {
      incremental_marking_job()->ScheduleTask();
    }
    DCHECK_NULL(schedule_);
    schedule_ =
        v8_flags.incremental_marking_bailout_when_ahead_of_schedule
            ? ::heap::base::IncrementalMarkingSchedule::
                  CreateWithZeroMinimumMarkedBytesPerStep(v8_flags.predictable)
            : ::heap::base::IncrementalMarkingSchedule::
                  CreateWithDefaultMinimumMarkedBytesPerStep(
                      v8_flags.predictable);
    schedule_->NotifyIncrementalMarkingStart();
  } else {
    // Allocation observers are not currently used by MinorMS because we don't
    // do incremental marking.
    StartMarkingMinor();
  }
}

void IncrementalMarking::MarkRoots() {
  if (IsMajorMarking()) {
    RootMarkingVisitor root_visitor(heap_->mark_compact_collector());
    heap_->IterateRoots(
        &root_visitor,
        base::EnumSet<SkipRoot>{SkipRoot::kStack, SkipRoot::kMainThreadHandles,
                                SkipRoot::kTracedHandles, SkipRoot::kWeak,
                                SkipRoot::kReadOnlyBuiltins});
  } else {
    DCHECK(IsMinorMarking());
    YoungGenerationRootMarkingVisitor root_visitor(
        heap_->minor_mark_sweep_collector());
    heap_->IterateRoots(
        &root_visitor,
        base::EnumSet<SkipRoot>{
            SkipRoot::kStack, SkipRoot::kMainThreadHandles, SkipRoot::kWeak,
            SkipRoot::kExternalStringTable, SkipRoot::kGlobalHandles,
            SkipRoot::kTracedHandles, SkipRoot::kOldGeneration,
            SkipRoot::kReadOnlyBuiltins});
    isolate()->global_handles()->IterateYoungStrongAndDependentRoots(
        &root_visitor);
  }
}

void IncrementalMarking::MarkRootsForTesting() { MarkRoots(); }

void IncrementalMarking::StartMarkingMajor() {
  if (isolate()->serializer_enabled()) {
    // Black allocation currently starts when we start incremental marking,
    // but we cannot enable black allocation while deserializing. Hence, we
    // have to delay the start of incremental marking in that case.
    if (v8_flags.trace_incremental_marking) {
      isolate()->PrintWithTimestamp(
          "[IncrementalMarking] Start delayed - serializer\n");
    }
    return;
  }
  if (v8_flags.trace_incremental_marking) {
    isolate()->PrintWithTimestamp("[IncrementalMarking] Start marking\n");
  }

  heap_->InvokeIncrementalMarkingPrologueCallbacks();

  // Free all existing LABs in the heap such that selecting evacuation
  // candidates does not need to deal with LABs on a page. While we don't need
  // this for correctness, we want to avoid creating additional work for
  // evacuation.
  heap_->FreeLinearAllocationAreas();

  is_compacting_ = major_collector_->StartCompaction(
      MarkCompactCollector::StartCompactionMode::kIncremental);

  major_collector_->StartMarking();
  current_local_marking_worklists_ =
      major_collector_->local_marking_worklists();

  marking_mode_ = MarkingMode::kMajorMarking;
  heap_->SetIsMarkingFlag(true);

  MarkingBarrier::ActivateAll(heap(), is_compacting_);
  isolate()->traced_handles()->SetIsMarking(true);

  StartBlackAllocation();

  {
    TRACE_GC(heap()->tracer(), GCTracer::Scope::MC_MARK_ROOTS);
    MarkRoots();
  }

  if (v8_flags.concurrent_marking && !heap_->IsTearingDown()) {
    heap_->concurrent_marking()->TryScheduleJob(
        GarbageCollector::MARK_COMPACTOR);
  }

  // Ready to start incremental marking.
  if (v8_flags.trace_incremental_marking) {
    isolate()->PrintWithTimestamp("[IncrementalMarking] Running\n");
  }

  if (heap()->cpp_heap()) {
    // StartTracing may call back into V8 in corner cases, requiring that
    // marking (including write barriers) is fully set up.
    TRACE_GC(heap()->tracer(), GCTracer::Scope::MC_MARK_EMBEDDER_PROLOGUE);
    CppHeap::From(heap()->cpp_heap())->StartMarking();
  }

  heap_->InvokeIncrementalMarkingEpilogueCallbacks();
}

void IncrementalMarking::StartMarkingMinor() {
  // Removed serializer_enabled() check because we don't do black allocation.

  if (v8_flags.trace_incremental_marking) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] (MinorMS) Start marking\n");
  }

  // We only reach this code if Heap::ShouldUseBackgroundThreads() returned
  // true. So we can force the use of background threads here.
  minor_collector_->StartMarking(true);
  current_local_marking_worklists_ =
      minor_collector_->local_marking_worklists();

  marking_mode_ = MarkingMode::kMinorMarking;
  heap_->SetIsMarkingFlag(true);
  heap_->SetIsMinorMarkingFlag(true);

  {
    Sweeper::PauseMajorSweepingScope pause_sweeping_scope(heap_->sweeper());
    MarkingBarrier::ActivateYoung(heap());
  }

  {
    TRACE_GC(heap()->tracer(), GCTracer::Scope::MINOR_MS_MARK_INCREMENTAL_SEED);
    MarkRoots();
  }

  if (v8_flags.concurrent_minor_ms_marking && !heap_->IsTearingDown()) {
    local_marking_worklists()->PublishWork();
    heap_->concurrent_marking()->TryScheduleJob(
        GarbageCollector::MINOR_MARK_SWEEPER);
  }

  if (v8_flags.trace_incremental_marking) {
    isolate()->PrintWithTimestamp("[IncrementalMarking] (MinorMS) Running\n");
  }

  DCHECK(!is_compacting_);
}

void IncrementalMarking::StartBlackAllocation() {
  DCHECK(!black_allocation_);
  DCHECK(IsMajorMarking());
  black_allocation_ = true;
  if (v8_flags.black_allocated_pages) {
    heap()->allocator()->FreeLinearAllocationAreasAndResetFreeLists();
  } else {
    heap()->allocator()->MarkLinearAllocationAreasBlack();
  }
  if (isolate()->is_shared_space_isolate()) {
    isolate()->global_safepoint()->IterateSharedSpaceAndClientIsolates(
        [](Isolate* client) {
          if (v8_flags.black_allocated_pages) {
            client->heap()->FreeSharedLinearAllocationAreasAndResetFreeLists();
          } else {
            client->heap()->MarkSharedLinearAllocationAreasBlack();
          }
        });
  }
  heap()->safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
    if (v8_flags.black_allocated_pages) {
      // The freelists of the underlying spaces must anyway be empty after the
      // first call to FreeLinearAllocationAreasAndResetFreeLists(). However,
      // don't call FreeLinearAllocationAreas(), since it also frees the
      // shared-space areas.
      local_heap->FreeLinearAllocationAreasAndResetFreeLists();
    } else {
      local_heap->MarkLinearAllocationAreasBlack();
    }
  });
  StartPointerTableBlackAllocation();
  if (v8_flags.trace_incremental_marking) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Black allocation started\n");
  }
}

void IncrementalMarking::PauseBlackAllocation() {
  DCHECK(IsMajorMarking());
  if (!v8_flags.black_allocated_pages) {
    heap()->allocator()->UnmarkLinearAllocationsArea();

    if (isolate()->is_shared_space_isolate()) {
      isolate()->global_safepoint()->IterateSharedSpaceAndClientIsolates(
          [](Isolate* client) {
            client->heap()->UnmarkSharedLinearAllocationAreas();
          });
    }

    heap()->safepoint()->IterateLocalHeaps([](LocalHeap* local_heap) {
      local_heap->UnmarkLinearAllocationsArea();
    });
  }
  StopPointerTableBlackAllocation();
  if (v8_flags.trace_incremental_marking) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Black allocation paused\n");
  }
  black_allocation_ = false;
}

void IncrementalMarking::FinishBlackAllocation() {
  if (!black_allocation_) {
    return;
  }
  // Don't fixup the marking bitmaps of the black allocated pages, since the
  // concurrent marker may still be running and will access the page flags.
  black_allocation_ = false;
  StopPointerTableBlackAllocation();
  if (v8_flags.trace_incremental_marking) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Black allocation finished\n");
  }
}

void IncrementalMarking::StartPointerTableBlackAllocation() {
#ifdef V8_COMPRESS_POINTERS
  heap()->old_external_pointer_space()->set_allocate_black(true);
  heap()->cpp_heap_pointer_space()->set_allocate_black(true);
#endif  // V8_COMPRESS_POINTERS
#ifdef V8_ENABLE_SANDBOX
  heap()->code_pointer_space()->set_allocate_black(true);
  heap()->trusted_pointer_space()->set_allocate_black(true);
  if (isolate()->is_shared_space_isolate()) {
    isolate()->shared_trusted_pointer_space()->set_allocate_black(true);
  }
#endif  // V8_ENABLE_SANDBOX
#ifdef V8_ENABLE_LEAPTIERING
  heap()->js_dispatch_table_space()->set_allocate_black(true);
#endif  // V8_ENABLE_LEAPTIERING
}

void IncrementalMarking::StopPointerTableBlackAllocation() {
#ifdef V8_COMPRESS_POINTERS
  heap()->old_external_pointer_space()->set_allocate_black(false);
  heap()->cpp_heap_pointer_space()->set_allocate_black(false);
#endif  // V8_COMPRESS_POINTERS
#ifdef V8_ENABLE_SANDBOX
  heap()->code_pointer_space()->set_allocate_black(false);
  heap()->trusted_pointer_space()->set_allocate_black(false);
  if (isolate()->is_shared_space_isolate()) {
    heap()->isolate()->shared_trusted_pointer_space()->set_allocate_black(
        false);
  }
#endif  // V8_ENABLE_SANDBOX
#ifdef V8_ENABLE_LEAPTIERING
  heap()->js_dispatch_table_space()->set_allocate_black(false);
#endif  // V8_ENABLE_LEAPTIERING
}

void IncrementalMarking::UpdateMarkingWorklistAfterScavenge() {
  if (!IsMajorMarking()) return;
  DCHECK(!v8_flags.separate_gc_phases);
  DCHECK(IsMajorMarking());
  // Minor MS never runs during incremental marking.
  DCHECK(!v8_flags.minor_ms);

  Tagged<Map> filler_map = ReadOnlyRoots(heap_).one_pointer_filler_map();

  MarkingState* marking_state = heap()->marking_state();

  major_collector_->local_marking_worklists()->Publish();
  MarkingBarrier::PublishAll(heap());
  PtrComprCageBase cage_base(isolate());
  major_collector_->marking_worklists()->Update([this, marking_state, cage_base,
                                                 filler_map](
                                                    Tagged<HeapObject> obj,
                                                    Tagged<HeapObject>* out)
                                                    -> bool {
    DCHECK(IsHeapObject(obj));
    USE(marking_state);

    // Only pointers to from space have to be updated.
    if (Heap::InFromPage(obj)) {
      MapWord map_word = obj->map_word(cage_base, kRelaxedLoad);
      if (!map_word.IsForwardingAddress()) {
        // There may be objects on the marking deque that do not exist
        // anymore, e.g. left trimmed objects or objects from the root set
        // (frames). If these object are dead at scavenging time, their
        // marking deque entries will not point to forwarding addresses.
        // Hence, we can discard them.
        return false;
      }
      // Live young large objects are not relocated and directly promoted into
      // the old generation before invoking this method. So they looke like any
      // other pointer into the old space and we won't encounter them here in
      // this code path.
      DCHECK(!Heap::IsLargeObject(obj));
      Tagged<HeapObject> dest = map_word.ToForwardingAddress(obj);
      DCHECK_IMPLIES(marking_state->IsUnmarked(obj), IsFreeSpaceOrFiller(obj));
      if (HeapLayout::InWritableSharedSpace(dest) &&
          !isolate()->is_shared_space_isolate()) {
        // Object got promoted into the shared heap. Drop it from the client
        // heap marking worklist.
        return false;
      }
      // For any object not a DescriptorArray, transferring the object always
      // increments live bytes as the marked state cannot distinguish fully
      // processed from to-be-processed. Decrement the counter for such objects
      // here.
      if (!IsDescriptorArray(dest)) {
        MutablePageMetadata::FromHeapObject(dest)->IncrementLiveBytesAtomically(
            -ALIGN_TO_ALLOCATION_ALIGNMENT(dest->Size()));
      }
      *out = dest;
      return true;
    } else {
      DCHECK(!Heap::InToPage(obj));
      DCHECK_IMPLIES(marking_state->IsUnmarked(obj),
                     IsFreeSpaceOrFiller(obj, cage_base));
      // Skip one word filler objects that appear on the
      // stack when we perform in place array shift.
      if (obj->map(cage_base) != filler_map) {
        *out = obj;
        return true;
      }
      return false;
    }
  });

  major_collector_->local_weak_objects()->Publish();
  weak_objects_->UpdateAfterScavenge();
}

void IncrementalMarking::UpdateExternalPointerTableAfterScavenge() {
#ifdef V8_COMPRESS_POINTERS
  if (!IsMajorMarking()) return;
  DCHECK(!v8_flags.separate_gc_phases);
  heap_->isolate()->external_pointer_table().UpdateAllEvacuationEntries(
      heap_->young_external_pointer_space(), [](Address old_handle_location) {
        if (old_handle_location == kNullAddress) {
          // Handle was clobbered by a previous Scavenger cycle.
          return kNullAddress;
        }
        // 1) Resolve object start from the marking bitmap. Note that it's safe
        //    since there is no black allocation for the young space (and hence
        //    no range or page marking).
        // 2) Get a relocated object from the forwaring reference stored in the
        //    map.
        // 3) Compute offset from the original object start to the handle
        //    location.
        // 4) Compute and return the new handle location.
        //
        // Please note that instead of updating the evacuation entries, we
        // could simply clobber them all, which would still work, but limit
        // compaction to some extent. We can reconsider this in the future, if
        // relying on the marking bitmap becomes an issue (e.g. with inlined
        // mark-bits).
        const MemoryChunk* chunk =
            MemoryChunk::FromAddress(old_handle_location);
        DCHECK_NOT_NULL(chunk);
        if (!chunk->InYoungGeneration()) {
          return old_handle_location;
        }
        // TODO(358485426): Check that the page is not black.

        Address base = MarkingBitmap::FindPreviousValidObject(
            static_cast<const PageMetadata*>(chunk->Metadata()),
            old_handle_location);
        Tagged<HeapObject> object(HeapObject::FromAddress(base));

        MapWord map_word = object->map_word(kRelaxedLoad);
        if (!map_word.IsForwardingAddress()) {
      // There may be objects in the EPT that do not exist anymore. If these
      // objects are dead at scavenging time, their marking deque entries will
      // not point to forwarding addresses. Hence, we can discard them.
#if DEBUG
          // Check that the handle did reside inside the original dead object.
          const int object_size = object->Size();
          // Map slots can never contain external pointers.
          DCHECK_LT(object.address(), old_handle_location);
          DCHECK_LT(old_handle_location, object.address() + object_size);
#endif  // DEBUG
          return kNullAddress;
        }

        Tagged<HeapObject> moved_object = map_word.ToForwardingAddress(object);
#if DEBUG
        const int object_size = moved_object->Size();
        // Map slots can never contain external pointers.
        DCHECK_LT(object.address(), old_handle_location);
        DCHECK_LT(old_handle_location, object.address() + object_size);
#endif  // DEBUG

        const ptrdiff_t handle_offset = old_handle_location - base;
        return moved_object.address() + handle_offset;
      });
#endif  // V8_COMPRESS_POINTERS
}

void IncrementalMarking::UpdateMarkedBytesAfterScavenge(
    size_t dead_bytes_in_new_space) {
  if (!IsMajorMarking()) return;
  // When removing the call, adjust the marking schedule to only support
  // monotonically increasing mutator marked bytes.
  main_thread_marked_bytes_ -=
      std::min(main_thread_marked_bytes_, dead_bytes_in_new_space);
}

v8::base::TimeDelta IncrementalMarking::EmbedderStep(
    v8::base::TimeDelta expected_duration) {
  DCHECK(IsMarking());
  auto* cpp_heap = CppHeap::From(heap_->cpp_heap());
  DCHECK_NOT_NULL(cpp_heap);
  if (!cpp_heap->incremental_marking_supported()) {
    return {};
  }

  TRACE_GC(heap()->tracer(), GCTracer::Scope::MC_INCREMENTAL_EMBEDDER_TRACING);
  const auto start = v8::base::TimeTicks::Now();
  cpp_heap->AdvanceTracing(expected_duration);
  return v8::base::TimeTicks::Now() - start;
}

bool IncrementalMarking::Stop() {
  if (IsStopped()) return false;

  if (v8_flags.trace_incremental_marking) {
    int old_generation_size_mb =
        static_cast<int>(heap()->OldGenerationSizeOfObjects() / MB);
    int old_generation_waste_mb =
        static_cast<int>(heap()->OldGenerationWastedBytes() / MB);
    int old_generation_limit_mb =
        static_cast<int>(heap()->old_generation_allocation_limit() / MB);
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Stopping: old generation size %dMB, waste %dMB, "
        "limit %dMB, "
        "overshoot %dMB\n",
        old_generation_size_mb, old_generation_waste_mb,
        old_generation_limit_mb,
        std::max(0, old_generation_size_mb + old_generation_waste_mb -
                        old_generation_limit_mb));
  }

  if (IsMajorMarking()) {
    heap()->allocator()->RemoveAllocationObserver(&old_generation_observer_,
                                                  &new_generation_observer_);
    major_collection_requested_via_stack_guard_ = false;
    isolate()->stack_guard()->ClearGC();
  }

  marking_mode_ = MarkingMode::kNoMarking;
  current_local_marking_worklists_ = nullptr;
  current_trace_id_.reset();

  if (isolate()->has_shared_space() && !isolate()->is_shared_space_isolate()) {
    // When disabling local incremental marking in a client isolate (= worker
    // isolate), the marking barrier needs to stay enabled when incremental
    // marking in the shared heap is running.
    const bool is_marking = isolate()
                                ->shared_space_isolate()
                                ->heap()
                                ->incremental_marking()
                                ->IsMajorMarking();
    heap_->SetIsMarkingFlag(is_marking);
  } else {
    heap_->SetIsMarkingFlag(false);
  }

  heap_->SetIsMinorMarkingFlag(false);
  is_compacting_ = false;
  FinishBlackAllocation();

  // Merge live bytes counters of background threads
  for (const auto& pair : background_live_bytes_) {
    MutablePageMetadata* memory_chunk = pair.first;
    intptr_t live_bytes = pair.second;
    if (live_bytes) {
      memory_chunk->IncrementLiveBytesAtomically(live_bytes);
    }
  }
  background_live_bytes_.clear();
  schedule_.reset();

  return true;
}

size_t IncrementalMarking::OldGenerationSizeOfObjects() const {
  // TODO(v8:14140): This is different to Heap::OldGenerationSizeOfObjects() in
  // that it only considers shared space for the shared space isolate. Consider
  // adjusting the Heap version.
  const bool is_shared_space_isolate =
      heap_->isolate()->is_shared_space_isolate();
  size_t total = 0;
  PagedSpaceIterator spaces(heap_);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    if (space->identity() == SHARED_SPACE && !is_shared_space_isolate) continue;
    total += space->SizeOfObjects();
  }
  total += heap_->lo_space()->SizeOfObjects();
  total += heap_->code_lo_space()->SizeOfObjects();
  if (heap_->shared_lo_space() && is_shared_space_isolate) {
    total += heap_->shared_lo_space()->SizeOfObjects();
  }
  return total;
}

bool IncrementalMarking::ShouldWaitForTask() {
  if (!completion_task_scheduled_) {
    if (!incremental_marking_job()) {
      return false;
    }
    incremental_marking_job()->ScheduleTask();
    completion_task_scheduled_ = true;
    if (!TryInitializeTaskTimeout()) {
      return false;
    }
  }

  const auto now = v8::base::TimeTicks::Now();
  const bool wait_for_task = now < completion_task_timeout_;
  if (V8_UNLIKELY(v8_flags.trace_incremental_marking)) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Completion: %s GC via stack guard, time left: "
        "%.1fms\n",
        wait_for_task ? "Delaying" : "Not delaying",
        (completion_task_timeout_ - now).InMillisecondsF());
  }
  return wait_for_task;
}

bool IncrementalMarking::TryInitializeTaskTimeout() {
  DCHECK_NOT_NULL(incremental_marking_job());
  // Allowed overshoot percentage of incremental marking walltime.
  constexpr double kAllowedOvershootPercentBasedOnWalltime = 0.1;
  // Minimum overshoot in ms. This is used to allow moving away from stack
  // when marking was fast.
  constexpr auto kMinAllowedOvershoot =
      v8::base::TimeDelta::FromMilliseconds(50);
  const auto now = v8::base::TimeTicks::Now();
  const auto allowed_overshoot = std::max(
      kMinAllowedOvershoot, v8::base::TimeDelta::FromMillisecondsD(
                                (now - start_time_).InMillisecondsF() *
                                kAllowedOvershootPercentBasedOnWalltime));
  const auto optional_avg_time_to_marking_task =
      incremental_marking_job()->AverageTimeToTask();
  // Only allowed to delay if the recorded average exists and is below the
  // threshold.
  bool delaying =
      optional_avg_time_to_marking_task.has_value() &&
      optional_avg_time_to_marking_task.value() <= allowed_overshoot;
  const auto optional_time_to_current_task =
      incremental_marking_job()->CurrentTimeToTask();
  // Don't bother delaying if the currently scheduled task is already waiting
  // too long.
  delaying =
      delaying && (!optional_time_to_current_task.has_value() ||
                   optional_time_to_current_task.value() <= allowed_overshoot);
  if (delaying) {
    const auto delta =
        !optional_time_to_current_task.has_value()
            ? allowed_overshoot
            : allowed_overshoot - optional_time_to_current_task.value();
    completion_task_timeout_ = now + delta;
  }
  DCHECK_IMPLIES(!delaying, completion_task_timeout_ <= now);
  if (V8_UNLIKELY(v8_flags.trace_incremental_marking)) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Completion: %s GC via stack guard, "
        "avg time to task: %.1fms, current time to task: %.1fms allowed "
        "overshoot: %.1fms\n",
        delaying ? "Delaying" : "Not delaying",
        optional_avg_time_to_marking_task.has_value()
            ? optional_avg_time_to_marking_task->InMillisecondsF()
            : NAN,
        optional_time_to_current_task.has_value()
            ? optional_time_to_current_task->InMillisecondsF()
            : NAN,
        allowed_overshoot.InMillisecondsF());
  }
  return delaying;
}

size_t IncrementalMarking::GetScheduledBytes(StepOrigin step_origin) {
  FetchBytesMarkedConcurrently();
  // TODO(v8:14140): Consider the size including young generation here as well
  // as the full marker marks both the young and old generations.
  const size_t max_bytes_to_process =
      schedule_->GetNextIncrementalStepDuration(OldGenerationSizeOfObjects());
  if (V8_UNLIKELY(v8_flags.trace_incremental_marking)) {
    const auto step_info = schedule_->GetCurrentStepInfo();
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Schedule: %zuKB to mark, origin: %s, elapsed: "
        "%.1f, marked: %zuKB (mutator: %zuKB, concurrent %zuKB), expected "
        "marked: %zuKB, estimated live: %zuKB, schedule delta: %+" PRIi64
        "KB\n",
        max_bytes_to_process / KB, ToString(step_origin),
        step_info.elapsed_time.InMillisecondsF(), step_info.marked_bytes() / KB,
        step_info.mutator_marked_bytes / KB,
        step_info.concurrent_marked_bytes / KB,
        step_info.expected_marked_bytes / KB,
        step_info.estimated_live_bytes / KB,
        step_info.scheduled_delta_bytes() / KB);
  }
  return max_bytes_to_process;
}

void IncrementalMarking::AdvanceAndFinalizeIfComplete() {
  const size_t max_bytes_to_process = GetScheduledBytes(StepOrigin::kTask);
  Step(GetMaxDuration(StepOrigin::kTask), max_bytes_to_process,
       StepOrigin::kTask);
  if (IsMajorMarkingComplete()) {
    heap()->FinalizeIncrementalMarkingAtomically(
        GarbageCollectionReason::kFinalizeMarkingViaTask);
  }
}

void IncrementalMarking::AdvanceAndFinalizeIfNecessary() {
  if (!IsMajorMarking()) return;
  DCHECK(!heap_->always_allocate());
  AdvanceOnAllocation();
  if (major_collection_requested_via_stack_guard_ && IsMajorMarkingComplete()) {
    heap()->FinalizeIncrementalMarkingAtomically(
        GarbageCollectionReason::kFinalizeMarkingViaStackGuard);
  }
}

"""


```