Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of the `gc-tracer.cc` file in V8, specifically:
    * A general overview of its purpose.
    * Identification as Torque or regular C++ source.
    * Connection to JavaScript functionality.
    * Logical reasoning with example input/output.
    * Common programming errors related to it.
    * A summary of its functions.

2. **Analyze the Provided Code:**  I scan the code for keywords and patterns that reveal its purpose. I look for:
    * **Class Names:** `GCTracer`, `Event`, `RecordGCPhasesInfo`. These immediately suggest the code is about tracking garbage collection activities.
    * **Method Names:** `StartCycle`, `StopCycle`, `StartAtomicPause`, `StopAtomicPause`, `SampleAllocation`, `AddIncrementalMarkingStep`, `Print`, `PrintNVP`. These are actions related to monitoring and reporting on GC.
    * **Data Members:** `current_`, `previous_`, `allocation_time_`, various counters and timers. These store the state and measurements of GC events.
    * **Includes:**  `<cstdarg>`, `<limits>`, `<optional>`, `"include/v8-metrics.h"`, `"src/base/...`, `"src/heap/..."`, `"src/logging/..."`, `"src/tracing/..."`. These reveal dependencies on core V8 structures, memory management, logging, and tracing.
    * **Namespaces:** `v8::internal`. This confirms it's part of V8's internal implementation.
    * **Logging and Tracing Statements:**  `VLOG`, `TRACE_EVENT_INSTANT`, `Output`, `Print`, `PrintNVP`. This indicates a key role in providing observability into GC behavior.
    * **Conditional Compilation (`v8_flags`)**:  This shows the functionality can be configured through command-line flags.

3. **Infer the Primary Functionality:** Based on the analysis, the core function of `gc-tracer.cc` is to **track and record details about garbage collection cycles** within the V8 JavaScript engine. This includes:
    * **Timing:**  Measuring the duration of various GC phases.
    * **Sizing:**  Tracking the amount of memory allocated and freed.
    * **Categorization:** Distinguishing between different types of GCs (Scavenger, Mark-Compact, Minor Mark-Sweep, Incremental).
    * **Reasoning:** Recording the reasons behind GC cycles.
    * **Performance Metrics:** Calculating averages and throughput.
    * **Logging and Tracing:** Outputting information about GC events for debugging and performance analysis.

4. **Address Specific Questions:**

    * **Torque Source:** The file extension is `.cc`, not `.tq`. So, it's a standard C++ source file. I'll state that clearly.

    * **Relationship to JavaScript:** While `gc-tracer.cc` is a C++ file, garbage collection is fundamental to JavaScript's memory management. I need to explain *how* it relates:  JavaScript doesn't have manual memory management. The V8 engine, using components like the GC tracer, automatically reclaims memory. I'll use a simple example of creating objects and letting the garbage collector handle them when they are no longer needed.

    * **Logical Reasoning (Input/Output):** This requires a simplified scenario. I'll choose the `StartCycle` and `StopCycle` methods. I'll create a hypothetical input (starting a Scavenger GC for a specific reason) and show how the `current_` event's state and type would change.

    * **Common Programming Errors:**  This is tricky because `gc-tracer.cc` is internal. Users don't directly interact with it. The errors are more likely in the *implementation* of the GC itself or in code that *triggers* GCs. I'll focus on the consequence of memory leaks in JavaScript (though the tracer doesn't *cause* them, it *observes* their effect).

    * **Summary of Functions:** I'll list the key functionalities identified earlier in a concise summary.

5. **Structure the Answer:** I'll organize the answer logically, addressing each part of the user's request clearly and separately. I'll use headings to improve readability.

6. **Refine and Review:** I'll reread my answer to ensure accuracy, clarity, and completeness. I'll double-check the code snippets and explanations. I'll make sure the language is appropriate and easy to understand. For example, instead of just saying "it logs", I'll specify *what* kind of information it logs.

By following these steps, I can provide a comprehensive and accurate answer to the user's request, even with limited direct user interaction with the specific source file.
好的，根据您提供的 V8 源代码 `v8/src/heap/gc-tracer.cc`，我们可以归纳一下它的功能：

**功能归纳：**

`gc-tracer.cc` 文件的主要功能是 **追踪和记录 V8 引擎中垃圾回收 (GC) 的各种事件和指标**。它负责收集和组织 GC 过程中发生的各种信息，用于性能分析、调试以及理解 GC 的行为。

**具体功能点包括：**

1. **事件跟踪:**
   - 记录 GC 周期的开始和结束，以及中间的各个阶段（如标记、压缩、清理等）。
   - 区分不同类型的 GC（新生代 GC - Scavenger, 老生代 GC - Mark-Compact 和 Minor Mark-Sweep）。
   - 记录 GC 的触发原因 (e.g., 内存压力、定时触发、开发者调用等)。
   - 跟踪 GC 事件的状态（例如，正在运行、已完成）。

2. **性能指标记录:**
   - 测量和记录 GC 各个阶段的耗时。
   - 记录 GC 前后的堆内存大小、对象大小、空洞大小等。
   - 记录新生代对象的存活大小。
   - 跟踪增量标记的进度（已标记的字节数和耗时）。
   - 记录压缩事件的信息（压缩的存活字节数和耗时）。
   - 采样记录分配速率。

3. **日志和输出:**
   - 提供详细的 GC 日志输出，可以包含各种 GC 事件的时间戳、持续时间、内存变化等信息。
   - 支持多种输出格式，例如普通的文本日志和 Name-Value Pair (NVP) 格式。
   - 将 GC 信息添加到环形缓冲区，用于在 OOM (Out Of Memory) 错误时提供上下文信息。
   - 与 V8 的 tracing 系统集成，可以将 GC 事件作为 trace events 输出，供 tracing 工具分析。

4. **与其他模块的交互:**
   - 与 `Heap` 类紧密协作，获取堆的状态信息。
   - 与 `IncrementalMarking` 类交互，跟踪增量标记的进度。
   - 与 `MemoryBalancer` 类交互，更新 GC 速度信息。
   - 与 `Counters` 类交互，更新和记录 GC 相关的性能计数器。
   - 与 `CppHeap` (Oilpan) 交互，处理 C++ 堆的 GC 完成通知。

5. **统计和分析:**
   - 计算 GC 的平均速度和吞吐量。
   - 记录生存率 (survival ratio)。
   - 维护 GC 的平均 mutator 利用率 (mutator utilization)。

**关于其他问题的回答：**

* **v8/src/heap/gc-tracer.cc 以 .tq 结尾：**  代码的文件名是 `.cc`，因此它是一个 **V8 的 C++ 源代码文件**，而不是 Torque 源代码。 Torque 源代码文件以 `.tq` 结尾。

* **与 JavaScript 的功能关系：** `gc-tracer.cc` 虽然是用 C++ 编写的，但它直接关系到 JavaScript 的内存管理。JavaScript 具有自动垃圾回收机制，V8 引擎负责实现这个机制。`gc-tracer.cc` 负责监控和记录 V8 执行垃圾回收操作的细节。

   **JavaScript 示例：**

   ```javascript
   let myObject = {}; // 创建一个对象

   // ... 一些操作，使得 myObject 不再被引用 ...
   myObject = null;

   // 在某个时刻，V8 的垃圾回收器会回收之前 myObject 占用的内存
   // gc-tracer.cc 会记录这次垃圾回收事件，包括回收的时间、内存大小等信息。
   ```

   在这个例子中，当 `myObject` 不再被引用时，它就成为了垃圾回收器的回收目标。`gc-tracer.cc` 会记录 V8 执行回收 `myObject` 所占内存的事件。

* **代码逻辑推理（假设输入与输出）：**

   **假设输入：**

   1. 在一个 V8 实例中，通过 JavaScript 代码分配了一些内存，例如创建了许多对象。
   2. 内存压力达到阈值，触发了一次新生代垃圾回收 (Scavenger)。
   3. `GCTracer::StartCycle` 被调用，`collector` 参数为 `GarbageCollector::SCAVENGER`，`gc_reason` 参数为 `kHeapPressure`.
   4. 新生代 GC 完成，`GCTracer::StopCycle` 被调用。

   **预期输出（部分）：**

   - `current_` 成员变量的状态会发生变化：
     - 在 `StartCycle` 调用后，`current_.type` 会被设置为 `Event::Type::SCAVENGER`，`current_.state` 会被设置为 `Event::State::MARKING`（或其他 GC 初期的状态）。
   - 日志输出（如果启用了 `v8_flags.trace_gc`）：
     - 会有一条类似于 `Scavenge ... kHeapPressure` 的日志记录，包含 GC 的开始时间、内存变化等信息。
   - 性能指标会被记录：
     - 新生代 GC 的耗时会被记录在 `current_.scopes` 中相应的键值下。
     - 回收的内存大小会被计算并记录。

* **涉及用户常见的编程错误：**

   虽然用户不直接操作 `gc-tracer.cc`，但 `gc-tracer.cc` 记录的信息可以帮助诊断与垃圾回收相关的编程错误，例如：

   **示例：内存泄漏**

   ```javascript
   let leakedObjects = [];
   function createLeakedObject() {
       let obj = { data: new Array(10000) };
       leakedObjects.push(obj); // 错误：持续引用导致无法回收
   }

   setInterval(createLeakedObject, 100); // 每 100 毫秒创建一个无法回收的对象
   ```

   在这个例子中，`leakedObjects` 数组持续引用创建的对象，导致这些对象无法被垃圾回收。`gc-tracer.cc` 记录的日志可能会显示：

   - 随着时间的推移，堆内存持续增长。
   - 垃圾回收的频率增加，但回收效果不明显。
   - 老生代 GC 的执行次数增加。

   通过分析 `gc-tracer.cc` 记录的这些信息，开发者可以更容易地诊断出内存泄漏的问题。

**总结：**

`v8/src/heap/gc-tracer.cc` 是 V8 引擎中负责 **监控、记录和报告垃圾回收活动** 的核心组件。它收集详细的 GC 事件和性能指标，为性能分析、调试和理解 V8 的内存管理机制提供了重要的依据。它与 JavaScript 的内存管理紧密相关，虽然开发者不直接操作它，但其记录的信息对于诊断 JavaScript 代码中的内存问题至关重要。

### 提示词
```
这是目录为v8/src/heap/gc-tracer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/gc-tracer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/gc-tracer.h"

#include <cstdarg>
#include <limits>
#include <optional>

#include "include/v8-metrics.h"
#include "src/base/atomic-utils.h"
#include "src/base/logging.h"
#include "src/base/platform/time.h"
#include "src/base/strings.h"
#include "src/common/globals.h"
#include "src/execution/thread-id.h"
#include "src/heap/cppgc-js/cpp-heap.h"
#include "src/heap/cppgc/metric-recorder.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/memory-balancer.h"
#include "src/heap/spaces.h"
#include "src/logging/counters.h"
#include "src/logging/metrics.h"
#include "src/logging/tracing-flags.h"
#include "src/tracing/tracing-category-observer.h"

namespace v8 {
namespace internal {

static size_t CountTotalHolesSize(Heap* heap) {
  size_t holes_size = 0;
  PagedSpaceIterator spaces(heap);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    DCHECK_GE(holes_size + space->Waste() + space->Available(), holes_size);
    holes_size += space->Waste() + space->Available();
  }
  return holes_size;
}

namespace {

std::atomic<CollectionEpoch> global_epoch{0};

CollectionEpoch next_epoch() {
  return global_epoch.fetch_add(1, std::memory_order_relaxed) + 1;
}

using BytesAndDuration = ::heap::base::BytesAndDuration;

double BoundedAverageSpeed(const base::RingBuffer<BytesAndDuration>& buffer) {
  constexpr size_t kMinNonEmptySpeedInBytesPerMs = 1;
  constexpr size_t kMaxSpeedInBytesPerMs = GB;
  return ::heap::base::AverageSpeed(buffer, BytesAndDuration(), std::nullopt,
                                    kMinNonEmptySpeedInBytesPerMs,
                                    kMaxSpeedInBytesPerMs);
}

double BoundedThroughput(const ::heap::base::SmoothedBytesAndDuration& buffer) {
  constexpr double kMaxSpeedInBytesPerMs = static_cast<double>(GB);
  return std::min(buffer.GetThroughput(), kMaxSpeedInBytesPerMs);
}

}  // namespace

GCTracer::Event::Event(Type type, State state,
                       GarbageCollectionReason gc_reason,
                       const char* collector_reason,
                       GCTracer::Priority priority)
    : type(type),
      state(state),
      gc_reason(gc_reason),
      collector_reason(collector_reason),
      priority(priority) {}

const char* ToString(GCTracer::Event::Type type, bool short_name) {
  switch (type) {
    case GCTracer::Event::Type::SCAVENGER:
      return (short_name) ? "s" : "Scavenge";
    case GCTracer::Event::Type::MARK_COMPACTOR:
    case GCTracer::Event::Type::INCREMENTAL_MARK_COMPACTOR:
      return (short_name) ? "mc" : "Mark-Compact";
    case GCTracer::Event::Type::MINOR_MARK_SWEEPER:
    case GCTracer::Event::Type::INCREMENTAL_MINOR_MARK_SWEEPER:
      return (short_name) ? "mms" : "Minor Mark-Sweep";
    case GCTracer::Event::Type::START:
      return (short_name) ? "st" : "Start";
  }
}

GCTracer::RecordGCPhasesInfo::RecordGCPhasesInfo(
    Heap* heap, GarbageCollector collector, GarbageCollectionReason reason) {
  if (Heap::IsYoungGenerationCollector(collector)) {
    type_timer_ = nullptr;
    type_priority_timer_ = nullptr;
    if (!v8_flags.minor_ms) {
      mode_ = Mode::Scavenger;
      trace_event_name_ = "V8.GCScavenger";
    } else {
      mode_ = Mode::None;
      trace_event_name_ = "V8.GCMinorMS";
    }
  } else {
    DCHECK_EQ(GarbageCollector::MARK_COMPACTOR, collector);
    Counters* counters = heap->isolate()->counters();
    const bool in_background = heap->isolate()->is_backgrounded();
    const bool is_incremental = !heap->incremental_marking()->IsStopped();
    mode_ = Mode::None;
    // The following block selects histogram counters to emit. The trace event
    // name should be changed when metrics are updated.
    //
    // Memory reducing GCs take priority over memory measurement GCs. They can
    // happen at the same time when measuring memory is folded into a memory
    // reducing GC.
    if (is_incremental) {
      if (heap->ShouldReduceMemory()) {
        type_timer_ = counters->gc_finalize_incremental_memory_reducing();
        type_priority_timer_ =
            in_background
                ? counters->gc_finalize_incremental_memory_reducing_background()
                : counters
                      ->gc_finalize_incremental_memory_reducing_foreground();
        trace_event_name_ = "V8.GCFinalizeMCReduceMemory";
      } else if (reason == GarbageCollectionReason::kMeasureMemory) {
        type_timer_ = counters->gc_finalize_incremental_memory_measure();
        type_priority_timer_ =
            in_background
                ? counters->gc_finalize_incremental_memory_measure_background()
                : counters->gc_finalize_incremental_memory_measure_foreground();
        trace_event_name_ = "V8.GCFinalizeMCMeasureMemory";
      } else {
        type_timer_ = counters->gc_finalize_incremental_regular();
        type_priority_timer_ =
            in_background
                ? counters->gc_finalize_incremental_regular_background()
                : counters->gc_finalize_incremental_regular_foreground();
        trace_event_name_ = "V8.GCFinalizeMC";
        mode_ = Mode::Finalize;
      }
    } else {
      trace_event_name_ = "V8.GCCompactor";
      if (heap->ShouldReduceMemory()) {
        type_timer_ = counters->gc_finalize_non_incremental_memory_reducing();
        type_priority_timer_ =
            in_background
                ? counters
                      ->gc_finalize_non_incremental_memory_reducing_background()
                : counters
                      ->gc_finalize_non_incremental_memory_reducing_foreground();
      } else if (reason == GarbageCollectionReason::kMeasureMemory) {
        type_timer_ = counters->gc_finalize_non_incremental_memory_measure();
        type_priority_timer_ =
            in_background
                ? counters
                      ->gc_finalize_non_incremental_memory_measure_background()
                : counters
                      ->gc_finalize_non_incremental_memory_measure_foreground();
      } else {
        type_timer_ = counters->gc_finalize_non_incremental_regular();
        type_priority_timer_ =
            in_background
                ? counters->gc_finalize_non_incremental_regular_background()
                : counters->gc_finalize_non_incremental_regular_foreground();
      }
    }
  }
}

GCTracer::GCTracer(Heap* heap, base::TimeTicks startup_time,
                   GarbageCollectionReason initial_gc_reason)
    : heap_(heap),
      current_(Event::Type::START, Event::State::NOT_RUNNING, initial_gc_reason,
               nullptr, heap_->isolate()->priority()),
      previous_(current_),
      allocation_time_(startup_time),
      previous_mark_compact_end_time_(startup_time) {
  // All accesses to incremental_marking_scope assume that incremental marking
  // scopes come first.
  static_assert(0 == Scope::FIRST_INCREMENTAL_SCOPE);
  // We assume that MC_INCREMENTAL is the first scope so that we can properly
  // map it to RuntimeCallStats.
  static_assert(0 == Scope::MC_INCREMENTAL);
  // Starting a new cycle will make the current event the previous event.
  // Setting the current end time here allows us to refer back to a previous
  // event's end time to compute time spent in mutator.
  current_.end_time = previous_mark_compact_end_time_;
}

void GCTracer::ResetForTesting() {
  auto* heap = heap_;
  this->~GCTracer();
  new (this)
      GCTracer(heap, base::TimeTicks::Now(), GarbageCollectionReason::kTesting);
}

void GCTracer::StartObservablePause(base::TimeTicks time) {
  DCHECK(!IsInObservablePause());
  start_of_observable_pause_.emplace(time);
}

void GCTracer::UpdateCurrentEvent(GarbageCollectionReason gc_reason,
                                  const char* collector_reason) {
  // For incremental marking, the event has already been created and we just
  // need to update a few fields.
  DCHECK(current_.type == Event::Type::INCREMENTAL_MARK_COMPACTOR ||
         current_.type == Event::Type::INCREMENTAL_MINOR_MARK_SWEEPER);
  DCHECK_EQ(Event::State::ATOMIC, current_.state);
  DCHECK(IsInObservablePause());
  current_.gc_reason = gc_reason;
  current_.collector_reason = collector_reason;
  // TODO(chromium:1154636): The start_time of the current event contains
  // currently the start time of the observable pause. This should be
  // reconsidered.
  current_.start_time = start_of_observable_pause_.value();
  current_.reduce_memory = heap_->ShouldReduceMemory();
}

void GCTracer::StartCycle(GarbageCollector collector,
                          GarbageCollectionReason gc_reason,
                          const char* collector_reason, MarkingType marking) {
  // We cannot start a new cycle while there's another one in its atomic pause.
  DCHECK_NE(Event::State::ATOMIC, current_.state);
  // We cannot start a new cycle while a young generation GC cycle has
  // already interrupted a full GC cycle.
  DCHECK(!young_gc_while_full_gc_);

  young_gc_while_full_gc_ = current_.state != Event::State::NOT_RUNNING;
  CHECK_IMPLIES(v8_flags.separate_gc_phases && young_gc_while_full_gc_,
                current_.state == Event::State::SWEEPING);
  if (young_gc_while_full_gc_) {
    // The cases for interruption are: Scavenger, MinorMS interrupting sweeping.
    // In both cases we are fine with fetching background counters now and
    // fixing them up later in StopAtomicPause().
    FetchBackgroundCounters();
  }

  DCHECK_IMPLIES(young_gc_while_full_gc_,
                 Heap::IsYoungGenerationCollector(collector));
  DCHECK_IMPLIES(young_gc_while_full_gc_,
                 !Event::IsYoungGenerationEvent(current_.type));

  Event::Type type;
  switch (collector) {
    case GarbageCollector::SCAVENGER:
      type = Event::Type::SCAVENGER;
      break;
    case GarbageCollector::MINOR_MARK_SWEEPER:
      type = marking == MarkingType::kIncremental
                 ? Event::Type::INCREMENTAL_MINOR_MARK_SWEEPER
                 : Event::Type::MINOR_MARK_SWEEPER;
      break;
    case GarbageCollector::MARK_COMPACTOR:
      type = marking == MarkingType::kIncremental
                 ? Event::Type::INCREMENTAL_MARK_COMPACTOR
                 : Event::Type::MARK_COMPACTOR;
      break;
  }

  DCHECK_IMPLIES(!young_gc_while_full_gc_,
                 current_.state == Event::State::NOT_RUNNING);
  DCHECK_EQ(Event::State::NOT_RUNNING, previous_.state);

  previous_ = current_;
  current_ = Event(type, Event::State::MARKING, gc_reason, collector_reason,
                   heap_->isolate()->priority());

  switch (marking) {
    case MarkingType::kAtomic:
      DCHECK(IsInObservablePause());
      // TODO(chromium:1154636): The start_time of the current event contains
      // currently the start time of the observable pause. This should be
      // reconsidered.
      current_.start_time = start_of_observable_pause_.value();
      current_.reduce_memory = heap_->ShouldReduceMemory();
      break;
    case MarkingType::kIncremental:
      // The current event will be updated later.
      DCHECK_IMPLIES(Heap::IsYoungGenerationCollector(collector),
                     (v8_flags.minor_ms &&
                      collector == GarbageCollector::MINOR_MARK_SWEEPER));
      DCHECK(!IsInObservablePause());
      break;
  }

  if (Heap::IsYoungGenerationCollector(collector)) {
    epoch_young_ = next_epoch();
  } else {
    epoch_full_ = next_epoch();
  }
}

void GCTracer::StartAtomicPause() {
  DCHECK_EQ(Event::State::MARKING, current_.state);
  current_.state = Event::State::ATOMIC;
}

void GCTracer::StartInSafepoint(base::TimeTicks time) {
  SampleAllocation(current_.start_time, heap_->NewSpaceAllocationCounter(),
                   heap_->OldGenerationAllocationCounter(),
                   heap_->EmbedderAllocationCounter());

  current_.start_object_size = heap_->SizeOfObjects();
  current_.start_memory_size = heap_->memory_allocator()->Size();
  current_.start_holes_size = CountTotalHolesSize(heap_);
  size_t new_space_size = (heap_->new_space() ? heap_->new_space()->Size() : 0);
  size_t new_lo_space_size =
      (heap_->new_lo_space() ? heap_->new_lo_space()->SizeOfObjects() : 0);
  current_.young_object_size = new_space_size + new_lo_space_size;
  current_.start_atomic_pause_time = time;
}

void GCTracer::StopInSafepoint(base::TimeTicks time) {
  current_.end_object_size = heap_->SizeOfObjects();
  current_.end_memory_size = heap_->memory_allocator()->Size();
  current_.end_holes_size = CountTotalHolesSize(heap_);
  current_.survived_young_object_size = heap_->SurvivedYoungObjectSize();
  current_.end_atomic_pause_time = time;

  // Do not include the GC pause for calculating the allocation rate. GC pause
  // with heap verification can decrease the allocation rate significantly.
  allocation_time_ = time;

  if (v8_flags.memory_balancer) {
    UpdateMemoryBalancerGCSpeed();
  }
}

void GCTracer::StopObservablePause(GarbageCollector collector,
                                   base::TimeTicks time) {
  DCHECK(IsConsistentWithCollector(collector));
  DCHECK(IsInObservablePause());
  start_of_observable_pause_.reset();

  // TODO(chromium:1154636): The end_time of the current event contains
  // currently the end time of the observable pause. This should be
  // reconsidered.
  current_.end_time = time;

  FetchBackgroundCounters();

  const base::TimeDelta duration = current_.end_time - current_.start_time;
  auto* long_task_stats = heap_->isolate()->GetCurrentLongTaskStats();
  const bool is_young = Heap::IsYoungGenerationCollector(collector);
  if (is_young) {
    recorded_minor_gc_atomic_pause_.Push(
        BytesAndDuration(current_.survived_young_object_size, duration));
    long_task_stats->gc_young_wall_clock_duration_us +=
        duration.InMicroseconds();
  } else {
    if (current_.type == Event::Type::INCREMENTAL_MARK_COMPACTOR) {
      RecordIncrementalMarkingSpeed(current_.incremental_marking_bytes,
                                    current_.incremental_marking_duration);
      recorded_incremental_mark_compacts_.Push(
          BytesAndDuration(current_.end_object_size, duration));
      for (int i = 0; i < Scope::NUMBER_OF_INCREMENTAL_SCOPES; i++) {
        current_.incremental_scopes[i] = incremental_scopes_[i];
        current_.scopes[i] = incremental_scopes_[i].duration;
        new (&incremental_scopes_[i]) IncrementalInfos;
      }
    } else {
      recorded_mark_compacts_.Push(
          BytesAndDuration(current_.end_object_size, duration));
      DCHECK_EQ(0u, current_.incremental_marking_bytes);
      DCHECK(current_.incremental_marking_duration.IsZero());
    }
    RecordGCSumCounters();
    combined_mark_compact_speed_cache_ = 0.0;
    long_task_stats->gc_full_atomic_wall_clock_duration_us +=
        duration.InMicroseconds();
    RecordMutatorUtilization(current_.end_time,
                             duration + current_.incremental_marking_duration);
  }

  heap_->UpdateTotalGCTime(duration);

  if (v8_flags.trace_gc_ignore_scavenger && is_young) return;

  if (v8_flags.trace_gc_nvp) {
    PrintNVP();
  } else {
    Print();
  }

  if (v8_flags.trace_gc) {
    heap_->PrintShortHeapStatistics();
  }

  if (V8_UNLIKELY(TracingFlags::gc.load(std::memory_order_relaxed) &
                  v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
    TRACE_GC_NOTE("V8.GC_HEAP_DUMP_STATISTICS");
    std::stringstream heap_stats;
    heap_->DumpJSONHeapStatistics(heap_stats);

    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("v8.gc"), "V8.GC_Heap_Stats",
                         TRACE_EVENT_SCOPE_THREAD, "stats",
                         TRACE_STR_COPY(heap_stats.str().c_str()));
  }
}

void GCTracer::UpdateMemoryBalancerGCSpeed() {
  DCHECK(v8_flags.memory_balancer);
  size_t major_gc_bytes = current_.start_object_size;
  const base::TimeDelta atomic_pause_duration =
      current_.end_atomic_pause_time - current_.start_atomic_pause_time;
  const base::TimeDelta blocked_time_taken =
      atomic_pause_duration + current_.incremental_marking_duration;
  base::TimeDelta concurrent_gc_time;
  {
    base::MutexGuard guard(&background_scopes_mutex_);
    concurrent_gc_time =
        background_scopes_[Scope::MC_BACKGROUND_EVACUATE_COPY] +
        background_scopes_[Scope::MC_BACKGROUND_EVACUATE_UPDATE_POINTERS] +
        background_scopes_[Scope::MC_BACKGROUND_MARKING] +
        background_scopes_[Scope::MC_BACKGROUND_SWEEPING];
  }
  const base::TimeDelta major_gc_duration =
      blocked_time_taken + concurrent_gc_time;
  const base::TimeDelta major_allocation_duration =
      (current_.end_atomic_pause_time - previous_mark_compact_end_time_) -
      blocked_time_taken;
  CHECK_GE(major_allocation_duration, base::TimeDelta());

  heap_->mb_->UpdateGCSpeed(major_gc_bytes, major_gc_duration);
}

void GCTracer::StopAtomicPause() {
  DCHECK_EQ(Event::State::ATOMIC, current_.state);
  current_.state = Event::State::SWEEPING;
}

namespace {

// Estimate of young generation wall time across all threads up to and including
// the atomic pause.
constexpr v8::base::TimeDelta YoungGenerationWallTime(
    const GCTracer::Event& event) {
  return
      // Scavenger events.
      event.scopes[GCTracer::Scope::SCAVENGER] +
      event.scopes[GCTracer::Scope::SCAVENGER_BACKGROUND_SCAVENGE_PARALLEL] +
      // Minor MS events.
      event.scopes[GCTracer::Scope::MINOR_MS] +
      event.scopes[GCTracer::Scope::MINOR_MS_BACKGROUND_MARKING];
}

}  // namespace

void GCTracer::StopCycle(GarbageCollector collector) {
  DCHECK_EQ(Event::State::SWEEPING, current_.state);
  current_.state = Event::State::NOT_RUNNING;

  DCHECK(IsConsistentWithCollector(collector));

  FetchBackgroundCounters();

  if (Heap::IsYoungGenerationCollector(collector)) {
    ReportYoungCycleToRecorder();

    const v8::base::TimeDelta per_thread_wall_time =
        YoungGenerationWallTime(current_) / current_.concurrency_estimate;
    recorded_minor_gc_per_thread_.Push(BytesAndDuration(
        current_.survived_young_object_size, per_thread_wall_time));

    // If a young generation GC interrupted an unfinished full GC cycle, restore
    // the event corresponding to the full GC cycle.
    if (young_gc_while_full_gc_) {
      // Sweeping for full GC could have occured during the young GC. Copy over
      // any sweeping scope values to the previous_ event. The full GC sweeping
      // scopes are never reported by young cycles.
      previous_.scopes[Scope::MC_SWEEP] += current_.scopes[Scope::MC_SWEEP];
      previous_.scopes[Scope::MC_BACKGROUND_SWEEPING] +=
          current_.scopes[Scope::MC_BACKGROUND_SWEEPING];
      std::swap(current_, previous_);
      young_gc_while_full_gc_ = false;
    }
  } else {
    ReportFullCycleToRecorder();

    heap_->isolate()->counters()->mark_compact_reason()->AddSample(
        static_cast<int>(current_.gc_reason));

    if (v8_flags.trace_gc_freelists) {
      PrintIsolate(heap_->isolate(),
                   "FreeLists statistics before collection:\n");
      heap_->PrintFreeListsStats();
    }
  }
}

void GCTracer::StopFullCycleIfNeeded() {
  if (current_.state != Event::State::SWEEPING) return;
  if (!notified_full_sweeping_completed_) return;
  if (heap_->cpp_heap() && !notified_full_cppgc_completed_) return;
  StopCycle(GarbageCollector::MARK_COMPACTOR);
  notified_full_sweeping_completed_ = false;
  notified_full_cppgc_completed_ = false;
  full_cppgc_completed_during_minor_gc_ = false;
}

void GCTracer::StopYoungCycleIfNeeded() {
  DCHECK(Event::IsYoungGenerationEvent(current_.type));
  if (current_.state != Event::State::SWEEPING) return;
  if ((current_.type == Event::Type::MINOR_MARK_SWEEPER ||
       current_.type == Event::Type::INCREMENTAL_MINOR_MARK_SWEEPER) &&
      !notified_young_sweeping_completed_)
    return;
  // Check if young cppgc was scheduled but hasn't completed yet.
  if (heap_->cpp_heap() && notified_young_cppgc_running_ &&
      !notified_young_cppgc_completed_)
    return;
  bool was_young_gc_while_full_gc_ = young_gc_while_full_gc_;
  StopCycle(current_.type == Event::Type::SCAVENGER
                ? GarbageCollector::SCAVENGER
                : GarbageCollector::MINOR_MARK_SWEEPER);
  notified_young_sweeping_completed_ = false;
  notified_young_cppgc_running_ = false;
  notified_young_cppgc_completed_ = false;
  if (was_young_gc_while_full_gc_) {
    // Check if the full gc cycle is ready to be stopped.
    StopFullCycleIfNeeded();
  }
}

void GCTracer::NotifyFullSweepingCompleted() {
  // Notifying twice that V8 sweeping is finished for the same cycle is possible
  // only if Oilpan sweeping is still in progress.
  DCHECK_IMPLIES(
      notified_full_sweeping_completed_,
      !notified_full_cppgc_completed_ || full_cppgc_completed_during_minor_gc_);

  if (Event::IsYoungGenerationEvent(current_.type)) {
    bool was_young_gc_while_full_gc = young_gc_while_full_gc_;
    bool was_full_sweeping_notified = notified_full_sweeping_completed_;
    NotifyYoungSweepingCompleted();
    // NotifyYoungSweepingCompleted checks if the full cycle needs to be stopped
    // as well. If full sweeping was already notified, nothing more needs to be
    // done here.
    if (!was_young_gc_while_full_gc || was_full_sweeping_notified) return;
  }

  DCHECK(!Event::IsYoungGenerationEvent(current_.type));
  // Sweeping finalization can also be triggered from inside a full GC cycle's
  // atomic pause.
  DCHECK(current_.state == Event::State::SWEEPING ||
         current_.state == Event::State::ATOMIC);

  // Stop a full GC cycle only when both v8 and cppgc (if available) GCs have
  // finished sweeping. This method is invoked by v8.
  if (v8_flags.trace_gc_freelists) {
    PrintIsolate(heap_->isolate(),
                 "FreeLists statistics after sweeping completed:\n");
    heap_->PrintFreeListsStats();
  }
  notified_full_sweeping_completed_ = true;
  StopFullCycleIfNeeded();
}

void GCTracer::NotifyYoungSweepingCompleted() {
  if (!Event::IsYoungGenerationEvent(current_.type)) return;
  if (v8_flags.verify_heap) {
    // If heap verification is enabled, sweeping finalization can also be
    // triggered from inside a full GC cycle's atomic pause.
    DCHECK(current_.type == Event::Type::MINOR_MARK_SWEEPER ||
           current_.type == Event::Type::INCREMENTAL_MINOR_MARK_SWEEPER);
    DCHECK(current_.state == Event::State::SWEEPING ||
           current_.state == Event::State::ATOMIC);
  } else {
    DCHECK(IsSweepingInProgress());
  }

  DCHECK(!notified_young_sweeping_completed_);
  notified_young_sweeping_completed_ = true;
  StopYoungCycleIfNeeded();
}

void GCTracer::NotifyFullCppGCCompleted() {
  // Stop a full GC cycle only when both v8 and cppgc (if available) GCs have
  // finished sweeping. This method is invoked by cppgc.
  DCHECK(heap_->cpp_heap());
  const auto* metric_recorder =
      CppHeap::From(heap_->cpp_heap())->GetMetricRecorder();
  USE(metric_recorder);
  DCHECK(metric_recorder->FullGCMetricsReportPending());
  DCHECK(!notified_full_cppgc_completed_);
  notified_full_cppgc_completed_ = true;
  // Cppgc sweeping may finalize during MinorMS sweeping. In that case, delay
  // stopping the cycle until the nested MinorMS cycle is stopped.
  if (Event::IsYoungGenerationEvent(current_.type)) {
    DCHECK(young_gc_while_full_gc_);
    full_cppgc_completed_during_minor_gc_ = true;
    return;
  }
  StopFullCycleIfNeeded();
}

void GCTracer::NotifyYoungCppGCCompleted() {
  // Stop a young GC cycle only when both v8 and cppgc (if available) GCs have
  // finished sweeping. This method is invoked by cppgc.
  DCHECK(heap_->cpp_heap());
  DCHECK(notified_young_cppgc_running_);
  const auto* metric_recorder =
      CppHeap::From(heap_->cpp_heap())->GetMetricRecorder();
  USE(metric_recorder);
  DCHECK(metric_recorder->YoungGCMetricsReportPending());
  DCHECK(!notified_young_cppgc_completed_);
  notified_young_cppgc_completed_ = true;
  StopYoungCycleIfNeeded();
}

void GCTracer::NotifyYoungCppGCRunning() {
  DCHECK(!notified_young_cppgc_running_);
  notified_young_cppgc_running_ = true;
}

void GCTracer::SampleAllocation(base::TimeTicks current,
                                size_t new_space_counter_bytes,
                                size_t old_generation_counter_bytes,
                                size_t embedder_counter_bytes) {
  int64_t new_space_allocated_bytes = std::max<int64_t>(
      new_space_counter_bytes - new_space_allocation_counter_bytes_, 0);
  int64_t old_generation_allocated_bytes = std::max<int64_t>(
      old_generation_counter_bytes - old_generation_allocation_counter_bytes_,
      0);
  int64_t embedder_allocated_bytes = std::max<int64_t>(
      embedder_counter_bytes - embedder_allocation_counter_bytes_, 0);
  const base::TimeDelta allocation_duration = current - allocation_time_;
  allocation_time_ = current;

  new_space_allocation_counter_bytes_ = new_space_counter_bytes;
  old_generation_allocation_counter_bytes_ = old_generation_counter_bytes;
  embedder_allocation_counter_bytes_ = embedder_counter_bytes;

  new_generation_allocations_.Update(
      BytesAndDuration(new_space_allocated_bytes, allocation_duration));
  old_generation_allocations_.Update(
      BytesAndDuration(old_generation_allocated_bytes, allocation_duration));
  embedder_generation_allocations_.Update(
      BytesAndDuration(embedder_allocated_bytes, allocation_duration));

  if (v8_flags.memory_balancer) {
    heap_->mb_->UpdateAllocationRate(old_generation_allocated_bytes,
                                     allocation_duration);
  }
}

void GCTracer::SampleConcurrencyEsimate(size_t concurrency) {
  // For now, we only expect a single sample.
  DCHECK_EQ(current_.concurrency_estimate, 1);
  DCHECK_GT(concurrency, 0);
  current_.concurrency_estimate = concurrency;
}

void GCTracer::NotifyMarkingStart() {
  const auto marking_start = base::TimeTicks::Now();

  // Handle code flushing time deltas. Times are incremented conservatively:
  // 1. The first delta is 0s.
  // 2. Any delta is rounded downwards to a full second.
  // 3. 0s-deltas are carried over to the next GC with their precise diff. This
  //    allows for frequent GCs (within a single second) to be attributed
  //    correctly later on.
  // 4. The first non-zero increment after a reset always just increments by 1s.
  using SFIAgeType = decltype(code_flushing_increase_s_);
  static_assert(SharedFunctionInfo::kAgeSize == sizeof(SFIAgeType));
  static constexpr auto kMaxDeltaForSFIAge =
      base::TimeDelta::FromSeconds(std::numeric_limits<SFIAgeType>::max());
  SFIAgeType code_flushing_increase_s = 0;
  if (last_marking_start_time_for_code_flushing_.has_value()) {
    const auto diff =
        marking_start - last_marking_start_time_for_code_flushing_.value();
    if (diff > kMaxDeltaForSFIAge) {
      code_flushing_increase_s = std::numeric_limits<SFIAgeType>::max();
    } else {
      code_flushing_increase_s = static_cast<SFIAgeType>(diff.InSeconds());
    }
  }
  DCHECK_LE(code_flushing_increase_s, std::numeric_limits<SFIAgeType>::max());
  code_flushing_increase_s_ = code_flushing_increase_s;
  if (!last_marking_start_time_for_code_flushing_.has_value() ||
      code_flushing_increase_s > 0) {
    last_marking_start_time_for_code_flushing_ = marking_start;
  }
  if (V8_UNLIKELY(v8_flags.trace_flush_code)) {
    PrintIsolate(heap_->isolate(), "code flushing: increasing time: %u s\n",
                 code_flushing_increase_s_);
  }
}

uint16_t GCTracer::CodeFlushingIncrease() const {
  return code_flushing_increase_s_;
}

void GCTracer::AddCompactionEvent(double duration,
                                  size_t live_bytes_compacted) {
  recorded_compactions_.Push(BytesAndDuration(
      live_bytes_compacted, base::TimeDelta::FromMillisecondsD(duration)));
}

void GCTracer::AddSurvivalRatio(double promotion_ratio) {
  recorded_survival_ratios_.Push(promotion_ratio);
}

void GCTracer::AddIncrementalMarkingStep(double duration, size_t bytes) {
  if (bytes > 0) {
    current_.incremental_marking_bytes += bytes;
    current_.incremental_marking_duration +=
        base::TimeDelta::FromMillisecondsD(duration);
  }
  ReportIncrementalMarkingStepToRecorder(duration);
}

void GCTracer::AddIncrementalSweepingStep(double duration) {
  ReportIncrementalSweepingStepToRecorder(duration);
}

void GCTracer::Output(const char* format, ...) const {
  if (v8_flags.trace_gc) {
    va_list arguments;
    va_start(arguments, format);
    base::OS::VPrint(format, arguments);
    va_end(arguments);
  }

  const int kBufferSize = 256;
  char raw_buffer[kBufferSize];
  base::Vector<char> buffer(raw_buffer, kBufferSize);
  va_list arguments2;
  va_start(arguments2, format);
  base::VSNPrintF(buffer, format, arguments2);
  va_end(arguments2);

  heap_->AddToRingBuffer(buffer.begin());
}

void GCTracer::Print() const {
  const base::TimeDelta duration = current_.end_time - current_.start_time;
  const size_t kIncrementalStatsSize = 128;
  char incremental_buffer[kIncrementalStatsSize] = {0};

  if (current_.type == Event::Type::INCREMENTAL_MARK_COMPACTOR) {
    base::OS::SNPrintF(
        incremental_buffer, kIncrementalStatsSize,
        " (+ %.1f ms in %d steps since start of marking, "
        "biggest step %.1f ms, walltime since start of marking %.f ms)",
        current_scope(Scope::MC_INCREMENTAL),
        incremental_scope(Scope::MC_INCREMENTAL).steps,
        incremental_scope(Scope::MC_INCREMENTAL).longest_step.InMillisecondsF(),
        (current_.end_time - current_.incremental_marking_start_time)
            .InMillisecondsF());
  }

  const double total_external_time =
      current_scope(Scope::HEAP_EXTERNAL_WEAK_GLOBAL_HANDLES) +
      current_scope(Scope::HEAP_EXTERNAL_EPILOGUE) +
      current_scope(Scope::HEAP_EXTERNAL_PROLOGUE) +
      current_scope(Scope::MC_INCREMENTAL_EXTERNAL_EPILOGUE) +
      current_scope(Scope::MC_INCREMENTAL_EXTERNAL_PROLOGUE);

  // Avoid PrintF as Output also appends the string to the tracing ring buffer
  // that gets printed on OOM failures.
  DCHECK_IMPLIES(young_gc_while_full_gc_,
                 Event::IsYoungGenerationEvent(current_.type));
  Output(
      "[%d:%p] "
      "%8.0f ms: "
      "%s%s%s %.1f (%.1f) -> %.1f (%.1f) MB, "
      "pooled: %1.f MB, "
      "%.2f / %.2f ms %s (average mu = %.3f, current mu = %.3f) %s; %s\n",
      base::OS::GetCurrentProcessId(),
      reinterpret_cast<void*>(heap_->isolate()),
      heap_->isolate()->time_millis_since_init(),
      ToString(current_.type, false), current_.reduce_memory ? " (reduce)" : "",
      young_gc_while_full_gc_ ? " (interleaved)" : "",
      static_cast<double>(current_.start_object_size) / MB,
      static_cast<double>(current_.start_memory_size) / MB,
      static_cast<double>(current_.end_object_size) / MB,
      static_cast<double>(current_.end_memory_size) / MB,
      static_cast<double>(
          heap_->memory_allocator()->pool()->CommittedBufferedMemory()) /
          MB,
      duration.InMillisecondsF(), total_external_time, incremental_buffer,
      AverageMarkCompactMutatorUtilization(),
      CurrentMarkCompactMutatorUtilization(), ToString(current_.gc_reason),
      current_.collector_reason != nullptr ? current_.collector_reason : "");
}

void GCTracer::PrintNVP() const {
  const base::TimeDelta duration = current_.end_time - current_.start_time;
  const base::TimeDelta spent_in_mutator =
      current_.start_time - previous_.end_time;
  size_t allocated_since_last_gc =
      current_.start_object_size - previous_.end_object_size;

  base::TimeDelta incremental_walltime_duration;
  if (current_.type == Event::Type::INCREMENTAL_MARK_COMPACTOR) {
    incremental_walltime_duration =
        current_.end_time - current_.incremental_marking_start_time;
  }

  // Avoid data races when printing the background scopes.
  base::MutexGuard guard(&background_scopes_mutex_);

  switch (current_.type) {
    case Event::Type::SCAVENGER:
      heap_->isolate()->PrintWithTimestamp(
          "pause=%.1f "
          "mutator=%.1f "
          "gc=%s "
          "reduce_memory=%d "
          "interleaved=%d "
          "time_to_safepoint=%.2f "
          "heap.prologue=%.2f "
          "heap.epilogue=%.2f "
          "heap.external.prologue=%.2f "
          "heap.external.epilogue=%.2f "
          "heap.external_weak_global_handles=%.2f "
          "complete.sweep_array_buffers=%.2f "
          "scavenge=%.2f "
          "scavenge.free_remembered_set=%.2f "
          "scavenge.roots=%.2f "
          "scavenge.weak=%.2f "
          "scavenge.weak_global_handles.identify=%
```