Response: Let's break down the thought process for analyzing the `stats-collector.cc` code and generating the summary and JavaScript example.

**1. Understanding the Core Task:**

The primary goal is to understand the functionality of `stats-collector.cc` within the context of V8's CppGC and its potential relationship with JavaScript.

**2. Initial Code Scan and Keyword Spotting:**

I'd start by quickly scanning the code for important keywords and patterns. This includes:

* **Class Name:** `StatsCollector` - This is the central entity.
* **Methods:**  `RegisterObserver`, `UnregisterObserver`, `NotifyAllocation`, `NotifyExplicitFree`, `NotifySafePointForConservativeCollection`, `NotifyMarkingStarted`, `NotifyMarkingCompleted`, `NotifySweepingCompleted`, etc. These suggest actions and state changes related to memory management.
* **Member Variables:** `allocated_bytes_since_safepoint_`, `explicitly_freed_bytes_since_safepoint_`, `gc_state_`, `marked_bytes_so_far_`, `memory_allocated_bytes_`, `metric_recorder_`, etc. These hold the state of the collector.
* **Namespaces:** `cppgc::internal` and `cppgc` - This confirms it's part of CppGC.
* **Includes:** `<algorithm>`, `<atomic>`, `<cmath>`, `"src/base/atomicops.h"`, `"src/base/logging.h"`, `"src/base/platform/time.h"`, `"src/heap/cppgc/metric-recorder.h"` - These indicate the use of standard library features, atomics for thread safety, math functions, base utilities, time measurement, and interaction with a `MetricRecorder`.
* **DCHECK/DCHECK_EQ/DCHECK_NE/DCHECK_IMPLIES:**  These are debug assertions, indicating invariants that should hold. They provide clues about the logic flow.
* **`AllocationObserver`:**  This suggests a pattern where other components are notified about allocation events.
* **`MetricRecorder`:**  This strongly indicates that the class is responsible for collecting and reporting metrics related to garbage collection.
* **"safepoint"**:  This term is commonly associated with garbage collection pauses.
* **"marking", "sweeping"**: These are standard phases in garbage collection.
* **"concurrent", "incremental", "atomic"**: These relate to different strategies for performing garbage collection.

**3. Inferring Functionality from Method Names and Logic:**

Based on the keywords and method names, I would start inferring the functionality:

* **Tracking Allocations and Deallocations:** `NotifyAllocation` and `NotifyExplicitFree` clearly track changes in allocated object sizes.
* **Garbage Collection Lifecycle:** Methods like `NotifyUnmarkingStarted`, `NotifyMarkingStarted`, `NotifyMarkingCompleted`, and `NotifySweepingCompleted` suggest the class manages the state transitions of a garbage collection cycle.
* **Observing Allocations:** `RegisterObserver` and `UnregisterObserver` suggest a mechanism for external components to receive notifications about allocations.
* **Safe Points:** `NotifySafePointForConservativeCollection` and `AllocatedObjectSizeSafepointImpl` indicate points in time where certain actions related to tracking and reporting allocation sizes occur, likely in coordination with garbage collection.
* **Metric Recording:** The presence of `metric_recorder_` and methods like `GetCycleEventForMetricRecorder` and `RecordHistogramSample` strongly suggest that the class is responsible for collecting and reporting GC metrics.
* **Memory Management Statistics:**  Variables like `memory_allocated_bytes_`, `memory_freed_bytes_since_end_of_marking_`, `discarded_bytes_`, and methods like `allocated_memory_size()` and `allocated_object_size()` point to tracking various memory-related statistics.

**4. Connecting to JavaScript:**

The prompt specifically asks about the relationship with JavaScript. Here's how I'd make the connection:

* **V8 Context:** Knowing this is within the V8 codebase is the crucial link. V8 is the JavaScript engine.
* **CppGC Purpose:** CppGC is a garbage collector for C++ objects *within* the V8 engine. These C++ objects are used to implement JavaScript features and the runtime environment.
* **Allocation Tracking for JavaScript:** When JavaScript code creates objects, arrays, or other data structures, V8 internally allocates memory for them using C++. `StatsCollector` is tracking these C++ allocations.
* **Garbage Collection Impact on JavaScript:** The garbage collection cycles tracked by `StatsCollector` directly impact JavaScript performance. When garbage collection occurs, JavaScript execution might be paused. Understanding and optimizing GC is vital for a smooth JavaScript experience.
* **Metrics for Performance Analysis:** The metrics collected by `StatsCollector` are essential for V8 developers to analyze and improve the performance of the JavaScript engine and the garbage collector.

**5. Constructing the JavaScript Example:**

To illustrate the connection, a simple example demonstrating JavaScript object creation and the potential impact of garbage collection is effective. The example should show:

* **Object Creation:**  Demonstrate allocating memory by creating JavaScript objects.
* **Potential for GC:**  Create enough objects that a garbage collection might be triggered (although explicitly triggering it in JavaScript is usually not possible).
* **Conceptual Link:** Explain how the C++ `StatsCollector` would be tracking the underlying memory used by these JavaScript objects.

**6. Structuring the Summary:**

The summary should be organized logically, covering the main aspects of the code:

* **Core Functionality:** Start with the main purpose.
* **Key Responsibilities:** Break down the core functionality into specific tasks.
* **Interaction with Other Components:** Explain how it interacts with observers and the metric recorder.
* **Relationship to Garbage Collection:** Emphasize its role in tracking GC cycles.
* **Relevance to JavaScript:** Explain the connection in clear terms.

**7. Refinement and Review:**

After drafting the summary and example, I would review them to ensure accuracy, clarity, and conciseness. I'd double-check that the JavaScript example accurately reflects JavaScript behavior and effectively illustrates the concept.

**Self-Correction Example during the Process:**

Initially, I might focus too heavily on the technical details of the C++ code. However, remembering the prompt's requirement to explain the connection to JavaScript would lead me to shift focus and emphasize the *why* – why is this C++ code important in the context of a JavaScript engine? This would lead to including more explanations about how JavaScript actions trigger C++ allocations and how GC impacts JavaScript execution. Also, I might initially provide a very technical description of the metric recorder, but then realize it's more helpful to explain its *purpose* – collecting data for performance analysis.
这个C++源代码文件 `stats-collector.cc` 属于 V8 引擎的 CppGC（C++ Garbage Collector）组件，其主要功能是**收集和管理垃圾回收相关的统计信息**。  更具体地说，它负责跟踪 CppGC 管理的堆内存的分配、释放以及垃圾回收周期的各种事件和指标。

以下是其主要功能的归纳：

1. **跟踪内存分配和释放:**
   - 记录自上次安全点（safepoint）以来的分配字节数 (`allocated_bytes_since_safepoint_`)。
   - 记录自上次安全点以来的显式释放字节数 (`explicitly_freed_bytes_since_safepoint_`)。
   - 维护跟踪的实时字节数 (`tracked_live_bytes_`，仅在 `CPPGC_VERIFY_HEAP` 宏定义下启用）。
   - 记录自标记结束以来的分配字节数 (`allocated_bytes_since_end_of_marking_`)。
   - 记录内存的分配和释放 (`memory_allocated_bytes_`, `memory_freed_bytes_since_end_of_marking_`)。

2. **管理和通知分配观察者 (Allocation Observers):**
   - 允许其他组件注册为分配观察者 (`RegisterObserver`)，以便在内存分配或释放事件发生时得到通知。
   - 允许取消注册观察者 (`UnregisterObserver`)。
   - 在分配大小增加或减少时通知已注册的观察者 (`NotifyAllocation`, `NotifyExplicitFree`, `AllocatedObjectSizeIncreased`, `AllocatedObjectSizeDecreased`, `AllocatedSizeIncreased`, `AllocatedSizeDecreased`)。
   - 在标记完成后重置观察者的分配对象大小 (`ResetAllocatedObjectSize`)。

3. **跟踪垃圾回收周期事件:**
   - 记录垃圾回收的不同阶段（未标记、标记、清除）的状态 (`gc_state_`)。
   - 记录标记过程的开始和完成事件 (`NotifyMarkingStarted`, `NotifyMarkingCompleted`)，包括收集类型、标记类型和是否强制 GC。
   - 记录清除过程的完成事件 (`NotifySweepingCompleted`)。
   - 记录非标记过程的开始事件 (`NotifyUnmarkingStarted`)。

4. **收集垃圾回收性能指标:**
   - 记录标记的字节数 (`marked_bytes_`)。
   - 记录清除前的对象大小和内存大小 (`object_size_before_sweep_bytes`, `memory_size_before_sweep_bytes`)。
   - 计算最近的分配速度 (`GetRecentAllocationSpeedInBytesPerMs`)。
   - 与 `MetricRecorder` 协同工作，记录详细的垃圾回收周期事件和性能数据，例如各种阶段的耗时 (`GetCycleEventForMetricRecorder`)。

5. **管理安全点 (Safepoints):**
   - 当分配或释放的字节数超过阈值时，会触发安全点通知 (`NotifySafePointForConservativeCollection`)。
   - 在安全点，会通知观察者对象大小的变化 (`AllocatedObjectSizeSafepointImpl`)。

6. **跟踪丢弃的内存 (Discarded Memory):**
   - 提供原子操作来增加和减少丢弃的内存量 (`IncrementDiscardedMemory`, `DecrementDiscardedMemory`)。
   - 允许重置丢弃的内存计数器 (`ResetDiscardedMemory`)。
   - 提供获取丢弃内存大小和常驻内存大小的方法 (`discarded_memory_size`, `resident_memory_size`)。

**与 JavaScript 的关系：**

`stats-collector.cc` 是 V8 引擎内部的组件，它直接管理着用于存储 C++ 对象的堆内存。这些 C++ 对象在 V8 中扮演着至关重要的角色，包括：

* **JavaScript 对象的底层表示:**  V8 内部使用 C++ 对象来表示 JavaScript 的对象、数组、函数等。
* **V8 引擎的内部数据结构:**  例如，用于存储作用域、闭包、原型链等的数据结构也是 C++ 对象。

因此，`stats-collector.cc` 收集的统计信息**间接地反映了 JavaScript 代码的内存使用情况和垃圾回收性能**。

**JavaScript 示例：**

虽然我们不能直接从 JavaScript 代码中访问或操作 `stats-collector.cc` 的功能，但 JavaScript 代码的行为会影响其收集的统计信息。例如：

```javascript
// 创建大量 JavaScript 对象
let objects = [];
for (let i = 0; i < 1000000; i++) {
  objects.push({ value: i });
}

// 执行一些操作，可能导致更多内存分配
let sum = 0;
for (let obj of objects) {
  sum += obj.value;
}

// 移除部分对象，可能触发垃圾回收
objects = objects.slice(500000);

// 创建新的对象
let moreObjects = [];
for (let i = 0; i < 500000; i++) {
  moreObjects.push({ data: 'some data' });
}
```

在这个 JavaScript 示例中：

1. **创建大量对象**会导致 CppGC 堆中分配大量的 C++ 对象来表示这些 JavaScript 对象，这会被 `StatsCollector::NotifyAllocation` 记录下来，并增加 `allocated_bytes_since_safepoint_` 等计数器。
2. **后续的操作**可能会导致更多的临时对象创建和释放。
3. **移除部分对象**后，这些不再被引用的 JavaScript 对象对应的 C++ 对象将成为垃圾，等待 CppGC 回收。垃圾回收周期会触发 `StatsCollector` 中相应的 `NotifyMarkingStarted`、`NotifyMarkingCompleted` 和 `NotifySweepingCompleted` 等方法，更新相关的统计信息，例如 `marked_bytes_`。
4. **创建新的对象** 又会触发新的内存分配。

V8 引擎会根据 `StatsCollector` 收集的统计信息以及其他因素来决定何时以及如何执行垃圾回收。`MetricRecorder` 会使用这些数据来生成关于垃圾回收效率和性能的报告，帮助 V8 团队优化垃圾回收策略。

**总结来说，`stats-collector.cc` 是 CppGC 的核心组成部分，负责监控和记录 C++ 堆的内存使用和垃圾回收行为，而这些行为直接受到 JavaScript 代码执行的影响。虽然 JavaScript 代码不能直接控制 `stats-collector.cc`，但 JavaScript 的内存分配模式和对象生命周期会直接反映在其收集的统计数据中。**

Prompt: 
```
这是目录为v8/src/heap/cppgc/stats-collector.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/stats-collector.h"

#include <algorithm>
#include <atomic>
#include <cmath>

#include "src/base/atomicops.h"
#include "src/base/logging.h"
#include "src/base/platform/time.h"
#include "src/heap/cppgc/metric-recorder.h"

namespace cppgc {
namespace internal {

// static
constexpr size_t StatsCollector::kAllocationThresholdBytes;

StatsCollector::StatsCollector(Platform* platform) : platform_(platform) {
  USE(platform_);
}

void StatsCollector::RegisterObserver(AllocationObserver* observer) {
  DCHECK_EQ(allocation_observers_.end(),
            std::find(allocation_observers_.begin(),
                      allocation_observers_.end(), observer));
  allocation_observers_.push_back(observer);
}

void StatsCollector::UnregisterObserver(AllocationObserver* observer) {
  auto it = std::find(allocation_observers_.begin(),
                      allocation_observers_.end(), observer);
  DCHECK_NE(allocation_observers_.end(), it);
  *it = nullptr;
  allocation_observer_deleted_ = true;
}

void StatsCollector::NotifyAllocation(size_t bytes) {
  // The current GC may not have been started. This is ok as recording considers
  // the whole time range between garbage collections.
  allocated_bytes_since_safepoint_ += bytes;
#ifdef CPPGC_VERIFY_HEAP
  DCHECK_GE(tracked_live_bytes_ + bytes, tracked_live_bytes_);
  tracked_live_bytes_ += bytes;
#endif  // CPPGC_VERIFY_HEAP
}

void StatsCollector::NotifyExplicitFree(size_t bytes) {
  // See IncreaseAllocatedObjectSize for lifetime of the counter.
  explicitly_freed_bytes_since_safepoint_ += bytes;
#ifdef CPPGC_VERIFY_HEAP
  DCHECK_GE(tracked_live_bytes_, bytes);
  tracked_live_bytes_ -= bytes;
#endif  // CPPGC_VERIFY_HEAP
}

void StatsCollector::NotifySafePointForConservativeCollection() {
  if (std::abs(allocated_bytes_since_safepoint_ -
               explicitly_freed_bytes_since_safepoint_) >=
      static_cast<int64_t>(kAllocationThresholdBytes)) {
    AllocatedObjectSizeSafepointImpl();
  }
}

void StatsCollector::NotifySafePointForTesting() {
  AllocatedObjectSizeSafepointImpl();
}

void StatsCollector::AllocatedObjectSizeSafepointImpl() {
  allocated_bytes_since_end_of_marking_ +=
      static_cast<int64_t>(allocated_bytes_since_safepoint_) -
      static_cast<int64_t>(explicitly_freed_bytes_since_safepoint_);

  // Save the epoch to avoid clearing counters when a GC happened, see below.
  const auto saved_epoch = current_.epoch;

  // These observer methods may start or finalize GC. In case they trigger a
  // final GC pause, the delta counters are reset there and the following
  // observer calls are called with '0' updates.
  ForAllAllocationObservers([this](AllocationObserver* observer) {
    // Recompute delta here so that a GC finalization is able to clear the
    // delta for other observer calls.
    int64_t delta = allocated_bytes_since_safepoint_ -
                    explicitly_freed_bytes_since_safepoint_;
    if (delta < 0) {
      observer->AllocatedObjectSizeDecreased(static_cast<size_t>(-delta));
    } else {
      observer->AllocatedObjectSizeIncreased(static_cast<size_t>(delta));
    }
  });
  // Only clear the counters when no garbage collection happened. In case of a
  // garbage collection in the callbacks, the counters have been cleared by
  // `NotifyMarkingFinished()`. In addition, atomic sweeping may have already
  // allocated new memory which would be dropped from accounting in case
  // of clearing here.
  if (saved_epoch == current_.epoch) {
    allocated_bytes_since_safepoint_ = 0;
    explicitly_freed_bytes_since_safepoint_ = 0;
  }
}

StatsCollector::Event::Event() {
  static std::atomic<size_t> epoch_counter{0};
  epoch = epoch_counter.fetch_add(1);
}

void StatsCollector::NotifyUnmarkingStarted(CollectionType collection_type) {
  DCHECK_EQ(GarbageCollectionState::kNotRunning, gc_state_);
  DCHECK_EQ(CollectionType::kMajor, collection_type);
  gc_state_ = GarbageCollectionState::kUnmarking;
}

void StatsCollector::NotifyMarkingStarted(CollectionType collection_type,
                                          MarkingType marking_type,
                                          IsForcedGC is_forced_gc) {
  DCHECK_IMPLIES(gc_state_ != GarbageCollectionState::kNotRunning,
                 (gc_state_ == GarbageCollectionState::kUnmarking &&
                  collection_type == CollectionType::kMajor));
  current_.collection_type = collection_type;
  current_.is_forced_gc = is_forced_gc;
  current_.marking_type = marking_type;
  gc_state_ = GarbageCollectionState::kMarking;
}

void StatsCollector::NotifyMarkingCompleted(size_t marked_bytes) {
  DCHECK_EQ(GarbageCollectionState::kMarking, gc_state_);
  gc_state_ = GarbageCollectionState::kSweeping;
  current_.marked_bytes = marked_bytes;
  current_.object_size_before_sweep_bytes =
      marked_bytes_so_far_ + allocated_bytes_since_end_of_marking_ +
      allocated_bytes_since_safepoint_ -
      explicitly_freed_bytes_since_safepoint_;
  allocated_bytes_since_safepoint_ = 0;
  explicitly_freed_bytes_since_safepoint_ = 0;

  if (current_.collection_type == CollectionType::kMajor)
    marked_bytes_so_far_ = 0;
  marked_bytes_so_far_ += marked_bytes;

#ifdef CPPGC_VERIFY_HEAP
  tracked_live_bytes_ = marked_bytes_so_far_;
#endif  // CPPGC_VERIFY_HEAP

  DCHECK_LE(memory_freed_bytes_since_end_of_marking_, memory_allocated_bytes_);
  memory_allocated_bytes_ -= memory_freed_bytes_since_end_of_marking_;
  current_.memory_size_before_sweep_bytes = memory_allocated_bytes_;
  memory_freed_bytes_since_end_of_marking_ = 0;

  ForAllAllocationObservers([this](AllocationObserver* observer) {
    observer->ResetAllocatedObjectSize(marked_bytes_so_far_);
  });

  // HeapGrowing would use the below fields to estimate allocation rate during
  // execution of ResetAllocatedObjectSize.
  allocated_bytes_since_end_of_marking_ = 0;
  time_of_last_end_of_marking_ = v8::base::TimeTicks::Now();
}

double StatsCollector::GetRecentAllocationSpeedInBytesPerMs() const {
  v8::base::TimeTicks current_time = v8::base::TimeTicks::Now();
  DCHECK_LE(time_of_last_end_of_marking_, current_time);
  if (time_of_last_end_of_marking_ == current_time) return 0;
  return allocated_bytes_since_end_of_marking_ /
         (current_time - time_of_last_end_of_marking_).InMillisecondsF();
}

namespace {

int64_t SumPhases(const MetricRecorder::GCCycle::Phases& phases) {
  DCHECK_LE(0, phases.mark_duration_us);
  DCHECK_LE(0, phases.weak_duration_us);
  DCHECK_LE(0, phases.compact_duration_us);
  DCHECK_LE(0, phases.sweep_duration_us);
  return phases.mark_duration_us + phases.weak_duration_us +
         phases.compact_duration_us + phases.sweep_duration_us;
}

MetricRecorder::GCCycle GetCycleEventForMetricRecorder(
    CollectionType type, StatsCollector::MarkingType marking_type,
    StatsCollector::SweepingType sweeping_type, int64_t atomic_mark_us,
    int64_t atomic_weak_us, int64_t atomic_compact_us, int64_t atomic_sweep_us,
    int64_t incremental_mark_us, int64_t incremental_sweep_us,
    int64_t concurrent_mark_us, int64_t concurrent_sweep_us,
    int64_t objects_before_bytes, int64_t objects_after_bytes,
    int64_t objects_freed_bytes, int64_t memory_before_bytes,
    int64_t memory_after_bytes, int64_t memory_freed_bytes) {
  MetricRecorder::GCCycle event;
  event.type = (type == CollectionType::kMajor)
                   ? MetricRecorder::GCCycle::Type::kMajor
                   : MetricRecorder::GCCycle::Type::kMinor;
  // MainThread.Incremental:
  event.main_thread_incremental.mark_duration_us =
      marking_type != StatsCollector::MarkingType::kAtomic ? incremental_mark_us
                                                           : -1;
  event.main_thread_incremental.sweep_duration_us =
      sweeping_type != StatsCollector::SweepingType::kAtomic
          ? incremental_sweep_us
          : -1;
  // MainThread.Atomic:
  event.main_thread_atomic.mark_duration_us = atomic_mark_us;
  event.main_thread_atomic.weak_duration_us = atomic_weak_us;
  event.main_thread_atomic.compact_duration_us = atomic_compact_us;
  event.main_thread_atomic.sweep_duration_us = atomic_sweep_us;
  // MainThread:
  event.main_thread.mark_duration_us =
      event.main_thread_atomic.mark_duration_us + incremental_mark_us;
  event.main_thread.weak_duration_us =
      event.main_thread_atomic.weak_duration_us;
  event.main_thread.compact_duration_us =
      event.main_thread_atomic.compact_duration_us;
  event.main_thread.sweep_duration_us =
      event.main_thread_atomic.sweep_duration_us + incremental_sweep_us;
  // Total:
  event.total.mark_duration_us =
      event.main_thread.mark_duration_us + concurrent_mark_us;
  event.total.weak_duration_us = event.main_thread.weak_duration_us;
  event.total.compact_duration_us = event.main_thread.compact_duration_us;
  event.total.sweep_duration_us =
      event.main_thread.sweep_duration_us + concurrent_sweep_us;
  // Objects:
  event.objects.before_bytes = objects_before_bytes;
  event.objects.after_bytes = objects_after_bytes;
  event.objects.freed_bytes = objects_freed_bytes;
  // Memory:
  event.memory.before_bytes = memory_before_bytes;
  event.memory.after_bytes = memory_after_bytes;
  event.memory.freed_bytes = memory_freed_bytes;
  // Collection Rate:
  if (event.objects.before_bytes == 0) {
    event.collection_rate_in_percent = 0;
  } else {
    event.collection_rate_in_percent =
        static_cast<double>(event.objects.freed_bytes) /
        event.objects.before_bytes;
  }
  // Efficiency:
  if (event.objects.freed_bytes == 0) {
    event.efficiency_in_bytes_per_us = 0;
    event.main_thread_efficiency_in_bytes_per_us = 0;
  } else {
    // Here, SumPhases(event.main_thread) or even SumPhases(event.total) can be
    // zero if the clock resolution is not small enough and the entire GC was
    // very short, so the timed value was zero. This appears to happen on
    // Windows, see crbug.com/1338256 and crbug.com/1339180. In this case, we
    // are only here if the number of freed bytes is nonzero and the division
    // below produces an infinite value.
    event.efficiency_in_bytes_per_us =
        static_cast<double>(event.objects.freed_bytes) / SumPhases(event.total);
    event.main_thread_efficiency_in_bytes_per_us =
        static_cast<double>(event.objects.freed_bytes) /
        SumPhases(event.main_thread);
  }
  return event;
}

}  // namespace

void StatsCollector::NotifySweepingCompleted(SweepingType sweeping_type) {
  DCHECK_EQ(GarbageCollectionState::kSweeping, gc_state_);
  gc_state_ = GarbageCollectionState::kNotRunning;
  current_.sweeping_type = sweeping_type;
  previous_ = std::move(current_);
  current_ = Event();
  DCHECK_IMPLIES(previous_.marking_type == StatsCollector::MarkingType::kAtomic,
                 previous_.scope_data[kIncrementalMark].IsZero());
  DCHECK_IMPLIES(
      previous_.sweeping_type == StatsCollector::SweepingType::kAtomic,
      previous_.scope_data[kIncrementalSweep].IsZero());
  if (metric_recorder_) {
    MetricRecorder::GCCycle event = GetCycleEventForMetricRecorder(
        previous_.collection_type, previous_.marking_type,
        previous_.sweeping_type,
        previous_.scope_data[kAtomicMark].InMicroseconds(),
        previous_.scope_data[kAtomicWeak].InMicroseconds(),
        previous_.scope_data[kAtomicCompact].InMicroseconds(),
        previous_.scope_data[kAtomicSweep].InMicroseconds(),
        previous_.scope_data[kIncrementalMark].InMicroseconds(),
        previous_.scope_data[kIncrementalSweep].InMicroseconds(),
        previous_.concurrent_scope_data[kConcurrentMark],
        previous_.concurrent_scope_data[kConcurrentSweep],
        previous_.object_size_before_sweep_bytes /* objects_before */,
        marked_bytes_so_far_ /* objects_after */,
        previous_.object_size_before_sweep_bytes -
            marked_bytes_so_far_ /* objects_freed */,
        previous_.memory_size_before_sweep_bytes /* memory_before */,
        previous_.memory_size_before_sweep_bytes -
            memory_freed_bytes_since_end_of_marking_ /* memory_after */,
        memory_freed_bytes_since_end_of_marking_ /* memory_freed */);
    metric_recorder_->AddMainThreadEvent(event);
  }
}

size_t StatsCollector::allocated_memory_size() const {
  return memory_allocated_bytes_ - memory_freed_bytes_since_end_of_marking_;
}

size_t StatsCollector::allocated_object_size() const {
  return marked_bytes_so_far_ + allocated_bytes_since_end_of_marking_;
}

size_t StatsCollector::marked_bytes() const {
  DCHECK_NE(GarbageCollectionState::kMarking, gc_state_);
  return marked_bytes_so_far_;
}

size_t StatsCollector::marked_bytes_on_current_cycle() const {
  DCHECK_NE(GarbageCollectionState::kNotRunning, gc_state_);
  return current_.marked_bytes;
}

v8::base::TimeDelta StatsCollector::marking_time() const {
  DCHECK_NE(GarbageCollectionState::kMarking, gc_state_);
  // During sweeping we refer to the current Event as that already holds the
  // correct marking information. In all other phases, the previous event holds
  // the most up-to-date marking information.
  const Event& event =
      gc_state_ == GarbageCollectionState::kSweeping ? current_ : previous_;
  return event.scope_data[kAtomicMark] + event.scope_data[kIncrementalMark] +
         v8::base::TimeDelta::FromMicroseconds(v8::base::Relaxed_Load(
             &event.concurrent_scope_data[kConcurrentMark]));
}

void StatsCollector::NotifyAllocatedMemory(int64_t size) {
  memory_allocated_bytes_ += size;
#ifdef DEBUG
  const auto saved_epoch = current_.epoch;
#endif  // DEBUG
  ForAllAllocationObservers([size](AllocationObserver* observer) {
    observer->AllocatedSizeIncreased(static_cast<size_t>(size));
  });
#ifdef DEBUG
  // AllocatedSizeIncreased() must not trigger GC.
  DCHECK_EQ(saved_epoch, current_.epoch);
#endif  // DEBUG
}

void StatsCollector::NotifyFreedMemory(int64_t size) {
  memory_freed_bytes_since_end_of_marking_ += size;
#ifdef DEBUG
  const auto saved_epoch = current_.epoch;
#endif  // DEBUG
  ForAllAllocationObservers([size](AllocationObserver* observer) {
    observer->AllocatedSizeDecreased(static_cast<size_t>(size));
  });
#ifdef DEBUG
  // AllocatedSizeDecreased() must not trigger GC.
  DCHECK_EQ(saved_epoch, current_.epoch);
#endif  // DEBUG
}

void StatsCollector::IncrementDiscardedMemory(size_t value) {
  const size_t old =
      discarded_bytes_.fetch_add(value, std::memory_order_relaxed);
  DCHECK_GE(old + value, old);
  USE(old);
}

void StatsCollector::DecrementDiscardedMemory(size_t value) {
  const size_t old =
      discarded_bytes_.fetch_sub(value, std::memory_order_relaxed);
  DCHECK_GE(old, old - value);
  USE(old);
}

void StatsCollector::ResetDiscardedMemory() {
  discarded_bytes_.store(0, std::memory_order_relaxed);
}

size_t StatsCollector::discarded_memory_size() const {
  return discarded_bytes_.load(std::memory_order_relaxed);
}

size_t StatsCollector::resident_memory_size() const {
  const auto allocated = allocated_memory_size();
  const auto discarded = discarded_memory_size();
  DCHECK_IMPLIES(allocated == 0, discarded == 0);
  DCHECK_IMPLIES(allocated > 0, allocated > discarded);
  return allocated - discarded;
}

void StatsCollector::RecordHistogramSample(ScopeId scope_id_,
                                           v8::base::TimeDelta time) {
  switch (scope_id_) {
    case kIncrementalMark: {
      MetricRecorder::MainThreadIncrementalMark event{time.InMicroseconds()};
      metric_recorder_->AddMainThreadEvent(event);
      break;
    }
    case kIncrementalSweep: {
      MetricRecorder::MainThreadIncrementalSweep event{time.InMicroseconds()};
      metric_recorder_->AddMainThreadEvent(event);
      break;
    }
    default:
      break;
  }
}

}  // namespace internal
}  // namespace cppgc

"""

```