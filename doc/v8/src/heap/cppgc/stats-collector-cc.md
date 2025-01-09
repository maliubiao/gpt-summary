Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Scan and High-Level Understanding:**

* **Keywords:**  Immediately, terms like `StatsCollector`, `AllocationObserver`, `NotifyAllocation`, `NotifyFree`, `GarbageCollectionState`, `MetricRecorder`, `marking`, `sweeping` stand out. This strongly suggests the code is related to garbage collection and performance monitoring within a C++ garbage collection system (cppgc, which is mentioned in the namespace).
* **File Name:** `stats-collector.cc` confirms its role in gathering and potentially reporting statistics.
* **Includes:** The included headers (`algorithm`, `atomic`, `cmath`, `logging`, `time`, `metric-recorder.h`) provide clues about the operations performed: managing collections, atomic operations for thread safety, math calculations, logging, time measurement, and interaction with a metric recording system.

**2. Deeper Dive into Key Components:**

* **`StatsCollector` Class:**  This is the central class. Focus on its public methods: `RegisterObserver`, `UnregisterObserver`, `NotifyAllocation`, `NotifyExplicitFree`, `NotifySafePoint...`, `Notify...Started/Completed`, and the various `get` methods. This reveals its role in tracking allocations, frees, GC phases, and providing access to collected data.
* **`AllocationObserver`:**  The observer pattern is evident. This suggests that other parts of the system can register to be notified of allocation events.
* **`MetricRecorder`:**  The inclusion of `metric-recorder.h` and the usage of `MetricRecorder::GCCycle` indicate the code reports GC statistics to an external system for analysis.
* **`GarbageCollectionState` Enum:** This is a classic pattern for tracking the progress of a garbage collection cycle.
* **`Event` Struct:**  This structure likely holds information about a single GC cycle. The `epoch` member suggests a way to track and differentiate cycles.

**3. Functional Breakdown - Method by Method:**

Go through the public methods and understand their purpose:

* **Constructor:** Initializes with a `Platform` pointer (likely an abstraction for platform-specific features).
* **Observer Management:** `RegisterObserver`, `UnregisterObserver` implement the observer pattern.
* **Allocation/Free Tracking:** `NotifyAllocation`, `NotifyExplicitFree` update counters. The `#ifdef CPPGC_VERIFY_HEAP` blocks hint at debugging/verification features.
* **Safepoints:** `NotifySafePointForConservativeCollection`, `NotifySafePointForTesting`, `AllocatedObjectSizeSafepointImpl` seem related to triggering actions at specific points during execution. The "conservative collection" comment is a key piece of information.
* **GC Phase Notifications:** `NotifyUnmarkingStarted`, `NotifyMarkingStarted`, `NotifyMarkingCompleted`, `NotifySweepingCompleted` track the stages of garbage collection.
* **Getters:**  Methods like `allocated_memory_size`, `allocated_object_size`, `marked_bytes`, `marking_time` provide read access to the collected statistics.
* **Memory Updates:** `NotifyAllocatedMemory`, `NotifyFreedMemory` track raw memory allocation/deallocation.
* **Discarded Memory:** `IncrementDiscardedMemory`, `DecrementDiscardedMemory`, `ResetDiscardedMemory`, `discarded_memory_size`, `resident_memory_size` likely relate to accounting for memory that is no longer in use but hasn't been fully released to the OS.
* **Histogram Recording:** `RecordHistogramSample` suggests recording timing information for different GC phases into histograms.

**4. Inferring Functionality and Connections:**

* **Core Function:**  The primary function is to monitor and record statistics related to memory allocation and garbage collection within cppgc.
* **Integration with GC:** The numerous `Notify...` methods show a tight coupling with the garbage collection process. The `StatsCollector` is informed about the beginning and end of various GC phases.
* **Metric Reporting:** The interaction with `MetricRecorder` means the collected statistics are likely used for performance analysis, debugging, and potentially informing GC decisions.
* **Observer Pattern Usage:** The observer pattern allows decoupling between the `StatsCollector` and other components that need to react to allocation events.

**5. Addressing Specific Questions:**

* **`.tq` Extension:**  Based on general knowledge of V8 and the absence of Torque-specific syntax, it's safe to say `.cc` means C++, not Torque.
* **JavaScript Relationship:**  Since V8 is the JavaScript engine, cppgc is the C++ garbage collector underlying it. The statistics gathered here are directly relevant to how JavaScript memory management performs. The example of memory leaks and performance issues in JavaScript ties directly to the kind of data being collected.
* **Code Logic Inference (Input/Output):** Focus on key methods like `NotifyAllocation` and how they update internal state. Simple scenarios like allocating a certain number of bytes and then freeing some illustrate the counter updates.
* **Common Programming Errors:** Memory leaks are the most obvious connection, as GC statistics help diagnose them. Excessive allocations and inefficient object management are also relevant.

**6. Structuring the Explanation:**

Organize the information logically:

* Start with a high-level summary of the file's purpose.
* Break down the functionality into key areas (tracking, GC integration, metric reporting, etc.).
* Explain the roles of important classes and methods.
* Address the specific questions from the prompt directly.
* Provide concrete examples in JavaScript and C++ to illustrate the concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is just about basic allocation counting.
* **Correction:** The presence of GC phase notifications and `MetricRecorder` clearly indicates a more sophisticated role in tracking garbage collection performance.
* **Initial thought:** The observers are just for debugging.
* **Correction:** The comments about safepoints and potential GC triggering suggest the observers can influence the GC process itself.
* **Initially missed:** The discarded memory section is important and needs to be explained in the context of resident memory.

By following this kind of systematic analysis, combined with knowledge of V8 architecture and garbage collection concepts, it's possible to generate a comprehensive and accurate explanation of the `stats-collector.cc` code.
这个C++源代码文件 `v8/src/heap/cppgc/stats-collector.cc` 的主要功能是收集和管理有关 **cppgc (C++ Garbage Collector)** 的统计信息。 这些统计信息对于理解和优化垃圾回收器的行为至关重要。

以下是它的主要功能点的详细说明：

**1. 跟踪内存分配和释放:**

* **`NotifyAllocation(size_t bytes)`:**  当 cppgc 管理的对象被分配时，这个函数会被调用，记录分配的字节数。它会更新 `allocated_bytes_since_safepoint_` 和 `tracked_live_bytes_` (在 `CPPGC_VERIFY_HEAP` 宏定义下)。
* **`NotifyExplicitFree(size_t bytes)`:**  当 cppgc 管理的对象被显式释放时（例如，通过 `delete`），这个函数会被调用，记录释放的字节数。它会更新 `explicitly_freed_bytes_since_safepoint_` 和 `tracked_live_bytes_` (在 `CPPGC_VERIFY_HEAP` 宏定义下)。
* **`NotifyAllocatedMemory(int64_t size)`:** 记录底层分配器分配的内存大小变化。
* **`NotifyFreedMemory(int64_t size)`:** 记录底层分配器释放的内存大小变化。

**2. 观察者模式 (Observer Pattern):**

* **`RegisterObserver(AllocationObserver* observer)`:**  允许其他组件注册为分配事件的观察者。当有分配或释放事件发生时，`StatsCollector` 会通知这些观察者。
* **`UnregisterObserver(AllocationObserver* observer)`:**  允许观察者取消注册。
* **`AllocationObserver` 接口:**  定义了观察者需要实现的接口，例如 `AllocatedObjectSizeIncreased`, `AllocatedObjectSizeDecreased`, `ResetAllocatedObjectSize`, `AllocatedSizeIncreased`, `AllocatedSizeDecreased` 等。

**3. 跟踪垃圾回收周期 (Garbage Collection Cycle):**

* **`NotifyUnmarkingStarted(CollectionType collection_type)`:**  在垃圾回收的 unmarking 阶段开始时被调用。
* **`NotifyMarkingStarted(CollectionType collection_type, MarkingType marking_type, IsForcedGC is_forced_gc)`:** 在垃圾回收的 marking 阶段开始时被调用，记录回收类型、标记类型以及是否是强制 GC。
* **`NotifyMarkingCompleted(size_t marked_bytes)`:** 在 marking 阶段完成时被调用，记录标记的字节数。它还会计算一些在 sweep 阶段开始前需要用到的统计信息。
* **`NotifySweepingCompleted(SweepingType sweeping_type)`:** 在 sweeping 阶段完成时被调用，记录 sweeping 类型。它会将当前周期的统计信息移动到 `previous_`，并创建一个新的 `current_` 事件，同时如果 `metric_recorder_` 存在，则会记录详细的 GC 事件信息。
* **`GarbageCollectionState` 枚举:**  用于跟踪当前的垃圾回收状态 (NotRunning, Unmarking, Marking, Sweeping)。
* **`Event` 结构体:**  存储单个垃圾回收周期的统计信息，例如回收类型、标记类型、标记的字节数、时间戳等。

**4. 记录安全点 (Safepoint) 信息:**

* **`NotifySafePointForConservativeCollection()`:** 在可能需要进行保守式垃圾回收的安全点被调用。它会检查自上次安全点以来分配和释放的字节数是否超过阈值 (`kAllocationThresholdBytes`)，如果是，则调用 `AllocatedObjectSizeSafepointImpl()`。
* **`NotifySafePointForTesting()`:**  用于测试目的的安全点通知。
* **`AllocatedObjectSizeSafepointImpl()`:**  实际执行安全点操作，通知观察者对象大小的变化。

**5. 提供统计信息查询接口:**

* **`allocated_memory_size()`:** 返回已分配的总内存大小。
* **`allocated_object_size()`:** 返回已分配的活动对象的大小。
* **`marked_bytes()`:** 返回上次垃圾回收周期中标记的字节数。
* **`marked_bytes_on_current_cycle()`:** 返回当前垃圾回收周期中标记的字节数。
* **`marking_time()`:** 返回上次垃圾回收周期的标记时间。
* **`GetRecentAllocationSpeedInBytesPerMs()`:**  计算最近的分配速度。
* **`discarded_memory_size()`:** 返回已丢弃的内存大小。
* **`resident_memory_size()`:** 返回常驻内存大小。

**6. 与 MetricRecorder 集成:**

* **`metric_recorder_` 成员:**  一个指向 `MetricRecorder` 的指针，用于将垃圾回收的详细事件信息记录下来。
* **`GetCycleEventForMetricRecorder()` 函数:**  将 `StatsCollector` 中收集的统计信息转换为 `MetricRecorder::GCCycle` 事件格式。
* **`RecordHistogramSample()` 函数:**  用于记录特定作用域（例如增量标记、增量清理）的时间信息到直方图中。

**如果 `v8/src/heap/cppgc/stats-collector.cc` 以 `.tq` 结尾:**

那么它将是一个 **V8 Torque** 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。如果它是 Torque 文件，那么它的内容将是使用 Torque 语法编写的，用于定义或实现 `StatsCollector` 的某些部分功能，或者与统计信息收集相关的其他运行时函数。

**与 JavaScript 的功能关系:**

`v8/src/heap/cppgc/stats-collector.cc` 代码直接影响 JavaScript 的内存管理和性能。  JavaScript 引擎 V8 使用 cppgc 作为其 C++ 堆的垃圾回收器。

* **内存泄漏检测和性能分析:**  `StatsCollector` 收集的统计信息可以用于分析 JavaScript 应用程序的内存使用情况，例如检测内存泄漏，理解对象分配模式，以及评估垃圾回收器的效率。
* **垃圾回收策略优化:**  V8 引擎可以利用这些统计信息来动态调整其垃圾回收策略，例如决定何时触发垃圾回收，选择哪种垃圾回收算法，以及调整堆的大小。
* **开发者工具:**  诸如 Chrome 开发者工具的 "内存" 面板所展示的内存使用图表和统计信息，很大程度上依赖于像 `StatsCollector` 这样的组件提供的数据。

**JavaScript 示例说明:**

```javascript
// 假设我们有一些 JavaScript 代码导致大量的对象分配和最终被垃圾回收

let largeArray = [];
function createManyObjects() {
  for (let i = 0; i < 10000; i++) {
    largeArray.push({ data: new Array(1000).fill(i) });
  }
}

createManyObjects(); // 执行后，大量的对象被分配到堆上

largeArray = null; // 解除对 largeArray 的引用，这些对象将成为垃圾

// 在 V8 的 cppgc 运行时，StatsCollector 会记录：
// - `NotifyAllocation` 被调用多次，记录分配的字节数
// - 当垃圾回收发生时，会调用 `NotifyMarkingStarted`, `NotifyMarkingCompleted`, `NotifySweepingCompleted`
// - `marked_bytes` 会记录被标记为存活的字节数
// - `allocated_memory_size`, `allocated_object_size` 等统计信息会更新

// 通过 Chrome 开发者工具的 "内存" 面板，我们可以观察到：
// - 堆大小的变化
// - 对象数量的变化
// - 垃圾回收的次数和耗时 (这些信息可能部分来源于 MetricRecorder)
```

**代码逻辑推理 (假设输入与输出):**

假设有以下操作序列：

1. **分配 1000 字节:** 调用 `NotifyAllocation(1000)`
   * **假设输入:** `bytes = 1000`
   * **预期输出:** `allocated_bytes_since_safepoint_` 增加 1000，`tracked_live_bytes_` (如果定义了 `CPPGC_VERIFY_HEAP`) 增加 1000。

2. **显式释放 500 字节:** 调用 `NotifyExplicitFree(500)`
   * **假设输入:** `bytes = 500`
   * **预期输出:** `explicitly_freed_bytes_since_safepoint_` 增加 500，`tracked_live_bytes_` (如果定义了 `CPPGC_VERIFY_HEAP`) 减少 500。

3. **触发安全点:** 调用 `NotifySafePointForConservativeCollection()`，假设 `kAllocationThresholdBytes` 为 200。
   * **当前状态:** `allocated_bytes_since_safepoint_ = 1000`, `explicitly_freed_bytes_since_safepoint_ = 500`
   * **计算:** `abs(1000 - 500) = 500`, 大于 `kAllocationThresholdBytes` (200)。
   * **预期输出:** 会调用 `AllocatedObjectSizeSafepointImpl()`，进而通知注册的 `AllocationObserver` 对象大小增加了 500 字节。如果之后没有触发 GC，`allocated_bytes_since_safepoint_` 和 `explicitly_freed_bytes_since_safepoint_` 将被重置为 0。

**用户常见的编程错误 (与 `StatsCollector` 相关的):**

`StatsCollector` 本身不直接阻止用户编程错误，但它收集的统计信息可以帮助识别这些错误。

* **内存泄漏:** 如果 JavaScript 代码持续创建对象但没有释放引用，导致这些对象无法被垃圾回收，`StatsCollector` 会记录到 `allocated_object_size` 持续增长，即使在多次垃圾回收后也没有明显下降。这表明可能存在内存泄漏。
    ```javascript
    // 示例：潜在的内存泄漏
    let leakedObjects = [];
    function createLeakedObject() {
      let obj = { data: new Array(1000).fill(1) };
      leakedObjects.push(obj); // 对象被添加到全局数组，无法被回收
    }

    setInterval(createLeakedObject, 100); // 每 100 毫秒创建一个泄漏的对象
    ```
* **过度的对象分配:**  如果代码在短时间内创建了大量的临时对象，`StatsCollector` 会记录到高的分配速率。这可能导致频繁的垃圾回收，影响性能。
    ```javascript
    // 示例：过度的对象分配
    function processData(data) {
      for (let i = 0; i < data.length; i++) {
        let temp = { value: data[i] * 2 }; // 每次循环都创建新对象
        // ... 对 temp 进行一些操作，但没有长期使用
      }
    }

    let largeData = new Array(1000000).fill(1);
    processData(largeData);
    ```
* **意外的全局变量:**  在 JavaScript 中意外创建的全局变量会阻止垃圾回收器回收它们，导致内存使用增加。`StatsCollector` 可能会显示 `allocated_object_size` 意外增长。
    ```javascript
    function accidentalGlobal() {
      globalVar = "oops"; // 忘记使用 var/let/const，创建了全局变量
    }
    accidentalGlobal();
    ```

总而言之，`v8/src/heap/cppgc/stats-collector.cc` 是 V8 引擎中一个关键的组件，负责收集 cppgc 垃圾回收器的运行状态信息，这些信息对于理解和优化内存管理至关重要，并间接地影响着 JavaScript 程序的性能。

Prompt: 
```
这是目录为v8/src/heap/cppgc/stats-collector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/stats-collector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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