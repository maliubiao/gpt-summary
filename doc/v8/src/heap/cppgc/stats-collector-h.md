Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan - Keywords and Structure:**  The first step is a quick read-through, looking for familiar keywords and structural elements. I see `#ifndef`, `#define`, `namespace`, `class`, `enum`, `struct`, `static_assert`, comments starting with `//`, and macros like `#define`. This confirms it's a C++ header file. The inclusion guards (`#ifndef V8_HEAP_CPPGC_STATS_COLLECTOR_H_`) are standard.

2. **Identify the Core Purpose:** The name `stats-collector.h` strongly suggests its function: collecting statistics. The namespace `cppgc` and the path `v8/src/heap/cppgc` indicate it's part of the C++ garbage collector within the V8 JavaScript engine. The copyright notice reinforces this.

3. **Macro Analysis - `CPPGC_FOR_ALL_*_SCOPES`:** These macros are immediately striking. The naming convention clearly points to defining lists of "scopes."  The repetition suggests they're used for code generation or iteration. The comments "Histogram scopes contribute to histogram as well as to traces and metrics" and "Other scopes contribute only to traces and metrics" clarify the distinction between these groups. I mentally note these scopes represent different phases or activities within the garbage collection process.

4. **`enum ScopeId` and `enum ConcurrentScopeId`:** These enums directly use the macros. This confirms the macros are used to define the possible scopes. The `kNum...ScopeIds` members suggest they are used to determine the total number of different scopes. The "Concurrent" prefix indicates some scopes run in parallel.

5. **`struct Event`:**  This structure is named `Event`, and the comment says it holds "interesting data accumulated during a garbage collection cycle." The members (`scope_data`, `concurrent_scope_data`, `epoch`, `collection_type`, etc.) confirm this. They store timings, types of collections, and sizes related to garbage collection.

6. **`class StatsCollector`:** This is the main class. It's `final`, meaning it can't be inherited from. The comments and member variables provide clues about its functionality:
    * **Time Tracking:** `v8::base::TimeDelta`, `v8::base::TimeTicks` members, the `InternalScope` class, and the scope enums suggest it tracks the duration of different GC phases.
    * **Memory Tracking:** `marked_bytes`, `object_size_before_sweep_bytes`, `memory_size_before_sweep_bytes`, `allocated_memory_size`, `discarded_memory_size`, `resident_memory_size`.
    * **Garbage Collection State:** `GarbageCollectionState` enum.
    * **Observers:** `AllocationObserver` suggests a mechanism to notify other parts of the system about memory allocation changes.
    * **Metrics:** `MetricRecorder` indicates the collected statistics can be recorded and potentially visualized.
    * **Tracing:**  `TRACE_EVENT_*` macros within `InternalScope` show it integrates with V8's tracing infrastructure.

7. **`InternalScope` Class:** This nested template class is crucial. The comment "Trace a particular scope" is key. It takes a `StatsCollector`, a `scope_id`, and uses `v8::base::TimeTicks` to measure the duration of the scope. The `TRACE_EVENT_BEGIN` and `TRACE_EVENT_END` calls confirm its role in V8's tracing system. The template parameters `TraceCategory` and `ScopeContext` are interesting – enabling/disabling tracing and differentiating between mutator and concurrent threads.

8. **`AllocationObserver` Class:** The comments explain its purpose: observing allocated object size changes. The virtual methods (`AllocatedObjectSizeIncreased`, `AllocatedObjectSizeDecreased`, etc.) define the interface for these notifications.

9. **Method Analysis (briefly):** Skimming the public methods of `StatsCollector` reinforces the identified functionalities: `NotifyAllocation`, `NotifyExplicitFree`, `NotifyMarkingStarted`, `NotifySweepingCompleted`, `allocated_memory_size`, `marked_bytes`, `SetMetricRecorder`. These methods are clearly involved in tracking allocation events and GC cycle phases.

10. **Answering the Specific Questions:** Now, with a good understanding of the code, I can address the prompts:
    * **Functionality:** Summarize the key roles: tracking GC timings, memory usage, triggering notifications, and integrating with tracing/metrics.
    * **`.tq` extension:** State that it's not `.tq` and therefore not Torque.
    * **JavaScript Relationship:** Connect the memory management aspects to JavaScript's automatic garbage collection. Illustrate with a simple JavaScript example showing how object creation leads to memory allocation handled by CppGC.
    * **Code Logic Reasoning:** Choose a simple scenario like tracking the duration of `AtomicMark`. Provide example input (start and end times) and the expected output (time difference stored in `scope_data`).
    * **Common Programming Errors:** Focus on potential issues with the `AllocationObserver` interface, like forgetting to unregister, leading to dangling pointers or unexpected behavior.

11. **Review and Refine:**  Finally, I'd reread the generated answer, ensuring it's clear, concise, and accurately reflects the functionality of the code. I'd double-check the examples and reasoning.

This detailed process, starting with a high-level overview and gradually diving deeper into specific components, allows for a comprehensive understanding of the C++ header file and how it contributes to V8's garbage collection mechanism.
好的，让我们来分析一下 `v8/src/heap/cppgc/stats-collector.h` 这个 V8 源代码文件。

**文件功能：**

`stats-collector.h` 文件定义了一个名为 `StatsCollector` 的类，其主要功能是收集和记录 CppGC（V8 的 C++ 垃圾回收器）在运行过程中的各种统计信息。这些统计信息对于理解和优化垃圾回收器的性能至关重要。

具体来说，`StatsCollector` 的功能包括：

1. **跟踪垃圾回收事件的耗时：** 它定义了一系列的“作用域”（Scopes），代表垃圾回收的不同阶段或操作，例如标记（Mark）、清除（Sweep）等。通过 `InternalScope` 模板类，可以方便地记录每个作用域的开始和结束时间，从而计算出其执行耗时。这些作用域又分为histogram scopes（会记录到直方图中）和其他 scopes（仅记录到跟踪和指标中）。
2. **记录内存使用情况：**  它跟踪已分配的内存大小、已标记的字节数、垃圾回收前后的对象大小和内存大小等信息。
3. **区分垃圾回收的类型和原因：** 记录垃圾回收是 Major GC 还是 Minor GC，是原子（Atomic）的还是增量的（Incremental），以及是否是强制触发的。
4. **提供观察者机制：**  允许注册 `AllocationObserver`，以便在内存分配发生变化时收到通知。这可以用于实现堆增长启发式算法等。
5. **集成到 V8 的跟踪和指标系统：**  使用 `TRACE_EVENT` 宏将垃圾回收事件记录到 V8 的跟踪系统中，方便开发者进行性能分析。同时，它还使用 `MetricRecorder` 来记录直方图数据。
6. **支持并发垃圾回收统计：**  定义了 `ConcurrentScopeId` 和相关的宏，用于跟踪并发垃圾回收阶段的耗时。

**关于文件扩展名：**

文件以 `.h` 结尾，这是 C++ 头文件的标准扩展名。如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码。因此，`v8/src/heap/cppgc/stats-collector.h` 不是 Torque 源代码。

**与 JavaScript 的功能关系：**

`StatsCollector` 直接参与 CppGC 的运行，而 CppGC 是 V8 用来管理 C++ 对象生命周期的垃圾回收器。这些 C++ 对象很多时候是 V8 内部实现 JavaScript 功能的基础设施。虽然 `StatsCollector` 本身不直接操作 JavaScript 对象，但它收集的统计信息反映了垃圾回收器的行为，而垃圾回收器的效率直接影响 JavaScript 代码的执行性能和内存使用。

**JavaScript 示例：**

虽然不能直接用 JavaScript 代码来展示 `StatsCollector` 的功能，但可以说明 JavaScript 的某些行为会触发 CppGC 的活动，进而影响 `StatsCollector` 收集的统计信息。

例如，在 JavaScript 中创建大量的对象：

```javascript
let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push({ data: new Array(100).fill(i) });
}

// 稍后，将不再使用的对象解除引用
largeArray = null;
```

在这个例子中，创建 `largeArray` 会导致 C++ 堆上分配大量的内存来存储这些 JavaScript 对象（尽管 JavaScript 对象本身是由 JavaScript 引擎的堆管理的，但其底层的支撑结构可能使用 C++ 对象）。当 `largeArray` 被设置为 `null` 时，之前创建的对象变得不可达，CppGC 最终会回收这些对象占用的内存。

`StatsCollector` 会记录下这次垃圾回收过程中的各种信息，例如：

* **`MarkAtomic` / `IncrementalMark` 等作用域的耗时：** 标记阶段所花费的时间。
* **`AtomicSweep` / `IncrementalSweep` 等作用域的耗时：** 清除阶段所花费的时间。
* **`marked_bytes`：**  标记为可回收的字节数。
* **`object_size_before_sweep_bytes` 和 `memory_size_before_sweep_bytes`：** 清除操作前的对象和内存大小。

**代码逻辑推理（假设输入与输出）：**

假设在一次 Major GC 过程中，`AtomicMark` 阶段开始和结束的时间分别为 `T_start` 和 `T_end`。

**假设输入：**

* `gc_state_` 为 `GarbageCollectionState::kMarking`
* 在 `AtomicMark` 作用域开始时，`v8::base::TimeTicks::Now()` 返回 `T_start`。
* 在 `AtomicMark` 作用域结束时，`v8::base::TimeTicks::Now()` 返回 `T_end`。
* `current_.collection_type` 为 `CollectionType::kMajor`。

**代码执行流程：**

当进入 `AtomicMark` 作用域时，会创建一个 `EnabledScope` 对象，记录开始时间 `start_time_ = T_start`。

```c++
{
  EnabledScope scope(this, kAtomicMark);
  // ... 执行标记相关的代码 ...
}
```

当 `AtomicMark` 作用域结束时，`InternalScope` 的析构函数会被调用，计算耗时并记录：

```c++
~InternalScope() {
  StopTrace();
  IncreaseScopeTime();
}

void IncreaseScopeTime() {
  // ...
  v8::base::TimeDelta time = v8::base::TimeTicks::Now() - start_time_;
  // ...
  stats_collector_->current_.scope_data[scope_id_] += time;
  // ...
}
```

**预期输出：**

* `current_.scope_data[kAtomicMark]` 的值将增加 `T_end - T_start` 这么多的时间差。
* 如果启用了指标记录器，`RecordHistogramSample(kAtomicMark, T_end - T_start)` 将会被调用。
* V8 的跟踪系统中会记录一个名为 `CppGC.AtomicMark` 的事件，其持续时间为 `T_end - T_start`。

**用户常见的编程错误（与 `AllocationObserver` 相关）：**

用户在与垃圾回收器交互时，特别是使用 `AllocationObserver` 时，可能会犯一些编程错误：

1. **忘记取消注册观察者：**  如果在不再需要接收通知时，没有调用 `UnregisterObserver` 取消注册观察者，那么 `StatsCollector` 仍然会持有指向该观察者的指针。如果观察者对象被销毁，会导致悬挂指针，并在后续尝试调用观察者方法时引发崩溃或未定义行为。

   ```c++
   class MyObserver : public StatsCollector::AllocationObserver {
     // ...
   };

   void someFunction(StatsCollector* statsCollector) {
     MyObserver* observer = new MyObserver();
     statsCollector->RegisterObserver(observer);

     // ... 使用观察者 ...

     // 错误：忘记取消注册
     // delete observer; // 如果在这里删除，StatsCollector 会持有悬挂指针
   }
   ```

2. **在观察者回调函数中进行耗时操作或阻塞操作：** `StatsCollector` 在分配或释放内存时会同步调用观察者的回调函数。如果在这些回调函数中执行耗时或阻塞的操作，会直接影响垃圾回收器的性能，甚至可能导致应用卡顿。

   ```c++
   class MyObserver : public StatsCollector::AllocationObserver {
    public:
     void AllocatedObjectSizeIncreased(size_t size) override {
       // 错误：在回调函数中进行耗时的文件操作
       std::ofstream outputFile("allocation_log.txt", std::ios::app);
       outputFile << "Allocated: " << size << std::endl;
     }
   };
   ```

3. **在观察者回调函数中触发新的垃圾回收：** 某些观察者的回调函数允许触发垃圾回收。如果在回调函数中不小心或者过度地触发垃圾回收，可能会导致垃圾回收器频繁运行，降低应用性能。文档中明确指出某些回调函数（如 `ResetAllocatedObjectSize`）不应同步触发 GC。

理解 `v8/src/heap/cppgc/stats-collector.h` 的功能对于深入了解 V8 的内存管理和垃圾回收机制至关重要。通过分析其定义的类、枚举和宏，可以更好地理解 V8 如何跟踪和监控 C++ 堆的使用情况。

### 提示词
```
这是目录为v8/src/heap/cppgc/stats-collector.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc/stats-collector.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_HEAP_CPPGC_STATS_COLLECTOR_H_
#define V8_HEAP_CPPGC_STATS_COLLECTOR_H_

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <atomic>
#include <vector>

#include "include/cppgc/platform.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/platform/time.h"
#include "src/heap/cppgc/garbage-collector.h"
#include "src/heap/cppgc/metric-recorder.h"
#include "src/heap/cppgc/trace-event.h"

namespace cppgc {
namespace internal {

// Histogram scopes contribute to histogram as well as to traces and metrics.
// Other scopes contribute only to traces and metrics.
#define CPPGC_FOR_ALL_HISTOGRAM_SCOPES(V) \
  V(AtomicMark)                           \
  V(AtomicWeak)                           \
  V(AtomicCompact)                        \
  V(AtomicSweep)                          \
  V(IncrementalMark)                      \
  V(IncrementalSweep)

#define CPPGC_FOR_ALL_SCOPES(V)             \
  V(Unmark)                                 \
  V(MarkIncrementalStart)                   \
  V(MarkIncrementalFinalize)                \
  V(MarkAtomicPrologue)                     \
  V(MarkAtomicEpilogue)                     \
  V(MarkTransitiveClosure)                  \
  V(MarkTransitiveClosureWithDeadline)      \
  V(MarkFlushEphemerons)                    \
  V(MarkOnAllocation)                       \
  V(MarkProcessBailOutObjects)              \
  V(MarkProcessMarkingWorklist)             \
  V(MarkProcessWriteBarrierWorklist)        \
  V(MarkProcessNotFullyconstructedWorklist) \
  V(MarkProcessEphemerons)                  \
  V(MarkVisitRoots)                         \
  V(MarkVisitNotFullyConstructedObjects)    \
  V(MarkVisitPersistents)                   \
  V(MarkVisitCrossThreadPersistents)        \
  V(MarkVisitStack)                         \
  V(MarkVisitRememberedSets)                \
  V(WeakContainerCallbacksProcessing)       \
  V(CustomCallbacksProcessing)              \
  V(SweepEmptyPages)                        \
  V(SweepFinish)                            \
  V(SweepFinalizeEmptyPages)                \
  V(SweepFinalizeSweptPages)                \
  V(SweepFinishIfOutOfWork)                 \
  V(SweepInvokePreFinalizers)               \
  V(SweepInLowPriorityTask)                 \
  V(SweepInTask)                            \
  V(SweepInTaskForStatistics)               \
  V(SweepOnAllocation)                      \
  V(SweepPages)

#define CPPGC_FOR_ALL_HISTOGRAM_CONCURRENT_SCOPES(V) \
  V(ConcurrentMark)                                  \
  V(ConcurrentSweep)                                 \
  V(ConcurrentWeakCallback)

#define CPPGC_FOR_ALL_CONCURRENT_SCOPES(V) V(ConcurrentMarkProcessEphemerons)

// Sink for various time and memory statistics.
class V8_EXPORT_PRIVATE StatsCollector final {
  using IsForcedGC = GCConfig::IsForcedGC;

 public:
  using MarkingType = GCConfig::MarkingType;
  using SweepingType = GCConfig::SweepingType;

#if defined(CPPGC_DECLARE_ENUM)
  static_assert(false, "CPPGC_DECLARE_ENUM macro is already defined");
#endif

  enum ScopeId {
#define CPPGC_DECLARE_ENUM(name) k##name,
    CPPGC_FOR_ALL_HISTOGRAM_SCOPES(CPPGC_DECLARE_ENUM)
        kNumHistogramScopeIds,
    CPPGC_FOR_ALL_SCOPES(CPPGC_DECLARE_ENUM)
#undef CPPGC_DECLARE_ENUM
        kNumScopeIds,
  };

  enum ConcurrentScopeId {
#define CPPGC_DECLARE_ENUM(name) k##name,
    CPPGC_FOR_ALL_HISTOGRAM_CONCURRENT_SCOPES(CPPGC_DECLARE_ENUM)
        kNumHistogramConcurrentScopeIds,
    CPPGC_FOR_ALL_CONCURRENT_SCOPES(CPPGC_DECLARE_ENUM)
#undef CPPGC_DECLARE_ENUM
        kNumConcurrentScopeIds
  };

  // POD to hold interesting data accumulated during a garbage collection cycle.
  //
  // The event is always fully populated when looking at previous events but
  // may only be partially populated when looking at the current event.
  struct Event final {
    V8_EXPORT_PRIVATE explicit Event();

    v8::base::TimeDelta scope_data[kNumHistogramScopeIds];
    v8::base::AtomicWord concurrent_scope_data[kNumHistogramConcurrentScopeIds]{
        0};

    size_t epoch = -1;
    CollectionType collection_type = CollectionType::kMajor;
    MarkingType marking_type = MarkingType::kAtomic;
    SweepingType sweeping_type = SweepingType::kAtomic;
    IsForcedGC is_forced_gc = IsForcedGC::kNotForced;
    // Marked bytes collected during marking.
    size_t marked_bytes = 0;
    size_t object_size_before_sweep_bytes = -1;
    size_t memory_size_before_sweep_bytes = -1;
  };

 private:
#if defined(CPPGC_CASE)
  static_assert(false, "CPPGC_CASE macro is already defined");
#endif

  constexpr static const char* GetScopeName(ScopeId id, CollectionType type) {
    switch (id) {
#define CPPGC_CASE(name)                                   \
  case k##name:                                            \
    return type == CollectionType::kMajor ? "CppGC." #name \
                                          : "CppGC." #name ".Minor";
      CPPGC_FOR_ALL_HISTOGRAM_SCOPES(CPPGC_CASE)
      CPPGC_FOR_ALL_SCOPES(CPPGC_CASE)
#undef CPPGC_CASE
      default:
        return nullptr;
    }
  }

  constexpr static const char* GetScopeName(ConcurrentScopeId id,
                                            CollectionType type) {
    switch (id) {
#define CPPGC_CASE(name)                                   \
  case k##name:                                            \
    return type == CollectionType::kMajor ? "CppGC." #name \
                                          : "CppGC." #name ".Minor";
      CPPGC_FOR_ALL_HISTOGRAM_CONCURRENT_SCOPES(CPPGC_CASE)
      CPPGC_FOR_ALL_CONCURRENT_SCOPES(CPPGC_CASE)
#undef CPPGC_CASE
      default:
        return nullptr;
    }
  }

  enum TraceCategory { kEnabled, kDisabled };
  enum ScopeContext { kMutatorThread, kConcurrentThread };

  // Trace a particular scope. Will emit a trace event and record the time in
  // the corresponding StatsCollector.
  template <TraceCategory trace_category, ScopeContext scope_category>
  class V8_NODISCARD InternalScope {
    using ScopeIdType = std::conditional_t<scope_category == kMutatorThread,
                                           ScopeId, ConcurrentScopeId>;

   public:
    template <typename... Args>
    InternalScope(StatsCollector* stats_collector, ScopeIdType scope_id,
                  Args... args)
        : stats_collector_(stats_collector),
          start_time_(v8::base::TimeTicks::Now()),
          scope_id_(scope_id) {
      DCHECK_LE(0, scope_id_);
      DCHECK_LT(static_cast<int>(scope_id_),
                scope_category == kMutatorThread
                    ? static_cast<int>(kNumScopeIds)
                    : static_cast<int>(kNumConcurrentScopeIds));
      DCHECK_NE(static_cast<int>(scope_id_),
                scope_category == kMutatorThread
                    ? static_cast<int>(kNumHistogramScopeIds)
                    : static_cast<int>(kNumHistogramConcurrentScopeIds));
      StartTrace(args...);
    }

    ~InternalScope() {
      StopTrace();
      IncreaseScopeTime();
    }

    InternalScope(const InternalScope&) = delete;
    InternalScope& operator=(const InternalScope&) = delete;

    void DecreaseStartTimeForTesting(v8::base::TimeDelta delta) {
      start_time_ -= delta;
    }

   private:
    void* operator new(size_t, void*) = delete;
    void* operator new(size_t) = delete;

    inline constexpr static const char* TraceCategory();

    template <typename... Args>
    inline void StartTrace(Args... args);
    inline void StopTrace();

    inline void StartTraceImpl();
    template <typename Value1>
    inline void StartTraceImpl(const char* k1, Value1 v1);
    template <typename Value1, typename Value2>
    inline void StartTraceImpl(const char* k1, Value1 v1, const char* k2,
                               Value2 v2);
    inline void StopTraceImpl();

    inline void IncreaseScopeTime();

    StatsCollector* const stats_collector_;
    v8::base::TimeTicks start_time_;
    const ScopeIdType scope_id_;
  };

 public:
  using DisabledScope = InternalScope<kDisabled, kMutatorThread>;
  using EnabledScope = InternalScope<kEnabled, kMutatorThread>;
  using DisabledConcurrentScope = InternalScope<kDisabled, kConcurrentThread>;
  using EnabledConcurrentScope = InternalScope<kEnabled, kConcurrentThread>;

  // Observer for allocated object size. May e.g. be used to implement heap
  // growing heuristics. Observers may register/unregister observers at any
  // time when being invoked.
  class AllocationObserver {
   public:
    // Called after observing at least
    // StatsCollector::kAllocationThresholdBytes changed bytes through
    // allocation or explicit free. Reports both, negative and positive
    // increments, to allow observer to decide whether absolute values or only
    // the deltas is interesting.
    //
    // May trigger GC.
    virtual void AllocatedObjectSizeIncreased(size_t) {}
    virtual void AllocatedObjectSizeDecreased(size_t) {}

    // Called when the exact size of allocated object size is known. In
    // practice, this is after marking when marked bytes == allocated bytes.
    //
    // Must not trigger GC synchronously.
    virtual void ResetAllocatedObjectSize(size_t) {}

    // Called upon allocating/releasing chunks of memory (e.g. pages) that can
    // contain objects.
    //
    // Must not trigger GC.
    virtual void AllocatedSizeIncreased(size_t) {}
    virtual void AllocatedSizeDecreased(size_t) {}
  };

  // Observers are implemented using virtual calls. Avoid notifications below
  // reasonably interesting sizes.
  static constexpr size_t kAllocationThresholdBytes = 1024;

  explicit StatsCollector(Platform*);
  StatsCollector(const StatsCollector&) = delete;
  StatsCollector& operator=(const StatsCollector&) = delete;

  void RegisterObserver(AllocationObserver*);
  void UnregisterObserver(AllocationObserver*);

  void NotifyAllocation(size_t);
  void NotifyExplicitFree(size_t);
  // Safepoints should only be invoked when garbage collections are possible.
  // This is necessary as increments and decrements are reported as close to
  // their actual allocation/reclamation as possible.
  void NotifySafePointForConservativeCollection();

  void NotifySafePointForTesting();

  // Indicates a new garbage collection cycle. The phase is optional and is only
  // used for major GC when generational GC is enabled.
  void NotifyUnmarkingStarted(CollectionType);
  // Indicates a new minor garbage collection cycle or a major, if generational
  // GC is not enabled.
  void NotifyMarkingStarted(CollectionType, MarkingType, IsForcedGC);
  // Indicates that marking of the current garbage collection cycle is
  // completed.
  void NotifyMarkingCompleted(size_t marked_bytes);
  // Indicates the end of a garbage collection cycle. This means that sweeping
  // is finished at this point.
  void NotifySweepingCompleted(SweepingType);

  size_t allocated_memory_size() const;
  // Size of live objects in bytes  on the heap. Based on the most recent marked
  // bytes and the bytes allocated since last marking.
  size_t allocated_object_size() const;

  // Returns the overall marked bytes count, i.e. if young generation is
  // enabled, it returns the accumulated number. Should not be called during
  // marking.
  size_t marked_bytes() const;

  // Returns the marked bytes for the current cycle. Should only be called
  // within GC cycle.
  size_t marked_bytes_on_current_cycle() const;

  // Returns the overall duration of the most recent marking phase. Should not
  // be called during marking.
  v8::base::TimeDelta marking_time() const;

  double GetRecentAllocationSpeedInBytesPerMs() const;

  const Event& GetPreviousEventForTesting() const { return previous_; }

  void NotifyAllocatedMemory(int64_t);
  void NotifyFreedMemory(int64_t);

  void IncrementDiscardedMemory(size_t);
  void DecrementDiscardedMemory(size_t);
  void ResetDiscardedMemory();
  size_t discarded_memory_size() const;
  size_t resident_memory_size() const;

  void SetMetricRecorder(std::unique_ptr<MetricRecorder> histogram_recorder) {
    metric_recorder_ = std::move(histogram_recorder);
  }

  MetricRecorder* GetMetricRecorder() const { return metric_recorder_.get(); }

 private:
  enum class GarbageCollectionState : uint8_t {
    kNotRunning,
    kUnmarking,
    kMarking,
    kSweeping
  };

  void RecordHistogramSample(ScopeId, v8::base::TimeDelta);
  void RecordHistogramSample(ConcurrentScopeId, v8::base::TimeDelta) {}

  // Invokes |callback| for all registered observers.
  template <typename Callback>
  void ForAllAllocationObservers(Callback callback);

  void AllocatedObjectSizeSafepointImpl();

  // Allocated bytes since the end of marking. These bytes are reset after
  // marking as they are accounted in marked_bytes then. May be negative in case
  // an object was explicitly freed that was marked as live in the previous
  // cycle.
  int64_t allocated_bytes_since_end_of_marking_ = 0;
  v8::base::TimeTicks time_of_last_end_of_marking_ = v8::base::TimeTicks::Now();
  // Counters for allocation and free. The individual values are never negative
  // but their delta may be because of the same reason the overall
  // allocated_bytes_since_end_of_marking_ may be negative. Keep integer
  // arithmetic for simplicity.
  int64_t allocated_bytes_since_safepoint_ = 0;
  int64_t explicitly_freed_bytes_since_safepoint_ = 0;
#ifdef CPPGC_VERIFY_HEAP
  // Tracks live bytes for overflows.
  size_t tracked_live_bytes_ = 0;
#endif  // CPPGC_VERIFY_HEAP

  // The number of bytes marked so far. For young generation (with sticky bits)
  // keeps track of marked bytes across multiple GC cycles.
  size_t marked_bytes_so_far_ = 0;

  int64_t memory_allocated_bytes_ = 0;
  int64_t memory_freed_bytes_since_end_of_marking_ = 0;
  std::atomic<size_t> discarded_bytes_{0};

  // vector to allow fast iteration of observers. Register/Unregisters only
  // happens on startup/teardown.
  std::vector<AllocationObserver*> allocation_observers_;
  bool allocation_observer_deleted_ = false;

  GarbageCollectionState gc_state_ = GarbageCollectionState::kNotRunning;

  // The event being filled by the current GC cycle between NotifyMarkingStarted
  // and NotifySweepingFinished.
  Event current_;
  // The previous GC event which is populated at NotifySweepingFinished.
  Event previous_;

  std::unique_ptr<MetricRecorder> metric_recorder_;

  // |platform_| is used by the TRACE_EVENT_* macros.
  Platform* platform_;
};

template <typename Callback>
void StatsCollector::ForAllAllocationObservers(Callback callback) {
  // Iterate using indices to allow push_back() of new observers.
  for (size_t i = 0; i < allocation_observers_.size(); ++i) {
    auto* observer = allocation_observers_[i];
    if (observer) {
      callback(observer);
    }
  }
  if (allocation_observer_deleted_) {
    allocation_observers_.erase(
        std::remove(allocation_observers_.begin(), allocation_observers_.end(),
                    nullptr),
        allocation_observers_.end());
    allocation_observer_deleted_ = false;
  }
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
constexpr const char*
StatsCollector::InternalScope<trace_category, scope_category>::TraceCategory() {
  switch (trace_category) {
    case kEnabled:
      return "cppgc";
    case kDisabled:
      return TRACE_DISABLED_BY_DEFAULT("cppgc");
  }
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
template <typename... Args>
void StatsCollector::InternalScope<trace_category, scope_category>::StartTrace(
    Args... args) {
  // Top level scopes that contribute to histogram should always be enabled.
  DCHECK_IMPLIES(static_cast<int>(scope_id_) <
                     (scope_category == kMutatorThread
                          ? static_cast<int>(kNumHistogramScopeIds)
                          : static_cast<int>(kNumHistogramConcurrentScopeIds)),
                 trace_category == StatsCollector::TraceCategory::kEnabled);
  StartTraceImpl(args...);
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
void StatsCollector::InternalScope<trace_category,
                                   scope_category>::StopTrace() {
  StopTraceImpl();
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
void StatsCollector::InternalScope<trace_category,
                                   scope_category>::StartTraceImpl() {
  TRACE_EVENT_BEGIN0(
      TraceCategory(),
      GetScopeName(scope_id_, stats_collector_->current_.collection_type));
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
template <typename Value1>
void StatsCollector::InternalScope<
    trace_category, scope_category>::StartTraceImpl(const char* k1, Value1 v1) {
  TRACE_EVENT_BEGIN1(
      TraceCategory(),
      GetScopeName(scope_id_, stats_collector_->current_.collection_type), k1,
      v1);
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
template <typename Value1, typename Value2>
void StatsCollector::InternalScope<
    trace_category, scope_category>::StartTraceImpl(const char* k1, Value1 v1,
                                                    const char* k2, Value2 v2) {
  TRACE_EVENT_BEGIN2(
      TraceCategory(),
      GetScopeName(scope_id_, stats_collector_->current_.collection_type), k1,
      v1, k2, v2);
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
void StatsCollector::InternalScope<trace_category,
                                   scope_category>::StopTraceImpl() {
  TRACE_EVENT_END2(
      TraceCategory(),
      GetScopeName(scope_id_, stats_collector_->current_.collection_type),
      "epoch", stats_collector_->current_.epoch, "forced",
      stats_collector_->current_.is_forced_gc == IsForcedGC::kForced);
}

template <StatsCollector::TraceCategory trace_category,
          StatsCollector::ScopeContext scope_category>
void StatsCollector::InternalScope<trace_category,
                                   scope_category>::IncreaseScopeTime() {
  DCHECK_NE(GarbageCollectionState::kNotRunning, stats_collector_->gc_state_);
  // Only record top level scopes.
  if (static_cast<int>(scope_id_) >=
      (scope_category == kMutatorThread
           ? static_cast<int>(kNumHistogramScopeIds)
           : static_cast<int>(kNumHistogramConcurrentScopeIds)))
    return;
  v8::base::TimeDelta time = v8::base::TimeTicks::Now() - start_time_;
  if (scope_category == StatsCollector::ScopeContext::kMutatorThread) {
    stats_collector_->current_.scope_data[scope_id_] += time;
    if (stats_collector_->metric_recorder_)
      stats_collector_->RecordHistogramSample(scope_id_, time);
    return;
  }
  // scope_category == StatsCollector::ScopeContext::kConcurrentThread
  using AtomicWord = v8::base::AtomicWord;
  const int64_t us = time.InMicroseconds();
  v8::base::Relaxed_AtomicIncrement(
      &stats_collector_->current_.concurrent_scope_data[scope_id_],
      static_cast<AtomicWord>(us));
}

}  // namespace internal
}  // namespace cppgc

#endif  // V8_HEAP_CPPGC_STATS_COLLECTOR_H_
```