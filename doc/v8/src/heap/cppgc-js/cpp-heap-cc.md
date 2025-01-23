Response:
The user wants me to analyze the provided C++ source code file `v8/src/heap/cppgc-js/cpp-heap.cc`. I need to identify its functionalities and address several specific points:

1. **List functionalities:** Summarize what the code does.
2. **Torque source:** Check if the filename ends with `.tq`.
3. **Javascript relation:** If the code interacts with Javascript, provide an example.
4. **Code logic inference:** If there's logical deduction, give an example with input and output.
5. **Common programming errors:** Point out potential mistakes related to this code.
6. **Summarize functionality (Part 1):**  Give a high-level overview of the code's purpose based on the first part provided.

Let's go through each point:

1. **Functionalities:** The code defines the `CppHeap` class, which seems to be an interface between V8's garbage collection and cppgc (the C++ garbage collector). It handles:
    - Creation and termination of the C++ heap.
    - Triggering garbage collection (major and minor).
    - Collecting heap statistics.
    - Integration with V8's platform and isolate.
    - Management of marking and sweeping phases of garbage collection.
    - Interaction with V8's heap profiler and metrics recorder.
    - Support for custom memory spaces.
    - Implementation of concurrent and incremental garbage collection.
    - Handling out-of-memory situations.

2. **Torque source:** The filename `cpp-heap.cc` ends with `.cc`, not `.tq`. So, it's not a Torque source file.

3. **Javascript relation:** Yes, the code is tightly coupled with Javascript. The `CppHeap` is part of V8's internal implementation, which executes Javascript. The code interacts with `v8::Isolate`, `v8::Heap`, and other V8 concepts.

4. **Code logic inference:**  A clear example is the `MinorGCHeapGrowing` class. It calculates a limit for the heap size before triggering a minor GC.
    - **Assumption:** The heap grows by a factor of 1.5, with a minimum increase.
    - **Input:** `allocated_object_size` (current allocated size).
    - **Output:** `limit_for_atomic_gc_` (the calculated limit).

5. **Common programming errors:**  While this is internal V8 code, potential errors based on the concepts involved include:
    - Incorrectly managing the lifecycle of objects in the C++ heap, potentially leading to leaks or double frees if not adhering to cppgc's rules.
    - Misunderstanding the interaction between V8's GC and cppgc, potentially leading to unexpected object lifetimes.
    - Issues with concurrent access to the heap if not properly synchronized (although V8 handles much of this).

6. **Summarize functionality (Part 1):** The first part of the `cpp-heap.cc` file focuses on the foundational setup and core responsibilities of the `CppHeap`. It defines how the `CppHeap` is created, integrates with the V8 platform, manages basic lifecycle operations (creation, termination), and exposes interfaces for triggering garbage collection and collecting statistics. It introduces the `MinorGCHeapGrowing` strategy for minor GCs and sets up the necessary adapters for cppgc to interact with V8 components.
```
功能列表:

* **作为 C++ 垃圾回收器 (cppgc) 在 V8 中的接口:** `CppHeap` 类充当了 cppgc 与 V8 JavaScript 引擎之间的桥梁，允许 C++ 对象被垃圾回收。
* **堆的创建和管理:**  负责创建 `CppHeap` 实例，并管理其生命周期，包括初始化和终止。
* **与 V8 平台的集成:**  使用 `v8::Platform` 接口与宿主平台进行交互，例如获取页分配器、时间函数和任务运行器。
* **垃圾回收的触发:** 提供了触发主垃圾回收 (Major GC) 和新生代垃圾回收 (Minor GC) 的接口，例如 `CollectGarbageForTesting` 和 `CollectGarbageInYoungGenerationForTesting`。
* **堆统计信息的收集:**  能够收集堆的使用情况统计信息，包括详细级别控制。
* **自定义内存空间的支持:**  允许创建和管理自定义的 C++ 内存空间。
* **分离垃圾回收 (Detached Garbage Collection) 的支持:**  为测试目的提供了启用独立垃圾回收的机制。
* **与 V8 Isolate 的关联:**  在 `AttachIsolate` 和 `DetachIsolate` 中处理 `CppHeap` 与 V8 `Isolate` 的关联和分离。
* **并发标记 (Concurrent Marking) 的管理:**  管理并发标记的启动、推进和完成，包括与 V8 的并发标记机制的协调。
* **增量标记 (Incremental Marking) 的管理:**  管理增量标记的推进，并在 V8 的标记步骤中进行协调。
* **原子暂停 (Atomic Pause) 的管理:**  管理垃圾回收的原子暂停阶段，包括进入和退出原子暂停。
* **度量记录 (Metrics Recording):**  集成了度量记录功能，用于记录 C++ 堆的垃圾回收事件，并与 V8 的度量系统进行交互。
* **OOM (Out Of Memory) 处理:**  设置自定义的 OOM 处理函数，在内存不足时触发致命错误。
* **与 V8 堆分析器 (Heap Profiler) 的集成:**  允许 V8 的堆分析器访问和分析 C++ 堆的信息。
* **写屏障 (Write Barrier):**  提供写屏障机制，用于在对象发生修改时通知垃圾回收器。
* **支持分代垃圾回收 (Generational GC):**  部分支持分代垃圾回收，特别是新生代垃圾回收。

关于源代码性质:

`v8/src/heap/cppgc-js/cpp-heap.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 v8 Torque 源代码。

与 Javascript 的功能关系和示例:

`v8/src/heap/cppgc-js/cpp-heap.cc` 的核心功能是为 V8 管理 C++ 对象的生命周期，这直接关系到 Javascript 的功能。  V8 引擎本身是用 C++ 编写的，许多内部对象和数据结构都是 C++ 对象。 `CppHeap` 确保这些 C++ 对象在不再被 Javascript 代码引用时能够被安全地回收，从而防止内存泄漏。

**JavaScript 例子:**

假设在 V8 内部，有一个 C++ 类 `MyCppObject`，它需要被垃圾回收。 当一段 Javascript 代码创建一个与 `MyCppObject` 关联的对象时，`CppHeap` 就负责管理 `MyCppObject` 实例的内存。

```javascript
// 假设 V8 内部的实现中，某个操作会创建 MyCppObject 的实例
let myJsObject = createMyObject(); // 内部会关联一个 MyCppObject 实例

// ... 一段时间后，myJsObject 不再被使用
myJsObject = null; // 解除引用

// 当 V8 执行垃圾回收时，CppHeap 会识别出关联的 MyCppObject 不再被引用，
// 并将其回收，释放其占用的内存。
```

在这个例子中，虽然 Javascript 代码本身没有直接操作 `CppHeap`，但 `CppHeap` 在后台默默地工作，确保与 Javascript 对象生命周期相关的 C++ 对象的内存得到正确管理。

代码逻辑推理示例:

**场景:** `MinorGCHeapGrowing` 类用于控制何时触发新生代垃圾回收。

**假设输入:**

* `stats_collector_.allocated_object_size()`: 当前 C++ 堆已分配的对象大小，例如 10MB。
* 初始堆大小 `initial_heap_size_`: 1MB。

**代码逻辑:**

```c++
  void ResetAllocatedObjectSize(size_t allocated_object_size) final {
    ConfigureLimit(allocated_object_size);
  }

 private:
  void ConfigureLimit(size_t allocated_object_size) {
    // Constant growing factor for growing the heap limit.
    static constexpr double kGrowingFactor = 1.5;
    // For smaller heaps, allow allocating at least LAB in each regular space
    // before triggering GC again.
    static constexpr size_t kMinLimitIncrease =
        cppgc::internal::kPageSize *
        cppgc::internal::RawHeap::kNumberOfRegularSpaces;

    const size_t size = std::max(allocated_object_size, initial_heap_size_);
    limit_for_atomic_gc_ = std::max(static_cast<size_t>(size * kGrowingFactor),
                                    size + kMinLimitIncrease);
  }
```

**推理过程:**

1. `ResetAllocatedObjectSize` 被调用，传入 `allocated_object_size` 为 10MB。
2. `ConfigureLimit` 被调用，`allocated_object_size` 为 10MB。
3. `size` 被计算为 `std::max(10MB, 1MB)`，结果为 10MB。
4. 假设 `kMinLimitIncrease` 计算结果为 2MB (这是一个假设值，实际取决于页大小和空间数量)。
5. `limit_for_atomic_gc_` 被计算为 `std::max(static_cast<size_t>(10MB * 1.5), 10MB + 2MB)`，即 `std::max(15MB, 12MB)`，结果为 15MB。

**输出:** `limit_for_atomic_gc_` 将被设置为 15MB。这意味着当 C++ 堆的已分配大小达到或超过 15MB 时，可能会触发一次新生代垃圾回收。

用户常见的编程错误 (与此代码相关的概念):

虽然用户通常不直接编写或修改 `v8/src` 下的代码，但理解 `CppHeap` 的概念可以帮助理解与内存管理相关的编程错误：

1. **C++ 对象生命周期管理错误:**  如果开发者在 V8 的 C++ 绑定层创建了需要在 `CppHeap` 上管理的 C++ 对象，但未能正确地处理它们的生命周期（例如，忘记使用 cppgc 的分配器，或者持有了不必要的引用），可能会导致内存泄漏。

   **例子 (假设的错误 C++ 代码):**

   ```c++
   // 错误的做法，可能导致内存泄漏
   MyCppObject* leaky_object = new MyCppObject();
   v8::Local<v8::External> external = v8::External::New(isolate, leaky_object);
   ```

   正确的做法应该使用 cppgc 的分配器：

   ```c++
   auto* cpp_heap = internal::CppHeap::From(v8_heap);
   MyCppObject* managed_object = cpp_heap->template Allocate<MyCppObject>();
   v8::Local<v8::External> external = v8::External::New(isolate, managed_object);
   ```

2. **对垃圾回收的误解:**  开发者可能错误地认为一旦 Javascript 对象被垃圾回收，所有相关的 C++ 对象也会立即被回收。实际上，这取决于 `CppHeap` 的回收机制和引用关系。如果 C++ 对象还有来自其他地方的强引用，它就不会被回收。

3. **在不适当的时机访问已回收的 C++ 对象:**  如果 Javascript 代码持有一个指向 C++ 对象的弱引用，并且该 C++ 对象已经被 `CppHeap` 回收，那么在访问该对象时会导致错误。

总结 (第 1 部分的功能):

`v8/src/heap/cppgc-js/cpp-heap.cc` 的第一部分主要负责定义 `CppHeap` 类的基本结构和核心功能，使其能够作为 cppgc 在 V8 中的接口。它处理了堆的创建、与 V8 平台的集成、基本的垃圾回收触发机制、统计信息的收集以及自定义内存空间的支持。 此外，它初步建立了与 V8 `Isolate` 的关联机制，并引入了新生代垃圾回收的初步管理策略 (`MinorGCHeapGrowing`)。  这一部分奠定了 `CppHeap` 作为 V8 中 C++ 对象内存管理基础的关键作用。
```
### 提示词
```
这是目录为v8/src/heap/cppgc-js/cpp-heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/cppgc-js/cpp-heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc-js/cpp-heap.h"

#include <cstdint>
#include <memory>
#include <numeric>
#include <optional>

#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/platform.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-platform.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/base/platform/time.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/v8threads.h"
#include "src/flags/flags.h"
#include "src/handles/handles.h"
#include "src/handles/traced-handles.h"
#include "src/heap/base/stack.h"
#include "src/heap/cppgc-js/cpp-marking-state.h"
#include "src/heap/cppgc-js/cpp-snapshot.h"
#include "src/heap/cppgc-js/unified-heap-marking-state-inl.h"
#include "src/heap/cppgc-js/unified-heap-marking-state.h"
#include "src/heap/cppgc-js/unified-heap-marking-verifier.h"
#include "src/heap/cppgc-js/unified-heap-marking-visitor.h"
#include "src/heap/cppgc/concurrent-marker.h"
#include "src/heap/cppgc/gc-info-table.h"
#include "src/heap/cppgc/heap-base.h"
#include "src/heap/cppgc/heap-object-header.h"
#include "src/heap/cppgc/marker.h"
#include "src/heap/cppgc/marking-state.h"
#include "src/heap/cppgc/marking-visitor.h"
#include "src/heap/cppgc/metric-recorder.h"
#include "src/heap/cppgc/object-allocator.h"
#include "src/heap/cppgc/page-memory.h"
#include "src/heap/cppgc/platform.h"
#include "src/heap/cppgc/prefinalizer-handler.h"
#include "src/heap/cppgc/raw-heap.h"
#include "src/heap/cppgc/stats-collector.h"
#include "src/heap/cppgc/sweeper.h"
#include "src/heap/cppgc/unmarker.h"
#include "src/heap/cppgc/visitor.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap.h"
#include "src/heap/marking-worklist.h"
#include "src/heap/minor-mark-sweep.h"
#include "src/heap/traced-handles-marking-visitor.h"
#include "src/init/v8.h"
#include "src/profiler/heap-profiler.h"

namespace v8 {

namespace internal {

class MinorGCHeapGrowing
    : public cppgc::internal::StatsCollector::AllocationObserver {
 public:
  explicit MinorGCHeapGrowing(cppgc::internal::StatsCollector& stats_collector)
      : stats_collector_(stats_collector) {
    stats_collector.RegisterObserver(this);
  }
  virtual ~MinorGCHeapGrowing() = default;

  void AllocatedObjectSizeIncreased(size_t) final {}
  void AllocatedObjectSizeDecreased(size_t) final {}
  void ResetAllocatedObjectSize(size_t allocated_object_size) final {
    ConfigureLimit(allocated_object_size);
  }

  bool LimitReached() const {
    return stats_collector_.allocated_object_size() >= limit_for_atomic_gc_;
  }

 private:
  void ConfigureLimit(size_t allocated_object_size) {
    // Constant growing factor for growing the heap limit.
    static constexpr double kGrowingFactor = 1.5;
    // For smaller heaps, allow allocating at least LAB in each regular space
    // before triggering GC again.
    static constexpr size_t kMinLimitIncrease =
        cppgc::internal::kPageSize *
        cppgc::internal::RawHeap::kNumberOfRegularSpaces;

    const size_t size = std::max(allocated_object_size, initial_heap_size_);
    limit_for_atomic_gc_ = std::max(static_cast<size_t>(size * kGrowingFactor),
                                    size + kMinLimitIncrease);
  }

  cppgc::internal::StatsCollector& stats_collector_;
  size_t initial_heap_size_ = 1 * cppgc::internal::kMB;
  size_t limit_for_atomic_gc_ = 0;  // See ConfigureLimit().
};

}  // namespace internal

// static
std::unique_ptr<CppHeap> CppHeap::Create(v8::Platform* platform,
                                         const CppHeapCreateParams& params) {
  return std::make_unique<internal::CppHeap>(platform, params.custom_spaces,
                                             params.marking_support,
                                             params.sweeping_support);
}

cppgc::AllocationHandle& CppHeap::GetAllocationHandle() {
  return internal::CppHeap::From(this)->object_allocator();
}

cppgc::HeapHandle& CppHeap::GetHeapHandle() {
  return *internal::CppHeap::From(this);
}

void CppHeap::Terminate() { internal::CppHeap::From(this)->Terminate(); }

cppgc::HeapStatistics CppHeap::CollectStatistics(
    cppgc::HeapStatistics::DetailLevel detail_level) {
  return internal::CppHeap::From(this)->AsBase().CollectStatistics(
      detail_level);
}

void CppHeap::CollectCustomSpaceStatisticsAtLastGC(
    std::vector<cppgc::CustomSpaceIndex> custom_spaces,
    std::unique_ptr<CustomSpaceStatisticsReceiver> receiver) {
  return internal::CppHeap::From(this)->CollectCustomSpaceStatisticsAtLastGC(
      std::move(custom_spaces), std::move(receiver));
}

void CppHeap::EnableDetachedGarbageCollectionsForTesting() {
  return internal::CppHeap::From(this)
      ->EnableDetachedGarbageCollectionsForTesting();
}

void CppHeap::CollectGarbageForTesting(cppgc::EmbedderStackState stack_state) {
  return internal::CppHeap::From(this)->CollectGarbageForTesting(
      internal::CppHeap::CollectionType::kMajor, stack_state);
}

void CppHeap::CollectGarbageInYoungGenerationForTesting(
    cppgc::EmbedderStackState stack_state) {
  return internal::CppHeap::From(this)->CollectGarbageForTesting(
      internal::CppHeap::CollectionType::kMinor, stack_state);
}

namespace internal {

namespace {

class CppgcPlatformAdapter final : public cppgc::Platform {
 public:
  explicit CppgcPlatformAdapter(v8::Platform* platform)
      : platform_(platform),
        page_allocator_(platform->GetPageAllocator()
                            ? platform->GetPageAllocator()
                            : &cppgc::internal::GetGlobalPageAllocator()) {}

  CppgcPlatformAdapter(const CppgcPlatformAdapter&) = delete;
  CppgcPlatformAdapter& operator=(const CppgcPlatformAdapter&) = delete;

  PageAllocator* GetPageAllocator() final { return page_allocator_; }

  double MonotonicallyIncreasingTime() final {
    return platform_->MonotonicallyIncreasingTime();
  }

  std::shared_ptr<TaskRunner> GetForegroundTaskRunner(
      TaskPriority priority) final {
    // If no Isolate has been set, there's no task runner to leverage for
    // foreground tasks. In detached mode the original platform handles the
    // task runner retrieval.
    if (!isolate_ && !is_in_detached_mode_) return nullptr;

    return platform_->GetForegroundTaskRunner(isolate_, priority);
  }

  std::unique_ptr<JobHandle> PostJob(TaskPriority priority,
                                     std::unique_ptr<JobTask> job_task) final {
    return platform_->PostJob(priority, std::move(job_task));
  }

  TracingController* GetTracingController() override {
    return platform_->GetTracingController();
  }

  void SetIsolate(v8::Isolate* isolate) { isolate_ = isolate; }
  void EnableDetachedModeForTesting() { is_in_detached_mode_ = true; }

 private:
  v8::Platform* platform_;
  cppgc::PageAllocator* page_allocator_;
  v8::Isolate* isolate_ = nullptr;
  bool is_in_detached_mode_ = false;
};

class UnifiedHeapConcurrentMarker
    : public cppgc::internal::ConcurrentMarkerBase {
 public:
  UnifiedHeapConcurrentMarker(
      cppgc::internal::HeapBase& heap, Heap* v8_heap,
      cppgc::internal::MarkingWorklists& marking_worklists,
      ::heap::base::IncrementalMarkingSchedule& incremental_marking_schedule,
      cppgc::Platform* platform,
      UnifiedHeapMarkingState& unified_heap_marking_state,
      CppHeap::CollectionType collection_type)
      : cppgc::internal::ConcurrentMarkerBase(
            heap, marking_worklists, incremental_marking_schedule, platform),
        v8_heap_(v8_heap),
        collection_type_(collection_type) {}

  std::unique_ptr<cppgc::Visitor> CreateConcurrentMarkingVisitor(
      cppgc::internal::ConcurrentMarkingState&) const final;

 private:
  Heap* const v8_heap_;
  CppHeap::CollectionType collection_type_;
};

std::unique_ptr<cppgc::Visitor>
UnifiedHeapConcurrentMarker::CreateConcurrentMarkingVisitor(
    cppgc::internal::ConcurrentMarkingState& marking_state) const {
  return std::make_unique<ConcurrentUnifiedHeapMarkingVisitor>(
      heap(), v8_heap_, marking_state, collection_type_);
}

void FatalOutOfMemoryHandlerImpl(const std::string& reason,
                                 const SourceLocation&, HeapBase* heap) {
  auto* cpp_heap = static_cast<v8::internal::CppHeap*>(heap);
  auto* isolate = cpp_heap->isolate();
  DCHECK_NOT_NULL(isolate);
  if (v8_flags.heap_snapshot_on_oom) {
    cppgc::internal::ClassNameAsHeapObjectNameScope names_scope(
        cpp_heap->AsBase());
    isolate->heap_profiler()->WriteSnapshotToDiskAfterGC(
        v8::HeapProfiler::HeapSnapshotMode::kExposeInternals);
  }
  V8::FatalProcessOutOfMemory(isolate, reason.c_str());
}

void GlobalFatalOutOfMemoryHandlerImpl(const std::string& reason,
                                       const SourceLocation&, HeapBase* heap) {
  V8::FatalProcessOutOfMemory(nullptr, reason.c_str());
}

class UnifiedHeapConservativeMarkingVisitor final
    : public cppgc::internal::ConservativeMarkingVisitor {
 public:
  UnifiedHeapConservativeMarkingVisitor(
      HeapBase& heap, MutatorMarkingState& mutator_marking_state,
      cppgc::Visitor& visitor)
      : ConservativeMarkingVisitor(heap, mutator_marking_state, visitor) {}
  ~UnifiedHeapConservativeMarkingVisitor() override = default;

  void SetConservativeTracedHandlesMarkingVisitor(
      std::unique_ptr<ConservativeTracedHandlesMarkingVisitor>
          global_handle_marking_visitor) {
    marking_visitor_ = std::move(global_handle_marking_visitor);
  }

  void TraceConservativelyIfNeeded(const void* address) override {
    ConservativeMarkingVisitor::TraceConservativelyIfNeeded(address);
    if (marking_visitor_) {
      marking_visitor_->VisitPointer(address);
    }
  }

 private:
  std::unique_ptr<ConservativeTracedHandlesMarkingVisitor> marking_visitor_;
};

}  // namespace

class UnifiedHeapMarker final : public cppgc::internal::MarkerBase {
 public:
  UnifiedHeapMarker(Heap* v8_heap, cppgc::internal::HeapBase& cpp_heap,
                    cppgc::Platform* platform,
                    cppgc::internal::MarkingConfig config);

  ~UnifiedHeapMarker() final = default;

  cppgc::internal::MarkingWorklists& GetMarkingWorklists() {
    return marking_worklists_;
  }

  cppgc::internal::MutatorMarkingState& GetMutatorMarkingState() {
    return static_cast<cppgc::internal::MutatorMarkingState&>(
        marking_visitor_->marking_state_);
  }

  UnifiedHeapMarkingState& GetMutatorUnifiedHeapMarkingState() {
    return mutator_unified_heap_marking_state_;
  }

  UnifiedHeapConservativeMarkingVisitor& conservative_visitor() final {
    return conservative_marking_visitor_;
  }

 protected:
  cppgc::Visitor& visitor() final { return *marking_visitor_; }
  ::heap::base::StackVisitor& stack_visitor() final {
    return conservative_marking_visitor_;
  }

 private:
  UnifiedHeapMarkingState mutator_unified_heap_marking_state_;
  std::unique_ptr<MutatorUnifiedHeapMarkingVisitor> marking_visitor_;
  UnifiedHeapConservativeMarkingVisitor conservative_marking_visitor_;
};

UnifiedHeapMarker::UnifiedHeapMarker(Heap* v8_heap,
                                     cppgc::internal::HeapBase& heap,
                                     cppgc::Platform* platform,
                                     cppgc::internal::MarkingConfig config)
    : cppgc::internal::MarkerBase(heap, platform, config),
      mutator_unified_heap_marking_state_(v8_heap, nullptr,
                                          config.collection_type),
      marking_visitor_(std::make_unique<MutatorUnifiedHeapMarkingVisitor>(
          heap, mutator_marking_state_, mutator_unified_heap_marking_state_)),
      conservative_marking_visitor_(heap, mutator_marking_state_,
                                    *marking_visitor_) {
  concurrent_marker_ = std::make_unique<UnifiedHeapConcurrentMarker>(
      heap_, v8_heap, marking_worklists_, *schedule_, platform_,
      mutator_unified_heap_marking_state_, config.collection_type);
}

void CppHeap::MetricRecorderAdapter::AddMainThreadEvent(
    const GCCycle& cppgc_event) {
  auto* tracer = GetIsolate()->heap()->tracer();
  if (cppgc_event.type == MetricRecorder::GCCycle::Type::kMinor) {
    DCHECK(!last_young_gc_event_);
    last_young_gc_event_ = cppgc_event;
    tracer->NotifyYoungCppGCCompleted();
  } else {
    DCHECK(!last_full_gc_event_);
    last_full_gc_event_ = cppgc_event;
    tracer->NotifyFullCppGCCompleted();
  }
}

void CppHeap::MetricRecorderAdapter::AddMainThreadEvent(
    const MainThreadIncrementalMark& cppgc_event) {
  // Incremental marking steps might be nested in V8 marking steps. In such
  // cases, stash the relevant values and delegate to V8 to report them. For
  // non-nested steps, report to the Recorder directly.
  if (cpp_heap_.is_in_v8_marking_step_) {
    last_incremental_mark_event_ = cppgc_event;
    return;
  }
  // This is a standalone incremental marking step.
  const std::shared_ptr<metrics::Recorder>& recorder =
      GetIsolate()->metrics_recorder();
  DCHECK_NOT_NULL(recorder);
  if (!recorder->HasEmbedderRecorder()) return;
  incremental_mark_batched_events_.events.emplace_back();
  incremental_mark_batched_events_.events.back().cpp_wall_clock_duration_in_us =
      cppgc_event.duration_us;
  if (incremental_mark_batched_events_.events.size() == kMaxBatchedEvents) {
    recorder->AddMainThreadEvent(std::move(incremental_mark_batched_events_),
                                 GetContextId());
    incremental_mark_batched_events_ = {};
  }
}

void CppHeap::MetricRecorderAdapter::AddMainThreadEvent(
    const MainThreadIncrementalSweep& cppgc_event) {
  // Incremental sweeping steps are never nested inside V8 sweeping steps, so
  // report to the Recorder directly.
  const std::shared_ptr<metrics::Recorder>& recorder =
      GetIsolate()->metrics_recorder();
  DCHECK_NOT_NULL(recorder);
  if (!recorder->HasEmbedderRecorder()) return;
  incremental_sweep_batched_events_.events.emplace_back();
  incremental_sweep_batched_events_.events.back()
      .cpp_wall_clock_duration_in_us = cppgc_event.duration_us;
  if (incremental_sweep_batched_events_.events.size() == kMaxBatchedEvents) {
    recorder->AddMainThreadEvent(std::move(incremental_sweep_batched_events_),
                                 GetContextId());
    incremental_sweep_batched_events_ = {};
  }
}

void CppHeap::MetricRecorderAdapter::FlushBatchedIncrementalEvents() {
  const std::shared_ptr<metrics::Recorder>& recorder =
      GetIsolate()->metrics_recorder();
  DCHECK_NOT_NULL(recorder);
  if (!incremental_mark_batched_events_.events.empty()) {
    recorder->AddMainThreadEvent(std::move(incremental_mark_batched_events_),
                                 GetContextId());
    incremental_mark_batched_events_ = {};
  }
  if (!incremental_sweep_batched_events_.events.empty()) {
    recorder->AddMainThreadEvent(std::move(incremental_sweep_batched_events_),
                                 GetContextId());
    incremental_sweep_batched_events_ = {};
  }
}

bool CppHeap::MetricRecorderAdapter::FullGCMetricsReportPending() const {
  return last_full_gc_event_.has_value();
}

bool CppHeap::MetricRecorderAdapter::YoungGCMetricsReportPending() const {
  return last_young_gc_event_.has_value();
}

const std::optional<cppgc::internal::MetricRecorder::GCCycle>
CppHeap::MetricRecorderAdapter::ExtractLastFullGcEvent() {
  auto res = std::move(last_full_gc_event_);
  last_full_gc_event_.reset();
  return res;
}

const std::optional<cppgc::internal::MetricRecorder::GCCycle>
CppHeap::MetricRecorderAdapter::ExtractLastYoungGcEvent() {
  auto res = std::move(last_young_gc_event_);
  last_young_gc_event_.reset();
  return res;
}

const std::optional<cppgc::internal::MetricRecorder::MainThreadIncrementalMark>
CppHeap::MetricRecorderAdapter::ExtractLastIncrementalMarkEvent() {
  auto res = std::move(last_incremental_mark_event_);
  last_incremental_mark_event_.reset();
  return res;
}

void CppHeap::MetricRecorderAdapter::ClearCachedEvents() {
  incremental_mark_batched_events_.events.clear();
  incremental_sweep_batched_events_.events.clear();
  last_incremental_mark_event_.reset();
  last_full_gc_event_.reset();
  last_young_gc_event_.reset();
}

Isolate* CppHeap::MetricRecorderAdapter::GetIsolate() const {
  DCHECK_NOT_NULL(cpp_heap_.isolate());
  return reinterpret_cast<Isolate*>(cpp_heap_.isolate());
}

v8::metrics::Recorder::ContextId CppHeap::MetricRecorderAdapter::GetContextId()
    const {
  DCHECK_NOT_NULL(GetIsolate());
  if (GetIsolate()->context().is_null())
    return v8::metrics::Recorder::ContextId::Empty();
  HandleScope scope(GetIsolate());
  return GetIsolate()->GetOrRegisterRecorderContextId(
      GetIsolate()->native_context());
}

// static
void CppHeap::InitializeOncePerProcess() {
  cppgc::internal::GetGlobalOOMHandler().SetCustomHandler(
      &GlobalFatalOutOfMemoryHandlerImpl);
}

CppHeap::CppHeap(
    v8::Platform* platform,
    const std::vector<std::unique_ptr<cppgc::CustomSpaceBase>>& custom_spaces,
    cppgc::Heap::MarkingType marking_support,
    cppgc::Heap::SweepingType sweeping_support)
    : cppgc::internal::HeapBase(
          std::make_shared<CppgcPlatformAdapter>(platform), custom_spaces,
          cppgc::internal::HeapBase::StackSupport::
              kSupportsConservativeStackScan,
          marking_support, sweeping_support, *this),
      minor_gc_heap_growing_(
          std::make_unique<MinorGCHeapGrowing>(*stats_collector())),
      cross_heap_remembered_set_(*this) {
  // Enter no GC scope. `AttachIsolate()` removes this and allows triggering
  // garbage collections.
  no_gc_scope_++;
  stats_collector()->RegisterObserver(this);
#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
  object_allocator().UpdateAllocationTimeout();
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT
}

CppHeap::~CppHeap() {
  if (isolate_) {
    isolate_->heap()->DetachCppHeap();
  }
}

void CppHeap::Terminate() {
  // Must not be attached to a heap when invoking termination GCs.
  CHECK(!isolate_);
  // Gracefully terminate the C++ heap invoking destructors.
  HeapBase::Terminate();
}

namespace {

class SweepingOnMutatorThreadForGlobalHandlesScope final {
 public:
  explicit SweepingOnMutatorThreadForGlobalHandlesScope(
      TracedHandles& traced_handles)
      : traced_handles_(traced_handles) {
    traced_handles_.SetIsSweepingOnMutatorThread(true);
  }
  ~SweepingOnMutatorThreadForGlobalHandlesScope() {
    traced_handles_.SetIsSweepingOnMutatorThread(false);
  }

  TracedHandles& traced_handles_;
};

class SweepingOnMutatorThreadForGlobalHandlesObserver final
    : public cppgc::internal::Sweeper::SweepingOnMutatorThreadObserver {
 public:
  SweepingOnMutatorThreadForGlobalHandlesObserver(CppHeap& cpp_heap,
                                                  TracedHandles& traced_handles)
      : cppgc::internal::Sweeper::SweepingOnMutatorThreadObserver(
            cpp_heap.sweeper()),
        traced_handles_(traced_handles) {}

  void Start() override { traced_handles_.SetIsSweepingOnMutatorThread(true); }

  void End() override { traced_handles_.SetIsSweepingOnMutatorThread(false); }

 private:
  TracedHandles& traced_handles_;
};

class MoveListenerImpl final : public HeapProfilerNativeMoveListener,
                               public cppgc::internal::MoveListener {
 public:
  MoveListenerImpl(HeapProfiler* profiler, CppHeap* heap)
      : HeapProfilerNativeMoveListener(profiler), heap_(heap) {}
  ~MoveListenerImpl() {
    if (active_) {
      heap_->UnregisterMoveListener(this);
    }
  }

  // HeapProfilerNativeMoveListener implementation:
  void StartListening() override {
    if (active_) return;
    active_ = true;
    heap_->RegisterMoveListener(this);
  }
  void StopListening() override {
    if (!active_) return;
    active_ = false;
    heap_->UnregisterMoveListener(this);
  }

  // cppgc::internal::MoveListener implementation:
  void OnMove(uint8_t* from, uint8_t* to,
              size_t size_including_header) override {
    ObjectMoveEvent(reinterpret_cast<Address>(from),
                    reinterpret_cast<Address>(to),
                    static_cast<int>(size_including_header));
  }

 private:
  CppHeap* heap_;
  bool active_ = false;
};

}  // namespace

void CppHeap::AttachIsolate(Isolate* isolate) {
  CHECK(!in_detached_testing_mode_);
  CHECK_NULL(isolate_);
  isolate_ = isolate;
  heap_ = isolate->heap();
  static_cast<CppgcPlatformAdapter*>(platform())
      ->SetIsolate(reinterpret_cast<v8::Isolate*>(isolate_));
  if (auto* heap_profiler = isolate_->heap_profiler()) {
    heap_profiler->AddBuildEmbedderGraphCallback(&CppGraphBuilder::Run, this);
    heap_profiler->set_native_move_listener(
        std::make_unique<MoveListenerImpl>(heap_profiler, this));
  }
  SetMetricRecorder(std::make_unique<MetricRecorderAdapter>(*this));
  oom_handler().SetCustomHandler(&FatalOutOfMemoryHandlerImpl);
  UpdateGCCapabilitiesFromFlags();
  sweeping_on_mutator_thread_observer_ =
      std::make_unique<SweepingOnMutatorThreadForGlobalHandlesObserver>(
          *this, *isolate_->traced_handles());
  no_gc_scope_--;

  // Propagate overridden stack state to the attached heap, if necessary.
  // TODO(b/326503098): This should not be required, to be removed when the
  // issue is resolved.
  CHECK(!override_stack_state_scope_);
  if (detached_override_stack_state_) {
    override_stack_state_scope_ = std::make_unique<EmbedderStackStateScope>(
        heap_, EmbedderStackStateOrigin::kExplicitInvocation,
        detached_override_stack_state_.value());
    detached_override_stack_state_.reset();
  }
}

void CppHeap::DetachIsolate() {
  // TODO(chromium:1056170): Investigate whether this can be enforced with a
  // CHECK across all relevant embedders and setups.
  if (!isolate_) return;

  // Finish any ongoing garbage collection.
  if (isolate_->heap()->incremental_marking()->IsMarking()) {
    isolate_->heap()->FinalizeIncrementalMarkingAtomically(
        i::GarbageCollectionReason::kExternalFinalize);
  }
  sweeper_.FinishIfRunning();

  sweeping_on_mutator_thread_observer_.reset();

  if (auto* heap_profiler = isolate_->heap_profiler()) {
    heap_profiler->RemoveBuildEmbedderGraphCallback(&CppGraphBuilder::Run,
                                                    this);
    heap_profiler->set_native_move_listener(nullptr);
  }
  SetMetricRecorder(nullptr);

  // Propagate overridden stack state from the attached heap, if necessary.
  // TODO(b/326503098): This should not be required, to be removed when the
  // issue is resolved.
  CHECK(!detached_override_stack_state_);
  if (override_stack_state_scope_) {
    detached_override_stack_state_ = heap_->overridden_stack_state();
    override_stack_state_scope_.reset();
  }

  isolate_ = nullptr;
  heap_ = nullptr;
  // Any future garbage collections will ignore the V8->C++ references.
  oom_handler().SetCustomHandler(nullptr);
  // Enter no GC scope.
  no_gc_scope_++;
}

::heap::base::Stack* CppHeap::stack() {
  return isolate_ ? &isolate_->heap()->stack() : HeapBase::stack();
}

namespace {

bool IsMemoryReducingGC(CppHeap::GarbageCollectionFlags flags) {
  return flags & CppHeap::GarbageCollectionFlagValues::kReduceMemory;
}

bool IsForceGC(CppHeap::GarbageCollectionFlags flags) {
  return flags & CppHeap::GarbageCollectionFlagValues::kForced;
}

bool ShouldReduceMemory(CppHeap::GarbageCollectionFlags flags) {
  return IsMemoryReducingGC(flags) || IsForceGC(flags);
}

constexpr size_t kIncrementalMarkingCheckInterval = 128 * KB;

}  // namespace

CppHeap::MarkingType CppHeap::SelectMarkingType() const {
  // For now, force atomic marking for minor collections.
  if (*collection_type_ == CollectionType::kMinor) return MarkingType::kAtomic;

  if (IsForceGC(current_gc_flags_) && !force_incremental_marking_for_testing_)
    return MarkingType::kAtomic;

  const MarkingType marking_type = marking_support();

  // CollectionType is major at this point. Check the surrounding
  // MarkCompactCollector for whether we should rely on background threads in
  // this GC cycle.
  if (marking_type == MarkingType::kIncrementalAndConcurrent && heap_ &&
      !heap_->mark_compact_collector()->UseBackgroundThreadsInCycle()) {
    return MarkingType::kIncremental;
  }

  return marking_support();
}

CppHeap::SweepingType CppHeap::SelectSweepingType() const {
  if (IsForceGC(current_gc_flags_)) return SweepingType::kAtomic;

  return sweeping_support();
}

void CppHeap::UpdateGCCapabilitiesFromFlags() {
  CHECK_IMPLIES(v8_flags.cppheap_concurrent_marking,
                v8_flags.cppheap_incremental_marking);
  if (v8_flags.cppheap_concurrent_marking) {
    marking_support_ = static_cast<MarkingType>(
        std::min(marking_support_, MarkingType::kIncrementalAndConcurrent));
  } else if (v8_flags.cppheap_incremental_marking) {
    marking_support_ = static_cast<MarkingType>(
        std::min(marking_support_, MarkingType::kIncremental));
  } else {
    marking_support_ = MarkingType::kAtomic;
  }

  sweeping_support_ = v8_flags.single_threaded_gc
                          ? CppHeap::SweepingType::kIncremental
                          : CppHeap::SweepingType::kIncrementalAndConcurrent;

  page_backend_->page_pool().SetDecommitPooledPages(
      v8_flags.decommit_pooled_pages);
}

void CppHeap::InitializeMarking(CollectionType collection_type,
                                GarbageCollectionFlags gc_flags) {
  DCHECK(!collection_type_);

  if (collection_type == CollectionType::kMinor) {
    if (!generational_gc_supported()) return;
    // Notify GC tracer that CppGC started young GC cycle.
    isolate_->heap()->tracer()->NotifyYoungCppGCRunning();
  }

  collection_type_ = collection_type;

  CHECK(!sweeper_.IsSweepingInProgress());

  // Check that previous cycle metrics for the same collection type have been
  // reported.
  if (GetMetricRecorder()) {
    if (collection_type == CollectionType::kMajor)
      DCHECK(!GetMetricRecorder()->FullGCMetricsReportPending());
    else
      DCHECK(!GetMetricRecorder()->YoungGCMetricsReportPending());
  }

#if defined(CPPGC_YOUNG_GENERATION)
  if (generational_gc_supported() &&
      *collection_type_ == CollectionType::kMajor) {
    stats_collector()->NotifyUnmarkingStarted(*collection_type_);
    cppgc::internal::StatsCollector::EnabledScope stats_scope(
        stats_collector(), cppgc::internal::StatsCollector::kUnmark);
    cppgc::internal::SequentialUnmarker unmarker(raw_heap());
  }
#endif  // defined(CPPGC_YOUNG_GENERATION)

  if (gc_flags == GarbageCollectionFlagValues::kNoFlags) {
    if (heap()->is_current_gc_forced()) {
      gc_flags |= CppHeap::GarbageCollectionFlagValues::kForced;
    }
    if (heap()->ShouldReduceMemory()) {
      gc_flags |= CppHeap::GarbageCollectionFlagValues::kReduceMemory;
    }
  }
  current_gc_flags_ = gc_flags;

  const cppgc::internal::MarkingConfig marking_config{
      *collection_type_,
      StackState::kNoHeapPointers,
      SelectMarkingType(),
      IsForceGC(current_gc_flags_)
          ? cppgc::internal::MarkingConfig::IsForcedGC::kForced
          : cppgc::internal::MarkingConfig::IsForcedGC::kNotForced,
      v8_flags.incremental_marking_bailout_when_ahead_of_schedule};
  DCHECK_IMPLIES(!isolate_,
                 (MarkingType::kAtomic == marking_config.marking_type) ||
                     force_incremental_marking_for_testing_);
  if (ShouldReduceMemory(current_gc_flags_)) {
    // Only enable compaction when in a memory reduction garbage collection as
    // it may significantly increase the final garbage collection pause.
    compactor_.InitializeIfShouldCompact(marking_config.marking_type,
                                         marking_config.stack_state);
  }
  marker_ = std::make_unique<UnifiedHeapMarker>(
      isolate_ ? isolate()->heap() : nullptr, AsBase(), platform_.get(),
      marking_config);
}

namespace {
MarkingWorklists::Local* GetV8MarkingWorklists(
    Isolate* isolate, cppgc::internal::CollectionType collection_type) {
  auto* heap = isolate->heap();
  if (collection_type == cppgc::internal::CollectionType::kMajor) {
    return heap->mark_compact_collector()->local_marking_worklists();
  } else {
    return heap->minor_mark_sweep_collector()->local_marking_worklists();
  }
}
}  // namespace

void CppHeap::StartMarking() {
  CHECK(marking_done_);
  if (!TracingInitialized()) return;
  if (isolate_) {
    // Reuse the same local worklist for the mutator marking state which results
    // in directly processing the objects by the JS logic. Also avoids
    // publishing local objects.
    marker_->To<UnifiedHeapMarker>().GetMutatorUnifiedHeapMarkingState().Update(
        GetV8MarkingWorklists(isolate_, *collection_type_));
  }
  marker_->StartMarking();
  marking_done_ = false;
}

bool CppHeap::AdvanceTracing(v8::base::TimeDelta max_duration) {
  if (!TracingInitialized()) return true;
  is_in_v8_marking_step_ = true;
  cppgc::internal::StatsCollector::EnabledScope stats_scope(
      stats_collector(),
      in_atomic_pause_ ? cppgc::internal::StatsCollector::kAtomicMark
                       : cppgc::internal::StatsCollector::kIncrementalMark);
  const v8::base::TimeDelta deadline =
      in_atomic_pause_ ? v8::base::TimeDelta::Max() : max_duration;
  const size_t marked_bytes_limit = in_atomic_pause_ ? SIZE_MAX : 0;
  DCHECK_NOT_NULL(marker_);
  if (in_atomic_pause_) {
    marker_->NotifyConcurrentMarkingOfWorkIfNeeded(
        cppgc::TaskPriority::kUserBlocking);
  }
  // TODO(chromium:1056170): Replace when unified heap transitions to
  // bytes-based deadline.
  marking_done_ =
      marker_->AdvanceMarkingWithLimits(deadline, marked_bytes_limit);
  DCHECK_IMPLIES(in_atomic_pause_, marking_done_);
  is_in_v8_marking_step_ = false;
  return marking_done_;
}

bool CppHeap::IsTracingDone() const {
  return !TracingInitialized() || marking_done_;
}

bool CppHeap::ShouldFinalizeIncrementalMarking() const {
  return !incremental_marking_supported() || IsTracingDone();
}

void CppHeap::EnterProcessGlobalAtomicPause() {
  if (!TracingInitialized()) {
    return;
  }
  DCHECK(in_atomic_pause_);
  marker_->To<UnifiedHeapMarker>().EnterProcessGlobalAtomicPause();
}

void CppHeap::EnterFinalPause(cppgc::EmbedderStackState stack_state) {
  CHECK(!IsGCForbidden());
  // Enter atomic pause even if tracing is not initialized. This is needed to
  // make sure that we always enable young generation from the atomic pause.
  in_atomic_pause_ = true;
  if (!TracingInitialized()) return;
  auto& marker = marker_->To<UnifiedHeapMarker>();
  // Scan global handles conservatively in case we are attached to an Isolate.
  // TODO(1029379): Support global handle marking visitors with minor GC.
  if (isolate_) {
    auto& heap = *isolate()->heap();
    marker.conservative_visitor().SetConservativeTracedHandlesMarkingVisitor(
        std::make_unique<ConservativeTracedHandlesMarkingVisitor>(
            heap, *GetV8MarkingWorklists(isolate_, *collection_type_),
            *collection_type_));
  }
  marker.EnterAtomicPause(stack_state);
  compactor_.CancelIfShouldNotCompact(MarkingType::kAtomic, stack_state);
}

bool CppHeap::FinishConcurrentMarkingIfNeeded() {
  if (!TracingInitialized()) return true;
  return marker_->JoinConcurrentMarkingIfNeeded();
}

void CppHeap::ReEnableConcurrentMarking() {
  CHECK(!in_atomic_pause_);
  marker_->ReEnableConcurrentMarking();
}

void CppHeap::WriteBarrier(void* object) {
  isolate()
      ->heap()
      ->mark_compact_collector()
      ->local_marking_worklists()
      ->cpp_marking_state()
      ->MarkAndPush(object);
}

namespace {

void RecordEmbedderMarkingSpeed(GCTracer* tracer, base::TimeDelta marking_time,
                                size_t marked_bytes) {
  tracer->RecordEmbedderMarkingSpeed(marked_bytes, marking_time);
}

}  // namespace

void CppHeap::FinishMarkingAndProcessWeakness() {
  CHECK(in_atomic_pause_);
  CHECK(marking_done_);

#if defined(CPPGC_YOUNG_GENERATION)
  // Check if the young generation was enabled via flag. We must enable young
  // generation before calling the custom weak callbacks to make sure that the
  // callbacks for old objects are registered in the remembered set.
  if (v8_flags.cppgc_young_generation) {
    EnableGenerationalGC();
  }
#endif  // defined(CPPGC_YOUNG_GENERATION)

  if (!TracingInitialized()) {
    in_atomic_pause_ = false;
    return;
  }

  {
    cppgc::subtle::DisallowGarbageCollectionScope disallow_gc_scope(*this);
    marker_->LeaveAtomicPause();
  }
  marker_.reset();

  if (isolate_) {
    // The size is used for recomputing the global heap limit.
    used_size_ = stats_collector_->marked_bytes();
    // Force a check next time
```