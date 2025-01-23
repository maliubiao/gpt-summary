Response:
Let's break down the thought process for analyzing this V8 C++ source code.

1. **Initial Scan and Purpose Identification:**

   - The file name `concurrent-marking.cc` immediately suggests its primary function: handling concurrent marking in V8's garbage collection.
   - The copyright notice and include statements confirm it's a V8 source file and reveal dependencies on core V8 components like `heap`, `objects`, `execution`, and `flags`. This hints at the code's involvement in memory management and interaction with V8's execution environment.

2. **High-Level Structure Recognition:**

   - The code defines classes like `ConcurrentMarkingVisitor`, `ConcurrentMarking`, `JobTaskMajor`, and `JobTaskMinor`. This points to an object-oriented design, where different classes handle specific aspects of concurrent marking.
   - The presence of `JobTaskMajor` and `JobTaskMinor` suggests the use of V8's job scheduling mechanism for offloading marking work to background threads.

3. **Key Class Analysis - `ConcurrentMarkingVisitor`:**

   - The inheritance from `FullMarkingVisitorBase` clearly indicates this class is responsible for traversing the object graph and marking live objects.
   - The constructor takes various parameters related to marking, including worklists, weak objects, heap information, and crucially, `MemoryChunkDataMap`.
   - The `ProcessEphemeron` method is a telltale sign of handling weak references (ephemerons) during marking.
   - `RecordSlot` and `RecordRelocSlot` are standard components of a marking visitor, responsible for tracking object references.
   - `IncrementLiveBytesCached` suggests the visitor is involved in calculating live object sizes within memory chunks.

4. **Key Class Analysis - `ConcurrentMarking`:**

   - This appears to be the central orchestrator of concurrent marking.
   - It holds references to the `Heap` and `WeakObjects`.
   - The `RunMajor` and `RunMinor` methods are likely the entry points for the main and minor GC concurrent marking tasks, respectively.
   - The `TryScheduleJob`, `RescheduleJobIfNeeded`, `Join`, `Pause`, and `Resume` methods point to the lifecycle management and control of the concurrent marking process.
   - The `task_state_` member, a vector of `TaskState`, hints at the parallel nature of the operation, where multiple tasks contribute to the marking process.
   - The methods related to concurrency (`GetMajorMaxConcurrency`, `GetMinorMaxConcurrency`) further emphasize the parallel execution.
   - `FlushPretenuringFeedback`, `FlushNativeContexts`, `FlushMemoryChunkData`, and `ClearMemoryChunkData` indicate the handling of auxiliary data associated with marking.

5. **Key Class Analysis - `JobTaskMajor` and `JobTaskMinor`:**

   - These classes inherit from `v8::JobTask`, confirming their role in V8's job scheduling system.
   - Their `Run` methods delegate to `ConcurrentMarking::RunMajor` and `ConcurrentMarking::RunMinor`, respectively.
   - The constructors take a `ConcurrentMarking` pointer, linking them to the main orchestrator.

6. **Workflow Understanding (Deduction from Methods):**

   - Concurrent marking is likely initiated by calling `TryScheduleJob`.
   - This creates either a `JobTaskMajor` for full GC or `JobTaskMinor` for minor GC.
   - These job tasks are scheduled to run on background threads.
   - The `RunMajor` and `RunMinor` methods in `ConcurrentMarking` then use `ConcurrentMarkingVisitor` to traverse the heap and mark objects.
   - Worklists are used to manage the objects to be visited.
   - The process can be paused and resumed using `Pause` and `Resume`.
   - After completion, `Join` is likely called to wait for the background tasks to finish.
   - Data collected during concurrent marking (like pretenuring feedback and native context stats) is then flushed.

7. **Relation to JavaScript (Conceptual):**

   - Concurrent marking is a low-level optimization that improves JavaScript performance by reducing GC pauses. JavaScript developers don't directly interact with these APIs.
   -  Think of it like this: when your JavaScript code creates objects, the V8 engine's garbage collector needs to periodically clean up objects that are no longer in use. Concurrent marking allows this cleanup process to happen in the background, minimizing interruptions to your JavaScript code's execution.

8. **Code Logic Inference (Simple Examples):**

   - The `ProcessEphemeron` method's logic is relatively straightforward: if the key is marked, mark the value. Otherwise, add the ephemeron to a list for later processing.
   - The worklist popping and visiting loop in `RunMajor` follows a common pattern in garbage collectors.

9. **Common User Programming Errors (Indirect):**

   - While JavaScript developers don't directly interact with this code, understanding its purpose helps in understanding the *consequences* of certain programming practices:
     - **Creating excessive temporary objects:**  This puts more pressure on the garbage collector, and while concurrent marking helps, it doesn't eliminate the overhead entirely.
     - **Memory leaks (unintentional object retention):**  Concurrent marking can't collect objects that are still reachable, even if they're no longer needed.

10. **Torque Check:**

    - The prompt specifically asks about `.tq` files. A quick check of the file extension confirms it's `.cc`, so it's C++ and not Torque.

11. **Refinement and Structuring:**

    - After the initial analysis, the information needs to be organized logically. This involves grouping related functionalities, explaining the purpose of each class and method, and providing illustrative examples (even if the direct interaction with JavaScript is limited). The thought process involves structuring the answer to address all parts of the prompt.

By following these steps, one can effectively analyze and understand the functionality of a complex C++ source file like `concurrent-marking.cc`. The process involves a combination of code reading, understanding V8's architecture, and logical deduction.
`v8/src/heap/concurrent-marking.cc` 是 V8 引擎中负责**并发标记**的源代码文件。并发标记是垃圾回收（Garbage Collection, GC）过程中的一个重要阶段，旨在在主 JavaScript 线程运行的同时，并行地标记出不再使用的对象，从而减少 GC 造成的停顿时间，提升 JavaScript 应用的性能。

以下是 `concurrent-marking.cc` 的主要功能：

1. **启动和管理并发标记任务:**  该文件中的代码负责启动、调度和管理在后台线程中运行的并发标记任务。这包括创建和管理 `JobTaskMajor` (用于 Major GC，即 Full GC) 和 `JobTaskMinor` (用于 Minor GC，即 Young Generation GC) 类型的任务。

2. **实现并发标记算法的核心逻辑:**  `ConcurrentMarkingVisitor` 类是并发标记的核心，它继承自 `FullMarkingVisitorBase` 或 `YoungGenerationMarkingVisitor`。这个访问器负责遍历堆中的对象图，并根据标记状态标记出可达对象。

3. **处理跨代引用 (Remembered Sets):** 对于 Minor GC，并发标记需要处理老年代对象指向新生代对象的引用，这些引用存储在 Remembered Sets 中。代码会处理这些 Remembered Sets，确保新生代中的可达对象被正确标记。

4. **处理弱引用 (Weak Objects):**  并发标记需要特别处理弱引用，例如 `WeakMap` 和 `WeakSet` 中的键值对。`ProcessEphemeron` 方法用于处理 Ephemeron 类型的弱引用，只有当键被标记时，值才会被标记。

5. **管理标记工作列表 (Marking Worklists):** 代码使用 `MarkingWorklists` 来管理待标记的对象。并发标记任务会从工作列表中取出对象进行标记。

6. **跟踪和统计标记信息:**  `TaskState` 结构体用于存储每个并发标记任务的状态，包括已标记的字节数、内存块数据等。这有助于监控和分析并发标记的进度和效果。

7. **与主线程同步:**  虽然标记工作在后台线程进行，但需要与主 JavaScript 线程进行同步，例如在扫描根对象、处理Remembered Sets 的过程中。

8. **处理预分配 (Pretenuring) 反馈:**  并发标记过程中收集的信息可以用于指导预分配策略，以减少未来 GC 的压力。

9. **与垃圾回收器的其他组件交互:**  并发标记需要与 V8 垃圾回收器的其他组件（如 Mark-Compact 收集器、Minor Mark-Sweep 收集器）进行交互，例如获取需要标记的对象、更新对象状态等。

**关于文件扩展名 `.tq`：**

`v8/src/heap/concurrent-marking.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++** 源代码文件，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系 (通过 GC 影响性能):**

`concurrent-marking.cc` 的功能直接影响 JavaScript 的性能，因为它优化了垃圾回收过程。JavaScript 是一种具有自动垃圾回收机制的语言，开发者无需手动管理内存。当 JavaScript 代码创建大量对象或对象之间存在复杂的引用关系时，垃圾回收的效率至关重要。

并发标记通过在后台线程执行标记任务，减少了主 JavaScript 线程的阻塞时间。这意味着在进行垃圾回收时，JavaScript 代码的执行停顿会更短，从而提供更流畅的用户体验。

**JavaScript 示例 (间接影响):**

虽然 JavaScript 代码不直接调用 `concurrent-marking.cc` 中的函数，但其行为会受到并发标记的影响。例如，考虑以下 JavaScript 代码：

```javascript
let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push({ data: i });
}

// ... 一段时间后，不再使用 largeArray ...

// 触发垃圾回收 (实际触发时机由 V8 决定)
```

在没有并发标记的情况下，当 V8 执行垃圾回收时，主线程可能会被阻塞较长时间，导致页面卡顿。有了并发标记，标记过程可以在后台进行，减少主线程的停顿，使得即使在处理 `largeArray` 这样的较大对象时，JavaScript 应用也能保持相对的响应性。

**代码逻辑推理 (假设输入与输出):**

假设输入：

* **一个待标记的对象 `object`:**  这个对象是堆中的一个 `HeapObject` 实例。
* **当前的标记状态:**  指示哪些对象已经被标记为可达。
* **并发标记工作列表 `marking_worklists_`:**  包含待标记的对象的队列。

输出：

* **如果 `object` 是可达的，则其标记状态会被更新为已标记。**
* **`object` 引用的其他对象会被添加到并发标记工作列表 `marking_worklists_` 中，以便后续标记。**
* **与 `object` 相关的元数据（例如，所在的内存块信息）可能会被更新。**

例如，在 `ConcurrentMarkingVisitor::Visit` 方法中，如果传入一个未标记的对象，该方法会：

1. 将该对象标记为已标记。
2. 遍历该对象的槽 (slots)，找到它引用的其他对象。
3. 将这些被引用的对象添加到并发标记工作列表，以便在后续的并发标记任务中被处理。

**用户常见的编程错误 (间接相关):**

虽然开发者不直接操作并发标记，但某些编程错误会增加 GC 的压力，从而间接地影响并发标记的效果：

1. **内存泄漏:**  创建对象后没有释放对它们的引用，导致垃圾回收器无法回收这些不再使用的对象，增加了并发标记的工作量。

   ```javascript
   // 错误示例：忘记解除事件监听器，导致闭包持有对象引用
   function createEventListener() {
     let largeData = { /* ... large object ... */ };
     document.getElementById('myButton').addEventListener('click', function() {
       console.log(largeData); // 闭包持有 largeData 的引用
     });
   }

   createEventListener(); // 即使按钮不再使用，largeData 也不会被回收
   ```

2. **创建大量临时对象:**  在循环或其他操作中创建大量的临时对象，虽然这些对象很快就会变得不可达，但仍然会给垃圾回收器带来压力，包括并发标记。

   ```javascript
   // 错误示例：在循环中创建大量字符串
   function processData(data) {
     let result = "";
     for (let item of data) {
       result += item.toString(); // 每次循环都创建一个新的字符串
     }
     return result;
   }
   ```

3. **过度使用闭包:**  不当使用闭包可能导致意外的对象引用，阻止垃圾回收器回收不再需要的对象。

理解 `concurrent-marking.cc` 的功能有助于开发者意识到优化 JavaScript 代码、减少不必要的对象创建和内存泄漏的重要性，从而充分利用 V8 引擎的垃圾回收机制，包括并发标记带来的性能提升。

### 提示词
```
这是目录为v8/src/heap/concurrent-marking.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/concurrent-marking.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/concurrent-marking.h"

#include <algorithm>
#include <atomic>
#include <stack>
#include <unordered_map>

#include "include/v8config.h"
#include "src/base/logging.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/heap/base/cached-unordered-map.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-utils-inl.h"
#include "src/heap/heap-visitor-inl.h"
#include "src/heap/heap-visitor.h"
#include "src/heap/heap.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking-visitor-inl.h"
#include "src/heap/marking-visitor.h"
#include "src/heap/marking.h"
#include "src/heap/memory-chunk-metadata.h"
#include "src/heap/memory-chunk.h"
#include "src/heap/memory-measurement-inl.h"
#include "src/heap/memory-measurement.h"
#include "src/heap/minor-mark-sweep-inl.h"
#include "src/heap/minor-mark-sweep.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/object-lock.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/weak-object-worklists.h"
#include "src/heap/young-generation-marking-visitor.h"
#include "src/init/v8.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/heap-object.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/slots-inl.h"
#include "src/objects/transitions-inl.h"
#include "src/utils/utils-inl.h"

namespace v8 {
namespace internal {

struct MemoryChunkData final {
  intptr_t live_bytes = 0;
  std::unique_ptr<TypedSlots> typed_slots;
};

using MemoryChunkDataMap =
    ::heap::base::CachedUnorderedMap<MutablePageMetadata*, MemoryChunkData>;

class ConcurrentMarkingVisitor final
    : public FullMarkingVisitorBase<ConcurrentMarkingVisitor> {
 public:
  ConcurrentMarkingVisitor(MarkingWorklists::Local* local_marking_worklists,
                           WeakObjects::Local* local_weak_objects, Heap* heap,
                           unsigned mark_compact_epoch,
                           base::EnumSet<CodeFlushMode> code_flush_mode,
                           bool should_keep_ages_unchanged,
                           uint16_t code_flushing_increase,
                           MemoryChunkDataMap* memory_chunk_data)
      : FullMarkingVisitorBase(local_marking_worklists, local_weak_objects,
                               heap, mark_compact_epoch, code_flush_mode,
                               should_keep_ages_unchanged,
                               code_flushing_increase),
        memory_chunk_data_(memory_chunk_data) {}

  using FullMarkingVisitorBase<
      ConcurrentMarkingVisitor>::VisitMapPointerIfNeeded;

  static constexpr bool EnableConcurrentVisitation() { return true; }

  // Implements ephemeron semantics: Marks value if key is already reachable.
  // Returns true if value was actually marked.
  bool ProcessEphemeron(Tagged<HeapObject> key, Tagged<HeapObject> value) {
    if (marking_state()->IsMarked(key)) {
      const auto target_worklist =
          MarkingHelper::ShouldMarkObject(heap_, value);
      DCHECK(target_worklist.has_value());
      if (MarkObject(key, value, target_worklist.value())) {
        return true;
      }
    } else if (marking_state()->IsUnmarked(value)) {
      local_weak_objects_->next_ephemerons_local.Push(Ephemeron{key, value});
    }
    return false;
  }

  template <typename TSlot>
  void RecordSlot(Tagged<HeapObject> object, TSlot slot,
                  Tagged<HeapObject> target) {
    MarkCompactCollector::RecordSlot(object, slot, target);
  }

  void IncrementLiveBytesCached(MutablePageMetadata* chunk, intptr_t by) {
    DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                   IsAligned(by, kObjectAlignment8GbHeap));
    (*memory_chunk_data_)[chunk].live_bytes += by;
  }

 private:
  void RecordRelocSlot(Tagged<InstructionStream> host, RelocInfo* rinfo,
                       Tagged<HeapObject> target) {
    if (!MarkCompactCollector::ShouldRecordRelocSlot(host, rinfo, target)) {
      return;
    }

    MarkCompactCollector::RecordRelocSlotInfo info =
        MarkCompactCollector::ProcessRelocInfo(host, rinfo, target);

    MemoryChunkData& data = (*memory_chunk_data_)[info.page_metadata];
    if (!data.typed_slots) {
      data.typed_slots.reset(new TypedSlots());
    }
    data.typed_slots->Insert(info.slot_type, info.offset);
  }

  MemoryChunkDataMap* memory_chunk_data_;

  friend class MarkingVisitorBase<ConcurrentMarkingVisitor>;
};

struct ConcurrentMarking::TaskState {
  size_t marked_bytes = 0;
  MemoryChunkDataMap memory_chunk_data;
  NativeContextStats native_context_stats;
  PretenuringHandler::PretenuringFeedbackMap local_pretenuring_feedback{
      PretenuringHandler::kInitialFeedbackCapacity};
};

class ConcurrentMarking::JobTaskMajor : public v8::JobTask {
 public:
  JobTaskMajor(ConcurrentMarking* concurrent_marking,
               unsigned mark_compact_epoch,
               base::EnumSet<CodeFlushMode> code_flush_mode,
               bool should_keep_ages_unchanged)
      : concurrent_marking_(concurrent_marking),
        mark_compact_epoch_(mark_compact_epoch),
        code_flush_mode_(code_flush_mode),
        should_keep_ages_unchanged_(should_keep_ages_unchanged),
        trace_id_(reinterpret_cast<uint64_t>(concurrent_marking) ^
                  concurrent_marking->heap_->tracer()->CurrentEpoch(
                      GCTracer::Scope::MC_BACKGROUND_MARKING)) {}

  ~JobTaskMajor() override = default;
  JobTaskMajor(const JobTaskMajor&) = delete;
  JobTaskMajor& operator=(const JobTaskMajor&) = delete;

  // v8::JobTask overrides.
  void Run(JobDelegate* delegate) override {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        concurrent_marking_->heap_->isolate());

    if (delegate->IsJoiningThread()) {
      // TRACE_GC is not needed here because the caller opens the right scope.
      concurrent_marking_->RunMajor(delegate, code_flush_mode_,
                                    mark_compact_epoch_,
                                    should_keep_ages_unchanged_);
    } else {
      TRACE_GC_EPOCH_WITH_FLOW(concurrent_marking_->heap_->tracer(),
                               GCTracer::Scope::MC_BACKGROUND_MARKING,
                               ThreadKind::kBackground, trace_id_,
                               TRACE_EVENT_FLAG_FLOW_IN);
      concurrent_marking_->RunMajor(delegate, code_flush_mode_,
                                    mark_compact_epoch_,
                                    should_keep_ages_unchanged_);
    }
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    return concurrent_marking_->GetMajorMaxConcurrency(worker_count);
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  ConcurrentMarking* concurrent_marking_;
  const unsigned mark_compact_epoch_;
  base::EnumSet<CodeFlushMode> code_flush_mode_;
  const bool should_keep_ages_unchanged_;
  const uint64_t trace_id_;
};

class ConcurrentMarking::JobTaskMinor : public v8::JobTask {
 public:
  explicit JobTaskMinor(ConcurrentMarking* concurrent_marking)
      : concurrent_marking_(concurrent_marking),
        trace_id_(reinterpret_cast<uint64_t>(concurrent_marking) ^
                  concurrent_marking->heap_->tracer()->CurrentEpoch(
                      GCTracer::Scope::MINOR_MS_MARK_PARALLEL)) {}

  ~JobTaskMinor() override = default;
  JobTaskMinor(const JobTaskMinor&) = delete;
  JobTaskMinor& operator=(const JobTaskMinor&) = delete;

  // v8::JobTask overrides.
  void Run(JobDelegate* delegate) override {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        concurrent_marking_->heap_->isolate());

    if (delegate->IsJoiningThread()) {
      TRACE_GC_WITH_FLOW(concurrent_marking_->heap_->tracer(),
                         GCTracer::Scope::MINOR_MS_MARK_PARALLEL, trace_id_,
                         TRACE_EVENT_FLAG_FLOW_IN);
      // TRACE_GC is not needed here because the caller opens the right scope.
      concurrent_marking_->RunMinor(delegate);
    } else {
      TRACE_GC_EPOCH_WITH_FLOW(concurrent_marking_->heap_->tracer(),
                               GCTracer::Scope::MINOR_MS_BACKGROUND_MARKING,
                               ThreadKind::kBackground, trace_id_,
                               TRACE_EVENT_FLAG_FLOW_IN);
      concurrent_marking_->RunMinor(delegate);
    }
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    return concurrent_marking_->GetMinorMaxConcurrency(worker_count);
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  ConcurrentMarking* concurrent_marking_;
  const uint64_t trace_id_;
};

ConcurrentMarking::ConcurrentMarking(Heap* heap, WeakObjects* weak_objects)
    : heap_(heap), weak_objects_(weak_objects) {
#ifndef V8_ATOMIC_OBJECT_FIELD_WRITES
  // Concurrent marking requires atomic object field writes.
  CHECK(!v8_flags.concurrent_marking);
#endif
  int max_tasks;
  if (v8_flags.concurrent_marking_max_worker_num == 0) {
    max_tasks = V8::GetCurrentPlatform()->NumberOfWorkerThreads();
  } else {
    max_tasks = v8_flags.concurrent_marking_max_worker_num;
  }

  task_state_.reserve(max_tasks + 1);
  for (int i = 0; i <= max_tasks; ++i) {
    task_state_.emplace_back(std::make_unique<TaskState>());
  }
}

ConcurrentMarking::~ConcurrentMarking() = default;

void ConcurrentMarking::RunMajor(JobDelegate* delegate,
                                 base::EnumSet<CodeFlushMode> code_flush_mode,
                                 unsigned mark_compact_epoch,
                                 bool should_keep_ages_unchanged) {
  size_t kBytesUntilInterruptCheck = 64 * KB;
  int kObjectsUntilInterruptCheck = 1000;
  uint8_t task_id = delegate->GetTaskId() + 1;
  TaskState* task_state = task_state_[task_id].get();
  auto* cpp_heap = CppHeap::From(heap_->cpp_heap());
  MarkingWorklists::Local local_marking_worklists(
      marking_worklists_, cpp_heap
                              ? cpp_heap->CreateCppMarkingState()
                              : MarkingWorklists::Local::kNoCppMarkingState);
  WeakObjects::Local local_weak_objects(weak_objects_);
  ConcurrentMarkingVisitor visitor(
      &local_marking_worklists, &local_weak_objects, heap_, mark_compact_epoch,
      code_flush_mode, should_keep_ages_unchanged,
      heap_->tracer()->CodeFlushingIncrease(), &task_state->memory_chunk_data);
  NativeContextInferrer native_context_inferrer;
  NativeContextStats& native_context_stats = task_state->native_context_stats;
  double time_ms;
  size_t marked_bytes = 0;
  Isolate* isolate = heap_->isolate();
  if (v8_flags.trace_concurrent_marking) {
    isolate->PrintWithTimestamp("Starting major concurrent marking task %d\n",
                                task_id);
  }
  bool another_ephemeron_iteration = false;
  MainAllocator* const new_space_allocator =
      heap_->use_new_space() ? heap_->allocator()->new_space_allocator()
                             : nullptr;

  {
    TimedScope scope(&time_ms);

    {
      Ephemeron ephemeron;
      while (local_weak_objects.current_ephemerons_local.Pop(&ephemeron)) {
        if (visitor.ProcessEphemeron(ephemeron.key, ephemeron.value)) {
          another_ephemeron_iteration = true;
        }
      }
    }
    PtrComprCageBase cage_base(isolate);
    bool is_per_context_mode = local_marking_worklists.IsPerContextMode();
    bool done = false;
    while (!done) {
      size_t current_marked_bytes = 0;
      int objects_processed = 0;
      while (current_marked_bytes < kBytesUntilInterruptCheck &&
             objects_processed < kObjectsUntilInterruptCheck) {
        Tagged<HeapObject> object;
        if (!local_marking_worklists.Pop(&object)) {
          done = true;
          break;
        }
        DCHECK(!HeapLayout::InReadOnlySpace(object));
        DCHECK_EQ(HeapUtils::GetOwnerHeap(object), heap_);
        objects_processed++;

        Address new_space_top = kNullAddress;
        Address new_space_limit = kNullAddress;
        Address new_large_object = kNullAddress;

        if (new_space_allocator) {
          // The order of the two loads is important.
          new_space_top = new_space_allocator->original_top_acquire();
          new_space_limit = new_space_allocator->original_limit_relaxed();
        }

        if (heap_->new_lo_space()) {
          new_large_object = heap_->new_lo_space()->pending_object();
        }

        Address addr = object.address();

        if ((new_space_top <= addr && addr < new_space_limit) ||
            addr == new_large_object) {
          local_marking_worklists.PushOnHold(object);
        } else {
          Tagged<Map> map = object->map(cage_base, kAcquireLoad);
          // The marking worklist should never contain filler objects.
          CHECK(!IsFreeSpaceOrFillerMap(map));
          if (is_per_context_mode) {
            Address context;
            if (native_context_inferrer.Infer(cage_base, map, object,
                                              &context)) {
              local_marking_worklists.SwitchToContext(context);
            }
          }
          const auto visited_size = visitor.Visit(map, object);
          visitor.IncrementLiveBytesCached(
              MutablePageMetadata::cast(
                  MemoryChunkMetadata::FromHeapObject(object)),
              ALIGN_TO_ALLOCATION_ALIGNMENT(visited_size));
          if (is_per_context_mode) {
            native_context_stats.IncrementSize(
                local_marking_worklists.Context(), map, object, visited_size);
          }
          current_marked_bytes += visited_size;
        }
      }
      if (objects_processed > 0) another_ephemeron_iteration = true;
      marked_bytes += current_marked_bytes;
      base::AsAtomicWord::Relaxed_Store<size_t>(&task_state->marked_bytes,
                                                marked_bytes);
      if (delegate->ShouldYield()) {
        TRACE_GC_NOTE("ConcurrentMarking::RunMajor Preempted");
        break;
      }
    }

    if (done) {
      Ephemeron ephemeron;
      while (local_weak_objects.discovered_ephemerons_local.Pop(&ephemeron)) {
        if (visitor.ProcessEphemeron(ephemeron.key, ephemeron.value)) {
          another_ephemeron_iteration = true;
        }
      }
    }

    local_marking_worklists.Publish();
    local_weak_objects.Publish();
    base::AsAtomicWord::Relaxed_Store<size_t>(&task_state->marked_bytes, 0);
    total_marked_bytes_ += marked_bytes;

    if (another_ephemeron_iteration) {
      set_another_ephemeron_iteration(true);
    }
  }
  if (v8_flags.trace_concurrent_marking) {
    heap_->isolate()->PrintWithTimestamp(
        "Major task %d concurrently marked %dKB in %.2fms\n", task_id,
        static_cast<int>(marked_bytes / KB), time_ms);
  }

  DCHECK(task_state->local_pretenuring_feedback.empty());
}

class ConcurrentMarking::MinorMarkingState {
 public:
  ~MinorMarkingState() { DCHECK_EQ(0, active_markers_); }

  V8_INLINE void MarkerStarted() {
    active_markers_.fetch_add(1, std::memory_order_relaxed);
  }

  // Returns true if all markers are done.
  V8_INLINE bool MarkerDone() {
    return active_markers_.fetch_sub(1, std::memory_order_relaxed) == 1;
  }

 private:
  std::atomic<int> active_markers_{0};
};

namespace {

V8_INLINE bool IsYoungObjectInLab(MainAllocator* new_space_allocator,
                                  NewLargeObjectSpace* new_lo_space,
                                  Tagged<HeapObject> heap_object) {
  // The order of the two loads is important.
  Address new_space_top = new_space_allocator->original_top_acquire();
  Address new_space_limit = new_space_allocator->original_limit_relaxed();
  Address new_large_object = new_lo_space->pending_object();

  Address addr = heap_object.address();

  return (new_space_top <= addr && addr < new_space_limit) ||
         addr == new_large_object;
}

}  // namespace

template <YoungGenerationMarkingVisitationMode marking_mode>
V8_INLINE size_t ConcurrentMarking::RunMinorImpl(JobDelegate* delegate,
                                                 TaskState* task_state) {
  static constexpr size_t kBytesUntilInterruptCheck = 64 * KB;
  static constexpr int kObjectsUntilInterruptCheck = 1000;
  size_t marked_bytes = 0;
  size_t current_marked_bytes = 0;
  int objects_processed = 0;
  YoungGenerationMarkingVisitor<marking_mode> visitor(
      heap_, &task_state->local_pretenuring_feedback);
  YoungGenerationRememberedSetsMarkingWorklist::Local remembered_sets(
      heap_->minor_mark_sweep_collector()->remembered_sets_marking_handler());
  auto& marking_worklists_local = visitor.marking_worklists_local();
  Isolate* isolate = heap_->isolate();
  minor_marking_state_->MarkerStarted();
  MainAllocator* const new_space_allocator =
      heap_->allocator()->new_space_allocator();
  NewLargeObjectSpace* const new_lo_space = heap_->new_lo_space();

  do {
    if (delegate->IsJoiningThread()) {
      marking_worklists_local.MergeOnHold();
    }
    Tagged<HeapObject> heap_object;
    TRACE_GC_EPOCH(heap_->tracer(),
                   GCTracer::Scope::MINOR_MS_BACKGROUND_MARKING_CLOSURE,
                   ThreadKind::kBackground);
    while (marking_worklists_local.Pop(&heap_object)) {
      if (IsYoungObjectInLab(new_space_allocator, new_lo_space, heap_object)) {
        visitor.marking_worklists_local().PushOnHold(heap_object);
      } else {
        Tagged<Map> map = heap_object->map(isolate);
        const auto visited_size = visitor.Visit(map, heap_object);
        if (visited_size) {
          current_marked_bytes += visited_size;
          visitor.IncrementLiveBytesCached(
              MutablePageMetadata::FromHeapObject(heap_object),
              ALIGN_TO_ALLOCATION_ALIGNMENT(visited_size));
        }
      }

      if (current_marked_bytes >= kBytesUntilInterruptCheck ||
          ++objects_processed >= kObjectsUntilInterruptCheck) {
        marked_bytes += current_marked_bytes;
        if (delegate->ShouldYield()) {
          TRACE_GC_NOTE("ConcurrentMarking::RunMinor Preempted");
          minor_marking_state_->MarkerDone();
          return marked_bytes;
        }
        objects_processed = 0;
        current_marked_bytes = 0;
      }
    }
  } while (remembered_sets.ProcessNextItem(&visitor));
  if (minor_marking_state_->MarkerDone()) {
    // This is the last active marker and it ran out of work. Request GC
    // finalization.
    heap_->minor_mark_sweep_collector()->RequestGC();
  }
  return marked_bytes + current_marked_bytes;
}

void ConcurrentMarking::RunMinor(JobDelegate* delegate) {
  DCHECK(heap_->use_new_space());
  DCHECK_NOT_NULL(heap_->new_lo_space());
  uint8_t task_id = delegate->GetTaskId() + 1;
  DCHECK_LT(task_id, task_state_.size());
  TaskState* task_state = task_state_[task_id].get();
  double time_ms;
  size_t marked_bytes = 0;
  Isolate* isolate = heap_->isolate();
  if (v8_flags.trace_concurrent_marking) {
    isolate->PrintWithTimestamp("Starting minor concurrent marking task %d\n",
                                task_id);
  }

  {
    TimedScope scope(&time_ms);
    if (heap_->minor_mark_sweep_collector()->is_in_atomic_pause()) {
      // This gets a lower bound for estimated concurrency as we may have marked
      // most of the graph concurrently already and may not be using parallism
      // as much.
      estimate_concurrency_.fetch_add(1, std::memory_order_relaxed);
      marked_bytes =
          RunMinorImpl<YoungGenerationMarkingVisitationMode::kParallel>(
              delegate, task_state);
    } else {
      marked_bytes =
          RunMinorImpl<YoungGenerationMarkingVisitationMode::kConcurrent>(
              delegate, task_state);
    }
  }

  if (v8_flags.trace_concurrent_marking) {
    heap_->isolate()->PrintWithTimestamp(
        "Minor task %d concurrently marked %dKB in %.2fms\n", task_id,
        static_cast<int>(marked_bytes / KB), time_ms);
  }

  DCHECK(task_state->memory_chunk_data.empty());
  DCHECK(task_state->native_context_stats.Empty());
  DCHECK_EQ(0, task_state->marked_bytes);
}

size_t ConcurrentMarking::GetMajorMaxConcurrency(size_t worker_count) {
  size_t marking_items = marking_worklists_->shared()->Size();
  marking_items += marking_worklists_->other()->Size();
  for (auto& worklist : marking_worklists_->context_worklists()) {
    marking_items += worklist.worklist->Size();
  }
  const size_t work = std::max<size_t>(
      {marking_items, weak_objects_->discovered_ephemerons.Size(),
       weak_objects_->current_ephemerons.Size()});
  size_t jobs = worker_count + work;
  jobs = std::min<size_t>(task_state_.size() - 1, jobs);
  if (heap_->ShouldOptimizeForBattery()) {
    return std::min<size_t>(jobs, 1);
  }
  return jobs;
}

size_t ConcurrentMarking::GetMinorMaxConcurrency(size_t worker_count) {
  const size_t marking_items = marking_worklists_->shared()->Size() +
                               heap_->minor_mark_sweep_collector()
                                   ->remembered_sets_marking_handler()
                                   ->RemainingRememberedSetsMarkingIteams();
  DCHECK(marking_worklists_->other()->IsEmpty());
  DCHECK(!marking_worklists_->IsUsingContextWorklists());
  size_t jobs = worker_count + marking_items;
  jobs = std::min<size_t>(task_state_.size() - 1, jobs);
  if (heap_->ShouldOptimizeForBattery()) {
    return std::min<size_t>(jobs, 1);
  }
  return jobs;
}

void ConcurrentMarking::TryScheduleJob(GarbageCollector garbage_collector,
                                       TaskPriority priority) {
  DCHECK(v8_flags.parallel_marking || v8_flags.concurrent_marking ||
         v8_flags.concurrent_minor_ms_marking);
  DCHECK(!heap_->IsTearingDown());
  DCHECK(IsStopped());

  DCHECK_NE(garbage_collector, GarbageCollector::SCAVENGER);
  if (garbage_collector == GarbageCollector::MARK_COMPACTOR &&
      !heap_->mark_compact_collector()->UseBackgroundThreadsInCycle()) {
    return;
  }
  if (garbage_collector == GarbageCollector::MINOR_MARK_SWEEPER &&
      !heap_->minor_mark_sweep_collector()->UseBackgroundThreadsInCycle()) {
    return;
  }

  if (v8_flags.concurrent_marking_high_priority_threads) {
    priority = TaskPriority::kUserBlocking;
  }

  // Marking state can only be alive if the concurrent marker was previously
  // stopped.
  DCHECK_IMPLIES(
      minor_marking_state_,
      garbage_collector_.has_value() &&
          (*garbage_collector_ == garbage_collector) &&
          (garbage_collector == GarbageCollector::MINOR_MARK_SWEEPER));
  DCHECK_IMPLIES(
      !garbage_collector_.has_value() ||
          *garbage_collector_ == GarbageCollector::MARK_COMPACTOR,
      std::all_of(task_state_.begin(), task_state_.end(), [](auto& task_state) {
        return task_state->local_pretenuring_feedback.empty();
      }));
  garbage_collector_ = garbage_collector;
  if (garbage_collector == GarbageCollector::MARK_COMPACTOR) {
    heap_->mark_compact_collector()->local_marking_worklists()->Publish();
    marking_worklists_ = heap_->mark_compact_collector()->marking_worklists();
    auto job = std::make_unique<JobTaskMajor>(
        this, heap_->mark_compact_collector()->epoch(),
        heap_->mark_compact_collector()->code_flush_mode(),
        heap_->ShouldCurrentGCKeepAgesUnchanged());
    current_job_trace_id_.emplace(job->trace_id());
    TRACE_GC_NOTE_WITH_FLOW("Major concurrent marking started", job->trace_id(),
                            TRACE_EVENT_FLAG_FLOW_OUT);
    job_handle_ = V8::GetCurrentPlatform()->PostJob(priority, std::move(job));
  } else {
    DCHECK(garbage_collector == GarbageCollector::MINOR_MARK_SWEEPER);
    minor_marking_state_ = std::make_unique<MinorMarkingState>();
    heap_->minor_mark_sweep_collector()->local_marking_worklists()->Publish();
    marking_worklists_ =
        heap_->minor_mark_sweep_collector()->marking_worklists();
    auto job = std::make_unique<JobTaskMinor>(this);
    current_job_trace_id_.emplace(job->trace_id());
    TRACE_GC_NOTE_WITH_FLOW("Minor concurrent marking started", job->trace_id(),
                            TRACE_EVENT_FLAG_FLOW_OUT);
    job_handle_ = V8::GetCurrentPlatform()->PostJob(priority, std::move(job));
  }
  DCHECK(job_handle_->IsValid());
}

bool ConcurrentMarking::IsWorkLeft() const {
  DCHECK(garbage_collector_.has_value());
  if (garbage_collector_ == GarbageCollector::MARK_COMPACTOR) {
    return !marking_worklists_->shared()->IsEmpty() ||
           !weak_objects_->current_ephemerons.IsEmpty() ||
           !weak_objects_->discovered_ephemerons.IsEmpty();
  }
  DCHECK_EQ(GarbageCollector::MINOR_MARK_SWEEPER, garbage_collector_);
  return !marking_worklists_->shared()->IsEmpty() ||
         (heap_->minor_mark_sweep_collector()
              ->remembered_sets_marking_handler()
              ->RemainingRememberedSetsMarkingIteams() > 0);
}

void ConcurrentMarking::RescheduleJobIfNeeded(
    GarbageCollector garbage_collector, TaskPriority priority) {
  DCHECK(v8_flags.parallel_marking || v8_flags.concurrent_marking ||
         v8_flags.concurrent_minor_ms_marking);

  if (garbage_collector == GarbageCollector::MARK_COMPACTOR &&
      !heap_->mark_compact_collector()->UseBackgroundThreadsInCycle()) {
    return;
  }

  if (garbage_collector == GarbageCollector::MINOR_MARK_SWEEPER &&
      !heap_->minor_mark_sweep_collector()->UseBackgroundThreadsInCycle()) {
    return;
  }

  if (heap_->IsTearingDown()) return;

  if (IsStopped()) {
    // This DCHECK is for the case that concurrent marking was paused.
    DCHECK_IMPLIES(garbage_collector_.has_value(),
                   garbage_collector == garbage_collector_);
    TryScheduleJob(garbage_collector, priority);
  } else {
    DCHECK(garbage_collector_.has_value());
    DCHECK_EQ(garbage_collector, garbage_collector_.value());
    if (garbage_collector == GarbageCollector::MARK_COMPACTOR) {
      heap_->mark_compact_collector()->local_marking_worklists()->Publish();
    } else {
      heap_->minor_mark_sweep_collector()->local_marking_worklists()->Publish();
    }
    if (!IsWorkLeft()) return;
    if (priority != TaskPriority::kUserVisible)
      job_handle_->UpdatePriority(priority);
    DCHECK(current_job_trace_id_.has_value());
    TRACE_GC_NOTE_WITH_FLOW(
        garbage_collector_ == GarbageCollector::MARK_COMPACTOR
            ? "Major concurrent marking rescheduled"
            : "Minor concurrent marking rescheduled",
        current_job_trace_id_.value(),
        TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
    job_handle_->NotifyConcurrencyIncrease();
  }
}

void ConcurrentMarking::FlushPretenuringFeedback() {
  PretenuringHandler* pretenuring_handler = heap_->pretenuring_handler();
  for (auto& task_state : task_state_) {
    pretenuring_handler->MergeAllocationSitePretenuringFeedback(
        task_state->local_pretenuring_feedback);
    task_state->local_pretenuring_feedback.clear();
  }
}

void ConcurrentMarking::Join() {
  DCHECK(v8_flags.parallel_marking || v8_flags.concurrent_marking ||
         v8_flags.concurrent_minor_ms_marking);
  DCHECK_IMPLIES(
      garbage_collector_ == GarbageCollector::MARK_COMPACTOR,
      heap_->mark_compact_collector()->UseBackgroundThreadsInCycle());
  if (!job_handle_ || !job_handle_->IsValid()) return;
  job_handle_->Join();
  current_job_trace_id_.reset();
  garbage_collector_.reset();
  minor_marking_state_.reset();
}

bool ConcurrentMarking::Pause() {
  DCHECK(v8_flags.parallel_marking || v8_flags.concurrent_marking);
  if (!job_handle_ || !job_handle_->IsValid()) return false;

  job_handle_->Cancel();
  DCHECK(current_job_trace_id_.has_value());
  TRACE_GC_NOTE_WITH_FLOW(garbage_collector_ == GarbageCollector::MARK_COMPACTOR
                              ? "Major concurrent marking paused"
                              : "Minor concurrent marking paused",
                          current_job_trace_id_.value(),
                          TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  return true;
}

bool ConcurrentMarking::IsStopped() {
  if (!v8_flags.concurrent_marking && !v8_flags.parallel_marking) return true;

  return !job_handle_ || !job_handle_->IsValid();
}

void ConcurrentMarking::Resume() {
  DCHECK(garbage_collector_.has_value());
  DCHECK(current_job_trace_id_.has_value());
  TRACE_GC_NOTE_WITH_FLOW(garbage_collector_ == GarbageCollector::MARK_COMPACTOR
                              ? "Major concurrent marking resumed"
                              : "Minor concurrent marking resumed",
                          current_job_trace_id_.value(),
                          TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT);
  RescheduleJobIfNeeded(garbage_collector_.value());
}

void ConcurrentMarking::FlushNativeContexts(NativeContextStats* main_stats) {
  DCHECK(!job_handle_ || !job_handle_->IsValid());
  for (size_t i = 1; i < task_state_.size(); i++) {
    main_stats->Merge(task_state_[i]->native_context_stats);
    task_state_[i]->native_context_stats.Clear();
  }
}

void ConcurrentMarking::FlushMemoryChunkData() {
  DCHECK(!job_handle_ || !job_handle_->IsValid());
  for (size_t i = 1; i < task_state_.size(); i++) {
    MemoryChunkDataMap& memory_chunk_data = task_state_[i]->memory_chunk_data;
    for (auto& pair : memory_chunk_data) {
      // ClearLiveness sets the live bytes to zero.
      // Pages with zero live bytes might be already unmapped.
      MutablePageMetadata* memory_chunk = pair.first;
      MemoryChunkData& data = pair.second;
      if (data.live_bytes) {
        memory_chunk->IncrementLiveBytesAtomically(data.live_bytes);
      }
      if (data.typed_slots) {
        RememberedSet<OLD_TO_OLD>::MergeTyped(memory_chunk,
                                              std::move(data.typed_slots));
      }
    }
    memory_chunk_data.clear();
    task_state_[i]->marked_bytes = 0;
  }
  total_marked_bytes_ = 0;
}

void ConcurrentMarking::ClearMemoryChunkData(MutablePageMetadata* chunk) {
  DCHECK(!job_handle_ || !job_handle_->IsValid());
  for (size_t i = 1; i < task_state_.size(); i++) {
    task_state_[i]->memory_chunk_data.erase(chunk);
  }
}

size_t ConcurrentMarking::TotalMarkedBytes() {
  size_t result = 0;
  for (size_t i = 1; i < task_state_.size(); i++) {
    result +=
        base::AsAtomicWord::Relaxed_Load<size_t>(&task_state_[i]->marked_bytes);
  }
  result += total_marked_bytes_;
  return result;
}

ConcurrentMarking::PauseScope::PauseScope(ConcurrentMarking* concurrent_marking)
    : concurrent_marking_(concurrent_marking),
      resume_on_exit_(v8_flags.concurrent_marking &&
                      concurrent_marking_->Pause()) {
  DCHECK(!v8_flags.minor_ms);
  DCHECK_IMPLIES(resume_on_exit_, v8_flags.concurrent_marking);
}

ConcurrentMarking::PauseScope::~PauseScope() {
  if (resume_on_exit_) {
    DCHECK_EQ(concurrent_marking_->garbage_collector_,
              GarbageCollector::MARK_COMPACTOR);
    concurrent_marking_->Resume();
  }
}

}  // namespace internal
}  // namespace v8
```