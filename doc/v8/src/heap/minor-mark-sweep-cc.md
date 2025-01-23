Response:
The user wants a summary of the provided C++ code snippet. The code is part of V8's minor mark-sweep garbage collector.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Functionality:** The filename `minor-mark-sweep.cc` and the class `MinorMarkSweepCollector` immediately suggest this code handles the minor garbage collection process in V8.

2. **Analyze Includes:** The included header files provide clues about the functionalities involved. Look for recurring themes:
    * `heap/*`:  Indicates heap management, memory allocation, and garbage collection.
    * `src/objects/*`: Suggests object manipulation and handling within the heap.
    * `src/codegen/*`:  Potentially related to code objects and optimization (although less central to *minor* GC).
    * `src/tasks/*`:  Points to the use of tasks, likely for parallelization.
    * `src/flags/*`: Implies configuration options that influence the collector's behavior.

3. **Examine Key Classes and Methods:** Focus on the central class `MinorMarkSweepCollector` and its methods. Note the purpose of the most significant ones:
    * `CollectGarbage()`: The main entry point for the minor GC.
    * `MarkLiveObjects()`: The marking phase where reachable objects are identified.
    * `ClearNonLiveReferences()`:  The process of removing references to unreachable objects.
    * `Sweep()`: The phase where unreachable objects are reclaimed.
    * `StartMarking()`, `Finish()`:  Lifecycle management of the GC process.
    * `DrainMarkingWorklist()`:  Processing the worklist of objects to be marked.
    * Methods related to remembered sets (`YoungGenerationRememberedSetsMarkingWorklist`): Handling cross-generational references.

4. **Look for Specific Mechanisms:**  Identify the core techniques used by the minor GC:
    * **Marking:**  The process of tracing live objects.
    * **Sweeping:** The process of reclaiming memory from unmarked objects.
    * **Remembered Sets:**  Mechanisms for efficiently tracking references from older generations to younger generations.
    * **Worklists:** Data structures for managing objects to be processed during marking.
    * **Parallelism:**  The use of concurrent/parallel marking (if enabled by flags).
    * **String Forwarding Table:** A mechanism for handling string compaction (if enabled).
    * **Ephemeron Tables:** Handling weak key-value pairs.

5. **Infer High-Level Goals:** Based on the functionality, deduce the primary objectives:
    * Reclaim memory from the young generation (new space).
    * Minimize pauses by potentially using concurrent marking.
    * Maintain the integrity of the heap by correctly identifying live objects.
    * Interact with other V8 components (e.g., CppHeap for embedded objects).

6. **Address Specific Instructions:**
    * **`.tq` extension:**  The code snippet is `.cc`, not `.tq`, so it's not Torque code.
    * **JavaScript relation:** Minor GC is crucial for managing the lifecycle of JavaScript objects. Provide a simple JavaScript example demonstrating object creation and garbage collection.
    * **Logic Inference:**  While the full logic is complex, a simple scenario of object marking can be illustrated with hypothetical inputs and outputs.
    * **Common Programming Errors:**  Relate the minor GC's purpose to common JavaScript errors, focusing on memory leaks due to dangling references.

7. **Structure the Summary:** Organize the findings into logical sections:
    * Core Functionality.
    * Key Features and Mechanisms.
    * Relationship to JavaScript.
    * Code Logic Inference Example.
    * Common Programming Errors.
    * Overall Purpose.

8. **Refine and Elaborate:**  Expand on the key points with more details, using terminology from the code (like "young generation," "remembered sets," "marking worklist"). Ensure clarity and conciseness. For the logic inference, provide a concrete example of how the marking process would work on a simplified object graph.

9. **Review and Verify:**  Read through the summary to ensure accuracy and completeness based on the provided code snippet. Check if all parts of the prompt have been addressed.
```javascript
// 假设我们创建了一些对象，其中一些对象之间存在引用关系
let obj1 = { data: 1 };
let obj2 = { ref: obj1 };
let obj3 = { data: 3 };

// 当 obj1 不再被其他对象引用时，它就成为了垃圾回收的候选者
obj2.ref = null; // obj1 现在只被局部变量 obj1 引用

// 当局部变量 obj1 也被设置为 null 时，obj1 就可以被回收了
obj1 = null;

// obj3 如果没有被其他对象引用，也会被回收
obj3 = null;

// V8 的 Minor GC (Minor Mark-Sweep) 主要负责回收新生代（New Space）的垃圾
// 上面的例子中，obj1、obj2、obj3 如果分配在新生代，当它们变成不可达时，
// Minor GC 就会负责回收它们占用的内存。

// Minor GC 的目的是快速回收新生代的短期存活对象，避免它们晋升到老年代，
// 从而影响老年代 GC 的效率。
```

**功能归纳:**

`v8/src/heap/minor-mark-sweep.cc` 是 V8 JavaScript 引擎中负责 **新生代 (Young Generation)** 垃圾回收 (Garbage Collection) 的核心代码文件。它实现了 **Minor Mark-Sweep** 算法，其主要功能是：

1. **标记 (Marking) 新生代中的存活对象:**  它会遍历新生代中的对象，并标记那些仍然被根对象 (如全局变量、栈上的局部变量) 或老年代对象引用的对象。
2. **清理 (Sweeping) 新生代中的非存活对象:**  对于没有被标记的对象，它会回收它们占用的内存空间。
3. **处理跨代引用:**  它会利用 **记忆集 (Remembered Set)** 来记录老年代对象对新生代对象的引用，从而在标记阶段能够找到所有需要保留的新生代对象。
4. **支持并发标记:**  根据配置，它可能支持在后台线程并发地执行标记操作，以减少主线程的暂停时间。
5. **与 CppHeap 集成:** 如果启用了 CppHeap (用于管理 V8 之外的 C++ 对象)，它会与 CppHeap 的垃圾回收机制协同工作，处理 V8 对象对 C++ 对象的引用。
6. **管理 Pretenuring:**  它会收集对象在新生代的存活信息，并利用这些信息来指导未来的对象分配，以便将更有可能长期存活的对象直接分配到老年代，减少 Minor GC 的压力。
7. **支持堆验证:**  在开发和调试模式下，它包含用于验证堆完整性的代码。
8. **与垃圾回收追踪器 (GC Tracer) 集成:**  它会将 Minor GC 的相关信息记录到 GC Tracer 中，用于性能分析和监控。
9. **处理弱引用:**  它会处理弱引用对象，确保在 Minor GC 过程中正确地处理它们的生命周期。
10. **管理字符串转发表 (String Forwarding Table):**  如果启用了字符串转发表，它会清理其中指向不再存活的新生代字符串的条目。
11. **清理外部字符串表 (External String Table):**  它会清理外部字符串表中不再存活的新生代字符串。
12. **处理全局句柄和跟踪句柄:**  它会处理全局句柄和跟踪句柄对新生代对象的引用。
13. **处理 EphemeronHashTable:** 它会清理 EphemeronHashTable 中键值对，其中键是新生代对象且不再存活。
14. **页面晋升 (Page Promotion):**  它会评估新生代页面的存活对象比例，并将满足条件的页面晋升到老年代。

**总结:**

`v8/src/heap/minor-mark-sweep.cc` 实现了 V8 引擎中至关重要的 Minor GC 功能，它专注于高效地回收新生代中的垃圾，是 V8 内存管理和性能优化的关键组成部分。它通过标记-清理算法，并结合记忆集、并发标记等技术，有效地管理新生代的内存，并与其他堆管理组件协同工作。

### 提示词
```
这是目录为v8/src/heap/minor-mark-sweep.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/minor-mark-sweep.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/minor-mark-sweep.h"

#include <algorithm>
#include <atomic>
#include <memory>
#include <unordered_set>
#include <vector>

#include "src/base/logging.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap.h"
#include "src/heap/large-spaces.h"
#include "src/heap/live-object-range-inl.h"
#include "src/heap/mark-sweep-utilities.h"
#include "src/heap/marking-barrier.h"
#include "src/heap/marking-visitor-inl.h"
#include "src/heap/marking-visitor.h"
#include "src/heap/marking-worklist-inl.h"
#include "src/heap/marking-worklist.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/minor-mark-sweep-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/new-spaces.h"
#include "src/heap/object-stats.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/read-only-spaces.h"
#include "src/heap/remembered-set.h"
#include "src/heap/safepoint.h"
#include "src/heap/slot-set.h"
#include "src/heap/sweeper.h"
#include "src/heap/traced-handles-marking-visitor.h"
#include "src/heap/weak-object-worklists.h"
#include "src/init/v8.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/objects.h"
#include "src/objects/string-forwarding-table-inl.h"
#include "src/objects/visitors.h"
#include "src/snapshot/shared-heap-serializer.h"
#include "src/tasks/cancelable-task.h"
#include "src/utils/utils-inl.h"

namespace v8 {
namespace internal {

// ==================================================================
// Verifiers
// ==================================================================

#ifdef VERIFY_HEAP
namespace {

class YoungGenerationMarkingVerifier : public MarkingVerifierBase {
 public:
  explicit YoungGenerationMarkingVerifier(Heap* heap)
      : MarkingVerifierBase(heap),
        marking_state_(heap->non_atomic_marking_state()) {}

  const MarkingBitmap* bitmap(const MutablePageMetadata* chunk) override {
    return chunk->marking_bitmap();
  }

  bool IsMarked(Tagged<HeapObject> object) override {
    return marking_state_->IsMarked(object);
  }

  void Run() override {
    VerifyRoots();
    if (v8_flags.sticky_mark_bits) {
      VerifyMarking(heap_->sticky_space());
    } else {
      VerifyMarking(heap_->new_space());
    }
  }

  GarbageCollector collector() const override {
    return GarbageCollector::MINOR_MARK_SWEEPER;
  }

 protected:
  void VerifyMap(Tagged<Map> map) override { VerifyHeapObjectImpl(map); }

  void VerifyPointers(ObjectSlot start, ObjectSlot end) override {
    VerifyPointersImpl(start, end);
  }

  void VerifyPointers(MaybeObjectSlot start, MaybeObjectSlot end) override {
    VerifyPointersImpl(start, end);
  }
  void VerifyCodePointer(InstructionStreamSlot slot) override {
    // Code slots never appear in new space because
    // Code objects, the only object that can contain code pointers, are
    // always allocated in the old space.
    UNREACHABLE();
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    VerifyHeapObjectImpl(target);
  }
  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    VerifyHeapObjectImpl(rinfo->target_object(cage_base()));
  }
  void VerifyRootPointers(FullObjectSlot start, FullObjectSlot end) override {
    VerifyPointersImpl(start, end);
  }

 private:
  V8_INLINE void VerifyHeapObjectImpl(Tagged<HeapObject> heap_object) {
    CHECK_IMPLIES(HeapLayout::InYoungGeneration(heap_object),
                  IsMarked(heap_object));
  }

  template <typename TSlot>
  V8_INLINE void VerifyPointersImpl(TSlot start, TSlot end) {
    PtrComprCageBase cage_base =
        GetPtrComprCageBaseFromOnHeapAddress(start.address());
    for (TSlot slot = start; slot < end; ++slot) {
      typename TSlot::TObject object = slot.load(cage_base);
#ifdef V8_ENABLE_DIRECT_HANDLE
      if (object.ptr() == kTaggedNullAddress) continue;
#endif
      Tagged<HeapObject> heap_object;
      // Minor MS treats weak references as strong.
      if (object.GetHeapObject(&heap_object)) {
        VerifyHeapObjectImpl(heap_object);
      }
    }
  }

  NonAtomicMarkingState* const marking_state_;
};

}  // namespace
#endif  // VERIFY_HEAP

// =============================================================================
// MinorMarkSweepCollector
// =============================================================================

namespace {
int EstimateMaxNumberOfRemeberedSets(Heap* heap) {
  // old space, lo space, trusted space and trusted lo space can have a maximum
  // of two remembered sets (OLD_TO_NEW and OLD_TO_NEW_BACKGROUND).
  // Code space and code lo space can have typed OLD_TO_NEW in addition.
  return 2 * (heap->old_space()->CountTotalPages() +
              heap->lo_space()->PageCount() +
              heap->trusted_space()->CountTotalPages() +
              heap->trusted_lo_space()->PageCount()) +
         3 * (heap->code_space()->CountTotalPages() +
              heap->code_lo_space()->PageCount());
}
}  // namespace

// static
std::vector<YoungGenerationRememberedSetsMarkingWorklist::MarkingItem>
YoungGenerationRememberedSetsMarkingWorklist::CollectItems(Heap* heap) {
  std::vector<MarkingItem> items;
  int max_remembered_set_count = EstimateMaxNumberOfRemeberedSets(heap);
  items.reserve(max_remembered_set_count);
  OldGenerationMemoryChunkIterator::ForAll(
      heap, [&items](MutablePageMetadata* chunk) {
        SlotSet* slot_set = chunk->ExtractSlotSet<OLD_TO_NEW>();
        SlotSet* background_slot_set =
            chunk->ExtractSlotSet<OLD_TO_NEW_BACKGROUND>();
        if (slot_set || background_slot_set) {
          items.emplace_back(chunk, MarkingItem::SlotsType::kRegularSlots,
                             slot_set, background_slot_set);
        }
        if (TypedSlotSet* typed_slot_set =
                chunk->ExtractTypedSlotSet<OLD_TO_NEW>()) {
          DCHECK(IsAnyCodeSpace(chunk->owner_identity()));
          items.emplace_back(chunk, MarkingItem::SlotsType::kTypedSlots,
                             typed_slot_set);
        }
      });
  DCHECK_LE(items.size(), max_remembered_set_count);
  return items;
}

void YoungGenerationRememberedSetsMarkingWorklist::MarkingItem::
    MergeAndDeleteRememberedSets() {
  DCHECK(IsAcquired());
  if (slots_type_ == SlotsType::kRegularSlots) {
    if (slot_set_)
      RememberedSet<OLD_TO_NEW>::MergeAndDelete(chunk_, std::move(*slot_set_));
    if (background_slot_set_)
      RememberedSet<OLD_TO_NEW_BACKGROUND>::MergeAndDelete(
          chunk_, std::move(*background_slot_set_));
  } else {
    DCHECK_EQ(slots_type_, SlotsType::kTypedSlots);
    DCHECK_NULL(background_slot_set_);
    if (typed_slot_set_)
      RememberedSet<OLD_TO_NEW>::MergeAndDeleteTyped(
          chunk_, std::move(*typed_slot_set_));
  }
}

void YoungGenerationRememberedSetsMarkingWorklist::MarkingItem::
    DeleteRememberedSets() {
  DCHECK(IsAcquired());
  if (slots_type_ == SlotsType::kRegularSlots) {
    if (slot_set_) SlotSet::Delete(slot_set_);
    if (background_slot_set_) SlotSet::Delete(background_slot_set_);
  } else {
    DCHECK_EQ(slots_type_, SlotsType::kTypedSlots);
    DCHECK_NULL(background_slot_set_);
    if (typed_slot_set_)
      RememberedSet<OLD_TO_NEW>::DeleteTyped(std::move(*typed_slot_set_));
  }
}

void YoungGenerationRememberedSetsMarkingWorklist::MarkingItem::
    DeleteSetsOnTearDown() {
  if (slots_type_ == SlotsType::kRegularSlots) {
    if (slot_set_) SlotSet::Delete(slot_set_);
    if (background_slot_set_) SlotSet::Delete(background_slot_set_);

  } else {
    DCHECK_EQ(slots_type_, SlotsType::kTypedSlots);
    DCHECK_NULL(background_slot_set_);
    if (typed_slot_set_) delete typed_slot_set_;
  }
}

YoungGenerationRememberedSetsMarkingWorklist::
    YoungGenerationRememberedSetsMarkingWorklist(Heap* heap)
    : remembered_sets_marking_items_(CollectItems(heap)),
      remaining_remembered_sets_marking_items_(
          remembered_sets_marking_items_.size()),
      remembered_sets_marking_index_generator_(
          remembered_sets_marking_items_.size()) {}

YoungGenerationRememberedSetsMarkingWorklist::
    ~YoungGenerationRememberedSetsMarkingWorklist() {
  for (MarkingItem item : remembered_sets_marking_items_) {
    if (v8_flags.sticky_mark_bits) {
      item.DeleteRememberedSets();
    } else {
      item.MergeAndDeleteRememberedSets();
    }
  }
}

void YoungGenerationRememberedSetsMarkingWorklist::TearDown() {
  for (MarkingItem& item : remembered_sets_marking_items_) {
    item.DeleteSetsOnTearDown();
  }
  remembered_sets_marking_items_.clear();
  remaining_remembered_sets_marking_items_.store(0, std::memory_order_relaxed);
}

YoungGenerationRootMarkingVisitor::YoungGenerationRootMarkingVisitor(
    MinorMarkSweepCollector* collector)
    : main_marking_visitor_(collector->main_marking_visitor()) {}

YoungGenerationRootMarkingVisitor::~YoungGenerationRootMarkingVisitor() =
    default;

// static
constexpr size_t MinorMarkSweepCollector::kMaxParallelTasks;

MinorMarkSweepCollector::MinorMarkSweepCollector(Heap* heap)
    : heap_(heap),
      marking_state_(heap_->marking_state()),
      non_atomic_marking_state_(heap_->non_atomic_marking_state()),
      sweeper_(heap_->sweeper()) {}

void MinorMarkSweepCollector::PerformWrapperTracing() {
  auto* cpp_heap = CppHeap::From(heap_->cpp_heap_);
  if (!cpp_heap) return;

  TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_EMBEDDER_TRACING);
  local_marking_worklists()->PublishCppHeapObjects();
  cpp_heap->AdvanceTracing(v8::base::TimeDelta::Max());
}

MinorMarkSweepCollector::~MinorMarkSweepCollector() = default;

void MinorMarkSweepCollector::TearDown() {
  if (heap_->incremental_marking()->IsMinorMarking()) {
    DCHECK(heap_->concurrent_marking()->IsStopped());
    remembered_sets_marking_handler_->TearDown();
    main_marking_visitor_->PublishWorklists();
    heap_->main_thread_local_heap_->marking_barrier()->PublishIfNeeded();
    // Marking barriers of LocalHeaps will be published in their destructors.
    marking_worklists_->Clear();
    ephemeron_table_list_->Clear();
  }
}

void MinorMarkSweepCollector::FinishConcurrentMarking() {
  if (v8_flags.concurrent_minor_ms_marking || v8_flags.parallel_marking) {
    DCHECK_IMPLIES(!heap_->concurrent_marking()->IsStopped(),
                   heap_->concurrent_marking()->garbage_collector() ==
                       GarbageCollector::MINOR_MARK_SWEEPER);
    heap_->concurrent_marking()->Join();
    heap_->concurrent_marking()->FlushPretenuringFeedback();
  }
  CHECK(heap_->concurrent_marking()->IsStopped());
  heap_->tracer()->SampleConcurrencyEsimate(
      heap_->concurrent_marking()->FetchAndResetConcurrencyEstimate());
  if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap_)) {
    cpp_heap->FinishConcurrentMarkingIfNeeded();
  }
}

#ifdef DEBUG
template <typename Space>
static bool ExternalPointerRememberedSetsEmpty(Space* space) {
  for (auto it = space->begin(); it != space->end();) {
    PageMetadata* p = *(it++);
    if (p->slot_set<SURVIVOR_TO_EXTERNAL_POINTER>()) {
      return false;
    }
  }
  return true;
}
#endif

void MinorMarkSweepCollector::StartMarking(bool force_use_background_threads) {
#if defined(VERIFY_HEAP) && !V8_ENABLE_STICKY_MARK_BITS_BOOL
  if (v8_flags.verify_heap) {
    for (PageMetadata* page : *heap_->new_space()) {
      CHECK(page->marking_bitmap()->IsClean());
    }
  }
#endif  // defined(VERIFY_HEAP) && !V8_ENABLE_STICKY_MARK_BITS_BOOL

  // The state for background thread is saved here and maintained for the whole
  // GC cycle. Both CppHeap and regular V8 heap will refer to this flag.
  CHECK(!use_background_threads_in_cycle_.has_value());
  // Once we decided to start concurrent marking we always need to use
  // background threads, this is because Minor MS doesn't perform incremental
  // marking. ShouldUseBackgroundThreads() on worker isolates can be updated
  // concurrently from the main thread outside a task, so we shouldn't invoke it
  // here again as it could return a different result.
  use_background_threads_in_cycle_ =
      force_use_background_threads || heap_->ShouldUseBackgroundThreads();

  auto* cpp_heap = CppHeap::From(heap_->cpp_heap_);
  // CppHeap's marker must be initialized before the V8 marker to allow
  // exchanging of worklists.
  if (cpp_heap && cpp_heap->generational_gc_supported()) {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_EMBEDDER_PROLOGUE);
    cpp_heap->InitializeMarking(CppHeap::CollectionType::kMinor);
  }
  DCHECK_NULL(ephemeron_table_list_);
  ephemeron_table_list_ = std::make_unique<EphemeronRememberedSet::TableList>();
  DCHECK_NULL(marking_worklists_);
  marking_worklists_ = std::make_unique<MarkingWorklists>();
  DCHECK_NULL(main_marking_visitor_);
  DCHECK_NULL(pretenuring_feedback_);
  if (v8_flags.sticky_mark_bits) {
    DCHECK(ExternalPointerRememberedSetsEmpty(heap_->sticky_space()));
  } else {
    DCHECK(ExternalPointerRememberedSetsEmpty(
        heap_->paged_new_space()->paged_space()));
  }
  pretenuring_feedback_ =
      std::make_unique<PretenuringHandler::PretenuringFeedbackMap>(
          PretenuringHandler::kInitialFeedbackCapacity);
  main_marking_visitor_ = std::make_unique<YoungGenerationMainMarkingVisitor>(
      heap_, pretenuring_feedback_.get());
  DCHECK_NULL(remembered_sets_marking_handler_);
  remembered_sets_marking_handler_ =
      std::make_unique<YoungGenerationRememberedSetsMarkingWorklist>(heap_);
  if (cpp_heap && cpp_heap->generational_gc_supported()) {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_EMBEDDER_PROLOGUE);
    // StartTracing immediately starts marking which requires V8 worklists to
    // be set up.
    cpp_heap->StartMarking();
  }
}

void MinorMarkSweepCollector::Finish() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_FINISH);

  use_background_threads_in_cycle_.reset();

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_FINISH_ENSURE_CAPACITY);
    switch (resize_new_space_) {
      case ResizeNewSpaceMode::kShrink:
        heap_->ReduceNewSpaceSize();
        break;
      case ResizeNewSpaceMode::kGrow:
        heap_->ExpandNewSpaceSize();
        break;
      case ResizeNewSpaceMode::kNone:
        break;
    }
    resize_new_space_ = ResizeNewSpaceMode::kNone;

    if (!v8_flags.sticky_mark_bits &&
        !heap_->new_space()->EnsureCurrentCapacity()) {
      heap_->FatalProcessOutOfMemory("NewSpace::EnsureCurrentCapacity");
    }
  }

  if (!v8_flags.sticky_mark_bits) {
    heap_->new_space()->GarbageCollectionEpilogue();
  }
}

void MinorMarkSweepCollector::CollectGarbage() {
  DCHECK(!heap_->mark_compact_collector()->in_use());
  DCHECK(heap_->use_new_space());
  DCHECK(!heap_->array_buffer_sweeper()->sweeping_in_progress());
  DCHECK(!sweeper()->AreMinorSweeperTasksRunning());
  if (v8_flags.sticky_mark_bits) {
    DCHECK(sweeper()->IsSweepingDoneForSpace(OLD_SPACE));
  } else {
    DCHECK(sweeper()->IsSweepingDoneForSpace(NEW_SPACE));
  }

  heap_->new_lo_space()->ResetPendingObject();

  is_in_atomic_pause_.store(true, std::memory_order_relaxed);

  MarkLiveObjects();
  ClearNonLiveReferences();
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_VERIFY);
    YoungGenerationMarkingVerifier verifier(heap_);
    verifier.Run();
  }
#endif  // VERIFY_HEAP

  if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap_)) {
    cpp_heap->FinishMarkingAndProcessWeakness();
  }

  Sweep();
  Finish();

  auto* isolate = heap_->isolate();
  isolate->global_handles()->UpdateListOfYoungNodes();
  isolate->traced_handles()->UpdateListOfYoungNodes();

  isolate->stack_guard()->ClearGC();
  gc_finalization_requested_.store(false, std::memory_order_relaxed);
  is_in_atomic_pause_.store(false, std::memory_order_relaxed);
}

namespace {

class YoungStringForwardingTableCleaner final
    : public StringForwardingTableCleanerBase {
 public:
  explicit YoungStringForwardingTableCleaner(Heap* heap)
      : StringForwardingTableCleanerBase(heap) {}

  // For Minor MS we don't mark forward objects, because they are always
  // in old generation (and thus considered live).
  // We only need to delete non-live young objects.
  void ProcessYoungObjects() {
    DCHECK(v8_flags.always_use_string_forwarding_table);
    StringForwardingTable* forwarding_table =
        isolate_->string_forwarding_table();
    forwarding_table->IterateElements(
        [&](StringForwardingTable::Record* record) {
          ClearNonLiveYoungObjects(record);
        });
  }

 private:
  void ClearNonLiveYoungObjects(StringForwardingTable::Record* record) {
    Tagged<Object> original = record->OriginalStringObject(isolate_);
    if (!IsHeapObject(original)) {
      DCHECK_EQ(original, StringForwardingTable::deleted_element());
      return;
    }
    Tagged<String> original_string = Cast<String>(original);
    if (!HeapLayout::InYoungGeneration(original_string)) return;
    if (!marking_state_->IsMarked(original_string)) {
      DisposeExternalResource(record);
      record->set_original_string(StringForwardingTable::deleted_element());
    }
  }
};

bool IsUnmarkedObjectInYoungGeneration(Heap* heap, FullObjectSlot p) {
  if (v8_flags.sticky_mark_bits) {
    return HeapLayout::InYoungGeneration(*p);
  }
  DCHECK_IMPLIES(HeapLayout::InYoungGeneration(*p), Heap::InToPage(*p));
  return HeapLayout::InYoungGeneration(*p) &&
         !heap->non_atomic_marking_state()->IsMarked(Cast<HeapObject>(*p));
}

}  // namespace

void MinorMarkSweepCollector::ClearNonLiveReferences() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_CLEAR);

  if (V8_UNLIKELY(v8_flags.always_use_string_forwarding_table)) {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MINOR_MS_CLEAR_STRING_FORWARDING_TABLE);
    // Clear non-live objects in the string fowarding table.
    YoungStringForwardingTableCleaner forwarding_table_cleaner(heap_);
    forwarding_table_cleaner.ProcessYoungObjects();
  }

  Heap::ExternalStringTable& external_string_table =
      heap_->external_string_table_;
  if (external_string_table.HasYoung()) {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_CLEAR_STRING_TABLE);
    // Internalized strings are always stored in old space, so there is no
    // need to clean them here.
    ExternalStringTableCleanerVisitor<
        ExternalStringTableCleaningMode::kYoungOnly>
        external_visitor(heap_);
    external_string_table.IterateYoung(&external_visitor);
    external_string_table.CleanUpYoung();
  }

  Isolate* isolate = heap_->isolate();
  if (isolate->global_handles()->HasYoung() ||
      isolate->traced_handles()->HasYoung()) {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MINOR_MS_CLEAR_WEAK_GLOBAL_HANDLES);
    isolate->global_handles()->ProcessWeakYoungObjects(
        nullptr, &IsUnmarkedObjectInYoungGeneration);
    if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap_);
        cpp_heap && cpp_heap->generational_gc_supported()) {
      isolate->traced_handles()->ResetYoungDeadNodes(
          &IsUnmarkedObjectInYoungGeneration);
    } else {
      isolate->traced_handles()->ProcessYoungObjects(
          nullptr, &IsUnmarkedObjectInYoungGeneration);
    }
  }

  // Clear ephemeron entries from EphemeronHashTables in the young generation
  // whenever the entry has a dead young generation key.
  //
  // Worklist is collected during marking.
  {
    DCHECK_NOT_NULL(ephemeron_table_list_);
    EphemeronRememberedSet::TableList::Local local_ephemeron_table_list(
        *ephemeron_table_list_);
    Tagged<EphemeronHashTable> table;
    while (local_ephemeron_table_list.Pop(&table)) {
      for (InternalIndex i : table->IterateEntries()) {
        // Keys in EphemeronHashTables must be heap objects.
        HeapObjectSlot key_slot(
            table->RawFieldOfElementAt(EphemeronHashTable::EntryToIndex(i)));
        Tagged<HeapObject> key = key_slot.ToHeapObject();
        if (HeapLayout::InYoungGeneration(key) &&
            non_atomic_marking_state_->IsUnmarked(key)) {
          table->RemoveEntry(i);
        }
      }
    }
  }
  ephemeron_table_list_.reset();

  // Clear ephemeron entries from EphemeronHashTables in the old generation
  // whenever the entry has a dead young generation key.
  //
  // Does not need to be iterated as roots but is maintained in the GC to avoid
  // treating keys as strong. The set is populated from the write barrier and
  // the sweeper during promoted pages iteration.
  auto* table_map = heap_->ephemeron_remembered_set()->tables();
  for (auto it = table_map->begin(); it != table_map->end();) {
    Tagged<EphemeronHashTable> table = it->first;
    auto& indices = it->second;
    for (auto iti = indices.begin(); iti != indices.end();) {
      // Keys in EphemeronHashTables must be heap objects.
      HeapObjectSlot key_slot(table->RawFieldOfElementAt(
          EphemeronHashTable::EntryToIndex(InternalIndex(*iti))));
      Tagged<HeapObject> key = key_slot.ToHeapObject();
      // There may be old generation entries left in the remembered set as
      // MinorMS only promotes pages after clearing non-live references.
      if (!HeapLayout::InYoungGeneration(key)) {
        iti = indices.erase(iti);
      } else if (non_atomic_marking_state_->IsUnmarked(key)) {
        table->RemoveEntry(InternalIndex(*iti));
        iti = indices.erase(iti);
      } else {
        ++iti;
      }
    }

    if (indices.empty()) {
      it = table_map->erase(it);
    } else {
      ++it;
    }
  }
}

namespace {
void VisitObjectWithEmbedderFields(Isolate* isolate, Tagged<JSObject> js_object,
                                   MarkingWorklists::Local& worklist) {
  DCHECK(js_object->MayHaveEmbedderFields());
  DCHECK(!HeapLayout::InYoungGeneration(js_object));
  // Not every object that can have embedder fields is actually a JSApiWrapper.
  if (!IsJSApiWrapperObject(js_object)) {
    return;
  }

  // Wrapper using cpp_heap_wrappable field.
  void* wrappable =
      JSApiWrapper(js_object).GetCppHeapWrappable(isolate, kAnyCppHeapPointer);
  if (wrappable) {
    worklist.cpp_marking_state()->MarkAndPush(wrappable);
  }
}
}  // namespace

void MinorMarkSweepCollector::MarkRootsFromTracedHandles(
    YoungGenerationRootMarkingVisitor& root_visitor) {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_TRACED_HANDLES);
  if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap_);
      cpp_heap && cpp_heap->generational_gc_supported()) {
    // Visit the Oilpan-to-V8 remembered set.
    heap_->isolate()->traced_handles()->IterateAndMarkYoungRootsWithOldHosts(
        &root_visitor);
    // Visit the V8-to-Oilpan remembered set.
    cpp_heap->VisitCrossHeapRememberedSetIfNeeded([this](Tagged<JSObject> obj) {
      VisitObjectWithEmbedderFields(heap_->isolate(), obj,
                                    *local_marking_worklists());
    });
  } else {
    // Otherwise, visit all young roots.
    heap_->isolate()->traced_handles()->IterateYoungRoots(&root_visitor);
  }
}

void MinorMarkSweepCollector::MarkRoots(
    YoungGenerationRootMarkingVisitor& root_visitor,
    bool was_marked_incrementally) {
  Isolate* isolate = heap_->isolate();

  // Seed the root set.
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_SEED);
    isolate->traced_handles()->ComputeWeaknessForYoungObjects();
    // MinorMS treats all weak roots except for global handles as strong.
    // That is why we don't set skip_weak = true here and instead visit
    // global handles separately.
    heap_->IterateRoots(
        &root_visitor,
        base::EnumSet<SkipRoot>{
            SkipRoot::kExternalStringTable, SkipRoot::kGlobalHandles,
            SkipRoot::kTracedHandles, SkipRoot::kOldGeneration,
            SkipRoot::kReadOnlyBuiltins, SkipRoot::kConservativeStack});
    isolate->global_handles()->IterateYoungStrongAndDependentRoots(
        &root_visitor);
    MarkRootsFromTracedHandles(root_visitor);
  }
}

void MinorMarkSweepCollector::MarkRootsFromConservativeStack(
    YoungGenerationRootMarkingVisitor& root_visitor) {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::CONSERVATIVE_STACK_SCANNING);
  heap_->IterateConservativeStackRoots(&root_visitor,
                                       Heap::IterateRootsMode::kMainIsolate);
}

void MinorMarkSweepCollector::MarkLiveObjects() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK);

  const bool was_marked_incrementally =
      !heap_->incremental_marking()->IsStopped();
  if (!was_marked_incrementally) {
    StartMarking(false);
  } else {
    auto* incremental_marking = heap_->incremental_marking();
    TRACE_GC_WITH_FLOW(
        heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_FINISH_INCREMENTAL,
        incremental_marking->current_trace_id(), TRACE_EVENT_FLAG_FLOW_IN);
    DCHECK(incremental_marking->IsMinorMarking());
    DCHECK(v8_flags.concurrent_minor_ms_marking);
    incremental_marking->Stop();
    MarkingBarrier::PublishYoung(heap_);
  }

  DCHECK_NOT_NULL(marking_worklists_);
  DCHECK_NOT_NULL(main_marking_visitor_);

  YoungGenerationRootMarkingVisitor root_visitor(this);

  MarkRoots(root_visitor, was_marked_incrementally);

  // CppGC starts parallel marking tasks that will trace TracedReferences.
  if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap())) {
    cpp_heap->EnterFinalPause(heap_->embedder_stack_state_);
  }

  {
    // Mark the transitive closure in parallel.
    TRACE_GC_ARG1(heap_->tracer(),
                  GCTracer::Scope::MINOR_MS_MARK_CLOSURE_PARALLEL,
                  "UseBackgroundThreads", UseBackgroundThreadsInCycle());
    if (v8_flags.parallel_marking) {
      heap_->concurrent_marking()->RescheduleJobIfNeeded(
          GarbageCollector::MINOR_MARK_SWEEPER, TaskPriority::kUserBlocking);
    }
    DrainMarkingWorklist();
    FinishConcurrentMarking();
  }

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MINOR_MS_MARK_CONSERVATIVE_STACK);
    MarkRootsFromConservativeStack(root_visitor);
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MINOR_MS_MARK_CLOSURE);
    if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap())) {
      cpp_heap->EnterProcessGlobalAtomicPause();
    }
    DrainMarkingWorklist();
  }
  CHECK(local_marking_worklists()->IsEmpty());

  if (was_marked_incrementally) {
    // Disable the marking barrier after concurrent/parallel marking has
    // finished as it will reset page flags.
    Sweeper::PauseMajorSweepingScope pause_sweeping_scope(heap_->sweeper());
    MarkingBarrier::DeactivateYoung(heap_);
  }

  main_marking_visitor_.reset();
  marking_worklists_.reset();
  remembered_sets_marking_handler_.reset();

  PretenuringHandler* pretenuring_handler = heap_->pretenuring_handler();
  pretenuring_handler->MergeAllocationSitePretenuringFeedback(
      *pretenuring_feedback_);
  pretenuring_feedback_.reset();

  if (v8_flags.minor_ms_trace_fragmentation) {
    TraceFragmentation();
  }
}

void MinorMarkSweepCollector::DrainMarkingWorklist() {
  PtrComprCageBase cage_base(heap_->isolate());
  YoungGenerationRememberedSetsMarkingWorklist::Local remembered_sets(
      remembered_sets_marking_handler_.get());
  auto* marking_worklists_local = local_marking_worklists();
  do {
    marking_worklists_local->MergeOnHold();

    PerformWrapperTracing();

    Tagged<HeapObject> heap_object;
    while (marking_worklists_local->Pop(&heap_object)) {
      DCHECK(!IsFreeSpaceOrFiller(heap_object, cage_base));
      DCHECK(IsHeapObject(heap_object));
      DCHECK(heap_->Contains(heap_object));
      DCHECK(!marking_state_->IsUnmarked(heap_object));
      // Maps won't change in the atomic pause, so the map can be read without
      // atomics.
      Tagged<Map> map = Cast<Map>(*heap_object->map_slot());
      const auto visited_size = main_marking_visitor_->Visit(map, heap_object);
      if (visited_size) {
        main_marking_visitor_->IncrementLiveBytesCached(
            MutablePageMetadata::FromHeapObject(heap_object),
            ALIGN_TO_ALLOCATION_ALIGNMENT(visited_size));
      }
    }
  } while (remembered_sets.ProcessNextItem(main_marking_visitor_.get()) ||
           !IsCppHeapMarkingFinished(heap_, marking_worklists_local));
}

void MinorMarkSweepCollector::TraceFragmentation() {
  PagedSpaceBase* new_space =
      v8_flags.sticky_mark_bits ? heap_->sticky_space()
                                : static_cast<PagedSpaceBase*>(
                                      heap_->paged_new_space()->paged_space());
  PtrComprCageBase cage_base(heap_->isolate());
  const std::array<size_t, 4> free_size_class_limits = {0, 1024, 2048, 4096};
  size_t free_bytes_of_class[free_size_class_limits.size()] = {0};
  size_t live_bytes = 0;
  size_t allocatable_bytes = 0;
  for (PageMetadata* p : *new_space) {
    Address free_start = p->area_start();
    for (auto [object, size] : LiveObjectRange(p)) {
      Address free_end = object.address();
      if (free_end != free_start) {
        size_t free_bytes = free_end - free_start;
        int free_bytes_index = 0;
        for (auto free_size_class_limit : free_size_class_limits) {
          if (free_bytes >= free_size_class_limit) {
            free_bytes_of_class[free_bytes_index] += free_bytes;
          }
          free_bytes_index++;
        }
      }
      live_bytes += size;
      free_start = free_end + size;
    }
    const Address top = heap_->NewSpaceTop();
    size_t area_end = p->Contains(top) ? top : p->area_end();
    if (free_start != area_end) {
      size_t free_bytes = area_end - free_start;
      int free_bytes_index = 0;
      for (auto free_size_class_limit : free_size_class_limits) {
        if (free_bytes >= free_size_class_limit) {
          free_bytes_of_class[free_bytes_index] += free_bytes;
        }
        free_bytes_index++;
      }
    }
    allocatable_bytes += area_end - p->area_start();
    CHECK_EQ(allocatable_bytes, live_bytes + free_bytes_of_class[0]);
  }
  PrintIsolate(heap_->isolate(),
               "Minor Mark-Sweep Fragmentation: allocatable_bytes=%zu "
               "live_bytes=%zu "
               "free_bytes=%zu free_bytes_1K=%zu free_bytes_2K=%zu "
               "free_bytes_4K=%zu\n",
               allocatable_bytes, live_bytes, free_bytes_of_class[0],
               free_bytes_of_class[1], free_bytes_of_class[2],
               free_bytes_of_class[3]);
}

namespace {

// NewSpacePages with more live bytes than this threshold qualify for fast
// evacuation.
intptr_t NewSpacePageEvacuationThreshold() {
  return v8_flags.minor_ms_page_promotion_threshold *
         MemoryChunkLayout::AllocatableMemoryInDataPage() / 100;
}

bool ShouldMovePage(PageMetadata* p, intptr_t live_bytes,
                    intptr_t wasted_bytes) {
  DCHECK(v8_flags.page_promotion);
  DCHECK(!v8_flags.sticky_mark_bits);
  Heap* heap = p->heap();
  DCHECK(!p->Chunk()->NeverEvacuate());
  const bool should_move_page =
      ((live_bytes + wasted_bytes) > NewSpacePageEvacuationThreshold() ||
       (p->AllocatedLabSize() == 0)) &&
      (heap->new_space()->IsPromotionCandidate(p)) &&
      heap->CanExpandOldGeneration(live_bytes);
  if (v8_flags.trace_page_promotions) {
    PrintIsolate(
        heap->isolate(),
        "[Page Promotion] %p: collector=mms, should move: %d"
        ", live bytes = %zu, wasted bytes = %zu, promotion threshold = %zu"
        ", allocated labs size = %zu\n",
        p, should_move_page, live_bytes, wasted_bytes,
        NewSpacePageEvacuationThreshold(), p->AllocatedLabSize());
  }
  if (!should_move_page &&
      (p->AgeInNewSpace() == v8_flags.minor_ms_max_page_age)) {
    // Don't allocate on old pages so that recently allocated objects on the
    // page get a chance to die young. The page will be force promoted on the
    // next GC because `AllocatedLabSize` will be 0.
    p->Chunk()->SetFlagNonExecutable(MemoryChunk::NEVER_ALLOCATE_ON_PAGE);
  }
  return should_move_page;
}

}  // namespace

void MinorMarkSweepCollector::EvacuateExternalPointerReferences(
    MutablePageMetadata* p) {
```