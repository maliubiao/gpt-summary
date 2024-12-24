Response: Let's break down the thought process for summarizing the C++ code and relating it to JavaScript.

1. **Understand the Core Request:** The request asks for a summary of the `scavenger.cc` file's functionality and how it relates to JavaScript. This means identifying the main purpose of the code and finding connections to the high-level language JavaScript.

2. **Initial Skim and Keyword Spotting:** Quickly scan the code, looking for recognizable terms and patterns. Keywords like "scavenger," "heap," "garbage collection," "promotion," "young generation," "old generation," "roots," "slots," and "memory" stand out. The inclusion of header files like `heap-inl.h`, `gc-tracer.h`, and `objects/` further reinforces the idea of memory management and object handling.

3. **Identify the Main Actor:** The file is named `scavenger.cc`, and the `Scavenger` class is central. The `ScavengerCollector` class also appears to be a key component, managing the scavenging process.

4. **Focus on the "What":**  Try to answer the question: "What does this code *do*?". The code clearly deals with a garbage collection mechanism. The terms "young generation" and "old generation" suggest a generational garbage collector. The process involves moving objects ("scavenging," "promotion," "copying"). The code interacts with the heap to manage memory.

5. **Extract Key Functions and Processes:**  As you read more carefully, identify the main steps or phases involved in the scavenging process. The code mentions:
    * **Root Scavenging:** Processing roots (starting points of object graphs).
    * **Parallel Scavenging:**  Utilizing multiple threads for efficiency.
    * **Object Copying/Promotion:** Moving objects between memory areas.
    * **Weak Reference Handling:**  Dealing with weak references.
    * **Finalization:**  Completing the scavenging process.
    * **Remembered Sets:** Tracking pointers between generations.
    * **Ephemerons:** Handling weak key-value pairs.

6. **Infer the "Why":**  Why does this process exist?  Garbage collection is essential for automatic memory management in languages like JavaScript. The generational approach aims to optimize collection by focusing on areas where objects are more likely to become garbage quickly (the "young generation"). Parallelism aims to improve performance.

7. **Connect to JavaScript (the Tricky Part):** This requires understanding how the C++ code supports JavaScript's behavior. Key connections include:
    * **Memory Management:**  JavaScript has automatic garbage collection; this C++ code is part of *how* that happens under the hood in V8.
    * **Object Lifecycles:** The young/old generation concept mirrors how JavaScript objects tend to have short or long lifespans.
    * **Weak References:** JavaScript has `WeakRef` and `WeakMap/WeakSet`. The C++ code needs to handle these.
    * **Performance:** The parallel processing directly impacts JavaScript's execution speed.

8. **Construct the Summary (Iterative Refinement):** Start writing a high-level overview. Then, add more detail about the key functions and processes identified earlier.

9. **Illustrate with JavaScript Examples:** This is crucial for showing the connection. Think about JavaScript features that directly relate to the concepts in the C++ code:
    * **Object Creation and Garbage Collection:** Simple examples of object creation demonstrate the need for garbage collection.
    * **Weak References:**  Show how `WeakRef` allows objects to be collected even if they are referenced weakly.
    * **Performance Implications (Implicit):** While you can't directly show the C++ parallelization in JS, you can discuss how efficient garbage collection contributes to a smoother user experience.

10. **Refine and Organize:**  Review the summary for clarity, accuracy, and completeness. Organize the information logically, starting with the high-level purpose and then going into more specific details. Ensure the JavaScript examples are clear and directly relevant. Use clear headings and bullet points to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about freeing memory."  **Correction:**  It's more nuanced than simple freeing. Generational collection, promotion, and weak reference handling are important aspects.
* **Struggling with the JavaScript connection:**  Think about *what* the C++ code manages and *how* that manifests in JavaScript. Memory management for objects is the core link.
* **Too much technical detail:**  The summary should be understandable to someone with a general understanding of garbage collection, not necessarily a V8 internals expert. Focus on the *what* and *why* more than the *how* of the C++ implementation details. Keep the JavaScript examples simple.

By following this iterative process of understanding, extracting, connecting, and refining, you can arrive at a comprehensive and accurate summary of the C++ code and its relationship to JavaScript.
这个C++源代码文件 `v8/src/heap/scavenger.cc` 实现了 V8 JavaScript 引擎中的 **Scavenger 垃圾回收器**。

**功能归纳:**

1. **新生代垃圾回收 (Young Generation Garbage Collection):** Scavenger 的主要职责是回收新生代（New Space）中的垃圾对象。新生代用于存放新创建的短期存活对象。
2. **复制式回收 (Copying Collection):** Scavenger 使用复制式的垃圾回收算法。这意味着它将存活的对象从 "From Space" 复制到 "To Space"，然后清空整个 "From Space"。
3. **晋升 (Promotion):**  在 Scavenger 过程中，仍然存活一定次数或满足特定条件的对象会被 **晋升** 到老年代 (Old Space)。这样老年代的对象可以避免频繁的垃圾回收。
4. **根扫描 (Root Scanning):** Scavenger 从一组被称为 "根" 的对象开始扫描，这些根对象是永远存活的。通过遍历根对象的可达对象，Scavenger 可以确定哪些对象是存活的。
5. **并行处理 (Parallel Processing):** 为了提高效率，Scavenger 能够以并行的方式执行部分垃圾回收任务，利用多核处理器的能力。
6. **弱引用处理 (Weak Reference Handling):** Scavenger 能够正确处理弱引用（例如 `WeakMap`, `WeakSet` 中的键），在垃圾回收时判断弱引用指向的对象是否存活。
7. **处理老年代到新生代的引用 (Remembered Sets):** 为了高效地找到老年代对象对新生代对象的引用，Scavenger 利用了 "Remembered Sets" 记录这些跨代引用，避免扫描整个老年代。
8. **处理新生代大对象 (New Large Object Space):** Scavenger 也负责管理新生代的大对象空间，并将其中的存活对象晋升到老年代的大对象空间。
9. **与标记-清除回收器的协同 (Integration with Mark-Compact):** Scavenger 与负责老年代垃圾回收的标记-清除（Mark-Compact）回收器协同工作。例如，当新生代对象晋升到老年代时，需要通知标记-清除回收器。
10. **性能优化 (Performance Optimizations):** 文件中包含了许多针对 Scavenger 性能的优化措施，例如预分配 (pretenuring)、并行处理等。

**与 JavaScript 的功能关系及示例:**

Scavenger 的工作对 JavaScript 开发者来说是透明的，但它直接影响着 JavaScript 代码的执行效率和内存管理。每当我们创建 JavaScript 对象时，这些对象最初都会分配在新生代中，并可能被 Scavenger 回收或晋升。

**JavaScript 示例:**

```javascript
// 创建一些对象，这些对象会分配在新生代中
let obj1 = { name: 'object1' };
let obj2 = { data: [1, 2, 3] };
let obj3 = function() { console.log('hello'); };

// 让 obj1 存活一段时间，可能被 Scavenger 回收，也可能晋升到老年代
setTimeout(() => {
  console.log(obj1.name);
}, 1000);

// obj2 的生命周期可能较短，更容易被 Scavenger 回收
obj2 = null;

// 创建一个弱引用
let weakRef = new WeakRef(obj3);

// 在 Scavenger 执行后，如果 obj3 没有被其他强引用引用，
// weakRef.deref() 可能返回 undefined
setTimeout(() => {
  console.log(weakRef.deref()); // 可能输出 undefined
}, 2000);

// 创建一个长期存活的对象，它更有可能被晋升到老年代
let longLivedObject = {};
for (let i = 0; i < 100000; i++) {
  longLivedObject[i] = i;
}
```

**解释:**

* 当我们创建 `obj1`, `obj2`, `obj3` 和 `longLivedObject` 时，V8 的内存分配器会在新生代中为它们分配空间。
* Scavenger 会定期运行，检查新生代中的对象是否仍然被引用。
* `obj2` 被设置为 `null`，使其不再被引用，很可能在下一次 Scavenger 运行中被回收。
* `obj1` 因为被 `setTimeout` 回调函数引用，可能会存活更久，甚至被晋升到老年代。
* `weakRef` 创建了一个对 `obj3` 的弱引用。如果 `obj3` 没有其他强引用，Scavenger 在运行时会认为 `obj3` 可以被回收，即使 `weakRef` 仍然存在。
* `longLivedObject` 由于被大量使用，存活时间很长，很有可能在 Scavenger 的多次运行后被晋升到老年代，从而减少被频繁回收的次数。

**总结:**

`v8/src/heap/scavenger.cc` 文件定义了 V8 引擎中负责高效回收新生代垃圾的关键组件。它的工作对 JavaScript 程序员来说是无感的，但它是实现 JavaScript 自动内存管理和保证程序运行效率的重要基石。通过复制、晋升、并行处理和弱引用处理等技术，Scavenger 能够有效地管理新生代内存，并与老年代垃圾回收器协同工作，确保整个 JavaScript 堆的健康运行。

Prompt: 
```
这是目录为v8/src/heap/scavenger.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/scavenger.h"

#include <atomic>
#include <optional>

#include "src/common/globals.h"
#include "src/handles/global-handles.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/ephemeron-remembered-set.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-visitor-inl.h"
#include "src/heap/heap.h"
#include "src/heap/large-page-metadata-inl.h"
#include "src/heap/mark-compact-inl.h"
#include "src/heap/mark-compact.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/mutable-page-metadata-inl.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/pretenuring-handler.h"
#include "src/heap/remembered-set-inl.h"
#include "src/heap/scavenger-inl.h"
#include "src/heap/slot-set.h"
#include "src/heap/sweeper.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/embedder-data-array-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/objects-body-descriptors-inl.h"
#include "src/objects/slots.h"
#include "src/objects/transitions-inl.h"
#include "src/utils/utils-inl.h"

namespace v8 {
namespace internal {

class IterateAndScavengePromotedObjectsVisitor final
    : public HeapVisitor<IterateAndScavengePromotedObjectsVisitor> {
 public:
  IterateAndScavengePromotedObjectsVisitor(Scavenger* scavenger,
                                           bool record_slots)
      : HeapVisitor(scavenger->heap()->isolate()),
        scavenger_(scavenger),
        record_slots_(record_slots) {}

  V8_INLINE static constexpr bool ShouldUseUncheckedCast() { return true; }

  V8_INLINE static constexpr bool UsePrecomputedObjectSize() { return true; }

  V8_INLINE void VisitMapPointer(Tagged<HeapObject> host) final {
    if (!record_slots_) return;
    MapWord map_word = host->map_word(kRelaxedLoad);
    if (map_word.IsForwardingAddress()) {
      // Surviving new large objects have forwarding pointers in the map word.
      DCHECK(MemoryChunk::FromHeapObject(host)->InNewLargeObjectSpace());
      return;
    }
    HandleSlot(host, HeapObjectSlot(host->map_slot()), map_word.ToMap());
  }

  V8_INLINE void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                               ObjectSlot end) final {
    VisitPointersImpl(host, start, end);
  }

  V8_INLINE void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                               MaybeObjectSlot end) final {
    VisitPointersImpl(host, start, end);
  }

  inline void VisitEphemeron(Tagged<HeapObject> obj, int entry, ObjectSlot key,
                             ObjectSlot value) override {
    DCHECK(Heap::IsLargeObject(obj) || IsEphemeronHashTable(obj));
    VisitPointer(obj, value);

    if (HeapLayout::InYoungGeneration(*key)) {
      // We cannot check the map here, as it might be a large object.
      scavenger_->RememberPromotedEphemeron(
          UncheckedCast<EphemeronHashTable>(obj), entry);
    } else {
      VisitPointer(obj, key);
    }
  }

  void VisitExternalPointer(Tagged<HeapObject> host,
                            ExternalPointerSlot slot) override {
#ifdef V8_COMPRESS_POINTERS
    DCHECK_NE(slot.tag(), kExternalPointerNullTag);
    DCHECK(!IsSharedExternalPointerType(slot.tag()));
    // TODO(chromium:337580006): Remove when pointer compression always uses
    // EPT.
    if (!slot.HasExternalPointerHandle()) return;
    ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
    Heap* heap = scavenger_->heap();
    ExternalPointerTable& table = heap->isolate()->external_pointer_table();

    // For survivor objects, the scavenger marks their EPT entries when they are
    // copied and then sweeps the young EPT space at the end of collection,
    // reclaiming unmarked EPT entries.  (Exception: if an incremental mark is
    // in progress, the scavenger neither marks nor sweeps, as it will be the
    // major GC's responsibility.)
    //
    // However when promoting, we just evacuate the entry from new to old space.
    // Usually the entry will be unmarked, unless an incremental mark is in
    // progress, or the slot was initialized since the last GC (external pointer
    // tags have the mark bit set), in which case it may be marked already.  In
    // any case, transfer the color from new to old EPT space.
    table.Evacuate(heap->young_external_pointer_space(),
                   heap->old_external_pointer_space(), handle, slot.address(),
                   ExternalPointerTable::EvacuateMarkMode::kTransferMark);
#endif  // V8_COMPRESS_POINTERS
  }

  // Special cases: Unreachable visitors for objects that are never found in the
  // young generation and thus cannot be found when iterating promoted objects.
  void VisitInstructionStreamPointer(Tagged<Code>,
                                     InstructionStreamSlot) final {
    UNREACHABLE();
  }
  void VisitCodeTarget(Tagged<InstructionStream>, RelocInfo*) final {
    UNREACHABLE();
  }
  void VisitEmbeddedPointer(Tagged<InstructionStream>, RelocInfo*) final {
    UNREACHABLE();
  }

 private:
  template <typename TSlot>
  V8_INLINE void VisitPointersImpl(Tagged<HeapObject> host, TSlot start,
                                   TSlot end) {
    using THeapObjectSlot = typename TSlot::THeapObjectSlot;
    // Treat weak references as strong.
    // TODO(marja): Proper weakness handling in the young generation.
    for (TSlot slot = start; slot < end; ++slot) {
      typename TSlot::TObject object = *slot;
      Tagged<HeapObject> heap_object;
      if (object.GetHeapObject(&heap_object)) {
        HandleSlot(host, THeapObjectSlot(slot), heap_object);
      }
    }
  }

  template <typename THeapObjectSlot>
  V8_INLINE void HandleSlot(Tagged<HeapObject> host, THeapObjectSlot slot,
                            Tagged<HeapObject> target) {
    static_assert(
        std::is_same<THeapObjectSlot, FullHeapObjectSlot>::value ||
            std::is_same<THeapObjectSlot, HeapObjectSlot>::value,
        "Only FullHeapObjectSlot and HeapObjectSlot are expected here");
    scavenger_->PageMemoryFence(target);

    if (Heap::InFromPage(target)) {
      SlotCallbackResult result = scavenger_->ScavengeObject(slot, target);
      bool success = (*slot).GetHeapObject(&target);
      USE(success);
      DCHECK(success);

      if (result == KEEP_SLOT) {
        SLOW_DCHECK(IsHeapObject(target));
        MemoryChunk* chunk = MemoryChunk::FromHeapObject(host);
        MutablePageMetadata* page =
            MutablePageMetadata::cast(chunk->Metadata());

        // Sweeper is stopped during scavenge, so we can directly
        // insert into its remembered set here.
        RememberedSet<OLD_TO_NEW>::Insert<AccessMode::ATOMIC>(
            page, chunk->Offset(slot.address()));
      }
      DCHECK(!MarkCompactCollector::IsOnEvacuationCandidate(target));
    } else if (record_slots_ &&
               MarkCompactCollector::IsOnEvacuationCandidate(target)) {
      // We should never try to record off-heap slots.
      DCHECK((std::is_same<THeapObjectSlot, HeapObjectSlot>::value));
      // InstructionStream slots never appear in new space because
      // Code objects, the only object that can contain code pointers, are
      // always allocated in the old space.
      DCHECK_IMPLIES(V8_EXTERNAL_CODE_SPACE_BOOL,
                     !MemoryChunk::FromHeapObject(target)->IsFlagSet(
                         MemoryChunk::IS_EXECUTABLE));

      // We cannot call MarkCompactCollector::RecordSlot because that checks
      // that the host page is not in young generation, which does not hold
      // for pending large pages.
      MemoryChunk* chunk = MemoryChunk::FromHeapObject(host);
      MutablePageMetadata* page = MutablePageMetadata::cast(chunk->Metadata());
      RememberedSet<OLD_TO_OLD>::Insert<AccessMode::ATOMIC>(
          page, chunk->Offset(slot.address()));
    }

    if (HeapLayout::InWritableSharedSpace(target)) {
      MemoryChunk* chunk = MemoryChunk::FromHeapObject(host);
      MutablePageMetadata* page = MutablePageMetadata::cast(chunk->Metadata());
      RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::ATOMIC>(
          page, chunk->Offset(slot.address()));
    }
  }

  Scavenger* const scavenger_;
  const bool record_slots_;
};

namespace {

V8_INLINE bool IsUnscavengedHeapObject(Heap* heap, Tagged<Object> object) {
  return Heap::InFromPage(object) && !Cast<HeapObject>(object)
                                          ->map_word(kRelaxedLoad)
                                          .IsForwardingAddress();
}

// Same as IsUnscavengedHeapObject() above but specialized for HeapObjects.
V8_INLINE bool IsUnscavengedHeapObject(Heap* heap,
                                       Tagged<HeapObject> heap_object) {
  return Heap::InFromPage(heap_object) &&
         !heap_object->map_word(kRelaxedLoad).IsForwardingAddress();
}

bool IsUnscavengedHeapObjectSlot(Heap* heap, FullObjectSlot p) {
  return IsUnscavengedHeapObject(heap, *p);
}

}  // namespace

ScavengerCollector::JobTask::JobTask(
    ScavengerCollector* collector,
    std::vector<std::unique_ptr<Scavenger>>* scavengers,
    std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
        old_to_new_chunks,
    const Scavenger::CopiedList& copied_list,
    const Scavenger::PromotionList& promotion_list)
    : collector_(collector),
      scavengers_(scavengers),
      old_to_new_chunks_(std::move(old_to_new_chunks)),
      remaining_memory_chunks_(old_to_new_chunks_.size()),
      generator_(old_to_new_chunks_.size()),
      copied_list_(copied_list),
      promotion_list_(promotion_list),
      trace_id_(reinterpret_cast<uint64_t>(this) ^
                collector_->heap_->tracer()->CurrentEpoch(
                    GCTracer::Scope::SCAVENGER)) {}

void ScavengerCollector::JobTask::Run(JobDelegate* delegate) {
  DCHECK_LT(delegate->GetTaskId(), scavengers_->size());
  // In case multi-cage pointer compression mode is enabled ensure that
  // current thread's cage base values are properly initialized.
  PtrComprCageAccessScope ptr_compr_cage_access_scope(
      collector_->heap_->isolate());

  collector_->estimate_concurrency_.fetch_add(1, std::memory_order_relaxed);

  Scavenger* scavenger = (*scavengers_)[delegate->GetTaskId()].get();
  if (delegate->IsJoiningThread()) {
    TRACE_GC_WITH_FLOW(collector_->heap_->tracer(),
                       GCTracer::Scope::SCAVENGER_SCAVENGE_PARALLEL, trace_id_,
                       TRACE_EVENT_FLAG_FLOW_IN);
    ProcessItems(delegate, scavenger);
  } else {
    TRACE_GC_EPOCH_WITH_FLOW(
        collector_->heap_->tracer(),
        GCTracer::Scope::SCAVENGER_BACKGROUND_SCAVENGE_PARALLEL,
        ThreadKind::kBackground, trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    ProcessItems(delegate, scavenger);
  }
}

size_t ScavengerCollector::JobTask::GetMaxConcurrency(
    size_t worker_count) const {
  // We need to account for local segments held by worker_count in addition to
  // GlobalPoolSize() of copied_list_ and promotion_list_.
  size_t wanted_num_workers = std::max<size_t>(
      remaining_memory_chunks_.load(std::memory_order_relaxed),
      worker_count + copied_list_.Size() + promotion_list_.Size());
  if (!collector_->heap_->ShouldUseBackgroundThreads() ||
      collector_->heap_->ShouldOptimizeForBattery()) {
    return std::min<size_t>(wanted_num_workers, 1);
  }
  return std::min<size_t>(scavengers_->size(), wanted_num_workers);
}

void ScavengerCollector::JobTask::ProcessItems(JobDelegate* delegate,
                                               Scavenger* scavenger) {
  double scavenging_time = 0.0;
  {
    TimedScope scope(&scavenging_time);
    ConcurrentScavengePages(scavenger);
    scavenger->Process(delegate);
  }
  if (V8_UNLIKELY(v8_flags.trace_parallel_scavenge)) {
    PrintIsolate(collector_->heap_->isolate(),
                 "scavenge[%p]: time=%.2f copied=%zu promoted=%zu\n",
                 static_cast<void*>(this), scavenging_time,
                 scavenger->bytes_copied(), scavenger->bytes_promoted());
  }
}

void ScavengerCollector::JobTask::ConcurrentScavengePages(
    Scavenger* scavenger) {
  while (remaining_memory_chunks_.load(std::memory_order_relaxed) > 0) {
    std::optional<size_t> index = generator_.GetNext();
    if (!index) {
      return;
    }
    for (size_t i = *index; i < old_to_new_chunks_.size(); ++i) {
      auto& work_item = old_to_new_chunks_[i];
      if (!work_item.first.TryAcquire()) {
        break;
      }
      scavenger->ScavengePage(work_item.second);
      if (remaining_memory_chunks_.fetch_sub(1, std::memory_order_relaxed) <=
          1) {
        return;
      }
    }
  }
}

ScavengerCollector::ScavengerCollector(Heap* heap)
    : isolate_(heap->isolate()), heap_(heap) {}

namespace {

// Helper class for updating weak global handles. There's no additional scavenge
// processing required here as this phase runs after actual scavenge.
class GlobalHandlesWeakRootsUpdatingVisitor final : public RootVisitor {
 public:
  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) final {
    UpdatePointer(p);
  }
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) final {
    for (FullObjectSlot p = start; p < end; ++p) {
      UpdatePointer(p);
    }
  }

 private:
  void UpdatePointer(FullObjectSlot p) {
    Tagged<Object> object = *p;
    DCHECK(!HasWeakHeapObjectTag(object));
    // The object may be in the old generation as global handles over
    // approximates the list of young nodes. This checks also bails out for
    // Smis.
    if (!HeapLayout::InYoungGeneration(object)) {
      return;
    }

    Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
    // TODO(chromium:1336158): Turn the following CHECKs into DCHECKs after
    // flushing out potential issues.
    CHECK(Heap::InFromPage(heap_object));
    MapWord first_word = heap_object->map_word(kRelaxedLoad);
    CHECK(first_word.IsForwardingAddress());
    Tagged<HeapObject> dest = first_word.ToForwardingAddress(heap_object);
    UpdateHeapObjectReferenceSlot(FullHeapObjectSlot(p), dest);
    CHECK_IMPLIES(HeapLayout::InYoungGeneration(dest),
                  Heap::InToPage(dest) || Heap::IsLargeObject(dest));
  }
};

}  // namespace

// Remove this crashkey after chromium:1010312 is fixed.
class V8_NODISCARD ScopedFullHeapCrashKey {
 public:
  explicit ScopedFullHeapCrashKey(Isolate* isolate) : isolate_(isolate) {
    isolate_->AddCrashKey(v8::CrashKeyId::kDumpType, "heap");
  }
  ~ScopedFullHeapCrashKey() {
    isolate_->AddCrashKey(v8::CrashKeyId::kDumpType, "");
  }

 private:
  Isolate* isolate_ = nullptr;
};

void ScavengerCollector::CollectGarbage() {
  ScopedFullHeapCrashKey collect_full_heap_dump_if_crash(isolate_);

  auto* new_space = SemiSpaceNewSpace::From(heap_->new_space());
  new_space->GarbageCollectionPrologue();
  new_space->EvacuatePrologue();

  // We also flip the young generation large object space. All large objects
  // will be in the from space.
  heap_->new_lo_space()->Flip();
  heap_->new_lo_space()->ResetPendingObject();

  DCHECK(!heap_->allocator()->new_space_allocator()->IsLabValid());

  DCHECK(surviving_new_large_objects_.empty());

  Scavenger::EmptyChunksList empty_chunks;
  Scavenger::CopiedList copied_list;
  Scavenger::PromotionList promotion_list;
  EphemeronRememberedSet::TableList ephemeron_table_list;

  const int num_scavenge_tasks = NumberOfScavengeTasks();
  std::vector<std::unique_ptr<Scavenger>> scavengers;
  {
    const bool is_logging = isolate_->log_object_relocation();
    for (int i = 0; i < num_scavenge_tasks; ++i) {
      scavengers.emplace_back(
          new Scavenger(this, heap_, is_logging, &empty_chunks, &copied_list,
                        &promotion_list, &ephemeron_table_list));
    }
    Scavenger& main_thread_scavenger = *scavengers[kMainThreadId].get();

    {
      // Identify weak unmodified handles. Requires an unmodified graph.
      TRACE_GC(
          heap_->tracer(),
          GCTracer::Scope::SCAVENGER_SCAVENGE_WEAK_GLOBAL_HANDLES_IDENTIFY);
      isolate_->traced_handles()->ComputeWeaknessForYoungObjects();
    }

    std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
        old_to_new_chunks;
    {
      // Copy roots.
      TRACE_GC(heap_->tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE_ROOTS);
      // Scavenger treats all weak roots except for global handles as strong.
      // That is why we don't set skip_weak = true here and instead visit
      // global handles separately.
      base::EnumSet<SkipRoot> options(
          {SkipRoot::kExternalStringTable, SkipRoot::kGlobalHandles,
           SkipRoot::kTracedHandles, SkipRoot::kOldGeneration,
           SkipRoot::kConservativeStack, SkipRoot::kReadOnlyBuiltins});
      if (V8_UNLIKELY(v8_flags.scavenge_separate_stack_scanning)) {
        options.Add(SkipRoot::kStack);
      }
      RootScavengeVisitor root_scavenge_visitor(main_thread_scavenger);

      // We must collect old-to-new pages before starting Scavenge because pages
      // could be removed from the old generation for allocation which hides
      // them from the iteration.
      OldGenerationMemoryChunkIterator::ForAll(
          heap_, [&old_to_new_chunks](MutablePageMetadata* chunk) {
            if (chunk->slot_set<OLD_TO_NEW>() ||
                chunk->typed_slot_set<OLD_TO_NEW>() ||
                chunk->slot_set<OLD_TO_NEW_BACKGROUND>()) {
              old_to_new_chunks.emplace_back(ParallelWorkItem{}, chunk);
            }
          });

      heap_->IterateRoots(&root_scavenge_visitor, options);
      isolate_->global_handles()->IterateYoungStrongAndDependentRoots(
          &root_scavenge_visitor);
      isolate_->traced_handles()->IterateYoungRoots(&root_scavenge_visitor);
    }
    {
      // Parallel phase scavenging all copied and promoted objects.
      TRACE_GC_ARG1(
          heap_->tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE_PARALLEL_PHASE,
          "UseBackgroundThreads", heap_->ShouldUseBackgroundThreads());

      auto job = std::make_unique<JobTask>(this, &scavengers,
                                           std::move(old_to_new_chunks),
                                           copied_list, promotion_list);
      TRACE_GC_NOTE_WITH_FLOW("Parallel scavenge started", job->trace_id(),
                              TRACE_EVENT_FLAG_FLOW_OUT);
      V8::GetCurrentPlatform()
          ->CreateJob(v8::TaskPriority::kUserBlocking, std::move(job))
          ->Join();
      DCHECK(copied_list.IsEmpty());
      DCHECK(promotion_list.IsEmpty());
    }

    if (V8_UNLIKELY(v8_flags.scavenge_separate_stack_scanning)) {
      {
        RootScavengeVisitor root_scavenge_visitor(main_thread_scavenger);
        IterateStackAndScavenge(&root_scavenge_visitor, &scavengers,
                                main_thread_scavenger);
      }
      DCHECK(copied_list.IsEmpty());
      DCHECK(promotion_list.IsEmpty());
    }

    {
      // Scavenge weak global handles.
      TRACE_GC(heap_->tracer(),
               GCTracer::Scope::SCAVENGER_SCAVENGE_WEAK_GLOBAL_HANDLES_PROCESS);
      GlobalHandlesWeakRootsUpdatingVisitor visitor;
      isolate_->global_handles()->ProcessWeakYoungObjects(
          &visitor, &IsUnscavengedHeapObjectSlot);
      isolate_->traced_handles()->ProcessYoungObjects(
          &visitor, &IsUnscavengedHeapObjectSlot);
    }

    {
      // Finalize parallel scavenging.
      TRACE_GC(heap_->tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE_FINALIZE);

      DCHECK(surviving_new_large_objects_.empty());

      for (auto& scavenger : scavengers) {
        scavenger->Finalize();
      }
      scavengers.clear();

#ifdef V8_COMPRESS_POINTERS
      // Sweep the external pointer table, unless an incremental mark is in
      // progress, in which case leave sweeping to the end of the
      // already-scheduled major GC cycle.  (If we swept here we'd clear EPT
      // marks that the major marker was using, which would be an error.)
      DCHECK(heap_->concurrent_marking()->IsStopped());
      if (!heap_->incremental_marking()->IsMajorMarking()) {
        heap_->isolate()->external_pointer_table().Sweep(
            heap_->young_external_pointer_space(),
            heap_->isolate()->counters());
      }
#endif  // V8_COMPRESS_POINTERS

      HandleSurvivingNewLargeObjects();

      heap_->tracer()->SampleConcurrencyEsimate(
          FetchAndResetConcurrencyEstimate());
    }
  }

  {
    // Update references into new space
    TRACE_GC(heap_->tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE_UPDATE_REFS);
    heap_->UpdateYoungReferencesInExternalStringTable(
        &Heap::UpdateYoungReferenceInExternalStringTableEntry);

    heap_->incremental_marking()->UpdateMarkingWorklistAfterScavenge();
    heap_->incremental_marking()->UpdateExternalPointerTableAfterScavenge();

    if (V8_UNLIKELY(v8_flags.always_use_string_forwarding_table)) {
      isolate_->string_forwarding_table()->UpdateAfterYoungEvacuation();
    }
  }

  SemiSpaceNewSpace* semi_space_new_space =
      SemiSpaceNewSpace::From(heap_->new_space());

  if (v8_flags.concurrent_marking) {
    // Ensure that concurrent marker does not track pages that are
    // going to be unmapped.
    for (PageMetadata* p :
         PageRange(semi_space_new_space->from_space().first_page(), nullptr)) {
      heap_->concurrent_marking()->ClearMemoryChunkData(p);
    }
  }

  ProcessWeakReferences(&ephemeron_table_list);

  // Need to free new space LAB that was allocated during scavenge.
  heap_->allocator()->new_space_allocator()->FreeLinearAllocationArea();

  new_space->GarbageCollectionEpilogue();

  // Since we promote all surviving large objects immediately, all remaining
  // large objects must be dead.
  // TODO(hpayer): Don't free all as soon as we have an intermediate generation.
  heap_->new_lo_space()->FreeDeadObjects(
      [](Tagged<HeapObject>) { return true; });

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::SCAVENGER_FREE_REMEMBERED_SET);
    Scavenger::EmptyChunksList::Local empty_chunks_local(empty_chunks);
    MutablePageMetadata* chunk;
    while (empty_chunks_local.Pop(&chunk)) {
      // Since sweeping was already restarted only check chunks that already got
      // swept.
      if (chunk->SweepingDone()) {
        RememberedSet<OLD_TO_NEW>::CheckPossiblyEmptyBuckets(chunk);
        RememberedSet<OLD_TO_NEW_BACKGROUND>::CheckPossiblyEmptyBuckets(chunk);
      } else {
        chunk->possibly_empty_buckets()->Release();
      }
    }

#ifdef DEBUG
    OldGenerationMemoryChunkIterator::ForAll(
        heap_, [](MutablePageMetadata* chunk) {
          if (chunk->slot_set<OLD_TO_NEW>() ||
              chunk->typed_slot_set<OLD_TO_NEW>() ||
              chunk->slot_set<OLD_TO_NEW_BACKGROUND>()) {
            DCHECK(chunk->possibly_empty_buckets()->IsEmpty());
          }
        });
#endif
  }

  SweepArrayBufferExtensions();

  isolate_->global_handles()->UpdateListOfYoungNodes();
  isolate_->traced_handles()->UpdateListOfYoungNodes();

  // Update how much has survived scavenge.
  heap_->IncrementYoungSurvivorsCounter(heap_->SurvivedYoungObjectSize());

  const auto resize_mode = heap_->ShouldResizeNewSpace();
  switch (resize_mode) {
    case Heap::ResizeNewSpaceMode::kShrink:
      heap_->ReduceNewSpaceSize();
      break;
    case Heap::ResizeNewSpaceMode::kGrow:
      heap_->ExpandNewSpaceSize();
      break;
    case Heap::ResizeNewSpaceMode::kNone:
      break;
  }
}

void ScavengerCollector::IterateStackAndScavenge(
    RootScavengeVisitor* root_scavenge_visitor,
    std::vector<std::unique_ptr<Scavenger>>* scavengers,
    Scavenger& main_thread_scavenger) {
  // Scan the stack, scavenge the newly discovered objects, and report
  // the survival statistics before and after the stack scanning.
  // This code is not intended for production.
  TRACE_GC(heap_->tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE_STACK_ROOTS);
  const auto sum_survived_bytes = [](size_t count, auto& scavenger) {
    return count + scavenger->bytes_copied() + scavenger->bytes_promoted();
  };
  const size_t survived_bytes_before = std::accumulate(
      scavengers->begin(), scavengers->end(), 0, sum_survived_bytes);
  heap_->IterateStackRoots(root_scavenge_visitor);
  main_thread_scavenger.Process();
  const size_t survived_bytes_after = std::accumulate(
      scavengers->begin(), scavengers->end(), 0, sum_survived_bytes);
  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
               "V8.GCScavengerStackScanning", "survived_bytes_before",
               survived_bytes_before, "survived_bytes_after",
               survived_bytes_after);
  if (v8_flags.trace_gc_verbose && !v8_flags.trace_gc_ignore_scavenger) {
    isolate_->PrintWithTimestamp(
        "Scavenge stack scanning: survived_before=%4zuKB, "
        "survived_after=%4zuKB delta=%.1f%%\n",
        survived_bytes_before / KB, survived_bytes_after / KB,
        (survived_bytes_after - survived_bytes_before) * 100.0 /
            survived_bytes_after);
  }
}

void ScavengerCollector::SweepArrayBufferExtensions() {
  DCHECK_EQ(0, heap_->new_lo_space()->Size());
  heap_->array_buffer_sweeper()->RequestSweep(
      ArrayBufferSweeper::SweepingType::kYoung,
      (heap_->new_space()->Size() == 0)
          ? ArrayBufferSweeper::TreatAllYoungAsPromoted::kYes
          : ArrayBufferSweeper::TreatAllYoungAsPromoted::kNo);
}

void ScavengerCollector::HandleSurvivingNewLargeObjects() {
  const bool is_compacting = heap_->incremental_marking()->IsCompacting();
  MarkingState* marking_state = heap_->marking_state();

  for (SurvivingNewLargeObjectMapEntry update_info :
       surviving_new_large_objects_) {
    Tagged<HeapObject> object = update_info.first;
    Tagged<Map> map = update_info.second;
    // Order is important here. We have to re-install the map to have access
    // to meta-data like size during page promotion.
    object->set_map_word(map, kRelaxedStore);

    if (is_compacting && marking_state->IsMarked(object) &&
        MarkCompactCollector::IsOnEvacuationCandidate(map)) {
      MemoryChunk* chunk = MemoryChunk::FromHeapObject(object);
      MutablePageMetadata* page = MutablePageMetadata::cast(chunk->Metadata());
      RememberedSet<OLD_TO_OLD>::Insert<AccessMode::ATOMIC>(
          page, chunk->Offset(object->map_slot().address()));
    }
    LargePageMetadata* page = LargePageMetadata::FromHeapObject(object);
    heap_->lo_space()->PromoteNewLargeObject(page);
  }
  surviving_new_large_objects_.clear();
  heap_->new_lo_space()->set_objects_size(0);
}

void ScavengerCollector::MergeSurvivingNewLargeObjects(
    const SurvivingNewLargeObjectsMap& objects) {
  for (SurvivingNewLargeObjectMapEntry object : objects) {
    bool success = surviving_new_large_objects_.insert(object).second;
    USE(success);
    DCHECK(success);
  }
}

int ScavengerCollector::NumberOfScavengeTasks() {
  if (!v8_flags.parallel_scavenge) {
    return 1;
  }
  const int num_scavenge_tasks =
      static_cast<int>(
          SemiSpaceNewSpace::From(heap_->new_space())->TotalCapacity()) /
          MB +
      1;
  static int num_cores = V8::GetCurrentPlatform()->NumberOfWorkerThreads() + 1;
  int tasks = std::max(
      1, std::min({num_scavenge_tasks, kMaxScavengerTasks, num_cores}));
  if (!heap_->CanPromoteYoungAndExpandOldGeneration(
          static_cast<size_t>(tasks * PageMetadata::kPageSize))) {
    // Optimize for memory usage near the heap limit.
    tasks = 1;
  }
  return tasks;
}

Scavenger::PromotionList::Local::Local(Scavenger::PromotionList* promotion_list)
    : regular_object_promotion_list_local_(
          promotion_list->regular_object_promotion_list_),
      large_object_promotion_list_local_(
          promotion_list->large_object_promotion_list_) {}

Scavenger::Scavenger(ScavengerCollector* collector, Heap* heap, bool is_logging,
                     EmptyChunksList* empty_chunks, CopiedList* copied_list,
                     PromotionList* promotion_list,
                     EphemeronRememberedSet::TableList* ephemeron_table_list)
    : collector_(collector),
      heap_(heap),
      local_empty_chunks_(*empty_chunks),
      local_promotion_list_(promotion_list),
      local_copied_list_(*copied_list),
      local_ephemeron_table_list_(*ephemeron_table_list),
      local_pretenuring_feedback_(PretenuringHandler::kInitialFeedbackCapacity),
      allocator_(heap, CompactionSpaceKind::kCompactionSpaceForScavenge),
      is_logging_(is_logging),
      is_incremental_marking_(heap->incremental_marking()->IsMarking()),
      is_compacting_(heap->incremental_marking()->IsCompacting()),
      shared_string_table_(v8_flags.shared_string_table &&
                           heap->isolate()->has_shared_space()),
      mark_shared_heap_(heap->isolate()->is_shared_space_isolate()),
      shortcut_strings_(
          heap->CanShortcutStringsDuringGC(GarbageCollector::SCAVENGER)) {
  DCHECK_IMPLIES(is_incremental_marking_,
                 heap->incremental_marking()->IsMajorMarking());
}

void Scavenger::IterateAndScavengePromotedObject(Tagged<HeapObject> target,
                                                 Tagged<Map> map, int size) {
  // We are not collecting slots on new space objects during mutation thus we
  // have to scan for pointers to evacuation candidates when we promote
  // objects. But we should not record any slots in non-black objects. Grey
  // object's slots would be rescanned. White object might not survive until
  // the end of collection it would be a violation of the invariant to record
  // its slots.
  const bool record_slots =
      is_compacting_ && heap()->marking_state()->IsMarked(target);

  IterateAndScavengePromotedObjectsVisitor visitor(this, record_slots);

  // Iterate all outgoing pointers including map word.
  visitor.Visit(map, target, size);

  if (IsJSArrayBufferMap(map)) {
    DCHECK(!MemoryChunk::FromHeapObject(target)->IsLargePage());
    Cast<JSArrayBuffer>(target)->YoungMarkExtensionPromoted();
  }
}

void Scavenger::RememberPromotedEphemeron(Tagged<EphemeronHashTable> table,
                                          int index) {
  auto indices = local_ephemeron_remembered_set_.insert(
      {table, std::unordered_set<int>()});
  indices.first->second.insert(index);
}

void Scavenger::ScavengePage(MutablePageMetadata* page) {
  const bool record_old_to_shared_slots = heap_->isolate()->has_shared_space();

  MemoryChunk* chunk = page->Chunk();

  if (page->slot_set<OLD_TO_NEW, AccessMode::ATOMIC>() != nullptr) {
    RememberedSet<OLD_TO_NEW>::IterateAndTrackEmptyBuckets(
        page,
        [this, chunk, page, record_old_to_shared_slots](MaybeObjectSlot slot) {
          SlotCallbackResult result = CheckAndScavengeObject(heap_, slot);
          // A new space string might have been promoted into the shared heap
          // during GC.
          if (result == REMOVE_SLOT && record_old_to_shared_slots) {
            CheckOldToNewSlotForSharedUntyped(chunk, page, slot);
          }
          return result;
        },
        &local_empty_chunks_);
  }

  if (chunk->executable()) {
    std::vector<std::tuple<Tagged<HeapObject>, SlotType, Address>> slot_updates;

    // The code running write access to executable memory poses CFI attack
    // surface and needs to be kept to a minimum. So we do the the iteration in
    // two rounds. First we iterate the slots and scavenge objects and in the
    // second round with write access, we only perform the pointer updates.
    RememberedSet<OLD_TO_NEW>::IterateTyped(
        page, [this, chunk, page, record_old_to_shared_slots, &slot_updates](
                  SlotType slot_type, Address slot_address) {
          Tagged<HeapObject> old_target =
              UpdateTypedSlotHelper::GetTargetObject(heap_, slot_type,
                                                     slot_address);
          Tagged<HeapObject> new_target = old_target;
          FullMaybeObjectSlot slot(&new_target);
          SlotCallbackResult result = CheckAndScavengeObject(heap(), slot);
          if (result == REMOVE_SLOT && record_old_to_shared_slots) {
            CheckOldToNewSlotForSharedTyped(chunk, page, slot_type,
                                            slot_address, *slot);
          }
          if (new_target != old_target) {
            slot_updates.emplace_back(new_target, slot_type, slot_address);
          }
          return result;
        });

    WritableJitPage jit_page = ThreadIsolation::LookupWritableJitPage(
        page->area_start(), page->area_size());
    for (auto& slot_update : slot_updates) {
      Tagged<HeapObject> new_target = std::get<0>(slot_update);
      SlotType slot_type = std::get<1>(slot_update);
      Address slot_address = std::get<2>(slot_update);

      WritableJitAllocation jit_allocation =
          jit_page.LookupAllocationContaining(slot_address);
      UpdateTypedSlotHelper::UpdateTypedSlot(
          jit_allocation, heap_, slot_type, slot_address,
          [new_target](FullMaybeObjectSlot slot) {
            slot.store(new_target);
            return KEEP_SLOT;
          });
    }
  } else {
    DCHECK_NULL(page->typed_slot_set<OLD_TO_NEW>());
  }

  if (page->slot_set<OLD_TO_NEW_BACKGROUND, AccessMode::ATOMIC>() != nullptr) {
    RememberedSet<OLD_TO_NEW_BACKGROUND>::IterateAndTrackEmptyBuckets(
        page,
        [this, chunk, page, record_old_to_shared_slots](MaybeObjectSlot slot) {
          SlotCallbackResult result = CheckAndScavengeObject(heap_, slot);
          // A new space string might have been promoted into the shared heap
          // during GC.
          if (result == REMOVE_SLOT && record_old_to_shared_slots) {
            CheckOldToNewSlotForSharedUntyped(chunk, page, slot);
          }
          return result;
        },
        &local_empty_chunks_);
  }
}

void Scavenger::Process(JobDelegate* delegate) {
  ScavengeVisitor scavenge_visitor(this);

  bool done;
  size_t objects = 0;
  do {
    done = true;
    ObjectAndSize object_and_size;
    while (!local_promotion_list_.ShouldEagerlyProcessPromotionList() &&
           local_copied_list_.Pop(&object_and_size)) {
      scavenge_visitor.Visit(object_and_size.first);
      done = false;
      if (delegate && ((++objects % kInterruptThreshold) == 0)) {
        if (!local_copied_list_.IsLocalEmpty()) {
          delegate->NotifyConcurrencyIncrease();
        }
      }
    }

    struct PromotionListEntry entry;
    while (local_promotion_list_.Pop(&entry)) {
      Tagged<HeapObject> target = entry.heap_object;
      IterateAndScavengePromotedObject(target, entry.map, entry.size);
      done = false;
      if (delegate && ((++objects % kInterruptThreshold) == 0)) {
        if (!local_promotion_list_.IsGlobalPoolEmpty()) {
          delegate->NotifyConcurrencyIncrease();
        }
      }
    }
  } while (!done);
}

void ScavengerCollector::ProcessWeakReferences(
    EphemeronRememberedSet::TableList* ephemeron_table_list) {
  ClearYoungEphemerons(ephemeron_table_list);
  ClearOldEphemerons();
}

// Clear ephemeron entries from EphemeronHashTables in new-space whenever the
// entry has a dead new-space key.
void ScavengerCollector::ClearYoungEphemerons(
    EphemeronRememberedSet::TableList* ephemeron_table_list) {
  ephemeron_table_list->Iterate([this](Tagged<EphemeronHashTable> table) {
    for (InternalIndex i : table->IterateEntries()) {
      // Keys in EphemeronHashTables must be heap objects.
      HeapObjectSlot key_slot(
          table->RawFieldOfElementAt(EphemeronHashTable::EntryToIndex(i)));
      Tagged<HeapObject> key = key_slot.ToHeapObject();
      if (IsUnscavengedHeapObject(heap_, key)) {
        table->RemoveEntry(i);
      } else {
        Tagged<HeapObject> forwarded = ForwardingAddress(key);
        key_slot.StoreHeapObject(forwarded);
      }
    }
  });
  ephemeron_table_list->Clear();
}

// Clear ephemeron entries from EphemeronHashTables in old-space whenever the
// entry has a dead new-space key.
void ScavengerCollector::ClearOldEphemerons() {
  auto* table_map = heap_->ephemeron_remembered_set_->tables();
  for (auto it = table_map->begin(); it != table_map->end();) {
    Tagged<EphemeronHashTable> table = it->first;
    auto& indices = it->second;
    for (auto iti = indices.begin(); iti != indices.end();) {
      // Keys in EphemeronHashTables must be heap objects.
      HeapObjectSlot key_slot(table->RawFieldOfElementAt(
          EphemeronHashTable::EntryToIndex(InternalIndex(*iti))));
      Tagged<HeapObject> key = key_slot.ToHeapObject();
      if (IsUnscavengedHeapObject(heap_, key)) {
        table->RemoveEntry(InternalIndex(*iti));
        iti = indices.erase(iti);
      } else {
        Tagged<HeapObject> forwarded = ForwardingAddress(key);
        key_slot.StoreHeapObject(forwarded);
        if (!HeapLayout::InYoungGeneration(forwarded)) {
          iti = indices.erase(iti);
        } else {
          ++iti;
        }
      }
    }

    if (indices.empty()) {
      it = table_map->erase(it);
    } else {
      ++it;
    }
  }
}

void Scavenger::Finalize() {
  heap()->pretenuring_handler()->MergeAllocationSitePretenuringFeedback(
      local_pretenuring_feedback_);
  for (const auto& it : local_ephemeron_remembered_set_) {
    DCHECK_IMPLIES(!MemoryChunk::FromHeapObject(it.first)->IsLargePage(),
                   !HeapLayout::InYoungGeneration(it.first));
    heap()->ephemeron_remembered_set()->RecordEphemeronKeyWrites(
        it.first, std::move(it.second));
  }
  heap()->IncrementNewSpaceSurvivingObjectSize(copied_size_);
  heap()->IncrementPromotedObjectsSize(promoted_size_);
  collector_->MergeSurvivingNewLargeObjects(local_surviving_new_large_objects_);
  allocator_.Finalize();
  local_empty_chunks_.Publish();
  local_ephemeron_table_list_.Publish();
}

void Scavenger::Publish() {
  local_copied_list_.Publish();
  local_promotion_list_.Publish();
}

void Scavenger::AddEphemeronHashTable(Tagged<EphemeronHashTable> table) {
  local_ephemeron_table_list_.Push(table);
}

template <typename TSlot>
void Scavenger::CheckOldToNewSlotForSharedUntyped(MemoryChunk* chunk,
                                                  MutablePageMetadata* page,
                                                  TSlot slot) {
  Tagged<MaybeObject> object = *slot;
  Tagged<HeapObject> heap_object;

  if (object.GetHeapObject(&heap_object) &&
      HeapLayout::InWritableSharedSpace(heap_object)) {
    RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::ATOMIC>(
        page, chunk->Offset(slot.address()));
  }
}

void Scavenger::CheckOldToNewSlotForSharedTyped(
    MemoryChunk* chunk, MutablePageMetadata* page, SlotType slot_type,
    Address slot_address, Tagged<MaybeObject> new_target) {
  Tagged<HeapObject> heap_object;

  if (new_target.GetHeapObject(&heap_object) &&
      HeapLayout::InWritableSharedSpace(heap_object)) {
    const uintptr_t offset = chunk->Offset(slot_address);
    DCHECK_LT(offset, static_cast<uintptr_t>(TypedSlotSet::kMaxOffset));

    base::MutexGuard guard(page->mutex());
    RememberedSet<OLD_TO_SHARED>::InsertTyped(page, slot_type,
                                              static_cast<uint32_t>(offset));
  }
}

void RootScavengeVisitor::VisitRootPointer(Root root, const char* description,
                                           FullObjectSlot p) {
  DCHECK(!HasWeakHeapObjectTag(*p));
  DCHECK(!MapWord::IsPacked((*p).ptr()));
  ScavengePointer(p);
}

void RootScavengeVisitor::VisitRootPointers(Root root, const char* description,
                                            FullObjectSlot start,
                                            FullObjectSlot end) {
  // Copy all HeapObject pointers in [start, end)
  for (FullObjectSlot p = start; p < end; ++p) {
    ScavengePointer(p);
  }
}

void RootScavengeVisitor::ScavengePointer(FullObjectSlot p) {
  Tagged<Object> object = *p;
  DCHECK(!HasWeakHeapObjectTag(object));
  DCHECK(!MapWord::IsPacked(object.ptr()));
  if (HeapLayout::InYoungGeneration(object)) {
    scavenger_.ScavengeObject(FullHeapObjectSlot(p), Cast<HeapObject>(object));
  }
}

RootScavengeVisitor::RootScavengeVisitor(Scavenger& scavenger)
    : scavenger_(scavenger) {}

RootScavengeVisitor::~RootScavengeVisitor() { scavenger_.Publish(); }

ScavengeVisitor::ScavengeVisitor(Scavenger* scavenger)
    : NewSpaceVisitor<ScavengeVisitor>(scavenger->heap()->isolate()),
      scavenger_(scavenger) {}

}  // namespace internal
}  // namespace v8

"""

```