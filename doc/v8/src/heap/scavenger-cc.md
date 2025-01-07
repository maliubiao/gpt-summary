Response:
My thinking process to summarize the functionality of `v8/src/heap/scavenger.cc` goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code, explicitly mentioning its role within V8, potential Torque presence (based on file extension), connection to JavaScript, examples, input/output scenarios, common errors, and finally, a concise overall summary for Part 1.

2. **Initial Scan for Keywords:** I quickly scan the code for significant terms. Keywords like "Scavenger," "Heap," "Garbage Collection," "Young Generation," "Promotion," "Copying," "Marking," "Roots," "Weak Handles," "Parallel," etc., immediately jump out. These provide a high-level understanding of the code's domain.

3. **Identify the Core Class:** The code clearly defines a `ScavengerCollector` and a `Scavenger` class. These are likely the central components. I note their relationship (the Collector manages Scavengers).

4. **Analyze Key Functionalities:**  I look for methods within these classes that describe their actions:
    * `ScavengerCollector::CollectGarbage()`:  This seems to be the main entry point for the scavenging process.
    * `Scavenger::ScavengePage()`: Suggests processing individual memory pages.
    * `Scavenger::ScavengeObject()`:  Indicates handling individual objects.
    * `Scavenger::IterateAndScavengePromotedObject()`: Points to how objects moved from young to old generation are processed.
    * `ScavengerCollector::JobTask`: Implies parallel processing of scavenging tasks.
    *  Visitors (`IterateAndScavengePromotedObjectsVisitor`, `RootScavengeVisitor`, `GlobalHandlesWeakRootsUpdatingVisitor`):  These suggest different ways of traversing and acting upon the heap.

5. **Infer the Overall Process (Scavenging):** Based on the keywords and method names, I deduce that this code implements a *scavenging garbage collector*. Scavenging is a generational GC technique that focuses on collecting garbage in the "young generation" (where most objects are short-lived).

6. **Connect to V8's GC:** I recognize that this code resides in `v8/src/heap`, strongly indicating its direct involvement in V8's memory management and garbage collection.

7. **Address Specific Questions:** Now, I address each part of the prompt:

    * **Functionality Listing:**  I synthesize a list based on my analysis, grouping related actions (copying, promotion, root scanning, weak handle processing, etc.).

    * **Torque Check:** The prompt explicitly asks about the `.tq` extension. I confirm that the provided file is `.cc` and therefore *not* a Torque file.

    * **JavaScript Relationship:**  Since garbage collection directly affects how JavaScript objects are managed in memory, I explain the connection. I then brainstorm a simple JavaScript example that would trigger garbage collection (creating and discarding objects). This demonstrates the *effect* of the scavenger, even though the JS doesn't directly *call* the C++ code.

    * **Code Logic/Input-Output:**  The prompt asks for specific logic. I choose the `Scavenger::ScavengeObject()` function (even though the provided snippet doesn't show its full implementation). I make assumptions about its behavior (copying objects and updating pointers) and create a simple hypothetical scenario with a young object pointing to another young object. I illustrate how the pointers would be updated. This is a simplified interpretation, given the limited context.

    * **Common Programming Errors:** I think about how memory management issues can arise in JavaScript. Memory leaks are the most relevant, and I provide an example of a closure causing a leak. While the *scavenger* tries to *prevent* leaks of reachable objects, this example illustrates a scenario where the programmer can inadvertently prevent objects from being collected.

    * **Overall Summary (Part 1):** I condense the key findings into a concise summary, emphasizing the core function of the scavenger in collecting garbage from the young generation.

8. **Review and Refine:** I reread my summary to ensure accuracy, clarity, and completeness based on the provided code snippet. I check if I've addressed all aspects of the prompt. I use the provided copyright notice and `#include` statements for additional context.

Essentially, I'm moving from a broad overview to specific details and back to a concise summary. I leverage my understanding of garbage collection principles and V8's architecture to interpret the code. Even without complete details of every function, I can infer the overall purpose and behavior based on the naming conventions and the context of the file.
好的，让我们来分析一下 `v8/src/heap/scavenger.cc` 这个 V8 源代码文件的功能。

**功能归纳 (第 1 部分):**

`v8/src/heap/scavenger.cc` 文件是 V8 JavaScript 引擎中负责**新生代垃圾回收（Young Generation Garbage Collection）**的关键组件。更具体地说，它实现了 **Scavenger** 算法，也被称为 **Minor GC**。

**具体功能列举:**

1. **新生代垃圾回收:**  这是其核心功能。Scavenger 专门处理 V8 堆内存中的新生代（New Space），这是一个用于分配生命周期较短的对象的区域。

2. **对象复制 (Copying):**  Scavenger 采用复制算法。它将存活的对象从当前的新生代（"From Space"）复制到另一个新的空闲区域（"To Space"）。

3. **对象晋升 (Promotion):**  在 Scavenger 过程中，如果一个对象经历了多次垃圾回收仍然存活，它会被“晋升”到老年代（Old Generation），以减少后续 Scavenger 的扫描负担。

4. **根扫描 (Root Scanning):**  Scavenger 必须从一组根对象开始追踪存活对象。这些根对象包括全局变量、栈上的变量以及 CPU 寄存器中的值。代码中可以看到 `RootScavengeVisitor` 的使用，它负责遍历这些根。

5. **弱句柄处理 (Weak Handle Processing):**  Scavenger 需要处理弱句柄，这些句柄不会阻止对象被回收，除非对象在其他地方也被强引用。代码中提到了 `GlobalHandlesWeakRootsUpdatingVisitor`。

6. **Remembered Set 处理:**  为了提高效率，Scavenger 利用 Remembered Set。老年代对象可能引用新生代对象。Remembered Set 记录了这些跨代引用，Scavenger 只需要扫描这些记录，而不需要扫描整个老年代。代码中多次提到 `RememberedSet` 以及 `OLD_TO_NEW` 等类型。

7. **并行处理 (Parallel Processing):**  为了加速垃圾回收，Scavenger 可以利用多线程并行执行部分任务。代码中可以看到 `ScavengerCollector::JobTask` 以及对 `V8::GetCurrentPlatform()->CreateJob` 的调用。

8. **外部指针表处理 (External Pointer Table):**  在启用了指针压缩的情况下，Scavenger 需要处理外部指针表，该表存储指向外部 C++ 对象的指针。

9. **处理幸存的新生代大对象 (Handling Surviving New Large Objects):** 新生代也可能分配大对象。Scavenger 需要特殊处理这些大对象的复制和晋升。

10. **更新引用 (Updating References):**  一旦对象被复制或晋升，所有指向这些对象的指针都需要更新，以指向它们的新位置。

11. **与 Concurrent Marking 的交互:**  代码中可以看到与并发标记（Concurrent Marking）相关的逻辑，例如检查 `heap_->concurrent_marking()->IsStopped()`。Scavenger 和 Major GC (Mark-Compact) 之间需要协调工作。

12. **ArrayBuffer 处理:** 代码中提到了 `ArrayBufferSweeper`，暗示 Scavenger 也需要考虑 `ArrayBuffer` 对象的特殊处理。

**关于文件类型:**

如果 `v8/src/heap/scavenger.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是 V8 使用的一种类型安全的代码生成器，用于生成高效的 C++ 代码。但是，根据您提供的文件路径，它以 `.cc` 结尾，所以它是一个标准的 **C++ 源代码**文件。

**与 JavaScript 的关系及示例:**

Scavenger 的功能与 JavaScript 的内存管理密切相关。当 JavaScript 代码创建对象时，这些对象通常最初分配在新生代。当新生代空间满时，Scavenger 会被触发来回收不再使用的对象，从而为新对象腾出空间。

**JavaScript 示例:**

```javascript
function createLotsOfObjects() {
  for (let i = 0; i < 100000; i++) {
    // 创建一个临时对象
    let obj = { data: i };
  }
  // 循环结束后，这些临时对象大部分变得不可达，
  // 下一次 Scavenger 运行时会被回收。
}

createLotsOfObjects();

// 创建一个长期存活的对象
let longLivedObject = { importantData: "This will survive many GCs" };

function createShortLivedObject() {
  let temp = { name: "Short Lived" };
  return temp; // 函数返回后，temp 指向的对象很可能很快被回收
}

let myObject = createShortLivedObject();
```

在这个例子中，`createLotsOfObjects` 函数创建了大量的临时对象。一旦函数执行完毕，这些对象大部分变得不可达，Scavenger 会负责回收它们。`longLivedObject` 则更有可能被晋升到老年代。

**代码逻辑推理与假设输入输出 (简化):**

假设有一个 `ScavengeObject` 函数（虽然在提供的代码片段中没有完整实现，但其存在是合理的），它的作用是处理新生代中的单个对象。

**假设输入:**

* `slot`: 一个指向可能包含新生代对象的内存槽位 (例如 `FullObjectSlot`)。
* `object`: `slot` 指向的对象。

**假设逻辑:**

```c++
// 假设的 ScavengeObject 函数逻辑
SlotCallbackResult Scavenger::ScavengeObject(FullObjectSlot slot, Tagged<HeapObject> object) {
  if (object->IsLive()) { // 检查对象是否存活 (例如，通过标记位)
    Tagged<HeapObject> forwarded_object = CopyObject(object); // 将对象复制到 To Space
    slot.store(forwarded_object); // 更新原始槽位，指向复制后的对象
    return UPDATE_SLOT; // 返回指示槽位已更新
  } else {
    return REMOVE_SLOT; // 对象已死，可以移除槽位
  }
}
```

**假设输出:**

* 如果 `object` 存活，`slot` 中的内容会被更新为指向复制后的对象，函数返回 `UPDATE_SLOT`。
* 如果 `object` 不存活，函数返回 `REMOVE_SLOT`。

**用户常见的编程错误:**

与 Scavenger 相关的常见编程错误通常会导致**内存泄漏**或**性能问题**：

1. **意外地持有对不再需要的对象的引用:** 这会导致 Scavenger 无法回收这些对象，即使它们实际上已经不再使用。例如：

   ```javascript
   let leakedArray = [];
   function createAndLeakObject() {
     let obj = { data: new Array(1000000) }; // 创建一个大对象
     leakedArray.push(obj); // 将其添加到全局数组，阻止其被回收
   }

   for (let i = 0; i < 10; i++) {
     createAndLeakObject();
   }
   // 尽管这些 obj 在循环后不再需要，但由于 leakedArray 持有它们的引用，
   // Scavenger 无法回收它们，导致内存泄漏。
   ```

2. **创建大量生命周期短暂的对象:** 虽然 Scavenger 旨在高效处理新生代，但过度创建和销毁对象仍然会给 GC 带来压力，影响性能。

3. **循环引用:**  如果对象之间形成循环引用，并且没有外部引用指向这个循环中的任何对象，那么 Scavenger 也无法回收它们，直到 Major GC 运行。

**总结 (针对第 1 部分):**

`v8/src/heap/scavenger.cc` 实现了 V8 引擎的新生代垃圾回收器（Scavenger），其核心功能是识别并回收新生代中不再使用的对象，并将存活的对象复制到新的空间或晋升到老年代。它通过根扫描、Remembered Set 和并行处理等技术来高效完成垃圾回收任务，直接影响 JavaScript 程序的内存管理和性能。用户常见的编程错误，如意外持有对象引用，可能导致 Scavenger 无法有效回收内存。

Prompt: 
```
这是目录为v8/src/heap/scavenger.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/scavenger.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

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

    WritableJitPage jit_page =
"""


```