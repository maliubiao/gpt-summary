Response:
The user wants a summary of the provided C++ code snippet, specifically focusing on its functionalities within the V8 JavaScript engine's garbage collection process.

Here's a breakdown of the thinking process to arrive at the summary:

1. **Identify the Core Functionality:** The code resides in `v8/src/heap/mark-compact.cc`, suggesting it's a part of the Mark-Compact garbage collection algorithm implementation in V8. Keywords like `UpdateSlot`, `EvacuatePrologue`, `EvacuateEpilogue`, `EvacuatePage`, `EvacuatePagesInParallel`, and the mention of "evacuation" strongly point towards the *relocation* or *moving* phase of garbage collection.

2. **Analyze Key Data Structures and Classes:**
    * **Slots (`ObjectSlot`, `MaybeObjectSlot`, etc.):** The code deals heavily with different types of slots, which are essentially pointers to objects in the heap. The template functions like `UpdateSlot` operate on these slots, indicating the process of modifying these pointers.
    * **`HeapObject`:** This is the base class for objects managed by the V8 heap. The code updates references *to* `HeapObject`s.
    * **`MapWord`:** This structure likely stores metadata about a heap object, including forwarding addresses used during evacuation.
    * **`MemoryChunk` and `PageMetadata`:** These represent memory regions within the heap. The code tracks evacuation on a per-page basis.
    * **`Evacuator`:** This class appears to be the central component for moving objects from one location to another. It handles different evacuation modes (new-to-old, old-to-old).
    * **`LiveObjectVisitor`:** This class iterates over live objects on a page.
    * **`MarkCompactCollector`:** This is the main class for the Mark-Compact collector, orchestrating the evacuation process.
    * **`PageEvacuationJob` and `PointersUpdatingJob`:** These indicate the use of multithreading for parallelizing the evacuation and pointer update processes.

3. **Understand the Evacuation Process:** The code outlines a multi-stage evacuation process:
    * **Prologue (`EvacuatePrologue`):**  Prepares for evacuation, identifying candidate pages (likely those needing compaction).
    * **Evacuation (`EvacuatePage`, `EvacuatePagesInParallel`):**  Moves live objects from the identified source pages to new locations. This involves copying object data and updating forwarding pointers. Parallelism is explicitly implemented.
    * **Pointer Updating (`UpdateSlot`, `PointersUpdatingVisitor`):** After objects are moved, all references to these objects need to be updated to point to the new locations. This is crucial for maintaining the integrity of the object graph.
    * **Epilogue (`EvacuateEpilogue`):**  Cleans up after evacuation, freeing up the old memory regions.

4. **Identify Potential JavaScript Relevance:** While this is low-level C++ code, its purpose directly impacts JavaScript performance. Garbage collection is essential for memory management in JavaScript. The code relates to *how* V8 reclaims memory and avoids fragmentation, which can affect the speed and responsiveness of JavaScript applications. The concept of "forwarding addresses" relates to how V8 handles object movement without breaking existing references.

5. **Look for Logic and Potential Errors:**
    * **Forwarding Addresses:** The code checks `map_word.IsForwardingAddress()`. This is a key part of the evacuation process. If an object has already been moved, its map word will contain the new address.
    * **Weak vs. Strong References:** The `UpdateSlot` function handles both weak and strong references, which are important concepts in garbage collection. Weak references don't prevent an object from being collected.
    * **Parallelism:** The use of `PageEvacuationJob` and `PointersUpdatingJob` highlights the parallel nature of the evacuation process for performance.
    * **Aborted Evacuation:** The code mentions "aborted evacuation candidates," indicating situations where evacuation of a page might fail (e.g., due to out-of-memory).

6. **Address the Specific Instructions:**
    * **`.tq` extension:** The code confirms it's C++ (`.cc`) and not Torque (`.tq`).
    * **JavaScript examples:** The JavaScript example illustrates the impact of garbage collection on object references. When an object is moved during GC, JavaScript code continues to work with the same conceptual object because the underlying references are updated.
    * **Input/Output:**  The example provides a plausible scenario for how the `UpdateSlot` function might work, demonstrating the transformation of a slot's value due to object movement.
    * **Common Errors:** The common error relates to dangling pointers in other languages. V8's GC aims to prevent this by automatically updating references.
    * **Part Number:** Acknowledge that this is part 6 of 8 and provide a concise summary of the functionalities covered in this specific part.

7. **Synthesize the Summary:** Combine the observations into a coherent summary that addresses the user's request, covering the core functionalities, potential JavaScript relevance, and the specific details asked for in the prompt. Focus on explaining *what* the code does and *why* it's important in the context of V8's garbage collection.
这是V8源代码文件 `v8/src/heap/mark-compact.cc` 的第6部分，主要负责 **Mark-Compact 垃圾回收算法中的对象迁移（Evacuation）和指针更新阶段**。

**功能归纳:**

本部分代码的核心功能是：

1. **对象迁移（Evacuation）：**
   - **决定哪些页面需要进行迁移：** 根据内存页面的存活对象情况，判断是否需要将整个页面或部分对象迁移到新的位置。
   - **实际的对象复制：**  将存活的对象从原来的位置复制到新的位置。这涉及到为对象在目标空间分配内存，并将对象的数据复制过去。
   - **处理不同类型的内存空间：** 包括新生代（New Space）、老年代（Old Space）和大型对象空间（Large Object Space）的迁移。
   - **支持并行迁移：** 使用多线程加速页面迁移过程。
   - **处理晋升（Promotion）：** 将新生代存活时间较长的对象迁移到老年代。
   - **处理因各种原因中止的迁移：** 记录并处理因为内存不足或其他原因未能成功迁移的页面。

2. **指针更新（Updating Pointers）：**
   - **更新所有指向已迁移对象的指针：** 在对象迁移完成后，需要遍历整个堆，找到所有指向已迁移对象的指针，并将这些指针更新到对象的新地址。
   - **处理不同类型的指针槽（Slots）：** 包括对象槽（`ObjectSlot`）、可能对象槽（`MaybeObjectSlot`）、外部对象槽（`OffHeapObjectSlot`）等。
   - **处理强引用和弱引用：**  弱引用在对象被回收后会被更新为特定值。
   - **支持并行指针更新：** 使用多线程加速指针更新过程。

**如果 `v8/src/heap/mark-compact.cc` 以 `.tq` 结尾:**

那么它将是 V8 的 Torque 源代码。Torque 是一种 V8 使用的类型化的中间语言，用于生成高效的 C++ 代码。如果这个文件是 `.tq`，那么它会用 Torque 语言定义 Mark-Compact 算法的逻辑，然后被编译成 C++ 代码。**但根据您提供的文件名，它实际上是 `.cc`，所以是 C++ 源代码。**

**与 JavaScript 的功能关系 (JavaScript 示例):**

Mark-Compact 垃圾回收是 V8 用来管理 JavaScript 程序内存的关键机制。当 JavaScript 代码创建对象时，V8 会在堆上分配内存。随着程序的运行，一些对象变得不再被引用，这时就需要垃圾回收器来回收这些不再使用的内存。

对象迁移是 Mark-Compact 垃圾回收中的一个重要步骤，目的是整理堆内存，减少碎片，提高内存利用率。

```javascript
let obj1 = { value: 1 };
let obj2 = { ref: obj1 };
let globalRef = obj1;

// ... 一段时间后，globalRef 不再引用 obj1
globalRef = null;

// 触发垃圾回收 (V8 会自动进行，这里只是示意)
// 假设在垃圾回收过程中，obj1 被迁移到了新的内存地址

console.log(obj2.ref.value); // 仍然可以访问到 obj1 的值，因为指针已经被更新
```

在这个例子中，当垃圾回收发生时，`obj1` 可能被移动到新的内存地址。`v8/src/heap/mark-compact.cc` 中涉及的代码就负责确保 `obj2.ref` 仍然指向 `obj1` 的新地址，从而保证 JavaScript 代码能够正常访问到对象。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个对象 `old_obj`，它位于内存地址 `0x1000`。另一个对象 `container_obj` 包含一个指向 `old_obj` 的指针，该指针存储在 `container_obj` 的某个槽位 `slot_in_container`。

在 Mark-Compact 垃圾回收的迁移阶段，`old_obj` 被移动到了新的内存地址 `0x2000`。

`UpdateSlot` 函数的作用就是将 `container_obj` 中 `slot_in_container` 的值从 `0x1000` 更新为 `0x2000`。

**假设输入:**

- `cage_base`: 当前的指针压缩基址。
- `slot`:  `container_obj` 中指向 `old_obj` 的槽位 (`slot_in_container`)，其原始值为指向 `0x1000` 的指针。
- `heap_obj`: 指向 `old_obj` 的指针，`old_obj` 的 `map_word` 已经被更新为包含转发地址的信息，指向 `0x2000`。

**预期输出:**

- `slot` 的值被更新为指向 `0x2000` 的指针。

**用户常见的编程错误 (与本部分代码相关的概念):**

虽然用户通常不会直接与这部分 C++ 代码交互，但理解其背后的概念有助于避免一些与内存管理相关的错误，尤其是在使用一些需要手动内存管理的语言时。

一个与此相关的概念是 **悬挂指针（Dangling Pointer）**。在手动内存管理的语言中，如果在对象被释放后仍然持有指向该对象内存的指针，就会出现悬挂指针。访问悬挂指针会导致程序崩溃或未定义的行为。

V8 的垃圾回收机制（包括 Mark-Compact）旨在自动管理内存，避免悬挂指针的问题。本部分代码中的指针更新操作正是为了确保在对象移动后，所有指向该对象的指针仍然有效。

**第 6 部分功能总结:**

`v8/src/heap/mark-compact.cc` 的第 6 部分主要负责 **Mark-Compact 垃圾回收算法中的核心环节：对象迁移和指针更新**。它实现了将存活对象移动到新的位置，并更新所有指向这些对象的指针，确保程序的正确性和内存的有效利用。这部分代码是 V8 垃圾回收器中非常关键且复杂的组成部分，直接影响着 JavaScript 程序的性能和稳定性。

Prompt: 
```
这是目录为v8/src/heap/mark-compact.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mark-compact.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能

"""
ot>::value ||
          std::is_same<TSlot, ObjectSlot>::value ||
          std::is_same<TSlot, FullMaybeObjectSlot>::value ||
          std::is_same<TSlot, MaybeObjectSlot>::value ||
          std::is_same<TSlot, OffHeapObjectSlot>::value ||
          std::is_same<TSlot, InstructionStreamSlot>::value ||
          std::is_same<TSlot, ProtectedPointerSlot>::value ||
          std::is_same<TSlot, WriteProtectedSlot<ObjectSlot>>::value ||
          std::is_same<TSlot, WriteProtectedSlot<ProtectedPointerSlot>>::value,
      "Only [Full|OffHeap]ObjectSlot, [Full]MaybeObjectSlot, "
      "InstructionStreamSlot, ProtectedPointerSlot, or WriteProtectedSlot are "
      "expected here");
  MapWord map_word = heap_obj->map_word(cage_base, kRelaxedLoad);
  if (!map_word.IsForwardingAddress()) return;
  DCHECK_IMPLIES((!v8_flags.minor_ms && !Heap::InFromPage(heap_obj)),
                 MarkCompactCollector::IsOnEvacuationCandidate(heap_obj) ||
                     MemoryChunk::FromHeapObject(heap_obj)->IsFlagSet(
                         MemoryChunk::COMPACTION_WAS_ABORTED));
  typename TSlot::TObject target = MakeSlotValue<TSlot, reference_type>(
      map_word.ToForwardingAddress(heap_obj));
  // Needs to be atomic for map space compaction: This slot could be a map
  // word which we update while loading the map word for updating the slot
  // on another page.
  slot.Relaxed_Store(target);
  DCHECK_IMPLIES(!v8_flags.sticky_mark_bits, !Heap::InFromPage(target));
  DCHECK(!MarkCompactCollector::IsOnEvacuationCandidate(target));
}

template <typename TSlot>
static inline void UpdateSlot(PtrComprCageBase cage_base, TSlot slot) {
  typename TSlot::TObject obj = slot.Relaxed_Load(cage_base);
  Tagged<HeapObject> heap_obj;
  if constexpr (TSlot::kCanBeWeak) {
    if (obj.GetHeapObjectIfWeak(&heap_obj)) {
      return UpdateSlot<HeapObjectReferenceType::WEAK>(cage_base, slot,
                                                       heap_obj);
    }
  }
  if (obj.GetHeapObjectIfStrong(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
  }
}

template <typename TSlot>
static inline SlotCallbackResult UpdateOldToSharedSlot(
    PtrComprCageBase cage_base, TSlot slot) {
  typename TSlot::TObject obj = slot.Relaxed_Load(cage_base);
  Tagged<HeapObject> heap_obj;

  if constexpr (TSlot::kCanBeWeak) {
    if (obj.GetHeapObjectIfWeak(&heap_obj)) {
      UpdateSlot<HeapObjectReferenceType::WEAK>(cage_base, slot, heap_obj);
      return HeapLayout::InWritableSharedSpace(heap_obj) ? KEEP_SLOT
                                                         : REMOVE_SLOT;
    }
  }

  if (obj.GetHeapObjectIfStrong(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
    return HeapLayout::InWritableSharedSpace(heap_obj) ? KEEP_SLOT
                                                       : REMOVE_SLOT;
  }

  return REMOVE_SLOT;
}

template <typename TSlot>
static inline void UpdateStrongSlot(PtrComprCageBase cage_base, TSlot slot) {
  typename TSlot::TObject obj = slot.Relaxed_Load(cage_base);
#ifdef V8_ENABLE_DIRECT_HANDLE
  if (obj.ptr() == kTaggedNullAddress) return;
#endif
  DCHECK(!HAS_WEAK_HEAP_OBJECT_TAG(obj.ptr()));
  Tagged<HeapObject> heap_obj;
  if (obj.GetHeapObject(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
  }
}

static inline SlotCallbackResult UpdateStrongOldToSharedSlot(
    PtrComprCageBase cage_base, FullMaybeObjectSlot slot) {
  Tagged<MaybeObject> obj = slot.Relaxed_Load(cage_base);
#ifdef V8_ENABLE_DIRECT_HANDLE
  if (obj.ptr() == kTaggedNullAddress) return REMOVE_SLOT;
#endif
  DCHECK(!HAS_WEAK_HEAP_OBJECT_TAG(obj.ptr()));
  Tagged<HeapObject> heap_obj;
  if (obj.GetHeapObject(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);
    return HeapLayout::InWritableSharedSpace(heap_obj) ? KEEP_SLOT
                                                       : REMOVE_SLOT;
  }

  return REMOVE_SLOT;
}

static inline void UpdateStrongCodeSlot(Tagged<HeapObject> host,
                                        PtrComprCageBase cage_base,
                                        PtrComprCageBase code_cage_base,
                                        InstructionStreamSlot slot) {
  Tagged<Object> obj = slot.Relaxed_Load(code_cage_base);
  DCHECK(!HAS_WEAK_HEAP_OBJECT_TAG(obj.ptr()));
  Tagged<HeapObject> heap_obj;
  if (obj.GetHeapObject(&heap_obj)) {
    UpdateSlot<HeapObjectReferenceType::STRONG>(cage_base, slot, heap_obj);

    Tagged<Code> code = Cast<Code>(HeapObject::FromAddress(
        slot.address() - Code::kInstructionStreamOffset));
    Tagged<InstructionStream> instruction_stream =
        code->instruction_stream(code_cage_base);
    code->UpdateInstructionStart(GetIsolateForSandbox(host),
                                 instruction_stream);
  }
}

}  // namespace

// Visitor for updating root pointers and to-space pointers.
// It does not expect to encounter pointers to dead objects.
class PointersUpdatingVisitor final : public ObjectVisitorWithCageBases,
                                      public RootVisitor {
 public:
  explicit PointersUpdatingVisitor(Heap* heap)
      : ObjectVisitorWithCageBases(heap) {}

  void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) override {
    UpdateStrongSlotInternal(cage_base(), p);
  }

  void VisitPointer(Tagged<HeapObject> host, MaybeObjectSlot p) override {
    UpdateSlotInternal(cage_base(), p);
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {
    for (ObjectSlot p = start; p < end; ++p) {
      UpdateStrongSlotInternal(cage_base(), p);
    }
  }

  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) final {
    for (MaybeObjectSlot p = start; p < end; ++p) {
      UpdateSlotInternal(cage_base(), p);
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    UpdateStrongCodeSlot(host, cage_base(), code_cage_base(), slot);
  }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    DCHECK(!MapWord::IsPacked(p.Relaxed_Load().ptr()));
    UpdateRootSlotInternal(cage_base(), p);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      UpdateRootSlotInternal(cage_base(), p);
    }
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      UpdateRootSlotInternal(cage_base(), p);
    }
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    // This visitor nevers visits code objects.
    UNREACHABLE();
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    // This visitor nevers visits code objects.
    UNREACHABLE();
  }

 private:
  static inline void UpdateRootSlotInternal(PtrComprCageBase cage_base,
                                            FullObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateRootSlotInternal(PtrComprCageBase cage_base,
                                            OffHeapObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateStrongMaybeObjectSlotInternal(
      PtrComprCageBase cage_base, MaybeObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateStrongSlotInternal(PtrComprCageBase cage_base,
                                              ObjectSlot slot) {
    UpdateStrongSlot(cage_base, slot);
  }

  static inline void UpdateSlotInternal(PtrComprCageBase cage_base,
                                        MaybeObjectSlot slot) {
    UpdateSlot(cage_base, slot);
  }
};

static Tagged<String> UpdateReferenceInExternalStringTableEntry(
    Heap* heap, FullObjectSlot p) {
  Tagged<HeapObject> old_string = Cast<HeapObject>(*p);
  MapWord map_word = old_string->map_word(kRelaxedLoad);

  if (map_word.IsForwardingAddress()) {
    Tagged<String> new_string =
        Cast<String>(map_word.ToForwardingAddress(old_string));

    if (IsExternalString(new_string)) {
      MutablePageMetadata::MoveExternalBackingStoreBytes(
          ExternalBackingStoreType::kExternalString,
          PageMetadata::FromAddress((*p).ptr()),
          PageMetadata::FromHeapObject(new_string),
          Cast<ExternalString>(new_string)->ExternalPayloadSize());
    }
    return new_string;
  }

  return Cast<String>(*p);
}

void MarkCompactCollector::EvacuatePrologue() {
  // New space.
  if (NewSpace* new_space = heap_->new_space()) {
    DCHECK(new_space_evacuation_pages_.empty());
    std::copy_if(new_space->begin(), new_space->end(),
                 std::back_inserter(new_space_evacuation_pages_),
                 [](PageMetadata* p) { return p->live_bytes() > 0; });
    if (!v8_flags.minor_ms) {
      SemiSpaceNewSpace::From(new_space)->EvacuatePrologue();
    }
  }

  // Large new space.
  if (NewLargeObjectSpace* new_lo_space = heap_->new_lo_space()) {
    new_lo_space->Flip();
    new_lo_space->ResetPendingObject();
  }

  // Old space.
  DCHECK(old_space_evacuation_pages_.empty());
  old_space_evacuation_pages_ = std::move(evacuation_candidates_);
  evacuation_candidates_.clear();
  DCHECK(evacuation_candidates_.empty());
}

void MarkCompactCollector::EvacuateEpilogue() {
  aborted_evacuation_candidates_due_to_oom_.clear();
  aborted_evacuation_candidates_due_to_flags_.clear();

  // New space.
  if (heap_->new_space()) {
    DCHECK_EQ(0, heap_->new_space()->Size());
  }

  // Old generation. Deallocate evacuated candidate pages.
  ReleaseEvacuationCandidates();

#ifdef DEBUG
  VerifyRememberedSetsAfterEvacuation(heap_, GarbageCollector::MARK_COMPACTOR);
#endif  // DEBUG
}

class Evacuator final : public Malloced {
 public:
  enum EvacuationMode {
    kObjectsNewToOld,
    kPageNewToOld,
    kObjectsOldToOld,
  };

  static const char* EvacuationModeName(EvacuationMode mode) {
    switch (mode) {
      case kObjectsNewToOld:
        return "objects-new-to-old";
      case kPageNewToOld:
        return "page-new-to-old";
      case kObjectsOldToOld:
        return "objects-old-to-old";
    }
  }

  static inline EvacuationMode ComputeEvacuationMode(MemoryChunk* chunk) {
    // Note: The order of checks is important in this function.
    if (chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION))
      return kPageNewToOld;
    if (chunk->InYoungGeneration()) return kObjectsNewToOld;
    return kObjectsOldToOld;
  }

  explicit Evacuator(Heap* heap)
      : heap_(heap),
        local_pretenuring_feedback_(
            PretenuringHandler::kInitialFeedbackCapacity),
        local_allocator_(heap_,
                         CompactionSpaceKind::kCompactionSpaceForMarkCompact),
        record_visitor_(heap_),
        new_space_visitor_(heap_, &local_allocator_, &record_visitor_,
                           &local_pretenuring_feedback_),
        new_to_old_page_visitor_(heap_, &record_visitor_,
                                 &local_pretenuring_feedback_),

        old_space_visitor_(heap_, &local_allocator_, &record_visitor_),
        duration_(0.0),
        bytes_compacted_(0) {}

  void EvacuatePage(MutablePageMetadata* chunk);

  void AddObserver(MigrationObserver* observer) {
    new_space_visitor_.AddObserver(observer);
    old_space_visitor_.AddObserver(observer);
  }

  // Merge back locally cached info sequentially. Note that this method needs
  // to be called from the main thread.
  void Finalize();

 private:
  // |saved_live_bytes| returns the live bytes of the page that was processed.
  bool RawEvacuatePage(MutablePageMetadata* chunk);

  inline Heap* heap() { return heap_; }

  void ReportCompactionProgress(double duration, intptr_t bytes_compacted) {
    duration_ += duration;
    bytes_compacted_ += bytes_compacted;
  }

  Heap* heap_;

  PretenuringHandler::PretenuringFeedbackMap local_pretenuring_feedback_;

  // Locally cached collector data.
  EvacuationAllocator local_allocator_;

  RecordMigratedSlotVisitor record_visitor_;

  // Visitors for the corresponding spaces.
  EvacuateNewSpaceVisitor new_space_visitor_;
  EvacuateNewToOldSpacePageVisitor new_to_old_page_visitor_;
  EvacuateOldSpaceVisitor old_space_visitor_;

  // Book keeping info.
  double duration_;
  intptr_t bytes_compacted_;
};

void Evacuator::EvacuatePage(MutablePageMetadata* page) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"), "Evacuator::EvacuatePage");
  DCHECK(page->SweepingDone());
  intptr_t saved_live_bytes = page->live_bytes();
  double evacuation_time = 0.0;
  bool success = false;
  {
    TimedScope timed_scope(&evacuation_time);
    success = RawEvacuatePage(page);
  }
  ReportCompactionProgress(evacuation_time, saved_live_bytes);
  if (v8_flags.trace_evacuation) {
    MemoryChunk* chunk = page->Chunk();
    PrintIsolate(heap_->isolate(),
                 "evacuation[%p]: page=%p new_space=%d "
                 "page_evacuation=%d executable=%d can_promote=%d "
                 "live_bytes=%" V8PRIdPTR " time=%f success=%d\n",
                 static_cast<void*>(this), static_cast<void*>(page),
                 chunk->InNewSpace(),
                 chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION),
                 chunk->IsFlagSet(MemoryChunk::IS_EXECUTABLE),
                 heap_->new_space()->IsPromotionCandidate(page),
                 saved_live_bytes, evacuation_time, success);
  }
}

void Evacuator::Finalize() {
  local_allocator_.Finalize();
  heap_->tracer()->AddCompactionEvent(duration_, bytes_compacted_);
  heap_->IncrementPromotedObjectsSize(new_space_visitor_.promoted_size() +
                                      new_to_old_page_visitor_.moved_bytes());
  heap_->IncrementNewSpaceSurvivingObjectSize(
      new_space_visitor_.semispace_copied_size());
  heap_->IncrementYoungSurvivorsCounter(
      new_space_visitor_.promoted_size() +
      new_space_visitor_.semispace_copied_size() +
      new_to_old_page_visitor_.moved_bytes());
  heap_->pretenuring_handler()->MergeAllocationSitePretenuringFeedback(
      local_pretenuring_feedback_);
}

class LiveObjectVisitor final : AllStatic {
 public:
  // Visits marked objects using `bool Visitor::Visit(HeapObject object, size_t
  // size)` as long as the return value is true.
  //
  // Returns whether all objects were successfully visited. Upon returning
  // false, also sets `failed_object` to the object for which the visitor
  // returned false.
  template <class Visitor>
  static bool VisitMarkedObjects(PageMetadata* page, Visitor* visitor,
                                 Tagged<HeapObject>* failed_object);

  // Visits marked objects using `bool Visitor::Visit(HeapObject object, size_t
  // size)` as long as the return value is true. Assumes that the return value
  // is always true (success).
  template <class Visitor>
  static void VisitMarkedObjectsNoFail(PageMetadata* page, Visitor* visitor);
};

template <class Visitor>
bool LiveObjectVisitor::VisitMarkedObjects(PageMetadata* page, Visitor* visitor,
                                           Tagged<HeapObject>* failed_object) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
               "LiveObjectVisitor::VisitMarkedObjects");
  for (auto [object, size] : LiveObjectRange(page)) {
    if (!visitor->Visit(object, size)) {
      *failed_object = object;
      return false;
    }
  }
  return true;
}

template <class Visitor>
void LiveObjectVisitor::VisitMarkedObjectsNoFail(PageMetadata* page,
                                                 Visitor* visitor) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
               "LiveObjectVisitor::VisitMarkedObjectsNoFail");
  for (auto [object, size] : LiveObjectRange(page)) {
    const bool success = visitor->Visit(object, size);
    USE(success);
    DCHECK(success);
  }
}

bool Evacuator::RawEvacuatePage(MutablePageMetadata* page) {
  MemoryChunk* chunk = page->Chunk();
  const EvacuationMode evacuation_mode = ComputeEvacuationMode(chunk);
  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
               "FullEvacuator::RawEvacuatePage", "evacuation_mode",
               EvacuationModeName(evacuation_mode), "live_bytes",
               page->live_bytes());
  switch (evacuation_mode) {
    case kObjectsNewToOld:
#if DEBUG
      new_space_visitor_.DisableAbortEvacuationAtAddress(page);
#endif  // DEBUG
      LiveObjectVisitor::VisitMarkedObjectsNoFail(PageMetadata::cast(page),
                                                  &new_space_visitor_);
      page->ClearLiveness();
      break;
    case kPageNewToOld:
      if (chunk->IsLargePage()) {
        auto object = LargePageMetadata::cast(page)->GetObject();
        bool success = new_to_old_page_visitor_.Visit(object, object->Size());
        USE(success);
        DCHECK(success);
      } else {
        LiveObjectVisitor::VisitMarkedObjectsNoFail(PageMetadata::cast(page),
                                                    &new_to_old_page_visitor_);
      }
      new_to_old_page_visitor_.account_moved_bytes(page->live_bytes());
      break;
    case kObjectsOldToOld: {
#if DEBUG
      old_space_visitor_.SetUpAbortEvacuationAtAddress(page);
#endif  // DEBUG
      Tagged<HeapObject> failed_object;
      if (LiveObjectVisitor::VisitMarkedObjects(
              PageMetadata::cast(page), &old_space_visitor_, &failed_object)) {
        page->ClearLiveness();
      } else {
        // Aborted compaction page. Actual processing happens on the main
        // thread for simplicity reasons.
        heap_->mark_compact_collector()
            ->ReportAbortedEvacuationCandidateDueToOOM(
                failed_object.address(), static_cast<PageMetadata*>(page));
        return false;
      }
      break;
    }
  }

  return true;
}

class PageEvacuationJob : public v8::JobTask {
 public:
  PageEvacuationJob(
      Isolate* isolate, MarkCompactCollector* collector,
      std::vector<std::unique_ptr<Evacuator>>* evacuators,
      std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
          evacuation_items)
      : collector_(collector),
        evacuators_(evacuators),
        evacuation_items_(std::move(evacuation_items)),
        remaining_evacuation_items_(evacuation_items_.size()),
        generator_(evacuation_items_.size()),
        tracer_(isolate->heap()->tracer()),
        trace_id_(reinterpret_cast<uint64_t>(this) ^
                  tracer_->CurrentEpoch(GCTracer::Scope::MC_EVACUATE)) {}

  void Run(JobDelegate* delegate) override {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        collector_->heap()->isolate());

    Evacuator* evacuator = (*evacuators_)[delegate->GetTaskId()].get();
    if (delegate->IsJoiningThread()) {
      TRACE_GC_WITH_FLOW(tracer_, GCTracer::Scope::MC_EVACUATE_COPY_PARALLEL,
                         trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      ProcessItems(delegate, evacuator);
    } else {
      TRACE_GC_EPOCH_WITH_FLOW(
          tracer_, GCTracer::Scope::MC_BACKGROUND_EVACUATE_COPY,
          ThreadKind::kBackground, trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      ProcessItems(delegate, evacuator);
    }
  }

  void ProcessItems(JobDelegate* delegate, Evacuator* evacuator) {
    while (remaining_evacuation_items_.load(std::memory_order_relaxed) > 0) {
      std::optional<size_t> index = generator_.GetNext();
      if (!index) return;
      for (size_t i = *index; i < evacuation_items_.size(); ++i) {
        auto& work_item = evacuation_items_[i];
        if (!work_item.first.TryAcquire()) break;
        evacuator->EvacuatePage(work_item.second);
        if (remaining_evacuation_items_.fetch_sub(
                1, std::memory_order_relaxed) <= 1) {
          return;
        }
      }
    }
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    const size_t kItemsPerWorker = std::max(1, MB / PageMetadata::kPageSize);
    // Ceiling division to ensure enough workers for all
    // |remaining_evacuation_items_|
    size_t wanted_num_workers =
        (remaining_evacuation_items_.load(std::memory_order_relaxed) +
         kItemsPerWorker - 1) /
        kItemsPerWorker;
    wanted_num_workers =
        std::min<size_t>(wanted_num_workers, evacuators_->size());
    if (!collector_->UseBackgroundThreadsInCycle()) {
      return std::min<size_t>(wanted_num_workers, 1);
    }
    return wanted_num_workers;
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  MarkCompactCollector* collector_;
  std::vector<std::unique_ptr<Evacuator>>* evacuators_;
  std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
      evacuation_items_;
  std::atomic<size_t> remaining_evacuation_items_{0};
  IndexGenerator generator_;

  GCTracer* tracer_;
  const uint64_t trace_id_;
};

namespace {
size_t CreateAndExecuteEvacuationTasks(
    Heap* heap, MarkCompactCollector* collector,
    std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
        evacuation_items) {
  std::optional<ProfilingMigrationObserver> profiling_observer;
  if (heap->isolate()->log_object_relocation()) {
    profiling_observer.emplace(heap);
  }
  std::vector<std::unique_ptr<v8::internal::Evacuator>> evacuators;
  const int wanted_num_tasks = NumberOfParallelCompactionTasks(heap);
  for (int i = 0; i < wanted_num_tasks; i++) {
    auto evacuator = std::make_unique<Evacuator>(heap);
    if (profiling_observer) {
      evacuator->AddObserver(&profiling_observer.value());
    }
    evacuators.push_back(std::move(evacuator));
  }
  auto page_evacuation_job = std::make_unique<PageEvacuationJob>(
      heap->isolate(), collector, &evacuators, std::move(evacuation_items));
  TRACE_GC_NOTE_WITH_FLOW("PageEvacuationJob started",
                          page_evacuation_job->trace_id(),
                          TRACE_EVENT_FLAG_FLOW_OUT);
  V8::GetCurrentPlatform()
      ->CreateJob(v8::TaskPriority::kUserBlocking,
                  std::move(page_evacuation_job))
      ->Join();
  for (auto& evacuator : evacuators) {
    evacuator->Finalize();
  }
  return wanted_num_tasks;
}

enum class MemoryReductionMode { kNone, kShouldReduceMemory };

// NewSpacePages with more live bytes than this threshold qualify for fast
// evacuation.
intptr_t NewSpacePageEvacuationThreshold() {
  return v8_flags.page_promotion_threshold *
         MemoryChunkLayout::AllocatableMemoryInDataPage() / 100;
}

bool ShouldMovePage(PageMetadata* p, intptr_t live_bytes,
                    MemoryReductionMode memory_reduction_mode) {
  Heap* heap = p->heap();
  DCHECK(!p->Chunk()->NeverEvacuate());
  const bool should_move_page =
      v8_flags.page_promotion &&
      (memory_reduction_mode == MemoryReductionMode::kNone) &&
      (live_bytes > NewSpacePageEvacuationThreshold()) &&
      heap->CanExpandOldGeneration(live_bytes);
  if (v8_flags.trace_page_promotions) {
    PrintIsolate(heap->isolate(),
                 "[Page Promotion] %p: collector=mc, should move: %d"
                 ", live bytes = %zu, promotion threshold = %zu"
                 ", allocated labs size = %zu\n",
                 p, should_move_page, live_bytes,
                 NewSpacePageEvacuationThreshold(), p->AllocatedLabSize());
  }
  return should_move_page;
}

void TraceEvacuation(Isolate* isolate, size_t pages_count,
                     size_t wanted_num_tasks, size_t live_bytes,
                     size_t aborted_pages) {
  DCHECK(v8_flags.trace_evacuation);
  PrintIsolate(
      isolate,
      "%8.0f ms: evacuation-summary: parallel=%s pages=%zu "
      "wanted_tasks=%zu cores=%d live_bytes=%" V8PRIdPTR
      " compaction_speed=%.f aborted=%zu\n",
      isolate->time_millis_since_init(),
      v8_flags.parallel_compaction ? "yes" : "no", pages_count,
      wanted_num_tasks, V8::GetCurrentPlatform()->NumberOfWorkerThreads() + 1,
      live_bytes,
      isolate->heap()->tracer()->CompactionSpeedInBytesPerMillisecond(),
      aborted_pages);
}

}  // namespace

void MarkCompactCollector::EvacuatePagesInParallel() {
  std::vector<std::pair<ParallelWorkItem, MutablePageMetadata*>>
      evacuation_items;
  intptr_t live_bytes = 0;

  // Evacuation of new space pages cannot be aborted, so it needs to run
  // before old space evacuation.
  bool force_page_promotion =
      heap_->IsGCWithStack() && !v8_flags.compact_with_stack;
  for (PageMetadata* page : new_space_evacuation_pages_) {
    intptr_t live_bytes_on_page = page->live_bytes();
    DCHECK_LT(0, live_bytes_on_page);
    live_bytes += live_bytes_on_page;
    MemoryReductionMode memory_reduction_mode =
        heap_->ShouldReduceMemory() ? MemoryReductionMode::kShouldReduceMemory
                                    : MemoryReductionMode::kNone;
    if (ShouldMovePage(page, live_bytes_on_page, memory_reduction_mode) ||
        force_page_promotion) {
      EvacuateNewToOldSpacePageVisitor::Move(page);
      page->Chunk()->SetFlagNonExecutable(MemoryChunk::PAGE_NEW_OLD_PROMOTION);
      DCHECK_EQ(heap_->old_space(), page->owner());
      // The move added page->allocated_bytes to the old space, but we are
      // going to sweep the page and add page->live_byte_count.
      heap_->old_space()->DecreaseAllocatedBytes(page->allocated_bytes(), page);
    }
    evacuation_items.emplace_back(ParallelWorkItem{}, page);
  }

  if (heap_->IsGCWithStack()) {
    if (!v8_flags.compact_with_stack) {
      for (PageMetadata* page : old_space_evacuation_pages_) {
        ReportAbortedEvacuationCandidateDueToFlags(page->area_start(), page);
      }
    } else if (!v8_flags.compact_code_space_with_stack ||
               heap_->isolate()->InFastCCall()) {
      // For fast C calls we cannot patch the return address in the native stack
      // frame if we would relocate InstructionStream objects.
      for (PageMetadata* page : old_space_evacuation_pages_) {
        if (page->owner_identity() != CODE_SPACE) continue;
        ReportAbortedEvacuationCandidateDueToFlags(page->area_start(), page);
      }
    }
  } else {
    // There should always be a stack when we are in a fast c call.
    DCHECK(!heap_->isolate()->InFastCCall());
  }

  if (v8_flags.stress_compaction || v8_flags.stress_compaction_random) {
    // Stress aborting of evacuation by aborting ~10% of evacuation candidates
    // when stress testing.
    const double kFraction = 0.05;

    for (PageMetadata* page : old_space_evacuation_pages_) {
      MemoryChunk* chunk = page->Chunk();
      if (chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED)) continue;

      if (heap_->isolate()->fuzzer_rng()->NextDouble() < kFraction) {
        ReportAbortedEvacuationCandidateDueToFlags(page->area_start(), page);
      }
    }
  }

  for (PageMetadata* page : old_space_evacuation_pages_) {
    MemoryChunk* chunk = page->Chunk();
    if (chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED)) continue;

    live_bytes += page->live_bytes();
    evacuation_items.emplace_back(ParallelWorkItem{}, page);
  }

  // Promote young generation large objects.
  if (auto* new_lo_space = heap_->new_lo_space()) {
    for (auto it = new_lo_space->begin(); it != new_lo_space->end();) {
      LargePageMetadata* current = *(it++);
      Tagged<HeapObject> object = current->GetObject();
      // The black-allocated flag was already cleared in SweepLargeSpace().
      DCHECK_IMPLIES(v8_flags.black_allocated_pages,
                     !HeapLayout::InBlackAllocatedPage(object));
      if (marking_state_->IsMarked(object)) {
        heap_->lo_space()->PromoteNewLargeObject(current);
        current->Chunk()->SetFlagNonExecutable(
            MemoryChunk::PAGE_NEW_OLD_PROMOTION);
        promoted_large_pages_.push_back(current);
        evacuation_items.emplace_back(ParallelWorkItem{}, current);
      }
    }
    new_lo_space->set_objects_size(0);
  }

  const size_t pages_count = evacuation_items.size();
  size_t wanted_num_tasks = 0;
  if (!evacuation_items.empty()) {
    TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
                 "MarkCompactCollector::EvacuatePagesInParallel", "pages",
                 evacuation_items.size());

    wanted_num_tasks = CreateAndExecuteEvacuationTasks(
        heap_, this, std::move(evacuation_items));
  }

  const size_t aborted_pages = PostProcessAbortedEvacuationCandidates();

  if (v8_flags.trace_evacuation) {
    TraceEvacuation(heap_->isolate(), pages_count, wanted_num_tasks, live_bytes,
                    aborted_pages);
  }
}

class EvacuationWeakObjectRetainer : public WeakObjectRetainer {
 public:
  Tagged<Object> RetainAs(Tagged<Object> object) override {
    if (object.IsHeapObject()) {
      Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
      MapWord map_word = heap_object->map_word(kRelaxedLoad);
      if (map_word.IsForwardingAddress()) {
        return map_word.ToForwardingAddress(heap_object);
      }
    }
    return object;
  }
};

void MarkCompactCollector::Evacuate() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE);
  base::MutexGuard guard(heap_->relocation_mutex());

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_PROLOGUE);
    EvacuatePrologue();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_COPY);
    EvacuatePagesInParallel();
  }

  UpdatePointersAfterEvacuation();

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_CLEAN_UP);

    for (PageMetadata* p : new_space_evacuation_pages_) {
      MemoryChunk* chunk = p->Chunk();
      AllocationSpace owner_identity = p->owner_identity();
      USE(owner_identity);
      if (chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION)) {
        chunk->ClearFlagNonExecutable(MemoryChunk::PAGE_NEW_OLD_PROMOTION);
        // The in-sandbox page flags may be corrupted, so we currently need
        // this check here to make sure that this doesn't lead to further
        // confusion about the state of MemoryChunkMetadata objects.
        // TODO(377724745): if we move (some of) the flags into the trusted
        // MemoryChunkMetadata object, then this wouldn't be necessary.
        SBXCHECK_EQ(OLD_SPACE, owner_identity);
        sweeper_->AddPage(OLD_SPACE, p);
      } else if (v8_flags.minor_ms) {
        // Sweep non-promoted pages to add them back to the free list.
        DCHECK_EQ(NEW_SPACE, owner_identity);
        DCHECK_EQ(0, p->live_bytes());
        DCHECK(p->SweepingDone());
        PagedNewSpace* space = heap_->paged_new_space();
        if (space->ShouldReleaseEmptyPage()) {
          space->ReleasePage(p);
        } else {
          sweeper_->SweepEmptyNewSpacePage(p);
        }
      }
    }
    new_space_evacuation_pages_.clear();

    for (LargePageMetadata* p : promoted_large_pages_) {
      MemoryChunk* chunk = p->Chunk();
      DCHECK(chunk->IsFlagSet(MemoryChunk::PAGE_NEW_OLD_PROMOTION));
      chunk->ClearFlagNonExecutable(MemoryChunk::PAGE_NEW_OLD_PROMOTION);
      Tagged<HeapObject> object = p->GetObject();
      if (!v8_flags.sticky_mark_bits) {
        MarkBit::From(object).Clear();
        p->SetLiveBytes(0);
      }
      p->MarkingProgressTracker().ResetIfEnabled();
    }
    promoted_large_pages_.clear();

    for (PageMetadata* p : old_space_evacuation_pages_) {
      MemoryChunk* chunk = p->Chunk();
      if (chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED)) {
        sweeper_->AddPage(p->owner_identity(), p);
        chunk->ClearFlagSlow(MemoryChunk::COMPACTION_WAS_ABORTED);
      }
    }
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_EPILOGUE);
    EvacuateEpilogue();
  }

#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap && !sweeper_->sweeping_in_progress()) {
    EvacuationVerifier verifier(heap_);
    verifier.Run();
  }
#endif  // VERIFY_HEAP
}

class UpdatingItem : public ParallelWorkItem {
 public:
  virtual ~UpdatingItem() = default;
  virtual void Process() = 0;
};

class PointersUpdatingJob : public v8::JobTask {
 public:
  explicit PointersUpdatingJob(
      Isolate* isolate, MarkCompactCollector* collector,
      std::vector<std::unique_ptr<UpdatingItem>> updating_items)
      : collector_(collector),
        updating_items_(std::move(updating_items)),
        remaining_updating_items_(updating_items_.size()),
        generator_(updating_items_.size()),
        tracer_(isolate->h
"""


```