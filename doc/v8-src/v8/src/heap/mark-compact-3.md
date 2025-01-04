Response: The user wants a summary of the functionality of the C++ code provided, specifically the `v8/src/heap/mark-compact.cc` file, part 4 of 4. I need to identify the main actions performed in this code snippet and explain its role in the mark-compact garbage collection process. Since the user explicitly asked about the relationship with Javascript, I should provide a Javascript example illustrating the concepts if applicable.

Based on the code, it appears this part focuses on the **pointer updating phase** after the evacuation phase of the mark-compact garbage collection. It involves iterating through different memory spaces and updating pointers that might have become stale due to object movement during evacuation. Key aspects include:

1. **Updating Pointers:** The core functionality revolves around the `UpdatePointers` methods within different `UpdatingItem` classes.
2. **Remembered Sets:** It processes remembered sets (`OLD_TO_NEW`, `OLD_TO_OLD`, `TRUSTED_TO_CODE`, etc.) to find pointers that need updating.
3. **Iterating through Memory Spaces:** It operates on various memory spaces like old space, code space, large object space, etc.
4. **Handling Different Pointer Types:** It distinguishes between regular object pointers and code pointers, handling them appropriately.
5. **Parallel Processing:**  It utilizes jobs to perform pointer updates in parallel.
6. **Ephemeron Tables:**  It handles ephemeron hash tables, updating keys if the pointed-to objects have moved.
7. **Weak References:**  It processes weak references.
8. **Aborted Evacuation:** It manages scenarios where evacuation was aborted and re-processes the affected pages.
9. **Sweeping:** It includes logic for initiating the sweeping phase for different memory spaces.

Regarding the connection to Javascript, this process is transparent to the Javascript developer. However, the efficiency of this pointer updating phase directly impacts the performance of Javascript execution. When a Javascript object is moved during garbage collection, its references throughout the heap must be updated so that the Javascript program can still access the object correctly.

I will structure the answer by:
1. Summarizing the main functionality: updating pointers after object evacuation.
2. Detailing the key processes: processing remembered sets, iterating through spaces, handling pointer types, parallelization, ephemeron tables, weak references, and aborted evacuation.
3. Providing a Javascript example illustrating the need for pointer updates due to object movement during GC.
4. Briefly mentioning the sweeping phase.
这是 `v8/src/heap/mark-compact.cc` 文件的第四部分，主要负责在标记压缩垃圾回收过程中的**疏散（Evacuation）阶段之后更新指针**。这是垃圾回收的关键步骤，因为在疏散阶段，存活的对象会被移动到新的位置，所有指向这些移动对象的指针都需要被更新，以确保程序能够正确地访问它们。

以下是这部分代码的主要功能归纳：

1. **更新根对象指针:**  遍历根对象（例如全局变量、栈上的变量等），如果它们指向的对象在疏散过程中被移动了，则更新这些指针。

2. **更新客户端堆的指针:** 如果V8运行时有多个隔离堆（Isolate），则更新其他客户端堆中指向当前堆中移动对象的指针。

3. **更新Remembered Sets中的指针:**  处理各种类型的 Remembered Sets (例如 `OLD_TO_NEW`, `OLD_TO_OLD`, `TRUSTED_TO_CODE` 等)。这些集合记录了跨代或跨空间的指针，需要被检查和更新。
    - 对于 `OLD_TO_NEW` 指针，将指向新生代对象的指针更新为对象的新位置。
    - 对于 `OLD_TO_OLD` 指针，将指向老年代对象的指针更新为对象的新位置。
    - 对于 `TRUSTED_TO_CODE` 指针，更新指向代码对象的指针。
    - 特别地，它会区分非类型化指针和类型化指针，并使用相应的更新机制。

4. **处理Ephemeron哈希表:**  更新 Ephemeron 哈希表中的键，如果键指向的对象被移动了，则更新键的指针。

5. **处理弱引用:**  更新外部字符串表中的引用，以及字符串转发表中的引用。处理弱引用列表，决定哪些弱引用对象应该被保留或清除。

6. **更新指针表:**  更新 `TrustedPointerTable` 和 `CodePointerTable` 等指针表中的条目，确保它们指向的对象是有效的。

7. **处理被中止的疏散候选页:**  记录并处理由于内存不足或其他原因导致疏散失败的页面，重新记录这些页面上的槽位信息。

8. **释放疏散候选页:**  释放成功疏散的页面。

9. **启动空间清理（Sweeping）:**  为不同类型的内存空间（新生代、老年代、代码空间等）启动清理过程，回收不再使用的内存。这部分代码开始设置清理操作，但实际的清理工作可能在其他地方完成。

**与 Javascript 的关系及示例:**

虽然 Javascript 开发者通常不需要直接关心垃圾回收的细节，但这个阶段的指针更新对于保证 Javascript 程序的正确性至关重要。当一个 Javascript 对象在内存中移动时，所有指向该对象的 Javascript 变量、对象属性等都需要相应地更新。

**Javascript 示例:**

```javascript
let obj1 = { data: "原始数据" };
let obj2 = { ref: obj1 }; // obj2 引用了 obj1

// ... 一些操作可能触发垃圾回收 ...

// 在垃圾回收的疏散阶段，obj1 可能被移动到新的内存地址

// 指针更新阶段会确保 obj2.ref 仍然指向 obj1 的新地址

console.log(obj2.ref.data); // 即使 obj1 移动了，仍然可以正确访问其数据
```

在这个例子中，`obj2.ref` 指向 `obj1`。当垃圾回收发生并且 `obj1` 因为内存整理而被移动时，`mark-compact.cc` 中的指针更新代码会确保 `obj2.ref` 不会指向旧的内存地址，而是指向 `obj1` 的新地址。这样，Javascript 代码仍然可以正确地通过 `obj2.ref` 访问 `obj1` 的数据，而无需开发者手动管理内存地址。

总而言之，`v8/src/heap/mark-compact.cc` 的这部分代码是 V8 引擎进行高效、可靠垃圾回收的关键组成部分，它确保了在内存整理后，Javascript 程序的引用关系仍然有效，从而保证了程序的正确运行。

Prompt: 
```
这是目录为v8/src/heap/mark-compact.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
eap()->tracer()),
        trace_id_(reinterpret_cast<uint64_t>(this) ^
                  tracer_->CurrentEpoch(GCTracer::Scope::MC_EVACUATE)) {}

  void Run(JobDelegate* delegate) override {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(
        collector_->heap()->isolate());

    if (delegate->IsJoiningThread()) {
      TRACE_GC_WITH_FLOW(tracer_,
                         GCTracer::Scope::MC_EVACUATE_UPDATE_POINTERS_PARALLEL,
                         trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      UpdatePointers(delegate);
    } else {
      TRACE_GC_EPOCH_WITH_FLOW(
          tracer_, GCTracer::Scope::MC_BACKGROUND_EVACUATE_UPDATE_POINTERS,
          ThreadKind::kBackground, trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      UpdatePointers(delegate);
    }
  }

  void UpdatePointers(JobDelegate* delegate) {
    while (remaining_updating_items_.load(std::memory_order_relaxed) > 0) {
      std::optional<size_t> index = generator_.GetNext();
      if (!index) return;
      for (size_t i = *index; i < updating_items_.size(); ++i) {
        auto& work_item = updating_items_[i];
        if (!work_item->TryAcquire()) break;
        work_item->Process();
        if (remaining_updating_items_.fetch_sub(1, std::memory_order_relaxed) <=
            1) {
          return;
        }
      }
    }
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    size_t items = remaining_updating_items_.load(std::memory_order_relaxed);
    if (!v8_flags.parallel_pointer_update ||
        !collector_->UseBackgroundThreadsInCycle()) {
      return std::min<size_t>(items, 1);
    }
    const size_t kMaxPointerUpdateTasks = 8;
    size_t max_concurrency = std::min<size_t>(kMaxPointerUpdateTasks, items);
    DCHECK_IMPLIES(items > 0, max_concurrency > 0);
    return max_concurrency;
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  MarkCompactCollector* collector_;
  std::vector<std::unique_ptr<UpdatingItem>> updating_items_;
  std::atomic<size_t> remaining_updating_items_{0};
  IndexGenerator generator_;

  GCTracer* tracer_;
  const uint64_t trace_id_;
};

namespace {

class RememberedSetUpdatingItem : public UpdatingItem {
 public:
  explicit RememberedSetUpdatingItem(Heap* heap, MutablePageMetadata* chunk)
      : heap_(heap),
        marking_state_(heap_->non_atomic_marking_state()),
        chunk_(chunk),
        record_old_to_shared_slots_(heap->isolate()->has_shared_space() &&
                                    !chunk->Chunk()->InWritableSharedSpace()) {}
  ~RememberedSetUpdatingItem() override = default;

  void Process() override {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
                 "RememberedSetUpdatingItem::Process");
    UpdateUntypedPointers();
    UpdateTypedPointers();
  }

 private:
  template <typename TSlot>
  inline void CheckSlotForOldToSharedUntyped(PtrComprCageBase cage_base,
                                             MutablePageMetadata* page,
                                             TSlot slot) {
    Tagged<HeapObject> heap_object;

    if (!slot.load(cage_base).GetHeapObject(&heap_object)) {
      return;
    }

    if (HeapLayout::InWritableSharedSpace(heap_object)) {
      RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::NON_ATOMIC>(
          page, page->Offset(slot.address()));
    }
  }

  inline void CheckSlotForOldToSharedTyped(
      MutablePageMetadata* page, SlotType slot_type, Address addr,
      WritableJitAllocation& jit_allocation) {
    Tagged<HeapObject> heap_object =
        UpdateTypedSlotHelper::GetTargetObject(page->heap(), slot_type, addr);

#if DEBUG
    UpdateTypedSlotHelper::UpdateTypedSlot(
        jit_allocation, page->heap(), slot_type, addr,
        [heap_object](FullMaybeObjectSlot slot) {
          DCHECK_EQ((*slot).GetHeapObjectAssumeStrong(), heap_object);
          return KEEP_SLOT;
        });
#endif  // DEBUG

    if (HeapLayout::InWritableSharedSpace(heap_object)) {
      const uintptr_t offset = page->Offset(addr);
      DCHECK_LT(offset, static_cast<uintptr_t>(TypedSlotSet::kMaxOffset));
      RememberedSet<OLD_TO_SHARED>::InsertTyped(page, slot_type,
                                                static_cast<uint32_t>(offset));
    }
  }

  template <typename TSlot>
  inline void CheckAndUpdateOldToNewSlot(TSlot slot,
                                         const PtrComprCageBase cage_base) {
    static_assert(
        std::is_same<TSlot, FullMaybeObjectSlot>::value ||
            std::is_same<TSlot, MaybeObjectSlot>::value,
        "Only FullMaybeObjectSlot and MaybeObjectSlot are expected here");
    Tagged<HeapObject> heap_object;
    if (!(*slot).GetHeapObject(&heap_object)) return;
    if (!HeapLayout::InYoungGeneration(heap_object)) return;

    if (!v8_flags.sticky_mark_bits) {
      DCHECK_IMPLIES(v8_flags.minor_ms && !Heap::IsLargeObject(heap_object),
                     Heap::InToPage(heap_object));
      DCHECK_IMPLIES(!v8_flags.minor_ms || Heap::IsLargeObject(heap_object),
                     Heap::InFromPage(heap_object));
    }

    // OLD_TO_NEW slots are recorded in dead memory, so they might point to
    // dead objects.
    DCHECK_IMPLIES(!heap_object->map_word(kRelaxedLoad).IsForwardingAddress(),
                   !marking_state_->IsMarked(heap_object));
    UpdateSlot(cage_base, slot);
  }

  void UpdateUntypedPointers() {
    UpdateUntypedOldToNewPointers<OLD_TO_NEW>();
    UpdateUntypedOldToNewPointers<OLD_TO_NEW_BACKGROUND>();
    UpdateUntypedOldToOldPointers();
    UpdateUntypedTrustedToCodePointers();
    UpdateUntypedTrustedToTrustedPointers();
  }

  template <RememberedSetType old_to_new_type>
  void UpdateUntypedOldToNewPointers() {
    if (!chunk_->slot_set<old_to_new_type, AccessMode::NON_ATOMIC>()) {
      return;
    }

    const PtrComprCageBase cage_base = heap_->isolate();
    // Marking bits are cleared already when the page is already swept. This
    // is fine since in that case the sweeper has already removed dead invalid
    // objects as well.
    RememberedSet<old_to_new_type>::Iterate(
        chunk_,
        [this, cage_base](MaybeObjectSlot slot) {
          CheckAndUpdateOldToNewSlot(slot, cage_base);
          // A new space string might have been promoted into the shared heap
          // during GC.
          if (record_old_to_shared_slots_) {
            CheckSlotForOldToSharedUntyped(cage_base, chunk_, slot);
          }
          // Always keep slot since all slots are dropped at once after
          // iteration.
          return KEEP_SLOT;
        },
        SlotSet::KEEP_EMPTY_BUCKETS);

    // Full GCs will empty new space, so [old_to_new_type] is empty.
    chunk_->ReleaseSlotSet(old_to_new_type);
  }

  void UpdateUntypedOldToOldPointers() {
    if (!chunk_->slot_set<OLD_TO_OLD, AccessMode::NON_ATOMIC>()) {
      return;
    }

    const PtrComprCageBase cage_base = heap_->isolate();
    if (chunk_->Chunk()->executable()) {
      // When updating pointer in an InstructionStream (in particular, the
      // pointer to relocation info), we need to use WriteProtectedSlots that
      // ensure that the code page is unlocked.
      WritableJitPage jit_page(chunk_->area_start(), chunk_->area_size());
      RememberedSet<OLD_TO_OLD>::Iterate(
          chunk_,
          [&](MaybeObjectSlot slot) {
            WritableJitAllocation jit_allocation =
                jit_page.LookupAllocationContaining(slot.address());
            UpdateSlot(cage_base, WriteProtectedSlot<ObjectSlot>(
                                      jit_allocation, slot.address()));
            // Always keep slot since all slots are dropped at once after
            // iteration.
            return KEEP_SLOT;
          },
          SlotSet::KEEP_EMPTY_BUCKETS);
    } else {
      RememberedSet<OLD_TO_OLD>::Iterate(
          chunk_,
          [&](MaybeObjectSlot slot) {
            UpdateSlot(cage_base, slot);
            // A string might have been promoted into the shared heap during
            // GC.
            if (record_old_to_shared_slots_) {
              CheckSlotForOldToSharedUntyped(cage_base, chunk_, slot);
            }
            // Always keep slot since all slots are dropped at once after
            // iteration.
            return KEEP_SLOT;
          },
          SlotSet::KEEP_EMPTY_BUCKETS);
    }

    chunk_->ReleaseSlotSet(OLD_TO_OLD);
  }

  void UpdateUntypedTrustedToCodePointers() {
    if (!chunk_->slot_set<TRUSTED_TO_CODE, AccessMode::NON_ATOMIC>()) {
      return;
    }

#ifdef V8_ENABLE_SANDBOX
    // When the sandbox is enabled, we must not process the TRUSTED_TO_CODE
    // remembered set on any chunk that is located inside the sandbox (in which
    // case the set should be unused). This is because an attacker could either
    // directly modify the TRUSTED_TO_CODE set on such a chunk, or trick the GC
    // into populating it with invalid pointers, both of which may lead to
    // memory corruption inside the (trusted) code space here.
    SBXCHECK(!InsideSandbox(chunk_->ChunkAddress()));
#endif

    const PtrComprCageBase cage_base = heap_->isolate();
#ifdef V8_EXTERNAL_CODE_SPACE
    const PtrComprCageBase code_cage_base(heap_->isolate()->code_cage_base());
#else
    const PtrComprCageBase code_cage_base = cage_base;
#endif
    RememberedSet<TRUSTED_TO_CODE>::Iterate(
        chunk_,
        [=](MaybeObjectSlot slot) {
          Tagged<HeapObject> host = HeapObject::FromAddress(
              slot.address() - Code::kInstructionStreamOffset);
          DCHECK(IsCode(host, cage_base));
          UpdateStrongCodeSlot(host, cage_base, code_cage_base,
                               InstructionStreamSlot(slot.address()));
          // Always keep slot since all slots are dropped at once after
          // iteration.
          return KEEP_SLOT;
        },
        SlotSet::FREE_EMPTY_BUCKETS);

    chunk_->ReleaseSlotSet(TRUSTED_TO_CODE);
  }

  void UpdateUntypedTrustedToTrustedPointers() {
    if (!chunk_->slot_set<TRUSTED_TO_TRUSTED, AccessMode::NON_ATOMIC>()) {
      return;
    }

#ifdef V8_ENABLE_SANDBOX
    // When the sandbox is enabled, we must not process the TRUSTED_TO_TRUSTED
    // remembered set on any chunk that is located inside the sandbox (in which
    // case the set should be unused). This is because an attacker could either
    // directly modify the TRUSTED_TO_TRUSTED set on such a chunk, or trick the
    // GC into populating it with invalid pointers, both of which may lead to
    // memory corruption inside the trusted space here.
    SBXCHECK(!InsideSandbox(chunk_->ChunkAddress()));
#endif

    // TODO(saelo) we can probably drop all the cage_bases here once we no
    // longer need to pass them into our slot implementations.
    const PtrComprCageBase unused_cage_base(kNullAddress);

    if (chunk_->Chunk()->executable()) {
      // When updating the InstructionStream -> Code pointer, we need to use
      // WriteProtectedSlots that ensure that the code page is unlocked.
      WritableJitPage jit_page(chunk_->area_start(), chunk_->area_size());

      RememberedSet<TRUSTED_TO_TRUSTED>::Iterate(
          chunk_,
          [&](MaybeObjectSlot slot) {
            WritableJitAllocation jit_allocation =
                jit_page.LookupAllocationContaining(slot.address());
            UpdateStrongSlot(unused_cage_base,
                             WriteProtectedSlot<ProtectedPointerSlot>(
                                 jit_allocation, slot.address()));
            // Always keep slot since all slots are dropped at once after
            // iteration.
            return KEEP_SLOT;
          },
          SlotSet::FREE_EMPTY_BUCKETS);
    } else {
      RememberedSet<TRUSTED_TO_TRUSTED>::Iterate(
          chunk_,
          [&](MaybeObjectSlot slot) {
            UpdateStrongSlot(unused_cage_base,
                             ProtectedPointerSlot(slot.address()));
            // Always keep slot since all slots are dropped at once after
            // iteration.
            return KEEP_SLOT;
          },
          SlotSet::FREE_EMPTY_BUCKETS);
    }

    chunk_->ReleaseSlotSet(TRUSTED_TO_TRUSTED);
  }

  void UpdateTypedPointers() {
    if (!chunk_->Chunk()->executable()) {
      DCHECK_NULL((chunk_->typed_slot_set<OLD_TO_NEW>()));
      DCHECK_NULL((chunk_->typed_slot_set<OLD_TO_OLD>()));
      return;
    }

    WritableJitPage jit_page = ThreadIsolation::LookupWritableJitPage(
        chunk_->area_start(), chunk_->area_size());
    UpdateTypedOldToNewPointers(jit_page);
    UpdateTypedOldToOldPointers(jit_page);
  }

  void UpdateTypedOldToNewPointers(WritableJitPage& jit_page) {
    if (chunk_->typed_slot_set<OLD_TO_NEW, AccessMode::NON_ATOMIC>() == nullptr)
      return;
    const PtrComprCageBase cage_base = heap_->isolate();
    const auto check_and_update_old_to_new_slot_fn =
        [this, cage_base](FullMaybeObjectSlot slot) {
          CheckAndUpdateOldToNewSlot(slot, cage_base);
          return KEEP_SLOT;
        };

    RememberedSet<OLD_TO_NEW>::IterateTyped(
        chunk_, [this, &check_and_update_old_to_new_slot_fn, &jit_page](
                    SlotType slot_type, Address slot) {
          WritableJitAllocation jit_allocation =
              jit_page.LookupAllocationContaining(slot);
          UpdateTypedSlotHelper::UpdateTypedSlot(
              jit_allocation, heap_, slot_type, slot,
              check_and_update_old_to_new_slot_fn);
          // A new space string might have been promoted into the shared heap
          // during GC.
          if (record_old_to_shared_slots_) {
            CheckSlotForOldToSharedTyped(chunk_, slot_type, slot,
                                         jit_allocation);
          }
          // Always keep slot since all slots are dropped at once after
          // iteration.
          return KEEP_SLOT;
        });
    // Full GCs will empty new space, so OLD_TO_NEW is empty.
    chunk_->ReleaseTypedSlotSet(OLD_TO_NEW);
    // OLD_TO_NEW_BACKGROUND typed slots set should always be empty.
    DCHECK_NULL(chunk_->typed_slot_set<OLD_TO_NEW_BACKGROUND>());
  }

  void UpdateTypedOldToOldPointers(WritableJitPage& jit_page) {
    if (chunk_->typed_slot_set<OLD_TO_OLD, AccessMode::NON_ATOMIC>() == nullptr)
      return;
    PtrComprCageBase cage_base = heap_->isolate();
    RememberedSet<OLD_TO_OLD>::IterateTyped(
        chunk_, [this, cage_base, &jit_page](SlotType slot_type, Address slot) {
          // Using UpdateStrongSlot is OK here, because there are no weak
          // typed slots.
          WritableJitAllocation jit_allocation =
              jit_page.LookupAllocationContaining(slot);
          SlotCallbackResult result = UpdateTypedSlotHelper::UpdateTypedSlot(
              jit_allocation, heap_, slot_type, slot,
              [cage_base](FullMaybeObjectSlot slot) {
                UpdateStrongSlot(cage_base, slot);
                // Always keep slot since all slots are dropped at once after
                // iteration.
                return KEEP_SLOT;
              });
          // A string might have been promoted into the shared heap during GC.
          if (record_old_to_shared_slots_) {
            CheckSlotForOldToSharedTyped(chunk_, slot_type, slot,
                                         jit_allocation);
          }
          return result;
        });
    chunk_->ReleaseTypedSlotSet(OLD_TO_OLD);
  }

  Heap* heap_;
  NonAtomicMarkingState* marking_state_;
  MutablePageMetadata* chunk_;
  const bool record_old_to_shared_slots_;
};

}  // namespace

namespace {
template <typename IterateableSpace>
void CollectRememberedSetUpdatingItems(
    std::vector<std::unique_ptr<UpdatingItem>>* items,
    IterateableSpace* space) {
  for (MutablePageMetadata* page : *space) {
    // No need to update pointers on evacuation candidates. Evacuated pages will
    // be released after this phase.
    if (page->Chunk()->IsEvacuationCandidate()) continue;
    if (page->ContainsAnySlots()) {
      items->emplace_back(
          std::make_unique<RememberedSetUpdatingItem>(space->heap(), page));
    }
  }
}
}  // namespace

class EphemeronTableUpdatingItem : public UpdatingItem {
 public:
  enum EvacuationState { kRegular, kAborted };

  explicit EphemeronTableUpdatingItem(Heap* heap) : heap_(heap) {}
  ~EphemeronTableUpdatingItem() override = default;

  void Process() override {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("v8.gc"),
                 "EphemeronTableUpdatingItem::Process");
    PtrComprCageBase cage_base(heap_->isolate());

    auto* table_map = heap_->ephemeron_remembered_set()->tables();
    for (auto it = table_map->begin(); it != table_map->end(); it++) {
      Tagged<EphemeronHashTable> table = it->first;
      auto& indices = it->second;
      if (Cast<HeapObject>(table)
              ->map_word(kRelaxedLoad)
              .IsForwardingAddress()) {
        // The object has moved, so ignore slots in dead memory here.
        continue;
      }
      DCHECK(IsMap(table->map(), cage_base));
      DCHECK(IsEphemeronHashTable(table, cage_base));
      for (auto iti = indices.begin(); iti != indices.end(); ++iti) {
        // EphemeronHashTable keys must be heap objects.
        ObjectSlot key_slot(table->RawFieldOfElementAt(
            EphemeronHashTable::EntryToIndex(InternalIndex(*iti))));
        Tagged<Object> key_object = key_slot.Relaxed_Load();
        Tagged<HeapObject> key;
        CHECK(key_object.GetHeapObject(&key));
        MapWord map_word = key->map_word(cage_base, kRelaxedLoad);
        if (map_word.IsForwardingAddress()) {
          key = map_word.ToForwardingAddress(key);
          key_slot.Relaxed_Store(key);
        }
      }
    }
    table_map->clear();
  }

 private:
  Heap* const heap_;
};

void MarkCompactCollector::UpdatePointersAfterEvacuation() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_EVACUATE_UPDATE_POINTERS);

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_EVACUATE_UPDATE_POINTERS_TO_NEW_ROOTS);
    // The external string table is updated at the end.
    PointersUpdatingVisitor updating_visitor(heap_);
    heap_->IterateRootsIncludingClients(
        &updating_visitor,
        base::EnumSet<SkipRoot>{SkipRoot::kExternalStringTable,
                                SkipRoot::kConservativeStack,
                                SkipRoot::kReadOnlyBuiltins});
  }

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_EVACUATE_UPDATE_POINTERS_CLIENT_HEAPS);
    UpdatePointersInClientHeaps();
  }

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_EVACUATE_UPDATE_POINTERS_SLOTS_MAIN);
    std::vector<std::unique_ptr<UpdatingItem>> updating_items;

    CollectRememberedSetUpdatingItems(&updating_items, heap_->old_space());
    CollectRememberedSetUpdatingItems(&updating_items, heap_->code_space());
    if (heap_->shared_space()) {
      CollectRememberedSetUpdatingItems(&updating_items, heap_->shared_space());
    }
    CollectRememberedSetUpdatingItems(&updating_items, heap_->lo_space());
    CollectRememberedSetUpdatingItems(&updating_items, heap_->code_lo_space());
    if (heap_->shared_lo_space()) {
      CollectRememberedSetUpdatingItems(&updating_items,
                                        heap_->shared_lo_space());
    }
    CollectRememberedSetUpdatingItems(&updating_items, heap_->trusted_space());
    CollectRememberedSetUpdatingItems(&updating_items,
                                      heap_->trusted_lo_space());
    if (heap_->shared_trusted_space()) {
      CollectRememberedSetUpdatingItems(&updating_items,
                                        heap_->shared_trusted_space());
    }
    if (heap_->shared_trusted_lo_space()) {
      CollectRememberedSetUpdatingItems(&updating_items,
                                        heap_->shared_trusted_lo_space());
    }

    // Iterating to space may require a valid body descriptor for e.g.
    // WasmStruct which races with updating a slot in Map. Since to space is
    // empty after a full GC, such races can't happen.
    DCHECK_IMPLIES(heap_->new_space(), heap_->new_space()->Size() == 0);

    updating_items.push_back(
        std::make_unique<EphemeronTableUpdatingItem>(heap_));

    auto pointers_updating_job = std::make_unique<PointersUpdatingJob>(
        heap_->isolate(), this, std::move(updating_items));
    TRACE_GC_NOTE_WITH_FLOW("PointersUpdatingJob started",
                            pointers_updating_job->trace_id(),
                            TRACE_EVENT_FLAG_FLOW_OUT);
    V8::GetCurrentPlatform()
        ->CreateJob(v8::TaskPriority::kUserBlocking,
                    std::move(pointers_updating_job))
        ->Join();
  }

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_EVACUATE_UPDATE_POINTERS_WEAK);
    // Update pointers from external string table.
    heap_->UpdateReferencesInExternalStringTable(
        &UpdateReferenceInExternalStringTableEntry);

    // Update pointers in string forwarding table.
    // When GC was performed without a stack, the table was cleared and this
    // does nothing. In the case this was a GC with stack, we need to update
    // the entries for evacuated objects.
    // All entries are objects in shared space (unless
    // --always-use-forwarding-table), so we only need to update pointers during
    // a shared GC.
    if (heap_->isolate()->OwnsStringTables() ||
        V8_UNLIKELY(v8_flags.always_use_string_forwarding_table)) {
      heap_->isolate()->string_forwarding_table()->UpdateAfterFullEvacuation();
    }

    EvacuationWeakObjectRetainer evacuation_object_retainer;
    heap_->ProcessWeakListRoots(&evacuation_object_retainer);
  }

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_EVACUATE_UPDATE_POINTERS_POINTER_TABLES);
    UpdatePointersInPointerTables();
  }

  // Flush the inner_pointer_to_code_cache which may now have stale contents.
  heap_->isolate()->inner_pointer_to_code_cache()->Flush();
}

void MarkCompactCollector::UpdatePointersInClientHeaps() {
  Isolate* const isolate = heap_->isolate();
  if (!isolate->is_shared_space_isolate()) return;

  isolate->global_safepoint()->IterateClientIsolates(
      [this](Isolate* client) { UpdatePointersInClientHeap(client); });
}

void MarkCompactCollector::UpdatePointersInClientHeap(Isolate* client) {
  PtrComprCageBase cage_base(client);
  MemoryChunkIterator chunk_iterator(client->heap());

  while (chunk_iterator.HasNext()) {
    MutablePageMetadata* page = chunk_iterator.Next();
    MemoryChunk* chunk = page->Chunk();

    const auto slot_count = RememberedSet<OLD_TO_SHARED>::Iterate(
        page,
        [cage_base](MaybeObjectSlot slot) {
          return UpdateOldToSharedSlot(cage_base, slot);
        },
        SlotSet::FREE_EMPTY_BUCKETS);

    if (slot_count == 0 || chunk->InYoungGeneration()) {
      page->ReleaseSlotSet(OLD_TO_SHARED);
    }

    const PtrComprCageBase unused_cage_base(kNullAddress);

    const auto protected_slot_count =
        RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::Iterate(
            page,
            [unused_cage_base](MaybeObjectSlot slot) {
              ProtectedPointerSlot protected_slot(slot.address());
              return UpdateOldToSharedSlot(unused_cage_base, protected_slot);
            },
            SlotSet::FREE_EMPTY_BUCKETS);
    if (protected_slot_count == 0) {
      page->ReleaseSlotSet(TRUSTED_TO_SHARED_TRUSTED);
    }

    if (!chunk->executable()) {
      DCHECK_NULL(page->typed_slot_set<OLD_TO_SHARED>());
      continue;
    }

    WritableJitPage jit_page = ThreadIsolation::LookupWritableJitPage(
        page->area_start(), page->area_size());
    const auto typed_slot_count = RememberedSet<OLD_TO_SHARED>::IterateTyped(
        page, [this, &jit_page](SlotType slot_type, Address slot) {
          // Using UpdateStrongSlot is OK here, because there are no weak
          // typed slots.
          PtrComprCageBase cage_base = heap_->isolate();
          WritableJitAllocation jit_allocation =
              jit_page.LookupAllocationContaining(slot);
          return UpdateTypedSlotHelper::UpdateTypedSlot(
              jit_allocation, heap_, slot_type, slot,
              [cage_base](FullMaybeObjectSlot slot) {
                return UpdateStrongOldToSharedSlot(cage_base, slot);
              });
        });
    if (typed_slot_count == 0 || chunk->InYoungGeneration())
      page->ReleaseTypedSlotSet(OLD_TO_SHARED);
  }
}

void MarkCompactCollector::UpdatePointersInPointerTables() {
#ifdef V8_ENABLE_SANDBOX
  // Process an entry of a pointer table, returning either the relocated object
  // or a null pointer if the object wasn't relocated.
  auto process_entry = [&](Address content) -> Tagged<ExposedTrustedObject> {
    Tagged<HeapObject> heap_obj = Cast<HeapObject>(Tagged<Object>(content));
    MapWord map_word = heap_obj->map_word(kRelaxedLoad);
    if (!map_word.IsForwardingAddress()) return {};
    Tagged<HeapObject> relocated_object =
        map_word.ToForwardingAddress(heap_obj);
    DCHECK(IsExposedTrustedObject(relocated_object));
    return Cast<ExposedTrustedObject>(relocated_object);
  };

  TrustedPointerTable* const tpt = &heap_->isolate()->trusted_pointer_table();
  tpt->IterateActiveEntriesIn(
      heap_->trusted_pointer_space(),
      [&](TrustedPointerHandle handle, Address content) {
        Tagged<ExposedTrustedObject> relocated_object = process_entry(content);
        if (!relocated_object.is_null()) {
          DCHECK_EQ(handle, relocated_object->self_indirect_pointer_handle());
          auto instance_type = relocated_object->map()->instance_type();
          auto tag = IndirectPointerTagFromInstanceType(instance_type);
          tpt->Set(handle, relocated_object.ptr(), tag);
        }
      });

  TrustedPointerTable* const stpt =
      &heap_->isolate()->shared_trusted_pointer_table();
  stpt->IterateActiveEntriesIn(
      heap_->isolate()->shared_trusted_pointer_space(),
      [&](TrustedPointerHandle handle, Address content) {
        Tagged<ExposedTrustedObject> relocated_object = process_entry(content);
        if (!relocated_object.is_null()) {
          DCHECK_EQ(handle, relocated_object->self_indirect_pointer_handle());
          auto instance_type = relocated_object->map()->instance_type();
          auto tag = IndirectPointerTagFromInstanceType(instance_type);
          DCHECK(IsSharedTrustedPointerType(tag));
          stpt->Set(handle, relocated_object.ptr(), tag);
        }
      });

  CodePointerTable* const cpt = IsolateGroup::current()->code_pointer_table();
  cpt->IterateActiveEntriesIn(
      heap_->code_pointer_space(),
      [&](CodePointerHandle handle, Address content) {
        Tagged<ExposedTrustedObject> relocated_object = process_entry(content);
        if (!relocated_object.is_null()) {
          DCHECK_EQ(handle, relocated_object->self_indirect_pointer_handle());
          cpt->SetCodeObject(handle, relocated_object.address());
        }
      });
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* const jdt = GetProcessWideJSDispatchTable();
  const EmbeddedData& embedded_data = EmbeddedData::FromBlob(heap_->isolate());
  jdt->IterateActiveEntriesIn(
      heap_->js_dispatch_table_space(), [&](JSDispatchHandle handle) {
        Address code_address = jdt->GetCodeAddress(handle);
        Address entrypoint_address = jdt->GetEntrypoint(handle);
        Tagged<TrustedObject> relocated_code = process_entry(code_address);
        bool code_object_was_relocated = !relocated_code.is_null();
        Tagged<Code> code = Cast<Code>(code_object_was_relocated
                                           ? relocated_code
                                           : Tagged<Object>(code_address));
        bool instruction_stream_was_relocated =
            code->instruction_start() != entrypoint_address;
        if (code_object_was_relocated || instruction_stream_was_relocated) {
          Address old_entrypoint = jdt->GetEntrypoint(handle);
          // Ensure tiering trampolines are not overwritten here.
          Address new_entrypoint = ([&]() {
#define CASE(name, ...)                                                       \
  if (old_entrypoint == embedded_data.InstructionStartOf(Builtin::k##name)) { \
    return old_entrypoint;                                                    \
  }
            BUILTIN_LIST_BASE_TIERING(CASE)
#undef CASE
            return code->instruction_start();
          })();
          jdt->SetCodeAndEntrypointNoWriteBarrier(handle, code, new_entrypoint);
          CHECK_IMPLIES(jdt->IsTieringRequested(handle),
                        old_entrypoint == new_entrypoint);
        }
      });
#endif  // V8_ENABLE_LEAPTIERING
}

void MarkCompactCollector::ReportAbortedEvacuationCandidateDueToOOM(
    Address failed_start, PageMetadata* page) {
  base::MutexGuard guard(&mutex_);
  aborted_evacuation_candidates_due_to_oom_.push_back(
      std::make_pair(failed_start, page));
}

void MarkCompactCollector::ReportAbortedEvacuationCandidateDueToFlags(
    Address failed_start, PageMetadata* page) {
  MemoryChunk* chunk = page->Chunk();
  DCHECK(!chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED));
  chunk->SetFlagSlow(MemoryChunk::COMPACTION_WAS_ABORTED);
  base::MutexGuard guard(&mutex_);
  aborted_evacuation_candidates_due_to_flags_.push_back(
      std::make_pair(failed_start, page));
}

namespace {

void ReRecordPage(Heap* heap, Address failed_start, PageMetadata* page) {
  DCHECK(page->Chunk()->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED));

  // Aborted compaction page. We have to record slots here, since we
  // might not have recorded them in first place.

  // Remove mark bits in evacuated area.
  page->marking_bitmap()->ClearRange<AccessMode::NON_ATOMIC>(
      MarkingBitmap::AddressToIndex(page->area_start()),
      MarkingBitmap::LimitAddressToIndex(failed_start));

  // Remove outdated slots.
  RememberedSet<OLD_TO_NEW>::RemoveRange(page, page->area_start(), failed_start,
                                         SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_NEW>::RemoveRangeTyped(page, page->area_start(),
                                              failed_start);

  RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
      page, page->area_start(), failed_start, SlotSet::FREE_EMPTY_BUCKETS);
  DCHECK_NULL(page->typed_slot_set<OLD_TO_NEW_BACKGROUND>());

  RememberedSet<OLD_TO_SHARED>::RemoveRange(
      page, page->area_start(), failed_start, SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_SHARED>::RemoveRangeTyped(page, page->area_start(),
                                                 failed_start);

  // Re-record slots and recompute live bytes.
  EvacuateRecordOnlyVisitor visitor(heap);
  LiveObjectVisitor::VisitMarkedObjectsNoFail(page, &visitor);
  page->SetLiveBytes(visitor.live_object_size());
  // Array buffers will be processed during pointer updating.
}

}  // namespace

size_t MarkCompactCollector::PostProcessAbortedEvacuationCandidates() {
  for (auto start_and_page : aborted_evacuation_candidates_due_to_oom_) {
    PageMetadata* page = start_and_page.second;
    MemoryChunk* chunk = page->Chunk();
    DCHECK(!chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED));
    chunk->SetFlagSlow(MemoryChunk::COMPACTION_WAS_ABORTED);
  }
  for (auto start_and_page : aborted_evacuation_candidates_due_to_oom_) {
    ReRecordPage(heap_, start_and_page.first, start_and_page.second);
  }
  for (auto start_and_page : aborted_evacuation_candidates_due_to_flags_) {
    ReRecordPage(heap_, start_and_page.first, start_and_page.second);
  }
  const size_t aborted_pages =
      aborted_evacuation_candidates_due_to_oom_.size() +
      aborted_evacuation_candidates_due_to_flags_.size();
  size_t aborted_pages_verified = 0;
  for (PageMetadata* p : old_space_evacuation_pages_) {
    MemoryChunk* chunk = p->Chunk();
    if (chunk->IsFlagSet(MemoryChunk::COMPACTION_WAS_ABORTED)) {
      // Only clear EVACUATION_CANDIDATE flag after all slots were re-recorded
      // on all aborted pages. Necessary since repopulating
      // OLD_TO_OLD still requires the EVACUATION_CANDIDATE flag. After clearing
      // the evacuation candidate flag the page is again in a regular state.
      p->ClearEvacuationCandidate();
      aborted_pages_verified++;
    } else {
      DCHECK(chunk->IsEvacuationCandidate());
      DCHECK(p->SweepingDone());
    }
  }
  DCHECK_EQ(aborted_pages_verified, aborted_pages);
  USE(aborted_pages_verified);
  return aborted_pages;
}

void MarkCompactCollector::ReleaseEvacuationCandidates() {
  for (PageMetadata* p : old_space_evacuation_pages_) {
    if (!p->Chunk()->IsEvacuationCandidate()) continue;
    PagedSpace* space = static_cast<PagedSpace*>(p->owner());
    p->SetLiveBytes(0);
    CHECK(p->SweepingDone());
    space->ReleasePage(p);
  }
  old_space_evacuation_pages_.clear();
  compacting_ = false;
}

void MarkCompactCollector::StartSweepNewSpace() {
  PagedSpaceForNewSpace* paged_space = heap_->paged_new_space()->paged_space();
  paged_space->ClearAllocatorState();

  int will_be_swept = 0;

  DCHECK_EQ(Heap::ResizeNewSpaceMode::kNone, resize_new_space_);
  resize_new_space_ = heap_->ShouldResizeNewSpace();
  if (resize_new_space_ == Heap::ResizeNewSpaceMode::kShrink) {
    paged_space->StartShrinking();
  }

  DCHECK(empty_new_space_pages_to_be_swept_.empty());
  for (auto it = paged_space->begin(); it != paged_space->end();) {
    PageMetadata* p = *(it++);
    DCHECK(p->SweepingDone());
    DCHECK(!p->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

    if (p->live_bytes() > 0) {
      // Non-empty pages will be evacuated/promoted.
      continue;
    }

    if (paged_space->ShouldReleaseEmptyPage()) {
      paged_space->ReleasePage(p);
    } else {
      empty_new_space_pages_to_be_swept_.push_back(p);
    }
    will_be_swept++;
  }

  if (v8_flags.gc_verbose) {
    PrintIsolate(heap_->isolate(),
                 "sweeping: space=%s initialized_for_sweeping=%d",
                 ToString(paged_space->identity()), will_be_swept);
  }
}

void MarkCompactCollector::ResetAndRelinkBlackAllocatedPage(
    PagedSpace* space, PageMetadata* page) {
  DCHECK(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  DCHECK_EQ(page->live_bytes(), 0);
  DCHECK_GE(page->allocated_bytes(), 0);
  DCHECK(page->marking_bitmap()->IsClean());
  std::optional<RwxMemoryWriteScope> scope;
  if (page->Chunk()->InCodeSpace()) {
    scope.emplace("For writing flags.");
  }
  page->Chunk()->ClearFlagUnlocked(MemoryChunk::BLACK_ALLOCATED);
  space->IncreaseAllocatedBytes(page->allocated_bytes(), page);
  space->RelinkFreeListCategories(page);
}

void MarkCompactCollector::StartSweepSpace(PagedSpace* space) {
  DCHECK_NE(NEW_SPACE, space->identity());
  space->ClearAllocatorState();

  int will_be_swept = 0;
  bool unused_page_present = false;

  Sweeper* sweeper = heap_->sweeper();

  // Loop needs to support deletion if live bytes == 0 for a page.
  for (auto it = space->begin(); it != space->end();) {
    PageMetadata* p = *(it++);
    DCHECK(p->SweepingDone());

    if (p->Chunk()->IsEvacuationCandidate()) {
      DCHECK(!p->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
      DCHECK_NE(NEW_SPACE, space->identity());
      // Will be processed in Evacuate.
      continue;
    }

    // If the page is black, just reset the flag and don't add the page to the
    // sweeper.
    if (p->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED)) {
      ResetAndRelinkBlackAllocatedPage(space, p);
      continue;
    }

    // One unused page is kept, all further are released before sweeping them.
    if (p->live_bytes() == 0) {
      if (unused_page_present) {
        if (v8_flags.gc_verbose) {
          PrintIsolate(heap_->isolate(), "sweeping: released page: %p",
                       static_cast<void*>(p));
        }
        space->ReleasePage(p);
        continue;
      }
      unused_page_present = true;
    }

    sweeper->AddPage(space->identity(), p);
    will_be_swept++;
  }

  if (v8_flags.sticky_mark_bits && space->identity() == OLD_SPACE) {
    static_cast<StickySpace*>(space)->set_old_objects_size(space->Size());
  }

  if (v8_flags.gc_verbose) {
    PrintIsolate(heap_->isolate(),
                 "sweeping: space=%s initialized_for_sweeping=%d",
                 ToString(space->identity()), will_be_swept);
  }
}

namespace {
bool ShouldPostponeFreeingEmptyPages(LargeObjectSpace* space) {
  // Delay releasing dead old large object pages until after pointer updating is
  // done because dead old space objects may have old-to-new slots (which
  // were possibly later overriden with old-to-old references) that are
  // pointing to these pages and will need to be updated.
  if (space->identity() == LO_SPACE) return true;
  // Old-to-new slots may also point to shared spaces. Delay releasing so that
  // updating slots in dead old objects can access the dead shared objects.
  if (space->identity() == SHARED_LO_SPACE) return true;
  return false;
}
}  // namespace

void MarkCompactCollector::SweepLargeSpace(LargeObjectSpace* space) {
  PtrComprCageBase cage_base(heap_->isolate());
  size_t surviving_object_size = 0;
  const MemoryAllocator::FreeMode free_mode =
      ShouldPostponeFreeingEmptyPages(space)
          ? MemoryAllocator::FreeMode::kPostpone
          : MemoryAllocator::FreeMode::kImmediately;
  for (auto it = space->begin(); it != space->end();) {
    LargePageMetadata* current = *(it++);
    DCHECK(!current->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
    Tagged<HeapObject> object = current->GetObject();
    if (!marking_state_->IsMarked(object)) {
      // Object is dead and page can be released.
      space->RemovePage(current);
      heap_->memory_allocator()->Free(free_mode, current);

      continue;
    }
    if (!v8_flags.sticky_mark_bits) {
      MarkBit::From(object).Clear();
      current->SetLiveBytes(0);
    }
    current->MarkingProgressTracker().ResetIfEnabled();
    surviving_object_size += static_cast<size_t>(object->Size(cage_base));
  }
  space->set_objects_size(surviving_object_size);
}

void MarkCompactCollector::Sweep() {
  DCHECK(!sweeper_->sweeping_in_progress());
  sweeper_->InitializeMajorSweeping();

  TRACE_GC_EPOCH_WITH_FLOW(
      heap_->tracer(), GCTracer::Scope::MC_SWEEP, ThreadKind::kMain,
      sweeper_->GetTraceIdForFlowEvent(GCTracer::Scope::MC_SWEEP),
      TRACE_EVENT_FLAG_FLOW_OUT);
#ifdef DEBUG
  state_ = SWEEP_SPACES;
#endif

  {
    GCTracer::Scope sweep_scope(heap_->tracer(), GCTracer::Scope::MC_SWEEP_LO,
                                ThreadKind::kMain);
    SweepLargeSpace(heap_->lo_space());
  }
  {
    GCTracer::Scope sweep_scope(
        heap_->tracer(), GCTracer::Scope::MC_SWEEP_CODE_LO, ThreadKind::kMain);
    SweepLargeSpace(heap_->code_lo_space());
  }
  if (heap_->shared_space()) {
    GCTracer::Scope sweep_scope(heap_->tracer(),
                                GCTracer::Scope::MC_SWEEP_SHARED_LO,
                                ThreadKind::kMain);
    SweepLargeSpace(heap_->shared_lo_space());
  }
  {
    GCTracer::Scope sweep_scope(heap_->tracer(), GCTracer::Scope::MC_SWEEP_OLD,
                                ThreadKind::kMain);
    StartSweepSpace(heap_->old_space());
  }
  {
    GCTracer::Scope sweep_scope(heap_->tracer(), GCTracer::Scope::MC_SWEEP_CODE,
                                ThreadKind::kMain);
    StartSweepSpace(heap_->code_space());
  }
  if (heap_->shared_space()) {
    GCTracer::Scope sweep_scope(
        heap_->tracer(), GCTracer::Scope::MC_SWEEP_SHARED, ThreadKind::kMain);
    StartSweepSpace(heap_->shared_space());
  }
  {
    GCTracer::Scope sweep_scope(
        heap_->tracer(), GCTracer::Scope::MC_SWEEP_TRUSTED, ThreadKind::kMain);
    StartSweepSpace(heap_->trusted_space());
  }
  if (heap_->shared_trusted_space()) {
    GCTracer::Scope sweep_scope(
        heap_->tracer(), GCTracer::Scope::MC_SWEEP_SHARED, ThreadKind::kMain);
    StartSweepSpace(heap_->shared_trusted_space());
  }
  {
    GCTracer::Scope sweep_scope(heap_->tracer(),
                                GCTracer::Scope::MC_SWEEP_TRUSTED_LO,
                                ThreadKind::kMain);
    SweepLargeSpace(heap_->trusted_lo_space());
  }
  if (v8_flags.minor_ms && heap_->new_space()) {
    GCTracer::Scope sweep_scope(heap_->tracer(), GCTracer::Scope::MC_SWEEP_NEW,
                                ThreadKind::kMain);
    StartSweepNewSpace();
  }

  sweeper_->StartMajorSweeping();
}

RootMarkingVisitor::RootMarkingVisitor(MarkCompactCollector* collector)
    : collector_(collector) {}

RootMarkingVisitor::~RootMarkingVisitor() = default;

void RootMarkingVisitor::VisitRunningCode(
    FullObjectSlot code_slot, FullObjectSlot istream_or_smi_zero_slot) {
  Tagged<Object> istream_or_smi_zero = *istream_or_smi_zero_slot;
  DCHECK(istream_or_smi_zero == Smi::zero() ||
         IsInstructionStream(istream_or_smi_zero));
  Tagged<Code> code = Cast<Code>(*code_slot);
  DCHECK_EQ(code->raw_instruction_stream(PtrComprCageBase{
                collector_->heap()->isolate()->code_cage_base()}),
            istream_or_smi_zero);

  // We must not remove deoptimization literals which may be needed in
  // order to successfully deoptimize.
  code->IterateDeoptimizationLiterals(this);

  if (istream_or_smi_zero != Smi::zero()) {
    VisitRootPointer(Root::kStackRoots, nullptr, istream_or_smi_zero_slot);
  }

  VisitRootPointer(Root::kStackRoots, nullptr, code_slot);
}

}  // namespace internal
}  // namespace v8

"""


```