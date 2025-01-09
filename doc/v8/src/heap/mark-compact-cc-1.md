Response:
The user wants a summary of the provided C++ code snippet from `v8/src/heap/mark-compact.cc`. This is part 2 of 8, implying a larger file is being discussed. The request asks to identify the functionality of the code, check if it relates to Torque (it doesn't based on the `.cc` extension), explain any connection to JavaScript with examples, analyze code logic with hypothetical input/output, point out common programming errors it might address, and finally, provide a concise summary of this specific section's purpose.

**Plan:**

1. **High-level overview:**  Scan the code for major operations and data structures being manipulated. Keywords like "ResizeNewSpaceMode", "SweepArrayBufferExtensions", "CustomRootBodyMarkingVisitor", "SharedHeapObjectVisitor", "InternalizedStringTableCleaner", "MarkCompactWeakObjectRetainer", "RecordMigratedSlotVisitor", "MigrationObserver", and "EvacuateVisitorBase" are good starting points.
2. **Function identification:**  Analyze the methods and classes to understand their individual roles within the larger mark-compact garbage collection process. Focus on what each part does.
3. **JavaScript relevance:** Consider how these low-level operations might manifest in JavaScript behavior. Think about garbage collection triggers and observable effects.
4. **Logic analysis (if applicable):** If there's a clearly defined algorithm or decision-making process within this snippet, devise a simple input and trace its likely output.
5. **Error examples:**  Think about common coding mistakes that might lead to issues this code aims to prevent or handle (e.g., memory leaks, dangling pointers).
6. **Section summary:** Condense the findings into a concise description of the purpose of this code segment within the larger mark-compact GC.
这是v8源代码文件 `v8/src/heap/mark-compact.cc` 的一部分，主要涉及 **Mark-Compact 垃圾回收器的完成阶段 (Finish Phase)** 以及一些辅助功能，用于对象迁移和处理不同类型的引用。

以下是代码段中包含的功能的详细归纳：

**1. 完成垃圾回收 (Finishing GC):**

* **调整新生代空间大小 (Resize New Space):**  根据堆的状态，决定是否需要收缩或扩展新生代空间。
    * `ResizeNewSpaceMode::kShrink`: 收缩新生代空间。
    * `ResizeNewSpaceMode::kGrow`: 扩展新生代空间。
    * `ResizeNewSpaceMode::kNone`: 不调整大小。
* **执行新生代垃圾回收的收尾工作 (GarbageCollectionEpilogue):**  清理新生代相关的状态。
* **清理全局句柄中年轻节点的列表 (ClearListOfYoungNodes):**  移除对年轻代对象的引用。
* **扫描 ArrayBuffer 扩展 (SweepArrayBufferExtensions):**  清理与 ArrayBuffer 相关的外部资源。
* **释放本地和全局的标记工作列表 (Release Marking Worklists):**  回收用于标记阶段的数据结构。
* **清理本地上下文统计信息 (Clear Native Context Stats):**  重置统计数据。
* **检查弱对象队列是否为空 (Check Weak Objects Queues):**  确保在处理完弱引用后队列为空。
* **启动主清扫器任务 (Start Major Sweeper Tasks):**  开始清扫阶段的主要工作。
* **释放空闲页 (Release Queued Pages):**  将不再使用的内存页归还。
* **根据对象大小收缩页面 (ShrinkPagesToObjectSizes):**  优化内存页的大小。
* **去优化标记的代码对象 (DeoptimizeMarkedCode):**  将标记为需要去优化的代码恢复到未优化状态。

**2. 自定义根对象体访问 (Custom Root Body Marking Visitor):**

* 定义了一个名为 `CustomRootBodyMarkingVisitor` 的类，用于访问特殊根对象（例如，被顶级优化帧保持的 InstructionStream）中指向其他对象的指针，确保这些对象在垃圾回收期间被正确标记为存活。

**3. 共享堆对象访问 (Shared Heap Object Visitor):**

* 定义了一个名为 `SharedHeapObjectVisitor` 的类，用于访问非共享堆中的对象指向共享堆中的对象的指针。  它的目的是在标记阶段记录这些跨堆的引用，以便在后续处理中正确处理。

**4. 清理内部化字符串表 (InternalizedStringTableCleaner):**

* 定义了一个名为 `InternalizedStringTableCleaner` 的类，用于遍历内部化字符串表，并将未标记的字符串条目标记为已删除。

**5. 处理外部字符串表的外部指针 (MarkExternalPointerFromExternalStringTable):**

* 定义了一个名为 `MarkExternalPointerFromExternalStringTable` 的类，用于扫描外部字符串表，并标记其中引用的外部指针。这在启用了沙箱模式 (`V8_ENABLE_SANDBOX`) 时尤为重要。

**6. 弱对象保留策略 (MarkCompactWeakObjectRetainer):**

* 定义了一个名为 `MarkCompactWeakObjectRetainer` 的类，实现了弱对象在 Mark-Compact 垃圾回收期间的保留策略。只有被标记为存活的对象才会被保留，除非是尚未成为僵尸的 `AllocationSite`。

**7. 记录迁移的槽位 (RecordMigratedSlotVisitor):**

* 定义了一个名为 `RecordMigratedSlotVisitor` 的类，用于遍历对象并记录在对象迁移后需要更新的槽位信息。它会根据引用的目标空间（新生代、老年代、共享空间等）将槽位信息记录到不同的 Remembered Set 中。

**8. 对象迁移观察者 (MigrationObserver):**

* 定义了一个名为 `MigrationObserver` 的抽象类，用于在对象迁移时执行额外的操作，例如性能分析。
* `ProfilingMigrationObserver` 是一个具体的观察者，用于记录代码对象和字节码数组的迁移事件。

**9. 对象迁移访问器基类 (EvacuateVisitorBase):**

* 定义了一个名为 `EvacuateVisitorBase` 的抽象类，作为对象迁移的基类。它提供了将对象迁移到新位置的核心逻辑，并支持观察者模式。
* `EvacuateNewSpaceVisitor` 是一个具体的访问器，用于将新生代中的对象迁移到老年代或其他空间。它还包含了避免不必要的拷贝的优化策略，例如对于 `ThinString`。

**与 JavaScript 的关系和示例:**

这些代码是 V8 引擎内部实现垃圾回收的关键部分，直接影响着 JavaScript 程序的内存管理和性能。 虽然开发者无法直接操作这些代码，但垃圾回收器的行为会影响 JavaScript 的执行。

例如，**调整新生代空间大小**影响着新生代垃圾回收的频率和效率，进而影响 JavaScript 中短期存活对象的生命周期。

```javascript
// JavaScript 代码，其行为会受到 Mark-Compact GC 的影响

let shortLivedObject = {}; // 一个短期存活的对象

// ... 一些操作，可能会触发新生代垃圾回收 ...

// 如果新生代空间太小，垃圾回收会更频繁，可能导致 shortLivedObject 被过早回收。
// 如果新生代空间足够大，可以容纳更多短期对象，减少垃圾回收频率。

let longLivedObject = {}; // 一个长期存活的对象

// ... 更多操作，可能会触发 full GC (Mark-Compact) ...

// Mark-Compact GC 会标记并压缩堆内存，确保 longLivedObject 不会被错误回收，
// 并且能有效地回收不再使用的内存。
```

**代码逻辑推理和假设输入/输出:**

以 **调整新生代空间大小** 为例：

**假设输入:**

* `heap_->ShouldResizeNewSpace()` 返回 `ResizeNewSpaceMode::kGrow` (表示应该扩展新生代空间)。
* 当前新生代空间大小为 X。
* `heap_->ExpandNewSpaceSize()` 的实现会将新生代空间扩大 Y。

**输出:**

* 新生代空间大小变为 X + Y。

**常见编程错误:**

虽然这段代码本身是 V8 引擎的内部实现，但它所处理的问题与用户常见的编程错误息息相关，例如：

* **内存泄漏:** 如果垃圾回收器无法正确标记和回收不再使用的对象，就会导致内存泄漏。这段代码中的标记和清扫功能就是为了防止这种情况发生。
* **野指针/悬 dangling pointer:**  在对象移动后，如果没有正确更新指向该对象的指针，就会出现野指针。`RecordMigratedSlotVisitor` 的作用就是确保在对象迁移后，所有指向它的指针都能被正确更新。
* **性能问题:**  不合理的内存分配和对象引用方式可能导致垃圾回收器频繁工作，影响程序性能。这段代码中调整新生代空间大小的逻辑旨在优化垃圾回收的效率。

**总结:**

这段 `v8/src/heap/mark-compact.cc` 代码片段是 Mark-Compact 垃圾回收器完成阶段的关键组成部分，负责执行对象迁移、清理各种类型的引用、调整堆空间大小以及启动后续的清扫工作。它确保了 JavaScript 程序的内存能够被有效管理和回收，防止内存泄漏，并保证程序的稳定性和性能。 该部分涉及到垃圾回收过程中的多个重要环节，包括对象标记的最终处理、不同内存区域的清理和调整，以及为后续的清扫阶段做准备。

Prompt: 
```
这是目录为v8/src/heap/mark-compact.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mark-compact.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
Heap::ResizeNewSpaceMode::kNone, resize_new_space_);
      resize_new_space_ = heap_->ShouldResizeNewSpace();
    }
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
  }

  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_FINISH);

  if (heap_->new_space()) {
    DCHECK(!heap_->allocator()->new_space_allocator()->IsLabValid());
    heap_->new_space()->GarbageCollectionEpilogue();
  }

  auto* isolate = heap_->isolate();
  isolate->global_handles()->ClearListOfYoungNodes();

  SweepArrayBufferExtensions();

  marking_visitor_.reset();
  local_marking_worklists_.reset();
  marking_worklists_.ReleaseContextWorklists();
  native_context_stats_.Clear();

  CHECK(weak_objects_.current_ephemerons.IsEmpty());
  CHECK(weak_objects_.discovered_ephemerons.IsEmpty());
  local_weak_objects_->next_ephemerons_local.Publish();
  local_weak_objects_.reset();
  weak_objects_.next_ephemerons.Clear();

  sweeper_->StartMajorSweeperTasks();

  // Release empty pages now, when the pointer-update phase is done.
  heap_->memory_allocator()->ReleaseQueuedPages();

  // Shrink pages if possible after processing and filtering slots.
  ShrinkPagesToObjectSizes(heap_, heap_->lo_space());

#ifdef DEBUG
  DCHECK(state_ == SWEEP_SPACES || state_ == RELOCATE_OBJECTS);
  state_ = IDLE;
#endif

  if (have_code_to_deoptimize_) {
    // Some code objects were marked for deoptimization during the GC.
    Deoptimizer::DeoptimizeMarkedCode(isolate);
    have_code_to_deoptimize_ = false;
  }
}

void MarkCompactCollector::SweepArrayBufferExtensions() {
  DCHECK_IMPLIES(heap_->new_space(), heap_->new_space()->Size() == 0);
  DCHECK_IMPLIES(heap_->new_lo_space(), heap_->new_lo_space()->Size() == 0);
  heap_->array_buffer_sweeper()->RequestSweep(
      ArrayBufferSweeper::SweepingType::kFull,
      ArrayBufferSweeper::TreatAllYoungAsPromoted::kYes);
}

// This visitor is used to visit the body of special objects held alive by
// other roots.
//
// It is currently used for
// - InstructionStream held alive by the top optimized frame. This code cannot
// be deoptimized and thus have to be kept alive in an isolate way, i.e., it
// should not keep alive other code objects reachable through the weak list but
// they should keep alive its embedded pointers (which would otherwise be
// dropped).
// - Prefix of the string table.
// - If V8_ENABLE_SANDBOX, client Isolates' waiter queue node
// ExternalPointer_t in shared Isolates.
class MarkCompactCollector::CustomRootBodyMarkingVisitor final
    : public ObjectVisitorWithCageBases {
 public:
  explicit CustomRootBodyMarkingVisitor(MarkCompactCollector* collector)
      : ObjectVisitorWithCageBases(collector->heap_->isolate()),
        collector_(collector) {}

  void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    MarkObject(host, p.load(cage_base()));
  }

  void VisitMapPointer(Tagged<HeapObject> host) final {
    MarkObject(host, host->map(cage_base()));
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) final {
    for (ObjectSlot p = start; p < end; ++p) {
      // The map slot should be handled in VisitMapPointer.
      DCHECK_NE(host->map_slot(), p);
      DCHECK(!HasWeakHeapObjectTag(p.load(cage_base())));
      MarkObject(host, p.load(cage_base()));
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    MarkObject(host, slot.load(code_cage_base()));
  }

  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) final {
    // At the moment, custom roots cannot contain weak pointers.
    UNREACHABLE();
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    MarkObject(host, target);
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    MarkObject(host, rinfo->target_object(cage_base()));
  }

 private:
  V8_INLINE void MarkObject(Tagged<HeapObject> host, Tagged<Object> object) {
    if (!IsHeapObject(object)) return;
    Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
    const auto target_worklist =
        MarkingHelper::ShouldMarkObject(collector_->heap(), heap_object);
    if (!target_worklist) {
      return;
    }
    collector_->MarkObject(host, heap_object, target_worklist.value());
  }

  MarkCompactCollector* const collector_;
};

class MarkCompactCollector::SharedHeapObjectVisitor final
    : public HeapVisitor<MarkCompactCollector::SharedHeapObjectVisitor> {
 public:
  explicit SharedHeapObjectVisitor(MarkCompactCollector* collector)
      : HeapVisitor(collector->heap_->isolate()), collector_(collector) {}

  void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    CheckForSharedObject(host, p, p.load(cage_base()));
  }

  void VisitPointer(Tagged<HeapObject> host, MaybeObjectSlot p) final {
    Tagged<MaybeObject> object = p.load(cage_base());
    Tagged<HeapObject> heap_object;
    if (object.GetHeapObject(&heap_object))
      CheckForSharedObject(host, ObjectSlot(p), heap_object);
  }

  void VisitMapPointer(Tagged<HeapObject> host) final {
    CheckForSharedObject(host, host->map_slot(), host->map(cage_base()));
  }

  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) final {
    for (ObjectSlot p = start; p < end; ++p) {
      // The map slot should be handled in VisitMapPointer.
      DCHECK_NE(host->map_slot(), p);
      DCHECK(!HasWeakHeapObjectTag(p.load(cage_base())));
      CheckForSharedObject(host, p, p.load(cage_base()));
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    UNREACHABLE();
  }

  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) final {
    for (MaybeObjectSlot p = start; p < end; ++p) {
      // The map slot should be handled in VisitMapPointer.
      DCHECK_NE(host->map_slot(), ObjectSlot(p));
      VisitPointer(host, p);
    }
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    UNREACHABLE();
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    UNREACHABLE();
  }

 private:
  V8_INLINE void CheckForSharedObject(Tagged<HeapObject> host, ObjectSlot slot,
                                      Tagged<Object> object) {
    DCHECK(!HeapLayout::InAnySharedSpace(host));
    Tagged<HeapObject> heap_object;
    if (!object.GetHeapObject(&heap_object)) return;
    if (!HeapLayout::InWritableSharedSpace(heap_object)) return;
    DCHECK(HeapLayout::InWritableSharedSpace(heap_object));
    MemoryChunk* host_chunk = MemoryChunk::FromHeapObject(host);
    MutablePageMetadata* host_page_metadata =
        MutablePageMetadata::cast(host_chunk->Metadata());
    DCHECK(HeapLayout::InYoungGeneration(host));
    // Temporarily record new-to-shared slots in the old-to-shared remembered
    // set so we don't need to iterate the page again later for updating the
    // references.
    RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::NON_ATOMIC>(
        host_page_metadata, host_chunk->Offset(slot.address()));
    if (MarkingHelper::ShouldMarkObject(collector_->heap(), heap_object)) {
      collector_->MarkRootObject(Root::kClientHeap, heap_object,
                                 MarkingHelper::WorklistTarget::kRegular);
    }
  }

  MarkCompactCollector* const collector_;
};

class InternalizedStringTableCleaner final : public RootVisitor {
 public:
  explicit InternalizedStringTableCleaner(Heap* heap) : heap_(heap) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    UNREACHABLE();
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK_EQ(root, Root::kStringTable);
    // Visit all HeapObject pointers in [start, end).
    Isolate* const isolate = heap_->isolate();
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      Tagged<Object> o = p.load(isolate);
      if (IsHeapObject(o)) {
        Tagged<HeapObject> heap_object = Cast<HeapObject>(o);
        DCHECK(!HeapLayout::InYoungGeneration(heap_object));
        if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
                heap_, heap_->marking_state(), heap_object)) {
          pointers_removed_++;
          p.store(StringTable::deleted_element());
        }
      }
    }
  }

  int PointersRemoved() const { return pointers_removed_; }

 private:
  Heap* heap_;
  int pointers_removed_ = 0;
};

#ifdef V8_ENABLE_SANDBOX
class MarkExternalPointerFromExternalStringTable : public RootVisitor {
 public:
  explicit MarkExternalPointerFromExternalStringTable(
      ExternalPointerTable* shared_table, ExternalPointerTable::Space* space)
      : visitor(shared_table, space) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    // Visit all HeapObject pointers in [start, end).
    for (FullObjectSlot p = start; p < end; ++p) {
      Tagged<Object> o = *p;
      if (IsHeapObject(o)) {
        Tagged<HeapObject> heap_object = Cast<HeapObject>(o);
        if (IsExternalString(heap_object)) {
          Tagged<ExternalString> string = Cast<ExternalString>(heap_object);
          string->VisitExternalPointers(&visitor);
        } else {
          // The original external string may have been internalized.
          DCHECK(IsThinString(o));
        }
      }
    }
  }

 private:
  class MarkExternalPointerTableVisitor : public ObjectVisitor {
   public:
    explicit MarkExternalPointerTableVisitor(ExternalPointerTable* table,
                                             ExternalPointerTable::Space* space)
        : table_(table), space_(space) {}
    void VisitExternalPointer(Tagged<HeapObject> host,
                              ExternalPointerSlot slot) override {
      DCHECK_NE(slot.tag(), kExternalPointerNullTag);
      DCHECK(IsSharedExternalPointerType(slot.tag()));
      ExternalPointerHandle handle = slot.Relaxed_LoadHandle();
      table_->Mark(space_, handle, slot.address());
    }
    void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                       ObjectSlot end) override {
      UNREACHABLE();
    }
    void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                       MaybeObjectSlot end) override {
      UNREACHABLE();
    }
    void VisitInstructionStreamPointer(Tagged<Code> host,
                                       InstructionStreamSlot slot) override {
      UNREACHABLE();
    }
    void VisitCodeTarget(Tagged<InstructionStream> host,
                         RelocInfo* rinfo) override {
      UNREACHABLE();
    }
    void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) override {
      UNREACHABLE();
    }

   private:
    ExternalPointerTable* table_;
    ExternalPointerTable::Space* space_;
  };

  MarkExternalPointerTableVisitor visitor;
};
#endif  // V8_ENABLE_SANDBOX

// Implementation of WeakObjectRetainer for mark compact GCs. All marked objects
// are retained.
class MarkCompactWeakObjectRetainer : public WeakObjectRetainer {
 public:
  MarkCompactWeakObjectRetainer(Heap* heap, MarkingState* marking_state)
      : heap_(heap), marking_state_(marking_state) {}

  Tagged<Object> RetainAs(Tagged<Object> object) override {
    Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_,
                                            heap_object)) {
      return object;
    } else if (IsAllocationSite(object) &&
               !Cast<AllocationSite>(object)->IsZombie()) {
      // "dead" AllocationSites need to live long enough for a traversal of new
      // space. These sites get a one-time reprieve.

      Tagged<Object> nested = object;
      while (IsAllocationSite(nested)) {
        Tagged<AllocationSite> current_site = Cast<AllocationSite>(nested);
        // MarkZombie will override the nested_site, read it first before
        // marking
        nested = current_site->nested_site();
        current_site->MarkZombie();
        marking_state_->TryMarkAndAccountLiveBytes(current_site);
      }

      return object;
    } else {
      return Smi::zero();
    }
  }

 private:
  Heap* const heap_;
  MarkingState* const marking_state_;
};

class RecordMigratedSlotVisitor
    : public HeapVisitor<RecordMigratedSlotVisitor> {
 public:
  explicit RecordMigratedSlotVisitor(Heap* heap)
      : HeapVisitor(heap->isolate()), heap_(heap) {}

  V8_INLINE static constexpr bool UsePrecomputedObjectSize() { return true; }

  inline void VisitPointer(Tagged<HeapObject> host, ObjectSlot p) final {
    DCHECK(!HasWeakHeapObjectTag(p.load(cage_base())));
    RecordMigratedSlot(host, p.load(cage_base()), p.address());
  }

  inline void VisitMapPointer(Tagged<HeapObject> host) final {
    VisitPointer(host, host->map_slot());
  }

  inline void VisitPointer(Tagged<HeapObject> host, MaybeObjectSlot p) final {
    DCHECK(!MapWord::IsPacked(p.Relaxed_Load(cage_base()).ptr()));
    RecordMigratedSlot(host, p.load(cage_base()), p.address());
  }

  inline void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                            ObjectSlot end) final {
    while (start < end) {
      VisitPointer(host, start);
      ++start;
    }
  }

  inline void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                            MaybeObjectSlot end) final {
    while (start < end) {
      VisitPointer(host, start);
      ++start;
    }
  }

  inline void VisitInstructionStreamPointer(Tagged<Code> host,
                                            InstructionStreamSlot slot) final {
    // This code is similar to the implementation of VisitPointer() modulo
    // new kind of slot.
    DCHECK(!HasWeakHeapObjectTag(slot.load(code_cage_base())));
    Tagged<Object> code = slot.load(code_cage_base());
    RecordMigratedSlot(host, code, slot.address());
  }

  inline void VisitEphemeron(Tagged<HeapObject> host, int index, ObjectSlot key,
                             ObjectSlot value) override {
    DCHECK(IsEphemeronHashTable(host));
    DCHECK(!HeapLayout::InYoungGeneration(host));

    // Simply record ephemeron keys in OLD_TO_NEW if it points into the young
    // generation instead of recording it in ephemeron_remembered_set here for
    // migrated objects. OLD_TO_NEW is per page and we can therefore easily
    // record in OLD_TO_NEW on different pages in parallel without merging. Both
    // sets are anyways guaranteed to be empty after a full GC.
    VisitPointer(host, key);
    VisitPointer(host, value);
  }

  inline void VisitCodeTarget(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) override {
    DCHECK(RelocInfo::IsCodeTargetMode(rinfo->rmode()));
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    // The target is always in old space, we don't have to record the slot in
    // the old-to-new remembered set.
    DCHECK(!HeapLayout::InYoungGeneration(target));
    DCHECK(!HeapLayout::InWritableSharedSpace(target));
    heap_->mark_compact_collector()->RecordRelocSlot(host, rinfo, target);
  }

  inline void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                                   RelocInfo* rinfo) override {
    DCHECK(RelocInfo::IsEmbeddedObjectMode(rinfo->rmode()));
    Tagged<HeapObject> object = rinfo->target_object(cage_base());
    WriteBarrier::GenerationalForRelocInfo(host, rinfo, object);
    WriteBarrier::SharedForRelocInfo(host, rinfo, object);
    heap_->mark_compact_collector()->RecordRelocSlot(host, rinfo, object);
  }

  // Entries that are skipped for recording.
  inline void VisitExternalReference(Tagged<InstructionStream> host,
                                     RelocInfo* rinfo) final {}
  inline void VisitInternalReference(Tagged<InstructionStream> host,
                                     RelocInfo* rinfo) final {}
  inline void VisitExternalPointer(Tagged<HeapObject> host,
                                   ExternalPointerSlot slot) final {}

  inline void VisitIndirectPointer(Tagged<HeapObject> host,
                                   IndirectPointerSlot slot,
                                   IndirectPointerMode mode) final {}

  inline void VisitTrustedPointerTableEntry(Tagged<HeapObject> host,
                                            IndirectPointerSlot slot) final {}

  inline void VisitProtectedPointer(Tagged<TrustedObject> host,
                                    ProtectedPointerSlot slot) final {
    RecordMigratedSlot(host, slot.load(), slot.address());
  }

 protected:
  inline void RecordMigratedSlot(Tagged<HeapObject> host,
                                 Tagged<MaybeObject> value, Address slot) {
    if (value.IsStrongOrWeak()) {
      MemoryChunk* value_chunk = MemoryChunk::FromAddress(value.ptr());
      MemoryChunk* host_chunk = MemoryChunk::FromHeapObject(host);
      if (HeapLayout::InYoungGeneration(value)) {
        MutablePageMetadata* host_metadata =
            MutablePageMetadata::cast(host_chunk->Metadata());
        DCHECK_IMPLIES(value_chunk->IsToPage(),
                       v8_flags.minor_ms || value_chunk->IsLargePage());
        DCHECK(host_metadata->SweepingDone());
        RememberedSet<OLD_TO_NEW>::Insert<AccessMode::NON_ATOMIC>(
            host_metadata, host_chunk->Offset(slot));
      } else if (value_chunk->IsEvacuationCandidate()) {
        MutablePageMetadata* host_metadata =
            MutablePageMetadata::cast(host_chunk->Metadata());
        if (value_chunk->IsFlagSet(MemoryChunk::IS_EXECUTABLE)) {
          // TODO(377724745): currently needed because flags are untrusted.
          SBXCHECK(!InsideSandbox(value_chunk->address()));
          RememberedSet<TRUSTED_TO_CODE>::Insert<AccessMode::NON_ATOMIC>(
              host_metadata, host_chunk->Offset(slot));
        } else if (value_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED) &&
                   host_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED)) {
          // When the sandbox is disabled, we use plain tagged pointers to
          // reference trusted objects from untrusted ones. However, for these
          // references we want to use the OLD_TO_OLD remembered set, so here
          // we need to check that both the value chunk and the host chunk are
          // trusted space chunks.
          // TODO(377724745): currently needed because flags are untrusted.
          SBXCHECK(!InsideSandbox(value_chunk->address()));
          if (value_chunk->InWritableSharedSpace()) {
            RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::Insert<
                AccessMode::NON_ATOMIC>(host_metadata,
                                        host_chunk->Offset(slot));
          } else {
            RememberedSet<TRUSTED_TO_TRUSTED>::Insert<AccessMode::NON_ATOMIC>(
                host_metadata, host_chunk->Offset(slot));
          }
        } else {
          RememberedSet<OLD_TO_OLD>::Insert<AccessMode::NON_ATOMIC>(
              host_metadata, host_chunk->Offset(slot));
        }
      } else if (value_chunk->InWritableSharedSpace() &&
                 !HeapLayout::InWritableSharedSpace(host)) {
        MutablePageMetadata* host_metadata =
            MutablePageMetadata::cast(host_chunk->Metadata());
        if (value_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED) &&
            host_chunk->IsFlagSet(MemoryChunk::IS_TRUSTED)) {
          RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::Insert<
              AccessMode::NON_ATOMIC>(host_metadata, host_chunk->Offset(slot));
        } else {
          RememberedSet<OLD_TO_SHARED>::Insert<AccessMode::NON_ATOMIC>(
              host_metadata, host_chunk->Offset(slot));
        }
      }
    }
  }

  Heap* const heap_;
};

class MigrationObserver {
 public:
  explicit MigrationObserver(Heap* heap) : heap_(heap) {}

  virtual ~MigrationObserver() = default;
  virtual void Move(AllocationSpace dest, Tagged<HeapObject> src,
                    Tagged<HeapObject> dst, int size) = 0;

 protected:
  Heap* heap_;
};

class ProfilingMigrationObserver final : public MigrationObserver {
 public:
  explicit ProfilingMigrationObserver(Heap* heap) : MigrationObserver(heap) {}

  inline void Move(AllocationSpace dest, Tagged<HeapObject> src,
                   Tagged<HeapObject> dst, int size) final {
    // Note this method is called in a concurrent setting. The current object
    // (src and dst) is somewhat safe to access without precautions, but other
    // objects may be subject to concurrent modification.
    if (dest == CODE_SPACE) {
      PROFILE(heap_->isolate(), CodeMoveEvent(Cast<InstructionStream>(src),
                                              Cast<InstructionStream>(dst)));
    } else if ((dest == OLD_SPACE || dest == TRUSTED_SPACE) &&
               IsBytecodeArray(dst)) {
      // TODO(saelo): remove `dest == OLD_SPACE` once BytecodeArrays are
      // allocated in trusted space.
      PROFILE(heap_->isolate(), BytecodeMoveEvent(Cast<BytecodeArray>(src),
                                                  Cast<BytecodeArray>(dst)));
    }
    heap_->OnMoveEvent(src, dst, size);
  }
};

class HeapObjectVisitor {
 public:
  virtual ~HeapObjectVisitor() = default;
  virtual bool Visit(Tagged<HeapObject> object, int size) = 0;
};

class EvacuateVisitorBase : public HeapObjectVisitor {
 public:
  void AddObserver(MigrationObserver* observer) {
    migration_function_ = RawMigrateObject<MigrationMode::kObserved>;
    observers_.push_back(observer);
  }

#if DEBUG
  void DisableAbortEvacuationAtAddress(MutablePageMetadata* chunk) {
    abort_evacuation_at_address_ = chunk->area_end();
  }

  void SetUpAbortEvacuationAtAddress(MutablePageMetadata* chunk) {
    if (v8_flags.stress_compaction || v8_flags.stress_compaction_random) {
      // Stress aborting of evacuation by aborting ~5% of evacuation candidates
      // when stress testing.
      const double kFraction = 0.05;

      if (rng_->NextDouble() < kFraction) {
        const double abort_evacuation_percentage = rng_->NextDouble();
        abort_evacuation_at_address_ =
            chunk->area_start() +
            abort_evacuation_percentage * chunk->area_size();
        return;
      }
    }

    abort_evacuation_at_address_ = chunk->area_end();
  }
#endif  // DEBUG

 protected:
  enum MigrationMode { kFast, kObserved };

  PtrComprCageBase cage_base() {
#if V8_COMPRESS_POINTERS
    return PtrComprCageBase{heap_->isolate()};
#else
    return PtrComprCageBase{};
#endif  // V8_COMPRESS_POINTERS
  }

  using MigrateFunction = void (*)(EvacuateVisitorBase* base,
                                   Tagged<HeapObject> dst,
                                   Tagged<HeapObject> src, int size,
                                   AllocationSpace dest);

  template <MigrationMode mode>
  static void RawMigrateObject(EvacuateVisitorBase* base,
                               Tagged<HeapObject> dst, Tagged<HeapObject> src,
                               int size, AllocationSpace dest) {
    Address dst_addr = dst.address();
    Address src_addr = src.address();
    PtrComprCageBase cage_base = base->cage_base();
    DCHECK(base->heap_->AllowedToBeMigrated(src->map(cage_base), src, dest));
    DCHECK_NE(dest, LO_SPACE);
    DCHECK_NE(dest, CODE_LO_SPACE);
    DCHECK_NE(dest, TRUSTED_LO_SPACE);
    if (dest == OLD_SPACE) {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(IsAligned(size, kTaggedSize));
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      // In case the object's map gets relocated during GC we load the old map
      // here. This is fine since they store the same content.
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else if (dest == SHARED_SPACE) {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(IsAligned(size, kTaggedSize));
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else if (dest == TRUSTED_SPACE) {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(IsAligned(size, kTaggedSize));
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      // In case the object's map gets relocated during GC we load the old map
      // here. This is fine since they store the same content.
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else if (dest == CODE_SPACE) {
      DCHECK_CODEOBJECT_SIZE(size);
      {
        WritableJitAllocation writable_allocation =
            ThreadIsolation::RegisterInstructionStreamAllocation(dst_addr,
                                                                 size);
        DCHECK_GT(size, InstructionStream::kHeaderSize);
        writable_allocation.CopyData(0, reinterpret_cast<uint8_t*>(src_addr),
                                     InstructionStream::kHeaderSize);
        writable_allocation.CopyCode(
            InstructionStream::kHeaderSize,
            reinterpret_cast<uint8_t*>(src_addr +
                                       InstructionStream::kHeaderSize),
            size - InstructionStream::kHeaderSize);
        Tagged<InstructionStream> istream = Cast<InstructionStream>(dst);
        istream->Relocate(writable_allocation, dst_addr - src_addr);
      }
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
      // In case the object's map gets relocated during GC we load the old map
      // here. This is fine since they store the same content.
      base->record_visitor_->Visit(dst->map(cage_base), dst, size);
    } else {
      DCHECK_OBJECT_SIZE(size);
      DCHECK(dest == NEW_SPACE);
      base->heap_->CopyBlock(dst_addr, src_addr, size);
      if (mode != MigrationMode::kFast) {
        base->ExecuteMigrationObservers(dest, src, dst, size);
      }
    }

    if (dest == CODE_SPACE) {
      WritableJitAllocation jit_allocation =
          WritableJitAllocation::ForInstructionStream(
              Cast<InstructionStream>(src));
      jit_allocation.WriteHeaderSlot<MapWord, HeapObject::kMapOffset>(
          MapWord::FromForwardingAddress(src, dst));
    } else {
      src->set_map_word_forwarded(dst, kRelaxedStore);
    }
  }

  EvacuateVisitorBase(Heap* heap, EvacuationAllocator* local_allocator,
                      RecordMigratedSlotVisitor* record_visitor)
      : heap_(heap),
        local_allocator_(local_allocator),
        record_visitor_(record_visitor),
        shared_string_table_(v8_flags.shared_string_table &&
                             heap->isolate()->has_shared_space()) {
    migration_function_ = RawMigrateObject<MigrationMode::kFast>;
#if DEBUG
    rng_.emplace(heap_->isolate()->fuzzer_rng()->NextInt64());
#endif  // DEBUG
  }

  inline bool TryEvacuateObject(AllocationSpace target_space,
                                Tagged<HeapObject> object, int size,
                                Tagged<HeapObject>* target_object) {
#if DEBUG
    DCHECK_LE(abort_evacuation_at_address_,
              MutablePageMetadata::FromHeapObject(object)->area_end());
    DCHECK_GE(abort_evacuation_at_address_,
              MutablePageMetadata::FromHeapObject(object)->area_start());

    if (V8_UNLIKELY(object.address() >= abort_evacuation_at_address_)) {
      return false;
    }
#endif  // DEBUG

    Tagged<Map> map = object->map(cage_base());
    AllocationAlignment alignment = HeapObject::RequiredAlignment(map);
    AllocationResult allocation;
    if (target_space == OLD_SPACE && ShouldPromoteIntoSharedHeap(map)) {
      allocation = local_allocator_->Allocate(SHARED_SPACE, size, alignment);
    } else {
      allocation = local_allocator_->Allocate(target_space, size, alignment);
    }
    if (allocation.To(target_object)) {
      MigrateObject(*target_object, object, size, target_space);
      return true;
    }
    return false;
  }

  inline bool ShouldPromoteIntoSharedHeap(Tagged<Map> map) {
    if (shared_string_table_) {
      return String::IsInPlaceInternalizableExcludingExternal(
          map->instance_type());
    }
    return false;
  }

  inline void ExecuteMigrationObservers(AllocationSpace dest,
                                        Tagged<HeapObject> src,
                                        Tagged<HeapObject> dst, int size) {
    for (MigrationObserver* obs : observers_) {
      obs->Move(dest, src, dst, size);
    }
  }

  inline void MigrateObject(Tagged<HeapObject> dst, Tagged<HeapObject> src,
                            int size, AllocationSpace dest) {
    migration_function_(this, dst, src, size, dest);
  }

  Heap* heap_;
  EvacuationAllocator* local_allocator_;
  RecordMigratedSlotVisitor* record_visitor_;
  std::vector<MigrationObserver*> observers_;
  MigrateFunction migration_function_;
  const bool shared_string_table_;
#if DEBUG
  Address abort_evacuation_at_address_{kNullAddress};
#endif  // DEBUG
  std::optional<base::RandomNumberGenerator> rng_;
};

class EvacuateNewSpaceVisitor final : public EvacuateVisitorBase {
 public:
  explicit EvacuateNewSpaceVisitor(
      Heap* heap, EvacuationAllocator* local_allocator,
      RecordMigratedSlotVisitor* record_visitor,
      PretenuringHandler::PretenuringFeedbackMap* local_pretenuring_feedback)
      : EvacuateVisitorBase(heap, local_allocator, record_visitor),
        promoted_size_(0),
        semispace_copied_size_(0),
        pretenuring_handler_(heap_->pretenuring_handler()),
        local_pretenuring_feedback_(local_pretenuring_feedback),
        is_incremental_marking_(heap->incremental_marking()->IsMarking()),
        shortcut_strings_(!heap_->IsGCWithStack() ||
                          v8_flags.shortcut_strings_with_stack) {
    DCHECK_IMPLIES(is_incremental_marking_,
                   heap->incremental_marking()->IsMajorMarking());
  }

  inline bool Visit(Tagged<HeapObject> object, int size) override {
    if (TryEvacuateWithoutCopy(object)) return true;
    Tagged<HeapObject> target_object;

    PretenuringHandler::UpdateAllocationSite(heap_, object->map(), object, size,
                                             local_pretenuring_feedback_);

    if (!TryEvacuateObject(OLD_SPACE, object, size, &target_object)) {
      heap_->FatalProcessOutOfMemory(
          "MarkCompactCollector: young object promotion failed");
    }

    promoted_size_ += size;
    return true;
  }

  intptr_t promoted_size() { return promoted_size_; }
  intptr_t semispace_copied_size() { return semispace_copied_size_; }

 private:
  inline bool TryEvacuateWithoutCopy(Tagged<HeapObject> object) {
    DCHECK(!is_incremental_marking_);

    if (!shortcut_strings_) return false;

    Tagged<Map> map = object->map();

    // Some objects can be evacuated without creating a copy.
    if (map->visitor_id() == kVisitThinString) {
      Tagged<HeapObject> actual = Cast<ThinString>(object)->unchecked_actual();
      if (MarkCompactCollector::IsOnEvacuationCandidate(actual)) return false;
      object->set_map_word_forwarded(actual, kRelaxedStore);
      return true;
    }
    // TODO(mlippautz): Handle ConsString.

    return false;
  }

  inline AllocationSpace AllocateTargetObject(
      Tagged<HeapObject> old_object, int size,
      Tagged<HeapObject>* target_object) {
    AllocationAlignment alignment =
        HeapObject::RequiredAlignment(old_object->map());
    AllocationSpace space_allocated_in = NEW_SPACE;
    AllocationResult allocation =
        local_allocator_->Allocate(NEW_SPACE, size, alignment);
    if (allocation.IsFailure()) {
      allocation = AllocateInOldSpace(size, alignment);
      space_allocated_in = OLD_SPACE;
    }
    bool ok 
"""


```