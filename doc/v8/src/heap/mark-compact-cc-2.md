Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/heap/mark-compact.cc`. The summary should cover several aspects:

1. **General Functionality:** What does this code do?
2. **Torque Source:** Does the `.cc` extension imply it's not Torque?
3. **Javascript Relation:** Does this code relate to Javascript behavior, and if so, how? Provide a Javascript example.
4. **Code Logic and Inference:**  Are there specific algorithms or logic flows that can be explained with input and output examples?
5. **Common Programming Errors:** Does this code relate to typical mistakes programmers might make?
6. **Overall Function:**  A concise summary of the code's purpose.
7. **Part of a Larger Whole:** Acknowledge that this is part 3 of 8.

**Plan:**

1. **Analyze the Code:** Read through the provided code, identifying key classes and their methods. Focus on the core operations being performed.
2. **Address Torque:** Explain that `.cc` indicates C++ and not Torque (which uses `.tq`).
3. **Connect to Javascript:**  Relate the garbage collection concepts (marking, evacuation, weak references) to Javascript memory management. Provide a simple Javascript example demonstrating garbage collection.
4. **Identify Logic/Inference:**  The code deals with marking objects as live and moving them. The ephemeron processing is a good candidate for illustrating logic. However, without complete context, precise input/output for complex logic might be difficult. Focus on the *concept* of ephemeron processing and its goal.
5. **Consider Common Errors:**  Think about common memory management errors in general programming and how garbage collection helps prevent them. Specifically, dangling pointers and memory leaks.
6. **Synthesize the Summary:** Combine the findings into a cohesive summary addressing all the user's points.
7. **Acknowledge Part 3 of 8:**  Include this detail in the final summary.
```
v8/src/heap/mark-compact.cc
``` 是 V8 引擎中负责执行 Mark-Compact 垃圾回收算法的核心 C++ 源代码文件的一部分。从提供的代码片段来看，它主要关注**标记（Mark）**阶段的细节，尤其是与对象标记、跨堆（client heap 和 shared heap）的对象标记以及处理弱引用（特别是 Ephemerons）相关的逻辑。

**功能列举:**

1. **对象分配辅助:** `AllocationResult` 和相关函数 (`AllocateInNewSpace`, `AllocateInOldSpace`) 提供了在堆的不同空间（New Space, Old Space）中分配内存的基本功能。
2. **对象疏散（Evacuation）:**  定义了不同的 Visitor 类 (`EvacuateNewToOldSpacePageVisitor`, `EvacuateOldSpaceVisitor`, `EvacuateRecordOnlyVisitor`)，用于在 Mark-Compact 算法的疏散阶段移动对象。`EvacuateNewToOldSpacePageVisitor` 负责将新生代的对象晋升到老年代。`EvacuateOldSpaceVisitor` 负责在老年代内疏散对象。`EvacuateRecordOnlyVisitor` 仅记录需要疏散的对象的尺寸。
3. **跨堆对象标记:** 包含了 `MarkObjectsFromClientHeaps` 和 `MarkObjectsFromClientHeap` 函数，负责在共享空间和客户端堆之间进行对象标记，确保从客户端堆引用的共享堆对象也被标记为存活。这涉及到遍历 remembered sets (`OLD_TO_SHARED`) 来追踪跨堆引用。
4. **根对象标记:** `MarkRoots` 函数负责标记从根对象（例如全局变量、栈变量）可达的对象。它使用了 `RootVisitor` 模式来遍历不同类型的根，并包括了对优化栈帧的特殊处理。
5. **保守栈扫描:** `MarkRootsFromConservativeStack` 函数用于保守地扫描栈，标记其中可能指向堆对象的指针。
6. **Ephemeron 处理:** 实现了 `MarkTransitiveClosureUntilFixpoint`, `ProcessEphemerons`, `MarkTransitiveClosureLinear` 等函数，用于处理 Ephemerons（一种键值都可能是弱引用的数据结构）。这些函数确保如果一个 Ephemeron 的键不可达，即使其值可达，该值也不会被标记为存活。
7. **标记工作队列处理:** `ProcessMarkingWorklist` 函数负责从标记工作队列中取出对象并进行标记，遍历其内部的引用，并将新发现的需要标记的对象添加到工作队列中。
8. **包装器追踪:** `PerformWrapperTracing` 函数涉及 C++ 堆的垃圾回收，用于追踪和标记 C++ 对象包装的 JavaScript 对象。
9. **对象统计:** `RecordObjectStats` 函数用于收集和记录垃圾回收后的对象统计信息。
10. **Map 对象保留:** `RetainMaps` 函数尝试保留一些 Map 对象，以提高性能，避免频繁创建相同的 Map。
11. **完整标记流程:** `MarkLiveObjects` 函数是标记阶段的入口，协调根对象标记、跨堆对象标记、Ephemeron 处理等步骤。
12. **顶层优化帧处理:** `ProcessTopOptimizedFrame` 用于特殊处理顶层优化 JavaScript 函数的栈帧，确保其中引用的对象被正确标记。

**关于源代码类型:**

如果 `v8/src/heap/mark-compact.cc` 以 `.tq` 结尾，那么它会是一个 V8 Torque 源代码。但实际上它是 `.cc` 结尾，这表明它是一个标准的 **C++ 源代码文件**。Torque 主要用于定义 V8 的内置函数和类型系统，而 `mark-compact.cc` 实现了核心的垃圾回收逻辑，因此使用 C++。

**与 JavaScript 的关系 (以及 JavaScript 示例):**

`v8/src/heap/mark-compact.cc` 中的代码直接影响 JavaScript 的内存管理和垃圾回收行为。Mark-Compact 算法负责识别和回收 JavaScript 中不再使用的对象，从而防止内存泄漏。

**JavaScript 示例:**

```javascript
let obj1 = { data: {} };
let obj2 = { ref: obj1 };
let weakRef = new WeakRef(obj1); // 创建一个指向 obj1 的弱引用

// 此时 obj1 是可达的，不会被回收
console.log(weakRef.deref()); // 输出 obj1

obj1 = null; // 解除 obj1 的强引用

// 此时 obj1 可能在下一次垃圾回收时被回收，因为只有 obj2 和 weakRef 引用它
// obj2 的引用是强引用，会阻止回收
// weakRef 的引用是弱引用，不会阻止回收

// 手动触发垃圾回收（在浏览器或 Node.js 中通常是自动的，此处仅为演示）
if (global.gc) {
  global.gc();
}

console.log(weakRef.deref()); // 输出 obj1 或 undefined，取决于是否被回收

obj2 = null; // 解除 obj2 的强引用

// 此时 obj1 没有强引用，只剩 weakRef，可能会被回收

if (global.gc) {
  global.gc();
}

console.log(weakRef.deref()); // 很可能输出 undefined，因为 obj1 已被回收
```

在这个例子中，Mark-Compact 算法会遍历对象图，标记 `obj2` 和 `weakRef` 等根对象可达的对象。当 `obj1` 的强引用被移除后，如果垃圾回收器执行，`mark-compact.cc` 中的标记逻辑会判断 `obj1` 是否仍然存活（被强引用）。由于 `weakRef` 不阻止回收，`obj1` 很可能在后续的垃圾回收中被回收。`mark-compact.cc` 中关于 Ephemeron 的处理也与 `WeakMap` 和 `WeakSet` 的行为密切相关。

**代码逻辑推理 (假设输入与输出):**

假设我们正在处理一个简单的 Ephemeron，其键 `key` 指向一个对象 `A`，值 `value` 指向一个对象 `B`。

**假设输入:**

* `key` 对象 `A` 在标记阶段开始时是未标记的。
* `value` 对象 `B` 在标记阶段开始时是未标记的。
* 在处理 Ephemeron 之前，没有其他强引用指向 `A` 或 `B`。

**代码逻辑推理 (基于 `ProcessEphemeron` 函数):**

1. `MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_, key)` 将返回 `false`，因为 `key` (对象 `A`) 未被标记。
2. `marking_state_->IsUnmarked(value)` 将返回 `true`，因为 `value` (对象 `B`) 未被标记。
3. `local_weak_objects()->next_ephemerons_local.Push(Ephemeron{key, value})` 将被执行，将这个 Ephemeron 添加到 `next_ephemerons` 队列中，等待后续迭代处理。

**后续迭代可能的结果:**

如果后续的标记阶段发现有强引用指向 `key` (对象 `A`) 并将其标记为存活，那么在下一次处理这个 Ephemeron 时，`ProcessEphemeron` 会尝试标记 `value` (对象 `B`)。如果 `key` 始终未被标记，则 `value` 即使自身可达也可能因为 Ephemeron 的特性而不被标记。

**涉及用户常见的编程错误:**

1. **内存泄漏:**  如果垃圾回收器的标记阶段存在缺陷，无法正确识别不再使用的对象，就会导致内存泄漏。`mark-compact.cc` 的目标是确保所有存活对象都被正确标记，从而避免泄漏。
2. **悬挂指针/野指针:** 虽然 JavaScript 有自动垃圾回收，但理解回收机制有助于避免一些潜在的问题。例如，依赖于一个弱引用指向的对象仍然存活，而该对象可能已经被回收。
3. **过度使用全局变量:** 全局变量会一直被认为是根对象，其引用的对象也不会被回收，可能导致意外的内存占用。

**归纳一下它的功能 (第3部分):**

作为 Mark-Compact 垃圾回收算法的一部分，`v8/src/heap/mark-compact.cc` 的这一部分主要负责**对象的标记阶段**。它涵盖了从根对象开始，遍历对象图，标记所有存活对象的过程。特别关注了跨堆（共享堆和客户端堆）的对象引用处理，以及 Ephemerons 这类特殊弱引用的处理逻辑。其核心目标是准确识别哪些对象是程序仍然需要的，为后续的清理和压缩阶段奠定基础。 这段代码还包含了对象分配的辅助功能和为后续疏散阶段做准备的 Visitor 实现。

Prompt: 
```
这是目录为v8/src/heap/mark-compact.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/mark-compact.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能

"""
= allocation.To(target_object);
    DCHECK(ok);
    USE(ok);
    return space_allocated_in;
  }

  inline AllocationResult AllocateInOldSpace(int size_in_bytes,
                                             AllocationAlignment alignment) {
    AllocationResult allocation =
        local_allocator_->Allocate(OLD_SPACE, size_in_bytes, alignment);
    if (allocation.IsFailure()) {
      heap_->FatalProcessOutOfMemory(
          "MarkCompactCollector: semi-space copy, fallback in old gen");
    }
    return allocation;
  }

  intptr_t promoted_size_;
  intptr_t semispace_copied_size_;
  PretenuringHandler* const pretenuring_handler_;
  PretenuringHandler::PretenuringFeedbackMap* local_pretenuring_feedback_;
  bool is_incremental_marking_;
  const bool shortcut_strings_;
};

class EvacuateNewToOldSpacePageVisitor final : public HeapObjectVisitor {
 public:
  explicit EvacuateNewToOldSpacePageVisitor(
      Heap* heap, RecordMigratedSlotVisitor* record_visitor,
      PretenuringHandler::PretenuringFeedbackMap* local_pretenuring_feedback)
      : heap_(heap),
        record_visitor_(record_visitor),
        moved_bytes_(0),
        pretenuring_handler_(heap_->pretenuring_handler()),
        local_pretenuring_feedback_(local_pretenuring_feedback) {}

  static void Move(PageMetadata* page) {
    page->heap()->new_space()->PromotePageToOldSpace(page);
  }

  inline bool Visit(Tagged<HeapObject> object, int size) override {
    if (v8_flags.minor_ms) {
      PretenuringHandler::UpdateAllocationSite(
          heap_, object->map(), object, size, local_pretenuring_feedback_);
    }
    DCHECK(!HeapLayout::InCodeSpace(object));
    record_visitor_->Visit(object->map(), object, size);
    return true;
  }

  intptr_t moved_bytes() { return moved_bytes_; }
  void account_moved_bytes(intptr_t bytes) { moved_bytes_ += bytes; }

 private:
  Heap* heap_;
  RecordMigratedSlotVisitor* record_visitor_;
  intptr_t moved_bytes_;
  PretenuringHandler* const pretenuring_handler_;
  PretenuringHandler::PretenuringFeedbackMap* local_pretenuring_feedback_;
};

class EvacuateOldSpaceVisitor final : public EvacuateVisitorBase {
 public:
  EvacuateOldSpaceVisitor(Heap* heap, EvacuationAllocator* local_allocator,
                          RecordMigratedSlotVisitor* record_visitor)
      : EvacuateVisitorBase(heap, local_allocator, record_visitor) {}

  inline bool Visit(Tagged<HeapObject> object, int size) override {
    Tagged<HeapObject> target_object;
    if (TryEvacuateObject(
            PageMetadata::FromHeapObject(object)->owner_identity(), object,
            size, &target_object)) {
      DCHECK(object->map_word(heap_->isolate(), kRelaxedLoad)
                 .IsForwardingAddress());
      return true;
    }
    return false;
  }
};

class EvacuateRecordOnlyVisitor final : public HeapObjectVisitor {
 public:
  explicit EvacuateRecordOnlyVisitor(Heap* heap)
      : heap_(heap), cage_base_(heap->isolate()) {}

  bool Visit(Tagged<HeapObject> object, int size) override {
    RecordMigratedSlotVisitor visitor(heap_);
    Tagged<Map> map = object->map(cage_base_);
    // Instead of calling object.IterateFast(cage_base(), &visitor) here
    // we can shortcut and use the precomputed size value passed to the visitor.
    DCHECK_EQ(object->SizeFromMap(map), size);
    live_object_size_ += ALIGN_TO_ALLOCATION_ALIGNMENT(size);
    visitor.Visit(map, object, size);
    return true;
  }

  size_t live_object_size() const { return live_object_size_; }

 private:
  Heap* heap_;
  const PtrComprCageBase cage_base_;
  size_t live_object_size_ = 0;
};

// static
bool MarkCompactCollector::IsUnmarkedHeapObject(Heap* heap, FullObjectSlot p) {
  Tagged<Object> o = *p;
  if (!IsHeapObject(o)) return false;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(o);
  return MarkingHelper::IsUnmarkedAndNotAlwaysLive(
      heap, heap->non_atomic_marking_state(), heap_object);
}

// static
bool MarkCompactCollector::IsUnmarkedSharedHeapObject(Heap* client_heap,
                                                      FullObjectSlot p) {
  Tagged<Object> o = *p;
  if (!IsHeapObject(o)) return false;
  Tagged<HeapObject> heap_object = Cast<HeapObject>(o);
  Heap* shared_space_heap =
      client_heap->isolate()->shared_space_isolate()->heap();
  if (!HeapLayout::InWritableSharedSpace(heap_object)) return false;
  return MarkingHelper::IsUnmarkedAndNotAlwaysLive(
      shared_space_heap, shared_space_heap->non_atomic_marking_state(),
      heap_object);
}

void MarkCompactCollector::MarkRoots(RootVisitor* root_visitor) {
  Isolate* const isolate = heap_->isolate();

  // Mark the heap roots including global variables, stack variables,
  // etc., and all objects reachable from them.
  heap_->IterateRoots(
      root_visitor,
      base::EnumSet<SkipRoot>{SkipRoot::kWeak, SkipRoot::kTracedHandles,
                              SkipRoot::kConservativeStack,
                              SkipRoot::kReadOnlyBuiltins});

  // Custom marking for top optimized frame.
  CustomRootBodyMarkingVisitor custom_root_body_visitor(this);
  ProcessTopOptimizedFrame(&custom_root_body_visitor, isolate);

  if (isolate->is_shared_space_isolate()) {
    ClientRootVisitor<> client_root_visitor(root_visitor);
    ClientObjectVisitor<> client_custom_root_body_visitor(
        &custom_root_body_visitor);

    isolate->global_safepoint()->IterateClientIsolates(
        [this, &client_root_visitor,
         &client_custom_root_body_visitor](Isolate* client) {
          client->heap()->IterateRoots(
              &client_root_visitor,
              base::EnumSet<SkipRoot>{SkipRoot::kWeak,
                                      SkipRoot::kConservativeStack,
                                      SkipRoot::kReadOnlyBuiltins});
          ProcessTopOptimizedFrame(&client_custom_root_body_visitor, client);
        });
  }
}

void MarkCompactCollector::MarkRootsFromConservativeStack(
    RootVisitor* root_visitor) {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::CONSERVATIVE_STACK_SCANNING);
  heap_->IterateConservativeStackRoots(root_visitor,
                                       Heap::IterateRootsMode::kMainIsolate);

  Isolate* const isolate = heap_->isolate();
  if (isolate->is_shared_space_isolate()) {
    ClientRootVisitor<> client_root_visitor(root_visitor);
    // For client isolates, use the stack marker to conservatively scan the
    // stack.
    isolate->global_safepoint()->IterateClientIsolates(
        [v = &client_root_visitor](Isolate* client) {
          client->heap()->IterateConservativeStackRoots(
              v, Heap::IterateRootsMode::kClientIsolate);
        });
  }
}

void MarkCompactCollector::MarkObjectsFromClientHeaps() {
  Isolate* const isolate = heap_->isolate();
  if (!isolate->is_shared_space_isolate()) return;

  isolate->global_safepoint()->IterateClientIsolates(
      [collector = this](Isolate* client) {
        collector->MarkObjectsFromClientHeap(client);
      });
}

void MarkCompactCollector::MarkObjectsFromClientHeap(Isolate* client) {
  // There is no OLD_TO_SHARED remembered set for the young generation. We
  // therefore need to iterate each object and check whether it points into the
  // shared heap. As an optimization and to avoid a second heap iteration in the
  // "update pointers" phase, all pointers into the shared heap are recorded in
  // the OLD_TO_SHARED remembered set as well.
  SharedHeapObjectVisitor visitor(this);

  PtrComprCageBase cage_base(client);
  Heap* client_heap = client->heap();

  // Finish sweeping for new space in order to iterate objects in it.
  client_heap->sweeper()->FinishMinorJobs();
  // Finish sweeping for old generation in order to iterate OLD_TO_SHARED.
  client_heap->sweeper()->FinishMajorJobs();

  if (auto* new_space = client_heap->new_space()) {
    DCHECK(!client_heap->allocator()->new_space_allocator()->IsLabValid());
    for (PageMetadata* page : *new_space) {
      for (Tagged<HeapObject> obj : HeapObjectRange(page)) {
        visitor.Visit(obj);
      }
    }
  }

  if (client_heap->new_lo_space()) {
    std::unique_ptr<ObjectIterator> iterator =
        client_heap->new_lo_space()->GetObjectIterator(client_heap);
    for (Tagged<HeapObject> obj = iterator->Next(); !obj.is_null();
         obj = iterator->Next()) {
      visitor.Visit(obj);
    }
  }

  // In the old generation we can simply use the OLD_TO_SHARED remembered set to
  // find all incoming pointers into the shared heap.
  OldGenerationMemoryChunkIterator chunk_iterator(client_heap);

  // Tracking OLD_TO_SHARED requires the write barrier.
  DCHECK(!v8_flags.disable_write_barriers);

  for (MutablePageMetadata* chunk = chunk_iterator.next(); chunk;
       chunk = chunk_iterator.next()) {
    const auto slot_count = RememberedSet<OLD_TO_SHARED>::Iterate(
        chunk,
        [collector = this, cage_base](MaybeObjectSlot slot) {
          Tagged<MaybeObject> obj = slot.Relaxed_Load(cage_base);
          Tagged<HeapObject> heap_object;

          if (obj.GetHeapObject(&heap_object) &&
              HeapLayout::InWritableSharedSpace(heap_object)) {
            // If the object points to the black allocated shared page, don't
            // mark the object, but still keep the slot.
            if (MarkingHelper::ShouldMarkObject(collector->heap(),
                                                heap_object)) {
              collector->MarkRootObject(
                  Root::kClientHeap, heap_object,
                  MarkingHelper::WorklistTarget::kRegular);
            }
            return KEEP_SLOT;
          } else {
            return REMOVE_SLOT;
          }
        },
        SlotSet::FREE_EMPTY_BUCKETS);
    if (slot_count == 0) {
      chunk->ReleaseSlotSet(OLD_TO_SHARED);
    }

    const auto typed_slot_count = RememberedSet<OLD_TO_SHARED>::IterateTyped(
        chunk,
        [collector = this, client_heap](SlotType slot_type, Address slot) {
          Tagged<HeapObject> heap_object =
              UpdateTypedSlotHelper::GetTargetObject(client_heap, slot_type,
                                                     slot);
          if (HeapLayout::InWritableSharedSpace(heap_object)) {
            // If the object points to the black allocated shared page, don't
            // mark the object, but still keep the slot.
            if (MarkingHelper::ShouldMarkObject(collector->heap(),
                                                heap_object)) {
              collector->MarkRootObject(
                  Root::kClientHeap, heap_object,
                  MarkingHelper::WorklistTarget::kRegular);
            }
            return KEEP_SLOT;
          } else {
            return REMOVE_SLOT;
          }
        });
    if (typed_slot_count == 0) {
      chunk->ReleaseTypedSlotSet(OLD_TO_SHARED);
    }

    const auto protected_slot_count =
        RememberedSet<TRUSTED_TO_SHARED_TRUSTED>::Iterate(
            chunk,
            [collector = this](MaybeObjectSlot slot) {
              ProtectedPointerSlot protected_slot(slot.address());
              Tagged<MaybeObject> obj = protected_slot.Relaxed_Load();
              Tagged<HeapObject> heap_object;

              if (obj.GetHeapObject(&heap_object) &&
                  HeapLayout::InWritableSharedSpace(heap_object)) {
                // If the object points to the black allocated shared page,
                // don't mark the object, but still keep the slot.
                if (MarkingHelper::ShouldMarkObject(collector->heap(),
                                                    heap_object)) {
                  collector->MarkRootObject(
                      Root::kClientHeap, heap_object,
                      MarkingHelper::WorklistTarget::kRegular);
                }
                return KEEP_SLOT;
              } else {
                return REMOVE_SLOT;
              }
            },
            SlotSet::FREE_EMPTY_BUCKETS);
    if (protected_slot_count == 0) {
      chunk->ReleaseSlotSet(TRUSTED_TO_SHARED_TRUSTED);
    }
  }

#ifdef V8_ENABLE_SANDBOX
  DCHECK(IsSharedExternalPointerType(kExternalStringResourceTag));
  DCHECK(IsSharedExternalPointerType(kExternalStringResourceDataTag));
  // All ExternalString resources are stored in the shared external pointer
  // table. Mark entries from client heaps.
  ExternalPointerTable& shared_table = client->shared_external_pointer_table();
  ExternalPointerTable::Space* shared_space =
      client->shared_external_pointer_space();
  MarkExternalPointerFromExternalStringTable external_string_visitor(
      &shared_table, shared_space);
  client_heap->external_string_table_.IterateAll(&external_string_visitor);
#endif  // V8_ENABLE_SANDBOX
}

bool MarkCompactCollector::MarkTransitiveClosureUntilFixpoint() {
  int iterations = 0;
  int max_iterations = v8_flags.ephemeron_fixpoint_iterations;

  bool another_ephemeron_iteration_main_thread;

  do {
    PerformWrapperTracing();

    if (iterations >= max_iterations) {
      // Give up fixpoint iteration and switch to linear algorithm.
      return false;
    }

    // Move ephemerons from next_ephemerons into current_ephemerons to
    // drain them in this iteration.
    DCHECK(
        local_weak_objects()->current_ephemerons_local.IsLocalAndGlobalEmpty());
    weak_objects_.current_ephemerons.Merge(weak_objects_.next_ephemerons);
    heap_->concurrent_marking()->set_another_ephemeron_iteration(false);

    {
      TRACE_GC(heap_->tracer(),
               GCTracer::Scope::MC_MARK_WEAK_CLOSURE_EPHEMERON_MARKING);
      another_ephemeron_iteration_main_thread = ProcessEphemerons();
    }

    // Can only check for local emptiness here as parallel marking tasks may
    // still be running. The caller performs the CHECKs for global emptiness.
    CHECK(local_weak_objects()->current_ephemerons_local.IsLocalEmpty());
    CHECK(local_weak_objects()->discovered_ephemerons_local.IsLocalEmpty());

    ++iterations;
  } while (another_ephemeron_iteration_main_thread ||
           heap_->concurrent_marking()->another_ephemeron_iteration() ||
           !local_marking_worklists_->IsEmpty() ||
           !IsCppHeapMarkingFinished(heap_, local_marking_worklists_.get()));

  return true;
}

bool MarkCompactCollector::ProcessEphemerons() {
  Ephemeron ephemeron;
  bool another_ephemeron_iteration = false;

  // Drain current_ephemerons and push ephemerons where key and value are still
  // unreachable into next_ephemerons.
  while (local_weak_objects()->current_ephemerons_local.Pop(&ephemeron)) {
    if (ProcessEphemeron(ephemeron.key, ephemeron.value)) {
      another_ephemeron_iteration = true;
    }
  }

  // Drain marking worklist and push discovered ephemerons into
  // discovered_ephemerons.
  size_t objects_processed;
  std::tie(std::ignore, objects_processed) =
      ProcessMarkingWorklist(v8::base::TimeDelta::Max(), SIZE_MAX,
                             MarkingWorklistProcessingMode::kDefault);

  // As soon as a single object was processed and potentially marked another
  // object we need another iteration. Otherwise we might miss to apply
  // ephemeron semantics on it.
  if (objects_processed > 0) another_ephemeron_iteration = true;

  // Drain discovered_ephemerons (filled in the drain MarkingWorklist-phase
  // before) and push ephemerons where key and value are still unreachable into
  // next_ephemerons.
  while (local_weak_objects()->discovered_ephemerons_local.Pop(&ephemeron)) {
    if (ProcessEphemeron(ephemeron.key, ephemeron.value)) {
      another_ephemeron_iteration = true;
    }
  }

  // Flush local ephemerons for main task to global pool.
  local_weak_objects()->ephemeron_hash_tables_local.Publish();
  local_weak_objects()->next_ephemerons_local.Publish();

  return another_ephemeron_iteration;
}

void MarkCompactCollector::MarkTransitiveClosureLinear() {
  TRACE_GC(heap_->tracer(),
           GCTracer::Scope::MC_MARK_WEAK_CLOSURE_EPHEMERON_LINEAR);
  // This phase doesn't support parallel marking.
  DCHECK(heap_->concurrent_marking()->IsStopped());
  // We must use the full pointer comparison here as this map will be queried
  // with objects from different cages (e.g. code- or trusted cage).
  std::unordered_multimap<Tagged<HeapObject>, Tagged<HeapObject>,
                          Object::Hasher, Object::KeyEqualSafe>
      key_to_values;
  Ephemeron ephemeron;

  DCHECK(
      local_weak_objects()->current_ephemerons_local.IsLocalAndGlobalEmpty());
  weak_objects_.current_ephemerons.Merge(weak_objects_.next_ephemerons);
  while (local_weak_objects()->current_ephemerons_local.Pop(&ephemeron)) {
    ProcessEphemeron(ephemeron.key, ephemeron.value);

    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, ephemeron.value)) {
      key_to_values.insert(std::make_pair(ephemeron.key, ephemeron.value));
    }
  }

  ephemeron_marking_.newly_discovered_limit = key_to_values.size();
  bool work_to_do = true;

  while (work_to_do) {
    PerformWrapperTracing();

    ResetNewlyDiscovered();
    ephemeron_marking_.newly_discovered_limit = key_to_values.size();

    {
      TRACE_GC(heap_->tracer(),
               GCTracer::Scope::MC_MARK_WEAK_CLOSURE_EPHEMERON_MARKING);
      // Drain marking worklist and push all discovered objects into
      // newly_discovered.
      ProcessMarkingWorklist(
          v8::base::TimeDelta::Max(), SIZE_MAX,
          MarkingWorklistProcessingMode::kTrackNewlyDiscoveredObjects);
    }

    while (local_weak_objects()->discovered_ephemerons_local.Pop(&ephemeron)) {
      ProcessEphemeron(ephemeron.key, ephemeron.value);

      if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
              heap_, non_atomic_marking_state_, ephemeron.value)) {
        key_to_values.insert(std::make_pair(ephemeron.key, ephemeron.value));
      }
    }

    if (ephemeron_marking_.newly_discovered_overflowed) {
      // If newly_discovered was overflowed just visit all ephemerons in
      // next_ephemerons.
      local_weak_objects()->next_ephemerons_local.Publish();
      weak_objects_.next_ephemerons.Iterate([&](Ephemeron ephemeron) {
        if (MarkingHelper::IsMarkedOrAlwaysLive(
                heap_, non_atomic_marking_state_, ephemeron.key)) {
          if (MarkingHelper::ShouldMarkObject(heap_, ephemeron.value)) {
            MarkingHelper::TryMarkAndPush(
                heap_, local_marking_worklists_.get(),
                non_atomic_marking_state_,
                MarkingHelper::WorklistTarget::kRegular, ephemeron.value);
          }
        }
      });

    } else {
      // This is the good case: newly_discovered stores all discovered
      // objects. Now use key_to_values to see if discovered objects keep more
      // objects alive due to ephemeron semantics.
      for (Tagged<HeapObject> object : ephemeron_marking_.newly_discovered) {
        auto range = key_to_values.equal_range(object);
        for (auto it = range.first; it != range.second; ++it) {
          Tagged<HeapObject> value = it->second;
          const auto target_worklist =
              MarkingHelper::ShouldMarkObject(heap_, value);
          if (target_worklist) {
            MarkObject(object, value, target_worklist.value());
          }
        }
      }
    }

    // Do NOT drain marking worklist here, otherwise the current checks
    // for work_to_do are not sufficient for determining if another iteration
    // is necessary.

    work_to_do =
        !local_marking_worklists_->IsEmpty() ||
        !IsCppHeapMarkingFinished(heap_, local_marking_worklists_.get());
    CHECK(local_weak_objects()
              ->discovered_ephemerons_local.IsLocalAndGlobalEmpty());
  }

  ResetNewlyDiscovered();
  ephemeron_marking_.newly_discovered.shrink_to_fit();

  CHECK(local_marking_worklists_->IsEmpty());

  CHECK(weak_objects_.current_ephemerons.IsEmpty());
  CHECK(weak_objects_.discovered_ephemerons.IsEmpty());

  // Flush local ephemerons for main task to global pool.
  local_weak_objects()->ephemeron_hash_tables_local.Publish();
  local_weak_objects()->next_ephemerons_local.Publish();
}

void MarkCompactCollector::PerformWrapperTracing() {
  auto* cpp_heap = CppHeap::From(heap_->cpp_heap_);
  if (!cpp_heap) return;

  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_EMBEDDER_TRACING);
  cpp_heap->AdvanceTracing(v8::base::TimeDelta::Max());
}

namespace {

constexpr size_t kDeadlineCheckInterval = 128u;

}  // namespace

std::pair<size_t, size_t> MarkCompactCollector::ProcessMarkingWorklist(
    v8::base::TimeDelta max_duration, size_t max_bytes_to_process,
    MarkingWorklistProcessingMode mode) {
  Tagged<HeapObject> object;
  size_t bytes_processed = 0;
  size_t objects_processed = 0;
  bool is_per_context_mode = local_marking_worklists_->IsPerContextMode();
  Isolate* const isolate = heap_->isolate();
  const auto start = v8::base::TimeTicks::Now();
  PtrComprCageBase cage_base(isolate);

  if (parallel_marking_ && UseBackgroundThreadsInCycle()) {
    heap_->concurrent_marking()->RescheduleJobIfNeeded(
        GarbageCollector::MARK_COMPACTOR, TaskPriority::kUserBlocking);
  }

  while (local_marking_worklists_->Pop(&object) ||
         local_marking_worklists_->PopOnHold(&object)) {
    // The marking worklist should never contain filler objects.
    CHECK(!IsFreeSpaceOrFiller(object, cage_base));
    DCHECK(IsHeapObject(object));
    DCHECK(!HeapLayout::InReadOnlySpace(object));
    DCHECK_EQ(HeapUtils::GetOwnerHeap(object), heap_);
    DCHECK(heap_->Contains(object));
    DCHECK(!(marking_state_->IsUnmarked(object)));
    if (mode == MarkCompactCollector::MarkingWorklistProcessingMode::
                    kTrackNewlyDiscoveredObjects) {
      AddNewlyDiscovered(object);
    }
    Tagged<Map> map = object->map(cage_base);
    if (is_per_context_mode) {
      Address context;
      if (native_context_inferrer_.Infer(cage_base, map, object, &context)) {
        local_marking_worklists_->SwitchToContext(context);
      }
    }
    const auto visited_size = marking_visitor_->Visit(map, object);
    if (visited_size) {
      MutablePageMetadata::FromHeapObject(object)->IncrementLiveBytesAtomically(
          ALIGN_TO_ALLOCATION_ALIGNMENT(visited_size));
    }
    if (is_per_context_mode) {
      native_context_stats_.IncrementSize(local_marking_worklists_->Context(),
                                          map, object, visited_size);
    }
    bytes_processed += visited_size;
    objects_processed++;
    static_assert(base::bits::IsPowerOfTwo(kDeadlineCheckInterval),
                  "kDeadlineCheckInterval must be power of 2");
    // The below check is an optimized version of
    // `(objects_processed % kDeadlineCheckInterval) == 0`
    if ((objects_processed & (kDeadlineCheckInterval -1)) == 0 &&
        ((v8::base::TimeTicks::Now() - start) > max_duration)) {
      break;
    }
    if (bytes_processed >= max_bytes_to_process) {
      break;
    }
  }
  return std::make_pair(bytes_processed, objects_processed);
}

bool MarkCompactCollector::ProcessEphemeron(Tagged<HeapObject> key,
                                            Tagged<HeapObject> value) {
  // Objects in the shared heap are prohibited from being used as keys in
  // WeakMaps and WeakSets and therefore cannot be ephemeron keys, because that
  // would enable thread local -> shared heap edges.
  DCHECK(!HeapLayout::InWritableSharedSpace(key));
  // Usually values that should not be marked are not added to the ephemeron
  // worklist. However, minor collection during incremental marking may promote
  // strings from the younger generation into the shared heap. This
  // ShouldMarkObject call catches those cases.
  const auto target_worklist = MarkingHelper::ShouldMarkObject(heap_, value);
  if (!target_worklist) {
    return false;
  }
  if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_, key)) {
    if (MarkingHelper::TryMarkAndPush(heap_, local_marking_worklists_.get(),
                                      marking_state_, target_worklist.value(),
                                      value)) {
      return true;
    }
  } else if (marking_state_->IsUnmarked(value)) {
    local_weak_objects()->next_ephemerons_local.Push(Ephemeron{key, value});
  }
  return false;
}

void MarkCompactCollector::VerifyEphemeronMarking() {
#ifdef VERIFY_HEAP
  if (v8_flags.verify_heap) {
    Ephemeron ephemeron;

    CHECK(
        local_weak_objects()->current_ephemerons_local.IsLocalAndGlobalEmpty());
    weak_objects_.current_ephemerons.Merge(weak_objects_.next_ephemerons);
    while (local_weak_objects()->current_ephemerons_local.Pop(&ephemeron)) {
      CHECK(!ProcessEphemeron(ephemeron.key, ephemeron.value));
    }
  }
#endif  // VERIFY_HEAP
}

void MarkCompactCollector::MarkTransitiveClosure() {
  // Incremental marking might leave ephemerons in main task's local
  // buffer, flush it into global pool.
  local_weak_objects()->next_ephemerons_local.Publish();

  if (!MarkTransitiveClosureUntilFixpoint()) {
    // Fixpoint iteration needed too many iterations and was cancelled. Use the
    // guaranteed linear algorithm. But only in the final single-thread marking
    // phase.
    if (!parallel_marking_) MarkTransitiveClosureLinear();
  }
}

void MarkCompactCollector::ProcessTopOptimizedFrame(ObjectVisitor* visitor,
                                                    Isolate* isolate) {
  for (StackFrameIterator it(isolate, isolate->thread_local_top(),
                             StackFrameIterator::NoHandles{});
       !it.done(); it.Advance()) {
    if (it.frame()->is_unoptimized_js()) return;
    if (it.frame()->is_optimized_js()) {
      Tagged<GcSafeCode> lookup_result = it.frame()->GcSafeLookupCode();
      if (!lookup_result->has_instruction_stream()) return;
      if (!lookup_result->CanDeoptAt(isolate,
                                     it.frame()->maybe_unauthenticated_pc())) {
        Tagged<InstructionStream> istream = UncheckedCast<InstructionStream>(
            lookup_result->raw_instruction_stream());
        PtrComprCageBase cage_base(isolate);
        InstructionStream::BodyDescriptor::IterateBody(istream->map(cage_base),
                                                       istream, visitor);
      }
      return;
    }
  }
}

void MarkCompactCollector::RecordObjectStats() {
  if (V8_LIKELY(!TracingFlags::is_gc_stats_enabled())) return;
  // Cannot run during bootstrapping due to incomplete objects.
  if (heap_->isolate()->bootstrapper()->IsActive()) return;
  TRACE_EVENT0(TRACE_GC_CATEGORIES, "V8.GC_OBJECT_DUMP_STATISTICS");
  heap_->CreateObjectStats();
  ObjectStatsCollector collector(heap_, heap_->live_object_stats_.get(),
                                 heap_->dead_object_stats_.get());
  collector.Collect();
  if (V8_UNLIKELY(TracingFlags::gc_stats.load(std::memory_order_relaxed) &
                  v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
    std::stringstream live, dead;
    heap_->live_object_stats_->Dump(live);
    heap_->dead_object_stats_->Dump(dead);
    TRACE_EVENT_INSTANT2(TRACE_DISABLED_BY_DEFAULT("v8.gc_stats"),
                         "V8.GC_Objects_Stats", TRACE_EVENT_SCOPE_THREAD,
                         "live", TRACE_STR_COPY(live.str().c_str()), "dead",
                         TRACE_STR_COPY(dead.str().c_str()));
  }
  if (v8_flags.trace_gc_object_stats) {
    heap_->live_object_stats_->PrintJSON("live");
    heap_->dead_object_stats_->PrintJSON("dead");
  }
  heap_->live_object_stats_->CheckpointObjectStats();
  heap_->dead_object_stats_->ClearObjectStats();
}

namespace {

bool ShouldRetainMap(Heap* heap, MarkingState* marking_state, Tagged<Map> map,
                     int age) {
  if (age == 0) {
    // The map has aged. Do not retain this map.
    return false;
  }
  Tagged<Object> constructor = map->GetConstructor();
  if (!IsHeapObject(constructor) ||
      MarkingHelper::IsUnmarkedAndNotAlwaysLive(
          heap, marking_state, Cast<HeapObject>(constructor))) {
    // The constructor is dead, no new objects with this map can
    // be created. Do not retain this map.
    return false;
  }
  return true;
}

}  // namespace

void MarkCompactCollector::RetainMaps() {
  // Retaining maps increases the chances of reusing map transitions at some
  // memory cost, hence disable it when trying to reduce memory footprint more
  // aggressively.
  const bool should_retain_maps =
      !heap_->ShouldReduceMemory() && v8_flags.retain_maps_for_n_gc != 0;

  for (Tagged<WeakArrayList> retained_maps : heap_->FindAllRetainedMaps()) {
    DCHECK_EQ(0, retained_maps->length() % 2);
    for (int i = 0; i < retained_maps->length(); i += 2) {
      Tagged<MaybeObject> value = retained_maps->Get(i);
      Tagged<HeapObject> map_heap_object;
      if (!value.GetHeapObjectIfWeak(&map_heap_object)) {
        continue;
      }
      int age = retained_maps->Get(i + 1).ToSmi().value();
      int new_age;
      Tagged<Map> map = Cast<Map>(map_heap_object);
      if (should_retain_maps && MarkingHelper::IsUnmarkedAndNotAlwaysLive(
                                    heap_, marking_state_, map)) {
        if (ShouldRetainMap(heap_, marking_state_, map, age)) {
          if (MarkingHelper::ShouldMarkObject(heap_, map)) {
            MarkingHelper::TryMarkAndPush(
                heap_, local_marking_worklists_.get(), marking_state_,
                MarkingHelper::WorklistTarget::kRegular, map);
          }
        }
        Tagged<Object> prototype = map->prototype();
        if (age > 0 && IsHeapObject(prototype) &&
            MarkingHelper::IsUnmarkedAndNotAlwaysLive(
                heap_, marking_state_, Cast<HeapObject>(prototype))) {
          // The prototype is not marked, age the map.
          new_age = age - 1;
        } else {
          // The prototype and the constructor are marked, this map keeps only
          // transition tree alive, not JSObjects. Do not age the map.
          new_age = age;
        }
      } else {
        new_age = v8_flags.retain_maps_for_n_gc;
      }
      // Compact the array and update the age.
      if (new_age != age) {
        retained_maps->Set(i + 1, Smi::FromInt(new_age));
      }
    }
  }
}

void MarkCompactCollector::MarkLiveObjects() {
  TRACE_GC_ARG1(heap_->tracer(), GCTracer::Scope::MC_MARK,
                "UseBackgroundThreads", UseBackgroundThreadsInCycle());

  const bool was_marked_incrementally =
      !heap_->incremental_marking()->IsStopped();
  if (was_marked_incrementally) {
    auto* incremental_marking = heap_->incremental_marking();
    TRACE_GC_WITH_FLOW(
        heap_->tracer(), GCTracer::Scope::MC_MARK_FINISH_INCREMENTAL,
        incremental_marking->current_trace_id(), TRACE_EVENT_FLAG_FLOW_IN);
    DCHECK(incremental_marking->IsMajorMarking());
    incremental_marking->Stop();
    MarkingBarrier::PublishAll(heap_);
  }

#ifdef DEBUG
  DCHECK(state_ == PREPARE_GC);
  state_ = MARK_LIVE_OBJECTS;
#endif

  if (heap_->cpp_heap_) {
    CppHeap::From(heap_->cpp_heap_)
        ->EnterFinalPause(heap_->embedder_stack_state_);
  }

  RootMarkingVisitor root_visitor(this);

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_ROOTS);
    MarkRoots(&root_visitor);
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_CLIENT_HEAPS);
    MarkObjectsFromClientHeaps();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_RETAIN_MAPS);
    RetainMaps();
  }

  if (v8_flags.parallel_marking && UseBackgroundThreadsInCycle()) {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_FULL_CLOSURE_PARALLEL);
    parallel_marking_ = true;
    heap_->concurrent_marking()->RescheduleJobIfNeeded(
        GarbageCollector::MARK_COMPACTOR, TaskPriority::kUserBlocking);
    MarkTransitiveClosure();
    {
      TRACE_GC(heap_->tracer(),
               GCTracer::Scope::MC_MARK_FULL_CLOSURE_PARALLEL_JOIN);
      FinishConcurrentMarking();
    }
    parallel_marking_ = false;
  } else {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_FULL_CLOSURE_SERIAL);
    MarkTransitiveClosure();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_ROOTS);
    MarkRootsFromConservativeStack(&root_visitor);
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_MARK_FULL_CLOSURE);
    // Complete the transitive closure single-threaded to avoid races with
    // multiple threads when processing weak maps and embedder heaps.
    CHECK(heap_->concurrent_marking()->IsStopped());
    if (auto* cpp_heap = CppHeap::From(heap_->cpp_heap())) {
      cpp_heap->EnterProcessGlobalAtomicPause();
    }
    MarkTransitiveClosure();
    CHECK(local_marking_worklists_->IsEmpty());
    CHECK(
        local_weak_objects()->current_ephemerons_local.IsLocalAndGlobalEmpty());
    CHECK(local_weak_objects()
              ->discovered_ephemerons_local.IsLocalAndGlobalEmpty());
    CHECK(IsCppHeapMarkingFinished(heap_, lo
"""


```