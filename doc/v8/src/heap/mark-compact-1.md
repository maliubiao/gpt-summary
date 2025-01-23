Response: The user is asking for a summary of the functionality of the provided C++ code snippet from `v8/src/heap/mark-compact.cc`. This is the second part of a four-part file.

The code primarily deals with the **marking phase** of the Mark-Compact garbage collection algorithm in V8. It defines various visitors and methods used to traverse the heap and identify live objects. It also includes logic for handling weak references, string tables, and other specific object types during marking.

Here's a breakdown of the key functionalities in this snippet:

1. **Object Evacuation:**  Defines visitors (`EvacuateNewSpaceVisitor`, `EvacuateOldSpaceVisitor`, `EvacuateRecordOnlyVisitor`) and related helper functions (`EvacuationAllocator`) for moving objects during the compaction phase (though heavily intertwined with marking in the logic).
2. **Root Marking:** Includes functions (`MarkRoots`, `MarkRootsFromConservativeStack`) to mark objects reachable from the roots of the object graph (e.g., global variables, stack variables).
3. **Cross-Heap Marking:**  Contains logic (`MarkObjectsFromClientHeaps`, `MarkObjectsFromClientHeap`) to handle marking objects in a shared heap environment, where different isolates (JavaScript execution contexts) can share objects.
4. **Ephemeron Handling:** Implements logic for handling ephemerons (weak key-value pairs) during marking. This involves iterative and linear algorithms (`MarkTransitiveClosureUntilFixpoint`, `MarkTransitiveClosureLinear`, `ProcessEphemerons`, `ProcessEphemeron`).
5. **Marking Worklist Processing:**  Provides a function (`ProcessMarkingWorklist`) to process the worklist of objects to be marked.
6. **String Table Management:** Includes classes and functions (`FullStringForwardingTableCleaner`, `ClearStringTableJobItem`) for managing and cleaning up the string table during garbage collection, including handling string externalization and internalization.
7. **Weak Reference Clearing:** Defines classes and methods for clearing different types of weak references (`ClearTrivialWeakRefJobItem`, `FilterNonTrivialWeakRefJobItem`, `ClearNonLiveReferences`).
8. **Map Retaining:**  Includes logic (`RetainMaps`) to retain frequently used Maps to optimize object creation.
9. **Object Statistics:**  Provides functionality (`RecordObjectStats`) to collect and record statistics about live and dead objects.
10. **Code Deoptimization:** Includes functions (`MarkDependentCodeForDeoptimization`) to mark code objects for deoptimization if they refer to dead objects.
11. **Bytecode Flushing:** Contains logic (`FlushBytecodeFromSFI`) to replace bytecode in SharedFunctionInfo objects with a lighter-weight representation if the code is no longer needed.

Now, let's try to connect some of these functionalities to JavaScript with examples.

**Relationship to JavaScript and Examples:**

The code in this file directly underpins how JavaScript's garbage collection works in V8. It determines which JavaScript objects are still in use and need to be kept, and which can be reclaimed.

**Example 1: Object Reachability and `MarkRoots`**

```javascript
// Global variable, acts as a root
let myObject = { data: "important" };

function myFunction() {
  // Local variable, also acts as a root while the function is executing
  let anotherObject = { value: 123 };
  console.log(myObject.data + anotherObject.value);
}

myFunction();

// After myFunction finishes, anotherObject is no longer reachable from a root
// unless it was somehow assigned to a longer-lived object.
```

The `MarkRoots` function in the C++ code would start by identifying `myObject` (as it's a global variable) and the active stack frames (which hold `anotherObject` while `myFunction` is running). Any objects reachable from these roots would be marked as live. After `myFunction` finishes, `anotherObject` would no longer be reachable and would be a candidate for garbage collection in subsequent phases.

**Example 2: Weak Maps and Ephemerons**

```javascript
let key1 = {};
let key2 = {};
let value1 = { name: "value1" };
let value2 = { name: "value2" };

let weakMap = new WeakMap();
weakMap.set(key1, value1);
weakMap.set(key2, value2);

// key1 is still referenced, so value1 is reachable
console.log(weakMap.get(key1)); // Output: { name: "value1" }

key1 = null; // key1 is no longer strongly referenced

// In a garbage collection cycle, if key1 is not reachable through other strong references,
// the entry for key1 in the WeakMap can be removed. This is the ephemeron behavior.
// The `MarkTransitiveClosure` and related functions in the C++ code handle this logic.
```

The `MarkTransitiveClosure` functions are crucial for implementing the ephemeron semantics of `WeakMap` and `WeakSet`. If the `key` in a `WeakMap` is no longer strongly reachable, the associated `value` might also become garbage collectible, even if the `WeakMap` itself is still alive.

**Example 3: String Table and String Interning**

```javascript
let str1 = "hello";
let str2 = "hello";
let str3 = "world";

// In many JavaScript engines (including V8), identical string literals are often
// "interned," meaning they refer to the same underlying string object in memory.

// The `ClearStringTableJobItem` in the C++ code is responsible for cleaning up
// the string table, removing strings that are no longer referenced by the program.
```

The `ClearStringTableJobItem` in the C++ code helps manage the string interning optimization. It ensures that the string table doesn't hold onto strings that are no longer actively used by the JavaScript program, freeing up memory.

In summary, this part of the `mark-compact.cc` file is a core component of V8's garbage collection, focusing on the marking phase where live objects are identified. Its functionalities directly affect how JavaScript objects are managed in memory and reclaimed when they are no longer needed.
这是文件 `v8/src/heap/mark-compact.cc` 的第二部分，主要负责 Mark-Compact 垃圾回收算法中的**标记（Mark）阶段**的核心逻辑。

**主要功能归纳：**

1. **对象疏散（Evacuation）：**定义了用于将新生代对象晋升到老年代或在老年代中进行对象移动的访问器 (`EvacuateNewSpaceVisitor`, `EvacuateOldSpaceVisitor`, `EvacuateRecordOnlyVisitor`) 和分配器 (`EvacuationAllocator`)。这些访问器会更新对象的转发地址，并记录移动后的对象位置。
2. **根对象标记（Root Marking）：** 包含用于遍历并标记从垃圾回收根节点（例如全局变量、栈变量）可达的对象的函数 (`MarkRoots`, `MarkRootsFromConservativeStack`)。这部分逻辑是标记阶段的起点。
3. **跨堆标记（Cross-Heap Marking）：**  处理在共享堆环境中，从客户端堆指向共享堆的对象引用 (`MarkObjectsFromClientHeaps`, `MarkObjectsFromClientHeap`)。这对于实现跨 Isolate 的对象共享至关重要。
4. **Ephemeron（瞬时键值对）处理：**  实现了处理 Ephemeron (弱引用的键值对，只有当键是可达的时值才被认为是可达的) 的逻辑 (`MarkTransitiveClosureUntilFixpoint`, `MarkTransitiveClosureLinear`, `ProcessEphemerons`, `ProcessEphemeron`)。 这部分使用迭代和线性两种方法来确保 Ephemeron 的语义正确性。
5. **标记工作队列处理（Marking Worklist Processing）：** 提供处理待标记对象工作队列的函数 (`ProcessMarkingWorklist`)。
6. **字符串表管理（String Table Management）：** 包含清理字符串转发表 (`FullStringForwardingTableCleaner`) 和字符串表本身的逻辑 (`ClearStringTableJobItem`)。这涉及到将存活的字符串转换为 ThinString/ExternalString，并移除不再被引用的字符串。
7. **弱引用清理（Weak Reference Clearing）：**  定义了用于清理不同类型的弱引用的任务 (`ClearTrivialWeakRefJobItem`, `FilterNonTrivialWeakRefJobItem`) 和核心清理逻辑 (`ClearNonLiveReferences`)。
8. **保留 Map（Retain Maps）：** 包含用于在垃圾回收后保留一些常用的 Map 对象的逻辑 (`RetainMaps`)，以优化未来对象的创建。
9. **对象统计信息记录（Record Object Stats）：**  提供记录存活和死亡对象统计信息的函数 (`RecordObjectStats`)。
10. **标记需要反优化的代码（Mark Dependent Code For Deoptimization）：** 包含标记需要因为所依赖的对象被回收而进行反优化的代码的逻辑 (`MarkDependentCodeForDeoptimization`)。
11. **刷新字节码（Flush Bytecode）：**  提供将 `SharedFunctionInfo` 中的字节码刷新为更轻量级表示的函数 (`FlushBytecodeFromSFI`)，以节省内存。

**与 JavaScript 的关系和 JavaScript 示例：**

这段 C++ 代码是 V8 引擎垃圾回收机制的核心部分，直接影响着 JavaScript 程序的内存管理。

**示例 1：对象可达性和 `MarkRoots`**

```javascript
// 全局变量，是垃圾回收的根
let obj1 = { data: "重要数据" };

function myFunction() {
  // 局部变量，在函数执行期间也是垃圾回收的根
  let obj2 = { value: 10 };
  console.log(obj1.data + obj2.value);
}

myFunction();

// 当 myFunction 执行结束后，obj2 就不再是根对象了
// 如果没有其他强引用指向 obj2，那么在下一次垃圾回收时它可能会被回收。
```

`MarkRoots` 函数会遍历全局变量（如 `obj1`）和当前的调用栈（包含 `myFunction` 执行时的局部变量 `obj2`），并将它们标记为存活。任何从这些根对象可达的对象也会被标记。当 `myFunction` 执行结束后，`obj2` 不再是根对象，如果没有任何其他强引用指向它，它将成为垃圾回收的候选对象。

**示例 2：WeakMap 和 Ephemeron**

```javascript
let key1 = {};
let key2 = {};
let value1 = { name: "值 1" };
let value2 = { name: "值 2" };

let weakMap = new WeakMap();
weakMap.set(key1, value1);
weakMap.set(key2, value2);

// 此时 key1 被强引用，所以 value1 是可达的
console.log(weakMap.get(key1)); // 输出: { name: "值 1" }

key1 = null; // key1 不再被强引用

// 在垃圾回收周期中，如果 key1 除了 WeakMap 之外没有其他强引用指向它，
// 那么 WeakMap 中 key1 对应的条目可能会被删除，value1 也可能被回收。
// 这就是 Ephemeron 的行为，由 C++ 代码中的 `MarkTransitiveClosure` 等函数处理。
```

`MarkTransitiveClosure` 函数及其相关逻辑负责处理 `WeakMap` 和 `WeakSet` 的 Ephemeron 语义。只有当 `WeakMap` 的键仍然是可达的时，对应的值才被认为是可达的。

**示例 3：字符串表和字符串驻留**

```javascript
let str1 = "hello";
let str2 = "hello";
let str3 = "world";

// 在 JavaScript 引擎中，相同的字符串字面量通常会被“驻留”（interned），
// 意味着它们在内存中指向同一个字符串对象。

// C++ 代码中的 `ClearStringTableJobItem` 负责清理字符串表，
// 移除不再被程序引用的字符串，释放内存。
```

`ClearStringTableJobItem` 函数负责清理字符串表，确保字符串表不会持有不再使用的字符串，从而节省内存。V8 会尽可能复用相同的字符串对象来减少内存占用。

总而言之，这部分 C++ 代码是 V8 引擎 Mark-Compact 垃圾回收器中至关重要的组成部分，专注于标记阶段的实现，决定哪些 JavaScript 对象是存活的，需要保留，哪些是可以被回收的。

### 提示词
```
这是目录为v8/src/heap/mark-compact.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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
    CHECK(IsCppHeapMarkingFinished(heap_, local_marking_worklists_.get()));
    VerifyEphemeronMarking();
  }

  if (was_marked_incrementally) {
    // Disable the marking barrier after concurrent/parallel marking has
    // finished as it will reset page flags that share the same bitmap as
    // the evacuation candidate bit.
    MarkingBarrier::DeactivateAll(heap_);
    heap_->isolate()->traced_handles()->SetIsMarking(false);
  }

  epoch_++;
}

namespace {

class ParallelClearingJob final : public v8::JobTask {
 public:
  class ClearingItem {
   public:
    virtual ~ClearingItem() = default;
    virtual void Run(JobDelegate* delegate) = 0;
  };

  explicit ParallelClearingJob(MarkCompactCollector* collector)
      : collector_(collector) {}
  ~ParallelClearingJob() override = default;
  ParallelClearingJob(const ParallelClearingJob&) = delete;
  ParallelClearingJob& operator=(const ParallelClearingJob&) = delete;

  // v8::JobTask overrides.
  void Run(JobDelegate* delegate) override {
    std::unique_ptr<ClearingItem> item;
    {
      base::MutexGuard guard(&items_mutex_);
      item = std::move(items_.back());
      items_.pop_back();
    }
    item->Run(delegate);
  }

  size_t GetMaxConcurrency(size_t worker_count) const override {
    base::MutexGuard guard(&items_mutex_);
    if (!v8_flags.parallel_weak_ref_clearing ||
        !collector_->UseBackgroundThreadsInCycle()) {
      return std::min<size_t>(items_.size(), 1);
    }
    return items_.size();
  }

  void Add(std::unique_ptr<ClearingItem> item) {
    items_.push_back(std::move(item));
  }

 private:
  MarkCompactCollector* collector_;
  mutable base::Mutex items_mutex_;
  std::vector<std::unique_ptr<ClearingItem>> items_;
};

class ClearStringTableJobItem final : public ParallelClearingJob::ClearingItem {
 public:
  explicit ClearStringTableJobItem(Isolate* isolate)
      : isolate_(isolate),
        trace_id_(reinterpret_cast<uint64_t>(this) ^
                  isolate->heap()->tracer()->CurrentEpoch(
                      GCTracer::Scope::MC_CLEAR_STRING_TABLE)) {}

  void Run(JobDelegate* delegate) final {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate_);

    if (isolate_->OwnsStringTables()) {
      TRACE_GC1_WITH_FLOW(isolate_->heap()->tracer(),
                          GCTracer::Scope::MC_CLEAR_STRING_TABLE,
                          delegate->IsJoiningThread() ? ThreadKind::kMain
                                                      : ThreadKind::kBackground,
                          trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
      // Prune the string table removing all strings only pointed to by the
      // string table.  Cannot use string_table() here because the string
      // table is marked.
      StringTable* string_table = isolate_->string_table();
      InternalizedStringTableCleaner internalized_visitor(isolate_->heap());
      string_table->DropOldData();
      string_table->IterateElements(&internalized_visitor);
      string_table->NotifyElementsRemoved(
          internalized_visitor.PointersRemoved());
    }
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  Isolate* const isolate_;
  const uint64_t trace_id_;
};

}  // namespace

class FullStringForwardingTableCleaner final
    : public StringForwardingTableCleanerBase {
 public:
  explicit FullStringForwardingTableCleaner(Heap* heap)
      : StringForwardingTableCleanerBase(heap), heap_(heap) {
    USE(heap_);
  }

  // Transition all strings in the forwarding table to
  // ThinStrings/ExternalStrings and clear the table afterwards.
  void TransitionStrings() {
    DCHECK(!heap_->IsGCWithStack() ||
           v8_flags.transition_strings_during_gc_with_stack);
    StringForwardingTable* forwarding_table =
        isolate_->string_forwarding_table();
    forwarding_table->IterateElements(
        [&](StringForwardingTable::Record* record) {
          TransitionStrings(record);
        });
    forwarding_table->Reset();
  }

  // When performing GC with a stack, we conservatively assume that
  // the GC could have been triggered by optimized code. Optimized code
  // assumes that flat strings don't transition during GCs, so we are not
  // allowed to transition strings to ThinString/ExternalString in that
  // case.
  // Instead we mark forward objects to keep them alive and update entries
  // of evacuated objects later.
  void ProcessFullWithStack() {
    DCHECK(heap_->IsGCWithStack() &&
           !v8_flags.transition_strings_during_gc_with_stack);
    StringForwardingTable* forwarding_table =
        isolate_->string_forwarding_table();
    forwarding_table->IterateElements(
        [&](StringForwardingTable::Record* record) {
          MarkForwardObject(record);
        });
  }

 private:
  void MarkForwardObject(StringForwardingTable::Record* record) {
    Tagged<Object> original = record->OriginalStringObject(isolate_);
    if (!IsHeapObject(original)) {
      DCHECK_EQ(original, StringForwardingTable::deleted_element());
      return;
    }
    Tagged<String> original_string = Cast<String>(original);
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_,
                                            original_string)) {
      Tagged<Object> forward = record->ForwardStringObjectOrHash(isolate_);
      if (!IsHeapObject(forward) ||
          (MarkingHelper::GetLivenessMode(heap_, Cast<HeapObject>(forward)) ==
           MarkingHelper::LivenessMode::kAlwaysLive)) {
        return;
      }
      marking_state_->TryMarkAndAccountLiveBytes(Cast<HeapObject>(forward));
    } else {
      DisposeExternalResource(record);
      record->set_original_string(StringForwardingTable::deleted_element());
    }
  }

  void TransitionStrings(StringForwardingTable::Record* record) {
    Tagged<Object> original = record->OriginalStringObject(isolate_);
    if (!IsHeapObject(original)) {
      DCHECK_EQ(original, StringForwardingTable::deleted_element());
      return;
    }
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state_,
                                            Cast<HeapObject>(original))) {
      Tagged<String> original_string = Cast<String>(original);
      if (IsThinString(original_string)) {
        original_string = Cast<ThinString>(original_string)->actual();
      }
      TryExternalize(original_string, record);
      TryInternalize(original_string, record);
      original_string->set_raw_hash_field(record->raw_hash(isolate_));
    } else {
      DisposeExternalResource(record);
    }
  }

  void TryExternalize(Tagged<String> original_string,
                      StringForwardingTable::Record* record) {
    // If the string is already external, dispose the resource.
    if (IsExternalString(original_string)) {
      record->DisposeUnusedExternalResource(isolate_, original_string);
      return;
    }

    bool is_one_byte;
    v8::String::ExternalStringResourceBase* external_resource =
        record->external_resource(&is_one_byte);
    if (external_resource == nullptr) return;

    if (is_one_byte) {
      original_string->MakeExternalDuringGC(
          isolate_,
          reinterpret_cast<v8::String::ExternalOneByteStringResource*>(
              external_resource));
    } else {
      original_string->MakeExternalDuringGC(
          isolate_, reinterpret_cast<v8::String::ExternalStringResource*>(
                        external_resource));
    }
  }

  void TryInternalize(Tagged<String> original_string,
                      StringForwardingTable::Record* record) {
    if (IsInternalizedString(original_string)) return;
    Tagged<Object> forward = record->ForwardStringObjectOrHash(isolate_);
    if (!IsHeapObject(forward)) {
      return;
    }
    Tagged<String> forward_string = Cast<String>(forward);

    // Mark the forwarded string to keep it alive.
    if (MarkingHelper::GetLivenessMode(heap_, forward_string) !=
        MarkingHelper::LivenessMode::kAlwaysLive) {
      marking_state_->TryMarkAndAccountLiveBytes(forward_string);
    }
    // Transition the original string to a ThinString and override the
    // forwarding index with the correct hash.
    original_string->MakeThin(isolate_, forward_string);
    // Record the slot in the old-to-old remembered set. This is
    // required as the internalized string could be relocated during
    // compaction.
    ObjectSlot slot(&Cast<ThinString>(original_string)->actual_);
    MarkCompactCollector::RecordSlot(original_string, slot, forward_string);
  }

  Heap* const heap_;
};

namespace {

class SharedStructTypeRegistryCleaner final : public RootVisitor {
 public:
  explicit SharedStructTypeRegistryCleaner(Heap* heap) : heap_(heap) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    UNREACHABLE();
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK_EQ(root, Root::kSharedStructTypeRegistry);
    // The SharedStructTypeRegistry holds the canonical SharedStructType
    // instance maps weakly. Visit all Map pointers in [start, end), deleting
    // it if unmarked.
    auto* marking_state = heap_->marking_state();
    Isolate* const isolate = heap_->isolate();
    for (OffHeapObjectSlot p = start; p < end; p++) {
      Tagged<Object> o = p.load(isolate);
      DCHECK(!IsString(o));
      if (IsMap(o)) {
        Tagged<HeapObject> map = Cast<Map>(o);
        DCHECK(HeapLayout::InAnySharedSpace(map));
        if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, marking_state, map))
          continue;
        elements_removed_++;
        p.store(SharedStructTypeRegistry::deleted_element());
      }
    }
  }

  int ElementsRemoved() const { return elements_removed_; }

 private:
  Heap* heap_;
  int elements_removed_ = 0;
};

class ClearSharedStructTypeRegistryJobItem final
    : public ParallelClearingJob::ClearingItem {
 public:
  explicit ClearSharedStructTypeRegistryJobItem(Isolate* isolate)
      : isolate_(isolate) {
    DCHECK(isolate->is_shared_space_isolate());
    DCHECK_NOT_NULL(isolate->shared_struct_type_registry());
  }

  void Run(JobDelegate* delegate) final {
    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(isolate_);

    auto* registry = isolate_->shared_struct_type_registry();
    SharedStructTypeRegistryCleaner cleaner(isolate_->heap());
    registry->IterateElements(isolate_, &cleaner);
    registry->NotifyElementsRemoved(cleaner.ElementsRemoved());
  }

 private:
  Isolate* const isolate_;
};

}  // namespace

class MarkCompactCollector::ClearTrivialWeakRefJobItem final
    : public ParallelClearingJob::ClearingItem {
 public:
  explicit ClearTrivialWeakRefJobItem(MarkCompactCollector* collector)
      : collector_(collector),
        trace_id_(reinterpret_cast<uint64_t>(this) ^
                  collector->heap()->tracer()->CurrentEpoch(
                      GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_TRIVIAL)) {}

  void Run(JobDelegate* delegate) final {
    Heap* heap = collector_->heap();

    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(heap->isolate());

    TRACE_GC1_WITH_FLOW(heap->tracer(),
                        GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_TRIVIAL,
                        delegate->IsJoiningThread() ? ThreadKind::kMain
                                                    : ThreadKind::kBackground,
                        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    collector_->ClearTrivialWeakReferences();
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  MarkCompactCollector* collector_;
  const uint64_t trace_id_;
};

class MarkCompactCollector::FilterNonTrivialWeakRefJobItem final
    : public ParallelClearingJob::ClearingItem {
 public:
  explicit FilterNonTrivialWeakRefJobItem(MarkCompactCollector* collector)
      : collector_(collector),
        trace_id_(
            reinterpret_cast<uint64_t>(this) ^
            collector->heap()->tracer()->CurrentEpoch(
                GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_FILTER_NON_TRIVIAL)) {
  }

  void Run(JobDelegate* delegate) final {
    Heap* heap = collector_->heap();

    // In case multi-cage pointer compression mode is enabled ensure that
    // current thread's cage base values are properly initialized.
    PtrComprCageAccessScope ptr_compr_cage_access_scope(heap->isolate());

    TRACE_GC1_WITH_FLOW(
        heap->tracer(),
        GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_FILTER_NON_TRIVIAL,
        delegate->IsJoiningThread() ? ThreadKind::kMain
                                    : ThreadKind::kBackground,
        trace_id_, TRACE_EVENT_FLAG_FLOW_IN);
    collector_->FilterNonTrivialWeakReferences();
  }

  uint64_t trace_id() const { return trace_id_; }

 private:
  MarkCompactCollector* collector_;
  const uint64_t trace_id_;
};

void MarkCompactCollector::ClearNonLiveReferences() {
  TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR);

  Isolate* const isolate = heap_->isolate();
  if (isolate->OwnsStringTables()) {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_CLEAR_STRING_FORWARDING_TABLE);
    // Clear string forwarding table. Live strings are transitioned to
    // ThinStrings/ExternalStrings in the cleanup process, if this is a GC
    // without stack.
    // Clearing the string forwarding table must happen before clearing the
    // string table, as entries in the forwarding table can keep internalized
    // strings alive.
    FullStringForwardingTableCleaner forwarding_table_cleaner(heap_);
    if (!heap_->IsGCWithStack() ||
        v8_flags.transition_strings_during_gc_with_stack) {
      forwarding_table_cleaner.TransitionStrings();
    } else {
      forwarding_table_cleaner.ProcessFullWithStack();
    }
  }

  {
    // Clear Isolate::topmost_script_having_context slot if it's not alive.
    Tagged<Object> maybe_caller_context =
        isolate->topmost_script_having_context();
    if (maybe_caller_context.IsHeapObject() &&
        MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, marking_state_, Cast<HeapObject>(maybe_caller_context))) {
      isolate->clear_topmost_script_having_context();
    }
  }

  std::unique_ptr<JobHandle> clear_string_table_job_handle;
  {
    auto job = std::make_unique<ParallelClearingJob>(this);
    auto job_item = std::make_unique<ClearStringTableJobItem>(isolate);
    const uint64_t trace_id = job_item->trace_id();
    job->Add(std::move(job_item));
    TRACE_GC_NOTE_WITH_FLOW("ClearStringTableJob started", trace_id,
                            TRACE_EVENT_FLAG_FLOW_OUT);
    if (isolate->is_shared_space_isolate() &&
        isolate->shared_struct_type_registry()) {
      auto registry_job_item =
          std::make_unique<ClearSharedStructTypeRegistryJobItem>(isolate);
      job->Add(std::move(registry_job_item));
    }
    clear_string_table_job_handle = V8::GetCurrentPlatform()->CreateJob(
        TaskPriority::kUserBlocking, std::move(job));
  }
  if (v8_flags.parallel_weak_ref_clearing && UseBackgroundThreadsInCycle()) {
    clear_string_table_job_handle->NotifyConcurrencyIncrease();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_EXTERNAL_STRING_TABLE);
    ExternalStringTableCleanerVisitor<ExternalStringTableCleaningMode::kAll>
        external_visitor(heap_);
    heap_->external_string_table_.IterateAll(&external_visitor);
    heap_->external_string_table_.CleanUpAll();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_WEAK_GLOBAL_HANDLES);
    // We depend on `IterateWeakRootsForPhantomHandles()` being called before
    // `ProcessOldCodeCandidates()` in order to identify flushed bytecode in the
    // CPU profiler.
    isolate->global_handles()->IterateWeakRootsForPhantomHandles(
        &IsUnmarkedHeapObject);
    isolate->traced_handles()->ResetDeadNodes(&IsUnmarkedHeapObject);

    if (isolate->is_shared_space_isolate()) {
      isolate->global_safepoint()->IterateClientIsolates([](Isolate* client) {
        client->global_handles()->IterateWeakRootsForPhantomHandles(
            &IsUnmarkedSharedHeapObject);
        // No need to reset traced handles since they are always strong.
      });
    }
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_FLUSHABLE_BYTECODE);
    // `ProcessFlushedBaselineCandidates()` must be called after
    // `ProcessOldCodeCandidates()` so that we correctly set the code object on
    // the JSFunction after flushing.
    ProcessOldCodeCandidates();
#ifndef V8_ENABLE_LEAPTIERING
    // With leaptiering this is done during sweeping.
    ProcessFlushedBaselineCandidates();
#endif  // !V8_ENABLE_LEAPTIERING
  }

#ifdef V8_ENABLE_LEAPTIERING
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_JS_DISPATCH_TABLE);
    JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
    Tagged<Code> compile_lazy = *BUILTIN_CODE(heap_->isolate(), CompileLazy);
    jdt->Sweep(heap_->js_dispatch_table_space(), isolate->counters(),
               [&](JSDispatchEntry& entry) {
                 Tagged<Code> code = entry.GetCode();
                 if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
                         heap_, marking_state_, code)) {
                   // Baseline flushing: if the Code object is no longer alive,
                   // it must have been flushed and so we replace it with the
                   // CompileLazy builtin. Once we use leaptiering on all
                   // platforms, we can probably simplify the other code related
                   // to baseline flushing.

                   // Currently, we can also see optimized code here. This
                   // happens when a FeedbackCell for which no JSFunctions
                   // remain references optimized code. However, in that case we
                   // probably do want to delete the optimized code, so that is
                   // working as intended. It does mean, however, that we cannot
                   // DCHECK here that we only see baseline code.
                   DCHECK(code->kind() == CodeKind::FOR_TESTING ||
                          code->kind() == CodeKind::BASELINE ||
                          code->kind() == CodeKind::MAGLEV ||
                          code->kind() == CodeKind::TURBOFAN_JS);
                   entry.SetCodeAndEntrypointPointer(
                       compile_lazy.ptr(), compile_lazy->instruction_start());
                 }
               });
  }
#endif  // V8_ENABLE_LEAPTIERING

  // TODO(olivf, 42204201): If we make the bytecode accessible from the dispatch
  // table this could also be implemented during JSDispatchTable::Sweep.
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_FLUSHED_JS_FUNCTIONS);
    ClearFlushedJsFunctions();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_WEAK_LISTS);
    // Process the weak references.
    MarkCompactWeakObjectRetainer mark_compact_object_retainer(heap_,
                                                               marking_state_);
    heap_->ProcessAllWeakReferences(&mark_compact_object_retainer);
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_MAPS);
    // ClearFullMapTransitions must be called before weak references are
    // cleared.
    ClearFullMapTransitions();
    // Weaken recorded strong DescriptorArray objects. This phase can
    // potentially move everywhere after `ClearFullMapTransitions()`.
    WeakenStrongDescriptorArrays();
  }

  // Start two parallel jobs: one for clearing trivial weak references and one
  // for filtering out non-trivial weak references that will not be cleared.
  // Both jobs read the values of weak references and the corresponding
  // mark bits. They cannot start before the following methods have finished,
  // because these may change the values of weak references and/or mark more
  // objects, thus creating data races:
  //   - ProcessOldCodeCandidates
  //   - ProcessAllWeakReferences
  //   - ClearFullMapTransitions
  //   - WeakenStrongDescriptorArrays
  // The two jobs could be merged but it's convenient to keep them separate,
  // as they are joined at different times. The filtering job must be joined
  // before proceeding to the actual clearing of non-trivial weak references,
  // whereas the job for clearing trivial weak references can be joined at the
  // end of this method.
  std::unique_ptr<JobHandle> clear_trivial_weakrefs_job_handle;
  {
    auto job = std::make_unique<ParallelClearingJob>(this);
    auto job_item = std::make_unique<ClearTrivialWeakRefJobItem>(this);
    const uint64_t trace_id = job_item->trace_id();
    job->Add(std::move(job_item));
    TRACE_GC_NOTE_WITH_FLOW("ClearTrivialWeakRefJob started", trace_id,
                            TRACE_EVENT_FLAG_FLOW_OUT);
    clear_trivial_weakrefs_job_handle = V8::GetCurrentPlatform()->CreateJob(
        TaskPriority::kUserBlocking, std::move(job));
  }
  std::unique_ptr<JobHandle> filter_non_trivial_weakrefs_job_handle;
  {
    auto job = std::make_unique<ParallelClearingJob>(this);
    auto job_item = std::make_unique<FilterNonTrivialWeakRefJobItem>(this);
    const uint64_t trace_id = job_item->trace_id();
    job->Add(std::move(job_item));
    TRACE_GC_NOTE_WITH_FLOW("FilterNonTrivialWeakRefJob started", trace_id,
                            TRACE_EVENT_FLAG_FLOW_OUT);
    filter_non_trivial_weakrefs_job_handle =
        V8::GetCurrentPlatform()->CreateJob(TaskPriority::kUserBlocking,
                                            std::move(job));
  }
  if (v8_flags.parallel_weak_ref_clearing && UseBackgroundThreadsInCycle()) {
    clear_trivial_weakrefs_job_handle->NotifyConcurrencyIncrease();
    filter_non_trivial_weakrefs_job_handle->NotifyConcurrencyIncrease();
  }

#ifdef V8_COMPRESS_POINTERS
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_EXTERNAL_POINTER_TABLE);
    // External pointer table sweeping needs to happen before evacuating live
    // objects as it may perform table compaction, which requires objects to
    // still be at the same location as during marking.
    //
    // Note we explicitly do NOT run SweepAndCompact on
    // read_only_external_pointer_space since these entries are all immortal by
    // definition.
    isolate->external_pointer_table().EvacuateAndSweepAndCompact(
        isolate->heap()->old_external_pointer_space(),
        isolate->heap()->young_external_pointer_space(), isolate->counters());
    isolate->heap()->young_external_pointer_space()->AssertEmpty();
    if (isolate->owns_shareable_data()) {
      isolate->shared_external_pointer_table().SweepAndCompact(
          isolate->shared_external_pointer_space(), isolate->counters());
    }
    isolate->cpp_heap_pointer_table().SweepAndCompact(
        isolate->heap()->cpp_heap_pointer_space(), isolate->counters());
  }
#endif  // V8_COMPRESS_POINTERS

#ifdef V8_ENABLE_SANDBOX
  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_TRUSTED_POINTER_TABLE);
    isolate->trusted_pointer_table().Sweep(heap_->trusted_pointer_space(),
                                           isolate->counters());
    if (isolate->owns_shareable_data()) {
      isolate->shared_trusted_pointer_table().Sweep(
          isolate->shared_trusted_pointer_space(), isolate->counters());
    }
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_SWEEP_CODE_POINTER_TABLE);
    IsolateGroup::current()->code_pointer_table()->Sweep(
        heap_->code_pointer_space(), isolate->counters());
  }
#endif  // V8_ENABLE_SANDBOX

#ifdef V8_ENABLE_WEBASSEMBLY
  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_SWEEP_WASM_CODE_POINTER_TABLE);
    wasm::GetProcessWideWasmCodePointerTable()->SweepSegments();
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  {
    TRACE_GC(heap_->tracer(),
             GCTracer::Scope::MC_CLEAR_WEAK_REFERENCES_JOIN_FILTER_JOB);
    filter_non_trivial_weakrefs_job_handle->Join();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_WEAKNESS_HANDLING);
    ClearNonTrivialWeakReferences();
    ClearWeakCollections();
    ClearJSWeakRefs();
  }

  PROFILE(heap_->isolate(), WeakCodeClearEvent());

  {
    // This method may be called from within a DisallowDeoptimizations scope.
    // Temporarily allow deopts for marking code for deopt. This is not doing
    // the deopt yet and the actual deopts will be bailed out on later if the
    // current safepoint is not safe for deopts.
    // TODO(357636610): Reconsider whether the DisallowDeoptimization scopes are
    // truly needed.
    AllowDeoptimization allow_deoptimization(heap_->isolate());
    MarkDependentCodeForDeoptimization();
  }

  {
    TRACE_GC(heap_->tracer(), GCTracer::Scope::MC_CLEAR_JOIN_JOB);
    clear_string_table_job_handle->Join();
    clear_trivial_weakrefs_job_handle->Join();
  }

  if (v8_flags.sticky_mark_bits) {
    // TODO(333906585): Consider adjusting the dchecks that happen on clearing
    // and move this phase into MarkingBarrier::DeactivateAll.
    heap()->DeactivateMajorGCInProgressFlag();
  }

  DCHECK(weak_objects_.transition_arrays.IsEmpty());
  DCHECK(weak_objects_.weak_references_trivial.IsEmpty());
  DCHECK(weak_objects_.weak_references_non_trivial.IsEmpty());
  DCHECK(weak_objects_.weak_references_non_trivial_unmarked.IsEmpty());
  DCHECK(weak_objects_.weak_objects_in_code.IsEmpty());
  DCHECK(weak_objects_.js_weak_refs.IsEmpty());
  DCHECK(weak_objects_.weak_cells.IsEmpty());
  DCHECK(weak_objects_.code_flushing_candidates.IsEmpty());
  DCHECK(weak_objects_.flushed_js_functions.IsEmpty());
#ifndef V8_ENABLE_LEAPTIERING
  DCHECK(weak_objects_.baseline_flushing_candidates.IsEmpty());
#endif  // !V8_ENABLE_LEAPTIERING
}

void MarkCompactCollector::MarkDependentCodeForDeoptimization() {
  HeapObjectAndCode weak_object_in_code;
  while (local_weak_objects()->weak_objects_in_code_local.Pop(
      &weak_object_in_code)) {
    Tagged<HeapObject> object = weak_object_in_code.heap_object;
    Tagged<Code> code = weak_object_in_code.code;
    if (MarkingHelper::IsUnmarkedAndNotAlwaysLive(
            heap_, non_atomic_marking_state_, object) &&
        !code->embedded_objects_cleared()) {
      if (!code->marked_for_deoptimization()) {
        code->SetMarkedForDeoptimization(heap_->isolate(), "weak objects");
        have_code_to_deoptimize_ = true;
      }
      code->ClearEmbeddedObjects(heap_);
      DCHECK(code->embedded_objects_cleared());
    }
  }
}

void MarkCompactCollector::ClearPotentialSimpleMapTransition(
    Tagged<Map> dead_target) {
  DCHECK(non_atomic_marking_state_->IsUnmarked(dead_target));
  Tagged<Object> potential_parent = dead_target->constructor_or_back_pointer();
  if (IsMap(potential_parent)) {
    Tagged<Map> parent = Cast<Map>(potential_parent);
    DisallowGarbageCollection no_gc_obviously;
    if (MarkingHelper::IsMarkedOrAlwaysLive(heap_, non_atomic_marking_state_,
                                            parent) &&
        TransitionsAccessor(heap_->isolate(), parent)
            .HasSimpleTransitionTo(dead_target)) {
      ClearPotentialSimpleMapTransition(parent, dead_target);
    }
  }
}

void MarkCompactCollector::ClearPotentialSimpleMapTransition(
    Tagged<Map> map, Tagged<Map> dead_target) {
  DCHECK(!map->is_prototype_map());
  DCHECK(!dead_target->is_prototype_map());
  DCHECK_EQ(map->raw_transitions(), MakeWeak(dead_target));
  // Take ownership of the descriptor array.
  int number_of_own_descriptors = map->NumberOfOwnDescriptors();
  Tagged<DescriptorArray> descriptors =
      map->instance_descriptors(heap_->isolate());
  if (descriptors == dead_target->instance_descriptors(heap_->isolate()) &&
      number_of_own_descriptors > 0) {
    TrimDescriptorArray(map, descriptors);
    DCHECK(descriptors->number_of_descriptors() == number_of_own_descriptors);
  }
}

bool MarkCompactCollector::SpecialClearMapSlot(Tagged<HeapObject> host,
                                               Tagged<Map> map,
                                               HeapObjectSlot slot) {
  ClearPotentialSimpleMapTransition(map);

  // Special handling for clearing field type entries, identified by their host
  // being a descriptor array.
  // TODO(olivf): This whole special handling of field-type clearing
  // could be replaced by eagerly triggering field type dependencies and
  // generalizing field types, as soon as a field-type map becomes
  // unstable.
  if (IsDescriptorArray(host)) {
    // We want to distinguish two cases:
    // 1. There are no instances of the descriptor owner's map left.
    // 2. The field type is not up to date because the stored object
    //    migrated away to a different map.
    // In case (1) it makes sense to clear the field type such that we
    // can learn a new one should we ever start creating instances
    // again.
    // In case (2) we must not re-learn a new field type. Doing so could
    // lead us to learning a field type that is not consistent with
    // still existing object's contents. To conservatively identify case
    // (1) we check the stability of the dead map.
    MaybeObjectSlot location(slot);
    if (map->is_stable() && FieldType::kFieldTypesCanBeClearedOnGC) {
      location.store(FieldType::None());
    } else {
      location.store(FieldType::Any());
    }
    return true;
  }
  return false;
}

void MarkCompactCollector::FlushBytecodeFromSFI(
    Tagged<SharedFunctionInfo> shared_info) {
  DCHECK(shared_info->HasBytecodeArray());

  // Retain objects required for uncompiled data.
  Tagged<String> inferred_name = shared_info->inferred_name();
  int start_position = shared_info->StartPosition();
  int end_position = shared_info->EndPosition();

  shared_info->DiscardCompiledMetadata(
      heap_->isolate(),
      [](Tagged<HeapObject> object, ObjectSlot slot,
         Tagged<HeapObject> target) { RecordSlot(object, slot, target); });

  // The size of the bytecode array should always be larger than an
  // UncompiledData object.
  static_assert(BytecodeArray::SizeFor(0) >=
                UncompiledDataWithoutPreparseData::kSize);

  // Replace the bytecode with an uncompiled data object.
  Tagged<BytecodeArray> bytecode_array =
      shared_info->GetBytecodeArray(heap_->isolate());

#ifdef V8_ENABLE_SANDBOX
  DCHECK(!HeapLayout::InWritableSharedSpace(shared_info));
  // Zap the old entry in the trusted pointer table.
  TrustedPointerTable& table = heap_->isolate()->trusted_pointer_table();
  IndirectPointerSlot self_indirect_pointer_slot =
      bytecode_array->RawIndirectPointerField(
          BytecodeArray::kSelfIndirectPointerOffset,
          kBytecodeArrayIndirectPointerTag);
  table.Zap(self_indirect_pointer_slot.Relaxed_LoadHandle());
#endif

  Tagged<HeapObject> compiled_data = bytecode_array;
  Address compiled_data_start = compiled_data.address();
  int compiled_data_size = ALIGN_TO_ALLOCATION_ALIGNMENT(compiled_data->Size());
  MutablePageMetadata* chunk =
      MutablePageMetadata::FromAddress(compiled_data_start);

  // Clear any recorded slots for the compiled data as being invalid.
  RememberedSet<OLD_TO_NEW>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_SHARED>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<OLD_TO_OLD>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);
  RememberedSet<TRUSTED_TO_TRUSTED>::RemoveRange(
      chunk, compiled_data_start, compiled_data_start + compiled_data_size,
      SlotSet::FREE_EMPTY_BUCKETS);

  // Swap the map, using set_map_after_allocation to avoid verify heap checks
  // which are not necessary since we are doing this during the GC atomic pause.
  compiled_data->set_map_after_allocation(
      heap_->isolate(),
      ReadOnlyRoots(heap_).uncompiled_data_without_preparse_data_map(),
      SKIP_WRITE_BARRIER);

  // Create a filler object for any left over space in the bytecode array.
  if (!heap_->IsLargeObject(compiled_data)) {
    const int aligned_filler_offset =
        ALIGN_TO_ALLOCATION_ALIGNMENT(UncompiledDataWith
```