Response:
The user wants to understand the functionality of the `v8/src/heap/heap.cc` file in V8. I need to go through the provided code snippet and identify the key responsibilities and features implemented in this file.

Here's a breakdown of the thought process:

1. **Identify core data structures and member variables:**  Scan the code for member variables that indicate the file's responsibilities. Keywords like `heap_`, `space_`, `collector_`, `tracker_`, etc., are good indicators.

2. **Analyze the purpose of methods:** Examine the function names and their implementations to understand their role. Methods like `StartTearDown`, `TearDown`, `CompactWeakArrayLists`, `AddRetainedMaps`, and methods related to GC callbacks are significant.

3. **Look for connections to garbage collection:**  The file path itself suggests heap management. Look for explicit mentions of GC phases (marking, sweeping, scavenging), related data structures (remembered sets), and interfaces to GC mechanisms.

4. **Identify interactions with other V8 components:**  Look for references to classes and namespaces like `v8::Isolate`, `CppHeap`, `ReadOnlyRoots`, `SafepointScope`, which reveal how this file interacts with the larger V8 system.

5. **Consider the lifecycle of a Heap object:** The `StartTearDown` and `TearDown` methods are crucial for understanding the object's lifecycle and resource management.

6. **Infer functionalities based on data structures:**  For instance, `ExternalStringTable` clearly manages external strings, and the various space types (old space, new space) suggest memory organization.

7. **Relate to JavaScript concepts (if applicable):** Since V8 executes JavaScript, consider how the features in this file might relate to JavaScript features like weak references, finalization registries, and memory management.

8. **Address specific user questions:** Ensure the response addresses the user's queries about `.tq` files, JavaScript examples, code logic, common errors, and the summary.

**Pre-computation and Pre-analysis:**

* **`.tq` files:**  Recall that `.tq` files in V8 are related to Torque, a V8-specific language for generating C++ code.
* **JavaScript examples:** Think about JavaScript features that interact with the heap, such as creating objects, using weak references, and potentially observing memory pressure.
* **Code logic:** Look for simple control flow and data manipulation that can be exemplified with input/output.
* **Common errors:** Consider typical programming mistakes related to memory management, like memory leaks or dangling pointers (although V8's GC mitigates many of these).
* **Summary:** Combine the identified functionalities into a concise overview of the file's purpose within V8.

**Drafting the response (iterative process):**

* **Start with a high-level summary:** Begin with the main purpose of the file (managing the V8 heap).
* **List key functionalities:** Enumerate the important features and responsibilities.
* **Address each user question systematically:**  Provide information about `.tq` files, JavaScript examples, code logic, and common errors.
* **Refine and organize:**  Structure the response clearly with headings and bullet points for better readability.
* **Review for accuracy and completeness:** Ensure the information is correct and covers the key aspects of the code snippet.

By following these steps, I can generate a comprehensive and informative response that addresses the user's request.
```cpp
ler;
}

EmbedderRootsHandler* Heap::GetEmbedderRootsHandler() const {
  return embedder_roots_handler_;
}

void Heap::AttachCppHeap(v8::CppHeap* cpp_heap) {
  // The API function should be a noop in case a CppHeap was passed on Isolate
  // creation.
  if (owning_cpp_heap_) {
    return;
  }

  CHECK_IMPLIES(incremental_marking(), !incremental_marking()->IsMarking());
  CppHeap::From(cpp_heap)->AttachIsolate(isolate());
  cpp_heap_ = cpp_heap;
}

void Heap::DetachCppHeap() {
  // The API function should be a noop in case a CppHeap was passed on Isolate
  // creation.
  if (owning_cpp_heap_) {
    return;
  }

  CppHeap::From(cpp_heap_)->DetachIsolate();
  cpp_heap_ = nullptr;
}

std::optional<StackState> Heap::overridden_stack_state() const {
  if (!embedder_stack_state_origin_) return {};
  return embedder_stack_state_;
}

void Heap::SetStackStart() {
  // If no main thread local heap has been set up (we're still in the
  // deserialization process), we don't need to set the stack start.
  if (main_thread_local_heap_ == nullptr) return;
  stack().SetStackStart();
}

::heap::base::Stack& Heap::stack() {
  CHECK_NOT_NULL(main_thread_local_heap_);
  return main_thread_local_heap_->stack_;
}

const ::heap::base::Stack& Heap::stack() const {
  CHECK_NOT_NULL(main_thread_local_heap_);
  return main_thread_local_heap_->stack_;
}

void Heap::StartTearDown() {
  if (owning_cpp_heap_) {
    // Release the pointer. The non-owning pointer is still set which allows
    // DetachCppHeap() to work properly.
    auto* cpp_heap = owning_cpp_heap_.release();
    DetachCppHeap();
    // Termination will free up all managed C++ memory and invoke destructors.
    cpp_heap->Terminate();
  }

  // Finish any ongoing sweeping to avoid stray background tasks still accessing
  // the heap during teardown.
  CompleteSweepingFull();

  if (v8_flags.concurrent_marking) {
    concurrent_marking()->Pause();
  }

  SetGCState(TEAR_DOWN);

  // Background threads may allocate and block until GC is performed. However
  // this might never happen when the main thread tries to quit and doesn't
  // process the event queue anymore. Avoid this deadlock by allowing all
  // allocations after tear down was requested to make sure all background
  // threads finish.
  collection_barrier_->NotifyShutdownRequested();

  // Main thread isn't going to allocate anymore.
  main_thread_local_heap()->FreeLinearAllocationAreas();

  FreeMainThreadLinearAllocationAreas();
}

void Heap::TearDownWithSharedHeap() {
  DCHECK_EQ(gc_state(), TEAR_DOWN);

  // Assert that there are no background threads left and no executable memory
  // chunks are unprotected.
  safepoint()->AssertMainThreadIsOnlyThread();

  // Now that all threads are stopped, verify the heap before tearing down the
  // heap/isolate.
  HeapVerifier::VerifyHeapIfEnabled(this);

  // Might use the external pointer which might be in the shared heap.
  external_string_table_.TearDown();

  // Publish shared object worklist for the main thread if incremental marking
  // is enabled for the shared heap.
  main_thread_local_heap()->marking_barrier()->PublishSharedIfNeeded();
}

void Heap::TearDown() {
  DCHECK_EQ(gc_state(), TEAR_DOWN);

  // Assert that there are no background threads left and no executable memory
  // chunks are unprotected.
  safepoint()->AssertMainThreadIsOnlyThread();

  DCHECK(concurrent_marking()->IsStopped());

  // It's too late for Heap::Verify() here, as parts of the Isolate are
  // already gone by the time this is called.

  UpdateMaximumCommitted();

  if (v8_flags.fuzzer_gc_analysis) {
    if (v8_flags.stress_marking > 0) {
      PrintMaxMarkingLimitReached();
    }
    if (IsStressingScavenge()) {
      PrintMaxNewSpaceSizeReached();
    }
  }

  minor_gc_task_observer_.reset();
  minor_gc_job_.reset();

  if (need_to_remove_stress_concurrent_allocation_observer_) {
    RemoveAllocationObserversFromAllSpaces(
        stress_concurrent_allocation_observer_.get(),
        stress_concurrent_allocation_observer_.get());
  }
  stress_concurrent_allocation_observer_.reset();

  if (IsStressingScavenge()) {
    allocator()->new_space_allocator()->RemoveAllocationObserver(
        stress_scavenge_observer_);
    delete stress_scavenge_observer_;
    stress_scavenge_observer_ = nullptr;
  }

  if (mark_compact_collector_) {
    mark_compact_collector_->TearDown();
    mark_compact_collector_.reset();
  }

  if (minor_mark_sweep_collector_) {
    minor_mark_sweep_collector_->TearDown();
    minor_mark_sweep_collector_.reset();
  }

  sweeper_->TearDown();
  sweeper_.reset();

  scavenger_collector_.reset();
  array_buffer_sweeper_.reset();
  incremental_marking_.reset();
  concurrent_marking_.reset();

  memory_measurement_.reset();
  allocation_tracker_for_debugging_.reset();
  ephemeron_remembered_set_.reset();

  if (memory_reducer_ != nullptr) {
    memory_reducer_->TearDown();
    memory_reducer_.reset();
  }

  live_object_stats_.reset();
  dead_object_stats_.reset();

  embedder_roots_handler_ = nullptr;

  if (cpp_heap_) {
    CppHeap::From(cpp_heap_)->DetachIsolate();
    cpp_heap_ = nullptr;
  }

  tracer_.reset();

  pretenuring_handler_.reset();

  for (int i = FIRST_MUTABLE_SPACE; i <= LAST_MUTABLE_SPACE; i++) {
    space_[i].reset();
  }

  read_only_space_ = nullptr;

  memory_allocator()->TearDown();

  StrongRootsEntry* next = nullptr;
  for (StrongRootsEntry* current = strong_roots_head_; current;
       current = next) {
    next = current->next;
    delete current;
  }
  strong_roots_head_ = nullptr;

  memory_allocator_.reset();
}

// static
bool Heap::IsFreeSpaceValid(FreeSpace object) {
  Heap* heap = HeapUtils::GetOwnerHeap(object);
  Tagged<Object> free_space_map =
      heap->isolate()->root(RootIndex::kFreeSpaceMap);
  CHECK(!heap->deserialization_complete() ||
        object.map_slot().contains_map_value(free_space_map.ptr()));
  CHECK_LE(FreeSpace::kNextOffset + kTaggedSize, object.size(kRelaxedLoad));
  return true;
}

void Heap::AddGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                                 GCType gc_type, void* data) {
  gc_prologue_callbacks_.Add(
      callback, reinterpret_cast<v8::Isolate*>(isolate()), gc_type, data);
}

void Heap::RemoveGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                                    void* data) {
  gc_prologue_callbacks_.Remove(callback, data);
}

void Heap::AddGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                                 GCType gc_type, void* data) {
  gc_epilogue_callbacks_.Add(
      callback, reinterpret_cast<v8::Isolate*>(isolate()), gc_type, data);
}

void Heap::RemoveGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                                    void* data) {
  gc_epilogue_callbacks_.Remove(callback, data);
}

namespace {
Handle<WeakArrayList> CompactWeakArrayList(Heap* heap,
                                           Handle<WeakArrayList> array,
                                           AllocationType allocation) {
  if (array->length() == 0) {
    return array;
  }
  int new_length = array->CountLiveWeakReferences();
  if (new_length == array->length()) {
    return array;
  }

  Handle<WeakArrayList> new_array = WeakArrayList::EnsureSpace(
      heap->isolate(),
      handle(ReadOnlyRoots(heap).empty_weak_array_list(), heap->isolate()),
      new_length, allocation);
  // Allocation might have caused GC and turned some of the elements into
  // cleared weak heap objects. Count the number of live references again and
  // fill in the new array.
  int copy_to = 0;
  for (int i = 0; i < array->length(); i++) {
    Tagged<MaybeObject> element = array->Get(i);
    if (element.IsCleared()) continue;
    new_array->Set(copy_to++, element);
  }
  new_array->set_length(copy_to);
  return new_array;
}

}  // anonymous namespace

void Heap::CompactWeakArrayLists() {
  // Find known PrototypeUsers and compact them.
  std::vector<Handle<PrototypeInfo>> prototype_infos;
  {
    HeapObjectIterator iterator(this);
    for (Tagged<HeapObject> o = iterator.Next(); !o.is_null();
         o = iterator.Next()) {
      if (IsPrototypeInfo(*o)) {
        Tagged<PrototypeInfo> prototype_info = Cast<PrototypeInfo>(o);
        if (IsWeakArrayList(prototype_info->prototype_users())) {
          prototype_infos.emplace_back(handle(prototype_info, isolate()));
        }
      }
    }
  }
  for (auto& prototype_info : prototype_infos) {
    DirectHandle<WeakArrayList> array(
        Cast<WeakArrayList>(prototype_info->prototype_users()), isolate());
    DCHECK(InOldSpace(*array) ||
           *array == ReadOnlyRoots(this).empty_weak_array_list());
    Tagged<WeakArrayList> new_array = PrototypeUsers::Compact(
        array, this, JSObject::PrototypeRegistryCompactionCallback,
        AllocationType::kOld);
    prototype_info->set_prototype_users(new_array);
  }

  // Find known WeakArrayLists and compact them.
  Handle<WeakArrayList> scripts(script_list(), isolate());
  DCHECK(InOldSpace(*scripts));
  scripts = CompactWeakArrayList(this, scripts, AllocationType::kOld);
  set_script_list(*scripts);
}

void Heap::AddRetainedMaps(DirectHandle<NativeContext> context,
                           GlobalHandleVector<Map> maps) {
  Handle<WeakArrayList> array(Cast<WeakArrayList>(context->retained_maps()),
                              isolate());
  if (array->IsFull()) {
    CompactRetainedMaps(*array);
  }
  int cur_length = array->length();
  array = WeakArrayList::EnsureSpace(
      isolate(), array, cur_length + static_cast<int>(maps.size()) * 2);
  if (*array != context->retained_maps()) {
    context->set_retained_maps(*array);
  }

  {
    DisallowGarbageCollection no_gc;
    Tagged<WeakArrayList> raw_array = *array;
    for (DirectHandle<Map> map : maps) {
      DCHECK(!HeapLayout::InAnySharedSpace(*map));

      if (map->is_in_retained_map_list()) {
        continue;
      }

      raw_array->Set(cur_length, MakeWeak(*map));
      raw_array->Set(cur_length + 1,
                     Smi::FromInt(v8_flags.retain_maps_for_n_gc));
      cur_length += 2;
      raw_array->set_length(cur_length);

      map->set_is_in_retained_map_list(true);
    }
  }
}

void Heap::CompactRetainedMaps(Tagged<WeakArrayList> retained_maps) {
  int length = retained_maps->length();
  int new_length = 0;
  // This loop compacts the array by removing cleared weak cells.
  for (int i = 0; i < length; i += 2) {
    Tagged<MaybeObject> maybe_object = retained_maps->Get(i);
    if (maybe_object.IsCleared()) {
      continue;
    }

    DCHECK(maybe_object.IsWeak());

    Tagged<MaybeObject> age = retained_maps->Get(i + 1);
    DCHECK(IsSmi(age));
    if (i != new_length) {
      retained_maps->Set(new_length, maybe_object);
      retained_maps->Set(new_length + 1, age);
    }
    new_length += 2;
  }
  Tagged<HeapObject> undefined = ReadOnlyRoots(this).undefined_value();
  for (int i = new_length; i < length; i++) {
    retained_maps->Set(i, undefined);
  }
  if (new_length != length) retained_maps->set_length(new_length);
}

void Heap::FatalProcessOutOfMemory(const char* location) {
  V8::FatalProcessOutOfMemory(isolate(), location, V8::kHeapOOM);
}

#ifdef DEBUG

class PrintHandleVisitor : public RootVisitor {
 public:
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p)
      PrintF("  handle %p to %p\n", p.ToVoidPtr(),
             reinterpret_cast<void*>((*p).ptr()));
  }
};

void Heap::PrintHandles() {
  PrintF("Handles:\n");
  PrintHandleVisitor v;
  isolate_->handle_scope_implementer()->Iterate(&v);
}

#endif

class CheckHandleCountVisitor : public RootVisitor {
 public:
  CheckHandleCountVisitor() : handle_count_(0) {}
  ~CheckHandleCountVisitor() override {
    CHECK_GT(HandleScope::kCheckHandleThreshold, handle_count_);
  }
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    handle_count_ += end - start;
  }

 private:
  ptrdiff_t handle_count_;
};

void Heap::CheckHandleCount() {
  CheckHandleCountVisitor v;
  isolate_->handle_scope_implementer()->Iterate(&v);
}

// static
int Heap::InsertIntoRememberedSetFromCode(MutablePageMetadata* chunk,
                                          size_t slot_offset) {
  // This is called during runtime by a builtin, therefore it is run in the main
  // thread.
  DCHECK_NULL(LocalHeap::Current());
  RememberedSet<OLD_TO_NEW>::Insert<AccessMode::NON_ATOMIC>(chunk, slot_offset);
  return 0;
}

#ifdef DEBUG
void Heap::VerifySlotRangeHasNoRecordedSlots(Address start, Address end) {
#ifndef V8_DISABLE_WRITE_BARRIERS
  PageMetadata* page = PageMetadata::FromAddress(start);
  RememberedSet<OLD_TO_NEW>::CheckNoneInRange(page, start, end);
  RememberedSet<OLD_TO_NEW_BACKGROUND>::CheckNoneInRange(page, start, end);
  RememberedSet<OLD_TO_SHARED>::CheckNoneInRange(page, start, end);
#endif
}
#endif

void Heap::ClearRecordedSlotRange(Address start, Address end) {
#ifndef V8_DISABLE_WRITE_BARRIERS
  MemoryChunk* chunk = MemoryChunk::FromAddress(start);
  DCHECK(!chunk->IsLargePage());
#if !V8_ENABLE_STICKY_MARK_BITS_BOOL
  if (!chunk->InYoungGeneration())
#endif
  {
    PageMetadata* page = PageMetadata::cast(chunk->Metadata());
    // This method will be invoked on objects in shared space for
    // internalization and string forwarding during GC.
    DCHECK(page->owner_identity() == OLD_SPACE ||
           page->owner_identity() == TRUSTED_SPACE ||
           page->owner_identity() == SHARED_SPACE);

    if (!page->SweepingDone()) {
      RememberedSet<OLD_TO_NEW>::RemoveRange(page, start, end,
                                             SlotSet::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
          page, start, end, SlotSet::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_SHARED>::RemoveRange(page, start, end,
                                                SlotSet::KEEP_EMPTY_BUCKETS);
    }
  }
#endif
}

PagedSpace* PagedSpaceIterator::Next() {
  DCHECK_GE(counter_, FIRST_GROWABLE_PAGED_SPACE);
  while (counter_ <= LAST_GROWABLE_PAGED_SPACE) {
    PagedSpace* space = heap_->paged_space(counter_++);
    if (space) return space;
  }
  return nullptr;
}

class HeapObjectsFilter {
 public:
  virtual ~HeapObjectsFilter() = default;
  virtual bool SkipObject(Tagged<HeapObject> object) = 0;
};

class UnreachableObjectsFilter : public HeapObjectsFilter {
 public:
  explicit UnreachableObjectsFilter(Heap* heap) : heap_(heap) {
    MarkReachableObjects();
  }

  ~UnreachableObjectsFilter() override = default;

  bool SkipObject(Tagged<HeapObject> object) override {
    // Space object iterators should skip free space or filler objects.
    DCHECK(!IsFreeSpaceOrFiller(object));
    // If the bucket corresponding to the object's chunk does not exist, or the
    // object is not found in the bucket, return true.
    MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);
    if (reachable_.count(chunk) == 0) return true;
    return reachable_[chunk]->count(object) == 0;
  }

 private:
  using BucketType = std::unordered_set<Tagged<HeapObject>, Object::Hasher>;

  bool MarkAsReachable(Tagged<HeapObject> object) {
    // If the bucket corresponding to the object's chunk does not exist, then
    // create an empty bucket.
    MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);
    if (reachable_.count(chunk) == 0) {
      reachable_[chunk] = std::make_unique<BucketType>();
    }
    // Insert the object if not present; return whether it was indeed inserted.
    if (reachable_[chunk]->count(object)) return false;
    reachable_[chunk]->insert(object);
    return true;
  }

  class MarkingVisitor : public ObjectVisitorWithCageBases, public RootVisitor {
   public:
    explicit MarkingVisitor(UnreachableObjectsFilter* filter)
        : ObjectVisitorWithCageBases(filter->heap_), filter_(filter) {}

    void VisitMapPointer(Tagged<HeapObject> object) override {
      MarkHeapObject(UncheckedCast<Map>(object->map(cage_base())));
    }
    void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                       ObjectSlot end) override {
      MarkPointersImpl(start, end);
    }

    void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                       MaybeObjectSlot end) final {
      MarkPointersImpl(start, end);
    }

    void VisitInstructionStreamPointer(Tagged<Code> host,
                                       InstructionStreamSlot slot) override {
      Tagged<Object> maybe_code = slot.load(code_cage_base());
      Tagged<HeapObject> heap_object;
      if (maybe_code.GetHeapObject(&heap_object)) {
        MarkHeapObject(heap_object);
      }
    }

    void VisitCodeTarget(Tagged<InstructionStream> host,
                         RelocInfo* rinfo) final {
      Tagged<InstructionStream> target =
          InstructionStream::FromTargetAddress(rinfo->target_address());
      MarkHeapObject(target);
    }
    void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) final {
      MarkHeapObject(rinfo->target_object(cage_base()));
    }

    void VisitRootPointers(Root root, const char* description,
                           FullObjectSlot start, FullObjectSlot end) override {
      MarkPointersImpl(start, end);
    }
    void VisitRootPointers(Root root, const char* description,
                           OffHeapObjectSlot start,
                           OffHeapObjectSlot end) override {
      MarkPointersImpl(start, end);
    }

    void TransitiveClosure() {
      while (!marking_stack_.empty()) {
        Tagged<HeapObject> obj = marking_stack_.back();
        marking_stack_.pop_back();
        VisitObject(filter_->heap_->isolate(), obj, this);
      }
    }

   private:
    template <typename TSlot>
    V8_INLINE void MarkPointersImpl(TSlot start, TSlot end) {
      // Treat weak references as strong.
      for (TSlot p = start; p < end; ++p) {
        typename TSlot::TObject object = p.load(cage_base());
#ifdef V8_ENABLE_DIRECT_HANDLE
        if (object.ptr() == kTaggedNullAddress) continue;
#endif
        Tagged<HeapObject> heap_object;
        if (object.GetHeapObject(&heap_object)) {
          MarkHeapObject(heap_object);
        }
      }
    }

    V8_INLINE void MarkHeapObject(Tagged<HeapObject> heap_object) {
      if (filter_->MarkAsReachable(heap_object)) {
        marking_stack_.push_back(heap_object);
      }
    }

    UnreachableObjectsFilter* filter_;
    std::vector<Tagged<HeapObject>> marking_stack_;
  };

  friend class MarkingVisitor;

  void MarkReachableObjects() {
    MarkingVisitor visitor(this);
    heap_->stack().SetMarkerIfNeededAndCallback(
        [this, &visitor]() { heap_->IterateRoots(&visitor, {}); });
    visitor.TransitiveClosure();
  }

  Heap* heap_;
  DISALLOW_GARBAGE_COLLECTION(no_gc_)
  std::unordered_map<MemoryChunkMetadata*, std::unique_ptr<BucketType>,
                     base::hash<MemoryChunkMetadata*>>
      reachable_;
};

HeapObjectIterator::HeapObjectIterator(
    Heap* heap, HeapObjectIterator::HeapObjectsFiltering filtering)
    : HeapObjectIterator(
          heap,
          new SafepointScope(heap->isolate(),
                             kGlobalSafepointForSharedSpaceIsolate),
          filtering) {}

HeapObjectIterator::HeapObjectIterator(Heap* heap,
                                       const SafepointScope& safepoint_scope,
                                       HeapObjectsFiltering filtering)
    : HeapObjectIterator(heap, nullptr, filtering) {}

HeapObjectIterator::HeapObjectIterator(
    Heap* heap, SafepointScope* safepoint_scope_or_nullptr,
    HeapObjectsFiltering filtering)
    : heap_(heap),
      safepoint_scope_(safepoint_scope_or_nullptr),
      space_iterator_(heap_) {
  heap_->MakeHeapIterable();
  switch (filtering) {
    case kFilterUnreachable:
      filter_ = std::make_unique<UnreachableObjectsFilter>(heap_);
      break;
    default:
      break;
  }
  // Start the iteration.
  CHECK(space_iterator_.HasNext());
  object_iterator_ = space_iterator_.Next()->GetObjectIterator(heap_);
}

HeapObjectIterator::~HeapObjectIterator() = default;

Tagged<HeapObject> HeapObjectIterator::Next() {
  if (!filter_) return NextObject();

  Tagged<HeapObject> obj = NextObject();
  while (!obj.is_null() && filter_->SkipObject(obj)) obj = NextObject();
  return obj;
}

Tagged<HeapObject> HeapObjectIterator::NextObject() {
  // No iterator means we are done.
  if (!object_iterator_) return Tagged<HeapObject>();

  Tagged<HeapObject> obj = object_iterator_->Next();
  // If the current iterator has more objects we are fine.
  if (!obj.is_null()) return obj;
  // Go though the spaces looking for one that has objects.
  while (space_iterator_.HasNext()) {
    object_iterator_ = space_iterator_.Next()->GetObjectIterator(heap_);
    obj = object_iterator_->Next();
    if (!obj.is_null()) return obj;
  }
  // Done with the last space.
  object_iterator_.reset();
  return Tagged<HeapObject>();
}

void Heap::UpdateTotalGCTime(base::TimeDelta duration) {
  total_gc_time_ms_ += duration;
}

void Heap::ExternalStringTable::CleanUpYoung() {
  int last = 0;
  Isolate* isolate = heap_->isolate();
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<Object> o = young_strings_[i];
    if (IsTheHole(o, isolate)) {
      continue;
    }
    // The real external string is already in one of these vectors and was or
    // will be processed. Re-processing it will add a duplicate to the vector.
    if (IsThinString(o)) continue;
    DCHECK(IsExternalString(o));
    if (HeapLayout::InYoungGeneration(o)) {
      young_strings_[last++] = o;
    } else {
      old_strings_.push_back(o);
    }
  }
  young_strings_.resize(last);
}

void Heap::ExternalStringTable::CleanUpAll() {
  CleanUpYoung();
  int last = 0;
  Isolate* isolate = heap_->isolate();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<Object> o = old_strings_[i];
    if (IsTheHole(o, isolate)) {
      continue;
    }
    // The real external string is already in one of these vectors and was or
    // will be processed. Re-processing it will add a duplicate to the vector.
    if (IsThinString(o)) continue;
    DCHECK(IsExternalString(o));
    DCHECK(!HeapLayout::InYoungGeneration(o));
    old_strings_[last++] = o;
  }
  old_strings_.resize(last);
  if (v8_flags.verify_heap) {
    Verify();
  }
}

void Heap::ExternalStringTable::TearDown() {
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<Object> o = young_strings_[i];
    // Dont finalize thin strings.
    if (IsThinString(o)) continue;
    heap_->FinalizeExternalString(Cast<ExternalString>(o));
  }
  young_strings_.clear();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<Object> o = old_strings_[i];
    // Dont finalize thin strings.
    if (IsThinString(o)) continue;
    heap_->FinalizeExternalString(Cast<ExternalString>(o));
  }
  old_strings_.clear();
}

void Heap::RememberUnmappedPage(Address page, bool compacted) {
  // Tag the page pointer to make it findable in the dump file.
  if (compacted) {
    page ^= 0xC1EAD & (PageMetadata::kPageSize - 1);  // Cleared.
  } else {
    page ^= 0x1D1ED & (PageMetadata::kPageSize - 1);  // I died.
  }
  remembered_unmapped_pages_[remembered_unmapped_pages_index_] = page;
  remembered_unmapped_pages_index_++;
  remembered_unmapped_pages_index_ %= kRememberedUnmappedPages;
}

size_t Heap::YoungArrayBufferBytes() {
  return array_buffer_sweeper()->YoungBytes();
}

uint64_t Heap::UpdateExternalMemory(int64_t delta) {
  uint64_t amount = external_memory_.UpdateAmount(delta);
  uint64_t low_since_mark_compact = external_memory_.low_since_mark_compact();
  if (amount < low_since_mark_compact) {
    external_memory_.UpdateLowSinceMarkCompact(amount);
  }
  return amount;
}

size_t Heap::OldArrayBufferBytes() {
  return array_buffer_sweeper()->OldBytes();
}

StrongRootsEntry* Heap::RegisterStrongRoots(const char* label,
                                            FullObjectSlot start,
                                            FullObjectSlot end) {
  // We're either on the main thread, or in a background thread with an active
  // local heap.
  DCHECK(isolate()->CurrentLocalHeap()->IsRunning());

  base::MutexGuard guard(&strong_roots_mutex_);

  StrongRootsEntry* entry = new StrongRootsEntry(label);
  entry->start = start;
  entry->end = end;
  entry->prev = nullptr;
  entry->next = strong_roots_head_;

  if (strong_roots_head_) {
    DCHECK_NULL(strong_roots_head_->prev);
    strong_roots_head_->prev = entry;
  }
  strong_roots_head_ = entry;

  return entry;
}

void Heap::UpdateStrongRoots(StrongRootsEntry* entry, FullObjectSlot start,
                             FullObjectSlot end) {
  entry->start = start;
  entry->end = end;
}

void Heap::UnregisterStrongRoots(StrongRootsEntry* entry) {
  // We're either on the main thread, or in a background thread with an active
  // local heap.
  DCHECK(isolate()->CurrentLocalHeap()->IsRunning());

  base::MutexGuard guard(&strong_roots_mutex_);

  StrongRootsEntry* prev = entry->prev;
  StrongRootsEntry* next = entry->next;

  if (prev) prev->next = next;
  if (next) next->prev = prev;

  if (strong_roots_head_ == entry) {
    DCHECK_NULL(prev);
    strong_roots_head_ = next;
  }

  delete entry;
}

void Heap::
### 提示词
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
ler;
}

EmbedderRootsHandler* Heap::GetEmbedderRootsHandler() const {
  return embedder_roots_handler_;
}

void Heap::AttachCppHeap(v8::CppHeap* cpp_heap) {
  // The API function should be a noop in case a CppHeap was passed on Isolate
  // creation.
  if (owning_cpp_heap_) {
    return;
  }

  CHECK_IMPLIES(incremental_marking(), !incremental_marking()->IsMarking());
  CppHeap::From(cpp_heap)->AttachIsolate(isolate());
  cpp_heap_ = cpp_heap;
}

void Heap::DetachCppHeap() {
  // The API function should be a noop in case a CppHeap was passed on Isolate
  // creation.
  if (owning_cpp_heap_) {
    return;
  }

  CppHeap::From(cpp_heap_)->DetachIsolate();
  cpp_heap_ = nullptr;
}

std::optional<StackState> Heap::overridden_stack_state() const {
  if (!embedder_stack_state_origin_) return {};
  return embedder_stack_state_;
}

void Heap::SetStackStart() {
  // If no main thread local heap has been set up (we're still in the
  // deserialization process), we don't need to set the stack start.
  if (main_thread_local_heap_ == nullptr) return;
  stack().SetStackStart();
}

::heap::base::Stack& Heap::stack() {
  CHECK_NOT_NULL(main_thread_local_heap_);
  return main_thread_local_heap_->stack_;
}

const ::heap::base::Stack& Heap::stack() const {
  CHECK_NOT_NULL(main_thread_local_heap_);
  return main_thread_local_heap_->stack_;
}

void Heap::StartTearDown() {
  if (owning_cpp_heap_) {
    // Release the pointer. The non-owning pointer is still set which allows
    // DetachCppHeap() to work properly.
    auto* cpp_heap = owning_cpp_heap_.release();
    DetachCppHeap();
    // Termination will free up all managed C++ memory and invoke destructors.
    cpp_heap->Terminate();
  }

  // Finish any ongoing sweeping to avoid stray background tasks still accessing
  // the heap during teardown.
  CompleteSweepingFull();

  if (v8_flags.concurrent_marking) {
    concurrent_marking()->Pause();
  }

  SetGCState(TEAR_DOWN);

  // Background threads may allocate and block until GC is performed. However
  // this might never happen when the main thread tries to quit and doesn't
  // process the event queue anymore. Avoid this deadlock by allowing all
  // allocations after tear down was requested to make sure all background
  // threads finish.
  collection_barrier_->NotifyShutdownRequested();

  // Main thread isn't going to allocate anymore.
  main_thread_local_heap()->FreeLinearAllocationAreas();

  FreeMainThreadLinearAllocationAreas();
}

void Heap::TearDownWithSharedHeap() {
  DCHECK_EQ(gc_state(), TEAR_DOWN);

  // Assert that there are no background threads left and no executable memory
  // chunks are unprotected.
  safepoint()->AssertMainThreadIsOnlyThread();

  // Now that all threads are stopped, verify the heap before tearing down the
  // heap/isolate.
  HeapVerifier::VerifyHeapIfEnabled(this);

  // Might use the external pointer which might be in the shared heap.
  external_string_table_.TearDown();

  // Publish shared object worklist for the main thread if incremental marking
  // is enabled for the shared heap.
  main_thread_local_heap()->marking_barrier()->PublishSharedIfNeeded();
}

void Heap::TearDown() {
  DCHECK_EQ(gc_state(), TEAR_DOWN);

  // Assert that there are no background threads left and no executable memory
  // chunks are unprotected.
  safepoint()->AssertMainThreadIsOnlyThread();

  DCHECK(concurrent_marking()->IsStopped());

  // It's too late for Heap::Verify() here, as parts of the Isolate are
  // already gone by the time this is called.

  UpdateMaximumCommitted();

  if (v8_flags.fuzzer_gc_analysis) {
    if (v8_flags.stress_marking > 0) {
      PrintMaxMarkingLimitReached();
    }
    if (IsStressingScavenge()) {
      PrintMaxNewSpaceSizeReached();
    }
  }

  minor_gc_task_observer_.reset();
  minor_gc_job_.reset();

  if (need_to_remove_stress_concurrent_allocation_observer_) {
    RemoveAllocationObserversFromAllSpaces(
        stress_concurrent_allocation_observer_.get(),
        stress_concurrent_allocation_observer_.get());
  }
  stress_concurrent_allocation_observer_.reset();

  if (IsStressingScavenge()) {
    allocator()->new_space_allocator()->RemoveAllocationObserver(
        stress_scavenge_observer_);
    delete stress_scavenge_observer_;
    stress_scavenge_observer_ = nullptr;
  }

  if (mark_compact_collector_) {
    mark_compact_collector_->TearDown();
    mark_compact_collector_.reset();
  }

  if (minor_mark_sweep_collector_) {
    minor_mark_sweep_collector_->TearDown();
    minor_mark_sweep_collector_.reset();
  }

  sweeper_->TearDown();
  sweeper_.reset();

  scavenger_collector_.reset();
  array_buffer_sweeper_.reset();
  incremental_marking_.reset();
  concurrent_marking_.reset();

  memory_measurement_.reset();
  allocation_tracker_for_debugging_.reset();
  ephemeron_remembered_set_.reset();

  if (memory_reducer_ != nullptr) {
    memory_reducer_->TearDown();
    memory_reducer_.reset();
  }

  live_object_stats_.reset();
  dead_object_stats_.reset();

  embedder_roots_handler_ = nullptr;

  if (cpp_heap_) {
    CppHeap::From(cpp_heap_)->DetachIsolate();
    cpp_heap_ = nullptr;
  }

  tracer_.reset();

  pretenuring_handler_.reset();

  for (int i = FIRST_MUTABLE_SPACE; i <= LAST_MUTABLE_SPACE; i++) {
    space_[i].reset();
  }

  read_only_space_ = nullptr;

  memory_allocator()->TearDown();

  StrongRootsEntry* next = nullptr;
  for (StrongRootsEntry* current = strong_roots_head_; current;
       current = next) {
    next = current->next;
    delete current;
  }
  strong_roots_head_ = nullptr;

  memory_allocator_.reset();
}

// static
bool Heap::IsFreeSpaceValid(FreeSpace object) {
  Heap* heap = HeapUtils::GetOwnerHeap(object);
  Tagged<Object> free_space_map =
      heap->isolate()->root(RootIndex::kFreeSpaceMap);
  CHECK(!heap->deserialization_complete() ||
        object.map_slot().contains_map_value(free_space_map.ptr()));
  CHECK_LE(FreeSpace::kNextOffset + kTaggedSize, object.size(kRelaxedLoad));
  return true;
}

void Heap::AddGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                                 GCType gc_type, void* data) {
  gc_prologue_callbacks_.Add(
      callback, reinterpret_cast<v8::Isolate*>(isolate()), gc_type, data);
}

void Heap::RemoveGCPrologueCallback(v8::Isolate::GCCallbackWithData callback,
                                    void* data) {
  gc_prologue_callbacks_.Remove(callback, data);
}

void Heap::AddGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                                 GCType gc_type, void* data) {
  gc_epilogue_callbacks_.Add(
      callback, reinterpret_cast<v8::Isolate*>(isolate()), gc_type, data);
}

void Heap::RemoveGCEpilogueCallback(v8::Isolate::GCCallbackWithData callback,
                                    void* data) {
  gc_epilogue_callbacks_.Remove(callback, data);
}

namespace {
Handle<WeakArrayList> CompactWeakArrayList(Heap* heap,
                                           Handle<WeakArrayList> array,
                                           AllocationType allocation) {
  if (array->length() == 0) {
    return array;
  }
  int new_length = array->CountLiveWeakReferences();
  if (new_length == array->length()) {
    return array;
  }

  Handle<WeakArrayList> new_array = WeakArrayList::EnsureSpace(
      heap->isolate(),
      handle(ReadOnlyRoots(heap).empty_weak_array_list(), heap->isolate()),
      new_length, allocation);
  // Allocation might have caused GC and turned some of the elements into
  // cleared weak heap objects. Count the number of live references again and
  // fill in the new array.
  int copy_to = 0;
  for (int i = 0; i < array->length(); i++) {
    Tagged<MaybeObject> element = array->Get(i);
    if (element.IsCleared()) continue;
    new_array->Set(copy_to++, element);
  }
  new_array->set_length(copy_to);
  return new_array;
}

}  // anonymous namespace

void Heap::CompactWeakArrayLists() {
  // Find known PrototypeUsers and compact them.
  std::vector<Handle<PrototypeInfo>> prototype_infos;
  {
    HeapObjectIterator iterator(this);
    for (Tagged<HeapObject> o = iterator.Next(); !o.is_null();
         o = iterator.Next()) {
      if (IsPrototypeInfo(*o)) {
        Tagged<PrototypeInfo> prototype_info = Cast<PrototypeInfo>(o);
        if (IsWeakArrayList(prototype_info->prototype_users())) {
          prototype_infos.emplace_back(handle(prototype_info, isolate()));
        }
      }
    }
  }
  for (auto& prototype_info : prototype_infos) {
    DirectHandle<WeakArrayList> array(
        Cast<WeakArrayList>(prototype_info->prototype_users()), isolate());
    DCHECK(InOldSpace(*array) ||
           *array == ReadOnlyRoots(this).empty_weak_array_list());
    Tagged<WeakArrayList> new_array = PrototypeUsers::Compact(
        array, this, JSObject::PrototypeRegistryCompactionCallback,
        AllocationType::kOld);
    prototype_info->set_prototype_users(new_array);
  }

  // Find known WeakArrayLists and compact them.
  Handle<WeakArrayList> scripts(script_list(), isolate());
  DCHECK(InOldSpace(*scripts));
  scripts = CompactWeakArrayList(this, scripts, AllocationType::kOld);
  set_script_list(*scripts);
}

void Heap::AddRetainedMaps(DirectHandle<NativeContext> context,
                           GlobalHandleVector<Map> maps) {
  Handle<WeakArrayList> array(Cast<WeakArrayList>(context->retained_maps()),
                              isolate());
  if (array->IsFull()) {
    CompactRetainedMaps(*array);
  }
  int cur_length = array->length();
  array = WeakArrayList::EnsureSpace(
      isolate(), array, cur_length + static_cast<int>(maps.size()) * 2);
  if (*array != context->retained_maps()) {
    context->set_retained_maps(*array);
  }

  {
    DisallowGarbageCollection no_gc;
    Tagged<WeakArrayList> raw_array = *array;
    for (DirectHandle<Map> map : maps) {
      DCHECK(!HeapLayout::InAnySharedSpace(*map));

      if (map->is_in_retained_map_list()) {
        continue;
      }

      raw_array->Set(cur_length, MakeWeak(*map));
      raw_array->Set(cur_length + 1,
                     Smi::FromInt(v8_flags.retain_maps_for_n_gc));
      cur_length += 2;
      raw_array->set_length(cur_length);

      map->set_is_in_retained_map_list(true);
    }
  }
}

void Heap::CompactRetainedMaps(Tagged<WeakArrayList> retained_maps) {
  int length = retained_maps->length();
  int new_length = 0;
  // This loop compacts the array by removing cleared weak cells.
  for (int i = 0; i < length; i += 2) {
    Tagged<MaybeObject> maybe_object = retained_maps->Get(i);
    if (maybe_object.IsCleared()) {
      continue;
    }

    DCHECK(maybe_object.IsWeak());

    Tagged<MaybeObject> age = retained_maps->Get(i + 1);
    DCHECK(IsSmi(age));
    if (i != new_length) {
      retained_maps->Set(new_length, maybe_object);
      retained_maps->Set(new_length + 1, age);
    }
    new_length += 2;
  }
  Tagged<HeapObject> undefined = ReadOnlyRoots(this).undefined_value();
  for (int i = new_length; i < length; i++) {
    retained_maps->Set(i, undefined);
  }
  if (new_length != length) retained_maps->set_length(new_length);
}

void Heap::FatalProcessOutOfMemory(const char* location) {
  V8::FatalProcessOutOfMemory(isolate(), location, V8::kHeapOOM);
}

#ifdef DEBUG

class PrintHandleVisitor : public RootVisitor {
 public:
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p)
      PrintF("  handle %p to %p\n", p.ToVoidPtr(),
             reinterpret_cast<void*>((*p).ptr()));
  }
};

void Heap::PrintHandles() {
  PrintF("Handles:\n");
  PrintHandleVisitor v;
  isolate_->handle_scope_implementer()->Iterate(&v);
}

#endif

class CheckHandleCountVisitor : public RootVisitor {
 public:
  CheckHandleCountVisitor() : handle_count_(0) {}
  ~CheckHandleCountVisitor() override {
    CHECK_GT(HandleScope::kCheckHandleThreshold, handle_count_);
  }
  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    handle_count_ += end - start;
  }

 private:
  ptrdiff_t handle_count_;
};

void Heap::CheckHandleCount() {
  CheckHandleCountVisitor v;
  isolate_->handle_scope_implementer()->Iterate(&v);
}

// static
int Heap::InsertIntoRememberedSetFromCode(MutablePageMetadata* chunk,
                                          size_t slot_offset) {
  // This is called during runtime by a builtin, therefore it is run in the main
  // thread.
  DCHECK_NULL(LocalHeap::Current());
  RememberedSet<OLD_TO_NEW>::Insert<AccessMode::NON_ATOMIC>(chunk, slot_offset);
  return 0;
}

#ifdef DEBUG
void Heap::VerifySlotRangeHasNoRecordedSlots(Address start, Address end) {
#ifndef V8_DISABLE_WRITE_BARRIERS
  PageMetadata* page = PageMetadata::FromAddress(start);
  RememberedSet<OLD_TO_NEW>::CheckNoneInRange(page, start, end);
  RememberedSet<OLD_TO_NEW_BACKGROUND>::CheckNoneInRange(page, start, end);
  RememberedSet<OLD_TO_SHARED>::CheckNoneInRange(page, start, end);
#endif
}
#endif

void Heap::ClearRecordedSlotRange(Address start, Address end) {
#ifndef V8_DISABLE_WRITE_BARRIERS
  MemoryChunk* chunk = MemoryChunk::FromAddress(start);
  DCHECK(!chunk->IsLargePage());
#if !V8_ENABLE_STICKY_MARK_BITS_BOOL
  if (!chunk->InYoungGeneration())
#endif
  {
    PageMetadata* page = PageMetadata::cast(chunk->Metadata());
    // This method will be invoked on objects in shared space for
    // internalization and string forwarding during GC.
    DCHECK(page->owner_identity() == OLD_SPACE ||
           page->owner_identity() == TRUSTED_SPACE ||
           page->owner_identity() == SHARED_SPACE);

    if (!page->SweepingDone()) {
      RememberedSet<OLD_TO_NEW>::RemoveRange(page, start, end,
                                             SlotSet::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_NEW_BACKGROUND>::RemoveRange(
          page, start, end, SlotSet::KEEP_EMPTY_BUCKETS);
      RememberedSet<OLD_TO_SHARED>::RemoveRange(page, start, end,
                                                SlotSet::KEEP_EMPTY_BUCKETS);
    }
  }
#endif
}

PagedSpace* PagedSpaceIterator::Next() {
  DCHECK_GE(counter_, FIRST_GROWABLE_PAGED_SPACE);
  while (counter_ <= LAST_GROWABLE_PAGED_SPACE) {
    PagedSpace* space = heap_->paged_space(counter_++);
    if (space) return space;
  }
  return nullptr;
}

class HeapObjectsFilter {
 public:
  virtual ~HeapObjectsFilter() = default;
  virtual bool SkipObject(Tagged<HeapObject> object) = 0;
};

class UnreachableObjectsFilter : public HeapObjectsFilter {
 public:
  explicit UnreachableObjectsFilter(Heap* heap) : heap_(heap) {
    MarkReachableObjects();
  }

  ~UnreachableObjectsFilter() override = default;

  bool SkipObject(Tagged<HeapObject> object) override {
    // Space object iterators should skip free space or filler objects.
    DCHECK(!IsFreeSpaceOrFiller(object));
    // If the bucket corresponding to the object's chunk does not exist, or the
    // object is not found in the bucket, return true.
    MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);
    if (reachable_.count(chunk) == 0) return true;
    return reachable_[chunk]->count(object) == 0;
  }

 private:
  using BucketType = std::unordered_set<Tagged<HeapObject>, Object::Hasher>;

  bool MarkAsReachable(Tagged<HeapObject> object) {
    // If the bucket corresponding to the object's chunk does not exist, then
    // create an empty bucket.
    MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);
    if (reachable_.count(chunk) == 0) {
      reachable_[chunk] = std::make_unique<BucketType>();
    }
    // Insert the object if not present; return whether it was indeed inserted.
    if (reachable_[chunk]->count(object)) return false;
    reachable_[chunk]->insert(object);
    return true;
  }

  class MarkingVisitor : public ObjectVisitorWithCageBases, public RootVisitor {
   public:
    explicit MarkingVisitor(UnreachableObjectsFilter* filter)
        : ObjectVisitorWithCageBases(filter->heap_), filter_(filter) {}

    void VisitMapPointer(Tagged<HeapObject> object) override {
      MarkHeapObject(UncheckedCast<Map>(object->map(cage_base())));
    }
    void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                       ObjectSlot end) override {
      MarkPointersImpl(start, end);
    }

    void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                       MaybeObjectSlot end) final {
      MarkPointersImpl(start, end);
    }

    void VisitInstructionStreamPointer(Tagged<Code> host,
                                       InstructionStreamSlot slot) override {
      Tagged<Object> maybe_code = slot.load(code_cage_base());
      Tagged<HeapObject> heap_object;
      if (maybe_code.GetHeapObject(&heap_object)) {
        MarkHeapObject(heap_object);
      }
    }

    void VisitCodeTarget(Tagged<InstructionStream> host,
                         RelocInfo* rinfo) final {
      Tagged<InstructionStream> target =
          InstructionStream::FromTargetAddress(rinfo->target_address());
      MarkHeapObject(target);
    }
    void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                              RelocInfo* rinfo) final {
      MarkHeapObject(rinfo->target_object(cage_base()));
    }

    void VisitRootPointers(Root root, const char* description,
                           FullObjectSlot start, FullObjectSlot end) override {
      MarkPointersImpl(start, end);
    }
    void VisitRootPointers(Root root, const char* description,
                           OffHeapObjectSlot start,
                           OffHeapObjectSlot end) override {
      MarkPointersImpl(start, end);
    }

    void TransitiveClosure() {
      while (!marking_stack_.empty()) {
        Tagged<HeapObject> obj = marking_stack_.back();
        marking_stack_.pop_back();
        VisitObject(filter_->heap_->isolate(), obj, this);
      }
    }

   private:
    template <typename TSlot>
    V8_INLINE void MarkPointersImpl(TSlot start, TSlot end) {
      // Treat weak references as strong.
      for (TSlot p = start; p < end; ++p) {
        typename TSlot::TObject object = p.load(cage_base());
#ifdef V8_ENABLE_DIRECT_HANDLE
        if (object.ptr() == kTaggedNullAddress) continue;
#endif
        Tagged<HeapObject> heap_object;
        if (object.GetHeapObject(&heap_object)) {
          MarkHeapObject(heap_object);
        }
      }
    }

    V8_INLINE void MarkHeapObject(Tagged<HeapObject> heap_object) {
      if (filter_->MarkAsReachable(heap_object)) {
        marking_stack_.push_back(heap_object);
      }
    }

    UnreachableObjectsFilter* filter_;
    std::vector<Tagged<HeapObject>> marking_stack_;
  };

  friend class MarkingVisitor;

  void MarkReachableObjects() {
    MarkingVisitor visitor(this);
    heap_->stack().SetMarkerIfNeededAndCallback(
        [this, &visitor]() { heap_->IterateRoots(&visitor, {}); });
    visitor.TransitiveClosure();
  }

  Heap* heap_;
  DISALLOW_GARBAGE_COLLECTION(no_gc_)
  std::unordered_map<MemoryChunkMetadata*, std::unique_ptr<BucketType>,
                     base::hash<MemoryChunkMetadata*>>
      reachable_;
};

HeapObjectIterator::HeapObjectIterator(
    Heap* heap, HeapObjectIterator::HeapObjectsFiltering filtering)
    : HeapObjectIterator(
          heap,
          new SafepointScope(heap->isolate(),
                             kGlobalSafepointForSharedSpaceIsolate),
          filtering) {}

HeapObjectIterator::HeapObjectIterator(Heap* heap,
                                       const SafepointScope& safepoint_scope,
                                       HeapObjectsFiltering filtering)
    : HeapObjectIterator(heap, nullptr, filtering) {}

HeapObjectIterator::HeapObjectIterator(
    Heap* heap, SafepointScope* safepoint_scope_or_nullptr,
    HeapObjectsFiltering filtering)
    : heap_(heap),
      safepoint_scope_(safepoint_scope_or_nullptr),
      space_iterator_(heap_) {
  heap_->MakeHeapIterable();
  switch (filtering) {
    case kFilterUnreachable:
      filter_ = std::make_unique<UnreachableObjectsFilter>(heap_);
      break;
    default:
      break;
  }
  // Start the iteration.
  CHECK(space_iterator_.HasNext());
  object_iterator_ = space_iterator_.Next()->GetObjectIterator(heap_);
}

HeapObjectIterator::~HeapObjectIterator() = default;

Tagged<HeapObject> HeapObjectIterator::Next() {
  if (!filter_) return NextObject();

  Tagged<HeapObject> obj = NextObject();
  while (!obj.is_null() && filter_->SkipObject(obj)) obj = NextObject();
  return obj;
}

Tagged<HeapObject> HeapObjectIterator::NextObject() {
  // No iterator means we are done.
  if (!object_iterator_) return Tagged<HeapObject>();

  Tagged<HeapObject> obj = object_iterator_->Next();
  // If the current iterator has more objects we are fine.
  if (!obj.is_null()) return obj;
  // Go though the spaces looking for one that has objects.
  while (space_iterator_.HasNext()) {
    object_iterator_ = space_iterator_.Next()->GetObjectIterator(heap_);
    obj = object_iterator_->Next();
    if (!obj.is_null()) return obj;
  }
  // Done with the last space.
  object_iterator_.reset();
  return Tagged<HeapObject>();
}

void Heap::UpdateTotalGCTime(base::TimeDelta duration) {
  total_gc_time_ms_ += duration;
}

void Heap::ExternalStringTable::CleanUpYoung() {
  int last = 0;
  Isolate* isolate = heap_->isolate();
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<Object> o = young_strings_[i];
    if (IsTheHole(o, isolate)) {
      continue;
    }
    // The real external string is already in one of these vectors and was or
    // will be processed. Re-processing it will add a duplicate to the vector.
    if (IsThinString(o)) continue;
    DCHECK(IsExternalString(o));
    if (HeapLayout::InYoungGeneration(o)) {
      young_strings_[last++] = o;
    } else {
      old_strings_.push_back(o);
    }
  }
  young_strings_.resize(last);
}

void Heap::ExternalStringTable::CleanUpAll() {
  CleanUpYoung();
  int last = 0;
  Isolate* isolate = heap_->isolate();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<Object> o = old_strings_[i];
    if (IsTheHole(o, isolate)) {
      continue;
    }
    // The real external string is already in one of these vectors and was or
    // will be processed. Re-processing it will add a duplicate to the vector.
    if (IsThinString(o)) continue;
    DCHECK(IsExternalString(o));
    DCHECK(!HeapLayout::InYoungGeneration(o));
    old_strings_[last++] = o;
  }
  old_strings_.resize(last);
  if (v8_flags.verify_heap) {
    Verify();
  }
}

void Heap::ExternalStringTable::TearDown() {
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<Object> o = young_strings_[i];
    // Dont finalize thin strings.
    if (IsThinString(o)) continue;
    heap_->FinalizeExternalString(Cast<ExternalString>(o));
  }
  young_strings_.clear();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<Object> o = old_strings_[i];
    // Dont finalize thin strings.
    if (IsThinString(o)) continue;
    heap_->FinalizeExternalString(Cast<ExternalString>(o));
  }
  old_strings_.clear();
}

void Heap::RememberUnmappedPage(Address page, bool compacted) {
  // Tag the page pointer to make it findable in the dump file.
  if (compacted) {
    page ^= 0xC1EAD & (PageMetadata::kPageSize - 1);  // Cleared.
  } else {
    page ^= 0x1D1ED & (PageMetadata::kPageSize - 1);  // I died.
  }
  remembered_unmapped_pages_[remembered_unmapped_pages_index_] = page;
  remembered_unmapped_pages_index_++;
  remembered_unmapped_pages_index_ %= kRememberedUnmappedPages;
}

size_t Heap::YoungArrayBufferBytes() {
  return array_buffer_sweeper()->YoungBytes();
}

uint64_t Heap::UpdateExternalMemory(int64_t delta) {
  uint64_t amount = external_memory_.UpdateAmount(delta);
  uint64_t low_since_mark_compact = external_memory_.low_since_mark_compact();
  if (amount < low_since_mark_compact) {
    external_memory_.UpdateLowSinceMarkCompact(amount);
  }
  return amount;
}

size_t Heap::OldArrayBufferBytes() {
  return array_buffer_sweeper()->OldBytes();
}

StrongRootsEntry* Heap::RegisterStrongRoots(const char* label,
                                            FullObjectSlot start,
                                            FullObjectSlot end) {
  // We're either on the main thread, or in a background thread with an active
  // local heap.
  DCHECK(isolate()->CurrentLocalHeap()->IsRunning());

  base::MutexGuard guard(&strong_roots_mutex_);

  StrongRootsEntry* entry = new StrongRootsEntry(label);
  entry->start = start;
  entry->end = end;
  entry->prev = nullptr;
  entry->next = strong_roots_head_;

  if (strong_roots_head_) {
    DCHECK_NULL(strong_roots_head_->prev);
    strong_roots_head_->prev = entry;
  }
  strong_roots_head_ = entry;

  return entry;
}

void Heap::UpdateStrongRoots(StrongRootsEntry* entry, FullObjectSlot start,
                             FullObjectSlot end) {
  entry->start = start;
  entry->end = end;
}

void Heap::UnregisterStrongRoots(StrongRootsEntry* entry) {
  // We're either on the main thread, or in a background thread with an active
  // local heap.
  DCHECK(isolate()->CurrentLocalHeap()->IsRunning());

  base::MutexGuard guard(&strong_roots_mutex_);

  StrongRootsEntry* prev = entry->prev;
  StrongRootsEntry* next = entry->next;

  if (prev) prev->next = next;
  if (next) next->prev = prev;

  if (strong_roots_head_ == entry) {
    DCHECK_NULL(prev);
    strong_roots_head_ = next;
  }

  delete entry;
}

void Heap::SetBuiltinsConstantsTable(Tagged<FixedArray> cache) {
  set_builtins_constants_table(cache);
}

void Heap::SetDetachedContexts(Tagged<WeakArrayList> detached_contexts) {
  set_detached_contexts(detached_contexts);
}

bool Heap::HasDirtyJSFinalizationRegistries() {
  return !IsUndefined(dirty_js_finalization_registries_list(), isolate());
}

void Heap::PostFinalizationRegistryCleanupTaskIfNeeded() {
  // Only one cleanup task is posted at a time.
  if (!HasDirtyJSFinalizationRegistries() ||
      is_finalization_registry_cleanup_task_posted_) {
    return;
  }
  auto task = std::make_unique<FinalizationRegistryCleanupTask>(this);
  task_runner_->PostNonNestableTask(std::move(task));
  is_finalization_registry_cleanup_task_posted_ = true;
}

void Heap::EnqueueDirtyJSFinalizationRegistry(
    Tagged<JSFinalizationRegistry> finalization_registry,
    std::function<void(Tagged<HeapObject> object, ObjectSlot slot,
                       Tagged<Object> target)>
        gc_notify_updated_slot) {
  // Add a FinalizationRegistry to the tail of the dirty list.
  DCHECK(!HasDirtyJSFinalizationRegistries() ||
         IsJSFinalizationRegistry(dirty_js_finalization_registries_list()));
  DCHECK(IsUndefined(finalization_registry->next_dirty(), isolate()));
  DCHECK(!finalization_registry->scheduled_for_cleanup());
  finalization_registry->set_scheduled_for_cleanup(true);
  if (IsUndefined(dirty_js_finalization_registries_list_tail(), isolate())) {
    DCHECK(IsUndefined(dirty_js_finalization_registries_list(), isolate()));
    set_dirty_js_finalization_registries_list(finalization_registry);
    // dirty_js_finalization_registries_list_ is rescanned by
    // ProcessWeakListRoots.
  } else {
    Tagged<JSFinalizationRegistry> tail = Cast<JSFinalizationRegistry>(
        dirty_js_finalization_registries_list_tail());
    tail->set_next_dirty(finalization_registry);
    gc_notify_updated_slot(
        tail, tail->RawField(JSFinalizationRegistry::kNextDirtyOffset),
        finalization_registry);
  }
  set_dirty_js_finalization_registries_list_tail(finalization_registry);
  // dirty_js_finalization_registries_list_tail_ is rescanned by
  // ProcessWeakListRoots.
}

MaybeHandle<JSFinalizationRegistry> Heap::DequeueDirtyJSFinalizationRegistry() {
  // Take a FinalizationRegistry from the head of the dirty list for fairness.
  if (HasDirtyJSFinalizationRegistries()) {
    Handle<JSFinalizationRegistry> head(
        Cast<JSFinalizationRegistry>(dirty_js_finalization_registries_list()),
        isolate());
    set_dirty_js_finalization_registries_list(head->next_dirty());
    head->set_next_dirty(ReadOnlyRoots(this).undefined_value());
    if (*head == dirty_js_finalization_registries_list_tail()) {
      set_dirty_js_finalization_registries_list_tail(
          ReadOnlyRoots(this).undefined_value());
    }
    return head;
  }
  return {};
}

void Heap::RemoveDirtyFinalizationRegistriesOnContext(
    Tagged<NativeContext> context) {
  DisallowGarbageCollection no_gc;

  Isolate* isolate = this->isolate();
  Tagged<Object> prev = ReadOnlyRoots(isolate).undefined_value();
  Tagged<Object> current = dirty_js_finalization_registries_list();
  while (!IsUndefined(current, isolate)) {
    Tagged<JSFinalizationRegistry> finalization_registry =
        Cast<JSFinalizationRegistry>(current);
    if (finalization_registry->native_context() == context) {
      if (IsUndefined(prev, isolate)) {
        set_dirty_js_finalization_registries_list(
            finalization_registry->next_dirty());
      } else {
        Cast<JSFinalizationRegistry>(prev)->set_next_dirty(
            finalization_registry->next_dirty());
      }
      finalization_registry->set_scheduled_for_cleanup(false);
      current = finalization_registry->next_dirty();
      finalization_registry->set_next_dirty(
          ReadOnlyRoots(isolate).undefined_value());
    } else {
      prev = current;
      current = finalization_registry->next_dirty();
    }
  }
  set_dirty_js_finalization_registries_list_tail(prev);
}

void Heap::KeepDuringJob(DirectHandle<HeapObject> target) {
  DCHECK(IsUndefined(weak_refs_keep_during_job()) ||
         IsOrderedHashSet(weak_refs_keep_during_job()));
  Handle<OrderedHashSet> table;
  if (IsUndefined(weak_refs_keep_during_job(), isolate())) {
    table = isolate()->factory()->NewOrderedHashSet();
  } else {
    table =
        handle(Cast<OrderedHashSet>(weak_refs_keep_during_job()), isolate());
  }
  MaybeHandle<OrderedHashSet> maybe_table =
      OrderedHashSet::Add(isolate(), table, target);
  if (!maybe_table.ToHandle(&table)) {
    FATAL(
        "Fatal JavaScript error: Too many distinct WeakRef objects "
        "created or dereferenced during single event loop turn.");
  }
  set_weak_refs_keep_during_job(*table);
}

void Heap::ClearKeptObjects() {
  set_weak_refs_keep_during_job(ReadOnlyRoots(isolate()).undefined_value());
}

size_t Heap::NumberOfTrackedHeapObjectTypes() {
  return ObjectStats::OBJECT_STATS_COUNT;
}

size_t Heap::ObjectCountAtLastGC(size_t index) {
  if (live_object_stats_ == nullptr || index >= ObjectStats::OBJECT_STATS_COUNT)
    return 0;
  return live_object_stats_->object_count_last_gc(index);
}

size_t Heap::ObjectSizeAtLastGC(size_t index) {
  if (live_object_stats_ == nullptr || index >= ObjectStats::OBJECT_STATS_COUNT)
    return 0;
  return live_object_stats_->object_size_last_gc(index);
}

bool Heap::GetObjectTypeName(size_t index, const char** object_type,
                             const char** object_sub_type) {
  if (index >= ObjectStats::OBJECT_STATS_COUNT) return false;

  switch (static_cast<int>(index)) {
#define COMPARE_AND_RETURN_NAME(name) \
  case name:                          \
    *object_type = #name;             \
    *object_sub_type = "";            \
    return true;
    INSTANCE_TYPE_LIST(COMPARE_AND_RETURN_NAME)
#undef COMPARE_AND_RETURN_NAME

#define COMPARE_AND_RETURN_NAME(name)                       \
  case ObjectStats::FIRST_VIRTUAL_TYPE + ObjectStats::name: \
    *object_type = #name;                                   \
    *object_sub_type = "";                                  \
    return true;
    VIRTUAL_INSTANCE_TYPE_LIST(COMPARE_AND_RETURN_NAME)
#undef COMPARE_AND_RETURN_NAME
  }
  return false;
}

size_t Heap::NumberOfNativeContexts() {
  int result = 0;
  Tagged<Object> context = native_contexts_list();
  while (!IsUndefined(context, isolate())) {
    ++result;
    Tagged<Context> native_context = Cast<Context>(context);
    context = native_context->next_context_link();
  }
  return result;
}

std::vector<Handle<NativeContext>> Heap::FindAllNativeContexts() {
  std::vector<Handle<NativeContext>> result;
  Tagged<Object> context = native_contexts_list();
  while (!IsUndefined(context, isolate())) {
    Tagged<NativeContext> native_context = Cast<NativeContext>(context);
    result.push_back(handle(native_context, isolate()));
    context = native_context->next_context_link();
  }
  return result;
}

std::vector<Tagged<WeakArrayList>> Heap::FindAllRetainedMaps() {
  std::vector<Tagged<WeakArrayList>> result;
  Tagged<Object> context = native_contexts_list();
  while (!IsUndefined(context, isolate())) {
    Tagged<NativeContext> native_context = Cast<NativeC
```