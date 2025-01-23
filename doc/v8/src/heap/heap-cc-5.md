Response:
The user wants a summary of the provided C++ code snippet from `v8/src/heap/heap.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The code deals with managing the V8 heap. Keywords like `Heap`, `Space`, `Allocate`, `Contains`, `Iterate`, `Garbage Collection`, and `Statistics` stand out.

2. **Group Related Functions:** Observe how the functions are structured and what they operate on. Notice groups of functions related to:
    * Collecting code statistics.
    * Checking if the heap contains certain objects.
    * Determining if an object belongs to a specific memory space.
    * Verifying internal state (counters, memory).
    * Iterating over different parts of the heap for garbage collection (roots).
    * Configuring the heap.
    * Recording heap statistics.

3. **Explain Key Concepts:**  Define important terms like "heap," "memory spaces" (new space, old space, code space, etc.), and their purpose.

4. **Address Specific Instructions:**
    * **`.tq` extension:** Explain that this code is C++ and `.tq` indicates Torque code (though this snippet isn't Torque).
    * **JavaScript relation:**  Illustrate how the heap relates to JavaScript object creation and memory management using simple examples.
    * **Code Logic/Input-Output:** Focus on the `Contains` functions as they have clear input (a `HeapObject`) and output (a boolean). Create a simple scenario.
    * **Common Programming Errors:** Relate heap management to memory leaks and dangling pointers in JavaScript.
    * **Part 6 of 9:** Acknowledge this context.

5. **Synthesize the Summary:**  Combine the grouped functionalities and key concepts into a concise overview of the code's purpose.

6. **Refine and Organize:** Ensure the explanation is clear, well-structured, and addresses all aspects of the prompt. Use bullet points or headings to improve readability. Double-check for accuracy.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus on individual function descriptions. **Correction:**  A higher-level functional summary is more useful given the context.
* **Considering `.tq`:**  The prompt mentions `.tq`. While this snippet isn't Torque, I need to explain what `.tq` files are in the V8 context to be comprehensive.
* **JavaScript example:** Keep the JavaScript example simple and directly related to the heap's role in object allocation.
* **Input/Output:** The `Contains` functions are the most straightforward for demonstrating input and output.
* **Error Example:** Focus on common, easily understandable memory-related errors in JavaScript, even if the C++ code doesn't directly prevent them. It shows the *impact* of the heap's management.
* **Conciseness:** Avoid overly technical jargon where possible and aim for a clear, understandable summary.

By following these steps, the comprehensive and accurate response can be generated.
```cpp
pIterable();
  CodeStatistics::ResetCodeAndMetadataStatistics(isolate());
  // We do not look for code in new space, or map space. If code
  // somehow ends up in those spaces, we would miss it here.
  CodeStatistics::CollectCodeStatistics(code_space_, isolate());
  CodeStatistics::CollectCodeStatistics(old_space_, isolate());
  CodeStatistics::CollectCodeStatistics(code_lo_space_, isolate());
  CodeStatistics::CollectCodeStatistics(trusted_space_, isolate());
  CodeStatistics::CollectCodeStatistics(trusted_lo_space_, isolate());
}

#ifdef DEBUG

void Heap::Print() {
  if (!HasBeenSetUp()) return;
  isolate()->PrintStack(stdout);

  for (SpaceIterator it(this); it.HasNext();) {
    it.Next()->Print();
  }
}

void Heap::ReportCodeStatistics(const char* title) {
  PrintF("###### Code Stats (%s) ######\n", title);
  CollectCodeStatistics();
  CodeStatistics::ReportCodeStatistics(isolate());
}

#endif  // DEBUG

bool Heap::Contains(Tagged<HeapObject> value) const {
  if (ReadOnlyHeap::Contains(value)) {
    return false;
  }
  if (memory_allocator()->IsOutsideAllocatedSpace(value.address())) {
    return false;
  }

  if (!HasBeenSetUp()) return false;

  return (new_space_ && new_space_->Contains(value)) ||
         old_space_->Contains(value) || code_space_->Contains(value) ||
         (shared_space_ && shared_space_->Contains(value)) ||
         (shared_trusted_space_ && shared_trusted_space_->Contains(value)) ||
         lo_space_->Contains(value) || code_lo_space_->Contains(value) ||
         (new_lo_space_ && new_lo_space_->Contains(value)) ||
         trusted_space_->Contains(value) ||
         trusted_lo_space_->Contains(value) ||
         (shared_lo_space_ && shared_lo_space_->Contains(value)) ||
         (shared_trusted_lo_space_ &&
          shared_trusted_lo_space_->Contains(value));
}

bool Heap::ContainsCode(Tagged<HeapObject> value) const {
  // TODO(v8:11880): support external code space.
  if (memory_allocator()->IsOutsideAllocatedSpace(value.address(),
                                                  EXECUTABLE)) {
    return false;
  }
  return HasBeenSetUp() &&
         (code_space_->Contains(value) || code_lo_space_->Contains(value));
}

bool Heap::SharedHeapContains(Tagged<HeapObject> value) const {
  if (shared_allocation_space_) {
    if (shared_allocation_space_->Contains(value)) return true;
    if (shared_lo_allocation_space_->Contains(value)) return true;
    if (shared_trusted_allocation_space_->Contains(value)) return true;
    if (shared_trusted_lo_allocation_space_->Contains(value)) return true;
  }

  return false;
}

bool Heap::MustBeInSharedOldSpace(Tagged<HeapObject> value) {
  if (isolate()->OwnsStringTables()) return false;
  if (ReadOnlyHeap::Contains(value)) return false;
  if (HeapLayout::InYoungGeneration(value)) return false;
  if (IsExternalString(value)) return false;
  if (IsInternalizedString(value)) return true;
  return false;
}

bool Heap::InSpace(Tagged<HeapObject> value, AllocationSpace space) const {
  if (memory_allocator()->IsOutsideAllocatedSpace(
          value.address(),
          IsAnyCodeSpace(space) ? EXECUTABLE : NOT_EXECUTABLE)) {
    return false;
  }
  if (!HasBeenSetUp()) return false;

  switch (space) {
    case NEW_SPACE:
      return new_space_->Contains(value);
    case OLD_SPACE:
      return old_space_->Contains(value);
    case CODE_SPACE:
      return code_space_->Contains(value);
    case SHARED_SPACE:
      return shared_space_->Contains(value);
    case TRUSTED_SPACE:
      return trusted_space_->Contains(value);
    case SHARED_TRUSTED_SPACE:
      return shared_trusted_space_->Contains(value);
    case LO_SPACE:
      return lo_space_->Contains(value);
    case CODE_LO_SPACE:
      return code_lo_space_->Contains(value);
    case NEW_LO_SPACE:
      return new_lo_space_->Contains(value);
    case SHARED_LO_SPACE:
      return shared_lo_space_->Contains(value);
    case SHARED_TRUSTED_LO_SPACE:
      return shared_trusted_lo_space_->Contains(value);
    case TRUSTED_LO_SPACE:
      return trusted_lo_space_->Contains(value);
    case RO_SPACE:
      return ReadOnlyHeap::Contains(value);
  }
  UNREACHABLE();
}

bool Heap::InSpaceSlow(Address addr, AllocationSpace space) const {
  if (memory_allocator()->IsOutsideAllocatedSpace(
          addr, IsAnyCodeSpace(space) ? EXECUTABLE : NOT_EXECUTABLE)) {
    return false;
  }
  if (!HasBeenSetUp()) return false;

  switch (space) {
    case NEW_SPACE:
      return new_space_->ContainsSlow(addr);
    case OLD_SPACE:
      return old_space_->ContainsSlow(addr);
    case CODE_SPACE:
      return code_space_->ContainsSlow(addr);
    case SHARED_SPACE:
      return shared_space_->ContainsSlow(addr);
    case TRUSTED_SPACE:
      return trusted_space_->ContainsSlow(addr);
    case SHARED_TRUSTED_SPACE:
      return shared_trusted_space_->ContainsSlow(addr);
    case LO_SPACE:
      return lo_space_->ContainsSlow(addr);
    case CODE_LO_SPACE:
      return code_lo_space_->ContainsSlow(addr);
    case NEW_LO_SPACE:
      return new_lo_space_->ContainsSlow(addr);
    case SHARED_LO_SPACE:
      return shared_lo_space_->ContainsSlow(addr);
    case SHARED_TRUSTED_LO_SPACE:
      return shared_trusted_lo_space_->ContainsSlow(addr);
    case TRUSTED_LO_SPACE:
      return trusted_lo_space_->ContainsSlow(addr);
    case RO_SPACE:
      return read_only_space_->ContainsSlow(addr);
  }
  UNREACHABLE();
}

bool Heap::IsValidAllocationSpace(AllocationSpace space) {
  switch (space) {
    case NEW_SPACE:
    case OLD_SPACE:
    case CODE_SPACE:
    case SHARED_SPACE:
    case LO_SPACE:
    case NEW_LO_SPACE:
    case CODE_LO_SPACE:
    case SHARED_LO_SPACE:
    case TRUSTED_SPACE:
    case SHARED_TRUSTED_SPACE:
    case TRUSTED_LO_SPACE:
    case SHARED_TRUSTED_LO_SPACE:
    case RO_SPACE:
      return true;
    default:
      return false;
  }
}

#ifdef DEBUG
void Heap::VerifyCountersAfterSweeping() {
  MakeHeapIterable();
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    space->VerifyCountersAfterSweeping(this);
  }
}

void Heap::VerifyCountersBeforeConcurrentSweeping(GarbageCollector collector) {
  if (v8_flags.minor_ms && new_space()) {
    PagedSpaceBase* space = paged_new_space()->paged_space();
    space->RefillFreeList();
    space->VerifyCountersBeforeConcurrentSweeping();
  }
  if (collector != GarbageCollector::MARK_COMPACTOR) return;
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    // We need to refine the counters on pages that are already swept and have
    // not been moved over to the actual space. Otherwise, the AccountingStats
    // are just an over approximation.
    space->RefillFreeList();
    space->VerifyCountersBeforeConcurrentSweeping();
  }
}

void Heap::VerifyCommittedPhysicalMemory() {
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    space->VerifyCommittedPhysicalMemory();
  }
  if (v8_flags.minor_ms && new_space()) {
    paged_new_space()->paged_space()->VerifyCommittedPhysicalMemory();
  }
}
#endif  // DEBUG

void Heap::IterateWeakRoots(RootVisitor* v, base::EnumSet<SkipRoot> options) {
  DCHECK(!options.contains(SkipRoot::kWeak));

  if (!options.contains(SkipRoot::kUnserializable)) {
    // Isolate::topmost_script_having_context_address is treated weakly.
    v->VisitRootPointer(
        Root::kWeakRoots, nullptr,
        FullObjectSlot(isolate()->topmost_script_having_context_address()));
  }

  if (!options.contains(SkipRoot::kOldGeneration) &&
      !options.contains(SkipRoot::kUnserializable) &&
      isolate()->OwnsStringTables()) {
    // Do not visit for the following reasons.
    // - Serialization, since the string table is custom serialized.
    // - If we are skipping old generation, since all internalized strings
    //   are in old space.
    // - If the string table is shared and this is not the shared heap,
    //   since all internalized strings are in the shared heap.
    isolate()->string_table()->IterateElements(v);
  }
  v->Synchronize(VisitorSynchronization::kStringTable);
  if (!options.contains(SkipRoot::kExternalStringTable) &&
      !options.contains(SkipRoot::kUnserializable)) {
    // Scavenge collections have special processing for this.
    // Do not visit for serialization, since the external string table will
    // be populated from scratch upon deserialization.
    external_string_table_.IterateAll(v);
  }
  v->Synchronize(VisitorSynchronization::kExternalStringsTable);
  if (!options.contains(SkipRoot::kOldGeneration) &&
      !options.contains(SkipRoot::kUnserializable) &&
      isolate()->is_shared_space_isolate() &&
      isolate()->shared_struct_type_registry()) {
    isolate()->shared_struct_type_registry()->IterateElements(isolate(), v);
  }
  v->Synchronize(VisitorSynchronization::kSharedStructTypeRegistry);
}

void Heap::IterateSmiRoots(RootVisitor* v) {
  // Acquire execution access since we are going to read stack limit values.
  ExecutionAccess access(isolate());
  v->VisitRootPointers(Root::kSmiRootList, nullptr,
                       roots_table().smi_roots_begin(),
                       roots_table().smi_roots_end());
  v->Synchronize(VisitorSynchronization::kSmiRootList);
}

// We cannot avoid stale handles to left-trimmed objects, but can only make
// sure all handles still needed are updated. Filter out a stale pointer
// and clear the slot to allow post processing of handles (needed because
// the sweeper might actually free the underlying page).
class ClearStaleLeftTrimmedPointerVisitor : public RootVisitor {
 public:
  ClearStaleLeftTrimmedPointerVisitor(Heap* heap, RootVisitor* visitor)
      : heap_(heap),
        visitor_(visitor)
#if V8_COMPRESS_POINTERS
        ,
        cage_base_(heap->isolate())
#endif  // V8_COMPRESS_POINTERS
  {
    USE(heap_);
  }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    ClearLeftTrimmedOrForward(root, description, p);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      ClearLeftTrimmedOrForward(root, description, p);
    }
  }

  void Synchronize(VisitorSynchronization::SyncTag tag) override {
    visitor_->Synchronize(tag);
  }

  void VisitRunningCode(FullObjectSlot code_slot,
                        FullObjectSlot istream_or_smi_zero_slot) override {
    // Directly forward to actualy visitor here. Code objects and instruction
    // stream will not be left-trimmed.
    DCHECK(!IsLeftTrimmed(code_slot));
    DCHECK(!IsLeftTrimmed(istream_or_smi_zero_slot));
    visitor_->VisitRunningCode(code_slot, istream_or_smi_zero_slot);
  }

  // The pointer compression cage base value used for decompression of all
  // tagged values except references to InstructionStream objects.
  PtrComprCageBase cage_base() const {
#if V8_COMPRESS_POINTERS
    return cage_base_;
#else
    return PtrComprCageBase{};
#endif  // V8_COMPRESS_POINTERS
  }

 private:
  inline void ClearLeftTrimmedOrForward(Root root, const char* description,
                                        FullObjectSlot p) {
    if (!IsHeapObject(*p)) return;

    if (IsLeftTrimmed(p)) {
      p.store(Smi::zero());
    } else {
      visitor_->VisitRootPointer(root, description, p);
    }
  }

  inline bool IsLeftTrimmed(FullObjectSlot p) {
    if (!IsHeapObject(*p)) return false;
    Tagged<HeapObject> current = Cast<HeapObject>(*p);
    if (!current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() &&
        IsFreeSpaceOrFiller(current, cage_base())) {
#ifdef DEBUG
      // We need to find a FixedArrayBase map after walking the fillers.
      while (
          !current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() &&
          IsFreeSpaceOrFiller(current, cage_base())) {
        Address next = current.ptr();
        if (current->map(cage_base()) ==
            ReadOnlyRoots(heap_).one_pointer_filler_map()) {
          next += kTaggedSize;
        } else if (current->map(cage_base()) ==
                   ReadOnlyRoots(heap_).two_pointer_filler_map()) {
          next += 2 * kTaggedSize;
        } else {
          next += current->Size();
        }
        current = Cast<HeapObject>(Tagged<Object>(next));
      }
      DCHECK(
          current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() ||
          IsFixedArrayBase(current, cage_base()));
#endif  // DEBUG
      return true;
    } else {
      return false;
    }
  }

  Heap* heap_;
  RootVisitor* visitor_;

#if V8_COMPRESS_POINTERS
  const PtrComprCageBase cage_base_;
#endif  // V8_COMPRESS_POINTERS
};

void Heap::IterateRoots(RootVisitor* v, base::EnumSet<SkipRoot> options,
                        IterateRootsMode roots_mode) {
  v->VisitRootPointers(Root::kStrongRootList, nullptr,
                       roots_table().strong_roots_begin(),
                       roots_table().strong_roots_end());
  v->Synchronize(VisitorSynchronization::kStrongRootList);

  isolate_->bootstrapper()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kBootstrapper);
  Relocatable::Iterate(isolate_, v);
  v->Synchronize(VisitorSynchronization::kRelocatable);
  isolate_->debug()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kDebug);

  isolate_->compilation_cache()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kCompilationCache);

  const bool skip_iterate_builtins =
      options.contains(SkipRoot::kOldGeneration) ||
      (Builtins::kCodeObjectsAreInROSpace &&
       options.contains(SkipRoot::kReadOnlyBuiltins) &&
       // Prior to ReadOnlyPromotion, builtins may be on the mutable heap.
       !isolate_->serializer_enabled());
  if (!skip_iterate_builtins) {
    IterateBuiltins(v);
    v->Synchronize(VisitorSynchronization::kBuiltins);
  }

  // Iterate over pointers being held by inactive threads.
  isolate_->thread_manager()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kThreadManager);

  // Visitors in this block only run when not serializing. These include:
  //
  // - Thread-local and stack.
  // - Handles.
  // - Microtasks.
  // - The startup object cache.
  //
  // When creating real startup snapshot, these areas are expected to be empty.
  // It is also possible to create a snapshot of a *running* isolate for testing
  // purposes. In this case, these areas are likely not empty and will simply be
  // skipped.
  //
  // The general guideline for adding visitors to this section vs. adding them
  // above is that non-transient heap state is always visited, transient heap
  // state is visited only when not serializing.
  if (!options.contains(SkipRoot::kUnserializable)) {
    if (!options.contains(SkipRoot::kTracedHandles)) {
      // Young GCs always skip traced handles and visit them manually.
      DCHECK(!options.contains(SkipRoot::kOldGeneration));

      isolate_->traced_handles()->Iterate(v);
    }

    if (!options.contains(SkipRoot::kGlobalHandles)) {
      // Young GCs always skip global handles and visit them manually.
      DCHECK(!options.contains(SkipRoot::kOldGeneration));

      if (options.contains(SkipRoot::kWeak)) {
        isolate_->global_handles()->IterateStrongRoots(v);
      } else {
        isolate_->global_handles()->IterateAllRoots(v);
      }
    }
    v->Synchronize(VisitorSynchronization::kGlobalHandles);

    if (!options.contains(SkipRoot::kStack)) {
      ClearStaleLeftTrimmedPointerVisitor left_trim_visitor(this, v);
      IterateStackRoots(&left_trim_visitor);
      if (!options.contains(SkipRoot::kConservativeStack)) {
        IterateConservativeStackRoots(v, roots_mode);
      }
      v->Synchronize(VisitorSynchronization::kStackRoots);
    }

    // Iterate over main thread handles in handle scopes.
    if (!options.contains(SkipRoot::kMainThreadHandles)) {
      // Clear main thread handles with stale references to left-trimmed
      // objects. The GC would crash on such stale references.
      ClearStaleLeftTrimmedPointerVisitor left_trim_visitor(this, v);
      isolate_->handle_scope_implementer()->Iterate(&left_trim_visitor);
    }
    // Iterate local handles for all local heaps.
    safepoint_->Iterate(v);
    // Iterates all persistent handles.
    isolate_->persistent_handles_list()->Iterate(v, isolate_);
    v->Synchronize(VisitorSynchronization::kHandleScope);

    if (options.contains(SkipRoot::kOldGeneration)) {
      isolate_->eternal_handles()->IterateYoungRoots(v);
    } else {
      isolate_->eternal_handles()->IterateAllRoots(v);
    }
    v->Synchronize(VisitorSynchronization::kEternalHandles);

    // Iterate over pending Microtasks stored in MicrotaskQueues.
    MicrotaskQueue* default_microtask_queue =
        isolate_->default_microtask_queue();
    if (default_microtask_queue) {
      MicrotaskQueue* microtask_queue = default_microtask_queue;
      do {
        microtask_queue->IterateMicrotasks(v);
        microtask_queue = microtask_queue->next();
      } while (microtask_queue != default_microtask_queue);
    }
    v->Synchronize(VisitorSynchronization::kMicroTasks);

    // Iterate over other strong roots (currently only identity maps and
    // deoptimization entries).
    for (StrongRootsEntry* current = strong_roots_head_; current;
         current = current->next) {
      v->VisitRootPointers(Root::kStrongRoots, current->label, current->start,
                           current->end);
    }
    v->Synchronize(VisitorSynchronization::kStrongRoots);

    // Iterate over the startup and shared heap object caches unless
    // serializing or deserializing.
    SerializerDeserializer::IterateStartupObjectCache(isolate_, v);
    v->Synchronize(VisitorSynchronization::kStartupObjectCache);

    // Iterate over shared heap object cache when the isolate owns this data
    // structure. Isolates which own the shared heap object cache are:
    //   * All isolates when not using --shared-string-table.
    //   * Shared space/main isolate with --shared-string-table.
    //
    // Isolates which do not own the shared heap object cache should not iterate
    // it.
    if (isolate_->OwnsStringTables()) {
      SerializerDeserializer::IterateSharedHeapObjectCache(isolate_, v);
      v->Synchronize(VisitorSynchronization::kSharedHeapObjectCache);
    }
  }

  if (!options.contains(SkipRoot::kWeak)) {
    IterateWeakRoots(v, options);
  }
}

void Heap::IterateRootsIncludingClients(RootVisitor* v,
                                        base::EnumSet<SkipRoot> options) {
  IterateRoots(v, options, IterateRootsMode::kMainIsolate);

  if (isolate()->is_shared_space_isolate()) {
    ClientRootVisitor<> client_root_visitor(v);
    isolate()->global_safepoint()->IterateClientIsolates(
        [v = &client_root_visitor, options](Isolate* client) {
          client->heap()->IterateRoots(v, options,
                                       IterateRootsMode::kClientIsolate);
        });
  }
}

void Heap::IterateWeakGlobalHandles(RootVisitor* v) {
  isolate_->global_handles()->IterateWeakRoots(v);
  isolate_->traced_handles()->Iterate(v);
}

void Heap::IterateBuiltins(RootVisitor* v) {
  Builtins* builtins = isolate()->builtins();
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const char* name = Builtins::name(builtin);
    v->VisitRootPointer(Root::kBuiltins, name, builtins->builtin_slot(builtin));
  }

  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLastTier0;
       ++builtin) {
    v->VisitRootPointer(Root::kBuiltins, Builtins::name(builtin),
                        builtins->builtin_tier0_slot(builtin));
  }

  // The entry table doesn't need to be updated since all builtins are embedded.
  static_assert(Builtins::AllBuiltinsAreIsolateIndependent());
}

void Heap::IterateStackRoots(RootVisitor* v) { isolate_->Iterate(v); }

void Heap::IterateConservativeStackRoots(RootVisitor* v,
                                         IterateRootsMode roots_mode) {
#ifdef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
  if (!IsGCWithStack()) return;

  // In case of a shared GC, we're interested in the main isolate for CSS.
  Isolate* main_isolate = roots_mode == IterateRootsMode::kClientIsolate
                              ? isolate()->shared_space_isolate()
                              : isolate();

  ConservativeStackVisitor stack_visitor(main_isolate, v);
  if (IsGCWithMainThreadStack()) {
    stack().IteratePointersUntilMarker(&stack_visitor);
  }
  stack().IterateBackgroundStacks(&stack_visitor);
#endif  // V8_ENABLE_CONSERVATIVE_STACK_SCANNING
}

// static
size_t Heap::DefaultMinSemiSpaceSize() {
#if ENABLE_HUGEPAGE
  static constexpr size_t kMinSemiSpaceSize =
      kHugePageSize * kPointerMultiplier;
#else
  static constexpr size_t kMinSemiSpaceSize = 512 * KB * kPointerMultiplier;
#endif
  static_assert(kMinSemiSpaceSize % (1 << kPageSizeBits) == 0);

  return kMinSemiSpaceSize;
}

// static
size_t Heap::DefaultMaxSemiSpaceSize() {
#if ENABLE_HUGEPAGE
  static constexpr size_t kMaxSemiSpaceCapacityBaseUnit =
      kHugePageSize * 2 * kPointerMultiplier;
#else
  static constexpr size_t kMaxSemiSpaceCapacityBaseUnit =
      MB * kPointerMultiplier;
#endif
  static_assert(kMaxSemiSpaceCapacityBaseUnit % (1 << kPageSizeBits) == 0);

  size_t max_semi_space_size =
      (v8_flags.minor_ms ? v8_flags.minor_ms_max_new_space_capacity_mb
                         : v8_flags.scavenger_max_new_space_capacity_mb) *
      kMaxSemiSpaceCapacityBaseUnit;
  DCHECK_EQ(0, max_semi_space_size % (1 << kPageSizeBits));
  return max_semi_space_size;
}

// static
size_t Heap::OldGenerationToSemiSpaceRatio() {
  DCHECK(!v8_flags.minor_ms);
  // Compute a ration such that when old gen max capacity is set to the highest
  // supported value, young gen max capacity would also be set to the max.
  static size_t kMaxOldGenSizeToMaxYoungGenSizeRatio =
      V8HeapTrait::kMaxSize /
      (v8_flags.scavenger_max_new_space_capacity_mb * MB);
  static size_t kOldGenerationToSemiSpaceRatio =
      kMaxOldGenSizeToMaxYoungGenSizeRatio * kHeapLimitMultiplier /
      kPointerMultiplier;
  return kOldGenerationToSemiSpaceRatio;
}

// static
size_t Heap::OldGenerationToSemiSpaceRatioLowMemory() {
  static constexpr size_t kOldGenerationToSemiSpaceRatioLowMemory =
      256 * kHeapLimitMultiplier / kPointerMultiplier;
  return kOldGenerationToSemiSpaceRatioLowMemory / (v8_flags.minor_ms ? 2 : 1);
}

void Heap::ConfigureHeap(const v8::ResourceConstraints& constraints,
                         v8::CppHeap* cpp_heap) {
  CHECK(!configured_);
  // Initialize max_semi_space_size_.
  {
    max_semi_space_size_ = DefaultMaxSemiSpaceSize();
    if (constraints.max_young_generation_size_in_bytes() > 0) {
      max_semi_space_size_ = SemiSpaceSizeFromYoungGenerationSize(
          constraints.max_young_generation_size_in_bytes());
    }
    if (v8_flags.max_semi_space_size > 0) {
      max_semi_space_size_ =
          static_cast<size_t>(v8_flags.max_semi_space_size) * MB;
    } else if (v8_flags.max_heap_size > 0) {
      size_t max_heap_size = static_cast<size_t>(v8_flags.max_heap_size) * MB;
      size_t young_generation_size, old_generation_size;
      if (v8_flags.max_old_space_size > 0) {
        old_generation_size =
            static_cast<size_t>(v8_flags.max_old_space_size) * MB;
        young_generation_size = max_heap_size > old_generation_size
                                    ? max_heap_size - old_generation_size
                                    : 0;
      } else {
        GenerationSizesFromHeapSize(max_heap_size, &young_generation_size,
                                    &old_generation_size);
      }
      max_semi_space_size_ =
          SemiSpaceSizeFromYoungGenerationSize(young_generation_size);
    }
    if (v8_flags.stress_compaction) {
      // This will cause more frequent GCs when stressing.
      max_semi_space_size_ = MB;
    }
    if (!v8_flags.minor_ms) {
      // TODO(dinfuehr): Rounding to a power of 2 is technically no longer
      // needed but yields best performance on Pixel2.
      max_semi_space_size_ =
          static_cast<size_t>(base::bits::RoundUpToPowerOfTwo64(
              static_cast<uint64_t>(max_semi_space_size_)));
    }
    max_semi_space_size_ =
        std::max(max_semi_space_size_, DefaultMinSemiSpaceSize());
    max_semi_space_size_ =
        RoundDown<PageMetadata::kPageSize>(max_semi_space_size_);
  }

  // Initialize max_old_generation_size_ and max_global_memory_.
  {
    size_t max_old_generation_size = 700ul * (kSystemPointerSize / 4) * MB;
    if (constraints.max_old_generation_size_in_bytes() > 0) {
      max_old_generation_size = constraints.max_old_generation_size_in_bytes();
    }
    if (v8_flags.max_old_space_size > 0) {
      max_old_generation_size =
          static_cast<size_t>(v8_flags.max_old_space_size) * MB;
    } else if (v8_flags.max_heap_size > 0) {
      size_t max_heap_size = static_cast<size_t>(v8_flags.max_heap_size) * MB;
      size_t young_generation_size =
          YoungGenerationSizeFromSemiSpaceSize(max_semi_space_size_);
      max_old_generation_size = max_heap_size > young_generation_size
                                    ? max_heap_size - young_generation_size
                                    : 0;
    }
    max_old_generation_size =
        std::max(max_old_generation_size, MinOldGenerationSize());
    max_old_generation_size = std::min(max_old_generation_size,
                                       AllocatorLimitOnMaxOldGenerationSize());
    max_old_generation_size =
        RoundDown<PageMetadata::kPageSize>(max_old_generation_size);

    SetOldGenerationAndGlobalMaximumSize(max_old_generation_size);
  }

  CHECK_IMPLIES(
      v8_flags.max_heap_size > 0,
      v8_flags.max_semi_space_size == 0 || v8_flags.max_old_space_size == 0);

  // Initialize initial_semispace_size_.
  {
    initial_semispace_size_ = DefaultMinSemiSpaceSize();
    if (!v8_flags.optimize_for_size
### 提示词
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
pIterable();
  CodeStatistics::ResetCodeAndMetadataStatistics(isolate());
  // We do not look for code in new space, or map space.  If code
  // somehow ends up in those spaces, we would miss it here.
  CodeStatistics::CollectCodeStatistics(code_space_, isolate());
  CodeStatistics::CollectCodeStatistics(old_space_, isolate());
  CodeStatistics::CollectCodeStatistics(code_lo_space_, isolate());
  CodeStatistics::CollectCodeStatistics(trusted_space_, isolate());
  CodeStatistics::CollectCodeStatistics(trusted_lo_space_, isolate());
}

#ifdef DEBUG

void Heap::Print() {
  if (!HasBeenSetUp()) return;
  isolate()->PrintStack(stdout);

  for (SpaceIterator it(this); it.HasNext();) {
    it.Next()->Print();
  }
}

void Heap::ReportCodeStatistics(const char* title) {
  PrintF("###### Code Stats (%s) ######\n", title);
  CollectCodeStatistics();
  CodeStatistics::ReportCodeStatistics(isolate());
}

#endif  // DEBUG

bool Heap::Contains(Tagged<HeapObject> value) const {
  if (ReadOnlyHeap::Contains(value)) {
    return false;
  }
  if (memory_allocator()->IsOutsideAllocatedSpace(value.address())) {
    return false;
  }

  if (!HasBeenSetUp()) return false;

  return (new_space_ && new_space_->Contains(value)) ||
         old_space_->Contains(value) || code_space_->Contains(value) ||
         (shared_space_ && shared_space_->Contains(value)) ||
         (shared_trusted_space_ && shared_trusted_space_->Contains(value)) ||
         lo_space_->Contains(value) || code_lo_space_->Contains(value) ||
         (new_lo_space_ && new_lo_space_->Contains(value)) ||
         trusted_space_->Contains(value) ||
         trusted_lo_space_->Contains(value) ||
         (shared_lo_space_ && shared_lo_space_->Contains(value)) ||
         (shared_trusted_lo_space_ &&
          shared_trusted_lo_space_->Contains(value));
}

bool Heap::ContainsCode(Tagged<HeapObject> value) const {
  // TODO(v8:11880): support external code space.
  if (memory_allocator()->IsOutsideAllocatedSpace(value.address(),
                                                  EXECUTABLE)) {
    return false;
  }
  return HasBeenSetUp() &&
         (code_space_->Contains(value) || code_lo_space_->Contains(value));
}

bool Heap::SharedHeapContains(Tagged<HeapObject> value) const {
  if (shared_allocation_space_) {
    if (shared_allocation_space_->Contains(value)) return true;
    if (shared_lo_allocation_space_->Contains(value)) return true;
    if (shared_trusted_allocation_space_->Contains(value)) return true;
    if (shared_trusted_lo_allocation_space_->Contains(value)) return true;
  }

  return false;
}

bool Heap::MustBeInSharedOldSpace(Tagged<HeapObject> value) {
  if (isolate()->OwnsStringTables()) return false;
  if (ReadOnlyHeap::Contains(value)) return false;
  if (HeapLayout::InYoungGeneration(value)) return false;
  if (IsExternalString(value)) return false;
  if (IsInternalizedString(value)) return true;
  return false;
}

bool Heap::InSpace(Tagged<HeapObject> value, AllocationSpace space) const {
  if (memory_allocator()->IsOutsideAllocatedSpace(
          value.address(),
          IsAnyCodeSpace(space) ? EXECUTABLE : NOT_EXECUTABLE)) {
    return false;
  }
  if (!HasBeenSetUp()) return false;

  switch (space) {
    case NEW_SPACE:
      return new_space_->Contains(value);
    case OLD_SPACE:
      return old_space_->Contains(value);
    case CODE_SPACE:
      return code_space_->Contains(value);
    case SHARED_SPACE:
      return shared_space_->Contains(value);
    case TRUSTED_SPACE:
      return trusted_space_->Contains(value);
    case SHARED_TRUSTED_SPACE:
      return shared_trusted_space_->Contains(value);
    case LO_SPACE:
      return lo_space_->Contains(value);
    case CODE_LO_SPACE:
      return code_lo_space_->Contains(value);
    case NEW_LO_SPACE:
      return new_lo_space_->Contains(value);
    case SHARED_LO_SPACE:
      return shared_lo_space_->Contains(value);
    case SHARED_TRUSTED_LO_SPACE:
      return shared_trusted_lo_space_->Contains(value);
    case TRUSTED_LO_SPACE:
      return trusted_lo_space_->Contains(value);
    case RO_SPACE:
      return ReadOnlyHeap::Contains(value);
  }
  UNREACHABLE();
}

bool Heap::InSpaceSlow(Address addr, AllocationSpace space) const {
  if (memory_allocator()->IsOutsideAllocatedSpace(
          addr, IsAnyCodeSpace(space) ? EXECUTABLE : NOT_EXECUTABLE)) {
    return false;
  }
  if (!HasBeenSetUp()) return false;

  switch (space) {
    case NEW_SPACE:
      return new_space_->ContainsSlow(addr);
    case OLD_SPACE:
      return old_space_->ContainsSlow(addr);
    case CODE_SPACE:
      return code_space_->ContainsSlow(addr);
    case SHARED_SPACE:
      return shared_space_->ContainsSlow(addr);
    case TRUSTED_SPACE:
      return trusted_space_->ContainsSlow(addr);
    case SHARED_TRUSTED_SPACE:
      return shared_trusted_space_->ContainsSlow(addr);
    case LO_SPACE:
      return lo_space_->ContainsSlow(addr);
    case CODE_LO_SPACE:
      return code_lo_space_->ContainsSlow(addr);
    case NEW_LO_SPACE:
      return new_lo_space_->ContainsSlow(addr);
    case SHARED_LO_SPACE:
      return shared_lo_space_->ContainsSlow(addr);
    case SHARED_TRUSTED_LO_SPACE:
      return shared_trusted_lo_space_->ContainsSlow(addr);
    case TRUSTED_LO_SPACE:
      return trusted_lo_space_->ContainsSlow(addr);
    case RO_SPACE:
      return read_only_space_->ContainsSlow(addr);
  }
  UNREACHABLE();
}

bool Heap::IsValidAllocationSpace(AllocationSpace space) {
  switch (space) {
    case NEW_SPACE:
    case OLD_SPACE:
    case CODE_SPACE:
    case SHARED_SPACE:
    case LO_SPACE:
    case NEW_LO_SPACE:
    case CODE_LO_SPACE:
    case SHARED_LO_SPACE:
    case TRUSTED_SPACE:
    case SHARED_TRUSTED_SPACE:
    case TRUSTED_LO_SPACE:
    case SHARED_TRUSTED_LO_SPACE:
    case RO_SPACE:
      return true;
    default:
      return false;
  }
}

#ifdef DEBUG
void Heap::VerifyCountersAfterSweeping() {
  MakeHeapIterable();
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    space->VerifyCountersAfterSweeping(this);
  }
}

void Heap::VerifyCountersBeforeConcurrentSweeping(GarbageCollector collector) {
  if (v8_flags.minor_ms && new_space()) {
    PagedSpaceBase* space = paged_new_space()->paged_space();
    space->RefillFreeList();
    space->VerifyCountersBeforeConcurrentSweeping();
  }
  if (collector != GarbageCollector::MARK_COMPACTOR) return;
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    // We need to refine the counters on pages that are already swept and have
    // not been moved over to the actual space. Otherwise, the AccountingStats
    // are just an over approximation.
    space->RefillFreeList();
    space->VerifyCountersBeforeConcurrentSweeping();
  }
}

void Heap::VerifyCommittedPhysicalMemory() {
  PagedSpaceIterator spaces(this);
  for (PagedSpace* space = spaces.Next(); space != nullptr;
       space = spaces.Next()) {
    space->VerifyCommittedPhysicalMemory();
  }
  if (v8_flags.minor_ms && new_space()) {
    paged_new_space()->paged_space()->VerifyCommittedPhysicalMemory();
  }
}
#endif  // DEBUG

void Heap::IterateWeakRoots(RootVisitor* v, base::EnumSet<SkipRoot> options) {
  DCHECK(!options.contains(SkipRoot::kWeak));

  if (!options.contains(SkipRoot::kUnserializable)) {
    // Isolate::topmost_script_having_context_address is treated weakly.
    v->VisitRootPointer(
        Root::kWeakRoots, nullptr,
        FullObjectSlot(isolate()->topmost_script_having_context_address()));
  }

  if (!options.contains(SkipRoot::kOldGeneration) &&
      !options.contains(SkipRoot::kUnserializable) &&
      isolate()->OwnsStringTables()) {
    // Do not visit for the following reasons.
    // - Serialization, since the string table is custom serialized.
    // - If we are skipping old generation, since all internalized strings
    //   are in old space.
    // - If the string table is shared and this is not the shared heap,
    //   since all internalized strings are in the shared heap.
    isolate()->string_table()->IterateElements(v);
  }
  v->Synchronize(VisitorSynchronization::kStringTable);
  if (!options.contains(SkipRoot::kExternalStringTable) &&
      !options.contains(SkipRoot::kUnserializable)) {
    // Scavenge collections have special processing for this.
    // Do not visit for serialization, since the external string table will
    // be populated from scratch upon deserialization.
    external_string_table_.IterateAll(v);
  }
  v->Synchronize(VisitorSynchronization::kExternalStringsTable);
  if (!options.contains(SkipRoot::kOldGeneration) &&
      !options.contains(SkipRoot::kUnserializable) &&
      isolate()->is_shared_space_isolate() &&
      isolate()->shared_struct_type_registry()) {
    isolate()->shared_struct_type_registry()->IterateElements(isolate(), v);
  }
  v->Synchronize(VisitorSynchronization::kSharedStructTypeRegistry);
}

void Heap::IterateSmiRoots(RootVisitor* v) {
  // Acquire execution access since we are going to read stack limit values.
  ExecutionAccess access(isolate());
  v->VisitRootPointers(Root::kSmiRootList, nullptr,
                       roots_table().smi_roots_begin(),
                       roots_table().smi_roots_end());
  v->Synchronize(VisitorSynchronization::kSmiRootList);
}

// We cannot avoid stale handles to left-trimmed objects, but can only make
// sure all handles still needed are updated. Filter out a stale pointer
// and clear the slot to allow post processing of handles (needed because
// the sweeper might actually free the underlying page).
class ClearStaleLeftTrimmedPointerVisitor : public RootVisitor {
 public:
  ClearStaleLeftTrimmedPointerVisitor(Heap* heap, RootVisitor* visitor)
      : heap_(heap),
        visitor_(visitor)
#if V8_COMPRESS_POINTERS
        ,
        cage_base_(heap->isolate())
#endif  // V8_COMPRESS_POINTERS
  {
    USE(heap_);
  }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    ClearLeftTrimmedOrForward(root, description, p);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      ClearLeftTrimmedOrForward(root, description, p);
    }
  }

  void Synchronize(VisitorSynchronization::SyncTag tag) override {
    visitor_->Synchronize(tag);
  }

  void VisitRunningCode(FullObjectSlot code_slot,
                        FullObjectSlot istream_or_smi_zero_slot) override {
    // Directly forward to actualy visitor here. Code objects and instruction
    // stream will not be left-trimmed.
    DCHECK(!IsLeftTrimmed(code_slot));
    DCHECK(!IsLeftTrimmed(istream_or_smi_zero_slot));
    visitor_->VisitRunningCode(code_slot, istream_or_smi_zero_slot);
  }

  // The pointer compression cage base value used for decompression of all
  // tagged values except references to InstructionStream objects.
  PtrComprCageBase cage_base() const {
#if V8_COMPRESS_POINTERS
    return cage_base_;
#else
    return PtrComprCageBase{};
#endif  // V8_COMPRESS_POINTERS
  }

 private:
  inline void ClearLeftTrimmedOrForward(Root root, const char* description,
                                        FullObjectSlot p) {
    if (!IsHeapObject(*p)) return;

    if (IsLeftTrimmed(p)) {
      p.store(Smi::zero());
    } else {
      visitor_->VisitRootPointer(root, description, p);
    }
  }

  inline bool IsLeftTrimmed(FullObjectSlot p) {
    if (!IsHeapObject(*p)) return false;
    Tagged<HeapObject> current = Cast<HeapObject>(*p);
    if (!current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() &&
        IsFreeSpaceOrFiller(current, cage_base())) {
#ifdef DEBUG
      // We need to find a FixedArrayBase map after walking the fillers.
      while (
          !current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() &&
          IsFreeSpaceOrFiller(current, cage_base())) {
        Address next = current.ptr();
        if (current->map(cage_base()) ==
            ReadOnlyRoots(heap_).one_pointer_filler_map()) {
          next += kTaggedSize;
        } else if (current->map(cage_base()) ==
                   ReadOnlyRoots(heap_).two_pointer_filler_map()) {
          next += 2 * kTaggedSize;
        } else {
          next += current->Size();
        }
        current = Cast<HeapObject>(Tagged<Object>(next));
      }
      DCHECK(
          current->map_word(cage_base(), kRelaxedLoad).IsForwardingAddress() ||
          IsFixedArrayBase(current, cage_base()));
#endif  // DEBUG
      return true;
    } else {
      return false;
    }
  }

  Heap* heap_;
  RootVisitor* visitor_;

#if V8_COMPRESS_POINTERS
  const PtrComprCageBase cage_base_;
#endif  // V8_COMPRESS_POINTERS
};

void Heap::IterateRoots(RootVisitor* v, base::EnumSet<SkipRoot> options,
                        IterateRootsMode roots_mode) {
  v->VisitRootPointers(Root::kStrongRootList, nullptr,
                       roots_table().strong_roots_begin(),
                       roots_table().strong_roots_end());
  v->Synchronize(VisitorSynchronization::kStrongRootList);

  isolate_->bootstrapper()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kBootstrapper);
  Relocatable::Iterate(isolate_, v);
  v->Synchronize(VisitorSynchronization::kRelocatable);
  isolate_->debug()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kDebug);

  isolate_->compilation_cache()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kCompilationCache);

  const bool skip_iterate_builtins =
      options.contains(SkipRoot::kOldGeneration) ||
      (Builtins::kCodeObjectsAreInROSpace &&
       options.contains(SkipRoot::kReadOnlyBuiltins) &&
       // Prior to ReadOnlyPromotion, builtins may be on the mutable heap.
       !isolate_->serializer_enabled());
  if (!skip_iterate_builtins) {
    IterateBuiltins(v);
    v->Synchronize(VisitorSynchronization::kBuiltins);
  }

  // Iterate over pointers being held by inactive threads.
  isolate_->thread_manager()->Iterate(v);
  v->Synchronize(VisitorSynchronization::kThreadManager);

  // Visitors in this block only run when not serializing. These include:
  //
  // - Thread-local and stack.
  // - Handles.
  // - Microtasks.
  // - The startup object cache.
  //
  // When creating real startup snapshot, these areas are expected to be empty.
  // It is also possible to create a snapshot of a *running* isolate for testing
  // purposes. In this case, these areas are likely not empty and will simply be
  // skipped.
  //
  // The general guideline for adding visitors to this section vs. adding them
  // above is that non-transient heap state is always visited, transient heap
  // state is visited only when not serializing.
  if (!options.contains(SkipRoot::kUnserializable)) {
    if (!options.contains(SkipRoot::kTracedHandles)) {
      // Young GCs always skip traced handles and visit them manually.
      DCHECK(!options.contains(SkipRoot::kOldGeneration));

      isolate_->traced_handles()->Iterate(v);
    }

    if (!options.contains(SkipRoot::kGlobalHandles)) {
      // Young GCs always skip global handles and visit them manually.
      DCHECK(!options.contains(SkipRoot::kOldGeneration));

      if (options.contains(SkipRoot::kWeak)) {
        isolate_->global_handles()->IterateStrongRoots(v);
      } else {
        isolate_->global_handles()->IterateAllRoots(v);
      }
    }
    v->Synchronize(VisitorSynchronization::kGlobalHandles);

    if (!options.contains(SkipRoot::kStack)) {
      ClearStaleLeftTrimmedPointerVisitor left_trim_visitor(this, v);
      IterateStackRoots(&left_trim_visitor);
      if (!options.contains(SkipRoot::kConservativeStack)) {
        IterateConservativeStackRoots(v, roots_mode);
      }
      v->Synchronize(VisitorSynchronization::kStackRoots);
    }

    // Iterate over main thread handles in handle scopes.
    if (!options.contains(SkipRoot::kMainThreadHandles)) {
      // Clear main thread handles with stale references to left-trimmed
      // objects. The GC would crash on such stale references.
      ClearStaleLeftTrimmedPointerVisitor left_trim_visitor(this, v);
      isolate_->handle_scope_implementer()->Iterate(&left_trim_visitor);
    }
    // Iterate local handles for all local heaps.
    safepoint_->Iterate(v);
    // Iterates all persistent handles.
    isolate_->persistent_handles_list()->Iterate(v, isolate_);
    v->Synchronize(VisitorSynchronization::kHandleScope);

    if (options.contains(SkipRoot::kOldGeneration)) {
      isolate_->eternal_handles()->IterateYoungRoots(v);
    } else {
      isolate_->eternal_handles()->IterateAllRoots(v);
    }
    v->Synchronize(VisitorSynchronization::kEternalHandles);

    // Iterate over pending Microtasks stored in MicrotaskQueues.
    MicrotaskQueue* default_microtask_queue =
        isolate_->default_microtask_queue();
    if (default_microtask_queue) {
      MicrotaskQueue* microtask_queue = default_microtask_queue;
      do {
        microtask_queue->IterateMicrotasks(v);
        microtask_queue = microtask_queue->next();
      } while (microtask_queue != default_microtask_queue);
    }
    v->Synchronize(VisitorSynchronization::kMicroTasks);

    // Iterate over other strong roots (currently only identity maps and
    // deoptimization entries).
    for (StrongRootsEntry* current = strong_roots_head_; current;
         current = current->next) {
      v->VisitRootPointers(Root::kStrongRoots, current->label, current->start,
                           current->end);
    }
    v->Synchronize(VisitorSynchronization::kStrongRoots);

    // Iterate over the startup and shared heap object caches unless
    // serializing or deserializing.
    SerializerDeserializer::IterateStartupObjectCache(isolate_, v);
    v->Synchronize(VisitorSynchronization::kStartupObjectCache);

    // Iterate over shared heap object cache when the isolate owns this data
    // structure. Isolates which own the shared heap object cache are:
    //   * All isolates when not using --shared-string-table.
    //   * Shared space/main isolate with --shared-string-table.
    //
    // Isolates which do not own the shared heap object cache should not iterate
    // it.
    if (isolate_->OwnsStringTables()) {
      SerializerDeserializer::IterateSharedHeapObjectCache(isolate_, v);
      v->Synchronize(VisitorSynchronization::kSharedHeapObjectCache);
    }
  }

  if (!options.contains(SkipRoot::kWeak)) {
    IterateWeakRoots(v, options);
  }
}

void Heap::IterateRootsIncludingClients(RootVisitor* v,
                                        base::EnumSet<SkipRoot> options) {
  IterateRoots(v, options, IterateRootsMode::kMainIsolate);

  if (isolate()->is_shared_space_isolate()) {
    ClientRootVisitor<> client_root_visitor(v);
    isolate()->global_safepoint()->IterateClientIsolates(
        [v = &client_root_visitor, options](Isolate* client) {
          client->heap()->IterateRoots(v, options,
                                       IterateRootsMode::kClientIsolate);
        });
  }
}

void Heap::IterateWeakGlobalHandles(RootVisitor* v) {
  isolate_->global_handles()->IterateWeakRoots(v);
  isolate_->traced_handles()->Iterate(v);
}

void Heap::IterateBuiltins(RootVisitor* v) {
  Builtins* builtins = isolate()->builtins();
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const char* name = Builtins::name(builtin);
    v->VisitRootPointer(Root::kBuiltins, name, builtins->builtin_slot(builtin));
  }

  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLastTier0;
       ++builtin) {
    v->VisitRootPointer(Root::kBuiltins, Builtins::name(builtin),
                        builtins->builtin_tier0_slot(builtin));
  }

  // The entry table doesn't need to be updated since all builtins are embedded.
  static_assert(Builtins::AllBuiltinsAreIsolateIndependent());
}

void Heap::IterateStackRoots(RootVisitor* v) { isolate_->Iterate(v); }

void Heap::IterateConservativeStackRoots(RootVisitor* v,
                                         IterateRootsMode roots_mode) {
#ifdef V8_ENABLE_CONSERVATIVE_STACK_SCANNING
  if (!IsGCWithStack()) return;

  // In case of a shared GC, we're interested in the main isolate for CSS.
  Isolate* main_isolate = roots_mode == IterateRootsMode::kClientIsolate
                              ? isolate()->shared_space_isolate()
                              : isolate();

  ConservativeStackVisitor stack_visitor(main_isolate, v);
  if (IsGCWithMainThreadStack()) {
    stack().IteratePointersUntilMarker(&stack_visitor);
  }
  stack().IterateBackgroundStacks(&stack_visitor);
#endif  // V8_ENABLE_CONSERVATIVE_STACK_SCANNING
}

// static
size_t Heap::DefaultMinSemiSpaceSize() {
#if ENABLE_HUGEPAGE
  static constexpr size_t kMinSemiSpaceSize =
      kHugePageSize * kPointerMultiplier;
#else
  static constexpr size_t kMinSemiSpaceSize = 512 * KB * kPointerMultiplier;
#endif
  static_assert(kMinSemiSpaceSize % (1 << kPageSizeBits) == 0);

  return kMinSemiSpaceSize;
}

// static
size_t Heap::DefaultMaxSemiSpaceSize() {
#if ENABLE_HUGEPAGE
  static constexpr size_t kMaxSemiSpaceCapacityBaseUnit =
      kHugePageSize * 2 * kPointerMultiplier;
#else
  static constexpr size_t kMaxSemiSpaceCapacityBaseUnit =
      MB * kPointerMultiplier;
#endif
  static_assert(kMaxSemiSpaceCapacityBaseUnit % (1 << kPageSizeBits) == 0);

  size_t max_semi_space_size =
      (v8_flags.minor_ms ? v8_flags.minor_ms_max_new_space_capacity_mb
                         : v8_flags.scavenger_max_new_space_capacity_mb) *
      kMaxSemiSpaceCapacityBaseUnit;
  DCHECK_EQ(0, max_semi_space_size % (1 << kPageSizeBits));
  return max_semi_space_size;
}

// static
size_t Heap::OldGenerationToSemiSpaceRatio() {
  DCHECK(!v8_flags.minor_ms);
  // Compute a ration such that when old gen max capacity is set to the highest
  // supported value, young gen max capacity would also be set to the max.
  static size_t kMaxOldGenSizeToMaxYoungGenSizeRatio =
      V8HeapTrait::kMaxSize /
      (v8_flags.scavenger_max_new_space_capacity_mb * MB);
  static size_t kOldGenerationToSemiSpaceRatio =
      kMaxOldGenSizeToMaxYoungGenSizeRatio * kHeapLimitMultiplier /
      kPointerMultiplier;
  return kOldGenerationToSemiSpaceRatio;
}

// static
size_t Heap::OldGenerationToSemiSpaceRatioLowMemory() {
  static constexpr size_t kOldGenerationToSemiSpaceRatioLowMemory =
      256 * kHeapLimitMultiplier / kPointerMultiplier;
  return kOldGenerationToSemiSpaceRatioLowMemory / (v8_flags.minor_ms ? 2 : 1);
}

void Heap::ConfigureHeap(const v8::ResourceConstraints& constraints,
                         v8::CppHeap* cpp_heap) {
  CHECK(!configured_);
  // Initialize max_semi_space_size_.
  {
    max_semi_space_size_ = DefaultMaxSemiSpaceSize();
    if (constraints.max_young_generation_size_in_bytes() > 0) {
      max_semi_space_size_ = SemiSpaceSizeFromYoungGenerationSize(
          constraints.max_young_generation_size_in_bytes());
    }
    if (v8_flags.max_semi_space_size > 0) {
      max_semi_space_size_ =
          static_cast<size_t>(v8_flags.max_semi_space_size) * MB;
    } else if (v8_flags.max_heap_size > 0) {
      size_t max_heap_size = static_cast<size_t>(v8_flags.max_heap_size) * MB;
      size_t young_generation_size, old_generation_size;
      if (v8_flags.max_old_space_size > 0) {
        old_generation_size =
            static_cast<size_t>(v8_flags.max_old_space_size) * MB;
        young_generation_size = max_heap_size > old_generation_size
                                    ? max_heap_size - old_generation_size
                                    : 0;
      } else {
        GenerationSizesFromHeapSize(max_heap_size, &young_generation_size,
                                    &old_generation_size);
      }
      max_semi_space_size_ =
          SemiSpaceSizeFromYoungGenerationSize(young_generation_size);
    }
    if (v8_flags.stress_compaction) {
      // This will cause more frequent GCs when stressing.
      max_semi_space_size_ = MB;
    }
    if (!v8_flags.minor_ms) {
      // TODO(dinfuehr): Rounding to a power of 2 is technically no longer
      // needed but yields best performance on Pixel2.
      max_semi_space_size_ =
          static_cast<size_t>(base::bits::RoundUpToPowerOfTwo64(
              static_cast<uint64_t>(max_semi_space_size_)));
    }
    max_semi_space_size_ =
        std::max(max_semi_space_size_, DefaultMinSemiSpaceSize());
    max_semi_space_size_ =
        RoundDown<PageMetadata::kPageSize>(max_semi_space_size_);
  }

  // Initialize max_old_generation_size_ and max_global_memory_.
  {
    size_t max_old_generation_size = 700ul * (kSystemPointerSize / 4) * MB;
    if (constraints.max_old_generation_size_in_bytes() > 0) {
      max_old_generation_size = constraints.max_old_generation_size_in_bytes();
    }
    if (v8_flags.max_old_space_size > 0) {
      max_old_generation_size =
          static_cast<size_t>(v8_flags.max_old_space_size) * MB;
    } else if (v8_flags.max_heap_size > 0) {
      size_t max_heap_size = static_cast<size_t>(v8_flags.max_heap_size) * MB;
      size_t young_generation_size =
          YoungGenerationSizeFromSemiSpaceSize(max_semi_space_size_);
      max_old_generation_size = max_heap_size > young_generation_size
                                    ? max_heap_size - young_generation_size
                                    : 0;
    }
    max_old_generation_size =
        std::max(max_old_generation_size, MinOldGenerationSize());
    max_old_generation_size = std::min(max_old_generation_size,
                                       AllocatorLimitOnMaxOldGenerationSize());
    max_old_generation_size =
        RoundDown<PageMetadata::kPageSize>(max_old_generation_size);

    SetOldGenerationAndGlobalMaximumSize(max_old_generation_size);
  }

  CHECK_IMPLIES(
      v8_flags.max_heap_size > 0,
      v8_flags.max_semi_space_size == 0 || v8_flags.max_old_space_size == 0);

  // Initialize initial_semispace_size_.
  {
    initial_semispace_size_ = DefaultMinSemiSpaceSize();
    if (!v8_flags.optimize_for_size) {
      // Start with at least 1*MB semi-space on machines with a lot of memory.
      initial_semispace_size_ =
          std::max(initial_semispace_size_, static_cast<size_t>(1 * MB));
    }
    DCHECK_GE(initial_semispace_size_, DefaultMinSemiSpaceSize());
    if (constraints.initial_young_generation_size_in_bytes() > 0) {
      initial_semispace_size_ = SemiSpaceSizeFromYoungGenerationSize(
          constraints.initial_young_generation_size_in_bytes());
    }
    if (v8_flags.initial_heap_size > 0) {
      size_t young_generation, old_generation;
      Heap::GenerationSizesFromHeapSize(
          static_cast<size_t>(v8_flags.initial_heap_size) * MB,
          &young_generation, &old_generation);
      initial_semispace_size_ =
          SemiSpaceSizeFromYoungGenerationSize(young_generation);
    }
    if (v8_flags.min_semi_space_size > 0) {
      initial_semispace_size_ =
          static_cast<size_t>(v8_flags.min_semi_space_size) * MB;
    }
    initial_semispace_size_ =
        std::min(initial_semispace_size_, max_semi_space_size_);
    initial_semispace_size_ =
        RoundDown<PageMetadata::kPageSize>(initial_semispace_size_);
  }

  if (v8_flags.lazy_new_space_shrinking) {
    initial_semispace_size_ = max_semi_space_size_;
  }

  // Initialize initial_old_space_size_.
  std::optional<size_t> initial_old_generation_size =
      [&]() -> std::optional<size_t> {
    if (v8_flags.initial_old_space_size > 0) {
      return static_cast<size_t>(v8_flags.initial_old_space_size) * MB;
    }
    if (v8_flags.initial_heap_size > 0) {
      size_t initial_heap_size =
          static_cast<size_t>(v8_flags.initial_heap_size) * MB;
      size_t young_generation_size =
          YoungGenerationSizeFromSemiSpaceSize(initial_semispace_size_);
      return initial_heap_size > young_generation_size
                 ? initial_heap_size - young_generation_size
                 : 0;
    }
    return std::nullopt;
  }();
  if (initial_old_generation_size.has_value()) {
    initial_limit_overwritten_ = true;
    initial_old_generation_size_ = *initial_old_generation_size;
  } else {
    initial_old_generation_size_ = kMaxInitialOldGenerationSize;
    if (constraints.initial_old_generation_size_in_bytes() > 0) {
      initial_old_generation_size_ =
          constraints.initial_old_generation_size_in_bytes();
    }
  }
  initial_old_generation_size_ =
      std::min(initial_old_generation_size_, max_old_generation_size() / 2);
  initial_old_generation_size_ =
      RoundDown<PageMetadata::kPageSize>(initial_old_generation_size_);
  if (initial_limit_overwritten_) {
    // If the embedder pre-configures the initial old generation size,
    // then allow V8 to skip full GCs below that threshold.
    min_old_generation_size_ = initial_old_generation_size_;
    min_global_memory_size_ =
        GlobalMemorySizeFromV8Size(min_old_generation_size_);
  }
  initial_max_old_generation_size_ = max_old_generation_size();
  ResetOldGenerationAndGlobalAllocationLimit();

  // We rely on being able to allocate new arrays in paged spaces.
  DCHECK(kMaxRegularHeapObjectSize >=
         (JSArray::kHeaderSize +
          FixedArray::SizeFor(JSArray::kInitialMaxFastElementArray) +
          ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize)));

  code_range_size_ = constraints.code_range_size_in_bytes();

  if (cpp_heap) {
    AttachCppHeap(cpp_heap);
    owning_cpp_heap_.reset(CppHeap::From(cpp_heap));
  }

  configured_ = true;
}

void Heap::AddToRingBuffer(const char* string) {
  size_t first_part =
      std::min(strlen(string), kTraceRingBufferSize - ring_buffer_end_);
  memcpy(trace_ring_buffer_ + ring_buffer_end_, string, first_part);
  ring_buffer_end_ += first_part;
  if (first_part < strlen(string)) {
    ring_buffer_full_ = true;
    size_t second_part = strlen(string) - first_part;
    memcpy(trace_ring_buffer_, string + first_part, second_part);
    ring_buffer_end_ = second_part;
  }
}

void Heap::GetFromRingBuffer(char* buffer) {
  size_t copied = 0;
  if (ring_buffer_full_) {
    copied = kTraceRingBufferSize - ring_buffer_end_;
    memcpy(buffer, trace_ring_buffer_ + ring_buffer_end_, copied);
  }
  memcpy(buffer + copied, trace_ring_buffer_, ring_buffer_end_);
}

void Heap::ConfigureHeapDefault() {
  v8::ResourceConstraints constraints;
  ConfigureHeap(constraints, nullptr);
}

void Heap::RecordStats(HeapStats* stats, bool take_snapshot) {
  *stats->start_marker = HeapStats::kStartMarker;
  *stats->end_marker = HeapStats::kEndMarker;
  *stats->ro_space_size = read_only_space_->Size();
  *stats->ro_space_capacity = read_only_space_->Capacity();
  *stats->new_space_size = NewSpaceSize();
  *stats->new_space_capacity = NewSpaceCapacity();
  *stats->old_space_size = old_space_->SizeOfObjects();
  *stats->old_space_capacity = old_space_->Capacity();
  *stats->code_space_size = code_space_->SizeOfObjects();
  *stats->code_space_capacity = code_space_->Capacity();
  *stats->map_space_size = 0;
  *stats->map_space_capacity = 0;
  *stats->lo_space_size = lo_space_->Size();
  *stats->code_lo_space_size = code_lo_space_->Size();
  isolate_->global_handles()->RecordStats(stats);
  *stats->memory_allocator_size = memory_allocator()->Size();
  *stats->memory_allocator_capacity =
      memory_allocator()->Size() + memory_allocator()->Available();
  *stats->os_error = base::OS::GetLastError();
  // TODO(leszeks): Include the string table in both current and peak usage.
  *stats->malloced_memory = isolate_->allocator()->GetCurrentMemoryUsage();
  *stats->malloced_peak_memory = isolate_->allocator()->GetMaxMemoryUsage();
  if (take_snapshot) {
    HeapObjectIterator iterator(this);
    for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
         obj = iterator.Next()) {
      InstanceType type = obj->map()->instance_type();
      DCHECK(0 <= type && type <= LAST_TYPE);
      stats->objects_per_type[type]++;
      stats->size_per_type[type] += obj->Size();
    }
  }
  if (stats->last_few_messages != nullptr)
    GetFromRingBuffer(stats->last_few_messages);
}

size_t Heap::OldGenerationSizeOfObjects() const {
  size_t total = 0;
  if (v8_flags.sticky_mark_bits)
    total += sticky_space()->old_objects_size();
  else
    total += old_space()->SizeOfObjects();
  total += lo_space()->SizeOfObjects();
  total += code_space()->SizeOfObjects();
  total += code_lo_space()->SizeOfObjects();
  if (shared_space()) {
    total += shared_space()->SizeOfObjects();
  }
  if (shared_lo_space()) {
    total += shared_lo_space()->SizeOfObjects();
  }
  total += trusted_space()->SizeOfObjects();
  total += trusted_lo_
```