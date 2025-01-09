Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understanding the Request:** The primary goal is to understand the functionality of the given C++ code from `v8/src/heap/heap.cc`. The prompt also includes specific instructions about Torque, JavaScript relationships, logic, common errors, and summarization, framed as part 4 of a 9-part series.

2. **Initial Code Scan and Keyword Recognition:**  A quick scan reveals several key terms and patterns:
    * `Heap::`: This clearly indicates methods belonging to a `Heap` class. Given the file path, this is likely the core heap management component of V8.
    * `ComputeNewAllocationLimits`, `SetOldGenerationAndGlobalAllocationLimit`:  These suggest memory management, specifically setting limits.
    * `CallGCPrologueCallbacks`, `CallGCEpilogueCallbacks`:  These strongly hint at garbage collection (GC) hooks. "Prologue" and "Epilogue" suggest actions taken before and after a GC cycle.
    * `MarkCompact`, `MinorMarkSweep`, `Scavenge`: These are well-known garbage collection algorithms or phases.
    * `ExternalStringTable`:  This points to the management of strings stored outside the main V8 heap.
    * `UpdateExternalString`, `UpdateYoungReferenceInExternalStringTableEntry`: Operations on the external string table.
    * `ProcessAllWeakReferences`, `ProcessNativeContexts`, `ProcessAllocationSites`, `ProcessDirtyJSFinalizationRegistries`:  Handling weak references and specific object types during GC.
    * `ForeachAllocationSite`, `ResetAllAllocationSitesDependentCode`: Iterating and manipulating allocation site information, likely related to optimization and deoptimization.
    * `EvaluateOldSpaceLocalPretenuring`:  An optimization technique where objects are allocated in the old generation directly.
    * `VisitExternalResources`:  Iterating over external resources.
    * `CreateFillerObjectAt`, `PrecedeWithFiller`, `AlignWithFillerBackground`: Managing free space within the heap using "filler" objects.
    * `AllocateExternalBackingStore`:  Allocating memory outside the main V8 heap.
    * `FlushNumberStringCache`:  Clearing a cache related to number-to-string conversions.
    * `OnMoveEvent`:  Handling object movement within the heap.
    * `LeftTrimFixedArray`:  Potentially an optimization for resizing arrays.

3. **Categorizing Functionality:**  Based on the keywords and patterns, I can start grouping the functions by their primary purpose:
    * **Memory Management & Allocation Limits:** `ComputeNewAllocationLimits`, `SetOldGenerationAndGlobalAllocationLimit`, `ShrinkOldGenerationAllocationLimitIfNotConfigured`.
    * **Garbage Collection (Lifecycle & Phases):** `CallGCPrologueCallbacks`, `CallGCEpilogueCallbacks`, `MarkCompact`, `MinorMarkSweep`, `Scavenge`, `MarkCompactPrologue`, `MarkCompactEpilogue`.
    * **External String Management:** `ExternalStringTable` (its methods like `Contains`, `UpdateExternalString`, `Verify`, `UpdateYoungReferences`, `PromoteYoung`, `Iterate`), `UpdateYoungReferencesInExternalStringTable`, `UpdateReferencesInExternalStringTable`.
    * **Weak Reference Processing:** `ProcessAllWeakReferences`, `ProcessNativeContexts`, `ProcessAllocationSites`, `ProcessDirtyJSFinalizationRegistries`, `ProcessWeakListRoots`.
    * **Allocation Site Management & Pretenuring:** `ForeachAllocationSite`, `ResetAllAllocationSitesDependentCode`, `EvaluateOldSpaceLocalPretenuring`.
    * **External Resource Handling:** `VisitExternalResources`.
    * **Heap Layout & Free Space Management:** `GetMaximumFillToAlign`, `GetFillToAlign`, `GetCodeRangeReservedAreaSize`, `PrecedeWithFiller`, `PrecedeWithFillerBackground`, `AlignWithFillerBackground`, `CreateFillerObjectAt`, `CreateFillerObjectAtBackground`, `CreateFillerObjectAtRaw`.
    * **External Memory Allocation:** `AllocateExternalBackingStore`.
    * **Caching:** `FlushNumberStringCache`.
    * **Object Movement Tracking:** `OnMoveEvent`.
    * **Array Optimization:** `LeftTrimFixedArray`.
    * **Object Properties:** `CanMoveObjectStart`, `IsImmovable`, `IsLargeObject`.

4. **Detailing Each Category:**  Now, I go through each category and elaborate on the specific functions within it. For instance, for "Garbage Collection," I explain that `MarkCompact` is a full GC, `MinorMarkSweep` is a minor GC, and `Scavenge` is for the young generation. I also note the prologue/epilogue callbacks.

5. **Addressing Specific Prompt Instructions:**
    * **Torque:** The code is C++, not Torque, so that's a simple observation.
    * **JavaScript Relationship:** This requires linking the C++ concepts to how they manifest in JavaScript. GC is the most obvious link – JavaScript's automatic memory management relies on these underlying GC mechanisms. External strings are also relevant (e.g., strings from files or network). Allocation sites connect to object creation in JS.
    * **JavaScript Examples:**  Provide concise examples to illustrate the connection (e.g., creating lots of objects triggers GC, using `fs` module creates external strings).
    * **Logic and Examples:**  For functions with clear logic, like setting allocation limits, describe the inputs and outputs. Hypothetical scenarios are helpful.
    * **Common Errors:** Think about how mistakes in JavaScript might relate to the underlying C++ (e.g., memory leaks in native modules, performance issues due to excessive object creation).
    * **Summarization (Part 4 of 9):**  Emphasize that this part focuses on core heap operations, particularly around memory management, garbage collection, and handling specific object types. Note that it's not about the JavaScript engine's execution or compilation.

6. **Refinement and Ordering:**  Organize the information logically. Start with a general overview, then delve into specific areas. Ensure clarity and conciseness. Use formatting (like bullet points) to improve readability.

7. **Self-Correction/Review:**  Read through the analysis. Are there any ambiguities?  Are the JavaScript examples accurate and relevant?  Have I addressed all parts of the prompt?  For example, I initially focused heavily on GC but realized I needed to give more weight to other areas like external strings and allocation sites as per the code. I also double-checked the prompt's framing as "part 4 of 9" to tailor the summary appropriately.
```cpp
  auto new_limits = ComputeNewAllocationLimits(this);
  size_t new_old_generation_allocation_limit =
      new_limits.old_generation_allocation_limit;
  size_t new_global_allocation_limit = new_limits.global_allocation_limit;

  new_old_generation_allocation_limit = std::max(
      new_old_generation_allocation_limit, old_generation_allocation_limit());
  new_global_allocation_limit =
      std::max(new_global_allocation_limit, global_allocation_limit());
  SetOldGenerationAndGlobalAllocationLimit(new_old_generation_allocation_limit,
                                           new_global_allocation_limit);

  CHECK_EQ(max_global_memory_size_,
           GlobalMemorySizeFromV8Size(max_old_generation_size_));
  CHECK_GE(global_allocation_limit(), old_generation_allocation_limit_);
}

void Heap::CallGCPrologueCallbacks(GCType gc_type, GCCallbackFlags flags,
                                   GCTracer::Scope::ScopeId scope_id) {
  if (gc_prologue_callbacks_.IsEmpty()) return;

  GCCallbacksScope scope(this);
  if (scope.CheckReenter()) {
    RCS_SCOPE(isolate(), RuntimeCallCounterId::kGCPrologueCallback);
    TRACE_GC(tracer(), scope_id);
    HandleScope handle_scope(isolate());
    gc_prologue_callbacks_.Invoke(gc_type, flags);
  }
}

void Heap::CallGCEpilogueCallbacks(GCType gc_type, GCCallbackFlags flags,
                                   GCTracer::Scope::ScopeId scope_id) {
  if (gc_epilogue_callbacks_.IsEmpty()) return;

  GCCallbacksScope scope(this);
  if (scope.CheckReenter()) {
    RCS_SCOPE(isolate(), RuntimeCallCounterId::kGCEpilogueCallback);
    TRACE_GC(tracer(), scope_id);
    HandleScope handle_scope(isolate());
    gc_epilogue_callbacks_.Invoke(gc_type, flags);
  }
}

void Heap::MarkCompact() {
  SetGCState(MARK_COMPACT);

  PROFILE(isolate_, CodeMovingGCEvent());

  UpdateOldGenerationAllocationCounter();
  uint64_t size_of_objects_before_gc = SizeOfObjects();

  mark_compact_collector()->Prepare();

  ms_count_++;
  contexts_disposed_ = 0;

  MarkCompactPrologue();

  mark_compact_collector()->CollectGarbage();

  MarkCompactEpilogue();

  if (v8_flags.allocation_site_pretenuring) {
    EvaluateOldSpaceLocalPretenuring(size_of_objects_before_gc);
  }
  // This should be updated before PostGarbageCollectionProcessing, which
  // can cause another GC. Take into account the objects promoted during
  // GC.
  old_generation_allocation_counter_at_last_gc_ +=
      static_cast<size_t>(promoted_objects_size_);
  old_generation_size_at_last_gc_ = OldGenerationSizeOfObjects();
  old_generation_wasted_at_last_gc_ = OldGenerationWastedBytes();
  external_memory_.UpdateLowSinceMarkCompact(external_memory_.total());
  embedder_size_at_last_gc_ = EmbedderSizeOfObjects();
  // Limits can now be computed based on estimate from MARK_COMPACT.
  set_using_initial_limit(false);
}

void Heap::MinorMarkSweep() {
  DCHECK(v8_flags.minor_ms);
  CHECK_EQ(NOT_IN_GC, gc_state());
  DCHECK(use_new_space());
  DCHECK(!incremental_marking()->IsMajorMarking());

  TRACE_GC(tracer(), GCTracer::Scope::MINOR_MS);

  SetGCState(MINOR_MARK_SWEEP);
  minor_mark_sweep_collector_->CollectGarbage();
  SetGCState(NOT_IN_GC);
}

void Heap::MarkCompactEpilogue() {
  TRACE_GC(tracer(), GCTracer::Scope::MC_EPILOGUE);
  SetGCState(NOT_IN_GC);

  isolate_->counters()->objs_since_last_full()->Set(0);
}

void Heap::MarkCompactPrologue() {
  TRACE_GC(tracer(), GCTracer::Scope::MC_PROLOGUE);
  isolate_->descriptor_lookup_cache()->Clear();
  RegExpResultsCache::Clear(string_split_cache());
  RegExpResultsCache::Clear(regexp_multiple_cache());
  RegExpResultsCache_MatchGlobalAtom::Clear(this);

  FlushNumberStringCache();
}

void Heap::Scavenge() {
  DCHECK_NOT_NULL(new_space());
  DCHECK_IMPLIES(v8_flags.separate_gc_phases,
                 !incremental_marking()->IsMarking());

  if (v8_flags.trace_incremental_marking &&
      !incremental_marking()->IsStopped()) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Scavenge during marking.\n");
  }

  TRACE_GC(tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE);
  base::MutexGuard guard(relocation_mutex());
  // Young generation garbage collection is orthogonal from full GC marking. It
  // is possible that objects that are currently being processed for marking are
  // reclaimed in the young generation GC that interleaves concurrent marking.
  // Pause concurrent markers to allow processing them using
  // `UpdateMarkingWorklistAfterYoungGenGC()`.
  ConcurrentMarking::PauseScope pause_js_marking(concurrent_marking());
  CppHeap::PauseConcurrentMarkingScope pause_cpp_marking(
      CppHeap::From(cpp_heap_));

  // Bump-pointer allocations done during scavenge are not real allocations.
  // Pause the inline allocation steps.
  IncrementalMarking::PauseBlackAllocationScope pause_black_allocation(
      incremental_marking());

  SetGCState(SCAVENGE);

  // Implements Cheney's copying algorithm
  scavenger_collector_->CollectGarbage();

  SetGCState(NOT_IN_GC);
}

bool Heap::ExternalStringTable::Contains(Tagged<String> string) {
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    if (young_strings_[i] == string) return true;
  }
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    if (old_strings_[i] == string) return true;
  }
  return false;
}

void Heap::UpdateExternalString(Tagged<String> string, size_t old_payload,
                                size_t new_payload) {
  DCHECK(IsExternalString(string));

  PageMetadata* page = PageMetadata::FromHeapObject(string);

  if (old_payload > new_payload) {
    page->DecrementExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString, old_payload - new_payload);
  } else {
    page->IncrementExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString, new_payload - old_payload);
  }
}

Tagged<String> Heap::UpdateYoungReferenceInExternalStringTableEntry(
    Heap* heap, FullObjectSlot p) {
  // This is only used for Scavenger.
  DCHECK(!v8_flags.minor_ms);

  PtrComprCageBase cage_base(heap->isolate());
  Tagged<HeapObject> obj = Cast<HeapObject>(*p);
  MapWord first_word = obj->map_word(cage_base, kRelaxedLoad);

  Tagged<String> new_string;

  if (InFromPage(obj)) {
    if (!first_word.IsForwardingAddress()) {
      // Unreachable external string can be finalized.
      Tagged<String> string = Cast<String>(obj);
      if (!IsExternalString(string, cage_base)) {
        // Original external string has been internalized.
        DCHECK(IsThinString(string, cage_base));
        return Tagged<String>();
      }
      heap->FinalizeExternalString(string);
      return Tagged<String>();
    }
    new_string = Cast<String>(first_word.ToForwardingAddress(obj));
  } else {
    new_string = Cast<String>(obj);
  }

  // String is still reachable.
  if (IsThinString(new_string, cage_base)) {
    // Filtering Thin strings out of the external string table.
    return Tagged<String>();
  } else if (IsExternalString(new_string, cage_base)) {
    MutablePageMetadata::MoveExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString,
        PageMetadata::FromAddress((*p).ptr()),
        PageMetadata::FromHeapObject(new_string),
        Cast<ExternalString>(new_string)->ExternalPayloadSize());
    return new_string;
  }

  // Internalization can replace external strings with non-external strings.
  return IsExternalString(new_string, cage_base) ? new_string
                                                 : Tagged<String>();
}

void Heap::ExternalStringTable::VerifyYoung() {
#ifdef DEBUG
  std::set<Tagged<String>> visited_map;
  std::map<MutablePageMetadata*, size_t> size_map;
  ExternalBackingStoreType type = ExternalBackingStoreType::kExternalString;
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<String> obj = Cast<String>(Tagged<Object>(young_strings_[i]));
    MutablePageMetadata* mc = MutablePageMetadata::FromHeapObject(obj);
    DCHECK_IMPLIES(!v8_flags.sticky_mark_bits,
                   mc->Chunk()->InYoungGeneration());
    DCHECK(HeapLayout::InYoungGeneration(obj));
    DCHECK(!IsTheHole(obj, heap_->isolate()));
    DCHECK(IsExternalString(obj));
    // Note: we can have repeated elements in the table.
    DCHECK_EQ(0, visited_map.count(obj));
    visited_map.insert(obj);
    size_map[mc] += Cast<ExternalString>(obj)->ExternalPayloadSize();
  }
  for (std::map<MutablePageMetadata*, size_t>::iterator it = size_map.begin();
       it != size_map.end(); it++)
    DCHECK_EQ(it->first->ExternalBackingStoreBytes(type), it->second);
#endif
}

void Heap::ExternalStringTable::Verify() {
#ifdef DEBUG
  std::set<Tagged<String>> visited_map;
  std::map<MutablePageMetadata*, size_t> size_map;
  ExternalBackingStoreType type = ExternalBackingStoreType::kExternalString;
  VerifyYoung();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<String> obj = Cast<String>(Tagged<Object>(old_strings_[i]));
    MutablePageMetadata* mc = MutablePageMetadata::FromHeapObject(obj);
    DCHECK_IMPLIES(!v8_flags.sticky_mark_bits,
                   !mc->Chunk()->InYoungGeneration());
    DCHECK(!HeapLayout::InYoungGeneration(obj));
    DCHECK(!IsTheHole(obj, heap_->isolate()));
    DCHECK(IsExternalString(obj));
    // Note: we can have repeated elements in the table.
    DCHECK_EQ(0, visited_map.count(obj));
    visited_map.insert(obj);
    size_map[mc] += Cast<ExternalString>(obj)->ExternalPayloadSize();
  }
  for (std::map<MutablePageMetadata*, size_t>::iterator it = size_map.begin();
       it != size_map.end(); it++)
    DCHECK_EQ(it->first->ExternalBackingStoreBytes(type), it->second);
#endif
}

void Heap::ExternalStringTable::UpdateYoungReferences(
    Heap::ExternalStringTableUpdaterCallback updater_func) {
  if (young_strings_.empty()) return;

  FullObjectSlot start(young_strings_.data());
  FullObjectSlot end(young_strings_.data() + young_strings_.size());
  FullObjectSlot last = start;

  for (FullObjectSlot p = start; p < end; ++p) {
    Tagged<String> target = updater_func(heap_, p);

    if (target.is_null()) continue;

    DCHECK(IsExternalString(target));

    if (HeapLayout::InYoungGeneration(target)) {
      // String is still in new space. Update the table entry.
      last.store(target);
      ++last;
    } else {
      // String got promoted. Move it to the old string list.
      old_strings_.push_back(target);
    }
  }

  DCHECK(last <= end);
  young_strings_.resize(last - start);
  if (v8_flags.verify_heap) {
    VerifyYoung();
  }
}

void Heap::ExternalStringTable::PromoteYoung() {
  old_strings_.reserve(old_strings_.size() + young_strings_.size());
  std::move(std::begin(young_strings_), std::end(young_strings_),
            std::back_inserter(old_strings_));
  young_strings_.clear();
}

void Heap::ExternalStringTable::IterateYoung(RootVisitor* v) {
  if (!young_strings_.empty()) {
    v->VisitRootPointers(
        Root::kExternalStringsTable, nullptr,
        FullObjectSlot(young_strings_.data()),
        FullObjectSlot(young_strings_.data() + young_strings_.size()));
  }
}

void Heap::ExternalStringTable::IterateAll(RootVisitor* v) {
  IterateYoung(v);
  if (!old_strings_.empty()) {
    v->VisitRootPointers(
        Root::kExternalStringsTable, nullptr,
        FullObjectSlot(old_strings_.data()),
        FullObjectSlot(old_strings_.data() + old_strings_.size()));
  }
}

void Heap::UpdateYoungReferencesInExternalStringTable(
    ExternalStringTableUpdaterCallback updater_func) {
  external_string_table_.UpdateYoungReferences(updater_func);
}

void Heap::ExternalStringTable::UpdateReferences(
    Heap::ExternalStringTableUpdaterCallback updater_func) {
  if (!old_strings_.empty()) {
    FullObjectSlot start(old_strings_.data());
    FullObjectSlot end(old_strings_.data() + old_strings_.size());
    for (FullObjectSlot p = start; p < end; ++p)
      p.store(updater_func(heap_, p));
  }

  UpdateYoungReferences(updater_func);
}

void Heap::UpdateReferencesInExternalStringTable(
    ExternalStringTableUpdaterCallback updater_func) {
  external_string_table_.UpdateReferences(updater_func);
}

void Heap::ProcessAllWeakReferences(WeakObjectRetainer* retainer) {
  ProcessNativeContexts(retainer);
  ProcessAllocationSites(retainer);
  ProcessDirtyJSFinalizationRegistries(retainer);
}

void Heap::ProcessNativeContexts(WeakObjectRetainer* retainer) {
  Tagged<Object> head =
      VisitWeakList<Context>(this, native_contexts_list(), retainer);
  // Update the head of the list of contexts.
  set_native_contexts_list(head);
}

void Heap::ProcessAllocationSites(WeakObjectRetainer* retainer) {
  Tagged<Object> allocation_site_obj =
      VisitWeakList<AllocationSite>(this, allocation_sites_list(), retainer);
  set_allocation_sites_list(allocation_site_obj);
}

void Heap::ProcessDirtyJSFinalizationRegistries(WeakObjectRetainer* retainer) {
  Tagged<Object> head = VisitWeakList<JSFinalizationRegistry>(
      this, dirty_js_finalization_registries_list(), retainer);
  set_dirty_js_finalization_registries_list(head);
  // If the list is empty, set the tail to undefined. Otherwise the tail is set
  // by WeakListVisitor<JSFinalizationRegistry>::VisitLiveObject.
  if (IsUndefined(head, isolate())) {
    set_dirty_js_finalization_registries_list_tail(head);
  }
}

void Heap::ProcessWeakListRoots(WeakObjectRetainer* retainer) {
  set_native_contexts_list(retainer->RetainAs(native_contexts_list()));
  set_allocation_sites_list(retainer->RetainAs(allocation_sites_list()));
  set_dirty_js_finalization_registries_list(
      retainer->RetainAs(dirty_js_finalization_registries_list()));
  set_dirty_js_finalization_registries_list_tail(
      retainer->RetainAs(dirty_js_finalization_registries_list_tail()));
}

void Heap::ForeachAllocationSite(
    Tagged<Object> list,
    const std::function<void(Tagged<AllocationSite>)>& visitor) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> current = list;
  while (IsAllocationSite(current)) {
    Tagged<AllocationSite> site = Cast<AllocationSite>(current);
    visitor(site);
    Tagged<Object> current_nested = site->nested_site();
    while (IsAllocationSite(current_nested)) {
      Tagged<AllocationSite> nested_site = Cast<AllocationSite>(current_nested);
      visitor(nested_site);
      current_nested = nested_site->nested_site();
    }
    current = site->weak_next();
  }
}

void Heap::ResetAllAllocationSitesDependentCode(AllocationType allocation) {
  DisallowGarbageCollection no_gc_scope;
  bool marked = false;

  ForeachAllocationSite(
      allocation_sites_list(),
      [&marked, allocation, this](Tagged<AllocationSite> site) {
        if (site->GetAllocationType() == allocation) {
          site->ResetPretenureDecision();
          site->set_deopt_dependent_code(true);
          marked = true;
          pretenuring_handler_.RemoveAllocationSitePretenuringFeedback(site);
          return;
        }
      });
  if (marked) isolate_->stack_guard()->RequestDeoptMarkedAllocationSites();
}

void Heap::EvaluateOldSpaceLocalPretenuring(
    uint64_t size_of_objects_before_gc) {
  uint64_t size_of_objects_after_gc = SizeOfObjects();
  double old_generation_survival_rate =
      (static_cast<double>(size_of_objects_after_gc) * 100) /
      static_cast<double>(size_of_objects_before_gc);

  if (old_generation_survival_rate < kOldSurvivalRateLowThreshold) {
    // Too many objects died in the old generation, pretenuring of wrong
    // allocation sites may be the cause for that. We have to deopt all
    // dependent code registered in the allocation sites to re-evaluate
    // our pretenuring decisions.
    ResetAllAllocationSitesDependentCode(AllocationType::kOld);
    if (v8_flags.trace_pretenuring) {
      PrintF(
          "Deopt all allocation sites dependent code due to low survival "
          "rate in the old generation %f\n",
          old_generation_survival_rate);
    }
  }
}

void Heap::VisitExternalResources(v8::ExternalResourceVisitor* visitor) {
  DisallowGarbageCollection no_gc;
  // All external strings are listed in the external string table.

  class ExternalStringTableVisitorAdapter : public RootVisitor {
   public:
    explicit ExternalStringTableVisitorAdapter(
        Isolate* isolate, v8::ExternalResourceVisitor* visitor)
        : isolate_(isolate), visitor_(visitor) {}
    void VisitRootPointers(Root root, const char* description,
                           FullObjectSlot start, FullObjectSlot end) override {
      for (FullObjectSlot p = start; p < end; ++p) {
        DCHECK(IsExternalString(*p));
        visitor_->VisitExternalString(
            Utils::ToLocal(Handle<String>(Cast<String>(*p), isolate_)));
      }
    }

   private:
    Isolate* isolate_;
    v8::ExternalResourceVisitor* visitor_;
  } external_string_table_visitor(isolate(), visitor);

  external_string_table_.IterateAll(&external_string_table_visitor);
}

static_assert(IsAligned(OFFSET_OF_DATA_START(FixedDoubleArray),
                        kDoubleAlignment));

#ifdef V8_COMPRESS_POINTERS
// TODO(ishell, v8:8875): When pointer compression is enabled the kHeaderSize
// is only kTaggedSize aligned but we can keep using unaligned access since
// both x64 and arm64 architectures (where pointer compression supported)
// allow unaligned access to doubles.
static_assert(IsAligned(OFFSET_OF_DATA_START(ByteArray), kTaggedSize));
#else
static_assert(IsAligned(OFFSET_OF_DATA_START(ByteArray), kDoubleAlignment));
#endif

int Heap::GetMaximumFillToAlign(AllocationAlignment alignment) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return 0;
  switch (alignment) {
    case kTaggedAligned:
      return 0;
    case kDoubleAligned:
    case kDoubleUnaligned:
      return kDoubleSize - kTaggedSize;
    default:
      UNREACHABLE();
  }
}

// static
int Heap::GetFillToAlign(Address address, AllocationAlignment alignment) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return 0;
  if (alignment == kDoubleAligned && (address & kDoubleAlignmentMask) != 0)
    return kTaggedSize;
  if (alignment == kDoubleUnaligned && (address & kDoubleAlignmentMask) == 0) {
    return kDoubleSize - kTaggedSize;  // No fill if double is always aligned.
  }
  return 0;
}

size_t Heap::GetCodeRangeReservedAreaSize() {
  return CodeRange::GetWritableReservedAreaSize();
}

Tagged<HeapObject> Heap::PrecedeWithFiller(Tagged<HeapObject> object,
                                           int filler_size) {
  CreateFillerObjectAt(object.address(), filler_size);
  return HeapObject::FromAddress(object.address() + filler_size);
}

Tagged<HeapObject> Heap::PrecedeWithFillerBackground(Tagged<HeapObject> object,
                                                     int filler_size) {
  CreateFillerObjectAtBackground(
      WritableFreeSpace::ForNonExecutableMemory(object.address(), filler_size));
  return HeapObject::FromAddress(object.address() + filler_size);
}

Tagged<HeapObject> Heap::AlignWithFillerBackground(
    Tagged<HeapObject> object, int object_size, int allocation_size,
    AllocationAlignment alignment) {
  const int filler_size = allocation_size - object_size;
  DCHECK_LT(0, filler_size);
  const int pre_filler = GetFillToAlign(object.address(), alignment);
  if (pre_filler) {
    object = PrecedeWithFillerBackground(object, pre_filler);
  }
  DCHECK_LE(0, filler_size - pre_filler);
  const int post_filler = filler_size - pre_filler;
  if (post_filler) {
    CreateFillerObjectAtBackground(WritableFreeSpace::ForNonExecutableMemory(
        object.address() + object_size, post_filler));
  }
  return object;
}

void* Heap::AllocateExternalBackingStore(
    const std::function<void*(size_t)>& allocate, size_t byte_length) {
  if (!always_allocate() && new_space()) {
    size_t new_space_backing_store_bytes =
        new_space()->ExternalBackingStoreOverallBytes();
    if ((!v8_flags.separate_gc_phases ||
         !incremental_marking()->IsMajorMarking()) &&
        new_space_backing_store_bytes >= 2 * DefaultMaxSemiSpaceSize() &&
        new_space_backing_store_bytes >= byte_length) {
      // Performing a young generation GC amortizes over the allocated backing
      // store bytes and may free enough external bytes for this allocation.
      CollectGarbage(NEW_SPACE,
                     GarbageCollectionReason::kExternalMemoryPressure);
    }
  }
  void* result = allocate(byte_length);
  if (result) return result;
  if (!always_allocate()) {
    for (int i = 0; i < 2; i++) {
      CollectGarbage(OLD_SPACE,
                     GarbageCollectionReason::kExternalMemoryPressure);
      result = allocate(byte_length);
      if (result) return result;
    }
    CollectAllAvailableGarbage(
        GarbageCollectionReason::kExternalMemoryPressure);
  }
  return allocate(byte_length);
}

// When old generation allocation limit is not configured (before the first full
// GC), this method shrinks the initial very large old generation size. This
// method can only shrink allocation limits but not increase it again.
void Heap::ShrinkOldGenerationAllocationLimitIfNotConfigured() {
  if (using_initial_limit() && !initial_limit_overwritten_ &&
      tracer()->SurvivalEventsRecorded()) {
    const size_t minimum_growing_step =
        MemoryController<V8HeapTrait>::MinimumAllocationLimitGrowingStep(
            CurrentHeapGrowingMode());
    size_t new_old_generation_allocation_limit =
        std::max(OldGenerationConsumedBytes() + minimum_growing_step,
                 static_cast<size_t>(
                     static_cast<double>(old_generation_allocation_limit()) *
                     (tracer()->AverageSurvivalRatio() / 100)));
    new_old_generation_allocation_limit = std::min(
        new_old_generation_allocation_limit, old_generation_allocation_limit());
    size_t new_global_allocation_limit = std::max(
        GlobalConsumedBytes() + minimum_growing_step,
        static_cast<size_t>(static_cast<double>(global_allocation_limit()) *
                            (tracer()->AverageSurvivalRatio() / 100)));
    new_global_allocation_limit =
        std::min(new_global_allocation_limit, global_allocation_limit());
    SetOldGenerationAndGlobalAllocationLimit(
        new_old_generation_allocation_limit, new_global_allocation_limit);
  }
}

void Heap::FlushNumberStringCache() {
  // Flush the number to string cache.
  int len = number_string_cache()->length();
  ReadOnlyRoots roots{isolate()};
  for (int i = 0; i < len; i++) {
    number_string_cache()->set(i, roots.undefined_value(), SKIP_WRITE_BARRIER);
  }
}

namespace {

void CreateFillerObjectAtImpl(const WritableFreeSpace& free_space, Heap* heap,
                              ClearFreedMemoryMode clear_memory_mode) {
  int size = free_space.Size();
  if (size == 0) return;
  DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                 IsAligned(free_space.Address(), kObjectAlignment8GbHeap));
  DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                 IsAligned(size, kObjectAlignment8GbHeap));

  // TODO(v8:13070): Filler sizes are irrelevant for 8GB+ heaps. Adding them
  // should be avoided in this mode.
  ReadOnlyRoots roots(heap);
  if (size == kTaggedSize) {
    HeapObject::SetFillerMap(free_space,
                             roots.unchecked_one_pointer_filler_map());
    // Ensure the filler map is properly initialized.
    DCHECK(IsMap(
        HeapObject::FromAddress(free_space.Address())->map(heap->isolate())));
  } else if (size == 2 * kTaggedSize) {
    HeapObject::SetFillerMap(free_space,
                             roots.unchecked_
Prompt: 
```
这是目录为v8/src/heap/heap.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/heap.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能

"""
  auto new_limits = ComputeNewAllocationLimits(this);
  size_t new_old_generation_allocation_limit =
      new_limits.old_generation_allocation_limit;
  size_t new_global_allocation_limit = new_limits.global_allocation_limit;

  new_old_generation_allocation_limit = std::max(
      new_old_generation_allocation_limit, old_generation_allocation_limit());
  new_global_allocation_limit =
      std::max(new_global_allocation_limit, global_allocation_limit());
  SetOldGenerationAndGlobalAllocationLimit(new_old_generation_allocation_limit,
                                           new_global_allocation_limit);

  CHECK_EQ(max_global_memory_size_,
           GlobalMemorySizeFromV8Size(max_old_generation_size_));
  CHECK_GE(global_allocation_limit(), old_generation_allocation_limit_);
}

void Heap::CallGCPrologueCallbacks(GCType gc_type, GCCallbackFlags flags,
                                   GCTracer::Scope::ScopeId scope_id) {
  if (gc_prologue_callbacks_.IsEmpty()) return;

  GCCallbacksScope scope(this);
  if (scope.CheckReenter()) {
    RCS_SCOPE(isolate(), RuntimeCallCounterId::kGCPrologueCallback);
    TRACE_GC(tracer(), scope_id);
    HandleScope handle_scope(isolate());
    gc_prologue_callbacks_.Invoke(gc_type, flags);
  }
}

void Heap::CallGCEpilogueCallbacks(GCType gc_type, GCCallbackFlags flags,
                                   GCTracer::Scope::ScopeId scope_id) {
  if (gc_epilogue_callbacks_.IsEmpty()) return;

  GCCallbacksScope scope(this);
  if (scope.CheckReenter()) {
    RCS_SCOPE(isolate(), RuntimeCallCounterId::kGCEpilogueCallback);
    TRACE_GC(tracer(), scope_id);
    HandleScope handle_scope(isolate());
    gc_epilogue_callbacks_.Invoke(gc_type, flags);
  }
}

void Heap::MarkCompact() {
  SetGCState(MARK_COMPACT);

  PROFILE(isolate_, CodeMovingGCEvent());

  UpdateOldGenerationAllocationCounter();
  uint64_t size_of_objects_before_gc = SizeOfObjects();

  mark_compact_collector()->Prepare();

  ms_count_++;
  contexts_disposed_ = 0;

  MarkCompactPrologue();

  mark_compact_collector()->CollectGarbage();

  MarkCompactEpilogue();

  if (v8_flags.allocation_site_pretenuring) {
    EvaluateOldSpaceLocalPretenuring(size_of_objects_before_gc);
  }
  // This should be updated before PostGarbageCollectionProcessing, which
  // can cause another GC. Take into account the objects promoted during
  // GC.
  old_generation_allocation_counter_at_last_gc_ +=
      static_cast<size_t>(promoted_objects_size_);
  old_generation_size_at_last_gc_ = OldGenerationSizeOfObjects();
  old_generation_wasted_at_last_gc_ = OldGenerationWastedBytes();
  external_memory_.UpdateLowSinceMarkCompact(external_memory_.total());
  embedder_size_at_last_gc_ = EmbedderSizeOfObjects();
  // Limits can now be computed based on estimate from MARK_COMPACT.
  set_using_initial_limit(false);
}

void Heap::MinorMarkSweep() {
  DCHECK(v8_flags.minor_ms);
  CHECK_EQ(NOT_IN_GC, gc_state());
  DCHECK(use_new_space());
  DCHECK(!incremental_marking()->IsMajorMarking());

  TRACE_GC(tracer(), GCTracer::Scope::MINOR_MS);

  SetGCState(MINOR_MARK_SWEEP);
  minor_mark_sweep_collector_->CollectGarbage();
  SetGCState(NOT_IN_GC);
}

void Heap::MarkCompactEpilogue() {
  TRACE_GC(tracer(), GCTracer::Scope::MC_EPILOGUE);
  SetGCState(NOT_IN_GC);

  isolate_->counters()->objs_since_last_full()->Set(0);
}

void Heap::MarkCompactPrologue() {
  TRACE_GC(tracer(), GCTracer::Scope::MC_PROLOGUE);
  isolate_->descriptor_lookup_cache()->Clear();
  RegExpResultsCache::Clear(string_split_cache());
  RegExpResultsCache::Clear(regexp_multiple_cache());
  RegExpResultsCache_MatchGlobalAtom::Clear(this);

  FlushNumberStringCache();
}

void Heap::Scavenge() {
  DCHECK_NOT_NULL(new_space());
  DCHECK_IMPLIES(v8_flags.separate_gc_phases,
                 !incremental_marking()->IsMarking());

  if (v8_flags.trace_incremental_marking &&
      !incremental_marking()->IsStopped()) {
    isolate()->PrintWithTimestamp(
        "[IncrementalMarking] Scavenge during marking.\n");
  }

  TRACE_GC(tracer(), GCTracer::Scope::SCAVENGER_SCAVENGE);
  base::MutexGuard guard(relocation_mutex());
  // Young generation garbage collection is orthogonal from full GC marking. It
  // is possible that objects that are currently being processed for marking are
  // reclaimed in the young generation GC that interleaves concurrent marking.
  // Pause concurrent markers to allow processing them using
  // `UpdateMarkingWorklistAfterYoungGenGC()`.
  ConcurrentMarking::PauseScope pause_js_marking(concurrent_marking());
  CppHeap::PauseConcurrentMarkingScope pause_cpp_marking(
      CppHeap::From(cpp_heap_));

  // Bump-pointer allocations done during scavenge are not real allocations.
  // Pause the inline allocation steps.
  IncrementalMarking::PauseBlackAllocationScope pause_black_allocation(
      incremental_marking());

  SetGCState(SCAVENGE);

  // Implements Cheney's copying algorithm
  scavenger_collector_->CollectGarbage();

  SetGCState(NOT_IN_GC);
}

bool Heap::ExternalStringTable::Contains(Tagged<String> string) {
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    if (young_strings_[i] == string) return true;
  }
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    if (old_strings_[i] == string) return true;
  }
  return false;
}

void Heap::UpdateExternalString(Tagged<String> string, size_t old_payload,
                                size_t new_payload) {
  DCHECK(IsExternalString(string));

  PageMetadata* page = PageMetadata::FromHeapObject(string);

  if (old_payload > new_payload) {
    page->DecrementExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString, old_payload - new_payload);
  } else {
    page->IncrementExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString, new_payload - old_payload);
  }
}

Tagged<String> Heap::UpdateYoungReferenceInExternalStringTableEntry(
    Heap* heap, FullObjectSlot p) {
  // This is only used for Scavenger.
  DCHECK(!v8_flags.minor_ms);

  PtrComprCageBase cage_base(heap->isolate());
  Tagged<HeapObject> obj = Cast<HeapObject>(*p);
  MapWord first_word = obj->map_word(cage_base, kRelaxedLoad);

  Tagged<String> new_string;

  if (InFromPage(obj)) {
    if (!first_word.IsForwardingAddress()) {
      // Unreachable external string can be finalized.
      Tagged<String> string = Cast<String>(obj);
      if (!IsExternalString(string, cage_base)) {
        // Original external string has been internalized.
        DCHECK(IsThinString(string, cage_base));
        return Tagged<String>();
      }
      heap->FinalizeExternalString(string);
      return Tagged<String>();
    }
    new_string = Cast<String>(first_word.ToForwardingAddress(obj));
  } else {
    new_string = Cast<String>(obj);
  }

  // String is still reachable.
  if (IsThinString(new_string, cage_base)) {
    // Filtering Thin strings out of the external string table.
    return Tagged<String>();
  } else if (IsExternalString(new_string, cage_base)) {
    MutablePageMetadata::MoveExternalBackingStoreBytes(
        ExternalBackingStoreType::kExternalString,
        PageMetadata::FromAddress((*p).ptr()),
        PageMetadata::FromHeapObject(new_string),
        Cast<ExternalString>(new_string)->ExternalPayloadSize());
    return new_string;
  }

  // Internalization can replace external strings with non-external strings.
  return IsExternalString(new_string, cage_base) ? new_string
                                                 : Tagged<String>();
}

void Heap::ExternalStringTable::VerifyYoung() {
#ifdef DEBUG
  std::set<Tagged<String>> visited_map;
  std::map<MutablePageMetadata*, size_t> size_map;
  ExternalBackingStoreType type = ExternalBackingStoreType::kExternalString;
  for (size_t i = 0; i < young_strings_.size(); ++i) {
    Tagged<String> obj = Cast<String>(Tagged<Object>(young_strings_[i]));
    MutablePageMetadata* mc = MutablePageMetadata::FromHeapObject(obj);
    DCHECK_IMPLIES(!v8_flags.sticky_mark_bits,
                   mc->Chunk()->InYoungGeneration());
    DCHECK(HeapLayout::InYoungGeneration(obj));
    DCHECK(!IsTheHole(obj, heap_->isolate()));
    DCHECK(IsExternalString(obj));
    // Note: we can have repeated elements in the table.
    DCHECK_EQ(0, visited_map.count(obj));
    visited_map.insert(obj);
    size_map[mc] += Cast<ExternalString>(obj)->ExternalPayloadSize();
  }
  for (std::map<MutablePageMetadata*, size_t>::iterator it = size_map.begin();
       it != size_map.end(); it++)
    DCHECK_EQ(it->first->ExternalBackingStoreBytes(type), it->second);
#endif
}

void Heap::ExternalStringTable::Verify() {
#ifdef DEBUG
  std::set<Tagged<String>> visited_map;
  std::map<MutablePageMetadata*, size_t> size_map;
  ExternalBackingStoreType type = ExternalBackingStoreType::kExternalString;
  VerifyYoung();
  for (size_t i = 0; i < old_strings_.size(); ++i) {
    Tagged<String> obj = Cast<String>(Tagged<Object>(old_strings_[i]));
    MutablePageMetadata* mc = MutablePageMetadata::FromHeapObject(obj);
    DCHECK_IMPLIES(!v8_flags.sticky_mark_bits,
                   !mc->Chunk()->InYoungGeneration());
    DCHECK(!HeapLayout::InYoungGeneration(obj));
    DCHECK(!IsTheHole(obj, heap_->isolate()));
    DCHECK(IsExternalString(obj));
    // Note: we can have repeated elements in the table.
    DCHECK_EQ(0, visited_map.count(obj));
    visited_map.insert(obj);
    size_map[mc] += Cast<ExternalString>(obj)->ExternalPayloadSize();
  }
  for (std::map<MutablePageMetadata*, size_t>::iterator it = size_map.begin();
       it != size_map.end(); it++)
    DCHECK_EQ(it->first->ExternalBackingStoreBytes(type), it->second);
#endif
}

void Heap::ExternalStringTable::UpdateYoungReferences(
    Heap::ExternalStringTableUpdaterCallback updater_func) {
  if (young_strings_.empty()) return;

  FullObjectSlot start(young_strings_.data());
  FullObjectSlot end(young_strings_.data() + young_strings_.size());
  FullObjectSlot last = start;

  for (FullObjectSlot p = start; p < end; ++p) {
    Tagged<String> target = updater_func(heap_, p);

    if (target.is_null()) continue;

    DCHECK(IsExternalString(target));

    if (HeapLayout::InYoungGeneration(target)) {
      // String is still in new space. Update the table entry.
      last.store(target);
      ++last;
    } else {
      // String got promoted. Move it to the old string list.
      old_strings_.push_back(target);
    }
  }

  DCHECK(last <= end);
  young_strings_.resize(last - start);
  if (v8_flags.verify_heap) {
    VerifyYoung();
  }
}

void Heap::ExternalStringTable::PromoteYoung() {
  old_strings_.reserve(old_strings_.size() + young_strings_.size());
  std::move(std::begin(young_strings_), std::end(young_strings_),
            std::back_inserter(old_strings_));
  young_strings_.clear();
}

void Heap::ExternalStringTable::IterateYoung(RootVisitor* v) {
  if (!young_strings_.empty()) {
    v->VisitRootPointers(
        Root::kExternalStringsTable, nullptr,
        FullObjectSlot(young_strings_.data()),
        FullObjectSlot(young_strings_.data() + young_strings_.size()));
  }
}

void Heap::ExternalStringTable::IterateAll(RootVisitor* v) {
  IterateYoung(v);
  if (!old_strings_.empty()) {
    v->VisitRootPointers(
        Root::kExternalStringsTable, nullptr,
        FullObjectSlot(old_strings_.data()),
        FullObjectSlot(old_strings_.data() + old_strings_.size()));
  }
}

void Heap::UpdateYoungReferencesInExternalStringTable(
    ExternalStringTableUpdaterCallback updater_func) {
  external_string_table_.UpdateYoungReferences(updater_func);
}

void Heap::ExternalStringTable::UpdateReferences(
    Heap::ExternalStringTableUpdaterCallback updater_func) {
  if (!old_strings_.empty()) {
    FullObjectSlot start(old_strings_.data());
    FullObjectSlot end(old_strings_.data() + old_strings_.size());
    for (FullObjectSlot p = start; p < end; ++p)
      p.store(updater_func(heap_, p));
  }

  UpdateYoungReferences(updater_func);
}

void Heap::UpdateReferencesInExternalStringTable(
    ExternalStringTableUpdaterCallback updater_func) {
  external_string_table_.UpdateReferences(updater_func);
}

void Heap::ProcessAllWeakReferences(WeakObjectRetainer* retainer) {
  ProcessNativeContexts(retainer);
  ProcessAllocationSites(retainer);
  ProcessDirtyJSFinalizationRegistries(retainer);
}

void Heap::ProcessNativeContexts(WeakObjectRetainer* retainer) {
  Tagged<Object> head =
      VisitWeakList<Context>(this, native_contexts_list(), retainer);
  // Update the head of the list of contexts.
  set_native_contexts_list(head);
}

void Heap::ProcessAllocationSites(WeakObjectRetainer* retainer) {
  Tagged<Object> allocation_site_obj =
      VisitWeakList<AllocationSite>(this, allocation_sites_list(), retainer);
  set_allocation_sites_list(allocation_site_obj);
}

void Heap::ProcessDirtyJSFinalizationRegistries(WeakObjectRetainer* retainer) {
  Tagged<Object> head = VisitWeakList<JSFinalizationRegistry>(
      this, dirty_js_finalization_registries_list(), retainer);
  set_dirty_js_finalization_registries_list(head);
  // If the list is empty, set the tail to undefined. Otherwise the tail is set
  // by WeakListVisitor<JSFinalizationRegistry>::VisitLiveObject.
  if (IsUndefined(head, isolate())) {
    set_dirty_js_finalization_registries_list_tail(head);
  }
}

void Heap::ProcessWeakListRoots(WeakObjectRetainer* retainer) {
  set_native_contexts_list(retainer->RetainAs(native_contexts_list()));
  set_allocation_sites_list(retainer->RetainAs(allocation_sites_list()));
  set_dirty_js_finalization_registries_list(
      retainer->RetainAs(dirty_js_finalization_registries_list()));
  set_dirty_js_finalization_registries_list_tail(
      retainer->RetainAs(dirty_js_finalization_registries_list_tail()));
}

void Heap::ForeachAllocationSite(
    Tagged<Object> list,
    const std::function<void(Tagged<AllocationSite>)>& visitor) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> current = list;
  while (IsAllocationSite(current)) {
    Tagged<AllocationSite> site = Cast<AllocationSite>(current);
    visitor(site);
    Tagged<Object> current_nested = site->nested_site();
    while (IsAllocationSite(current_nested)) {
      Tagged<AllocationSite> nested_site = Cast<AllocationSite>(current_nested);
      visitor(nested_site);
      current_nested = nested_site->nested_site();
    }
    current = site->weak_next();
  }
}

void Heap::ResetAllAllocationSitesDependentCode(AllocationType allocation) {
  DisallowGarbageCollection no_gc_scope;
  bool marked = false;

  ForeachAllocationSite(
      allocation_sites_list(),
      [&marked, allocation, this](Tagged<AllocationSite> site) {
        if (site->GetAllocationType() == allocation) {
          site->ResetPretenureDecision();
          site->set_deopt_dependent_code(true);
          marked = true;
          pretenuring_handler_.RemoveAllocationSitePretenuringFeedback(site);
          return;
        }
      });
  if (marked) isolate_->stack_guard()->RequestDeoptMarkedAllocationSites();
}

void Heap::EvaluateOldSpaceLocalPretenuring(
    uint64_t size_of_objects_before_gc) {
  uint64_t size_of_objects_after_gc = SizeOfObjects();
  double old_generation_survival_rate =
      (static_cast<double>(size_of_objects_after_gc) * 100) /
      static_cast<double>(size_of_objects_before_gc);

  if (old_generation_survival_rate < kOldSurvivalRateLowThreshold) {
    // Too many objects died in the old generation, pretenuring of wrong
    // allocation sites may be the cause for that. We have to deopt all
    // dependent code registered in the allocation sites to re-evaluate
    // our pretenuring decisions.
    ResetAllAllocationSitesDependentCode(AllocationType::kOld);
    if (v8_flags.trace_pretenuring) {
      PrintF(
          "Deopt all allocation sites dependent code due to low survival "
          "rate in the old generation %f\n",
          old_generation_survival_rate);
    }
  }
}

void Heap::VisitExternalResources(v8::ExternalResourceVisitor* visitor) {
  DisallowGarbageCollection no_gc;
  // All external strings are listed in the external string table.

  class ExternalStringTableVisitorAdapter : public RootVisitor {
   public:
    explicit ExternalStringTableVisitorAdapter(
        Isolate* isolate, v8::ExternalResourceVisitor* visitor)
        : isolate_(isolate), visitor_(visitor) {}
    void VisitRootPointers(Root root, const char* description,
                           FullObjectSlot start, FullObjectSlot end) override {
      for (FullObjectSlot p = start; p < end; ++p) {
        DCHECK(IsExternalString(*p));
        visitor_->VisitExternalString(
            Utils::ToLocal(Handle<String>(Cast<String>(*p), isolate_)));
      }
    }

   private:
    Isolate* isolate_;
    v8::ExternalResourceVisitor* visitor_;
  } external_string_table_visitor(isolate(), visitor);

  external_string_table_.IterateAll(&external_string_table_visitor);
}

static_assert(IsAligned(OFFSET_OF_DATA_START(FixedDoubleArray),
                        kDoubleAlignment));

#ifdef V8_COMPRESS_POINTERS
// TODO(ishell, v8:8875): When pointer compression is enabled the kHeaderSize
// is only kTaggedSize aligned but we can keep using unaligned access since
// both x64 and arm64 architectures (where pointer compression supported)
// allow unaligned access to doubles.
static_assert(IsAligned(OFFSET_OF_DATA_START(ByteArray), kTaggedSize));
#else
static_assert(IsAligned(OFFSET_OF_DATA_START(ByteArray), kDoubleAlignment));
#endif

int Heap::GetMaximumFillToAlign(AllocationAlignment alignment) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return 0;
  switch (alignment) {
    case kTaggedAligned:
      return 0;
    case kDoubleAligned:
    case kDoubleUnaligned:
      return kDoubleSize - kTaggedSize;
    default:
      UNREACHABLE();
  }
}

// static
int Heap::GetFillToAlign(Address address, AllocationAlignment alignment) {
  if (V8_COMPRESS_POINTERS_8GB_BOOL) return 0;
  if (alignment == kDoubleAligned && (address & kDoubleAlignmentMask) != 0)
    return kTaggedSize;
  if (alignment == kDoubleUnaligned && (address & kDoubleAlignmentMask) == 0) {
    return kDoubleSize - kTaggedSize;  // No fill if double is always aligned.
  }
  return 0;
}

size_t Heap::GetCodeRangeReservedAreaSize() {
  return CodeRange::GetWritableReservedAreaSize();
}

Tagged<HeapObject> Heap::PrecedeWithFiller(Tagged<HeapObject> object,
                                           int filler_size) {
  CreateFillerObjectAt(object.address(), filler_size);
  return HeapObject::FromAddress(object.address() + filler_size);
}

Tagged<HeapObject> Heap::PrecedeWithFillerBackground(Tagged<HeapObject> object,
                                                     int filler_size) {
  CreateFillerObjectAtBackground(
      WritableFreeSpace::ForNonExecutableMemory(object.address(), filler_size));
  return HeapObject::FromAddress(object.address() + filler_size);
}

Tagged<HeapObject> Heap::AlignWithFillerBackground(
    Tagged<HeapObject> object, int object_size, int allocation_size,
    AllocationAlignment alignment) {
  const int filler_size = allocation_size - object_size;
  DCHECK_LT(0, filler_size);
  const int pre_filler = GetFillToAlign(object.address(), alignment);
  if (pre_filler) {
    object = PrecedeWithFillerBackground(object, pre_filler);
  }
  DCHECK_LE(0, filler_size - pre_filler);
  const int post_filler = filler_size - pre_filler;
  if (post_filler) {
    CreateFillerObjectAtBackground(WritableFreeSpace::ForNonExecutableMemory(
        object.address() + object_size, post_filler));
  }
  return object;
}

void* Heap::AllocateExternalBackingStore(
    const std::function<void*(size_t)>& allocate, size_t byte_length) {
  if (!always_allocate() && new_space()) {
    size_t new_space_backing_store_bytes =
        new_space()->ExternalBackingStoreOverallBytes();
    if ((!v8_flags.separate_gc_phases ||
         !incremental_marking()->IsMajorMarking()) &&
        new_space_backing_store_bytes >= 2 * DefaultMaxSemiSpaceSize() &&
        new_space_backing_store_bytes >= byte_length) {
      // Performing a young generation GC amortizes over the allocated backing
      // store bytes and may free enough external bytes for this allocation.
      CollectGarbage(NEW_SPACE,
                     GarbageCollectionReason::kExternalMemoryPressure);
    }
  }
  void* result = allocate(byte_length);
  if (result) return result;
  if (!always_allocate()) {
    for (int i = 0; i < 2; i++) {
      CollectGarbage(OLD_SPACE,
                     GarbageCollectionReason::kExternalMemoryPressure);
      result = allocate(byte_length);
      if (result) return result;
    }
    CollectAllAvailableGarbage(
        GarbageCollectionReason::kExternalMemoryPressure);
  }
  return allocate(byte_length);
}

// When old generation allocation limit is not configured (before the first full
// GC), this method shrinks the initial very large old generation size. This
// method can only shrink allocation limits but not increase it again.
void Heap::ShrinkOldGenerationAllocationLimitIfNotConfigured() {
  if (using_initial_limit() && !initial_limit_overwritten_ &&
      tracer()->SurvivalEventsRecorded()) {
    const size_t minimum_growing_step =
        MemoryController<V8HeapTrait>::MinimumAllocationLimitGrowingStep(
            CurrentHeapGrowingMode());
    size_t new_old_generation_allocation_limit =
        std::max(OldGenerationConsumedBytes() + minimum_growing_step,
                 static_cast<size_t>(
                     static_cast<double>(old_generation_allocation_limit()) *
                     (tracer()->AverageSurvivalRatio() / 100)));
    new_old_generation_allocation_limit = std::min(
        new_old_generation_allocation_limit, old_generation_allocation_limit());
    size_t new_global_allocation_limit = std::max(
        GlobalConsumedBytes() + minimum_growing_step,
        static_cast<size_t>(static_cast<double>(global_allocation_limit()) *
                            (tracer()->AverageSurvivalRatio() / 100)));
    new_global_allocation_limit =
        std::min(new_global_allocation_limit, global_allocation_limit());
    SetOldGenerationAndGlobalAllocationLimit(
        new_old_generation_allocation_limit, new_global_allocation_limit);
  }
}

void Heap::FlushNumberStringCache() {
  // Flush the number to string cache.
  int len = number_string_cache()->length();
  ReadOnlyRoots roots{isolate()};
  for (int i = 0; i < len; i++) {
    number_string_cache()->set(i, roots.undefined_value(), SKIP_WRITE_BARRIER);
  }
}

namespace {

void CreateFillerObjectAtImpl(const WritableFreeSpace& free_space, Heap* heap,
                              ClearFreedMemoryMode clear_memory_mode) {
  int size = free_space.Size();
  if (size == 0) return;
  DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                 IsAligned(free_space.Address(), kObjectAlignment8GbHeap));
  DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                 IsAligned(size, kObjectAlignment8GbHeap));

  // TODO(v8:13070): Filler sizes are irrelevant for 8GB+ heaps. Adding them
  // should be avoided in this mode.
  ReadOnlyRoots roots(heap);
  if (size == kTaggedSize) {
    HeapObject::SetFillerMap(free_space,
                             roots.unchecked_one_pointer_filler_map());
    // Ensure the filler map is properly initialized.
    DCHECK(IsMap(
        HeapObject::FromAddress(free_space.Address())->map(heap->isolate())));
  } else if (size == 2 * kTaggedSize) {
    HeapObject::SetFillerMap(free_space,
                             roots.unchecked_two_pointer_filler_map());
    if (clear_memory_mode == ClearFreedMemoryMode::kClearFreedMemory) {
      free_space.ClearTagged<kTaggedSize>((size / kTaggedSize) - 1);
    }
    // Ensure the filler map is properly initialized.
    DCHECK(IsMap(
        HeapObject::FromAddress(free_space.Address())->map(heap->isolate())));
  } else {
    DCHECK_GT(size, 2 * kTaggedSize);
    HeapObject::SetFillerMap(free_space, roots.unchecked_free_space_map());
    FreeSpace::SetSize(free_space, size, kRelaxedStore);
    if (clear_memory_mode == ClearFreedMemoryMode::kClearFreedMemory) {
      free_space.ClearTagged<2 * kTaggedSize>((size / kTaggedSize) - 2);
    }

    // During bootstrapping we need to create a free space object before its
    // map is initialized. In this case we cannot access the map yet, as it
    // might be null, or not set up properly yet.
    DCHECK_IMPLIES(roots.is_initialized(RootIndex::kFreeSpaceMap),
                   IsMap(HeapObject::FromAddress(free_space.Address())
                             ->map(heap->isolate())));
  }
}

#ifdef DEBUG
void VerifyNoNeedToClearSlots(Address start, Address end) {
  MemoryChunk* chunk = MemoryChunk::FromAddress(start);
  if (chunk->InReadOnlySpace()) return;
  if (!v8_flags.sticky_mark_bits && chunk->InYoungGeneration()) return;
  MutablePageMetadata* mutable_page =
      MutablePageMetadata::cast(chunk->Metadata());
  BaseSpace* space = mutable_page->owner();
  space->heap()->VerifySlotRangeHasNoRecordedSlots(start, end);
}
#else
void VerifyNoNeedToClearSlots(Address start, Address end) {}
#endif  // DEBUG

}  // namespace

void Heap::CreateFillerObjectAtBackground(const WritableFreeSpace& free_space) {
  // TODO(leszeks): Verify that no slots need to be recorded.
  // Do not verify whether slots are cleared here: the concurrent thread is not
  // allowed to access the main thread's remembered set.
  CreateFillerObjectAtRaw(free_space,
                          ClearFreedMemoryMode::kDontClearFreedMemory,
                          ClearRecordedSlots::kNo, VerifyNoSlotsRecorded::kNo);
}

void Heap::CreateFillerObjectAt(Address addr, int size,
                                ClearFreedMemoryMode clear_memory_mode) {
  if (size == 0) return;
  if (MemoryChunk::FromAddress(addr)->executable()) {
    WritableJitPage jit_page(addr, size);
    WritableFreeSpace free_space = jit_page.FreeRange(addr, size);
    CreateFillerObjectAtRaw(free_space, clear_memory_mode,
                            ClearRecordedSlots::kNo,
                            VerifyNoSlotsRecorded::kYes);
  } else {
    WritableFreeSpace free_space =
        WritableFreeSpace::ForNonExecutableMemory(addr, size);
    CreateFillerObjectAtRaw(free_space, clear_memory_mode,
                            ClearRecordedSlots::kNo,
                            VerifyNoSlotsRecorded::kYes);
  }
}

void Heap::CreateFillerObjectAtRaw(
    const WritableFreeSpace& free_space, ClearFreedMemoryMode clear_memory_mode,
    ClearRecordedSlots clear_slots_mode,
    VerifyNoSlotsRecorded verify_no_slots_recorded) {
  // TODO(mlippautz): It would be nice to DCHECK that we never call this
  // with {addr} pointing into large object space; however we currently do,
  // see, e.g., Factory::NewFillerObject and in many tests.
  size_t size = free_space.Size();
  if (size == 0) return;
  CreateFillerObjectAtImpl(free_space, this, clear_memory_mode);
  Address addr = free_space.Address();
  if (clear_slots_mode == ClearRecordedSlots::kYes) {
    ClearRecordedSlotRange(addr, addr + size);
  } else if (verify_no_slots_recorded == VerifyNoSlotsRecorded::kYes) {
    VerifyNoNeedToClearSlots(addr, addr + size);
  }
}

bool Heap::CanMoveObjectStart(Tagged<HeapObject> object) {
  if (!v8_flags.move_object_start) return false;

  // Sampling heap profiler may have a reference to the object.
  if (isolate()->heap_profiler()->is_sampling_allocations()) return false;

  if (IsLargeObject(object)) return false;

  // Compilation jobs may have references to the object.
  if (isolate()->concurrent_recompilation_enabled() &&
      isolate()->optimizing_compile_dispatcher()->HasJobs()) {
    return false;
  }

  // Concurrent marking does not support moving object starts without snapshot
  // protocol.
  //
  // TODO(v8:13726): This can be improved via concurrently reading the contents
  // in the marker at the cost of some complexity.
  if (incremental_marking()->IsMarking()) return false;

  // Concurrent sweeper does not support moving object starts. It assumes that
  // markbits (black regions) and object starts are matching up.
  if (!PageMetadata::FromHeapObject(object)->SweepingDone()) return false;

  return true;
}

bool Heap::IsImmovable(Tagged<HeapObject> object) {
  MemoryChunk* chunk = MemoryChunk::FromHeapObject(object);
  return chunk->NeverEvacuate() || chunk->IsLargePage();
}

bool Heap::IsLargeObject(Tagged<HeapObject> object) {
  return MemoryChunk::FromHeapObject(object)->IsLargePage();
}

#ifdef ENABLE_SLOW_DCHECKS
namespace {

class LeftTrimmerVerifierRootVisitor : public RootVisitor {
 public:
  explicit LeftTrimmerVerifierRootVisitor(Tagged<FixedArrayBase> to_check)
      : to_check_(to_check) {}

  LeftTrimmerVerifierRootVisitor(const LeftTrimmerVerifierRootVisitor&) =
      delete;
  LeftTrimmerVerifierRootVisitor& operator=(
      const LeftTrimmerVerifierRootVisitor&) = delete;

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      // V8_EXTERNAL_CODE_SPACE specific: we might be comparing
      // InstructionStream object with non-InstructionStream object here and it
      // might produce false positives because operator== for tagged values
      // compares only lower 32 bits when pointer compression is enabled.
      DCHECK_NE((*p).ptr(), to_check_.ptr());
    }
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK(root == Root::kStringTable ||
           root == Root::kSharedStructTypeRegistry);
    // We can skip iterating the string table and shared struct type registry,
    // they don't point to any fixed arrays.
  }

 private:
  Tagged<FixedArrayBase> to_check_;
};
}  // namespace
#endif  // ENABLE_SLOW_DCHECKS

namespace {
bool MayContainRecordedSlots(Tagged<HeapObject> object) {
  // New space object do not have recorded slots.
  if (HeapLayout::InYoungGeneration(object)) {
    return false;
  }
  // Allowlist objects that definitely do not have pointers.
  if (IsByteArray(object) || IsFixedDoubleArray(object)) return false;
  // Conservatively return true for other objects.
  return true;
}
}  // namespace

void Heap::OnMoveEvent(Tagged<HeapObject> source, Tagged<HeapObject> target,
                       int size_in_bytes) {
  HeapProfiler* heap_profiler = isolate_->heap_profiler();
  if (heap_profiler->is_tracking_object_moves()) {
    heap_profiler->ObjectMoveEvent(source.address(), target.address(),
                                   size_in_bytes, /*is_embedder_object=*/false);
  }
  for (auto& tracker : allocation_trackers_) {
    tracker->MoveEvent(source.address(), target.address(), size_in_bytes);
  }
  if (IsSharedFunctionInfo(target, isolate_)) {
    LOG_CODE_EVENT(isolate_, SharedFunctionInfoMoveEvent(source.address(),
                                                         target.address()));
  } else if (IsNativeContext(target, isolate_)) {
    if (isolate_->current_embedder_state() != nullptr) {
      isolate_->current_embedder_state()->OnMoveEvent(source.address(),
                                                      target.address());
    }
    PROFILE(isolate_,
            NativeContextMoveEvent(source.address(), target.address()));
  } else if (IsMap(target, isolate_)) {
    LOG(isolate_, MapMoveEvent(Cast<Map>(source), Cast<Map>(target)));
  }
}

Tagged<FixedArrayBase> Heap::LeftTrimFixedArray(Tagged<FixedArrayBase> object,
                                                int elements_to_trim) {
  if (elements_to_trim == 0) {
    // This simplifies reasoning in the rest of the function.
    return object;
  }
  CHECK(!object.is_null());
  DCHECK(CanMoveObjectStart(object));
  // Add custom visitor to concurrent marker if new left-trimmable type
  // is added.
  DCHECK(IsFixedArray(object) || IsFixedDoubleArray(object));
  const int element_size = IsFixedArray(object) ? kTaggedSize : kDoubleSize;
  const int bytes_to_trim = elements_to_trim * element_size;
  Tagged<Map> map = object->map();

  // For now this trick is only applied to fixed arrays which may be in new
  // space or old space. In a large object space the object's start must
  // coincide with chunk and thus the trick is just not applicable.
  DCHECK(!IsLargeObject(object));
  DCHECK(object->map() != ReadOnlyRoots(this).fixed_cow_array_map());

  static_assert(offsetof(FixedArrayBase, map_) == 0);
  static_assert(offsetof(FixedArrayBase, length_) == kTaggedSize);
  static_assert(sizeof(FixedArrayBase) == 2 * kTaggedSize);

  const int len = object->length();
  DCHECK(elements_to_trim <= len);

  // Calculate location of new array start.
  Address old_start = object.address();
  A
"""


```