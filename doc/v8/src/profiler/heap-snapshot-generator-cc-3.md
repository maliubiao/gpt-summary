Response:
The user wants a summary of the provided C++ code snippet, focusing on its functionality within the V8 JavaScript engine. Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the Core Purpose:** The filename "heap-snapshot-generator.cc" immediately suggests this code is responsible for creating heap snapshots. The presence of classes like `V8HeapExplorer`, `HeapEntry`, and methods like `ExtractReferences` confirms this.

2. **Analyze Key Classes:**
    * **`V8HeapExplorer`:** This class seems to be the primary driver for traversing the V8 heap and identifying objects and their relationships. It has methods for extracting different types of references (internal, weak, property, etc.) and handling specific object types (Wasm, JSFunction, etc.).
    * **`HeapEntry`:** This likely represents a node in the heap snapshot graph, storing information about an object.
    * **`HeapSnapshotGenerator`:**  This class probably orchestrates the overall snapshot process, using the `V8HeapExplorer` to gather data and building the final snapshot.

3. **Understand the Flow:** The `IterateAndExtractReferences` method within `V8HeapExplorer` is a crucial point. It iterates through heap objects and calls `ExtractReferences` for each. This suggests a deep traversal of the heap.

4. **Examine Specific Methods:**
    * **`ExtractWasm*References`:**  These methods indicate the code has specific logic for handling WebAssembly objects, extracting references to internal components like `trusted_data`, `module_object`, and `exports`.
    * **`GetConstructor*`:** These methods are related to identifying the constructor of JavaScript objects, which is important for understanding object types in the snapshot.
    * **`Set*Reference` methods:** These methods are responsible for creating edges in the heap graph, linking objects based on different kinds of relationships (internal, weak, element, etc.).
    * **`SetGc*Reference` methods:** These seem to handle references from the garbage collector's roots, which are the starting points for reachability analysis.

5. **Consider Conditional Compilation:** The `#ifdef V8_ENABLE_WEBASSEMBLY` blocks indicate that some functionality is specific to builds with WebAssembly support enabled.

6. **Look for Assertions and Helper Functions:** The `ASSERT_*` macros and helper functions like `IsEssentialObject` and `MarkVisitedField` suggest internal checks and optimizations within the process. `IsEssentialObject` likely helps filter out less relevant internal objects to keep the snapshot concise.

7. **Connect to JavaScript:**  The code deals with concepts directly tied to JavaScript, such as constructors, prototypes, global objects, and WebAssembly. The example provided in the code snippet itself shows how to get the constructor of a JavaScript object.

8. **Infer Logic and Potential Issues:** The code traverses object graphs, which is inherently complex. Incorrectly identifying references or missing connections could lead to an incomplete or inaccurate snapshot. Common programming errors in manual memory management (which this resembles at a low level) could be a concern, although V8 handles most of this automatically. However, the code itself needs to correctly identify *logical* connections between objects.

9. **Address the `.tq` Question:** The prompt explicitly asks about `.tq` files. Based on knowledge of V8 development, `.tq` files are indeed Torque (a V8-specific language).

10. **Structure the Summary:** Organize the findings into logical sections covering functionality, JavaScript relevance, potential errors, and a concise overall summary.

11. **Refine and Elaborate:** Flesh out the details in each section, providing context and explanations. For example, explain *why* constructor names are important in a heap snapshot. Explain that the code aims to capture the object graph.

12. **Address Part 4/5:**  Acknowledge that this is a part of a larger codebase and provide a summarized function based on the analyzed code.

By following this thought process, combining code analysis with knowledge of V8's architecture and JavaScript concepts, the detailed and accurate summary can be constructed.
```cpp
  SetInternalReference(entry, "trusted_data",
                       instance_object->trusted_data(heap_->isolate()),
                       WasmInstanceObject::kTrustedDataOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmInstanceObject, TrustedData, ModuleObject);
  SetInternalReference(entry, "module_object", instance_object->module_object(),
                       WasmInstanceObject::kModuleObjectOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmInstanceObject, ModuleObject, ExportsObject);
  SetInternalReference(entry, "exports", instance_object->exports_object(),
                       WasmInstanceObject::kExportsObjectOffset);
  ASSERT_LAST_FIELD(WasmInstanceObject, ExportsObject);
}

void V8HeapExplorer::ExtractWasmModuleObjectReferences(
    Tagged<WasmModuleObject> module_object, HeapEntry* entry) {
  // The static assertions verify that we do not miss any fields here when we
  // update the class definition.
  ASSERT_FIRST_FIELD(WasmModuleObject, ManagedNativeModule);
  SetInternalReference(entry, "managed_native_module",
                       module_object->managed_native_module(),
                       WasmModuleObject::kManagedNativeModuleOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmModuleObject, ManagedNativeModule, Script);
  SetInternalReference(entry, "script", module_object->script(),
                       WasmModuleObject::kScriptOffset);
  ASSERT_LAST_FIELD(WasmModuleObject, Script);
}

#undef ASSERT_FIRST_FIELD
#undef ASSERT_CONSECUTIVE_FIELDS
#undef ASSERT_LAST_FIELD

#endif  // V8_ENABLE_WEBASSEMBLY

Tagged<JSFunction> V8HeapExplorer::GetConstructor(Isolate* isolate,
                                                  Tagged<JSReceiver> receiver) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  MaybeHandle<JSFunction> maybe_constructor =
      JSReceiver::GetConstructor(isolate, handle(receiver, isolate));

  if (maybe_constructor.is_null()) return JSFunction();

  return *maybe_constructor.ToHandleChecked();
}

Tagged<String> V8HeapExplorer::GetConstructorName(Isolate* isolate,
                                                  Tagged<JSObject> object) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  return *JSReceiver::GetConstructorName(isolate, handle(object, isolate));
}

HeapEntry* V8HeapExplorer::GetEntry(Tagged<Object> obj) {
  if (IsHeapObject(obj)) {
    return generator_->FindOrAddEntry(reinterpret_cast<void*>(obj.ptr()), this);
  }

  DCHECK(IsSmi(obj));
  if (!snapshot_->capture_numeric_value()) {
    return nullptr;
  }
  return generator_->FindOrAddEntry(Cast<Smi>(obj), this);
}

class RootsReferencesExtractor : public RootVisitor {
 public:
  explicit RootsReferencesExtractor(V8HeapExplorer* explorer)
      : explorer_(explorer), visiting_weak_roots_(false) {}

  void SetVisitingWeakRoots() { visiting_weak_roots_ = true; }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    Tagged<Object> object = *p;
#ifdef V8_ENABLE_DIRECT_HANDLE
    if (object.ptr() == kTaggedNullAddress) return;
#endif
    if (root == Root::kBuiltins) {
      explorer_->TagBuiltinCodeObject(Cast<Code>(object), description);
    }
    explorer_->SetGcSubrootReference(root, description, visiting_weak_roots_,
                                     object);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      DCHECK(!MapWord::IsPacked(p.Relaxed_Load().ptr()));
      VisitRootPointer(root, description, p);
    }
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK_EQ(root, Root::kStringTable);
    PtrComprCageBase cage_base(explorer_->heap_->isolate());
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      explorer_->SetGcSubrootReference(root, description, visiting_weak_roots_,
                                       p.load(cage_base));
    }
  }

  // Keep this synced with
  // MarkCompactCollector::RootMarkingVisitor::VisitRunningCode.
  void VisitRunningCode(FullObjectSlot code_slot,
                        FullObjectSlot istream_or_smi_zero_slot) final {
    Tagged<Object> istream_or_smi_zero = *istream_or_smi_zero_slot;
    if (istream_or_smi_zero != Smi::zero()) {
      Tagged<Code> code = Cast<Code>(*code_slot);
      code->IterateDeoptimizationLiterals(this);
      VisitRootPointer(Root::kStackRoots, nullptr, istream_or_smi_zero_slot);
    }
    VisitRootPointer(Root::kStackRoots, nullptr, code_slot);
  }

 private:
  V8HeapExplorer* explorer_;
  bool visiting_weak_roots_;
};

bool V8HeapExplorer::IterateAndExtractReferences(
    HeapSnapshotGenerator* generator) {
  generator_ = generator;

  // Create references to the synthetic roots.
  SetRootGcRootsReference();
  for (int root = 0; root < static_cast<int>(Root::kNumberOfRoots); root++) {
    SetGcRootsReference(static_cast<Root>(root));
  }

  // Make sure builtin code objects get their builtin tags
  // first. Otherwise a particular JSFunction object could set
  // its custom name to a generic builtin.
  RootsReferencesExtractor extractor(this);
  ReadOnlyRoots(heap_).Iterate(&extractor);
  heap_->IterateRoots(
      &extractor,
      base::EnumSet<SkipRoot>{SkipRoot::kWeak, SkipRoot::kTracedHandles});
  // TODO(v8:11800): The heap snapshot generator incorrectly considers the weak
  // string tables as strong retainers. Move IterateWeakRoots after
  // SetVisitingWeakRoots.
  heap_->IterateWeakRoots(&extractor, {});
  extractor.SetVisitingWeakRoots();
  heap_->IterateWeakGlobalHandles(&extractor);

  bool interrupted = false;

  CombinedHeapObjectIterator iterator(heap_);
  PtrComprCageBase cage_base(heap_->isolate());
  // Heap iteration need not be finished but progress reporting may depend on
  // it being finished.
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next(), progress_->ProgressStep()) {
    if (interrupted) continue;

    max_pointers_ = obj->Size(cage_base) / kTaggedSize;
    if (max_pointers_ > visited_fields_.size()) {
      // Reallocate to right size.
      visited_fields_.resize(max_pointers_, false);
    }

#ifdef V8_ENABLE_HEAP_SNAPSHOT_VERIFY
    std::unique_ptr<HeapEntryVerifier> verifier;
    // MarkingVisitorBase doesn't expect that we will ever visit read-only
    // objects, and fails DCHECKs if we attempt to. Read-only objects can
    // never retain read-write objects, so there is no risk in skipping
    // verification for them.
    if (v8_flags.heap_snapshot_verify &&
        !MemoryChunk::FromHeapObject(obj)->InReadOnlySpace()) {
      verifier = std::make_unique<HeapEntryVerifier>(generator, obj);
    }
#endif

    HeapEntry* entry = GetEntry(obj);
    ExtractReferences(entry, obj);
    SetInternalReference(entry, "map", obj->map(cage_base),
                         HeapObject::kMapOffset);
    // Extract unvisited fields as hidden references and restore tags
    // of visited fields.
    IndexedReferencesExtractor refs_extractor(this, obj, entry);
    VisitObject(heap_->isolate(), obj, &refs_extractor);

#if DEBUG
    // Ensure visited_fields_ doesn't leak to the next object.
    for (size_t i = 0; i < max_pointers_; ++i) {
      DCHECK(!visited_fields_[i]);
    }
#endif  // DEBUG

    // Extract location for specific object types
    ExtractLocation(entry, obj);

    if (!progress_->ProgressReport(false)) interrupted = true;
  }

  generator_ = nullptr;
  return interrupted ? false : progress_->ProgressReport(true);
}

bool V8HeapExplorer::IsEssentialObject(Tagged<Object> object) {
  if (!IsHeapObject(object)) return false;
  // Avoid comparing objects in other pointer compression cages to objects
  // inside the main cage as the comparison may only look at the lower 32 bits.
  if (HeapLayout::InCodeSpace(Cast<HeapObject>(object)) ||
      HeapLayout::InTrustedSpace(Cast<HeapObject>(object))) {
    return true;
  }
  Isolate* isolate = heap_->isolate();
  ReadOnlyRoots roots(isolate);
  return !IsOddball(object, isolate) && object != roots.the_hole_value() &&
         object != roots.empty_byte_array() &&
         object != roots.empty_fixed_array() &&
         object != roots.empty_weak_fixed_array() &&
         object != roots.empty_descriptor_array() &&
         object != roots.fixed_array_map() && object != roots.cell_map() &&
         object != roots.global_property_cell_map() &&
         object != roots.shared_function_info_map() &&
         object != roots.free_space_map() &&
         object != roots.one_pointer_filler_map() &&
         object != roots.two_pointer_filler_map();
}

bool V8HeapExplorer::IsEssentialHiddenReference(Tagged<Object> parent,
                                                int field_offset) {
  if (IsAllocationSite(parent) &&
      field_offset == AllocationSite::kWeakNextOffset)
    return false;
  if (IsContext(parent) &&
      field_offset == Context::OffsetOfElementAt(Context::NEXT_CONTEXT_LINK))
    return false;
  if (IsJSFinalizationRegistry(parent) &&
      field_offset == JSFinalizationRegistry::kNextDirtyOffset)
    return false;
  return true;
}

void V8HeapExplorer::SetContextReference(HeapEntry* parent_entry,
                                         Tagged<String> reference_name,
                                         Tagged<Object> child_obj,
                                         int field_offset) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetNamedReference(HeapGraphEdge::kContextVariable,
                                  names_->GetName(reference_name), child_entry,
                                  generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::MarkVisitedField(int offset) {
  if (offset < 0) return;
  int index = offset / kTaggedSize;
  DCHECK_LT(index, max_pointers_);
  DCHECK(!visited_fields_[index]);
  visited_fields_[index] = true;
}

void V8HeapExplorer::SetNativeBindReference(HeapEntry* parent_entry,
                                            const char* reference_name,
                                            Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetNamedReference(HeapGraphEdge::kShortcut, reference_name,
                                  child_entry, generator_);
}

void V8HeapExplorer::SetElementReference(HeapEntry* parent_entry, int index,
                                         Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetIndexedReference(HeapGraphEdge::kElement, index, child_entry,
                                    generator_);
}

void V8HeapExplorer::SetInternalReference(HeapEntry* parent_entry,
                                          const char* reference_name,
                                          Tagged<Object> child_obj,
                                          int field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kInternal, reference_name,
                                  child_entry, generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetInternalReference(HeapEntry* parent_entry, int index,
                                          Tagged<Object> child_obj,
                                          int field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kInternal,
                                  names_->GetName(index), child_entry,
                                  generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetHiddenReference(Tagged<HeapObject> parent_obj,
                                        HeapEntry* parent_entry, int index,
                                        Tagged<Object> child_obj,
                                        int field_offset) {
  DCHECK_EQ(parent_entry, GetEntry(parent_obj));
  DCHECK(!MapWord::IsPacked(child_obj.ptr()));
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  if (IsEssentialHiddenReference(parent_obj, field_offset)) {
    parent_entry->SetIndexedReference(HeapGraphEdge::kHidden, index,
                                      child_entry, generator_);
  }
}

void V8HeapExplorer::SetWeakReference(
    HeapEntry* parent_entry, const char* reference_name,
    Tagged<Object> child_obj, int field_offset,
    HeapEntry::ReferenceVerification verification) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kWeak, reference_name,
                                  child_entry, generator_, verification);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetWeakReference(HeapEntry* parent_entry, int index,
                                      Tagged<Object> child_obj,
                                      std::optional<int> field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kWeak,
                                  names_->GetFormatted("%d", index),
                                  child_entry, generator_);
  if (field_offset.has_value()) {
    MarkVisitedField(*field_offset);
  }
}

void V8HeapExplorer::SetDataOrAccessorPropertyReference(
    PropertyKind kind, HeapEntry* parent_entry, Tagged<Name> reference_name,
    Tagged<Object> child_obj, const char* name_format_string,
    int field_offset) {
  if (kind == PropertyKind::kAccessor) {
    ExtractAccessorPairProperty(parent_entry, reference_name, child_obj,
                                field_offset);
  } else {
    SetPropertyReference(parent_entry, reference_name, child_obj,
                         name_format_string, field_offset);
  }
}

void V8HeapExplorer::SetPropertyReference(HeapEntry* parent_entry,
                                          Tagged<Name> reference_name,
                                          Tagged<Object> child_obj,
                                          const char* name_format_string,
                                          int field_offset) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  HeapGraphEdge::Type type =
      IsSymbol(reference_name) || Cast<String>(reference_name)->length() > 0
          ? HeapGraphEdge::kProperty
          : HeapGraphEdge::kInternal;
  const char* name = name_format_string != nullptr && IsString(reference_name)
                         ? names_->GetFormatted(
                               name_format_string,
                               Cast<String>(reference_name)->ToCString().get())
                         : names_->GetName(reference_name);

  parent_entry->SetNamedReference(type, name, child_entry, generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetRootGcRootsReference() {
  snapshot_->root()->SetIndexedAutoIndexReference(
      HeapGraphEdge::kElement, snapshot_->gc_roots(), generator_);
}

void V8HeapExplorer::SetUserGlobalReference(Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  snapshot_->root()->SetNamedAutoIndexReference(
      HeapGraphEdge::kShortcut, nullptr, child_entry, names_, generator_);
}

void V8HeapExplorer::SetGcRootsReference(Root root) {
  snapshot_->gc_roots()->SetIndexedAutoIndexReference(
      HeapGraphEdge::kElement, snapshot_->gc_subroot(root), generator_);
}

void V8HeapExplorer::SetGcSubrootReference(Root root, const char* description,
                                           bool is_weak,
                                           Tagged<Object> child_obj) {
  if (IsSmi(child_obj)) {
    // TODO(arenevier): if we handle smis here, the snapshot gets 2 to 3 times
    // slower on large heaps. According to perf, The bulk of the extra works
    // happens in TemplateHashMapImpl::Probe method, when tyring to get
    // names->GetFormatted("%d / %s", index, description)
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  auto child_heap_obj = Cast<HeapObject>(child_obj);
  const char* name = GetStrongGcSubrootName(child_heap_obj);
  HeapGraphEdge::Type edge_type =
      is_weak ? HeapGraphEdge::kWeak : HeapGraphEdge::kInternal;
  if (name != nullptr) {
    snapshot_->gc_subroot(root)->SetNamedReference(edge_type, name, child_entry,
                                                   generator_);
  } else {
    snapshot_->gc_subroot(root)->SetNamedAutoIndexReference(
        edge_type, description, child_entry, names_, generator_);
  }

  // For full heap snapshots we do not emit user roots but rather rely on
  // regular GC roots to retain objects.
  if (snapshot_->expose_internals()) return;

  // Add a shortcut to JS global object reference at snapshot root.
  // That allows the user to easily find global objects. They are
  // also used as starting points in distance calculations.
  if (is_weak || !IsNativeContext(child_heap_obj)) return;

  Tagged<JSGlobalObject> global =
      Cast<Context>(child_heap_obj)->global_object();
  if (!IsJSGlobalObject(global)) return;

  if (!user_roots_.insert(global).second) return;

  SetUserGlobalReference(global);
}

const char* V8HeapExplorer::GetStrongGcSubrootName(Tagged<HeapObject> object) {
  if (strong_gc_subroot_names_.empty()) {
    Isolate* isolate = Isolate::FromHeap(heap_);
    for (RootIndex root_index = RootIndex::kFirstStrongOrReadOnlyRoot;
         root_index <= RootIndex::kLastStrongOrReadOnlyRoot; ++root_index) {
      const char* name = RootsTable::name(root_index);
      Tagged<Object> root = isolate->root(root_index);
      CHECK(!IsSmi(root));
      strong_gc_subroot_names_.emplace(Cast<HeapObject>(root), name);
    }
    CHECK(!strong_gc_subroot_names_.empty());
  }
  auto it = strong_gc_subroot_names_.find(object);
  return it != strong_gc_subroot_names_.end() ? it->second : nullptr;
}

void V8HeapExplorer::TagObject(Tagged<Object> obj, const char* tag,
                               std::optional<HeapEntry::Type> type,
                               bool overwrite_existing_name) {
  if (IsEssentialObject(obj)) {
    HeapEntry* entry = GetEntry(obj);
    if (overwrite_existing_name || entry->name()[0] == '\0') {
      entry->set_name(tag);
    }
    if (type.has_value()) {
      entry->set_type(*type);
    }
  }
}

void V8HeapExplorer::RecursivelyTagConstantPool(Tagged<Object> obj,
                                                const char* tag,
                                                HeapEntry::Type type,
                                                int recursion_limit) {
  --recursion_limit;
  if (IsFixedArrayExact(obj, isolate())) {
    Tagged<FixedArray> arr = Cast<FixedArray>(obj);
    TagObject(arr, tag, type);
    if (recursion_limit <= 0) return;
    for (int i = 0; i < arr->length(); ++i) {
      RecursivelyTagConstantPool(arr->get(i), tag, type, recursion_limit);
    }
  } else if (IsTrustedFixedArray(obj, isolate())) {
    Tagged<TrustedFixedArray> arr = Cast<TrustedFixedArray>(obj);
    TagObject(arr, tag, type, /*overwrite_existing_name=*/true);
    if (recursion_limit <= 0) return;
    for (int i = 0; i < arr->length(); ++i) {
      RecursivelyTagConstantPool(arr->get(i), tag, type, recursion_limit);
    }
  } else if (IsNameDictionary(obj, isolate()) ||
             IsNumberDictionary(obj, isolate())) {
    TagObject(obj, tag, type);
  }
}

class GlobalObjectsEnumerator : public RootVisitor {
 public:
  GlobalObjectsEnumerator(Isolate* isolate,
                          std::function<void(Handle<JSGlobalObject>)> handler)
      : isolate_(isolate), handler_(handler) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    VisitRootPointersImpl(root, description, start, end);
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    VisitRootPointersImpl(root, description, start, end);
  }

 private:
  template <typename TSlot>
  void VisitRootPointersImpl(Root root, const char* description, TSlot start,
                             TSlot end) {
    for (TSlot p = start; p < end; ++p) {
      DCHECK(!MapWord::IsPacked(p.Relaxed_Load(isolate_).ptr()));
      Tagged<Object> o = p.load(isolate_);
      if (!IsNativeContext(o, isolate_)) continue;
      Tagged<JSObject> proxy = Cast<Context>(o)->global_proxy();
      if (!IsJSGlobalProxy(proxy, isolate_)) continue;
      Tagged<Object> global = proxy->map(isolate_)->prototype(isolate_);
      if (!IsJSGlobalObject(global, isolate_)) continue;
      handler_(handle(Cast<JSGlobalObject>(global), isolate_));
    }
  }

  Isolate* isolate_;
  std::function<void(Handle<JSGlobalObject>)> handler_;
};

V8HeapExplorer::TemporaryGlobalObjectTags
V8HeapExplorer::CollectTemporaryGlobalObjectsTags() {
  if (!global_object_name_resolver_) return {};

  Isolate* isolate = heap_->isolate();
  TemporaryGlobalObjectTags global_object_tags;
  HandleScope scope(isolate);
  GlobalObjectsEnumerator enumerator(
      isolate, [this, isolate,
                &global_object_tags](Handle<JSGlobalObject> global_object) {
        if (const char* tag = global_object_name_resolver_->GetName(
                Utils::ToLocal(Cast<JSObject>(global_object)))) {
          global_object_tags.emplace_back(
              Global<v8::Object>(reinterpret_cast<v8::Isolate*>(isolate),
                                 Utils::ToLocal(Cast<JSObject>(global_object))),
              tag);
          global_object_tags.back().first.SetWeak();
        }
      });
  isolate->global_handles()->IterateAllRoots(&enumerator);
  isolate->traced_handles()->Iterate(&enumerator);
  return global_object_tags;
}

void V8HeapExplorer::MakeGlobalObjectTagMap(
    TemporaryGlobalObjectTags&& global_object_tags) {
  HandleScope scope(heap_->isolate());
  for (const auto& pair : global_object_tags) {
    if (!pair.first.IsEmpty()) {
      // Temporary local.
      auto local = Utils::OpenPersistent(pair.first);
      global_object_tag_map_.emplace(Cast<JSGlobalObject>(*local), pair.second);
    }
  }
}

class EmbedderGraphImpl : public EmbedderGraph {
 public:
  struct Edge {
    Node* from;
    Node* to;
    const char* name;
  };

  class V8NodeImpl : public Node {
   public:
    explicit V8NodeImpl(Tagged<Object> object) : object_(object) {}
    Tagged<Object> GetObject() { return object_; }

    // Node overrides.
    bool IsEmbedderNode() override { return false; }
    const char* Name() override {
      // The name should be retrieved via GetObject().
      UNREACHABLE();
    }
    size_t SizeInBytes() override {
      // The size should be retrieved via GetObject().
      UNREACHABLE();
    }

   private:
    Tagged<Object> object_;
  };

  Node* V8Node(const v8::Local<v8::Value>& value) final {
    v8::Local<v8::Data> data = value;
    return V8Node(data);
  }

  Node* V8Node(const v8::Local<v8::Data>& data) final {
    Handle<Object> object = v8::Utils::OpenHandle(*data);
    DCHECK(!object.is_null());
    return AddNode(std::unique_ptr<Node>(new V8NodeImpl(*object)));
  }

  Node* AddNode(std::unique_ptr<Node> node) final {
    Node* result = node.get();
    nodes_.push_back(std::move(node));
    return result;
  }

  void AddEdge(Node* from, Node* to, const char* name) final {
    edges_.push_back({from, to, name});
  }

  const std::vector<std::unique_ptr<Node>>& nodes() { return nodes_; }
  const std::vector<Edge>& edges() { return edges_; }

 private:
  std::vector<std::unique_ptr<Node>> nodes_;
  std::vector<Edge> edges_;
};

class EmbedderGraphEntriesAllocator : public HeapEntriesAllocator {
 public:
  explicit EmbedderGraphEntriesAllocator(HeapSnapshot* snapshot)
      : snapshot_(snapshot),
        names_(snapshot_->profiler()->names()),
        heap_object_map_(snapshot_->profiler()->heap_object_map()) {}
  HeapEntry* AllocateEntry(HeapThing ptr) override;
  HeapEntry* AllocateEntry(Tagged<Smi> smi) override;

 private:
  HeapSnapshot* snapshot_;
  StringsStorage* names_;
  HeapObjectsMap* heap_object_map_;
};

namespace {

const char* EmbedderGraphNodeName(StringsStorage* names,
                                  EmbedderGraphImpl::Node* node) {
  const char* prefix = node->NamePrefix();
  return prefix ? names->GetFormatted("%s %s", prefix, node->Name())
                : names->GetCopy(node->Name());
}

HeapEntry::Type EmbedderGraphNodeType(EmbedderGraphImpl::Node* node) {
  return node->IsRootNode() ? HeapEntry::kSynthetic : HeapEntry::kNative;
}

// Merges the names of an embedder node and its wrapper node.
// If the wrapper node name contains a tag suffix (part after '/') then the
// result is the embedder node name concatenated with the tag suffix.
// Otherwise, the result is the embedder node name.
const char* MergeNames(StringsStorage* names, const char* embedder_name,
                       const char* wrapper_name) {
  const char* suffix = strchr(wrapper_name, '/');
  return suffix ? names->GetFormatted("%s %s", embedder_name, suffix)
                : embedder_name;
}

}  // anonymous namespace

HeapEntry* EmbedderGraphEntriesAllocator::AllocateEntry(HeapThing ptr) {
  EmbedderGraphImpl::Node* node =
      reinterpret_cast<EmbedderGraphImpl::Node*>(ptr);
  DCHECK(node->IsEmbedderNode());
  size_t size = node->SizeInBytes();
  Address lookup_address = reinterpret_cast<Address>(node->GetNativeObject());
  HeapObjectsMap::MarkEntryAccessed accessed =
      HeapObjectsMap::MarkEntryAccessed::kYes;
  HeapObjectsMap::IsNativeObject is_native_object =
      HeapObjectsMap::IsNativeObject::kNo;
  if (!lookup_address) {
    // If there is not a native object associated with this embedder object,
    // then request the address of the embedder object.
    lookup_address = reinterpret_cast<Address>(node->GetAddress());
    is_native_object = HeapObjectsMap::IsNativeObject::kYes;
  }
  if (!lookup_address) {
    // If the Node implementation did not provide either a native address or an
    // embedder address, then use the address of the Node itself for the lookup.
    // In this case, we'll set the "accessed" flag on the newly created
    // HeapEntry to false, to indicate that this entry should not persist for
    // future snapshots
### 提示词
```
这是目录为v8/src/profiler/heap-snapshot-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/heap-snapshot-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
SetInternalReference(entry, "trusted_data",
                       instance_object->trusted_data(heap_->isolate()),
                       WasmInstanceObject::kTrustedDataOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmInstanceObject, TrustedData, ModuleObject);
  SetInternalReference(entry, "module_object", instance_object->module_object(),
                       WasmInstanceObject::kModuleObjectOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmInstanceObject, ModuleObject, ExportsObject);
  SetInternalReference(entry, "exports", instance_object->exports_object(),
                       WasmInstanceObject::kExportsObjectOffset);
  ASSERT_LAST_FIELD(WasmInstanceObject, ExportsObject);
}

void V8HeapExplorer::ExtractWasmModuleObjectReferences(
    Tagged<WasmModuleObject> module_object, HeapEntry* entry) {
  // The static assertions verify that we do not miss any fields here when we
  // update the class definition.
  ASSERT_FIRST_FIELD(WasmModuleObject, ManagedNativeModule);
  SetInternalReference(entry, "managed_native_module",
                       module_object->managed_native_module(),
                       WasmModuleObject::kManagedNativeModuleOffset);
  ASSERT_CONSECUTIVE_FIELDS(WasmModuleObject, ManagedNativeModule, Script);
  SetInternalReference(entry, "script", module_object->script(),
                       WasmModuleObject::kScriptOffset);
  ASSERT_LAST_FIELD(WasmModuleObject, Script);
}

#undef ASSERT_FIRST_FIELD
#undef ASSERT_CONSECUTIVE_FIELDS
#undef ASSERT_LAST_FIELD

#endif  // V8_ENABLE_WEBASSEMBLY

Tagged<JSFunction> V8HeapExplorer::GetConstructor(Isolate* isolate,
                                                  Tagged<JSReceiver> receiver) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  MaybeHandle<JSFunction> maybe_constructor =
      JSReceiver::GetConstructor(isolate, handle(receiver, isolate));

  if (maybe_constructor.is_null()) return JSFunction();

  return *maybe_constructor.ToHandleChecked();
}

Tagged<String> V8HeapExplorer::GetConstructorName(Isolate* isolate,
                                                  Tagged<JSObject> object) {
  DisallowGarbageCollection no_gc;
  HandleScope scope(isolate);
  return *JSReceiver::GetConstructorName(isolate, handle(object, isolate));
}

HeapEntry* V8HeapExplorer::GetEntry(Tagged<Object> obj) {
  if (IsHeapObject(obj)) {
    return generator_->FindOrAddEntry(reinterpret_cast<void*>(obj.ptr()), this);
  }

  DCHECK(IsSmi(obj));
  if (!snapshot_->capture_numeric_value()) {
    return nullptr;
  }
  return generator_->FindOrAddEntry(Cast<Smi>(obj), this);
}

class RootsReferencesExtractor : public RootVisitor {
 public:
  explicit RootsReferencesExtractor(V8HeapExplorer* explorer)
      : explorer_(explorer), visiting_weak_roots_(false) {}

  void SetVisitingWeakRoots() { visiting_weak_roots_ = true; }

  void VisitRootPointer(Root root, const char* description,
                        FullObjectSlot p) override {
    Tagged<Object> object = *p;
#ifdef V8_ENABLE_DIRECT_HANDLE
    if (object.ptr() == kTaggedNullAddress) return;
#endif
    if (root == Root::kBuiltins) {
      explorer_->TagBuiltinCodeObject(Cast<Code>(object), description);
    }
    explorer_->SetGcSubrootReference(root, description, visiting_weak_roots_,
                                     object);
  }

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    for (FullObjectSlot p = start; p < end; ++p) {
      DCHECK(!MapWord::IsPacked(p.Relaxed_Load().ptr()));
      VisitRootPointer(root, description, p);
    }
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    DCHECK_EQ(root, Root::kStringTable);
    PtrComprCageBase cage_base(explorer_->heap_->isolate());
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      explorer_->SetGcSubrootReference(root, description, visiting_weak_roots_,
                                       p.load(cage_base));
    }
  }

  // Keep this synced with
  // MarkCompactCollector::RootMarkingVisitor::VisitRunningCode.
  void VisitRunningCode(FullObjectSlot code_slot,
                        FullObjectSlot istream_or_smi_zero_slot) final {
    Tagged<Object> istream_or_smi_zero = *istream_or_smi_zero_slot;
    if (istream_or_smi_zero != Smi::zero()) {
      Tagged<Code> code = Cast<Code>(*code_slot);
      code->IterateDeoptimizationLiterals(this);
      VisitRootPointer(Root::kStackRoots, nullptr, istream_or_smi_zero_slot);
    }
    VisitRootPointer(Root::kStackRoots, nullptr, code_slot);
  }

 private:
  V8HeapExplorer* explorer_;
  bool visiting_weak_roots_;
};

bool V8HeapExplorer::IterateAndExtractReferences(
    HeapSnapshotGenerator* generator) {
  generator_ = generator;

  // Create references to the synthetic roots.
  SetRootGcRootsReference();
  for (int root = 0; root < static_cast<int>(Root::kNumberOfRoots); root++) {
    SetGcRootsReference(static_cast<Root>(root));
  }

  // Make sure builtin code objects get their builtin tags
  // first. Otherwise a particular JSFunction object could set
  // its custom name to a generic builtin.
  RootsReferencesExtractor extractor(this);
  ReadOnlyRoots(heap_).Iterate(&extractor);
  heap_->IterateRoots(
      &extractor,
      base::EnumSet<SkipRoot>{SkipRoot::kWeak, SkipRoot::kTracedHandles});
  // TODO(v8:11800): The heap snapshot generator incorrectly considers the weak
  // string tables as strong retainers. Move IterateWeakRoots after
  // SetVisitingWeakRoots.
  heap_->IterateWeakRoots(&extractor, {});
  extractor.SetVisitingWeakRoots();
  heap_->IterateWeakGlobalHandles(&extractor);

  bool interrupted = false;

  CombinedHeapObjectIterator iterator(heap_);
  PtrComprCageBase cage_base(heap_->isolate());
  // Heap iteration need not be finished but progress reporting may depend on
  // it being finished.
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next(), progress_->ProgressStep()) {
    if (interrupted) continue;

    max_pointers_ = obj->Size(cage_base) / kTaggedSize;
    if (max_pointers_ > visited_fields_.size()) {
      // Reallocate to right size.
      visited_fields_.resize(max_pointers_, false);
    }

#ifdef V8_ENABLE_HEAP_SNAPSHOT_VERIFY
    std::unique_ptr<HeapEntryVerifier> verifier;
    // MarkingVisitorBase doesn't expect that we will ever visit read-only
    // objects, and fails DCHECKs if we attempt to. Read-only objects can
    // never retain read-write objects, so there is no risk in skipping
    // verification for them.
    if (v8_flags.heap_snapshot_verify &&
        !MemoryChunk::FromHeapObject(obj)->InReadOnlySpace()) {
      verifier = std::make_unique<HeapEntryVerifier>(generator, obj);
    }
#endif

    HeapEntry* entry = GetEntry(obj);
    ExtractReferences(entry, obj);
    SetInternalReference(entry, "map", obj->map(cage_base),
                         HeapObject::kMapOffset);
    // Extract unvisited fields as hidden references and restore tags
    // of visited fields.
    IndexedReferencesExtractor refs_extractor(this, obj, entry);
    VisitObject(heap_->isolate(), obj, &refs_extractor);

#if DEBUG
    // Ensure visited_fields_ doesn't leak to the next object.
    for (size_t i = 0; i < max_pointers_; ++i) {
      DCHECK(!visited_fields_[i]);
    }
#endif  // DEBUG

    // Extract location for specific object types
    ExtractLocation(entry, obj);

    if (!progress_->ProgressReport(false)) interrupted = true;
  }

  generator_ = nullptr;
  return interrupted ? false : progress_->ProgressReport(true);
}

bool V8HeapExplorer::IsEssentialObject(Tagged<Object> object) {
  if (!IsHeapObject(object)) return false;
  // Avoid comparing objects in other pointer compression cages to objects
  // inside the main cage as the comparison may only look at the lower 32 bits.
  if (HeapLayout::InCodeSpace(Cast<HeapObject>(object)) ||
      HeapLayout::InTrustedSpace(Cast<HeapObject>(object))) {
    return true;
  }
  Isolate* isolate = heap_->isolate();
  ReadOnlyRoots roots(isolate);
  return !IsOddball(object, isolate) && object != roots.the_hole_value() &&
         object != roots.empty_byte_array() &&
         object != roots.empty_fixed_array() &&
         object != roots.empty_weak_fixed_array() &&
         object != roots.empty_descriptor_array() &&
         object != roots.fixed_array_map() && object != roots.cell_map() &&
         object != roots.global_property_cell_map() &&
         object != roots.shared_function_info_map() &&
         object != roots.free_space_map() &&
         object != roots.one_pointer_filler_map() &&
         object != roots.two_pointer_filler_map();
}

bool V8HeapExplorer::IsEssentialHiddenReference(Tagged<Object> parent,
                                                int field_offset) {
  if (IsAllocationSite(parent) &&
      field_offset == AllocationSite::kWeakNextOffset)
    return false;
  if (IsContext(parent) &&
      field_offset == Context::OffsetOfElementAt(Context::NEXT_CONTEXT_LINK))
    return false;
  if (IsJSFinalizationRegistry(parent) &&
      field_offset == JSFinalizationRegistry::kNextDirtyOffset)
    return false;
  return true;
}

void V8HeapExplorer::SetContextReference(HeapEntry* parent_entry,
                                         Tagged<String> reference_name,
                                         Tagged<Object> child_obj,
                                         int field_offset) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetNamedReference(HeapGraphEdge::kContextVariable,
                                  names_->GetName(reference_name), child_entry,
                                  generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::MarkVisitedField(int offset) {
  if (offset < 0) return;
  int index = offset / kTaggedSize;
  DCHECK_LT(index, max_pointers_);
  DCHECK(!visited_fields_[index]);
  visited_fields_[index] = true;
}

void V8HeapExplorer::SetNativeBindReference(HeapEntry* parent_entry,
                                            const char* reference_name,
                                            Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetNamedReference(HeapGraphEdge::kShortcut, reference_name,
                                  child_entry, generator_);
}

void V8HeapExplorer::SetElementReference(HeapEntry* parent_entry, int index,
                                         Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  parent_entry->SetIndexedReference(HeapGraphEdge::kElement, index, child_entry,
                                    generator_);
}

void V8HeapExplorer::SetInternalReference(HeapEntry* parent_entry,
                                          const char* reference_name,
                                          Tagged<Object> child_obj,
                                          int field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kInternal, reference_name,
                                  child_entry, generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetInternalReference(HeapEntry* parent_entry, int index,
                                          Tagged<Object> child_obj,
                                          int field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kInternal,
                                  names_->GetName(index), child_entry,
                                  generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetHiddenReference(Tagged<HeapObject> parent_obj,
                                        HeapEntry* parent_entry, int index,
                                        Tagged<Object> child_obj,
                                        int field_offset) {
  DCHECK_EQ(parent_entry, GetEntry(parent_obj));
  DCHECK(!MapWord::IsPacked(child_obj.ptr()));
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  if (IsEssentialHiddenReference(parent_obj, field_offset)) {
    parent_entry->SetIndexedReference(HeapGraphEdge::kHidden, index,
                                      child_entry, generator_);
  }
}

void V8HeapExplorer::SetWeakReference(
    HeapEntry* parent_entry, const char* reference_name,
    Tagged<Object> child_obj, int field_offset,
    HeapEntry::ReferenceVerification verification) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kWeak, reference_name,
                                  child_entry, generator_, verification);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetWeakReference(HeapEntry* parent_entry, int index,
                                      Tagged<Object> child_obj,
                                      std::optional<int> field_offset) {
  if (!IsEssentialObject(child_obj)) {
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  parent_entry->SetNamedReference(HeapGraphEdge::kWeak,
                                  names_->GetFormatted("%d", index),
                                  child_entry, generator_);
  if (field_offset.has_value()) {
    MarkVisitedField(*field_offset);
  }
}

void V8HeapExplorer::SetDataOrAccessorPropertyReference(
    PropertyKind kind, HeapEntry* parent_entry, Tagged<Name> reference_name,
    Tagged<Object> child_obj, const char* name_format_string,
    int field_offset) {
  if (kind == PropertyKind::kAccessor) {
    ExtractAccessorPairProperty(parent_entry, reference_name, child_obj,
                                field_offset);
  } else {
    SetPropertyReference(parent_entry, reference_name, child_obj,
                         name_format_string, field_offset);
  }
}

void V8HeapExplorer::SetPropertyReference(HeapEntry* parent_entry,
                                          Tagged<Name> reference_name,
                                          Tagged<Object> child_obj,
                                          const char* name_format_string,
                                          int field_offset) {
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  HeapGraphEdge::Type type =
      IsSymbol(reference_name) || Cast<String>(reference_name)->length() > 0
          ? HeapGraphEdge::kProperty
          : HeapGraphEdge::kInternal;
  const char* name = name_format_string != nullptr && IsString(reference_name)
                         ? names_->GetFormatted(
                               name_format_string,
                               Cast<String>(reference_name)->ToCString().get())
                         : names_->GetName(reference_name);

  parent_entry->SetNamedReference(type, name, child_entry, generator_);
  MarkVisitedField(field_offset);
}

void V8HeapExplorer::SetRootGcRootsReference() {
  snapshot_->root()->SetIndexedAutoIndexReference(
      HeapGraphEdge::kElement, snapshot_->gc_roots(), generator_);
}

void V8HeapExplorer::SetUserGlobalReference(Tagged<Object> child_obj) {
  HeapEntry* child_entry = GetEntry(child_obj);
  DCHECK_NOT_NULL(child_entry);
  snapshot_->root()->SetNamedAutoIndexReference(
      HeapGraphEdge::kShortcut, nullptr, child_entry, names_, generator_);
}

void V8HeapExplorer::SetGcRootsReference(Root root) {
  snapshot_->gc_roots()->SetIndexedAutoIndexReference(
      HeapGraphEdge::kElement, snapshot_->gc_subroot(root), generator_);
}

void V8HeapExplorer::SetGcSubrootReference(Root root, const char* description,
                                           bool is_weak,
                                           Tagged<Object> child_obj) {
  if (IsSmi(child_obj)) {
    // TODO(arenevier): if we handle smis here, the snapshot gets 2 to 3 times
    // slower on large heaps. According to perf, The bulk of the extra works
    // happens in TemplateHashMapImpl::Probe method, when tyring to get
    // names->GetFormatted("%d / %s", index, description)
    return;
  }
  HeapEntry* child_entry = GetEntry(child_obj);
  if (child_entry == nullptr) return;
  auto child_heap_obj = Cast<HeapObject>(child_obj);
  const char* name = GetStrongGcSubrootName(child_heap_obj);
  HeapGraphEdge::Type edge_type =
      is_weak ? HeapGraphEdge::kWeak : HeapGraphEdge::kInternal;
  if (name != nullptr) {
    snapshot_->gc_subroot(root)->SetNamedReference(edge_type, name, child_entry,
                                                   generator_);
  } else {
    snapshot_->gc_subroot(root)->SetNamedAutoIndexReference(
        edge_type, description, child_entry, names_, generator_);
  }

  // For full heap snapshots we do not emit user roots but rather rely on
  // regular GC roots to retain objects.
  if (snapshot_->expose_internals()) return;

  // Add a shortcut to JS global object reference at snapshot root.
  // That allows the user to easily find global objects. They are
  // also used as starting points in distance calculations.
  if (is_weak || !IsNativeContext(child_heap_obj)) return;

  Tagged<JSGlobalObject> global =
      Cast<Context>(child_heap_obj)->global_object();
  if (!IsJSGlobalObject(global)) return;

  if (!user_roots_.insert(global).second) return;

  SetUserGlobalReference(global);
}

const char* V8HeapExplorer::GetStrongGcSubrootName(Tagged<HeapObject> object) {
  if (strong_gc_subroot_names_.empty()) {
    Isolate* isolate = Isolate::FromHeap(heap_);
    for (RootIndex root_index = RootIndex::kFirstStrongOrReadOnlyRoot;
         root_index <= RootIndex::kLastStrongOrReadOnlyRoot; ++root_index) {
      const char* name = RootsTable::name(root_index);
      Tagged<Object> root = isolate->root(root_index);
      CHECK(!IsSmi(root));
      strong_gc_subroot_names_.emplace(Cast<HeapObject>(root), name);
    }
    CHECK(!strong_gc_subroot_names_.empty());
  }
  auto it = strong_gc_subroot_names_.find(object);
  return it != strong_gc_subroot_names_.end() ? it->second : nullptr;
}

void V8HeapExplorer::TagObject(Tagged<Object> obj, const char* tag,
                               std::optional<HeapEntry::Type> type,
                               bool overwrite_existing_name) {
  if (IsEssentialObject(obj)) {
    HeapEntry* entry = GetEntry(obj);
    if (overwrite_existing_name || entry->name()[0] == '\0') {
      entry->set_name(tag);
    }
    if (type.has_value()) {
      entry->set_type(*type);
    }
  }
}

void V8HeapExplorer::RecursivelyTagConstantPool(Tagged<Object> obj,
                                                const char* tag,
                                                HeapEntry::Type type,
                                                int recursion_limit) {
  --recursion_limit;
  if (IsFixedArrayExact(obj, isolate())) {
    Tagged<FixedArray> arr = Cast<FixedArray>(obj);
    TagObject(arr, tag, type);
    if (recursion_limit <= 0) return;
    for (int i = 0; i < arr->length(); ++i) {
      RecursivelyTagConstantPool(arr->get(i), tag, type, recursion_limit);
    }
  } else if (IsTrustedFixedArray(obj, isolate())) {
    Tagged<TrustedFixedArray> arr = Cast<TrustedFixedArray>(obj);
    TagObject(arr, tag, type, /*overwrite_existing_name=*/true);
    if (recursion_limit <= 0) return;
    for (int i = 0; i < arr->length(); ++i) {
      RecursivelyTagConstantPool(arr->get(i), tag, type, recursion_limit);
    }
  } else if (IsNameDictionary(obj, isolate()) ||
             IsNumberDictionary(obj, isolate())) {
    TagObject(obj, tag, type);
  }
}

class GlobalObjectsEnumerator : public RootVisitor {
 public:
  GlobalObjectsEnumerator(Isolate* isolate,
                          std::function<void(Handle<JSGlobalObject>)> handler)
      : isolate_(isolate), handler_(handler) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    VisitRootPointersImpl(root, description, start, end);
  }

  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    VisitRootPointersImpl(root, description, start, end);
  }

 private:
  template <typename TSlot>
  void VisitRootPointersImpl(Root root, const char* description, TSlot start,
                             TSlot end) {
    for (TSlot p = start; p < end; ++p) {
      DCHECK(!MapWord::IsPacked(p.Relaxed_Load(isolate_).ptr()));
      Tagged<Object> o = p.load(isolate_);
      if (!IsNativeContext(o, isolate_)) continue;
      Tagged<JSObject> proxy = Cast<Context>(o)->global_proxy();
      if (!IsJSGlobalProxy(proxy, isolate_)) continue;
      Tagged<Object> global = proxy->map(isolate_)->prototype(isolate_);
      if (!IsJSGlobalObject(global, isolate_)) continue;
      handler_(handle(Cast<JSGlobalObject>(global), isolate_));
    }
  }

  Isolate* isolate_;
  std::function<void(Handle<JSGlobalObject>)> handler_;
};

V8HeapExplorer::TemporaryGlobalObjectTags
V8HeapExplorer::CollectTemporaryGlobalObjectsTags() {
  if (!global_object_name_resolver_) return {};

  Isolate* isolate = heap_->isolate();
  TemporaryGlobalObjectTags global_object_tags;
  HandleScope scope(isolate);
  GlobalObjectsEnumerator enumerator(
      isolate, [this, isolate,
                &global_object_tags](Handle<JSGlobalObject> global_object) {
        if (const char* tag = global_object_name_resolver_->GetName(
                Utils::ToLocal(Cast<JSObject>(global_object)))) {
          global_object_tags.emplace_back(
              Global<v8::Object>(reinterpret_cast<v8::Isolate*>(isolate),
                                 Utils::ToLocal(Cast<JSObject>(global_object))),
              tag);
          global_object_tags.back().first.SetWeak();
        }
      });
  isolate->global_handles()->IterateAllRoots(&enumerator);
  isolate->traced_handles()->Iterate(&enumerator);
  return global_object_tags;
}

void V8HeapExplorer::MakeGlobalObjectTagMap(
    TemporaryGlobalObjectTags&& global_object_tags) {
  HandleScope scope(heap_->isolate());
  for (const auto& pair : global_object_tags) {
    if (!pair.first.IsEmpty()) {
      // Temporary local.
      auto local = Utils::OpenPersistent(pair.first);
      global_object_tag_map_.emplace(Cast<JSGlobalObject>(*local), pair.second);
    }
  }
}

class EmbedderGraphImpl : public EmbedderGraph {
 public:
  struct Edge {
    Node* from;
    Node* to;
    const char* name;
  };

  class V8NodeImpl : public Node {
   public:
    explicit V8NodeImpl(Tagged<Object> object) : object_(object) {}
    Tagged<Object> GetObject() { return object_; }

    // Node overrides.
    bool IsEmbedderNode() override { return false; }
    const char* Name() override {
      // The name should be retrieved via GetObject().
      UNREACHABLE();
    }
    size_t SizeInBytes() override {
      // The size should be retrieved via GetObject().
      UNREACHABLE();
    }

   private:
    Tagged<Object> object_;
  };

  Node* V8Node(const v8::Local<v8::Value>& value) final {
    v8::Local<v8::Data> data = value;
    return V8Node(data);
  }

  Node* V8Node(const v8::Local<v8::Data>& data) final {
    Handle<Object> object = v8::Utils::OpenHandle(*data);
    DCHECK(!object.is_null());
    return AddNode(std::unique_ptr<Node>(new V8NodeImpl(*object)));
  }

  Node* AddNode(std::unique_ptr<Node> node) final {
    Node* result = node.get();
    nodes_.push_back(std::move(node));
    return result;
  }

  void AddEdge(Node* from, Node* to, const char* name) final {
    edges_.push_back({from, to, name});
  }

  const std::vector<std::unique_ptr<Node>>& nodes() { return nodes_; }
  const std::vector<Edge>& edges() { return edges_; }

 private:
  std::vector<std::unique_ptr<Node>> nodes_;
  std::vector<Edge> edges_;
};

class EmbedderGraphEntriesAllocator : public HeapEntriesAllocator {
 public:
  explicit EmbedderGraphEntriesAllocator(HeapSnapshot* snapshot)
      : snapshot_(snapshot),
        names_(snapshot_->profiler()->names()),
        heap_object_map_(snapshot_->profiler()->heap_object_map()) {}
  HeapEntry* AllocateEntry(HeapThing ptr) override;
  HeapEntry* AllocateEntry(Tagged<Smi> smi) override;

 private:
  HeapSnapshot* snapshot_;
  StringsStorage* names_;
  HeapObjectsMap* heap_object_map_;
};

namespace {

const char* EmbedderGraphNodeName(StringsStorage* names,
                                  EmbedderGraphImpl::Node* node) {
  const char* prefix = node->NamePrefix();
  return prefix ? names->GetFormatted("%s %s", prefix, node->Name())
                : names->GetCopy(node->Name());
}

HeapEntry::Type EmbedderGraphNodeType(EmbedderGraphImpl::Node* node) {
  return node->IsRootNode() ? HeapEntry::kSynthetic : HeapEntry::kNative;
}

// Merges the names of an embedder node and its wrapper node.
// If the wrapper node name contains a tag suffix (part after '/') then the
// result is the embedder node name concatenated with the tag suffix.
// Otherwise, the result is the embedder node name.
const char* MergeNames(StringsStorage* names, const char* embedder_name,
                       const char* wrapper_name) {
  const char* suffix = strchr(wrapper_name, '/');
  return suffix ? names->GetFormatted("%s %s", embedder_name, suffix)
                : embedder_name;
}

}  // anonymous namespace

HeapEntry* EmbedderGraphEntriesAllocator::AllocateEntry(HeapThing ptr) {
  EmbedderGraphImpl::Node* node =
      reinterpret_cast<EmbedderGraphImpl::Node*>(ptr);
  DCHECK(node->IsEmbedderNode());
  size_t size = node->SizeInBytes();
  Address lookup_address = reinterpret_cast<Address>(node->GetNativeObject());
  HeapObjectsMap::MarkEntryAccessed accessed =
      HeapObjectsMap::MarkEntryAccessed::kYes;
  HeapObjectsMap::IsNativeObject is_native_object =
      HeapObjectsMap::IsNativeObject::kNo;
  if (!lookup_address) {
    // If there is not a native object associated with this embedder object,
    // then request the address of the embedder object.
    lookup_address = reinterpret_cast<Address>(node->GetAddress());
    is_native_object = HeapObjectsMap::IsNativeObject::kYes;
  }
  if (!lookup_address) {
    // If the Node implementation did not provide either a native address or an
    // embedder address, then use the address of the Node itself for the lookup.
    // In this case, we'll set the "accessed" flag on the newly created
    // HeapEntry to false, to indicate that this entry should not persist for
    // future snapshots.
    lookup_address = reinterpret_cast<Address>(node);
    accessed = HeapObjectsMap::MarkEntryAccessed::kNo;
  }
  SnapshotObjectId id = heap_object_map_->FindOrAddEntry(
      lookup_address, 0, accessed, is_native_object);
  auto* heap_entry = snapshot_->AddEntry(EmbedderGraphNodeType(node),
                                         EmbedderGraphNodeName(names_, node),
                                         id, static_cast<int>(size), 0);
  heap_entry->set_detachedness(node->GetDetachedness());
  return heap_entry;
}

HeapEntry* EmbedderGraphEntriesAllocator::AllocateEntry(Tagged<Smi> smi) {
  DCHECK(false);
  return nullptr;
}

NativeObjectsExplorer::NativeObjectsExplorer(
    HeapSnapshot* snapshot, SnapshottingProgressReportingInterface* progress)
    : isolate_(
          Isolate::FromHeap(snapshot->profiler()->heap_object_map()->heap())),
      snapshot_(snapshot),
      names_(snapshot_->profiler()->names()),
      heap_object_map_(snapshot_->profiler()->heap_object_map()),
      embedder_graph_entries_allocator_(
          new EmbedderGraphEntriesAllocator(snapshot)) {}

void NativeObjectsExplorer::MergeNodeIntoEntry(
    HeapEntry* entry, EmbedderGraph::Node* original_node,
    EmbedderGraph::Node* wrapper_node) {
  // The wrapper node may be an embedder node (for testing purposes) or a V8
  // node (production code).
  if (!wrapper_node->IsEmbedderNode()) {
    // For V8 nodes only we can add a lookup.
    EmbedderGraphImpl::V8NodeImpl* v8_node =
        static_cast<EmbedderGraphImpl::V8NodeImpl*>(wrapper_node);
    Tagged<Object> object = v8_node->GetObject();
    DCHECK(!IsSmi(object));
    if (original_node->GetNativeObject()) {
      Tagged<HeapObject> heap_object = Cast<HeapObject>(object);
      heap_object_map_->AddMergedNativeEntry(original_node->GetNativeObject(),
                                             heap_object.address());
      DCHECK_EQ(entry->id(), heap_object_map_->FindMergedNativeEntry(
                                 original_node->GetNativeObject()));
    }
  }
  entry->set_detachedness(original_node->GetDetachedness());
  entry->set_name(MergeNames(
      names_, EmbedderGraphNodeName(names_, original_node), entry->name()));
  entry->set_type(EmbedderGraphNodeType(original_node));
  DCHECK_GE(entry->self_size() + original_node->SizeInBytes(),
            entry->self_size());
  entry->add_self_size(original_node->SizeInBytes());
}

HeapEntry* NativeObjectsExplorer::EntryForEmbedderGraphNode(
    EmbedderGraphImpl::Node* node) {
  // Return the entry for the wrapper node if present.
  if (node->WrapperNode()) {
    node = node->WrapperNode();
  }
  // Node is EmbedderNode.
  if (node->IsEmbedderNode()) {
    return generator_->FindOrAddEntry(node,
                                      embedder_graph_entries_allocator_.get());
  }
  // Node is V8NodeImpl.
  Tagged<Object> object =
      static_cast<EmbedderGraphImpl::V8NodeImpl*>(node)->GetObject();
  if (IsSmi(object)) return nullptr;
  auto* entry = generator_->FindEntry(
      reinterpret_cast<void*>(Cast<Object>(object).ptr()));
  return entry;
}

bool NativeObjectsExplorer::IterateAndExtractReferences(
    HeapSnapshotGenerator* generator) {
  generator_ = generator;

  if (v8_flags.heap_profiler_use_embedder_graph &&
      snapshot_->profiler()->HasBuildEmbedderGraphCallback()) {
    v8::HandleScope scope(reinterpret_cast<v8::Isolate*>(isolate_));
    DisallowGarbageCollection no_gc;
    EmbedderGraphImpl graph;
    snapshot_->profiler()->BuildEmbedderGraph(isolate_, &graph);
    for (const auto& node : graph.nodes()) {
      // Only add embedder nodes as V8 nodes have been added already by the
      // V8HeapExplorer.
      if (!node->IsEmbedderNode()) continue;

      if (auto* entry = EntryForEmbedderGraphNode(node.get())) {
        if (node->IsRootNode()) {
          snapshot_->root()->SetIndexedAutoIndexReference(
              HeapGraphEdge::kElement, entry, generator_,
              HeapEntry::kOffHeapPointer);
        }
        if (node->WrapperNode()) {
          MergeNodeIntoEntry(entry, node.get(), node->WrapperNode());
        }
      }
    }
    // Fill edges of the graph.
    for (const auto& edge : graph.edges()) {
      // |from| and |to| can be nullptr if the corresponding node is a V8 node
      // pointing to a Smi.
      HeapEntry* from = EntryForEmbedderGraphNode(edge.from);
      if (!from) continue;
      HeapEntry* to = EntryForEmbedderGraphNode(edge.to);
      if (!to) continue;
      if (edge.name == nullptr) {
        from->SetIndexedAutoIndexReference(HeapGraphEdge::kElement, to,
                                           generator_,
                                           HeapEntry::kOffHeapPointer);
      } else {
        from->SetNamedReference(HeapGraphEdge::kInternal,
                                names_->GetCopy(edge.name), to, generator_,
                                HeapEntry::kOffHeapPointer);
      }
    }
  }
  generator_ = nullptr;
  return true;
}

HeapSnapshotGenerator::HeapSnapshotGenerator(
    HeapSnapshot* snapshot, v8::ActivityControl* control,
    v8::HeapProfiler::ObjectNameResolver* resolver, Heap* heap,
    cppgc::EmbedderStackState stack_state)
    : snapshot_(snapshot),
      control_(control),
      v8_heap_explorer_(snapshot_, this, resolver),
      dom_explorer_(snapshot_, this),
      heap_(heap),
      stack_state_(stack_state) {}

namespace {
class V8_NODISCARD NullContextForSnapshotScope {
 public:
  explicit NullContextForSnapshotScope(Isolate* isolate)
      : isolate_(isolate), prev_(isolate->context()) {
    isolate_->set_context(Context());
  }
  ~NullContextForSnapshotScope() { isolate_->set_context(prev_); }

 private:
  Isolate* isolate_;
  Tagged<Context> prev_;
};
}  // namespace

bool HeapSnapshotGenerator::GenerateSnaps
```