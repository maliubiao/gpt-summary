Response:

### 提示词
```
这是目录为v8/src/heap/factory.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
HasDictionaryElements() || js_obj->HasSharedArrayElements());
  return handle(js_obj, isolate());
}

Handle<JSObject> Factory::NewSlowJSObjectFromMap(
    DirectHandle<Map> map, int capacity, AllocationType allocation,
    DirectHandle<AllocationSite> allocation_site,
    NewJSObjectType new_js_object_type) {
  DCHECK(map->is_dictionary_map());
  DirectHandle<HeapObject> object_properties;
  if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    object_properties = NewSwissNameDictionary(capacity, allocation);
  } else {
    object_properties = NameDictionary::New(isolate(), capacity);
  }
  Handle<JSObject> js_object =
      NewJSObjectFromMap(map, allocation, allocation_site, new_js_object_type);
  js_object->set_raw_properties_or_hash(*object_properties, kRelaxedStore);
  return js_object;
}

Handle<JSObject> Factory::NewSlowJSObjectFromMap(DirectHandle<Map> map) {
  return NewSlowJSObjectFromMap(map, PropertyDictionary::kInitialCapacity);
}

Handle<JSObject> Factory::NewSlowJSObjectWithPropertiesAndElements(
    Handle<JSPrototype> prototype, DirectHandle<HeapObject> properties,
    DirectHandle<FixedArrayBase> elements) {
  DCHECK(IsPropertyDictionary(*properties));

  Handle<Map> object_map = isolate()->slow_object_with_object_prototype_map();
  if (object_map->prototype() != *prototype) {
    object_map = Map::TransitionRootMapToPrototypeForNewObject(
        isolate(), object_map, prototype);
  }
  DCHECK(object_map->is_dictionary_map());
  Handle<JSObject> object =
      NewJSObjectFromMap(object_map, AllocationType::kYoung);
  object->set_raw_properties_or_hash(*properties);
  if (*elements != read_only_roots().empty_fixed_array()) {
    DCHECK(IsNumberDictionary(*elements));
    object_map =
        JSObject::GetElementsTransitionMap(object, DICTIONARY_ELEMENTS);
    JSObject::MigrateToMap(isolate(), object, object_map);
    object->set_elements(*elements);
  }
  return object;
}

Handle<JSArray> Factory::NewJSArray(ElementsKind elements_kind, int length,
                                    int capacity,
                                    ArrayStorageAllocationMode mode,
                                    AllocationType allocation) {
  DCHECK(capacity >= length);
  if (capacity == 0) {
    return NewJSArrayWithElements(empty_fixed_array(), elements_kind, length,
                                  allocation);
  }

  HandleScope inner_scope(isolate());
  DirectHandle<FixedArrayBase> elms =
      NewJSArrayStorage(elements_kind, capacity, mode);
  return inner_scope.CloseAndEscape(NewJSArrayWithUnverifiedElements(
      elms, elements_kind, length, allocation));
}

Handle<JSArray> Factory::NewJSArrayWithElements(
    DirectHandle<FixedArrayBase> elements, ElementsKind elements_kind,
    int length, AllocationType allocation) {
  Handle<JSArray> array = NewJSArrayWithUnverifiedElements(
      elements, elements_kind, length, allocation);
#ifdef ENABLE_SLOW_DCHECKS
  JSObject::ValidateElements(*array);
#endif
  return array;
}

Handle<JSArray> Factory::NewJSArrayWithUnverifiedElements(
    DirectHandle<FixedArrayBase> elements, ElementsKind elements_kind,
    int length, AllocationType allocation) {
  DCHECK(length <= elements->length());
  Tagged<NativeContext> native_context = isolate()->raw_native_context();
  Tagged<Map> map = native_context->GetInitialJSArrayMap(elements_kind);
  if (map.is_null()) {
    Tagged<JSFunction> array_function = native_context->array_function();
    map = array_function->initial_map();
  }
  return NewJSArrayWithUnverifiedElements(handle(map, isolate()), elements,
                                          length, allocation);
}

Handle<JSArray> Factory::NewJSArrayWithUnverifiedElements(
    DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements, int length,
    AllocationType allocation) {
  auto array = Cast<JSArray>(NewJSObjectFromMap(map, allocation));
  DisallowGarbageCollection no_gc;
  Tagged<JSArray> raw = *array;
  raw->set_elements(*elements);
  raw->set_length(Smi::FromInt(length));
  return array;
}

Handle<JSArray> Factory::NewJSArrayForTemplateLiteralArray(
    DirectHandle<FixedArray> cooked_strings,
    DirectHandle<FixedArray> raw_strings, int function_literal_id,
    int slot_id) {
  Handle<JSArray> raw_object =
      NewJSArrayWithElements(raw_strings, PACKED_ELEMENTS,
                             raw_strings->length(), AllocationType::kOld);
  JSObject::SetIntegrityLevel(isolate(), raw_object, FROZEN, kThrowOnError)
      .ToChecked();

  DirectHandle<NativeContext> native_context = isolate()->native_context();
  auto template_object =
      Cast<TemplateLiteralObject>(NewJSArrayWithUnverifiedElements(
          handle(native_context->js_array_template_literal_object_map(),
                 isolate()),
          cooked_strings, cooked_strings->length(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  Tagged<TemplateLiteralObject> raw_template_object = *template_object;
  DCHECK_EQ(raw_template_object->map(),
            native_context->js_array_template_literal_object_map());
  raw_template_object->set_raw(*raw_object);
  raw_template_object->set_function_literal_id(function_literal_id);
  raw_template_object->set_slot_id(slot_id);
  return template_object;
}

void Factory::NewJSArrayStorage(DirectHandle<JSArray> array, int length,
                                int capacity, ArrayStorageAllocationMode mode) {
  DCHECK(capacity >= length);

  if (capacity == 0) {
    Tagged<JSArray> raw = *array;
    DisallowGarbageCollection no_gc;
    raw->set_length(Smi::zero());
    raw->set_elements(*empty_fixed_array());
    return;
  }

  HandleScope inner_scope(isolate());
  DirectHandle<FixedArrayBase> elms =
      NewJSArrayStorage(array->GetElementsKind(), capacity, mode);
  DisallowGarbageCollection no_gc;
  Tagged<JSArray> raw = *array;
  raw->set_elements(*elms);
  raw->set_length(Smi::FromInt(length));
}

Handle<FixedArrayBase> Factory::NewJSArrayStorage(
    ElementsKind elements_kind, int capacity, ArrayStorageAllocationMode mode) {
  DCHECK_GT(capacity, 0);
  Handle<FixedArrayBase> elms;
  if (IsDoubleElementsKind(elements_kind)) {
    if (mode == ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS) {
      elms = NewFixedDoubleArray(capacity);
    } else {
      DCHECK_EQ(
          mode,
          ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
      elms = NewFixedDoubleArrayWithHoles(capacity);
    }
  } else {
    DCHECK(IsSmiOrObjectElementsKind(elements_kind));
    if (mode == ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS) {
      elms = NewFixedArray(capacity);
    } else {
      DCHECK_EQ(
          mode,
          ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
      elms = NewFixedArrayWithHoles(capacity);
    }
  }
  return elms;
}

Handle<JSWeakMap> Factory::NewJSWeakMap() {
  Tagged<NativeContext> native_context = isolate()->raw_native_context();
  DirectHandle<Map> map(native_context->js_weak_map_fun()->initial_map(),
                        isolate());
  Handle<JSWeakMap> weakmap(Cast<JSWeakMap>(*NewJSObjectFromMap(map)),
                            isolate());
  {
    // Do not leak handles for the hash table, it would make entries strong.
    HandleScope scope(isolate());
    JSWeakCollection::Initialize(weakmap, isolate());
  }
  return weakmap;
}

Handle<JSModuleNamespace> Factory::NewJSModuleNamespace() {
  DirectHandle<Map> map = isolate()->js_module_namespace_map();
  Handle<JSModuleNamespace> module_namespace(
      Cast<JSModuleNamespace>(NewJSObjectFromMap(
          map, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
          NewJSObjectType::kAPIWrapper)));
  FieldIndex index = FieldIndex::ForDescriptor(
      *map, InternalIndex(JSModuleNamespace::kToStringTagFieldIndex));
  module_namespace->FastPropertyAtPut(index, read_only_roots().Module_string(),
                                      SKIP_WRITE_BARRIER);
  return module_namespace;
}

Handle<JSWrappedFunction> Factory::NewJSWrappedFunction(
    DirectHandle<NativeContext> creation_context, DirectHandle<Object> target) {
  DCHECK(IsCallable(*target));
  DirectHandle<Map> map(
      Cast<Map>(creation_context->get(Context::WRAPPED_FUNCTION_MAP_INDEX)),
      isolate());
  // 2. Let wrapped be ! MakeBasicObject(internalSlotsList).
  // 3. Set wrapped.[[Prototype]] to
  // callerRealm.[[Intrinsics]].[[%Function->prototype%]].
  // 4. Set wrapped.[[Call]] as described in 2.1.
  Handle<JSWrappedFunction> wrapped =
      Cast<JSWrappedFunction>(isolate()->factory()->NewJSObjectFromMap(map));
  // 5. Set wrapped.[[WrappedTargetFunction]] to Target.
  wrapped->set_wrapped_target_function(Cast<JSCallable>(*target));
  // 6. Set wrapped.[[Realm]] to callerRealm.
  wrapped->set_context(*creation_context);
  // TODO(v8:11989): https://github.com/tc39/proposal-shadowrealm/pull/348

  return wrapped;
}

Handle<JSGeneratorObject> Factory::NewJSGeneratorObject(
    Handle<JSFunction> function) {
  DCHECK(IsResumableFunction(function->shared()->kind()));
  JSFunction::EnsureHasInitialMap(function);
  DirectHandle<Map> map(function->initial_map(), isolate());

  DCHECK(map->instance_type() == JS_GENERATOR_OBJECT_TYPE ||
         map->instance_type() == JS_ASYNC_GENERATOR_OBJECT_TYPE);

  return Cast<JSGeneratorObject>(NewJSObjectFromMap(map));
}

Handle<JSDisposableStackBase> Factory::NewJSDisposableStackBase() {
  DirectHandle<NativeContext> native_context = isolate()->native_context();
  DirectHandle<Map> map(native_context->js_disposable_stack_map(), isolate());
  Handle<JSDisposableStackBase> disposable_stack(
      Cast<JSDisposableStackBase>(NewJSObjectFromMap(map)));
  disposable_stack->set_status(0);
  return disposable_stack;
}

Handle<JSSyncDisposableStack> Factory::NewJSSyncDisposableStack(
    DirectHandle<Map> map) {
  Handle<JSSyncDisposableStack> disposable_stack(
      Cast<JSSyncDisposableStack>(NewJSObjectFromMap(map)));
  disposable_stack->set_status(0);
  return disposable_stack;
}

Handle<JSAsyncDisposableStack> Factory::NewJSAsyncDisposableStack(
    DirectHandle<Map> map) {
  Handle<JSAsyncDisposableStack> disposable_stack(
      Cast<JSAsyncDisposableStack>(NewJSObjectFromMap(map)));
  disposable_stack->set_status(0);
  return disposable_stack;
}

Handle<SourceTextModule> Factory::NewSourceTextModule(
    DirectHandle<SharedFunctionInfo> sfi) {
  DirectHandle<SourceTextModuleInfo> module_info(
      sfi->scope_info()->ModuleDescriptorInfo(), isolate());
  DirectHandle<ObjectHashTable> exports =
      ObjectHashTable::New(isolate(), module_info->RegularExportCount());
  DirectHandle<FixedArray> regular_exports =
      NewFixedArray(module_info->RegularExportCount());
  DirectHandle<FixedArray> regular_imports =
      NewFixedArray(module_info->regular_imports()->length());
  int requested_modules_length = module_info->module_requests()->length();
  DirectHandle<FixedArray> requested_modules =
      requested_modules_length > 0 ? NewFixedArray(requested_modules_length)
                                   : empty_fixed_array();

  ReadOnlyRoots roots(isolate());
  Tagged<SourceTextModule> module = Cast<SourceTextModule>(
      New(source_text_module_map(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  module->set_code(*sfi);
  module->set_exports(*exports);
  module->set_regular_exports(*regular_exports);
  module->set_regular_imports(*regular_imports);
  module->set_hash(isolate()->GenerateIdentityHash(Smi::kMaxValue));
  module->set_module_namespace(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_requested_modules(*requested_modules);
  module->set_status(Module::kUnlinked);
  module->set_exception(roots.the_hole_value(), SKIP_WRITE_BARRIER);
  module->set_top_level_capability(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_import_meta(roots.the_hole_value(), kReleaseStore,
                          SKIP_WRITE_BARRIER);
  module->set_dfs_index(-1);
  module->set_dfs_ancestor_index(-1);
  module->set_flags(0);
  module->set_has_toplevel_await(IsModuleWithTopLevelAwait(sfi->kind()));
  module->set_async_evaluation_ordinal(SourceTextModule::kNotAsyncEvaluated);
  module->set_cycle_root(roots.the_hole_value(), SKIP_WRITE_BARRIER);
  module->set_async_parent_modules(roots.empty_array_list());
  module->set_pending_async_dependencies(0);
  return handle(module, isolate());
}

Handle<SyntheticModule> Factory::NewSyntheticModule(
    DirectHandle<String> module_name, DirectHandle<FixedArray> export_names,
    v8::Module::SyntheticModuleEvaluationSteps evaluation_steps) {
  ReadOnlyRoots roots(isolate());

  DirectHandle<ObjectHashTable> exports =
      ObjectHashTable::New(isolate(), static_cast<int>(export_names->length()));
  DirectHandle<Foreign> evaluation_steps_foreign =
      NewForeign<kSyntheticModuleTag>(
          reinterpret_cast<Address>(evaluation_steps));

  Tagged<SyntheticModule> module =
      Cast<SyntheticModule>(New(synthetic_module_map(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  module->set_hash(isolate()->GenerateIdentityHash(Smi::kMaxValue));
  module->set_module_namespace(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_status(Module::kUnlinked);
  module->set_exception(roots.the_hole_value(), SKIP_WRITE_BARRIER);
  module->set_top_level_capability(roots.undefined_value(), SKIP_WRITE_BARRIER);
  module->set_name(*module_name);
  module->set_export_names(*export_names);
  module->set_exports(*exports);
  module->set_evaluation_steps(*evaluation_steps_foreign);
  return handle(module, isolate());
}

Handle<JSArrayBuffer> Factory::NewJSArrayBuffer(
    std::shared_ptr<BackingStore> backing_store, AllocationType allocation) {
  DirectHandle<Map> map(
      isolate()->native_context()->array_buffer_fun()->initial_map(),
      isolate());
  ResizableFlag resizable_by_js = ResizableFlag::kNotResizable;
  if (backing_store->is_resizable_by_js()) {
    resizable_by_js = ResizableFlag::kResizable;
  }
  auto result = Cast<JSArrayBuffer>(
      NewJSObjectFromMap(map, allocation, DirectHandle<AllocationSite>::null(),
                         NewJSObjectType::kAPIWrapper));
  result->Setup(SharedFlag::kNotShared, resizable_by_js,
                std::move(backing_store), isolate());
  return result;
}

MaybeHandle<JSArrayBuffer> Factory::NewJSArrayBufferAndBackingStore(
    size_t byte_length, InitializedFlag initialized,
    AllocationType allocation) {
  return NewJSArrayBufferAndBackingStore(byte_length, byte_length, initialized,
                                         ResizableFlag::kNotResizable,
                                         allocation);
}

MaybeHandle<JSArrayBuffer> Factory::NewJSArrayBufferAndBackingStore(
    size_t byte_length, size_t max_byte_length, InitializedFlag initialized,
    ResizableFlag resizable, AllocationType allocation) {
  DCHECK_LE(byte_length, max_byte_length);
  std::unique_ptr<BackingStore> backing_store = nullptr;

  if (resizable == ResizableFlag::kResizable) {
    size_t page_size, initial_pages, max_pages;
    if (JSArrayBuffer::GetResizableBackingStorePageConfiguration(
            isolate(), byte_length, max_byte_length, kDontThrow, &page_size,
            &initial_pages, &max_pages)
            .IsNothing()) {
      return MaybeHandle<JSArrayBuffer>();
    }

    backing_store = BackingStore::TryAllocateAndPartiallyCommitMemory(
        isolate(), byte_length, max_byte_length, page_size, initial_pages,
        max_pages, WasmMemoryFlag::kNotWasm, SharedFlag::kNotShared);
    if (!backing_store) return MaybeHandle<JSArrayBuffer>();
  } else {
    if (byte_length > 0) {
      backing_store = BackingStore::Allocate(
          isolate(), byte_length, SharedFlag::kNotShared, initialized);
      if (!backing_store) return MaybeHandle<JSArrayBuffer>();
    }
  }
  DirectHandle<Map> map(
      isolate()->native_context()->array_buffer_fun()->initial_map(),
      isolate());
  auto array_buffer = Cast<JSArrayBuffer>(
      NewJSObjectFromMap(map, allocation, DirectHandle<AllocationSite>::null(),
                         NewJSObjectType::kAPIWrapper));
  array_buffer->Setup(SharedFlag::kNotShared, resizable,
                      std::move(backing_store), isolate());
  return array_buffer;
}

Handle<JSArrayBuffer> Factory::NewJSSharedArrayBuffer(
    std::shared_ptr<BackingStore> backing_store) {
  DirectHandle<Map> map(
      isolate()->native_context()->shared_array_buffer_fun()->initial_map(),
      isolate());
  auto result = Cast<JSArrayBuffer>(NewJSObjectFromMap(
      map, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
      NewJSObjectType::kAPIWrapper));
  ResizableFlag resizable = backing_store->is_resizable_by_js()
                                ? ResizableFlag::kResizable
                                : ResizableFlag::kNotResizable;
  result->Setup(SharedFlag::kShared, resizable, std::move(backing_store),
                isolate());
  return result;
}

Handle<JSIteratorResult> Factory::NewJSIteratorResult(
    DirectHandle<Object> value, bool done) {
  DirectHandle<Map> map(isolate()->native_context()->iterator_result_map(),
                        isolate());
  Handle<JSIteratorResult> js_iter_result =
      Cast<JSIteratorResult>(NewJSObjectFromMap(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  Tagged<JSIteratorResult> raw = *js_iter_result;
  raw->set_value(*value, SKIP_WRITE_BARRIER);
  raw->set_done(*ToBoolean(done), SKIP_WRITE_BARRIER);
  return js_iter_result;
}

Handle<JSAsyncFromSyncIterator> Factory::NewJSAsyncFromSyncIterator(
    DirectHandle<JSReceiver> sync_iterator, DirectHandle<Object> next) {
  DirectHandle<Map> map(
      isolate()->native_context()->async_from_sync_iterator_map(), isolate());
  Handle<JSAsyncFromSyncIterator> iterator = Cast<JSAsyncFromSyncIterator>(
      NewJSObjectFromMap(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  Tagged<JSAsyncFromSyncIterator> raw = *iterator;
  raw->set_sync_iterator(*sync_iterator, SKIP_WRITE_BARRIER);
  raw->set_next(*next, SKIP_WRITE_BARRIER);
  return iterator;
}

Handle<JSMap> Factory::NewJSMap() {
  DirectHandle<Map> map(isolate()->native_context()->js_map_map(), isolate());
  Handle<JSMap> js_map = Cast<JSMap>(NewJSObjectFromMap(map));
  JSMap::Initialize(js_map, isolate());
  return js_map;
}

Handle<JSSet> Factory::NewJSSet() {
  DirectHandle<Map> map(isolate()->native_context()->js_set_map(), isolate());
  Handle<JSSet> js_set = Cast<JSSet>(NewJSObjectFromMap(map));
  JSSet::Initialize(js_set, isolate());
  return js_set;
}

void Factory::TypeAndSizeForElementsKind(ElementsKind kind,
                                         ExternalArrayType* array_type,
                                         size_t* element_size) {
  switch (kind) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                           \
    *array_type = kExternal##Type##Array;         \
    *element_size = sizeof(ctype);                \
    break;
    TYPED_ARRAYS(TYPED_ARRAY_CASE)
    RAB_GSAB_TYPED_ARRAYS_WITH_TYPED_ARRAY_TYPE(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

    default:
      UNREACHABLE();
  }
}

Handle<JSArrayBufferView> Factory::NewJSArrayBufferView(
    DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements,
    DirectHandle<JSArrayBuffer> buffer, size_t byte_offset,
    size_t byte_length) {
  if (!IsRabGsabTypedArrayElementsKind(map->elements_kind())) {
    CHECK_LE(byte_length, buffer->GetByteLength());
    CHECK_LE(byte_offset, buffer->GetByteLength());
    CHECK_LE(byte_offset + byte_length, buffer->GetByteLength());
  }

  Handle<JSArrayBufferView> array_buffer_view =
      Cast<JSArrayBufferView>(NewJSObjectFromMap(
          map, AllocationType::kYoung, DirectHandle<AllocationSite>::null(),
          NewJSObjectType::kAPIWrapper));
  DisallowGarbageCollection no_gc;
  Tagged<JSArrayBufferView> raw = *array_buffer_view;
  raw->set_elements(*elements, SKIP_WRITE_BARRIER);
  raw->set_buffer(*buffer, SKIP_WRITE_BARRIER);
  raw->set_byte_offset(byte_offset);
  raw->set_byte_length(byte_length);
  raw->set_bit_field(0);
  // TODO(v8) remove once embedder data slots are always zero-initialized.
  InitEmbedderFields(raw, Smi::zero());
  DCHECK_EQ(raw->GetEmbedderFieldCount(),
            v8::ArrayBufferView::kEmbedderFieldCount);
  return array_buffer_view;
}

Handle<JSTypedArray> Factory::NewJSTypedArray(
    ExternalArrayType type, DirectHandle<JSArrayBuffer> buffer,
    size_t byte_offset, size_t length, bool is_length_tracking) {
  size_t element_size;
  ElementsKind elements_kind;
  JSTypedArray::ForFixedTypedArray(type, &element_size, &elements_kind);

  const bool is_backed_by_rab =
      buffer->is_resizable_by_js() && !buffer->is_shared();

  DirectHandle<Map> map;
  if (is_backed_by_rab || is_length_tracking) {
    map = direct_handle(
        isolate()->raw_native_context()->TypedArrayElementsKindToRabGsabCtorMap(
            elements_kind),
        isolate());
  } else {
    map = direct_handle(
        isolate()->raw_native_context()->TypedArrayElementsKindToCtorMap(
            elements_kind),
        isolate());
  }

  if (is_length_tracking) {
    // Security: enforce the invariant that length-tracking TypedArrays have
    // their length and byte_length set to 0.
    length = 0;
  }

  CHECK_LE(length, JSTypedArray::kMaxByteLength / element_size);
  CHECK_EQ(0, byte_offset % element_size);
  size_t byte_length = length * element_size;

  Handle<JSTypedArray> typed_array = Cast<JSTypedArray>(NewJSArrayBufferView(
      map, empty_byte_array(), buffer, byte_offset, byte_length));
  Tagged<JSTypedArray> raw = *typed_array;
  DisallowGarbageCollection no_gc;
  raw->set_length(length);
  raw->SetOffHeapDataPtr(isolate(), buffer->backing_store(), byte_offset);
  raw->set_is_length_tracking(is_length_tracking);
  raw->set_is_backed_by_rab(is_backed_by_rab);
  return typed_array;
}

Handle<JSDataViewOrRabGsabDataView> Factory::NewJSDataViewOrRabGsabDataView(
    DirectHandle<JSArrayBuffer> buffer, size_t byte_offset, size_t byte_length,
    bool is_length_tracking) {
  if (is_length_tracking) {
    // Security: enforce the invariant that length-tracking DataViews have their
    // byte_length set to 0.
    byte_length = 0;
  }
  bool is_backed_by_rab = !buffer->is_shared() && buffer->is_resizable_by_js();
  DirectHandle<Map> map;
  if (is_backed_by_rab || is_length_tracking) {
    map = direct_handle(
        isolate()->native_context()->js_rab_gsab_data_view_map(), isolate());
  } else {
    map = direct_handle(
        isolate()->native_context()->data_view_fun()->initial_map(), isolate());
  }
  Handle<JSDataViewOrRabGsabDataView> obj =
      Cast<JSDataViewOrRabGsabDataView>(NewJSArrayBufferView(
          map, empty_fixed_array(), buffer, byte_offset, byte_length));
  obj->set_data_pointer(
      isolate(), static_cast<uint8_t*>(buffer->backing_store()) + byte_offset);
  obj->set_is_length_tracking(is_length_tracking);
  obj->set_is_backed_by_rab(is_backed_by_rab);
  return obj;
}

MaybeHandle<JSBoundFunction> Factory::NewJSBoundFunction(
    DirectHandle<JSReceiver> target_function, DirectHandle<JSAny> bound_this,
    base::Vector<DirectHandle<Object>> bound_args,
    Handle<JSPrototype> prototype) {
  DCHECK(IsCallable(*target_function));
  static_assert(Code::kMaxArguments <= FixedArray::kMaxLength);
  if (bound_args.length() >= Code::kMaxArguments) {
    THROW_NEW_ERROR(isolate(),
                    NewRangeError(MessageTemplate::kTooManyArguments));
  }

  SaveAndSwitchContext save(isolate(),
                            target_function->GetCreationContext().value());

  // Create the [[BoundArguments]] for the result.
  DirectHandle<FixedArray> bound_arguments;
  if (bound_args.empty()) {
    bound_arguments = empty_fixed_array();
  } else {
    bound_arguments = NewFixedArray(bound_args.length());
    for (int i = 0; i < bound_args.length(); ++i) {
      bound_arguments->set(i, *bound_args[i]);
    }
  }

  // Setup the map for the JSBoundFunction instance.
  Handle<Map> map = IsConstructor(*target_function)
                        ? isolate()->bound_function_with_constructor_map()
                        : isolate()->bound_function_without_constructor_map();
  if (map->prototype() != *prototype) {
    map = Map::TransitionRootMapToPrototypeForNewObject(isolate(), map,
                                                        prototype);
  }
  DCHECK_EQ(IsConstructor(*target_function), map->is_constructor());

  // Setup the JSBoundFunction instance.
  Handle<JSBoundFunction> result =
      Cast<JSBoundFunction>(NewJSObjectFromMap(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  Tagged<JSBoundFunction> raw = *result;
  raw->set_bound_target_function(Cast<JSCallable>(*target_function),
                                 SKIP_WRITE_BARRIER);
  raw->set_bound_this(*bound_this, SKIP_WRITE_BARRIER);
  raw->set_bound_arguments(*bound_arguments, SKIP_WRITE_BARRIER);
  return result;
}

// ES6 section 9.5.15 ProxyCreate (target, handler)
Handle<JSProxy> Factory::NewJSProxy(DirectHandle<JSReceiver> target,
                                    DirectHandle<JSReceiver> handler) {
  // Allocate the proxy object.
  DirectHandle<Map> map = IsCallable(*target)
                              ? IsConstructor(*target)
                                    ? isolate()->proxy_constructor_map()
                                    : isolate()->proxy_callable_map()
                              : isolate()->proxy_map();
  DCHECK(IsNull(map->prototype(), isolate()));
  Tagged<JSProxy> result = Cast<JSProxy>(New(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  result->initialize_properties(isolate());
  result->set_target(*target, SKIP_WRITE_BARRIER);
  result->set_handler(*handler, SKIP_WRITE_BARRIER);
  return handle(result, isolate());
}

Handle<JSGlobalProxy> Factory::NewUninitializedJSGlobalProxy(int size) {
  // Create an empty shell of a JSGlobalProxy that needs to be reinitialized
  // via ReinitializeJSGlobalProxy later.
  DirectHandle<Map> map = NewContextlessMap(JS_GLOBAL_PROXY_TYPE, size);
  // Maintain invariant expected from any JSGlobalProxy.
  {
    DisallowGarbageCollection no_gc;
    Tagged<Map> raw = *map;
    raw->set_is_access_check_needed(true);
    raw->set_may_have_interesting_properties(true);
    LOG(isolate(), MapDetails(raw));
  }
  Handle<JSGlobalProxy> proxy = Cast<JSGlobalProxy>(NewJSObjectFromMap(
      map, AllocationType::kOld, DirectHandle<AllocationSite>::null(),
      NewJSObjectType::kAPIWrapper));
  // Create identity hash early in case there is any JS collection containing
  // a global proxy key and needs to be rehashed after deserialization.
  proxy->GetOrCreateIdentityHash(isolate());
  return proxy;
}

void Factory::ReinitializeJSGlobalProxy(DirectHandle<JSGlobalProxy> object,
                                        DirectHandle<JSFunction> constructor) {
  DCHECK(constructor->has_initial_map());
  Handle<Map> map(constructor->initial_map(), isolate());
  DirectHandle<Map> old_map(object->map(), isolate());

  // The proxy's hash should be retained across reinitialization.
  DirectHandle<Object> raw_properties_or_hash(object->raw_properties_or_hash(),
                                              isolate());

  if (old_map->is_prototype_map()) {
    map = Map::Copy(isolate(), map, "CopyAsPrototypeForJSGlobalProxy");
    map->set_is_prototype_map(true);
  }
  JSObject::NotifyMapChange(old_map, map, isolate());
  old_map->NotifyLeafMapLayoutChange(isolate());

  // Check that the already allocated object has the same size and type as
  // objects allocated using the constructor.
  DCHECK(map->instance_size() == old_map->instance_size());
  DCHECK(map->instance_type() == old_map->instance_type());

  // In order to keep heap in consistent state there must be no allocations
  // before object re-initialization is finished.
  DisallowGarbageCollection no_gc;

  // Reset the map for the object.
  Tagged<JSGlobalProxy> raw = *object;
  raw->set_map(isolate(), *map, kReleaseStore);

  // Reinitialize the object from the constructor map.
  InitializeJSObjectFromMap(raw, *raw_properties_or_hash, *map,
                            NewJSObjectType::kAPIWrapper);
  // Ensure that the object and constructor belongs to the same native context.
  DCHECK_EQ(object->map()->map(), constructor->map()->map());
}

Handle<JSMessageObject> Factory::NewJSMessageObject(
    MessageTemplate message, DirectHandle<Object> argument, int start_position,
    int end_position, DirectHandle<SharedFunctionInfo> shared_info,
    int bytecode_offset, DirectHandle<Script> script,
    DirectHandle<StackTraceInfo> stack_trace) {
  DirectHandle<Map> map = message_object_map();
  Tagged<JSMessageObject> message_obj =
      Cast<JSMessageObject>(New(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  message_obj->set_raw_properties_or_hash(*empty_fixed_array(),
                                          SKIP_WRITE_BARRIER);
  message_obj->initialize_elements();
  message_obj->set_elements(*empty_fixed_array(), SKIP_WRITE_BARRIER);
  message_obj->set_type(message);
  message_obj->set_argument(*argument, SKIP_WRITE_BARRIER);
  message_obj->set_start_position(start_position);
  message_obj->set_end_position(end_position);
  message_obj->set_script(*script, SKIP_WRITE_BARRIER);
  if (start_position >= 0) {
    // If there's a start_position, then there's no need to store the
    // SharedFunctionInfo as it will never be necessary to regenerate the
    // position.
    message_obj->set_shared_info(Smi::FromInt(-1));
    message_obj->set_bytecode_offset(Smi::FromInt(0));
  } else {
    message_obj->set_bytecode_offset(Smi::FromInt(bytecode_offset));
    if (shared_info.is_null()) {
      message_obj->set_shared_info(Smi::FromInt(-1));
      DCHECK_EQ(bytecode_offset, -1);
    } else {
      message_obj->set_shared_info(*shared_info, SKIP_WRITE_BARRIER);
      DCHECK_GE(bytecode_offset, kFunctionEntryBytecodeOffset);
    }
  }

  if (stack_trace.is_null()) {
    message_obj->set_stack_trace(*the_hole_value(), SKIP_WRITE_BARRIER);
  } else {
    message_obj->set_stack_trace(*stack_trace, SKIP_WRITE_BARRIER);
  }
  message_obj->set_error_level(v8::Isolate::kMessageError);
  return handle(message_obj, isolate());
}

Handle<SharedFunctionInfo> Factory::NewSharedFunctionInfoForApiFunction(
    MaybeDirectHandle<String> maybe_name,
    DirectHandle<FunctionTemplateInfo> function_template_info,
    FunctionKind kind) {
  return NewSharedFunctionInfo(
      maybe_name, function_template_info, Builtin::kNoBuiltinId,
      function_template_info->length(), kDontAdapt, kind);
}

Handle<SharedFunctionInfo> Factory::NewSharedFunctionInfoForBuiltin(
    MaybeDirectHandle<String> maybe_name, Builtin builtin, int len,
    AdaptArguments adapt, FunctionKind kind) {
  return NewSharedFunctionInfo(maybe_name, MaybeHandle<HeapObject>(), builtin,
                               len, adapt, kind);
}

Handle<InterpreterData> Factory::NewInterpreterData(
    DirectHandle<BytecodeArray> bytecode_array, DirectHandle<Code> code) {
  Tagged<Map> map = *interpreter_data_map();
  Tagged<InterpreterData> interpreter_data = Cast<InterpreterData>(
      AllocateRawWithImmortalMap(map->instance_size(), AllocationType::kTrusted,
                                 *interpreter_data_map()));
  DisallowGarbageCollection no_gc;
  interpreter_data->init_self_indirect_pointer(isolate());
  interpreter_data->set_bytecode_array(*bytecode_array);
  interpreter_data->set_interpreter_trampoline(*code);
  return handle(interpreter_data, isolate());
}

int Factory::NumberToStringCacheHash(Tagged<Smi> number) {
  int mask = (number_string_cache()->length() >> 1) - 1;
  return number.value() & mask;
}

int Factory::NumberToStringCacheHash(double number) {
  int mask = (number_string_cache()->length() >> 1) - 1;
  int64_t bits = base::bit_cast<int64_t>(number);
  return (static_cast<int>(bits) ^ static_cast<int>(bits >> 32)) & mask;
}

Handle<String> Factory::SizeToString(size_t value, bool check_cache) {
  Handle<String> result;
  NumberCacheMode cache_mode =
      check_cache ? NumberCacheMode::kBoth : NumberCacheMode::kIgnore;
  if (value <= Smi::kMaxValue) {
    int32_t int32v = static_cast<int32_t>(static_cast<uint32_t>(value));
    // SmiToString sets the hash when needed, we can return immediately.
    return SmiToString(Smi::FromInt(int32v), cache_mode);
  } else if (value <= kMaxSafeInteger) {
    // TODO(jkummerow): Refactor the cache to not require Objects as keys.
    double double_value = static_cast<double>(value);
    result = HeapNumberToString(NewHeapNumber(double_value), value, cache_mode);
  } else {
    char arr[kNumberToS
```