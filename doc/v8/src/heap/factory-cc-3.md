Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/heap/factory.cc`. The request also includes specific instructions: check if it could be a Torque file (based on the `.tq` extension), relate it to JavaScript with examples if possible, provide logical reasoning with hypothetical input/output, highlight common user errors, and finally, summarize the overall function of the code.

Here's a breakdown of the thought process to achieve the desired output:

1. **Identify the Core Functionality:**  The code primarily deals with creating and manipulating various heap objects, particularly `Map` and `JSObject`. The `Factory` class acts as a central point for object allocation and initialization.

2. **Check for Torque:** The prompt explicitly asks about the `.tq` extension. Since the provided code is in a `.cc` file, it's not a Torque file. This is a direct observation.

3. **Relate to JavaScript:**  The created objects (like `JSObject`, `Map`, arrays, errors) are fundamental building blocks of the JavaScript language in V8. The connection lies in how these C++ structures represent JavaScript concepts internally. Examples are needed to illustrate this:
    * Creating an object (`{}`) is directly linked to `NewJSObject`.
    * Creating a map (`new Map()`) is related to `NewMap`.
    * Creating errors (`new Error()`) uses the `NewError` functions.
    * Array creation (`[]`) uses functions like `CopyFixedArray`.

4. **Logical Reasoning (Input/Output):**  Consider specific functions and what they do.
    * `NewMap`: Takes parameters defining the map's characteristics (size, type, elements kind) and returns a `Handle<Map>`. A simple example would be calling it with basic object parameters.
    * `CopyJSObject`: Takes an existing `JSObject` and returns a copy. The input is a `JSObject`, the output is a new `JSObject` with the same data.
    * `CopyFixedArray`: Takes a `FixedArray` and returns a copy. The input is a `FixedArray`, the output is a new `FixedArray` with the same elements.

5. **Common User Errors:** Think about how JavaScript developers might interact with the concepts these functions represent and what errors could occur.
    * Trying to modify immutable objects (handled internally by V8, but can lead to unexpected behavior).
    * Incorrectly assuming object structure or properties.
    * Errors related to string lengths (handled by `NewInvalidStringLengthError`).

6. **Section Summary:** This is the core request. Synthesize the information gathered so far into a concise description of the file's purpose. Focus on the role of the `Factory` in object creation and management.

7. **Structure the Output:** Organize the findings clearly based on the prompt's requirements:
    * Functionality Summary.
    * Torque Check.
    * Relationship to JavaScript (with examples).
    * Logical Reasoning (with examples).
    * Common User Errors (with examples).
    * Overall Function Summary.

8. **Refine and Elaborate:**  Review the generated output for clarity, accuracy, and completeness. For instance, in the JavaScript examples, ensure the C++ function mentioned is relevant. In the logical reasoning, the input and output should align with the function's purpose. For common errors, make the link between the error and the V8 code clear.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus only on the `New...` functions.
* **Correction:** Realize that `Copy...` functions are equally important for object management and should be included.
* **Initial thought:** Provide very technical C++ examples for logical reasoning.
* **Correction:**  Simplify the examples to focus on the JavaScript-level concepts that the C++ code underpins. The input/output should be understandable even without deep C++ knowledge.
* **Initial thought:**  Focus on low-level memory details for user errors.
* **Correction:**  Shift to higher-level JavaScript programming errors that are related to the concepts handled by the factory (e.g., immutability, object structure).

By following these steps, the detailed and informative response provided earlier can be constructed.
```cpp
!map->is_in_retained_map_list());
  map->clear_padding();
  map->set_elements_kind(elements_kind);
  if (V8_UNLIKELY(v8_flags.log_maps)) {
    LOG(isolate(), MapCreate(map));
  }
  return map;
}

Handle<Map> Factory::NewMap(Handle<HeapObject> meta_map_holder,
                            InstanceType type, int instance_size,
                            ElementsKind elements_kind, int inobject_properties,
                            AllocationType allocation_type) {
  auto meta_map_provider = [=] {
    // Tie new map to the same native context as given |meta_map_holder| object.
    Tagged<Map> meta_map = meta_map_holder->map();
    DCHECK(IsMapMap(meta_map));
    return meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewMapWithMetaMap(Handle<Map> meta_map, InstanceType type,
                                       int instance_size,
                                       ElementsKind elements_kind,
                                       int inobject_properties,
                                       AllocationType allocation_type) {
  DCHECK_EQ(*meta_map, meta_map->map());
  auto meta_map_provider = [=] {
    // Use given meta map.
    return *meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMap(
    Handle<JSReceiver> creation_context_holder, InstanceType type,
    int instance_size, ElementsKind elements_kind, int inobject_properties,
    AllocationType allocation_type) {
  auto meta_map_provider = [=] {
    // Tie new map to the creation context of given |creation_context_holder|
    // object.
    Tagged<Map> meta_map = creation_context_holder->map()->map();
    DCHECK(IsMapMap(meta_map));
    return meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMap(Handle<NativeContext> native_context,
                                      InstanceType type, int instance_size,
                                      ElementsKind elements_kind,
                                      int inobject_properties,
                                      AllocationType allocation_type) {
  DCHECK(InstanceTypeChecker::IsNativeContextSpecific(type) ||
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=] {
    // Tie new map to given native context.
    return native_context->meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMapForCurrentContext(
    InstanceType type, int instance_size, ElementsKind elements_kind,
    int inobject_properties, AllocationType allocation_type) {
  DCHECK(InstanceTypeChecker::IsNativeContextSpecific(type) ||
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=, this] {
    // Tie new map to current native context.
    return isolate()->raw_native_context()->meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextlessMap(InstanceType type, int instance_size,
                                       ElementsKind elements_kind,
                                       int inobject_properties,
                                       AllocationType allocation_type) {
  DCHECK(!InstanceTypeChecker::IsNativeContextSpecific(type) ||
         type == NATIVE_CONTEXT_TYPE ||   // just during NativeContext creation.
         type == JS_GLOBAL_PROXY_TYPE ||  // might be a placeholder object.
         type == JS_SPECIAL_API_OBJECT_TYPE ||  // might be a remote Api object.
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=, this] {
    // The new map is not tied to any context.
    return ReadOnlyRoots(isolate()).meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<JSObject> Factory::CopyJSObject(DirectHandle<JSObject> source) {
  return CopyJSObjectWithAllocationSite(source, Handle<AllocationSite>());
}

Handle<JSObject> Factory::CopyJSObjectWithAllocationSite(
    DirectHandle<JSObject> source, DirectHandle<AllocationSite> site) {
  DirectHandle<Map> map(source->map(), isolate());

  // We can only clone regexps, normal objects, api objects, errors or arrays.
  // Copying anything else will break invariants.
  InstanceType instance_type = map->instance_type();
  bool is_clonable_js_type =
      instance_type == JS_REG_EXP_TYPE || instance_type == JS_OBJECT_TYPE ||
      instance_type == JS_ERROR_TYPE || instance_type == JS_ARRAY_TYPE ||
      instance_type == JS_SPECIAL_API_OBJECT_TYPE ||
      InstanceTypeChecker::IsJSApiObject(instance_type);
  bool is_clonable_wasm_type = false;
#if V8_ENABLE_WEBASSEMBLY
  is_clonable_wasm_type = instance_type == WASM_GLOBAL_OBJECT_TYPE ||
                          instance_type == WASM_INSTANCE_OBJECT_TYPE ||
                          instance_type == WASM_MEMORY_OBJECT_TYPE ||
                          instance_type == WASM_MODULE_OBJECT_TYPE ||
                          instance_type == WASM_TABLE_OBJECT_TYPE;
#endif  // V8_ENABLE_WEBASSEMBLY
  CHECK(is_clonable_js_type || is_clonable_wasm_type);

  DCHECK(site.is_null() || AllocationSite::CanTrack(instance_type));

  int object_size = map->instance_size();
  int aligned_object_size = ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);
  int adjusted_object_size = aligned_object_size;
  if (!site.is_null()) {
    DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
    adjusted_object_size +=
        ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize);
  }
  Tagged<HeapObject> raw_clone =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
          adjusted_object_size, AllocationType::kYoung);

  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), raw_clone);

  Heap::CopyBlock(raw_clone.address(), source->address(), object_size);
  Handle<JSObject> clone(Cast<JSObject>(raw_clone), isolate());

  if (v8_flags.enable_unconditional_write_barriers) {
    // By default, we shouldn't need to update the write barrier here, as the
    // clone will be allocated in new space.
    const ObjectSlot start(raw_clone.address());
    const ObjectSlot end(raw_clone.address() + object_size);
    WriteBarrier::ForRange(isolate()->heap(), raw_clone, start, end);
  }
  if (!site.is_null()) {
    Tagged<AllocationMemento> alloc_memento = UncheckedCast<AllocationMemento>(
        Tagged<Object>(raw_clone.ptr() + aligned_object_size));
    InitializeAllocationMemento(alloc_memento, *site);
  }

  SLOW_DCHECK(clone->GetElementsKind() == source->GetElementsKind());
  Tagged<FixedArrayBase> elements = source->elements();
  // Update elements if necessary.
  if (elements->length() > 0) {
    Tagged<FixedArrayBase> elem;
    if (elements->map() == *fixed_cow_array_map()) {
      elem = elements;
    } else if (source->HasDoubleElements()) {
      elem = *CopyFixedDoubleArray(
          handle(Cast<FixedDoubleArray>(elements), isolate()));
    } else {
      elem = *CopyFixedArray(handle(Cast<FixedArray>(elements), isolate()));
    }
    clone->set_elements(elem);
  }

  // Update properties if necessary.
  if (source->HasFastProperties()) {
    Tagged<PropertyArray> properties = source->property_array();
    if (properties->length() > 0) {
      // TODO(gsathya): Do not copy hash code.
      DirectHandle<PropertyArray> prop =
          CopyArrayWithMap(direct_handle(properties, isolate()),
                           direct_handle(properties->map(), isolate()));
      clone->set_raw_properties_or_hash(*prop, kRelaxedStore);
    }
  } else {
    DirectHandle<Object> copied_properties;
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      copied_properties = SwissNameDictionary::ShallowCopy(
          isolate(), handle(source->property_dictionary_swiss(), isolate()));
    } else {
      copied_properties =
          CopyFixedArray(handle(source->property_dictionary(), isolate()));
    }
    clone->set_raw_properties_or_hash(*copied_properties, kRelaxedStore);
  }
  return clone;
}

namespace {
template <typename T>
void initialize_length(Tagged<T> array, int length) {
  array->set_length(length);
}

template <>
void initialize_length<PropertyArray>(Tagged<PropertyArray> array, int length) {
  array->initialize_length(length);
}

inline void InitEmbedderFields(Tagged<JSObject> obj,
                               Tagged<Object> initial_value) {
  for (int i = 0; i < obj->GetEmbedderFieldCount(); i++) {
    EmbedderDataSlot(obj, i).Initialize(initial_value);
  }
}

}  // namespace

template <typename T>
Handle<T> Factory::CopyArrayWithMap(DirectHandle<T> src, DirectHandle<Map> map,
                                    AllocationType allocation) {
  int len = src->length();
  Tagged<HeapObject> new_object = AllocateRawFixedArray(len, allocation);
  DisallowGarbageCollection no_gc;
  new_object->set_map_after_allocation(isolate(), *map, SKIP_WRITE_BARRIER);
  Tagged<T> result = Cast<T>(new_object);
  initialize_length(result, len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  T::CopyElements(isolate(), result, 0, *src, 0, len, mode);
  return handle(result, isolate());
}

template <typename T>
Handle<T> Factory::CopyArrayAndGrow(DirectHandle<T> src, int grow_by,
                                    AllocationType allocation) {
  DCHECK_LT(0, grow_by);
  DCHECK_LE(grow_by, kMaxInt - src->length());
  int old_len = src->length();
  int new_len = old_len + grow_by;
  // TODO(jgruber,v8:14345): Use T::Allocate instead.
  Tagged<HeapObject> new_object = AllocateRawFixedArray(new_len, allocation);
  DisallowGarbageCollection no_gc;
  new_object->set_map_after_allocation(isolate(), src->map(),
                                       SKIP_WRITE_BARRIER);
  Tagged<T> result = Cast<T>(new_object);
  initialize_length(result, new_len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  T::CopyElements(isolate(), result, 0, *src, 0, old_len, mode);
  // TODO(jgruber,v8:14345): Enable the static assert once all T's support it:
  // static_assert(T::kElementSize == kTaggedSize);
  MemsetTagged(ObjectSlot(result->RawFieldOfElementAt(old_len)),
               read_only_roots().undefined_value(), grow_by);
  return handle(result, isolate());
}

Handle<FixedArray> Factory::CopyFixedArrayWithMap(
    DirectHandle<FixedArray> array, DirectHandle<Map> map,
    AllocationType allocation) {
  return CopyArrayWithMap(array, map, allocation);
}

Handle<WeakArrayList> Factory::NewUninitializedWeakArrayList(
    int capacity, AllocationType allocation) {
  DCHECK_LE(0, capacity);
  if (capacity == 0) return empty_weak_array_list();

  Tagged<HeapObject> heap_object =
      AllocateRawWeakArrayList(capacity, allocation);
  DisallowGarbageCollection no_gc;
  heap_object->set_map_after_allocation(isolate(), *weak_array_list_map(),
                                        SKIP_WRITE_BARRIER);
  Tagged<WeakArrayList> result = Cast<WeakArrayList>(heap_object);
  result->set_length(0);
  result->set_capacity(capacity);
  return handle(result, isolate());
}

Handle<WeakArrayList> Factory::NewWeakArrayList(int capacity,
                                                AllocationType allocation) {
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(capacity, allocation);
  MemsetTagged(ObjectSlot(result->data_start()),
               read_only_roots().undefined_value(), capacity);
  return result;
}

Handle<FixedArray> Factory::CopyFixedArrayAndGrow(
    DirectHandle<FixedArray> array, int grow_by, AllocationType allocation) {
  return CopyArrayAndGrow(array, grow_by, allocation);
}

Handle<WeakFixedArray> Factory::CopyWeakFixedArray(
    DirectHandle<WeakFixedArray> src) {
  DCHECK(!IsTransitionArray(*src));  // Compacted by GC, this code doesn't work
  return CopyArrayWithMap(src, weak_fixed_array_map(), AllocationType::kOld);
}

Handle<WeakFixedArray> Factory::CopyWeakFixedArrayAndGrow(
    DirectHandle<WeakFixedArray> src, int grow_by) {
  DCHECK(!IsTransitionArray(*src));  // Compacted by GC, this code doesn't work
  return CopyArrayAndGrow(src, grow_by, AllocationType::kOld);
}

Handle<WeakArrayList> Factory::CopyWeakArrayListAndGrow(
    DirectHandle<WeakArrayList> src, int grow_by, AllocationType allocation) {
  int old_capacity = src->capacity();
  int new_capacity = old_capacity + grow_by;
  DCHECK_GE(new_capacity, old_capacity);
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(new_capacity, allocation);
  DisallowGarbageCollection no_gc;
  Tagged<WeakArrayList> raw = *result;
  int old_len = src->length();
  raw->set_length(old_len);
  // Copy the content.
  WriteBarrierMode mode = raw->GetWriteBarrierMode(no_gc);
  raw->CopyElements(isolate(), 0, *src, 0, old_len, mode);
  MemsetTagged(ObjectSlot(raw->data_start() + old_len),
               read_only_roots().undefined_value(), new_capacity - old_len);
  return result;
}

Handle<WeakArrayList> Factory::CompactWeakArrayList(
    DirectHandle<WeakArrayList> src, int new_capacity,
    AllocationType allocation) {
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(new_capacity, allocation);

  // Copy the content.
  DisallowGarbageCollection no_gc;
  Tagged<WeakArrayList> raw_src = *src;
  Tagged<WeakArrayList> raw_result = *result;
  WriteBarrierMode mode = raw_result->GetWriteBarrierMode(no_gc);
  int copy_to = 0, length = raw_src->length();
  for (int i = 0; i < length; i++) {
    Tagged<MaybeObject> element = raw_src->Get(i);
    if (element.IsCleared()) continue;
    raw_result->Set(copy_to++, element, mode);
  }
  raw_result->set_length(copy_to);

  MemsetTagged(ObjectSlot(raw_result->data_start() + copy_to),
               read_only_roots().undefined_value(), new_capacity - copy_to);
  return result;
}

Handle<PropertyArray> Factory::CopyPropertyArrayAndGrow(
    DirectHandle<PropertyArray> array, int grow_by) {
  return CopyArrayAndGrow(array, grow_by, AllocationType::kYoung);
}

Handle<FixedArray> Factory::CopyFixedArrayUpTo(DirectHandle<FixedArray> array,
                                               int new_len,
                                               AllocationType allocation) {
  DCHECK_LE(0, new_len);
  DCHECK_LE(new_len, array->length());
  if (new_len == 0) return empty_fixed_array();
  Tagged<HeapObject> heap_object = AllocateRawFixedArray(new_len, allocation);
  DisallowGarbageCollection no_gc;
  heap_object->set_map_after_allocation(isolate(), *fixed_array_map(),
                                        SKIP_WRITE_BARRIER);
  Tagged<FixedArray> result = Cast<FixedArray>(heap_object);
  result->set_length(new_len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  result->CopyElements(isolate(), 0, *array, 0, new_len, mode);
  return handle(result, isolate());
}

Handle<FixedArray> Factory::CopyFixedArray(Handle<FixedArray> array) {
  if (array->length() == 0) return array;
  return CopyArrayWithMap(DirectHandle<FixedArray>(array),
                          direct_handle(array->map(), isolate()));
}

Handle<FixedDoubleArray> Factory::CopyFixedDoubleArray(
    Handle<FixedDoubleArray> array) {
  int len = array->length();
  if (len == 0) return array;
  Handle<FixedDoubleArray> result =
      Cast<FixedDoubleArray>(NewFixedDoubleArray(len));
  Heap::CopyBlock(
      result->address() + offsetof(FixedDoubleArray, length_),
      array->address() + offsetof(FixedDoubleArray, length_),
      FixedDoubleArray::SizeFor(len) - offsetof(FixedDoubleArray, length_));
  return result;
}

Handle<HeapNumber> Factory::NewHeapNumberForCodeAssembler(double value) {
  ReadOnlyRoots roots(isolate());
  auto num = roots.FindHeapNumber(value);
  if (!num.is_null()) return num;
  // Add known HeapNumber constants to the read only roots. This ensures
  // r/o snapshots to be deterministic.
  DCHECK(!CanAllocateInReadOnlySpace());
  return NewHeapNumber<AllocationType::kOld>(value);
}

Handle<JSObject> Factory::NewError(
    Handle<JSFunction> constructor, MessageTemplate template_index,
    base::Vector<const DirectHandle<Object>> args) {
  HandleScope scope(isolate());

  return scope.CloseAndEscape(ErrorUtils::MakeGenericError(
      isolate(), constructor, template_index, args, SKIP_NONE));
}

Handle<JSObject> Factory::NewError(Handle<JSFunction> constructor,
                                   DirectHandle<String> message,
                                   Handle<Object> options) {
  // Construct a new error object. If an exception is thrown, use the exception
  // as the result.

  Handle<Object> no_caller;
  if (options.is_null()) options = undefined_value();
  return ErrorUtils::Construct(isolate(), constructor, constructor, message,
                               options, SKIP_NONE, no_caller,
                               ErrorUtils::StackTraceCollection::kEnabled)
      .ToHandleChecked();
}

Handle<JSObject> Factory::ShadowRealmNewTypeErrorCopy(
    Handle<Object> original, MessageTemplate template_index,
    base::Vector<const DirectHandle<Object>> args) {
  return ErrorUtils::ShadowRealmConstructTypeErrorCopy(isolate(), original,
                                                       template_index, args);
}

Handle<Object> Factory::NewInvalidStringLengthError() {
  if (v8_flags.correctness_fuzzer_suppressions) {
    FATAL("Aborting on invalid string length");
  }
  // Invalidate the "string length" protector.
  if (Protectors::IsStringLengthOverflowLookupChainIntact(isolate())) {
    Protectors::InvalidateStringLengthOverflowLookupChain(isolate());
  }
  return NewRangeError(MessageTemplate::kInvalidStringLength);
}

Handle<JSObject> Factory::NewSuppressedErrorAtDisposal(
    Isolate* isolate, Handle<Object> error, Handle<Object> suppressed_error) {
  Handle<JSObject> err =
      NewSuppressedError(MessageTemplate::kSuppressedErrorDuringDisposal);

  JSObject::SetOwnPropertyIgnoreAttributes(
      err, isolate->factory()->error_string(), error, DONT_ENUM)
      .Assert();

  JSObject::SetOwnPropertyIgnoreAttributes(
      err, isolate->factory()->suppressed_string(), suppressed_error, DONT_ENUM)
      .Assert();

  return err;
}

#define DEFINE_ERROR(NAME, name)                                         \
  Handle<JSObject> Factory::New##NAME(                                   \
      MessageTemplate template_index,                                    \
      base::Vector<const DirectHandle<Object>> args) {                   \
    return NewError(isolate()->name##_function(), template_index, args); \
  }
DEFINE_ERROR(Error, error)
DEFINE_ERROR(EvalError, eval_error)
DEFINE_ERROR(RangeError, range_error)
DEFINE_ERROR(ReferenceError, reference_error)
DEFINE_ERROR(SyntaxError, syntax_error)
DEFINE_ERROR(SuppressedError, suppressed_error)
DEFINE_ERROR(TypeError, type_error)
DEFINE_ERROR(WasmCompileError, wasm_compile_error)
DEFINE_ERROR(WasmLinkError, wasm_link_error)
DEFINE_ERROR(WasmRuntimeError, wasm_runtime_error)
#undef DEFINE_ERROR

Handle<JSObject> Factory::NewFunctionPrototype(
    DirectHandle<JSFunction> function) {
  // Make sure to use globals from the function's context, since the function
  // can be from a different context.
  DirectHandle<NativeContext> native_context(function->native_context(),
                                             isolate());
  DirectHandle<Map> new_map;
  if (V8_UNLIKELY(IsAsyncGeneratorFunction(function->shared()->kind()))) {
    new_map = direct_handle(
        native_context->async_generator_object_prototype_map(), isolate());
  } else if (IsResumableFunction(function->shared()->kind())) {
    // Generator and async function prototypes can share maps since they
    // don't have "constructor" properties.
    new_map = direct_handle(native_context->generator_object_prototype_map(),
                            isolate());
  } else {
    // Each function prototype gets a fresh map to avoid unwanted sharing of
    // maps between prototypes of different constructors.
    DirectHandle<JSFunction> object_function(native_context->object_function(),
                                             isolate());
    DCHECK(object_function->has_initial_map());
    new_map = direct_handle(object_function->initial_map(), isolate());
  }

  DCHECK(!new_map->is_prototype_map());
  Handle<JSObject> prototype = NewJSObjectFromMap(new_map);

  if (!IsResumableFunction(function->shared()->kind())) {
    JSObject::AddProperty(isolate(), prototype, constructor_string(), function,
                          DONT_ENUM);
  }

  return prototype;
}

Handle<JSObject> Factory::NewExternal(void* value,
                                      AllocationType allocation_type) {
  auto external = Cast<JSExternalObject>(
      NewJSObjectFromMap(external_map(), allocation_type));
  external->init_value(isolate(), value);
  return external;
}

Handle<Code> Factory::NewCodeObjectForEmbeddedBuiltin(DirectHandle<Code> code,
                                                      Address off_heap_entry) {
  CHECK_NOT_NULL(isolate()->embedded_blob_code());
  CHECK_NE(0, isolate()->embedded_blob_code_size());
  CHECK(Builtins::IsIsolateIndependentBuiltin(*code));

  DCHECK(code->has_instruction_stream());  // Just generated as on-heap code.
  DCHECK(Builtins::IsBuiltinId(code->builtin_id()));
  DCHECK_EQ(code->inlined_bytecode_size(), 0);
  DCHECK_EQ(code->osr_offset(), BytecodeOffset::None());
  DCHECK_EQ(code->raw_deoptimization_data_or_interpreter_data(), Smi::zero());
  // .. because we don't explicitly initialize these flags:
  DCHECK(!code->marked_for_deoptimization());
  DCHECK(!code->can_have_weak_objects());
  DCHECK(!code->embedded_objects_cleared());
  // This check would fail. We explicitly clear any existing position tables
  // below. Note this isn't strictly necessary - we could keep the position
  // tables if we'd properly allocate them into RO space when needed.
  // DCHECK_EQ(code->raw_position_table(), *empty_byte_array());

  NewCodeOptions new_code_options = {
      code->kind(),
      code->builtin_id(),
      code->is_context_specialized(),
      code->is_turbofanned(),
      code->parameter_count(),
      code->instruction_size(),
      code->metadata_size(),
      code->inlined_bytecode_size(),
      code->osr_offset(),
      code->handler_table_offset(),
      code->constant_pool_offset(),
      code->code_comments_offset(),
      code->builtin_jump_table_info_offset(),
      code->unwinding_info_offset(),
      MaybeHandle<TrustedObject>{},
      MaybeHandle<DeoptimizationData>{},
      /*bytecode_offset_table=*/MaybeHandle<TrustedByteArray>{},
      /*source_position_table=*/MaybeHandle<TrustedByteArray>{},
      MaybeHandle<InstructionStream>{},
      off_heap_entry,
  };

  return NewCode(new_code_options);
}

Handle<BytecodeArray> Factory::CopyBytecodeArray(
    DirectHandle<BytecodeArray> source) {
  DirectHandle<BytecodeWrapper> wrapper = NewBytecodeWrapper();
  int size = BytecodeArray::SizeFor(source->length());
  Tagged<BytecodeArray> copy = Cast<BytecodeArray>(AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, *bytecode_array_map()));
  DisallowGarbageCollection no_gc;
  Tagged<BytecodeArray> raw_source = *source;
  copy->init_self_indirect_pointer(isolate());
  copy->set_length(raw_source->length());
  copy->set_frame_size(raw_source->frame_size());
  copy->set_parameter_count(raw_source->parameter_count());
  copy->set_max_arguments(raw_source->max_arguments());
  copy->set_incoming_new_target_or_generator_register(
      raw_source->incoming_new_target_or_generator_register());
  copy->set_constant_pool(raw_source->constant_pool());
  copy->set_handler_table(raw_source->handler_table());
  copy->set_wrapper(*wrapper);
  if (raw_source->has_source_position_table(kAcquireLoad)) {
    copy->set_source_position_table(
        raw_source->source_position_table(kAcquireLoad), kReleaseStore);
  } else {
    copy->clear_source_position_table(kReleaseStore);
  }
  raw_source->CopyBytecodesTo(copy);
  wrapper->set_bytecode(copy);
  return handle(copy, isolate());
}

Handle<JSObject> Factory::NewJSObject(Handle<JSFunction> constructor,
                                      AllocationType allocation,
                                      NewJSObjectType new_js_object_type) {
  JSFunction::EnsureHasInitialMap(constructor);
  DirectHandle<Map> map(constructor->initial_map(), isolate());
  // NewJSObjectFromMap does not support creating dictionary mode objects. Need
  // to use NewSlowJSObjectFromMap instead.
  DCHECK(!map->is_dictionary_map());
  return NewJSObjectFromMap(map, allocation,
                            DirectHandle<AllocationSite>::null(),
                            new_js_object_type);
}

Handle<JSObject> Factory::NewSlowJSObjectWithNullProto() {
  Handle<JSObject> result =
      NewSlowJSObjectFromMap(isolate()->slow_object_with_null_prototype_map());
  return result;
}

Handle<JSObject> Factory::NewJSObjectWithNullProto() {
  Handle<Map> map(isolate()->object_function()->initial_map(), isolate());
  DirectHandle<Map> map_with_null_proto =
      Map::TransitionRootMapToPrototypeForNewObject(isolate(), map,
                                                    null_value());
  return NewJSObjectFromMap(map_with_null_proto);
}

Handle<JSGlobalObject> Factory::NewJSGlobalObject(
    DirectHandle<JSFunction> constructor) {
  DCHECK(constructor->has_initial_map());
  Handle<Map> map(constructor->initial_map(), isolate());
  DCHECK(map->is_dictionary_map());

  // Make sure no field properties are described in the initial map.
### 提示词
```
这是目录为v8/src/heap/factory.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
!map->is_in_retained_map_list());
  map->clear_padding();
  map->set_elements_kind(elements_kind);
  if (V8_UNLIKELY(v8_flags.log_maps)) {
    LOG(isolate(), MapCreate(map));
  }
  return map;
}

Handle<Map> Factory::NewMap(Handle<HeapObject> meta_map_holder,
                            InstanceType type, int instance_size,
                            ElementsKind elements_kind, int inobject_properties,
                            AllocationType allocation_type) {
  auto meta_map_provider = [=] {
    // Tie new map to the same native context as given |meta_map_holder| object.
    Tagged<Map> meta_map = meta_map_holder->map();
    DCHECK(IsMapMap(meta_map));
    return meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewMapWithMetaMap(Handle<Map> meta_map, InstanceType type,
                                       int instance_size,
                                       ElementsKind elements_kind,
                                       int inobject_properties,
                                       AllocationType allocation_type) {
  DCHECK_EQ(*meta_map, meta_map->map());
  auto meta_map_provider = [=] {
    // Use given meta map.
    return *meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMap(
    Handle<JSReceiver> creation_context_holder, InstanceType type,
    int instance_size, ElementsKind elements_kind, int inobject_properties,
    AllocationType allocation_type) {
  auto meta_map_provider = [=] {
    // Tie new map to the creation context of given |creation_context_holder|
    // object.
    Tagged<Map> meta_map = creation_context_holder->map()->map();
    DCHECK(IsMapMap(meta_map));
    return meta_map;
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMap(Handle<NativeContext> native_context,
                                      InstanceType type, int instance_size,
                                      ElementsKind elements_kind,
                                      int inobject_properties,
                                      AllocationType allocation_type) {
  DCHECK(InstanceTypeChecker::IsNativeContextSpecific(type) ||
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=] {
    // Tie new map to given native context.
    return native_context->meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextfulMapForCurrentContext(
    InstanceType type, int instance_size, ElementsKind elements_kind,
    int inobject_properties, AllocationType allocation_type) {
  DCHECK(InstanceTypeChecker::IsNativeContextSpecific(type) ||
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=, this] {
    // Tie new map to current native context.
    return isolate()->raw_native_context()->meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<Map> Factory::NewContextlessMap(InstanceType type, int instance_size,
                                       ElementsKind elements_kind,
                                       int inobject_properties,
                                       AllocationType allocation_type) {
  DCHECK(!InstanceTypeChecker::IsNativeContextSpecific(type) ||
         type == NATIVE_CONTEXT_TYPE ||   // just during NativeContext creation.
         type == JS_GLOBAL_PROXY_TYPE ||  // might be a placeholder object.
         type == JS_SPECIAL_API_OBJECT_TYPE ||  // might be a remote Api object.
         InstanceTypeChecker::IsMap(type));
  auto meta_map_provider = [=, this] {
    // The new map is not tied to any context.
    return ReadOnlyRoots(isolate()).meta_map();
  };
  Handle<Map> map =
      NewMapImpl(meta_map_provider, type, instance_size, elements_kind,
                 inobject_properties, allocation_type);
  return map;
}

Handle<JSObject> Factory::CopyJSObject(DirectHandle<JSObject> source) {
  return CopyJSObjectWithAllocationSite(source, Handle<AllocationSite>());
}

Handle<JSObject> Factory::CopyJSObjectWithAllocationSite(
    DirectHandle<JSObject> source, DirectHandle<AllocationSite> site) {
  DirectHandle<Map> map(source->map(), isolate());

  // We can only clone regexps, normal objects, api objects, errors or arrays.
  // Copying anything else will break invariants.
  InstanceType instance_type = map->instance_type();
  bool is_clonable_js_type =
      instance_type == JS_REG_EXP_TYPE || instance_type == JS_OBJECT_TYPE ||
      instance_type == JS_ERROR_TYPE || instance_type == JS_ARRAY_TYPE ||
      instance_type == JS_SPECIAL_API_OBJECT_TYPE ||
      InstanceTypeChecker::IsJSApiObject(instance_type);
  bool is_clonable_wasm_type = false;
#if V8_ENABLE_WEBASSEMBLY
  is_clonable_wasm_type = instance_type == WASM_GLOBAL_OBJECT_TYPE ||
                          instance_type == WASM_INSTANCE_OBJECT_TYPE ||
                          instance_type == WASM_MEMORY_OBJECT_TYPE ||
                          instance_type == WASM_MODULE_OBJECT_TYPE ||
                          instance_type == WASM_TABLE_OBJECT_TYPE;
#endif  // V8_ENABLE_WEBASSEMBLY
  CHECK(is_clonable_js_type || is_clonable_wasm_type);

  DCHECK(site.is_null() || AllocationSite::CanTrack(instance_type));

  int object_size = map->instance_size();
  int aligned_object_size = ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);
  int adjusted_object_size = aligned_object_size;
  if (!site.is_null()) {
    DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
    adjusted_object_size +=
        ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize);
  }
  Tagged<HeapObject> raw_clone =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(
          adjusted_object_size, AllocationType::kYoung);

  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), raw_clone);

  Heap::CopyBlock(raw_clone.address(), source->address(), object_size);
  Handle<JSObject> clone(Cast<JSObject>(raw_clone), isolate());

  if (v8_flags.enable_unconditional_write_barriers) {
    // By default, we shouldn't need to update the write barrier here, as the
    // clone will be allocated in new space.
    const ObjectSlot start(raw_clone.address());
    const ObjectSlot end(raw_clone.address() + object_size);
    WriteBarrier::ForRange(isolate()->heap(), raw_clone, start, end);
  }
  if (!site.is_null()) {
    Tagged<AllocationMemento> alloc_memento = UncheckedCast<AllocationMemento>(
        Tagged<Object>(raw_clone.ptr() + aligned_object_size));
    InitializeAllocationMemento(alloc_memento, *site);
  }

  SLOW_DCHECK(clone->GetElementsKind() == source->GetElementsKind());
  Tagged<FixedArrayBase> elements = source->elements();
  // Update elements if necessary.
  if (elements->length() > 0) {
    Tagged<FixedArrayBase> elem;
    if (elements->map() == *fixed_cow_array_map()) {
      elem = elements;
    } else if (source->HasDoubleElements()) {
      elem = *CopyFixedDoubleArray(
          handle(Cast<FixedDoubleArray>(elements), isolate()));
    } else {
      elem = *CopyFixedArray(handle(Cast<FixedArray>(elements), isolate()));
    }
    clone->set_elements(elem);
  }

  // Update properties if necessary.
  if (source->HasFastProperties()) {
    Tagged<PropertyArray> properties = source->property_array();
    if (properties->length() > 0) {
      // TODO(gsathya): Do not copy hash code.
      DirectHandle<PropertyArray> prop =
          CopyArrayWithMap(direct_handle(properties, isolate()),
                           direct_handle(properties->map(), isolate()));
      clone->set_raw_properties_or_hash(*prop, kRelaxedStore);
    }
  } else {
    DirectHandle<Object> copied_properties;
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      copied_properties = SwissNameDictionary::ShallowCopy(
          isolate(), handle(source->property_dictionary_swiss(), isolate()));
    } else {
      copied_properties =
          CopyFixedArray(handle(source->property_dictionary(), isolate()));
    }
    clone->set_raw_properties_or_hash(*copied_properties, kRelaxedStore);
  }
  return clone;
}

namespace {
template <typename T>
void initialize_length(Tagged<T> array, int length) {
  array->set_length(length);
}

template <>
void initialize_length<PropertyArray>(Tagged<PropertyArray> array, int length) {
  array->initialize_length(length);
}

inline void InitEmbedderFields(Tagged<JSObject> obj,
                               Tagged<Object> initial_value) {
  for (int i = 0; i < obj->GetEmbedderFieldCount(); i++) {
    EmbedderDataSlot(obj, i).Initialize(initial_value);
  }
}

}  // namespace

template <typename T>
Handle<T> Factory::CopyArrayWithMap(DirectHandle<T> src, DirectHandle<Map> map,
                                    AllocationType allocation) {
  int len = src->length();
  Tagged<HeapObject> new_object = AllocateRawFixedArray(len, allocation);
  DisallowGarbageCollection no_gc;
  new_object->set_map_after_allocation(isolate(), *map, SKIP_WRITE_BARRIER);
  Tagged<T> result = Cast<T>(new_object);
  initialize_length(result, len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  T::CopyElements(isolate(), result, 0, *src, 0, len, mode);
  return handle(result, isolate());
}

template <typename T>
Handle<T> Factory::CopyArrayAndGrow(DirectHandle<T> src, int grow_by,
                                    AllocationType allocation) {
  DCHECK_LT(0, grow_by);
  DCHECK_LE(grow_by, kMaxInt - src->length());
  int old_len = src->length();
  int new_len = old_len + grow_by;
  // TODO(jgruber,v8:14345): Use T::Allocate instead.
  Tagged<HeapObject> new_object = AllocateRawFixedArray(new_len, allocation);
  DisallowGarbageCollection no_gc;
  new_object->set_map_after_allocation(isolate(), src->map(),
                                       SKIP_WRITE_BARRIER);
  Tagged<T> result = Cast<T>(new_object);
  initialize_length(result, new_len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  T::CopyElements(isolate(), result, 0, *src, 0, old_len, mode);
  // TODO(jgruber,v8:14345): Enable the static assert once all T's support it:
  // static_assert(T::kElementSize == kTaggedSize);
  MemsetTagged(ObjectSlot(result->RawFieldOfElementAt(old_len)),
               read_only_roots().undefined_value(), grow_by);
  return handle(result, isolate());
}

Handle<FixedArray> Factory::CopyFixedArrayWithMap(
    DirectHandle<FixedArray> array, DirectHandle<Map> map,
    AllocationType allocation) {
  return CopyArrayWithMap(array, map, allocation);
}

Handle<WeakArrayList> Factory::NewUninitializedWeakArrayList(
    int capacity, AllocationType allocation) {
  DCHECK_LE(0, capacity);
  if (capacity == 0) return empty_weak_array_list();

  Tagged<HeapObject> heap_object =
      AllocateRawWeakArrayList(capacity, allocation);
  DisallowGarbageCollection no_gc;
  heap_object->set_map_after_allocation(isolate(), *weak_array_list_map(),
                                        SKIP_WRITE_BARRIER);
  Tagged<WeakArrayList> result = Cast<WeakArrayList>(heap_object);
  result->set_length(0);
  result->set_capacity(capacity);
  return handle(result, isolate());
}

Handle<WeakArrayList> Factory::NewWeakArrayList(int capacity,
                                                AllocationType allocation) {
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(capacity, allocation);
  MemsetTagged(ObjectSlot(result->data_start()),
               read_only_roots().undefined_value(), capacity);
  return result;
}

Handle<FixedArray> Factory::CopyFixedArrayAndGrow(
    DirectHandle<FixedArray> array, int grow_by, AllocationType allocation) {
  return CopyArrayAndGrow(array, grow_by, allocation);
}

Handle<WeakFixedArray> Factory::CopyWeakFixedArray(
    DirectHandle<WeakFixedArray> src) {
  DCHECK(!IsTransitionArray(*src));  // Compacted by GC, this code doesn't work
  return CopyArrayWithMap(src, weak_fixed_array_map(), AllocationType::kOld);
}

Handle<WeakFixedArray> Factory::CopyWeakFixedArrayAndGrow(
    DirectHandle<WeakFixedArray> src, int grow_by) {
  DCHECK(!IsTransitionArray(*src));  // Compacted by GC, this code doesn't work
  return CopyArrayAndGrow(src, grow_by, AllocationType::kOld);
}

Handle<WeakArrayList> Factory::CopyWeakArrayListAndGrow(
    DirectHandle<WeakArrayList> src, int grow_by, AllocationType allocation) {
  int old_capacity = src->capacity();
  int new_capacity = old_capacity + grow_by;
  DCHECK_GE(new_capacity, old_capacity);
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(new_capacity, allocation);
  DisallowGarbageCollection no_gc;
  Tagged<WeakArrayList> raw = *result;
  int old_len = src->length();
  raw->set_length(old_len);
  // Copy the content.
  WriteBarrierMode mode = raw->GetWriteBarrierMode(no_gc);
  raw->CopyElements(isolate(), 0, *src, 0, old_len, mode);
  MemsetTagged(ObjectSlot(raw->data_start() + old_len),
               read_only_roots().undefined_value(), new_capacity - old_len);
  return result;
}

Handle<WeakArrayList> Factory::CompactWeakArrayList(
    DirectHandle<WeakArrayList> src, int new_capacity,
    AllocationType allocation) {
  Handle<WeakArrayList> result =
      NewUninitializedWeakArrayList(new_capacity, allocation);

  // Copy the content.
  DisallowGarbageCollection no_gc;
  Tagged<WeakArrayList> raw_src = *src;
  Tagged<WeakArrayList> raw_result = *result;
  WriteBarrierMode mode = raw_result->GetWriteBarrierMode(no_gc);
  int copy_to = 0, length = raw_src->length();
  for (int i = 0; i < length; i++) {
    Tagged<MaybeObject> element = raw_src->Get(i);
    if (element.IsCleared()) continue;
    raw_result->Set(copy_to++, element, mode);
  }
  raw_result->set_length(copy_to);

  MemsetTagged(ObjectSlot(raw_result->data_start() + copy_to),
               read_only_roots().undefined_value(), new_capacity - copy_to);
  return result;
}

Handle<PropertyArray> Factory::CopyPropertyArrayAndGrow(
    DirectHandle<PropertyArray> array, int grow_by) {
  return CopyArrayAndGrow(array, grow_by, AllocationType::kYoung);
}

Handle<FixedArray> Factory::CopyFixedArrayUpTo(DirectHandle<FixedArray> array,
                                               int new_len,
                                               AllocationType allocation) {
  DCHECK_LE(0, new_len);
  DCHECK_LE(new_len, array->length());
  if (new_len == 0) return empty_fixed_array();
  Tagged<HeapObject> heap_object = AllocateRawFixedArray(new_len, allocation);
  DisallowGarbageCollection no_gc;
  heap_object->set_map_after_allocation(isolate(), *fixed_array_map(),
                                        SKIP_WRITE_BARRIER);
  Tagged<FixedArray> result = Cast<FixedArray>(heap_object);
  result->set_length(new_len);
  // Copy the content.
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  result->CopyElements(isolate(), 0, *array, 0, new_len, mode);
  return handle(result, isolate());
}

Handle<FixedArray> Factory::CopyFixedArray(Handle<FixedArray> array) {
  if (array->length() == 0) return array;
  return CopyArrayWithMap(DirectHandle<FixedArray>(array),
                          direct_handle(array->map(), isolate()));
}

Handle<FixedDoubleArray> Factory::CopyFixedDoubleArray(
    Handle<FixedDoubleArray> array) {
  int len = array->length();
  if (len == 0) return array;
  Handle<FixedDoubleArray> result =
      Cast<FixedDoubleArray>(NewFixedDoubleArray(len));
  Heap::CopyBlock(
      result->address() + offsetof(FixedDoubleArray, length_),
      array->address() + offsetof(FixedDoubleArray, length_),
      FixedDoubleArray::SizeFor(len) - offsetof(FixedDoubleArray, length_));
  return result;
}

Handle<HeapNumber> Factory::NewHeapNumberForCodeAssembler(double value) {
  ReadOnlyRoots roots(isolate());
  auto num = roots.FindHeapNumber(value);
  if (!num.is_null()) return num;
  // Add known HeapNumber constants to the read only roots. This ensures
  // r/o snapshots to be deterministic.
  DCHECK(!CanAllocateInReadOnlySpace());
  return NewHeapNumber<AllocationType::kOld>(value);
}

Handle<JSObject> Factory::NewError(
    Handle<JSFunction> constructor, MessageTemplate template_index,
    base::Vector<const DirectHandle<Object>> args) {
  HandleScope scope(isolate());

  return scope.CloseAndEscape(ErrorUtils::MakeGenericError(
      isolate(), constructor, template_index, args, SKIP_NONE));
}

Handle<JSObject> Factory::NewError(Handle<JSFunction> constructor,
                                   DirectHandle<String> message,
                                   Handle<Object> options) {
  // Construct a new error object. If an exception is thrown, use the exception
  // as the result.

  Handle<Object> no_caller;
  if (options.is_null()) options = undefined_value();
  return ErrorUtils::Construct(isolate(), constructor, constructor, message,
                               options, SKIP_NONE, no_caller,
                               ErrorUtils::StackTraceCollection::kEnabled)
      .ToHandleChecked();
}

Handle<JSObject> Factory::ShadowRealmNewTypeErrorCopy(
    Handle<Object> original, MessageTemplate template_index,
    base::Vector<const DirectHandle<Object>> args) {
  return ErrorUtils::ShadowRealmConstructTypeErrorCopy(isolate(), original,
                                                       template_index, args);
}

Handle<Object> Factory::NewInvalidStringLengthError() {
  if (v8_flags.correctness_fuzzer_suppressions) {
    FATAL("Aborting on invalid string length");
  }
  // Invalidate the "string length" protector.
  if (Protectors::IsStringLengthOverflowLookupChainIntact(isolate())) {
    Protectors::InvalidateStringLengthOverflowLookupChain(isolate());
  }
  return NewRangeError(MessageTemplate::kInvalidStringLength);
}

Handle<JSObject> Factory::NewSuppressedErrorAtDisposal(
    Isolate* isolate, Handle<Object> error, Handle<Object> suppressed_error) {
  Handle<JSObject> err =
      NewSuppressedError(MessageTemplate::kSuppressedErrorDuringDisposal);

  JSObject::SetOwnPropertyIgnoreAttributes(
      err, isolate->factory()->error_string(), error, DONT_ENUM)
      .Assert();

  JSObject::SetOwnPropertyIgnoreAttributes(
      err, isolate->factory()->suppressed_string(), suppressed_error, DONT_ENUM)
      .Assert();

  return err;
}

#define DEFINE_ERROR(NAME, name)                                         \
  Handle<JSObject> Factory::New##NAME(                                   \
      MessageTemplate template_index,                                    \
      base::Vector<const DirectHandle<Object>> args) {                   \
    return NewError(isolate()->name##_function(), template_index, args); \
  }
DEFINE_ERROR(Error, error)
DEFINE_ERROR(EvalError, eval_error)
DEFINE_ERROR(RangeError, range_error)
DEFINE_ERROR(ReferenceError, reference_error)
DEFINE_ERROR(SyntaxError, syntax_error)
DEFINE_ERROR(SuppressedError, suppressed_error)
DEFINE_ERROR(TypeError, type_error)
DEFINE_ERROR(WasmCompileError, wasm_compile_error)
DEFINE_ERROR(WasmLinkError, wasm_link_error)
DEFINE_ERROR(WasmRuntimeError, wasm_runtime_error)
#undef DEFINE_ERROR

Handle<JSObject> Factory::NewFunctionPrototype(
    DirectHandle<JSFunction> function) {
  // Make sure to use globals from the function's context, since the function
  // can be from a different context.
  DirectHandle<NativeContext> native_context(function->native_context(),
                                             isolate());
  DirectHandle<Map> new_map;
  if (V8_UNLIKELY(IsAsyncGeneratorFunction(function->shared()->kind()))) {
    new_map = direct_handle(
        native_context->async_generator_object_prototype_map(), isolate());
  } else if (IsResumableFunction(function->shared()->kind())) {
    // Generator and async function prototypes can share maps since they
    // don't have "constructor" properties.
    new_map = direct_handle(native_context->generator_object_prototype_map(),
                            isolate());
  } else {
    // Each function prototype gets a fresh map to avoid unwanted sharing of
    // maps between prototypes of different constructors.
    DirectHandle<JSFunction> object_function(native_context->object_function(),
                                             isolate());
    DCHECK(object_function->has_initial_map());
    new_map = direct_handle(object_function->initial_map(), isolate());
  }

  DCHECK(!new_map->is_prototype_map());
  Handle<JSObject> prototype = NewJSObjectFromMap(new_map);

  if (!IsResumableFunction(function->shared()->kind())) {
    JSObject::AddProperty(isolate(), prototype, constructor_string(), function,
                          DONT_ENUM);
  }

  return prototype;
}

Handle<JSObject> Factory::NewExternal(void* value,
                                      AllocationType allocation_type) {
  auto external = Cast<JSExternalObject>(
      NewJSObjectFromMap(external_map(), allocation_type));
  external->init_value(isolate(), value);
  return external;
}

Handle<Code> Factory::NewCodeObjectForEmbeddedBuiltin(DirectHandle<Code> code,
                                                      Address off_heap_entry) {
  CHECK_NOT_NULL(isolate()->embedded_blob_code());
  CHECK_NE(0, isolate()->embedded_blob_code_size());
  CHECK(Builtins::IsIsolateIndependentBuiltin(*code));

  DCHECK(code->has_instruction_stream());  // Just generated as on-heap code.
  DCHECK(Builtins::IsBuiltinId(code->builtin_id()));
  DCHECK_EQ(code->inlined_bytecode_size(), 0);
  DCHECK_EQ(code->osr_offset(), BytecodeOffset::None());
  DCHECK_EQ(code->raw_deoptimization_data_or_interpreter_data(), Smi::zero());
  // .. because we don't explicitly initialize these flags:
  DCHECK(!code->marked_for_deoptimization());
  DCHECK(!code->can_have_weak_objects());
  DCHECK(!code->embedded_objects_cleared());
  // This check would fail. We explicitly clear any existing position tables
  // below. Note this isn't strictly necessary - we could keep the position
  // tables if we'd properly allocate them into RO space when needed.
  // DCHECK_EQ(code->raw_position_table(), *empty_byte_array());

  NewCodeOptions new_code_options = {
      code->kind(),
      code->builtin_id(),
      code->is_context_specialized(),
      code->is_turbofanned(),
      code->parameter_count(),
      code->instruction_size(),
      code->metadata_size(),
      code->inlined_bytecode_size(),
      code->osr_offset(),
      code->handler_table_offset(),
      code->constant_pool_offset(),
      code->code_comments_offset(),
      code->builtin_jump_table_info_offset(),
      code->unwinding_info_offset(),
      MaybeHandle<TrustedObject>{},
      MaybeHandle<DeoptimizationData>{},
      /*bytecode_offset_table=*/MaybeHandle<TrustedByteArray>{},
      /*source_position_table=*/MaybeHandle<TrustedByteArray>{},
      MaybeHandle<InstructionStream>{},
      off_heap_entry,
  };

  return NewCode(new_code_options);
}

Handle<BytecodeArray> Factory::CopyBytecodeArray(
    DirectHandle<BytecodeArray> source) {
  DirectHandle<BytecodeWrapper> wrapper = NewBytecodeWrapper();
  int size = BytecodeArray::SizeFor(source->length());
  Tagged<BytecodeArray> copy = Cast<BytecodeArray>(AllocateRawWithImmortalMap(
      size, AllocationType::kTrusted, *bytecode_array_map()));
  DisallowGarbageCollection no_gc;
  Tagged<BytecodeArray> raw_source = *source;
  copy->init_self_indirect_pointer(isolate());
  copy->set_length(raw_source->length());
  copy->set_frame_size(raw_source->frame_size());
  copy->set_parameter_count(raw_source->parameter_count());
  copy->set_max_arguments(raw_source->max_arguments());
  copy->set_incoming_new_target_or_generator_register(
      raw_source->incoming_new_target_or_generator_register());
  copy->set_constant_pool(raw_source->constant_pool());
  copy->set_handler_table(raw_source->handler_table());
  copy->set_wrapper(*wrapper);
  if (raw_source->has_source_position_table(kAcquireLoad)) {
    copy->set_source_position_table(
        raw_source->source_position_table(kAcquireLoad), kReleaseStore);
  } else {
    copy->clear_source_position_table(kReleaseStore);
  }
  raw_source->CopyBytecodesTo(copy);
  wrapper->set_bytecode(copy);
  return handle(copy, isolate());
}

Handle<JSObject> Factory::NewJSObject(Handle<JSFunction> constructor,
                                      AllocationType allocation,
                                      NewJSObjectType new_js_object_type) {
  JSFunction::EnsureHasInitialMap(constructor);
  DirectHandle<Map> map(constructor->initial_map(), isolate());
  // NewJSObjectFromMap does not support creating dictionary mode objects. Need
  // to use NewSlowJSObjectFromMap instead.
  DCHECK(!map->is_dictionary_map());
  return NewJSObjectFromMap(map, allocation,
                            DirectHandle<AllocationSite>::null(),
                            new_js_object_type);
}

Handle<JSObject> Factory::NewSlowJSObjectWithNullProto() {
  Handle<JSObject> result =
      NewSlowJSObjectFromMap(isolate()->slow_object_with_null_prototype_map());
  return result;
}

Handle<JSObject> Factory::NewJSObjectWithNullProto() {
  Handle<Map> map(isolate()->object_function()->initial_map(), isolate());
  DirectHandle<Map> map_with_null_proto =
      Map::TransitionRootMapToPrototypeForNewObject(isolate(), map,
                                                    null_value());
  return NewJSObjectFromMap(map_with_null_proto);
}

Handle<JSGlobalObject> Factory::NewJSGlobalObject(
    DirectHandle<JSFunction> constructor) {
  DCHECK(constructor->has_initial_map());
  Handle<Map> map(constructor->initial_map(), isolate());
  DCHECK(map->is_dictionary_map());

  // Make sure no field properties are described in the initial map.
  // This guarantees us that normalizing the properties does not
  // require us to change property values to PropertyCells.
  DCHECK_EQ(map->NextFreePropertyIndex(), 0);

  // Make sure we don't have a ton of pre-allocated slots in the
  // global objects. They will be unused once we normalize the object.
  DCHECK_EQ(map->UnusedPropertyFields(), 0);
  DCHECK_EQ(map->GetInObjectProperties(), 0);

  // Initial size of the backing store to avoid resize of the storage during
  // bootstrapping. The size differs between the JS global object ad the
  // builtins object.
  int initial_size = 64;

  // Allocate a dictionary object for backing storage.
  int at_least_space_for = map->NumberOfOwnDescriptors() * 2 + initial_size;
  Handle<GlobalDictionary> dictionary =
      GlobalDictionary::New(isolate(), at_least_space_for);

  // The global object might be created from an object template with accessors.
  // Fill these accessors into the dictionary.
  DirectHandle<DescriptorArray> descs(map->instance_descriptors(isolate()),
                                      isolate());
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    PropertyDetails details = descs->GetDetails(i);
    // Only accessors are expected.
    DCHECK_EQ(PropertyKind::kAccessor, details.kind());
    PropertyDetails d(PropertyKind::kAccessor, details.attributes(),
                      PropertyCellType::kMutable);
    Handle<Name> name(descs->GetKey(i), isolate());
    DirectHandle<Object> value(descs->GetStrongValue(i), isolate());
    Handle<PropertyCell> cell = NewPropertyCell(name, d, value);
    // |dictionary| already contains enough space for all properties.
    USE(GlobalDictionary::Add(isolate(), dictionary, name, cell, d));
  }

  // Allocate the global object and initialize it with the backing store.
  Handle<JSGlobalObject> global(
      Cast<JSGlobalObject>(New(map, AllocationType::kOld)), isolate());
  InitializeJSObjectFromMap(*global, *dictionary, *map,
                            NewJSObjectType::kAPIWrapper);

  // Create a new map for the global object.
  DirectHandle<Map> new_map = Map::CopyDropDescriptors(isolate(), map);
  Tagged<Map> raw_map = *new_map;
  raw_map->set_may_have_interesting_properties(true);
  raw_map->set_is_dictionary_map(true);
  LOG(isolate(), MapDetails(raw_map));

  // Set up the global object as a normalized object.
  global->set_global_dictionary(*dictionary, kReleaseStore);
  global->set_map(isolate(), raw_map, kReleaseStore);

  // Make sure result is a global object with properties in dictionary.
  DCHECK(IsJSGlobalObject(*global) && !global->HasFastProperties());
  return global;
}

void Factory::InitializeCppHeapWrapper(Tagged<JSObject> obj) {
  DCHECK(IsJSApiWrapperObject(obj));
  DCHECK(IsJSAPIObjectWithEmbedderSlots(obj) || IsJSSpecialObject(obj));
  static_assert(JSSpecialObject::kCppHeapWrappableOffset ==
                JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset);
  obj->SetupLazilyInitializedCppHeapPointerField(
      JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset);
}

void Factory::InitializeJSObjectFromMap(Tagged<JSObject> obj,
                                        Tagged<Object> properties,
                                        Tagged<Map> map,
                                        NewJSObjectType new_js_object_type) {
  DisallowGarbageCollection no_gc;
  obj->set_raw_properties_or_hash(properties, kRelaxedStore);
  obj->initialize_elements();
  // TODO(1240798): Initialize the object's body using valid initial values
  // according to the object's initial map.  For example, if the map's
  // instance type is JS_ARRAY_TYPE, the length field should be initialized
  // to a number (e.g. Smi::zero()) and the elements initialized to a
  // fixed array (e.g. Heap::empty_fixed_array()).  Currently, the object
  // verification code has to cope with (temporarily) invalid objects.  See
  // for example, JSArray::JSArrayVerify).
  DCHECK_EQ(IsJSApiWrapperObject(map),
            new_js_object_type == NewJSObjectType::kAPIWrapper);
  InitializeJSObjectBody(obj, map,
                         new_js_object_type == NewJSObjectType::kNoAPIWrapper
                             ? JSObject::kHeaderSize
                             : JSAPIObjectWithEmbedderSlots::kHeaderSize);
  if (new_js_object_type == NewJSObjectType::kAPIWrapper) {
    InitializeCppHeapWrapper(obj);
  }
}

void Factory::InitializeJSObjectBody(Tagged<JSObject> obj, Tagged<Map> map,
                                     int start_offset) {
  DisallowGarbageCollection no_gc;
  if (start_offset == map->instance_size()) return;
  DCHECK_LT(start_offset, map->instance_size());

  // We cannot always fill with one_pointer_filler_map because objects
  // created from API functions expect their embedder fields to be initialized
  // with undefined_value.
  // Pre-allocated fields need to be initialized with undefined_value as well
  // so that object accesses before the constructor completes (e.g. in the
  // debugger) will not cause a crash.

  // In case of Array subclassing the |map| could already be transitioned
  // to different elements kind from the initial map on which we track slack.
  bool in_progress = map->IsInobjectSlackTrackingInProgress();
  obj->InitializeBody(map, start_offset, in_progress,
                      ReadOnlyRoots(isolate()).one_pointer_filler_map_word(),
                      *undefined_value());
  if (in_progress) {
    map->FindRootMap(isolate())->InobjectSlackTrackingStep(isolate());
  }
}

Handle<JSObject> Factory::NewJSObjectFromMap(
    DirectHandle<Map> map, AllocationType allocation,
    DirectHandle<AllocationSite> allocation_site,
    NewJSObjectType new_js_object_type) {
  // JSFunctions should be allocated using AllocateFunction to be
  // properly initialized.
  DCHECK(!InstanceTypeChecker::IsJSFunction(*map));

  // Both types of global objects should be allocated using
  // AllocateGlobalObject to be properly initialized.
  DCHECK_NE(map->instance_type(), JS_GLOBAL_OBJECT_TYPE);

  Tagged<JSObject> js_obj = Cast<JSObject>(
      AllocateRawWithAllocationSite(map, allocation, allocation_site));

  InitializeJSObjectFromMap(js_obj, *empty_fixed_array(), *map,
                            new_js_object_type);

  DCHECK(js_obj->HasFastElements() ||
         (isolate()->bootstrapper()->IsActive() ||
          *map == isolate()
                      ->raw_native_context()
                      ->js_array_template_literal_object_map()) ||
         js_obj->HasTypedArrayOrRabGsabTypedArrayElements() ||
         js_obj->HasFastStringWrapperElements() ||
         js_obj->HasFastArgumentsElements() ||
         js_obj->
```