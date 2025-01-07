Response:
My thought process to analyze the provided C++ code snippet goes through these stages:

1. **Identify the Core Functionality:** I first scan the code for function definitions and their names. Key function names like `SpeciesConstructor`, `IterationHasObservableEffects`, `SizeFromMap`, `NeedsRehashing`, `RehashBasedOnMap`, `SetProperty`, `SetSuperProperty`, `SetDataProperty`, `WriteToReadOnlyProperty`, `RedefineIncompatibleProperty`, and `CheckContextualStoreToJSGlobalObject` immediately stand out. These names suggest operations related to object creation, property access and modification, memory management (size), and internal data structure manipulation (rehashing).

2. **Analyze Individual Functions:** I then examine each function's purpose based on its name, parameters, and internal logic.

    * **`SpeciesConstructor`:** The name and the code clearly point to the implementation of the `Species` concept in JavaScript, used for customizing object creation in subclasses. It retrieves the `constructor` and `Symbol.species` properties.

    * **`IterationHasObservableEffects`:** This function checks if iterating over an object, specifically an array, would have side effects due to potential modifications of the prototype chain or array elements. The checks for `IsFastPackedElementsKind` and `IsHoleyElementsKind` are key here.

    * **`IsCodeLike`:** This function checks if an object is a `JSReceiver` and has the characteristic of being "code-like."  This suggests it might be related to callable objects or functions.

    * **`ShortPrint` and `operator<<`:** These are utility functions for debugging and printing object information in a concise format.

    * **`SizeFromMap` and `HeapObject::SizeFromMap`:** These functions calculate the size of a heap object based on its `Map` (which describes the object's structure and type). The code handles various object types and their specific size calculation logic. The presence of `kVariableSizeSentinel` and the numerous `if` conditions indicate the handling of variable-sized objects.

    * **`NeedsRehashing` and `CanBeRehashed`:** These functions determine if a hash-based data structure needs to be rehashed (to improve performance after many insertions/deletions) and whether it's safe to do so at the current moment.

    * **`RehashBasedOnMap`:** This function performs the actual rehashing for different types of hash-based structures.

    * **`GeneralizeAllFields`:** This function is related to optimizing object layouts by making field types more general.

    * **`SetProperty`, `SetPropertyInternal`, `SetSuperProperty`, `SetDataProperty`:** These are core functions for setting properties on objects, handling different scenarios like accessors, interceptors, prototypes, and read-only properties. The `LookupIterator` plays a crucial role in navigating the object's property hierarchy.

    * **`CheckContextualStoreToJSGlobalObject`:** This function checks for attempts to assign to non-existent global variables in strict mode.

    * **`CannotCreateProperty`, `WriteToReadOnlyProperty`, `RedefineIncompatibleProperty`:** These functions handle specific error conditions that can occur during property assignment.

3. **Identify JavaScript Relevance:** I look for functions that directly correspond to JavaScript concepts or behaviors. `SpeciesConstructor` directly relates to the `Symbol.species` feature. The property setting functions (`SetProperty`, etc.) directly implement JavaScript's property assignment semantics. The iteration checks are relevant to how `for...of` and other iteration mechanisms work in JavaScript.

4. **Infer Torque Involvement:** The prompt explicitly asks about Torque. Since the file extension is `.cc`, it's a standard C++ file, *not* a Torque file. I need to point this out clearly.

5. **Code Logic and Assumptions:** For functions like `SizeFromMap` and `NeedsRehashing`, I can infer the assumptions about object structure and memory layout. For `SetProperty`, the logic around `LookupIterator` and the handling of different property types (data, accessor, interceptor) reveals the underlying implementation of JavaScript's property access model. I consider what inputs would lead to different code paths (e.g., setting a property on a normal object vs. a proxy vs. an object with interceptors).

6. **Common Programming Errors:**  The error handling functions (`WriteToReadOnlyProperty`, `CannotCreateProperty`) directly relate to common JavaScript errors. I think about scenarios that would trigger these errors (e.g., trying to assign to a `const` property or a property on a non-extensible object).

7. **Synthesize the Functionality:** Finally, I combine my understanding of the individual functions to summarize the overall purpose of the file. I focus on the key areas of responsibility: object model implementation, property access and manipulation, memory management, and interaction with the JavaScript language semantics.

8. **Structure the Response:** I organize my findings into logical sections based on the prompt's requirements (file type, functionality, JavaScript relationship, code logic, common errors, summary). This makes the information clear and easy to understand. I use examples to illustrate the JavaScript relationships and potential errors.

By following these steps, I can effectively analyze the provided C++ code snippet and provide a comprehensive and accurate explanation of its functionality within the V8 JavaScript engine.
```cpp
te)) {
        constructor = isolate->factory()->undefined_value();
      }
    }
  }
  if (IsUndefined(*constructor, isolate)) {
    return default_species;
  } else {
    if (!IsConstructor(*constructor)) {
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kSpeciesNotConstructor));
    }
    return constructor;
  }
}

// ES6 section 7.3.20 SpeciesConstructor ( O, defaultConstructor )
V8_WARN_UNUSED_RESULT MaybeHandle<Object> Object::SpeciesConstructor(
    Isolate* isolate, Handle<JSReceiver> recv,
    Handle<JSFunction> default_ctor) {
  Handle<Object> ctor_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, ctor_obj,
      JSObject::GetProperty(isolate, recv,
                            isolate->factory()->constructor_string()));

  if (IsUndefined(*ctor_obj, isolate)) return default_ctor;

  if (!IsJSReceiver(*ctor_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kConstructorNotReceiver));
  }

  Handle<JSReceiver> ctor = Cast<JSReceiver>(ctor_obj);

  Handle<Object> species;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, species,
      JSObject::GetProperty(isolate, ctor,
                            isolate->factory()->species_symbol()));

  if (IsNullOrUndefined(*species, isolate)) {
    return default_ctor;
  }

  if (IsConstructor(*species)) return species;

  THROW_NEW_ERROR(isolate,
                  NewTypeError(MessageTemplate::kSpeciesNotConstructor));
}

// static
bool Object::IterationHasObservableEffects(Tagged<Object> obj) {
  DisallowGarbageCollection no_gc;
  // Check that this object is an array.
  if (!IsJSArray(obj)) return true;
  Tagged<JSArray> array = Cast<JSArray>(obj);

  // Check that we have the original ArrayPrototype.
  Tagged<Object> array_proto = array->map()->prototype();
  if (!IsJSObject(array_proto)) return true;
  Tagged<NativeContext> native_context = array->GetCreationContext().value();
  auto initial_array_prototype = native_context->initial_array_prototype();
  if (initial_array_prototype != array_proto) return true;

  Isolate* isolate = array->GetIsolate();
  // Check that the ArrayPrototype hasn't been modified in a way that would
  // affect iteration.
  if (!Protectors::IsArrayIteratorLookupChainIntact(isolate)) return true;

  // For FastPacked kinds, iteration will have the same effect as simply
  // accessing each property in order.
  ElementsKind array_kind = array->GetElementsKind();
  if (IsFastPackedElementsKind(array_kind)) return false;

  // For FastHoley kinds, an element access on a hole would cause a lookup on
  // the prototype. This could have different results if the prototype has been
  // changed.
  if (IsHoleyElementsKind(array_kind) &&
      Protectors::IsNoElementsIntact(isolate)) {
    return false;
  }
  return true;
}

// static
bool Object::IsCodeLike(Tagged<Object> obj, Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  return IsJSReceiver(obj) && Cast<JSReceiver>(obj)->IsCodeLike(isolate);
}

void ShortPrint(Tagged<Object> obj, FILE* out) {
  OFStream os(out);
  os << Brief(obj);
}

void ShortPrint(Tagged<Object> obj, StringStream* accumulator) {
  std::ostringstream os;
  os << Brief(obj);
  accumulator->Add(os.str().c_str());
}

void ShortPrint(Tagged<Object> obj, std::ostream& os) { os << Brief(obj); }

std::ostream& operator<<(std::ostream& os, Tagged<Object> obj) {
  ShortPrint(obj, os);
  return os;
}

std::ostream& operator<<(std::ostream& os, Object::Conversion kind) {
  switch (kind) {
    case Object::Conversion::kToNumber:
      return os << "ToNumber";
    case Object::Conversion::kToNumeric:
      return os << "ToNumeric";
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, const Brief& v) {
  Tagged<MaybeObject> maybe_object(v.value);
  Tagged<Smi> smi;
  Tagged<HeapObject> heap_object;
  if (maybe_object.ToSmi(&smi)) {
    Smi::SmiPrint(smi, os);
  } else if (maybe_object.IsCleared()) {
    os << "[cleared]";
  } else if (maybe_object.GetHeapObjectIfWeak(&heap_object)) {
    os << "[weak] ";
    heap_object->HeapObjectShortPrint(os);
  } else if (maybe_object.GetHeapObjectIfStrong(&heap_object)) {
    heap_object->HeapObjectShortPrint(os);
  } else {
    UNREACHABLE();
  }
  return os;
}

// static
void Smi::SmiPrint(Tagged<Smi> smi, std::ostream& os) { os << smi.value(); }

void Struct::BriefPrintDetails(std::ostream& os) {}

void Tuple2::BriefPrintDetails(std::ostream& os) {
  os << " " << Brief(value1()) << ", " << Brief(value2());
}

void MegaDomHandler::BriefPrintDetails(std::ostream& os) {
  os << " " << Brief(accessor(kAcquireLoad)) << ", " << Brief(context());
}

void ClassPositions::BriefPrintDetails(std::ostream& os) {
  os << " " << start() << ", " << end();
}

void CallableTask::BriefPrintDetails(std::ostream& os) {
  os << " callable=" << Brief(callable());
}

int HeapObjectLayout::SizeFromMap(Tagged<Map> map) const {
  return Tagged<HeapObject>(this)->SizeFromMap(map);
}

int HeapObject::SizeFromMap(Tagged<Map> map) const {
  int instance_size = map->instance_size();
  if (instance_size != kVariableSizeSentinel) return instance_size;
  // Only inline the most frequent cases.
  InstanceType instance_type = map->instance_type();
  if (base::IsInRange(instance_type, FIRST_FIXED_ARRAY_TYPE,
                      LAST_FIXED_ARRAY_TYPE)) {
    return UncheckedCast<FixedArray>(*this)->AllocatedSize();
  }
#define CASE(TypeCamelCase, TYPE_UPPER_CASE)                     \
  if (instance_type == TYPE_UPPER_CASE##_TYPE) {                 \
    return UncheckedCast<TypeCamelCase>(*this)->AllocatedSize(); \
  }
  SIMPLE_HEAP_OBJECT_LIST2(CASE)
#undef CASE
  if (instance_type == SLOPPY_ARGUMENTS_ELEMENTS_TYPE) {
    return UncheckedCast<SloppyArgumentsElements>(*this)->AllocatedSize();
  }
  if (base::IsInRange(instance_type, FIRST_CONTEXT_TYPE, LAST_CONTEXT_TYPE)) {
    if (instance_type == NATIVE_CONTEXT_TYPE) return NativeContext::kSize;
    return Context::SizeFor(UncheckedCast<Context>(*this)->length());
  }
  if (instance_type == SEQ_ONE_BYTE_STRING_TYPE ||
      instance_type == INTERNALIZED_ONE_BYTE_STRING_TYPE ||
      instance_type == SHARED_SEQ_ONE_BYTE_STRING_TYPE) {
    // Strings may get concurrently truncated, hence we have to access its
    // length synchronized.
    return SeqOneByteString::SizeFor(
        UncheckedCast<SeqOneByteString>(*this)->length(kAcquireLoad));
  }
  if (instance_type == BYTECODE_ARRAY_TYPE) {
    return BytecodeArray::SizeFor(
        UncheckedCast<BytecodeArray>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FREE_SPACE_TYPE) {
    return UncheckedCast<FreeSpace>(*this)->size(kRelaxedLoad);
  }
  if (instance_type == SEQ_TWO_BYTE_STRING_TYPE ||
      instance_type == INTERNALIZED_TWO_BYTE_STRING_TYPE ||
      instance_type == SHARED_SEQ_TWO_BYTE_STRING_TYPE) {
    // Strings may get concurrently truncated, hence we have to access its
    // length synchronized.
    return SeqTwoByteString::SizeFor(
        UncheckedCast<SeqTwoByteString>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FIXED_DOUBLE_ARRAY_TYPE) {
    return UncheckedCast<FixedDoubleArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_FIXED_ARRAY_TYPE) {
    return UncheckedCast<TrustedFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == PROTECTED_FIXED_ARRAY_TYPE) {
    return UncheckedCast<ProtectedFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_WEAK_FIXED_ARRAY_TYPE) {
    return UncheckedCast<TrustedWeakFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_BYTE_ARRAY_TYPE) {
    return UncheckedCast<TrustedByteArray>(*this)->AllocatedSize();
  }
  if (instance_type == FEEDBACK_METADATA_TYPE) {
    return UncheckedCast<FeedbackMetadata>(*this)->AllocatedSize();
  }
  if (base::IsInRange(instance_type, FIRST_DESCRIPTOR_ARRAY_TYPE,
                      LAST_DESCRIPTOR_ARRAY_TYPE)) {
    return DescriptorArray::SizeFor(
        UncheckedCast<DescriptorArray>(*this)->number_of_all_descriptors());
  }
  if (base::IsInRange(instance_type, FIRST_WEAK_FIXED_ARRAY_TYPE,
                      LAST_WEAK_FIXED_ARRAY_TYPE)) {
    return UncheckedCast<WeakFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == WEAK_ARRAY_LIST_TYPE) {
    return WeakArrayList::SizeForCapacity(
        UncheckedCast<WeakArrayList>(*this)->capacity());
  }
  if (instance_type == SMALL_ORDERED_HASH_SET_TYPE) {
    return SmallOrderedHashSet::SizeFor(
        UncheckedCast<SmallOrderedHashSet>(*this)->Capacity());
  }
  if (instance_type == SMALL_ORDERED_HASH_MAP_TYPE) {
    return SmallOrderedHashMap::SizeFor(
        UncheckedCast<SmallOrderedHashMap>(*this)->Capacity());
  }
  if (instance_type == SMALL_ORDERED_NAME_DICTIONARY_TYPE) {
    return SmallOrderedNameDictionary::SizeFor(
        UncheckedCast<SmallOrderedNameDictionary>(*this)->Capacity());
  }
  if (instance_type == SWISS_NAME_DICTIONARY_TYPE) {
    return SwissNameDictionary::SizeFor(
        UncheckedCast<SwissNameDictionary>(*this)->Capacity());
  }
  if (instance_type == PROPERTY_ARRAY_TYPE) {
    return PropertyArray::SizeFor(
        UncheckedCast<PropertyArray>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FEEDBACK_VECTOR_TYPE) {
    return FeedbackVector::SizeFor(
        UncheckedCast<FeedbackVector>(*this)->length());
  }
  if (instance_type == BIGINT_TYPE) {
    return BigInt::SizeFor(UncheckedCast<BigInt>(*this)->length());
  }
  if (instance_type == PREPARSE_DATA_TYPE) {
    Tagged<PreparseData> data = UncheckedCast<PreparseData>(*this);
    return PreparseData::SizeFor(data->data_length(), data->children_length());
  }
#define MAKE_TORQUE_SIZE_FOR(TYPE, TypeName)                \
  if (instance_type == TYPE) {                              \
    return UncheckedCast<TypeName>(*this)->AllocatedSize(); \
  }
  TORQUE_INSTANCE_TYPE_TO_BODY_DESCRIPTOR_LIST(MAKE_TORQUE_SIZE_FOR)
#undef MAKE_TORQUE_SIZE_FOR

  if (instance_type == INSTRUCTION_STREAM_TYPE) {
    return UncheckedCast<InstructionStream>(*this)->Size();
  }
  if (instance_type == COVERAGE_INFO_TYPE) {
    return CoverageInfo::SizeFor(
        UncheckedCast<CoverageInfo>(*this)->slot_count());
  }
#if V8_ENABLE_WEBASSEMBLY
  if (instance_type == WASM_TYPE_INFO_TYPE) {
    return WasmTypeInfo::SizeFor(
        UncheckedCast<WasmTypeInfo>(*this)->supertypes_length());
  }
  if (instance_type == WASM_STRUCT_TYPE) {
    return WasmStruct::GcSafeSize(map);
  }
  if (instance_type == WASM_ARRAY_TYPE) {
    return WasmArray::SizeFor(map, UncheckedCast<WasmArray>(*this)->length());
  }
  if (instance_type == WASM_NULL_TYPE) {
    return WasmNull::kSize;
  }
  if (instance_type == WASM_DISPATCH_TABLE_TYPE) {
    return WasmDispatchTable::SizeFor(
        UncheckedCast<WasmDispatchTable>(*this)->capacity());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  DCHECK_EQ(instance_type, EMBEDDER_DATA_ARRAY_TYPE);
  return EmbedderDataArray::SizeFor(
      UncheckedCast<EmbedderDataArray>(*this)->length());
}

bool HeapObject::NeedsRehashing(PtrComprCageBase cage_base) const {
  return NeedsRehashing(map(cage_base)->instance_type());
}

bool HeapObject::NeedsRehashing(InstanceType instance_type) const {
  if (V8_EXTERNAL_CODE_SPACE_BOOL) {
    // Use map() only when it's guaranteed that it's not an InstructionStream
    // object.
    DCHECK_IMPLIES(instance_type != INSTRUCTION_STREAM_TYPE,
                   instance_type == map()->instance_type());
  } else {
    DCHECK_EQ(instance_type, map()->instance_type());
  }
  switch (instance_type) {
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      return Cast<DescriptorArray>(*this)->number_of_descriptors() > 1;
    case TRANSITION_ARRAY_TYPE:
      return Cast<TransitionArray>(*this)->number_of_transitions() > 1;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      return false;  // We'll rehash from the JSMap or JSSet referencing them.
    case NAME_DICTIONARY_TYPE:
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case HASH_TABLE_TYPE:
    case SMALL_ORDERED_HASH_MAP_TYPE:
    case SMALL_ORDERED_HASH_SET_TYPE:
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
    case SWISS_NAME_DICTIONARY_TYPE:
    case JS_MAP_TYPE:
    case JS_SET_TYPE:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

bool HeapObject::CanBeRehashed(PtrComprCageBase cage_base) const {
  DCHECK(NeedsRehashing(cage_base));
  switch (map(cage_base)->instance_type()) {
    case JS_MAP_TYPE:
    case JS_SET_TYPE:
      return true;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      UNREACHABLE();  // We'll rehash from the JSMap or JSSet referencing them.
    case ORDERED_NAME_DICTIONARY_TYPE:
      return false;
    case NAME_DICTIONARY_TYPE:
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case SWISS_NAME_DICTIONARY_TYPE:
      return true;
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      return true;
    case TRANSITION_ARRAY_TYPE:
      return true;
    case SMALL_ORDERED_HASH_MAP_TYPE:
      return Cast<SmallOrderedHashMap>(*this)->NumberOfElements() == 0;
    case SMALL_ORDERED_HASH_SET_TYPE:
      return Cast<SmallOrderedHashMap>(*this)->NumberOfElements() == 0;
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
      return Cast<SmallOrderedNameDictionary>(*this)->NumberOfElements() == 0;
    default:
      return false;
  }
  UNREACHABLE();
}

template <typename IsolateT>
void HeapObject::RehashBasedOnMap(IsolateT* isolate) {
  switch (map(isolate)->instance_type()) {
    case HASH_TABLE_TYPE:
      Cast<ObjectHashTable>(*this)->Rehash(isolate);
      break;
    case NAME_DICTIONARY_TYPE:
      Cast<NameDictionary>(*this)->Rehash(isolate);
      break;
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
      Cast<NameToIndexHashTable>(*this)->Rehash(isolate);
      break;
    case REGISTERED_SYMBOL_TABLE_TYPE:
      Cast<RegisteredSymbolTable>(*this)->Rehash(isolate);
      break;
    case SWISS_NAME_DICTIONARY_TYPE:
      Cast<SwissNameDictionary>(*this)->Rehash(isolate);
      break;
    case GLOBAL_DICTIONARY_TYPE:
      Cast<GlobalDictionary>(*this)->Rehash(isolate);
      break;
    case NUMBER_DICTIONARY_TYPE:
      Cast<NumberDictionary>(*this)->Rehash(isolate);
      break;
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
      Cast<SimpleNumberDictionary>(*this)->Rehash(isolate);
      break;
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      DCHECK_LE(1, Cast<DescriptorArray>(*this)->number_of_descriptors());
      Cast<DescriptorArray>(*this)->Sort();
      break;
    case TRANSITION_ARRAY_TYPE:
      Cast<TransitionArray>(*this)->Sort();
      break;
    case SMALL_ORDERED_HASH_MAP_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedHashMap>(*this)->NumberOfElements());
      break;
    case SMALL_ORDERED_HASH_SET_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedHashSet>(*this)->NumberOfElements());
      break;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      UNREACHABLE();  // We'll rehash from the JSMap or JSSet referencing them.
    case JS_MAP_TYPE: {
      Cast<JSMap>(*this)->Rehash(isolate->AsIsolate());
      break;
    }
    case JS_SET_TYPE: {
      Cast<JSSet>(*this)->Rehash(isolate->AsIsolate());
      break;
    }
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedNameDictionary>(*this)->NumberOfElements());
      break;
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case INTERNALIZED_TWO_BYTE_STRING_TYPE:
      // Rare case, rehash read-only space strings before they are sealed.
      DCHECK(ReadOnlyHeap::Contains(*this));
      Cast<String>(*this)->EnsureHash();
      break;
    default:
      // TODO(ishell): remove once b/326043780 is no longer an issue.
      isolate->AsIsolate()->PushParamsAndDie(
          reinterpret_cast<void*>(ptr()), reinterpret_cast<void*>(map().ptr()),
          reinterpret_cast<void*>(
              static_cast<uintptr_t>(map()->instance_type())));
      UNREACHABLE();
  }
}
template void HeapObject::RehashBasedOnMap(Isolate* isolate);
template void HeapObject::RehashBasedOnMap(LocalIsolate* isolate);

void DescriptorArray::GeneralizeAllFields(bool clear_constness) {
  int length = number_of_descriptors();
  for (InternalIndex i : InternalIndex::Range(length)) {
    PropertyDetails details = GetDetails(i);
    details = details.CopyWithRepresentation(Representation::Tagged());
    if (details.location() == PropertyLocation::kField) {
      // Since constness is not propagated across proto transitions we must
      // clear the flag here.
      if (clear_constness) {
        details = details.CopyWithConstness(PropertyConstness::kMutable);
      }
      DCHECK_EQ(PropertyKind::kData, details.kind());
      SetValue(i, FieldType::Any());
    }
    SetDetails(i, details);
  }
}

MaybeHandle<Object> Object::SetProperty(Isolate* isolate, Handle<JSAny> object,
                                        Handle<Name> name, Handle<Object> value,
                                        StoreOrigin store_origin,
                                        Maybe<ShouldThrow> should_throw) {
  LookupIterator it(isolate, object, name);
  MAYBE_RETURN_NULL(SetProperty(&it, value, store_origin, should_throw));
  return value;
}

Maybe<bool> Object::SetPropertyInternal(LookupIterator* it,
                                        Handle<Object> value,
                                        Maybe<ShouldThrow> should_throw,
                                        StoreOrigin store_origin, bool* found) {
  it->UpdateProtector();
  DCHECK(it->IsFound());

  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(it->isolate());

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        // Check whether it makes sense to reuse the lookup iterator. Here it
        // might still call into setters up the prototype chain.
        return JSObject::SetPropertyWithFailedAccessCheck(it, value,
                                                          should_throw);

      case LookupIterator::JSPROXY: {
        Handle<JSAny> receiver = it->GetReceiver();
        // In case of global IC, the receiver is the global object. Replace by
        // the global proxy.
        if (IsJSGlobalObject(*receiver)) {
          receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(),
                            it->isolate());
        }
        return JSProxy::SetProperty(it->GetHolder<JSProxy>(), it->GetName(),
                                    value, receiver, should_throw);
      }

      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(it->isolate(), kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));

      case LookupIterator::INTERCEPTOR: {
        if (it->HolderIsReceiverOrHiddenPrototype()) {
          InterceptorResult result;
          if (!JSObject::SetPropertyWithInterceptor(it, should_throw, value)
                   .To(&result)) {
            // An exception was thrown in the interceptor. Propagate.
            return Nothing<bool>();
          }
          switch (result) {
            case InterceptorResult::kFalse:
              return Just(false);
            case InterceptorResult::kTrue:
              return Just(true);
            case InterceptorResult::kNotIntercepted:
              // Proceed lookup.
              break;
          }
          // Assuming that the callback has side effects, we use
          // Object::SetSuperProperty() which works properly regardless on
          // whether the property was present on the receiver or not when
          // storing to the receiver.
          // Proceed lookup from the next state.
          it->Next();
        } else {
          Maybe<PropertyAttributes> maybe_attributes =
              JSObject::GetPropertyAttributesWithInterceptor(it);
          if (maybe_attributes.IsNothing()) return Nothing<bool>();
          if ((maybe_attributes.FromJust() & READ_ONLY) != 0) {
            return WriteToReadOnlyProperty(it, value, should_throw);
          }
          // At this point we might have called interceptor's query or getter
          // callback. Assuming that the callbacks have side effects, we use
          // Object::SetSuperProperty() which works properly regardless on
          // whether the property was present on the receiver or not when
          // storing to the receiver.
          if (maybe_attributes.FromJust() == ABSENT) {
            // Proceed lookup from the next state.
            it->Next();
          } else {
            // Finish lookup in order to make Object::SetSuperProperty() store
            // property to the receiver.
            it->NotFound();
          }
        }
        return Object::SetSuperProperty(it, value, store_origin, should_throw);
      }

      case LookupIterator::ACCESSOR: {
        if (it->IsReadOnly()) {
          return WriteToReadOnlyProperty(it, value, should_throw);
        }
        DirectHandle<Object> accessors = it->GetAccessors();
        if (IsAccessorInfo(*accessors) &&
            !it->HolderIsReceiverOrHiddenPrototype()) {
          *found = false;
          return Nothing<bool>();
        }
        return SetPropertyWithAccessor(it, value, should_throw);
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND: {
        // IntegerIndexedElementSet converts value to a Number/BigInt prior to
        // the bounds check. The bounds check has already happened here, but
        // perform the possibly effectful ToNumber (or ToBigInt) operation
        // anyways.
        DirectHandle<JSTypedArray> holder = it->GetHolder<JSTypedArray>();
        Handle<Object> converted_value;
        if (holder->type() == kExternalBigInt64Array ||
            holder->type() == kExternalBigUint64Array) {
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              it->isolate(), converted_value,
              BigInt::FromObject(it->isolate(), value), Nothing<bool>());
        } else {
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              it->isolate(), converted_value,
              Object::ToNumber(it->isolate(), value), Nothing<bool>());
        }

        // For RAB/GSABs, the above conversion might grow the buffer so that the
        // index is no longer out of bounds. Redo the bounds check and try
        // again.
        it->RecheckTypedArrayBounds();
        if (it->state() != LookupIterator::DATA) {
          // Still out of bounds.
          DCHECK_EQ(it->state(), LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND);

          // FIXME: Throw a TypeError if the holder is detached here
          // (IntegerIndexedElementSet step 5).

          // TODO(verwaest): Per spec, we should return false here (steps 6-9
          // in IntegerIndexedElementSet), resulting in an exception being
          // thrown on OOB accesses in strict code. Historically, v8 has not
          // done made this change due to uncertainty about web compat.
          // (v8:4901)
          return Just(true);
        }
        value = converted_value;
        [[fallthrough]];
      }

      case LookupIterator::DATA:
        if (it->IsReadOnly()) {
          return WriteToReadOnlyProperty(it, value, should_throw);
        }
        if (it->HolderIsReceiverOrHiddenPrototype()) {
          return SetDataProperty(it, value);
        }
        [[fallthrough]];
      case LookupIterator::NOT_FOUND:
      case LookupIterator::TRANSITION:
        *found = false;
        return Nothing<bool>();
    }
    UNREACHABLE();
  }
}

bool Object::CheckContextualStoreToJSGlobalObject(
    LookupIterator* it, Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();

  if (IsJSGlobalObject(*it->GetReceiver(), isolate) &&
      (GetShouldThrow(isolate, should_throw) == ShouldThrow::kThrowOnError)) {
    if (it->state() == LookupIterator::TRANSITION) {
      // The property cell that we have created is garbage because we are going
      // to throw now instead of putting it into the global dictionary. However,
      // the cell might already have been stored into the feedback vector, so
      // we must invalidate it nevertheless.
      it->transition_cell()->ClearAndInvalidate(ReadOnlyRoots(isolate));
    }
    isolate->Throw(*isolate->factory()->NewReferenceError(
        MessageTemplate::kNotDefined, it->GetName()));
    return false;
  }
Prompt: 
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能

"""
te)) {
        constructor = isolate->factory()->undefined_value();
      }
    }
  }
  if (IsUndefined(*constructor, isolate)) {
    return default_species;
  } else {
    if (!IsConstructor(*constructor)) {
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kSpeciesNotConstructor));
    }
    return constructor;
  }
}

// ES6 section 7.3.20 SpeciesConstructor ( O, defaultConstructor )
V8_WARN_UNUSED_RESULT MaybeHandle<Object> Object::SpeciesConstructor(
    Isolate* isolate, Handle<JSReceiver> recv,
    Handle<JSFunction> default_ctor) {
  Handle<Object> ctor_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, ctor_obj,
      JSObject::GetProperty(isolate, recv,
                            isolate->factory()->constructor_string()));

  if (IsUndefined(*ctor_obj, isolate)) return default_ctor;

  if (!IsJSReceiver(*ctor_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kConstructorNotReceiver));
  }

  Handle<JSReceiver> ctor = Cast<JSReceiver>(ctor_obj);

  Handle<Object> species;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, species,
      JSObject::GetProperty(isolate, ctor,
                            isolate->factory()->species_symbol()));

  if (IsNullOrUndefined(*species, isolate)) {
    return default_ctor;
  }

  if (IsConstructor(*species)) return species;

  THROW_NEW_ERROR(isolate,
                  NewTypeError(MessageTemplate::kSpeciesNotConstructor));
}

// static
bool Object::IterationHasObservableEffects(Tagged<Object> obj) {
  DisallowGarbageCollection no_gc;
  // Check that this object is an array.
  if (!IsJSArray(obj)) return true;
  Tagged<JSArray> array = Cast<JSArray>(obj);

  // Check that we have the original ArrayPrototype.
  Tagged<Object> array_proto = array->map()->prototype();
  if (!IsJSObject(array_proto)) return true;
  Tagged<NativeContext> native_context = array->GetCreationContext().value();
  auto initial_array_prototype = native_context->initial_array_prototype();
  if (initial_array_prototype != array_proto) return true;

  Isolate* isolate = array->GetIsolate();
  // Check that the ArrayPrototype hasn't been modified in a way that would
  // affect iteration.
  if (!Protectors::IsArrayIteratorLookupChainIntact(isolate)) return true;

  // For FastPacked kinds, iteration will have the same effect as simply
  // accessing each property in order.
  ElementsKind array_kind = array->GetElementsKind();
  if (IsFastPackedElementsKind(array_kind)) return false;

  // For FastHoley kinds, an element access on a hole would cause a lookup on
  // the prototype. This could have different results if the prototype has been
  // changed.
  if (IsHoleyElementsKind(array_kind) &&
      Protectors::IsNoElementsIntact(isolate)) {
    return false;
  }
  return true;
}

// static
bool Object::IsCodeLike(Tagged<Object> obj, Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  return IsJSReceiver(obj) && Cast<JSReceiver>(obj)->IsCodeLike(isolate);
}

void ShortPrint(Tagged<Object> obj, FILE* out) {
  OFStream os(out);
  os << Brief(obj);
}

void ShortPrint(Tagged<Object> obj, StringStream* accumulator) {
  std::ostringstream os;
  os << Brief(obj);
  accumulator->Add(os.str().c_str());
}

void ShortPrint(Tagged<Object> obj, std::ostream& os) { os << Brief(obj); }

std::ostream& operator<<(std::ostream& os, Tagged<Object> obj) {
  ShortPrint(obj, os);
  return os;
}

std::ostream& operator<<(std::ostream& os, Object::Conversion kind) {
  switch (kind) {
    case Object::Conversion::kToNumber:
      return os << "ToNumber";
    case Object::Conversion::kToNumeric:
      return os << "ToNumeric";
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, const Brief& v) {
  Tagged<MaybeObject> maybe_object(v.value);
  Tagged<Smi> smi;
  Tagged<HeapObject> heap_object;
  if (maybe_object.ToSmi(&smi)) {
    Smi::SmiPrint(smi, os);
  } else if (maybe_object.IsCleared()) {
    os << "[cleared]";
  } else if (maybe_object.GetHeapObjectIfWeak(&heap_object)) {
    os << "[weak] ";
    heap_object->HeapObjectShortPrint(os);
  } else if (maybe_object.GetHeapObjectIfStrong(&heap_object)) {
    heap_object->HeapObjectShortPrint(os);
  } else {
    UNREACHABLE();
  }
  return os;
}

// static
void Smi::SmiPrint(Tagged<Smi> smi, std::ostream& os) { os << smi.value(); }

void Struct::BriefPrintDetails(std::ostream& os) {}

void Tuple2::BriefPrintDetails(std::ostream& os) {
  os << " " << Brief(value1()) << ", " << Brief(value2());
}

void MegaDomHandler::BriefPrintDetails(std::ostream& os) {
  os << " " << Brief(accessor(kAcquireLoad)) << ", " << Brief(context());
}

void ClassPositions::BriefPrintDetails(std::ostream& os) {
  os << " " << start() << ", " << end();
}

void CallableTask::BriefPrintDetails(std::ostream& os) {
  os << " callable=" << Brief(callable());
}

int HeapObjectLayout::SizeFromMap(Tagged<Map> map) const {
  return Tagged<HeapObject>(this)->SizeFromMap(map);
}

int HeapObject::SizeFromMap(Tagged<Map> map) const {
  int instance_size = map->instance_size();
  if (instance_size != kVariableSizeSentinel) return instance_size;
  // Only inline the most frequent cases.
  InstanceType instance_type = map->instance_type();
  if (base::IsInRange(instance_type, FIRST_FIXED_ARRAY_TYPE,
                      LAST_FIXED_ARRAY_TYPE)) {
    return UncheckedCast<FixedArray>(*this)->AllocatedSize();
  }
#define CASE(TypeCamelCase, TYPE_UPPER_CASE)                     \
  if (instance_type == TYPE_UPPER_CASE##_TYPE) {                 \
    return UncheckedCast<TypeCamelCase>(*this)->AllocatedSize(); \
  }
  SIMPLE_HEAP_OBJECT_LIST2(CASE)
#undef CASE
  if (instance_type == SLOPPY_ARGUMENTS_ELEMENTS_TYPE) {
    return UncheckedCast<SloppyArgumentsElements>(*this)->AllocatedSize();
  }
  if (base::IsInRange(instance_type, FIRST_CONTEXT_TYPE, LAST_CONTEXT_TYPE)) {
    if (instance_type == NATIVE_CONTEXT_TYPE) return NativeContext::kSize;
    return Context::SizeFor(UncheckedCast<Context>(*this)->length());
  }
  if (instance_type == SEQ_ONE_BYTE_STRING_TYPE ||
      instance_type == INTERNALIZED_ONE_BYTE_STRING_TYPE ||
      instance_type == SHARED_SEQ_ONE_BYTE_STRING_TYPE) {
    // Strings may get concurrently truncated, hence we have to access its
    // length synchronized.
    return SeqOneByteString::SizeFor(
        UncheckedCast<SeqOneByteString>(*this)->length(kAcquireLoad));
  }
  if (instance_type == BYTECODE_ARRAY_TYPE) {
    return BytecodeArray::SizeFor(
        UncheckedCast<BytecodeArray>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FREE_SPACE_TYPE) {
    return UncheckedCast<FreeSpace>(*this)->size(kRelaxedLoad);
  }
  if (instance_type == SEQ_TWO_BYTE_STRING_TYPE ||
      instance_type == INTERNALIZED_TWO_BYTE_STRING_TYPE ||
      instance_type == SHARED_SEQ_TWO_BYTE_STRING_TYPE) {
    // Strings may get concurrently truncated, hence we have to access its
    // length synchronized.
    return SeqTwoByteString::SizeFor(
        UncheckedCast<SeqTwoByteString>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FIXED_DOUBLE_ARRAY_TYPE) {
    return UncheckedCast<FixedDoubleArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_FIXED_ARRAY_TYPE) {
    return UncheckedCast<TrustedFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == PROTECTED_FIXED_ARRAY_TYPE) {
    return UncheckedCast<ProtectedFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_WEAK_FIXED_ARRAY_TYPE) {
    return UncheckedCast<TrustedWeakFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_BYTE_ARRAY_TYPE) {
    return UncheckedCast<TrustedByteArray>(*this)->AllocatedSize();
  }
  if (instance_type == FEEDBACK_METADATA_TYPE) {
    return UncheckedCast<FeedbackMetadata>(*this)->AllocatedSize();
  }
  if (base::IsInRange(instance_type, FIRST_DESCRIPTOR_ARRAY_TYPE,
                      LAST_DESCRIPTOR_ARRAY_TYPE)) {
    return DescriptorArray::SizeFor(
        UncheckedCast<DescriptorArray>(*this)->number_of_all_descriptors());
  }
  if (base::IsInRange(instance_type, FIRST_WEAK_FIXED_ARRAY_TYPE,
                      LAST_WEAK_FIXED_ARRAY_TYPE)) {
    return UncheckedCast<WeakFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == WEAK_ARRAY_LIST_TYPE) {
    return WeakArrayList::SizeForCapacity(
        UncheckedCast<WeakArrayList>(*this)->capacity());
  }
  if (instance_type == SMALL_ORDERED_HASH_SET_TYPE) {
    return SmallOrderedHashSet::SizeFor(
        UncheckedCast<SmallOrderedHashSet>(*this)->Capacity());
  }
  if (instance_type == SMALL_ORDERED_HASH_MAP_TYPE) {
    return SmallOrderedHashMap::SizeFor(
        UncheckedCast<SmallOrderedHashMap>(*this)->Capacity());
  }
  if (instance_type == SMALL_ORDERED_NAME_DICTIONARY_TYPE) {
    return SmallOrderedNameDictionary::SizeFor(
        UncheckedCast<SmallOrderedNameDictionary>(*this)->Capacity());
  }
  if (instance_type == SWISS_NAME_DICTIONARY_TYPE) {
    return SwissNameDictionary::SizeFor(
        UncheckedCast<SwissNameDictionary>(*this)->Capacity());
  }
  if (instance_type == PROPERTY_ARRAY_TYPE) {
    return PropertyArray::SizeFor(
        UncheckedCast<PropertyArray>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FEEDBACK_VECTOR_TYPE) {
    return FeedbackVector::SizeFor(
        UncheckedCast<FeedbackVector>(*this)->length());
  }
  if (instance_type == BIGINT_TYPE) {
    return BigInt::SizeFor(UncheckedCast<BigInt>(*this)->length());
  }
  if (instance_type == PREPARSE_DATA_TYPE) {
    Tagged<PreparseData> data = UncheckedCast<PreparseData>(*this);
    return PreparseData::SizeFor(data->data_length(), data->children_length());
  }
#define MAKE_TORQUE_SIZE_FOR(TYPE, TypeName)                \
  if (instance_type == TYPE) {                              \
    return UncheckedCast<TypeName>(*this)->AllocatedSize(); \
  }
  TORQUE_INSTANCE_TYPE_TO_BODY_DESCRIPTOR_LIST(MAKE_TORQUE_SIZE_FOR)
#undef MAKE_TORQUE_SIZE_FOR

  if (instance_type == INSTRUCTION_STREAM_TYPE) {
    return UncheckedCast<InstructionStream>(*this)->Size();
  }
  if (instance_type == COVERAGE_INFO_TYPE) {
    return CoverageInfo::SizeFor(
        UncheckedCast<CoverageInfo>(*this)->slot_count());
  }
#if V8_ENABLE_WEBASSEMBLY
  if (instance_type == WASM_TYPE_INFO_TYPE) {
    return WasmTypeInfo::SizeFor(
        UncheckedCast<WasmTypeInfo>(*this)->supertypes_length());
  }
  if (instance_type == WASM_STRUCT_TYPE) {
    return WasmStruct::GcSafeSize(map);
  }
  if (instance_type == WASM_ARRAY_TYPE) {
    return WasmArray::SizeFor(map, UncheckedCast<WasmArray>(*this)->length());
  }
  if (instance_type == WASM_NULL_TYPE) {
    return WasmNull::kSize;
  }
  if (instance_type == WASM_DISPATCH_TABLE_TYPE) {
    return WasmDispatchTable::SizeFor(
        UncheckedCast<WasmDispatchTable>(*this)->capacity());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  DCHECK_EQ(instance_type, EMBEDDER_DATA_ARRAY_TYPE);
  return EmbedderDataArray::SizeFor(
      UncheckedCast<EmbedderDataArray>(*this)->length());
}

bool HeapObject::NeedsRehashing(PtrComprCageBase cage_base) const {
  return NeedsRehashing(map(cage_base)->instance_type());
}

bool HeapObject::NeedsRehashing(InstanceType instance_type) const {
  if (V8_EXTERNAL_CODE_SPACE_BOOL) {
    // Use map() only when it's guaranteed that it's not an InstructionStream
    // object.
    DCHECK_IMPLIES(instance_type != INSTRUCTION_STREAM_TYPE,
                   instance_type == map()->instance_type());
  } else {
    DCHECK_EQ(instance_type, map()->instance_type());
  }
  switch (instance_type) {
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      return Cast<DescriptorArray>(*this)->number_of_descriptors() > 1;
    case TRANSITION_ARRAY_TYPE:
      return Cast<TransitionArray>(*this)->number_of_transitions() > 1;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      return false;  // We'll rehash from the JSMap or JSSet referencing them.
    case NAME_DICTIONARY_TYPE:
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case HASH_TABLE_TYPE:
    case SMALL_ORDERED_HASH_MAP_TYPE:
    case SMALL_ORDERED_HASH_SET_TYPE:
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
    case SWISS_NAME_DICTIONARY_TYPE:
    case JS_MAP_TYPE:
    case JS_SET_TYPE:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

bool HeapObject::CanBeRehashed(PtrComprCageBase cage_base) const {
  DCHECK(NeedsRehashing(cage_base));
  switch (map(cage_base)->instance_type()) {
    case JS_MAP_TYPE:
    case JS_SET_TYPE:
      return true;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      UNREACHABLE();  // We'll rehash from the JSMap or JSSet referencing them.
    case ORDERED_NAME_DICTIONARY_TYPE:
      return false;
    case NAME_DICTIONARY_TYPE:
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case SWISS_NAME_DICTIONARY_TYPE:
      return true;
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      return true;
    case TRANSITION_ARRAY_TYPE:
      return true;
    case SMALL_ORDERED_HASH_MAP_TYPE:
      return Cast<SmallOrderedHashMap>(*this)->NumberOfElements() == 0;
    case SMALL_ORDERED_HASH_SET_TYPE:
      return Cast<SmallOrderedHashMap>(*this)->NumberOfElements() == 0;
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
      return Cast<SmallOrderedNameDictionary>(*this)->NumberOfElements() == 0;
    default:
      return false;
  }
  UNREACHABLE();
}

template <typename IsolateT>
void HeapObject::RehashBasedOnMap(IsolateT* isolate) {
  switch (map(isolate)->instance_type()) {
    case HASH_TABLE_TYPE:
      Cast<ObjectHashTable>(*this)->Rehash(isolate);
      break;
    case NAME_DICTIONARY_TYPE:
      Cast<NameDictionary>(*this)->Rehash(isolate);
      break;
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
      Cast<NameToIndexHashTable>(*this)->Rehash(isolate);
      break;
    case REGISTERED_SYMBOL_TABLE_TYPE:
      Cast<RegisteredSymbolTable>(*this)->Rehash(isolate);
      break;
    case SWISS_NAME_DICTIONARY_TYPE:
      Cast<SwissNameDictionary>(*this)->Rehash(isolate);
      break;
    case GLOBAL_DICTIONARY_TYPE:
      Cast<GlobalDictionary>(*this)->Rehash(isolate);
      break;
    case NUMBER_DICTIONARY_TYPE:
      Cast<NumberDictionary>(*this)->Rehash(isolate);
      break;
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
      Cast<SimpleNumberDictionary>(*this)->Rehash(isolate);
      break;
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      DCHECK_LE(1, Cast<DescriptorArray>(*this)->number_of_descriptors());
      Cast<DescriptorArray>(*this)->Sort();
      break;
    case TRANSITION_ARRAY_TYPE:
      Cast<TransitionArray>(*this)->Sort();
      break;
    case SMALL_ORDERED_HASH_MAP_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedHashMap>(*this)->NumberOfElements());
      break;
    case SMALL_ORDERED_HASH_SET_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedHashSet>(*this)->NumberOfElements());
      break;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      UNREACHABLE();  // We'll rehash from the JSMap or JSSet referencing them.
    case JS_MAP_TYPE: {
      Cast<JSMap>(*this)->Rehash(isolate->AsIsolate());
      break;
    }
    case JS_SET_TYPE: {
      Cast<JSSet>(*this)->Rehash(isolate->AsIsolate());
      break;
    }
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedNameDictionary>(*this)->NumberOfElements());
      break;
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case INTERNALIZED_TWO_BYTE_STRING_TYPE:
      // Rare case, rehash read-only space strings before they are sealed.
      DCHECK(ReadOnlyHeap::Contains(*this));
      Cast<String>(*this)->EnsureHash();
      break;
    default:
      // TODO(ishell): remove once b/326043780 is no longer an issue.
      isolate->AsIsolate()->PushParamsAndDie(
          reinterpret_cast<void*>(ptr()), reinterpret_cast<void*>(map().ptr()),
          reinterpret_cast<void*>(
              static_cast<uintptr_t>(map()->instance_type())));
      UNREACHABLE();
  }
}
template void HeapObject::RehashBasedOnMap(Isolate* isolate);
template void HeapObject::RehashBasedOnMap(LocalIsolate* isolate);

void DescriptorArray::GeneralizeAllFields(bool clear_constness) {
  int length = number_of_descriptors();
  for (InternalIndex i : InternalIndex::Range(length)) {
    PropertyDetails details = GetDetails(i);
    details = details.CopyWithRepresentation(Representation::Tagged());
    if (details.location() == PropertyLocation::kField) {
      // Since constness is not propagated across proto transitions we must
      // clear the flag here.
      if (clear_constness) {
        details = details.CopyWithConstness(PropertyConstness::kMutable);
      }
      DCHECK_EQ(PropertyKind::kData, details.kind());
      SetValue(i, FieldType::Any());
    }
    SetDetails(i, details);
  }
}

MaybeHandle<Object> Object::SetProperty(Isolate* isolate, Handle<JSAny> object,
                                        Handle<Name> name, Handle<Object> value,
                                        StoreOrigin store_origin,
                                        Maybe<ShouldThrow> should_throw) {
  LookupIterator it(isolate, object, name);
  MAYBE_RETURN_NULL(SetProperty(&it, value, store_origin, should_throw));
  return value;
}

Maybe<bool> Object::SetPropertyInternal(LookupIterator* it,
                                        Handle<Object> value,
                                        Maybe<ShouldThrow> should_throw,
                                        StoreOrigin store_origin, bool* found) {
  it->UpdateProtector();
  DCHECK(it->IsFound());

  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(it->isolate());

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        // Check whether it makes sense to reuse the lookup iterator. Here it
        // might still call into setters up the prototype chain.
        return JSObject::SetPropertyWithFailedAccessCheck(it, value,
                                                          should_throw);

      case LookupIterator::JSPROXY: {
        Handle<JSAny> receiver = it->GetReceiver();
        // In case of global IC, the receiver is the global object. Replace by
        // the global proxy.
        if (IsJSGlobalObject(*receiver)) {
          receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(),
                            it->isolate());
        }
        return JSProxy::SetProperty(it->GetHolder<JSProxy>(), it->GetName(),
                                    value, receiver, should_throw);
      }

      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(it->isolate(), kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));

      case LookupIterator::INTERCEPTOR: {
        if (it->HolderIsReceiverOrHiddenPrototype()) {
          InterceptorResult result;
          if (!JSObject::SetPropertyWithInterceptor(it, should_throw, value)
                   .To(&result)) {
            // An exception was thrown in the interceptor. Propagate.
            return Nothing<bool>();
          }
          switch (result) {
            case InterceptorResult::kFalse:
              return Just(false);
            case InterceptorResult::kTrue:
              return Just(true);
            case InterceptorResult::kNotIntercepted:
              // Proceed lookup.
              break;
          }
          // Assuming that the callback has side effects, we use
          // Object::SetSuperProperty() which works properly regardless on
          // whether the property was present on the receiver or not when
          // storing to the receiver.
          // Proceed lookup from the next state.
          it->Next();
        } else {
          Maybe<PropertyAttributes> maybe_attributes =
              JSObject::GetPropertyAttributesWithInterceptor(it);
          if (maybe_attributes.IsNothing()) return Nothing<bool>();
          if ((maybe_attributes.FromJust() & READ_ONLY) != 0) {
            return WriteToReadOnlyProperty(it, value, should_throw);
          }
          // At this point we might have called interceptor's query or getter
          // callback. Assuming that the callbacks have side effects, we use
          // Object::SetSuperProperty() which works properly regardless on
          // whether the property was present on the receiver or not when
          // storing to the receiver.
          if (maybe_attributes.FromJust() == ABSENT) {
            // Proceed lookup from the next state.
            it->Next();
          } else {
            // Finish lookup in order to make Object::SetSuperProperty() store
            // property to the receiver.
            it->NotFound();
          }
        }
        return Object::SetSuperProperty(it, value, store_origin, should_throw);
      }

      case LookupIterator::ACCESSOR: {
        if (it->IsReadOnly()) {
          return WriteToReadOnlyProperty(it, value, should_throw);
        }
        DirectHandle<Object> accessors = it->GetAccessors();
        if (IsAccessorInfo(*accessors) &&
            !it->HolderIsReceiverOrHiddenPrototype()) {
          *found = false;
          return Nothing<bool>();
        }
        return SetPropertyWithAccessor(it, value, should_throw);
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND: {
        // IntegerIndexedElementSet converts value to a Number/BigInt prior to
        // the bounds check. The bounds check has already happened here, but
        // perform the possibly effectful ToNumber (or ToBigInt) operation
        // anyways.
        DirectHandle<JSTypedArray> holder = it->GetHolder<JSTypedArray>();
        Handle<Object> converted_value;
        if (holder->type() == kExternalBigInt64Array ||
            holder->type() == kExternalBigUint64Array) {
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              it->isolate(), converted_value,
              BigInt::FromObject(it->isolate(), value), Nothing<bool>());
        } else {
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              it->isolate(), converted_value,
              Object::ToNumber(it->isolate(), value), Nothing<bool>());
        }

        // For RAB/GSABs, the above conversion might grow the buffer so that the
        // index is no longer out of bounds. Redo the bounds check and try
        // again.
        it->RecheckTypedArrayBounds();
        if (it->state() != LookupIterator::DATA) {
          // Still out of bounds.
          DCHECK_EQ(it->state(), LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND);

          // FIXME: Throw a TypeError if the holder is detached here
          // (IntegerIndexedElementSet step 5).

          // TODO(verwaest): Per spec, we should return false here (steps 6-9
          // in IntegerIndexedElementSet), resulting in an exception being
          // thrown on OOB accesses in strict code. Historically, v8 has not
          // done made this change due to uncertainty about web compat.
          // (v8:4901)
          return Just(true);
        }
        value = converted_value;
        [[fallthrough]];
      }

      case LookupIterator::DATA:
        if (it->IsReadOnly()) {
          return WriteToReadOnlyProperty(it, value, should_throw);
        }
        if (it->HolderIsReceiverOrHiddenPrototype()) {
          return SetDataProperty(it, value);
        }
        [[fallthrough]];
      case LookupIterator::NOT_FOUND:
      case LookupIterator::TRANSITION:
        *found = false;
        return Nothing<bool>();
    }
    UNREACHABLE();
  }
}

bool Object::CheckContextualStoreToJSGlobalObject(
    LookupIterator* it, Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();

  if (IsJSGlobalObject(*it->GetReceiver(), isolate) &&
      (GetShouldThrow(isolate, should_throw) == ShouldThrow::kThrowOnError)) {
    if (it->state() == LookupIterator::TRANSITION) {
      // The property cell that we have created is garbage because we are going
      // to throw now instead of putting it into the global dictionary. However,
      // the cell might already have been stored into the feedback vector, so
      // we must invalidate it nevertheless.
      it->transition_cell()->ClearAndInvalidate(ReadOnlyRoots(isolate));
    }
    isolate->Throw(*isolate->factory()->NewReferenceError(
        MessageTemplate::kNotDefined, it->GetName()));
    return false;
  }
  return true;
}

Maybe<bool> Object::SetProperty(LookupIterator* it, Handle<Object> value,
                                StoreOrigin store_origin,
                                Maybe<ShouldThrow> should_throw) {
  if (it->IsFound()) {
    bool found = true;
    Maybe<bool> result =
        SetPropertyInternal(it, value, should_throw, store_origin, &found);
    if (found) return result;
  }

  if (!CheckContextualStoreToJSGlobalObject(it, should_throw)) {
    return Nothing<bool>();
  }
  return AddDataProperty(it, value, NONE, should_throw, store_origin);
}

Maybe<bool> Object::SetSuperProperty(LookupIterator* it, Handle<Object> value,
                                     StoreOrigin store_origin,
                                     Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();

  if (it->IsFound()) {
    bool found = true;
    Maybe<bool> result =
        SetPropertyInternal(it, value, should_throw, store_origin, &found);
    if (found) return result;
  }

  it->UpdateProtector();

  // The property either doesn't exist on the holder or exists there as a data
  // property.

  if (!IsJSReceiver(*it->GetReceiver())) {
    return WriteToReadOnlyProperty(it, value, should_throw);
  }
  Handle<JSReceiver> receiver = Cast<JSReceiver>(it->GetReceiver());

  // Note, the callers rely on the fact that this code is redoing the full own
  // lookup from scratch.
  LookupIterator own_lookup(isolate, receiver, it->GetKey(),
                            LookupIterator::OWN);
  for (;; own_lookup.Next()) {
    switch (own_lookup.state()) {
      case LookupIterator::ACCESS_CHECK:
        if (!own_lookup.HasAccess()) {
          return JSObject::SetPropertyWithFailedAccessCheck(&own_lookup, value,
                                                            should_throw);
        }
        continue;

      case LookupIterator::ACCESSOR:
        if (IsAccessorInfo(*own_lookup.GetAccessors())) {
          if (own_lookup.IsReadOnly()) {
            return WriteToReadOnlyProperty(&own_lookup, value, should_throw);
          }
          return Object::SetPropertyWithAccessor(&own_lookup, value,
                                                 should_throw);
        }
        [[fallthrough]];
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return RedefineIncompatibleProperty(isolate, it->GetName(), value,
                                            should_throw);

      case LookupIterator::DATA: {
        if (own_lookup.IsReadOnly()) {
          return WriteToReadOnlyProperty(&own_lookup, value, should_throw);
        }
        return SetDataProperty(&own_lookup, value);
      }

      case LookupIterator::INTERCEPTOR:
      case LookupIterator::JSPROXY: {
        PropertyDescriptor desc;
        Maybe<bool> owned =
            JSReceiver::GetOwnPropertyDescriptor(&own_lookup, &desc);
        MAYBE_RETURN(owned, Nothing<bool>());
        if (!owned.FromJust()) {
          // |own_lookup| might become outdated at this point anyway.
          // TODO(leszeks): Remove this restart since we don't really use the
          // lookup iterator after this.
          own_lookup.Restart();
          if (!CheckContextualStoreToJSGlobalObject(&own_lookup,
                                                    should_throw)) {
            return Nothing<bool>();
          }
          return JSReceiver::CreateDataProperty(isolate, receiver, it->GetKey(),
                                                value, should_throw);
        }
        if (PropertyDescriptor::IsAccessorDescriptor(&desc) ||
            !desc.writable()) {
          return RedefineIncompatibleProperty(isolate, it->GetName(), value,
                                              should_throw);
        }

        PropertyDescriptor value_desc;
        value_desc.set_value(Cast<JSAny>(value));
        return JSReceiver::DefineOwnProperty(isolate, receiver, it->GetName(),
                                             &value_desc, should_throw);
      }

      case LookupIterator::NOT_FOUND:
        if (!CheckContextualStoreToJSGlobalObject(&own_lookup, should_throw)) {
          return Nothing<bool>();
        }
        return AddDataProperty(&own_lookup, value, NONE, should_throw,
                               store_origin);

      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(it->isolate(), kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));

      case LookupIterator::TRANSITION:
        UNREACHABLE();
    }
    UNREACHABLE();
  }
}

Maybe<bool> Object::CannotCreateProperty(Isolate* isolate,
                                         Handle<JSAny> receiver,
                                         Handle<Object> name,
                                         DirectHandle<Object> value,
                                         Maybe<ShouldThrow> should_throw) {
  RETURN_FAILURE(
      isolate, GetShouldThrow(isolate, should_throw),
      NewTypeError(MessageTemplate::kStrictCannotCreateProperty, name,
                   Object::TypeOf(isolate, receiver), receiver));
}

Maybe<bool> Object::WriteToReadOnlyProperty(
    LookupIterator* it, DirectHandle<Object> value,
    Maybe<ShouldThrow> maybe_should_throw) {
  ShouldThrow should_throw = GetShouldThrow(it->isolate(), maybe_should_throw);
  if (it->IsFound() && !it->HolderIsReceiver()) {
    // "Override mistake" attempted, record a use count to track this per
    // v8:8175
    v8::Isolate::UseCounterFeature feature =
        should_throw == kThrowOnError
            ? v8::Isolate::kAttemptOverrideReadOnlyOnPrototypeStrict
            : v8::Isolate::kAttemptOverrideReadOnlyOnPrototypeSloppy;
    it->isolate()->CountUsage(feature);
  }
  return WriteToReadOnlyProperty(it->isolate(), it->GetReceiver(),
                                 it->GetName(), value, should_throw);
}

Maybe<bool> Object::WriteToReadOnlyProperty(Isolate* isolate,
                                            Handle<JSAny> receiver,
                                            Handle<Object> name,
                                            DirectHandle<Object> value,
                                            ShouldThrow should_throw) {
  RETURN_FAILURE(isolate, should_throw,
                 NewTypeError(MessageTemplate::kStrictReadOnlyProperty, name,
                              Object::TypeOf(isolate, receiver), receiver));
}

Maybe<bool> Object::RedefineIncompatibleProperty(
    Isolate* isolate, Handle<Object> name, DirectHandle<Object> value,
    Maybe<ShouldThrow> should_throw) {
  RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                 NewTypeError(MessageTemplate::kRedefineDisallowed, name));
}

Maybe<bool> Object::SetDataProperty(LookupIterator* it, Handle<Object> value) {
  Isolate* isolate = it->isolate();
  DCHECK_IMPLIES(IsJSProxy(*it->GetReceiver(), isolate),
                 it->GetName()->IsPrivateName());
  DCHECK_IMPLIES(!it->IsElement() && it->GetName()->IsPrivateName(),
                 it->state() == LookupIterator::DATA);
  Handle<JSReceiver> receiver = Cast<JSReceiver>(it->GetReceiver());

  // Store on the holder which may be hidden behind the receiver.
  DCHECK(it->HolderIsReceiverOrHiddenPrototype());

  Handle<Object> to_assign = value;
  // Convert the incoming value to a number for storing into typed arrays.
  if (it->IsElement() && IsJSObject(*receiver, isolate) &&
      Cast<JSObject>(*receiver)->HasTypedArrayOrRabGsabTypedArrayElements(
          isolate)) {
    auto receiver_ta = Cast<JSTypedArray>(receiver);
    ElementsKind elements_kind = Cast<JSObject>(*receiver)->GetElementsKind();
    if (IsBigIntTypedArrayElementsKind(elements_kind)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, to_assign,
                                       BigInt::FromObject(isolate, value),
                                       Nothing<bool>());
      if (V8_UNLIKELY(receiver_ta->IsDetachedOrOutOfBounds() ||
                      it->index() >= receiver_ta->GetLength())) {
        return Just(true);
      }
    
"""


```