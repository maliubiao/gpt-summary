Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/js-objects.cc`. I need to analyze the code and list its capabilities. The prompt also includes specific instructions related to Torque files, JavaScript examples, logic inference, common programming errors, and its position in a larger sequence.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:**  Read through the code, focusing on the function names and the operations they perform. Look for keywords like `DefineOwnProperty`, `TestIntegrityLevel`, `PreventExtensions`, `IsExtensible`, `ApplyAttributesToDictionary`, `FastPropertyAt`, `DictionaryPropertyAt`, `HasEnumerableElements`, `DefineOwnAccessorIgnoreAttributes`, `SetAccessor`, `CheckIfCanDefineAsConfigurable`, `SlowReverseLookup`, `MakePrototypesFast`, and `OptimizeAsPrototype`. These names give strong clues about the code's purpose.

2. **Group Related Functions:** Notice patterns in the function names and their actions. For example, functions dealing with "integrity level" are likely related to sealing and freezing objects. Functions involving "DefineOwn" are about property definition.

3. **Address Specific Instructions:**
    * **Torque:** Check if the filename ends with `.tq`. In this case, it doesn't.
    * **JavaScript Relevance:** For functionalities related to JavaScript, provide illustrative examples. This will likely involve concepts like defining properties, preventing extensions, sealing, freezing, accessing properties, and working with prototypes.
    * **Logic Inference:** Look for conditional statements and loops that perform specific logic. Identify potential inputs and the corresponding outputs based on the code flow.
    * **Common Errors:** Think about how the operations in the code might lead to common JavaScript errors. For instance, attempting to define a non-configurable property after an object is sealed or frozen.
    * **Part of a Sequence:** The prompt mentions "Part 6 of 8". Without the other parts, I'll focus on the functionality within this specific snippet and avoid speculating on how it fits into the larger file.

4. **Synthesize the Summary:** Combine the identified functionalities into a concise summary.

**Pre-computation/Analysis:**

* **Property Definition:** The code includes functions for defining properties with specific attributes (configurable, writable, enumerable). It handles both data properties and accessors (getters/setters).
* **Object Integrity:**  The code deals with the concepts of preventing extensions, sealing, and freezing objects. It includes checks for whether these operations can be performed and functions to test the current integrity level.
* **Property Access:**  There are functions to access properties efficiently (fast properties) and for dictionary-based properties.
* **Element Handling:** The code considers how elements (indexed properties) are handled, including different element kinds (packed, holey, dictionary).
* **Prototypes:** Functions related to making prototypes "fast" suggest optimizations for prototype chains.
* **Error Handling:** The code uses `Maybe` and `RETURN_ON_EXCEPTION_VALUE` indicating error handling mechanisms.

**Drafting the Summary (Internal thought process):**

"This part of the `js-objects.cc` file focuses on several key aspects of how JavaScript objects are managed within V8. It includes functions for defining object properties, considering attributes like configurability, writability, and enumerability. A significant portion deals with controlling the structure of objects through operations like preventing extensions, sealing, and freezing, with checks for whether these operations are valid. The code also provides ways to access object properties, distinguishing between fast property access and access for objects with dictionary-based properties. Furthermore, it touches on how elements (indexed properties) are handled, including considerations for different storage types. Finally, there are functions related to optimizing object prototypes to improve performance."

**Refining the Summary and Adding Specifics:**

Now, integrate the specific instructions and JavaScript examples.

* **Torque:** Explicitly mention it's not a Torque file.
* **JavaScript Examples:** Create short, clear examples to illustrate concepts like `Object.defineProperty`, `Object.preventExtensions`, `Object.seal`, `Object.freeze`, and property access.
* **Logic Inference:** Choose a straightforward example, like the `TestIntegrityLevel` functions, and show a simple input and expected output.
* **Common Errors:**  Provide examples of attempting to modify sealed/frozen objects.

This structured approach will lead to a comprehensive and accurate summary that addresses all aspects of the user's request.
```cpp
an_define = JSObject::CheckIfCanDefineAsConfigurable(
      isolate, &it, value, should_throw);
  if (can_define.IsNothing() || !can_define.FromJust()) {
    return can_define;
  }

  RETURN_ON_EXCEPTION_VALUE(isolate,
                            DefineOwnPropertyIgnoreAttributes(&it, value, NONE),
                            Nothing<bool>());

  return Just(true);
}

namespace {

template <typename Dictionary>
bool TestDictionaryPropertiesIntegrityLevel(Tagged<Dictionary> dict,
                                            ReadOnlyRoots roots,
                                            PropertyAttributes level) {
  DCHECK(level == SEALED || level == FROZEN);

  for (InternalIndex i : dict->IterateEntries()) {
    Tagged<Object> key;
    if (!dict->ToKey(roots, i, &key)) continue;
    if (Object::FilterKey(key, ALL_PROPERTIES)) continue;
    PropertyDetails details = dict->DetailsAt(i);
    if (details.IsConfigurable()) return false;
    if (level == FROZEN && details.kind() == PropertyKind::kData &&
        !details.IsReadOnly()) {
      return false;
    }
  }
  return true;
}

bool TestFastPropertiesIntegrityLevel(Tagged<Map> map,
                                      PropertyAttributes level) {
  DCHECK(level == SEALED || level == FROZEN);
  DCHECK(!IsCustomElementsReceiverMap(map));
  DCHECK(!map->is_dictionary_map());

  Tagged<DescriptorArray> descriptors = map->instance_descriptors();
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    if (descriptors->GetKey(i)->IsPrivate()) continue;
    PropertyDetails details = descriptors->GetDetails(i);
    if (details.IsConfigurable()) return false;
    if (level == FROZEN && details.kind() == PropertyKind::kData &&
        !details.IsReadOnly()) {
      return false;
    }
  }
  return true;
}

bool TestPropertiesIntegrityLevel(Tagged<JSObject> object,
                                  PropertyAttributes level) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));

  if (object->HasFastProperties()) {
    return TestFastPropertiesIntegrityLevel(object->map(), level);
  }

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    return TestDictionaryPropertiesIntegrityLevel(
        object->property_dictionary_swiss(), object->GetReadOnlyRoots(), level);
  } else {
    return TestDictionaryPropertiesIntegrityLevel(
        object->property_dictionary(), object->GetReadOnlyRoots(), level);
  }
}

bool TestElementsIntegrityLevel(Isolate* isolate, Tagged<JSObject> object,
                                PropertyAttributes level) {
  DCHECK(!object->HasSloppyArgumentsElements());

  ElementsKind kind = object->GetElementsKind();

  if (IsDictionaryElementsKind(kind)) {
    return TestDictionaryPropertiesIntegrityLevel(
        Cast<NumberDictionary>(object->elements()), object->GetReadOnlyRoots(),
        level);
  }
  if (IsTypedArrayOrRabGsabTypedArrayElementsKind(kind)) {
    if (level == FROZEN && Cast<JSArrayBufferView>(object)->byte_length() > 0) {
      return false;  // TypedArrays with elements can't be frozen.
    }
    return TestPropertiesIntegrityLevel(object, level);
  }
  if (IsFrozenElementsKind(kind)) return true;
  if (IsSealedElementsKind(kind) && level != FROZEN) return true;
  if (IsNonextensibleElementsKind(kind) && level == NONE) return true;

  ElementsAccessor* accessor = ElementsAccessor::ForKind(kind);
  // Only DICTIONARY_ELEMENTS and SLOW_SLOPPY_ARGUMENTS_ELEMENTS have
  // PropertyAttributes so just test if empty
  return accessor->NumberOfElements(isolate, object) == 0;
}

bool FastTestIntegrityLevel(Isolate* isolate, Tagged<JSObject> object,
                            PropertyAttributes level) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));

  return !object->map()->is_extensible() &&
         TestElementsIntegrityLevel(isolate, object, level) &&
         TestPropertiesIntegrityLevel(object, level);
}

}  // namespace

Maybe<bool> JSObject::TestIntegrityLevel(Isolate* isolate,
                                         Handle<JSObject> object,
                                         IntegrityLevel level) {
  if (!IsCustomElementsReceiverMap(object->map()) &&
      !object->HasSloppyArgumentsElements()) {
    return Just(FastTestIntegrityLevel(isolate, *object, level));
  }
  return GenericTestIntegrityLevel(isolate, Cast<JSReceiver>(object), level);
}

Maybe<bool> JSObject::PreventExtensions(Isolate* isolate,
                                        Handle<JSObject> object,
                                        ShouldThrow should_throw) {
  if (!object->HasSloppyArgumentsElements()) {
    return PreventExtensionsWithTransition<NONE>(isolate, object, should_throw);
  }

  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(object),
                              Nothing<bool>());
    UNREACHABLE();
  }

  if (!object->map()->is_extensible()) return Just(true);

  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, object);
    if (iter.IsAtEnd()) return Just(true);
    DCHECK(IsJSGlobalObject(*PrototypeIterator::GetCurrent(iter)));
    return PreventExtensions(
        isolate, PrototypeIterator::GetCurrent<JSObject>(iter), should_throw);
  }

  if (object->map()->has_named_interceptor() ||
      object->map()->has_indexed_interceptor()) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kCannotPreventExt));
  }

  DCHECK(!object->HasTypedArrayOrRabGsabTypedArrayElements());

  // Normalize fast elements.
  DirectHandle<NumberDictionary> dictionary = NormalizeElements(object);
  DCHECK(object->HasDictionaryElements() || object->HasSlowArgumentsElements());

  // Make sure that we never go back to fast case.
  if (*dictionary != ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
    object->RequireSlowElements(*dictionary);
  }

  // Do a map transition, other objects with this map may still
  // be extensible.
  // TODO(adamk): Extend the NormalizedMapCache to handle non-extensible maps.
  DirectHandle<Map> new_map =
      Map::Copy(isolate, handle(object->map(), isolate), "PreventExtensions");

  new_map->set_is_extensible(false);
  JSObject::MigrateToMap(isolate, object, new_map);
  DCHECK(!object->map()->is_extensible());

  return Just(true);
}

bool JSObject::IsExtensible(Isolate* isolate, Handle<JSObject> object) {
  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    return true;
  }
  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, *object);
    if (iter.IsAtEnd()) return false;
    DCHECK(IsJSGlobalObject(iter.GetCurrent()));
    return iter.GetCurrent<JSObject>()->map()->is_extensible();
  }
  return object->map()->is_extensible();
}

// static
MaybeHandle<Object> JSObject::ReadFromOptionsBag(Handle<Object> options,
                                                 Handle<String> option_name,
                                                 Isolate* isolate) {
  if (IsJSReceiver(*options)) {
    Handle<JSReceiver> js_options = Cast<JSReceiver>(options);
    return JSObject::GetProperty(isolate, js_options, option_name);
  }
  return MaybeHandle<Object>(isolate->factory()->undefined_value());
}

template <typename Dictionary>
void JSObject::ApplyAttributesToDictionary(
    Isolate* isolate, ReadOnlyRoots roots, Handle<Dictionary> dictionary,
    const PropertyAttributes attributes) {
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> k;
    if (!dictionary->ToKey(roots, i, &k)) continue;
    if (Object::FilterKey(k, ALL_PROPERTIES)) continue;
    PropertyDetails details = dictionary->DetailsAt(i);
    int attrs = attributes;
    // READ_ONLY is an invalid attribute for JS setters/getters.
    if ((attributes & READ_ONLY) && details.kind() == PropertyKind::kAccessor) {
      Tagged<Object> v = dictionary->ValueAt(i);
      if (IsAccessorPair(v)) attrs &= ~READ_ONLY;
    }
    details = details.CopyAddAttributes(PropertyAttributesFromInt(attrs));
    dictionary->DetailsAtPut(i, details);
  }
}

template void JSObject::ApplyAttributesToDictionary(
    Isolate* isolate, ReadOnlyRoots roots, Handle<NumberDictionary> dictionary,
    const PropertyAttributes attributes);

Handle<NumberDictionary> CreateElementDictionary(Isolate* isolate,
                                                 Handle<JSObject> object) {
  Handle<NumberDictionary> new_element_dictionary;
  if (!object->HasTypedArrayOrRabGsabTypedArrayElements() &&
      !object->HasDictionaryElements() &&
      !object->HasSlowStringWrapperElements()) {
    int length = IsJSArray(*object)
                     ? Smi::ToInt(Cast<JSArray>(object)->length())
                     : object->elements()->length();
    new_element_dictionary =
        length == 0 ? isolate->factory()->empty_slow_element_dictionary()
                    : object->GetElementsAccessor()->Normalize(object);
  }
  return new_element_dictionary;
}

template <PropertyAttributes attrs>
Maybe<bool> JSObject::PreventExtensionsWithTransition(
    Isolate* isolate, Handle<JSObject> object, ShouldThrow should_throw) {
  static_assert(attrs == NONE || attrs == SEALED || attrs == FROZEN);

  // Sealing/freezing sloppy arguments or namespace objects should be handled
  // elsewhere.
  DCHECK(!object->HasSloppyArgumentsElements());
  DCHECK_IMPLIES(IsJSModuleNamespace(*object), attrs == NONE);

  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(object),
                              Nothing<bool>());
    UNREACHABLE();
  }

  if (attrs == NONE && !object->map()->is_extensible()) {
    return Just(true);
  }

  {
    ElementsKind old_elements_kind = object->map()->elements_kind();
    if (IsFrozenElementsKind(old_elements_kind)) return Just(true);
    if (attrs != FROZEN && IsSealedElementsKind(old_elements_kind)) {
      return Just(true);
    }
  }

  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, object);
    if (iter.IsAtEnd()) return Just(true);
    DCHECK(IsJSGlobalObject(*PrototypeIterator::GetCurrent(iter)));
    return PreventExtensionsWithTransition<attrs>(
        isolate, PrototypeIterator::GetCurrent<JSObject>(iter), should_throw);
  }

  // Shared objects are designed to have fixed layout, i.e. their maps are
  // effectively immutable. They are constructed seal, but the semantics of
  // ordinary ECMAScript objects allow sealed to be upgraded to frozen. This
  // upgrade violates the fixed layout invariant and is disallowed.
  if (IsAlwaysSharedSpaceJSObject(*object)) {
    DCHECK(FastTestIntegrityLevel(isolate, *object, SEALED));
    if (attrs != FROZEN) return Just(true);
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kCannotFreeze));
  }

  if (object->map()->has_named_interceptor() ||
      object->map()->has_indexed_interceptor() ||
      (object->HasTypedArrayOrRabGsabTypedArrayElements() &&
       Cast<JSTypedArray>(*object)->IsVariableLength())) {
    MessageTemplate message = MessageTemplate::kNone;
    switch (attrs) {
      case NONE:
        message = MessageTemplate::kCannotPreventExt;
        break;

      case SEALED:
        message = MessageTemplate::kCannotSeal;
        break;

      case FROZEN:
        message = MessageTemplate::kCannotFreeze;
        break;
    }
    RETURN_FAILURE(isolate, should_throw, NewTypeError(message));
  }

  Handle<Symbol> transition_marker;
  if (attrs == NONE) {
    transition_marker = isolate->factory()->nonextensible_symbol();
  } else if (attrs == SEALED) {
    transition_marker = isolate->factory()->sealed_symbol();
  } else {
    DCHECK(attrs == FROZEN);
    transition_marker = isolate->factory()->frozen_symbol();
  }

  // Currently, there are only have sealed/frozen Object element kinds and
  // Map::MigrateToMap doesn't handle properties' attributes reconfiguring and
  // elements kind change in one go. If seal or freeze with Smi or Double
  // elements kind, we will transition to Object elements kind first to make
  // sure of valid element access.
  if (v8_flags.enable_sealed_frozen_elements_kind) {
    switch (object->map()->elements_kind()) {
      case PACKED_SMI_ELEMENTS:
      case PACKED_DOUBLE_ELEMENTS:
        JSObject::TransitionElementsKind(object, PACKED_ELEMENTS);
        break;
      case HOLEY_SMI_ELEMENTS:
      case HOLEY_DOUBLE_ELEMENTS:
        JSObject::TransitionElementsKind(object, HOLEY_ELEMENTS);
        break;
      default:
        break;
    }
  }

  // Make sure we only use this element dictionary in case we can't transition
  // to sealed, frozen elements kind.
  Handle<NumberDictionary> new_element_dictionary;

  Handle<Map> old_map(object->map(), isolate);
  old_map = Map::Update(isolate, old_map);
  Handle<Map> transition_map;
  MaybeHandle<Map> maybe_transition_map =
      TransitionsAccessor::SearchSpecial(isolate, old_map, *transition_marker);
  if (maybe_transition_map.ToHandle(&transition_map)) {
    DCHECK(transition_map->has_dictionary_elements() ||
           transition_map->has_typed_array_or_rab_gsab_typed_array_elements() ||
           transition_map->elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS ||
           transition_map->has_any_nonextensible_elements());
    DCHECK(!transition_map->is_extensible());
    if (!transition_map->has_any_nonextensible_elements()) {
      new_element_dictionary = CreateElementDictionary(isolate, object);
    }
    JSObject::MigrateToMap(isolate, object, transition_map);
  } else if (TransitionsAccessor::CanHaveMoreTransitions(isolate, old_map)) {
    // Create a new descriptor array with the appropriate property attributes
    DirectHandle<Map> new_map = Map::CopyForPreventExtensions(
        isolate, old_map, attrs, transition_marker, "CopyForPreventExtensions");
    if (!new_map->has_any_nonextensible_elements()) {
      new_element_dictionary = CreateElementDictionary(isolate, object);
    }
    JSObject::MigrateToMap(isolate, object, new_map);
  } else {
    DCHECK(old_map->is_dictionary_map() || !old_map->is_prototype_map());
    // Slow path: need to normalize properties for safety
    NormalizeProperties(isolate, object, CLEAR_INOBJECT_PROPERTIES, 0,
                        "SlowPreventExtensions");

    // Create a new map, since other objects with this map may be extensible.
    // TODO(adamk): Extend the NormalizedMapCache to handle non-extensible maps.
    DirectHandle<Map> new_map =
        Map::Copy(isolate, handle(object->map(), isolate),
                  "SlowCopyForPreventExtensions");
    new_map->set_is_extensible(false);
    new_element_dictionary = CreateElementDictionary(isolate, object);
    if (!new_element_dictionary.is_null()) {
      ElementsKind new_kind =
          IsStringWrapperElementsKind(old_map->elements_kind())
              ? SLOW_STRING_WRAPPER_ELEMENTS
              : DICTIONARY_ELEMENTS;
      new_map->set_elements_kind(new_kind);
    }
    JSObject::MigrateToMap(isolate, object, new_map);

    if (attrs != NONE) {
      ReadOnlyRoots roots(isolate);
      if (IsJSGlobalObject(*object)) {
        Handle<GlobalDictionary> dictionary(
            Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
            isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      } else if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        Handle<SwissNameDictionary> dictionary(
            object->property_dictionary_swiss(), isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      } else {
        Handle<NameDictionary> dictionary(object->property_dictionary(),
                                          isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      }
    }
  }

  if (object->map()->has_any_nonextensible_elements()) {
    DCHECK(new_element_dictionary.is_null());
    return Just(true);
  }

  // Both seal and preventExtensions always go through without modifications to
  // typed array elements if the typed array is fixed length. Freeze works only
  // if there are no actual elements.
  if (object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    DCHECK(new_element_dictionary.is_null());
    if (attrs == FROZEN && Cast<JSTypedArray>(*object)->GetLength() > 0) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kCannotFreezeArrayBufferView));
      return Nothing<bool>();
    }
    return Just(true);
  }

  DCHECK(object->map()->has_dictionary_elements() ||
         object->map()->elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS);
  if (!new_element_dictionary.is_null()) {
    object->set_elements(*new_element_dictionary);
  }

  if (object->elements() !=
      ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
    Handle<NumberDictionary> dictionary(object->element_dictionary(), isolate);
    // Make sure we never go back to the fast case
    object->RequireSlowElements(*dictionary);
    if (attrs != NONE) {
      JSObject::ApplyAttributesToDictionary(isolate, ReadOnlyRoots(isolate),
                                            dictionary, attrs);
    }
  }

  return Just(true);
}

Handle<JSAny> JSObject::FastPropertyAt(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Representation representation,
                                       FieldIndex index) {
  Handle<JSAny> raw_value(object->RawFastPropertyAt(index), isolate);
  return Object::WrapForRead(isolate, raw_value, representation);
}

Handle<JSAny> JSObject::FastPropertyAt(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Representation representation,
                                       FieldIndex index, SeqCstAccessTag tag) {
  Handle<JSAny> raw_value(object->RawFastPropertyAt(index, tag), isolate);
  return Object::WrapForRead(isolate, raw_value, representation);
}

// static
Handle<Object> JSObject::DictionaryPropertyAt(Isolate* isolate,
                                              DirectHandle<JSObject> object,
                                              InternalIndex dict_index) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Tagged<SwissNameDictionary> dict = object->property_dictionary_swiss();
    return handle(dict->ValueAt(dict_index), isolate);
  } else {
    Tagged<NameDictionary> dict = object->property_dictionary();
    return handle(dict->ValueAt(dict_index), isolate);
  }
}

// static
std::optional<Tagged<Object>> JSObject::DictionaryPropertyAt(
    DirectHandle<JSObject> object, InternalIndex dict_index, Heap* heap) {
  Tagged<Object> backing_store = object->raw_properties_or_hash(kRelaxedLoad);
  if (!IsHeapObject(backing_store)) return {};
  if (heap->IsPendingAllocation(Cast<HeapObject>(backing_store))) return {};

  if (!IsPropertyDictionary(backing_store)) return {};
  std::optional<Tagged<Object>> maybe_obj =
      Cast<PropertyDictionary>(backing_store)->TryValueAt(dict_index);

  if (!maybe_obj) return {};
  return maybe_obj.value();
}

// TODO(cbruni/jkummerow): Consider moving this into elements.cc.
bool JSObject::HasEnumerableElements() {
  // TODO(cbruni): cleanup
  Tagged<JSObject> object = *this;
  switch (object->GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS: {
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : object->elements()->length();
      return length > 0;
    }
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS: {
      Tagged<FixedArray> elements = Cast<FixedArray>(object->elements());
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : elements->length();
      Isolate* isolate = GetIsolate();
      for (int i = 0; i < length; i++) {
        if (!elements->is_the_hole(isolate, i)) return true;
      }
      return false;
    }
    case HOLEY_DOUBLE_ELEMENTS: {
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : object->elements()->length();
      // Zero-length arrays would use the empty FixedArray...
      if (length == 0) return false;
      // ...so only cast to FixedDoubleArray otherwise.
      Tagged<FixedDoubleArray> elements =
          Cast<FixedDoubleArray>(object->elements());
      for (int i = 0; i < length; i++) {
        if (!elements->is_the_hole(i)) return true;
      }
      return false;
    }
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE) {
        size_t length = Cast<JSTypedArray>(object)->length();
        return length > 0;
      }

      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      {
        size_t length = Cast<JSTypedArray>(object)->GetLength();
        return length > 0;
      }
    case DICTIONARY_ELEMENTS: {
      Tagged<NumberDictionary> elements =
          Cast<NumberDictionary>(object->elements());
      return elements->NumberOfEnumerableProperties() > 0;
    }
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      // We're approximating non-empty arguments objects here.
      return true;
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
      if (Cast<String>(Cast<JSPrimitiveWrapper>(object)->value())->length() >
          0) {
        return true;
      }
      return object->elements()->length() > 0;
    case WASM_ARRAY_ELEMENTS:
      UNIMPLEMENTED();

    case NO_ELEMENTS:
      return false;
  }
  UNREACHABLE();
}

MaybeHandle<Object> JSObject::DefineOwnAccessorIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, DirectHandle<Object> getter,
    DirectHandle<Object> setter, PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  return DefineOwnAccessorIgnoreAttributes(&it, getter, setter, attributes);
}

MaybeHandle<Object> JSObject::DefineOwnAccessorIgnoreAttributes(
    LookupIterator* it, DirectHandle<Object> getter,
    DirectHandle<Object> setter, PropertyAttributes attributes) {
  Isolate* isolate = it->isolate();

  it->UpdateProtector();

  while (it->state() == LookupIterator::ACCESS_CHECK) {
    if (!it->HasAccess()) {
      RETURN_ON_EXCEPTION(
          isolate, isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()));
      UNREACHABLE();
    }
    it->Next();
  }

  auto object = Cast<JSObject>(it->GetReceiver());
  // Ignore accessors on typed arrays.
  if (it->IsElement() && object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    return it->factory()->undefined_value();
  }

  DCHECK(IsCallable(*getter) || IsUndefined(*getter, isolate) ||
         IsNull(*getter, isolate) || IsFunctionTemplateInfo(*getter));
  DCHECK(IsCallable(*setter) || IsUndefined(*setter, isolate) ||
         IsNull(*setter, isolate) || IsFunctionTemplateInfo(*setter));
  it->TransitionToAccessorProperty(getter, setter, attributes);

  return isolate->factory()->undefined_value();
}

MaybeHandle<Object> JSObject::SetAccessor(Handle<JSObject> object,
                                          Handle<Name> name,
                                          Handle<AccessorInfo> info,
                                          PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);

  // Duplicate ACCESS_CHECK outside of GetPropertyAttributes for the case that
  // the FailedAccessCheckCallbackFunction doesn't throw an exception.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    if (!it.HasAccess()) {
      RETURN_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(object));
      UNREACHABLE();
    }
    it.Next();
  }

  // Ignore accessors on typed arrays.
  if (it.IsElement() && object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    return it.factory()->undefined_value();
  }

  Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
      isolate, &it, info, Nothing<ShouldThrow>());
  MAYBE_RETURN_NULL(can_define);
  if (!can_define.FromJust()) return it.factory()->undefined_value();

  it.TransitionToAccessorPair(info, attributes);

  return object;
}

// static
Maybe<bool> JSObject::CheckIfCanDefineAsConfigurable(
    Isolate* isolate, LookupIterator* it, DirectHandle<Object> value,
    Maybe<ShouldThrow> should_throw) {
  DCHECK(IsJSObject(*it->GetReceiver()));
  if (it->IsFound()) {
    Maybe<PropertyAttributes> attributes = GetPropertyAttributes(it);
    MAYBE_RETURN(attributes, Nothing<bool>());
    if (attributes.FromJust() != ABSENT) {
      if ((attributes.FromJust() & DONT_DELETE) != 0) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed, it->GetName()));
      }
      return Just(true);
    }
    // Property does not exist, check object extensibility.
  }
  if (!JSObject::IsExtensible(isolate, Cast<JSObject>(it->GetReceiver()))) {
    RETURN_FAILURE(
        isolate, GetShouldThrow(isolate, should_throw),
        NewTypeError(MessageTemplate::kDefineDisallowed, it->GetName()));
  }
  return Just(true);
}

Tagged<Object> JSObject::SlowReverseLookup(Tagged<Object> value) {
  if (HasFastProperties()) {
    Tagged<DescriptorArray> descs = map()->instance_descriptors();
    bool value_is_number = IsNumber(value);
    for (InternalIndex i : map()->IterateOwnDescriptors()) {
      PropertyDetails details = descs->GetDetails(i);
      if (details.location() == PropertyLocation::kField) {
        DCHECK_EQ(PropertyKind::kData, details.kind());
        FieldIndex field_index = FieldIndex::ForDetails(map(), details);
        Tagged<Object> property = RawFastPropertyAt(field_index);
        if (field_index.is_double()) {
          DCHECK(IsHeapNumber(property));
          if (value_is_number && Cast<HeapNumber>(property)->value() ==
                                     Object::NumberValue(Cast<Number>(value))) {
            return descs->GetKey(i);
          }
        } else if (property
### 提示词
```
这是目录为v8/src/objects/js-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
an_define = JSObject::CheckIfCanDefineAsConfigurable(
      isolate, &it, value, should_throw);
  if (can_define.IsNothing() || !can_define.FromJust()) {
    return can_define;
  }

  RETURN_ON_EXCEPTION_VALUE(isolate,
                            DefineOwnPropertyIgnoreAttributes(&it, value, NONE),
                            Nothing<bool>());

  return Just(true);
}

namespace {

template <typename Dictionary>
bool TestDictionaryPropertiesIntegrityLevel(Tagged<Dictionary> dict,
                                            ReadOnlyRoots roots,
                                            PropertyAttributes level) {
  DCHECK(level == SEALED || level == FROZEN);

  for (InternalIndex i : dict->IterateEntries()) {
    Tagged<Object> key;
    if (!dict->ToKey(roots, i, &key)) continue;
    if (Object::FilterKey(key, ALL_PROPERTIES)) continue;
    PropertyDetails details = dict->DetailsAt(i);
    if (details.IsConfigurable()) return false;
    if (level == FROZEN && details.kind() == PropertyKind::kData &&
        !details.IsReadOnly()) {
      return false;
    }
  }
  return true;
}

bool TestFastPropertiesIntegrityLevel(Tagged<Map> map,
                                      PropertyAttributes level) {
  DCHECK(level == SEALED || level == FROZEN);
  DCHECK(!IsCustomElementsReceiverMap(map));
  DCHECK(!map->is_dictionary_map());

  Tagged<DescriptorArray> descriptors = map->instance_descriptors();
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    if (descriptors->GetKey(i)->IsPrivate()) continue;
    PropertyDetails details = descriptors->GetDetails(i);
    if (details.IsConfigurable()) return false;
    if (level == FROZEN && details.kind() == PropertyKind::kData &&
        !details.IsReadOnly()) {
      return false;
    }
  }
  return true;
}

bool TestPropertiesIntegrityLevel(Tagged<JSObject> object,
                                  PropertyAttributes level) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));

  if (object->HasFastProperties()) {
    return TestFastPropertiesIntegrityLevel(object->map(), level);
  }

  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    return TestDictionaryPropertiesIntegrityLevel(
        object->property_dictionary_swiss(), object->GetReadOnlyRoots(), level);
  } else {
    return TestDictionaryPropertiesIntegrityLevel(
        object->property_dictionary(), object->GetReadOnlyRoots(), level);
  }
}

bool TestElementsIntegrityLevel(Isolate* isolate, Tagged<JSObject> object,
                                PropertyAttributes level) {
  DCHECK(!object->HasSloppyArgumentsElements());

  ElementsKind kind = object->GetElementsKind();

  if (IsDictionaryElementsKind(kind)) {
    return TestDictionaryPropertiesIntegrityLevel(
        Cast<NumberDictionary>(object->elements()), object->GetReadOnlyRoots(),
        level);
  }
  if (IsTypedArrayOrRabGsabTypedArrayElementsKind(kind)) {
    if (level == FROZEN && Cast<JSArrayBufferView>(object)->byte_length() > 0) {
      return false;  // TypedArrays with elements can't be frozen.
    }
    return TestPropertiesIntegrityLevel(object, level);
  }
  if (IsFrozenElementsKind(kind)) return true;
  if (IsSealedElementsKind(kind) && level != FROZEN) return true;
  if (IsNonextensibleElementsKind(kind) && level == NONE) return true;

  ElementsAccessor* accessor = ElementsAccessor::ForKind(kind);
  // Only DICTIONARY_ELEMENTS and SLOW_SLOPPY_ARGUMENTS_ELEMENTS have
  // PropertyAttributes so just test if empty
  return accessor->NumberOfElements(isolate, object) == 0;
}

bool FastTestIntegrityLevel(Isolate* isolate, Tagged<JSObject> object,
                            PropertyAttributes level) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));

  return !object->map()->is_extensible() &&
         TestElementsIntegrityLevel(isolate, object, level) &&
         TestPropertiesIntegrityLevel(object, level);
}

}  // namespace

Maybe<bool> JSObject::TestIntegrityLevel(Isolate* isolate,
                                         Handle<JSObject> object,
                                         IntegrityLevel level) {
  if (!IsCustomElementsReceiverMap(object->map()) &&
      !object->HasSloppyArgumentsElements()) {
    return Just(FastTestIntegrityLevel(isolate, *object, level));
  }
  return GenericTestIntegrityLevel(isolate, Cast<JSReceiver>(object), level);
}

Maybe<bool> JSObject::PreventExtensions(Isolate* isolate,
                                        Handle<JSObject> object,
                                        ShouldThrow should_throw) {
  if (!object->HasSloppyArgumentsElements()) {
    return PreventExtensionsWithTransition<NONE>(isolate, object, should_throw);
  }

  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(object),
                              Nothing<bool>());
    UNREACHABLE();
  }

  if (!object->map()->is_extensible()) return Just(true);

  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, object);
    if (iter.IsAtEnd()) return Just(true);
    DCHECK(IsJSGlobalObject(*PrototypeIterator::GetCurrent(iter)));
    return PreventExtensions(
        isolate, PrototypeIterator::GetCurrent<JSObject>(iter), should_throw);
  }

  if (object->map()->has_named_interceptor() ||
      object->map()->has_indexed_interceptor()) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kCannotPreventExt));
  }

  DCHECK(!object->HasTypedArrayOrRabGsabTypedArrayElements());

  // Normalize fast elements.
  DirectHandle<NumberDictionary> dictionary = NormalizeElements(object);
  DCHECK(object->HasDictionaryElements() || object->HasSlowArgumentsElements());

  // Make sure that we never go back to fast case.
  if (*dictionary != ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
    object->RequireSlowElements(*dictionary);
  }

  // Do a map transition, other objects with this map may still
  // be extensible.
  // TODO(adamk): Extend the NormalizedMapCache to handle non-extensible maps.
  DirectHandle<Map> new_map =
      Map::Copy(isolate, handle(object->map(), isolate), "PreventExtensions");

  new_map->set_is_extensible(false);
  JSObject::MigrateToMap(isolate, object, new_map);
  DCHECK(!object->map()->is_extensible());

  return Just(true);
}

bool JSObject::IsExtensible(Isolate* isolate, Handle<JSObject> object) {
  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    return true;
  }
  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, *object);
    if (iter.IsAtEnd()) return false;
    DCHECK(IsJSGlobalObject(iter.GetCurrent()));
    return iter.GetCurrent<JSObject>()->map()->is_extensible();
  }
  return object->map()->is_extensible();
}

// static
MaybeHandle<Object> JSObject::ReadFromOptionsBag(Handle<Object> options,
                                                 Handle<String> option_name,
                                                 Isolate* isolate) {
  if (IsJSReceiver(*options)) {
    Handle<JSReceiver> js_options = Cast<JSReceiver>(options);
    return JSObject::GetProperty(isolate, js_options, option_name);
  }
  return MaybeHandle<Object>(isolate->factory()->undefined_value());
}

template <typename Dictionary>
void JSObject::ApplyAttributesToDictionary(
    Isolate* isolate, ReadOnlyRoots roots, Handle<Dictionary> dictionary,
    const PropertyAttributes attributes) {
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> k;
    if (!dictionary->ToKey(roots, i, &k)) continue;
    if (Object::FilterKey(k, ALL_PROPERTIES)) continue;
    PropertyDetails details = dictionary->DetailsAt(i);
    int attrs = attributes;
    // READ_ONLY is an invalid attribute for JS setters/getters.
    if ((attributes & READ_ONLY) && details.kind() == PropertyKind::kAccessor) {
      Tagged<Object> v = dictionary->ValueAt(i);
      if (IsAccessorPair(v)) attrs &= ~READ_ONLY;
    }
    details = details.CopyAddAttributes(PropertyAttributesFromInt(attrs));
    dictionary->DetailsAtPut(i, details);
  }
}

template void JSObject::ApplyAttributesToDictionary(
    Isolate* isolate, ReadOnlyRoots roots, Handle<NumberDictionary> dictionary,
    const PropertyAttributes attributes);

Handle<NumberDictionary> CreateElementDictionary(Isolate* isolate,
                                                 Handle<JSObject> object) {
  Handle<NumberDictionary> new_element_dictionary;
  if (!object->HasTypedArrayOrRabGsabTypedArrayElements() &&
      !object->HasDictionaryElements() &&
      !object->HasSlowStringWrapperElements()) {
    int length = IsJSArray(*object)
                     ? Smi::ToInt(Cast<JSArray>(object)->length())
                     : object->elements()->length();
    new_element_dictionary =
        length == 0 ? isolate->factory()->empty_slow_element_dictionary()
                    : object->GetElementsAccessor()->Normalize(object);
  }
  return new_element_dictionary;
}

template <PropertyAttributes attrs>
Maybe<bool> JSObject::PreventExtensionsWithTransition(
    Isolate* isolate, Handle<JSObject> object, ShouldThrow should_throw) {
  static_assert(attrs == NONE || attrs == SEALED || attrs == FROZEN);

  // Sealing/freezing sloppy arguments or namespace objects should be handled
  // elsewhere.
  DCHECK(!object->HasSloppyArgumentsElements());
  DCHECK_IMPLIES(IsJSModuleNamespace(*object), attrs == NONE);

  if (IsAccessCheckNeeded(*object) &&
      !isolate->MayAccess(isolate->native_context(), object)) {
    RETURN_ON_EXCEPTION_VALUE(isolate, isolate->ReportFailedAccessCheck(object),
                              Nothing<bool>());
    UNREACHABLE();
  }

  if (attrs == NONE && !object->map()->is_extensible()) {
    return Just(true);
  }

  {
    ElementsKind old_elements_kind = object->map()->elements_kind();
    if (IsFrozenElementsKind(old_elements_kind)) return Just(true);
    if (attrs != FROZEN && IsSealedElementsKind(old_elements_kind)) {
      return Just(true);
    }
  }

  if (IsJSGlobalProxy(*object)) {
    PrototypeIterator iter(isolate, object);
    if (iter.IsAtEnd()) return Just(true);
    DCHECK(IsJSGlobalObject(*PrototypeIterator::GetCurrent(iter)));
    return PreventExtensionsWithTransition<attrs>(
        isolate, PrototypeIterator::GetCurrent<JSObject>(iter), should_throw);
  }

  // Shared objects are designed to have fixed layout, i.e. their maps are
  // effectively immutable. They are constructed seal, but the semantics of
  // ordinary ECMAScript objects allow sealed to be upgraded to frozen. This
  // upgrade violates the fixed layout invariant and is disallowed.
  if (IsAlwaysSharedSpaceJSObject(*object)) {
    DCHECK(FastTestIntegrityLevel(isolate, *object, SEALED));
    if (attrs != FROZEN) return Just(true);
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kCannotFreeze));
  }

  if (object->map()->has_named_interceptor() ||
      object->map()->has_indexed_interceptor() ||
      (object->HasTypedArrayOrRabGsabTypedArrayElements() &&
       Cast<JSTypedArray>(*object)->IsVariableLength())) {
    MessageTemplate message = MessageTemplate::kNone;
    switch (attrs) {
      case NONE:
        message = MessageTemplate::kCannotPreventExt;
        break;

      case SEALED:
        message = MessageTemplate::kCannotSeal;
        break;

      case FROZEN:
        message = MessageTemplate::kCannotFreeze;
        break;
    }
    RETURN_FAILURE(isolate, should_throw, NewTypeError(message));
  }

  Handle<Symbol> transition_marker;
  if (attrs == NONE) {
    transition_marker = isolate->factory()->nonextensible_symbol();
  } else if (attrs == SEALED) {
    transition_marker = isolate->factory()->sealed_symbol();
  } else {
    DCHECK(attrs == FROZEN);
    transition_marker = isolate->factory()->frozen_symbol();
  }

  // Currently, there are only have sealed/frozen Object element kinds and
  // Map::MigrateToMap doesn't handle properties' attributes reconfiguring and
  // elements kind change in one go. If seal or freeze with Smi or Double
  // elements kind, we will transition to Object elements kind first to make
  // sure of valid element access.
  if (v8_flags.enable_sealed_frozen_elements_kind) {
    switch (object->map()->elements_kind()) {
      case PACKED_SMI_ELEMENTS:
      case PACKED_DOUBLE_ELEMENTS:
        JSObject::TransitionElementsKind(object, PACKED_ELEMENTS);
        break;
      case HOLEY_SMI_ELEMENTS:
      case HOLEY_DOUBLE_ELEMENTS:
        JSObject::TransitionElementsKind(object, HOLEY_ELEMENTS);
        break;
      default:
        break;
    }
  }

  // Make sure we only use this element dictionary in case we can't transition
  // to sealed, frozen elements kind.
  Handle<NumberDictionary> new_element_dictionary;

  Handle<Map> old_map(object->map(), isolate);
  old_map = Map::Update(isolate, old_map);
  Handle<Map> transition_map;
  MaybeHandle<Map> maybe_transition_map =
      TransitionsAccessor::SearchSpecial(isolate, old_map, *transition_marker);
  if (maybe_transition_map.ToHandle(&transition_map)) {
    DCHECK(transition_map->has_dictionary_elements() ||
           transition_map->has_typed_array_or_rab_gsab_typed_array_elements() ||
           transition_map->elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS ||
           transition_map->has_any_nonextensible_elements());
    DCHECK(!transition_map->is_extensible());
    if (!transition_map->has_any_nonextensible_elements()) {
      new_element_dictionary = CreateElementDictionary(isolate, object);
    }
    JSObject::MigrateToMap(isolate, object, transition_map);
  } else if (TransitionsAccessor::CanHaveMoreTransitions(isolate, old_map)) {
    // Create a new descriptor array with the appropriate property attributes
    DirectHandle<Map> new_map = Map::CopyForPreventExtensions(
        isolate, old_map, attrs, transition_marker, "CopyForPreventExtensions");
    if (!new_map->has_any_nonextensible_elements()) {
      new_element_dictionary = CreateElementDictionary(isolate, object);
    }
    JSObject::MigrateToMap(isolate, object, new_map);
  } else {
    DCHECK(old_map->is_dictionary_map() || !old_map->is_prototype_map());
    // Slow path: need to normalize properties for safety
    NormalizeProperties(isolate, object, CLEAR_INOBJECT_PROPERTIES, 0,
                        "SlowPreventExtensions");

    // Create a new map, since other objects with this map may be extensible.
    // TODO(adamk): Extend the NormalizedMapCache to handle non-extensible maps.
    DirectHandle<Map> new_map =
        Map::Copy(isolate, handle(object->map(), isolate),
                  "SlowCopyForPreventExtensions");
    new_map->set_is_extensible(false);
    new_element_dictionary = CreateElementDictionary(isolate, object);
    if (!new_element_dictionary.is_null()) {
      ElementsKind new_kind =
          IsStringWrapperElementsKind(old_map->elements_kind())
              ? SLOW_STRING_WRAPPER_ELEMENTS
              : DICTIONARY_ELEMENTS;
      new_map->set_elements_kind(new_kind);
    }
    JSObject::MigrateToMap(isolate, object, new_map);

    if (attrs != NONE) {
      ReadOnlyRoots roots(isolate);
      if (IsJSGlobalObject(*object)) {
        Handle<GlobalDictionary> dictionary(
            Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
            isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      } else if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        Handle<SwissNameDictionary> dictionary(
            object->property_dictionary_swiss(), isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      } else {
        Handle<NameDictionary> dictionary(object->property_dictionary(),
                                          isolate);
        JSObject::ApplyAttributesToDictionary(isolate, roots, dictionary,
                                              attrs);
      }
    }
  }

  if (object->map()->has_any_nonextensible_elements()) {
    DCHECK(new_element_dictionary.is_null());
    return Just(true);
  }

  // Both seal and preventExtensions always go through without modifications to
  // typed array elements if the typed array is fixed length. Freeze works only
  // if there are no actual elements.
  if (object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    DCHECK(new_element_dictionary.is_null());
    if (attrs == FROZEN && Cast<JSTypedArray>(*object)->GetLength() > 0) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kCannotFreezeArrayBufferView));
      return Nothing<bool>();
    }
    return Just(true);
  }

  DCHECK(object->map()->has_dictionary_elements() ||
         object->map()->elements_kind() == SLOW_STRING_WRAPPER_ELEMENTS);
  if (!new_element_dictionary.is_null()) {
    object->set_elements(*new_element_dictionary);
  }

  if (object->elements() !=
      ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
    Handle<NumberDictionary> dictionary(object->element_dictionary(), isolate);
    // Make sure we never go back to the fast case
    object->RequireSlowElements(*dictionary);
    if (attrs != NONE) {
      JSObject::ApplyAttributesToDictionary(isolate, ReadOnlyRoots(isolate),
                                            dictionary, attrs);
    }
  }

  return Just(true);
}

Handle<JSAny> JSObject::FastPropertyAt(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Representation representation,
                                       FieldIndex index) {
  Handle<JSAny> raw_value(object->RawFastPropertyAt(index), isolate);
  return Object::WrapForRead(isolate, raw_value, representation);
}

Handle<JSAny> JSObject::FastPropertyAt(Isolate* isolate,
                                       DirectHandle<JSObject> object,
                                       Representation representation,
                                       FieldIndex index, SeqCstAccessTag tag) {
  Handle<JSAny> raw_value(object->RawFastPropertyAt(index, tag), isolate);
  return Object::WrapForRead(isolate, raw_value, representation);
}

// static
Handle<Object> JSObject::DictionaryPropertyAt(Isolate* isolate,
                                              DirectHandle<JSObject> object,
                                              InternalIndex dict_index) {
  DCHECK_EQ(ThreadId::Current(), isolate->thread_id());
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Tagged<SwissNameDictionary> dict = object->property_dictionary_swiss();
    return handle(dict->ValueAt(dict_index), isolate);
  } else {
    Tagged<NameDictionary> dict = object->property_dictionary();
    return handle(dict->ValueAt(dict_index), isolate);
  }
}

// static
std::optional<Tagged<Object>> JSObject::DictionaryPropertyAt(
    DirectHandle<JSObject> object, InternalIndex dict_index, Heap* heap) {
  Tagged<Object> backing_store = object->raw_properties_or_hash(kRelaxedLoad);
  if (!IsHeapObject(backing_store)) return {};
  if (heap->IsPendingAllocation(Cast<HeapObject>(backing_store))) return {};

  if (!IsPropertyDictionary(backing_store)) return {};
  std::optional<Tagged<Object>> maybe_obj =
      Cast<PropertyDictionary>(backing_store)->TryValueAt(dict_index);

  if (!maybe_obj) return {};
  return maybe_obj.value();
}

// TODO(cbruni/jkummerow): Consider moving this into elements.cc.
bool JSObject::HasEnumerableElements() {
  // TODO(cbruni): cleanup
  Tagged<JSObject> object = *this;
  switch (object->GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS: {
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : object->elements()->length();
      return length > 0;
    }
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS: {
      Tagged<FixedArray> elements = Cast<FixedArray>(object->elements());
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : elements->length();
      Isolate* isolate = GetIsolate();
      for (int i = 0; i < length; i++) {
        if (!elements->is_the_hole(isolate, i)) return true;
      }
      return false;
    }
    case HOLEY_DOUBLE_ELEMENTS: {
      int length = IsJSArray(object)
                       ? Smi::ToInt(Cast<JSArray>(object)->length())
                       : object->elements()->length();
      // Zero-length arrays would use the empty FixedArray...
      if (length == 0) return false;
      // ...so only cast to FixedDoubleArray otherwise.
      Tagged<FixedDoubleArray> elements =
          Cast<FixedDoubleArray>(object->elements());
      for (int i = 0; i < length; i++) {
        if (!elements->is_the_hole(i)) return true;
      }
      return false;
    }
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE) {
        size_t length = Cast<JSTypedArray>(object)->length();
        return length > 0;
      }

      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      {
        size_t length = Cast<JSTypedArray>(object)->GetLength();
        return length > 0;
      }
    case DICTIONARY_ELEMENTS: {
      Tagged<NumberDictionary> elements =
          Cast<NumberDictionary>(object->elements());
      return elements->NumberOfEnumerableProperties() > 0;
    }
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      // We're approximating non-empty arguments objects here.
      return true;
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
      if (Cast<String>(Cast<JSPrimitiveWrapper>(object)->value())->length() >
          0) {
        return true;
      }
      return object->elements()->length() > 0;
    case WASM_ARRAY_ELEMENTS:
      UNIMPLEMENTED();

    case NO_ELEMENTS:
      return false;
  }
  UNREACHABLE();
}

MaybeHandle<Object> JSObject::DefineOwnAccessorIgnoreAttributes(
    Handle<JSObject> object, Handle<Name> name, DirectHandle<Object> getter,
    DirectHandle<Object> setter, PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  return DefineOwnAccessorIgnoreAttributes(&it, getter, setter, attributes);
}

MaybeHandle<Object> JSObject::DefineOwnAccessorIgnoreAttributes(
    LookupIterator* it, DirectHandle<Object> getter,
    DirectHandle<Object> setter, PropertyAttributes attributes) {
  Isolate* isolate = it->isolate();

  it->UpdateProtector();

  while (it->state() == LookupIterator::ACCESS_CHECK) {
    if (!it->HasAccess()) {
      RETURN_ON_EXCEPTION(
          isolate, isolate->ReportFailedAccessCheck(it->GetHolder<JSObject>()));
      UNREACHABLE();
    }
    it->Next();
  }

  auto object = Cast<JSObject>(it->GetReceiver());
  // Ignore accessors on typed arrays.
  if (it->IsElement() && object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    return it->factory()->undefined_value();
  }

  DCHECK(IsCallable(*getter) || IsUndefined(*getter, isolate) ||
         IsNull(*getter, isolate) || IsFunctionTemplateInfo(*getter));
  DCHECK(IsCallable(*setter) || IsUndefined(*setter, isolate) ||
         IsNull(*setter, isolate) || IsFunctionTemplateInfo(*setter));
  it->TransitionToAccessorProperty(getter, setter, attributes);

  return isolate->factory()->undefined_value();
}

MaybeHandle<Object> JSObject::SetAccessor(Handle<JSObject> object,
                                          Handle<Name> name,
                                          Handle<AccessorInfo> info,
                                          PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);

  // Duplicate ACCESS_CHECK outside of GetPropertyAttributes for the case that
  // the FailedAccessCheckCallbackFunction doesn't throw an exception.
  while (it.state() == LookupIterator::ACCESS_CHECK) {
    if (!it.HasAccess()) {
      RETURN_ON_EXCEPTION(isolate, isolate->ReportFailedAccessCheck(object));
      UNREACHABLE();
    }
    it.Next();
  }

  // Ignore accessors on typed arrays.
  if (it.IsElement() && object->HasTypedArrayOrRabGsabTypedArrayElements()) {
    return it.factory()->undefined_value();
  }

  Maybe<bool> can_define = JSObject::CheckIfCanDefineAsConfigurable(
      isolate, &it, info, Nothing<ShouldThrow>());
  MAYBE_RETURN_NULL(can_define);
  if (!can_define.FromJust()) return it.factory()->undefined_value();

  it.TransitionToAccessorPair(info, attributes);

  return object;
}

// static
Maybe<bool> JSObject::CheckIfCanDefineAsConfigurable(
    Isolate* isolate, LookupIterator* it, DirectHandle<Object> value,
    Maybe<ShouldThrow> should_throw) {
  DCHECK(IsJSObject(*it->GetReceiver()));
  if (it->IsFound()) {
    Maybe<PropertyAttributes> attributes = GetPropertyAttributes(it);
    MAYBE_RETURN(attributes, Nothing<bool>());
    if (attributes.FromJust() != ABSENT) {
      if ((attributes.FromJust() & DONT_DELETE) != 0) {
        RETURN_FAILURE(
            isolate, GetShouldThrow(isolate, should_throw),
            NewTypeError(MessageTemplate::kRedefineDisallowed, it->GetName()));
      }
      return Just(true);
    }
    // Property does not exist, check object extensibility.
  }
  if (!JSObject::IsExtensible(isolate, Cast<JSObject>(it->GetReceiver()))) {
    RETURN_FAILURE(
        isolate, GetShouldThrow(isolate, should_throw),
        NewTypeError(MessageTemplate::kDefineDisallowed, it->GetName()));
  }
  return Just(true);
}

Tagged<Object> JSObject::SlowReverseLookup(Tagged<Object> value) {
  if (HasFastProperties()) {
    Tagged<DescriptorArray> descs = map()->instance_descriptors();
    bool value_is_number = IsNumber(value);
    for (InternalIndex i : map()->IterateOwnDescriptors()) {
      PropertyDetails details = descs->GetDetails(i);
      if (details.location() == PropertyLocation::kField) {
        DCHECK_EQ(PropertyKind::kData, details.kind());
        FieldIndex field_index = FieldIndex::ForDetails(map(), details);
        Tagged<Object> property = RawFastPropertyAt(field_index);
        if (field_index.is_double()) {
          DCHECK(IsHeapNumber(property));
          if (value_is_number && Cast<HeapNumber>(property)->value() ==
                                     Object::NumberValue(Cast<Number>(value))) {
            return descs->GetKey(i);
          }
        } else if (property == value) {
          return descs->GetKey(i);
        }
      } else {
        DCHECK_EQ(PropertyLocation::kDescriptor, details.location());
        if (details.kind() == PropertyKind::kData) {
          if (descs->GetStrongValue(i) == value) {
            return descs->GetKey(i);
          }
        }
      }
    }
    return GetReadOnlyRoots().undefined_value();
  } else if (IsJSGlobalObject(*this)) {
    return Cast<JSGlobalObject>(*this)
        ->global_dictionary(kAcquireLoad)
        ->SlowReverseLookup(value);
  } else if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    return property_dictionary_swiss()->SlowReverseLookup(GetIsolate(), value);
  } else {
    return property_dictionary()->SlowReverseLookup(value);
  }
}

void JSObject::PrototypeRegistryCompactionCallback(Tagged<HeapObject> value,
                                                   int old_index,
                                                   int new_index) {
  DCHECK(IsMap(value) && Cast<Map>(value)->is_prototype_map());
  Tagged<Map> map = Cast<Map>(value);
  DCHECK(IsPrototypeInfo(map->prototype_info()));
  Tagged<PrototypeInfo> proto_info = Cast<PrototypeInfo>(map->prototype_info());
  DCHECK_EQ(old_index, proto_info->registry_slot());
  proto_info->set_registry_slot(new_index);
}

// static
void JSObject::MakePrototypesFast(Handle<Object> receiver,
                                  WhereToStart where_to_start,
                                  Isolate* isolate) {
  if (!IsJSReceiver(*receiver)) return;
  for (PrototypeIterator iter(isolate, Cast<JSReceiver>(receiver),
                              where_to_start);
       !iter.IsAtEnd(); iter.Advance()) {
    Handle<Object> current = PrototypeIterator::GetCurrent(iter);
    if (!IsJSObjectThatCanBeTrackedAsPrototype(*current)) return;
    DirectHandle<JSObject> current_obj = Cast<JSObject>(current);
    Tagged<Map> current_map = current_obj->map();
    if (current_map->is_prototype_map()) {
      // If the map is already marked as should be fast, we're done. Its
      // prototypes will have been marked already as well.
      if (current_map->should_be_fast_prototype_map()) return;
      DirectHandle<Map> map(current_map, isolate);
      Map::SetShouldBeFastPrototypeMap(map, true, isolate);
      JSObject::OptimizeAsPrototype(current_obj);
    }
  }
}

static bool PrototypeBenefitsFromNormalization(Tagged<JSObject> object) {
  DisallowGarbageCollection no_gc;
  if (!object->HasFastProperties()) return false;
  if (IsJSGlobalProxy(object)) return false;
  // TODO(v8:11248) make bootstrapper create dict mode prototypes, too?
  if (object->GetIsolate()->bootstrapper()->IsActive()) return false;
  if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL) return true;
  return !object->map()->is_prototype_map() ||
         !object->map()->should_be_fast_prototype_map();
}

// static
void JSObject::OptimizeAsPrototype(DirectHandle<JSObject> object,
                                   bool enable_setup_mode) {
  DCHECK(IsJSObjectThatCanBeTrackedAsPrototype(*object));
  if (IsJSGlobalObject(*object)) return;
  Isolate* isolate = object->GetIsolate();
  if (object->map()->is_prototype_map()) {
    if (enable_setup_mode && PrototypeBenefitsFromNormalization(*object)) {
      // This is the only way PrototypeBenefitsFromNormalization can be true:
      DCHECK(!object->map()->should_be_fast_prototype_map());
      // First normalize to ensure all JSFunctions are DATA_CONSTANT.
      constexpr bool kUseCache = true;
      JSObject::NormalizeProperties(isolate, object, KEEP_INOBJECT_PROPERTIES,
                                    0, kUseCache, "NormalizeAsPrototype");
    }
    if (!V8_DICT_PROPERTY_CONST_TRACKING_BOOL &&
        object->map()->should_be_fast_prototype_map() &&
        !object->HasFastProperties()) {
      JSObject::MigrateSlowToFast(object, 0, "OptimizeAsPrototype");
    }
  } else {
    DirectHandle<Map> new_map;
    if (enable_setup_mode && PrototypeBenefitsFromNormalization(*object)) {
#if DEBUG
      DirectHandle<Map> old_map(object->map(isolate), isolate);
#endif  // DEBUG
      // First normalize to ensure all JSFunctions are DATA_CONSTANT. Don't use
      // the cache, since we're going to use the normalized version directly,
      // without making a copy.
      constexpr bool kUseCache = false;
      JSObject::NormalizeProperties(isolate, object, KEEP_INOBJECT_PROPERTIES,
                                    0, kUseCache,
                                    "NormalizeAndCopyAsPrototype");
      // A new map was created.
      DCHECK_NE(*old_map, object->map(isolate));

      new_map = direct_handle(object->map(isolate), isolate);
    } else {
      new_map =
          Map::Copy(isolate, handle(object->map(), isolate), "CopyAsPrototype");
    }
    new_map->set_is_prototype_map(true);

    // Replace the pointer to the exact constructor with the Object function
    // from the same context if undetectable from JS. This is to avoid keeping
    // memory alive unnecessarily.
    Tagged<Object> maybe_constructor = new_map->GetConstructorRaw();
    Tagged<Tuple2> tuple;
    if (IsTuple2(maybe_constructor)) {
      // Handle the {constructor, non-instance_prototype} tuple case if the map
      // has non-instance prototype.
      tuple = Cast<Tuple2>(maybe_constructor);
      maybe_constructor = tuple->value1();
    }
    if (IsJSFunction(maybe_constructor)) {
      Tagged<JSFunction> constructor = Cast<JSFunction>(maybe_constructor);
      if (!constructor->shared()->IsApiFunction()) {
        Tagged<NativeContext> context = constructor->native_context();
        Tagged<JSFunction> object_function = context->object_function();
        if (!tuple.is_null()) {
          tuple->set_value1(object_function);
```