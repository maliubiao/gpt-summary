Response:
The user wants a summary of the functionalities of the provided C++ code snippet from `v8/src/objects/elements.cc`.

Here's a breakdown of the request and how to approach it:

1. **Identify the file and its purpose:** The file is `v8/src/objects/elements.cc`. Based on the name, it likely deals with the representation and manipulation of JavaScript object properties stored as elements (e.g., in arrays).

2. **Check for Torque usage:** The prompt mentions checking if the file ends in `.tq`. This is not the case here, so it's standard C++.

3. **Relate to JavaScript functionality:**  The core task is to connect the C++ code to JavaScript behaviors. This involves understanding how V8 implements JavaScript array and object operations.

4. **Illustrate with JavaScript examples:** For relevant functionalities, provide simple JavaScript code snippets demonstrating the behavior the C++ code likely implements.

5. **Analyze code logic with examples:**  For more complex logic, provide hypothetical inputs and expected outputs to illustrate the code's behavior.

6. **Identify common programming errors:** Think about how developers might misuse the JavaScript features that this C++ code underlies and provide examples.

7. **Summarize the functionality:**  Provide a concise overview of the code's purpose based on the analysis.

8. **Address the "Part X of 8" instruction:** Acknowledge and incorporate this information.

**Detailed Plan:**

* **`DictionaryElementsAccessor` Class:**
    * **`NumberOfElementsImpl`:** Relates to getting the number of elements in a sparse array or object with a dictionary backing store (like JavaScript objects with string keys). Example: `Object.keys(obj).length`.
    * **`SetLengthImpl`:**  Handles setting the `length` property of an array, including removing elements if the new length is smaller. Example: `arr.length = 5`. Highlight the handling of non-configurable properties.
    * **`CopyElementsImpl`:**  While marked `UNREACHABLE()`, its intended function is likely copying elements, potentially during array resizing or `slice`. Note it's not currently implemented for dictionaries.
    * **`DeleteImpl`:**  Implements the `delete` operator for array elements, removing the property from the dictionary. Example: `delete arr[5]`.
    * **`HasAccessorsImpl`:** Checks if the object's backing store has any accessor properties (getters/setters). Example: `Object.defineProperty(obj, 'a', { get: ... })`.
    * **`GetRaw`, `GetImpl`, `GetAtomicInternalImpl`:**  Implement getting the raw or processed value of an element. Example: `arr[3]`.
    * **`SetImpl`, `SetAtomicInternalImpl`, `SwapAtomicInternalImpl`, `CompareAndSwapAtomicInternalImpl`:** Implement setting element values, including atomic operations for concurrent scenarios. Example: `arr[2] = 10`.
    * **`ReconfigureImpl`:**  Handles reconfiguring the attributes of an existing property. Example: `Object.defineProperty(obj, 'a', { configurable: true })`.
    * **`AddImpl`:**  Adds a new element to the dictionary. Example: `arr[10] = 'hello'`.
    * **`HasEntryImpl`:** Checks if a specific index has a defined value. Example: `5 in arr`.
    * **`GetEntryForIndexImpl`:**  Finds the internal representation of an element's entry in the dictionary.
    * **`GetDetailsImpl`:** Retrieves the details (attributes, kind) of a property.
    * **`FilterKey`, `GetKeyForEntryImpl`:** Helper functions for extracting and filtering keys.
    * **`CollectElementIndicesImpl`, `DirectCollectElementIndicesImpl`:**  Collect the numerical indices of elements. Example: `Object.keys(arr)`.
    * **`AddElementsToKeyAccumulatorImpl`:**  Adds element values to an accumulator.
    * **`IncludesValueFastPath`, `IncludesValueImpl`:** Implement the `includes()` method for arrays. Example: `arr.includes(value)`.
    * **`IndexOfValueImpl`:** Implements the `indexOf()` method for arrays. Example: `arr.indexOf(value)`.
    * **`ValidateContents`:**  Performs internal consistency checks.

* **`FastElementsAccessor` Template:**
    * **`NormalizeImpl`:** Converts fast elements to dictionary elements (normalization). This happens when arrays become sparse or have properties added.
    * **`DeleteAtEnd`, `DeleteCommon`:** Implement element deletion for fast arrays, potentially triggering normalization. Example: `delete arr[arr.length - 1]`.
    * **`ReconfigureImpl`:**  Reconfigures properties in fast arrays, potentially triggering normalization.
    * **`AddImpl`:** Adds elements to fast arrays, handling resizing and type transitions. Example: `arr.push(value)`.
    * **`DeleteImpl`:**  Deletes elements in fast arrays.
    * **`HasEntryImpl`:** Checks for the existence of an element in a fast array.
    * **`NumberOfElementsImpl`:** Gets the number of elements in a fast array.
    * **`AddElementsToKeyAccumulatorImpl`:** Adds elements to a key accumulator for fast arrays.
    * **`ValidateContents`:** Performs internal validation for fast arrays.
    * **`PopImpl`, `ShiftImpl`:** Implement array `pop()` and `shift()` operations.

* **Common Programming Errors:** Focus on common mistakes related to array manipulation and property access.

* **Summary:**  Synthesize the identified functionalities into a concise description of the code's role.
```cpp
;
    return dict->NumberOfElements();
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate,
                                   DirectHandle<JSArray> array, uint32_t length,
                                   Handle<FixedArrayBase> backing_store) {
    auto dict = Cast<NumberDictionary>(backing_store);
    uint32_t old_length = 0;
    CHECK(Object::ToArrayLength(array->length(), &old_length));
    {
      DisallowGarbageCollection no_gc;
      ReadOnlyRoots roots(isolate);
      if (length < old_length) {
        if (dict->requires_slow_elements()) {
          // Find last non-deletable element in range of elements to be
          // deleted and adjust range accordingly.
          for (InternalIndex entry : dict->IterateEntries()) {
            Tagged<Object> index = dict->KeyAt(isolate, entry);
            if (dict->IsKey(roots, index)) {
              uint32_t number =
                  static_cast<uint32_t>(Object::NumberValue(index));
              if (length <= number && number < old_length) {
                PropertyDetails details = dict->DetailsAt(entry);
                if (!details.IsConfigurable()) length = number + 1;
              }
            }
          }
        }

        if (length == 0) {
          // Flush the backing store.
          array->initialize_elements();
        } else {
          // Remove elements that should be deleted.
          int removed_entries = 0;
          for (InternalIndex entry : dict->IterateEntries()) {
            Tagged<Object> index = dict->KeyAt(isolate, entry);
            if (dict->IsKey(roots, index)) {
              uint32_t number =
                  static_cast<uint32_t>(Object::NumberValue(index));
              if (length <= number && number < old_length) {
                dict->ClearEntry(entry);
                removed_entries++;
              }
            }
          }

          if (removed_entries > 0) {
            // Update the number of elements.
            dict->ElementsRemoved(removed_entries);
          }
        }
      }
    }

    DirectHandle<Number> length_obj =
        isolate->factory()->NewNumberFromUint(length);
    array->set_length(*length_obj);
    return Just(true);
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    UNREACHABLE();
  }

  static void DeleteImpl(DirectHandle<JSObject> obj, InternalIndex entry) {
    Handle<NumberDictionary> dict(Cast<NumberDictionary>(obj->elements()),
                                  obj->GetIsolate());
    dict = NumberDictionary::DeleteEntry(obj->GetIsolate(), dict, entry);
    obj->set_elements(*dict);
  }

  static bool HasAccessorsImpl(Tagged<JSObject> holder,
                               Tagged<FixedArrayBase> backing_store) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dict = Cast<NumberDictionary>(backing_store);
    if (!dict->requires_slow_elements()) return false;
    PtrComprCageBase cage_base = GetPtrComprCageBase(holder);
    ReadOnlyRoots roots = holder->GetReadOnlyRoots(cage_base);
    for (InternalIndex i : dict->IterateEntries()) {
      Tagged<Object> key = dict->KeyAt(cage_base, i);
      if (!dict->IsKey(roots, key)) continue;
      PropertyDetails details = dict->DetailsAt(i);
      if (details.kind() == PropertyKind::kAccessor) return true;
    }
    return false;
  }

  static Tagged<Object> GetRaw(Tagged<FixedArrayBase> store,
                               InternalIndex entry) {
    Tagged<NumberDictionary> backing_store = Cast<NumberDictionary>(store);
    return backing_store->ValueAt(entry);
  }

  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> backing_store,
                                InternalIndex entry) {
    return handle(GetRaw(backing_store, entry), isolate);
  }

  static Handle<Object> GetAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, SeqCstAccessTag tag) {
    return handle(Cast<NumberDictionary>(backing_store)->ValueAt(entry, tag),
                  isolate);
  }

  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    SetImpl(holder->elements(), entry, value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value) {
    Cast<NumberDictionary>(backing_store)->ValueAtPut(entry, value);
  }

  static void SetAtomicInternalImpl(Tagged<FixedArrayBase> backing_store,
                                    InternalIndex entry, Tagged<Object> value,
                                    SeqCstAccessTag tag) {
    Cast<NumberDictionary>(backing_store)->ValueAtPut(entry, value, tag);
  }

  static Handle<Object> SwapAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, Tagged<Object> value, SeqCstAccessTag tag) {
    return handle(
        Cast<NumberDictionary>(backing_store)->ValueAtSwap(entry, value, tag),
        isolate);
  }

  static Tagged<Object> CompareAndSwapAtomicInternalImpl(
      Tagged<FixedArrayBase> backing_store, InternalIndex entry,
      Tagged<Object> expected, Tagged<Object> value, SeqCstAccessTag tag) {
    return Cast<NumberDictionary>(backing_store)
        ->ValueAtCompareAndSwap(entry, expected, value, tag);
  }

  static void ReconfigureImpl(DirectHandle<JSObject> object,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    Tagged<NumberDictionary> dictionary = Cast<NumberDictionary>(*store);
    if (attributes != NONE) object->RequireSlowElements(dictionary);
    dictionary->ValueAtPut(entry, *value);
    PropertyDetails details = dictionary->DetailsAt(entry);
    details =
        PropertyDetails(PropertyKind::kData, attributes,
                        PropertyCellType::kNoCell, details.dictionary_index());

    dictionary->DetailsAtPut(entry, details);
  }

  static Maybe<bool> AddImpl(Handle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    PropertyDetails details(PropertyKind::kData, attributes,
                            PropertyCellType::kNoCell);
    Handle<NumberDictionary> dictionary =
        object->HasFastElements() || object->HasFastStringWrapperElements()
            ? JSObject::NormalizeElements(object)
            : handle(Cast<NumberDictionary>(object->elements()),
                     object->GetIsolate());
    Handle<NumberDictionary> new_dictionary = NumberDictionary::Add(
        object->GetIsolate(), dictionary, index, value, details);
    new_dictionary->UpdateMaxNumberKey(index, object);
    if (attributes != NONE) object->RequireSlowElements(*new_dictionary);
    if (dictionary.is_identical_to(new_dictionary)) return Just(true);
    object->set_elements(*new_dictionary);
    return Just(true);
  }

  static bool HasEntryImpl(Isolate* isolate, Tagged<FixedArrayBase> store,
                           InternalIndex entry) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dict = Cast<NumberDictionary>(store);
    Tagged<Object> index = dict->KeyAt(isolate, entry);
    return !IsTheHole(index, isolate);
  }

  static InternalIndex GetEntryForIndexImpl(Isolate* isolate,
                                            Tagged<JSObject> holder,
                                            Tagged<FixedArrayBase> store,
                                            size_t index,
                                            PropertyFilter filter) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dictionary = Cast<NumberDictionary>(store);
    DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
    InternalIndex entry =
        dictionary->FindEntry(isolate, static_cast<uint32_t>(index));
    if (entry.is_not_found()) return entry;

    if (filter != ALL_PROPERTIES) {
      PropertyDetails details = dictionary->DetailsAt(entry);
      PropertyAttributes attr = details.attributes();
      if ((int{attr} & filter) != 0) return InternalIndex::NotFound();
    }
    return entry;
  }

  static PropertyDetails GetDetailsImpl(Tagged<JSObject> holder,
                                        InternalIndex entry) {
    return GetDetailsImpl(holder->elements(), entry);
  }

  static PropertyDetails GetDetailsImpl(Tagged<FixedArrayBase> backing_store,
                                        InternalIndex entry) {
    return Cast<NumberDictionary>(backing_store)->DetailsAt(entry);
  }

  static uint32_t FilterKey(DirectHandle<NumberDictionary> dictionary,
                            InternalIndex entry, Tagged<Object> raw_key,
                            PropertyFilter filter) {
    DCHECK(IsNumber(raw_key));
    DCHECK_LE(Object::NumberValue(raw_key), kMaxUInt32);
    PropertyDetails details = dictionary->DetailsAt(entry);
    PropertyAttributes attr = details.attributes();
    if ((int{attr} & filter) != 0) return kMaxUInt32;
    return static_cast<uint32_t>(Object::NumberValue(raw_key));
  }

  static uint32_t GetKeyForEntryImpl(Isolate* isolate,
                                     DirectHandle<NumberDictionary> dictionary,
                                     InternalIndex entry,
                                     PropertyFilter filter) {
    DisallowGarbageCollection no_gc;
    Tagged<Object> raw_key = dictionary->KeyAt(isolate, entry);
    if (!dictionary->IsKey(ReadOnlyRoots(isolate), raw_key)) return kMaxUInt32;
    return FilterKey(dictionary, entry, raw_key, filter);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus CollectElementIndicesImpl(
      DirectHandle<JSObject> object, Handle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) {
    if (keys->filter() & SKIP_STRINGS) return ExceptionStatus::kSuccess;
    Isolate* isolate = keys->isolate();
    auto dictionary = Cast<NumberDictionary>(backing_store);
    DirectHandle<FixedArray> elements = isolate->factory()->NewFixedArray(
        GetMaxNumberOfEntries(isolate, *object, *backing_store));
    int insertion_index = 0;
    PropertyFilter filter = keys->filter();
    ReadOnlyRoots roots(isolate);
    for (InternalIndex i : dictionary->IterateEntries()) {
      AllowGarbageCollection allow_gc;
      Tagged<Object> raw_key = dictionary->KeyAt(isolate, i);
      if (!dictionary->IsKey(roots, raw_key)) continue;
      uint32_t key = FilterKey(dictionary, i, raw_key, filter);
      if (key == kMaxUInt32) {
        // This might allocate, but {raw_key} is not used afterwards.
        keys->AddShadowingKey(raw_key, &allow_gc);
        continue;
      }
      elements->set(insertion_index, raw_key);
      insertion_index++;
    }
    SortIndices(isolate, elements, insertion_index);
    for (int i = 0; i < insertion_index; i++) {
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(keys->AddKey(elements->get(i)));
    }
    return ExceptionStatus::kSuccess;
  }

  static Handle<FixedArray> DirectCollectElementIndicesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      Handle<FixedArrayBase> backing_store, GetKeysConversion convert,
      PropertyFilter filter, Handle<FixedArray> list, uint32_t* nof_indices,
      uint32_t insertion_index = 0) {
    if (filter & SKIP_STRINGS) return list;

    auto dictionary = Cast<NumberDictionary>(backing_store);
    for (InternalIndex i : dictionary->IterateEntries()) {
      uint32_t key = GetKeyForEntryImpl(isolate, dictionary, i, filter);
      if (key == kMaxUInt32) continue;
      DirectHandle<Object> index = isolate->factory()->NewNumberFromUint(key);
      list->set(insertion_index, *index);
      insertion_index++;
    }
    *nof_indices = insertion_index;
    return list;
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus AddElementsToKeyAccumulatorImpl(
      DirectHandle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) {
    Isolate* isolate = accumulator->isolate();
    DirectHandle<NumberDictionary> dictionary(
        Cast<NumberDictionary>(receiver->elements()), isolate);
    ReadOnlyRoots roots(isolate);
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k = dictionary->KeyAt(isolate, i);
      if (!dictionary->IsKey(roots, k)) continue;
      Tagged<Object> value = dictionary->ValueAt(isolate, i);
      DCHECK(!IsTheHole(value, isolate));
      DCHECK(!IsAccessorPair(value));
      DCHECK(!IsAccessorInfo(value));
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(accumulator->AddKey(value, convert));
    }
    return ExceptionStatus::kSuccess;
  }

  static bool IncludesValueFastPath(Isolate* isolate,
                                    DirectHandle<JSObject> receiver,
                                    DirectHandle<Object> value,
                                    size_t start_from, size_t length,
                                    Maybe<bool>* result) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dictionary =
        Cast<NumberDictionary>(receiver->elements());
    Tagged<Object> the_hole = ReadOnlyRoots(isolate).the_hole_value();
    Tagged<Object> undefined = ReadOnlyRoots(isolate).undefined_value();

    // Scan for accessor properties. If accessors are present, then elements
    // must be accessed in order via the slow path.
    bool found = false;
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k = dictionary->KeyAt(isolate, i);
      if (k == the_hole) continue;
      if (k == undefined) continue;

      uint32_t index;
      if (!Object::ToArrayIndex(k, &index) || index < start_from ||
          index >= length) {
        continue;
      }

      if (dictionary->DetailsAt(i).kind() == PropertyKind::kAccessor) {
        // Restart from beginning in slow path, otherwise we may observably
        // access getters out of order
        return false;
      } else if (!found) {
        Tagged<Object> element_k = dictionary->ValueAt(isolate, i);
        if (Object::SameValueZero(*value, element_k)) found = true;
      }
    }

    *result = Just(found);
    return true;
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       Handle<JSObject> receiver,
                                       Handle<Object> value, size_t start_from,
                                       size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));
    bool search_for_hole = IsUndefined(*value, isolate);

    if (!search_for_hole) {
      Maybe<bool> result = Nothing<bool>();
      if (DictionaryElementsAccessor::IncludesValueFastPath(
              isolate, receiver, value, start_from, length, &result)) {
        return result;
      }
    }
    ElementsKind original_elements_kind = receiver->GetElementsKind();
    USE(original_elements_kind);
    DirectHandle<NumberDictionary> dictionary(
        Cast<NumberDictionary>(receiver->elements()), isolate);
    // Iterate through the entire range, as accessing elements out of order is
    // observable.
    for (size_t k = start_from; k < length; ++k) {
      DCHECK_EQ(receiver->GetElementsKind(), original_elements_kind);
      InternalIndex entry =
          dictionary->FindEntry(isolate, static_cast<uint32_t>(k));
      if (entry.is_not_found()) {
        if (search_for_hole) return Just(true);
        continue;
      }

      PropertyDetails details = GetDetailsImpl(*dictionary, entry);
      switch (details.kind()) {
        case PropertyKind::kData: {
          Tagged<Object> element_k = dictionary->ValueAt(entry);
          if (Object::SameValueZero(*value, element_k)) return Just(true);
          break;
        }
        case PropertyKind::kAccessor: {
          LookupIterator it(isolate, receiver, k,
                            LookupIterator::OWN_SKIP_INTERCEPTOR);
          DCHECK(it.IsFound());
          DCHECK_EQ(it.state(), LookupIterator::ACCESSOR);
          Handle<Object> element_k;

          ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                           Object::GetPropertyWithAccessor(&it),
                                           Nothing<bool>());

          if (Object::SameValueZero(*value, *element_k)) return Just(true);

          // Bailout to slow path if elements on prototype changed
          if (!JSObject::PrototypeHasNoElements(isolate, *receiver)) {
            return IncludesValueSlowPath(isolate, receiver, value, k + 1,
                                         length);
          }

          // Continue if elements unchanged
          if (*dictionary == receiver->elements()) continue;

          // Otherwise, bailout or update elements

          // If switched to initial elements, return true if searching for
          // undefined, and false otherwise.
          if (receiver->map()->GetInitialElements() == receiver->elements()) {
            return Just(search_for_hole);
          }

          // If switched to fast elements, continue with the correct accessor.
          if (receiver->GetElementsKind() != DICTIONARY_ELEMENTS) {
            ElementsAccessor* accessor = receiver->GetElementsAccessor();
            return accessor->IncludesValue(isolate, receiver, value, k + 1,
                                           length);
          }
          dictionary =
              handle(Cast<NumberDictionary>(receiver->elements()), isolate);
          break;
        }
      }
    }
    return Just(false);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         Handle<JSObject> receiver,
                                         DirectHandle<Object> value,
                                         size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));

    ElementsKind original_elements_kind = receiver->GetElementsKind();
    USE(original_elements_kind);
    DirectHandle<NumberDictionary> dictionary(
        Cast<NumberDictionary>(receiver->elements()), isolate);
    // Iterate through entire range, as accessing elements out of order is
    // observable.
    for (size_t k = start_from; k < length; ++k) {
      DCHECK_EQ(receiver->GetElementsKind(), original_elements_kind);
      DCHECK_LE(k, std::numeric_limits<uint32_t>::max());
      InternalIndex entry =
          dictionary->FindEntry(isolate, static_cast<uint32_t>(k));
      if (entry.is_not_found()) continue;

      PropertyDetails details =
          GetDetailsImpl(*dictionary, InternalIndex(entry));
      switch (details.kind()) {
        case PropertyKind::kData: {
          Tagged<Object> element_k = dictionary->ValueAt(entry);
          if (Object::StrictEquals(*value, element_k)) {
            return Just<int64_t>(k);
          }
          break;
        }
        case PropertyKind::kAccessor: {
          LookupIterator it(isolate, receiver, k,
                            LookupIterator::OWN_SKIP_INTERCEPTOR);
          DCHECK(it.IsFound());
          DCHECK_EQ(it.state(), LookupIterator::ACCESSOR);
          Handle<Object> element_k;

          ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                           Object::GetPropertyWithAccessor(&it),
                                           Nothing<int64_t>());

          if (Object::StrictEquals(*value, *element_k)) return Just<int64_t>(k);

          // Bailout to slow path if elements on prototype changed.
          if (!JSObject::PrototypeHasNoElements(isolate, *receiver)) {
            return IndexOfValueSlowPath(isolate, receiver, value, k + 1,
                                        length);
          }

          // Continue if elements unchanged.
          if (*dictionary == receiver->elements()) continue;

          // Otherwise, bailout or update elements.
          if (receiver->GetElementsKind() != DICTIONARY_ELEMENTS) {
            // Otherwise, switch to slow path.
            return IndexOfValueSlowPath(isolate, receiver, value, k + 1,
                                        length);
          }
          dictionary = direct_handle(
              Cast<NumberDictionary>(receiver->elements()), isolate);
          break;
        }
      }
    }
    return Just<int64_t>(-1);
  }

  static void ValidateContents(Tagged<JSObject> holder, size_t length) {
    DisallowGarbageCollection no_gc;
#if DEBUG
    DCHECK_EQ(holder->map()->elements_kind(), DICTIONARY_ELEMENTS);
    if (!v8_flags.enable_slow_asserts) return;
    ReadOnlyRoots roots = holder->GetReadOnlyRoots();
    Tagged<NumberDictionary> dictionary =
        Cast<NumberDictionary>(holder->elements());
    // Validate the requires_slow_elements and max_number_key values.
    bool requires_slow_elements = false;
    int max_key = 0;
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k;
      if (!dictionary->ToKey(roots, i, &k)) continue;
      DCHECK_LE(0.0, Object::NumberValue(k));
      if (Object::NumberValue(k) >
          NumberDictionary::kRequiresSlowElementsLimit) {
        requires_slow_elements = true;
      } else {
        max_key = std::max(max_key, Smi::ToInt(k));
      }
    }
    if (requires_slow_elements) {
      DCHECK(dictionary->requires_slow_elements());
    } else if (!dictionary->requires_slow_elements()) {
      DCHECK_LE(max_key, dictionary->max_number_key());
    }
#endif
  }
};

// Super class for all fast element arrays.
template <typename Subclass, typename KindTraits>
class FastElementsAccessor : public ElementsAccessorBase<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static Handle<NumberDictionary> NormalizeImpl(
      Handle<JSObject> object, DirectHandle<FixedArrayBase> store) {
    Isolate* isolate = object->GetIsolate();
    ElementsKind kind = Subclass::kind();

    // Ensure that notifications fire if the array or object prototypes are
    // normalizing.
    if (IsSmiOrObjectElementsKind(kind) ||
        kind == FAST_STRING_WRAPPER_ELEMENTS) {
      isolate->UpdateNoElementsProtectorOnNormalizeElements(object);
    }

    int capacity = object->GetFastElementsUsage();
    Handle<NumberDictionary> dictionary =
        NumberDictionary::New(isolate, capacity);

    PropertyDetails details = PropertyDetails::Empty();
    int j = 0;
    int max_number_key = -1;
    for (int i = 0; j < capacity; i++) {
      if (IsHoleyElementsKindForRead(kind)) {
        if (Cast<BackingStore>(*store)->is_the_hole(isolate, i)) continue;
      }
      max_number_key = i;
      DirectHandle<Object> value =
          Subclass::GetImpl(isolate, *store, InternalIndex(i));
      dictionary =
          NumberDictionary::Add(isolate, dictionary, i, value, details);
      j++;
    }

    if (max_number_key > 0) {
      dictionary->UpdateMaxNumberKey(static_cast<uint32_t>(max_number_key),
                                     object);
    }
    return dictionary;
  }

  static void DeleteAtEnd(DirectHandle<JSObject> obj,
                          Handle<BackingStore> backing_store, uint32_t entry) {
    uint32_t length = static_cast<uint32_t>(backing_store->length());
    DCHECK_LT(entry, length);
    Isolate* isolate = obj->GetIsolate();
    for (; entry > 0; entry--) {
      if (!backing_store->is_the_hole(isolate, entry - 1)) break;
    }
    if (entry == 0) {
      Tagged<FixedArray> empty = ReadOnlyRoots(isolate).empty_fixed_array();
      // Dynamically ask for the elements kind here since we manually redirect
      // the operations for argument backing stores.
      if (obj->GetElementsKind() == FAST_SLOPPY_ARGUMENTS_ELEMENTS) {
        Cast<SloppyArgumentsElements>(obj->elements())->set_arguments(empty);
      } else {
        obj->set_elements(empty);
      }
      return;
    }

    isolate->heap()->RightTrimArray(*backing_store, entry, length);
  }

  static void DeleteCommon(Handle<JSObject> obj, uint32_t entry,
                           Handle<FixedArrayBase> store) {
    DCHECK(obj->HasSmiOrObjectElements() || obj->HasDoubleElements() ||
           obj->HasNonextensibleElements() || obj->HasFastArgumentsElements() ||
           obj->HasFastStringWrapperElements());
    Handle<BackingStore> backing_store = Cast<BackingStore>(store);
    if (!IsJSArray(*obj) &&
        entry == static_cast<uint32_t>(store->length()) - 1) {
      DeleteAtEnd(obj, backing_store, entry);
      return;
    }

    Isolate* isolate = obj->GetIsolate();
    backing_store->set_the_hole(isolate, entry);

    // TODO(verwaest): Move this out of elements.cc.
    // If the backing store is larger than a certain size and
    // has too few used values, normalize it.
    const int kMinLengthForSparsenessCheck = 64;
    if (backing_store->length() < kMinLengthForSparsenessCheck) return;
    uint32_t length = 0;
    if (IsJSArray(*obj)) {
      Object::ToArrayLength(Cast<JSArray>(*obj)->length(), &length);
    } else {
      length = static_cast<uint32_t>(store->length());
    }

    // To avoid doing the check on every delete, use a counter-based heuristic.
    const int kLengthFraction = 16;
    // The above constant must be large enough to ensure that we check for
    // normalization frequently enough. At a minimum, it should be large
    // enough to reliably hit the "window" of remaining elements count where
    // normalization would be beneficial.
    static_assert(kLengthFraction >=
                  NumberDictionary::kEntrySize *
                      NumberDictionary::kPreferFastElementsSizeFactor);
    size_t current_counter = isolate->elements_deletion_counter();
    if (current_counter < length / kLengthFraction) {
      isolate->set_elements_deletion_counter(current_counter + 1);
      return;
    }
    // Reset the counter whenever the full check is performed.
    isolate->set_elements_deletion_counter(0);

    if (!IsJSArray(*obj)) {
      uint32_t i;
      for (i = entry + 1; i < length; i++) {
        if (!backing_store->is_the_hole(isolate, i)) break;
      }
      if (i == length) {
        DeleteAtEnd(obj, backing_store, entry);
        return;
      }
    }
    int num_used = 0;
    for (int i = 0; i < backing_store->length(); ++i) {
      if (!backing_store->is_the_hole(isolate, i)) {
        ++num_used;
        // Bail out if a number dictionary wouldn't be able to save much space.
        if (NumberDictionary::kPreferFast
### 提示词
```
这是目录为v8/src/objects/elements.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/elements.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
;
    return dict->NumberOfElements();
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate,
                                   DirectHandle<JSArray> array, uint32_t length,
                                   Handle<FixedArrayBase> backing_store) {
    auto dict = Cast<NumberDictionary>(backing_store);
    uint32_t old_length = 0;
    CHECK(Object::ToArrayLength(array->length(), &old_length));
    {
      DisallowGarbageCollection no_gc;
      ReadOnlyRoots roots(isolate);
      if (length < old_length) {
        if (dict->requires_slow_elements()) {
          // Find last non-deletable element in range of elements to be
          // deleted and adjust range accordingly.
          for (InternalIndex entry : dict->IterateEntries()) {
            Tagged<Object> index = dict->KeyAt(isolate, entry);
            if (dict->IsKey(roots, index)) {
              uint32_t number =
                  static_cast<uint32_t>(Object::NumberValue(index));
              if (length <= number && number < old_length) {
                PropertyDetails details = dict->DetailsAt(entry);
                if (!details.IsConfigurable()) length = number + 1;
              }
            }
          }
        }

        if (length == 0) {
          // Flush the backing store.
          array->initialize_elements();
        } else {
          // Remove elements that should be deleted.
          int removed_entries = 0;
          for (InternalIndex entry : dict->IterateEntries()) {
            Tagged<Object> index = dict->KeyAt(isolate, entry);
            if (dict->IsKey(roots, index)) {
              uint32_t number =
                  static_cast<uint32_t>(Object::NumberValue(index));
              if (length <= number && number < old_length) {
                dict->ClearEntry(entry);
                removed_entries++;
              }
            }
          }

          if (removed_entries > 0) {
            // Update the number of elements.
            dict->ElementsRemoved(removed_entries);
          }
        }
      }
    }

    DirectHandle<Number> length_obj =
        isolate->factory()->NewNumberFromUint(length);
    array->set_length(*length_obj);
    return Just(true);
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    UNREACHABLE();
  }

  static void DeleteImpl(DirectHandle<JSObject> obj, InternalIndex entry) {
    Handle<NumberDictionary> dict(Cast<NumberDictionary>(obj->elements()),
                                  obj->GetIsolate());
    dict = NumberDictionary::DeleteEntry(obj->GetIsolate(), dict, entry);
    obj->set_elements(*dict);
  }

  static bool HasAccessorsImpl(Tagged<JSObject> holder,
                               Tagged<FixedArrayBase> backing_store) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dict = Cast<NumberDictionary>(backing_store);
    if (!dict->requires_slow_elements()) return false;
    PtrComprCageBase cage_base = GetPtrComprCageBase(holder);
    ReadOnlyRoots roots = holder->GetReadOnlyRoots(cage_base);
    for (InternalIndex i : dict->IterateEntries()) {
      Tagged<Object> key = dict->KeyAt(cage_base, i);
      if (!dict->IsKey(roots, key)) continue;
      PropertyDetails details = dict->DetailsAt(i);
      if (details.kind() == PropertyKind::kAccessor) return true;
    }
    return false;
  }

  static Tagged<Object> GetRaw(Tagged<FixedArrayBase> store,
                               InternalIndex entry) {
    Tagged<NumberDictionary> backing_store = Cast<NumberDictionary>(store);
    return backing_store->ValueAt(entry);
  }

  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> backing_store,
                                InternalIndex entry) {
    return handle(GetRaw(backing_store, entry), isolate);
  }

  static Handle<Object> GetAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, SeqCstAccessTag tag) {
    return handle(Cast<NumberDictionary>(backing_store)->ValueAt(entry, tag),
                  isolate);
  }

  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    SetImpl(holder->elements(), entry, value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value) {
    Cast<NumberDictionary>(backing_store)->ValueAtPut(entry, value);
  }

  static void SetAtomicInternalImpl(Tagged<FixedArrayBase> backing_store,
                                    InternalIndex entry, Tagged<Object> value,
                                    SeqCstAccessTag tag) {
    Cast<NumberDictionary>(backing_store)->ValueAtPut(entry, value, tag);
  }

  static Handle<Object> SwapAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, Tagged<Object> value, SeqCstAccessTag tag) {
    return handle(
        Cast<NumberDictionary>(backing_store)->ValueAtSwap(entry, value, tag),
        isolate);
  }

  static Tagged<Object> CompareAndSwapAtomicInternalImpl(
      Tagged<FixedArrayBase> backing_store, InternalIndex entry,
      Tagged<Object> expected, Tagged<Object> value, SeqCstAccessTag tag) {
    return Cast<NumberDictionary>(backing_store)
        ->ValueAtCompareAndSwap(entry, expected, value, tag);
  }

  static void ReconfigureImpl(DirectHandle<JSObject> object,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    Tagged<NumberDictionary> dictionary = Cast<NumberDictionary>(*store);
    if (attributes != NONE) object->RequireSlowElements(dictionary);
    dictionary->ValueAtPut(entry, *value);
    PropertyDetails details = dictionary->DetailsAt(entry);
    details =
        PropertyDetails(PropertyKind::kData, attributes,
                        PropertyCellType::kNoCell, details.dictionary_index());

    dictionary->DetailsAtPut(entry, details);
  }

  static Maybe<bool> AddImpl(Handle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    PropertyDetails details(PropertyKind::kData, attributes,
                            PropertyCellType::kNoCell);
    Handle<NumberDictionary> dictionary =
        object->HasFastElements() || object->HasFastStringWrapperElements()
            ? JSObject::NormalizeElements(object)
            : handle(Cast<NumberDictionary>(object->elements()),
                     object->GetIsolate());
    Handle<NumberDictionary> new_dictionary = NumberDictionary::Add(
        object->GetIsolate(), dictionary, index, value, details);
    new_dictionary->UpdateMaxNumberKey(index, object);
    if (attributes != NONE) object->RequireSlowElements(*new_dictionary);
    if (dictionary.is_identical_to(new_dictionary)) return Just(true);
    object->set_elements(*new_dictionary);
    return Just(true);
  }

  static bool HasEntryImpl(Isolate* isolate, Tagged<FixedArrayBase> store,
                           InternalIndex entry) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dict = Cast<NumberDictionary>(store);
    Tagged<Object> index = dict->KeyAt(isolate, entry);
    return !IsTheHole(index, isolate);
  }

  static InternalIndex GetEntryForIndexImpl(Isolate* isolate,
                                            Tagged<JSObject> holder,
                                            Tagged<FixedArrayBase> store,
                                            size_t index,
                                            PropertyFilter filter) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dictionary = Cast<NumberDictionary>(store);
    DCHECK_LE(index, std::numeric_limits<uint32_t>::max());
    InternalIndex entry =
        dictionary->FindEntry(isolate, static_cast<uint32_t>(index));
    if (entry.is_not_found()) return entry;

    if (filter != ALL_PROPERTIES) {
      PropertyDetails details = dictionary->DetailsAt(entry);
      PropertyAttributes attr = details.attributes();
      if ((int{attr} & filter) != 0) return InternalIndex::NotFound();
    }
    return entry;
  }

  static PropertyDetails GetDetailsImpl(Tagged<JSObject> holder,
                                        InternalIndex entry) {
    return GetDetailsImpl(holder->elements(), entry);
  }

  static PropertyDetails GetDetailsImpl(Tagged<FixedArrayBase> backing_store,
                                        InternalIndex entry) {
    return Cast<NumberDictionary>(backing_store)->DetailsAt(entry);
  }

  static uint32_t FilterKey(DirectHandle<NumberDictionary> dictionary,
                            InternalIndex entry, Tagged<Object> raw_key,
                            PropertyFilter filter) {
    DCHECK(IsNumber(raw_key));
    DCHECK_LE(Object::NumberValue(raw_key), kMaxUInt32);
    PropertyDetails details = dictionary->DetailsAt(entry);
    PropertyAttributes attr = details.attributes();
    if ((int{attr} & filter) != 0) return kMaxUInt32;
    return static_cast<uint32_t>(Object::NumberValue(raw_key));
  }

  static uint32_t GetKeyForEntryImpl(Isolate* isolate,
                                     DirectHandle<NumberDictionary> dictionary,
                                     InternalIndex entry,
                                     PropertyFilter filter) {
    DisallowGarbageCollection no_gc;
    Tagged<Object> raw_key = dictionary->KeyAt(isolate, entry);
    if (!dictionary->IsKey(ReadOnlyRoots(isolate), raw_key)) return kMaxUInt32;
    return FilterKey(dictionary, entry, raw_key, filter);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus CollectElementIndicesImpl(
      DirectHandle<JSObject> object, Handle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) {
    if (keys->filter() & SKIP_STRINGS) return ExceptionStatus::kSuccess;
    Isolate* isolate = keys->isolate();
    auto dictionary = Cast<NumberDictionary>(backing_store);
    DirectHandle<FixedArray> elements = isolate->factory()->NewFixedArray(
        GetMaxNumberOfEntries(isolate, *object, *backing_store));
    int insertion_index = 0;
    PropertyFilter filter = keys->filter();
    ReadOnlyRoots roots(isolate);
    for (InternalIndex i : dictionary->IterateEntries()) {
      AllowGarbageCollection allow_gc;
      Tagged<Object> raw_key = dictionary->KeyAt(isolate, i);
      if (!dictionary->IsKey(roots, raw_key)) continue;
      uint32_t key = FilterKey(dictionary, i, raw_key, filter);
      if (key == kMaxUInt32) {
        // This might allocate, but {raw_key} is not used afterwards.
        keys->AddShadowingKey(raw_key, &allow_gc);
        continue;
      }
      elements->set(insertion_index, raw_key);
      insertion_index++;
    }
    SortIndices(isolate, elements, insertion_index);
    for (int i = 0; i < insertion_index; i++) {
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(keys->AddKey(elements->get(i)));
    }
    return ExceptionStatus::kSuccess;
  }

  static Handle<FixedArray> DirectCollectElementIndicesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      Handle<FixedArrayBase> backing_store, GetKeysConversion convert,
      PropertyFilter filter, Handle<FixedArray> list, uint32_t* nof_indices,
      uint32_t insertion_index = 0) {
    if (filter & SKIP_STRINGS) return list;

    auto dictionary = Cast<NumberDictionary>(backing_store);
    for (InternalIndex i : dictionary->IterateEntries()) {
      uint32_t key = GetKeyForEntryImpl(isolate, dictionary, i, filter);
      if (key == kMaxUInt32) continue;
      DirectHandle<Object> index = isolate->factory()->NewNumberFromUint(key);
      list->set(insertion_index, *index);
      insertion_index++;
    }
    *nof_indices = insertion_index;
    return list;
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus AddElementsToKeyAccumulatorImpl(
      DirectHandle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) {
    Isolate* isolate = accumulator->isolate();
    DirectHandle<NumberDictionary> dictionary(
        Cast<NumberDictionary>(receiver->elements()), isolate);
    ReadOnlyRoots roots(isolate);
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k = dictionary->KeyAt(isolate, i);
      if (!dictionary->IsKey(roots, k)) continue;
      Tagged<Object> value = dictionary->ValueAt(isolate, i);
      DCHECK(!IsTheHole(value, isolate));
      DCHECK(!IsAccessorPair(value));
      DCHECK(!IsAccessorInfo(value));
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(accumulator->AddKey(value, convert));
    }
    return ExceptionStatus::kSuccess;
  }

  static bool IncludesValueFastPath(Isolate* isolate,
                                    DirectHandle<JSObject> receiver,
                                    DirectHandle<Object> value,
                                    size_t start_from, size_t length,
                                    Maybe<bool>* result) {
    DisallowGarbageCollection no_gc;
    Tagged<NumberDictionary> dictionary =
        Cast<NumberDictionary>(receiver->elements());
    Tagged<Object> the_hole = ReadOnlyRoots(isolate).the_hole_value();
    Tagged<Object> undefined = ReadOnlyRoots(isolate).undefined_value();

    // Scan for accessor properties. If accessors are present, then elements
    // must be accessed in order via the slow path.
    bool found = false;
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k = dictionary->KeyAt(isolate, i);
      if (k == the_hole) continue;
      if (k == undefined) continue;

      uint32_t index;
      if (!Object::ToArrayIndex(k, &index) || index < start_from ||
          index >= length) {
        continue;
      }

      if (dictionary->DetailsAt(i).kind() == PropertyKind::kAccessor) {
        // Restart from beginning in slow path, otherwise we may observably
        // access getters out of order
        return false;
      } else if (!found) {
        Tagged<Object> element_k = dictionary->ValueAt(isolate, i);
        if (Object::SameValueZero(*value, element_k)) found = true;
      }
    }

    *result = Just(found);
    return true;
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       Handle<JSObject> receiver,
                                       Handle<Object> value, size_t start_from,
                                       size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));
    bool search_for_hole = IsUndefined(*value, isolate);

    if (!search_for_hole) {
      Maybe<bool> result = Nothing<bool>();
      if (DictionaryElementsAccessor::IncludesValueFastPath(
              isolate, receiver, value, start_from, length, &result)) {
        return result;
      }
    }
    ElementsKind original_elements_kind = receiver->GetElementsKind();
    USE(original_elements_kind);
    DirectHandle<NumberDictionary> dictionary(
        Cast<NumberDictionary>(receiver->elements()), isolate);
    // Iterate through the entire range, as accessing elements out of order is
    // observable.
    for (size_t k = start_from; k < length; ++k) {
      DCHECK_EQ(receiver->GetElementsKind(), original_elements_kind);
      InternalIndex entry =
          dictionary->FindEntry(isolate, static_cast<uint32_t>(k));
      if (entry.is_not_found()) {
        if (search_for_hole) return Just(true);
        continue;
      }

      PropertyDetails details = GetDetailsImpl(*dictionary, entry);
      switch (details.kind()) {
        case PropertyKind::kData: {
          Tagged<Object> element_k = dictionary->ValueAt(entry);
          if (Object::SameValueZero(*value, element_k)) return Just(true);
          break;
        }
        case PropertyKind::kAccessor: {
          LookupIterator it(isolate, receiver, k,
                            LookupIterator::OWN_SKIP_INTERCEPTOR);
          DCHECK(it.IsFound());
          DCHECK_EQ(it.state(), LookupIterator::ACCESSOR);
          Handle<Object> element_k;

          ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                           Object::GetPropertyWithAccessor(&it),
                                           Nothing<bool>());

          if (Object::SameValueZero(*value, *element_k)) return Just(true);

          // Bailout to slow path if elements on prototype changed
          if (!JSObject::PrototypeHasNoElements(isolate, *receiver)) {
            return IncludesValueSlowPath(isolate, receiver, value, k + 1,
                                         length);
          }

          // Continue if elements unchanged
          if (*dictionary == receiver->elements()) continue;

          // Otherwise, bailout or update elements

          // If switched to initial elements, return true if searching for
          // undefined, and false otherwise.
          if (receiver->map()->GetInitialElements() == receiver->elements()) {
            return Just(search_for_hole);
          }

          // If switched to fast elements, continue with the correct accessor.
          if (receiver->GetElementsKind() != DICTIONARY_ELEMENTS) {
            ElementsAccessor* accessor = receiver->GetElementsAccessor();
            return accessor->IncludesValue(isolate, receiver, value, k + 1,
                                           length);
          }
          dictionary =
              handle(Cast<NumberDictionary>(receiver->elements()), isolate);
          break;
        }
      }
    }
    return Just(false);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         Handle<JSObject> receiver,
                                         DirectHandle<Object> value,
                                         size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));

    ElementsKind original_elements_kind = receiver->GetElementsKind();
    USE(original_elements_kind);
    DirectHandle<NumberDictionary> dictionary(
        Cast<NumberDictionary>(receiver->elements()), isolate);
    // Iterate through entire range, as accessing elements out of order is
    // observable.
    for (size_t k = start_from; k < length; ++k) {
      DCHECK_EQ(receiver->GetElementsKind(), original_elements_kind);
      DCHECK_LE(k, std::numeric_limits<uint32_t>::max());
      InternalIndex entry =
          dictionary->FindEntry(isolate, static_cast<uint32_t>(k));
      if (entry.is_not_found()) continue;

      PropertyDetails details =
          GetDetailsImpl(*dictionary, InternalIndex(entry));
      switch (details.kind()) {
        case PropertyKind::kData: {
          Tagged<Object> element_k = dictionary->ValueAt(entry);
          if (Object::StrictEquals(*value, element_k)) {
            return Just<int64_t>(k);
          }
          break;
        }
        case PropertyKind::kAccessor: {
          LookupIterator it(isolate, receiver, k,
                            LookupIterator::OWN_SKIP_INTERCEPTOR);
          DCHECK(it.IsFound());
          DCHECK_EQ(it.state(), LookupIterator::ACCESSOR);
          Handle<Object> element_k;

          ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                           Object::GetPropertyWithAccessor(&it),
                                           Nothing<int64_t>());

          if (Object::StrictEquals(*value, *element_k)) return Just<int64_t>(k);

          // Bailout to slow path if elements on prototype changed.
          if (!JSObject::PrototypeHasNoElements(isolate, *receiver)) {
            return IndexOfValueSlowPath(isolate, receiver, value, k + 1,
                                        length);
          }

          // Continue if elements unchanged.
          if (*dictionary == receiver->elements()) continue;

          // Otherwise, bailout or update elements.
          if (receiver->GetElementsKind() != DICTIONARY_ELEMENTS) {
            // Otherwise, switch to slow path.
            return IndexOfValueSlowPath(isolate, receiver, value, k + 1,
                                        length);
          }
          dictionary = direct_handle(
              Cast<NumberDictionary>(receiver->elements()), isolate);
          break;
        }
      }
    }
    return Just<int64_t>(-1);
  }

  static void ValidateContents(Tagged<JSObject> holder, size_t length) {
    DisallowGarbageCollection no_gc;
#if DEBUG
    DCHECK_EQ(holder->map()->elements_kind(), DICTIONARY_ELEMENTS);
    if (!v8_flags.enable_slow_asserts) return;
    ReadOnlyRoots roots = holder->GetReadOnlyRoots();
    Tagged<NumberDictionary> dictionary =
        Cast<NumberDictionary>(holder->elements());
    // Validate the requires_slow_elements and max_number_key values.
    bool requires_slow_elements = false;
    int max_key = 0;
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> k;
      if (!dictionary->ToKey(roots, i, &k)) continue;
      DCHECK_LE(0.0, Object::NumberValue(k));
      if (Object::NumberValue(k) >
          NumberDictionary::kRequiresSlowElementsLimit) {
        requires_slow_elements = true;
      } else {
        max_key = std::max(max_key, Smi::ToInt(k));
      }
    }
    if (requires_slow_elements) {
      DCHECK(dictionary->requires_slow_elements());
    } else if (!dictionary->requires_slow_elements()) {
      DCHECK_LE(max_key, dictionary->max_number_key());
    }
#endif
  }
};

// Super class for all fast element arrays.
template <typename Subclass, typename KindTraits>
class FastElementsAccessor : public ElementsAccessorBase<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static Handle<NumberDictionary> NormalizeImpl(
      Handle<JSObject> object, DirectHandle<FixedArrayBase> store) {
    Isolate* isolate = object->GetIsolate();
    ElementsKind kind = Subclass::kind();

    // Ensure that notifications fire if the array or object prototypes are
    // normalizing.
    if (IsSmiOrObjectElementsKind(kind) ||
        kind == FAST_STRING_WRAPPER_ELEMENTS) {
      isolate->UpdateNoElementsProtectorOnNormalizeElements(object);
    }

    int capacity = object->GetFastElementsUsage();
    Handle<NumberDictionary> dictionary =
        NumberDictionary::New(isolate, capacity);

    PropertyDetails details = PropertyDetails::Empty();
    int j = 0;
    int max_number_key = -1;
    for (int i = 0; j < capacity; i++) {
      if (IsHoleyElementsKindForRead(kind)) {
        if (Cast<BackingStore>(*store)->is_the_hole(isolate, i)) continue;
      }
      max_number_key = i;
      DirectHandle<Object> value =
          Subclass::GetImpl(isolate, *store, InternalIndex(i));
      dictionary =
          NumberDictionary::Add(isolate, dictionary, i, value, details);
      j++;
    }

    if (max_number_key > 0) {
      dictionary->UpdateMaxNumberKey(static_cast<uint32_t>(max_number_key),
                                     object);
    }
    return dictionary;
  }

  static void DeleteAtEnd(DirectHandle<JSObject> obj,
                          Handle<BackingStore> backing_store, uint32_t entry) {
    uint32_t length = static_cast<uint32_t>(backing_store->length());
    DCHECK_LT(entry, length);
    Isolate* isolate = obj->GetIsolate();
    for (; entry > 0; entry--) {
      if (!backing_store->is_the_hole(isolate, entry - 1)) break;
    }
    if (entry == 0) {
      Tagged<FixedArray> empty = ReadOnlyRoots(isolate).empty_fixed_array();
      // Dynamically ask for the elements kind here since we manually redirect
      // the operations for argument backing stores.
      if (obj->GetElementsKind() == FAST_SLOPPY_ARGUMENTS_ELEMENTS) {
        Cast<SloppyArgumentsElements>(obj->elements())->set_arguments(empty);
      } else {
        obj->set_elements(empty);
      }
      return;
    }

    isolate->heap()->RightTrimArray(*backing_store, entry, length);
  }

  static void DeleteCommon(Handle<JSObject> obj, uint32_t entry,
                           Handle<FixedArrayBase> store) {
    DCHECK(obj->HasSmiOrObjectElements() || obj->HasDoubleElements() ||
           obj->HasNonextensibleElements() || obj->HasFastArgumentsElements() ||
           obj->HasFastStringWrapperElements());
    Handle<BackingStore> backing_store = Cast<BackingStore>(store);
    if (!IsJSArray(*obj) &&
        entry == static_cast<uint32_t>(store->length()) - 1) {
      DeleteAtEnd(obj, backing_store, entry);
      return;
    }

    Isolate* isolate = obj->GetIsolate();
    backing_store->set_the_hole(isolate, entry);

    // TODO(verwaest): Move this out of elements.cc.
    // If the backing store is larger than a certain size and
    // has too few used values, normalize it.
    const int kMinLengthForSparsenessCheck = 64;
    if (backing_store->length() < kMinLengthForSparsenessCheck) return;
    uint32_t length = 0;
    if (IsJSArray(*obj)) {
      Object::ToArrayLength(Cast<JSArray>(*obj)->length(), &length);
    } else {
      length = static_cast<uint32_t>(store->length());
    }

    // To avoid doing the check on every delete, use a counter-based heuristic.
    const int kLengthFraction = 16;
    // The above constant must be large enough to ensure that we check for
    // normalization frequently enough. At a minimum, it should be large
    // enough to reliably hit the "window" of remaining elements count where
    // normalization would be beneficial.
    static_assert(kLengthFraction >=
                  NumberDictionary::kEntrySize *
                      NumberDictionary::kPreferFastElementsSizeFactor);
    size_t current_counter = isolate->elements_deletion_counter();
    if (current_counter < length / kLengthFraction) {
      isolate->set_elements_deletion_counter(current_counter + 1);
      return;
    }
    // Reset the counter whenever the full check is performed.
    isolate->set_elements_deletion_counter(0);

    if (!IsJSArray(*obj)) {
      uint32_t i;
      for (i = entry + 1; i < length; i++) {
        if (!backing_store->is_the_hole(isolate, i)) break;
      }
      if (i == length) {
        DeleteAtEnd(obj, backing_store, entry);
        return;
      }
    }
    int num_used = 0;
    for (int i = 0; i < backing_store->length(); ++i) {
      if (!backing_store->is_the_hole(isolate, i)) {
        ++num_used;
        // Bail out if a number dictionary wouldn't be able to save much space.
        if (NumberDictionary::kPreferFastElementsSizeFactor *
                NumberDictionary::ComputeCapacity(num_used) *
                NumberDictionary::kEntrySize >
            static_cast<uint32_t>(backing_store->length())) {
          return;
        }
      }
    }
    JSObject::NormalizeElements(obj);
  }

  static void ReconfigureImpl(Handle<JSObject> object,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    Handle<NumberDictionary> dictionary = JSObject::NormalizeElements(object);
    entry = InternalIndex(
        dictionary->FindEntry(object->GetIsolate(), entry.as_uint32()));
    DictionaryElementsAccessor::ReconfigureImpl(
        object, Cast<FixedArrayBase>(dictionary), entry, value, attributes);
  }

  static Maybe<bool> AddImpl(Handle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    DCHECK_EQ(NONE, attributes);
    ElementsKind from_kind = object->GetElementsKind();
    ElementsKind to_kind = Subclass::kind();
    if (IsDictionaryElementsKind(from_kind) ||
        IsDoubleElementsKind(from_kind) != IsDoubleElementsKind(to_kind) ||
        Subclass::GetCapacityImpl(*object, object->elements()) !=
            new_capacity) {
      MAYBE_RETURN(Subclass::GrowCapacityAndConvertImpl(object, new_capacity),
                   Nothing<bool>());
    } else {
      if (IsFastElementsKind(from_kind) && from_kind != to_kind) {
        JSObject::TransitionElementsKind(object, to_kind);
      }
      if (IsSmiOrObjectElementsKind(from_kind)) {
        DCHECK(IsSmiOrObjectElementsKind(to_kind));
        JSObject::EnsureWritableFastElements(object);
      }
    }
    Subclass::SetImpl(object, InternalIndex(index), *value);
    return Just(true);
  }

  static void DeleteImpl(Handle<JSObject> obj, InternalIndex entry) {
    ElementsKind kind = KindTraits::Kind;
    if (IsFastPackedElementsKind(kind) ||
        kind == PACKED_NONEXTENSIBLE_ELEMENTS) {
      JSObject::TransitionElementsKind(obj, GetHoleyElementsKind(kind));
    }
    if (IsSmiOrObjectElementsKind(KindTraits::Kind) ||
        IsNonextensibleElementsKind(kind)) {
      JSObject::EnsureWritableFastElements(obj);
    }
    DeleteCommon(obj, entry.as_uint32(),
                 handle(obj->elements(), obj->GetIsolate()));
  }

  static bool HasEntryImpl(Isolate* isolate,
                           Tagged<FixedArrayBase> backing_store,
                           InternalIndex entry) {
    return !Cast<BackingStore>(backing_store)
                ->is_the_hole(isolate, entry.as_int());
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> receiver,
                                       Tagged<FixedArrayBase> backing_store) {
    size_t max_index = Subclass::GetMaxIndex(receiver, backing_store);
    DCHECK_LE(max_index, std::numeric_limits<uint32_t>::max());
    if (IsFastPackedElementsKind(Subclass::kind())) {
      return static_cast<uint32_t>(max_index);
    }
    uint32_t count = 0;
    for (size_t i = 0; i < max_index; i++) {
      if (Subclass::HasEntryImpl(isolate, backing_store, InternalIndex(i))) {
        count++;
      }
    }
    return count;
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus AddElementsToKeyAccumulatorImpl(
      DirectHandle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) {
    Isolate* isolate = accumulator->isolate();
    DirectHandle<FixedArrayBase> elements(receiver->elements(), isolate);
    size_t length =
        Subclass::GetMaxNumberOfEntries(isolate, *receiver, *elements);
    for (size_t i = 0; i < length; i++) {
      if (IsFastPackedElementsKind(KindTraits::Kind) ||
          HasEntryImpl(isolate, *elements, InternalIndex(i))) {
        RETURN_FAILURE_IF_NOT_SUCCESSFUL(accumulator->AddKey(
            Subclass::GetImpl(isolate, *elements, InternalIndex(i)), convert));
      }
    }
    return ExceptionStatus::kSuccess;
  }

  static void ValidateContents(Tagged<JSObject> holder, size_t length) {
#if DEBUG
    Isolate* isolate = holder->GetIsolate();
    Heap* heap = isolate->heap();
    Tagged<FixedArrayBase> elements = holder->elements();
    Tagged<Map> map = elements->map();
    if (IsSmiOrObjectElementsKind(KindTraits::Kind)) {
      DCHECK_NE(map, ReadOnlyRoots(heap).fixed_double_array_map());
    } else if (IsDoubleElementsKind(KindTraits::Kind)) {
      DCHECK_NE(map, ReadOnlyRoots(heap).fixed_cow_array_map());
      if (map == ReadOnlyRoots(heap).fixed_array_map()) DCHECK_EQ(0u, length);
    } else {
      UNREACHABLE();
    }
    if (length == 0u) return;  // nothing to do!
#if ENABLE_SLOW_DCHECKS
    DisallowGarbageCollection no_gc;
    Tagged<BackingStore> backing_store = Cast<BackingStore>(elements);
    DCHECK(length <= std::numeric_limits<int>::max());
    int length_int = static_cast<int>(length);
    if (IsSmiElementsKind(KindTraits::Kind)) {
      HandleScope scope(isolate);
      for (int i = 0; i < length_int; i++) {
        Tagged<Object> element = Cast<FixedArray>(backing_store)->get(i);
        DCHECK(IsSmi(element) || (IsHoleyElementsKind(KindTraits::Kind) &&
                                  IsTheHole(element, isolate)));
      }
    } else if (KindTraits::Kind == PACKED_ELEMENTS ||
               KindTraits::Kind == PACKED_DOUBLE_ELEMENTS) {
      for (int i = 0; i < length_int; i++) {
        DCHECK(!backing_store->is_the_hole(isolate, i));
      }
    } else {
      DCHECK(IsHoleyElementsKind(KindTraits::Kind));
    }
#endif
#endif
  }

  static MaybeHandle<Object> PopImpl(Handle<JSArray> receiver) {
    return Subclass::RemoveElement(receiver, AT_END);
  }

  static MaybeHandle<Object> ShiftImpl(Handle<JSArray> receiver) {
    return Subclass::RemoveElement(receiver, AT_START);
  }

  static Maybe<uint32_t> P
```