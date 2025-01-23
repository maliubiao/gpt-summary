Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/elements.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The code defines a template class `ElementsAccessorBase`. This immediately suggests a base class for handling elements of JavaScript objects (specifically arrays).

2. **Notice the Template Parameters:** The template takes `Subclass` and `Traits`. This indicates a design pattern where different element access strategies will inherit from this base and provide specific implementations. The `Traits` parameter likely holds information about the specific element kind.

3. **Scan for Virtual and Static Methods:**  The presence of `virtual` and `final` methods like `Get`, `Set`, `Add`, `Delete`, etc., suggests an interface for interacting with object elements. The `static` methods, often with `Impl` suffixes, hint at the actual implementations being provided by the derived classes. The `UNREACHABLE()` calls in the base class reinforce that this is an abstract-like base providing a common interface.

4. **Look for Method Names Related to Common JavaScript Array Operations:** Method names like `Push`, `Pop`, `Shift`, `Unshift`, `SetLength`, `Fill`, `IncludesValue`, `IndexOfValue`, `LastIndexOfValue`, and `Reverse` strongly suggest that this code is related to the implementation of JavaScript array methods.

5. **Pay Attention to Types:**  The use of `Handle`, `DirectHandle`, `Maybe`, `MaybeHandle`, `Tagged`, `FixedArrayBase`, `FixedArray`, `NumberDictionary`, `JSObject`, and `JSArray` are all V8-specific types related to memory management and object representation. This confirms we're dealing with V8 internals.

6. **Identify Key Concepts:**
    * **Elements Kind:**  The code frequently refers to `ElementsKind`. This is a crucial concept in V8, representing the internal storage type of an array (e.g., packed integers, doubles, holes, dictionary). The code handles transitions between these kinds.
    * **Backing Store:**  The terms `backing_store` and `elements` refer to the underlying memory where the array elements are stored.
    * **Capacity:**  The code manages the capacity of the backing store, growing and potentially shrinking it as needed.
    * **Holes:** The concept of "holes" in arrays (where an element is logically absent) is explicitly handled.
    * **Dictionary Elements:** The `DictionaryElementsAccessor` class points to a different storage strategy using hash tables for sparse arrays.
    * **Property Attributes:** The code deals with `PropertyAttributes`, indicating that it handles more than just simple values, including properties' enumerability, writability, and configurability.

7. **Infer Functionality from Method Signatures and Names:**
    * **Get/Set:**  Basic access to elements at specific indices.
    * **Add:**  Adding elements, potentially resizing the array.
    * **Push/Pop/Shift/Unshift:** Implementing the standard array manipulation methods.
    * **SetLength:** Resizing the array, handling hole creation and potential shrinking/growing of the backing store.
    * **TransitionElementsKind:** Changing the internal storage representation of the array elements.
    * **GrowCapacity:**  Increasing the size of the backing store.
    * **Normalize:** Converting the array to a dictionary representation.
    * **CollectValuesOrEntries/CollectElementIndices:**  Iterating over array elements and collecting their values or indices.
    * **Fill/IncludesValue/IndexOfValue/LastIndexOfValue/Reverse:** Implementing other common array methods.
    * **CopyElements:**  Copying elements between arrays.
    * **Delete:**  Removing elements from the array.

8. **Connect to JavaScript:**  The function names directly correspond to common JavaScript array methods. The concept of "elements kind" relates to how JavaScript engines optimize array storage.

9. **Consider Potential Errors:**  The code deals with resizing and type transitions. Common JavaScript errors related to arrays include setting invalid lengths or causing unexpected type changes, leading to performance issues or errors.

10. **Synthesize the Summary:** Combine the identified concepts and functionalities into a concise description of the code's purpose. Emphasize the role of the base class and the handling of different element kinds.

11. **Address Specific Instructions:**  Go back to the user's prompt and ensure all specific points are covered:
    * Mention it's C++ source.
    * Note the `.cc` extension (and contrast with `.tq`).
    * Explain its relation to JavaScript array functionality and provide examples.
    * Acknowledge the lack of concrete implementations in the provided snippet makes detailed input/output reasoning difficult.
    * List common programming errors.
    * Summarize the functionality as requested in the last part of the prompt.
```cpp
,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    UNREACHABLE();
  }

  Maybe<bool> Add(Handle<JSObject> object, uint32_t index,
                  DirectHandle<Object> value, PropertyAttributes attributes,
                  uint32_t new_capacity) final {
    return Subclass::AddImpl(object, index, value, attributes, new_capacity);
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  Maybe<uint32_t> Push(Handle<JSArray> receiver, BuiltinArguments* args,
                       uint32_t push_size) final {
    return Subclass::PushImpl(receiver, args, push_size);
  }

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_sized) {
    UNREACHABLE();
  }

  Maybe<uint32_t> Unshift(Handle<JSArray> receiver, BuiltinArguments* args,
                          uint32_t unshift_size) final {
    return Subclass::UnshiftImpl(receiver, args, unshift_size);
  }

  static Maybe<uint32_t> UnshiftImpl(DirectHandle<JSArray> receiver,
                                     BuiltinArguments* args,
                                     uint32_t unshift_size) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Pop(Handle<JSArray> receiver) final {
    return Subclass::PopImpl(receiver);
  }

  static MaybeHandle<Object> PopImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Shift(Handle<JSArray> receiver) final {
    return Subclass::ShiftImpl(receiver);
  }

  static MaybeHandle<Object> ShiftImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  Maybe<bool> SetLength(Handle<JSArray> array, uint32_t length) final {
    return Subclass::SetLengthImpl(
        array->GetIsolate(), array, length,
        handle(array->elements(), array->GetIsolate()));
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate, Handle<JSArray> array,
                                   uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    DCHECK(!array->SetLengthWouldNormalize(length));
    DCHECK(IsFastElementsKind(array->GetElementsKind()));
    uint32_t old_length = 0;
    CHECK(Object::ToArrayIndex(array->length(), &old_length));

    if (old_length < length) {
      ElementsKind kind = array->GetElementsKind();
      if (!IsHoleyElementsKind(kind)) {
        kind = GetHoleyElementsKind(kind);
        JSObject::TransitionElementsKind(array, kind);
      }
    }

    // Check whether the backing store should be shrunk.
    uint32_t capacity = backing_store->length();
    old_length = std::min(old_length, capacity);
    if (length == 0) {
      array->initialize_elements();
    } else if (length <= capacity) {
      if (IsSmiOrObjectElementsKind(kind())) {
        JSObject::EnsureWritableFastElements(array);
        if (array->elements() != *backing_store) {
          backing_store = handle(array->elements(), isolate);
        }
      }
      if (2 * length + JSObject::kMinAddedElementsCapacity <= capacity) {
        // If more than half the elements won't be used, trim the array.
        // Do not trim from short arrays to prevent frequent trimming on
        // repeated pop operations.
        // Leave some space to allow for subsequent push operations.
        uint32_t new_capacity =
            length + 1 == old_length ? (capacity + length) / 2 : length;
        DCHECK_LT(new_capacity, capacity);
        isolate->heap()->RightTrimArray(Cast<BackingStore>(*backing_store),
                                        new_capacity, capacity);
        // Fill the non-trimmed elements with holes.
        Cast<BackingStore>(*backing_store)
            ->FillWithHoles(length, std::min(old_length, new_capacity));
      } else {
        // Otherwise, fill the unused tail with holes.
        Cast<BackingStore>(*backing_store)->FillWithHoles(length, old_length);
      }
    } else {
      // Check whether the backing store should be expanded.
      capacity = std::max(length, JSObject::NewElementsCapacity(capacity));
      MAYBE_RETURN(Subclass::GrowCapacityAndConvertImpl(array, capacity),
                   Nothing<bool>());
    }

    array->set_length(Smi::FromInt(length));
    JSObject::ValidateElements(*array);
    return Just(true);
  }

  size_t NumberOfElements(Isolate* isolate, Tagged<JSObject> receiver) final {
    return Subclass::NumberOfElementsImpl(isolate, receiver,
                                          receiver->elements());
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> receiver,
                                       Tagged<FixedArrayBase> backing_store) {
    UNREACHABLE();
  }

  static size_t GetMaxIndex(Tagged<JSObject> receiver,
                            Tagged<FixedArrayBase> elements) {
    if (IsJSArray(receiver)) {
      DCHECK(IsSmi(Cast<JSArray>(receiver)->length()));
      return static_cast<uint32_t>(
          Smi::ToInt(Cast<JSArray>(receiver)->length()));
    }
    return Subclass::GetCapacityImpl(receiver, elements);
  }

  static size_t GetMaxNumberOfEntries(Isolate* isolate,
                                      Tagged<JSObject> receiver,
                                      Tagged<FixedArrayBase> elements) {
    return Subclass::GetMaxIndex(receiver, elements);
  }

  static MaybeHandle<FixedArrayBase> ConvertElementsWithCapacity(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, uint32_t capacity) {
    return ConvertElementsWithCapacity(object, old_elements, from_kind,
                                       capacity, 0, 0);
  }

  static MaybeHandle<FixedArrayBase> ConvertElementsWithCapacity(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> old_elements,
      ElementsKind from_kind, uint32_t capacity, uint32_t src_index,
      uint32_t dst_index) {
    Isolate* isolate = object->GetIsolate();
    Handle<FixedArrayBase> new_elements;
    // TODO(victorgomes): Retrieve native context in optimized code
    // and remove the check isolate->context().is_null().
    if (IsDoubleElementsKind(kind())) {
      if (!isolate->context().is_null() &&
          !base::IsInRange(capacity, 0, FixedDoubleArray::kMaxLength)) {
        THROW_NEW_ERROR(isolate,
                        NewRangeError(MessageTemplate::kInvalidArrayLength));
      }
      new_elements = isolate->factory()->NewFixedDoubleArray(capacity);
    } else {
      if (!isolate->context().is_null() &&
          !base::IsInRange(capacity, 0, FixedArray::kMaxLength)) {
        THROW_NEW_ERROR(isolate,
                        NewRangeError(MessageTemplate::kInvalidArrayLength));
      }
      new_elements = isolate->factory()->NewFixedArray(capacity);
    }

    int packed_size = kPackedSizeNotKnown;
    if (IsFastPackedElementsKind(from_kind) && IsJSArray(*object)) {
      packed_size = Smi::ToInt(Cast<JSArray>(*object)->length());
    }

    Subclass::CopyElementsImpl(isolate, *old_elements, src_index, *new_elements,
                               from_kind, dst_index, packed_size,
                               kCopyToEndAndInitializeToHole);

    return MaybeHandle<FixedArrayBase>(new_elements);
  }

  static Maybe<bool> TransitionElementsKindImpl(Handle<JSObject> object,
                                                DirectHandle<Map> to_map) {
    Isolate* isolate = object->GetIsolate();
    DirectHandle<Map> from_map(object->map(), isolate);
    ElementsKind from_kind = from_map->elements_kind();
    ElementsKind to_kind = to_map->elements_kind();
    if (IsHoleyElementsKind(from_kind)) {
      to_kind = GetHoleyElementsKind(to_kind);
    }
    if (from_kind != to_kind) {
      // This method should never be called for any other case.
      DCHECK(IsFastElementsKind(from_kind));
      DCHECK(IsFastElementsKind(to_kind));
      DCHECK_NE(TERMINAL_FAST_ELEMENTS_KIND, from_kind);

      Handle<FixedArrayBase> from_elements(object->elements(), isolate);
      if (object->elements() == ReadOnlyRoots(isolate).empty_fixed_array() ||
          IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind)) {
        // No change is needed to the elements() buffer, the transition
        // only requires a map change.
        JSObject::MigrateToMap(isolate, object, to_map);
      } else {
        DCHECK(
            (IsSmiElementsKind(from_kind) && IsDoubleElementsKind(to_kind)) ||
            (IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind)));
        uint32_t capacity = static_cast<uint32_t>(object->elements()->length());
        Handle<FixedArrayBase> elements;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            object->GetIsolate(), elements,
            ConvertElementsWithCapacity(object, from_elements, from_kind,
                                        capacity),
            Nothing<bool>());
        JSObject::SetMapAndElements(object, to_map, elements);
      }
      if (v8_flags.trace_elements_transitions) {
        JSObject::PrintElementsTransition(stdout, object, from_kind,
                                          from_elements, to_kind,
                                          handle(object->elements(), isolate));
      }
    }
    return Just(true);
  }

  static Maybe<bool> GrowCapacityAndConvertImpl(Handle<JSObject> object,
                                                uint32_t capacity) {
    ElementsKind from_kind = object->GetElementsKind();
    if (IsSmiOrObjectElementsKind(from_kind)) {
      // Array optimizations rely on the prototype lookups of Array objects
      // always returning undefined. If there is a store to the initial
      // prototype object, make sure all of these optimizations are invalidated.
      object->GetIsolate()->UpdateNoElementsProtectorOnSetLength(object);
    }
    Handle<FixedArrayBase> old_elements(object->elements(),
                                        object->GetIsolate());
    // This method should only be called if there's a reason to update the
    // elements.
    DCHECK(IsDoubleElementsKind(from_kind) != IsDoubleElementsKind(kind()) ||
           IsDictionaryElementsKind(from_kind) ||
           static_cast<uint32_t>(old_elements->length()) < capacity);
    return Subclass::BasicGrowCapacityAndConvertImpl(
        object, old_elements, from_kind, kind(), capacity);
  }

  static Maybe<bool> BasicGrowCapacityAndConvertImpl(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, ElementsKind to_kind, uint32_t capacity) {
    Handle<FixedArrayBase> elements;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        object->GetIsolate(), elements,
        ConvertElementsWithCapacity(object, old_elements, from_kind, capacity),
        Nothing<bool>());

    if (IsHoleyElementsKind(from_kind)) {
      to_kind = GetHoleyElementsKind(to_kind);
    }
    DirectHandle<Map> new_map =
        JSObject::GetElementsTransitionMap(object, to_kind);
    JSObject::SetMapAndElements(object, new_map, elements);

    // Transition through the allocation site as well if present.
    JSObject::UpdateAllocationSite(object, to_kind);

    if (v8_flags.trace_elements_transitions) {
      JSObject::PrintElementsTransition(stdout, object, from_kind, old_elements,
                                        to_kind, elements);
    }
    return Just(true);
  }

  Maybe<bool> TransitionElementsKind(Handle<JSObject> object,
                                     Handle<Map> map) final {
    return Subclass::TransitionElementsKindImpl(object, map);
  }

  Maybe<bool> GrowCapacityAndConvert(Handle<JSObject> object,
                                     uint32_t capacity) final {
    return Subclass::GrowCapacityAndConvertImpl(object, capacity);
  }

  Maybe<bool> GrowCapacity(Handle<JSObject> object, uint32_t index) final {
    // This function is intended to be called from optimized code. We don't
    // want to trigger lazy deopts there, so refuse to handle cases that would.
    if (object->map()->is_prototype_map() ||
        object->WouldConvertToSlowElements(index)) {
      return Just(false);
    }
    Handle<FixedArrayBase> old_elements(object->elements(),
                                        object->GetIsolate());
    uint32_t new_capacity = JSObject::NewElementsCapacity(index + 1);
    DCHECK(static_cast<uint32_t>(old_elements->length()) < new_capacity);
    const uint32_t kMaxLength = IsDoubleElementsKind(kind())
                                    ? FixedDoubleArray::kMaxLength
                                    : FixedArray::kMaxLength;
    if (new_capacity > kMaxLength) {
      return Just(false);
    }
    Handle<FixedArrayBase> elements;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        object->GetIsolate(), elements,
        ConvertElementsWithCapacity(object, old_elements, kind(), new_capacity),
        Nothing<bool>());

    DCHECK_EQ(object->GetElementsKind(), kind());
    // Transition through the allocation site as well if present.
    if (JSObject::UpdateAllocationSite<AllocationSiteUpdateMode::kCheckOnly>(
            object, kind())) {
      return Just(false);
    }

    object->set_elements(*elements);
    return Just(true);
  }

  void Delete(Handle<JSObject> obj, InternalIndex entry) final {
    Subclass::DeleteImpl(obj, entry);
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    UNREACHABLE();
  }

  void CopyElements(Isolate* isolate, Tagged<JSObject> from_holder,
                    uint32_t from_start, ElementsKind from_kind,
                    Handle<FixedArrayBase> to, uint32_t to_start,
                    int copy_size) final {
    int packed_size = kPackedSizeNotKnown;
    bool is_packed =
        IsFastPackedElementsKind(from_kind) && IsJSArray(from_holder);
    if (is_packed) {
      packed_size = Smi::ToInt(Cast<JSArray>(from_holder)->length());
      if (copy_size >= 0 && packed_size > copy_size) {
        packed_size = copy_size;
      }
    }
    Tagged<FixedArrayBase> from = from_holder->elements();
    // NOTE: the Subclass::CopyElementsImpl() methods
    // violate the handlified function signature convention:
    // raw pointer parameters in the function that allocates. This is done
    // intentionally to avoid ArrayConcat() builtin performance degradation.
    //
    // Details: The idea is that allocations actually happen only in case of
    // copying from object with fast double elements to object with object
    // elements. In all the other cases there are no allocations performed and
    // handle creation causes noticeable performance degradation of the builtin.
    Subclass::CopyElementsImpl(isolate, from, from_start, *to, from_kind,
                               to_start, packed_size, copy_size);
  }

  void CopyElements(Isolate* isolate, Handle<FixedArrayBase> source,
                    ElementsKind source_kind,
                    Handle<FixedArrayBase> destination, int size) override {
    Subclass::CopyElementsImpl(isolate, *source, 0, *destination, source_kind,
                               0, kPackedSizeNotKnown, size);
  }

  void CopyTypedArrayElementsSlice(Tagged<JSTypedArray> source,
                                   Tagged<JSTypedArray> destination,
                                   size_t start, size_t end) override {
    Subclass::CopyTypedArrayElementsSliceImpl(source, destination, start, end);
  }

  static void CopyTypedArrayElementsSliceImpl(Tagged<JSTypedArray> source,
                                              Tagged<JSTypedArray> destination,
                                              size_t start, size_t end) {
    UNREACHABLE();
  }

  Tagged<Object> CopyElements(Handle<JSAny> source,
                              Handle<JSObject> destination, size_t length,
                              size_t offset) final {
    return Subclass::CopyElementsHandleImpl(source, destination, length,
                                            offset);
  }

  static Tagged<Object> CopyElementsHandleImpl(
      DirectHandle<Object> source, DirectHandle<JSObject> destination,
      size_t length, size_t offset) {
    UNREACHABLE();
  }

  Handle<NumberDictionary> Normalize(Handle<JSObject> object) final {
    return Subclass::NormalizeImpl(
        object, handle(object->elements(), object->GetIsolate()));
  }

  static Handle<NumberDictionary> NormalizeImpl(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> elements) {
    UNREACHABLE();
  }

  Maybe<bool> CollectValuesOrEntries(Isolate* isolate, Handle<JSObject> object,
                                     Handle<FixedArray> values_or_entries,
                                     bool get_entries, int* nof_items,
                                     PropertyFilter filter) override {
    return Subclass::CollectValuesOrEntriesImpl(
        isolate, object, values_or_entries, get_entries, nof_items, filter);
  }

  static Maybe<bool> CollectValuesOrEntriesImpl(
      Isolate* isolate, Handle<JSObject> object,
      DirectHandle<FixedArray> values_or_entries, bool get_entries,
      int* nof_items, PropertyFilter filter) {
    DCHECK_EQ(*nof_items, 0);
    KeyAccumulator accumulator(isolate, KeyCollectionMode::kOwnOnly,
                               ALL_PROPERTIES);
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(Subclass::CollectElementIndicesImpl(
        object, handle(object->elements(), isolate), &accumulator));
    DirectHandle<FixedArray> keys = accumulator.GetKeys();

    int count = 0;
    int i = 0;
    ElementsKind original_elements_kind = object->GetElementsKind();

    for (; i < keys->length(); ++i) {
      DirectHandle<Object> key(keys->get(i), isolate);
      uint32_t index;
      if (!Object::ToUint32(*key, &index)) continue;

      DCHECK_EQ(object->GetElementsKind(), original_elements_kind);
      InternalIndex entry = Subclass::GetEntryForIndexImpl(
          isolate, *object, object->elements(), index, filter);
      if (entry.is_not_found()) continue;
      PropertyDetails details = Subclass::GetDetailsImpl(*object, entry);

      DirectHandle<Object> value;
      if (details.kind() == PropertyKind::kData) {
        value = Subclass::GetInternalImpl(isolate, object, entry);
      } else {
        // This might modify the elements and/or change the elements kind.
        LookupIterator it(isolate, object, index, LookupIterator::OWN);
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, value, Object::GetProperty(&it), Nothing<bool>());
      }
      if (get_entries) value = MakeEntryPair(isolate, index, value);
      values_or_entries->set(count++, *value);
      if (object->GetElementsKind() != original_elements_kind) break;
    }

    // Slow path caused by changes in elements kind during iteration.
    for (; i < keys->length(); i++) {
      DirectHandle<Object> key(keys->get(i), isolate);
      uint32_t index;
      if (!Object::ToUint32(*key, &index)) continue;

      if (filter & ONLY_ENUMERABLE) {
        InternalElementsAccessor* accessor =
            reinterpret_cast<InternalElementsAccessor*>(
                object->GetElementsAccessor());
        InternalIndex entry = accessor->GetEntryForIndex(
            isolate, *object, object->elements(), index);
        if (entry.is_not_found()) continue;
        PropertyDetails details = accessor->GetDetails(*object, entry);
        if (!details.IsEnumerable()) continue;
      }

      Handle<Object> value;
      LookupIterator it(isolate, object, index, LookupIterator::OWN);
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, value, Object::GetProperty(&it),
                                       Nothing<bool>());

      if (get_entries) value = MakeEntryPair(isolate, index, value);
      values_or_entries->set(count++, *value);
    }

    *nof_items = count;
    return Just(true);
  }

  V8_WARN_UNUSED_RESULT ExceptionStatus CollectElementIndices(
      Handle<JSObject> object, Handle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) final {
    return Subclass::CollectElementIndicesImpl(object, backing_store, keys);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus CollectElementIndicesImpl(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) {
    DCHECK_NE(DICTIONARY_ELEMENTS, kind());
    // Non-dictionary elements can't have all-can-read accessors.
    size_t length = Subclass::GetMaxIndex(*object, *backing_store);
    PropertyFilter filter = keys->filter();
    Isolate* isolate = keys->isolate();
    Factory* factory = isolate->factory();
    for (size_t i = 0; i < length; i++) {
      if (Subclass::HasElementImpl(isolate, *object, i, *backing_store,
                                   filter)) {
        RETURN_FAILURE_IF_NOT_SUCCESSFUL(
            keys->AddKey(factory->NewNumberFromSize(i)));
      }
    }
    return ExceptionStatus::kSuccess;
  }

  static Handle<FixedArray> DirectCollectElementIndicesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      DirectHandle<FixedArrayBase> backing_store, GetKeysConversion convert,
      PropertyFilter filter, Handle<FixedArray> list, uint32_t* nof_indices,
      uint32_t insertion_index = 0) {
    size_t length = Subclass::GetMaxIndex(*object, *backing_store);
    uint32_t const kMaxStringTableEntries =
        isolate->heap()->MaxNumberToStringCacheSize();
    for (size_t i = 0; i < length; i++) {
      if (Subclass::HasElementImpl(isolate, *object, i, *backing_store,
                                   filter)) {
        if (convert == GetKeysConversion::kConvertToString) {
          bool use_cache = i < kMaxStringTableEntries;
          DirectHandle<String> index_string =
              isolate->factory()->SizeToString(i, use_cache);
          list->set(insertion_index, *index_string);
        } else {
          DirectHandle<Object> number =
              isolate->factory()->NewNumberFromSize(i);
          list->set(insertion_index, *number);
        }
        insertion_index++;
      }
    }
    *nof_indices = insertion_index;
    return list;
  }

  MaybeHandle<FixedArray> PrependElementIndices(
      Isolate* isolate, Handle<JSObject> object,
      Handle<FixedArrayBase> backing_store, Handle<FixedArray> keys,
      GetKeysConversion convert, PropertyFilter filter) final {
    return Subclass::PrependElementIndicesImpl(isolate, object, backing_store,
                                               keys, convert, filter);
  }

  static MaybeHandle<FixedArray> PrependElementIndicesImpl(
      Isolate* isolate, Handle<JSObject> object,
      Handle<FixedArrayBase> backing_store, DirectHandle<FixedArray> keys,
      GetKeysConversion convert, PropertyFilter filter) {
    uint32_t nof_property_keys = keys->length();
    size_t initial_list_length =
        Subclass::GetMaxNumberOfEntries(isolate, *object, *backing_store);

    if (initial_list_length > FixedArray::kMaxLength - nof_property_keys) {
      THROW_NEW_ERROR(isolate,
                      NewRangeError(MessageTemplate::kInvalidArrayLength));
    }
    initial_list_length += nof_property_keys;

    // Collect the element indices into a new list.
    DCHECK_LE(initial_list_length, std::numeric_limits<int>::max());
    MaybeHandle<FixedArray> raw_array = isolate->factory()->TryNewFixedArray(
        static_cast<int>(initial_list_length));
    Handle<FixedArray> combined_keys;

    // If we have a holey backing store try to precisely estimate the backing
    // store size as a last emergency measure if we cannot allocate the big
    // array.
    if (!raw_array.ToHandle(&combined_keys)) {
      if (IsHoleyOrDictionaryElementsKind(kind())) {
        // If we overestimate the result list size we might end up in the
        // large-object space which doesn't free memory on shrinking the list.
        // Hence we try to estimate the final size for holey backing stores more
        // precisely here.
        initial_list_length =
            Subclass::NumberOfElementsImpl(isolate, *object, *backing_store);
        initial_list_length += nof_property_keys;
      }
      DCHECK_LE(initial_list_length, std::numeric_limits<int>::max());
      combined_keys = isolate->factory()->NewFixedArray(
          static_cast<int>(initial_list_length));
    }

    uint32_t nof_indices = 0;
    bool needs_sorting = IsDictionaryElementsKind(kind()) ||
                         IsSloppyArgumentsElementsKind(kind());
    combined_keys = Subclass::DirectCollectElementIndicesImpl(
        isolate, object, backing_store,
        needs_sorting ? GetKeysConversion::kKeepNumbers : convert, filter,
        combined_keys, &nof_indices);

    if (needs_sorting) {
      SortIndices(isolate, combined_keys, nof_indices);
      // Indices from dictionary elements should only be converted after
      // sorting.
      if (convert == GetKeysConversion::kConvertToString) {
        for (uint32_t i = 0; i < nof_indices; i++) {
          DirectHandle<Object> index_string =
              isolate->factory()->Uint32ToString(
                  Object::NumberValue(combined_keys->get(i)));
          combined_keys->set(i, *index_string);
        }
      }
    }

    // Copy over the passed-in property keys.
    CopyObjectToObjectElements(isolate, *keys, PACKED_ELEMENTS, 0,
                               *combined_keys, PACKED_ELEMENTS, nof_indices,
                               nof_property_keys);

    // For holey elements and arguments we might have to shrink the collected
    // keys since the estimates might be off.
    if (IsHoleyOrDictionaryElementsKind(kind()) ||
        IsSloppyArgumentsElementsKind(kind())) {
      // Shrink combined_keys to the final size.
      int final_size = nof_indices + nof_property_keys;
      DCHECK_LE(final_size, combined_keys->length());
      return FixedArray::RightTrimOrEmpty(isolate, combined_keys, final_size);
    }

    return combined_keys;
  }

  V8_WARN_UNUSED_RESULT ExceptionStatus AddElementsToKeyAccumulator(
      Handle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) final {
    return Subclass::AddElementsToKeyAccumulatorImpl(receiver, accumulator,
                                                     convert);
  }

  static uint32_t GetCapacityImpl(Tagged<JSObject> holder,
                                  Tagged<FixedArrayBase> backing_store) {
    return backing_store->length();
  }

  size_t GetCapacity(Tagged<JSObject> holder,
                     Tagged<FixedArrayBase> backing_store) final {
    return Subclass::GetCapacityImpl(holder, backing_store);
  }

  static MaybeHandle<Object> FillImpl(DirectHandle<JSObject> receiver,
                                      Direct
### 提示词
```
这是目录为v8/src/objects/elements.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/elements.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    UNREACHABLE();
  }

  Maybe<bool> Add(Handle<JSObject> object, uint32_t index,
                  DirectHandle<Object> value, PropertyAttributes attributes,
                  uint32_t new_capacity) final {
    return Subclass::AddImpl(object, index, value, attributes, new_capacity);
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  Maybe<uint32_t> Push(Handle<JSArray> receiver, BuiltinArguments* args,
                       uint32_t push_size) final {
    return Subclass::PushImpl(receiver, args, push_size);
  }

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_sized) {
    UNREACHABLE();
  }

  Maybe<uint32_t> Unshift(Handle<JSArray> receiver, BuiltinArguments* args,
                          uint32_t unshift_size) final {
    return Subclass::UnshiftImpl(receiver, args, unshift_size);
  }

  static Maybe<uint32_t> UnshiftImpl(DirectHandle<JSArray> receiver,
                                     BuiltinArguments* args,
                                     uint32_t unshift_size) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Pop(Handle<JSArray> receiver) final {
    return Subclass::PopImpl(receiver);
  }

  static MaybeHandle<Object> PopImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Shift(Handle<JSArray> receiver) final {
    return Subclass::ShiftImpl(receiver);
  }

  static MaybeHandle<Object> ShiftImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  Maybe<bool> SetLength(Handle<JSArray> array, uint32_t length) final {
    return Subclass::SetLengthImpl(
        array->GetIsolate(), array, length,
        handle(array->elements(), array->GetIsolate()));
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate, Handle<JSArray> array,
                                   uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    DCHECK(!array->SetLengthWouldNormalize(length));
    DCHECK(IsFastElementsKind(array->GetElementsKind()));
    uint32_t old_length = 0;
    CHECK(Object::ToArrayIndex(array->length(), &old_length));

    if (old_length < length) {
      ElementsKind kind = array->GetElementsKind();
      if (!IsHoleyElementsKind(kind)) {
        kind = GetHoleyElementsKind(kind);
        JSObject::TransitionElementsKind(array, kind);
      }
    }

    // Check whether the backing store should be shrunk.
    uint32_t capacity = backing_store->length();
    old_length = std::min(old_length, capacity);
    if (length == 0) {
      array->initialize_elements();
    } else if (length <= capacity) {
      if (IsSmiOrObjectElementsKind(kind())) {
        JSObject::EnsureWritableFastElements(array);
        if (array->elements() != *backing_store) {
          backing_store = handle(array->elements(), isolate);
        }
      }
      if (2 * length + JSObject::kMinAddedElementsCapacity <= capacity) {
        // If more than half the elements won't be used, trim the array.
        // Do not trim from short arrays to prevent frequent trimming on
        // repeated pop operations.
        // Leave some space to allow for subsequent push operations.
        uint32_t new_capacity =
            length + 1 == old_length ? (capacity + length) / 2 : length;
        DCHECK_LT(new_capacity, capacity);
        isolate->heap()->RightTrimArray(Cast<BackingStore>(*backing_store),
                                        new_capacity, capacity);
        // Fill the non-trimmed elements with holes.
        Cast<BackingStore>(*backing_store)
            ->FillWithHoles(length, std::min(old_length, new_capacity));
      } else {
        // Otherwise, fill the unused tail with holes.
        Cast<BackingStore>(*backing_store)->FillWithHoles(length, old_length);
      }
    } else {
      // Check whether the backing store should be expanded.
      capacity = std::max(length, JSObject::NewElementsCapacity(capacity));
      MAYBE_RETURN(Subclass::GrowCapacityAndConvertImpl(array, capacity),
                   Nothing<bool>());
    }

    array->set_length(Smi::FromInt(length));
    JSObject::ValidateElements(*array);
    return Just(true);
  }

  size_t NumberOfElements(Isolate* isolate, Tagged<JSObject> receiver) final {
    return Subclass::NumberOfElementsImpl(isolate, receiver,
                                          receiver->elements());
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> receiver,
                                       Tagged<FixedArrayBase> backing_store) {
    UNREACHABLE();
  }

  static size_t GetMaxIndex(Tagged<JSObject> receiver,
                            Tagged<FixedArrayBase> elements) {
    if (IsJSArray(receiver)) {
      DCHECK(IsSmi(Cast<JSArray>(receiver)->length()));
      return static_cast<uint32_t>(
          Smi::ToInt(Cast<JSArray>(receiver)->length()));
    }
    return Subclass::GetCapacityImpl(receiver, elements);
  }

  static size_t GetMaxNumberOfEntries(Isolate* isolate,
                                      Tagged<JSObject> receiver,
                                      Tagged<FixedArrayBase> elements) {
    return Subclass::GetMaxIndex(receiver, elements);
  }

  static MaybeHandle<FixedArrayBase> ConvertElementsWithCapacity(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, uint32_t capacity) {
    return ConvertElementsWithCapacity(object, old_elements, from_kind,
                                       capacity, 0, 0);
  }

  static MaybeHandle<FixedArrayBase> ConvertElementsWithCapacity(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> old_elements,
      ElementsKind from_kind, uint32_t capacity, uint32_t src_index,
      uint32_t dst_index) {
    Isolate* isolate = object->GetIsolate();
    Handle<FixedArrayBase> new_elements;
    // TODO(victorgomes): Retrieve native context in optimized code
    // and remove the check isolate->context().is_null().
    if (IsDoubleElementsKind(kind())) {
      if (!isolate->context().is_null() &&
          !base::IsInRange(capacity, 0, FixedDoubleArray::kMaxLength)) {
        THROW_NEW_ERROR(isolate,
                        NewRangeError(MessageTemplate::kInvalidArrayLength));
      }
      new_elements = isolate->factory()->NewFixedDoubleArray(capacity);
    } else {
      if (!isolate->context().is_null() &&
          !base::IsInRange(capacity, 0, FixedArray::kMaxLength)) {
        THROW_NEW_ERROR(isolate,
                        NewRangeError(MessageTemplate::kInvalidArrayLength));
      }
      new_elements = isolate->factory()->NewFixedArray(capacity);
    }

    int packed_size = kPackedSizeNotKnown;
    if (IsFastPackedElementsKind(from_kind) && IsJSArray(*object)) {
      packed_size = Smi::ToInt(Cast<JSArray>(*object)->length());
    }

    Subclass::CopyElementsImpl(isolate, *old_elements, src_index, *new_elements,
                               from_kind, dst_index, packed_size,
                               kCopyToEndAndInitializeToHole);

    return MaybeHandle<FixedArrayBase>(new_elements);
  }

  static Maybe<bool> TransitionElementsKindImpl(Handle<JSObject> object,
                                                DirectHandle<Map> to_map) {
    Isolate* isolate = object->GetIsolate();
    DirectHandle<Map> from_map(object->map(), isolate);
    ElementsKind from_kind = from_map->elements_kind();
    ElementsKind to_kind = to_map->elements_kind();
    if (IsHoleyElementsKind(from_kind)) {
      to_kind = GetHoleyElementsKind(to_kind);
    }
    if (from_kind != to_kind) {
      // This method should never be called for any other case.
      DCHECK(IsFastElementsKind(from_kind));
      DCHECK(IsFastElementsKind(to_kind));
      DCHECK_NE(TERMINAL_FAST_ELEMENTS_KIND, from_kind);

      Handle<FixedArrayBase> from_elements(object->elements(), isolate);
      if (object->elements() == ReadOnlyRoots(isolate).empty_fixed_array() ||
          IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind)) {
        // No change is needed to the elements() buffer, the transition
        // only requires a map change.
        JSObject::MigrateToMap(isolate, object, to_map);
      } else {
        DCHECK(
            (IsSmiElementsKind(from_kind) && IsDoubleElementsKind(to_kind)) ||
            (IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind)));
        uint32_t capacity = static_cast<uint32_t>(object->elements()->length());
        Handle<FixedArrayBase> elements;
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            object->GetIsolate(), elements,
            ConvertElementsWithCapacity(object, from_elements, from_kind,
                                        capacity),
            Nothing<bool>());
        JSObject::SetMapAndElements(object, to_map, elements);
      }
      if (v8_flags.trace_elements_transitions) {
        JSObject::PrintElementsTransition(stdout, object, from_kind,
                                          from_elements, to_kind,
                                          handle(object->elements(), isolate));
      }
    }
    return Just(true);
  }

  static Maybe<bool> GrowCapacityAndConvertImpl(Handle<JSObject> object,
                                                uint32_t capacity) {
    ElementsKind from_kind = object->GetElementsKind();
    if (IsSmiOrObjectElementsKind(from_kind)) {
      // Array optimizations rely on the prototype lookups of Array objects
      // always returning undefined. If there is a store to the initial
      // prototype object, make sure all of these optimizations are invalidated.
      object->GetIsolate()->UpdateNoElementsProtectorOnSetLength(object);
    }
    Handle<FixedArrayBase> old_elements(object->elements(),
                                        object->GetIsolate());
    // This method should only be called if there's a reason to update the
    // elements.
    DCHECK(IsDoubleElementsKind(from_kind) != IsDoubleElementsKind(kind()) ||
           IsDictionaryElementsKind(from_kind) ||
           static_cast<uint32_t>(old_elements->length()) < capacity);
    return Subclass::BasicGrowCapacityAndConvertImpl(
        object, old_elements, from_kind, kind(), capacity);
  }

  static Maybe<bool> BasicGrowCapacityAndConvertImpl(
      Handle<JSObject> object, Handle<FixedArrayBase> old_elements,
      ElementsKind from_kind, ElementsKind to_kind, uint32_t capacity) {
    Handle<FixedArrayBase> elements;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        object->GetIsolate(), elements,
        ConvertElementsWithCapacity(object, old_elements, from_kind, capacity),
        Nothing<bool>());

    if (IsHoleyElementsKind(from_kind)) {
      to_kind = GetHoleyElementsKind(to_kind);
    }
    DirectHandle<Map> new_map =
        JSObject::GetElementsTransitionMap(object, to_kind);
    JSObject::SetMapAndElements(object, new_map, elements);

    // Transition through the allocation site as well if present.
    JSObject::UpdateAllocationSite(object, to_kind);

    if (v8_flags.trace_elements_transitions) {
      JSObject::PrintElementsTransition(stdout, object, from_kind, old_elements,
                                        to_kind, elements);
    }
    return Just(true);
  }

  Maybe<bool> TransitionElementsKind(Handle<JSObject> object,
                                     Handle<Map> map) final {
    return Subclass::TransitionElementsKindImpl(object, map);
  }

  Maybe<bool> GrowCapacityAndConvert(Handle<JSObject> object,
                                     uint32_t capacity) final {
    return Subclass::GrowCapacityAndConvertImpl(object, capacity);
  }

  Maybe<bool> GrowCapacity(Handle<JSObject> object, uint32_t index) final {
    // This function is intended to be called from optimized code. We don't
    // want to trigger lazy deopts there, so refuse to handle cases that would.
    if (object->map()->is_prototype_map() ||
        object->WouldConvertToSlowElements(index)) {
      return Just(false);
    }
    Handle<FixedArrayBase> old_elements(object->elements(),
                                        object->GetIsolate());
    uint32_t new_capacity = JSObject::NewElementsCapacity(index + 1);
    DCHECK(static_cast<uint32_t>(old_elements->length()) < new_capacity);
    const uint32_t kMaxLength = IsDoubleElementsKind(kind())
                                    ? FixedDoubleArray::kMaxLength
                                    : FixedArray::kMaxLength;
    if (new_capacity > kMaxLength) {
      return Just(false);
    }
    Handle<FixedArrayBase> elements;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        object->GetIsolate(), elements,
        ConvertElementsWithCapacity(object, old_elements, kind(), new_capacity),
        Nothing<bool>());

    DCHECK_EQ(object->GetElementsKind(), kind());
    // Transition through the allocation site as well if present.
    if (JSObject::UpdateAllocationSite<AllocationSiteUpdateMode::kCheckOnly>(
            object, kind())) {
      return Just(false);
    }

    object->set_elements(*elements);
    return Just(true);
  }

  void Delete(Handle<JSObject> obj, InternalIndex entry) final {
    Subclass::DeleteImpl(obj, entry);
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    UNREACHABLE();
  }

  void CopyElements(Isolate* isolate, Tagged<JSObject> from_holder,
                    uint32_t from_start, ElementsKind from_kind,
                    Handle<FixedArrayBase> to, uint32_t to_start,
                    int copy_size) final {
    int packed_size = kPackedSizeNotKnown;
    bool is_packed =
        IsFastPackedElementsKind(from_kind) && IsJSArray(from_holder);
    if (is_packed) {
      packed_size = Smi::ToInt(Cast<JSArray>(from_holder)->length());
      if (copy_size >= 0 && packed_size > copy_size) {
        packed_size = copy_size;
      }
    }
    Tagged<FixedArrayBase> from = from_holder->elements();
    // NOTE: the Subclass::CopyElementsImpl() methods
    // violate the handlified function signature convention:
    // raw pointer parameters in the function that allocates. This is done
    // intentionally to avoid ArrayConcat() builtin performance degradation.
    //
    // Details: The idea is that allocations actually happen only in case of
    // copying from object with fast double elements to object with object
    // elements. In all the other cases there are no allocations performed and
    // handle creation causes noticeable performance degradation of the builtin.
    Subclass::CopyElementsImpl(isolate, from, from_start, *to, from_kind,
                               to_start, packed_size, copy_size);
  }

  void CopyElements(Isolate* isolate, Handle<FixedArrayBase> source,
                    ElementsKind source_kind,
                    Handle<FixedArrayBase> destination, int size) override {
    Subclass::CopyElementsImpl(isolate, *source, 0, *destination, source_kind,
                               0, kPackedSizeNotKnown, size);
  }

  void CopyTypedArrayElementsSlice(Tagged<JSTypedArray> source,
                                   Tagged<JSTypedArray> destination,
                                   size_t start, size_t end) override {
    Subclass::CopyTypedArrayElementsSliceImpl(source, destination, start, end);
  }

  static void CopyTypedArrayElementsSliceImpl(Tagged<JSTypedArray> source,
                                              Tagged<JSTypedArray> destination,
                                              size_t start, size_t end) {
    UNREACHABLE();
  }

  Tagged<Object> CopyElements(Handle<JSAny> source,
                              Handle<JSObject> destination, size_t length,
                              size_t offset) final {
    return Subclass::CopyElementsHandleImpl(source, destination, length,
                                            offset);
  }

  static Tagged<Object> CopyElementsHandleImpl(
      DirectHandle<Object> source, DirectHandle<JSObject> destination,
      size_t length, size_t offset) {
    UNREACHABLE();
  }

  Handle<NumberDictionary> Normalize(Handle<JSObject> object) final {
    return Subclass::NormalizeImpl(
        object, handle(object->elements(), object->GetIsolate()));
  }

  static Handle<NumberDictionary> NormalizeImpl(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> elements) {
    UNREACHABLE();
  }

  Maybe<bool> CollectValuesOrEntries(Isolate* isolate, Handle<JSObject> object,
                                     Handle<FixedArray> values_or_entries,
                                     bool get_entries, int* nof_items,
                                     PropertyFilter filter) override {
    return Subclass::CollectValuesOrEntriesImpl(
        isolate, object, values_or_entries, get_entries, nof_items, filter);
  }

  static Maybe<bool> CollectValuesOrEntriesImpl(
      Isolate* isolate, Handle<JSObject> object,
      DirectHandle<FixedArray> values_or_entries, bool get_entries,
      int* nof_items, PropertyFilter filter) {
    DCHECK_EQ(*nof_items, 0);
    KeyAccumulator accumulator(isolate, KeyCollectionMode::kOwnOnly,
                               ALL_PROPERTIES);
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(Subclass::CollectElementIndicesImpl(
        object, handle(object->elements(), isolate), &accumulator));
    DirectHandle<FixedArray> keys = accumulator.GetKeys();

    int count = 0;
    int i = 0;
    ElementsKind original_elements_kind = object->GetElementsKind();

    for (; i < keys->length(); ++i) {
      DirectHandle<Object> key(keys->get(i), isolate);
      uint32_t index;
      if (!Object::ToUint32(*key, &index)) continue;

      DCHECK_EQ(object->GetElementsKind(), original_elements_kind);
      InternalIndex entry = Subclass::GetEntryForIndexImpl(
          isolate, *object, object->elements(), index, filter);
      if (entry.is_not_found()) continue;
      PropertyDetails details = Subclass::GetDetailsImpl(*object, entry);

      DirectHandle<Object> value;
      if (details.kind() == PropertyKind::kData) {
        value = Subclass::GetInternalImpl(isolate, object, entry);
      } else {
        // This might modify the elements and/or change the elements kind.
        LookupIterator it(isolate, object, index, LookupIterator::OWN);
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(
            isolate, value, Object::GetProperty(&it), Nothing<bool>());
      }
      if (get_entries) value = MakeEntryPair(isolate, index, value);
      values_or_entries->set(count++, *value);
      if (object->GetElementsKind() != original_elements_kind) break;
    }

    // Slow path caused by changes in elements kind during iteration.
    for (; i < keys->length(); i++) {
      DirectHandle<Object> key(keys->get(i), isolate);
      uint32_t index;
      if (!Object::ToUint32(*key, &index)) continue;

      if (filter & ONLY_ENUMERABLE) {
        InternalElementsAccessor* accessor =
            reinterpret_cast<InternalElementsAccessor*>(
                object->GetElementsAccessor());
        InternalIndex entry = accessor->GetEntryForIndex(
            isolate, *object, object->elements(), index);
        if (entry.is_not_found()) continue;
        PropertyDetails details = accessor->GetDetails(*object, entry);
        if (!details.IsEnumerable()) continue;
      }

      Handle<Object> value;
      LookupIterator it(isolate, object, index, LookupIterator::OWN);
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, value, Object::GetProperty(&it),
                                       Nothing<bool>());

      if (get_entries) value = MakeEntryPair(isolate, index, value);
      values_or_entries->set(count++, *value);
    }

    *nof_items = count;
    return Just(true);
  }

  V8_WARN_UNUSED_RESULT ExceptionStatus CollectElementIndices(
      Handle<JSObject> object, Handle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) final {
    return Subclass::CollectElementIndicesImpl(object, backing_store, keys);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus CollectElementIndicesImpl(
      DirectHandle<JSObject> object, DirectHandle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) {
    DCHECK_NE(DICTIONARY_ELEMENTS, kind());
    // Non-dictionary elements can't have all-can-read accessors.
    size_t length = Subclass::GetMaxIndex(*object, *backing_store);
    PropertyFilter filter = keys->filter();
    Isolate* isolate = keys->isolate();
    Factory* factory = isolate->factory();
    for (size_t i = 0; i < length; i++) {
      if (Subclass::HasElementImpl(isolate, *object, i, *backing_store,
                                   filter)) {
        RETURN_FAILURE_IF_NOT_SUCCESSFUL(
            keys->AddKey(factory->NewNumberFromSize(i)));
      }
    }
    return ExceptionStatus::kSuccess;
  }

  static Handle<FixedArray> DirectCollectElementIndicesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      DirectHandle<FixedArrayBase> backing_store, GetKeysConversion convert,
      PropertyFilter filter, Handle<FixedArray> list, uint32_t* nof_indices,
      uint32_t insertion_index = 0) {
    size_t length = Subclass::GetMaxIndex(*object, *backing_store);
    uint32_t const kMaxStringTableEntries =
        isolate->heap()->MaxNumberToStringCacheSize();
    for (size_t i = 0; i < length; i++) {
      if (Subclass::HasElementImpl(isolate, *object, i, *backing_store,
                                   filter)) {
        if (convert == GetKeysConversion::kConvertToString) {
          bool use_cache = i < kMaxStringTableEntries;
          DirectHandle<String> index_string =
              isolate->factory()->SizeToString(i, use_cache);
          list->set(insertion_index, *index_string);
        } else {
          DirectHandle<Object> number =
              isolate->factory()->NewNumberFromSize(i);
          list->set(insertion_index, *number);
        }
        insertion_index++;
      }
    }
    *nof_indices = insertion_index;
    return list;
  }

  MaybeHandle<FixedArray> PrependElementIndices(
      Isolate* isolate, Handle<JSObject> object,
      Handle<FixedArrayBase> backing_store, Handle<FixedArray> keys,
      GetKeysConversion convert, PropertyFilter filter) final {
    return Subclass::PrependElementIndicesImpl(isolate, object, backing_store,
                                               keys, convert, filter);
  }

  static MaybeHandle<FixedArray> PrependElementIndicesImpl(
      Isolate* isolate, Handle<JSObject> object,
      Handle<FixedArrayBase> backing_store, DirectHandle<FixedArray> keys,
      GetKeysConversion convert, PropertyFilter filter) {
    uint32_t nof_property_keys = keys->length();
    size_t initial_list_length =
        Subclass::GetMaxNumberOfEntries(isolate, *object, *backing_store);

    if (initial_list_length > FixedArray::kMaxLength - nof_property_keys) {
      THROW_NEW_ERROR(isolate,
                      NewRangeError(MessageTemplate::kInvalidArrayLength));
    }
    initial_list_length += nof_property_keys;

    // Collect the element indices into a new list.
    DCHECK_LE(initial_list_length, std::numeric_limits<int>::max());
    MaybeHandle<FixedArray> raw_array = isolate->factory()->TryNewFixedArray(
        static_cast<int>(initial_list_length));
    Handle<FixedArray> combined_keys;

    // If we have a holey backing store try to precisely estimate the backing
    // store size as a last emergency measure if we cannot allocate the big
    // array.
    if (!raw_array.ToHandle(&combined_keys)) {
      if (IsHoleyOrDictionaryElementsKind(kind())) {
        // If we overestimate the result list size we might end up in the
        // large-object space which doesn't free memory on shrinking the list.
        // Hence we try to estimate the final size for holey backing stores more
        // precisely here.
        initial_list_length =
            Subclass::NumberOfElementsImpl(isolate, *object, *backing_store);
        initial_list_length += nof_property_keys;
      }
      DCHECK_LE(initial_list_length, std::numeric_limits<int>::max());
      combined_keys = isolate->factory()->NewFixedArray(
          static_cast<int>(initial_list_length));
    }

    uint32_t nof_indices = 0;
    bool needs_sorting = IsDictionaryElementsKind(kind()) ||
                         IsSloppyArgumentsElementsKind(kind());
    combined_keys = Subclass::DirectCollectElementIndicesImpl(
        isolate, object, backing_store,
        needs_sorting ? GetKeysConversion::kKeepNumbers : convert, filter,
        combined_keys, &nof_indices);

    if (needs_sorting) {
      SortIndices(isolate, combined_keys, nof_indices);
      // Indices from dictionary elements should only be converted after
      // sorting.
      if (convert == GetKeysConversion::kConvertToString) {
        for (uint32_t i = 0; i < nof_indices; i++) {
          DirectHandle<Object> index_string =
              isolate->factory()->Uint32ToString(
                  Object::NumberValue(combined_keys->get(i)));
          combined_keys->set(i, *index_string);
        }
      }
    }

    // Copy over the passed-in property keys.
    CopyObjectToObjectElements(isolate, *keys, PACKED_ELEMENTS, 0,
                               *combined_keys, PACKED_ELEMENTS, nof_indices,
                               nof_property_keys);

    // For holey elements and arguments we might have to shrink the collected
    // keys since the estimates might be off.
    if (IsHoleyOrDictionaryElementsKind(kind()) ||
        IsSloppyArgumentsElementsKind(kind())) {
      // Shrink combined_keys to the final size.
      int final_size = nof_indices + nof_property_keys;
      DCHECK_LE(final_size, combined_keys->length());
      return FixedArray::RightTrimOrEmpty(isolate, combined_keys, final_size);
    }

    return combined_keys;
  }

  V8_WARN_UNUSED_RESULT ExceptionStatus AddElementsToKeyAccumulator(
      Handle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) final {
    return Subclass::AddElementsToKeyAccumulatorImpl(receiver, accumulator,
                                                     convert);
  }

  static uint32_t GetCapacityImpl(Tagged<JSObject> holder,
                                  Tagged<FixedArrayBase> backing_store) {
    return backing_store->length();
  }

  size_t GetCapacity(Tagged<JSObject> holder,
                     Tagged<FixedArrayBase> backing_store) final {
    return Subclass::GetCapacityImpl(holder, backing_store);
  }

  static MaybeHandle<Object> FillImpl(DirectHandle<JSObject> receiver,
                                      DirectHandle<Object> obj_value,
                                      size_t start, size_t end) {
    UNREACHABLE();
  }

  MaybeHandle<Object> Fill(Handle<JSObject> receiver, Handle<Object> obj_value,
                           size_t start, size_t end) override {
    return Subclass::FillImpl(receiver, obj_value, start, end);
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       Handle<JSObject> receiver,
                                       DirectHandle<Object> value,
                                       size_t start_from, size_t length) {
    return IncludesValueSlowPath(isolate, receiver, value, start_from, length);
  }

  Maybe<bool> IncludesValue(Isolate* isolate, Handle<JSObject> receiver,
                            Handle<Object> value, size_t start_from,
                            size_t length) final {
    return Subclass::IncludesValueImpl(isolate, receiver, value, start_from,
                                       length);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         Handle<JSObject> receiver,
                                         DirectHandle<Object> value,
                                         size_t start_from, size_t length) {
    return IndexOfValueSlowPath(isolate, receiver, value, start_from, length);
  }

  Maybe<int64_t> IndexOfValue(Isolate* isolate, Handle<JSObject> receiver,
                              Handle<Object> value, size_t start_from,
                              size_t length) final {
    return Subclass::IndexOfValueImpl(isolate, receiver, value, start_from,
                                      length);
  }

  static Maybe<int64_t> LastIndexOfValueImpl(DirectHandle<JSObject> receiver,
                                             DirectHandle<Object> value,
                                             size_t start_from) {
    UNREACHABLE();
  }

  Maybe<int64_t> LastIndexOfValue(Handle<JSObject> receiver,
                                  Handle<Object> value,
                                  size_t start_from) final {
    return Subclass::LastIndexOfValueImpl(receiver, value, start_from);
  }

  static void ReverseImpl(Tagged<JSObject> receiver) { UNREACHABLE(); }

  void Reverse(Tagged<JSObject> receiver) final {
    Subclass::ReverseImpl(receiver);
  }

  static InternalIndex GetEntryForIndexImpl(
      Isolate* isolate, Tagged<JSObject> holder,
      Tagged<FixedArrayBase> backing_store, size_t index,
      PropertyFilter filter) {
    DCHECK(IsFastElementsKind(kind()) ||
           IsAnyNonextensibleElementsKind(kind()));
    size_t length = Subclass::GetMaxIndex(holder, backing_store);
    if (IsHoleyElementsKindForRead(kind())) {
      DCHECK_IMPLIES(
          index < length,
          index <= static_cast<size_t>(std::numeric_limits<int>::max()));
      return index < length &&
                     !Cast<BackingStore>(backing_store)
                          ->is_the_hole(isolate, static_cast<int>(index))
                 ? InternalIndex(index)
                 : InternalIndex::NotFound();
    } else {
      return index < length ? InternalIndex(index) : InternalIndex::NotFound();
    }
  }

  InternalIndex GetEntryForIndex(Isolate* isolate, Tagged<JSObject> holder,
                                 Tagged<FixedArrayBase> backing_store,
                                 size_t index) final {
    return Subclass::GetEntryForIndexImpl(isolate, holder, backing_store, index,
                                          ALL_PROPERTIES);
  }

  static PropertyDetails GetDetailsImpl(Tagged<FixedArrayBase> backing_store,
                                        InternalIndex entry) {
    return PropertyDetails(PropertyKind::kData, NONE,
                           PropertyCellType::kNoCell);
  }

  static PropertyDetails GetDetailsImpl(Tagged<JSObject> holder,
                                        InternalIndex entry) {
    return PropertyDetails(PropertyKind::kData, NONE,
                           PropertyCellType::kNoCell);
  }

  PropertyDetails GetDetails(Tagged<JSObject> holder,
                             InternalIndex entry) final {
    return Subclass::GetDetailsImpl(holder, entry);
  }

  Handle<FixedArray> CreateListFromArrayLike(Isolate* isolate,
                                             Handle<JSObject> object,
                                             uint32_t length) final {
    return Subclass::CreateListFromArrayLikeImpl(isolate, object, length);
  }

  static Handle<FixedArray> CreateListFromArrayLikeImpl(
      Isolate* isolate, DirectHandle<JSObject> object, uint32_t length) {
    UNREACHABLE();
  }
};

class DictionaryElementsAccessor
    : public ElementsAccessorBase<DictionaryElementsAccessor,
                                  ElementsKindTraits<DICTIONARY_ELEMENTS>> {
 public:
  static uint32_t GetMaxIndex(Tagged<JSObject> receiver,
                              Tagged<FixedArrayBase> elements) {
    // We cannot properly estimate this for dictionaries.
    UNREACHABLE();
  }

  static uint32_t GetMaxNumberOfEntries(Isolate* isolate,
                                        Tagged<JSObject> receiver,
                                        Tagged<FixedArrayBase> backing_store) {
    return NumberOfElementsImpl(isolate, receiver, backing_store);
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> receiver,
                                       Tagged<FixedArrayBase> backing_store) {
    Tagged<NumberDictionary> dict = Cast<NumberDictionary>(backing_store)
```