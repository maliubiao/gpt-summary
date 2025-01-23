Response: The user wants to understand the functionality of the C++ code provided, which is part of the `v8/src/objects/elements.cc` file. Specifically, they've asked for a summary of its function in the context of a larger file (part 2 of 4). They also want to see how this code relates to JavaScript, using JavaScript examples.

My plan is to:

1. **Analyze the code snippets:** Identify the key classes and methods defined in this section.
2. **Infer functionality:** Based on the method names and operations, deduce the purpose of this code. It seems to be related to how JavaScript arrays and objects store their elements when using a `NumberDictionary`.
3. **Relate to JavaScript:** Explain how the C++ code implements specific JavaScript behaviors related to arrays and objects with non-contiguous or sparse numeric indices.
4. **Provide JavaScript examples:**  Create simple JavaScript code snippets that demonstrate the functionality implemented in the C++ code.
这是 `v8/src/objects/elements.cc` 文件的第二部分，主要负责实现 **字典模式 (Dictionary Elements)** 的对象元素访问和操作。字典模式用于存储对象的元素，特别是当对象的键主要为非连续的数字索引或者包含字符串键时。与快速模式 (Fast Elements) 相比，字典模式更加灵活，但访问速度相对较慢。

具体来说，这部分代码定义了一个 `DictionaryElementsAccessor` 类，其中包含了一系列静态方法，用于实现以下功能：

* **获取元素数量 (`NumberOfElementsImpl`)**: 返回字典中元素的数量。
* **设置数组长度 (`SetLengthImpl`)**:  当数组长度被修改时，更新字典中的元素。这包括删除超出新长度的元素，并处理不可配置的元素。
* **复制元素 (`CopyElementsImpl`)**:  虽然此处 `UNREACHABLE()`，但在其他部分，这个方法会被用于在不同类型的元素存储之间复制元素。
* **删除元素 (`DeleteImpl`)**: 从字典中删除指定的元素。
* **检查是否存在访问器属性 (`HasAccessorsImpl`)**:  判断字典中是否存在访问器属性（getter/setter）。
* **获取原始元素值 (`GetRaw`, `GetImpl`, `GetAtomicInternalImpl`)**: 从字典中获取指定索引的元素值。原子操作版本用于并发场景。
* **设置元素值 (`SetImpl`, `SetAtomicInternalImpl`)**: 在字典中设置指定索引的元素值。原子操作版本用于并发场景。
* **原子交换元素值 (`SwapAtomicInternalImpl`)**:  原子地交换字典中指定索引的元素值。
* **原子比较并交换元素值 (`CompareAndSwapAtomicInternalImpl`)**: 原子地比较字典中指定索引的元素值与预期值，如果相等则设置为新值。
* **重新配置元素属性 (`ReconfigureImpl`)**:  修改字典中指定元素的属性（例如，可写、可枚举、可配置）。
* **添加元素 (`AddImpl`)**: 向字典中添加新的元素。
* **检查是否存在指定索引的元素 (`HasEntryImpl`)**:  判断字典中是否存在指定索引的元素。
* **获取指定索引的条目 (`GetEntryForIndexImpl`)**:  在字典中查找指定索引的条目。
* **获取元素详情 (`GetDetailsImpl`)**:  获取字典中指定元素的详细信息（例如，属性）。
* **获取指定条目的键 (`GetKeyForEntryImpl`)**:  获取字典中指定条目的键。
* **收集元素索引 (`CollectElementIndicesImpl`, `DirectCollectElementIndicesImpl`)**:  收集字典中的数字索引。
* **将元素添加到键累加器 (`AddElementsToKeyAccumulatorImpl`)**: 将字典中的元素添加到键累加器中，用于属性枚举等操作。
* **判断是否包含指定值 (`IncludesValueFastPath`, `IncludesValueImpl`)**:  判断字典中是否包含指定的元素值。快速路径版本尝试进行优化。
* **查找指定值的索引 (`IndexOfValueImpl`)**:  查找字典中指定元素值的索引。
* **验证字典内容 (`ValidateContents`)**:  在调试模式下验证字典的内部状态。

**与 JavaScript 的关系及示例：**

这部分 C++ 代码直接对应于 JavaScript 中对象和数组在特定情况下的元素存储方式。当 JavaScript 对象的属性键主要为非连续的数字或者包含字符串键时，V8 引擎会将其元素的存储方式切换为字典模式。

**JavaScript 示例：**

```javascript
const obj = {};

// 添加一些非连续的数字索引属性
obj[100] = 'a';
obj[1] = 'b';
obj[50] = 'c';

// 添加一个字符串键
obj['name'] = 'example';

// 此时，obj 的元素存储很可能就是字典模式

// 获取元素数量
// 对应的 C++ 函数是 DictionaryElementsAccessor::NumberOfElementsImpl
console.log(Object.keys(obj).length); // 输出 4

// 设置数组长度（对于数组而言，对象类似）
const arr = [];
arr[2] = 'x';
arr[5] = 'y';
console.log(arr.length); // 输出 6
arr.length = 3;
console.log(arr); // 输出 [ <2 empty items>, 'x' ]
// 对应的 C++ 函数是 DictionaryElementsAccessor::SetLengthImpl （如果 arr 使用了字典模式）

// 删除元素
delete obj[50];
console.log(obj[50]); // 输出 undefined
// 对应的 C++ 函数是 DictionaryElementsAccessor::DeleteImpl

// 检查是否存在属性
console.log(obj.hasOwnProperty(100)); // 输出 true
// 对应的 C++ 函数会涉及 DictionaryElementsAccessor::HasEntryImpl 等

// 获取元素值
console.log(obj[1]); // 输出 'b'
// 对应的 C++ 函数是 DictionaryElementsAccessor::GetImpl

// 判断是否包含某个值
console.log(Object.values(obj).includes('a')); // 输出 true
// 对应的 C++ 函数是 DictionaryElementsAccessor::IncludesValueImpl

// 查找值的索引 (对于数组)
const arr2 = [10, 20, 30];
console.log(arr2.indexOf(20)); // 输出 1
// 如果 arr2 使用了字典模式，对应的 C++ 函数是 DictionaryElementsAccessor::IndexOfValueImpl
```

总而言之，这部分 C++ 代码是 V8 引擎实现 JavaScript 对象和数组在字典模式下元素管理的关键部分，它定义了各种底层操作，确保了 JavaScript 代码在处理具有稀疏数字索引或字符串键的对象时能够正确运行。

### 提示词
```
这是目录为v8/src/objects/elements.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
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

  static Maybe<uint32_t> PushImpl(Handle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    Handle<FixedArrayBase> backing_store(receiver->elements(),
                                         receiver->GetIsolate());
    return Subclass::AddArguments(receiver, backing_store, args, push_size,
                                  AT_END);
  }

  static Maybe<uint32_t> UnshiftImpl(Handle<JSArray> receiver,
                                     BuiltinArguments* args,
                                     uint32_t unshift_size) {
    Handle<FixedArrayBase> backing_store(receiver->elements(),
                                         receiver->GetIsolate());
    return Subclass::AddArguments(receiver, backing_store, args, unshift_size,
                                  AT_START);
  }

  static void MoveElements(Isolate* isolate, DirectHandle<JSArray> receiver,
                           Handle<FixedArrayBase> backing_store, int dst_index,
                           int src_index, int len, int hole_start,
                           int hole_end) {
    DisallowGarbageCollection no_gc;
    Tagged<BackingStore> dst_elms = Cast<BackingStore>(*backing_store);
    if (len > JSArray::kMaxCopyElements && dst_index == 0 &&
        isolate->heap()->CanMoveObjectStart(dst_elms)) {
      dst_elms = Cast<BackingStore>(
          isolate->heap()->LeftTrimFixedArray(dst_elms, src_index));
      // Update all the copies of this backing_store handle.
      backing_store.PatchValue(dst_elms);
      receiver->set_elements(dst_elms);
      // Adjust the hole offset as the array has been shrunk.
      hole_end -= src_index;
      DCHECK_LE(hole_start, backing_store->length());
      DCHECK_LE(hole_end, backing_store->length());
    } else if (len != 0) {
      WriteBarrierMode mode =
          GetWriteBarrierMode(dst_elms, KindTraits::Kind, no_gc);
      dst_elms->MoveElements(isolate, dst_index, src_index, len, mode);
    }
    if (hole_start != hole_end) {
      dst_elms->FillWithHoles(hole_start, hole_end);
    }
  }

  static MaybeHandle<Object> FillImpl(Handle<JSObject> receiver,
                                      DirectHandle<Object> obj_value,
                                      size_t start, size_t end) {
    // Ensure indexes are within array bounds
    DCHECK_LE(0, start);
    DCHECK_LE(start, end);

    // Make sure COW arrays are copied.
    if (IsSmiOrObjectElementsKind(Subclass::kind())) {
      JSObject::EnsureWritableFastElements(receiver);
    }

    // Make sure we have enough space.
    DCHECK_LE(end, std::numeric_limits<uint32_t>::max());
    if (end > Subclass::GetCapacityImpl(*receiver, receiver->elements())) {
      MAYBE_RETURN_NULL(Subclass::GrowCapacityAndConvertImpl(
          receiver, static_cast<uint32_t>(end)));
      CHECK_EQ(Subclass::kind(), receiver->GetElementsKind());
    }
    DCHECK_LE(end, Subclass::GetCapacityImpl(*receiver, receiver->elements()));

    for (size_t index = start; index < end; ++index) {
      Subclass::SetImpl(receiver, InternalIndex(index), *obj_value);
    }
    return MaybeHandle<Object>(receiver);
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       DirectHandle<JSObject> receiver,
                                       DirectHandle<Object> search_value,
                                       size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> elements_base = receiver->elements();
    Tagged<Object> the_hole = ReadOnlyRoots(isolate).the_hole_value();
    Tagged<Object> undefined = ReadOnlyRoots(isolate).undefined_value();
    Tagged<Object> value = *search_value;

    if (start_from >= length) return Just(false);

    // Elements beyond the capacity of the backing store treated as undefined.
    size_t elements_length = static_cast<size_t>(elements_base->length());
    if (value == undefined && elements_length < length) return Just(true);
    if (elements_length == 0) {
      DCHECK_NE(value, undefined);
      return Just(false);
    }

    length = std::min(elements_length, length);
    DCHECK_LE(length, std::numeric_limits<int>::max());

    if (!IsNumber(value)) {
      if (value == undefined) {
        // Search for `undefined` or The Hole. Even in the case of
        // PACKED_DOUBLE_ELEMENTS or PACKED_SMI_ELEMENTS, we might encounter The
        // Hole here, since the {length} used here can be larger than
        // JSArray::length.
        if (IsSmiOrObjectElementsKind(Subclass::kind()) ||
            IsAnyNonextensibleElementsKind(Subclass::kind())) {
          Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            Tagged<Object> element_k = elements->get(static_cast<int>(k));

            if (element_k == the_hole || element_k == undefined) {
              return Just(true);
            }
          }
          return Just(false);
        } else {
          // Search for The Hole in HOLEY_DOUBLE_ELEMENTS or
          // PACKED_DOUBLE_ELEMENTS.
          DCHECK(IsDoubleElementsKind(Subclass::kind()));
          Tagged<FixedDoubleArray> elements =
              Cast<FixedDoubleArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (elements->is_the_hole(static_cast<int>(k))) return Just(true);
          }
          return Just(false);
        }
      } else if (!IsObjectElementsKind(Subclass::kind()) &&
                 !IsAnyNonextensibleElementsKind(Subclass::kind())) {
        // Search for non-number, non-Undefined value, with either
        // PACKED_SMI_ELEMENTS, PACKED_DOUBLE_ELEMENTS, HOLEY_SMI_ELEMENTS or
        // HOLEY_DOUBLE_ELEMENTS. Guaranteed to return false, since these
        // elements kinds can only contain Number values or undefined.
        return Just(false);
      } else {
        // Search for non-number, non-Undefined value with either
        // PACKED_ELEMENTS or HOLEY_ELEMENTS.
        DCHECK(IsObjectElementsKind(Subclass::kind()) ||
               IsAnyNonextensibleElementsKind(Subclass::kind()));
        Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

        for (size_t k = start_from; k < length; ++k) {
          Tagged<Object> element_k = elements->get(static_cast<int>(k));
          if (element_k == the_hole) continue;
          if (Object::SameValueZero(value, element_k)) return Just(true);
        }
        return Just(false);
      }
    } else {
      if (!IsNaN(value)) {
        double search_number = Object::NumberValue(value);
        if (IsDoubleElementsKind(Subclass::kind())) {
          // Search for non-NaN Number in PACKED_DOUBLE_ELEMENTS or
          // HOLEY_DOUBLE_ELEMENTS --- Skip TheHole, and trust UCOMISD or
          // similar operation for result.
          Tagged<FixedDoubleArray> elements =
              Cast<FixedDoubleArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (elements->is_the_hole(static_cast<int>(k))) continue;
            if (elements->get_scalar(static_cast<int>(k)) == search_number) {
              return Just(true);
            }
          }
          return Just(false);
        } else {
          // Search for non-NaN Number in PACKED_ELEMENTS, HOLEY_ELEMENTS,
          // PACKED_SMI_ELEMENTS or HOLEY_SMI_ELEMENTS --- Skip non-Numbers,
          // and trust UCOMISD or similar operation for result
          Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            Tagged<Object> element_k = elements->get(static_cast<int>(k));
            if (IsNumber(element_k) &&
                Object::NumberValue(element_k) == search_number) {
              return Just(true);
            }
          }
          return Just(false);
        }
      } else {
        // Search for NaN --- NaN cannot be represented with Smi elements, so
        // abort if ElementsKind is PACKED_SMI_ELEMENTS or HOLEY_SMI_ELEMENTS
        if (IsSmiElementsKind(Subclass::kind())) return Just(false);

        if (IsDoubleElementsKind(Subclass::kind())) {
          // Search for NaN in PACKED_DOUBLE_ELEMENTS or
          // HOLEY_DOUBLE_ELEMENTS --- Skip The Hole and trust
          // std::isnan(elementK) for result
          Tagged<FixedDoubleArray> elements =
              Cast<FixedDoubleArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (elements->is_the_hole(static_cast<int>(k))) continue;
            if (std::isnan(elements->get_scalar(static_cast<int>(k)))) {
              return Just(true);
            }
          }
          return Just(false);
        } else {
          // Search for NaN in PACKED_ELEMENTS or HOLEY_ELEMENTS. Return true
          // if elementK->IsHeapNumber() && std::isnan(elementK->Number())
          DCHECK(IsObjectElementsKind(Subclass::kind()) ||
                 IsAnyNonextensibleElementsKind(Subclass::kind()));
          Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());

          for (size_t k = start_from; k < length; ++k) {
            if (IsNaN(elements->get(static_cast<int>(k)))) return Just(true);
          }
          return Just(false);
        }
      }
    }
  }

  static Handle<FixedArray> CreateListFromArrayLikeImpl(
      Isolate* isolate, DirectHandle<JSObject> object, uint32_t length) {
    Handle<FixedArray> result = isolate->factory()->NewFixedArray(length);
    DirectHandle<FixedArrayBase> elements(object->elements(), isolate);
    for (uint32_t i = 0; i < length; i++) {
      InternalIndex entry(i);
      if (!Subclass::HasEntryImpl(isolate, *elements, entry)) continue;
      Handle<Object> value;
      value = Subclass::GetImpl(isolate, *elements, entry);
      if (IsName(*value)) {
        value = isolate->factory()->InternalizeName(Cast<Name>(value));
      }
      result->set(i, *value);
    }
    return result;
  }

  static MaybeHandle<Object> RemoveElement(Handle<JSArray> receiver,
                                           Where remove_position) {
    Isolate* isolate = receiver->GetIsolate();
    ElementsKind kind = KindTraits::Kind;
    if (IsSmiOrObjectElementsKind(kind)) {
      HandleScope scope(isolate);
      JSObject::EnsureWritableFastElements(receiver);
    }
    Handle<FixedArrayBase> backing_store(receiver->elements(), isolate);
    uint32_t length = static_cast<uint32_t>(Smi::ToInt(receiver->length()));
    DCHECK_GT(length, 0);
    int new_length = length - 1;
    int remove_index = remove_position == AT_START ? 0 : new_length;
    Handle<Object> result =
        Subclass::GetImpl(isolate, *backing_store, InternalIndex(remove_index));
    if (remove_position == AT_START) {
      Subclass::MoveElements(isolate, receiver, backing_store, 0, 1, new_length,
                             0, 0);
    }
    MAYBE_RETURN_NULL(
        Subclass::SetLengthImpl(isolate, receiver, new_length, backing_store));

    if (IsHoleyElementsKind(kind) && IsTheHole(*result, isolate)) {
      return isolate->factory()->undefined_value();
    }
    return MaybeHandle<Object>(result);
  }

  static Maybe<uint32_t> AddArguments(Handle<JSArray> receiver,
                                      Handle<FixedArrayBase> backing_store,
                                      BuiltinArguments* args, uint32_t add_size,
                                      Where add_position) {
    uint32_t length = Smi::ToInt(receiver->length());
    DCHECK_LT(0, add_size);
    uint32_t elms_len = backing_store->length();
    // Check we do not overflow the new_length.
    DCHECK(add_size <= static_cast<uint32_t>(Smi::kMaxValue - length));
    uint32_t new_length = length + add_size;
    Isolate* isolate = receiver->GetIsolate();

    if (new_length > elms_len) {
      // New backing storage is needed.
      uint32_t capacity = JSObject::NewElementsCapacity(new_length);
      // If we add arguments to the start we have to shift the existing objects.
      int copy_dst_index = add_position == AT_START ? add_size : 0;
      // Copy over all objects to a new backing_store.
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(
          isolate, backing_store,
          Subclass::ConvertElementsWithCapacity(receiver, backing_store,
                                                KindTraits::Kind, capacity, 0,
                                                copy_dst_index),
          Nothing<uint32_t>());
      receiver->set_elements(*backing_store);
    } else if (add_position == AT_START) {
      // If the backing store has enough capacity and we add elements to the
      // start we have to shift the existing objects.
      Subclass::MoveElements(isolate, receiver, backing_store, add_size, 0,
                             length, 0, 0);
    }

    int insertion_index = add_position == AT_START ? 0 : length;
    // Copy the arguments to the start.
    Subclass::CopyArguments(args, backing_store, add_size, 1, insertion_index);
    // Set the length.
    receiver->set_length(Smi::FromInt(new_length));
    return Just(new_length);
  }

  static void CopyArguments(BuiltinArguments* args,
                            DirectHandle<FixedArrayBase> dst_store,
                            uint32_t copy_size, uint32_t src_index,
                            uint32_t dst_index) {
    // Add the provided values.
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> raw_backing_store = *dst_store;
    WriteBarrierMode mode = raw_backing_store->GetWriteBarrierMode(no_gc);
    for (uint32_t i = 0; i < copy_size; i++) {
      Tagged<Object> argument = (*args)[src_index + i];
      DCHECK(!IsTheHole(argument));
      Subclass::SetImpl(raw_backing_store, InternalIndex(dst_index + i),
                        argument, mode);
    }
  }
};

template <typename Subclass, typename KindTraits>
class FastSmiOrObjectElementsAccessor
    : public FastElementsAccessor<Subclass, KindTraits> {
 public:
  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    SetImpl(holder->elements(), entry, value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value) {
    Cast<FixedArray>(backing_store)->set(entry.as_int(), value);
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value,
                             WriteBarrierMode mode) {
    Cast<FixedArray>(backing_store)->set(entry.as_int(), value, mode);
  }

  static Tagged<Object> GetRaw(Tagged<FixedArray> backing_store,
                               InternalIndex entry) {
    return backing_store->get(entry.as_int());
  }

  // NOTE: this method violates the handlified function signature convention:
  // raw pointer parameters in the function that allocates.
  // See ElementsAccessor::CopyElements() for details.
  // This method could actually allocate if copying from double elements to
  // object elements.
  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    DisallowGarbageCollection no_gc;
    ElementsKind to_kind = KindTraits::Kind;
    switch (from_kind) {
      case PACKED_SMI_ELEMENTS:
      case HOLEY_SMI_ELEMENTS:
      case PACKED_ELEMENTS:
      case PACKED_FROZEN_ELEMENTS:
      case PACKED_SEALED_ELEMENTS:
      case PACKED_NONEXTENSIBLE_ELEMENTS:
      case HOLEY_ELEMENTS:
      case HOLEY_FROZEN_ELEMENTS:
      case HOLEY_SEALED_ELEMENTS:
      case HOLEY_NONEXTENSIBLE_ELEMENTS:
      case SHARED_ARRAY_ELEMENTS:
        CopyObjectToObjectElements(isolate, from, from_kind, from_start, to,
                                   to_kind, to_start, copy_size);
        break;
      case PACKED_DOUBLE_ELEMENTS:
      case HOLEY_DOUBLE_ELEMENTS: {
        AllowGarbageCollection allow_allocation;
        DCHECK(IsObjectElementsKind(to_kind));
        CopyDoubleToObjectElements(isolate, from, from_start, to, to_start,
                                   copy_size);
        break;
      }
      case DICTIONARY_ELEMENTS:
        CopyDictionaryToObjectElements(isolate, from, from_start, to, to_kind,
                                       to_start, copy_size);
        break;
      case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
      case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      case FAST_STRING_WRAPPER_ELEMENTS:
      case SLOW_STRING_WRAPPER_ELEMENTS:
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:
        TYPED_ARRAYS(TYPED_ARRAY_CASE)
        RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      case WASM_ARRAY_ELEMENTS:
        // This function is currently only used for JSArrays with non-zero
        // length.
        UNREACHABLE();
      case NO_ELEMENTS:
        break;  // Nothing to do.
    }
  }

  static Maybe<bool> CollectValuesOrEntriesImpl(
      Isolate* isolate, DirectHandle<JSObject> object,
      DirectHandle<FixedArray> values_or_entries, bool get_entries,
      int* nof_items, PropertyFilter filter) {
    int count = 0;
    if (get_entries) {
      // Collecting entries needs to allocate, so this code must be handlified.
      DirectHandle<FixedArray> elements(Cast<FixedArray>(object->elements()),
                                        isolate);
      uint32_t length = elements->length();
      for (uint32_t index = 0; index < length; ++index) {
        InternalIndex entry(index);
        if (!Subclass::HasEntryImpl(isolate, *elements, entry)) continue;
        DirectHandle<Object> value =
            Subclass::GetImpl(isolate, *elements, entry);
        value = MakeEntryPair(isolate, index, value);
        values_or_entries->set(count++, *value);
      }
    } else {
      // No allocations here, so we can avoid handlification overhead.
      DisallowGarbageCollection no_gc;
      Tagged<FixedArray> elements = Cast<FixedArray>(object->elements());
      uint32_t length = elements->length();
      for (uint32_t index = 0; index < length; ++index) {
        InternalIndex entry(index);
        if (!Subclass::HasEntryImpl(isolate, elements, entry)) continue;
        Tagged<Object> value = GetRaw(elements, entry);
        values_or_entries->set(count++, value);
      }
    }
    *nof_items = count;
    return Just(true);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         DirectHandle<JSObject> receiver,
                                         DirectHandle<Object> search_value,
                                         size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *receiver));
    DisallowGarbageCollection no_gc;
    Tagged<FixedArrayBase> elements_base = receiver->elements();
    Tagged<Object> value = *search_value;

    if (start_from >= length) return Just<int64_t>(-1);

    length = std::min(static_cast<size_t>(elements_base->length()), length);

    // Only FAST_{,HOLEY_}ELEMENTS can store non-numbers.
    if (!IsNumber(value) && !IsObjectElementsKind(Subclass::kind()) &&
        !IsAnyNonextensibleElementsKind(Subclass::kind())) {
      return Just<int64_t>(-1);
    }
    // NaN can never be found by strict equality.
    if (IsNaN(value)) return Just<int64_t>(-1);

    // k can be greater than receiver->length() below, but it is bounded by
    // elements_base->length() so we never read out of bounds. This means that
    // elements->get(k) can return the hole, for which the StrictEquals will
    // always fail.
    Tagged<FixedArray> elements = Cast<FixedArray>(receiver->elements());
    static_assert(FixedArray::kMaxLength <=
                  std::numeric_limits<uint32_t>::max());
    for (size_t k = start_from; k < length; ++k) {
      if (Object::StrictEquals(value,
                               elements->get(static_cast<uint32_t>(k)))) {
        return Just<int64_t>(k);
      }
    }
    return Just<int64_t>(-1);
  }
};

class FastPackedSmiElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastPackedSmiElementsAccessor,
          ElementsKindTraits<PACKED_SMI_ELEMENTS>> {};

class FastHoleySmiElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastHoleySmiElementsAccessor,
          ElementsKindTraits<HOLEY_SMI_ELEMENTS>> {};

class FastPackedObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastPackedObjectElementsAccessor,
          ElementsKindTraits<PACKED_ELEMENTS>> {};

template <typename Subclass, typename KindTraits>
class FastNonextensibleObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    UNREACHABLE();
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  // TODO(duongn): refactor this due to code duplication of sealed version.
  // Consider using JSObject::NormalizeElements(). Also consider follow the fast
  // element logic instead of changing to dictionary mode.
  static Maybe<bool> SetLengthImpl(Isolate* isolate, Handle<JSArray> array,
                                   uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    uint32_t old_length = 0;
    CHECK(Object::ToArrayIndex(array->length(), &old_length));
    if (length == old_length) {
      // Do nothing.
      return Just(true);
    }

    // Transition to DICTIONARY_ELEMENTS.
    // Convert to dictionary mode.
    Handle<NumberDictionary> new_element_dictionary =
        old_length == 0 ? isolate->factory()->empty_slow_element_dictionary()
                        : array->GetElementsAccessor()->Normalize(array);

    // Migrate map.
    DirectHandle<Map> new_map = Map::Copy(
        isolate, handle(array->map(), isolate), "SlowCopyForSetLengthImpl");
    new_map->set_is_extensible(false);
    new_map->set_elements_kind(DICTIONARY_ELEMENTS);
    JSObject::MigrateToMap(isolate, array, new_map);

    if (!new_element_dictionary.is_null()) {
      array->set_elements(*new_element_dictionary);
    }

    if (array->elements() !=
        ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
      Handle<NumberDictionary> dictionary(array->element_dictionary(), isolate);
      // Make sure we never go back to the fast case
      array->RequireSlowElements(*dictionary);
      JSObject::ApplyAttributesToDictionary(isolate, ReadOnlyRoots(isolate),
                                            dictionary,
                                            PropertyAttributes::NONE);
    }

    // Set length.
    Handle<FixedArrayBase> new_backing_store(array->elements(), isolate);
    return DictionaryElementsAccessor::SetLengthImpl(isolate, array, length,
                                                     new_backing_store);
  }
};

class FastPackedNonextensibleObjectElementsAccessor
    : public FastNonextensibleObjectElementsAccessor<
          FastPackedNonextensibleObjectElementsAccessor,
          ElementsKindTraits<PACKED_NONEXTENSIBLE_ELEMENTS>> {};

class FastHoleyNonextensibleObjectElementsAccessor
    : public FastNonextensibleObjectElementsAccessor<
          FastHoleyNonextensibleObjectElementsAccessor,
          ElementsKindTraits<HOLEY_NONEXTENSIBLE_ELEMENTS>> {};

template <typename Subclass, typename KindTraits>
class FastSealedObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static Handle<Object> RemoveElement(DirectHandle<JSArray> receiver,
                                      Where remove_position) {
    UNREACHABLE();
  }

  static void DeleteImpl(DirectHandle<JSObject> obj, InternalIndex entry) {
    UNREACHABLE();
  }

  static void DeleteAtEnd(DirectHandle<JSObject> obj,
                          DirectHandle<BackingStore> backing_store,
                          uint32_t entry) {
    UNREACHABLE();
  }

  static void DeleteCommon(DirectHandle<JSObject> obj, uint32_t entry,
                           DirectHandle<FixedArrayBase> store) {
    UNREACHABLE();
  }

  static MaybeHandle<Object> PopImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    UNREACHABLE();
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  // TODO(duongn): refactor this due to code duplication of nonextensible
  // version. Consider using JSObject::NormalizeElements(). Also consider follow
  // the fast element logic instead of changing to dictionary mode.
  static Maybe<bool> SetLengthImpl(Isolate* isolate, Handle<JSArray> array,
                                   uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    uint32_t old_length = 0;
    CHECK(Object::ToArrayIndex(array->length(), &old_length));
    if (length == old_length) {
      // Do nothing.
      return Just(true);
    }

    // Transition to DICTIONARY_ELEMENTS.
    // Convert to dictionary mode
    DirectHandle<NumberDictionary> new_element_dictionary =
        old_length == 0 ? isolate->factory()->empty_slow_element_dictionary()
                        : array->GetElementsAccessor()->Normalize(array);

    // Migrate map.
    DirectHandle<Map> new_map = Map::Copy(
        isolate, handle(array->map(), isolate), "SlowCopyForSetLengthImpl");
    new_map->set_is_extensible(false);
    new_map->set_elements_kind(DICTIONARY_ELEMENTS);
    JSObject::MigrateToMap(isolate, array, new_map);

    if (!new_element_dictionary.is_null()) {
      array->set_elements(*new_element_dictionary);
    }

    if (array->elements() !=
        ReadOnlyRoots(isolate).empty_slow_element_dictionary()) {
      Handle<NumberDictionary> dictionary(array->element_dictionary(), isolate);
      // Make sure we never go back to the fast case
      array->RequireSlowElements(*dictionary);
      JSObject::ApplyAttributesToDictionary(isolate, ReadOnlyRoots(isolate),
                                            dictionary,
                                            PropertyAttributes::SEALED);
    }

    // Set length
    Handle<FixedArrayBase> new_backing_store(array->elements(), isolate);
    return DictionaryElementsAccessor::SetLengthImpl(isolate, array, length,
                                                     new_backing_store);
  }
};

class FastPackedSealedObjectElementsAccessor
    : public FastSealedObjectElementsAccessor<
          FastPackedSealedObjectElementsAccessor,
          ElementsKindTraits<PACKED_SEALED_ELEMENTS>> {};

class SharedArrayElementsAccessor
    : public FastSealedObjectElementsAccessor<
          SharedArrayElementsAccessor,
          ElementsKindTraits<SHARED_ARRAY_ELEMENTS>> {
 public:
  static Handle<Object> GetAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, SeqCstAccessTag tag) {
    return handle(Cast<BackingStore>(backing_store)->get(entry.as_int(), tag),
                  isolate);
  }

  static void SetAtomicInternalImpl(Tagged<FixedArrayBase> backing_store,
                                    InternalIndex entry, Tagged<Object> value,
                                    SeqCstAccessTag tag) {
    Cast<BackingStore>(backing_store)->set(entry.as_int(), value, tag);
  }

  static Handle<Object> SwapAtomicInternalImpl(
      Isolate* isolate, Tagged<FixedArrayBase> backing_store,
      InternalIndex entry, Tagged<Object> value, SeqCstAccessTag tag) {
    return handle(
        Cast<BackingStore>(backing_store)->swap(entry.as_int(), value, tag),
        isolate);
  }

  static Tagged<Object> CompareAndSwapAtomicInternalImpl(
      Tagged<FixedArrayBase> backing_store, InternalIndex entry,
      Tagged<Object> expected, Tagged<Object> value, SeqCstAccessTag tag) {
    return Cast<BackingStore>(backing_store)
        ->compare_and_swap(entry.as_int(), expected, value, tag);
  }
};

class FastHoleySealedObjectElementsAccessor
    : public FastSealedObjectElementsAccessor<
          FastHoleySealedObjectElementsAccessor,
          ElementsKindTraits<HOLEY_SEALED_ELEMENTS>> {};

template <typename Subclass, typename KindTraits>
class FastFrozenObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<Subclass, KindTraits> {
 public:
  using BackingStore = typename KindTraits::BackingStore;

  static inline void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                             Tagged<Object> value) {
    UNREACHABLE();
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value) {
    UNREACHABLE();
  }

  static inline void SetImpl(Tagged<FixedArrayBase> backing_store,
                             InternalIndex entry, Tagged<Object> value,
                             WriteBarrierMode mode) {
    UNREACHABLE();
  }

  static Handle<Object> RemoveElement(DirectHandle<JSArray> receiver,
                                      Where remove_position) {
    UNREACHABLE();
  }

  static void DeleteImpl(DirectHandle<JSObject> obj, InternalIndex entry) {
    UNREACHABLE();
  }

  static void DeleteAtEnd(DirectHandle<JSObject> obj,
                          DirectHandle<BackingStore> backing_store,
                          uint32_t entry) {
    UNREACHABLE();
  }

  static void DeleteCommon(DirectHandle<JSObject> obj, uint32_t entry,
                           DirectHandle<FixedArrayBase> store) {
    UNREACHABLE();
  }

  static MaybeHandle<Object> PopImpl(DirectHandle<JSArray> receiver) {
    UNREACHABLE();
  }

  static Maybe<uint32_t> PushImpl(DirectHandle<JSArray> receiver,
                                  BuiltinArguments* args, uint32_t push_size) {
    UNREACHABLE();
  }

  static Maybe<bool> AddImpl(DirectHandle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    UNREACHABLE();
  }

  static Maybe<bool> SetLengthImpl(Isolate* isolate,
                                   DirectHandle<JSArray> array, uint32_t length,
                                   DirectHandle<FixedArrayBase> backing_store) {
    UNREACHABLE();
  }

  static void ReconfigureImpl(DirectHandle<JSObject> object,
                              DirectHandle<FixedArrayBase> store,
                              InternalIndex entry, DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    UNREACHABLE();
  }
};

class FastPackedFrozenObjectElementsAccessor
    : public FastFrozenObjectElementsAccessor<
          FastPackedFrozenObjectElementsAccessor,
          ElementsKindTraits<PACKED_FROZEN_ELEMENTS>> {};

class FastHoleyFrozenObjectElementsAccessor
    : public FastFrozenObjectElementsAccessor<
          FastHoleyFrozenObjectElementsAccessor,
          ElementsKindTraits<HOLEY_FROZEN_ELEMENTS>> {};

class FastHoleyObjectElementsAccessor
    : public FastSmiOrObjectElementsAccessor<
          FastHoleyObjectElementsAccessor, ElementsKindTraits<HOLEY_ELEMENTS>> {
};

// Helper templates to statically determine if our destination type can contain
// the source type.
template <ElementsKind Kind, typename ElementType, ElementsKind SourceKind,
          typename SourceElementType>
struct CopyBetweenBackingStoresImpl;

template <typename Subclass, typename KindTraits>
class FastDoubleElementsAccessor
    : public FastElementsAccessor<Subclass, KindTraits> {
 public:
  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> backing_store,
                                InternalIndex entry) {
    return FixedDoubleArray::get(Cast<Fixe
```