Response: The user wants a summary of the C++ source code file `v8/src/objects/elements.cc`.
This is the fourth and final part of the file.
The goal is to understand the functionality of this code and its relation to JavaScript.
I need to identify the key data structures and functions in this part and connect them to JavaScript concepts if applicable.

Looking at the code, I see several classes implementing `ElementsAccessor` with different backing stores and elements kinds.
Specifically, I see:
- `SlowSloppyArgumentsElementsAccessor` and `FastSloppyArgumentsElementsAccessor` related to handling arguments objects in JavaScript functions.
- `StringWrapperElementsAccessor`, `FastStringWrapperElementsAccessor`, and `SlowStringWrapperElementsAccessor` which seem to handle the elements of String wrapper objects.
- Functions like `ArrayConstructInitializeElements`, `CopyFastNumberJSArrayElementsToTypedArray`, `CopyTypedArrayElementsToTypedArray`, and `CopyTypedArrayElementsSlice` that deal with array initialization and copying elements.
- The `ElementsAccessor` class itself, including initialization and the `Concat` function.

Key functionalities to summarize:
1. **Handling of "sloppy arguments" objects:** These objects behave like arrays but have special properties related to function parameters.
2. **Handling of String wrapper objects:** These objects wrap primitive strings and allow accessing individual characters as elements.
3. **Array construction and initialization:** How JavaScript arrays are created and populated with initial values.
4. **Efficient element copying:** Optimized functions for copying elements between different types of arrays (JSArrays and TypedArrays).
5. **ElementsAccessor infrastructure:** The overall framework for managing elements of JavaScript objects with different storage strategies.
这是 `v8/src/objects/elements.cc` 文件的第 4 部分，主要负责实现 JavaScript 对象元素（properties accessed by index) 的各种操作，特别是针对一些特殊情况的优化和处理。 结合前三部分，这一部分延续了对不同元素存储方式（ElementsKind）的具体实现，并提供了一些高级功能。

**主要功能归纳:**

1. **Sloppy Arguments 对象的元素访问:**
   - 实现了 `SlowSloppyArgumentsElementsAccessor` 和 `FastSloppyArgumentsElementsAccessor` 两个类，专门用于处理“sloppy arguments”对象（非严格模式下 `arguments` 对象）的元素访问。
   - "Sloppy arguments" 对象比较特殊，它的元素可能映射到函数的形参变量。 这两个类分别处理了慢速和快速情况下的访问、添加、删除和修改元素，以及与参数映射相关的逻辑。
   - 快速版本 (`FastSloppyArgumentsElementsAccessor`) 尝试使用更高效的存储方式，并在必要时转换为慢速版本 (`SlowSloppyArgumentsElementsAccessor`)。

2. **String Wrapper 对象的元素访问:**
   - 实现了 `StringWrapperElementsAccessor`, `FastStringWrapperElementsAccessor`, 和 `SlowStringWrapperElementsAccessor` 用于处理 String 包装对象的元素访问。
   - String 包装对象允许像访问数组一样访问字符串的单个字符。
   - 这些类处理了获取字符、获取属性描述符、检查是否存在、删除（实际上不允许删除字符串字符）、设置（也不允许修改字符串字符）等操作。
   - 同样存在快速和慢速的实现，快速版本在可能的情况下使用更高效的存储。

3. **数组构造和初始化 (`ArrayConstructInitializeElements`):**
   -  `ArrayConstructInitializeElements` 函数负责在 JavaScript 中使用 `new Array()` 或 `[...]` 语法创建数组时，初始化数组的元素。
   -  它根据传入的参数数量和类型，选择合适的元素存储方式 (ElementsKind)，并分配和填充数组的底层存储。
   -  针对不同的元素类型 (SMI, Object, Double)，使用了不同的填充逻辑。

4. **TypedArray 的元素复制 (`CopyFastNumberJSArrayElementsToTypedArray`, `CopyTypedArrayElementsToTypedArray`, `CopyTypedArrayElementsSlice`):**
   -  提供了高效的函数，用于将快速数字类型的 `JSArray` 的元素复制到 `TypedArray`，以及在不同的 `TypedArray` 之间复制元素。
   -  `CopyTypedArrayElementsSlice` 允许复制 `TypedArray` 的一部分。
   -  这些函数直接操作内存，避免了 JavaScript 层面的循环，提高了性能。

5. **`ElementsAccessor` 类的初始化和管理:**
   -  `ElementsAccessor::InitializeOncePerProcess()` 负责在进程启动时初始化一个 `ElementsAccessor` 数组，该数组根据 `ElementsKind` 存储了不同元素访问器的实例。
   -  这是一种策略模式的应用，根据对象的 `ElementsKind` 动态选择合适的访问器。

6. **数组的 `concat` 操作 (`ElementsAccessor::Concat`):**
   -  `ElementsAccessor::Concat` 函数实现了 JavaScript 数组的 `concat` 方法。
   -  它会分析参与连接的数组的 `ElementsKind`，选择一个最通用的 `ElementsKind` 作为结果数组的存储方式，并高效地将源数组的元素复制到结果数组中。

**与 JavaScript 功能的关联和示例:**

1. **Sloppy Arguments:**
   ```javascript
   function foo(a, b) {
     console.log(arguments[0]); // 访问 arguments 对象的元素
     arguments[0] = 10;       // 修改 arguments 对象的元素，可能影响到形参 a
     console.log(a);           // 输出可能被修改的形参 a 的值
   }
   foo(1, 2);
   ```
   `SlowSloppyArgumentsElementsAccessor` 和 `FastSloppyArgumentsElementsAccessor` 负责实现 `arguments[0]` 的读取和赋值操作，并处理与形参 `a` 之间的映射关系。

2. **String Wrapper:**
   ```javascript
   const str = new String("hello");
   console.log(str[0]); // 访问 String 包装对象的元素，获取字符 'h'
   str[0] = 'H';         // 尝试修改 String 包装对象的元素，但无效
   console.log(str[0]); // 仍然是 'h'
   ```
   `StringWrapperElementsAccessor` 等类负责实现 `str[0]` 的读取操作，并处理修改操作的只读特性。

3. **数组构造:**
   ```javascript
   const arr1 = new Array(5);     // 创建一个长度为 5 的空数组
   const arr2 = new Array(1, 2, 3); // 创建并初始化数组
   const arr3 = [4, 5, 6];          // 字面量方式创建并初始化数组
   ```
   `ArrayConstructInitializeElements` 函数会在这些数组创建过程中被调用，根据参数情况分配和初始化数组的底层存储。

4. **TypedArray 复制:**
   ```javascript
   const buffer1 = new ArrayBuffer(8);
   const typedArray1 = new Int32Array(buffer1);
   typedArray1[0] = 1;
   typedArray1[1] = 2;

   const buffer2 = new ArrayBuffer(8);
   const typedArray2 = new Int32Array(buffer2);

   typedArray2.set(typedArray1); // 使用 set 方法复制 TypedArray 的元素
   ```
   `CopyTypedArrayElementsToTypedArray` 等函数会在 `typedArray2.set(typedArray1)` 内部被调用，高效地将 `typedArray1` 的元素复制到 `typedArray2` 中。

5. **数组 `concat`:**
   ```javascript
   const arrA = [1, 2];
   const arrB = [3, 4];
   const arrC = arrA.concat(arrB); // 连接两个数组
   console.log(arrC); // 输出 [1, 2, 3, 4]
   ```
   `ElementsAccessor::Concat` 函数负责实现 `arrA.concat(arrB)` 的逻辑，创建新的数组并合并元素。

总而言之，这部分代码深入 V8 引擎的内部，实现了 JavaScript 中一些复杂对象（如 arguments 对象和 String 包装对象）的元素访问机制，并提供了高性能的数组操作功能，这些都对 JavaScript 代码的执行效率至关重要。

Prompt: 
```
这是目录为v8/src/objects/elements.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
                             Tagged<FixedArrayBase> store) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(store);
    Tagged<FixedArray> arguments = elements->arguments();
    return elements->length() +
           ArgumentsAccessor::GetCapacityImpl(holder, arguments);
  }

  static uint32_t GetMaxNumberOfEntries(Isolate* isolate,
                                        Tagged<JSObject> holder,
                                        Tagged<FixedArrayBase> backing_store) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(backing_store);
    Tagged<FixedArrayBase> arguments = elements->arguments();
    size_t max_entries =
        ArgumentsAccessor::GetMaxNumberOfEntries(isolate, holder, arguments);
    DCHECK_LE(max_entries, std::numeric_limits<uint32_t>::max());
    return elements->length() + static_cast<uint32_t>(max_entries);
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> receiver,
                                       Tagged<FixedArrayBase> backing_store) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(backing_store);
    Tagged<FixedArrayBase> arguments = elements->arguments();
    uint32_t nof_elements = 0;
    uint32_t length = elements->length();
    for (uint32_t index = 0; index < length; index++) {
      if (HasParameterMapArg(isolate, elements, index)) nof_elements++;
    }
    return nof_elements + ArgumentsAccessor::NumberOfElementsImpl(
                              isolate, receiver, arguments);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus AddElementsToKeyAccumulatorImpl(
      DirectHandle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) {
    Isolate* isolate = accumulator->isolate();
    DirectHandle<FixedArrayBase> elements(receiver->elements(), isolate);
    uint32_t length = GetCapacityImpl(*receiver, *elements);
    for (uint32_t index = 0; index < length; index++) {
      InternalIndex entry(index);
      if (!HasEntryImpl(isolate, *elements, entry)) continue;
      Handle<Object> value = GetImpl(isolate, *elements, entry);
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(accumulator->AddKey(value, convert));
    }
    return ExceptionStatus::kSuccess;
  }

  static bool HasEntryImpl(Isolate* isolate, Tagged<FixedArrayBase> parameters,
                           InternalIndex entry) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(parameters);
    uint32_t length = elements->length();
    if (entry.raw_value() < length) {
      return HasParameterMapArg(isolate, elements, entry.raw_value());
    }
    Tagged<FixedArrayBase> arguments = elements->arguments();
    return ArgumentsAccessor::HasEntryImpl(isolate, arguments,
                                           entry.adjust_down(length));
  }

  static bool HasAccessorsImpl(Tagged<JSObject> holder,
                               Tagged<FixedArrayBase> backing_store) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(backing_store);
    Tagged<FixedArray> arguments = elements->arguments();
    return ArgumentsAccessor::HasAccessorsImpl(holder, arguments);
  }

  static InternalIndex GetEntryForIndexImpl(Isolate* isolate,
                                            Tagged<JSObject> holder,
                                            Tagged<FixedArrayBase> parameters,
                                            size_t index,
                                            PropertyFilter filter) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(parameters);
    if (HasParameterMapArg(isolate, elements, index)) {
      return InternalIndex(index);
    }
    Tagged<FixedArray> arguments = elements->arguments();
    InternalIndex entry = ArgumentsAccessor::GetEntryForIndexImpl(
        isolate, holder, arguments, index, filter);
    if (entry.is_not_found()) return entry;
    // Arguments entries could overlap with the dictionary entries, hence offset
    // them by the number of context mapped entries.
    return entry.adjust_up(elements->length());
  }

  static PropertyDetails GetDetailsImpl(Tagged<JSObject> holder,
                                        InternalIndex entry) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(holder->elements());
    uint32_t length = elements->length();
    if (entry.as_uint32() < length) {
      return PropertyDetails(PropertyKind::kData, NONE,
                             PropertyCellType::kNoCell);
    }
    Tagged<FixedArray> arguments = elements->arguments();
    return ArgumentsAccessor::GetDetailsImpl(arguments,
                                             entry.adjust_down(length));
  }

  static bool HasParameterMapArg(Isolate* isolate,
                                 Tagged<SloppyArgumentsElements> elements,
                                 size_t index) {
    uint32_t length = elements->length();
    if (index >= length) return false;
    return !IsTheHole(
        elements->mapped_entries(static_cast<uint32_t>(index), kRelaxedLoad),
        isolate);
  }

  static void DeleteImpl(Handle<JSObject> obj, InternalIndex entry) {
    Handle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(obj->elements()), obj->GetIsolate());
    uint32_t length = elements->length();
    InternalIndex delete_or_entry = entry;
    if (entry.as_uint32() < length) {
      delete_or_entry = InternalIndex::NotFound();
    }
    Subclass::SloppyDeleteImpl(obj, elements, delete_or_entry);
    // SloppyDeleteImpl allocates a new dictionary elements store. For making
    // heap verification happy we postpone clearing out the mapped entry.
    if (entry.as_uint32() < length) {
      elements->set_mapped_entries(entry.as_uint32(),
                                   obj->GetReadOnlyRoots().the_hole_value());
    }
  }

  static void SloppyDeleteImpl(DirectHandle<JSObject> obj,
                               DirectHandle<SloppyArgumentsElements> elements,
                               InternalIndex entry) {
    // Implemented in subclasses.
    UNREACHABLE();
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus CollectElementIndicesImpl(
      Handle<JSObject> object, Handle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) {
    Isolate* isolate = keys->isolate();
    uint32_t nof_indices = 0;
    Handle<FixedArray> indices = isolate->factory()->NewFixedArray(
        GetCapacityImpl(*object, *backing_store));
    DirectCollectElementIndicesImpl(isolate, object, backing_store,
                                    GetKeysConversion::kKeepNumbers,
                                    ENUMERABLE_STRINGS, indices, &nof_indices);
    SortIndices(isolate, indices, nof_indices);
    for (uint32_t i = 0; i < nof_indices; i++) {
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(keys->AddKey(indices->get(i)));
    }
    return ExceptionStatus::kSuccess;
  }

  static Handle<FixedArray> DirectCollectElementIndicesImpl(
      Isolate* isolate, Handle<JSObject> object,
      Handle<FixedArrayBase> backing_store, GetKeysConversion convert,
      PropertyFilter filter, Handle<FixedArray> list, uint32_t* nof_indices,
      uint32_t insertion_index = 0) {
    auto elements = Cast<SloppyArgumentsElements>(backing_store);
    uint32_t length = elements->length();

    for (uint32_t i = 0; i < length; ++i) {
      if (IsTheHole(elements->mapped_entries(i, kRelaxedLoad), isolate))
        continue;
      if (convert == GetKeysConversion::kConvertToString) {
        DirectHandle<String> index_string =
            isolate->factory()->Uint32ToString(i);
        list->set(insertion_index, *index_string);
      } else {
        list->set(insertion_index, Smi::FromInt(i));
      }
      insertion_index++;
    }

    Handle<FixedArray> store(elements->arguments(), isolate);
    return ArgumentsAccessor::DirectCollectElementIndicesImpl(
        isolate, object, store, convert, filter, list, nof_indices,
        insertion_index);
  }

  static Maybe<bool> IncludesValueImpl(Isolate* isolate,
                                       Handle<JSObject> object,
                                       DirectHandle<Object> value,
                                       size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *object));
    DirectHandle<Map> original_map(object->map(), isolate);
    DirectHandle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(object->elements()), isolate);
    bool search_for_hole = IsUndefined(*value, isolate);

    for (size_t k = start_from; k < length; ++k) {
      DCHECK_EQ(object->map(), *original_map);
      InternalIndex entry =
          GetEntryForIndexImpl(isolate, *object, *elements, k, ALL_PROPERTIES);
      if (entry.is_not_found()) {
        if (search_for_hole) return Just(true);
        continue;
      }

      DirectHandle<Object> element_k =
          Subclass::GetImpl(isolate, *elements, entry);

      if (IsAccessorPair(*element_k)) {
        LookupIterator it(isolate, object, k, LookupIterator::OWN);
        DCHECK(it.IsFound());
        DCHECK_EQ(it.state(), LookupIterator::ACCESSOR);
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                         Object::GetPropertyWithAccessor(&it),
                                         Nothing<bool>());

        if (Object::SameValueZero(*value, *element_k)) return Just(true);

        if (object->map() != *original_map) {
          // Some mutation occurred in accessor. Abort "fast" path
          return IncludesValueSlowPath(isolate, object, value, k + 1, length);
        }
      } else if (Object::SameValueZero(*value, *element_k)) {
        return Just(true);
      }
    }
    return Just(false);
  }

  static Maybe<int64_t> IndexOfValueImpl(Isolate* isolate,
                                         Handle<JSObject> object,
                                         DirectHandle<Object> value,
                                         size_t start_from, size_t length) {
    DCHECK(JSObject::PrototypeHasNoElements(isolate, *object));
    DirectHandle<Map> original_map(object->map(), isolate);
    DirectHandle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(object->elements()), isolate);

    for (size_t k = start_from; k < length; ++k) {
      DCHECK_EQ(object->map(), *original_map);
      InternalIndex entry =
          GetEntryForIndexImpl(isolate, *object, *elements, k, ALL_PROPERTIES);
      if (entry.is_not_found()) {
        continue;
      }

      DirectHandle<Object> element_k =
          Subclass::GetImpl(isolate, *elements, entry);

      if (IsAccessorPair(*element_k)) {
        LookupIterator it(isolate, object, k, LookupIterator::OWN);
        DCHECK(it.IsFound());
        DCHECK_EQ(it.state(), LookupIterator::ACCESSOR);
        ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, element_k,
                                         Object::GetPropertyWithAccessor(&it),
                                         Nothing<int64_t>());

        if (Object::StrictEquals(*value, *element_k)) {
          return Just<int64_t>(k);
        }

        if (object->map() != *original_map) {
          // Some mutation occurred in accessor. Abort "fast" path.
          return IndexOfValueSlowPath(isolate, object, value, k + 1, length);
        }
      } else if (Object::StrictEquals(*value, *element_k)) {
        return Just<int64_t>(k);
      }
    }
    return Just<int64_t>(-1);
  }
};

class SlowSloppyArgumentsElementsAccessor
    : public SloppyArgumentsElementsAccessor<
          SlowSloppyArgumentsElementsAccessor, DictionaryElementsAccessor,
          ElementsKindTraits<SLOW_SLOPPY_ARGUMENTS_ELEMENTS>> {
 public:
  static Handle<Object> ConvertArgumentsStoreResult(
      Isolate* isolate, DirectHandle<SloppyArgumentsElements> elements,
      Handle<Object> result) {
    // Elements of the arguments object in slow mode might be slow aliases.
    if (IsAliasedArgumentsEntry(*result)) {
      DisallowGarbageCollection no_gc;
      Tagged<AliasedArgumentsEntry> alias =
          Cast<AliasedArgumentsEntry>(*result);
      Tagged<Context> context = elements->context();
      int context_entry = alias->aliased_context_slot();
      DCHECK(!IsTheHole(context->get(context_entry), isolate));
      return handle(context->get(context_entry), isolate);
    }
    return result;
  }
  static void SloppyDeleteImpl(DirectHandle<JSObject> obj,
                               DirectHandle<SloppyArgumentsElements> elements,
                               InternalIndex entry) {
    // No need to delete a context mapped entry from the arguments elements.
    if (entry.is_not_found()) return;
    Isolate* isolate = obj->GetIsolate();
    Handle<NumberDictionary> dict(Cast<NumberDictionary>(elements->arguments()),
                                  isolate);
    uint32_t length = elements->length();
    dict =
        NumberDictionary::DeleteEntry(isolate, dict, entry.adjust_down(length));
    elements->set_arguments(*dict);
  }
  static Maybe<bool> AddImpl(Handle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    Isolate* isolate = object->GetIsolate();
    DirectHandle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(object->elements()), isolate);
    Handle<FixedArrayBase> old_arguments(elements->arguments(), isolate);
    Handle<NumberDictionary> dictionary =
        IsNumberDictionary(*old_arguments)
            ? Cast<NumberDictionary>(old_arguments)
            : JSObject::NormalizeElements(object);
    PropertyDetails details(PropertyKind::kData, attributes,
                            PropertyCellType::kNoCell);
    DirectHandle<NumberDictionary> new_dictionary =
        NumberDictionary::Add(isolate, dictionary, index, value, details);
    if (attributes != NONE) object->RequireSlowElements(*new_dictionary);
    if (*dictionary != *new_dictionary) {
      elements->set_arguments(*new_dictionary);
    }
    return Just(true);
  }

  static void ReconfigureImpl(DirectHandle<JSObject> object,
                              Handle<FixedArrayBase> store, InternalIndex entry,
                              DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    Isolate* isolate = object->GetIsolate();
    auto elements = Cast<SloppyArgumentsElements>(store);
    uint32_t length = elements->length();
    if (entry.as_uint32() < length) {
      Tagged<Object> probe =
          elements->mapped_entries(entry.as_uint32(), kRelaxedLoad);
      DCHECK(!IsTheHole(probe, isolate));
      Tagged<Context> context = elements->context();
      int context_entry = Smi::ToInt(probe);
      DCHECK(!IsTheHole(context->get(context_entry), isolate));
      context->set(context_entry, *value);

      // Redefining attributes of an aliased element destroys fast aliasing.
      elements->set_mapped_entries(entry.as_uint32(),
                                   ReadOnlyRoots(isolate).the_hole_value());
      // For elements that are still writable we re-establish slow aliasing.
      if ((attributes & READ_ONLY) == 0) {
        value = isolate->factory()->NewAliasedArgumentsEntry(context_entry);
      }

      PropertyDetails details(PropertyKind::kData, attributes,
                              PropertyCellType::kNoCell);
      Handle<NumberDictionary> arguments(
          Cast<NumberDictionary>(elements->arguments()), isolate);
      arguments = NumberDictionary::Add(isolate, arguments, entry.as_uint32(),
                                        value, details);
      // If the attributes were NONE, we would have called set rather than
      // reconfigure.
      DCHECK_NE(NONE, attributes);
      object->RequireSlowElements(*arguments);
      elements->set_arguments(*arguments);
    } else {
      DirectHandle<FixedArrayBase> arguments(elements->arguments(), isolate);
      DictionaryElementsAccessor::ReconfigureImpl(
          object, arguments, entry.adjust_down(length), value, attributes);
    }
  }
};

class FastSloppyArgumentsElementsAccessor
    : public SloppyArgumentsElementsAccessor<
          FastSloppyArgumentsElementsAccessor, FastHoleyObjectElementsAccessor,
          ElementsKindTraits<FAST_SLOPPY_ARGUMENTS_ELEMENTS>> {
 public:
  static Handle<Object> ConvertArgumentsStoreResult(
      Isolate* isolate, DirectHandle<SloppyArgumentsElements> parameter_map,
      Handle<Object> result) {
    DCHECK(!IsAliasedArgumentsEntry(*result));
    return result;
  }

  static Handle<FixedArray> GetArguments(Isolate* isolate,
                                         Tagged<FixedArrayBase> store) {
    Tagged<SloppyArgumentsElements> elements =
        Cast<SloppyArgumentsElements>(store);
    return Handle<FixedArray>(elements->arguments(), isolate);
  }

  static Handle<NumberDictionary> NormalizeImpl(
      Handle<JSObject> object, DirectHandle<FixedArrayBase> elements) {
    DirectHandle<FixedArray> arguments =
        GetArguments(object->GetIsolate(), *elements);
    return FastHoleyObjectElementsAccessor::NormalizeImpl(object, arguments);
  }

  static Handle<NumberDictionary> NormalizeArgumentsElements(
      Handle<JSObject> object, DirectHandle<SloppyArgumentsElements> elements,
      InternalIndex* entry) {
    Handle<NumberDictionary> dictionary = JSObject::NormalizeElements(object);
    elements->set_arguments(*dictionary);
    // kMaxUInt32 indicates that a context mapped element got deleted. In this
    // case we only normalize the elements (aka. migrate to SLOW_SLOPPY).
    if (entry->is_not_found()) return dictionary;
    uint32_t length = elements->length();
    if (entry->as_uint32() >= length) {
      *entry =
          dictionary
              ->FindEntry(object->GetIsolate(), entry->as_uint32() - length)
              .adjust_up(length);
    }
    return dictionary;
  }

  static void SloppyDeleteImpl(Handle<JSObject> obj,
                               DirectHandle<SloppyArgumentsElements> elements,
                               InternalIndex entry) {
    // Always normalize element on deleting an entry.
    NormalizeArgumentsElements(obj, elements, &entry);
    SlowSloppyArgumentsElementsAccessor::SloppyDeleteImpl(obj, elements, entry);
  }

  static Maybe<bool> AddImpl(Handle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    DCHECK_EQ(NONE, attributes);
    Isolate* isolate = object->GetIsolate();
    DirectHandle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(object->elements()), isolate);
    DirectHandle<FixedArray> old_arguments(elements->arguments(), isolate);
    if (IsNumberDictionary(*old_arguments) ||
        static_cast<uint32_t>(old_arguments->length()) < new_capacity) {
      MAYBE_RETURN(GrowCapacityAndConvertImpl(object, new_capacity),
                   Nothing<bool>());
    }
    Tagged<FixedArray> arguments = elements->arguments();
    // For fast holey objects, the entry equals the index. The code above made
    // sure that there's enough space to store the value. We cannot convert
    // index to entry explicitly since the slot still contains the hole, so the
    // current EntryForIndex would indicate that it is "absent" by returning
    // kMaxUInt32.
    FastHoleyObjectElementsAccessor::SetImpl(arguments, InternalIndex(index),
                                             *value);
    return Just(true);
  }

  static void ReconfigureImpl(Handle<JSObject> object,
                              Handle<FixedArrayBase> store, InternalIndex entry,
                              DirectHandle<Object> value,
                              PropertyAttributes attributes) {
    DCHECK_EQ(object->elements(), *store);
    DirectHandle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(*store), object->GetIsolate());
    NormalizeArgumentsElements(object, elements, &entry);
    SlowSloppyArgumentsElementsAccessor::ReconfigureImpl(object, store, entry,
                                                         value, attributes);
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    DCHECK(!IsNumberDictionary(to));
    if (from_kind == SLOW_SLOPPY_ARGUMENTS_ELEMENTS) {
      CopyDictionaryToObjectElements(isolate, from, from_start, to,
                                     HOLEY_ELEMENTS, to_start, copy_size);
    } else {
      DCHECK_EQ(FAST_SLOPPY_ARGUMENTS_ELEMENTS, from_kind);
      CopyObjectToObjectElements(isolate, from, HOLEY_ELEMENTS, from_start, to,
                                 HOLEY_ELEMENTS, to_start, copy_size);
    }
  }

  static Maybe<bool> GrowCapacityAndConvertImpl(Handle<JSObject> object,
                                                uint32_t capacity) {
    Isolate* isolate = object->GetIsolate();
    DirectHandle<SloppyArgumentsElements> elements(
        Cast<SloppyArgumentsElements>(object->elements()), isolate);
    Handle<FixedArray> old_arguments(Cast<FixedArray>(elements->arguments()),
                                     isolate);
    ElementsKind from_kind = object->GetElementsKind();
    // This method should only be called if there's a reason to update the
    // elements.
    DCHECK(from_kind == SLOW_SLOPPY_ARGUMENTS_ELEMENTS ||
           static_cast<uint32_t>(old_arguments->length()) < capacity);
    Handle<FixedArrayBase> arguments;
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, arguments,
        ConvertElementsWithCapacity(object, old_arguments, from_kind, capacity),
        Nothing<bool>());
    DirectHandle<Map> new_map = JSObject::GetElementsTransitionMap(
        object, FAST_SLOPPY_ARGUMENTS_ELEMENTS);
    JSObject::MigrateToMap(isolate, object, new_map);
    elements->set_arguments(Cast<FixedArray>(*arguments));
    JSObject::ValidateElements(*object);
    return Just(true);
  }
};

template <typename Subclass, typename BackingStoreAccessor, typename KindTraits>
class StringWrapperElementsAccessor
    : public ElementsAccessorBase<Subclass, KindTraits> {
 public:
  static Handle<Object> GetInternalImpl(Isolate* isolate,
                                        Handle<JSObject> holder,
                                        InternalIndex entry) {
    return GetImpl(holder, entry);
  }

  static Handle<Object> GetImpl(DirectHandle<JSObject> holder,
                                InternalIndex entry) {
    Isolate* isolate = holder->GetIsolate();
    Handle<String> string(GetString(*holder), isolate);
    uint32_t length = static_cast<uint32_t>(string->length());
    if (entry.as_uint32() < length) {
      return isolate->factory()->LookupSingleCharacterStringFromCode(
          String::Flatten(isolate, string)->Get(entry.as_int()));
    }
    return BackingStoreAccessor::GetImpl(isolate, holder->elements(),
                                         entry.adjust_down(length));
  }

  static Handle<Object> GetImpl(Isolate* isolate,
                                Tagged<FixedArrayBase> elements,
                                InternalIndex entry) {
    UNREACHABLE();
  }

  static PropertyDetails GetDetailsImpl(Tagged<JSObject> holder,
                                        InternalIndex entry) {
    uint32_t length = static_cast<uint32_t>(GetString(holder)->length());
    if (entry.as_uint32() < length) {
      PropertyAttributes attributes =
          static_cast<PropertyAttributes>(READ_ONLY | DONT_DELETE);
      return PropertyDetails(PropertyKind::kData, attributes,
                             PropertyCellType::kNoCell);
    }
    return BackingStoreAccessor::GetDetailsImpl(holder,
                                                entry.adjust_down(length));
  }

  static InternalIndex GetEntryForIndexImpl(
      Isolate* isolate, Tagged<JSObject> holder,
      Tagged<FixedArrayBase> backing_store, size_t index,
      PropertyFilter filter) {
    uint32_t length = static_cast<uint32_t>(GetString(holder)->length());
    if (index < length) return InternalIndex(index);
    InternalIndex backing_store_entry =
        BackingStoreAccessor::GetEntryForIndexImpl(
            isolate, holder, backing_store, index, filter);
    if (backing_store_entry.is_not_found()) return backing_store_entry;
    return backing_store_entry.adjust_up(length);
  }

  static void DeleteImpl(Handle<JSObject> holder, InternalIndex entry) {
    uint32_t length = static_cast<uint32_t>(GetString(*holder)->length());
    if (entry.as_uint32() < length) {
      return;  // String contents can't be deleted.
    }
    BackingStoreAccessor::DeleteImpl(holder, entry.adjust_down(length));
  }

  static void SetImpl(DirectHandle<JSObject> holder, InternalIndex entry,
                      Tagged<Object> value) {
    uint32_t length = static_cast<uint32_t>(GetString(*holder)->length());
    if (entry.as_uint32() < length) {
      return;  // String contents are read-only.
    }
    BackingStoreAccessor::SetImpl(holder->elements(), entry.adjust_down(length),
                                  value);
  }

  static Maybe<bool> AddImpl(Handle<JSObject> object, uint32_t index,
                             DirectHandle<Object> value,
                             PropertyAttributes attributes,
                             uint32_t new_capacity) {
    DCHECK(index >= static_cast<uint32_t>(GetString(*object)->length()));
    // Explicitly grow fast backing stores if needed. Dictionaries know how to
    // extend their capacity themselves.
    if (KindTraits::Kind == FAST_STRING_WRAPPER_ELEMENTS &&
        (object->GetElementsKind() == SLOW_STRING_WRAPPER_ELEMENTS ||
         BackingStoreAccessor::GetCapacityImpl(*object, object->elements()) !=
             new_capacity)) {
      MAYBE_RETURN(GrowCapacityAndConvertImpl(object, new_capacity),
                   Nothing<bool>());
    }
    BackingStoreAccessor::AddImpl(object, index, value, attributes,
                                  new_capacity);
    return Just(true);
  }

  static void ReconfigureImpl(Handle<JSObject> object,
                              Handle<FixedArrayBase> store, InternalIndex entry,
                              Handle<Object> value,
                              PropertyAttributes attributes) {
    uint32_t length = static_cast<uint32_t>(GetString(*object)->length());
    if (entry.as_uint32() < length) {
      return;  // String contents can't be reconfigured.
    }
    BackingStoreAccessor::ReconfigureImpl(
        object, store, entry.adjust_down(length), value, attributes);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus AddElementsToKeyAccumulatorImpl(
      Handle<JSObject> receiver, KeyAccumulator* accumulator,
      AddKeyConversion convert) {
    Isolate* isolate = receiver->GetIsolate();
    Handle<String> string(GetString(*receiver), isolate);
    string = String::Flatten(isolate, string);
    uint32_t length = static_cast<uint32_t>(string->length());
    for (uint32_t i = 0; i < length; i++) {
      Handle<String> key =
          isolate->factory()->LookupSingleCharacterStringFromCode(
              string->Get(i));
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(accumulator->AddKey(key, convert));
    }
    return BackingStoreAccessor::AddElementsToKeyAccumulatorImpl(
        receiver, accumulator, convert);
  }

  V8_WARN_UNUSED_RESULT static ExceptionStatus CollectElementIndicesImpl(
      Handle<JSObject> object, Handle<FixedArrayBase> backing_store,
      KeyAccumulator* keys) {
    uint32_t length = GetString(*object)->length();
    Factory* factory = keys->isolate()->factory();
    for (uint32_t i = 0; i < length; i++) {
      RETURN_FAILURE_IF_NOT_SUCCESSFUL(
          keys->AddKey(factory->NewNumberFromUint(i)));
    }
    return BackingStoreAccessor::CollectElementIndicesImpl(object,
                                                           backing_store, keys);
  }

  static Maybe<bool> GrowCapacityAndConvertImpl(Handle<JSObject> object,
                                                uint32_t capacity) {
    Handle<FixedArrayBase> old_elements(object->elements(),
                                        object->GetIsolate());
    ElementsKind from_kind = object->GetElementsKind();
    if (from_kind == FAST_STRING_WRAPPER_ELEMENTS) {
      // The optimizing compiler relies on the prototype lookups of String
      // objects always returning undefined. If there's a store to the
      // initial String.prototype object, make sure all the optimizations
      // are invalidated.
      object->GetIsolate()->UpdateNoElementsProtectorOnSetLength(object);
    }
    // This method should only be called if there's a reason to update the
    // elements.
    DCHECK(from_kind == SLOW_STRING_WRAPPER_ELEMENTS ||
           static_cast<uint32_t>(old_elements->length()) < capacity);
    return Subclass::BasicGrowCapacityAndConvertImpl(
        object, old_elements, from_kind, FAST_STRING_WRAPPER_ELEMENTS,
        capacity);
  }

  static void CopyElementsImpl(Isolate* isolate, Tagged<FixedArrayBase> from,
                               uint32_t from_start, Tagged<FixedArrayBase> to,
                               ElementsKind from_kind, uint32_t to_start,
                               int packed_size, int copy_size) {
    DCHECK(!IsNumberDictionary(to));
    if (from_kind == SLOW_STRING_WRAPPER_ELEMENTS) {
      CopyDictionaryToObjectElements(isolate, from, from_start, to,
                                     HOLEY_ELEMENTS, to_start, copy_size);
    } else {
      DCHECK_EQ(FAST_STRING_WRAPPER_ELEMENTS, from_kind);
      CopyObjectToObjectElements(isolate, from, HOLEY_ELEMENTS, from_start, to,
                                 HOLEY_ELEMENTS, to_start, copy_size);
    }
  }

  static uint32_t NumberOfElementsImpl(Isolate* isolate,
                                       Tagged<JSObject> object,
                                       Tagged<FixedArrayBase> backing_store) {
    uint32_t length = GetString(object)->length();
    return length + BackingStoreAccessor::NumberOfElementsImpl(isolate, object,
                                                               backing_store);
  }

 private:
  static Tagged<String> GetString(Tagged<JSObject> holder) {
    DCHECK(IsJSPrimitiveWrapper(holder));
    Tagged<JSPrimitiveWrapper> js_value = Cast<JSPrimitiveWrapper>(holder);
    DCHECK(IsString(js_value->value()));
    return Cast<String>(js_value->value());
  }
};

class FastStringWrapperElementsAccessor
    : public StringWrapperElementsAccessor<
          FastStringWrapperElementsAccessor, FastHoleyObjectElementsAccessor,
          ElementsKindTraits<FAST_STRING_WRAPPER_ELEMENTS>> {
 public:
  static Handle<NumberDictionary> NormalizeImpl(
      Handle<JSObject> object, DirectHandle<FixedArrayBase> elements) {
    return FastHoleyObjectElementsAccessor::NormalizeImpl(object, elements);
  }
};

class SlowStringWrapperElementsAccessor
    : public StringWrapperElementsAccessor<
          SlowStringWrapperElementsAccessor, DictionaryElementsAccessor,
          ElementsKindTraits<SLOW_STRING_WRAPPER_ELEMENTS>> {
 public:
  static bool HasAccessorsImpl(Tagged<JSObject> holder,
                               Tagged<FixedArrayBase> backing_store) {
    return DictionaryElementsAccessor::HasAccessorsImpl(holder, backing_store);
  }
};

}  // namespace

MaybeHandle<Object> ArrayConstructInitializeElements(
    Handle<JSArray> array, JavaScriptArguments* args) {
  if (args->length() == 0) {
    // Optimize the case where there are no parameters passed.
    JSArray::Initialize(array, JSArray::kPreallocatedArrayElements);
    return array;

  } else if (args->length() == 1 && IsNumber(*args->at(0))) {
    uint32_t length;
    if (!Object::ToArrayLength(*args->at(0), &length)) {
      return ThrowArrayLengthRangeError(array->GetIsolate());
    }

    // Optimize the case where there is one argument and the argument is a small
    // smi.
    if (length > 0 && length < JSArray::kInitialMaxFastElementArray) {
      ElementsKind elements_kind = array->GetElementsKind();
      JSArray::Initialize(array, length, length);

      if (!IsHoleyElementsKind(elements_kind)) {
        elements_kind = GetHoleyElementsKind(elements_kind);
        JSObject::TransitionElementsKind(array, elements_kind);
      }
    } else if (length == 0) {
      JSArray::Initialize(array, JSArray::kPreallocatedArrayElements);
    } else {
      // Take the argument as the length.
      JSArray::Initialize(array, 0);
      MAYBE_RETURN_NULL(JSArray::SetLength(array, length));
    }
    return array;
  }

  Factory* factory = array->GetIsolate()->factory();

  // Set length and elements on the array.
  int number_of_elements = args->length();
  JSObject::EnsureCanContainElements(array, args, number_of_elements,
                                     ALLOW_CONVERTED_DOUBLE_ELEMENTS);

  // Allocate an appropriately typed elements array.
  ElementsKind elements_kind = array->GetElementsKind();
  Handle<FixedArrayBase> elms;
  if (IsDoubleElementsKind(elements_kind)) {
    elms =
        Cast<FixedArrayBase>(factory->NewFixedDoubleArray(number_of_elements));
  } else {
    elms = Cast<FixedArrayBase>(
        factory->NewFixedArrayWithHoles(number_of_elements));
  }

  // Fill in the content
  switch (elements_kind) {
    case HOLEY_SMI_ELEMENTS:
    case PACKED_SMI_ELEMENTS: {
      auto smi_elms = Cast<FixedArray>(elms);
      for (int entry = 0; entry < number_of_elements; entry++) {
        smi_elms->set(entry, (*args)[entry], SKIP_WRITE_BARRIER);
      }
      break;
    }
    case HOLEY_ELEMENTS:
    case PACKED_ELEMENTS: {
      DisallowGarbageCollection no_gc;
      WriteBarrierMode mode = elms->GetWriteBarrierMode(no_gc);
      auto object_elms = Cast<FixedArray>(elms);
      for (int entry = 0; entry < number_of_elements; entry++) {
        object_elms->set(entry, (*args)[entry], mode);
      }
      break;
    }
    case HOLEY_DOUBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS: {
      auto double_elms = Cast<FixedDoubleArray>(elms);
      for (int entry = 0; entry < number_of_elements; entry++) {
        double_elms->set(entry, Object::NumberValue((*args)[entry]));
      }
      break;
    }
    default:
      UNREACHABLE();
  }

  array->set_elements(*elms);
  array->set_length(Smi::FromInt(number_of_elements));
  return array;
}

void CopyFastNumberJSArrayElementsToTypedArray(Address raw_context,
                                               Address raw_source,
                                               Address raw_destination,
                                               uintptr_t length,
                                               uintptr_t offset) {
  Tagged<Context> context = Cast<Context>(Tagged<Object>(raw_context));
  Tagged<JSArray> source = Cast<JSArray>(Tagged<Object>(raw_source));
  Tagged<JSTypedArray> destination =
      Cast<JSTypedArray>(Tagged<Object>(raw_destination));

  switch (destination->GetElementsKind()) {
#define TYPED_ARRAYS_CASE(Type, type, TYPE, ctype)           \
  case TYPE##_ELEMENTS:                                      \
    CHECK(Type##ElementsAccessor::TryCopyElementsFastNumber( \
        context, source, destination, length, offset));      \
    break;
    TYPED_ARRAYS(TYPED_ARRAYS_CASE)
    RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAYS_CASE)
#undef TYPED_ARRAYS_CASE
    default:
      UNREACHABLE();
  }
}

void CopyTypedArrayElementsToTypedArray(Address raw_source,
                                        Address raw_destination,
                                        uintptr_t length, uintptr_t offset) {
  Tagged<JSTypedArray> source = Cast<JSTypedArray>(Tagged<Object>(raw_source));
  Tagged<JSTypedArray> destination =
      Cast<JSTypedArray>(Tagged<Object>(raw_destination));

  switch (destination->GetElementsKind()) {
#define TYPED_ARRAYS_CASE(Type, type, TYPE, ctype)                          \
  case TYPE##_ELEMENTS:                                                     \
    Type##ElementsAccessor::CopyElementsFromTypedArray(source, destination, \
                                                       length, offset);     \
    break;
    TYPED_ARRAYS(TYPED_ARRAYS_CASE)
    RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAYS_CASE)
#undef TYPED_ARRAYS_CASE
    default:
      UNREACHABLE();
  }
}

void CopyTypedArrayElementsSlice(Address raw_source, Address raw_destination,
                                 uintptr_t start, uintptr_t end) {
  Tagged<JSTypedArray> source = Cast<JSTypedArray>(Tagged<Object>(raw_source));
  Tagged<JSTypedArray> destination =
      Cast<JSTypedArray>(Tagged<Object>(raw_destination));

  destination->GetElementsAccessor()->CopyTypedArrayElementsSlice(
      source, destination, start, end);
}

template <typename Mapping>
constexpr bool IsIdentityMapping(const Mapping& mapping, size_t index) {
  return (index >= std::size(mapping)) ||
         (mapping[index] == index && IsIdentityMapping(mapping, index + 1));
}

void ElementsAccessor::InitializeOncePerProcess() {
  // Here we create an array with more entries than element kinds.
  // This is due to the sandbox: this array is indexed with an ElementsKind
  // read directly from within the sandbox, which must therefore be considered
  // attacker-controlled. An ElementsKind is a uint8_t under the hood, so we
  // can either use an array with 256 entries or have an explicit bounds-check
  // on access. The latter is probably more expensive.
  static_assert(std::is_same_v<std::underlying_type_t<ElementsKind>, uint8_t>);
  static ElementsAccessor* accessor_array[256] = {
#define ACCESSOR_ARRAY(Class, Kind, Store) new Class(),
      ELEMENTS_LIST(ACCESSOR_ARRAY)
#undef ACCESSOR_ARRAY
  };

  static_assert((sizeof(accessor_array) / sizeof(*accessor_array)) >=
                kElementsKindCount);

  // Check that the ELEMENTS_LIST macro is in the same order as the ElementsKind
  // enum.
  constexpr ElementsKind elements_kinds_from_macro[] = {
#define ACCESSOR_KIND(Class, Kind, Store) Kind,
      ELEMENTS_LIST(ACCESSOR_KIND)
#undef ACCESSOR_KIND
  };
  static_assert(IsIdentityMapping(elements_kinds_from_macro, 0));

  elements_accessors_ = accessor_array;
}

void ElementsAccessor::TearDown() {
  if (elements_accessors_ == nullptr) return;
#define ACCESSOR_DELETE(Class, Kind, Store) delete elements_accessors_[Kind];
  ELEMENTS_LIST(ACCESSOR_DELETE)
#undef ACCESSOR_DELETE
  elements_accessors_ = nullptr;
}

Handle<JSArray> ElementsAccessor::Concat(Isolate* isolate,
                                         BuiltinArguments* args,
                                         uint32_t concat_size,
                                         uint32_t result_len) {
  ElementsKind result_elements_kind = GetInitialFastElementsKind();
  bool has_raw_doubles = false;
  {
    DisallowGarbageCollection no_gc;
    bool is_holey = false;
    for (uint32_t i = 0; i < concat_size; i++) {
      Tagged<Object> arg = (*args)[i];
      ElementsKind arg_kind = Cast<JSArray>(arg)->GetElementsKind();
      has_raw_doubles = has_raw_doubles || IsDoubleElementsKind(arg_kind);
      is_holey = is_holey || IsHoleyElementsKind(arg_kind);
      result_elements_kind =
          GetMoreGeneralElementsKind(result_elements_kind, arg_kind);
    }
    if (is_holey) {
      result_elements_kind = GetHoleyElementsKind(result_elements_kind);
    }
  }

  // If a double array is concatted into a fast elements array, the fast
  // elements array needs to be initialized to contain proper holes, since
  // boxing doubles may cause incremental marking.
  bool requires_double_boxing =
      has_raw_doubles && !IsDoubleElementsKind(result_elements_kind);
  auto mode =
      requires_double_boxing
          ? ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE
          : ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS;
  Handle<JSArray> result_array = isolate->factory()->NewJSArray(
      result_elements_kind, result_len, result_len, mode);
  if (result_len == 0) return result_array;

  uint32_t insertion_index = 0;
  Handle<FixedArrayBase> storage(result_array->elements(), isolate);
  ElementsAccessor* accessor = ElementsAccessor::ForKind(result_elements_kind);
  for (uint32_t i = 0; i < concat_size; i++) {
    // It is crucial to keep |array| in a raw pointer form to avoid
    // performance degradation.
    Tagged<JSArray> array = Cast<JSArray>((*args)[i]);
    uint32_t len = 0;
    Object::ToArrayLength(array->length(), &len);
    if (len == 0) continue;
    ElementsKind from_kind = array->GetElementsKind();
    accessor->CopyElements(isolate, array, 0, from_kind, storage,
                           insertion_index, len);
    insertion_index += len;
  }

  DCHECK_EQ(insertion_index, result_len);
  return result_array;
}

ElementsAccessor** ElementsAccessor::elements_accessors_ = nullptr;

#undef ELEMENTS_LIST
#undef RETURN_NOTHING_IF_NOT_SUCCESSFUL
#undef RETURN_FAILURE_IF_NOT_SUCCESSFUL
}  // namespace internal
}  // namespace v8

"""


```