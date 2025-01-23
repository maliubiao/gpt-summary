Response: My thought process for summarizing the C++ code goes like this:

1. **Understand the Goal:** The request asks for a functional summary of a specific C++ file (`code-stub-assembler.cc`), specifically section 7 out of 12. It also wants to know the relationship to JavaScript and see a JavaScript example.

2. **Initial Scan for Keywords and Patterns:** I quickly scanned the code looking for recurring patterns, function names, and data structures. I noticed a lot of functions related to:
    * `Dictionary` (NameDictionary, GlobalDictionary, NumberDictionary, SwissNameDictionary)
    * `Lookup` (NameDictionaryLookup, NumberDictionaryLookup, LookupLinear, LookupBinary, DescriptorLookup, TransitionLookup, TryLookupProperty)
    * `InsertEntry`, `AddToDictionary`
    * `Property` (PropertyDetails, PropertyDescriptorObject, GetProperty, TryGetOwnProperty)
    * `Map`, `DescriptorArray`, `TransitionArray`
    * `CodeStubAssembler` itself.

3. **Identify Core Functionality Areas:**  Based on the keywords, I started grouping related functionalities. The key areas that emerged were:
    * **Dictionary Management:**  Adding, looking up, and managing different types of dictionaries used for storing object properties.
    * **Property Lookup:**  Efficiently finding properties in various data structures (dictionaries, descriptor arrays, transition arrays). This involves linear and binary search strategies.
    * **Property Retrieval:** Loading property values, handling accessors (getters/setters), and dealing with different property types (data, accessor).
    * **Object Structure Introspection:**  Working with maps, descriptors, and transitions, which are fundamental to how V8 represents object structure and properties.
    * **Iteration:** Iterating over object properties.
    * **Property Descriptor Objects:**  Creating and manipulating objects that describe property attributes (enumerable, configurable, writable).

4. **Focus on Section 7 (Based on the "This is part 7 of 12" instruction):** I paid closer attention to the functions and templates defined *within* the provided code snippet. This helped refine the summary and ensure it specifically addresses the given section. For example, the `ForEachEnumerableOwnProperty` function is a significant part of this section.

5. **Infer the Relationship to JavaScript:**  I know V8 is the JavaScript engine for Chrome and Node.js. Therefore, any code dealing with object properties, lookups, and accessors directly relates to how JavaScript objects work. Specifically:
    * JavaScript objects are fundamentally key-value stores, and dictionaries are a natural way to implement this.
    * JavaScript's prototype chain involves looking up properties in different objects until found. The lookup functions likely play a role in this.
    * JavaScript's getters and setters correspond to the accessor handling logic.
    * Concepts like "enumerable," "configurable," and "writable" directly map to JavaScript property attributes.

6. **Construct a High-Level Summary:** I started writing a concise summary covering the major functional areas. I used terms like "managing object properties," "efficient lookup," and "handling accessors" to capture the essence.

7. **Provide JavaScript Examples:** To illustrate the connection to JavaScript, I created simple examples demonstrating the concepts being implemented in the C++ code. I focused on:
    * Object property access (`object.property`, `object['property']`).
    * Property iteration (`for...in`).
    * Getters and setters.
    * `Object.getOwnPropertyDescriptor()`.

8. **Refine and Iterate:** I reread the code and my summary to ensure accuracy and completeness. I made sure the JavaScript examples were relevant and easy to understand. I also considered the "part 7 of 12" instruction to ensure I wasn't straying too far into functionalities that might be covered in other parts. I made sure to call out specific data structures like `DescriptorArray` and `TransitionArray` as they are key to understanding V8's internal workings.

9. **Address the "Part 7" Constraint:** I explicitly mentioned in the summary that the code focuses on dictionary operations, property lookup within those dictionaries, and related utilities. This helps frame the summary within the context of the larger file.

By following these steps, I could move from a raw code snippet to a comprehensive summary explaining its functionality and relevance to JavaScript. The key was to identify the core concepts and connect the low-level C++ implementation to the high-level behavior of JavaScript.这个C++源代码文件 `v8/src/codegen/code-stub-assembler.cc` 的第7部分，主要集中在 **高效地在V8的内部数据结构中查找和管理对象属性**。它提供了一系列用于在不同类型的字典（Dictionary）和数组中查找属性的助手函数。

以下是其主要功能归纳：

**1. 字典查找 (Dictionary Lookup):**

* 提供了针对不同类型字典（`NameDictionary`, `GlobalDictionary`, `NumberDictionary`, `SwissNameDictionary`）进行属性查找的模板函数 `NameDictionaryLookup` 和专门化的实现。
* `NameDictionaryLookupWithForwardIndex`:  用于处理包含转发索引的字典查找。
* `NumberDictionaryLookup`:  专门针对数字索引的字典查找，使用哈希探测。
* 这些函数允许根据属性名（`TNode<Name>`）在字典中查找对应的条目，并提供找到和未找到时的跳转标签（`Label*`）以及存储索引的变量（`TVariable<IntPtrT>*`）。
* 提供了 `ComputeSeededHash` 函数，用于计算哈希值，这是字典查找的基础。

**2. 线性查找和二分查找 (Linear and Binary Lookup):**

* 提供了模板函数 `LookupLinear` 和 `LookupBinary` 用于在排序的数组结构（如 `DescriptorArray` 和 `TransitionArray`）中查找属性。
* `LookupLinear` 进行简单的线性扫描。
* `LookupBinary`  使用二分查找算法，适用于大型的排序数组，提高查找效率。

**3. 属性添加和插入 (Property Addition and Insertion):**

* 提供了模板函数 `AddToDictionary` 和 `InsertEntry` 用于向不同类型的字典中添加新的属性。
* 针对 `NameDictionary` 提供了 `InsertEntry` 的具体实现，用于存储属性名、值和属性详情。
* `AddToDictionary` 包含添加属性前的各种检查，例如容量是否足够，是否需要扩容或重新哈希。

**4. 遍历可枚举属性 (Iterating over Enumerable Properties):**

* 提供了 `ForEachEnumerableOwnProperty` 函数，用于遍历对象的自有可枚举属性。
* 该函数支持按照枚举顺序遍历，并能处理快速属性和字典属性，以及访问器属性。

**5. 获取构造函数和原型 (Getting Constructor and Prototype):**

* 提供了 `GetConstructor` 函数，用于获取对象的构造函数。
* 提供了 `GetCreationContextFromMap` 和 `GetCreationContext` 函数，用于获取对象创建时的上下文。

**6. 处理方法调用 (Method Invocation):**

* 提供了 `GetMethod` 和 `GetIteratorMethod` 函数，用于获取对象的方法。
* 提供了 `CreateAsyncFromSyncIterator` 函数，用于将同步迭代器转换为异步迭代器。

**7. 加载属性值 (Loading Property Values):**

* 提供了 `LoadPropertyFromFastObject` 和 `LoadPropertyFromDictionary` 函数，用于从快速对象和字典中加载属性值。
* `LoadPropertyFromGlobalDictionary` 用于从全局字典中加载属性值，并处理 PropertyCell。

**8. 调用访问器 (Calling Accessors):**

* 提供了 `CallGetterIfAccessor` 函数，用于判断属性是否是访问器（getter/setter），如果是则调用 getter 方法。

**9. 尝试获取自有属性 (Trying to Get Own Property):**

* 提供了 `TryGetOwnProperty` 函数的多个重载，用于尝试获取对象的自有属性，包括快速属性、字典属性和全局属性。

**10. 初始化属性描述符对象 (Initializing Property Descriptor Object):**

* 提供了 `InitializePropertyDescriptorObject` 和 `AllocatePropertyDescriptorObject` 函数，用于创建和初始化 `PropertyDescriptorObject`，该对象用于描述属性的特性（如可枚举性、可配置性、可写性）。

**11. 判断有趣的属性 (Identifying Interesting Properties):**

* 提供了 `IsInterestingProperty` 函数，用于判断属性名是否是特殊的内部符号或字符串（例如 `Symbol.toPrimitive`）。
* 提供了 `GetInterestingProperty` 函数，用于获取这些特殊的属性。

**与 Javascript 的关系：**

这个文件的功能与 JavaScript 中对象的属性访问和管理密切相关。V8 引擎在执行 JavaScript 代码时，需要高效地查找、添加、删除和修改对象的属性。这个文件中的函数提供了实现这些操作的基础设施。

**Javascript 示例：**

```javascript
const obj = {
  name: 'Alice',
  age: 30,
  [Symbol.iterator]: function*() {
    yield 1;
    yield 2;
  },
  get fullName() {
    return this.name + ' Smith';
  }
};

// 属性访问 (对应字典查找, 线性/二分查找)
console.log(obj.name); // V8 内部会使用类似 NameDictionaryLookup 查找 "name" 属性

// 数字索引属性访问 (对应 NumberDictionaryLookup)
const arr = [10, 20];
console.log(arr[0]); // V8 内部会使用类似 NumberDictionaryLookup 查找索引为 0 的属性

// 添加属性 (对应 AddToDictionary, InsertEntry)
obj.city = 'New York';

// 遍历可枚举属性 (对应 ForEachEnumerableOwnProperty)
for (let key in obj) {
  console.log(key); // 输出 "name", "age", "city", "fullName" (如果 fullName 可枚举)
}

// 获取属性描述符 (对应 InitializePropertyDescriptorObject)
const descriptor = Object.getOwnPropertyDescriptor(obj, 'name');
console.log(descriptor); // 输出 name 属性的描述符对象，包含 value, writable, enumerable, configurable

// 获取迭代器方法 (对应 GetIteratorMethod)
const iterator = obj[Symbol.iterator]();
console.log(iterator.next());

// 调用 getter (对应 CallGetterIfAccessor)
console.log(obj.fullName); // V8 内部会调用 fullName 的 getter 函数

// 判断特殊的 Symbol 属性 (对应 IsInterestingProperty)
console.log(Symbol.iterator in obj); // V8 内部会判断 Symbol.iterator 是否是 "interesting"
```

**总结来说，这个代码文件是 V8 引擎中负责对象属性管理和查找的核心组件之一，它为执行 JavaScript 代码中涉及对象属性的操作提供了底层的、高性能的实现。**  它使用了多种优化技术，例如不同类型的字典和查找算法，来确保属性访问的效率。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共12部分，请归纳一下它的功能
```

### 源代码
```
ary>, TNode<Name>, Label*,
                      TVariable<IntPtrT>*, Label*, LookupMode);

template <typename Dictionary>
void CodeStubAssembler::NameDictionaryLookupWithForwardIndex(
    TNode<Dictionary> dictionary, TNode<Name> unique_name, Label* if_found,
    TVariable<IntPtrT>* var_name_index, Label* if_not_found, LookupMode mode) {
  using ER = ExternalReference;  // To avoid super long lines below.
  ER func_ref;
  if constexpr (std::is_same<Dictionary, NameDictionary>::value) {
    func_ref = mode == kFindInsertionIndex
                   ? ER::name_dictionary_find_insertion_entry_forwarded_string()
                   : ER::name_dictionary_lookup_forwarded_string();
  } else if constexpr (std::is_same<Dictionary, GlobalDictionary>::value) {
    func_ref =
        mode == kFindInsertionIndex
            ? ER::global_dictionary_find_insertion_entry_forwarded_string()
            : ER::global_dictionary_lookup_forwarded_string();
  } else {
    auto ref0 =
        ER::name_to_index_hashtable_find_insertion_entry_forwarded_string();
    auto ref1 = ER::name_to_index_hashtable_lookup_forwarded_string();
    func_ref = mode == kFindInsertionIndex ? ref0 : ref1;
  }
  const TNode<ER> function = ExternalConstant(func_ref);
  const TNode<ER> isolate_ptr = ExternalConstant(ER::isolate_address());
  TNode<IntPtrT> entry = UncheckedCast<IntPtrT>(
      CallCFunction(function, MachineType::IntPtr(),
                    std::make_pair(MachineType::Pointer(), isolate_ptr),
                    std::make_pair(MachineType::TaggedPointer(), dictionary),
                    std::make_pair(MachineType::TaggedPointer(), unique_name)));

  if (var_name_index) *var_name_index = EntryToIndex<Dictionary>(entry);
  switch (mode) {
    case kFindInsertionIndex:
      CSA_DCHECK(
          this,
          WordNotEqual(entry,
                       IntPtrConstant(InternalIndex::NotFound().raw_value())));
      Goto(if_not_found);
      break;
    case kFindExisting:
      GotoIf(IntPtrEqual(entry,
                         IntPtrConstant(InternalIndex::NotFound().raw_value())),
             if_not_found);
      Goto(if_found);
      break;
    case kFindExistingOrInsertionIndex:
      GotoIfNot(IntPtrEqual(entry, IntPtrConstant(
                                       InternalIndex::NotFound().raw_value())),
                if_found);
      NameDictionaryLookupWithForwardIndex(dictionary, unique_name, if_found,
                                           var_name_index, if_not_found,
                                           kFindInsertionIndex);
      break;
  }
}

TNode<Word32T> CodeStubAssembler::ComputeSeededHash(TNode<IntPtrT> key) {
  const TNode<ExternalReference> function_addr =
      ExternalConstant(ExternalReference::compute_integer_hash());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  MachineType type_ptr = MachineType::Pointer();
  MachineType type_uint32 = MachineType::Uint32();
  MachineType type_int32 = MachineType::Int32();

  return UncheckedCast<Word32T>(CallCFunction(
      function_addr, type_uint32, std::make_pair(type_ptr, isolate_ptr),
      std::make_pair(type_int32, TruncateIntPtrToInt32(key))));
}

template <>
void CodeStubAssembler::NameDictionaryLookup(
    TNode<SwissNameDictionary> dictionary, TNode<Name> unique_name,
    Label* if_found, TVariable<IntPtrT>* var_name_index, Label* if_not_found,
    LookupMode mode) {
  // TODO(pthier): Support mode kFindExistingOrInsertionIndex for
  // SwissNameDictionary.
  SwissNameDictionaryFindEntry(dictionary, unique_name, if_found,
                               var_name_index, if_not_found);
}

void CodeStubAssembler::NumberDictionaryLookup(
    TNode<NumberDictionary> dictionary, TNode<IntPtrT> intptr_index,
    Label* if_found, TVariable<IntPtrT>* var_entry, Label* if_not_found) {
  CSA_DCHECK(this, IsNumberDictionary(dictionary));
  DCHECK_EQ(MachineType::PointerRepresentation(), var_entry->rep());
  Comment("NumberDictionaryLookup");

  TNode<IntPtrT> capacity =
      PositiveSmiUntag(GetCapacity<NumberDictionary>(dictionary));
  TNode<IntPtrT> mask = IntPtrSub(capacity, IntPtrConstant(1));

  TNode<UintPtrT> hash = ChangeUint32ToWord(ComputeSeededHash(intptr_index));
  TNode<Float64T> key_as_float64 = RoundIntPtrToFloat64(intptr_index);

  // See Dictionary::FirstProbe().
  TNode<IntPtrT> count = IntPtrConstant(0);
  TNode<IntPtrT> initial_entry = Signed(WordAnd(hash, mask));

  TNode<Undefined> undefined = UndefinedConstant();
  TNode<Hole> the_hole = TheHoleConstant();

  TVARIABLE(IntPtrT, var_count, count);
  Label loop(this, {&var_count, var_entry});
  *var_entry = initial_entry;
  Goto(&loop);
  BIND(&loop);
  {
    TNode<IntPtrT> entry = var_entry->value();

    TNode<IntPtrT> index = EntryToIndex<NumberDictionary>(entry);
    TNode<Object> current = UnsafeLoadFixedArrayElement(dictionary, index);
    GotoIf(TaggedEqual(current, undefined), if_not_found);
    Label next_probe(this);
    {
      Label if_currentissmi(this), if_currentisnotsmi(this);
      Branch(TaggedIsSmi(current), &if_currentissmi, &if_currentisnotsmi);
      BIND(&if_currentissmi);
      {
        TNode<IntPtrT> current_value = SmiUntag(CAST(current));
        Branch(WordEqual(current_value, intptr_index), if_found, &next_probe);
      }
      BIND(&if_currentisnotsmi);
      {
        GotoIf(TaggedEqual(current, the_hole), &next_probe);
        // Current must be the Number.
        TNode<Float64T> current_value = LoadHeapNumberValue(CAST(current));
        Branch(Float64Equal(current_value, key_as_float64), if_found,
               &next_probe);
      }
    }

    BIND(&next_probe);
    // See Dictionary::NextProbe().
    Increment(&var_count);
    entry = Signed(WordAnd(IntPtrAdd(entry, var_count.value()), mask));

    *var_entry = entry;
    Goto(&loop);
  }
}

TNode<Object> CodeStubAssembler::BasicLoadNumberDictionaryElement(
    TNode<NumberDictionary> dictionary, TNode<IntPtrT> intptr_index,
    Label* not_data, Label* if_hole) {
  TVARIABLE(IntPtrT, var_entry);
  Label if_found(this);
  NumberDictionaryLookup(dictionary, intptr_index, &if_found, &var_entry,
                         if_hole);
  BIND(&if_found);

  // Check that the value is a data property.
  TNode<IntPtrT> index = EntryToIndex<NumberDictionary>(var_entry.value());
  TNode<Uint32T> details = LoadDetailsByKeyIndex(dictionary, index);
  TNode<Uint32T> kind = DecodeWord32<PropertyDetails::KindField>(details);
  // TODO(jkummerow): Support accessors without missing?
  GotoIfNot(
      Word32Equal(kind, Int32Constant(static_cast<int>(PropertyKind::kData))),
      not_data);
  // Finally, load the value.
  return LoadValueByKeyIndex(dictionary, index);
}

template <class Dictionary>
void CodeStubAssembler::FindInsertionEntry(TNode<Dictionary> dictionary,
                                           TNode<Name> key,
                                           TVariable<IntPtrT>* var_key_index) {
  UNREACHABLE();
}

template <>
void CodeStubAssembler::FindInsertionEntry<NameDictionary>(
    TNode<NameDictionary> dictionary, TNode<Name> key,
    TVariable<IntPtrT>* var_key_index) {
  Label done(this);
  NameDictionaryLookup<NameDictionary>(dictionary, key, nullptr, var_key_index,
                                       &done, kFindInsertionIndex);
  BIND(&done);
}

template <class Dictionary>
void CodeStubAssembler::InsertEntry(TNode<Dictionary> dictionary,
                                    TNode<Name> key, TNode<Object> value,
                                    TNode<IntPtrT> index,
                                    TNode<Smi> enum_index) {
  UNREACHABLE();  // Use specializations instead.
}

template <>
void CodeStubAssembler::InsertEntry<NameDictionary>(
    TNode<NameDictionary> dictionary, TNode<Name> name, TNode<Object> value,
    TNode<IntPtrT> index, TNode<Smi> enum_index) {
  // This should only be used for adding, not updating existing mappings.
  CSA_DCHECK(this,
             Word32Or(TaggedEqual(LoadFixedArrayElement(dictionary, index),
                                  UndefinedConstant()),
                      TaggedEqual(LoadFixedArrayElement(dictionary, index),
                                  TheHoleConstant())));

  // Store name and value.
  StoreFixedArrayElement(dictionary, index, name);
  StoreValueByKeyIndex<NameDictionary>(dictionary, index, value);

  // Prepare details of the new property.
  PropertyDetails d(PropertyKind::kData, NONE,
                    PropertyDetails::kConstIfDictConstnessTracking);

  // We ignore overflow of |enum_index| here and accept potentially
  // broken enumeration order (https://crbug.com/41432983).
  enum_index = UnsignedSmiShl(enum_index,
                              PropertyDetails::DictionaryStorageField::kShift);
  // We OR over the actual index below, so we expect the initial value to be 0.
  DCHECK_EQ(0, d.dictionary_index());
  TVARIABLE(Smi, var_details, SmiOr(SmiConstant(d.AsSmi()), enum_index));

  // Private names must be marked non-enumerable.
  Label not_private(this, &var_details);
  GotoIfNot(IsPrivateSymbol(name), &not_private);
  TNode<Smi> dont_enum = UnsignedSmiShl(
      SmiConstant(DONT_ENUM), PropertyDetails::AttributesField::kShift);
  var_details = SmiOr(var_details.value(), dont_enum);
  Goto(&not_private);
  BIND(&not_private);

  // Finally, store the details.
  StoreDetailsByKeyIndex<NameDictionary>(dictionary, index,
                                         var_details.value());
}

template <>
void CodeStubAssembler::InsertEntry<GlobalDictionary>(
    TNode<GlobalDictionary> dictionary, TNode<Name> key, TNode<Object> value,
    TNode<IntPtrT> index, TNode<Smi> enum_index) {
  UNIMPLEMENTED();
}

template <class Dictionary>
void CodeStubAssembler::AddToDictionary(
    TNode<Dictionary> dictionary, TNode<Name> key, TNode<Object> value,
    Label* bailout, std::optional<TNode<IntPtrT>> insertion_index) {
  CSA_DCHECK(this, Word32BinaryNot(IsEmptyPropertyDictionary(dictionary)));
  TNode<Smi> capacity = GetCapacity<Dictionary>(dictionary);
  TNode<Smi> nof = GetNumberOfElements<Dictionary>(dictionary);
  TNode<Smi> new_nof = SmiAdd(nof, SmiConstant(1));
  // Require 33% to still be free after adding additional_elements.
  // Computing "x + (x >> 1)" on a Smi x does not return a valid Smi!
  // But that's OK here because it's only used for a comparison.
  TNode<Smi> required_capacity_pseudo_smi = SmiAdd(new_nof, SmiShr(new_nof, 1));
  GotoIf(SmiBelow(capacity, required_capacity_pseudo_smi), bailout);
  // Require rehashing if more than 50% of free elements are deleted elements.
  TNode<Smi> deleted = GetNumberOfDeletedElements<Dictionary>(dictionary);
  CSA_DCHECK(this, SmiAbove(capacity, new_nof));
  TNode<Smi> half_of_free_elements = SmiShr(SmiSub(capacity, new_nof), 1);
  GotoIf(SmiAbove(deleted, half_of_free_elements), bailout);

  TNode<Smi> enum_index = GetNextEnumerationIndex<Dictionary>(dictionary);
  TNode<Smi> new_enum_index = SmiAdd(enum_index, SmiConstant(1));
  TNode<Smi> max_enum_index =
      SmiConstant(PropertyDetails::DictionaryStorageField::kMax);
  GotoIf(SmiAbove(new_enum_index, max_enum_index), bailout);

  // No more bailouts after this point.
  // Operations from here on can have side effects.

  SetNextEnumerationIndex<Dictionary>(dictionary, new_enum_index);
  SetNumberOfElements<Dictionary>(dictionary, new_nof);

  if (insertion_index.has_value()) {
    InsertEntry<Dictionary>(dictionary, key, value, *insertion_index,
                            enum_index);
  } else {
    TVARIABLE(IntPtrT, var_key_index);
    FindInsertionEntry<Dictionary>(dictionary, key, &var_key_index);
    InsertEntry<Dictionary>(dictionary, key, value, var_key_index.value(),
                            enum_index);
  }
}

template <>
void CodeStubAssembler::AddToDictionary(
    TNode<SwissNameDictionary> dictionary, TNode<Name> key, TNode<Object> value,
    Label* bailout, std::optional<TNode<IntPtrT>> insertion_index) {
  PropertyDetails d(PropertyKind::kData, NONE,
                    PropertyDetails::kConstIfDictConstnessTracking);

  PropertyDetails d_dont_enum(PropertyKind::kData, DONT_ENUM,
                              PropertyDetails::kConstIfDictConstnessTracking);
  TNode<Uint8T> details_byte_enum =
      UncheckedCast<Uint8T>(Uint32Constant(d.ToByte()));
  TNode<Uint8T> details_byte_dont_enum =
      UncheckedCast<Uint8T>(Uint32Constant(d_dont_enum.ToByte()));

  Label not_private(this);
  TVARIABLE(Uint8T, var_details, details_byte_enum);

  GotoIfNot(IsPrivateSymbol(key), &not_private);
  var_details = details_byte_dont_enum;
  Goto(&not_private);

  BIND(&not_private);
  // TODO(pthier): Use insertion_index if it was provided.
  SwissNameDictionaryAdd(dictionary, key, value, var_details.value(), bailout);
}

template void CodeStubAssembler::AddToDictionary<NameDictionary>(
    TNode<NameDictionary>, TNode<Name>, TNode<Object>, Label*,
    std::optional<TNode<IntPtrT>>);

template <class Dictionary>
TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<Dictionary> dictionary) {
  return CAST(
      LoadFixedArrayElement(dictionary, Dictionary::kNumberOfElementsIndex));
}

template <>
TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<SwissNameDictionary> dictionary) {
  TNode<IntPtrT> capacity =
      ChangeInt32ToIntPtr(LoadSwissNameDictionaryCapacity(dictionary));
  return SmiFromIntPtr(
      LoadSwissNameDictionaryNumberOfElements(dictionary, capacity));
}

template TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<NameDictionary> dictionary);
template TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<NumberDictionary> dictionary);
template TNode<Smi> CodeStubAssembler::GetNumberOfElements(
    TNode<GlobalDictionary> dictionary);

template <>
TNode<Smi> CodeStubAssembler::GetNameDictionaryFlags(
    TNode<NameDictionary> dictionary) {
  return CAST(LoadFixedArrayElement(dictionary, NameDictionary::kFlagsIndex));
}

template <>
void CodeStubAssembler::SetNameDictionaryFlags(TNode<NameDictionary> dictionary,
                                               TNode<Smi> flags) {
  StoreFixedArrayElement(dictionary, NameDictionary::kFlagsIndex, flags,
                         SKIP_WRITE_BARRIER);
}

template <>
TNode<Smi> CodeStubAssembler::GetNameDictionaryFlags(
    TNode<SwissNameDictionary> dictionary) {
  // TODO(pthier): Add flags to swiss dictionaries.
  Unreachable();
  return SmiConstant(0);
}

template <>
void CodeStubAssembler::SetNameDictionaryFlags(
    TNode<SwissNameDictionary> dictionary, TNode<Smi> flags) {
  // TODO(pthier): Add flags to swiss dictionaries.
  Unreachable();
}

namespace {
// TODO(leszeks): Remove once both TransitionArray and DescriptorArray are
// HeapObjectLayout.
template <typename Array>
struct OffsetOfArrayDataStart;
template <>
struct OffsetOfArrayDataStart<TransitionArray> {
  static constexpr int value = OFFSET_OF_DATA_START(TransitionArray);
};
template <>
struct OffsetOfArrayDataStart<DescriptorArray> {
  static constexpr int value = DescriptorArray::kHeaderSize;
};
}  // namespace

template <typename Array>
void CodeStubAssembler::LookupLinear(TNode<Name> unique_name,
                                     TNode<Array> array,
                                     TNode<Uint32T> number_of_valid_entries,
                                     Label* if_found,
                                     TVariable<IntPtrT>* var_name_index,
                                     Label* if_not_found) {
  static_assert(std::is_base_of<FixedArray, Array>::value ||
                    std::is_base_of<WeakFixedArray, Array>::value ||
                    std::is_base_of<DescriptorArray, Array>::value,
                "T must be a descendant of FixedArray or a WeakFixedArray");
  Comment("LookupLinear");
  CSA_DCHECK(this, IsUniqueName(unique_name));
  TNode<IntPtrT> first_inclusive = IntPtrConstant(Array::ToKeyIndex(0));
  TNode<IntPtrT> factor = IntPtrConstant(Array::kEntrySize);
  TNode<IntPtrT> last_exclusive = IntPtrAdd(
      first_inclusive,
      IntPtrMul(ChangeInt32ToIntPtr(number_of_valid_entries), factor));

  BuildFastLoop<IntPtrT>(
      last_exclusive, first_inclusive,
      [=, this](TNode<IntPtrT> name_index) {
        TNode<MaybeObject> element = LoadArrayElement(
            array, OffsetOfArrayDataStart<Array>::value, name_index);
        TNode<Name> candidate_name = CAST(element);
        *var_name_index = name_index;
        GotoIf(TaggedEqual(candidate_name, unique_name), if_found);
      },
      -Array::kEntrySize, LoopUnrollingMode::kYes, IndexAdvanceMode::kPre);
  Goto(if_not_found);
}

template <>
constexpr int CodeStubAssembler::MaxNumberOfEntries<TransitionArray>() {
  return TransitionsAccessor::kMaxNumberOfTransitions;
}

template <>
constexpr int CodeStubAssembler::MaxNumberOfEntries<DescriptorArray>() {
  return kMaxNumberOfDescriptors;
}

template <>
TNode<Uint32T> CodeStubAssembler::NumberOfEntries<DescriptorArray>(
    TNode<DescriptorArray> descriptors) {
  return Unsigned(LoadNumberOfDescriptors(descriptors));
}

template <>
TNode<Uint32T> CodeStubAssembler::NumberOfEntries<TransitionArray>(
    TNode<TransitionArray> transitions) {
  TNode<Uint32T> length = LoadAndUntagWeakFixedArrayLengthAsUint32(transitions);
  return Select<Uint32T>(
      Uint32LessThan(length, Uint32Constant(TransitionArray::kFirstIndex)),
      [=, this] { return Unsigned(Int32Constant(0)); },
      [=, this] {
        return Unsigned(LoadAndUntagToWord32ArrayElement(
            transitions, OFFSET_OF_DATA_START(WeakFixedArray),
            IntPtrConstant(TransitionArray::kTransitionLengthIndex)));
      });
}

template <typename Array>
TNode<IntPtrT> CodeStubAssembler::EntryIndexToIndex(
    TNode<Uint32T> entry_index) {
  TNode<Int32T> entry_size = Int32Constant(Array::kEntrySize);
  TNode<Word32T> index = Int32Mul(entry_index, entry_size);
  return ChangeInt32ToIntPtr(index);
}

template <typename Array>
TNode<IntPtrT> CodeStubAssembler::ToKeyIndex(TNode<Uint32T> entry_index) {
  return IntPtrAdd(IntPtrConstant(Array::ToKeyIndex(0)),
                   EntryIndexToIndex<Array>(entry_index));
}

template TNode<IntPtrT> CodeStubAssembler::ToKeyIndex<DescriptorArray>(
    TNode<Uint32T>);
template TNode<IntPtrT> CodeStubAssembler::ToKeyIndex<TransitionArray>(
    TNode<Uint32T>);

template <>
TNode<Uint32T> CodeStubAssembler::GetSortedKeyIndex<DescriptorArray>(
    TNode<DescriptorArray> descriptors, TNode<Uint32T> descriptor_number) {
  TNode<Uint32T> details =
      DescriptorArrayGetDetails(descriptors, descriptor_number);
  return DecodeWord32<PropertyDetails::DescriptorPointer>(details);
}

template <>
TNode<Uint32T> CodeStubAssembler::GetSortedKeyIndex<TransitionArray>(
    TNode<TransitionArray> transitions, TNode<Uint32T> transition_number) {
  return transition_number;
}

template <typename Array>
TNode<Name> CodeStubAssembler::GetKey(TNode<Array> array,
                                      TNode<Uint32T> entry_index) {
  static_assert(std::is_base_of<TransitionArray, Array>::value ||
                    std::is_base_of<DescriptorArray, Array>::value,
                "T must be a descendant of DescriptorArray or TransitionArray");
  const int key_offset = Array::ToKeyIndex(0) * kTaggedSize;
  TNode<MaybeObject> element =
      LoadArrayElement(array, OffsetOfArrayDataStart<Array>::value,
                       EntryIndexToIndex<Array>(entry_index), key_offset);
  return CAST(element);
}

template TNode<Name> CodeStubAssembler::GetKey<DescriptorArray>(
    TNode<DescriptorArray>, TNode<Uint32T>);
template TNode<Name> CodeStubAssembler::GetKey<TransitionArray>(
    TNode<TransitionArray>, TNode<Uint32T>);

TNode<Uint32T> CodeStubAssembler::DescriptorArrayGetDetails(
    TNode<DescriptorArray> descriptors, TNode<Uint32T> descriptor_number) {
  const int details_offset = DescriptorArray::ToDetailsIndex(0) * kTaggedSize;
  return Unsigned(LoadAndUntagToWord32ArrayElement(
      descriptors, DescriptorArray::kHeaderSize,
      EntryIndexToIndex<DescriptorArray>(descriptor_number), details_offset));
}

template <typename Array>
void CodeStubAssembler::LookupBinary(TNode<Name> unique_name,
                                     TNode<Array> array,
                                     TNode<Uint32T> number_of_valid_entries,
                                     Label* if_found,
                                     TVariable<IntPtrT>* var_name_index,
                                     Label* if_not_found) {
  Comment("LookupBinary");
  TVARIABLE(Uint32T, var_low, Unsigned(Int32Constant(0)));
  TNode<Uint32T> limit =
      Unsigned(Int32Sub(NumberOfEntries<Array>(array), Int32Constant(1)));
  TVARIABLE(Uint32T, var_high, limit);
  TNode<Uint32T> hash = LoadNameHashAssumeComputed(unique_name);
  CSA_DCHECK(this, Word32NotEqual(hash, Int32Constant(0)));

  // Assume non-empty array.
  CSA_DCHECK(this, Uint32LessThanOrEqual(var_low.value(), var_high.value()));

  int max_entries = MaxNumberOfEntries<Array>();

  auto calculate_mid = [&](TNode<Uint32T> low, TNode<Uint32T> high) {
    if (max_entries < kMaxInt31) {
      // mid = (low + high) / 2.
      return Unsigned(Word32Shr(Int32Add(low, high), 1));
    } else {
      // mid = low + (high - low) / 2.
      return Unsigned(Int32Add(low, Word32Shr(Int32Sub(high, low), 1)));
    }
  };

  Label binary_loop(this, {&var_high, &var_low});
  Goto(&binary_loop);
  BIND(&binary_loop);
  {
    TNode<Uint32T> mid = calculate_mid(var_low.value(), var_high.value());
    // mid_name = array->GetSortedKey(mid).
    TNode<Uint32T> sorted_key_index = GetSortedKeyIndex<Array>(array, mid);
    TNode<Name> mid_name = GetKey<Array>(array, sorted_key_index);

    TNode<Uint32T> mid_hash = LoadNameHashAssumeComputed(mid_name);

    Label mid_greater(this), mid_less(this), merge(this);
    Branch(Uint32GreaterThanOrEqual(mid_hash, hash), &mid_greater, &mid_less);
    BIND(&mid_greater);
    {
      var_high = mid;
      Goto(&merge);
    }
    BIND(&mid_less);
    {
      var_low = Unsigned(Int32Add(mid, Int32Constant(1)));
      Goto(&merge);
    }
    BIND(&merge);
    GotoIf(Word32NotEqual(var_low.value(), var_high.value()), &binary_loop);
  }

  Label scan_loop(this, &var_low);
  Goto(&scan_loop);
  BIND(&scan_loop);
  {
    GotoIf(Int32GreaterThan(var_low.value(), limit), if_not_found);

    TNode<Uint32T> sort_index =
        GetSortedKeyIndex<Array>(array, var_low.value());
    TNode<Name> current_name = GetKey<Array>(array, sort_index);
    TNode<Uint32T> current_hash = LoadNameHashAssumeComputed(current_name);
    GotoIf(Word32NotEqual(current_hash, hash), if_not_found);
    Label next(this);
    GotoIf(TaggedNotEqual(current_name, unique_name), &next);
    GotoIf(Uint32GreaterThanOrEqual(sort_index, number_of_valid_entries),
           if_not_found);
    *var_name_index = ToKeyIndex<Array>(sort_index);
    Goto(if_found);

    BIND(&next);
    var_low = Unsigned(Int32Add(var_low.value(), Int32Constant(1)));
    Goto(&scan_loop);
  }
}

void CodeStubAssembler::ForEachEnumerableOwnProperty(
    TNode<Context> context, TNode<Map> map, TNode<JSObject> object,
    PropertiesEnumerationMode mode, const ForEachKeyValueFunction& body,
    Label* bailout) {
  TNode<Uint16T> type = LoadMapInstanceType(map);
  TNode<Uint32T> bit_field3 = EnsureOnlyHasSimpleProperties(map, type, bailout);

  TVARIABLE(DescriptorArray, var_descriptors, LoadMapDescriptors(map));
  TNode<Uint32T> nof_descriptors =
      DecodeWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bit_field3);

  TVARIABLE(BoolT, var_stable, Int32TrueConstant());

  TVARIABLE(BoolT, var_has_symbol, Int32FalseConstant());
  // false - iterate only string properties, true - iterate only symbol
  // properties
  TVARIABLE(BoolT, var_is_symbol_processing_loop, Int32FalseConstant());
  TVARIABLE(IntPtrT, var_start_key_index,
            ToKeyIndex<DescriptorArray>(Unsigned(Int32Constant(0))));
  // Note: var_end_key_index is exclusive for the loop
  TVARIABLE(IntPtrT, var_end_key_index,
            ToKeyIndex<DescriptorArray>(nof_descriptors));
  VariableList list({&var_descriptors, &var_stable, &var_has_symbol,
                     &var_is_symbol_processing_loop, &var_start_key_index,
                     &var_end_key_index},
                    zone());
  Label descriptor_array_loop(this, list);

  Goto(&descriptor_array_loop);
  BIND(&descriptor_array_loop);

  BuildFastLoop<IntPtrT>(
      list, var_start_key_index.value(), var_end_key_index.value(),
      [&](TNode<IntPtrT> descriptor_key_index) {
        TNode<Name> next_key =
            LoadKeyByKeyIndex(var_descriptors.value(), descriptor_key_index);

        TVARIABLE(Object, var_value_or_accessor, SmiConstant(0));
        Label next_iteration(this);

        if (mode == kEnumerationOrder) {
          // |next_key| is either a string or a symbol
          // Skip strings or symbols depending on
          // |var_is_symbol_processing_loop|.
          Label if_string(this), if_symbol(this), if_name_ok(this);
          Branch(IsSymbol(next_key), &if_symbol, &if_string);
          BIND(&if_symbol);
          {
            // Process symbol property when |var_is_symbol_processing_loop| is
            // true.
            GotoIf(var_is_symbol_processing_loop.value(), &if_name_ok);
            // First iteration need to calculate smaller range for processing
            // symbols
            Label if_first_symbol(this);
            // var_end_key_index is still inclusive at this point.
            var_end_key_index = descriptor_key_index;
            Branch(var_has_symbol.value(), &next_iteration, &if_first_symbol);
            BIND(&if_first_symbol);
            {
              var_start_key_index = descriptor_key_index;
              var_has_symbol = Int32TrueConstant();
              Goto(&next_iteration);
            }
          }
          BIND(&if_string);
          {
            CSA_DCHECK(this, IsString(next_key));
            // Process string property when |var_is_symbol_processing_loop| is
            // false.
            Branch(var_is_symbol_processing_loop.value(), &next_iteration,
                   &if_name_ok);
          }
          BIND(&if_name_ok);
        }
        {
          TVARIABLE(Map, var_map);
          TVARIABLE(HeapObject, var_meta_storage);
          TVARIABLE(IntPtrT, var_entry);
          TVARIABLE(Uint32T, var_details);
          Label if_found(this);

          Label if_found_fast(this), if_found_dict(this);

          Label if_stable(this), if_not_stable(this);
          Branch(var_stable.value(), &if_stable, &if_not_stable);
          BIND(&if_stable);
          {
            // Directly decode from the descriptor array if |object| did not
            // change shape.
            var_map = map;
            var_meta_storage = var_descriptors.value();
            var_entry = Signed(descriptor_key_index);
            Goto(&if_found_fast);
          }
          BIND(&if_not_stable);
          {
            // If the map did change, do a slower lookup. We are still
            // guaranteed that the object has a simple shape, and that the key
            // is a name.
            var_map = LoadMap(object);
            TryLookupPropertyInSimpleObject(object, var_map.value(), next_key,
                                            &if_found_fast, &if_found_dict,
                                            &var_meta_storage, &var_entry,
                                            &next_iteration, bailout);
          }

          BIND(&if_found_fast);
          {
            TNode<DescriptorArray> descriptors = CAST(var_meta_storage.value());
            TNode<IntPtrT> name_index = var_entry.value();

            // Skip non-enumerable properties.
            var_details = LoadDetailsByKeyIndex(descriptors, name_index);
            GotoIf(IsSetWord32(var_details.value(),
                               PropertyDetails::kAttributesDontEnumMask),
                   &next_iteration);

            LoadPropertyFromFastObject(object, var_map.value(), descriptors,
                                       name_index, var_details.value(),
                                       &var_value_or_accessor);
            Goto(&if_found);
          }
          BIND(&if_found_dict);
          {
            TNode<PropertyDictionary> dictionary =
                CAST(var_meta_storage.value());
            TNode<IntPtrT> entry = var_entry.value();

            TNode<Uint32T> details = LoadDetailsByKeyIndex(dictionary, entry);
            // Skip non-enumerable properties.
            GotoIf(
                IsSetWord32(details, PropertyDetails::kAttributesDontEnumMask),
                &next_iteration);

            var_details = details;
            var_value_or_accessor =
                LoadValueByKeyIndex<PropertyDictionary>(dictionary, entry);
            Goto(&if_found);
          }

          // Here we have details and value which could be an accessor.
          BIND(&if_found);
          {
            TNode<Object> value_or_accessor = var_value_or_accessor.value();
            body(next_key, [&]() {
              TVARIABLE(Object, var_value);
              Label value_ready(this), slow_load(this, Label::kDeferred);

              var_value = CallGetterIfAccessor(
                  value_or_accessor, object, var_details.value(), context,
                  object, next_key, &slow_load, kCallJSGetterUseCachedName);
              Goto(&value_ready);

              BIND(&slow_load);
              var_value =
                  CallRuntime(Runtime::kGetProperty, context, object, next_key);
              Goto(&value_ready);

              BIND(&value_ready);
              return var_value.value();
            });

            // Check if |object| is still stable, i.e. the descriptors in the
            // preloaded |descriptors| are still the same modulo in-place
            // representation changes.
            GotoIfNot(var_stable.value(), &next_iteration);
            var_stable = TaggedEqual(LoadMap(object), map);
            // Reload the descriptors just in case the actual array changed, and
            // any of the field representations changed in-place.
            var_descriptors = LoadMapDescriptors(map);

            Goto(&next_iteration);
          }
        }
        BIND(&next_iteration);
      },
      DescriptorArray::kEntrySize, LoopUnrollingMode::kNo,
      IndexAdvanceMode::kPost);

  if (mode == kEnumerationOrder) {
    Label done(this);
    GotoIf(var_is_symbol_processing_loop.value(), &done);
    GotoIfNot(var_has_symbol.value(), &done);
    // All string properties are processed, now process symbol properties.
    var_is_symbol_processing_loop = Int32TrueConstant();
    // Add DescriptorArray::kEntrySize to make the var_end_key_index exclusive
    // as BuildFastLoop() expects.
    Increment(&var_end_key_index, DescriptorArray::kEntrySize);
    Goto(&descriptor_array_loop);

    BIND(&done);
  }
}

TNode<Object> CodeStubAssembler::GetConstructor(TNode<Map> map) {
  TVARIABLE(HeapObject, var_maybe_constructor);
  var_maybe_constructor = map;
  Label loop(this, &var_maybe_constructor), done(this);
  GotoIfNot(IsMap(var_maybe_constructor.value()), &done);
  Goto(&loop);

  BIND(&loop);
  {
    var_maybe_constructor = CAST(
        LoadObjectField(var_maybe_constructor.value(),
                        Map::kConstructorOrBackPointerOrNativeContextOffset));
    GotoIf(IsMap(var_maybe_constructor.value()), &loop);
    Goto(&done);
  }

  BIND(&done);
  return var_maybe_constructor.value();
}

TNode<NativeContext> CodeStubAssembler::GetCreationContextFromMap(
    TNode<Map> map, Label* if_bailout) {
  TNode<Map> meta_map = LoadMap(map);
  TNode<Object> maybe_context =
      LoadMapConstructorOrBackPointerOrNativeContext(meta_map);
  GotoIf(IsNull(maybe_context), if_bailout);
  return CAST(maybe_context);
}

TNode<NativeContext> CodeStubAssembler::GetCreationContext(
    TNode<JSReceiver> receiver, Label* if_bailout) {
  return GetCreationContextFromMap(LoadMap(receiver), if_bailout);
}

TNode<NativeContext> CodeStubAssembler::GetFunctionRealm(
    TNode<Context> context, TNode<JSReceiver> receiver, Label* if_bailout) {
  TVARIABLE(JSReceiver, current);
  TVARIABLE(Map, current_map);
  Label loop(this, VariableList({&current}, zone())), if_proxy(this),
      if_simple_case(this), if_bound_function(this), if_wrapped_function(this),
      proxy_revoked(this, Label::kDeferred);
  CSA_DCHECK(this, IsCallable(receiver));
  current = receiver;
  Goto(&loop);

  BIND(&loop);
  {
    current_map = LoadMap(current.value());
    TNode<Int32T> instance_type = LoadMapInstanceType(current_map.value());
    GotoIf(IsJSFunctionInstanceType(instance_type), &if_simple_case);
    GotoIf(InstanceTypeEqual(instance_type, JS_PROXY_TYPE), &if_proxy);
    GotoIf(InstanceTypeEqual(instance_type, JS_BOUND_FUNCTION_TYPE),
           &if_bound_function);
    GotoIf(InstanceTypeEqual(instance_type, JS_WRAPPED_FUNCTION_TYPE),
           &if_wrapped_function);
    Goto(&if_simple_case);
  }

  BIND(&if_proxy);
  {
    TNode<JSProxy> proxy = CAST(current.value());
    TNode<HeapObject> handler =
        CAST(LoadObjectField(proxy, JSProxy::kHandlerOffset));
    // Proxy is revoked.
    GotoIfNot(IsJSReceiver(handler), &proxy_revoked);
    TNode<JSReceiver> target =
        CAST(LoadObjectField(proxy, JSProxy::kTargetOffset));
    current = target;
    Goto(&loop);
  }

  BIND(&proxy_revoked);
  { ThrowTypeError(context, MessageTemplate::kProxyRevoked, "apply"); }

  BIND(&if_bound_function);
  {
    TNode<JSBoundFunction> bound_function = CAST(current.value());
    TNode<JSReceiver> target = CAST(LoadObjectField(
        bound_function, JSBoundFunction::kBoundTargetFunctionOffset));
    current = target;
    Goto(&loop);
  }

  BIND(&if_wrapped_function);
  {
    TNode<JSWrappedFunction> wrapped_function = CAST(current.value());
    TNode<JSReceiver> target = CAST(LoadObjectField(
        wrapped_function, JSWrappedFunction::kWrappedTargetFunctionOffset));
    current = target;
    Goto(&loop);
  }

  BIND(&if_simple_case);
  {
    // Load native context from the meta map.
    return GetCreationContextFromMap(current_map.value(), if_bailout);
  }
}

void CodeStubAssembler::DescriptorLookup(TNode<Name> unique_name,
                                         TNode<DescriptorArray> descriptors,
                                         TNode<Uint32T> bitfield3,
                                         Label* if_found,
                                         TVariable<IntPtrT>* var_name_index,
                                         Label* if_not_found) {
  Comment("DescriptorArrayLookup");
  TNode<Uint32T> nof =
      DecodeWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bitfield3);
  Lookup<DescriptorArray>(unique_name, descriptors, nof, if_found,
                          var_name_index, if_not_found);
}

void CodeStubAssembler::TransitionLookup(TNode<Name> unique_name,
                                         TNode<TransitionArray> transitions,
                                         Label* if_found,
                                         TVariable<IntPtrT>* var_name_index,
                                         Label* if_not_found) {
  Comment("TransitionArrayLookup");
  TNode<Uint32T> number_of_valid_transitions =
      NumberOfEntries<TransitionArray>(transitions);
  Lookup<TransitionArray>(unique_name, transitions, number_of_valid_transitions,
                          if_found, var_name_index, if_not_found);
}

template <typename Array>
void CodeStubAssembler::Lookup(TNode<Name> unique_name, TNode<Array> array,
                               TNode<Uint32T> number_of_valid_entries,
                               Label* if_found,
                               TVariable<IntPtrT>* var_name_index,
                               Label* if_not_found) {
  Comment("ArrayLookup");
  if (!number_of_valid_entries) {
    number_of_valid_entries = NumberOfEntries(array);
  }
  GotoIf(Word32Equal(number_of_valid_entries, Int32Constant(0)), if_not_found);
  Label linear_search(this), binary_search(this);
  const int kMaxElementsForLinearSearch = 32;
  Branch(Uint32LessThanOrEqual(number_of_valid_entries,
                               Int32Constant(kMaxElementsForLinearSearch)),
         &linear_search, &binary_search);
  BIND(&linear_search);
  {
    LookupLinear<Array>(unique_name, array, number_of_valid_entries, if_found,
                        var_name_index, if_not_found);
  }
  BIND(&binary_search);
  {
    LookupBinary<Array>(unique_name, array, number_of_valid_entries, if_found,
                        var_name_index, if_not_found);
  }
}

void CodeStubAssembler::TryLookupPropertyInSimpleObject(
    TNode<JSObject> object, TNode<Map> map, TNode<Name> unique_name,
    Label* if_found_fast, Label* if_found_dict,
    TVariable<HeapObject>* var_meta_storage, TVariable<IntPtrT>* var_name_index,
    Label* if_not_found, Label* bailout) {
  CSA_DCHECK(this, IsSimpleObjectMap(map));
  CSA_DCHECK(this, IsUniqueNameNoCachedIndex(unique_name));

  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  Label if_isfastmap(this), if_isslowmap(this);
  Branch(IsSetWord32<Map::Bits3::IsDictionaryMapBit>(bit_field3), &if_isslowmap,
         &if_isfastmap);
  BIND(&if_isfastmap);
  {
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(map);
    *var_meta_storage = descriptors;

    DescriptorLookup(unique_name, descriptors, bit_field3, if_found_fast,
                     var_name_index, if_not_found);
  }
  BIND(&if_isslowmap);
  {
    TNode<PropertyDictionary> dictionary = CAST(LoadSlowProperties(object));
    *var_meta_storage = dictionary;

    NameDictionaryLookup<PropertyDictionary>(
        dictionary, unique_name, if_found_dict, var_name_index, if_not_found);
  }
}

void CodeStubAssembler::TryLookupProperty(
    TNode<HeapObject> object, TNode<Map> map, TNode<Int32T> instance_type,
    TNode<Name> unique_name, Label* if_found_fast, Label* if_found_dict,
    Label* if_found_global, TVariable<HeapObject>* var_meta_storage,
    TVariable<IntPtrT>* var_name_index, Label* if_not_found,
    Label* if_bailout) {
  Label if_objectisspecial(this);
  GotoIf(IsSpecialReceiverInstanceType(instance_type), &if_objectisspecial);

  TryLookupPropertyInSimpleObject(CAST(object), map, unique_name, if_found_fast,
                                  if_found_dict, var_meta_storage,
                                  var_name_index, if_not_found, if_bailout);

  BIND(&if_objectisspecial);
  {
    // Handle global object here and bailout for other special objects.
    GotoIfNot(InstanceTypeEqual(instance_type, JS_GLOBAL_OBJECT_TYPE),
              if_bailout);

    // Handle interceptors and access checks in runtime.
    TNode<Int32T> bit_field = LoadMapBitField(map);
    int mask = Map::Bits1::HasNamedInterceptorBit::kMask |
               Map::Bits1::IsAccessCheckNeededBit::kMask;
    GotoIf(IsSetWord32(bit_field, mask), if_bailout);

    TNode<GlobalDictionary> dictionary = CAST(LoadSlowProperties(CAST(object)));
    *var_meta_storage = dictionary;

    NameDictionaryLookup<GlobalDictionary>(
        dictionary, unique_name, if_found_global, var_name_index, if_not_found);
  }
}

void CodeStubAssembler::TryHasOwnProperty(TNode<HeapObject> object,
                                          TNode<Map> map,
                                          TNode<Int32T> instance_type,
                                          TNode<Name> unique_name,
                                          Label* if_found, Label* if_not_found,
                                          Label* if_bailout) {
  Comment("TryHasOwnProperty");
  CSA_DCHECK(this, IsUniqueNameNoCachedIndex(unique_name));
  TVARIABLE(HeapObject, var_meta_storage);
  TVARIABLE(IntPtrT, var_name_index);

  Label if_found_global(this);
  TryLookupProperty(object, map, instance_type, unique_name, if_found, if_found,
                    &if_found_global, &var_meta_storage, &var_name_index,
                    if_not_found, if_bailout);

  BIND(&if_found_global);
  {
    TVARIABLE(Object, var_value);
    TVARIABLE(Uint32T, var_details);
    // Check if the property cell is not deleted.
    LoadPropertyFromGlobalDictionary(CAST(var_meta_storage.value()),
                                     var_name_index.value(), &var_details,
                                     &var_value, if_not_found);
    Goto(if_found);
  }
}

TNode<Object> CodeStubAssembler::GetMethod(TNode<Context> context,
                                           TNode<Object> object,
                                           Handle<Name> name,
                                           Label* if_null_or_undefined) {
  TNode<Object> method = GetProperty(context, object, name);

  GotoIf(IsUndefined(method), if_null_or_undefined);
  GotoIf(IsNull(method), if_null_or_undefined);

  return method;
}

TNode<Object> CodeStubAssembler::GetIteratorMethod(
    TNode<Context> context, TNode<HeapObject> heap_obj,
    Label* if_iteratorundefined) {
  return GetMethod(context, heap_obj, isolate()->factory()->iterator_symbol(),
                   if_iteratorundefined);
}

TNode<Object> CodeStubAssembler::CreateAsyncFromSyncIterator(
    TNode<Context> context, TNode<Object> sync_iterator) {
  Label not_receiver(this, Label::kDeferred);
  Label done(this);
  TVARIABLE(Object, return_value);

  GotoIf(TaggedIsSmi(sync_iterator), &not_receiver);
  GotoIfNot(IsJSReceiver(CAST(sync_iterator)), &not_receiver);

  const TNode<Object> next =
      GetProperty(context, sync_iterator, factory()->next_string());
  return_value =
      CreateAsyncFromSyncIterator(context, CAST(sync_iterator), next);
  Goto(&done);

  BIND(&not_receiver);
  {
    return_value = CallRuntime(Runtime::kThrowSymbolIteratorInvalid, context);

    // Unreachable due to the Throw in runtime call.
    Goto(&done);
  }

  BIND(&done);
  return return_value.value();
}

TNode<JSObject> CodeStubAssembler::CreateAsyncFromSyncIterator(
    TNode<Context> context, TNode<JSReceiver> sync_iterator,
    TNode<Object> next) {
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::ASYNC_FROM_SYNC_ITERATOR_MAP_INDEX));
  const TNode<JSObject> iterator = AllocateJSObjectFromMap(map);

  StoreObjectFieldNoWriteBarrier(
      iterator, JSAsyncFromSyncIterator::kSyncIteratorOffset, sync_iterator);
  StoreObjectFieldNoWriteBarrier(iterator, JSAsyncFromSyncIterator::kNextOffset,
                                 next);
  return iterator;
}

void CodeStubAssembler::LoadPropertyFromFastObject(
    TNode<HeapObject> object, TNode<Map> map,
    TNode<DescriptorArray> descriptors, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value) {
  TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, name_index);
  *var_details = details;

  LoadPropertyFromFastObject(object, map, descriptors, name_index, details,
                             var_value);
}

void CodeStubAssembler::LoadPropertyFromFastObject(
    TNode<HeapObject> object, TNode<Map> map,
    TNode<DescriptorArray> descriptors, TNode<IntPtrT> name_index,
    TNode<Uint32T> details, TVariable<Object>* var_value) {
  Comment("[ LoadPropertyFromFastObject");

  TNode<Uint32T> location =
      DecodeWord32<PropertyDetails::LocationField>(details);

  Label if_in_field(this), if_in_descriptor(this), done(this);
  Branch(Word32Equal(location, Int32Constant(static_cast<int32_t>(
                                   PropertyLocation::kField))),
         &if_in_field, &if_in_descriptor);
  BIND(&if_in_field);
  {
    TNode<IntPtrT> field_index =
        Signed(DecodeWordFromWord32<PropertyDetails::FieldIndexField>(details));
    TNode<Uint32T> representation =
        DecodeWord32<PropertyDetails::RepresentationField>(details);

    // TODO(ishell): support WasmValues.
    CSA_DCHECK(this, Word32NotEqual(representation,
                                    Int32Constant(Representation::kWasmValue)));
    field_index =
        IntPtrAdd(field_index, LoadMapInobjectPropertiesStartInWords(map));
    TNode<IntPtrT> instance_size_in_words = LoadMapInstanceSizeInWords(map);

    Label if_inobject(this), if_backing_store(this);
    TVARIABLE(Float64T, var_double_value);
    Label rebox_double(this, &var_double_value);
    Branch(UintPtrLessThan(field_index, instance_size_in_words), &if_inobject,
           &if_backing_store);
    BIND(&if_inobject);
    {
      Comment("if_inobject");
      TNode<IntPtrT> field_offset = TimesTaggedSize(field_index);

      Label if_double(this), if_tagged(this);
      Branch(Word32NotEqual(representation,
                            Int32Constant(Representation::kDouble)),
             &if_tagged, &if_double);
      BIND(&if_tagged);
      {
        *var_value = LoadObjectField(object, field_offset);
        Goto(&done);
      }
      BIND(&if_double);
      {
        TNode<HeapNumber> heap_number =
            CAST(LoadObjectField(object, field_offset));
        var_double_value = LoadHeapNumberValue(heap_number);
        Goto(&rebox_double);
      }
    }
    BIND(&if_backing_store);
    {
      Comment("if_backing_store");
      TNode<HeapObject> properties = LoadFastProperties(CAST(object), true);
      field_index = Signed(IntPtrSub(field_index, instance_size_in_words));
      TNode<Object> value =
          LoadPropertyArrayElement(CAST(properties), field_index);

      Label if_double(this), if_tagged(this);
      Branch(Word32NotEqual(representation,
                            Int32Constant(Representation::kDouble)),
             &if_tagged, &if_double);
      BIND(&if_tagged);
      {
        *var_value = value;
        Goto(&done);
      }
      BIND(&if_double);
      {
        var_double_value = LoadHeapNumberValue(CAST(value));
        Goto(&rebox_double);
      }
    }
    BIND(&rebox_double);
    {
      Comment("rebox_double");
      TNode<HeapNumber> heap_number =
          AllocateHeapNumberWithValue(var_double_value.value());
      *var_value = heap_number;
      Goto(&done);
    }
  }
  BIND(&if_in_descriptor);
  {
    *var_value = LoadValueByKeyIndex(descriptors, name_index);
    Goto(&done);
  }
  BIND(&done);

  Comment("] LoadPropertyFromFastObject");
}

template <typename Dictionary>
void CodeStubAssembler::LoadPropertyFromDictionary(
    TNode<Dictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value) {
  Comment("LoadPropertyFromNameDictionary");
  *var_details = LoadDetailsByKeyIndex(dictionary, name_index);
  *var_value = LoadValueByKeyIndex(dictionary, name_index);

  Comment("] LoadPropertyFromNameDictionary");
}

void CodeStubAssembler::LoadPropertyFromGlobalDictionary(
    TNode<GlobalDictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value,
    Label* if_deleted) {
  Comment("[ LoadPropertyFromGlobalDictionary");
  TNode<PropertyCell> property_cell =
      CAST(LoadFixedArrayElement(dictionary, name_index));

  TNode<Object> value =
      LoadObjectField(property_cell, PropertyCell::kValueOffset);
  GotoIf(TaggedEqual(value, PropertyCellHoleConstant()), if_deleted);

  *var_value = value;

  TNode<Uint32T> details = Unsigned(LoadAndUntagToWord32ObjectField(
      property_cell, PropertyCell::kPropertyDetailsRawOffset));
  *var_details = details;

  Comment("] LoadPropertyFromGlobalDictionary");
}

template void CodeStubAssembler::LoadPropertyFromDictionary(
    TNode<NameDictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value);

template void CodeStubAssembler::LoadPropertyFromDictionary(
    TNode<SwissNameDictionary> dictionary, TNode<IntPtrT> name_index,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_value);

// |value| is the property backing store's contents, which is either a value or
// an accessor pair, as specified by |details|. |holder| is a JSObject or a
// PropertyCell (TODO: use Union). Returns either the original value, or the
// result of the getter call.
TNode<Object> CodeStubAssembler::CallGetterIfAccessor(
    TNode<Object> value, TNode<HeapObject> holder, TNode<Uint32T> details,
    TNode<Context> context, TNode<Object> receiver, TNode<Object> name,
    Label* if_bailout, GetOwnPropertyMode mode,
    ExpectedReceiverMode expected_receiver_mode) {
  TVARIABLE(Object, var_value, value);
  Label done(this), if_accessor_info(this, Label::kDeferred);

  TNode<Uint32T> kind = DecodeWord32<PropertyDetails::KindField>(details);
  GotoIf(
      Word32Equal(kind, Int32Constant(static_cast<int>(PropertyKind::kData))),
      &done);

  // Accessor case.
  GotoIfNot(IsAccessorPair(CAST(value)), &if_accessor_info);

  // AccessorPair case.
  {
    if (mode == kCallJSGetterUseCachedName ||
        mode == kCallJSGetterDontUseCachedName) {
      Label if_callable(this), if_function_template_info(this);
      TNode<AccessorPair> accessor_pair = CAST(value);
      TNode<HeapObject> getter =
          CAST(LoadObjectField(accessor_pair, AccessorPair::kGetterOffset));
      TNode<Map> getter_map = LoadMap(getter);

      GotoIf(IsCallableMap(getter_map), &if_callable);
      GotoIf(IsFunctionTemplateInfoMap(getter_map), &if_function_template_info);

      // Return undefined if the {getter} is not callable.
      var_value = UndefinedConstant();
      Goto(&done);

      BIND(&if_callable);
      {
        // Call the accessor. No need to check side-effect mode here, since it
        // will be checked later in DebugOnFunctionCall.
        // It's too early to convert receiver to JSReceiver at this point
        // (the Call builtin will do the conversion), so we ignore the
        // |expected_receiver_mode| here.
        var_value = Call(context, getter, receiver);
        Goto(&done);
      }

      BIND(&if_function_template_info);
      {
        Label use_cached_property(this);
        TNode<HeapObject> cached_property_name = LoadObjectField<HeapObject>(
            getter, FunctionTemplateInfo::kCachedPropertyNameOffset);

        Label* has_cached_property = mode == kCallJSGetterUseCachedName
                                         ? &use_cached_property
                                         : if_bailout;
        GotoIfNot(IsTheHole(cached_property_name), has_cached_property);

        TNode<JSReceiver> js_receiver;
        switch (expected_receiver_mode) {
          case kExpectingJSReceiver:
            js_receiver = CAST(receiver);
            break;
          case kExpectingAnyReceiver:
            // TODO(ishell): in case the function template info has a signature
            // and receiver is not a JSReceiver the signature check in
            // CallFunctionTemplate builtin will fail anyway, so we can short
            // cut it here and throw kIllegalInvocation immediately.
            js_receiver = ToObject_Inline(context, receiver);
            break;
        }
        TNode<NativeContext> creation_context =
            GetCreationContext(CAST(holder), if_bailout);
        TNode<Context> caller_context = context;
        var_value = CallBuiltin(
            Builtin::kCallFunctionTemplate_Generic, creation_context, getter,
            Int32Constant(i::JSParameterCount(0)), caller_context, js_receiver);
        Goto(&done);

        if (mode == kCallJSGetterUseCachedName) {
          Bind(&use_cached_property);

          var_value = GetProperty(context, holder, cached_property_name);

          Goto(&done);
        }
      }
    } else {
      DCHECK_EQ(mode, kReturnAccessorPair);
      Goto(&done);
    }
  }

  // AccessorInfo case.
  BIND(&if_accessor_info);
  {
    TNode<AccessorInfo> accessor_info = CAST(value);
    Label if_array(this), if_function(this), if_wrapper(this);

    // Dispatch based on {holder} instance type.
    TNode<Map> holder_map = LoadMap(holder);
    TNode<Uint16T> holder_instance_type = LoadMapInstanceType(holder_map);
    GotoIf(IsJSArrayInstanceType(holder_instance_type), &if_array);
    GotoIf(IsJSFunctionInstanceType(holder_instance_type), &if_function);
    Branch(IsJSPrimitiveWrapperInstanceType(holder_instance_type), &if_wrapper,
           if_bailout);

    // JSArray AccessorInfo case.
    BIND(&if_array);
    {
      // We only deal with the "length" accessor on JSArray.
      GotoIfNot(IsLengthString(
                    LoadObjectField(accessor_info, AccessorInfo::kNameOffset)),
                if_bailout);
      TNode<JSArray> array = CAST(holder);
      var_value = LoadJSArrayLength(array);
      Goto(&done);
    }

    // JSFunction AccessorInfo case.
    BIND(&if_function);
    {
      // We only deal with the "prototype" accessor on JSFunction here.
      GotoIfNot(IsPrototypeString(
                    LoadObjectField(accessor_info, AccessorInfo::kNameOffset)),
                if_bailout);

      TNode<JSFunction> function = CAST(holder);
      GotoIfPrototypeRequiresRuntimeLookup(function, holder_map, if_bailout);
      var_value = LoadJSFunctionPrototype(function, if_bailout);
      Goto(&done);
    }

    // JSPrimitiveWrapper AccessorInfo case.
    BIND(&if_wrapper);
    {
      // We only deal with the "length" accessor on JSPrimitiveWrapper string
      // wrappers.
      GotoIfNot(IsLengthString(
                    LoadObjectField(accessor_info, AccessorInfo::kNameOffset)),
                if_bailout);
      TNode<Object> holder_value = LoadJSPrimitiveWrapperValue(CAST(holder));
      GotoIfNot(TaggedIsNotSmi(holder_value), if_bailout);
      GotoIfNot(IsString(CAST(holder_value)), if_bailout);
      var_value = LoadStringLengthAsSmi(CAST(holder_value));
      Goto(&done);
    }
  }

  BIND(&done);
  return var_value.value();
}

void CodeStubAssembler::TryGetOwnProperty(
    TNode<Context> context, TNode<Object> receiver, TNode<JSReceiver> object,
    TNode<Map> map, TNode<Int32T> instance_type, TNode<Name> unique_name,
    Label* if_found_value, TVariable<Object>* var_value, Label* if_not_found,
    Label* if_bailout, ExpectedReceiverMode expected_receiver_mode) {
  TryGetOwnProperty(context, receiver, object, map, instance_type, unique_name,
                    if_found_value, var_value, nullptr, nullptr, if_not_found,
                    if_bailout,
                    receiver == object ? kCallJSGetterUseCachedName
                                       : kCallJSGetterDontUseCachedName,
                    expected_receiver_mode);
}

void CodeStubAssembler::TryGetOwnProperty(
    TNode<Context> context, TNode<Object> receiver, TNode<JSReceiver> object,
    TNode<Map> map, TNode<Int32T> instance_type, TNode<Name> unique_name,
    Label* if_found_value, TVariable<Object>* var_value,
    TVariable<Uint32T>* var_details, TVariable<Object>* var_raw_value,
    Label* if_not_found, Label* if_bailout, GetOwnPropertyMode mode,
    ExpectedReceiverMode expected_receiver_mode) {
  DCHECK_EQ(MachineRepresentation::kTagged, var_value->rep());
  Comment("TryGetOwnProperty");
  if (receiver == object) {
    // If |receiver| is exactly the same Node as the |object| which is
    // guaranteed to be JSReceiver override the |expected_receiver_mode|.
    expected_receiver_mode = kExpectingJSReceiver;
  }
  CSA_DCHECK(this, IsUniqueNameNoCachedIndex(unique_name));
  TVARIABLE(HeapObject, var_meta_storage);
  TVARIABLE(IntPtrT, var_entry);

  Label if_found_fast(this), if_found_dict(this), if_found_global(this);

  TVARIABLE(Uint32T, local_var_details);
  if (!var_details) {
    var_details = &local_var_details;
  }
  Label if_found(this);

  TryLookupProperty(object, map, instance_type, unique_name, &if_found_fast,
                    &if_found_dict, &if_found_global, &var_meta_storage,
                    &var_entry, if_not_found, if_bailout);
  BIND(&if_found_fast);
  {
    TNode<DescriptorArray> descriptors = CAST(var_meta_storage.value());
    TNode<IntPtrT> name_index = var_entry.value();

    LoadPropertyFromFastObject(object, map, descriptors, name_index,
                               var_details, var_value);
    Goto(&if_found);
  }
  BIND(&if_found_dict);
  {
    TNode<PropertyDictionary> dictionary = CAST(var_meta_storage.value());
    TNode<IntPtrT> entry = var_entry.value();
    LoadPropertyFromDictionary(dictionary, entry, var_details, var_value);

    Goto(&if_found);
  }
  BIND(&if_found_global);
  {
    TNode<GlobalDictionary> dictionary = CAST(var_meta_storage.value());
    TNode<IntPtrT> entry = var_entry.value();

    LoadPropertyFromGlobalDictionary(dictionary, entry, var_details, var_value,
                                     if_not_found);
    Goto(&if_found);
  }
  // Here we have details and value which could be an accessor.
  BIND(&if_found);
  {
    // TODO(ishell): Execute C++ accessor in case of accessor info
    if (var_raw_value) {
      *var_raw_value = *var_value;
    }
    TNode<Object> value = CallGetterIfAccessor(
        var_value->value(), object, var_details->value(), context, receiver,
        unique_name, if_bailout, mode, expected_receiver_mode);
    *var_value = value;
    Goto(if_found_value);
  }
}

void CodeStubAssembler::InitializePropertyDescriptorObject(
    TNode<PropertyDescriptorObject> descriptor, TNode<Object> value,
    TNode<Uint32T> details, Label* if_bailout) {
  Label if_data_property(this), if_accessor_property(this),
      test_configurable(this), test_property_type(this), done(this);
  TVARIABLE(Smi, flags,
            SmiConstant(PropertyDescriptorObject::HasEnumerableBit::kMask |
                        PropertyDescriptorObject::HasConfigurableBit::kMask));

  {  // test enumerable
    TNode<Uint32T> dont_enum =
        Uint32Constant(DONT_ENUM << PropertyDetails::AttributesField::kShift);
    GotoIf(Word32And(details, dont_enum), &test_configurable);
    flags =
        SmiOr(flags.value(),
              SmiConstant(PropertyDescriptorObject::IsEnumerableBit::kMask));
    Goto(&test_configurable);
  }

  BIND(&test_configurable);
  {
    TNode<Uint32T> dont_delete =
        Uint32Constant(DONT_DELETE << PropertyDetails::AttributesField::kShift);
    GotoIf(Word32And(details, dont_delete), &test_property_type);
    flags =
        SmiOr(flags.value(),
              SmiConstant(PropertyDescriptorObject::IsConfigurableBit::kMask));
    Goto(&test_property_type);
  }

  BIND(&test_property_type);
  BranchIfAccessorPair(value, &if_accessor_property, &if_data_property);

  BIND(&if_accessor_property);
  {
    Label done_get(this), store_fields(this);
    TNode<AccessorPair> accessor_pair = CAST(value);

    auto BailoutIfTemplateInfo = [this, &if_bailout](TNode<HeapObject> value) {
      TVARIABLE(HeapObject, result);

      Label bind_undefined(this), return_result(this);
      GotoIf(IsNull(value), &bind_undefined);
      result = value;
      TNode<Map> map = LoadMap(value);
      // TODO(ishell): probe template instantiations cache.
      GotoIf(IsFunctionTemplateInfoMap(map), if_bailout);
      Goto(&return_result);

      BIND(&bind_undefined);
      result = UndefinedConstant();
      Goto(&return_result);

      BIND(&return_result);
      return result.value();
    };

    TNode<HeapObject> getter =
        LoadObjectField<HeapObject>(accessor_pair, AccessorPair::kGetterOffset);
    TNode<HeapObject> setter =
        LoadObjectField<HeapObject>(accessor_pair, AccessorPair::kSetterOffset);
    getter = BailoutIfTemplateInfo(getter);
    setter = BailoutIfTemplateInfo(setter);

    Label bind_undefined(this, Label::kDeferred), return_result(this);
    flags = SmiOr(flags.value(),
                  SmiConstant(PropertyDescriptorObject::HasGetBit::kMask |
                              PropertyDescriptorObject::HasSetBit::kMask));
    StoreObjectField(descriptor, PropertyDescriptorObject::kFlagsOffset,
                     flags.value());
    StoreObjectField(descriptor, PropertyDescriptorObject::kValueOffset,
                     NullConstant());
    StoreObjectField(descriptor, PropertyDescriptorObject::kGetOffset,
                     BailoutIfTemplateInfo(getter));
    StoreObjectField(descriptor, PropertyDescriptorObject::kSetOffset,
                     BailoutIfTemplateInfo(setter));
    Goto(&done);
  }

  BIND(&if_data_property);
  {
    Label store_fields(this);
    flags = SmiOr(flags.value(),
                  SmiConstant(PropertyDescriptorObject::HasValueBit::kMask |
                              PropertyDescriptorObject::HasWritableBit::kMask));
    TNode<Uint32T> read_only =
        Uint32Constant(READ_ONLY << PropertyDetails::AttributesField::kShift);
    GotoIf(Word32And(details, read_only), &store_fields);
    flags = SmiOr(flags.value(),
                  SmiConstant(PropertyDescriptorObject::IsWritableBit::kMask));
    Goto(&store_fields);

    BIND(&store_fields);
    StoreObjectField(descriptor, PropertyDescriptorObject::kFlagsOffset,
                     flags.value());
    StoreObjectField(descriptor, PropertyDescriptorObject::kValueOffset, value);
    StoreObjectField(descriptor, PropertyDescriptorObject::kGetOffset,
                     NullConstant());
    StoreObjectField(descriptor, PropertyDescriptorObject::kSetOffset,
                     NullConstant());
    Goto(&done);
  }

  BIND(&done);
}

TNode<PropertyDescriptorObject>
CodeStubAssembler::AllocatePropertyDescriptorObject(TNode<Context> context) {
  TNode<HeapObject> result = Allocate(PropertyDescriptorObject::kSize);
  TNode<Map> map = GetInstanceTypeMap(PROPERTY_DESCRIPTOR_OBJECT_TYPE);
  StoreMapNoWriteBarrier(result, map);
  TNode<Smi> zero = SmiConstant(0);
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kFlagsOffset,
                                 zero);
  TNode<Hole> the_hole = TheHoleConstant();
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kValueOffset,
                                 the_hole);
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kGetOffset,
                                 the_hole);
  StoreObjectFieldNoWriteBarrier(result, PropertyDescriptorObject::kSetOffset,
                                 the_hole);
  return CAST(result);
}

TNode<BoolT> CodeStubAssembler::IsInterestingProperty(TNode<Name> name) {
  TVARIABLE(BoolT, var_result);
  Label return_false(this), return_true(this), return_generic(this);
  // TODO(ishell): consider using ReadOnlyRoots::IsNameForProtector() trick for
  // these strings and interesting symbols.
  GotoIf(IsToJSONString(name), &return_true);
  GotoIf(IsGetString(name), &return_true);
  GotoIfNot(InstanceTypeEqual(LoadMapInstanceType(LoadMap(name)), SYMBOL_TYPE),
            &return_false);
  Branch(IsSetWord32<Symbol::IsInterestingSymbolBit>(
             LoadObjectField<Uint32T>(name, offsetof(Symbol, flags_))),
         &return_true, &return_false);

  BIND(&return_false);
  var_result = BoolConstant(false);
  Goto(&return_generic);

  BIND(&return_true);
  var_result = BoolConstant(true);
  Goto(&return_generic);

  BIND(&return_generic);
  return var_result.value();
}

TNode<Object> CodeStubAssembler::GetInterestingProperty(
    TNode<Context> context, TNode<JSReceiver> receiver, TNode<Name> name,
    Label* if_not_found) {
  TVARIABLE(HeapObject, var_holder, receiver);
  TVARIABLE(Map, var_holder_map, LoadMap(receiver));

  return GetInterestingProperty(context, receiver, &var_holder, &var_holder_map,
                                name, if_not_found);
}

TNode<Object> CodeStubAssembler::GetInterestingProperty(
    TNode<Context> context, TNode<Object> receiver,
    TVariable<HeapObject>* var_holder, TVariable<Map>* var_holder_map,
    TNode<Name> name, Label* if_not_found) {
  CSA_DCHECK(this, IsInterestingProperty(name));
  // The lookup starts at the var_holder and var_holder_map must contain
  // var_holder's map.
  CSA_DCHECK(this, TaggedEqual(LoadMap((*var_holder).value()),
                               (*var_holder_map).value()));
  TVARIABLE(Object, var_result, UndefinedConstant());

  // Check if all relevant maps (including the prototype maps) don't
  // have any interesting properties (i.e. that none of them have the
  // @@toStringTag or @@toPrimitive property).
  Label loop(this, {var_holder, var_holder_map}),
      lookup(this, Label::kDeferred);
  Goto(&loop);
  BIND(&loop);
  {
    Label interesting_properties(this);
    TNode<HeapObject> holder = (*var_holder).value();
    TNode<Map> holder_map = (*var_holder_map).value();
    GotoIf(IsNull(holder), if_not_found);
    TNode<Uint32T> holder_bit_field3 = LoadMapBitField3(holder_map);
    GotoIf(IsSetWord32<Map::Bits3::MayHaveInterestingPropertiesBit>(
               holder_bit_field3),
           &interesting_properties);
    *var_holder = LoadMapPrototype(holder_map);
    *var_holder_map = LoadMap((*var_holder).value());
    Goto(&loop);
    BIND(&interesting_properties);
    {
      // Check flags for dictionary objects.
      GotoIf(IsClearWord32<Map::Bits3::IsDictionaryMapBit>(holder_bit_field3),
             &lookup);
      // JSProxy has dictionary properties but has to be handled in runtime.
      GotoIf(InstanceTypeEqual(LoadMapInstanceType(holder_map), JS_PROXY_TYPE),
             &lookup);
      TNode<Object> properties =
          LoadObjectField(holder, JSObject::kPropertiesOrHashOffset);
      CSA_DCHECK(this, TaggedIsNotSmi(properties));
      CSA_DCHECK(this, IsPropertyDictionary(CAST(properties)));
      // TODO(pthier): Support swiss dictionaries.
      if constexpr (!V8_ENABL
```