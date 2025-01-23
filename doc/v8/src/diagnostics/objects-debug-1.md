Response: The user wants me to summarize the functionality of a C++ source code file related to V8's debugging features, specifically the `objects-debug.cc` file. This is the second part of a two-part file.

My plan is to:
1. **Understand the context:** The file is in the `v8/src/diagnostics` directory, suggesting it's related to debugging and introspection of V8's internal objects.
2. **Analyze the code:** I need to go through the provided code snippets and identify the main functionalities. The presence of `Verify` methods for various V8 internal classes suggests this part of the file is focused on **heap object verification**.
3. **Summarize the functionality:**  Based on the analysis, I'll describe the primary purpose of this code.
4. **Identify JavaScript relationships:** I'll look for connections between the verified C++ objects and their corresponding JavaScript counterparts.
5. **Provide JavaScript examples:** For each identified relationship, I'll provide a simple JavaScript example to illustrate the connection.
这个C++源代码文件（`v8/src/diagnostics/objects-debug.cc`的第2部分）的主要功能是为V8引擎的各种内部对象提供**运行时的一致性检查和验证机制**。

具体来说，它包含了一系列以 `Verify` 结尾的函数，这些函数是针对不同类型的V8堆对象的验证器。这些验证器函数会在Debug模式下被调用，用于确保堆对象的内部状态满足预期的约束条件和不变量。这有助于在开发和调试V8引擎时尽早发现潜在的内存错误、数据结构损坏或逻辑错误。

这些验证函数会检查对象的各种属性，例如：

* **类型和标志位**: 验证对象是否属于预期的类型，以及其内部的标志位是否设置正确。
* **内存布局**:  验证对象是否位于预期的内存空间（例如，共享空间）。
* **属性和元素**: 验证对象的属性和元素是否符合预期类型，以及是否满足特定的约束（例如，共享的结构体只能指向共享的对象）。
* **关联关系**: 验证对象之间的关联关系是否正确（例如，WeakCell的前后指针）。
* **内部状态**: 验证对象的内部状态是否有效（例如，Promise的状态）。

**与JavaScript的功能的关系以及JavaScript示例:**

虽然这个C++文件本身不直接执行JavaScript代码，但它验证的V8内部对象是JavaScript运行时环境的基础。  这些C++对象在JavaScript引擎的执行过程中被创建和操作，因此该文件的功能间接地与所有JavaScript功能都有关系。  任何JavaScript代码的执行都会涉及到这些内部对象的创建、修改和交互。

以下是一些具体的JavaScript功能及其背后相关的C++对象和验证示例：

1. **共享对象 (Shared Objects):**

   * **C++对象:** `JSSharedStruct`, `JSSharedArray`, `JSAtomicsMutex`, `JSAtomicsCondition`
   * **JavaScript功能:**  `SharedArrayBuffer`, `Atomics` 等用于实现多线程和共享内存的特性。
   * **验证功能体现:** `VerifyElementIsShared` 函数确保共享数组或共享结构体中存储的元素本身也是可以跨线程共享的对象。
   * **JavaScript 示例:**
     ```javascript
     const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 2);
     const arr = new Int32Array(sab);
     arr[0] = 10;
     ```
     在V8内部，`sab` 对应一个 `JSSharedArrayBuffer` 对象，`arr` 的操作会涉及到对 `JSSharedArray` 对象的修改。 `JSSharedArrayVerify` 函数会确保 `JSSharedArray` 中的元素是共享的。

2. **弱引用和终结器 (Weak References and Finalizers):**

   * **C++对象:** `WeakCell`, `JSWeakRef`, `JSFinalizationRegistry`, `JSWeakMap`, `JSWeakSet`
   * **JavaScript功能:** `WeakRef`, `FinalizationRegistry` 等用于管理对象生命周期和避免内存泄漏的特性。
   * **验证功能体现:** `WeakCellVerify` 检查弱引用的目标对象是否可以被弱持有，以及链表的连接是否正确。 `JSFinalizationRegistryVerify` 检查活跃和已清除的弱引用链表。
   * **JavaScript 示例:**
     ```javascript
     let target = {};
     const weakRef = new WeakRef(target);
     const registry = new FinalizationRegistry(heldValue => {
       console.log('Object finalized:', heldValue);
     });
     registry.register(target, 'some value');
     target = null; // 让 target 可以被垃圾回收
     ```
     `weakRef` 对应一个 `JSWeakRef` 对象，`registry` 对应 `JSFinalizationRegistry` 对象。验证函数会确保这些对象的状态是正确的。

3. **迭代器 (Iterators):**

   * **C++对象:** `JSArrayIterator`, `JSStringIterator`, `JSIteratorMapHelper`, `JSIteratorFilterHelper`, 等
   * **JavaScript功能:** `for...of` 循环，`Array.prototype.values()`, `String.prototype[Symbol.iterator]()` 等。
   * **验证功能体现:**  `JSArrayIteratorVerify` 检查迭代器的索引是否在有效范围内。
   * **JavaScript 示例:**
     ```javascript
     const arr = [1, 2, 3];
     for (const value of arr) {
       console.log(value);
     }
     ```
     在 `for...of` 循环执行期间，V8内部会创建 `JSArrayIterator` 对象来遍历数组。 `JSArrayIteratorVerify` 会验证这个迭代器的状态。

4. **Promise:**

   * **C++对象:** `JSPromise`
   * **JavaScript功能:** `Promise` 对象，用于处理异步操作。
   * **验证功能体现:** `JSPromiseVerify` 检查Promise对象的状态（pending, fulfilled, rejected）以及相关的反应链表是否有效。
   * **JavaScript 示例:**
     ```javascript
     const promise = new Promise((resolve, reject) => {
       setTimeout(() => resolve('done'), 1000);
     });
     promise.then(result => console.log(result));
     ```
     `promise` 对应一个 `JSPromise` 对象。`JSPromiseVerify` 会确保其内部状态和反应链表在不同阶段是正确的。

5. **正则表达式 (Regular Expressions):**

   * **C++对象:** `JSRegExp`, `RegExpData`, `AtomRegExpData`, `IrRegExpData`
   * **JavaScript功能:** `RegExp` 对象，用于模式匹配。
   * **验证功能体现:** `JSRegExpVerify` 检查正则表达式的源码和标志，以及编译后的数据结构（bytecode 或原生代码）。
   * **JavaScript 示例:**
     ```javascript
     const regex = /ab+c/;
     const result = regex.test('abbbc');
     ```
     `regex` 对应一个 `JSRegExp` 对象，其内部的编译结果存储在 `RegExpData` 及其子类中。 验证函数会检查这些内部数据的有效性。

总而言之，这个C++文件的核心功能是提供一种机制，用于在V8引擎的开发和调试过程中，对各种关键的内部对象进行健全性检查，从而提高引擎的稳定性和可靠性。它验证的对象直接对应着JavaScript语言的各种特性和功能。

### 提示词
```
这是目录为v8/src/diagnostics/objects-debug.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
g(element)) {
    CHECK(v8_flags.shared_string_table);
    CHECK(HeapLayout::InWritableSharedSpace(Cast<ThinString>(element)));
  } else {
    CHECK(IsShared(element));
  }
}

}  // namespace

void JSSharedStruct::JSSharedStructVerify(Isolate* isolate) {
  CHECK(IsJSSharedStruct(*this));
  CHECK(HeapLayout::InWritableSharedSpace(*this));
  JSObjectVerify(isolate);
  CHECK(HasFastProperties());
  // Shared structs can only point to primitives or other shared HeapObjects,
  // even internally.
  Tagged<Map> struct_map = map();
  CHECK(HeapLayout::InAnySharedSpace(property_array()));
  Tagged<DescriptorArray> descriptors =
      struct_map->instance_descriptors(isolate);
  for (InternalIndex i : struct_map->IterateOwnDescriptors()) {
    PropertyDetails details = descriptors->GetDetails(i);
    CHECK_EQ(PropertyKind::kData, details.kind());

    if (JSSharedStruct::IsRegistryKeyDescriptor(isolate, struct_map, i)) {
      CHECK_EQ(PropertyLocation::kDescriptor, details.location());
      CHECK(IsInternalizedString(descriptors->GetStrongValue(i)));
    } else if (JSSharedStruct::IsElementsTemplateDescriptor(isolate, struct_map,
                                                            i)) {
      CHECK_EQ(PropertyLocation::kDescriptor, details.location());
      CHECK(IsNumberDictionary(descriptors->GetStrongValue(i)));
    } else {
      CHECK_EQ(PropertyLocation::kField, details.location());
      CHECK(details.representation().IsTagged());
      CHECK(!IsNumberDictionary(descriptors->GetStrongValue(i)));
      CHECK(!IsInternalizedString(descriptors->GetStrongValue(i)));
      FieldIndex field_index = FieldIndex::ForDetails(struct_map, details);
      VerifyElementIsShared(RawFastPropertyAt(field_index));
    }
  }
}

void JSAtomicsMutex::JSAtomicsMutexVerify(Isolate* isolate) {
  CHECK(IsJSAtomicsMutex(*this));
  CHECK(HeapLayout::InWritableSharedSpace(*this));
  JSObjectVerify(isolate);
}

void JSAtomicsCondition::JSAtomicsConditionVerify(Isolate* isolate) {
  CHECK(IsJSAtomicsCondition(*this));
  CHECK(HeapLayout::InAnySharedSpace(*this));
  JSObjectVerify(isolate);
}

void JSDisposableStackBase::JSDisposableStackBaseVerify(Isolate* isolate) {
  CHECK(IsJSDisposableStackBase(*this));
  JSObjectVerify(isolate);
  CHECK_EQ(length() % 3, 0);
  CHECK_GE(stack()->capacity(), length());
}

void JSSyncDisposableStack::JSSyncDisposableStackVerify(Isolate* isolate) {
  CHECK(IsJSSyncDisposableStack(*this));
  JSDisposableStackBase::JSDisposableStackBaseVerify(isolate);
}

void JSAsyncDisposableStack::JSAsyncDisposableStackVerify(Isolate* isolate) {
  CHECK(IsJSAsyncDisposableStack(*this));
  JSDisposableStackBase::JSDisposableStackBaseVerify(isolate);
}

void JSSharedArray::JSSharedArrayVerify(Isolate* isolate) {
  CHECK(IsJSSharedArray(*this));
  JSObjectVerify(isolate);
  CHECK(HasFastProperties());
  // Shared arrays can only point to primitives or other shared HeapObjects,
  // even internally.
  Tagged<FixedArray> storage = Cast<FixedArray>(elements());
  uint32_t length = storage->length();
  for (uint32_t j = 0; j < length; j++) {
    Tagged<Object> element_value = storage->get(j);
    VerifyElementIsShared(element_value);
  }
}

void JSIteratorMapHelper::JSIteratorMapHelperVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSIteratorMapHelperVerify(*this, isolate);
  CHECK(IsCallable(mapper()));
  CHECK_GE(Object::NumberValue(counter()), 0);
}

void JSIteratorFilterHelper::JSIteratorFilterHelperVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSIteratorFilterHelperVerify(*this, isolate);
  CHECK(IsCallable(predicate()));
  CHECK_GE(Object::NumberValue(counter()), 0);
}

void JSIteratorTakeHelper::JSIteratorTakeHelperVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSIteratorTakeHelperVerify(*this, isolate);
  CHECK_GE(Object::NumberValue(remaining()), 0);
}

void JSIteratorDropHelper::JSIteratorDropHelperVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSIteratorDropHelperVerify(*this, isolate);
  CHECK_GE(Object::NumberValue(remaining()), 0);
}

void JSIteratorFlatMapHelper::JSIteratorFlatMapHelperVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSIteratorFlatMapHelperVerify(*this, isolate);
  CHECK(IsCallable(mapper()));
  CHECK_GE(Object::NumberValue(counter()), 0);
}

void WeakCell::WeakCellVerify(Isolate* isolate) {
  CHECK(IsWeakCell(*this));

  CHECK(IsUndefined(target(), isolate) || Object::CanBeHeldWeakly(target()));

  CHECK(IsWeakCell(prev()) || IsUndefined(prev(), isolate));
  if (IsWeakCell(prev())) {
    CHECK_EQ(Cast<WeakCell>(prev())->next(), *this);
  }

  CHECK(IsWeakCell(next()) || IsUndefined(next(), isolate));
  if (IsWeakCell(next())) {
    CHECK_EQ(Cast<WeakCell>(next())->prev(), *this);
  }

  CHECK_IMPLIES(IsUndefined(unregister_token(), isolate),
                IsUndefined(key_list_prev(), isolate));
  CHECK_IMPLIES(IsUndefined(unregister_token(), isolate),
                IsUndefined(key_list_next(), isolate));

  CHECK(IsWeakCell(key_list_prev()) || IsUndefined(key_list_prev(), isolate));

  CHECK(IsWeakCell(key_list_next()) || IsUndefined(key_list_next(), isolate));

  CHECK(IsUndefined(finalization_registry(), isolate) ||
        IsJSFinalizationRegistry(finalization_registry()));
}

void JSWeakRef::JSWeakRefVerify(Isolate* isolate) {
  CHECK(IsJSWeakRef(*this));
  JSObjectVerify(isolate);
  CHECK(IsUndefined(target(), isolate) || Object::CanBeHeldWeakly(target()));
}

void JSFinalizationRegistry::JSFinalizationRegistryVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSFinalizationRegistryVerify(*this, isolate);
  if (IsWeakCell(active_cells())) {
    CHECK(IsUndefined(Cast<WeakCell>(active_cells())->prev(), isolate));
  }
  if (IsWeakCell(cleared_cells())) {
    CHECK(IsUndefined(Cast<WeakCell>(cleared_cells())->prev(), isolate));
  }
}

void JSWeakMap::JSWeakMapVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSWeakMapVerify(*this, isolate);
  CHECK(IsEphemeronHashTable(table()) || IsUndefined(table(), isolate));
}

void JSArrayIterator::JSArrayIteratorVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSArrayIteratorVerify(*this, isolate);

  CHECK_GE(Object::NumberValue(next_index()), 0);
  CHECK_LE(Object::NumberValue(next_index()), kMaxSafeInteger);

  if (IsJSTypedArray(iterated_object())) {
    // JSTypedArray::length is limited to Smi range.
    CHECK(IsSmi(next_index()));
    CHECK_LE(Object::NumberValue(next_index()), Smi::kMaxValue);
  } else if (IsJSArray(iterated_object())) {
    // JSArray::length is limited to Uint32 range.
    CHECK_LE(Object::NumberValue(next_index()), kMaxUInt32);
  }
}

void JSStringIterator::JSStringIteratorVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSStringIteratorVerify(*this, isolate);
  CHECK_GE(index(), 0);
  CHECK_LE(index(), String::kMaxLength);
}

void JSWeakSet::JSWeakSetVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSWeakSetVerify(*this, isolate);
  CHECK(IsEphemeronHashTable(table()) || IsUndefined(table(), isolate));
}

void CallableTask::CallableTaskVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::CallableTaskVerify(*this, isolate);
  CHECK(IsCallable(callable()));
}

void JSPromise::JSPromiseVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSPromiseVerify(*this, isolate);
  if (status() == Promise::kPending) {
    CHECK(IsSmi(reactions()) || IsPromiseReaction(reactions()));
  }
}

template <typename Derived>
void SmallOrderedHashTable<Derived>::SmallOrderedHashTableVerify(
    Isolate* isolate) {
  CHECK(IsSmallOrderedHashTable(*this));

  int capacity = Capacity();
  CHECK_GE(capacity, kMinCapacity);
  CHECK_LE(capacity, kMaxCapacity);

  for (int entry = 0; entry < NumberOfBuckets(); entry++) {
    int bucket = GetFirstEntry(entry);
    if (bucket == kNotFound) continue;
    CHECK_GE(bucket, 0);
    CHECK_LE(bucket, capacity);
  }

  for (int entry = 0; entry < NumberOfElements(); entry++) {
    int chain = GetNextEntry(entry);
    if (chain == kNotFound) continue;
    CHECK_GE(chain, 0);
    CHECK_LE(chain, capacity);
  }

  for (int entry = 0; entry < NumberOfElements(); entry++) {
    for (int offset = 0; offset < Derived::kEntrySize; offset++) {
      Tagged<Object> val = GetDataEntry(entry, offset);
      Object::VerifyPointer(isolate, val);
    }
  }

  for (int entry = NumberOfElements() + NumberOfDeletedElements();
       entry < Capacity(); entry++) {
    for (int offset = 0; offset < Derived::kEntrySize; offset++) {
      Tagged<Object> val = GetDataEntry(entry, offset);
      CHECK(IsTheHole(val, isolate));
    }
  }
}

void SmallOrderedHashMap::SmallOrderedHashMapVerify(Isolate* isolate) {
  CHECK(IsSmallOrderedHashMap(*this));
  SmallOrderedHashTable<SmallOrderedHashMap>::SmallOrderedHashTableVerify(
      isolate);
  for (int entry = NumberOfElements(); entry < NumberOfDeletedElements();
       entry++) {
    for (int offset = 0; offset < kEntrySize; offset++) {
      Tagged<Object> val = GetDataEntry(entry, offset);
      CHECK(IsTheHole(val, isolate));
    }
  }
}

void SmallOrderedHashSet::SmallOrderedHashSetVerify(Isolate* isolate) {
  CHECK(IsSmallOrderedHashSet(*this));
  SmallOrderedHashTable<SmallOrderedHashSet>::SmallOrderedHashTableVerify(
      isolate);
  for (int entry = NumberOfElements(); entry < NumberOfDeletedElements();
       entry++) {
    for (int offset = 0; offset < kEntrySize; offset++) {
      Tagged<Object> val = GetDataEntry(entry, offset);
      CHECK(IsTheHole(val, isolate));
    }
  }
}

void SmallOrderedNameDictionary::SmallOrderedNameDictionaryVerify(
    Isolate* isolate) {
  CHECK(IsSmallOrderedNameDictionary(*this));
  SmallOrderedHashTable<
      SmallOrderedNameDictionary>::SmallOrderedHashTableVerify(isolate);
  for (int entry = NumberOfElements(); entry < NumberOfDeletedElements();
       entry++) {
    for (int offset = 0; offset < kEntrySize; offset++) {
      Tagged<Object> val = GetDataEntry(entry, offset);
      CHECK(IsTheHole(val, isolate) ||
            (PropertyDetails::Empty().AsSmi() == Cast<Smi>(val)));
    }
  }
}

void SwissNameDictionary::SwissNameDictionaryVerify(Isolate* isolate) {
  this->SwissNameDictionaryVerify(isolate, false);
}

void SwissNameDictionary::SwissNameDictionaryVerify(Isolate* isolate,
                                                    bool slow_checks) {
  DisallowHeapAllocation no_gc;

  CHECK(IsValidCapacity(Capacity()));

  meta_table()->ByteArrayVerify(isolate);

  int seen_deleted = 0;
  int seen_present = 0;

  for (int i = 0; i < Capacity(); i++) {
    ctrl_t ctrl = GetCtrl(i);

    if (IsFull(ctrl) || slow_checks) {
      Tagged<Object> key = KeyAt(i);
      Tagged<Object> value = ValueAtRaw(i);

      if (IsFull(ctrl)) {
        ++seen_present;

        Tagged<Name> name = Cast<Name>(key);
        if (slow_checks) {
          CHECK_EQ(swiss_table::H2(name->hash()), ctrl);
        }

        CHECK(!IsTheHole(key));
        CHECK(!IsTheHole(value));
        name->NameVerify(isolate);
        Object::ObjectVerify(value, isolate);
      } else if (IsDeleted(ctrl)) {
        ++seen_deleted;
        CHECK(IsTheHole(key));
        CHECK(IsTheHole(value));
      } else if (IsEmpty(ctrl)) {
        CHECK(IsTheHole(key));
        CHECK(IsTheHole(value));
      } else {
        // Something unexpected. Note that we don't use kSentinel at the moment.
        UNREACHABLE();
      }
    }
  }

  CHECK_EQ(seen_present, NumberOfElements());
  if (slow_checks) {
    CHECK_EQ(seen_deleted, NumberOfDeletedElements());

    // Verify copy of first group at end (= after Capacity() slots) of control
    // table.
    for (int i = 0; i < std::min(static_cast<int>(Group::kWidth), Capacity());
         ++i) {
      CHECK_EQ(CtrlTable()[i], CtrlTable()[Capacity() + i]);
    }
    // If 2 * capacity is smaller than the capacity plus group width, the slots
    // after that must be empty.
    for (int i = 2 * Capacity(); i < Capacity() + kGroupWidth; ++i) {
      CHECK_EQ(Ctrl::kEmpty, CtrlTable()[i]);
    }

    for (int enum_index = 0; enum_index < UsedCapacity(); ++enum_index) {
      int entry = EntryForEnumerationIndex(enum_index);
      CHECK_LT(entry, Capacity());
      ctrl_t ctrl = GetCtrl(entry);

      // Enum table must not point to empty slots.
      CHECK(IsFull(ctrl) || IsDeleted(ctrl));
    }
  }
}

void JSRegExp::JSRegExpVerify(Isolate* isolate) {
  Tagged<Object> source = TaggedField<Object>::load(*this, kSourceOffset);
  Tagged<Object> flags = TaggedField<Object>::load(*this, kFlagsOffset);
  CHECK(IsString(source) || IsUndefined(source));
  CHECK(IsSmi(flags) || IsUndefined(flags));
  if (!has_data()) return;

  Tagged<RegExpData> data = this->data(isolate);
  switch (data->type_tag()) {
    case RegExpData::Type::ATOM:
      CHECK(Is<AtomRegExpData>(data));
      return;
    case RegExpData::Type::EXPERIMENTAL:
    case RegExpData::Type::IRREGEXP:
      CHECK(Is<IrRegExpData>(data));
      return;
  }
  UNREACHABLE();
}

void RegExpData::RegExpDataVerify(Isolate* isolate) {
  ExposedTrustedObjectVerify(isolate);
  CHECK(IsSmi(TaggedField<Object>::load(*this, kTypeTagOffset)));
  CHECK(IsString(source()));
  CHECK(IsSmi(TaggedField<Object>::load(*this, kFlagsOffset)));
}

void AtomRegExpData::AtomRegExpDataVerify(Isolate* isolate) {
  ExposedTrustedObjectVerify(isolate);
  RegExpDataVerify(isolate);
  CHECK(IsString(pattern()));
}

void IrRegExpData::IrRegExpDataVerify(Isolate* isolate) {
  ExposedTrustedObjectVerify(isolate);
  RegExpDataVerify(isolate);

  VerifyProtectedPointerField(isolate, kLatin1BytecodeOffset);
  VerifyProtectedPointerField(isolate, kUc16BytecodeOffset);

  CHECK_IMPLIES(!has_latin1_code(), !has_latin1_bytecode());
  CHECK_IMPLIES(!has_uc16_code(), !has_uc16_bytecode());

  CHECK_IMPLIES(has_latin1_code(), Is<Code>(latin1_code(isolate)));
  CHECK_IMPLIES(has_uc16_code(), Is<Code>(uc16_code(isolate)));
  CHECK_IMPLIES(has_latin1_bytecode(), Is<TrustedByteArray>(latin1_bytecode()));
  CHECK_IMPLIES(has_uc16_bytecode(), Is<TrustedByteArray>(uc16_bytecode()));

  CHECK_IMPLIES(
      IsSmi(capture_name_map()),
      Smi::ToInt(capture_name_map()) == JSRegExp::kUninitializedValue ||
          capture_name_map() == Smi::zero());
  CHECK_IMPLIES(!IsSmi(capture_name_map()), Is<FixedArray>(capture_name_map()));
  CHECK(IsSmi(TaggedField<Object>::load(*this, kMaxRegisterCountOffset)));
  CHECK(IsSmi(TaggedField<Object>::load(*this, kCaptureCountOffset)));
  CHECK(IsSmi(TaggedField<Object>::load(*this, kTicksUntilTierUpOffset)));
  CHECK(IsSmi(TaggedField<Object>::load(*this, kBacktrackLimitOffset)));

  switch (type_tag()) {
    case RegExpData::Type::EXPERIMENTAL: {
      if (has_latin1_code()) {
        CHECK_EQ(latin1_code(isolate)->builtin_id(),
                 Builtin::kRegExpExperimentalTrampoline);
        CHECK_EQ(latin1_code(isolate), uc16_code(isolate));
        CHECK(Is<TrustedByteArray>(latin1_bytecode()));
        CHECK_EQ(latin1_bytecode(), uc16_bytecode());
      } else {
        CHECK(!has_uc16_code());
        CHECK(!has_latin1_bytecode());
        CHECK(!has_uc16_bytecode());
      }

      CHECK_EQ(max_register_count(), JSRegExp::kUninitializedValue);
      CHECK_EQ(ticks_until_tier_up(), JSRegExp::kUninitializedValue);
      CHECK_EQ(backtrack_limit(), JSRegExp::kUninitializedValue);

      break;
    }
    case RegExpData::Type::IRREGEXP: {
      bool can_be_interpreted = RegExp::CanGenerateBytecode();
      CHECK_IMPLIES(has_latin1_bytecode(), can_be_interpreted);
      CHECK_IMPLIES(has_uc16_bytecode(), can_be_interpreted);

      static_assert(JSRegExp::kUninitializedValue == -1);
      CHECK_GE(max_register_count(), JSRegExp::kUninitializedValue);
      CHECK_GE(capture_count(), 0);
      if (v8_flags.regexp_tier_up) {
        // With tier-up enabled, ticks_until_tier_up should actually be >= 0.
        // However FlagScopes in unittests can modify the flag and verification
        // on Isolate deinitialization will fail.
        CHECK_GE(ticks_until_tier_up(), JSRegExp::kUninitializedValue);
        CHECK_LE(ticks_until_tier_up(), v8_flags.regexp_tier_up_ticks);
      } else {
        CHECK_EQ(ticks_until_tier_up(), JSRegExp::kUninitializedValue);
      }
      CHECK_GE(backtrack_limit(), 0);

      break;
    }
    default:
      UNREACHABLE();
  }
}

void RegExpDataWrapper::RegExpDataWrapperVerify(Isolate* isolate) {
  if (!this->has_data()) return;
  auto data = this->data(isolate);
  Object::VerifyPointer(isolate, data);
  CHECK_EQ(data->wrapper(), *this);
}

void JSProxy::JSProxyVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSProxyVerify(*this, isolate);
  CHECK(IsJSFunction(map()->GetConstructor()));
  if (!IsRevoked()) {
    CHECK_EQ(IsCallable(target()), map()->is_callable());
    CHECK_EQ(IsConstructor(target()), map()->is_constructor());
  }
  CHECK(IsNull(map()->prototype(), isolate));
  // There should be no properties on a Proxy.
  CHECK_EQ(0, map()->NumberOfOwnDescriptors());
}

void JSArrayBuffer::JSArrayBufferVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSArrayBufferVerify(*this, isolate);
  if (FIELD_SIZE(kOptionalPaddingOffset) != 0) {
    CHECK_EQ(4, FIELD_SIZE(kOptionalPaddingOffset));
    CHECK_EQ(0,
             *reinterpret_cast<uint32_t*>(address() + kOptionalPaddingOffset));
  }
}

void JSArrayBufferView::JSArrayBufferViewVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSArrayBufferViewVerify(*this, isolate);
  CHECK_LE(byte_length(), JSArrayBuffer::kMaxByteLength);
  CHECK_LE(byte_offset(), JSArrayBuffer::kMaxByteLength);
}

void JSTypedArray::JSTypedArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSTypedArrayVerify(*this, isolate);
  CHECK_LE(GetLength(), JSTypedArray::kMaxByteLength / element_size());
}

void JSDataView::JSDataViewVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSDataViewVerify(*this, isolate);
  CHECK(!IsVariableLength());
  if (!WasDetached()) {
    CHECK_EQ(reinterpret_cast<uint8_t*>(
                 Cast<JSArrayBuffer>(buffer())->backing_store()) +
                 byte_offset(),
             data_pointer());
  }
}

void JSRabGsabDataView::JSRabGsabDataViewVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSRabGsabDataViewVerify(*this, isolate);
  CHECK(IsVariableLength());
  if (!WasDetached()) {
    CHECK_EQ(reinterpret_cast<uint8_t*>(
                 Cast<JSArrayBuffer>(buffer())->backing_store()) +
                 byte_offset(),
             data_pointer());
  }
}

void AsyncGeneratorRequest::AsyncGeneratorRequestVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::AsyncGeneratorRequestVerify(*this, isolate);
  CHECK_GE(resume_mode(), JSGeneratorObject::kNext);
  CHECK_LE(resume_mode(), JSGeneratorObject::kThrow);
}

void BigIntBase::BigIntBaseVerify(Isolate* isolate) {
  CHECK_GE(length(), 0);
  CHECK_IMPLIES(is_zero(), !sign());  // There is no -0n.
}

void SourceTextModuleInfoEntry::SourceTextModuleInfoEntryVerify(
    Isolate* isolate) {
  TorqueGeneratedClassVerifiers::SourceTextModuleInfoEntryVerify(*this,
                                                                 isolate);
  CHECK_IMPLIES(IsString(import_name()), module_request() >= 0);
  CHECK_IMPLIES(IsString(export_name()) && IsString(import_name()),
                IsUndefined(local_name(), isolate));
}

void Module::ModuleVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::ModuleVerify(*this, isolate);

  CHECK_EQ(status() == Module::kErrored, !IsTheHole(exception(), isolate));

  CHECK(IsUndefined(module_namespace(), isolate) ||
        IsJSModuleNamespace(module_namespace()));
  if (IsJSModuleNamespace(module_namespace())) {
    CHECK_LE(Module::kLinking, status());
    CHECK_EQ(Cast<JSModuleNamespace>(module_namespace())->module(), *this);
  }

  if (!(status() == kErrored || status() == kEvaluating ||
        status() == kEvaluatingAsync || status() == kEvaluated)) {
    CHECK(IsUndefined(top_level_capability()));
  }

  CHECK_NE(hash(), 0);
}

void ModuleRequest::ModuleRequestVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::ModuleRequestVerify(*this, isolate);
  CHECK_EQ(0,
           import_attributes()->length() % ModuleRequest::kAttributeEntrySize);

  for (int i = 0; i < import_attributes()->length();
       i += ModuleRequest::kAttributeEntrySize) {
    CHECK(IsString(import_attributes()->get(i)));      // Attribute key
    CHECK(IsString(import_attributes()->get(i + 1)));  // Attribute value
    CHECK(IsSmi(import_attributes()->get(i + 2)));     // Attribute location
  }
}

void SourceTextModule::SourceTextModuleVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::SourceTextModuleVerify(*this, isolate);

  if (status() == kErrored) {
    CHECK(IsSharedFunctionInfo(code()));
  } else if (status() == kEvaluating || status() == kEvaluatingAsync ||
             status() == kEvaluated) {
    CHECK(IsJSGeneratorObject(code()));
  } else {
    if (status() == kLinked) {
      CHECK(IsJSGeneratorObject(code()));
    } else if (status() == kLinking) {
      CHECK(IsJSFunction(code()));
    } else if (status() == kPreLinking) {
      CHECK(IsSharedFunctionInfo(code()));
    } else if (status() == kUnlinked) {
      CHECK(IsSharedFunctionInfo(code()));
    }
    CHECK(!AsyncParentModuleCount());
    CHECK(!pending_async_dependencies());
    CHECK(!HasAsyncEvaluationOrdinal());
  }

  CHECK_EQ(requested_modules()->length(), info()->module_requests()->length());
}

void SyntheticModule::SyntheticModuleVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::SyntheticModuleVerify(*this, isolate);

  for (int i = 0; i < export_names()->length(); i++) {
    CHECK(IsString(export_names()->get(i)));
  }
}

void PrototypeInfo::PrototypeInfoVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::PrototypeInfoVerify(*this, isolate);
  if (IsWeakArrayList(prototype_users())) {
    PrototypeUsers::Verify(Cast<WeakArrayList>(prototype_users()));
  } else {
    CHECK(IsSmi(prototype_users()));
  }
  Tagged<HeapObject> derived = derived_maps(isolate);
  if (!IsUndefined(derived)) {
    auto derived_list = Cast<WeakArrayList>(derived);
    CHECK_GT(derived_list->length(), 0);
    for (int i = 0; i < derived_list->length(); ++i) {
      derived_list->Get(i).IsWeakOrCleared();
    }
  }
}

void PrototypeUsers::Verify(Tagged<WeakArrayList> array) {
  if (array->length() == 0) {
    // Allow empty & uninitialized lists.
    return;
  }
  // Verify empty slot chain.
  int empty_slot = Smi::ToInt(empty_slot_index(array));
  int empty_slots_count = 0;
  while (empty_slot != kNoEmptySlotsMarker) {
    CHECK_GT(empty_slot, 0);
    CHECK_LT(empty_slot, array->length());
    empty_slot = array->Get(empty_slot).ToSmi().value();
    ++empty_slots_count;
  }

  // Verify that all elements are either weak pointers or SMIs marking empty
  // slots.
  int weak_maps_count = 0;
  for (int i = kFirstIndex; i < array->length(); ++i) {
    Tagged<HeapObject> heap_object;
    Tagged<MaybeObject> object = array->Get(i);
    if ((object.GetHeapObjectIfWeak(&heap_object) && IsMap(heap_object)) ||
        object.IsCleared()) {
      ++weak_maps_count;
    } else {
      CHECK(IsSmi(object));
    }
  }

  CHECK_EQ(weak_maps_count + empty_slots_count + 1, array->length());
}

void EnumCache::EnumCacheVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::EnumCacheVerify(*this, isolate);
  Heap* heap = isolate->heap();
  if (*this == ReadOnlyRoots(heap).empty_enum_cache()) {
    CHECK_EQ(ReadOnlyRoots(heap).empty_fixed_array(), keys());
    CHECK_EQ(ReadOnlyRoots(heap).empty_fixed_array(), indices());
  }
}

void ObjectBoilerplateDescription::ObjectBoilerplateDescriptionVerify(
    Isolate* isolate) {
  CHECK(IsSmi(length_.load()));
  CHECK(IsSmi(backing_store_size_.load()));
  CHECK(IsSmi(flags_.load()));
  // The keys of the boilerplate should not be thin strings. The values can be.
  for (int i = 0; i < boilerplate_properties_count(); ++i) {
    CHECK(!IsThinString(name(i), isolate));
  }
}

void ClassBoilerplate::ClassBoilerplateVerify(Isolate* isolate) {
  CHECK(IsSmi(TaggedField<Object>::load(*this, kArgumentsCountOffset)));
  Object::VerifyPointer(isolate, static_properties_template());
  Object::VerifyPointer(isolate, static_elements_template());
  Object::VerifyPointer(isolate, static_computed_properties());
  CHECK(IsFixedArray(static_computed_properties()));
  Object::VerifyPointer(isolate, instance_properties_template());
  Object::VerifyPointer(isolate, instance_elements_template());
  Object::VerifyPointer(isolate, instance_computed_properties());
  CHECK(IsFixedArray(instance_computed_properties()));
}

void RegExpBoilerplateDescription::RegExpBoilerplateDescriptionVerify(
    Isolate* isolate) {
  {
    auto o = data(isolate);
    Object::VerifyPointer(isolate, o);
    CHECK(IsRegExpData(o));
  }
  {
    auto o = source();
    Object::VerifyPointer(isolate, o);
    CHECK(IsString(o));
  }
  CHECK(IsSmi(TaggedField<Object>::load(*this, kFlagsOffset)));
}

#if V8_ENABLE_WEBASSEMBLY

void WasmTrustedInstanceData::WasmTrustedInstanceDataVerify(Isolate* isolate) {
  // Check all tagged fields.
  for (uint16_t offset : kTaggedFieldOffsets) {
    VerifyObjectField(isolate, offset);
  }

  // Check all protected fields.
  for (uint16_t offset : kProtectedFieldOffsets) {
    VerifyProtectedPointerField(isolate, offset);
  }

  int num_dispatch_tables = dispatch_tables()->length();
  for (int i = 0; i < num_dispatch_tables; ++i) {
    Tagged<Object> table = dispatch_tables()->get(i);
    if (table == Smi::zero()) continue;
    CHECK(IsWasmDispatchTable(table));
    if (i == 0) CHECK_EQ(table, dispatch_table0());
  }
  if (num_dispatch_tables == 0) CHECK_EQ(0, dispatch_table0()->length());
}

void WasmDispatchTable::WasmDispatchTableVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);

  int len = length();
  CHECK_LE(len, capacity());
  for (int i = 0; i < len; ++i) {
    Tagged<Object> arg = implicit_arg(i);
    Object::VerifyPointer(isolate, arg);
    CHECK(IsWasmTrustedInstanceData(arg) || IsWasmImportData(arg) ||
          arg == Smi::zero());
    if (!v8_flags.wasm_jitless) {
      // call_target always null with the interpreter.
      CHECK_EQ(arg == Smi::zero(), target(i) == wasm::kInvalidWasmCodePointer);
    }
  }
}

void WasmValueObject::WasmValueObjectVerify(Isolate* isolate) {
  JSObjectVerify(isolate);
  CHECK(IsWasmValueObject(*this));
}

void WasmExceptionPackage::WasmExceptionPackageVerify(Isolate* isolate) {
  JSObjectVerify(isolate);
  CHECK(IsWasmExceptionPackage(*this));
}

void WasmExportedFunctionData::WasmExportedFunctionDataVerify(
    Isolate* isolate) {
  TorqueGeneratedClassVerifiers::WasmExportedFunctionDataVerify(*this, isolate);
  Tagged<Code> wrapper = wrapper_code(isolate);
  CHECK(
      wrapper->kind() == CodeKind::JS_TO_WASM_FUNCTION ||
      wrapper->kind() == CodeKind::C_WASM_ENTRY ||
      (wrapper->is_builtin() &&
       (wrapper->builtin_id() == Builtin::kJSToWasmWrapper ||
#if V8_ENABLE_DRUMBRAKE
        wrapper->builtin_id() == Builtin::kGenericJSToWasmInterpreterWrapper ||
#endif  // V8_ENABLE_DRUMBRAKE
        wrapper->builtin_id() == Builtin::kWasmPromising ||
        wrapper->builtin_id() == Builtin::kWasmStressSwitch)));
}

#endif  // V8_ENABLE_WEBASSEMBLY

void DataHandler::DataHandlerVerify(Isolate* isolate) {
  // Don't call TorqueGeneratedClassVerifiers::DataHandlerVerify because the
  // Torque definition of this class includes all of the optional fields.

  // This assertion exists to encourage updating this verification function if
  // new fields are added in the Torque class layout definition.
  static_assert(DataHandler::kHeaderSize == 6 * kTaggedSize);

  StructVerify(isolate);
  CHECK(IsDataHandler(*this));
  Object::VerifyPointer(isolate, smi_handler(isolate));
  CHECK_IMPLIES(!IsSmi(smi_handler()),
                IsStoreHandler(*this) && IsCode(smi_handler()));
  Object::VerifyPointer(isolate, validity_cell(isolate));
  CHECK(IsSmi(validity_cell()) || IsCell(validity_cell()));
  int data_count = data_field_count();
  if (data_count >= 1) {
    VerifyMaybeObjectField(isolate, kData1Offset);
  }
  if (data_count >= 2) {
    VerifyMaybeObjectField(isolate, kData2Offset);
  }
  if (data_count >= 3) {
    VerifyMaybeObjectField(isolate, kData3Offset);
  }
}

void LoadHandler::LoadHandlerVerify(Isolate* isolate) {
  DataHandler::DataHandlerVerify(isolate);
  // TODO(ishell): check handler integrity
}

void StoreHandler::StoreHandlerVerify(Isolate* isolate) {
  DataHandler::DataHandlerVerify(isolate);
  // TODO(ishell): check handler integrity
}

void AllocationSite::AllocationSiteVerify(Isolate* isolate) {
  CHECK(IsAllocationSite(*this));
  CHECK(IsDependentCode(dependent_code()));
  CHECK(IsSmi(transition_info_or_boilerplate()) ||
        IsJSObject(transition_info_or_boilerplate()));
  CHECK(IsAllocationSite(nested_site()) || nested_site() == Smi::zero());
}

void Script::ScriptVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::ScriptVerify(*this, isolate);
#if V8_ENABLE_WEBASSEMBLY
  if (type() == Script::Type::kWasm) {
    CHECK_EQ(line_ends(), ReadOnlyRoots(isolate).empty_fixed_array());
  } else {
    CHECK(CanHaveLineEnds());
  }
#else   // V8_ENABLE_WEBASSEMBLY
  CHECK(CanHaveLineEnds());
#endif  // V8_ENABLE_WEBASSEMBLY
  for (int i = 0; i < infos()->length(); ++i) {
    Tagged<MaybeObject> maybe_object = infos()->get(i);
    Tagged<HeapObject> heap_object;
    CHECK(!maybe_object.GetHeapObjectIfWeak(isolate, &heap_object) ||
          (maybe_object.GetHeapObjectIfStrong(&heap_object) &&
           IsUndefined(heap_object, isolate)) ||
          Is<SharedFunctionInfo>(heap_object) || Is<ScopeInfo>(heap_object));
  }
}

void NormalizedMapCache::NormalizedMapCacheVerify(Isolate* isolate) {
  Cast<WeakFixedArray>(this)->WeakFixedArrayVerify(isolate);
  if (v8_flags.enable_slow_asserts) {
    for (int i = 0; i < length(); i++) {
      Tagged<MaybeObject> e = WeakFixedArray::get(i);
      Tagged<HeapObject> heap_object;
      if (e.GetHeapObjectIfWeak(&heap_object)) {
        Cast<Map>(heap_object)->DictionaryMapVerify(isolate);
      } else {
        CHECK(e.IsCleared() || (e.GetHeapObjectIfStrong(&heap_object) &&
                                IsUndefined(heap_object, isolate)));
      }
    }
  }
}

void PreparseData::PreparseDataVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::PreparseDataVerify(*this, isolate);
  CHECK_LE(0, data_length());
  CHECK_LE(0, children_length());

  for (int i = 0; i < children_length(); ++i) {
    Tagged<Object> child = get_child_raw(i);
    CHECK(IsNull(child) || IsPreparseData(child));
    Object::VerifyPointer(isolate, child);
  }
}

void CallSiteInfo::CallSiteInfoVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::CallSiteInfoVerify(*this, isolate);
#if V8_ENABLE_WEBASSEMBLY
  CHECK_IMPLIES(IsAsmJsWasm(), IsWasm());
  CHECK_IMPLIES(IsWasm(), IsWasmInstanceObject(receiver_or_instance()));
  CHECK_IMPLIES(IsWasm() || IsBuiltin(), IsSmi(function()));
  CHECK_IMPLIES(!IsWasm() && !IsBuiltin(), IsJSFunction(function()));
  CHECK_IMPLIES(IsAsync(), !IsWasm());
  CHECK_IMPLIES(IsConstructor(), !IsWasm());
#endif  // V8_ENABLE_WEBASSEMBLY
}

void FunctionTemplateRareData::FunctionTemplateRareDataVerify(
    Isolate* isolate) {
  CHECK(IsFixedArray(c_function_overloads()) ||
        IsUndefined(c_function_overloads(), isolate));
}

void StackFrameInfo::StackFrameInfoVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::StackFrameInfoVerify(*this, isolate);
}

void StackTraceInfo::StackTraceInfoVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::StackTraceInfoVerify(*this, isolate);
}

void ErrorStackData::ErrorStackDataVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::ErrorStackDataVerify(*this, isolate);
}

void SloppyArgumentsElements::SloppyArgumentsElementsVerify(Isolate* isolate) {
  CHECK(IsSmi(length_.load()));
  {
    auto o = context();
    Object::VerifyPointer(isolate, o);
    CHECK(IsContext(o));
  }
  {
    auto o = arguments();
    Object::VerifyPointer(isolate, o);
    CHECK(IsFixedArray(o));
  }
  for (int i = 0; i < length(); ++i) {
    auto o = mapped_entries(i, kRelaxedLoad);
    CHECK(IsSmi(o) || IsTheHole(o));
  }
}

// Helper class for verifying the string table.
class StringTableVerifier : public RootVisitor {
 public:
  explicit StringTableVerifier(Isolate* isolate) : isolate_(isolate) {}

  void VisitRootPointers(Root root, const char* description,
                         FullObjectSlot start, FullObjectSlot end) override {
    UNREACHABLE();
  }
  void VisitRootPointers(Root root, const char* description,
                         OffHeapObjectSlot start,
                         OffHeapObjectSlot end) override {
    // Visit all HeapObject pointers in [start, end).
    for (OffHeapObjectSlot p = start; p < end; ++p) {
      Tagged<Object> o = p.load(isolate_);
      CHECK(!HasWeakHeapObjectTag(o));
      if (IsHeapObject(o)) {
        Tagged<HeapObject> object = Cast<HeapObject>(o);
        // Check that the string is actually internalized.
        CHECK(IsInternalizedString(object));
      }
    }
  }

 private:
  Isolate* isolate_;
};

void StringTable::VerifyIfOwnedBy(Isolate* isolate) {
  CHECK_EQ(isolate->string_table(), this);
  if (!isolate->OwnsStringTables()) return;
  StringTableVerifier verifier(isolate);
  IterateElements(&verifier);
}

#endif  // VERIFY_HEAP

#ifdef DEBUG

void JSObject::IncrementSpillStatistics(Isolate* isolate,
                                        SpillInformation* info) {
  info->number_of_objects_++;
  // Named properties
  if (HasFastProperties()) {
    info->number_of_objects_with_fast_properties_++;
    info->number_of_fast_used_fields_ += map()->NextFreePropertyIndex();
    info->number_of_fast_unused_fields_ += map()->UnusedPropertyFields();
  } else if (IsJSGlobalObject(*this)) {
    Tagged<GlobalDictionary> dict =
        Cast<JSGlobalObject>(*this)->global_dictionary(kAcquireLoad);
    info->number_of_slow_used_properties_ += dict->NumberOfElements();
    info->number_of_slow_unused_properties_ +=
        dict->Capacity() - dict->NumberOfElements();
  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    Tagged<SwissNameDictionary> dict = property_dictionary_swiss();
    info->number_of_slow_used_properties_ += dict->NumberOfElements();
    info->number_of_slow_unused_properties_ +=
        dict->Capacity() - dict->NumberOfElements();
  } else {
    Tagged<NameDictionary> dict = property_dictionary();
    info->number_of_slow_used_properties_ += dict->NumberOfElements();
    info->number_of_slow_unused_properties_ +=
        dict->Capacity() - dict->NumberOfElements();
  }
  // Indexed properties
  switch (GetElementsKind()) {
    case HOLEY_SMI_ELEMENTS:
    case PACKED_SMI_ELEMENTS:
    case HOLEY_DOUBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS:
    case HOLEY_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS: {
      info->number_of_objects_with_fast_elements_++;
      int holes = 0;
      Tagged<FixedArray> e = Cast<FixedArray>(elements());
      int len = e->length();
      for (int i = 0; i < len; i++) {
        if (IsTheHole(e->get(i), isolate)) holes++;
      }
      info->number_of_fast_used_elements_ += len - holes;
      info->number_of_fast_unused_elements_ += holes;
      break;
    }

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      {
        info->number_of_objects_with_fast_elements_++;
        Tagged<FixedArrayBase> e = Cast<FixedArrayBase>(elements());
        info->number_of_fast_used_elements_ += e->length();
        break;
      }
    case DICTIONARY_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS: {
      Tagged<NumberDictionary> dict = element_dictionary();
      info->number_of_slow_used_elements_ += dict->NumberOfElements();
      info->number_of_slow_unused_elements_ +=
          dict->Capacity() - dict->NumberOfElements();
      break;
    }
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
    case WASM_ARRAY_ELEMENTS:
    case NO_ELEMENTS:
      break;
  }
}

void JSObject::SpillInformation::Clear() {
  number_of_objects_ = 0;
  number_of_objects_with_fast_properties_ = 0;
  number_of_objects_with_fast_elements_ = 0;
  number_of_fast_used_fields_ = 0;
  number_of_fast_unused_fields_ = 0;
  number_of_slow_used_properties_ = 0;
  number_of_slow_unused_properties_ = 0;
  number_of_fast_used_elements_ = 0;
  number_of_fast_unused_elements_ = 0;
  number_of_slow_used_elements_ = 0;
  number_of_slow_unused_elements_ = 0;
}

void JSObject::SpillInformation::Print() {
  PrintF("\n  JSObject Spill Statistics (#%d):\n", number_of_objects_);

  PrintF("    - fast properties (#%d): %d (used) %d (unused)\n",
         number_of_objects_with_fast_properties_, number_of_fast_used_fields_,
         number_of_fast_unused_fields_);

  PrintF("    - slow properties (#%d): %d (used) %d (unused)\n",
         number_of_objects_ - number_of_objects_with_fast_properties_,
         number_of_slow_used_properties_, number_of_slow_unused_properties_);

  PrintF("    - fast elements (#%d): %d (used) %d (unused)\n",
         number_of_objects_with_fast_elements_, number_of_fast_used_elements_,
         number_of_fast_unused_elements_);

  PrintF("    - slow elements (#%d): %d (used) %d (unused)\n",
         number_of_objects_ - number_of_objects_with_fast_elements_,
         number_of_slow_used_elements_, number_of_slow_unused_elements_);

  PrintF("\n");
}

bool DescriptorArray::IsSortedNoDuplicates() {
  Tagged<Name> current_key;
  uint32_t current = 0;
  for (int i = 0; i < number_of_descriptors(); i++) {
    Tagged<Name> key = GetSortedKey(i);
    uint32_t hash;
    const bool has_hash = key->TryGetHash(&hash);
    CHECK(has_hash);
    if (key == current_key) {
      Print(*this);
      return false;
    }
    current_key = key;
    if (hash < current) {
      Print(*this);
      return false;
    }
    current = hash;
  }
  return true;
}

bool TransitionArray::IsSortedNoDuplicates() {
  Tagged<Name> prev_key;
  PropertyKind prev_kind = PropertyKind::kData;
  PropertyAttributes prev_attributes = NONE;
  uint32_t prev_hash = 0;

  for (int i = 0; i < number_of_transitions(); i++) {
    Tagged<Name> key = GetKey(i);
    uint32_t hash;
    const bool has_hash = key->TryGetHash(&hash);
    CHECK(has_hash);
    PropertyKind kind = PropertyKind::kData;
    PropertyAttributes attributes = NONE;
    if (!TransitionsAccessor::IsSpecialTransition(key->GetReadOnlyRoots(),
                                                  key)) {
      Tagged<Map> target = GetTarget(i);
      PropertyDetails details =
          TransitionsAccessor::GetTargetDetails(key, target);
      kind = details.kind();
      attributes = details.attributes();
    } else {
      // Duplicate entries are not allowed for non-property transitions.
      DCHECK_NE(prev_key, key);
    }

    int cmp = CompareKeys(prev_key, prev_hash, prev_kind, prev_attributes, key,
                          hash, kind, attributes);
    if (cmp >= 0) {
      Print(this);
      return false;
    }
    prev_key = key;
    prev_hash = hash;
    prev_attributes = attributes;
    prev_kind = kind;
  }
  return true;
}

bool TransitionsAccessor::IsSortedNoDuplicates() {
  // Simple and non-existent transitions are always sorted.
  if (encoding() != kFullTransitionArray) return true;
  return transitions()->IsSortedNoDuplicates();
}

static bool CheckOneBackPointer(Tagged<Map> current_map, Tagged<Map> target) {
  return target->GetBackPointer() == current_map;
}

bool TransitionsAccessor::IsConsistentWithBackPointers() {
  DisallowGarbageCollection no_gc;
  bool success = true;
  ReadOnlyRoots roots(isolate_);
  DCHECK_IMPLIES(map_->IsInobjectSlackTrackingInProgress(),
                 !HasSideStepTransitions());
  auto CheckTarget =
      [&](Tagged<Map> target) {
#ifdef DEBUG
        if (!map_->is_deprecated() && !target->is_deprecated()) {
          DCHECK_EQ(map_->IsInobjectSlackTrackingInProgress(),
                    target->IsInobjectSlackTrackingInProgress());
          // Check prototype transitions are first.
          DCHECK_IMPLIES(map_->prototype() != target->prototype(),
                         IsUndefined(map_->GetBackPointer()));
        }
        DCHECK_EQ(target->map(), map_->map());
#endif  // DEBUG
        if (!CheckOneBackPointer(map_, target)) {
          success = false;
        }
      };
  ForEachTransition(
      &no_gc, [&](Tagged<Map> target) { CheckTarget(target); },
      [&](Tagged<Map> proto_target) {
        if (v8_flags.move_prototype_transitions_first) {
          CheckTarget(proto_target);
        }
      },
      [&](Tagged<Object> side_step) {
        if (!side_step.IsSmi()) {
          DCHECK_EQ(Cast<Map>(side_step)->map(), map_->map());
          DCHECK(!Cast<Map>(side_step)->IsInobjectSlackTrackingInProgress());
          DCHECK_EQ(
              Cast<Map>(side_step)->GetInObjectProperties() -
                  Cast<Map>(side_step)->UnusedInObjectProperties(),
              map_->GetInObjectProperties() - map_->UnusedInObjectProperties());
        }
      });
  return success;
}

#undef USE_TORQUE_VERIFIER

#endif  // DEBUG

}  // namespace internal
}  // namespace v8
```