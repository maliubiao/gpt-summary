Response:
The user wants to understand the functionality of the `v8/src/diagnostics/objects-debug.cc` file. I need to analyze the provided C++ code and identify its purpose. The code contains a series of functions named `[ClassName]Verify`, which suggests it's involved in verifying the integrity of different V8 heap object types.

Here's a breakdown of the steps to generate the response:

1. **Identify the core functionality:** The presence of `[ClassName]Verify` functions strongly indicates that the file is responsible for validating the internal state and structure of various V8 heap objects. This is likely used for debugging and ensuring the consistency of the heap.

2. **List the verified classes:** Go through the code and list all the class names for which a `Verify` function is defined (e.g., `JSSharedStruct`, `JSAtomicsMutex`, `JSArrayBuffer`, etc.). This will provide a concrete list of what the file covers.

3. **Check for Torque usage:** The prompt mentions looking for `.tq` extensions. The code itself doesn't show any includes or direct usage of `.tq` files. However, many of the `Verify` functions call `TorqueGeneratedClassVerifiers::[ClassName]Verify`, indicating that the underlying structure and possibly some basic verifications are defined in Torque.

4. **Relate to JavaScript functionality (if applicable):**  For some of the verified classes, it's possible to relate them to JavaScript concepts. For example:
    - `JSSharedArray`: Directly related to JavaScript SharedArrayBuffer and typed arrays.
    - `JSPromise`:  Core JavaScript Promise object.
    - `JSWeakMap`/`JSWeakSet`/`JSWeakRef`:  JavaScript weak collections.
    - `JSRegExp`: JavaScript regular expressions.
    - `JSArrayBuffer`: JavaScript ArrayBuffer.
    - `JSProxy`: JavaScript Proxy object.
    - `Module`:  JavaScript modules.

5. **Provide JavaScript examples:** For the related JavaScript functionalities, provide simple code snippets to illustrate their use.

6. **Look for code logic/assertions:** The `Verify` functions are full of `CHECK` statements. These are assertions that verify internal invariants. While they don't represent complex logic, they show what conditions are expected to be true for a valid object. I can infer potential input/output by considering what the checks are validating. For instance, `JSSharedArrayVerify` checks if the elements are shared, implying the input is a `JSSharedArray` and the output is a verification status (no errors if the checks pass).

7. **Identify common programming errors (if applicable):**  By looking at the assertions, I can infer potential user errors. For example, the checks in `JSSharedArrayVerify` imply that a common error might be trying to store non-shared objects in a shared array.

8. **Summarize the functionality:**  Based on the analysis, provide a concise summary of the file's purpose.

**Self-Correction/Refinement during thought process:**

- Initially, I might focus too much on individual `Verify` functions. It's more important to see the overall pattern and purpose.
- I need to distinguish between direct C++ verification and verification delegated to Torque.
- When providing JavaScript examples, keep them simple and directly related to the verified class.
- For the code logic, focus on the *intent* of the checks rather than trying to reverse-engineer complex algorithms. The input is usually an instance of the class being verified, and the output is an indication of whether the object is in a valid state.
- For common errors, link them directly to the assertions in the code.
```cpp
void VerifyElementIsShared(Tagged<Object> element) {
  if (IsSmi(element)) return;
  if (IsHeapObject(element)) {
    CHECK(HeapLayout::InAnySharedSpace(element));
  }
  if (v8_flags.shared_string_table && IsInternalizedString(element)) {
    CHECK(HeapLayout::InReadOnlySpace(Cast<InternalizedString>(element)));
  } else if (v8_flags.shared_string_table && IsThinString(element) &&
             !String::VisitFlat(Cast<String>(element), [](String::Segment)) {
    return true;
  })) {
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
  Object::VerifyPointer(isolate, static_properties_
### 提示词
```
这是目录为v8/src/diagnostics/objects-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/objects-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
                         OffHeapObjectSlot end)
```