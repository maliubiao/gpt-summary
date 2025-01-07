Response:
The user wants me to analyze a C++ file from the V8 project (`v8/src/diagnostics/objects-debug.cc`). I need to:

1. **Identify the file's purpose:**  Based on the content, it seems to be related to object verification within V8's debugging/diagnostic framework.
2. **Check for Torque:**  Determine if the file is a Torque source (ends with `.tq`). This file ends with `.cc`, so it's not Torque.
3. **Relate to JavaScript:** If the code is related to JavaScript functionality, provide JavaScript examples. The code deals with internal V8 object structures that directly correspond to JavaScript concepts.
4. **Infer logic and provide examples:**  If there's logic involved, give hypothetical inputs and outputs. The code primarily contains verification logic, which doesn't transform inputs into outputs in the typical sense. The "input" is the object being verified, and the "output" is a pass/fail signal (though not explicitly returned, failures would likely trigger assertions).
5. **Highlight common programming errors:**  Point out user programming errors that could lead to the verification failures.
6. **Summarize functionality:**  Provide a concise summary of the file's purpose, as this is part 2 of a 4-part analysis.

**Overall Strategy:**

- Analyze each `Verify` function to understand the invariants it checks for a specific V8 object type.
- Connect these invariants to JavaScript concepts where applicable.
- Consider how incorrect JavaScript usage could violate these invariants.
- Synthesize the information into a functional summary.
这是 `v8/src/diagnostics/objects-debug.cc` 的第二部分代码，它主要定义了各种 V8 堆对象的验证函数。这些函数在调试和测试 V8 引擎时用于检查对象的内部状态是否有效和一致。

**功能归纳:**

这部分代码延续了第一部分的功能，继续为更多的 V8 内部对象类型提供了 `Verify` 方法。这些 `Verify` 方法的主要功能是：

* **一致性检查:**  检查对象的内部字段是否符合预期的关系和约束。例如，`ArrayListVerify` 检查 `length` 是否小于等于 `capacity`，`PropertyArrayVerify` 检查长度是否非负。
* **类型检查:**  验证对象字段是否指向预期类型的对象。例如，`ContextVerify` 检查上下文槽中的数据是否为 `FixedArray`。
* **状态检查:**  检查对象的状态是否有效。例如，`FixedDoubleArrayVerify` 检查双精度浮点数是否不是特定的 NaN 值。
* **与根对象的比较:**  检查某些特殊的对象是否与 V8 堆中的预定义根对象一致，例如空数组、空属性数组等。
* **与其他对象的关联性检查:** 验证对象之间的引用关系是否正确。例如，`TransitionArrayVerify` 检查所有 transition 条目是否具有相同的 owner。
* **特定对象类型的约束检查:** 针对特定对象类型进行更深入的验证，例如 `JSArgumentsObjectVerify` 检查 arguments 对象的元素类型和上下文映射关系。
* **性能优化相关的检查:** 例如，`JSFunctionVerify` 中涉及到 dispatch table 的验证，这与 V8 的性能优化机制有关。

**与 JavaScript 的关系和举例:**

这些验证函数虽然是 C++ 代码，但它们直接关系到 JavaScript 的运行时行为。V8 引擎在执行 JavaScript 代码时会创建和操作这些内部对象。如果这些对象的状态不正确，可能会导致 JavaScript 代码运行错误或产生意外的结果。

例如，`JSArrayVerify` 检查 `JSArray` 对象的长度和元素存储是否一致。在 JavaScript 中，如果你修改数组的长度，V8 内部会调整其元素存储。如果这个过程出现错误，`JSArrayVerify` 可能会检测到不一致。

```javascript
// JavaScript 示例，可能导致内部 JSArray 对象状态异常的情况
const arr = [1, 2, 3];
// 直接操作数组的内部属性（JavaScript 中不允许这样做，这里只是为了说明原理）
// 假设 V8 内部的元素存储对象被错误地修改，导致长度不一致

// 实际的 JavaScript 代码不会直接暴露这些内部属性，
// 但某些极端情况下（例如引擎的 bug），可能会发生类似的不一致。
```

**代码逻辑推理和假设输入输出:**

以 `ArrayList::ArrayListVerify` 为例：

**假设输入:** 一个 `ArrayList` 对象实例。

**代码逻辑:**

1. 检查 `length()` 是否大于等于 0。
2. 检查 `length()` 是否小于等于 `capacity()`。
3. 如果 `capacity()` 为 0，检查该对象是否是全局唯一的空数组列表 (`ReadOnlyRoots(isolate).empty_array_list()`)。
4. 遍历数组列表中的每个元素，使用 `Object::VerifyPointer` 检查其有效性。

**假设输出:** 如果所有检查都通过，函数将返回（或者不产生任何输出）。如果任何检查失败，将会触发 `CHECK` 宏，导致程序终止并输出错误信息。

**用户常见的编程错误:**

虽然用户无法直接操作这些底层的 V8 对象，但一些常见的 JavaScript 编程错误可能会间接地导致这些内部对象的状态异常，从而可能被这些 `Verify` 函数检测到。

例如：

* **数组长度错误:**  在 JavaScript 中设置了不合理的数组长度，可能会导致 V8 内部的 `JSArray` 对象状态异常。虽然 V8 会进行一些处理，但某些极端情况下可能导致问题。
  ```javascript
  const arr = [];
  arr.length = -1; // 这在 JavaScript 中会被修正为 0，但在引擎内部可能触发某些边界情况。
  ```
* **对象属性的意外修改:**  虽然 JavaScript 提供了属性访问控制，但在某些情况下（例如使用 `Object.defineProperty` 不当），可能会导致对象的内部结构出现意外的状态。
  ```javascript
  const obj = { x: 1 };
  Object.defineProperty(obj, 'x', { value: null }); // 某些内部优化可能会依赖于特定类型的属性值。
  ```
* **原型链污染:**  修改内置对象的原型可能会导致意想不到的行为，并可能影响到 V8 内部对象的结构。

总而言之，这部分代码定义了 V8 内部对象的健康检查机制，用于确保引擎在运行过程中的数据结构完整性和一致性。虽然用户无法直接触发这些验证，但用户的 JavaScript 代码行为会间接地影响这些内部对象的状态。这些验证机制是 V8 引擎稳定性和可靠性的重要组成部分。

Prompt: 
```
这是目录为v8/src/diagnostics/objects-debug.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/objects-debug.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
IsScriptContext());
  }
}

void ArrayList::ArrayListVerify(Isolate* isolate) {
  CHECK_LE(0, length());
  CHECK_LE(length(), capacity());
  CHECK_IMPLIES(capacity() == 0,
                this == ReadOnlyRoots(isolate).empty_array_list());
  for (int i = 0; i < capacity(); ++i) {
    Object::VerifyPointer(isolate, get(i));
  }
}

void PropertyArray::PropertyArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::PropertyArrayVerify(*this, isolate);
  if (length() == 0) {
    CHECK_EQ(*this, ReadOnlyRoots(isolate).empty_property_array());
    return;
  }
  // There are no empty PropertyArrays.
  CHECK_LT(0, length());
  for (int i = 0; i < length(); i++) {
    Tagged<Object> e = get(i);
    Object::VerifyPointer(isolate, e);
  }
}

void ByteArray::ByteArrayVerify(Isolate* isolate) {}

void TrustedByteArray::TrustedByteArrayVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);
}

void FixedDoubleArray::FixedDoubleArrayVerify(Isolate* isolate) {
  for (int i = 0; i < length(); i++) {
    if (!is_the_hole(i)) {
      uint64_t value = get_representation(i);
      uint64_t unexpected =
          base::bit_cast<uint64_t>(std::numeric_limits<double>::quiet_NaN()) &
          uint64_t{0x7FF8000000000000};
      // Create implementation specific sNaN by inverting relevant bit.
      unexpected ^= uint64_t{0x0008000000000000};
      CHECK((value & uint64_t{0x7FF8000000000000}) != unexpected ||
            (value & uint64_t{0x0007FFFFFFFFFFFF}) == uint64_t{0});
    }
  }
}

void Context::ContextVerify(Isolate* isolate) {
  if (has_extension()) VerifyExtensionSlot(extension());
  TorqueGeneratedClassVerifiers::ContextVerify(*this, isolate);
  for (int i = 0; i < length(); i++) {
    VerifyObjectField(isolate, OffsetOfElementAt(i));
  }
  if (IsScriptContext()) {
    Tagged<Object> side_data = get(CONTEXT_SIDE_TABLE_PROPERTY_INDEX);
    CHECK(IsFixedArray(side_data));
    Tagged<FixedArray> side_data_array = Cast<FixedArray>(side_data);
    if (v8_flags.const_tracking_let) {
      for (int i = 0; i < side_data_array->length(); i++) {
        Tagged<Object> element = side_data_array->get(i);
        if (IsSmi(element)) {
          int value = element.ToSmi().value();
          CHECK(ContextSidePropertyCell::kOther <= value);
          CHECK(value <= ContextSidePropertyCell::kMutableHeapNumber);
        } else {
          // The slot contains `undefined` before the variable is initialized.
          CHECK(IsUndefined(element) || IsContextSidePropertyCell(element));
        }
      }
    } else {
      CHECK_EQ(0, side_data_array->length());
    }
  }
}

void NativeContext::NativeContextVerify(Isolate* isolate) {
  ContextVerify(isolate);
  CHECK(retained_maps() == Smi::zero() || IsWeakArrayList(retained_maps()));
  CHECK_EQ(length(), NativeContext::NATIVE_CONTEXT_SLOTS);
  CHECK_EQ(kVariableSizeSentinel, map()->instance_size());
}

void FeedbackMetadata::FeedbackMetadataVerify(Isolate* isolate) {
  if (slot_count() == 0 && create_closure_slot_count() == 0) {
    CHECK_EQ(ReadOnlyRoots(isolate).empty_feedback_metadata(), *this);
  } else {
    FeedbackMetadataIterator iter(*this);
    while (iter.HasNext()) {
      iter.Next();
      FeedbackSlotKind kind = iter.kind();
      CHECK_NE(FeedbackSlotKind::kInvalid, kind);
      CHECK_GT(kFeedbackSlotKindCount, kind);
    }
  }
}

void DescriptorArray::DescriptorArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::DescriptorArrayVerify(*this, isolate);
  if (number_of_all_descriptors() == 0) {
    CHECK_EQ(ReadOnlyRoots(isolate).empty_descriptor_array(), *this);
    CHECK_EQ(0, number_of_all_descriptors());
    CHECK_EQ(0, number_of_descriptors());
    CHECK_EQ(ReadOnlyRoots(isolate).empty_enum_cache(), enum_cache());
  } else {
    CHECK_LT(0, number_of_all_descriptors());
    CHECK_LE(number_of_descriptors(), number_of_all_descriptors());

    // Check that properties with private symbols names are non-enumerable, and
    // that fields are in order.
    int expected_field_index = 0;
    for (InternalIndex descriptor :
         InternalIndex::Range(number_of_descriptors())) {
      Tagged<Object> key =
          *(GetDescriptorSlot(descriptor.as_int()) + kEntryKeyIndex);
      // number_of_descriptors() may be out of sync with the actual descriptors
      // written during descriptor array construction.
      if (IsUndefined(key, isolate)) continue;
      PropertyDetails details = GetDetails(descriptor);
      if (Cast<Name>(key)->IsPrivate()) {
        CHECK_NE(details.attributes() & DONT_ENUM, 0);
      }
      Tagged<MaybeObject> value = GetValue(descriptor);
      if (details.location() == PropertyLocation::kField) {
        CHECK_EQ(details.field_index(), expected_field_index);
        CHECK(value == FieldType::None() || value == FieldType::Any() ||
              IsMap(value.GetHeapObjectAssumeWeak()));
        expected_field_index += details.field_width_in_words();
      } else {
        CHECK(!value.IsWeakOrCleared());
        CHECK(!IsMap(Cast<Object>(value)));
      }
    }
  }
}

void TransitionArray::TransitionArrayVerify(Isolate* isolate) {
  WeakFixedArrayVerify(isolate);
  CHECK_LE(LengthFor(number_of_transitions()), length());

  ReadOnlyRoots roots(isolate);
  Tagged<Map> owner;

  // Check all entries have the same owner
  for (int i = 0; i < number_of_transitions(); ++i) {
    Tagged<Map> target = GetTarget(i);
    Tagged<Map> parent = Cast<Map>(target->constructor_or_back_pointer());
    if (owner.is_null()) {
      parent = owner;
    } else {
      CHECK_EQ(parent, owner);
    }
  }
  // Check all entries have the same owner
  if (HasPrototypeTransitions()) {
    Tagged<WeakFixedArray> proto_trans = GetPrototypeTransitions();
    int length = TransitionArray::NumberOfPrototypeTransitions(proto_trans);
    for (int i = 0; i < length; ++i) {
      int index = TransitionArray::kProtoTransitionHeaderSize + i;
      Tagged<MaybeObject> maybe_target = proto_trans->get(index);
      Tagged<HeapObject> target;
      if (maybe_target.GetHeapObjectIfWeak(&target)) {
        if (v8_flags.move_prototype_transitions_first) {
          Tagged<Map> parent =
              Cast<Map>(Cast<Map>(target)->constructor_or_back_pointer());
          if (owner.is_null()) {
            parent = Cast<Map>(target);
          } else {
            CHECK_EQ(parent, owner);
          }
        } else {
          CHECK(IsUndefined(Cast<Map>(target)->GetBackPointer()));
        }
      }
    }
  }
  // Check all entries are valid
  if (HasSideStepTransitions()) {
    Tagged<WeakFixedArray> side_trans = GetSideStepTransitions();
    for (uint32_t index = SideStepTransition::kFirstMapIdx;
         index <= SideStepTransition::kLastMapIdx; ++index) {
      Tagged<MaybeObject> maybe_target = side_trans->get(index);
      Tagged<HeapObject> target;
      if (maybe_target.GetHeapObjectIfWeak(&target)) {
        CHECK(IsMap(target));
        if (!owner.is_null()) {
          CHECK_EQ(target->map(), owner->map());
        }
      } else {
        CHECK(maybe_target == SideStepTransition::Unreachable ||
              maybe_target == SideStepTransition::Empty ||
              maybe_target.IsCleared());
      }
    }
    Tagged<MaybeObject> maybe_cell =
        side_trans->get(SideStepTransition::index_of(
            SideStepTransition::Kind::kObjectAssignValidityCell));
    Tagged<HeapObject> cell;
    if (maybe_cell.GetHeapObjectIfWeak(&cell)) {
      CHECK(IsCell(cell));
    } else {
      CHECK(maybe_cell == SideStepTransition::Empty || maybe_cell.IsCleared());
    }
  }
}

namespace {
void SloppyArgumentsElementsVerify(Isolate* isolate,
                                   Tagged<SloppyArgumentsElements> elements,
                                   Tagged<JSObject> holder) {
  elements->SloppyArgumentsElementsVerify(isolate);
  ElementsKind kind = holder->GetElementsKind();
  bool is_fast = kind == FAST_SLOPPY_ARGUMENTS_ELEMENTS;
  Tagged<Context> context_object = elements->context();
  Tagged<FixedArray> arg_elements = elements->arguments();
  if (arg_elements->length() == 0) {
    CHECK(arg_elements == ReadOnlyRoots(isolate).empty_fixed_array());
    return;
  }
  ElementsAccessor* accessor;
  if (is_fast) {
    accessor = ElementsAccessor::ForKind(HOLEY_ELEMENTS);
  } else {
    accessor = ElementsAccessor::ForKind(DICTIONARY_ELEMENTS);
  }
  int nofMappedParameters = 0;
  int maxMappedIndex = 0;
  for (int i = 0; i < nofMappedParameters; i++) {
    // Verify that each context-mapped argument is either the hole or a valid
    // Smi within context length range.
    Tagged<Object> mapped = elements->mapped_entries(i, kRelaxedLoad);
    if (IsTheHole(mapped, isolate)) {
      // Slow sloppy arguments can be holey.
      if (!is_fast) continue;
      // Fast sloppy arguments elements are never holey. Either the element is
      // context-mapped or present in the arguments elements.
      CHECK(accessor->HasElement(holder, i, arg_elements));
      continue;
    }
    int mappedIndex = Smi::ToInt(mapped);
    nofMappedParameters++;
    CHECK_LE(maxMappedIndex, mappedIndex);
    maxMappedIndex = mappedIndex;
    Tagged<Object> value = context_object->get(mappedIndex);
    CHECK(IsObject(value));
    // None of the context-mapped entries should exist in the arguments
    // elements.
    CHECK(!accessor->HasElement(holder, i, arg_elements));
  }
  CHECK_LE(nofMappedParameters, context_object->length());
  CHECK_LE(nofMappedParameters, arg_elements->length());
  CHECK_LE(maxMappedIndex, context_object->length());
  CHECK_LE(maxMappedIndex, arg_elements->length());
}
}  // namespace

void JSArgumentsObject::JSArgumentsObjectVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSArgumentsObjectVerify(*this, isolate);
  if (IsSloppyArgumentsElementsKind(GetElementsKind())) {
    SloppyArgumentsElementsVerify(
        isolate, Cast<SloppyArgumentsElements>(elements()), *this);
  }
  Tagged<NativeContext> native_context = map()->map()->native_context();
  if (map() == native_context->get(Context::SLOPPY_ARGUMENTS_MAP_INDEX) ||
      map() == native_context->get(Context::SLOW_ALIASED_ARGUMENTS_MAP_INDEX) ||
      map() == native_context->get(Context::FAST_ALIASED_ARGUMENTS_MAP_INDEX)) {
    VerifyObjectField(isolate, JSSloppyArgumentsObject::kLengthOffset);
    VerifyObjectField(isolate, JSSloppyArgumentsObject::kCalleeOffset);
  } else if (map() ==
             native_context->get(Context::STRICT_ARGUMENTS_MAP_INDEX)) {
    VerifyObjectField(isolate, JSStrictArgumentsObject::kLengthOffset);
  }
}

void JSAsyncFunctionObject::JSAsyncFunctionObjectVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSAsyncFunctionObjectVerify(*this, isolate);
}

void JSAsyncGeneratorObject::JSAsyncGeneratorObjectVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSAsyncGeneratorObjectVerify(*this, isolate);
}

void JSDate::JSDateVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSDateVerify(*this, isolate);

  if (IsSmi(month())) {
    int month = Smi::ToInt(this->month());
    CHECK(0 <= month && month <= 11);
  }
  if (IsSmi(day())) {
    int day = Smi::ToInt(this->day());
    CHECK(1 <= day && day <= 31);
  }
  if (IsSmi(hour())) {
    int hour = Smi::ToInt(this->hour());
    CHECK(0 <= hour && hour <= 23);
  }
  if (IsSmi(min())) {
    int min = Smi::ToInt(this->min());
    CHECK(0 <= min && min <= 59);
  }
  if (IsSmi(sec())) {
    int sec = Smi::ToInt(this->sec());
    CHECK(0 <= sec && sec <= 59);
  }
  if (IsSmi(weekday())) {
    int weekday = Smi::ToInt(this->weekday());
    CHECK(0 <= weekday && weekday <= 6);
  }
  if (IsSmi(cache_stamp())) {
    CHECK(Smi::ToInt(cache_stamp()) <=
          Smi::ToInt(isolate->date_cache()->stamp()));
  }
}

void String::StringVerify(Isolate* isolate) {
  PrimitiveHeapObjectVerify(isolate);
  CHECK(IsString(this, isolate));
  CHECK(length() >= 0 && length() <= Smi::kMaxValue);
  CHECK_IMPLIES(length() == 0, this == ReadOnlyRoots(isolate).empty_string());
  if (IsInternalizedString(this)) {
    CHECK(HasHashCode());
    CHECK(!HeapLayout::InYoungGeneration(this));
  }
}

void ConsString::ConsStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsConsString(this, isolate));
  CHECK_GE(length(), ConsString::kMinLength);
  CHECK(length() == first()->length() + second()->length());
  if (IsFlat()) {
    // A flat cons can only be created by String::SlowFlatten.
    // Afterwards, the first part may be externalized or internalized.
    CHECK(IsSeqString(first()) || IsExternalString(first()) ||
          IsThinString(first()));
  }
}

void ThinString::ThinStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsThinString(this, isolate));
  CHECK(!HasForwardingIndex(kAcquireLoad));
  CHECK(IsInternalizedString(actual()));
  CHECK(IsSeqString(actual()) || IsExternalString(actual()));
}

void SlicedString::SlicedStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsSlicedString(this, isolate));
  CHECK(!IsConsString(parent()));
  CHECK(!IsSlicedString(parent()));
#ifdef DEBUG
  if (!isolate->has_turbofan_string_builders()) {
    // Turbofan's string builder optimization can introduce SlicedString that
    // are less than SlicedString::kMinLength characters. Their live range and
    // scope are pretty limitted, but they can be visible to the GC, which
    // shouldn't treat them as invalid.
    CHECK_GE(length(), SlicedString::kMinLength);
  }
#endif
}

void ExternalString::ExternalStringVerify(Isolate* isolate) {
  StringVerify(isolate);
  CHECK(IsExternalString(this, isolate));
}

void JSBoundFunction::JSBoundFunctionVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSBoundFunctionVerify(*this, isolate);
  CHECK(IsCallable(*this));
  CHECK_EQ(IsConstructor(*this), IsConstructor(bound_target_function()));
  // Ensure that the function's meta map belongs to the same native context
  // as the target function (i.e. meta maps are the same).
  CHECK_EQ(map()->map(), bound_target_function()->map()->map());
}

void JSFunction::JSFunctionVerify(Isolate* isolate) {
  // Don't call TorqueGeneratedClassVerifiers::JSFunctionVerify here because the
  // Torque class definition contains the field `prototype_or_initial_map` which
  // may not be allocated.

  // This assertion exists to encourage updating this verification function if
  // new fields are added in the Torque class layout definition.
  static_assert(JSFunction::TorqueGeneratedClass::kHeaderSize ==
                8 * kTaggedSize);

  JSFunctionOrBoundFunctionOrWrappedFunctionVerify(isolate);
  CHECK(IsJSFunction(*this));
  Object::VerifyPointer(isolate, shared(isolate));
  CHECK(IsSharedFunctionInfo(shared(isolate)));
  Object::VerifyPointer(isolate, context(isolate, kRelaxedLoad));
  CHECK(IsContext(context(isolate, kRelaxedLoad)));
  Object::VerifyPointer(isolate, raw_feedback_cell(isolate));
  CHECK(IsFeedbackCell(raw_feedback_cell(isolate)));
  Object::VerifyPointer(isolate, code(isolate));
  CHECK(IsCode(code(isolate)));
  CHECK(map(isolate)->is_callable());
  // Ensure that the function's meta map belongs to the same native context.
  CHECK_EQ(map()->map()->native_context_or_null(), native_context());

#ifdef V8_ENABLE_LEAPTIERING
  JSDispatchTable* jdt = GetProcessWideJSDispatchTable();
  JSDispatchHandle handle = dispatch_handle();
  CHECK_NE(handle, kNullJSDispatchHandle);
  uint16_t parameter_count = jdt->GetParameterCount(handle);
  CHECK_EQ(parameter_count,
           shared(isolate)->internal_formal_parameter_count_with_receiver());
  Tagged<Code> code_from_table = jdt->GetCode(handle);
  CHECK(code_from_table->parameter_count() == kDontAdaptArgumentsSentinel ||
        code_from_table->parameter_count() == parameter_count);

  // Currently, a JSFunction must have the same dispatch entry as its
  // FeedbackCell, unless the FeedbackCell has no entry.
  JSDispatchHandle feedback_cell_handle =
      raw_feedback_cell(isolate)->dispatch_handle();
  CHECK_EQ(raw_feedback_cell(isolate) == isolate->heap()->many_closures_cell(),
           feedback_cell_handle == kNullJSDispatchHandle);
  if (code_from_table->is_context_specialized()) {
    // This function is context specialized. It must have its own dispatch
    // handle. The canonical handle must exist and be different.
    CHECK_NE(feedback_cell_handle, handle);
  } else {
    // This function is not context specialized. Then we should either use the
    // canonical dispatch handle. Except for builtins, which use the
    // many_closures_cell (see check above).
    // Also, after code flushing this js function can point to the CompileLazy
    // builtin, which will unify the dispatch handles on the next UpdateCode.
    if (feedback_cell_handle != kNullJSDispatchHandle) {
      if (code_from_table->kind() != CodeKind::BUILTIN) {
        CHECK_EQ(feedback_cell_handle, handle);
      }
    }
  }
  if (feedback_cell_handle != kNullJSDispatchHandle) {
    CHECK(!jdt->GetCode(feedback_cell_handle)->is_context_specialized());
  }

  // Verify the entrypoint corresponds to the code or a tiering builtin.
  Address entrypoint = jdt->GetEntrypoint(handle);
#define CASE(name, ...) \
  entrypoint == BUILTIN_CODE(isolate, name)->instruction_start() ||
  CHECK(BUILTIN_LIST_BASE_TIERING(CASE)
            entrypoint == code_from_table->instruction_start());
#undef CASE

#endif  // V8_ENABLE_LEAPTIERING

  Handle<JSFunction> function(*this, isolate);
  LookupIterator it(isolate, function, isolate->factory()->prototype_string(),
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  if (has_prototype_slot()) {
    VerifyObjectField(isolate, kPrototypeOrInitialMapOffset);
  }

  if (has_prototype_property()) {
    CHECK(it.IsFound());
    CHECK_EQ(LookupIterator::ACCESSOR, it.state());
    CHECK(IsAccessorInfo(*it.GetAccessors()));
  } else {
    CHECK(!it.IsFound() || it.state() != LookupIterator::ACCESSOR ||
          !IsAccessorInfo(*it.GetAccessors()));
  }

  CHECK_IMPLIES(shared()->HasBuiltinId(),
                Builtins::CheckFormalParameterCount(
                    shared()->builtin_id(), shared()->length(),
                    shared()->internal_formal_parameter_count_with_receiver()));
}

void JSWrappedFunction::JSWrappedFunctionVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSWrappedFunctionVerify(*this, isolate);
  CHECK(IsCallable(*this));
  // Ensure that the function's meta map belongs to the same native context.
  CHECK_EQ(map()->map()->native_context_or_null(), context());
}

namespace {

bool ShouldVerifySharedFunctionInfoFunctionIndex(
    Tagged<SharedFunctionInfo> sfi) {
  if (!sfi->HasBuiltinId()) return true;
  switch (sfi->builtin_id()) {
    case Builtin::kPromiseCapabilityDefaultReject:
    case Builtin::kPromiseCapabilityDefaultResolve:
      // For these we manually set custom function indices.
      return false;
    default:
      return true;
  }
  UNREACHABLE();
}

}  // namespace

void SharedFunctionInfo::SharedFunctionInfoVerify(LocalIsolate* isolate) {
  ReadOnlyRoots roots(isolate);

  Tagged<Object> value = name_or_scope_info(kAcquireLoad);
  if (IsScopeInfo(value)) {
    CHECK(!Cast<ScopeInfo>(value)->IsEmpty());
    CHECK_NE(value, roots.empty_scope_info());
  }

#if V8_ENABLE_WEBASSEMBLY
  bool is_wasm = HasWasmExportedFunctionData() || HasAsmWasmData() ||
                 HasWasmJSFunctionData() || HasWasmCapiFunctionData() ||
                 HasWasmResumeData();
#else
  bool is_wasm = false;
#endif  // V8_ENABLE_WEBASSEMBLY
  CHECK(is_wasm || IsApiFunction() || HasBytecodeArray() || HasBuiltinId() ||
        HasUncompiledDataWithPreparseData() ||
        HasUncompiledDataWithoutPreparseData());

  {
    Tagged<HeapObject> script = this->script(kAcquireLoad);
    CHECK(IsUndefined(script, roots) || IsScript(script));
  }

  if (!is_compiled()) {
    CHECK(!HasFeedbackMetadata());
    CHECK(IsScopeInfo(outer_scope_info()) ||
          IsTheHole(outer_scope_info(), roots));
  } else if (HasBytecodeArray() && HasFeedbackMetadata()) {
    CHECK(IsFeedbackMetadata(feedback_metadata()));
  }

  if (HasBytecodeArray() && !IsDontAdaptArguments()) {
    CHECK_EQ(GetBytecodeArray(isolate)->parameter_count(),
             internal_formal_parameter_count_with_receiver());
  }

  if (ShouldVerifySharedFunctionInfoFunctionIndex(*this)) {
    int expected_map_index =
        Context::FunctionMapIndex(language_mode(), kind(), HasSharedName());
    CHECK_EQ(expected_map_index, function_map_index());
  }

  Tagged<ScopeInfo> info = EarlyScopeInfo(kAcquireLoad);
  if (!info->IsEmpty()) {
    CHECK(kind() == info->function_kind());
    CHECK_EQ(internal::IsModule(kind()), info->scope_type() == MODULE_SCOPE);
  }

  if (IsApiFunction()) {
    CHECK(construct_as_builtin());
  } else if (!HasBuiltinId()) {
    CHECK(!construct_as_builtin());
  } else {
    if (builtin_id() != Builtin::kCompileLazy &&
        builtin_id() != Builtin::kEmptyFunction) {
      CHECK(construct_as_builtin());
    } else {
      CHECK(!construct_as_builtin());
    }
  }
  CHECK_IMPLIES(HasBuiltinId(),
                Builtins::CheckFormalParameterCount(
                    builtin_id(), length(),
                    internal_formal_parameter_count_with_receiver()));
}

void SharedFunctionInfo::SharedFunctionInfoVerify(Isolate* isolate) {
  // TODO(leszeks): Add a TorqueGeneratedClassVerifier for LocalIsolate.
  SharedFunctionInfoVerify(isolate->AsLocalIsolate());
}

void SharedFunctionInfoWrapper::SharedFunctionInfoWrapperVerify(
    Isolate* isolate) {
  Object::VerifyPointer(isolate, shared_info());
}

void JSGlobalProxy::JSGlobalProxyVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSGlobalProxyVerify(*this, isolate);
  CHECK(map()->is_access_check_needed());
  // Make sure that this object has no properties, elements.
  CHECK_EQ(0, Cast<FixedArray>(elements())->length());
}

void JSGlobalObject::JSGlobalObjectVerify(Isolate* isolate) {
  CHECK(IsJSGlobalObject(*this));
  // Do not check the dummy global object for the builtins.
  if (global_dictionary(kAcquireLoad)->NumberOfElements() == 0 &&
      elements()->length() == 0) {
    return;
  }
  JSObjectVerify(isolate);
}

void PrimitiveHeapObject::PrimitiveHeapObjectVerify(Isolate* isolate) {
  CHECK(IsPrimitiveHeapObject(this, isolate));
}

void HeapNumber::HeapNumberVerify(Isolate* isolate) {
  PrimitiveHeapObjectVerify(isolate);
  CHECK(IsHeapNumber(this, isolate));
}

void Oddball::OddballVerify(Isolate* isolate) {
  PrimitiveHeapObjectVerify(isolate);
  CHECK(IsOddball(this, isolate));

  Heap* heap = isolate->heap();
  Tagged<Object> string = to_string();
  Object::VerifyPointer(isolate, string);
  CHECK(IsString(string));
  Tagged<Object> type = type_of();
  Object::VerifyPointer(isolate, type);
  CHECK(IsString(type));
  Tagged<Object> kind_value = kind_.load();
  Object::VerifyPointer(isolate, kind_value);
  CHECK(IsSmi(kind_value));

  Tagged<Object> number = to_number();
  Object::VerifyPointer(isolate, number);
  CHECK(IsSmi(number) || IsHeapNumber(number));
  if (IsHeapObject(number)) {
    CHECK(number == ReadOnlyRoots(heap).nan_value() ||
          number == ReadOnlyRoots(heap).hole_nan_value());
  } else {
    CHECK(IsSmi(number));
    int value = Smi::ToInt(number);
    // Hidden oddballs have negative smis.
    const int kLeastHiddenOddballNumber = -7;
    CHECK_LE(value, 1);
    CHECK_GE(value, kLeastHiddenOddballNumber);
  }

  ReadOnlyRoots roots(heap);
  if (map() == roots.undefined_map()) {
    CHECK(this == roots.undefined_value());
  } else if (map() == roots.null_map()) {
    CHECK(this == roots.null_value());
  } else if (map() == roots.boolean_map()) {
    CHECK(this == roots.true_value() || this == roots.false_value());
  } else {
    UNREACHABLE();
  }
}

void Hole::HoleVerify(Isolate* isolate) {
  ReadOnlyRoots roots(isolate->heap());
  CHECK_EQ(map(), roots.hole_map());

#define COMPARE_ROOTS_VALUE(_, Value, __) \
  if (*this == roots.Value()) {           \
    return;                               \
  }
  HOLE_LIST(COMPARE_ROOTS_VALUE);
#undef COMPARE_ROOTS_VALUE

  UNREACHABLE();
}

void PropertyCell::PropertyCellVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::PropertyCellVerify(*this, isolate);
  CHECK(IsUniqueName(name()));
  CheckDataIsCompatible(property_details(), value());
}

void ContextSidePropertyCell::ContextSidePropertyCellVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::ContextSidePropertyCellVerify(*this, isolate);
}

void TrustedObject::TrustedObjectVerify(Isolate* isolate) {
#if defined(V8_ENABLE_SANDBOX)
  // All trusted objects must live in trusted space.
  // TODO(saelo): Some objects are trusted but do not yet live in trusted space.
  CHECK(HeapLayout::InTrustedSpace(*this) || IsCode(*this));
#endif
}

void TrustedObjectLayout::TrustedObjectVerify(Isolate* isolate) {
  UncheckedCast<TrustedObject>(this)->TrustedObjectVerify(isolate);
}

void ExposedTrustedObject::ExposedTrustedObjectVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);
#if defined(V8_ENABLE_SANDBOX)
  // Check that the self indirect pointer is consistent, i.e. points back to
  // this object.
  InstanceType instance_type = map()->instance_type();
  IndirectPointerTag tag = IndirectPointerTagFromInstanceType(instance_type);
  // We can't use ReadIndirectPointerField here because the tag is not a
  // compile-time constant.
  IndirectPointerSlot slot =
      RawIndirectPointerField(kSelfIndirectPointerOffset, tag);
  Tagged<Object> self = slot.load(isolate);
  CHECK_EQ(self, *this);
  // If the object is in the read-only space, the self indirect pointer entry
  // must be in the read-only segment, and vice versa.
  if (tag == kCodeIndirectPointerTag) {
    CodePointerTable::Space* space =
        IsolateForSandbox(isolate).GetCodePointerTableSpaceFor(slot.address());
    // During snapshot creation, the code pointer space of the read-only heap is
    // not marked as an internal read-only space.
    bool is_space_read_only =
        space == isolate->read_only_heap()->code_pointer_space();
    CHECK_EQ(is_space_read_only, HeapLayout::InReadOnlySpace(*this));
  } else {
    CHECK(!HeapLayout::InReadOnlySpace(*this));
  }
#endif
}

void Code::CodeVerify(Isolate* isolate) {
  ExposedTrustedObjectVerify(isolate);
  CHECK(IsCode(*this));
  if (has_instruction_stream()) {
    Tagged<InstructionStream> istream = instruction_stream();
    CHECK_EQ(istream->code(kAcquireLoad), *this);
    CHECK_EQ(safepoint_table_offset(), 0);
    CHECK_LE(safepoint_table_offset(), handler_table_offset());
    CHECK_LE(handler_table_offset(), constant_pool_offset());
    CHECK_LE(constant_pool_offset(), code_comments_offset());
    CHECK_LE(code_comments_offset(), unwinding_info_offset());
    CHECK_LE(unwinding_info_offset(), metadata_size());

    // Ensure the cached code entry point corresponds to the InstructionStream
    // object associated with this Code.
#if defined(V8_COMPRESS_POINTERS) && defined(V8_SHORT_BUILTIN_CALLS)
    if (istream->instruction_start() == instruction_start()) {
      // Most common case, all good.
    } else {
      // When shared pointer compression cage is enabled and it has the
      // embedded code blob copy then the
      // InstructionStream::instruction_start() might return the address of
      // the remapped builtin regardless of whether the builtins copy existed
      // when the instruction_start value was cached in the Code (see
      // InstructionStream::OffHeapInstructionStart()).  So, do a reverse
      // Code object lookup via instruction_start value to ensure it
      // corresponds to this current Code object.
      Tagged<Code> lookup_result =
          isolate->heap()->FindCodeForInnerPointer(instruction_start());
      CHECK_EQ(lookup_result, *this);
    }
#else
    CHECK_EQ(istream->instruction_start(), instruction_start());
#endif  // V8_COMPRESS_POINTERS && V8_SHORT_BUILTIN_CALLS
  }

  // Our wrapper must point back to us.
  CHECK_EQ(wrapper()->code(isolate), *this);
}

void CodeWrapper::CodeWrapperVerify(Isolate* isolate) {
  if (!this->has_code()) return;
  auto code = this->code(isolate);
  Object::VerifyPointer(isolate, code);
  CHECK_EQ(code->wrapper(), *this);
}

void InstructionStream::InstructionStreamVerify(Isolate* isolate) {
  TrustedObjectVerify(isolate);
  Tagged<Code> code;
  if (!TryGetCode(&code, kAcquireLoad)) return;
  CHECK(
      IsAligned(code->instruction_size(),
                static_cast<unsigned>(InstructionStream::kMetadataAlignment)));
#if (!defined(_MSC_VER) || defined(__clang__)) && !defined(V8_OS_ZOS)
  // See also: PlatformEmbeddedFileWriterWin::AlignToCodeAlignment
  //      and: PlatformEmbeddedFileWriterZOS::AlignToCodeAlignment
  CHECK_IMPLIES(!ReadOnlyHeap::Contains(*this),
                IsAligned(instruction_start(), kCodeAlignment));
#endif  // (!defined(_MSC_VER) || defined(__clang__)) && !defined(V8_OS_ZOS)
  CHECK_IMPLIES(!ReadOnlyHeap::Contains(*this),
                IsAligned(instruction_start(), kCodeAlignment));
  CHECK_EQ(*this, code->instruction_stream());
  CHECK(Size() <= MemoryChunkLayout::MaxRegularCodeObjectSize() ||
        isolate->heap()->InSpace(*this, CODE_LO_SPACE));
  Address last_gc_pc = kNullAddress;

  Object::ObjectVerify(relocation_info(), isolate);

  for (RelocIterator it(code); !it.done(); it.next()) {
    it.rinfo()->Verify(isolate);
    // Ensure that GC will not iterate twice over the same pointer.
    if (RelocInfo::IsGCRelocMode(it.rinfo()->rmode())) {
      CHECK(it.rinfo()->pc() != last_gc_pc);
      last_gc_pc = it.rinfo()->pc();
    }
  }
}

void JSArray::JSArrayVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSArrayVerify(*this, isolate);
  // If a GC was caused while constructing this array, the elements
  // pointer may point to a one pointer filler map.
  if (!ElementsAreSafeToExamine(isolate)) return;
  if (IsUndefined(elements(), isolate)) return;
  CHECK(IsFixedArray(elements()) || IsFixedDoubleArray(elements()));
  if (elements()->length() == 0) {
    CHECK_EQ(elements(), ReadOnlyRoots(isolate).empty_fixed_array());
  }
  // Verify that the length and the elements backing store are in sync.
  if (IsSmi(length()) && (HasFastElements() || HasAnyNonextensibleElements())) {
    if (elements()->length() > 0) {
      CHECK_IMPLIES(HasDoubleElements(), IsFixedDoubleArray(elements()));
      CHECK_IMPLIES(HasSmiOrObjectElements() || HasAnyNonextensibleElements(),
                    IsFixedArray(elements()));
    }
    int size = Smi::ToInt(length());
    // Holey / Packed backing stores might have slack or might have not been
    // properly initialized yet.
    CHECK(size <= elements()->length() ||
          elements() == ReadOnlyRoots(isolate).empty_fixed_array());
  } else {
    CHECK(HasDictionaryElements());
    uint32_t array_length;
    CHECK(Object::ToArrayLength(length(), &array_length));
    if (array_length == 0xFFFFFFFF) {
      CHECK(Object::ToArrayLength(length(), &array_length));
    }
    if (array_length != 0) {
      Tagged<NumberDictionary> dict = Cast<NumberDictionary>(elements());
      // The dictionary can never have more elements than the array length + 1.
      // If the backing store grows the verification might be triggered with
      // the old length in place.
      uint32_t nof_elements = static_cast<uint32_t>(dict->NumberOfElements());
      if (nof_elements != 0) nof_elements--;
      CHECK_LE(nof_elements, array_length);
    }
  }
}

void JSSet::JSSetVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSSetVerify(*this, isolate);
  CHECK(IsOrderedHashSet(table()) || IsUndefined(table(), isolate));
  // TODO(arv): Verify OrderedHashTable too.
}

void JSMap::JSMapVerify(Isolate* isolate) {
  TorqueGeneratedClassVerifiers::JSMapVerify(*this, isolate);
  CHECK(IsOrderedHashMap(table()) || IsUndefined(table(), isolate));
  // TODO(arv): Verify OrderedHashTable too.
}

void JSSetIterator::JSSetIteratorVerify(Isolate* isolate) {
  CHECK(IsJSSetIterator(*this));
  JSCollectionIteratorVerify(isolate);
  CHECK(IsOrderedHashSet(table()));
  CHECK(IsSmi(index()));
}

void JSMapIterator::JSMapIteratorVerify(Isolate* isolate) {
  CHECK(IsJSMapIterator(*this));
  JSCollectionIteratorVerify(isolate);
  CHECK(IsOrderedHashMap(table()));
  CHECK(IsSmi(index()));
}

USE_TORQUE_VERIFIER(JSShadowRealm)

namespace {

void VerifyElementIsShared(Tagged<Object> element) {
  // Exception for ThinStrings:
  // When storing a ThinString in a shared object, we want to store the actual
  // string, which is shared when sharing the string table.
  // It is possible that a stored shared string migrates to a ThinString later
  // on, which is fine as the ThinString resides in shared space if the original
  // string was in shared space.
  if (IsThinStrin
"""


```