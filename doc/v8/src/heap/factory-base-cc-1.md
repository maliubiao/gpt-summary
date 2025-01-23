Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `factory-base.cc`. They also want to know:
1. What it would mean if the file had a `.tq` extension.
2. If the code relates to JavaScript features, with examples.
3. Potential code logic, inputs and outputs.
4. Common programming errors related to the code.
5. A general summary of the code's function.

Let's break down the code snippet:

- **String Creation:**  The code defines several methods for creating different types of strings in V8, including `SeqOneByteString`, `SeqTwoByteString`, `ConsString`, and internalized strings. It handles cases for empty strings, single-character strings, and combining strings.
- **Number to String Conversion:**  It includes functions for converting numbers (Smis and HeapNumbers) to strings, with caching mechanisms.
- **Object Allocation:**  There are methods for allocating raw memory for various V8 objects like `BigInt`, `ScopeInfo`, `SharedFunctionInfo`, `DescriptorArray`, `ClassPositions`, `FixedArray`, `WeakArrayList`, and `SwissNameDictionary`.
- **Allocation with Maps:** Functions like `NewWithImmortalMap` and `AllocateRawWithImmortalMap` suggest associating type information (Maps) with allocated memory.
- **Internalization:**  The code mentions internalization of strings, which is a process to ensure that identical strings share the same memory.
- **Templates:** The use of templates suggests a base class (`FactoryBase`) that can be used with different concrete factory implementations.

Considering the instructions:

1. **.tq extension:** If the file ended in `.tq`, it would be a Torque source file. Torque is V8's domain-specific language for writing low-level runtime code.
2. **JavaScript Relation:** String creation and number-to-string conversion are fundamental to JavaScript.
3. **Code Logic:**  The `NewConsString` function has logic for combining strings and handling different string representations. The number-to-string functions have logic for caching.
4. **Common Errors:** Incorrect length calculations or not handling memory allocation failures are potential errors.
5. **Summary:** The code provides basic factory functions for creating fundamental V8 objects, particularly strings and related data structures, in the heap.

Plan:
- Describe the core functionality: object creation.
- Explain the `.tq` implication.
- Provide JavaScript examples for string creation and number conversion.
- Give an example of the `NewConsString` logic.
- Discuss potential programming errors.
- Summarize the overall function.
好的，这是对 `v8/src/heap/factory-base.cc` 代码片段的功能归纳：

**功能归纳：**

这段代码是 V8 JavaScript 引擎中 `FactoryBase` 模板类的部分实现，主要负责提供创建各种堆上对象的底层方法，特别是针对字符串类型的对象。它封装了原始内存分配和对象初始化的过程，并处理了一些优化和特殊情况。

**具体功能点：**

1. **原始字符串的创建：**
   - `NewRawOneByteString`: 创建指定长度的原始单字节字符串。
   - `NewRawTwoByteString`: 创建指定长度的原始双字节字符串。
   - `NewRawSharedOneByteString`: 创建指定长度的共享单字节字符串。
   - `NewRawSharedTwoByteString`: 创建指定长度的共享双字节字符串。
   - 这些方法通常分配内存，设置字符串的长度和初始哈希值。

2. **ConsString（拼接字符串）的创建：**
   - `NewConsString`: 创建由两个现有字符串拼接而成的新字符串。
   - 它会处理一些优化情况，例如：
     - 如果其中一个字符串为空，则直接返回另一个字符串。
     - 如果拼接后的长度很小，则会创建一个新的扁平（flat）字符串，直接复制内容。
     - 否则，创建一个 `ConsString` 对象，其中包含指向两个原始字符串的指针。

3. **单字符字符串的查找：**
   - `LookupSingleCharacterStringFromCode`: 从内部的单字符字符串表中查找给定编码的字符串，如果不存在则会创建。

4. **从字节数组创建字符串：**
   - `NewStringFromOneByte`: 从单字节数组创建新的字符串对象。它会处理空字符串和单字符字符串的特殊情况。

5. **数字到字符串的转换：**
   - `NumberToString`: 将数字对象（Smi 或 HeapNumber）转换为字符串。
   - `HeapNumberToString`: 将堆上的数字对象转换为字符串。
   - `SmiToString`: 将 Smi（小整数）转换为字符串。
   - 这些方法会尝试使用缓存来提高性能，并处理特殊值（如 0 和 NaN）。

6. **其他堆对象的创建：**
   - `NewBigInt`: 创建 BigInt 对象。
   - `NewScopeInfo`: 创建 ScopeInfo 对象，用于存储作用域信息。
   - `NewSourceTextModuleInfo`: 创建 SourceTextModuleInfo 对象。
   - `NewSharedFunctionInfo`: 创建 SharedFunctionInfo 对象，存储共享的函数信息。
   - `NewDescriptorArray`: 创建 DescriptorArray 对象，用于存储属性描述符。
   - `NewClassPositions`: 创建 ClassPositions 对象。
   - `AllocateRawOneByteInternalizedString`: 分配原始的内部化单字节字符串。
   - `AllocateRawTwoByteInternalizedString`: 分配原始的内部化双字节字符串。
   - `AllocateRawArray`, `AllocateRawFixedArray`, `AllocateRawWeakArrayList`: 分配原始数组相关的对象。
   - `NewWithImmortalMap`, `AllocateRawWithImmortalMap`, `AllocateRaw`: 底层的内存分配方法，并关联对象的 Map（类型信息）。
   - `NewSwissNameDictionaryWithCapacity`, `NewSwissNameDictionary`: 创建 SwissNameDictionary 对象，用于存储属性。
   - `NewFunctionTemplateRareData`: 创建 FunctionTemplateRareData 对象。

7. **内部化字符串相关的辅助方法：**
   - `GetInPlaceInternalizedStringMap`: 获取可原地内部化的字符串的 Map。
   - `RefineAllocationTypeForInPlaceInternalizableString`:  根据字符串的类型优化分配类型，用于内部化字符串。

**关于问题中的其他点：**

* **如果 `v8/src/heap/factory-base.cc` 以 `.tq` 结尾：**
   那么它将是一个 **Torque** 源代码文件。Torque 是 V8 专门用于编写底层运行时代码的领域特定语言。Torque 代码通常用于实现性能关键的操作，并且可以更直接地与 V8 的内部结构交互。

* **与 JavaScript 的功能关系及 JavaScript 示例：**
   这段代码直接支持 JavaScript 中的核心功能，尤其是字符串操作和类型转换。

   ```javascript
   // 字符串创建
   const str1 = 'hello';
   const str2 = 'world';
   const combinedStr = str1 + str2; // 内部会使用类似 NewConsString 的机制

   // 数字到字符串的转换
   const num = 123;
   const numStr = num.toString(); // 内部会使用类似 NumberToString 的机制
   ```

* **代码逻辑推理、假设输入与输出：**
   以 `NewConsString` 为例：

   **假设输入：**
   - `left`:  一个 `Handle<String>`，指向字符串 "abc"。
   - `right`: 一个 `Handle<String>`，指向字符串 "def"。
   - `allocation`: `AllocationType::kYoung` (假设分配在新生代)。

   **代码逻辑：**
   1. 检查 `left` 和 `right` 是否是 ThinString，如果是则获取实际的字符串。
   2. 计算总长度 `length` = 3 + 3 = 6。
   3. 由于 `length` (6) 小于 `ConsString::kMinLength` (假设是某个大于6的值)，代码可能会进入创建扁平字符串的分支。
   4. 创建一个新的扁平字符串（可能是 `SeqOneByteString` 或 `SeqTwoByteString`，取决于输入字符串的编码）。
   5. 将 "abc" 和 "def" 的内容复制到新的扁平字符串中。

   **预期输出：**
   - 返回一个新的 `Handle<String>`，指向内容为 "abcdef" 的扁平字符串对象。

* **涉及用户常见的编程错误：**

   1. **字符串长度溢出：**  尝试拼接非常长的字符串可能会导致长度超出 `String::kMaxLength`，V8 会抛出 `NewInvalidStringLengthError`。

      ```javascript
      let longString = "";
      for (let i = 0; i < Number.MAX_SAFE_INTEGER; i++) {
        longString += "a"; // 这会导致错误
      }
      ```

   2. **内存泄漏（理论上，对于 V8 来说不太可能由用户直接触发）：**  虽然这段 C++ 代码处理了内存分配，但如果 V8 的内部逻辑出现错误，可能会导致内存泄漏。然而，对于 JavaScript 用户来说，V8 的垃圾回收器通常会处理内存管理。

* **总结其功能：**

   这段 `FactoryBase` 的代码是 V8 引擎中负责 **对象创建** 的核心组件，特别是对于各种类型的 **字符串** 和其他基础堆对象。它提供了创建这些对象的底层机制，包括内存分配、初始化以及一些性能优化策略（如字符串扁平化和数字到字符串的缓存）。 这是 V8 引擎高效运行和管理内存的关键部分。

总而言之，这段代码是 V8 引擎的“工厂”，用于生产各种 JavaScript 运行时所需的堆对象，特别是字符串。它隐藏了底层的内存管理细节，并提供了创建和管理这些对象的一致接口。

### 提示词
```
这是目录为v8/src/heap/factory-base.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory-base.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
(length);
  string->set_length(length);
  string->set_raw_hash_field(String::kEmptyHashField);
  DCHECK_EQ(size, string->Size());
  return handle(string, isolate());
}

template <typename Impl>
MaybeHandle<SeqOneByteString> FactoryBase<Impl>::NewRawOneByteString(
    int length, AllocationType allocation) {
  Tagged<Map> map = read_only_roots().seq_one_byte_string_map();
  return NewRawStringWithMap<SeqOneByteString>(
      length, map,
      RefineAllocationTypeForInPlaceInternalizableString(allocation, map));
}

template <typename Impl>
MaybeHandle<SeqTwoByteString> FactoryBase<Impl>::NewRawTwoByteString(
    int length, AllocationType allocation) {
  Tagged<Map> map = read_only_roots().seq_two_byte_string_map();
  return NewRawStringWithMap<SeqTwoByteString>(
      length, map,
      RefineAllocationTypeForInPlaceInternalizableString(allocation, map));
}

template <typename Impl>
MaybeHandle<SeqOneByteString> FactoryBase<Impl>::NewRawSharedOneByteString(
    int length) {
  return NewRawStringWithMap<SeqOneByteString>(
      length, read_only_roots().shared_seq_one_byte_string_map(),
      AllocationType::kSharedOld);
}

template <typename Impl>
MaybeHandle<SeqTwoByteString> FactoryBase<Impl>::NewRawSharedTwoByteString(
    int length) {
  return NewRawStringWithMap<SeqTwoByteString>(
      length, read_only_roots().shared_seq_two_byte_string_map(),
      AllocationType::kSharedOld);
}

template <typename Impl>
MaybeHandle<String> FactoryBase<Impl>::NewConsString(
    Handle<String> left, Handle<String> right, AllocationType allocation) {
  if (IsThinString(*left)) {
    left = handle(Cast<ThinString>(*left)->actual(), isolate());
  }
  if (IsThinString(*right)) {
    right = handle(Cast<ThinString>(*right)->actual(), isolate());
  }
  uint32_t left_length = left->length();
  if (left_length == 0) return right;
  uint32_t right_length = right->length();
  if (right_length == 0) return left;

  uint32_t length = left_length + right_length;

  if (length == 2) {
    uint16_t c1 = left->Get(0, isolate());
    uint16_t c2 = right->Get(0, isolate());
    return MakeOrFindTwoCharacterString(c1, c2);
  }

  // Make sure that an out of memory exception is thrown if the length
  // of the new cons string is too large.
  if (length > String::kMaxLength || length < 0) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }

  bool left_is_one_byte = left->IsOneByteRepresentation();
  bool right_is_one_byte = right->IsOneByteRepresentation();
  bool is_one_byte = left_is_one_byte && right_is_one_byte;

  // If the resulting string is small make a flat string.
  if (length < ConsString::kMinLength) {
    // Note that neither of the two inputs can be a slice because:
    static_assert(ConsString::kMinLength <= SlicedString::kMinLength);
    DCHECK(left->IsFlat());
    DCHECK(right->IsFlat());

    static_assert(ConsString::kMinLength <= String::kMaxLength);
    if (is_one_byte) {
      Handle<SeqOneByteString> result =
          NewRawOneByteString(length, allocation).ToHandleChecked();
      DisallowGarbageCollection no_gc;
      SharedStringAccessGuardIfNeeded access_guard(isolate());
      uint8_t* dest = result->GetChars(no_gc, access_guard);
      // Copy left part.
      {
        const uint8_t* src =
            left->template GetDirectStringChars<uint8_t>(no_gc, access_guard);
        CopyChars(dest, src, left_length);
      }
      // Copy right part.
      {
        const uint8_t* src =
            right->template GetDirectStringChars<uint8_t>(no_gc, access_guard);
        CopyChars(dest + left_length, src, right_length);
      }
      return result;
    }

    Handle<SeqTwoByteString> result =
        NewRawTwoByteString(length, allocation).ToHandleChecked();

    DisallowGarbageCollection no_gc;
    SharedStringAccessGuardIfNeeded access_guard(isolate());
    base::uc16* sink = result->GetChars(no_gc, access_guard);
    String::WriteToFlat(*left, sink, 0, left->length(), access_guard);
    String::WriteToFlat(*right, sink + left->length(), 0, right->length(),
                        access_guard);
    return result;
  }

  return NewConsString(left, right, length, is_one_byte, allocation);
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::NewConsString(DirectHandle<String> left,
                                                DirectHandle<String> right,
                                                int length, bool one_byte,
                                                AllocationType allocation) {
  DCHECK(!IsThinString(*left));
  DCHECK(!IsThinString(*right));
  DCHECK_GE(length, ConsString::kMinLength);
  DCHECK_LE(length, String::kMaxLength);

  Tagged<ConsString> result = Cast<ConsString>(
      one_byte ? NewWithImmortalMap(
                     read_only_roots().cons_one_byte_string_map(), allocation)
               : NewWithImmortalMap(
                     read_only_roots().cons_two_byte_string_map(), allocation));

  DisallowGarbageCollection no_gc;
  WriteBarrierMode mode = result->GetWriteBarrierMode(no_gc);
  result->set_raw_hash_field(String::kEmptyHashField);
  result->set_length(length);
  result->set_first(*left, mode);
  result->set_second(*right, mode);
  return handle(result, isolate());
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::LookupSingleCharacterStringFromCode(
    uint16_t code) {
  if (code <= unibrow::Latin1::kMaxChar) {
    DisallowGarbageCollection no_gc;
    Tagged<Object> value = single_character_string_table()->get(code);
    DCHECK_NE(value, *undefined_value());
    return handle(Cast<String>(value), isolate());
  }
  uint16_t buffer[] = {code};
  return InternalizeString(base::Vector<const uint16_t>(buffer, 1));
}

template <typename Impl>
MaybeHandle<String> FactoryBase<Impl>::NewStringFromOneByte(
    base::Vector<const uint8_t> string, AllocationType allocation) {
  DCHECK_NE(allocation, AllocationType::kReadOnly);
  int length = string.length();
  if (length == 0) return empty_string();
  if (length == 1) return LookupSingleCharacterStringFromCode(string[0]);
  Handle<SeqOneByteString> result;
  ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                             NewRawOneByteString(string.length(), allocation));

  DisallowGarbageCollection no_gc;
  // Copy the characters into the new object.
  // SharedStringAccessGuardIfNeeded is NotNeeded because {result} is freshly
  // allocated and hasn't escaped the factory yet, so it can't be concurrently
  // accessed.
  CopyChars(Cast<SeqOneByteString>(*result)->GetChars(
                no_gc, SharedStringAccessGuardIfNeeded::NotNeeded()),
            string.begin(), length);
  return result;
}
namespace {

template <typename Impl>
V8_INLINE Handle<String> CharToString(FactoryBase<Impl>* factory,
                                      const char* string,
                                      NumberCacheMode mode) {
  // We tenure the allocated string since it is referenced from the
  // number-string cache which lives in the old space.
  AllocationType type = mode == NumberCacheMode::kIgnore
                            ? AllocationType::kYoung
                            : AllocationType::kOld;
  return factory->NewStringFromAsciiChecked(string, type);
}

}  // namespace

template <typename Impl>
Handle<String> FactoryBase<Impl>::NumberToString(DirectHandle<Object> number,
                                                 NumberCacheMode mode) {
  SLOW_DCHECK(IsNumber(*number));
  if (IsSmi(*number)) return SmiToString(Cast<Smi>(*number), mode);

  double double_value = Cast<HeapNumber>(number)->value();
  // Try to canonicalize doubles.
  int smi_value;
  if (DoubleToSmiInteger(double_value, &smi_value)) {
    return SmiToString(Smi::FromInt(smi_value), mode);
  }
  return HeapNumberToString(Cast<HeapNumber>(number), double_value, mode);
}

template <typename Impl>
Handle<String> FactoryBase<Impl>::HeapNumberToString(
    DirectHandle<HeapNumber> number, double value, NumberCacheMode mode) {
  int hash = mode == NumberCacheMode::kIgnore
                 ? 0
                 : impl()->NumberToStringCacheHash(value);

  if (mode == NumberCacheMode::kBoth) {
    Handle<Object> cached = impl()->NumberToStringCacheGet(*number, hash);
    if (!IsUndefined(*cached, isolate())) return Cast<String>(cached);
  }

  Handle<String> result;
  if (value == 0) {
    result = zero_string();
  } else if (std::isnan(value)) {
    result = NaN_string();
  } else {
    char arr[kNumberToStringBufferSize];
    base::Vector<char> buffer(arr, arraysize(arr));
    const char* string = DoubleToCString(value, buffer);
    result = CharToString(this, string, mode);
  }
  if (mode != NumberCacheMode::kIgnore) {
    impl()->NumberToStringCacheSet(number, hash, result);
  }
  return result;
}

template <typename Impl>
inline Handle<String> FactoryBase<Impl>::SmiToString(Tagged<Smi> number,
                                                     NumberCacheMode mode) {
  int hash = mode == NumberCacheMode::kIgnore
                 ? 0
                 : impl()->NumberToStringCacheHash(number);

  if (mode == NumberCacheMode::kBoth) {
    Handle<Object> cached = impl()->NumberToStringCacheGet(number, hash);
    if (!IsUndefined(*cached, isolate())) return Cast<String>(cached);
  }

  Handle<String> result;
  if (number == Smi::zero()) {
    result = zero_string();
  } else {
    char arr[kNumberToStringBufferSize];
    base::Vector<char> buffer(arr, arraysize(arr));
    const char* string = IntToCString(number.value(), buffer);
    result = CharToString(this, string, mode);
  }
  if (mode != NumberCacheMode::kIgnore) {
    impl()->NumberToStringCacheSet(handle(number, isolate()), hash, result);
  }

  // Compute the hash here (rather than letting the caller take care of it) so
  // that the "cache hit" case above doesn't have to bother with it.
  static_assert(Smi::kMaxValue <= std::numeric_limits<uint32_t>::max());
  {
    DisallowGarbageCollection no_gc;
    Tagged<String> raw = *result;
    if (raw->raw_hash_field() == String::kEmptyHashField &&
        number.value() >= 0) {
      uint32_t raw_hash_field = StringHasher::MakeArrayIndexHash(
          static_cast<uint32_t>(number.value()), raw->length());
      raw->set_raw_hash_field(raw_hash_field);
    }
  }
  return result;
}

template <typename Impl>
Handle<FreshlyAllocatedBigInt> FactoryBase<Impl>::NewBigInt(
    uint32_t length, AllocationType allocation) {
  if (length > BigInt::kMaxLength) {
    FATAL("Fatal JavaScript invalid size error %d", length);
    UNREACHABLE();
  }
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(
      BigInt::SizeFor(length), allocation, read_only_roots().bigint_map());
  DisallowGarbageCollection no_gc;
  Tagged<FreshlyAllocatedBigInt> bigint = Cast<FreshlyAllocatedBigInt>(result);
  bigint->clear_padding();
  return handle(bigint, isolate());
}

template <typename Impl>
Handle<ScopeInfo> FactoryBase<Impl>::NewScopeInfo(int length,
                                                  AllocationType type) {
  DCHECK(type == AllocationType::kOld || type == AllocationType::kReadOnly);
  int size = ScopeInfo::SizeFor(length);
  Tagged<HeapObject> obj = AllocateRawWithImmortalMap(
      size, type, read_only_roots().scope_info_map());
  Tagged<ScopeInfo> scope_info = Cast<ScopeInfo>(obj);
  MemsetTagged(scope_info->data_start(), read_only_roots().undefined_value(),
               length);
#if TAGGED_SIZE_8_BYTES
  scope_info->set_optional_padding(0);
#endif
  return handle(scope_info, isolate());
}

template <typename Impl>
Handle<SourceTextModuleInfo> FactoryBase<Impl>::NewSourceTextModuleInfo() {
  return Cast<SourceTextModuleInfo>(NewFixedArrayWithMap(
      read_only_roots().module_info_map_handle(), SourceTextModuleInfo::kLength,
      AllocationType::kOld));
}

template <typename Impl>
Handle<SharedFunctionInfo> FactoryBase<Impl>::NewSharedFunctionInfo(
    AllocationType allocation) {
  Tagged<Map> map = read_only_roots().shared_function_info_map();
  Tagged<SharedFunctionInfo> shared =
      Cast<SharedFunctionInfo>(NewWithImmortalMap(map, allocation));

  DisallowGarbageCollection no_gc;
  shared->Init(read_only_roots(), isolate()->GetAndIncNextUniqueSfiId());
  return handle(shared, isolate());
}

template <typename Impl>
Handle<DescriptorArray> FactoryBase<Impl>::NewDescriptorArray(
    int number_of_descriptors, int slack, AllocationType allocation) {
  int number_of_all_descriptors = number_of_descriptors + slack;
  // Zero-length case must be handled outside.
  DCHECK_LT(0, number_of_all_descriptors);
  int size = DescriptorArray::SizeFor(number_of_all_descriptors);
  Tagged<HeapObject> obj = AllocateRawWithImmortalMap(
      size, allocation, read_only_roots().descriptor_array_map());
  Tagged<DescriptorArray> array = Cast<DescriptorArray>(obj);

  auto raw_gc_state = DescriptorArrayMarkingState::kInitialGCState;
  if (allocation != AllocationType::kYoung &&
      allocation != AllocationType::kReadOnly) {
    auto* local_heap = allocation == AllocationType::kSharedOld
                           ? isolate()->shared_space_isolate()->heap()
                           : isolate()->heap();
    Heap* heap = local_heap->AsHeap();
    if (heap->incremental_marking()->IsMajorMarking()) {
      // Black allocation: We must create a full marked state.
      raw_gc_state = DescriptorArrayMarkingState::GetFullyMarkedState(
          heap->mark_compact_collector()->epoch(), number_of_descriptors);
    }
  }
  array->Initialize(read_only_roots().empty_enum_cache(),
                    read_only_roots().undefined_value(), number_of_descriptors,
                    slack, raw_gc_state);
  return handle(array, isolate());
}

template <typename Impl>
Handle<ClassPositions> FactoryBase<Impl>::NewClassPositions(int start,
                                                            int end) {
  auto result = NewStructInternal<ClassPositions>(CLASS_POSITIONS_TYPE,
                                                  AllocationType::kOld);
  result->set_start(start);
  result->set_end(end);
  return handle(result, isolate());
}

template <typename Impl>
Handle<SeqOneByteString>
FactoryBase<Impl>::AllocateRawOneByteInternalizedString(
    int length, uint32_t raw_hash_field) {
  CHECK_GE(String::kMaxLength, length);
  // The canonical empty_string is the only zero-length string we allow.
  DCHECK_IMPLIES(length == 0, !impl()->EmptyStringRootIsInitialized());

  Tagged<Map> map = read_only_roots().internalized_one_byte_string_map();
  const int size = SeqOneByteString::SizeFor(length);
  const AllocationType allocation =
      RefineAllocationTypeForInPlaceInternalizableString(
          impl()->CanAllocateInReadOnlySpace() ? AllocationType::kReadOnly
                                               : AllocationType::kOld,
          map);
  Tagged<HeapObject> result = AllocateRawWithImmortalMap(size, allocation, map);
  Tagged<SeqOneByteString> answer = Cast<SeqOneByteString>(result);
  DisallowGarbageCollection no_gc;
  answer->clear_padding_destructively(length);
  answer->set_length(length);
  answer->set_raw_hash_field(raw_hash_field);
  DCHECK_EQ(size, answer->Size());
  return handle(answer, isolate());
}

template <typename Impl>
Handle<SeqTwoByteString>
FactoryBase<Impl>::AllocateRawTwoByteInternalizedString(
    int length, uint32_t raw_hash_field) {
  CHECK_GE(String::kMaxLength, length);
  DCHECK_NE(0, length);  // Use Heap::empty_string() instead.

  Tagged<Map> map = read_only_roots().internalized_two_byte_string_map();
  int size = SeqTwoByteString::SizeFor(length);
  Tagged<SeqTwoByteString> answer =
      Cast<SeqTwoByteString>(AllocateRawWithImmortalMap(
          size,
          RefineAllocationTypeForInPlaceInternalizableString(
              AllocationType::kOld, map),
          map));
  DisallowGarbageCollection no_gc;
  answer->clear_padding_destructively(length);
  answer->set_length(length);
  answer->set_raw_hash_field(raw_hash_field);
  DCHECK_EQ(size, answer->Size());
  return handle(answer, isolate());
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawArray(
    int size, AllocationType allocation) {
  Tagged<HeapObject> result = AllocateRaw(size, allocation);
  if ((size >
       isolate()->heap()->AsHeap()->MaxRegularHeapObjectSize(allocation)) &&
      v8_flags.use_marking_progress_bar) {
    LargePageMetadata::FromHeapObject(result)->MarkingProgressTracker().Enable(
        size);
  }
  return result;
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawFixedArray(
    int length, AllocationType allocation) {
  if (length < 0 || length > FixedArray::kMaxLength) {
    FATAL("Fatal JavaScript invalid size error %d", length);
    UNREACHABLE();
  }
  return AllocateRawArray(FixedArray::SizeFor(length), allocation);
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawWeakArrayList(
    int capacity, AllocationType allocation) {
  if (capacity < 0 || capacity > WeakArrayList::kMaxCapacity) {
    FATAL("Fatal JavaScript invalid size error %d", capacity);
    UNREACHABLE();
  }
  return AllocateRawArray(WeakArrayList::SizeForCapacity(capacity), allocation);
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::NewWithImmortalMap(
    Tagged<Map> map, AllocationType allocation) {
  return AllocateRawWithImmortalMap(map->instance_size(), allocation, map);
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRawWithImmortalMap(
    int size, AllocationType allocation, Tagged<Map> map,
    AllocationAlignment alignment) {
  // TODO(delphick): Potentially you could also pass an immortal immovable Map
  // from OLD_SPACE here, like external_map or message_object_map, but currently
  // no one does so this check is sufficient.
  DCHECK(ReadOnlyHeap::Contains(map));
  Tagged<HeapObject> result = AllocateRaw(size, allocation, alignment);
  DisallowGarbageCollection no_gc;
  result->set_map_after_allocation(isolate(), map, SKIP_WRITE_BARRIER);
  return result;
}

template <typename Impl>
Tagged<HeapObject> FactoryBase<Impl>::AllocateRaw(
    int size, AllocationType allocation, AllocationAlignment alignment) {
  return impl()->AllocateRaw(size, allocation, alignment);
}

template <typename Impl>
Handle<SwissNameDictionary>
FactoryBase<Impl>::NewSwissNameDictionaryWithCapacity(
    int capacity, AllocationType allocation) {
  DCHECK(SwissNameDictionary::IsValidCapacity(capacity));

  if (capacity == 0) {
    DCHECK_NE(
        read_only_roots().address_at(RootIndex::kEmptySwissPropertyDictionary),
        kNullAddress);

    return read_only_roots().empty_swiss_property_dictionary_handle();
  }

  if (capacity < 0 || capacity > SwissNameDictionary::MaxCapacity()) {
    FATAL("Fatal JavaScript invalid size error %d", capacity);
    UNREACHABLE();
  }

  int meta_table_length = SwissNameDictionary::MetaTableSizeFor(capacity);
  DirectHandle<ByteArray> meta_table =
      impl()->NewByteArray(meta_table_length, allocation);

  Tagged<Map> map = read_only_roots().swiss_name_dictionary_map();
  int size = SwissNameDictionary::SizeFor(capacity);
  Tagged<SwissNameDictionary> table = Cast<SwissNameDictionary>(
      AllocateRawWithImmortalMap(size, allocation, map));
  DisallowGarbageCollection no_gc;
  table->Initialize(isolate(), *meta_table, capacity);
  return handle(table, isolate());
}

template <typename Impl>
Handle<SwissNameDictionary> FactoryBase<Impl>::NewSwissNameDictionary(
    int at_least_space_for, AllocationType allocation) {
  return NewSwissNameDictionaryWithCapacity(
      SwissNameDictionary::CapacityFor(at_least_space_for), allocation);
}

template <typename Impl>
Handle<FunctionTemplateRareData>
FactoryBase<Impl>::NewFunctionTemplateRareData() {
  auto function_template_rare_data =
      NewStructInternal<FunctionTemplateRareData>(
          FUNCTION_TEMPLATE_RARE_DATA_TYPE, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  function_template_rare_data->set_c_function_overloads(
      *impl()->empty_fixed_array(), SKIP_WRITE_BARRIER);
  return handle(function_template_rare_data, isolate());
}

template <typename Impl>
MaybeDirectHandle<Map> FactoryBase<Impl>::GetInPlaceInternalizedStringMap(
    Tagged<Map> from_string_map) {
  InstanceType instance_type = from_string_map->instance_type();
  MaybeDirectHandle<Map> map;
  switch (instance_type) {
    case SEQ_TWO_BYTE_STRING_TYPE:
    case SHARED_SEQ_TWO_BYTE_STRING_TYPE:
      map = read_only_roots().internalized_two_byte_string_map_handle();
      break;
    case SEQ_ONE_BYTE_STRING_TYPE:
    case SHARED_SEQ_ONE_BYTE_STRING_TYPE:
      map = read_only_roots().internalized_one_byte_string_map_handle();
      break;
    case SHARED_EXTERNAL_TWO_BYTE_STRING_TYPE:
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
      map =
          read_only_roots().external_internalized_two_byte_string_map_handle();
      break;
    case SHARED_EXTERNAL_ONE_BYTE_STRING_TYPE:
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
      map =
          read_only_roots().external_internalized_one_byte_string_map_handle();
      break;
    default:
      break;
  }
  DCHECK_EQ(!map.is_null(), String::IsInPlaceInternalizable(instance_type));
  return map;
}

template <typename Impl>
AllocationType
FactoryBase<Impl>::RefineAllocationTypeForInPlaceInternalizableString(
    AllocationType allocation, Tagged<Map> string_map) {
#ifdef DEBUG
  InstanceType instance_type = string_map->instance_type();
  DCHECK(InstanceTypeChecker::IsInternalizedString(instance_type) ||
         String::IsInPlaceInternalizable(instance_type));
#endif
  if (v8_flags.single_generation && allocation == AllocationType::kYoung) {
    allocation = AllocationType::kOld;
  }
  if (allocation != AllocationType::kOld) return allocation;
  return impl()->AllocationTypeForInPlaceInternalizableString();
}

// Instantiate FactoryBase for the two variants we want.
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) FactoryBase<Factory>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE)
    FactoryBase<LocalFactory>;

}  // namespace internal
}  // namespace v8
```