Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/heap/factory.cc`.

Here's a plan to summarize the code:

1. **Identify the core purpose of `Factory` class:** The `Factory` class in V8 is responsible for creating and allocating various objects on the heap.
2. **Analyze the functions related to string creation:**  The code heavily focuses on creating different types of strings (one-byte, two-byte, external, sliced, internalized, shared) from various sources (UTF-8, two-byte arrays).
3. **Analyze the functions related to symbol creation:** The code includes functions for creating both regular and private symbols.
4. **Analyze the functions related to context creation:** There are multiple functions for creating different types of contexts (native, script, module, function, catch, debug evaluate, with, block, builtin).
5. **Analyze other object creation functions:**  The code also includes functions for creating `JSStringIterator`, `AliasedArgumentsEntry`, `AccessorInfo`, `ErrorStackData`, `Script`, `CallableTask`, `CallbackTask`, and `PromiseResolveThenableJobTask`.
6. **Identify helper functions and logic:** Pay attention to functions like `ComputeInternalizationStrategyForString`, `ComputeSharingStrategyForString`, and the use of `DisallowGarbageCollection`.
7. **Consider the "part 2 of 7" instruction:** This suggests the entire `factory.cc` file is large and this snippet is a section focusing on specific object creations.

Based on these observations, the summary should focus on the string, symbol, context, and other specific object creation functionalities demonstrated in the provided code.
这是 `v8/src/heap/factory.cc` 源代码的**第二部分**，主要功能是**创建和初始化各种V8堆对象**，特别是与**字符串、符号和上下文**相关的对象。

以下是代码片段功能的归纳：

**字符串的创建和管理:**

*   **从UTF-8数据创建字符串 (`NewStringFromUtf8`)**:
    *   可以处理 ASCII 和非 ASCII 的 UTF-8 数据。
    *   如果字符串是 ASCII，则可能创建子字符串。
    *   根据 UTF-16 编码后的长度和字符类型（单字节或双字节）分配 `SeqOneByteString` 或 `SeqTwoByteString`。
    *   解码 UTF-8 数据并复制到新分配的字符串中。
*   **从双字节数据创建字符串 (`NewStringFromTwoByte`)**:
    *   可以从 `base::uc16` 数组或 `ZoneVector<base::uc16>` 创建字符串。
    *   如果双字节数据实际上是单字节字符，则会创建 `SeqOneByteString` 以优化存储。
*   **内部化字符串 (`NewInternalizedStringImpl`, `ComputeInternalizationStrategyForString`, `InternalizeExternalString`)**:
    *   内部化是将具有相同内容的字符串存储在字符串表中的过程，以节省内存。
    *   `ComputeInternalizationStrategyForString` 决定是否需要复制字符串进行内部化，或者是否可以直接在原位置内部化。
    *   根据字符串的类型（单字节或双字节），分配 `SeqOneByteInternalizedString` 或 `SeqTwoByteInternalizedString`。
    *   `InternalizeExternalString` 用于内部化外部字符串。
*   **共享字符串 (`ComputeSharingStrategyForString`)**:
    *   在启用了共享字符串表的情况下，将字符串标记为共享，以便在多个上下文中共享。
    *   `ComputeSharingStrategyForString` 决定是否需要复制字符串进行共享，或者是否可以直接在原位置共享。
*   **创建代理对字符串 (`NewSurrogatePairString`)**:
    *   专门用于创建包含 UTF-16 代理对的字符串。
*   **创建子字符串 (`NewCopiedSubstring`, `NewProperSubString`)**:
    *   `NewCopiedSubstring` 创建原始字符串的副本。
    *   `NewProperSubString` 创建原始字符串的切片，如果切片足够小，则会复制，否则会创建 `SlicedString`。
*   **创建外部字符串 (`NewExternalStringFromOneByte`, `NewExternalStringFromTwoByte`)**:
    *   从外部资源创建字符串，避免在 V8 堆中复制大量数据。
    *   根据资源是否可缓存，创建 `ExternalOneByteString` 或 `UncachedExternalOneByteString`。
*   **创建字符串迭代器 (`NewJSStringIterator`)**:
    *   用于遍历字符串中的字符。

**符号的创建:**

*   **创建符号 (`NewSymbolInternal`, `NewSymbol`, `NewPrivateSymbol`, `NewPrivateNameSymbol`)**:
    *   符号是唯一的标识符。
    *   可以创建普通的符号或私有符号。
    *   私有名字符号与一个字符串名称关联。

**上下文的创建:**

*   **创建各种类型的上下文 (`NewContextInternal`, `NewNativeContext`, `NewScriptContext`, `NewModuleContext`, `NewFunctionContext`, `NewCatchContext`, `NewDebugEvaluateContext`, `NewWithContext`, `NewBlockContext`, `NewBuiltinContext`)**:
    *   上下文是执行 JavaScript 代码的环境，包含变量和作用域信息。
    *   创建不同类型的上下文以适应不同的执行场景，例如：
        *   `NativeContext`:  顶级的全局上下文。
        *   `ScriptContext`:  用于执行脚本的上下文。
        *   `ModuleContext`: 用于执行 ES 模块的上下文。
        *   `FunctionContext`: 用于函数调用的上下文。
        *   `CatchContext`: 用于 `try...catch` 语句的上下文。
        *   `DebugEvaluateContext`: 用于调试求值的上下文。
        *   `WithContext`: 用于 `with` 语句的上下文。
        *   `BlockContext`: 用于块级作用域的上下文。
        *   `BuiltinContext`: 用于内置函数的上下文。
    *   上下文的创建涉及到分配内存、设置原型链、关联作用域信息等。
*   **创建脚本上下文表 (`NewScriptContextTable`)**:
    *   用于存储脚本上下文。

**其他对象的创建:**

*   **创建别名参数条目 (`NewAliasedArgumentsEntry`)**:
    *   用于表示 `arguments` 对象中的别名参数。
*   **创建访问器信息 (`NewAccessorInfo`)**:
    *   用于定义对象属性的 getter 和 setter。
*   **创建错误堆栈数据 (`NewErrorStackData`)**:
    *   存储错误发生时的调用栈信息。
*   **创建脚本对象 (`NewScript`, `CloneScript`)**:
    *   表示一段可执行的 JavaScript 代码。
    *   `CloneScript` 用于复制现有的脚本对象。
*   **创建微任务 (`NewCallableTask`, `NewCallbackTask`, `NewPromiseResolveThenableJobTask`)**:
    *   用于延迟执行的异步任务。
    *   `CallableTask` 包装一个可调用对象。
    *   `CallbackTask` 包装一个 C++ 回调函数。
    *   `NewPromiseResolveThenableJobTask` 用于 Promise 的 `then` 方法的回调。

**代码逻辑推理示例:**

假设输入一个 UTF-8 字符串 "hello"，调用 `Factory::NewStringFromUtf8`。

*   **假设输入:**
    *   `str`: 指向包含 "hello" 的 `base::Vector<const uint8_t>`。
    *   `begin`: 0
    *   `length`: 5
    *   `allocation`: `AllocationType::kNormal`
*   **推理:**
    1. `UTF8Decoder::Decode` 会确定字符串是 ASCII。
    2. 由于是 ASCII，并且长度不为 1，代码会尝试创建子字符串。
    3. 调用 `NewSubString` (虽然这段代码没有直接展示 `NewSubString` 的实现，但可以推断其行为)。
    4. `NewSubString` 可能会创建一个指向原始字符串的 `SeqOneByteString`，并设置适当的偏移量和长度。
*   **假设输出:**  一个 `Handle<String>`，指向一个 `SeqOneByteString` 对象，其内容为 "hello"。

**用户常见的编程错误示例:**

*   **错误使用字符串创建函数:**  用户可能错误地估计字符串的长度，或者传递了不正确的编码数据给字符串创建函数。例如，将 UTF-16 数据传递给期望 UTF-8 数据的 `NewStringFromUtf8` 函数。
    ```javascript
    // 错误示例：将 UTF-16 数据当做 UTF-8 处理
    const utf16Data = new Uint16Array([0x0048, 0x0065, 0x006c, 0x006c, 0x006f]); // "Hello" in UTF-16
    const incorrectString = new TextDecoder().decode(utf16Data); // 错误的解码方式
    ```
    V8 的 `Factory::NewStringFromUtf8` 如果遇到无效的 UTF-8 序列，会采取特定的处理方式（例如替换为坏字符）。

*   **混淆字符串的内部表示:** 用户可能没有意识到 V8 内部会根据字符串的内容选择不同的存储方式（单字节或双字节）。这在需要直接操作字符串底层内存时可能会导致错误。

**总结:**

这段 `v8/src/heap/factory.cc` 的代码片段是 V8 引擎中负责创建和管理核心堆对象的关键部分，特别是针对字符串、符号和上下文这些在 JavaScript 执行中至关重要的概念。它包含了针对不同场景和优化策略的多种创建方法，并处理了诸如字符串内部化、共享以及外部字符串等高级特性。

Prompt: 
```
这是目录为v8/src/heap/factory.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共7部分，请归纳一下它的功能

"""
 a bad character.
    decoder.Decode(&t, utf8_data);
    return LookupSingleCharacterStringFromCode(t);
  }

  if (decoder.is_ascii()) {
    // If the string is ASCII, we can just make a substring.
    // TODO(v8): the allocation flag is ignored in this case.
    return NewSubString(str, begin, begin + length);
  }

  DCHECK_GT(decoder.utf16_length(), 0);

  if (decoder.is_one_byte()) {
    // Allocate string.
    Handle<SeqOneByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), result,
        NewRawOneByteString(decoder.utf16_length(), allocation));
    DisallowGarbageCollection no_gc;
    // Update pointer references, since the original string may have moved after
    // allocation.
    utf8_data =
        base::Vector<const uint8_t>(str->GetChars(no_gc) + begin, length);
    decoder.Decode(result->GetChars(no_gc), utf8_data);
    return result;
  }

  // Allocate string.
  Handle<SeqTwoByteString> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate(), result,
      NewRawTwoByteString(decoder.utf16_length(), allocation));

  DisallowGarbageCollection no_gc;
  // Update pointer references, since the original string may have moved after
  // allocation.
  utf8_data = base::Vector<const uint8_t>(str->GetChars(no_gc) + begin, length);
  decoder.Decode(result->GetChars(no_gc), utf8_data);
  return result;
}

MaybeHandle<String> Factory::NewStringFromTwoByte(const base::uc16* string,
                                                  int length,
                                                  AllocationType allocation) {
  DCHECK_NE(allocation, AllocationType::kReadOnly);
  if (length == 0) return empty_string();
  if (String::IsOneByte(string, length)) {
    if (length == 1) return LookupSingleCharacterStringFromCode(string[0]);
    Handle<SeqOneByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                               NewRawOneByteString(length, allocation));
    DisallowGarbageCollection no_gc;
    CopyChars(result->GetChars(no_gc), string, length);
    return result;
  } else {
    Handle<SeqTwoByteString> result;
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                               NewRawTwoByteString(length, allocation));
    DisallowGarbageCollection no_gc;
    CopyChars(result->GetChars(no_gc), string, length);
    return result;
  }
}

MaybeHandle<String> Factory::NewStringFromTwoByte(
    base::Vector<const base::uc16> string, AllocationType allocation) {
  return NewStringFromTwoByte(string.begin(), string.length(), allocation);
}

MaybeHandle<String> Factory::NewStringFromTwoByte(
    const ZoneVector<base::uc16>* string, AllocationType allocation) {
  return NewStringFromTwoByte(string->data(), static_cast<int>(string->size()),
                              allocation);
}

#if V8_ENABLE_WEBASSEMBLY
MaybeHandle<String> Factory::NewStringFromTwoByteLittleEndian(
    base::Vector<const base::uc16> str, AllocationType allocation) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
  return NewStringFromTwoByte(str, allocation);
#elif defined(V8_TARGET_BIG_ENDIAN)
  // TODO(12868): Duplicate the guts of NewStringFromTwoByte, so that
  // copying and transcoding the data can be done in a single pass.
  UNIMPLEMENTED();
#else
#error Unknown endianness
#endif
}
#endif  // V8_ENABLE_WEBASSEMBLY

Handle<String> Factory::NewInternalizedStringImpl(DirectHandle<String> string,
                                                  int len,
                                                  uint32_t hash_field) {
  if (string->IsOneByteRepresentation()) {
    Handle<SeqOneByteString> result =
        AllocateRawOneByteInternalizedString(len, hash_field);
    DisallowGarbageCollection no_gc;
    String::WriteToFlat(*string, result->GetChars(no_gc), 0, len);
    return result;
  }

  Handle<SeqTwoByteString> result =
      AllocateRawTwoByteInternalizedString(len, hash_field);
  DisallowGarbageCollection no_gc;
  String::WriteToFlat(*string, result->GetChars(no_gc), 0, len);
  return result;
}

StringTransitionStrategy Factory::ComputeInternalizationStrategyForString(
    DirectHandle<String> string, MaybeDirectHandle<Map>* internalized_map) {
  // The serializer requires internalized strings to be in ReadOnlySpace s.t.
  // other objects referencing the string can be allocated in RO space
  // themselves.
  if (isolate()->enable_ro_allocation_for_snapshot() &&
      isolate()->serializer_enabled()) {
    return StringTransitionStrategy::kCopy;
  }
  // Do not internalize young strings in-place: This allows us to ignore both
  // string table and stub cache on scavenges.
  if (HeapLayout::InYoungGeneration(*string)) {
    return StringTransitionStrategy::kCopy;
  }
  // If the string table is shared, we need to copy if the string is not already
  // in the shared heap.
  if (v8_flags.shared_string_table && !HeapLayout::InAnySharedSpace(*string)) {
    return StringTransitionStrategy::kCopy;
  }
  DCHECK_NOT_NULL(internalized_map);
  DisallowGarbageCollection no_gc;
  // This method may be called concurrently, so snapshot the map from the input
  // string instead of the calling IsType methods on HeapObject, which would
  // reload the map each time.
  Tagged<Map> map = string->map();
  *internalized_map = GetInPlaceInternalizedStringMap(map);
  if (!internalized_map->is_null()) {
    return StringTransitionStrategy::kInPlace;
  }
  if (InstanceTypeChecker::IsInternalizedString(map)) {
    return StringTransitionStrategy::kAlreadyTransitioned;
  }
  return StringTransitionStrategy::kCopy;
}

template <class StringClass>
Handle<StringClass> Factory::InternalizeExternalString(
    DirectHandle<String> string) {
  DirectHandle<Map> map =
      GetInPlaceInternalizedStringMap(string->map()).ToHandleChecked();
  Tagged<StringClass> external_string =
      Cast<StringClass>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  external_string->InitExternalPointerFields(isolate());
  Tagged<StringClass> cast_string = Cast<StringClass>(*string);
  external_string->set_length(cast_string->length());
  external_string->set_raw_hash_field(cast_string->raw_hash_field());
  external_string->SetResource(isolate(), nullptr);
  isolate()->heap()->RegisterExternalString(external_string);
  return handle(external_string, isolate());
}

template Handle<ExternalOneByteString> Factory::InternalizeExternalString<
    ExternalOneByteString>(DirectHandle<String>);
template Handle<ExternalTwoByteString> Factory::InternalizeExternalString<
    ExternalTwoByteString>(DirectHandle<String>);

StringTransitionStrategy Factory::ComputeSharingStrategyForString(
    DirectHandle<String> string, MaybeDirectHandle<Map>* shared_map) {
  DCHECK(v8_flags.shared_string_table);
  // TODO(pthier): Avoid copying LO-space strings. Update page flags instead.
  if (!HeapLayout::InAnySharedSpace(*string)) {
    return StringTransitionStrategy::kCopy;
  }
  DCHECK_NOT_NULL(shared_map);
  DisallowGarbageCollection no_gc;
  InstanceType instance_type = string->map()->instance_type();
  if (StringShape(instance_type).IsShared()) {
    return StringTransitionStrategy::kAlreadyTransitioned;
  }
  switch (instance_type) {
    case SEQ_TWO_BYTE_STRING_TYPE:
      *shared_map = read_only_roots().shared_seq_two_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case SEQ_ONE_BYTE_STRING_TYPE:
      *shared_map = read_only_roots().shared_seq_one_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case EXTERNAL_TWO_BYTE_STRING_TYPE:
      *shared_map =
          read_only_roots().shared_external_two_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case EXTERNAL_ONE_BYTE_STRING_TYPE:
      *shared_map =
          read_only_roots().shared_external_one_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case UNCACHED_EXTERNAL_TWO_BYTE_STRING_TYPE:
      *shared_map = read_only_roots()
                        .shared_uncached_external_two_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    case UNCACHED_EXTERNAL_ONE_BYTE_STRING_TYPE:
      *shared_map = read_only_roots()
                        .shared_uncached_external_one_byte_string_map_handle();
      return StringTransitionStrategy::kInPlace;
    default:
      return StringTransitionStrategy::kCopy;
  }
}

Handle<String> Factory::NewSurrogatePairString(uint16_t lead, uint16_t trail) {
  DCHECK_GE(lead, 0xD800);
  DCHECK_LE(lead, 0xDBFF);
  DCHECK_GE(trail, 0xDC00);
  DCHECK_LE(trail, 0xDFFF);

  Handle<SeqTwoByteString> str =
      isolate()->factory()->NewRawTwoByteString(2).ToHandleChecked();
  DisallowGarbageCollection no_gc;
  base::uc16* dest = str->GetChars(no_gc);
  dest[0] = lead;
  dest[1] = trail;
  return str;
}

Handle<String> Factory::NewCopiedSubstring(DirectHandle<String> str,
                                           uint32_t begin, uint32_t length) {
  DCHECK(str->IsFlat());  // Callers must flatten.
  DCHECK_GT(length, 0);   // Callers must handle empty string.
  bool one_byte;
  {
    DisallowGarbageCollection no_gc;
    String::FlatContent flat = str->GetFlatContent(no_gc);
    if (flat.IsOneByte()) {
      one_byte = true;
    } else {
      one_byte = String::IsOneByte(flat.ToUC16Vector().data() + begin, length);
    }
  }
  if (one_byte) {
    Handle<SeqOneByteString> result =
        NewRawOneByteString(length).ToHandleChecked();
    DisallowGarbageCollection no_gc;
    uint8_t* dest = result->GetChars(no_gc);
    String::WriteToFlat(*str, dest, begin, length);
    return result;
  } else {
    Handle<SeqTwoByteString> result =
        NewRawTwoByteString(length).ToHandleChecked();
    DisallowGarbageCollection no_gc;
    base::uc16* dest = result->GetChars(no_gc);
    String::WriteToFlat(*str, dest, begin, length);
    return result;
  }
}

Handle<String> Factory::NewProperSubString(Handle<String> str, uint32_t begin,
                                           uint32_t end) {
#if VERIFY_HEAP
  if (v8_flags.verify_heap) str->StringVerify(isolate());
#endif
  DCHECK_LE(begin, str->length());
  DCHECK_LE(end, str->length());

  str = String::Flatten(isolate(), str);

  if (begin >= end) return empty_string();
  uint32_t length = end - begin;

  if (length == 1) {
    return LookupSingleCharacterStringFromCode(str->Get(begin));
  }
  if (length == 2) {
    // Optimization for 2-byte strings often used as keys in a decompression
    // dictionary.  Check whether we already have the string in the string
    // table to prevent creation of many unnecessary strings.
    uint16_t c1 = str->Get(begin);
    uint16_t c2 = str->Get(begin + 1);
    return MakeOrFindTwoCharacterString(c1, c2);
  }

  if (!v8_flags.string_slices || length < SlicedString::kMinLength) {
    return NewCopiedSubstring(str, begin, length);
  }

  int offset = begin;

  if (IsSlicedString(*str)) {
    auto slice = Cast<SlicedString>(str);
    str = Handle<String>(slice->parent(), isolate());
    offset += slice->offset();
  }
  if (IsThinString(*str)) {
    auto thin = Cast<ThinString>(str);
    str = handle(thin->actual(), isolate());
  }

  DCHECK(IsSeqString(*str) || IsExternalString(*str));
  DirectHandle<Map> map = str->IsOneByteRepresentation()
                              ? sliced_one_byte_string_map()
                              : sliced_two_byte_string_map();
  Tagged<SlicedString> slice =
      Cast<SlicedString>(New(map, AllocationType::kYoung));
  DisallowGarbageCollection no_gc;
  slice->set_raw_hash_field(String::kEmptyHashField);
  slice->set_length(length);
  slice->set_parent(*str);
  slice->set_offset(offset);
  return handle(slice, isolate());
}

MaybeHandle<String> Factory::NewExternalStringFromOneByte(
    const ExternalOneByteString::Resource* resource) {
  size_t length = resource->length();
  if (length > static_cast<size_t>(String::kMaxLength)) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }
  if (length == 0) return empty_string();

  DirectHandle<Map> map = resource->IsCacheable()
                              ? external_one_byte_string_map()
                              : uncached_external_one_byte_string_map();
  Tagged<ExternalOneByteString> external_string =
      Cast<ExternalOneByteString>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  external_string->InitExternalPointerFields(isolate());
  external_string->set_length(static_cast<int>(length));
  external_string->set_raw_hash_field(String::kEmptyHashField);
  external_string->SetResource(isolate(), resource);

  isolate()->heap()->RegisterExternalString(external_string);

  return Handle<String>(external_string, isolate());
}

MaybeHandle<String> Factory::NewExternalStringFromTwoByte(
    const ExternalTwoByteString::Resource* resource) {
  size_t length = resource->length();
  if (length > static_cast<size_t>(String::kMaxLength)) {
    THROW_NEW_ERROR(isolate(), NewInvalidStringLengthError());
  }
  if (length == 0) return empty_string();

  DirectHandle<Map> map = resource->IsCacheable()
                              ? external_two_byte_string_map()
                              : uncached_external_two_byte_string_map();
  Tagged<ExternalTwoByteString> string =
      Cast<ExternalTwoByteString>(New(map, AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  string->InitExternalPointerFields(isolate());
  string->set_length(static_cast<int>(length));
  string->set_raw_hash_field(String::kEmptyHashField);
  string->SetResource(isolate(), resource);

  isolate()->heap()->RegisterExternalString(string);

  return Handle<ExternalTwoByteString>(string, isolate());
}

Handle<JSStringIterator> Factory::NewJSStringIterator(Handle<String> string) {
  DirectHandle<Map> map(
      isolate()->native_context()->initial_string_iterator_map(), isolate());
  DirectHandle<String> flat_string = String::Flatten(isolate(), string);
  Handle<JSStringIterator> iterator =
      Cast<JSStringIterator>(NewJSObjectFromMap(map));

  DisallowGarbageCollection no_gc;
  Tagged<JSStringIterator> raw = *iterator;
  raw->set_string(*flat_string);
  raw->set_index(0);
  return iterator;
}

Tagged<Symbol> Factory::NewSymbolInternal(AllocationType allocation) {
  DCHECK(allocation != AllocationType::kYoung);
  // Statically ensure that it is safe to allocate symbols in paged spaces.
  static_assert(sizeof(Symbol) <= kMaxRegularHeapObjectSize);

  Tagged<Symbol> symbol = Cast<Symbol>(AllocateRawWithImmortalMap(
      sizeof(Symbol), allocation, read_only_roots().symbol_map()));
  DisallowGarbageCollection no_gc;
  // Generate a random hash value.
  int hash = isolate()->GenerateIdentityHash(Name::HashBits::kMax);
  symbol->set_raw_hash_field(
      Name::CreateHashFieldValue(hash, Name::HashFieldType::kHash));
  if (isolate()->read_only_heap()->roots_init_complete()) {
    symbol->set_description(read_only_roots().undefined_value(),
                            SKIP_WRITE_BARRIER);
  } else {
    // Can't use setter during bootstrapping as its typecheck tries to access
    // the roots table before it is initialized.
    symbol->description_.store(&*symbol, read_only_roots().undefined_value(),
                               SKIP_WRITE_BARRIER);
  }
  symbol->set_flags(0);
  DCHECK(!symbol->is_private());
  return symbol;
}

Handle<Symbol> Factory::NewSymbol(AllocationType allocation) {
  return handle(NewSymbolInternal(allocation), isolate());
}

Handle<Symbol> Factory::NewPrivateSymbol(AllocationType allocation) {
  DCHECK(allocation != AllocationType::kYoung);
  Tagged<Symbol> symbol = NewSymbolInternal(allocation);
  DisallowGarbageCollection no_gc;
  symbol->set_is_private(true);
  return handle(symbol, isolate());
}

Handle<Symbol> Factory::NewPrivateNameSymbol(DirectHandle<String> name) {
  Tagged<Symbol> symbol = NewSymbolInternal();
  DisallowGarbageCollection no_gc;
  symbol->set_is_private_name();
  symbol->set_description(*name);
  return handle(symbol, isolate());
}

Tagged<Context> Factory::NewContextInternal(DirectHandle<Map> map, int size,
                                            int variadic_part_length,
                                            AllocationType allocation) {
  DCHECK_LE(Context::kTodoHeaderSize, size);
  DCHECK(IsAligned(size, kTaggedSize));
  DCHECK_LE(Context::MIN_CONTEXT_SLOTS, variadic_part_length);
  DCHECK_LE(Context::SizeFor(variadic_part_length), size);

  Tagged<HeapObject> result =
      allocator()->AllocateRawWith<HeapAllocator::kRetryOrFail>(size,
                                                                allocation);
  result->set_map_after_allocation(isolate(), *map);
  DisallowGarbageCollection no_gc;
  Tagged<Context> context = Cast<Context>(result);
  context->set_length(variadic_part_length);
  DCHECK_EQ(context->SizeFromMap(*map), size);
  if (size > Context::kTodoHeaderSize) {
    ObjectSlot start = context->RawField(Context::kTodoHeaderSize);
    ObjectSlot end = context->RawField(size);
    size_t slot_count = end - start;
    MemsetTagged(start, *undefined_value(), slot_count);
  }
  return context;
}

// Creates new maps and new native context and wires them up.
//
// +-+------------->|NativeContext|
// | |                    |
// | |                   map
// | |                    v
// | |              |context_map| <Map(NATIVE_CONTEXT_TYPE)>
// | |                  |   |
// | +--native_context--+  map
// |                        v
// |   +------->|contextful_meta_map| <Map(MAP_TYPE)>
// |   |             |      |
// |   +-----map-----+      |
// |                        |
// +-----native_context-----+
//
Handle<NativeContext> Factory::NewNativeContext() {
  // All maps that belong to this new native context will have this meta map.
  // The native context does not exist yet, so create the map as contextless
  // for now.
  Handle<Map> contextful_meta_map = NewContextlessMap(MAP_TYPE, Map::kSize);
  contextful_meta_map->set_map(isolate(), *contextful_meta_map);

  Handle<Map> context_map = NewMapWithMetaMap(
      contextful_meta_map, NATIVE_CONTEXT_TYPE, kVariableSizeSentinel);

  if (v8_flags.log_maps) {
    LOG(isolate(),
        MapEvent("NewNativeContext", isolate()->factory()->meta_map(),
                 contextful_meta_map, "contextful meta map"));
    LOG(isolate(),
        MapEvent("NewNativeContext", isolate()->factory()->meta_map(),
                 context_map, "native context map"));
  }

  Tagged<NativeContext> context = Cast<NativeContext>(NewContextInternal(
      context_map, NativeContext::kSize, NativeContext::NATIVE_CONTEXT_SLOTS,
      AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  contextful_meta_map->set_native_context(context);
  context_map->set_native_context(context);
  context->set_meta_map(*contextful_meta_map);
  context->set_scope_info(*native_scope_info());
  context->set_previous(Context());
  context->set_extension(*undefined_value());
  context->set_errors_thrown(Smi::zero());
  context->set_is_wasm_js_installed(Smi::zero());
  context->set_is_wasm_jspi_installed(Smi::zero());
  context->set_math_random_index(Smi::zero());
  context->set_serialized_objects(*empty_fixed_array());
  context->init_microtask_queue(isolate(), nullptr);
  context->set_retained_maps(*empty_weak_array_list());
  return handle(context, isolate());
}

Handle<Context> Factory::NewScriptContext(DirectHandle<NativeContext> outer,
                                          DirectHandle<ScopeInfo> scope_info) {
  DCHECK(scope_info->is_script_scope());
  int variadic_part_length = scope_info->ContextLength();

  DirectHandle<FixedArray> side_data;
  if (v8_flags.const_tracking_let ||
      v8_flags.script_context_mutable_heap_number) {
    side_data = NewFixedArray(scope_info->ContextLocalCount());
  } else {
    side_data = empty_fixed_array();
  }
  Tagged<Context> context =
      NewContextInternal(handle(outer->script_context_map(), isolate()),
                         Context::SizeFor(variadic_part_length),
                         variadic_part_length, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  context->set_scope_info(*scope_info);
  context->set_previous(*outer);
  context->set(Context::CONTEXT_SIDE_TABLE_PROPERTY_INDEX, *side_data);
  DCHECK(context->IsScriptContext());
  return handle(context, isolate());
}

Handle<ScriptContextTable> Factory::NewScriptContextTable() {
  static constexpr int kInitialCapacity = 0;
  return ScriptContextTable::New(isolate(), kInitialCapacity);
}

Handle<Context> Factory::NewModuleContext(DirectHandle<SourceTextModule> module,
                                          DirectHandle<NativeContext> outer,
                                          DirectHandle<ScopeInfo> scope_info) {
  // TODO(v8:13567): Const tracking let in module contexts.
  DCHECK_EQ(scope_info->scope_type(), MODULE_SCOPE);
  int variadic_part_length = scope_info->ContextLength();
  Tagged<Context> context = NewContextInternal(
      isolate()->module_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kOld);
  DisallowGarbageCollection no_gc;
  context->set_scope_info(*scope_info);
  context->set_previous(*outer);
  context->set_extension(*module);
  DCHECK(context->IsModuleContext());
  return handle(context, isolate());
}

Handle<Context> Factory::NewFunctionContext(
    DirectHandle<Context> outer, DirectHandle<ScopeInfo> scope_info) {
  DirectHandle<Map> map;
  switch (scope_info->scope_type()) {
    case EVAL_SCOPE:
      map = isolate()->eval_context_map();
      break;
    case FUNCTION_SCOPE:
      map = isolate()->function_context_map();
      break;
    default:
      UNREACHABLE();
  }
  int variadic_part_length = scope_info->ContextLength();
  Tagged<Context> context =
      NewContextInternal(map, Context::SizeFor(variadic_part_length),
                         variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  context->set_scope_info(*scope_info);
  context->set_previous(*outer);
  return handle(context, isolate());
}

#if V8_SINGLE_GENERATION_BOOL
#define DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate, object)
#elif V8_ENABLE_STICKY_MARK_BITS_BOOL
#define DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate, object)             \
  DCHECK_IMPLIES(!isolate->heap()->incremental_marking()->IsMajorMarking(), \
                 HeapLayout::InYoungGeneration(object))
#else
#define DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate, object) \
  DCHECK(HeapLayout::InYoungGeneration(object))
#endif

Handle<Context> Factory::NewCatchContext(DirectHandle<Context> previous,
                                         DirectHandle<ScopeInfo> scope_info,
                                         DirectHandle<Object> thrown_object) {
  DCHECK_EQ(scope_info->scope_type(), CATCH_SCOPE);
  static_assert(Context::MIN_CONTEXT_SLOTS == Context::THROWN_OBJECT_INDEX);
  // TODO(ishell): Take the details from CatchContext class.
  int variadic_part_length = Context::MIN_CONTEXT_SLOTS + 1;
  Tagged<Context> context = NewContextInternal(
      isolate()->catch_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  context->set(Context::THROWN_OBJECT_INDEX, *thrown_object,
               SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<Context> Factory::NewDebugEvaluateContext(
    DirectHandle<Context> previous, DirectHandle<ScopeInfo> scope_info,
    DirectHandle<JSReceiver> extension, DirectHandle<Context> wrapped) {
  DCHECK(scope_info->IsDebugEvaluateScope());
  DirectHandle<HeapObject> ext = extension.is_null()
                                     ? Cast<HeapObject>(undefined_value())
                                     : Cast<HeapObject>(extension);
  // TODO(ishell): Take the details from DebugEvaluateContextContext class.
  int variadic_part_length = Context::MIN_CONTEXT_EXTENDED_SLOTS + 1;
  Tagged<Context> context =
      NewContextInternal(isolate()->debug_evaluate_context_map(),
                         Context::SizeFor(variadic_part_length),
                         variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  context->set_extension(*ext, SKIP_WRITE_BARRIER);
  if (!wrapped.is_null()) {
    context->set(Context::WRAPPED_CONTEXT_INDEX, *wrapped, SKIP_WRITE_BARRIER);
  }
  return handle(context, isolate());
}

Handle<Context> Factory::NewWithContext(DirectHandle<Context> previous,
                                        DirectHandle<ScopeInfo> scope_info,
                                        DirectHandle<JSReceiver> extension) {
  DCHECK_EQ(scope_info->scope_type(), WITH_SCOPE);
  // TODO(ishell): Take the details from WithContext class.
  int variadic_part_length = Context::MIN_CONTEXT_EXTENDED_SLOTS;
  Tagged<Context> context = NewContextInternal(
      isolate()->with_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  context->set_extension(*extension, SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<Context> Factory::NewBlockContext(DirectHandle<Context> previous,
                                         DirectHandle<ScopeInfo> scope_info) {
  DCHECK_IMPLIES(scope_info->scope_type() != BLOCK_SCOPE,
                 scope_info->scope_type() == CLASS_SCOPE);
  int variadic_part_length = scope_info->ContextLength();
  Tagged<Context> context = NewContextInternal(
      isolate()->block_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(*scope_info, SKIP_WRITE_BARRIER);
  context->set_previous(*previous, SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<Context> Factory::NewBuiltinContext(
    DirectHandle<NativeContext> native_context, int variadic_part_length) {
  DCHECK_LE(Context::MIN_CONTEXT_SLOTS, variadic_part_length);
  Tagged<Context> context = NewContextInternal(
      isolate()->function_context_map(), Context::SizeFor(variadic_part_length),
      variadic_part_length, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  DCHECK_NEWLY_ALLOCATED_OBJECT_IS_YOUNG(isolate(), context);
  context->set_scope_info(read_only_roots().empty_scope_info(),
                          SKIP_WRITE_BARRIER);
  context->set_previous(*native_context, SKIP_WRITE_BARRIER);
  return handle(context, isolate());
}

Handle<AliasedArgumentsEntry> Factory::NewAliasedArgumentsEntry(
    int aliased_context_slot) {
  auto entry = NewStructInternal<AliasedArgumentsEntry>(
      ALIASED_ARGUMENTS_ENTRY_TYPE, AllocationType::kYoung);
  entry->set_aliased_context_slot(aliased_context_slot);
  return handle(entry, isolate());
}

Handle<AccessorInfo> Factory::NewAccessorInfo() {
  Tagged<AccessorInfo> info =
      Cast<AccessorInfo>(New(accessor_info_map(), AllocationType::kOld));
  DisallowGarbageCollection no_gc;
  info->set_name(*empty_string(), SKIP_WRITE_BARRIER);
  info->set_data(*undefined_value(), SKIP_WRITE_BARRIER);
  info->set_flags(0);  // Must clear the flags, it was initialized as undefined.
  info->set_is_sloppy(true);
  info->set_initial_property_attributes(NONE);

  info->init_getter(isolate(), kNullAddress);
  info->init_setter(isolate(), kNullAddress);

  info->clear_padding();

  return handle(info, isolate());
}

Handle<ErrorStackData> Factory::NewErrorStackData(
    DirectHandle<UnionOf<JSAny, FixedArray>> call_site_infos_or_formatted_stack,
    DirectHandle<StackTraceInfo> stack_trace) {
  Tagged<ErrorStackData> error_stack_data = NewStructInternal<ErrorStackData>(
      ERROR_STACK_DATA_TYPE, AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  error_stack_data->set_call_site_infos_or_formatted_stack(
      *call_site_infos_or_formatted_stack, SKIP_WRITE_BARRIER);
  error_stack_data->set_stack_trace(*stack_trace, SKIP_WRITE_BARRIER);
  return handle(error_stack_data, isolate());
}

void Factory::ProcessNewScript(Handle<Script> script,
                               ScriptEventType script_event_type) {
  int script_id = script->id();
  if (script_id != Script::kTemporaryScriptId) {
    Handle<WeakArrayList> scripts = script_list();
    scripts = WeakArrayList::Append(isolate(), scripts,
                                    MaybeObjectDirectHandle::Weak(script),
                                    AllocationType::kOld);
    isolate()->heap()->set_script_list(*scripts);
  }
  if (IsString(script->source()) && isolate()->NeedsSourcePositions()) {
    Script::InitLineEnds(isolate(), script);
  }
  LOG(isolate(), ScriptEvent(script_event_type, script_id));
}

Handle<Script> Factory::CloneScript(DirectHandle<Script> script,
                                    DirectHandle<String> source) {
  int script_id = isolate()->GetNextScriptId();
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
  Handle<ArrayList> list = ArrayList::New(isolate(), 0);
#endif
  Handle<Script> new_script_handle =
      Cast<Script>(NewStruct(SCRIPT_TYPE, AllocationType::kOld));
  {
    DisallowGarbageCollection no_gc;
    Tagged<Script> new_script = *new_script_handle;
    const Tagged<Script> old_script = *script;
    new_script->set_source(*source);
    new_script->set_name(old_script->name());
    new_script->set_id(script_id);
    new_script->set_line_offset(old_script->line_offset());
    new_script->set_column_offset(old_script->column_offset());
    new_script->set_context_data(old_script->context_data());
    new_script->set_type(old_script->type());
    new_script->set_line_ends(Smi::zero());
    new_script->set_eval_from_shared_or_wrapped_arguments(
        script->eval_from_shared_or_wrapped_arguments());
    new_script->set_infos(*empty_weak_fixed_array(), SKIP_WRITE_BARRIER);
    new_script->set_eval_from_position(old_script->eval_from_position());
    new_script->set_flags(old_script->flags());
    new_script->set_host_defined_options(old_script->host_defined_options());
    new_script->set_source_hash(*undefined_value(), SKIP_WRITE_BARRIER);
    new_script->set_compiled_lazy_function_positions(*undefined_value(),
                                                     SKIP_WRITE_BARRIER);
#ifdef V8_SCRIPTORMODULE_LEGACY_LIFETIME
    new_script->set_script_or_modules(*list);
#endif
  }
  ProcessNewScript(new_script_handle, ScriptEventType::kCreate);
  return new_script_handle;
}

Handle<CallableTask> Factory::NewCallableTask(DirectHandle<JSReceiver> callable,
                                              DirectHandle<Context> context) {
  DCHECK(IsCallable(*callable));
  auto microtask = NewStructInternal<CallableTask>(CALLABLE_TASK_TYPE,
                                                   AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  microtask->set_callable(*callable, SKIP_WRITE_BARRIER);
  microtask->set_context(*context, SKIP_WRITE_BARRIER);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  microtask->set_continuation_preserved_embedder_data(
      isolate()->isolate_data()->continuation_preserved_embedder_data(),
      SKIP_WRITE_BARRIER);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return handle(microtask, isolate());
}

Handle<CallbackTask> Factory::NewCallbackTask(DirectHandle<Foreign> callback,
                                              DirectHandle<Foreign> data) {
  auto microtask = NewStructInternal<CallbackTask>(CALLBACK_TASK_TYPE,
                                                   AllocationType::kYoung);
  DisallowGarbageCollection no_gc;
  microtask->set_callback(*callback, SKIP_WRITE_BARRIER);
  microtask->set_data(*data, SKIP_WRITE_BARRIER);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  microtask->set_continuation_preserved_embedder_data(
      isolate()->isolate_data()->continuation_preserved_embedder_data(),
      SKIP_WRITE_BARRIER);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  return handle(microtask, isolate());
}

Handle<PromiseResolveThenableJobTask> Factory::NewPromiseResolveThenableJobTask(
    DirectHandle<JSPromise> promise_to_resolve,
    DirectHandle<JSReceiver> thenable, DirectHandle<JSReceiver> then,
    DirectHandle<Context> context) {
  DCH
"""


```