Response: The user wants a summary of the C++ code provided, specifically the `ValueDeserializer` class methods in the `v8/src/objects/value-serializer.cc` file. They've indicated this is part 2 of 2, suggesting the previous part described the serialization process. Therefore, this part should focus on *deserialization*, converting serialized data back into JavaScript objects. If a method relates to a JavaScript feature, I need to provide a JavaScript example.

Here's a breakdown of the methods and their probable functionality:

* **`ReadSparseJSArray()`**:  Handles deserializing sparse JavaScript arrays.
* **`ReadDenseJSArray()`**: Handles deserializing dense JavaScript arrays.
* **`ReadJSDate()`**:  Handles deserializing `Date` objects.
* **`ReadJSPrimitiveWrapper()`**: Handles deserializing wrapper objects for primitive types (Boolean, Number, BigInt, String).
* **`ReadJSRegExp()`**: Handles deserializing `RegExp` objects.
* **`ReadJSMap()`**: Handles deserializing `Map` objects.
* **`ReadJSSet()`**: Handles deserializing `Set` objects.
* **`ReadJSArrayBuffer()`**: Handles deserializing `ArrayBuffer` objects (including Shared and Resizable ArrayBuffers).
* **`ReadTransferredJSArrayBuffer()`**: Handles deserializing `ArrayBuffer`s that were transferred (likely detached from the original context).
* **`ReadJSArrayBufferView()`**: Handles deserializing `TypedArray` and `DataView` objects.
* **`ValidateJSArrayBufferViewFlags()`**: A helper function to validate flags associated with `ArrayBufferView`s during deserialization.
* **`ReadJSError()`**: Handles deserializing `Error` objects (including different error types and their properties like `message`, `stack`, and `cause`).
* **`ReadWasmModuleTransfer()`**: Handles deserializing WebAssembly `Module` objects that were transferred.
* **`ReadWasmMemory()`**: Handles deserializing WebAssembly `Memory` objects.
* **`ReadSharedObject()`**: Handles deserializing shared objects (likely related to shared memory or cross-context communication).
* **`ReadHostObject()`**: Handles deserializing host-defined objects.
* **`CommitProperties()`**: A static helper function to efficiently set properties on a newly created object.
* **`ReadJSObjectProperties()`**: Handles deserializing the properties of a JavaScript object.
* **`HasObjectWithID()`**: Checks if an object with a given ID has already been deserialized.
* **`GetObjectWithID()`**: Retrieves a previously deserialized object using its ID (used for handling references).
* **`AddObjectWithID()`**: Registers a newly deserialized object with an ID for later reference.
* **`SetPropertiesFromKeyValuePairs()`**: A static helper function to set properties from an array of key-value pairs (used for older serialization formats).
* **`ReadObjectUsingEntireBufferForLegacyFormat()`**: Handles deserialization for a legacy serialization format.

The general flow seems to be: read a tag indicating the type of object, read the object's data based on its type, potentially read nested objects recursively, and reconstruct the JavaScript object. The `id_map_` and `next_id_` variables are used to handle circular references by assigning IDs to deserialized objects.
这是 `v8/src/objects/value-serializer.cc` 文件中 `ValueDeserializer` 类的部分源代码，主要负责**将之前序列化的数据反序列化为 JavaScript 对象**。这是序列化过程的逆向操作。

**核心功能概括:**

* **读取序列化数据流:**  `ValueDeserializer` 从输入流中读取字节，并根据预定义的格式（由 `ValueSerializer` 写入）解析这些字节。
* **重建 JavaScript 对象:**  根据读取到的数据，创建相应的 JavaScript 对象，例如：
    * `ReadSparseJSArray` 和 `ReadDenseJSArray`:  创建稀疏或稠密的 JavaScript 数组。
    * `ReadJSDate`: 创建 `Date` 对象。
    * `ReadJSPrimitiveWrapper`: 创建基本类型（Boolean, Number, String, BigInt）的包装对象。
    * `ReadJSRegExp`: 创建 `RegExp` 对象。
    * `ReadJSMap` 和 `ReadJSSet`: 创建 `Map` 和 `Set` 对象。
    * `ReadJSArrayBuffer`: 创建 `ArrayBuffer` 对象（包括 SharedArrayBuffer 和 Resizable ArrayBuffer）。
    * `ReadJSArrayBufferView`: 创建 `TypedArray` (如 Int8Array, Uint32Array 等) 和 `DataView` 对象。
    * `ReadJSError`: 创建各种 `Error` 对象 (如 TypeError, RangeError 等)，并恢复其 `message`、`stack` 和 `cause` 属性。
    * `ReadWasmModuleTransfer` 和 `ReadWasmMemory`:  创建 WebAssembly 的 `Module` 和 `Memory` 对象（如果启用了 WebAssembly）。
    * `ReadHostObject`:  允许宿主环境（例如浏览器或 Node.js）自定义反序列化过程。
* **处理对象引用:**  `ValueDeserializer` 维护一个已反序列化对象的 ID 映射 (`id_map_`)，以处理循环引用。当遇到之前已经反序列化的对象时，它会直接引用已存在的对象，而不是创建新的对象。
* **处理属性:** `ReadJSObjectProperties` 方法负责读取和设置 JavaScript 对象的属性。它可以优化属性设置过程，如果属性键是字符串且存在映射过渡。
* **错误处理:**  在反序列化过程中，如果遇到格式错误或数据不一致，`ValueDeserializer` 会返回 `MaybeHandle`，表示操作可能失败。
* **兼容旧版本:**  `ReadObjectUsingEntireBufferForLegacyFormat` 方法处理旧版本的序列化格式。

**与 JavaScript 的关系及示例:**

`ValueDeserializer` 的主要作用是将 JavaScript 数据结构序列化后的字节流还原为 JavaScript 可以直接使用的对象。

**JavaScript 示例:**

假设我们有以下 JavaScript 代码，使用 `structuredClone` 或类似机制进行了序列化和反序列化：

```javascript
const originalArray = [1, 'hello', { a: 2 }];
const originalDate = new Date();
const originalMap = new Map([['key', 'value']]);

// 模拟序列化过程 (ValueSerializer 的工作)
// ...

// 模拟反序列化过程 (ValueDeserializer 的工作)
// 假设 serializedData 是序列化后的数据
// const deserializedData = ValueDeserializer.deserialize(serializedData); // 实际 API 可能不同

// 内部实现中，ValueDeserializer 的方法会被调用来重建对象

// 例如，ReadDenseJSArray 会被调用来重建数组
// 例如，ReadJSDate 会被调用来重建 Date 对象
// 例如，ReadJSMap 会被调用来重建 Map 对象

// 反序列化后的对象应该与原始对象相同 (在结构和值上)
// console.log(deserializedData); // 应该类似于 originalArray, originalDate, originalMap

// 具体到 ReadSparseJSArray 和 ReadDenseJSArray 的例子：
const sparseArray = [];
sparseArray[100] = 'present';
// 序列化 sparseArray 后，ReadSparseJSArray 会负责重建它

const denseArray = [1, 2, 3];
// 序列化 denseArray 后，ReadDenseJSArray 会负责重建它

// ReadJSPrimitiveWrapper 的例子：
const boolObj = new Boolean(true);
const numObj = new Number(5);
// 序列化这些包装对象后，ReadJSPrimitiveWrapper 会负责重建它们

// ReadJSError 的例子：
const error = new TypeError('Something went wrong');
error.cause = new Error('Root cause');
// 序列化 error 对象后，ReadJSError 会负责重建它，包括 message 和 cause 属性
```

在 JavaScript 中，我们通常不会直接调用 `ValueDeserializer` 的方法。这些方法是 V8 引擎内部实现序列化和反序列化机制的一部分，例如用于 `structuredClone` API 或在不同 V8 上下文之间传递数据。

总结来说，`ValueDeserializer` 是 V8 引擎中至关重要的组件，它使得 JavaScript 对象能够被安全地序列化和反序列化，从而支持诸如数据持久化、跨上下文通信等功能。这段代码展示了它如何根据序列化数据中的标签和信息，一步步地重建各种 JavaScript 对象。

Prompt: 
```
这是目录为v8/src/objects/value-serializer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
ecurse.
  STACK_CHECK(isolate_, MaybeHandle<JSArray>());

  uint32_t length;
  if (!ReadVarint<uint32_t>().To(&length)) return MaybeHandle<JSArray>();

  uint32_t id = next_id_++;
  HandleScope scope(isolate_);
  Handle<JSArray> array =
      isolate_->factory()->NewJSArray(0, TERMINAL_FAST_ELEMENTS_KIND);
  MAYBE_RETURN(JSArray::SetLength(array, length), MaybeHandle<JSArray>());
  AddObjectWithID(id, array);

  uint32_t num_properties;
  uint32_t expected_num_properties;
  uint32_t expected_length;
  if (!ReadJSObjectProperties(array, SerializationTag::kEndSparseJSArray, false)
           .To(&num_properties) ||
      !ReadVarint<uint32_t>().To(&expected_num_properties) ||
      !ReadVarint<uint32_t>().To(&expected_length) ||
      num_properties != expected_num_properties || length != expected_length) {
    return MaybeHandle<JSArray>();
  }

  DCHECK(HasObjectWithID(id));
  return scope.CloseAndEscape(array);
}

MaybeHandle<JSArray> ValueDeserializer::ReadDenseJSArray() {
  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, MaybeHandle<JSArray>());

  // We shouldn't permit an array larger than the biggest we can request from
  // V8. As an additional sanity check, since each entry will take at least one
  // byte to encode, if there are fewer bytes than that we can also fail fast.
  uint32_t length;
  if (!ReadVarint<uint32_t>().To(&length) ||
      length > static_cast<uint32_t>(FixedArray::kMaxLength) ||
      length > static_cast<size_t>(end_ - position_)) {
    return MaybeHandle<JSArray>();
  }

  uint32_t id = next_id_++;
  HandleScope scope(isolate_);
  Handle<JSArray> array = isolate_->factory()->NewJSArray(
      HOLEY_ELEMENTS, length, length,
      ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
  AddObjectWithID(id, array);

  DirectHandle<FixedArray> elements(Cast<FixedArray>(array->elements()),
                                    isolate_);
  auto elements_length = static_cast<uint32_t>(elements->length());
  for (uint32_t i = 0; i < length; i++) {
    SerializationTag tag;
    if (PeekTag().To(&tag) && tag == SerializationTag::kTheHole) {
      ConsumeTag(SerializationTag::kTheHole);
      continue;
    }

    Handle<Object> element;
    if (!ReadObject().ToHandle(&element)) return MaybeHandle<JSArray>();

    // Serialization versions less than 11 encode the hole the same as
    // undefined. For consistency with previous behavior, store these as the
    // hole. Past version 11, undefined means undefined.
    if (version_ < 11 && IsUndefined(*element, isolate_)) continue;

    // Safety check.
    if (i >= elements_length) return MaybeHandle<JSArray>();

    elements->set(i, *element);
  }

  uint32_t num_properties;
  uint32_t expected_num_properties;
  uint32_t expected_length;
  if (!ReadJSObjectProperties(array, SerializationTag::kEndDenseJSArray, false)
           .To(&num_properties) ||
      !ReadVarint<uint32_t>().To(&expected_num_properties) ||
      !ReadVarint<uint32_t>().To(&expected_length) ||
      num_properties != expected_num_properties || length != expected_length) {
    return MaybeHandle<JSArray>();
  }

  DCHECK(HasObjectWithID(id));
  return scope.CloseAndEscape(array);
}

MaybeHandle<JSDate> ValueDeserializer::ReadJSDate() {
  double value;
  if (!ReadDouble().To(&value)) return MaybeHandle<JSDate>();
  uint32_t id = next_id_++;
  Handle<JSDate> date;
  if (!JSDate::New(isolate_->date_function(), isolate_->date_function(), value)
           .ToHandle(&date)) {
    return MaybeHandle<JSDate>();
  }
  AddObjectWithID(id, date);
  return date;
}

MaybeHandle<JSPrimitiveWrapper> ValueDeserializer::ReadJSPrimitiveWrapper(
    SerializationTag tag) {
  uint32_t id = next_id_++;
  Handle<JSPrimitiveWrapper> value;
  switch (tag) {
    case SerializationTag::kTrueObject:
      value = Cast<JSPrimitiveWrapper>(
          isolate_->factory()->NewJSObject(isolate_->boolean_function()));
      value->set_value(ReadOnlyRoots(isolate_).true_value());
      break;
    case SerializationTag::kFalseObject:
      value = Cast<JSPrimitiveWrapper>(
          isolate_->factory()->NewJSObject(isolate_->boolean_function()));
      value->set_value(ReadOnlyRoots(isolate_).false_value());
      break;
    case SerializationTag::kNumberObject: {
      double number;
      if (!ReadDouble().To(&number)) return MaybeHandle<JSPrimitiveWrapper>();
      value = Cast<JSPrimitiveWrapper>(
          isolate_->factory()->NewJSObject(isolate_->number_function()));
      DirectHandle<Number> number_object =
          isolate_->factory()->NewNumber(number);
      value->set_value(*number_object);
      break;
    }
    case SerializationTag::kBigIntObject: {
      Handle<BigInt> bigint;
      if (!ReadBigInt().ToHandle(&bigint))
        return MaybeHandle<JSPrimitiveWrapper>();
      value = Cast<JSPrimitiveWrapper>(
          isolate_->factory()->NewJSObject(isolate_->bigint_function()));
      value->set_value(*bigint);
      break;
    }
    case SerializationTag::kStringObject: {
      Handle<String> string;
      if (!ReadString().ToHandle(&string))
        return MaybeHandle<JSPrimitiveWrapper>();
      value = Cast<JSPrimitiveWrapper>(
          isolate_->factory()->NewJSObject(isolate_->string_function()));
      value->set_value(*string);
      break;
    }
    default:
      UNREACHABLE();
  }
  AddObjectWithID(id, value);
  return value;
}

MaybeHandle<JSRegExp> ValueDeserializer::ReadJSRegExp() {
  uint32_t id = next_id_++;
  Handle<String> pattern;
  uint32_t raw_flags;
  Handle<JSRegExp> regexp;
  if (!ReadString().ToHandle(&pattern) ||
      !ReadVarint<uint32_t>().To(&raw_flags)) {
    return MaybeHandle<JSRegExp>();
  }

  // Ensure the deserialized flags are valid.
  uint32_t bad_flags_mask = static_cast<uint32_t>(-1) << JSRegExp::kFlagCount;
  // kLinear is accepted only with the appropriate flag.
  if (!v8_flags.enable_experimental_regexp_engine) {
    bad_flags_mask |= JSRegExp::kLinear;
  }
  if ((raw_flags & bad_flags_mask) ||
      !RegExp::VerifyFlags(static_cast<RegExpFlags>(raw_flags)) ||
      !JSRegExp::New(isolate_, pattern, static_cast<JSRegExp::Flags>(raw_flags))
           .ToHandle(&regexp)) {
    return MaybeHandle<JSRegExp>();
  }

  AddObjectWithID(id, regexp);
  return regexp;
}

MaybeHandle<JSMap> ValueDeserializer::ReadJSMap() {
  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, MaybeHandle<JSMap>());

  HandleScope scope(isolate_);
  uint32_t id = next_id_++;
  Handle<JSMap> map = isolate_->factory()->NewJSMap();
  AddObjectWithID(id, map);

  Handle<JSFunction> map_set = isolate_->map_set();
  uint32_t length = 0;
  while (true) {
    SerializationTag tag;
    if (!PeekTag().To(&tag)) return MaybeHandle<JSMap>();
    if (tag == SerializationTag::kEndJSMap) {
      ConsumeTag(SerializationTag::kEndJSMap);
      break;
    }

    Handle<Object> argv[2];
    if (!ReadObject().ToHandle(&argv[0]) || !ReadObject().ToHandle(&argv[1])) {
      return MaybeHandle<JSMap>();
    }

    AllowJavascriptExecution allow_js(isolate_);
    if (Execution::Call(isolate_, map_set, map, arraysize(argv), argv)
            .is_null()) {
      return MaybeHandle<JSMap>();
    }
    length += 2;
  }

  uint32_t expected_length;
  if (!ReadVarint<uint32_t>().To(&expected_length) ||
      length != expected_length) {
    return MaybeHandle<JSMap>();
  }
  DCHECK(HasObjectWithID(id));
  return scope.CloseAndEscape(map);
}

MaybeHandle<JSSet> ValueDeserializer::ReadJSSet() {
  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, MaybeHandle<JSSet>());

  HandleScope scope(isolate_);
  uint32_t id = next_id_++;
  Handle<JSSet> set = isolate_->factory()->NewJSSet();
  AddObjectWithID(id, set);
  Handle<JSFunction> set_add = isolate_->set_add();
  uint32_t length = 0;
  while (true) {
    SerializationTag tag;
    if (!PeekTag().To(&tag)) return MaybeHandle<JSSet>();
    if (tag == SerializationTag::kEndJSSet) {
      ConsumeTag(SerializationTag::kEndJSSet);
      break;
    }

    Handle<Object> argv[1];
    if (!ReadObject().ToHandle(&argv[0])) return MaybeHandle<JSSet>();

    AllowJavascriptExecution allow_js(isolate_);
    if (Execution::Call(isolate_, set_add, set, arraysize(argv), argv)
            .is_null()) {
      return MaybeHandle<JSSet>();
    }
    length++;
  }

  uint32_t expected_length;
  if (!ReadVarint<uint32_t>().To(&expected_length) ||
      length != expected_length) {
    return MaybeHandle<JSSet>();
  }
  DCHECK(HasObjectWithID(id));
  return scope.CloseAndEscape(set);
}

MaybeHandle<JSArrayBuffer> ValueDeserializer::ReadJSArrayBuffer(
    bool is_shared, bool is_resizable) {
  uint32_t id = next_id_++;
  if (is_shared) {
    uint32_t clone_id;
    Local<SharedArrayBuffer> sab_value;
    if (!ReadVarint<uint32_t>().To(&clone_id) || delegate_ == nullptr ||
        !delegate_
             ->GetSharedArrayBufferFromId(
                 reinterpret_cast<v8::Isolate*>(isolate_), clone_id)
             .ToLocal(&sab_value)) {
      RETURN_EXCEPTION_IF_EXCEPTION(isolate_);
      return MaybeHandle<JSArrayBuffer>();
    }
    Handle<JSArrayBuffer> array_buffer = Utils::OpenHandle(*sab_value);
    DCHECK_EQ(is_shared, array_buffer->is_shared());
    AddObjectWithID(id, array_buffer);
    return array_buffer;
  }
  uint32_t byte_length;
  if (!ReadVarint<uint32_t>().To(&byte_length)) {
    return MaybeHandle<JSArrayBuffer>();
  }
  uint32_t max_byte_length = byte_length;
  if (is_resizable) {
    if (!ReadVarint<uint32_t>().To(&max_byte_length)) {
      return MaybeHandle<JSArrayBuffer>();
    }
    if (byte_length > max_byte_length) {
      return MaybeHandle<JSArrayBuffer>();
    }
  }
  if (byte_length > static_cast<size_t>(end_ - position_)) {
    return MaybeHandle<JSArrayBuffer>();
  }
  MaybeHandle<JSArrayBuffer> result =
      isolate_->factory()->NewJSArrayBufferAndBackingStore(
          byte_length, max_byte_length, InitializedFlag::kUninitialized,
          is_resizable ? ResizableFlag::kResizable
                       : ResizableFlag::kNotResizable);

  Handle<JSArrayBuffer> array_buffer;
  if (!result.ToHandle(&array_buffer)) return result;

  if (byte_length > 0) {
    memcpy(array_buffer->backing_store(), position_, byte_length);
  }
  position_ += byte_length;
  AddObjectWithID(id, array_buffer);
  return array_buffer;
}

MaybeHandle<JSArrayBuffer> ValueDeserializer::ReadTransferredJSArrayBuffer() {
  uint32_t id = next_id_++;
  uint32_t transfer_id;
  Handle<SimpleNumberDictionary> transfer_map;
  if (!ReadVarint<uint32_t>().To(&transfer_id) ||
      !array_buffer_transfer_map_.ToHandle(&transfer_map)) {
    return MaybeHandle<JSArrayBuffer>();
  }
  InternalIndex index = transfer_map->FindEntry(isolate_, transfer_id);
  if (index.is_not_found()) {
    return MaybeHandle<JSArrayBuffer>();
  }
  Handle<JSArrayBuffer> array_buffer(
      Cast<JSArrayBuffer>(transfer_map->ValueAt(index)), isolate_);
  AddObjectWithID(id, array_buffer);
  return array_buffer;
}

MaybeHandle<JSArrayBufferView> ValueDeserializer::ReadJSArrayBufferView(
    DirectHandle<JSArrayBuffer> buffer) {
  uint32_t buffer_byte_length = static_cast<uint32_t>(buffer->GetByteLength());
  uint8_t tag = 0;
  uint32_t byte_offset = 0;
  uint32_t byte_length = 0;
  uint32_t flags = 0;
  if (!ReadVarint<uint8_t>().To(&tag) ||
      !ReadVarint<uint32_t>().To(&byte_offset) ||
      !ReadVarint<uint32_t>().To(&byte_length) ||
      byte_offset > buffer_byte_length ||
      byte_length > buffer_byte_length - byte_offset) {
    return MaybeHandle<JSArrayBufferView>();
  }
  const bool should_read_flags = version_ >= 14 || version_13_broken_data_mode_;
  if (should_read_flags && !ReadVarint<uint32_t>().To(&flags)) {
    return MaybeHandle<JSArrayBufferView>();
  }
  uint32_t id = next_id_++;
  ExternalArrayType external_array_type = kExternalInt8Array;
  unsigned element_size = 0;

  switch (static_cast<ArrayBufferViewTag>(tag)) {
    case ArrayBufferViewTag::kDataView: {
      bool is_length_tracking = false;
      bool is_backed_by_rab = false;
      if (!ValidateJSArrayBufferViewFlags(*buffer, flags, is_length_tracking,
                                          is_backed_by_rab)) {
        return MaybeHandle<JSArrayBufferView>();
      }
      Handle<JSDataViewOrRabGsabDataView> data_view =
          isolate_->factory()->NewJSDataViewOrRabGsabDataView(
              buffer, byte_offset, byte_length, is_length_tracking);
      CHECK_EQ(is_backed_by_rab, data_view->is_backed_by_rab());
      CHECK_EQ(is_length_tracking, data_view->is_length_tracking());
      AddObjectWithID(id, data_view);
      return data_view;
    }
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case ArrayBufferViewTag::k##Type##Array:        \
    external_array_type = kExternal##Type##Array; \
    element_size = sizeof(ctype);                 \
    break;
      TYPED_ARRAYS_BASE(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
    case ArrayBufferViewTag::kFloat16Array: {
      if (i::v8_flags.js_float16array) {
        external_array_type = kExternalFloat16Array;
        element_size = sizeof(uint16_t);
      }
      break;
    }
  }
  if (element_size == 0 || byte_offset % element_size != 0 ||
      byte_length % element_size != 0) {
    return MaybeHandle<JSArrayBufferView>();
  }
  bool is_length_tracking = false;
  bool is_backed_by_rab = false;
  if (!ValidateJSArrayBufferViewFlags(*buffer, flags, is_length_tracking,
                                      is_backed_by_rab)) {
    return MaybeHandle<JSArrayBufferView>();
  }
  Handle<JSTypedArray> typed_array = isolate_->factory()->NewJSTypedArray(
      external_array_type, buffer, byte_offset, byte_length / element_size,
      is_length_tracking);
  CHECK_EQ(is_length_tracking, typed_array->is_length_tracking());
  CHECK_EQ(is_backed_by_rab, typed_array->is_backed_by_rab());
  AddObjectWithID(id, typed_array);
  return typed_array;
}

bool ValueDeserializer::ValidateJSArrayBufferViewFlags(
    Tagged<JSArrayBuffer> buffer, uint32_t serialized_flags,
    bool& is_length_tracking, bool& is_backed_by_rab) {
  is_length_tracking =
      JSArrayBufferViewIsLengthTracking::decode(serialized_flags);
  is_backed_by_rab = JSArrayBufferViewIsBackedByRab::decode(serialized_flags);

  // TODO(marja): When the version number is bumped the next time, check that
  // serialized_flags doesn't contain spurious 1-bits.

  if (is_backed_by_rab || is_length_tracking) {
    if (!buffer->is_resizable_by_js()) {
      return false;
    }
    if (is_backed_by_rab && buffer->is_shared()) {
      return false;
    }
  }
  // The RAB-ness of the buffer and the TA's "is_backed_by_rab" need to be in
  // sync.
  if (buffer->is_resizable_by_js() && !buffer->is_shared() &&
      !is_backed_by_rab) {
    return false;
  }
  return true;
}

MaybeHandle<Object> ValueDeserializer::ReadJSError() {
  uint32_t id = next_id_++;

#define READ_NEXT_ERROR_TAG()              \
  do {                                     \
    if (!ReadVarint<uint8_t>().To(&tag)) { \
      return MaybeHandle<JSObject>();      \
    }                                      \
  } while (false)

  uint8_t tag;
  READ_NEXT_ERROR_TAG();

  // Read error type constructor.
  Handle<JSFunction> constructor;
  switch (static_cast<ErrorTag>(tag)) {
    case ErrorTag::kEvalErrorPrototype:
      constructor = isolate_->eval_error_function();
      READ_NEXT_ERROR_TAG();
      break;
    case ErrorTag::kRangeErrorPrototype:
      constructor = isolate_->range_error_function();
      READ_NEXT_ERROR_TAG();
      break;
    case ErrorTag::kReferenceErrorPrototype:
      constructor = isolate_->reference_error_function();
      READ_NEXT_ERROR_TAG();
      break;
    case ErrorTag::kSyntaxErrorPrototype:
      constructor = isolate_->syntax_error_function();
      READ_NEXT_ERROR_TAG();
      break;
    case ErrorTag::kTypeErrorPrototype:
      constructor = isolate_->type_error_function();
      READ_NEXT_ERROR_TAG();
      break;
    case ErrorTag::kUriErrorPrototype:
      constructor = isolate_->uri_error_function();
      READ_NEXT_ERROR_TAG();
      break;
    default:
      // The default prototype in the deserialization side is Error.prototype,
      // so we don't have to do anything here.
      constructor = isolate_->error_function();
      break;
  }

  // Check for message property.
  DirectHandle<Object> message = isolate_->factory()->undefined_value();
  if (static_cast<ErrorTag>(tag) == ErrorTag::kMessage) {
    Handle<String> message_string;
    if (!ReadString().ToHandle(&message_string)) {
      return MaybeHandle<JSObject>();
    }
    message = message_string;
    READ_NEXT_ERROR_TAG();
  }

  // Check for stack property.
  Handle<Object> stack = isolate_->factory()->undefined_value();
  if (static_cast<ErrorTag>(tag) == ErrorTag::kStack) {
    Handle<String> stack_string;
    if (!ReadString().ToHandle(&stack_string)) {
      return MaybeHandle<JSObject>();
    }
    stack = stack_string;
    READ_NEXT_ERROR_TAG();
  }

  // Create error object before adding the cause property.
  Handle<JSObject> error;
  Handle<Object> no_caller;
  Handle<Object> undefined_options = isolate_->factory()->undefined_value();
  if (!ErrorUtils::Construct(isolate_, constructor, constructor, message,
                             undefined_options, SKIP_NONE, no_caller,
                             ErrorUtils::StackTraceCollection::kDisabled)
           .ToHandle(&error)) {
    return MaybeHandle<Object>();
  }
  ErrorUtils::SetFormattedStack(isolate_, error, stack);
  AddObjectWithID(id, error);

  // Add cause property if needed.
  if (static_cast<ErrorTag>(tag) == ErrorTag::kCause) {
    Handle<Object> cause;
    if (!ReadObject().ToHandle(&cause)) {
      return MaybeHandle<JSObject>();
    }
    Handle<Name> cause_string = isolate_->factory()->cause_string();
    if (JSObject::SetOwnPropertyIgnoreAttributes(error, cause_string, cause,
                                                 DONT_ENUM)
            .is_null()) {
      return MaybeHandle<JSObject>();
    }
    READ_NEXT_ERROR_TAG();
  }

#undef READ_NEXT_ERROR_TAG

  if (static_cast<ErrorTag>(tag) != ErrorTag::kEnd) {
    return MaybeHandle<Object>();
  }
  return error;
}

#if V8_ENABLE_WEBASSEMBLY
MaybeHandle<JSObject> ValueDeserializer::ReadWasmModuleTransfer() {
  uint32_t transfer_id = 0;
  Local<Value> module_value;
  if (!ReadVarint<uint32_t>().To(&transfer_id) || delegate_ == nullptr ||
      !delegate_
           ->GetWasmModuleFromId(reinterpret_cast<v8::Isolate*>(isolate_),
                                 transfer_id)
           .ToLocal(&module_value)) {
    RETURN_EXCEPTION_IF_EXCEPTION(isolate_);
    return MaybeHandle<JSObject>();
  }
  uint32_t id = next_id_++;
  Handle<JSObject> module = Cast<JSObject>(Utils::OpenHandle(*module_value));
  AddObjectWithID(id, module);
  return module;
}

MaybeHandle<WasmMemoryObject> ValueDeserializer::ReadWasmMemory() {
  uint32_t id = next_id_++;

  int32_t maximum_pages;
  if (!ReadZigZag<int32_t>().To(&maximum_pages)) return {};
  uint8_t memory64_byte;
  if (!ReadByte(&memory64_byte)) return {};
  if (memory64_byte > 1) return {};
  wasm::AddressType address_type =
      memory64_byte ? wasm::AddressType::kI64 : wasm::AddressType::kI32;

  Handle<Object> buffer_object;
  if (!ReadObject().ToHandle(&buffer_object)) return {};
  if (!IsJSArrayBuffer(*buffer_object)) return {};

  Handle<JSArrayBuffer> buffer = Cast<JSArrayBuffer>(buffer_object);
  if (!buffer->is_shared()) return {};

  Handle<WasmMemoryObject> result =
      WasmMemoryObject::New(isolate_, buffer, maximum_pages, address_type);

  AddObjectWithID(id, result);
  return result;
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

// Throws a generic "deserialization failed" exception by default, unless a more
// specific exception has already been thrown.
void ThrowDeserializationExceptionIfNonePending(Isolate* isolate) {
  if (!isolate->has_exception()) {
    isolate->Throw(*isolate->factory()->NewError(
        MessageTemplate::kDataCloneDeserializationError));
  }
  DCHECK(isolate->has_exception());
}

}  // namespace

MaybeHandle<HeapObject> ValueDeserializer::ReadSharedObject() {
  STACK_CHECK(isolate_, MaybeHandle<HeapObject>());
  DCHECK_GE(version_, 15);

  uint32_t shared_object_id;
  if (!ReadVarint<uint32_t>().To(&shared_object_id)) {
    RETURN_EXCEPTION_IF_EXCEPTION(isolate_);
    return MaybeHandle<HeapObject>();
  }

  if (!delegate_) {
    ThrowDeserializationExceptionIfNonePending(isolate_);
    return MaybeHandle<HeapObject>();
  }

  if (shared_object_conveyor_ == nullptr) {
    const v8::SharedValueConveyor* conveyor = delegate_->GetSharedValueConveyor(
        reinterpret_cast<v8::Isolate*>(isolate_));
    if (!conveyor) {
      RETURN_EXCEPTION_IF_EXCEPTION(isolate_);
      return MaybeHandle<HeapObject>();
    }
    shared_object_conveyor_ = conveyor->private_.get();
  }

  Handle<HeapObject> shared_object(
      shared_object_conveyor_->GetPersisted(shared_object_id), isolate_);
  DCHECK(IsShared(*shared_object));
  return shared_object;
}

MaybeHandle<JSObject> ValueDeserializer::ReadHostObject() {
  if (!delegate_) return MaybeHandle<JSObject>();
  STACK_CHECK(isolate_, MaybeHandle<JSObject>());
  uint32_t id = next_id_++;
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
  v8::Local<v8::Object> object;
  if (!delegate_->ReadHostObject(v8_isolate).ToLocal(&object)) {
    RETURN_EXCEPTION_IF_EXCEPTION(isolate_);
    return MaybeHandle<JSObject>();
  }
  Handle<JSObject> js_object = Cast<JSObject>(Utils::OpenHandle(*object));
  AddObjectWithID(id, js_object);
  return js_object;
}

// Copies a vector of property values into an object, given the map that should
// be used.
static void CommitProperties(Handle<JSObject> object, Handle<Map> map,
                             const std::vector<Handle<Object>>& properties) {
  JSObject::AllocateStorageForMap(object, map);
  DCHECK(!object->map()->is_dictionary_map());

  DisallowGarbageCollection no_gc;
  Tagged<DescriptorArray> descriptors = object->map()->instance_descriptors();
  for (InternalIndex i : InternalIndex::Range(properties.size())) {
    // Initializing store.
    object->WriteToField(i, descriptors->GetDetails(i),
                         *properties[i.raw_value()]);
  }
}

static bool IsValidObjectKey(Tagged<Object> value, Isolate* isolate) {
  if (IsSmi(value)) return true;
  auto instance_type = Cast<HeapObject>(value)->map(isolate)->instance_type();
  return InstanceTypeChecker::IsName(instance_type) ||
         InstanceTypeChecker::IsHeapNumber(instance_type);
}

Maybe<uint32_t> ValueDeserializer::ReadJSObjectProperties(
    Handle<JSObject> object, SerializationTag end_tag,
    bool can_use_transitions) {
  uint32_t num_properties = 0;

  // Fast path (following map transitions).
  if (can_use_transitions) {
    bool transitioning = true;
    Handle<Map> map(object->map(), isolate_);
    DCHECK(!map->is_dictionary_map());
    DCHECK_EQ(0, map->instance_descriptors(isolate_)->number_of_descriptors());
    std::vector<Handle<Object>> properties;
    properties.reserve(8);

    while (transitioning) {
      // If there are no more properties, finish.
      SerializationTag tag;
      if (!PeekTag().To(&tag)) return Nothing<uint32_t>();
      if (tag == end_tag) {
        ConsumeTag(end_tag);
        CommitProperties(object, map, properties);
        CHECK_LT(properties.size(), std::numeric_limits<uint32_t>::max());
        return Just(static_cast<uint32_t>(properties.size()));
      }

      // Determine the key to be used and the target map to transition to, if
      // possible. Transitioning may abort if the key is not a string, or if no
      // transition was found.
      Handle<Object> key;
      Handle<Map> target;
      bool transition_was_found = false;
      const uint8_t* start_position = position_;
      uint32_t byte_length;
      if (!ReadTag().To(&tag) || !ReadVarint<uint32_t>().To(&byte_length)) {
        return Nothing<uint32_t>();
      }
      // Length is also checked in ReadRawBytes.
#ifdef V8_VALUE_DESERIALIZER_HARD_FAIL
      CHECK_LE(byte_length,
               static_cast<uint32_t>(std::numeric_limits<int32_t>::max()));
#endif  // V8_VALUE_DESERIALIZER_HARD_FAIL
      std::pair<Handle<String>, Handle<Map>> expected_transition;
      {
        TransitionsAccessor transitions(isolate_, *map);
        if (tag == SerializationTag::kOneByteString) {
          base::Vector<const uint8_t> key_chars;
          if (ReadRawBytes(byte_length).To(&key_chars)) {
            expected_transition = transitions.ExpectedTransition(key_chars);
          }
        } else if (tag == SerializationTag::kTwoByteString) {
          base::Vector<const base::uc16> key_chars;
          if (ReadRawTwoBytes(byte_length).To(&key_chars)) {
            expected_transition = transitions.ExpectedTransition(key_chars);
          }
        } else if (tag == SerializationTag::kUtf8String) {
          base::Vector<const uint8_t> key_chars;
          if (ReadRawBytes(byte_length).To(&key_chars) &&
              String::IsAscii(key_chars.begin(), key_chars.length())) {
            expected_transition = transitions.ExpectedTransition(key_chars);
          }
        }
        if (!expected_transition.first.is_null()) {
          transition_was_found = true;
          key = expected_transition.first;
          target = expected_transition.second;
        }
      }
      if (!transition_was_found) {
        position_ = start_position;
        if (!ReadObject().ToHandle(&key) || !IsValidObjectKey(*key, isolate_)) {
          return Nothing<uint32_t>();
        }
        if (IsString(*key, isolate_)) {
          key = isolate_->factory()->InternalizeString(Cast<String>(key));
          // Don't reuse |transitions| because it could be stale.
          transitioning = TransitionsAccessor(isolate_, *map)
                              .FindTransitionToField(Cast<String>(key))
                              .ToHandle(&target);
        } else {
          transitioning = false;
        }
      }

      // Read the value that corresponds to it.
      Handle<Object> value;
      if (!ReadObject().ToHandle(&value)) return Nothing<uint32_t>();

      // If still transitioning and the value fits the field representation
      // (though generalization may be required), store the property value so
      // that we can copy them all at once. Otherwise, stop transitioning.
      if (transitioning) {
        // Deserializaton of |value| might have deprecated current |target|,
        // ensure we are working with the up-to-date version.
        target = Map::Update(isolate_, target);
        if (!target->is_dictionary_map()) {
          InternalIndex descriptor(properties.size());
          PropertyDetails details =
              target->instance_descriptors(isolate_)->GetDetails(descriptor);
          Representation expected_representation = details.representation();
          if (Object::FitsRepresentation(*value, expected_representation)) {
            if (expected_representation.IsHeapObject() &&
                !FieldType::NowContains(
                    target->instance_descriptors(isolate_)->GetFieldType(
                        descriptor),
                    value)) {
              Handle<FieldType> value_type = Object::OptimalType(
                  *value, isolate_, expected_representation);
              MapUpdater::GeneralizeField(isolate_, target, descriptor,
                                          details.constness(),
                                          expected_representation, value_type);
            }
            DCHECK(FieldType::NowContains(
                target->instance_descriptors(isolate_)->GetFieldType(
                    descriptor),
                value));
            properties.push_back(value);
            map = target;
            continue;
          }
        }
        transitioning = false;
      }

      // Fell out of transitioning fast path. Commit the properties gathered so
      // far, and then start setting properties slowly instead.
      DCHECK(!transitioning);
      CHECK_LT(properties.size(), std::numeric_limits<uint32_t>::max());
      CHECK(!map->is_dictionary_map());
      CommitProperties(object, map, properties);
      num_properties = static_cast<uint32_t>(properties.size());

      // We checked earlier that IsValidObjectKey(key).
      PropertyKey lookup_key(isolate_, key);
      LookupIterator it(isolate_, object, lookup_key, LookupIterator::OWN);
      if (it.state() != LookupIterator::NOT_FOUND ||
          JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, NONE)
              .is_null()) {
        return Nothing<uint32_t>();
      }
      num_properties++;
    }

    // At this point, transitioning should be done, but at least one property
    // should have been written (in the zero-property case, there is an early
    // return).
    DCHECK(!transitioning);
    DCHECK_GE(num_properties, 1u);
  }

  // Slow path.
  for (;; num_properties++) {
    SerializationTag tag;
    if (!PeekTag().To(&tag)) return Nothing<uint32_t>();
    if (tag == end_tag) {
      ConsumeTag(end_tag);
      return Just(num_properties);
    }

    Handle<Object> key;
    if (!ReadObject().ToHandle(&key) || !IsValidObjectKey(*key, isolate_)) {
      return Nothing<uint32_t>();
    }
    Handle<Object> value;
    if (!ReadObject().ToHandle(&value)) return Nothing<uint32_t>();

    // We checked earlier that IsValidObjectKey(key).
    PropertyKey lookup_key(isolate_, key);
    LookupIterator it(isolate_, object, lookup_key, LookupIterator::OWN);
    if (it.state() != LookupIterator::NOT_FOUND ||
        JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, NONE)
            .is_null()) {
      return Nothing<uint32_t>();
    }
  }
}

bool ValueDeserializer::HasObjectWithID(uint32_t id) {
  return id < static_cast<unsigned>(id_map_->length()) &&
         !IsTheHole(id_map_->get(id), isolate_);
}

MaybeHandle<JSReceiver> ValueDeserializer::GetObjectWithID(uint32_t id) {
  if (id >= static_cast<unsigned>(id_map_->length())) {
    return MaybeHandle<JSReceiver>();
  }
  Tagged<Object> value = id_map_->get(id);
  if (IsTheHole(value, isolate_)) return MaybeHandle<JSReceiver>();
  DCHECK(IsJSReceiver(value));
  return Handle<JSReceiver>(Cast<JSReceiver>(value), isolate_);
}

void ValueDeserializer::AddObjectWithID(uint32_t id,
                                        DirectHandle<JSReceiver> object) {
  DCHECK(!HasObjectWithID(id));
  Handle<FixedArray> new_array =
      FixedArray::SetAndGrow(isolate_, id_map_, id, object);

  // If the dictionary was reallocated, update the global handle.
  if (!new_array.is_identical_to(id_map_)) {
    GlobalHandles::Destroy(id_map_.location());
    id_map_ = isolate_->global_handles()->Create(*new_array);
  }
}

static Maybe<bool> SetPropertiesFromKeyValuePairs(Isolate* isolate,
                                                  Handle<JSObject> object,
                                                  Handle<Object>* data,
                                                  uint32_t num_properties) {
  for (unsigned i = 0; i < 2 * num_properties; i += 2) {
    Handle<Object> key = data[i];
    if (!IsValidObjectKey(*key, isolate)) return Nothing<bool>();
    Handle<Object> value = data[i + 1];
    PropertyKey lookup_key(isolate, key);
    LookupIterator it(isolate, object, lookup_key, LookupIterator::OWN);
    if (it.state() != LookupIterator::NOT_FOUND ||
        JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, NONE)
            .is_null()) {
      return Nothing<bool>();
    }
  }
  return Just(true);
}

MaybeHandle<Object>
ValueDeserializer::ReadObjectUsingEntireBufferForLegacyFormat() {
  DCHECK_EQ(version_, 0u);
  HandleScope scope(isolate_);
  std::vector<Handle<Object>> stack;
  while (position_ < end_) {
    SerializationTag tag;
    if (!PeekTag().To(&tag)) break;

    Handle<Object> new_object;
    switch (tag) {
      case SerializationTag::kEndJSObject: {
        ConsumeTag(SerializationTag::kEndJSObject);

        // JS Object: Read the last 2*n values from the stack and use them as
        // key-value pairs.
        uint32_t num_properties;
        if (!ReadVarint<uint32_t>().To(&num_properties) ||
            stack.size() / 2 < num_properties) {
          isolate_->Throw(*isolate_->factory()->NewError(
              MessageTemplate::kDataCloneDeserializationError));
          return MaybeHandle<Object>();
        }

        size_t begin_properties =
            stack.size() - 2 * static_cast<size_t>(num_properties);
        Handle<JSObject> js_object =
            isolate_->factory()->NewJSObject(isolate_->object_function());
        if (num_properties &&
            !SetPropertiesFromKeyValuePairs(
                 isolate_, js_object, &stack[begin_properties], num_properties)
                 .FromMaybe(false)) {
          ThrowDeserializationExceptionIfNonePending(isolate_);
          return MaybeHandle<Object>();
        }

        stack.resize(begin_properties);
        new_object = js_object;
        break;
      }
      case SerializationTag::kEndSparseJSArray: {
        ConsumeTag(SerializationTag::kEndSparseJSArray);

        // Sparse JS Array: Read the last 2*|num_properties| from the stack.
        uint32_t num_properties;
        uint32_t length;
        if (!ReadVarint<uint32_t>().To(&num_properties) ||
            !ReadVarint<uint32_t>().To(&length) ||
            stack.size() / 2 < num_properties) {
          isolate_->Throw(*isolate_->factory()->NewError(
              MessageTemplate::kDataCloneDeserializationError));
          return MaybeHandle<Object>();
        }

        Handle<JSArray> js_array =
            isolate_->factory()->NewJSArray(0, TERMINAL_FAST_ELEMENTS_KIND);
        MAYBE_RETURN_NULL(JSArray::SetLength(js_array, length));
        size_t begin_properties =
            stack.size() - 2 * static_cast<size_t>(num_properties);
        if (num_properties &&
            !SetPropertiesFromKeyValuePairs(
                 isolate_, js_array, &stack[begin_properties], num_properties)
                 .FromMaybe(false)) {
          ThrowDeserializationExceptionIfNonePending(isolate_);
          return MaybeHandle<Object>();
        }

        stack.resize(begin_properties);
        new_object = js_array;
        break;
      }
      case SerializationTag::kEndDenseJSArray: {
        // This was already broken in Chromium, and apparently wasn't missed.
        isolate_->Throw(*isolate_->factory()->NewError(
            MessageTemplate::kDataCloneDeserializationError));
        return MaybeHandle<Object>();
      }
      default:
        if (!ReadObject().ToHandle(&new_object)) return MaybeHandle<Object>();
        break;
    }
    stack.push_back(new_object);
  }

// Nothing remains but padding.
#ifdef DEBUG
  while (position_ < end_) {
    DCHECK(*position_++ == static_cast<uint8_t>(SerializationTag::kPadding));
  }
#endif
  position_ = end_;

  if (stack.size() != 1) {
    isolate_->Throw(*isolate_->factory()->NewError(
        MessageTemplate::kDataCloneDeserializationError));
    return MaybeHandle<Object>();
  }
  return scope.CloseAndEscape(stack[0]);
}

}  // namespace internal
}  // namespace v8

"""


```