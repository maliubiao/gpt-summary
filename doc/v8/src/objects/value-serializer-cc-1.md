Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/value-serializer.cc`. This is the second part of a four-part code block.

Here's a plan to address the user's request:

1. **Identify the core functionalities** present in this code block. This involves looking at the function names and the types they handle (e.g., `WriteJSMap`, `WriteJSSet`, `WriteJSArrayBuffer`, `ReadJSObject`, `ReadJSArray`).
2. **Group related functionalities** together. For instance, the `WriteJS...` functions are all about serializing JavaScript objects, while the `ReadJS...` functions are about deserializing them.
3. **Summarize the purpose of each group**.
4. **Note any connections to JavaScript concepts**.
5. **Mention any error handling or specific scenarios** addressed in this section (e.g., handling shared array buffers, detached array buffers, host objects).
这是 `v8/src/objects/value-serializer.cc` 源代码的第二部分，它主要负责 **序列化** 和 **反序列化** 特定类型的 JavaScript 值。

**归纳功能:**

这部分代码主要负责以下 JavaScript 值的序列化和反序列化：

* **`JSMap` 和 `JSSet`:**  将 JavaScript 的 Map 和 Set 对象转换为可存储或传输的格式，并能从该格式恢复。
* **`JSArrayBuffer`:**  处理 JavaScript 的 ArrayBuffer 对象，包括共享的、可调整大小的和已分离的 ArrayBuffer。它会根据 ArrayBuffer 的状态选择不同的序列化方式。
* **`JSArrayBufferView` (如 TypedArray 和 DataView):**  处理 ArrayBuffer 的视图，例如 Int8Array、Uint32Array 和 DataView。可以选择将其视为宿主对象进行处理。
* **`JSError`:**  序列化 JavaScript 的 Error 对象，包括其 name、message 和 stack 属性，以及可选的 cause 属性。
* **`JSSharedStruct` 和 `JSSharedArray`:** 处理共享的结构体和数组。
* **Wasm 相关的对象 (在 `V8_ENABLE_WEBASSEMBLY` 宏定义下):**  处理 WebAssembly 的模块 (`WasmModuleObject`) 和内存 (`WasmMemoryObject`) 对象。
* **宿主对象 (Host Object):**  提供序列化由嵌入器定义的宿主对象的能力。

**与 JavaScript 功能的关系及示例:**

* **`JSMap` 和 `JSSet`:**
   ```javascript
   const map = new Map();
   map.set('a', 1);
   map.set('b', 2);

   const set = new Set();
   set.add(1);
   set.add('hello');

   // ValueSerializer 的代码负责将 map 和 set 转换为字节流
   // ... 序列化 map 和 set ...
   ```

* **`JSArrayBuffer`:**
   ```javascript
   const buffer = new ArrayBuffer(16);
   const sharedBuffer = new SharedArrayBuffer(16);

   // ValueSerializer 的代码负责将 buffer 或 sharedBuffer 转换为字节流
   // ... 序列化 buffer 或 sharedBuffer ...
   ```

* **`JSArrayBufferView`:**
   ```javascript
   const buffer = new ArrayBuffer(16);
   const view = new Uint32Array(buffer);
   view[0] = 123;

   const dataView = new DataView(buffer, 4, 8);
   dataView.setInt32(0, 456);

   // ValueSerializer 的代码负责将 view 或 dataView 转换为字节流
   // ... 序列化 view 或 dataView ...
   ```

* **`JSError`:**
   ```javascript
   try {
     throw new Error('Something went wrong');
   } catch (e) {
     // ValueSerializer 的代码负责将 error 对象转换为字节流
     // ... 序列化 e ...
   }
   ```

**代码逻辑推理和假设输入输出:**

以 `WriteJSMap` 为例：

**假设输入:** 一个 JavaScript Map 对象 `js_map`，其中包含键值对 `{'a': 1, 'b': 2}`。

**输出:**  一个表示该 Map 对象的序列化字节流。该字节流会包含以下信息（顺序可能不同，具体格式取决于内部实现）：
1. 表示开始序列化 Map 的标签 (`SerializationTag::kBeginJSMap`)。
2. 键 'a' 的序列化表示。
3. 值 1 的序列化表示。
4. 键 'b' 的序列化表示。
5. 值 2 的序列化表示。
6. 表示结束序列化 Map 的标签 (`SerializationTag::kEndJSMap`)。
7. Map 中键值对数量的两倍 (因为存储了键和值) 。

**用户常见的编程错误示例:**

在使用序列化/反序列化功能时，一个常见的错误是尝试序列化 **不可序列化的值**，例如包含循环引用的对象或者某些特定的宿主对象，如果 `ValueSerializer::delegate_` 没有正确处理这些情况，就会导致 `ThrowDataCloneError`。

例如，一个包含循环引用的对象：

```javascript
const obj = {};
obj.circular = obj;

// 尝试序列化 obj 可能会导致错误，因为默认的序列化机制无法处理循环引用。
// ... 尝试使用 ValueSerializer 序列化 obj ...
```

**总结第 2 部分的功能:**

这部分 `ValueSerializer` 代码的核心功能是 **提供将多种特定类型的 JavaScript 值（如 Map、Set、ArrayBuffer、Error 等）序列化为字节流以及从字节流反序列化回这些对象的能力**。它考虑了不同类型的特性和状态（例如 ArrayBuffer 的共享性、可调整大小性、是否已分离），并针对 WebAssembly 和宿主对象提供了相应的处理机制。 代码中包含了错误处理机制，用于处理无法序列化的值或其他异常情况。

Prompt: 
```
这是目录为v8/src/objects/value-serializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/value-serializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
ate them.
  DirectHandle<OrderedHashMap> table(Cast<OrderedHashMap>(js_map->table()),
                                     isolate_);
  int length = table->NumberOfElements() * 2;
  DirectHandle<FixedArray> entries = isolate_->factory()->NewFixedArray(length);
  {
    DisallowGarbageCollection no_gc;
    Tagged<OrderedHashMap> raw_table = *table;
    Tagged<FixedArray> raw_entries = *entries;
    Tagged<Hole> hash_table_hole =
        ReadOnlyRoots(isolate_).hash_table_hole_value();
    int result_index = 0;
    for (InternalIndex entry : raw_table->IterateEntries()) {
      Tagged<Object> key = raw_table->KeyAt(entry);
      if (key == hash_table_hole) continue;
      raw_entries->set(result_index++, key);
      raw_entries->set(result_index++, raw_table->ValueAt(entry));
    }
    DCHECK_EQ(result_index, length);
  }

  // Then write it out.
  WriteTag(SerializationTag::kBeginJSMap);
  for (int i = 0; i < length; i++) {
    if (!WriteObject(handle(entries->get(i), isolate_)).FromMaybe(false)) {
      return Nothing<bool>();
    }
  }
  WriteTag(SerializationTag::kEndJSMap);
  WriteVarint<uint32_t>(length);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSSet(DirectHandle<JSSet> js_set) {
  // First copy the element pointers, since getters could mutate them.
  DirectHandle<OrderedHashSet> table(Cast<OrderedHashSet>(js_set->table()),
                                     isolate_);
  int length = table->NumberOfElements();
  DirectHandle<FixedArray> entries = isolate_->factory()->NewFixedArray(length);
  {
    DisallowGarbageCollection no_gc;
    Tagged<OrderedHashSet> raw_table = *table;
    Tagged<FixedArray> raw_entries = *entries;
    Tagged<Hole> hash_table_hole =
        ReadOnlyRoots(isolate_).hash_table_hole_value();
    int result_index = 0;
    for (InternalIndex entry : raw_table->IterateEntries()) {
      Tagged<Object> key = raw_table->KeyAt(entry);
      if (key == hash_table_hole) continue;
      raw_entries->set(result_index++, key);
    }
    DCHECK_EQ(result_index, length);
  }

  // Then write it out.
  WriteTag(SerializationTag::kBeginJSSet);
  for (int i = 0; i < length; i++) {
    if (!WriteObject(handle(entries->get(i), isolate_)).FromMaybe(false)) {
      return Nothing<bool>();
    }
  }
  WriteTag(SerializationTag::kEndJSSet);
  WriteVarint<uint32_t>(length);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSArrayBuffer(
    Handle<JSArrayBuffer> array_buffer) {
  if (array_buffer->is_shared()) {
    if (!delegate_) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 array_buffer);
    }

    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    Maybe<uint32_t> index = delegate_->GetSharedArrayBufferId(
        v8_isolate, Utils::ToLocalShared(array_buffer));
    RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());

    WriteTag(SerializationTag::kSharedArrayBuffer);
    WriteVarint(index.FromJust());
    return ThrowIfOutOfMemory();
  }

  uint32_t* transfer_entry = array_buffer_transfer_map_.Find(array_buffer);
  if (transfer_entry) {
    WriteTag(SerializationTag::kArrayBufferTransfer);
    WriteVarint(*transfer_entry);
    return ThrowIfOutOfMemory();
  }
  if (array_buffer->was_detached()) {
    return ThrowDataCloneError(
        MessageTemplate::kDataCloneErrorDetachedArrayBuffer);
  }
  size_t byte_length = array_buffer->byte_length();
  if (byte_length > std::numeric_limits<uint32_t>::max()) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, array_buffer);
  }
  if (array_buffer->is_resizable_by_js()) {
    size_t max_byte_length = array_buffer->max_byte_length();
    if (max_byte_length > std::numeric_limits<uint32_t>::max()) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 array_buffer);
    }

    WriteTag(SerializationTag::kResizableArrayBuffer);
    WriteVarint<uint32_t>(static_cast<uint32_t>(byte_length));
    WriteVarint<uint32_t>(static_cast<uint32_t>(max_byte_length));
    WriteRawBytes(array_buffer->backing_store(), byte_length);
    return ThrowIfOutOfMemory();
  }
  WriteTag(SerializationTag::kArrayBuffer);
  WriteVarint<uint32_t>(static_cast<uint32_t>(byte_length));
  WriteRawBytes(array_buffer->backing_store(), byte_length);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSArrayBufferView(
    Tagged<JSArrayBufferView> view) {
  if (treat_array_buffer_views_as_host_objects_) {
    return WriteHostObject(handle(view, isolate_));
  }
  WriteTag(SerializationTag::kArrayBufferView);
  ArrayBufferViewTag tag = ArrayBufferViewTag::kInt8Array;
  if (IsJSTypedArray(view)) {
    if (Cast<JSTypedArray>(view)->IsOutOfBounds()) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 handle(view, isolate_));
    }
    switch (Cast<JSTypedArray>(view)->type()) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case kExternal##Type##Array:                    \
    tag = ArrayBufferViewTag::k##Type##Array;     \
    break;
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
    }
  } else {
    DCHECK(IsJSDataViewOrRabGsabDataView(view));
    if (IsJSRabGsabDataView(view) &&
        Cast<JSRabGsabDataView>(view)->IsOutOfBounds()) {
      return ThrowDataCloneError(MessageTemplate::kDataCloneError,
                                 handle(view, isolate_));
    }

    tag = ArrayBufferViewTag::kDataView;
  }
  WriteVarint(static_cast<uint8_t>(tag));
  WriteVarint(static_cast<uint32_t>(view->byte_offset()));
  WriteVarint(static_cast<uint32_t>(view->byte_length()));
  uint32_t flags =
      JSArrayBufferViewIsLengthTracking::encode(view->is_length_tracking()) |
      JSArrayBufferViewIsBackedByRab::encode(view->is_backed_by_rab());
  WriteVarint(flags);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSError(Handle<JSObject> error) {
  Handle<Object> stack;
  PropertyDescriptor message_desc;
  Maybe<bool> message_found = JSReceiver::GetOwnPropertyDescriptor(
      isolate_, error, isolate_->factory()->message_string(), &message_desc);
  MAYBE_RETURN(message_found, Nothing<bool>());
  PropertyDescriptor cause_desc;
  Maybe<bool> cause_found = JSReceiver::GetOwnPropertyDescriptor(
      isolate_, error, isolate_->factory()->cause_string(), &cause_desc);

  WriteTag(SerializationTag::kError);

  Handle<Object> name_object;
  if (!JSObject::GetProperty(isolate_, error, "name").ToHandle(&name_object)) {
    return Nothing<bool>();
  }
  Handle<String> name;
  if (!Object::ToString(isolate_, name_object).ToHandle(&name)) {
    return Nothing<bool>();
  }

  if (name->IsOneByteEqualTo(base::CStrVector("EvalError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kEvalErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("RangeError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kRangeErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("ReferenceError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kReferenceErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("SyntaxError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kSyntaxErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("TypeError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kTypeErrorPrototype));
  } else if (name->IsOneByteEqualTo(base::CStrVector("URIError"))) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kUriErrorPrototype));
  } else {
    // The default prototype in the deserialization side is Error.prototype, so
    // we don't have to do anything here.
  }

  if (message_found.FromJust() &&
      PropertyDescriptor::IsDataDescriptor(&message_desc)) {
    Handle<String> message;
    if (!Object::ToString(isolate_, message_desc.value()).ToHandle(&message)) {
      return Nothing<bool>();
    }
    WriteVarint(static_cast<uint8_t>(ErrorTag::kMessage));
    WriteString(message);
  }

  if (!Object::GetProperty(isolate_, error, isolate_->factory()->stack_string())
           .ToHandle(&stack)) {
    return Nothing<bool>();
  }
  if (IsString(*stack)) {
    WriteVarint(static_cast<uint8_t>(ErrorTag::kStack));
    WriteString(Cast<String>(stack));
  }

  // The {cause} can self-reference the error. We add at the end, so that we can
  // create the Error first when deserializing.
  if (cause_found.FromJust() &&
      PropertyDescriptor::IsDataDescriptor(&cause_desc)) {
    Handle<Object> cause = cause_desc.value();
    WriteVarint(static_cast<uint8_t>(ErrorTag::kCause));
    if (!WriteObject(cause).FromMaybe(false)) {
      return Nothing<bool>();
    }
  }

  WriteVarint(static_cast<uint8_t>(ErrorTag::kEnd));
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSSharedStruct(
    DirectHandle<JSSharedStruct> shared_struct) {
  // TODO(v8:12547): Support copying serialization for shared structs as well.
  return WriteSharedObject(shared_struct);
}

Maybe<bool> ValueSerializer::WriteJSSharedArray(
    DirectHandle<JSSharedArray> shared_array) {
  return WriteSharedObject(shared_array);
}

#if V8_ENABLE_WEBASSEMBLY
Maybe<bool> ValueSerializer::WriteWasmModule(Handle<WasmModuleObject> object) {
  if (delegate_ == nullptr) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
  }

  Maybe<uint32_t> transfer_id = delegate_->GetWasmModuleTransferId(
      reinterpret_cast<v8::Isolate*>(isolate_), Utils::ToLocal(object));
  RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
  uint32_t id = 0;
  if (transfer_id.To(&id)) {
    WriteTag(SerializationTag::kWasmModuleTransfer);
    WriteVarint<uint32_t>(id);
    return Just(true);
  }
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteWasmMemory(
    DirectHandle<WasmMemoryObject> object) {
  if (!object->array_buffer()->is_shared()) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
  }

  GlobalBackingStoreRegistry::Register(
      object->array_buffer()->GetBackingStore());

  WriteTag(SerializationTag::kWasmMemoryTransfer);
  WriteZigZag<int32_t>(object->maximum_pages());
  WriteByte(object->is_memory64() ? 1 : 0);
  return WriteJSReceiver(Handle<JSReceiver>(object->array_buffer(), isolate_));
}
#endif  // V8_ENABLE_WEBASSEMBLY

Maybe<bool> ValueSerializer::WriteSharedObject(
    DirectHandle<HeapObject> object) {
  if (!delegate_ || !isolate_->has_shared_space()) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
  }

  DCHECK(IsShared(*object));

  // The first time a shared object is serialized, a new conveyor is made. This
  // conveyor is used for every shared object in this serialization and
  // subsequent deserialization sessions. The embedder owns the lifetime of the
  // conveyor.
  if (!shared_object_conveyor_) {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    v8::SharedValueConveyor v8_conveyor(v8_isolate);
    shared_object_conveyor_ = v8_conveyor.private_.get();
    if (!delegate_->AdoptSharedValueConveyor(v8_isolate,
                                             std::move(v8_conveyor))) {
      shared_object_conveyor_ = nullptr;
      RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
      return Nothing<bool>();
    }
  }

  WriteTag(SerializationTag::kSharedObject);
  WriteVarint(shared_object_conveyor_->Persist(*object));

  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteHostObject(Handle<JSObject> object) {
  WriteTag(SerializationTag::kHostObject);
  if (!delegate_) {
    isolate_->Throw(*isolate_->factory()->NewError(
        isolate_->error_function(), MessageTemplate::kDataCloneError, object));
    return Nothing<bool>();
  }
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
  Maybe<bool> result =
      delegate_->WriteHostObject(v8_isolate, Utils::ToLocal(object));
  RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
  USE(result);
  DCHECK(!result.IsNothing());
  DCHECK(result.ToChecked());
  return ThrowIfOutOfMemory();
}

Maybe<uint32_t> ValueSerializer::WriteJSObjectPropertiesSlow(
    Handle<JSObject> object, DirectHandle<FixedArray> keys) {
  uint32_t properties_written = 0;
  int length = keys->length();
  for (int i = 0; i < length; i++) {
    Handle<Object> key(keys->get(i), isolate_);

    PropertyKey lookup_key(isolate_, key);
    LookupIterator it(isolate_, object, lookup_key, LookupIterator::OWN);
    Handle<Object> value;
    if (!Object::GetProperty(&it).ToHandle(&value)) return Nothing<uint32_t>();

    // If the property is no longer found, do not serialize it.
    // This could happen if a getter deleted the property.
    if (!it.IsFound()) continue;

    if (!WriteObject(key).FromMaybe(false) ||
        !WriteObject(value).FromMaybe(false)) {
      return Nothing<uint32_t>();
    }

    properties_written++;
  }
  return Just(properties_written);
}

Maybe<bool> ValueSerializer::IsHostObject(Handle<JSObject> js_object) {
  if (!has_custom_host_objects_) {
    return Just<bool>(
        JSObject::GetEmbedderFieldCount(js_object->map(isolate_)));
  }
  DCHECK_NOT_NULL(delegate_);

  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
  Maybe<bool> result =
      delegate_->IsHostObject(v8_isolate, Utils::ToLocal(js_object));
  RETURN_VALUE_IF_EXCEPTION(isolate_, Nothing<bool>());
  DCHECK(!result.IsNothing());

  if (V8_UNLIKELY(out_of_memory_)) return ThrowIfOutOfMemory();
  return result;
}

Maybe<bool> ValueSerializer::ThrowIfOutOfMemory() {
  if (out_of_memory_) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneErrorOutOfMemory);
  }
  return Just(true);
}

Maybe<bool> ValueSerializer::ThrowDataCloneError(
    MessageTemplate template_index) {
  return ThrowDataCloneError(template_index,
                             isolate_->factory()->empty_string());
}

Maybe<bool> ValueSerializer::ThrowDataCloneError(MessageTemplate index,
                                                 DirectHandle<Object> arg0) {
  Handle<String> message =
      MessageFormatter::Format(isolate_, index, base::VectorOf({arg0}));
  if (delegate_) {
    delegate_->ThrowDataCloneError(Utils::ToLocal(message));
  } else {
    isolate_->Throw(
        *isolate_->factory()->NewError(isolate_->error_function(), message));
  }
  return Nothing<bool>();
}

ValueDeserializer::ValueDeserializer(Isolate* isolate,
                                     base::Vector<const uint8_t> data,
                                     v8::ValueDeserializer::Delegate* delegate)
    : isolate_(isolate),
      delegate_(delegate),
      position_(data.begin()),
      end_(data.end()),
      id_map_(isolate->global_handles()->Create(
          ReadOnlyRoots(isolate_).empty_fixed_array())) {}

ValueDeserializer::ValueDeserializer(Isolate* isolate, const uint8_t* data,
                                     size_t size)
    : isolate_(isolate),
      delegate_(nullptr),
      position_(data),
      end_(data + size),
      id_map_(isolate->global_handles()->Create(
          ReadOnlyRoots(isolate_).empty_fixed_array())) {}

ValueDeserializer::~ValueDeserializer() {
  DCHECK_LE(position_, end_);
  GlobalHandles::Destroy(id_map_.location());

  Handle<Object> transfer_map_handle;
  if (array_buffer_transfer_map_.ToHandle(&transfer_map_handle)) {
    GlobalHandles::Destroy(transfer_map_handle.location());
  }
}

Maybe<bool> ValueDeserializer::ReadHeader() {
  if (position_ < end_ &&
      *position_ == static_cast<uint8_t>(SerializationTag::kVersion)) {
    ReadTag().ToChecked();
    if (!ReadVarintLoop<uint32_t>().To(&version_) ||
        version_ > kLatestVersion) {
      isolate_->Throw(*isolate_->factory()->NewError(
          MessageTemplate::kDataCloneDeserializationVersionError));
      return Nothing<bool>();
    }
  }
  return Just(true);
}

Maybe<SerializationTag> ValueDeserializer::PeekTag() const {
  const uint8_t* peek_position = position_;
  SerializationTag tag;
  do {
    if (peek_position >= end_) return Nothing<SerializationTag>();
    tag = static_cast<SerializationTag>(*peek_position);
    peek_position++;
  } while (tag == SerializationTag::kPadding);
  return Just(tag);
}

void ValueDeserializer::ConsumeTag(SerializationTag peeked_tag) {
  SerializationTag actual_tag = ReadTag().ToChecked();
  DCHECK(actual_tag == peeked_tag);
  USE(actual_tag);
}

Maybe<SerializationTag> ValueDeserializer::ReadTag() {
  SerializationTag tag;
  do {
    if (position_ >= end_) return Nothing<SerializationTag>();
    tag = static_cast<SerializationTag>(*position_);
    position_++;
  } while (tag == SerializationTag::kPadding);
  return Just(tag);
}

template <typename T>
Maybe<T> ValueDeserializer::ReadVarint() {
  // Reads an unsigned integer as a base-128 varint.
  // The number is written, 7 bits at a time, from the least significant to the
  // most significant 7 bits. Each byte, except the last, has the MSB set.
  // If the varint is larger than T, any more significant bits are discarded.
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be read as varints.");
  if (sizeof(T) > 4) return ReadVarintLoop<T>();
  auto max_read_position = position_ + sizeof(T) + 1;
  if (V8_UNLIKELY(max_read_position >= end_)) return ReadVarintLoop<T>();
#ifdef DEBUG
  // DCHECK code to make sure the manually unrolled loop yields the exact
  // same end state and result.
  auto previous_position = position_;
  Maybe<T> maybe_expected_value = ReadVarintLoop<T>();
  // ReadVarintLoop can't return Nothing here; all such conditions have been
  // checked above.
  T expected_value = maybe_expected_value.ToChecked();
  auto expected_position = position_;
  position_ = previous_position;
#endif  // DEBUG
#define EXIT_DCHECK()                      \
  DCHECK_LE(position_, end_);              \
  DCHECK_EQ(position_, expected_position); \
  DCHECK_EQ(value, expected_value)

  T value = 0;
#define ITERATION_SHIFTED(shift)                     \
  if (shift < sizeof(T) * 8) {                       \
    uint8_t byte = *position_;                       \
    position_++;                                     \
    if (byte < 0x80) {                               \
      value |= static_cast<T>(byte) << shift;        \
      EXIT_DCHECK();                                 \
      return Just(value);                            \
    } else {                                         \
      value |= static_cast<T>(byte & 0x7F) << shift; \
    }                                                \
  }
  // Manually unroll the loop to achieve the best measured peformance.
  // This is ~15% faster than ReadVarintLoop.
  ITERATION_SHIFTED(0);
  ITERATION_SHIFTED(7);
  ITERATION_SHIFTED(14);
  ITERATION_SHIFTED(21);
  ITERATION_SHIFTED(28);

  EXIT_DCHECK();
  return Just(value);
#undef ITERATION_SHIFTED
#undef EXIT_DCHECK
}

template <typename T>
Maybe<T> ValueDeserializer::ReadVarintLoop() {
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be read as varints.");
  T value = 0;
  unsigned shift = 0;
  bool has_another_byte;
  do {
    if (position_ >= end_) return Nothing<T>();
    uint8_t byte = *position_;
    has_another_byte = byte & 0x80;
    if (V8_LIKELY(shift < sizeof(T) * 8)) {
      value |= static_cast<T>(byte & 0x7F) << shift;
      shift += 7;
    } else {
      // For consistency with the fast unrolled loop in ReadVarint we return
      // after we have read size(T) + 1 bytes.
#ifdef V8_VALUE_DESERIALIZER_HARD_FAIL
      CHECK(!has_another_byte);
#endif  // V8_VALUE_DESERIALIZER_HARD_FAIL
      return Just(value);
    }
    position_++;
  } while (has_another_byte);
  return Just(value);
}

template <typename T>
Maybe<T> ValueDeserializer::ReadZigZag() {
  // Writes a signed integer as a varint using ZigZag encoding (i.e. 0 is
  // encoded as 0, -1 as 1, 1 as 2, -2 as 3, and so on).
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  static_assert(std::is_integral<T>::value && std::is_signed<T>::value,
                "Only signed integer types can be read as zigzag.");
  using UnsignedT = typename std::make_unsigned<T>::type;
  UnsignedT unsigned_value;
  if (!ReadVarint<UnsignedT>().To(&unsigned_value)) return Nothing<T>();
  return Just(static_cast<T>((unsigned_value >> 1) ^
                             -static_cast<T>(unsigned_value & 1)));
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) Maybe<int32_t> ValueDeserializer::ReadZigZag();

Maybe<double> ValueDeserializer::ReadDouble() {
  // Warning: this uses host endianness.
  if (sizeof(double) > static_cast<unsigned>(end_ - position_)) {
    return Nothing<double>();
  }
  double value;
  memcpy(&value, position_, sizeof(double));
  position_ += sizeof(double);
  if (std::isnan(value)) value = std::numeric_limits<double>::quiet_NaN();
  return Just(value);
}

Maybe<base::Vector<const uint8_t>> ValueDeserializer::ReadRawBytes(
    size_t size) {
  if (size > static_cast<size_t>(end_ - position_)) {
    return Nothing<base::Vector<const uint8_t>>();
  }
  const uint8_t* start = position_;
  position_ += size;
  return Just(base::Vector<const uint8_t>(start, size));
}

Maybe<base::Vector<const base::uc16>> ValueDeserializer::ReadRawTwoBytes(
    size_t size) {
  if (size > static_cast<size_t>(end_ - position_) ||
      size % sizeof(base::uc16) != 0) {
    return Nothing<base::Vector<const base::uc16>>();
  }
  const base::uc16* start = (const base::uc16*)(position_);
  position_ += size;
  return Just(base::Vector<const base::uc16>(start, size / sizeof(base::uc16)));
}

bool ValueDeserializer::ReadByte(uint8_t* value) {
  if (static_cast<size_t>(end_ - position_) < sizeof(uint8_t)) return false;
  *value = *position_;
  position_++;
  return true;
}

bool ValueDeserializer::ReadUint32(uint32_t* value) {
  return ReadVarint<uint32_t>().To(value);
}

bool ValueDeserializer::ReadUint64(uint64_t* value) {
  return ReadVarint<uint64_t>().To(value);
}

bool ValueDeserializer::ReadDouble(double* value) {
  return ReadDouble().To(value);
}

bool ValueDeserializer::ReadRawBytes(size_t length, const void** data) {
  if (length > static_cast<size_t>(end_ - position_)) return false;
  *data = position_;
  position_ += length;
  return true;
}

void ValueDeserializer::TransferArrayBuffer(
    uint32_t transfer_id, Handle<JSArrayBuffer> array_buffer) {
  if (array_buffer_transfer_map_.is_null()) {
    array_buffer_transfer_map_ = isolate_->global_handles()->Create(
        *SimpleNumberDictionary::New(isolate_, 0));
  }
  Handle<SimpleNumberDictionary> dictionary =
      array_buffer_transfer_map_.ToHandleChecked();
  Handle<SimpleNumberDictionary> new_dictionary = SimpleNumberDictionary::Set(
      isolate_, dictionary, transfer_id, array_buffer);
  if (!new_dictionary.is_identical_to(dictionary)) {
    GlobalHandles::Destroy(dictionary.location());
    array_buffer_transfer_map_ =
        isolate_->global_handles()->Create(*new_dictionary);
  }
}

MaybeHandle<Object> ValueDeserializer::ReadObjectWrapper() {
  // We had a bug which produced invalid version 13 data (see
  // crbug.com/1284506). This compatibility mode tries to first read the data
  // normally, and if it fails, and the version is 13, tries to read the broken
  // format.
  const uint8_t* original_position = position_;
  suppress_deserialization_errors_ = true;
  MaybeHandle<Object> result = ReadObject();

  // The deserialization code doesn't throw errors for invalid data. It throws
  // errors for stack overflows, though, and in that case we won't retry.
  if (result.is_null() && version_ == 13 && !isolate_->has_exception()) {
    version_13_broken_data_mode_ = true;
    position_ = original_position;
    result = ReadObject();
  }

  if (result.is_null() && !isolate_->has_exception()) {
    isolate_->Throw(*isolate_->factory()->NewError(
        MessageTemplate::kDataCloneDeserializationError));
  }

  return result;
}

MaybeHandle<Object> ValueDeserializer::ReadObject() {
  DisallowJavascriptExecution no_js(isolate_);
  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, MaybeHandle<Object>());

  MaybeHandle<Object> result = ReadObjectInternal();

  // ArrayBufferView is special in that it consumes the value before it, even
  // after format version 0.
  Handle<Object> object;
  SerializationTag tag;
  if (result.ToHandle(&object) && V8_UNLIKELY(IsJSArrayBuffer(*object)) &&
      PeekTag().To(&tag) && tag == SerializationTag::kArrayBufferView) {
    ConsumeTag(SerializationTag::kArrayBufferView);
    result = ReadJSArrayBufferView(Cast<JSArrayBuffer>(object));
  }

  if (result.is_null() && !suppress_deserialization_errors_ &&
      !isolate_->has_exception()) {
    isolate_->Throw(*isolate_->factory()->NewError(
        MessageTemplate::kDataCloneDeserializationError));
  }
#if defined(DEBUG) && defined(VERIFY_HEAP)
  if (!result.is_null() && v8_flags.enable_slow_asserts &&
      v8_flags.verify_heap) {
    Object::ObjectVerify(*object, isolate_);
  }
#endif

  return result;
}

MaybeHandle<Object> ValueDeserializer::ReadObjectInternal() {
  SerializationTag tag;
  if (!ReadTag().To(&tag)) return MaybeHandle<Object>();
  switch (tag) {
    case SerializationTag::kVerifyObjectCount:
      // Read the count and ignore it.
      if (ReadVarint<uint32_t>().IsNothing()) return MaybeHandle<Object>();
      return ReadObject();
    case SerializationTag::kUndefined:
      return isolate_->factory()->undefined_value();
    case SerializationTag::kNull:
      return isolate_->factory()->null_value();
    case SerializationTag::kTrue:
      return isolate_->factory()->true_value();
    case SerializationTag::kFalse:
      return isolate_->factory()->false_value();
    case SerializationTag::kInt32: {
      Maybe<int32_t> number = ReadZigZag<int32_t>();
      if (number.IsNothing()) return MaybeHandle<Object>();
      return isolate_->factory()->NewNumberFromInt(number.FromJust());
    }
    case SerializationTag::kUint32: {
      Maybe<uint32_t> number = ReadVarint<uint32_t>();
      if (number.IsNothing()) return MaybeHandle<Object>();
      return isolate_->factory()->NewNumberFromUint(number.FromJust());
    }
    case SerializationTag::kDouble: {
      Maybe<double> number = ReadDouble();
      if (number.IsNothing()) return MaybeHandle<Object>();
      return isolate_->factory()->NewNumber(number.FromJust());
    }
    case SerializationTag::kBigInt:
      return ReadBigInt();
    case SerializationTag::kUtf8String:
      return ReadUtf8String();
    case SerializationTag::kOneByteString:
      return ReadOneByteString();
    case SerializationTag::kTwoByteString:
      return ReadTwoByteString();
    case SerializationTag::kObjectReference: {
      uint32_t id;
      if (!ReadVarint<uint32_t>().To(&id)) return MaybeHandle<Object>();
      return GetObjectWithID(id);
    }
    case SerializationTag::kBeginJSObject:
      return ReadJSObject();
    case SerializationTag::kBeginSparseJSArray:
      return ReadSparseJSArray();
    case SerializationTag::kBeginDenseJSArray:
      return ReadDenseJSArray();
    case SerializationTag::kDate:
      return ReadJSDate();
    case SerializationTag::kTrueObject:
    case SerializationTag::kFalseObject:
    case SerializationTag::kNumberObject:
    case SerializationTag::kBigIntObject:
    case SerializationTag::kStringObject:
      return ReadJSPrimitiveWrapper(tag);
    case SerializationTag::kRegExp:
      return ReadJSRegExp();
    case SerializationTag::kBeginJSMap:
      return ReadJSMap();
    case SerializationTag::kBeginJSSet:
      return ReadJSSet();
    case SerializationTag::kArrayBuffer: {
      constexpr bool is_shared = false;
      constexpr bool is_resizable = false;
      return ReadJSArrayBuffer(is_shared, is_resizable);
    }
    case SerializationTag::kResizableArrayBuffer: {
      constexpr bool is_shared = false;
      constexpr bool is_resizable = true;
      return ReadJSArrayBuffer(is_shared, is_resizable);
    }
    case SerializationTag::kArrayBufferTransfer: {
      return ReadTransferredJSArrayBuffer();
    }
    case SerializationTag::kSharedArrayBuffer: {
      constexpr bool is_shared = true;
      constexpr bool is_resizable = false;
      return ReadJSArrayBuffer(is_shared, is_resizable);
    }
    case SerializationTag::kError:
      return ReadJSError();
#if V8_ENABLE_WEBASSEMBLY
    case SerializationTag::kWasmModuleTransfer:
      return ReadWasmModuleTransfer();
    case SerializationTag::kWasmMemoryTransfer:
      return ReadWasmMemory();
#endif  // V8_ENABLE_WEBASSEMBLY
    case SerializationTag::kHostObject:
      return ReadHostObject();
    case SerializationTag::kSharedObject:
      if (version_ >= 15) return ReadSharedObject();
      // If the data doesn't support shared values because it is from an older
      // version, treat the tag as unknown.
      [[fallthrough]];
    default:
      // Before there was an explicit tag for host objects, all unknown tags
      // were delegated to the host.
      if (version_ < 13) {
        position_--;
        return ReadHostObject();
      }
      return MaybeHandle<Object>();
  }
}

MaybeHandle<String> ValueDeserializer::ReadString() {
  if (version_ < 12) return ReadUtf8String();
  Handle<Object> object;
  if (!ReadObject().ToHandle(&object) || !IsString(*object, isolate_)) {
    return MaybeHandle<String>();
  }
  return Cast<String>(object);
}

MaybeHandle<BigInt> ValueDeserializer::ReadBigInt() {
  uint32_t bitfield;
  if (!ReadVarint<uint32_t>().To(&bitfield)) return MaybeHandle<BigInt>();
  size_t bytelength = BigInt::DigitsByteLengthForBitfield(bitfield);
  base::Vector<const uint8_t> digits_storage;
  if (!ReadRawBytes(bytelength).To(&digits_storage)) {
    return MaybeHandle<BigInt>();
  }
  return BigInt::FromSerializedDigits(isolate_, bitfield, digits_storage);
}

MaybeHandle<String> ValueDeserializer::ReadUtf8String(
    AllocationType allocation) {
  uint32_t utf8_length;
  if (!ReadVarint<uint32_t>().To(&utf8_length)) return {};
  // utf8_length is checked in ReadRawBytes.
  base::Vector<const uint8_t> utf8_bytes;
  if (!ReadRawBytes(utf8_length).To(&utf8_bytes)) return {};
  return isolate_->factory()->NewStringFromUtf8(
      base::Vector<const char>::cast(utf8_bytes), allocation);
}

MaybeHandle<String> ValueDeserializer::ReadOneByteString(
    AllocationType allocation) {
  uint32_t byte_length;
  base::Vector<const uint8_t> bytes;
  if (!ReadVarint<uint32_t>().To(&byte_length)) return {};
  // byte_length is checked in ReadRawBytes.
  if (!ReadRawBytes(byte_length).To(&bytes)) return {};
  return isolate_->factory()->NewStringFromOneByte(bytes, allocation);
}

MaybeHandle<String> ValueDeserializer::ReadTwoByteString(
    AllocationType allocation) {
  uint32_t byte_length;
  base::Vector<const uint8_t> bytes;
  if (!ReadVarint<uint32_t>().To(&byte_length)) return {};
  // byte_length is checked in ReadRawBytes.
  if (byte_length % sizeof(base::uc16) != 0 ||
      !ReadRawBytes(byte_length).To(&bytes)) {
    return MaybeHandle<String>();
  }

  // Allocate an uninitialized string so that we can do a raw memcpy into the
  // string on the heap (regardless of alignment).
  if (byte_length == 0) return isolate_->factory()->empty_string();
  Handle<SeqTwoByteString> string;
  if (!isolate_->factory()
           ->NewRawTwoByteString(byte_length / sizeof(base::uc16), allocation)
           .ToHandle(&string)) {
    return MaybeHandle<String>();
  }

  // Copy the bytes directly into the new string.
  // Warning: this uses host endianness.
  DisallowGarbageCollection no_gc;
  memcpy(string->GetChars(no_gc), bytes.begin(), bytes.length());
  return string;
}

MaybeHandle<JSObject> ValueDeserializer::ReadJSObject() {
  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, MaybeHandle<JSObject>());

  uint32_t id = next_id_++;
  HandleScope scope(isolate_);
  Handle<JSObject> object =
      isolate_->factory()->NewJSObject(isolate_->object_function());
  AddObjectWithID(id, object);

  uint32_t num_properties;
  uint32_t expected_num_properties;
  if (!ReadJSObjectProperties(object, SerializationTag::kEndJSObject, true)
           .To(&num_properties) ||
      !ReadVarint<uint32_t>().To(&expected_num_properties) ||
      num_properties != expected_num_properties) {
    return MaybeHandle<JSObject>();
  }

  DCHECK(HasObjectWithID(id));
  return scope.CloseAndEscape(object);
}

MaybeHandle<JSArray> ValueDeserializer::ReadSparseJSArray() {
  // If we are at the end of the stack, abort. This function may r
"""


```