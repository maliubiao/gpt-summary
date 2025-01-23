Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/value-serializer.cc`. The snippet seems to be part of a deserialization process.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Class:** The code is within the `ValueDeserializer` class. This immediately suggests the code is responsible for reading serialized data and reconstructing V8 JavaScript objects.

2. **Analyze Function Names:** The function names are very descriptive:
    * `ReadSparseJSArray`:  Deals with sparse arrays.
    * `ReadDenseJSArray`: Deals with dense arrays.
    * `ReadJSDate`:  Reconstructs `Date` objects.
    * `ReadJSPrimitiveWrapper`: Handles `Boolean`, `Number`, `BigInt`, and `String` wrapper objects.
    * `ReadJSRegExp`:  Recreates regular expressions.
    * `ReadJSMap`:  Rebuilds `Map` objects.
    * `ReadJSSet`:  Recreates `Set` objects.
    * `ReadJSArrayBuffer`, `ReadTransferredJSArrayBuffer`:  Deal with different types of `ArrayBuffer` objects (shared, resizable, transferred).
    * `ReadJSArrayBufferView`: Handles `TypedArray` and `DataView`.
    * `ReadJSError`: Reconstructs `Error` objects.
    * `ReadWasmModuleTransfer`, `ReadWasmMemory`:  Specific to WebAssembly modules and memory.
    * `ReadSharedObject`:  Handles shared objects, likely for cross-isolate communication.
    * `ReadHostObject`:  Deals with objects provided by the host environment.
    * `ReadJSObjectProperties`:  A helper function for reading object properties.
    * `GetObjectWithID`, `AddObjectWithID`, `HasObjectWithID`: Manage a mapping of IDs to deserialized objects, likely to handle circular references.
    * `ReadObjectUsingEntireBufferForLegacyFormat`:  Handles deserialization of older formats.

3. **Identify Common Patterns:** Several functions follow a similar pattern:
    * Read a tag or length to determine the object type or size.
    * Create a new V8 object instance.
    * Read the object's data from the input buffer.
    * Potentially use `AddObjectWithID` to register the object for later reference.
    * Perform validation checks to ensure the data is consistent.

4. **Look for Key Data Structures and Operations:**
    * `SerializationTag`:  Used to identify the type of object being deserialized.
    * `ReadVarint`, `ReadDouble`, `ReadString`, `ReadRawBytes`, `ReadByte`, `ReadZigZag`: Functions for reading different data types from the serialized stream.
    * `HandleScope`: Used for memory management of V8 objects.
    * `isolate_`:  A pointer to the V8 isolate, the core execution environment.
    * `delegate_`:  A delegate interface, suggesting that some deserialization tasks might be handled by external code (e.g., for `SharedArrayBuffer` and `WasmModule`).
    * `id_map_`:  A map to store deserialized objects by ID, crucial for handling references and cycles.
    * `STACK_CHECK`: A mechanism to prevent stack overflow during recursive deserialization.

5. **Focus on the Provided Snippet:** The specific snippet contains functions for deserializing various JavaScript objects. Notice the consistency in how they read data and reconstruct objects.

6. **Infer Overall Functionality:** Based on the function names and patterns, the overall functionality of `v8/src/objects/value-serializer.cc` is to take a byte stream and reconstruct a graph of JavaScript objects within the V8 engine. This is essential for features like `structuredClone` and inter-process communication.

7. **Address Specific Questions:**
    * **`.tq` extension:** The code is `.cc`, not `.tq`, so it's standard C++ code.
    * **Relationship to JavaScript:**  The code directly implements the deserialization logic for JavaScript objects. The JavaScript examples will demonstrate how the *serialization* (the inverse process) might be used.
    * **Logic and Assumptions:** Focus on the input data (serialized representation) and the output (reconstructed V8 objects). The assumptions are that the input data is a valid serialization.
    * **Common Errors:**  Think about issues that could arise during deserialization, like corrupted data or attempting to deserialize data from an incompatible V8 version.

8. **Structure the Summary:** Organize the findings into a coherent summary covering the key aspects of the code's functionality.

By following these steps, we can generate a comprehensive and accurate summary of the provided code snippet, addressing the user's specific questions.
好的，根据你提供的代码片段，`v8/src/objects/value-serializer.cc` 的第 3 部分主要负责反序列化以下类型的 JavaScript 值：

**反序列化 JavaScript 核心对象:**

* **稀疏数组 (Sparse JSArray):**  `ReadSparseJSArray()`  函数负责读取稀疏数组的序列化数据。这包括数组的长度和属性。稀疏数组指的是包含空洞（holes）的数组，即某些索引上没有定义值。
* **密集数组 (Dense JSArray):** `ReadDenseJSArray()` 函数负责读取密集数组的序列化数据。密集数组在所有索引上都有值。它会读取数组的长度和每个元素的值。
* **Date 对象 (JSDate):** `ReadJSDate()` 函数读取表示 Date 对象的时间戳，并创建一个新的 `JSDate` 对象。
* **原始值包装对象 (JSPrimitiveWrapper):** `ReadJSPrimitiveWrapper()` 函数根据 `SerializationTag` 读取布尔值、数字、BigInt 或字符串的值，并创建对应的包装对象（如 `new Boolean(true)`）。
* **正则表达式对象 (JSRegExp):** `ReadJSRegExp()` 函数读取正则表达式的模式和标志，并创建一个新的 `JSRegExp` 对象。
* **Map 对象 (JSMap):** `ReadJSMap()` 函数读取 Map 对象的键值对，并重新构建 `JSMap`。它会循环读取键值对，直到遇到 `kEndJSMap` 标签。
* **Set 对象 (JSSet):** `ReadJSSet()` 函数读取 Set 对象的值，并重新构建 `JSSet`。它会循环读取值，直到遇到 `kEndJSSet` 标签。
* **ArrayBuffer 对象 (JSArrayBuffer):**
    * `ReadJSArrayBuffer()` 函数用于读取新的 `ArrayBuffer` 对象。它可以处理共享 (`is_shared`) 和可调整大小 (`is_resizable`) 的 `ArrayBuffer`。对于共享 `ArrayBuffer`，它会通过 `delegate_` 获取已存在的 `SharedArrayBuffer`。对于非共享 `ArrayBuffer`，它会分配内存并复制数据。
    * `ReadTransferredJSArrayBuffer()` 函数用于读取已经转移（不再属于原始上下文）的 `ArrayBuffer`。它通过 `transfer_id` 从 `array_buffer_transfer_map_` 中查找并重构 `ArrayBuffer`。
* **ArrayBufferView 对象 (JSArrayBufferView):** `ReadJSArrayBufferView()` 函数用于读取 `DataView` 和各种类型的 `TypedArray`（如 `Int8Array`, `Uint32Array` 等）。它会读取类型标签、字节偏移量、字节长度以及一些标志位。
* **Error 对象 (JSError):** `ReadJSError()` 函数读取不同类型的 `Error` 对象（如 `TypeError`, `RangeError` 等），包括其消息、堆栈信息以及 `cause` 属性。
* **WebAssembly 模块和内存对象 (如果启用了 WebAssembly):**
    * `ReadWasmModuleTransfer()` 函数用于读取转移的 WebAssembly 模块。
    * `ReadWasmMemory()` 函数用于读取 WebAssembly 内存对象。
* **共享对象 (SharedObject):** `ReadSharedObject()` 函数用于读取跨 Isolate 共享的对象。它通过一个 `delegate_` 和 `shared_object_conveyor_` 来获取共享对象。
* **宿主对象 (HostObject):** `ReadHostObject()` 函数用于读取由宿主环境提供的对象。这通常通过 `delegate_` 来实现。

**辅助功能和逻辑:**

* **`ReadJSObjectProperties()`:**  这是一个辅助函数，用于读取普通 JavaScript 对象的属性。它可以处理快速属性（通过 Map 转换）和慢速属性（字典模式）。
* **`HasObjectWithID()`, `GetObjectWithID()`, `AddObjectWithID()`:**  这三个函数用于管理已反序列化对象的 ID 映射。这对于处理循环引用至关重要，确保同一个对象在序列化和反序列化后仍然是同一个逻辑上的实体。当遇到之前反序列化过的对象时，可以直接通过 ID 引用，避免重复创建。
* **`ReadObjectUsingEntireBufferForLegacyFormat()`:**  此函数用于处理旧版本的序列化格式。

**与 JavaScript 的关系 (示例):**

这个 `.cc` 文件中的代码是 V8 引擎内部实现的一部分，负责将序列化后的数据转换回 JavaScript 可以使用的对象。  例如，当你使用 `structuredClone()` 方法在 JavaScript 中克隆一个复杂对象时，V8 内部会使用 `ValueSerializer` 将对象序列化成字节流，然后使用 `ValueDeserializer` 将这个字节流还原成新的对象。

```javascript
// 序列化一个包含不同类型值的对象
const original = {
  name: "Alice",
  age: 30,
  hobbies: ["reading", "coding"],
  birthDate: new Date(),
  isEmployed: true,
  data: new Uint8Array([1, 2, 3]),
  map: new Map([["a", 1], ["b", 2]]),
  set: new Set([1, 2, 3]),
  error: new Error("Something went wrong"),
  regex: /abc/g
};

// 使用 structuredClone 进行克隆 (内部会用到 ValueSerializer 和 ValueDeserializer)
const cloned = structuredClone(original);

// cloned 对象是 original 对象的深拷贝，包含了相同的数据和结构
console.log(cloned.name); // 输出: Alice
console.log(cloned.hobbies); // 输出: ["reading", "coding"]
console.log(cloned.birthDate instanceof Date); // 输出: true
console.log(cloned.data instanceof Uint8Array); // 输出: true
console.log(cloned.map instanceof Map); // 输出: true
console.log(cloned.error instanceof Error); // 输出: true
console.log(cloned.regex instanceof RegExp); // 输出: true
```

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一段表示密集数组 `[10, 20, 30]` 的序列化字节流 (具体的字节流格式是 V8 内部定义的，这里仅作概念性描述)。

**预期输出:**  `ReadDenseJSArray()` 函数会创建一个新的 JavaScript 数组对象，其元素为数字 10, 20, 和 30。

**更具体的假设输入 (概念性):**

假设序列化格式为：`[Tag::kJSArray, length(varint), element1, element2, element3, Tag::kEndDenseJSArray, num_properties(varint), expected_num_properties(varint), expected_length(varint)]`

那么，对于 `[10, 20, 30]`，可能的输入片段如下（仅为示例，实际格式更复杂）：

```
[/* Tag::kJSArray */, 3, /* 序列化的 10 */, /* 序列化的 20 */, /* 序列化的 30 */, /* Tag::kEndDenseJSArray */, 0, 0, 3]
```

**预期 `ReadDenseJSArray()` 的行为:**

1. 读取标签，识别为 `kJSArray` (或类似的表示密集数组的标签)。
2. 读取长度 `3`。
3. 创建一个新的 `JSArray`，长度为 3。
4. 循环读取 3 个元素的值，并将它们添加到数组中。
5. 读取结束标签 `kEndDenseJSArray`。
6. 读取属性相关的信息并进行校验。
7. 返回创建的 `JSArray` 对象。

**用户常见的编程错误 (与序列化/反序列化相关):**

* **尝试反序列化不兼容版本的数据:** 如果序列化数据是由一个 V8 版本生成的，而尝试在另一个不兼容的版本中反序列化，可能会导致错误或意外行为。V8 的序列化格式可能会在不同版本之间发生变化。
* **修改了序列化数据:** 如果用户手动修改了序列化的字节流，可能会导致反序列化失败或产生不正确的结果。
* **假设序列化格式是公开且稳定的:** V8 的序列化格式是内部实现细节，不保证公开稳定。依赖特定的序列化格式进行外部存储或传输可能会导致兼容性问题。
* **忘记处理异步操作中的序列化/反序列化:**  在异步操作中，如果需要传递复杂对象，需要确保正确地序列化和反序列化，特别是在使用 `postMessage` 等 API 时。

**总结 (第 3 部分的功能):**

`v8/src/objects/value-serializer.cc` 的第 3 部分的核心功能是 **反序列化多种核心的 JavaScript 值和对象**。它负责将序列化后的字节流转换回 JavaScript 引擎可以理解和使用的对象，包括基本类型、集合类型、错误对象、以及与 WebAssembly 相关的对象。这部分代码是 V8 引擎实现诸如 `structuredClone` 等功能的关键组成部分。它还管理着已反序列化对象的 ID 映射，以处理循环引用并确保反序列化的正确性。

### 提示词
```
这是目录为v8/src/objects/value-serializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/value-serializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
            isolate_->factory()->New
```