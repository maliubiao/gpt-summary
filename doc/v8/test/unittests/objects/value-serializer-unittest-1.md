Response: The user wants a summary of the provided C++ code snippet, which is part of a larger test file. The file appears to be testing the functionality of a `ValueSerializer` and `ValueDeserializer` in the V8 JavaScript engine.

The snippet focuses on testing the serialization and deserialization of various JavaScript types, particularly:

*   **Regular Expressions (RegExp):**  Testing different flag combinations and the behavior of experimental features.
*   **Maps:**  Testing the round trip, decoding, and preservation of iteration order. It also checks how getters on map keys and values interact with serialization.
*   **Sets:**  Similar tests as for Maps, focusing on round trip, decoding, and iteration order. It also checks the impact of getters during serialization.
*   **ArrayBuffers:** Testing basic serialization, resizable ArrayBuffers, and handling out-of-memory scenarios during deserialization. It also includes tests for transferring ArrayBuffers between contexts.
*   **Typed Arrays:** Testing the serialization and deserialization of different Typed Array types (Uint8Array, Int16Array, Float32Array, etc.), including length-tracking and resizable array buffer backed typed arrays. It also tests backward compatibility for older serialization versions.
*   **DataViews:** Testing basic serialization and deserialization, including resizable array buffer backed DataViews.

The code uses a testing framework with assertions (`ASSERT_TRUE`, `EXPECT_EQ`, `ExpectScriptTrue`) to verify the correctness of the serialization and deserialization process. `RoundTripTest` likely serializes and then deserializes a JavaScript value, while `DecodeTest` directly deserializes a given byte sequence. `InvalidDecodeTest` checks if the deserializer correctly handles invalid byte sequences.

The user also requests a JavaScript example to illustrate the functionality being tested. Given the focus on Maps, Sets, ArrayBuffers, and Typed Arrays, a good example would involve creating these objects, serializing them, and then deserializing them, comparing the original and the deserialized versions.
这是对 `v8/test/unittests/objects/value-serializer-unittest.cc` 源代码文件的第二部分内容的归纳。 这部分主要关注 `ValueSerializer` 和 `ValueDeserializer` 对以下 JavaScript 类型的序列化和反序列化功能的测试：

**功能归纳:**

*   **正则表达式 (RegExp):**
    *   测试了正则表达式的编码和解码，包括各种标志（如 `i`, `m`, `s`, `y`, `d`, `v`）。
    *   测试了对包含 Unicode 字符的正则表达式的处理。
    *   测试了反序列化时对无效标志的处理。
    *   测试了实验性的线性正则表达式和 `hasIndices` 属性的编码和解码，并使用了条件编译 (`i::v8_flags.enable_experimental_regexp_engine`) 来控制相关测试。
    *   测试了 `unicodeSets` 标志的编码和解码，并确保互斥的标志不会被同时接受。

*   **Map 对象:**
    *   测试了 `Map` 对象的完整序列化和反序列化过程 (`RoundTripTest`)，包括其内部键值对的存储和恢复。
    *   验证了反序列化后 `Map` 对象的原型 (`Map.prototype`) 和大小 (`size`)。
    *   测试了 `Map` 对象中自引用的情况 (`m.set(m, m)`)。
    *   **重点：** 测试了 `Map` 中键值对的插入顺序是否在序列化和反序列化后得到保留。
    *   测试了在序列化过程中，如果访问 `Map` 的键或值的 getter 方法会修改 `Map` 本身（例如删除或添加元素），序列化器是否会使用原始的键值对。
    *   验证了对尚未序列化的对象的更深层次的修改仍然会生效。

*   **Set 对象:**
    *   测试了 `Set` 对象的完整序列化和反序列化过程 (`RoundTripTest`)，包括其内部元素的存储和恢复。
    *   验证了反序列化后 `Set` 对象的原型 (`Set.prototype`) 和大小 (`size`)。
    *   测试了 `Set` 对象中自引用的情况 (`s.add(s)`)。
    *   **重点：** 测试了 `Set` 中元素的插入顺序是否在序列化和反序列化后得到保留。
    *   测试了在序列化过程中，如果访问 `Set` 元素的 getter 方法会修改 `Set` 本身（例如删除或添加元素），序列化器是否会使用原始的元素集合。
    *   验证了对尚未序列化的对象的更深层次的修改仍然会生效。

*   **ArrayBuffer 对象:**
    *   测试了 `ArrayBuffer` 对象的序列化和反序列化，包括空 `ArrayBuffer` 和包含数据的 `ArrayBuffer`。
    *   验证了反序列化后 `ArrayBuffer` 对象的字节长度 (`ByteLength`) 和原型 (`ArrayBuffer.prototype`)。
    *   测试了包含循环引用的 `ArrayBuffer` 的序列化和反序列化。
    *   测试了可调整大小的 `ArrayBuffer` (`ResizableArrayBuffer`) 的序列化和反序列化，包括 `maxByteLength` 属性。
    *   通过 `DecodeTestFutureVersions` 测试了未来版本中 `ArrayBuffer` 的解码兼容性。
    *   通过 `DecodeInvalidArrayBuffer` 测试了对无效的 `ArrayBuffer` 数据的处理。
    *   通过 `DecodeInvalidResizableArrayBuffer` 测试了对无效的可调整大小的 `ArrayBuffer` 数据的处理。
    *   模拟了内存不足 (OOM) 的情况来测试 `ValueDeserializer` 在反序列化 `ArrayBuffer` 时的处理。
    *   引入了 `ValueSerializerTestWithArrayBufferTransfer` 测试类，专门测试 `ArrayBuffer` 在序列化和反序列化过程中的转移 (transfer)，确保在不同上下文之间正确传递 `ArrayBuffer` 的所有权。

**与 Javascript 功能的关系及 Javascript 示例:**

这部分测试直接关系到 JavaScript 中数据的持久化和跨上下文传输。 `ValueSerializer` 和 `ValueDeserializer` 的功能类似于 JavaScript 的 `structuredClone` API (以及早期的 `postMessage` 使用的序列化机制)，可以将复杂的 JavaScript 对象转换为字节流，以便存储或传输，并在需要时恢复。

**Javascript 示例:**

```javascript
// 创建一个包含 Map、Set 和 ArrayBuffer 的对象
const originalObject = {
  map: new Map([[42, 'foo'], ['bar', { a: 1 }]]),
  set: new Set([1, 'hello', { b: 2 }]),
  buffer: new Uint8Array([0, 128, 255]).buffer,
  regexp: /hello/gi
};

// 假设存在一个 ValueSerializer 和 ValueDeserializer 的 C++ 绑定
// (这只是一个概念性的例子，实际 V8 内部使用，无法直接在 JS 中访问)
// function serialize(value) { /* ... C++ 序列化逻辑 ... */ }
// function deserialize(bytes) { /* ... C++ 反序列化逻辑 ... */ }

// 模拟序列化
// const serializedData = serialize(originalObject);
const serializedData = new Uint8Array([
  // ... (假设的序列化后的字节流) ...
]);

// 模拟反序列化
// const deserializedObject = deserialize(serializedData);
const deserializedObject = { /* ... (假设的反序列化后的对象) ... */ };

// 验证反序列化后的对象
console.log(deserializedObject.map instanceof Map); // true
console.log(deserializedObject.map.get(42));       // 'foo'
console.log(deserializedObject.set instanceof Set); // true
console.log(deserializedObject.set.has('hello'));  // true
console.log(deserializedObject.buffer instanceof ArrayBuffer); // true
console.log(new Uint8Array(deserializedObject.buffer).toString()); // '0,128,255'
console.log(deserializedObject.regexp instanceof RegExp); // true
console.log(deserializedObject.regexp.flags); // 'gi'
```

**总结:**

这部分测试全面地验证了 V8 引擎中 `ValueSerializer` 和 `ValueDeserializer` 组件对于 JavaScript 中常用复杂数据类型（正则表达式、Map、Set、ArrayBuffer）的序列化和反序列化功能的正确性和健壮性。它涵盖了正常情况、边界情况、错误情况以及对未来版本和旧版本的兼容性测试，确保了数据在序列化和反序列化过程中的完整性和一致性。 尤其关注了 Map 和 Set 的元素顺序以及在序列化过程中 getter 方法可能带来的影响，这对于保证 JavaScript 程序的行为至关重要。对于 ArrayBuffer，还特别测试了其在跨上下文传输时的特殊处理。

Prompt: ```这是目录为v8/test/unittests/objects/value-serializer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""

        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("result.toString() === '/Qu\\xe9bec/i'");
      });
}

// Tests that invalid flags are not accepted by the deserializer.
TEST_F(ValueSerializerTest, DecodeRegExpDotAll) {
  DecodeTestUpToVersion(
      11, {0xFF, 0x09, 0x3F, 0x00, 0x52, 0x03, 0x66, 0x6F, 0x6F, 0x1F},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("Object.getPrototypeOf(result) === RegExp.prototype");
        ExpectScriptTrue("result.toString() === '/foo/gimuy'");
      });

  DecodeTestUpToVersion(
      11, {0xFF, 0x09, 0x3F, 0x00, 0x52, 0x03, 0x66, 0x6F, 0x6F, 0x3F},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("Object.getPrototypeOf(result) === RegExp.prototype");
        ExpectScriptTrue("result.toString() === '/foo/gimsuy'");
      });

  InvalidDecodeTest(
      {0xFF, 0x09, 0x3F, 0x00, 0x52, 0x03, 0x66, 0x6F, 0x6F, 0xFF});
}

TEST_F(ValueSerializerTest, DecodeLinearRegExp) {
  bool flag_was_enabled = i::v8_flags.enable_experimental_regexp_engine;

  // The last byte encodes the regexp flags.
  std::vector<uint8_t> regexp_encoding = {0xFF, 0x09, 0x3F, 0x00, 0x52,
                                          0x03, 0x66, 0x6F, 0x6F, 0x6D};

  i::v8_flags.enable_experimental_regexp_engine = true;
  // DecodeTestUpToVersion will overwrite the version number in the data but
  // it's fine.
  DecodeTestUpToVersion(
      11, std::move(regexp_encoding), [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("Object.getPrototypeOf(result) === RegExp.prototype");
        ExpectScriptTrue("result.toString() === '/foo/glmsy'");
      });

  i::v8_flags.enable_experimental_regexp_engine = false;
  InvalidDecodeTest(regexp_encoding);

  i::v8_flags.enable_experimental_regexp_engine = flag_was_enabled;
}

TEST_F(ValueSerializerTest, DecodeHasIndicesRegExp) {
  // The last byte encodes the regexp flags.
  std::vector<uint8_t> regexp_encoding = {0xFF, 0x09, 0x3F, 0x00, 0x52, 0x03,
                                          0x66, 0x6F, 0x6F, 0xAD, 0x01};

  DecodeTestUpToVersion(
      11, std::move(regexp_encoding), [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("Object.getPrototypeOf(result) === RegExp.prototype");
        ExpectScriptTrue("result.toString() === '/foo/dgmsy'");
      });
}

TEST_F(ValueSerializerTest, DecodeRegExpUnicodeSets) {
  // The last two bytes encode the regexp flags.
  std::vector<uint8_t> regexp_encoding = {
      0xFF, 0x0C,        // Version 12
      0x52,              // RegExp
      0x22, 0x03,        // 3 char OneByteString
      0x66, 0x6F, 0x6F,  // String content "foo"
      0x83, 0x02         // Flags giv
  };
  DecodeTestUpToVersion(
      15, std::move(regexp_encoding), [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("Object.getPrototypeOf(result) === RegExp.prototype");
        ExpectScriptTrue("result.toString() === '/foo/giv'");
      });

  // Flags u and v are mutually exclusive.
  InvalidDecodeTest({
      0xFF, 0x0C,        // Version 12
      0x52,              // RegExp
      0x22, 0x03,        // 3 char OneByteString
      0x66, 0x6F, 0x6F,  // String content "foo"
      0x93, 0x02         // Flags giuv
  });
}

TEST_F(ValueSerializerTest, RoundTripMap) {
  Local<Value> value = RoundTripTest("var m = new Map(); m.set(42, 'foo'); m;");
  ASSERT_TRUE(value->IsMap());
  ExpectScriptTrue("Object.getPrototypeOf(result) === Map.prototype");
  ExpectScriptTrue("result.size === 1");
  ExpectScriptTrue("result.get(42) === 'foo'");

  value = RoundTripTest("var m = new Map(); m.set(m, m); m;");
  ASSERT_TRUE(value->IsMap());
  ExpectScriptTrue("result.size === 1");
  ExpectScriptTrue("result.get(result) === result");

  // Iteration order must be preserved.
  value = RoundTripTest(
      "var m = new Map();"
      "m.set(1, 0); m.set('a', 0); m.set(3, 0); m.set(2, 0);"
      "m;");
  ASSERT_TRUE(value->IsMap());
  ExpectScriptTrue("Array.from(result.keys()).toString() === '1,a,3,2'");
}

TEST_F(ValueSerializerTest, DecodeMap) {
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x3B, 0x3F, 0x01, 0x49, 0x54, 0x3F, 0x01, 0x53,
       0x03, 0x66, 0x6F, 0x6F, 0x3A, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsMap());
        ExpectScriptTrue("Object.getPrototypeOf(result) === Map.prototype");
        ExpectScriptTrue("result.size === 1");
        ExpectScriptTrue("result.get(42) === 'foo'");
      });

  DecodeTestFutureVersions({0xFF, 0x09, 0x3F, 0x00, 0x3B, 0x3F, 0x01, 0x5E,
                            0x00, 0x3F, 0x01, 0x5E, 0x00, 0x3A, 0x02, 0x00},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsMap());
                             ExpectScriptTrue("result.size === 1");
                             ExpectScriptTrue("result.get(result) === result");
                           });

  // Iteration order must be preserved.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x3B, 0x3F, 0x01, 0x49, 0x02, 0x3F,
       0x01, 0x49, 0x00, 0x3F, 0x01, 0x53, 0x01, 0x61, 0x3F, 0x01,
       0x49, 0x00, 0x3F, 0x01, 0x49, 0x06, 0x3F, 0x01, 0x49, 0x00,
       0x3F, 0x01, 0x49, 0x04, 0x3F, 0x01, 0x49, 0x00, 0x3A, 0x08},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsMap());
        ExpectScriptTrue("Array.from(result.keys()).toString() === '1,a,3,2'");
      });
}

TEST_F(ValueSerializerTest, RoundTripMapWithTrickyGetters) {
  // Even if an entry is removed or reassigned, the original key/value pair is
  // used.
  Local<Value> value = RoundTripTest(
      "var m = new Map();"
      "m.set(0, { get a() {"
      "  m.delete(1); m.set(2, 'baz'); m.set(3, 'quux');"
      "}});"
      "m.set(1, 'foo');"
      "m.set(2, 'bar');"
      "m;");
  ASSERT_TRUE(value->IsMap());
  ExpectScriptTrue("Array.from(result.keys()).toString() === '0,1,2'");
  ExpectScriptTrue("result.get(1) === 'foo'");
  ExpectScriptTrue("result.get(2) === 'bar'");

  // However, deeper modifications of objects yet to be serialized still apply.
  value = RoundTripTest(
      "var m = new Map();"
      "var key = { get a() { value.foo = 'bar'; } };"
      "var value = { get a() { key.baz = 'quux'; } };"
      "m.set(key, value);"
      "m;");
  ASSERT_TRUE(value->IsMap());
  ExpectScriptTrue("!('baz' in Array.from(result.keys())[0])");
  ExpectScriptTrue("Array.from(result.values())[0].foo === 'bar'");
}

TEST_F(ValueSerializerTest, RoundTripSet) {
  Local<Value> value =
      RoundTripTest("var s = new Set(); s.add(42); s.add('foo'); s;");
  ASSERT_TRUE(value->IsSet());
  ExpectScriptTrue("Object.getPrototypeOf(result) === Set.prototype");
  ExpectScriptTrue("result.size === 2");
  ExpectScriptTrue("result.has(42)");
  ExpectScriptTrue("result.has('foo')");

  value = RoundTripTest("var s = new Set(); s.add(s); s;");
  ASSERT_TRUE(value->IsSet());
  ExpectScriptTrue("result.size === 1");
  ExpectScriptTrue("result.has(result)");

  // Iteration order must be preserved.
  value = RoundTripTest(
      "var s = new Set();"
      "s.add(1); s.add('a'); s.add(3); s.add(2);"
      "s;");
  ASSERT_TRUE(value->IsSet());
  ExpectScriptTrue("Array.from(result.keys()).toString() === '1,a,3,2'");
}

TEST_F(ValueSerializerTest, DecodeSet) {
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x27, 0x3F, 0x01, 0x49, 0x54, 0x3F, 0x01, 0x53,
       0x03, 0x66, 0x6F, 0x6F, 0x2C, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsSet());
        ExpectScriptTrue("Object.getPrototypeOf(result) === Set.prototype");
        ExpectScriptTrue("result.size === 2");
        ExpectScriptTrue("result.has(42)");
        ExpectScriptTrue("result.has('foo')");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x27, 0x3F, 0x01, 0x5E, 0x00, 0x2C, 0x01, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsSet());
        ExpectScriptTrue("result.size === 1");
        ExpectScriptTrue("result.has(result)");
      });

  // Iteration order must be preserved.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x27, 0x3F, 0x01, 0x49, 0x02, 0x3F, 0x01, 0x53,
       0x01, 0x61, 0x3F, 0x01, 0x49, 0x06, 0x3F, 0x01, 0x49, 0x04, 0x2C, 0x04},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsSet());
        ExpectScriptTrue("Array.from(result.keys()).toString() === '1,a,3,2'");
      });
}

TEST_F(ValueSerializerTest, RoundTripSetWithTrickyGetters) {
  // Even if an element is added or removed during serialization, the original
  // set of elements is used.
  Local<Value> value = RoundTripTest(
      "var s = new Set();"
      "s.add({ get a() { s.delete(1); s.add(2); } });"
      "s.add(1);"
      "s;");
  ASSERT_TRUE(value->IsSet());
  ExpectScriptTrue(
      "Array.from(result.keys()).toString() === '[object Object],1'");

  // However, deeper modifications of objects yet to be serialized still apply.
  value = RoundTripTest(
      "var s = new Set();"
      "var first = { get a() { second.foo = 'bar'; } };"
      "var second = { get a() { first.baz = 'quux'; } };"
      "s.add(first);"
      "s.add(second);"
      "s;");
  ASSERT_TRUE(value->IsSet());
  ExpectScriptTrue("!('baz' in Array.from(result.keys())[0])");
  ExpectScriptTrue("Array.from(result.keys())[1].foo === 'bar'");
}

TEST_F(ValueSerializerTest, RoundTripArrayBuffer) {
  Local<Value> value = RoundTripTest("new ArrayBuffer()");
  ASSERT_TRUE(value->IsArrayBuffer());
  EXPECT_EQ(0u, ArrayBuffer::Cast(*value)->ByteLength());
  ExpectScriptTrue("Object.getPrototypeOf(result) === ArrayBuffer.prototype");
  // TODO(v8:11111): Use API functions for testing max_byte_length and resizable
  // once they're exposed via the API.
  i::DirectHandle<i::JSArrayBuffer> array_buffer =
      Utils::OpenDirectHandle(ArrayBuffer::Cast(*value));
  EXPECT_EQ(0u, array_buffer->max_byte_length());
  EXPECT_EQ(false, array_buffer->is_resizable_by_js());

  value = RoundTripTest("new Uint8Array([0, 128, 255]).buffer");
  ASSERT_TRUE(value->IsArrayBuffer());
  EXPECT_EQ(3u, ArrayBuffer::Cast(*value)->ByteLength());
  ExpectScriptTrue("new Uint8Array(result).toString() === '0,128,255'");
  array_buffer = Utils::OpenDirectHandle(ArrayBuffer::Cast(*value));
  EXPECT_EQ(3u, array_buffer->max_byte_length());
  EXPECT_EQ(false, array_buffer->is_resizable_by_js());

  value =
      RoundTripTest("({ a: new ArrayBuffer(), get b() { return this.a; }})");
  ExpectScriptTrue("result.a instanceof ArrayBuffer");
  ExpectScriptTrue("result.a === result.b");
}

TEST_F(ValueSerializerTest, RoundTripResizableArrayBuffer) {
  Local<Value> value =
      RoundTripTest("new ArrayBuffer(100, {maxByteLength: 200})");
  ASSERT_TRUE(value->IsArrayBuffer());
  EXPECT_EQ(100u, ArrayBuffer::Cast(*value)->ByteLength());

  // TODO(v8:11111): Use API functions for testing max_byte_length and resizable
  // once they're exposed via the API.
  i::DirectHandle<i::JSArrayBuffer> array_buffer =
      Utils::OpenDirectHandle(ArrayBuffer::Cast(*value));
  EXPECT_EQ(200u, array_buffer->max_byte_length());
  EXPECT_EQ(true, array_buffer->is_resizable_by_js());
}

TEST_F(ValueSerializerTest, DecodeArrayBuffer) {
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x42, 0x00}, [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArrayBuffer());
        EXPECT_EQ(0u, ArrayBuffer::Cast(*value)->ByteLength());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === ArrayBuffer.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x42, 0x03, 0x00, 0x80, 0xFF, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArrayBuffer());
        EXPECT_EQ(3u, ArrayBuffer::Cast(*value)->ByteLength());
        ExpectScriptTrue("new Uint8Array(result).toString() === '0,128,255'");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01,
       0x61, 0x3F, 0x01, 0x42, 0x00, 0x3F, 0x02, 0x53, 0x01,
       0x62, 0x3F, 0x02, 0x5E, 0x01, 0x7B, 0x02, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.a instanceof ArrayBuffer");
        ExpectScriptTrue("result.a === result.b");
      });
}

TEST_F(ValueSerializerTest, DecodeInvalidArrayBuffer) {
  InvalidDecodeTest({0xFF, 0x09, 0x42, 0xFF, 0xFF, 0x00});
}

TEST_F(ValueSerializerTest, DecodeInvalidResizableArrayBuffer) {
  // Enough bytes available after reading the length, but not anymore when
  // reading the max byte length.
  InvalidDecodeTest({0xFF, 0x09, 0x7E, 0x2, 0x10, 0x00});
}

// An array buffer allocator that never has available memory.
class OOMArrayBufferAllocator : public ArrayBuffer::Allocator {
 public:
  void* Allocate(size_t) override { return nullptr; }
  void* AllocateUninitialized(size_t) override { return nullptr; }
  void Free(void*, size_t) override {}
};

TEST_F(ValueSerializerTest, DecodeArrayBufferOOM) {
  // This test uses less of the harness, because it has to customize the
  // isolate.
  OOMArrayBufferAllocator allocator;
  Isolate::CreateParams params;
  params.array_buffer_allocator = &allocator;
  Isolate* isolate = Isolate::New(params);
  {
    Isolate::Scope isolate_scope(isolate);
    HandleScope handle_scope(isolate);
    Local<Context> context = Context::New(isolate);
    Context::Scope context_scope(context);
    TryCatch try_catch(isolate);

    const std::vector<uint8_t> data = {0xFF, 0x09, 0x3F, 0x00, 0x42,
                                       0x03, 0x00, 0x80, 0xFF, 0x00};
    ValueDeserializer deserializer(isolate, &data[0],
                                   static_cast<int>(data.size()), nullptr);
    deserializer.SetSupportsLegacyWireFormat(true);
    ASSERT_TRUE(deserializer.ReadHeader(context).FromMaybe(false));
    ASSERT_FALSE(try_catch.HasCaught());
    EXPECT_TRUE(deserializer.ReadValue(context).IsEmpty());
    EXPECT_TRUE(try_catch.HasCaught());
  }
  isolate->Dispose();
}

// Includes an ArrayBuffer wrapper marked for transfer from the serialization
// context to the deserialization context.
class ValueSerializerTestWithArrayBufferTransfer : public ValueSerializerTest {
 protected:
  static const size_t kTestByteLength = 4;

  ValueSerializerTestWithArrayBufferTransfer() {
    {
      Context::Scope scope(serialization_context());
      input_buffer_.Reset(isolate(), ArrayBuffer::New(isolate(), 0));
    }
    {
      Context::Scope scope(deserialization_context());
      output_buffer_.Reset(isolate(),
                           ArrayBuffer::New(isolate(), kTestByteLength));
      const uint8_t data[kTestByteLength] = {0x00, 0x01, 0x80, 0xFF};
      memcpy(output_buffer()->GetBackingStore()->Data(), data, kTestByteLength);
    }
  }

  Local<ArrayBuffer> input_buffer() { return input_buffer_.Get(isolate()); }
  Local<ArrayBuffer> output_buffer() { return output_buffer_.Get(isolate()); }

  void BeforeEncode(ValueSerializer* serializer) override {
    serializer->TransferArrayBuffer(0, input_buffer());
  }

  void BeforeDecode(ValueDeserializer* deserializer) override {
    deserializer->TransferArrayBuffer(0, output_buffer());
  }

 private:
  Global<ArrayBuffer> input_buffer_;
  Global<ArrayBuffer> output_buffer_;
};

TEST_F(ValueSerializerTestWithArrayBufferTransfer,
       RoundTripArrayBufferTransfer) {
  Local<Value> value = RoundTripTest(input_buffer());
  ASSERT_TRUE(value->IsArrayBuffer());
  EXPECT_EQ(output_buffer(), value);
  ExpectScriptTrue("new Uint8Array(result).toString() === '0,1,128,255'");

  Local<Object> object;
  {
    Context::Scope scope(serialization_context());
    object = Object::New(isolate());
    EXPECT_TRUE(object
                    ->CreateDataProperty(serialization_context(),
                                         StringFromUtf8("a"), input_buffer())
                    .FromMaybe(false));
    EXPECT_TRUE(object
                    ->CreateDataProperty(serialization_context(),
                                         StringFromUtf8("b"), input_buffer())
                    .FromMaybe(false));
  }
  value = RoundTripTest(object);
  ExpectScriptTrue("result.a instanceof ArrayBuffer");
  ExpectScriptTrue("result.a === result.b");
  ExpectScriptTrue("new Uint8Array(result.a).toString() === '0,1,128,255'");
}

TEST_F(ValueSerializerTest, RoundTripTypedArray) {
  FLAG_SCOPE(js_float16array);
  // Check that the right type comes out the other side for every kind of typed
  // array.
  // TODO(v8:11111): Use API functions for testing is_length_tracking and
  // is_backed_by_rab, once they're exposed via the API.
  Local<Value> value;
  i::DirectHandle<i::JSTypedArray> i_ta;
#define TYPED_ARRAY_ROUND_TRIP_TEST(Type, type, TYPE, ctype)             \
  value = RoundTripTest("new " #Type "Array(2)");                        \
  ASSERT_TRUE(value->Is##Type##Array());                                 \
  EXPECT_EQ(2u * sizeof(ctype), TypedArray::Cast(*value)->ByteLength()); \
  EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());                     \
  ExpectScriptTrue("Object.getPrototypeOf(result) === " #Type            \
                   "Array.prototype");                                   \
  i_ta = v8::Utils::OpenDirectHandle(TypedArray::Cast(*value));          \
  EXPECT_EQ(false, i_ta->is_length_tracking());                          \
  EXPECT_EQ(false, i_ta->is_backed_by_rab());

  TYPED_ARRAYS(TYPED_ARRAY_ROUND_TRIP_TEST)
#undef TYPED_ARRAY_ROUND_TRIP_TEST

  // Check that values of various kinds are suitably preserved.
  value = RoundTripTest("new Uint8Array([1, 128, 255])");
  ExpectScriptTrue("result.toString() === '1,128,255'");

  value = RoundTripTest("new Int16Array([0, 256, -32768])");
  ExpectScriptTrue("result.toString() === '0,256,-32768'");

  value = RoundTripTest("new Float32Array([0, -0.5, NaN, Infinity])");
  ExpectScriptTrue("result.toString() === '0,-0.5,NaN,Infinity'");

  // Array buffer views sharing a buffer should do so on the other side.
  // Similarly, multiple references to the same typed array should be resolved.
  value = RoundTripTest(
      "var buffer = new ArrayBuffer(32);"
      "({"
      "  u8: new Uint8Array(buffer),"
      "  get u8_2() { return this.u8; },"
      "  f32: new Float32Array(buffer, 4, 5),"
      "  b: buffer,"
      "});");
  ExpectScriptTrue("result.u8 instanceof Uint8Array");
  ExpectScriptTrue("result.u8 === result.u8_2");
  ExpectScriptTrue("result.f32 instanceof Float32Array");
  ExpectScriptTrue("result.u8.buffer === result.f32.buffer");
  ExpectScriptTrue("result.f32.byteOffset === 4");
  ExpectScriptTrue("result.f32.length === 5");
}

TEST_F(ValueSerializerTest, RoundTripRabBackedLengthTrackingTypedArray) {
  FLAG_SCOPE(js_float16array);
  // Check that the right type comes out the other side for every kind of typed
  // array.
  // TODO(v8:11111): Use API functions for testing is_length_tracking and
  // is_backed_by_rab, once they're exposed via the API.
  Local<Value> value;
  i::DirectHandle<i::JSTypedArray> i_ta;
#define TYPED_ARRAY_ROUND_TRIP_TEST(Type, type, TYPE, ctype)          \
  value = RoundTripTest("new " #Type                                  \
                        "Array(new ArrayBuffer(80, "                  \
                        "{maxByteLength: 160}))");                    \
  ASSERT_TRUE(value->Is##Type##Array());                              \
  EXPECT_EQ(80u, TypedArray::Cast(*value)->ByteLength());             \
  EXPECT_EQ(80u / sizeof(ctype), TypedArray::Cast(*value)->Length()); \
  ExpectScriptTrue("Object.getPrototypeOf(result) === " #Type         \
                   "Array.prototype");                                \
  i_ta = v8::Utils::OpenDirectHandle(TypedArray::Cast(*value));       \
  EXPECT_EQ(true, i_ta->is_length_tracking());                        \
  EXPECT_EQ(true, i_ta->is_backed_by_rab());

  TYPED_ARRAYS(TYPED_ARRAY_ROUND_TRIP_TEST)
#undef TYPED_ARRAY_ROUND_TRIP_TEST
}

TEST_F(ValueSerializerTest, RoundTripRabBackedNonLengthTrackingTypedArray) {
  FLAG_SCOPE(js_float16array);
  // Check that the right type comes out the other side for every kind of typed
  // array.
  // TODO(v8:11111): Use API functions for testing is_length_tracking and
  // is_backed_by_rab, once they're exposed via the API.
  Local<Value> value;
  i::DirectHandle<i::JSTypedArray> i_ta;
#define TYPED_ARRAY_ROUND_TRIP_TEST(Type, type, TYPE, ctype)             \
  value = RoundTripTest("new " #Type                                     \
                        "Array(new ArrayBuffer(80, "                     \
                        "{maxByteLength: 160}), 8, 4)");                 \
  ASSERT_TRUE(value->Is##Type##Array());                                 \
  EXPECT_EQ(4u * sizeof(ctype), TypedArray::Cast(*value)->ByteLength()); \
  EXPECT_EQ(4u, TypedArray::Cast(*value)->Length());                     \
  ExpectScriptTrue("Object.getPrototypeOf(result) === " #Type            \
                   "Array.prototype");                                   \
  i_ta = v8::Utils::OpenDirectHandle(TypedArray::Cast(*value));          \
  EXPECT_EQ(false, i_ta->is_length_tracking());                          \
  EXPECT_EQ(true, i_ta->is_backed_by_rab());

  TYPED_ARRAYS(TYPED_ARRAY_ROUND_TRIP_TEST)
#undef TYPED_ARRAY_ROUND_TRIP_TEST
}

TEST_F(ValueSerializerTest, DecodeTypedArray) {
  // Check that the right type comes out the other side for every kind of typed
  // array (version 14 and above).
  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x02, 0x00, 0x00, 0x56, 0x42,
       0x00, 0x02, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsUint8Array());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Uint8Array.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x02, 0x00, 0x00, 0x56, 0x62,
       0x00, 0x02, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsInt8Array());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Int8Array.prototype");
      });

#if defined(V8_TARGET_LITTLE_ENDIAN)
  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00,
       0x56, 0x57, 0x00, 0x04, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsUint16Array());
        EXPECT_EQ(4u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Uint16Array.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00,
       0x56, 0x77, 0x00, 0x04, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsInt16Array());
        EXPECT_EQ(4u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Int16Array.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x08, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x44, 0x00, 0x08, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsUint32Array());
        EXPECT_EQ(8u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Uint32Array.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x08, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x64, 0x00, 0x08, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsInt32Array());
        EXPECT_EQ(8u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Int32Array.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x08, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x66, 0x00, 0x08, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsFloat32Array());
        EXPECT_EQ(8u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Float32Array.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x10, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x56, 0x46, 0x00, 0x10, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsFloat64Array());
        EXPECT_EQ(16u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Float64Array.prototype");
      });

#endif  // V8_TARGET_LITTLE_ENDIAN

  // Check that values of various kinds are suitably preserved.
  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x03, 0x01, 0x80, 0xFF, 0x56,
       0x42, 0x00, 0x03, 0x00, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.toString() === '1,128,255'");
      });
#if defined(V8_TARGET_LITTLE_ENDIAN)
  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x06, 0x00, 0x00, 0x00, 0x01,
       0x00, 0x80, 0x56, 0x77, 0x00, 0x06, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.toString() === '0,256,-32768'");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x10, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0xC0, 0x7F,
       0x00, 0x00, 0x80, 0x7F, 0x56, 0x66, 0x00, 0x10, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.toString() === '0,-0.5,NaN,Infinity'");
      });

#endif  // V8_TARGET_LITTLE_ENDIAN

  // Array buffer views sharing a buffer should do so on the other side.
  // Similarly, multiple references to the same typed array should be resolved.
  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x02, 0x75, 0x38, 0x3F,
       0x01, 0x3F, 0x01, 0x42, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x56, 0x42, 0x00, 0x20, 0x00, 0x3F, 0x03, 0x53, 0x04, 0x75, 0x38,
       0x5F, 0x32, 0x3F, 0x03, 0x5E, 0x02, 0x3F, 0x03, 0x53, 0x03, 0x66, 0x33,
       0x32, 0x3F, 0x03, 0x3F, 0x03, 0x5E, 0x01, 0x56, 0x66, 0x04, 0x14, 0x00,
       0x3F, 0x04, 0x53, 0x01, 0x62, 0x3F, 0x04, 0x5E, 0x01, 0x7B, 0x04, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.u8 instanceof Uint8Array");
        ExpectScriptTrue("result.u8 === result.u8_2");
        ExpectScriptTrue("result.f32 instanceof Float32Array");
        ExpectScriptTrue("result.u8.buffer === result.f32.buffer");
        ExpectScriptTrue("result.f32.byteOffset === 4");
        ExpectScriptTrue("result.f32.length === 5");
      });
}

TEST_F(ValueSerializerTest, DecodeTypedArrayBackwardsCompatiblity) {
  // Check that we can still decode TypedArrays in the version <= 13 format.
  DecodeTestUpToVersion(
      13,
      {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x02, 0x00, 0x00, 0x56, 0x42,
       0x00, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsUint8Array());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Uint8Array.prototype");
      });

  DecodeTestUpToVersion(
      13,
      {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x02, 0x00, 0x00, 0x56, 0x62,
       0x00, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsInt8Array());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Int8Array.prototype");
      });
#if defined(V8_TARGET_LITTLE_ENDIAN)
  DecodeTestUpToVersion(
      13,
      {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00,
       0x56, 0x57, 0x00, 0x04},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsUint16Array());
        EXPECT_EQ(4u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Uint16Array.prototype");
      });

  DecodeTestUpToVersion(
      13,
      {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00,
       0x56, 0x77, 0x00, 0x04},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsInt16Array());
        EXPECT_EQ(4u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Int16Array.prototype");
      });

  DecodeTestUpToVersion(
      13, {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x08, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x44, 0x00, 0x08},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsUint32Array());
        EXPECT_EQ(8u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Uint32Array.prototype");
      });

  DecodeTestUpToVersion(
      13, {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x08, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x64, 0x00, 0x08},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsInt32Array());
        EXPECT_EQ(8u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Int32Array.prototype");
      });

  DecodeTestUpToVersion(
      13, {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x08, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x66, 0x00, 0x08},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsFloat32Array());
        EXPECT_EQ(8u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Float32Array.prototype");
      });

  DecodeTestUpToVersion(
      13, {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x10, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x56, 0x46, 0x00, 0x10},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsFloat64Array());
        EXPECT_EQ(16u, TypedArray::Cast(*value)->ByteLength());
        EXPECT_EQ(2u, TypedArray::Cast(*value)->Length());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === Float64Array.prototype");
      });

#endif  // V8_TARGET_LITTLE_ENDIAN

  // Check that values of various kinds are suitably preserved.
  DecodeTestUpToVersion(13,
                        {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x03, 0x01,
                         0x80, 0xFF, 0x56, 0x42, 0x00, 0x03},
                        [this](Local<Value> value) {
                          ExpectScriptTrue("result.toString() === '1,128,255'");
                        });

#if defined(V8_TARGET_LITTLE_ENDIAN)
  DecodeTestUpToVersion(
      13,
      {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x06, 0x00, 0x00, 0x00, 0x01,
       0x00, 0x80, 0x56, 0x77, 0x00, 0x06},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.toString() === '0,256,-32768'");
      });

  DecodeTestUpToVersion(
      13, {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x10, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0xC0, 0x7F,
           0x00, 0x00, 0x80, 0x7F, 0x56, 0x66, 0x00, 0x10},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.toString() === '0,-0.5,NaN,Infinity'");
      });
#endif  // V8_TARGET_LITTLE_ENDIAN

  // Array buffer views sharing a buffer should do so on the other side.
  // Similarly, multiple references to the same typed array should be resolved.
  DecodeTestUpToVersion(
      13,
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x02, 0x75, 0x38, 0x3F,
       0x01, 0x3F, 0x01, 0x42, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x56, 0x42, 0x00, 0x20, 0x00, 0x3F, 0x03, 0x53, 0x04, 0x75, 0x38,
       0x5F, 0x32, 0x3F, 0x03, 0x5E, 0x02, 0x3F, 0x03, 0x53, 0x03, 0x66, 0x33,
       0x32, 0x3F, 0x03, 0x3F, 0x03, 0x5E, 0x01, 0x56, 0x66, 0x04, 0x14, 0x00,
       0x3F, 0x04, 0x53, 0x01, 0x62, 0x3F, 0x04, 0x5E, 0x01, 0x7B, 0x04},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.u8 instanceof Uint8Array");
        ExpectScriptTrue("result.u8 === result.u8_2");
        ExpectScriptTrue("result.f32 instanceof Float32Array");
        ExpectScriptTrue("result.u8.buffer === result.f32.buffer");
        ExpectScriptTrue("result.f32.byteOffset === 4");
        ExpectScriptTrue("result.f32.length === 5");
      });
}

TEST_F(ValueSerializerTest, DecodeTypedArrayBrokenData) {
  // Test decoding the broken data where the version is 13 but the
  // JSArrayBufferView flags are present.

  // The data below is produced by the following code + changing the version
  // to 13:
  // std::vector<uint8_t> encoded =
  //     EncodeTest("({ a: new Uint8Array(), b: 13 })");

  Local<Value> value = DecodeTest({0xFF, 0xD,  0x6F, 0x22, 0x1,  0x61, 0x42,
                                   0x0,  0x56, 0x42, 0x0,  0x0,  0xE8, 0x47,
                                   0x22, 0x1,  0x62, 0x49, 0x1A, 0x7B, 0x2});
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("Object.getPrototypeOf(result.a) === Uint8Array.prototype");
  ExpectScriptTrue("result.b === 13");
}

TEST_F(ValueSerializerTest, DecodeInvalidTypedArray) {
  // Byte offset out of range.
  InvalidDecodeTest(
      {0xFF, 0x09, 0x42, 0x02, 0x00, 0x00, 0x56, 0x42, 0x03, 0x01});
  // Byte offset in range, offset + length out of range.
  InvalidDecodeTest(
      {0xFF, 0x09, 0x42, 0x02, 0x00, 0x00, 0x56, 0x42, 0x01, 0x03});
  // Byte offset not divisible by element size.
  InvalidDecodeTest(
      {0xFF, 0x09, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, 0x56, 0x77, 0x01, 0x02});
  // Byte length not divisible by element size.
  InvalidDecodeTest(
      {0xFF, 0x09, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, 0x56, 0x77, 0x02, 0x01});
  // Invalid view type (0xFF).
  InvalidDecodeTest(
      {0xFF, 0x09, 0x42, 0x02, 0x00, 0x00, 0x56, 0xFF, 0x01, 0x01});
}

TEST_F(ValueSerializerTest, RoundTripDataView) {
  Local<Value> value = RoundTripTest("new DataView(new ArrayBuffer(4), 1, 2)");
  ASSERT_TRUE(value->IsDataView());
  EXPECT_EQ(1u, DataView::Cast(*value)->ByteOffset());
  EXPECT_EQ(2u, DataView::Cast(*value)->ByteLength());
  EXPECT_EQ(4u, DataView::Cast(*value)->Buffer()->ByteLength());
  ExpectScriptTrue("Object.getPrototypeOf(result) === DataView.prototype");
  // TODO(v8:11111): Use API functions for testing is_length_tracking and
  // is_backed_by_rab, once they're exposed
  // via the API.
  i::DirectHandle<i::JSDataViewOrRabGsabDataView> i_dv =
      v8::Utils::OpenDirectHandle(DataView::Cast(*value));
  EXPECT_EQ(false, i_dv->is_length_tracking());
  EXPECT_EQ(false, i_dv->is_backed_by_rab());
}

TEST_F(ValueSerializerTest, DecodeDataView) {
  DecodeTestFutureVersions(
      {0xFF, 0x0E, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00,
       0x56, 0x3F, 0x01, 0x02, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsDataView());
        EXPECT_EQ(1u, DataView::Cast(*value)->ByteOffset());
        EXPECT_EQ(2u, DataView::Cast(*value)->ByteLength());
        EXPECT_EQ(4u, DataView::Cast(*value)->Buffer()->ByteLength());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === DataView.prototype");
      });
}

TEST_F(ValueSerializerTest, RoundTripRabBackedDataView) {
  Local<Value> value = RoundTripTest(
      "new DataView(new ArrayBuffer(4, {maxByteLength: 8}), 1, 2)");
  ASSERT_TRUE(value->IsDataView());
  EXPECT_EQ(1u, DataView::Cast(*value)->ByteOffset());
  EXPECT_EQ(2u, DataView::Cast(*value)->ByteLength());
  EXPECT_EQ(4u, DataView::Cast(*value)->Buffer()->ByteLength());
  ExpectScriptTrue("Object.getPrototypeOf(result) === DataView.prototype");
  // TODO(v8:11111): Use API functions for testing is_length_tracking and
  // is_backed_by_rab, once they're exposed via the API.
  i::DirectHandle<i::JSDataViewOrRabGsabDataView> i_dv =
      v8::Utils::OpenDirectHandle(DataView::Cast(*value));
  EXPECT_EQ(false, i_dv->is_length_tracking());
  EXPECT_EQ(true, i_dv->is_backed_by_rab());
}

TEST_F(ValueSerializerTest, RoundTripRabBackedLengthTrackingDataView) {
  Local<Value> value =
      RoundTripTest("new DataView(new ArrayBuffer(4, {maxByteLength: 8}), 1)");
  ASSERT_TRUE(value->IsDataView());
  EXPECT_EQ(1u, DataView::Cast(*value)->ByteOffset());
  EXPECT_EQ(3u, DataView::Cast(*value)->ByteLength());
  EXPECT_EQ(4u, DataView::Cast(*value)->Buffer()->ByteLength());
  ExpectScriptTrue("Object.getPrototypeOf(result) === DataView.prototype");
  // TODO(v8:11111): Use API functions for testing is_length_tracking and
  // is_backed_by_rab, once they're exposed via the API.
  i::DirectHandle<i::JSDataViewOrRabGsabDataView> i_dv =
      v8::Utils::OpenDirectHandle(DataView::Cast(*value));
  EXPECT_EQ(true, i_dv->is_length_tracking());
  EXPECT_EQ(true, i_dv->is_backed_by_rab());
}

TEST_F(ValueSerializerTest, DecodeDataViewBackwardsCompatibility) {
  DecodeTestUpToVersion(
      13,
      {0xFF, 0x09, 0x3F, 0x00, 0x3F, 0x00, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00,
       0x56, 0x3F, 0x01, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsDataView());
        EXPECT_EQ(1u, DataView::Cast(*value)->ByteOffset());
        EXPECT_EQ(2u, DataView::Cast(*value)->ByteLength());
        EXPECT_EQ(4u, DataView::Cast(*value)->Buffer()->ByteLength());
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === DataView.prototype");
      });
}

TEST_F(ValueSerializerTest, DecodeArrayWithLengthProperty1) {
  InvalidDecodeTest({0xff, 0x0d, 0x41, 0x03, 0x49, 0x02, 0x49, 0x04,
                     0x49, 0x06, 0x22, 0x06, 0x6c, 0x65, 0x6e, 0x67,
                     0x74, 0x68, 0x49, 0x02, 0x24, 0x01, 0x03});
}

TEST_F(ValueSerializerTest, DecodeArrayWithLengthProperty2) {
  InvalidDecodeTest({0xff, 0x0d, 0x41, 0x03, 0x49, 0x02, 0x49, 0x04,
                     0x49, 0x06, 0x22, 0x06, 0x6c, 0x65, 0x6e, 0x67,
                     0x74, 0x68, 0x6f, 0x7b, 0x00, 0x24, 0x01, 0x03});
}

TEST_F(ValueSerializerTest, DecodeInvalidDataView) {
  // Byte offset out of range.
  InvalidDecodeTest(
      {0xFF, 0x09, 0x42, 0x02, 0x00, 0x00, 0x56, 0x3F, 0x03, 0x01});
  // Byte offset in range, offset + length out of range.
  InvalidDecodeTest(
      {0xFF, 0x09, 0x42, 0x02, 0x00, 0x00, 0x56, 0x3F, 0x01, 0x03});
}

class ValueSerializerTestWithSharedArrayBufferClone
    : public ValueSerializerTest {
 protected:
  ValueSerializerTestWithSharedArrayBufferClone()
      : serializer_delegate_(this), deserializer_delegate_(this) {}

  void InitializeData(const std::vector<uint8_t>& data, bool is_wasm_memory) {
    data_ = data;
    {
      Context::Scope scope(serialization_context());
      input_buffer_.Reset(
          isolate(),
          NewSharedArrayBuffer(data_.data(), data_.size(), is_wasm_memory));
    }
    {
      Context::Scope scope(deserialization_context());
      output_buffer_.Reset(
          isolate(),
          NewSharedArrayBuffer(data_.data(), data_.size(), is_wasm_memory));
    }
  }

  Local<SharedArrayBuffer> input_buffer() {
    return input_buffer_.Get(isolate());
  }
  Local<SharedArrayBuffer> output_buffer() {
    return output_buffer_.Get(isolate());
  }

  Local<SharedArrayBuffer> NewSharedArrayBuffer(void* data, size_t byte_length,
                                                bool is_wasm_memory) {
#if V8_ENABLE_WEBASSEMBLY
    if (is_wasm_memory) {
      // TODO(titzer): there is no way to create Wasm memory backing stores
      // through the API, or to create a shared array buffer whose backing
      // store is wasm memory, so use the internal API.
      DCHECK_EQ(0, byte_length % i::wasm::kWasmPageSize);
      auto pages = byte_length / i::wasm::kWasmPageSize;
      auto i_isolate = reinterpret_cast<i::Isolate*>(isolate());
      auto backing_store = i::BackingStore::AllocateWasmMemory(
          i_isolate, pages, pages, i::WasmMemoryFlag::kWasmMemory32,
          i::SharedFlag::kShared);
      memcpy(backing_store->buffer_start(), data, byte_length);
      i::Handle<i::JSArrayBuffer> buffer =
          i_isolate->factory()->NewJSSharedArrayBuffer(
              std::move(backing_store));
      return Utils::ToLocalShared(buffer);
    }
#endif  // V8_ENABLE_WEBASSEMBLY

    CHECK(!is_wasm_memory);
    auto sab = SharedArrayBuffer::New(isolate(), byte_length);
    memcpy(sab->GetBackingStore()->Data(), data, byte_length);
    return sab;
  }

 protected:
// GMock doesn't use the "override" keyword.
#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winconsistent-missing-override"
#endif

  class SerializerDelegate : public ValueSerializer::Delegate {
   public:
    explicit SerializerDelegate(
        ValueSerializerTestWithSharedArrayBufferClone* test)
        : test_(test) {}
    MOCK_METHOD(Maybe<uint32_t>, GetSharedArrayBufferId,
                (Isolate*, Local<SharedArrayBuffer> shared_array_buffer),
                (override));
    void ThrowDataCloneError(Local<String> message) override {
      test_->isolate()->ThrowException(Exception::Error(message));
    }

   private:
    ValueSerializerTestWithSharedArrayBufferClone* test_;
  };

  class DeserializerDelegate : public ValueDeserializer::Delegate {
   public:
    explicit DeserializerDelegate(
        ValueSerializerTestWithSharedArrayBufferClone* test) {}
    MOCK_METHOD(MaybeLocal<SharedArrayBuffer>, GetSharedArrayBufferFromId,
                (Isolate*, uint32_t id), (override));
  };

#if __clang__
#pragma clang diagnostic pop
#endif

  ValueSerializer::Delegate* GetSerializerDelegate() override {
    return &serializer_delegate_;
  }

  ValueDeserializer::Delegate* GetDeserializerDelegate() override {
    return &deserializer_delegate_;
  }

  SerializerDelegate serializer_delegate_;
  DeserializerDelegate deserializer_delegate_;

 private:
  std::vector<uint8_t> data_;
  Global<SharedArrayBuffer> input_buffer_;
  Global<SharedArrayBuffer> output_buffer_;
};

TEST_F(ValueSerializerTestWithSharedArrayBufferClone,
       RoundTripSharedArrayBufferClone) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  InitializeData({0x00, 0x01, 0x80, 0xFF}, false);

  EXPECT_CALL(serializer_delegate_,
              GetSharedArrayBufferId(isolate(), input_buffer()))
      .WillRepeatedly(Return(Just(0U)));
  EXPECT_CALL(deserializer_delegate_, GetSharedArrayBufferFromId(isolate(), 0U))
      .WillRepeatedly(Return(output_buffer()));

  Local<Value> value = RoundTripTest(input_buffer());
  ASSERT_TRUE(value->IsSharedArrayBuffer());
  EXPECT_EQ(output_buffer(), value);
  ExpectScriptTrue("new Uint8Array(result).toString() === '0,1,128,255'");

  Local<Object> object;
  {
    Context::Scope scope(serialization_context());
    object = Object::New(isolate());
    EXPECT_TRUE(object
                    ->CreateDataProperty(serialization_context(),
                                         StringFromUtf8("a"), input_buffer())
                    .FromMaybe(false));
    EXPECT_TRUE(object
                    ->CreateDataProperty(serialization_context(),
                                         StringFromUtf8("b"), input_buffer())
                    .FromMaybe(false));
  }
  value = RoundTripTest(object);
  ExpectScriptTrue("result.a instanceof SharedArrayBuffer");
  ExpectScriptTrue("result.a === result.b");
  ExpectScriptTrue("new Uint8Array(result.a).toString() === '0,1,128,255'");
}

#if V8_ENABLE_WEBASSEMBLY
TEST_F(ValueSerializerTestWithSharedArrayBufferClone,
       RoundTripWebAssemblyMemory) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  std::vector<uint8_t> data = {0x00, 0x01, 0x80, 0xFF};
  data.resize(65536);
  InitializeData(data, true);

  EXPECT_CALL(serializer_delegate_,
              GetSharedArrayBufferId(isolate(), input_buffer()))
      .WillRepeatedly(Return(Just(0U)));
  EXPECT_CALL(deserializer_delegate_, GetSharedArrayBufferFromId(isolate(), 0U))
      .WillRepeatedly(Return(output_buffer()));

  Local<Value> input;
  {
    Context::Scope scope(serialization_context());
    const int32_t kMaxPages = 1;
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
    i::Handle<i::JSArrayBuffer> obj = Utils::OpenHandle(*input_buffer());
    input = Utils::Convert<i::WasmMemoryObject, Value>(i::WasmMemoryObject::New(
        i_isolate, obj, kMaxPages, i::wasm::AddressType::kI32));
  }
  RoundTripTest(input);
  ExpectScriptTrue("result instanceof WebAssembly.Memory");
  ExpectScriptTrue("result.buffer.byteLength === 65536");
  ExpectScriptTrue(
      "new Uint8Array(result.buffer, 0, 4).toString() === '0,1,128,255'");
}

TEST_F(ValueSerializerTestWithSharedArrayBufferClone,
       RoundTripWebAssemblyMemory_WithPreviousReference) {
  // This is a regression test for crbug.com/1421524.
  // It ensures that WasmMemoryObject can deserialize even if its underlying
  // buffer was already encountered, and so will be encoded with an object
  // backreference.
  i::DisableHandleChecksForMockingScope mocking_scope;

  std::vector<uint8_t> data = {0x00, 0x01, 0x80, 0xFF};
  data.resize(65536);
  InitializeData(data, true);

  EXPECT_CALL(serializer_delegate_,
              GetSharedArrayBufferId(isolate(), input_buffer()))
      .WillRepeatedly(Return(Just(0U)));
  EXPECT_CALL(deserializer_delegate_, GetSharedArrayBufferFromId(isolate(), 0U))
      .WillRepeatedly(Return(output_buffer()));

  Local<Value> input;
  {
    Context::Scope scope(serialization_context());
    const int32_t kMaxPages = 1;
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
    i::Handle<i::JSArrayBuffer> buffer = Utils::OpenHandle(*input_buffer());
    i::DirectHandle<i::WasmMemoryObject> wasm_memory = i::WasmMemoryObject::New(
        i_isolate, buffer, kMaxPages, i::wasm::AddressType::kI32);
    i::DirectHandle<i::FixedArray> fixed_array =
        i_isolate->factory()->NewFixedArray(2);
    fixed_array->set(0, *buffer);
    fixed_array->set(1, *wasm_memory);
    input = Utils::ToLocal(i_isolate->factory()->NewJSArrayWithElements(
        fixed_array, i::PACKED_ELEMENTS, 2));
  }
  RoundTripTest(input);
  ExpectScriptTrue("result[0] instanceof SharedArrayBuffer");
  ExpectScriptTrue("result[1] instanceof WebAssembly.Memory");
  ExpectScriptTrue("result[0] === result[1].buffer");
  ExpectScriptTrue("result[0].byteLength === 65536");
  ExpectScriptTrue(
      "new Uint8Array(result[0], 0, 4).toString() === '0,1,128,255'");
}
#endif  // V8_ENABLE_WEBASSEMBLY

TEST_F(ValueSerializerTest, UnsupportedHostObject) {
  InvalidEncodeTest("new ExampleHostObject()");
  InvalidEncodeTest("({ a: new ExampleHostObject() })");
}

class ValueSerializerTestWithHostObject : public ValueSerializerTest {
 protected:
  ValueSerializerTestWithHostObject() : serializer_delegate_(this) {
    ON_CALL(serializer_delegate_, HasCustomHostObject)
        .WillByDefault([this](Isolate* isolate) {
          return serializer_delegate_
              .ValueSerializer::Delegate::HasCustomHostObject(isolate);
        });
    ON_CALL(serializer_delegate_, IsHostObject)
        .WillByDefault([this](Isolate* isolate, Local<Object> object) {
          return serializer_delegate_.ValueSerializer::Delegate::IsHostObject(
              isolate, object);
        });
  }

  static const uint8_t kExampleHostObjectTag;

  void WriteExampleHostObjectTag() {
    serializer_->WriteRawBytes(&kExampleHostObjectTag, 1);
  }

  bool ReadExampleHostObjectTag() {
    const void* tag;
    return deserializer_->ReadRawBytes(1, &tag) &&
           *reinterpret_cast<const uint8_t*>(tag) == kExampleHostObjectTag;
  }

// GMock doesn't use the "override" keyword.
#if __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winconsistent-missing-override"
#endif

  class SerializerDelegate : public ValueSerializer::Delegate {
   public:
    explicit SerializerDelegate(ValueSerializerTestWithHostObject* test)
        : test_(test) {}
    MOCK_METHOD(bool, HasCustomHostObject, (Isolate*), (override));
    MOCK_METHOD(Maybe<bool>, IsHostObject, (Isolate*, Local<Object> object),
                (override));
    MOCK_METHOD(Maybe<bool>, WriteHostObject, (Isolate*, Local<Object> object),
                (override));
    void ThrowDataCloneError(Local<String> message) override {
      test_->isolate()->ThrowException(Exception::Error(message));
    }

   private:
    ValueSerializerTestWithHostObject* test_;
  };

  class DeserializerDelegate : public ValueDeserializer::Delegate {
   public:
    MOCK_METHOD(MaybeLocal<Object>, ReadHostObject, (Isolate*), (override));
  };

#if __clang__
#pragma clang diagnostic pop
#endif

  ValueSerializer::Delegate* GetSerializerDelegate() override {
    return &serializer_delegate_;
  }
  void BeforeEncode(ValueSerializer* serializer) override {
    serializer_ = serializer;
  }
  ValueDeserializer::Delegate* GetDeserializerDelegate() override {
    return &deserializer_delegate_;
  }
  void BeforeDecode(ValueDeserializer* deserializer) override {
    deserializer_ = deserializer;
  }

  SerializerDelegate serializer_delegate_;
  DeserializerDelegate deserializer_delegate_;
  ValueSerializer* serializer_;
  ValueDeserializer* deserializer_;

  friend class SerializerDelegate;
  friend class DeserializerDelegate;
};

// This is a tag that is used in V8. Using this ensures that we have separate
// tag namespaces.
const uint8_t ValueSerializerTestWithHostObject::kExampleHostObjectTag = 'T';

TEST_F(ValueSerializerTestWithHostObject, RoundTripUint32) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  // The host can serialize data as uint32_t.
  EXPECT_CALL(serializer_delegate_, WriteHostObject(isolate(), _))
      .WillRepeatedly(Invoke([this](Isolate*, Local<Object> object) {
        uint32_t value = 0;
        EXPECT_TRUE(object->GetInternalField(0)
                        .As<v8::Value>()
                        ->Uint32Value(serialization_context())
                        .To(&value));
        WriteExampleHostObjectTag();
        serializer_->WriteUint32(value);
        return Just(true);
      }));
  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillRepeatedly(Invoke([this](Isolate*) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        uint32_t value = 0;
        EXPECT_TRUE(deserializer_->ReadUint32(&value));
        Local<Value> argv[] = {Integer::NewFromUnsigned(isolate(), value)};
        return NewHostObject(deserialization_context(), arraysize(argv), argv);
      }));
  Local<Value> value = RoundTripTest("new ExampleHostObject(42)");
  ASSERT_TRUE(value->IsObject());
  ASSERT_TRUE(Object::Cast(*value)->InternalFieldCount());
  ExpectScriptTrue(
      "Object.getPrototypeOf(result) === ExampleHostObject.prototype");
  ExpectScriptTrue("result.value === 42");

  value = RoundTripTest("new ExampleHostObject(0xCAFECAFE)");
  ExpectScriptTrue("result.value === 0xCAFECAFE");
}

TEST_F(ValueSerializerTestWithHostObject, RoundTripUint64) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  // The host can serialize data as uint64_t.
  EXPECT_CALL(serializer_delegate_, WriteHostObject(isolate(), _))
      .WillRepeatedly(Invoke([this](Isolate*, Local<Object> object) {
        uint32_t value = 0, value2 = 0;
        EXPECT_TRUE(object->GetInternalField(0)
                        .As<v8::Value>()
                        ->Uint32Value(serialization_context())
                        .To(&value));
        EXPECT_TRUE(object->GetInternalField(1)
                        .As<v8::Value>()
                        ->Uint32Value(serialization_context())
                        .To(&value2));
        WriteExampleHostObjectTag();
        serializer_->WriteUint64((static_cast<uint64_t>(value) << 32) | value2);
        return Just(true);
      }));
  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillRepeatedly(Invoke([this](Isolate*) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        uint64_t value_packed;
        EXPECT_TRUE(deserializer_->ReadUint64(&value_packed));
        Local<Value> argv[] = {
            Integer::NewFromUnsigned(isolate(),
                                     static_cast<uint32_t>(value_packed >> 32)),
            Integer::NewFromUnsigned(isolate(),
                                     static_cast<uint32_t>(value_packed))};
        return NewHostObject(deserialization_context(), arraysize(argv), argv);
      }));
  Local<Value> value = RoundTripTest("new ExampleHostObject(42, 0)");
  ASSERT_TRUE(value->IsObject());
  ASSERT_TRUE(Object::Cast(*value)->InternalFieldCount());
  ExpectScriptTrue(
      "Object.getPrototypeOf(result) === ExampleHostObject.prototype");
  ExpectScriptTrue("result.value === 42");
  ExpectScriptTrue("result.value2 === 0");

  value = RoundTripTest("new ExampleHostObject(0xFFFFFFFF, 0x12345678)");
  ExpectScriptTrue("result.value === 0xFFFFFFFF");
  ExpectScriptTrue("result.value2 === 0x12345678");
}

TEST_F(ValueSerializerTestWithHostObject, RoundTripDouble) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  // The host can serialize data as double.
  EXPECT_CALL(serializer_delegate_, WriteHostObject(isolate(), _))
      .WillRepeatedly(Invoke([this](Isolate*, Local<Object> object) {
        double value = 0;
        EXPECT_TRUE(object->GetInternalField(0)
                        .As<v8::Value>()
                        ->NumberValue(serialization_context())
                        .To(&value));
        WriteExampleHostObjectTag();
        serializer_->WriteDouble(value);
        return Just(true);
      }));
  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillRepeatedly(Invoke([this](Isolate*) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        double value = 0;
        EXPECT_TRUE(deserializer_->ReadDouble(&value));
        Local<Value> argv[] = {Number::New(isolate(), value)};
        return NewHostObject(deserialization_context(), arraysize(argv), argv);
      }));
  Local<Value> value = RoundTripTest("new ExampleHostObject(-3.5)");
  ASSERT_TRUE(value->IsObject());
  ASSERT_TRUE(Object::Cast(*value)->InternalFieldCount());
  ExpectScriptTrue(
      "Object.getPrototypeOf(result) === ExampleHostObject.prototype");
  ExpectScriptTrue("result.value === -3.5");

  value = RoundTripTest("new ExampleHostObject(NaN)");
  ExpectScriptTrue("Number.isNaN(result.value)");

  value = RoundTripTest("new ExampleHostObject(Infinity)");
  ExpectScriptTrue("result.value === Infinity");

  value = RoundTripTest("new ExampleHostObject(-0)");
  ExpectScriptTrue("1/result.value === -Infinity");
}

TEST_F(ValueSerializerTestWithHostObject, RoundTripRawBytes) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  // The host can serialize arbitrary raw bytes.
  const struct {
    uint64_t u64;
    uint32_t u32;
    char str[12];
  } sample_data = {0x1234567812345678, 0x87654321, "Hello world"};
  EXPECT_CALL(serializer_delegate_, WriteHostObject(isolate(), _))
      .WillRepeatedly(
          Invoke([this, &sample_data](Isolate*, Local<Object> object) {
            WriteExampleHostObjectTag();
            serializer_->WriteRawBytes(&sample_data, sizeof(sample_data));
            return Just(true);
          }));
  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillRepeatedly(Invoke([this, &sample_data](Isolate*) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        const void* copied_data = nullptr;
        EXPECT_TRUE(
            deserializer_->ReadRawBytes(sizeof(sample_data), &copied_data));
        if (copied_data) {
          EXPECT_EQ(0, memcmp(&sample_data, copied_data, sizeof(sample_data)));
        }
        return NewHostObject(deserialization_context(), 0, nullptr);
      }));
  Local<Value> value = RoundTripTest("new ExampleHostObject()");
  ASSERT_TRUE(value->IsObject());
  ASSERT_TRUE(Object::Cast(*value)->InternalFieldCount());
  ExpectScriptTrue(
      "Object.getPrototypeOf(result) === ExampleHostObject.prototype");
}

TEST_F(ValueSerializerTestWithHostObject, RoundTripSameObject) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  // If the same object exists in two places, the delegate should be invoked
  // only once, and the objects should be the same (by reference equality) on
  // the other side.
  EXPECT_CALL(serializer_delegate_, WriteHostObject(isolate(), _))
      .WillOnce(Invoke([this](Isolate*, Local<Object> object) {
        WriteExampleHostObjectTag();
        return Just(true);
      }));
  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillOnce(Invoke([this](Isolate*) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        return NewHostObject(deserialization_context(), 0, nullptr);
      }));
  RoundTripTest("({ a: new ExampleHostObject(), get b() { return this.a; }})");
  ExpectScriptTrue("result.a instanceof ExampleHostObject");
  ExpectScriptTrue("result.a === result.b");
}

TEST_F(ValueSerializerTestWithHostObject, DecodeSimpleHostObject) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillRepeatedly(Invoke([this](Isolate*) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        return NewHostObject(deserialization_context(), 0, nullptr);
      }));
  DecodeTestFutureVersions(
      {0xFF, 0x0D, 0x5C, kExampleHostObjectTag}, [this](Local<Value> value) {
        ExpectScriptTrue(
            "Object.getPrototypeOf(result) === ExampleHostObject.prototype");
      });
}

TEST_F(ValueSerializerTestWithHostObject,
       RoundTripHostJSObjectWithoutCustomHostObject) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  EXPECT_CALL(serializer_delegate_, HasCustomHostObject(isolate()))
      .WillOnce(Invoke([](Isolate* isolate) { return false; }));
  RoundTripTest("({ a: { my_host_object: true }, get b() { return this.a; }})");
}

TEST_F(ValueSerializerTestWithHostObject, RoundTripHostJSObject) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  EXPECT_CALL(serializer_delegate_, HasCustomHostObject(isolate()))
      .WillOnce(Invoke([](Isolate* isolate) { return true; }));
  EXPECT_CALL(serializer_delegate_, IsHostObject(isolate(), _))
      .WillRepeatedly(Invoke([this](Isolate* isolate, Local<Object> object) {
        EXPECT_TRUE(object->IsObject());
        Local<Context> context = isolate->GetCurrentContext();
        return object->Has(context, StringFromUtf8("my_host_object"));
      }));
  EXPECT_CALL(serializer_delegate_, WriteHostObject(isolate(), _))
      .WillOnce(Invoke([this](Isolate*, Local<Object> object) {
        EXPECT_TRUE(object->IsObject());
        WriteExampleHostObjectTag();
        return Just(true);
      }));
  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillOnce(Invoke([this](Isolate* isolate) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        Local<Context> context = isolate->GetCurrentContext();
        Local<Object> obj = Object::New(isolate);
        obj->Set(context, StringFromUtf8("my_host_object"), v8::True(isolate))
            .Check();
        return obj;
      }));
  RoundTripTest("({ a: { my_host_object: true }, get b() { return this.a; }})");
  ExpectScriptTrue("!('my_host_object' in result)");
  ExpectScriptTrue("result.a.my_host_object");
  ExpectScriptTrue("result.a === result.b");
}

class ValueSerializerTestWithHostArrayBufferView
    : public ValueSerializerTestWithHostObject {
 protected:
  void BeforeEncode(ValueSerializer* serializer) override {
    ValueSerializerTestWithHostObject::BeforeEncode(serializer);
    serializer_->SetTreatArrayBufferViewsAsHostObjects(true);
  }
};

TEST_F(ValueSerializerTestWithHostArrayBufferView, RoundTripUint8ArrayInput) {
  i::DisableHandleChecksForMockingScope mocking_scope;

  EXPECT_CALL(serializer_delegate_, WriteHostObject(isolate(), _))
      .WillOnce(Invoke([this](Isolate*, Local<Object> object) {
        EXPECT_TRUE(object->IsUint8Array());
        WriteExampleHostObjectTag();
        return Just(true);
      }));
  EXPECT_CALL(deserializer_delegate_, ReadHostObject(isolate()))
      .WillOnce(Invoke([this](Isolate*) {
        EXPECT_TRUE(ReadExampleHostObjectTag());
        return NewDummyUint8Array();
      }));
  RoundTripTest(
      "({ a: new Uint8Array([1, 2, 3]), get b() { return this.a; }})");
  ExpectScriptTrue("result.a instanceof Uint8Array");
  ExpectScriptTrue("result.a.toString() === '4,5,6'");
  ExpectScriptTrue("result.a === result.b");
}

#if V8_ENABLE_WEBASSEMBLY
// It's expected that WebAssembly has more exhaustive tests elsewhere; this
// mostly checks that the logic to embed it in structured clone serialization
// works correctly.

// A simple module which exports an "increment" function.
// Copied from test/mjsunit/wasm/incrementer.wasm.
constexpr uint8_t kIncrementerWasm[] = {
    0,   97, 115, 109, 1, 0,  0, 0, 1,   6,   1,  96,  1,   127, 1,   127,
    3,   2,  1,   0,   7, 13, 1, 9, 105, 110, 99, 114, 101, 109, 101, 110,
    116, 0,  0,   10,  9, 1,  7, 0, 32,  0,   65, 1,   106, 11,
};

class ValueSerializerTestWithWasm : public ValueSerializerTest {
 public:
  static const char* kUnsupportedSerialization;

  ValueSerializerTestWithWasm()
      : serialize_delegate_(&transfer_modules_),
        deserialize_delegate_(&transfer_modules_) {}

  void Reset() {
    current_serializer_delegate_ = nullptr;
    transfer_modules_.clear();
  }

  void EnableTransferSerialization() {
    current_serializer_delegate_ = &serialize_delegate_;
  }

  void EnableTransferDeserialization() {
    current_deserializer_delegate_ = &deserialize_delegate_;
  }

  void EnableThrowingSerializer() {
    current_serializer_delegate_ = &throwing_serializer_;
  }

  void EnableDefaultDeserializer() {
    current_deserializer_delegate_ = &default_deserializer_;
  }

 protected:
  static void SetUpTestSuite() {
    ValueSerializerTest::SetUpTestSuite();
  }

  static void TearDownTestSuite() {
    ValueSerializerTest::TearDownTestSuite();
  }

  class ThrowingSerializer : public ValueSerializer::Delegate {
   public:
    Maybe<uint32_t> GetWasmModuleTransferId(
        Isolate* isolate, Local<WasmModuleObject> module) override {
      isolate->ThrowException(Exception::Error(
          String::NewFromOneByte(isolate, reinterpret_cast<const uint8_t*>(
                                              kUnsupportedSerialization))
              .ToLocalChecked()));
      return Nothing<uint32_t>();
    }

    void ThrowDataCloneError(Local<String> message) override { UNREACHABLE(); }
  };

  class SerializeToTransfer : public ValueSerializer::Delegate {
   public:
    explicit SerializeToTransfer(std::vector<CompiledWasmModule>* modules)
        : modules_(modules) {}
    Maybe<uint32_t> GetWasmModuleTransferId(
        Isolate* isolate, Local<WasmModuleObject> module) override {
      modules_->push_back(module->GetCompiledModule());
      return Just(static_cast<uint32_t>(modules_->size()) - 1);
    }

    void ThrowDataCloneError(Local<String> message) override { UNREACHABLE(); }

   private:
    std::vector<CompiledWasmModule>* modules_;
  };

  class DeserializeFromTransfer : public ValueDeserializer::Delegate {
   public:
    explicit DeserializeFromTransfer(std::vector<CompiledWasmModule>* modules)
        : modules_(modules) {}

    MaybeLocal<WasmModuleObject> GetWasmModuleFromId(Isolate* isolate,
                                                     uint32_t id) override {
      return WasmModuleObject::FromCompiledModule(isolate, modules_->at(id));
    }

   private:
    std::vector<CompiledWasmModule>* modules_;
  };

  ValueSerializer::Delegate* GetSerializerDelegate() override {
    return current_serializer_delegate_;
  }

  ValueDeserializer::Delegate* GetDeserializerDelegate() override {
    return current_deserializer_delegate_;
  }

  Local<WasmModuleObject> MakeWasm() {
    Context::Scope scope(serialization_context());
    i::wasm::ErrorThrower thrower(i_isolate(), "MakeWasm");
    auto enabled_features =
        i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate());
    i::MaybeHandle<i::J
"""

```