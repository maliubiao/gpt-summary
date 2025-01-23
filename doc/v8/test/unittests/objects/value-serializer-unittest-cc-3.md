Response:
The user wants a summary of the provided C++ code snippet, which is part of V8's unit tests for the `ValueSerializer`.

Here's a breakdown of how to address each of the user's requests:

1. **List the functionalities:**  This involves reading through the code and identifying the key test cases. Look for the `TEST_F` macros and the assertions within them. The tests seem to cover:
    * Serializing and deserializing typed arrays (Uint8Array, Float32Array).
    * Handling references to the same typed array during serialization.
    * Testing the deserialization of potentially broken typed array data.
    * Testing error handling during typed array deserialization (invalid offsets, lengths, view types).
    * Serializing and deserializing `DataView` objects.
    * Serializing and deserializing `DataView` objects backed by resizable array buffers (RABs).
    * Testing backward compatibility for `DataView` deserialization.
    * Testing invalid array deserialization (specifically with a "length" property).
    * Serializing and deserializing `SharedArrayBuffer` with custom delegates for cloning behavior.
    * Serializing and deserializing `WebAssembly.Memory` objects.
    * Handling unsupported host objects during serialization.
    * Serializing and deserializing custom host objects with custom serialization logic.
    * Serializing and deserializing host objects that are `ArrayBufferView`s.
    * Serializing and deserializing `WebAssembly.Module` objects with a focus on transferring them.

2. **Check for Torque source:**  The prompt explicitly states to check for a `.tq` extension. The filename provided (`value-serializer-unittest.cc`) has a `.cc` extension, so it's not a Torque file.

3. **Relate to JavaScript with examples:**  For each functionality identified in step 1, provide a corresponding JavaScript code snippet that demonstrates the concept being tested.

4. **Provide code logic inference (input/output):** For some tests, especially those dealing with specific byte sequences, it's possible to infer the input data and the expected output based on the assertions. For example, for the typed array tests, the byte sequence represents the serialized form, and the `ExpectScriptTrue` lines define the expected JavaScript object structure.

5. **Illustrate common programming errors:**  The "InvalidDecodeTest" cases directly show examples of common errors that could occur when manually constructing or manipulating serialized data (e.g., incorrect offsets, lengths).

6. **Summarize the functionality (part 4 of 5):** Given that this is part 4, it likely focuses on a specific set of features. Based on the content, this part appears to concentrate on:
    * Typed arrays and their serialization/deserialization.
    * DataView objects and their serialization/deserialization, including RAB-backed views.
    * Handling SharedArrayBuffers and WebAssembly.Memory objects.
    * Support for custom host objects, allowing embedding of native data.

**Mental Sandbox/Pre-computation:**

* **Typed Arrays:**  The byte sequences are crucial. Understanding the `ValueSerializer`'s format for typed arrays is key to linking the byte data to the JavaScript expectations. The references test shows how the serializer handles duplicate objects.
* **DataView:** Similar to TypedArrays, but with explicit offset and length. The RAB tests introduce the concept of resizable buffers.
* **SharedArrayBuffer/Wasm Memory:** These tests highlight the use of delegates to handle cloning and transferring these objects. The `GetSharedArrayBufferId` and `GetWasmModuleTransferId` methods are key here.
* **Host Objects:** The `WriteHostObject` and `ReadHostObject` methods of the delegates are central to understanding how custom native objects are integrated into the serialization process.

**Final Plan of Action:**

1. Iterate through each `TEST_F` block.
2. For each test, determine the primary functionality being tested.
3. If it relates to JavaScript, write a clear and concise JavaScript example.
4. If there's a specific byte sequence involved, explain what it represents and what the expected outcome is.
5. For "InvalidDecodeTest" cases, explicitly mention the programming error being demonstrated.
6. Keep track of the overarching themes of the tests (typed arrays, DataViews, shared buffers, host objects).
7. Synthesize a summary for part 4, focusing on the identified themes.
好的，让我们来分析一下 `v8/test/unittests/objects/value-serializer-unittest.cc` 这个代码片段的功能。

**功能列举:**

1. **Typed Array 的引用解析:** 测试 `ValueSerializer` 能正确处理对同一个 Typed Array 的多次引用，在反序列化时能够恢复成同一个 JavaScript 对象。
2. **Typed Array 的反序列化 (兼容旧版本):** 测试在版本 13 的反序列化过程中，即使存在新的 `JSArrayBufferView` 标志，也能正确处理 Typed Array。
3. **损坏的 Typed Array 数据反序列化:**  测试当 Typed Array 的数据出现错误（例如，版本号不一致）时，反序列化是否会抛出异常或返回错误。
4. **无效的 Typed Array 反序列化:** 测试各种无效的 Typed Array 数据，例如：
    * `byteOffset` 超出范围。
    * `byteOffset + length` 超出范围。
    * `byteOffset` 不是元素大小的倍数。
    * `byteLength` 不是元素大小的倍数。
    * 无效的 view type。
5. **DataView 的序列化和反序列化 (往返测试):** 测试 `ValueSerializer` 能正确地序列化和反序列化 `DataView` 对象，并验证其属性（`byteOffset`, `byteLength`, `buffer` 等）。
6. **DataView 的反序列化:** 测试 `ValueSerializer` 能正确反序列化 `DataView` 对象。
7. **可调整大小的 ArrayBuffer (Resizable ArrayBuffer, RAB) 支持的 DataView 的序列化和反序列化:** 测试 `ValueSerializer` 能正确处理基于 RAB 的 `DataView` 对象。
8. **可调整大小的 ArrayBuffer 支持的长度追踪 DataView 的序列化和反序列化:** 测试 `ValueSerializer` 能正确处理基于 RAB 且具有长度追踪特性的 `DataView` 对象。
9. **DataView 的反序列化 (兼容旧版本):** 测试在版本 13 的反序列化过程中，能够正确处理 `DataView` 对象。
10. **带有 length 属性的数组的反序列化 (无效):** 测试反序列化带有自定义 `length` 属性的数组是否会失败，这可以防止一些潜在的安全问题。
11. **无效的 DataView 反序列化:** 测试各种无效的 `DataView` 数据，例如：
    * `byteOffset` 超出范围。
    * `byteOffset + length` 超出范围。
12. **SharedArrayBuffer 的克隆序列化和反序列化:** 测试 `ValueSerializer` 如何处理 `SharedArrayBuffer` 的克隆，涉及到自定义的序列化和反序列化委托 (delegate)。它验证了对同一个 `SharedArrayBuffer` 的引用在序列化和反序列化后仍然是同一个对象。
13. **WebAssembly.Memory 的序列化和反序列化:** 测试 `ValueSerializer` 如何处理 `WebAssembly.Memory` 对象，包括在存在对同一个 `SharedArrayBuffer` 的先前引用的情况下。
14. **不支持的宿主对象:** 测试当尝试序列化不支持的宿主对象时，`ValueSerializer` 是否会抛出异常。
15. **自定义宿主对象的序列化和反序列化:**  测试 `ValueSerializer` 如何通过自定义的委托 (delegate) 来序列化和反序列化宿主对象 (Host Object)，允许嵌入原生数据。测试了以下数据类型的序列化：
    * `uint32_t`
    * `uint64_t`
    * `double`
    * 原始字节流 (`raw bytes`)
16. **相同自定义宿主对象的序列化和反序列化:** 测试当同一个自定义宿主对象在多个地方被引用时，序列化委托只会被调用一次，并且反序列化后这些引用指向同一个对象。
17. **简单的自定义宿主对象的反序列化:** 测试直接反序列化一个简单的自定义宿主对象。
18. **不带自定义宿主对象的宿主 JS 对象的序列化和反序列化:** 测试当没有自定义宿主对象委托时，如何处理包含普通 JavaScript 对象的结构。
19. **带自定义宿主对象的宿主 JS 对象的序列化和反序列化:** 测试当存在自定义宿主对象委托时，如何处理被识别为宿主对象的 JavaScript 对象。
20. **将 ArrayBufferView 视为宿主对象进行序列化和反序列化:** 测试当配置 `ValueSerializer` 将 `ArrayBufferView` 视为宿主对象时，如何进行序列化和反序列化。
21. **WebAssembly 模块的序列化和反序列化:** 测试 `ValueSerializer` 如何处理 `WebAssembly.Module` 对象的传输和序列化，包括当序列化委托抛出错误的情况。

**是否为 Torque 源代码:**

`v8/test/unittests/objects/value-serializer-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 的功能关系及举例:**

`ValueSerializer` 的主要功能是将 JavaScript 的值序列化成字节流，以便存储或传输，并在需要时反序列化回 JavaScript 值。

* **Typed Array 的引用解析:**

```javascript
const buffer = new Uint8Array([1, 2, 3]).buffer;
const u8_1 = new Uint8Array(buffer);
const u8_2 = new Uint8Array(buffer);

const serialized = structuredClone({ u8_1, u8_2 });
// 反序列化后 serialized.u8_1 === serialized.u8_2 应该为 true
```

* **DataView 的序列化和反序列化:**

```javascript
const buffer = new ArrayBuffer(8);
const dataView = new DataView(buffer, 2, 4);
dataView.setInt32(0, 0x12345678);

const serialized = structuredClone(dataView);
// 反序列化后 serialized instanceof DataView 应该为 true
// serialized.byteOffset 应该为 2
// serialized.byteLength 应该为 4
// new Int32Array(serialized.buffer)[0] 应该为 0x12345678
```

* **SharedArrayBuffer 的克隆序列化和反序列化:**

```javascript
const sab = new SharedArrayBuffer(4);
const view1 = new Uint8Array(sab);
const view2 = new Uint8Array(sab);
view1[0] = 10;

const cloned = structuredClone({ sab1: sab, sab2: sab });
// cloned.sab1 === cloned.sab2 应该为 true
// new Uint8Array(cloned.sab1)[0] 应该为 10
```

* **WebAssembly.Memory 的序列化和反序列化:**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const array = new Uint8Array(memory.buffer);
array[0] = 20;

const cloned = structuredClone(memory);
// cloned instanceof WebAssembly.Memory 应该为 true
// new Uint8Array(cloned.buffer)[0] 应该为 20
```

* **自定义宿主对象 (假设 `ExampleHostObject` 已在 JavaScript 中定义):**

```javascript
class ExampleHostObject {
  constructor(value) {
    this.value = value;
  }
}

const hostObject = new ExampleHostObject(100);
const serialized = structuredClone(hostObject);
// 反序列化后 serialized instanceof ExampleHostObject 应该为 true
// serialized.value 应该为 100
```

**代码逻辑推理 (假设输入与输出):**

以下以 "References to the same typed array should be resolved." 这个测试为例：

**假设输入 (序列化前 JavaScript 对象):**

```javascript
const buffer = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]).buffer;
const u8 = new Uint8Array(buffer);
const f32 = new Float32Array(buffer, 4, 1);
const obj = { u8: u8, f32: f32, u8_2: u8 };
```

**预期输出 (反序列化后 JavaScript 对象的断言):**

* `result.u8 instanceof Uint8Array` 为真 (反序列化后是 Uint8Array)。
* `result.u8 === result.u8_2` 为真 (对同一个 Typed Array 的引用被解析为同一个对象)。
* `result.f32 instanceof Float32Array` 为真 (反序列化后是 Float32Array)。
* `result.u8.buffer === result.f32.buffer` 为真 (它们共享同一个 ArrayBuffer)。
* `result.f32.byteOffset === 4` 为真 (Float32Array 的字节偏移量是 4)。
* `result.f32.length === 1` 为真 (Float32Array 的长度是 1)。

在代码片段中，给出的字节序列 `0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x02, 0x75, 0x38, 0x3F, 0x01, 0x3F, 0x01, 0x42, 0x20, 0x00, ...`  就是序列化后的字节流，它包含了重建上述 JavaScript 对象所需的信息。

**用户常见的编程错误:**

* **手动构建序列化数据时的偏移量和长度错误:**  例如，在 `DecodeInvalidTypedArray` 和 `DecodeInvalidDataView` 测试中，展示了 `byteOffset` 和 `byteLength` 设置不正确的情况。用户如果尝试手动创建或修改序列化后的数据，很容易犯这类错误，导致反序列化失败。

   ```javascript
   // 错误示例：手动构建 Typed Array 的序列化数据，但偏移量错误
   const invalidTypedArrayData = new Uint8Array([0xFF, 0x09, 0x42, 0x02, 0x00, 0x00, 0x56, 0x42, 0x03, 0x01]);
   // 尝试反序列化 invalidTypedArrayData 会失败
   ```

* **假设 `structuredClone` 或类似的机制会处理所有类型的对象:** 用户可能会尝试序列化一些不能被结构化克隆的对象（例如，包含原生资源的对象，除非有自定义的处理逻辑），导致错误。`UnsupportedHostObject` 测试就演示了这种情况。

* **不理解 `SharedArrayBuffer` 的共享特性:**  用户可能认为克隆 `SharedArrayBuffer` 会创建一个新的独立的缓冲区，但实际上克隆的是对同一个共享内存区域的引用。

**第4部分功能归纳:**

这部分代码主要测试了 `ValueSerializer` 在处理以下类型的 JavaScript 对象时的序列化和反序列化能力，以及相关的错误处理：

* **Typed Arrays:**  包括引用解析、兼容性处理和错误数据处理。
* **DataView:** 包括基本序列化、RAB 支持和错误数据处理。
* **SharedArrayBuffer:** 涉及到自定义的克隆逻辑和委托。
* **WebAssembly.Memory:**  作为 `SharedArrayBuffer` 的一种特殊形式进行测试。
* **自定义宿主对象:**  通过委托机制扩展了 `ValueSerializer` 的能力，允许序列化原生数据。

总而言之，这部分单元测试旨在确保 `ValueSerializer` 能够正确、健壮地处理各种与二进制数据相关的 JavaScript 对象，并且能够通过自定义委托来支持更复杂的数据类型。

### 提示词
```
这是目录为v8/test/unittests/objects/value-serializer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/objects/value-serializer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
eferences to the same typed array should be resolved.
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
```