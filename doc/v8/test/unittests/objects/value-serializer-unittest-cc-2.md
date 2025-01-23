Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understanding the Goal:** The request asks for a functional description of the provided C++ code (`value-serializer-unittest.cc`), considering potential Torque implications, JavaScript relevance, code logic, and common programming errors. It also specifies that this is part 3 of a 5-part series, so a summary of the current functionality is needed.

2. **Initial Code Scan - Identifying the Core Theme:** Quickly scanning the code reveals a pattern:  `TEST_F(ValueSerializerTest, ...)` and `DecodeTest...`. This immediately suggests that the code is testing the `ValueSerializer` and related deserialization functionalities in V8. The file name also reinforces this.

3. **Focusing on `ValueSerializerTest`:** The `TEST_F` macro indicates that these are test cases within a test fixture named `ValueSerializerTest`. This fixture likely provides common setup and utility functions for testing serialization and deserialization.

4. **Analyzing Individual Test Cases:**  The names of the test cases are highly descriptive: `DecodeRegExp`, `DecodeLinearRegExp`, `RoundTripMap`, `DecodeMap`, `RoundTripSet`, `DecodeSet`, `RoundTripArrayBuffer`, `DecodeArrayBuffer`, `RoundTripTypedArray`, `DecodeTypedArray`, etc. These names directly tell us what specific data types and scenarios are being tested.

5. **Deciphering `DecodeTest...` and `RoundTripTest`:**
    * `DecodeTest...`: These functions likely take serialized data (a `std::vector<uint8_t>`) and attempt to deserialize it. The lambda expression passed to these functions then asserts properties of the deserialized value using `ASSERT_TRUE` and `ExpectScriptTrue`. `DecodeTestUpToVersion` and `DecodeTestFutureVersions` suggest testing compatibility across different V8 versions. `InvalidDecodeTest` likely checks that invalid serialized data is handled correctly (throws an error or returns an invalid value).
    * `RoundTripTest`: This function appears to perform both serialization and deserialization. It probably takes a JavaScript expression string, evaluates it, serializes the resulting value, deserializes it, and then the lambda performs assertions on the deserialized value. This confirms that the serialization and deserialization processes are reversible.

6. **Identifying Tested Data Types:**  By examining the test case names and the assertions within the lambdas (e.g., `IsRegExp()`, `IsMap()`, `IsSet()`, `IsArrayBuffer()`, `IsUint8Array()`), we can compile a list of the JavaScript data types that the `ValueSerializer` handles:
    * RegExp (including different flag combinations)
    * Map
    * Set
    * ArrayBuffer (including resizable ones)
    * TypedArrays (Uint8Array, Int16Array, Float32Array, etc.)

7. **Connecting to JavaScript:** The `ExpectScriptTrue` function is a clear indicator of the connection to JavaScript. It executes a JavaScript expression in the test environment to verify properties of the deserialized object. This allows us to provide JavaScript examples.

8. **Considering `.tq` files (Torque):** The prompt asks about `.tq` files. The code provided is `.cc`, so it's standard C++. However, the prompt correctly identifies that `.tq` files are related to Torque. We need to mention that *this specific file is not Torque*, but the `ValueSerializer` likely has Torque implementations for the actual serialization/deserialization logic within the V8 engine.

9. **Inferring Logic and Potential Errors:**
    * **RegExp Flags:** The tests for `DecodeRegExp` with different flag combinations (g, i, m, s, u, y, v) highlight the need for careful encoding and decoding of these flags. Invalid flag combinations are also tested, demonstrating the deserializer's error handling. A common error would be incorrectly setting or interpreting these flags.
    * **Map and Set Iteration Order:** The tests for `RoundTripMap` and `RoundTripSet` explicitly check the preservation of insertion order. This is a crucial aspect of these data structures in JavaScript. A common error could be assuming a different order after deserialization.
    * **Circular References:** The tests involving `m.set(m, m)` and `s.add(s)` demonstrate the ability to handle circular references during serialization and deserialization, which is a common requirement. Failing to handle these can lead to infinite loops or stack overflows in a naive implementation.
    * **ArrayBuffer Transfers:** The `ValueSerializerTestWithArrayBufferTransfer` fixture demonstrates a mechanism for efficiently transferring `ArrayBuffer` data, potentially avoiding unnecessary copying. A common error might be failing to correctly transfer or manage these buffers.
    * **Typed Array Handling:** The numerous tests for `TypedArray` variants ensure that the correct type, byte length, and data are preserved. Errors could involve incorrect type reconstruction or misinterpretation of byte offsets and lengths.
    * **Resizable ArrayBuffers:** The tests for `RoundTripResizableArrayBuffer` and `DecodeInvalidResizableArrayBuffer` cover the specific handling of this newer feature. Errors could arise from incorrect encoding or decoding of the `maxByteLength`.
    * **Out-of-Memory (OOM):** The `DecodeArrayBufferOOM` test specifically checks how the deserializer behaves when memory allocation fails. This is a critical robustness consideration.

10. **Structuring the Output:** Organize the findings into logical sections as requested: functionality, Torque relevance, JavaScript examples, code logic/assumptions, common errors, and a summary.

11. **Drafting and Refining:** Write the initial description, then review and refine it for clarity, accuracy, and completeness. Ensure that the JavaScript examples are concise and illustrative. Make sure the assumptions about input/output are clear and directly related to the test cases.

By following these steps, systematically analyzing the code, and considering the different aspects of the request, we arrive at a comprehensive and informative answer.
好的，让我们来分析一下 `v8/test/unittests/objects/value-serializer-unittest.cc` 这个文件的功能。

**文件功能概览**

`v8/test/unittests/objects/value-serializer-unittest.cc` 是 V8 引擎的一个单元测试文件，专门用于测试 `ValueSerializer` 和 `ValueDeserializer` 这两个类的功能。这两个类负责将 JavaScript 值序列化成字节流，以及将字节流反序列化成 JavaScript 值。

**详细功能拆解**

这个文件中的测试用例覆盖了 `ValueSerializer` 和 `ValueDeserializer` 对各种 JavaScript 值的序列化和反序列化能力，包括：

* **基本类型:**  数字、字符串、布尔值、null、undefined。
* **复杂对象:**
    * **正则表达式 (RegExp):**  测试了不同标志 (flags) 的正则表达式的序列化和反序列化，包括 `i` (忽略大小写), `m` (多行模式), `g` (全局匹配), `s` (dotAll 模式), `u` (Unicode 模式), `y` (粘性匹配), `v` (Unicode Sets)。还测试了无效的标志处理。
    * **Map:** 测试了 Map 对象的序列化和反序列化，包括键值对的存储和迭代顺序的保持。还包括了键或值是自身的情况（循环引用）。
    * **Set:** 测试了 Set 对象的序列化和反序列化，包括元素的存储和迭代顺序的保持。还包括了元素是自身的情况。
    * **ArrayBuffer:** 测试了 ArrayBuffer 对象的序列化和反序列化，包括空 ArrayBuffer 和带有数据的 ArrayBuffer。还测试了可调整大小的 ArrayBuffer。
    * **TypedArray (Uint8Array, Int16Array, Float32Array 等):** 测试了各种类型的 TypedArray 对象的序列化和反序列化，包括数据的保存和类型信息的恢复。还测试了共享同一 ArrayBuffer 的多个 TypedArray 的情况。

**关于 .tq 结尾**

如果 `v8/test/unittests/objects/value-serializer-unittest.cc` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。 Torque 是一种用于编写 V8 内部实现的领域特定语言。但是，**当前提供的文件路径和内容显示它是一个 `.cc` 文件，即 C++ 源代码文件。**  虽然测试代码是用 C++ 编写的，但被测试的 `ValueSerializer` 和 `ValueDeserializer` 的 *实现* 内部可能使用了 Torque。

**与 JavaScript 的关系和举例**

`ValueSerializer` 和 `ValueDeserializer` 的主要作用就是让 JavaScript 引擎能够在不同环境或持久化存储之间传递和恢复 JavaScript 值。

**JavaScript 示例：**

```javascript
// 假设我们有一个实现了序列化和反序列化功能的对象，类似 ValueSerializer 和 ValueDeserializer 的作用
const serializer = {
  serialize: (value) => { /* ... 实现序列化逻辑 ... */ },
  deserialize: (serialized) => { /* ... 实现反序列化逻辑 ... */ },
};

// 一些 JavaScript 值
const numberValue = 42;
const stringValue = "hello";
const arrayValue = [1, 2, 3];
const objectValue = { a: 1, b: "test" };
const mapValue = new Map([[1, 'one'], [2, 'two']]);
const regExpValue = /abc/g;

// 序列化
const serializedNumber = serializer.serialize(numberValue);
const serializedMap = serializer.serialize(mapValue);

// 反序列化
const deserializedNumber = serializer.deserialize(serializedNumber);
const deserializedMap = serializer.deserialize(serializedMap);

console.log(deserializedNumber === numberValue); // true
console.log(deserializedMap instanceof Map); // true
console.log(deserializedMap.get(1)); // 'one'
```

**代码逻辑推理、假设输入与输出**

让我们以 `TEST_F(ValueSerializerTest, DecodeRegExp)` 这个测试用例为例：

**假设输入 (反序列化的字节流):**

```
{0xFF, 0x09, 0x3F, 0x00, 0x52, 0x05, 0x51, 0x75, 0x5Cx65, 0x62, 0x65, 0x63, 0x01}
```

**代码逻辑推理:**

这段字节流会被 `ValueDeserializer` 解析。根据 V8 的内部格式，我们可以推断：

* `0xFF, 0x09`:  可能是版本信息或头部。
* `0x3F, 0x00`:  可能表示上下文或一些标志。
* `0x52`:  很可能是一个标识符，指示接下来是一个正则表达式。
* `0x05`:  可能表示正则表达式的模式字符串的长度。
* `0x51, 0x75, 0x5Cx65, 0x62, 0x65, 0x63`:  是模式字符串 "Quebec" 的 UTF-8 编码，其中 `0x5Cx65` 代表字符 `é`。
* `0x01`:  可能表示正则表达式的标志位，这里是 `i` (忽略大小写)。

**预期输出 (反序列化后的 JavaScript 值):**

一个 `RegExp` 对象，等价于 JavaScript 代码 `/Quebec/i`。

**在测试用例中，`ExpectScriptTrue("result.toString() === '/Quebec/i'")`  验证了这个预期输出。**

**用户常见的编程错误**

与 `ValueSerializer` 和 `ValueDeserializer` 使用相关的常见编程错误可能包括：

1. **序列化和反序列化的环境不一致：**  如果在序列化时注册了自定义的序列化器或反序列化器，但在反序列化时没有进行相应的配置，会导致反序列化失败或得到错误的结果。

2. **尝试序列化无法序列化的值：**  某些 JavaScript 值（例如包含循环引用的复杂对象，如果没有特殊处理）可能无法直接序列化。尝试序列化这些值可能会导致错误。

   ```javascript
   const obj = {};
   obj.circular = obj;

   // 尝试直接序列化包含循环引用的对象 (在某些简单的序列化场景下会出错)
   // JSON.stringify(obj); // 会抛出 TypeError: Converting circular structure to JSON
   ```

3. **假设反序列化后的对象与原始对象完全相同：**  虽然 `ValueSerializer` 努力保持值的语义不变，但在某些情况下，反序列化后的对象可能是原始对象的一个新的副本，而不是同一个对象（尤其是在涉及到对象引用时）。

4. **忽略版本兼容性：**  如果序列化和反序列化发生在不同版本的 V8 引擎之间，旧版本可能无法正确反序列化新版本序列化的数据，或者反之亦然。  `DecodeTestUpToVersion` 和 `DecodeTestFutureVersions` 这些测试用例就是在验证版本兼容性。

**第 3 部分功能归纳**

作为第 3 部分，这部分测试用例主要关注 `ValueSerializer` 和 `ValueDeserializer` 对以下 JavaScript 类型的序列化和反序列化功能：

* **更复杂的正则表达式：**  涵盖了更多的正则表达式标志组合，包括较新的 `s`, `u`, `y`, `v` 标志，并测试了无效标志的处理。
* **Map 和 Set 对象：**  验证了 Map 和 Set 对象的序列化和反序列化，特别强调了元素插入顺序的保持，以及处理循环引用的能力。
* **ArrayBuffer 对象：**  测试了 ArrayBuffer 对象的序列化和反序列化，包括可调整大小的 ArrayBuffer。
* **TypedArray 对象：**  涵盖了各种类型的 TypedArray 对象的序列化和反序列化，并测试了共享 ArrayBuffer 的情况。

总的来说，这部分深入测试了 `ValueSerializer` 和 `ValueDeserializer` 处理更复杂数据结构的能力，并开始关注一些 V8 的新特性（例如可调整大小的 ArrayBuffer 和新的正则表达式标志）。这些测试确保了 V8 能够正确地序列化和反序列化这些重要的 JavaScript 数据类型，保证了引擎状态的正确保存和恢复。

### 提示词
```
这是目录为v8/test/unittests/objects/value-serializer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/objects/value-serializer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  // Similarly, multiple r
```