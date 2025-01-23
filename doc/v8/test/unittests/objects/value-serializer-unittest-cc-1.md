Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/unittests/objects/value-serializer-unittest.cc`.

Here's a breakdown of the thought process to analyze the code and fulfill the request:

1. **Identify the Core Functionality:** The file name `value-serializer-unittest.cc` strongly suggests that this code is testing the serialization and deserialization of JavaScript values in V8. The presence of `RoundTripTest`, `DecodeTestFutureVersions`, `InvalidDecodeTest`, `InvalidEncodeTest`, and `DecodeTestForVersion0` further confirms this. These are clearly test helper functions.

2. **Analyze Individual Test Cases:**  Examine each `TEST_F` function to understand what specific aspect of serialization/deserialization is being tested.

    * **`InvalidDecodeObjectWithInvalidKeyType`:**  Tests that objects with non-string/number keys cannot be deserialized.
    * **`RoundTripOnlyOwnEnumerableStringKeys`:** Checks that only own, enumerable string keys are serialized. This involves testing inheritance, enumerability, and symbol keys.
    * **`RoundTripTrickyGetters`:** Focuses on how getters affect the serialization process, specifically when properties are deleted, added, or have their enumerability changed during enumeration. It also tests error handling during encoding.
    * **`RoundTripDictionaryObjectForTransitions`:** Seems to be testing the serialization and deserialization of objects with a specific internal representation (dictionary mode) and how transitions between object layouts are handled.
    * **`DecodeDictionaryObjectVersion0`:** Tests the deserialization of objects in an older serialization format.
    * **`RoundTripArray`:** Tests the serialization and deserialization of various array types, including sparse arrays, arrays with duplicate references, and self-referential arrays.
    * **`DecodeArray`:** Tests the deserialization of different array scenarios.
    * **`DecodeInvalidOverLargeArray`:** Checks how the deserializer handles invalid array sizes.
    * **`RoundTripArrayWithNonEnumerableElement`:**  Verifies that non-enumerable array elements are not serialized.
    * **`RoundTripArrayWithTrickyGetters`:** Similar to `RoundTripTrickyGetters` but specifically for arrays, focusing on how getters affect element serialization, including deletion and length changes.
    * **`DecodeSparseArrayVersion0`:** Tests the deserialization of sparse arrays in an older format.
    * **`RoundTripDenseArrayContainingUndefined`:** Checks how `undefined` values in dense arrays are serialized.
    * **`DecodeDenseArrayContainingUndefinedBackwardCompatibility`:** Tests how older deserializers handle `undefined` in dense arrays.
    * **`DecodeDenseArrayContainingUndefined`:** Tests how newer deserializers handle `undefined` in dense arrays.
    * **`RoundTripDate`:** Tests the serialization and deserialization of `Date` objects, including special values like NaN.
    * **`DecodeDate`:** Tests the deserialization of `Date` objects.
    * **`RoundTripValueObjects`:** Tests the serialization and deserialization of primitive wrapper objects (`Boolean`, `Number`, `String`).
    * **`RejectsOtherValueObjects`:** Verifies that other value wrapper objects (like `Symbol`) are not allowed.
    * **`DecodeValueObjects`:** Tests the deserialization of primitive wrapper objects.
    * **`RoundTripRegExp`:** Tests the serialization and deserialization of `RegExp` objects.
    * **`DecodeRegExp`:** Tests the deserialization of `RegExp` objects.

3. **Identify JavaScript Relevance and Provide Examples:**  For test cases that clearly relate to JavaScript features (like objects, arrays, dates, regular expressions), construct simple JavaScript examples that demonstrate the behavior being tested. This makes the C++ test cases more understandable for someone familiar with JavaScript.

4. **Identify Potential Programming Errors:**  Based on the test cases, pinpoint common programming errors that developers might make, especially concerning serialization and deserialization. Examples include:
    * Assuming non-enumerable properties are serialized.
    * Expecting properties on the prototype chain to be serialized.
    * Not considering the impact of getters during serialization.
    * Mishandling `undefined` values in arrays.

5. **Code Logic Inference (Input/Output):**  For some test cases, especially those involving specific byte sequences in `DecodeTest...`, it's possible to infer the expected input (the byte stream) and output (the deserialized JavaScript value). This requires understanding the serialization format being tested.

6. **Address Specific Instructions:** Ensure all parts of the prompt are addressed:
    * Listing functionalities.
    * Checking for `.tq` extension (in this case, it's `.cc`).
    * Providing JavaScript examples.
    * Giving input/output examples for decoding tests.
    * Listing common programming errors.
    * A final summary.

7. **Synthesize the Summary:** Based on the analysis of individual test cases, provide a concise summary of the overall functionality of the `value-serializer-unittest.cc` file. Emphasize its role in verifying the correctness of the value serialization and deserialization mechanism in V8.

8. **Refine and Organize:** Review the generated information for clarity, accuracy, and organization. Ensure the JavaScript examples are clear and directly related to the test cases. Structure the explanation logically, starting with the general purpose and then diving into specifics.
好的，让我们来分析一下这段代码的功能。

**代码功能归纳:**

这段代码是 `v8/test/unittests/objects/value-serializer-unittest.cc` 文件的一部分，它专注于测试 V8 引擎中 **ValueSerializer** 的反序列化 (解码) 功能，特别是针对 **对象 (Object)** 和 **数组 (Array)** 的反序列化。

**具体功能点:**

1. **反序列化具有特定属性的对象:**
    *   测试反序列化后，对象是否拥有预期的属性名 (包括字符串和大整数索引)，以及对应的属性值是否正确。
    *   测试了对象在反序列化时，自身引用能否正确解析。

2. **反序列化失败的场景:**
    *   测试了当遇到无效的键类型 (例如，需要转换为字符串的对象作为键) 时，反序列化是否会失败。

3. **反序列化对象时属性的筛选:**
    *   验证只有对象自身的、可枚举的字符串键才会被反序列化，原型链上的属性和不可枚举的属性会被忽略。
    *   验证符号类型的键不会被反序列化。

4. **反序列化带有复杂 Getter 的对象:**
    *   测试在反序列化过程中，Getter 的执行对属性序列化的影响。例如，Getter 中删除属性、添加属性、修改属性的枚举性等。
    *   验证当 Getter 抛出异常时，反序列化会失败并抛出相同的异常。

5. **反序列化不同状态的字典对象:**
    *   测试了反序列化不同状态 (例如，经历过属性添加和删除) 的字典模式对象。

6. **反序列化旧版本的字典对象 (版本 0):**
    *   测试了反序列化旧版本序列化格式的对象，包括空对象、带有字符串键、整数键的对象，以及键的顺序是否被保留。
    *   测试了旧版本中同时包含属性和元素的对象反序列化。

7. **反序列化数组:**
    *   测试了反序列化不同类型的数组，包括：
        *   简单数字数组
        *   稀疏数组
        *   包含重复引用的数组
        *   自引用数组
        *   带有额外属性的数组
        *   包含 `undefined` 元素的数组
        *   维护 `hole` 和 `undefined` 元素区别的数组

8. **反序列化指定版本的数组:**
    *   使用 `DecodeTestFutureVersions` 测试了未来版本序列化的数组的反序列化。
    *   使用 `DecodeTestForVersion0` 测试了版本 0 序列化的数组的反序列化。

9. **处理反序列化超大数组的错误:**
    *   测试了当反序列化的数组过大 (超过 V8 堆限制或 SMI 限制) 或数据不完整时，反序列化是否会失败。

10. **反序列化带有不可枚举元素的数组:**
    *   验证了不可枚举的数组元素不会被反序列化。

11. **反序列化带有复杂 Getter 的数组:**
    *   测试了在反序列化数组元素时，Getter 的执行对元素序列化的影响，包括删除元素、修改数组长度等。

12. **反序列化包含 `undefined` 的密集数组:**
    *   测试了如何反序列化包含 `undefined` 值的密集数组，并区分了 `hole` 和 `undefined`。
    *   测试了向后兼容性，即旧版本如何处理密集数组中的 `undefined`。

**关于文件类型和 JavaScript 关联:**

*   `v8/test/unittests/objects/value-serializer-unittest.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，用于编写 V8 的单元测试。
*   这段代码与 JavaScript 的功能密切相关，因为它测试的是 JavaScript 值的序列化和反序列化机制。

**JavaScript 示例:**

以下是一些与代码功能相关的 JavaScript 示例：

*   **反序列化具有特定属性的对象:**

    ```javascript
    let obj = { a: 2, 4294967295: 1, 4294967294: 3, 1: 0 };
    // 将 obj 序列化为二进制数据 (假设 serialize 是序列化函数)
    let serializedData = serialize(obj);
    // 将二进制数据反序列化回对象 (假设 deserialize 是反序列化函数)
    let result = deserialize(serializedData);
    // result 应该和 obj 具有相同的属性和值
    ```

*   **反序列化对象时属性的筛选:**

    ```javascript
    let obj = {};
    Object.defineProperty(obj, 'a', { value: 1, enumerable: false });
    obj.__proto__ = { b: 2 };
    obj[Symbol()] = 3;

    // 序列化和反序列化后，只有 obj 自身的、可枚举的字符串键会被保留
    let serializedData = serialize(obj);
    let result = deserialize(serializedData);
    // result 应该是一个空对象 {}
    ```

*   **反序列化带有复杂 Getter 的对象:**

    ```javascript
    let obj = {
      get a() {
        delete this.b;
        return 1;
      },
      b: 2,
    };

    let serializedData = serialize(obj);
    let result = deserialize(serializedData);
    // result 应该只包含属性 'a'，不包含 'b'
    ```

*   **反序列化数组:**

    ```javascript
    let arr = [1, , 3, undefined]; // 稀疏数组，包含 hole 和 undefined
    let serializedData = serialize(arr);
    let result = deserialize(serializedData);
    // result 应该和 arr 保持相同的结构和元素，包括 hole 和 undefined
    ```

**代码逻辑推理 (假设输入与输出):**

以 `DecodeTestFutureVersions` 中的一个测试用例为例：

```c++
DecodeTestFutureVersions(
    {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x04, 0x73,
     0x65, 0x6C, 0x66, 0x3F, 0x01, 0x5E, 0x00, 0x7B, 0x01, 0x00},
    [this](Local<Value> value) {
      ASSERT_TRUE(value->IsObject());
      ExpectScriptTrue("result === result.self");
    });
```

*   **假设输入 (二进制数据):** `{0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x04, 0x73, 0x65, 0x6C, 0x66, 0x3F, 0x01, 0x5E, 0x00, 0x7B, 0x01, 0x00}`
*   **预期输出 (反序列化的 JavaScript 值):**  一个对象 `{ self: [Circular] }`，其中 `[Circular]` 表示该对象的 `self` 属性指向自身。

**用户常见的编程错误:**

*   **假设所有对象属性都会被序列化:** 用户可能期望原型链上的属性或不可枚举的属性在序列化后仍然存在，但 `ValueSerializer` 默认只序列化对象自身的、可枚举的属性。
    ```javascript
    let parent = { inheritedProp: 1 };
    let child = Object.create(parent);
    child.ownProp = 2;

    // 序列化 child 后，inheritedProp 将不会存在
    let serialized = serialize(child);
    let restoredChild = deserialize(serialized);
    console.log(restoredChild.inheritedProp); // 输出 undefined
    ```

*   **忽略 Getter 的副作用:** 用户可能没有意识到 Getter 在序列化过程中会被调用，并且 Getter 中的逻辑 (例如删除属性) 会影响最终序列化的结果.
    ```javascript
    let obj = {
      get myProp() {
        delete this.otherProp;
        return 'getter value';
      },
      otherProp: 'initial value',
    };

    let serialized = serialize(obj);
    let restoredObj = deserialize(serialized);
    console.log(restoredObj.otherProp); // 输出 undefined，因为 getter 被调用删除了它
    ```

*   **混淆 `hole` 和 `undefined` 在数组中的表示:**  在某些旧的序列化格式中，`undefined` 可能被表示为 `hole`。用户需要理解 `ValueSerializer` 如何处理这两种不同的情况。

**总结这段代码的功能 (第 2 部分):**

这段代码主要测试了 V8 引擎的 `ValueSerializer` 在反序列化 **对象** 和 **数组** 时的各种场景。它涵盖了不同类型的对象属性、Getter 的影响、不同版本的序列化格式、以及各种类型的数组结构。这些测试用例旨在确保 `ValueSerializer` 能够正确地将序列化的数据还原为原始的 JavaScript 值，并能有效地处理各种边界情况和潜在的错误。

### 提示词
```
这是目录为v8/test/unittests/objects/value-serializer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/objects/value-serializer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
[this](Local<Value> value) {
        ExpectScriptTrue(
            "Object.getOwnPropertyNames(result).toString() === "
            "'1,4294967294,a,4294967295'");
        ExpectScriptTrue("result.a === 2");
        ExpectScriptTrue("result[0xFFFFFFFF] === 1");
        ExpectScriptTrue("result[0xFFFFFFFE] === 3");
        ExpectScriptTrue("result[1] === 0");
      });

  // This detects a fairly subtle case: the object itself must be in the map
  // before its properties are deserialized, so that references to it can be
  // resolved.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x04, 0x73,
       0x65, 0x6C, 0x66, 0x3F, 0x01, 0x5E, 0x00, 0x7B, 0x01, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsObject());
        ExpectScriptTrue("result === result.self");
      });
}

TEST_F(ValueSerializerTest, InvalidDecodeObjectWithInvalidKeyType) {
  // Objects which would need conversion to string shouldn't be present as
  // object keys. The serializer would have obtained them from the own property
  // keys list, which should only contain names and indices.
  InvalidDecodeTest(
      {0xFF, 0x09, 0x6F, 0x61, 0x00, 0x40, 0x00, 0x00, 0x7B, 0x01});
}

TEST_F(ValueSerializerTest, RoundTripOnlyOwnEnumerableStringKeys) {
  // Only "own" properties should be serialized, not ones on the prototype.
  Local<Value> value = RoundTripTest("var x = {}; x.__proto__ = {a: 4}; x;");
  ExpectScriptTrue("!('a' in result)");

  // Only enumerable properties should be serialized.
  value = RoundTripTest(
      "var x = {};"
      "Object.defineProperty(x, 'a', {value: 1, enumerable: false});"
      "x;");
  ExpectScriptTrue("!('a' in result)");

  // Symbol keys should not be serialized.
  value = RoundTripTest("({ [Symbol()]: 4 })");
  ExpectScriptTrue("Object.getOwnPropertySymbols(result).length === 0");
}

TEST_F(ValueSerializerTest, RoundTripTrickyGetters) {
  // Keys are enumerated before any setters are called, but if there is no own
  // property when the value is to be read, then it should not be serialized.
  Local<Value> value =
      RoundTripTest("({ get a() { delete this.b; return 1; }, b: 2 })");
  ExpectScriptTrue("!('b' in result)");

  // Keys added after the property enumeration should not be serialized.
  value = RoundTripTest("({ get a() { this.b = 3; }})");
  ExpectScriptTrue("!('b' in result)");

  // But if you remove a key and add it back, that's fine. But it will appear in
  // the original place in enumeration order.
  value =
      RoundTripTest("({ get a() { delete this.b; this.b = 4; }, b: 2, c: 3 })");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).toString() === 'a,b,c'");
  ExpectScriptTrue("result.b === 4");

  // Similarly, it only matters if a property was enumerable when the
  // enumeration happened.
  value = RoundTripTest(
      "({ get a() {"
      "    Object.defineProperty(this, 'b', {value: 2, enumerable: false});"
      "}, b: 1})");
  ExpectScriptTrue("result.b === 2");

  value = RoundTripTest(
      "var x = {"
      "  get a() {"
      "    Object.defineProperty(this, 'b', {value: 2, enumerable: true});"
      "  }"
      "};"
      "Object.defineProperty(x, 'b',"
      "    {value: 1, enumerable: false, configurable: true});"
      "x;");
  ExpectScriptTrue("!('b' in result)");

  // The property also should not be read if it can only be found on the
  // prototype chain (but not as an own property) after enumeration.
  value = RoundTripTest(
      "var x = { get a() { delete this.b; }, b: 1 };"
      "x.__proto__ = { b: 0 };"
      "x;");
  ExpectScriptTrue("!('b' in result)");

  // If an exception is thrown by script, encoding must fail and the exception
  // must be thrown.
  Local<Message> message =
      InvalidEncodeTest("({ get a() { throw new Error('sentinel'); } })");
  ASSERT_FALSE(message.IsEmpty());
  EXPECT_NE(std::string::npos, Utf8Value(message->Get()).find("sentinel"));
}

TEST_F(ValueSerializerTest, RoundTripDictionaryObjectForTransitions) {
  // A case which should run on the fast path, and should reach all of the
  // different cases:
  // 1. no known transition (first time creating this kind of object)
  // 2. expected transitions match to end
  // 3. transition partially matches, but falls back due to new property 'w'
  // 4. transition to 'z' is now a full transition (needs to be looked up)
  // 5. same for 'w'
  // 6. new property after complex transition succeeded
  // 7. new property after complex transition failed (due to new property)
  RoundTripJSON(
      "[{\"x\":1,\"y\":2,\"z\":3}"
      ",{\"x\":4,\"y\":5,\"z\":6}"
      ",{\"x\":5,\"y\":6,\"w\":7}"
      ",{\"x\":6,\"y\":7,\"z\":8}"
      ",{\"x\":0,\"y\":0,\"w\":0}"
      ",{\"x\":3,\"y\":1,\"w\":4,\"z\":1}"
      ",{\"x\":5,\"y\":9,\"k\":2,\"z\":6}]");
  // A simpler case that uses two-byte strings.
  RoundTripJSON(
      "[{\"\xF0\x9F\x91\x8A\":1,\"\xF0\x9F\x91\x8B\":2}"
      ",{\"\xF0\x9F\x91\x8A\":3,\"\xF0\x9F\x91\x8C\":4}"
      ",{\"\xF0\x9F\x91\x8A\":5,\"\xF0\x9F\x91\x9B\":6}]");
}

TEST_F(ValueSerializerTest, DecodeDictionaryObjectVersion0) {
  // Empty object.
  Local<Value> value = DecodeTestForVersion0({0x7B, 0x00});
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("Object.getPrototypeOf(result) === Object.prototype");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 0");

  // String key.
  value =
      DecodeTestForVersion0({0x53, 0x01, 0x61, 0x49, 0x54, 0x7B, 0x01, 0x00});
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("Object.getPrototypeOf(result) === Object.prototype");
  ExpectScriptTrue("result.hasOwnProperty('a')");
  ExpectScriptTrue("result.a === 42");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 1");

  // Integer key (treated as a string, but may be encoded differently).
  value =
      DecodeTestForVersion0({0x49, 0x54, 0x53, 0x01, 0x61, 0x7B, 0x01, 0x00});
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("result.hasOwnProperty('42')");
  ExpectScriptTrue("result[42] === 'a'");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 1");

  // Key order must be preserved.
  value = DecodeTestForVersion0({0x53, 0x01, 0x78, 0x49, 0x02, 0x53, 0x01, 0x79,
                                 0x49, 0x04, 0x53, 0x01, 0x61, 0x49, 0x06, 0x7B,
                                 0x03, 0x00});
  ExpectScriptTrue("Object.getOwnPropertyNames(result).toString() === 'x,y,a'");

  // A property and an element.
  value = DecodeTestForVersion0(
      {0x49, 0x54, 0x53, 0x01, 0x61, 0x53, 0x01, 0x61, 0x49, 0x54, 0x7B, 0x02});
  ExpectScriptTrue("Object.getOwnPropertyNames(result).toString() === '42,a'");
  ExpectScriptTrue("result[42] === 'a'");
  ExpectScriptTrue("result.a === 42");
}

TEST_F(ValueSerializerTest, RoundTripArray) {
  // A simple array of integers.
  Local<Value> value = RoundTripTest("[1, 2, 3, 4, 5]");
  ASSERT_TRUE(value->IsArray());
  EXPECT_EQ(5u, Array::Cast(*value)->Length());
  ExpectScriptTrue("Object.getPrototypeOf(result) === Array.prototype");
  ExpectScriptTrue("result.toString() === '1,2,3,4,5'");

  // A long (sparse) array.
  value = RoundTripTest("var x = new Array(1000); x[500] = 42; x;");
  ASSERT_TRUE(value->IsArray());
  EXPECT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[500] === 42");

  // Duplicate reference.
  value = RoundTripTest("var y = {}; [y, y];");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(2u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[0] === result[1]");

  // Duplicate reference in a sparse array.
  value = RoundTripTest("var x = new Array(1000); x[1] = x[500] = {}; x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("typeof result[1] === 'object'");
  ExpectScriptTrue("result[1] === result[500]");

  // Self reference.
  value = RoundTripTest("var y = []; y[0] = y; y;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[0] === result");

  // Self reference in a sparse array.
  value = RoundTripTest("var y = new Array(1000); y[519] = y; y;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[519] === result");

  // Array with additional properties.
  value = RoundTripTest("var y = [1, 2]; y.foo = 'bar'; y;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(2u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result.toString() === '1,2'");
  ExpectScriptTrue("result.foo === 'bar'");

  // Sparse array with additional properties.
  value = RoundTripTest("var y = new Array(1000); y.foo = 'bar'; y;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result.toString() === ','.repeat(999)");
  ExpectScriptTrue("result.foo === 'bar'");

  // The distinction between holes and undefined elements must be maintained.
  value = RoundTripTest("[,undefined]");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(2u, Array::Cast(*value)->Length());
  ExpectScriptTrue("typeof result[0] === 'undefined'");
  ExpectScriptTrue("typeof result[1] === 'undefined'");
  ExpectScriptTrue("!result.hasOwnProperty(0)");
  ExpectScriptTrue("result.hasOwnProperty(1)");
}

TEST_F(ValueSerializerTest, DecodeArray) {
  // A simple array of integers.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x41, 0x05, 0x3F, 0x01, 0x49, 0x02,
       0x3F, 0x01, 0x49, 0x04, 0x3F, 0x01, 0x49, 0x06, 0x3F, 0x01,
       0x49, 0x08, 0x3F, 0x01, 0x49, 0x0A, 0x24, 0x00, 0x05, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        EXPECT_EQ(5u, Array::Cast(*value)->Length());
        ExpectScriptTrue("Object.getPrototypeOf(result) === Array.prototype");
        ExpectScriptTrue("result.toString() === '1,2,3,4,5'");
      });
  // A long (sparse) array.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x61, 0xE8, 0x07, 0x3F, 0x01, 0x49,
       0xE8, 0x07, 0x3F, 0x01, 0x49, 0x54, 0x40, 0x01, 0xE8, 0x07},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        EXPECT_EQ(1000u, Array::Cast(*value)->Length());
        ExpectScriptTrue("result[500] === 42");
      });

  // Duplicate reference.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x41, 0x02, 0x3F, 0x01, 0x6F, 0x7B, 0x00, 0x3F,
       0x02, 0x5E, 0x01, 0x24, 0x00, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        ASSERT_EQ(2u, Array::Cast(*value)->Length());
        ExpectScriptTrue("result[0] === result[1]");
      });
  // Duplicate reference in a sparse array.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x61, 0xE8, 0x07, 0x3F, 0x01, 0x49,
       0x02, 0x3F, 0x01, 0x6F, 0x7B, 0x00, 0x3F, 0x02, 0x49, 0xE8,
       0x07, 0x3F, 0x02, 0x5E, 0x01, 0x40, 0x02, 0xE8, 0x07, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        ASSERT_EQ(1000u, Array::Cast(*value)->Length());
        ExpectScriptTrue("typeof result[1] === 'object'");
        ExpectScriptTrue("result[1] === result[500]");
      });
  // Self reference.
  DecodeTestFutureVersions({0xFF, 0x09, 0x3F, 0x00, 0x41, 0x01, 0x3F, 0x01,
                            0x5E, 0x00, 0x24, 0x00, 0x01, 0x00},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsArray());
                             ASSERT_EQ(1u, Array::Cast(*value)->Length());
                             ExpectScriptTrue("result[0] === result");
                           });
  // Self reference in a sparse array.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x61, 0xE8, 0x07, 0x3F, 0x01, 0x49,
       0x8E, 0x08, 0x3F, 0x01, 0x5E, 0x00, 0x40, 0x01, 0xE8, 0x07},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        ASSERT_EQ(1000u, Array::Cast(*value)->Length());
        ExpectScriptTrue("result[519] === result");
      });
  // Array with additional properties.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x41, 0x02, 0x3F, 0x01, 0x49, 0x02, 0x3F,
       0x01, 0x49, 0x04, 0x3F, 0x01, 0x53, 0x03, 0x66, 0x6F, 0x6F, 0x3F,
       0x01, 0x53, 0x03, 0x62, 0x61, 0x72, 0x24, 0x01, 0x02, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        ASSERT_EQ(2u, Array::Cast(*value)->Length());
        ExpectScriptTrue("result.toString() === '1,2'");
        ExpectScriptTrue("result.foo === 'bar'");
      });

  // Sparse array with additional properties.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x61, 0xE8, 0x07, 0x3F, 0x01,
       0x53, 0x03, 0x66, 0x6F, 0x6F, 0x3F, 0x01, 0x53, 0x03,
       0x62, 0x61, 0x72, 0x40, 0x01, 0xE8, 0x07, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        ASSERT_EQ(1000u, Array::Cast(*value)->Length());
        ExpectScriptTrue("result.toString() === ','.repeat(999)");
        ExpectScriptTrue("result.foo === 'bar'");
      });

  // The distinction between holes and undefined elements must be maintained.
  // Note that since the previous output from Chrome fails this test, an
  // encoding using the sparse format was constructed instead.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x61, 0x02, 0x49, 0x02, 0x5F, 0x40, 0x01, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsArray());
        ASSERT_EQ(2u, Array::Cast(*value)->Length());
        ExpectScriptTrue("typeof result[0] === 'undefined'");
        ExpectScriptTrue("typeof result[1] === 'undefined'");
        ExpectScriptTrue("!result.hasOwnProperty(0)");
        ExpectScriptTrue("result.hasOwnProperty(1)");
      });
}

TEST_F(ValueSerializerTest, DecodeInvalidOverLargeArray) {
  // So large it couldn't exist in the V8 heap, and its size couldn't fit in a
  // SMI on 32-bit systems (2^30).
  InvalidDecodeTest({0xFF, 0x09, 0x41, 0x80, 0x80, 0x80, 0x80, 0x04});
  // Not so large, but there isn't enough data left in the buffer.
  InvalidDecodeTest({0xFF, 0x09, 0x41, 0x01});
}

TEST_F(ValueSerializerTest, RoundTripArrayWithNonEnumerableElement) {
  // Even though this array looks like [1,5,3], the 5 should be missing from the
  // perspective of structured clone, which only clones properties that were
  // enumerable.
  Local<Value> value = RoundTripTest(
      "var x = [1,2,3];"
      "Object.defineProperty(x, '1', {enumerable:false, value:5});"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(3u, Array::Cast(*value)->Length());
  ExpectScriptTrue("!result.hasOwnProperty('1')");
}

TEST_F(ValueSerializerTest, RoundTripArrayWithTrickyGetters) {
  // If an element is deleted before it is serialized, then it's deleted.
  Local<Value> value =
      RoundTripTest("var x = [{ get a() { delete x[1]; }}, 42]; x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(2u, Array::Cast(*value)->Length());
  ExpectScriptTrue("typeof result[1] === 'undefined'");
  ExpectScriptTrue("!result.hasOwnProperty(1)");

  // Same for sparse arrays.
  value = RoundTripTest(
      "var x = [{ get a() { delete x[1]; }}, 42];"
      "x.length = 1000;"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("typeof result[1] === 'undefined'");
  ExpectScriptTrue("!result.hasOwnProperty(1)");

  // If the length is changed, then the resulting array still has the original
  // length, but elements that were not yet serialized are gone.
  value = RoundTripTest("var x = [1, { get a() { x.length = 0; }}, 3, 4]; x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(4u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[0] === 1");
  ExpectScriptTrue("!result.hasOwnProperty(2)");

  // The same is true if the length is shortened, but there are still items
  // remaining.
  value = RoundTripTest("var x = [1, { get a() { x.length = 3; }}, 3, 4]; x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(4u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[2] === 3");
  ExpectScriptTrue("!result.hasOwnProperty(3)");

  // Same for sparse arrays.
  value = RoundTripTest(
      "var x = [1, { get a() { x.length = 0; }}, 3, 4];"
      "x.length = 1000;"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[0] === 1");
  ExpectScriptTrue("!result.hasOwnProperty(2)");

  value = RoundTripTest(
      "var x = [1, { get a() { x.length = 3; }}, 3, 4];"
      "x.length = 1000;"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[2] === 3");
  ExpectScriptTrue("!result.hasOwnProperty(3)");

  // If a getter makes a property non-enumerable, it should still be enumerated
  // as enumeration happens once before getters are invoked.
  value = RoundTripTest(
      "var x = [{ get a() {"
      "  Object.defineProperty(x, '1', { value: 3, enumerable: false });"
      "}}, 2];"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(2u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[1] === 3");

  // Same for sparse arrays.
  value = RoundTripTest(
      "var x = [{ get a() {"
      "  Object.defineProperty(x, '1', { value: 3, enumerable: false });"
      "}}, 2];"
      "x.length = 1000;"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[1] === 3");

  // Getters on the array itself must also run.
  value = RoundTripTest(
      "var x = [1, 2, 3];"
      "Object.defineProperty(x, '1', { enumerable: true, get: () => 4 });"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(3u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[1] === 4");

  // Same for sparse arrays.
  value = RoundTripTest(
      "var x = [1, 2, 3];"
      "Object.defineProperty(x, '1', { enumerable: true, get: () => 4 });"
      "x.length = 1000;"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result[1] === 4");

  // Even with a getter that deletes things, we don't read from the prototype.
  value = RoundTripTest(
      "var x = [{ get a() { delete x[1]; } }, 2];"
      "x.__proto__ = Object.create(Array.prototype, { 1: { value: 6 } });"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(2u, Array::Cast(*value)->Length());
  ExpectScriptTrue("!(1 in result)");

  // Same for sparse arrays.
  value = RoundTripTest(
      "var x = [{ get a() { delete x[1]; } }, 2];"
      "x.__proto__ = Object.create(Array.prototype, { 1: { value: 6 } });"
      "x.length = 1000;"
      "x;");
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(1000u, Array::Cast(*value)->Length());
  ExpectScriptTrue("!(1 in result)");
}

TEST_F(ValueSerializerTest, DecodeSparseArrayVersion0) {
  // Empty (sparse) array.
  Local<Value> value = DecodeTestForVersion0({0x40, 0x00, 0x00, 0x00});
  ASSERT_TRUE(value->IsArray());
  ASSERT_EQ(0u, Array::Cast(*value)->Length());

  // Sparse array with a mixture of elements and properties.
  value = DecodeTestForVersion0({0x55, 0x00, 0x53, 0x01, 'a',  0x55, 0x02, 0x55,
                                 0x05, 0x53, 0x03, 'f',  'o',  'o',  0x53, 0x03,
                                 'b',  'a',  'r',  0x53, 0x03, 'b',  'a',  'z',
                                 0x49, 0x0B, 0x40, 0x04, 0x03, 0x00});
  ASSERT_TRUE(value->IsArray());
  EXPECT_EQ(3u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result.toString() === 'a,,5'");
  ExpectScriptTrue("!(1 in result)");
  ExpectScriptTrue("result.foo === 'bar'");
  ExpectScriptTrue("result.baz === -6");

  // Sparse array in a sparse array (sanity check of nesting).
  value = DecodeTestForVersion0(
      {0x55, 0x01, 0x55, 0x01, 0x54, 0x40, 0x01, 0x02, 0x40, 0x01, 0x02, 0x00});
  ASSERT_TRUE(value->IsArray());
  EXPECT_EQ(2u, Array::Cast(*value)->Length());
  ExpectScriptTrue("!(0 in result)");
  ExpectScriptTrue("result[1] instanceof Array");
  ExpectScriptTrue("!(0 in result[1])");
  ExpectScriptTrue("result[1][1] === true");
}

TEST_F(ValueSerializerTest, RoundTripDenseArrayContainingUndefined) {
  // In previous serialization versions, this would be interpreted as an absent
  // property.
  Local<Value> value = RoundTripTest("[undefined]");
  ASSERT_TRUE(value->IsArray());
  EXPECT_EQ(1u, Array::Cast(*value)->Length());
  ExpectScriptTrue("result.hasOwnProperty(0)");
  ExpectScriptTrue("result[0] === undefined");
}

TEST_F(ValueSerializerTest,
       DecodeDenseArrayContainingUndefinedBackwardCompatibility) {
  // In previous versions, "undefined" in a dense array signified absence of the
  // element (for compatibility). In new versions, it has a separate encoding.
  DecodeTestUpToVersion(
      10, {0xFF, 0x09, 0x41, 0x01, 0x5F, 0x24, 0x00, 0x01},
      [this](Local<Value> value) { ExpectScriptTrue("!(0 in result)"); });
}

TEST_F(ValueSerializerTest, DecodeDenseArrayContainingUndefined) {
  DecodeTestFutureVersions({0xFF, 0x0B, 0x41, 0x01, 0x5F, 0x24, 0x00, 0x01},
                           [this](Local<Value> value) {
                             ExpectScriptTrue("0 in result");
                             ExpectScriptTrue("result[0] === undefined");
                           });

  DecodeTestFutureVersions(
      {0xFF, 0x0B, 0x41, 0x01, 0x2D, 0x24, 0x00, 0x01},
      [this](Local<Value> value) { ExpectScriptTrue("!(0 in result)"); });
}

TEST_F(ValueSerializerTest, RoundTripDate) {
  Local<Value> value = RoundTripTest("new Date(1e6)");
  ASSERT_TRUE(value->IsDate());
  EXPECT_EQ(1e6, Date::Cast(*value)->ValueOf());
  ExpectScriptTrue("Object.getPrototypeOf(result) === Date.prototype");

  value = RoundTripTest("new Date(Date.UTC(1867, 6, 1))");
  ASSERT_TRUE(value->IsDate());
  ExpectScriptTrue("result.toISOString() === '1867-07-01T00:00:00.000Z'");

  value = RoundTripTest("new Date(NaN)");
  ASSERT_TRUE(value->IsDate());
  EXPECT_TRUE(std::isnan(Date::Cast(*value)->ValueOf()));

  value = RoundTripTest("({ a: new Date(), get b() { return this.a; } })");
  ExpectScriptTrue("result.a instanceof Date");
  ExpectScriptTrue("result.a === result.b");
}

TEST_F(ValueSerializerTest, DecodeDate) {
#if defined(V8_TARGET_LITTLE_ENDIAN)
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x80, 0x84, 0x2E,
       0x41, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsDate());
        EXPECT_EQ(1e6, Date::Cast(*value)->ValueOf());
        ExpectScriptTrue("Object.getPrototypeOf(result) === Date.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x44, 0x00, 0x00, 0x20, 0x45, 0x27, 0x89, 0x87,
       0xC2, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsDate());
        ExpectScriptTrue("result.toISOString() === '1867-07-01T00:00:00.000Z'");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8,
       0x7F, 0x00},
      [](Local<Value> value) {
        ASSERT_TRUE(value->IsDate());
        EXPECT_TRUE(std::isnan(Date::Cast(*value)->ValueOf()));
      });
#else
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x44, 0x41, 0x2E, 0x84, 0x80, 0x00, 0x00, 0x00,
       0x00, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsDate());
        EXPECT_EQ(1e6, Date::Cast(*value)->ValueOf());
        ExpectScriptTrue("Object.getPrototypeOf(result) === Date.prototype");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x44, 0xC2, 0x87, 0x89, 0x27, 0x45, 0x20, 0x00,
       0x00, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsDate());
        ExpectScriptTrue("result.toISOString() === '1867-07-01T00:00:00.000Z'");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x44, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00},
      [](Local<Value> value) {
        ASSERT_TRUE(value->IsDate());
        EXPECT_TRUE(std::isnan(Date::Cast(*value)->ValueOf()));
      });
#endif
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01, 0x61, 0x3F,
       0x01, 0x44, 0x00, 0x20, 0x39, 0x50, 0x37, 0x6A, 0x75, 0x42, 0x3F,
       0x02, 0x53, 0x01, 0x62, 0x3F, 0x02, 0x5E, 0x01, 0x7B, 0x02},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.a instanceof Date");
        ExpectScriptTrue("result.a === result.b");
      });
}

TEST_F(ValueSerializerTest, RoundTripValueObjects) {
  Local<Value> value = RoundTripTest("new Boolean(true)");
  ExpectScriptTrue("Object.getPrototypeOf(result) === Boolean.prototype");
  ExpectScriptTrue("result.valueOf() === true");

  value = RoundTripTest("new Boolean(false)");
  ExpectScriptTrue("Object.getPrototypeOf(result) === Boolean.prototype");
  ExpectScriptTrue("result.valueOf() === false");

  value =
      RoundTripTest("({ a: new Boolean(true), get b() { return this.a; }})");
  ExpectScriptTrue("result.a instanceof Boolean");
  ExpectScriptTrue("result.a === result.b");

  value = RoundTripTest("new Number(-42)");
  ExpectScriptTrue("Object.getPrototypeOf(result) === Number.prototype");
  ExpectScriptTrue("result.valueOf() === -42");

  value = RoundTripTest("new Number(NaN)");
  ExpectScriptTrue("Object.getPrototypeOf(result) === Number.prototype");
  ExpectScriptTrue("Number.isNaN(result.valueOf())");

  value = RoundTripTest("({ a: new Number(6), get b() { return this.a; }})");
  ExpectScriptTrue("result.a instanceof Number");
  ExpectScriptTrue("result.a === result.b");

  value = RoundTripTest("new String('Qu\\xe9bec')");
  ExpectScriptTrue("Object.getPrototypeOf(result) === String.prototype");
  ExpectScriptTrue("result.valueOf() === 'Qu\\xe9bec'");
  ExpectScriptTrue("result.length === 6");

  value = RoundTripTest("new String('\\ud83d\\udc4a')");
  ExpectScriptTrue("Object.getPrototypeOf(result) === String.prototype");
  ExpectScriptTrue("result.valueOf() === '\\ud83d\\udc4a'");
  ExpectScriptTrue("result.length === 2");

  value = RoundTripTest("({ a: new String(), get b() { return this.a; }})");
  ExpectScriptTrue("result.a instanceof String");
  ExpectScriptTrue("result.a === result.b");
}

TEST_F(ValueSerializerTest, RejectsOtherValueObjects) {
  // This is a roundabout way of getting an instance of Symbol.
  InvalidEncodeTest("Object.valueOf.apply(Symbol())");
}

TEST_F(ValueSerializerTest, DecodeValueObjects) {
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x79, 0x00}, [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === Boolean.prototype");
        ExpectScriptTrue("result.valueOf() === true");
      });
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x78, 0x00}, [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === Boolean.prototype");
        ExpectScriptTrue("result.valueOf() === false");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01, 0x61, 0x3F, 0x01,
       0x79, 0x3F, 0x02, 0x53, 0x01, 0x62, 0x3F, 0x02, 0x5E, 0x01, 0x7B, 0x02},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.a instanceof Boolean");
        ExpectScriptTrue("result.a === result.b");
      });

#if defined(V8_TARGET_LITTLE_ENDIAN)
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45,
       0xC0, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === Number.prototype");
        ExpectScriptTrue("result.valueOf() === -42");
      });
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8,
       0x7F, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === Number.prototype");
        ExpectScriptTrue("Number.isNaN(result.valueOf())");
      });
#else
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6E, 0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === Number.prototype");
        ExpectScriptTrue("result.valueOf() === -42");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6E, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === Number.prototype");
        ExpectScriptTrue("Number.isNaN(result.valueOf())");
      });
#endif
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01, 0x61, 0x3F,
       0x01, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x40, 0x3F,
       0x02, 0x53, 0x01, 0x62, 0x3F, 0x02, 0x5E, 0x01, 0x7B, 0x02},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.a instanceof Number");
        ExpectScriptTrue("result.a === result.b");
      });

  DecodeTestUpToVersion(
      11,
      {0xFF, 0x09, 0x3F, 0x00, 0x73, 0x07, 0x51, 0x75, 0xC3, 0xA9, 0x62, 0x65,
       0x63, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === String.prototype");
        ExpectScriptTrue("result.valueOf() === 'Qu\\xe9bec'");
        ExpectScriptTrue("result.length === 6");
      });

  DecodeTestUpToVersion(
      11, {0xFF, 0x09, 0x3F, 0x00, 0x73, 0x04, 0xF0, 0x9F, 0x91, 0x8A},
      [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === String.prototype");
        ExpectScriptTrue("result.valueOf() === '\\ud83d\\udc4a'");
        ExpectScriptTrue("result.length === 2");
      });

  DecodeTestUpToVersion(11,
                        {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01,
                         0x61, 0x3F, 0x01, 0x73, 0x00, 0x3F, 0x02, 0x53, 0x01,
                         0x62, 0x3F, 0x02, 0x5E, 0x01, 0x7B, 0x02, 0x00},
                        [this](Local<Value> value) {
                          ExpectScriptTrue("result.a instanceof String");
                          ExpectScriptTrue("result.a === result.b");
                        });
  // String object containing a Latin-1 string.
  DecodeTestFutureVersions(
      {0xFF, 0x0C, 0x73, 0x22, 0x06, 'Q', 'u', 0xE9, 'b', 'e', 'c'},
      [this](Local<Value> value) {
        ExpectScriptTrue("Object.getPrototypeOf(result) === String.prototype");
        ExpectScriptTrue("result.valueOf() === 'Qu\\xe9bec'");
        ExpectScriptTrue("result.length === 6");
      });
}

TEST_F(ValueSerializerTest, RoundTripRegExp) {
  Local<Value> value = RoundTripTest("/foo/g");
  ASSERT_TRUE(value->IsRegExp());
  ExpectScriptTrue("Object.getPrototypeOf(result) === RegExp.prototype");
  ExpectScriptTrue("result.toString() === '/foo/g'");

  value = RoundTripTest("new RegExp('Qu\\xe9bec', 'i')");
  ASSERT_TRUE(value->IsRegExp());
  ExpectScriptTrue("result.toString() === '/Qu\\xe9bec/i'");

  value = RoundTripTest("new RegExp('\\ud83d\\udc4a', 'ug')");
  ASSERT_TRUE(value->IsRegExp());
  ExpectScriptTrue("result.toString() === '/\\ud83d\\udc4a/gu'");

  value = RoundTripTest("({ a: /foo/gi, get b() { return this.a; }})");
  ExpectScriptTrue("result.a instanceof RegExp");
  ExpectScriptTrue("result.a === result.b");
}

TEST_F(ValueSerializerTest, DecodeRegExp) {
  DecodeTestUpToVersion(
      11, {0xFF, 0x09, 0x3F, 0x00, 0x52, 0x03, 0x66, 0x6F, 0x6F, 0x01},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("Object.getPrototypeOf(result) === RegExp.prototype");
        ExpectScriptTrue("result.toString() === '/foo/g'");
      });
  DecodeTestUpToVersion(
      11,
      {0xFF, 0x09, 0x3F, 0x00, 0x52, 0x07, 0x51, 0x75, 0xC3, 0xA9, 0x62, 0x65,
       0x63, 0x02},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("result.toString() === '/Qu\\xe9bec/i'");
      });
  DecodeTestUpToVersion(
      11,
      {0xFF, 0x09, 0x3F, 0x00, 0x52, 0x04, 0xF0, 0x9F, 0x91, 0x8A, 0x11, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsRegExp());
        ExpectScriptTrue("result.toString() === '/\\ud83d\\udc4a/gu'");
      });

  DecodeTestUpToVersion(
      11, {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01, 0x61,
           0x3F, 0x01, 0x52, 0x03, 0x66, 0x6F, 0x6F, 0x03, 0x3F, 0x02,
           0x53, 0x01, 0x62, 0x3F, 0x02, 0x5E, 0x01, 0x7B, 0x02, 0x00},
      [this](Local<Value> value) {
        ExpectScriptTrue("result.a instanceof RegExp");
        ExpectScriptTrue("result.a === result.b");
      });
  // RegExp containing a Latin-1 string.
  DecodeTestFutureVersions(
      {0xFF, 0x0C, 0x52, 0x22, 0x06, 'Q', 'u', 0xE9, 'b', 'e', 'c', 0x02},
      [this](Local<Value> value) {
```