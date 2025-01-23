Response: Let's break down the thought process to analyze the C++ code and generate the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and a JavaScript example if it relates to JavaScript. The file path indicates it's a test file (`protocol_core_test.cc`) within the V8 project's inspector protocol. This immediately suggests the code is about testing the core functionality of a protocol implementation, likely related to debugging and inspection of JavaScript within V8.

2. **Initial Scan and Keyword Identification:** Quickly scan the code for important keywords and patterns. Keywords like `TEST`, `ASSERT_THAT`, `EXPECT_THAT`, `Roundtrip`, `Serialize`, `Deserialize`, and class names like `TestTypeBasic`, `TestTypeComposite`, `TestTypeArrays`, `TestTypeOptional`, and `TestTypeLazy` are crucial. The namespace `v8_crdtp` confirms its connection to the Chrome DevTools Protocol (CDP) within V8.

3. **Identify Core Functionality:** The repeated `Roundtrip` function strongly suggests testing serialization and deserialization. The various `TestType...` classes likely represent data structures used in the protocol. The `V8_CRDTP_BEGIN/END_DESERIALIZER/SERIALIZER` macros confirm the serialization/deserialization aspect.

4. **Analyze Individual Test Cases:** Examine the different `TEST` blocks:
    * `Basic`: Tests basic serialization/deserialization of a simple object with a string field.
    * `FailedToDeserializeTestTypeBasic`:  Tests a failure case during deserialization, specifically handling invalid CBOR.
    * `TestBasicDouble`: Tests deserializing a double, including the case where it's encoded as an integer (important for JSON compatibility).
    * `Composite`: Tests serialization/deserialization of a more complex object containing various data types and nested objects.
    * `CompositeParsingTest`: Sets up a fixture to test error handling during deserialization, focusing on:
        * `DecodingFailure_CBORTokenizer`: Invalid CBOR format.
        * `DecodingFailure_MandatoryFieldMissingShallow/Nested`: Missing required fields.
        * `DecodingFailure_BoolValueExpected`: Type mismatch during deserialization.
    * `Arrays`: Tests serialization/deserialization of objects containing arrays of different types.
    * `OptionalAbsent/Present`: Tests serialization/deserialization of optional fields (using `Maybe`).
    * `TestDeferredMessage`: Tests a "lazy" deserialization mechanism (`DeferredMessage`), where part of the message is not immediately deserialized.

5. **Infer the Overall Purpose:** Based on the identified functionalities, the main purpose of the `protocol_core_test.cc` file is to verify the correctness and robustness of the core serialization and deserialization mechanisms used by the V8 inspector protocol. It tests various scenarios, including basic types, composite objects, arrays, optional values, and error handling.

6. **Connect to JavaScript (if applicable):** The V8 inspector protocol is directly used by browser developer tools to inspect and debug JavaScript code running within V8. The data structures being serialized and deserialized in the C++ code correspond to the data exchanged between the browser's JavaScript engine and the developer tools frontend.

7. **Construct the Summary:**  Synthesize the findings into a concise summary, highlighting the key functionalities and the relationship to the V8 inspector protocol. Mention the use of CBOR for serialization and the testing of different data types and error conditions.

8. **Create the JavaScript Example:**  Think about how the C++ test cases relate to JavaScript concepts. The `TestTypeBasic` class with a `value` field directly maps to a simple JavaScript object. The serialization and deserialization process in C++ mimics how data is sent and received in the CDP. Create a JavaScript example that demonstrates the creation of a similar object and conceptually illustrates the idea of sending and receiving this data through the DevTools Protocol. Emphasize the analogous structure between the C++ class and the JavaScript object.

9. **Refine and Review:** Read through the summary and JavaScript example to ensure accuracy, clarity, and conciseness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have just said "tests serialization," but refining it to specify "CBOR serialization and deserialization" adds valuable detail. Similarly, explicitly linking the tested data structures to the data exchanged in the DevTools protocol strengthens the explanation. Ensure the JavaScript example is simple and directly relates to the C++ code's core concepts.

This systematic approach, starting with high-level understanding and gradually diving into details, helps to effectively analyze the C++ code and generate a comprehensive and relevant summary and JavaScript example.
这个C++源代码文件 `protocol_core_test.cc` 的主要功能是**测试 V8 JavaScript 引擎的 Chrome DevTools Protocol (CRDP) 核心功能中的序列化和反序列化机制**。

更具体地说，它做了以下几件事：

1. **定义测试用的数据结构：**  文件中定义了一系列名为 `TestTypeBasic`、`TestTypeBasicDouble`、`TestTypeComposite`、`TestTypeArrays`、`TestTypeOptional` 和 `TestTypeLazy` 的 C++ 类。这些类模拟了在 CRDP 协议中可能出现的各种数据结构，包括基本类型（字符串、数字、布尔值）、复合类型（包含其他对象的对象）、数组和可选字段。这些类的定义中使用了宏 `V8_CRDTP_BEGIN_DESERIALIZER/SERIALIZER` 和 `V8_CRDTP_DESERIALIZE_FIELD/SERIALIZE_FIELD`，这表明使用了某种代码生成或宏机制来辅助实现序列化和反序列化。

2. **实现序列化和反序列化逻辑：**  每个测试类都通过宏定义了如何将其成员变量序列化成字节流以及如何从字节流反序列化回对象。这通常涉及到将 C++ 的数据类型转换为 CRDP 协议使用的传输格式（通常是 CBOR，Canonical CBOR）。

3. **编写单元测试：** 文件中包含了多个 `TEST` 宏定义的单元测试用例，例如 `ProtocolCoreTest.Basic`、`ProtocolCoreTest.Composite`、`ProtocolCoreTest.Arrays` 等。这些测试用例覆盖了不同的序列化和反序列化场景：
    * **正常情况下的序列化和反序列化：** 例如 `Roundtrip` 函数会将一个对象序列化成字节流，然后再从字节流反序列化回一个新的对象，并验证两个对象的内容是否一致。
    * **错误处理：** 例如 `FailedToDeserializeTestTypeBasic` 测试了当输入的字节流不是有效的 CRDP 格式时，反序列化过程是否能够正确地返回错误状态。 `CompositeParsingTest` 类及其子测试则更深入地测试了各种反序列化失败的情况，比如 CBOR 格式错误、缺少必需的字段、类型不匹配等。
    * **特殊类型处理：**  例如 `TestBasicDouble` 测试了 `double` 类型的数据，以及允许将整数编码为 `double` 的情况，这可能是为了兼容 JSON 的序列化方式。
    * **数组和可选字段的处理：** 测试了包含数组和可选字段的对象的序列化和反序列化。
    * **延迟反序列化：** `TestTypeLazy` 和 `TestDeferredMessage` 测试了延迟反序列化的机制，允许在需要的时候再反序列化消息的一部分。

4. **使用 Google Test 框架：**  代码使用了 Google Test 框架 (`testing::Eq`, `testing::IsNull`, `StatusIs`) 来编写断言和验证测试结果。

**与 JavaScript 的关系：**

这个 C++ 文件测试的代码是 V8 引擎中处理 Chrome DevTools Protocol 的核心部分。CRDP 协议被用于 Chrome 开发者工具与 JavaScript 引擎进行通信，以便进行调试、性能分析等操作。

**在 JavaScript 中，当你使用 Chrome 开发者工具时，你所看到的数据和执行的操作，很多都通过 CRDP 协议与 V8 引擎进行交互。**  `protocol_core_test.cc` 中测试的数据结构，在概念上与 JavaScript 中可以表示的对象和数据类型相对应。

**JavaScript 举例说明：**

假设 `TestTypeBasic` 类在 CRDP 协议中对应一个简单的包含 `value` 属性的对象。

**C++ (来自 `TestTypeBasic`):**

```c++
class TestTypeBasic : public ProtocolObject<TestTypeBasic> {
 public:
  TestTypeBasic() = default;

  const std::string& GetValue() const { return value_; }
  void SetValue(std::string value) { value_ = std::move(value); }

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  std::string value_;
};
```

**当开发者工具想要从 JavaScript 引擎获取一个类似于 `TestTypeBasic` 的对象时，或者向引擎发送一个这样的对象时，在协议层面上可能会进行类似的序列化和反序列化操作。**

**JavaScript 中的概念对应:**

```javascript
// 假设这是在 Chrome 开发者工具前端接收到的一个来自 V8 引擎的数据
const basicObject = {
  value: "foo"
};

// 或者，这是开发者工具前端想要发送给 V8 引擎的数据
const dataToSend = {
  value: "bar"
};
```

**在 CRDP 协议的底层，当 V8 引擎发送 `basicObject` 给开发者工具时，`TestTypeBasic` 类会被实例化，其 `value_` 成员会被设置为 `"foo"`，然后该对象会被序列化成字节流并发送出去。开发者工具接收到字节流后，会将其反序列化成 JavaScript 对象。反之亦然。**

再例如，`TestTypeComposite` 类可能对应于更复杂的 JavaScript 对象：

**C++ (来自 `TestTypeComposite`):**

```c++
class TestTypeComposite : public ProtocolObject<TestTypeComposite> {
 public:
  // ... (各种 Get/Set 方法) ...

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  bool bool_field_ = false;
  int int_field_ = 0;
  double double_field_ = 0.0;
  std::string str_field_;
  std::unique_ptr<TestTypeBasic> test_type1_field_;
};
```

**对应的 JavaScript 概念:**

```javascript
const compositeObject = {
  bool_field: true,
  int_field: 42,
  double_field: 2.718281828,
  str_field: "bar",
  test_type1_field: {
    value: "bazzzz"
  }
};
```

总而言之，`protocol_core_test.cc` 这个文件是 V8 引擎中非常重要的一个测试文件，它确保了用于与开发者工具通信的 CRDP 协议能够正确地序列化和反序列化各种数据结构，从而保证了开发者工具功能的正常运作。

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/protocol_core_test.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "protocol_core.h"

#include <memory>

#include "cbor.h"
#include "maybe.h"
#include "status_test_support.h"
#include "test_platform.h"
#include "test_string_traits.h"

namespace v8_crdtp {

namespace {
using ::testing::Eq;

template <typename TResult, typename TArg>
std::unique_ptr<TResult> RoundtripToType(const TArg& obj) {
  std::vector<uint8_t> bytes;
  obj.AppendSerialized(&bytes);

  StatusOr<std::unique_ptr<TResult>> result =
      TResult::ReadFrom(std::move(bytes));
  return std::move(result).value();
}

template <typename T>
std::unique_ptr<T> Roundtrip(const T& obj) {
  return RoundtripToType<T, T>(obj);
}

// These TestTypeFOO classes below would normally be generated
// by the protocol generator.

class TestTypeBasic : public ProtocolObject<TestTypeBasic> {
 public:
  TestTypeBasic() = default;

  const std::string& GetValue() const { return value_; }
  void SetValue(std::string value) { value_ = std::move(value); }

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  std::string value_;
};

// clang-format off
V8_CRDTP_BEGIN_DESERIALIZER(TestTypeBasic)
  V8_CRDTP_DESERIALIZE_FIELD("value", value_)
V8_CRDTP_END_DESERIALIZER()

V8_CRDTP_BEGIN_SERIALIZER(TestTypeBasic)
  V8_CRDTP_SERIALIZE_FIELD("value", value_);
V8_CRDTP_END_SERIALIZER();
// clang-format on

TEST(ProtocolCoreTest, Basic) {
  TestTypeBasic obj1;
  obj1.SetValue("foo");

  auto obj2 = Roundtrip(obj1);
  ASSERT_THAT(obj2, Not(testing::IsNull()));
  EXPECT_THAT(obj2->GetValue(), Eq("foo"));
}

TEST(ProtocolCoreTest, FailedToDeserializeTestTypeBasic) {
  std::vector<uint8_t> garbage = {'g', 'a', 'r', 'b', 'a', 'g', 'e'};
  StatusOr<std::unique_ptr<TestTypeBasic>> result =
      TestTypeBasic::ReadFrom(std::move(garbage));
  EXPECT_THAT(result.status(), StatusIs(Error::CBOR_INVALID_STRING8, 0));
}

class TestTypeBasicDouble : public ProtocolObject<TestTypeBasicDouble> {
 public:
  TestTypeBasicDouble() = default;

  double GetValue() const { return value_; }
  void SetValue(double value) { value_ = value; }

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  double value_;
};

// clang-format off
V8_CRDTP_BEGIN_DESERIALIZER(TestTypeBasicDouble)
  V8_CRDTP_DESERIALIZE_FIELD("value", value_)
V8_CRDTP_END_DESERIALIZER()

V8_CRDTP_BEGIN_SERIALIZER(TestTypeBasicDouble)
  V8_CRDTP_SERIALIZE_FIELD("value", value_);
V8_CRDTP_END_SERIALIZER();
// clang-format on

TEST(TestBasicDouble, ParserAllowsAllowsDoubleEncodedAsInt) {
  // We allow double's encoded as INT32, because this is what a roundtrip via
  // JSON would produce.
  std::vector<uint8_t> encoded;
  crdtp::cbor::EnvelopeEncoder envelope;
  envelope.EncodeStart(&encoded);
  encoded.push_back(crdtp::cbor::EncodeIndefiniteLengthMapStart());
  crdtp::cbor::EncodeString8(crdtp::SpanFrom("value"), &encoded);
  crdtp::cbor::EncodeInt32(
      42, &encoded);  // It's a double field, but we encode an int.
  encoded.push_back(crdtp::cbor::EncodeStop());
  envelope.EncodeStop(&encoded);
  auto obj = TestTypeBasicDouble::ReadFrom(encoded).value();
  ASSERT_THAT(obj, Not(testing::IsNull()));
  EXPECT_THAT(obj->GetValue(), Eq(42));
}

class TestTypeComposite : public ProtocolObject<TestTypeComposite> {
 public:
  bool GetBoolField() const { return bool_field_; }
  void SetBoolField(bool value) { bool_field_ = value; }

  int GetIntField() const { return int_field_; }
  void SetIntField(int value) { int_field_ = value; }

  double GetDoubleField() const { return double_field_; }
  void SetDoubleField(double value) { double_field_ = value; }

  const std::string& GetStrField() const { return str_field_; }
  void SetStrField(std::string value) { str_field_ = std::move(value); }

  const TestTypeBasic* GetTestTypeBasicField() {
    return test_type1_field_.get();
  }
  void SetTestTypeBasicField(std::unique_ptr<TestTypeBasic> value) {
    test_type1_field_ = std::move(value);
  }

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  bool bool_field_ = false;
  int int_field_ = 0;
  double double_field_ = 0.0;
  std::string str_field_;
  std::unique_ptr<TestTypeBasic> test_type1_field_;
};

// clang-format off
V8_CRDTP_BEGIN_DESERIALIZER(TestTypeComposite)
  V8_CRDTP_DESERIALIZE_FIELD("bool_field", bool_field_),
  V8_CRDTP_DESERIALIZE_FIELD("double_field", double_field_),
  V8_CRDTP_DESERIALIZE_FIELD("int_field", int_field_),
  V8_CRDTP_DESERIALIZE_FIELD("str_field", str_field_),
  V8_CRDTP_DESERIALIZE_FIELD("test_type1_field", test_type1_field_),
V8_CRDTP_END_DESERIALIZER()

V8_CRDTP_BEGIN_SERIALIZER(TestTypeComposite)
  V8_CRDTP_SERIALIZE_FIELD("bool_field", bool_field_),
  V8_CRDTP_SERIALIZE_FIELD("double_field", double_field_),
  V8_CRDTP_SERIALIZE_FIELD("int_field", int_field_),
  V8_CRDTP_SERIALIZE_FIELD("str_field", str_field_),
  V8_CRDTP_SERIALIZE_FIELD("test_type1_field", test_type1_field_),
V8_CRDTP_END_SERIALIZER();
// clang-format on

TEST(ProtocolCoreTest, Composite) {
  TestTypeComposite obj1;
  obj1.SetBoolField(true);
  obj1.SetIntField(42);
  obj1.SetDoubleField(2.718281828);
  obj1.SetStrField("bar");
  auto val1 = std::make_unique<TestTypeBasic>();
  val1->SetValue("bazzzz");
  obj1.SetTestTypeBasicField(std::move(val1));

  auto obj2 = Roundtrip(obj1);
  ASSERT_THAT(obj2, Not(testing::IsNull()));
  EXPECT_THAT(obj2->GetBoolField(), Eq(true));
  EXPECT_THAT(obj2->GetIntField(), Eq(42));
  EXPECT_THAT(obj2->GetDoubleField(), Eq(2.718281828));
  EXPECT_THAT(obj2->GetStrField(), Eq("bar"));
  EXPECT_THAT(obj2->GetTestTypeBasicField()->GetValue(), Eq("bazzzz"));
}

class CompositeParsingTest : public testing::Test {
 public:
  CompositeParsingTest() {
    TestTypeComposite top;
    top.SetIntField(42);
    top.SetBoolField(true);
    top.SetIntField(42);
    top.SetDoubleField(2.718281828);
    top.SetStrField("junk");
    auto child = std::make_unique<TestTypeBasic>();
    child->SetValue("child_value");
    top.SetTestTypeBasicField(std::move(child));

    // Let's establish that |serialized_| is a properly serialized
    // representation of |top|, by checking that it deserializes ok.
    top.AppendSerialized(&serialized_);
    TestTypeComposite::ReadFrom(serialized_).value();
  }

 protected:
  std::vector<uint8_t> serialized_;
};

TEST_F(CompositeParsingTest, DecodingFailure_CBORTokenizer) {
  // Mutates |serialized_| so that it won't parse correctly. In this case,
  // we're changing a string value so that it's invalid, making CBORTokenizer
  // unhappy.
  size_t position =
      std::string(reinterpret_cast<const char*>(serialized_.data()),
                  serialized_.size())
          .find("child_value");
  EXPECT_GT(position, 0ul);
  // We override the byte just before so that it's still a string
  // (3 << 5), but the length is encoded in the bytes that follows.
  // So, we override that with 0xff (255), which exceeds the length
  // of the message and thereby makes the string8 invalid.
  --position;
  serialized_[position] = 3 << 5 |   // major type: STRING
                          25;        // length in encoded in byte that follows.
  serialized_[position + 1] = 0xff;  // length
  auto result = TestTypeComposite::ReadFrom(serialized_);

  EXPECT_THAT(result.status(), StatusIs(Error::CBOR_INVALID_STRING8, position));
}

TEST_F(CompositeParsingTest, DecodingFailure_MandatoryFieldMissingShallow) {
  // We're changing the string key "int_field" to something else ("lnt_field"),
  // so that the mandatory field value won't be found. Unknown fields are
  // ignored for compatibility, so that's why this simple technique works here.
  size_t position =
      std::string(reinterpret_cast<const char*>(serialized_.data()),
                  serialized_.size())
          .find("int_field");
  serialized_[position] = 'l';  // Change 'i' to 'l'.
  // serialized_.size() - 1 is the STOP character for the entire message,
  size_t expected_error_pos = serialized_.size() - 1;
  auto result = TestTypeComposite::ReadFrom(serialized_);
  EXPECT_THAT(result.status(), StatusIs(Error::BINDINGS_MANDATORY_FIELD_MISSING,
                                        expected_error_pos));
}

TEST_F(CompositeParsingTest, DecodingFailure_MandatoryFieldMissingNested) {
  // We're changing the string key "value" to something else ("falue"), so that
  // the mandatory field value in TestTypeBasic in the child won't be found.
  size_t position =
      std::string(reinterpret_cast<const char*>(serialized_.data()),
                  serialized_.size())
          .find("value");
  serialized_[position] = 'f';  // Change 'v' to 'f'.
  // serialized_.size() - 1 is the STOP character for the enclosing message,
  // and serialized_.size() - 2 is the STOP character for TestTypeBasic.
  size_t expected_error_pos = serialized_.size() - 2;
  auto result = TestTypeComposite::ReadFrom(serialized_);
  EXPECT_THAT(result.status(), StatusIs(Error::BINDINGS_MANDATORY_FIELD_MISSING,
                                        expected_error_pos));
}

TEST_F(CompositeParsingTest, DecodingFailure_BoolValueExpected) {
  // We're changing the bool value (true) to null; we do this by looking
  // for bool_field, and searching from there for TRUE; both TRUE and null
  // are just one byte in the serialized buffer, so this swap is convenient.
  std::string serialized_view(reinterpret_cast<const char*>(serialized_.data()),
                              serialized_.size());
  size_t position = serialized_view.find("bool_field");
  for (; position < serialized_.size(); ++position) {
    if (serialized_[position] == crdtp::cbor::EncodeTrue()) {
      serialized_[position] = crdtp::cbor::EncodeNull();
      break;
    }
  }
  auto result = TestTypeComposite::ReadFrom(serialized_);
  EXPECT_THAT(result.status(),
              StatusIs(Error::BINDINGS_BOOL_VALUE_EXPECTED, position));
}

class TestTypeArrays : public ProtocolObject<TestTypeArrays> {
 public:
  const std::vector<int>* GetIntArray() const { return &int_array_; }
  void SetIntArray(std::vector<int> value) { int_array_ = std::move(value); }

  const std::vector<double>* GetDoubleArray() const { return &double_array_; }
  void SetDoubleArray(std::vector<double> value) {
    double_array_ = std::move(value);
  }

  const std::vector<std::string>* GetStrArray() const { return &str_array_; }
  void SetStrArray(std::vector<std::string> value) {
    str_array_ = std::move(value);
  }

  const std::vector<std::unique_ptr<TestTypeBasic>>* GetTestTypeBasicArray()
      const {
    return &test_type_basic_array_;
  }

  void SetTestTypeBasicArray(
      std::vector<std::unique_ptr<TestTypeBasic>> value) {
    test_type_basic_array_ = std::move(value);
  }

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  std::vector<int> int_array_;
  std::vector<double> double_array_;
  std::vector<std::string> str_array_;
  std::vector<std::unique_ptr<TestTypeBasic>> test_type_basic_array_;
};

// clang-format off
V8_CRDTP_BEGIN_DESERIALIZER(TestTypeArrays)
  V8_CRDTP_DESERIALIZE_FIELD("int_array", int_array_),
  V8_CRDTP_DESERIALIZE_FIELD("str_array", str_array_),
  V8_CRDTP_DESERIALIZE_FIELD("test_type_basic_array", test_type_basic_array_),
V8_CRDTP_END_DESERIALIZER()

V8_CRDTP_BEGIN_SERIALIZER(TestTypeArrays)
  V8_CRDTP_SERIALIZE_FIELD("int_array", int_array_),
  V8_CRDTP_SERIALIZE_FIELD("str_array", str_array_),
  V8_CRDTP_SERIALIZE_FIELD("test_type_basic_array", test_type_basic_array_),
V8_CRDTP_END_SERIALIZER();
// clang-format on

TEST_F(CompositeParsingTest, Arrays) {
  TestTypeArrays obj1;
  obj1.SetIntArray(std::vector<int>{1, 3, 5, 7});
  std::vector<std::string> strs;
  strs.emplace_back("foo");
  strs.emplace_back(std::string("bar"));
  obj1.SetStrArray(std::move(strs));
  auto val1 = std::make_unique<TestTypeBasic>();
  val1->SetValue("bazzzz");
  std::vector<std::unique_ptr<TestTypeBasic>> vec1;
  vec1.emplace_back(std::move(val1));
  obj1.SetTestTypeBasicArray(std::move(vec1));

  auto obj2 = Roundtrip(obj1);
  ASSERT_THAT(obj2, Not(testing::IsNull()));
  EXPECT_THAT(*obj2->GetIntArray(), testing::ElementsAre(1, 3, 5, 7));
  EXPECT_THAT(*obj2->GetStrArray(), testing::ElementsAre("foo", "bar"));
  EXPECT_THAT(obj2->GetDoubleArray()->size(), Eq(0ul));
  EXPECT_THAT(obj2->GetTestTypeBasicArray()->size(), Eq(1ul));
  EXPECT_THAT(obj2->GetTestTypeBasicArray()->front()->GetValue(), Eq("bazzzz"));
}

class TestTypeOptional : public ProtocolObject<TestTypeOptional> {
 public:
  TestTypeOptional() = default;

  bool HasIntField() const { return int_field_.has_value(); }
  int GetIntField() const { return int_field_.value(); }
  void SetIntField(int value) { int_field_ = value; }

  bool HasStrField() { return str_field_.has_value(); }
  const std::string& GetStrField() const { return str_field_.value(); }
  void SetStrField(std::string value) { str_field_ = std::move(value); }

  bool HasTestTypeBasicField() { return test_type_basic_field_.has_value(); }
  const TestTypeBasic* GetTestTypeBasicField() const {
    return test_type_basic_field_.has_value() ? &test_type_basic_field_.value()
                                              : nullptr;
  }
  void SetTestTypeBasicField(std::unique_ptr<TestTypeBasic> value) {
    test_type_basic_field_ = std::move(value);
  }

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  Maybe<int> int_field_;
  Maybe<std::string> str_field_;
  Maybe<TestTypeBasic> test_type_basic_field_;
};

// clang-format off
V8_CRDTP_BEGIN_DESERIALIZER(TestTypeOptional)
  V8_CRDTP_DESERIALIZE_FIELD_OPT("int_field", int_field_),
  V8_CRDTP_DESERIALIZE_FIELD_OPT("str_field", str_field_),
  V8_CRDTP_DESERIALIZE_FIELD_OPT("test_type_basic_field", test_type_basic_field_),
V8_CRDTP_END_DESERIALIZER()

V8_CRDTP_BEGIN_SERIALIZER(TestTypeOptional)
  V8_CRDTP_SERIALIZE_FIELD("int_field", int_field_),
  V8_CRDTP_SERIALIZE_FIELD("str_field", str_field_),
  V8_CRDTP_SERIALIZE_FIELD("test_type_basic_field", test_type_basic_field_),
V8_CRDTP_END_SERIALIZER();
// clang-format on

TEST(ProtocolCoreTest, OptionalAbsent) {
  TestTypeOptional obj1;
  auto obj2 = Roundtrip(obj1);
  ASSERT_THAT(obj2, Not(testing::IsNull()));

  EXPECT_THAT(obj2->HasIntField(), Eq(false));
  EXPECT_THAT(obj2->HasStrField(), Eq(false));
  EXPECT_THAT(obj2->HasTestTypeBasicField(), Eq(false));
}

TEST(ProtocolCoreTest, OptionalPresent) {
  TestTypeOptional obj1;
  obj1.SetIntField(42);
  obj1.SetStrField("foo");

  auto val1 = std::make_unique<TestTypeBasic>();
  val1->SetValue("bar");
  obj1.SetTestTypeBasicField(std::move(val1));

  auto obj2 = Roundtrip(obj1);
  ASSERT_THAT(obj2, Not(testing::IsNull()));

  EXPECT_THAT(obj2->HasIntField(), Eq(true));
  EXPECT_THAT(obj2->GetIntField(), Eq(42));
  EXPECT_THAT(obj2->HasStrField(), Eq(true));
  EXPECT_THAT(obj2->GetStrField(), Eq("foo"));
  EXPECT_THAT(obj2->HasTestTypeBasicField(), Eq(true));
  EXPECT_THAT(obj2->GetTestTypeBasicField()->GetValue(), Eq("bar"));
}

class TestTypeLazy : public ProtocolObject<TestTypeLazy> {
 public:
  TestTypeLazy() = default;

  const std::string& GetStrField() const { return str_field_; }
  void SetStrField(std::string value) { str_field_ = std::move(value); }

  const DeferredMessage* deferred_test_type1_field() const {
    return test_type1_field_.get();
  }

 private:
  DECLARE_SERIALIZATION_SUPPORT();

  std::string str_field_;
  std::unique_ptr<DeferredMessage> test_type1_field_;
};

// clang-format off
V8_CRDTP_BEGIN_DESERIALIZER(TestTypeLazy)
  V8_CRDTP_DESERIALIZE_FIELD("str_field", str_field_),
  V8_CRDTP_DESERIALIZE_FIELD_OPT("test_type1_field", test_type1_field_),
V8_CRDTP_END_DESERIALIZER()

V8_CRDTP_BEGIN_SERIALIZER(TestTypeLazy)
  V8_CRDTP_SERIALIZE_FIELD("str_field", str_field_),
  V8_CRDTP_SERIALIZE_FIELD("test_type1_field", test_type1_field_),
V8_CRDTP_END_SERIALIZER();
// clang-format on

TEST(ProtocolCoreTest, TestDeferredMessage) {
  TestTypeComposite obj1;
  obj1.SetStrField("bar");
  auto val1 = std::make_unique<TestTypeBasic>();
  val1->SetValue("bazzzz");
  obj1.SetTestTypeBasicField(std::move(val1));

  auto obj2 = RoundtripToType<TestTypeLazy>(obj1);
  EXPECT_THAT(obj2->GetStrField(), Eq("bar"));

  TestTypeBasic basic_val;
  auto deserializer = obj2->deferred_test_type1_field()->MakeDeserializer();
  EXPECT_THAT(TestTypeBasic::Deserialize(&deserializer, &basic_val), Eq(true));
  EXPECT_THAT(basic_val.GetValue(), Eq("bazzzz"));

  StatusOr<std::unique_ptr<TestTypeBasic>> maybe_parsed =
      TestTypeBasic::ReadFrom(*obj2->deferred_test_type1_field());
  ASSERT_THAT(maybe_parsed.status(), StatusIsOk());
  ASSERT_THAT((*maybe_parsed), Not(testing::IsNull()));
  ASSERT_EQ((*maybe_parsed)->GetValue(), "bazzzz");
}

}  // namespace
}  // namespace v8_crdtp
```