Response:
Let's break down the thought process for analyzing the C++ code and generating the requested information.

1. **Understanding the Goal:** The request asks for an analysis of the provided C++ code (`protocol_core_test.cc`). The key aspects to cover are functionality, relevance to JavaScript, code logic (with examples), and common programming errors. The initial check for `.tq` extension is a minor detail to handle upfront.

2. **Initial Scan and Structure Recognition:**  A quick scan reveals standard C++ test setup (`#include`, `namespace`, `TEST` macros). The core seems to revolve around classes with `Get`/`Set` methods and serialization/deserialization. The presence of `cbor.h` hints at CBOR (Concise Binary Object Representation) being used for serialization. The `V8_CRDTP_BEGIN/END_...` macros are likely part of a custom serialization framework.

3. **Deconstructing the Core Functionality - Test by Test:** The most effective way to understand the functionality is to examine each `TEST` case:

    * **`Basic`:**  Creates a `TestTypeBasic` object, sets a string value, roundtrips it through serialization/deserialization, and verifies the value. This clearly demonstrates basic serialization and deserialization of a simple string.

    * **`FailedToDeserializeTestTypeBasic`:**  Attempts to deserialize garbage data into `TestTypeBasic` and checks if the expected error status (`CBOR_INVALID_STRING8`) is returned. This verifies error handling during deserialization.

    * **`ParserAllowsAllowsDoubleEncodedAsInt`:** Focuses on `TestTypeBasicDouble`. It manually constructs a CBOR payload where a double field is encoded as an integer. It then verifies that the deserializer correctly interprets the integer as a double. This highlights a specific deserialization behavior related to JSON compatibility.

    * **`Composite`:**  Deals with `TestTypeComposite`, a class containing various data types (bool, int, double, string, and a nested `TestTypeBasic`). It performs a roundtrip and verifies all the fields. This shows serialization/deserialization of complex objects.

    * **`CompositeParsingTest` (Fixture and its Tests):** This is crucial for understanding error handling in more detail. The fixture sets up a valid serialized `TestTypeComposite` object. The subsequent tests then intentionally corrupt the serialized data to trigger different types of deserialization errors:
        * **`DecodingFailure_CBORTokenizer`:**  Corrupts a string length encoding, causing a low-level CBOR parsing error.
        * **`DecodingFailure_MandatoryFieldMissingShallow`:** Renames a key in the top-level object, causing a mandatory field check to fail.
        * **`DecodingFailure_MandatoryFieldMissingNested`:** Renames a key in the nested `TestTypeBasic` object, demonstrating error propagation.
        * **`DecodingFailure_BoolValueExpected`:**  Replaces a boolean `true` with `null`, causing a type mismatch error.

    * **`Arrays`:**  Tests `TestTypeArrays`, which contains vectors of different types (int, double, string, and `TestTypeBasic`). It roundtrips the object and verifies the array contents.

    * **`OptionalAbsent` and `OptionalPresent`:** Focuses on `TestTypeOptional`, which uses `Maybe` (likely a variant of `std::optional`) for optional fields. It tests both cases: when optional fields are absent and when they are present.

    * **`TestDeferredMessage`:** Introduces `TestTypeLazy` and `DeferredMessage`. It serializes a `TestTypeComposite` and then deserializes it as a `TestTypeLazy`. The key here is that the nested `TestTypeBasic` is accessed through a `DeferredMessage`, allowing for lazy deserialization. This is relevant for performance when dealing with potentially large nested objects.

4. **Identifying the Core Functionality:** Based on the individual test analysis, the primary function of `protocol_core_test.cc` is to **test the serialization and deserialization logic** implemented in `protocol_core.h` (implied by the `#include`). It uses CBOR as the serialization format and tests various data types, including basic types, nested objects, arrays, and optional fields. It also thoroughly tests error handling during deserialization.

5. **JavaScript Relevance:** The "inspector_protocol" part of the path strongly suggests a connection to the Chrome DevTools Protocol (CDP). CDP is used to remotely debug and inspect web pages and other Chromium-based applications. The serialization and deserialization tested here are likely used to exchange data between the browser (V8) and the DevTools frontend (which is primarily JavaScript).

6. **JavaScript Example:**  To illustrate the JavaScript connection, a simple example showing how JavaScript might receive and interpret a serialized object (similar to `TestTypeBasic`) is necessary. This would involve a JavaScript object with a "value" property and mentioning that the data would likely arrive as a JSON or binary (potentially CBOR) string that needs parsing.

7. **Code Logic and Examples:**  For each test case demonstrating code logic, providing a simplified explanation and a hypothetical input/output is helpful. For instance, in the `Basic` test, the input is a `TestTypeBasic` object with `value = "foo"`, and the output after roundtrip is the same. For error scenarios, the input is the corrupted byte stream, and the output is the specific error status and position.

8. **Common Programming Errors:**  The error tests in `CompositeParsingTest` provide excellent examples of common programming errors related to serialization and deserialization:
    * **Data corruption:**  As shown in `DecodingFailure_CBORTokenizer`.
    * **Missing mandatory fields:**  Demonstrated in `DecodingFailure_MandatoryFieldMissingShallow` and `DecodingFailure_MandatoryFieldMissingNested`.
    * **Type mismatches:**  Illustrated in `DecodingFailure_BoolValueExpected`.

9. **Torque Check:**  The request includes a check for the `.tq` extension. A quick look at the filename confirms it's `.cc`, so it's C++ and not Torque.

10. **Structuring the Output:** Finally, organize the gathered information logically under the headings requested in the prompt: Functionality, JavaScript Relation, Code Logic, and Common Errors. Use clear and concise language. Include code snippets and examples where appropriate. Ensure the JavaScript example is easy to understand even without deep knowledge of CDP internals.
The file `v8/third_party/inspector_protocol/crdtp/protocol_core_test.cc` is a **C++ source file containing unit tests** for the `protocol_core.h` header file, which likely defines core functionalities for handling the Chrome DevTools Protocol (CRDP) within the V8 engine.

Here's a breakdown of its functionalities:

**1. Testing Basic Serialization and Deserialization:**

*   It defines simple test classes like `TestTypeBasic` and `TestTypeBasicDouble` which represent data structures that need to be serialized and deserialized.
*   It uses the `V8_CRDTP_BEGIN/END_SERIALIZER/DESERIALIZER` macros to define how these classes are converted to and from a byte stream (likely CBOR, based on the `#include "cbor.h"`).
*   The `Roundtrip` template function serializes an object and then deserializes it back, allowing for verification that the process is working correctly.
*   The `TEST(ProtocolCoreTest, Basic)` test case demonstrates this by creating a `TestTypeBasic` object, setting a value, roundtripping it, and asserting that the value remains the same.

**2. Testing Error Handling during Deserialization:**

*   The `TEST(ProtocolCoreTest, FailedToDeserializeTestTypeBasic)` test case attempts to deserialize garbage data into a `TestTypeBasic` object and checks if the expected error status (`Error::CBOR_INVALID_STRING8`) is returned. This validates the error handling mechanisms.
*   The `CompositeParsingTest` fixture and its associated tests (`DecodingFailure_CBORTokenizer`, `DecodingFailure_MandatoryFieldMissingShallow`, `DecodingFailure_MandatoryFieldMissingNested`, `DecodingFailure_BoolValueExpected`) systematically introduce errors into a serialized object and verify that the deserializer correctly identifies the type and location of the error.

**3. Testing Composite Objects:**

*   The `TestTypeComposite` class represents a more complex object containing various data types (bool, int, double, string, and a nested `TestTypeBasic`).
*   The `TEST(ProtocolCoreTest, Composite)` test case demonstrates the serialization and deserialization of such composite objects, ensuring that all nested fields are handled correctly.

**4. Testing Arrays:**

*   The `TestTypeArrays` class includes vectors of different data types (int, double, string, and `TestTypeBasic`).
*   The `TEST_F(CompositeParsingTest, Arrays)` test verifies the serialization and deserialization of arrays.

**5. Testing Optional Fields:**

*   The `TestTypeOptional` class uses `Maybe` (likely a custom optional type) to represent fields that might be present or absent.
*   The `TEST(ProtocolCoreTest, OptionalAbsent)` and `TEST(ProtocolCoreTest, OptionalPresent)` tests check that optional fields are handled correctly in both scenarios.

**6. Testing Lazy Deserialization (Deferred Messages):**

*   The `TestTypeLazy` class includes a `DeferredMessage` for one of its fields. This mechanism allows for delaying the deserialization of a potentially complex or large nested object until it's actually needed.
*   The `TEST(ProtocolCoreTest, TestDeferredMessage)` test case shows how to serialize a `TestTypeComposite`, deserialize it as a `TestTypeLazy`, and then explicitly deserialize the deferred message.

**Regarding the file extension and JavaScript relation:**

*   The file extension is `.cc`, which indicates it's a **C++ source file**. Therefore, it's **not a v8 torque source file**.
*   Given the path `v8/third_party/inspector_protocol/crdtp/`, the code is definitely related to the **Chrome DevTools Protocol (CRDP)**. This protocol is used for communication between the Chrome DevTools frontend (written in JavaScript) and the Chromium browser (including the V8 JavaScript engine).
*   The serialization and deserialization tested in this file are crucial for converting data between the C++ backend of V8 and the JavaScript frontend of the DevTools.

**JavaScript Example:**

Imagine the `TestTypeBasic` class represents data about a variable in the JavaScript debugger. In JavaScript, you might receive this data as a JSON object (which is conceptually similar to the CBOR being used here):

```javascript
// Example of a JSON object representing a TestTypeBasic
const variableData = {
  value: "myVariableValue"
};

// You might have a function in the DevTools frontend that processes this data
function displayVariableValue(data) {
  console.log("Variable Value:", data.value);
}

displayVariableValue(variableData);
```

The C++ code in `protocol_core_test.cc` ensures that the V8 backend can correctly serialize its internal representation of this variable data into a format (like CBOR) that can be transmitted and then deserialized by the JavaScript frontend (which might then convert it to a JavaScript object like the one above).

**Code Logic Reasoning with Assumptions and Outputs:**

Let's take the `TEST(ProtocolCoreTest, Basic)` case as an example:

**Assumption:** The serialization and deserialization logic for `TestTypeBasic` is implemented correctly using the `V8_CRDTP_BEGIN/END` macros.

**Input:**

1. Create a `TestTypeBasic` object named `obj1`.
2. Set `obj1.value_` to the string "foo".

**Steps:**

1. `Roundtrip(obj1)` serializes `obj1` into a byte vector. Assuming the serialization for "foo" in CBOR involves a string tag and the bytes for "foo", the byte vector might look something like `[0x63, 0x66, 0x6f, 0x6f]` (this is a simplification, the exact CBOR encoding depends on the implementation).
2. `Roundtrip` then deserializes this byte vector back into a new `TestTypeBasic` object named `obj2`.

**Output:**

1. `ASSERT_THAT(obj2, Not(testing::IsNull()));` will pass because the deserialization is expected to be successful.
2. `EXPECT_THAT(obj2->GetValue(), Eq("foo"));` will pass because the deserialized `obj2` should have its `value_` field set back to "foo".

**Common Programming Errors and Examples:**

The `CompositeParsingTest` suite directly tests for common errors:

1. **Data Corruption during Transmission/Storage:**
    *   **Example:** The `DecodingFailure_CBORTokenizer` test simulates this by corrupting the byte stream, making it invalid CBOR.
    *   **JavaScript Equivalent:** Imagine a network issue causing the JSON data to be truncated or garbled before reaching the DevTools frontend. Trying to `JSON.parse()` such corrupted data would result in an error.

2. **Missing Mandatory Fields:**
    *   **Example:** The `DecodingFailure_MandatoryFieldMissingShallow` and `DecodingFailure_MandatoryFieldMissingNested` tests demonstrate what happens when a required field is absent in the serialized data.
    *   **JavaScript Equivalent:** If the JavaScript code expects a property named `value` in the `variableData` object, but the backend sends `{ name: "myVariable" }`, accessing `data.value` would result in `undefined`.

3. **Type Mismatches:**
    *   **Example:** The `DecodingFailure_BoolValueExpected` test changes a boolean value to null in the serialized data.
    *   **JavaScript Equivalent:** If the JavaScript code expects the `value` property to be a string, but the backend incorrectly sends a number (`{ value: 123 }`), this could lead to unexpected behavior or errors in the JavaScript code if it tries to perform string operations on it.

In summary, `v8/third_party/inspector_protocol/crdtp/protocol_core_test.cc` is a crucial part of V8's testing infrastructure, ensuring the reliability of the serialization and deserialization mechanisms used for communication with the Chrome DevTools. It helps prevent common errors that can occur when exchanging data between the C++ backend and the JavaScript frontend.

Prompt: 
```
这是目录为v8/third_party/inspector_protocol/crdtp/protocol_core_test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/protocol_core_test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```