Response:
The user wants a summary of the functionality of the provided C++ code. The code is a unit test file for the `ValueSerializer` and `ValueDeserializer` classes in V8.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The filename `value-serializer-unittest.cc` and the includes like `value-serializer.h` and `v8-value-serializer.h` clearly indicate that this file tests the serialization and deserialization of JavaScript values.

2. **Look for key classes and methods:** The presence of `ValueSerializer` and `ValueDeserializer` within the code, along with methods like `EncodeTest`, `DecodeTest`, and `RoundTripTest`, confirms the core purpose.

3. **Examine the test cases:** The various `TEST_F` macros define individual test cases. By looking at the names of these tests (e.g., `RoundTripOddball`, `RoundTripNumber`, `RoundTripString`), we can understand the specific types of values being tested. The "RoundTrip" pattern suggests that the tests serialize a value and then deserialize it, checking if the result is the same as the original.

4. **Consider the edge cases:**  Tests like `EncodeArrayStackOverflow`, `DecodeArrayStackOverflow`, and `DecodeInvalid` indicate that the tests also cover error handling and boundary conditions.

5. **Check for JavaScript interaction:** The inclusion of `include/v8-context.h` and the use of `Local<Context>` suggest that the tests are run within a V8 JavaScript context. The `EvaluateScriptForInput` and `ExpectScriptTrue` methods further confirm the interaction with JavaScript.

6. **Look for specific data types:** The tests explicitly mention various JavaScript data types like `undefined`, `true`, `false`, `null`, numbers, big integers, strings, objects, arrays, dates, array buffers, typed arrays, data views, maps, sets, regular expressions, promises, and weak collections. This provides a comprehensive overview of the serializer's capabilities.

7. **Address specific instructions:**
    * **".tq" check:** The filename ends with ".cc", not ".tq", so it's not a Torque file.
    * **JavaScript relationship:**  The tests heavily rely on JavaScript values, and the `RoundTripTest` variants using string input demonstrate this.
    * **Code logic inference:** The round-trip tests implicitly provide input/output examples.
    * **Common programming errors:** The stack overflow tests and the `DecodeInvalid` test hint at potential issues.

8. **Synthesize the information:** Combine the observations into a concise summary, grouping related functionalities.

9. **Refine and organize:** Structure the summary into logical points, addressing all aspects of the user's request. Use clear and descriptive language.
Based on the provided C++ code snippet from `v8/test/unittests/objects/value-serializer-unittest.cc`, here's a breakdown of its functionality:

**Core Functionality:**

The code is a unit test suite for the `ValueSerializer` and `ValueDeserializer` classes in the V8 JavaScript engine. Its primary purpose is to verify that these classes correctly serialize (encode) JavaScript values into a byte stream and then deserialize (decode) that byte stream back into equivalent JavaScript values. The "RoundTrip" tests are central to this, where a value is serialized and then immediately deserialized, with assertions to ensure the original and resulting values are the same.

**Key Features and Tested Aspects:**

* **Basic Data Types:**  It tests the serialization and deserialization of fundamental JavaScript data types like:
    * `undefined`, `true`, `false`, `null` (oddballs)
    * Integers (positive and negative)
    * Floating-point numbers (including NaN)
    * BigInts (large integers)
    * Strings (empty, ASCII, Latin-1, and multi-byte UTF-8 characters, including emojis)

* **Object Serialization:**  It verifies the serialization and deserialization of JavaScript objects, including:
    * Empty objects
    * Objects with string and integer keys
    * Preservation of property order
    * Handling of circular references within objects.

* **Error Handling:**  The tests include scenarios designed to trigger errors during serialization and deserialization:
    * **Stack Overflow:** Tests for deeply nested arrays and objects that could cause stack overflows during encoding and decoding.
    * **Invalid Input:** Tests for invalid byte streams during deserialization (e.g., truncated data, incorrect tags).

* **Wire Format Versioning:** The tests use `DecodeTestFutureVersions` and explicitly check different wire format versions (indicated by the byte after the magic number `0xFF`). This ensures backward compatibility and proper handling of different serialization formats.

* **Host Objects:**  The code sets up a custom "ExampleHostObject" to test the serialization and deserialization of native objects and their associated data.

**Specific Observations:**

* **Not a Torque File:** The filename ends with `.cc`, not `.tq`, so it is a standard C++ source file, not a V8 Torque file.
* **Relationship to JavaScript:** The entire purpose of this code is to test the serialization and deserialization of JavaScript values. The tests manipulate and assert the properties of JavaScript values within a V8 context.

**Code Logic Inference (Hypothetical Example):**

Let's consider the `RoundTripTest("({ a: 42 })")` test.

* **Hypothetical Input:** A JavaScript object `{ a: 42 }`.
* **Serialization Process (Internal):** The `ValueSerializer` would traverse the object, encoding its type (object), keys ("a"), and values (42) into a byte stream according to V8's serialization format.
* **Deserialization Process (Internal):** The `ValueDeserializer` would read the byte stream, interpreting the type information and reconstructing the JavaScript object in memory.
* **Hypothetical Output:**  A JavaScript object that, when inspected in the test, has a property `a` with the value `42`. The `ExpectScriptTrue("result.hasOwnProperty('a')")` and `ExpectScriptTrue("result.a === 42")` lines verify this.

**User-Common Programming Errors (Related to Serialization/Deserialization):**

While this code tests the V8 engine itself, it indirectly highlights potential user errors when dealing with serialization:

1. **Circular References:**  If a user attempts to serialize an object with circular references without proper handling, it could lead to infinite loops or stack overflows. V8's serializer handles this, but custom serialization implementations might not.

   ```javascript
   // Example of a circular reference:
   const obj = {};
   obj.self = obj;

   // Attempting to serialize this with a naive approach might fail.
   // JSON.stringify would throw an error.
   ```

2. **Incorrect Data Types or Formats:** When manually implementing serialization or communicating with systems expecting specific formats, users can make mistakes in data type conversion or encoding, leading to deserialization errors on the receiving end.

3. **Version Mismatches:**  If different versions of a serializer/deserializer are used, or if the underlying data structure changes, deserialization might fail or produce unexpected results. V8's versioning mechanism (tested here) aims to mitigate this.

**Summary of Functionality (Part 1):**

This first part of the `value-serializer-unittest.cc` file focuses on testing the **fundamental serialization and deserialization capabilities of V8's `ValueSerializer` and `ValueDeserializer`**. It covers the most basic JavaScript data types (oddballs, numbers, BigInts, and strings) and simple objects. It also includes initial tests for error handling (stack overflows, invalid input) and demonstrates the setup for testing different wire format versions. The tests are designed to ensure that these core serialization mechanisms function correctly and can reliably round-trip these fundamental JavaScript values.

### 提示词
```
这是目录为v8/test/unittests/objects/value-serializer-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/objects/value-serializer-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/value-serializer.h"

#include <algorithm>
#include <string>

#include "include/v8-context.h"
#include "include/v8-date.h"
#include "include/v8-function.h"
#include "include/v8-json.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive-object.h"
#include "include/v8-template.h"
#include "include/v8-value-serializer-version.h"
#include "include/v8-value-serializer.h"
#include "include/v8-wasm.h"
#include "src/api/api-inl.h"
#include "src/base/build_config.h"
#include "src/objects/backing-store.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/objects-inl.h"
#include "test/common/flag-utils.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-result.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

class ValueSerializerTest : public TestWithIsolate {
 public:
  ValueSerializerTest(const ValueSerializerTest&) = delete;
  ValueSerializerTest& operator=(const ValueSerializerTest&) = delete;

 protected:
  ValueSerializerTest() {
    FLAG_SCOPE(js_float16array);
    Local<Context> serialization_context = Context::New(isolate());
    Local<Context> deserialization_context = Context::New(isolate());
    serialization_context_.Reset(isolate(), serialization_context);
    deserialization_context_.Reset(isolate(), deserialization_context);
    // Create a host object type that can be tested through
    // serialization/deserialization delegates below.
    Local<FunctionTemplate> function_template = v8::FunctionTemplate::New(
        isolate(), [](const FunctionCallbackInfo<Value>& info) {
          CHECK(i::ValidateCallbackInfo(info));
          info.HolderSoonToBeDeprecated()->SetInternalField(0, info[0]);
          info.HolderSoonToBeDeprecated()->SetInternalField(1, info[1]);
        });
    function_template->InstanceTemplate()->SetInternalFieldCount(2);
    function_template->InstanceTemplate()->SetNativeDataProperty(
        StringFromUtf8("value"),
        [](Local<Name> property, const PropertyCallbackInfo<Value>& info) {
          CHECK(i::ValidateCallbackInfo(info));
          info.GetReturnValue().Set(
              info.HolderV2()->GetInternalField(0).As<v8::Value>());
        });
    function_template->InstanceTemplate()->SetNativeDataProperty(
        StringFromUtf8("value2"),
        [](Local<Name> property, const PropertyCallbackInfo<Value>& info) {
          CHECK(i::ValidateCallbackInfo(info));
          info.GetReturnValue().Set(
              info.HolderV2()->GetInternalField(1).As<v8::Value>());
        });
    for (Local<Context> context :
         {serialization_context, deserialization_context}) {
      context->Global()
          ->CreateDataProperty(
              context, StringFromUtf8("ExampleHostObject"),
              function_template->GetFunction(context).ToLocalChecked())
          .ToChecked();
    }
    host_object_constructor_template_.Reset(isolate(), function_template);
    isolate_ = reinterpret_cast<i::Isolate*>(isolate());
  }

  ~ValueSerializerTest() override { DCHECK(!isolate_->has_exception()); }

  Local<Context> serialization_context() {
    return serialization_context_.Get(isolate());
  }
  Local<Context> deserialization_context() {
    return deserialization_context_.Get(isolate());
  }

  // Overridden in more specific fixtures.
  virtual ValueSerializer::Delegate* GetSerializerDelegate() { return nullptr; }
  virtual void BeforeEncode(ValueSerializer*) {}
  virtual ValueDeserializer::Delegate* GetDeserializerDelegate() {
    return nullptr;
  }
  virtual void BeforeDecode(ValueDeserializer*) {}

  Local<Value> RoundTripTest(Local<Value> input_value) {
    std::vector<uint8_t> encoded = EncodeTest(input_value);
    return DecodeTest(encoded);
  }

  // Variant for the common case where a script is used to build the original
  // value.
  Local<Value> RoundTripTest(const char* source) {
    return RoundTripTest(EvaluateScriptForInput(source));
  }

  // Variant which uses JSON.parse/stringify to check the result.
  void RoundTripJSON(const char* source) {
    Local<Value> input_value =
        JSON::Parse(serialization_context(), StringFromUtf8(source))
            .ToLocalChecked();
    Local<Value> result = RoundTripTest(input_value);
    ASSERT_TRUE(result->IsObject());
    EXPECT_EQ(source, Utf8Value(JSON::Stringify(deserialization_context(),
                                                result.As<Object>())
                                    .ToLocalChecked()));
  }

  Maybe<std::vector<uint8_t>> DoEncode(Local<Value> value) {
    Local<Context> context = serialization_context();
    ValueSerializer serializer(isolate(), GetSerializerDelegate());
    BeforeEncode(&serializer);
    serializer.WriteHeader();
    if (!serializer.WriteValue(context, value).FromMaybe(false)) {
      return Nothing<std::vector<uint8_t>>();
    }
    std::pair<uint8_t*, size_t> buffer = serializer.Release();
    std::vector<uint8_t> result(buffer.first, buffer.first + buffer.second);
    if (auto* delegate = GetSerializerDelegate())
      delegate->FreeBufferMemory(buffer.first);
    else
      free(buffer.first);
    return Just(std::move(result));
  }

  std::vector<uint8_t> EncodeTest(Local<Value> input_value) {
    Context::Scope scope(serialization_context());
    TryCatch try_catch(isolate());
    std::vector<uint8_t> buffer;
    // Ideally we would use GTest's ASSERT_* macros here and below. However,
    // those only work in functions returning {void}, and they only terminate
    // the current function, but not the entire current test (so we would need
    // additional manual checks whether it is okay to proceed). Given that our
    // test driver starts a new process for each test anyway, it is acceptable
    // to just use a CHECK (which would kill the process on failure) instead.
    CHECK(DoEncode(input_value).To(&buffer));
    CHECK(!try_catch.HasCaught());
    return buffer;
  }

  std::vector<uint8_t> EncodeTest(const char* source) {
    return EncodeTest(EvaluateScriptForInput(source));
  }

  v8::Local<v8::Message> InvalidEncodeTest(Local<Value> input_value) {
    Context::Scope scope(serialization_context());
    TryCatch try_catch(isolate());
    CHECK(DoEncode(input_value).IsNothing());
    return try_catch.Message();
  }

  v8::Local<v8::Message> InvalidEncodeTest(const char* source) {
    return InvalidEncodeTest(EvaluateScriptForInput(source));
  }

  Local<Value> DecodeTest(const std::vector<uint8_t>& data) {
    Local<Context> context = deserialization_context();
    Context::Scope scope(context);
    TryCatch try_catch(isolate());
    ValueDeserializer deserializer(isolate(), &data[0],
                                   static_cast<int>(data.size()),
                                   GetDeserializerDelegate());
    deserializer.SetSupportsLegacyWireFormat(true);
    BeforeDecode(&deserializer);
    CHECK(deserializer.ReadHeader(context).FromMaybe(false));
    Local<Value> result;
    CHECK(deserializer.ReadValue(context).ToLocal(&result));
    CHECK(!result.IsEmpty());
    CHECK(!try_catch.HasCaught());
    CHECK(context->Global()
              ->CreateDataProperty(context, StringFromUtf8("result"), result)
              .FromMaybe(false));
    CHECK(!try_catch.HasCaught());
    return result;
  }

  template <typename Lambda>
  void DecodeTestFutureVersions(std::vector<uint8_t>&& data, Lambda test) {
    DecodeTestUpToVersion(v8::CurrentValueSerializerFormatVersion(),
                          std::move(data), test);
  }

  template <typename Lambda>
  void DecodeTestUpToVersion(int last_version, std::vector<uint8_t>&& data,
                             Lambda test) {
    // Check that there is at least one version to test.
    CHECK_LE(data[1], last_version);
    for (int version = data[1]; version <= last_version; ++version) {
      data[1] = version;
      Local<Value> value = DecodeTest(data);
      test(value);
    }
  }

  Local<Value> DecodeTestForVersion0(const std::vector<uint8_t>& data) {
    Local<Context> context = deserialization_context();
    Context::Scope scope(context);
    TryCatch try_catch(isolate());
    ValueDeserializer deserializer(isolate(), &data[0],
                                   static_cast<int>(data.size()),
                                   GetDeserializerDelegate());
    deserializer.SetSupportsLegacyWireFormat(true);
    BeforeDecode(&deserializer);
    CHECK(deserializer.ReadHeader(context).FromMaybe(false));
    CHECK_EQ(0u, deserializer.GetWireFormatVersion());
    Local<Value> result;
    CHECK(deserializer.ReadValue(context).ToLocal(&result));
    CHECK(!result.IsEmpty());
    CHECK(!try_catch.HasCaught());
    CHECK(context->Global()
              ->CreateDataProperty(context, StringFromUtf8("result"), result)
              .FromMaybe(false));
    CHECK(!try_catch.HasCaught());
    return result;
  }

  void InvalidDecodeTest(const std::vector<uint8_t>& data) {
    Local<Context> context = deserialization_context();
    Context::Scope scope(context);
    TryCatch try_catch(isolate());
    ValueDeserializer deserializer(isolate(), &data[0],
                                   static_cast<int>(data.size()),
                                   GetDeserializerDelegate());
    deserializer.SetSupportsLegacyWireFormat(true);
    BeforeDecode(&deserializer);
    Maybe<bool> header_result = deserializer.ReadHeader(context);
    if (header_result.IsNothing()) {
      EXPECT_TRUE(try_catch.HasCaught());
      return;
    }
    CHECK(header_result.ToChecked());
    CHECK(deserializer.ReadValue(context).IsEmpty());
    EXPECT_TRUE(try_catch.HasCaught());
  }

  Local<Value> EvaluateScriptForInput(const char* utf8_source) {
    Context::Scope scope(serialization_context());
    Local<String> source = StringFromUtf8(utf8_source);
    Local<Script> script =
        Script::Compile(serialization_context(), source).ToLocalChecked();
    return script->Run(serialization_context()).ToLocalChecked();
  }

  void ExpectScriptTrue(const char* utf8_source) {
    Context::Scope scope(deserialization_context());
    Local<String> source = StringFromUtf8(utf8_source);
    Local<Script> script =
        Script::Compile(deserialization_context(), source).ToLocalChecked();
    Local<Value> value =
        script->Run(deserialization_context()).ToLocalChecked();
    EXPECT_TRUE(value->BooleanValue(isolate()));
  }

  Local<String> StringFromUtf8(const char* source) {
    return String::NewFromUtf8(isolate(), source).ToLocalChecked();
  }

  std::string Utf8Value(Local<Value> value) {
    String::Utf8Value utf8(isolate(), value);
    return std::string(*utf8, utf8.length());
  }

  Local<Object> NewHostObject(Local<Context> context, int argc,
                              Local<Value> argv[]) {
    return host_object_constructor_template_.Get(isolate())
        ->GetFunction(context)
        .ToLocalChecked()
        ->NewInstance(context, argc, argv)
        .ToLocalChecked();
  }

  Local<Object> NewDummyUint8Array() {
    const uint8_t data[] = {4, 5, 6};
    Local<ArrayBuffer> ab = ArrayBuffer::New(isolate(), sizeof(data));
    memcpy(ab->GetBackingStore()->Data(), data, sizeof(data));
    return Uint8Array::New(ab, 0, sizeof(data));
  }

 private:
  Global<Context> serialization_context_;
  Global<Context> deserialization_context_;
  Global<FunctionTemplate> host_object_constructor_template_;
  i::Isolate* isolate_;
};

TEST_F(ValueSerializerTest, DecodeInvalid) {
  // Version tag but no content.
  InvalidDecodeTest({0xFF});
  // Version too large.
  InvalidDecodeTest({0xFF, 0x7F, 0x5F});
  // Nonsense tag.
  InvalidDecodeTest({0xFF, 0x09, 0xDD});
}

TEST_F(ValueSerializerTest, RoundTripOddball) {
  Local<Value> value = RoundTripTest(Undefined(isolate()));
  EXPECT_TRUE(value->IsUndefined());
  value = RoundTripTest(True(isolate()));
  EXPECT_TRUE(value->IsTrue());
  value = RoundTripTest(False(isolate()));
  EXPECT_TRUE(value->IsFalse());
  value = RoundTripTest(Null(isolate()));
  EXPECT_TRUE(value->IsNull());
}

TEST_F(ValueSerializerTest, DecodeOddball) {
  // What this code is expected to generate.
  DecodeTestFutureVersions({0xFF, 0x09, 0x5F}, [](Local<Value> value) {
    EXPECT_TRUE(value->IsUndefined());
  });
  DecodeTestFutureVersions({0xFF, 0x09, 0x54}, [](Local<Value> value) {
    EXPECT_TRUE(value->IsTrue());
  });
  DecodeTestFutureVersions({0xFF, 0x09, 0x46}, [](Local<Value> value) {
    EXPECT_TRUE(value->IsFalse());
  });
  DecodeTestFutureVersions({0xFF, 0x09, 0x30}, [](Local<Value> value) {
    EXPECT_TRUE(value->IsNull());
  });

  // What v9 of the Blink code generates.
  Local<Value> value = DecodeTest({0xFF, 0x09, 0x3F, 0x00, 0x5F, 0x00});
  EXPECT_TRUE(value->IsUndefined());
  value = DecodeTest({0xFF, 0x09, 0x3F, 0x00, 0x54, 0x00});
  EXPECT_TRUE(value->IsTrue());
  value = DecodeTest({0xFF, 0x09, 0x3F, 0x00, 0x46, 0x00});
  EXPECT_TRUE(value->IsFalse());
  value = DecodeTest({0xFF, 0x09, 0x3F, 0x00, 0x30, 0x00});
  EXPECT_TRUE(value->IsNull());

  // v0 (with no explicit version).
  value = DecodeTest({0x5F, 0x00});
  EXPECT_TRUE(value->IsUndefined());
  value = DecodeTest({0x54, 0x00});
  EXPECT_TRUE(value->IsTrue());
  value = DecodeTest({0x46, 0x00});
  EXPECT_TRUE(value->IsFalse());
  value = DecodeTest({0x30, 0x00});
  EXPECT_TRUE(value->IsNull());
}

TEST_F(ValueSerializerTest, EncodeArrayStackOverflow) {
  InvalidEncodeTest("var a = []; for (var i = 0; i < 1E5; i++) a = [a]; a");
}

TEST_F(ValueSerializerTest, EncodeObjectStackOverflow) {
  InvalidEncodeTest("var a = {}; for (var i = 0; i < 1E5; i++) a = {a}; a");
}

TEST_F(ValueSerializerTest, DecodeArrayStackOverflow) {
  static const int nesting_level = 1E5;
  std::vector<uint8_t> payload;
  // Header.
  payload.push_back(0xFF);
  payload.push_back(0x0D);

  // Nested arrays, each with one element.
  for (int i = 0; i < nesting_level; i++) {
    payload.push_back(0x41);
    payload.push_back(0x01);
  }

  // Innermost array is empty.
  payload.push_back(0x41);
  payload.push_back(0x00);
  payload.push_back(0x24);
  payload.push_back(0x00);
  payload.push_back(0x00);

  // Close nesting.
  for (int i = 0; i < nesting_level; i++) {
    payload.push_back(0x24);
    payload.push_back(0x00);
    payload.push_back(0x01);
  }

  InvalidDecodeTest(payload);
}

TEST_F(ValueSerializerTest, DecodeObjectStackOverflow) {
  static const int nesting_level = 1E5;
  std::vector<uint8_t> payload;
  // Header.
  payload.push_back(0xFF);
  payload.push_back(0x0D);

  // Nested objects, each with one property 'a'.
  for (int i = 0; i < nesting_level; i++) {
    payload.push_back(0x6F);
    payload.push_back(0x22);
    payload.push_back(0x01);
    payload.push_back(0x61);
  }

  // Innermost array is empty.
  payload.push_back(0x6F);
  payload.push_back(0x7B);
  payload.push_back(0x00);

  // Close nesting.
  for (int i = 0; i < nesting_level; i++) {
    payload.push_back(0x7B);
    payload.push_back(0x01);
  }

  InvalidDecodeTest(payload);
}

TEST_F(ValueSerializerTest, DecodeVerifyObjectCount) {
  static const int nesting_level = 1E5;
  std::vector<uint8_t> payload;
  // Header.
  payload.push_back(0xFF);
  payload.push_back(0x0D);

  // Repeat SerializationTag:kVerifyObjectCount. This leads to stack overflow.
  for (int i = 0; i < nesting_level; i++) {
    payload.push_back(0x3F);
    payload.push_back(0x01);
  }

  InvalidDecodeTest(payload);
}

TEST_F(ValueSerializerTest, RoundTripNumber) {
  Local<Value> value = RoundTripTest(Integer::New(isolate(), 42));
  ASSERT_TRUE(value->IsInt32());
  EXPECT_EQ(42, Int32::Cast(*value)->Value());

  value = RoundTripTest(Integer::New(isolate(), -31337));
  ASSERT_TRUE(value->IsInt32());
  EXPECT_EQ(-31337, Int32::Cast(*value)->Value());

  value = RoundTripTest(
      Integer::New(isolate(), std::numeric_limits<int32_t>::min()));
  ASSERT_TRUE(value->IsInt32());
  EXPECT_EQ(std::numeric_limits<int32_t>::min(), Int32::Cast(*value)->Value());

  value = RoundTripTest(Number::New(isolate(), -0.25));
  ASSERT_TRUE(value->IsNumber());
  EXPECT_EQ(-0.25, Number::Cast(*value)->Value());

  value = RoundTripTest(
      Number::New(isolate(), std::numeric_limits<double>::quiet_NaN()));
  ASSERT_TRUE(value->IsNumber());
  EXPECT_TRUE(std::isnan(Number::Cast(*value)->Value()));
}

TEST_F(ValueSerializerTest, DecodeNumber) {
  // 42 zig-zag encoded (signed)
  DecodeTestFutureVersions({0xFF, 0x09, 0x49, 0x54}, [](Local<Value> value) {
    ASSERT_TRUE(value->IsInt32());
    EXPECT_EQ(42, Int32::Cast(*value)->Value());
  });

  // 42 varint encoded (unsigned)
  DecodeTestFutureVersions({0xFF, 0x09, 0x55, 0x2A}, [](Local<Value> value) {
    ASSERT_TRUE(value->IsInt32());
    EXPECT_EQ(42, Int32::Cast(*value)->Value());
  });

  // 160 zig-zag encoded (signed)
  DecodeTestFutureVersions({0xFF, 0x09, 0x49, 0xC0, 0x02},
                           [](Local<Value> value) {
                             ASSERT_TRUE(value->IsInt32());
                             ASSERT_EQ(160, Int32::Cast(*value)->Value());
                           });

  // 160 varint encoded (unsigned)
  DecodeTestFutureVersions({0xFF, 0x09, 0x55, 0xA0, 0x01},
                           [](Local<Value> value) {
                             ASSERT_TRUE(value->IsInt32());
                             ASSERT_EQ(160, Int32::Cast(*value)->Value());
                           });

#if defined(V8_TARGET_LITTLE_ENDIAN)
  // IEEE 754 doubles, little-endian byte order
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD0, 0xBF},
      [](Local<Value> value) {
        ASSERT_TRUE(value->IsNumber());
        EXPECT_EQ(-0.25, Number::Cast(*value)->Value());
      });

  // quiet NaN
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x7F},
      [](Local<Value> value) {
        ASSERT_TRUE(value->IsNumber());
        EXPECT_TRUE(std::isnan(Number::Cast(*value)->Value()));
      });

  // signaling NaN
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x4E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF4, 0x7F},
      [](Local<Value> value) {
        ASSERT_TRUE(value->IsNumber());
        EXPECT_TRUE(std::isnan(Number::Cast(*value)->Value()));
      });
#endif
  // TODO(jbroman): Equivalent test for big-endian machines.
}

TEST_F(ValueSerializerTest, RoundTripBigInt) {
  Local<Value> value = RoundTripTest(BigInt::New(isolate(), -42));
  ASSERT_TRUE(value->IsBigInt());
  ExpectScriptTrue("result === -42n");

  value = RoundTripTest(BigInt::New(isolate(), 42));
  ExpectScriptTrue("result === 42n");

  value = RoundTripTest(BigInt::New(isolate(), 0));
  ExpectScriptTrue("result === 0n");

  value = RoundTripTest("0x1234567890abcdef777888999n");
  ExpectScriptTrue("result === 0x1234567890abcdef777888999n");

  value = RoundTripTest("-0x1234567890abcdef777888999123n");
  ExpectScriptTrue("result === -0x1234567890abcdef777888999123n");

  Context::Scope scope(serialization_context());
  value = RoundTripTest(BigIntObject::New(isolate(), 23));
  ASSERT_TRUE(value->IsBigIntObject());
  ExpectScriptTrue("result == 23n");
}

TEST_F(ValueSerializerTest, DecodeBigInt) {
  DecodeTestFutureVersions(
      {
          0xFF, 0x0D,              // Version 13
          0x5A,                    // BigInt
          0x08,                    // Bitfield: sign = false, bytelength = 4
          0x2A, 0x00, 0x00, 0x00,  // Digit: 42
      },
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsBigInt());
        ExpectScriptTrue("result === 42n");
      });

  DecodeTestFutureVersions(
      {
          0xFF, 0x0D,  // Version 13
          0x7A,        // BigIntObject
          0x11,        // Bitfield: sign = true, bytelength = 8
          0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Digit: 42
      },
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsBigIntObject());
        ExpectScriptTrue("result == -42n");
      });

  DecodeTestFutureVersions(
      {
          0xFF, 0x0D,  // Version 13
          0x5A,        // BigInt
          0x10,        // Bitfield: sign = false, bytelength = 8
          0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12  // Digit(s).
      },
      [this](Local<Value> value) {
        ExpectScriptTrue("result === 0x1234567890abcdefn");
      });

  DecodeTestFutureVersions(
      {0xFF, 0x0D,              // Version 13
       0x5A,                    // BigInt
       0x17,                    // Bitfield: sign = true, bytelength = 11
       0xEF, 0xCD, 0xAB, 0x90,  // Digits.
       0x78, 0x56, 0x34, 0x12, 0x33, 0x44, 0x55},
      [this](Local<Value> value) {
        ExpectScriptTrue("result === -0x5544331234567890abcdefn");
      });
  DecodeTestFutureVersions(
      {
          0xFF, 0x0D,  // Version 13
          0x5A,        // BigInt
          0x02,        // Bitfield: sign = false, bytelength = 1
          0x2A,        // Digit: 42
      },
      [this](Local<Value> value) { ExpectScriptTrue("result === 42n"); });
  InvalidDecodeTest({
      0xFF, 0x0F,  // Version 15
      0x5A,        // BigInt
      0x01,        // Bitfield: sign = true, bytelength = 0
  });
  // From a philosophical standpoint, we could reject this case as invalid as
  // well, but it would require extra code and probably isn't worth it, so
  // we quietly normalize this invalid input to {0n}.
  DecodeTestFutureVersions(
      {
          0xFF, 0x0F,             // Version 15
          0x5A,                   // BigInt
          0x09,                   // Bitfield: sign = true, bytelength = 4
          0x00, 0x00, 0x00, 0x00  // Digits.
      },
      [this](Local<Value> value) {
        ExpectScriptTrue("(result | result) === 0n");
      });
}

// String constants (in UTF-8) used for string encoding tests.
static const char kHelloString[] = "Hello";
static const char kQuebecString[] = "\x51\x75\xC3\xA9\x62\x65\x63";
static const char kEmojiString[] = "\xF0\x9F\x91\x8A";

TEST_F(ValueSerializerTest, RoundTripString) {
  Local<Value> value = RoundTripTest(String::Empty(isolate()));
  ASSERT_TRUE(value->IsString());
  EXPECT_EQ(0, String::Cast(*value)->Length());

  // Inside ASCII.
  value = RoundTripTest(StringFromUtf8(kHelloString));
  ASSERT_TRUE(value->IsString());
  EXPECT_EQ(5, String::Cast(*value)->Length());
  EXPECT_EQ(kHelloString, Utf8Value(value));

  // Inside Latin-1 (i.e. one-byte string), but not ASCII.
  value = RoundTripTest(StringFromUtf8(kQuebecString));
  ASSERT_TRUE(value->IsString());
  EXPECT_EQ(6, String::Cast(*value)->Length());
  EXPECT_EQ(kQuebecString, Utf8Value(value));

  // An emoji (decodes to two 16-bit chars).
  value = RoundTripTest(StringFromUtf8(kEmojiString));
  ASSERT_TRUE(value->IsString());
  EXPECT_EQ(2, String::Cast(*value)->Length());
  EXPECT_EQ(kEmojiString, Utf8Value(value));
}

TEST_F(ValueSerializerTest, DecodeString) {
  // Decoding the strings above from UTF-8.
  DecodeTestFutureVersions({0xFF, 0x09, 0x53, 0x00}, [](Local<Value> value) {
    ASSERT_TRUE(value->IsString());
    EXPECT_EQ(0, String::Cast(*value)->Length());
  });

  DecodeTestFutureVersions({0xFF, 0x09, 0x53, 0x05, 'H', 'e', 'l', 'l', 'o'},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsString());
                             EXPECT_EQ(5, String::Cast(*value)->Length());
                             EXPECT_EQ(kHelloString, Utf8Value(value));
                           });

  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x53, 0x07, 'Q', 'u', 0xC3, 0xA9, 'b', 'e', 'c'},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsString());
        EXPECT_EQ(6, String::Cast(*value)->Length());
        EXPECT_EQ(kQuebecString, Utf8Value(value));
      });

  DecodeTestFutureVersions({0xFF, 0x09, 0x53, 0x04, 0xF0, 0x9F, 0x91, 0x8A},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsString());
                             EXPECT_EQ(2, String::Cast(*value)->Length());
                             EXPECT_EQ(kEmojiString, Utf8Value(value));
                           });

  // And from Latin-1 (for the ones that fit).
  DecodeTestFutureVersions({0xFF, 0x0A, 0x22, 0x00}, [](Local<Value> value) {
    ASSERT_TRUE(value->IsString());
    EXPECT_EQ(0, String::Cast(*value)->Length());
  });

  DecodeTestFutureVersions({0xFF, 0x0A, 0x22, 0x05, 'H', 'e', 'l', 'l', 'o'},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsString());
                             EXPECT_EQ(5, String::Cast(*value)->Length());
                             EXPECT_EQ(kHelloString, Utf8Value(value));
                           });

  DecodeTestFutureVersions(
      {0xFF, 0x0A, 0x22, 0x06, 'Q', 'u', 0xE9, 'b', 'e', 'c'},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsString());
        EXPECT_EQ(6, String::Cast(*value)->Length());
        EXPECT_EQ(kQuebecString, Utf8Value(value));
      });

// And from two-byte strings (endianness dependent).
#if defined(V8_TARGET_LITTLE_ENDIAN)
  DecodeTestFutureVersions({0xFF, 0x09, 0x63, 0x00}, [](Local<Value> value) {
    ASSERT_TRUE(value->IsString());
    EXPECT_EQ(0, String::Cast(*value)->Length());
  });

  DecodeTestFutureVersions({0xFF, 0x09, 0x63, 0x0A, 'H', '\0', 'e', '\0', 'l',
                            '\0', 'l', '\0', 'o', '\0'},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsString());
                             EXPECT_EQ(5, String::Cast(*value)->Length());
                             EXPECT_EQ(kHelloString, Utf8Value(value));
                           });

  DecodeTestFutureVersions({0xFF, 0x09, 0x63, 0x0C, 'Q', '\0', 'u', '\0', 0xE9,
                            '\0', 'b', '\0', 'e', '\0', 'c', '\0'},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsString());
                             EXPECT_EQ(6, String::Cast(*value)->Length());
                             EXPECT_EQ(kQuebecString, Utf8Value(value));
                           });

  DecodeTestFutureVersions({0xFF, 0x09, 0x63, 0x04, 0x3D, 0xD8, 0x4A, 0xDC},
                           [this](Local<Value> value) {
                             ASSERT_TRUE(value->IsString());
                             EXPECT_EQ(2, String::Cast(*value)->Length());
                             EXPECT_EQ(kEmojiString, Utf8Value(value));
                           });
#endif
  // TODO(jbroman): The same for big-endian systems.
}

TEST_F(ValueSerializerTest, DecodeInvalidString) {
  // UTF-8 string with too few bytes available.
  InvalidDecodeTest({0xFF, 0x09, 0x53, 0x10, 'v', '8'});
  // One-byte string with too few bytes available.
  InvalidDecodeTest({0xFF, 0x0A, 0x22, 0x10, 'v', '8'});
#if defined(V8_TARGET_LITTLE_ENDIAN)
  // Two-byte string with too few bytes available.
  InvalidDecodeTest({0xFF, 0x09, 0x63, 0x10, 'v', '\0', '8', '\0'});
  // Two-byte string with an odd byte length.
  InvalidDecodeTest({0xFF, 0x09, 0x63, 0x03, 'v', '\0', '8'});
#endif
  // TODO(jbroman): The same for big-endian systems.
}

TEST_F(ValueSerializerTest, EncodeTwoByteStringUsesPadding) {
  // As long as the output has a version that Blink expects to be able to read,
  // we must respect its alignment requirements. It requires that two-byte
  // characters be aligned.
  // We need a string whose length will take two bytes to encode, so that
  // a padding byte is needed to keep the characters aligned. The string
  // must also have a two-byte character, so that it gets the two-byte
  // encoding.
  std::string string(200, ' ');
  string += kEmojiString;
  const std::vector<uint8_t> data = EncodeTest(StringFromUtf8(string.c_str()));
  // This is a sufficient but not necessary condition. This test assumes
  // that the wire format version is one byte long, but is flexible to
  // what that value may be.
  const uint8_t expected_prefix[] = {0x00, 0x63, 0x94, 0x03};
  ASSERT_GT(data.size(), sizeof(expected_prefix) + 2);
  EXPECT_EQ(0xFF, data[0]);
  EXPECT_GE(data[1], 0x09);
  EXPECT_LE(data[1], 0x7F);
  EXPECT_TRUE(std::equal(std::begin(expected_prefix), std::end(expected_prefix),
                         data.begin() + 2));
}

TEST_F(ValueSerializerTest, RoundTripDictionaryObject) {
  // Empty object.
  Local<Value> value = RoundTripTest("({})");
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("Object.getPrototypeOf(result) === Object.prototype");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 0");

  // String key.
  value = RoundTripTest("({ a: 42 })");
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("result.hasOwnProperty('a')");
  ExpectScriptTrue("result.a === 42");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 1");

  // Integer key (treated as a string, but may be encoded differently).
  value = RoundTripTest("({ 42: 'a' })");
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("result.hasOwnProperty('42')");
  ExpectScriptTrue("result[42] === 'a'");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 1");

  // Key order must be preserved.
  value = RoundTripTest("({ x: 1, y: 2, a: 3 })");
  ExpectScriptTrue("Object.getOwnPropertyNames(result).toString() === 'x,y,a'");

  // A harder case of enumeration order.
  // Indexes first, in order (but not 2^32 - 1, which is not an index), then the
  // remaining (string) keys, in the order they were defined.
  value = RoundTripTest("({ a: 2, 0xFFFFFFFF: 1, 0xFFFFFFFE: 3, 1: 0 })");
  ExpectScriptTrue(
      "Object.getOwnPropertyNames(result).toString() === "
      "'1,4294967294,a,4294967295'");
  ExpectScriptTrue("result.a === 2");
  ExpectScriptTrue("result[0xFFFFFFFF] === 1");
  ExpectScriptTrue("result[0xFFFFFFFE] === 3");
  ExpectScriptTrue("result[1] === 0");

  // This detects a fairly subtle case: the object itself must be in the map
  // before its properties are deserialized, so that references to it can be
  // resolved.
  value = RoundTripTest("var y = {}; y.self = y; y;");
  ASSERT_TRUE(value->IsObject());
  ExpectScriptTrue("result === result.self");
}

TEST_F(ValueSerializerTest, DecodeDictionaryObject) {
  // Empty object.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x7B, 0x00, 0x00},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsObject());
        ExpectScriptTrue("Object.getPrototypeOf(result) === Object.prototype");
        ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 0");
      });

  // String key.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01, 0x61, 0x3F, 0x01,
       0x49, 0x54, 0x7B, 0x01},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsObject());
        ExpectScriptTrue("result.hasOwnProperty('a')");
        ExpectScriptTrue("result.a === 42");
        ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 1");
      });

  // Integer key (treated as a string, but may be encoded differently).
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x49, 0x54, 0x3F, 0x01, 0x53,
       0x01, 0x61, 0x7B, 0x01},
      [this](Local<Value> value) {
        ASSERT_TRUE(value->IsObject());
        ExpectScriptTrue("result.hasOwnProperty('42')");
        ExpectScriptTrue("result[42] === 'a'");
        ExpectScriptTrue("Object.getOwnPropertyNames(result).length === 1");
      });

  // Key order must be preserved.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x53, 0x01, 0x78, 0x3F, 0x01,
       0x49, 0x02, 0x3F, 0x01, 0x53, 0x01, 0x79, 0x3F, 0x01, 0x49, 0x04, 0x3F,
       0x01, 0x53, 0x01, 0x61, 0x3F, 0x01, 0x49, 0x06, 0x7B, 0x03},
      [this](Local<Value> value) {
        ExpectScriptTrue(
            "Object.getOwnPropertyNames(result).toString() === 'x,y,a'");
      });

  // A harder case of enumeration order.
  DecodeTestFutureVersions(
      {0xFF, 0x09, 0x3F, 0x00, 0x6F, 0x3F, 0x01, 0x49, 0x02, 0x3F, 0x01,
       0x49, 0x00, 0x3F, 0x01, 0x55, 0xFE, 0xFF, 0xFF, 0xFF, 0x0F, 0x3F,
       0x01, 0x49, 0x06, 0x3F, 0x01, 0x53, 0x01, 0x61, 0x3F, 0x01, 0x49,
       0x04, 0x3F, 0x01, 0x53, 0x0A, 0x34, 0x32, 0x39, 0x34, 0x39, 0x36,
       0x37, 0x32, 0x39, 0x35, 0x3F, 0x01, 0x49, 0x02, 0x7B, 0x04},
```