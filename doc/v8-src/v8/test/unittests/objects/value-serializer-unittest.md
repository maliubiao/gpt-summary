Response: The user wants a summary of the provided C++ source code file. The file seems to be a unit test for the `ValueSerializer` and `ValueDeserializer` classes in V8.

Here's a breakdown of my thought process to arrive at the summary:

1. **Identify the core subject:** The filename `v8/test/unittests/objects/value-serializer-unittest.cc` immediately points to unit tests for `ValueSerializer`. The inclusion of `<src/objects/value-serializer.h>` confirms this.

2. **Recognize the testing framework:** The inclusion of `<testing/gtest/include/gtest/gtest.h>` indicates the use of Google Test for writing the unit tests.

3. **Analyze the included headers:** The headers provide clues about the functionalities being tested:
    * `include/v8*.h`:  These are V8 public API headers, hinting at the JavaScript-related aspects. Specifically,  `v8-context.h`, `v8-date.h`, `v8-function.h`, `v8-json.h`, `v8-value-serializer*.h`, and `v8-wasm.h` are relevant.
    * `src/*`: These are internal V8 headers, providing details about the implementation. `objects/*.h` confirms the focus on V8 objects.
    * Standard C++ headers like `<algorithm>`, `<string>`, and build-related headers like `<src/base/build_config.h>` are also present.

4. **Examine the `ValueSerializerTest` class:** This is the main test fixture. Key observations:
    * It inherits from `TestWithIsolate`, a common V8 testing base class.
    * It sets up `serialization_context_` and `deserialization_context_`, suggesting the testing of serialization and deserialization processes.
    * The creation of `ExampleHostObject` using `FunctionTemplate` indicates testing the serialization of host objects.
    * The `RoundTripTest` methods are crucial, implying that the tests involve serializing a value and then deserializing it, checking for equivalence.
    * `EncodeTest` and `DecodeTest` methods isolate the serialization and deserialization steps.
    * The `InvalidEncodeTest` and `InvalidDecodeTest` methods are used to check error handling.
    * The presence of `DecodeTestFutureVersions` and `DecodeTestUpToVersion` suggests testing compatibility across different serialization versions.

5. **Look at the individual `TEST_F` functions:**  These provide concrete examples of what's being tested. Scanning through the names and the basic structure of the tests reveals various scenarios:
    * Testing different JavaScript data types (oddballs like `undefined`, `null`, booleans; numbers, strings, BigInts, arrays, objects, dates, regexps, value objects).
    * Testing edge cases like stack overflow during encoding/decoding.
    * Testing handling of invalid data during decoding.
    * Testing object property enumeration order and handling of getters/setters.
    * Testing sparse arrays and arrays with non-enumerable elements.
    * Testing host objects and their interaction with serialization.
    * Testing WASM (indicated by `#if V8_ENABLE_WEBASSEMBLY`).

6. **Connect to JavaScript functionality:** The tests directly manipulate V8's JavaScript representation. The `RoundTripTest` effectively simulates JavaScript's "structured clone" algorithm. The tests use string literals to represent JavaScript code, which are then evaluated using `EvaluateScriptForInput`. The comparisons often involve checking the properties and behavior of the deserialized objects using JavaScript assertions like `ExpectScriptTrue`.

7. **Formulate the summary:** Based on the above analysis, I can create a concise summary highlighting the main purpose of the file and its relation to JavaScript.

8. **Provide a JavaScript example:** To illustrate the connection to JavaScript, I need a simple example that demonstrates the core functionality being tested. Serializing and deserializing a JavaScript object using `structuredClone` (or the older `postMessage` equivalent) is the most direct way to demonstrate this.

By following these steps, I could confidently generate the summary and the JavaScript example.
这个C++源代码文件是V8 JavaScript引擎的一部分，它包含了针对 **ValueSerializer** 和 **ValueDeserializer** 类的单元测试。这两个类负责将JavaScript值序列化为二进制格式，以及将二进制数据反序列化为JavaScript值。

**具体功能归纳如下：**

* **测试 ValueSerializer 的序列化功能：**  验证 `ValueSerializer` 能否正确地将各种JavaScript数据类型（如 `undefined`, `null`, 布尔值, 数字, 字符串, BigInt, 数组, 对象, Date, RegExp, 以及特定的对象封装类型如 `Boolean`, `Number`, `String`）转换为二进制表示。
* **测试 ValueDeserializer 的反序列化功能：** 验证 `ValueDeserializer` 能否正确地将 `ValueSerializer` 生成的二进制数据还原为相应的JavaScript值。
* **测试序列化和反序列化的往返一致性：**  通过 `RoundTripTest` 系列函数，测试将一个JavaScript值序列化后再反序列化，得到的结果是否与原始值相等。这确保了序列化和反序列化过程的正确性。
* **测试各种边界情况和错误处理：**  例如，测试编码和解码过程中出现的栈溢出情况，以及解码无效的二进制数据时是否能正确抛出错误。
* **测试不同版本的序列化格式的兼容性：**  通过 `DecodeTestFutureVersions` 和 `DecodeTestUpToVersion` 等函数，测试旧版本的序列化数据能否被新版本的反序列化器正确解析，以及不同版本间的兼容性。
* **测试 Host Object 的序列化和反序列化：** 代码中创建了一个名为 `ExampleHostObject` 的宿主对象类型，并测试了它的序列化和反序列化过程，这涉及到 C++ 代码和 JavaScript 代码之间的交互。
* **测试特定细节：** 例如，测试对象属性的枚举顺序是否被保留，以及处理带有 getter 和 setter 的属性时的行为是否正确。

**与 JavaScript 功能的关系及 JavaScript 示例:**

`ValueSerializer` 和 `ValueDeserializer` 的功能直接对应于 JavaScript 中的 **结构化克隆算法 (Structured Clone Algorithm)**。 这个算法允许在不同的执行上下文 (例如，不同的窗口、Web Workers 或 Service Workers) 之间安全地复制复杂的 JavaScript 对象。

虽然 JavaScript 本身没有直接暴露 `ValueSerializer` 和 `ValueDeserializer` 的 API，但结构化克隆算法在幕后使用了类似的机制。

**JavaScript 示例:**

```javascript
// 假设我们想在两个不同的上下文中传递一个复杂对象

// 原始对象
const originalObject = {
  name: "Example",
  value: 42,
  nested: {
    data: [1, 2, 3],
    date: new Date()
  }
};

// 使用结构化克隆进行复制 (例如，通过 postMessage)
const clonedObject = structuredClone(originalObject);

// 或者在旧版本的浏览器中，可以使用 postMessage (虽然更复杂)
// 模拟序列化和反序列化
// const serializedData = JSON.stringify(originalObject); // JSON 无法处理 Date 对象和循环引用
// const clonedObject = JSON.parse(serializedData);

// 比较原始对象和克隆对象
console.log(originalObject);
console.log(clonedObject);
console.log(originalObject !== clonedObject); // 克隆对象是一个新的对象
console.log(originalObject.name === clonedObject.name);
console.log(originalObject.nested.date.getTime() === clonedObject.nested.date.getTime()); // Date 对象的值相同
```

在这个例子中，`structuredClone` 函数在内部执行了类似于 `ValueSerializer` 和 `ValueDeserializer` 的操作，将 `originalObject` 复制到了一个新的对象 `clonedObject` 中，并且保留了其结构和数据。

**总结来说，这个 C++ 单元测试文件验证了 V8 引擎中用于实现 JavaScript 结构化克隆算法的核心组件的正确性和可靠性。**

Prompt: ```这是目录为v8/test/unittests/objects/value-serializer-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
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
"""

```