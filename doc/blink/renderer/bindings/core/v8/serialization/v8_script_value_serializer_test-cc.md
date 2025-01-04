Response:
My thought process to analyze the provided code snippet and fulfill the request went through these stages:

1. **Understand the Goal:** The request asks for a summary of the functionality of `v8_script_value_serializer_test.cc`, focusing on its relationship with web technologies, logical reasoning (with examples), common user/programming errors, and debugging context. It specifically mentions that this is the first of four parts and asks for a summarization of this part.

2. **Identify Key Components:**  I scanned the `#include` directives and the core logic of the tests to identify the main areas of functionality. The presence of `<gtest/gtest.h>` immediately signals that this is a unit test file. The includes related to serialization (`V8ScriptValueSerializer`, `V8ScriptValueDeserializer`, `SerializedScriptValue`) are crucial. The numerous includes for DOM objects (`DOMPoint`, `DOMRect`, `DOMMatrix`, `Blob`, `File`, etc.) indicate that serialization of these web platform types is being tested.

3. **Determine Core Functionality:**  Based on the key components, the primary function of this file is to test the serialization and deserialization of JavaScript values and specific web platform objects within the Blink rendering engine. This involves converting these objects to a byte stream and back again, ensuring the process is lossless and handles errors correctly.

4. **Analyze Relationships with Web Technologies:** I considered how the tested objects relate to JavaScript, HTML, and CSS.
    * **JavaScript:** The tests directly manipulate JavaScript values using V8's API and the `Eval` function. The serialization/deserialization process is fundamental to JavaScript's structured clone algorithm used in `postMessage`, `localStorage`, `IndexedDB`, etc.
    * **HTML:** Objects like `Blob`, `File`, `ImageData`, and the geometry types (`DOMPoint`, `DOMRect`, `DOMMatrix`) are frequently used in conjunction with HTML elements and APIs (e.g., `<canvas>`, file inputs, drag-and-drop).
    * **CSS:** The geometry types (`DOMPoint`, `DOMRect`, `DOMMatrix`) are used in CSS transforms and other visual properties. While not directly testing CSS manipulation, the ability to serialize these values is relevant in scenarios where state needs to be preserved or transferred.

5. **Look for Logical Reasoning and Examples:** The test cases themselves represent logical reasoning. Each `TEST` macro defines a specific scenario with assumptions (input values) and expected outcomes (assertions). I picked a few representative examples:
    * `RoundTripJSONLikeValue`: Tests basic object serialization. Input: a simple JavaScript object. Output: a deserialized object equal to the original.
    * `ThrowsDataCloneError`: Tests error handling. Input: a non-serializable symbol. Output: a `DataCloneError`.
    * `DetachHappensAfterSerialization`: Tests the order of operations. Input: an object that throws an error during serialization and an array buffer to transfer. Output: the array buffer is not detached.

6. **Consider Common User/Programming Errors:** I thought about what developers might do incorrectly when dealing with serialization:
    * Trying to serialize non-serializable objects (like symbols).
    * Expecting exceptions on deserialization failures instead of `null`.
    * Misunderstanding the concept of transferring ownership (e.g., expecting a transferred `ArrayBuffer` to remain usable in the original context).

7. **Trace User Operations to Reach the Code:** I constructed a plausible sequence of user actions that would trigger the serialization/deserialization mechanisms being tested:
    * A user action (e.g., clicking a button) triggers a JavaScript function.
    * This function uses `postMessage` to send data to a web worker or another window.
    * The browser's implementation of `postMessage` internally uses the structured clone algorithm, which relies on the serializer and deserializer being tested.

8. **Focus on Summarization for Part 1:**  Finally, I synthesized the identified functionalities and relationships into a concise summary, keeping in mind that this is only the first part of a larger analysis. The key was to highlight the testing nature of the file and the core functionality of verifying the serialization and deserialization of JavaScript values and web platform objects.

**(Self-Correction/Refinement during the process):** Initially, I might have focused too much on the individual DOM object tests. I then realized the importance of emphasizing the overarching goal of testing the serializer and deserializer, and how these components fit into the broader context of web platform features like `postMessage`. I also ensured to specifically address the "Part 1" constraint by providing a summary rather than an exhaustive explanation.
这是对Chromium Blink引擎中 `blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer_test.cc` 文件功能的归纳，该文件是测试套件的一部分。

**该文件的主要功能：**

这个文件包含了一系列的单元测试，用于验证 `V8ScriptValueSerializer` 和 `V8ScriptValueDeserializer` 类的正确性。这两个类负责将JavaScript值序列化（转换为字节流）和反序列化（从字节流转换回JavaScript值）。  这对于在不同的执行上下文（例如，Web Workers、跨文档消息传递、持久化存储）之间传递或存储JavaScript数据至关重要。

**与 Javascript, HTML, CSS 的关系：**

这个文件直接关系到 **JavaScript** 的功能，特别是当需要在不同环境或生命周期之间传递复杂数据结构时。

* **JavaScript 序列化 (Structured Clone Algorithm 的一部分):**  浏览器内部使用序列化机制来实现 `postMessage`、`localStorage`、`sessionStorage`、`IndexedDB` 等功能。这个测试文件验证了 Blink 引擎中负责此功能的代码的正确性。
    * **举例说明 (postMessage):**  假设一个网页（主线程）想向一个 Web Worker 发送一个包含复杂对象的 JavaScript 数据：
        ```javascript
        const worker = new Worker('worker.js');
        const dataToSend = {
          message: 'Hello from main thread!',
          details: {
            nestedArray: [1, 2, { key: 'value' }],
            timestamp: new Date()
          }
        };
        worker.postMessage(dataToSend);
        ```
        在幕后，`V8ScriptValueSerializer` 会将 `dataToSend` 对象序列化为字节流，以便跨线程传递。`V8ScriptValueDeserializer` 在 Web Worker 线程中会将这个字节流还原为 JavaScript 对象。

* **HTML 相关对象序列化:**  该文件测试了许多与 HTML 相关的 JavaScript 对象的序列化和反序列化，例如：
    * `Blob` 和 `File`:  用于处理文件上传、下载等场景。序列化 `Blob` 对象允许在不同上下文间传递文件数据。
    * `ImageData`:  用于操作 canvas 元素的像素数据。序列化 `ImageData` 可以在 Web Worker 中处理图像数据后将其返回给主线程。
    * `DOMPoint`, `DOMRect`, `DOMMatrix`:  用于表示几何图形信息，例如在 CSS 变换或 Canvas 绘图中。序列化这些对象可以保存或传递图形状态。

* **CSS 间接关系:** 虽然这个文件不直接测试 CSS，但它测试了 `DOMMatrix` 等与 CSS 变换相关的对象的序列化。这意味着，如果一个网页使用 JavaScript 来操作元素的 CSS 变换矩阵，并且需要将这个矩阵传递给 Web Worker 或保存起来，那么这个测试文件所验证的序列化功能就会被用到。

**逻辑推理的假设输入与输出：**

该文件中的每个 `TEST` 都是一个逻辑推理的例子。

**假设输入：** 一个 JavaScript 对象，例如 `({ a: 1, b: [2, 3] })`。
**预期输出：**  经过序列化和反序列化后，得到一个新的 JavaScript 对象，其结构和值与原始对象完全相同 (`{ a: 1, b: [2, 3] }`)，但不是同一个对象实例。

**假设输入 (错误情况):**  一个包含不可序列化值的 JavaScript 对象，例如包含 `Symbol` 类型的对象。
**预期输出：**  序列化过程会抛出一个 `DataCloneError` 类型的异常。

**涉及用户或编程常见的使用错误：**

* **尝试序列化不可序列化的值:**  JavaScript 中有一些值是不能被结构化克隆算法序列化的，例如函数、`Symbol`、包含循环引用的对象等。如果尝试序列化这些值，`V8ScriptValueSerializer` 会抛出 `DataCloneError`。
    * **举例:**
        ```javascript
        const obj = {
          name: 'My Object',
          method: function() { console.log('Hello'); } // 函数不可序列化
        };
        const worker = new Worker('worker.js');
        try {
          worker.postMessage(obj); // 可能抛出 DataCloneError
        } catch (e) {
          console.error('Failed to send message:', e);
        }
        ```
* **假设反序列化一定会成功:**  虽然 `V8ScriptValueDeserializer` 在遇到无效数据时通常返回 `null` 而不是抛出异常（如测试用例 `DeserializationErrorReturnsNull` 所示），但在某些情况下，数据损坏或版本不匹配可能会导致反序列化失败。开发者需要检查反序列化的结果是否为 `null` 或进行其他错误处理。
* **忘记处理 `postMessage` 的异步性:**  在使用 `postMessage` 进行跨上下文通信时，序列化和反序列化是异步发生的。开发者需要使用事件监听器来接收来自其他上下文的消息，并确保在消息到达后处理数据。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在网页上执行某些操作:** 例如，点击一个按钮，提交一个表单，或者页面加载完成。
2. **JavaScript 代码被触发:**  这些用户操作通常会触发 JavaScript 代码的执行。
3. **JavaScript 代码尝试跨上下文传递数据:**  例如，代码可能使用 `postMessage` 将数据发送到 Web Worker，或者将数据存储到 `localStorage` 中。
4. **浏览器调用序列化/反序列化 API:**  当 JavaScript 代码执行到需要跨上下文传递或存储数据的操作时，浏览器会调用 Blink 引擎中相应的序列化或反序列化 API（即 `V8ScriptValueSerializer` 和 `V8ScriptValueDeserializer`）。
5. **如果出现问题，开发者可能会断点调试到 `v8_script_value_serializer_test.cc` 中的相关测试用例:**
    * 如果在序列化过程中出现 `DataCloneError`，开发者可能会查看 `ThrowsDataCloneError` 这样的测试用例，以理解哪些类型的对象不能被序列化。
    * 如果在反序列化过程中出现问题，开发者可能会查看 `DeserializationErrorReturnsNull` 这样的测试用例，以了解反序列化失败时的行为。
    * 如果涉及到特定的 DOM 对象（例如 `DOMPoint`）的序列化问题，开发者可能会查看 `RoundTripDOMPoint` 或 `DecodeDOMPoint` 这样的测试用例。

**第1部分功能归纳：**

这个代码文件的第一部分主要关注以下功能：

* **基础的序列化和反序列化测试:** 验证了对于简单的 JavaScript 对象，序列化和反序列化能够保持数据的完整性。
* **错误处理测试 (序列化):**  测试了在尝试序列化不可序列化的值时，是否会抛出正确的 `DataCloneError` 异常。
* **异常冒泡测试:** 验证了在序列化过程中，如果对象的 getter 抛出异常，这个异常能够正确地被捕获和传递。
* **错误处理测试 (反序列化):**  测试了在反序列化无效数据时，是否会返回 `null` 而不是抛出异常。
* **传输操作顺序测试:**  验证了在序列化过程中发生错误时，传输操作（例如 `ArrayBuffer` 的转移）是否会被取消。
* **特定 DOM 对象的序列化和反序列化测试:** 针对 `DOMPoint`, `DOMPointReadOnly`, `DOMRect`, `DOMRectReadOnly`, `DOMQuad`, `DOMMatrix` 等几何图形相关的 DOM 对象进行了序列化和反序列化的正确性测试，包括双向转换 (RoundTrip) 和从特定字节流解码 (Decode)。

总而言之，这部分测试用例涵盖了 `V8ScriptValueSerializer` 和 `V8ScriptValueDeserializer` 的基本功能和错误处理，并开始测试一些重要的 DOM 对象的序列化能力。 这为确保 Blink 引擎能够正确地在不同 JavaScript 执行上下文之间传递复杂的数据结构奠定了基础。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.h"

#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "gin/wrappable.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/trailer_reader.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/unpacked_serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_deserializer.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_quad.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fenced_frame_config.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_message_port.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_handle.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_offscreen_canvas.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_string_resource.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_float32array_uint16array_uint8clampedarray.h"
#include "third_party/blink/renderer/core/context_features/context_feature_settings.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_point.h"
#include "third_party/blink/renderer/core/geometry/dom_point_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_quad.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_config.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/mojo/mojo_handle.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/transform_stream.h"
#include "third_party/blink/renderer/core/testing/file_backed_blob_factory_test_helper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkSurface.h"

namespace blink {
namespace {

v8::Local<v8::Value> RoundTrip(v8::Local<v8::Value> value,
                               V8TestingScope& scope,
                               ExceptionState& exception_state,
                               Transferables* transferables = nullptr,
                               WebBlobInfoArray* blob_info = nullptr) {
  ScriptState* script_state = scope.GetScriptState();

  // Extract message ports and disentangle them.
  Vector<MessagePortChannel> channels;
  if (transferables) {
    channels = MessagePort::DisentanglePorts(scope.GetExecutionContext(),
                                             transferables->message_ports,
                                             exception_state);
    if (exception_state.HadException())
      return v8::Local<v8::Value>();
  }

  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = transferables;
  serialize_options.blob_info = blob_info;
  V8ScriptValueSerializer serializer(script_state, serialize_options);
  scoped_refptr<SerializedScriptValue> serialized_script_value =
      serializer.Serialize(value, exception_state);
  DCHECK_EQ(!serialized_script_value, exception_state.HadException());
  if (!serialized_script_value)
    return v8::Local<v8::Value>();
  // If there are message ports, make new ones and entangle them.
  MessagePortArray* transferred_message_ports = MessagePort::EntanglePorts(
      *scope.GetExecutionContext(), std::move(channels));

  UnpackedSerializedScriptValue* unpacked =
      SerializedScriptValue::Unpack(std::move(serialized_script_value));
  V8ScriptValueDeserializer::Options deserialize_options;
  deserialize_options.message_ports = transferred_message_ports;
  deserialize_options.blob_info = blob_info;
  V8ScriptValueDeserializer deserializer(script_state, unpacked,
                                         deserialize_options);
  return deserializer.Deserialize();
}

v8::Local<v8::Value> Eval(const String& source, V8TestingScope& scope) {
  return ClassicScript::CreateUnspecifiedScript(source)
      ->RunScriptAndReturnValue(&scope.GetWindow())
      .GetSuccessValueOrEmpty();
}

String ToJSON(v8::Local<v8::Object> object, const V8TestingScope& scope) {
  return ToBlinkString<String>(
      scope.GetIsolate(),
      v8::JSON::Stringify(scope.GetContext(), object).ToLocalChecked(),
      kDoNotExternalize);
}
}  // namespace

scoped_refptr<SerializedScriptValue> SerializedValue(
    const Vector<uint8_t>& bytes) {
  return SerializedScriptValue::Create(bytes);
}

// Checks for a DOM exception, including a rethrown one.
testing::AssertionResult HadDOMExceptionInCoreTest(const StringView& name,
                                                   ScriptState* script_state,
                                                   v8::TryCatch& try_catch) {
  if (!try_catch.HasCaught()) {
    return testing::AssertionFailure() << "no exception thrown";
  }
  DOMException* dom_exception = V8DOMException::ToWrappable(
      script_state->GetIsolate(), try_catch.Exception());
  if (!dom_exception)
    return testing::AssertionFailure()
           << "exception thrown was not a DOMException";
  if (dom_exception->name() != name)
    return testing::AssertionFailure() << "was " << dom_exception->name();
  return testing::AssertionSuccess();
}

TEST(V8ScriptValueSerializerTest, RoundTripJSONLikeValue) {
  test::TaskEnvironment task_environment;
  // Ensure that simple JavaScript objects work.
  // There are more exhaustive tests of JavaScript objects in V8.
  V8TestingScope scope;
  v8::Local<v8::Value> object = Eval("({ foo: [1, 2, 3], bar: 'baz' })", scope);
  DCHECK(object->IsObject());
  v8::Local<v8::Value> result =
      RoundTrip(object, scope, scope.GetExceptionState());
  ASSERT_TRUE(result->IsObject());
  EXPECT_NE(object, result);
  EXPECT_EQ(ToJSON(object.As<v8::Object>(), scope),
            ToJSON(result.As<v8::Object>(), scope));
}

TEST(V8ScriptValueSerializerTest, ThrowsDataCloneError) {
  test::TaskEnvironment task_environment;
  // Ensure that a proper DataCloneError DOMException is thrown when issues
  // are encountered in V8 (for example, cloning a symbol). It should be an
  // instance of DOMException.
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Value> symbol = Eval("Symbol()", scope);
  DCHECK(symbol->IsSymbol());
  ASSERT_FALSE(
      V8ScriptValueSerializer(script_state)
          .Serialize(symbol, PassThroughException(scope.GetIsolate())));
  ASSERT_TRUE(
      HadDOMExceptionInCoreTest("DataCloneError", script_state, try_catch));
  DOMException* dom_exception =
      V8DOMException::ToWrappable(scope.GetIsolate(), try_catch.Exception());
  EXPECT_TRUE(dom_exception);
}

TEST(V8ScriptValueSerializerTest, RethrowsScriptError) {
  test::TaskEnvironment task_environment;
  // Ensure that other exceptions, like those thrown by script, are properly
  // rethrown.
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  v8::TryCatch try_catch(scope.GetIsolate());
  v8::Local<v8::Value> exception = Eval("myException=new Error()", scope);
  v8::Local<v8::Value> object =
      Eval("({ get a() { throw myException; }})", scope);
  DCHECK(object->IsObject());
  ASSERT_FALSE(
      V8ScriptValueSerializer(script_state)
          .Serialize(object, PassThroughException(scope.GetIsolate())));
  ASSERT_TRUE(try_catch.HasCaught());
  EXPECT_EQ(exception, try_catch.Exception());
}

TEST(V8ScriptValueSerializerTest, DeserializationErrorReturnsNull) {
  test::TaskEnvironment task_environment;
  // If there's a problem during deserialization, it results in null, but no
  // exception.
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> invalid =
      SerializedScriptValue::Create("invalid data");
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, invalid).Deserialize();
  EXPECT_TRUE(result->IsNull());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

TEST(V8ScriptValueSerializerTest, DetachHappensAfterSerialization) {
  test::TaskEnvironment task_environment;
  // This object will throw an exception before the [[Transfer]] step.
  // As a result, the ArrayBuffer will not be transferred.
  V8TestingScope scope;
  v8::TryCatch try_catch(scope.GetIsolate());

  DOMArrayBuffer* array_buffer = DOMArrayBuffer::Create(1, 1);
  ASSERT_FALSE(array_buffer->IsDetached());
  v8::Local<v8::Value> object = Eval("({ get a() { throw 'party'; }})", scope);
  Transferables transferables;
  transferables.array_buffers.push_back(array_buffer);

  RoundTrip(object, scope, PassThroughException(scope.GetIsolate()),
            &transferables);
  ASSERT_TRUE(try_catch.HasCaught());
  EXPECT_FALSE(HadDOMExceptionInCoreTest("DataCloneError",
                                         scope.GetScriptState(), try_catch));
  EXPECT_FALSE(array_buffer->IsDetached());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMPoint) {
  test::TaskEnvironment task_environment;
  // DOMPoint objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMPoint* point = DOMPoint::Create(1, 2, 3, 4);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMPoint>::ToV8(scope.GetScriptState(), point);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  DOMPoint* new_point = V8DOMPoint::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_point, nullptr);
  EXPECT_NE(point, new_point);
  EXPECT_EQ(point->x(), new_point->x());
  EXPECT_EQ(point->y(), new_point->y());
  EXPECT_EQ(point->z(), new_point->z());
  EXPECT_EQ(point->w(), new_point->w());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMPoint) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x11, 0xff, 0x0d, 0x5c, 'Q',  0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMPoint* point = V8DOMPoint::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(1, point->x());
  EXPECT_EQ(2, point->y());
  EXPECT_EQ(3, point->z());
  EXPECT_EQ(4, point->w());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMPointReadOnly) {
  test::TaskEnvironment task_environment;
  // DOMPointReadOnly objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMPointReadOnly* point = DOMPointReadOnly::Create(1, 2, 3, 4);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMPointReadOnly>::ToV8(scope.GetScriptState(), point);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  EXPECT_FALSE(V8DOMPoint::HasInstance(scope.GetIsolate(), result));
  DOMPointReadOnly* new_point =
      V8DOMPointReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_point, nullptr);
  EXPECT_NE(point, new_point);
  EXPECT_EQ(point->x(), new_point->x());
  EXPECT_EQ(point->y(), new_point->y());
  EXPECT_EQ(point->z(), new_point->z());
  EXPECT_EQ(point->w(), new_point->w());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMPointReadOnly) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x11, 0xff, 0x0d, 0x5c, 'W',  0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMPointReadOnly* point =
      V8DOMPointReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(point, nullptr);
  EXPECT_EQ(1, point->x());
  EXPECT_EQ(2, point->y());
  EXPECT_EQ(3, point->z());
  EXPECT_EQ(4, point->w());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMRect) {
  test::TaskEnvironment task_environment;
  // DOMRect objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMRect* rect = DOMRect::Create(1, 2, 3, 4);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMRect>::ToV8(scope.GetScriptState(), rect);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  DOMRect* new_rect = V8DOMRect::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_rect, nullptr);
  EXPECT_NE(rect, new_rect);
  EXPECT_EQ(rect->x(), new_rect->x());
  EXPECT_EQ(rect->y(), new_rect->y());
  EXPECT_EQ(rect->width(), new_rect->width());
  EXPECT_EQ(rect->height(), new_rect->height());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMRect) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x11, 0xff, 0x0d, 0x5c, 'E',  0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMRect* rect = V8DOMRect::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(rect, nullptr);
  EXPECT_EQ(1, rect->x());
  EXPECT_EQ(2, rect->y());
  EXPECT_EQ(3, rect->width());
  EXPECT_EQ(4, rect->height());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMRectReadOnly) {
  test::TaskEnvironment task_environment;
  // DOMRectReadOnly objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMRectReadOnly* rect = DOMRectReadOnly::Create(1, 2, 3, 4);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMRectReadOnly>::ToV8(scope.GetScriptState(), rect);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  EXPECT_FALSE(V8DOMRect::HasInstance(scope.GetIsolate(), result));
  DOMRectReadOnly* new_rect =
      V8DOMRectReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_rect, nullptr);
  EXPECT_NE(rect, new_rect);
  EXPECT_EQ(rect->x(), new_rect->x());
  EXPECT_EQ(rect->y(), new_rect->y());
  EXPECT_EQ(rect->width(), new_rect->width());
  EXPECT_EQ(rect->height(), new_rect->height());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMRectReadOnly) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x11, 0xff, 0x0d, 0x5c, 'R',  0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMRectReadOnly* rect =
      V8DOMRectReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(rect, nullptr);
  EXPECT_EQ(1, rect->x());
  EXPECT_EQ(2, rect->y());
  EXPECT_EQ(3, rect->width());
  EXPECT_EQ(4, rect->height());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMQuad) {
  test::TaskEnvironment task_environment;
  // DOMQuad objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMPointInit* pi1 = DOMPointInit::Create();
  pi1->setX(1);
  pi1->setY(5);
  pi1->setZ(9);
  pi1->setW(13);
  DOMPointInit* pi2 = DOMPointInit::Create();
  pi2->setX(2);
  pi2->setY(6);
  pi2->setZ(10);
  pi2->setW(14);
  DOMPointInit* pi3 = DOMPointInit::Create();
  pi3->setX(3);
  pi3->setY(7);
  pi3->setZ(11);
  pi3->setW(15);
  DOMPointInit* pi4 = DOMPointInit::Create();
  pi4->setX(4);
  pi4->setY(8);
  pi4->setZ(12);
  pi4->setW(16);
  DOMQuad* quad = DOMQuad::Create(pi1, pi2, pi3, pi4);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMQuad>::ToV8(scope.GetScriptState(), quad);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  DOMQuad* new_quad = V8DOMQuad::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_quad, nullptr);
  EXPECT_NE(quad, new_quad);
  EXPECT_NE(quad->p1(), new_quad->p1());
  EXPECT_NE(quad->p2(), new_quad->p2());
  EXPECT_NE(quad->p3(), new_quad->p3());
  EXPECT_NE(quad->p4(), new_quad->p4());
  EXPECT_EQ(quad->p1()->x(), new_quad->p1()->x());
  EXPECT_EQ(quad->p1()->y(), new_quad->p1()->y());
  EXPECT_EQ(quad->p1()->z(), new_quad->p1()->z());
  EXPECT_EQ(quad->p1()->w(), new_quad->p1()->w());
  EXPECT_EQ(quad->p2()->x(), new_quad->p2()->x());
  EXPECT_EQ(quad->p2()->y(), new_quad->p2()->y());
  EXPECT_EQ(quad->p2()->z(), new_quad->p2()->z());
  EXPECT_EQ(quad->p2()->w(), new_quad->p2()->w());
  EXPECT_EQ(quad->p3()->x(), new_quad->p3()->x());
  EXPECT_EQ(quad->p3()->y(), new_quad->p3()->y());
  EXPECT_EQ(quad->p3()->z(), new_quad->p3()->z());
  EXPECT_EQ(quad->p3()->w(), new_quad->p3()->w());
  EXPECT_EQ(quad->p4()->x(), new_quad->p4()->x());
  EXPECT_EQ(quad->p4()->y(), new_quad->p4()->y());
  EXPECT_EQ(quad->p4()->z(), new_quad->p4()->z());
  EXPECT_EQ(quad->p4()->w(), new_quad->p4()->w());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMQuad) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x11, 0xff, 0x0d, 0x5c, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x22, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x2a, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x40, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x1c, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x40, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x2e, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x40, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x28, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x30, 0x40});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMQuad* quad = V8DOMQuad::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(quad, nullptr);
  EXPECT_EQ(1, quad->p1()->x());
  EXPECT_EQ(5, quad->p1()->y());
  EXPECT_EQ(9, quad->p1()->z());
  EXPECT_EQ(13, quad->p1()->w());
  EXPECT_EQ(2, quad->p2()->x());
  EXPECT_EQ(6, quad->p2()->y());
  EXPECT_EQ(10, quad->p2()->z());
  EXPECT_EQ(14, quad->p2()->w());
  EXPECT_EQ(3, quad->p3()->x());
  EXPECT_EQ(7, quad->p3()->y());
  EXPECT_EQ(11, quad->p3()->z());
  EXPECT_EQ(15, quad->p3()->w());
  EXPECT_EQ(4, quad->p4()->x());
  EXPECT_EQ(8, quad->p4()->y());
  EXPECT_EQ(12, quad->p4()->z());
  EXPECT_EQ(16, quad->p4()->w());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMMatrix2D) {
  test::TaskEnvironment task_environment;
  // DOMMatrix objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMMatrixInit* init = DOMMatrixInit::Create();
  init->setIs2D(true);
  init->setA(1.0);
  init->setB(2.0);
  init->setC(3.0);
  init->setD(4.0);
  init->setE(5.0);
  init->setF(6.0);
  DOMMatrix* matrix = DOMMatrix::fromMatrix(init, scope.GetExceptionState());
  EXPECT_TRUE(matrix->is2D());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMMatrix>::ToV8(scope.GetScriptState(), matrix);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  DOMMatrix* new_matrix = V8DOMMatrix::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_matrix, nullptr);
  EXPECT_NE(matrix, new_matrix);
  EXPECT_TRUE(new_matrix->is2D());
  EXPECT_EQ(matrix->a(), new_matrix->a());
  EXPECT_EQ(matrix->b(), new_matrix->b());
  EXPECT_EQ(matrix->c(), new_matrix->c());
  EXPECT_EQ(matrix->d(), new_matrix->d());
  EXPECT_EQ(matrix->e(), new_matrix->e());
  EXPECT_EQ(matrix->f(), new_matrix->f());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMMatrix2D) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff, 0x11, 0xff, 0x0d, 0x5c, 0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x18, 0x40, 0xff, 0x11, 0xff, 0x0d, 0x5c, 0x49,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x40,
  });
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMMatrix* matrix = V8DOMMatrix::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(matrix, nullptr);
  EXPECT_TRUE(matrix->is2D());
  EXPECT_EQ(1.0, matrix->a());
  EXPECT_EQ(2.0, matrix->b());
  EXPECT_EQ(3.0, matrix->c());
  EXPECT_EQ(4.0, matrix->d());
  EXPECT_EQ(5.0, matrix->e());
  EXPECT_EQ(6.0, matrix->f());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMMatrixReadOnly2D) {
  test::TaskEnvironment task_environment;
  // DOMMatrix objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMMatrixInit* init = DOMMatrixInit::Create();
  init->setIs2D(true);
  init->setA(1.0);
  init->setB(2.0);
  init->setC(3.0);
  init->setD(4.0);
  init->setE(5.0);
  init->setF(6.0);
  DOMMatrixReadOnly* matrix =
      DOMMatrixReadOnly::fromMatrix(init, scope.GetExceptionState());
  EXPECT_TRUE(matrix->is2D());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMMatrixReadOnly>::ToV8(scope.GetScriptState(), matrix);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  EXPECT_FALSE(V8DOMMatrix::HasInstance(scope.GetIsolate(), result));
  DOMMatrixReadOnly* new_matrix =
      V8DOMMatrixReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_matrix, nullptr);
  EXPECT_NE(matrix, new_matrix);
  EXPECT_TRUE(new_matrix->is2D());
  EXPECT_EQ(matrix->a(), new_matrix->a());
  EXPECT_EQ(matrix->b(), new_matrix->b());
  EXPECT_EQ(matrix->c(), new_matrix->c());
  EXPECT_EQ(matrix->d(), new_matrix->d());
  EXPECT_EQ(matrix->e(), new_matrix->e());
  EXPECT_EQ(matrix->f(), new_matrix->f());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMMatrixReadOnly2D) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff, 0x11, 0xff, 0x0d, 0x5c, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x18, 0x40, 0xff, 0x11, 0xff, 0x0d, 0x5c, 0x49,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x40,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x40,
  });
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMMatrixReadOnly* matrix =
      V8DOMMatrixReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(matrix, nullptr);
  EXPECT_TRUE(matrix->is2D());
  EXPECT_EQ(1.0, matrix->a());
  EXPECT_EQ(2.0, matrix->b());
  EXPECT_EQ(3.0, matrix->c());
  EXPECT_EQ(4.0, matrix->d());
  EXPECT_EQ(5.0, matrix->e());
  EXPECT_EQ(6.0, matrix->f());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMMatrix) {
  test::TaskEnvironment task_environment;
  // DOMMatrix objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMMatrixInit* init = DOMMatrixInit::Create();
  init->setIs2D(false);
  init->setM11(1.1);
  init->setM12(1.2);
  init->setM13(1.3);
  init->setM14(1.4);
  init->setM21(2.1);
  init->setM22(2.2);
  init->setM23(2.3);
  init->setM24(2.4);
  init->setM31(3.1);
  init->setM32(3.2);
  init->setM33(3.3);
  init->setM34(3.4);
  init->setM41(4.1);
  init->setM42(4.2);
  init->setM43(4.3);
  init->setM44(4.4);
  DOMMatrix* matrix = DOMMatrix::fromMatrix(init, scope.GetExceptionState());
  EXPECT_FALSE(matrix->is2D());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMMatrix>::ToV8(scope.GetScriptState(), matrix);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  DOMMatrix* new_matrix = V8DOMMatrix::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_matrix, nullptr);
  EXPECT_NE(matrix, new_matrix);
  EXPECT_FALSE(new_matrix->is2D());
  EXPECT_EQ(matrix->m11(), new_matrix->m11());
  EXPECT_EQ(matrix->m12(), new_matrix->m12());
  EXPECT_EQ(matrix->m13(), new_matrix->m13());
  EXPECT_EQ(matrix->m14(), new_matrix->m14());
  EXPECT_EQ(matrix->m21(), new_matrix->m21());
  EXPECT_EQ(matrix->m22(), new_matrix->m22());
  EXPECT_EQ(matrix->m23(), new_matrix->m23());
  EXPECT_EQ(matrix->m24(), new_matrix->m24());
  EXPECT_EQ(matrix->m31(), new_matrix->m31());
  EXPECT_EQ(matrix->m32(), new_matrix->m32());
  EXPECT_EQ(matrix->m33(), new_matrix->m33());
  EXPECT_EQ(matrix->m34(), new_matrix->m34());
  EXPECT_EQ(matrix->m41(), new_matrix->m41());
  EXPECT_EQ(matrix->m42(), new_matrix->m42());
  EXPECT_EQ(matrix->m43(), new_matrix->m43());
  EXPECT_EQ(matrix->m44(), new_matrix->m44());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMMatrix) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff, 0x11, 0xff, 0x0d, 0x5c, 0x59, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
      0xf1, 0x3f, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0xf3, 0x3f, 0xcd, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xf4, 0x3f, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0xf6, 0x3f, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x40, 0x9a, 0x99,
      0x99, 0x99, 0x99, 0x99, 0x01, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0x02, 0x40, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x03, 0x40, 0xcd, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0x08, 0x40, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
      0x09, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0a, 0x40, 0x33, 0x33,
      0x33, 0x33, 0x33, 0x33, 0x0b, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0x10, 0x40, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x40, 0x33, 0x33,
      0x33, 0x33, 0x33, 0x33, 0x11, 0x40, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
      0x11, 0x40,
  });
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMMatrix* matrix = V8DOMMatrix::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(matrix, nullptr);
  EXPECT_FALSE(matrix->is2D());
  EXPECT_EQ(1.1, matrix->m11());
  EXPECT_EQ(1.2, matrix->m12());
  EXPECT_EQ(1.3, matrix->m13());
  EXPECT_EQ(1.4, matrix->m14());
  EXPECT_EQ(2.1, matrix->m21());
  EXPECT_EQ(2.2, matrix->m22());
  EXPECT_EQ(2.3, matrix->m23());
  EXPECT_EQ(2.4, matrix->m24());
  EXPECT_EQ(3.1, matrix->m31());
  EXPECT_EQ(3.2, matrix->m32());
  EXPECT_EQ(3.3, matrix->m33());
  EXPECT_EQ(3.4, matrix->m34());
  EXPECT_EQ(4.1, matrix->m41());
  EXPECT_EQ(4.2, matrix->m42());
  EXPECT_EQ(4.3, matrix->m43());
  EXPECT_EQ(4.4, matrix->m44());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMMatrixReadOnly) {
  test::TaskEnvironment task_environment;
  // DOMMatrixReadOnly objects should serialize and deserialize correctly.
  V8TestingScope scope;
  DOMMatrixInit* init = DOMMatrixInit::Create();
  init->setIs2D(false);
  init->setM11(1.1);
  init->setM12(1.2);
  init->setM13(1.3);
  init->setM14(1.4);
  init->setM21(2.1);
  init->setM22(2.2);
  init->setM23(2.3);
  init->setM24(2.4);
  init->setM31(3.1);
  init->setM32(3.2);
  init->setM33(3.3);
  init->setM34(3.4);
  init->setM41(4.1);
  init->setM42(4.2);
  init->setM43(4.3);
  init->setM44(4.4);
  DOMMatrixReadOnly* matrix =
      DOMMatrixReadOnly::fromMatrix(init, scope.GetExceptionState());
  EXPECT_FALSE(matrix->is2D());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMMatrixReadOnly>::ToV8(scope.GetScriptState(), matrix);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  EXPECT_FALSE(V8DOMMatrix::HasInstance(scope.GetIsolate(), result));
  DOMMatrixReadOnly* new_matrix =
      V8DOMMatrixReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_matrix, nullptr);
  EXPECT_NE(matrix, new_matrix);
  EXPECT_FALSE(new
"""


```