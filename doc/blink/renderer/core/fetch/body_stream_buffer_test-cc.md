Response:
The user wants a summary of the functionality of the `body_stream_buffer_test.cc` file in the Chromium Blink engine. I need to extract the key features being tested in this file and explain their relationship to web technologies like JavaScript, HTML, and CSS if applicable. I also need to consider aspects like logical reasoning with input/output examples, common user errors, and how a user's interaction might lead to the execution of this code.

**Plan:**
1. **Identify the core purpose:** The filename strongly suggests this file tests the `BodyStreamBuffer` class.
2. **Analyze the tests:** Go through each `TEST_F` function and summarize what aspect of `BodyStreamBuffer` it's verifying.
3. **Relate to web technologies:** For each tested feature, consider its connection to JavaScript (e.g., ReadableStream API), HTML (e.g., form submissions), and CSS (less direct, but potentially related to resource loading).
4. **Consider logical reasoning:** Identify test cases that involve specific input and expected output behaviors.
5. **Think about user errors:**  Pinpoint scenarios where incorrect usage might trigger the tested functionalities.
6. **Trace user actions:** Imagine a user interacting with a webpage and how that might involve fetching resources and thus the `BodyStreamBuffer`.
7. **Focus on the first part:**  Since this is part 1 of 2, concentrate on summarizing the functionalities covered in this specific code snippet.
```
这是目录为blink/renderer/core/fetch/body_stream_buffer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

这个 `body_stream_buffer_test.cc` 文件是 Chromium Blink 引擎中用于测试 `BodyStreamBuffer` 类的单元测试文件。它的主要功能是验证 `BodyStreamBuffer` 类的各种行为和功能是否符合预期。

以下是它主要测试的功能点归纳：

**核心功能测试:**

1. **`Tee()` 方法:**
    *   测试 `Tee()` 方法能否正确地创建一个 `BodyStreamBuffer` 的两个独立副本（tees）。
    *   验证原始的 `BodyStreamBuffer` 在 `Tee()` 调用后是否被锁定和标记为已扰乱。
    *   测试从 `BytesConsumer` 创建的 `BodyStreamBuffer` 和从 JavaScript `ReadableStream` 创建的 `BodyStreamBuffer` 的 `Tee()` 行为差异。
    *   验证 `Tee()` 操作后 side data blob 的正确传递。

2. **`DrainAsBlobDataHandle()` 方法:**
    *   测试 `DrainAsBlobDataHandle()` 方法能否将 `BodyStreamBuffer` 的内容成功转换为 `BlobDataHandle`。
    *   验证对于不可 drain 的 `BytesConsumer`，此方法返回 `nullptr`。
    *   验证转换后 `BodyStreamBuffer` 的状态（是否锁定和扰乱）。
    *   测试从 JavaScript `ReadableStream` 创建的 `BodyStreamBuffer` 的 drain 行为。

3. **`DrainAsFormData()` 方法:**
    *   测试 `DrainAsFormData()` 方法能否将 `BodyStreamBuffer` 的内容成功转换为 `EncodedFormData`。
    *   验证对于不可 drain 的 `BytesConsumer`，此方法返回 `nullptr`。
    *   验证转换后 `BodyStreamBuffer` 的状态。
    *   测试从 JavaScript `ReadableStream` 创建的 `BodyStreamBuffer` 的 drain 行为。

4. **`StartLoading()` 方法的不同加载方式:**
    *   测试使用 `CreateLoaderAsArrayBuffer()` 加载 `BodyStreamBuffer` 的内容为 `DOMArrayBuffer`。
    *   测试使用 `CreateLoaderAsBlobHandle()` 加载 `BodyStreamBuffer` 的内容为 `BlobDataHandle`。
    *   测试使用 `CreateLoaderAsString()` 加载 `BodyStreamBuffer` 的内容为字符串。
    *   验证在加载过程中和加载完成后 `BodyStreamBuffer` 的状态变化（是否锁定和扰乱）。
    *   测试加载已关闭或已出错的 `BytesConsumer` 创建的 `BodyStreamBuffer` 的行为。

5. **生命周期管理:**
    *   测试 `BodyStreamBuffer` 是否能正确地持有 `FetchDataLoader` 的生命周期，防止过早释放。
    *   测试 `BodyStreamBuffer` 被取消 (cancel) 时，底层的 `BytesConsumer` 是否也会被取消。

6. **与 JavaScript ReadableStream 的集成:**
    *   测试从 JavaScript `ReadableStream` 创建 `BodyStreamBuffer` 的场景。
    *   测试在 JavaScript 中对 `BodyStreamBuffer` 暴露的流进行读取操作 (`getReader()`, `read()`)。

7. **AbortSignal 集成:**
    *   测试 `BodyStreamBuffer` 能否通过 `AbortSignal` 被中止 (abort)。
    *   测试在 `StartLoading()` 前和后中止 `BodyStreamBuffer` 是否会调用 `FetchDataLoaderClient` 的 `Abort()` 方法。

8. **Cached Metadata Handler:**
    *   测试 `BodyStreamBuffer` 是否能正确地持有和传递 `ScriptCachedMetadataHandler`。
    *   测试 `Tee()` 操作后，新的 `BodyStreamBuffer` 是否继承了相同的 `ScriptCachedMetadataHandler`。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **JavaScript:** `BodyStreamBuffer` 直接与 JavaScript 的 `ReadableStream` API 相关联。
    *   **举例:** 在 JavaScript 中，可以使用 `response.body` 获取一个 `ReadableStream`，Blink 引擎会将其转换为 `BodyStreamBuffer` 进行处理。测试中模拟了 JavaScript 创建 `ReadableStream` 并将其传递给 `BodyStreamBuffer` 的场景。
    *   **举例:** `Tee()` 方法对应于 JavaScript `ReadableStream` 的 `tee()` 方法，允许将流分叉。
    *   **举例:**  测试中使用了 `V8TestingScope` 和 `ScriptValue` 来模拟 JavaScript 环境并执行 JavaScript 代码来操作流。

*   **HTML:** `BodyStreamBuffer` 主要用于处理 HTTP 响应体，这与 HTML 中通过 `<script>`, `<link>`, `<img>`, `<iframe>` 等标签发起的网络请求密切相关。
    *   **举例:** 当浏览器接收到一个 HTML 文档的网络响应时，响应体的数据会被放入 `BodyStreamBuffer` 中进行处理。
    *   **举例:** 表单提交（`<form>`) 也可以使用流式的方式发送数据，`BodyStreamBuffer` 可以处理表单数据的读取。

*   **CSS:** 虽然 `BodyStreamBuffer` 不直接操作 CSS 属性，但它负责加载 CSS 文件内容。
    *   **举例:** 当浏览器请求一个 CSS 文件时，服务器返回的 CSS 内容会通过 `BodyStreamBuffer` 进行传输和处理。

**逻辑推理、假设输入与输出:**

*   **假设输入 (针对 `Tee()` 测试):** 一个包含字符串 "hello, world" 的 `BytesConsumer`。
*   **预期输出:** 调用 `Tee()` 后，创建了两个新的 `BodyStreamBuffer`，当它们分别被加载为字符串时，都会得到 "hello, world"。

*   **假设输入 (针对 `DrainAsBlobDataHandle()` 测试):** 一个包含字符串 "hello" 的 `BlobBytesConsumer`。
*   **预期输出:** 调用 `DrainAsBlobDataHandle()` 后，返回一个包含 "hello" 的 `BlobDataHandle`。

**用户或编程常见的使用错误及举例说明:**

*   **错误地多次读取流:**  一旦 `BodyStreamBuffer` 被读取 (例如通过 `getReader().read()` 或 `DrainAsBlobDataHandle()`)，它通常会被标记为已扰乱，再次读取可能会失败或得到空数据。测试验证了 `IsStreamDisturbed()` 的状态。
    *   **用户操作导致:** 开发者在 JavaScript 中尝试多次读取 `response.body`。

*   **在流被锁定的情况下操作:**  某些操作（如 `Tee()` 或 drain 操作）需要流未被锁定。如果在流已经被读取器锁定后尝试这些操作，可能会导致错误。测试验证了 `IsStreamLocked()` 的状态。
    *   **用户操作导致:**  JavaScript 代码中先调用了 `response.body.getReader()` 获取读取器，然后又尝试调用 `response.blob()` 或 `response.text()`。

**用户操作到达这里的调试线索:**

1. **发起网络请求:** 用户在浏览器中访问一个网页，或者通过 JavaScript 代码（例如使用 `fetch()` API）发起一个网络请求。
2. **接收响应头:** 浏览器接收到服务器的响应头。
3. **处理响应体:** 对于包含响应体的请求，Blink 引擎会创建一个 `BodyStreamBuffer` 来处理响应体的数据流。
4. **读取响应体:** JavaScript 代码可能会尝试以不同的方式读取响应体，例如：
    *   `response.text()`: 将响应体作为文本读取。
    *   `response.json()`: 将响应体作为 JSON 读取。
    *   `response.blob()`: 将响应体作为 Blob 读取。
    *   `response.arrayBuffer()`: 将响应体作为 ArrayBuffer 读取。
    *   `response.body`: 获取一个 `ReadableStream` 对象。
5. **执行相应的代码:** 当执行到这些读取响应体的 JavaScript 代码时，会触发 `BodyStreamBuffer` 相应的操作，例如调用 `StartLoading()` 并使用不同的 `FetchDataLoader`。
6. **调试:** 如果在这些过程中出现问题，开发者可能会查看 Blink 引擎的源代码，或者设置断点来调试 `BodyStreamBuffer` 的行为，从而会接触到 `body_stream_buffer_test.cc` 中测试的逻辑。

**归纳一下它的功能 (针对第1部分):**

这个测试文件的第一部分主要关注 `BodyStreamBuffer` 的基本操作，包括创建、复制 (`Tee`)、转换为不同数据类型 (`DrainAsBlobDataHandle`, `DrainAsFormData`)、以及基本的加载功能 (`StartLoading` 为 String, ArrayBuffer, Blob)。它还测试了与 JavaScript `ReadableStream` 的基本集成，以及 `AbortSignal` 和 `CachedMetadataHandler` 的初步集成。 总的来说，这部分测试覆盖了 `BodyStreamBuffer` 的核心功能和状态管理。

Prompt: 
```
这是目录为blink/renderer/core/fetch/body_stream_buffer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/body_stream_buffer.h"

#include <memory>

#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/core/dom/abort_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"
#include "third_party/blink/renderer/core/fetch/bytes_consumer_test_util.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/core/html/forms/form_data.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_controller_with_script_scope.h"
#include "third_party/blink/renderer/core/streams/test_underlying_source.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/blob/blob_url.h"
#include "third_party/blink/renderer/platform/blob/testing/fake_blob.h"
#include "third_party/blink/renderer/platform/blob/testing/fake_blob_registry.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/bytes_consumer.h"
#include "third_party/blink/renderer/platform/loader/fetch/cached_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/script_cached_metadata_handler.h"
#include "third_party/blink/renderer/platform/loader/fetch/text_resource_decoder_options.h"
#include "third_party/blink/renderer/platform/loader/testing/replaying_bytes_consumer.h"
#include "third_party/blink/renderer/platform/network/encoded_form_data.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

using testing::InSequence;
using testing::Return;
using testing::_;
using testing::SaveArg;
using Checkpoint = testing::StrictMock<testing::MockFunction<void(int)>>;
using MockFetchDataLoaderClient =
    BytesConsumerTestUtil::MockFetchDataLoaderClient;

class BodyStreamBufferTest : public testing::Test {
 protected:
  using Command = ReplayingBytesConsumer::Command;
  ScriptValue Eval(ScriptState* script_state, const char* s) {
    v8::Local<v8::String> source;
    v8::Local<v8::Script> script;
    v8::MicrotasksScope microtasks(script_state->GetIsolate(),
                                   ToMicrotaskQueue(script_state),
                                   v8::MicrotasksScope::kDoNotRunMicrotasks);
    if (!v8::String::NewFromUtf8(script_state->GetIsolate(), s,
                                 v8::NewStringType::kNormal)
             .ToLocal(&source)) {
      ADD_FAILURE();
      return ScriptValue();
    }
    if (!v8::Script::Compile(script_state->GetContext(), source)
             .ToLocal(&script)) {
      ADD_FAILURE() << "Compilation fails";
      return ScriptValue();
    }
    return ScriptValue(
        script_state->GetIsolate(),
        script->Run(script_state->GetContext()).ToLocalChecked());
  }
  ScriptValue EvalWithPrintingError(ScriptState* script_state, const char* s) {
    v8::TryCatch block(script_state->GetIsolate());
    ScriptValue r = Eval(script_state, s);
    if (block.HasCaught()) {
      ADD_FAILURE() << ToCoreString(script_state->GetIsolate(),
                                    block.Exception()
                                        ->ToString(script_state->GetContext())
                                        .ToLocalChecked())
                           .Utf8();
      block.ReThrow();
    }
    return r;
  }
  scoped_refptr<BlobDataHandle> CreateBlob(const String& body) {
    auto data = std::make_unique<BlobData>();
    data->AppendText(body, false);
    uint64_t length = data->length();
    return BlobDataHandle::Create(std::move(data), length);
  }

 private:
  test::TaskEnvironment task_environment;
};

class MockFetchDataLoader : public FetchDataLoader {
 public:
  // Cancel() gets called during garbage collection after the test is
  // finished. Since most tests don't care about this, use NiceMock so that the
  // calls to Cancel() are ignored.
  static testing::NiceMock<MockFetchDataLoader>* Create() {
    return MakeGarbageCollected<testing::NiceMock<MockFetchDataLoader>>();
  }

  MOCK_METHOD2(Start, void(BytesConsumer*, FetchDataLoader::Client*));
  MOCK_METHOD0(Cancel, void());

 protected:
  MockFetchDataLoader() = default;
};

TEST_F(BodyStreamBufferTest, Tee) {
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;
  Checkpoint checkpoint;
  auto* client1 = MakeGarbageCollected<MockFetchDataLoaderClient>();
  auto* client2 = MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(0));
  EXPECT_CALL(*client1, DidFetchDataLoadedString(String("hello, world")));
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*client2, DidFetchDataLoadedString(String("hello, world")));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(checkpoint, Call(4));

  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");

  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kData, "hello, "));
  src->Add(Command(Command::kData, "world"));
  src->Add(Command(Command::kDone));
  BodyStreamBuffer* buffer =
      BodyStreamBuffer::Create(scope.GetScriptState(), src,
                               /*abort_signal=*/nullptr,
                               /*cached_metadata=*/nullptr, side_data_blob);
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());

  BodyStreamBuffer* new1;
  BodyStreamBuffer* new2;
  buffer->Tee(&new1, &new2, exception_state);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());

  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());
  EXPECT_EQ(side_data_blob, new1->GetSideDataBlobForTest());
  EXPECT_EQ(side_data_blob, new2->GetSideDataBlobForTest());

  checkpoint.Call(0);
  new1->StartLoading(FetchDataLoader::CreateLoaderAsString(
                         TextResourceDecoderOptions::CreateUTF8Decode()),
                     client1, exception_state);
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);

  new2->StartLoading(FetchDataLoader::CreateLoaderAsString(
                         TextResourceDecoderOptions::CreateUTF8Decode()),
                     client2, exception_state);
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
}

TEST_F(BodyStreamBufferTest, TeeFromHandleMadeFromStream) {
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;

  auto* underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(scope.GetScriptState());
  auto* chunk1 = DOMUint8Array::Create(std::array<uint8_t, 2>{0x41, 0x42});
  auto* chunk2 = DOMUint8Array::Create(std::array<uint8_t, 2>{0x55, 0x58});

  auto* stream = ReadableStream::CreateWithCountQueueingStrategy(
      scope.GetScriptState(), underlying_source, 0);
  ASSERT_TRUE(stream);

  underlying_source->Enqueue(ScriptValue(
      scope.GetIsolate(),
      ToV8Traits<DOMUint8Array>::ToV8(scope.GetScriptState(), chunk1)));
  underlying_source->Enqueue(ScriptValue(
      scope.GetIsolate(),
      ToV8Traits<DOMUint8Array>::ToV8(scope.GetScriptState(), chunk2)));
  underlying_source->Close();

  Checkpoint checkpoint;
  auto* client1 = MakeGarbageCollected<MockFetchDataLoaderClient>();
  auto* client2 = MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*client1, DidFetchDataLoadedString(String("ABUX")));
  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(checkpoint, Call(3));
  EXPECT_CALL(*client2, DidFetchDataLoadedString(String("ABUX")));
  EXPECT_CALL(checkpoint, Call(4));

  BodyStreamBuffer* buffer = MakeGarbageCollected<BodyStreamBuffer>(
      scope.GetScriptState(), stream, /*cached_metadta_handler=*/nullptr);

  BodyStreamBuffer* new1;
  BodyStreamBuffer* new2;
  buffer->Tee(&new1, &new2, exception_state);

  EXPECT_TRUE(buffer->IsStreamLocked());
  // Note that this behavior is slightly different from for the behavior of
  // a BodyStreamBuffer made from a BytesConsumer. See the above test. In this
  // test, the stream will get disturbed when the microtask is performed.
  // TODO(yhirano): A uniformed behavior is preferred.
  EXPECT_FALSE(buffer->IsStreamDisturbed());

  scope.PerformMicrotaskCheckpoint();

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());

  new1->StartLoading(FetchDataLoader::CreateLoaderAsString(
                         TextResourceDecoderOptions::CreateUTF8Decode()),
                     client1, exception_state);
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);

  new2->StartLoading(FetchDataLoader::CreateLoaderAsString(
                         TextResourceDecoderOptions::CreateUTF8Decode()),
                     client2, exception_state);
  checkpoint.Call(3);
  test::RunPendingTasks();
  checkpoint.Call(4);
}

TEST_F(BodyStreamBufferTest, DrainAsBlobDataHandle) {
  V8TestingScope scope;
  scoped_refptr<BlobDataHandle> blob_data_handle = CreateBlob("hello");
  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(),
      MakeGarbageCollected<BlobBytesConsumer>(scope.GetExecutionContext(),
                                              blob_data_handle),
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());
  scoped_refptr<BlobDataHandle> output_blob_data_handle =
      buffer->DrainAsBlobDataHandle(
          BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize,
          ASSERT_NO_EXCEPTION);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());
  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());
  EXPECT_EQ(blob_data_handle, output_blob_data_handle);
}

TEST_F(BodyStreamBufferTest, DrainAsBlobDataHandleReturnsNull) {
  V8TestingScope scope;
  // This BytesConsumer is not drainable.
  BytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src,
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());

  EXPECT_FALSE(buffer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize,
      ASSERT_NO_EXCEPTION));

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());
}

TEST_F(BodyStreamBufferTest,
       DrainAsBlobFromBufferMadeFromBufferMadeFromStream) {
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;
  auto* stream =
      ReadableStream::Create(scope.GetScriptState(), exception_state);
  ASSERT_TRUE(stream);
  BodyStreamBuffer* buffer = MakeGarbageCollected<BodyStreamBuffer>(
      scope.GetScriptState(), stream, /*cached_metadata_handler=*/nullptr);

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_TRUE(buffer->IsStreamReadable());

  EXPECT_FALSE(buffer->DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy::kAllowBlobWithInvalidSize,
      ASSERT_NO_EXCEPTION));

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_TRUE(buffer->IsStreamReadable());
}

TEST_F(BodyStreamBufferTest, DrainAsFormData) {
  V8TestingScope scope;
  auto* data = MakeGarbageCollected<FormData>(UTF8Encoding());
  data->append("name1", "value1");
  data->append("name2", "value2");
  scoped_refptr<EncodedFormData> input_form_data =
      data->EncodeMultiPartFormData();
  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");

  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(),
      MakeGarbageCollected<FormDataBytesConsumer>(scope.GetExecutionContext(),
                                                  input_form_data),
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());
  scoped_refptr<EncodedFormData> output_form_data =
      buffer->DrainAsFormData(ASSERT_NO_EXCEPTION);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());
  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());
  EXPECT_EQ(output_form_data->FlattenToString(),
            input_form_data->FlattenToString());
}

TEST_F(BodyStreamBufferTest, DrainAsFormDataReturnsNull) {
  V8TestingScope scope;
  // This BytesConsumer is not drainable.
  BytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src,
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());

  EXPECT_FALSE(buffer->DrainAsFormData(ASSERT_NO_EXCEPTION));

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());
}

TEST_F(BodyStreamBufferTest,
       DrainAsFormDataFromBufferMadeFromBufferMadeFromStream) {
  V8TestingScope scope;
  NonThrowableExceptionState exception_state;
  auto* stream =
      ReadableStream::Create(scope.GetScriptState(), exception_state);
  BodyStreamBuffer* buffer = MakeGarbageCollected<BodyStreamBuffer>(
      scope.GetScriptState(), stream, /*cached_metadata_handler=*/nullptr);

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_TRUE(buffer->IsStreamReadable());

  EXPECT_FALSE(buffer->DrainAsFormData(ASSERT_NO_EXCEPTION));

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_TRUE(buffer->IsStreamReadable());
}

TEST_F(BodyStreamBufferTest, LoadBodyStreamBufferAsArrayBuffer) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();
  DOMArrayBuffer* array_buffer = nullptr;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*client, DidFetchDataLoadedArrayBufferMock(_))
      .WillOnce(SaveArg<0>(&array_buffer));
  EXPECT_CALL(checkpoint, Call(2));

  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "hello"));
  src->Add(Command(Command::kDone));
  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src,
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());
  buffer->StartLoading(FetchDataLoader::CreateLoaderAsArrayBuffer(), client,
                       ASSERT_NO_EXCEPTION);

  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());
  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());

  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());
  ASSERT_TRUE(array_buffer);
  EXPECT_EQ("hello", String(array_buffer->ByteSpan()));
}

class BodyStreamBufferBlobTest : public BodyStreamBufferTest {
 public:
  BodyStreamBufferBlobTest()
      : fake_task_runner_(base::MakeRefCounted<scheduler::FakeTaskRunner>()),
        blob_registry_receiver_(
            &fake_blob_registry_,
            blob_registry_remote_.BindNewPipeAndPassReceiver()) {
    BlobDataHandle::SetBlobRegistryForTesting(blob_registry_remote_.get());
  }

  ~BodyStreamBufferBlobTest() override {
    BlobDataHandle::SetBlobRegistryForTesting(nullptr);
  }

 protected:
  scoped_refptr<scheduler::FakeTaskRunner> fake_task_runner_;

 private:
  FakeBlobRegistry fake_blob_registry_;
  mojo::Remote<mojom::blink::BlobRegistry> blob_registry_remote_;
  mojo::Receiver<mojom::blink::BlobRegistry> blob_registry_receiver_;
};

TEST_F(BodyStreamBufferBlobTest, LoadBodyStreamBufferAsBlob) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();
  scoped_refptr<BlobDataHandle> blob_data_handle;

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*client, DidFetchDataLoadedBlobHandleMock(_))
      .WillOnce(SaveArg<0>(&blob_data_handle));
  EXPECT_CALL(checkpoint, Call(2));

  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "hello"));
  src->Add(Command(Command::kDone));
  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src,
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());
  buffer->StartLoading(FetchDataLoader::CreateLoaderAsBlobHandle(
                           "text/plain", fake_task_runner_),
                       client, ASSERT_NO_EXCEPTION);

  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());
  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());

  checkpoint.Call(1);
  fake_task_runner_->RunUntilIdle();
  test::RunPendingTasks();
  checkpoint.Call(2);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());
  EXPECT_EQ(5u, blob_data_handle->size());
}

TEST_F(BodyStreamBufferTest, LoadBodyStreamBufferAsString) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*client, DidFetchDataLoadedString(String("hello")));
  EXPECT_CALL(checkpoint, Call(2));

  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "hello"));
  src->Add(Command(Command::kDone));
  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src,
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);
  EXPECT_EQ(side_data_blob, buffer->GetSideDataBlobForTest());
  buffer->StartLoading(FetchDataLoader::CreateLoaderAsString(
                           TextResourceDecoderOptions::CreateUTF8Decode()),
                       client, ASSERT_NO_EXCEPTION);

  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());
  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());

  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());
}

TEST_F(BodyStreamBufferTest, LoadClosedHandle) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*client, DidFetchDataLoadedString(String("")));
  EXPECT_CALL(checkpoint, Call(2));

  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), BytesConsumer::CreateClosed(),
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);

  EXPECT_TRUE(buffer->IsStreamClosed());

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());

  checkpoint.Call(1);
  buffer->StartLoading(FetchDataLoader::CreateLoaderAsString(
                           TextResourceDecoderOptions::CreateUTF8Decode()),
                       client, ASSERT_NO_EXCEPTION);
  checkpoint.Call(2);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());
}

TEST_F(BodyStreamBufferTest, LoadErroredHandle) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*client, DidFetchDataLoadFailed());
  EXPECT_CALL(checkpoint, Call(2));

  scoped_refptr<BlobDataHandle> side_data_blob = CreateBlob("side data");
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(),
      BytesConsumer::CreateErrored(BytesConsumer::Error()),
      /*abort_signal=*/nullptr, /*cached_metadata_handler=*/nullptr,
      side_data_blob);

  EXPECT_TRUE(buffer->IsStreamErrored());

  EXPECT_FALSE(buffer->IsStreamLocked());
  EXPECT_FALSE(buffer->IsStreamDisturbed());
  EXPECT_EQ(nullptr, buffer->GetSideDataBlobForTest());

  checkpoint.Call(1);
  buffer->StartLoading(FetchDataLoader::CreateLoaderAsString(
                           TextResourceDecoderOptions::CreateUTF8Decode()),
                       client, ASSERT_NO_EXCEPTION);
  checkpoint.Call(2);

  EXPECT_TRUE(buffer->IsStreamLocked());
  EXPECT_TRUE(buffer->IsStreamDisturbed());
}

TEST_F(BodyStreamBufferTest, LoaderShouldBeKeptAliveByBodyStreamBuffer) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();

  InSequence s;
  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*client, DidFetchDataLoadedString(String("hello")));
  EXPECT_CALL(checkpoint, Call(2));

  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "hello"));
  src->Add(Command(Command::kDone));
  Persistent<BodyStreamBuffer> buffer =
      BodyStreamBuffer::Create(scope.GetScriptState(), src, nullptr,
                               /*cached_metadata_handler=*/nullptr);
  buffer->StartLoading(FetchDataLoader::CreateLoaderAsString(
                           TextResourceDecoderOptions::CreateUTF8Decode()),
                       client, ASSERT_NO_EXCEPTION);

  ThreadState::Current()->CollectAllGarbageForTesting();
  checkpoint.Call(1);
  test::RunPendingTasks();
  checkpoint.Call(2);
}

TEST_F(BodyStreamBufferTest, SourceShouldBeCanceledWhenCanceled) {
  V8TestingScope scope;
  ReplayingBytesConsumer* consumer =
      MakeGarbageCollected<ReplayingBytesConsumer>(
          scope.GetDocument().GetTaskRunner(TaskType::kNetworking));

  BodyStreamBuffer* buffer =
      BodyStreamBuffer::Create(scope.GetScriptState(), consumer, nullptr,
                               /*cached_metadata_handler=*/nullptr);
  ScriptValue reason(scope.GetIsolate(),
                     V8String(scope.GetIsolate(), "reason"));
  EXPECT_FALSE(consumer->IsCancelled());
  buffer->Cancel(reason.V8Value());
  EXPECT_TRUE(consumer->IsCancelled());
}

TEST_F(BodyStreamBufferTest, NestedPull) {
  V8TestingScope scope;
  ReplayingBytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  src->Add(Command(Command::kWait));
  src->Add(Command(Command::kData, "hello"));
  src->Add(Command(Command::kError));
  Persistent<BodyStreamBuffer> buffer =
      BodyStreamBuffer::Create(scope.GetScriptState(), src, nullptr,
                               /*cached_metadata_handler=*/nullptr);

  auto result =
      scope.GetScriptState()->GetContext()->Global()->CreateDataProperty(
          scope.GetScriptState()->GetContext(),
          V8String(scope.GetIsolate(), "stream"),
          ToV8Traits<ReadableStream>::ToV8(scope.GetScriptState(),
                                           buffer->Stream()));

  ASSERT_TRUE(result.IsJust());
  ASSERT_TRUE(result.FromJust());

  ScriptValue stream = EvalWithPrintingError(scope.GetScriptState(),
                                             "reader = stream.getReader();");
  ASSERT_FALSE(stream.IsEmpty());

  EvalWithPrintingError(scope.GetScriptState(), "reader.read();");
  EvalWithPrintingError(scope.GetScriptState(), "reader.read();");

  test::RunPendingTasks();
  scope.PerformMicrotaskCheckpoint();
}

TEST_F(BodyStreamBufferTest, NullAbortSignalIsNotAborted) {
  V8TestingScope scope;
  // This BytesConsumer is not drainable.
  BytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  BodyStreamBuffer* buffer =
      BodyStreamBuffer::Create(scope.GetScriptState(), src, nullptr,
                               /*cached_metadata_handler=*/nullptr);

  EXPECT_FALSE(buffer->IsAborted());
}

TEST_F(BodyStreamBufferTest, AbortSignalMakesAborted) {
  V8TestingScope scope;
  // This BytesConsumer is not drainable.
  BytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  auto* controller = AbortController::Create(scope.GetScriptState());
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src, controller->signal(),
      /*cached_metadata_handler=*/nullptr);

  EXPECT_FALSE(buffer->IsAborted());
  controller->abort(scope.GetScriptState());
  EXPECT_TRUE(buffer->IsAborted());
}

TEST_F(BodyStreamBufferTest,
       AbortBeforeStartLoadingCallsDataLoaderClientAbort) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  MockFetchDataLoader* loader = MockFetchDataLoader::Create();
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();
  auto* src = MakeGarbageCollected<BytesConsumerTestUtil::MockBytesConsumer>();

  EXPECT_CALL(*loader, Start(_, _)).Times(0);

  InSequence s;
  EXPECT_CALL(*src, SetClient(_));
  EXPECT_CALL(*src, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));

  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*src, Cancel());

  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*client, Abort());

  EXPECT_CALL(checkpoint, Call(3));

  auto* controller = AbortController::Create(scope.GetScriptState());
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src, controller->signal(),
      /*cached_metadata_handler=*/nullptr);

  checkpoint.Call(1);
  controller->abort(scope.GetScriptState());

  checkpoint.Call(2);
  buffer->StartLoading(loader, client, ASSERT_NO_EXCEPTION);

  checkpoint.Call(3);
}

TEST_F(BodyStreamBufferTest, AbortAfterStartLoadingCallsDataLoaderClientAbort) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  MockFetchDataLoader* loader = MockFetchDataLoader::Create();
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();
  auto* src = MakeGarbageCollected<BytesConsumerTestUtil::MockBytesConsumer>();

  InSequence s;
  EXPECT_CALL(*src, SetClient(_));
  EXPECT_CALL(*src, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));

  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*src, ClearClient());
  EXPECT_CALL(*loader, Start(_, _));

  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*client, Abort());

  EXPECT_CALL(checkpoint, Call(3));

  auto* controller = AbortController::Create(scope.GetScriptState());
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src, controller->signal(),
      /*cached_metadata_handler=*/nullptr);

  checkpoint.Call(1);
  buffer->StartLoading(loader, client, ASSERT_NO_EXCEPTION);

  checkpoint.Call(2);
  controller->abort(scope.GetScriptState());

  checkpoint.Call(3);
}

TEST_F(BodyStreamBufferTest,
       AsyncAbortAfterStartLoadingCallsDataLoaderClientAbort) {
  V8TestingScope scope;
  Checkpoint checkpoint;
  MockFetchDataLoader* loader = MockFetchDataLoader::Create();
  auto* client = MakeGarbageCollected<MockFetchDataLoaderClient>();
  auto* src = MakeGarbageCollected<BytesConsumerTestUtil::MockBytesConsumer>();

  InSequence s;
  EXPECT_CALL(*src, SetClient(_));
  EXPECT_CALL(*src, GetPublicState())
      .WillOnce(Return(BytesConsumer::PublicState::kReadableOrWaiting));

  EXPECT_CALL(checkpoint, Call(1));
  EXPECT_CALL(*src, ClearClient());
  EXPECT_CALL(*loader, Start(_, _));

  EXPECT_CALL(checkpoint, Call(2));
  EXPECT_CALL(*client, Abort());

  EXPECT_CALL(checkpoint, Call(3));

  auto* controller = AbortController::Create(scope.GetScriptState());
  BodyStreamBuffer* buffer = BodyStreamBuffer::Create(
      scope.GetScriptState(), src, controller->signal(),
      /*cached_metadata_handler=*/nullptr);

  checkpoint.Call(1);
  buffer->StartLoading(loader, client, ASSERT_NO_EXCEPTION);
  test::RunPendingTasks();

  checkpoint.Call(2);
  controller->abort(scope.GetScriptState());

  checkpoint.Call(3);
}

TEST_F(BodyStreamBufferTest, CachedMetadataHandler) {
  V8TestingScope scope;
  Persistent<BodyStreamBuffer> buffer;
  WeakPersistent<ScriptCachedMetadataHandler> weak_handler;
  {
    BytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
        scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
    auto* handler = MakeGarbageCollected<ScriptCachedMetadataHandler>(
        WTF::TextEncoding(), nullptr);
    weak_handler = handler;
    buffer = BodyStreamBuffer::Create(scope.GetScriptState(), src,
                                      /*abort_signal=*/nullptr, handler);

    EXPECT_EQ(handler, buffer->GetCachedMetadataHandler());
    EXPECT_NE(weak_handler.Get(), nullptr);

    buffer->CloseAndLockAndDisturb(ASSERT_NO_EXCEPTION);
  }

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_EQ(weak_handler.Get(), nullptr);
}

TEST_F(BodyStreamBufferTest, CachedMetadataHandlerAndTee) {
  V8TestingScope scope;
  BytesConsumer* src = MakeGarbageCollected<ReplayingBytesConsumer>(
      scope.GetDocument().GetTaskRunner(TaskType::kNetworking));
  auto* handler = MakeGarbageCollected<ScriptCachedMetadataHandler>(
      WTF::TextEncoding(), nullptr);
  auto* buffer = BodyStreamBuffer::Create(scope.GetScriptState(), src,
                                          /*abort_signal=*/nullptr, handler);

  EXPECT_EQ(handler, buffer->GetCachedMetadataHandler());

  BodyStreamBuffer* dest1 = nullptr;
  BodyStreamBuffer* dest2 = nullptr;
  buffer->Tee(&dest1, &dest2, ASSERT_NO_EXCEPTION);

  EXPECT_EQ(dest1->GetCachedMetadataHandler(), handler);
  EXPECT_EQ(dest2->GetCachedMetadataHandler(), handler);
}

TEST_F(BodyStreamBufferTest,
       CachedMetadataHandlerAndTeeForBufferMadeFromStream) {
  V8TestingScope scope;
  auto* handler = MakeGarbageCollected<ScriptCachedMetadataHandler>(
      WTF::TextEncoding(), nullptr);
  auto* stream =
      ReadableStream::Create(scope.GetScriptState(), ASSERT_NO_EXCEPTION);
  auto* buffer = MakeGarbageCollected<BodyStreamBuffer>(scope.GetScriptState(),
                                                        stream, handler);

  EXPECT_EQ(handler, buffer->GetCachedMetadataHandler());

  BodyStreamBuffer* d
"""


```