Response:
The user wants to understand the functionality of the `outgoing_stream_test.cc` file in the Chromium Blink engine. I need to analyze the C++ code and explain its purpose, focusing on:

1. **Core Functionality:** What does the test file actually test?
2. **Relationship to Web Technologies:** Does it interact with JavaScript, HTML, or CSS concepts? If so, how?
3. **Logic and Data Flow:** Can I identify any logical steps or data transformations? Provide examples with input and output if possible.
4. **Common Usage Errors:** What mistakes might a developer make when using the tested functionality?
5. **Debugging Context:** How might a developer end up looking at this test file during debugging?

**Analysis of the Code:**

The file `outgoing_stream_test.cc` is a C++ unit test file for the `OutgoingStream` class. The `OutgoingStream` class appears to be a Blink implementation of a writable stream for the WebTransport API.

* **Key Classes and Concepts:**
    * `OutgoingStream`: The class being tested, likely responsible for sending data over a WebTransport connection.
    * `WritableStream`: A standard JavaScript API for writing data to a sink. `OutgoingStream` seems to wrap or implement this.
    * `DataPipe`: A Mojo primitive for inter-process communication, used here to simulate the underlying transport.
    * `WebTransportError`:  A specific error type within the WebTransport API.
    * `MockClient`: A test double to simulate the underlying WebTransport connection and verify interactions.
* **Test Structure:** The file uses the Google Test framework (`TEST`, `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_CALL`, etc.). Each `TEST` function focuses on a specific aspect of `OutgoingStream`'s behavior.

**Mapping to User's Requirements:**

1. **Functionality:**  The tests cover creating an `OutgoingStream`, writing data (ArrayBuffer, ArrayBufferView), asynchronous writing, closing the stream, handling data pipe closure, aborting the stream (with and without `WebTransportError`), and handling connection errors.

2. **Relationship to Web Technologies:** The key connection is to the **JavaScript Streams API**, specifically the `WritableStream`. The tests demonstrate how JavaScript code interacts with the underlying `OutgoingStream` implementation in Blink.

3. **Logic and Data Flow:** The tests involve writing data to the `WritableStream` in JavaScript and verifying that this data is correctly passed to the underlying `DataPipe`. The `StreamCreator` helper class facilitates this by managing the `DataPipe` and providing a way to read the written data.

4. **Common Usage Errors:**  Developers might misuse the `WritableStream` API, such as writing to a closed or errored stream, or not properly handling promises returned by `write()` or `close()`.

5. **Debugging Context:** A developer might look at this test file if they are:
    * Implementing or debugging the WebTransport API in Blink.
    * Investigating issues related to data flow or stream lifecycle in WebTransport.
    * Trying to understand how the JavaScript `WritableStream` API is mapped to the underlying network implementation.

Now I can generate the final response based on these insights.
这个文件 `outgoing_stream_test.cc` 是 Chromium Blink 引擎中 **WebTransport API** 的一个 **单元测试文件**。它专门用于测试 `OutgoingStream` 类的功能。`OutgoingStream` 类在 WebTransport 的上下文中，负责处理 **从客户端发送到服务器的数据流**。

**功能列举:**

该文件通过一系列的测试用例，验证了 `OutgoingStream` 类的以下功能：

1. **创建和销毁:** 测试 `OutgoingStream` 对象的创建和基本的清理工作。
2. **写入数据 (Write):**
   - 测试使用 `WritableStreamDefaultWriter` 的 `write()` 方法向流中写入 `ArrayBuffer` 和 `ArrayBufferView` 类型的数据。
   - 验证写入的数据是否正确地通过底层的 `DataPipe` 传输。
   - 测试异步写入的场景，即当写入的数据量超过管道容量时，数据是否会被分批发送。
3. **关闭流 (Close):**
   - 测试 `close()` 方法，验证在写入数据后立即关闭流时，所有数据都能被发送出去。
   - 验证关闭操作会通知底层的 `MockClient` 发送 FIN 信号。
4. **数据管道关闭 (Data Pipe Closed):**
   - 模拟底层数据管道被关闭的情况，验证 `OutgoingStream` 是否能正确处理，并使 `WritableStream` 的 `closed` promise 被 rejected。
   - 验证在数据管道关闭后，继续写入数据会导致 `write()` promise 被 rejected。
   - 测试异步写入过程中数据管道被关闭的情况。
5. **中止流 (Abort):**
   - 测试 `abort()` 方法，验证可以主动中止数据流的发送。
   - 测试使用不同的参数调用 `abort()`，包括传递 `WebTransportError` 对象，并验证底层的 `MockClient` 会收到正确的 `Reset` 调用。
6. **连接错误 (Connection Error):**
   - 测试在调用 `close()` 之后，如果发生连接错误，`OutgoingStream` 能否正确处理。

**与 Javascript, HTML, CSS 的功能关系:**

`OutgoingStream` 类是 WebTransport API 在 Blink 渲染引擎中的底层实现。WebTransport 允许 JavaScript 代码直接通过底层的传输协议 (例如 QUIC) 与服务器进行双向、多路复用的通信。

* **JavaScript:**  `OutgoingStream` 暴露了 Web 标准的 `WritableStream` 接口，JavaScript 代码可以通过这个接口来控制数据流的写入。
    * **举例:**  在 JavaScript 中，你可以通过 `WebTransport.createUnidirectionalStream()` 方法获得一个 `WritableStream` 实例，它在底层就对应着一个 `OutgoingStream` 对象。你可以使用 `getWriter()` 方法获取一个 `WritableStreamDefaultWriter`，然后使用其 `write()` 方法发送数据:

      ```javascript
      const transport = new WebTransport('https://example.com');
      await transport.ready;
      const stream = await transport.createUnidirectionalStream();
      const writer = stream.getWriter();
      const data = new Uint8Array([65, 66, 67]); // ABC
      await writer.write(data);
      await writer.close();
      ```
      在这个例子中，`writer.write(data)` 的操作最终会调用到 `outgoing_stream_test.cc` 中测试的 `OutgoingStream::Write()` 方法的底层逻辑。

* **HTML:**  HTML 本身不直接与 `OutgoingStream` 交互。但是，运行在 HTML 页面中的 JavaScript 代码可以使用 WebTransport API，从而间接地使用到 `OutgoingStream` 的功能。
* **CSS:** CSS 与 `OutgoingStream` 没有直接关系。

**逻辑推理与假设输入/输出:**

以下以 `WriteArrayBuffer` 测试用例为例进行逻辑推理：

**假设输入:**

1. 创建了一个 `OutgoingStream` 对象。
2. 从 `OutgoingStream` 获取了一个 `WritableStreamDefaultWriter`。
3. 在 JavaScript 中创建了一个包含字符 "A" 的 `ArrayBuffer`。
4. 调用 `writer.write(arrayBuffer)`。

**逻辑推理:**

1. `writer.write()` 方法被调用，并将 `ArrayBuffer` 的数据传递给底层的 `OutgoingStream`。
2. `OutgoingStream` 将数据通过 `DataPipe` 发送出去。
3. 测试代码使用 `stream_creator.ReadAllPendingData()` 从 `DataPipe` 的另一端读取数据。

**预期输出:**

`stream_creator.ReadAllPendingData()` 返回一个包含单个字节 'A' 的 `Vector<uint8_t>`。

**用户或编程常见的使用错误举例说明:**

1. **在流关闭后尝试写入:**  如果 JavaScript 代码在调用 `writer.close()` 或流因为错误关闭后，仍然尝试调用 `writer.write()`，那么 `write()` 方法返回的 Promise 会被 rejected。

   ```javascript
   const transport = new WebTransport('https://example.com');
   await transport.ready;
   const stream = await transport.createUnidirectionalStream();
   const writer = stream.getWriter();
   await writer.close();
   try {
     await writer.write(new Uint8Array([68])); // 错误: 流已关闭
   } catch (error) {
     console.error("写入失败:", error);
   }
   ```

2. **未处理 `write()` 或 `close()` 返回的 Promise:**  `write()` 和 `close()` 方法都返回 Promise。如果开发者没有正确地 `await` 这些 Promise 或者使用 `.then()` 和 `.catch()` 处理结果，可能会导致数据发送不完整或者错误没有被捕获。

   ```javascript
   const transport = new WebTransport('https://example.com');
   await transport.ready;
   const stream = await transport.createUnidirectionalStream();
   const writer = stream.getWriter();
   writer.write(new Uint8Array([69])); // 可能会在数据发送完成前执行后续代码
   writer.close();
   console.log("数据发送可能已开始");
   ```

3. **假设 `write()` 是同步的:**  `write()` 操作可能是异步的，尤其是在数据量较大或者网络状况不佳时。开发者不能假设 `write()` 调用返回后数据就立即发送到了服务器。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用一个基于 WebTransport 的在线应用时遇到了数据发送问题。以下是一些可能导致开发者查看 `outgoing_stream_test.cc` 的步骤：

1. **用户报告问题:** 用户反馈消息发送失败或者延迟很高。
2. **前端开发排查:** 前端开发者检查 JavaScript 代码，确认 WebTransport 连接已建立，并且使用了 `WritableStream` 的 `write()` 方法发送数据。他们可能会看到 `write()` 返回的 Promise 没有被 resolve 或者被 rejected。
3. **后端开发排查:** 后端开发者检查服务器端，发现没有收到预期的消息，或者收到的消息不完整。
4. **怀疑 Blink 引擎实现:**  如果前端和后端排查都没有发现明显的应用层错误，开发者可能会怀疑是浏览器底层 WebTransport API 的实现存在问题，特别是数据发送部分。
5. **查找相关代码:** 开发者可能会在 Chromium 源码中搜索与 WebTransport 和 `WritableStream` 相关的代码，从而找到 `blink/renderer/modules/webtransport/outgoing_stream.h` 和 `outgoing_stream.cc`。
6. **查看测试用例:** 为了理解 `OutgoingStream` 的预期行为以及如何进行测试，开发者会查看 `outgoing_stream_test.cc` 文件。这个文件提供了各种场景下的测试用例，可以帮助开发者理解 `OutgoingStream` 的工作原理，例如数据写入、流关闭、错误处理等。
7. **本地调试或修改测试:**  开发者可能会尝试在本地构建 Chromium，并运行 `outgoing_stream_test.cc` 中的特定测试用例，以便复现问题或者验证他们对代码的修改。他们可能还会添加新的测试用例来覆盖他们怀疑出错的场景。

总而言之，`outgoing_stream_test.cc` 是 WebTransport 功能开发和调试的重要组成部分，它确保了 Blink 引擎中 `OutgoingStream` 类的正确性和稳定性，从而保证了基于 WebTransport 的 Web 应用的可靠运行。

### 提示词
```
这是目录为blink/renderer/modules/webtransport/outgoing_stream_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webtransport/outgoing_stream.h"

#include <utility>

#include "base/containers/span.h"
#include "base/ranges/algorithm.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/webtransport/web_transport_error.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

using ::testing::ElementsAre;
using ::testing::StrictMock;

class MockClient : public GarbageCollected<MockClient>,
                   public OutgoingStream::Client {
 public:
  MOCK_METHOD0(SendFin, void());
  MOCK_METHOD0(ForgetStream, void());
  MOCK_METHOD1(Reset, void(uint8_t));
};

// The purpose of this class is to ensure that the data pipe is reset before the
// V8TestingScope is destroyed, so that the OutgoingStream object doesn't try to
// create a DOMException after the ScriptState has gone away.
class StreamCreator {
  STACK_ALLOCATED();

 public:
  StreamCreator() = default;
  ~StreamCreator() {
    Reset();

    // Let the OutgoingStream object respond to the closure if it needs to.
    test::RunPendingTasks();
  }

  // The default value of |capacity| means some sensible value selected by mojo.
  OutgoingStream* Create(const V8TestingScope& scope, uint32_t capacity = 0) {
    MojoCreateDataPipeOptions options;
    options.struct_size = sizeof(MojoCreateDataPipeOptions);
    options.flags = MOJO_CREATE_DATA_PIPE_FLAG_NONE;
    options.element_num_bytes = 1;
    options.capacity_num_bytes = capacity;

    mojo::ScopedDataPipeProducerHandle data_pipe_producer;
    MojoResult result =
        mojo::CreateDataPipe(&options, data_pipe_producer, data_pipe_consumer_);
    if (result != MOJO_RESULT_OK) {
      ADD_FAILURE() << "CreateDataPipe() returned " << result;
    }

    auto* script_state = scope.GetScriptState();
    mock_client_ = MakeGarbageCollected<StrictMock<MockClient>>();
    auto* outgoing_stream = MakeGarbageCollected<OutgoingStream>(
        script_state, mock_client_, std::move(data_pipe_producer));
    outgoing_stream->Init(ASSERT_NO_EXCEPTION);
    return outgoing_stream;
  }

  // Closes the pipe.
  void Reset() { data_pipe_consumer_.reset(); }

  // This is for use in EXPECT_CALL(), which is why it returns a reference.
  MockClient& GetMockClient() { return *mock_client_; }

  // Reads everything from |data_pipe_consumer_| and returns it in a vector.
  Vector<uint8_t> ReadAllPendingData() {
    Vector<uint8_t> data;
    base::span<const uint8_t> buffer;
    MojoResult result = data_pipe_consumer_->BeginReadData(
        MOJO_BEGIN_READ_DATA_FLAG_NONE, buffer);

    switch (result) {
      case MOJO_RESULT_OK:
        break;

      case MOJO_RESULT_SHOULD_WAIT:  // No more data yet.
        return data;

      default:
        ADD_FAILURE() << "BeginReadData() failed: " << result;
        return data;
    }

    data.AppendRange(buffer.begin(), buffer.end());
    data_pipe_consumer_->EndReadData(buffer.size());
    return data;
  }

  Persistent<StrictMock<MockClient>> mock_client_;
  mojo::ScopedDataPipeConsumerHandle data_pipe_consumer_;
};

TEST(OutgoingStreamTest, Create) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  auto* outgoing_stream = stream_creator.Create(scope);
  EXPECT_TRUE(outgoing_stream->Writable());

  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());
}

TEST(OutgoingStreamTest, WriteArrayBuffer) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  auto* outgoing_stream = stream_creator.Create(scope);
  auto* script_state = scope.GetScriptState();
  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("A"));
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(scope.GetScriptState(), result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_THAT(stream_creator.ReadAllPendingData(), ElementsAre('A'));

  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());
}

TEST(OutgoingStreamTest, WriteArrayBufferView) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  auto* outgoing_stream = stream_creator.Create(scope);
  auto* script_state = scope.GetScriptState();
  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);
  auto* buffer = DOMArrayBuffer::Create(base::byte_span_from_cstring("*B"));
  // Create a view into the buffer with offset 1, ie. "B".
  auto* chunk = DOMUint8Array::Create(buffer, 1, 1);
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(scope.GetScriptState(), result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_THAT(stream_creator.ReadAllPendingData(), ElementsAre('B'));

  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());
}

bool IsAllNulls(base::span<const uint8_t> data) {
  return base::ranges::all_of(data, [](uint8_t c) { return !c; });
}

TEST(OutgoingStreamTest, AsyncWrite) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  // Set a large pipe capacity, so any platform-specific excess is dwarfed in
  // size.
  constexpr uint32_t kPipeCapacity = 512u * 1024u;
  auto* outgoing_stream = stream_creator.Create(scope, kPipeCapacity);

  auto* script_state = scope.GetScriptState();
  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);

  // Write a chunk that definitely will not fit in the pipe.
  const size_t kChunkSize = kPipeCapacity * 3;
  auto* chunk = DOMArrayBuffer::Create(kChunkSize, 1);
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(scope.GetScriptState(), result);

  // Let the first pipe write complete.
  test::RunPendingTasks();

  // Let microtasks run just in case write() returns prematurely.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_FALSE(tester.IsFulfilled());

  // Read the first part of the data.
  auto data1 = stream_creator.ReadAllPendingData();
  EXPECT_LT(data1.size(), kChunkSize);

  // Verify the data wasn't corrupted.
  EXPECT_TRUE(IsAllNulls(data1));

  // Allow the asynchronous pipe write to happen.
  test::RunPendingTasks();

  // Read the second part of the data.
  auto data2 = stream_creator.ReadAllPendingData();
  EXPECT_TRUE(IsAllNulls(data2));

  test::RunPendingTasks();

  // Read the final part of the data.
  auto data3 = stream_creator.ReadAllPendingData();
  EXPECT_TRUE(IsAllNulls(data3));
  EXPECT_EQ(data1.size() + data2.size() + data3.size(), kChunkSize);

  // Now the write() should settle.
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  // Nothing should be left to read.
  EXPECT_THAT(stream_creator.ReadAllPendingData(), ElementsAre());

  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());
}

// Writing immediately followed by closing should not lose data.
TEST(OutgoingStreamTest, WriteThenClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;

  auto* outgoing_stream = stream_creator.Create(scope);
  auto* script_state = scope.GetScriptState();
  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("D"));
  auto write_promise =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);

  EXPECT_CALL(stream_creator.GetMockClient(), SendFin()).WillOnce([&]() {
    // This needs to happen asynchronously.
    scope.GetExecutionContext()
        ->GetTaskRunner(TaskType::kNetworking)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(&OutgoingStream::OnOutgoingStreamClosed,
                                 WrapWeakPersistent(outgoing_stream)));
  });

  auto close_promise = writer->close(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_tester(scope.GetScriptState(), write_promise);
  ScriptPromiseTester close_tester(scope.GetScriptState(), close_promise);

  // Make sure that write() and close() both run before the event loop is
  // serviced.
  scope.PerformMicrotaskCheckpoint();

  write_tester.WaitUntilSettled();
  EXPECT_TRUE(write_tester.IsFulfilled());
  close_tester.WaitUntilSettled();
  EXPECT_TRUE(close_tester.IsFulfilled());

  EXPECT_THAT(stream_creator.ReadAllPendingData(), ElementsAre('D'));
}

TEST(OutgoingStreamTest, DataPipeClosed) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;

  auto* outgoing_stream = stream_creator.Create(scope);
  auto* script_state = scope.GetScriptState();

  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);
  auto closed = writer->closed(script_state);
  ScriptPromiseTester closed_tester(script_state, closed);

  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());

  // Close the other end of the pipe.
  stream_creator.Reset();

  closed_tester.WaitUntilSettled();
  EXPECT_TRUE(closed_tester.IsRejected());

  DOMException* closed_exception = V8DOMException::ToWrappable(
      scope.GetIsolate(), closed_tester.Value().V8Value());
  ASSERT_TRUE(closed_exception);
  EXPECT_EQ(closed_exception->name(), "NetworkError");
  EXPECT_EQ(closed_exception->message(),
            "The stream was aborted by the remote server");

  auto* chunk = DOMArrayBuffer::Create('C', 1);
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_tester(script_state, result);
  write_tester.WaitUntilSettled();

  EXPECT_TRUE(write_tester.IsRejected());

  DOMException* write_exception = V8DOMException::ToWrappable(
      scope.GetIsolate(), write_tester.Value().V8Value());
  ASSERT_TRUE(write_exception);
  EXPECT_EQ(write_exception->name(), "NetworkError");
  EXPECT_EQ(write_exception->message(),
            "The stream was aborted by the remote server");
}

TEST(OutgoingStreamTest, DataPipeClosedDuringAsyncWrite) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;

  constexpr uint32_t kPipeCapacity = 512 * 1024;
  auto* outgoing_stream = stream_creator.Create(scope, kPipeCapacity);

  auto* script_state = scope.GetScriptState();

  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);

  const size_t kChunkSize = kPipeCapacity * 2;
  auto* chunk = DOMArrayBuffer::Create(kChunkSize, 1);
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_tester(script_state, result);

  auto closed = writer->closed(script_state);
  ScriptPromiseTester closed_tester(script_state, closed);

  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());

  // Close the other end of the pipe.
  stream_creator.Reset();

  write_tester.WaitUntilSettled();

  EXPECT_TRUE(write_tester.IsRejected());

  DOMException* write_exception = V8DOMException::ToWrappable(
      scope.GetIsolate(), write_tester.Value().V8Value());
  ASSERT_TRUE(write_exception);
  EXPECT_EQ(write_exception->name(), "NetworkError");
  EXPECT_EQ(write_exception->message(),
            "The stream was aborted by the remote server");

  closed_tester.WaitUntilSettled();

  EXPECT_TRUE(closed_tester.IsRejected());

  DOMException* closed_exception = V8DOMException::ToWrappable(
      scope.GetIsolate(), write_tester.Value().V8Value());
  ASSERT_TRUE(closed_exception);
  EXPECT_EQ(closed_exception->name(), "NetworkError");
  EXPECT_EQ(closed_exception->message(),
            "The stream was aborted by the remote server");
}

TEST(OutgoingStreamTest, Abort) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  auto* outgoing_stream = stream_creator.Create(scope);

  testing::InSequence s;
  EXPECT_CALL(stream_creator.GetMockClient(), Reset(0u));
  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());

  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);
  writer->abort(script_state, ScriptValue(isolate, v8::Undefined(isolate)),
                ASSERT_NO_EXCEPTION);
}

TEST(OutgoingStreamTest, AbortWithWebTransportError) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  auto* outgoing_stream = stream_creator.Create(scope);

  testing::InSequence s;
  EXPECT_CALL(stream_creator.GetMockClient(), Reset(0));
  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());

  v8::Local<v8::Value> error =
      WebTransportError::Create(isolate,
                                /*stream_error_code=*/std::nullopt, "foobar",
                                V8WebTransportErrorSource::Enum::kStream);

  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);
  writer->abort(script_state, ScriptValue(isolate, error), ASSERT_NO_EXCEPTION);
}

TEST(OutgoingStreamTest, AbortWithWebTransportErrorWithCode) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  auto* outgoing_stream = stream_creator.Create(scope);

  testing::InSequence s;
  EXPECT_CALL(stream_creator.GetMockClient(), Reset(8));
  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());

  v8::Local<v8::Value> error =
      WebTransportError::Create(isolate,
                                /*stream_error_code=*/8, "foobar",
                                V8WebTransportErrorSource::Enum::kStream);

  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);
  writer->abort(script_state, ScriptValue(isolate, error), ASSERT_NO_EXCEPTION);
}

TEST(OutgoingStreamTest, CloseAndConnectionError) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  StreamCreator stream_creator;
  ScriptState* script_state = scope.GetScriptState();
  v8::Isolate* isolate = scope.GetIsolate();

  auto* outgoing_stream = stream_creator.Create(scope);

  testing::InSequence s;
  EXPECT_CALL(stream_creator.GetMockClient(), SendFin());
  EXPECT_CALL(stream_creator.GetMockClient(), ForgetStream());

  auto* writer =
      outgoing_stream->Writable()->getWriter(script_state, ASSERT_NO_EXCEPTION);

  // Run microtasks to ensure that the underlying sink's close function is
  // called immediately.
  scope.PerformMicrotaskCheckpoint();

  writer->close(script_state, ASSERT_NO_EXCEPTION);
  outgoing_stream->Error(ScriptValue(isolate, v8::Undefined(isolate)));
}

}  // namespace

}  // namespace blink
```