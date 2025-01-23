Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for a breakdown of the file's functionality, its relationship to web technologies, logical inferences, common errors, and debugging context. Essentially, "explain what this code does and how it fits into the bigger picture."

2. **Identify the Core Subject:** The filename `bidirectional_stream_test.cc` immediately points to the central entity being tested: `BidirectionalStream`. The `webtransport` directory confirms this is related to the WebTransport API.

3. **Recognize the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` strongly indicates this is a unit test file using the Google Test framework. This is crucial because it tells us the file's primary purpose is *verification* of the `BidirectionalStream` class.

4. **Scan for Key Classes and Functions:**  A quick scan reveals several important elements:
    * **`#include` directives:** These tell us the dependencies and related classes. We see includes for `BidirectionalStream`, Mojo bindings (`network/public/mojom/web_transport.mojom-blink.h`), streams (`core/streams/...`), typed arrays, and test utilities.
    * **`namespace blink { namespace { ... } }`:** This isolates the test code and avoids naming conflicts.
    * **`StubWebTransport`:** This is a custom mock or stub implementation of the `network::mojom::blink::WebTransport` interface. This is *very* important. It means the tests aren't interacting with the *real* network layer but a simplified version for controlled testing.
    * **`ScopedWebTransport`:** This appears to be a helper class to manage the setup and teardown of the `WebTransport` and its stub within the tests.
    * **`TEST(BidirectionalStreamTest, ...)`:** These are the individual test cases, each focusing on a specific aspect of `BidirectionalStream` behavior. The names of the tests are informative (e.g., `CreateLocallyAndWrite`, `IncomingStreamCleanClose`).
    * **Functions like `TestWrite` and `TestRead`:** These are helper functions to reduce code duplication in the tests.

5. **Analyze `StubWebTransport`:** This is the key to understanding *how* the tests work.
    * It implements the `network::mojom::blink::WebTransport` interface.
    * It uses Mojo data pipes (`mojo::ScopedDataPipeConsumerHandle`, `mojo::ScopedDataPipeProducerHandle`) to simulate data transfer.
    * It has boolean flags (`was_send_fin_called_`, `was_abort_stream_called_`) to track if certain methods were called.
    * The `CreateRemote()` method simulates a remote peer initiating a stream.

6. **Analyze `ScopedWebTransport`:** This class simplifies test setup:
    * It creates an instance of the `StubWebTransport`.
    * It provides methods like `CreateBidirectionalStream` and `RemoteCreateBidirectionalStream` that interact with the JavaScript API to create `BidirectionalStream` objects and then obtain the C++ representation.

7. **Examine Individual Test Cases:** Look at what each test case does:
    * **`CreateLocallyAndWrite` / `CreateRemotelyAndWrite`:** Test writing data to a locally/remotely initiated stream.
    * **`CreateLocallyAndRead` / `CreateRemotelyAndRead`:** Test reading data from a locally/remotely initiated stream.
    * **`IncomingStreamCleanClose` / `OutgoingStreamCleanClose`:** Test the behavior when one side closes the stream cleanly.
    * **`CloseWebTransport` / `RemoteDropWebTransport`:** Test what happens when the underlying `WebTransport` connection is closed or dropped.
    * **`WriteAfterCancellingIncoming` / `WriteAfterIncomingClosed`:** Test writing after the receiving side is cancelled or closed.
    * **`ReadAfterClosingOutgoing` / `ReadAfterAbortingOutgoing` / `ReadAfterOutgoingAborted`:** Test reading after the sending side is closed or aborted.

8. **Connect to Web Technologies:** Consider how these tests relate to JavaScript, HTML, and CSS.
    * **JavaScript:** The tests directly interact with the JavaScript API for WebTransport (e.g., `createBidirectionalStream`, `writable().getWriter()`, `readable().read()`). The `ScriptPromiseTester` class highlights the asynchronous nature of these operations.
    * **HTML:** WebTransport is typically initiated from JavaScript within a web page loaded in an HTML document. The tests simulate this by creating the necessary JavaScript environment (`V8TestingScope`).
    * **CSS:** CSS is not directly related to the core functionality of WebTransport or these tests.

9. **Infer Logical Reasoning:**  The tests demonstrate logical deductions about how the `BidirectionalStream` should behave in various scenarios:
    * If you write data to the writable side, it should appear on the consumer end of the data pipe.
    * If the incoming side is closed, reading should eventually return a "done" signal.
    * If the underlying WebTransport is closed, the streams should become errored.

10. **Identify Potential Errors:**  Think about how a developer might misuse the WebTransport API and how these tests could catch such errors. For example, writing to a closed stream, reading from a cancelled stream, or not handling asynchronous operations correctly.

11. **Consider the Debugging Context:** How would a developer end up looking at this file?  Most likely, when investigating a bug related to `BidirectionalStream` functionality. This file provides concrete examples and expected behavior to compare against.

12. **Structure the Explanation:** Organize the findings into logical categories as requested: functionality, relationship to web technologies, logical inferences, common errors, and debugging context. Use clear and concise language. Provide specific code examples where possible.

13. **Review and Refine:**  Read through the explanation to ensure accuracy, clarity, and completeness. Check if all parts of the original request have been addressed.

This detailed thought process, starting with high-level understanding and progressively drilling down into the code, allows for a comprehensive and accurate analysis of the test file. The focus on understanding the mocking/stubbing mechanism is crucial for grasping the test's purpose and limitations.
这个文件 `bidirectional_stream_test.cc` 是 Chromium Blink 引擎中用于测试 `BidirectionalStream` 类的单元测试文件。`BidirectionalStream` 是 WebTransport API 的一个核心概念，它允许在客户端和服务器之间建立双向的数据流通道。

**主要功能:**

1. **测试 `BidirectionalStream` 的创建:**  测试通过 WebTransport API 在 JavaScript 中创建 `BidirectionalStream` 对象的功能，包括本地创建和模拟远程创建。
2. **测试数据写入 (`writable` 侧):** 验证可以通过 `BidirectionalStream` 的 `writable` 属性获取到的 `WritableStream` 对象向流中写入数据的功能。测试将数据写入流，并验证数据是否正确地通过底层的 Mojo 数据管道传递。
3. **测试数据读取 (`readable` 侧):**  验证可以通过 `BidirectionalStream` 的 `readable` 属性获取到的 `ReadableStream` 对象从流中读取数据的功能。测试向底层的 Mojo 数据管道写入数据，并验证 JavaScript 可以正确地读取到这些数据。
4. **测试流的关闭和中止:**  测试在各种场景下关闭和中止 `BidirectionalStream` 的行为，包括本地发起关闭、远程发起关闭、以及通过 `WebTransport` 对象关闭连接。
5. **测试流状态变化:** 验证当流被关闭或中止时，`readable` 和 `writable` 端的 `IsErrored()` 等状态是否正确更新。
6. **测试 WebTransport 连接的关闭和断开的影响:** 测试当底层的 `WebTransport` 连接被关闭或远程断开时，`BidirectionalStream` 的状态和行为。
7. **测试在不同操作顺序下的行为:** 例如，在取消读取端之后写入数据，或者在关闭写入端之后读取数据。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件是用来验证 WebTransport API 在 Blink 引擎中的实现，而 WebTransport API 是一个 JavaScript API，用于在 Web 浏览器和服务器之间进行低延迟的双向通信。

* **JavaScript:**  测试代码模拟了 JavaScript 中使用 `WebTransport` API 创建和操作 `BidirectionalStream` 的过程。例如，测试中会调用 `webTransport.createBidirectionalStream()` 方法，并操作返回的 `BidirectionalStream` 对象的 `readable` 和 `writable` 属性，这些属性对应 JavaScript 中的 `ReadableStream` 和 `WritableStream` 对象。

   **举例说明:**
   ```javascript
   // JavaScript 代码 (模拟)
   const transport = new WebTransport("https://example.com");
   await transport.ready;
   const bidirectionalStream = await transport.createBidirectionalStream();
   const writer = bidirectionalStream.writable.getWriter();
   writer.write(new Uint8Array([65])); // 'A'
   await writer.close();

   const reader = bidirectionalStream.readable.getReader();
   const { value, done } = await reader.read();
   console.log(value); // 可能输出 Uint8Array [66]
   ```
   测试文件中的代码，例如 `scoped_web_transport.CreateBidirectionalStream(scope)` 和 `bidirectional_stream->writable()->getWriter(...)`，就是在 C++ 层面模拟和验证上述 JavaScript 代码的行为。

* **HTML:**  虽然这个测试文件本身不涉及 HTML，但 WebTransport API 是在 Web 页面中使用 JavaScript 通过 HTML 加载的。HTML 提供了运行 JavaScript 的环境，从而可以使用 WebTransport。

* **CSS:** CSS 与 WebTransport 的核心功能没有直接关系。CSS 主要负责网页的样式和布局。

**逻辑推理 (假设输入与输出):**

假设我们测试写入数据的功能 (`CreateLocallyAndWrite` 测试用例):

* **假设输入:**
    1. 创建了一个 `BidirectionalStream` 对象。
    2. 获取了其 `writable` 端的 `WritableStream` 的 `writer`。
    3. 准备写入一个包含字符 'A' 的 `Uint8Array`。
* **逻辑推理:**
    1. 调用 `writer.write()` 应该将数据发送到 WebTransport 连接的另一端。
    2. 底层的 Mojo 数据管道应该接收到该数据。
* **预期输出:**
    1. `writer.write()` 返回的 Promise 应该成功 fulfilled。
    2. 通过 `scoped_web_transport->Stub()->OutputConsumer()` 获取的 Mojo 数据管道的消费者端应该可以读取到包含 'A' 的数据。

**用户或编程常见的使用错误 (举例说明):**

1. **在流关闭后尝试写入:** 用户可能会在调用 `writable.close()` 或流被远程关闭后，仍然尝试调用 `writer.write()` 写入数据。测试会验证这种情况是否会抛出错误或导致未定义的行为。
   ```javascript
   const writer = bidirectionalStream.writable.getWriter();
   await writer.close();
   try {
     await writer.write(new Uint8Array([65])); // 错误: 流已关闭
   } catch (e) {
     console.error(e);
   }
   ```
2. **在流关闭后尝试读取:** 类似于写入，用户可能会在 `readable` 端关闭后尝试调用 `reader.read()`。测试会验证这种情况。
   ```javascript
   const reader = bidirectionalStream.readable.getReader();
   await reader.cancel(); // 或者远程关闭
   const { value, done } = await reader.read(); // done 应该为 true
   ```
3. **没有正确处理 Promise:** WebTransport 的许多操作是异步的，依赖于 Promise。用户可能没有正确地使用 `await` 或 `.then()` 来处理 Promise 的结果，导致程序逻辑错误。测试中的 `ScriptPromiseTester` 就是用于辅助验证 Promise 的状态。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个使用了 WebTransport API 的网页。**
2. **网页中的 JavaScript 代码调用 `new WebTransport(url)` 来建立与服务器的连接。**
3. **连接建立成功后，JavaScript 代码调用 `transport.createBidirectionalStream()` 来创建一个双向流。**
4. **在 JavaScript 中，用户可能通过 `bidirectionalStream.writable.getWriter().write(data)` 向流中发送数据。**
5. **或者，用户可能通过 `bidirectionalStream.readable.getReader().read()` 从流中接收数据。**
6. **如果在上述任何步骤中出现了问题，例如数据没有正确发送或接收，或者流的状态异常，开发人员可能会开始调试。**
7. **作为调试的一部分，开发人员可能会查看 Blink 引擎的源代码，包括 `bidirectional_stream_test.cc` 文件，以了解 `BidirectionalStream` 类的预期行为以及如何进行测试。**
8. **如果怀疑问题出在 `BidirectionalStream` 类的实现上，开发人员可能会运行相关的单元测试，例如 `CreateLocallyAndWrite` 或 `CreateRemotelyAndRead`，来验证该类的基本功能是否正常。**
9. **如果测试失败，开发人员可以使用调试器来跟踪代码执行，查看变量的值，并找出错误的原因。**
10. **例如，如果 `CreateLocallyAndWrite` 测试失败，开发人员可能会检查 `StubWebTransport` 类中的 `OutputConsumer()` 是否正确接收到了写入的数据，或者 `BidirectionalStream` 对象内部的状态是否正确。**

总而言之，`bidirectional_stream_test.cc` 是 Blink 引擎中保证 WebTransport API 的 `BidirectionalStream` 功能正确性的重要组成部分。它通过模拟各种场景和用户操作，验证了该类的行为是否符合预期，并帮助开发人员发现和修复潜在的错误。

### 提示词
```
这是目录为blink/renderer/modules/webtransport/bidirectional_stream_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/webtransport/bidirectional_stream.h"

#include <memory>
#include <utility>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/notreached.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "services/network/public/mojom/web_transport.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/webtransport/web_transport_connector.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/iterable.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_bidirectional_stream.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_web_transport_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_default_reader.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/webtransport/test_utils.h"
#include "third_party/blink/renderer/modules/webtransport/web_transport.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

// These tests only ever create one stream at a time, so use a hardcoded stream
// id.
constexpr uint32_t kDefaultStreamId = 0;

// BidirectionalStream depends on blink::WebTransport. Rather than virtualise
// blink::WebTransport for these tests, we use a stub implementation of
// network::mojom::blink::WebTransport to get the behaviour we want. This class
// only supports the creation of one BidirectionalStream at a time for
// simplicity.
class StubWebTransport : public network::mojom::blink::WebTransport {
 public:
  explicit StubWebTransport(
      mojo::PendingReceiver<network::mojom::blink::WebTransport>
          pending_receiver)
      : receiver_(this, std::move(pending_receiver)) {}

  // Functions used by tests to inspect and manipulate the object.

  // Data written to the |writable| side of the bidirectional stream can be read
  // from this handle.
  mojo::ScopedDataPipeConsumerHandle& OutputConsumer() {
    return output_consumer_;
  }

  // Data written to this handle will appear on the |readable| side of the
  // bidirectional stream.
  mojo::ScopedDataPipeProducerHandle& InputProducer() {
    return input_producer_;
  }

  bool WasSendFinCalled() const { return was_send_fin_called_; }
  bool WasAbortStreamCalled() const { return was_abort_stream_called_; }

  // Responds to an earlier call to AcceptBidirectionalStream with a new stream
  // as if it was created by the remote server. The remote handles can be
  // accessed via OutputConsumer() and InputConsumer() as with locally-created
  // streams.
  void CreateRemote() {
    ASSERT_TRUE(accept_callback_);
    mojo::ScopedDataPipeProducerHandle output_producer;
    mojo::ScopedDataPipeConsumerHandle output_consumer;

    ASSERT_TRUE(
        CreateDataPipeForWebTransportTests(&output_producer, &output_consumer));
    output_consumer_ = std::move(output_consumer);

    mojo::ScopedDataPipeProducerHandle input_producer;
    mojo::ScopedDataPipeConsumerHandle input_consumer;

    ASSERT_TRUE(
        CreateDataPipeForWebTransportTests(&input_producer, &input_consumer));
    input_producer_ = std::move(input_producer);

    std::move(accept_callback_)
        .Run(kDefaultStreamId, std::move(input_consumer),
             std::move(output_producer));

    // This prevents redundant calls to AcceptBidirectionalStream() by ensuring
    // the call to Enqueue() happens before the next call to pull().
    test::RunPendingTasks();
  }

  // Implementation of WebTransport.
  void SendDatagram(base::span<const uint8_t> data,
                    base::OnceCallback<void(bool)>) override {
    NOTREACHED();
  }

  void CreateStream(
      mojo::ScopedDataPipeConsumerHandle output_consumer,
      mojo::ScopedDataPipeProducerHandle input_producer,
      base::OnceCallback<void(bool, uint32_t)> callback) override {
    EXPECT_TRUE(output_consumer.is_valid());
    EXPECT_FALSE(output_consumer_.is_valid());
    output_consumer_ = std::move(output_consumer);

    EXPECT_TRUE(input_producer.is_valid());
    EXPECT_FALSE(input_producer_.is_valid());
    input_producer_ = std::move(input_producer);

    std::move(callback).Run(true, kDefaultStreamId);
  }

  void AcceptBidirectionalStream(
      base::OnceCallback<void(uint32_t,
                              mojo::ScopedDataPipeConsumerHandle,
                              mojo::ScopedDataPipeProducerHandle)> callback)
      override {
    DCHECK(!accept_callback_);
    accept_callback_ = std::move(callback);
  }

  void AcceptUnidirectionalStream(
      base::OnceCallback<void(uint32_t, mojo::ScopedDataPipeConsumerHandle)>
          callback) override {
    DCHECK(!ignored_unidirectional_stream_callback_);
    // This method is always called. We have to retain the callback to avoid an
    // error about early destruction, but never call it.
    ignored_unidirectional_stream_callback_ = std::move(callback);
  }

  void SendFin(uint32_t stream_id) override {
    EXPECT_EQ(stream_id, kDefaultStreamId);
    was_send_fin_called_ = true;
  }

  void AbortStream(uint32_t stream_id, uint8_t code) override {
    EXPECT_EQ(stream_id, kDefaultStreamId);
    was_abort_stream_called_ = true;
  }

  void StopSending(uint32_t stream_id, uint8_t code) override {
    // TODO(ricea): Record that this was called when a test needs it.
  }

  void SetOutgoingDatagramExpirationDuration(base::TimeDelta) override {}

  void GetStats(GetStatsCallback callback) override {
    std::move(callback).Run(nullptr);
  }

  void Close(network::mojom::blink::WebTransportCloseInfoPtr) override {}

 private:
  base::OnceCallback<void(uint32_t,
                          mojo::ScopedDataPipeConsumerHandle,
                          mojo::ScopedDataPipeProducerHandle)>
      accept_callback_;
  base::OnceCallback<void(uint32_t, mojo::ScopedDataPipeConsumerHandle)>
      ignored_unidirectional_stream_callback_;
  mojo::Receiver<network::mojom::blink::WebTransport> receiver_;
  mojo::ScopedDataPipeConsumerHandle output_consumer_;
  mojo::ScopedDataPipeProducerHandle input_producer_;
  bool was_send_fin_called_ = false;
  bool was_abort_stream_called_ = false;
};

// This class sets up a connected blink::WebTransport object using a
// StubWebTransport and provides access to both.
class ScopedWebTransport {
  STACK_ALLOCATED();

 public:
  // This constructor runs the event loop.
  explicit ScopedWebTransport(const V8TestingScope& scope) {
    creator_.Init(scope.GetScriptState(),
                  WTF::BindRepeating(&ScopedWebTransport::CreateStub,
                            weak_ptr_factory_.GetWeakPtr()));
  }

  WebTransport* GetWebTransport() const { return creator_.GetWebTransport(); }
  StubWebTransport* Stub() const { return stub_.get(); }

  void ResetCreator() { creator_.Reset(); }
  void ResetStub() { stub_.reset(); }

  BidirectionalStream* CreateBidirectionalStream(const V8TestingScope& scope) {
    auto* script_state = scope.GetScriptState();
    auto bidirectional_stream_promise =
        GetWebTransport()->createBidirectionalStream(script_state,
                                                     ASSERT_NO_EXCEPTION);
    ScriptPromiseTester tester(script_state, bidirectional_stream_promise);

    tester.WaitUntilSettled();

    EXPECT_TRUE(tester.IsFulfilled());
    auto* bidirectional_stream = V8WebTransportBidirectionalStream::ToWrappable(
        scope.GetIsolate(), tester.Value().V8Value());
    EXPECT_TRUE(bidirectional_stream);
    return bidirectional_stream;
  }

  BidirectionalStream* RemoteCreateBidirectionalStream(
      const V8TestingScope& scope) {
    stub_->CreateRemote();
    ReadableStream* streams = GetWebTransport()->incomingBidirectionalStreams();

    v8::Local<v8::Value> v8value = ReadValueFromStream(scope, streams);

    BidirectionalStream* bidirectional_stream =
        V8WebTransportBidirectionalStream::ToWrappable(scope.GetIsolate(),
                                                       v8value);
    EXPECT_TRUE(bidirectional_stream);

    return bidirectional_stream;
  }

 private:
  void CreateStub(mojo::PendingRemote<network::mojom::blink::WebTransport>&
                      web_transport_to_pass) {
    stub_ = std::make_unique<StubWebTransport>(
        web_transport_to_pass.InitWithNewPipeAndPassReceiver());
  }

  TestWebTransportCreator creator_;
  std::unique_ptr<StubWebTransport> stub_;

  base::WeakPtrFactory<ScopedWebTransport> weak_ptr_factory_{this};
};

// This test fragment is common to CreateLocallyAndWrite and
// CreateRemotelyAndWrite.
void TestWrite(const V8TestingScope& scope,
               ScopedWebTransport* scoped_web_transport,
               BidirectionalStream* bidirectional_stream) {
  auto* script_state = scope.GetScriptState();
  auto* writer = bidirectional_stream->writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMUint8Array::Create(1);
  *chunk->Data() = 'A';
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_TRUE(tester.Value().IsUndefined());

  mojo::ScopedDataPipeConsumerHandle& output_consumer =
      scoped_web_transport->Stub()->OutputConsumer();
  base::span<const uint8_t> buffer;
  MojoResult mojo_result =
      output_consumer->BeginReadData(MOJO_BEGIN_READ_DATA_FLAG_NONE, buffer);

  ASSERT_EQ(mojo_result, MOJO_RESULT_OK);
  EXPECT_EQ(buffer.size(), 1u);
  EXPECT_EQ(base::as_string_view(buffer), "A");

  output_consumer->EndReadData(buffer.size());
}

TEST(BidirectionalStreamTest, CreateLocallyAndWrite) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  TestWrite(scope, &scoped_web_transport, bidirectional_stream);
}

TEST(BidirectionalStreamTest, CreateRemotelyAndWrite) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.RemoteCreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  TestWrite(scope, &scoped_web_transport, bidirectional_stream);
}

// This test fragment is common to CreateLocallyAndRead and
// CreateRemotelyAndRead.
void TestRead(V8TestingScope& scope,
              ScopedWebTransport* scoped_web_transport,
              BidirectionalStream* bidirectional_stream) {
  mojo::ScopedDataPipeProducerHandle& input_producer =
      scoped_web_transport->Stub()->InputProducer();
  MojoResult mojo_result =
      input_producer->WriteAllData(base::as_byte_span(std::string_view("B")));

  ASSERT_EQ(mojo_result, MOJO_RESULT_OK);

  v8::Local<v8::Value> v8array =
      ReadValueFromStream(scope, bidirectional_stream->readable());
  NotShared<DOMUint8Array> u8array =
      NativeValueTraits<NotShared<DOMUint8Array>>::NativeValue(
          scope.GetIsolate(), v8array, scope.GetExceptionState());
  ASSERT_TRUE(u8array);

  ASSERT_EQ(u8array->byteLength(), 1u);
  EXPECT_EQ(reinterpret_cast<char*>(u8array->Data())[0], 'B');
}

TEST(BidirectionalStreamTest, CreateLocallyAndRead) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  TestRead(scope, &scoped_web_transport, bidirectional_stream);
}

TEST(BidirectionalStreamTest, CreateRemotelyAndRead) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.RemoteCreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  TestRead(scope, &scoped_web_transport, bidirectional_stream);
}

TEST(BidirectionalStreamTest, IncomingStreamCleanClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  scoped_web_transport.GetWebTransport()->OnIncomingStreamClosed(
      kDefaultStreamId, true);
  scoped_web_transport.Stub()->InputProducer().reset();

  auto* script_state = scope.GetScriptState();
  auto* reader = bidirectional_stream->readable()->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);

  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester read_tester(script_state, read_promise);
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsFulfilled());

  v8::Local<v8::Value> result = read_tester.Value().V8Value();
  DCHECK(result->IsObject());
  v8::Local<v8::Value> v8value;
  bool done = false;
  EXPECT_TRUE(V8UnpackIterationResult(script_state, result.As<v8::Object>(),
                                      &v8value, &done));
  EXPECT_TRUE(done);
}

TEST(BidirectionalStreamTest, OutgoingStreamCleanClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  auto* script_state = scope.GetScriptState();
  auto close_promise = bidirectional_stream->writable()->close(
      script_state, ASSERT_NO_EXCEPTION);

  scoped_web_transport.GetWebTransport()->OnOutgoingStreamClosed(
      kDefaultStreamId);

  ScriptPromiseTester close_tester(script_state, close_promise);
  close_tester.WaitUntilSettled();
  EXPECT_TRUE(close_tester.IsFulfilled());

  // The incoming side is closed by the network service.
  scoped_web_transport.GetWebTransport()->OnIncomingStreamClosed(
      kDefaultStreamId, false);
  scoped_web_transport.Stub()->InputProducer().reset();

  const auto* const stub = scoped_web_transport.Stub();
  EXPECT_TRUE(stub->WasSendFinCalled());
  EXPECT_FALSE(stub->WasAbortStreamCalled());
}

TEST(BidirectionalStreamTest, CloseWebTransport) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  scoped_web_transport.GetWebTransport()->close(nullptr);

  EXPECT_TRUE(bidirectional_stream->readable()->IsErrored());
  EXPECT_TRUE(bidirectional_stream->writable()->IsErrored());
}

TEST(BidirectionalStreamTest, RemoteDropWebTransport) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  scoped_web_transport.ResetCreator();

  test::RunPendingTasks();

  EXPECT_TRUE(bidirectional_stream->readable()->IsErrored());
  EXPECT_TRUE(bidirectional_stream->writable()->IsErrored());
}

TEST(BidirectionalStreamTest, WriteAfterCancellingIncoming) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  auto* script_state = scope.GetScriptState();
  auto cancel_promise = bidirectional_stream->readable()->cancel(
      script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester cancel_tester(script_state, cancel_promise);
  cancel_tester.WaitUntilSettled();
  EXPECT_TRUE(cancel_tester.IsFulfilled());

  TestWrite(scope, &scoped_web_transport, bidirectional_stream);

  scoped_web_transport.ResetStub();
  test::RunPendingTasks();
}

TEST(BidirectionalStreamTest, WriteAfterIncomingClosed) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  scoped_web_transport.GetWebTransport()->OnIncomingStreamClosed(
      kDefaultStreamId, true);
  scoped_web_transport.Stub()->InputProducer().reset();

  test::RunPendingTasks();

  TestWrite(scope, &scoped_web_transport, bidirectional_stream);

  scoped_web_transport.ResetStub();
  test::RunPendingTasks();
}

TEST(BidirectionalStreamTest, ReadAfterClosingOutgoing) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  auto* script_state = scope.GetScriptState();
  auto close_promise = bidirectional_stream->writable()->close(
      script_state, ASSERT_NO_EXCEPTION);

  scoped_web_transport.GetWebTransport()->OnOutgoingStreamClosed(
      kDefaultStreamId);

  ScriptPromiseTester close_tester(script_state, close_promise);
  close_tester.WaitUntilSettled();
  EXPECT_TRUE(close_tester.IsFulfilled());

  TestRead(scope, &scoped_web_transport, bidirectional_stream);
}

TEST(BidirectionalStreamTest, ReadAfterAbortingOutgoing) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  auto* script_state = scope.GetScriptState();
  auto abort_promise = bidirectional_stream->writable()->abort(
      script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester abort_tester(script_state, abort_promise);
  abort_tester.WaitUntilSettled();
  EXPECT_TRUE(abort_tester.IsFulfilled());

  TestRead(scope, &scoped_web_transport, bidirectional_stream);
}

TEST(BidirectionalStreamTest, ReadAfterOutgoingAborted) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScopedWebTransport scoped_web_transport(scope);
  auto* bidirectional_stream =
      scoped_web_transport.CreateBidirectionalStream(scope);
  ASSERT_TRUE(bidirectional_stream);

  scoped_web_transport.Stub()->OutputConsumer().reset();
  test::RunPendingTasks();

  TestRead(scope, &scoped_web_transport, bidirectional_stream);
}

}  // namespace

}  // namespace blink
```