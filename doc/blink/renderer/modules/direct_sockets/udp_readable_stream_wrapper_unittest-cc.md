Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Functionality:** The file name `udp_readable_stream_wrapper_unittest.cc` immediately suggests this code is testing the `UDPReadableStreamWrapper` class. The "unittest" suffix is a strong indicator.

2. **Examine the Includes:** The included headers provide crucial context:
    * `udp_readable_stream_wrapper.h`:  This confirms the class under test.
    * `base/containers/span.h`, `base/functional/callback_helpers.h`, `base/notreached.h`: Basic utility and assertion mechanisms.
    * `mojo/public/cpp/bindings/...`: Indicates interaction with the Mojo IPC system. This is key for understanding how Blink communicates with other processes (like the network service).
    * `net/base/net_errors.h`:  Network error codes, relevant for handling connection issues.
    * `services/network/public/mojom/...`:  Defines the Mojo interfaces for interacting with the network service, specifically UDP sockets.
    * `third_party/blink/renderer/bindings/...`:  Headers related to the JavaScript bindings (V8 integration). This is where the connection to JavaScript/web APIs will be found.
    * `third_party/blink/renderer/core/streams/...`:  Core Blink streaming API, likely the base class for `UDPReadableStreamWrapper`.
    * `third_party/blink/renderer/core/typed_arrays/...`: Handling of binary data (ArrayBuffers).
    * `third_party/blink/renderer/modules/direct_sockets/...`: The module this class belongs to, hinting at functionality related to low-level socket access.
    * `third_party/blink/renderer/platform/...`: Platform-specific utilities, including testing helpers.

3. **Analyze the Test Structure:**  The `namespace blink { namespace { ... } }` structure is standard for Chromium C++ unittests, isolating the test code. The `TEST(UDPReadableStreamWrapperTest, ...)` macros define individual test cases.

4. **Understand the Test Fixtures (Helper Classes):**
    * `FakeRestrictedUDPSocket`: This is a mock implementation of the `network::mojom::blink::RestrictedUDPSocket` interface. It simulates the behavior of a real UDP socket, allowing the tests to control the data received. This is crucial for isolated unit testing.
    * `StreamCreator`: This helper class simplifies the creation of `UDPReadableStreamWrapper` instances for the tests, handling the necessary setup with the mock socket and Mojo bindings. The `ScopedStreamCreator` further automates cleanup.

5. **Dissect Individual Tests:** For each `TEST` function:
    * **`Create`:**  Verifies that an instance of `UDPReadableStreamWrapper` can be created successfully and that its `Readable()` method returns a truthy value (indicating it has a readable stream).
    * **`ReadUdpMessage`:** Tests the basic read functionality. It sends data through the mock socket and checks if the `UDPReadableStreamWrapper` correctly receives and unpacks it. The `UnpackPromiseResult` function is key here – it emulates how JavaScript would interact with the stream reader.
    * **`ReadDelayedUdpMessage`:** Similar to `ReadUdpMessage`, but the data is provided *after* the read operation has started, testing asynchronous behavior.
    * **`ReadEmptyUdpMessage`:** Tests the handling of empty UDP datagrams.
    * **`CancelStreamFromReader`:** Checks the behavior when the readable stream is cancelled from the JavaScript side. It verifies that subsequent reads return a "done" signal.
    * **`ReadRejectsOnError`:** Tests error handling. It simulates an error on the underlying socket and verifies that the read operation on the stream is rejected.

6. **Identify the JavaScript Connection:**  The key lies in:
    * The inclusion of binding-related headers (`third_party/blink/renderer/bindings/...`).
    * The use of `ScriptPromise` and `ScriptPromiseTester`, which are used to interact with JavaScript promises.
    * The `UnpackPromiseResult` function, which mimics the JavaScript code `let { value, done } = await reader.read();`.
    * The interaction with `ReadableStream` and its `GetDefaultReaderForTesting` method.
    * The instantiation of `UDPReadableStreamWrapper` likely happens in response to a JavaScript API call (though this specific file doesn't show that call).

7. **Infer the User Interaction:** Based on the functionality, the user interaction likely involves JavaScript code using a web API that exposes UDP socket functionality. The `direct_sockets` module name strongly suggests a newer or experimental API providing more direct socket control.

8. **Consider Potential Errors:** Analyze the tests for what could go wrong. Things like:
    * Not providing enough data.
    * Providing data in the wrong format.
    * Network errors occurring.
    * Attempting to read after the stream is closed or errored.

9. **Structure the Explanation:** Organize the findings into logical categories as requested by the prompt (functionality, JavaScript/HTML/CSS relation, logic, errors, debugging). Use clear and concise language.

10. **Review and Refine:** Read through the explanation, ensuring accuracy and completeness. Double-check assumptions and inferences. For example, initially, one might think this is directly tied to a specific JavaScript API. However, the tests use `GetDefaultReaderForTesting`, implying a more internal testing mechanism. While the *intent* is to support a JavaScript API, this specific test file focuses on the C++ implementation details. This nuance is important.

This detailed analysis of the code structure, included headers, and test cases allows for a comprehensive understanding of the file's purpose and its connection to the wider Chromium and web platform.这个文件 `udp_readable_stream_wrapper_unittest.cc` 是 Chromium Blink 引擎中 `direct_sockets` 模块的一部分，专门用于测试 `UDPReadableStreamWrapper` 类的功能。 `UDPReadableStreamWrapper` 的作用是将底层的 UDP socket 数据流包装成一个可读的流 (ReadableStream)，使其能够在 JavaScript 中以流的方式被消费。

以下是该文件的详细功能分解：

**核心功能:**

1. **单元测试 `UDPReadableStreamWrapper`:** 该文件包含了多个单元测试，用于验证 `UDPReadableStreamWrapper` 类的各种行为是否符合预期。这些测试覆盖了诸如创建流、读取数据、处理空数据、取消流以及处理错误等场景。

2. **模拟 UDP Socket 行为:**  文件中定义了一个名为 `FakeRestrictedUDPSocket` 的类，它模拟了真实的受限 UDP socket 的行为。这个模拟类允许测试在不依赖实际网络连接的情况下进行，提高了测试的可靠性和速度。它可以模拟接收数据，并允许测试代码控制何时以及如何提供数据。

3. **测试数据读取:** 测试用例验证了从 `UDPReadableStreamWrapper` 创建的 ReadableStream 中读取数据的能力。它模拟了 UDP socket 接收到数据的情况，并检查 JavaScript 端是否能够成功读取到这些数据。

4. **测试流的生命周期管理:**  测试用例涵盖了流的创建、读取、取消和错误处理等生命周期阶段。例如，测试用例 `CancelStreamFromReader` 验证了当 JavaScript 端取消可读流时，底层资源是否被正确释放。

5. **与 JavaScript ReadableStream 的集成测试:** 虽然这个文件是 C++ 代码，但它的目的是测试一个用于连接 C++ UDP socket 和 JavaScript ReadableStream 的桥梁。测试用例通过模拟 JavaScript 的流操作（如 `reader.read()` 和 `reader.cancel()`）来验证 C++ 端的实现。

**与 JavaScript, HTML, CSS 的关系：**

这个文件直接关系到 **JavaScript** 中的 `ReadableStream` API 和可能存在的用于访问 UDP socket 的 JavaScript API (尽管目前浏览器的标准 Web API 中并没有直接操作 UDP socket 的能力，`direct_sockets` 模块可能是一个实验性或内部使用的特性)。

* **JavaScript `ReadableStream`:**  `UDPReadableStreamWrapper` 的目标就是创建一个可以在 JavaScript 中使用的 `ReadableStream` 对象。JavaScript 代码可以使用 `getReader()` 方法获取一个 `ReadableStreamDefaultReader`，然后调用 `read()` 方法来异步地读取从 UDP socket 接收到的数据。

**举例说明:**

假设有一个 JavaScript API (目前是假设的，因为标准浏览器 API 中没有直接的 UDP socket API) 允许创建一个 UDP socket 并返回其可读流：

```javascript
// 假设的 JavaScript API
const udpSocket = await navigator.directSockets.createUDPSocket({ /* 配置 */ });
const readableStream = udpSocket.readable;
const reader = readableStream.getReader();

async function readData() {
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      console.log("UDP stream closed");
      break;
    }
    // `value` 将是一个包含 UDP 数据的对象，可能包含数据本身和发送者信息
    console.log("Received UDP data:", value);
  }
}

readData();
```

在这个假设的场景中，`UDPReadableStreamWrapper` 的作用就是在 C++ 层将底层的 UDP socket 数据转换为可以被 JavaScript `ReadableStream` 理解和消费的数据块。

**逻辑推理与假设输入输出:**

**假设输入:**  `FakeRestrictedUDPSocket` 模拟接收到一段包含 "test data" 字符串的 UDP 数据报。

**C++ 逻辑:** `UDPReadableStreamWrapper` 接收到 `OnReceived` 事件，将数据封装成 `UDPMessage` 对象，并通过 ReadableStream 的控制器将数据推送到 JavaScript 端。

**JavaScript 端输出:**  调用 `reader.read()` 返回的 Promise 会 resolve，其 `value` 属性将包含一个 `UDPMessage` 对象，该对象的 `data` 属性 (可能是 `Uint8Array`) 包含 "test data" 的字节表示。

**用户或编程常见的使用错误:**

1. **过早关闭或销毁 Socket:** 如果在 JavaScript 端持有 `ReadableStreamReader` 的情况下，底层的 UDP socket 被过早关闭或销毁，可能会导致流读取失败或程序崩溃。`UDPReadableStreamWrapper` 需要妥善处理这种情况，并通知 JavaScript 端流已关闭。

2. **不正确地处理流的错误:** JavaScript 端需要正确监听和处理 `ReadableStream` 上的错误事件。如果 UDP socket 发生错误（例如网络连接中断），`UDPReadableStreamWrapper` 需要将错误传递到 JavaScript 端，以便应用程序能够采取适当的措施。

3. **在流关闭后尝试读取:**  如果在 `ReadableStream` 已经关闭或发生错误后，JavaScript 代码仍然尝试调用 `reader.read()`，将会得到一个 resolved 的 Promise，其 `done` 属性为 `true`。开发者需要正确处理这种情况，避免无限循环或错误访问。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户交互触发 JavaScript 代码:** 用户在网页上的操作（例如点击按钮、输入信息等）可能会触发 JavaScript 代码执行。

2. **JavaScript 调用 `direct_sockets` API:**  假设存在一个 JavaScript API 用于创建和操作 UDP socket，JavaScript 代码会调用该 API 来创建一个 UDP socket 并获取其可读流。例如：
   ```javascript
   const socket = await navigator.experimental.createUDPSocket({ /* ... */ });
   const readableStream = socket.readable;
   ```

3. **Blink 引擎处理 API 调用:** 当 JavaScript 调用这个 API 时，Blink 引擎会接收到请求，并调用相应的 C++ 代码来创建底层的 UDP socket 资源。

4. **创建 `UDPReadableStreamWrapper`:** 在 C++ 代码中，为了将底层的 UDP socket 数据暴露给 JavaScript，会创建一个 `UDPReadableStreamWrapper` 对象，并将底层的 UDP socket 和一个 Mojo 管道连接到这个 wrapper。

5. **Mojo 通信:**  底层的 UDP socket 数据到达时，会通过 Mojo 管道通知 `UDPReadableStreamWrapper`。

6. **数据推送到 JavaScript `ReadableStream`:** `UDPReadableStreamWrapper` 接收到数据后，会将其封装并推送到与之关联的 JavaScript `ReadableStream` 中。

7. **JavaScript 读取流数据:** JavaScript 代码通过 `reader.read()` 方法从 `ReadableStream` 中读取数据。

**调试线索:**

* 如果在 JavaScript 端读取流数据时遇到问题，可以检查 C++ 端的 `UDPReadableStreamWrapper` 是否正确接收到了来自底层 UDP socket 的数据。
* 可以断点在 `FakeRestrictedUDPSocket::ProvideRequestedDatagrams()` 方法中，查看模拟的 UDP 数据是否被正确发送。
* 可以断点在 `UDPReadableStreamWrapper` 的相关方法中，例如处理 `OnReceived` 事件的方法，查看数据是否被正确封装和推送到 JavaScript 端。
* 使用 Chromium 的 tracing 工具 (chrome://tracing) 可以查看 Mojo 消息的传递过程，帮助理解数据如何在 C++ 和 JavaScript 之间流动。

总而言之，`udp_readable_stream_wrapper_unittest.cc` 是一个关键的测试文件，用于确保 Blink 引擎中将 UDP socket 数据转换为 JavaScript 可读流的功能能够正确可靠地工作。它模拟了各种场景，包括正常的数据接收、空数据、错误情况以及流的取消，以保证代码的健壮性。

Prompt: 
```
这是目录为blink/renderer/modules/direct_sockets/udp_readable_stream_wrapper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/direct_sockets/udp_readable_stream_wrapper.h"

#include "base/containers/span.h"
#include "base/functional/callback_helpers.h"
#include "base/notreached.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "net/base/net_errors.h"
#include "services/network/public/mojom/restricted_udp_socket.mojom-blink.h"
#include "services/network/public/mojom/udp_socket.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/iterable.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream_read_result.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_udp_message.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_piece.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/direct_sockets/stream_wrapper.h"
#include "third_party/blink/renderer/modules/direct_sockets/udp_writable_stream_wrapper.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/gc_plugin.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_uchar.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {
namespace {

class FakeRestrictedUDPSocket final
    : public GarbageCollected<FakeRestrictedUDPSocket>,
      public network::mojom::blink::RestrictedUDPSocket {
 public:
  explicit FakeRestrictedUDPSocket(ContextLifecycleNotifier* notifier)
      : remote_(notifier) {}
  void Send(base::span<const uint8_t> data, SendCallback callback) override {
    NOTREACHED();
  }

  void SendTo(base::span<const uint8_t> data,
              const net::HostPortPair& dest_addr,
              net::DnsQueryType dns_query_type,
              SendToCallback callback) override {
    NOTREACHED();
  }

  void ReceiveMore(uint32_t num_additional_datagrams) override {
    num_requested_datagrams += num_additional_datagrams;
  }

  void ProvideRequestedDatagrams() {
    DCHECK(remote_.is_bound());
    while (num_requested_datagrams > 0) {
      remote_->OnReceived(net::OK,
                          net::IPEndPoint{net::IPAddress::IPv4Localhost(), 0U},
                          datagram_.Span8());
      num_requested_datagrams--;
    }
  }

  void Bind(mojo::PendingRemote<network::mojom::blink::UDPSocketListener>
                pending_remote,
            scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    remote_.Bind(std::move(pending_remote), task_runner);
  }

  const String& GetTestingDatagram() const { return datagram_; }
  void SetTestingDatagram(String datagram) { datagram_ = std::move(datagram); }

  void Trace(Visitor* visitor) const { visitor->Trace(remote_); }

 private:
  HeapMojoRemote<network::mojom::blink::UDPSocketListener> remote_;
  uint32_t num_requested_datagrams = 0;
  String datagram_{"abcde"};
};

class StreamCreator : public GarbageCollected<StreamCreator> {
 public:
  explicit StreamCreator(const V8TestingScope& scope)
      : fake_udp_socket_(MakeGarbageCollected<FakeRestrictedUDPSocket>(
            scope.GetExecutionContext())),
        receiver_(fake_udp_socket_.Get(), scope.GetExecutionContext()) {}

  ~StreamCreator() = default;

  UDPReadableStreamWrapper* Create(V8TestingScope& scope) {
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        scope.GetExecutionContext()->GetTaskRunner(TaskType::kNetworking);
    auto* udp_socket =
        MakeGarbageCollected<UDPSocketMojoRemote>(scope.GetExecutionContext());
    udp_socket->get().Bind(receiver_.BindNewPipeAndPassRemote(task_runner),
                           task_runner);

    mojo::PendingReceiver<network::mojom::blink::UDPSocketListener> receiver;
    fake_udp_socket_->Bind(receiver.InitWithNewPipeAndPassRemote(),
                           task_runner);

    auto* script_state = scope.GetScriptState();
    stream_wrapper_ = MakeGarbageCollected<UDPReadableStreamWrapper>(
        script_state, base::DoNothing(), udp_socket, std::move(receiver));

    // Ensure that udp_socket->ReceiveMore(...) call from
    // UDPReadableStreamWrapper constructor completes.
    scope.PerformMicrotaskCheckpoint();
    test::RunPendingTasks();

    return stream_wrapper_.Get();
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(fake_udp_socket_);
    visitor->Trace(stream_wrapper_);
    visitor->Trace(receiver_);
  }

  FakeRestrictedUDPSocket& fake_udp_socket() { return *fake_udp_socket_; }

  void Cleanup() { receiver_.reset(); }

 private:
  Member<FakeRestrictedUDPSocket> fake_udp_socket_;
  Member<UDPReadableStreamWrapper> stream_wrapper_;

  HeapMojoReceiver<network::mojom::blink::RestrictedUDPSocket,
                   FakeRestrictedUDPSocket>
      receiver_;
};

class ScopedStreamCreator {
 public:
  explicit ScopedStreamCreator(StreamCreator* stream_creator)
      : stream_creator_(stream_creator) {}

  ~ScopedStreamCreator() { stream_creator_->Cleanup(); }

  StreamCreator* operator->() const { return stream_creator_; }

 private:
  Persistent<StreamCreator> stream_creator_;
};

std::pair<UDPMessage*, bool> UnpackPromiseResult(const V8TestingScope& scope,
                                                 v8::Local<v8::Value> result) {
  // js call looks like this:
  // let { value, done } = await reader.read();
  // So we have to unpack the iterator first.
  EXPECT_TRUE(result->IsObject());
  v8::Local<v8::Value> udp_message_packed;
  bool done = false;
  EXPECT_TRUE(V8UnpackIterationResult(scope.GetScriptState(),
                                      result.As<v8::Object>(),
                                      &udp_message_packed, &done));
  if (done) {
    return {nullptr, true};
  }
  auto* message = NativeValueTraits<UDPMessage>::NativeValue(
      scope.GetIsolate(), udp_message_packed, ASSERT_NO_EXCEPTION);

  return {message, false};
}

String UDPMessageDataToString(const UDPMessage* message) {
  DOMArrayPiece array_piece{message->data()};
  return String{array_piece.ByteSpan()};
}

TEST(UDPReadableStreamWrapperTest, Create) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_readable_stream_wrapper = stream_creator->Create(scope);

  EXPECT_TRUE(udp_readable_stream_wrapper->Readable());
}

TEST(UDPReadableStreamWrapperTest, ReadUdpMessage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));

  auto* udp_readable_stream_wrapper = stream_creator->Create(scope);
  auto& fake_udp_socket = stream_creator->fake_udp_socket();

  fake_udp_socket.ProvideRequestedDatagrams();

  auto* script_state = scope.GetScriptState();
  auto* reader =
      udp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state,
                             reader->read(script_state, ASSERT_NO_EXCEPTION));
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  auto [message, done] = UnpackPromiseResult(scope, tester.Value().V8Value());
  ASSERT_FALSE(done);
  ASSERT_TRUE(message->hasData());
  ASSERT_EQ(UDPMessageDataToString(message),
            fake_udp_socket.GetTestingDatagram());
}

TEST(UDPReadableStreamWrapperTest, ReadDelayedUdpMessage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_readable_stream_wrapper = stream_creator->Create(scope);

  auto& fake_udp_socket = stream_creator->fake_udp_socket();

  auto* script_state = scope.GetScriptState();
  auto* reader =
      udp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state,
                             reader->read(script_state, ASSERT_NO_EXCEPTION));

  fake_udp_socket.ProvideRequestedDatagrams();

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  auto [message, done] = UnpackPromiseResult(scope, tester.Value().V8Value());
  ASSERT_FALSE(done);
  ASSERT_TRUE(message->hasData());
  ASSERT_EQ(UDPMessageDataToString(message),
            fake_udp_socket.GetTestingDatagram());
}

TEST(UDPReadableStreamWrapperTest, ReadEmptyUdpMessage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_readable_stream_wrapper = stream_creator->Create(scope);

  // Send empty datagrams.
  auto& fake_udp_socket = stream_creator->fake_udp_socket();
  fake_udp_socket.SetTestingDatagram({});
  fake_udp_socket.ProvideRequestedDatagrams();

  auto* script_state = scope.GetScriptState();
  auto* reader =
      udp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state,
                             reader->read(script_state, ASSERT_NO_EXCEPTION));
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  auto [message, done] = UnpackPromiseResult(scope, tester.Value().V8Value());
  ASSERT_FALSE(done);
  ASSERT_TRUE(message->hasData());

  ASSERT_EQ(UDPMessageDataToString(message).length(), 0U);
}

TEST(UDPReadableStreamWrapperTest, CancelStreamFromReader) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* reader =
      udp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester cancel_tester(
      script_state, reader->cancel(script_state, ASSERT_NO_EXCEPTION));
  cancel_tester.WaitUntilSettled();
  EXPECT_TRUE(cancel_tester.IsFulfilled());

  ScriptPromiseTester read_tester(
      script_state, reader->read(script_state, ASSERT_NO_EXCEPTION));
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsFulfilled());

  auto [message, done] =
      UnpackPromiseResult(scope, read_tester.Value().V8Value());

  EXPECT_TRUE(done);
  EXPECT_FALSE(message);
}

TEST(UDPReadableStreamWrapperTest, ReadRejectsOnError) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_readable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* reader =
      udp_readable_stream_wrapper->Readable()->GetDefaultReaderForTesting(
          script_state, ASSERT_NO_EXCEPTION);

  udp_readable_stream_wrapper->ErrorStream(net::ERR_UNEXPECTED);

  ScriptPromiseTester read_tester(
      script_state, reader->read(script_state, ASSERT_NO_EXCEPTION));
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsRejected());
}

}  // namespace

}  // namespace blink

"""

```