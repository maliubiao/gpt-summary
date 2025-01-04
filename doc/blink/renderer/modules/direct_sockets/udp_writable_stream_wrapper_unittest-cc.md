Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding - File Name and Imports:**

* **File Name:** `udp_writable_stream_wrapper_unittest.cc`. The `_unittest.cc` suffix immediately signals this is a unit test file. The core class being tested is likely `UDPWritableStreamWrapper`. The `udp` and `writable_stream` parts hint at its purpose.
* **Includes:**  Looking at the includes gives significant clues:
    *  `udp_writable_stream_wrapper.h`:  Confirms the main class being tested.
    *  `base/containers/span.h`, `base/functional/bind.h`, etc.:  Basic Chromium/C++ utilities.
    *  `mojo/public/cpp/bindings/...`:  Indicates interaction with Mojo, Chromium's inter-process communication mechanism. This is crucial.
    *  `net/base/net_errors.h`:  Deals with network error codes.
    *  `services/network/public/mojom/...`:  More Mojo, specifically for network services. `RestrictedUDPSocket` is a key interface.
    *  `third_party/blink/renderer/bindings/...`:  Signals integration with Blink's JavaScript binding layer. Keywords like `ScriptPromise`, `V8...`, `DOMException` are strong indicators.
    *  `third_party/blink/renderer/core/dom/...`, `third_party/blink/renderer/core/streams/...`, `third_party/blink/renderer/core/typed_arrays/...`: Core Blink DOM and Streams API, including `WritableStream`.
    *  `third_party/blink/renderer/modules/direct_sockets/...`:  The module this class belongs to – direct sockets. This hints at lower-level network interaction exposed to web pages.
    *  `third_party/blink/renderer/platform/...`:  Platform-level Blink utilities and testing frameworks.
    *  `third_party/googletest/...`: Google Test framework, confirming this is a unit test file.

**2. Dissecting the Test Structure:**

* **Namespaces:** The code is within the `blink` namespace and an anonymous namespace. This is standard C++ practice.
* **Fake Classes:** The `FakeRestrictedUDPSocket` class immediately stands out. This is a mock object for testing. It intercepts calls to the real `RestrictedUDPSocket` and allows verification of behavior. The key method is `Send`.
* **`StreamCreator` Class:** This class is a test fixture or helper. It's responsible for creating instances of `UDPWritableStreamWrapper` and managing dependencies (like the fake socket). The `Create` method is central. The `Close` method and the `close_called_with_` member are used to verify closing behavior.
* **`ScopedStreamCreator`:** This is a RAII wrapper for `StreamCreator`, ensuring cleanup.
* **`TEST` Macros:**  The `TEST` macros from Google Test define individual test cases. The names are descriptive (e.g., `Create`, `WriteUdpMessage`).

**3. Analyzing Individual Test Cases:**

* **`Create`:**  A basic sanity check to see if the `UDPWritableStreamWrapper` can be created successfully and if its `Writable()` method returns a valid object.
* **`WriteUdpMessage`:**  This test is crucial. It simulates writing data to the stream.
    * It gets the `WritableStream`'s writer.
    * It creates a `UDPMessage` and sets its data with a `DOMArrayBuffer`.
    * It calls `writer->write()`.
    * It uses `ScriptPromiseTester` to handle the asynchronous nature of the write operation.
    * It checks if the promise is fulfilled.
    * **Crucially, it checks the data received by the `FakeRestrictedUDPSocket` using `EXPECT_THAT` and `ElementsAre`.** This verifies the data is being sent correctly.
* **`WriteUdpMessageFromTypedArray`:** Similar to the previous test but uses a `DOMUint8Array` (a typed array view) to ensure different data representations are handled.
* **`WriteUdpMessageWithEmptyDataFieldFails`:**  Tests error handling. It sends an empty buffer and expects the write promise to be rejected.
* **`WriteAfterFinishedWrite`:** Checks that multiple successful writes can be performed sequentially.
* **`WriteAfterClose`:**  Tests the behavior of writing to a stream after it has been closed. It expects the write to fail.
* **`WriteFailed`:** Simulates a network error during the `Send` operation using a `FailingFakeRestrictedUDPSocket`. It verifies that the write promise is rejected, the stream is aborted, and the close callback is called with an error.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **Direct Sockets API:**  The presence of `UDPWritableStreamWrapper` and the `direct_sockets` module strongly suggest this is part of the Direct Sockets API being implemented in Chromium. This API allows JavaScript in web pages to directly interact with UDP sockets.
* **`WritableStream`:** The test uses Blink's `WritableStream` API. This is a standard JavaScript Streams API that allows writing data to a sink. In this case, the sink is the underlying UDP socket.
* **`UDPMessage`:** This class likely represents the structure of a UDP message as exposed to JavaScript (or the internal representation used when interacting with JavaScript).
* **`ArrayBuffer` and `TypedArray`:** These are JavaScript data structures for representing binary data. The tests show how data from these structures is passed to the native code for sending over the socket.

**5. Logical Inference and Assumptions:**

* **Assumption:** The tests assume a basic understanding of asynchronous operations and promises in JavaScript.
* **Input/Output:** For `WriteUdpMessage`, the input is a `UDPMessage` with a `DOMArrayBuffer` containing "A". The expected output is that the `FakeRestrictedUDPSocket` receives the byte 'A'. Similar input/output can be defined for other tests.

**6. Common Usage Errors:**

* **Writing to a closed stream:**  The `WriteAfterClose` test explicitly demonstrates this.
* **Providing invalid data:** The `WriteUdpMessageWithEmptyDataFieldFails` test touches on this. Other potential errors could involve incorrect data types or formats if the API weren't designed carefully.

**7. Debugging Clues (User Actions):**

To reach this code, a developer would likely be:

1. **Developing or debugging the Direct Sockets API in Chromium.**
2. **Working on the implementation of UDP socket functionality.**
3. **Potentially investigating issues related to sending data over UDP from a web page.**
4. **Writing unit tests to ensure the `UDPWritableStreamWrapper` class functions correctly.**

**Self-Correction/Refinement During Analysis:**

* Initially, I might have focused too much on the C++ specifics. Realizing the connection to JavaScript and the Streams API is crucial.
* Understanding the role of Mojo for inter-process communication is key to grasping how the `UDPWritableStreamWrapper` interacts with the network service.
* Recognizing the pattern of using fake objects for testing dependencies is a standard practice in software development and important for understanding the test setup.

By following this systematic approach, starting with the file name and includes, dissecting the code structure, analyzing individual tests, and connecting the code to broader web technologies, we can arrive at a comprehensive understanding of the purpose and functionality of this unit test file.
这个文件 `udp_writable_stream_wrapper_unittest.cc` 是 Chromium Blink 引擎中 `direct_sockets` 模块下的一个单元测试文件。它的主要功能是测试 `UDPWritableStreamWrapper` 类的各种行为和功能。

以下是更详细的功能列表和相关说明：

**主要功能:**

1. **测试 `UDPWritableStreamWrapper` 对象的创建:**  验证 `UDPWritableStreamWrapper` 对象能否被成功创建。
2. **测试通过 `UDPWritableStreamWrapper` 写入 UDP 消息:**
   - 验证能够将包含 `ArrayBuffer` 或 `ArrayBufferView` 的 `UDPMessage` 写入到 `UDPWritableStreamWrapper` 中。
   - 验证写入的数据是否正确地传递到了底层的 UDP socket (通过 `FakeRestrictedUDPSocket` 模拟)。
3. **测试写入不同类型的数据:** 验证能够写入 `ArrayBuffer` 和 `TypedArray` (例如 `Uint8Array`) 作为 UDP 消息的数据。
4. **测试写入空数据字段时的行为:** 验证当 `UDPMessage` 的数据字段为空时，写入操作是否会失败。
5. **测试在完成写入后继续写入:** 验证在之前的写入操作完成后，可以继续写入新的 UDP 消息。
6. **测试在流关闭后尝试写入:** 验证当 `UDPWritableStreamWrapper` 被关闭后，尝试写入操作会失败。
7. **测试写入失败的情况:** 模拟底层 UDP socket 发送失败的情况，并验证 `UDPWritableStreamWrapper` 的状态和行为。

**与 JavaScript, HTML, CSS 的关系:**

`UDPWritableStreamWrapper` 是 Chromium 中 Direct Sockets API 的一部分，该 API 允许 JavaScript 代码直接与 UDP 网络进行交互。

* **JavaScript:**  `UDPWritableStreamWrapper` 的作用是将底层的 UDP socket 操作封装成一个 `WritableStream` 对象，这个 `WritableStream` 可以被 JavaScript 代码访问和使用。
    * **举例:** JavaScript 代码可以使用 `WritableStream` 的 `getWriter()` 方法获取一个 `WritableStreamDefaultWriter`，然后使用 `writer.write(udpMessage)` 方法将数据写入 UDP socket。这里的 `udpMessage` 对象在 JavaScript 中对应着 `UDPMessage` 类。
    * **`UDPMessage` 对象:**  在 JavaScript 中，你需要创建一个表示 UDP 消息的对象，该对象通常包含要发送的数据（`ArrayBuffer` 或 `ArrayBufferView`）。这个 JavaScript 对象最终会映射到 C++ 中的 `UDPMessage` 类。
* **HTML:** HTML 本身不直接与 `UDPWritableStreamWrapper` 交互。Direct Sockets API 是通过 JavaScript 暴露给 Web 开发者的。开发者需要在 HTML 中引入 JavaScript 代码来使用 Direct Sockets API。
* **CSS:** CSS 与 `UDPWritableStreamWrapper` 没有任何直接关系。CSS 负责网页的样式和布局，而 Direct Sockets API 负责网络通信。

**逻辑推理 (假设输入与输出):**

**测试用例: `WriteUdpMessage`**

* **假设输入:**
    * JavaScript 代码创建一个 `UDPMessage` 对象，并将其数据设置为包含字符串 "A" 的 `ArrayBuffer`。
    * JavaScript 代码调用 `writableStream.getWriter().write(udpMessage)`.
* **预期输出:**
    * C++ 测试代码中的 `FakeRestrictedUDPSocket` 接收到的数据应该是一个包含字节 'A' 的 `Vector<uint8_t>`.
    * `writer.write()` 返回的 Promise 应该成功 resolve。

**测试用例: `WriteAfterClose`**

* **假设输入:**
    * JavaScript 代码先写入一条消息并成功发送。
    * JavaScript 代码调用 `writableStream.getWriter().close()`.
    * JavaScript 代码再次尝试使用 `writableStream.getWriter().write(udpMessage)` 写入另一条消息。
* **预期输出:**
    * 第一次 `write()` 操作成功。
    * `close()` 操作成功。
    * 第二次 `write()` 操作返回的 Promise 应该被 reject。
    * `UDPWritableStreamWrapper` 的状态应该变为 `kClosed`.

**用户或编程常见的使用错误举例说明:**

1. **在流关闭后尝试写入:**
   * **用户操作:**  用户在 JavaScript 中调用了 `writableStream.getWriter().close()` 来关闭 UDP 连接，然后尝试再次调用 `writer.write()` 发送数据。
   * **错误:**  `writer.write()` 返回的 Promise 会被 reject，因为流已经关闭，无法再写入数据。这是 Direct Sockets API 的预期行为，为了防止在连接断开后意外发送数据。

2. **发送空的 UDP 消息数据:**
   * **用户操作:** 用户在 JavaScript 中创建了一个 `UDPMessage` 对象，但是没有设置 `data` 属性，或者将其设置为一个空的 `ArrayBuffer`。
   * **错误:**  `UDPWritableStreamWrapper` 的测试表明，发送数据字段为空的 UDP 消息可能会导致写入失败（具体取决于实现细节，测试中是会 reject Promise）。这可能是因为网络协议通常需要一些有效载荷才能进行传输。

**用户操作是如何一步步到达这里的 (作为调试线索):**

假设开发者正在调试一个使用 Direct Sockets API 的 Web 应用，该应用尝试通过 UDP 发送数据但遇到了问题。以下是可能的调试步骤，最终可能涉及到 `udp_writable_stream_wrapper_unittest.cc`:

1. **Web 开发者报告问题:** 用户反馈 Web 应用的 UDP 数据发送功能无法正常工作。
2. **初步排查 JavaScript 代码:** Web 开发者检查 JavaScript 代码，确认 Direct Sockets API 的调用方式是否正确，例如 `UDPSocket`, `UDPMessage`, `WritableStream` 的使用是否符合预期。
3. **网络层面分析:**  开发者可能使用网络抓包工具 (例如 Wireshark) 来查看是否真的有 UDP数据包被发送出去，以及数据包的内容是否正确。
4. **怀疑 Blink 引擎实现问题:** 如果网络抓包显示没有数据包发送，或者发送的数据不正确，开发者可能会怀疑 Chromium Blink 引擎中 Direct Sockets API 的实现存在问题。
5. **定位到相关 Blink 代码:**  开发者可能会搜索 Blink 引擎的源代码，寻找与 Direct Sockets 和 UDP 相关的代码，最终找到 `blink/renderer/modules/direct_sockets/udp_writable_stream_wrapper.h` 和 `udp_writable_stream_wrapper_unittest.cc`。
6. **查看单元测试:** 开发者会查看 `udp_writable_stream_wrapper_unittest.cc` 文件，了解该类的预期行为和测试覆盖范围。如果发现某个测试用例失败或者缺少相关的测试用例，这可能指示了问题的根源。
7. **运行单元测试:** 开发者可能会运行 `udp_writable_stream_wrapper_unittest` 来验证 `UDPWritableStreamWrapper` 的行为是否符合预期。如果测试失败，则可以进一步定位到具体的代码错误。
8. **代码调试:** 如果单元测试失败，开发者可以使用调试器 (例如 gdb) 来跟踪 `UDPWritableStreamWrapper` 的代码执行流程，查看变量的值，并找出导致问题的代码逻辑。

总而言之，`udp_writable_stream_wrapper_unittest.cc` 是 Blink 引擎中用于保证 `UDPWritableStreamWrapper` 类功能正确性的重要组成部分。它可以帮助开发者在开发和维护 Direct Sockets API 时发现和修复潜在的 bug。

Prompt: 
```
这是目录为blink/renderer/modules/direct_sockets/udp_writable_stream_wrapper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/direct_sockets/udp_writable_stream_wrapper.h"

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/notreached.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "net/base/net_errors.h"
#include "services/network/public/mojom/restricted_udp_socket.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_udp_message.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream_default_writer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/direct_sockets/udp_socket_mojo_remote.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_receiver.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/gc_plugin.h"
#include "third_party/googletest/src/googlemock/include/gmock/gmock-matchers.h"

namespace blink {

namespace {

class FakeRestrictedUDPSocket
    : public GarbageCollected<FakeRestrictedUDPSocket>,
      public network::mojom::blink::RestrictedUDPSocket {
 public:
  void Send(base::span<const uint8_t> data, SendCallback callback) override {
    data_.AppendSpan(data);
    std::move(callback).Run(net::Error::OK);
  }

  void SendTo(base::span<const uint8_t> data,
              const net::HostPortPair& dest_addr,
              net::DnsQueryType dns_query_type,
              SendToCallback callback) override {
    NOTREACHED();
  }

  void ReceiveMore(uint32_t num_additional_datagrams) override { NOTREACHED(); }

  const Vector<uint8_t>& GetReceivedData() const { return data_; }
  void Trace(cppgc::Visitor* visitor) const {}

 private:
  Vector<uint8_t> data_;
};

class StreamCreator : public GarbageCollected<StreamCreator> {
 public:
  explicit StreamCreator(const V8TestingScope& scope)
      : StreamCreator(scope, MakeGarbageCollected<FakeRestrictedUDPSocket>()) {}

  StreamCreator(const V8TestingScope& scope, FakeRestrictedUDPSocket* socket)
      : fake_udp_socket_(socket),
        receiver_{fake_udp_socket_.Get(), scope.GetExecutionContext()} {}

  ~StreamCreator() = default;

  UDPWritableStreamWrapper* Create(const V8TestingScope& scope) {
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        scope.GetExecutionContext()->GetTaskRunner(TaskType::kNetworking);
    auto* udp_socket =
        MakeGarbageCollected<UDPSocketMojoRemote>(scope.GetExecutionContext());
    udp_socket->get().Bind(receiver_.BindNewPipeAndPassRemote(task_runner),
                           task_runner);

    auto* script_state = scope.GetScriptState();
    stream_wrapper_ = MakeGarbageCollected<UDPWritableStreamWrapper>(
        script_state,
        WTF::BindOnce(&StreamCreator::Close, WrapWeakPersistent(this)),
        udp_socket, network::mojom::RestrictedUDPSocketMode::CONNECTED);
    return stream_wrapper_.Get();
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(fake_udp_socket_);
    visitor->Trace(receiver_);
    visitor->Trace(stream_wrapper_);
  }

  FakeRestrictedUDPSocket* fake_udp_socket() { return fake_udp_socket_.Get(); }

  bool CloseCalledWith(bool error) { return close_called_with_ == error; }

  void Cleanup() { receiver_.reset(); }

 private:
  void Close(ScriptValue exception) {
    close_called_with_ = !exception.IsEmpty();
  }

  std::optional<bool> close_called_with_;
  Member<FakeRestrictedUDPSocket> fake_udp_socket_;
  HeapMojoReceiver<network::mojom::blink::RestrictedUDPSocket,
                   FakeRestrictedUDPSocket>
      receiver_;
  Member<UDPWritableStreamWrapper> stream_wrapper_;
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

TEST(UDPWritableStreamWrapperTest, Create) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_writable_stream_wrapper = stream_creator->Create(scope);

  EXPECT_TRUE(udp_writable_stream_wrapper->Writable());
}

TEST(UDPWritableStreamWrapperTest, WriteUdpMessage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();

  auto* writer = udp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);

  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("A"));
  auto* message = UDPMessage::Create();
  message->setData(
      MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(chunk));

  auto result =
      writer->write(script_state, ScriptValue::From(script_state, message),
                    ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();

  ASSERT_TRUE(tester.IsFulfilled());

  auto* fake_udp_socket = stream_creator->fake_udp_socket();
  EXPECT_THAT(fake_udp_socket->GetReceivedData(), ::testing::ElementsAre('A'));
}

TEST(UDPWritableStreamWrapperTest, WriteUdpMessageFromTypedArray) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();

  auto* writer = udp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);

  auto* buffer = DOMArrayBuffer::Create(base::byte_span_from_cstring("ABC"));
  auto* chunk = DOMUint8Array::Create(buffer, 0, 3);

  auto* message = UDPMessage::Create();
  message->setData(MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(
      NotShared<DOMUint8Array>(chunk)));

  auto result =
      writer->write(script_state, ScriptValue::From(script_state, message),
                    ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();

  ASSERT_TRUE(tester.IsFulfilled());

  auto* fake_udp_socket = stream_creator->fake_udp_socket();
  EXPECT_THAT(fake_udp_socket->GetReceivedData(),
              ::testing::ElementsAre('A', 'B', 'C'));
}

TEST(UDPWritableStreamWrapperTest, WriteUdpMessageWithEmptyDataFieldFails) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();

  auto* writer = udp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);

  // Create empty DOMArrayBuffer.
  auto* chunk = DOMArrayBuffer::Create(/*num_elements=*/static_cast<size_t>(0),
                                       /*element_byte_size=*/1);
  auto* message = UDPMessage::Create();
  message->setData(
      MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(chunk));

  auto result =
      writer->write(script_state, ScriptValue::From(script_state, message),
                    ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();

  ASSERT_TRUE(tester.IsRejected());
}

TEST(UDPWritableStreamWrapperTest, WriteAfterFinishedWrite) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();

  auto* writer = udp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);

  for (const std::string_view value : {"A", "B"}) {
    auto* chunk = DOMArrayBuffer::Create(base::as_byte_span(value));
    auto* message = UDPMessage::Create();
    message->setData(
        MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(chunk));

    auto result =
        writer->write(script_state, ScriptValue::From(script_state, message),
                      ASSERT_NO_EXCEPTION);

    ScriptPromiseTester tester(script_state, result);
    tester.WaitUntilSettled();

    ASSERT_TRUE(tester.IsFulfilled());
  }

  auto* fake_udp_socket = stream_creator->fake_udp_socket();
  EXPECT_THAT(fake_udp_socket->GetReceivedData(),
              ::testing::ElementsAre('A', 'B'));
}

TEST(UDPWritableStreamWrapperTest, WriteAfterClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(
      MakeGarbageCollected<StreamCreator>(scope));
  auto* udp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();

  auto* writer = udp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);

  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("A"));
  auto* message = UDPMessage::Create();
  message->setData(
      MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(chunk));

  auto write_result =
      writer->write(script_state, ScriptValue::From(script_state, message),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_tester(script_state, write_result);
  write_tester.WaitUntilSettled();

  ASSERT_TRUE(write_tester.IsFulfilled());

  auto close_result = writer->close(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester close_tester(script_state, close_result);
  close_tester.WaitUntilSettled();

  ASSERT_TRUE(write_tester.IsFulfilled());

  ASSERT_EQ(udp_writable_stream_wrapper->GetState(),
            StreamWrapper::State::kClosed);

  auto write_after_close_result =
      writer->write(script_state, ScriptValue::From(script_state, message),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_after_close_tester(script_state,
                                               write_after_close_result);
  write_after_close_tester.WaitUntilSettled();

  ASSERT_TRUE(write_after_close_tester.IsRejected());
}

TEST(UDPWritableStreamWrapperTest, WriteFailed) {
  class FailingFakeRestrictedUDPSocket : public FakeRestrictedUDPSocket {
   public:
    void Send(base::span<const uint8_t> data, SendCallback callback) override {
      std::move(callback).Run(net::ERR_UNEXPECTED);
    }
  };

  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ScopedStreamCreator stream_creator(MakeGarbageCollected<StreamCreator>(
      scope, MakeGarbageCollected<FailingFakeRestrictedUDPSocket>()));
  auto* udp_writable_stream_wrapper = stream_creator->Create(scope);

  auto* script_state = scope.GetScriptState();
  auto* writer = udp_writable_stream_wrapper->Writable()->getWriter(
      script_state, ASSERT_NO_EXCEPTION);

  auto* chunk = DOMArrayBuffer::Create(base::byte_span_from_cstring("A"));
  auto* message = UDPMessage::Create();
  message->setData(
      MakeGarbageCollected<V8UnionArrayBufferOrArrayBufferView>(chunk));

  auto write_result =
      writer->write(script_state, ScriptValue::From(script_state, message),
                    ASSERT_NO_EXCEPTION);
  ScriptPromiseTester write_tester(script_state, write_result);
  write_tester.WaitUntilSettled();

  ASSERT_TRUE(write_tester.IsRejected());
  ASSERT_EQ(udp_writable_stream_wrapper->GetState(),
            StreamWrapper::State::kAborted);

  ASSERT_TRUE(stream_creator->CloseCalledWith(/*error=*/true));
}

}  // namespace

}  // namespace blink

"""

```