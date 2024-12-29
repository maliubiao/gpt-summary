Response:
The user wants a summary of the functionality of the provided C++ code for `web_transport_test.cc`. This is the second part of a three-part code snippet. I need to focus on summarizing the tests present in this specific section.

Looking at the code, it appears to be testing the following aspects of WebTransport datagram and stream functionalities:

- Sending datagrams before and after connection/closure.
- Receiving datagrams before, during, and with different reader types.
- Handling datagram reception with insufficient buffer space.
- Cancelling datagram reads.
- Error handling for datagrams after connection closure or transport errors.
- Datagram queuing and dropping based on high-water mark and max age.
- Testing simultaneous reads on the datagram stream.
- Creating and handling send streams (unidirectional).
- Testing garbage collection of WebTransport and send/receive stream objects.
- Handling send stream creation failures and aborts due to connection closure.
- Basic testing of receive stream creation and handling after connection and remote closure.
根据提供的代码片段，这个部分主要测试了 **WebTransport 的数据报 (Datagrams) 和发送/接收单向流 (Unidirectional Streams) 的功能**。  它涵盖了在连接的不同状态下（连接前、连接后、关闭后）发送和接收数据报的行为，以及创建和管理单向流的生命周期。

以下是对其功能的归纳：

**1. 数据报 (Datagrams) 功能测试:**

* **发送数据报的时机：**
    * 测试在连接建立之前尝试发送数据报的情况，验证数据报是否被正确缓存并在连接建立后发送。
    * 测试在连接关闭后尝试发送数据报的情况，验证是否会失败。
* **接收数据报的时机和方式：**
    * 测试在调用读取操作之前收到数据报的情况，验证数据报是否被正确缓存并在读取时返回。
    * 测试在等待读取操作时收到数据报的情况，验证 Promise 是否会成功解析并返回数据。
    * 测试使用 BYOB (Bring Your Own Buffer) 读取器接收数据报的情况。
* **接收数据报的错误处理：**
    * 测试使用 BYOB 读取器时提供的缓冲区不足以容纳接收到的数据报的情况，验证是否会抛出 `RangeError`。
* **取消数据报读取：**
    * 测试取消数据报的 `readable` 流，验证已接收但未读取的数据报是否会被丢弃。
* **连接关闭后的数据报处理：**
    * 测试在连接关闭后尝试读取数据报的情况，验证 Promise 是否会被拒绝。
    * 测试在连接关闭后设置 `incomingHighWaterMark` 是否会影响已有的待读取数据报。
* **传输错误后的数据报处理：**
    * 测试当底层连接发生错误时，数据报 `readable` 流是否会进入错误状态。
* **数据报的丢弃机制：**
    * 测试当接收速度超过处理速度时，是否会根据 `incomingHighWaterMark` 丢弃旧的数据报。
* **高水位线 (High Water Mark) 的作用：**
    * 测试 `incomingHighWaterMark` 的设置对接收队列大小的影响，验证是否会限制缓存的数据报数量。
    * 测试重置 `incomingHighWaterMark` 是否会清空接收队列。
    * 测试当 `incomingHighWaterMark` 设置为 0 时接收数据报的情况。
* **最大生存时间 (Max Age) 的作用：**
    * 测试 `incomingMaxAge` 的设置，验证超过最大生存时间的数据报是否会被丢弃。
* **并发读取：**
    * 测试同时发起多个数据报读取操作，验证是否都能正确接收到数据。

**2. 单向发送流 (Unidirectional Send Streams) 功能测试:**

* **创建发送流：**
    * 测试成功创建发送流的情况。
    * 测试在连接建立之前尝试创建发送流的情况，验证是否会失败并抛出异常。
    * 测试创建发送流失败的情况。
* **垃圾回收：**
    * 测试发送流对象在没有显式引用时是否会被垃圾回收，以及 WebTransport 对象对发送流的持有。
    * 测试在本地或远程关闭发送流后，对象是否会被垃圾回收。

**3. 单向接收流 (Unidirectional Receive Streams) 功能测试:**

* **创建接收流：**
    * 简单验证接收流的创建过程。
* **连接关闭对接收流的影响：**
    * 测试在创建接收流后关闭 WebTransport 连接，验证读取接收流是否会失败。
* **远程关闭对接收流的影响：**
    * 测试在创建接收流后远程关闭连接，验证读取接收流是否会受到影响。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件本身是用 C++ 编写的，用于测试 Blink 引擎中 WebTransport API 的 C++ 实现。但它直接关联到开发者在 JavaScript 中使用的 WebTransport API。

* **JavaScript:** 这些测试验证了 JavaScript 中 `WebTransport` 接口的 `datagrams.readable` 和 `datagrams.writable` 属性以及 `createUnidirectionalStream()` 方法的行为。例如：
    * 当 JavaScript 代码调用 `webTransport.datagrams.writable.getWriter().write(data)` 时，`SendDatagramBeforeConnect` 和 `SendDatagramAfterClose` 测试会验证引擎的 C++ 代码是否按照规范处理了这些调用。
    * 当 JavaScript 代码从 `webTransport.datagrams.readable.getReader().read()` 获取数据报时，`ReceiveDatagramBeforeRead` 和 `ReceiveDatagramDuringRead` 测试验证了 C++ 层的接收逻辑。
    * 当 JavaScript 代码调用 `webTransport.createUnidirectionalStream()` 时，`CreateSendStream` 和 `CreateSendStreamFailure` 测试验证了 C++ 层的流创建逻辑。
* **HTML:**  虽然这个测试文件不直接涉及 HTML，但 WebTransport API 是通过 JavaScript 在网页中使用的。HTML 页面中的 JavaScript 代码会调用这些 API 来建立 WebTransport 连接和收发数据。
* **CSS:** CSS 与 WebTransport 的功能没有直接关系。

**逻辑推理和假设输入/输出：**

* **`SendDatagramBeforeConnect`:**
    * **假设输入:**  在 WebTransport 连接建立之前，JavaScript 调用 `writer.write(data)` 发送数据报 'A'，然后在连接建立后又发送数据报 'N'。
    * **预期输出:**  两个数据报 'A' 和 'N' 都会在连接建立后成功发送到服务器。
* **`ReceiveDatagramWithBYOBReader`:**
    * **假设输入:**  JavaScript 获取数据报 `readable` 流的 BYOB 读取器，并提供一个大小为 1 的缓冲区。服务器发送一个字节的数据报 'A'。
    * **预期输出:**  读取器的 Promise 会成功解析，返回包含数据 'A' 的 `Uint8Array`。
* **`ReceiveDatagramWithoutEnoughBuffer`:**
    * **假设输入:** JavaScript 获取数据报 `readable` 流的 BYOB 读取器，并提供一个大小为 1 的缓冲区。服务器发送一个包含 'A', 'B', 'C' 三个字节的数据报。
    * **预期输出:** 读取器的 Promise 会被拒绝，并抛出一个 `RangeError`，因为提供的缓冲区太小。

**用户或编程常见的使用错误：**

* **在连接建立前发送数据报：**  虽然 WebTransport 规范允许这样做，但开发者可能会误以为必须先等待连接建立成功才能发送数据。此测试确保了引擎能正确处理这种情况。
* **在连接关闭后尝试发送或接收数据：** 开发者可能会忘记检查连接状态，在连接已经关闭的情况下尝试进行数据操作。测试验证了这些操作会失败并抛出相应的错误。
* **使用 BYOB 读取器时提供的缓冲区大小不足：** 开发者可能没有正确预估接收数据的大小，导致提供的缓冲区过小。测试 `ReceiveDatagramWithoutEnoughBuffer` 模拟了这种情况。
* **忘记处理 Promise 的 rejected 状态：**  在进行异步操作（如读取数据报或创建流）时，开发者需要妥善处理 Promise 的 `rejected` 状态，以应对连接错误、流创建失败等情况。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中打开一个网页。**
2. **网页中的 JavaScript 代码使用 `new WebTransport(url)` 创建一个 WebTransport 对象。**
3. **JavaScript 代码可能会立即调用 `webTransport.datagrams.writable.getWriter().write(data)` 尝试发送数据报，即使连接尚未建立 (对应 `SendDatagramBeforeConnect` 测试)。**
4. **或者，JavaScript 代码可能会等待连接建立成功后才发送数据报。**
5. **服务器可能会主动发送数据报到客户端 (对应各种 `ReceiveDatagram` 测试)。**
6. **JavaScript 代码可能会调用 `webTransport.datagrams.readable.getReader().read()` 或使用 BYOB 读取器来接收数据报。**
7. **用户或网页代码可能会调用 `webTransport.close()` 关闭连接 (对应 `SendDatagramAfterClose` 和 `DatagramsShouldBeErroredAfterClose` 等测试)。**
8. **在调试过程中，如果发现数据报发送或接收出现问题，或者流的创建或管理不符合预期，开发者可能会查看 Blink 引擎的源代码，例如 `web_transport_test.cc`，来理解引擎的内部行为和验证其正确性。**
9. **如果涉及到缓冲区大小问题，开发者可能会检查 JavaScript 代码中用于接收数据的 `ArrayBuffer` 或 `Uint8Array` 的大小是否足够。**

**本部分的功能归纳:**

这部分 `web_transport_test.cc` 代码主要负责测试 Blink 引擎中 **WebTransport 数据报和单向流的核心功能和边界情况**。它涵盖了数据报的发送和接收时机、错误处理、队列管理、以及单向流的创建和生命周期管理，并验证了在各种场景下 WebTransport API 的行为是否符合预期。这些测试是确保 WebTransport 功能在 Chromium 浏览器中正确实现的关键。

Prompt: 
```
这是目录为blink/renderer/modules/webtransport/web_transport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
T_NO_EXCEPTION);
  }

  // The first two promises are resolved immediately.
  scope.PerformMicrotaskCheckpoint();
  EXPECT_EQ(promise1.V8Promise()->State(), v8::Promise::kFulfilled);
  EXPECT_EQ(promise2.V8Promise()->State(), v8::Promise::kFulfilled);
  EXPECT_EQ(promise3.V8Promise()->State(), v8::Promise::kPending);
  EXPECT_EQ(promise4.V8Promise()->State(), v8::Promise::kPending);

  // The rest are resolved by the callback.
  test::RunPendingTasks();
  scope.PerformMicrotaskCheckpoint();
  EXPECT_EQ(promise3.V8Promise()->State(), v8::Promise::kFulfilled);
  EXPECT_EQ(promise4.V8Promise()->State(), v8::Promise::kFulfilled);
}

TEST_F(WebTransportTest, SendDatagramBeforeConnect) {
  V8TestingScope scope;
  auto* web_transport = Create(scope, "https://example.com", EmptyOptions());

  auto* writable = web_transport->datagrams()->writable();
  auto* script_state = scope.GetScriptState();
  auto* writer = writable->getWriter(script_state, ASSERT_NO_EXCEPTION);
  auto* chunk = DOMUint8Array::Create(1);
  *chunk->Data() = 'A';
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);

  ConnectSuccessfullyWithoutRunningPendingTasks(web_transport);

  testing::Sequence s;
  EXPECT_CALL(*mock_web_transport_, SendDatagram(ElementsAre('A'), _))
      .WillOnce(Invoke([](base::span<const uint8_t>,
                          MockWebTransport::SendDatagramCallback callback) {
        std::move(callback).Run(true);
      }));
  EXPECT_CALL(*mock_web_transport_, SendDatagram(ElementsAre('N'), _))
      .WillOnce(Invoke([](base::span<const uint8_t>,
                          MockWebTransport::SendDatagramCallback callback) {
        std::move(callback).Run(true);
      }));

  test::RunPendingTasks();
  *chunk->Data() = 'N';
  result = writer->write(script_state, ScriptValue::From(script_state, chunk),
                         ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_TRUE(tester.Value().IsUndefined());
}

TEST_F(WebTransportTest, SendDatagramAfterClose) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  EXPECT_CALL(*mock_web_transport_, Close());

  web_transport->close(nullptr);
  test::RunPendingTasks();

  auto* writable = web_transport->datagrams()->writable();
  auto* script_state = scope.GetScriptState();
  auto* writer = writable->getWriter(script_state, ASSERT_NO_EXCEPTION);

  auto* chunk = DOMUint8Array::Create(1);
  *chunk->Data() = 'A';
  auto result =
      writer->write(script_state, ScriptValue::From(script_state, chunk),
                    ASSERT_NO_EXCEPTION);

  // No datagram is sent.

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
}

Vector<uint8_t> GetValueAsVector(ScriptState* script_state,
                                 ScriptValue iterator_result) {
  bool done = false;
  v8::Local<v8::Value> value;
  if (!V8UnpackIterationResult(script_state,
                               iterator_result.V8Value().As<v8::Object>(),
                               &value, &done)) {
    ADD_FAILURE() << "unable to unpack iterator_result";
    return {};
  }

  EXPECT_FALSE(done);
  DummyExceptionStateForTesting exception_state;
  auto array = NativeValueTraits<NotShared<DOMUint8Array>>::NativeValue(
      script_state->GetIsolate(), value, exception_state);
  if (!array) {
    ADD_FAILURE() << "value was not a Uint8Array";
    return {};
  }

  Vector<uint8_t> result;
  result.Append(array->Data(), base::checked_cast<wtf_size_t>(array->length()));
  return result;
}

TEST_F(WebTransportTest, ReceiveDatagramBeforeRead) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  const std::array<uint8_t, 1> chunk = {'A'};
  client_remote_->OnDatagramReceived(chunk);

  test::RunPendingTasks();

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  EXPECT_THAT(GetValueAsVector(script_state, tester.Value()), ElementsAre('A'));
}

TEST_F(WebTransportTest, ReceiveDatagramDuringRead) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);

  const std::array<uint8_t, 1> chunk = {'A'};
  client_remote_->OnDatagramReceived(chunk);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  EXPECT_THAT(GetValueAsVector(script_state, tester.Value()), ElementsAre('A'));
}

TEST_F(WebTransportTest, ReceiveDatagramWithBYOBReader) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetBYOBReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  NotShared<DOMArrayBufferView> view =
      NotShared<DOMUint8Array>(DOMUint8Array::Create(1));
  auto result = reader->read(script_state, view, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);

  const std::array<uint8_t, 1> chunk = {'A'};
  client_remote_->OnDatagramReceived(chunk);

  test::RunPendingTasks();

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());
  EXPECT_THAT(GetValueAsVector(script_state, tester.Value()), ElementsAre('A'));
}

bool IsRangeError(ScriptState* script_state,
                  ScriptValue value,
                  const String& message) {
  v8::Local<v8::Object> object;
  if (!value.V8Value()->ToObject(script_state->GetContext()).ToLocal(&object)) {
    return false;
  }
  if (!object->IsNativeError())
    return false;

  const auto& Has = [script_state, object](const String& key,
                                           const String& value) -> bool {
    v8::Local<v8::Value> actual;
    return object
               ->Get(script_state->GetContext(),
                     V8AtomicString(script_state->GetIsolate(), key))
               .ToLocal(&actual) &&
           ToCoreStringWithUndefinedOrNullCheck(script_state->GetIsolate(),
                                                actual) == value;
  };

  return Has("name", "RangeError") && Has("message", message);
}

TEST_F(WebTransportTest, ReceiveDatagramWithoutEnoughBuffer) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetBYOBReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  NotShared<DOMArrayBufferView> view =
      NotShared<DOMUint8Array>(DOMUint8Array::Create(1));
  auto result = reader->read(script_state, view, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, result);

  const std::array<uint8_t, 3> chunk = {'A', 'B', 'C'};
  client_remote_->OnDatagramReceived(chunk);

  test::RunPendingTasks();

  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
  EXPECT_TRUE(IsRangeError(script_state, tester.Value(),
                           "supplied view is not large enough."));
}

TEST_F(WebTransportTest, CancelDatagramReadableWorks) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  auto* readable = web_transport->datagrams()->readable();

  // This datagram should be discarded.
  const std::array<uint8_t, 1> chunk1 = {'A'};
  client_remote_->OnDatagramReceived(chunk1);

  test::RunPendingTasks();

  readable->cancel(scope.GetScriptState(), ASSERT_NO_EXCEPTION);

  // This datagram should also be discarded.
  const std::array<uint8_t, 1> chunk2 = {'B'};
  client_remote_->OnDatagramReceived(chunk2);

  test::RunPendingTasks();
}

TEST_F(WebTransportTest, DatagramsShouldBeErroredAfterClose) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  EXPECT_CALL(*mock_web_transport_, Close());

  const std::array<uint8_t, 1> chunk1 = {'A'};
  client_remote_->OnDatagramReceived(chunk1);

  test::RunPendingTasks();

  web_transport->close(nullptr);

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto result1 = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester1(script_state, result1);
  tester1.WaitUntilSettled();
  EXPECT_TRUE(tester1.IsRejected());
}

TEST_F(WebTransportTest, ResettingIncomingHighWaterMarkWorksAfterClose) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  EXPECT_CALL(*mock_web_transport_, Close());

  const std::array<uint8_t, 1> chunk1 = {'A'};
  client_remote_->OnDatagramReceived(chunk1);

  test::RunPendingTasks();

  web_transport->close(nullptr);

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  web_transport->datagrams()->setIncomingHighWaterMark(0);
  auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsRejected());
}

TEST_F(WebTransportTest, TransportErrorErrorsReadableStream) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  // This datagram should be discarded.
  const std::array<uint8_t, 1> chunk1 = {'A'};
  client_remote_->OnDatagramReceived(chunk1);

  test::RunPendingTasks();

  // Cause a transport error.
  client_remote_.reset();

  test::RunPendingTasks();

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();

  EXPECT_TRUE(tester.IsRejected());
}

TEST_F(WebTransportTest, DatagramsAreDropped) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  // Chunk 'A' gets placed in the source queue.
  const std::array<uint8_t, 1> chunk1 = {'A'};
  client_remote_->OnDatagramReceived(chunk1);

  // Chunk 'B' replaces chunk 'A'.
  const std::array<uint8_t, 1> chunk2 = {'B'};
  client_remote_->OnDatagramReceived(chunk2);

  // Make sure that the calls have run.
  test::RunPendingTasks();

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto result1 = reader->read(script_state, ASSERT_NO_EXCEPTION);
  auto result2 = reader->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester1(script_state, result1);
  ScriptPromiseTester tester2(script_state, result2);
  tester1.WaitUntilSettled();
  EXPECT_TRUE(tester1.IsFulfilled());
  EXPECT_FALSE(tester2.IsFulfilled());

  EXPECT_THAT(GetValueAsVector(script_state, tester1.Value()),
              ElementsAre('B'));

  // Chunk 'C' fulfills the pending read.
  const std::array<uint8_t, 1> chunk3 = {'C'};
  client_remote_->OnDatagramReceived(chunk3);

  tester2.WaitUntilSettled();
  EXPECT_TRUE(tester2.IsFulfilled());

  EXPECT_THAT(GetValueAsVector(script_state, tester2.Value()),
              ElementsAre('C'));
}

TEST_F(WebTransportTest, IncomingHighWaterMarkIsObeyed) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  constexpr int32_t kHighWaterMark = 5;
  web_transport->datagrams()->setIncomingHighWaterMark(kHighWaterMark);

  for (int i = 0; i < kHighWaterMark + 1; ++i) {
    const std::array<uint8_t, 1> chunk = {static_cast<uint8_t>('0' + i)};
    client_remote_->OnDatagramReceived(chunk);
  }

  // Make sure that the calls have run.
  test::RunPendingTasks();

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  for (int i = 0; i < kHighWaterMark; ++i) {
    auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);

    ScriptPromiseTester tester(script_state, result);
    tester.WaitUntilSettled();

    EXPECT_TRUE(tester.IsFulfilled());
    EXPECT_THAT(GetValueAsVector(script_state, tester.Value()),
                ElementsAre('0' + i + 1));
  }
}

TEST_F(WebTransportTest, ResettingHighWaterMarkClearsQueue) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  constexpr int32_t kHighWaterMark = 5;
  web_transport->datagrams()->setIncomingHighWaterMark(kHighWaterMark);

  for (int i = 0; i < kHighWaterMark; ++i) {
    const std::array<uint8_t, 1> chunk = {'A'};
    client_remote_->OnDatagramReceived(chunk);
  }

  // Make sure that the calls have run.
  test::RunPendingTasks();

  web_transport->datagrams()->setIncomingHighWaterMark(0);

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);

  // Give the promise an opportunity to settle.
  test::RunPendingTasks();

  // The queue should be empty, so read() should not have completed.
  EXPECT_FALSE(tester.IsFulfilled());
  EXPECT_FALSE(tester.IsRejected());
}

TEST_F(WebTransportTest, ReadIncomingDatagramWorksWithHighWaterMarkZero) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  web_transport->datagrams()->setIncomingHighWaterMark(0);

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);
  auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);

  const std::array<uint8_t, 1> chunk = {'A'};
  client_remote_->OnDatagramReceived(chunk);

  ScriptPromiseTester tester(script_state, result);
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  EXPECT_THAT(GetValueAsVector(script_state, tester.Value()), ElementsAre('A'));
}

// We only do an extremely basic test for incomingMaxAge as overriding
// base::TimeTicks::Now() doesn't work well in Blink and passing in a mock clock
// would add a lot of complexity for little benefit.
TEST_F(WebTransportTest, IncomingMaxAgeIsObeyed) {
  V8TestingScope scope;

  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  web_transport->datagrams()->setIncomingHighWaterMark(2);

  const std::array<uint8_t, 1> chunk1 = {'A'};
  client_remote_->OnDatagramReceived(chunk1);

  const std::array<uint8_t, 1> chunk2 = {'B'};
  client_remote_->OnDatagramReceived(chunk2);

  test::RunPendingTasks();

  constexpr base::TimeDelta kMaxAge = base::Microseconds(1);
  web_transport->datagrams()->setIncomingMaxAge(kMaxAge.InMillisecondsF());

  test::RunDelayedTasks(kMaxAge);

  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  // The queue should be empty so the read should not complete.
  auto result = reader->read(script_state, ASSERT_NO_EXCEPTION);

  ScriptPromiseTester tester(script_state, result);

  test::RunPendingTasks();

  EXPECT_FALSE(tester.IsFulfilled());
  EXPECT_FALSE(tester.IsRejected());
}

// This is a regression test for https://crbug.com/1246335
TEST_F(WebTransportTest, TwoSimultaneousReadsWork) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");
  auto* readable = web_transport->datagrams()->readable();
  auto* script_state = scope.GetScriptState();
  auto* reader =
      readable->GetDefaultReaderForTesting(script_state, ASSERT_NO_EXCEPTION);

  auto result1 = reader->read(script_state, ASSERT_NO_EXCEPTION);
  auto result2 = reader->read(script_state, ASSERT_NO_EXCEPTION);

  const std::array<uint8_t, 1> chunk1 = {'A'};
  client_remote_->OnDatagramReceived(chunk1);

  const std::array<uint8_t, 1> chunk2 = {'B'};
  client_remote_->OnDatagramReceived(chunk2);

  ScriptPromiseTester tester1(script_state, result1);
  tester1.WaitUntilSettled();
  EXPECT_TRUE(tester1.IsFulfilled());

  EXPECT_THAT(GetValueAsVector(script_state, tester1.Value()),
              ElementsAre('A'));

  ScriptPromiseTester tester2(script_state, result2);
  tester2.WaitUntilSettled();
  EXPECT_TRUE(tester2.IsFulfilled());

  EXPECT_THAT(GetValueAsVector(script_state, tester2.Value()),
              ElementsAre('B'));
}

bool ValidProducerHandle(const mojo::ScopedDataPipeProducerHandle& handle) {
  return handle.is_valid();
}

bool ValidConsumerHandle(const mojo::ScopedDataPipeConsumerHandle& handle) {
  return handle.is_valid();
}

TEST_F(WebTransportTest, CreateSendStream) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  EXPECT_CALL(*mock_web_transport_,
              CreateStream(Truly(ValidConsumerHandle),
                           Not(Truly(ValidProducerHandle)), _))
      .WillOnce([](Unused, Unused,
                   base::OnceCallback<void(bool, uint32_t)> callback) {
        std::move(callback).Run(true, 0);
      });

  auto* script_state = scope.GetScriptState();
  auto send_stream_promise = web_transport->createUnidirectionalStream(
      script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, send_stream_promise);

  tester.WaitUntilSettled();

  EXPECT_TRUE(tester.IsFulfilled());
  auto* writable = V8WritableStream::ToWrappable(scope.GetIsolate(),
                                                 tester.Value().V8Value());
  EXPECT_TRUE(writable);
}

TEST_F(WebTransportTest, CreateSendStreamBeforeConnect) {
  V8TestingScope scope;

  auto* script_state = scope.GetScriptState();
  auto* web_transport = WebTransport::Create(
      script_state, "https://example.com", EmptyOptions(), ASSERT_NO_EXCEPTION);
  auto& exception_state = scope.GetExceptionState();
  auto send_stream_promise =
      web_transport->createUnidirectionalStream(script_state, exception_state);
  EXPECT_TRUE(send_stream_promise.IsEmpty());
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(static_cast<int>(DOMExceptionCode::kNetworkError),
            exception_state.Code());
}

TEST_F(WebTransportTest, CreateSendStreamFailure) {
  V8TestingScope scope;
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  EXPECT_CALL(*mock_web_transport_, CreateStream(_, _, _))
      .WillOnce([](Unused, Unused,
                   base::OnceCallback<void(bool, uint32_t)> callback) {
        std::move(callback).Run(false, 0);
      });

  auto* script_state = scope.GetScriptState();
  auto send_stream_promise = web_transport->createUnidirectionalStream(
      script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, send_stream_promise);

  tester.WaitUntilSettled();

  EXPECT_TRUE(tester.IsRejected());
  DOMException* exception =
      V8DOMException::ToWrappable(scope.GetIsolate(), tester.Value().V8Value());
  EXPECT_EQ(exception->name(), "NetworkError");
  EXPECT_EQ(exception->message(), "Failed to create send stream.");
}

// Every active stream is kept alive by the WebTransport object.
TEST_F(WebTransportTest, SendStreamGarbageCollection) {
  V8TestingScope scope;

  WeakPersistent<WebTransport> web_transport;
  WeakPersistent<SendStream> send_stream;

  auto* isolate = scope.GetIsolate();

  {
    // The streams created when creating a WebTransport or SendStream create
    // some v8 handles. To ensure these are collected, we need to create a
    // handle scope. This is not a problem for garbage collection in normal
    // operation.
    v8::HandleScope handle_scope(isolate);

    web_transport = CreateAndConnectSuccessfully(scope, "https://example.com");
    EXPECT_CALL(*mock_web_transport_, Close());
    send_stream = CreateSendStreamSuccessfully(scope, web_transport);
  }

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_TRUE(web_transport);
  EXPECT_TRUE(send_stream);

  {
    v8::HandleScope handle_scope(isolate);
    web_transport->close(nullptr);
  }

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(web_transport);
  EXPECT_FALSE(send_stream);
}

// A live stream will be kept alive even if there is no explicit reference.
// When the underlying connection is shut down, the connection will be swept.
TEST_F(WebTransportTest, SendStreamGarbageCollectionLocalClose) {
  V8TestingScope scope;

  WeakPersistent<SendStream> send_stream;
  WeakPersistent<WebTransport> web_transport;

  {
    // The writable stream created when creating a SendStream creates some
    // v8 handles. To ensure these are collected, we need to create a handle
    // scope. This is not a problem for garbage collection in normal operation.
    v8::HandleScope handle_scope(scope.GetIsolate());

    web_transport = CreateAndConnectSuccessfully(scope, "https://example.com");
    send_stream = CreateSendStreamSuccessfully(scope, web_transport);
  }

  // Pretend the stack is empty. This will avoid accidentally treating any
  // copies of the |send_stream| pointer as references.
  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(send_stream);

  auto* script_state = scope.GetScriptState();
  auto* isolate = scope.GetIsolate();
  // We use v8::Persistent instead of ScriptPromise, because
  // ScriptPromise will be broken when CollectAllGarbageForTesting is
  // called.
  v8::Persistent<v8::Promise> close_promise_persistent;

  {
    v8::HandleScope handle_scope(isolate);
    auto close_promise = send_stream->close(script_state, ASSERT_NO_EXCEPTION);
    close_promise_persistent.Reset(isolate, close_promise.V8Promise());
  }

  test::RunPendingTasks();
  ThreadState::Current()->CollectAllGarbageForTesting();

  // The WebTransport object is alive because it's connected.
  ASSERT_TRUE(web_transport);

  // The SendStream object has not been collected yet, because it remains
  // referenced by |web_transport| until OnOutgoingStreamClosed is called.
  EXPECT_TRUE(send_stream);

  web_transport->OnOutgoingStreamClosed(/*stream_id=*/0);

  {
    v8::HandleScope handle_scope(isolate);
    ScriptPromiseTester tester(
        script_state, ScriptPromise<IDLUndefined>::FromV8Promise(
                          isolate, close_promise_persistent.Get(isolate)));
    close_promise_persistent.Reset();
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
  }

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_TRUE(web_transport);
  EXPECT_FALSE(send_stream);
}

TEST_F(WebTransportTest, SendStreamGarbageCollectionRemoteClose) {
  V8TestingScope scope;

  WeakPersistent<SendStream> send_stream;

  {
    v8::HandleScope handle_scope(scope.GetIsolate());

    auto* web_transport =
        CreateAndConnectSuccessfully(scope, "https://example.com");
    send_stream = CreateSendStreamSuccessfully(scope, web_transport);
  }

  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(send_stream);

  // Close the other end of the pipe.
  send_stream_consumer_handle_.reset();

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(send_stream);
}

// A live stream will be kept alive even if there is no explicit reference.
// When the underlying connection is shut down, the connection will be swept.
TEST_F(WebTransportTest, ReceiveStreamGarbageCollectionCancel) {
  V8TestingScope scope;

  WeakPersistent<ReceiveStream> receive_stream;
  mojo::ScopedDataPipeProducerHandle producer;

  {
    // The readable stream created when creating a ReceiveStream creates some
    // v8 handles. To ensure these are collected, we need to create a handle
    // scope. This is not a problem for garbage collection in normal operation.
    v8::HandleScope handle_scope(scope.GetIsolate());

    auto* web_transport =
        CreateAndConnectSuccessfully(scope, "https://example.com");

    producer = DoAcceptUnidirectionalStream();
    receive_stream = ReadReceiveStream(scope, web_transport);
  }

  // Pretend the stack is empty. This will avoid accidentally treating any
  // copies of the |receive_stream| pointer as references.
  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(receive_stream);

  auto* script_state = scope.GetScriptState();

  // Eagerly destroy the promise as this test is using manual GC
  // without stack which is incompatible with ScriptValue.
  std::optional<ScriptPromise<IDLUndefined>> cancel_promise;
  {
    // Cancelling also creates v8 handles, so we need a new handle scope as
    // above.
    v8::HandleScope handle_scope(scope.GetIsolate());
    cancel_promise.emplace(
        receive_stream->cancel(script_state, ASSERT_NO_EXCEPTION));
  }

  ScriptPromiseTester tester(script_state, cancel_promise.value());
  cancel_promise.reset();
  tester.WaitUntilSettled();
  EXPECT_TRUE(tester.IsFulfilled());

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(receive_stream);
}

TEST_F(WebTransportTest, ReceiveStreamGarbageCollectionRemoteClose) {
  V8TestingScope scope;

  WeakPersistent<ReceiveStream> receive_stream;
  mojo::ScopedDataPipeProducerHandle producer;

  {
    v8::HandleScope handle_scope(scope.GetIsolate());

    auto* web_transport =
        CreateAndConnectSuccessfully(scope, "https://example.com");
    producer = DoAcceptUnidirectionalStream();
    receive_stream = ReadReceiveStream(scope, web_transport);
  }

  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(receive_stream);

  // Close the other end of the pipe.
  producer.reset();

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(receive_stream);

  receive_stream->GetIncomingStream()->OnIncomingStreamClosed(false);

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(receive_stream);
}

// This is the same test as ReceiveStreamGarbageCollectionRemoteClose, except
// that the order of the data pipe being reset and the OnIncomingStreamClosed
// message is reversed. It is important that the object is not collected until
// both events have happened.
TEST_F(WebTransportTest, ReceiveStreamGarbageCollectionRemoteCloseReverse) {
  V8TestingScope scope;

  WeakPersistent<ReceiveStream> receive_stream;
  mojo::ScopedDataPipeProducerHandle producer;

  {
    v8::HandleScope handle_scope(scope.GetIsolate());

    auto* web_transport =
        CreateAndConnectSuccessfully(scope, "https://example.com");

    producer = DoAcceptUnidirectionalStream();
    receive_stream = ReadReceiveStream(scope, web_transport);
  }

  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(receive_stream);

  receive_stream->GetIncomingStream()->OnIncomingStreamClosed(false);

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  ASSERT_TRUE(receive_stream);

  producer.reset();

  test::RunPendingTasks();

  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_FALSE(receive_stream);
}

TEST_F(WebTransportTest, CreateSendStreamAbortedByClose) {
  V8TestingScope scope;

  auto* script_state = scope.GetScriptState();
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  base::OnceCallback<void(bool, uint32_t)> create_stream_callback;
  EXPECT_CALL(*mock_web_transport_, CreateStream(_, _, _))
      .WillOnce([&](Unused, Unused,
                    base::OnceCallback<void(bool, uint32_t)> callback) {
        create_stream_callback = std::move(callback);
      });
  EXPECT_CALL(*mock_web_transport_, Close());

  auto send_stream_promise = web_transport->createUnidirectionalStream(
      script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester tester(script_state, send_stream_promise);

  test::RunPendingTasks();

  web_transport->close(nullptr);
  std::move(create_stream_callback).Run(true, 0);

  tester.WaitUntilSettled();

  EXPECT_TRUE(tester.IsRejected());
}

// ReceiveStream functionality is thoroughly tested in incoming_stream_test.cc.
// This test just verifies that the creation is done correctly.
TEST_F(WebTransportTest, CreateReceiveStream) {
  V8TestingScope scope;

  auto* script_state = scope.GetScriptState();
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  mojo::ScopedDataPipeProducerHandle producer = DoAcceptUnidirectionalStream();

  ReceiveStream* receive_stream = ReadReceiveStream(scope, web_transport);

  const std::string_view data = "what";
  EXPECT_EQ(producer->WriteAllData(base::as_byte_span(data)), MOJO_RESULT_OK);

  producer.reset();
  web_transport->OnIncomingStreamClosed(/*stream_id=*/0, true);

  auto* reader = receive_stream->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester read_tester(script_state, read_promise);
  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsFulfilled());
  auto read_result = read_tester.Value().V8Value();
  ASSERT_TRUE(read_result->IsObject());
  v8::Local<v8::Value> value;
  bool done = false;
  ASSERT_TRUE(V8UnpackIterationResult(
      script_state, read_result.As<v8::Object>(), &value, &done));
  NotShared<DOMUint8Array> u8array =
      NativeValueTraits<NotShared<DOMUint8Array>>::NativeValue(
          scope.GetIsolate(), value, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(u8array);
  EXPECT_THAT(u8array->ByteSpan(), ElementsAre('w', 'h', 'a', 't'));
}

TEST_F(WebTransportTest, CreateReceiveStreamThenClose) {
  V8TestingScope scope;

  auto* script_state = scope.GetScriptState();
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  EXPECT_CALL(*mock_web_transport_, Close());

  mojo::ScopedDataPipeProducerHandle producer = DoAcceptUnidirectionalStream();

  ReceiveStream* receive_stream = ReadReceiveStream(scope, web_transport);

  auto* reader = receive_stream->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester read_tester(script_state, read_promise);

  web_transport->close(nullptr);

  read_tester.WaitUntilSettled();
  EXPECT_TRUE(read_tester.IsRejected());
  WebTransportError* exception = V8WebTransportError::ToWrappable(
      scope.GetIsolate(), read_tester.Value().V8Value());
  ASSERT_TRUE(exception);
  EXPECT_EQ(exception->name(), "WebTransportError");
  EXPECT_EQ(exception->source(), "session");
  EXPECT_EQ(exception->streamErrorCode(), std::nullopt);
}

TEST_F(WebTransportTest, CreateReceiveStreamThenRemoteClose) {
  V8TestingScope scope;

  auto* script_state = scope.GetScriptState();
  auto* web_transport =
      CreateAndConnectSuccessfully(scope, "https://example.com");

  mojo::ScopedDataPipeProducerHandle producer = DoAcceptUnidirectionalStream();

  ReceiveStream* receive_stream = ReadReceiveStream(scope, web_transport);

  auto* reader = receive_stream->GetDefaultReaderForTesting(
      script_state, ASSERT_NO_EXCEPTION);
  auto read_promise = reader->read(script_state, ASSERT_NO_EXCEPTION);
  ScriptPromiseTester read_tester(script_state, read_promise);

  client_remote_.rese
"""


```