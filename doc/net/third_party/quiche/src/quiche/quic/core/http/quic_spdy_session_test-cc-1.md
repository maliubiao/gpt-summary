Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium network stack file. The file `quic_spdy_session_test.cc` is a test file for `QuicSpdySession`. I need to analyze the individual test cases to understand the functionalities being tested. I should also look for connections to Javascript functionalities (likely through the networking stack), logical reasoning (input/output of tested functions), common user/programming errors, and how a user operation might lead to this code being executed.

**Overall Functionality of the Snippet:**

The provided code snippet focuses on testing various aspects of the `QuicSpdySession` class, particularly related to:

1. **Stream Management:** Blocking/unblocking streams, handling closed streams, managing the number of open streams.
2. **Congestion Control:** How the session interacts with the congestion control algorithm.
3. **Write Buffering and Bundling:** How the session buffers and bundles data for sending.
4. **GoAway Frames:** Sending and receiving GOAWAY frames (both legacy and HTTP/3).
5. **Connectivity Probing:** Responding to connectivity probes.
6. **Idle Timeout:** Adjusting the idle timeout after the handshake.
7. **Stream Resets:** Handling RST_STREAM and STOP_SENDING frames, especially on static and invalid stream IDs, and before headers are decompressed.
8. **Flow Control:**  Connection and stream level flow control, and how the handshake affects it.
9. **Error Handling:** Handling invalid configurations and states.

**Step-by-step Analysis of Each Test Case:**

* **`IllRepeatedly` Test:** Focuses on a scenario where a stream repeatedly signals that it's write blocked.
* **`TooLargeStreamBlocked` Test:** Checks the behavior when the maximum number of incoming streams is reached.
* **`OnCanWriteBundlesStreams` Test:** Verifies that data from multiple streams can be bundled into a single packet.
* **`OnCanWriteCongestionControlBlocks` Test:** Examines how congestion control affects the ability to write to streams.
* **`OnCanWriteWriterBlocks` Test:** Tests the scenario where the underlying writer is blocked.
* **`BufferedHandshake` Test:**  Checks the prioritization of the crypto stream during the handshake when other streams are blocked.
* **`OnCanWriteWithClosedStream` Test:**  Ensures that closed streams don't interfere with the `OnCanWrite` logic.
* **`OnCanWriteLimitsNumWritesIfFlowControlBlocked` Test:** Verifies that the number of writes is limited when flow control is blocked.
* **`SendGoAway` Test:** Tests sending a GOAWAY frame.
* **`SendGoAwayWithoutEncryption` Test:** Tests sending a GOAWAY frame before encryption is established.
* **`SendHttp3GoAway` Test:** Tests sending an HTTP/3 GOAWAY frame.
* **`SendHttp3GoAwayAndNoMoreMaxStreams` Test:** Verifies that MAX_STREAMS frames aren't sent after sending a GOAWAY in HTTP/3.
* **`SendHttp3GoAwayWithoutEncryption` Test:** Tests sending an HTTP/3 GOAWAY frame without encryption.
* **`SendHttp3GoAwayAfterStreamIsCreated` Test:** Tests sending an HTTP/3 GOAWAY frame after a stream is created.
* **`DoNotSendGoAwayTwice` Test:** Checks that GOAWAY frames are not sent multiple times.
* **`InvalidGoAway` Test:** Tests the handling of an invalid GOAWAY frame.
* **`Http3GoAwayLargerIdThanBefore` Test:** Verifies the handling of HTTP/3 GOAWAY frames with increasing IDs.
* **`ServerReplyToConnecitivityProbe` Test:** Tests the server's response to a connectivity probe.
* **`IncreasedTimeoutAfterCryptoHandshake` Test:** Checks the increase in idle timeout after the handshake.
* **`RstStreamBeforeHeadersDecompressed` Test:**  Tests handling of RST_STREAM frames received before headers are decompressed.
* **`OnStreamFrameFinStaticStreamId` Test:** Checks the behavior when a FIN is received for a static stream.
* **`OnRstStreamStaticStreamId` Test:** Tests handling of RST_STREAM frames for static streams.
* **`OnStreamFrameInvalidStreamId` Test:**  Verifies the behavior when data is received for an invalid stream ID.
* **`OnRstStreamInvalidStreamId` Test:** Checks the handling of RST_STREAM frames for invalid stream IDs.
* **`HandshakeUnblocksFlowControlBlockedStream` Test:** Tests that completing the handshake unblocks flow-control blocked streams.
* **`HandshakeUnblocksFlowControlBlockedHeadersStream` Test:**  Verifies that completing the handshake unblocks the flow-control blocked headers stream.
* **`ConnectionFlowControlAccountingRstOutOfOrder` Test:** Tests flow control accounting when an out-of-order RST_STREAM is received.
* **`InvalidStreamFlowControlWindowInHandshake` Test:** Checks the handling of invalid stream flow control windows during the handshake.
这是`net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc`文件的第2部分，主要测试了`QuicSpdySession`类的以下功能：

**功能归纳:**

1. **处理重复的写阻塞:**  测试了当一个流持续报告写阻塞时会发生什么，以及如何处理这种情况，避免无限循环。
2. **处理过多的流被阻塞:**  测试了当达到最大流数量限制时，会发送 `STREAMS_BLOCKED` 帧（仅限IETF QUIC）。
3. **`OnCanWrite` 方法的流数据捆绑:**  验证了当多个流准备好写入时，`OnCanWrite` 方法能否将它们的数据捆绑到一个数据包中发送，以提高效率。
4. **`OnCanWrite` 方法受拥塞控制的影响:** 测试了当拥塞控制阻止发送时，`OnCanWrite` 方法的行为，以及如何根据拥塞窗口的状态来调度流的写入。
5. **`OnCanWrite` 方法受写入器阻塞的影响:** 验证了当底层的写入器被阻塞时，`OnCanWrite` 方法不会调用流的 `OnCanWrite`，并且正确处理 application-limited 信号。
6. **握手过程中的缓冲处理:**  测试了当加密流因缓冲而阻塞时，session 能否检测到，并优先处理加密流的写入。
7. **`OnCanWrite` 方法处理已关闭的流:**  验证了 `OnCanWrite` 方法在有已关闭的流处于写阻塞状态时，能够正常工作，不会尝试写入已关闭的流。
8. **当流控阻塞时限制 `OnCanWrite` 的写入次数:** 测试了当连接层面流控被阻塞时，即使某些流处于写阻塞状态，也不会允许它们写入数据，但加密流和头部流除外，它们仍然可以发送数据。
9. **发送 GOAWAY 帧:**  测试了发送 `GOAWAY` 帧的功能，包括正常发送和在未建立加密连接时发送。区分了传统 QUIC 的 `GOAWAY` 和 HTTP/3 的 `GOAWAY` 帧的语义。
10. **处理收到的 GOAWAY 帧:**  测试了接收到无效的 `GOAWAY` 帧的处理方式，以及 HTTP/3 中 `GOAWAY` 帧 ID 比之前更大的情况。
11. **响应连接性探测:** 测试了服务器端 session 如何响应客户端发送的连接性探测包。
12. **加密握手后增加超时时间:** 验证了在完成加密握手后，连接的空闲超时时间会增加。
13. **在头部解压缩前收到 RST_STREAM 帧:** 测试了在收到流数据但头部尚未解压缩时，收到 `RST_STREAM` 帧的处理方式。
14. **在静态流 ID 上收到 FIN 或 RST_STREAM 帧:**  测试了当客户端尝试关闭或重置静态流（例如头部流或控制流）时，服务器端的处理，会关闭连接。
15. **在无效流 ID 上收到数据或 RST_STREAM 帧:** 测试了当收到针对无效流 ID 的数据帧或 `RST_STREAM` 帧时，服务器端的处理，会关闭连接。
16. **握手解除流控阻塞的流:** 测试了当流因流控被阻塞时，完成握手（收到包含足够发送窗口偏移量的 SHLO）后，流是否会被解除阻塞。
17. **握手解除流控阻塞的头部流:** 测试了当头部流因流控被阻塞时，完成握手后，头部流是否会被解除阻塞。
18. **乱序 RST_STREAM 帧的连接流控记账:** 测试了当收到乱序的 `RST_STREAM` 帧时，连接层面的流控窗口是否能正确调整。
19. **握手期间无效的流控窗口:** 测试了如果握手期间收到对端发送的无效（小于默认值）的流控窗口，连接是否会被断开。

**与 JavaScript 的关系 (举例说明):**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它所测试的网络栈功能是浏览器中 JavaScript 发起网络请求的基础。

* **用户在浏览器地址栏输入 URL 或点击链接:**  JavaScript 会调用浏览器提供的 Web API (例如 `fetch` 或 `XMLHttpRequest`) 发起 HTTP/3 (或 HTTP/2) 请求。
* **网络栈处理请求:** Chromium 的网络栈会接管这些请求，并使用 QUIC 协议（如果适用）与服务器建立连接。 `QuicSpdySession` 就是在 QUIC 连接之上管理 HTTP/3 或 HTTP/2 流的核心组件。
* **流的创建和管理:** JavaScript 发起的每个请求都会在 QUIC 连接上创建一个或多个流。这里测试的流的创建、阻塞、关闭等功能，直接影响着 JavaScript 发起的请求的生命周期。
* **数据发送和接收:**  JavaScript 发送的请求数据和接收的响应数据，都会通过 QUIC 流进行传输。 `OnCanWrite` 方法的测试关系到何时以及如何将 JavaScript 产生的数据发送出去。
* **错误处理:**  如果服务器发送 `GOAWAY` 帧，或者由于流控等原因导致连接或流被关闭，网络栈会通知 JavaScript 相关的错误信息，例如 `net::ERR_QUIC_PROTOCOL_ERROR`。
* **性能优化:**  `OnCanWriteBundlesStreams` 测试的流数据捆绑功能，直接关系到网络请求的性能，减少了数据包的数量，降低了延迟，从而提升 JavaScript 应用的用户体验。

**逻辑推理 (假设输入与输出):**

以 `TEST_P(QuicSpdySessionTestServer, OnCanWriteBundlesStreams)` 为例：

**假设输入:**

* 三个已经创建但处于写阻塞状态的出站双向流 (stream2, stream4, stream6)。
* 拥塞控制允许发送数据 (`CanSend(_)` 返回 true)。
* 足够的拥塞窗口 (`GetCongestionWindow()` 返回足够大的值)。

**预期输出:**

* `OnCanWrite` 方法被调用。
* 每个流的 `OnCanWrite` 方法被调用一次。
* 每个流的 `SendStreamData` 方法被调用一次。
* **只发送一个数据包** (`WritePacket(_, _, _, _, _, _)` 被调用一次)。
* 拥塞控制算法的 `OnPacketSent` 和 `OnApplicationLimited` 方法被调用。
* `WillingAndAbleToWrite()` 返回 false，表示当前没有更多数据需要发送。

**用户或编程常见的使用错误 (举例说明):**

* **过早关闭流:** 开发者在 JavaScript 中可能在数据完全发送或接收完成之前就关闭了 `ReadableStream` 或 `WritableStream`，这可能导致连接层面或流层面的错误，触发类似 `OnStreamReset` 的处理逻辑。
* **发送过大的数据:** 开发者尝试通过单个请求发送超过服务器或客户端允许的最大数据量，可能导致流控阻塞或连接关闭。 `TooLargeStreamBlocked` 测试就与此相关。
* **不处理 `GOAWAY` 帧:**  服务器发送 `GOAWAY` 表明即将关闭连接。JavaScript 代码应该能够优雅地处理这种情况，例如停止发送新的请求，完成正在进行的请求，并可能重新连接。如果代码没有处理 `GOAWAY`，可能会导致请求失败或状态错误。
* **依赖静态流 ID:**  开发者错误地假设某些流 ID 是固定的，并在代码中硬编码这些 ID。例如，在 HTTP/3 中，控制流的 ID 是动态分配的。尝试在错误的流 ID 上发送数据或重置流会导致连接错误，正如 `OnStreamFrameFinStaticStreamId` 和 `OnRstStreamStaticStreamId` 测试所展示的。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问一个支持 HTTP/3 的网站，并且发生了与流管理相关的错误：

1. **用户在地址栏输入 URL 并回车:** 浏览器开始解析 URL，并确定需要建立与服务器的连接。
2. **DNS 查询和连接建立:**  浏览器进行 DNS 查询获取服务器 IP 地址，然后尝试建立 TCP 或 UDP 连接（对于 QUIC）。
3. **QUIC 握手:** 如果网站支持 HTTP/3，浏览器会尝试使用 QUIC 协议进行握手。这涉及到交换加密密钥和协商连接参数。
4. **创建 `QuicSpdySession`:**  一旦 QUIC 连接建立，Chromium 网络栈会创建一个 `QuicSpdySession` 对象来管理 HTTP/3 流。
5. **JavaScript 发起请求:** 网页加载完成后，JavaScript 代码可能会通过 `fetch` API 向服务器发起多个请求，例如获取图片、CSS 或其他资源。
6. **流的创建和数据传输:**  每个 `fetch` 请求都会对应 `QuicSpdySession` 中的一个或多个流。数据通过这些流进行发送和接收。
7. **出现问题:**  假设由于服务器繁忙或网络问题，服务器发送了一个 `GOAWAY` 帧，或者由于某种原因导致客户端尝试在一个已经关闭的流上发送数据。
8. **触发 `QuicSpdySession` 的处理逻辑:**  `QuicSpdySession` 会接收并处理这些网络事件，例如调用 `OnGoAway` 或检查流的状态。
9. **测试代码覆盖:**  在开发和测试 Chromium 网络栈时，开发者会编写类似 `quic_spdy_session_test.cc` 这样的测试用例来模拟各种场景，包括上述的错误情况。当用户遇到问题时，开发者可能会检查相关的测试用例是否覆盖了该场景，以便更好地理解和修复 bug。例如，如果用户报告了与 `GOAWAY` 帧处理相关的错误，开发者可能会重点查看 `SendGoAway` 和 `OnGoAway` 相关的测试用例。

**总结:**

这段代码是 `QuicSpdySession` 类的单元测试，涵盖了其在各种网络场景下的核心功能，特别是与流管理、拥塞控制、数据发送和错误处理相关的逻辑。理解这些测试用例有助于理解 QUIC 协议和 Chromium 网络栈的工作原理，并能帮助开发者排查网络相关的错误。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
illRepeatedly(Return(WriteResult(WRITE_STATUS_OK, 0)));

  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  QuicStreamId closed_stream_id = stream2->id();
  // Close the stream.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(closed_stream_id, _));
  stream2->Reset(QUIC_BAD_APPLICATION_PAYLOAD);
  std::string msg =
      absl::StrCat("Marking unknown stream ", closed_stream_id, " blocked.");
  EXPECT_QUIC_BUG(session_->MarkConnectionLevelWriteBlocked(closed_stream_id),
                  msg);
}

TEST_P(QuicSpdySessionTestServer, TooLargeStreamBlocked) {
  Initialize();
  // STREAMS_BLOCKED frame is IETF QUIC only.
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // Simualte the situation where the incoming stream count is at its limit and
  // the peer is blocked.
  QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(
      static_cast<QuicSession*>(&*session_), QuicUtils::GetMaxStreamCount());
  QuicStreamsBlockedFrame frame;
  frame.stream_count = QuicUtils::GetMaxStreamCount();
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(debug_visitor, OnGoAwayFrameSent(_));
  session_->OnStreamsBlockedFrame(frame);
}

TEST_P(QuicSpdySessionTestServer, OnCanWriteBundlesStreams) {
  Initialize();
  // Encryption needs to be established before data can be sent.
  CompleteHandshake();

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_->connection(), send_algorithm);

  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_->CreateOutgoingBidirectionalStream();

  session_->MarkConnectionLevelWriteBlocked(stream2->id());
  session_->MarkConnectionLevelWriteBlocked(stream6->id());
  session_->MarkConnectionLevelWriteBlocked(stream4->id());

  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm, GetCongestionWindow())
      .WillRepeatedly(Return(kMaxOutgoingPacketSize * 10));
  EXPECT_CALL(*send_algorithm, InRecovery()).WillRepeatedly(Return(false));
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_->SendStreamData(stream2);
  }));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_->SendStreamData(stream4);
  }));
  EXPECT_CALL(*stream6, OnCanWrite()).WillOnce(Invoke([this, stream6]() {
    session_->SendStreamData(stream6);
  }));

  // Expect that we only send one packet, the writes from different streams
  // should be bundled together.
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*send_algorithm, OnPacketSent(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_->OnCanWrite();
  EXPECT_FALSE(session_->WillingAndAbleToWrite());
}

TEST_P(QuicSpdySessionTestServer, OnCanWriteCongestionControlBlocks) {
  Initialize();
  CompleteHandshake();
  session_->set_writev_consumes_all_data(true);
  InSequence s;

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_->connection(), send_algorithm);

  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_->CreateOutgoingBidirectionalStream();

  session_->MarkConnectionLevelWriteBlocked(stream2->id());
  session_->MarkConnectionLevelWriteBlocked(stream6->id());
  session_->MarkConnectionLevelWriteBlocked(stream4->id());

  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_->SendStreamData(stream2);
  }));
  EXPECT_CALL(*send_algorithm, GetCongestionWindow()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream6, OnCanWrite()).WillOnce(Invoke([this, stream6]() {
    session_->SendStreamData(stream6);
  }));
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(false));
  // stream4->OnCanWrite is not called.

  session_->OnCanWrite();
  EXPECT_TRUE(session_->WillingAndAbleToWrite());

  // Still congestion-control blocked.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(false));
  session_->OnCanWrite();
  EXPECT_TRUE(session_->WillingAndAbleToWrite());

  // stream4->OnCanWrite is called once the connection stops being
  // congestion-control blocked.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_->SendStreamData(stream4);
  }));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_->OnCanWrite();
  EXPECT_FALSE(session_->WillingAndAbleToWrite());
}

TEST_P(QuicSpdySessionTestServer, OnCanWriteWriterBlocks) {
  Initialize();
  CompleteHandshake();
  // Drive congestion control manually in order to ensure that
  // application-limited signaling is handled correctly.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_->connection(), send_algorithm);
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(true));

  // Drive packet writer manually.
  EXPECT_CALL(*writer_, IsWriteBlocked()).WillRepeatedly(Return(true));
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _)).Times(0);

  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();

  session_->MarkConnectionLevelWriteBlocked(stream2->id());

  EXPECT_CALL(*stream2, OnCanWrite()).Times(0);
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_)).Times(0);

  session_->OnCanWrite();
  EXPECT_TRUE(session_->WillingAndAbleToWrite());
}

TEST_P(QuicSpdySessionTestServer, BufferedHandshake) {
  Initialize();
  // This tests prioritization of the crypto stream when flow control limits are
  // reached. When CRYPTO frames are in use, there is no flow control for the
  // crypto handshake, so this test is irrelevant.
  if (QuicVersionUsesCryptoFrames(transport_version())) {
    return;
  }
  session_->set_writev_consumes_all_data(true);
  EXPECT_FALSE(session_->HasPendingHandshake());  // Default value.

  // Test that blocking other streams does not change our status.
  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  session_->MarkConnectionLevelWriteBlocked(stream2->id());
  EXPECT_FALSE(session_->HasPendingHandshake());

  TestStream* stream3 = session_->CreateOutgoingBidirectionalStream();
  session_->MarkConnectionLevelWriteBlocked(stream3->id());
  EXPECT_FALSE(session_->HasPendingHandshake());

  // Blocking (due to buffering of) the Crypto stream is detected.
  session_->MarkConnectionLevelWriteBlocked(
      QuicUtils::GetCryptoStreamId(transport_version()));
  EXPECT_TRUE(session_->HasPendingHandshake());

  TestStream* stream4 = session_->CreateOutgoingBidirectionalStream();
  session_->MarkConnectionLevelWriteBlocked(stream4->id());
  EXPECT_TRUE(session_->HasPendingHandshake());

  InSequence s;
  // Force most streams to re-register, which is common scenario when we block
  // the Crypto stream, and only the crypto stream can "really" write.

  // Due to prioritization, we *should* be asked to write the crypto stream
  // first.
  // Don't re-register the crypto stream (which signals complete writing).
  TestCryptoStream* crypto_stream = session_->GetMutableCryptoStream();
  EXPECT_CALL(*crypto_stream, OnCanWrite());

  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_->SendStreamData(stream2);
  }));
  EXPECT_CALL(*stream3, OnCanWrite()).WillOnce(Invoke([this, stream3]() {
    session_->SendStreamData(stream3);
  }));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_->SendStreamData(stream4);
    session_->MarkConnectionLevelWriteBlocked(stream4->id());
  }));

  session_->OnCanWrite();
  EXPECT_TRUE(session_->WillingAndAbleToWrite());
  EXPECT_FALSE(session_->HasPendingHandshake());  // Crypto stream wrote.
}

TEST_P(QuicSpdySessionTestServer, OnCanWriteWithClosedStream) {
  Initialize();
  CompleteHandshake();
  session_->set_writev_consumes_all_data(true);
  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_->CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_->CreateOutgoingBidirectionalStream();

  session_->MarkConnectionLevelWriteBlocked(stream2->id());
  session_->MarkConnectionLevelWriteBlocked(stream6->id());
  session_->MarkConnectionLevelWriteBlocked(stream4->id());
  CloseStream(stream6->id());

  InSequence s;
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*stream2, OnCanWrite()).WillOnce(Invoke([this, stream2]() {
    session_->SendStreamData(stream2);
  }));
  EXPECT_CALL(*stream4, OnCanWrite()).WillOnce(Invoke([this, stream4]() {
    session_->SendStreamData(stream4);
  }));
  session_->OnCanWrite();
  EXPECT_FALSE(session_->WillingAndAbleToWrite());
}

TEST_P(QuicSpdySessionTestServer,
       OnCanWriteLimitsNumWritesIfFlowControlBlocked) {
  Initialize();
  CompleteHandshake();
  // Drive congestion control manually in order to ensure that
  // application-limited signaling is handled correctly.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_->connection(), send_algorithm);
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(true));

  // Ensure connection level flow control blockage.
  QuicFlowControllerPeer::SetSendWindowOffset(session_->flow_controller(), 0);
  EXPECT_TRUE(session_->flow_controller()->IsBlocked());
  EXPECT_TRUE(session_->IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_->IsStreamFlowControlBlocked());

  // Mark the crypto and headers streams as write blocked, we expect them to be
  // allowed to write later.
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    session_->MarkConnectionLevelWriteBlocked(
        QuicUtils::GetCryptoStreamId(transport_version()));
  }

  // Create a data stream, and although it is write blocked we never expect it
  // to be allowed to write as we are connection level flow control blocked.
  TestStream* stream = session_->CreateOutgoingBidirectionalStream();
  session_->MarkConnectionLevelWriteBlocked(stream->id());
  EXPECT_CALL(*stream, OnCanWrite()).Times(0);

  // The crypto and headers streams should be called even though we are
  // connection flow control blocked.
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    TestCryptoStream* crypto_stream = session_->GetMutableCryptoStream();
    EXPECT_CALL(*crypto_stream, OnCanWrite());
  }

  if (!VersionUsesHttp3(transport_version())) {
    TestHeadersStream* headers_stream;
    QuicSpdySessionPeer::SetHeadersStream(&*session_, nullptr);
    headers_stream = new TestHeadersStream(&*session_);
    QuicSpdySessionPeer::SetHeadersStream(&*session_, headers_stream);
    session_->MarkConnectionLevelWriteBlocked(
        QuicUtils::GetHeadersStreamId(transport_version()));
    EXPECT_CALL(*headers_stream, OnCanWrite());
  }

  // After the crypto and header streams perform a write, the connection will be
  // blocked by the flow control, hence it should become application-limited.
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));

  session_->OnCanWrite();
  EXPECT_FALSE(session_->WillingAndAbleToWrite());
}

TEST_P(QuicSpdySessionTestServer, SendGoAway) {
  Initialize();
  CompleteHandshake();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // HTTP/3 GOAWAY has different semantic and thus has its own test.
    return;
  }
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallySendControlFrame));
  session_->SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
  EXPECT_TRUE(session_->goaway_sent());

  const QuicStreamId kTestStreamId = 5u;
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(0);
  EXPECT_CALL(*connection_,
              OnStreamReset(kTestStreamId, QUIC_STREAM_PEER_GOING_AWAY))
      .Times(0);
  EXPECT_TRUE(session_->GetOrCreateStream(kTestStreamId));
}

TEST_P(QuicSpdySessionTestServer, SendGoAwayWithoutEncryption) {
  Initialize();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // HTTP/3 GOAWAY has different semantic and thus has its own test.
    return;
  }
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_PEER_GOING_AWAY, "Going Away.",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(0);
  session_->SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
  EXPECT_FALSE(session_->goaway_sent());
}

TEST_P(QuicSpdySessionTestServer, SendHttp3GoAway) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  // Send max stream id (currently 32 bits).
  EXPECT_CALL(debug_visitor, OnGoAwayFrameSent(/* stream_id = */ 0xfffffffc));
  session_->SendHttp3GoAway(QUIC_PEER_GOING_AWAY, "Goaway");
  EXPECT_TRUE(session_->goaway_sent());

  // New incoming stream is not reset.
  const QuicStreamId kTestStreamId =
      GetNthClientInitiatedBidirectionalStreamId(transport_version(), 0);
  EXPECT_CALL(*connection_, OnStreamReset(kTestStreamId, _)).Times(0);
  EXPECT_TRUE(session_->GetOrCreateStream(kTestStreamId));

  // No more GOAWAY frames are sent because they could not convey new
  // information to the client.
  session_->SendHttp3GoAway(QUIC_PEER_GOING_AWAY, "Goaway");
}

TEST_P(QuicSpdySessionTestServer, SendHttp3GoAwayAndNoMoreMaxStreams) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  // Send max stream id (currently 32 bits).
  EXPECT_CALL(debug_visitor, OnGoAwayFrameSent(/* stream_id = */ 0xfffffffc));
  session_->SendHttp3GoAway(QUIC_PEER_GOING_AWAY, "Goaway");
  EXPECT_TRUE(session_->goaway_sent());

  // No MAX_STREAMS frames should be sent, even after all available
  // streams are opened and then closed.
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(0);

  const QuicStreamCount max_streams =
      QuicSessionPeer::ietf_streamid_manager(&*session_)
          ->max_incoming_bidirectional_streams();
  for (QuicStreamCount i = 0; i < max_streams; ++i) {
    QuicStreamId stream_id = StreamCountToId(
        i + 1,
        Perspective::IS_CLIENT,  // Client initates stream, allocs stream id.
        /*bidirectional=*/true);
    EXPECT_NE(nullptr, session_->GetOrCreateStream(stream_id));

    CloseStream(stream_id);
    QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_id,
                                 QUIC_STREAM_CANCELLED,
                                 /* bytes_written = */ 0);
    session_->OnRstStream(rst_frame);
  }
  EXPECT_EQ(max_streams, QuicSessionPeer::ietf_streamid_manager(&*session_)
                             ->max_incoming_bidirectional_streams());
}

TEST_P(QuicSpdySessionTestServer, SendHttp3GoAwayWithoutEncryption) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_PEER_GOING_AWAY, "Goaway",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_->SendHttp3GoAway(QUIC_PEER_GOING_AWAY, "Goaway");
  EXPECT_FALSE(session_->goaway_sent());
}

TEST_P(QuicSpdySessionTestServer, SendHttp3GoAwayAfterStreamIsCreated) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  const QuicStreamId kTestStreamId =
      GetNthClientInitiatedBidirectionalStreamId(transport_version(), 0);
  EXPECT_TRUE(session_->GetOrCreateStream(kTestStreamId));

  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  // Send max stream id (currently 32 bits).
  EXPECT_CALL(debug_visitor, OnGoAwayFrameSent(/* stream_id = */ 0xfffffffc));
  session_->SendHttp3GoAway(QUIC_PEER_GOING_AWAY, "Goaway");
  EXPECT_TRUE(session_->goaway_sent());

  // No more GOAWAY frames are sent because they could not convey new
  // information to the client.
  session_->SendHttp3GoAway(QUIC_PEER_GOING_AWAY, "Goaway");
}

TEST_P(QuicSpdySessionTestServer, DoNotSendGoAwayTwice) {
  Initialize();
  CompleteHandshake();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // HTTP/3 GOAWAY doesn't have such restriction.
    return;
  }
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  session_->SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
  EXPECT_TRUE(session_->goaway_sent());
  session_->SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
}

TEST_P(QuicSpdySessionTestServer, InvalidGoAway) {
  Initialize();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // HTTP/3 GOAWAY has different semantics and thus has its own test.
    return;
  }
  QuicGoAwayFrame go_away(kInvalidControlFrameId, QUIC_PEER_GOING_AWAY,
                          session_->next_outgoing_bidirectional_stream_id(),
                          "");
  session_->OnGoAway(go_away);
}

TEST_P(QuicSpdySessionTestServer, Http3GoAwayLargerIdThanBefore) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  EXPECT_FALSE(session_->goaway_received());
  session_->OnHttp3GoAway(/* id = */ 0);
  EXPECT_TRUE(session_->goaway_received());

  EXPECT_CALL(
      *connection_,
      CloseConnection(
          QUIC_HTTP_GOAWAY_ID_LARGER_THAN_PREVIOUS,
          "GOAWAY received with ID 1 greater than previously received ID 0",
          _));
  session_->OnHttp3GoAway(/* id = */ 1);
}

// Test that server session will send a connectivity probe in response to a
// connectivity probe on the same path.
TEST_P(QuicSpdySessionTestServer, ServerReplyToConnecitivityProbe) {
  Initialize();
  if (VersionHasIetfQuicFrames(transport_version()) ||
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  QuicSocketAddress old_peer_address =
      QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort);
  EXPECT_EQ(old_peer_address, session_->peer_address());

  QuicSocketAddress new_peer_address =
      QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort + 1);

  EXPECT_CALL(*connection_,
              SendConnectivityProbingPacket(nullptr, new_peer_address));

  session_->OnPacketReceived(session_->self_address(), new_peer_address,
                             /*is_connectivity_probe=*/true);
  EXPECT_EQ(old_peer_address, session_->peer_address());
}

TEST_P(QuicSpdySessionTestServer, IncreasedTimeoutAfterCryptoHandshake) {
  Initialize();
  EXPECT_EQ(kInitialIdleTimeoutSecs + 3,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
  CompleteHandshake();
  EXPECT_EQ(kMaximumIdleTimeoutSecs + 3,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
}

TEST_P(QuicSpdySessionTestServer, RstStreamBeforeHeadersDecompressed) {
  Initialize();
  CompleteHandshake();
  // Send two bytes of payload.
  QuicStreamFrame data1(GetNthClientInitiatedBidirectionalId(0), false, 0,
                        absl::string_view("HT"));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));

  if (!VersionHasIetfQuicFrames(transport_version())) {
    // For version99, OnStreamReset gets called because of the STOP_SENDING,
    // below. EXPECT the call there.
    EXPECT_CALL(*connection_,
                OnStreamReset(GetNthClientInitiatedBidirectionalId(0), _));
  }

  EXPECT_CALL(*connection_, SendControlFrame(_));
  QuicRstStreamFrame rst1(kInvalidControlFrameId,
                          GetNthClientInitiatedBidirectionalId(0),
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  session_->OnRstStream(rst1);

  // Create and inject a STOP_SENDING frame. In GOOGLE QUIC, receiving a
  // RST_STREAM frame causes a two-way close. For IETF QUIC, RST_STREAM causes a
  // one-way close.
  if (VersionHasIetfQuicFrames(transport_version())) {
    // Only needed for version 99/IETF QUIC.
    QuicStopSendingFrame stop_sending(kInvalidControlFrameId,
                                      GetNthClientInitiatedBidirectionalId(0),
                                      QUIC_ERROR_PROCESSING_STREAM);
    // Expect the RESET_STREAM that is generated in response to receiving a
    // STOP_SENDING.
    EXPECT_CALL(*connection_,
                OnStreamReset(GetNthClientInitiatedBidirectionalId(0),
                              QUIC_ERROR_PROCESSING_STREAM));
    session_->OnStopSendingFrame(stop_sending);
  }

  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));
  // Connection should remain alive.
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSpdySessionTestServer, OnStreamFrameFinStaticStreamId) {
  Initialize();
  QuicStreamId id;
  // Initialize HTTP/3 control stream.
  if (VersionUsesHttp3(transport_version())) {
    CompleteHandshake();
    id = GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
    char type[] = {kControlStream};

    QuicStreamFrame data1(id, false, 0, absl::string_view(type, 1));
    session_->OnStreamFrame(data1);
  } else {
    id = QuicUtils::GetHeadersStreamId(transport_version());
  }

  // Send two bytes of payload.
  QuicStreamFrame data1(id, true, 0, absl::string_view("HT"));
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_STREAM_ID, "Attempt to close a static stream",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_->OnStreamFrame(data1);
}

TEST_P(QuicSpdySessionTestServer, OnRstStreamStaticStreamId) {
  Initialize();
  QuicStreamId id;
  QuicErrorCode expected_error;
  std::string error_message;
  // Initialize HTTP/3 control stream.
  if (VersionUsesHttp3(transport_version())) {
    CompleteHandshake();
    id = GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
    char type[] = {kControlStream};

    QuicStreamFrame data1(id, false, 0, absl::string_view(type, 1));
    session_->OnStreamFrame(data1);
    expected_error = QUIC_HTTP_CLOSED_CRITICAL_STREAM;
    error_message = "RESET_STREAM received for receive control stream";
  } else {
    id = QuicUtils::GetHeadersStreamId(transport_version());
    expected_error = QUIC_INVALID_STREAM_ID;
    error_message = "Attempt to reset headers stream";
  }

  // Send two bytes of payload.
  QuicRstStreamFrame rst1(kInvalidControlFrameId, id,
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(
      *connection_,
      CloseConnection(expected_error, error_message,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_->OnRstStream(rst1);
}

TEST_P(QuicSpdySessionTestServer, OnStreamFrameInvalidStreamId) {
  Initialize();
  // Send two bytes of payload.
  QuicStreamFrame data1(QuicUtils::GetInvalidStreamId(transport_version()),
                        true, 0, absl::string_view("HT"));
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_->OnStreamFrame(data1);
}

TEST_P(QuicSpdySessionTestServer, OnRstStreamInvalidStreamId) {
  Initialize();
  // Send two bytes of payload.
  QuicRstStreamFrame rst1(kInvalidControlFrameId,
                          QuicUtils::GetInvalidStreamId(transport_version()),
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_->OnRstStream(rst1);
}

TEST_P(QuicSpdySessionTestServer, HandshakeUnblocksFlowControlBlockedStream) {
  Initialize();
  if (connection_->version().handshake_protocol == PROTOCOL_TLS1_3) {
    // This test requires Google QUIC crypto because it assumes streams start
    // off unblocked.
    return;
  }
  // Test that if a stream is flow control blocked, then on receipt of the SHLO
  // containing a suitable send window offset, the stream becomes unblocked.

  // Ensure that Writev consumes all the data it is given (simulate no socket
  // blocking).
  session_->GetMutableCryptoStream()->EstablishZeroRttEncryption();
  session_->set_writev_consumes_all_data(true);

  // Create a stream, and send enough data to make it flow control blocked.
  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  std::string body(kMinimumFlowControlSendWindow, '.');
  EXPECT_FALSE(stream2->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_->IsStreamFlowControlBlocked());
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(AtLeast(1));
  stream2->WriteOrBufferBody(body, false);
  EXPECT_TRUE(stream2->IsFlowControlBlocked());
  EXPECT_TRUE(session_->IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_->IsStreamFlowControlBlocked());

  // Now complete the crypto handshake, resulting in an increased flow control
  // send window.
  CompleteHandshake();
  EXPECT_TRUE(QuicSessionPeer::IsStreamWriteBlocked(&*session_, stream2->id()));
  // Stream is now unblocked.
  EXPECT_FALSE(stream2->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_->IsStreamFlowControlBlocked());
}

#if !defined(OS_IOS)
// This test is failing flakily for iOS bots.
// http://crbug.com/425050
// NOTE: It's not possible to use the standard MAYBE_ convention to disable
// this test on iOS because when this test gets instantiated it ends up with
// various names that are dependent on the parameters passed.
TEST_P(QuicSpdySessionTestServer,
       HandshakeUnblocksFlowControlBlockedHeadersStream) {
  Initialize();
  // This test depends on stream-level flow control for the crypto stream, which
  // doesn't exist when CRYPTO frames are used.
  if (QuicVersionUsesCryptoFrames(transport_version())) {
    return;
  }

  // This test depends on the headers stream, which does not exist when QPACK is
  // used.
  if (VersionUsesHttp3(transport_version())) {
    return;
  }

  // Test that if the header stream is flow control blocked, then if the SHLO
  // contains a larger send window offset, the stream becomes unblocked.
  session_->GetMutableCryptoStream()->EstablishZeroRttEncryption();
  session_->set_writev_consumes_all_data(true);
  TestCryptoStream* crypto_stream = session_->GetMutableCryptoStream();
  EXPECT_FALSE(crypto_stream->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_->IsStreamFlowControlBlocked());
  QuicHeadersStream* headers_stream =
      QuicSpdySessionPeer::GetHeadersStream(&*session_);
  EXPECT_FALSE(headers_stream->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_->IsStreamFlowControlBlocked());
  QuicStreamId stream_id = 5;
  // Write until the header stream is flow control blocked.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  HttpHeaderBlock headers;
  SimpleRandom random;
  while (!headers_stream->IsFlowControlBlocked() && stream_id < 2000) {
    EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
    EXPECT_FALSE(session_->IsStreamFlowControlBlocked());
    headers["header"] = absl::StrCat(random.RandUint64(), random.RandUint64(),
                                     random.RandUint64());
    session_->WriteHeadersOnHeadersStream(stream_id, headers.Clone(), true,
                                          spdy::SpdyStreamPrecedence(0),
                                          nullptr);
    stream_id += IdDelta();
  }
  // Write once more to ensure that the headers stream has buffered data. The
  // random headers may have exactly filled the flow control window.
  session_->WriteHeadersOnHeadersStream(stream_id, std::move(headers), true,
                                        spdy::SpdyStreamPrecedence(0), nullptr);
  EXPECT_TRUE(headers_stream->HasBufferedData());

  EXPECT_TRUE(headers_stream->IsFlowControlBlocked());
  EXPECT_FALSE(crypto_stream->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_->IsStreamFlowControlBlocked());
  EXPECT_FALSE(session_->HasDataToWrite());

  // Now complete the crypto handshake, resulting in an increased flow control
  // send window.
  CompleteHandshake();

  // Stream is now unblocked and will no longer have buffered data.
  EXPECT_FALSE(headers_stream->IsFlowControlBlocked());
  EXPECT_FALSE(session_->IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_->IsStreamFlowControlBlocked());
  EXPECT_TRUE(headers_stream->HasBufferedData());
  EXPECT_TRUE(QuicSessionPeer::IsStreamWriteBlocked(
      &*session_, QuicUtils::GetHeadersStreamId(transport_version())));
}
#endif  // !defined(OS_IOS)

TEST_P(QuicSpdySessionTestServer,
       ConnectionFlowControlAccountingRstOutOfOrder) {
  Initialize();

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  CompleteHandshake();
  // Test that when we receive an out of order stream RST we correctly adjust
  // our connection level flow control receive window.
  // On close, the stream should mark as consumed all bytes between the highest
  // byte consumed so far and the final byte offset from the RST frame.
  TestStream* stream = session_->CreateOutgoingBidirectionalStream();

  const QuicStreamOffset kByteOffset =
      1 + kInitialSessionFlowControlWindowForTest / 2;

  if (!VersionHasIetfQuicFrames(transport_version())) {
    // For version99 the call to OnStreamReset happens as a result of receiving
    // the STOP_SENDING, so set up the EXPECT there.
    EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
    EXPECT_CALL(*connection_, SendControlFrame(_));
  }
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream->id(),
                               QUIC_STREAM_CANCELLED, kByteOffset);
  session_->OnRstStream(rst_frame);
  // Create and inject a STOP_SENDING frame. In GOOGLE QUIC, receiving a
  // RST_STREAM frame causes a two-way close. For IETF QUIC, RST_STREAM causes a
  // one-way close.
  if (VersionHasIetfQuicFrames(transport_version())) {
    // Only needed for version 99/IETF QUIC.
    QuicStopSendingFrame stop_sending(kInvalidControlFrameId, stream->id(),
                                      QUIC_STREAM_CANCELLED);
    // Expect the RESET_STREAM that is generated in response to receiving a
    // STOP_SENDING.
    EXPECT_CALL(*connection_,
                OnStreamReset(stream->id(), QUIC_STREAM_CANCELLED));
    EXPECT_CALL(*connection_, SendControlFrame(_));
    session_->OnStopSendingFrame(stop_sending);
  }

  EXPECT_EQ(kByteOffset, session_->flow_controller()->bytes_consumed());
}

TEST_P(QuicSpdySessionTestServer, InvalidStreamFlowControlWindowInHandshake) {
  Initialize();
  if (GetParam().handshake_protocol == PROTOCOL_TLS1_3) {
    // IETF Quic doesn't require a minimum flow control window.
    return;
  }
  // Test that receipt of an invalid (< default) stream flow control window from
  // the peer results in the connection being torn down.
  const uint32_t kInvalidWindow = kMinimumFlowControlSendWindow - 1;
  QuicConfigPeer::SetRec
```