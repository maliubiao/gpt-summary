Response:
The user is asking for a functional summary of the provided C++ code snippet, which is part of a test file for QUIC session management in the Chromium network stack. The snippet focuses on testing various aspects of `QuicSession`'s behavior, particularly on the server-side. I need to:

1. **Identify the core functionalities being tested:**  These involve handling stream creation, closure, reset, data transmission (including loss and retransmission), message handling, and interactions with connection-level states and timers.
2. **Determine if any tested functionalities relate to JavaScript:** Since this is low-level network code, direct JavaScript interaction is unlikely. However, QUIC is the underlying protocol for many web applications, and some features, like message handling, might have conceptual parallels.
3. **Look for logical reasoning and identify potential input/output:**  Test cases often involve setting up specific conditions (inputs) and verifying the resulting state or actions (outputs).
4. **Identify common user or programming errors the tests might be preventing:** These are usually related to incorrect API usage or logic flaws in the session management.
5. **Infer the user's actions leading to these code paths:**  This involves thinking about the typical lifecycle of a QUIC connection and the events that trigger these functionalities.
6. **Summarize the overall function of this specific part of the test file.**

**Mental Sandbox:**

* **Stream Management:** Many tests revolve around creating, closing, and resetting streams. Input: specific stream IDs, actions like `CloseStream`, `Reset`. Output: state of the stream, calls to `connection_->SendControlFrame`, `connection_->OnStreamReset`.
* **Data Transmission/Retransmission:** Tests like `OnStreamFrameLost` and `RetransmitFrames` simulate packet loss and verify retransmission logic. Input: lost frames. Output: calls to `stream->OnCanWrite`, `stream->RetransmitStreamData`.
* **Message Handling:**  `SendMessage` tests the ability to send messages over the QUIC connection. Input: message data. Output: calls to `connection_->SendMessage`, tracking of message IDs.
* **Unidirectional Streams:** Several tests specifically address unidirectional streams and the expected behavior when trying to write to a read-only stream or receive data on a write-only stream.
* **Stream ID Limits:** The tests related to `NewStreamIdBelowLimit`, `NewStreamIdAtLimit`, and `NewStreamIdAboveLimit` verify the enforcement of stream ID limits. Input: incoming stream frames with various IDs. Output: connection closure if the limit is exceeded.
* **STOP_SENDING Handling:**  Tests around `OnStopSending` check how the session reacts to receiving `STOP_SENDING` frames in different stream states. Input: `STOP_SENDING` frames. Output: potentially sending `RST_STREAM`, connection closure.
* **Zombie Streams:**  Tests with "Zombie Streams" explore how the session manages streams that are no longer fully active.

**JavaScript Connection:** While no direct interaction, concepts like message sending and stream management are fundamental to how web applications built on top of QUIC (like those using the Fetch API over HTTP/3) function. For example, a JavaScript application sending a request would conceptually initiate a QUIC stream.

**High-Level Plan:** I'll go through each test case in the provided snippet, identify its purpose, and then synthesize a summary addressing all the user's requirements.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc` 文件的一部分，主要针对 `QuicSession` 类在 **服务器端** 的行为进行测试。这部分测试涵盖了多种与流（stream）和消息（message）处理相关的场景，以及一些连接管理方面的功能。

**功能归纳（第 4 部分）：**

这部分 `QuicSessionTestServer` 主要测试以下功能：

1. **处理 `MAX_STREAMS` 帧:**  验证服务器是否正确处理客户端发送的 `MAX_STREAMS` 帧，并根据此调整可创建的流的数量。
2. **管理单向流:**  测试服务器如何处理和限制单向流的创建和使用，包括检查单向流是否可用。
3. **处理已关闭读取端的流接收 FIN:** 确保即使流的读取端已关闭，接收到 FIN 也会被记录，防止资源泄露。
4. **拒绝客户端发起的流 ID 的数据帧:** 验证服务器是否正确拒绝使用客户端发起的流 ID 的数据帧。
5. **连接空闲超时处理:**  测试在即将达到空闲超时时，服务器是否会阻止创建新流并发送连接性探测包。
6. **僵尸流（Zombie Streams）管理:**  测试服务器如何处理已经关闭但可能还有未确认数据的流（僵尸流），包括在收到 RST_STREAM 后的处理。
7. **处理在发送 `RST_STREAM` 后收到的 `RST_STREAM`:** 确保在服务器已经发送 `RST_STREAM` 后，再收到对端发送的 `RST_STREAM` 能正确处理。
8. **模拟数据丢失和重传机制:**  测试服务器在数据帧丢失后如何进行重传，包括对加密流和普通流的处理，以及对已关闭流的数据的处理。
9. **重传帧:**  测试服务器如何处理需要重传的帧集合。
10. **处理重传数据导致连接关闭的情况:**  模拟动态流重传丢失数据并导致连接关闭的场景。
11. **发送消息（Message）:**  测试服务器发送消息的功能，包括在加密未建立时的处理、成功发送、消息大小超出限制以及消息的确认和丢失处理。
12. **本地重置僵尸流:**  测试本地重置僵尸流的场景。
13. **清理已关闭流的定时器:**  验证用于清理已关闭流的定时器是否按预期工作。
14. **处理单向流的写入和接收数据:**  测试服务器如何处理尝试写入只读单向流以及在只写单向流上接收数据的情况。
15. **处理单向流的读取和写入操作:**  测试服务器如何处理对只读单向流的读取操作，以及尝试在其上进行写入操作。
16. **基于流 ID 限制接受新流:**  测试服务器如何根据配置的最大流数量来接受或拒绝新的传入流，包括双向流和单向流。
17. **处理无效的 `STOP_SENDING` 帧:**  测试服务器如何处理针对无效流 ID、只读单向流和静态流的 `STOP_SENDING` 帧。
18. **在流已关闭写入端时处理 `STOP_SENDING`:**  确保在流的写入端已关闭时，收到 `STOP_SENDING` 不会发送额外的 `RST_STREAM`。
19. **处理针对僵尸流的 `STOP_SENDING`:**  测试服务器如何处理接收到的针对僵尸流的 `STOP_SENDING` 帧。
20. **处理已关闭流的 `STOP_SENDING`:**  确保在流已完全关闭后收到 `STOP_SENDING` 不会导致问题。

**与 Javascript 功能的关系：**

虽然这段 C++ 代码是网络协议栈的底层实现，不直接与 JavaScript 交互，但它所测试的功能是支撑基于 QUIC 的网络应用（例如使用 HTTP/3 的应用）的基础。

* **流的创建和管理:**  当 JavaScript 发起一个网络请求（例如使用 `fetch` API）时，底层可能就会创建一个 QUIC 流来传输数据。服务器端对流的管理直接影响到这些请求的成功与否。
* **消息的发送:**  虽然 HTTP/3 主要使用流，但 QUIC 协议本身支持消息。未来 JavaScript 的 API 可能直接利用 QUIC 的消息功能，服务器端的这些测试确保了消息传输的可靠性。
* **连接管理和错误处理:**  JavaScript 应用依赖于稳定的网络连接。服务器端对连接管理（如空闲超时处理）和错误处理（如接收到非法帧时关闭连接）的正确实现，保证了应用的稳定运行。

**举例说明:**

假设一个使用 JavaScript 的网页应用通过 HTTP/3 向服务器请求一个图片资源。

1. **假设输入:** 客户端 JavaScript 发起 `fetch('/image.jpg')` 请求。
2. **逻辑推理:** 底层网络栈会在客户端创建一个 QUIC 流，并将 HTTP/3 请求数据发送到服务器。服务器端的 `QuicSession` 接收到客户端发送的数据帧。
3. **服务器端处理:**  `QuicSessionTestServer` 中的一些测试模拟了服务器接收到客户端数据帧后的处理逻辑，例如 `OnStreamFrame` 测试了如何处理接收到的数据。如果客户端发送的流 ID 超出了服务器允许的范围（受到 `MAX_STREAMS` 限制），相关的测试（如 `NewStreamIdAboveLimit`) 确保服务器会正确关闭连接，这最终会导致 JavaScript 的 `fetch` 请求失败。

**用户或编程常见的使用错误举例：**

* **错误地使用流 ID:** 客户端或服务器端在创建或使用流时，可能会错误地使用了不合法的流 ID。例如，客户端可能错误地尝试使用服务器端发起的流 ID 发送数据。`IncomingStreamWithClientInitiatedStreamId` 测试就是为了防止这种错误，如果发生，服务器会关闭连接。
* **未正确处理流的关闭状态:**  开发者在实现网络应用时，可能没有正确处理流的关闭状态，例如在流的读取端已经关闭后，仍然尝试读取数据。`RecordFinAfterReadSideClosed` 测试确保即使在这种情况下，服务器也能正确处理接收到的 FIN 帧。
* **在高负载下创建过多流:**  客户端可能在短时间内尝试创建大量的流，超出服务器的处理能力。服务器端的 `OnMaxStreamFrame` 测试了服务器如何响应客户端发送的 `MAX_STREAMS` 帧，以限制客户端可以创建的流的数量，防止服务器过载。

**用户操作到达这里的调试线索：**

为了调试与 `QuicSession` 服务器端行为相关的问题，开发者可能需要：

1. **查看服务器端的日志:** 检查服务器是否因为接收到无效帧、超出流 ID 限制等原因关闭了连接。
2. **使用网络抓包工具 (如 Wireshark):**  分析客户端和服务器之间的 QUIC 数据包，查看是否存在协议层面的错误，例如错误的流 ID、意外的 `RST_STREAM` 帧等。
3. **在 Chromium 源码中设置断点:**  在 `quic_session.cc` 和相关的代码中设置断点，特别是与 `OnStreamFrame`, `OnRstStream`, `OnStopSendingFrame` 等函数相关的部分，来跟踪数据包的处理流程。
4. **查看 `chrome://net-internals/#quic`:**  在 Chrome 浏览器中，可以通过 `chrome://net-internals/#quic` 页面查看当前活跃的 QUIC 连接信息，包括连接状态、流信息、错误日志等。这可以帮助开发者定位问题。

总而言之，这部分测试覆盖了 `QuicSession` 在服务器端处理流和消息的关键逻辑，确保了 QUIC 协议的正确性和可靠性，从而为基于 QUIC 的网络应用提供了稳定的基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
&MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));

  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
}

TEST_P(QuicSessionTestClient, OnMaxStreamFrame) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  QuicMaxStreamsFrame frame;
  frame.unidirectional = false;
  frame.stream_count = 120;
  EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(false)).Times(1);
  session_.OnMaxStreamsFrame(frame);

  QuicMaxStreamsFrame frame2;
  frame2.unidirectional = false;
  frame2.stream_count = 110;
  EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(false)).Times(0);
  session_.OnMaxStreamsFrame(frame2);
}

TEST_P(QuicSessionTestClient, AvailableUnidirectionalStreamsClient) {
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthServerInitiatedUnidirectionalId(2)) != nullptr);
  // Smaller unidirectional streams should be available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthServerInitiatedUnidirectionalId(0)));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthServerInitiatedUnidirectionalId(1)));
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthServerInitiatedUnidirectionalId(0)) != nullptr);
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthServerInitiatedUnidirectionalId(1)) != nullptr);
  // And 5 should be not available.
  EXPECT_FALSE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthClientInitiatedUnidirectionalId(1)));
}

TEST_P(QuicSessionTestClient, RecordFinAfterReadSideClosed) {
  CompleteHandshake();
  // Verify that an incoming FIN is recorded in a stream object even if the read
  // side has been closed.  This prevents an entry from being made in
  // locally_closed_streams_highest_offset_ (which will never be deleted).
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  QuicStreamId stream_id = stream->id();

  // Close the read side manually.
  QuicStreamPeer::CloseReadSide(stream);

  // Receive a stream data frame with FIN.
  QuicStreamFrame frame(stream_id, true, 0, absl::string_view());
  session_.OnStreamFrame(frame);
  EXPECT_TRUE(stream->fin_received());

  // Reset stream locally.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream));

  EXPECT_TRUE(connection_->connected());
  EXPECT_TRUE(QuicSessionPeer::IsStreamClosed(&session_, stream_id));
  EXPECT_FALSE(QuicSessionPeer::IsStreamCreated(&session_, stream_id));

  // The stream is not waiting for the arrival of the peer's final offset as it
  // was received with the FIN earlier.
  EXPECT_EQ(
      0u,
      QuicSessionPeer::GetLocallyClosedStreamsHighestOffset(&session_).size());
}

TEST_P(QuicSessionTestClient, IncomingStreamWithClientInitiatedStreamId) {
  const QuicErrorCode expected_error =
      VersionHasIetfQuicFrames(transport_version())
          ? QUIC_HTTP_STREAM_WRONG_DIRECTION
          : QUIC_INVALID_STREAM_ID;
  EXPECT_CALL(
      *connection_,
      CloseConnection(expected_error, "Data for nonexistent stream",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));

  QuicStreamFrame frame(GetNthClientInitiatedBidirectionalId(1),
                        /* fin = */ false, /* offset = */ 0,
                        absl::string_view("foo"));
  session_.OnStreamFrame(frame);
}

TEST_P(QuicSessionTestClient, MinAckDelaySetOnTheClientQuicConfig) {
  if (!session_.version().HasIetfQuicFrames()) {
    return;
  }
  session_.config()->SetClientConnectionOptions({kAFFE});
  session_.Initialize();
  ASSERT_EQ(session_.config()->GetMinAckDelayToSendMs(),
            kDefaultMinAckDelayTimeMs);
  ASSERT_TRUE(session_.connection()->can_receive_ack_frequency_frame());
}

TEST_P(QuicSessionTestClient, FailedToCreateStreamIfTooCloseToIdleTimeout) {
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(session_.CanOpenNextOutgoingBidirectionalStream());
  QuicTime deadline = QuicConnectionPeer::GetIdleNetworkDeadline(connection_);
  ASSERT_TRUE(deadline.IsInitialized());
  QuicTime::Delta timeout = deadline - helper_.GetClock()->ApproximateNow();
  // Advance time to very close idle timeout.
  connection_->AdvanceTime(timeout - QuicTime::Delta::FromMilliseconds(1));
  // Verify creation of new stream gets pushed back and connectivity probing
  // packet gets sent.
  EXPECT_CALL(*connection_, SendConnectivityProbingPacket(_, _)).Times(1);
  EXPECT_FALSE(session_.CanOpenNextOutgoingBidirectionalStream());

  // New packet gets received, idle deadline gets extended.
  EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(false));
  QuicConnectionPeer::GetIdleNetworkDetector(connection_)
      .OnPacketReceived(helper_.GetClock()->ApproximateNow());
  session_.OnPacketDecrypted(ENCRYPTION_FORWARD_SECURE);

  EXPECT_TRUE(session_.CanOpenNextOutgoingBidirectionalStream());
}

TEST_P(QuicSessionTestServer, ZombieStreams) {
  CompleteHandshake();
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  QuicStreamPeer::SetStreamBytesWritten(3, stream2);
  EXPECT_TRUE(stream2->IsWaitingForAcks());

  CloseStream(stream2->id());
  ASSERT_EQ(1u, session_.closed_streams()->size());
  EXPECT_EQ(stream2->id(), session_.closed_streams()->front()->id());
  session_.MaybeCloseZombieStream(stream2->id());
  EXPECT_EQ(1u, session_.closed_streams()->size());
  EXPECT_EQ(stream2->id(), session_.closed_streams()->front()->id());
}

TEST_P(QuicSessionTestServer, RstStreamReceivedAfterRstStreamSent) {
  CompleteHandshake();
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  QuicStreamPeer::SetStreamBytesWritten(3, stream2);
  EXPECT_TRUE(stream2->IsWaitingForAcks());

  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream2->id(), _));
  EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(false)).Times(0);
  stream2->Reset(quic::QUIC_STREAM_CANCELLED);

  QuicRstStreamFrame rst1(kInvalidControlFrameId, stream2->id(),
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  if (!VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(false)).Times(1);
  }
  session_.OnRstStream(rst1);
}

// Regression test of b/71548958.
TEST_P(QuicSessionTestServer, TestZombieStreams) {
  CompleteHandshake();
  session_.set_writev_consumes_all_data(true);

  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  std::string body(100, '.');
  stream2->WriteOrBufferData(body, false, nullptr);
  EXPECT_TRUE(stream2->IsWaitingForAcks());
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream2).size());

  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream2->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  // Just for the RST_STREAM
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  if (VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_CALL(*connection_,
                OnStreamReset(stream2->id(), QUIC_STREAM_CANCELLED));
  } else {
    EXPECT_CALL(*connection_,
                OnStreamReset(stream2->id(), QUIC_RST_ACKNOWLEDGEMENT));
  }
  stream2->OnStreamReset(rst_frame);

  if (VersionHasIetfQuicFrames(transport_version())) {
    // The test requires the stream to be fully closed in both directions. For
    // IETF QUIC, the RST_STREAM only closes one side.
    QuicStopSendingFrame frame(kInvalidControlFrameId, stream2->id(),
                               QUIC_STREAM_CANCELLED);
    EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
    session_.OnStopSendingFrame(frame);
  }
  ASSERT_EQ(1u, session_.closed_streams()->size());
  EXPECT_EQ(stream2->id(), session_.closed_streams()->front()->id());

  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // Once for the RST_STREAM, once for the STOP_SENDING
    EXPECT_CALL(*connection_, SendControlFrame(_))
        .Times(2)
        .WillRepeatedly(Invoke(&ClearControlFrame));
  } else {
    // Just for the RST_STREAM
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(1);
  }
  EXPECT_CALL(*connection_,
              OnStreamReset(stream4->id(), QUIC_STREAM_CANCELLED));
  stream4->WriteOrBufferData(body, false, nullptr);
  // Note well: Reset() actually closes the stream in both directions. For
  // GOOGLE QUIC it sends a RST_STREAM (which does a 2-way close), for IETF
  // QUIC it sends both a RST_STREAM and a STOP_SENDING (each of which
  // closes in only one direction).
  stream4->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_EQ(2u, session_.closed_streams()->size());
}

TEST_P(QuicSessionTestServer, OnStreamFrameLost) {
  CompleteHandshake();
  InSequence s;

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), send_algorithm);

  TestCryptoStream* crypto_stream = session_.GetMutableCryptoStream();
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();

  QuicStreamFrame frame1;
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    frame1 = QuicStreamFrame(
        QuicUtils::GetCryptoStreamId(connection_->transport_version()), false,
        0, 1300);
  }
  QuicStreamFrame frame2(stream2->id(), false, 0, 9);
  QuicStreamFrame frame3(stream4->id(), false, 0, 9);

  // Lost data on cryption stream, streams 2 and 4.
  EXPECT_CALL(*stream4, HasPendingRetransmission()).WillOnce(Return(true));
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .WillOnce(Return(true));
  }
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(true));
  session_.OnFrameLost(QuicFrame(frame3));
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    session_.OnFrameLost(QuicFrame(frame1));
  } else {
    QuicCryptoFrame crypto_frame(ENCRYPTION_INITIAL, 0, 1300);
    session_.OnFrameLost(QuicFrame(&crypto_frame));
  }
  session_.OnFrameLost(QuicFrame(frame2));
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  // Mark streams 2 and 4 write blocked.
  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  // Lost data is retransmitted before new data, and retransmissions for crypto
  // stream go first.
  // Do not check congestion window when crypto stream has lost data.
  EXPECT_CALL(*send_algorithm, CanSend(_)).Times(0);
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    EXPECT_CALL(*crypto_stream, OnCanWrite());
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .WillOnce(Return(false));
  }
  // Check congestion window for non crypto streams.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream4, OnCanWrite());
  EXPECT_CALL(*stream4, HasPendingRetransmission()).WillOnce(Return(false));
  // Connection is blocked.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillRepeatedly(Return(false));

  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  // Unblock connection.
  // Stream 2 retransmits lost data.
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(false));
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  // Stream 2 sends new data.
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*send_algorithm, CanSend(_)).WillOnce(Return(true));
  EXPECT_CALL(*stream4, OnCanWrite());
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));

  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, DonotRetransmitDataOfClosedStreams) {
  CompleteHandshake();
  InSequence s;

  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_.CreateOutgoingBidirectionalStream();

  QuicStreamFrame frame1(stream2->id(), false, 0, 9);
  QuicStreamFrame frame2(stream4->id(), false, 0, 9);
  QuicStreamFrame frame3(stream6->id(), false, 0, 9);

  EXPECT_CALL(*stream6, HasPendingRetransmission()).WillOnce(Return(true));
  EXPECT_CALL(*stream4, HasPendingRetransmission()).WillOnce(Return(true));
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(true));
  session_.OnFrameLost(QuicFrame(frame3));
  session_.OnFrameLost(QuicFrame(frame2));
  session_.OnFrameLost(QuicFrame(frame1));

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());

  // Reset stream 4 locally.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream4->id(), _));
  stream4->Reset(QUIC_STREAM_CANCELLED);

  // Verify stream 4 is removed from streams with lost data list.
  EXPECT_CALL(*stream6, OnCanWrite());
  EXPECT_CALL(*stream6, HasPendingRetransmission()).WillOnce(Return(false));
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*stream2, HasPendingRetransmission()).WillOnce(Return(false));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*stream2, OnCanWrite());
  EXPECT_CALL(*stream6, OnCanWrite());
  session_.OnCanWrite();
}

TEST_P(QuicSessionTestServer, RetransmitFrames) {
  CompleteHandshake();
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), send_algorithm);
  InSequence s;

  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream4 = session_.CreateOutgoingBidirectionalStream();
  TestStream* stream6 = session_.CreateOutgoingBidirectionalStream();
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  session_.SendWindowUpdate(stream2->id(), 9);

  QuicStreamFrame frame1(stream2->id(), false, 0, 9);
  QuicStreamFrame frame2(stream4->id(), false, 0, 9);
  QuicStreamFrame frame3(stream6->id(), false, 0, 9);
  QuicWindowUpdateFrame window_update(1, stream2->id(), 9);
  QuicFrames frames;
  frames.push_back(QuicFrame(frame1));
  frames.push_back(QuicFrame(window_update));
  frames.push_back(QuicFrame(frame2));
  frames.push_back(QuicFrame(frame3));
  EXPECT_FALSE(session_.WillingAndAbleToWrite());

  EXPECT_CALL(*stream2, RetransmitStreamData(_, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&ClearControlFrame));
  EXPECT_CALL(*stream4, RetransmitStreamData(_, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*stream6, RetransmitStreamData(_, _, _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_.RetransmitFrames(frames, PTO_RETRANSMISSION);
}

// Regression test of b/110082001.
TEST_P(QuicSessionTestServer, RetransmitLostDataCausesConnectionClose) {
  CompleteHandshake();
  // This test mimics the scenario when a dynamic stream retransmits lost data
  // and causes connection close.
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  QuicStreamFrame frame(stream->id(), false, 0, 9);

  EXPECT_CALL(*stream, HasPendingRetransmission())
      .Times(2)
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  session_.OnFrameLost(QuicFrame(frame));
  // Retransmit stream data causes connection close. Stream has not sent fin
  // yet, so an RST is sent.
  EXPECT_CALL(*stream, OnCanWrite()).WillOnce(Invoke([this, stream]() {
    session_.ResetStream(stream->id(), QUIC_STREAM_CANCELLED);
  }));
  if (VersionHasIetfQuicFrames(transport_version())) {
    // Once for the RST_STREAM, once for the STOP_SENDING
    EXPECT_CALL(*connection_, SendControlFrame(_))
        .Times(2)
        .WillRepeatedly(Invoke(&session_, &TestSession::SaveFrame));
  } else {
    // Just for the RST_STREAM
    EXPECT_CALL(*connection_, SendControlFrame(_))
        .WillOnce(Invoke(&session_, &TestSession::SaveFrame));
  }
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
  session_.OnCanWrite();
}

TEST_P(QuicSessionTestServer, SendMessage) {
  // Cannot send message when encryption is not established.
  EXPECT_FALSE(session_.OneRttKeysAvailable());
  EXPECT_EQ(MessageResult(MESSAGE_STATUS_ENCRYPTION_NOT_ESTABLISHED, 0),
            session_.SendMessage(MemSliceFromString("")));

  CompleteHandshake();
  EXPECT_TRUE(session_.OneRttKeysAvailable());

  EXPECT_CALL(*connection_, SendMessage(1, _, false))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));
  EXPECT_EQ(MessageResult(MESSAGE_STATUS_SUCCESS, 1),
            session_.SendMessage(MemSliceFromString("")));
  // Verify message_id increases.
  EXPECT_CALL(*connection_, SendMessage(2, _, false))
      .WillOnce(Return(MESSAGE_STATUS_TOO_LARGE));
  EXPECT_EQ(MessageResult(MESSAGE_STATUS_TOO_LARGE, 0),
            session_.SendMessage(MemSliceFromString("")));
  // Verify unsent message does not consume a message_id.
  EXPECT_CALL(*connection_, SendMessage(2, _, false))
      .WillOnce(Return(MESSAGE_STATUS_SUCCESS));
  EXPECT_EQ(MessageResult(MESSAGE_STATUS_SUCCESS, 2),
            session_.SendMessage(MemSliceFromString("")));

  QuicMessageFrame frame(1);
  QuicMessageFrame frame2(2);
  EXPECT_FALSE(session_.IsFrameOutstanding(QuicFrame(&frame)));
  EXPECT_FALSE(session_.IsFrameOutstanding(QuicFrame(&frame2)));

  // Lost message 2.
  session_.OnMessageLost(2);
  EXPECT_FALSE(session_.IsFrameOutstanding(QuicFrame(&frame2)));

  // message 1 gets acked.
  session_.OnMessageAcked(1, QuicTime::Zero());
  EXPECT_FALSE(session_.IsFrameOutstanding(QuicFrame(&frame)));
}

// Regression test of b/115323618.
TEST_P(QuicSessionTestServer, LocallyResetZombieStreams) {
  CompleteHandshake();
  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  std::string body(100, '.');
  QuicStreamPeer::CloseReadSide(stream2);
  stream2->WriteOrBufferData(body, true, nullptr);
  EXPECT_TRUE(stream2->IsWaitingForAcks());
  // Verify stream2 is a zombie streams.
  auto& stream_map = QuicSessionPeer::stream_map(&session_);
  ASSERT_TRUE(stream_map.contains(stream2->id()));
  auto* stream = stream_map.find(stream2->id())->second.get();
  EXPECT_TRUE(stream->IsZombie());

  QuicStreamFrame frame(stream2->id(), true, 0, 100);
  EXPECT_CALL(*stream2, HasPendingRetransmission())
      .WillRepeatedly(Return(true));
  session_.OnFrameLost(QuicFrame(frame));

  // Reset stream2 locally.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(stream2->id(), _));
  stream2->Reset(QUIC_STREAM_CANCELLED);

  // Verify stream 2 gets closed.
  EXPECT_TRUE(session_.IsClosedStream(stream2->id()));
  EXPECT_CALL(*stream2, OnCanWrite()).Times(0);
  session_.OnCanWrite();
}

TEST_P(QuicSessionTestServer, CleanUpClosedStreamsAlarm) {
  CompleteHandshake();
  EXPECT_FALSE(
      QuicSessionPeer::GetCleanUpClosedStreamsAlarm(&session_)->IsSet());

  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  EXPECT_FALSE(stream2->IsWaitingForAcks());

  CloseStream(stream2->id());
  EXPECT_EQ(1u, session_.closed_streams()->size());
  EXPECT_TRUE(
      QuicSessionPeer::GetCleanUpClosedStreamsAlarm(&session_)->IsSet());

  alarm_factory_.FireAlarm(
      QuicSessionPeer::GetCleanUpClosedStreamsAlarm(&session_));
  EXPECT_TRUE(session_.closed_streams()->empty());
}

TEST_P(QuicSessionTestServer, WriteUnidirectionalStream) {
  session_.set_writev_consumes_all_data(true);
  TestStream* stream4 = new TestStream(GetNthServerInitiatedUnidirectionalId(1),
                                       &session_, WRITE_UNIDIRECTIONAL);
  session_.ActivateStream(absl::WrapUnique(stream4));
  std::string body(100, '.');
  stream4->WriteOrBufferData(body, false, nullptr);
  stream4->WriteOrBufferData(body, true, nullptr);
  auto& stream_map = QuicSessionPeer::stream_map(&session_);
  ASSERT_TRUE(stream_map.contains(stream4->id()));
  auto* stream = stream_map.find(stream4->id())->second.get();
  EXPECT_TRUE(stream->IsZombie());
}

TEST_P(QuicSessionTestServer, ReceivedDataOnWriteUnidirectionalStream) {
  TestStream* stream4 = new TestStream(GetNthServerInitiatedUnidirectionalId(1),
                                       &session_, WRITE_UNIDIRECTIONAL);
  session_.ActivateStream(absl::WrapUnique(stream4));

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_DATA_RECEIVED_ON_WRITE_UNIDIRECTIONAL_STREAM, _, _))
      .Times(1);
  QuicStreamFrame stream_frame(GetNthServerInitiatedUnidirectionalId(1), false,
                               0, 2);
  session_.OnStreamFrame(stream_frame);
}

TEST_P(QuicSessionTestServer, ReadUnidirectionalStream) {
  TestStream* stream4 = new TestStream(GetNthClientInitiatedUnidirectionalId(1),
                                       &session_, READ_UNIDIRECTIONAL);
  session_.ActivateStream(absl::WrapUnique(stream4));
  EXPECT_FALSE(stream4->IsWaitingForAcks());
  // Discard all incoming data.
  stream4->StopReading();

  std::string data(100, '.');
  QuicStreamFrame stream_frame(GetNthClientInitiatedUnidirectionalId(1), false,
                               0, data);
  stream4->OnStreamFrame(stream_frame);
  EXPECT_TRUE(session_.closed_streams()->empty());

  QuicStreamFrame stream_frame2(GetNthClientInitiatedUnidirectionalId(1), true,
                                100, data);
  stream4->OnStreamFrame(stream_frame2);
  EXPECT_EQ(1u, session_.closed_streams()->size());
}

TEST_P(QuicSessionTestServer, WriteOrBufferDataOnReadUnidirectionalStream) {
  TestStream* stream4 = new TestStream(GetNthClientInitiatedUnidirectionalId(1),
                                       &session_, READ_UNIDIRECTIONAL);
  session_.ActivateStream(absl::WrapUnique(stream4));

  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM, _, _))
      .Times(1);
  std::string body(100, '.');
  stream4->WriteOrBufferData(body, false, nullptr);
}

TEST_P(QuicSessionTestServer, WritevDataOnReadUnidirectionalStream) {
  TestStream* stream4 = new TestStream(GetNthClientInitiatedUnidirectionalId(1),
                                       &session_, READ_UNIDIRECTIONAL);
  session_.ActivateStream(absl::WrapUnique(stream4));

  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM, _, _))
      .Times(1);
  std::string body(100, '.');
  struct iovec iov = {const_cast<char*>(body.data()), body.length()};
  quiche::QuicheMemSliceStorage storage(
      &iov, 1, session_.connection()->helper()->GetStreamSendBufferAllocator(),
      1024);
  stream4->WriteMemSlices(storage.ToSpan(), false);
}

TEST_P(QuicSessionTestServer, WriteMemSlicesOnReadUnidirectionalStream) {
  TestStream* stream4 = new TestStream(GetNthClientInitiatedUnidirectionalId(1),
                                       &session_, READ_UNIDIRECTIONAL);
  session_.ActivateStream(absl::WrapUnique(stream4));

  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM, _, _))
      .Times(1);
  std::string data(1024, 'a');
  std::vector<quiche::QuicheMemSlice> buffers;
  buffers.push_back(MemSliceFromString(data));
  buffers.push_back(MemSliceFromString(data));
  stream4->WriteMemSlices(absl::MakeSpan(buffers), false);
}

// Test code that tests that an incoming stream frame with a new (not previously
// seen) stream id is acceptable. The ID must not be larger than has been
// advertised. It may be equal to what has been advertised.  These tests
// invoke QuicStreamIdManager::MaybeIncreaseLargestPeerStreamId by calling
// QuicSession::OnStreamFrame in order to check that all the steps are connected
// properly and that nothing in the call path interferes with the check.
// First test make sure that streams with ids below the limit are accepted.
TEST_P(QuicSessionTestServer, NewStreamIdBelowLimit) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    // Applicable only to IETF QUIC
    return;
  }
  QuicStreamId bidirectional_stream_id = StreamCountToId(
      QuicSessionPeer::ietf_streamid_manager(&session_)
              ->advertised_max_incoming_bidirectional_streams() -
          1,
      Perspective::IS_CLIENT,
      /*bidirectional=*/true);

  QuicStreamFrame bidirectional_stream_frame(bidirectional_stream_id, false, 0,
                                             "Random String");
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_.OnStreamFrame(bidirectional_stream_frame);

  QuicStreamId unidirectional_stream_id = StreamCountToId(
      QuicSessionPeer::ietf_streamid_manager(&session_)
              ->advertised_max_incoming_unidirectional_streams() -
          1,
      Perspective::IS_CLIENT,
      /*bidirectional=*/false);
  QuicStreamFrame unidirectional_stream_frame(unidirectional_stream_id, false,
                                              0, "Random String");
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_.OnStreamFrame(unidirectional_stream_frame);
}

// Accept a stream with an ID that equals the limit.
TEST_P(QuicSessionTestServer, NewStreamIdAtLimit) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    // Applicable only to IETF QUIC
    return;
  }
  QuicStreamId bidirectional_stream_id =
      StreamCountToId(QuicSessionPeer::ietf_streamid_manager(&session_)
                          ->advertised_max_incoming_bidirectional_streams(),
                      Perspective::IS_CLIENT, /*bidirectional=*/true);
  QuicStreamFrame bidirectional_stream_frame(bidirectional_stream_id, false, 0,
                                             "Random String");
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_.OnStreamFrame(bidirectional_stream_frame);

  QuicStreamId unidirectional_stream_id =
      StreamCountToId(QuicSessionPeer::ietf_streamid_manager(&session_)
                          ->advertised_max_incoming_unidirectional_streams(),
                      Perspective::IS_CLIENT, /*bidirectional=*/false);
  QuicStreamFrame unidirectional_stream_frame(unidirectional_stream_id, false,
                                              0, "Random String");
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_.OnStreamFrame(unidirectional_stream_frame);
}

// Close the connection if the id exceeds the limit.
TEST_P(QuicSessionTestServer, NewStreamIdAboveLimit) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    // Applicable only to IETF QUIC
    return;
  }

  QuicStreamId bidirectional_stream_id = StreamCountToId(
      QuicSessionPeer::ietf_streamid_manager(&session_)
              ->advertised_max_incoming_bidirectional_streams() +
          1,
      Perspective::IS_CLIENT, /*bidirectional=*/true);
  QuicStreamFrame bidirectional_stream_frame(bidirectional_stream_id, false, 0,
                                             "Random String");
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_STREAM_ID,
                      "Stream id 400 would exceed stream count limit 100", _));
  session_.OnStreamFrame(bidirectional_stream_frame);

  QuicStreamId unidirectional_stream_id = StreamCountToId(
      QuicSessionPeer::ietf_streamid_manager(&session_)
              ->advertised_max_incoming_unidirectional_streams() +
          1,
      Perspective::IS_CLIENT, /*bidirectional=*/false);
  QuicStreamFrame unidirectional_stream_frame(unidirectional_stream_id, false,
                                              0, "Random String");
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_STREAM_ID,
                      "Stream id 402 would exceed stream count limit 100", _));
  session_.OnStreamFrame(unidirectional_stream_frame);
}

// Checks that invalid stream ids are handled.
TEST_P(QuicSessionTestServer, OnStopSendingInvalidStreamId) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  // Check that "invalid" stream ids are rejected.
  QuicStopSendingFrame frame(1, -1, QUIC_STREAM_CANCELLED);
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_STREAM_ID,
                      "Received STOP_SENDING for an invalid stream", _));
  session_.OnStopSendingFrame(frame);
}

TEST_P(QuicSessionTestServer, OnStopSendingReadUnidirectional) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  // It's illegal to send STOP_SENDING with a stream ID that is read-only.
  QuicStopSendingFrame frame(1, GetNthClientInitiatedUnidirectionalId(1),
                             QUIC_STREAM_CANCELLED);
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_STREAM_ID,
                      "Received STOP_SENDING for a read-only stream", _));
  session_.OnStopSendingFrame(frame);
}

// Static streams ignore STOP_SENDING.
TEST_P(QuicSessionTestServer, OnStopSendingStaticStreams) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  QuicStreamId stream_id = 0;
  std::unique_ptr<TestStream> fake_static_stream = std::make_unique<TestStream>(
      stream_id, &session_, /*is_static*/ true, BIDIRECTIONAL);
  QuicSessionPeer::ActivateStream(&session_, std::move(fake_static_stream));
  // Check that a stream id in the static stream map is ignored.
  QuicStopSendingFrame frame(1, stream_id, QUIC_STREAM_CANCELLED);
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_STREAM_ID,
                              "Received STOP_SENDING for a static stream", _));
  session_.OnStopSendingFrame(frame);
}

// If stream is write closed, do not send a RST_STREAM frame.
TEST_P(QuicSessionTestServer, OnStopSendingForWriteClosedStream) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }

  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  QuicStreamId stream_id = stream->id();
  QuicStreamPeer::SetFinSent(stream);
  stream->CloseWriteSide();
  EXPECT_TRUE(stream->write_side_closed());
  QuicStopSendingFrame frame(1, stream_id, QUIC_STREAM_CANCELLED);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_.OnStopSendingFrame(frame);
}

// Regression test for b/368421586.
TEST_P(QuicSessionTestServer, OnStopSendingForZombieStreams) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  CompleteHandshake();
  session_.set_writev_consumes_all_data(true);

  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  std::string body(100, '.');
  QuicStreamPeer::CloseReadSide(stream);
  stream->WriteOrBufferData(body, true, nullptr);
  EXPECT_TRUE(stream->IsWaitingForAcks());
  // Verify that the stream is a zombie.
  EXPECT_TRUE(stream->IsZombie());
  ASSERT_EQ(0u, session_.closed_streams()->size());

  QuicStopSendingFrame frame(1, stream->id(), QUIC_STREAM_CANCELLED);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  if (GetQuicReloadableFlag(quic_deliver_stop_sending_to_zombie_streams)) {
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(1);
    EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(1);
  } else {
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(0);
    EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(0);
  }
  session_.OnStopSendingFrame(frame);
  if (GetQuicReloadableFlag(quic_deliver_stop_sending_to_zombie_streams)) {
    // STOP_SENDING should cause the stream to be closed.
    EXPECT_FALSE(stream->IsZombie());
    EXPECT_EQ(1u, session_.closed_streams()->size());
  } else {
    // STOP_SENDING is not delivered to zombie streams.
    EXPECT_TRUE(stream->IsZombie());
    EXPECT_EQ(0u, session_.closed_streams()->size());
  }
}

// If stream is closed, return true and do not close the connection.
TEST_P(QuicSessionTestServer, OnStopSendingClosedStream) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  CompleteHandshake();
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  QuicStreamId stream_id = stream->id();
  CloseStream(stream_id);
  QuicStopSendingFrame frame(1, stream_id
"""


```