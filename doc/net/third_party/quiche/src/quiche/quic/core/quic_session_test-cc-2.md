Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for the QUIC protocol implementation in Chromium. The request has several sub-constraints: explain functionality, relate to JavaScript (if applicable), provide input/output examples for logic, highlight common user/programming errors, describe user steps to reach this code, and acknowledge it's part 3/5.

My plan is to:
1. **Analyze each test case individually:**  Identify the core functionality being tested in each `TEST_P` block.
2. **Group related tests:** Look for common themes or areas of the QUIC protocol being targeted.
3. **Relate to JavaScript:** Consider if any of the tested scenarios have direct or indirect parallels in web browser JavaScript environments (e.g., handling network errors, flow control concepts, stream management).
4. **Construct input/output examples:**  For tests with clear logical steps, create simplified examples of how data or events might lead to the expected outcomes.
5. **Identify potential errors:** Think about how users or developers might misuse the QUIC API or encounter issues related to the tested functionalities.
6. **Trace user steps:** Imagine the user actions that could trigger the QUIC behavior being tested.
7. **Synthesize a summary:** Combine the insights from the individual tests and groupings into a concise description of the overall functionality covered by this code snippet.
8. **Address the "part 3 of 5" requirement:**  Clearly state that this is a summary of part 3.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc` 文件的一部分，主要关注 QUIC 会话在 **服务器端** 对接收到各种帧的处理和相关的状态管理。

**功能归纳 (针对提供的代码片段):**

这部分代码主要测试了服务器端 QUIC 会话在接收到来自客户端的特定类型的帧时，如何进行错误处理、流量控制管理和流管理。 涵盖了以下几个关键功能点：

1. **无效流 ID 处理:**
   - 测试服务器接收到针对无效流 ID 的 `STREAM` 帧、`RST_STREAM` 帧和 `RESET_STREAM_AT` 帧时的行为。预期行为是关闭连接并给出相应的错误原因。

2. **握手后流量控制解除阻塞:**
   - 测试当一个流因为流量控制而被阻塞时，在完成握手并获得更大的发送窗口后，该流能否被正确地解除阻塞。

3. **连接级流量控制核算:**
   - 测试当服务器接收到乱序的 `RST_STREAM` 帧、在接收到 `FIN` 帧后本地重置流、以及在本地重置流后收到 `FIN` 或 `RST_STREAM` 帧时，连接级的流量控制接收窗口是否能被正确调整。

4. **握手阶段的流量控制窗口验证:**
   - 测试服务器接收到小于默认值的流或会话流量控制窗口时，是否会正确关闭连接。

5. **超过流量控制限制的处理:**
   - 测试当接收到的 `RST_STREAM` 帧带有超过流量控制限制的最终偏移量时，服务器是否会关闭连接。

6. **超过最大未完成流数量的处理:**
   - 测试当客户端创建过多未发送 `FIN` 或 `RST_STREAM` 的流时，服务器如何拒绝新的流请求，在 IETF QUIC 中会关闭连接，而在 Google QUIC 中会发送 `RST_STREAM` 帧。

7. **Drain 状态流的处理:**
   - 测试处于 drain 状态（已收到 FIN 但未消费完所有数据）的流是否会计入最大打开流的限制。

8. **待处理流 (Pending Streams) 的处理 (HTTP/3 特性):**
   - 测试 HTTP/3 中引入的待处理流的特性，包括接收到数据帧、`RST_STREAM` 帧、`FIN` 帧、`WINDOW_UPDATE` 帧和 `STOP_SENDING` 帧时的行为。

**与 JavaScript 的关系:**

这段 C++ 代码主要负责 QUIC 协议的底层实现，与直接的 JavaScript 功能关联较少。然而，它所测试的功能直接影响了基于 QUIC 的网络应用在浏览器中的行为，例如：

* **网络错误处理:** 当服务器因为接收到无效数据而关闭连接时，JavaScript 中的 `fetch` 或 `XMLHttpRequest` API 可能会抛出网络错误，例如 `net::ERR_QUIC_PROTOCOL_ERROR` 或类似的错误码。
* **流量控制和性能:** QUIC 的流量控制机制影响了数据传输的速度和效率。如果服务器端流量控制出现问题，可能会导致 JavaScript 应用的网络请求变慢或卡顿。
* **流管理和多路复用:** QUIC 的流机制允许多个请求在同一个连接上并发传输。服务器端对流的管理直接影响了 JavaScript 应用中并发请求的性能。

**举例说明 (与 JavaScript 的间接关系):**

假设一个 JavaScript 应用使用 `fetch` API 向一个 QUIC 服务器发送多个请求。

* **假设输入:** 服务器接收到针对一个不存在的流 ID 的数据帧。
* **逻辑推理:**  `QuicSessionTestServer::OnStreamFrameInvalidStreamId` 测试了这个场景。服务器会调用 `CloseConnection` 关闭连接。
* **输出:**  JavaScript 端 `fetch` API 的 Promise 会 reject，并且会得到一个网络错误，表明连接已关闭。开发者可以通过 `catch` 语句捕获这个错误并进行处理，例如提示用户刷新页面或重试。

**用户或编程常见的使用错误举例说明:**

* **用户操作:**  用户在网络不稳定的环境下快速重复点击页面上的某个按钮，导致浏览器在短时间内向服务器发送了大量请求。
* **可能触发的 QUIC 行为:** 如果服务器端的最大未完成流数量设置过低，并且客户端创建了过多的新流而没有及时关闭，则可能会触发 `QuicSessionTestServer::TooManyUnfinishedStreamsCauseServerRejectStream` 测试的场景。
* **结果:** 服务器可能会发送 `RST_STREAM` 拒绝新的流请求（Google QUIC）或者直接关闭连接（IETF QUIC）。在 JavaScript 端，新的 `fetch` 请求可能会失败，导致页面功能异常。
* **编程错误:**  后端开发者在配置 QUIC 服务器时，可能错误地设置了过小的初始流或会话流量控制窗口，这会导致客户端连接建立后立即被服务器断开，对应于 `QuicSessionTestServer::InvalidStreamFlowControlWindowInHandshake` 和 `QuicSessionTestServer::InvalidSessionFlowControlWindowInHandshake` 的测试场景。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户发起网络请求:** 用户在浏览器中访问一个使用了 QUIC 协议的网站，或者 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 向 QUIC 服务器发送请求。
2. **QUIC 连接建立:** 浏览器与服务器之间建立 QUIC 连接，包括握手过程。
3. **数据传输:** 浏览器或服务器发送各种 QUIC 帧来传输数据、控制连接状态等。
4. **触发特定事件:**  用户操作或网络环境可能导致特定的 QUIC 帧被发送或接收，例如：
   -  **发送给无效流 ID 的数据:**  客户端代码或网络错误可能导致数据被发送到已关闭或不存在的流 ID。
   -  **流量控制阻塞:**  客户端发送大量数据，超过了服务器的接收窗口。
   -  **乱序的 RST_STREAM:**  网络延迟或重排序可能导致 `RST_STREAM` 帧在其他帧之后到达。
   -  **创建过多流:** 客户端代码逻辑错误或者恶意行为导致创建了超过服务器允许的最大流数量。
5. **服务器端处理:** 服务器端的 QUIC 实现（代码就位于 `net/third_party/quiche/src/quiche/quic/core/` 目录下）接收到这些帧，并按照协议逻辑进行处理。`quic_session_test.cc` 中的测试用例模拟了这些接收和处理过程。
6. **调试:** 当网络行为出现异常时，开发者可能会查看 Chromium 的网络日志，或者使用抓包工具分析 QUIC 数据包，从而定位到可能触发了服务器端特定处理逻辑的帧类型和状态。

**功能归纳 (第 3 部分):**

总而言之，这部分 `quic_session_test.cc` 的代码主要测试了 **服务器端 QUIC 会话在接收到各种异常或特定类型的帧时，其错误处理、流量控制和流管理机制的正确性**。 这些测试确保了服务器能够健壮地处理来自客户端的各种输入，并维护连接的稳定性和安全性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Send two bytes of payload.
  QuicStreamFrame data1(
      QuicUtils::GetInvalidStreamId(connection_->transport_version()), true, 0,
      absl::string_view("HT"));
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_.OnStreamFrame(data1);
}

TEST_P(QuicSessionTestServer, OnRstStreamInvalidStreamId) {
  // Send two bytes of payload.
  QuicRstStreamFrame rst1(
      kInvalidControlFrameId,
      QuicUtils::GetInvalidStreamId(connection_->transport_version()),
      QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_.OnRstStream(rst1);
}

TEST_P(QuicSessionTestServer, OnResetStreamAtInvalidStreamId) {
  if (connection_->version().handshake_protocol != PROTOCOL_TLS1_3) {
    // This test requires IETF QUIC.
    return;
  }
  // Send two bytes of payload.
  QuicResetStreamAtFrame rst1(
      kInvalidControlFrameId,
      QuicUtils::GetInvalidStreamId(connection_->transport_version()),
      QUIC_ERROR_PROCESSING_STREAM, 10, 0);
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_.OnResetStreamAt(rst1);
}

TEST_P(QuicSessionTestServer, HandshakeUnblocksFlowControlBlockedStream) {
  if (connection_->version().handshake_protocol == PROTOCOL_TLS1_3) {
    // This test requires Google QUIC crypto because it assumes streams start
    // off unblocked.
    return;
  }
  // Test that if a stream is flow control blocked, then on receipt of the SHLO
  // containing a suitable send window offset, the stream becomes unblocked.

  // Ensure that Writev consumes all the data it is given (simulate no socket
  // blocking).
  session_.set_writev_consumes_all_data(true);
  session_.GetMutableCryptoStream()->EstablishZeroRttEncryption();

  // Create a stream, and send enough data to make it flow control blocked.
  TestStream* stream2 = session_.CreateOutgoingBidirectionalStream();
  std::string body(kMinimumFlowControlSendWindow, '.');
  EXPECT_FALSE(stream2->IsFlowControlBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
  EXPECT_CALL(*connection_, SendControlFrame(_)).Times(AtLeast(1));
  stream2->WriteOrBufferData(body, false, nullptr);
  EXPECT_TRUE(stream2->IsFlowControlBlocked());
  EXPECT_TRUE(session_.IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_.IsStreamFlowControlBlocked());

  // Now complete the crypto handshake, resulting in an increased flow control
  // send window.
  CompleteHandshake();
  EXPECT_TRUE(QuicSessionPeer::IsStreamWriteBlocked(&session_, stream2->id()));
  // Stream is now unblocked.
  EXPECT_FALSE(stream2->IsFlowControlBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
}

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingRstOutOfOrder) {
  CompleteHandshake();
  // Test that when we receive an out of order stream RST we correctly adjust
  // our connection level flow control receive window.
  // On close, the stream should mark as consumed all bytes between the highest
  // byte consumed so far and the final byte offset from the RST frame.
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();

  const QuicStreamOffset kByteOffset =
      1 + kInitialSessionFlowControlWindowForTest / 2;

  EXPECT_CALL(*connection_, SendControlFrame(_))
      .Times(2)
      .WillRepeatedly(Invoke(&ClearControlFrame));
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));

  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream->id(),
                               QUIC_STREAM_CANCELLED, kByteOffset);
  session_.OnRstStream(rst_frame);
  if (VersionHasIetfQuicFrames(transport_version())) {
    // The test requires the stream to be fully closed in both directions. For
    // IETF QUIC, the RST_STREAM only closes one side.
    QuicStopSendingFrame frame(kInvalidControlFrameId, stream->id(),
                               QUIC_STREAM_CANCELLED);
    EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
    session_.OnStopSendingFrame(frame);
  }
  EXPECT_EQ(kByteOffset, session_.flow_controller()->bytes_consumed());
}

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingFinAndLocalReset) {
  CompleteHandshake();
  // Test the situation where we receive a FIN on a stream, and before we fully
  // consume all the data from the sequencer buffer we locally RST the stream.
  // The bytes between highest consumed byte, and the final byte offset that we
  // determined when the FIN arrived, should be marked as consumed at the
  // connection level flow controller when the stream is reset.
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();

  const QuicStreamOffset kByteOffset =
      kInitialSessionFlowControlWindowForTest / 2 - 1;
  QuicStreamFrame frame(stream->id(), true, kByteOffset, ".");
  session_.OnStreamFrame(frame);
  EXPECT_TRUE(connection_->connected());

  EXPECT_EQ(0u, session_.flow_controller()->bytes_consumed());
  EXPECT_EQ(kByteOffset + frame.data_length,
            stream->highest_received_byte_offset());

  // Reset stream locally.
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_EQ(kByteOffset + frame.data_length,
            session_.flow_controller()->bytes_consumed());
}

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingFinAfterRst) {
  CompleteHandshake();
  // Test that when we RST the stream (and tear down stream state), and then
  // receive a FIN from the peer, we correctly adjust our connection level flow
  // control receive window.

  // Connection starts with some non-zero highest received byte offset,
  // due to other active streams.
  const uint64_t kInitialConnectionBytesConsumed = 567;
  const uint64_t kInitialConnectionHighestReceivedOffset = 1234;
  EXPECT_LT(kInitialConnectionBytesConsumed,
            kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->UpdateHighestReceivedOffset(
      kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->AddBytesConsumed(kInitialConnectionBytesConsumed);

  // Reset our stream: this results in the stream being closed locally.
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
  stream->Reset(QUIC_STREAM_CANCELLED);

  // Now receive a response from the peer with a FIN. We should handle this by
  // adjusting the connection level flow control receive window to take into
  // account the total number of bytes sent by the peer.
  const QuicStreamOffset kByteOffset = 5678;
  std::string body = "hello";
  QuicStreamFrame frame(stream->id(), true, kByteOffset,
                        absl::string_view(body));
  session_.OnStreamFrame(frame);

  QuicStreamOffset total_stream_bytes_sent_by_peer =
      kByteOffset + body.length();
  EXPECT_EQ(kInitialConnectionBytesConsumed + total_stream_bytes_sent_by_peer,
            session_.flow_controller()->bytes_consumed());
  EXPECT_EQ(
      kInitialConnectionHighestReceivedOffset + total_stream_bytes_sent_by_peer,
      session_.flow_controller()->highest_received_byte_offset());
}

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingRstAfterRst) {
  CompleteHandshake();
  // Test that when we RST the stream (and tear down stream state), and then
  // receive a RST from the peer, we correctly adjust our connection level flow
  // control receive window.

  // Connection starts with some non-zero highest received byte offset,
  // due to other active streams.
  const uint64_t kInitialConnectionBytesConsumed = 567;
  const uint64_t kInitialConnectionHighestReceivedOffset = 1234;
  EXPECT_LT(kInitialConnectionBytesConsumed,
            kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->UpdateHighestReceivedOffset(
      kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->AddBytesConsumed(kInitialConnectionBytesConsumed);

  // Reset our stream: this results in the stream being closed locally.
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream));

  // Now receive a RST from the peer. We should handle this by adjusting the
  // connection level flow control receive window to take into account the total
  // number of bytes sent by the peer.
  const QuicStreamOffset kByteOffset = 5678;
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream->id(),
                               QUIC_STREAM_CANCELLED, kByteOffset);
  session_.OnRstStream(rst_frame);

  EXPECT_EQ(kInitialConnectionBytesConsumed + kByteOffset,
            session_.flow_controller()->bytes_consumed());
  EXPECT_EQ(kInitialConnectionHighestReceivedOffset + kByteOffset,
            session_.flow_controller()->highest_received_byte_offset());
}

TEST_P(QuicSessionTestServer, InvalidStreamFlowControlWindowInHandshake) {
  // Test that receipt of an invalid (< default) stream flow control window from
  // the peer results in the connection being torn down.
  const uint32_t kInvalidWindow = kMinimumFlowControlSendWindow - 1;
  QuicConfigPeer::SetReceivedInitialStreamFlowControlWindow(session_.config(),
                                                            kInvalidWindow);

  if (connection_->version().handshake_protocol != PROTOCOL_TLS1_3) {
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_FLOW_CONTROL_INVALID_WINDOW, _, _));
  } else {
    EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  }
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
}

// Test negotiation of custom server initial flow control window.
TEST_P(QuicSessionTestServer, CustomFlowControlWindow) {
  QuicTagVector copt;
  copt.push_back(kIFW7);
  QuicConfigPeer::SetReceivedConnectionOptions(session_.config(), copt);

  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
  EXPECT_EQ(192 * 1024u, QuicFlowControllerPeer::ReceiveWindowSize(
                             session_.flow_controller()));
}

TEST_P(QuicSessionTestServer, FlowControlWithInvalidFinalOffset) {
  CompleteHandshake();
  // Test that if we receive a stream RST with a highest byte offset that
  // violates flow control, that we close the connection.
  const uint64_t kLargeOffset = kInitialSessionFlowControlWindowForTest + 1;
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _))
      .Times(2);

  // Check that stream frame + FIN results in connection close.
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  EXPECT_CALL(*connection_, SendControlFrame(_));
  EXPECT_CALL(*connection_, OnStreamReset(stream->id(), _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  QuicStreamFrame frame(stream->id(), true, kLargeOffset, absl::string_view());
  session_.OnStreamFrame(frame);

  // Check that RST results in connection close.
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream->id(),
                               QUIC_STREAM_CANCELLED, kLargeOffset);
  session_.OnRstStream(rst_frame);
}

TEST_P(QuicSessionTestServer, TooManyUnfinishedStreamsCauseServerRejectStream) {
  CompleteHandshake();
  // If a buggy/malicious peer creates too many streams that are not ended
  // with a FIN or RST then we send an RST to refuse streams. For IETF QUIC the
  // connection is closed.
  const QuicStreamId kMaxStreams = 5;
  if (VersionHasIetfQuicFrames(transport_version())) {
    QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&session_,
                                                            kMaxStreams);
  } else {
    QuicSessionPeer::SetMaxOpenIncomingStreams(&session_, kMaxStreams);
  }
  const QuicStreamId kFirstStreamId = GetNthClientInitiatedBidirectionalId(0);
  const QuicStreamId kFinalStreamId =
      GetNthClientInitiatedBidirectionalId(kMaxStreams);
  // Create kMaxStreams data streams, and close them all without receiving a
  // FIN or a RST_STREAM from the client.
  for (QuicStreamId i = kFirstStreamId; i < kFinalStreamId;
       i += QuicUtils::StreamIdDelta(connection_->transport_version())) {
    QuicStreamFrame data1(i, false, 0, absl::string_view("HT"));
    session_.OnStreamFrame(data1);
    CloseStream(i);
  }

  if (VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_CALL(
        *connection_,
        CloseConnection(QUIC_INVALID_STREAM_ID,
                        "Stream id 20 would exceed stream count limit 5", _));
  } else {
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(1);
    EXPECT_CALL(*connection_,
                OnStreamReset(kFinalStreamId, QUIC_REFUSED_STREAM))
        .Times(1);
  }
  // Create one more data streams to exceed limit of open stream.
  QuicStreamFrame data1(kFinalStreamId, false, 0, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
}

TEST_P(QuicSessionTestServer, DrainingStreamsDoNotCountAsOpenedOutgoing) {
  // Verify that a draining stream (which has received a FIN but not consumed
  // it) does not count against the open quota (because it is closed from the
  // protocol point of view).
  CompleteHandshake();
  TestStream* stream = session_.CreateOutgoingBidirectionalStream();
  QuicStreamId stream_id = stream->id();
  QuicStreamFrame data1(stream_id, true, 0, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  if (!VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_CALL(session_, OnCanCreateNewOutgoingStream(false)).Times(1);
  }
  session_.StreamDraining(stream_id, /*unidirectional=*/false);
}

TEST_P(QuicSessionTestServer, NoPendingStreams) {
  session_.set_uses_pending_streams(false);

  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data1(stream_id, true, 10, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_EQ(1, session_.num_incoming_streams_created());

  QuicStreamFrame data2(stream_id, false, 0, absl::string_view("HT"));
  session_.OnStreamFrame(data2);
  EXPECT_EQ(1, session_.num_incoming_streams_created());
}

TEST_P(QuicSessionTestServer, PendingStreams) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  session_.set_uses_pending_streams(true);

  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data1(stream_id, true, 10, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());

  QuicStreamFrame data2(stream_id, false, 0, absl::string_view("HT"));
  session_.OnStreamFrame(data2);
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(1, session_.num_incoming_streams_created());
}

TEST_P(QuicSessionTestServer, BufferAllIncomingStreams) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  session_.set_uses_pending_streams(true);

  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data1(stream_id, true, 10, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  // Read unidirectional stream is still buffered when the first byte arrives.
  QuicStreamFrame data2(stream_id, false, 0, absl::string_view("HT"));
  session_.OnStreamFrame(data2);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());

  // Bidirectional stream is buffered.
  QuicStreamId bidirectional_stream_id =
      QuicUtils::GetFirstBidirectionalStreamId(transport_version(),
                                               Perspective::IS_CLIENT);
  QuicStreamFrame data3(bidirectional_stream_id, false, 0,
                        absl::string_view("HT"));
  session_.OnStreamFrame(data3);
  EXPECT_TRUE(
      QuicSessionPeer::GetPendingStream(&session_, bidirectional_stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());

  connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  session_.ProcessAllPendingStreams();
  // Both bidirectional and read-unidirectional streams are unbuffered.
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_FALSE(
      QuicSessionPeer::GetPendingStream(&session_, bidirectional_stream_id));
  EXPECT_EQ(2, session_.num_incoming_streams_created());
  EXPECT_EQ(1, QuicSessionPeer::GetStream(&session_, stream_id)
                   ->pending_duration()
                   .ToMilliseconds());
  EXPECT_EQ(1, QuicSessionPeer::GetStream(&session_, bidirectional_stream_id)
                   ->pending_duration()
                   .ToMilliseconds());
  EXPECT_EQ(2, session_.connection()->GetStats().num_total_pending_streams);
}

TEST_P(QuicSessionTestServer, RstPendingStreams) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  session_.set_uses_pending_streams(true);

  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data1(stream_id, true, 10, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&session_));

  QuicRstStreamFrame rst1(kInvalidControlFrameId, stream_id,
                          QUIC_ERROR_PROCESSING_STREAM, 12);
  session_.OnRstStream(rst1);
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&session_));

  QuicStreamFrame data2(stream_id, false, 0, absl::string_view("HT"));
  session_.OnStreamFrame(data2);
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&session_));

  session_.ProcessAllPendingStreams();
  // Bidirectional stream is buffered.
  QuicStreamId bidirectional_stream_id =
      QuicUtils::GetFirstBidirectionalStreamId(transport_version(),
                                               Perspective::IS_CLIENT);
  QuicStreamFrame data3(bidirectional_stream_id, false, 0,
                        absl::string_view("HT"));
  session_.OnStreamFrame(data3);
  EXPECT_TRUE(
      QuicSessionPeer::GetPendingStream(&session_, bidirectional_stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());

  // Bidirectional pending stream is removed after RST_STREAM is received.
  QuicRstStreamFrame rst2(kInvalidControlFrameId, bidirectional_stream_id,
                          QUIC_ERROR_PROCESSING_STREAM, 12);
  session_.OnRstStream(rst2);
  EXPECT_FALSE(
      QuicSessionPeer::GetPendingStream(&session_, bidirectional_stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&session_));
}

TEST_P(QuicSessionTestServer, OnFinPendingStreamsReadUnidirectional) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  session_.set_uses_pending_streams(true);

  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data(stream_id, true, 0, "");
  session_.OnStreamFrame(data);

  // The pending stream will be immediately converted to a normal unidirectional
  // stream, but because its FIN has been received, it should be closed
  // immediately.
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&session_));
  EXPECT_EQ(nullptr, QuicSessionPeer::GetStream(&session_, stream_id));
}

TEST_P(QuicSessionTestServer, OnFinPendingStreamsBidirectional) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  session_.set_uses_pending_streams(true);
  // Bidirectional pending stream remains after Fin is received.
  // Bidirectional stream is buffered.
  QuicStreamId bidirectional_stream_id =
      QuicUtils::GetFirstBidirectionalStreamId(transport_version(),
                                               Perspective::IS_CLIENT);
  QuicStreamFrame data2(bidirectional_stream_id, true, 0,
                        absl::string_view("HT"));
  session_.OnStreamFrame(data2);
  EXPECT_TRUE(
      QuicSessionPeer::GetPendingStream(&session_, bidirectional_stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());

  session_.ProcessAllPendingStreams();
  EXPECT_FALSE(
      QuicSessionPeer::GetPendingStream(&session_, bidirectional_stream_id));
  EXPECT_EQ(1, session_.num_incoming_streams_created());
  QuicStream* bidirectional_stream =
      QuicSessionPeer::GetStream(&session_, bidirectional_stream_id);
  EXPECT_TRUE(bidirectional_stream->fin_received());
}

TEST_P(QuicSessionTestServer, UnidirectionalPendingStreamOnWindowUpdate) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  session_.set_uses_pending_streams(true);
  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data1(stream_id, true, 10, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  QuicWindowUpdateFrame window_update_frame(kInvalidControlFrameId, stream_id,
                                            0);
  EXPECT_CALL(
      *connection_,
      CloseConnection(
          QUIC_WINDOW_UPDATE_RECEIVED_ON_READ_UNIDIRECTIONAL_STREAM,
          "WindowUpdateFrame received on READ_UNIDIRECTIONAL stream.", _));
  session_.OnWindowUpdateFrame(window_update_frame);
}

TEST_P(QuicSessionTestServer, BidirectionalPendingStreamOnWindowUpdate) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  session_.set_uses_pending_streams(true);
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data(stream_id, true, 10, absl::string_view("HT"));
  session_.OnStreamFrame(data);
  QuicWindowUpdateFrame window_update_frame(kInvalidControlFrameId, stream_id,
                                            kDefaultFlowControlSendWindow * 2);
  session_.OnWindowUpdateFrame(window_update_frame);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());

  session_.ProcessAllPendingStreams();
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(1, session_.num_incoming_streams_created());
  QuicStream* bidirectional_stream =
      QuicSessionPeer::GetStream(&session_, stream_id);
  QuicByteCount send_window =
      QuicStreamPeer::SendWindowSize(bidirectional_stream);
  EXPECT_EQ(send_window, kDefaultFlowControlSendWindow * 2);
}

TEST_P(QuicSessionTestServer, UnidirectionalPendingStreamOnStopSending) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  session_.set_uses_pending_streams(true);
  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data1(stream_id, true, 10, absl::string_view("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());
  QuicStopSendingFrame stop_sending_frame(kInvalidControlFrameId, stream_id,
                                          QUIC_STREAM_CANCELLED);
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_STREAM_ID,
                      "Received STOP_SENDING for a read-only stream", _));
  session_.OnStopSendingFrame(stop_sending_frame);
}

TEST_P(QuicSessionTestServer, BidirectionalPendingStreamOnStopSending) {
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  session_.set_uses_pending_streams(true);
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  QuicStreamFrame data(stream_id, true, 0, absl::string_view("HT"));
  session_.OnStreamFrame(data);
  QuicStopSendingFrame stop_sending_frame(kInvalidControlFrameId, stream_id,
                                          QUIC_STREAM_CANCELLED);
  session_.OnStopSendingFrame(stop_sending_frame);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(0, session_.num_incoming_streams_created());

  EXPECT_CALL(*connection_, OnStreamReset(stream_id, _));
  session_.ProcessAllPendingStreams();
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&session_, stream_id));
  EXPECT_EQ(1, session_.num_incoming_streams_created());
  QuicStream* bidirectional_stream =
      QuicSessionPeer::GetStream(&session_, stream_id);
  EXPECT_TRUE(bidirectional_stream->write_side_closed());
}

TEST_P(QuicSessionTestServer, DrainingStreamsDoNotCountAsOpened) {
  // Verify that a draining stream (which has received a FIN but not consumed
  // it) does not count against the open quota (because it is closed from the
  // protocol point of view).
  CompleteHandshake();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // On IETF QUIC, we will expect to see a MAX_STREAMS go out when there are
    // not enough streams to create the next one.
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(1);
  } else {
    EXPECT_CALL(*connection_, SendControlFrame(_)).Times(0);
  }
  EXPECT_CALL(*connection_, OnStreamReset(_, QUIC_REFUSED_STREAM)).Times(0);
  const QuicStreamId kMaxStreams = 5;
  if (VersionHasIetfQuicFrames(transport_version())) {
    QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&session_,
                                                            kMaxStreams);
  } else {
    QuicSessionPeer::SetMaxOpenIncomingStreams(&session_, kMaxStreams);
  }

  // Create kMaxStreams + 1 data streams, and mark them draining.
  const QuicStreamId kFirstStreamId = GetNthClientInitiatedBidirectionalId(0);
  const QuicStreamId kFinalStreamId =
      GetNthClientInitiatedBidirectionalId(2 * kMaxStreams + 1);
  for (QuicStreamId i = kFirstStreamId; i < kFinalStreamId;
       i += QuicUtils::StreamIdDelta(connection_->transport_version())) {
    QuicStreamFrame data1(i, true, 0, absl::string_view("HT"));
    session_.OnStreamFrame(data1);
    EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(&session_));
    session_.StreamDraining(i, /*unidirectional=*/false);
    EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&session_));
    QuicAlarm* alarm = QuicSessionPeer::GetStreamCountResetAlarm(&session_);
    if (alarm->IsSet()) {
      alarm_factory_.FireAlarm(alarm);
    }
  }
}

class QuicSessionTestClient : public QuicSessionTestBase {
 protected:
  QuicSessionTestClient()
      : QuicSessionTestBase(Perspective::IS_CLIENT,
                            /*configure_session=*/true) {}
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSessionTestClient,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSessionTestClient, AvailableBidirectionalStreamsClient) {
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthServerInitiatedBidirectionalId(2)) != nullptr);
  // Smaller bidirectional streams should be available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthServerInitiatedBidirectionalId(0)));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthServerInitiatedBidirectionalId(1)));
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthServerInitiatedBidirectionalId(0)) != nullptr);
  ASSERT_TRUE(session_.GetOrCreateStream(
                  GetNthServerInitiatedBidirectionalId(1)) != nullptr);
  // And 5 should be not available.
  EXPECT_FALSE(QuicSessionPeer::IsStreamAvailable(
      &session_, GetNthClientInitiatedBidirectionalId(1)));
}

// Regression test for
// https://bugs.chromium.org/p/chromium/issues/detail?id=1514016
TEST_P(QuicSessionTestClient, DonotSendRetireCIDFrameWhenConnectionClosed) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  connection_->ReallyCloseConnection(QUIC_NO_ERROR, "closing",
                                     ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_FALSE(connection_->connected());
  if (!GetQuicReloadableFlag(
          quic_no_write_control_frame_upon_connection_close2)) {
    EXPECT_QUIC_BUG(session_.SendRetireConnectionId(20),
                    "Try to write control frame");
  } else {
    session_.SendRetireConnectionId(20);
  }
}

TEST_P(QuicSessionTestClient, NewStreamCreationResumesMultiPortProbing) {
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  session_.config()->SetClientConnectionOptions({kMPQC});
  session_.Initialize();
  connection_->CreateConnectionIdManager();
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_->OnHandshakeComplete();
  session_.OnConfigNegotiated();

  EXPECT_CALL(*connection_, MaybeProbeMultiPortPath());
  session_.CreateOutgoingBidirectionalStream();
}

TEST_P(QuicSessionTestClient, InvalidSessionFlowControlWindowInHandshake) {
  // Test that receipt of an invalid (< default for gQUIC, < current for TLS)
  // session flow control window from the peer results in the connection being
  // torn down.
  const uint32_t kInvalidWindow = kMinimumFlowControlSendWindow - 1;
  QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(session_.config(),
                                                             kInvalidWindow);
  EXPECT_CALL(
      *connection_,
      CloseConnection(connection_->version().AllowsLowFlowControlLimits()
                          ? QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED
                          : QUIC_FLOW_CONTROL_INVALID_WINDOW,
                      _, _));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
}

TEST_P(QuicSessionTestClient, InvalidBidiStreamLimitInHandshake) {
  // IETF QUIC only feature.
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  QuicConfigPeer::SetReceivedMaxBidirectionalStreams(
      session_.config(), kDefaultMaxStreamsPerConnection - 1);
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED, _, _));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
}

TEST_P(QuicSessionTestClient, InvalidUniStreamLimitInHandshake) {
  // IETF QUIC only feature.
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
      session_.config(), kDefaultMaxStreamsPerConnection - 1);
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED, _, _));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  session_.OnConfigNegotiated();
}

TEST_P(QuicSessionTestClient, InvalidStreamFlowControlWindowInHandshake) {
  // IETF QUIC only feature.
  if (!VersionHasIetfQuicFrames(transport_version())) {
    return;
  }
  session_.CreateOutgoingBidirectionalStream();
  session_.CreateOutgoingBidirectionalStream();
  QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
      session_.config(), kMinimumFlowControlSendWindow - 1);

  EXPECT_CALL(*connection_, CloseConnection(_, _, _))
      .WillOnce(
          Invoke(connection_,
```