Response:
The user wants to understand the functionality of the provided C++ code snippet from `quic_connection_test.cc`. The code is part of a series of tests for the QUIC connection implementation in Chromium.

Here's a breakdown of the thought process to analyze the code and generate the response:

1. **Identify the Core Functionality:** The code snippet focuses on testing the path degrading detection and the pinging mechanisms within a QUIC connection. Keywords like `PathDegrading`, `UnmarkPathDegrading`, `NoPathDegrading`, `Ping`, `RetransmittableOnWireTimeout` are strong indicators.

2. **Analyze Individual Test Cases:**  Go through each `TEST_P` block and understand what it's trying to verify:
    * `UnmarkPathDegradingOnTimeout`: Checks that the connection identifies path degradation if no ACK is received within the timeout period.
    * `NoPathDegradingDetectionBeforeHandshakeConfirmed`: Verifies that path degrading detection doesn't start before the handshake is confirmed. There's a flag dependency here that needs to be noted.
    * `UnmarkPathDegradingOnForwardProgress`: Confirms that path degradation is cleared if forward progress (receiving an ACK) is made.
    * `NoPathDegradingOnServer`:  Checks that the server side doesn't initiate path degrading detection.
    * `NoPathDegradingAfterSendingAck`:  Verifies path degrading isn't triggered just because an ACK was sent.
    * `MultipleCallsToCloseConnection`: Ensures that closing the connection multiple times doesn't cause issues.
    * `ServerReceivesChloOnNonCryptoStream`/`ClientReceivesRejOnNonCryptoStream`: Tests how the connection handles handshake messages on non-crypto streams, which should lead to connection closure.
    * `CloseConnectionOnPacketTooLarge`/`AlwaysGetPacketTooLarge`/`CloseConnectionOnQueuedWriteError`:  These tests cover scenarios where sending fails due to packet size limits or write errors and verify the connection closes gracefully.
    * `SendDataAndBecomeApplicationLimited`/`NotBecomeApplicationLimitedIfMoreDataAvailable`/`NotBecomeApplicationLimitedDueToWriteBlock`: These test cases relate to the congestion control mechanism and how the connection determines if it's application-limited (no more data to send).
    * `DoNotForceSendingAckOnPacketTooLarge`: Checks that when a packet is too large, the connection doesn't try to force sending an ACK along with the closure.
    * `CloseConnectionAllLevels`/`CloseConnectionOneLevel`: Tests the connection closure process for different scenarios, especially regarding multiple encryption levels.
    * `DoNotPadServerInitialConnectionClose`: Verifies that initial connection close packets from the server aren't padded.
    * `FailedToWriteHandshakePacket`: Tests error handling when writing handshake packets fails.
    * `MaxPacingRate`: Checks the setting and getting of the maximum pacing rate.
    * `ClientAlwaysSendConnectionId`: Verifies that the client always includes the connection ID in packets.
    * Tests related to `PingAfterLastRetransmittablePacketAcked`, `NoPingIfRetransmittablePacketSent`, `BackOffRetransmittableOnWireTimeout`, `ResetBackOffRetransmitableOnWireTimeout`: These test the pinging mechanism, particularly how it behaves when the last retransmittable packet is acknowledged and the backoff strategy for the retransmittable-on-wire timeout.

3. **Relate to JavaScript (If Applicable):** Since this is low-level networking code, the direct relation to JavaScript is limited. However, the *effects* of these mechanisms can be observed in JavaScript through network performance. Mentioning APIs like `fetch` or WebSockets and how underlying QUIC behavior might influence their performance is relevant.

4. **Provide Hypothetical Inputs and Outputs:** For each test case, consider a simple scenario and predict the expected outcome based on the test's purpose. Focus on the key actions and assertions.

5. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when working with network connections or the QUIC protocol itself. Examples include not handling connection closure properly or misunderstanding the timing of handshake completion.

6. **Explain Debugging Steps:** Outline how a developer might reach this specific part of the codebase during debugging. This typically involves tracing network events, looking at connection state, and examining packet flows.

7. **Summarize Functionality (Part 11 of 24):**  Synthesize the main themes covered in this particular code snippet, considering its position within the broader set of tests. Highlight the path degrading detection and pinging mechanisms as the core functionalities being tested.

8. **Review and Refine:**  Read through the generated response to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation and ensure the examples are easy to understand. Make sure the connection to JavaScript, while indirect, is clearly explained.
这个C++源代码文件 `quic_connection_test.cc` 是 Chromium 网络栈中 QUIC 协议连接的核心测试文件。作为第 11 部分（共 24 部分），它主要负责测试 `QuicConnection` 类的特定功能，特别是关于**路径劣化检测 (Path Degrading Detection)** 和 **Keep-Alive 机制 (Pinging)** 的相关逻辑。

以下是这个代码片段涵盖的主要功能归纳：

**主要功能:**

* **路径劣化检测:** 测试连接是否能在没有数据包确认的情况下，检测到网络路径可能正在劣化，并触发相应的处理逻辑 (例如 `OnPathDegrading` 回调)。
    * 测试在握手完成前不应启动路径劣化检测。
    * 测试在路径被标记为劣化后，如果收到确认包，则应取消劣化标记并重新开始检测。
    * 测试服务器端不应进行路径劣化检测。
    * 测试发送 ACK 包后不应触发路径劣化检测。
* **连接关闭:** 测试多种场景下连接关闭的行为，包括：
    * 多次调用 `CloseConnection` 是否会产生预期效果。
    * 接收到非加密流上的握手消息 (CHLO/REJ) 时，连接应正确关闭。
    * 当尝试发送数据包但超过最大大小时，连接应关闭。
    * 当写入队列发生错误时，连接应关闭。
    * 测试在不同加密级别下连接关闭的处理。
    * 测试在尝试写入握手包失败时连接应关闭。
* **拥塞控制交互:** 测试连接与拥塞控制算法的交互，例如：
    * 当连接没有更多数据要发送时，是否会通知拥塞控制算法 (`OnApplicationLimited`)。
    * 当连接仍有数据待发送时，是否不会通知拥塞控制算法。
* **数据包发送:** 测试数据包发送的相关逻辑：
    * 测试当数据包过大时，是否会关闭连接，并且不会强制发送 ACK 包。
    * 测试客户端是否总是发送连接 ID。
* **Keep-Alive 机制 (Pinging):** 测试连接的 Ping 机制，确保连接在空闲时发送 PING 包以保持连接活跃。
    * 测试在最后一个可重传包被确认后，Ping 告警是否会被设置。
    * 测试如果发送了新的可重传包，是否会取消 Ping 告警。
    * 测试在没有接收到新数据的情况下，是否会进行退避的 Ping 超时策略 (先使用较短的超时，然后指数退避)。
    * 测试当接收到新数据时，是否会重置退避的 Ping 超时策略。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不直接涉及 JavaScript，但它测试的网络连接的核心功能会直接影响基于 JavaScript 的网络应用，例如：

* **`fetch` API 和 WebSocket API:**  当 JavaScript 使用 `fetch` 或 WebSocket 与服务器通信时，底层可能使用 QUIC 协议。 此文件中测试的路径劣化检测和 Keep-Alive 机制直接影响这些 API 的性能和连接稳定性。
    * **路径劣化检测:** 如果网络路径出现问题，QUIC 连接能及时检测到并可能触发重传或其他优化策略，从而避免 JavaScript 应用出现长时间卡顿或连接中断。
    * **Keep-Alive 机制:**  确保即使在没有数据传输时，连接也能保持活跃，避免 JavaScript 应用因为连接超时而需要重新建立连接。

**逻辑推理、假设输入与输出:**

以 `TEST_P(QuicConnectionTest, UnmarkPathDegradingOnTimeout)` 为例：

* **假设输入:**
    1. 连接已建立，握手已确认。
    2. 发送一个数据包到对端。
    3. 在路径劣化检测超时时间内，没有收到该数据包的 ACK。
* **预期输出:**
    1. `PathDegradingDetectionInProgress()` 返回 `false` (超时后检测过程结束)。
    2. `IsPathDegrading()` 返回 `true` (连接被标记为正在劣化)。
    3. `visitor_.OnPathDegrading()` 被调用 (通知上层路径正在劣化)。

**用户或编程常见的使用错误:**

* **用户操作:**
    * 用户在网络不稳定的环境下使用应用程序，可能导致数据包丢失或延迟，从而触发路径劣化检测。
    * 用户长时间不操作应用程序，可能导致连接空闲，依赖 Keep-Alive 机制来维持连接。
* **编程错误:**
    * **未正确处理连接关闭事件:** 开发者可能没有监听或正确处理连接关闭事件，导致应用程序在连接意外关闭时无法做出合适的响应。
    * **不合理的超时设置:**  如果开发者自定义了连接超时参数，设置不当可能导致连接过早或过晚地关闭。
    * **对 QUIC 内部机制的误解:**  不理解 QUIC 的路径劣化检测和 Keep-Alive 机制，可能导致在排查网络问题时产生错误的判断。

**用户操作如何一步步到达这里 (调试线索):**

当开发者遇到与 QUIC 连接稳定性或性能相关的问题时，可能会进行以下调试步骤，最终可能需要查看 `quic_connection_test.cc` 这样的测试文件来理解 QUIC 的行为：

1. **应用程序出现网络问题:** 用户反馈应用程序在特定网络环境下连接不稳定、速度慢或容易断开。
2. **抓包分析:** 开发者使用 Wireshark 等工具抓取网络包，观察 QUIC 连接的握手、数据传输和可能的错误信息。
3. **查看 Chromium 网络日志:** Chromium 提供了详细的网络日志，开发者可以查看这些日志来分析 QUIC 连接的状态变化、错误代码和告警信息。
4. **阅读 QUIC 规范和 Chromium QUIC 源码:** 为了深入理解问题的根源，开发者会查阅 QUIC 的 RFC 文档以及 Chromium 中 QUIC 的源代码实现。
5. **查看单元测试:**  为了验证自己对 QUIC 某些行为的理解，或者查找相关的测试用例，开发者可能会查看 `quic_connection_test.cc` 这样的测试文件，看看是否有类似的场景被测试到。例如，如果怀疑是路径劣化检测导致了问题，就会查找包含 "PathDegrading" 关键字的测试用例。

**作为第 11 部分，共 24 部分，它的功能归纳:**

作为整个 `quic_connection_test.cc` 文件的一部分，第 11 部分主要聚焦于测试 `QuicConnection` 类的以下两个关键方面：

1. **路径劣化检测的正确性和健壮性:** 确保连接能够准确地检测到路径劣化的情况，并在不同场景下做出正确的反应，避免误判或漏判。
2. **连接保活机制的有效性:**  验证 PING 机制能否有效地维持连接活跃，并测试其在各种情况下的行为，例如在发送和接收数据包时的交互，以及超时策略的调整。

总而言之，这个代码片段是 QUIC 连接功能测试的重要组成部分，它确保了 QUIC 连接在面对网络问题时能够做出合理的应对，并保持连接的活跃性。这对于保证基于 QUIC 的网络应用的稳定性和性能至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
ds(5));
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  // Send a third packet. The path degrading detection is no longer set but path
  // should still be marked as degrading.
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_TRUE(connection_.IsPathDegrading());
}

TEST_P(QuicConnectionTest, NoPathDegradingDetectionBeforeHandshakeConfirmed) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_COMPLETE));

  connection_.SendStreamDataWithString(1, "data", 0, NO_FIN);
  if (GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed) &&
      connection_.SupportsMultiplePacketNumberSpaces()) {
    EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  } else {
    EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
  }
}

// This test verifies that the connection unmarks path as degrarding and spins
// the timer to detect future path degrading when forward progress is made
// after path has been marked degrading.
TEST_P(QuicConnectionTest, UnmarkPathDegradingOnForwardProgress) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  const char data[] = "data";
  size_t data_size = strlen(data);
  QuicStreamOffset offset = 0;

  // Send the first packet. Now there's a retransmittable packet on the wire, so
  // the path degrading alarm should be set.
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
  // Check the deadline of the path degrading alarm.
  QuicTime::Delta delay = QuicConnectionPeer::GetSentPacketManager(&connection_)
                              ->GetPathDegradingDelay();
  EXPECT_EQ(delay, connection_.GetBlackholeDetectorAlarm()->deadline() -
                       clock_.ApproximateNow());

  // Send a second packet. The path degrading alarm's deadline should remain
  // the same.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  QuicTime prev_deadline = connection_.GetBlackholeDetectorAlarm()->deadline();
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
  EXPECT_EQ(prev_deadline, connection_.GetBlackholeDetectorAlarm()->deadline());

  // Now receive an ACK of the first packet. This should advance the path
  // degrading alarm's deadline since forward progress has been made.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1u), QuicPacketNumber(2u)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
  // Check the deadline of the path degrading alarm.
  delay = QuicConnectionPeer::GetSentPacketManager(&connection_)
              ->GetPathDegradingDelay();
  EXPECT_EQ(delay, connection_.GetBlackholeDetectorAlarm()->deadline() -
                       clock_.ApproximateNow());

  // Advance time to the path degrading alarm's deadline and simulate
  // firing the alarm.
  clock_.AdvanceTime(delay);
  EXPECT_CALL(visitor_, OnPathDegrading()).Times(1);
  connection_.PathDegradingTimeout();
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_TRUE(connection_.IsPathDegrading());

  // Send a third packet. The path degrading alarm is no longer set but path
  // should still be marked as degrading.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_TRUE(connection_.IsPathDegrading());

  // Now receive an ACK of the second packet. This should unmark the path as
  // degrading. And will set a timer to detect new path degrading.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(visitor_, OnForwardProgressMadeAfterPathDegrading()).Times(1);
  frame = InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
  ProcessAckPacket(&frame);
  EXPECT_EQ(1,
            connection_.GetStats().num_forward_progress_after_path_degrading);
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
}

TEST_P(QuicConnectionTest, NoPathDegradingOnServer) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());

  // Send data.
  const char data[] = "data";
  connection_.SendStreamDataWithString(1, data, 0, NO_FIN);
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());

  // Ack data.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1u), QuicPacketNumber(2u)}});
  ProcessAckPacket(&frame);
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
}

TEST_P(QuicConnectionTest, NoPathDegradingAfterSendingAck) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacket(1);
  SendAckPacketToPeer();
  EXPECT_FALSE(connection_.sent_packet_manager().unacked_packets().empty());
  EXPECT_FALSE(connection_.sent_packet_manager().HasInFlightPackets());
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
}

TEST_P(QuicConnectionTest, MultipleCallsToCloseConnection) {
  // Verifies that multiple calls to CloseConnection do not
  // result in multiple attempts to close the connection - it will be marked as
  // disconnected after the first call.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(1);
  connection_.CloseConnection(QUIC_NO_ERROR, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
  connection_.CloseConnection(QUIC_NO_ERROR, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
}

TEST_P(QuicConnectionTest, ServerReceivesChloOnNonCryptoStream) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  QuicConnectionPeer::SetAddressValidated(&connection_);

  CryptoHandshakeMessage message;
  CryptoFramer framer;
  message.set_tag(kCHLO);
  std::unique_ptr<QuicData> data = framer.ConstructHandshakeMessage(message);
  frame1_.stream_id = 10;
  frame1_.data_buffer = data->data();
  frame1_.data_length = data->length();

  if (version().handshake_protocol == PROTOCOL_TLS1_3) {
    EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  }
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  ForceProcessFramePacket(QuicFrame(frame1_));
  if (VersionHasIetfQuicFrames(version().transport_version)) {
    // INITIAL packet should not contain STREAM frame.
    TestConnectionCloseQuicErrorCode(IETF_QUIC_PROTOCOL_VIOLATION);
  } else {
    TestConnectionCloseQuicErrorCode(QUIC_MAYBE_CORRUPTED_MEMORY);
  }
}

TEST_P(QuicConnectionTest, ClientReceivesRejOnNonCryptoStream) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  CryptoHandshakeMessage message;
  CryptoFramer framer;
  message.set_tag(kREJ);
  std::unique_ptr<QuicData> data = framer.ConstructHandshakeMessage(message);
  frame1_.stream_id = 10;
  frame1_.data_buffer = data->data();
  frame1_.data_length = data->length();

  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  ForceProcessFramePacket(QuicFrame(frame1_));
  if (VersionHasIetfQuicFrames(version().transport_version)) {
    // INITIAL packet should not contain STREAM frame.
    TestConnectionCloseQuicErrorCode(IETF_QUIC_PROTOCOL_VIOLATION);
  } else {
    TestConnectionCloseQuicErrorCode(QUIC_MAYBE_CORRUPTED_MEMORY);
  }
}

TEST_P(QuicConnectionTest, CloseConnectionOnPacketTooLarge) {
  SimulateNextPacketTooLarge();
  // A connection close packet is sent
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(1);
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  TestConnectionCloseQuicErrorCode(QUIC_PACKET_WRITE_ERROR);
}

TEST_P(QuicConnectionTest, AlwaysGetPacketTooLarge) {
  // Test even we always get packet too large, we do not infinitely try to send
  // close packet.
  AlwaysGetPacketTooLarge();
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(1);
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  TestConnectionCloseQuicErrorCode(QUIC_PACKET_WRITE_ERROR);
}

TEST_P(QuicConnectionTest, CloseConnectionOnQueuedWriteError) {
  // Regression test for crbug.com/979507.
  //
  // If we get a write error when writing queued packets, we should attempt to
  // send a connection close packet, but if sending that fails, it shouldn't get
  // queued.

  // Queue a packet to write.
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Configure writer to always fail.
  AlwaysGetPacketTooLarge();

  // Expect that we attempt to close the connection exactly once.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(1);

  // Unblock the writes and actually send.
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());

  TestConnectionCloseQuicErrorCode(QUIC_PACKET_WRITE_ERROR);
}

// Verify that if connection has no outstanding data, it notifies the send
// algorithm after the write.
TEST_P(QuicConnectionTest, SendDataAndBecomeApplicationLimited) {
  EXPECT_CALL(*send_algorithm_, OnApplicationLimited(_)).Times(1);
  {
    InSequence seq;
    EXPECT_CALL(visitor_, WillingAndAbleToWrite()).WillRepeatedly(Return(true));
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
    EXPECT_CALL(visitor_, WillingAndAbleToWrite())
        .WillRepeatedly(Return(false));
  }

  connection_.SendStreamData3();
}

// Verify that the connection does not become app-limited if there is
// outstanding data to send after the write.
TEST_P(QuicConnectionTest, NotBecomeApplicationLimitedIfMoreDataAvailable) {
  EXPECT_CALL(*send_algorithm_, OnApplicationLimited(_)).Times(0);
  {
    InSequence seq;
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
    EXPECT_CALL(visitor_, WillingAndAbleToWrite()).WillRepeatedly(Return(true));
  }

  connection_.SendStreamData3();
}

// Verify that the connection does not become app-limited after blocked write
// even if there is outstanding data to send after the write.
TEST_P(QuicConnectionTest, NotBecomeApplicationLimitedDueToWriteBlock) {
  EXPECT_CALL(*send_algorithm_, OnApplicationLimited(_)).Times(0);
  EXPECT_CALL(visitor_, WillingAndAbleToWrite()).WillRepeatedly(Return(true));
  BlockOnNextWrite();

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamData3();

  // Now unblock the writer, become congestion control blocked,
  // and ensure we become app-limited after writing.
  writer_->SetWritable();
  CongestionBlockWrites();
  EXPECT_CALL(visitor_, WillingAndAbleToWrite()).WillRepeatedly(Return(false));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*send_algorithm_, OnApplicationLimited(_)).Times(1);
  connection_.OnCanWrite();
}

TEST_P(QuicConnectionTest, DoNotForceSendingAckOnPacketTooLarge) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  // Send an ack by simulating delayed ack alarm firing.
  ProcessPacket(1);
  EXPECT_TRUE(connection_.HasPendingAcks());
  connection_.GetAckAlarm()->Fire();
  // Simulate data packet causes write error.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  SimulateNextPacketTooLarge();
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  EXPECT_EQ(1u, writer_->connection_close_frames().size());
  // Ack frame is not bundled in connection close packet.
  EXPECT_TRUE(writer_->ack_frames().empty());
  if (writer_->padding_frames().empty()) {
    EXPECT_EQ(1u, writer_->frame_count());
  } else {
    EXPECT_EQ(2u, writer_->frame_count());
  }

  TestConnectionCloseQuicErrorCode(QUIC_PACKET_WRITE_ERROR);
}

TEST_P(QuicConnectionTest, CloseConnectionAllLevels) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }

  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  const QuicErrorCode kQuicErrorCode = QUIC_INTERNAL_ERROR;
  connection_.CloseConnection(
      kQuicErrorCode, "Some random error message",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);

  EXPECT_EQ(2u, QuicConnectionPeer::GetNumEncryptionLevels(&connection_));

  TestConnectionCloseQuicErrorCode(kQuicErrorCode);
  EXPECT_EQ(1u, writer_->connection_close_frames().size());

  if (!connection_.version().CanSendCoalescedPackets()) {
    // Each connection close packet should be sent in distinct UDP packets.
    EXPECT_EQ(QuicConnectionPeer::GetNumEncryptionLevels(&connection_),
              writer_->connection_close_packets());
    EXPECT_EQ(QuicConnectionPeer::GetNumEncryptionLevels(&connection_),
              writer_->packets_write_attempts());
    return;
  }

  // A single UDP packet should be sent with multiple connection close packets
  // coalesced together.
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  // Only the first packet has been processed yet.
  EXPECT_EQ(1u, writer_->connection_close_packets());

  // ProcessPacket resets the visitor and frees the coalesced packet.
  ASSERT_TRUE(writer_->coalesced_packet() != nullptr);
  auto packet = writer_->coalesced_packet()->Clone();
  writer_->framer()->ProcessPacket(*packet);
  EXPECT_EQ(1u, writer_->connection_close_packets());
  ASSERT_TRUE(writer_->coalesced_packet() == nullptr);
}

TEST_P(QuicConnectionTest, CloseConnectionOneLevel) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }

  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  const QuicErrorCode kQuicErrorCode = QUIC_INTERNAL_ERROR;
  connection_.CloseConnection(
      kQuicErrorCode, "Some random error message",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);

  EXPECT_EQ(2u, QuicConnectionPeer::GetNumEncryptionLevels(&connection_));

  TestConnectionCloseQuicErrorCode(kQuicErrorCode);
  EXPECT_EQ(1u, writer_->connection_close_frames().size());
  EXPECT_EQ(1u, writer_->connection_close_packets());
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  ASSERT_TRUE(writer_->coalesced_packet() == nullptr);
}

TEST_P(QuicConnectionTest, DoNotPadServerInitialConnectionClose) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  // Receives packet 1000 in initial data.
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);

  if (version().handshake_protocol == PROTOCOL_TLS1_3) {
    EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  }
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  const QuicErrorCode kQuicErrorCode = QUIC_INTERNAL_ERROR;
  connection_.CloseConnection(
      kQuicErrorCode, "Some random error message",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);

  EXPECT_EQ(2u, QuicConnectionPeer::GetNumEncryptionLevels(&connection_));

  TestConnectionCloseQuicErrorCode(kQuicErrorCode);
  EXPECT_EQ(1u, writer_->connection_close_frames().size());
  EXPECT_TRUE(writer_->padding_frames().empty());
  EXPECT_EQ(ENCRYPTION_INITIAL, writer_->framer()->last_decrypted_level());
}

// Regression test for b/63620844.
TEST_P(QuicConnectionTest, FailedToWriteHandshakePacket) {
  SimulateNextPacketTooLarge();
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .Times(1);

  connection_.SendCryptoStreamData();
  TestConnectionCloseQuicErrorCode(QUIC_PACKET_WRITE_ERROR);
}

TEST_P(QuicConnectionTest, MaxPacingRate) {
  EXPECT_EQ(0, connection_.MaxPacingRate().ToBytesPerSecond());
  connection_.SetMaxPacingRate(QuicBandwidth::FromBytesPerSecond(100));
  EXPECT_EQ(100, connection_.MaxPacingRate().ToBytesPerSecond());
}

TEST_P(QuicConnectionTest, ClientAlwaysSendConnectionId) {
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  EXPECT_EQ(CONNECTION_ID_PRESENT,
            writer_->last_packet_header().destination_connection_id_included);

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicConfigPeer::SetReceivedBytesForConnectionId(&config, 0);
  connection_.SetFromConfig(config);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(3, "bar", 3, NO_FIN);
  // Verify connection id is still sent in the packet.
  EXPECT_EQ(CONNECTION_ID_PRESENT,
            writer_->last_packet_header().destination_connection_id_included);
}

TEST_P(QuicConnectionTest, PingAfterLastRetransmittablePacketAcked) {
  const QuicTime::Delta retransmittable_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(50);
  connection_.set_initial_retransmittable_on_wire_timeout(
      retransmittable_on_wire_timeout);

  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

  const char data[] = "data";
  size_t data_size = strlen(data);
  QuicStreamOffset offset = 0;

  // Advance 5ms, send a retransmittable packet to the peer.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_TRUE(connection_.sent_packet_manager().HasInFlightPackets());
  // The ping alarm is set for the ping timeout, not the shorter
  // retransmittable_on_wire_timeout.
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  QuicTime::Delta ping_delay = QuicTime::Delta::FromSeconds(kPingTimeoutSecs);
  EXPECT_EQ(ping_delay,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Advance 5ms, send a second retransmittable packet to the peer.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());

  // Now receive an ACK of the first packet. This should not set the
  // retransmittable-on-wire alarm since packet 2 is still on the wire.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.sent_packet_manager().HasInFlightPackets());
  // The ping alarm is set for the ping timeout, not the shorter
  // retransmittable_on_wire_timeout.
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  // The ping alarm has a 1 second granularity, and the clock has been advanced
  // 10ms since it was originally set.
  EXPECT_EQ(ping_delay - QuicTime::Delta::FromMilliseconds(10),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Now receive an ACK of the second packet. This should set the
  // retransmittable-on-wire alarm now that no retransmittable packets are on
  // the wire.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  frame = InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(retransmittable_on_wire_timeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Now receive a duplicate ACK of the second packet. This should not update
  // the ping alarm.
  QuicTime prev_deadline = connection_.GetPingAlarm()->deadline();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  frame = InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(prev_deadline, connection_.GetPingAlarm()->deadline());

  // Now receive a non-ACK packet.  This should not update the ping alarm.
  prev_deadline = connection_.GetPingAlarm()->deadline();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  ProcessPacket(4);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(prev_deadline, connection_.GetPingAlarm()->deadline());

  // Simulate the alarm firing and check that a PING is sent.
  connection_.GetPingAlarm()->Fire();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 2u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->ping_frames().size());
}

TEST_P(QuicConnectionTest, NoPingIfRetransmittablePacketSent) {
  const QuicTime::Delta retransmittable_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(50);
  connection_.set_initial_retransmittable_on_wire_timeout(
      retransmittable_on_wire_timeout);

  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

  const char data[] = "data";
  size_t data_size = strlen(data);
  QuicStreamOffset offset = 0;

  // Advance 5ms, send a retransmittable packet to the peer.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_TRUE(connection_.sent_packet_manager().HasInFlightPackets());
  // The ping alarm is set for the ping timeout, not the shorter
  // retransmittable_on_wire_timeout.
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  QuicTime::Delta ping_delay = QuicTime::Delta::FromSeconds(kPingTimeoutSecs);
  EXPECT_EQ(ping_delay,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Now receive an ACK of the first packet. This should set the
  // retransmittable-on-wire alarm now that no retransmittable packets are on
  // the wire.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(retransmittable_on_wire_timeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Before the alarm fires, send another retransmittable packet. This should
  // cancel the retransmittable-on-wire alarm since now there's a
  // retransmittable packet on the wire.
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());

  // Now receive an ACK of the second packet. This should set the
  // retransmittable-on-wire alarm now that no retransmittable packets are on
  // the wire.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  frame = InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(retransmittable_on_wire_timeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Simulate the alarm firing and check that a PING is sent.
  writer_->Reset();
  connection_.GetPingAlarm()->Fire();
  size_t padding_frame_count = writer_->padding_frames().size();
  // Do not ACK acks.
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->ping_frames().size());
}

// When there is no stream data received but are open streams, send the
// first few consecutive pings with aggressive retransmittable-on-wire
// timeout. Exponentially back off the retransmittable-on-wire ping timeout
// afterwards until it exceeds the default ping timeout.
TEST_P(QuicConnectionTest, BackOffRetransmittableOnWireTimeout) {
  int max_aggressive_retransmittable_on_wire_ping_count = 5;
  SetQuicFlag(quic_max_aggressive_retransmittable_on_wire_ping_count,
              max_aggressive_retransmittable_on_wire_ping_count);
  const QuicTime::Delta initial_retransmittable_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(200);
  connection_.set_initial_retransmittable_on_wire_timeout(
      initial_retransmittable_on_wire_timeout);

  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

  const char data[] = "data";
  // Advance 5ms, send a retransmittable data packet to the peer.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  connection_.SendStreamDataWithString(1, data, 0, NO_FIN);
  EXPECT_TRUE(connection_.sent_packet_manager().HasInFlightPackets());
  // The ping alarm is set for the ping timeout, not the shorter
  // retransmittable_on_wire_timeout.
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _))
      .Times(AnyNumber());

  // Verify that the first few consecutive retransmittable on wire pings are
  // sent with aggressive timeout.
  for (int i = 0; i <= max_aggressive_retransmittable_on_wire_ping_count; i++) {
    // Receive an ACK of the previous packet. This should set the ping alarm
    // with the initial retransmittable-on-wire timeout.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    QuicPacketNumber ack_num = creator_->packet_number();
    QuicAckFrame frame = InitAckFrame(
        {{QuicPacketNumber(ack_num), QuicPacketNumber(ack_num + 1)}});
    ProcessAckPacket(&frame);
    EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
    EXPECT_EQ(initial_retransmittable_on_wire_timeout,
              connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
    // Simulate the alarm firing and check that a PING is sent.
    writer_->Reset();
    clock_.AdvanceTime(initial_retransmittable_on_wire_timeout);
    connection_.GetPingAlarm()->Fire();
  }

  QuicTime::Delta retransmittable_on_wire_timeout =
      initial_retransmittable_on_wire_timeout;

  // Verify subsequent pings are sent with timeout that is exponentially backed
  // off.
  while (retransmittable_on_wire_timeout * 2 <
         QuicTime::Delta::FromSeconds(kPingTimeoutSecs)) {
    // Receive an ACK for the previous PING. This should set the
    // ping alarm with backed off retransmittable-on-wire timeout.
    retransmittable_on_wire_timeout = retransmittable_on_wire_timeout * 2;
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    QuicPacketNumber ack_num = creator_->packet_number();
    QuicAckFrame frame = InitAckFrame(
        {{QuicPacketNumber(ack_num), QuicPacketNumber(ack_num + 1)}});
    ProcessAckPacket(&frame);
    EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
    EXPECT_EQ(retransmittable_on_wire_timeout,
              connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

    // Simulate the alarm firing and check that a PING is sent.
    writer_->Reset();
    clock_.AdvanceTime(retransmittable_on_wire_timeout);
    connection_.GetPingAlarm()->Fire();
  }

  // The ping alarm is set with default ping timeout.
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Receive an ACK for the previous PING. The ping alarm is set with an
  // earlier deadline.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  QuicPacketNumber ack_num = creator_->packet_number();
  QuicAckFrame frame = InitAckFrame(
      {{QuicPacketNumber(ack_num), QuicPacketNumber(ack_num + 1)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs) -
                QuicTime::Delta::FromMilliseconds(5),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
}

// This test verify that the count of consecutive aggressive pings is reset
// when new data is received. And it also verifies the connection resets
// the exponential back-off of the retransmittable-on-wire ping timeout
// after receiving new stream data.
TEST_P(QuicConnectionTest, ResetBackOffRetransmitableOnWireTimeout) {
  int max_aggressive_retransmittable_on_wire_ping_count = 3;
  SetQuicFlag(quic_max_aggressive_retransmittable_on_wire_ping_count, 3);
  const QuicTime::Delta initial_retransmittable_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(200);
  connection_.set_initial_retransmittable_on_wire_timeout(
      initial_retransmittable_on_wire_timeout);

  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _))
      .Times(AnyNumber());

  const char data[] = "data";
  // Advance 5ms, send a retransmittable data packet to the peer.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  connection_.SendStreamDataWithString(1, data, 0, NO_FIN);
  EXPECT_TRUE(connection_.sent_packet_manager().HasInFlightPackets());
  // The ping alarm is set for the ping timeout, not the shorter
  // retransmittable_on_wire_timeout.
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Receive an ACK of the first packet. This should set the ping alarm with
  // initial retransmittable-on-wire timeout since there is no retransmittable
  // packet on the wire.
  {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    QuicAckFrame frame =
        InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
    ProcessAckPacket(&frame);
    EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
    EXPECT_EQ(initial_retransmittable_on_wire_timeout,
              connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
  }

  // Simulate the alarm firing and check that a PING is sent.
  writer_->Reset();
  clock_.AdvanceTime(initial_retransmittable_on_wire_timeout);
  connection_.GetPingAlarm()->Fire();

  // Receive an ACK for the previous PING. Ping alarm will be set with
  // aggressive timeout.
  {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    QuicPacketNumber ack_num = creator_->packet_number();
    QuicAckFrame frame = InitAckFrame(
        {{QuicPacketNumber(ack_num), QuicPacketNumber(ack_num + 1)}});
    ProcessAckPacket(&frame);
    EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
    EXPECT_EQ(initial_retransmittable_on_wire_timeout,
              connection_.GetPingAlarm()->deadline() - clock_.Approx
```