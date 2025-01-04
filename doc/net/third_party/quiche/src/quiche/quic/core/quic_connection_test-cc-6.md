Response:
The user wants to understand the functionality of the `quic_connection_test.cc` file in the Chromium network stack.

Here's a plan to address the request:

1. **General Functionality:**  Analyze the test cases present in the provided code snippet and infer the broader functionalities of the `QuicConnection` class being tested.
2. **JavaScript Relationship:** Examine the tested functionalities for any direct or indirect relation to JavaScript concepts or APIs. Since this is low-level network code, the relationship is likely indirect.
3. **Logical Reasoning with Examples:** Select a few representative test cases and demonstrate the logical flow by providing hypothetical inputs and expected outputs.
4. **Common User/Programming Errors:** Identify potential pitfalls or incorrect usages of the `QuicConnection` class that these tests aim to prevent.
5. **User Operation to Reach Here:** Outline the steps a user might take in a web browser that would eventually lead to the execution of this code.
6. **Part 7 of 24 Summary:**  Based on the analyzed test cases in this specific snippet, summarize the key functionalities covered in this part of the test suite.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 文件的一部分，它是一个 Chromium 网络栈中 QUIC 连接的核心测试文件。从提供的代码片段来看，这部分测试主要集中在以下功能：

**功能归纳 (基于提供的第 7 部分):**

1. **处理 UDP 数据包和加密:** 测试 `QuicConnection` 如何接收和处理来自对端的加密 UDP 数据包，包括数据包的解密和对连接状态的影响（例如，设置发送告警）。
2. **写入阻塞机制:**  测试在连接因为写入器（writer）阻塞时，`QuicConnection` 如何将其自身添加到写入阻塞列表，并在连接断开后避免添加到该列表。
3. **处理 ACK 和 NACK 包:** 测试 `QuicConnection` 如何处理对端发送的 ACK (确认) 和 NACK (否定确认) 包，并触发相应的操作，例如拥塞控制算法的更新和丢包检测。
4. **处理多个 ACK:** 测试连接如何处理来自对端的多个 ACK 包，以及这如何影响已发送但未确认的数据的状态。
5. **数据包的重传行为:** 测试在握手完成前后，`QuicConnection` 如何处理初始加密数据包的重传。
6. **缓冲无法解密的包:** 测试 `QuicConnection` 如何缓冲由于加密密钥尚未就绪而无法解密的包，并在密钥就绪后进行处理。
7. **RTO (重传超时) 机制:** 测试 RTO 计时器的启动和管理，特别是在写入套接字时。
8. **数据包排队:** 测试当写入器阻塞时，数据包如何在 `QuicConnection` 中排队。
9. **空闲超时和握手超时:** 测试连接的空闲超时和握手超时机制，以及在超时发生时连接如何关闭。
10. **Ping 机制:** 测试连接在需要保持连接活跃时发送 PING 帧的机制，包括正常超时和缩短超时的情况。
11. **MTU (最大传输单元) 发现:** 测试连接如何发送 MTU 发现包来探测网络路径的最大包大小，并根据探测结果调整连接的 MTU。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它所测试的 QUIC 连接功能是 Web 浏览器与服务器进行通信的基础。当 JavaScript 代码通过浏览器发起网络请求 (例如使用 `fetch` API 或 `XMLHttpRequest`) 时，浏览器底层可能会使用 QUIC 协议来建立和维护连接。

**举例说明:**

假设一个用户在浏览器中访问一个使用 QUIC 的网站。当 JavaScript 代码执行 `fetch("https://example.com/data")` 时，浏览器会：

1. **建立 QUIC 连接:** 如果尚未建立到 `example.com` 的 QUIC 连接，浏览器会尝试建立连接。这涉及到握手过程，其中 `quic_connection_test.cc` 中测试的加密和密钥交换逻辑会发挥作用。
2. **发送请求:**  一旦连接建立，浏览器会将 JavaScript 发起的 HTTP 请求 (封装在 QUIC 的 Stream 中) 发送到服务器。`QuicConnection` 类负责将这些数据包发送出去。
3. **接收响应:** 服务器会通过 QUIC 连接发送响应。`QuicConnection` 类负责接收和处理这些响应数据包，其中包括测试文件中涉及的解密、ACK 处理等。
4. **处理拥塞和丢包:** 如果网络出现拥塞或丢包，`QuicConnection` 中测试的拥塞控制和重传机制会介入，确保数据可靠传输。

**逻辑推理与假设输入输出 (选取部分测试用例):**

**测试用例:** `AddToWriteBlockedListIfWriterBlockedWhenProcessing`

* **假设输入:**
    * 连接已经建立。
    * 客户端发送了一些数据到服务端。
    * 服务端发送一个 ACK 包来确认收到了一些数据。
    * 底层的写入器 (`writer_`) 因为其他连接而被阻塞 (`writer_->SetWriteBlocked();`)。
* **预期输出:**
    * 当 `QuicConnection` 处理这个 ACK 包时，它会检测到写入器被阻塞。
    * `visitor_->OnWriteBlocked()` 方法会被调用，通知上层应用连接被阻塞，无法发送数据。

**测试用例:** `BufferNonDecryptablePackets`

* **假设输入:**
    * 连接的加密级别尚未达到足以解密新到达的数据包的程度（例如，收到了使用 `ENCRYPTION_ZERO_RTT` 加密的包，但解密器尚未就绪）。
    * 接收到一个数据包，其包序号为 1，加密级别为 `ENCRYPTION_ZERO_RTT`。
    * 接收到第二个数据包，其包序号为 2，加密级别也为 `ENCRYPTION_ZERO_RTT`。
    * 连接随后更新了解密器，可以处理 `ENCRYPTION_ZERO_RTT` 的包。
    * 接收到第三个数据包，其包序号为 3，加密级别为 `ENCRYPTION_ZERO_RTT`。
* **预期输出:**
    * 第一个数据包因为无法解密而被缓冲。
    * 第二个数据包也因为无法解密而被缓冲。
    * 当解密器更新后，缓冲的第一个和第二个数据包会被处理，`visitor_->OnStreamFrame(_)` 会被调用两次。
    * 第三个数据包到达时，由于解密器已就绪，它会立即被处理，`visitor_->OnStreamFrame(_)` 会被调用一次。

**用户或编程常见的使用错误 (可能由这些测试覆盖):**

1. **在连接关闭后尝试发送数据:** 测试 `DoNotAddToWriteBlockedListAfterDisconnect` 确保在连接关闭后不会因为写入阻塞而产生意外行为。用户或程序如果未正确检查连接状态，可能会尝试在连接已关闭后发送数据，导致错误。
2. **假设所有接收到的包都能立即解密:** `BufferNonDecryptablePackets` 测试处理了密钥交换过程中的包乱序问题。开发者需要意识到，在 QUIC 连接建立的早期阶段，收到的包可能由于密钥未就绪而无法立即解密。
3. **未正确处理连接超时:**  `InitialTimeout` 和 `IdleTimeoutAfterFirstSentPacket` 等测试覆盖了连接超时的场景。开发者需要确保应用层能妥善处理连接超时事件，例如重新建立连接。
4. **依赖即时的 MTU 更新:** `SendMtuDiscoveryPacket` 测试了 MTU 发现的过程。开发者不应假设 MTU 的改变会立即生效，因为 MTU 探测需要时间。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在 Chrome 浏览器中访问 `https://example.com`：

1. **用户在地址栏输入网址并回车。**
2. **浏览器开始解析域名 `example.com` 的 IP 地址。**
3. **浏览器尝试与服务器建立连接，优先考虑 QUIC 协议。**
4. **QUIC 连接建立过程:**
    * 浏览器和服务器交换初始握手包。
    * `QuicConnection` 类在浏览器端被创建和初始化。
    * 这段 `quic_connection_test.cc` 中测试的加密、密钥协商、超时处理等逻辑会在这个阶段被执行。
5. **数据传输:** 连接建立后，浏览器发送 HTTP 请求，服务器发送响应。这个过程中：
    * `QuicConnection` 负责将请求数据分割成 QUIC 数据包并发送。
    * 如果网络拥塞或丢包，测试中涉及的拥塞控制和重传机制会被触发。
    * 如果接收到加密的数据包，`BufferNonDecryptablePackets` 测试覆盖的逻辑可能会被执行。
6. **连接维护:**  即使在数据传输完成后，连接也可能保持一段时间的活跃。`PingAfterSend` 和 `ReducedPingTimeout` 测试的 PING 机制用于维持连接活跃。
7. **连接关闭:** 当会话结束或发生错误时，QUIC 连接会被关闭。

在调试网络问题时，开发者可能会查看 Chrome 的内部日志 (例如 `chrome://net-internals/#quic`) 来分析 QUIC 连接的状态，例如丢包率、RTT、拥塞窗口等，这能帮助定位到 `QuicConnection` 层的潜在问题。

总而言之，这段代码是 `QuicConnection` 类的单元测试，它验证了 QUIC 连接在各种场景下的核心功能，包括数据包的收发、加密解密、拥塞控制、超时处理以及 MTU 发现等。这些功能是浏览器实现高效可靠网络通信的关键组成部分。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共24部分，请归纳一下它的功能

"""
N_FORWARD_SECURE;
  std::unique_ptr<QuicPacket> packet(
      ConstructDataPacket(received_packet_num, has_stop_waiting, level));
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      peer_framer_.EncryptPayload(level, QuicPacketNumber(received_packet_num),
                                  *packet, buffer, kMaxOutgoingPacketSize);
  EXPECT_CALL(visitor_, WillingAndAbleToWrite()).WillRepeatedly(Return(true));
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false));

  EXPECT_TRUE(connection_.GetSendAlarm()->IsSet());
  // It was set to be 10 ms in the future, so it should at the least be greater
  // than now + 5 ms.
  EXPECT_TRUE(connection_.GetSendAlarm()->deadline() >
              clock_.ApproximateNow() + QuicTime::Delta::FromMilliseconds(5));
}

TEST_P(QuicConnectionTest, AddToWriteBlockedListIfWriterBlockedWhenProcessing) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, nullptr);

  // Simulate the case where a shared writer gets blocked by another connection.
  writer_->SetWriteBlocked();

  // Process an ACK, make sure the connection calls visitor_->OnWriteBlocked().
  QuicAckFrame ack1 = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(1);
  ProcessAckPacket(1, &ack1);
}

TEST_P(QuicConnectionTest, DoNotAddToWriteBlockedListAfterDisconnect) {
  writer_->SetBatchMode(true);
  EXPECT_TRUE(connection_.connected());
  // Have to explicitly grab the OnConnectionClosed frame and check
  // its parameters because this is a silent connection close and the
  // frame is not also transmitted to the peer.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));

  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(0);

  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.CloseConnection(QUIC_PEER_GOING_AWAY, "no reason",
                                ConnectionCloseBehavior::SILENT_CLOSE);

    EXPECT_FALSE(connection_.connected());
    writer_->SetWriteBlocked();
  }
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_PEER_GOING_AWAY));
}

TEST_P(QuicConnectionTest, AddToWriteBlockedListIfBlockedOnFlushPackets) {
  writer_->SetBatchMode(true);
  writer_->BlockOnNextFlush();

  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(1);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // flusher's destructor will call connection_.FlushPackets, which should add
    // the connection to the write blocked list.
  }
}

TEST_P(QuicConnectionTest, NoLimitPacketsPerNack) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  int offset = 0;
  // Send packets 1 to 15.
  for (int i = 0; i < 15; ++i) {
    SendStreamDataToPeer(1, "foo", offset, NO_FIN, nullptr);
    offset += 3;
  }

  // Ack 15, nack 1-14.

  QuicAckFrame nack =
      InitAckFrame({{QuicPacketNumber(15), QuicPacketNumber(16)}});

  // 14 packets have been NACK'd and lost.
  LostPacketVector lost_packets;
  for (int i = 1; i < 15; ++i) {
    lost_packets.push_back(
        LostPacket(QuicPacketNumber(i), kMaxOutgoingPacketSize));
  }
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessAckPacket(&nack);
}

// Test sending multiple acks from the connection to the session.
TEST_P(QuicConnectionTest, MultipleAcks) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacket(1);
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 2);
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);  // Packet 1
  EXPECT_EQ(QuicPacketNumber(1u), last_packet);
  SendStreamDataToPeer(3, "foo", 0, NO_FIN, &last_packet);  // Packet 2
  EXPECT_EQ(QuicPacketNumber(2u), last_packet);
  SendAckPacketToPeer();                                    // Packet 3
  SendStreamDataToPeer(5, "foo", 0, NO_FIN, &last_packet);  // Packet 4
  EXPECT_EQ(QuicPacketNumber(4u), last_packet);
  SendStreamDataToPeer(1, "foo", 3, NO_FIN, &last_packet);  // Packet 5
  EXPECT_EQ(QuicPacketNumber(5u), last_packet);
  SendStreamDataToPeer(3, "foo", 3, NO_FIN, &last_packet);  // Packet 6
  EXPECT_EQ(QuicPacketNumber(6u), last_packet);

  // Client will ack packets 1, 2, [!3], 4, 5.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame1 = ConstructAckFrame(5, 3);
  ProcessAckPacket(&frame1);

  // Now the client implicitly acks 3, and explicitly acks 6.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame2 = InitAckFrame(6);
  ProcessAckPacket(&frame2);
}

TEST_P(QuicConnectionTest, DontLatchUnackedPacket) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacket(1);
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 2);
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, nullptr);  // Packet 1;
  // From now on, we send acks, so the send algorithm won't mark them pending.
  SendAckPacketToPeer();  // Packet 2

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame = InitAckFrame(1);
  ProcessAckPacket(&frame);

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  frame = InitAckFrame(2);
  ProcessAckPacket(&frame);

  // When we send an ack, we make sure our least-unacked makes sense.  In this
  // case since we're not waiting on an ack for 2 and all packets are acked, we
  // set it to 3.
  SendAckPacketToPeer();  // Packet 3

  // Ack the ack, which updates the rtt and raises the least unacked.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  frame = InitAckFrame(3);
  ProcessAckPacket(&frame);

  SendStreamDataToPeer(1, "bar", 3, NO_FIN, nullptr);  // Packet 4
  SendAckPacketToPeer();                               // Packet 5

  // Send two data packets at the end, and ensure if the last one is acked,
  // the least unacked is raised above the ack packets.
  SendStreamDataToPeer(1, "bar", 6, NO_FIN, nullptr);  // Packet 6
  SendStreamDataToPeer(1, "bar", 9, NO_FIN, nullptr);  // Packet 7

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  frame = InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(5)},
                        {QuicPacketNumber(7), QuicPacketNumber(8)}});
  ProcessAckPacket(&frame);
}

TEST_P(QuicConnectionTest, SendHandshakeMessages) {
  // Attempt to send a handshake message and have the socket block.
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  BlockOnNextWrite();
  connection_.SendCryptoDataWithString("foo", 0);
  // The packet should be serialized, but not queued.
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Switch to the new encrypter.
  connection_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);

  // Now become writeable and flush the packets.
  writer_->SetWritable();
  EXPECT_CALL(visitor_, OnCanWrite());
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());

  // Verify that the handshake packet went out with Initial encryption.
  EXPECT_NE(0x02020202u, writer_->final_bytes_of_last_packet());
}

TEST_P(QuicConnectionTest, DropRetransmitsForInitialPacketAfterForwardSecure) {
  connection_.SendCryptoStreamData();
  // Simulate the retransmission alarm firing and the socket blocking.
  BlockOnNextWrite();
  clock_.AdvanceTime(DefaultRetransmissionTime());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Go forward secure.
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  notifier_.NeuterUnencryptedData();
  connection_.NeuterUnencryptedPackets();
  connection_.OnHandshakeComplete();

  EXPECT_EQ(QuicTime::Zero(), connection_.GetRetransmissionAlarm()->deadline());
  // Unblock the socket and ensure that no packets are sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  writer_->SetWritable();
  connection_.OnCanWrite();
}

TEST_P(QuicConnectionTest, RetransmitPacketsWithInitialEncryption) {
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);

  connection_.SendCryptoDataWithString("foo", 0);

  connection_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  if (!connection_.version().KnowsWhichDecrypterToUse()) {
    writer_->framer()->framer()->SetAlternativeDecrypter(
        ENCRYPTION_ZERO_RTT,
        std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT), false);
  }

  SendStreamDataToPeer(2, "bar", 0, NO_FIN, nullptr);
  EXPECT_FALSE(notifier_.HasLostStreamData());
  connection_.MarkZeroRttPacketsForRetransmission(0);
  EXPECT_TRUE(notifier_.HasLostStreamData());
}

TEST_P(QuicConnectionTest, BufferNonDecryptablePackets) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  if (!connection_.version().KnowsWhichDecrypterToUse()) {
    writer_->framer()->framer()->SetDecrypter(
        ENCRYPTION_ZERO_RTT, std::make_unique<TaggingDecrypter>());
  }

  // Process an encrypted packet which can not yet be decrypted which should
  // result in the packet being buffered.
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);

  // Transition to the new encryption state and process another encrypted packet
  // which should result in the original packet being processed.
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(2);
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);

  // Finally, process a third packet and note that we do not reprocess the
  // buffered packet.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
}

TEST_P(QuicConnectionTest, Buffer100NonDecryptablePacketsThenKeyChange) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.set_max_undecryptable_packets(100);
  connection_.SetFromConfig(config);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));

  // Process an encrypted packet which can not yet be decrypted which should
  // result in the packet being buffered.
  for (uint64_t i = 1; i <= 100; ++i) {
    ProcessDataPacketAtLevel(i, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
  }

  // Transition to the new encryption state and process another encrypted packet
  // which should result in the original packets being processed.
  EXPECT_FALSE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  EXPECT_TRUE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  connection_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(100);
  if (!connection_.version().KnowsWhichDecrypterToUse()) {
    writer_->framer()->framer()->SetDecrypter(
        ENCRYPTION_ZERO_RTT, std::make_unique<TaggingDecrypter>());
  }
  connection_.GetProcessUndecryptablePacketsAlarm()->Fire();

  // Finally, process a third packet and note that we do not reprocess the
  // buffered packet.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(102, !kHasStopWaiting, ENCRYPTION_ZERO_RTT);
}

TEST_P(QuicConnectionTest, SetRTOAfterWritingToSocket) {
  BlockOnNextWrite();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Test that RTO is started once we write to the socket.
  writer_->SetWritable();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, TestQueued) {
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Unblock the writes and actually send.
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, InitialTimeout) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());

  // SetFromConfig sets the initial timeouts before negotiation.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  // Subtract a second from the idle timeout on the client side.
  QuicTime default_timeout =
      clock_.ApproximateNow() +
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  // Simulate the timeout alarm firing.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1));
  connection_.GetTimeoutAlarm()->Fire();

  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());

  EXPECT_FALSE(connection_.HasPendingAcks());
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetProcessUndecryptablePacketsAlarm()->IsSet());
  TestConnectionCloseQuicErrorCode(QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicConnectionTest, IdleTimeoutAfterFirstSentPacket) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  QuicTime initial_ddl =
      clock_.ApproximateNow() +
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  EXPECT_EQ(initial_ddl, connection_.GetTimeoutAlarm()->deadline());
  EXPECT_TRUE(connection_.connected());

  // Advance the time and send the first packet to the peer.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(1u), last_packet);
  // This will be the updated deadline for the connection to idle time out.
  QuicTime new_ddl = clock_.ApproximateNow() +
                     QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);

  // Simulate the timeout alarm firing, the connection should not be closed as
  // a new packet has been sent.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(0);
  QuicTime::Delta delay = initial_ddl - clock_.ApproximateNow();
  clock_.AdvanceTime(delay);
  // Verify the timeout alarm deadline is updated.
  EXPECT_TRUE(connection_.connected());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_EQ(new_ddl, connection_.GetTimeoutAlarm()->deadline());

  // Simulate the timeout alarm firing again, the connection now should be
  // closed.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  clock_.AdvanceTime(new_ddl - clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());

  EXPECT_FALSE(connection_.HasPendingAcks());
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  TestConnectionCloseQuicErrorCode(QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicConnectionTest, IdleTimeoutAfterSendTwoPackets) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  QuicTime initial_ddl =
      clock_.ApproximateNow() +
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  EXPECT_EQ(initial_ddl, connection_.GetTimeoutAlarm()->deadline());
  EXPECT_TRUE(connection_.connected());

  // Immediately send the first packet, this is a rare case but test code will
  // hit this issue often as MockClock used for tests doesn't move with code
  // execution until manually adjusted.
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(1u), last_packet);

  // Advance the time and send the second packet to the peer.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(2u), last_packet);

  // Simulate the timeout alarm firing, the connection will be closed.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  clock_.AdvanceTime(initial_ddl - clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();

  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());

  EXPECT_FALSE(connection_.HasPendingAcks());
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  TestConnectionCloseQuicErrorCode(QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicConnectionTest, HandshakeTimeout) {
  // Use a shorter handshake timeout than idle timeout for this test.
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  connection_.SetNetworkTimeouts(timeout, timeout);
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());

  QuicTime handshake_timeout =
      clock_.ApproximateNow() + timeout - QuicTime::Delta::FromSeconds(1);
  EXPECT_EQ(handshake_timeout, connection_.GetTimeoutAlarm()->deadline());
  EXPECT_TRUE(connection_.connected());

  // Send and ack new data 3 seconds later to lengthen the idle timeout.
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(0, connection_.transport_version()),
      "GET /", 0, FIN, nullptr);
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(3));
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&frame);

  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_TRUE(connection_.connected());

  clock_.AdvanceTime(timeout - QuicTime::Delta::FromSeconds(2));

  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  // Simulate the timeout alarm firing.
  connection_.GetTimeoutAlarm()->Fire();

  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());

  EXPECT_FALSE(connection_.HasPendingAcks());
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());
  TestConnectionCloseQuicErrorCode(QUIC_HANDSHAKE_TIMEOUT);
}

TEST_P(QuicConnectionTest, PingAfterSend) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());

  // Advance to 5ms, and send a packet to the peer, which will set
  // the ping alarm.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(0, connection_.transport_version()),
      "GET /", 0, FIN, nullptr);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(15),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Now recevie an ACK of the previous packet, which will move the
  // ping alarm forward.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  // The ping timer is set slightly less than 15 seconds in the future, because
  // of the 1s ping timer alarm granularity.
  EXPECT_EQ(
      QuicTime::Delta::FromSeconds(15) - QuicTime::Delta::FromMilliseconds(5),
      connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  writer_->Reset();
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(15));
  connection_.GetPingAlarm()->Fire();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->ping_frames().size());
  writer_->Reset();

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(false));
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  SendAckPacketToPeer();

  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, ReducedPingTimeout) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());

  // Use a reduced ping timeout for this connection.
  connection_.set_keep_alive_ping_timeout(QuicTime::Delta::FromSeconds(10));

  // Advance to 5ms, and send a packet to the peer, which will set
  // the ping alarm.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(0, connection_.transport_version()),
      "GET /", 0, FIN, nullptr);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(10),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Now recevie an ACK of the previous packet, which will move the
  // ping alarm forward.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  // The ping timer is set slightly less than 10 seconds in the future, because
  // of the 1s ping timer alarm granularity.
  EXPECT_EQ(
      QuicTime::Delta::FromSeconds(10) - QuicTime::Delta::FromMilliseconds(5),
      connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  writer_->Reset();
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(10));
  connection_.GetPingAlarm()->Fire();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->ping_frames().size());
  writer_->Reset();

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(false));
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  SendAckPacketToPeer();

  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
}

// Tests whether sending an MTU discovery packet to peer successfully causes the
// maximum packet size to increase.
TEST_P(QuicConnectionTest, SendMtuDiscoveryPacket) {
  MtuDiscoveryTestInit();

  // Send an MTU probe.
  const size_t new_mtu = kDefaultMaxPacketSize + 100;
  QuicByteCount mtu_probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&mtu_probe_size));
  connection_.SendMtuDiscoveryPacket(new_mtu);
  EXPECT_EQ(new_mtu, mtu_probe_size);
  EXPECT_EQ(QuicPacketNumber(1u), creator_->packet_number());

  // Send more than MTU worth of data.  No acknowledgement was received so far,
  // so the MTU should be at its old value.
  const std::string data(kDefaultMaxPacketSize + 1, '.');
  QuicByteCount size_before_mtu_change;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(2)
      .WillOnce(SaveArg<3>(&size_before_mtu_change))
      .WillOnce(Return());
  connection_.SendStreamDataWithString(3, data, 0, FIN);
  EXPECT_EQ(QuicPacketNumber(3u), creator_->packet_number());
  EXPECT_EQ(kDefaultMaxPacketSize, size_before_mtu_change);

  // Acknowledge all packets so far.
  QuicAckFrame probe_ack = InitAckFrame(3);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&probe_ack);
  EXPECT_EQ(new_mtu, connection_.max_packet_length());

  // Send the same data again.  Check that it fits into a single packet now.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(3, data, 0, FIN);
  EXPECT_EQ(QuicPacketNumber(4u), creator_->packet_number());
}

// Verifies that when a MTU probe packet is sent and buffered in a batch writer,
// the writer is flushed immediately.
TEST_P(QuicConnectionTest, BatchWriterFlushedAfterMtuDiscoveryPacket) {
  writer_->SetBatchMode(true);
  MtuDiscoveryTestInit();

  // Send an MTU probe.
  const size_t target_mtu = kDefaultMaxPacketSize + 100;
  QuicByteCount mtu_probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&mtu_probe_size));
  const uint32_t prior_flush_attempts = writer_->flush_attempts();
  connection_.SendMtuDiscoveryPacket(target_mtu);
  EXPECT_EQ(target_mtu, mtu_probe_size);
  EXPECT_EQ(writer_->flush_attempts(), prior_flush_attempts + 1);
}

// Tests whether MTU discovery does not happen when it is not explicitly enabled
// by the connection options.
TEST_P(QuicConnectionTest, MtuDiscoveryDisabled) {
  MtuDiscoveryTestInit();

  const QuicPacketCount packets_between_probes_base = 10;
  set_packets_between_probes_base(packets_between_probes_base);

  const QuicPacketCount number_of_packets = packets_between_probes_base * 2;
  for (QuicPacketCount i = 0; i < number_of_packets; i++) {
    SendStreamDataToPeer(3, ".", i, NO_FIN, nullptr);
    EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
    EXPECT_EQ(0u, connection_.mtu_probe_count());
  }
}

// Tests whether MTU discovery works when all probes are acknowledged on the
// first try.
TEST_P(QuicConnectionTest, MtuDiscoveryEnabled) {
  MtuDiscoveryTestInit();

  const QuicPacketCount packets_between_probes_base = 5;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < packets_between_probes_base - 1; i++) {
    SendStreamDataToPeer(3, ".", i, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", packets_between_probes_base - 1, NO_FIN,
                       nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&probe_size));
  connection_.GetMtuDiscoveryAlarm()->Fire();

  EXPECT_THAT(probe_size, InRange(connection_.max_packet_length(),
                                  kMtuDiscoveryTargetPacketSizeHigh));

  const QuicPacketNumber probe_packet_number =
      FirstSendingPacketNumber() + packets_between_probes_base;
  ASSERT_EQ(probe_packet_number, creator_->packet_number());

  // Acknowledge all packets sent so far.
  {
    QuicAckFrame probe_ack = InitAckFrame(probe_packet_number);
    EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _))
        .Times(AnyNumber());
    ProcessAckPacket(&probe_ack);
    EXPECT_EQ(probe_size, connection_.max_packet_length());
    EXPECT_EQ(0u, connection_.GetBytesInFlight());

    EXPECT_EQ(1u, connection_.mtu_probe_count());
  }

  QuicStreamOffset stream_offset = packets_between_probes_base;
  QuicByteCount last_probe_size = 0;
  for (size_t num_probes = 1; num_probes < kMtuDiscoveryAttempts;
       ++num_probes) {
    // Send just enough packets without triggering the next probe.
    for (QuicPacketCount i = 0;
         i < (packets_between_probes_base << num_probes) - 1; ++i) {
      SendStreamDataToPeer(3, ".", stream_offset++, NO_FIN, nullptr);
      ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
    }

    // Trigger the next probe.
    SendStreamDataToPeer(3, "!", stream_offset++, NO_FIN, nullptr);
    ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
    QuicByteCount new_probe_size;
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .WillOnce(SaveArg<3>(&new_probe_size));
    connection_.GetMtuDiscoveryAlarm()->Fire();
    EXPECT_THAT(new_probe_size,
                InRange(probe_size, kMtuDiscoveryTargetPacketSizeHigh));
    EXPECT_EQ(num_probes + 1, connection_.mtu_probe_count());

    // Acknowledge all packets sent so far.
    QuicAckFrame probe_ack = InitAckFrame(creator_->packet_number());
    ProcessAckPacket(&probe_ack);
    EXPECT_EQ(new_probe_size, connection_.max_packet_length());
    EXPECT_EQ(0u, connection_.GetBytesInFlight());

    last_probe_size = probe_size;
    probe_size = new_probe_size;
  }

  // The last probe size should be equal to the target.
  EXPECT_EQ(probe_size, kMtuDiscoveryTargetPacketSizeHigh);

  writer_->SetShouldWriteFail();

  // Ignore PACKET_WRITE_ERROR once.
  SendStreamDataToPeer(3, "(", stream_offset++, NO_FIN, nullptr);
  EXPECT_EQ(last_probe_size, connection_.max_packet_length());
  EXPECT_TRUE(connection_.connected());

  // Close connection on another PACKET_WRITE_ERROR.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  SendStreamDataToPeer(3, ")", stream_offset++, NO_FIN, nullptr);
  EXPECT_EQ(last_probe_size, connection_.max_packet_length());
  EXPECT_FALSE(connection_.c
"""


```