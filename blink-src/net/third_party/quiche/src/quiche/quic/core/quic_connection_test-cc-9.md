Response:
The user wants to understand the functionality of the `quic_connection_test.cc` file in the Chromium network stack.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file name `quic_connection_test.cc` strongly suggests it contains unit tests for the `QuicConnection` class. This is the primary function.

2. **Analyze the provided code snippets:** Scan the provided code for common testing patterns. Look for:
    * `TEST_P`: This indicates parameterized tests, meaning the same test is run with different configurations (likely Quic versions).
    * `EXPECT_CALL`:  These lines set up expectations for interactions with mock objects (like `visitor_`, `send_algorithm_`, `writer_`). This helps verify correct behavior under specific conditions.
    * Actions being tested: Look for methods of `connection_` being called (e.g., `ProcessUdpPacket`, `SendStreamDataWithString`, `SetFromConfig`).
    * Assertions: `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT` indicate checks on the state of the `QuicConnection` object after performing an action.
    * Specific scenarios being tested: Notice tests with names like `ClientHandlesVersionNegotiation`, `BadVersionNegotiation`, `ProcessFramesIfPacketClosedConnection`, `ConnectionCloseWhenWritable`, etc. These describe the specific behaviors being verified.

3. **Categorize the functionalities being tested:** Group the identified scenarios into broader categories. Based on the code, key areas seem to be:
    * **Connection Lifecycle:**  Connection establishment, closing (both graceful and error-based).
    * **Version Negotiation:** Handling different Quic versions.
    * **Packet Processing:** Receiving and processing different types of packets (data, control, version negotiation, connection close).
    * **Error Handling:** How the connection reacts to invalid or unexpected input.
    * **Congestion Control and Pacing:** Testing the mechanisms for managing network congestion.
    * **ACK Handling:**  How acknowledgments are processed.
    * **Retransmission and Probing:** Testing the mechanisms for retransmitting lost packets and probing the network path.
    * **Keep-Alive Mechanisms:** Testing how the connection stays alive when idle.
    * **Debug Functionality:** Observing interactions through a debug visitor.

4. **Address specific requirements from the prompt:**
    * **Relationship with JavaScript:**  Consider how these low-level networking tests relate to the higher-level JavaScript API. The core idea is that these tests ensure the underlying Quic implementation is robust, which indirectly supports the functionality exposed to JavaScript through browser APIs. Direct code-level interaction is unlikely. Focus on the *impact* of correct Quic behavior on JavaScript.
    * **Logic and I/O Examples:**  For tests involving logic (e.g., version negotiation), provide a simple example with assumed input (a version negotiation packet) and expected output (the connection closing).
    * **Common User Errors:**  Think about common mistakes users or developers might make that could trigger these tested scenarios. Examples include network configuration issues, misconfiguration of Quic options, or sending invalid data.
    * **Debugging Steps:** Describe a hypothetical user action that would lead to the execution of this code, highlighting the role of these tests in catching bugs.
    * **Summary of Functionality (Part 10 of 24):** Given this is part of a larger suite, summarize the functionalities *covered in this specific excerpt*. It focuses heavily on connection lifecycle, version negotiation, and basic packet processing.

5. **Structure the answer:** Organize the information logically with clear headings and bullet points. Start with the main purpose, then elaborate on specific functionalities. Address the JavaScript relationship, logic examples, user errors, and debugging steps separately. Finally, provide the summary for this specific part.

6. **Refine and Review:**  Ensure the language is clear, concise, and accurate. Check for any potential misunderstandings or ambiguities. Make sure all parts of the prompt have been addressed. For example, initially, I might have missed the emphasis on *this specific excerpt* being part 10/24, leading to an overly broad summary. Reviewing the prompt helps to correct this.
这是位于 `net/third_party/quiche/src/quiche/quic/core/` 目录下的 `quic_connection_test.cc` 文件，它是 Chromium 网络栈中 QUIC 协议核心部分的测试文件。顾名思义，这个文件主要用于测试 `QuicConnection` 类的各种功能和行为。

**主要功能归纳 (基于提供的代码片段):**

这个文件中的测试用例主要关注 `QuicConnection` 对象在处理连接生命周期、版本协商、数据包处理以及错误处理等方面的行为。具体来说，从提供的代码片段来看，它测试了以下功能：

1. **版本协商处理:**
   - 测试客户端接收到服务端发来的包含不支持版本的 `CONNECTION_CLOSE` 帧时的行为 ( `ClientRejectsUnsupportedVersion` )。
   - 测试客户端处理包含无效版本的版本协商包时的行为 (`ClientHandlesVersionNegotiationWithConnectionClose`)，会发送 `CONNECTION_CLOSE` 包。
   - 测试接收到包含自身已使用版本的错误版本协商包时的行为 (`BadVersionNegotiation`)。
   - 测试在可用版本列表中选择合适的协议版本 (`SelectMutualVersion`)。

2. **连接关闭处理:**
   - 测试当接收到的数据包中包含 `CONNECTION_CLOSE` 帧时，连接如何处理后续帧 (`ProcessFramesIfPacketClosedConnection`)。
   - 测试在不同连接状态下（可写、写入被阻塞）关闭连接的行为 (`ConnectionCloseWhenWritable`, `ConnectionCloseGettingWriteBlocked`, `ConnectionCloseWhenWriteBlocked`)。

3. **数据包发送和接收:**
   - 测试在发送数据包时是否会调用调试访问器 (`OnPacketSentDebugVisitor`)。
   - 测试处理数据包头时是否会调用调试访问器 (`OnPacketHeaderDebugVisitor`)。

4. **拥塞控制和 Pacing (基于名称推断):**
   - 尽管代码片段中没有直接体现，但 `Pacing` 测试用例表明该文件也测试了连接的发送速率控制功能。

5. **ACK 处理:**
   - 测试接收到 `WINDOW_UPDATE` 帧后是否会触发 ACK 告警 (`WindowUpdateInstigateAcks`)。
   - 测试接收到 `BLOCKED` 帧后是否会触发 ACK 告警 (`BlockedFrameInstigateAcks`)。
   - 测试接收到 ACK 后重新评估发送时间间隔 (`ReevaluateTimeUntilSendOnAck`)。
   - 测试立即发送 ACK 包的场景 (`SendAcksImmediately`)。

6. **即时发送控制帧:**
   - 测试立即发送 `PING` 帧 (`SendPingImmediately`)。
   - 测试立即发送 `BLOCKED` 帧 (`SendBlockedImmediately`)。
   - 测试发送 `BLOCKED` 帧失败的场景 (`FailedToSendBlockedFrames`)。

7. **加密处理:**
   - 测试尝试发送未加密的流数据会触发错误并关闭连接 (`SendingUnencryptedStreamDataFails`)。
   - 测试为加密数据包设置重传告警 (`SetRetransmissionAlarmForCryptoPacket`)。

8. **路径降级检测:**
   - 测试在非加密数据包传输过程中检测路径降级 (`PathDegradingDetectionForNonCryptoPackets`)。
   - 测试当有可重传数据包在途时设置 Ping 告警 (`RetransmittableOnWireSetsPingAlarm`)。
   - 测试服务端的可重传数据包在途机制 (`ServerRetransmittableOnWire`)。
   - 测试可重传数据包在途机制在发送首个数据包时的行为 (`RetransmittableOnWireSendFirstPacket`)。
   - 测试可重传数据包在途机制发送随机字节的行为 (`RetransmittableOnWireSendRandomBytes`, `RetransmittableOnWireSendRandomBytesWithWriterBlocked`)。
   - 测试当路径被标记为降级时不进行新的路径降级检测 (`NoPathDegradingDetectionIfPathIsDegrading`)。

**与 JavaScript 的关系:**

`quic_connection_test.cc` 文件本身不包含任何 JavaScript 代码。但是，它测试的 `QuicConnection` 类是 Chromium 网络栈实现 QUIC 协议的核心部分。这意味着它直接影响着浏览器中基于 QUIC 协议的网络连接。

**举例说明:**

假设一个使用 Chromium 内核的浏览器尝试连接到一个只支持 QUICv1 的服务器，而浏览器自身配置为优先使用最新的 QUIC 版本。  `ClientHandlesVersionNegotiationWithConnectionClose` 这个测试用例模拟了浏览器接收到服务器发来的版本协商失败的 `CONNECTION_CLOSE` 包的情形。如果这个测试用例通过，就意味着底层的 `QuicConnection` 实现能够正确处理这种情况，浏览器可以优雅地关闭连接或者尝试其他连接方式（例如回退到 HTTP/2）。

**逻辑推理的假设输入与输出:**

**示例：`ClientHandlesVersionNegotiationWithConnectionClose`**

* **假设输入:**
    * `QuicConnection` 对象当前支持一个特定的 QUIC 版本（例如，草案版本）。
    * 接收到一个来自服务器的版本协商包，其中不包含客户端支持的版本，但包含其他所有支持的版本。
* **预期输出:**
    * `QuicConnection` 对象会发送一个 `CONNECTION_CLOSE` 包，指明 `QUIC_INVALID_VERSION` 错误。
    * 连接状态变为断开 (`connected()` 返回 `false`)。
    * `visitor_` 的 `OnConnectionClosed` 方法会被调用。

**用户或编程常见的使用错误:**

1. **网络配置错误:** 用户的网络环境可能阻止 UDP 数据包的传输，或者存在防火墙阻止 QUIC 连接。这可能导致连接建立失败，而相关的测试用例（例如，测试连接建立过程中的错误处理）可以验证 `QuicConnection` 是否能正确处理这些情况。

2. **服务端配置错误:** 服务端可能配置了不支持的 QUIC 版本，或者其版本协商逻辑存在错误。`ClientHandlesVersionNegotiationWithConnectionClose` 和 `BadVersionNegotiation` 这类测试用例可以帮助发现这类问题。

3. **应用程序逻辑错误:** 程序员在使用 QUIC API 时，可能会尝试在连接未完全建立或者加密级别不够的情况下发送数据。 `SendingUnencryptedStreamDataFails` 这个测试用例可以确保 `QuicConnection` 能够阻止这种不正确的操作，并提供相应的错误信息。

**用户操作如何到达这里 (作为调试线索):**

假设用户在浏览器中访问一个只支持特定 QUIC 版本的网站，而用户的浏览器配置不支持该版本。以下步骤可能会导致执行到与版本协商相关的代码：

1. **用户在地址栏输入网址并回车。**
2. **浏览器尝试与服务器建立连接。**
3. **浏览器发送 ClientHello 或初始连接请求，其中包含浏览器支持的 QUIC 版本列表。**
4. **服务器接收到请求，发现没有与浏览器共同支持的 QUIC 版本。**
5. **服务器构造一个版本协商数据包或者直接发送一个包含 `QUIC_INVALID_VERSION` 错误的 `CONNECTION_CLOSE` 帧。**
6. **浏览器接收到服务器的响应。**
7. **`QuicConnection::ProcessUdpPacket` 方法会被调用，处理接收到的数据包。**
8. **如果接收到的是版本协商失败的 `CONNECTION_CLOSE` 帧，则会触发 `ClientHandlesVersionNegotiationWithConnectionClose` 测试用例中模拟的场景。**
9. **如果接收到的是错误的版本协商包，则会触发 `BadVersionNegotiation` 测试用例中模拟的场景。**

调试时，开发者可以通过抓包分析网络数据，查看客户端和服务端之间交互的 QUIC 数据包，特别是版本协商相关的包。还可以设置断点在 `QuicConnection::ProcessUdpPacket` 等关键方法中，观察连接状态和数据包处理流程。

**作为第 10 部分，共 24 部分的功能归纳:**

考虑到这是整个测试套件的第 10 部分，且前面已经涉及了连接建立、加密握手等基础功能的测试，可以推断这部分重点关注 **连接的健壮性和错误处理能力**，特别是针对版本协商和连接关闭这两个关键阶段。它确保了 `QuicConnection` 在面对不兼容的版本或异常关闭时能够正确、安全地处理，并提供相应的错误反馈。此外，也开始涉及一些更深入的功能，例如拥塞控制（通过 `Pacing` 测试推断）和路径探测 (`PathDegradingDetectionForNonCryptoPackets`)。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共24部分，请归纳一下它的功能

"""
ctionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  // Verify no connection close packet gets sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *received);
  EXPECT_FALSE(connection_.connected());
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_INVALID_VERSION));
}

TEST_P(QuicConnectionTest, ClientHandlesVersionNegotiationWithConnectionClose) {
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kINVC);
  config.SetClientConnectionOptions(connection_options);
  connection_.SetFromConfig(config);

  // All supported versions except the one the connection supports.
  ParsedQuicVersionVector versions;
  for (auto version : AllSupportedVersions()) {
    if (version != connection_.version()) {
      versions.push_back(version);
    }
  }

  // Send a version negotiation packet.
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      QuicFramer::BuildVersionNegotiationPacket(
          connection_id_, EmptyQuicConnectionId(), /*ietf_quic=*/true,
          connection_.version().HasLengthPrefixedConnectionIds(), versions));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*encrypted, QuicTime::Zero()));
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  // Verify connection close packet gets sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1u));
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *received);
  EXPECT_FALSE(connection_.connected());
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_INVALID_VERSION));
}

TEST_P(QuicConnectionTest, BadVersionNegotiation) {
  // Send a version negotiation packet with the version the client started with.
  // It should be rejected.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      QuicFramer::BuildVersionNegotiationPacket(
          connection_id_, EmptyQuicConnectionId(), /*ietf_quic=*/true,
          connection_.version().HasLengthPrefixedConnectionIds(),
          AllSupportedVersions()));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*encrypted, QuicTime::Zero()));
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *received);
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_INVALID_VERSION_NEGOTIATION_PACKET));
}

TEST_P(QuicConnectionTest, ProcessFramesIfPacketClosedConnection) {
  // Construct a packet with stream frame and connection close frame.
  QuicPacketHeader header;
  if (peer_framer_.perspective() == Perspective::IS_SERVER) {
    header.source_connection_id = connection_id_;
    header.destination_connection_id_included = CONNECTION_ID_ABSENT;
  } else {
    header.destination_connection_id = connection_id_;
    header.destination_connection_id_included = CONNECTION_ID_ABSENT;
  }
  header.packet_number = QuicPacketNumber(1);
  header.version_flag = false;

  QuicErrorCode kQuicErrorCode = QUIC_PEER_GOING_AWAY;
  // This QuicConnectionCloseFrame will default to being for a Google QUIC
  // close. If doing IETF QUIC then set fields appropriately for CC/T or CC/A,
  // depending on the mapping.
  QuicConnectionCloseFrame qccf(peer_framer_.transport_version(),
                                kQuicErrorCode, NO_IETF_QUIC_ERROR, "",
                                /*transport_close_frame_type=*/0);
  QuicFrames frames;
  frames.push_back(QuicFrame(frame1_));
  frames.push_back(QuicFrame(&qccf));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  EXPECT_TRUE(nullptr != packet);
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = peer_framer_.EncryptPayload(
      ENCRYPTION_FORWARD_SECURE, QuicPacketNumber(1), *packet, buffer,
      kMaxOutgoingPacketSize);

  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_PEER))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_PEER_GOING_AWAY));
}

TEST_P(QuicConnectionTest, SelectMutualVersion) {
  connection_.SetSupportedVersions(AllSupportedVersions());
  // Set the connection to speak the lowest quic version.
  connection_.set_version(QuicVersionMin());
  EXPECT_EQ(QuicVersionMin(), connection_.version());

  // Pass in available versions which includes a higher mutually supported
  // version.  The higher mutually supported version should be selected.
  ParsedQuicVersionVector supported_versions = AllSupportedVersions();
  EXPECT_TRUE(connection_.SelectMutualVersion(supported_versions));
  EXPECT_EQ(QuicVersionMax(), connection_.version());

  // Expect that the lowest version is selected.
  // Ensure the lowest supported version is less than the max, unless they're
  // the same.
  ParsedQuicVersionVector lowest_version_vector;
  lowest_version_vector.push_back(QuicVersionMin());
  EXPECT_TRUE(connection_.SelectMutualVersion(lowest_version_vector));
  EXPECT_EQ(QuicVersionMin(), connection_.version());

  // Shouldn't be able to find a mutually supported version.
  ParsedQuicVersionVector unsupported_version;
  unsupported_version.push_back(UnsupportedQuicVersion());
  EXPECT_FALSE(connection_.SelectMutualVersion(unsupported_version));
}

TEST_P(QuicConnectionTest, ConnectionCloseWhenWritable) {
  EXPECT_FALSE(writer_->IsWriteBlocked());

  // Send a packet.
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  TriggerConnectionClose();
  EXPECT_LE(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, ConnectionCloseGettingWriteBlocked) {
  BlockOnNextWrite();
  TriggerConnectionClose();
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(writer_->IsWriteBlocked());
}

TEST_P(QuicConnectionTest, ConnectionCloseWhenWriteBlocked) {
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(writer_->IsWriteBlocked());
  TriggerConnectionClose();
  EXPECT_EQ(1u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, OnPacketSentDebugVisitor) {
  PathProbeTestInit(Perspective::IS_CLIENT);
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);

  EXPECT_CALL(debug_visitor, OnPacketSent(_, _, _, _, _, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);

  EXPECT_CALL(debug_visitor, OnPacketSent(_, _, _, _, _, _, _, _, _)).Times(1);
  connection_.SendConnectivityProbingPacket(writer_.get(),
                                            connection_.peer_address());
}

TEST_P(QuicConnectionTest, OnPacketHeaderDebugVisitor) {
  QuicPacketHeader header;
  header.packet_number = QuicPacketNumber(1);
  header.form = IETF_QUIC_LONG_HEADER_PACKET;

  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);
  EXPECT_CALL(debug_visitor, OnPacketHeader(Ref(header), _, _)).Times(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_)).Times(1);
  EXPECT_CALL(debug_visitor, OnSuccessfulVersionNegotiation(_)).Times(1);
  connection_.OnPacketHeader(header);
}

TEST_P(QuicConnectionTest, Pacing) {
  TestConnection server(connection_id_, kPeerAddress, kSelfAddress,
                        helper_.get(), alarm_factory_.get(), writer_.get(),
                        Perspective::IS_SERVER, version(),
                        connection_id_generator_);
  TestConnection client(connection_id_, kSelfAddress, kPeerAddress,
                        helper_.get(), alarm_factory_.get(), writer_.get(),
                        Perspective::IS_CLIENT, version(),
                        connection_id_generator_);
  EXPECT_FALSE(QuicSentPacketManagerPeer::UsingPacing(
      static_cast<const QuicSentPacketManager*>(
          &client.sent_packet_manager())));
  EXPECT_FALSE(QuicSentPacketManagerPeer::UsingPacing(
      static_cast<const QuicSentPacketManager*>(
          &server.sent_packet_manager())));
}

TEST_P(QuicConnectionTest, WindowUpdateInstigateAcks) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Send a WINDOW_UPDATE frame.
  QuicWindowUpdateFrame window_update;
  window_update.stream_id = 3;
  window_update.max_data = 1234;
  EXPECT_CALL(visitor_, OnWindowUpdateFrame(_));
  ProcessFramePacket(QuicFrame(window_update));

  // Ensure that this has caused the ACK alarm to be set.
  EXPECT_TRUE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, BlockedFrameInstigateAcks) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Send a BLOCKED frame.
  QuicBlockedFrame blocked;
  blocked.stream_id = 3;
  EXPECT_CALL(visitor_, OnBlockedFrame(_));
  ProcessFramePacket(QuicFrame(blocked));

  // Ensure that this has caused the ACK alarm to be set.
  EXPECT_TRUE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, ReevaluateTimeUntilSendOnAck) {
  // Enable pacing.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);

  // Send two packets.  One packet is not sufficient because if it gets acked,
  // there will be no packets in flight after that and the pacer will always
  // allow the next packet in that situation.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, NO_FIN);
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "bar",
      3, NO_FIN);
  connection_.OnCanWrite();

  // Schedule the next packet for a few milliseconds in future.
  QuicSentPacketManagerPeer::DisablePacerBursts(manager_);
  QuicTime scheduled_pacing_time =
      clock_.Now() + QuicTime::Delta::FromMilliseconds(5);
  QuicSentPacketManagerPeer::SetNextPacedPacketTime(manager_,
                                                    scheduled_pacing_time);

  // Send a packet and have it be blocked by congestion control.
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(false));
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "baz",
      6, NO_FIN);
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());

  // Process an ack and the send alarm will be set to the new 5ms delay.
  QuicAckFrame ack = InitAckFrame(1);
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  ProcessAckPacket(&ack);
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_TRUE(connection_.GetSendAlarm()->IsSet());
  EXPECT_EQ(scheduled_pacing_time, connection_.GetSendAlarm()->deadline());
  writer_->Reset();
}

TEST_P(QuicConnectionTest, SendAcksImmediately) {
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacket(1);
  CongestionBlockWrites();
  SendAckPacketToPeer();
}

TEST_P(QuicConnectionTest, SendPingImmediately) {
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);

  CongestionBlockWrites();
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_CALL(debug_visitor, OnPacketSent(_, _, _, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(debug_visitor, OnPingSent()).Times(1);
  connection_.SendControlFrame(QuicFrame(QuicPingFrame(1)));
  EXPECT_FALSE(connection_.HasQueuedData());
}

TEST_P(QuicConnectionTest, SendBlockedImmediately) {
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);

  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_CALL(debug_visitor, OnPacketSent(_, _, _, _, _, _, _, _, _)).Times(1);
  EXPECT_EQ(0u, connection_.GetStats().blocked_frames_sent);
  connection_.SendControlFrame(QuicFrame(QuicBlockedFrame(1, 3, 0)));
  EXPECT_EQ(1u, connection_.GetStats().blocked_frames_sent);
  EXPECT_FALSE(connection_.HasQueuedData());
}

TEST_P(QuicConnectionTest, FailedToSendBlockedFrames) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);
  QuicBlockedFrame blocked(1, 3, 0);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  EXPECT_CALL(debug_visitor, OnPacketSent(_, _, _, _, _, _, _, _, _)).Times(0);
  EXPECT_EQ(0u, connection_.GetStats().blocked_frames_sent);
  connection_.SendControlFrame(QuicFrame(blocked));
  EXPECT_EQ(0u, connection_.GetStats().blocked_frames_sent);
  EXPECT_FALSE(connection_.HasQueuedData());
}

TEST_P(QuicConnectionTest, SendingUnencryptedStreamDataFails) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(visitor_,
                    OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
            .WillOnce(
                Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
        connection_.SaveAndSendStreamData(3, {}, 0, FIN);
        EXPECT_FALSE(connection_.connected());
        EXPECT_EQ(1, connection_close_frame_count_);
        EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
                    IsError(QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA));
      },
      "Cannot send stream data with level: ENCRYPTION_INITIAL");
}

TEST_P(QuicConnectionTest, SetRetransmissionAlarmForCryptoPacket) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendCryptoStreamData();

  // Verify retransmission timer is correctly set after crypto packet has been
  // sent.
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  QuicTime retransmission_time =
      QuicConnectionPeer::GetSentPacketManager(&connection_)
          ->GetRetransmissionTime();
  EXPECT_NE(retransmission_time, clock_.ApproximateNow());
  EXPECT_EQ(retransmission_time,
            connection_.GetRetransmissionAlarm()->deadline());

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.GetRetransmissionAlarm()->Fire();
}

// Includes regression test for b/69979024.
TEST_P(QuicConnectionTest, PathDegradingDetectionForNonCryptoPackets) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  const char data[] = "data";
  size_t data_size = strlen(data);
  QuicStreamOffset offset = 0;

  for (int i = 0; i < 2; ++i) {
    // Send a packet. Now there's a retransmittable packet on the wire, so the
    // path degrading detection should be set.
    connection_.SendStreamDataWithString(
        GetNthClientInitiatedStreamId(1, connection_.transport_version()), data,
        offset, NO_FIN);
    offset += data_size;
    EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
    // Check the deadline of the path degrading detection.
    QuicTime::Delta delay =
        QuicConnectionPeer::GetSentPacketManager(&connection_)
            ->GetPathDegradingDelay();
    EXPECT_EQ(delay, connection_.GetBlackholeDetectorAlarm()->deadline() -
                         clock_.ApproximateNow());

    // Send a second packet. The path degrading detection's deadline should
    // remain the same.
    // Regression test for b/69979024.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    QuicTime prev_deadline =
        connection_.GetBlackholeDetectorAlarm()->deadline();
    connection_.SendStreamDataWithString(
        GetNthClientInitiatedStreamId(1, connection_.transport_version()), data,
        offset, NO_FIN);
    offset += data_size;
    EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
    EXPECT_EQ(prev_deadline,
              connection_.GetBlackholeDetectorAlarm()->deadline());

    // Now receive an ACK of the first packet. This should advance the path
    // degrading detection's deadline since forward progress has been made.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    if (i == 0) {
      EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
    }
    EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
    QuicAckFrame frame = InitAckFrame(
        {{QuicPacketNumber(1u + 2u * i), QuicPacketNumber(2u + 2u * i)}});
    ProcessAckPacket(&frame);
    EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
    // Check the deadline of the path degrading detection.
    delay = QuicConnectionPeer::GetSentPacketManager(&connection_)
                ->GetPathDegradingDelay();
    EXPECT_EQ(delay, connection_.GetBlackholeDetectorAlarm()->deadline() -
                         clock_.ApproximateNow());

    if (i == 0) {
      // Now receive an ACK of the second packet. Since there are no more
      // retransmittable packets on the wire, this should cancel the path
      // degrading detection.
      clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
      EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
      frame = InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)}});
      ProcessAckPacket(&frame);
      EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
    } else {
      // Advance time to the path degrading alarm's deadline and simulate
      // firing the alarm.
      clock_.AdvanceTime(delay);
      EXPECT_CALL(visitor_, OnPathDegrading());
      connection_.PathDegradingTimeout();
      EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
    }
  }
  EXPECT_TRUE(connection_.IsPathDegrading());
}

TEST_P(QuicConnectionTest, RetransmittableOnWireSetsPingAlarm) {
  const QuicTime::Delta retransmittable_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(50);
  connection_.set_initial_retransmittable_on_wire_timeout(
      retransmittable_on_wire_timeout);

  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  connection_.OnHandshakeComplete();

  const char data[] = "data";
  size_t data_size = strlen(data);
  QuicStreamOffset offset = 0;

  // Send a packet.
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  // Now there's a retransmittable packet on the wire, so the path degrading
  // alarm should be set.
  // The retransmittable-on-wire alarm should not be set.
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
  QuicTime::Delta delay = QuicConnectionPeer::GetSentPacketManager(&connection_)
                              ->GetPathDegradingDelay();
  EXPECT_EQ(delay, connection_.GetBlackholeDetectorAlarm()->deadline() -
                       clock_.ApproximateNow());
  ASSERT_TRUE(connection_.sent_packet_manager().HasInFlightPackets());
  // The ping alarm is set for the ping timeout, not the shorter
  // retransmittable_on_wire_timeout.
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  QuicTime::Delta ping_delay = QuicTime::Delta::FromSeconds(kPingTimeoutSecs);
  EXPECT_EQ(ping_delay,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Now receive an ACK of the packet.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
  ProcessAckPacket(&frame);
  // No more retransmittable packets on the wire, so the path degrading alarm
  // should be cancelled, and the ping alarm should be set to the
  // retransmittable_on_wire_timeout.
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(retransmittable_on_wire_timeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  // Simulate firing the ping alarm and sending a PING.
  clock_.AdvanceTime(retransmittable_on_wire_timeout);
  connection_.GetPingAlarm()->Fire();

  // Now there's a retransmittable packet (PING) on the wire, so the path
  // degrading alarm should be set.
  ASSERT_TRUE(connection_.PathDegradingDetectionInProgress());
  delay = QuicConnectionPeer::GetSentPacketManager(&connection_)
              ->GetPathDegradingDelay();
  EXPECT_EQ(delay, connection_.GetBlackholeDetectorAlarm()->deadline() -
                       clock_.ApproximateNow());
}

TEST_P(QuicConnectionTest, ServerRetransmittableOnWire) {
  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
  SetQuicReloadableFlag(quic_enable_server_on_wire_ping, true);

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kSRWP);
  config.SetInitialReceivedConnectionOptions(connection_options);
  connection_.SetFromConfig(config);

  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

  ProcessPacket(1);

  ASSERT_TRUE(connection_.GetPingAlarm()->IsSet());
  QuicTime::Delta ping_delay = QuicTime::Delta::FromMilliseconds(200);
  EXPECT_EQ(ping_delay,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  connection_.SendStreamDataWithString(2, "foo", 0, NO_FIN);
  // Verify PING alarm gets cancelled.
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());

  // Now receive an ACK of the packet.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
  ProcessAckPacket(2, &frame);
  // Verify PING alarm gets scheduled.
  ASSERT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(ping_delay,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
}

TEST_P(QuicConnectionTest, RetransmittableOnWireSendFirstPacket) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  const QuicTime::Delta kRetransmittableOnWireTimeout =
      QuicTime::Delta::FromMilliseconds(200);
  const QuicTime::Delta kTestRtt = QuicTime::Delta::FromMilliseconds(100);

  connection_.set_initial_retransmittable_on_wire_timeout(
      kRetransmittableOnWireTimeout);

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kROWF);
  config.SetClientConnectionOptions(connection_options);
  connection_.SetFromConfig(config);

  // Send a request.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  // Receive an ACK after 1-RTT.
  clock_.AdvanceTime(kTestRtt);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
  ProcessAckPacket(&frame);
  ASSERT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(kRetransmittableOnWireTimeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  // Fire retransmittable-on-wire alarm.
  clock_.AdvanceTime(kRetransmittableOnWireTimeout);
  connection_.GetPingAlarm()->Fire();
  EXPECT_EQ(2u, writer_->packets_write_attempts());
  // Verify alarm is set in keep-alive mode.
  ASSERT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
}

TEST_P(QuicConnectionTest, RetransmittableOnWireSendRandomBytes) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  const QuicTime::Delta kRetransmittableOnWireTimeout =
      QuicTime::Delta::FromMilliseconds(200);
  const QuicTime::Delta kTestRtt = QuicTime::Delta::FromMilliseconds(100);

  connection_.set_initial_retransmittable_on_wire_timeout(
      kRetransmittableOnWireTimeout);

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kROWR);
  config.SetClientConnectionOptions(connection_options);
  connection_.SetFromConfig(config);

  // Send a request.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  // Receive an ACK after 1-RTT.
  clock_.AdvanceTime(kTestRtt);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
  ProcessAckPacket(&frame);
  ASSERT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(kRetransmittableOnWireTimeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  // Fire retransmittable-on-wire alarm.
  clock_.AdvanceTime(kRetransmittableOnWireTimeout);
  // Next packet is not processable by the framer in the test writer.
  ExpectNextPacketUnprocessable();
  connection_.GetPingAlarm()->Fire();
  EXPECT_EQ(2u, writer_->packets_write_attempts());
  // Verify alarm is set in keep-alive mode.
  ASSERT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
}

TEST_P(QuicConnectionTest,
       RetransmittableOnWireSendRandomBytesWithWriterBlocked) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);

  const QuicTime::Delta kRetransmittableOnWireTimeout =
      QuicTime::Delta::FromMilliseconds(200);
  const QuicTime::Delta kTestRtt = QuicTime::Delta::FromMilliseconds(100);

  connection_.set_initial_retransmittable_on_wire_timeout(
      kRetransmittableOnWireTimeout);

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kROWR);
  config.SetClientConnectionOptions(connection_options);
  connection_.SetFromConfig(config);

  // Send a request.
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  // Receive an ACK after 1-RTT.
  clock_.AdvanceTime(kTestRtt);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame frame =
      InitAckFrame({{QuicPacketNumber(1), QuicPacketNumber(2)}});
  ProcessAckPacket(&frame);
  ASSERT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(kRetransmittableOnWireTimeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  // Receive an out of order data packet and block the ACK packet.
  BlockOnNextWrite();
  ProcessDataPacket(3);
  EXPECT_EQ(2u, writer_->packets_write_attempts());
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Fire retransmittable-on-wire alarm.
  clock_.AdvanceTime(kRetransmittableOnWireTimeout);
  connection_.GetPingAlarm()->Fire();
  // Verify the random bytes packet gets queued.
  EXPECT_EQ(2u, connection_.NumQueuedPackets());
}

// This test verifies that the connection marks path as degrading and does not
// spin timer to detect path degrading when a new packet is sent on the
// degraded path.
TEST_P(QuicConnectionTest, NoPathDegradingDetectionIfPathIsDegrading) {
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
  // Check the deadline of the path degrading detection.
  QuicTime::Delta delay = QuicConnectionPeer::GetSentPacketManager(&connection_)
                              ->GetPathDegradingDelay();
  EXPECT_EQ(delay, connection_.GetBlackholeDetectorAlarm()->deadline() -
                       clock_.ApproximateNow());

  // Send a second packet. The path degrading detection's deadline should remain
  // the same.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  QuicTime prev_deadline = connection_.GetBlackholeDetectorAlarm()->deadline();
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
  EXPECT_EQ(prev_deadline, connection_.GetBlackholeDetectorAlarm()->deadline());

  // Now receive an ACK of the first packet. This should advance the path
  // degrading detection's deadline since forward progress has been made.
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

  // Advance time to the path degrading detection's deadline and simulate
  // firing the path degrading detection. This path will be considered as
  // degrading.
  clock_.AdvanceTime(delay);
  EXPECT_CALL(visitor_, OnPathDegrading()).Times(1);
  connection_.PathDegradingTimeout();
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());
  EXPECT_TRUE(connection_.IsPathDegrading());

  clock_.AdvanceTime(QuicTime::Delta::FromMillisecon
"""


```