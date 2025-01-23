Response:
The user wants a summary of the functionalities of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`. I need to analyze the provided code snippet and identify its main purposes. Specifically, I need to:

1. **List the functionalities** demonstrated by the test cases in the code.
2. **Explain the relationship with JavaScript**, if any. This is likely to be minimal as it's a low-level networking component.
3. **Provide examples of logical reasoning** with hypothetical inputs and outputs. This involves understanding the control flow of the tests.
4. **Illustrate common usage errors** related to the tested functionalities.
5. **Describe the user actions** that could lead to this code being executed during debugging.
6. **Summarize the overall function** of the file, considering it's the last part of a larger set of tests.

Based on the code, it seems to focus on testing various aspects of the `QuicConnection` class, particularly related to:

- **Explicit Congestion Notification (ECN):** Testing how the connection handles different ECN codepoints, including enabling, disabling, and handling feedback.
- **Connection Migration:**  Testing scenarios where the client or server changes IP addresses and ports.
- **Preferred Addresses:** Testing how the connection handles server-preferred addresses.
- **Connection ID Management:** Testing the issuance and retirement of connection IDs.
- **Packet Processing:** Testing the handling of received packets, including those with specific ECN markings.
- **Retransmission Timeouts (RTOs):**  Testing how RTOs interact with ECN.
- **Reliable Stream Resets:** Testing the handling of `RESET_STREAM_AT` frames.
- **Client Hello Information:** Testing the handling of parsed client hello information.

It's important to note that this is a *test* file, so its primary function is to *verify* the behavior of the `QuicConnection` class under various conditions.
This C++ source code file, `quic_connection_test.cc`, belonging to the Chromium network stack's QUIC implementation, is a **unit test suite** for the `QuicConnection` class. Being the 24th and final part of the test suite suggests it covers a variety of less central or more complex scenarios not covered in earlier parts.

Here's a breakdown of its functionalities:

**Core Functionalities Tested:**

* **Explicit Congestion Notification (ECN) Handling:**
    * Verifies the connection's ability to set and respect ECN codepoints (ECT0, ECT1, CE) on outgoing packets.
    * Tests how the connection reacts to receiving packets with different ECN markings.
    * Checks if ECN settings are correctly applied during retransmissions (RTO).
    * Investigates the behavior when invalid ECN feedback is received.
    * Examines how ECN interacts with coalesced packets and buffered packets.
    * Ensures ECN marking is disabled if the underlying packet writer doesn't support it.
* **Connection Migration:**
    * Tests scenarios where a server migrates to a preferred address.
    * Evaluates the connection's ability to detect simultaneous address changes from both the client and server.
    * Verifies the handling of probing packets during migration.
* **Connection ID Management:**
    * Checks the process of issuing new connection IDs, particularly in the context of preferred addresses.
    * Tests the handling of `RETIRE_CONNECTION_ID` frames.
* **Packet Processing and Buffering:**
    * Examines how the connection buffers packets when a required decryption key is not yet available.
    * Tests the processing of coalesced packets (multiple QUIC packets within a single UDP datagram).
* **Error Handling and Control Frames:**
    * Tests the handling of `RESET_STREAM_AT` frames, which signal the sender's intent to reset a stream at a specific offset.
* **Client Hello Information:**
    * Checks how the connection handles parsed client hello information, specifically when a debug visitor is present.
* **Packet Information Tracking:**
    * Verifies that the `ReceivedPacketInfo` structure correctly defaults its values.

**Relationship with JavaScript:**

This C++ file has **no direct runtime relationship with JavaScript**. QUIC is a transport layer protocol implemented at a lower level than where JavaScript typically operates in a web browser or Node.js environment.

However, indirectly, this code is crucial for the performance and reliability of network communication that JavaScript-based web applications rely on. When a user interacts with a website that uses QUIC (like many Google services or websites using Chromium-based browsers), the underlying QUIC implementation, which this code tests, ensures the data is transferred efficiently and reliably.

**Examples of Logical Reasoning (Hypothetical Input and Output):**

**Scenario: Testing ECN-CE marking on a received packet.**

* **Hypothetical Input:**
    * The `QuicConnection` is in a state where it has negotiated ECN support.
    * A UDP packet is received with the ECN codepoint set to `ECN_CE`.
    * This packet contains data for the handshake.
* **Logical Steps:**
    * The `ProcessUdpPacket` function in `QuicConnection` will be called.
    * The connection will decrypt the packet.
    * The connection will update its internal ECN counters, specifically incrementing the `ce` counter for the handshake packet number space.
    * When an ACK frame is generated for the handshake, it will include the updated ECN counters.
* **Expected Output:**
    * The `GetAckFrame(HANDSHAKE_DATA)` call will return an `QuicAckFrame` where `ack_frame.ecn_counters.has_value()` is true, and `ack_frame.ecn_counters->ce` is 1 (assuming this is the first CE marked packet received for the handshake).

**Common Usage Errors and Debugging Clues:**

* **Forgetting to enable ECN in the configuration:** If a developer intends to use ECN but doesn't configure the `QuicConfig` to support it, the connection won't mark outgoing packets, and received ECN markings might be ignored or handled incorrectly. Debugging clue: Check the connection's configuration settings related to ECN.
* **Incorrectly setting ECN codepoints manually:**  The code shows how the connection manages setting ECN codepoints. A programmer attempting to manually manipulate these flags might lead to unexpected behavior. Debugging clue: Inspect the values of ECN-related flags and variables within the `QuicConnection` object.
* **Misunderstanding connection migration behavior:** Developers might assume immediate migration upon receiving a packet from a new address. This test suite clarifies that there are validation steps involved. Debugging clue: Examine the connection's state related to path validation and alternative paths.
* **Not handling `RESET_STREAM_AT` frames correctly:**  An application might expect data up to a certain point on a stream, but if a `RESET_STREAM_AT` frame is received, it needs to adjust its expectations. Debugging clue: Check for received `RESET_STREAM_AT` frames and the associated stream ID and offset.

**User Operations Leading to This Code (Debugging Perspective):**

Imagine a developer is debugging a QUIC connection issue in a Chromium-based browser or a server application using the QUIC library. The following steps could lead them to investigate this specific test file:

1. **Encountering a bug related to ECN:**  Perhaps users are reporting performance issues on networks with known congestion, and the developer suspects ECN isn't working correctly. They might start by looking at ECN-related code and tests.
2. **Investigating connection migration problems:** Users might experience connection drops or instability when their network changes (e.g., switching from Wi-Fi to cellular). The developer would then investigate connection migration logic and its corresponding tests.
3. **Debugging issues with preferred addresses:** If a server is configured with a preferred address, but clients are not connecting to it as expected, the developer would examine the code related to preferred address handling and these tests.
4. **Troubleshooting stream reset behavior:** If applications are behaving incorrectly after a stream reset, the developer might look at the `RESET_STREAM_AT` frame handling logic and its tests.
5. **Examining crashes or unexpected behavior during handshake:** Issues during the initial connection setup might lead a developer to investigate how client hello information is processed, making them look at related tests.

By stepping through the code in `quic_connection_test.cc` with a debugger and comparing the actual behavior of the `QuicConnection` with the expected behavior defined in these tests, the developer can pinpoint the source of the bug.

**Summary of the File's Function (as Part 24/24):**

As the final part of the `QuicConnection` test suite, this file likely focuses on **edge cases, less common scenarios, and more complex interactions** within the `QuicConnection` class. It ties up loose ends by testing features like ECN in various contexts, intricate connection migration scenarios, and specific control frame handling that might not have been thoroughly covered in earlier parts of the test suite. Its purpose is to provide comprehensive coverage and ensure the robustness of the `QuicConnection` implementation under a wide range of conditions.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第24部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
d_size, buffer, encrypted_length);
    coalesced_size += encrypted_length;
  }
  QuicAckFrame ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(APPLICATION_DATA)
          : connection_.received_packet_manager().ack_frame();
  EXPECT_FALSE(ack_frame.ecn_counters.has_value());
  ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(HANDSHAKE_DATA)
          : connection_.received_packet_manager().ack_frame();
  EXPECT_FALSE(ack_frame.ecn_counters.has_value());
  // Deliver packets, but first remove the Forward Secure decrypter so that
  // packet has to be buffered.
  connection_.RemoveDecrypter(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(coalesced_buffer, coalesced_size, clock_.Now(), false,
                         0, true, nullptr, 0, true, ECN_ECT0));
  if (connection_.GetSendAlarm()->IsSet()) {
    connection_.GetSendAlarm()->Fire();
  }
  ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(HANDSHAKE_DATA)
          : connection_.received_packet_manager().ack_frame();
  ASSERT_TRUE(ack_frame.ecn_counters.has_value());
  EXPECT_EQ(ack_frame.ecn_counters->ect0, 1);
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    ack_frame = connection_.SupportsMultiplePacketNumberSpaces()
                    ? connection_.received_packet_manager().GetAckFrame(
                          APPLICATION_DATA)
                    : connection_.received_packet_manager().ack_frame();
    EXPECT_FALSE(ack_frame.ecn_counters.has_value());
  }
  // Send PING packet with ECN_CE, which will change the ECN codepoint in
  // last_received_packet_info_.
  ProcessFramePacketAtLevelWithEcn(4, QuicFrame(QuicPingFrame()),
                                   ENCRYPTION_HANDSHAKE, ECN_CE);
  ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(HANDSHAKE_DATA)
          : connection_.received_packet_manager().ack_frame();
  ASSERT_TRUE(ack_frame.ecn_counters.has_value());
  EXPECT_EQ(ack_frame.ecn_counters->ect0, 1);
  EXPECT_EQ(ack_frame.ecn_counters->ce, 1);
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    ack_frame = connection_.SupportsMultiplePacketNumberSpaces()
                    ? connection_.received_packet_manager().GetAckFrame(
                          APPLICATION_DATA)
                    : connection_.received_packet_manager().ack_frame();
    EXPECT_FALSE(ack_frame.ecn_counters.has_value());
  }
  // Install decrypter for ENCRYPTION_FORWARD_SECURE. Make sure the original
  // ECN codepoint is incremented.
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  SetDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  connection_.GetProcessUndecryptablePacketsAlarm()->Fire();
  ack_frame =
      connection_.SupportsMultiplePacketNumberSpaces()
          ? connection_.received_packet_manager().GetAckFrame(APPLICATION_DATA)
          : connection_.received_packet_manager().ack_frame();
  ASSERT_TRUE(ack_frame.ecn_counters.has_value());
  // Should be recorded as ECT(0), not CE.
  EXPECT_EQ(ack_frame.ecn_counters->ect0,
            connection_.SupportsMultiplePacketNumberSpaces() ? 1 : 2);
  QuicConnectionStats stats = connection_.GetStats();
  EXPECT_EQ(stats.num_ecn_marks_received.ect0, 2);
  EXPECT_EQ(stats.num_ecn_marks_received.ect1, 0);
  EXPECT_EQ(stats.num_ecn_marks_received.ce, 1);
}

TEST_P(QuicConnectionTest, ReceivedPacketInfoDefaults) {
  EXPECT_TRUE(QuicConnectionPeer::TestLastReceivedPacketInfoDefaults());
}

TEST_P(QuicConnectionTest, DetectMigrationToPreferredAddress) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  ServerHandlePreferredAddressInit();

  // Issue a new server CID associated with the preferred address.
  QuicConnectionId server_issued_cid_for_preferred_address =
      TestConnectionId(17);
  EXPECT_CALL(connection_id_generator_,
              GenerateNextConnectionId(connection_id_))
      .WillOnce(Return(server_issued_cid_for_preferred_address));
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_)).WillOnce(Return(true));
  std::optional<QuicNewConnectionIdFrame> frame =
      connection_.MaybeIssueNewConnectionIdForPreferredAddress();
  ASSERT_TRUE(frame.has_value());

  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(),
            connection_.client_connection_id());
  ASSERT_EQ(packet_creator->GetSourceConnectionId(), connection_id_);

  // Process a packet received at the preferred Address.
  peer_creator_.SetServerConnectionId(server_issued_cid_for_preferred_address);
  EXPECT_CALL(visitor_, OnCryptoFrame(_));
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kServerPreferredAddress,
                                  kPeerAddress, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  // The server migrates half-way with the default path unchanged, and
  // continuing with the client issued CID 1.
  EXPECT_EQ(kSelfAddress.host(), writer_->last_write_source_address());
  EXPECT_EQ(kSelfAddress, connection_.self_address());

  // The peer retires CID 123.
  QuicRetireConnectionIdFrame retire_cid_frame;
  retire_cid_frame.sequence_number = 0u;
  EXPECT_CALL(connection_id_generator_,
              GenerateNextConnectionId(server_issued_cid_for_preferred_address))
      .WillOnce(Return(TestConnectionId(456)));
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_)).WillOnce(Return(true));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  EXPECT_TRUE(connection_.OnRetireConnectionIdFrame(retire_cid_frame));

  // Process another packet received at Preferred Address.
  EXPECT_CALL(visitor_, OnCryptoFrame(_));
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kServerPreferredAddress,
                                  kPeerAddress, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kSelfAddress.host(), writer_->last_write_source_address());
  EXPECT_EQ(kSelfAddress, connection_.self_address());
}

TEST_P(QuicConnectionTest,
       DetectSimutanuousServerAndClientAddressChangeWithProbe) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  ServerHandlePreferredAddressInit();

  // Issue a new server CID associated with the preferred address.
  QuicConnectionId server_issued_cid_for_preferred_address =
      TestConnectionId(17);
  EXPECT_CALL(connection_id_generator_,
              GenerateNextConnectionId(connection_id_))
      .WillOnce(Return(server_issued_cid_for_preferred_address));
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_)).WillOnce(Return(true));
  std::optional<QuicNewConnectionIdFrame> frame =
      connection_.MaybeIssueNewConnectionIdForPreferredAddress();
  ASSERT_TRUE(frame.has_value());

  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  ASSERT_EQ(packet_creator->GetSourceConnectionId(), connection_id_);
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(),
            connection_.client_connection_id());

  // Receiving a probing packet from a new client address to the preferred
  // address.
  peer_creator_.SetServerConnectionId(server_issued_cid_for_preferred_address);
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/34567);
  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  uint64_t num_probing_received =
      connection_.GetStats().num_connectivity_probing_received;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, writer_->path_response_frames().size());
        EXPECT_EQ(1u, writer_->path_challenge_frames().size());
        // The responses should be sent from preferred address given server
        // has not received packet on original address from the new client
        // address.
        EXPECT_EQ(kServerPreferredAddress.host(),
                  writer_->last_write_source_address());
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
      }))
      .WillRepeatedly(DoDefault());
  ProcessReceivedPacket(kServerPreferredAddress, kNewPeerAddress, *received);
  EXPECT_EQ(num_probing_received + 1,
            connection_.GetStats().num_connectivity_probing_received);
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(&connection_, kSelfAddress,
                                                    kNewPeerAddress));
  EXPECT_LT(0u, QuicConnectionPeer::BytesSentOnAlternativePath(&connection_));
  EXPECT_EQ(received->length(),
            QuicConnectionPeer::BytesReceivedOnAlternativePath(&connection_));
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kSelfAddress, connection_.self_address());

  // Process a data packet received at the preferred Address from the new client
  // address.
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE));
  EXPECT_CALL(visitor_, OnCryptoFrame(_));
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kServerPreferredAddress,
                                  kNewPeerAddress, ENCRYPTION_FORWARD_SECURE);
  // The server migrates half-way with the new peer address but the same default
  // self address.
  EXPECT_EQ(kSelfAddress.host(), writer_->last_write_source_address());
  EXPECT_EQ(kSelfAddress, connection_.self_address());
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  EXPECT_FALSE(QuicConnectionPeer::GetDefaultPath(&connection_)->validated);
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePath(&connection_, kSelfAddress,
                                                    kPeerAddress));
  EXPECT_EQ(packet_creator->GetSourceConnectionId(),
            server_issued_cid_for_preferred_address);

  // Process another packet received at the preferred Address.
  EXPECT_CALL(visitor_, OnCryptoFrame(_));
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kServerPreferredAddress,
                                  kNewPeerAddress, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_EQ(kServerPreferredAddress.host(),
            writer_->last_write_source_address());
  EXPECT_EQ(kSelfAddress, connection_.self_address());
}

TEST_P(QuicConnectionTest, EcnCodepointsRejected) {
  SetQuicRestartFlag(quic_support_ect1, true);
  for (QuicEcnCodepoint ecn : {ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE}) {
    if (ecn == ECN_ECT0) {
      EXPECT_CALL(*send_algorithm_, EnableECT0()).WillOnce(Return(false));
    } else if (ecn == ECN_ECT1) {
      EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(false));
    }
    if (ecn == ECN_NOT_ECT) {
      EXPECT_TRUE(connection_.set_ecn_codepoint(ecn));
    } else {
      EXPECT_FALSE(connection_.set_ecn_codepoint(ecn));
    }
    EXPECT_EQ(connection_.ecn_codepoint(), ECN_NOT_ECT);
    EXPECT_CALL(connection_, OnSerializedPacket(_));
    SendPing();
    EXPECT_EQ(writer_->last_ecn_sent(), ECN_NOT_ECT);
  }
}

TEST_P(QuicConnectionTest, EcnCodepointsAccepted) {
  SetQuicRestartFlag(quic_support_ect1, true);
  for (QuicEcnCodepoint ecn : {ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE}) {
    if (ecn == ECN_ECT0) {
      EXPECT_CALL(*send_algorithm_, EnableECT0()).WillOnce(Return(true));
    } else if (ecn == ECN_ECT1) {
      EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(true));
    }
    if (ecn == ECN_CE) {
      EXPECT_FALSE(connection_.set_ecn_codepoint(ecn));
    } else {
      EXPECT_TRUE(connection_.set_ecn_codepoint(ecn));
    }
    EXPECT_CALL(connection_, OnSerializedPacket(_));
    SendPing();
    QuicEcnCodepoint expected_codepoint = ecn;
    if (ecn == ECN_CE) {
      expected_codepoint = ECN_ECT1;
    }
    EXPECT_EQ(connection_.ecn_codepoint(), expected_codepoint);
    EXPECT_EQ(writer_->last_ecn_sent(), expected_codepoint);
  }
}

TEST_P(QuicConnectionTest, EcnCodepointsRejectedIfFlagIsFalse) {
  SetQuicRestartFlag(quic_support_ect1, false);
  for (QuicEcnCodepoint ecn : {ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE}) {
    EXPECT_FALSE(connection_.set_ecn_codepoint(ecn));
    EXPECT_CALL(connection_, OnSerializedPacket(_));
    SendPing();
    EXPECT_EQ(connection_.ecn_codepoint(), ECN_NOT_ECT);
    EXPECT_EQ(writer_->last_ecn_sent(), ECN_NOT_ECT);
  }
}

TEST_P(QuicConnectionTest, EcnValidationDisabled) {
  SetQuicRestartFlag(quic_support_ect1, true);
  QuicConnectionPeer::DisableEcnCodepointValidation(&connection_);
  for (QuicEcnCodepoint ecn : {ECN_NOT_ECT, ECN_ECT0, ECN_ECT1, ECN_CE}) {
    EXPECT_TRUE(connection_.set_ecn_codepoint(ecn));
    EXPECT_CALL(connection_, OnSerializedPacket(_));
    SendPing();
    EXPECT_EQ(connection_.ecn_codepoint(), ecn);
    EXPECT_EQ(writer_->last_ecn_sent(), ecn);
  }
}

TEST_P(QuicConnectionTest, RtoDisablesEcnMarking) {
  SetQuicRestartFlag(quic_support_ect1, true);
  EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(true));
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT1));
  QuicPacketCreatorPeer::SetPacketNumber(
      QuicConnectionPeer::GetPacketCreator(&connection_), 1);
  SendPing();
  connection_.OnRetransmissionAlarm();
  EXPECT_EQ(writer_->last_ecn_sent(), ECN_NOT_ECT);
  EXPECT_EQ(connection_.ecn_codepoint(), ECN_ECT1);
  // On 2nd RTO, QUIC abandons ECN.
  connection_.OnRetransmissionAlarm();
  EXPECT_EQ(writer_->last_ecn_sent(), ECN_NOT_ECT);
  EXPECT_EQ(connection_.ecn_codepoint(), ECN_NOT_ECT);
}

TEST_P(QuicConnectionTest, RtoDoesntDisableEcnMarkingIfEcnAcked) {
  SetQuicRestartFlag(quic_support_ect1, true);
  EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(true));
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT1));
  QuicPacketCreatorPeer::SetPacketNumber(
      QuicConnectionPeer::GetPacketCreator(&connection_), 1);
  connection_.OnInFlightEcnPacketAcked();
  SendPing();
  // Because an ECN packet was acked, PTOs have no effect on ECN settings.
  connection_.OnRetransmissionAlarm();
  QuicEcnCodepoint expected_codepoint = ECN_ECT1;
  EXPECT_EQ(writer_->last_ecn_sent(), expected_codepoint);
  EXPECT_EQ(connection_.ecn_codepoint(), expected_codepoint);
  connection_.OnRetransmissionAlarm();
  EXPECT_EQ(writer_->last_ecn_sent(), expected_codepoint);
  EXPECT_EQ(connection_.ecn_codepoint(), expected_codepoint);
}

TEST_P(QuicConnectionTest, InvalidFeedbackCancelsEcn) {
  SetQuicRestartFlag(quic_support_ect1, true);
  EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(true));
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT1));
  EXPECT_EQ(connection_.ecn_codepoint(), ECN_ECT1);
  connection_.OnInvalidEcnFeedback();
  EXPECT_EQ(connection_.ecn_codepoint(), ECN_NOT_ECT);
}

TEST_P(QuicConnectionTest, StateMatchesSentEcn) {
  SetQuicRestartFlag(quic_support_ect1, true);
  EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(true));
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT1));
  SendPing();
  QuicSentPacketManager* sent_packet_manager =
      QuicConnectionPeer::GetSentPacketManager(&connection_);
  EXPECT_EQ(writer_->last_ecn_sent(), ECN_ECT1);
  EXPECT_EQ(
      QuicSentPacketManagerPeer::GetEct1Sent(sent_packet_manager, INITIAL_DATA),
      1);
}

TEST_P(QuicConnectionTest, CoalescedPacketSplitsEcn) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  SetQuicRestartFlag(quic_support_ect1, true);
  EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(true));
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT1));
  // All these steps are necessary to send an INITIAL ping and save it to be
  // coalesced, instead of just calling SendPing() and sending it immediately.
  char buffer[1000];
  creator_->set_encryption_level(ENCRYPTION_INITIAL);
  QuicFrames frames;
  QuicPingFrame ping;
  frames.emplace_back(QuicFrame(ping));
  SerializedPacket packet1 = QuicPacketCreatorPeer::SerializeAllFrames(
      creator_, frames, buffer, sizeof(buffer));
  connection_.SendOrQueuePacket(std::move(packet1));
  creator_->set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(*send_algorithm_, EnableECT0()).WillOnce(Return(true));
  // If not for the line below, these packets would coalesce.
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT0));
  EXPECT_EQ(writer_->packets_write_attempts(), 0);
  SendPing();
  EXPECT_EQ(writer_->packets_write_attempts(), 2);
  EXPECT_EQ(writer_->last_ecn_sent(), ECN_ECT0);
}

TEST_P(QuicConnectionTest, BufferedPacketRetainsOldEcn) {
  SetQuicRestartFlag(quic_support_ect1, true);
  EXPECT_CALL(*send_algorithm_, EnableECT1()).WillOnce(Return(true));
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT1));
  writer_->SetWriteBlocked();
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(2);
  SendPing();
  EXPECT_CALL(*send_algorithm_, EnableECT0()).WillOnce(Return(true));
  EXPECT_TRUE(connection_.set_ecn_codepoint(ECN_ECT0));
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(writer_->last_ecn_sent(), ECN_ECT1);
}

TEST_P(QuicConnectionTest, RejectEcnIfWriterDoesNotSupport) {
  SetQuicRestartFlag(quic_support_ect1, true);
  MockPacketWriter mock_writer;
  QuicConnectionPeer::SetWriter(&connection_, &mock_writer, false);
  EXPECT_CALL(mock_writer, SupportsEcn()).WillOnce(Return(false));
  EXPECT_FALSE(connection_.set_ecn_codepoint(ECN_ECT1));
  EXPECT_EQ(connection_.ecn_codepoint(), ECN_NOT_ECT);
}

TEST_P(QuicConnectionTest, RejectResetStreamAtIfNotNegotiated) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.SetReliableStreamReset(false);
  connection_.SetFromConfig(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(1);
  connection_.OnResetStreamAtFrame(QuicResetStreamAtFrame());
}

TEST_P(QuicConnectionTest, ResetStreamAt) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.SetReliableStreamReset(true);
  connection_.SetFromConfig(config);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  EXPECT_CALL(visitor_, OnResetStreamAt(QuicResetStreamAtFrame(
                            0, 0, QUIC_STREAM_NO_ERROR, 20, 10)))
      .Times(1);
  connection_.OnResetStreamAtFrame(QuicResetStreamAtFrame(0, 0, 0, 20, 10));
}

TEST_P(QuicConnectionTest, OnParsedClientHelloInfoWithDebugVisitor) {
  const ParsedClientHello parsed_chlo{.sni = "sni",
                                      .uaid = "uiad",
                                      .supported_groups = {1, 2, 3},
                                      .cert_compression_algos = {4, 5, 6},
                                      .alpns = {"h2", "http/1.1"},
                                      .retry_token = "retry_token"};
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);
  EXPECT_CALL(debug_visitor, OnParsedClientHelloInfo(parsed_chlo)).Times(1);
  connection_.OnParsedClientHelloInfo(parsed_chlo);
}

}  // namespace
}  // namespace test
}  // namespace quic
```