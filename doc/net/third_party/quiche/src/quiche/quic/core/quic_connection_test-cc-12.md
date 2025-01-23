Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`. I need to go through the provided code snippets and identify the core functionalities being tested.

The code appears to be a unit test file for the `QuicConnection` class. The tests cover various aspects of connection management, including:

- **Acknowledgement (ACK) handling:**  Testing how the connection handles and sends acknowledgements, including scenarios where writing is blocked.
- **Connection ID handling:** Verifying the processing of packets with valid and invalid client connection IDs, and how the connection ID is updated.
- **Coalesced packets:**  Testing the correct parsing of packets containing multiple smaller packets.
- **Retransmission and timeouts (RTO, PTO):**  Checking how the connection behaves when retransmission alarms fire, especially when writing is blocked. Also, tests related to probing timeouts and the connection closing after multiple PTOs.
- **Anti-amplification limit:** Testing the connection's behavior related to the anti-amplification mechanism to prevent abuse during the handshake.
- **Connection closure:**  Verifying the connection closure process in specific scenarios, like receiving a connection close frame.

Regarding the user's specific requests:

- **Functionality Listing:** I will create a bulleted list of the main functionalities being tested.
- **Relationship with Javascript:** QUIC is a transport layer protocol. While the Chromium network stack (which includes this C++ code) is used by the Chrome browser (which executes Javascript), there's no direct, functional link between this specific C++ code and Javascript. Javascript running in a web page would interact with higher-level browser APIs, which would eventually use the underlying QUIC implementation. I will provide an example to illustrate this indirect relationship.
- **Logical Reasoning (Input/Output):**  The tests themselves are examples of logical reasoning with specific inputs (packet data, connection state) and expected outputs (changes in connection state, actions taken by the connection). I can pick a simple test case and describe the assumed input and the expected output.
- **Common User/Programming Errors:** These tests often expose potential error conditions. I can point out a few examples where incorrect handling could lead to issues.
- **User Operation to Reach This Code:**  This is part of the QUIC implementation within the Chromium network stack. I can outline a general scenario that would involve this code being executed.
- **Functionality Summary (Part 13/24):** I need to summarize the functionalities covered in this specific excerpt, keeping in mind it's a portion of a larger test file.

**Mental Sandbox:**

I will focus on a few specific test cases to demonstrate the thought process:

- **`ValidClientConnectionId` and `InvalidClientConnectionId`:** These test the core functionality of filtering packets based on connection IDs. Input: a received packet with a specific destination connection ID. Output: the packet is processed or dropped based on whether the ID matches the expected client connection ID.
- **`RtoAndWriteBlocked` and `PtoAndWriteBlocked`:** These test the interaction between retransmission mechanisms and write blocking. Input: trigger a retransmission alarm while the writer is blocked. Output: verify that packets are not flushed or only specific types of packets are flushed based on the alarm type.
- **`AntiAmplificationLimit`:** Input: a server receiving packets and attempting to send data before address validation is complete. Output: the server should be rate-limited in sending data based on the anti-amplification factor.

By analyzing these and other test cases, I can generate the comprehensive summary requested by the user. I need to be careful to distinguish between the direct functionality of the C++ code and its indirect role in enabling network communication for higher-level applications like those using Javascript.
This section of the `quic_connection_test.cc` file primarily focuses on testing the following functionalities of the `QuicConnection` class in the Chromium network stack:

**Core Functionalities Tested in this Section:**

* **Acknowledgement (ACK) Handling and Write Blocking:**
    * Verifies that when the write queue is blocked, pending ACK frames are not immediately flushed.
    * Checks that when the write queue becomes unblocked, all pending ACK frames are sent.
    * This tests the interaction between the ACK alarm, the write blocking mechanism, and the `OnCanWrite()` event.
* **Client Connection ID Validation and Updates:**
    * **Valid Client Connection ID:** Confirms that packets received with the correct client connection ID are processed successfully.
    * **Invalid Client Connection ID:** Ensures that packets with incorrect client connection IDs are dropped.
    * **Updating Client Connection ID:** Verifies that the server can update the client connection ID upon receiving the first packet from the client with a different ID.
    * **Replacing Connection ID from Initial Packets:** Tests that the connection ID can be replaced once by an initial packet and that subsequent attempts to replace it are ignored. This is tested for both server and client perspectives.
* **Handling Connection Close Frames:**
    * Checks that when a connection close frame is received, the connection is closed, and pending ACK alarms are not scheduled.
* **Processing Coalesced Packets:**
    * Tests the ability of the `QuicConnection` to correctly parse and process packets containing multiple smaller QUIC packets within a single UDP datagram.
* **Interaction of Retransmission Timers (RTO/PTO) and Write Blocking:**
    * **RTO and Write Blocked:** Verifies that when the retransmission timer (RTO) fires while the write queue is blocked, no packets are sent.
    * **PTO and Write Blocked:** Checks that when the probe timeout (PTO) timer fires while the write queue is blocked, only a limited number of packets (typically probes) are sent.
* **Probe Timeout (PTO) Behavior:**
    * Tests that when a PTO occurs, only control frames like `RST_STREAM` are retransmitted, not the original stream data.
* **Connection Closure after Multiple Client PTOs (Blackhole Detection):**
    * Verifies that the connection closes itself after a configurable number of consecutive PTOs without receiving any response, indicating a potential network blackhole. This involves the `BlackholeDetectorAlarm`.
* **Handshake Mode Deprecation and PING Sending:**
    * Tests that if the handshake is not confirmed and there's no data to send when the retransmission alarm fires, a PING frame is sent to probe the connection.
* **Anti-Amplification Limit:**
    * Verifies that a server connection correctly enforces the anti-amplification limit during the handshake, restricting the amount of data sent before receiving acknowledgements and completing address validation. Different amplification factors (e.g., 3, 10) are tested based on negotiated connection options.

**Relationship with JavaScript:**

While this C++ code is part of the underlying network stack, it doesn't have a direct, functional relationship with JavaScript. JavaScript running in a web browser interacts with network resources through browser APIs like `fetch()` or `XMLHttpRequest`. The browser, in turn, uses the Chromium network stack (which includes this QUIC implementation) to handle the underlying QUIC protocol.

**Example:**

Imagine a user clicks a link in a web page that initiates a request to a server using QUIC.

1. **JavaScript (`fetch()` API):** The JavaScript code uses the `fetch()` API to make the request.
2. **Browser Network Stack:** The browser's network stack receives this request. If the connection to the server uses QUIC, the browser will utilize the QUIC implementation.
3. **`QuicConnection`:** The `QuicConnection` class (the one being tested here) will be responsible for managing the QUIC connection, including sending and receiving packets, handling acknowledgements, managing retransmissions, and enforcing connection limits like the anti-amplification limit.
4. **Test Case Example:**  The `AntiAmplificationLimit` tests in this file ensure that the server, when handling the initial handshake for this new connection initiated by the JavaScript request, doesn't send excessive data before the client's address is validated, preventing potential amplification attacks.

**Logical Reasoning (Hypothetical Input and Output):**

**Test Case:** `ValidClientConnectionId`

**Hypothetical Input:**

* The `QuicConnection` is configured with a client connection ID of `0x33`.
* A received QUIC packet has a destination connection ID of `0x33`.

**Expected Output:**

* The packet is successfully processed by the `QuicConnection`.
* The `packets_dropped` counter in the connection's statistics remains at 0.
* The `visitor_` (a mock object representing the higher-level QUIC session) would be notified of the received frames (e.g., a PING frame in this test).

**Common User or Programming Usage Errors:**

* **Incorrectly configuring connection IDs:** If the server and client are not configured with matching connection IDs (or if the client doesn't include the correct connection ID in its packets), the server might drop valid client packets. The `InvalidClientConnectionId` test specifically checks for this scenario.
* **Not handling write blocking correctly:** If the application layer doesn't respect the `OnWriteBlocked()` notification and continues to send data when the connection is congested, it can lead to inefficient network usage and potential packet drops. The tests involving `writer_->SetWriteBlocked()` simulate this situation to ensure the `QuicConnection` handles it correctly.
* **Misunderstanding the anti-amplification limit:**  A server implementation might mistakenly try to send large amounts of data during the handshake before address validation is complete. The `AntiAmplificationLimit` tests ensure the `QuicConnection` enforces this limit, preventing potential abuse.

**User Operation Steps to Reach This Code (Debugging Context):**

1. **User opens a website in Chrome:**  The user types a URL in the Chrome address bar or clicks a link.
2. **Browser initiates a connection:** If the website supports QUIC, Chrome will attempt to establish a QUIC connection with the server.
3. **QUIC handshake:** The QUIC handshake process begins, involving the exchange of initial packets.
4. **Packet processing in `QuicConnection`:**  As packets are received from the server, the `QuicConnection::ProcessUdpPacket()` method is called.
5. **Connection ID validation:** Within `ProcessUdpPacket()`, the code might check the destination connection ID of the incoming packet against the expected client connection ID (as tested by `ValidClientConnectionId` and `InvalidClientConnectionId`).
6. **ACK handling:**  When the connection receives data, it schedules ACK frames to be sent back to the peer. The logic tested by the ACK-related tests comes into play here.
7. **Potential write blocking:** If the network is congested, the underlying socket might become unwritable, leading to the `OnWriteBlocked()` notification being triggered, as simulated in the write blocking tests.
8. **Retransmission and timeouts:** If packets are lost, the retransmission timers (RTO/PTO) will fire, triggering the retransmission logic tested in the respective test cases.
9. **Blackhole detection:** If the client experiences prolonged periods without receiving responses, the blackhole detection mechanism (tested by the PTO-related closure tests) might be activated.
10. **Debugging:** If developers suspect issues with QUIC connection management, they might set breakpoints in the `QuicConnection` class or related components (like the packet parser or ACK handler) and observe the execution flow as the browser interacts with a website using QUIC. The test file provides a controlled environment to verify the correctness of these mechanisms.

**Summary of Functionality (Part 13/24):**

This section of the `quic_connection_test.cc` file primarily focuses on verifying the robustness and correctness of the `QuicConnection` class in handling fundamental aspects of connection management, including acknowledgement processing, client connection ID validation and updates, handling connection closure, managing coalesced packets, and ensuring proper behavior during retransmissions and timeouts, especially when the write queue is blocked. It also tests the anti-amplification mechanism designed to protect servers during the handshake phase. These tests are crucial for ensuring the stability and security of QUIC connections.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
ECT_TRUE(connection_.HasPendingAcks());

  writer_->SetWriteBlocked();
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AnyNumber());
  // Simulates ACK alarm fires and verify no ACK is flushed because of write
  // blocked.
  clock_.AdvanceTime(DefaultDelayedAckTime());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(0x02));
  connection_.GetAckAlarm()->Fire();
  // Verify ACK alarm is not set.
  EXPECT_FALSE(connection_.HasPendingAcks());

  writer_->SetWritable();
  // Verify 2 ACKs are sent when connection gets unblocked.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  connection_.OnCanWrite();
  EXPECT_FALSE(connection_.HasPendingAcks());
}

// Make sure a packet received with the right client connection ID is processed.
TEST_P(QuicConnectionTest, ValidClientConnectionId) {
  if (!framer_.version().SupportsClientConnectionIds()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  SetClientConnectionId(TestConnectionId(0x33));
  QuicPacketHeader header = ConstructPacketHeader(1, ENCRYPTION_FORWARD_SECURE);
  header.destination_connection_id = TestConnectionId(0x33);
  header.destination_connection_id_included = CONNECTION_ID_PRESENT;
  header.source_connection_id_included = CONNECTION_ID_ABSENT;
  QuicFrames frames;
  QuicPingFrame ping_frame;
  QuicPaddingFrame padding_frame;
  frames.push_back(QuicFrame(ping_frame));
  frames.push_back(QuicFrame(padding_frame));
  std::unique_ptr<QuicPacket> packet =
      BuildUnsizedDataPacket(&peer_framer_, header, frames);
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = peer_framer_.EncryptPayload(
      ENCRYPTION_FORWARD_SECURE, QuicPacketNumber(1), *packet, buffer,
      kMaxOutgoingPacketSize);
  QuicReceivedPacket received_packet(buffer, encrypted_length, clock_.Now(),
                                     false);
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  ProcessReceivedPacket(kSelfAddress, kPeerAddress, received_packet);
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
}

// Make sure a packet received with a different client connection ID is dropped.
TEST_P(QuicConnectionTest, InvalidClientConnectionId) {
  if (!framer_.version().SupportsClientConnectionIds()) {
    return;
  }
  SetClientConnectionId(TestConnectionId(0x33));
  QuicPacketHeader header = ConstructPacketHeader(1, ENCRYPTION_FORWARD_SECURE);
  header.destination_connection_id = TestConnectionId(0xbad);
  header.destination_connection_id_included = CONNECTION_ID_PRESENT;
  header.source_connection_id_included = CONNECTION_ID_ABSENT;
  QuicFrames frames;
  QuicPingFrame ping_frame;
  QuicPaddingFrame padding_frame;
  frames.push_back(QuicFrame(ping_frame));
  frames.push_back(QuicFrame(padding_frame));
  std::unique_ptr<QuicPacket> packet =
      BuildUnsizedDataPacket(&peer_framer_, header, frames);
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length = peer_framer_.EncryptPayload(
      ENCRYPTION_FORWARD_SECURE, QuicPacketNumber(1), *packet, buffer,
      kMaxOutgoingPacketSize);
  QuicReceivedPacket received_packet(buffer, encrypted_length, clock_.Now(),
                                     false);
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  ProcessReceivedPacket(kSelfAddress, kPeerAddress, received_packet);
  EXPECT_EQ(1u, connection_.GetStats().packets_dropped);
}

// Make sure the first packet received with a different client connection ID on
// the server is processed and it changes the client connection ID.
TEST_P(QuicConnectionTest, UpdateClientConnectionIdFromFirstPacket) {
  if (!framer_.version().SupportsClientConnectionIds()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  QuicPacketHeader header = ConstructPacketHeader(1, ENCRYPTION_INITIAL);
  header.source_connection_id = TestConnectionId(0x33);
  header.source_connection_id_included = CONNECTION_ID_PRESENT;
  QuicFrames frames;
  QuicPingFrame ping_frame;
  QuicPaddingFrame padding_frame;
  frames.push_back(QuicFrame(ping_frame));
  frames.push_back(QuicFrame(padding_frame));
  std::unique_ptr<QuicPacket> packet =
      BuildUnsizedDataPacket(&peer_framer_, header, frames);
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      peer_framer_.EncryptPayload(ENCRYPTION_INITIAL, QuicPacketNumber(1),
                                  *packet, buffer, kMaxOutgoingPacketSize);
  QuicReceivedPacket received_packet(buffer, encrypted_length, clock_.Now(),
                                     false);
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  ProcessReceivedPacket(kSelfAddress, kPeerAddress, received_packet);
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  EXPECT_EQ(TestConnectionId(0x33), connection_.client_connection_id());
}
void QuicConnectionTest::TestReplaceConnectionIdFromInitial() {
  if (!framer_.version().AllowsVariableLengthConnectionIds()) {
    return;
  }
  // We start with a known connection ID.
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  EXPECT_NE(TestConnectionId(0x33), connection_.connection_id());
  // Receiving an initial can replace the connection ID once.
  {
    QuicPacketHeader header = ConstructPacketHeader(1, ENCRYPTION_INITIAL);
    header.source_connection_id = TestConnectionId(0x33);
    header.source_connection_id_included = CONNECTION_ID_PRESENT;
    QuicFrames frames;
    QuicPingFrame ping_frame;
    QuicPaddingFrame padding_frame;
    frames.push_back(QuicFrame(ping_frame));
    frames.push_back(QuicFrame(padding_frame));
    std::unique_ptr<QuicPacket> packet =
        BuildUnsizedDataPacket(&peer_framer_, header, frames);
    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length =
        peer_framer_.EncryptPayload(ENCRYPTION_INITIAL, QuicPacketNumber(1),
                                    *packet, buffer, kMaxOutgoingPacketSize);
    QuicReceivedPacket received_packet(buffer, encrypted_length, clock_.Now(),
                                       false);
    ProcessReceivedPacket(kSelfAddress, kPeerAddress, received_packet);
  }
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(0u, connection_.GetStats().packets_dropped);
  EXPECT_EQ(TestConnectionId(0x33), connection_.connection_id());
  // Trying to replace the connection ID a second time drops the packet.
  {
    QuicPacketHeader header = ConstructPacketHeader(2, ENCRYPTION_INITIAL);
    header.source_connection_id = TestConnectionId(0x66);
    header.source_connection_id_included = CONNECTION_ID_PRESENT;
    QuicFrames frames;
    QuicPingFrame ping_frame;
    QuicPaddingFrame padding_frame;
    frames.push_back(QuicFrame(ping_frame));
    frames.push_back(QuicFrame(padding_frame));
    std::unique_ptr<QuicPacket> packet =
        BuildUnsizedDataPacket(&peer_framer_, header, frames);
    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length =
        peer_framer_.EncryptPayload(ENCRYPTION_INITIAL, QuicPacketNumber(2),
                                    *packet, buffer, kMaxOutgoingPacketSize);
    QuicReceivedPacket received_packet(buffer, encrypted_length, clock_.Now(),
                                       false);
    ProcessReceivedPacket(kSelfAddress, kPeerAddress, received_packet);
  }
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(1u, connection_.GetStats().packets_dropped);
  EXPECT_EQ(TestConnectionId(0x33), connection_.connection_id());
}

TEST_P(QuicConnectionTest, ReplaceServerConnectionIdFromInitial) {
  TestReplaceConnectionIdFromInitial();
}

TEST_P(QuicConnectionTest, ReplaceServerConnectionIdFromRetryAndInitial) {
  // First make the connection process a RETRY and replace the server connection
  // ID a first time.
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);
  // Reset the test framer to use the right connection ID.
  peer_framer_.SetInitialObfuscators(connection_.connection_id());
  // Now process an INITIAL and replace the server connection ID a second time.
  TestReplaceConnectionIdFromInitial();
}

// Regression test for b/134416344.
TEST_P(QuicConnectionTest, CheckConnectedBeforeFlush) {
  // This test mimics a scenario where a connection processes 2 packets and the
  // 2nd packet contains connection close frame. When the 2nd flusher goes out
  // of scope, a delayed ACK is pending, and ACK alarm should not be scheduled
  // because connection is disconnected.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  const QuicErrorCode kErrorCode = QUIC_INTERNAL_ERROR;
  std::unique_ptr<QuicConnectionCloseFrame> connection_close_frame(
      new QuicConnectionCloseFrame(connection_.transport_version(), kErrorCode,
                                   NO_IETF_QUIC_ERROR, "",
                                   /*transport_close_frame_type=*/0));

  // Received 2 packets.
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  }
  ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());
  ProcessFramePacketWithAddresses(QuicFrame(connection_close_frame.release()),
                                  kSelfAddress, kPeerAddress,
                                  ENCRYPTION_INITIAL);
  // Verify ack alarm is not set.
  EXPECT_FALSE(connection_.HasPendingAcks());
}

// Verify that a packet containing three coalesced packets is parsed correctly.
TEST_P(QuicConnectionTest, CoalescedPacket) {
  if (!QuicVersionHasLongHeaderLengths(connection_.transport_version())) {
    // Coalesced packets can only be encoded using long header lengths.
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_TRUE(connection_.connected());
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(3);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(3);
  }

  uint64_t packet_numbers[3] = {1, 2, 3};
  EncryptionLevel encryption_levels[3] = {
      ENCRYPTION_INITIAL, ENCRYPTION_INITIAL, ENCRYPTION_FORWARD_SECURE};
  char buffer[kMaxOutgoingPacketSize] = {};
  size_t total_encrypted_length = 0;
  for (int i = 0; i < 3; i++) {
    QuicPacketHeader header =
        ConstructPacketHeader(packet_numbers[i], encryption_levels[i]);
    QuicFrames frames;
    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      frames.push_back(QuicFrame(&crypto_frame_));
    } else {
      frames.push_back(QuicFrame(frame1_));
    }
    std::unique_ptr<QuicPacket> packet = ConstructPacket(header, frames);
    peer_creator_.set_encryption_level(encryption_levels[i]);
    size_t encrypted_length = peer_framer_.EncryptPayload(
        encryption_levels[i], QuicPacketNumber(packet_numbers[i]), *packet,
        buffer + total_encrypted_length,
        sizeof(buffer) - total_encrypted_length);
    EXPECT_GT(encrypted_length, 0u);
    total_encrypted_length += encrypted_length;
  }
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, total_encrypted_length, clock_.Now(), false));
  if (connection_.GetSendAlarm()->IsSet()) {
    connection_.GetSendAlarm()->Fire();
  }

  EXPECT_TRUE(connection_.connected());
}

// Regression test for crbug.com/992831.
TEST_P(QuicConnectionTest, CoalescedPacketThatSavesFrames) {
  if (!QuicVersionHasLongHeaderLengths(connection_.transport_version())) {
    // Coalesced packets can only be encoded using long header lengths.
    return;
  }
  if (connection_.SupportsMultiplePacketNumberSpaces()) {
    // TODO(b/129151114) Enable this test with multiple packet number spaces.
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_TRUE(connection_.connected());
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_))
        .Times(3)
        .WillRepeatedly([this](const QuicCryptoFrame& /*frame*/) {
          // QuicFrame takes ownership of the QuicBlockedFrame.
          connection_.SendControlFrame(QuicFrame(QuicBlockedFrame(1, 3, 0)));
        });
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_))
        .Times(3)
        .WillRepeatedly([this](const QuicStreamFrame& /*frame*/) {
          // QuicFrame takes ownership of the QuicBlockedFrame.
          connection_.SendControlFrame(QuicFrame(QuicBlockedFrame(1, 3, 0)));
        });
  }

  uint64_t packet_numbers[3] = {1, 2, 3};
  EncryptionLevel encryption_levels[3] = {
      ENCRYPTION_INITIAL, ENCRYPTION_INITIAL, ENCRYPTION_FORWARD_SECURE};
  char buffer[kMaxOutgoingPacketSize] = {};
  size_t total_encrypted_length = 0;
  for (int i = 0; i < 3; i++) {
    QuicPacketHeader header =
        ConstructPacketHeader(packet_numbers[i], encryption_levels[i]);
    QuicFrames frames;
    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      frames.push_back(QuicFrame(&crypto_frame_));
    } else {
      frames.push_back(QuicFrame(frame1_));
    }
    std::unique_ptr<QuicPacket> packet = ConstructPacket(header, frames);
    peer_creator_.set_encryption_level(encryption_levels[i]);
    size_t encrypted_length = peer_framer_.EncryptPayload(
        encryption_levels[i], QuicPacketNumber(packet_numbers[i]), *packet,
        buffer + total_encrypted_length,
        sizeof(buffer) - total_encrypted_length);
    EXPECT_GT(encrypted_length, 0u);
    total_encrypted_length += encrypted_length;
  }
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, total_encrypted_length, clock_.Now(), false));
  if (connection_.GetSendAlarm()->IsSet()) {
    connection_.GetSendAlarm()->Fire();
  }

  EXPECT_TRUE(connection_.connected());

  SendAckPacketToPeer();
}

// Regresstion test for b/138962304.
TEST_P(QuicConnectionTest, RtoAndWriteBlocked) {
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  QuicStreamId stream_id = 2;
  QuicPacketNumber last_data_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_data_packet);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Writer gets blocked.
  writer_->SetWriteBlocked();

  // Cancel the stream.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(1));
  EXPECT_CALL(visitor_, WillingAndAbleToWrite())
      .WillRepeatedly(
          Invoke(&notifier_, &SimpleSessionNotifier::WillingToWrite));
  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 3);

  // Retransmission timer fires in RTO mode.
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify no packets get flushed when writer is blocked.
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

// Regresstion test for b/138962304.
TEST_P(QuicConnectionTest, PtoAndWriteBlocked) {
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  QuicStreamId stream_id = 2;
  QuicPacketNumber last_data_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_data_packet);
  SendStreamDataToPeer(4, "foo", 0, NO_FIN, &last_data_packet);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Writer gets blocked.
  writer_->SetWriteBlocked();

  // Cancel stream 2.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(1));
  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 3);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  // Retransmission timer fires in TLP mode.
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify one packets is forced flushed when writer is blocked.
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, ProbeTimeout) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k2PTO);
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foooooo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "foooooo", 7, NO_FIN, &last_packet);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Reset stream.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 3);

  // Fire the PTO and verify only the RST_STREAM is resent, not stream data.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(0u, writer_->stream_frames().size());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, CloseConnectionAfter6ClientPTOs) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k1PTO);
  connection_options.push_back(k6PTO);
  config.SetConnectionOptionsToSend(connection_options);
  QuicConfigPeer::SetNegotiated(&config, true);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2) ||
      GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed)) {
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  }
  connection_.OnHandshakeComplete();
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Send stream data.
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);

  // Fire the retransmission alarm 5 times.
  for (int i = 0; i < 5; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.GetRetransmissionAlarm()->Fire();
    EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
    EXPECT_TRUE(connection_.connected());
  }
  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.PathDegradingTimeout();

  EXPECT_EQ(5u, connection_.sent_packet_manager().GetConsecutivePtoCount());
  // Closes connection on 6th PTO.
  // May send multiple connecction close packets with multiple PN spaces.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  ASSERT_TRUE(connection_.BlackholeDetectionInProgress());
  connection_.GetBlackholeDetectorAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_TOO_MANY_RTOS);
}

TEST_P(QuicConnectionTest, CloseConnectionAfter7ClientPTOs) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k2PTO);
  connection_options.push_back(k7PTO);
  config.SetConnectionOptionsToSend(connection_options);
  QuicConfigPeer::SetNegotiated(&config, true);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2) ||
      GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed)) {
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  }
  connection_.OnHandshakeComplete();
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Send stream data.
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);

  // Fire the retransmission alarm 6 times.
  for (int i = 0; i < 6; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
    connection_.GetRetransmissionAlarm()->Fire();
    EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
    EXPECT_TRUE(connection_.connected());
  }
  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.PathDegradingTimeout();

  EXPECT_EQ(6u, connection_.sent_packet_manager().GetConsecutivePtoCount());
  // Closes connection on 7th PTO.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  ASSERT_TRUE(connection_.BlackholeDetectionInProgress());
  connection_.GetBlackholeDetectorAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_TOO_MANY_RTOS);
}

TEST_P(QuicConnectionTest, CloseConnectionAfter8ClientPTOs) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k2PTO);
  connection_options.push_back(k8PTO);
  QuicConfigPeer::SetNegotiated(&config, true);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  if (GetQuicReloadableFlag(quic_default_enable_5rto_blackhole_detection2) ||
      GetQuicReloadableFlag(
          quic_no_path_degrading_before_handshake_confirmed)) {
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  }
  connection_.OnHandshakeComplete();
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Send stream data.
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);

  // Fire the retransmission alarm 7 times.
  for (int i = 0; i < 7; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
    connection_.GetRetransmissionAlarm()->Fire();
    EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
    EXPECT_TRUE(connection_.connected());
  }
  EXPECT_CALL(visitor_, OnPathDegrading());
  connection_.PathDegradingTimeout();

  EXPECT_EQ(7u, connection_.sent_packet_manager().GetConsecutivePtoCount());
  // Closes connection on 8th PTO.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  ASSERT_TRUE(connection_.BlackholeDetectionInProgress());
  connection_.GetBlackholeDetectorAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_TOO_MANY_RTOS);
}

TEST_P(QuicConnectionTest, DeprecateHandshakeMode) {
  if (!connection_.version().SupportsAntiAmplificationLimit()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Send CHLO.
  connection_.SendCryptoStreamData();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  QuicAckFrame frame1 = InitAckFrame(1);
  // Received ACK for packet 1.
  ProcessFramePacketAtLevel(1, QuicFrame(&frame1), ENCRYPTION_INITIAL);

  // Verify retransmission alarm is still set because handshake is not
  // confirmed although there is nothing in flight.
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_EQ(0u, connection_.GetStats().pto_count);
  EXPECT_EQ(0u, connection_.GetStats().crypto_retransmit_count);

  // PTO fires, verify a PING packet gets sent because there is no data to send.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(3), _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(1u, connection_.GetStats().pto_count);
  EXPECT_EQ(1u, connection_.GetStats().crypto_retransmit_count);
  EXPECT_EQ(1u, writer_->ping_frames().size());
}

TEST_P(QuicConnectionTest, AntiAmplificationLimit) {
  if (!connection_.version().SupportsAntiAmplificationLimit() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());

  set_perspective(Perspective::IS_SERVER);
  // Verify no data can be sent at the beginning because bytes received is 0.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo", 0);
  EXPECT_FALSE(connection_.CanWrite(HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.CanWrite(NO_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Receives packet 1.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);

  const size_t anti_amplification_factor =
      GetQuicFlag(quic_anti_amplification_factor);
  // Verify now packets can be sent.
  for (size_t i = 1; i < anti_amplification_factor; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendCryptoDataWithString("foo", i * 3);
    // Verify retransmission alarm is not set if throttled by anti-amplification
    // limit.
    EXPECT_EQ(i != anti_amplification_factor - 1,
              connection_.GetRetransmissionAlarm()->IsSet());
  }
  // Verify server is throttled by anti-amplification limit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo", anti_amplification_factor * 3);

  // Receives packet 2.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessCryptoPacketAtLevel(2, ENCRYPTION_INITIAL);
  // Verify more packets can be sent.
  for (size_t i = anti_amplification_factor + 1;
       i < anti_amplification_factor * 2; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendCryptoDataWithString("foo", i * 3);
  }
  // Verify server is throttled by anti-amplification limit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo",
                                       2 * anti_amplification_factor * 3);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessPacket(3);
  // Verify anti-amplification limit is gone after address validation.
  for (size_t i = 0; i < 100; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendStreamDataWithString(3, "first", i * 0, NO_FIN);
  }
}

TEST_P(QuicConnectionTest, 3AntiAmplificationLimit) {
  if (!connection_.version().SupportsAntiAmplificationLimit() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());

  set_perspective(Perspective::IS_SERVER);
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k3AFF);
  config.SetInitialReceivedConnectionOptions(connection_options);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(&config,
                                                         QuicConnectionId());
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);

  // Verify no data can be sent at the beginning because bytes received is 0.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo", 0);
  EXPECT_FALSE(connection_.CanWrite(HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.CanWrite(NO_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Receives packet 1.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);

  const size_t anti_amplification_factor = 3;
  // Verify now packets can be sent.
  for (size_t i = 1; i < anti_amplification_factor; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendCryptoDataWithString("foo", i * 3);
    // Verify retransmission alarm is not set if throttled by anti-amplification
    // limit.
    EXPECT_EQ(i != anti_amplification_factor - 1,
              connection_.GetRetransmissionAlarm()->IsSet());
  }
  // Verify server is throttled by anti-amplification limit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo", anti_amplification_factor * 3);

  // Receives packet 2.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessCryptoPacketAtLevel(2, ENCRYPTION_INITIAL);
  // Verify more packets can be sent.
  for (size_t i = anti_amplification_factor + 1;
       i < anti_amplification_factor * 2; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendCryptoDataWithString("foo", i * 3);
  }
  // Verify server is throttled by anti-amplification limit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo",
                                       2 * anti_amplification_factor * 3);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessPacket(3);
  // Verify anti-amplification limit is gone after address validation.
  for (size_t i = 0; i < 100; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendStreamDataWithString(3, "first", i * 0, NO_FIN);
  }
}

TEST_P(QuicConnectionTest, 10AntiAmplificationLimit) {
  if (!connection_.version().SupportsAntiAmplificationLimit() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());

  set_perspective(Perspective::IS_SERVER);
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k10AF);
  config.SetInitialReceivedConnectionOptions(connection_options);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(&config,
                                                         QuicConnectionId());
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);

  // Verify no data can be sent at the beginning because bytes received is 0.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendCryptoDataWithString("foo", 0);
  EXPECT_FALSE(connection_.CanWrite(HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.CanWrite(NO_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Receives packet 1.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);

  const size_t anti_amplification_factor = 10;
  // Verify
```