Response:
The user wants to understand the functionality of the `quic_connection_test.cc` file in the Chromium network stack. They've provided a code snippet from the middle of the file and are asking for a summary of its features, its relation to JavaScript, logical inferences with examples, common usage errors, debugging tips, and a general function summary considering it's part 14 of 24.

Here's a breakdown of the thinking process to answer the user's request:

1. **Identify the Core Functionality:** The filename `quic_connection_test.cc` strongly suggests that this file contains unit tests for the `QuicConnection` class. The code snippet confirms this, as it uses `EXPECT_CALL` and performs various actions on a `connection_` object.

2. **Analyze the Code Snippet:**  Examine the individual test cases within the snippet. Look for patterns, common setups, and specific actions being tested. The snippet contains tests related to:
    * Anti-amplification limits during connection establishment.
    * Handling of pending acknowledgements (ACKs) when amplification limits are in place.
    * Processing of `CONNECTION_CLOSE` frames.
    * Packet number skipping during Probing Timeouts (PTO).
    * Changing flow labels during PTO and upon receiving new flow labels.
    * Sending coalesced packets (multiple QUIC packets in a single UDP datagram).
    * Handling the `HANDSHAKE_DONE` frame.
    * PTO in multiple packet number spaces (Initial, Handshake, Application).
    * Client-side handling of `RETRY` packets, including valid and invalid scenarios.
    * Adjusting timeouts based on connection options.

3. **Relate to QUIC Concepts:**  Connect the observed test cases to core QUIC concepts. For instance, anti-amplification is a security feature to prevent attackers from exploiting the connection establishment. PTO is a mechanism to recover from packet loss. Coalesced packets improve efficiency. `HANDSHAKE_DONE` signals the completion of the handshake. `RETRY` is a mechanism for servers to validate client addresses.

4. **Determine JavaScript Relevance:**  Consider how these QUIC functionalities might relate to JavaScript in a browser context. JavaScript doesn't directly interact with these low-level QUIC details. The browser's network stack handles the QUIC protocol. However, the *outcomes* of these features are relevant to JavaScript. For example, successful connection establishment (tested by anti-amplification and handshake tests) allows JavaScript to fetch resources. Efficient packet handling (tested by coalescing and PTO) leads to faster page loads, which benefits the user and the JavaScript running on the page.

5. **Infer Logical Inputs and Outputs:** For each test case, consider what input triggers the tested behavior and what the expected output is. For example, the anti-amplification test inputs sending multiple crypto packets, and the output is that the server is initially throttled until address validation. The PTO test inputs sending data and experiencing packet loss, with the output being a retransmission with a skipped packet number.

6. **Identify Potential User/Programming Errors:**  Think about how a developer or user might misuse or encounter issues related to the tested functionalities. For example, a server not handling retry correctly could lead to connection failures. Incorrect configuration of connection options could impact performance or security.

7. **Trace User Operations (Debugging):** Consider how a user's actions in a browser might lead to the execution of this code. Opening a website that uses QUIC, especially during the initial connection establishment or when experiencing network issues, would trigger these code paths. Debugging would involve inspecting network logs, QUIC connection states, and potentially stepping through the C++ code.

8. **Synthesize the Functionality Summary (Part 14 of 24):** Combine the understanding of individual test cases to form a higher-level summary. Consider what broader aspects of the `QuicConnection` class are being tested in this section. Given it's part 14,  it's likely focused on more advanced or specific aspects of connection management and error handling, building upon the fundamental connection setup and data transfer tested in earlier parts.

9. **Structure the Answer:** Organize the findings into clear sections as requested by the user: Functionality, JavaScript relation, logical inferences, usage errors, debugging, and overall summary. Use clear and concise language. Provide concrete examples where possible.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focus heavily on the code details within each test case.
* **Correction:**  Shift focus to the *purpose* of each test case and how it relates to the overall functionality of `QuicConnection`.
* **Initial thought:**  Overstate the direct relationship between JavaScript and the C++ QUIC implementation.
* **Correction:**  Clarify that JavaScript benefits from the correct functioning of QUIC but doesn't directly interact with these implementation details. Focus on the user-visible outcomes.
* **Initial thought:**  Provide overly technical explanations of QUIC concepts.
* **Correction:** Explain QUIC concepts in a way that is understandable to a broader audience, even those not deeply familiar with the protocol. Provide links to more information if needed.
Here's a breakdown of the functionality of the provided code snippet from `quic_connection_test.cc`, along with explanations and examples:

**Functionality of the Code Snippet:**

This code snippet contains several unit tests for the `QuicConnection` class in Chromium's QUIC implementation. These tests focus on various aspects of connection management, including:

* **Anti-Amplification Limit:**  Testing how the connection handles sending data before address validation is complete. This is a security mechanism to prevent denial-of-service attacks where an attacker spoofs the client's address and causes the server to send large responses to the spoofed address.
* **Acknowledgement (ACK) Handling with Amplification Limits:** Verifying that ACKs are handled correctly when the connection is limited by the anti-amplification factor. It ensures ACKs are eventually sent once the limit is lifted.
* **Connection Close Frame Types:**  Specifically testing the framing of `CONNECTION_CLOSE` frames for IETF QUIC, ensuring the correct frame type and error codes are used.
* **Probing Timeouts (PTO):**  Testing how the connection handles packet loss detection and retransmission using PTO, including scenarios where packet numbers are skipped and flow labels are changed to potentially bypass middleboxes.
* **Flow Label Changes:**  Verifying how the connection reacts to receiving packets with new flow labels, particularly after a gap in packet numbers, which can be used for black hole avoidance.
* **Coalesced Packets:** Testing the ability of the connection to send multiple QUIC packets (at different encryption levels) within a single underlying UDP datagram for efficiency. It also includes a negative test case for when coalescing fails.
* **Handshake Done Frame:**  Testing the reception and handling of the `HANDSHAKE_DONE` frame, which signals the completion of the QUIC handshake. This includes verifying that clients process it while servers might close the connection if they receive it unexpectedly.
* **Multiple Packet Number Spaces:** Testing PTO behavior when using separate packet number spaces for different phases of the connection (Initial, Handshake, Application Data).
* **Client Retry Handling:**  Testing how a client handles `RETRY` packets from the server, which are used to validate the client's address. This includes testing scenarios with valid and invalid retry tokens, and incorrect configuration.
* **Fixing Timeouts:** Testing connection logic related to handshake timeouts and how they are potentially adjusted based on connection options.
* **Retransmission on Retry:** Verifying that a client retransmits initial packets after receiving a valid `RETRY` packet.
* **Handling Invalid Retry:** Ensuring that a client does *not* retransmit initial packets when a `RETRY` packet has an invalid integrity tag.
* **Receiving Original Connection ID without Retry:**  Testing the scenario where a client receives the `original_destination_connection_id` transport parameter without having first received a `RETRY`, which should lead to a connection close in certain QUIC versions.

**Relationship to JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it underpins the network communication that JavaScript relies on in web browsers. Here's how it relates:

* **Faster Page Loads:** The optimizations and correctness ensured by these tests (like coalesced packets, efficient PTO, and proper handshake handling) contribute to faster loading of web pages and web applications. JavaScript running on these pages benefits from this improved network performance.
* **Reliable Connections:** Features like anti-amplification protection and robust retry mechanisms make QUIC connections more reliable. This means JavaScript applications are less likely to experience connection drops or failures.
* **Secure Communication:** The correct handling of the QUIC handshake and encryption (implicitly tested here) ensures that JavaScript applications communicate securely with servers.
* **WebSockets and WebTransport:** QUIC is the underlying transport for newer web technologies like WebTransport. The reliability and efficiency of the QUIC connection directly impact the performance and stability of WebTransport connections used by JavaScript.

**Example:** Imagine a JavaScript application fetching data from a server using `fetch()`. If the underlying QUIC connection (managed by the code being tested) correctly handles a packet loss scenario using PTO, the JavaScript application will experience a seamless recovery and the `fetch()` request will likely complete without interruption or significant delay.

**Logical Inferences with Assumptions:**

Let's take the "AntiPendingWithAmplificationLimited" test as an example:

**Assumptions (Input):**

1. The connection is on the server side (`set_perspective(Perspective::IS_SERVER)`).
2. The server has received an initial packet from the client (`ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL)`).
3. The server needs to send handshake data.
4. The server is initially limited by the anti-amplification factor.
5. The server's ACK alarm fires.
6. The server then receives another packet from the client (`ProcessCryptoPacketAtLevel(2, ENCRYPTION_INITIAL)`).

**Outputs:**

1. Initially, the server is throttled and cannot send all its handshake data immediately.
2. An ACK is pending (`connection_.HasPendingAcks()`).
3. When the ACK alarm fires, the ACK *cannot* be sent due to the amplification limit (`EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0)`).
4. After receiving another packet from the client, the pending ACK is flushed, and an ACK frame is present in the writer (`EXPECT_FALSE(writer_->ack_frames().empty())`).

**User or Programming Common Usage Errors:**

* **Incorrect Configuration of Connection Options:** A programmer might incorrectly configure QUIC connection options, potentially disabling important security features like anti-amplification or causing unexpected timeout behavior. For example, a server might disable anti-amplification too early, making it vulnerable to attacks.
* **Misunderstanding the Anti-Amplification Limit:** A developer might not realize that the server is initially rate-limited during connection establishment, leading to confusion about why data isn't being sent immediately.
* **Improper Handling of Connection Close:**  A server implementation might not correctly generate or process `CONNECTION_CLOSE` frames, leading to connection errors or incomplete shutdown.
* **Incorrectly Implementing Retry Logic (Server):** A server might incorrectly implement the logic for sending `RETRY` packets, leading to clients being unable to connect or getting stuck in retry loops.

**User Operation Steps to Reach This Code (Debugging Line):**

Let's consider a user experiencing a slow initial connection to a website using QUIC:

1. **User opens a web page:** The user types a URL in the browser or clicks a link.
2. **Browser initiates QUIC connection:** The browser checks if the server supports QUIC and attempts to establish a QUIC connection.
3. **Initial handshake:** The browser sends an initial QUIC packet to the server.
4. **Server processing (leading to anti-amplification tests):** The server receives the initial packet. The code in the `QuicConnection` class, specifically the logic tested in the "SendCryptoDataWithAntiAmplification" test, is executed to manage sending handshake responses while respecting the anti-amplification limit. If the server needs to send multiple handshake messages, it will be temporarily throttled.
5. **Potential packet loss (leading to PTO tests):**  If network conditions are poor, some of the initial handshake packets might be lost. This would trigger the PTO mechanism tested in the "PtoSkipsPacketNumber" and related tests.
6. **Server sends RETRY (leading to client retry tests):** If the server needs to validate the client's address, it might send a `RETRY` packet. This would execute the client-side `RETRY` handling logic tested in "ClientReceivedHandshakeDone" and related tests.
7. **Handshake completion:**  If all goes well, the handshake completes successfully. The reception of the `HANDSHAKE_DONE` frame would trigger the logic in the "ClientReceivedHandshakeDone" test.
8. **Data transfer:** Once the connection is established, the browser can start fetching web page resources.

A developer debugging a slow initial connection might examine network logs to see if the server is being throttled by anti-amplification, if there are retransmissions due to PTO, or if the client is receiving and processing `RETRY` packets correctly.

**Summary of Functionality (Part 14 of 24):**

Considering that this is part 14 of 24, this section of the `quic_connection_test.cc` file appears to focus on **connection establishment and early connection lifecycle management**, including:

* **Security mechanisms during early connection:** Testing anti-amplification limits and how they interact with sending data and acknowledgements.
* **Error handling and connection termination:**  Testing the generation and processing of `CONNECTION_CLOSE` frames.
* **Mechanisms for handling packet loss and network issues:**  Focusing on Probing Timeouts (PTO) and flow label changes as a way to recover from packet loss and potential middlebox interference.
* **Optimization for efficiency:** Testing the sending of coalesced packets.
* **Completion of the handshake:** Testing the handling of the `HANDSHAKE_DONE` frame.
* **Client-side validation by the server:**  Extensive testing of the client's handling of `RETRY` packets.
* **Configuration and adaptation:** Testing how connection options can influence timeouts.

This part likely builds upon earlier sections that focused on more fundamental aspects of connection setup and packet processing. It delves into the complexities of establishing a secure and reliable QUIC connection, especially in the initial stages where security and network probing are critical.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第14部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
now packets can be sent.
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

TEST_P(QuicConnectionTest, AckPendingWithAmplificationLimited) {
  if (!connection_.version().SupportsAntiAmplificationLimit()) {
    return;
  }
  EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(AnyNumber());
  set_perspective(Perspective::IS_SERVER);
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  // Receives packet 1.
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_TRUE(connection_.HasPendingAcks());
  // Send response in different encryption level and cause amplification factor
  // throttled.
  size_t i = 0;
  while (connection_.CanWrite(HAS_RETRANSMITTABLE_DATA)) {
    connection_.SendCryptoDataWithString(std::string(1024, 'a'), i * 1024,
                                         ENCRYPTION_HANDSHAKE);
    ++i;
  }
  // Verify ACK is still pending.
  EXPECT_TRUE(connection_.HasPendingAcks());

  // Fire ACK alarm and verify ACK cannot be sent due to amplification factor.
  clock_.AdvanceTime(connection_.GetAckAlarm()->deadline() - clock_.Now());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.GetAckAlarm()->Fire();
  // Verify ACK alarm is cancelled.
  EXPECT_FALSE(connection_.HasPendingAcks());

  // Receives packet 2 and verify ACK gets flushed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessCryptoPacketAtLevel(2, ENCRYPTION_INITIAL);
  EXPECT_FALSE(writer_->ack_frames().empty());
}

TEST_P(QuicConnectionTest, ConnectionCloseFrameType) {
  if (!VersionHasIetfQuicFrames(version().transport_version)) {
    // Test relevent only for IETF QUIC.
    return;
  }
  const QuicErrorCode kQuicErrorCode = IETF_QUIC_PROTOCOL_VIOLATION;
  // Use the (unknown) frame type of 9999 to avoid triggering any logic
  // which might be associated with the processing of a known frame type.
  const uint64_t kTransportCloseFrameType = 9999u;
  QuicFramerPeer::set_current_received_frame_type(
      QuicConnectionPeer::GetFramer(&connection_), kTransportCloseFrameType);
  // Do a transport connection close
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  connection_.CloseConnection(
      kQuicErrorCode, "Some random error message",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  const std::vector<QuicConnectionCloseFrame>& connection_close_frames =
      writer_->connection_close_frames();
  ASSERT_EQ(1u, connection_close_frames.size());
  EXPECT_EQ(IETF_QUIC_TRANSPORT_CONNECTION_CLOSE,
            connection_close_frames[0].close_type);
  EXPECT_EQ(kQuicErrorCode, connection_close_frames[0].quic_error_code);
  EXPECT_EQ(kTransportCloseFrameType,
            connection_close_frames[0].transport_close_frame_type);
}

TEST_P(QuicConnectionTest, PtoSkipsPacketNumber) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k1PTO);
  connection_options.push_back(kPTOS);
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foooooo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "foooooo", 7, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(2), last_packet);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Fire PTO and verify the PTO retransmission skips one packet number.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(QuicPacketNumber(4), writer_->last_packet_header().packet_number);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, PtoChangesFlowLabel) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k1PTO);
  connection_options.push_back(kPTOS);
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_EQ(0, connection_.outgoing_flow_label());
  connection_.EnableBlackholeAvoidanceViaFlowLabel();
  static_cast<test::MockRandom*>(helper_->GetRandomGenerator())->ChangeValue();
  const uint32_t flow_label = connection_.outgoing_flow_label();
  EXPECT_NE(0, flow_label);

  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foooooo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "foooooo", 7, NO_FIN, &last_packet);
  EXPECT_EQ(QuicPacketNumber(2), last_packet);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  // Fire PTO and verify the flow label has changed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_NE(flow_label, connection_.outgoing_flow_label());
  EXPECT_EQ(1, connection_.GetStats().num_flow_label_changes);

  EXPECT_CALL(visitor_, OnForwardProgressMadeAfterFlowLabelChange());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  QuicAckFrame frame = InitAckFrame(last_packet);
  ProcessAckPacket(1, &frame);
  EXPECT_EQ(
      1, connection_.GetStats().num_forward_progress_after_flow_label_change);
}

TEST_P(QuicConnectionTest, NewReceiveNewFlowLabelWithGapChangesFlowLabel) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k1PTO);
  connection_options.push_back(kPTOS);
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_EQ(0, connection_.outgoing_flow_label());
  connection_.EnableBlackholeAvoidanceViaFlowLabel();
  static_cast<test::MockRandom*>(helper_->GetRandomGenerator())->ChangeValue();
  const uint32_t flow_label = connection_.outgoing_flow_label();
  EXPECT_NE(0, flow_label);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());

  // Receive the first packet to initialize the flow label.
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_INITIAL, 0);
  EXPECT_EQ(flow_label, connection_.outgoing_flow_label());

  // Receive the second packet with the same flow label
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_INITIAL, flow_label);
  EXPECT_EQ(flow_label, connection_.outgoing_flow_label());

  // Receive a packet with gap and a new flow label and verify the outgoing
  // flow label has changed.
  static_cast<test::MockRandom*>(helper_->GetRandomGenerator())->ChangeValue();
  ProcessDataPacketAtLevel(4, !kHasStopWaiting, ENCRYPTION_INITIAL,
                           flow_label + 1);
  EXPECT_NE(flow_label, connection_.outgoing_flow_label());
}

TEST_P(QuicConnectionTest,
       NewReceiveNewFlowLabelWithNoGapDoesNotChangeFlowLabel) {
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k1PTO);
  connection_options.push_back(kPTOS);
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_EQ(0, connection_.outgoing_flow_label());
  connection_.EnableBlackholeAvoidanceViaFlowLabel();
  static_cast<test::MockRandom*>(helper_->GetRandomGenerator())->ChangeValue();
  const uint32_t flow_label = connection_.outgoing_flow_label();
  EXPECT_NE(0, flow_label);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());

  // Receive the first packet to initialize the flow label.
  ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_INITIAL, 0);
  EXPECT_EQ(flow_label, connection_.outgoing_flow_label());

  // Receive the second packet with the same flow label
  ProcessDataPacketAtLevel(2, !kHasStopWaiting, ENCRYPTION_INITIAL, flow_label);
  EXPECT_EQ(flow_label, connection_.outgoing_flow_label());

  // Receive a packet with no gap and a new flow label and verify the outgoing
  // flow label has not changed.
  ProcessDataPacketAtLevel(3, !kHasStopWaiting, ENCRYPTION_INITIAL, flow_label);
  EXPECT_EQ(flow_label, connection_.outgoing_flow_label());
}

TEST_P(QuicConnectionTest, SendCoalescedPackets) {
  if (!connection_.version().CanSendCoalescedPackets()) {
    return;
  }
  MockQuicConnectionDebugVisitor debug_visitor;
  connection_.set_debug_visitor(&debug_visitor);
  EXPECT_CALL(debug_visitor, OnPacketSent(_, _, _, _, _, _, _, _, _)).Times(3);
  EXPECT_CALL(debug_visitor, OnCoalescedPacketSent(_, _)).Times(1);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
    connection_.SendCryptoDataWithString("foo", 0);
    // Verify this packet is on hold.
    EXPECT_EQ(0u, writer_->packets_write_attempts());

    connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                             std::make_unique<TaggingEncrypter>(0x02));
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
    connection_.SendCryptoDataWithString("bar", 3);
    EXPECT_EQ(0u, writer_->packets_write_attempts());

    connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                             std::make_unique<TaggingEncrypter>(0x03));
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    SendStreamDataToPeer(2, "baz", 3, NO_FIN, nullptr);
  }
  // Verify all 3 packets are coalesced in the same UDP datagram.
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
  // Verify the packet is padded to full.
  EXPECT_EQ(connection_.max_packet_length(), writer_->last_packet_size());

  // Verify packet process.
  EXPECT_EQ(1u, writer_->crypto_frames().size());
  EXPECT_EQ(0u, writer_->stream_frames().size());
  // Verify there is coalesced packet.
  EXPECT_NE(nullptr, writer_->coalesced_packet());
}

TEST_P(QuicConnectionTest, FailToCoalescePacket) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration() ||
      !connection_.version().CanSendCoalescedPackets() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }

  set_perspective(Perspective::IS_SERVER);

  auto test_body = [&] {
    EXPECT_CALL(visitor_,
                OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
        .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));

    ProcessDataPacketAtLevel(1, !kHasStopWaiting, ENCRYPTION_INITIAL);

    {
      QuicConnection::ScopedPacketFlusher flusher(&connection_);
      connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
      connection_.SendCryptoDataWithString("foo", 0);
      // Verify this packet is on hold.
      EXPECT_EQ(0u, writer_->packets_write_attempts());

      connection_.SetEncrypter(ENCRYPTION_HANDSHAKE,
                               std::make_unique<TaggingEncrypter>(0x02));
      connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
      connection_.SendCryptoDataWithString("bar", 3);
      EXPECT_EQ(0u, writer_->packets_write_attempts());

      connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                               std::make_unique<TaggingEncrypter>(0x03));
      connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
      SendStreamDataToPeer(2, "baz", 3, NO_FIN, nullptr);

      creator_->Flush();

      auto& coalesced_packet =
          QuicConnectionPeer::GetCoalescedPacket(&connection_);
      QuicPacketLength coalesced_packet_max_length =
          coalesced_packet.max_packet_length();
      QuicCoalescedPacketPeer::SetMaxPacketLength(coalesced_packet,
                                                  coalesced_packet.length());

      // Make the coalescer's FORWARD_SECURE packet longer.
      *QuicCoalescedPacketPeer::GetMutableEncryptedBuffer(
          coalesced_packet, ENCRYPTION_FORWARD_SECURE) += "!!! TEST !!!";

      QUIC_LOG(INFO) << "Reduced coalesced_packet_max_length from "
                     << coalesced_packet_max_length << " to "
                     << coalesced_packet.max_packet_length()
                     << ", coalesced_packet.length:"
                     << coalesced_packet.length()
                     << ", coalesced_packet.packet_lengths:"
                     << absl::StrJoin(coalesced_packet.packet_lengths(), ":");
    }

    EXPECT_FALSE(connection_.connected());
    EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
                IsError(QUIC_FAILED_TO_SERIALIZE_PACKET));
    EXPECT_EQ(saved_connection_close_frame_.error_details,
              "Failed to serialize coalesced packet.");
  };

  EXPECT_QUIC_BUG(test_body(), "SerializeCoalescedPacket failed.");
}

TEST_P(QuicConnectionTest, ClientReceivedHandshakeDone) {
  if (!connection_.version().UsesTls()) {
    return;
  }
  EXPECT_CALL(visitor_, OnHandshakeDoneReceived());
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicHandshakeDoneFrame()));
  frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
  ProcessFramesPacketAtLevel(1, frames, ENCRYPTION_FORWARD_SECURE);
}

TEST_P(QuicConnectionTest, ServerReceivedHandshakeDone) {
  if (!connection_.version().UsesTls()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  EXPECT_CALL(visitor_, OnHandshakeDoneReceived()).Times(0);
  if (version().handshake_protocol == PROTOCOL_TLS1_3) {
    EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  }
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  QuicFrames frames;
  frames.push_back(QuicFrame(QuicHandshakeDoneFrame()));
  frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
  ProcessFramesPacketAtLevel(1, frames, ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(IETF_QUIC_PROTOCOL_VIOLATION));
}

TEST_P(QuicConnectionTest, MultiplePacketNumberSpacePto) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  // Send handshake packet.
  connection_.SetEncrypter(
      ENCRYPTION_HANDSHAKE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_HANDSHAKE));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_CALL(visitor_, OnHandshakePacketSent()).Times(1);
  connection_.SendCryptoDataWithString("foo", 0, ENCRYPTION_HANDSHAKE);
  EXPECT_EQ(0x01010101u, writer_->final_bytes_of_last_packet());

  // Send application data.
  connection_.SendApplicationDataAtLevel(ENCRYPTION_FORWARD_SECURE, 5, "data",
                                         0, NO_FIN);
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
  QuicTime retransmission_time =
      connection_.GetRetransmissionAlarm()->deadline();
  EXPECT_NE(QuicTime::Zero(), retransmission_time);

  // Retransmit handshake data.
  clock_.AdvanceTime(retransmission_time - clock_.Now());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(4), _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify 1-RTT packet gets coalesced with handshake retransmission.
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());

  // Send application data.
  connection_.SendApplicationDataAtLevel(ENCRYPTION_FORWARD_SECURE, 5, "data",
                                         4, NO_FIN);
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
  retransmission_time = connection_.GetRetransmissionAlarm()->deadline();
  EXPECT_NE(QuicTime::Zero(), retransmission_time);

  // Retransmit handshake data again.
  clock_.AdvanceTime(retransmission_time - clock_.Now());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(9), _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(8), _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  // Verify 1-RTT packet gets coalesced with handshake retransmission.
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());

  // Discard handshake key.
  connection_.OnHandshakeComplete();
  retransmission_time = connection_.GetRetransmissionAlarm()->deadline();
  EXPECT_NE(QuicTime::Zero(), retransmission_time);

  // Retransmit application data.
  clock_.AdvanceTime(retransmission_time - clock_.Now());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(11), _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
}

void QuicConnectionTest::TestClientRetryHandling(
    bool invalid_retry_tag, bool missing_original_id_in_config,
    bool wrong_original_id_in_config, bool missing_retry_id_in_config,
    bool wrong_retry_id_in_config) {
  if (invalid_retry_tag) {
    ASSERT_FALSE(missing_original_id_in_config);
    ASSERT_FALSE(wrong_original_id_in_config);
    ASSERT_FALSE(missing_retry_id_in_config);
    ASSERT_FALSE(wrong_retry_id_in_config);
  } else {
    ASSERT_FALSE(missing_original_id_in_config && wrong_original_id_in_config);
    ASSERT_FALSE(missing_retry_id_in_config && wrong_retry_id_in_config);
  }
  if (!version().UsesTls()) {
    return;
  }

  // These values come from draft-ietf-quic-v2 Appendix A.4.
  uint8_t retry_packet_rfcv2[] = {
      0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
      0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0xc8, 0x64, 0x6c, 0xe8,
      0xbf, 0xe3, 0x39, 0x52, 0xd9, 0x55, 0x54, 0x36, 0x65, 0xdc, 0xc7, 0xb6};
  // These values come from RFC9001 Appendix A.4.
  uint8_t retry_packet_rfcv1[] = {
      0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
      0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
      0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba};
  uint8_t retry_packet29[] = {
      0xff, 0xff, 0x00, 0x00, 0x1d, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
      0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0xd1, 0x69, 0x26, 0xd8,
      0x1f, 0x6f, 0x9c, 0xa2, 0x95, 0x3a, 0x8a, 0xa4, 0x57, 0x5e, 0x1e, 0x49};

  uint8_t* retry_packet;
  size_t retry_packet_length;
  if (version() == ParsedQuicVersion::RFCv2()) {
    retry_packet = retry_packet_rfcv2;
    retry_packet_length = ABSL_ARRAYSIZE(retry_packet_rfcv2);
  } else if (version() == ParsedQuicVersion::RFCv1()) {
    retry_packet = retry_packet_rfcv1;
    retry_packet_length = ABSL_ARRAYSIZE(retry_packet_rfcv1);
  } else if (version() == ParsedQuicVersion::Draft29()) {
    retry_packet = retry_packet29;
    retry_packet_length = ABSL_ARRAYSIZE(retry_packet29);
  } else {
    // TODO(dschinazi) generate retry packets for all versions once we have
    // server-side support for generating these programmatically.
    return;
  }

  uint8_t original_connection_id_bytes[] = {0x83, 0x94, 0xc8, 0xf0,
                                            0x3e, 0x51, 0x57, 0x08};
  uint8_t new_connection_id_bytes[] = {0xf0, 0x67, 0xa5, 0x50,
                                       0x2a, 0x42, 0x62, 0xb5};
  uint8_t retry_token_bytes[] = {0x74, 0x6f, 0x6b, 0x65, 0x6e};

  QuicConnectionId original_connection_id(
      reinterpret_cast<char*>(original_connection_id_bytes),
      ABSL_ARRAYSIZE(original_connection_id_bytes));
  QuicConnectionId new_connection_id(
      reinterpret_cast<char*>(new_connection_id_bytes),
      ABSL_ARRAYSIZE(new_connection_id_bytes));

  std::string retry_token(reinterpret_cast<char*>(retry_token_bytes),
                          ABSL_ARRAYSIZE(retry_token_bytes));

  if (invalid_retry_tag) {
    // Flip the last bit of the retry packet to prevent the integrity tag
    // from validating correctly.
    retry_packet[retry_packet_length - 1] ^= 1;
  }

  QuicConnectionId config_original_connection_id = original_connection_id;
  if (wrong_original_id_in_config) {
    // Flip the first bit of the connection ID.
    ASSERT_FALSE(config_original_connection_id.IsEmpty());
    config_original_connection_id.mutable_data()[0] ^= 0x80;
  }
  QuicConnectionId config_retry_source_connection_id = new_connection_id;
  if (wrong_retry_id_in_config) {
    // Flip the first bit of the connection ID.
    ASSERT_FALSE(config_retry_source_connection_id.IsEmpty());
    config_retry_source_connection_id.mutable_data()[0] ^= 0x80;
  }

  // Make sure the connection uses the connection ID from the test vectors,
  QuicConnectionPeer::SetServerConnectionId(&connection_,
                                            original_connection_id);
  // Make sure our fake framer has the new post-retry INITIAL keys so that any
  // retransmission triggered by retry can be decrypted.
  writer_->framer()->framer()->SetInitialObfuscators(new_connection_id);

  // Process the RETRY packet.
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(reinterpret_cast<char*>(retry_packet),
                         retry_packet_length, clock_.Now()));

  if (invalid_retry_tag) {
    // Make sure we refuse to process a RETRY with invalid tag.
    EXPECT_FALSE(connection_.GetStats().retry_packet_processed);
    EXPECT_EQ(connection_.connection_id(), original_connection_id);
    EXPECT_TRUE(QuicPacketCreatorPeer::GetRetryToken(
                    QuicConnectionPeer::GetPacketCreator(&connection_))
                    .empty());
    return;
  }

  // Make sure we correctly parsed the RETRY.
  EXPECT_TRUE(connection_.GetStats().retry_packet_processed);
  EXPECT_EQ(connection_.connection_id(), new_connection_id);
  EXPECT_EQ(QuicPacketCreatorPeer::GetRetryToken(
                QuicConnectionPeer::GetPacketCreator(&connection_)),
            retry_token);

  // Test validating the original_connection_id from the config.
  QuicConfig received_config;
  QuicConfigPeer::SetNegotiated(&received_config, true);
  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &received_config, connection_.connection_id());
    if (!missing_retry_id_in_config) {
      QuicConfigPeer::SetReceivedRetrySourceConnectionId(
          &received_config, config_retry_source_connection_id);
    }
  }
  if (!missing_original_id_in_config) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &received_config, config_original_connection_id);
  }

  if (missing_original_id_in_config || wrong_original_id_in_config ||
      missing_retry_id_in_config || wrong_retry_id_in_config) {
    EXPECT_CALL(visitor_,
                OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
        .Times(1);
  } else {
    EXPECT_CALL(visitor_,
                OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
        .Times(0);
  }
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(AnyNumber());
  connection_.SetFromConfig(received_config);
  if (missing_original_id_in_config || wrong_original_id_in_config ||
      missing_retry_id_in_config || wrong_retry_id_in_config) {
    ASSERT_FALSE(connection_.connected());
    TestConnectionCloseQuicErrorCode(IETF_QUIC_PROTOCOL_VIOLATION);
  } else {
    EXPECT_TRUE(connection_.connected());
  }
}

TEST_P(QuicConnectionTest, FixTimeoutsClient) {
  if (!connection_.version().UsesTls()) {
    return;
  }
  set_perspective(Perspective::IS_CLIENT);
  if (GetQuicReloadableFlag(quic_fix_timeouts)) {
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_START));
  }
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kFTOE);
  config.SetConnectionOptionsToSend(connection_options);
  QuicConfigPeer::SetNegotiated(&config, true);
  QuicConfigPeer::SetReceivedOriginalConnectionId(&config,
                                                  connection_.connection_id());
  QuicConfigPeer::SetReceivedInitialSourceConnectionId(
      &config, connection_.connection_id());

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(1);
  connection_.SetFromConfig(config);
  QuicIdleNetworkDetector& idle_network_detector =
      QuicConnectionPeer::GetIdleNetworkDetector(&connection_);
  if (GetQuicReloadableFlag(quic_fix_timeouts)) {
    // Handshake timeout has not been removed yet.
    EXPECT_NE(idle_network_detector.handshake_timeout(),
              QuicTime::Delta::Infinite());
  } else {
    // Handshake timeout has been set to infinite.
    EXPECT_EQ(idle_network_detector.handshake_timeout(),
              QuicTime::Delta::Infinite());
  }
}

TEST_P(QuicConnectionTest, FixTimeoutsServer) {
  if (!connection_.version().UsesTls()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  if (GetQuicReloadableFlag(quic_fix_timeouts)) {
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_START));
  }
  QuicConfig config;
  quic::QuicTagVector initial_received_options;
  initial_received_options.push_back(quic::kFTOE);
  ASSERT_TRUE(
      config.SetInitialReceivedConnectionOptions(initial_received_options));
  QuicConfigPeer::SetNegotiated(&config, true);
  QuicConfigPeer::SetReceivedOriginalConnectionId(&config,
                                                  connection_.connection_id());
  QuicConfigPeer::SetReceivedInitialSourceConnectionId(&config,
                                                       QuicConnectionId());

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(1);
  connection_.SetFromConfig(config);
  QuicIdleNetworkDetector& idle_network_detector =
      QuicConnectionPeer::GetIdleNetworkDetector(&connection_);
  if (GetQuicReloadableFlag(quic_fix_timeouts)) {
    // Handshake timeout has not been removed yet.
    EXPECT_NE(idle_network_detector.handshake_timeout(),
              QuicTime::Delta::Infinite());
  } else {
    // Handshake timeout has been set to infinite.
    EXPECT_EQ(idle_network_detector.handshake_timeout(),
              QuicTime::Delta::Infinite());
  }
}

TEST_P(QuicConnectionTest, ClientParsesRetry) {
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);
}

TEST_P(QuicConnectionTest, ClientParsesRetryInvalidTag) {
  TestClientRetryHandling(/*invalid_retry_tag=*/true,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);
}

TEST_P(QuicConnectionTest, ClientParsesRetryMissingOriginalId) {
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/true,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);
}

TEST_P(QuicConnectionTest, ClientParsesRetryWrongOriginalId) {
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/true,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);
}

TEST_P(QuicConnectionTest, ClientParsesRetryMissingRetryId) {
  if (!connection_.version().UsesTls()) {
    // Versions that do not authenticate connection IDs never send the
    // retry_source_connection_id transport parameter.
    return;
  }
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/true,
                          /*wrong_retry_id_in_config=*/false);
}

TEST_P(QuicConnectionTest, ClientParsesRetryWrongRetryId) {
  if (!connection_.version().UsesTls()) {
    // Versions that do not authenticate connection IDs never send the
    // retry_source_connection_id transport parameter.
    return;
  }
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/true);
}

TEST_P(QuicConnectionTest, ClientRetransmitsInitialPacketsOnRetry) {
  if (!connection_.version().HasIetfQuicFrames()) {
    // TestClientRetryHandling() currently only supports IETF draft versions.
    return;
  }
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);

  connection_.SendCryptoStreamData();

  EXPECT_EQ(1u, writer_->packets_write_attempts());
  TestClientRetryHandling(/*invalid_retry_tag=*/false,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);

  // Verify that initial data is retransmitted immediately after receiving
  // RETRY.
  if (GetParam().ack_response == AckResponse::kImmediate) {
    EXPECT_EQ(2u, writer_->packets_write_attempts());
    EXPECT_EQ(1u, writer_->framer()->crypto_frames().size());
  }
}

TEST_P(QuicConnectionTest, NoInitialPacketsRetransmissionOnInvalidRetry) {
  if (!connection_.version().HasIetfQuicFrames()) {
    return;
  }
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);

  connection_.SendCryptoStreamData();

  EXPECT_EQ(1u, writer_->packets_write_attempts());
  TestClientRetryHandling(/*invalid_retry_tag=*/true,
                          /*missing_original_id_in_config=*/false,
                          /*wrong_original_id_in_config=*/false,
                          /*missing_retry_id_in_config=*/false,
                          /*wrong_retry_id_in_config=*/false);

  EXPECT_EQ(1u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, ClientReceivesOriginalConnectionIdWithoutRetry) {
  if (!connection_.version().UsesTls()) {
    // QUIC+TLS is required to transmit connection ID transport parameters.
    return;
  }
  if (connection_.version().UsesTls()) {
    // Versions that authenticate connection IDs always send the
    // original_destination_connection_id transport parameter.
    return;
  }
  // Make sure that receiving the original_destination_connection_id transport
  // parameter fails the handshake when no RETRY packet was received before it.
  QuicConfig received_config;
  QuicConfigPeer::SetNegotiated(&received_confi
```