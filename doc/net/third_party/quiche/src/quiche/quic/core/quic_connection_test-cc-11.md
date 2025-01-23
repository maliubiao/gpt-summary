Response:
The user wants to understand the functionality of the given C++ source code file, which is a test file for `QuicConnection` in Chromium's QUIC implementation.

Here's a breakdown of the thought process to analyze the provided code snippet:

1. **Identify the Core Purpose:** The file name `quic_connection_test.cc` immediately suggests that this file contains unit tests for the `QuicConnection` class. Unit tests verify the behavior of individual units of code, in this case, the `QuicConnection` class.

2. **Scan for Test Cases (TEST_P):** The code is structured around `TEST_P` macros, indicating parameterized tests. This means the same test logic is executed with different configurations or input values (likely different QUIC versions, as seen with `QUIC_TEST_P`).

3. **Analyze Individual Test Cases:** Go through each `TEST_P` block and try to understand what it's testing. Look for:
    * **Setup:**  Initialization of `QuicConnection`, setting expectations using `EXPECT_CALL`, and any initial data or configuration.
    * **Actions:** Simulating events like sending/receiving packets, timer expirations, and function calls to the `QuicConnection` object.
    * **Assertions:** Using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, etc., to verify the expected state or behavior of the `QuicConnection` after the actions.

4. **Group Related Tests:** Notice patterns and group tests by the feature they are testing. For example, several tests involve the "ping alarm," others involve "path challenge/response," and some focus on "message sending."

5. **Look for External Dependencies:** Identify the use of mock objects (`visitor_`, `send_algorithm_`, `loss_algorithm_`) which indicate interactions with other parts of the QUIC stack.

6. **Consider JavaScript Relevance:**  Think about how the tested QUIC functionality relates to web browsing and JavaScript interactions. QUIC is a transport protocol for HTTP/3, which underlies web requests made by browsers where JavaScript plays a key role. Focus on features like connection management, reliability, and security.

7. **Consider Logical Reasoning:**  If a test case seems to involve a cause-and-effect sequence, think about possible inputs and the expected outputs. For example, sending a data packet and then receiving an ACK should trigger certain internal states within the `QuicConnection`.

8. **Identify Potential User Errors:** Based on the tests, consider common mistakes a developer might make when using the `QuicConnection` API, or issues that might arise due to network conditions or misconfigurations.

9. **Trace User Actions:** Imagine a user interacting with a web page. How do those actions translate to QUIC connection states and events that might trigger the tested code paths?  Think about initial connection setup, data transfer, and potential network issues.

10. **Synthesize and Summarize:** Combine the understanding of individual tests into a higher-level summary of the file's functionality. Focus on the major aspects being tested.

**Applying the Process to the Snippet:**

* **Retransmittable On Wire Ping:** Tests aggressive pinging behavior when no data is being sent to keep the connection alive. This is related to connection management and preventing idle timeouts.
* **Retransmittable On Wire Ping Limit:**  Verifies a limit on the number of aggressive pings sent. This is about resource management and preventing excessive control traffic.
* **Stateless Reset Token:** Tests the validation of stateless reset tokens, a mechanism for abruptly terminating a connection. This is crucial for security and handling certain error scenarios.
* **Write Blocked with Invalid Ack:** Tests how the connection handles an invalid acknowledgment when the write buffer is full. This is related to flow control and error handling.
* **SendMessage:** Tests the functionality for sending messages using the DATAGRAM frame (in QUIC), including handling message size limits and congestion control. This directly relates to application-level data transfer.
* **GetCurrentLargestMessagePayload/GetGuaranteedLargestMessagePayload:** Tests the calculation of the maximum message size that can be sent without fragmentation. This is important for efficient data transfer.
* **LimitedLargestMessagePayload:** Tests the behavior when a limit is imposed on the maximum message size.
* **Server/Client Response to Path Challenge:** Tests the path validation mechanism using PATH_CHALLENGE and PATH_RESPONSE frames. This is essential for path migration and multi-path QUIC.
* **Restart Path Degrading Detection After Migration:** Tests how path degrading detection (detecting a poor network path) is restarted after a connection migration. This is about network performance and resilience.
* **ClientsResetCwndAfterConnectionMigration:** Tests that the congestion window (cwnd) is reset after a connection migration. This is important for congestion control after a path change.
* **DoNotScheduleSpuriousAckAlarm:** Tests a scenario where an ACK alarm should not be scheduled when the writer is blocked. This is an optimization to avoid unnecessary timer events.
* **DisablePacingOffloadConnectionOptions:** Tests the ability to disable pacing offload using connection options. Pacing offload is a performance optimization.
* **OrphanPathResponse:** Tests the handling of unexpected PATH_RESPONSE frames. This is part of security and protocol robustness.
* **AcceptPacketNumberZero:**  Tests the handling of packet number zero, especially during the initial handshake.
* **Multiple Packet Number Spaces:** Tests the functionality of using separate packet number spaces for different encryption levels (Initial, Handshake, Application). This is a key feature of QUIC for security and handshake separation.
* **PeerAcksPacketsInWrongPacketNumberSpace:** Tests the behavior when a peer sends acknowledgments in the wrong packet number space, which should lead to a connection error.
* **MultiplePacketNumberSpacesBasicReceiving/CancelAckAlarmOnWriteBlocked:** Further tests related to receiving packets in different packet number spaces and how ACK alarms interact with write blocking.

By following these steps, you can systematically analyze the code and arrive at a comprehensive understanding of its functionality and its relation to broader concepts.
This Chromium network stack source code file, located at `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`, is a **unit test file for the `QuicConnection` class**. Its primary function is to **thoroughly test the behavior and functionality of the `QuicConnection` class** under various conditions.

Here's a breakdown of its functions based on the provided code snippet:

**Core Functionality Being Tested (Based on the Snippet):**

1. **Retransmittable On-Wire Ping Mechanism:**
   - Tests how the connection sends PING frames when it hasn't sent other retransmittable data for a while (retransmittable-on-wire timeout).
   - Verifies that it uses an "aggressive" initial timeout and backs off the timeout if pings are not acknowledged.
   - Checks if receiving an ACK resets the aggressive ping counter.
   - **Concept:** Ensures the connection stays alive even with no active data transfer, preventing idle timeouts.

2. **Retransmittable On-Wire Ping Limit:**
   - Tests the maximum number of consecutive aggressive retransmittable-on-wire pings that will be sent before reverting to the normal ping timeout.
   - **Concept:** Prevents excessive control traffic if the peer is not responding.

3. **Stateless Reset Token Validation:**
   - Checks if the connection correctly validates stateless reset tokens received from the peer.
   - **Concept:** Security mechanism to allow a server to abruptly close a connection without maintaining per-connection state.

4. **Handling Write Blocking with Invalid Acks:**
   - Tests the scenario where the connection is blocked from writing data, and an invalid ACK packet is received.
   - **Concept:** Error handling and connection closure logic when faced with inconsistencies.

5. **Sending Messages (DATAGRAM Frames):**
   - Tests the functionality for sending application-layer messages using DATAGRAM frames (or MESSAGE frames in older QUIC versions).
   - Checks handling of message sizes, congestion control blocking, and fragmentation (if necessary).
   - **Concept:** Enables sending unreliable, unordered application data.

6. **Calculating Largest Message Payload:**
   - Tests the calculation of the maximum message payload size that can be sent in a single packet, considering protocol overhead.
   - **Concept:** Optimizing packet size to avoid fragmentation and improve efficiency.

7. **Path Challenge and Response (for IETF QUIC):**
   - Tests the logic for sending and receiving PATH_CHALLENGE and PATH_RESPONSE frames.
   - Verifies that the server responds to a PATH_CHALLENGE and the client responds on both the default and alternative sockets.
   - **Concept:** Mechanism to validate the reachability of the peer on a different network path, used for path migration.

8. **Restarting Path Degrading Detection after Migration:**
   - Tests that the mechanism for detecting a degrading network path (blackholing) is restarted after a successful connection migration.
   - **Concept:** Ensures continued monitoring of the network path even after switching to a new path.

9. **Resetting Congestion Window after Connection Migration:**
   - Verifies that the client's congestion window (cwnd) is reset after a connection migration.
   - **Concept:** Congestion control adjustment after a potential change in network conditions.

10. **Avoiding Spurious ACK Alarm Scheduling:**
   - Tests that the ACK alarm is not scheduled unnecessarily when the connection is write-blocked.
   - **Concept:** Optimization to avoid unnecessary timer events.

11. **Disabling Pacing Offload:**
   - Tests the ability to disable pacing offload (a feature for smoother packet sending) using connection options.
   - **Concept:** Configuration option for specific deployment scenarios.

12. **Handling Orphaned Path Responses:**
   - Tests the behavior when a PATH_RESPONSE frame is received without a corresponding PATH_CHALLENGE.
   - **Concept:** Robustness against unexpected or out-of-order packets.

13. **Accepting Packet Number Zero (for IETF QUIC):**
   - Tests the ability to process packets with packet number zero, especially during the initial handshake.
   - **Concept:** Necessary for IETF QUIC's packet numbering scheme.

14. **Multiple Packet Number Spaces (for newer QUIC versions):**
   - Tests the functionality of using different packet number spaces for different encryption levels (Initial, 0-RTT, Handshake, Application).
   - Verifies sending and receiving packets in different spaces, and handling acknowledgments for each space.
   - **Concept:** Enhanced security by isolating packet number spaces for different phases of the handshake.
   - Tests handling of invalid acknowledgments targeting the wrong packet number space.

15. **Canceling ACK Alarm on Write Blocked (with multiple packet number spaces):**
   - Similar to point 10, but specifically for scenarios involving multiple packet number spaces.

**Relationship to JavaScript:**

While this C++ code doesn't directly execute JavaScript, it's fundamental to how a web browser (which executes JavaScript) communicates over the internet using QUIC.

* **Data Transfer:** The `SendMessage` tests directly relate to how JavaScript running in a browser can send data to a server. When a JavaScript application makes an HTTP/3 request, the underlying browser implementation uses `QuicConnection` to send the data.
* **Reliability and Performance:** The tests for retransmittable pings, path challenges, and congestion control mechanisms ensure reliable and efficient data delivery, which directly impacts the performance and responsiveness of web applications interacting with JavaScript.
* **Security:** The stateless reset token validation and multiple packet number space tests are crucial for the security of the QUIC connection, protecting user data during web browsing initiated by JavaScript.
* **Network Changes:** The path migration tests are relevant to how browsers handle network changes (e.g., switching from Wi-Fi to cellular) without interrupting the user experience, which JavaScript applications running in the browser benefit from.

**Examples of Logical Reasoning (Hypothetical):**

**Hypothetical Input (for Retransmittable On-Wire Ping):**

* **Input:** A `QuicConnection` becomes idle after sending some initial data. The retransmittable-on-wire timer expires.
* **Expected Output:** The `QuicConnection` sends a PING frame to the peer.

**Hypothetical Input (for Stateless Reset Token Validation):**

* **Input:** The `QuicConnection` receives a packet containing a CONNECTION_CLOSE frame with a stateless reset token.
* **Expected Output:** The `QuicConnection` checks if the received token matches the expected token. If it matches, the connection is closed immediately.

**Common User or Programming Errors:**

* **Incorrectly handling `MESSAGE_STATUS_BLOCKED`:** A developer might try to send a message without checking if the connection is currently congestion-controlled, leading to dropped messages.
* **Not understanding message size limits:** Trying to send a message larger than `GetCurrentLargestMessagePayload()` without proper fragmentation handling.
* **Misinterpreting stateless reset tokens:** A server implementation might generate or validate stateless reset tokens incorrectly, leading to unexpected connection closures.
* **Incorrectly configuring connection options:**  For example, trying to enable pacing offload on a network that doesn't support it.

**User Operation Steps to Reach This Code (Debugging Clues):**

Imagine a user browsing a website that uses HTTP/3 (which relies on QUIC):

1. **User opens a website:** The user types a URL in the browser or clicks a link.
2. **Browser initiates a QUIC connection:** The browser determines that the server supports HTTP/3 and initiates a QUIC connection. This involves setting up a `QuicConnection` object.
3. **Initial handshake:** The browser and server exchange handshake packets to establish encryption and other parameters. The multiple packet number space tests are relevant here.
4. **Data transfer:** The browser (via JavaScript) makes requests for web page resources (HTML, CSS, images, etc.). These requests are sent as data over the QUIC connection, potentially using `SendMessage` for unreliable data.
5. **Idle connection:** If the user pauses interaction with the website, the connection might become idle, triggering the retransmittable-on-wire ping mechanism to keep it alive.
6. **Network change:** If the user moves their device from one network to another (e.g., Wi-Fi to cellular), the path migration mechanisms tested here come into play.
7. **Server-side reset:** If the server needs to abruptly close the connection without maintaining state, it might send a CONNECTION_CLOSE with a stateless reset token, which is tested in the stateless reset token validation tests.
8. **Errors and debugging:** If something goes wrong during any of these steps, developers might need to debug the QUIC connection, potentially stepping through the `QuicConnection` code and relying on these unit tests to understand expected behavior.

**Summary of Functionality (Part 12 of 24):**

This specific section of the `quic_connection_test.cc` file focuses on testing **connection keep-alive mechanisms (retransmittable pings), security features (stateless reset tokens), message sending functionality, path validation and migration, and congestion control adjustments after migration**. It also includes tests for error handling, optimization of alarm scheduling, and specific protocol features like multiple packet number spaces (critical for newer QUIC versions). Essentially, it's a deep dive into crucial aspects of maintaining a healthy, secure, and performant QUIC connection.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
imateNow());
  }

  // Process a data packet.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacket(peer_creator_.packet_number() + 1);
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_,
                                         peer_creator_.packet_number() + 1);
  EXPECT_EQ(initial_retransmittable_on_wire_timeout,
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
  clock_.AdvanceTime(initial_retransmittable_on_wire_timeout);
  connection_.GetPingAlarm()->Fire();

  // Verify the count of consecutive aggressive pings is reset.
  for (int i = 0; i < max_aggressive_retransmittable_on_wire_ping_count; i++) {
    // Receive an ACK of the previous packet. This should set the ping alarm
    // with the initial retransmittable-on-wire timeout.
    const QuicPacketNumber ack_num = creator_->packet_number();
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
    // Advance 5ms to receive next packet.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  }

  // Receive another ACK for the previous PING. This should set the
  // ping alarm with backed off retransmittable-on-wire timeout.
  {
    const QuicPacketNumber ack_num = creator_->packet_number();
    QuicAckFrame frame = InitAckFrame(
        {{QuicPacketNumber(ack_num), QuicPacketNumber(ack_num + 1)}});
    ProcessAckPacket(&frame);
    EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
    EXPECT_EQ(initial_retransmittable_on_wire_timeout * 2,
              connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
  }

  writer_->Reset();
  clock_.AdvanceTime(2 * initial_retransmittable_on_wire_timeout);
  connection_.GetPingAlarm()->Fire();

  // Process another data packet and a new ACK packet. The ping alarm is set
  // with aggressive ping timeout again.
  {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    ProcessDataPacket(peer_creator_.packet_number() + 1);
    QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_,
                                           peer_creator_.packet_number() + 1);
    const QuicPacketNumber ack_num = creator_->packet_number();
    QuicAckFrame frame = InitAckFrame(
        {{QuicPacketNumber(ack_num), QuicPacketNumber(ack_num + 1)}});
    ProcessAckPacket(&frame);
    EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
    EXPECT_EQ(initial_retransmittable_on_wire_timeout,
              connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
  }
}

// Make sure that we never send more retransmissible on the wire pings than
// the limit in FLAGS_quic_max_retransmittable_on_wire_ping_count.
TEST_P(QuicConnectionTest, RetransmittableOnWirePingLimit) {
  static constexpr int kMaxRetransmittableOnWirePingCount = 3;
  SetQuicFlag(quic_max_retransmittable_on_wire_ping_count,
              kMaxRetransmittableOnWirePingCount);
  static constexpr QuicTime::Delta initial_retransmittable_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(200);
  static constexpr QuicTime::Delta short_delay =
      QuicTime::Delta::FromMilliseconds(5);
  ASSERT_LT(short_delay * 10, initial_retransmittable_on_wire_timeout);
  connection_.set_initial_retransmittable_on_wire_timeout(
      initial_retransmittable_on_wire_timeout);

  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));

  const char data[] = "data";
  // Advance 5ms, send a retransmittable data packet to the peer.
  clock_.AdvanceTime(short_delay);
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
  for (int i = 0; i <= kMaxRetransmittableOnWirePingCount; i++) {
    // Receive an ACK of the previous packet. This should set the ping alarm
    // with the initial retransmittable-on-wire timeout.
    clock_.AdvanceTime(short_delay);
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

  // Receive an ACK of the previous packet. This should set the ping alarm
  // but this time with the default ping timeout.
  QuicPacketNumber ack_num = creator_->packet_number();
  QuicAckFrame frame = InitAckFrame(
      {{QuicPacketNumber(ack_num), QuicPacketNumber(ack_num + 1)}});
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            connection_.GetPingAlarm()->deadline() - clock_.ApproximateNow());
}

TEST_P(QuicConnectionTest, ValidStatelessResetToken) {
  const StatelessResetToken kTestToken{0, 1, 0, 1, 0, 1, 0, 1,
                                       0, 1, 0, 1, 0, 1, 0, 1};
  const StatelessResetToken kWrongTestToken{0, 1, 0, 1, 0, 1, 0, 1,
                                            0, 1, 0, 1, 0, 1, 0, 2};
  QuicConfig config;
  // No token has been received.
  EXPECT_FALSE(connection_.IsValidStatelessResetToken(kTestToken));

  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(2);
  // Token is different from received token.
  QuicConfigPeer::SetReceivedStatelessResetToken(&config, kTestToken);
  connection_.SetFromConfig(config);
  EXPECT_FALSE(connection_.IsValidStatelessResetToken(kWrongTestToken));

  QuicConfigPeer::SetReceivedStatelessResetToken(&config, kTestToken);
  connection_.SetFromConfig(config);
  EXPECT_TRUE(connection_.IsValidStatelessResetToken(kTestToken));
}

TEST_P(QuicConnectionTest, WriteBlockedWithInvalidAck) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _)).Times(0);
  BlockOnNextWrite();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(5, "foo", 0, FIN);
  // This causes connection to be closed because packet 1 has not been sent yet.
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _, _, _, _));
  ProcessAckPacket(1, &frame);
  EXPECT_EQ(0, connection_close_frame_count_);
}

TEST_P(QuicConnectionTest, SendMessage) {
  if (connection_.version().UsesTls()) {
    QuicConfig config;
    QuicConfigPeer::SetReceivedMaxDatagramFrameSize(
        &config, kMaxAcceptedDatagramFrameSize);
    EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
    connection_.SetFromConfig(config);
  }
  std::string message(connection_.GetCurrentLargestMessagePayload() * 2, 'a');
  quiche::QuicheMemSlice slice;
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SendStreamData3();
    // Send a message which cannot fit into current open packet, and 2 packets
    // get sent, one contains stream frame, and the other only contains the
    // message frame.
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
    slice = MemSliceFromString(absl::string_view(
        message.data(), connection_.GetCurrentLargestMessagePayload()));
    EXPECT_EQ(MESSAGE_STATUS_SUCCESS,
              connection_.SendMessage(1, absl::MakeSpan(&slice, 1), false));
  }
  // Fail to send a message if connection is congestion control blocked.
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillOnce(Return(false));
  slice = MemSliceFromString("message");
  EXPECT_EQ(MESSAGE_STATUS_BLOCKED,
            connection_.SendMessage(2, absl::MakeSpan(&slice, 1), false));

  // Always fail to send a message which cannot fit into one packet.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  slice = MemSliceFromString(absl::string_view(
      message.data(), connection_.GetCurrentLargestMessagePayload() + 1));
  EXPECT_EQ(MESSAGE_STATUS_TOO_LARGE,
            connection_.SendMessage(3, absl::MakeSpan(&slice, 1), false));
}

TEST_P(QuicConnectionTest, GetCurrentLargestMessagePayload) {
  QuicPacketLength expected_largest_payload = 1215;
  if (connection_.version().SendsVariableLengthPacketNumberInLongHeader()) {
    expected_largest_payload += 3;
  }
  if (connection_.version().HasLongHeaderLengths()) {
    expected_largest_payload -= 2;
  }
  if (connection_.version().HasLengthPrefixedConnectionIds()) {
    expected_largest_payload -= 1;
  }
  if (connection_.version().UsesTls()) {
    // QUIC+TLS disallows DATAGRAM/MESSAGE frames before the handshake.
    EXPECT_EQ(connection_.GetCurrentLargestMessagePayload(), 0);
    QuicConfig config;
    QuicConfigPeer::SetReceivedMaxDatagramFrameSize(
        &config, kMaxAcceptedDatagramFrameSize);
    EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
    connection_.SetFromConfig(config);
    // Verify the value post-handshake.
    EXPECT_EQ(connection_.GetCurrentLargestMessagePayload(),
              expected_largest_payload);
  } else {
    EXPECT_EQ(connection_.GetCurrentLargestMessagePayload(),
              expected_largest_payload);
  }
}

TEST_P(QuicConnectionTest, GetGuaranteedLargestMessagePayload) {
  QuicPacketLength expected_largest_payload = 1215;
  if (connection_.version().HasLongHeaderLengths()) {
    expected_largest_payload -= 2;
  }
  if (connection_.version().HasLengthPrefixedConnectionIds()) {
    expected_largest_payload -= 1;
  }
  if (connection_.version().UsesTls()) {
    // QUIC+TLS disallows DATAGRAM/MESSAGE frames before the handshake.
    EXPECT_EQ(connection_.GetGuaranteedLargestMessagePayload(), 0);
    QuicConfig config;
    QuicConfigPeer::SetReceivedMaxDatagramFrameSize(
        &config, kMaxAcceptedDatagramFrameSize);
    EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
    connection_.SetFromConfig(config);
    // Verify the value post-handshake.
    EXPECT_EQ(connection_.GetGuaranteedLargestMessagePayload(),
              expected_largest_payload);
  } else {
    EXPECT_EQ(connection_.GetGuaranteedLargestMessagePayload(),
              expected_largest_payload);
  }
}

TEST_P(QuicConnectionTest, LimitedLargestMessagePayload) {
  if (!connection_.version().UsesTls()) {
    return;
  }
  constexpr QuicPacketLength kFrameSizeLimit = 1000;
  constexpr QuicPacketLength kPayloadSizeLimit =
      kFrameSizeLimit - kQuicFrameTypeSize;
  // QUIC+TLS disallows DATAGRAM/MESSAGE frames before the handshake.
  EXPECT_EQ(connection_.GetCurrentLargestMessagePayload(), 0);
  EXPECT_EQ(connection_.GetGuaranteedLargestMessagePayload(), 0);
  QuicConfig config;
  QuicConfigPeer::SetReceivedMaxDatagramFrameSize(&config, kFrameSizeLimit);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  // Verify the value post-handshake.
  EXPECT_EQ(connection_.GetCurrentLargestMessagePayload(), kPayloadSizeLimit);
  EXPECT_EQ(connection_.GetGuaranteedLargestMessagePayload(),
            kPayloadSizeLimit);
}

// Test to check that the path challenge/path response logic works
// correctly. This test is only for version-99
TEST_P(QuicConnectionTest, ServerResponseToPathChallenge) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);
  QuicConnectionPeer::SetAddressValidated(&connection_);
  // First check if the server can send probing packet.
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  // Create and send the probe request (PATH_CHALLENGE frame).
  // SendConnectivityProbingPacket ends up calling
  // TestPacketWriter::WritePacket() which in turns receives and parses the
  // packet by calling framer_.ProcessPacket() -- which in turn calls
  // SimpleQuicFramer::OnPathChallengeFrame(). SimpleQuicFramer saves
  // the packet in writer_->path_challenge_frames()
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendConnectivityProbingPacket(writer_.get(),
                                            connection_.peer_address());
  // Save the random contents of the challenge for later comparison to the
  // response.
  ASSERT_GE(writer_->path_challenge_frames().size(), 1u);
  QuicPathFrameBuffer challenge_data =
      writer_->path_challenge_frames().front().data_buffer;

  // Normally, QuicConnection::OnPathChallengeFrame and OnPaddingFrame would be
  // called and it will perform actions to ensure that the rest of the protocol
  // is performed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_TRUE(connection_.OnPathChallengeFrame(
      writer_->path_challenge_frames().front()));
  EXPECT_TRUE(connection_.OnPaddingFrame(writer_->padding_frames().front()));
  creator_->FlushCurrentPacket();

  // The final check is to ensure that the random data in the response matches
  // the random data from the challenge.
  EXPECT_EQ(1u, writer_->path_response_frames().size());
  EXPECT_EQ(0, memcmp(&challenge_data,
                      &(writer_->path_response_frames().front().data_buffer),
                      sizeof(challenge_data)));
}

TEST_P(QuicConnectionTest, ClientResponseToPathChallengeOnDefaulSocket) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  // First check if the client can send probing packet.
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  // Create and send the probe request (PATH_CHALLENGE frame).
  // SendConnectivityProbingPacket ends up calling
  // TestPacketWriter::WritePacket() which in turns receives and parses the
  // packet by calling framer_.ProcessPacket() -- which in turn calls
  // SimpleQuicFramer::OnPathChallengeFrame(). SimpleQuicFramer saves
  // the packet in writer_->path_challenge_frames()
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendConnectivityProbingPacket(writer_.get(),
                                            connection_.peer_address());
  // Save the random contents of the challenge for later validation against the
  // response.
  ASSERT_GE(writer_->path_challenge_frames().size(), 1u);
  QuicPathFrameBuffer challenge_data =
      writer_->path_challenge_frames().front().data_buffer;

  // Normally, QuicConnection::OnPathChallengeFrame would be
  // called and it will perform actions to ensure that the rest of the protocol
  // is performed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_TRUE(connection_.OnPathChallengeFrame(
      writer_->path_challenge_frames().front()));
  EXPECT_TRUE(connection_.OnPaddingFrame(writer_->padding_frames().front()));
  creator_->FlushCurrentPacket();

  // The final check is to ensure that the random data in the response matches
  // the random data from the challenge.
  EXPECT_EQ(1u, writer_->path_response_frames().size());
  EXPECT_EQ(0, memcmp(&challenge_data,
                      &(writer_->path_response_frames().front().data_buffer),
                      sizeof(challenge_data)));
}

TEST_P(QuicConnectionTest, ClientResponseToPathChallengeOnAlternativeSocket) {
  if (!VersionHasIetfQuicFrames(connection_.version().transport_version)) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  QuicSocketAddress kNewSelfAddress(QuicIpAddress::Loopback6(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(1u, new_writer.packets_write_attempts());
        EXPECT_EQ(1u, new_writer.path_challenge_frames().size());
        EXPECT_EQ(1u, new_writer.padding_frames().size());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }));
  bool success = false;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), &new_writer),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);

  // Receiving a PATH_CHALLENGE on the alternative path. Response to this
  // PATH_CHALLENGE should be sent via the alternative writer.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .Times(AtLeast(1u))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(2u, new_writer.packets_write_attempts());
        EXPECT_EQ(1u, new_writer.path_response_frames().size());
        EXPECT_EQ(1u, new_writer.padding_frames().size());
        EXPECT_EQ(kNewSelfAddress.host(),
                  new_writer.last_write_source_address());
      }))
      .WillRepeatedly(DoDefault());
  ;
  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  ProcessReceivedPacket(kNewSelfAddress, kPeerAddress, *received);

  QuicSocketAddress kNewerSelfAddress(QuicIpAddress::Loopback6(),
                                      /*port=*/34567);
  // Receiving a PATH_CHALLENGE on an unknown socket should be ignored.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0u);
  ProcessReceivedPacket(kNewerSelfAddress, kPeerAddress, *received);
}

TEST_P(QuicConnectionTest,
       RestartPathDegradingDetectionAfterMigrationWithProbe) {
  if (!version().HasIetfQuicFrames() &&
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  PathProbeTestInit(Perspective::IS_CLIENT);

  // Send data and verify the path degrading detection is set.
  const char data[] = "data";
  size_t data_size = strlen(data);
  QuicStreamOffset offset = 0;
  connection_.SendStreamDataWithString(1, data, offset, NO_FIN);
  offset += data_size;

  // Verify the path degrading detection is in progress.
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
  EXPECT_FALSE(connection_.IsPathDegrading());
  QuicTime ddl = connection_.GetBlackholeDetectorAlarm()->deadline();

  // Simulate the firing of path degrading.
  clock_.AdvanceTime(ddl - clock_.ApproximateNow());
  EXPECT_CALL(visitor_, OnPathDegrading()).Times(1);
  connection_.PathDegradingTimeout();
  EXPECT_TRUE(connection_.IsPathDegrading());
  EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());

  if (!GetParam().version.HasIetfQuicFrames()) {
    // Simulate path degrading handling by sending a probe on an alternet path.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    TestPacketWriter probing_writer(version(), &clock_, Perspective::IS_CLIENT);
    connection_.SendConnectivityProbingPacket(&probing_writer,
                                              connection_.peer_address());
    // Verify that path degrading detection is not reset.
    EXPECT_FALSE(connection_.PathDegradingDetectionInProgress());

    // Simulate successful path degrading handling by receiving probe response.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));

    EXPECT_CALL(visitor_,
                OnPacketReceived(_, _, /*is_connectivity_probe=*/true))
        .Times(1);
    const QuicSocketAddress kNewSelfAddress =
        QuicSocketAddress(QuicIpAddress::Loopback6(), /*port=*/23456);

    std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();
    std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
        QuicEncryptedPacket(probing_packet->encrypted_buffer,
                            probing_packet->encrypted_length),
        clock_.Now()));
    uint64_t num_probing_received =
        connection_.GetStats().num_connectivity_probing_received;
    ProcessReceivedPacket(kNewSelfAddress, kPeerAddress, *received);

    EXPECT_EQ(num_probing_received +
                  (GetQuicReloadableFlag(quic_ignore_gquic_probing) ? 0u : 1u),
              connection_.GetStats().num_connectivity_probing_received);
    EXPECT_EQ(kPeerAddress, connection_.peer_address());
    EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
    EXPECT_TRUE(connection_.IsPathDegrading());
  }

  // Verify new path degrading detection is activated.
  EXPECT_CALL(visitor_, OnForwardProgressMadeAfterPathDegrading()).Times(1);
  connection_.OnSuccessfulMigration(/*is_port_change*/ true);
  EXPECT_FALSE(connection_.IsPathDegrading());
  EXPECT_TRUE(connection_.PathDegradingDetectionInProgress());
}

TEST_P(QuicConnectionTest, ClientsResetCwndAfterConnectionMigration) {
  if (!GetParam().version.HasIetfQuicFrames()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  PathProbeTestInit(Perspective::IS_CLIENT);
  EXPECT_EQ(kSelfAddress, connection_.self_address());

  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  QuicTime::Delta default_init_rtt = rtt_stats->initial_rtt();
  rtt_stats->set_initial_rtt(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt());

  QuicSentPacketManagerPeer::SetConsecutivePtoCount(manager_, 1);
  EXPECT_EQ(1u, manager_->GetConsecutivePtoCount());
  const SendAlgorithmInterface* send_algorithm = manager_->GetSendAlgorithm();

  // Migrate to a new address with different IP.
  const QuicSocketAddress kNewSelfAddress =
      QuicSocketAddress(QuicIpAddress::Loopback4(), /*port=*/23456);
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  connection_.MigratePath(kNewSelfAddress, connection_.peer_address(),
                          &new_writer, false);
  EXPECT_EQ(default_init_rtt, manager_->GetRttStats()->initial_rtt());
  EXPECT_EQ(0u, manager_->GetConsecutivePtoCount());
  EXPECT_NE(send_algorithm, manager_->GetSendAlgorithm());
}

// Regression test for b/110259444
TEST_P(QuicConnectionTest, DoNotScheduleSpuriousAckAlarm) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(1));
  writer_->SetWriteBlocked();

  ProcessPacket(1);
  // Verify ack alarm is set.
  EXPECT_TRUE(connection_.HasPendingAcks());
  // Fire the ack alarm, verify no packet is sent because the writer is blocked.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.GetAckAlarm()->Fire();

  writer_->SetWritable();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessPacket(2);
  // Verify ack alarm is not set.
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, DisablePacingOffloadConnectionOptions) {
  EXPECT_FALSE(QuicConnectionPeer::SupportsReleaseTime(&connection_));
  writer_->set_supports_release_time(true);
  QuicConfig config;
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  EXPECT_TRUE(QuicConnectionPeer::SupportsReleaseTime(&connection_));

  QuicTagVector connection_options;
  connection_options.push_back(kNPCO);
  config.SetConnectionOptionsToSend(connection_options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  connection_.SetFromConfig(config);
  // Verify pacing offload is disabled.
  EXPECT_FALSE(QuicConnectionPeer::SupportsReleaseTime(&connection_));
}

// Regression test for b/110259444
// Get a path response without having issued a path challenge...
TEST_P(QuicConnectionTest, OrphanPathResponse) {
  QuicPathFrameBuffer data = {{0, 1, 2, 3, 4, 5, 6, 7}};

  QuicPathResponseFrame frame(99, data);
  EXPECT_TRUE(connection_.OnPathResponseFrame(frame));
  // If PATH_RESPONSE was accepted (payload matches the payload saved
  // in QuicConnection::transmitted_connectivity_probe_payload_) then
  // current_packet_content_ would be set to FIRST_FRAME_IS_PING.
  // Since this PATH_RESPONSE does not match, current_packet_content_
  // must not be FIRST_FRAME_IS_PING.
  EXPECT_NE(QuicConnection::FIRST_FRAME_IS_PING,
            QuicConnectionPeer::GetCurrentPacketContent(&connection_));
}

TEST_P(QuicConnectionTest, AcceptPacketNumberZero) {
  if (!VersionHasIetfQuicFrames(version().transport_version)) {
    return;
  }
  // Set first_sending_packet_number to be 0 to allow successfully processing
  // acks which ack packet number 0.
  QuicFramerPeer::SetFirstSendingPacketNumber(writer_->framer()->framer(), 0);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(0);
  EXPECT_EQ(QuicPacketNumber(0), LargestAcked(connection_.ack_frame()));
  EXPECT_EQ(1u, connection_.ack_frame().packets.NumIntervals());

  ProcessPacket(1);
  EXPECT_EQ(QuicPacketNumber(1), LargestAcked(connection_.ack_frame()));
  EXPECT_EQ(1u, connection_.ack_frame().packets.NumIntervals());

  ProcessPacket(2);
  EXPECT_EQ(QuicPacketNumber(2), LargestAcked(connection_.ack_frame()));
  EXPECT_EQ(1u, connection_.ack_frame().packets.NumIntervals());
}

TEST_P(QuicConnectionTest, MultiplePacketNumberSpacesBasicSending) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  connection_.SendCryptoStreamData();
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  QuicAckFrame frame1 = InitAckFrame(1);
  // Received ACK for packet 1.
  ProcessFramePacketAtLevel(30, QuicFrame(&frame1), ENCRYPTION_INITIAL);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(4);
  connection_.SendApplicationDataAtLevel(ENCRYPTION_ZERO_RTT, 5, "data", 0,
                                         NO_FIN);
  connection_.SendApplicationDataAtLevel(ENCRYPTION_ZERO_RTT, 5, "data", 4,
                                         NO_FIN);
  connection_.SendApplicationDataAtLevel(ENCRYPTION_FORWARD_SECURE, 5, "data",
                                         8, NO_FIN);
  connection_.SendApplicationDataAtLevel(ENCRYPTION_FORWARD_SECURE, 5, "data",
                                         12, FIN);
  // Received ACK for packets 2, 4, 5.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  QuicAckFrame frame2 =
      InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(3)},
                    {QuicPacketNumber(4), QuicPacketNumber(6)}});
  // Make sure although the same packet number is used, but they are in
  // different packet number spaces.
  ProcessFramePacketAtLevel(30, QuicFrame(&frame2), ENCRYPTION_FORWARD_SECURE);
}

TEST_P(QuicConnectionTest, PeerAcksPacketsInWrongPacketNumberSpace) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<TaggingEncrypter>(0x01));

  connection_.SendCryptoStreamData();
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  QuicAckFrame frame1 = InitAckFrame(1);
  // Received ACK for packet 1.
  ProcessFramePacketAtLevel(30, QuicFrame(&frame1), ENCRYPTION_INITIAL);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  connection_.SendApplicationDataAtLevel(ENCRYPTION_ZERO_RTT, 5, "data", 0,
                                         NO_FIN);
  connection_.SendApplicationDataAtLevel(ENCRYPTION_ZERO_RTT, 5, "data", 4,
                                         NO_FIN);

  // Received ACK for packets 2 and 3 in wrong packet number space.
  QuicAckFrame invalid_ack =
      InitAckFrame({{QuicPacketNumber(2), QuicPacketNumber(4)}});
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  ProcessFramePacketAtLevel(300, QuicFrame(&invalid_ack), ENCRYPTION_INITIAL);
  TestConnectionCloseQuicErrorCode(QUIC_INVALID_ACK_DATA);
}

TEST_P(QuicConnectionTest, MultiplePacketNumberSpacesBasicReceiving) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Receives packet 1000 in initial data.
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());
  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  SetDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  // Receives packet 1000 in application data.
  ProcessDataPacketAtLevel(1000, false, ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.HasPendingAcks());
  connection_.SendApplicationDataAtLevel(ENCRYPTION_FORWARD_SECURE, 5, "data",
                                         0, NO_FIN);
  // Verify application data ACK gets bundled with outgoing data.
  EXPECT_EQ(2u, writer_->frame_count());
  // Make sure ACK alarm is still set because initial data is not ACKed.
  EXPECT_TRUE(connection_.HasPendingAcks());
  // Receive packet 1001 in application data.
  ProcessDataPacketAtLevel(1001, false, ENCRYPTION_FORWARD_SECURE);
  clock_.AdvanceTime(DefaultRetransmissionTime());
  // Simulates ACK alarm fires and verify two ACKs are flushed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  connection_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  connection_.GetAckAlarm()->Fire();
  EXPECT_FALSE(connection_.HasPendingAcks());
  // Receives more packets in application data.
  ProcessDataPacketAtLevel(1002, false, ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.HasPendingAcks());

  // Verify zero rtt and forward secure packets get acked in the same packet.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  ProcessDataPacket(1003);
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, CancelAckAlarmOnWriteBlocked) {
  if (!connection_.SupportsMultiplePacketNumberSpaces()) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
  // Receives packet 1000 in initial data.
  ProcessCryptoPacketAtLevel(1000, ENCRYPTION_INITIAL);
  EXPECT_TRUE(connection_.HasPendingAcks());
  peer_framer_.SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  SetDecrypter(ENCRYPTION_ZERO_RTT,
               std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  // Receives packet 1000 in application data.
  ProcessDataPacketAtLevel(1000, false, ENCRYPTION_ZERO_RTT);
  EXP
```