Response:
The user is asking for a summary of the functionality of the `quic_connection_test.cc` file in the Chromium network stack. They are also interested in any relationships to JavaScript, logical reasoning examples (with input/output), common user/programming errors, and debugging tips related to this file.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The filename `quic_connection_test.cc` strongly suggests that this file contains unit tests for the `QuicConnection` class. This class is a central component in the QUIC implementation, managing the state and behavior of a single QUIC connection.

2. **Analyze the provided code snippet:** The code heavily uses Google Test (`TEST_P`, `EXPECT_CALL`, `ASSERT_EQ`, etc.) and mock objects (`MockSendAlgorithm`, `MockQuicConnectionVisitor`). This confirms the unit testing nature of the file. The specific tests in the snippet focus on:
    * Connection migration (changing the peer's IP address or port).
    * Path validation (verifying reachability of a new path).
    * Connection ID management (issuing, retiring, and handling new connection IDs).

3. **Generalize the functionalities:** Based on the code and the name of the file, the core functionalities being tested are likely to include:
    * **Connection Establishment and Tear-down:** While not explicitly shown in the snippet, this is a fundamental aspect of any connection management.
    * **Data Transmission and Reception:**  The presence of `OnStreamFrame` indicates testing of how data is handled.
    * **Flow Control:**  Managing the rate of data transmission.
    * **Congestion Control:** Adapting the sending rate based on network conditions.
    * **Error Handling:** How the connection reacts to various errors.
    * **Security:** While not the primary focus of the snippet, QUIC inherently involves encryption and authentication.
    * **Connection Migration:**  As seen in the snippet, this is a key feature of QUIC.
    * **Path Validation:** Also prominent in the snippet, ensuring reachability.
    * **Connection ID Management:**  The snippet heavily tests this.

4. **Consider the JavaScript relationship:**  QUIC is a transport protocol, and while JavaScript doesn't directly implement it at the OS level, it interacts with QUIC through browser APIs. The most relevant connection is the `fetch` API and WebSockets, which can utilize QUIC when available.

5. **Develop logical reasoning examples:**  Choose a specific test scenario from the snippet and illustrate it with concrete input and output. Connection migration is a good choice due to its complexity.

6. **Identify common user/programming errors:** Think about mistakes developers might make when interacting with or implementing QUIC connections, especially related to the functionalities being tested.

7. **Explain how a user might reach this code (debugging):** Trace the user actions from a high-level interaction (like opening a webpage) down to the QUIC connection handling in the browser.

8. **Summarize the functionality (for part 20 of 24):**  Since it's part 20, it's likely focusing on more advanced features. Connection migration and connection ID management fit this description.

9. **Structure the response:** Organize the information clearly with headings and bullet points for readability. Address each part of the user's request.

10. **Review and refine:**  Ensure accuracy, clarity, and completeness. Check for any missing information or areas that could be explained better. For example, explicitly mentioning the use of mocks and Google Test adds value.
Based on the filename and the provided code snippet, the file `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` in the Chromium network stack primarily focuses on **unit testing the `QuicConnection` class**. This class is a fundamental part of the QUIC implementation, responsible for managing the state and behavior of a single QUIC connection.

Here's a breakdown of its functions:

* **Comprehensive Testing of `QuicConnection` Functionality:** The file contains numerous test cases (`TEST_P`) that thoroughly exercise different aspects of the `QuicConnection` class. This includes:
    * **Connection Establishment and Tear-down (implicitly tested):** Although not directly shown in this snippet, other parts of the file likely test the initial handshake and graceful closure of connections.
    * **Data Transmission and Reception:**  Tests involving `OnStreamFrame` demonstrate testing the handling of data packets.
    * **Flow Control and Congestion Control:** While the snippet uses mocks (`MockSendAlgorithm`),  other tests likely verify the interaction of `QuicConnection` with flow control and congestion control mechanisms.
    * **Error Handling:** Tests likely exist to verify how the connection reacts to various error conditions.
    * **Connection Migration:** The provided snippet heavily focuses on testing connection migration scenarios, where the IP address or port of either the client or server changes. This involves:
        * **Probing new paths:** Sending `PATH_CHALLENGE` and expecting `PATH_RESPONSE`.
        * **Validating new paths:** Ensuring the new path is viable.
        * **Switching to new paths:**  Migrating the connection to the validated path.
        * **Handling address changes:**  Reacting to changes in the peer's address.
    * **Connection ID Management (IETF QUIC):** The snippet includes extensive testing of how the connection manages connection IDs, including:
        * **Issuing new Connection IDs (`SendNewConnectionId`).**
        * **Receiving new Connection IDs (`OnNewConnectionIdFrame`).**
        * **Retiring Connection IDs (`SendRetireConnectionId`, `OnRetireConnectionIdFrame`).**
        * **Handling scenarios where Connection IDs are missing or invalid.**
    * **Path Validation:** Testing the mechanisms used to verify reachability on different network paths.
    * **Interaction with other QUIC components:**  The tests use mock objects (`MockQuicConnectionVisitor`, `MockSendAlgorithm`) to isolate the `QuicConnection` and test its interactions with other parts of the QUIC stack.

**Relationship to JavaScript:**

While JavaScript in a web browser doesn't directly interact with the C++ implementation of `QuicConnection`, it indirectly benefits from its functionality.

* **`fetch` API and WebSockets over QUIC:** When a browser uses the `fetch` API or establishes a WebSocket connection over HTTP/3 (which uses QUIC), the underlying network stack utilizes the `QuicConnection` class to manage the connection. JavaScript code using these APIs doesn't directly see the `QuicConnection`, but its behavior and reliability are influenced by it.

**Example:**

Imagine a JavaScript application using the `fetch` API to download a large file from a server. If the user's network changes (e.g., they switch from Wi-Fi to cellular), the `QuicConnection`'s connection migration features (tested in this file) allow the download to continue seamlessly without interruption. The JavaScript code wouldn't need to be aware of the underlying network change or the migration process.

**Logical Reasoning Examples (with assumptions):**

Let's take the connection migration scenario when a new peer address is detected.

**Assumption:** The server receives a packet from a new IP address for the same connection.

**Input:**

1. **Current connection state:**  Established connection with `peer_address` A.
2. **Incoming packet:**  Received from `new_peer_address` B.

**Logical Steps (based on the code):**

1. **Detection:** The `QuicConnection` detects a change in the peer's address.
2. **Initiate Path Validation:**  The connection starts a path validation process to the `new_peer_address` B. This involves sending a `PATH_CHALLENGE`.
3. **Send `PATH_CHALLENGE`:** The `EXPECT_CALL(*send_algorithm_, OnPacketSent(...))` verifies that a packet is sent to the `new_peer_address`.
4. **Store Challenge Data:** The `payload = writer_->path_challenge_frames().front().data_buffer;` line captures the data sent in the `PATH_CHALLENGE`.
5. **Expect `PATH_RESPONSE`:** The connection waits for a `PATH_RESPONSE` containing the same `payload` from `new_peer_address` B.
6. **Validation Success (later in the code):**  When the correct `PATH_RESPONSE` is received, the new path is validated.
7. **Potential Migration:** Depending on the configuration and the nature of the address change, the connection might migrate to the new path.

**Output:**

* If the path validation succeeds, the `connection_.effective_peer_address()` will eventually become `new_peer_address` B.
* The `visitor_`'s `OnConnectionMigration` method might be called.
* The connection might start using the new path for sending future packets.

**User or Programming Common Usage Errors:**

* **Incorrectly configuring network interfaces:** On a server, if the QUIC implementation isn't bound to all relevant network interfaces, it might miss connection migration attempts from clients changing their address.
* **Firewall blocking path validation probes:** Firewalls might inadvertently block `PATH_CHALLENGE` or `PATH_RESPONSE` packets, preventing successful connection migration.
* **Misunderstanding connection ID lifecycle:** Incorrectly managing or prematurely retiring connection IDs can lead to connection failures, especially during migration. For example, a client might retire a server's connection ID too early, preventing the server from sending responses on the old path during migration.
* **Not handling `NEW_CONNECTION_ID` frames properly:** Ignoring or mishandling `NEW_CONNECTION_ID` frames can lead to the connection becoming unusable as the peer rotates its connection IDs.

**User Operation Steps to Reach This Code (Debugging):**

1. **User opens a webpage or application that uses QUIC:** The user might simply type a URL in their browser that uses HTTPS/3.
2. **Browser initiates a QUIC connection:** The browser's networking stack attempts to establish a QUIC connection with the server.
3. **Network change occurs:** While the connection is active, the user's network environment changes (e.g., switching Wi-Fi networks, moving from a wired to a wireless connection, or a mobile device switching between cellular and Wi-Fi).
4. **Client/Server detects a change in peer address:** The underlying QUIC implementation on either the client or the server detects that packets are now being received from a different IP address or port.
5. **`QuicConnection`'s migration logic is triggered:** The `QuicConnection` class on either end starts the connection migration process, sending `PATH_CHALLENGE` frames to the new address.
6. **If debugging the client:** A developer might be using browser developer tools to inspect network traffic and observe the QUIC handshake and subsequent connection migration attempts. They might see `PATH_CHALLENGE` and `PATH_RESPONSE` frames.
7. **If debugging the server:** A developer might be examining server-side logs or using network analysis tools (like Wireshark) to observe the incoming packets from the new client address and the server's attempts to validate the new path. They might set breakpoints in the `QuicConnection` code (like in this `quic_connection_test.cc` file during development) to understand the migration process.

**Functionality Summary (Part 20 of 24):**

Given that this is part 20 of 24, this section of `quic_connection_test.cc` likely focuses on **advanced aspects of connection management within the `QuicConnection` class**, specifically emphasizing:

* **Robustness of connection migration:** Ensuring the connection can reliably migrate to new network paths without interruption.
* **Correct handling of connection IDs in complex scenarios:**  Verifying that the connection ID management mechanisms work correctly during connection migration and other events.
* **Interaction between path validation and connection ID management:** Ensuring that these two features work together seamlessly.

The tests demonstrate scenarios where connection migration is triggered by peer address changes and how the connection manages connection IDs to maintain communication on the new path. They also cover cases where path validation might fail due to missing connection IDs.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第20部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
id) {
        server_cid1 = cid;
        return true;
      }));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  connection_.MaybeSendConnectionIdToClient();
  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  ASSERT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);

  // Receive probing packet with new peer address.
  peer_creator_.SetServerConnectionId(server_cid1);
  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/23456);
  QuicPathFrameBuffer payload;
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, NO_RETRANSMITTABLE_DATA))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
        EXPECT_EQ(kPeerAddress, connection_.peer_address());
        EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
        EXPECT_FALSE(writer_->path_response_frames().empty());
        EXPECT_FALSE(writer_->path_challenge_frames().empty());
        payload = writer_->path_challenge_frames().front().data_buffer;
      }))
      .WillRepeatedly(Invoke([&]() {
        // Only start reverse path validation once.
        EXPECT_TRUE(writer_->path_challenge_frames().empty());
      }));
  QuicPathFrameBuffer path_challenge_payload{0, 1, 2, 3, 4, 5, 6, 7};
  QuicFrames frames1;
  frames1.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_challenge_payload)));
  ProcessFramesPacketWithAddresses(frames1, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  const auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  const auto* alternative_path =
      QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_EQ(default_path->server_connection_id, server_cid0);
  EXPECT_EQ(alternative_path->server_connection_id, server_cid1);
  EXPECT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);

  // Receive PATH_RESPONSE should mark the new peer address validated.
  QuicFrames frames3;
  frames3.push_back(QuicFrame(QuicPathResponseFrame(99, payload)));
  ProcessFramesPacketWithAddresses(frames3, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);

  // Process another packet with a newer peer address with the same port will
  // start connection migration.
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  // IETF QUIC send algorithm should be changed to a different object, so no
  // OnPacketSent() called on the old send algorithm.
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, NO_RETRANSMITTABLE_DATA))
      .Times(0);
  const QuicSocketAddress kNewerPeerAddress(QuicIpAddress::Loopback4(),
                                            /*port=*/34567);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).WillOnce(Invoke([=, this]() {
    EXPECT_EQ(kNewerPeerAddress, connection_.peer_address());
  }));
  EXPECT_CALL(visitor_, MaybeSendAddressToken());
  QuicFrames frames2;
  frames2.push_back(QuicFrame(frame2_));
  ProcessFramesPacketWithAddresses(frames2, kSelfAddress, kNewerPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewerPeerAddress, connection_.peer_address());
  EXPECT_EQ(kNewerPeerAddress, connection_.effective_peer_address());
  // Since the newer address has the same IP as the previously validated probing
  // address. The peer migration becomes validated immediately.
  EXPECT_EQ(NO_CHANGE, connection_.active_effective_peer_migration_type());
  EXPECT_EQ(kNewerPeerAddress, writer_->last_write_peer_address());
  EXPECT_EQ(1u, connection_.GetStats()
                    .num_peer_migration_to_proactively_validated_address);
  EXPECT_FALSE(connection_.HasPendingPathValidation());
  EXPECT_NE(connection_.sent_packet_manager().GetSendAlgorithm(),
            send_algorithm_);

  EXPECT_EQ(default_path->server_connection_id, server_cid1);
  EXPECT_EQ(packet_creator->GetSourceConnectionId(), server_cid1);
  // Verify that alternative_path_ is cleared.
  EXPECT_TRUE(alternative_path->server_connection_id.IsEmpty());
  EXPECT_FALSE(alternative_path->stateless_reset_token.has_value());

  // Switch to use the mock send algorithm.
  send_algorithm_ = new StrictMock<MockSendAlgorithm>();
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(kDefaultTCPMSS));
  EXPECT_CALL(*send_algorithm_, OnApplicationLimited(_)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
      .Times(AnyNumber())
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, InSlowStart()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, InRecovery()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, PopulateConnectionStats(_)).Times(AnyNumber());
  connection_.SetSendAlgorithm(send_algorithm_);

  // Verify the server is not throttled by the anti-amplification limit by
  // sending a packet larger than the anti-amplification limit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendCryptoDataWithString(std::string(1200, 'a'), 0);
  EXPECT_EQ(1u, connection_.GetStats().num_validated_peer_migration);
}

// Regression test of b/228645208.
TEST_P(QuicConnectionTest, NoNonProbingFrameOnAlternativePath) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }

  PathProbeTestInit(Perspective::IS_SERVER);
  SetClientConnectionId(TestConnectionId(1));
  connection_.CreateConnectionIdManager();

  QuicConnectionId server_cid0 = connection_.connection_id();
  QuicConnectionId client_cid0 = connection_.client_connection_id();
  QuicConnectionId client_cid1 = TestConnectionId(2);
  QuicConnectionId server_cid1;
  // Sends new server CID to client.
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_))
      .WillOnce(Invoke([&](const QuicConnectionId& cid) {
        server_cid1 = cid;
        return true;
      }));
  EXPECT_CALL(visitor_, SendNewConnectionId(_));
  connection_.MaybeSendConnectionIdToClient();
  // Receives new client CID from client.
  QuicNewConnectionIdFrame new_cid_frame;
  new_cid_frame.connection_id = client_cid1;
  new_cid_frame.sequence_number = 1u;
  new_cid_frame.retire_prior_to = 0u;
  connection_.OnNewConnectionIdFrame(new_cid_frame);
  auto* packet_creator = QuicConnectionPeer::GetPacketCreator(&connection_);
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(), client_cid0);
  ASSERT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);

  peer_creator_.SetServerConnectionId(server_cid1);
  const QuicSocketAddress kNewPeerAddress =
      QuicSocketAddress(QuicIpAddress::Loopback4(), /*port=*/23456);
  QuicPathFrameBuffer path_challenge_payload{0, 1, 2, 3, 4, 5, 6, 7};
  QuicFrames frames1;
  frames1.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_challenge_payload)));
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, NO_RETRANSMITTABLE_DATA))
      .Times(AtLeast(1))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
        EXPECT_EQ(kPeerAddress, connection_.peer_address());
        EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
        EXPECT_FALSE(writer_->path_response_frames().empty());
        EXPECT_FALSE(writer_->path_challenge_frames().empty());
      }))
      .WillRepeatedly(DoDefault());
  ProcessFramesPacketWithAddresses(frames1, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
  EXPECT_TRUE(connection_.HasPendingPathValidation());
  const auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  const auto* alternative_path =
      QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_EQ(default_path->client_connection_id, client_cid0);
  EXPECT_EQ(default_path->server_connection_id, server_cid0);
  EXPECT_EQ(alternative_path->client_connection_id, client_cid1);
  EXPECT_EQ(alternative_path->server_connection_id, server_cid1);
  EXPECT_EQ(packet_creator->GetDestinationConnectionId(), client_cid0);
  EXPECT_EQ(packet_creator->GetSourceConnectionId(), server_cid0);

  // Process non-probing packets on the default path.
  peer_creator_.SetServerConnectionId(server_cid0);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).WillRepeatedly(Invoke([=, this]() {
    EXPECT_EQ(kPeerAddress, connection_.peer_address());
  }));
  // Receives packets 3 - 39 to send 19 ACK-only packets, which will force the
  // connection to reach |kMaxConsecutiveNonRetransmittablePackets| while
  // sending the next ACK.
  for (size_t i = 3; i <= 39; ++i) {
    ProcessDataPacket(i);
  }
  EXPECT_EQ(kPeerAddress, connection_.peer_address());
  EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());

  EXPECT_TRUE(connection_.HasPendingAcks());
  QuicTime ack_time = connection_.GetAckAlarm()->deadline();
  QuicTime path_validation_retry_time =
      connection_.GetRetryTimeout(kNewPeerAddress, writer_.get());
  // Advance time to simultaneously fire path validation retry and ACK alarms.
  clock_.AdvanceTime(std::max(ack_time, path_validation_retry_time) -
                     clock_.ApproximateNow());

  // The 20th ACK should bundle with a WINDOW_UPDATE frame.
  EXPECT_CALL(visitor_, OnAckNeedsRetransmittableFrame())
      .WillOnce(Invoke([this]() {
        connection_.SendControlFrame(QuicFrame(QuicWindowUpdateFrame(1, 0, 0)));
      }));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(kNewPeerAddress, writer_->last_write_peer_address());
        EXPECT_FALSE(writer_->path_challenge_frames().empty());
        // Retry path validation shouldn't bundle ACK.
        EXPECT_TRUE(writer_->ack_frames().empty());
      }))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(kPeerAddress, writer_->last_write_peer_address());
        EXPECT_FALSE(writer_->ack_frames().empty());
        EXPECT_FALSE(writer_->window_update_frames().empty());
      }));
  static_cast<TestAlarmFactory::TestAlarm*>(
      QuicPathValidatorPeer::retry_timer(
          QuicConnectionPeer::path_validator(&connection_)))
      ->Fire();
}

TEST_P(QuicConnectionTest, DoNotIssueNewCidIfVisitorSaysNo) {
  set_perspective(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames()) {
    return;
  }

  connection_.CreateConnectionIdManager();

  QuicConnectionId server_cid0 = connection_.connection_id();
  QuicConnectionId client_cid1 = TestConnectionId(2);
  QuicConnectionId server_cid1;
  // Sends new server CID to client.
  if (!connection_.connection_id().IsEmpty()) {
    EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
        .WillOnce(Return(TestConnectionId(456)));
  }
  EXPECT_CALL(visitor_, MaybeReserveConnectionId(_)).WillOnce(Return(false));
  EXPECT_CALL(visitor_, SendNewConnectionId(_)).Times(0);
  connection_.MaybeSendConnectionIdToClient();
}

TEST_P(QuicConnectionTest,
       ProbedOnAnotherPathAfterPeerIpAddressChangeAtServer) {
  PathProbeTestInit(Perspective::IS_SERVER);
  if (!version().HasIetfQuicFrames()) {
    return;
  }

  const QuicSocketAddress kNewPeerAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/23456);

  // Process a packet with a new peer address will start connection migration.
  EXPECT_CALL(visitor_, OnConnectionMigration(IPV6_TO_IPV4_CHANGE)).Times(1);
  // IETF QUIC send algorithm should be changed to a different object, so no
  // OnPacketSent() called on the old send algorithm.
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, NO_RETRANSMITTABLE_DATA))
      .Times(0);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).WillOnce(Invoke([=, this]() {
    EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  }));
  QuicFrames frames2;
  frames2.push_back(QuicFrame(frame2_));
  ProcessFramesPacketWithAddresses(frames2, kSelfAddress, kNewPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePathValidated(&connection_));
  EXPECT_TRUE(connection_.HasPendingPathValidation());

  // Switch to use the mock send algorithm.
  send_algorithm_ = new StrictMock<MockSendAlgorithm>();
  EXPECT_CALL(*send_algorithm_, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(kDefaultTCPMSS));
  EXPECT_CALL(*send_algorithm_, OnApplicationLimited(_)).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
      .Times(AnyNumber())
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, InSlowStart()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, InRecovery()).Times(AnyNumber());
  EXPECT_CALL(*send_algorithm_, PopulateConnectionStats(_)).Times(AnyNumber());
  connection_.SetSendAlgorithm(send_algorithm_);

  // Receive probing packet with a newer peer address shouldn't override the
  // on-going path validation.
  const QuicSocketAddress kNewerPeerAddress(QuicIpAddress::Loopback4(),
                                            /*port=*/34567);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(Invoke([&]() {
        EXPECT_EQ(kNewerPeerAddress, writer_->last_write_peer_address());
        EXPECT_FALSE(writer_->path_response_frames().empty());
        EXPECT_TRUE(writer_->path_challenge_frames().empty());
      }));
  QuicPathFrameBuffer path_challenge_payload{0, 1, 2, 3, 4, 5, 6, 7};
  QuicFrames frames1;
  frames1.push_back(
      QuicFrame(QuicPathChallengeFrame(0, path_challenge_payload)));
  ProcessFramesPacketWithAddresses(frames1, kSelfAddress, kNewerPeerAddress,
                                   ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(kNewPeerAddress, connection_.effective_peer_address());
  EXPECT_EQ(kNewPeerAddress, connection_.peer_address());
  EXPECT_TRUE(QuicConnectionPeer::IsAlternativePathValidated(&connection_));
  EXPECT_TRUE(connection_.HasPendingPathValidation());
}

TEST_P(QuicConnectionTest,
       PathValidationFailedOnClientDueToLackOfServerConnectionId) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT,
                    /*receive_new_server_connection_id=*/false);

  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/34567);

  bool success;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), writer_.get()),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);

  EXPECT_FALSE(success);
}

TEST_P(QuicConnectionTest,
       PathValidationFailedOnClientDueToLackOfClientConnectionIdTheSecondTime) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT,
                    /*receive_new_server_connection_id=*/false);
  SetClientConnectionId(TestConnectionId(1));

  // Make sure server connection ID is available for the 1st validation.
  QuicConnectionId server_cid0 = connection_.connection_id();
  QuicConnectionId server_cid1 = TestConnectionId(2);
  QuicConnectionId server_cid2 = TestConnectionId(4);
  QuicConnectionId client_cid1;
  QuicNewConnectionIdFrame frame1;
  frame1.connection_id = server_cid1;
  frame1.sequence_number = 1u;
  frame1.retire_prior_to = 0u;
  frame1.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame1.connection_id);
  connection_.OnNewConnectionIdFrame(frame1);
  const auto* packet_creator =
      QuicConnectionPeer::GetPacketCreator(&connection_);
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(), server_cid0);

  // Client will issue a new client connection ID to server.
  EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
      .WillOnce(Return(TestConnectionId(456)));
  EXPECT_CALL(visitor_, SendNewConnectionId(_))
      .WillOnce(Invoke([&](const QuicNewConnectionIdFrame& frame) {
        client_cid1 = frame.connection_id;
      }));

  const QuicSocketAddress kSelfAddress1(QuicIpAddress::Any4(), 12345);
  ASSERT_NE(kSelfAddress1, connection_.self_address());
  bool success1;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kSelfAddress1, connection_.peer_address(), writer_.get()),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kSelfAddress1, connection_.peer_address(), &success1),
      PathValidationReason::kReasonUnknown);

  // Migrate upon 1st validation success.
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  ASSERT_TRUE(connection_.MigratePath(kSelfAddress1, connection_.peer_address(),
                                      &new_writer, /*owns_writer=*/false));
  QuicConnectionPeer::RetirePeerIssuedConnectionIdsNoLongerOnPath(&connection_);
  const auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  EXPECT_EQ(default_path->client_connection_id, client_cid1);
  EXPECT_EQ(default_path->server_connection_id, server_cid1);
  EXPECT_EQ(default_path->stateless_reset_token, frame1.stateless_reset_token);
  const auto* alternative_path =
      QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_TRUE(alternative_path->client_connection_id.IsEmpty());
  EXPECT_TRUE(alternative_path->server_connection_id.IsEmpty());
  EXPECT_FALSE(alternative_path->stateless_reset_token.has_value());
  ASSERT_EQ(packet_creator->GetDestinationConnectionId(), server_cid1);

  // Client will retire server connection ID on old default_path.
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();

  // Another server connection ID is available to client.
  QuicNewConnectionIdFrame frame2;
  frame2.connection_id = server_cid2;
  frame2.sequence_number = 2u;
  frame2.retire_prior_to = 1u;
  frame2.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame2.connection_id);
  connection_.OnNewConnectionIdFrame(frame2);

  const QuicSocketAddress kSelfAddress2(QuicIpAddress::Loopback4(),
                                        /*port=*/45678);
  bool success2;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kSelfAddress2, connection_.peer_address(), writer_.get()),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kSelfAddress2, connection_.peer_address(), &success2),
      PathValidationReason::kReasonUnknown);
  // Since server does not retire any client connection ID yet, 2nd validation
  // would fail due to lack of client connection ID.
  EXPECT_FALSE(success2);
}

TEST_P(QuicConnectionTest, ServerConnectionIdRetiredUponPathValidationFailure) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT);

  // Make sure server connection ID is available for validation.
  QuicNewConnectionIdFrame frame;
  frame.connection_id = TestConnectionId(2);
  frame.sequence_number = 1u;
  frame.retire_prior_to = 0u;
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  connection_.OnNewConnectionIdFrame(frame);

  const QuicSocketAddress kNewSelfAddress(QuicIpAddress::Loopback4(),
                                          /*port=*/34567);
  bool success;
  connection_.ValidatePath(
      std::make_unique<TestQuicPathValidationContext>(
          kNewSelfAddress, connection_.peer_address(), writer_.get()),
      std::make_unique<TestValidationResultDelegate>(
          &connection_, kNewSelfAddress, connection_.peer_address(), &success),
      PathValidationReason::kReasonUnknown);

  auto* path_validator = QuicConnectionPeer::path_validator(&connection_);
  path_validator->CancelPathValidation();
  QuicConnectionPeer::RetirePeerIssuedConnectionIdsNoLongerOnPath(&connection_);
  EXPECT_FALSE(success);
  const auto* alternative_path =
      QuicConnectionPeer::GetAlternativePath(&connection_);
  EXPECT_TRUE(alternative_path->client_connection_id.IsEmpty());
  EXPECT_TRUE(alternative_path->server_connection_id.IsEmpty());
  EXPECT_FALSE(alternative_path->stateless_reset_token.has_value());

  // Client will retire server connection ID on alternative_path.
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/1u));
  retire_peer_issued_cid_alarm->Fire();
}

TEST_P(QuicConnectionTest,
       MigratePathDirectlyFailedDueToLackOfServerConnectionId) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT,
                    /*receive_new_server_connection_id=*/false);
  const QuicSocketAddress kSelfAddress1(QuicIpAddress::Any4(), 12345);
  ASSERT_NE(kSelfAddress1, connection_.self_address());

  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  ASSERT_FALSE(connection_.MigratePath(kSelfAddress1,
                                       connection_.peer_address(), &new_writer,
                                       /*owns_writer=*/false));
}

TEST_P(QuicConnectionTest,
       MigratePathDirectlyFailedDueToLackOfClientConnectionIdTheSecondTime) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_CLIENT,
                    /*receive_new_server_connection_id=*/false);
  SetClientConnectionId(TestConnectionId(1));

  // Make sure server connection ID is available for the 1st migration.
  QuicNewConnectionIdFrame frame1;
  frame1.connection_id = TestConnectionId(2);
  frame1.sequence_number = 1u;
  frame1.retire_prior_to = 0u;
  frame1.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame1.connection_id);
  connection_.OnNewConnectionIdFrame(frame1);

  // Client will issue a new client connection ID to server.
  QuicConnectionId new_client_connection_id;
  EXPECT_CALL(connection_id_generator_, GenerateNextConnectionId(_))
      .WillOnce(Return(TestConnectionId(456)));
  EXPECT_CALL(visitor_, SendNewConnectionId(_))
      .WillOnce(Invoke([&](const QuicNewConnectionIdFrame& frame) {
        new_client_connection_id = frame.connection_id;
      }));

  // 1st migration is successful.
  const QuicSocketAddress kSelfAddress1(QuicIpAddress::Any4(), 12345);
  ASSERT_NE(kSelfAddress1, connection_.self_address());
  TestPacketWriter new_writer(version(), &clock_, Perspective::IS_CLIENT);
  ASSERT_TRUE(connection_.MigratePath(kSelfAddress1, connection_.peer_address(),
                                      &new_writer,
                                      /*owns_writer=*/false));
  QuicConnectionPeer::RetirePeerIssuedConnectionIdsNoLongerOnPath(&connection_);
  const auto* default_path = QuicConnectionPeer::GetDefaultPath(&connection_);
  EXPECT_EQ(default_path->client_connection_id, new_client_connection_id);
  EXPECT_EQ(default_path->server_connection_id, frame1.connection_id);
  EXPECT_EQ(default_path->stateless_reset_token, frame1.stateless_reset_token);

  // Client will retire server connection ID on old default_path.
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();

  // Another server connection ID is available to client.
  QuicNewConnectionIdFrame frame2;
  frame2.connection_id = TestConnectionId(4);
  frame2.sequence_number = 2u;
  frame2.retire_prior_to = 1u;
  frame2.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame2.connection_id);
  connection_.OnNewConnectionIdFrame(frame2);

  // Since server does not retire any client connection ID yet, 2nd migration
  // would fail due to lack of client connection ID.
  const QuicSocketAddress kSelfAddress2(QuicIpAddress::Loopback4(),
                                        /*port=*/45678);
  auto new_writer2 = std::make_unique<TestPacketWriter>(version(), &clock_,
                                                        Perspective::IS_CLIENT);
  ASSERT_FALSE(connection_.MigratePath(
      kSelfAddress2, connection_.peer_address(), new_writer2.release(),
      /*owns_writer=*/true));
}

TEST_P(QuicConnectionTest,
       CloseConnectionAfterReceiveNewConnectionIdFromPeerUsingEmptyCID) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  ASSERT_TRUE(connection_.client_connection_id().IsEmpty());

  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 1u;
  frame.connection_id = TestConnectionId(1);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;

  EXPECT_FALSE(connection_.OnNewConnectionIdFrame(frame));

  EXPECT_FALSE(connection_.connected());
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(IETF_QUIC_PROTOCOL_VIOLATION));
}

TEST_P(QuicConnectionTest, NewConnectionIdFrameResultsInError) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  connection_.CreateConnectionIdManager();
  ASSERT_FALSE(connection_.connection_id().IsEmpty());

  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 1u;
  frame.connection_id = connection_id_;  // Reuses connection ID casuing error.
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;

  EXPECT_FALSE(connection_.OnNewConnectionIdFrame(frame));

  EXPECT_FALSE(connection_.connected());
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(IETF_QUIC_PROTOCOL_VIOLATION));
}

TEST_P(QuicConnectionTest,
       ClientRetirePeerIssuedConnectionIdTriggeredByNewConnectionIdFrame) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  connection_.CreateConnectionIdManager();

  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 1u;
  frame.connection_id = TestConnectionId(1);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;

  EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_FALSE(retire_peer_issued_cid_alarm->IsSet());

  frame.sequence_number = 2u;
  frame.connection_id = TestConnectionId(2);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 1u;  // CID associated with #1 will be retired.

  EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_EQ(connection_.connection_id(), connection_id_);

  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();
  EXPECT_EQ(connection_.connection_id(), TestConnectionId(2));
  EXPECT_EQ(connection_.packet_creator().GetDestinationConnectionId(),
            TestConnectionId(2));
}

TEST_P(QuicConnectionTest,
       ServerRetirePeerIssuedConnectionIdTriggeredByNewConnectionIdFrame) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  SetClientConnectionId(TestConnectionId(0));

  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 1u;
  frame.connection_id = TestConnectionId(1);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;

  EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_FALSE(retire_peer_issued_cid_alarm->IsSet());

  frame.sequence_number = 2u;
  frame.connection_id = TestConnectionId(2);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 1u;  // CID associated with #1 will be retired.

  EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_EQ(connection_.client_connection_id(), TestConnectionId(0));

  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();
  EXPECT_EQ(connection_.client_connection_id(), TestConnectionId(2));
  EXPECT_EQ(connection_.packet_creator().GetDestinationConnectionId(),
            TestConnectionId(2));
}

TEST_P(
    QuicConnectionTest,
    ReplacePeerIssuedConnectionIdOnBothPathsTriggeredByNewConnectionIdFrame) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  PathProbeTestInit(Perspective::IS_SERVER);
  SetClientConnectionId(TestConnectionId(0));

  // Populate alternative_path_ with probing packet.
  std::unique_ptr<SerializedPacket> probing_packet = ConstructProbingPacket();

  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      QuicEncryptedPacket(probing_packet->encrypted_buffer,
                          probing_packet->encrypted_length),
      clock_.Now()));
  QuicIpAddress new_host;
  new_host.FromString("1.1.1.1");
  ProcessReceivedPacket(kSelfAddress,
                        QuicSocketAddress(new_host, /*port=*/23456), *received);

  EXPECT_EQ(
      TestConnectionId(0),
      QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(&connection_));

  QuicNewConnectionIdFrame frame;
  frame.sequence_number = 1u;
  frame.connection_id = TestConnectionId(1);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 0u;

  EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
  auto* retire_peer_issued_cid_alarm =
      connection_.GetRetirePeerIssuedConnectionIdAlarm();
  ASSERT_FALSE(retire_peer_issued_cid_alarm->IsSet());

  frame.sequence_number = 2u;
  frame.connection_id = TestConnectionId(2);
  frame.stateless_reset_token =
      QuicUtils::GenerateStatelessResetToken(frame.connection_id);
  frame.retire_prior_to = 1u;  // CID associated with #1 will be retired.

  EXPECT_TRUE(connection_.OnNewConnectionIdFrame(frame));
  ASSERT_TRUE(retire_peer_issued_cid_alarm->IsSet());
  EXPECT_EQ(connection_.client_connection_id(), TestConnectionId(0));

  EXPECT_CALL(visitor_, SendRetireConnectionId(/*sequence_number=*/0u));
  retire_peer_issued_cid_alarm->Fire();
  EXPECT_EQ(connection_.client_connection_id(), TestConnectionId(2));
  EXPECT_EQ(connection_.packet_creator().GetDestinationConnectionId(),
            TestConnectionId(2));
  // Clean up alternative path connection ID.
  EXPECT_EQ(
      TestConnectionId(2),
      QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(&connection_));
}

TEST_P(QuicConnectionTest,
       CloseConnectionAfterReceiveRetireConnectionIdWhenNoCIDIssued) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);

  EXPECT_CALL(visitor_, BeforeConnectionCloseSent());
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  QuicRetireConnectionIdFrame frame;
  frame.sequence_number = 1u;

  EXPECT_FALSE(connection_.OnRetireConnectionIdFrame(frame));

  EXPECT_FALSE(connection_.connected());
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(IETF_QUIC_PROTOCOL_VIOLATION));
}

TEST_P(QuicConnectionTest, RetireConnectionIdFrameResultsInError) {
  if (!version().HasIetfQuicFrames()) {
    return;
  }
  set_perspective(Perspective::IS_SERVER);
  connection_.CreateConnectionIdManager();

  if
```