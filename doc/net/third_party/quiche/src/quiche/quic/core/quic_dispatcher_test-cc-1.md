Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This code is part of a test file (`quic_dispatcher_test.cc`) within the Chromium network stack's QUIC implementation.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core component:** The file name clearly indicates this is testing the `QuicDispatcher`.

2. **Recognize the testing context:** The code uses the Google Test framework (`TEST_P`, `EXPECT_CALL`, `ASSERT_EQ`, etc.). This means the primary purpose is to verify the behavior of `QuicDispatcher` under various conditions.

3. **Analyze individual test cases:** Go through each `TEST_P` block and try to understand what scenario is being tested. Keywords like "TlsMultiPacketClientHello", "ProcessPackets", "StatelessVersionNegotiation", "Shutdown", "TimeWaitListManager", "LimitResets", etc., provide hints.

4. **Group related tests:** Notice patterns and group tests that address similar functionalities. For instance, multiple tests cover different variations of handling multi-packet Client Hellos. Several tests relate to version negotiation and how the dispatcher interacts with the `TimeWaitListManager`.

5. **Focus on the dispatcher's role:**  Remember that the `QuicDispatcher` is responsible for receiving UDP packets and routing them to the appropriate QUIC session or handling them directly (e.g., version negotiation).

6. **Infer functionality from mocks and expectations:** The `EXPECT_CALL` statements reveal the dispatcher's interactions with other components like `CreateQuicSession` and the `TimeWaitListManager`. The arguments passed to these mocked methods provide further insight into the dispatcher's behavior.

7. **Consider edge cases and error handling:** Look for tests that examine how the dispatcher handles invalid or unexpected input, like packets with invalid connection IDs, incorrect versions, or zero ports.

8. **Identify key responsibilities:** Based on the analyzed tests, list the main functions of the `QuicDispatcher`. This will include:
    * Session creation.
    * Packet routing.
    * Handling multi-packet Client Hellos.
    * Performing stateless version negotiation.
    * Managing the time-wait state for closed connections.
    * Sending public resets.
    * Handling invalid or unexpected packets.
    * Managing connection ID lengths.
    * Interacting with the connection ID generator.

9. **Formulate the summary:**  Synthesize the identified responsibilities into a concise overview of the code's functionality.

10. **Address specific questions from the prompt:**  Although not explicitly asked for in this "part 2" prompt, keep in mind the broader context of the original request regarding JavaScript interaction, logical reasoning, common errors, and debugging. This will be relevant for the subsequent parts.

Applying this process to the provided code snippet leads to the summary provided in the example answer. The key is to systematically analyze the test cases and understand the underlying functionality they are designed to verify.
This is the **second part** of a test file for the `QuicDispatcher` in Chromium's QUIC implementation. Building upon the context from the first part (which we don't have access to here, but we can infer), this section primarily focuses on testing the `QuicDispatcher`'s ability to handle various scenarios related to **connection establishment, version negotiation, and interaction with the time-wait list manager.**

Here's a breakdown of the functionalities demonstrated in this part:

**Key Functions and Scenarios Tested:**

* **Handling Multi-Packet TLS Client Hello (CHLO):**
    * Tests how the dispatcher correctly assembles a Client Hello that arrives in multiple packets.
    * Includes scenarios with and without packet reordering.
    * Verifies that a new session is only created after all parts of the CHLO are received.
    * Tests the interaction with `CreateQuicSession` and the underlying `QuicConnection`'s `ProcessUdpPacket`.
    * Checks handling of long connection IDs in multi-packet CHLOs.

* **Processing Incoming Packets:**
    * Verifies that the dispatcher correctly creates new `QuicSession`s for new connections based on incoming packets.
    * Confirms that subsequent packets for an existing connection are routed to the correct session.
    * Uses mocks to verify that `CreateQuicSession` is called with the expected connection ID and client address.
    * Asserts that `ProcessUdpPacket` on the established connection is called with the received packet data.

* **Handling Packets with Packet Number Zero:**
    * A regression test to ensure the dispatcher doesn't reject packets with a packet number that appears as zero due to packet number length encoding.

* **Stateless Version Negotiation:**
    * Tests the dispatcher's ability to perform stateless version negotiation when the client sends a packet with a reserved version.
    * Verifies that the dispatcher *doesn't* create a new session in this case.
    * Confirms that the `TimeWaitListManager` is called to send a version negotiation packet back to the client.
    * Tests scenarios with different connection ID lengths in the version negotiation packet.
    * Checks that version negotiation is not triggered for small packets (to avoid amplification attacks).
    * Verifies that version negotiation *is* sent even for small CHLOs if CHLO size validation is disabled.

* **Graceful Shutdown:**
    * Checks that when the dispatcher is shut down, it closes all active connections.

* **Time-Wait List Management:**
    * Tests the integration with the `TimeWaitListManager`.
    * Verifies that when a connection is closed, its connection ID is added to the time-wait list.
    * Confirms that subsequent packets for a connection in the time-wait state are forwarded to the `TimeWaitListManager` for handling (likely sending a public reset).
    * Tests the case where a packet with an unknown connection ID and no version flag arrives; it should trigger a public reset.
    * Ensures that small packets with unknown connection IDs and no version are dropped silently.

* **Handling Packets with Invalid Flags:**
    * Checks that packets with invalid flags are dropped.

* **Limiting Public Resets:**
    * Tests that the dispatcher limits the rate of sending public resets to the same client address to mitigate potential abuse.
    * Includes a test to stop sending resets if too many recent addresses are seen, with a mechanism to clear the recent address list after a timeout.

* **Handling Long Connection IDs:**
    * Verifies that the dispatcher can handle and replace excessively long connection IDs with shorter, valid ones.
    * Tests scenarios with a mix of valid and invalid length connection IDs.

* **Handling Packets with Specific Ports:**
    * Checks that packets originating from port 0 are dropped.
    * Verifies that packets from blocked ports (like port 17, the QUIC alternative before standardization) are dropped.
    * Confirms that packets from non-blocked ports (like 443) are processed normally.

* **Dropping Packets with Invalid Initial Connection IDs:**
    * Tests that packets with known versions but invalid short initial connection IDs are dropped.
    * Verifies that packets with known versions and generally invalid connection IDs are also dropped.

* **Version Negotiation for Unknown Version with Invalid Short Initial Connection ID:**
    * Tests specific scenarios where a version negotiation packet is sent in response to an unknown version with invalid short initial connection IDs.

* **Dynamically Changing Supported Versions:**
    * Verifies that the dispatcher correctly handles enabling and disabling QUIC versions at runtime.

* **Rejecting Deprecated Versions with Version Negotiation:**
    * Ensures that the dispatcher correctly sends version negotiation responses when it receives packets using deprecated QUIC versions (drafts and older versions).

**Relationship to JavaScript:**

While this C++ code doesn't directly interact with JavaScript, it underpins the network communication for web browsers and other applications that might use JavaScript. Here's how they are related conceptually:

* **Browser's Network Stack:** When a browser (which executes JavaScript) needs to establish a QUIC connection with a server, the underlying network stack (which includes this C++ code) handles the low-level details of sending and receiving QUIC packets.
* **`navigator.connection` API:** JavaScript has APIs like `navigator.connection` that can provide information about the network connection, although it doesn't directly expose the QUIC dispatcher.
* **WebTransport and WebSockets over QUIC:**  Emerging web standards like WebTransport can utilize QUIC as a transport protocol. In these cases, JavaScript code would use the WebTransport API, and the underlying QUIC implementation (including this dispatcher) would manage the connection details.

**Example of Logical Reasoning (Hypothetical Input & Output):**

**Scenario:** Handling a multi-packet Client Hello with reordering.

**Hypothetical Input:**

1. **Packet 1:** Contains the latter part of the Client Hello, with the version flag set and the correct connection ID.
2. **Packet 2:** Contains the initial part of the Client Hello, also with the version flag and the same connection ID.

**Expected Output:**

1. **Processing Packet 1:** The dispatcher temporarily stores this packet. Since it's not the complete CHLO, no new session is created yet.
2. **Processing Packet 2:** The dispatcher recognizes that this completes the Client Hello. It assembles the full CHLO, successfully decrypts it, and then:
    * Calls `CreateQuicSession` with the correct connection ID and client address.
    * Passes both packets to the newly created `QuicConnection`'s `ProcessUdpPacket` method in the correct order (after reordering).
    * The `NumSessions()` counter increases to 1.

**Common Usage Errors and Debugging Hints:**

* **Incorrect Server Configuration:** If the server isn't configured to support the QUIC version advertised by the client, the dispatcher might send a version negotiation packet. This can be a common issue during deployment. Debugging would involve checking server-side QUIC configuration.
* **Firewall Blocking UDP:** QUIC uses UDP. Firewalls blocking UDP traffic on the server's port will prevent the dispatcher from receiving packets. A user experiencing connection issues should check their firewall settings.
* **Client and Server Version Mismatch:** If the client and server don't have a mutually supported QUIC version, the version negotiation process will occur. Debugging involves inspecting the version negotiation packets exchanged.
* **Network Issues Causing Packet Reordering/Loss:** While the dispatcher handles some reordering, severe packet loss or out-of-order delivery can lead to connection failures. Tools like `tcpdump` or Wireshark can help analyze packet flow.

**User Operation to Reach This Code (Debugging Context):**

1. **User attempts to connect to a website or service using a QUIC-enabled browser or application.**
2. **The browser's network stack initiates a QUIC handshake with the server.**
3. **The initial Client Hello (CHLO) might be sent in one or more UDP packets.**
4. **On the server side, the operating system receives these UDP packets.**
5. **The server's QUIC listener (likely a socket) receives the packets.**
6. **The server's `QuicDispatcher` receives the raw UDP packets.**
7. **The `ProcessPacket` method in `QuicDispatcher` is called for each received packet.**
8. **The code in this test file is designed to simulate and verify the behavior of `QuicDispatcher::ProcessPacket` under different conditions, including the scenarios described above.**

**In summary, this part of the `quic_dispatcher_test.cc` file extensively tests the core functionalities of the `QuicDispatcher` related to establishing new QUIC connections, handling version negotiation, and managing the lifecycle of connections, including their transition to the time-wait state.**

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
meterId =
      static_cast<TransportParameters::TransportParameterId>(0xff33);
  std::string kCustomParameterValue(2000, '-');
  client_config.custom_transport_parameters_to_send()[kCustomParameterId] =
      kCustomParameterValue;
  std::vector<std::unique_ptr<QuicReceivedPacket>> packets =
      GetFirstFlightOfPackets(version_, client_config, original_connection_id,
                              EmptyQuicConnectionId(),
                              TestClientCryptoConfig());
  ASSERT_EQ(packets.size(), 2u);
  if (add_reordering) {
    std::swap(packets[0], packets[1]);
  }

  // Processing the first packet should not create a new session.
  ProcessReceivedPacket(std::move(packets[0]), client_address, version_,
                        original_connection_id);

  EXPECT_EQ(dispatcher_->NumSessions(), 0u)
      << "No session should be created before the rest of the CHLO arrives.";

  // Processing the second packet should create the new session.
  EXPECT_CALL(
      *dispatcher_,
      CreateQuicSession(new_connection_id, _, client_address,
                        Eq(ExpectedAlpn()), _, MatchParsedClientHello(), _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, new_connection_id, client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(2);

  ProcessReceivedPacket(std::move(packets[1]), client_address, version_,
                        original_connection_id);
  EXPECT_EQ(dispatcher_->NumSessions(), 1u);
}

TEST_P(QuicDispatcherTestAllVersions, TlsMultiPacketClientHello) {
  TestTlsMultiPacketClientHello(/*add_reordering=*/false,
                                /*long_connection_id=*/false);
}

TEST_P(QuicDispatcherTestAllVersions, TlsMultiPacketClientHelloWithReordering) {
  TestTlsMultiPacketClientHello(/*add_reordering=*/true,
                                /*long_connection_id=*/false);
}

TEST_P(QuicDispatcherTestAllVersions, TlsMultiPacketClientHelloWithLongId) {
  TestTlsMultiPacketClientHello(/*add_reordering=*/false,
                                /*long_connection_id=*/true);
}

TEST_P(QuicDispatcherTestAllVersions,
       TlsMultiPacketClientHelloWithReorderingAndLongId) {
  TestTlsMultiPacketClientHello(/*add_reordering=*/true,
                                /*long_connection_id=*/true);
}

TEST_P(QuicDispatcherTestAllVersions, ProcessPackets) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(
      *dispatcher_,
      CreateQuicSession(TestConnectionId(1), _, client_address,
                        Eq(ExpectedAlpn()), _, MatchParsedClientHello(), _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessFirstFlight(client_address, TestConnectionId(1));

  EXPECT_CALL(
      *dispatcher_,
      CreateQuicSession(TestConnectionId(2), _, client_address,
                        Eq(ExpectedAlpn()), _, MatchParsedClientHello(), _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(2), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session2_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session2_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(2), packet);
      })));
  ProcessFirstFlight(client_address, TestConnectionId(2));

  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(1)
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessPacket(client_address, TestConnectionId(1), false, "data");
}

// Regression test of b/93325907.
TEST_P(QuicDispatcherTestAllVersions, DispatcherDoesNotRejectPacketNumberZero) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(1), _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  // Verify both packets 1 and 2 are processed by connection 1.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(2)
      .WillRepeatedly(
          WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
            ValidatePacket(TestConnectionId(1), packet);
          })));
  ProcessFirstFlight(client_address, TestConnectionId(1));
  // Packet number 256 with packet number length 1 would be considered as 0 in
  // dispatcher.
  ProcessPacket(client_address, TestConnectionId(1), false, version_, "", true,
                CONNECTION_ID_PRESENT, PACKET_1BYTE_PACKET_NUMBER, 256);
}

TEST_P(QuicDispatcherTestOneVersion, StatelessVersionNegotiation) {
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(TestConnectionId(1), _, _, _, _, _, _, _))
      .Times(1);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(QuicVersionReservedForNegotiation(), client_address,
                     TestConnectionId(1));
}

TEST_P(QuicDispatcherTestOneVersion,
       StatelessVersionNegotiationWithVeryLongConnectionId) {
  QuicConnectionId connection_id = QuicUtils::CreateRandomConnectionId(33);
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              SendVersionNegotiationPacket(connection_id, _, _, _, _, _, _, _))
      .Times(1);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(QuicVersionReservedForNegotiation(), client_address,
                     connection_id);
}

TEST_P(QuicDispatcherTestOneVersion,
       StatelessVersionNegotiationWithClientConnectionId) {
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              SendVersionNegotiationPacket(
                  TestConnectionId(1), TestConnectionId(2), _, _, _, _, _, _))
      .Times(1);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(QuicVersionReservedForNegotiation(), client_address,
                     TestConnectionId(1), TestConnectionId(2));
}

TEST_P(QuicDispatcherTestOneVersion, NoVersionNegotiationWithSmallPacket) {
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              SendVersionNegotiationPacket(_, _, _, _, _, _, _, _))
      .Times(0);
  std::string chlo = SerializeCHLO() + std::string(1200, 'a');
  // Truncate to 1100 bytes of payload which results in a packet just
  // under 1200 bytes after framing, packet, and encryption overhead.
  QUICHE_DCHECK_LE(1200u, chlo.length());
  std::string truncated_chlo = chlo.substr(0, 1100);
  QUICHE_DCHECK_EQ(1100u, truncated_chlo.length());
  ProcessPacket(client_address, TestConnectionId(1), true,
                QuicVersionReservedForNegotiation(), truncated_chlo, false,
                CONNECTION_ID_PRESENT, PACKET_4BYTE_PACKET_NUMBER, 1);
}

// Disabling CHLO size validation allows the dispatcher to send version
// negotiation packets in response to a CHLO that is otherwise too small.
TEST_P(QuicDispatcherTestOneVersion,
       VersionNegotiationWithoutChloSizeValidation) {
  crypto_config_.set_validate_chlo_size(false);

  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              SendVersionNegotiationPacket(_, _, _, _, _, _, _, _))
      .Times(1);
  std::string chlo = SerializeCHLO() + std::string(1200, 'a');
  // Truncate to 1100 bytes of payload which results in a packet just
  // under 1200 bytes after framing, packet, and encryption overhead.
  QUICHE_DCHECK_LE(1200u, chlo.length());
  std::string truncated_chlo = chlo.substr(0, 1100);
  QUICHE_DCHECK_EQ(1100u, truncated_chlo.length());
  ProcessPacket(client_address, TestConnectionId(1), true,
                QuicVersionReservedForNegotiation(), truncated_chlo, true,
                CONNECTION_ID_PRESENT, PACKET_4BYTE_PACKET_NUMBER, 1);
}

TEST_P(QuicDispatcherTestAllVersions, Shutdown) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, client_address,
                                              Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));

  ProcessFirstFlight(client_address, TestConnectionId(1));

  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              CloseConnection(QUIC_PEER_GOING_AWAY, _, _));

  dispatcher_->Shutdown();
}

TEST_P(QuicDispatcherTestAllVersions, TimeWaitListManager) {
  CreateTimeWaitListManager();

  // Create a new session.
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  QuicConnectionId connection_id = TestConnectionId(1);
  EXPECT_CALL(*dispatcher_, CreateQuicSession(connection_id, _, client_address,
                                              Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, connection_id, client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));

  ProcessFirstFlight(client_address, connection_id);

  // Now close the connection, which should add it to the time wait list.
  session1_->connection()->CloseConnection(
      QUIC_INVALID_VERSION,
      "Server: Packet 2 without version flag before version negotiated.",
      ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_TRUE(time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));

  // Dispatcher forwards subsequent packets for this connection_id to the time
  // wait list manager.
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _, _))
      .Times(1);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  ProcessPacket(client_address, connection_id, true, "data");
}

TEST_P(QuicDispatcherTestAllVersions, NoVersionPacketToTimeWaitListManager) {
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  QuicConnectionId connection_id = TestConnectionId(1);
  // Dispatcher forwards all packets for this connection_id to the time wait
  // list manager.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(1);
  ProcessPacket(client_address, connection_id, /*has_version_flag=*/false,
                "data");
}

TEST_P(QuicDispatcherTestAllVersions,
       DonotTimeWaitPacketsWithUnknownConnectionIdAndNoVersion) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();

  uint8_t short_packet[22] = {0x70, 0xa7, 0x02, 0x6b};
  uint8_t valid_size_packet[23] = {0x70, 0xa7, 0x02, 0x6c};
  size_t short_packet_len = 21;
  QuicReceivedPacket packet(reinterpret_cast<char*>(short_packet),
                            short_packet_len, QuicTime::Zero());
  QuicReceivedPacket packet2(reinterpret_cast<char*>(valid_size_packet),
                             short_packet_len + 1, QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  // Verify small packet is silently dropped.
  EXPECT_CALL(connection_id_generator_, ConnectionIdLength(0xa7))
      .WillOnce(Return(kQuicDefaultConnectionIdLength));
  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(0);
  dispatcher_->ProcessPacket(server_address_, client_address, packet);
  EXPECT_CALL(connection_id_generator_, ConnectionIdLength(0xa7))
      .WillOnce(Return(kQuicDefaultConnectionIdLength));
  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, packet2);
}

TEST_P(QuicDispatcherTestOneVersion, DropPacketWithInvalidFlags) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t all_zero_packet[1200] = {};
  QuicReceivedPacket packet(reinterpret_cast<char*>(all_zero_packet),
                            sizeof(all_zero_packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(connection_id_generator_, ConnectionIdLength(_))
      .WillOnce(Return(kQuicDefaultConnectionIdLength));
  dispatcher_->ProcessPacket(server_address_, client_address, packet);
}

TEST_P(QuicDispatcherTestAllVersions, LimitResetsToSameClientAddress) {
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  QuicSocketAddress client_address2(QuicIpAddress::Loopback4(), 2);
  QuicSocketAddress client_address3(QuicIpAddress::Loopback6(), 1);
  QuicConnectionId connection_id = TestConnectionId(1);

  // Verify only one reset is sent to the address, although multiple packets
  // are received.
  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(1);
  ProcessPacket(client_address, connection_id, /*has_version_flag=*/false,
                "data");
  ProcessPacket(client_address, connection_id, /*has_version_flag=*/false,
                "data2");
  ProcessPacket(client_address, connection_id, /*has_version_flag=*/false,
                "data3");

  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(2);
  ProcessPacket(client_address2, connection_id, /*has_version_flag=*/false,
                "data");
  ProcessPacket(client_address3, connection_id, /*has_version_flag=*/false,
                "data");
}

TEST_P(QuicDispatcherTestAllVersions,
       StopSendingResetOnTooManyRecentAddresses) {
  SetQuicFlag(quic_max_recent_stateless_reset_addresses, 2);
  const size_t kTestLifeTimeMs = 10;
  SetQuicFlag(quic_recent_stateless_reset_addresses_lifetime_ms,
              kTestLifeTimeMs);
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  QuicSocketAddress client_address2(QuicIpAddress::Loopback4(), 2);
  QuicSocketAddress client_address3(QuicIpAddress::Loopback6(), 1);
  QuicConnectionId connection_id = TestConnectionId(1);

  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(2);
  EXPECT_FALSE(GetClearResetAddressesAlarm()->IsSet());
  ProcessPacket(client_address, connection_id, /*has_version_flag=*/false,
                "data");
  const QuicTime expected_deadline =
      mock_helper_.GetClock()->Now() +
      QuicTime::Delta::FromMilliseconds(kTestLifeTimeMs);
  ASSERT_TRUE(GetClearResetAddressesAlarm()->IsSet());
  EXPECT_EQ(expected_deadline, GetClearResetAddressesAlarm()->deadline());
  // Received no version packet 2 after 5ms.
  mock_helper_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  ProcessPacket(client_address2, connection_id, /*has_version_flag=*/false,
                "data");
  ASSERT_TRUE(GetClearResetAddressesAlarm()->IsSet());
  // Verify deadline does not change.
  EXPECT_EQ(expected_deadline, GetClearResetAddressesAlarm()->deadline());
  // Verify reset gets throttled since there are too many recent addresses.
  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(0);
  ProcessPacket(client_address3, connection_id, /*has_version_flag=*/false,
                "data");

  mock_helper_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  GetClearResetAddressesAlarm()->Fire();
  EXPECT_CALL(*time_wait_list_manager_, SendPublicReset(_, _, _, _, _, _))
      .Times(2);
  ProcessPacket(client_address, connection_id, /*has_version_flag=*/false,
                "data");
  ProcessPacket(client_address2, connection_id, /*has_version_flag=*/false,
                "data");
  ProcessPacket(client_address3, connection_id, /*has_version_flag=*/false,
                "data");
}

// Makes sure nine-byte connection IDs are replaced by 8-byte ones.
TEST_P(QuicDispatcherTestAllVersions, LongConnectionIdLengthReplaced) {
  if (!version_.AllowsVariableLengthConnectionIds()) {
    // When variable length connection IDs are not supported, the connection
    // fails. See StrayPacketTruncatedConnectionId.
    return;
  }
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  QuicConnectionId bad_connection_id = TestConnectionIdNineBytesLong(2);
  generated_connection_id_ = kReturnConnectionId;

  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(*generated_connection_id_, _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, *generated_connection_id_, client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(
          Invoke([this, bad_connection_id](const QuicEncryptedPacket& packet) {
            ValidatePacket(bad_connection_id, packet);
          })));
  ProcessFirstFlight(client_address, bad_connection_id);
}

// Makes sure TestConnectionId(1) creates a new connection and
// TestConnectionIdNineBytesLong(2) gets replaced.
TEST_P(QuicDispatcherTestAllVersions, MixGoodAndBadConnectionIdLengthPackets) {
  if (!version_.AllowsVariableLengthConnectionIds()) {
    return;
  }

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  QuicConnectionId bad_connection_id = TestConnectionIdNineBytesLong(2);

  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(1), _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessFirstFlight(client_address, TestConnectionId(1));

  generated_connection_id_ = kReturnConnectionId;
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(*generated_connection_id_, _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, *generated_connection_id_, client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session2_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session2_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(
          Invoke([this, bad_connection_id](const QuicEncryptedPacket& packet) {
            ValidatePacket(bad_connection_id, packet);
          })));
  ProcessFirstFlight(client_address, bad_connection_id);

  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(1)
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessPacket(client_address, TestConnectionId(1), false, "data");
}

TEST_P(QuicDispatcherTestAllVersions, ProcessPacketWithZeroPort) {
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 0);

  // dispatcher_ should drop this packet.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(TestConnectionId(1), _,
                                              client_address, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  ProcessPacket(client_address, TestConnectionId(1), /*has_version_flag=*/true,
                "data");
}

TEST_P(QuicDispatcherTestAllVersions, ProcessPacketWithBlockedPort) {
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 17);

  // dispatcher_ should drop this packet.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(TestConnectionId(1), _,
                                              client_address, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  ProcessPacket(client_address, TestConnectionId(1), /*has_version_flag=*/true,
                "data");
}

TEST_P(QuicDispatcherTestAllVersions, ProcessPacketWithNonBlockedPort) {
  CreateTimeWaitListManager();

  // Port 443 must not be blocked because it might be useful for proxies to send
  // proxied traffic with source port 443 as that allows building a full QUIC
  // proxy using a single UDP socket.
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 443);

  // dispatcher_ should not drop this packet.
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(1), _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  ProcessFirstFlight(client_address, TestConnectionId(1));
}

TEST_P(QuicDispatcherTestAllVersions,
       DropPacketWithKnownVersionAndInvalidShortInitialConnectionId) {
  if (!version_.AllowsVariableLengthConnectionIds()) {
    return;
  }
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  // dispatcher_ should drop this packet.
  EXPECT_CALL(connection_id_generator_, ConnectionIdLength(0x00))
      .WillOnce(Return(10));
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(client_address, EmptyQuicConnectionId());
}

TEST_P(QuicDispatcherTestAllVersions,
       DropPacketWithKnownVersionAndInvalidInitialConnectionId) {
  CreateTimeWaitListManager();

  QuicSocketAddress server_address;
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  // dispatcher_ should drop this packet with invalid connection ID.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  absl::string_view cid_str = "123456789abcdefg123456789abcdefg";
  QuicConnectionId invalid_connection_id(cid_str.data(), cid_str.length());
  QuicReceivedPacket packet("packet", 6, QuicTime::Zero());
  ReceivedPacketInfo packet_info(server_address, client_address, packet);
  packet_info.version_flag = true;
  packet_info.version = version_;
  packet_info.destination_connection_id = invalid_connection_id;

  ASSERT_TRUE(dispatcher_->MaybeDispatchPacket(packet_info));
}

void QuicDispatcherTestBase::
    TestVersionNegotiationForUnknownVersionInvalidShortInitialConnectionId(
        const QuicConnectionId& server_connection_id,
        const QuicConnectionId& client_connection_id) {
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              SendVersionNegotiationPacket(
                  server_connection_id, client_connection_id,
                  /*ietf_quic=*/true,
                  /*use_length_prefix=*/true, _, _, client_address, _))
      .Times(1);
  expect_generator_is_called_ = false;
  EXPECT_CALL(connection_id_generator_, ConnectionIdLength(_)).Times(0);
  ProcessFirstFlight(ParsedQuicVersion::ReservedForNegotiation(),
                     client_address, server_connection_id,
                     client_connection_id);
}

TEST_P(QuicDispatcherTestOneVersion,
       VersionNegotiationForUnknownVersionInvalidShortInitialConnectionId) {
  TestVersionNegotiationForUnknownVersionInvalidShortInitialConnectionId(
      EmptyQuicConnectionId(), EmptyQuicConnectionId());
}

TEST_P(QuicDispatcherTestOneVersion,
       VersionNegotiationForUnknownVersionInvalidShortInitialConnectionId2) {
  char server_connection_id_bytes[3] = {1, 2, 3};
  QuicConnectionId server_connection_id(server_connection_id_bytes,
                                        sizeof(server_connection_id_bytes));
  TestVersionNegotiationForUnknownVersionInvalidShortInitialConnectionId(
      server_connection_id, EmptyQuicConnectionId());
}

TEST_P(QuicDispatcherTestOneVersion,
       VersionNegotiationForUnknownVersionInvalidShortInitialConnectionId3) {
  char client_connection_id_bytes[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  QuicConnectionId client_connection_id(client_connection_id_bytes,
                                        sizeof(client_connection_id_bytes));
  TestVersionNegotiationForUnknownVersionInvalidShortInitialConnectionId(
      EmptyQuicConnectionId(), client_connection_id);
}

TEST_P(QuicDispatcherTestOneVersion, VersionsChangeInFlight) {
  VerifyVersionNotSupported(QuicVersionReservedForNegotiation());
  for (ParsedQuicVersion version : CurrentSupportedVersions()) {
    VerifyVersionSupported(version);
    QuicDisableVersion(version);
    VerifyVersionNotSupported(version);
    QuicEnableVersion(version);
    VerifyVersionSupported(version);
  }
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionDraft28WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 0xFF, 0x00, 0x00, 28, /*destination connection ID length*/ 0x08};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionDraft27WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 0xFF, 0x00, 0x00, 27, /*destination connection ID length*/ 0x08};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionDraft25WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 0xFF, 0x00, 0x00, 25, /*destination connection ID length*/ 0x08};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionT050WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 'T', '0', '5', '0', /*destination connection ID length*/ 0x08};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionQ049WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_
```