Response:
The user wants to understand the functionality of a specific part of a C++ file related to network testing in Chromium's QUIC implementation. They're asking for:

1. **Functionality Summary:** What does this code do?
2. **JavaScript Relation:** Are there any connections to JavaScript? If so, how?
3. **Logical Inference:** Can we deduce inputs and outputs based on the code?
4. **Common Errors:** What mistakes do users or programmers typically make related to this?
5. **User Journey:** How does a user's action lead to this code being executed?
6. **Part Summary:**  A concise summary of this specific section of the code.

Let's break down each of these points by analyzing the provided code snippets.

**Code Analysis:**

The code consists of several C++ test cases within a larger testing framework. These tests focus on various aspects of QUIC's end-to-end behavior, particularly around connection migration, path validation, server preferred addresses, connection ID management, and key updates.

* **Path Degrading and Migration:** Tests like `ClientDoNotMigrateOnPathDegrading`, `ClientMultiPortMigrationOnPathDegrading` explore how the client reacts to network path quality changes and whether it initiates connection migration.
* **Server Preferred Address:** Tests like `SimpleServerPreferredAddressTest`, `SimpleServerPreferredAddressTestNoSPAD`, `OptimizedServerPreferredAddress` verify the mechanism where the server suggests an alternative address for the client to connect to.
* **Packet Reordering and Path Validation:** Tests like `ReorderedPathChallenge`, `PathValidationFailure`, `MigrateAgainAfterPathValidationFailure`, and `MigrateAgainAfterPathValidationFailureWithNonZeroClientCid` examine how the client handles out-of-order packets during path validation and what happens when path validation fails.
* **Connection ID Management:** Several tests implicitly or explicitly cover connection ID usage during migration and updates (`ClientMultiPortMigrationOnPathDegrading`,  `MigrateAgainAfterPathValidationFailure`, `MigrateAgainAfterPathValidationFailureWithNonZeroClientCid`).
* **0-RTT and Buffering:** The `Buffer0RttRequest` test checks the behavior when a client sends data before the handshake is fully complete (0-RTT).
* **Stream Management:** `SimpleStopSendingRstStreamTest` verifies how `RST_STREAM` and `STOP_SENDING` frames affect stream states.
* **Connection Closure:** `ConnectionCloseBeforeHandshakeComplete` and `ForwardSecureConnectionClose` test different scenarios of connection closure during the handshake process.
* **Stream ID Limits:** `TooBigStreamIdClosesConnection` checks if the connection is closed when a stream ID exceeds the allowed limit.
* **Custom Transport Parameters:** `CustomTransportParameters` tests the ability to exchange custom parameters during the QUIC handshake.
* **Key Updates:** `KeyUpdateInitiatedByClient` and `KeyUpdateInitiatedByServer` verify the key update mechanism initiated by either the client or the server.

**Addressing the User's Questions:**

1. **Functionality Summary:** This section of the `end_to_end_test.cc` file focuses on testing various advanced features and edge cases of the QUIC protocol implementation in Chromium. It specifically tests connection migration under different conditions (path degradation, multi-port), server preferred address handling, robustness against packet reordering, connection ID lifecycle, 0-RTT behavior, stream management, connection closure scenarios during handshake, stream ID limits, custom transport parameters, and key update mechanisms.

2. **JavaScript Relation:**  While this C++ code directly tests the QUIC implementation, QUIC is the underlying transport protocol for HTTP/3. Web browsers (like Chrome) use this QUIC implementation. JavaScript running in a browser uses the browser's networking stack.

    * **Example:** When a JavaScript application uses `fetch()` to make an HTTP/3 request, the browser's networking stack, including the QUIC implementation tested here, handles the underlying communication. If a network path degrades during this `fetch()` call, the logic tested in `ClientMultiPortMigrationOnPathDegrading` would be involved in potentially migrating the connection to a better path, making the `fetch()` call more reliable without the JavaScript code needing to be aware of the underlying QUIC complexities.

3. **Logical Inference (Hypothetical):**

    * **Assumption:** `client_->SendSynchronousRequest("/foo")` sends an HTTP request to the server. The server is configured to respond with "kFooResponseBody".

    * **Input (for `SimpleServerPreferredAddressTest`):**
        * Server advertises a preferred address.
        * Client connects initially to the primary server address.
        * Client sends a request.

    * **Output (for `SimpleServerPreferredAddressTest`):**
        * The client successfully validates the server's preferred address.
        * Subsequent requests are sent to the server's preferred address.
        * Connection IDs might change due to the migration.
        * Client-side statistics will reflect the successful validation.

4. **Common Errors:**

    * **Incorrect Server Configuration:**  If the server is not correctly configured to send a `NEW_CONNECTION_ID` frame or advertise a preferred address, tests related to connection migration or server preferred addresses might fail. For example, in `SimpleServerPreferredAddressTest`, if the server doesn't send the necessary transport parameters containing the preferred address, the client won't be able to validate it.

    * **Network Interference:**  Tests involving packet reordering or path degradation might behave unexpectedly if the test environment doesn't accurately simulate these network conditions. For instance, in `PathValidationFailure`, if packets are not reliably dropped as intended by `server_writer_->set_fake_packet_loss_percentage(100)`, the path validation might not time out as expected.

    * **Client Configuration Mismatch:** If the client's configuration doesn't align with the server's capabilities (e.g., not enabling multi-port migration when the server supports it), tests for those features will not be properly exercised. For example, in `ClientMultiPortMigrationOnPathDegrading`, if `client_config_.SetClientConnectionOptions(QuicTagVector{kMPQC, kMPQM})` is not set, multi-port migration won't be attempted.

5. **User Journey (Debugging):**

    Let's imagine a user in Chrome experiences intermittent connectivity issues with a website. Here's how it might relate to this code:

    1. **User Action:** The user browses a website that uses HTTP/3.
    2. **Network Issue:** The user's network connection experiences temporary degradation (e.g., signal weakening on Wi-Fi).
    3. **QUIC Detection:** The browser's QUIC implementation detects the path degradation. This might trigger the logic in `client_connection->OnPathDegradingDetected()` as seen in `ClientDoNotMigrateOnPathDegrading` and `ClientMultiPortMigrationOnPathDegrading`.
    4. **Connection Migration (Potential):** If multi-port is enabled, the QUIC implementation might attempt to migrate the connection to an alternative network path (if available), as tested in `ClientMultiPortMigrationOnPathDegrading`.
    5. **Path Validation:**  After migration, the browser will perform path validation (sending `PATH_CHALLENGE` and expecting `PATH_RESPONSE`), as tested in `ReorderedPathChallenge` and `PathValidationFailure`.
    6. **Debugging:** If the user reports the issue, developers might look at network logs in Chrome's developer tools. They might see events related to path degradation, connection migration attempts, and path validation failures. They could then use the tests in `end_to_end_test.cc` to reproduce and debug the specific scenario the user encountered. For instance, if path validation is failing, they might focus on the `PathValidationFailure` test.

6. **Part Summary:** This specific section of `end_to_end_test.cc` extensively tests QUIC's resilience and advanced features related to connection management and adaptation in the face of changing network conditions. It covers scenarios like path degradation, connection migration, server preferred addresses, connection ID management, handling packet reordering during path validation, and key updates. These tests are crucial for ensuring the robustness and reliability of Chromium's QUIC implementation.
This section of the `end_to_end_test.cc` file primarily focuses on testing the **connection migration and path validation** functionalities of the QUIC protocol, particularly in scenarios involving packet reordering and server-preferred addresses. It also includes tests for other features like `STOP_SENDING`, connection closure during handshake, stream ID limits, custom transport parameters, and key updates.

Here's a breakdown of the functionalities tested in this part:

**Key Functionalities Tested:**

* **Path Degrading and No Migration:** Verifies that if path degrading is detected but the maximum number of allowed mitigations has been reached, the client will not attempt to migrate.
* **Client Multi-Port Migration on Path Degrading:** Tests the scenario where the client, configured for multi-port, initiates connection migration when path degradation is detected. It checks if the client switches to an alternative path and retires connection IDs.
* **Simple Server Preferred Address:** Tests the basic functionality where the client learns the server's preferred address and migrates to it after validating the path.
* **Optimized Server Preferred Address:** Tests a potentially optimized version of the server preferred address mechanism.
* **Reordered Path Challenge:** Simulates a scenario where a `PATH_CHALLENGE` packet is reordered and verifies that the client and server correctly handle it.
* **Path Validation Failure:** Tests the case where path validation to a new network address fails due to dropped `PATH_RESPONSE` packets. It verifies that the client falls back to the original address.
* **Migration After Path Validation Failure:**  Tests scenarios where the client attempts to migrate again after a previous path validation failed, including cases with non-zero client connection IDs.
* **Buffering 0-RTT Requests:** Checks if the client can correctly buffer and send 0-RTT data even when handshake confirmation is delayed due to packet reordering.
* **Simple STOP_SENDING RST_STREAM Test:** Verifies the interaction between `STOP_SENDING` and `RST_STREAM` frames for closing streams.
* **Connection Close Before Handshake Complete:** Tests how the client handles a connection close initiated by the server before the handshake is fully complete.
* **Forward Secure Connection Close:** Tests the scenario where the server closes the connection after reaching forward-secure encryption.
* **Too Big Stream ID Closes Connection:**  For IETF QUIC, verifies that the connection is closed if the client attempts to use a stream ID that exceeds the allowed maximum.
* **Custom Transport Parameters:** Tests the ability to send and receive custom transport parameters during the QUIC handshake.
* **Key Update Initiated by Client/Server:**  Tests the key update mechanism where either the client or the server initiates a key rotation.

**Relationship to JavaScript:**

While this C++ code is not directly related to JavaScript code execution, it is fundamental to the networking stack used by web browsers (like Chrome) where JavaScript runs.

* **Example:** When a JavaScript application in a browser uses the `fetch()` API to make an HTTP/3 request, the underlying network communication is handled by the QUIC implementation tested here. If the network path degrades during the `fetch()`, the logic tested in sections like `ClientMultiPortMigrationOnPathDegrading` would be responsible for potentially migrating the connection to a better path, making the `fetch()` call more reliable without the JavaScript code needing to be aware of the underlying QUIC complexities. The tests ensure that these migration and validation mechanisms function correctly, leading to a better user experience for web applications.

**Logical Inference (Hypothetical Input and Output):**

Let's take the `SimpleServerPreferredAddressTest` as an example:

* **Assumption:** The server is configured to advertise a preferred address during the handshake.
* **Input:**
    * Client initiates a connection to the server's initial address.
    * The server sends its preferred address in the transport parameters.
    * The client sends a request (`SendSynchronousFooRequestAndCheckResponse()`).
* **Output:**
    * The client's `effective_peer_address()` will initially be the server's initial address.
    * After successful path validation to the preferred address, the client's `effective_peer_address()` will change to the server's preferred address.
    * The client connection statistics (`GetClientConnection()->GetStats()`) will show `server_preferred_address_validated` as true.
    * The connection ID might change during the migration.

**User or Programming Common Usage Errors:**

* **Incorrect Server Configuration:**  A common error would be a server not being correctly configured to send the `NEW_CONNECTION_ID` frame or advertise the preferred address. This would cause tests like `SimpleServerPreferredAddressTest` to fail, and in a real-world scenario, clients wouldn't be able to migrate to the preferred address.
* **Client Not Supporting Multi-Port:** If a client's configuration doesn't enable multi-port support, tests like `ClientMultiPortMigrationOnPathDegrading` wouldn't be properly exercised. Similarly, in a real application, the client wouldn't be able to take advantage of multi-port migration even if the server supports it.
* **Misunderstanding Connection ID Lifecycle:**  Developers might incorrectly assume that connection IDs remain static throughout the connection's lifetime. The tests here highlight that connection IDs can change during migration and key updates.
* **Improperly Handling Path Validation Failures:**  A client implementation might not correctly handle scenarios where path validation to a new address fails, potentially leading to connection stalls or errors. The `PathValidationFailure` tests ensure the robustness of this handling.

**User Operation to Reach Here (Debugging Clues):**

Let's consider a user experiencing intermittent network issues on a website using HTTP/3:

1. **User Browses a Website:** The user opens a website in Chrome that utilizes the HTTP/3 protocol.
2. **Network Fluctuation:** The user's network connection experiences a temporary drop in quality or a change in the underlying IP address (e.g., switching from Wi-Fi to cellular).
3. **QUIC Detects Path Degradation:** The browser's QUIC implementation detects the network path degradation, potentially triggering the logic checked in `client_connection->OnPathDegradingDetected()` (as seen in the first test of this section).
4. **QUIC Attempts Migration (if configured):** If multi-port is enabled, the QUIC implementation might attempt to migrate the connection to a new IP address or port, similar to what's tested in `ClientMultiPortMigrationOnPathDegrading`.
5. **Path Validation Initiated:** After a migration attempt, the QUIC implementation will initiate path validation to ensure the new path is viable. This involves sending `PATH_CHALLENGE` frames, as tested in `ReorderedPathChallenge`.
6. **Path Validation Failure (Possible):** If packets are lost during the path validation process (simulated by `server_writer_->set_fake_packet_loss_percentage(100)` in `PathValidationFailure`), the validation might fail.
7. **Debugging:** If the user reports issues, developers might investigate network logs in Chrome's developer tools. They might see QUIC events related to path degrading, migration attempts, and path validation failures. The tests in this file provide a way to reproduce and understand these scenarios in a controlled environment.

**归纳一下它的功能 (Summary of its Functionality):**

This section of the `end_to_end_test.cc` file meticulously tests the QUIC protocol's capabilities related to **connection migration, path validation, and related connection management features**. It covers scenarios where the client proactively migrates due to path degradation, utilizes server-provided preferred addresses, handles packet reordering during path validation, and gracefully recovers from path validation failures. Furthermore, it includes tests for stream management (`STOP_SENDING`), connection lifecycle during handshake, stream ID limits, custom transport parameters, and key updates, ensuring the overall robustness and reliability of the QUIC implementation in various network conditions and protocol interactions.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
The next path degrading shouldn't trigger port migration.
  WaitForNewConnectionIds();
  QuicSocketAddress original_self_addr = client_connection->self_address();
  client_connection->OnPathDegradingDetected();
  EXPECT_FALSE(client_->client()->HasPendingPathValidation());
  client_->SendSynchronousRequest("/eep");
  EXPECT_EQ(original_self_addr, client_connection->self_address());
  EXPECT_EQ(max_num_path_degrading_to_mitigate + 1,
            GetClientConnection()->GetStats().num_path_degrading);
  EXPECT_EQ(max_num_path_degrading_to_mitigate,
            GetClientConnection()->GetStats().num_path_response_received);
}

TEST_P(EndToEndTest, ClientMultiPortMigrationOnPathDegrading) {
  client_config_.SetClientConnectionOptions(QuicTagVector{kMPQC, kMPQM});
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));
  QuicConnection* client_connection = GetClientConnection();
  QuicSpdyClientStream* stream = client_->GetOrCreateStream();
  ASSERT_TRUE(stream);
  // Increase the probing frequency to speed up this test.
  client_connection->SetMultiPortProbingInterval(
      QuicTime::Delta::FromMilliseconds(100));
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return 1u == client_connection->GetStats().num_path_response_received;
  }));
  // Verify that the alternative path keeps sending probes periodically.
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return 2u == client_connection->GetStats().num_path_response_received;
  }));
  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  // Verify that no migration has happened.
  if (server_connection != nullptr) {
    EXPECT_EQ(0u, server_connection->GetStats()
                      .num_peer_migration_to_proactively_validated_address);
  }
  server_thread_->Resume();

  auto original_self_addr = client_connection->self_address();
  // Trigger client side path degrading
  client_connection->OnPathDegradingDetected();
  EXPECT_NE(original_self_addr, client_connection->self_address());

  // Send another request to trigger connection id retirement.
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(1u, client_connection->GetStats().num_retire_connection_id_sent);
  auto new_alt_path = QuicConnectionPeer::GetAlternativePath(client_connection);
  EXPECT_NE(client_connection->self_address(), new_alt_path->self_address);

  stream->Reset(QuicRstStreamErrorCode::QUIC_STREAM_NO_ERROR);
}

TEST_P(EndToEndTest, SimpleServerPreferredAddressTest) {
  use_preferred_address_ = true;
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(CreateQuicClient(nullptr));
  QuicConnection* client_connection = GetClientConnection();
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  EXPECT_EQ(server_address_, client_connection->effective_peer_address());
  EXPECT_EQ(server_address_, client_connection->peer_address());
  EXPECT_TRUE(client_->client()->HasPendingPathValidation());
  QuicConnectionId server_cid1 = client_connection->connection_id();

  SendSynchronousFooRequestAndCheckResponse();
  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(server_preferred_address_,
            client_connection->effective_peer_address());
  EXPECT_EQ(server_preferred_address_, client_connection->peer_address());
  EXPECT_NE(server_cid1, client_connection->connection_id());

  const auto client_stats = GetClientConnection()->GetStats();
  EXPECT_TRUE(client_stats.server_preferred_address_validated);
  EXPECT_FALSE(client_stats.failed_to_validate_server_preferred_address);
}

TEST_P(EndToEndTest, SimpleServerPreferredAddressTestNoSPAD) {
  SetQuicFlag(quic_always_support_server_preferred_address, true);
  use_preferred_address_ = true;
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(CreateQuicClient(nullptr));
  QuicConnection* client_connection = GetClientConnection();
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  EXPECT_EQ(server_address_, client_connection->effective_peer_address());
  EXPECT_EQ(server_address_, client_connection->peer_address());
  EXPECT_TRUE(client_->client()->HasPendingPathValidation());
  QuicConnectionId server_cid1 = client_connection->connection_id();

  SendSynchronousFooRequestAndCheckResponse();
  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(server_preferred_address_,
            client_connection->effective_peer_address());
  EXPECT_EQ(server_preferred_address_, client_connection->peer_address());
  EXPECT_NE(server_cid1, client_connection->connection_id());

  const auto client_stats = GetClientConnection()->GetStats();
  EXPECT_TRUE(client_stats.server_preferred_address_validated);
  EXPECT_FALSE(client_stats.failed_to_validate_server_preferred_address);
}

TEST_P(EndToEndTest, OptimizedServerPreferredAddress) {
  use_preferred_address_ = true;
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_config_.SetClientConnectionOptions(QuicTagVector{kSPA2});
  client_.reset(CreateQuicClient(nullptr));
  QuicConnection* client_connection = GetClientConnection();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  EXPECT_EQ(server_address_, client_connection->effective_peer_address());
  EXPECT_EQ(server_address_, client_connection->peer_address());
  EXPECT_TRUE(client_->client()->HasPendingPathValidation());
  SendSynchronousFooRequestAndCheckResponse();
  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }

  const auto client_stats = GetClientConnection()->GetStats();
  EXPECT_TRUE(client_stats.server_preferred_address_validated);
  EXPECT_FALSE(client_stats.failed_to_validate_server_preferred_address);
}

TEST_P(EndToEndPacketReorderingTest, ReorderedPathChallenge) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));

  // Finish one request to make sure handshake established.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  // Wait for the connection to become idle, to make sure the packet gets
  // delayed is the connectivity probing packet.
  client_->WaitForDelayedAcks();

  QuicSocketAddress old_addr =
      client_->client()->network_helper()->GetLatestClientAddress();

  // Migrate socket to the new IP address.
  QuicIpAddress new_host = TestLoopback(2);
  EXPECT_NE(old_addr.host(), new_host);

  // Setup writer wrapper to hold the probing packet.
  auto holding_writer = new PacketHoldingWriter();
  client_->UseWriter(holding_writer);
  // Write a connectivity probing after the next /foo request.
  holding_writer->HoldNextPacket();

  // A packet with PATH_CHALLENGE will be held in the writer.
  client_->client()->ValidateNewNetwork(new_host);

  // Send (on-hold) PATH_CHALLENGE after this request.
  client_->SendRequest("/foo");
  holding_writer->ReleasePacket();

  client_->WaitForResponse();

  EXPECT_EQ(kFooResponseBody, client_->response_body());
  // Send yet another request after the PATH_CHALLENGE, when this request
  // returns, the probing is guaranteed to have been received by the server, and
  // the server's response to probing is guaranteed to have been received by the
  // client.
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));

  // Client should have received a PATH_CHALLENGE.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    EXPECT_EQ(1u,
              server_connection->GetStats().num_connectivity_probing_received);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndPacketReorderingTest, PathValidationFailure) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  client_.reset(CreateQuicClient(nullptr));
  // Finish one request to make sure handshake established.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  // Wait for the connection to become idle, to make sure the packet gets
  // delayed is the connectivity probing packet.
  client_->WaitForDelayedAcks();

  QuicSocketAddress old_addr = client_->client()->session()->self_address();

  // Migrate socket to the new IP address.
  QuicIpAddress new_host = TestLoopback(2);
  EXPECT_NE(old_addr.host(), new_host);

  // Drop PATH_RESPONSE packets to timeout the path validation.
  server_writer_->set_fake_packet_loss_percentage(100);
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(new_host));
  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(old_addr, client_->client()->session()->self_address());
  server_writer_->set_fake_packet_loss_percentage(0);
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    EXPECT_EQ(3u,
              server_connection->GetStats().num_connectivity_probing_received);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndPacketReorderingTest, MigrateAgainAfterPathValidationFailure) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  client_.reset(CreateQuicClient(nullptr));
  // Finish one request to make sure handshake established.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  // Wait for the connection to become idle, to make sure the packet gets
  // delayed is the connectivity probing packet.
  client_->WaitForDelayedAcks();

  QuicSocketAddress addr1 = client_->client()->session()->self_address();
  QuicConnection* client_connection = GetClientConnection();
  QuicConnectionId server_cid1 = client_connection->connection_id();

  // Migrate socket to the new IP address.
  QuicIpAddress host2 = TestLoopback(2);
  EXPECT_NE(addr1.host(), host2);

  // Drop PATH_RESPONSE packets to timeout the path validation.
  server_writer_->set_fake_packet_loss_percentage(100);
  ASSERT_TRUE(
      QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(client_connection));

  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host2));

  QuicConnectionId server_cid2 =
      QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
          client_connection);
  EXPECT_FALSE(server_cid2.IsEmpty());
  EXPECT_NE(server_cid2, server_cid1);
  // Wait until path validation fails at the client.
  while (client_->client()->HasPendingPathValidation()) {
    EXPECT_EQ(server_cid2,
              QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection));
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(addr1, client_->client()->session()->self_address());
  EXPECT_EQ(server_cid1, GetClientConnection()->connection_id());

  server_writer_->set_fake_packet_loss_percentage(0);
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));

  WaitForNewConnectionIds();
  EXPECT_EQ(1u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(0u, client_connection->GetStats().num_new_connection_id_sent);

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  // Server has received 3 path challenges.
  EXPECT_EQ(3u,
            server_connection->GetStats().num_connectivity_probing_received);
  EXPECT_EQ(server_cid1, server_connection->connection_id());
  EXPECT_EQ(0u, server_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(2u, server_connection->GetStats().num_new_connection_id_sent);
  server_thread_->Resume();

  // Migrate socket to a new IP address again.
  QuicIpAddress host3 = TestLoopback(3);
  EXPECT_NE(addr1.host(), host3);
  EXPECT_NE(host2, host3);

  WaitForNewConnectionIds();
  EXPECT_EQ(1u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(0u, client_connection->GetStats().num_new_connection_id_sent);

  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host3));
  QuicConnectionId server_cid3 =
      QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
          client_connection);
  EXPECT_FALSE(server_cid3.IsEmpty());
  EXPECT_NE(server_cid1, server_cid3);
  EXPECT_NE(server_cid2, server_cid3);
  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(host3, client_->client()->session()->self_address().host());
  EXPECT_EQ(server_cid3, GetClientConnection()->connection_id());
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));

  // Server should send a new connection ID to client.
  WaitForNewConnectionIds();
  EXPECT_EQ(2u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(0u, client_connection->GetStats().num_new_connection_id_sent);
}

TEST_P(EndToEndPacketReorderingTest,
       MigrateAgainAfterPathValidationFailureWithNonZeroClientCid) {
  if (!version_.HasIetfQuicFrames()) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_client_connection_id_length_ = kQuicDefaultConnectionIdLength;
  ASSERT_TRUE(Initialize());

  client_.reset(CreateQuicClient(nullptr));
  // Finish one request to make sure handshake established.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  // Wait for the connection to become idle, to make sure the packet gets
  // delayed is the connectivity probing packet.
  client_->WaitForDelayedAcks();

  QuicSocketAddress addr1 = client_->client()->session()->self_address();
  QuicConnection* client_connection = GetClientConnection();
  QuicConnectionId server_cid1 = client_connection->connection_id();
  QuicConnectionId client_cid1 = client_connection->client_connection_id();

  // Migrate socket to the new IP address.
  QuicIpAddress host2 = TestLoopback(2);
  EXPECT_NE(addr1.host(), host2);

  // Drop PATH_RESPONSE packets to timeout the path validation.
  server_writer_->set_fake_packet_loss_percentage(100);
  ASSERT_TRUE(
      QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(client_connection));
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host2));
  QuicConnectionId server_cid2 =
      QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
          client_connection);
  EXPECT_FALSE(server_cid2.IsEmpty());
  EXPECT_NE(server_cid2, server_cid1);
  QuicConnectionId client_cid2 =
      QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(
          client_connection);
  EXPECT_FALSE(client_cid2.IsEmpty());
  EXPECT_NE(client_cid2, client_cid1);
  while (client_->client()->HasPendingPathValidation()) {
    EXPECT_EQ(server_cid2,
              QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection));
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(addr1, client_->client()->session()->self_address());
  EXPECT_EQ(server_cid1, GetClientConnection()->connection_id());
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  server_writer_->set_fake_packet_loss_percentage(0);
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));
  WaitForNewConnectionIds();
  EXPECT_EQ(1u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(2u, client_connection->GetStats().num_new_connection_id_sent);

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    EXPECT_EQ(3u,
              server_connection->GetStats().num_connectivity_probing_received);
    EXPECT_EQ(server_cid1, server_connection->connection_id());
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  EXPECT_EQ(1u, server_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(2u, server_connection->GetStats().num_new_connection_id_sent);
  server_thread_->Resume();

  // Migrate socket to a new IP address again.
  QuicIpAddress host3 = TestLoopback(3);
  EXPECT_NE(addr1.host(), host3);
  EXPECT_NE(host2, host3);
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host3));

  QuicConnectionId server_cid3 =
      QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
          client_connection);
  EXPECT_FALSE(server_cid3.IsEmpty());
  EXPECT_NE(server_cid1, server_cid3);
  EXPECT_NE(server_cid2, server_cid3);
  QuicConnectionId client_cid3 =
      QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(
          client_connection);
  EXPECT_NE(client_cid1, client_cid3);
  EXPECT_NE(client_cid2, client_cid3);
  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(host3, client_->client()->session()->self_address().host());
  EXPECT_EQ(server_cid3, GetClientConnection()->connection_id());
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));

  // Server should send new server connection ID to client and retires old
  // client connection ID.
  WaitForNewConnectionIds();
  EXPECT_EQ(2u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(3u, client_connection->GetStats().num_new_connection_id_sent);
}

TEST_P(EndToEndPacketReorderingTest, Buffer0RttRequest) {
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls() &&
      GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    return;
  }
  // Finish one request to make sure handshake established.
  client_->SendSynchronousRequest("/foo");
  // Disconnect for next 0-rtt request.
  client_->Disconnect();

  // Client has valid Session Ticket now. Do a 0-RTT request.
  // Buffer a CHLO till the request is sent out. HTTP/3 sends two packets: a
  // SETTINGS frame and a request.
  reorder_writer_->SetDelay(version_.UsesHttp3() ? 2 : 1);
  // Only send out a CHLO.
  client_->client()->Initialize();

  // Send a request before handshake finishes.
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/bar";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  client_->SendMessage(headers, "");
  client_->WaitForResponse();
  EXPECT_EQ(kBarResponseBody, client_->response_body());
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionStats client_stats = client_connection->GetStats();
  EXPECT_EQ(0u, client_stats.packets_lost);
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());
}

TEST_P(EndToEndTest, SimpleStopSendingRstStreamTest) {
  ASSERT_TRUE(Initialize());

  // Send a request without a fin, to keep the stream open
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  client_->SendMessage(headers, "", /*fin=*/false);
  // Stream should be open
  ASSERT_NE(nullptr, client_->latest_created_stream());
  EXPECT_FALSE(client_->latest_created_stream()->write_side_closed());
  EXPECT_FALSE(
      QuicStreamPeer::read_side_closed(client_->latest_created_stream()));

  // Send a RST_STREAM+STOP_SENDING on the stream
  // Code is not important.
  client_->latest_created_stream()->Reset(QUIC_BAD_APPLICATION_PAYLOAD);
  client_->WaitForResponse();

  // Stream should be gone.
  ASSERT_EQ(nullptr, client_->latest_created_stream());
}

class BadShloPacketWriter : public QuicPacketWriterWrapper {
 public:
  BadShloPacketWriter(ParsedQuicVersion version)
      : error_returned_(false), version_(version) {}
  ~BadShloPacketWriter() override {}

  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          quic::PerPacketOptions* options,
                          const quic::QuicPacketWriterParams& params) override {
    const WriteResult result = QuicPacketWriterWrapper::WritePacket(
        buffer, buf_len, self_address, peer_address, options, params);
    const uint8_t type_byte = buffer[0];
    if (!error_returned_ && (type_byte & FLAGS_LONG_HEADER) &&
        TypeByteIsServerHello(type_byte)) {
      QUIC_DVLOG(1) << "Return write error for packet containing ServerHello";
      error_returned_ = true;
      return WriteResult(WRITE_STATUS_ERROR, *MessageTooBigErrorCode());
    }
    return result;
  }

  bool TypeByteIsServerHello(uint8_t type_byte) {
    if (version_.UsesV2PacketTypes()) {
      return ((type_byte & 0x30) >> 4) == 3;
    }
    if (version_.UsesQuicCrypto()) {
      // ENCRYPTION_ZERO_RTT packet.
      return ((type_byte & 0x30) >> 4) == 1;
    }
    // ENCRYPTION_HANDSHAKE packet.
    return ((type_byte & 0x30) >> 4) == 2;
  }

 private:
  bool error_returned_;
  ParsedQuicVersion version_;
};

TEST_P(EndToEndTest, ConnectionCloseBeforeHandshakeComplete) {
  // This test ensures ZERO_RTT_PROTECTED connection close could close a client
  // which has switched to forward secure.
  connect_to_server_on_initialize_ = false;
  ASSERT_TRUE(Initialize());
  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  if (dispatcher == nullptr) {
    ADD_FAILURE() << "Missing dispatcher";
    server_thread_->Resume();
    return;
  }
  if (dispatcher->NumSessions() > 0) {
    ADD_FAILURE() << "Dispatcher session map not empty";
    server_thread_->Resume();
    return;
  }
  // Note: this writer will only used by the server connection, not the time
  // wait list.
  QuicDispatcherPeer::UseWriter(
      dispatcher,
      // This causes the first server sent ZERO_RTT_PROTECTED packet (i.e.,
      // SHLO) to be sent, but WRITE_ERROR is returned. Such that a
      // ZERO_RTT_PROTECTED connection close would be sent to a client with
      // encryption level FORWARD_SECURE.
      new BadShloPacketWriter(version_));
  server_thread_->Resume();

  client_.reset(CreateQuicClient(client_writer_));
  EXPECT_EQ("", client_->SendSynchronousRequest("/foo"));
  // Verify ZERO_RTT_PROTECTED connection close is successfully processed by
  // client which switches to FORWARD_SECURE.
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_PACKET_WRITE_ERROR));
}

class BadShloPacketWriter2 : public QuicPacketWriterWrapper {
 public:
  BadShloPacketWriter2(ParsedQuicVersion version)
      : error_returned_(false), version_(version) {}
  ~BadShloPacketWriter2() override {}

  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          quic::PerPacketOptions* options,
                          const quic::QuicPacketWriterParams& params) override {
    const uint8_t type_byte = buffer[0];

    if (type_byte & FLAGS_LONG_HEADER) {
      if (((type_byte & 0x30 >> 4) == (version_.UsesV2PacketTypes() ? 2 : 1)) ||
          ((type_byte & 0x7F) == 0x7C)) {
        QUIC_DVLOG(1) << "Dropping ZERO_RTT_PACKET packet";
        return WriteResult(WRITE_STATUS_OK, buf_len);
      }
    } else if (!error_returned_) {
      QUIC_DVLOG(1) << "Return write error for short header packet";
      error_returned_ = true;
      return WriteResult(WRITE_STATUS_ERROR, *MessageTooBigErrorCode());
    }
    return QuicPacketWriterWrapper::WritePacket(buffer, buf_len, self_address,
                                                peer_address, options, params);
  }

 private:
  bool error_returned_;
  ParsedQuicVersion version_;
};

TEST_P(EndToEndTest, ForwardSecureConnectionClose) {
  // This test ensures ZERO_RTT_PROTECTED connection close is sent to a client
  // which has ZERO_RTT_PROTECTED encryption level.
  connect_to_server_on_initialize_ = false;
  ASSERT_TRUE(Initialize());
  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  if (dispatcher == nullptr) {
    ADD_FAILURE() << "Missing dispatcher";
    server_thread_->Resume();
    return;
  }
  if (dispatcher->NumSessions() > 0) {
    ADD_FAILURE() << "Dispatcher session map not empty";
    server_thread_->Resume();
    return;
  }
  // Note: this writer will only used by the server connection, not the time
  // wait list.
  QuicDispatcherPeer::UseWriter(
      dispatcher,
      // This causes the all server sent ZERO_RTT_PROTECTED packets to be
      // dropped, and first short header packet causes write error.
      new BadShloPacketWriter2(version_));
  server_thread_->Resume();
  client_.reset(CreateQuicClient(client_writer_));
  EXPECT_EQ("", client_->SendSynchronousRequest("/foo"));
  // Verify ZERO_RTT_PROTECTED connection close is successfully processed by
  // client.
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_PACKET_WRITE_ERROR));
}

// Test that the stream id manager closes the connection if a stream
// in excess of the allowed maximum.
TEST_P(EndToEndTest, TooBigStreamIdClosesConnection) {
  // Has to be before version test, see EndToEndTest::TearDown()
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    // Only runs for IETF QUIC.
    return;
  }
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  std::string body(kMaxOutgoingPacketSize, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  // Force the client to write with a stream ID that exceeds the limit.
  QuicSpdySession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicStreamIdManager* stream_id_manager =
      QuicSessionPeer::ietf_bidirectional_stream_id_manager(client_session);
  ASSERT_TRUE(stream_id_manager);
  QuicStreamCount max_number_of_streams =
      stream_id_manager->outgoing_max_streams();
  QuicSessionPeer::SetNextOutgoingBidirectionalStreamId(
      client_session,
      GetNthClientInitiatedBidirectionalId(max_number_of_streams + 1));
  client_->SendCustomSynchronousRequest(headers, body);
  EXPECT_THAT(client_->stream_error(),
              IsStreamError(QUIC_STREAM_CONNECTION_ERROR));
  EXPECT_THAT(client_session->error(), IsError(QUIC_INVALID_STREAM_ID));
  EXPECT_EQ(IETF_QUIC_TRANSPORT_CONNECTION_CLOSE, client_session->close_type());
  EXPECT_TRUE(
      IS_IETF_STREAM_FRAME(client_session->transport_close_frame_type()));
}

TEST_P(EndToEndTest, CustomTransportParameters) {
  if (!version_.UsesTls()) {
    // Custom transport parameters are only supported with TLS.
    ASSERT_TRUE(Initialize());
    return;
  }
  constexpr auto kCustomParameter =
      static_cast<TransportParameters::TransportParameterId>(0xff34);
  client_config_.custom_transport_parameters_to_send()[kCustomParameter] =
      "test";
  NiceMock<MockQuicConnectionDebugVisitor> visitor;
  connection_debug_visitor_ = &visitor;
  EXPECT_CALL(visitor, OnTransportParametersSent(_))
      .WillOnce(Invoke([kCustomParameter](
                           const TransportParameters& transport_parameters) {
        auto it = transport_parameters.custom_parameters.find(kCustomParameter);
        ASSERT_NE(it, transport_parameters.custom_parameters.end());
        EXPECT_EQ(it->second, "test");
      }));
  EXPECT_CALL(visitor, OnTransportParametersReceived(_)).Times(1);
  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  QuicConfig* server_config = nullptr;
  if (server_session != nullptr) {
    server_config = server_session->config();
  } else {
    ADD_FAILURE() << "Missing server session";
  }
  if (server_config != nullptr) {
    if (auto it = server_config->received_custom_transport_parameters().find(
            kCustomParameter);
        it != server_config->received_custom_transport_parameters().end()) {
      EXPECT_EQ(it->second, "test");
    } else {
      ADD_FAILURE() << "Did not find custom parameter";
    }
  } else {
    ADD_FAILURE() << "Missing server config";
  }
  server_thread_->Resume();
}

// Testing packet writer that makes a copy of the first sent packets before
// sending them. Useful for tests that need access to sent packets.
class CopyingPacketWriter : public PacketDroppingTestWriter {
 public:
  explicit CopyingPacketWriter(int num_packets_to_copy)
      : num_packets_to_copy_(num_packets_to_copy) {}
  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options,
                          const QuicPacketWriterParams& params) override {
    if (num_packets_to_copy_ > 0) {
      num_packets_to_copy_--;
      packets_.push_back(
          QuicEncryptedPacket(buffer, buf_len, /*owns_buffer=*/false).Clone());
    }
    return PacketDroppingTestWriter::WritePacket(buffer, buf_len, self_address,
                                                 peer_address, options, params);
  }

  std::vector<std::unique_ptr<QuicEncryptedPacket>>& packets() {
    return packets_;
  }

 private:
  int num_packets_to_copy_;
  std::vector<std::unique_ptr<QuicEncryptedPacket>> packets_;
};

TEST_P(EndToEndTest, KeyUpdateInitiatedByClient) {
  if (!version_.UsesTls()) {
    // Key Update is only supported in TLS handshake.
    ASSERT_TRUE(Initialize());
    return;
  }

  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(0u, client_connection->GetStats().key_update_count);

  EXPECT_TRUE(
      client_connection->InitiateKeyUpdate(KeyUpdateReason::kLocalForTests));
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(1u, client_connection->GetStats().key_update_count);

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(1u, client_connection->GetStats().key_update_count);

  EXPECT_TRUE(
      client_connection->InitiateKeyUpdate(KeyUpdateReason::kLocalForTests));
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(2u, client_connection->GetStats().key_update_count);

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection) {
    QuicConnectionStats server_stats = server_connection->GetStats();
    EXPECT_EQ(2u, server_stats.key_update_count);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, KeyUpdateInitiatedByServer) {
  if (!version_.UsesTls()) {
    // Key Update is only supported in TLS handshake.
    ASSERT_TRUE(Initialize());
    return;
  }

  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(0u, client_connection->GetStats().key_update_count);

  // Use WaitUntil to ensure the server had executed the key update predicate
  // before sending the Foo request, otherwise the test can be flaky if it
  // receives the Foo request before executing the key update.
  server_thread_->WaitUntil(
      [this]() {
        QuicConnection* server_connection = GetServerConnection();
        if (server_connection != nullptr) {
          if (!server_connection->IsKeyUpdateAllowed()) {
            // Server may not have received ack from client yet for the current
            // key phase, wait a bit and try again.
            return false;
          }
          EXPECT_TRUE(server_connection->InitiateKeyUpdate(
              KeyUpdateReason::kLocalForTests));
        } else {
          ADD_FAILURE() << "Missing server connection";
        }
        return true;
      },
      QuicTime::Delta::FromSeconds(5));

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(1u, client_connection->GetStats().key_update_cou
```