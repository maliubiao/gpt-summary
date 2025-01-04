Response:
My thinking process for analyzing the provided C++ code snippet goes like this:

1. **Understand the Context:** The initial prompt clearly states this is a part of Chromium's network stack, specifically related to QUIC (a network protocol) and HTTP. The file path (`net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc`) strongly suggests it's an integration or end-to-end test file.

2. **High-Level Structure Recognition:**  I scan the code for familiar C++ testing constructs. The `TEST_P` macros immediately stand out. This signals that it's using Google Test with parameterized tests. The `EndToEndTest` class is the test fixture.

3. **Identify Key Components:**  I look for variables and methods that indicate the core functionality being tested:
    * `client_`:  Likely an object representing a QUIC client.
    * `server_thread_`:  Indicates a separate thread for the QUIC server.
    * `Initialize()`: A setup method common in tests.
    * `SendMessage()`, `WaitForResponse()`, `SendSynchronousRequest()`: Methods related to sending HTTP requests and receiving responses.
    * `CheckResponseHeaders()`: A helper function to validate HTTP response headers.
    * Flags and configuration options like `SetQuicReloadableFlag`, `SetQuicRestartFlag`, `client_extra_copts_`, `use_preferred_address_`. These hint at testing different QUIC features and configurations.

4. **Analyze Individual Test Cases (`TEST_P` blocks):** I go through each test case, trying to understand its purpose based on the method name and the actions performed within it:

    * **`RejectRequestWithInvalidCharactersInHeaderName` and `RejectRequestWithInvalidToken`:** These clearly test the server's ability to reject requests with malformed HTTP headers.
    * **`OriginalConnectionIdClearedFromMap`:** This focuses on connection ID management, specifically ensuring that original connection IDs are properly cleaned up after a connection closes.
    * **`FlowLabelSend`:** This checks if flow labels (a QUIC feature for identifying flows) are being correctly sent and received by both client and server.
    * **`ServerReportsNotEct`, `ServerReportsEct0`, `ServerReportsEct1`, `ServerReportsCe`, `ClientReportsEct1`:** These tests are related to Explicit Congestion Notification (ECN), a mechanism for network congestion signaling. They verify that ECN codepoints are correctly handled by both client and server.
    * **`FixTimeouts`:**  This tests a feature that disables handshake timeouts, likely for specific deployment scenarios.
    * **`ClientMigrationAfterHalfwayServerMigration` and `MultiPortCreationFollowingServerMigration`:** These test various aspects of connection migration (changing the network path of a connection), a key feature of QUIC.
    * **`DoNotAdvertisePreferredAddressWithoutSPAD`:**  This checks that the server doesn't advertise a preferred address if the "Server Preferred Address Delegation" (SPAD) feature isn't active.
    * **`MaxPacingRate`:** This test verifies that the server can limit the rate at which it sends data, which is important for congestion control and fairness.
    * **`RequestsBurstMitigation`:**  This tests a mechanism to handle bursts of incoming requests, preventing the server from being overwhelmed.
    * **`SerializeConnectionClosePacketWithLargestPacketNumber`:** This tests the correct serialization of connection close packets, especially when the packet number is large.

5. **Identify JavaScript Relevance (or lack thereof):**  Based on my understanding of the code and QUIC, I know that QUIC operates at a lower network layer than JavaScript in typical web development. While JavaScript in a browser might *use* QUIC for communication, this C++ code is focused on the core implementation of the protocol. Therefore, the direct relationship is minimal. I would explain this by noting that JavaScript would interact with QUIC through browser APIs, but this code is internal to the browser's network stack.

6. **Infer Assumptions, Inputs, and Outputs:** For each test case, I consider:
    * **Assumption:** The underlying QUIC implementation is working correctly at a lower level.
    * **Input:** Typically, an HTTP request with specific headers or conditions (e.g., invalid headers, ECN codepoints). Sometimes, server-side configurations are modified.
    * **Output:**  Verification of the server's response (status code, headers), or checks on internal state (e.g., connection ID maps, ECN counters, pacing rates).

7. **Identify User/Programming Errors:** I think about how incorrect usage of QUIC or HTTP might lead to the tested scenarios:
    * Sending malformed headers.
    * Network conditions that trigger connection migration.
    * Server misconfiguration related to preferred addresses or pacing.

8. **Trace User Operations (Debugging Clues):** I consider how a user's actions in a browser might lead to these tests being relevant during development or debugging:
    * A user browsing a website over QUIC.
    * Network changes during a browsing session.
    * Issues with server configuration affecting QUIC behavior.

9. **Synthesize the Overall Function:** I combine my understanding of the individual test cases to describe the file's overall purpose: comprehensive end-to-end testing of QUIC's HTTP implementation, covering various features, error handling, and edge cases.

10. **Address the "Part 10 of 10" Request:**  Knowing this is the final part, I summarize the key functionalities covered across the entire hypothetical set of files, drawing upon my understanding of this specific part. This would involve reiterating the major QUIC features tested (connection establishment, HTTP semantics, connection migration, congestion control, error handling, etc.).

By following these steps, I can systematically analyze the C++ code, understand its purpose, and address the specific requirements of the prompt. The key is to combine knowledge of C++, testing frameworks, and the QUIC protocol itself.
This is the 10th and final part of a series of source code files for end-to-end testing of the QUIC HTTP implementation in Chromium's network stack. Building upon the previous parts, this specific snippet continues to define various test cases that simulate real-world scenarios and verify the correct behavior of the QUIC HTTP implementation.

Here's a breakdown of the functionalities covered in this section:

**Core Functionalities Tested:**

* **Handling Invalid HTTP Headers:**
    * **`RejectRequestWithInvalidCharactersInHeaderName`:** Tests if the server correctly rejects requests with invalid characters in the header name, responding with a "400 Bad Request".
    * **`RejectRequestWithInvalidToken`:** Tests if the server rejects requests with invalid tokens in headers (likely referring to syntax or allowed characters), also responding with "400".

* **Connection ID Management:**
    * **`OriginalConnectionIdClearedFromMap`:**  Verifies that the server correctly removes the original connection ID from its internal map after a connection has been established and potentially migrated or closed. This is crucial for resource management and preventing issues with reusing connection IDs.

* **Flow Label Handling (IPv6):**
    * **`FlowLabelSend`:** Checks if flow labels, a feature in IPv6 for identifying network flows, are correctly sent and received by both the client and server. This test specifically focuses on scenarios where both client and server set outgoing flow labels.

* **Explicit Congestion Notification (ECN):**  Several tests explore how the client handles ECN markings reported by the server:
    * **`ServerReportsNotEct`:** Tests the case where the server reports "Not-ECT" (no congestion experienced).
    * **`ServerReportsEct0`:** Tests the case where the server reports "ECT(0)" (congestion experienced).
    * **`ServerReportsEct1`:** Tests the case where the server reports "ECT(1)" (congestion experienced).
    * **`ServerReportsCe`:** Tests the case where the server reports "CE" (Congestion Experienced).
    * **`ClientReportsEct1`:** Tests the reverse scenario where the *client* reports "ECT(1)" to the server.

* **Disabling Handshake Timeouts:**
    * **`FixTimeouts`:**  Verifies the functionality of disabling handshake timeouts (using the `kFTOE` option). This might be used in specific network environments or for testing purposes.

* **Connection Migration and Multi-Path:**
    * **`ClientMigrationAfterHalfwayServerMigration`:** Tests a complex scenario where the server migrates to a preferred address, and then the client also migrates its socket to a new IP address. It verifies that the connection remains stable and path validation occurs correctly.
    * **`MultiPortCreationFollowingServerMigration`:** Tests the scenario where the client uses multi-path QUIC (`kMPQC`) and the server migrates to a preferred address. It checks that the client establishes multiple paths to the server.

* **Preferred Address Advertisement:**
    * **`DoNotAdvertisePreferredAddressWithoutSPAD`:**  Verifies that the server does not advertise a preferred address if the "Server Preferred Address Delegation" (SPAD) feature is not enabled.

* **Pacing Rate Limits:**
    * **`MaxPacingRate`:** Tests the server's ability to limit its sending rate using the `SetMaxPacingRate` function. This ensures that the server can control its bandwidth usage.

* **Request Burst Mitigation:**
    * **`RequestsBurstMitigation`:** Tests a mechanism to handle bursts of incoming requests at the server, preventing overload and ensuring requests are processed correctly, even if they arrive in close succession.

* **Serialization of Connection Close Packet with Large Packet Number:**
    * **`SerializeConnectionClosePacketWithLargestPacketNumber`:**  Tests the correct serialization of a `CONNECTION_CLOSE` packet, especially when the packet number is very large. This ensures that even in scenarios with many packets sent, the close packet is formed correctly.

**Relationship to JavaScript:**

While this code is C++ and part of the Chromium network stack, it indirectly relates to JavaScript. When a website accessed through a Chromium-based browser uses QUIC, the browser's network stack (including this QUIC implementation) handles the underlying communication.

* **Example:** If a JavaScript application on a webpage makes an HTTP request (e.g., using `fetch()`), and the connection to the server uses QUIC, the logic tested in this file is responsible for the reliable and efficient delivery of that request and response. The JavaScript developer wouldn't directly interact with this C++ code, but its correctness is crucial for the performance and reliability of their web application.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take the `RejectRequestWithInvalidCharactersInHeaderName` test as an example:

* **Hypothetical Input:** A QUIC client sends an HTTP request to the server with the following headers:
  ```
  :scheme: https
  :authority: localhost
  :method: GET
  :path: /echo
  inva!id-header: foo
  ```
  Notice the "!" character in the header name `inva!id-header`, which is invalid according to HTTP/2 and HTTP/3 specifications.

* **Expected Output:** The QUIC server should:
    1. Detect the invalid character in the header name.
    2. Not process the request further.
    3. Send an HTTP response with a status code of "400 Bad Request".
    4. Potentially send a QUIC error indicating a protocol violation.

**User or Programming Common Usage Errors:**

* **Incorrectly constructing HTTP headers:**  A programmer might inadvertently include invalid characters or tokens in HTTP header names or values when building requests. This test helps ensure the server gracefully handles such errors.
* **Misunderstanding HTTP specifications:** Developers might not be fully aware of the restrictions on characters allowed in HTTP headers. These tests serve as a safeguard against such misunderstandings.
* **Server-side misconfiguration:** While not directly a user error, an incorrectly configured server might not properly validate headers, leading to security vulnerabilities or unexpected behavior. These tests help verify the server's adherence to standards.

**User Operation Steps to Reach Here (Debugging Clues):**

If a developer is debugging an issue related to HTTP requests over QUIC, they might encounter the code in `end_to_end_test.cc` under these circumstances:

1. **A user reports a "Bad Request" error when accessing a specific webpage.** The developer might suspect an issue with the HTTP headers being sent by the browser.
2. **The developer investigates the browser's network logs.** They might see a 400 response from the server and want to understand why the request was rejected.
3. **The developer suspects a QUIC-specific issue.** If the connection uses QUIC, they might look into the QUIC implementation within the browser.
4. **The developer runs the `end_to_end_test.cc` tests.** Specifically, they might run the `RejectRequestWithInvalidCharactersInHeaderName` test to verify if the server is correctly rejecting requests with malformed headers.
5. **Stepping through the test code:** The developer can analyze how the test constructs a request with an invalid header and how the server handles it, providing valuable insights into the root cause of the user's error.

**Summary of Functionality (Part 10 of 10):**

This final part of the `end_to_end_test.cc` file focuses on testing the robustness and correctness of the QUIC HTTP implementation in various edge cases and advanced scenarios. It covers:

* **Strict adherence to HTTP specifications** by rejecting invalid headers.
* **Proper management of QUIC connection identifiers** for resource efficiency.
* **Correct handling of IPv6 flow labels** for network optimization.
* **Accurate processing of Explicit Congestion Notification (ECN)** for congestion control.
* **Support for disabling handshake timeouts** in specific deployment scenarios.
* **Robustness in connection migration scenarios**, both client-initiated and server-initiated, including multi-path connections.
* **Correct advertisement of preferred server addresses** based on configuration.
* **Enforcement of server-side pacing limits** for bandwidth management.
* **Mechanisms to mitigate request bursts** to prevent server overload.
* **Correct serialization of critical QUIC control packets** even with large packet numbers.

Collectively, these tests ensure that the QUIC HTTP implementation in Chromium is reliable, performs well under various network conditions, and adheres to relevant internet standards. This contributes to a better and more robust browsing experience for users.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共10部分，请归纳一下它的功能

"""
o";

  client_->SendMessage(headers, "", /*fin=*/false);
  client_->WaitForResponse();
  CheckResponseHeaders("400");
}

TEST_P(EndToEndTest, RejectRequestWithInvalidToken) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  ASSERT_TRUE(Initialize());

  quiche::HttpHeaderBlock headers;
  headers[":scheme"] = "https";
  headers[":authority"] = "localhost";
  headers[":method"] = "GET";
  headers[":path"] = "/echo";
  headers["invalid,header"] = "foo";

  client_->SendMessage(headers, "", /*fin=*/false);
  client_->WaitForResponse();
  CheckResponseHeaders("400");
}

TEST_P(EndToEndTest, OriginalConnectionIdClearedFromMap) {
  connect_to_server_on_initialize_ = false;
  ASSERT_TRUE(Initialize());
  if (override_client_connection_id_length_ != kLongConnectionIdLength) {
    // There might not be an original connection ID.
    CreateClientWithWriter();
    return;
  }

  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  EXPECT_EQ(QuicDispatcherPeer::GetFirstSessionIfAny(dispatcher), nullptr);
  server_thread_->Resume();

  CreateClientWithWriter();  // Also connects.
  EXPECT_NE(client_, nullptr);

  server_thread_->Pause();
  EXPECT_NE(QuicDispatcherPeer::GetFirstSessionIfAny(dispatcher), nullptr);
  EXPECT_EQ(dispatcher->NumSessions(), 1);
  auto ids = GetServerConnection()->GetActiveServerConnectionIds();
  ASSERT_EQ(ids.size(), 2);
  for (QuicConnectionId id : ids) {
    EXPECT_NE(QuicDispatcherPeer::FindSession(dispatcher, id), nullptr);
  }
  QuicConnectionId original = ids[1];
  server_thread_->Resume();

  client_->SendSynchronousRequest("/foo");
  client_->Disconnect();

  server_thread_->Pause();
  EXPECT_EQ(QuicDispatcherPeer::GetFirstSessionIfAny(dispatcher), nullptr);
  EXPECT_EQ(QuicDispatcherPeer::FindSession(dispatcher, original), nullptr);
  server_thread_->Resume();
}

TEST_P(EndToEndTest, FlowLabelSend) {
  SetQuicRestartFlag(quic_support_flow_label2, true);
  ASSERT_TRUE(Initialize());

  const uint32_t server_flow_label = 2;
  quiche::QuicheNotification set;
  server_thread_->Schedule([this, &set]() {
    QuicConnection* server_connection = GetServerConnection();
    if (server_connection != nullptr) {
      server_connection->set_outgoing_flow_label(server_flow_label);
    } else {
      ADD_FAILURE() << "Missing server connection";
    }
    set.Notify();
  });
  set.WaitForNotification();

  const uint32_t client_flow_label = 1;
  QuicConnection* client_connection = GetClientConnection();
  client_connection->set_outgoing_flow_label(client_flow_label);

  client_->SendSynchronousRequest("/foo");

  if (server_address_.host().IsIPv6()) {
    EXPECT_EQ(client_flow_label, client_connection->outgoing_flow_label());
    EXPECT_EQ(server_flow_label, client_connection->last_received_flow_label());

    server_thread_->Pause();
    QuicConnection* server_connection = GetServerConnection();
    EXPECT_EQ(server_flow_label, server_connection->outgoing_flow_label());
    EXPECT_EQ(client_flow_label, server_connection->last_received_flow_label());
  }
}

TEST_P(EndToEndTest, ServerReportsNotEct) {
  // Client connects using not-ECT.
  SetQuicRestartFlag(quic_support_ect1, true);
  ASSERT_TRUE(Initialize());
  QuicConnection* client_connection = GetClientConnection();
  QuicConnectionPeer::DisableEcnCodepointValidation(client_connection);
  QuicEcnCounts* ecn = QuicSentPacketManagerPeer::GetPeerEcnCounts(
      QuicConnectionPeer::GetSentPacketManager(client_connection),
      APPLICATION_DATA);
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ect1, 0);
  EXPECT_EQ(ecn->ce, 0);
  EXPECT_TRUE(client_connection->set_ecn_codepoint(ECN_NOT_ECT));
  client_->SendSynchronousRequest("/foo");
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ect1, 0);
  EXPECT_EQ(ecn->ce, 0);
  client_->Disconnect();
}

TEST_P(EndToEndTest, ServerReportsEct0) {
  // Client connects using not-ECT.
  SetQuicRestartFlag(quic_support_ect1, true);
  ASSERT_TRUE(Initialize());
  QuicConnection* client_connection = GetClientConnection();
  QuicConnectionPeer::DisableEcnCodepointValidation(client_connection);
  QuicEcnCounts* ecn = QuicSentPacketManagerPeer::GetPeerEcnCounts(
      QuicConnectionPeer::GetSentPacketManager(client_connection),
      APPLICATION_DATA);
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ect1, 0);
  EXPECT_EQ(ecn->ce, 0);
  EXPECT_TRUE(client_connection->set_ecn_codepoint(ECN_ECT0));
  client_->SendSynchronousRequest("/foo");
  if (!VersionHasIetfQuicFrames(version_.transport_version)) {
    EXPECT_EQ(ecn->ect0, 0);
  } else {
    EXPECT_GT(ecn->ect0, 0);
  }
  EXPECT_EQ(ecn->ect1, 0);
  EXPECT_EQ(ecn->ce, 0);
  client_->Disconnect();
}

TEST_P(EndToEndTest, ServerReportsEct1) {
  // Client connects using not-ECT.
  SetQuicRestartFlag(quic_support_ect1, true);
  ASSERT_TRUE(Initialize());
  QuicConnection* client_connection = GetClientConnection();
  QuicConnectionPeer::DisableEcnCodepointValidation(client_connection);
  QuicEcnCounts* ecn = QuicSentPacketManagerPeer::GetPeerEcnCounts(
      QuicConnectionPeer::GetSentPacketManager(client_connection),
      APPLICATION_DATA);
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ect1, 0);
  EXPECT_EQ(ecn->ce, 0);
  EXPECT_TRUE(client_connection->set_ecn_codepoint(ECN_ECT1));
  client_->SendSynchronousRequest("/foo");
  if (!VersionHasIetfQuicFrames(version_.transport_version)) {
    EXPECT_EQ(ecn->ect1, 0);
  } else {
    EXPECT_GT(ecn->ect1, 0);
  }
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ce, 0);
  client_->Disconnect();
}

TEST_P(EndToEndTest, ServerReportsCe) {
  // Client connects using not-ECT.
  SetQuicRestartFlag(quic_support_ect1, true);
  ASSERT_TRUE(Initialize());
  QuicConnection* client_connection = GetClientConnection();
  QuicConnectionPeer::DisableEcnCodepointValidation(client_connection);
  QuicEcnCounts* ecn = QuicSentPacketManagerPeer::GetPeerEcnCounts(
      QuicConnectionPeer::GetSentPacketManager(client_connection),
      APPLICATION_DATA);
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ect1, 0);
  EXPECT_EQ(ecn->ce, 0);
  EXPECT_TRUE(client_connection->set_ecn_codepoint(ECN_CE));
  client_->SendSynchronousRequest("/foo");
  if (!VersionHasIetfQuicFrames(version_.transport_version)) {
    EXPECT_EQ(ecn->ce, 0);
  } else {
    EXPECT_GT(ecn->ce, 0);
  }
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ect1, 0);
  client_->Disconnect();
}

TEST_P(EndToEndTest, ClientReportsEct1) {
  SetQuicRestartFlag(quic_support_ect1, true);
  ASSERT_TRUE(Initialize());
  // Wait for handshake to complete, so that we can manipulate the server
  // connection without race conditions.
  server_thread_->WaitForCryptoHandshakeConfirmed();
  QuicConnection* server_connection = GetServerConnection();
  QuicConnectionPeer::DisableEcnCodepointValidation(server_connection);
  QuicEcnCounts* ecn = QuicSentPacketManagerPeer::GetPeerEcnCounts(
      QuicConnectionPeer::GetSentPacketManager(server_connection),
      APPLICATION_DATA);
  EXPECT_TRUE(server_connection->set_ecn_codepoint(ECN_ECT1));
  client_->SendSynchronousRequest("/foo");
  // A second request provides a packet for the client ACKs to go with.
  client_->SendSynchronousRequest("/foo");
  server_thread_->Pause();
  EXPECT_EQ(ecn->ect0, 0);
  EXPECT_EQ(ecn->ce, 0);
  if (!VersionHasIetfQuicFrames(version_.transport_version)) {
    EXPECT_EQ(ecn->ect1, 0);
  } else {
    EXPECT_GT(ecn->ect1, 0);
  }
  server_connection->set_per_packet_options(nullptr);
  server_thread_->Resume();
  client_->Disconnect();
}

TEST_P(EndToEndTest, FixTimeouts) {
  client_extra_copts_.push_back(kFTOE);
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls()) {
    return;
  }
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  // Verify handshake timeout has been removed on both endpoints.
  QuicConnection* client_connection = GetClientConnection();
  EXPECT_EQ(QuicConnectionPeer::GetIdleNetworkDetector(client_connection)
                .handshake_timeout(),
            QuicTime::Delta::Infinite());
  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  EXPECT_EQ(QuicConnectionPeer::GetIdleNetworkDetector(server_connection)
                .handshake_timeout(),
            QuicTime::Delta::Infinite());
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ClientMigrationAfterHalfwayServerMigration) {
  use_preferred_address_ = true;
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));
  QuicConnection* client_connection = GetClientConnection();
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  EXPECT_EQ(server_address_, client_connection->effective_peer_address());
  EXPECT_EQ(server_address_, client_connection->peer_address());
  EXPECT_TRUE(client_->client()->HasPendingPathValidation());
  QuicConnectionId server_cid1 = client_connection->connection_id();

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_TRUE(client_->WaitUntil(
      1000, [&]() { return !client_->client()->HasPendingPathValidation(); }));
  EXPECT_EQ(server_preferred_address_,
            client_connection->effective_peer_address());
  EXPECT_EQ(server_preferred_address_, client_connection->peer_address());
  EXPECT_NE(server_cid1, client_connection->connection_id());
  EXPECT_EQ(0u,
            client_connection->GetStats().num_connectivity_probing_received);
  const auto client_stats = GetClientConnection()->GetStats();
  EXPECT_TRUE(client_stats.server_preferred_address_validated);
  EXPECT_FALSE(client_stats.failed_to_validate_server_preferred_address);

  WaitForNewConnectionIds();
  // Migrate socket to a new IP address.
  QuicIpAddress host = TestLoopback(2);
  ASSERT_NE(
      client_->client()->network_helper()->GetLatestClientAddress().host(),
      host);
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host));
  EXPECT_TRUE(client_->WaitUntil(
      1000, [&]() { return !client_->client()->HasPendingPathValidation(); }));
  EXPECT_EQ(host, client_->client()->session()->self_address().host());

  SendSynchronousBarRequestAndCheckResponse();

  // Wait for the PATH_CHALLENGE.
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return client_connection->GetStats().num_connectivity_probing_received >= 1;
  }));

  // Send another request to ensure that the server will have time to finish the
  // reverse path validation and send address token.
  SendSynchronousBarRequestAndCheckResponse();
  // By the time the above request is completed, the PATH_RESPONSE must have
  // been received by the server. Check server stats.
  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  EXPECT_FALSE(server_connection->HasPendingPathValidation());
  EXPECT_EQ(2u, server_connection->GetStats().num_validated_peer_migration);
  EXPECT_EQ(2u, server_connection->GetStats().num_new_connection_id_sent);
  server_thread_->Resume();
}

TEST_P(EndToEndTest, MultiPortCreationFollowingServerMigration) {
  use_preferred_address_ = true;
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  client_config_.SetClientConnectionOptions(QuicTagVector{kMPQC});
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));
  QuicConnection* client_connection = GetClientConnection();
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  EXPECT_EQ(server_address_, client_connection->effective_peer_address());
  EXPECT_EQ(server_address_, client_connection->peer_address());
  QuicConnectionId server_cid1 = client_connection->connection_id();
  EXPECT_TRUE(client_connection->IsValidatingServerPreferredAddress());

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return !client_connection->IsValidatingServerPreferredAddress();
  }));
  EXPECT_EQ(server_preferred_address_,
            client_connection->effective_peer_address());
  EXPECT_EQ(server_preferred_address_, client_connection->peer_address());
  const auto client_stats = GetClientConnection()->GetStats();
  EXPECT_TRUE(client_stats.server_preferred_address_validated);
  EXPECT_FALSE(client_stats.failed_to_validate_server_preferred_address);

  QuicConnectionId server_cid2 = client_connection->connection_id();
  EXPECT_NE(server_cid1, server_cid2);
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return client_connection->GetStats().num_path_response_received == 2;
  }));
  EXPECT_TRUE(
      QuicConnectionPeer::IsAlternativePathValidated(client_connection));
  QuicConnectionId server_cid3 =
      QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
          client_connection);
  EXPECT_NE(server_cid2, server_cid3);
  EXPECT_NE(server_cid1, server_cid3);
}

TEST_P(EndToEndTest, DoNotAdvertisePreferredAddressWithoutSPAD) {
  if (!version_.HasIetfQuicFrames()) {
    ASSERT_TRUE(Initialize());
    return;
  }
  server_config_.SetIPv4AlternateServerAddressToSend(
      QuicSocketAddress(QuicIpAddress::Any4(), 12345));
  server_config_.SetIPv6AlternateServerAddressToSend(
      QuicSocketAddress(QuicIpAddress::Any6(), 12345));
  NiceMock<MockQuicConnectionDebugVisitor> visitor;
  connection_debug_visitor_ = &visitor;
  EXPECT_CALL(visitor, OnTransportParametersReceived(_))
      .WillOnce(Invoke([](const TransportParameters& transport_parameters) {
        EXPECT_EQ(nullptr, transport_parameters.preferred_address);
      }));
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
}

TEST_P(EndToEndTest, MaxPacingRate) {
  const std::string huge_response(10 * 1024 * 1024, 'a');  // 10 MB
  ASSERT_TRUE(Initialize());

  if (!GetQuicReloadableFlag(quic_pacing_remove_non_initial_burst)) {
    return;
  }

  AddToCache("/10MB_response", 200, huge_response);

  ASSERT_TRUE(client_->client()->WaitForHandshakeConfirmed());

  auto set_server_max_pacing_rate = [&](QuicBandwidth max_pacing_rate) {
    QuicSpdySession* server_session = GetServerSession();
    ASSERT_NE(server_session, nullptr);
    server_session->connection()->SetMaxPacingRate(max_pacing_rate);
  };

  // Set up the first response to be paced at 2 MB/s.
  server_thread_->ScheduleAndWaitForCompletion([&]() {
    set_server_max_pacing_rate(
        QuicBandwidth::FromBytesPerSecond(2 * 1024 * 1024));
  });

  QuicTime start = QuicDefaultClock::Get()->Now();
  SendSynchronousRequestAndCheckResponse(client_.get(), "/10MB_response",
                                         huge_response);
  QuicTime::Delta duration = QuicDefaultClock::Get()->Now() - start;
  QUIC_LOG(INFO) << "Response 1 duration: " << duration;
  EXPECT_GE(duration, QuicTime::Delta::FromMilliseconds(5000));
  EXPECT_LE(duration, QuicTime::Delta::FromMilliseconds(7500));

  // Set up the second response to be paced at 512 KB/s.
  server_thread_->ScheduleAndWaitForCompletion([&]() {
    set_server_max_pacing_rate(QuicBandwidth::FromBytesPerSecond(512 * 1024));
  });

  start = QuicDefaultClock::Get()->Now();
  SendSynchronousRequestAndCheckResponse(client_.get(), "/10MB_response",
                                         huge_response);
  duration = QuicDefaultClock::Get()->Now() - start;
  QUIC_LOG(INFO) << "Response 2 duration: " << duration;
  EXPECT_GE(duration, QuicTime::Delta::FromSeconds(20));
  EXPECT_LE(duration, QuicTime::Delta::FromSeconds(25));
}

TEST_P(EndToEndTest, RequestsBurstMitigation) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  // Send 50 requests simutanuously and wait for their responses. Hopefully at
  // least more than 5 of these requests will arrive at the server in the same
  // event loop and cause some of them to be pending till the next loop.
  for (int i = 0; i < 50; ++i) {
    EXPECT_LT(0, client_->SendRequest("/foo"));
  }

  while (50 > client_->num_responses()) {
    client_->ClearPerRequestState();
    client_->WaitForResponse();
    CheckResponseHeaders(client_.get());
  }
  EXPECT_TRUE(client_->connected());

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    const QuicConnectionStats& server_stats = server_connection->GetStats();
    EXPECT_LT(0u, server_stats.num_total_pending_streams);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, SerializeConnectionClosePacketWithLargestPacketNumber) {
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls()) {
    return;
  }
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());

  std::unique_ptr<SerializedPacket> connection_close_packet =
      GetClientConnection()->SerializeLargePacketNumberConnectionClosePacket(
          QUIC_CLIENT_LOST_NETWORK_ACCESS, "EndToEndTest");
  ASSERT_NE(connection_close_packet, nullptr);

  // Send 50 requests to increase the packet number.
  for (int i = 0; i < 50; ++i) {
    EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  }

  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  EXPECT_EQ(dispatcher->NumSessions(), 1);
  server_thread_->Resume();

  // Send the connection close packet to the server.
  QUIC_LOG(INFO) << "Sending close connection packet";
  client_writer_->WritePacket(
      connection_close_packet->encrypted_buffer,
      connection_close_packet->encrypted_length,
      client_->client()->network_helper()->GetLatestClientAddress().host(),
      server_address_, nullptr, packet_writer_params_);

  // Wait for the server to close the connection.
  EXPECT_TRUE(
      server_thread_->WaitUntil([&] { return dispatcher->NumSessions() == 0; },
                                QuicTime::Delta::FromSeconds(5)));

  EXPECT_EQ("", client_->SendSynchronousRequest("/foo"));
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_PUBLIC_RESET));
}
}  // namespace
}  // namespace test
}  // namespace quic

"""


```