Response:
Let's break down the thought process to arrive at the summary and analysis of the provided code snippet.

1. **Understanding the Request:** The core request is to analyze a specific Chromium network stack file (`end_to_end_test.cc`) and provide:
    * Functionality of the file.
    * Relationship to JavaScript.
    * Logic reasoning with input/output examples.
    * Common user/programming errors.
    * Debugging steps to reach the code.
    * A summary of the *current* snippet (part 6 of 10).

2. **Initial Scan for Clues:**  I'll first scan the code for keywords and patterns that indicate the file's purpose. Keywords like `TEST_P`, `EXPECT_TRUE`, `ASSERT_TRUE`, `SendSynchronousRequest`, `QuicSession`, `HttpHeaderBlock`, `QuicConnection`, `QuicFramer`, `PublicResetPacket`, `VersionNegotiationPacket`, `PacketWriter`, `AckListener`, etc., strongly suggest this is a *testing* file for the QUIC protocol's HTTP implementation. The `EndToEndTest` class name reinforces this.

3. **Dissecting the Test Cases:** The `TEST_P` macro indicates parameterized tests, meaning the same test logic is run with different configurations (likely QUIC versions). Each `TEST_P` function represents a distinct test case. I'll go through each test case and summarize its goal:

    * `AdjustMaxStreams`:  Checks if the client can adjust the maximum number of outgoing streams and if the server respects this limit.
    * `RequestWithNoBodyWillNeverSendStreamFrameWithFIN`:  Verifies that streams created by requests without a body are properly cleaned up on the server.
    * `AckNotifierWithPacketLossAndBlockedSocket`:  Tests the reliability of ACK notifications even under network challenges like packet loss and temporary socket blocking. This is a key test for ensuring reliable data delivery.
    * `ServerSendPublicReset`: Tests the client's behavior when the server sends a QUIC Public Reset, a mechanism to abruptly terminate the connection.
    * `ServerSendPublicResetWithDifferentConnectionId`: Checks that the client ignores Public Resets intended for different connections.
    * `InduceStatelessResetFromServer`: Tests the client's response to a stateless reset initiated by the server, often triggered by the server going away unexpectedly.
    * `ClientSendPublicResetWithDifferentConnectionId`:  Verifies that the server ignores Public Resets from the client with an incorrect connection ID.
    * `ServerSendVersionNegotiationWithDifferentConnectionId`:  Confirms that the client ignores version negotiation packets intended for other connections.
    * `VersionNegotiationDowngradeAttackIsDetected`:  A security test to ensure the client can detect and prevent version downgrade attacks, where a malicious actor tries to force the client to use an older, potentially vulnerable version of the protocol.
    * `BadPacketHeaderTruncated`: Checks the client's resilience to malformed packets with truncated headers. It shouldn't crash the entire connection.
    * `BadPacketHeaderFlags`: Similar to the above, but tests malformed packets with invalid header flags.
    * `BadEncryptedData`: Tests the client's ability to handle packets with corrupted encrypted data without crashing.
    * `CanceledStreamDoesNotBecomeZombie`: Ensures that canceling a stream on the client properly cleans up resources and doesn't leave the stream in a problematic "zombie" state.
    * Tests involving `ServerStreamWithErrorResponseBody`, `StreamWithErrorFactory`, `ServerStreamThatDropsBody`, `ServerStreamThatDropsBodyFactory`, `ServerStreamThatSendsHugeResponse`, `ServerStreamThatSendsHugeResponseFactory`: These introduce custom server-side stream behavior to test various edge cases and error handling scenarios, such as sending error responses, dropping request bodies, and sending very large responses.
    * `BlockedFrameIncludesOffset`: Verifies that BLOCKED frames (used for flow control) include the correct offset information, which is important for IETF QUIC.
    * `EarlyResponseFinRecording`: Tests a specific scenario where the server sends a response FIN early, and ensures the client correctly handles this to avoid resource leaks.

4. **Identifying Core Functionality:**  Based on the individual test case summaries, the overall functionality of `end_to_end_test.cc` is to perform comprehensive **end-to-end testing of the QUIC HTTP implementation**. This involves simulating client-server interactions and verifying correct behavior under various conditions, including normal operations, error scenarios, and potential attacks.

5. **JavaScript Relationship:**  Consider how JavaScript interacts with networking. Browsers use network stacks (which include QUIC) to fetch resources. So, while this specific C++ file doesn't *contain* JavaScript, its tests validate the underlying network behavior that JavaScript code in a browser relies on. Examples could involve `fetch()` API calls or WebSocket connections over QUIC.

6. **Logic Reasoning (Input/Output):**  Choose a representative test case (like `AdjustMaxStreams`) and think about the input and expected output.

7. **Common Errors:** Reflect on common mistakes developers might make when working with network protocols, such as incorrect header construction, neglecting error handling, or mismanaging connection state.

8. **Debugging Steps:** Consider the typical workflow of a developer debugging network issues, such as setting breakpoints, examining network traffic, and analyzing logs.

9. **Focusing on "Part 6":** Carefully examine the specific code provided in the snippet. It starts within the `BlockedFrameIncludesOffset` test and continues to the `EarlyResponseFinRecording` test. This narrows down the summary of *this specific part* to functionalities related to flow control (`BlockedFrame`) and handling early response termination.

10. **Synthesizing the Summary:** Combine the insights from the above steps to create a concise summary of the provided code snippet. Emphasize the key themes and the types of tests being performed.

**Self-Correction/Refinement:** During this process, I might realize:

* **Overly broad initial assessment:**  Initially, I might just say "it tests QUIC."  I need to be more specific about *what aspects* of QUIC/HTTP are being tested.
* **Missing JavaScript link:** I might initially forget to connect the low-level C++ to higher-level browser functionality.
* **Insufficiently concrete examples:**  My input/output examples might be too abstract. I need to provide specific examples of headers, body content, or expected errors.
* **Vague error descriptions:**  Instead of saying "network errors," I should specify types of errors like "connection reset," "invalid header," etc.

By iterating through these steps and refining my understanding, I can generate a comprehensive and accurate analysis of the provided code snippet.
This is the 6th part of a 10-part analysis of the `end_to_end_test.cc` file. Based on the code snippet provided in this part, here's a breakdown of its functionality:

**Functionality Covered in This Snippet (Part 6):**

This section of the test file focuses on testing various error handling and edge cases in QUIC and HTTP communication, specifically:

* **Handling Public Resets from the Server:**
    * **`ServerSendPublicReset`:** Tests how the client reacts when the server sends a Public Reset packet, which is a way for the server to abruptly terminate the connection. It verifies that the client recognizes the reset, terminates the connection, and reports the `QUIC_PUBLIC_RESET` error.
    * **`ServerSendPublicResetWithDifferentConnectionId`:**  Tests that the client correctly ignores Public Reset packets that are intended for a different connection ID. This is crucial for preventing denial-of-service attacks.
    * **`InduceStatelessResetFromServer`:**  Simulates a scenario where the server effectively disappears (by dropping packets and restarting), leading the client to receive a stateless reset. It verifies the client handles this scenario by closing the connection with `QUIC_PUBLIC_RESET`.

* **Handling Public Resets from the Client (Negative Test):**
    * **`ClientSendPublicResetWithDifferentConnectionId`:**  Tests that the server ignores Public Reset packets sent by the client if the connection ID in the reset doesn't match the server's connection ID for that client. This prevents malicious clients from disrupting other connections.

* **Handling Version Negotiation with Incorrect Connection ID:**
    * **`ServerSendVersionNegotiationWithDifferentConnectionId`:** Tests that the client ignores Version Negotiation packets from the server if they are intended for a different connection ID. This is important for security and stability.

* **Detecting Version Downgrade Attacks:**
    * **`VersionNegotiationDowngradeAttackIsDetected`:** This is a security-focused test. It simulates a "version downgrade attack" where a malicious actor attempts to force the client to use an older, potentially vulnerable QUIC version. The test verifies that the client detects this attempt and fails the handshake, preventing the downgrade.

* **Handling Malformed Packets:**
    * **`BadPacketHeaderTruncated`:** Tests the client's behavior when receiving a packet with a truncated header. It ensures the connection isn't torn down immediately because the receiver can't reliably identify the connection ID. The error `QUIC_INVALID_PACKET_HEADER` is expected.
    * **`BadPacketHeaderFlags`:** Tests the client's reaction to a packet with invalid public flags in the header. Similar to the truncated header test, the connection should remain and the `QUIC_INVALID_PACKET_HEADER` error is expected.
    * **`BadEncryptedData`:** Tests how the server handles a packet with corrupted encrypted data. It verifies that the server doesn't crash and the connection remains active.

* **Handling Canceled Streams:**
    * **`CanceledStreamDoesNotBecomeZombie`:**  Ensures that when a client cancels a stream (using `Reset`), the stream resources are properly cleaned up and don't linger in a "zombie" state within the session.

* **Testing Server-Side Error Responses:**
    * Includes the definition of `ServerStreamWithErrorResponseBody` and `StreamWithErrorFactory`. These are used to simulate a server intentionally sending an error response (e.g., HTTP 500) with a specific body. This is used in subsequent tests (not fully shown in this snippet) to verify client-side handling of such errors.

* **Testing Server Dropping Request Body:**
    * Introduces `ServerStreamThatDropsBody` and `ServerStreamThatDropsBodyFactory`. This simulates a server intentionally consuming and discarding the request body without fully processing it. This helps test scenarios where the server might have limitations or specific logic for handling request bodies.

* **Testing Large Response Bodies:**
    * Defines `ServerStreamThatSendsHugeResponse` and `ServerStreamThatSendsHugeResponseFactory` to simulate the server sending a response body larger than 4GB. This tests how the client handles potentially very large data transfers.

* **Verifying BLOCKED Frame Offset:**
    * **`BlockedFrameIncludesOffset`:** This test specifically focuses on IETF QUIC. It verifies that when the server's flow control window is exhausted, and it sends a `BLOCKED` frame to the client, that frame correctly includes the offset of the data it's blocked on. This is important for flow control mechanisms.

* **Early Response FIN Recording:**
    * **`EarlyResponseFinRecording`:** This test tackles a complex scenario where the server sends a response FIN (indicating the end of the response) early, even if the client's read side is closed. It ensures that the FIN is correctly recorded in the stream object to prevent resource leaks and inconsistencies.

**Relationship to JavaScript:**

While this C++ code itself doesn't directly involve JavaScript, the functionality it tests is crucial for how web browsers (which heavily use JavaScript) interact with web servers using the QUIC protocol.

* **Error Handling:**  The tests for Public Resets, bad packets, and version downgrade attacks ensure the underlying network stack is robust and secure. This indirectly benefits JavaScript applications in browsers by providing a reliable and secure transport layer. If these scenarios weren't handled correctly, JavaScript applications could experience unexpected connection failures or security vulnerabilities.
* **Stream Management:** The tests for maximum streams and canceled streams ensure that the underlying QUIC implementation manages resources efficiently. This impacts how well browsers can handle concurrent requests initiated by JavaScript.
* **Flow Control:** The `BlockedFrameIncludesOffset` test is directly related to QUIC's flow control mechanisms, which prevent senders from overwhelming receivers. This is important for ensuring smooth data transfer and preventing buffer overflows, which indirectly benefits the performance and stability of JavaScript applications fetching resources.
* **Large Responses:** The tests for large response bodies ensure that the network stack can handle the transfer of substantial amounts of data, which is relevant for JavaScript applications downloading large files or receiving significant data from APIs.

**Examples and Logic Reasoning:**

Let's take the `ServerSendPublicReset` test as an example:

* **Hypothetical Input:**
    1. Client establishes a QUIC connection with the server.
    2. Client sends an HTTP request (e.g., `/foo`).
    3. Server decides to send a Public Reset packet to the client (simulated in the test).
* **Expected Output:**
    1. The client's `SendSynchronousRequest` will return an empty string (indicating no response body).
    2. `client_->response_headers()` will be empty.
    3. `client_->connection_error()` will indicate `QUIC_PUBLIC_RESET`.
    4. The client's connection to the server will be terminated.

**User/Programming Common Usage Errors and Debugging:**

* **Mismatched QUIC Versions:** If a client and server are configured with incompatible QUIC versions, the handshake might fail, potentially leading to scenarios tested by the version negotiation tests. Debugging would involve checking the QUIC version settings on both client and server.
* **Incorrect Connection ID Handling:**  If a developer manually crafts QUIC packets (which is rare but possible in testing or debugging), incorrectly setting the connection ID can lead to packets being ignored, as tested by the Public Reset and Version Negotiation with different connection ID tests. Debugging would involve carefully inspecting the packet headers.
* **Misinterpreting Error Codes:** A common error is not properly handling network error codes like `QUIC_PUBLIC_RESET`. Developers might not implement retry mechanisms or provide informative error messages to the user. Debugging involves logging and inspecting the reported error codes.
* **Flow Control Issues:** If the client or server's flow control windows are not correctly managed, it can lead to blocked streams or performance problems. The `BlockedFrameIncludesOffset` test highlights the importance of correct flow control signaling. Debugging involves monitoring flow control windows and `BLOCKED` frames.

**User Operation Steps to Reach This Code (Debugging线索):**

While a typical user doesn't directly interact with this low-level C++ code, here's how their actions might indirectly lead to these code paths being executed during debugging or testing:

1. **User Opens a Website in a Browser:** The browser initiates a QUIC connection to the web server.
2. **Network Issues Occur:**  During the connection, various network events might happen:
    * **Server Overload/Restart:** The server might become overloaded or need to restart, potentially leading to it sending a Public Reset or a stateless reset.
    * **Network Errors/Corruption:** Network infrastructure might introduce errors, leading to truncated or corrupted packets.
    * **Potential Attacks:** A malicious actor might try to perform a version downgrade attack or send packets with incorrect connection IDs.
3. **Developer Investigates:** If the user experiences connection problems, a developer might:
    * **Enable QUIC Logging:** Chromium has flags to enable detailed QUIC logging.
    * **Use Network Inspection Tools:** Tools like Wireshark can capture network packets, allowing inspection of QUIC headers and packet contents.
    * **Step Through Chromium Code:** Developers working on the Chromium network stack might set breakpoints in files like `end_to_end_test.cc` or related QUIC implementation files to understand how the browser handles these error scenarios. The tests in this file serve as examples of how such error conditions are simulated and verified.
4. **Analyzing Test Failures:** When making changes to the QUIC implementation, developers run these end-to-end tests. Failures in tests like `ServerSendPublicReset` would indicate a regression in how the client handles server resets.

**Summary of Part 6 Functionality:**

This portion of `end_to_end_test.cc` primarily focuses on **robustness and security testing of the QUIC HTTP implementation**. It verifies how the client and server handle various error conditions, including public resets, malformed packets, version downgrade attacks, and edge cases in stream management and flow control. These tests ensure the QUIC implementation is resilient to network problems and potential security threats, ultimately contributing to a more reliable and secure browsing experience.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
/
                   (QuicStreamPeer::ReceiveWindowSize(
                        QuicSpdySessionPeer::GetHeadersStream(client_session)) +
                    frame.size());
    EXPECT_TRUE(ratio1 == kSessionToStreamRatio ||
                ratio2 == kSessionToStreamRatio);
  }

  server_thread_->Resume();
}

TEST_P(EndToEndTest, RequestWithNoBodyWillNeverSendStreamFrameWithFIN) {
  // A stream created on receipt of a simple request with no body will never get
  // a stream frame with a FIN. Verify that we don't keep track of the stream in
  // the locally closed streams map: it will never be removed if so.
  ASSERT_TRUE(Initialize());

  // Send a simple headers only request, and receive response.
  SendSynchronousFooRequestAndCheckResponse();

  // Now verify that the server is not waiting for a final FIN or RST.
  server_thread_->Pause();
  QuicSession* server_session = GetServerSession();
  if (server_session != nullptr) {
    EXPECT_EQ(0u, QuicSessionPeer::GetLocallyClosedStreamsHighestOffset(
                      server_session)
                      .size());
  } else {
    ADD_FAILURE() << "Missing server session";
  }
  server_thread_->Resume();
}

// TestAckListener counts how many bytes are acked during its lifetime.
class TestAckListener : public QuicAckListenerInterface {
 public:
  TestAckListener() {}

  void OnPacketAcked(int acked_bytes,
                     QuicTime::Delta /*delta_largest_observed*/) override {
    total_bytes_acked_ += acked_bytes;
  }

  void OnPacketRetransmitted(int /*retransmitted_bytes*/) override {}

  int total_bytes_acked() const { return total_bytes_acked_; }

 protected:
  // Object is ref counted.
  ~TestAckListener() override {}

 private:
  int total_bytes_acked_ = 0;
};

class TestResponseListener : public QuicSpdyClientBase::ResponseListener {
 public:
  void OnCompleteResponse(QuicStreamId id,
                          const HttpHeaderBlock& response_headers,
                          absl::string_view response_body) override {
    QUIC_DVLOG(1) << "response for stream " << id << " "
                  << response_headers.DebugString() << "\n"
                  << response_body;
  }
};

TEST_P(EndToEndTest, AckNotifierWithPacketLossAndBlockedSocket) {
  // Verify that even in the presence of packet loss and occasionally blocked
  // socket, an AckNotifierDelegate will get informed that the data it is
  // interested in has been ACKed. This tests end-to-end ACK notification, and
  // demonstrates that retransmissions do not break this functionality.
  // Disable blackhole detection as this test is testing loss recovery.
  client_extra_copts_.push_back(kNBHD);
  SetPacketLossPercentage(5);
  ASSERT_TRUE(Initialize());
  // Wait for the server SHLO before upping the packet loss.
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  SetPacketLossPercentage(30);
  client_writer_->set_fake_blocked_socket_percentage(10);

  // Wait for SETTINGS frame from server that sets QPACK dynamic table capacity
  // to make sure request headers will be compressed using the dynamic table.
  if (version_.UsesHttp3()) {
    while (true) {
      // Waits for up to 50 ms.
      client_->client()->WaitForEvents();
      ASSERT_TRUE(client_->connected());
      QuicSpdyClientSession* client_session = GetClientSession();
      if (client_session == nullptr) {
        ADD_FAILURE() << "Missing client session";
        return;
      }
      QpackEncoder* qpack_encoder = client_session->qpack_encoder();
      if (qpack_encoder == nullptr) {
        ADD_FAILURE() << "Missing QPACK encoder";
        return;
      }
      QpackEncoderHeaderTable* header_table =
          QpackEncoderPeer::header_table(qpack_encoder);
      if (header_table == nullptr) {
        ADD_FAILURE() << "Missing header table";
        return;
      }
      if (header_table->dynamic_table_capacity() > 0) {
        break;
      }
    }
  }

  // Create a POST request and send the headers only.
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  // Here, we have to specify flush=false, otherwise we risk a race condition in
  // which the headers are sent and acknowledged before the ack notifier is
  // installed.
  client_->SendMessage(headers, "", /*fin=*/false, /*flush=*/false);

  // Size of headers on the request stream. This is zero if headers are sent on
  // the header stream.
  size_t header_size = 0;
  if (version_.UsesHttp3()) {
    // Determine size of headers after QPACK compression.
    NoopDecoderStreamErrorDelegate decoder_stream_error_delegate;
    NoopQpackStreamSenderDelegate encoder_stream_sender_delegate;
    QpackEncoder qpack_encoder(&decoder_stream_error_delegate,
                               HuffmanEncoding::kEnabled,
                               CookieCrumbling::kEnabled);
    qpack_encoder.set_qpack_stream_sender_delegate(
        &encoder_stream_sender_delegate);

    qpack_encoder.SetMaximumDynamicTableCapacity(
        kDefaultQpackMaxDynamicTableCapacity);
    qpack_encoder.SetDynamicTableCapacity(kDefaultQpackMaxDynamicTableCapacity);
    qpack_encoder.SetMaximumBlockedStreams(kDefaultMaximumBlockedStreams);

    std::string encoded_headers = qpack_encoder.EncodeHeaderList(
        /* stream_id = */ 0, headers, nullptr);
    header_size = encoded_headers.size();
  }

  // Test the AckNotifier's ability to track multiple packets by making the
  // request body exceed the size of a single packet.
  std::string request_string = "a request body bigger than one packet" +
                               std::string(kMaxOutgoingPacketSize, '.');

  const int expected_bytes_acked = header_size + request_string.length();

  // The TestAckListener will cause a failure if not notified.
  quiche::QuicheReferenceCountedPointer<TestAckListener> ack_listener(
      new TestAckListener());

  // Send the request, and register the delegate for ACKs.
  client_->SendData(request_string, true, ack_listener);
  WaitForFooResponseAndCheckIt();

  // Send another request to flush out any pending ACKs on the server.
  SendSynchronousBarRequestAndCheckResponse();

  // Make sure the delegate does get the notification it expects.
  int attempts = 0;
  constexpr int kMaxAttempts = 20;
  while (ack_listener->total_bytes_acked() < expected_bytes_acked) {
    // Waits for up to 50 ms.
    client_->client()->WaitForEvents();
    ASSERT_TRUE(client_->connected());
    if (++attempts >= kMaxAttempts) {
      break;
    }
  }
  EXPECT_EQ(ack_listener->total_bytes_acked(), expected_bytes_acked)
      << " header_size " << header_size << " request length "
      << request_string.length();
}

// Send a public reset from the server.
TEST_P(EndToEndTest, ServerSendPublicReset) {
  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  QuicSpdySession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicConfig* config = client_session->config();
  ASSERT_TRUE(config);
  EXPECT_TRUE(config->HasReceivedStatelessResetToken());
  StatelessResetToken stateless_reset_token =
      config->ReceivedStatelessResetToken();

  // Send the public reset.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionId connection_id = client_connection->connection_id();
  QuicFramer framer(server_supported_versions_, QuicTime::Zero(),
                    Perspective::IS_SERVER, kQuicDefaultConnectionIdLength);
  std::unique_ptr<QuicEncryptedPacket> packet =
      framer.BuildIetfStatelessResetPacket(
          connection_id, /*received_packet_length=*/100, stateless_reset_token);
  // We must pause the server's thread in order to call WritePacket without
  // race conditions.
  server_thread_->Pause();
  auto client_address = client_connection->self_address();
  server_writer_->WritePacket(packet->data(), packet->length(),
                              server_address_.host(), client_address, nullptr,
                              packet_writer_params_);
  server_thread_->Resume();

  // The request should fail.
  EXPECT_EQ("", client_->SendSynchronousRequest("/foo"));
  EXPECT_TRUE(client_->response_headers()->empty());
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_PUBLIC_RESET));
}

// Send a public reset from the server for a different connection ID.
// It should be ignored.
TEST_P(EndToEndTest, ServerSendPublicResetWithDifferentConnectionId) {
  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  QuicSpdySession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicConfig* config = client_session->config();
  ASSERT_TRUE(config);
  EXPECT_TRUE(config->HasReceivedStatelessResetToken());
  StatelessResetToken stateless_reset_token =
      config->ReceivedStatelessResetToken();
  // Send the public reset.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionId incorrect_connection_id = TestConnectionId(
      TestConnectionIdToUInt64(client_connection->connection_id()) + 1);
  QuicFramer framer(server_supported_versions_, QuicTime::Zero(),
                    Perspective::IS_SERVER, kQuicDefaultConnectionIdLength);
  NiceMock<MockQuicConnectionDebugVisitor> visitor;
  client_connection->set_debug_visitor(&visitor);
  std::unique_ptr<QuicEncryptedPacket> packet =
      framer.BuildIetfStatelessResetPacket(incorrect_connection_id,
                                           /*received_packet_length=*/100,
                                           stateless_reset_token);
  EXPECT_CALL(visitor, OnIncorrectConnectionId(incorrect_connection_id))
      .Times(0);
  // We must pause the server's thread in order to call WritePacket without
  // race conditions.
  server_thread_->Pause();
  auto client_address = client_connection->self_address();
  server_writer_->WritePacket(packet->data(), packet->length(),
                              server_address_.host(), client_address, nullptr,
                              packet_writer_params_);
  server_thread_->Resume();

  // The request should fail. IETF stateless reset does not include connection
  // ID.
  EXPECT_EQ("", client_->SendSynchronousRequest("/foo"));
  EXPECT_TRUE(client_->response_headers()->empty());
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_PUBLIC_RESET));

  client_connection->set_debug_visitor(nullptr);
}

TEST_P(EndToEndTest, InduceStatelessResetFromServer) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  SetPacketLossPercentage(100);  // Block PEER_GOING_AWAY message from server.
  StopServer(true);
  server_writer_ = new PacketDroppingTestWriter();
  StartServer();
  SetPacketLossPercentage(0);
  // The request should generate a public reset.
  EXPECT_EQ("", client_->SendSynchronousRequest("/foo"));
  EXPECT_TRUE(client_->response_headers()->empty());
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_PUBLIC_RESET));
  EXPECT_FALSE(client_->connected());
}

// Send a public reset from the client for a different connection ID.
// It should be ignored.
TEST_P(EndToEndTest, ClientSendPublicResetWithDifferentConnectionId) {
  ASSERT_TRUE(Initialize());

  // Send the public reset.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionId incorrect_connection_id = TestConnectionId(
      TestConnectionIdToUInt64(client_connection->connection_id()) + 1);
  QuicPublicResetPacket header;
  header.connection_id = incorrect_connection_id;
  QuicFramer framer(server_supported_versions_, QuicTime::Zero(),
                    Perspective::IS_CLIENT, kQuicDefaultConnectionIdLength);
  std::unique_ptr<QuicEncryptedPacket> packet(
      framer.BuildPublicResetPacket(header));
  client_writer_->WritePacket(
      packet->data(), packet->length(),
      client_->client()->network_helper()->GetLatestClientAddress().host(),
      server_address_, nullptr, packet_writer_params_);

  // The connection should be unaffected.
  SendSynchronousFooRequestAndCheckResponse();
}

// Send a version negotiation packet from the server for a different
// connection ID.  It should be ignored.
TEST_P(EndToEndTest, ServerSendVersionNegotiationWithDifferentConnectionId) {
  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // Send the version negotiation packet.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionId incorrect_connection_id = TestConnectionId(
      TestConnectionIdToUInt64(client_connection->connection_id()) + 1);
  std::unique_ptr<QuicEncryptedPacket> packet(
      QuicFramer::BuildVersionNegotiationPacket(
          incorrect_connection_id, EmptyQuicConnectionId(), /*ietf_quic=*/true,
          version_.HasLengthPrefixedConnectionIds(),
          server_supported_versions_));
  NiceMock<MockQuicConnectionDebugVisitor> visitor;
  client_connection->set_debug_visitor(&visitor);
  EXPECT_CALL(visitor, OnIncorrectConnectionId(incorrect_connection_id))
      .Times(1);
  // We must pause the server's thread in order to call WritePacket without
  // race conditions.
  server_thread_->Pause();
  server_writer_->WritePacket(
      packet->data(), packet->length(), server_address_.host(),
      client_->client()->network_helper()->GetLatestClientAddress(), nullptr,
      packet_writer_params_);
  server_thread_->Resume();

  // The connection should be unaffected.
  SendSynchronousFooRequestAndCheckResponse();

  client_connection->set_debug_visitor(nullptr);
}

// DowngradePacketWriter is a client writer which will intercept all the client
// writes for |target_version| and reply to them with version negotiation
// packets to attempt a version downgrade attack. Once the client has downgraded
// to a different version, the writer stops intercepting. |server_thread| must
// start off paused, and will be resumed once interception is done.
class DowngradePacketWriter : public PacketDroppingTestWriter {
 public:
  explicit DowngradePacketWriter(
      const ParsedQuicVersion& target_version,
      const ParsedQuicVersionVector& supported_versions, QuicTestClient* client,
      QuicPacketWriter* server_writer, ServerThread* server_thread)
      : target_version_(target_version),
        supported_versions_(supported_versions),
        client_(client),
        server_writer_(server_writer),
        server_thread_(server_thread) {}
  ~DowngradePacketWriter() override {}

  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          quic::PerPacketOptions* options,
                          const quic::QuicPacketWriterParams& params) override {
    if (!intercept_enabled_) {
      return PacketDroppingTestWriter::WritePacket(
          buffer, buf_len, self_address, peer_address, options, params);
    }
    PacketHeaderFormat format;
    QuicLongHeaderType long_packet_type;
    bool version_present, has_length_prefix;
    QuicVersionLabel version_label;
    ParsedQuicVersion parsed_version = ParsedQuicVersion::Unsupported();
    QuicConnectionId destination_connection_id, source_connection_id;
    std::optional<absl::string_view> retry_token;
    std::string detailed_error;
    if (QuicFramer::ParsePublicHeaderDispatcher(
            QuicEncryptedPacket(buffer, buf_len),
            kQuicDefaultConnectionIdLength, &format, &long_packet_type,
            &version_present, &has_length_prefix, &version_label,
            &parsed_version, &destination_connection_id, &source_connection_id,
            &retry_token, &detailed_error) != QUIC_NO_ERROR) {
      ADD_FAILURE() << "Failed to parse our own packet: " << detailed_error;
      return WriteResult(WRITE_STATUS_ERROR, 0);
    }
    if (!version_present || parsed_version != target_version_) {
      // Client is sending with another version, the attack has succeeded so we
      // can stop intercepting.
      intercept_enabled_ = false;
      server_thread_->Resume();
      // Pass the client-sent packet through.
      return WritePacket(buffer, buf_len, self_address, peer_address, options,
                         params);
    }
    // Send a version negotiation packet.
    std::unique_ptr<QuicEncryptedPacket> packet(
        QuicFramer::BuildVersionNegotiationPacket(
            destination_connection_id, source_connection_id, /*ietf_quic=*/true,
            has_length_prefix, supported_versions_));
    QuicPacketWriterParams default_params;
    server_writer_->WritePacket(
        packet->data(), packet->length(), peer_address.host(),
        client_->client()->network_helper()->GetLatestClientAddress(), nullptr,
        default_params);
    // Drop the client-sent packet but pretend it was sent.
    return WriteResult(WRITE_STATUS_OK, buf_len);
  }

 private:
  bool intercept_enabled_ = true;
  ParsedQuicVersion target_version_;
  ParsedQuicVersionVector supported_versions_;
  QuicTestClient* client_;           // Unowned.
  QuicPacketWriter* server_writer_;  // Unowned.
  ServerThread* server_thread_;      // Unowned.
};

TEST_P(EndToEndTest, VersionNegotiationDowngradeAttackIsDetected) {
  ParsedQuicVersion target_version = server_supported_versions_.back();
  if (!version_.UsesTls() || target_version == version_) {
    ASSERT_TRUE(Initialize());
    return;
  }
  connect_to_server_on_initialize_ = false;
  client_supported_versions_.insert(client_supported_versions_.begin(),
                                    target_version);
  ParsedQuicVersionVector downgrade_versions{version_};
  ASSERT_TRUE(Initialize());
  ASSERT_TRUE(server_thread_);
  // Pause the server thread to allow our DowngradePacketWriter to write version
  // negotiation packets in a thread-safe manner. It will be resumed by the
  // DowngradePacketWriter.
  server_thread_->Pause();
  client_.reset(new QuicTestClient(server_address_, server_hostname_,
                                   client_config_, client_supported_versions_,
                                   crypto_test_utils::ProofVerifierForTesting(),
                                   std::make_unique<QuicClientSessionCache>()));
  delete client_writer_;
  client_writer_ = new DowngradePacketWriter(target_version, downgrade_versions,
                                             client_.get(), server_writer_,
                                             server_thread_.get());
  client_->UseWriter(client_writer_);
  // Have the client attempt to send a request.
  client_->Connect();
  EXPECT_TRUE(client_->SendSynchronousRequest("/foo").empty());
  // Make sure the downgrade is detected and the handshake fails.
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_HANDSHAKE_FAILED));
}

// A bad header shouldn't tear down the connection, because the receiver can't
// tell the connection ID.
TEST_P(EndToEndTest, BadPacketHeaderTruncated) {
  ASSERT_TRUE(Initialize());

  // Start the connection.
  SendSynchronousFooRequestAndCheckResponse();

  // Packet with invalid public flags.
  char packet[] = {// public flags (8 byte connection_id)
                   0x3C,
                   // truncated connection ID
                   0x11};
  client_writer_->WritePacket(
      &packet[0], sizeof(packet),
      client_->client()->network_helper()->GetLatestClientAddress().host(),
      server_address_, nullptr, packet_writer_params_);
  EXPECT_TRUE(server_thread_->WaitUntil(
      [&] {
        return QuicDispatcherPeer::GetAndClearLastError(
                   QuicServerPeer::GetDispatcher(server_thread_->server())) ==
               QUIC_INVALID_PACKET_HEADER;
      },
      QuicTime::Delta::FromSeconds(5)));

  // The connection should not be terminated.
  SendSynchronousFooRequestAndCheckResponse();
}

// A bad header shouldn't tear down the connection, because the receiver can't
// tell the connection ID.
TEST_P(EndToEndTest, BadPacketHeaderFlags) {
  ASSERT_TRUE(Initialize());

  // Start the connection.
  SendSynchronousFooRequestAndCheckResponse();

  // Packet with invalid public flags.
  uint8_t packet[] = {
      // invalid public flags
      0xFF,
      // connection_id
      0x10,
      0x32,
      0x54,
      0x76,
      0x98,
      0xBA,
      0xDC,
      0xFE,
      // packet sequence number
      0xBC,
      0x9A,
      0x78,
      0x56,
      0x34,
      0x12,
      // private flags
      0x00,
  };
  client_writer_->WritePacket(
      reinterpret_cast<const char*>(packet), sizeof(packet),
      client_->client()->network_helper()->GetLatestClientAddress().host(),
      server_address_, nullptr, packet_writer_params_);

  EXPECT_TRUE(server_thread_->WaitUntil(
      [&] {
        return QuicDispatcherPeer::GetAndClearLastError(
                   QuicServerPeer::GetDispatcher(server_thread_->server())) ==
               QUIC_INVALID_PACKET_HEADER;
      },
      QuicTime::Delta::FromSeconds(5)));

  // The connection should not be terminated.
  SendSynchronousFooRequestAndCheckResponse();
}

// Send a packet from the client with bad encrypted data.  The server should not
// tear down the connection.
// Marked as slow since it calls absl::SleepFor().
TEST_P(EndToEndTest, QUICHE_SLOW_TEST(BadEncryptedData)) {
  ASSERT_TRUE(Initialize());

  // Start the connection.
  SendSynchronousFooRequestAndCheckResponse();

  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
      client_connection->connection_id(), EmptyQuicConnectionId(), false, false,
      1, "At least 20 characters.", CONNECTION_ID_PRESENT, CONNECTION_ID_ABSENT,
      PACKET_4BYTE_PACKET_NUMBER));
  // Damage the encrypted data.
  std::string damaged_packet(packet->data(), packet->length());
  damaged_packet[30] ^= 0x01;
  QUIC_DLOG(INFO) << "Sending bad packet.";
  client_writer_->WritePacket(
      damaged_packet.data(), damaged_packet.length(),
      client_->client()->network_helper()->GetLatestClientAddress().host(),
      server_address_, nullptr, packet_writer_params_);
  // Give the server time to process the packet.
  absl::SleepFor(absl::Seconds(1));
  // This error is sent to the connection's OnError (which ignores it), so the
  // dispatcher doesn't see it.
  // Pause the server so we can access the server's internals without races.
  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  if (dispatcher != nullptr) {
    EXPECT_THAT(QuicDispatcherPeer::GetAndClearLastError(dispatcher),
                IsQuicNoError());
  } else {
    ADD_FAILURE() << "Missing dispatcher";
  }
  server_thread_->Resume();

  // The connection should not be terminated.
  SendSynchronousFooRequestAndCheckResponse();
}

TEST_P(EndToEndTest, CanceledStreamDoesNotBecomeZombie) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  // Lose the request.
  SetPacketLossPercentage(100);
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  client_->SendMessage(headers, "test_body", /*fin=*/false);
  QuicSpdyClientStream* stream = client_->GetOrCreateStream();

  // Cancel the stream.
  stream->Reset(QUIC_STREAM_CANCELLED);
  QuicSession* session = GetClientSession();
  ASSERT_TRUE(session);
  // Verify canceled stream does not become zombie.
  EXPECT_EQ(1u, QuicSessionPeer::closed_streams(session).size());
}

// A test stream that gives |response_body_| as an error response body.
class ServerStreamWithErrorResponseBody : public QuicSimpleServerStream {
 public:
  ServerStreamWithErrorResponseBody(
      QuicStreamId id, QuicSpdySession* session,
      QuicSimpleServerBackend* quic_simple_server_backend,
      std::string response_body)
      : QuicSimpleServerStream(id, session, BIDIRECTIONAL,
                               quic_simple_server_backend),
        response_body_(std::move(response_body)) {}

  ~ServerStreamWithErrorResponseBody() override = default;

 protected:
  void SendErrorResponse() override {
    QUIC_DLOG(INFO) << "Sending error response for stream " << id();
    HttpHeaderBlock headers;
    headers[":status"] = "500";
    headers["content-length"] = absl::StrCat(response_body_.size());
    // This method must call CloseReadSide to cause the test case, StopReading
    // is not sufficient.
    QuicStreamPeer::CloseReadSide(this);
    SendHeadersAndBody(std::move(headers), response_body_);
  }

  std::string response_body_;
};

class StreamWithErrorFactory : public QuicTestServer::StreamFactory {
 public:
  explicit StreamWithErrorFactory(std::string response_body)
      : response_body_(std::move(response_body)) {}

  ~StreamWithErrorFactory() override = default;

  QuicSimpleServerStream* CreateStream(
      QuicStreamId id, QuicSpdySession* session,
      QuicSimpleServerBackend* quic_simple_server_backend) override {
    return new ServerStreamWithErrorResponseBody(
        id, session, quic_simple_server_backend, response_body_);
  }

  QuicSimpleServerStream* CreateStream(
      PendingStream* /*pending*/, QuicSpdySession* /*session*/,
      QuicSimpleServerBackend* /*response_cache*/) override {
    return nullptr;
  }

 private:
  std::string response_body_;
};

// A test server stream that drops all received body.
class ServerStreamThatDropsBody : public QuicSimpleServerStream {
 public:
  ServerStreamThatDropsBody(QuicStreamId id, QuicSpdySession* session,
                            QuicSimpleServerBackend* quic_simple_server_backend)
      : QuicSimpleServerStream(id, session, BIDIRECTIONAL,
                               quic_simple_server_backend) {}

  ~ServerStreamThatDropsBody() override = default;

 protected:
  void OnBodyAvailable() override {
    while (HasBytesToRead()) {
      struct iovec iov;
      if (GetReadableRegions(&iov, 1) == 0) {
        // No more data to read.
        break;
      }
      QUIC_DVLOG(1) << "Processed " << iov.iov_len << " bytes for stream "
                    << id();
      MarkConsumed(iov.iov_len);
    }

    if (!sequencer()->IsClosed()) {
      sequencer()->SetUnblocked();
      return;
    }

    // If the sequencer is closed, then all the body, including the fin, has
    // been consumed.
    OnFinRead();

    if (write_side_closed() || fin_buffered()) {
      return;
    }

    SendResponse();
  }
};

class ServerStreamThatDropsBodyFactory : public QuicTestServer::StreamFactory {
 public:
  ServerStreamThatDropsBodyFactory() = default;

  ~ServerStreamThatDropsBodyFactory() override = default;

  QuicSimpleServerStream* CreateStream(
      QuicStreamId id, QuicSpdySession* session,
      QuicSimpleServerBackend* quic_simple_server_backend) override {
    return new ServerStreamThatDropsBody(id, session,
                                         quic_simple_server_backend);
  }

  QuicSimpleServerStream* CreateStream(
      PendingStream* /*pending*/, QuicSpdySession* /*session*/,
      QuicSimpleServerBackend* /*response_cache*/) override {
    return nullptr;
  }
};

// A test server stream that sends response with body size greater than 4GB.
class ServerStreamThatSendsHugeResponse : public QuicSimpleServerStream {
 public:
  ServerStreamThatSendsHugeResponse(
      QuicStreamId id, QuicSpdySession* session,
      QuicSimpleServerBackend* quic_simple_server_backend, int64_t body_bytes)
      : QuicSimpleServerStream(id, session, BIDIRECTIONAL,
                               quic_simple_server_backend),
        body_bytes_(body_bytes) {}

  ~ServerStreamThatSendsHugeResponse() override = default;

 protected:
  void SendResponse() override {
    QuicBackendResponse response;
    std::string body(body_bytes_, 'a');
    response.set_body(body);
    SendHeadersAndBodyAndTrailers(response.headers().Clone(), response.body(),
                                  response.trailers().Clone());
  }

 private:
  // Use a explicit int64_t rather than size_t to simulate a 64-bit server
  // talking to a 32-bit client.
  int64_t body_bytes_;
};

class ServerStreamThatSendsHugeResponseFactory
    : public QuicTestServer::StreamFactory {
 public:
  explicit ServerStreamThatSendsHugeResponseFactory(int64_t body_bytes)
      : body_bytes_(body_bytes) {}

  ~ServerStreamThatSendsHugeResponseFactory() override = default;

  QuicSimpleServerStream* CreateStream(
      QuicStreamId id, QuicSpdySession* session,
      QuicSimpleServerBackend* quic_simple_server_backend) override {
    return new ServerStreamThatSendsHugeResponse(
        id, session, quic_simple_server_backend, body_bytes_);
  }

  QuicSimpleServerStream* CreateStream(
      PendingStream* /*pending*/, QuicSpdySession* /*session*/,
      QuicSimpleServerBackend* /*response_cache*/) override {
    return nullptr;
  }

  int64_t body_bytes_;
};

class BlockedFrameObserver : public QuicConnectionDebugVisitor {
 public:
  std::vector<QuicBlockedFrame> blocked_frames() const {
    return blocked_frames_;
  }

  void OnBlockedFrame(const QuicBlockedFrame& frame) override {
    blocked_frames_.push_back(frame);
  }

 private:
  std::vector<QuicBlockedFrame> blocked_frames_;
};

TEST_P(EndToEndTest, BlockedFrameIncludesOffset) {
  if (!version_.HasIetfQuicFrames()) {
    // For Google QUIC, the BLOCKED frame offset is ignored.
    Initialize();
    return;
  }

  set_smaller_flow_control_receive_window();
  ASSERT_TRUE(Initialize());

  // Observe the connection for BLOCKED frames.
  BlockedFrameObserver observer;
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  client_connection->set_debug_visitor(&observer);

  // Set the response body larger than the flow control window so the server
  // must receive a window update from the client before it can finish sending
  // it (hence, causing the server to send a BLOCKED frame)
  uint32_t response_body_size =
      client_config_.GetInitialSessionFlowControlWindowToSend() + 10;
  std::string response_body(response_body_size, 'a');
  AddToCache("/blocked", 200, response_body);
  SendSynchronousRequestAndCheckResponse("/blocked", response_body);
  client_->Disconnect();

  ASSERT_GE(observer.blocked_frames().size(), static_cast<uint64_t>(0));
  for (const QuicBlockedFrame& frame : observer.blocked_frames()) {
    if (frame.stream_id ==
        QuicUtils::GetInvalidStreamId(version_.transport_version)) {
      // connection-level BLOCKED frame
      ASSERT_EQ(frame.offset,
                client_config_.GetInitialSessionFlowControlWindowToSend());
    } else {
      // stream-level BLOCKED frame
      ASSERT_EQ(frame.offset,
                client_config_.GetInitialStreamFlowControlWindowToSend());
    }
  }

  client_connection->set_debug_visitor(nullptr);
}

TEST_P(EndToEndTest, EarlyResponseFinRecording) {
  set_smaller_flow_control_receive_window();

  // Verify that an incoming FIN is recorded in a stream object even if the read
  // side has been closed.  This prevents an entry from being made in
  // locally_close_streams_highest_offset_ (which will never be deleted).
  // To set up the test condition, the server must do the following in order:
  // start sending the response and call CloseReadSide
  // receive the FIN of the request
  // send the FIN of the response

  // The response body must be larger than the flow control window so the server
  // must receive a window update from the client before it can finish sending
  // it.
  uint32_t response_body_size =
      2 * client_config_.GetInitialStreamFlowControlWindowToSend();
  std::string response_body(response_body_size, 'a');

  StreamWithErrorFactory stream_factory(response_body);
  SetSpdyStreamFactory(&stream_factory);

  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // A POST that gets an early error response, after the headers are received
  // and before the body is received, due to invalid content-length.
  // Set an invalid content-length, so the request will receive an early 500
  // response.
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/garbage";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["content-length"] = "-1";

  // The body must be large enough that the FIN will be in a different packet
  // than the end of the headers, but short enough to not require a flow control
  // update.  This allows
```