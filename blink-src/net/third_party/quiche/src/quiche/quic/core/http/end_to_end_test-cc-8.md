Response:
The user wants to understand the functionality of the provided C++ code file, which is part of the Chromium network stack and specifically relates to QUIC's end-to-end testing.

Here's a breakdown of how to approach this:

1. **Identify the main purpose:** The filename "end_to_end_test.cc" strongly suggests this file contains integration tests that simulate real-world scenarios between a QUIC client and server.

2. **Analyze the test cases:**  The `TEST_P` macros define individual test cases. Examine the names of these tests to understand what aspects of QUIC are being tested. Keywords like "KeyUpdate," "TlsResumption," "WebTransport," "Connect," and "Reject" are crucial.

3. **Look for common setup and utility functions:** The code uses `Initialize()`, `SendSynchronousFooRequestAndCheckResponse()`, `GetClientConnection()`, `GetServerConnection()`, etc. These indicate common setup and helper functions for the tests.

4. **Focus on specific functionalities:**
    * **Key Update:** Tests around `InitiateKeyUpdate` and tracking `key_update_count` verify the key rotation mechanism in QUIC.
    * **TLS Resumption:** Tests involving `ssl_early_data_no_session_offered`, `EarlyDataAccepted()`, and `ssl_early_data_session_not_resumed` cover TLS session resumption.
    * **WebTransport:** Tests with names like "WebTransportSessionSetup," "WebTransportSessionUnidirectionalStream," etc., obviously test the WebTransport protocol over QUIC.
    * **Extended CONNECT:** Tests involving "InvalidExtendedConnect" and "RejectExtendedConnect" examine the handling of the HTTP/3 CONNECT method for protocols like WebTransport.
    * **Header Validation:** Tests with "RejectInvalidRequestHeader," "RejectTransferEncodingResponse," and "RejectUpperCaseRequest" focus on enforcing HTTP/3 header rules.

5. **Relate to JavaScript (if possible):** Think about how these QUIC features are exposed or used in a browser context. For instance, WebTransport has a direct JavaScript API. TLS resumption is a lower-level optimization that affects connection establishment speed, which can impact the user experience in web applications.

6. **Infer input and output:** For each test case, consider the initial state, the actions taken by the client and server, and the expected outcome (assertions using `EXPECT_EQ`, `EXPECT_TRUE`, etc.).

7. **Identify potential errors:** Look for scenarios where the tests check for specific error conditions or rejections (e.g., invalid headers, disabled features).

8. **Trace user actions:**  Consider the sequence of steps a user might take in a browser that would lead to these QUIC functionalities being exercised. Opening a webpage, establishing a secure connection, sending data, using WebTransport APIs, etc.

9. **Summarize the overall function:** Combine the understanding gained from the individual test cases to describe the broader purpose of the file.

**Self-Correction/Refinement:**

* **Initial thought:** Focus only on the code snippets provided in this part.
* **Correction:** Remember that this is part 9 of 10, meaning the previous parts likely established the testing framework and basic setup. This part builds upon that. The summary should reflect this incremental nature.
* **Initial thought:**  Assume all tests are independent.
* **Correction:** Some tests might have dependencies or a logical flow (e.g., testing enabling and then disabling a feature).

By following these steps and refining the understanding along the way, I can generate a comprehensive answer to the user's request.
This is the 9th part of a 10-part series of a C++ source file in the Chromium network stack, specifically located in `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc`. Given the context of the previous parts and the function names within this snippet, we can infer its primary function and details about its operation.

**Overall Function of `end_to_end_test.cc` (Based on Part 9):**

This file contains **end-to-end integration tests for the QUIC protocol's HTTP/3 implementation in Chromium**. It sets up a client and a server, simulates network conditions, and verifies that various aspects of the QUIC and HTTP/3 interaction function correctly.

**Specific Functionality Covered in this Snippet (Part 9):**

This part focuses on testing more advanced features of QUIC and HTTP/3, particularly around:

* **Key Updates:**
    * Initiating key updates by the client.
    * Initiating key updates by the server.
    * Initiating key updates by both client and server concurrently.
    * Triggering key updates based on confidentiality limits (packet count).
* **TLS Resumption:**
    * Enabling and disabling TLS resumption dynamically on the server-side.
    * Verifying that clients can successfully resume TLS sessions (0-RTT).
    * Testing scenarios where the server declines resumption.
    * Checking the behavior when the client runs out of resumption tickets.
* **Blocking Requests Until Settings:**
    * Testing the behavior of a client blocking requests until it receives HTTP/3 settings from the server. This is important for ensuring proper initialization.
* **WebTransport:**
    * Establishing WebTransport sessions.
    * Sending and receiving unidirectional and bidirectional streams over WebTransport.
    * Handling data loss during WebTransport sessions.
    * Sending data early in a WebTransport session before the server's initial response.
    * Closing WebTransport sessions gracefully (with and without explicit close messages).
    * Handling server-initiated session closures.
    * Testing WebTransport session draining (GOAWAY).
    * Handling stream termination (resets and `STOP_SENDING`).
    * Testing the reliability of reset signals in WebTransport under lossy conditions (though this test is currently disabled).
    * Handling cases where the WebTransport endpoint is not found (404).
    * Handling HTTP/3 GOAWAY frames in WebTransport sessions.
* **Extended CONNECT (for protocols like WebTransport):**
    * Testing the rejection of invalid extended CONNECT requests.
    * Testing the rejection of extended CONNECT when the feature is disabled on the server.
* **Invalid HTTP/3 Header Handling:**
    * Testing the server's rejection of requests with invalid headers (e.g., `transfer-encoding`).
    * Testing the client's handling of responses with `transfer-encoding` headers.
    * Testing the server's rejection of requests with uppercase headers.

**Relationship to JavaScript Functionality (with Examples):**

Many of the features tested here directly relate to JavaScript APIs used in web browsers:

* **WebTransport:** The tests for `WebTransportSessionSetup`, `WebTransportStream`, and `WebTransportDatagrams` directly correspond to the JavaScript WebTransport API. A JavaScript application can use the `WebTransport` API to establish a connection and send/receive data streams and unreliable datagrams.
    * **Example:**  A JavaScript application might use the following code to establish a WebTransport connection (which is being tested in `WebTransportSessionSetup`):
      ```javascript
      const transport = new WebTransport("https://example.com/webtransport");
      await transport.ready;
      ```
    * **Example:** Sending data on a WebTransport bidirectional stream (tested in `WebTransportSessionBidirectionalStream`):
      ```javascript
      const stream = await transport.createBidirectionalStream();
      const writer = stream.writable.getWriter();
      writer.write(new TextEncoder().encode("Hello from JavaScript!"));
      writer.close();
      ```
* **TLS Resumption:** While not directly controlled by JavaScript, TLS resumption improves page load times and connection establishment, enhancing the user experience. The tests in this file ensure that this optimization works correctly. When a user revisits a website, a successful TLS resumption (0-RTT) avoids a full handshake, making the connection faster.
* **HTTP/3:**  While JavaScript doesn't directly interact with the underlying HTTP/3 protocol details, the performance and reliability benefits provided by HTTP/3, which these tests validate, improve the overall web browsing experience.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

Let's take the `TEST_P(EndToEndTest, KeyUpdateInitiatedByClient)` as an example:

* **Assumption:** The client and server have established a QUIC connection.
* **Input:**
    1. A synchronous "foo" request is sent from the client.
    2. The client initiates a key update.
    3. Another synchronous "foo" request is sent.
    4. The server initiates a key update.
    5. A final synchronous "foo" request is sent.
* **Expected Output:**
    1. The first request and response succeed.
    2. The client's key update count is 1.
    3. The second request and response succeed.
    4. The client's key update count is 2.
    5. The third request and response succeed.
    6. The server's key update count is 2.

**User or Programming Common Usage Errors (with Examples):**

* **Incorrect WebTransport API Usage:**  A common mistake in JavaScript when using WebTransport would be trying to send data before the `transport.ready` promise resolves, leading to errors. The tests in this file help ensure the underlying protocol handles such scenarios gracefully (though the test focuses on the C++ implementation).
* **Misunderstanding TLS Resumption:** Developers might assume TLS resumption will always work. These tests cover scenarios where it might fail (disabled on the server, no session ticket), helping developers understand potential fallback mechanisms.
* **Sending Invalid HTTP/3 Headers:**  If a backend or a proxy generates responses with `transfer-encoding` when using HTTP/3, these tests ensure the client correctly rejects them. Similarly, sending requests with forbidden headers like `transfer-encoding` is a programming error that these tests validate the server handles.

**User Operations Leading to This Code (Debugging Clues):**

To reach the code being tested here, a user might perform the following actions in a Chromium-based browser:

1. **Navigate to a website over HTTPS:** This initiates a QUIC connection if the server supports it.
2. **The browser might negotiate a key update:** This could happen automatically after a certain amount of data transfer or time. The `KeyUpdateInitiatedByClient`, `KeyUpdateInitiatedByServer`, and `KeyUpdateInitiatedByBoth` tests cover these scenarios.
3. **The user might revisit a website quickly:** This triggers TLS session resumption (0-RTT), tested by `TlsResumptionEnabledOnTheFly` and `TlsResumptionDisabledOnTheFly`.
4. **A web application might use the WebTransport API:**  If a website uses WebTransport, the tests for `WebTransportSessionSetup`, `WebTransportStream`, etc., become relevant. The user interacting with such a website exercises this code.
5. **A web application might send requests with specific headers:** The tests like `RejectInvalidRequestHeader` simulate scenarios where either the browser itself or a web application attempts to send requests with invalid HTTP/3 headers.
6. **A server might send responses with specific headers:** The `RejectTransferEncodingResponse` test checks how the browser handles non-compliant HTTP/3 responses.

**Summary of Part 9's Functionality:**

This 9th part of the `end_to_end_test.cc` file in Chromium's QUIC implementation rigorously tests advanced features of the protocol and its HTTP/3 mapping. It covers various key update scenarios, the enabling and disabling of TLS resumption, and a comprehensive suite of tests for the WebTransport protocol. Additionally, it validates the handling of extended CONNECT requests and the enforcement of HTTP/3 header validity rules. These tests are crucial for ensuring the robustness, security, and interoperability of Chromium's QUIC implementation, directly impacting the performance and functionality experienced by users browsing the web.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共10部分，请归纳一下它的功能

"""
nt);

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(1u, client_connection->GetStats().key_update_count);

  server_thread_->WaitUntil(
      [this]() {
        QuicConnection* server_connection = GetServerConnection();
        if (server_connection != nullptr) {
          if (!server_connection->IsKeyUpdateAllowed()) {
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

TEST_P(EndToEndTest, KeyUpdateInitiatedByBoth) {
  if (!version_.UsesTls()) {
    // Key Update is only supported in TLS handshake.
    ASSERT_TRUE(Initialize());
    return;
  }

  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();

  // Use WaitUntil to ensure the server had executed the key update predicate
  // before the client sends the Foo request, otherwise the Foo request from
  // the client could trigger the server key update before the server can
  // initiate the key update locally. That would mean the test is no longer
  // hitting the intended test state of both sides locally initiating a key
  // update before receiving a packet in the new key phase from the other side.
  // Additionally the test would fail since InitiateKeyUpdate() would not allow
  // to do another key update yet and return false.
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
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_TRUE(
      client_connection->InitiateKeyUpdate(KeyUpdateReason::kLocalForTests));

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(1u, client_connection->GetStats().key_update_count);

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(1u, client_connection->GetStats().key_update_count);

  server_thread_->WaitUntil(
      [this]() {
        QuicConnection* server_connection = GetServerConnection();
        if (server_connection != nullptr) {
          if (!server_connection->IsKeyUpdateAllowed()) {
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

TEST_P(EndToEndTest, KeyUpdateInitiatedByConfidentialityLimit) {
  SetQuicFlag(quic_key_update_confidentiality_limit, 16U);

  if (!version_.UsesTls()) {
    // Key Update is only supported in TLS handshake.
    ASSERT_TRUE(Initialize());
    return;
  }

  ASSERT_TRUE(Initialize());

  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(0u, client_connection->GetStats().key_update_count);

  server_thread_->WaitUntil(
      [this]() {
        QuicConnection* server_connection = GetServerConnection();
        if (server_connection != nullptr) {
          EXPECT_EQ(0u, server_connection->GetStats().key_update_count);
        } else {
          ADD_FAILURE() << "Missing server connection";
        }
        return true;
      },
      QuicTime::Delta::FromSeconds(5));

  for (uint64_t i = 0; i < GetQuicFlag(quic_key_update_confidentiality_limit);
       ++i) {
    SendSynchronousFooRequestAndCheckResponse();
  }

  // Don't know exactly how many packets will be sent in each request/response,
  // so just test that at least one key update occurred.
  EXPECT_LE(1u, client_connection->GetStats().key_update_count);

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection) {
    QuicConnectionStats server_stats = server_connection->GetStats();
    EXPECT_LE(1u, server_stats.key_update_count);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, TlsResumptionEnabledOnTheFly) {
  SetQuicFlag(quic_disable_server_tls_resumption, true);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesTls()) {
    // This test is TLS specific.
    return;
  }

  // Send the first request. Client should not have a resumption ticket.
  SendSynchronousFooRequestAndCheckResponse();
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_EQ(client_session->GetCryptoStream()->EarlyDataReason(),
            ssl_early_data_no_session_offered);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  client_->Disconnect();

  SetQuicFlag(quic_disable_server_tls_resumption, false);

  // Send the second request. Client should still have no resumption ticket, but
  // it will receive one which can be used by the next request.
  client_->Connect();
  SendSynchronousFooRequestAndCheckResponse();

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_EQ(client_session->GetCryptoStream()->EarlyDataReason(),
            ssl_early_data_no_session_offered);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  client_->Disconnect();

  // Send the third request in 0RTT.
  client_->Connect();
  SendSynchronousFooRequestAndCheckResponse();

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  client_->Disconnect();
}

TEST_P(EndToEndTest, TlsResumptionDisabledOnTheFly) {
  SetQuicFlag(quic_disable_server_tls_resumption, false);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesTls()) {
    // This test is TLS specific.
    return;
  }

  // Send the first request and then disconnect.
  SendSynchronousFooRequestAndCheckResponse();
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  client_->Disconnect();

  // Send the second request in 0RTT.
  client_->Connect();
  SendSynchronousFooRequestAndCheckResponse();

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  client_->Disconnect();

  SetQuicFlag(quic_disable_server_tls_resumption, true);

  // Send the third request. The client should try resumption but server should
  // decline it.
  client_->Connect();
  SendSynchronousFooRequestAndCheckResponse();

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_EQ(client_session->GetCryptoStream()->EarlyDataReason(),
            ssl_early_data_session_not_resumed);
  client_->Disconnect();

  // Keep sending until the client runs out of resumption tickets.
  for (int i = 0; i < 10; ++i) {
    client_->Connect();
    SendSynchronousFooRequestAndCheckResponse();

    client_session = GetClientSession();
    ASSERT_TRUE(client_session);
    EXPECT_FALSE(client_session->EarlyDataAccepted());
    const auto early_data_reason =
        client_session->GetCryptoStream()->EarlyDataReason();
    client_->Disconnect();

    if (early_data_reason != ssl_early_data_session_not_resumed) {
      EXPECT_EQ(early_data_reason, ssl_early_data_unsupported_for_session);
      return;
    }
  }

  ADD_FAILURE() << "Client should not have 10 resumption tickets.";
}

TEST_P(EndToEndTest, BlockServerUntilSettingsReceived) {
  SetQuicReloadableFlag(quic_block_until_settings_received_copt, true);
  // Force loss to test data stream being blocked when SETTINGS are missing.
  SetPacketLossPercentage(30);
  client_extra_copts_.push_back(kBSUS);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  SendSynchronousFooRequestAndCheckResponse();

  QuicSpdySession* server_session = GetServerSession();
  EXPECT_FALSE(GetClientSession()->ShouldBufferRequestsUntilSettings());
  server_thread_->ScheduleAndWaitForCompletion([server_session] {
    EXPECT_TRUE(server_session->ShouldBufferRequestsUntilSettings());
  });
}

TEST_P(EndToEndTest, WebTransportSessionSetup) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* web_transport =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_NE(web_transport, nullptr);

  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  EXPECT_TRUE(server_session->GetWebTransportSession(web_transport->id()) !=
              nullptr);
  server_thread_->Resume();
}

TEST_P(EndToEndTest, WebTransportSessionSetupWithEchoWithSuffix) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  // "/echoFoo" should be accepted as "echo" with "set-header" query.
  WebTransportHttp3* web_transport = CreateWebTransportSession(
      "/echoFoo?set-header=bar:baz", /*wait_for_server_response=*/true);
  ASSERT_NE(web_transport, nullptr);

  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  EXPECT_TRUE(server_session->GetWebTransportSession(web_transport->id()) !=
              nullptr);
  server_thread_->Resume();
  const quiche::HttpHeaderBlock* response_headers = client_->response_headers();
  auto it = response_headers->find("bar");
  EXPECT_NE(it, response_headers->end());
  EXPECT_EQ(it->second, "baz");
}

TEST_P(EndToEndTest, WebTransportSessionWithLoss) {
  enable_web_transport_ = true;
  // Enable loss to verify all permutations of receiving SETTINGS and
  // request/response data.
  SetPacketLossPercentage(30);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* web_transport =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_NE(web_transport, nullptr);

  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  EXPECT_TRUE(server_session->GetWebTransportSession(web_transport->id()) !=
              nullptr);
  server_thread_->Resume();
}

TEST_P(EndToEndTest, WebTransportSessionUnidirectionalStream) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);
  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);

  WebTransportStream* outgoing_stream =
      session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(outgoing_stream != nullptr);
  EXPECT_EQ(outgoing_stream,
            session->GetStreamById(outgoing_stream->GetStreamId()));

  auto stream_visitor =
      std::make_unique<NiceMock<MockWebTransportStreamVisitor>>();
  bool data_acknowledged = false;
  EXPECT_CALL(*stream_visitor, OnWriteSideInDataRecvdState())
      .WillOnce(Assign(&data_acknowledged, true));
  outgoing_stream->SetVisitor(std::move(stream_visitor));

  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*outgoing_stream, "test"));
  EXPECT_TRUE(outgoing_stream->SendFin());

  bool stream_received = false;
  EXPECT_CALL(visitor, OnIncomingUnidirectionalStreamAvailable())
      .WillOnce(Assign(&stream_received, true));
  client_->WaitUntil(2000, [&stream_received]() { return stream_received; });
  EXPECT_TRUE(stream_received);
  WebTransportStream* received_stream =
      session->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(received_stream != nullptr);
  EXPECT_EQ(received_stream,
            session->GetStreamById(received_stream->GetStreamId()));
  std::string received_data;
  WebTransportStream::ReadResult result = received_stream->Read(&received_data);
  EXPECT_EQ(received_data, "test");
  EXPECT_TRUE(result.fin);

  client_->WaitUntil(2000,
                     [&data_acknowledged]() { return data_acknowledged; });
  EXPECT_TRUE(data_acknowledged);
}

TEST_P(EndToEndTest, WebTransportSessionUnidirectionalStreamSentEarly) {
  enable_web_transport_ = true;
  SetPacketLossPercentage(30);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/false);
  ASSERT_TRUE(session != nullptr);
  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);

  WebTransportStream* outgoing_stream =
      session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(outgoing_stream != nullptr);
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*outgoing_stream, "test"));
  EXPECT_TRUE(outgoing_stream->SendFin());

  bool stream_received = false;
  EXPECT_CALL(visitor, OnIncomingUnidirectionalStreamAvailable())
      .WillOnce(Assign(&stream_received, true));
  client_->WaitUntil(5000, [&stream_received]() { return stream_received; });
  EXPECT_TRUE(stream_received);
  WebTransportStream* received_stream =
      session->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(received_stream != nullptr);
  std::string received_data;
  WebTransportStream::ReadResult result = received_stream->Read(&received_data);
  EXPECT_EQ(received_data, "test");
  EXPECT_TRUE(result.fin);
}

TEST_P(EndToEndTest, WebTransportSessionBidirectionalStream) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);

  WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  EXPECT_EQ(stream, session->GetStreamById(stream->GetStreamId()));

  auto stream_visitor_owned =
      std::make_unique<NiceMock<MockWebTransportStreamVisitor>>();
  MockWebTransportStreamVisitor* stream_visitor = stream_visitor_owned.get();
  bool data_acknowledged = false;
  EXPECT_CALL(*stream_visitor, OnWriteSideInDataRecvdState())
      .WillOnce(Assign(&data_acknowledged, true));
  stream->SetVisitor(std::move(stream_visitor_owned));

  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  EXPECT_TRUE(stream->SendFin());

  std::string received_data =
      ReadDataFromWebTransportStreamUntilFin(stream, stream_visitor);
  EXPECT_EQ(received_data, "test");

  client_->WaitUntil(2000,
                     [&data_acknowledged]() { return data_acknowledged; });
  EXPECT_TRUE(data_acknowledged);
}

TEST_P(EndToEndTest, WebTransportSessionBidirectionalStreamWithBuffering) {
  enable_web_transport_ = true;
  SetPacketLossPercentage(30);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/false);
  ASSERT_TRUE(session != nullptr);

  WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  EXPECT_TRUE(stream->SendFin());

  std::string received_data = ReadDataFromWebTransportStreamUntilFin(stream);
  EXPECT_EQ(received_data, "test");
}

TEST_P(EndToEndTest, WebTransportSessionServerBidirectionalStream) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/false);
  ASSERT_TRUE(session != nullptr);
  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);

  bool stream_received = false;
  EXPECT_CALL(visitor, OnIncomingBidirectionalStreamAvailable())
      .WillOnce(Assign(&stream_received, true));
  client_->WaitUntil(5000, [&stream_received]() { return stream_received; });
  EXPECT_TRUE(stream_received);

  WebTransportStream* stream = session->AcceptIncomingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  // Test the full Writev() API.
  const std::string kLongString = std::string(16 * 1024, 'a');
  std::vector<absl::string_view> write_vector = {"foo", "bar", "test",
                                                 kLongString};
  quiche::StreamWriteOptions options;
  options.set_send_fin(true);
  QUICHE_EXPECT_OK(stream->Writev(absl::MakeConstSpan(write_vector), options));

  std::string received_data = ReadDataFromWebTransportStreamUntilFin(stream);
  EXPECT_EQ(received_data, absl::StrCat("foobartest", kLongString));
}

TEST_P(EndToEndTest, WebTransportDatagrams) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);
  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);

  quiche::SimpleBufferAllocator allocator;
  for (int i = 0; i < 10; i++) {
    session->SendOrQueueDatagram("test");
  }

  int received = 0;
  EXPECT_CALL(visitor, OnDatagramReceived(_)).WillRepeatedly([&received]() {
    received++;
  });
  client_->WaitUntil(5000, [&received]() { return received > 0; });
  EXPECT_GT(received, 0);
}

TEST_P(EndToEndTest, WebTransportSessionClose) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);
  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);

  WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  QuicStreamId stream_id = stream->GetStreamId();
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  // Keep stream open.

  bool close_received = false;
  EXPECT_CALL(visitor, OnSessionClosed(42, "test error"))
      .WillOnce(Assign(&close_received, true));
  session->CloseSession(42, "test error");
  client_->WaitUntil(2000, [&]() { return close_received; });
  EXPECT_TRUE(close_received);

  QuicSpdyStream* spdy_stream =
      GetClientSession()->GetOrCreateSpdyDataStream(stream_id);
  EXPECT_TRUE(spdy_stream == nullptr);
}

TEST_P(EndToEndTest, WebTransportSessionCloseWithoutCapsule) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);
  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);

  WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  QuicStreamId stream_id = stream->GetStreamId();
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  // Keep stream open.

  bool close_received = false;
  EXPECT_CALL(visitor, OnSessionClosed(0, ""))
      .WillOnce(Assign(&close_received, true));
  session->CloseSessionWithFinOnlyForTests();
  client_->WaitUntil(2000, [&]() { return close_received; });
  EXPECT_TRUE(close_received);

  QuicSpdyStream* spdy_stream =
      GetClientSession()->GetOrCreateSpdyDataStream(stream_id);
  EXPECT_TRUE(spdy_stream == nullptr);
}

TEST_P(EndToEndTest, WebTransportSessionReceiveClose) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session = CreateWebTransportSession(
      "/session-close", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);
  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);

  WebTransportStream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  QuicStreamId stream_id = stream->GetStreamId();
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "42 test error"));
  EXPECT_TRUE(stream->SendFin());

  // Have some other streams open pending, to ensure they are closed properly.
  stream = session->OpenOutgoingUnidirectionalStream();
  stream = session->OpenOutgoingBidirectionalStream();

  bool close_received = false;
  EXPECT_CALL(visitor, OnSessionClosed(42, "test error"))
      .WillOnce(Assign(&close_received, true));
  client_->WaitUntil(2000, [&]() { return close_received; });
  EXPECT_TRUE(close_received);

  QuicSpdyStream* spdy_stream =
      GetClientSession()->GetOrCreateSpdyDataStream(stream_id);
  EXPECT_TRUE(spdy_stream == nullptr);
}

TEST_P(EndToEndTest, WebTransportSessionReceiveDrain) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session = CreateWebTransportSession(
      "/session-close", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);

  WebTransportStream* stream = session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "DRAIN"));
  EXPECT_TRUE(stream->SendFin());

  bool drain_received = false;
  session->SetOnDraining([&drain_received] { drain_received = true; });
  client_->WaitUntil(2000, [&]() { return drain_received; });
  EXPECT_TRUE(drain_received);
}

TEST_P(EndToEndTest, WebTransportSessionStreamTermination) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/resets", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);

  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);
  EXPECT_CALL(visitor, OnIncomingUnidirectionalStreamAvailable())
      .WillRepeatedly([this, session]() {
        ReadAllIncomingWebTransportUnidirectionalStreams(session);
      });

  WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
  QuicStreamId id1 = stream->GetStreamId();
  ASSERT_TRUE(stream != nullptr);
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  stream->ResetWithUserCode(42);

  // This read fails if the stream is closed in both directions, since that
  // results in stream object being deleted.
  std::string received_data = ReadDataFromWebTransportStreamUntilFin(stream);
  EXPECT_LE(received_data.size(), 4u);

  stream = session->OpenOutgoingBidirectionalStream();
  QuicStreamId id2 = stream->GetStreamId();
  ASSERT_TRUE(stream != nullptr);
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  stream->SendStopSending(100024);

  std::array<std::string, 2> expected_log = {
      absl::StrCat("Received reset for stream ", id1, " with error code 42"),
      absl::StrCat("Received stop sending for stream ", id2,
                   " with error code 100024"),
  };
  client_->WaitUntil(2000, [this, &expected_log]() {
    return received_webtransport_unidirectional_streams_.size() >=
           expected_log.size();
  });
  EXPECT_THAT(received_webtransport_unidirectional_streams_,
              UnorderedElementsAreArray(expected_log));

  // Since we closed the read side, cleanly closing the write side should result
  // in the stream getting deleted.
  ASSERT_TRUE(GetClientSession()->GetOrCreateSpdyDataStream(id2) != nullptr);
  EXPECT_TRUE(stream->SendFin());
  EXPECT_TRUE(client_->WaitUntil(2000, [this, id2]() {
    return GetClientSession()->GetOrCreateSpdyDataStream(id2) == nullptr;
  }));
}

// This test currently does not pass; we need support for
// https://datatracker.ietf.org/doc/draft-seemann-quic-reliable-stream-reset/ in
// order to make this work.
TEST_P(EndToEndTest, DISABLED_WebTransportSessionResetReliability) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  SetPacketLossPercentage(30);

  WebTransportHttp3* session =
      CreateWebTransportSession("/resets", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);

  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);
  EXPECT_CALL(visitor, OnIncomingUnidirectionalStreamAvailable())
      .WillRepeatedly([this, session]() {
        ReadAllIncomingWebTransportUnidirectionalStreams(session);
      });

  std::vector<std::string> expected_log;
  constexpr int kStreamsToCreate = 10;
  for (int i = 0; i < kStreamsToCreate; i++) {
    WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
    QuicStreamId id = stream->GetStreamId();
    ASSERT_TRUE(stream != nullptr);
    stream->ResetWithUserCode(42);

    expected_log.push_back(
        absl::StrCat("Received reset for stream ", id, " with error code 42"));
  }
  client_->WaitUntil(2000, [this, &expected_log]() {
    return received_webtransport_unidirectional_streams_.size() >=
           expected_log.size();
  });
  EXPECT_THAT(received_webtransport_unidirectional_streams_,
              UnorderedElementsAreArray(expected_log));
}

TEST_P(EndToEndTest, WebTransportSession404) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session = CreateWebTransportSession(
      "/does-not-exist", /*wait_for_server_response=*/false);
  ASSERT_TRUE(session != nullptr);
  QuicSpdyStream* connect_stream = client_->latest_created_stream();
  QuicStreamId connect_stream_id = connect_stream->id();

  WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  EXPECT_TRUE(stream->SendFin());

  EXPECT_TRUE(client_->WaitUntil(-1, [this, connect_stream_id]() {
    return GetClientSession()->GetOrCreateSpdyDataStream(connect_stream_id) ==
           nullptr;
  }));
}
TEST_P(EndToEndTest, WebTransportSessionGoaway) {
  enable_web_transport_ = true;
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }

  WebTransportHttp3* session =
      CreateWebTransportSession("/echo", /*wait_for_server_response=*/true);
  ASSERT_TRUE(session != nullptr);

  NiceMock<MockWebTransportSessionVisitor>& visitor =
      SetupWebTransportVisitor(session);
  bool goaway_received = false;
  session->SetOnDraining([&goaway_received] { goaway_received = true; });
  server_thread_->Schedule([server_session = GetServerSession()]() {
    server_session->SendHttp3GoAway(QUIC_PEER_GOING_AWAY,
                                    "server shutting down");
  });
  client_->WaitUntil(2000, [&]() { return goaway_received; });
  EXPECT_TRUE(goaway_received);

  // Ensure that we can still send and receive unidirectional streams after
  // GOAWAY has been processed.
  WebTransportStream* outgoing_stream =
      session->OpenOutgoingUnidirectionalStream();
  ASSERT_TRUE(outgoing_stream != nullptr);
  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*outgoing_stream, "test"));
  EXPECT_TRUE(outgoing_stream->SendFin());

  EXPECT_CALL(visitor, OnIncomingUnidirectionalStreamAvailable())
      .WillRepeatedly([this, session]() {
        ReadAllIncomingWebTransportUnidirectionalStreams(session);
      });
  client_->WaitUntil(2000, [this]() {
    return !received_webtransport_unidirectional_streams_.empty();
  });
  EXPECT_THAT(received_webtransport_unidirectional_streams_,
              testing::ElementsAre("test"));

// TODO(b/283160645): fix this and re-enable the test.
#if 0
  // Ensure that we can still send and receive bidirectional data streams after
  // GOAWAY has been processed.
  WebTransportStream* stream = session->OpenOutgoingBidirectionalStream();
  ASSERT_TRUE(stream != nullptr);

  auto stream_visitor_owned =
      std::make_unique<NiceMock<MockWebTransportStreamVisitor>>();
  MockWebTransportStreamVisitor* stream_visitor = stream_visitor_owned.get();
  stream->SetVisitor(std::move(stream_visitor_owned));

  QUICHE_EXPECT_OK(quiche::WriteIntoStream(*stream, "test"));
  EXPECT_TRUE(stream->SendFin());

  std::string received_data =
      ReadDataFromWebTransportStreamUntilFin(stream, stream_visitor);
  EXPECT_EQ(received_data, "test");
#endif
}

TEST_P(EndToEndTest, InvalidExtendedConnect) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }
  // Missing :path header.
  quiche::HttpHeaderBlock headers;
  headers[":scheme"] = "https";
  headers[":authority"] = "localhost";
  headers[":method"] = "CONNECT";
  headers[":protocol"] = "webtransport";

  client_->SendMessage(headers, "", /*fin=*/false);
  client_->WaitForResponse();
  // An early response should be received.
  CheckResponseHeaders("400");
}

TEST_P(EndToEndTest, RejectExtendedConnect) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  // Disable extended CONNECT.
  memory_cache_backend_.set_enable_extended_connect(false);
  ASSERT_TRUE(Initialize());

  if (!version_.UsesHttp3()) {
    return;
  }
  // This extended CONNECT should be rejected.
  quiche::HttpHeaderBlock headers;
  headers[":scheme"] = "https";
  headers[":authority"] = "localhost";
  headers[":method"] = "CONNECT";
  headers[":path"] = "/echo";
  headers[":protocol"] = "webtransport";

  client_->SendMessage(headers, "", /*fin=*/false);
  client_->WaitForResponse();
  CheckResponseHeaders("400");

  // Vanilla CONNECT should be sent to backend.
  quiche::HttpHeaderBlock headers2;
  headers2[":authority"] = "localhost";
  headers2[":method"] = "CONNECT";

  // Backend not configured/implemented to fully handle CONNECT requests, so
  // expect it to send a 405.
  client_->SendMessage(headers2, "body", /*fin=*/true);
  client_->WaitForResponse();
  CheckResponseHeaders("405");
}

TEST_P(EndToEndTest, RejectInvalidRequestHeader) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  ASSERT_TRUE(Initialize());

  quiche::HttpHeaderBlock headers;
  headers[":scheme"] = "https";
  headers[":authority"] = "localhost";
  headers[":method"] = "GET";
  headers[":path"] = "/echo";
  // transfer-encoding header is not allowed.
  headers["transfer-encoding"] = "chunk";

  client_->SendMessage(headers, "", /*fin=*/false);
  client_->WaitForResponse();
  CheckResponseHeaders("400");
}

TEST_P(EndToEndTest, RejectTransferEncodingResponse) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  ASSERT_TRUE(Initialize());

  // Add a response with transfer-encoding headers.
  HttpHeaderBlock headers;
  headers[":status"] = "200";
  headers["transfer-encoding"] = "gzip";

  HttpHeaderBlock trailers;
  trailers["some-trailing-header"] = "trailing-header-value";

  memory_cache_backend_.AddResponse(server_hostname_, "/eep",
                                    std::move(headers), "", trailers.Clone());

  std::string received_response = client_->SendSynchronousRequest("/eep");
  EXPECT_THAT(client_->stream_error(),
              IsStreamError(QUIC_BAD_APPLICATION_PAYLOAD));
}

TEST_P(EndToEndTest, RejectUpperCaseRequest) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  ASSERT_TRUE(Initialize());

  quiche::HttpHeaderBlock headers;
  headers[":scheme"] = "https";
  headers[":authority"] = "localhost";
  headers[":method"] = "GET";
  headers[":path"] = "/echo";
  headers["UpperCaseHeader"] = "fo
"""


```