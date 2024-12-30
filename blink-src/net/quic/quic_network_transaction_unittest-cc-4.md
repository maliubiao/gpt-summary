Response:
The user wants to understand the functionality of the `quic_network_transaction_unittest.cc` file in the Chromium networking stack. I need to analyze the provided code snippets and extract its purpose, its relation to JavaScript (if any), logical reasoning with hypothetical inputs and outputs, common user or programming errors, debugging information, and a summary of its functionality as part 5 of 13.

**Functionality:**

The code snippets are test cases for `QuicNetworkTransaction`. These tests primarily focus on how the network stack behaves when a QUIC connection encounters errors or specific scenarios, particularly regarding fallback to TCP and management of alternate protocols.

**Relationship to JavaScript:**

While the C++ code itself isn't directly used in JavaScript, the functionality it tests (QUIC protocol and network transactions) affects how web browsers (which run JavaScript) communicate with servers. If QUIC connections fail, the browser might fall back to TCP, impacting the performance and reliability of web applications running JavaScript.

**Logical Reasoning (Hypothetical Input/Output):**

Consider the `ProtocolErrorAfterHandshakeConfirmedThenBroken` test:

*   **Hypothetical Input:** A request is made to a server that advertises QUIC as an alternative protocol. The QUIC handshake completes successfully. The server then sends an invalid data packet.
*   **Logical Steps:**
    1. The client attempts to use QUIC.
    2. Handshake is confirmed.
    3. The client receives a `QUIC_HTTP_STREAM_WRONG_DIRECTION` error due to the invalid server packet.
    4. The QUIC connection is closed.
    5. The `HttpNetworkTransaction` detects the error.
    6. The request is retried over TCP.
    7. The alternate protocol (QUIC) for this server is marked as broken.
*   **Hypothetical Output:** The request succeeds over TCP. Subsequent requests to the same server (at least for a while) will not attempt to use QUIC.

**User/Programming Errors:**

A common error tested here is a server misbehaving or having protocol errors. From a user perspective, this might manifest as a failed connection or a noticeable delay as the browser falls back to TCP. From a programming perspective, incorrect server-side QUIC implementation could lead to these errors.

**Debugging Lineage:**

A user action like clicking a link or typing a URL in the address bar initiates a network request. This request goes through the Chromium network stack. If the server supports QUIC, the stack might attempt a QUIC connection. This test file comes into play when simulating scenarios where the QUIC connection encounters errors. Debugging would involve examining the network logs, checking if QUIC was attempted, if an error occurred, and if fallback to TCP happened correctly.

**Function Summary (Part 5 of 13):**

This part of the test suite focuses on validating the behavior of `QuicNetworkTransaction` when encountering errors on established QUIC connections *after* the handshake has been confirmed. It verifies that in such scenarios:

*   The connection is gracefully closed.
*   The request is retried over TCP (if configured to do so).
*   The availability of QUIC as an alternate protocol for the affected server is correctly managed, often being marked as "broken" to avoid repeated failures.
*   Network isolation keys are respected when marking alternate protocols as broken.
*   The correct fallback mechanisms are triggered when using DNS HTTPS SVCB records with ALPN.
这是 `net/quic/quic_network_transaction_unittest.cc` 文件的一部分，主要功能是 **测试 `HttpNetworkTransaction` 在使用 QUIC 协议时，当连接建立后发生各种错误情况时的行为，并验证其是否能正确回退到 TCP，以及是否正确记录和处理 QUIC 的状态（例如标记为 broken）**。

具体来说，这部分测试主要关注以下场景：

*   **握手确认后发生协议错误并回退**: 测试当 QUIC 握手完成后，由于协议错误（例如收到来自不存在的数据流的数据包）导致连接断开时，`HttpNetworkTransaction` 是否能正确回退到 TCP，并标记该服务器的 QUIC 连接为 broken。
*   **考虑 NetworkAnonymizationKey 的协议错误回退**: 类似于上述测试，但增加了对 `NetworkAnonymizationKey` 的考虑，验证在不同的 `NetworkAnonymizationKey` 下，QUIC 连接被标记为 broken 的行为是否符合预期。
*   **使用 DNS HTTPS SVCB ALPN 的协议错误回退**:  测试在使用 DNS HTTPS SVCB 记录和 ALPN 的情况下，QUIC 连接发生协议错误时，是否能正确回退到 TCP。
*   **握手确认后收到 RST 并回退**: 测试当 QUIC 握手完成后，客户端收到服务器发送的 RST 数据包（例如，指示头部过大）导致连接重置时，`HttpNetworkTransaction` 是否能正确回退到 TCP，并标记该服务器的 QUIC 连接为 broken。
*   **本地 Alt-Svc 损坏时使用远程 Alt-Svc**: 测试当一个 origin 有多个 Alt-Svc 声明（一个本地，一个远程），且本地 Alt-Svc 被标记为 broken 时，请求是否会尝试通过远程的 Alt-Svc 进行 QUIC 连接。
*   **重复标记 broken 的问题**: 验证当多个 alternative 被标记为 broken 时，`ALTERNATE_PROTOCOL_USAGE_BROKEN` 指标是否只记录一次，避免重复记录。
*   **连接池中连接被 RST 后的回退**: 测试当一个使用了连接池的 QUIC 连接在握手完成后被重置时，`HttpNetworkTransaction` 能否正确回退到 TCP，并且后续的请求会使用新的 TCP 连接，而不是再次尝试使用被标记为 broken 的 QUIC 连接。
*   **不支持的 QUIC 版本**: 测试当服务器声明了一个客户端不支持的 QUIC 版本时，客户端是否会拒绝使用该 Alt-Svc。

**与 JavaScript 的关系举例说明:**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它测试的网络栈功能直接影响着 JavaScript 在浏览器中的网络请求行为。

例如，在 `ProtocolErrorAfterHandshakeConfirmedThenBroken` 测试中，当 QUIC 连接发生错误并回退到 TCP 时，如果一个 JavaScript 应用正在发起一个 `fetch` 请求：

1. **假设输入 (JavaScript):**  一个 JavaScript 应用发起一个 `fetch('https://mail.example.org/data.json')` 请求。
2. **内部逻辑 (C++):**  Chromium 网络栈尝试使用 QUIC 连接。握手成功，但之后服务器发送了一个错误的 QUIC 数据包。
3. **内部处理 (C++):**  `HttpNetworkTransaction` 检测到错误，关闭 QUIC 连接，并将该服务器的 QUIC 标记为 broken。然后，它会重新使用 TCP 发起请求。
4. **输出 (JavaScript):**  尽管中间经历了 QUIC 连接的失败和回退，`fetch` 请求最终会成功返回 `data.json` 的内容。JavaScript 代码本身可能不会感知到 QUIC 的失败，除非通过一些底层的网络监控 API。

**逻辑推理的假设输入与输出:**

以 `ResetAfterHandshakeConfirmedThenBroken` 测试为例：

*   **假设输入:**
    *   发起一个 `GET` 请求到 `https://mail.example.org/`。
    *   服务器支持 QUIC，并且客户端配置了使用 QUIC。
    *   QUIC 握手成功完成。
    *   服务器在收到请求后，发送一个 RST 数据包，错误码为 `QUIC_HEADERS_TOO_LARGE`。
*   **输出:**
    *   QUIC 连接被关闭。
    *   `HttpNetworkTransaction` 回退到 TCP 并重新发送请求。
    *   HTTP 响应状态码为 200 OK，包含 `kHttpRespData` 的响应体。
    *   `mail.example.org` 的 QUIC 协议被标记为 broken。

**用户或编程常见的使用错误举例说明:**

在测试的场景中，一个常见的编程错误是 **服务端 QUIC 实现的错误**，例如：

*   服务器错误地发送了来自不存在 stream 的数据，导致客户端收到 `QUIC_HTTP_STREAM_WRONG_DIRECTION` 错误（如 `ProtocolErrorAfterHandshakeConfirmedThenBroken` 测试所示）。
*   服务器对客户端发送的头部大小限制不正确，导致客户端请求被 RST（如 `ResetAfterHandshakeConfirmedThenBroken` 测试所示）。

从用户的角度来看，这些错误可能表现为 **网页加载失败或加载缓慢**，因为浏览器需要回退到 TCP 并重新建立连接。用户通常不会直接看到 QUIC 相关的错误信息。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 `https://mail.example.org/` 并回车，或者点击了指向该链接的超链接。**
2. **浏览器解析 URL，并查询 DNS 获取 `mail.example.org` 的 IP 地址。**
3. **浏览器检查是否已经有可用的到 `mail.example.org` 的 QUIC 连接。** 如果没有，并且服务器声明了支持 QUIC，浏览器会尝试建立 QUIC 连接。
4. **在建立 QUIC 连接的过程中，或者连接建立之后，如果服务器的行为不符合 QUIC 协议规范，例如发送了错误的数据包或者 RST 数据包，就会触发这些测试用例所模拟的错误场景。**
5. **调试线索:** 如果在网络调试工具 (如 Chrome 的 DevTools 的 Network 面板) 中看到连接从 QUIC 切换到 TCP，并且可能伴随着连接错误的信息，那么就可能遇到了这些测试所覆盖的场景。 检查 `net-internals` (chrome://net-internals/#quic) 可以提供更详细的 QUIC 连接信息。

**功能归纳 (第5部分，共13部分):**

这部分测试主要集中在 **验证 `HttpNetworkTransaction` 在 QUIC 连接建立后遇到各种错误时的健壮性和回退机制**。它确保在 QUIC 连接不可用或发生错误时，网络栈能够安全地回退到 TCP，保证网络请求的最终完成，并正确维护 QUIC 的状态，避免未来重复尝试使用失败的 QUIC 连接。这对于保证用户体验和网络连接的稳定性至关重要。

Prompt: 
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共13部分，请归纳一下它的功能

"""
hout racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  ExpectQuicAlternateProtocolMapping();

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, kHttpRespData);
  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

// Verify that with retry_without_alt_svc_on_quic_errors enabled, if a QUIC
// protocol error occurs after the handshake is confirmed, the request
// retried over TCP and the QUIC will be marked as broken.
TEST_P(QuicNetworkTransactionTest,
       ProtocolErrorAfterHandshakeConfirmedThenBroken) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  context_.params()->idle_connection_timeout = base::Seconds(5);

  // The request will initially go out over QUIC.
  MockQuicData quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause

  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  quic_data.AddRead(ASYNC,
                    ConstructServerRstPacket(
                        1, GetNthClientInitiatedBidirectionalStreamId(47),
                        quic::QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndConnectionClosePacket(
          packet_num++, 1, 1, quic::QUIC_HTTP_STREAM_WRONG_DIRECTION,
          quic_error_details, quic::IETF_STOP_SENDING));
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  quic_data.Resume();

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  ExpectQuicAlternateProtocolMapping();

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, kHttpRespData);
  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

// Much like above test, but verifies that NetworkAnonymizationKey is respected.
TEST_P(QuicNetworkTransactionTest,
       ProtocolErrorAfterHandshakeConfirmedThenBrokenWithNetworkIsolationKey) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  context_.params()->idle_connection_timeout = base::Seconds(5);

  // The request will initially go out over QUIC.
  MockQuicData quic_data(version_);
  uint64_t packet_number = 1;
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  quic_data.AddWrite(SYNCHRONOUS,
                     ConstructInitialSettingsPacket(packet_number++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_number++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause

  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  quic_data.AddRead(ASYNC,
                    ConstructServerRstPacket(
                        1, GetNthClientInitiatedBidirectionalStreamId(47),
                        quic::QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  quic::QuicErrorCode quic_error_code = quic::QUIC_INVALID_STREAM_ID;
  quic_error_code = quic::QUIC_HTTP_STREAM_WRONG_DIRECTION;
  quic_data.AddWrite(SYNCHRONOUS,
                     ConstructClientAckAndConnectionClosePacket(
                         packet_number++, 1, 1, quic_error_code,
                         quic_error_details, quic::IETF_STOP_SENDING));
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT,
                                  kNetworkAnonymizationKey1);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT,
                                  kNetworkAnonymizationKey2);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  request_.network_isolation_key = kNetworkIsolationKey1;
  request_.network_anonymization_key = kNetworkAnonymizationKey1;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  quic_data.Resume();

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, kHttpRespData);
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());

  // The alternative service shouldhave been marked as broken under
  // kNetworkIsolationKey1 but not kNetworkIsolationKey2.
  ExpectBrokenAlternateProtocolMapping(kNetworkAnonymizationKey1);
  ExpectQuicAlternateProtocolMapping(kNetworkAnonymizationKey2);

  // Subsequent requests using kNetworkIsolationKey1 should not use QUIC.
  AddHttpDataAndRunRequest();
  // Requests using other NetworkIsolationKeys can still use QUIC.
  request_.network_isolation_key = kNetworkIsolationKey2;
  request_.network_anonymization_key = kNetworkAnonymizationKey2;

  AddQuicDataAndRunRequest();

  // The last two requests should not have changed the alternative service
  // mappings.
  ExpectBrokenAlternateProtocolMapping(kNetworkAnonymizationKey1);
  ExpectQuicAlternateProtocolMapping(kNetworkAnonymizationKey2);
}

TEST_P(QuicNetworkTransactionTest,
       ProtocolErrorAfterHandshakeConfirmedThenBrokenWithUseDnsHttpsSvcbAlpn) {
  session_params_.use_dns_https_svcb_alpn = true;
  context_.params()->idle_connection_timeout = base::Seconds(5);

  // The request will initially go out over QUIC.
  MockQuicData quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause

  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  quic_data.AddRead(ASYNC,
                    ConstructServerRstPacket(
                        1, GetNthClientInitiatedBidirectionalStreamId(47),
                        quic::QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndConnectionClosePacket(
          packet_num++, 1, 1, quic::QUIC_HTTP_STREAM_WRONG_DIRECTION,
          quic_error_details, quic::IETF_STOP_SENDING));
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  HostResolverEndpointResult endpoint_result1;
  endpoint_result1.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoint_result1.metadata.supported_protocol_alpns = {
      quic::QuicVersionLabelToString(quic::CreateQuicVersionLabel(version_))};
  HostResolverEndpointResult endpoint_result2;
  endpoint_result2.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  std::vector<HostResolverEndpointResult> endpoints;
  endpoints.push_back(endpoint_result1);
  endpoints.push_back(endpoint_result2);
  host_resolver_.rules()->AddRule(
      "mail.example.org",
      MockHostResolverBase::RuleResolver::RuleResult(
          std::move(endpoints),
          /*aliases=*/std::set<std::string>{"mail.example.org"}));

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  quic_data.Resume();

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  ExpectQuicAlternateProtocolMapping();

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, kHttpRespData);
  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

// Verify that with retry_without_alt_svc_on_quic_errors enabled, if a QUIC
// request is reset from, then QUIC will be marked as broken and the request
// retried over TCP.
TEST_P(QuicNetworkTransactionTest, ResetAfterHandshakeConfirmedThenBroken) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  // The request will initially go out over QUIC.
  MockQuicData quic_data(version_);
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          priority, GetRequestHeaders("GET", "https", "/"), nullptr));

  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause

  quic_data.AddRead(ASYNC, ConstructServerRstPacket(
                               1, GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_HEADERS_TOO_LARGE));

  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/1,
                       /*smallest_received=*/1)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_HEADERS_TOO_LARGE)
          .Build());

  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  quic_data.Resume();

  // Run the QUIC session to completion.
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  ExpectQuicAlternateProtocolMapping();

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, kHttpRespData);
  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

// Verify that when an origin has two alt-svc advertisements, one local and one
// remote, that when the local is broken the request will go over QUIC via
// the remote Alt-Svc.
// This is a regression test for crbug/825646.
TEST_P(QuicNetworkTransactionTest, RemoteAltSvcWorkingWhileLocalAltSvcBroken) {
  context_.params()->allow_remote_alt_svc = true;

  GURL origin1 = request_.url;  // mail.example.org
  GURL origin2("https://www.example.org/");
  ASSERT_NE(origin1.host(), origin2.host());

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch("www.example.org"));
  ASSERT_TRUE(cert->VerifyNameMatch("mail.example.org"));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();

  // Set up alternative service for |origin1|.
  AlternativeService local_alternative(kProtoQUIC, "mail.example.org", 443);
  AlternativeService remote_alternative(kProtoQUIC, "www.example.org", 443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  AlternativeServiceInfoVector alternative_services;
  alternative_services.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          local_alternative, expiration,
          context_.params()->supported_versions));
  alternative_services.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          remote_alternative, expiration,
          context_.params()->supported_versions));
  http_server_properties_->SetAlternativeServices(url::SchemeHostPort(origin1),
                                                  NetworkAnonymizationKey(),
                                                  alternative_services);

  http_server_properties_->MarkAlternativeServiceBroken(
      local_alternative, NetworkAnonymizationKey());

  SendRequestAndExpectQuicResponse(kQuicRespData);
}

// Verify that when multiple alternatives are broken,
// ALTERNATE_PROTOCOL_USAGE_BROKEN is only logged once.
// This is a regression test for crbug/1024613.
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeOnlyRecordedOnce) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  base::HistogramTester histogram_tester;

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  GURL origin1 = request_.url;  // mail.example.org

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch("mail.example.org"));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  CreateSession();

  // Set up alternative service for |origin1|.
  AlternativeService local_alternative(kProtoQUIC, "mail.example.org", 443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  AlternativeServiceInfoVector alternative_services;
  alternative_services.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          local_alternative, expiration,
          context_.params()->supported_versions));
  alternative_services.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          local_alternative, expiration,
          context_.params()->supported_versions));
  http_server_properties_->SetAlternativeServices(url::SchemeHostPort(origin1),
                                                  NetworkAnonymizationKey(),
                                                  alternative_services);

  http_server_properties_->MarkAlternativeServiceBroken(
      local_alternative, NetworkAnonymizationKey());

  SendRequestAndExpectHttpResponse(kHttpRespData);

  histogram_tester.ExpectBucketCount("Net.AlternateProtocolUsage",
                                     ALTERNATE_PROTOCOL_USAGE_BROKEN, 1);
}

// Verify that with retry_without_alt_svc_on_quic_errors enabled, if a QUIC
// request is reset from, then QUIC will be marked as broken and the request
// retried over TCP. Then, subsequent requests will go over a new TCP
// connection instead of going back to the broken QUIC connection.
// This is a regression tests for crbug/731303.
TEST_P(QuicNetworkTransactionTest,
       ResetPooledAfterHandshakeConfirmedThenBroken) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  context_.params()->allow_remote_alt_svc = true;

  GURL origin1 = request_.url;
  GURL origin2("https://www.example.org/");
  ASSERT_NE(origin1.host(), origin2.host());

  MockQuicData mock_quic_data(version_);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch("www.example.org"));
  ASSERT_TRUE(cert->VerifyNameMatch("mail.example.org"));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  // First request.
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));

  // Second request will go over the pooled QUIC connection, but will be
  // reset by the server.
  QuicTestPacketMaker client_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin2.host(), quic::Perspective::IS_CLIENT, true);
  QuicTestPacketMaker server_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin2.host(), quic::Perspective::IS_SERVER, false);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(1), true,
          GetRequestHeaders("GET", "https", "/", &client_maker2)));
  mock_quic_data.AddRead(
      ASYNC,
      ConstructServerRstPacket(3, GetNthClientInitiatedBidirectionalStreamId(1),
                               quic::QUIC_HEADERS_TOO_LARGE));

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddAckFrame(/*first_received=*/1, /*largest_received=*/3,
                       /*smallest_received=*/2)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(1),
                             quic::QUIC_HEADERS_TOO_LARGE)
          .Build());

  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: www.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // Then the next request to the second origin will be sent over TCP.
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  // Set up alternative service for |origin1|.
  base::Time expiration = base::Time::Now() + base::Days(1);
  AlternativeService alternative1(kProtoQUIC, origin1.host(), 443);
  http_server_properties_->SetQuicAlternativeService(
      url::SchemeHostPort(origin1), NetworkAnonymizationKey(), alternative1,
      expiration, supported_versions_);

  // Set up alternative service for |origin2|.
  AlternativeService alternative2(kProtoQUIC, origin2.host(), 443);
  http_server_properties_->SetQuicAlternativeService(
      url::SchemeHostPort(origin2), NetworkAnonymizationKey(), alternative2,
      expiration, supported_versions_);

  // First request opens connection to `kDestination1`
  // with quic::QuicServerId.host() == origin1.host().
  SendRequestAndExpectQuicResponse(kQuicRespData);

  // Second request pools to existing connection with same destination,
  // because certificate matches, even though quic::QuicServerId is different.
  // After it is reset, it will fail back to TCP and mark QUIC as broken.
  request_.url = origin2;
  SendRequestAndExpectHttpResponse(kHttpRespData);
  EXPECT_FALSE(http_server_properties_->IsAlternativeServiceBroken(
      alternative1, NetworkAnonymizationKey()))
      << alternative1.ToString();
  EXPECT_TRUE(http_server_properties_->IsAlternativeServiceBroken(
      alternative2, NetworkAnonymizationKey()))
      << alternative2.ToString();

  // The third request should use a new TCP connection, not the broken
  // QUIC connection.
  SendRequestAndExpectHttpResponse(kHttpRespData);
}

TEST_P(QuicNetworkTransactionTest,
       DoNotUseAlternativeServiceQuicUnsupportedVersion) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  std::string altsvc_header =
      base::StringPrintf("Alt-Svc: quic=\":443\"; v=\"%u\"\r\n\r\n",
                         version_.transport_version - 1);
  MockRead http_reads[] = {
"""


```