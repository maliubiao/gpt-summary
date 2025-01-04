Response:
The user wants to understand the functionality of the `spdy_network_transaction_unittest.cc` file in Chromium's network stack.

To achieve this, I need to:

1. **Identify the primary purpose of the file:** Based on the name, it likely contains unit tests for the `SpdyNetworkTransaction` class.
2. **Analyze the test cases:** Go through the provided code snippets to understand what specific functionalities are being tested.
3. **Check for JavaScript relevance:** Determine if any of the tested features interact with JavaScript in a browser context.
4. **Infer logic and provide examples:** For tests involving specific scenarios, deduce the expected input and output.
5. **Identify potential user errors:** Based on the tests, point out common mistakes users or developers might make.
6. **Explain how a user reaches this code:** Describe the sequence of user actions leading to the execution of this code (mainly during development and testing).
7. **Summarize the functionality of this specific part (part 11/12).**

Let's break down the provided code snippets:

* **WebSocket tests:** The code includes tests for WebSocket connections over SPDY, including scenarios with and without proxies, and different HTTP versions for the proxy connection.
* **Zero-RTT tests:**  There are tests related to 0-RTT (Zero Round Trip Time) connection establishment, focusing on whether handshake confirmation is required for concurrent streams.

**High-level plan:**

1. Start with the general function of the file.
2. Detail the WebSocket testing scenarios, highlighting potential JavaScript interactions.
3. Explain the 0-RTT tests and their implications.
4. Address user errors and debugging.
5. Finally, summarize the functionality of this specific part.
这是文件 `net/spdy/spdy_network_transaction_unittest.cc` 的第 11 部分，主要功能是测试 `SpdyNetworkTransaction` 类在各种网络场景下的行为，尤其关注 WebSocket 和 0-RTT (Zero Round Trip Time) 连接。

**主要功能归纳：**

这部分主要集中在以下几个方面的测试：

1. **安全的 WebSocket 连接 (wss://) 通过 HTTP/2 代理：** 测试了通过一个 HTTPS 代理建立安全 WebSocket 连接的场景，包括 HTTP/2 代理和最终服务器都使用 HTTP/2 的情况，以及 HTTP/2 代理但最终服务器使用 HTTP/1.1 的情况。
2. **处理代理协商 HTTP/2 但 WebSocket 不支持的情况：**  测试了当通过 HTTP/2 代理建立 WebSocket 连接时，即使隧道连接意外地协商了 HTTP/2，也能正确处理的情况，并预期会返回 `ERR_NOT_IMPLEMENTED` 错误。
3. **0-RTT 连接 (Zero Round Trip Time) 的行为：**
    *   **不确认握手：**  测试了当使用 0-RTT 并且不需要再次确认 TLS 握手时，请求能否成功完成，并且连接时间是否正确计算（不包含确认握手的时间）。
    *   **并发多个不需要确认握手的 0-RTT 连接：** 测试了同时发起多个不需要确认握手的 0-RTT 请求能否正常工作。
    *   **并发多个需要确认握手的 0-RTT 连接：** 测试了同时发起多个需要再次确认 TLS 握手的 0-RTT 请求能否正常工作。
    *   **并发混合需要和不需要确认握手的 0-RTT 连接：** 测试了同时发起需要和不需要确认握手的 0-RTT 请求混合的情况。
    *   **同步确认握手和同步写入的 0-RTT 连接：** 测试了当 0-RTT 连接需要同步确认握手，并且请求数据需要同步写入时的情况。

**与 JavaScript 的关系：**

WebSocket 是 Web 应用程序中常用的双向通信协议，与 JavaScript 紧密相关。当 JavaScript 代码尝试建立一个 `wss://` 连接时，并且网络层决定使用 SPDY (或 HTTP/2)，就会涉及到这里测试的代码。

**举例说明：**

假设一个网页的 JavaScript 代码尝试连接到一个安全的 WebSocket 服务器：

```javascript
const websocket = new WebSocket('wss://www.example.org/');

websocket.onopen = function(event) {
  console.log('WebSocket connection opened');
  websocket.send('Hello Server!');
};

websocket.onmessage = function(event) {
  console.log('Message from server:', event.data);
};

websocket.onerror = function(error) {
  console.error('WebSocket error:', error);
};

websocket.onclose = function() {
  console.log('WebSocket connection closed');
};
```

如果用户的浏览器配置了 HTTPS 代理 `https://proxy:70`，并且服务器支持 HTTP/2，那么 `SecureWebSocketOverH2OverH2Proxy` 或 `SecureWebSocketOverHttp2Proxy` 等测试覆盖的场景就可能被触发。

**逻辑推理、假设输入与输出：**

以 `SecureWebSocketOverH2OverH2Proxy` 测试为例：

*   **假设输入：**
    *   用户通过浏览器访问一个需要建立 `wss://www.example.org/` 连接的网页。
    *   浏览器配置了 HTTPS 代理 `https://proxy:70`。
    *   代理服务器和目标服务器都支持 HTTP/2。
    *   测试代码中预设的 Mock 数据模拟了代理和目标服务器的 SPDY 帧交互，包括 CONNECT 请求、WebSocket 握手请求和响应等。
*   **预期输出：**
    *   `helper.output().rv` 为 `IsOk()`，表示连接建立成功。
    *   WebSocket 握手成功，可以进行数据传输（虽然测试代码中没有模拟数据传输，但握手是前提）。
    *   相关的网络统计信息被正确记录。

以 `SecureWebSocketOverHttp2ProxyNegotiatesHttp2` 测试为例：

*   **假设输入：**
    *   用户尝试建立一个 `wss://www.example.org/` 连接，通过 HTTPS 代理。
    *   代理使用 HTTP/2。
    *   模拟的服务器行为错误地尝试在 WebSocket 隧道上协商 HTTP/2。
*   **预期输出：**
    *   `helper.output().rv` 为 `IsError(ERR_NOT_IMPLEMENTED)`，因为 WebSocket 隧道不应该协商 HTTP/2。

**用户或编程常见的使用错误：**

*   **WebSocket 连接配置错误：** 用户可能在 JavaScript 中错误地配置了 WebSocket 的 URL，例如使用了 `ws://` 而不是 `wss://`，或者端口号不正确。
*   **代理配置错误：** 用户可能在浏览器或操作系统中配置了错误的代理服务器地址或端口，导致连接失败。
*   **服务器不支持 WebSocket 或指定的协议版本：**  如果服务器没有启用 WebSocket 支持，或者不支持客户端请求的 `Sec-WebSocket-Version`，连接将无法建立。
*   **混合内容错误 (Mixed Content)：** 在 HTTPS 页面中尝试连接到 `ws://` 的 WebSocket 服务器会被浏览器阻止，导致连接失败。
*   **在通过 HTTP/2 代理建立 WebSocket 连接时，错误地期望隧道内部也协商 HTTP/2。**  `SecureWebSocketOverHttp2ProxyNegotiatesHttp2` 测试就覆盖了这种情况，并展示了正确的处理方式是返回错误。

**用户操作如何一步步的到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入一个 URL，该网页包含尝试建立 WebSocket 连接的 JavaScript 代码。**
2. **浏览器解析 URL，并根据配置（例如代理设置）决定如何发起网络请求。**
3. **如果需要通过 HTTPS 代理建立 `wss://` 连接，网络栈会尝试与代理建立连接。**
4. **如果代理支持 HTTP/2，则会建立一个 HTTP/2 连接。**
5. **接下来，网络栈会向代理发送一个 CONNECT 请求，请求建立到目标 WebSocket 服务器的隧道。**
6. **在隧道建立后，会发送 WebSocket 握手请求。**
7. **`spdy_network_transaction_unittest.cc` 中的测试代码模拟了这个过程，用于验证 `SpdyNetworkTransaction` 在处理这些步骤时的正确性。**

**调试线索：**

*   当 WebSocket 连接失败时，开发者可以通过浏览器的开发者工具（Network 面板）查看 WebSocket 连接的握手过程，包括请求头和响应头，以及错误信息。
*   检查浏览器的网络日志 (chrome://net-export/) 可以获取更详细的网络事件信息，包括 SPDY 帧的交互。
*   如果怀疑是代理问题，可以尝试禁用代理进行测试。
*   使用 Wireshark 等网络抓包工具可以捕获网络数据包，分析底层的 TCP 和 TLS 交互。

**总结第 11 部分的功能：**

第 11 部分的 `spdy_network_transaction_unittest.cc` 主要专注于测试 `SpdyNetworkTransaction` 在处理安全的 WebSocket 连接，特别是通过 HTTP/2 代理的情况，以及在 0-RTT 连接场景下的各种行为，包括是否需要确认握手以及并发连接的处理。这些测试确保了 Chromium 网络栈在这些复杂场景下的稳定性和正确性。

Prompt: 
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共12部分，请归纳一下它的功能

"""
,
                      CreateMockRead(websocket_response, 3),
                      MockRead(ASYNC, 0, 4)};

  SequencedSocketData data(reads, writes);

  request_.url = GURL("ws://www.example.org/");
  request_.extra_headers.SetHeader("Connection", "Upgrade");
  request_.extra_headers.SetHeader("Upgrade", "websocket");
  request_.extra_headers.SetHeader("Origin", "http://www.example.org");
  request_.extra_headers.SetHeader("Sec-WebSocket-Version", "13");
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();
  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  EXPECT_TRUE(helper.StartDefaultTest());
  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());

  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, SecureWebSocketOverH2OverH2Proxy) {
  SpdyTestUtil proxy_spdy_util(/*use_priority_header=*/true);
  SpdyTestUtil origin_spdy_util(/*use_priority_header=*/true);

  // Connect request to the origin using HTTP/2.
  spdy::SpdySerializedFrame connect_request(
      proxy_spdy_util.ConstructSpdyConnect(
          nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
          HostPortPair("www.example.org", 443)));

  // Requests through the proxy are wrapped in DATA frames on the proxy's
  // stream ID 1.
  spdy::SpdySerializedFrame req(
      origin_spdy_util.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame wrapped_req(
      proxy_spdy_util.ConstructSpdyDataFrame(1, req, false));
  spdy::SpdySerializedFrame settings_ack(
      origin_spdy_util.ConstructSpdySettingsAck());
  spdy::SpdySerializedFrame wrapped_settings_ack(
      proxy_spdy_util.ConstructSpdyDataFrame(1, settings_ack, false));

  // WebSocket Extended CONNECT using HTTP/2.
  quiche::HttpHeaderBlock websocket_request_headers;
  websocket_request_headers[spdy::kHttp2MethodHeader] = "CONNECT";
  websocket_request_headers[spdy::kHttp2AuthorityHeader] = "www.example.org";
  websocket_request_headers[spdy::kHttp2SchemeHeader] = "https";
  websocket_request_headers[spdy::kHttp2PathHeader] = "/";
  websocket_request_headers[spdy::kHttp2ProtocolHeader] = "websocket";
  websocket_request_headers["origin"] = "http://www.example.org";
  websocket_request_headers["sec-websocket-version"] = "13";
  websocket_request_headers["sec-websocket-extensions"] =
      "permessage-deflate; client_max_window_bits";
  spdy::SpdySerializedFrame websocket_request(
      origin_spdy_util.ConstructSpdyHeaders(
          3, std::move(websocket_request_headers), MEDIUM, false));
  spdy::SpdySerializedFrame wrapped_websocket_request(
      proxy_spdy_util.ConstructSpdyDataFrame(1, websocket_request, false));

  MockWrite writes[] = {CreateMockWrite(connect_request, 0),
                        CreateMockWrite(wrapped_req, 2),
                        CreateMockWrite(wrapped_settings_ack, 4),
                        CreateMockWrite(wrapped_websocket_request, 6)};

  spdy::SpdySerializedFrame connect_response(
      proxy_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));

  spdy::SettingsMap settings;
  settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings_frame(
      origin_spdy_util.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame wrapped_settings_frame(
      proxy_spdy_util.ConstructSpdyDataFrame(1, settings_frame, false));
  spdy::SpdySerializedFrame resp1(
      origin_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_resp1(
      proxy_spdy_util.ConstructSpdyDataFrame(1, resp1, false));
  spdy::SpdySerializedFrame body1(
      origin_spdy_util.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame wrapped_body1(
      proxy_spdy_util.ConstructSpdyDataFrame(1, body1, false));
  spdy::SpdySerializedFrame websocket_response(
      origin_spdy_util.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame wrapped_websocket_response(
      proxy_spdy_util.ConstructSpdyDataFrame(1, websocket_response, false));

  MockRead reads[] = {CreateMockRead(connect_response, 1),
                      CreateMockRead(wrapped_settings_frame, 3),
                      CreateMockRead(wrapped_resp1, 5),
                      CreateMockRead(wrapped_body1, 7),
                      CreateMockRead(wrapped_websocket_response, 8),
                      MockRead(ASYNC, 0, 9)};

  SequencedSocketData data(reads, writes);

  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));

  // |request_| is used for a plain GET request to the origin because we need
  // an existing HTTP/2 connection that has exchanged SETTINGS before we can
  // use WebSockets.
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_,
                                     std::move(session_deps));

  // Add SSL data for the proxy.
  auto proxy_ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  proxy_ssl_provider->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  proxy_ssl_provider->next_protos_expected_in_ssl_config = {kProtoHTTP2,
                                                            kProtoHTTP11};
  proxy_ssl_provider->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data, std::move(proxy_ssl_provider));

  // Add SSL data for the tunneled connection.
  SSLSocketDataProvider origin_ssl_provider(ASYNC, OK);
  origin_ssl_provider.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  origin_ssl_provider.next_protos_expected_in_ssl_config = {kProtoHTTP2,
                                                            kProtoHTTP11};
  // This test uses WebSocket over HTTP/2.
  origin_ssl_provider.next_proto = kProtoHTTP2;
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      &origin_ssl_provider);

  helper.RunPreTestSetup();

  TestCompletionCallback callback1;
  int rv = helper.trans()->Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create HTTP/2 connection.
  base::RunLoop().RunUntilIdle();

  SpdySessionKey key(
      HostPortPair::FromURL(request_.url), PRIVACY_MODE_DISABLED,
      ProxyUriToProxyChain("proxy:70", ProxyServer::SCHEME_HTTPS),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> spdy_session =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ true, log_);
  ASSERT_TRUE(spdy_session);
  EXPECT_TRUE(spdy_session->support_websocket());

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://www.example.org/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(request_.url)
                  .Equals(HostPortPair::FromURL(request2.url)));
  request2.extra_headers.SetHeader("Origin", "http://www.example.org");
  request2.extra_headers.SetHeader("Sec-WebSocket-Version", "13");
  // The following two headers must be removed by WebSocketHttp2HandshakeStream.
  request2.extra_headers.SetHeader("Connection", "Upgrade");
  request2.extra_headers.SetHeader("Upgrade", "websocket");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  trans2.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create WebSocket stream.
  base::RunLoop().RunUntilIdle();

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, SecureWebSocketOverHttp2Proxy) {
  spdy::SpdySerializedFrame connect_request(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  const char kWebSocketRequest[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: Upgrade\r\n"
      "Upgrade: websocket\r\n"
      "Origin: http://www.example.org\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
      "Sec-WebSocket-Extensions: permessage-deflate; "
      "client_max_window_bits\r\n\r\n";
  spdy::SpdySerializedFrame websocket_request(
      spdy_util_.ConstructSpdyDataFrame(1, kWebSocketRequest, false));
  MockWrite writes[] = {CreateMockWrite(connect_request, 0),
                        CreateMockWrite(websocket_request, 2)};

  spdy::SpdySerializedFrame connect_response(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  const char kWebSocketResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
  spdy::SpdySerializedFrame websocket_response(
      spdy_util_.ConstructSpdyDataFrame(1, kWebSocketResponse, false));
  MockRead reads[] = {CreateMockRead(connect_response, 1),
                      CreateMockRead(websocket_response, 3),
                      MockRead(ASYNC, 0, 4)};

  SequencedSocketData data(reads, writes);

  request_.url = GURL("wss://www.example.org/");
  request_.extra_headers.SetHeader("Connection", "Upgrade");
  request_.extra_headers.SetHeader("Upgrade", "websocket");
  request_.extra_headers.SetHeader("Origin", "http://www.example.org");
  request_.extra_headers.SetHeader("Sec-WebSocket-Version", "13");
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();
  helper.AddData(&data);

  // Add SSL data for the tunneled connection.
  SSLSocketDataProvider ssl_provider(ASYNC, OK);
  ssl_provider.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  // A WebSocket request should not advertise HTTP/2 support.
  ssl_provider.next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // This test uses WebSocket over HTTP/1.1.
  ssl_provider.next_proto = kProtoHTTP11;
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      &ssl_provider);

  HttpNetworkTransaction* trans = helper.trans();
  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  EXPECT_TRUE(helper.StartDefaultTest());
  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());
  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(70, response->remote_endpoint.port());
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 101 Switching Protocols",
            response->headers->GetStatusLine());

  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

// Regression test for https://crbug.com/828865.
TEST_P(SpdyNetworkTransactionTest,
       SecureWebSocketOverHttp2ProxyNegotiatesHttp2) {
  spdy::SpdySerializedFrame connect_request(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  MockWrite writes[] = {CreateMockWrite(connect_request, 0)};
  spdy::SpdySerializedFrame connect_response(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {CreateMockRead(connect_response, 1),
                      MockRead(ASYNC, 0, 2)};
  SequencedSocketData data(reads, writes);

  request_.url = GURL("wss://www.example.org/");
  request_.extra_headers.SetHeader("Connection", "Upgrade");
  request_.extra_headers.SetHeader("Upgrade", "websocket");
  request_.extra_headers.SetHeader("Origin", "http://www.example.org");
  request_.extra_headers.SetHeader("Sec-WebSocket-Version", "13");
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();
  helper.AddData(&data);

  // Add SSL data for the tunneled connection.
  SSLSocketDataProvider ssl_provider(ASYNC, OK);
  ssl_provider.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  // A WebSocket request should not advertise HTTP/2 support.
  ssl_provider.next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // The server should not negotiate HTTP/2 over the tunnelled connection,
  // but it must be handled gracefully if it does.
  ssl_provider.next_proto = kProtoHTTP2;
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      &ssl_provider);

  HttpNetworkTransaction* trans = helper.trans();
  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  EXPECT_TRUE(helper.StartDefaultTest());
  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsError(ERR_NOT_IMPLEMENTED));

  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

TEST_P(SpdyNetworkTransactionTest, ZeroRTTDoesntConfirm) {
  static const base::TimeDelta kDelay = base::Milliseconds(10);
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->enable_early_data = true;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  auto ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider->connect_callback = FastForwardByCallback(kDelay);
  // Configure |ssl_provider| to fail if ConfirmHandshake is called. The request
  // should still succeed.
  ssl_provider->confirm = MockConfirm(SYNCHRONOUS, ERR_SSL_PROTOCOL_ERROR);
  ssl_provider->confirm_callback = FastForwardByCallback(kDelay);
  base::TimeTicks start_time = base::TimeTicks::Now();
  helper.RunToCompletionWithSSLData(&data, std::move(ssl_provider));
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // The handshake time should include the time it took to run Connect(), but
  // not ConfirmHandshake().
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(helper.trans()->GetLoadTimingInfo(&load_timing_info));
  EXPECT_EQ(load_timing_info.connect_timing.connect_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_end, start_time + kDelay);
  EXPECT_EQ(load_timing_info.connect_timing.connect_end, start_time + kDelay);
}

// Run multiple concurrent streams that don't require handshake confirmation.
TEST_P(SpdyNetworkTransactionTest, ZeroRTTNoConfirmMultipleStreams) {
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  MockWrite writes1[] = {CreateMockWrite(req1, 0), CreateMockWrite(req2, 3)};

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads1[] = {
      CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data1(reads1, writes1);
  SequencedSocketData data2({}, {});
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->enable_early_data = true;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider1->confirm = MockConfirm(SYNCHRONOUS, ERR_SSL_PROTOCOL_ERROR);
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider2->confirm = MockConfirm(SYNCHRONOUS, ERR_SSL_PROTOCOL_ERROR);

  helper.RunPreTestSetup();
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));
  EXPECT_TRUE(helper.StartDefaultTest());

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(kDefaultUrl);
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;
  int rv = trans2.Start(&request2, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  helper.FinishDefaultTest();
  EXPECT_THAT(callback2.GetResult(ERR_IO_PENDING), IsOk());
  helper.VerifyDataConsumed();

  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Run multiple concurrent streams that require handshake confirmation.
TEST_P(SpdyNetworkTransactionTest, ZeroRTTConfirmMultipleStreams) {
  quiche::HttpHeaderBlock req_block1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, 0));
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(req_block1), LOWEST, true));
  quiche::HttpHeaderBlock req_block2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, 0));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(req_block2), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 3),
  };
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {
      CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data1(reads, writes);
  SequencedSocketData data2({}, {});
  UsePostRequest();
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->enable_early_data = true;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider1->confirm = MockConfirm(ASYNC, OK);
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider2->confirm = MockConfirm(ASYNC, OK);

  helper.RunPreTestSetup();
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request1;
  request1.method = "POST";
  request1.url = GURL(kDefaultUrl);
  request1.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback1;
  int rv = trans1.Start(&request1, callback1.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request2;
  request2.method = "POST";
  request2.url = GURL(kDefaultUrl);
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback1.GetResult(ERR_IO_PENDING), IsOk());
  EXPECT_THAT(callback2.GetResult(ERR_IO_PENDING), IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response1->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response1->headers->GetStatusLine());
  std::string response_data;
  ReadTransaction(&trans1, &response_data);
  EXPECT_EQ("hello!", response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response2->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response2->headers->GetStatusLine());
  ReadTransaction(&trans2, &response_data);
  EXPECT_EQ("hello!", response_data);

  helper.VerifyDataConsumed();
}

// Run multiple concurrent streams, the first require a confirmation and the
// second not requiring confirmation.
TEST_P(SpdyNetworkTransactionTest, ZeroRTTConfirmNoConfirmStreams) {
  // This test orders the writes such that the GET (no confirmation) is written
  // before the POST (confirmation required).
  quiche::HttpHeaderBlock req_block1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(req_block1), LOWEST, true));
  quiche::HttpHeaderBlock req_block2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, 0));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(req_block2), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 3),
  };
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {
      CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data1(reads, writes);
  SequencedSocketData data2({}, {});
  UsePostRequest();
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->enable_early_data = true;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider1->confirm = MockConfirm(ASYNC, OK);
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider2->confirm = MockConfirm(ASYNC, OK);

  helper.RunPreTestSetup();
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  // TODO(crbug.com/41451271): Explicitly verify the ordering of
  // ConfirmHandshake and the second stream.

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request1;
  request1.method = "POST";
  request1.url = GURL(kDefaultUrl);
  request1.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback1;
  int rv = trans1.Start(&request1, callback1.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(kDefaultUrl);
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback1.GetResult(ERR_IO_PENDING), IsOk());
  EXPECT_THAT(callback2.GetResult(ERR_IO_PENDING), IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response1->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response1->headers->GetStatusLine());
  std::string response_data;
  ReadTransaction(&trans1, &response_data);
  EXPECT_EQ("hello!", response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response2->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response2->headers->GetStatusLine());
  ReadTransaction(&trans2, &response_data);
  EXPECT_EQ("hello!", response_data);

  helper.VerifyDataConsumed();
}

// Run multiple concurrent streams, the first not requiring confirmation and the
// second requiring confirmation.
TEST_P(SpdyNetworkTransactionTest, ZeroRTTNoConfirmConfirmStreams) {
  // This test orders the writes such that the GET (no confirmation) is written
  // before the POST (confirmation required).
  quiche::HttpHeaderBlock req_block1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(req_block1), LOWEST, true));
  quiche::HttpHeaderBlock req_block2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, 0));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(req_block2), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 3),
  };
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {
      CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data1(reads, writes);
  SequencedSocketData data2({}, {});
  UsePostRequest();
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->enable_early_data = true;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider1->confirm = MockConfirm(ASYNC, OK);
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider2->confirm = MockConfirm(ASYNC, OK);

  helper.RunPreTestSetup();
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  // TODO(crbug.com/41451271): Explicitly verify the ordering of
  // ConfirmHandshake and the second stream.

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(kDefaultUrl);
  request1.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback1;
  int rv = trans1.Start(&request1, callback1.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request2;
  request2.method = "POST";
  request2.url = GURL(kDefaultUrl);
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback1.GetResult(ERR_IO_PENDING), IsOk());
  EXPECT_THAT(callback2.GetResult(ERR_IO_PENDING), IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response1->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response1->headers->GetStatusLine());
  std::string response_data;
  ReadTransaction(&trans1, &response_data);
  EXPECT_EQ("hello!", response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response2->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response2->headers->GetStatusLine());
  ReadTransaction(&trans2, &response_data);
  EXPECT_EQ("hello!", response_data);

  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, ZeroRTTSyncConfirmSyncWrite) {
  static const base::TimeDelta kDelay = base::Milliseconds(10);
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kUploadDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0, SYNCHRONOUS),
      CreateMockWrite(body, 1),  // POST upload frame
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  UsePostRequest();
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->enable_early_data = true;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  auto ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  ssl_provider->connect_callback = FastForwardByCallback(kDelay);
  ssl_provider->confirm = MockConfirm(SYNCHRONOUS, OK);
  ssl_provider->confirm_callback = FastForwardByCallback(kDelay);
  base::TimeTicks start_time = base::TimeTicks::Now();
  helper.RunToCompletionWithSSLData(&data, std::move(ssl_provider));
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // The handshake time should include the time it took to run Connect(), but
  // not ConfirmHandshake(). If ConfirmHandshake() returns synchronously, we
  // assume the connection did not negotiate 0-RTT or the handshake was already
  // confirmed.
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(helper.trans()->GetLoadTimingInfo(&load_timing_info));
  EXPECT_EQ(load_timing_info.connect_timing.connect_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_start, start_time);
  EXPECT_EQ(load_timing_info.connect_timing.ssl_end, start_time + kDelay);
  EXPECT_EQ(load_timing_info.connect_timing.connect_end, start_time + kDelay);
}

TEST_P(SpdyNetworkTransactionTest, ZeroRTTSyncConfirmAsyncWrite
"""


```