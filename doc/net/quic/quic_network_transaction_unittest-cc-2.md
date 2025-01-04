Response:
The user wants me to analyze a C++ unit test file for Chromium's network stack, specifically `net/quic/quic_network_transaction_unittest.cc`. I need to extract its functionalities, relate them to JavaScript if applicable, provide examples with input and output, list common user errors, describe the user journey to this code, and summarize its purpose. This is part 3 of 13, so I need to focus on the functionalities present in this specific snippet.

**Functionality Breakdown of the Provided Snippet:**

The code snippet mainly contains various test cases for `QuicNetworkTransaction`. Each test case sets up a scenario involving a QUIC connection, simulates network interactions using `MockQuicData`, and then verifies the behavior of the `HttpNetworkTransaction`. The tests cover different aspects of QUIC communication, including:

1. **Handling large response headers:** `TooLargeResponseHeaders` checks if the transaction correctly handles and errors out when response headers exceed the limit.
2. **Handling multiple `Location` headers in redirects:** `RedirectMultipleLocations` verifies the behavior when a server sends multiple `Location` headers in a redirect response.
3. **Forcing QUIC for all origins:** `ForceQuicForAll` tests the scenario where QUIC is forced for all origins.
4. **Handling specific HTTP response codes (e.g., 408):** `408Response` ensures the transaction handles specific HTTP status codes correctly.
5. **Using a QUIC proxy:** `QuicProxy` and `QuicProxyWithCert` test HTTP connections made through a QUIC proxy, including certificate validation for the proxy.
6. **Using alternative services with different hosts:** `AlternativeServicesDifferentHost` checks if the transaction can use QUIC for an alternative service hosted on a different domain.
7. **Ignoring unsupported QUIC versions:** `DoNotUseQuicForUnsupportedVersion` verifies that the transaction doesn't attempt to use QUIC if the advertised version is not supported.
8. **Retrying after a "421 Misdirected Request" error:** `RetryMisdirectedRequest` tests the retry mechanism when a server indicates it cannot handle the request on the current connection.
9. **Handling errors during QUIC connection establishment:** `ForceQuicWithErrorConnecting` checks the behavior when a forced QUIC connection fails to establish.
10. **Not forcing QUIC for HTTPS when specifically configured not to:** `DoNotForceQuicForHttps` tests the scenario where forcing QUIC is disabled for HTTPS.
11. **Using Alternative Services for QUIC:** `UseAlternativeServiceForQuic` tests the basic functionality of using advertised Alternative Services to establish a QUIC connection.
这个 `net/quic/quic_network_transaction_unittest.cc` 文件中的代码片段主要包含以下功能：

1. **测试处理过大的响应头:** `TooLargeResponseHeaders` 测试用例模拟了服务端发送过大响应头的情况，并验证 `HttpNetworkTransaction` 是否能正确处理这种情况，即客户端会因为 `QUIC_HEADERS_TOO_LARGE` 错误而中断连接。

2. **测试处理包含多个 `Location` 头的重定向响应:** `RedirectMultipleLocations` 测试用例模拟了服务端在重定向响应中发送多个 `Location` 头的情况，并验证 `HttpNetworkTransaction` 是否能正确处理（通常这种情况应该被视为错误）。

3. **测试强制所有域名都使用 QUIC:** `ForceQuicForAll` 测试用例设置强制所有域名都使用 QUIC，并验证 `HttpNetworkTransaction` 能否按照预期使用 QUIC 连接。

4. **测试处理特定的 HTTP 响应状态码（例如 408）：** `408Response` 测试用例验证 `HttpNetworkTransaction` 是否能正确处理服务端返回的 "408 Request Timeout" 状态码。

5. **测试通过 QUIC 代理连接:** `QuicProxy` 和 `QuicProxyWithCert` 测试用例模拟了通过 QUIC 代理进行 HTTP 连接的情况，包括测试代理的证书验证。

6. **测试使用不同主机名的备用服务:** `AlternativeServicesDifferentHost` 测试用例验证 `HttpNetworkTransaction` 是否能使用在不同主机名上的备用 QUIC 服务。

7. **测试当备用服务版本不受支持时不使用 QUIC:** `DoNotUseQuicForUnsupportedVersion` 测试用例模拟了服务端通告了一个客户端不支持的 QUIC 版本作为备用服务，并验证 `HttpNetworkTransaction` 不会尝试使用该备用服务。

8. **测试在收到 "421 Misdirected Request" 错误后重试:** `RetryMisdirectedRequest` 测试用例模拟了服务端返回 "421 Misdirected Request" 错误，并验证 `HttpNetworkTransaction` 会回退到 TCP 并重试请求。

9. **测试强制使用 QUIC 连接但连接失败的情况:** `ForceQuicWithErrorConnecting` 测试用例设置强制使用 QUIC，但模拟连接失败的情况，并验证 `HttpNetworkTransaction` 的行为。

10. **测试不强制 HTTPS 使用 QUIC:** `DoNotForceQuicForHttps` 测试用例尝试强制 HTTPS 连接使用 QUIC，但预期这种设置会被忽略，因为 HTTPS 通常有自己的处理机制。

11. **测试使用备用服务进行 QUIC 连接:** `UseAlternativeServiceForQuic` 测试用例验证 `HttpNetworkTransaction` 是否能正确使用服务端通告的备用服务来建立 QUIC 连接。

**与 Javascript 的关系：**

虽然这段代码是 C++，直接与 JavaScript 无关，但它测试的网络栈功能是浏览器处理网络请求的基础。JavaScript 通过浏览器提供的 API (例如 `fetch` 或 `XMLHttpRequest`) 发起网络请求，而 Chromium 的网络栈 (包括 QUIC 的实现) 负责底层传输。

*   **举例说明：** 当一个 JavaScript 应用使用 `fetch("https://mail.example.org/")` 发起一个 HTTPS 请求时，如果 Chromium 的网络栈决定使用 QUIC (例如，因为该域名被强制使用 QUIC，或者服务器通告了 QUIC 备用服务)，那么这段 C++ 测试代码覆盖的场景，例如 `ForceQuicForAll` 或 `UseAlternativeServiceForQuic`，就与这个 JavaScript 请求的处理过程相关。

**逻辑推理 (假设输入与输出):**

*   **测试用例：`TooLargeResponseHeaders`**
    *   **假设输入：** 服务端发送包含多个大型 Header 的 HTTP/3 响应，总大小超过客户端允许的限制。
    *   **预期输出：** `HttpNetworkTransaction::Start()` 返回 `ERR_IO_PENDING`，回调函数返回 `ERR_QUIC_PROTOCOL_ERROR`，表明连接因 `QUIC_HEADERS_TOO_LARGE` 错误而中断。

*   **测试用例：`RedirectMultipleLocations`**
    *   **假设输入：** 服务端发送包含多个 `Location` 头的 HTTP/3 301 重定向响应。
    *   **预期输出：** `HttpNetworkTransaction::Start()` 返回 `ERR_IO_PENDING`，回调函数返回 `ERR_QUIC_PROTOCOL_ERROR`，因为 QUIC 不应该发送多个 `Location` 头。

**用户或编程常见的使用错误：**

*   **配置错误导致强制 QUIC 连接失败:** 用户或开发者可能错误地配置了强制某些域名使用 QUIC，但服务器不支持 QUIC，或者网络环境存在问题导致 QUIC 连接无法建立。 `ForceQuicWithErrorConnecting` 这个测试用例就模拟了这种情况。例如，用户可能在 Chrome 的实验性功能中启用了强制 QUIC 的选项，但目标网站并没有部署 QUIC。这将导致连接错误。

*   **服务端发送了过大的响应头:** 开发者在服务端代码中可能没有考虑到 HTTP/3 的头部压缩限制，导致发送的响应头过大，触发客户端的 `QUIC_HEADERS_TOO_LARGE` 错误。`TooLargeResponseHeaders` 测试用例模拟了这种情况。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 URL，例如 `https://mail.example.org/`。**
2. **浏览器解析 URL 并查找相关的网络配置。** 这可能包括检查是否配置了强制使用 QUIC 的规则 (对应 `ForceQuicForAll`)，或者服务器是否通告了 QUIC 备用服务 (对应 `UseAlternativeServiceForQuic`)。
3. **如果网络栈决定尝试 QUIC 连接，则会创建 `QuicNetworkTransaction` 对象。**
4. **`QuicNetworkTransaction` 会与 QUIC 会话建立连接，并发送请求。**
5. **服务端返回响应。** 如果响应头过大 (对应 `TooLargeResponseHeaders`) 或者服务端返回了特定的错误码 (例如 421，对应 `RetryMisdirectedRequest`)，则会触发相应的测试用例覆盖的逻辑。
6. **在调试过程中，开发者可能会设置断点在 `QuicNetworkTransaction` 的相关代码中，或者查看网络日志 (net-internals) 来追踪 QUIC 连接的建立和数据传输过程。** 测试用例中使用的 `MockQuicData` 模拟了网络数据的发送和接收，可以帮助理解实际网络交互的过程。

**功能归纳 (第 3 部分):**

这部分代码主要集中在 `QuicNetworkTransaction` 的各种错误处理和特定场景处理的测试上，包括处理过大的响应头、处理包含多个 `Location` 头的重定向、处理特定的 HTTP 错误码、以及在强制使用 QUIC 但连接失败时的行为。此外，还测试了通过 QUIC 代理进行连接和使用备用服务的能力，以及当备用服务版本不受支持时的处理。 总之，这部分测试旨在确保 `QuicNetworkTransaction` 在各种异常和特殊情况下都能按照预期工作，保证 QUIC 连接的健壮性和可靠性。

Prompt: 
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共13部分，请归纳一下它的功能

"""
 {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  quiche::HttpHeaderBlock response_headers = GetResponseHeaders("200");
  response_headers["key1"] = std::string(30000, 'A');
  response_headers["key2"] = std::string(30000, 'A');
  response_headers["key3"] = std::string(30000, 'A');
  response_headers["key4"] = std::string(30000, 'A');
  response_headers["key5"] = std::string(30000, 'A');
  response_headers["key6"] = std::string(30000, 'A');
  response_headers["key7"] = std::string(30000, 'A');
  response_headers["key8"] = std::string(30000, 'A');
  quic::QuicStreamId stream_id;
  std::string response_data;
  stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  response_data = server_maker_.QpackEncodeHeaders(
      stream_id, std::move(response_headers), nullptr);

  uint64_t packet_number = 1;
  size_t chunk_size = 1200;
  for (size_t offset = 0; offset < response_data.length();
       offset += chunk_size) {
    size_t len = std::min(chunk_size, response_data.length() - offset);
    mock_quic_data.AddRead(
        ASYNC, ConstructServerDataPacket(
                   packet_number++, stream_id, false,
                   std::string_view(response_data).substr(offset, len)));
  }

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 packet_number, GetNthClientInitiatedBidirectionalStreamId(0),
                 true, ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddWrite(ASYNC, ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddWrite(
      ASYNC, ConstructClientAckPacket(packet_num++, packet_number, 3));

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  SendRequestAndExpectQuicResponse(kQuicRespData);
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

TEST_P(QuicNetworkTransactionTest, TooLargeResponseHeaders) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));

  quiche::HttpHeaderBlock response_headers = GetResponseHeaders("200");
  response_headers["key1"] = std::string(30000, 'A');
  response_headers["key2"] = std::string(30000, 'A');
  response_headers["key3"] = std::string(30000, 'A');
  response_headers["key4"] = std::string(30000, 'A');
  response_headers["key5"] = std::string(30000, 'A');
  response_headers["key6"] = std::string(30000, 'A');
  response_headers["key7"] = std::string(30000, 'A');
  response_headers["key8"] = std::string(30000, 'A');
  response_headers["key9"] = std::string(30000, 'A');

  quic::QuicStreamId stream_id;
  std::string response_data;
  stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  response_data = server_maker_.QpackEncodeHeaders(
      stream_id, std::move(response_headers), nullptr);

  uint64_t packet_number = 1;
  size_t chunk_size = 1200;
  for (size_t offset = 0; offset < response_data.length();
       offset += chunk_size) {
    size_t len = std::min(chunk_size, response_data.length() - offset);
    mock_quic_data.AddRead(
        ASYNC, ConstructServerDataPacket(
                   packet_number++, stream_id, false,
                   std::string_view(response_data).substr(offset, len)));
  }

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 packet_number, GetNthClientInitiatedBidirectionalStreamId(0),
                 true, ConstructDataFrame("hello!")));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddWrite(ASYNC, ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddWrite(
      ASYNC, ConstructClientAckAndRstPacket(
                 packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
                 quic::QUIC_HEADERS_TOO_LARGE, packet_number, 3));

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

TEST_P(QuicNetworkTransactionTest, RedirectMultipleLocations) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));

  quiche::HttpHeaderBlock response_headers = GetResponseHeaders("301");
  response_headers.AppendValueOrAddHeader("location", "https://example1.test");
  response_headers.AppendValueOrAddHeader("location", "https://example2.test");

  const quic::QuicStreamId stream_id =
      GetNthClientInitiatedBidirectionalStreamId(0);
  const std::string response_data = server_maker_.QpackEncodeHeaders(
      stream_id, std::move(response_headers), nullptr);
  ASSERT_LT(response_data.size(), 1200u);
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(/*packet_number=*/1, stream_id,
                                       /*fin=*/true, response_data));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddWrite(
      ASYNC, ConstructClientAckAndRstPacket(
                 packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
                 quic::QUIC_STREAM_CANCELLED,
                 /*largest_received=*/1, /*smallest_received=*/1));

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

TEST_P(QuicNetworkTransactionTest, ForceQuicForAll) {
  context_.params()->origins_to_force_quic_on.insert(HostPortPair());

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);

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
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  SendRequestAndExpectQuicResponse(kQuicRespData);
  EXPECT_TRUE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

// Regression test for https://crbug.com/695225
TEST_P(QuicNetworkTransactionTest, 408Response) {
  context_.params()->origins_to_force_quic_on.insert(HostPortPair());

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);

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
                 GetResponseHeaders("408")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  SendRequestAndExpectQuicResponse(kQuicRespData, "HTTP/1.1 408");
}

TEST_P(QuicNetworkTransactionTest, QuicProxy) {
  DisablePriorityHeader();
  session_params_.enable_quic = true;

  const auto kQuicProxyChain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)});
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {kQuicProxyChain}, TRAFFIC_ANNOTATION_FOR_TESTS);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientPriorityPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          DEFAULT_PRIORITY));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), false,
          DEFAULT_PRIORITY, ConnectRequestHeaders("mail.example.org:80"),
          false));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));

  const char kGetRequest[] =
      "GET / HTTP/1.1\r\n"
      "Host: mail.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndDataPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), 1, 1,
          false, ConstructDataFrame(kGetRequest)));

  const char kGetResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 11\r\n\r\n";
  ASSERT_EQ(strlen(kHttpRespData), 11u);

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 ConstructDataFrame(kGetResponse)));

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 3, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 ConstructDataFrame(kHttpRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 3, 2));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  EXPECT_FALSE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
  // There is no need to set up an alternate protocol job, because
  // no attempt will be made to speak to the proxy over TCP.

  request_.url = GURL("http://mail.example.org/");
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);
  SendRequestAndExpectHttpResponseFromProxy(
      kHttpRespData, kQuicProxyChain.First().GetPort(), kQuicProxyChain);

  // Causes MockSSLClientSocket to disconnect, which causes the underlying QUIC
  // proxy socket to disconnect.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());

  EXPECT_TRUE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

// Regression test for https://crbug.com/492458.  Test that for an HTTP
// connection through a QUIC proxy, the certificate exhibited by the proxy is
// checked against the proxy hostname, not the origin hostname.
TEST_P(QuicNetworkTransactionTest, QuicProxyWithCert) {
  DisablePriorityHeader();
  const std::string kOriginHost = "mail.example.com";
  const std::string kProxyHost = "proxy.example.org";

  session_params_.enable_quic = true;
  const auto kQuicProxyChain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, kProxyHost, 70)});
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {kQuicProxyChain}, TRAFFIC_ANNOTATION_FOR_TESTS);

  client_maker_->set_hostname(kOriginHost);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientPriorityPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          DEFAULT_PRIORITY));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), false,
          DEFAULT_PRIORITY, ConnectRequestHeaders("mail.example.com:80"),
          false));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));

  const char kGetRequest[] =
      "GET / HTTP/1.1\r\n"
      "Host: mail.example.com\r\n"
      "Connection: keep-alive\r\n\r\n";
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndDataPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), 1, 1,
          false, ConstructDataFrame(kGetRequest)));

  const char kGetResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 11\r\n\r\n";
  ASSERT_EQ(strlen(kHttpRespData), 11u);

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 ConstructDataFrame(kGetResponse)));

  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 3, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 ConstructDataFrame(kHttpRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 3, 2));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientDataPacket(packet_num++, GetQpackDecoderStreamId(), false,
                                StreamCancellationQpackDecoderInstruction(0)));

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRstPacket(packet_num++,
                               GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED));

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert.get());
  // This certificate is valid for the proxy, but not for the origin.
  EXPECT_TRUE(cert->VerifyNameMatch(kProxyHost));
  EXPECT_FALSE(cert->VerifyNameMatch(kOriginHost));
  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  request_.url = GURL("http://" + kOriginHost);
  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);
  SendRequestAndExpectHttpResponseFromProxy(
      kHttpRespData, kQuicProxyChain.First().GetPort(), kQuicProxyChain);
}

TEST_P(QuicNetworkTransactionTest, AlternativeServicesDifferentHost) {
  context_.params()->allow_remote_alt_svc = true;
  HostPortPair origin("www.example.org", 443);
  HostPortPair alternative("mail.example.org", 443);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert.get());
  // TODO(rch): the connection should be "to" the origin, so if the cert is
  // valid for the origin but not the alternative, that should work too.
  EXPECT_TRUE(cert->VerifyNameMatch(origin.host()));
  EXPECT_TRUE(cert->VerifyNameMatch(alternative.host()));
  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  client_maker_->set_hostname(origin.host());
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

  request_.url = GURL("https://" + origin.host());
  AddQuicRemoteAlternativeServiceMapping(
      MockCryptoClientStream::CONFIRM_HANDSHAKE, alternative);
  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectQuicResponse(kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, DoNotUseQuicForUnsupportedVersion) {
  quic::ParsedQuicVersion unsupported_version =
      quic::ParsedQuicVersion::Unsupported();
  // Add support for another QUIC version besides |version_|. Also find an
  // unsupported version.
  for (const quic::ParsedQuicVersion& version : quic::AllSupportedVersions()) {
    if (version == version_) {
      continue;
    }
    if (supported_versions_.size() != 2) {
      supported_versions_.push_back(version);
      continue;
    }
    unsupported_version = version;
    break;
  }
  ASSERT_EQ(2u, supported_versions_.size());
  ASSERT_NE(quic::ParsedQuicVersion::Unsupported(), unsupported_version);

  // Set up alternative service to use QUIC with a version that is not
  // supported.
  url::SchemeHostPort server(request_.url);
  AlternativeService alternative_service(kProtoQUIC, kDefaultServerHostName,
                                         443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties_->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      {unsupported_version});

  AlternativeServiceInfoVector alt_svc_info_vector =
      http_server_properties_->GetAlternativeServiceInfos(
          server, NetworkAnonymizationKey());
  EXPECT_EQ(1u, alt_svc_info_vector.size());
  EXPECT_EQ(kProtoQUIC, alt_svc_info_vector[0].alternative_service().protocol);
  EXPECT_EQ(1u, alt_svc_info_vector[0].advertised_versions().size());
  EXPECT_EQ(unsupported_version,
            alt_svc_info_vector[0].advertised_versions()[0]);

  // First request should still be sent via TCP as the QUIC version advertised
  // in the stored AlternativeService is not supported by the client. However,
  // the response from the server will advertise new Alt-Svc with supported
  // versions.
  std::string altsvc_header = GenerateQuicAltSvcHeader(supported_versions_);
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(altsvc_header.c_str()),
      MockRead("\r\n"),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // Second request should be sent via QUIC as a new list of verions supported
  // by the client has been advertised by the server.
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

  CreateSession(supported_versions_);

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);

  // Check alternative service list is updated with new versions.
  alt_svc_info_vector =
      session_->http_server_properties()->GetAlternativeServiceInfos(
          server, NetworkAnonymizationKey());
  VerifyQuicVersionsInAlternativeServices(alt_svc_info_vector,
                                          supported_versions_);
}

// Regression test for https://crbug.com/546991.
// The server might not be able to serve a request on an alternative connection,
// and might send a 421 Misdirected Request response status to indicate this.
// HttpNetworkTransaction should reset the request and retry without using
// alternative services.
TEST_P(QuicNetworkTransactionTest, RetryMisdirectedRequest) {
  // Set up alternative service to use QUIC.
  // Note that |origins_to_force_quic_on| cannot be used in this test, because
  // that overrides |enable_alternative_services|.
  url::SchemeHostPort server(request_.url);
  AlternativeService alternative_service(kProtoQUIC, kDefaultServerHostName,
                                         443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties_->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      supported_versions_);

  // First try: The alternative job uses QUIC and reports an HTTP 421
  // Misdirected Request error.  The main job uses TCP, but |http_data| below is
  // paused at Connect(), so it will never exit the socket pool. This ensures
  // that the alternate job always wins the race and keeps whether the
  // |http_data| exits the socket pool before the main job is aborted
  // deterministic. The first main job gets aborted without the socket pool ever
  // dispensing the socket, making it available for the second try.
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
                 1, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 GetResponseHeaders("421")));
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // Second try: The main job uses TCP, and there is no alternate job. Once the
  // Connect() is unblocked, |http_data| will leave the socket pool, binding to
  // the main job of the second request. It then succeeds over HTTP/1.1.
  // Note that if there was an alternative QUIC Job created for the second try,
  // that would read these data, and would fail with ERR_QUIC_PROTOCOL_ERROR.
  // Therefore this test ensures that no alternative Job is created on retry.
  MockWrite writes[] = {MockWrite(ASYNC, 0, "GET / HTTP/1.1\r\n"),
                        MockWrite(ASYNC, 1, "Host: mail.example.org\r\n"),
                        MockWrite(ASYNC, 2, "Connection: keep-alive\r\n\r\n")};
  MockRead reads[] = {MockRead(ASYNC, 3, "HTTP/1.1 200 OK\r\n\r\n"),
                      MockRead(ASYNC, 4, kHttpRespData),
                      MockRead(ASYNC, OK, 5)};
  SequencedSocketData http_data(MockConnect(ASYNC, ERR_IO_PENDING) /* pause */,
                                reads, writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());

  // Run until |mock_quic_data| has failed and |http_data| has paused.
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  // |mock_quic_data| must have run to completion.
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());

  // Now that the QUIC data has been consumed, unblock |http_data|.
  http_data.socket()->OnConnectComplete(MockConnect());

  // The retry logic must hide the 421 status. The transaction succeeds on
  // |http_data|.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  CheckWasHttpResponse(&trans);
  CheckResponsePort(&trans, 443);
  CheckResponseData(&trans, kHttpRespData);
}

TEST_P(QuicNetworkTransactionTest, ForceQuicWithErrorConnecting) {
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data1(version_);
  mock_quic_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  mock_quic_data1.AddRead(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  client_maker_->Reset();
  MockQuicData mock_quic_data2(version_);
  mock_quic_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(1));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);
  mock_quic_data2.AddRead(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);

  mock_quic_data1.AddSocketDataToFactory(&socket_factory_);
  mock_quic_data2.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  EXPECT_EQ(0U, test_socket_performance_watcher_factory_.watcher_count());
  for (size_t i = 0; i < 2; ++i) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    TestCompletionCallback callback;
    int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
    EXPECT_EQ(1 + i, test_socket_performance_watcher_factory_.watcher_count());

    NetErrorDetails details;
    trans.PopulateNetErrorDetails(&details);
    EXPECT_EQ(quic::QUIC_PACKET_READ_ERROR, details.quic_connection_error);
  }
}

TEST_P(QuicNetworkTransactionTest, DoNotForceQuicForHttps) {
  // Attempt to "force" quic on 443, which will not be honored.
  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("www.google.com:443"));

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  CreateSession();

  SendRequestAndExpectHttpResponse(kHttpRespData);
  EXPECT_EQ(0U, test_socket_performance_watcher_factory_.watcher_count());
}

TEST_P(QuicNetworkTransactionTest, UseAlternativeServiceForQuic) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

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

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, UseIetfAlternativeServiceForQuic) {
  if (vers
"""


```