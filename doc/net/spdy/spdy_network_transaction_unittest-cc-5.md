Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/spdy/spdy_network_transaction_unittest.cc`. I need to identify the key features being tested in this section of the unit tests. The tests seem to focus on the `SpdyNetworkTransaction`'s behavior in various scenarios, especially related to server-initiated events like `GOAWAY` frames and handling the `HTTP_1_1_REQUIRED` error code for protocol fallback. I also need to consider if these tests relate to JavaScript, involve logical deductions, highlight potential user errors, and how a user might reach this code.

**Plan:**

1. **Identify Core Functionality:** Analyze each test case to determine the primary scenario being validated.
2. **JavaScript Relation:**  Consider if any of the tested scenarios directly impact JavaScript execution in a browser (e.g., through network requests initiated by scripts).
3. **Logical Deductions:** Examine tests that involve conditional behavior based on server responses or connection states and formulate input/output examples.
4. **User/Programming Errors:**  Look for tests that address misconfigurations or incorrect usage patterns that a developer or user might encounter.
5. **User Operation Flow:** Trace how a user's actions in a browser might trigger the network stack behavior being tested.
6. **Summarize Functionality:**  Condense the identified functionalities into a concise overview.
```cpp
  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect only HTTP/1.1 protocol in SSLConfig.
  ssl_provider1->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP11};
  // Force HTTP/1.1.
  ssl_provider1->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  // A third socket is needed for the tunnelled connection to the next proxy.
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider2.get());

  // A fourth socket is needed for the tunnelled connection to the origin.
  auto ssl_provider3 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider3.get());

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  url::SchemeHostPort proxy_scheme_host_port = kProxyServer1.GetSchemeHostPort();
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  EXPECT_FALSE(response->was_alpn_negotiated);
  EXPECT_TRUE(request_.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
  EXPECT_EQ(70, response->remote_endpoint.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

// Same as HTTP11RequiredNestedProxyFirstProxyRetry above except for nested
// proxies where HTTP_1_1_REQUIRED is received from the second proxy in the
// chain.
TEST_P(SpdyNetworkTransactionTest, HTTP11RequiredNestedProxySecondProxyRetry) {
  request_.method = "GET";

  // Configure a nested proxy.
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS)));
  // Do not force SPDY so that third socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));

  // First socket: Successful HTTP/2 CONNECT to the first proxy.
  spdy::SpdySerializedFrame connect1_req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));
  spdy::SpdySerializedFrame connect1_resp(
      spdy_util_.ConstructSpdyConnectReply(nullptr, 0, 1));
  MockWrite writes0[] = {CreateMockWrite(connect1_req, 0)};
  MockRead reads0[] = {CreateMockRead(connect1_resp, 1)};
  SequencedSocketData data0(reads0, writes0);

  auto ssl_provider0 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider0->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  // Force SPDY.
  ssl_provider0->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

  // Second socket: HTTP/2 CONNECT to the second proxy rejected with
  // HTTP_1_1_REQUIRED.
  spdy::SpdySerializedFrame connect2_req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  MockWrite writes1[] = {CreateMockWrite(connect2_req, 0)};
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
  MockRead reads1[] = {CreateMockRead(rst, 1)};
  SequencedSocketData data1(reads1, writes1);

  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider1->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  // Force SPDY.
  ssl_provider1->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  // Third socket: retry using HTTP/1.1.
  MockWrite writes2[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 2,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead reads2[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 3,
               "HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
  };
  SequencedSocketData data2(reads2, writes2);

  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect only HTTP/1.1 protocol in SSLConfig.
  ssl_provider2->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP11};
  // Force HTTP/1.1.
  ssl_provider2->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  // A fourth socket is needed for the tunnelled connection to the origin.
  auto ssl_provider3 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider3.get());

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  url::SchemeHostPort proxy_scheme_host_port = kProxyServer2.GetSchemeHostPort();
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  EXPECT_FALSE(response->was_alpn_negotiated);
  EXPECT_TRUE(request_.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
  EXPECT_EQ(71, response->remote_endpoint.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

}  // namespace test
}  // namespace net
```

### 功能归纳

这个C++源代码文件 `net/spdy/spdy_network_transaction_unittest.cc` 的第 6 部分主要包含了以下功能的单元测试：

1. **处理连接关闭时的活跃流:** 测试当连接在有活跃的 SPDY 流时关闭，`SpdyNetworkTransaction` 是否能正确处理，并返回 `ERR_CONNECTION_CLOSED` 错误。
2. **立即收到 GOAWAY 帧:** 测试当客户端在连接建立后立即收到 `GOAWAY` 帧时，`SpdyNetworkTransaction` 是否能正确处理，并返回 `ERR_CONNECTION_CLOSED` 错误。
3. **接收到 HTTP_1_1_REQUIRED 错误后的重试机制:**
    *   **重试到原始服务器:** 测试当 SPDY 连接被服务器拒绝并返回 `HTTP_1_1_REQUIRED` 错误码时，`SpdyNetworkTransaction` 能否回退到 HTTP/1.1 并重新发起请求。同时测试了 `NetworkAnonymizationKey` 对此重试机制的影响。
    *   **重试到代理服务器:** 测试当通过代理连接时，如果代理服务器返回 `HTTP_1_1_REQUIRED` 错误码，`SpdyNetworkTransaction` 能否回退到 HTTP/1.1 并重新发起请求，包括直接连接的代理和嵌套代理的情况。同样测试了 `NetworkAnonymizationKey` 的影响。
4. **嵌套代理场景下的 HTTP_1_1_REQUIRED 重试:** 专门测试了在多层代理场景下，当第一层或第二层代理返回 `HTTP_1_1_REQUIRED` 错误码时，客户端能否正确回退并使用 HTTP/1.1 连接。

### 与 JavaScript 的关系

这些测试覆盖了网络协议的底层实现，与 JavaScript 的直接功能没有直接关联。但是，JavaScript 通过浏览器提供的 API（例如 `fetch` 或 `XMLHttpRequest`）发起网络请求，最终会走到这些网络栈代码。

**举例说明:**

如果一个网页中的 JavaScript 代码使用 `fetch` API 请求一个 HTTPS 资源，而服务器由于某些原因（例如配置变更）开始发送 `HTTP_1_1_REQUIRED` 错误码来拒绝 HTTP/2 连接。这里的测试确保了 Chromium 的网络栈能够正确处理这种情况，回退到 HTTP/1.1 并完成请求，从而保证 JavaScript 代码的网络请求最终能够成功，即使底层协议发生了变化。

### 逻辑推理的假设输入与输出

**场景：接收到 HTTP_1_1_REQUIRED 错误后的重试机制 (不使用代理)**

**假设输入:**

*   客户端发起一个使用 HTTP/2 的 HTTPS 请求到 `https://www.example.org`.
*   服务器拒绝 HTTP/2 连接，并返回一个包含 `RST_STREAM` 帧，错误码为 `HTTP_1_1_REQUIRED`。

**输出:**

*   `SpdyNetworkTransaction` 捕获到 `HTTP_1_1_REQUIRED` 错误。
*   `SpdyNetworkTransaction` 放弃当前的 SPDY 连接。
*   `SpdyNetworkTransaction` 创建一个新的 HTTP/1.1 连接到 `https://www.example.org`.
*   `SpdyNetworkTransaction` 使用 HTTP/1.1 重新发送相同的请求。
*   服务器使用 HTTP/1.1 响应请求。

### 用户或编程常见的使用错误

**场景：不理解 HTTP_1_1_REQUIRED 的含义并强制使用 HTTP/2**

**使用错误:** 开发者可能错误地配置或者假设服务器总是支持 HTTP/2，并且没有处理服务器返回 `HTTP_1_1_REQUIRED` 错误的情况。

**后果:** 如果 Chromium 的网络栈没有实现正确的重试逻辑，用户的请求将会失败。这里的测试确保了即使开发者没有显式处理这种情况，浏览器也能通过协议降级来保证用户的访问。

### 用户操作如何一步步到达这里 (调试线索)

1. **用户在浏览器地址栏输入一个 HTTPS URL (例如 `https://www.example.org`) 并回车。**
2. **浏览器解析 URL 并确定需要建立网络连接。**
3. **浏览器的网络栈尝试与服务器建立连接，并进行 ALPN 协商，尝试使用 HTTP/2。**
4. **如果服务器配置改变，不再支持 HTTP/2，它可能会发送一个 `RST_STREAM` 帧，错误码为 `HTTP_1_1_REQUIRED`。**
5. **`SpdyNetworkTransaction` 接收到这个错误码。**
6. **这里的单元测试 (例如 `HTTP11RequiredRetry`) 就是模拟了这个过程，确保 `SpdyNetworkTransaction` 能正确处理并回退到 HTTP/1.1。**

### 功能归纳

总而言之，这部分单元测试主要关注 `SpdyNetworkTransaction` 在遇到服务器主动关闭连接 (`GOAWAY`) 以及服务器要求使用 HTTP/1.1 (`HTTP_1_1_REQUIRED`) 时的健壮性和正确性，包括在有代理和嵌套代理的复杂网络环境下的处理逻辑，并验证了 `NetworkAnonymizationKey` 在这些场景下的作用。

Prompt: 
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共12部分，请归纳一下它的功能

"""
ack;

  const int kReadSize = 256;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kReadSize);
  rv = trans->Read(buf.get(), kReadSize, read_callback.callback());
  ASSERT_EQ(ERR_IO_PENDING, rv) << "Unexpected read: " << rv;

  // Complete the read now, which causes buffering to start.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  // Destroy the transaction, causing the stream to get cancelled
  // and orphaning the buffered IO task.
  helper.ResetTrans();

  // Flush the MessageLoop; this will cause the buffered IO task
  // to run for the final time.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();
}

// Request should fail upon receiving a GOAWAY frame
// with Last-Stream-ID lower than the stream id corresponding to the request
// and with error code other than NO_ERROR.
TEST_P(SpdyNetworkTransactionTest, FailOnGoAway) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame go_away(
      spdy_util_.ConstructSpdyGoAway(0, spdy::ERROR_CODE_INTERNAL_ERROR, ""));
  MockRead reads[] = {
      CreateMockRead(go_away, 1),
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Request should be retried on a new connection upon receiving a GOAWAY frame
// with Last-Stream-ID lower than the stream id corresponding to the request
// and with error code NO_ERROR.
TEST_P(SpdyNetworkTransactionTest, RetryOnGoAway) {
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  // First connection.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes1[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame go_away(
      spdy_util_.ConstructSpdyGoAway(0, spdy::ERROR_CODE_NO_ERROR, ""));
  MockRead reads1[] = {CreateMockRead(go_away, 1)};
  SequencedSocketData data1(reads1, writes1);
  helper.AddData(&data1);

  // Second connection.
  MockWrite writes2[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp, 1), CreateMockRead(body, 2),
                       MockRead(ASYNC, 0, 3)};
  SequencedSocketData data2(reads2, writes2);
  helper.AddData(&data2);

  helper.RunPreTestSetup();
  helper.RunDefaultTest();

  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());

  helper.VerifyDataConsumed();
}

// A server can gracefully shut down by sending a GOAWAY frame
// with maximum last-stream-id value.
// Transactions started before receiving such a GOAWAY frame should succeed,
// but SpdySession should be unavailable for new streams.
TEST_P(SpdyNetworkTransactionTest, GracefulGoaway) {
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet("https://www.example.org/foo", 3, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req1, 0), CreateMockWrite(req2, 3)};

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0x7fffffff, spdy::ERROR_CODE_NO_ERROR, "Graceful shutdown."));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                      CreateMockRead(goaway, 4), CreateMockRead(resp2, 5),
                      CreateMockRead(body2, 6)};

  // Run first transaction.
  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.RunDefaultTest();

  // Verify first response.
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // GOAWAY frame has not yet been received, SpdySession should be available.
  SpdySessionPool* spdy_session_pool = helper.session()->spdy_session_pool();
  SpdySessionKey key(host_port_pair_, PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  EXPECT_TRUE(
      spdy_session_pool->HasAvailableSession(key, /* is_websocket = */ false));
  base::WeakPtr<SpdySession> spdy_session =
      spdy_session_pool->FindAvailableSession(
          key, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, log_);
  EXPECT_TRUE(spdy_session);

  // Start second transaction.
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  TestCompletionCallback callback;
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/foo");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  int rv = trans2.Start(&request2, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Verify second response.
  const HttpResponseInfo* response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response->connection_info);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
  EXPECT_EQ(443, response->remote_endpoint.port());
  std::string response_data;
  rv = ReadTransaction(&trans2, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  // Graceful GOAWAY was received, SpdySession should be unavailable.
  EXPECT_FALSE(
      spdy_session_pool->HasAvailableSession(key, /* is_websocket = */ false));
  spdy_session = spdy_session_pool->FindAvailableSession(
      key, /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ false, log_);
  EXPECT_FALSE(spdy_session);

  helper.VerifyDataConsumed();
}

// Verify that an active stream with ID not exceeding the Last-Stream-ID field
// of the incoming GOAWAY frame can receive data both before and after the
// GOAWAY frame.
TEST_P(SpdyNetworkTransactionTest, ActiveStreamWhileGoingAway) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      /* last_good_stream_id = */ 1, spdy::ERROR_CODE_NO_ERROR,
      "Graceful shutdown."));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, "foo", false));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(1, "bar", true));
  MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(body1, 2),
                      CreateMockRead(goaway, 3), CreateMockRead(body2, 4)};

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.AddData(&data);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, helper.session());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), log_);
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->was_fetched_via_spdy);

  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("foobar", response_data);
}

TEST_P(SpdyNetworkTransactionTest, CloseWithActiveStream) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(SYNCHRONOUS, 0, 2)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));

  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsError(ERR_CONNECTION_CLOSED));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, GoAwayImmediately) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {CreateMockRead(goaway, 0, SYNCHRONOUS)};
  SequencedSocketData data(reads, base::span<MockWrite>());

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));

  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsError(ERR_CONNECTION_CLOSED));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  EXPECT_FALSE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();
}

// Retry with HTTP/1.1 when receiving HTTP_1_1_REQUIRED.  Note that no actual
// protocol negotiation happens, instead this test forces protocols for both
// sockets.
TEST_P(SpdyNetworkTransactionTest, HTTP11RequiredRetry) {
  request_.method = "GET";
  // Do not force SPDY so that second socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  // First socket: HTTP/2 request rejected with HTTP_1_1_REQUIRED.
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  MockWrite writes0[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
  MockRead reads0[] = {CreateMockRead(rst, 1)};
  SequencedSocketData data0(reads0, writes0);

  auto ssl_provider0 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider0->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  // Force SPDY.
  ssl_provider0->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

  // Second socket: falling back to HTTP/1.1.
  MockWrite writes1[] = {MockWrite(ASYNC, 0,
                                   "GET / HTTP/1.1\r\n"
                                   "Host: www.example.org\r\n"
                                   "Connection: keep-alive\r\n\r\n")};
  MockRead reads1[] = {MockRead(ASYNC, 1,
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Length: 5\r\n\r\n"
                                "hello")};
  SequencedSocketData data1(reads1, writes1);

  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect only HTTP/1.1 protocol in SSLConfig.
  ssl_provider1->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP11};
  // Force HTTP/1.1.
  ssl_provider1->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(
      url::SchemeHostPort(request_.url), NetworkAnonymizationKey()));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(
      url::SchemeHostPort(request_.url), NetworkAnonymizationKey()));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_TRUE(request_.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
  EXPECT_EQ(443, response->remote_endpoint.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

// Same as above test, but checks that NetworkAnonymizationKeys are respected.
TEST_P(SpdyNetworkTransactionTest,
       HTTP11RequiredRetryWithNetworkAnonymizationKey) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);

  const NetworkIsolationKey kNetworkIsolationKeys[] = {
      kNetworkIsolationKey1, kNetworkIsolationKey2, NetworkIsolationKey()};

  base::test::ScopedFeatureList feature_list;
  // Need to partition connections by NetworkAnonymizationKey for
  // SpdySessionKeys to include NetworkAnonymizationKeys.
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Do not force SPDY so that sockets can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  // For each server, set up and tear down a QUIC session cleanly, and check
  // that stats have been added to HttpServerProperties using the correct
  // NetworkAnonymizationKey.
  for (size_t i = 0; i < std::size(kNetworkIsolationKeys); ++i) {
    SCOPED_TRACE(i);

    request_.method = "GET";
    request_.network_isolation_key = kNetworkIsolationKeys[i];
    request_.network_anonymization_key =
        net::NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
            kNetworkIsolationKeys[i]);

    // First socket: HTTP/2 request rejected with HTTP_1_1_REQUIRED.
    SpdyTestUtil spdy_util(/*use_priority_header=*/true);
    quiche::HttpHeaderBlock headers(
        spdy_util.ConstructGetHeaderBlock(kDefaultUrl));
    spdy::SpdySerializedFrame req(
        spdy_util.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
    MockWrite writes0[] = {CreateMockWrite(req, 0)};
    spdy::SpdySerializedFrame rst(spdy_util.ConstructSpdyRstStream(
        1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
    MockRead reads0[] = {CreateMockRead(rst, 1)};
    SequencedSocketData data0(reads0, writes0);

    auto ssl_provider0 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    // Expect HTTP/2 protocols too in SSLConfig.
    ssl_provider0->next_protos_expected_in_ssl_config =
        NextProtoVector{kProtoHTTP2, kProtoHTTP11};
    // Force SPDY.
    ssl_provider0->next_proto = kProtoHTTP2;
    helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

    // Second socket: falling back to HTTP/1.1.
    MockWrite writes1[] = {MockWrite(ASYNC, 0,
                                     "GET / HTTP/1.1\r\n"
                                     "Host: www.example.org\r\n"
                                     "Connection: keep-alive\r\n\r\n")};
    MockRead reads1[] = {MockRead(ASYNC, 1,
                                  "HTTP/1.1 200 OK\r\n"
                                  "Content-Length: 5\r\n\r\n"
                                  "hello")};
    SequencedSocketData data1(reads1, writes1);

    auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    // Expect only HTTP/1.1 protocol in SSLConfig.
    ssl_provider1->next_protos_expected_in_ssl_config =
        NextProtoVector{kProtoHTTP11};
    // Force HTTP/1.1.
    ssl_provider1->next_proto = kProtoHTTP11;
    helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

    HttpServerProperties* http_server_properties =
        helper.session()->spdy_session_pool()->http_server_properties();
    EXPECT_FALSE(http_server_properties->RequiresHTTP11(
        url::SchemeHostPort(request_.url),
        net::NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
            kNetworkIsolationKeys[i])));

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, helper.session());

    TestCompletionCallback callback;
    int rv = trans.Start(&request_, callback.callback(), log_);
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_FALSE(response->was_fetched_via_spdy);
    EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
    EXPECT_TRUE(response->was_alpn_negotiated);
    EXPECT_TRUE(request_.url.SchemeIs("https"));
    EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
    EXPECT_EQ(443, response->remote_endpoint.port());
    std::string response_data;
    ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
    EXPECT_EQ("hello", response_data);

    for (size_t j = 0; j < std::size(kNetworkIsolationKeys); ++j) {
      // NetworkAnonymizationKeys up to kNetworkIsolationKeys[j] are known
      // to require HTTP/1.1, others are not.
      if (j <= i) {
        EXPECT_TRUE(http_server_properties->RequiresHTTP11(
            url::SchemeHostPort(request_.url),
            net::NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
                kNetworkIsolationKeys[j])));
      } else {
        EXPECT_FALSE(http_server_properties->RequiresHTTP11(
            url::SchemeHostPort(request_.url),
            net::NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
                kNetworkIsolationKeys[j])));
      }
    }
  }
}

// Retry with HTTP/1.1 to the proxy when receiving HTTP_1_1_REQUIRED from the
// proxy.  Note that no actual protocol negotiation happens, instead this test
// forces protocols for both sockets.
TEST_P(SpdyNetworkTransactionTest, HTTP11RequiredProxyRetry) {
  request_.method = "GET";
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  // Do not force SPDY so that second socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));

  // First socket: HTTP/2 CONNECT rejected with HTTP_1_1_REQUIRED.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  MockWrite writes0[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
  MockRead reads0[] = {CreateMockRead(rst, 1)};
  SequencedSocketData data0(reads0, writes0);

  auto ssl_provider0 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider0->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  // Force SPDY.
  ssl_provider0->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

  // Second socket: retry using HTTP/1.1.
  MockWrite writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 2,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead reads1[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 3,
               "HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
  };
  SequencedSocketData data1(reads1, writes1);

  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect only HTTP/1.1 protocol in SSLConfig.
  ssl_provider1->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP11};
  // Force HTTP/1.1.
  ssl_provider1->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  // A third socket is needed for the tunnelled connection.
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider2.get());

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  url::SchemeHostPort proxy_scheme_host_port(url::kHttpsScheme, "myproxy", 70);
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(
      proxy_scheme_host_port, NetworkAnonymizationKey()));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  EXPECT_FALSE(response->was_alpn_negotiated);
  EXPECT_TRUE(request_.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
  EXPECT_EQ(70, response->remote_endpoint.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

// Same as above, but also test that NetworkAnonymizationKeys are respected.
TEST_P(SpdyNetworkTransactionTest,
       HTTP11RequiredProxyRetryWithNetworkAnonymizationKey) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);

  const NetworkAnonymizationKey kNetworkAnonymizationKeys[] = {
      kNetworkAnonymizationKey1, kNetworkAnonymizationKey2,
      NetworkAnonymizationKey()};
  const NetworkIsolationKey kNetworkIsolationKeys[] = {
      kNetworkIsolationKey1, kNetworkIsolationKey2, NetworkIsolationKey()};

  base::test::ScopedFeatureList feature_list;
  // Need to partition connections by NetworkAnonymizationKey for
  // SpdySessionKeys to include NetworkAnonymizationKeys.
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  request_.method = "GET";
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  // Do not force SPDY so that second socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();

  for (size_t i = 0; i < std::size(kNetworkAnonymizationKeys); ++i) {
    // First socket: HTTP/2 CONNECT rejected with HTTP_1_1_REQUIRED.

    SpdyTestUtil spdy_util(/*use_priority_header=*/true);
    spdy::SpdySerializedFrame req(spdy_util.ConstructSpdyConnect(
        nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair("www.example.org", 443)));
    MockWrite writes0[] = {CreateMockWrite(req, 0)};
    spdy::SpdySerializedFrame rst(spdy_util.ConstructSpdyRstStream(
        1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
    MockRead reads0[] = {CreateMockRead(rst, 1)};
    SequencedSocketData data0(reads0, writes0);

    auto ssl_provider0 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    // Expect HTTP/2 protocols too in SSLConfig.
    ssl_provider0->next_protos_expected_in_ssl_config =
        NextProtoVector{kProtoHTTP2, kProtoHTTP11};
    // Force SPDY.
    ssl_provider0->next_proto = kProtoHTTP2;
    helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

    // Second socket: retry using HTTP/1.1.
    MockWrite writes1[] = {
        MockWrite(ASYNC, 0,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),
        MockWrite(ASYNC, 2,
                  "GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    MockRead reads1[] = {
        MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
        MockRead(ASYNC, 3,
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Length: 5\r\n\r\n"
                 "hello"),
    };
    SequencedSocketData data1(reads1, writes1);

    auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    // Expect only HTTP/1.1 protocol in SSLConfig.
    ssl_provider1->next_protos_expected_in_ssl_config =
        NextProtoVector{kProtoHTTP11};
    // Force HTTP/1.1.
    ssl_provider1->next_proto = kProtoHTTP11;
    helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

    // A third socket is needed for the tunnelled connection.
    auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
        ssl_provider2.get());

    HttpServerProperties* http_server_properties =
        helper.session()->spdy_session_pool()->http_server_properties();
    url::SchemeHostPort proxy_scheme_host_port(url::kHttpsScheme, "myproxy",
                                               70);
    EXPECT_FALSE(http_server_properties->RequiresHTTP11(
        proxy_scheme_host_port, kNetworkAnonymizationKeys[i]));

    request_.network_isolation_key = kNetworkIsolationKeys[i];
    request_.network_anonymization_key = kNetworkAnonymizationKeys[i];
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, helper.session());
    TestCompletionCallback callback;
    int rv = trans.Start(&request_, callback.callback(), log_);
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    helper.VerifyDataConsumed();

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_FALSE(response->was_fetched_via_spdy);
    EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
    EXPECT_FALSE(response->was_alpn_negotiated);
    EXPECT_TRUE(request_.url.SchemeIs("https"));
    EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
    EXPECT_EQ(70, response->remote_endpoint.port());
    std::string response_data;
    ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
    EXPECT_EQ("hello", response_data);

    for (size_t j = 0; j < std::size(kNetworkAnonymizationKeys); ++j) {
      // The proxy SchemeHostPort URL should not be marked as requiring HTTP/1.1
      // using the current NetworkAnonymizationKey, and the state of others
      // should be unchanged since the last loop iteration..
      if (j <= i) {
        EXPECT_TRUE(http_server_properties->RequiresHTTP11(
            proxy_scheme_host_port, kNetworkAnonymizationKeys[j]));
      } else {
        EXPECT_FALSE(http_server_properties->RequiresHTTP11(
            proxy_scheme_host_port, kNetworkAnonymizationKeys[j]));
      }
    }

    // The destination SchemeHostPort should not be marked as requiring
    // HTTP/1.1.
    EXPECT_FALSE(http_server_properties->RequiresHTTP11(
        url::SchemeHostPort(request_.url), kNetworkAnonymizationKeys[i]));
  }
}

// Same as HTTP11RequiredProxyRetry above except for nested proxies where
// HTTP_1_1_REQUIRED is received from the first proxy in the chain.
TEST_P(SpdyNetworkTransactionTest, HTTP11RequiredNestedProxyFirstProxyRetry) {
  request_.method = "GET";

  // Configure a nested proxy.
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS)));
  // Do not force SPDY so that second socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));

  // First socket: HTTP/2 CONNECT rejected with HTTP_1_1_REQUIRED.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));
  MockWrite writes0[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
  MockRead reads0[] = {CreateMockRead(rst, 1)};
  SequencedSocketData data0(reads0, writes0);

  auto ssl_provider0 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider0->next_protos_expected_in_ssl_config =
      NextProtoVector{kProtoHTTP2, kProtoHTTP11};
  // Force SPDY.
  ssl_provider0->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

  // Second socket: retry using HTTP/1.1.
  MockWrite writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT proxy2.test:71 HTTP/1.1\r\n"
                "Host: proxy2.test:71\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 2,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 4,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead reads1[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 3, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 5,
               "HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
  };
  SequencedSocketData data1(reads1, writes1);

  auto ssl_provider1 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Expect only HTTP/1.1 protocol in SS
"""


```