Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. I need to analyze the code and explain its purpose, especially in relation to JavaScript, logical inferences, user errors, and debugging. Since this is part 13 of 34, I should also summarize the overall function of this specific section.

Here's a breakdown of how I'll approach this:

1. **Identify the core functionality:** Look for the main test scenarios being set up. Keywords like `TEST_P`, `HttpRequestInfo`, `MockWrite`, `MockRead`, and `HttpNetworkTransaction` are strong indicators of the tested features.

2. **Analyze test cases:** Each `TEST_P` block represents a specific testing scenario. I need to understand what each test is verifying.

3. **Relate to JavaScript (if applicable):** Determine if the tested features have direct implications for how web pages (and thus JavaScript) interact with the network. This often involves areas like proxy authentication, connection reuse, and performance timing.

4. **Identify logical inferences:**  Look for test cases that demonstrate how the system behaves based on certain inputs (e.g., providing authentication credentials). I'll create input/output examples.

5. **Highlight potential user errors:** Think about common mistakes users or developers might make that would lead them to encounter the code being tested.

6. **Explain the debugging path:**  Consider the user actions that would trigger the network requests being simulated in the tests.

7. **Summarize the section's function:** Based on the analyzed test cases, provide a concise overview of the purpose of this specific code snippet.
```cpp
ingProxyResolverFactory>(
              &capturing_proxy_resolver),
          nullptr, /*quick_check_enabled=*/true);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const char kMyUrl[] = "https://www.example.org/";
  spdy::SpdySerializedFrame get(spdy_util_.ConstructSpdyGet(kMyUrl, 1, LOWEST));
  spdy::SpdySerializedFrame get_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));

  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame get2(
      spdy_util_.ConstructSpdyGet(kMyUrl, 3, LOWEST));
  spdy::SpdySerializedFrame get_resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));

  MockWrite auth_challenge_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 2,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead auth_challenge_reads[] = {
      MockRead(ASYNC, 1,
               "HTTP/1.1 407 Authentication Required\r\n"
               "Content-Length: 0\r\n"
               "Proxy-Connection: close\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n"),
  };

  MockWrite spdy_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
      CreateMockWrite(get, 2),
      CreateMockWrite(get2, 5),
  };

  MockRead spdy_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      CreateMockRead(get_resp, 3, ASYNC),
      CreateMockRead(body, 4, ASYNC),
      CreateMockRead(get_resp2, 6, ASYNC),
      CreateMockRead(body2, 7, ASYNC),

      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 8),
  };

  MockWrite auth_response_writes_discarded_socket[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead auth_response_reads_discarded_socket[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
  };

  SequencedSocketData auth_challenge1(auth_challenge_reads,
                                      auth_challenge_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&auth_challenge1);

  SequencedSocketData auth_challenge2(auth_challenge_reads,
                                      auth_challenge_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&auth_challenge2);

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SequencedSocketData auth_response_discarded_socket(
      auth_response_reads_discarded_socket,
      auth_response_writes_discarded_socket);
  session_deps_.socket_factory->AddSocketDataProvider(
      &auth_response_discarded_socket);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;
  std::string response_data;

  // Run first request until an auth challenge is observed.
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(kMyUrl);
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(LOWEST, session.get());
  int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  // Run second request until an auth challenge is observed.
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(kMyUrl);
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(LOWEST, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  // Now provide credentials for the first request, and wait for it to complete.
  rv = trans1.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsOk());
  response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);

  // Now provide credentials for the second request. It should notice the
  // existing session, and reuse it.
  rv = trans2.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Test load timing in the case of two HTTPS (non-SPDY) requests through a SPDY
// HTTPS Proxy to different servers.
TEST_P(HttpNetworkTransactionTest,
       HttpsProxySpdyConnectHttpsLoadTimingTwoRequestsTwoServers) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.org/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFrame connect1(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame conn_resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Fetch https://www.example.org/ via HTTP.
  const char kGet1[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get1(
      spdy_util_.ConstructSpdyDataFrame(1, kGet1, false));
  const char kResp1[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 1\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp1(
      spdy_util_.ConstructSpdyDataFrame(1, kResp1, false));
  spdy::SpdySerializedFrame wrapped_body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", false));

  // CONNECT to mail.example.org:443 via SPDY.
  quiche::HttpHeaderBlock connect2_block;
  connect2_block[spdy::kHttp2MethodHeader] = "CONNECT";
  connect2_block[spdy::kHttp2AuthorityHeader] = "mail.example.org:443";
  connect2_block["user-agent"] = "test-ua";
  spdy::SpdySerializedFrame connect2(spdy_util_.ConstructSpdyHeaders(
      3, std::move(connect2_block), HttpProxyConnectJob::kH2QuicTunnelPriority,
      false));

  spdy::SpdySerializedFrame conn_resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));

  // Fetch https://mail.example.org/ via HTTP.
  const char kGet2[] =
      "GET / HTTP/1.1\r\n"
      "Host: mail.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get2(
      spdy_util_.ConstructSpdyDataFrame(3, kGet2, false));
  const char kResp2[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 2\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp2(
      spdy_util_.ConstructSpdyDataFrame(3, kResp2, false));
  spdy::SpdySerializedFrame wrapped_body2(
      spdy_util_.ConstructSpdyDataFrame(3, "22", false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect1, 0),
      CreateMockWrite(wrapped_get1, 2),
      CreateMockWrite(connect2, 5),
      CreateMockWrite(wrapped_get2, 7),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp1, 1, ASYNC),
      CreateMockRead(wrapped_get_resp1, 3, ASYNC),
      CreateMockRead(wrapped_body1, 4, ASYNC),
      CreateMockRead(conn_resp2, 6, ASYNC),
      CreateMockRead(wrapped_get_resp2, 8, ASYNC),
      CreateMockRead(wrapped_body2, 9, ASYNC),
      MockRead(ASYNC, 0, 10),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
  rv = trans.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(1, callback.GetResult(rv));

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  // Even though the SPDY connection is reused, a new tunnelled connection has
  // to be created, so the socket's load timing looks like a fresh connection.
  TestLoadTimingNotReused(load_timing_info2, CONNECT_TIMING_HAS_SSL_TIMES);

  // The requests should have different IDs, since they each are using their own
  // separate stream.
  EXPECT_NE(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  rv = trans2.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(2, callback.GetResult(rv));
}

// Test load timing in the case of two HTTPS (non-SPDY) requests through a SPDY
// HTTPS Proxy to the same server.
TEST_P(HttpNetworkTransactionTest,
       HttpsProxySpdyConnectHttpsLoadTimingTwoRequestsSameServer) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/2");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFrame connect1(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame conn_resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Fetch https://www.example.org/ via HTTP.
  const char kGet1[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get1(
      spdy_util_.ConstructSpdyDataFrame(1, kGet1, false));
  const char kResp1[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 1\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp1(
      spdy_util_.ConstructSpdyDataFrame(1, kResp1, false));
  spdy::SpdySerializedFrame wrapped_body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", false));

  // Fetch https://www.example.org/2 via HTTP.
  const char kGet2[] =
      "GET /2 HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get2(
      spdy_util_.ConstructSpdyDataFrame(1, kGet2, false));
  const char kResp2[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 2\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp2(
      spdy_util_.ConstructSpdyDataFrame(1, kResp2, false));
  spdy::SpdySerializedFrame wrapped_body2(
      spdy_util_.ConstructSpdyDataFrame(1, "22", false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect1, 0),
      CreateMockWrite(wrapped_get1, 2),
      CreateMockWrite(wrapped_get2, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp1, 1, ASYNC),
      CreateMockRead(wrapped_get_resp1, 3, ASYNC),
      CreateMockRead(wrapped_body1, 4, SYNCHRONOUS),
      CreateMockRead(wrapped_get_resp2, 6, ASYNC),
      CreateMockRead(wrapped_body2, 7, SYNCHRONOUS),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
  EXPECT_EQ(1, trans->Read(buf.get(), 256, callback.callback()));
  trans.reset();

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  // The requests should have the same ID.
  EXPECT_EQ(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  EXPECT_EQ(2, trans2->Read(buf.get(), 256, callback.callback()));
}

// Test load timing in the case of of two HTTP requests through a SPDY HTTPS
// Proxy to different servers.
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyLoadTimingTwoHttpRequests) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://mail.example.org/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // http://www.example.org/
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://www.example.org/"));
  spdy::SpdySerializedFrame get1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  spdy::SpdySerializedFrame get_resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", true));
  spdy_util_.UpdateWithStreamDestruction(1);

  // http://mail.example.org/
  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://mail.example.org/"));
  spdy::SpdySerializedFrame get2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(headers2), LOWEST, true));
  spdy::SpdySerializedFrame get_resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(3, "22", true));

  MockWrite spdy_writes[] = {
      CreateMockWrite(get1, 0),
      CreateMockWrite(get2, 3),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(get_resp1, 1, ASYNC),
      CreateMockRead(body1, 2, ASYNC),
      CreateMockRead(get_resp2, 4, ASYNC),
      CreateMockRead(body2, 5, ASYNC),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
  rv = trans->Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(1, callback.GetResult(rv));
  // Delete the first request, so the second one can reuse the socket.
  trans.reset();

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  // The requests should have the same ID.
  EXPECT_EQ(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  rv = trans2.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(2, callback.GetResult(rv));
}

// Test that an HTTP/2 CONNECT through an HTTPS Proxy to a HTTP/2 server and a
// direct (non-proxied) request to the proxy server are not pooled, as that
// would break socket pool isolation.
TEST_P(HttpNetworkTransactionTest, SpdyProxyIsolation1) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));

  CapturingProxyResolver capturing_proxy_resolver;
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<CapturingProxyResolverFactory>(
              &capturing_proxy_resolver),
          nullptr, /*quick_check_enabled=*/true);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SpdyTestUtil spdy_util1(/*use_priority_header=*/true);
  // CONNECT to www.example.org:443 via HTTP/2.
  spdy::SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via HTTP/2.
  const char kMyUrl[] = "https://www.example.org/";
  spdy::SpdySerializedFrame get(spdy_util1.ConstructSpdyGet(kMyUrl, 1, LOWEST));
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(get, 1));
  spdy::SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame get_resp(
      spdy_util1.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(get_resp, 1));
  spdy::SpdySerializedFrame body(spdy_util1.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(body, 1));
  spdy::SpdySerializedFrame window_update_get_resp(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp.size()));
  spdy::SpdySerializedFrame window_update_body(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_body.size()));

  MockWrite spdy_writes1[] = {
      CreateMockWrite(connect, 0),
      CreateMockWrite(wrapped_get, 2),
      CreateMockWrite(window_update_get_resp, 6),
      CreateMockWrite(window_update_body, 7),
  };

  MockRead spdy_reads1[] = {
      CreateMockRead(conn_resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_get_resp, 4, ASYNC),
      CreateMockRead(wrapped_body, 5, ASYNC),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data1(spdy_reads1, spdy_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data1);

  // Fetch https://proxy:70/ via HTTP/2. Needs a new SpdyTestUtil, since it uses
  // a new pipe.
  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame req(
      spdy_util2.ConstructSpdyGet("https://proxy:70/", 1, LOWEST));

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
ingProxyResolverFactory>(
              &capturing_proxy_resolver),
          nullptr, /*quick_check_enabled=*/true);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const char kMyUrl[] = "https://www.example.org/";
  spdy::SpdySerializedFrame get(spdy_util_.ConstructSpdyGet(kMyUrl, 1, LOWEST));
  spdy::SpdySerializedFrame get_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));

  spdy_util_.UpdateWithStreamDestruction(1);
  spdy::SpdySerializedFrame get2(
      spdy_util_.ConstructSpdyGet(kMyUrl, 3, LOWEST));
  spdy::SpdySerializedFrame get_resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));

  MockWrite auth_challenge_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 2,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  MockRead auth_challenge_reads[] = {
      MockRead(ASYNC, 1,
               "HTTP/1.1 407 Authentication Required\r\n"
               "Content-Length: 0\r\n"
               "Proxy-Connection: close\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n"),
  };

  MockWrite spdy_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
      CreateMockWrite(get, 2),
      CreateMockWrite(get2, 5),
  };

  MockRead spdy_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      CreateMockRead(get_resp, 3, ASYNC),
      CreateMockRead(body, 4, ASYNC),
      CreateMockRead(get_resp2, 6, ASYNC),
      CreateMockRead(body2, 7, ASYNC),

      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 8),
  };

  MockWrite auth_response_writes_discarded_socket[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead auth_response_reads_discarded_socket[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
  };

  SequencedSocketData auth_challenge1(auth_challenge_reads,
                                      auth_challenge_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&auth_challenge1);

  SequencedSocketData auth_challenge2(auth_challenge_reads,
                                      auth_challenge_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&auth_challenge2);

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SequencedSocketData auth_response_discarded_socket(
      auth_response_reads_discarded_socket,
      auth_response_writes_discarded_socket);
  session_deps_.socket_factory->AddSocketDataProvider(
      &auth_response_discarded_socket);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;
  std::string response_data;

  // Run first request until an auth challenge is observed.
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(kMyUrl);
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(LOWEST, session.get());
  int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  // Run second request until an auth challenge is observed.
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(kMyUrl);
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(LOWEST, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge));

  // Now provide credentials for the first request, and wait for it to complete.
  rv = trans1.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsOk());
  response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);

  // Now provide credentials for the second request. It should notice the
  // existing session, and reuse it.
  rv = trans2.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Test load timing in the case of two HTTPS (non-SPDY) requests through a SPDY
// HTTPS Proxy to different servers.
TEST_P(HttpNetworkTransactionTest,
       HttpsProxySpdyConnectHttpsLoadTimingTwoRequestsTwoServers) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.org/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFrame connect1(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame conn_resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Fetch https://www.example.org/ via HTTP.
  const char kGet1[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get1(
      spdy_util_.ConstructSpdyDataFrame(1, kGet1, false));
  const char kResp1[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 1\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp1(
      spdy_util_.ConstructSpdyDataFrame(1, kResp1, false));
  spdy::SpdySerializedFrame wrapped_body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", false));

  // CONNECT to mail.example.org:443 via SPDY.
  quiche::HttpHeaderBlock connect2_block;
  connect2_block[spdy::kHttp2MethodHeader] = "CONNECT";
  connect2_block[spdy::kHttp2AuthorityHeader] = "mail.example.org:443";
  connect2_block["user-agent"] = "test-ua";
  spdy::SpdySerializedFrame connect2(spdy_util_.ConstructSpdyHeaders(
      3, std::move(connect2_block), HttpProxyConnectJob::kH2QuicTunnelPriority,
      false));

  spdy::SpdySerializedFrame conn_resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));

  // Fetch https://mail.example.org/ via HTTP.
  const char kGet2[] =
      "GET / HTTP/1.1\r\n"
      "Host: mail.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get2(
      spdy_util_.ConstructSpdyDataFrame(3, kGet2, false));
  const char kResp2[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 2\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp2(
      spdy_util_.ConstructSpdyDataFrame(3, kResp2, false));
  spdy::SpdySerializedFrame wrapped_body2(
      spdy_util_.ConstructSpdyDataFrame(3, "22", false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect1, 0),
      CreateMockWrite(wrapped_get1, 2),
      CreateMockWrite(connect2, 5),
      CreateMockWrite(wrapped_get2, 7),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp1, 1, ASYNC),
      CreateMockRead(wrapped_get_resp1, 3, ASYNC),
      CreateMockRead(wrapped_body1, 4, ASYNC),
      CreateMockRead(conn_resp2, 6, ASYNC),
      CreateMockRead(wrapped_get_resp2, 8, ASYNC),
      CreateMockRead(wrapped_body2, 9, ASYNC),
      MockRead(ASYNC, 0, 10),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
  rv = trans.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(1, callback.GetResult(rv));

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  // Even though the SPDY connection is reused, a new tunnelled connection has
  // to be created, so the socket's load timing looks like a fresh connection.
  TestLoadTimingNotReused(load_timing_info2, CONNECT_TIMING_HAS_SSL_TIMES);

  // The requests should have different IDs, since they each are using their own
  // separate stream.
  EXPECT_NE(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  rv = trans2.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(2, callback.GetResult(rv));
}

// Test load timing in the case of two HTTPS (non-SPDY) requests through a SPDY
// HTTPS Proxy to the same server.
TEST_P(HttpNetworkTransactionTest,
       HttpsProxySpdyConnectHttpsLoadTimingTwoRequestsSameServer) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/2");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // CONNECT to www.example.org:443 via SPDY.
  spdy::SpdySerializedFrame connect1(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  spdy::SpdySerializedFrame conn_resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Fetch https://www.example.org/ via HTTP.
  const char kGet1[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get1(
      spdy_util_.ConstructSpdyDataFrame(1, kGet1, false));
  const char kResp1[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 1\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp1(
      spdy_util_.ConstructSpdyDataFrame(1, kResp1, false));
  spdy::SpdySerializedFrame wrapped_body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", false));

  // Fetch https://www.example.org/2 via HTTP.
  const char kGet2[] =
      "GET /2 HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get2(
      spdy_util_.ConstructSpdyDataFrame(1, kGet2, false));
  const char kResp2[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 2\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp2(
      spdy_util_.ConstructSpdyDataFrame(1, kResp2, false));
  spdy::SpdySerializedFrame wrapped_body2(
      spdy_util_.ConstructSpdyDataFrame(1, "22", false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect1, 0),
      CreateMockWrite(wrapped_get1, 2),
      CreateMockWrite(wrapped_get2, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp1, 1, ASYNC),
      CreateMockRead(wrapped_get_resp1, 3, ASYNC),
      CreateMockRead(wrapped_body1, 4, SYNCHRONOUS),
      CreateMockRead(wrapped_get_resp2, 6, ASYNC),
      CreateMockRead(wrapped_body2, 7, SYNCHRONOUS),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
  EXPECT_EQ(1, trans->Read(buf.get(), 256, callback.callback()));
  trans.reset();

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  // The requests should have the same ID.
  EXPECT_EQ(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  EXPECT_EQ(2, trans2->Read(buf.get(), 256, callback.callback()));
}

// Test load timing in the case of of two HTTP requests through a SPDY HTTPS
// Proxy to different servers.
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyLoadTimingTwoHttpRequests) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.example.org/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://mail.example.org/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // http://www.example.org/
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://www.example.org/"));
  spdy::SpdySerializedFrame get1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  spdy::SpdySerializedFrame get_resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", true));
  spdy_util_.UpdateWithStreamDestruction(1);

  // http://mail.example.org/
  quiche::HttpHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://mail.example.org/"));
  spdy::SpdySerializedFrame get2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(headers2), LOWEST, true));
  spdy::SpdySerializedFrame get_resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(3, "22", true));

  MockWrite spdy_writes[] = {
      CreateMockWrite(get1, 0),
      CreateMockWrite(get2, 3),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(get_resp1, 1, ASYNC),
      CreateMockRead(body1, 2, ASYNC),
      CreateMockRead(get_resp2, 4, ASYNC),
      CreateMockRead(body2, 5, ASYNC),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
  rv = trans->Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(1, callback.GetResult(rv));
  // Delete the first request, so the second one can reuse the socket.
  trans.reset();

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  // The requests should have the same ID.
  EXPECT_EQ(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  rv = trans2.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(2, callback.GetResult(rv));
}

// Test that an HTTP/2 CONNECT through an HTTPS Proxy to a HTTP/2 server and a
// direct (non-proxied) request to the proxy server are not pooled, as that
// would break socket pool isolation.
TEST_P(HttpNetworkTransactionTest, SpdyProxyIsolation1) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));

  CapturingProxyResolver capturing_proxy_resolver;
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<CapturingProxyResolverFactory>(
              &capturing_proxy_resolver),
          nullptr, /*quick_check_enabled=*/true);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SpdyTestUtil spdy_util1(/*use_priority_header=*/true);
  // CONNECT to www.example.org:443 via HTTP/2.
  spdy::SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via HTTP/2.
  const char kMyUrl[] = "https://www.example.org/";
  spdy::SpdySerializedFrame get(spdy_util1.ConstructSpdyGet(kMyUrl, 1, LOWEST));
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(get, 1));
  spdy::SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame get_resp(
      spdy_util1.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(get_resp, 1));
  spdy::SpdySerializedFrame body(spdy_util1.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(body, 1));
  spdy::SpdySerializedFrame window_update_get_resp(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp.size()));
  spdy::SpdySerializedFrame window_update_body(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_body.size()));

  MockWrite spdy_writes1[] = {
      CreateMockWrite(connect, 0),
      CreateMockWrite(wrapped_get, 2),
      CreateMockWrite(window_update_get_resp, 6),
      CreateMockWrite(window_update_body, 7),
  };

  MockRead spdy_reads1[] = {
      CreateMockRead(conn_resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_get_resp, 4, ASYNC),
      CreateMockRead(wrapped_body, 5, ASYNC),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data1(spdy_reads1, spdy_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data1);

  // Fetch https://proxy:70/ via HTTP/2. Needs a new SpdyTestUtil, since it uses
  // a new pipe.
  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame req(
      spdy_util2.ConstructSpdyGet("https://proxy:70/", 1, LOWEST));
  MockWrite spdy_writes2[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util2.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util2.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads2[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(data, 2),
      MockRead(ASYNC, 0, 3),
  };
  SequencedSocketData spdy_data2(spdy_reads2, spdy_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data2);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  ssl3.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback;
  std::string response_data;

  // Make a request using proxy:70 as a HTTP/2 proxy.
  capturing_proxy_resolver.set_proxy_chain(
      ProxyChain(ProxyServer::SCHEME_HTTPS, HostPortPair("proxy", 70)));
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans1(LOWEST, session.get());
  int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Allow the SpdyProxyClientSocket's write callback to complete.
  base::RunLoop().RunUntilIdle();
  // Now allow the read of the response to complete.
  spdy_data1.Resume();
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
  RunUntilIdle();

  // Make a direct HTTP/2 request to proxy:70.
  capturing_proxy_resolver.set_proxy_chain(ProxyChain::Direct());
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://proxy:70/");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(LOWEST, session.get());
  EXPECT_THAT(callback.GetResult(trans2.Start(&request2, callback.callback(),
                                              NetLogWithSource())),
              IsOk());
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
}

// Same as above, but reverse request order, since the code to check for an
// existing session is different for tunnels and direct connections.
TEST_P(HttpNetworkTransactionTest, SpdyProxyIsolation2) {
  // Configure against https proxy server "myproxy:80".
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));

  CapturingProxyResolver capturing_proxy_resolver;
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<CapturingProxyResolverFactory>(
              &capturing_proxy_resolver),
          nullptr, /*quick_check_enabled=*/true);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  // Fetch https://proxy:70/ via HTTP/2.
  SpdyTestUtil spdy_util1(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame req(
      spdy_util1.ConstructSpdyGet("https://proxy:70/", 1, LOWEST));
  MockWrite spdy_writes1[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util1.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util1.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads1[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(data, 2),
      MockRead(ASYNC, 0, 3),
  };
  SequencedSocketData spdy_data1(spdy_reads1, spdy_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data1);

  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  // CONNECT to www.example.org:443 via HTTP/2.
  spdy::SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via HTTP/2.
  const char kMyUrl[] = "https://www.example.org/";
  spdy::SpdySerializedFrame get(spdy_util2.ConstructSpdyGet(kMyUrl, 1, LOWEST));
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructWrappedSpdyFrame(get, 1));
  spdy::SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame get_resp(
      spdy_util2.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(get_resp, 1));
  spdy::SpdySerializedFrame body(spdy_util2.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(body, 1));
  spdy::SpdySerializedFrame window_update_get_resp(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp.size()));
  spdy::SpdySerializedFrame window_update_body(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_body.size()));

  MockWrite spdy_writes2[] = {
      CreateMockWrite(connect, 0),
      CreateMockWrite(wrapped_get, 2),
      CreateMockWrite(window_update_get_resp, 6),
      CreateMockWrite(window_update_body, 7),
  };

  MockRead spdy_reads2[] = {
      CreateMockRead(conn_resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_get_resp, 4, ASYNC),
      CreateMockRead(wrapped_body, 5, ASYNC),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data2(spdy_reads2, spdy_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data2);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  ssl3.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback;
  std::string response_data;

  // Make a direct HTTP/2 request to proxy:70.
  capturing_proxy_resolver.set_proxy_chain(ProxyChain::Direct());
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://proxy:70/");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(LOWEST, session.get());
  EXPECT_THAT(callback.GetResult(trans1.Start(&request1, callback.callback(),
                                              NetLogWithSource())),
              IsOk());
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  RunUntilIdle();

  // Make a request using proxy:70 as a HTTP/2 proxy.
  capturing_proxy_resolver.set_proxy_chain(
      ProxyChain(ProxyServer::SCHEME_HTTPS, HostPortPair("proxy", 70)));
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans2(LOWEST, session.get());
  int rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Allow the SpdyProxyClientSocket's write callback to complete.
  base::RunLoop().RunUntilIdle();
  // Now allow the read of the response to complete.
  spdy_data2.Resume();
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ("HTTP/1.1 200", response2->headers->GetStatusLine());

  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Test the challenge-response-retry sequence through an HTTPS Proxy
TEST_P(HttpNetworkTransactionTest, HttpsProxyAuthRetry) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  // when the no authentication data flag is set.
  request.privacy_mode = PRIVACY_MODE_ENABLED;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTA
```