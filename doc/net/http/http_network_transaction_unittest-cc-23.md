Response:
The user wants a summary of the functionality of the provided C++ code snippet from `http_network_transaction_unittest.cc`. They are particularly interested in:

1. **General functionality:** What does this code do?
2. **Relationship to JavaScript:** Is there any interaction with JavaScript?
3. **Logic and assumptions:** Are there any logical deductions, and what are the assumed inputs and outputs?
4. **Common user errors:** What are some frequent mistakes users or programmers might make when interacting with this code?
5. **Debugging context:** How would a user end up at this point in the code during debugging?
6. **Summary of functionality (part 24/34):**  A concise overview of the code's purpose within the larger file.

**Thinking Process:**

1. **Identify the core class under test:** The code heavily uses `HttpNetworkTransaction`. This is the primary class being tested.
2. **Recognize the test framework:** The presence of `TEST_P` indicates this is part of a parameterized test suite, likely using Google Test.
3. **Analyze individual test cases:** Go through each `TEST_P` block and understand its specific goal.
    *   `CancelBeforeStart`: Tests cancellation before the transaction starts.
    *   `CancelAfterHeaders`: Tests cancellation after receiving headers, focusing on proper socket draining.
    *   `ProxyGet`: Tests a simple HTTP GET request through a proxy.
    *   `ProxyTunnelGet`: Tests an HTTPS GET request through a proxy (using a tunnel).
    *   `ProxyTunnelGetIPv6`: Similar to `ProxyTunnelGet`, but for IPv6 addresses.
    *   `ProxyTunnelGetHangup`: Tests the scenario where the proxy server hangs up during tunnel establishment.
    *   `PreconnectWithExistingSpdySession`: Tests pre-connection when a SPDY session already exists.
    *   `SSLWriteCertError`: Tests handling of SSL certificate errors during writing.
    *   `ClientAuthCertCache_Direct_NoFalseStart`: Tests client certificate caching when no proxy is involved and TLS False Start is disabled.
    *   `ClientAuthCertCache_Direct_FalseStart`: Similar to the above, but with TLS False Start enabled.
    *   `ClientAuthCertCache_Proxy_Fail`: Tests client certificate caching when using an HTTPS proxy and the client certificate is rejected.
4. **Look for common patterns:**  Notice the use of `MockRead` and `MockWrite` to simulate network interactions, `StaticSocketDataProvider` and `SSLSocketDataProvider` to provide mock data, and `TestCompletionCallback` for asynchronous testing.
5. **Address specific user questions:**
    *   **JavaScript relationship:**  Network requests initiated by JavaScript in a browser would eventually utilize the networking stack, including `HttpNetworkTransaction`.
    *   **Logic and assumptions:**  Each test makes assumptions about the network behavior (e.g., specific headers, response codes). The input is typically an `HttpRequestInfo` object, and the output is the result of the network transaction (success or failure, response data).
    *   **User errors:**  Common errors involve incorrect proxy settings, invalid certificates, or issues with handling asynchronous operations.
    *   **Debugging:**  Developers might land in this code while debugging network issues, particularly those related to proxying, SSL/TLS, or connection management.
6. **Synthesize the summary:** Combine the individual test case functionalities into a concise overview. Emphasize the focus on testing various network scenarios for `HttpNetworkTransaction`.
7. **Consider the "part 24/34" context:**  This snippet represents a portion of a larger test file. The tests likely cover a wide range of functionalities for `HttpNetworkTransaction`.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
```cpp
>());
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  trans.reset();  // Cancel the transaction here.

  base::RunLoop().RunUntilIdle();
}

// Test that if a transaction is cancelled after receiving the headers, the
// stream is drained properly and added back to the socket pool. The main
// purpose of this test is to make sure that an HttpStreamParser can be read
// from after the HttpNetworkTransaction and the objects it owns have been
// deleted.
// See http://crbug.com/368418
TEST_P(HttpNetworkTransactionTest, CancelAfterHeaders) {
  MockRead data_reads[] = {
      MockRead(ASYNC, "HTTP/1.1 200 OK\r\n"),
      MockRead(ASYNC, "Content-Length: 2\r\n"),
      MockRead(ASYNC, "Connection: Keep-Alive\r\n\r\n"), MockRead(ASYNC, "1"),
      // 2 async reads are necessary to trigger a ReadResponseBody call after
      // the HttpNetworkTransaction has been deleted.
      MockRead(ASYNC, "2"),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING),  // Should never read this.
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
    TestCompletionCallback callback;

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    callback.WaitForResult();

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

    // The transaction and HttpRequestInfo are deleted.
  }

  // Let the HttpResponseBodyDrainer drain the socket.
  base::RunLoop().RunUntilIdle();

  // Socket should now be idle, waiting to be reused.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test a basic GET request through a proxy.
TEST_P(HttpNetworkTransactionTest, ProxyGet) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  ConnectedHandler connected_handler;
  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(response->WasFetchedViaProxy());
  EXPECT_FALSE(response->proxy_chain.is_for_ip_protection());
  EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                       HostPortPair::FromString("myproxy:70")),
            response->proxy_chain);
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);
}

// Test a basic HTTPS GET request through a proxy.
TEST_P(HttpNetworkTransactionTest, ProxyTunnelGet) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  ConnectedHandler connected_handler;
  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->WasFetchedViaProxy());
  EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                       HostPortPair::FromString("myproxy:70")),
            response->proxy_chain);

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test a basic HTTPS GET request through a proxy, connecting to an IPv6
// literal host.
TEST_P(HttpNetworkTransactionTest, ProxyTunnelGetIPv6) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://[::2]:443/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT [::2]:443 HTTP/1.1\r\n"
                "Host: [::2]:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: [::2]\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->WasFetchedViaProxy());
  EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                       HostPortPair::FromString("myproxy:70")),
            response->proxy_chain);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test a basic HTTPS GET request through a proxy, but the server hangs up
// while establishing the tunnel.
TEST_P(HttpNetworkTransactionTest, ProxyTunnelGetHangup) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead(ASYNC, 0, 0),  // EOF
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_EMPTY_RESPONSE));
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);
}

// Test for crbug.com/55424.
TEST_P(HttpNetworkTransactionTest, PreconnectWithExistingSpdySession) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(data, 2),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Set up an initial SpdySession in the pool to reuse.
  HostPortPair host_port_pair("www.example.org", 443);
  SpdySessionKey key(host_port_pair, PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> spdy_session =
      CreateSpdySession(session.get(), key, NetLogWithSource());

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Given a net error, cause that error to be returned from the first Write()
// call and verify that the HttpNetworkTransaction fails with that error.
void HttpNetworkTransactionTestBase::CheckErrorIsPassedBack(int error,
                                                            IoMode mode) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  SSLSocketDataProvider ssl_data(mode, OK);
  MockWrite data_writes[] = {
      MockWrite(mode, error),
  };
  StaticSocketDataProvider data(base::span<MockRead>(), data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  ASSERT_EQ(error, rv);
}

TEST_P(HttpNetworkTransactionTest, SSLWriteCertError) {
  // Just check a grab bag of cert errors.
  static const int kErrors[] = {
      ERR_CERT_COMMON_NAME_INVALID,
      ERR_CERT_AUTHORITY_INVALID,
      ERR_CERT_DATE_INVALID,
  };
  for (int error : kErrors) {
    CheckErrorIsPassedBack(error, ASYNC);
    CheckErrorIsPassedBack(error, SYNCHRONOUS);
  }
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) No proxy is involved.
//  2) TLS False Start is disabled.
//  3) The initial TLS handshake requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate.
TEST_P(HttpNetworkTransactionTest, ClientAuthCertCache_Direct_NoFalseStart) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request->host_and_port = HostPortPair("www.example.com", 443);

  // [ssl_]data1 contains the data for the first SSL handshake. When a
  // CertificateRequest is received for the first time, the handshake will
  // be aborted to allow the caller to provide a certificate.
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider data1;
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // [ssl_]data2 contains the data for the second SSL handshake. When TLS
  // False Start is not being used, the result of the SSL handshake will be
  // returned as part of the SSLClientSocket::Connect() call. This test
  // matches the result of a server sending a handshake_failure alert,
  // rather than a Finished message, because it requires a client
  // certificate and none was supplied.
  SSLSocketDataProvider ssl_data2(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data2.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  StaticSocketDataProvider data2;
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // [ssl_]data3 contains the data for the third SSL handshake. When a
  // connection to a server fails during an SSL handshake,
  // HttpNetworkTransaction will attempt to fallback with legacy cryptography
  // enabled on some errors. This is transparent to the caller
  // of the HttpNetworkTransaction. Because this test failure is due to
  // requiring a client certificate, this fallback handshake should also
  // fail.
  SSLSocketDataProvider ssl_data3(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data3.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);
  StaticSocketDataProvider data3;
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Begin the SSL handshake with the peer. This consumes ssl_data1.
  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Complete the SSL handshake, which should abort due to requiring a
  // client certificate.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Indicate that no certificate should be supplied. From the perspective
  // of SSLClientCertCache, NULL is just as meaningful as a real
  // certificate, so this is the same as supply a
  // legitimate-but-unacceptable certificate.
  rv = trans.RestartWithCertificate(nullptr, nullptr, callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Ensure the certificate was added to the client auth cache before
  // allowing the connection to continue restarting.
  scoped_refptr<X509Certificate> client_cert;
  scoped_refptr<SSLPrivateKey> client_private_key;
  ASSERT_TRUE(session->ssl_client_context()->GetClientCertificate(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
  ASSERT_FALSE(client_cert);

  // Restart the handshake. This will consume ssl_data2, which fails, and
  // then consume ssl_data3 and ssl_data4, both of which should also fail.
  // The result code is checked against what ssl_data4 should return.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));

  // Ensure that the client certificate is removed from the cache on a
  // handshake failure.
  ASSERT_FALSE(session->ssl_client_context()->GetClientCertificate(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) No proxy is involved.
//  2) TLS False Start is enabled.
//  3) The initial TLS handshake requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate.
TEST_P(HttpNetworkTransactionTest, ClientAuthCertCache_Direct_FalseStart) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request->host_and_port = HostPortPair("www.example.com", 443);

  // When TLS False Start is used, SSLClientSocket::Connect() calls will
  // return successfully after reading up to the peer's Certificate message.
  // This is to allow the caller to call SSLClientSocket::Write(), which can
  // enqueue application data to be sent in the same packet as the
  // ChangeCipherSpec and Finished messages.
  // The actual handshake will be finished when SSLClientSocket::Read() is
  // called, which expects to process the peer's ChangeCipherSpec and
  // Finished messages. If there was an error negotiating with the peer,
  // such as due to the peer requiring a client certificate when none was
  // supplied, the alert sent by the peer won't be processed until Read() is
  // called.

  // Like the non-False Start case, when a client certificate is requested by
  // the peer, the handshake is aborted during the Connect() call.
  // [ssl_]data1 represents the initial SSL handshake with the peer.
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider data1;
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // When a client certificate is supplied, Connect() will not be aborted
  // when the peer requests the certificate. Instead, the handshake will
  // artificially succeed, allowing the caller to write the HTTP request to
  // the socket. The handshake messages are not processed until Read() is
  // called, which then detects that the handshake was aborted, due to the
  // peer sending a handshake_failure because it requires a client
  // certificate.
  SSLSocketDataProvider ssl_data2(ASYNC, OK);
  ssl_data2.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  MockRead data2_reads[] = {
      MockRead(ASYNC /* async */, ERR_SSL_PROTOCOL_ERROR),
  };
  StaticSocketDataProvider data2(data2_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // As described in ClientAuthCertCache_Direct_NoFalseStart, [ssl_]data3 is
  // the data for the SSL handshake once the TLSv1.1 connection falls back to
  // TLSv1. It has the same behaviour as [ssl_]data2.
  SSLSocketDataProvider ssl_data3(ASYNC, OK);
  ssl_data3.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);
  StaticSocketDataProvider data3(data2_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  // [ssl_]data4 is the data for the SSL handshake once the TLSv1 connection
  // falls back to SSLv3. It has the same behaviour as [
### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第24部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
>());
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(),
                        NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  trans.reset();  // Cancel the transaction here.

  base::RunLoop().RunUntilIdle();
}

// Test that if a transaction is cancelled after receiving the headers, the
// stream is drained properly and added back to the socket pool.  The main
// purpose of this test is to make sure that an HttpStreamParser can be read
// from after the HttpNetworkTransaction and the objects it owns have been
// deleted.
// See http://crbug.com/368418
TEST_P(HttpNetworkTransactionTest, CancelAfterHeaders) {
  MockRead data_reads[] = {
      MockRead(ASYNC, "HTTP/1.1 200 OK\r\n"),
      MockRead(ASYNC, "Content-Length: 2\r\n"),
      MockRead(ASYNC, "Connection: Keep-Alive\r\n\r\n"), MockRead(ASYNC, "1"),
      // 2 async reads are necessary to trigger a ReadResponseBody call after
      // the HttpNetworkTransaction has been deleted.
      MockRead(ASYNC, "2"),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING),  // Should never read this.
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
    TestCompletionCallback callback;

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    callback.WaitForResult();

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

    // The transaction and HttpRequestInfo are deleted.
  }

  // Let the HttpResponseBodyDrainer drain the socket.
  base::RunLoop().RunUntilIdle();

  // Socket should now be idle, waiting to be reused.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test a basic GET request through a proxy.
TEST_P(HttpNetworkTransactionTest, ProxyGet) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  ConnectedHandler connected_handler;
  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(response->WasFetchedViaProxy());
  EXPECT_FALSE(response->proxy_chain.is_for_ip_protection());
  EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                       HostPortPair::FromString("myproxy:70")),
            response->proxy_chain);
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);
}

// Test a basic HTTPS GET request through a proxy.
TEST_P(HttpNetworkTransactionTest, ProxyTunnelGet) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  ConnectedHandler connected_handler;
  trans.SetConnectedCallback(connected_handler.Callback());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->WasFetchedViaProxy());
  EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                       HostPortPair::FromString("myproxy:70")),
            response->proxy_chain);

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kProxied;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 70);
  expected_transport.negotiated_protocol = kProtoUnknown;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test a basic HTTPS GET request through a proxy, connecting to an IPv6
// literal host.
TEST_P(HttpNetworkTransactionTest, ProxyTunnelGetIPv6) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://[::2]:443/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT [::2]:443 HTTP/1.1\r\n"
                "Host: [::2]:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: [::2]\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->WasFetchedViaProxy());
  EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                       HostPortPair::FromString("myproxy:70")),
            response->proxy_chain);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test a basic HTTPS GET request through a proxy, but the server hangs up
// while establishing the tunnel.
TEST_P(HttpNetworkTransactionTest, ProxyTunnelGetHangup) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  RecordingNetLogObserver net_log_observer;
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead(ASYNC, 0, 0),  // EOF
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_EMPTY_RESPONSE));
  auto entries = net_log_observer.GetEntries();
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);
}

// Test for crbug.com/55424.
TEST_P(HttpNetworkTransactionTest, PreconnectWithExistingSpdySession) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(data, 2),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Set up an initial SpdySession in the pool to reuse.
  HostPortPair host_port_pair("www.example.org", 443);
  SpdySessionKey key(host_port_pair, PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> spdy_session =
      CreateSpdySession(session.get(), key, NetLogWithSource());

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Given a net error, cause that error to be returned from the first Write()
// call and verify that the HttpNetworkTransaction fails with that error.
void HttpNetworkTransactionTestBase::CheckErrorIsPassedBack(int error,
                                                            IoMode mode) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  SSLSocketDataProvider ssl_data(mode, OK);
  MockWrite data_writes[] = {
      MockWrite(mode, error),
  };
  StaticSocketDataProvider data(base::span<MockRead>(), data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  ASSERT_EQ(error, rv);
}

TEST_P(HttpNetworkTransactionTest, SSLWriteCertError) {
  // Just check a grab bag of cert errors.
  static const int kErrors[] = {
      ERR_CERT_COMMON_NAME_INVALID,
      ERR_CERT_AUTHORITY_INVALID,
      ERR_CERT_DATE_INVALID,
  };
  for (int error : kErrors) {
    CheckErrorIsPassedBack(error, ASYNC);
    CheckErrorIsPassedBack(error, SYNCHRONOUS);
  }
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) No proxy is involved.
//  2) TLS False Start is disabled.
//  3) The initial TLS handshake requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate.
TEST_P(HttpNetworkTransactionTest, ClientAuthCertCache_Direct_NoFalseStart) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request->host_and_port = HostPortPair("www.example.com", 443);

  // [ssl_]data1 contains the data for the first SSL handshake. When a
  // CertificateRequest is received for the first time, the handshake will
  // be aborted to allow the caller to provide a certificate.
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider data1;
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // [ssl_]data2 contains the data for the second SSL handshake. When TLS
  // False Start is not being used, the result of the SSL handshake will be
  // returned as part of the SSLClientSocket::Connect() call. This test
  // matches the result of a server sending a handshake_failure alert,
  // rather than a Finished message, because it requires a client
  // certificate and none was supplied.
  SSLSocketDataProvider ssl_data2(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data2.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  StaticSocketDataProvider data2;
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // [ssl_]data3 contains the data for the third SSL handshake. When a
  // connection to a server fails during an SSL handshake,
  // HttpNetworkTransaction will attempt to fallback with legacy cryptography
  // enabled on some errors. This is transparent to the caller
  // of the HttpNetworkTransaction. Because this test failure is due to
  // requiring a client certificate, this fallback handshake should also
  // fail.
  SSLSocketDataProvider ssl_data3(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data3.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);
  StaticSocketDataProvider data3;
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Begin the SSL handshake with the peer. This consumes ssl_data1.
  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Complete the SSL handshake, which should abort due to requiring a
  // client certificate.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Indicate that no certificate should be supplied. From the perspective
  // of SSLClientCertCache, NULL is just as meaningful as a real
  // certificate, so this is the same as supply a
  // legitimate-but-unacceptable certificate.
  rv = trans.RestartWithCertificate(nullptr, nullptr, callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Ensure the certificate was added to the client auth cache before
  // allowing the connection to continue restarting.
  scoped_refptr<X509Certificate> client_cert;
  scoped_refptr<SSLPrivateKey> client_private_key;
  ASSERT_TRUE(session->ssl_client_context()->GetClientCertificate(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
  ASSERT_FALSE(client_cert);

  // Restart the handshake. This will consume ssl_data2, which fails, and
  // then consume ssl_data3 and ssl_data4, both of which should also fail.
  // The result code is checked against what ssl_data4 should return.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));

  // Ensure that the client certificate is removed from the cache on a
  // handshake failure.
  ASSERT_FALSE(session->ssl_client_context()->GetClientCertificate(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) No proxy is involved.
//  2) TLS False Start is enabled.
//  3) The initial TLS handshake requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate.
TEST_P(HttpNetworkTransactionTest, ClientAuthCertCache_Direct_FalseStart) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request->host_and_port = HostPortPair("www.example.com", 443);

  // When TLS False Start is used, SSLClientSocket::Connect() calls will
  // return successfully after reading up to the peer's Certificate message.
  // This is to allow the caller to call SSLClientSocket::Write(), which can
  // enqueue application data to be sent in the same packet as the
  // ChangeCipherSpec and Finished messages.
  // The actual handshake will be finished when SSLClientSocket::Read() is
  // called, which expects to process the peer's ChangeCipherSpec and
  // Finished messages. If there was an error negotiating with the peer,
  // such as due to the peer requiring a client certificate when none was
  // supplied, the alert sent by the peer won't be processed until Read() is
  // called.

  // Like the non-False Start case, when a client certificate is requested by
  // the peer, the handshake is aborted during the Connect() call.
  // [ssl_]data1 represents the initial SSL handshake with the peer.
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider data1;
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // When a client certificate is supplied, Connect() will not be aborted
  // when the peer requests the certificate. Instead, the handshake will
  // artificially succeed, allowing the caller to write the HTTP request to
  // the socket. The handshake messages are not processed until Read() is
  // called, which then detects that the handshake was aborted, due to the
  // peer sending a handshake_failure because it requires a client
  // certificate.
  SSLSocketDataProvider ssl_data2(ASYNC, OK);
  ssl_data2.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  MockRead data2_reads[] = {
      MockRead(ASYNC /* async */, ERR_SSL_PROTOCOL_ERROR),
  };
  StaticSocketDataProvider data2(data2_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // As described in ClientAuthCertCache_Direct_NoFalseStart, [ssl_]data3 is
  // the data for the SSL handshake once the TLSv1.1 connection falls back to
  // TLSv1. It has the same behaviour as [ssl_]data2.
  SSLSocketDataProvider ssl_data3(ASYNC, OK);
  ssl_data3.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);
  StaticSocketDataProvider data3(data2_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  // [ssl_]data4 is the data for the SSL handshake once the TLSv1 connection
  // falls back to SSLv3. It has the same behaviour as [ssl_]data2.
  SSLSocketDataProvider ssl_data4(ASYNC, OK);
  ssl_data4.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data4);
  StaticSocketDataProvider data4(data2_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data4);

  // Need one more if TLSv1.2 is enabled.
  SSLSocketDataProvider ssl_data5(ASYNC, OK);
  ssl_data5.cert_request_info = cert_request;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data5);
  StaticSocketDataProvider data5(data2_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data5);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Begin the initial SSL handshake.
  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Complete the SSL handshake, which should abort due to requiring a
  // client certificate.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Indicate that no certificate should be supplied. From the perspective
  // of SSLClientCertCache, NULL is just as meaningful as a real
  // certificate, so this is the same as supply a
  // legitimate-but-unacceptable certificate.
  rv = trans.RestartWithCertificate(nullptr, nullptr, callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Ensure the certificate was added to the client auth cache before
  // allowing the connection to continue restarting.
  scoped_refptr<X509Certificate> client_cert;
  scoped_refptr<SSLPrivateKey> client_private_key;
  ASSERT_TRUE(session->ssl_client_context()->GetClientCertificate(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
  ASSERT_FALSE(client_cert);

  // Restart the handshake. This will consume ssl_data2, which fails, and
  // then consume ssl_data3 and ssl_data4, both of which should also fail.
  // The result code is checked against what ssl_data4 should return.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));

  // Ensure that the client certificate is removed from the cache on a
  // handshake failure.
  ASSERT_FALSE(session->ssl_client_context()->GetClientCertificate(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) An HTTPS proxy is involved.
//  3) The HTTPS proxy requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate for the
//     proxy.
TEST_P(HttpNetworkTransactionTest, ClientAuthCertCache_Proxy_Fail) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();

  auto cert_request = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request->host_and_port = HostPortPair("proxy", 70);

  // Repeat the test for connecting to an HTTPS endpoint, then for connecting to
  // an HTTP endpoint.
  HttpRequestInfo requests[2];
  requests[0].url = GURL("https://www.example.com/");
  requests[0].method = "GET";
  requests[0].load_flags = LOAD_NORMAL;
  requests[0].traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // HTTPS requests are tunneled.
  MockWrite https_writes[] = {
      MockWrite("CONNECT www.example.com:443 HTTP/1.1\r\n"
                "Host: www.example.com:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  requests[1].url = GURL("http://www.example.com/");
  requests[1].method = "GET";
  requests[1].load_flags = LOAD_NORMAL;
  requests[1].traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // HTTP requests are not.
  MockWrite http_writes[] = {
      MockWrite("GET http://www.example.com/ HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // When the server rejects the client certificate, it will close the
  // connection. In TLS 1.2, this is signaled out of Connect(). In TLS 1.3 (or
  // TLS 1.2 with False Start), the error is returned out of the first Read().
  for (bool reject_in_connect : {true, false}) {
    SCOPED_TRACE(reject_in_connect);
    // Client certificate errors are typically signaled with
    // ERR_BAD_SSL_CLIENT_AUTH_CERT, but sometimes the server gives an arbitrary
    // protocol error.
    for (Error reject_error :
         {ERR_SSL_PROTOCOL_ERROR, ERR_BAD_SSL_CLIENT_AUTH_CERT}) {
      SCOPED_TRACE(reject_error);
      // Tunneled and non-tunneled requests are handled differently. Test both.
      for (const HttpRequestInfo& request : requests) {
        SCOPED_TRACE(request.url);

        session_deps_.socket_factory =
            std::make_unique<MockClientSocketFactory>();

        // See ClientAuthCertCache_Direct_NoFalseStart for the explanation of
        // [ssl_]data[1-3].
        SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
        ssl_data1.cert_request_info = cert_request;
        session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
        StaticSocketDataProvider data1;
        session_deps_.socket_factory->AddSocketDataProvider(&data1);

        std::optional<SSLSocketDataProvider> ssl_data2;
        std::optional<StaticSocketDataProvider> data2;
        MockRead error_in_read[] = {MockRead(ASYNC, reject_error)};
        if (reject_in_connect) {
          ssl_data2.emplace(ASYNC, reject_error);
          // There are no reads or writes.
          data2.emplace();
        } else {
          ssl_data2.emplace(ASYNC, OK);
          // We will get one Write() in before observing the error in Read().
          if (request.url.SchemeIsCryptographic()) {
            data2.emplace(error_in_read, https_writes);
          } else {
            data2.emplace(error_in_read, http_writes);
          }
        }
        ssl_data2->cert_request_info = cert_request.get();
        session_deps_.socket_factory->AddSSLSocketDataProvider(
            &ssl_data2.value());
        session_deps_.socket_factory->AddSocketDataProvider(&data2.value());

        // If the handshake returns ERR_SSL_PROTOCOL_ERROR, we attempt to
        // connect twice.
        std::optional<SSLSocketDataProvider> ssl_data3;
        std::optional<StaticSocketDataProvider> data3;
        if (reject_in_connect && reject_error == ERR_SSL_PROTOCOL_ERROR) {
          ssl_data3.emplace(ASYNC, reject_error);
          data3.emplace();  // There are no reads or writes.
          ssl_data3->cert_request_info = cert_request.get();
          session_deps_.socket_factory->AddSSLSocketDataProvider(
              &ssl_data3.value());
          session_deps_.socket_factory->AddSocketDataProvider(&data3.value());
        }

        std::unique_ptr<HttpNetworkSession> session =
            CreateSession(&session_deps_);
        HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

        // Begin the SSL handshake with the proxy.
        TestCompletionCallback callback;
        int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
        ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

        // Complete the SSL handshake,
```