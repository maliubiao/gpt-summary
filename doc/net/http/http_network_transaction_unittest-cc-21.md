Response:
My thought process to address the user's request goes through these stages:

1. **Understanding the Core Request:** The user wants a functional summary of a specific Chromium source file (`http_network_transaction_unittest.cc`), particularly section 22 out of 34. They are also interested in connections to JavaScript, logic inferences, common user/programming errors, debugging information, and a general summarization of this section.

2. **Initial Scan and Keyword Spotting:** I quickly scanned the provided code snippet, looking for recurring patterns and keywords. Key observations include:
    * `TEST_P`: This indicates parameterized tests, suggesting the code tests various scenarios.
    * `HttpNetworkTransactionTest`:  The test suite is for `HttpNetworkTransaction`, a core component of Chromium's networking stack.
    * `UseAlternateProtocol`, `AlternateProtocolWithSpdyLateBinding`, `StallAlternativeService`, `UseOriginNotAlternativeForProxy`, `UseAlternativeServiceForTunneledNpnSpdy`, `UseAlternativeServiceForNpnSpdyWithExistingSpdySession`: These test names clearly indicate a focus on alternative protocols (like SPDY/HTTP2) and how they interact with HTTP/1.1.
    * Mocking (`MockRead`, `MockWrite`, `StaticSocketDataProvider`, `SequencedSocketData`, `MockConnect`): The tests heavily rely on mocking network interactions to simulate different server responses and network conditions.
    * `HttpResponseInfo`, `HttpRequestInfo`: These represent the data structures for HTTP requests and responses.
    * `SpdySerializedFrame`:  Indicates interaction with the SPDY protocol.
    * `ProxyConfig`, `CapturingProxyResolver`: Some tests involve proxy configurations.
    * Assertions (`ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`, `ASSERT_THAT`):  Standard C++ testing macros to check for expected outcomes.
    * Completion Callbacks (`TestCompletionCallback`): Used to handle asynchronous operations.
    * `NetLogWithSource`:  Indicates logging within the networking stack.

3. **Focusing on Section 22:** The user explicitly requested analysis of "section 22". While the provided snippet isn't explicitly divided into sections, I inferred the user likely wanted a summary of the functionality demonstrated within the given code block. This block primarily deals with testing different aspects of *alternative services*.

4. **Identifying Key Functionalities within the Snippet:**  Based on the test names and the mocking patterns, I identified the following functionalities being tested:
    * **Basic Alternative Protocol Usage (NPN/SPDY):**  Testing if the browser correctly upgrades to SPDY/HTTP2 when the server advertises it via the `Alt-Svc` header.
    * **Late Binding of Alternative Protocols:**  Simulating a scenario where an alternative protocol connection succeeds after a delay, and a pending HTTP/1.1 request is "upgraded" to use the established SPDY connection.
    * **Stalling of Alternative Services:** Checking the behavior when an alternative protocol connection hangs, ensuring the browser falls back to the original protocol for subsequent requests.
    * **Proxy Interaction with Alternative Services:** Verifying that proxy resolution uses the origin URL, not the alternative service's hostname, ensuring proper proxy bypassing rules are applied.
    * **Alternative Services over Tunneled Connections:** Testing the use of alternative protocols when connecting through an HTTP proxy using the `CONNECT` method.
    * **Reusing Existing SPDY Sessions with Alternative Services:** Confirming that an already established SPDY session is used for subsequent requests to the same origin, even if the initial connection used HTTP/1.1 and discovered the alternative service.

5. **Considering JavaScript Relevance:** I thought about how these networking functionalities relate to JavaScript. JavaScript in web browsers uses the Fetch API or XMLHttpRequest to make network requests. While the underlying protocol negotiation (like SPDY/HTTP2) is mostly transparent to the JavaScript code, the performance benefits (multiplexing, header compression) are significant. I formulated examples illustrating this.

6. **Developing Hypothetical Inputs and Outputs:** For each test scenario, I considered what the simulated server responses and client behaviors would be. This involved analyzing the `MockRead` and `MockWrite` data. I tried to create simplified examples to illustrate the core logic.

7. **Identifying Potential User/Programming Errors:** I reflected on common mistakes developers might make when dealing with alternative protocols or network configurations. Examples include incorrect `Alt-Svc` headers, firewall issues, or assuming immediate availability of alternative protocols.

8. **Tracing User Operations (Debugging Clues):** I considered how a user action (like clicking a link or typing a URL) might lead to the execution paths tested in this code. This involves understanding the browser's network request lifecycle.

9. **Synthesizing the Summary:** Finally, I compiled all the observations and analyses into a concise summary, highlighting the main focus of this section: testing the robustness and correctness of alternative protocol handling within Chromium's networking stack. I also made sure to incorporate the "part 22 of 34" context.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps the "section" division is literal in the file.
* **Correction:** Realized the user likely meant the functional grouping of tests within the provided code block, as there are no explicit section markers.
* **Initial thought:** Focus heavily on the low-level socket interactions.
* **Refinement:**  Elevated the explanation to discuss the higher-level concepts of alternative protocols and their benefits, making it more accessible.
* **Initial thought:** The JavaScript connection might be too abstract.
* **Refinement:** Provided concrete examples using `fetch()` to illustrate the practical implications.
* **Initial thought:** Just list the test cases.
* **Refinement:**  Synthesized the common themes and functionalities being tested across these cases.
Based on the provided C++ code snippet from `net/http/http_network_transaction_unittest.cc`, which is part 22 of 34, the primary function of this section is to **test the behavior of `HttpNetworkTransaction` when dealing with alternative network protocols, specifically SPDY (and by extension, HTTP/2) announced via the `Alt-Svc` header.**

Here's a breakdown of the functionalities being tested:

**Core Functionalities Tested:**

1. **Using Alternative Protocols (NPN/SPDY):**
   - Tests if the `HttpNetworkTransaction` correctly uses an alternative protocol (like SPDY) when advertised by the server via the `Alt-Svc` header in the initial HTTP/1.1 response.
   - Verifies that subsequent requests to the same origin use the established SPDY connection.

2. **Late Binding of Alternative Protocols:**
   - Examines a scenario where the initial HTTP/1.1 connection receives an `Alt-Svc` header. A new connection attempt using the alternative protocol is made.
   - Tests if a pending HTTP/1.1 transaction can be "upgraded" to use the newly established alternative protocol connection if it succeeds later.

3. **Stalling Alternative Services:**
   - Checks how the `HttpNetworkTransaction` handles a situation where an attempt to connect using an alternative protocol hangs or fails.
   - Verifies that in such cases, the transaction falls back to using the original protocol (HTTP/1.1) for subsequent requests.

4. **Proxy Interaction with Alternative Services:**
   - Confirms that when a proxy is involved, the proxy resolution and bypass rules are applied based on the *origin* URL, not the hostname of the alternative service. This prevents bypassing proxy rules unintentionally.

5. **Alternative Services over Tunneled Connections (HTTPS through a Proxy):**
   - Tests the scenario where an alternative protocol is used when connecting to an HTTPS server through an HTTP proxy (using the `CONNECT` method for tunneling).
   - Verifies the correct sequence of operations, including the initial HTTP/1.1 connection to the proxy, the `CONNECT` handshake, and then the negotiation of the alternative protocol over the tunnel.

6. **Reusing Existing SPDY Sessions:**
   - Checks if an existing SPDY session in the session pool is reused for subsequent requests to the same origin, even if the initial connection discovered the alternative service via HTTP/1.1.

**Relationship to JavaScript:**

While the code itself is C++, these tests directly impact the behavior of network requests initiated by JavaScript in a web browser.

* **Performance:** The successful usage of alternative protocols like SPDY/HTTP/2 leads to significant performance improvements for web applications. JavaScript making `fetch()` or `XMLHttpRequest` calls will benefit from features like header compression, multiplexing, and server push provided by these protocols.
    * **Example:** A JavaScript application might load multiple resources (images, scripts, stylesheets) from the same domain. If an HTTP/2 connection is established due to the `Alt-Svc` header, these resources can be loaded in parallel over the same connection, reducing latency compared to multiple HTTP/1.1 connections.

* **Transparent to Developers:**  Ideally, the switch to alternative protocols should be transparent to JavaScript developers. They don't need to write different code depending on whether SPDY/HTTP/2 is used. The browser handles the underlying protocol negotiation.

**Logic Inference (Hypothetical Input & Output):**

Let's take the `UseAlternateProtocolForNpnSpdy` test as an example:

* **Hypothetical Input:**
    1. A JavaScript `fetch("https://www.example.org/")` call is made.
    2. The first HTTP/1.1 response from `www.example.org` includes the `Alt-Svc` header advertising SPDY.
    3. Subsequent `fetch("https://www.example.org/")` calls are made.

* **Hypothetical Output:**
    1. The first `fetch()` call uses HTTP/1.1.
    2. The browser parses the `Alt-Svc` header and attempts to establish a SPDY connection.
    3. Subsequent `fetch()` calls to `www.example.org` will use the established SPDY connection, leading to faster resource loading and potentially different network timings observable in the browser's developer tools. The `response.was_fetched_via_spdy` property (if exposed in a browser API) would be true for these subsequent requests.

**User or Programming Common Usage Errors:**

* **Incorrect `Alt-Svc` Header Configuration:**  If a server administrator misconfigures the `Alt-Svc` header (e.g., incorrect port, protocol), the browser might fail to establish an alternative protocol connection. This could lead to unexpected fallback to HTTP/1.1 and potential performance degradation.
    * **Example:** A server might send `Alt-Svc: h2=":444"` when it's actually listening for HTTP/2 on port 443. The browser would likely fail to connect on port 444.

* **Firewall Issues:** Firewalls might block connections on the port specified in the `Alt-Svc` header, preventing the browser from establishing the alternative protocol connection.

* **Assuming Immediate Availability:** Developers shouldn't assume that an alternative protocol will be immediately available after the first response. The browser needs time to establish the new connection.

**User Operations Leading to This Code (Debugging Clues):**

A user action that triggers network requests to a server that supports and advertises alternative protocols could lead to the execution paths tested here.

1. **Typing a URL in the address bar:** If the website at that URL advertises `Alt-Svc`, the browser will attempt to use the alternative protocol for subsequent requests.

2. **Clicking a link:** Similar to typing a URL, clicking a link can initiate a navigation that may involve alternative protocol negotiation.

3. **Loading a web page with multiple resources:** When a browser loads an HTML page, it fetches various resources (images, scripts, stylesheets). If the server supports alternative protocols, the browser will attempt to use them for these resource requests.

4. **JavaScript making `fetch()` or `XMLHttpRequest` calls:** As mentioned earlier, JavaScript code can initiate network requests that will be subject to the alternative protocol logic.

**Summary of Functionality (Part 22 of 34):**

This specific section of `http_network_transaction_unittest.cc` focuses on rigorously testing the `HttpNetworkTransaction`'s ability to correctly handle and utilize alternative network protocols like SPDY/HTTP/2, as advertised by servers using the `Alt-Svc` header. It covers various scenarios, including initial negotiation, late binding, handling of failures, interaction with proxies, and the reuse of existing connections. This ensures the reliability and performance benefits of alternative protocols in Chromium's network stack.

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第22部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
lback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_P(HttpNetworkTransactionTest, UseAlternateProtocolForNpnSpdy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider first_transaction(data_reads,
                                             base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  AddSSLSocketData();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
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

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_non_alternate_protocol_socket;
  hanging_non_alternate_protocol_socket.set_connect_data(
      never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_non_alternate_protocol_socket);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_P(HttpNetworkTransactionTest, AlternateProtocolWithSpdyLateBinding) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // First transaction receives Alt-Svc header over HTTP/1.1.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider http11_data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&http11_data);

  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl_http11.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  // Second transaction starts an alternative and a non-alternative Job.
  // Both sockets hang.
  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_socket1;
  hanging_socket1.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&hanging_socket1);

  StaticSocketDataProvider hanging_socket2;
  hanging_socket2.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&hanging_socket2);

  // Third transaction starts an alternative and a non-alternative job.
  // The non-alternative job hangs, but the alternative one succeeds.
  // The second transaction, still pending, binds to this socket.
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 3, LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 1),
  };
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame data2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp1, 2), CreateMockRead(data1, 3),
      CreateMockRead(resp2, 4), CreateMockRead(data2, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  AddSSLSocketData();

  StaticSocketDataProvider hanging_socket3;
  hanging_socket3.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&hanging_socket3);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  TestCompletionCallback callback1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  TestCompletionCallback callback2;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request, callback2.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TestCompletionCallback callback3;
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, session.get());
  rv = trans3.Start(&request, callback3.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_THAT(callback3.WaitForResult(), IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  response = trans3.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans3, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_P(HttpNetworkTransactionTest, StallAlternativeServiceForNpnSpdy) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider first_transaction(data_reads,
                                             base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_alternate_protocol_socket;
  hanging_alternate_protocol_socket.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_alternate_protocol_socket);

  // 2nd request is just a copy of the first one, over HTTP/1.1 again.
  StaticSocketDataProvider second_transaction(data_reads,
                                              base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&second_transaction);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);
}

// Test that proxy is resolved using the origin url,
// regardless of the alternative server.
TEST_P(HttpNetworkTransactionTest, UseOriginNotAlternativeForProxy) {
  // Configure proxy to bypass www.example.org, which is the origin URL.
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString("myproxy:70");
  proxy_config.proxy_rules().bypass_rules.AddRuleFromString("www.example.org");
  auto proxy_config_service = std::make_unique<ProxyConfigServiceFixed>(
      ProxyConfigWithAnnotation(proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS));

  CapturingProxyResolver capturing_proxy_resolver;
  auto proxy_resolver_factory = std::make_unique<CapturingProxyResolverFactory>(
      &capturing_proxy_resolver);

  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::move(proxy_config_service), std::move(proxy_resolver_factory),
          NetLog::Get(), /*quick_check_enabled=*/true);

  session_deps_.net_log = NetLog::Get();

  // Configure alternative service with a hostname that is not bypassed by the
  // proxy.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  url::SchemeHostPort server("https", "www.example.org", 443);
  HostPortPair alternative("www.example.com", 443);
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration);

  // Non-alternative job should hang.
  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_alternate_protocol_socket;
  hanging_alternate_protocol_socket.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_alternate_protocol_socket);

  AddSSLSocketData();

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));

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

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  // Origin host bypasses proxy, no resolution should have happened.
  ASSERT_TRUE(capturing_proxy_resolver.lookup_info().empty());
}

TEST_P(HttpNetworkTransactionTest, UseAlternativeServiceForTunneledNpnSpdy) {
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
  session_deps_.net_log = NetLog::Get();

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider first_transaction(data_reads,
                                             base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  AddSSLSocketData();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      CreateMockWrite(req, 2),
  };

  const char kCONNECTResponse[] = "HTTP/1.1 200 Connected\r\n\r\n";

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      MockRead(ASYNC, 1, kCONNECTResponse),
      CreateMockRead(resp, 3),
      CreateMockRead(data, 4),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_non_alternate_protocol_socket;
  hanging_non_alternate_protocol_socket.set_connect_data(
      never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_non_alternate_protocol_socket);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/0.9 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  ASSERT_EQ(2u, capturing_proxy_resolver.lookup_info().size());
  EXPECT_EQ("https://www.example.org/",
            capturing_proxy_resolver.lookup_info()[0].url.spec());
  EXPECT_EQ("https://www.example.org/",
            capturing_proxy_resolver.lookup_info()[1].url.spec());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

TEST_P(HttpNetworkTransactionTest,
       UseAlternativeServiceForNpnSpdyWithExistingSpdySession) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider first_transaction(data_reads,
                                             base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  AddSSLSocketData();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
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

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  // Set up an initial SpdySession in the pool to reuse.
  HostPortPair host_port_pair("www.example.org", 443);
  SpdySessionKey key(host_port_pair, PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> spdy_session =
      CreateSpdySession(session.get(), key, NetLogWithSource());

  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  ConnectedHandler connected_handler;
  trans->SetConnectedCallback(connected_handler.Callback());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  TransportInfo expected_transport;
  expected_transport.type = TransportType::kDirect;
  expected_transport.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 443);
  expected_transport.negotiated_protocol = kProtoHTTP2;
  EXPECT_THAT(connected_handler.transports(), ElementsAre(expected_transport));

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

// GenerateAuthToken is a mighty big test.
// It tests all permutation of GenerateAuthToken behavior:
//   - Synchronous and Asynchronous completion.
//   - OK or error on completion.
//   - Direct connection, non-authenticating proxy, and authenticating proxy.
//   - HTTP or HTTPS backend (to include proxy tunneling).
//   - Non-authenticating and authenticating backend.
//
// In all, there are 44 reasonable permuations (for example, if there are
// problems generating an auth token for an authenticating proxy, we don't
// need to test all permutations of the backend server).
//
// The test proceeds by going over each of the configuration cases, and
// potentially running up to three rounds in each of the tests. The TestConfig
// specifies both the configuration for the test as well as the expectations
// for the results.
TEST_P(HttpNetworkTransactionTest, GenerateAuthToken) {
  static const char kServer[] = "http://www.example.com";
  static const char kSecureServer[] = "https://www.example.com";
  static const char kProxy[] = "myproxy:70";

  enum AuthTiming {
    AUTH_NONE,
    AUTH_SYNC,
    AUTH_ASYNC,
  };

  const MockWrite kGet(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n\r\n");
  const MockWrite kGetProxy(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n\r\n");
  const MockWrite kGetAuth(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n"
      "Authorization: auth_token\r\n\r\n");
  const MockWrite kGetProxyAuth(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Proxy-Authorization: auth_token\r\n\r\n");
  const MockWrite kGetAuthThroughProxy(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Authorization: auth_token\r\n\r\n");
  const MockWrite kGetAuthWithProxyAuth(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Proxy-Authorization: auth_token\r\n"
      "Authorization: auth_token\r\n\r\n");
  const MockWrite kConnect(
      "CONNECT www.example.com:443 HTTP/1.1\r\n"
      "Host: www.example.com:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n");
  const MockWrite kConnectProxyAuth(
      "CONNECT www.example.com:443 HTTP/1.1\r\n"
      "Host: www.example.com:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "Proxy-Authorization: auth_token\r\n\r\n");

  const MockRead kSuccess(
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 3\r\n\r\n"
      "Yes");
  const MockRead kFailure("Should not be called.");
  const MockRead kServerChallenge(
      "HTTP/1.1 401 Unauthorized\r\n"
      "WWW-Authenticate: Mock realm=server\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 14\r\n\r\n"
      "Unauthorized\r\n");
  const MockRead kProxyChallenge(
      "HTTP/1.1 407 Unauthorized\r\n"
      "Proxy-Authenticate: Mock realm=proxy\r\n"
      "Proxy-Connection: close\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 14\r\n\r\n"
      "Unauthorized\r\n");
  const MockRead kProxyConnected("HTTP/1.1 200 Connection Established\r\n\r\n");

  // NOTE(cbentzel): I wanted TestReadWriteRound to be a simple struct with
  // no constructors, but the C++ compiler on Windows warns about
  // unspecified data in compound literals. So, moved to using constructors,
  // and TestRound's created with the default constructor should not be used.
  struct TestRound {
    TestRound()
        : expected_rv(ERR_UNEXPECTED),
          extra_write(nullptr),
          extra_read(nullptr) {}
    TestRound(const MockWrite& write_arg,
              const MockRead& read_arg,
              int expected_rv_arg)
        : write(write_arg),
          read(read_arg),
          expected_rv(expected_rv_arg),
          extra_write(nullptr),
          extra_read(nullptr) {}
    TestRound(const MockWrite& write_arg,
              const MockRead& read_arg,
              int expected_rv_arg,
              const MockWrite* extra_write_arg,
              const MockRead* extra_read_arg)
        : write(write_arg),
          read(read_arg),
          expected_rv(expected_rv_arg),
          extra_write(extra_write_arg),
          extra_read(extra_read_arg) {}
    MockWrite write;
    MockRead read;
    int expected_rv;
    raw_ptr<const MockWrite> extra_write = nullptr;
    raw_ptr<const MockRead> extra_read = nullptr;
  };

  static const int kNoSSL = 500;

  struct TestConfig {
    int line_number;
    const char* const proxy_url;
    AuthTiming proxy_auth_timing;
    int first_generate_proxy_token_rv;
    const char* const server_url;
    AuthTiming server_auth_timing;
    int first_generate_server_token_rv;
    int num_auth_rounds;
    int first_ssl_round;
    TestRound rounds[4];
  } test_configs[] = {
      // Non-authenticating HTTP server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       1,
       kNoSSL,
       {TestRound(kGet, kSuccess, OK)}},
      // Authenticating HTTP server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_UNSUPPORTED_AUTH_SCHEME,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_FAILED,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kFailure, ERR_FAILED)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_FAILED,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kFailure, ERR_FAILED)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_FAILED,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGet, kFailure, ERR_FAILED)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_FAILED,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGet, kFailure, ERR_FAILED)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        // The second round uses a HttpAuthHandlerMock that always succeeds.
        TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      // Non-authenticating HTTP server through a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       1,
       kNoSSL,
       {TestRound(kGetProxy, kSuccess, OK)}},
      // Authenticating HTTP server through a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetAuthThroughProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetAuthThroughProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetAuthThroughProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
```