Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Context:** The prompt tells us this is part of the Chromium networking stack, specifically a unit test file named `http_network_transaction_unittest.cc`. This immediately gives us a strong clue about its primary function: testing the `HttpNetworkTransaction` class.

2. **Identify Key Classes and Concepts:**  The filename and the presence of `TEST_P` (parameterized tests) point to Google Test being used. The code uses terms like `HttpNetworkTransaction`, `HttpNetworkSession`, `HttpRequestInfo`, `HttpResponseInfo`, `SpdySession`, `ClientSocketPoolManager`, `MockWrite`, `MockRead`, `SSLSocketDataProvider`, etc. These are core networking concepts within Chromium. Understanding these classes and their roles is crucial.

3. **Analyze Individual Test Cases:**  The file is a series of independent test cases. The best approach is to analyze each one individually. Look for:
    * **Test Name:**  The name usually gives a good indication of what's being tested (e.g., `AlternativeServiceShouldNotPoolToHttp11`).
    * **Setup:**  What data structures and mock objects are being created?  What network conditions are being simulated (e.g., alternative services, proxy configurations, specific error conditions)?
    * **Actions:** What methods of `HttpNetworkTransaction` are being called (e.g., `Start`)? What callbacks are being used?
    * **Assertions:** What are the `EXPECT_THAT` and `ASSERT_TRUE/FALSE` statements checking? These are the core verification steps of the test.

4. **Look for Patterns and Themes:** After analyzing a few test cases, you'll start to see patterns. For example, many tests involve:
    * Setting up mock socket data using `MockWrite`, `MockRead`, and `StaticSocketDataProvider`.
    * Creating an `HttpNetworkSession` with specific configurations.
    * Creating an `HttpNetworkTransaction`.
    * Starting the transaction with a request.
    * Checking the response status, headers, and data.
    * Checking properties like `was_fetched_via_spdy`, `was_alpn_negotiated`, and load timing information.
    * Testing error conditions and how the transaction handles them.

5. **Relate to JavaScript (If Applicable):** The prompt specifically asks about the relationship to JavaScript. Think about how networking in the browser affects JavaScript:
    * Fetch API:  The `HttpNetworkTransaction` is the underlying mechanism that powers `fetch`. When JavaScript code calls `fetch`, it eventually leads to the creation and execution of an `HttpNetworkTransaction`.
    * XMLHttpRequest (XHR):  Similar to Fetch, XHR relies on the network stack, including `HttpNetworkTransaction`.
    * WebSockets: While not directly covered in this snippet, the network stack handles WebSocket connections as well.
    * Service Workers: Service workers can intercept network requests made by JavaScript and can use the underlying network stack.

6. **Consider Logic and Input/Output:**  For each test case, try to reason about the expected input (the request URL, headers, etc.) and the expected output (the response status, headers, data, errors). The mock data provides the "input" to the network stack being tested.

7. **Identify Common Errors:** Based on the test names and the error codes being checked (e.g., `ERR_CONNECTION_REFUSED`, `ERR_CONNECTION_CLOSED`, `ERR_NAME_NOT_RESOLVED`), you can infer common user or programming errors that the code is designed to handle. For example, incorrect proxy settings, DNS resolution failures, or server-side connection closures.

8. **Trace User Actions (Debugging Clues):** Think about the steps a user might take in a browser that would lead to the execution of this code. This helps understand the context of these unit tests. Examples include:
    * Typing a URL in the address bar.
    * Clicking a link.
    * JavaScript code making a `fetch` or XHR request.
    * A service worker intercepting a request.

9. **Synthesize the Overall Function:**  After analyzing several test cases, you can summarize the main purpose of the file. It's clearly focused on thoroughly testing the behavior of `HttpNetworkTransaction` under various network conditions, protocol interactions (HTTP/1.1, HTTP/2/SPDY), proxy configurations, and error scenarios.

10. **Address the "Part X of Y" Question:**  The prompt mentions this is part 27 of 34. This suggests that the entire test suite is quite comprehensive. This specific part likely focuses on more complex scenarios and interactions, potentially involving alternative services, connection pooling, and error handling related to SPDY/HTTP/2.

**Self-Correction/Refinement During Analysis:**

* **Initial Misinterpretation:**  Perhaps initially, I might not fully grasp the significance of "alternative services." Reading the relevant test case (`AlternativeServiceShouldNotPoolToHttp11`) more carefully clarifies this feature and its testing.
* **Missing a JavaScript Link:** I might initially focus too much on the C++ internals. Recalling the role of `fetch` and XHR helps bridge the gap to JavaScript.
* **Overlooking Error Scenarios:**  I might initially focus only on successful requests. Paying attention to tests with names containing "Error" and the error codes being checked broadens the understanding.

By following these steps, moving from the general context to specific test cases and then synthesizing the overall purpose, we can effectively analyze and understand the functionality of this C++ unit test file.好的，让我们来分析一下 `net/http/http_network_transaction_unittest.cc` 这个文件的第 27 部分，并解答你的问题。

**功能归纳 (第 27 部分):**

这部分主要关注 `HttpNetworkTransaction` 在涉及 **HTTP/2 (或 SPDY) 和连接池** 时的行为，特别是以下几个方面：

* **备用服务（Alternative Service）和连接池：**  测试当存在 HTTP/2 的备用服务，但已经存在到该备用服务器的 HTTP/1.1 连接时，`HttpNetworkTransaction` 是否会正确处理，避免错误的连接复用。
* **通过隧道（Tunnel）的 HTTP 请求与 SPDY 会话：** 测试通过 CONNECT 隧道发送的 HTTPS 请求和直接发送的 HTTP 请求在使用 SPDY 会话时的行为，确保不会错误地复用 SPDY 会话。
* **证书不匹配时避免复用 SPDY 会话：**  测试当存在到 SPDY 代理的连接，但后续请求的 HTTPS 站点证书与代理不匹配时，是否会正确地建立新的连接，而不是错误地复用现有的 SPDY 会话。
* **SPDY 会话中的连接错误处理：** 测试当 SPDY 会话中出现连接关闭错误（`ERR_CONNECTION_CLOSED`）时，`HttpNetworkTransaction` 是否能够正确处理，关闭旧会话，并为后续请求建立新的连接。
* **关闭空闲 SPDY 会话以建立新会话：** 测试在高并发场景下，当连接池满时，是否能够关闭一个空闲的 SPDY 会话，以便为新的连接请求腾出空间。
* **同步和异步连接、写入、读取错误处理：** 测试 `HttpNetworkTransaction` 在同步和异步操作中遇到连接、写入、读取错误时的行为和错误报告。

**与 JavaScript 的关系及举例：**

`HttpNetworkTransaction` 是 Chromium 网络栈的核心组件，负责处理 HTTP 和 HTTPS 请求。 当 JavaScript 代码通过以下 API 发起网络请求时，最终会涉及到 `HttpNetworkTransaction` 的使用：

* **`fetch` API:** 这是现代浏览器中推荐的网络请求 API。当你使用 `fetch` 发起一个请求时，浏览器底层会创建并使用 `HttpNetworkTransaction` 来处理该请求。
* **`XMLHttpRequest` (XHR):** 虽然是较旧的 API，但仍然被广泛使用。 XHR 的底层实现同样依赖于 Chromium 的网络栈，包括 `HttpNetworkTransaction`。

**举例说明:**

假设你的 JavaScript 代码中使用 `fetch` 发起一个 HTTPS 请求到一个支持 HTTP/2 的服务器，并且该服务器之前已经被访问过，建立了 SPDY 会话。

```javascript
// JavaScript 代码
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个场景下，`HttpNetworkTransaction` 的功能（如本部分测试的）会影响到：

* **连接复用：**  `HttpNetworkTransaction` 会检查是否存在到 `example.com` 的空闲 HTTP/2 连接（SPDY 会话），如果存在且可用，则会复用该连接，提高性能。 第 27 部分中的测试确保了这种复用在各种复杂场景下（例如，存在 HTTP/1.1 连接但不应复用时）的正确性。
* **备用服务：** 如果 `example.com` 声明了备用服务（例如，在另一个端口上的 HTTP/2 服务），`HttpNetworkTransaction` 可能会尝试连接到备用服务。 第 27 部分的测试确保了备用服务的正确使用和避免了与现有 HTTP/1.1 连接的冲突。
* **错误处理：** 如果在请求过程中出现网络错误（例如，连接被服务器关闭），`HttpNetworkTransaction` 会负责处理这些错误，并将错误信息传递给 `fetch` API，最终导致 `fetch` Promise 的 reject。 第 27 部分测试了各种同步和异步错误场景。

**逻辑推理、假设输入与输出：**

**测试用例:** `AlternativeServiceShouldNotPoolToHttp11`

**假设输入:**

1. 一个到 `alternative.example.org:443` 的 HTTP/1.1 连接已经建立并保持活跃。
2. `origin.example.org:443` 声明了 `alternative.example.org:443` 作为 HTTP/2 的备用服务。
3. 发起一个到 `origin.example.org:443` 的请求。

**预期输出:**

*   `HttpNetworkTransaction` 不会复用已有的到 `alternative.example.org` 的 HTTP/1.1 连接来处理到 `origin.example.org` 的请求，因为它要求 HTTP/2。
*   由于测试中模拟了到 `origin.example.org` 的直接连接失败 (`ERR_CONNECTION_REFUSED`)，因此该请求会失败并返回 `ERR_CONNECTION_REFUSED` 错误。

**用户或编程常见的使用错误举例：**

* **配置错误的代理导致连接复用问题：**  用户如果配置了一个错误的 HTTPS 代理，可能导致 `HttpNetworkTransaction` 尝试将不应该通过代理发送的请求发送到代理，或者复用错误的连接。  第 27 部分的某些测试，如涉及代理的测试，就在验证这种场景。
* **不正确的证书配置导致 SPDY 会话复用失败：**  如果用户的服务器证书配置不正确，或者客户端的信任存储不包含必要的证书，可能导致 HTTPS 连接建立失败，进而影响 SPDY 会话的建立和复用。 `DoNotUseSpdySessionIfCertDoesNotMatch` 测试就模拟了这种情况。
* **在高并发场景下，不了解连接池限制导致请求被阻塞：**  开发者可能没有意识到浏览器的连接池限制，在高并发请求的情况下，可能会遇到请求被阻塞等待连接释放的情况。 `CloseIdleSpdySessionToOpenNewOne` 测试验证了在这种情况下，系统如何释放空闲连接。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS URL 并按下回车。**
2. **浏览器开始解析 URL，进行 DNS 查询，并查找是否已经存在到该域名的可用连接。**
3. **如果该域名支持 HTTP/2 并且之前已经建立了 SPDY 会话，浏览器可能会尝试复用该会话。**  此时会涉及到连接池的管理和备用服务的检查。
4. **如果需要建立新的连接，`HttpNetworkTransaction` 会负责创建和管理连接。**  这涉及到 TCP 连接的建立、TLS 握手（如果使用 HTTPS）、以及协议协商（例如，ALPN协商 HTTP/2）。
5. **如果请求需要通过代理，会涉及到代理连接的建立和 CONNECT 隧道的创建（如果是 HTTPS）。**  `DoNotUseSpdySessionForHttpOverTunnel` 测试就覆盖了这种情况。
6. **在数据传输过程中，如果出现网络错误（例如，连接中断），`HttpNetworkTransaction` 会负责处理这些错误。**  相关的错误处理测试模拟了这些场景。

作为调试线索，当用户遇到网络问题时，开发者可以关注以下几点：

*   **检查 NetLog:** Chromium 的 NetLog 记录了详细的网络事件，可以帮助开发者追踪请求的整个生命周期，包括连接建立、协议协商、数据传输和错误信息。
*   **分析连接池状态:** 了解连接池中连接的状态，可以帮助诊断连接复用和资源竞争问题。
*   **模拟网络条件:** 使用 Chromium 提供的工具（例如，Network Throttling）可以模拟不同的网络环境，帮助复现和诊断问题。
*   **检查服务器配置:**  确保服务器的 HTTP/2 配置、证书配置和备用服务声明是正确的。

**总结第 27 部分的功能:**

总而言之，`net/http/http_network_transaction_unittest.cc` 的第 27 部分专注于测试 `HttpNetworkTransaction` 在处理现代网络协议（HTTP/2/SPDY）和连接管理时的复杂场景和边缘情况，确保网络栈的稳定性和性能。 它覆盖了连接复用、备用服务、隧道、证书匹配以及各种错误处理机制，这些对于提供流畅和可靠的网络浏览体验至关重要。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第27部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
WithSource());
  rv = callback2.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response2->headers->GetStatusLine());

  std::string response_data2;
  ASSERT_THAT(ReadTransaction(&trans2, &response_data2), IsOk());
  EXPECT_EQ("another", response_data2);
}

// Alternative service requires HTTP/2 (or SPDY), but there is already a
// HTTP/1.1 socket open to the alternative server.  That socket should not be
// used.
TEST_P(HttpNetworkTransactionTest, AlternativeServiceShouldNotPoolToHttp11) {
  url::SchemeHostPort server("https", "origin.example.org", 443);
  HostPortPair alternative("alternative.example.org", 443);
  std::string origin_url = "https://origin.example.org:443";
  std::string alternative_url = "https://alternative.example.org:443";

  // Negotiate HTTP/1.1 with alternative.example.org.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // HTTP/1.1 data for |request1| and |request2|.
  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: alternative.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: alternative.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 40\r\n\r\n"
               "first HTTP/1.1 response from alternative"),
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 41\r\n\r\n"
               "second HTTP/1.1 response from alternative"),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  // This test documents that an alternate Job should not pool to an already
  // existing HTTP/1.1 connection.  In order to test this, a failed connection
  // to the server is mocked.  This way |request2| relies on the alternate Job.
  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  // Set up alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::Days(1);
  http_server_properties->SetHttp2AlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration);

  // First transaction to alternative to open an HTTP/1.1 socket.
  HttpRequestInfo request1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());
  request1.method = "GET";
  request1.url = GURL(alternative_url);
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback1;

  int rv = trans1.Start(&request1, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(callback1.GetResult(rv), IsOk());
  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response1->headers->GetStatusLine());
  EXPECT_TRUE(response1->was_alpn_negotiated);
  EXPECT_FALSE(response1->was_fetched_via_spdy);
  std::string response_data1;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data1), IsOk());
  EXPECT_EQ("first HTTP/1.1 response from alternative", response_data1);

  // Request for origin.example.org, which has an alternative service.  This
  // will start two Jobs: the alternative looks for connections to pool to,
  // finds one which is HTTP/1.1, and should ignore it, and should not try to
  // open other connections to alternative server.  The Job to server fails, so
  // this request fails.
  HttpRequestInfo request2;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  request2.method = "GET";
  request2.url = GURL(origin_url);
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback2;

  rv = trans2.Start(&request2, callback2.callback(), NetLogWithSource());
  EXPECT_THAT(callback2.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));

  // Another transaction to alternative.  This is to test that the HTTP/1.1
  // socket is still open and in the pool.
  HttpRequestInfo request3;
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, session.get());
  request3.method = "GET";
  request3.url = GURL(alternative_url);
  request3.load_flags = 0;
  request3.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  TestCompletionCallback callback3;

  rv = trans3.Start(&request3, callback3.callback(), NetLogWithSource());
  EXPECT_THAT(callback3.GetResult(rv), IsOk());
  const HttpResponseInfo* response3 = trans3.GetResponseInfo();
  ASSERT_TRUE(response3);
  ASSERT_TRUE(response3->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response3->headers->GetStatusLine());
  EXPECT_TRUE(response3->was_alpn_negotiated);
  EXPECT_FALSE(response3->was_fetched_via_spdy);
  std::string response_data3;
  ASSERT_THAT(ReadTransaction(&trans3, &response_data3), IsOk());
  EXPECT_EQ("second HTTP/1.1 response from alternative", response_data3);
}

TEST_P(HttpNetworkTransactionTest, DoNotUseSpdySessionForHttpOverTunnel) {
  const std::string https_url = "https://www.example.org:8080/";
  const std::string http_url = "http://www.example.org:8080/";

  // Separate SPDY util instance for naked and wrapped requests.
  SpdyTestUtil spdy_util_wrapped(/*use_priority_header=*/true);

  // SPDY GET for HTTPS URL (through CONNECT tunnel)
  const HostPortPair host_port_pair("www.example.org", 8080);
  spdy::SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      host_port_pair));
  spdy::SpdySerializedFrame req1(
      spdy_util_wrapped.ConstructSpdyGet(https_url.c_str(), 1, LOWEST));
  spdy::SpdySerializedFrame wrapped_req1(
      spdy_util_.ConstructWrappedSpdyFrame(req1, 1));

  // SPDY GET for HTTP URL (through the proxy, but not the tunnel).
  quiche::HttpHeaderBlock req2_block;
  req2_block[spdy::kHttp2MethodHeader] = "GET";
  req2_block[spdy::kHttp2AuthorityHeader] = "www.example.org:8080";
  req2_block[spdy::kHttp2SchemeHeader] = "http";
  req2_block[spdy::kHttp2PathHeader] = "/";
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(req2_block), MEDIUM, true));

  MockWrite writes1[] = {
      CreateMockWrite(connect, 0),
      CreateMockWrite(wrapped_req1, 2),
      CreateMockWrite(req2, 6),
  };

  spdy::SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame resp1(
      spdy_util_wrapped.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(
      spdy_util_wrapped.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame wrapped_resp1(
      spdy_util_wrapped.ConstructWrappedSpdyFrame(resp1, 1));
  spdy::SpdySerializedFrame wrapped_body1(
      spdy_util_wrapped.ConstructWrappedSpdyFrame(body1, 1));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads1[] = {
      CreateMockRead(conn_resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_resp1, 4),
      CreateMockRead(wrapped_body1, 5),
      MockRead(ASYNC, ERR_IO_PENDING, 7),
      CreateMockRead(resp2, 8),
      CreateMockRead(body2, 9),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 10),
  };

  SequencedSocketData data1(reads1, writes1);
  MockConnect connect_data1(ASYNC, OK);
  data1.set_connect_data(connect_data1);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  SSLSocketDataProvider ssl1(ASYNC, OK);  // to the proxy
  ssl1.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  SSLSocketDataProvider ssl2(ASYNC, OK);  // to the server
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Start the first transaction to set up the SpdySession
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(https_url);
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(LOWEST, session.get());
  TestCompletionCallback callback1;
  int rv = trans1.Start(&request1, callback1.callback(), NetLogWithSource());

  // This pause is a hack to avoid running into https://crbug.com/497228.
  data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  data1.Resume();
  EXPECT_THAT(callback1.GetResult(rv), IsOk());
  EXPECT_TRUE(trans1.GetResponseInfo()->was_fetched_via_spdy);

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans1.GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReusedWithPac(load_timing_info1,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  // Now, start the HTTP request.
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(http_url);
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), NetLogWithSource());

  // This pause is a hack to avoid running into https://crbug.com/497228.
  data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  data1.Resume();
  EXPECT_THAT(callback2.GetResult(rv), IsOk());

  EXPECT_TRUE(trans2.GetResponseInfo()->was_fetched_via_spdy);

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  // The established SPDY sessions is considered reused by the HTTP request.
  TestLoadTimingReusedWithPac(load_timing_info2);
  // HTTP requests over a SPDY session should have a different connection
  // socket_log_id than requests over a tunnel.
  EXPECT_NE(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);
}

// Test that in the case where we have a SPDY session to a SPDY proxy
// that we do not pool other origins that resolve to the same IP when
// the certificate does not match the new origin.
// http://crbug.com/134690
TEST_P(HttpNetworkTransactionTest, DoNotUseSpdySessionIfCertDoesNotMatch) {
  const std::string url1 = "http://www.example.org/";
  const std::string url2 = "https://news.example.org/";
  const std::string ip_addr = "1.2.3.4";

  // Second SpdyTestUtil instance for the second socket.
  SpdyTestUtil spdy_util_secure(/*use_priority_header=*/true);

  // SPDY GET for HTTP URL (through SPDY proxy)
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://www.example.org/"));
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));

  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(resp1, 2),
      CreateMockRead(body1, 3), MockRead(ASYNC, OK, 4),  // EOF
  };

  SequencedSocketData data1(reads1, writes1);
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);
  MockConnect connect_data1(ASYNC, OK, peer_addr);
  data1.set_connect_data(connect_data1);

  // SPDY GET for HTTPS URL (direct)
  spdy::SpdySerializedFrame req2(
      spdy_util_secure.ConstructSpdyGet(url2.c_str(), 1, MEDIUM));

  MockWrite writes2[] = {
      CreateMockWrite(req2, 0),
  };

  spdy::SpdySerializedFrame resp2(
      spdy_util_secure.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body2(
      spdy_util_secure.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp2, 1), CreateMockRead(body2, 2),
                       MockRead(ASYNC, OK, 3)};

  SequencedSocketData data2(reads2, writes2);
  MockConnect connect_data2(ASYNC, OK);
  data2.set_connect_data(connect_data2);

  // Set up a proxy config that sends HTTP requests to a proxy, and
  // all others direct.
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString("http=https://proxy:443");
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));

  SSLSocketDataProvider ssl1(ASYNC, OK);  // to the proxy
  ssl1.next_proto = kProtoHTTP2;
  // Load a valid cert.  Note, that this does not need to
  // be valid for proxy because the MockSSLClientSocket does
  // not actually verify it.  But SpdySession will use this
  // to see if it is valid for the new origin
  ssl1.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(ssl1.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl2(ASYNC, OK);  // to the server
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  session_deps_.host_resolver = std::make_unique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("news.example.org", ip_addr);
  session_deps_.host_resolver->rules()->AddRule("proxy", ip_addr);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Start the first transaction to set up the SpdySession
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(url1);
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(LOWEST, session.get());
  TestCompletionCallback callback1;
  ASSERT_EQ(ERR_IO_PENDING,
            trans1.Start(&request1, callback1.callback(), NetLogWithSource()));
  // This pause is a hack to avoid running into https://crbug.com/497228.
  data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  data1.Resume();

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(trans1.GetResponseInfo()->was_fetched_via_spdy);

  // Now, start the HTTP request
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(url2);
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            trans2.Start(&request2, callback2.callback(), NetLogWithSource()));
  base::RunLoop().RunUntilIdle();

  ASSERT_TRUE(callback2.have_result());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_TRUE(trans2.GetResponseInfo()->was_fetched_via_spdy);
}

// Test to verify that a failed socket read (due to an ERR_CONNECTION_CLOSED
// error) in SPDY session, removes the socket from pool and closes the SPDY
// session. Verify that new url's from the same HttpNetworkSession (and a new
// SpdySession) do work. http://crbug.com/224701
TEST_P(HttpNetworkTransactionTest, ErrorSocketNotConnected) {
  const std::string https_url = "https://www.example.org/";

  MockRead reads1[] = {MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED, 0)};

  SequencedSocketData data1(reads1, base::span<MockWrite>());

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(https_url.c_str(), 1, MEDIUM));
  MockWrite writes2[] = {
      CreateMockWrite(req2, 0),
  };

  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {
      CreateMockRead(resp2, 1), CreateMockRead(body2, 2),
      MockRead(ASYNC, OK, 3)  // EOF
  };

  SequencedSocketData data2(reads2, writes2);

  SSLSocketDataProvider ssl1(ASYNC, OK);
  ssl1.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  // Start the first transaction to set up the SpdySession and verify that
  // connection was closed.
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(https_url);
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans1(MEDIUM, session.get());
  TestCompletionCallback callback1;
  EXPECT_EQ(ERR_IO_PENDING,
            trans1.Start(&request1, callback1.callback(), NetLogWithSource()));
  EXPECT_THAT(callback1.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));

  // Now, start the second request and make sure it succeeds.
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(https_url);
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            trans2.Start(&request2, callback2.callback(), NetLogWithSource()));

  ASSERT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_TRUE(trans2.GetResponseInfo()->was_fetched_via_spdy);
}

TEST_P(HttpNetworkTransactionTest, CloseIdleSpdySessionToOpenNewOne) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Use two different hosts with different IPs so they don't get pooled.
  session_deps_.host_resolver->rules()->AddRule("www.a.com", "10.0.0.1");
  session_deps_.host_resolver->rules()->AddRule("www.b.com", "10.0.0.2");
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    session->http_stream_pool()->set_max_stream_sockets_per_group_for_testing(
        1u);
    session->http_stream_pool()->set_max_stream_sockets_per_pool_for_testing(
        1u);
  }

  SSLSocketDataProvider ssl1(ASYNC, OK);
  ssl1.next_proto = kProtoHTTP2;
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  spdy::SpdySerializedFrame host1_req(
      spdy_util_.ConstructSpdyGet("https://www.a.com", 1, DEFAULT_PRIORITY));
  MockWrite spdy1_writes[] = {
      CreateMockWrite(host1_req, 0),
  };
  spdy::SpdySerializedFrame host1_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame host1_resp_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy1_reads[] = {
      CreateMockRead(host1_resp, 1),
      CreateMockRead(host1_resp_body, 2),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),
  };

  // Use a separate test instance for the separate SpdySession that will be
  // created.
  SpdyTestUtil spdy_util_2(/*use_priority_header=*/true);
  SequencedSocketData spdy1_data(spdy1_reads, spdy1_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy1_data);

  spdy::SpdySerializedFrame host2_req(
      spdy_util_2.ConstructSpdyGet("https://www.b.com", 1, DEFAULT_PRIORITY));
  MockWrite spdy2_writes[] = {
      CreateMockWrite(host2_req, 0),
  };
  spdy::SpdySerializedFrame host2_resp(
      spdy_util_2.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame host2_resp_body(
      spdy_util_2.ConstructSpdyDataFrame(1, true));
  MockRead spdy2_reads[] = {
      CreateMockRead(host2_resp, 1),
      CreateMockRead(host2_resp_body, 2),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),
  };

  SequencedSocketData spdy2_data(spdy2_reads, spdy2_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy2_data);

  MockWrite http_write[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.a.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_read[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 6\r\n\r\n"),
      MockRead("hello!"),
  };
  StaticSocketDataProvider http_data(http_read, http_write);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  HostPortPair host_port_pair_a("www.a.com", 443);
  SpdySessionKey spdy_session_key_a(
      host_port_pair_a, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.a.com/");
  request1.load_flags = 0;
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  trans.reset();
  EXPECT_TRUE(HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));

  HostPortPair host_port_pair_b("www.b.com", 443);
  SpdySessionKey spdy_session_key_b(
      host_port_pair_b, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_b));
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.b.com/");
  request2.load_flags = 0;
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request2, callback.callback(), NetLogWithSource());
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
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));
  EXPECT_TRUE(HasSpdySession(session->spdy_session_pool(), spdy_session_key_b));

  HostPortPair host_port_pair_a1("www.a.com", 80);
  SpdySessionKey spdy_session_key_a1(
      host_port_pair_a1, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a1));
  HttpRequestInfo request3;
  request3.method = "GET";
  request3.url = GURL("http://www.a.com/");
  request3.load_flags = 0;
  request3.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request3, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_b));
}

TEST_P(HttpNetworkTransactionTest, HttpSyncConnectError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockConnect mock_connect(SYNCHRONOUS, ERR_NAME_NOT_RESOLVED);
  StaticSocketDataProvider data;
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));

  ConnectionAttempts attempts = trans.GetConnectionAttempts();
  ASSERT_EQ(1u, attempts.size());
  EXPECT_THAT(attempts[0].result, IsError(ERR_NAME_NOT_RESOLVED));

  IPEndPoint endpoint;
  EXPECT_FALSE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_TRUE(endpoint.address().empty());
}

TEST_P(HttpNetworkTransactionTest, HttpAsyncConnectError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockConnect mock_connect(ASYNC, ERR_NAME_NOT_RESOLVED);
  StaticSocketDataProvider data;
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));

  ConnectionAttempts attempts = trans.GetConnectionAttempts();
  ASSERT_EQ(1u, attempts.size());
  EXPECT_THAT(attempts[0].result, IsError(ERR_NAME_NOT_RESOLVED));

  IPEndPoint endpoint;
  EXPECT_FALSE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_TRUE(endpoint.address().empty());
}

TEST_P(HttpNetworkTransactionTest, HttpSyncWriteError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };
  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),  // Should not be reached.
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest, HttpAsyncWriteError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(ASYNC, ERR_CONNECTION_RESET),
  };
  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),  // Should not be reached.
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest, HttpSyncReadError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_P(HttpNetworkTransactionTest, HttpAsyncReadError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead(ASYNC, ERR_CONNECTION_RESET),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

// Tests that when a used socket is returned to the SSL socket pool, it's closed
// if the transport socket pool is stalled on the global socket limit.
TEST_P(HttpNetworkTransactionTest, CloseSSLSocketOnIdleForHttpRequest) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKE
```