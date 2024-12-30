Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's network stack. The file is `net/http/http_network_transaction_unittest.cc`. This strongly suggests the file contains unit tests for the `HttpNetworkTransaction` class.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The filename immediately points to unit tests for `HttpNetworkTransaction`.

2. **Scan the test names:**  Look for patterns in the test names. This will reveal the specific features being tested. Keywords like "WebSocket", "TotalNetworkBytes", "ContentEncoding", "ProxyResolution", "Reporting", "NetworkErrorLogging" are strong indicators.

3. **Examine the test logic:**  For each identified feature area, look at the `MockWrite` and `MockRead` arrays. These define the simulated network interactions. Pay attention to the HTTP methods, headers, and status codes being tested.

4. **Look for JavaScript relevance:**  Focus on tests related to WebSockets, as this is the most obvious connection point between the network stack and JavaScript in a browser.

5. **Identify logic and potential user errors:** Tests involving proxy configurations, content encoding, and network errors often highlight areas where things can go wrong, either due to server misconfiguration or user configuration issues.

6. **Trace user actions:** Consider how a user's actions in a browser could trigger the tested scenarios. For example, typing a URL, clicking a link, or a website making a fetch request.

7. **Pay attention to the section number:** The prompt indicates this is part 29 of 34. This means I need to summarize the specific functionality within this snippet, not the entire file.

**Mental Walkthrough of the Code Snippet:**

* **WebSocket over HTTP proxy with authentication:** This tests a specific scenario for establishing a WebSocket connection through a proxy that requires authentication.
* **WebSocket over QUIC proxy (not supported):**  This tests that WebSocket connections are not attempted over QUIC proxies.
* **Total network bytes for POST requests:**  These tests verify the correct calculation of sent and received bytes for POST requests, including scenarios with and without "100 Continue" responses, and chunked encoding.
* **Content encoding matching:** These tests verify that the network stack correctly handles `Accept-Encoding` and `Content-Encoding` headers, including redirect scenarios where mismatch is allowed.
* **Proxy resolution failures:** These tests cover synchronous and asynchronous failures during proxy resolution.
* **No supported proxies:** This tests the case where the configured proxies are not usable for the requested protocol.
* **Reporting API tests:**  These tests focus on the `Report-To` header and how the browser handles reporting policies.
* **Network Error Logging (NEL) tests:** These tests examine how the browser processes the `NEL` header and generates error reports for various network issues.

**Constraint Checklist & Confidence Score:**

* Provide functionality? Yes.
* JavaScript relationship? Yes.
* JavaScript examples? Yes.
* Logical inference? Yes.
* Input/output examples? Yes.
* User/programming errors? Yes.
* User operation steps? Yes.
* Part of larger file? Yes.
* Summarize section? Yes.

Confidence Score: 5/5

**Overall Strategy:**  Summarize each test case group, highlighting its purpose and any connections to JavaScript, user errors, or logical inferences. Be specific to the code provided in this section.
这个 Chromium 网络栈的 C++ 源代码文件 `net/http/http_network_transaction_unittest.cc` 的第 29 部分，主要集中在以下几个方面的功能测试：

**1. WebSocket 通过 HTTP 代理 (带认证):**

*   **功能:** 测试通过需要身份验证的 HTTP 代理建立 WebSocket 连接的过程。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  一个 WebSocket 连接请求，需要通过一个需要 Basic 认证的 HTTP 代理。代理服务器的地址是 `http://myproxy:70/`，用户名为 `foo`，密码为 `bar`。
    *   **预期输出:**  `HttpNetworkTransaction` 能够成功完成握手，返回 HTTP 状态码 101 (Switching Protocols)。
*   **用户或编程常见错误:**  用户配置错误的代理服务器地址、端口，或者错误的用户名密码会导致连接失败。开发者在代码中错误地配置 `Proxy-Authorization` 头信息也会导致认证失败。
*   **用户操作步骤 (调试线索):**
    1. 用户尝试访问一个 `ws://` 或 `wss://` 的 URL。
    2. 浏览器检测到需要使用代理服务器。
    3. 浏览器尝试与代理服务器建立连接 (可能首先发起一个 `CONNECT` 请求建立隧道)。
    4. 代理服务器返回 407 (Proxy Authentication Required)。
    5. 浏览器在请求头中添加 `Proxy-Authorization` 头信息，包含认证信息。
    6. 代理服务器验证认证信息，如果成功，建立隧道。
    7. 浏览器通过隧道发送 WebSocket 握手请求。
    8. 服务器返回 101 状态码，WebSocket 连接建立。

**2. WebSocket 不能通过 QUIC 代理:**

*   **功能:** 测试确认 WebSocket 连接不会尝试通过 QUIC 协议的代理服务器。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 一个 WebSocket 连接请求 (`ws://` 或 `wss://`)，并且网络配置中指定使用 QUIC 代理服务器。
    *   **预期输出:** `HttpNetworkTransaction` 会返回错误 `ERR_NO_SUPPORTED_PROXIES`，因为它不支持通过 QUIC 代理进行 WebSocket 连接。
*   **用户或编程常见错误:**  用户或系统管理员错误地配置了 QUIC 代理作为 WebSocket 连接的代理。
*   **用户操作步骤 (调试线索):**
    1. 用户尝试访问一个 `ws://` 或 `wss://` 的 URL。
    2. 浏览器检测到需要使用代理服务器，且配置的代理是 QUIC 协议的。
    3. 由于不支持 WebSocket over QUIC 代理，连接尝试失败。

**3. 计算 POST 请求的总网络字节数:**

*   **功能:** 测试 `HttpNetworkTransaction` 能否正确计算 POST 请求发送和接收的总字节数。测试了普通 POST 请求，包含请求头和请求体，以及接收到的响应头和响应体。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 一个带有请求体的 POST 请求，例如发送字符串 "foo"。
    *   **预期输出:** `GetTotalSentBytes()` 返回发送的请求头和请求体的总字节数，`GetTotalReceivedBytes()` 返回接收到的响应头和响应体的总字节数。
*   **用户或编程常见错误:**  这个测试主要关注内部实现，用户不太可能直接触发此类错误。开发者在计算网络字节数时可能存在逻辑错误。
*   **用户操作步骤 (调试线索):**
    1. 用户在网页上提交一个表单，使用 POST 方法。
    2. 或者 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 发送 POST 请求。
    3. 浏览器构建 HTTP 请求，包含请求头和请求体。
    4. 服务器返回响应。
    5. `HttpNetworkTransaction` 记录发送和接收的字节数。

**4. 计算带有 "100 Continue" 响应的 POST 请求的总网络字节数:**

*   **功能:** 测试 `HttpNetworkTransaction` 在接收到 "100 Continue" 临时响应后，仍然能正确计算 POST 请求发送和接收的总字节数。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 一个带有请求体的 POST 请求，服务器先返回 "100 Continue"，然后返回最终的 200 OK 响应。
    *   **预期输出:**  `GetTotalSentBytes()` 和 `GetTotalReceivedBytes()` 会分别计算所有发送和接收的字节数，包括 "100 Continue" 响应的字节。
*   **用户或编程常见错误:**  类似于上面的情况，主要关注内部实现。服务器可能错误地发送或不发送 "100 Continue" 响应。
*   **用户操作步骤 (调试线索):**  与上述 POST 请求类似，但服务器端配置了在接收到请求头后发送 "100 Continue" 响应。

**5. 计算分块 (Chunked) POST 请求的总网络字节数:**

*   **功能:** 测试 `HttpNetworkTransaction` 能否正确计算使用分块传输编码的 POST 请求的发送和接收字节数。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  一个使用分块传输编码的 POST 请求，例如分块发送 "f" 和 "oo"。
    *   **预期输出:** `GetTotalSentBytes()` 会计算请求头以及所有数据块的字节数，包括分块的元数据 (大小信息等)。`GetTotalReceivedBytes()` 类似。
*   **用户或编程常见错误:**  开发者在代码中错误地使用了分块传输编码，或者服务器端处理分块请求时出现错误。
*   **用户操作步骤 (调试线索):**
    1. JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 发送 POST 请求，并明确指定使用分块传输编码，或者浏览器在无法确定内容长度时自动使用。
    2. 浏览器将请求体分成多个块进行发送。

**6. 检查 Content-Encoding 的匹配:**

*   **功能:** 测试 `HttpNetworkTransaction` 如何根据请求头的 `Accept-Encoding` 和响应头的 `Content-Encoding` 来判断是否需要进行内容解码。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**
        *   请求头包含 `Accept-Encoding: gzip,sdch`，响应头包含 `Content-Encoding: br`。
        *   请求头包含 `Accept-Encoding: identity;q=1, *;q=0`，响应头不包含 `Content-Encoding`。
        *   请求头包含 `Accept-Encoding: identity;q=1, *;q=0`，响应头包含 `Content-Encoding: gzip`。
        *   请求头包含 `Accept-Encoding: identity;q=1, *;q=0`，响应头包含 `Content-Encoding: gzip`，且是重定向响应。
    *   **预期输出:**  在需要解码但不支持的编码情况下，返回 `ERR_CONTENT_DECODING_FAILED` 错误。在允许不解码或支持解码的情况下，请求成功。重定向时，即使编码不匹配也可能被允许。
*   **用户或编程常见错误:**  服务器配置错误的 `Content-Encoding`，与客户端 `Accept-Encoding` 不匹配。开发者错误地设置了 `Accept-Encoding` 请求头。
*   **用户操作步骤 (调试线索):**
    1. 用户请求一个网页或资源。
    2. 浏览器根据自身支持的压缩算法设置 `Accept-Encoding` 请求头。
    3. 服务器返回响应，并在 `Content-Encoding` 头中指定使用的压缩算法。
    4. 浏览器检查这两个头是否匹配，如果需要解码但不支持，则会报错。

**7. 代理解析失败:**

*   **功能:** 测试同步和异步代理解析失败的情况，特别是当 PAC 脚本配置为强制执行时。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  系统配置了一个强制执行的 PAC 文件，但 PAC 文件的解析或执行失败。
    *   **预期输出:**  `HttpNetworkTransaction` 会返回错误 `ERR_MANDATORY_PROXY_CONFIGURATION_FAILED`。
*   **用户或编程常见错误:**  用户配置了错误的 PAC 文件 URL，或者 PAC 文件本身存在语法错误或运行时错误。
*   **用户操作步骤 (调试线索):**
    1. 用户或系统管理员配置了使用 PAC 文件来解析代理。
    2. 浏览器尝试下载或解析 PAC 文件。
    3. 如果下载或解析失败，连接尝试失败。

**8. 没有支持的代理:**

*   **功能:** 测试当配置的代理服务器协议不受支持时的情况。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  配置了 QUIC 代理，但 QUIC 协议未启用。
    *   **预期输出:**  `HttpNetworkTransaction` 会返回错误 `ERR_NO_SUPPORTED_PROXIES`。
*   **用户或编程常见错误:**  用户或系统管理员配置了不兼容的代理协议。
*   **用户操作步骤 (调试线索):**
    1. 用户配置了代理服务器。
    2. 浏览器尝试使用配置的代理连接，但发现该协议当前不可用或未启用。

**9. Reporting API 测试 (BUILDFLAG(ENABLE_REPORTING)):**

*   **功能:**  测试 `Report-To` 响应头处理，用于配置 Reporting API 的策略。
*   **JavaScript 关系:** Reporting API 是浏览器向服务器报告错误和性能指标的一种机制，JavaScript 可以通过 `navigator.sendBeacon()` 等 API 触发报告。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  一个 HTTPS 响应头包含 `Report-To` 头信息，指定了一个报告的端点。
    *   **预期输出:**  浏览器会解析 `Report-To` 头，并将报告策略存储起来，以便后续可以向指定的端点发送报告。
*   **用户或编程常见错误:**  服务器配置错误的 `Report-To` 头信息，导致浏览器无法正确解析策略。
*   **用户操作步骤 (调试线索):**
    1. 用户访问一个启用了 Reporting API 的 HTTPS 网站。
    2. 服务器在响应头中包含 `Report-To` 头信息。
    3. 浏览器解析并存储该策略。

**10. 网络错误日志 (NEL) 测试 (BUILDFLAG(ENABLE_REPORTING)):**

*   **功能:** 测试 `NEL` 响应头处理以及网络错误的记录。
*   **JavaScript 关系:** Network Error Logging (NEL) 是一种让网站能够接收到用户在访问他们网站时遇到的网络错误报告的机制。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**
        *   一个 HTTPS 响应头包含 `NEL` 头信息。
        *   发生 DNS 解析错误、连接错误、或读取响应体错误等网络问题。
    *   **预期输出:**  浏览器会解析 `NEL` 头，存储 NEL 策略。当发生网络错误时，浏览器会根据 NEL 策略生成错误报告。
*   **用户或编程常见错误:**  服务器配置错误的 `NEL` 头信息。网络环境不稳定导致各种网络错误。
*   **用户操作步骤 (调试线索):**
    1. 用户访问一个启用了 NEL 的 HTTPS 网站。
    2. 服务器在响应头中包含 `NEL` 头信息。
    3. 如果用户在访问过程中遇到网络错误 (例如 DNS 解析失败)，浏览器会记录这些错误。

**总结第 29 部分的功能:**

这部分单元测试主要覆盖了 `HttpNetworkTransaction` 在处理 WebSocket 连接（特别是通过代理）、计算网络传输字节数、处理内容编码协商、处理代理解析以及支持 Reporting API 和 Network Error Logging (NEL) 方面的功能。它着重测试了在各种网络场景下 `HttpNetworkTransaction` 的正确行为和错误处理机制。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第29部分，共34部分，请归纳一下它的功能

"""
     "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead data_reads[] = {
      // HTTP CONNECT with credentials.
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      // WebSocket connection established inside tunnel.
      MockRead("HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  session->http_auth_cache()->Add(
      url::SchemeHostPort(GURL("http://myproxy:70/")), HttpAuth::AUTH_PROXY,
      "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
      "Basic realm=MyRealm1", AuthCredentials(kFoo, kBar), "/");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);

  EXPECT_EQ(101, response->headers->response_code());

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// WebSockets over QUIC is not supported, including over QUIC proxies.
TEST_P(HttpNetworkTransactionTest, WebSocketNotSentOverQuicProxy) {
  for (bool secure : {true, false}) {
    SCOPED_TRACE(secure);
    session_deps_.proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
            {ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                               "myproxy.org", 443)},
            TRAFFIC_ANNOTATION_FOR_TESTS);
    session_deps_.enable_quic = true;

    HttpRequestInfo request;
    request.url =
        GURL(secure ? "ws://www.example.org/" : "wss://www.example.org/");
    AddWebSocketHeaders(&request.extra_headers);
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    TestWebSocketHandshakeStreamCreateHelper
        websocket_handshake_stream_create_helper;

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkTransaction trans(LOW, session.get());
    trans.SetWebSocketHandshakeStreamCreateHelper(
        &websocket_handshake_stream_create_helper);

    TestCompletionCallback callback;
    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsError(ERR_NO_SUPPORTED_PROXIES));
  }
}

#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

TEST_P(HttpNetworkTransactionTest, TotalNetworkBytesPost) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("foo")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite("foo"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  std::string response_data;
  EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

  EXPECT_EQ(CountWriteBytes(data_writes), trans.GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(data_reads), trans.GetTotalReceivedBytes());
}

TEST_P(HttpNetworkTransactionTest, TotalNetworkBytesPost100Continue) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("foo")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite("foo"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 100 Continue\r\n\r\n"),
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  std::string response_data;
  EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

  EXPECT_EQ(CountWriteBytes(data_writes), trans.GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(data_reads), trans.GetTotalReceivedBytes());
}

TEST_P(HttpNetworkTransactionTest, TotalNetworkBytesChunkedPost) {
  ChunkedUploadDataStream upload_data_stream(0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite("1\r\nf\r\n"),
      MockWrite("2\r\noo\r\n"),
      MockWrite("0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));

  base::RunLoop().RunUntilIdle();
  upload_data_stream.AppendData(base::byte_span_from_cstring("f"), false);

  base::RunLoop().RunUntilIdle();
  upload_data_stream.AppendData(base::byte_span_from_cstring("oo"), true);

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  std::string response_data;
  EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

  EXPECT_EQ(CountWriteBytes(data_writes), trans.GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(data_reads), trans.GetTotalReceivedBytes());
}

void CheckContentEncodingMatching(SpdySessionDependencies* session_deps,
                                  const std::string& accept_encoding,
                                  const std::string& content_encoding,
                                  const std::string& location,
                                  bool should_match) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.extra_headers.SetHeader(HttpRequestHeaders::kAcceptEncoding,
                                  accept_encoding);
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(session_deps));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Accept-Encoding: "),
      MockWrite(accept_encoding.data()),
      MockWrite("\r\n\r\n"),
  };

  std::string response_code = "200 OK";
  std::string extra;
  if (!location.empty()) {
    response_code = "301 Redirect\r\nLocation: ";
    response_code.append(location);
  }

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 "),
      MockRead(response_code.data()),
      MockRead("\r\nContent-Encoding: "),
      MockRead(content_encoding.data()),
      MockRead("\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps->socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  if (should_match) {
    EXPECT_THAT(rv, IsOk());
  } else {
    EXPECT_THAT(rv, IsError(ERR_CONTENT_DECODING_FAILED));
  }
}

TEST_P(HttpNetworkTransactionTest, MatchContentEncoding1) {
  CheckContentEncodingMatching(&session_deps_, "gzip,sdch", "br", "", false);
}

TEST_P(HttpNetworkTransactionTest, MatchContentEncoding2) {
  CheckContentEncodingMatching(&session_deps_, "identity;q=1, *;q=0", "", "",
                               true);
}

TEST_P(HttpNetworkTransactionTest, MatchContentEncoding3) {
  CheckContentEncodingMatching(&session_deps_, "identity;q=1, *;q=0", "gzip",
                               "", false);
}

TEST_P(HttpNetworkTransactionTest, MatchContentEncoding4) {
  CheckContentEncodingMatching(&session_deps_, "identity;q=1, *;q=0", "gzip",
                               "www.foo.com/other", true);
}

TEST_P(HttpNetworkTransactionTest, ProxyResolutionFailsSync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  MockAsyncProxyResolver resolver;
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(

          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<FailingProxyResolverFactory>(), nullptr,
          /*quick_check_enabled=*/true);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(),
              IsError(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
}

TEST_P(HttpNetworkTransactionTest, ProxyResolutionFailsAsync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  auto proxy_resolver_factory =
      std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* proxy_resolver_factory_ptr = proxy_resolver_factory.get();
  MockAsyncProxyResolver resolver;
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(

          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::move(proxy_resolver_factory), nullptr,
          /*quick_check_enabled=*/true);
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  proxy_resolver_factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(
      ERR_FAILED, &resolver);
  EXPECT_THAT(callback.WaitForResult(),
              IsError(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
}

TEST_P(HttpNetworkTransactionTest, NoSupportedProxies) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                             "myproxy.org", 443)},
          TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.enable_quic = false;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_NO_SUPPORTED_PROXIES));
}

//-----------------------------------------------------------------------------
// Reporting tests

#if BUILDFLAG(ENABLE_REPORTING)
class HttpNetworkTransactionReportingTest
    : public HttpNetworkTransactionTestBase,
      public ::testing::WithParamInterface<bool> {
 protected:
  HttpNetworkTransactionReportingTest() {
    std::vector<base::test::FeatureRef> required_features = {
        features::kPartitionConnectionsByNetworkIsolationKey};
    if (UseDocumentReporting()) {
      required_features.push_back(features::kDocumentReporting);
    }
    feature_list_.InitWithFeatures(required_features, {});
  }

  void SetUp() override {
    HttpNetworkTransactionTestBase::SetUp();
    auto test_reporting_context = std::make_unique<TestReportingContext>(
        &clock_, &tick_clock_, ReportingPolicy());
    test_reporting_context_ = test_reporting_context.get();
    session_deps_.reporting_service =
        ReportingService::CreateForTesting(std::move(test_reporting_context));
  }

  TestReportingContext* reporting_context() const {
    return test_reporting_context_;
  }

  void TearDown() override {
    clear_reporting_service();
    HttpNetworkTransactionTestBase::TearDown();
  }
  void clear_reporting_service() {
    test_reporting_context_ = nullptr;
    session_deps_.reporting_service.reset();
  }

  // Makes an HTTPS request that should install a valid Reporting policy
  // using Report-To header.
  void RequestPolicy(CertStatus cert_status = 0) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL(url_);
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    request.network_isolation_key = kNetworkIsolationKey;
    request.network_anonymization_key = kNetworkAnonymizationKey;
    MockWrite data_writes[] = {
        MockWrite("GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    MockRead reporting_header;
    reporting_header = MockRead(
        "Report-To: {\"group\": \"nel\", \"max_age\": 86400, "
        "\"endpoints\": [{\"url\": "
        "\"https://www.example.org/upload/\"}]}\r\n");
    MockRead data_reads[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        std::move(reporting_header),
        MockRead("\r\n"),
        MockRead("hello world"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider reads(data_reads, data_writes);
    session_deps_.socket_factory->AddSocketDataProvider(&reads);

    SSLSocketDataProvider ssl(ASYNC, OK);
    if (request.url.SchemeIsCryptographic()) {
      ssl.ssl_info.cert =
          ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
      ASSERT_TRUE(ssl.ssl_info.cert);
      ssl.ssl_info.cert_status = cert_status;
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
    }

    TestCompletionCallback callback;
    auto session = CreateSession(&session_deps_);
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
  }

 protected:
  bool UseDocumentReporting() const { return GetParam(); }
  std::string url_ = "https://www.example.org/";

 private:
  base::test::ScopedFeatureList feature_list_;
  raw_ptr<TestReportingContext> test_reporting_context_ = nullptr;
};

TEST_P(HttpNetworkTransactionReportingTest,
       DontProcessReportToHeaderNoService) {
  clear_reporting_service();
  RequestPolicy();
  // No crash.
}

TEST_P(HttpNetworkTransactionReportingTest, DontProcessReportToHeaderHttp) {
  url_ = "http://www.example.org/";
  RequestPolicy();
  EXPECT_EQ(0u, reporting_context()->cache()->GetEndpointCount());
}

TEST_P(HttpNetworkTransactionReportingTest, ProcessReportToHeaderHttps) {
  RequestPolicy();
  ASSERT_EQ(1u, reporting_context()->cache()->GetEndpointCount());
  const ReportingEndpoint endpoint =
      reporting_context()->cache()->GetEndpointForTesting(
          ReportingEndpointGroupKey(
              kNetworkAnonymizationKey,
              url::Origin::Create(GURL("https://www.example.org/")), "nel",
              ReportingTargetType::kDeveloper),
          GURL("https://www.example.org/upload/"));
  EXPECT_TRUE(endpoint);
}

TEST_P(HttpNetworkTransactionReportingTest,
       DontProcessReportToHeaderInvalidHttps) {
  CertStatus cert_status = CERT_STATUS_COMMON_NAME_INVALID;
  RequestPolicy(cert_status);
  EXPECT_EQ(0u, reporting_context()->cache()->GetEndpointCount());
}

INSTANTIATE_TEST_SUITE_P(All,
                         HttpNetworkTransactionReportingTest,
                         ::testing::Bool());

#endif  // BUILDFLAG(ENABLE_REPORTING)

//-----------------------------------------------------------------------------
// Network Error Logging tests

#if BUILDFLAG(ENABLE_REPORTING)
namespace {

const char kUserAgent[] = "Mozilla/1.0";
const char kReferrer[] = "https://www.referrer.org/";

}  // namespace

class HttpNetworkTransactionNetworkErrorLoggingTest
    : public HttpNetworkTransactionTest {
 protected:
  void SetUp() override {
    HttpNetworkTransactionTestBase::SetUp();
    auto network_error_logging_service =
        std::make_unique<TestNetworkErrorLoggingService>();
    test_network_error_logging_service_ = network_error_logging_service.get();
    session_deps_.network_error_logging_service =
        std::move(network_error_logging_service);

    extra_headers_.SetHeader("User-Agent", kUserAgent);
    extra_headers_.SetHeader("Referer", kReferrer);

    request_.method = "GET";
    request_.url = GURL(url_);
    request_.network_isolation_key = kNetworkIsolationKey;
    request_.network_anonymization_key = kNetworkAnonymizationKey;
    request_.extra_headers = extra_headers_;
    request_.reporting_upload_depth = reporting_upload_depth_;
    request_.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  void TearDown() override {
    clear_network_error_logging_service();
    HttpNetworkTransactionTestBase::TearDown();
  }

  TestNetworkErrorLoggingService* network_error_logging_service() const {
    return test_network_error_logging_service_;
  }

  void clear_network_error_logging_service() {
    test_network_error_logging_service_ = nullptr;
    session_deps_.network_error_logging_service.reset();
  }

  // Makes an HTTPS request that should install a valid NEL policy.
  void RequestPolicy(CertStatus cert_status = 0) {
    std::string extra_header_string = extra_headers_.ToString();
    MockWrite data_writes[] = {
        MockWrite("GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"),
        MockWrite(ASYNC, extra_header_string.data(),
                  extra_header_string.size()),
    };
    MockRead data_reads[] = {
        MockRead("HTTP/1.0 200 OK\r\n"),
        MockRead("NEL: {\"report_to\": \"nel\", \"max_age\": 86400}\r\n"),
        MockRead("\r\n"),
        MockRead("hello world"),
        MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider reads(data_reads, data_writes);
    session_deps_.socket_factory->AddSocketDataProvider(&reads);

    SSLSocketDataProvider ssl(ASYNC, OK);
    if (request_.url.SchemeIsCryptographic()) {
      ssl.ssl_info.cert =
          ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
      ASSERT_TRUE(ssl.ssl_info.cert);
      ssl.ssl_info.cert_status = cert_status;
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
    }

    TestCompletionCallback callback;
    auto session = CreateSession(&session_deps_);
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
    int rv = trans.Start(&request_, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    std::string response_data;
    ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
    EXPECT_EQ("hello world", response_data);
  }

  void CheckReport(size_t index,
                   int status_code,
                   int error_type,
                   IPAddress server_ip = IPAddress::IPv4Localhost()) {
    ASSERT_LT(index, network_error_logging_service()->errors().size());

    const NetworkErrorLoggingService::RequestDetails& error =
        network_error_logging_service()->errors()[index];
    EXPECT_EQ(url_, error.uri);
    EXPECT_EQ(kNetworkAnonymizationKey, error.network_anonymization_key);
    EXPECT_EQ(kReferrer, error.referrer);
    EXPECT_EQ(kUserAgent, error.user_agent);
    EXPECT_EQ(server_ip, error.server_ip);
    EXPECT_EQ("http/1.1", error.protocol);
    EXPECT_EQ("GET", error.method);
    EXPECT_EQ(status_code, error.status_code);
    EXPECT_EQ(error_type, error.type);
    EXPECT_EQ(0, error.reporting_upload_depth);
  }

 protected:
  std::string url_ = "https://www.example.org/";
  CertStatus cert_status_ = 0;
  HttpRequestInfo request_;
  HttpRequestHeaders extra_headers_;
  int reporting_upload_depth_ = 0;

 private:
  raw_ptr<TestNetworkErrorLoggingService> test_network_error_logging_service_ =
      nullptr;
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpNetworkTransactionNetworkErrorLoggingTest,
                         testing::ValuesIn(GetTestParams()));

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       DontProcessNelHeaderNoService) {
  clear_network_error_logging_service();
  RequestPolicy();
  // No crash.
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       DontProcessNelHeaderHttp) {
  url_ = "http://www.example.org/";
  request_.url = GURL(url_);
  RequestPolicy();
  EXPECT_EQ(0u, network_error_logging_service()->headers().size());
}

// Don't set NEL policies received on a proxied connection.
TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       DontProcessNelHeaderProxy) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
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
      MockRead("NEL: {\"report_to\": \"nel\", \"max_age\": 86400}\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  ssl.ssl_info.cert_status = 0;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_TRUE(response->WasFetchedViaProxy());

  // No NEL header was set.
  EXPECT_EQ(0u, network_error_logging_service()->headers().size());
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest, ProcessNelHeaderHttps) {
  RequestPolicy();
  ASSERT_EQ(1u, network_error_logging_service()->headers().size());
  const auto& header = network_error_logging_service()->headers()[0];
  EXPECT_EQ(kNetworkAnonymizationKey, header.network_anonymization_key);
  EXPECT_EQ(url::Origin::Create(GURL("https://www.example.org/")),
            header.origin);
  EXPECT_EQ(IPAddress::IPv4Localhost(), header.received_ip_address);
  EXPECT_EQ("{\"report_to\": \"nel\", \"max_age\": 86400}", header.value);
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       DontProcessNelHeaderInvalidHttps) {
  CertStatus cert_status = CERT_STATUS_COMMON_NAME_INVALID;
  RequestPolicy(cert_status);
  EXPECT_EQ(0u, network_error_logging_service()->headers().size());
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest, CreateReportSuccess) {
  RequestPolicy();
  ASSERT_EQ(1u, network_error_logging_service()->errors().size());
  CheckReport(0 /* index */, 200 /* status_code */, OK);
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       CreateReportDNSErrorAfterStartSync) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.host_resolver->rules()->AddRule(GURL(url_).host(),
                                                ERR_NAME_NOT_RESOLVED);
  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_NAME_NOT_RESOLVED));

  trans.reset();

  ASSERT_EQ(1u, network_error_logging_service()->errors().size());
  CheckReport(0 /* index */, 0 /* status_code */, ERR_NAME_NOT_RESOLVED,
              IPAddress() /* server_ip */);
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       CreateReportDNSErrorAfterStartAsync) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  session_deps_.host_resolver->set_synchronous_mode(false);
  session_deps_.host_resolver->rules()->AddRule(GURL(url_).host(),
                                                ERR_NAME_NOT_RESOLVED);
  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_NAME_NOT_RESOLVED));

  trans.reset();

  ASSERT_EQ(1u, network_error_logging_service()->errors().size());
  CheckReport(0 /* index */, 0 /* status_code */, ERR_NAME_NOT_RESOLVED,
              IPAddress() /* server_ip */);
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       CreateReportErrorAfterStart) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockConnect mock_connect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider data;
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));

  trans.reset();

  ASSERT_EQ(1u, network_error_logging_service()->errors().size());
  CheckReport(0 /* index */, 0 /* status_code */, ERR_CONNECTION_REFUSED,
              IPAddress::IPv4Localhost() /* server_ip */);
}

// Same as above except the error is ASYNC
TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       CreateReportErrorAfterStartAsync) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider data;
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));

  trans.reset();

  ASSERT_EQ(1u, network_error_logging_service()->errors().size());
  CheckReport(0 /* index */, 0 /* status_code */, ERR_CONNECTION_REFUSED,
              IPAddress::IPv4Localhost() /* server_ip */);
}

TEST_P(HttpNetworkTransactionNetworkErrorLoggingTest,
       CreateReportReadBodyError) {
  std::string extra_header_string = extra_headers_.ToString();
  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"),
      MockWrite(ASYNC, extra_header_string.data(), extra_header_string.size()),
  };
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),  // wrong content length
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider reads(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&reads);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // Log start time
  base::TimeTicks start_time = base::TimeTicks::Now();

  TestCompletionCallback callback;
  auto session = CreateSession(&session_deps_);
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, se
"""


```