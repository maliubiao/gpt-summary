Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `http_network_transaction_unittest.cc` file. They are interested in:

1. **General functionality:** What does this code do?
2. **Relationship to JavaScript:** Does it interact with JavaScript, and how?
3. **Logical inference:** Can we deduce inputs and outputs based on the code?
4. **Common user/programming errors:** What mistakes can lead to this code being executed?
5. **User journey for debugging:** How does a user's action lead to this code being relevant during debugging?
6. **Summary of functionality (part 16 of 34):** Condense the functionality covered in this specific snippet.

Let's break down the code section by section to address these points.

**Code Breakdown and Analysis:**

* **NTLM Authentication with WebSocket:** The first test case `NTLMAuthOverWebSocket` tests the scenario where a WebSocket handshake requires NTLM authentication. It sets up a WebSocket request with specific headers, attempts the handshake, receives an authentication challenge, and then retries with credentials. Finally, it checks if the server is marked as requiring HTTP/1.1.

* **NTLM Proxy and TLS Reset:** The `NTLMProxyTLSHandshakeReset` test deals with a scenario involving an NTLM proxy and a connection reset during the TLS handshake. It simulates the sequence of CONNECT requests, authentication challenges and responses, and then introduces an `ERR_CONNECTION_RESET` during the SSL handshake to test the fallback mechanism.

* **Large Headers:** The `LargeHeadersNoBody` test checks how the system handles a response with excessively large headers but no body. It expects the transaction to fail with `ERR_RESPONSE_HEADERS_TOO_BIG`.

* **Socket Recycling (Tunnel Failure):** The `DontRecycleTransportSocketForSSLTunnel` test verifies that a transport socket used for a failed SSL tunnel establishment is *not* recycled.

* **Socket Recycling (Successful Request):** The `RecycleSocket` and `RecycleSSLSocket` tests demonstrate the normal socket recycling behavior after a successful HTTP or HTTPS request where the entire response body is read.

* **Recycling "Dead" SSL Socket:** The `RecycleDeadSSLSocket` test simulates a scenario where an SSL socket is recycled, but the connection is closed by the server. The next request reuses the socket and should handle the error correctly.

* **Closing Connection on Destruction:** The `CloseConnectionOnDestruction` test checks the behavior of the `CloseConnectionOnDestruction` method, ensuring that the underlying socket is properly handled when the `HttpNetworkTransaction` is destroyed, especially in different stages of response reading (headers only, partial body, full body).

* **Flushing Socket Pool on Low Memory:** The `FlushSocketPoolOnLowMemoryNotifications` and `FlushSSLSocketPoolOnLowMemoryNotifications` tests examine how the socket pool reacts to low-memory notifications. They verify that idle sockets are closed to free up resources. The `NoFlushSocketPoolOnLowMemoryNotifications` test checks the scenario where this behavior is explicitly disabled.

* **Recycling After Zero-Length Response:** The `RecycleSocketAfterZeroContentLength` test confirms that sockets are correctly recycled even after receiving a response with a `Content-Length: 0`.

**Answering the User's Questions:**

1. **Functionality:** This code contains unit tests for the `HttpNetworkTransaction` class in Chromium's network stack. It tests various scenarios related to:
    * Authentication (NTLM, including over WebSockets)
    * Proxy connections
    * Handling connection errors and resets
    * Managing socket resources (recycling, closing on destruction, flushing on low memory)
    * Handling large headers
    * Handling zero-length responses

2. **Relationship to JavaScript:** While this C++ code doesn't directly execute JavaScript, it underpins the network functionality that JavaScript uses in web browsers. For example:
    * **`NTLMAuthOverWebSocket`:**  JavaScript using the `WebSocket` API might encounter NTLM authentication challenges, and this test ensures the underlying network layer handles it correctly. A user visiting an intranet site requiring NTLM authentication via a WebSocket connection would trigger this flow.
    * **`LargeHeadersNoBody`:** If a JavaScript application makes an `XMLHttpRequest` or `fetch` request to a server that responds with very large headers, this test ensures the browser's network stack correctly handles the error to prevent potential denial-of-service scenarios.

3. **Logical Inference:**
    * **`NTLMAuthOverWebSocket`:**
        * **Input (Hypothetical):** A WebSocket request initiated by the browser to a server requiring NTLM authentication. The server responds with a `401` (or similar) status code and an NTLM authentication challenge in the `WWW-Authenticate` header. The user has NTLM credentials stored.
        * **Output:** The test verifies that the `HttpNetworkTransaction` correctly handles the authentication handshake, sends the necessary NTLM messages, and eventually establishes the WebSocket connection. It also verifies that the server is marked as requiring HTTP/1.1.
    * **`LargeHeadersNoBody`:**
        * **Input (Hypothetical):** An HTTP GET request to a server that is configured to respond with a large number of headers (e.g., for tracking purposes or due to misconfiguration).
        * **Output:** The test expects the `HttpNetworkTransaction` to fail with `ERR_RESPONSE_HEADERS_TOO_BIG` before consuming the entire header block.

4. **Common User/Programming Errors:**
    * **Incorrect Proxy Configuration:** If a user's proxy settings are misconfigured (e.g., wrong proxy server address), tests like `NTLMProxyTLSHandshakeReset` might reveal issues in how the browser handles authentication failures or connection resets with proxies.
    * **Server Misconfiguration:** A server sending excessively large headers (as in `LargeHeadersNoBody`) is a server-side error that the browser needs to handle gracefully.
    * **Network Instability:** Intermittent network issues leading to connection resets (simulated in `NTLMProxyTLSHandshakeReset`) are common user-facing problems that the browser needs to handle robustly.
    * **Resource Leaks (Programming Error):** If the `HttpNetworkTransaction` doesn't correctly manage socket resources (e.g., failing to recycle them), it could lead to resource exhaustion over time. The socket recycling tests aim to prevent such programming errors.

5. **User Operation as Debugging Clue:**
    * **"Website not loading" or "Connection timed out":** If a user reports these issues, and the website requires NTLM authentication through a proxy, debugging might involve examining the flow tested in `NTLMProxyTLSHandshakeReset`. Network logs could show the sequence of authentication attempts and the point of failure (e.g., the TLS reset).
    * **"Page is blank" or "Incomplete content":** If a server is misconfigured and sends very large headers, the browser might fail to load the page, leading to the scenario tested in `LargeHeadersNoBody`.
    * **"Too many open connections" (less common for typical users):**  While less directly user-facing, if developers notice excessive resource usage, the socket recycling tests become relevant to ensure the browser isn't leaking sockets.
    * **Browser crashing or becoming unresponsive:** In extreme cases of resource mismanagement (which the low-memory tests aim to prevent), the browser could become unstable.

6. **Summary of Functionality (Part 16):** This section of the unit tests for `HttpNetworkTransaction` focuses on:
    * **NTLM authentication over WebSockets.**
    * **Handling connection resets during TLS handshakes when using an NTLM proxy.**
    * **Enforcing limits on the size of response headers.**
    * **Properly managing and recycling TCP and SSL sockets in various scenarios, including tunnel failures, successful requests, and "dead" connections.**
    * **Controlling socket lifecycle on object destruction and in response to low-memory conditions.**
    * **Ensuring correct socket recycling after receiving zero-length content responses.**

In essence, this section tests the robustness and efficiency of the `HttpNetworkTransaction` class in handling various network conditions, authentication schemes, and resource management requirements.

这是文件 `net/http/http_network_transaction_unittest.cc` 的第 16 部分，它主要包含了一系列针对 `HttpNetworkTransaction` 类的单元测试。`HttpNetworkTransaction` 是 Chromium 网络栈中负责执行 HTTP 请求的核心类。

**本部分的功能归纳如下：**

1. **测试通过 WebSocket 进行 NTLM 认证：**  测试了当 WebSocket 握手过程中需要进行 NTLM 认证时，`HttpNetworkTransaction` 的处理流程，包括接收认证质询、使用凭据重新尝试连接，并验证服务器是否被标记为需要 HTTP/1.1。
2. **测试 NTLM 代理和 TLS 握手重置：**  模拟了在使用 NTLM 代理的情况下，如果发生 TLS 握手重置，`HttpNetworkTransaction` 如何避免无限重试，验证了连接回退机制。
3. **测试处理超大响应头的情况：** 验证了当服务器返回的响应头过大但没有响应体时，`HttpNetworkTransaction` 会抛出 `ERR_RESPONSE_HEADERS_TOO_BIG` 错误。
4. **测试 SSL 隧道连接失败时不重用传输层 Socket：** 确保在建立 SSL 隧道的过程中如果失败，底层的 TCP Socket 不会被放回连接池中重用。
5. **测试成功读取完整响应体后 Socket 的回收：**  验证了在成功完成 HTTP 请求并读取了完整的响应体后，底层的 Socket 会被正确回收并放回连接池。
6. **测试成功读取完整响应体的 SSL Socket 的回收：** 与上一条类似，但针对 HTTPS 请求，验证了 SSL Socket 的回收机制。
7. **测试回收失效的 SSL Socket：** 模拟了一个 SSL Socket 被回收后，但连接实际上已经关闭的情况，验证了后续请求可以正确处理这种情况。
8. **测试在销毁时关闭连接：**  验证了 `HttpNetworkTransaction` 对象销毁时，可以主动关闭底层连接，并针对读取响应的不同阶段（仅读取头、部分读取体、全部读取体）进行了测试。
9. **测试低内存通知时刷新 Socket 连接池：** 验证了当系统发出低内存通知时，空闲的 Socket 连接会被关闭以释放资源。同时也测试了禁用此特性的情况。
10. **测试低内存通知时刷新 SSL Socket 连接池：** 与上一条类似，但针对 SSL Socket。
11. **测试零长度响应后的 Socket 回收：** 验证了接收到 `Content-Length: 0` 的响应后，底层的 Socket 能够被正确回收。

**与 JavaScript 功能的关系和举例：**

这些测试虽然直接在 C++ 代码中进行，但它们验证了浏览器底层网络功能的核心逻辑，这些逻辑支撑着 JavaScript 发起的网络请求。

* **`NTLMAuthOverWebSocket`:** 当 JavaScript 代码使用 `WebSocket` API 连接到需要 NTLM 认证的服务器时，例如连接到企业内部网的 WebSocket 服务，这个测试保证了底层的网络层能够正确处理认证流程。
* **`LargeHeadersNoBody`:**  如果 JavaScript 使用 `fetch` 或 `XMLHttpRequest` 发起请求，而服务器返回了过大的响应头，这个测试保证了浏览器能够防止潜在的拒绝服务攻击，并向 JavaScript 返回相应的错误。
* **Socket 回收相关的测试:** 当 JavaScript 代码频繁发起网络请求时，底层的 Socket 回收机制的正确性直接影响到浏览器的性能和资源占用。如果 Socket 不能被正确回收，可能会导致连接数耗尽，影响用户体验。

**逻辑推理、假设输入与输出：**

* **`NTLMAuthOverWebSocket`:**
    * **假设输入：** 一个 JavaScript 页面尝试通过 `WebSocket` 连接到 `wss://server/`，服务器要求 NTLM 认证。
    * **输出：**  `HttpNetworkTransaction` 会首先尝试连接，收到 401 或 407 状态码和 NTLM 质询，然后使用用户凭据重新发起连接，最终建立 WebSocket 连接。如果认证失败，则连接失败。测试还会验证服务器的 HTTP/1.1 要求。
* **`LargeHeadersNoBody`:**
    * **假设输入：** JavaScript 使用 `fetch('http://www.example.org/')` 发起一个 GET 请求，服务器响应的头部非常大（例如超过 256KB），但没有响应体。
    * **输出：** `HttpNetworkTransaction::Start()` 或后续的读取操作会返回 `ERR_RESPONSE_HEADERS_TOO_BIG` 错误。

**用户或编程常见的使用错误举例：**

* **代理配置错误：**  用户在操作系统或浏览器中配置了错误的代理服务器地址或端口，可能会导致类似 `NTLMProxyTLSHandshakeReset` 测试中遇到的认证或连接问题。
* **服务器端配置错误：**  服务器端返回了过大的响应头，这通常是服务器端的编程错误或配置问题。
* **网络不稳定：**  网络连接不稳定，导致连接中断或重置，可能会触发 `NTLMProxyTLSHandshakeReset` 测试中模拟的 TLS 握手重置场景。
* **资源泄漏（程序员错误）：** 如果 `HttpNetworkTransaction` 没有正确管理 Socket，例如在错误发生时不释放 Socket，会导致资源泄漏，最终可能导致连接数耗尽。Socket 回收相关的测试就是为了防止这类编程错误。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户尝试访问一个需要 NTLM 认证的 WebSocket 服务：** 用户在浏览器中打开一个网页，该网页中的 JavaScript 代码尝试连接到一个内部网的 WebSocket 服务，该服务需要 NTLM 认证。如果连接失败或出现认证问题，开发者可能会查看网络日志，追踪 `HttpNetworkTransaction` 的行为，并可能发现与 `NTLMAuthOverWebSocket` 测试相关的错误。
2. **用户通过代理访问 HTTPS 网站遇到连接问题：**  用户在配置了代理服务器的情况下，尝试访问一个 HTTPS 网站，但由于网络不稳定或代理服务器的问题，导致 TLS 握手重置。调试时，网络日志可能会显示连接重置的错误，并指向 `HttpNetworkTransaction` 中处理代理和 TLS 的逻辑，例如 `NTLMProxyTLSHandshakeReset` 测试覆盖的场景。
3. **用户访问的网站响应速度很慢或无法加载：** 用户访问某个网站，发现网页加载非常缓慢甚至无法加载。开发者可能会检查网络请求的详细信息，发现响应头非常大，这时就可能与 `LargeHeadersNoBody` 测试相关。
4. **在高负载情况下，浏览器出现连接问题：** 在用户频繁进行网络操作的情况下，如果底层的 Socket 没有被正确回收，可能会导致连接数耗尽，影响浏览器的性能。调试这类问题时，可能会关注 Socket 的生命周期管理，与 Socket 回收相关的测试就提供了这方面的验证。
5. **用户在使用某些功能时，浏览器内存占用过高：**  如果浏览器在低内存环境下没有及时关闭空闲的 Socket 连接，可能会导致内存占用过高。调试这类问题时，与低内存通知和 Socket 池刷新相关的测试就提供了重要的线索。

**总结来说，这部分测试覆盖了 `HttpNetworkTransaction` 在各种复杂网络场景下的核心功能，确保了 Chromium 浏览器在处理认证、代理、错误恢复和资源管理等方面的健壮性和效率，为用户提供稳定可靠的网络体验。**

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第16部分，共34部分，请归纳一下它的功能

"""
rigin", "http://server");
  websocket_request_info.extra_headers.SetHeader("Sec-WebSocket-Version", "13");
  // The following two headers must be removed by WebSocketHttp2HandshakeStream.
  websocket_request_info.extra_headers.SetHeader("Connection", "Upgrade");
  websocket_request_info.extra_headers.SetHeader("Upgrade", "websocket");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction websocket_trans(MEDIUM, session.get());
  websocket_trans.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback websocket_callback;
  rv = websocket_trans.Start(&websocket_request_info,
                             websocket_callback.callback(), NetLogWithSource());
  EXPECT_THAT(websocket_callback.GetResult(rv), IsOk());

  EXPECT_FALSE(websocket_trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = websocket_trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge));

  rv = websocket_trans.RestartWithAuth(
      AuthCredentials(ntlm::test::kDomainUserCombined, ntlm::test::kPassword),
      websocket_callback.callback());
  EXPECT_THAT(websocket_callback.GetResult(rv), IsOk());

  EXPECT_TRUE(websocket_trans.IsReadyToRestartForAuth());

  response = websocket_trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());

  rv = websocket_trans.RestartWithAuth(AuthCredentials(),
                                       websocket_callback.callback());
  EXPECT_THAT(websocket_callback.GetResult(rv), IsOk());

  // The server should have been marked as requiring HTTP/1.1. The important
  // part here is that the scheme that requires HTTP/1.1 should be HTTPS, not
  // WSS.
  EXPECT_TRUE(session->http_server_properties()->RequiresHTTP11(
      url::SchemeHostPort(kInitialUrl), NetworkAnonymizationKey()));
}

#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

// Test that, if we have an NTLM proxy and the origin resets the connection, we
// do no retry forever as a result of TLS retries. This is a regression test for
// https://crbug.com/823387. The version interference probe has since been
// removed, but we now have a legacy crypto fallback. (If that fallback is
// removed, this test should be kept but with the expectations tweaked, in case
// future fallbacks are added.)
TEST_P(HttpNetworkTransactionTest, NTLMProxyTLSHandshakeReset) {
  // The NTLM test data expects the proxy to be named 'server'. The origin is
  // https://origin/.
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY server", TRAFFIC_ANNOTATION_FOR_TESTS);

  SSLContextConfig config;
  session_deps_.ssl_config_service =
      std::make_unique<TestSSLConfigService>(config);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://origin/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Ensure load is not disrupted by flags which suppress behaviour specific
  // to other auth schemes.
  request.load_flags = LOAD_DO_NOT_USE_EMBEDDED_IDENTITY;

  HttpAuthNtlmMechanism::ScopedProcSetter proc_setter(
      MockGetMSTime, MockGenerateRandom, MockGetHostName);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Generate the NTLM messages based on known test data.
  std::string negotiate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kExpectedNegotiateMsg),
      std::size(ntlm::test::kExpectedNegotiateMsg)));
  std::string challenge_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(ntlm::test::kChallengeMsgFromSpecV2),
      std::size(ntlm::test::kChallengeMsgFromSpecV2)));
  std::string authenticate_msg = base::Base64Encode(std::string_view(
      reinterpret_cast<const char*>(
          ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2),
      std::size(ntlm::test::kExpectedAuthenticateMsgEmptyChannelBindingsV2)));

  MockWrite data_writes[] = {
      // The initial CONNECT request.
      MockWrite("CONNECT origin:443 HTTP/1.1\r\n"
                "Host: origin:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      // After restarting with an identity.
      MockWrite("CONNECT origin:443 HTTP/1.1\r\n"
                "Host: origin:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: NTLM "),
      MockWrite(negotiate_msg.c_str()),
      // End headers.
      MockWrite("\r\n\r\n"),

      // The second restart.
      MockWrite("CONNECT origin:443 HTTP/1.1\r\n"
                "Host: origin:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: NTLM "),
      MockWrite(authenticate_msg.c_str()),
      // End headers.
      MockWrite("\r\n\r\n"),
  };

  MockRead data_reads[] = {
      // The initial NTLM response.
      MockRead("HTTP/1.1 407 Access Denied\r\n"
               "Content-Length: 0\r\n"
               "Proxy-Authenticate: NTLM\r\n\r\n"),

      // The NTLM challenge message.
      MockRead("HTTP/1.1 407 Access Denied\r\n"
               "Content-Length: 0\r\n"
               "Proxy-Authenticate: NTLM "),
      MockRead(challenge_msg.c_str()),
      // End headers.
      MockRead("\r\n\r\n"),

      // Finally the tunnel is established.
      MockRead("HTTP/1.1 200 Connected\r\n\r\n"),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  SSLSocketDataProvider data_ssl(ASYNC, ERR_CONNECTION_RESET);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&data_ssl);

  StaticSocketDataProvider data2(data_reads, data_writes);
  SSLSocketDataProvider data2_ssl(ASYNC, ERR_CONNECTION_RESET);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&data2_ssl);

  // Start the transaction. The proxy responds with an NTLM authentication
  // request.
  TestCompletionCallback callback;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = callback.GetResult(
      trans.Start(&request, callback.callback(), NetLogWithSource()));

  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());
  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMProxyAuth(response->auth_challenge));

  // Configure credentials and restart. The proxy responds with the challenge
  // message.
  rv = callback.GetResult(trans.RestartWithAuth(
      AuthCredentials(ntlm::test::kDomainUserCombined, ntlm::test::kPassword),
      callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(trans.IsReadyToRestartForAuth());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());

  // Restart once more. The tunnel will be established and the the SSL handshake
  // will reset. The fallback will then kick in and restart the process. The
  // proxy responds with another NTLM authentiation request, but we don't need
  // to provide credentials as the cached ones work.
  rv = callback.GetResult(
      trans.RestartWithAuth(AuthCredentials(), callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(trans.IsReadyToRestartForAuth());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());

  // The proxy responds with the NTLM challenge message.
  rv = callback.GetResult(
      trans.RestartWithAuth(AuthCredentials(), callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(trans.IsReadyToRestartForAuth());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());

  // Send the NTLM authenticate message. The tunnel is established and the
  // handshake resets again. We should not retry again.
  rv = callback.GetResult(
      trans.RestartWithAuth(AuthCredentials(), callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

#endif  // NTLM_PORTABLE

// Test reading a server response which has only headers, and no body.
// After some maximum number of bytes is consumed, the transaction should
// fail with ERR_RESPONSE_HEADERS_TOO_BIG.
TEST_P(HttpNetworkTransactionTest, LargeHeadersNoBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Respond with 300 kb of headers (we should fail after 256 kb).
  std::string large_headers_string;
  FillLargeHeadersString(&large_headers_string, 300 * 1024);

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead(ASYNC, large_headers_string.data(), large_headers_string.size()),
      MockRead("\r\nBODY"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_RESPONSE_HEADERS_TOO_BIG));
}

// Make sure that we don't try to reuse a TCPClientSocket when failing to
// establish tunnel.
// http://code.google.com/p/chromium/issues/detail?id=3772
TEST_P(HttpNetworkTransactionTest, DontRecycleTransportSocketForSSLTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy responds to the connect with a 404, using a persistent
  // connection. Usually a proxy would return 501 (not implemented),
  // or 200 (tunnel established).
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 404 Not Found\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback1;

  int rv = trans->Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the TCPClientSocket was not added back to
  // the pool.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
  trans.reset();
  base::RunLoop().RunUntilIdle();
  // Make sure that the socket didn't get recycled after calling the destructor.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Make sure that we recycle a socket after reading all of the response body.
TEST_P(HttpNetworkTransactionTest, RecycleSocket) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      // A part of the response body is received with the response headers.
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhel"),
      // The rest of the response body is received in two parts.
      MockRead("lo"),
      MockRead(" world"),
      MockRead("junk"),  // Should not be read!!
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  std::string status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 200 OK", status_line);

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Make sure that we recycle a SSL socket after reading all of the response
// body.
TEST_P(HttpNetworkTransactionTest, RecycleSSLSocket) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 11\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Grab a SSL socket, use it, and put it back into the pool.  Then, reuse it
// from the pool and make sure that we recover okay.
TEST_P(HttpNetworkTransactionTest, RecycleDeadSSLSocket) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead("Content-Length: 11\r\n\r\n"),
      MockRead("hello world"), MockRead(ASYNC, ERR_CONNECTION_CLOSED)};

  SSLSocketDataProvider ssl(ASYNC, OK);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  StaticSocketDataProvider data(data_reads, data_writes);
  StaticSocketDataProvider data2(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

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

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Now start the second transaction, which should reuse the previous socket.

  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  rv = ReadTransaction(trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_P(HttpNetworkTransactionTest, CloseConnectionOnDestruction) {
  enum class TestCase {
    kReadHeaders,
    kReadPartOfBodyRead,
    kReadAllOfBody,
  };

  for (auto test_case : {TestCase::kReadHeaders, TestCase::kReadPartOfBodyRead,
                         TestCase::kReadAllOfBody}) {
    SCOPED_TRACE(testing::Message()
                 << "Test case: " << static_cast<int>(test_case));
    for (bool close_connection : {false, true}) {
      if (test_case != TestCase::kReadAllOfBody || close_connection == false) {
        continue;
      }
      SCOPED_TRACE(testing::Message()
                   << "Close connection: " << close_connection);

      HttpRequestInfo request;
      request.method = "GET";
      request.url = GURL("http://foo.test/");
      request.traffic_annotation =
          MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

      std::unique_ptr<HttpNetworkSession> session(
          CreateSession(&session_deps_));

      std::unique_ptr<HttpNetworkTransaction> trans =
          std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                   session.get());

      MockRead data_reads[] = {
          // A part of the response body is received with the response headers.
          MockRead("HTTP/1.1 200 OK\r\n"
                   "Content-Length: 11\r\n\r\n"
                   "hello world"),
          MockRead(SYNCHRONOUS, OK),
      };

      StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
      session_deps_.socket_factory->AddSocketDataProvider(&data);

      TestCompletionCallback callback;

      int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
      EXPECT_THAT(callback.GetResult(rv), IsOk());

      const HttpResponseInfo* response = trans->GetResponseInfo();
      ASSERT_TRUE(response);

      EXPECT_TRUE(response->headers);
      std::string status_line = response->headers->GetStatusLine();
      EXPECT_EQ("HTTP/1.1 200 OK", status_line);

      EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

      std::string response_data;
      switch (test_case) {
        case TestCase::kReadHeaders: {
          // Already read the headers, nothing else to do.
          break;
        }

        case TestCase::kReadPartOfBodyRead: {
          auto buf = base::MakeRefCounted<IOBufferWithSize>(5);
          rv = trans->Read(buf.get(), 5, callback.callback());
          ASSERT_EQ(5, callback.GetResult(rv));
          response_data.assign(buf->data(), 5);
          EXPECT_EQ("hello", response_data);
          break;
        }

        case TestCase::kReadAllOfBody: {
          rv = ReadTransaction(trans.get(), &response_data);
          EXPECT_THAT(rv, IsOk());
          EXPECT_EQ("hello world", response_data);
          break;
        }
      }

      if (close_connection) {
        trans->CloseConnectionOnDestruction();
      }
      trans.reset();

      // Wait for the socket to be drained and added to the socket pool or
      // destroyed.
      base::RunLoop().RunUntilIdle();

      // In the case all the body was read, the socket will have been released
      // before the CloseConnectionOnDestruction() call, so will not be
      // destroyed.
      if (close_connection && test_case != TestCase::kReadAllOfBody) {
        EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
      } else {
        EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
      }
    }
  }
}

// Grab a socket, use it, and put it back into the pool. Then, make
// low memory notification and ensure the socket pool is flushed.
TEST_P(HttpNetworkTransactionTest, FlushSocketPoolOnLowMemoryNotifications) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      // A part of the response body is received with the response headers.
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhel"),
      // The rest of the response body is received in two parts.
      MockRead("lo"),
      MockRead(" world"),
      MockRead("junk"),  // Should not be read!!
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers);
  std::string status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 200 OK", status_line);

  // Make memory critical notification and ensure the transaction still has been
  // operating right.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  // Socket should not be flushed as long as it is not idle.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Idle sockets should be flushed now.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Disable idle socket closing on memory pressure.
// Grab a socket, use it, and put it back into the pool. Then, make
// low memory notification and ensure the socket pool is NOT flushed.
TEST_P(HttpNetworkTransactionTest, NoFlushSocketPoolOnLowMemoryNotifications) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Disable idle socket closing on memory pressure.
  session_deps_.disable_idle_sockets_close_on_memory_pressure = true;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      // A part of the response body is received with the response headers.
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhel"),
      // The rest of the response body is received in two parts.
      MockRead("lo"),
      MockRead(" world"),
      MockRead("junk"),  // Should not be read!!
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers);
  std::string status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 200 OK", status_line);

  // Make memory critical notification and ensure the transaction still has been
  // operating right.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  // Socket should not be flushed as long as it is not idle.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Idle sockets should NOT be flushed on moderate memory pressure.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Idle sockets should NOT be flushed on critical memory pressure.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Grab an SSL socket, use it, and put it back into the pool. Then, make
// low memory notification and ensure the socket pool is flushed.
TEST_P(HttpNetworkTransactionTest, FlushSSLSocketPoolOnLowMemoryNotifications) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.load_flags = 0;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead("Content-Length: 11\r\n\r\n"),
      MockRead("hello world"), MockRead(ASYNC, ERR_CONNECTION_CLOSED)};

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  // Make memory critical notification and ensure the transaction still has been
  // operating right.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Make memory notification once again and ensure idle socket is closed.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Make sure that we recycle a socket after a zero-length response.
// http://crbug.com/9880
TEST_P(HttpNetworkTransactionTest, RecycleSocketAfterZeroContentLength) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(
      "http://www.example.org/csi?v=3&s=web&action=&"
      "tran=undefined&ei=mAXcSeegAo-SMurloeUN&"
      "e=17259,18167,19592,19773,19981,20133,20173,20233&"
      "rt=prt.2642,ol.2649,xjs.2951");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 204 No Content\r\n"
               "Content-Length: 0\r\n"
               "Content-Type: text/html\r\n\r\n"),
      MockRead("junk"),  // Should not be read!!
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // Transaction must be created after the MockReads, so it's destroyed before
  // them.
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get()
"""


```