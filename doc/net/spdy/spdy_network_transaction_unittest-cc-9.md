Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Identify the Core Functionality:** The filename `spdy_network_transaction_unittest.cc` immediately signals that this is a unit test file. The content confirms this, showing various test cases for `SpdyNetworkTransaction`. The tests primarily focus on interactions between `SpdyNetworkTransaction` and other components, especially concerning WebSocket connections over HTTP/2 (SPDY).

2. **Break Down Individual Test Cases:** I'd go through each `TEST_P` (parameterized test) and `TEST` block, understanding the specific scenario being tested. Keywords like "WebSocket," "proxy," "HTTP2," "aliasing," "priority," and error codes like "ERR_NOT_IMPLEMENTED" and "ERROR_CODE_HTTP_1_1_REQUIRED" are crucial.

3. **Summarize Overall Functionality:** Based on the individual tests, I can deduce the broader purpose of the file. It tests the `SpdyNetworkTransaction`'s ability to:
    * Establish and manage HTTP/2 connections.
    * Handle WebSocket upgrades over HTTP/2.
    * Handle WebSocket connections through HTTP/2 proxies.
    * Deal with scenarios involving existing HTTP/2 sessions (aliasing).
    * Handle server-side requirements for HTTP/1.1 for WebSockets.
    * Prioritize requests correctly.
    * Avoid using incompatible existing HTTP/2 sessions for WebSockets.

4. **JavaScript Relationship (if any):**  WebSockets are a standard web technology heavily used in JavaScript. While the *C++ code* doesn't directly interact with JavaScript, it's testing the *underlying network implementation* that enables JavaScript WebSocket APIs in the browser. The connection is that this C++ code ensures the browser's networking layer correctly handles WebSocket requests initiated by JavaScript. I need to make this connection explicit.

5. **Logical Inference (Hypothetical Inputs/Outputs):**  Each test case provides an implicit input (the `HttpRequestInfo` objects) and expected outputs (successful connection, specific headers, data transfer, error conditions). I can choose a representative test, like the first one involving a direct WebSocket connection over HTTP/2, and describe the input request (URL, headers) and the expected successful outcome (response headers, data).

6. **Common Usage Errors:**  Thinking about how a developer might misuse the network stack related to WebSockets, I can come up with examples like:
    * Incorrect WebSocket URL (missing `wss://` or `ws://`).
    * Missing or incorrect headers (`Connection: Upgrade`, `Upgrade: websocket`, `Origin`, `Sec-WebSocket-Version`).
    * Trying to establish a WebSocket connection over plain HTTP when the server requires TLS.

7. **User Operation to Reach This Code (Debugging Context):** This requires tracing back from a user action to the network stack. A user entering a `wss://` URL or a web application using the JavaScript `WebSocket` API are the starting points. I need to outline the steps: URL entered/JavaScript API call -> Browser's networking layer -> HTTP/2 negotiation (if applicable) -> `SpdyNetworkTransaction` (if HTTP/2 is used) -> the code being tested.

8. **Section Summary (Part 10 of 12):** Given the focus of the tests in this snippet (primarily WebSocket over HTTP/2 and related edge cases), I can summarize this section's function as specifically testing the `SpdyNetworkTransaction`'s role in handling WebSocket connections, including proxy scenarios, session reuse, and error handling. Knowing it's part 10 of 12 suggests it's delving into more specific and potentially complex features.

9. **Review and Refine:** After drafting the initial response, I'd reread the code and my analysis to ensure accuracy, clarity, and completeness. I'd check for any missed details or potential misunderstandings. For example, ensuring the explanation of "aliasing" is clear and the connection to JavaScript is well-articulated.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and accurate response that addresses all aspects of the prompt.
这个C++源代码文件 `net/spdy/spdy_network_transaction_unittest.cc` 是 Chromium 网络栈中用于测试 `SpdyNetworkTransaction` 类的单元测试文件。 `SpdyNetworkTransaction` 是 Chromium 中处理 SPDY (以及其后继 HTTP/2) 协议网络请求的核心类之一。

**文件功能归纳:**

这个文件的主要功能是 **验证 `SpdyNetworkTransaction` 类在各种场景下的行为是否符合预期，特别是涉及到 WebSocket 连接 over HTTP/2 的情况。** 由于这是第 10 部分，并且之前的代码片段也集中在 WebSocket 功能上，我们可以推断这部分主要关注 `SpdyNetworkTransaction` 如何处理和建立 WebSocket 连接，以及与其他组件（如 `SpdySession`，代理服务器）的交互。

**具体功能列举:**

基于提供的代码片段，我们可以列举出以下具体测试的功能点：

1. **成功建立 WebSocket 连接 over HTTP/2:** 测试当服务器支持 WebSocket 并且客户端发起 WebSocket 升级请求时，`SpdyNetworkTransaction` 是否能够成功建立连接。
2. **WebSocket 不会使用不支持 WebSocket 的新 HTTP/2 会话 (Over HTTPS Proxy):**  测试在使用 HTTPS 代理的情况下，如果新的 HTTP/2 会话不支持 WebSocket，则 WebSocket 连接不会使用这个会话。这避免了潜在的连接错误。
3. **WebSocket over HTTP/2 可以检测到具有别名的新会话:** 测试当存在一个可以用于 WebSocket 连接的 HTTP/2 会话（即使主机名不同，但底层连接相同，即别名）时，WebSocket 请求可以重用该会话。
4. **WebSocket over HTTP/2 检测到新会话但该会话在使用前被关闭:** 测试即使检测到可以重用的 HTTP/2 会话，但如果在 WebSocket 请求使用之前该会话被关闭，则会回退到使用 HTTP/1.1 进行 WebSocket 连接。
5. **WebSocket 协商 HTTP/2 失败:** 测试当客户端请求 WebSocket over HTTP/2，但服务器强制使用 HTTP/2 并且客户端没有声明支持时，连接会失败并返回 `ERR_NOT_IMPLEMENTED` 错误。
6. **WebSocket 需要 HTTP/1.1:** 测试当服务器通过 HTTP/2 发送 `ERROR_CODE_HTTP_1_1_REQUIRED` 指示需要使用 HTTP/1.1 进行 WebSocket 连接时，`SpdyNetworkTransaction` 是否能够正确处理并回退到 HTTP/1.1。
7. **纯文本 WebSocket over HTTP/2 代理:** 测试通过 HTTP/2 代理建立纯文本 WebSocket 连接（使用 CONNECT 隧道）是否能够正常工作。

**与 JavaScript 的关系及举例说明:**

这个 C++ 文件测试的是浏览器网络栈的底层实现，它直接服务于浏览器中运行的 JavaScript 代码。当 JavaScript 代码使用 `WebSocket` API 发起 WebSocket 连接时，底层的网络请求会由 Chromium 的网络栈处理，其中就包括 `SpdyNetworkTransaction`。

**举例说明:**

假设 JavaScript 代码如下：

```javascript
const websocket = new WebSocket('wss://www.example.org/');

websocket.onopen = function(event) {
  console.log("WebSocket connection opened!");
  websocket.send("Hello from JavaScript!");
};

websocket.onmessage = function(event) {
  console.log("Received message:", event.data);
};

websocket.onerror = function(error) {
  console.error("WebSocket error:", error);
};

websocket.onclose = function(event) {
  console.log("WebSocket connection closed.");
};
```

当这段 JavaScript 代码执行时，浏览器会发起一个到 `wss://www.example.org/` 的 WebSocket 连接请求。如果服务器支持 HTTP/2，并且满足其他条件，`SpdyNetworkTransaction` 就会参与处理这个请求。这个 C++ 测试文件中的测试用例，例如测试成功建立 WebSocket 连接的用例，就是为了确保在 JavaScript 发起这样的请求时，底层的 C++ 代码能够正确地建立和维护连接，从而使得 JavaScript 的回调函数（如 `onopen`，`onmessage`）能够被正常调用。

**逻辑推理（假设输入与输出）:**

以 "成功建立 WebSocket 连接 over HTTP/2" 这个测试为例：

**假设输入:**

* **客户端请求 (`HttpRequestInfo`):**
    * `method`: "GET"
    * `url`: "wss://www.example.org/"
    * `extra_headers`: 包含 "Connection: Upgrade", "Upgrade: websocket", "Origin", "Sec-WebSocket-Version" 等 WebSocket 握手所需的头部。
* **服务器响应 (通过 `MockRead` 模拟):**
    * 先发送一个 HTTP/2 Settings 帧，声明支持 CONNECT 协议 (`SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`)。
    * 然后发送一个 HTTP/2 响应帧 (HEADERS 帧) 作为对初始 HTTP 请求的回复 (状态码通常是 200)。
    * 接着发送一个 HTTP/2 响应帧 (HEADERS 帧) 作为 WebSocket 握手的响应 (状态码 101 Switching Protocols)，包含 "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Accept" 等头部。

**预期输出:**

* `SpdyNetworkTransaction::Start()` 返回 `ERR_IO_PENDING`，表示异步操作。
* 通过 `base::RunLoop().RunUntilIdle()` 触发异步操作完成。
* `TestCompletionCallback` 的回调函数被调用，返回 `OK` (0)，表示连接建立成功。
* `helper.trans()->GetResponseInfo()` 返回的 `HttpResponseInfo` 对象包含正确的头部信息，例如 `was_fetched_via_spdy` 为 true，表示使用了 SPDY/HTTP/2 协议。
* 后续可以通过该连接进行 WebSocket 数据传输。

**用户或编程常见的使用错误:**

1. **错误的 WebSocket URL:** 用户可能在 JavaScript 中使用了 `http://` 而不是 `ws://` 或 `https://` 而不是 `wss://` 作为 WebSocket URL。这会导致连接失败或安全问题。
2. **缺少必要的头部:** 在手动构造 HTTP 请求时（虽然通常浏览器会自动处理），可能会忘记添加 "Connection: Upgrade" 或 "Upgrade: websocket" 等关键头部，导致服务器无法识别这是一个 WebSocket 升级请求。
3. **服务器不支持 WebSocket:** 用户尝试连接到不支持 WebSocket 协议的服务器，会导致连接失败。
4. **网络问题或防火墙阻止:**  底层的网络连接可能存在问题，或者防火墙阻止了 WebSocket 连接。
5. **HTTPS 证书问题:** 对于 `wss://` 连接，如果服务器的 SSL 证书无效或不受信任，连接会失败。

**用户操作如何一步步到达这里（作为调试线索）:**

1. **用户在浏览器地址栏输入或点击了一个 `ws://` 或 `wss://` 开头的链接。**
2. **网页上的 JavaScript 代码创建了一个 `WebSocket` 对象。**
3. **浏览器解析 URL，识别出需要建立 WebSocket 连接。**
4. **浏览器网络栈开始处理 WebSocket 连接请求。**
5. **如果 URL 是 `wss://`，则会先进行 TLS 握手。**
6. **如果确定可以使用 HTTP/2 协议，则会创建或重用一个 `SpdySession`。**
7. **`SpdyNetworkTransaction` 被创建来处理这个 WebSocket 连接。**
8. **`SpdyNetworkTransaction` 会构造一个 HTTP 请求，包含必要的升级头部。**
9. **将请求发送到服务器。**
10. **服务器返回 101 Switching Protocols 响应，表示 WebSocket 握手成功。**
11. **`SpdyNetworkTransaction` 完成握手，WebSocket 连接建立完成。**

在调试过程中，如果 WebSocket 连接出现问题，开发人员可能会检查网络请求的头部信息，查看服务器的响应，或者使用 Chromium 提供的网络工具 (chrome://net-export/) 来捕获网络日志，从而追踪到 `SpdyNetworkTransaction` 及其相关的组件。单元测试如这个文件，就是为了确保在这个过程中，各个环节的 C++ 代码能够正确运行。

### 提示词
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
eateMockWrite(priority1, 5),
      CreateMockWrite(priority2, 6)};

  spdy::SettingsMap settings;
  settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame websocket_response(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead reads[] = {CreateMockRead(settings_frame, 1),
                      CreateMockRead(resp1, 3), CreateMockRead(body1, 7),
                      CreateMockRead(websocket_response, 8),
                      MockRead(ASYNC, 0, 9)};

  SequencedSocketData data(reads, writes);
  helper.AddData(&data);

  TestCompletionCallback callback1;
  int rv = helper.trans()->Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create HTTP/2 connection.
  base::RunLoop().RunUntilIdle();

  SpdySessionKey key(HostPortPair::FromURL(request_.url), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
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
  ASSERT_TRUE(spdy_session);

  // First request has HIGHEST priority, WebSocket request has MEDIUM priority.
  // Changing the priority of the first request to LOWEST changes their order,
  // and therefore triggers sending PRIORITY frames.
  helper.trans()->SetPriority(LOWEST);

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(helper.trans(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  helper.VerifyDataConsumed();

  // Server advertised WebSocket support.
  histogram_tester.ExpectUniqueSample("Net.SpdySession.ServerSupportsWebSocket",
                                      /* support_websocket = true */ 1,
                                      /* expected_count = */ 1);
}

// Make sure that a WebSocket job doesn't pick up a newly created SpdySession
// that supports WebSockets through an HTTPS proxy when an H2 server doesn't
// support websockets. See https://crbug.com/1010491.
TEST_P(SpdyNetworkTransactionTest,
       WebSocketDoesNotUseNewH2SessionWithoutWebSocketSupportOverHttpsProxy) {
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));

  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));

  MockWrite writes[] = {MockWrite(SYNCHRONOUS, 0,
                                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                                  "Host: www.example.org:443\r\n"
                                  "Proxy-Connection: keep-alive\r\n"
                                  "User-Agent: test-ua\r\n\r\n"),
                        CreateMockWrite(req, 2)};

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 OK\r\n\r\n"),
                      CreateMockRead(resp1, 3), CreateMockRead(body1, 4),
                      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5)};

  // SSL data for the proxy.
  SSLSocketDataProvider tunnel_ssl_data(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      &tunnel_ssl_data);

  SequencedSocketData data(
      // Just as with other operations, this means to pause during connection
      // establishment.
      MockConnect(ASYNC, ERR_IO_PENDING), reads, writes);
  helper.AddData(&data);

  MockWrite writes2[] = {
      MockWrite(SYNCHRONOUS, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(SYNCHRONOUS, 2,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead reads2[] = {
      MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(SYNCHRONOUS, 3,
               "HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};
  SequencedSocketData data2(MockConnect(ASYNC, ERR_IO_PENDING), reads2,
                            writes2);

  // SSL data for the proxy.
  SSLSocketDataProvider tunnel_ssl_data2(ASYNC, OK);
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      &tunnel_ssl_data2);

  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Test that the request has HTTP/2 disabled.
  ssl_provider2->next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // Force socket to use HTTP/1.1, the default protocol without ALPN.
  ssl_provider2->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  TestCompletionCallback callback1;
  int rv = helper.trans()->Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create HTTP/2 connection.
  base::RunLoop().RunUntilIdle();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://www.example.org/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(request_.url)
                  .Equals(HostPortPair::FromURL(request2.url)));
  request2.extra_headers.SetHeader("Connection", "Upgrade");
  request2.extra_headers.SetHeader("Upgrade", "websocket");
  request2.extra_headers.SetHeader("Origin", "http://www.example.org");
  request2.extra_headers.SetHeader("Sec-WebSocket-Version", "13");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  trans2.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Run until waiting on both connections.
  base::RunLoop().RunUntilIdle();

  // The H2 connection completes.
  data.socket()->OnConnectComplete(MockConnect(SYNCHRONOUS, OK));
  EXPECT_EQ(OK, callback1.WaitForResult());
  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  std::string response_data;
  rv = ReadTransaction(helper.trans(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  SpdySessionKey key(
      HostPortPair::FromURL(request_.url), PRIVACY_MODE_DISABLED,
      ProxyUriToProxyChain("https://proxy:70", ProxyServer::SCHEME_HTTPS),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);

  base::WeakPtr<SpdySession> spdy_session =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, log_);
  ASSERT_TRUE(spdy_session);
  EXPECT_FALSE(spdy_session->support_websocket());

  EXPECT_FALSE(callback2.have_result());

  // Create WebSocket stream.
  data2.socket()->OnConnectComplete(MockConnect(SYNCHRONOUS, OK));

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  helper.VerifyDataConsumed();
}

// Same as above, but checks that a WebSocket connection avoids creating a new
// socket if it detects an H2 session when host resolution completes, and
// requests also use different hostnames.
TEST_P(SpdyNetworkTransactionTest,
       WebSocketOverHTTP2DetectsNewSessionWithAliasing) {
  base::HistogramTester histogram_tester;
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->host_resolver->set_ondemand_mode(true);
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  quiche::HttpHeaderBlock websocket_request_headers;
  websocket_request_headers[spdy::kHttp2MethodHeader] = "CONNECT";
  websocket_request_headers[spdy::kHttp2AuthorityHeader] = "example.test";
  websocket_request_headers[spdy::kHttp2SchemeHeader] = "https";
  websocket_request_headers[spdy::kHttp2PathHeader] = "/";
  websocket_request_headers[spdy::kHttp2ProtocolHeader] = "websocket";
  websocket_request_headers["origin"] = "http://example.test";
  websocket_request_headers["sec-websocket-version"] = "13";
  websocket_request_headers["sec-websocket-extensions"] =
      "permessage-deflate; client_max_window_bits";
  spdy::SpdySerializedFrame websocket_request(spdy_util_.ConstructSpdyHeaders(
      3, std::move(websocket_request_headers), MEDIUM, false));

  spdy::SpdySerializedFrame priority1(
      spdy_util_.ConstructSpdyPriority(3, 0, MEDIUM, true));
  spdy::SpdySerializedFrame priority2(
      spdy_util_.ConstructSpdyPriority(1, 3, LOWEST, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(settings_ack, 2),
      CreateMockWrite(websocket_request, 4), CreateMockWrite(priority1, 5),
      CreateMockWrite(priority2, 6)};

  spdy::SettingsMap settings;
  settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame websocket_response(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead reads[] = {CreateMockRead(settings_frame, 1),
                      CreateMockRead(resp1, 3), CreateMockRead(body1, 7),
                      CreateMockRead(websocket_response, 8),
                      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 9)};

  SequencedSocketData data(reads, writes);
  helper.AddData(&data);

  TestCompletionCallback callback1;
  int rv = helper.trans()->Start(&request_, callback1.callback(), log_);
  // This fast forward makes sure that the transaction switches to the
  // HttpStreamPool when HappyEyeballsV3 is enabled.
  FastForwardBy(base::Milliseconds(1));
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://example.test/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request2.extra_headers.SetHeader("Origin", "http://example.test");
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

  // Make sure both requests are blocked on host resolution.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(helper.session_deps()->host_resolver->has_pending_requests());
  // Complete the first DNS lookup, which should result in the first transaction
  // creating an H2 session (And completing successfully).
  helper.session_deps()->host_resolver->ResolveNow(1);
  base::RunLoop().RunUntilIdle();

  SpdySessionKey key1(HostPortPair::FromURL(request_.url),
                      PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                      SessionUsage::kDestination, SocketTag(),
                      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_TRUE(helper.session()->spdy_session_pool()->HasAvailableSession(
      key1, /* is_websocket = */ false));
  base::WeakPtr<SpdySession> spdy_session1 =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key1, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, log_);
  ASSERT_TRUE(spdy_session1);
  EXPECT_TRUE(spdy_session1->support_websocket());

  // Second DNS lookup completes, which results in creating a WebSocket stream.
  helper.session_deps()->host_resolver->ResolveNow(2);
  ASSERT_TRUE(spdy_session1);

  SpdySessionKey key2(HostPortPair::FromURL(request2.url),
                      PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                      SessionUsage::kDestination, SocketTag(),
                      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_TRUE(helper.session()->spdy_session_pool()->HasAvailableSession(
      key2, /* is_websocket = */ true));
  base::WeakPtr<SpdySession> spdy_session2 =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key1, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ true, log_);
  ASSERT_TRUE(spdy_session2);
  EXPECT_EQ(spdy_session1.get(), spdy_session2.get());

  base::RunLoop().RunUntilIdle();

  // First request has HIGHEST priority, WebSocket request has MEDIUM priority.
  // Changing the priority of the first request to LOWEST changes their order,
  // and therefore triggers sending PRIORITY frames.
  helper.trans()->SetPriority(LOWEST);

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(helper.trans(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  helper.VerifyDataConsumed();
}

// Same as above, but the SpdySession is closed just before use, so the
// WebSocket is sent over a new HTTP/1.x connection instead.
TEST_P(SpdyNetworkTransactionTest,
       WebSocketOverDetectsNewSessionWithAliasingButClosedBeforeUse) {
  base::HistogramTester histogram_tester;
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  session_deps->host_resolver->set_ondemand_mode(true);
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  MockWrite writes[] = {CreateMockWrite(req, 0),
                        CreateMockWrite(settings_ack, 2)};

  spdy::SettingsMap settings;
  settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {CreateMockRead(settings_frame, 1),
                      CreateMockRead(resp1, 3), CreateMockRead(body1, 4),
                      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5)};

  SequencedSocketData data(reads, writes);
  helper.AddData(&data);

  MockWrite writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: example.test\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://example.test\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};
  MockRead reads2[] = {
      MockRead("HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};
  StaticSocketDataProvider data2(reads2, writes2);
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Test that the request has HTTP/2 disabled.
  ssl_provider2->next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // Force socket to use HTTP/1.1, the default protocol without ALPN.
  ssl_provider2->next_proto = kProtoHTTP11;
  ssl_provider2->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  TestCompletionCallback callback1;
  int rv = helper.trans()->Start(&request_, callback1.callback(), log_);
  // This fast forward makes sure that the transaction switches to the
  // HttpStreamPool when HappyEyeballsV3 is enabled.
  FastForwardBy(base::Milliseconds(1));
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://example.test/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request2.extra_headers.SetHeader("Connection", "Upgrade");
  request2.extra_headers.SetHeader("Upgrade", "websocket");
  request2.extra_headers.SetHeader("Origin", "http://example.test");
  request2.extra_headers.SetHeader("Sec-WebSocket-Version", "13");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  trans2.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Make sure both requests are blocked on host resolution.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(helper.session_deps()->host_resolver->has_pending_requests());
  // Complete the first DNS lookup, which should result in the first transaction
  // creating an H2 session (And completing successfully).
  helper.session_deps()->host_resolver->ResolveNow(1);

  // Complete first request.
  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  std::string response_data;
  rv = ReadTransaction(helper.trans(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  SpdySessionKey key1(HostPortPair::FromURL(request_.url),
                      PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                      SessionUsage::kDestination, SocketTag(),
                      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> spdy_session1 =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key1, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, log_);
  ASSERT_TRUE(spdy_session1);
  EXPECT_TRUE(spdy_session1->support_websocket());

  // Second DNS lookup completes, which results in creating an alias for the
  // SpdySession immediately, and a task is posted asynchronously to use the
  // alias..
  helper.session_deps()->host_resolver->ResolveNow(2);

  SpdySessionKey key2(HostPortPair::FromURL(request2.url),
                      PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                      SessionUsage::kDestination, SocketTag(),
                      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> spdy_session2 =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key1, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ true, log_);
  ASSERT_TRUE(spdy_session2);
  EXPECT_EQ(spdy_session1.get(), spdy_session2.get());

  // But the session is closed before it can be used.
  helper.session()->spdy_session_pool()->CloseAllSessions();

  // The second request establishes another connection (without even doing
  // another DNS lookup) instead, and uses HTTP/1.x.
  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, WebSocketNegotiatesHttp2) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("wss://www.example.org/");
  request.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(request_.url)
                  .Equals(HostPortPair::FromURL(request.url)));
  request.extra_headers.SetHeader("Connection", "Upgrade");
  request.extra_headers.SetHeader("Upgrade", "websocket");
  request.extra_headers.SetHeader("Origin", "http://www.example.org");
  request.extra_headers.SetHeader("Sec-WebSocket-Version", "13");

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();

  StaticSocketDataProvider data;

  auto ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Test that the request has HTTP/2 disabled.
  ssl_provider->next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // Force socket to use HTTP/2, which should never happen (TLS implementation
  // should fail TLS handshake if server chooses HTTP/2 without client
  // advertising support).
  ssl_provider->next_proto = kProtoHTTP2;
  ssl_provider->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  helper.AddDataWithSSLSocketDataProvider(&data, std::move(ssl_provider));

  HttpNetworkTransaction* trans = helper.trans();
  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_NOT_IMPLEMENTED));

  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, WebSocketHttp11Required) {
  base::HistogramTester histogram_tester;
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

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
  spdy::SpdySerializedFrame websocket_request(spdy_util_.ConstructSpdyHeaders(
      3, std::move(websocket_request_headers), MEDIUM, false));

  spdy::SpdySerializedFrame priority1(
      spdy_util_.ConstructSpdyPriority(3, 0, MEDIUM, true));
  spdy::SpdySerializedFrame priority2(
      spdy_util_.ConstructSpdyPriority(1, 3, LOWEST, true));

  MockWrite writes1[] = {CreateMockWrite(req, 0),
                         CreateMockWrite(settings_ack, 2),
                         CreateMockWrite(websocket_request, 4)};

  spdy::SettingsMap settings;
  settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame websocket_response_http11_required(
      spdy_util_.ConstructSpdyRstStream(3, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
  MockRead reads1[] = {CreateMockRead(settings_frame, 1),
                       CreateMockRead(resp1, 3),
                       CreateMockRead(websocket_response_http11_required, 5)};

  SequencedSocketData data1(reads1, writes1);
  helper.AddData(&data1);

  MockWrite writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};
  MockRead reads2[] = {
      MockRead("HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};
  StaticSocketDataProvider data2(reads2, writes2);
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Test that the request has HTTP/2 disabled.
  ssl_provider2->next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // Force socket to use HTTP/1.1, the default protocol without ALPN.
  ssl_provider2->next_proto = kProtoHTTP11;
  ssl_provider2->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  // Create HTTP/2 connection.
  TestCompletionCallback callback1;
  int rv = helper.trans()->Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create HTTP/2 connection.
  base::RunLoop().RunUntilIdle();

  SpdySessionKey key(HostPortPair::FromURL(request_.url), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
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
  EXPECT_THAT(callback2.GetResult(rv), IsOk());

  helper.VerifyDataConsumed();

  // Server advertised WebSocket support.
  histogram_tester.ExpectUniqueSample("Net.SpdySession.ServerSupportsWebSocket",
                                      /* support_websocket = true */ 1,
                                      /* expected_count = */ 1);
}

// When using an HTTP(S) proxy, plaintext WebSockets use CONNECT tunnels. This
// should work for HTTP/2 proxies.
TEST_P(SpdyNetworkTransactionTest, PlaintextWebSocketOverHttp2Proxy) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 80)));
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
  spdy::SpdySerializedFrame websocket_request(spdy_util_.ConstructSpdyDataFrame(
      /*stream_id=*/1, kWebSocketRequest, /*fin=*/false));
  MockWrite writes[] = {CreateMockWrite(req, 0),
                        CreateMockWrite(websocket_request, 2)};

  spdy::SpdySerializedFrame connect_response(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  const char kWebSocketResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
  spdy::SpdySerializedFrame websocket_response(
      spdy_util_.ConstructSpdyDataFrame(/*stream_id=*/1, kWebSocketResponse,
                                        /*fin=*/false));
  MockRead reads[] = {CreateMockRead(connect_response, 1)
```