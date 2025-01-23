Response:
My thinking process to analyze the provided C++ code and answer the prompt follows these steps:

1. **Understand the Goal:** The request asks for a functional summary of the C++ code, its relation to JavaScript, examples of logical reasoning, common user errors, debugging tips, and a final summary. It's crucial to recognize this is a unit test file for Chromium's network stack, specifically the `HttpStreamFactory`.

2. **Identify Key Components:** I scan the code for recurring patterns, class names, and function calls. Key elements that jump out are:
    * `TEST_P`: Indicating parameterized tests.
    * `HttpStreamFactoryTest`: The main test fixture.
    * `SpdySessionDependencies`:  Configuration for network sessions.
    * `HttpNetworkSession`: Represents a network session.
    * `HttpRequestInfo`:  Describes an HTTP request.
    * `StreamRequester`: A helper class for making stream requests.
    * `WebSocketStreamCreateHelper`:  Specifically for WebSocket requests.
    * `MockRead`, `MockWrite`, `StaticSocketDataProvider`, `SSLSocketDataProvider`:  Tools for simulating network interactions.
    * `GetSpdySessionCount`, `GetPoolGroupCount`: Functions to inspect the state of the HTTP/2 session pool and socket pools.
    * Different request types: HTTP, HTTPS, WebSocket (ws:// and wss://), SPDY, and Bidirectional streams.
    * Proxy configurations.
    * Feature flags (`features::kHappyEyeballsV3`, `features::kPartitionConnectionsByNetworkIsolationKey`).
    * Focus on testing different scenarios related to creating and managing HTTP streams.

3. **Group Tests by Functionality:** I mentally group the tests based on what they are testing. This helps in understanding the overall purpose of the file. The groups I identify are:
    * Basic HTTP/1.1 requests (with and without SSL).
    * HTTP/1.1 requests through a proxy.
    * Basic WebSocket handshake requests (with and without SSL, and via proxy).
    * HTTP/2 (SPDY) requests (with and without explicit HTTPS, and with HTTP over HTTPS proxy).
    * Impact of Network Anonymization Key on SPDY.
    * Behavior when new SPDY sessions are established (closing idle sockets).
    * Concurrent SPDY connection attempts.
    * Bidirectional stream requests (HTTP/2).

4. **Summarize the File's Functionality:** Based on the grouped tests, I formulate a concise summary. The core functionality is testing the `HttpStreamFactory`'s ability to create different types of HTTP streams under various network conditions. This includes direct connections, proxy connections, SSL/TLS, HTTP/2 (SPDY), and WebSockets. The tests also cover aspects like connection pooling and interaction with other network components.

5. **Analyze the Relationship with JavaScript:** I consider how these network operations relate to JavaScript in a browser context. JavaScript uses browser APIs like `fetch()` and `WebSocket` which internally rely on the network stack being tested here. I provide concrete examples of how a JavaScript `fetch()` call translates to the underlying network operations tested in the C++ code.

6. **Identify Logical Reasoning and Provide Examples:** I look for tests that demonstrate specific logic or conditions. For example:
    * The test checking if a `SetPriority` call before the stream is fully established doesn't crash the system demonstrates defensive programming.
    * The tests involving proxies (`RequestHttpStreamOverProxy`, `RequestWebSocketBasicHandshakeStreamOverProxy`) verify the proxying logic.
    * The tests involving SPDY (`RequestSpdyHttpStreamHttpsURL`, `RequestSpdyHttpStreamHttpURL`) confirm the HTTP/2 upgrade mechanism and the role of `HttpServerProperties`.
    * The `NewSpdySessionCloseIdleH2Sockets` test shows logic for managing idle HTTP/2 connections.

    For each of these, I create hypothetical inputs (e.g., a specific URL, proxy configuration) and expected outputs (e.g., a stream is created, a SPDY session is established).

7. **Identify Common User/Programming Errors:** I think about mistakes developers might make when using the networking APIs that these tests are validating:
    * Incorrect proxy configuration.
    * Using `ws://` for HTTPS sites or `wss://` for HTTP sites.
    * Not handling certificate errors properly.
    * Misunderstanding connection pooling behavior.

8. **Explain User Actions Leading to the Code:** I trace back how a user's action in a browser can trigger this code. The most common scenario is a user navigating to a website or a web application making network requests. I break down the steps, linking the user's action (typing a URL, clicking a link, a script making a `fetch()` call) to the internal browser processes that eventually reach the `HttpStreamFactory`.

9. **Address the "Debugging Clues" Aspect:** I consider what information from this test file could be helpful during debugging. The test names themselves often indicate specific scenarios. The use of `MockRead`, `MockWrite`, and the socket data providers show how to simulate and inspect network traffic. Assertions (`EXPECT_TRUE`, `ASSERT_EQ`) pinpoint where failures occur.

10. **Craft the Final Summary:** I reiterate the core function of the code based on the detailed analysis, highlighting its role in ensuring the reliability and correctness of HTTP stream creation within the Chromium network stack.

11. **Review and Refine:** I reread my analysis and the code to ensure accuracy, clarity, and completeness, making any necessary corrections or improvements to the language and examples. I specifically check that I've addressed all parts of the prompt.

This structured approach ensures that I systematically analyze the code, understand its purpose, and provide a comprehensive answer to the complex request. The grouping of tests by functionality and the explicit linking to JavaScript concepts are key to providing a helpful and insightful response.
这是`net/http/http_stream_factory_unittest.cc`文件的第3部分，主要包含了一系列针对 `HttpStreamFactory` 类的单元测试。 `HttpStreamFactory` 是 Chromium 网络栈中负责创建各种 HTTP 流的关键组件。

**本部分的功能归纳：**

本部分主要测试了 `HttpStreamFactory` 在不同场景下创建各种类型 HTTP 流的能力，包括：

* **基本的 HTTP 流创建 (无 SSL)：**  验证 `HttpStreamFactory` 能否成功创建用于普通 HTTP 请求的流。
* **通过 SSL 创建 HTTP 流：** 测试 `HttpStreamFactory` 创建 HTTPS 请求所需的安全流。
* **通过 HTTP 代理创建 HTTP 流：**  验证 `HttpStreamFactory` 在存在 HTTP 代理的情况下能否正确建立连接。
* **基本的 WebSocket 握手流创建 (无 SSL 和 SSL)：** 测试 `HttpStreamFactory` 创建用于 `ws://` 和 `wss://` WebSocket 连接的握手流。
* **通过 HTTP 代理创建 WebSocket 握手流：** 验证 `HttpStreamFactory` 在通过 HTTP 代理连接 WebSocket 时的功能。
* **创建 SPDY (HTTP/2) 流 (HTTPS URL)：** 测试 `HttpStreamFactory` 为 HTTPS URL 创建 HTTP/2 连接的能力。
* **创建 SPDY (HTTP/2) 流 (HTTP URL，通过 HTTPS 代理)：** 验证 `HttpStreamFactory` 在通过声明支持 HTTP/2 的 HTTPS 代理访问 HTTP URL 时创建 HTTP/2 连接的功能，并测试 `HttpServerProperties` 的更新。
* **使用 NetworkAnonymizationKey 创建 SPDY 流：**  测试在启用 NetworkAnonymizationKey 的情况下，`HttpStreamFactory` 如何创建 SPDY 流并更新 `HttpServerProperties`。
* **新 SPDY 会话建立时关闭空闲的 HTTP/2 套接字：**  测试当建立新的 HTTP/2 连接时，`HttpStreamFactory` 是否会关闭之前可能存在的空闲的相同目标的 HTTP/2 套接字，以优化资源利用。
* **两次 SPDY 连接尝试：**  一个回归测试，用于验证在两个并发的 SPDY 连接尝试中，`HttpStreamFactory` 的行为是否正确。
* **创建双向流 (`BidirectionalStreamImpl`)：** 测试 `HttpStreamFactory` 创建 HTTP/2 双向流的能力。

**与 JavaScript 功能的关系及举例说明：**

`HttpStreamFactory` 的功能是 JavaScript 中网络请求的基础。当 JavaScript 代码发起一个网络请求时，无论是通过 `fetch()` API 还是 `XMLHttpRequest` 对象，浏览器底层都会调用网络栈的组件来建立连接和传输数据。 `HttpStreamFactory` 就负责创建用于这些请求的底层网络流。

**举例：**

1. **`fetch()` API:**
   ```javascript
   fetch('https://www.google.com')
     .then(response => response.text())
     .then(data => console.log(data));
   ```
   当这段 JavaScript 代码执行时，浏览器会调用网络栈，`HttpStreamFactory` 会被用来创建一个 HTTPS 流，因为 URL 是 `https://`。这个流会处理 TLS 握手，建立安全连接，然后用于下载 `www.google.com` 的内容。  本部分中的 `TEST_P(HttpStreamFactoryTest, RequestHttpStreamOverSSL)` 就覆盖了类似场景的测试。

2. **WebSocket API:**
   ```javascript
   const websocket = new WebSocket('wss://example.com/socket');

   websocket.onopen = () => {
     console.log('WebSocket connection opened');
   };

   websocket.onmessage = (event) => {
     console.log('Message received:', event.data);
   };
   ```
   当创建 `WebSocket` 对象时，`HttpStreamFactory` 会被用来创建一个 WebSocket 握手流。这个流会发送 HTTP Upgrade 请求，完成 WebSocket 握手。 本部分中的 `TEST_P(HttpStreamFactoryTest, RequestWebSocketBasicHandshakeStreamOverSSL)` 就测试了这种场景。

**逻辑推理及假设输入与输出：**

**示例 1：`TEST_P(HttpStreamFactoryTest, RequestHttpStream)`**

* **假设输入:**
    * `HttpRequestInfo` 对象，包含 URL `http://www.google.com` 和 GET 方法。
    * 没有配置代理。
* **逻辑推理:** `HttpStreamFactory` 应该尝试直接连接到 `www.google.com` 的 80 端口，创建一个普通的 HTTP/1.1 流。
* **预期输出:**
    * `requester.stream_done()` 为 `true`，表示流创建完成。
    * `requester.stream()` 不为 `nullptr`，表示成功创建了一个 HTTP 流。
    * `requester.websocket_stream()` 为 `nullptr`，因为这是一个普通的 HTTP 请求，而不是 WebSocket。
    * `GetSpdySessionCount(session.get())` 根据 `HappyEyeballsV3` 特性是否启用，可能为 0 或 1。

**示例 2：`TEST_P(HttpStreamFactoryTest, RequestSpdyHttpStreamHttpURL)`**

* **假设输入:**
    * `HttpRequestInfo` 对象，包含 URL `http://www.google.com` 和 GET 方法。
    * 配置了一个 HTTPS 代理 `myproxy.org:443`，并且服务器声明支持 HTTP/2。
* **逻辑推理:**  由于代理支持 HTTP/2，并且目标服务器可以通过代理访问，`HttpStreamFactory` 应该通过 HTTPS 代理建立到 `myproxy.org` 的 HTTP/2 连接，并使用该连接来请求 `http://www.google.com`。同时，`HttpServerProperties` 应该被更新，记录 `myproxy.org:443` 支持 SPDY。
* **预期输出:**
    * `requester.stream_done()` 为 `true`。
    * `requester.stream()` 不为 `nullptr`。
    * `GetSpdySessionCount(session.get())` 为 1，表示创建了一个 SPDY 会话。
    * `http_server_properties->GetSupportsSpdy(...)` 返回 `true`，表示 `HttpServerProperties` 已更新。

**涉及用户或编程常见的使用错误及举例说明：**

1. **错误的代理配置:** 用户可能在操作系统或浏览器中配置了错误的代理地址或端口。这会导致 `HttpStreamFactory` 尝试连接到错误的代理服务器，导致连接失败。例如，配置了 `http://wrongproxy:8080` 但实际代理地址是 `http://correctproxy:8888`。

2. **在 HTTPS 站点上使用 `ws://` 或在 HTTP 站点上使用 `wss://`:**  开发者可能会错误地使用 WebSocket 协议，导致握手失败。例如，尝试连接到 `wss://example.com`，但服务器只支持 `ws://`。 本部分中的相关测试验证了 `HttpStreamFactory` 在这些场景下的行为。

3. **未处理证书错误:** 当访问 HTTPS 站点时，如果服务器的 SSL 证书无效或不受信任，`HttpStreamFactory` 会拒绝建立连接。 用户或程序需要正确处理这些证书错误，例如提示用户或使用允许不安全证书的配置（仅限开发环境）。

4. **混淆 HTTP 和 WebSocket 连接:** 开发者可能会尝试使用 HTTP 流来发送 WebSocket 数据，或反之，这会导致协议错误。`HttpStreamFactory` 区分了这两种类型的流，并根据请求的 URL 和协议创建相应的流。

**用户操作如何一步步地到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问 `https://www.example.com`：

1. **用户在地址栏输入 `https://www.example.com` 并按下回车键。**
2. **浏览器解析 URL，确定需要进行 HTTPS 请求。**
3. **浏览器查找本地缓存或进行 DNS 查询以获取 `www.example.com` 的 IP 地址。**
4. **浏览器创建一个网络请求对象 (可能对应 `HttpRequestInfo`)，包含请求方法 (GET)、URL、头部等信息。**
5. **浏览器的网络栈开始工作，`HttpStreamFactory` 被调用来创建处理这个请求的流。**  由于是 HTTPS 请求，`HttpStreamFactory` 会尝试创建一个支持 SSL/TLS 的流。
6. **`HttpStreamFactory` 可能会检查是否存在可重用的连接或 SPDY 会话。** 如果有，可能会复用现有的连接。
7. **如果需要建立新的连接，`HttpStreamFactory` 会与 SocketPool 交互，请求一个到 `www.example.com` 的套接字连接。**
8. **如果需要进行 TLS 握手，会使用 SSLSocket 进行处理。**
9. **一旦连接建立，就会创建一个 `HttpStream` 对象，用于发送 HTTP 请求和接收响应。**
10. **本文件中的单元测试模拟了上述过程中的各种场景，例如直接连接、通过代理连接、使用 HTTP/2 等。**

**调试线索:**

* 如果网络请求失败，可以查看 Chrome 的 `net-internals` (chrome://net-internals/#events) 日志，查找与 `HttpStreamFactory` 相关的事件，例如尝试创建连接、连接成功/失败、使用的协议等。
* 可以检查 `net-internals` 中的 Sockets 和 SPDY 会话信息，查看连接池的状态和 SPDY 会话的详细信息。
* 如果怀疑是代理问题，可以检查 `net-internals` 中的 Proxy 信息。
* 本文件中的单元测试可以作为参考，了解 `HttpStreamFactory` 在各种情况下的预期行为，有助于诊断问题。例如，如果某个功能在单元测试中失败，可能表明该功能存在 Bug。

总而言之，这部分代码通过各种单元测试用例，全面地验证了 `HttpStreamFactory` 创建不同类型 HTTP 流的能力和在各种网络条件下的正确性，确保了 Chromium 浏览器网络功能的稳定性和可靠性。

### 提示词
```
这是目录为net/http/http_stream_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
true);
  requester.MaybeWaitForSwitchesToHttpStreamPool();
  EXPECT_FALSE(requester.stream_done());

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    // When the HappyEyeballsV3 is enabled, SpdySessions never created
    // synchronously even when the mocked connects complete synchronously.
    // There is no new session at this point.
    ASSERT_EQ(0, GetSpdySessionCount(session.get()));
  } else {
    // Confirm a stream has been created by asserting that a new session
    // has been created.  (The stream is only created at the SPDY level on
    // first write, which happens after the request has returned a stream).
    ASSERT_EQ(1, GetSpdySessionCount(session.get()));
  }

  // Test to confirm that a SetPriority received after the stream is created
  // but before the request returns it does not crash.
  requester.request()->SetPriority(HIGHEST);

  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  ASSERT_TRUE(requester.stream());
  EXPECT_FALSE(requester.websocket_stream());
}

TEST_P(HttpStreamFactoryTest, RequestHttpStreamOverSSL) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  StaticSocketDataProvider socket_data(base::span_from_ref(mock_read),
                                       base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester.stream_done());
  ASSERT_TRUE(nullptr != requester.stream());
  EXPECT_TRUE(nullptr == requester.websocket_stream());

  EXPECT_EQ(0, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

TEST_P(HttpStreamFactoryTest, RequestHttpStreamOverProxy) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:8888", TRAFFIC_ANNOTATION_FOR_TESTS));

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.  It should succeed using the second proxy in the
  // list.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester.stream_done());
  ASSERT_TRUE(nullptr != requester.stream());
  EXPECT_TRUE(nullptr == requester.websocket_stream());

  EXPECT_EQ(0, GetSpdySessionCount(session.get()));
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain(ProxyServer::SCHEME_HTTP,
                                            HostPortPair("myproxy", 8888))));
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain(ProxyServer::SCHEME_HTTPS,
                                            HostPortPair("myproxy", 8888))));
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::WEBSOCKET_SOCKET_POOL,
                                 ProxyChain(ProxyServer::SCHEME_HTTP,
                                            HostPortPair("myproxy", 8888))));
  EXPECT_FALSE(requester.used_proxy_info().is_direct());
}

TEST_P(HttpStreamFactoryTest, RequestWebSocketBasicHandshakeStream) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("ws://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  WebSocketStreamCreateHelper create_helper;
  requester.RequestWebSocketHandshakeStream(
      session->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{}, &create_helper,
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);
  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_TRUE(nullptr == requester.stream());
  ASSERT_TRUE(nullptr != requester.websocket_stream());
  EXPECT_EQ(MockWebSocketHandshakeStream::kStreamTypeBasic,
            requester.websocket_stream()->type());
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

TEST_P(HttpStreamFactoryTest, RequestWebSocketBasicHandshakeStreamOverSSL) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  StaticSocketDataProvider socket_data(base::span_from_ref(mock_read),
                                       base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("wss://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  WebSocketStreamCreateHelper create_helper;
  requester.RequestWebSocketHandshakeStream(
      session->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{}, &create_helper,
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);
  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_TRUE(nullptr == requester.stream());
  ASSERT_TRUE(nullptr != requester.websocket_stream());
  EXPECT_EQ(MockWebSocketHandshakeStream::kStreamTypeBasic,
            requester.websocket_stream()->type());
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

TEST_P(HttpStreamFactoryTest, RequestWebSocketBasicHandshakeStreamOverProxy) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:8888", TRAFFIC_ANNOTATION_FOR_TESTS));

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, "HTTP/1.0 200 Connection established\r\n\r\n")};
  StaticSocketDataProvider socket_data(reads, base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("ws://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  WebSocketStreamCreateHelper create_helper;
  requester.RequestWebSocketHandshakeStream(
      session->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{}, &create_helper,
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);
  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_TRUE(nullptr == requester.stream());
  ASSERT_TRUE(nullptr != requester.websocket_stream());
  EXPECT_EQ(MockWebSocketHandshakeStream::kStreamTypeBasic,
            requester.websocket_stream()->type());
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::WEBSOCKET_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain(ProxyServer::SCHEME_HTTP,
                                            HostPortPair("myproxy", 8888))));
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::WEBSOCKET_SOCKET_POOL,
                                 ProxyChain(ProxyServer::SCHEME_HTTP,
                                            HostPortPair("myproxy", 8888))));
  EXPECT_FALSE(requester.used_proxy_info().is_direct());
}

TEST_P(HttpStreamFactoryTest, RequestSpdyHttpStreamHttpsURL) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  HostPortPair host_port_pair("www.google.com", 443);
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester.stream_done());
  EXPECT_TRUE(nullptr == requester.websocket_stream());
  ASSERT_TRUE(nullptr != requester.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

TEST_P(HttpStreamFactoryTest, RequestSpdyHttpStreamHttpURL) {
  url::SchemeHostPort scheme_host_port("http", "myproxy.org", 443);
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy.org:443", TRAFFIC_ANNOTATION_FOR_TESTS));
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy.org:443", TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps->socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps->socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  session_deps->proxy_resolution_service = std::move(proxy_resolution_service);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(session_deps.get()));

  HttpServerProperties* http_server_properties =
      session->spdy_session_pool()->http_server_properties();
  EXPECT_FALSE(http_server_properties->GetSupportsSpdy(
      scheme_host_port, NetworkAnonymizationKey()));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester.stream_done());
  EXPECT_TRUE(nullptr == requester.websocket_stream());
  ASSERT_TRUE(nullptr != requester.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_FALSE(requester.used_proxy_info().is_direct());
  EXPECT_TRUE(http_server_properties->GetSupportsSpdy(
      scheme_host_port, NetworkAnonymizationKey()));
}

// Same as above, but checks HttpServerProperties is updated using the correct
// NetworkAnonymizationKey. When/if NetworkAnonymizationKey is enabled by
// default, this should probably be merged into the above test.
TEST_P(HttpStreamFactoryTest,
       RequestSpdyHttpStreamHttpURLWithNetworkAnonymizationKey) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const NetworkIsolationKey kNetworkIsolationKey2(kSite1, kSite1);

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  url::SchemeHostPort scheme_host_port("http", "myproxy.org", 443);
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy.org:443", TRAFFIC_ANNOTATION_FOR_TESTS));
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy.org:443", TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps->socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps->socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  session_deps->proxy_resolution_service = std::move(proxy_resolution_service);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(session_deps.get()));

  HttpServerProperties* http_server_properties =
      session->spdy_session_pool()->http_server_properties();
  EXPECT_FALSE(http_server_properties->GetSupportsSpdy(
      scheme_host_port, kNetworkAnonymizationKey1));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.load_flags = 0;
  request_info.network_isolation_key = kNetworkIsolationKey1;
  request_info.network_anonymization_key = kNetworkAnonymizationKey1;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester.stream_done());
  EXPECT_TRUE(nullptr == requester.websocket_stream());
  ASSERT_TRUE(nullptr != requester.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(0, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_FALSE(requester.used_proxy_info().is_direct());
  EXPECT_TRUE(http_server_properties->GetSupportsSpdy(
      scheme_host_port, kNetworkAnonymizationKey1));
  // Other NetworkAnonymizationKeys should not be recorded as supporting SPDY.
  EXPECT_FALSE(http_server_properties->GetSupportsSpdy(
      scheme_host_port, NetworkAnonymizationKey()));
  EXPECT_FALSE(http_server_properties->GetSupportsSpdy(
      scheme_host_port, kNetworkAnonymizationKey2));
}

// Tests that when a new SpdySession is established, duplicated idle H2 sockets
// to the same server are closed.
TEST_P(HttpStreamFactoryTest, NewSpdySessionCloseIdleH2Sockets) {
  // Explicitly disable the HappyEyeballsV3 feature because this test relies on
  // ClientSocketPool. When HappyEyeballsV3 is enabled we immediately create
  // a SpdySession after negotiating to use HTTP/2 so there would be no idle
  // HTTP/2 sockets when the feature is enabled.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  const int kNumIdleSockets = 4;
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  std::vector<std::unique_ptr<SequencedSocketData>> providers;
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  for (int i = 0; i < kNumIdleSockets; i++) {
    auto provider =
        std::make_unique<SequencedSocketData>(reads, base::span<MockWrite>());
    provider->set_connect_data(MockConnect(ASYNC, OK));
    session_deps.socket_factory->AddSocketDataProvider(provider.get());
    providers.push_back(std::move(provider));
    session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  }

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  url::SchemeHostPort destination(url::kHttpsScheme, "www.google.com", 443);

  // Create some HTTP/2 sockets.
  std::vector<std::unique_ptr<ClientSocketHandle>> handles;
  for (size_t i = 0; i < kNumIdleSockets; i++) {
    auto connection = std::make_unique<ClientSocketHandle>();
    TestCompletionCallback callback;
    scoped_refptr<ClientSocketPool::SocketParams> socket_params =
        base::MakeRefCounted<ClientSocketPool::SocketParams>(
            /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    ClientSocketPool::GroupId group_id(
        destination, PrivacyMode::PRIVACY_MODE_DISABLED,
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_network_fetches=*/false);
    int rv = connection->Init(
        group_id, socket_params, std::nullopt /* proxy_annotation_tag */,
        MEDIUM, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
        callback.callback(), ClientSocketPool::ProxyAuthCallback(),
        session->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                               ProxyChain::Direct()),
        NetLogWithSource());
    rv = callback.GetResult(rv);
    handles.push_back(std::move(connection));
  }

  // Releases handles now, and these sockets should go into the socket pool.
  handles.clear();
  EXPECT_EQ(kNumIdleSockets,
            session
                ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                ProxyChain::Direct())
                ->IdleSocketCount());

  // Request two streams at once and make sure they use the same connection.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester1(session.get());
  StreamRequester requester2(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_TRUE(requester2.stream_done());
  ASSERT_NE(nullptr, requester1.stream());
  ASSERT_NE(nullptr, requester2.stream());
  ASSERT_NE(requester1.stream(), requester2.stream());

  // Establishing the SpdySession will close idle H2 sockets.
  EXPECT_EQ(0, session
                   ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                   ProxyChain::Direct())
                   ->IdleSocketCount());
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
}

// Regression test for https://crbug.com/706974.
TEST_P(HttpStreamFactoryTest, TwoSpdyConnects) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  SSLSocketDataProvider ssl_socket_data0(ASYNC, OK);
  ssl_socket_data0.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data0);

  MockRead reads0[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  SequencedSocketData data0(reads0, base::span<MockWrite>());
  data0.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&data0);

  SSLSocketDataProvider ssl_socket_data1(ASYNC, OK);
  ssl_socket_data1.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data1);

  SequencedSocketData data1;
  data1.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&data1);

  std::unique_ptr<HttpNetworkSession> session =
      SpdySessionDependencies::SpdyCreateSession(&session_deps);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Request two streams at once and make sure they use the same connection.
  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  EXPECT_TRUE(requester1.stream_done());
  EXPECT_TRUE(requester2.stream_done());
  ASSERT_NE(nullptr, requester1.stream());
  ASSERT_NE(nullptr, requester2.stream());
  ASSERT_NE(requester1.stream(), requester2.stream());

  // Establishing the SpdySession will close the extra H2 socket.
  EXPECT_EQ(0, session
                   ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                   ProxyChain::Direct())
                   ->IdleSocketCount());
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_TRUE(data0.AllReadDataConsumed());
  EXPECT_TRUE(data1.AllReadDataConsumed());
}

TEST_P(HttpStreamFactoryTest, RequestBidirectionalStreamImpl) {
  base::test::ScopedFeatureList scoped_feature_list;
  // Explicitly disable HappyEyeballsV3 because it doesn't support bidirectional
  // streams yet.
  // TODO(crbug.com/346835898): Support bidirectional streams in
  // HappyEyeballsV3.
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestBidirectionalStreamImpl(
      session->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{},
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);
  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  ASSERT_FALSE(requester.stream());
  ASSERT_TRUE(requester.bidirectional_stream_impl());
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

// Tests for creating an HTTP stream via QUIC.
class HttpStreamFactoryQuicTest
    : public TestWithTaskEnvironment,
      public ::testing::WithParamInterface<QuicTestParams> {
 protected:
  HttpStreamFactoryQuicTest()
      : version_(GetParam().quic_version),
        quic_context_(std::make_unique<MockQuicContext>()),
        session_deps_(ConfiguredProxyResolutionService::CreateDirect()),
        clock_(quic_context_->clock()),
        random_generator_(quic_context_->random_generator()) {
    FLAGS_quic_enable_http3_grease_randomness = false;
    quic::QuicEnableVersion(version_);
    quic_context_->params()->supported_versions =
        quic::test::SupportedVersions(version_);
    quic_context_->params()->origins_to_force_quic_on.insert(
        HostPortPair::FromString("www.example.org:443"));
    quic_context_->AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
    session_deps_.enable_quic = true;
    session_deps_.quic_context = std::move(quic_context_);

    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    verify_details_.cert_verify_result.verified_cert = test_cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    auto mock_crypto_client_stream_factory =
        std::make_unique<MockCryptoClientStreamFactory>();
    mock_crypto_client_stream_factory->AddProofVerifyDetails(&verify_details_);
    mock_crypto_client_stream_factory->set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    session_deps_.quic_crypto_client_stream_factory =
        std::move(mock_crypto_client_stream_factory);

    session_deps_.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("test-lang", "test-ua");
  }

  HttpNetworkSession* MakeSession() {
    session_ = SpdySessionDependencies::SpdyCreateSessionWithSocketFactory(
        &session_deps_, &socket_factory_);
    session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
        true);
    return session_.get();
  }

  void TearDown() override { session_.reset(); }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructInitialSettingsPacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number) {
    return packet_maker.MakeInitialSettingsPacket(packet_number);
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructAckPacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number,
      uint64_t packet_num_received,
      uint64_t smallest_received,
      uint64_t largest_received) {
    return packet_maker.Packet(packet_number)
        .AddAckFrame(packet_num_received, smallest_received, largest_received)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructConnectUdpRequestPacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      std::string authority,
      std::string path,
      bool fin) {
    quiche::HttpHeaderBlock headers;
    headers[":scheme"] = "https";
    headers[":path"] = path;
    headers[":protocol"] = "connect-udp";
    headers[":method"] = "CONNECT";
    headers[":authority"] = authority;
    headers["user-agent"] = "test-ua";
    headers["capsule-protocol"] = "?1";
    spdy::SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
    size_t spdy_headers_frame_len;
    auto rv = packet_maker.MakeRequestHeadersPacket(
        packet_number, stream_id, fin, priority, std::move(headers),
        &spdy_headers_frame_len, /*should_include_priority_frame=*/false);
    return rv;
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructOkResponsePacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      bool fin) {
    quiche::HttpHeaderBlock headers = packet_maker.GetResponseHeaders("200");
    size_t spdy_headers_frame_len;
    return packet_maker.MakeResponseHeadersPacket(packet_number, stream_id, fin,
                                                  std::move(headers),
```