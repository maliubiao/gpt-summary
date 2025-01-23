Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Understanding the Goal:**

The request asks for the functionality of the `quic_network_transaction_unittest.cc` file, specifically within the Chromium network stack. It also probes for connections to JavaScript, logical reasoning examples, common user errors, debugging hints, and a summary of the provided code snippet (part 11 of 13).

**2. Initial Scan and Keyword Recognition:**

I immediately scan the code for keywords and patterns:

* **`TEST_P`:**  Indicates parameterized tests. This means the tests are run with different configurations or input values. The parameterization is likely based on QUIC versions.
* **`QuicNetworkTransactionTest`:**  This is the test fixture class. It sets up the environment for testing `HttpNetworkTransaction` in the context of QUIC.
* **`MockQuicData`:** This is a crucial component. It's a mock object simulating QUIC network behavior (sending and receiving packets). This is how the tests control the QUIC interaction.
* **`ConstructInitialSettingsPacket`, `ConstructClientPriorityPacket`, `ConstructClientRequestHeadersPacket`:** These function names strongly suggest the tests are verifying the correct structure and content of QUIC packets sent by the client.
* **`ConnectRequestHeaders`:**  This implies testing scenarios where the client is connecting through a QUIC proxy.
* **`EXPECT_EQ`, `EXPECT_TRUE`:** Standard Google Test assertions to verify expected outcomes.
* **`ERR_IO_PENDING`, `OK`, `ERR_CERT_AUTHORITY_INVALID`, `ERR_QUIC_PROTOCOL_ERROR`, `ERR_CONNECTION_FAILED`, `ERR_FAILED`:**  Network error codes, indicating tests are checking how the system handles various error conditions.
* **`HttpRequestHeaders`, `HttpResponseInfo`:** Standard Chromium network classes, showing the interaction with the higher-level HTTP transaction API.
* **`NetworkChangeNotifier`:**  This suggests a test case related to network connectivity changes.
* **`proxy_resolution_service_`:**  Another indicator of proxy-related tests.
* **`AuthCredentials`, `AuthChallengeInfo`:**  Specifically points to tests for HTTP authentication over QUIC proxies.
* **`NetworkIsolationKey`, `NetworkAnonymizationKey`:**  Highlights tests related to network isolation and privacy features.
* **`kPartitionConnectionsByNetworkIsolationKey`:** A feature flag relevant to network isolation.

**3. Deeper Dive into Individual Tests:**

I then examine each test function (`TEST_P`) individually:

* **`QuicProxyRestartNoLastError`:** Focuses on restarting a QUIC proxy connection after a certificate error. The key is understanding the sequence of `Start` and `RestartIgnoringLastError`.
* **`QuicProxyUserAgent`:** Checks if the correct user-agent header is sent in the CONNECT request to a QUIC proxy. It highlights the difference between configured and request-specific user agents.
* **`QuicProxyRequestPriority`:** Verifies that the request priority is correctly encoded in the QUIC CONNECT request to a proxy.
* **`QuicProxyMultipleRequestsError`:** Tests how the system handles multiple concurrent requests through a QUIC proxy when the initial connection fails. It involves setting socket pool limits.
* **`QuicProxyAuth`:**  A complex test simulating the HTTP basic authentication handshake over a QUIC proxy. It verifies the handling of 407 Proxy Authentication Required responses and the `RestartWithAuth` mechanism. The loop (`for (int i = 0; i < 2; ++i)`) indicates testing different timings of data arrival.
* **`NetworkIsolation`:** Tests the behavior of QUIC connections when network isolation is enabled or disabled. It verifies that requests with different `NetworkIsolationKey` values either share a connection or create separate ones, depending on the feature flag.
* **`NetworkIsolationTunnel`:** Specifically tests network isolation in the context of QUIC *tunnels* (connections through a proxy). It confirms that requests with different isolation keys use different QUIC sessions when the feature is enabled.

**4. Identifying Core Functionality:**

Based on the individual test analyses, I synthesize the overall functionality of the file:

* **Testing `HttpNetworkTransaction` with QUIC:** The primary goal is to ensure that HTTP requests using QUIC are handled correctly.
* **QUIC Proxy Scenarios:** A significant portion of the tests focuses on interactions with QUIC proxies, including connection setup, authentication, and header handling.
* **Error Handling:** Tests cover various error conditions that can occur during QUIC connections.
* **Request Prioritization:**  Verifying that request priorities are properly communicated in QUIC.
* **Network Isolation:**  Ensuring that network isolation features work as expected with QUIC.

**5. Addressing Specific Questions:**

* **JavaScript Relationship:** I consider if any of the tested functionalities directly relate to how JavaScript would interact with the network stack (e.g., through `fetch`). While the tests are low-level, the user-agent test is a good example because the user-agent string is often set by the browser environment, including JavaScript.
* **Logical Reasoning:** I look for tests where the outcome isn't immediately obvious and requires a sequence of actions and assertions. The `QuicProxyRestartNoLastError` and `QuicProxyAuth` tests are good examples where the order of operations and expected state transitions are important. I create hypothetical inputs and outputs based on the test logic.
* **User/Programming Errors:**  I think about common mistakes developers might make when using the Chromium network stack, such as incorrect proxy configuration or not handling authentication challenges. The proxy authentication test directly addresses this.
* **Debugging:** I consider how a developer might end up at this code during debugging. Network errors, especially related to QUIC or proxies, would lead a developer to investigate these tests. I trace back user actions to potential triggers.

**6. Summarizing Part 11:**

Finally, I review the specific code snippet provided (Part 11) and summarize its functionality. It primarily covers tests related to network isolation, including both direct QUIC connections and connections through QUIC proxies (tunnels).

**Self-Correction/Refinement:**

* **Initial thought:**  Maybe focus too much on individual packet details.
* **Correction:** Realize the high-level *functionality* being tested is more important than the exact byte sequence of each packet (though the tests do verify that).
* **Initial thought:**  Overlook the significance of the parameterized tests.
* **Correction:** Recognize that the `version_` parameter is key to testing different QUIC protocol versions.
* **Initial thought:**  Not clearly connecting the tests to user actions.
* **Correction:**  Think about what a user would *do* that would trigger these network requests (e.g., visiting a website, encountering a proxy, needing to authenticate).

By following this systematic approach, I can effectively analyze the C++ unittest file and address all aspects of the request.
这个文件 `net/quic/quic_network_transaction_unittest.cc` 是 Chromium 网络栈中专门用于测试 `HttpNetworkTransaction` 类在 QUIC 协议下的行为的单元测试文件。  `HttpNetworkTransaction` 是网络栈中处理 HTTP 请求的核心类之一，它负责发起请求、处理响应等。  这个测试文件确保了当底层使用 QUIC 协议时，`HttpNetworkTransaction` 的各种功能能够正常工作。

以下是这个文件的主要功能：

1. **测试基本的 QUIC 连接和数据传输:**  验证 `HttpNetworkTransaction` 能否成功建立 QUIC 连接，发送请求，并接收响应数据。
2. **测试 QUIC 代理场景:**  涵盖了通过 QUIC 代理服务器连接到目标服务器的各种情况，包括连接建立、请求发送、响应接收等。
3. **测试 QUIC 代理认证:**  验证 `HttpNetworkTransaction` 如何处理 QUIC 代理服务器的身份验证挑战（例如，Basic 认证），包括重试认证请求。
4. **测试请求优先级:**  检查 `HttpNetworkTransaction` 设置的请求优先级是否正确地传递到 QUIC 层。
5. **测试网络隔离 (Network Isolation) 和网络匿名化 (Network Anonymization):**  验证在启用网络隔离和网络匿名化功能时，QUIC 连接是否按照预期进行隔离和处理。
6. **测试连接重用和管理:**  验证在多个请求之间 QUIC 连接是否可以正确地被重用，以及连接池的管理机制是否正常工作。
7. **测试错误处理:**  测试 `HttpNetworkTransaction` 在遇到各种 QUIC 协议错误时的处理方式，例如连接失败、协议错误等。
8. **模拟网络行为:**  使用 `MockQuicData` 来模拟 QUIC 连接中的数据包发送和接收，以便精确控制测试场景。

**与 JavaScript 的功能关系及举例说明:**

虽然这个文件是 C++ 代码，直接与 JavaScript 没有代码上的交互，但它测试的网络功能是 JavaScript 通过 Web API (如 `fetch` 或 `XMLHttpRequest`) 发起网络请求的基础。  例如：

* **用户代理 (User-Agent) 头:**  `QuicNetworkTransactionTest.QuicProxyUserAgent` 测试确保了通过 QUIC 代理发送请求时，配置的 User-Agent 头被正确发送。  在 JavaScript 中，浏览器会根据自身信息设置 User-Agent 头，服务端可以根据这个头信息来判断客户端类型。

   **举例:**
   ```javascript
   // 在 JavaScript 中使用 fetch 发起请求
   fetch('https://mail.example.org/', {
       headers: {
           'User-Agent': 'MyCustomUserAgent'
       }
   }).then(response => {
       // 处理响应
   });
   ```
   这个 C++ 测试确保了当这个 JavaScript 代码在底层使用 QUIC 并通过代理时，`MyCustomUserAgent` 这个值能够正确地传递到代理服务器。

* **网络隔离:** `QuicNetworkTransactionTest.NetworkIsolation` 测试了网络隔离功能。  在浏览器中，网络隔离可以防止不同源的页面共享连接，从而提高安全性。当 JavaScript 从不同的域名发起请求时，这个测试确保了 QUIC 连接会被正确地隔离。

   **举例:**  假设一个网页 `http://origin1/index.html`  使用 JavaScript 发起对 `https://mail.example.org/1` 和 `https://mail.example.org/2` 的请求，而另一个网页 `http://origin2/index.html` 也发起对 `https://mail.example.org/2` 的请求。  网络隔离功能确保了来自 `origin1` 和 `origin2` 的请求即使目标相同，也可能使用不同的 QUIC 连接（取决于是否启用和如何配置网络隔离）。

**逻辑推理的假设输入与输出:**

以 `QuicNetworkTransactionTest.QuicProxyRestartNoLastError` 为例：

**假设输入:**

1. 一个配置为使用 QUIC 代理的 `HttpNetworkSession`。
2. 一个指向需要通过代理访问的 HTTPS 站点的 `HttpRequestInfo` 对象。
3. 模拟的 QUIC 数据流，初始请求尝试连接代理时返回证书授权无效的错误 (`ERR_CERT_AUTHORITY_INVALID`)。
4. 调用 `RestartIgnoringLastError` 后，模拟的 QUIC 数据流成功建立连接并返回 HTTP 响应。

**预期输出:**

1. 第一次调用 `trans.Start()` 返回 `ERR_IO_PENDING`，表示异步操作正在进行。
2. `callback.WaitForResult()` 返回 `ERR_CERT_AUTHORITY_INVALID`，表示初始连接尝试失败。
3. 调用 `trans.RestartIgnoringLastError()` 返回 `ERR_IO_PENDING`。
4. `callback.WaitForResult()` 返回 `OK`，表示忽略错误后重新连接成功。
5. `CheckWasHttpResponse(&trans)` 验证响应是一个 HTTP 响应。
6. `CheckResponsePort(&trans, kQuicProxyChain.First().GetPort())` 验证响应来自预期的代理端口。
7. `CheckResponseData(&trans, kRespData)` 验证接收到的响应数据是预期的。
8. `trans.GetResponseInfo()->proxy_chain` 包含预期的代理链信息。

**涉及用户或编程常见的使用错误及举例说明:**

* **未正确配置代理:** 用户如果手动配置了错误的 QUIC 代理地址或端口，那么 `HttpNetworkTransaction` 在尝试连接时会失败。  例如，`QuicNetworkTransactionTest` 中通过 `ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest` 来设置代理，如果用户的配置与此不符，就会出现连接问题。

* **没有处理代理认证:**  如果用户需要通过需要身份验证的 QUIC 代理访问资源，但代码中没有处理 `407 Proxy Authentication Required` 响应并提供凭据，那么请求会失败。 `QuicNetworkTransactionTest.QuicProxyAuth` 测试了这种情况，并展示了如何使用 `RestartWithAuth` 来处理认证。  常见的编程错误是忘记检查响应状态码，或者没有正确实现认证逻辑。

* **网络隔离配置不当:**  开发者可能不理解或错误配置了网络隔离相关的设置，导致预期的连接重用没有发生，或者出现意外的连接失败。  `QuicNetworkTransactionTest.NetworkIsolation`  和 `QuicNetworkTransactionTest.NetworkIsolationTunnel`  测试了不同网络隔离配置下的行为，帮助开发者理解其影响。

**用户操作如何一步步到达这里作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个使用了 QUIC 协议的 HTTPS 网站，并且这个连接是通过一个 QUIC 代理建立的。  如果用户遇到了网络问题，例如页面加载缓慢或失败，开发人员可能会采取以下调试步骤，最终可能涉及到这个测试文件：

1. **检查网络连接:**  确认用户的网络是否正常。
2. **检查 Chrome 的网络设置:**  查看是否配置了代理服务器。
3. **使用 Chrome 的 `chrome://net-internals/#quic`:**  查看 QUIC 连接的状态和日志，可能会看到连接错误或异常。
4. **查看 `chrome://net-internals/#http2`:**  即使是 QUIC，某些信息也会在这里显示。
5. **如果怀疑是代理问题:**  检查代理服务器的配置和状态。
6. **查看 Chrome 的 NetLog:**  捕获详细的网络事件日志，其中会包含 `HttpNetworkTransaction` 和 QUIC 相关的事件。
7. **如果问题涉及到特定的 QUIC 行为或代理交互:**  网络栈的开发人员可能会查看 `net/quic` 目录下的代码，包括这个测试文件，来理解 `HttpNetworkTransaction` 在 QUIC 场景下的预期行为，并对照实际的 NetLog 信息进行分析。
8. **运行相关的单元测试:**  如果怀疑是代码缺陷，开发人员会运行 `quic_network_transaction_unittest.cc` 中的相关测试用例，例如 `QuicProxyAuth` 或 `NetworkIsolationTunnel`，来复现问题或验证修复。

**第11部分功能归纳:**

从提供的代码片段来看，第 11 部分主要集中在以下功能的测试：

* **QUIC 代理认证 (续):**  测试了通过 QUIC 代理进行基本身份验证的流程，包括接收 `407` 响应，然后使用正确的凭据重新发起请求。它特别关注了在身份验证挑战后，即使在隐私模式下也应尝试代理身份验证。
* **网络隔离 (Network Isolation):**  测试了在启用 `kPartitionConnectionsByNetworkIsolationKey` 功能时，对于相同 origin 但具有不同 `NetworkIsolationKey` 的请求，是否会建立不同的 QUIC 连接。这部分测试了在非代理场景下的网络隔离。
* **网络隔离与 QUIC 隧道 (代理):**  测试了在启用 `kPartitionConnectionsByNetworkIsolationKey` 功能时，通过 QUIC 代理（隧道）访问相同 origin，但具有不同 `NetworkIsolationKey` 的请求，是否会使用不同的 QUIC 会话。

总的来说，第 11 部分重点验证了 `HttpNetworkTransaction` 在涉及 QUIC 代理认证和网络隔离时的正确行为，特别强调了网络隔离功能在 QUIC 连接和 QUIC 隧道中的作用。

### 提示词
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
k callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_EQ(ERR_IO_PENDING, rv);
  EXPECT_EQ(ERR_CERT_AUTHORITY_INVALID, callback.WaitForResult());

  rv = trans.RestartIgnoringLastError(callback.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);
  EXPECT_EQ(OK, callback.WaitForResult());

  CheckWasHttpResponse(&trans);
  CheckResponsePort(&trans, kQuicProxyChain.First().GetPort());
  CheckResponseData(&trans, kRespData);
  EXPECT_EQ(trans.GetResponseInfo()->proxy_chain, kQuicProxyChain);

  // Causes MockSSLClientSocket to disconnect, which causes the underlying QUIC
  // proxy socket to disconnect.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

// Checks if a request's specified "user-agent" header shows up correctly in the
// CONNECT request to a QUIC proxy.
TEST_P(QuicNetworkTransactionTest, QuicProxyUserAgent) {
  DisablePriorityHeader();
  const char kConfiguredUserAgent[] = "Configured User-Agent";
  const char kRequestUserAgent[] = "Request User-Agent";
  session_params_.enable_quic = true;
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
              ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)})},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientPriorityPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          DEFAULT_PRIORITY));

  quiche::HttpHeaderBlock headers =
      ConnectRequestHeaders("mail.example.org:443");
  headers["user-agent"] = kConfiguredUserAgent;
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), false,
          DEFAULT_PRIORITY, std::move(headers), false));
  // Return an error, so the transaction stops here (this test isn't interested
  // in the rest).
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_FAILED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  StaticHttpUserAgentSettings http_user_agent_settings(
      std::string() /* accept_language */, kConfiguredUserAgent);
  session_context_.http_user_agent_settings = &http_user_agent_settings;
  CreateSession();

  request_.url = GURL("https://mail.example.org/");
  request_.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent,
                                   kRequestUserAgent);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_EQ(ERR_IO_PENDING, rv);
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback.WaitForResult());

  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

// Makes sure the CONNECT request packet for a QUIC proxy contains the correct
// HTTP/2 stream dependency and weights given the request priority.
TEST_P(QuicNetworkTransactionTest, QuicProxyRequestPriority) {
  DisablePriorityHeader();
  session_params_.enable_quic = true;
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
              ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)})},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  const RequestPriority request_priority = MEDIUM;

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
          DEFAULT_PRIORITY, ConnectRequestHeaders("mail.example.org:443"),
          false));
  // Return an error, so the transaction stops here (this test isn't interested
  // in the rest).
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_FAILED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  request_.url = GURL("https://mail.example.org/");
  HttpNetworkTransaction trans(request_priority, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_EQ(ERR_IO_PENDING, rv);
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback.WaitForResult());

  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

// Makes sure the CONNECT request packet for a QUIC proxy contains the correct
// HTTP/2 stream dependency and weights given the request priority.
TEST_P(QuicNetworkTransactionTest, QuicProxyMultipleRequestsError) {
  session_params_.enable_quic = true;
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
              ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)})},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  const RequestPriority kRequestPriority = MEDIUM;
  const RequestPriority kRequestPriority2 = LOWEST;

  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddWrite(ASYNC, ConstructInitialSettingsPacket(1));
  mock_quic_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  // This should never be reached.
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_FAILED);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // Second connection attempt just fails - result doesn't really matter.
  MockQuicData mock_quic_data2(version_);
  mock_quic_data2.AddConnect(SYNCHRONOUS, ERR_FAILED);
  mock_quic_data2.AddSocketDataToFactory(&socket_factory_);

  int original_max_sockets_per_group =
      ClientSocketPoolManager::max_sockets_per_group(
          HttpNetworkSession::SocketPoolType::NORMAL_SOCKET_POOL);
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::SocketPoolType::NORMAL_SOCKET_POOL, 1);
  int original_max_sockets_per_pool =
      ClientSocketPoolManager::max_sockets_per_pool(
          HttpNetworkSession::SocketPoolType::NORMAL_SOCKET_POOL);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::SocketPoolType::NORMAL_SOCKET_POOL, 1);
  CreateSession();

  request_.url = GURL("https://mail.example.org/");
  HttpNetworkTransaction trans(kRequestPriority, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_EQ(ERR_IO_PENDING, rv);

  HttpRequestInfo request2;
  request2.url = GURL("https://mail.example.org/some/other/path/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans2(kRequestPriority2, session_.get());
  TestCompletionCallback callback2;
  int rv2 = trans2.Start(&request2, callback2.callback(), net_log_with_source_);
  EXPECT_EQ(ERR_IO_PENDING, rv2);

  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR, callback.WaitForResult());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());

  EXPECT_EQ(ERR_FAILED, callback2.WaitForResult());

  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::SocketPoolType::NORMAL_SOCKET_POOL,
      original_max_sockets_per_pool);
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::SocketPoolType::NORMAL_SOCKET_POOL,
      original_max_sockets_per_group);
}

// Test the request-challenge-retry sequence for basic auth, over a QUIC
// connection when setting up a QUIC proxy tunnel.
TEST_P(QuicNetworkTransactionTest, QuicProxyAuth) {
  const std::u16string kBaz(u"baz");
  const std::u16string kFoo(u"foo");

  session_params_.enable_quic = true;
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
              ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)})},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  // On the second pass, the body read of the auth challenge is synchronous, so
  // IsConnectedAndIdle returns false.  The socket should still be drained and
  // reused. See http://crbug.com/544255.
  for (int i = 0; i < 2; ++i) {
    QuicTestPacketMaker client_maker(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        true);
    QuicTestPacketMaker server_maker(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_SERVER,
        false);

    MockQuicData mock_quic_data(version_);

    int packet_num = 1;
    mock_quic_data.AddWrite(
        SYNCHRONOUS, client_maker.MakeInitialSettingsPacket(packet_num++));

    mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker.MakePriorityPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
            quic::HttpStreamPriority::kDefaultUrgency));

    mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker.MakeRequestHeadersPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), false,
            quic::HttpStreamPriority::kDefaultUrgency,
            client_maker.ConnectRequestHeaders("mail.example.org:443"), nullptr,
            false));

    quiche::HttpHeaderBlock headers = server_maker.GetResponseHeaders("407");
    headers["proxy-authenticate"] = "Basic realm=\"MyRealm1\"";
    headers["content-length"] = "10";
    mock_quic_data.AddRead(
        ASYNC, server_maker.MakeResponseHeadersPacket(
                   1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                   std::move(headers), nullptr));

    if (i == 0) {
      mock_quic_data.AddRead(
          ASYNC,
          server_maker.Packet(2)
              .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                              false, "0123456789")
              .Build());
    } else {
      mock_quic_data.AddRead(
          SYNCHRONOUS,
          server_maker.Packet(2)
              .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                              false, "0123456789")
              .Build());
    }

    mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker.Packet(packet_num++).AddAckFrame(1, 2, 1).Build());

    mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker.Packet(packet_num++)
            .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                            StreamCancellationQpackDecoderInstruction(0))
            .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                                 quic::QUIC_STREAM_CANCELLED)
            .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
            .Build());

    mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker.MakePriorityPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(1),
            quic::HttpStreamPriority::kDefaultUrgency));

    headers = client_maker.ConnectRequestHeaders("mail.example.org:443");
    headers["proxy-authorization"] = "Basic Zm9vOmJheg==";
    mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker.MakeRequestHeadersPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(1), false,
            quic::HttpStreamPriority::kDefaultUrgency, std::move(headers),
            nullptr, false));

    // Response to wrong password
    headers = server_maker.GetResponseHeaders("407");
    headers["proxy-authenticate"] = "Basic realm=\"MyRealm1\"";
    headers["content-length"] = "10";
    mock_quic_data.AddRead(
        ASYNC, server_maker.MakeResponseHeadersPacket(
                   3, GetNthClientInitiatedBidirectionalStreamId(1), false,
                   std::move(headers), nullptr));
    mock_quic_data.AddRead(SYNCHRONOUS,
                           ERR_IO_PENDING);  // No more data to read

    mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker.Packet(packet_num++)
            .AddAckFrame(/*first_received=*/1, /*largest_received=*/3,
                         /*smallest_received=*/3)
            .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                            StreamCancellationQpackDecoderInstruction(1, false))
            .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(1),
                                 quic::QUIC_STREAM_CANCELLED)
            .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(1),
                               quic::QUIC_STREAM_CANCELLED)
            .Build());

    mock_quic_data.AddSocketDataToFactory(&socket_factory_);
    mock_quic_data.GetSequencedSocketData()->set_busy_before_sync_reads(true);

    CreateSession();

    request_.url = GURL("https://mail.example.org/");
    // Ensure that proxy authentication is attempted even
    // when privacy mode is enabled.
    request_.privacy_mode = PRIVACY_MODE_ENABLED;
    {
      HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
      RunTransaction(&trans);

      const HttpResponseInfo* response = trans.GetResponseInfo();
      ASSERT_TRUE(response != nullptr);
      ASSERT_TRUE(response->headers.get() != nullptr);
      EXPECT_EQ("HTTP/1.1 407", response->headers->GetStatusLine());
      EXPECT_TRUE(response->headers->IsKeepAlive());
      EXPECT_EQ(407, response->headers->response_code());
      EXPECT_EQ(10, response->headers->GetContentLength());
      EXPECT_EQ(HttpVersion(1, 1), response->headers->GetHttpVersion());
      std::optional<AuthChallengeInfo> auth_challenge =
          response->auth_challenge;
      ASSERT_TRUE(auth_challenge.has_value());
      EXPECT_TRUE(auth_challenge->is_proxy);
      EXPECT_EQ("https://proxy.example.org:70",
                auth_challenge->challenger.Serialize());
      EXPECT_EQ("MyRealm1", auth_challenge->realm);
      EXPECT_EQ("basic", auth_challenge->scheme);

      TestCompletionCallback callback;
      int rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBaz),
                                     callback.callback());
      EXPECT_EQ(ERR_IO_PENDING, rv);
      EXPECT_EQ(OK, callback.WaitForResult());

      response = trans.GetResponseInfo();
      ASSERT_TRUE(response != nullptr);
      ASSERT_TRUE(response->headers.get() != nullptr);
      EXPECT_EQ("HTTP/1.1 407", response->headers->GetStatusLine());
      EXPECT_TRUE(response->headers->IsKeepAlive());
      EXPECT_EQ(407, response->headers->response_code());
      EXPECT_EQ(10, response->headers->GetContentLength());
      EXPECT_EQ(HttpVersion(1, 1), response->headers->GetHttpVersion());
      auth_challenge = response->auth_challenge;
      ASSERT_TRUE(auth_challenge.has_value());
      EXPECT_TRUE(auth_challenge->is_proxy);
      EXPECT_EQ("https://proxy.example.org:70",
                auth_challenge->challenger.Serialize());
      EXPECT_EQ("MyRealm1", auth_challenge->realm);
      EXPECT_EQ("basic", auth_challenge->scheme);
    }
    // HttpNetworkTransaction is torn down now that it's out of scope, causing
    // the QUIC stream to be cleaned up (since the proxy socket cannot be
    // reused because it's not connected).
    EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
    EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
  }
}

// Test that NetworkAnonymizationKey is respected by QUIC connections, when
// kPartitionConnectionsByNetworkIsolationKey is enabled.
TEST_P(QuicNetworkTransactionTest, NetworkIsolation) {
  const SchemefulSite kSite1(GURL("http://origin1/"));
  const SchemefulSite kSite2(GURL("http://origin2/"));
  NetworkIsolationKey network_isolation_key1(kSite1, kSite1);
  NetworkIsolationKey network_isolation_key2(kSite2, kSite2);
  const auto network_anonymization_key1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto network_anonymization_key2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  context_.params()->origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  GURL url1 = GURL("https://mail.example.org/1");
  GURL url2 = GURL("https://mail.example.org/2");
  GURL url3 = GURL("https://mail.example.org/3");

  for (bool partition_connections : {false, true}) {
    SCOPED_TRACE(partition_connections);

    base::test::ScopedFeatureList feature_list;
    if (partition_connections) {
      feature_list.InitAndEnableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    } else {
      feature_list.InitAndDisableFeature(
          features::kPartitionConnectionsByNetworkIsolationKey);
    }

    // Reads and writes for the unpartitioned case, where only one socket is
    // used.

    context_.params()->origins_to_force_quic_on.insert(
        HostPortPair::FromString("mail.example.org:443"));

    MockQuicData unpartitioned_mock_quic_data(version_);
    QuicTestPacketMaker client_maker1(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        /*client_priority_uses_incremental=*/true,
        /*use_priority_header=*/true);
    QuicTestPacketMaker server_maker1(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_SERVER,
        /*client_priority_uses_incremental=*/false,
        /*use_priority_header=*/false);

    int packet_num = 1;
    unpartitioned_mock_quic_data.AddWrite(
        SYNCHRONOUS, client_maker1.MakeInitialSettingsPacket(packet_num++));

    unpartitioned_mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker1.MakeRequestHeadersPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
            ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY),
            GetRequestHeaders("GET", url1.scheme(), "/1"), nullptr));
    unpartitioned_mock_quic_data.AddRead(
        ASYNC, server_maker1.MakeResponseHeadersPacket(
                   1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                   GetResponseHeaders("200"), nullptr));
    const char kRespData1[] = "1";
    unpartitioned_mock_quic_data.AddRead(
        ASYNC,
        server_maker1.Packet(2)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0), true,
                            ConstructDataFrame(kRespData1))
            .Build());
    unpartitioned_mock_quic_data.AddWrite(
        SYNCHRONOUS, ConstructClientAckPacket(packet_num++, 2, 1));

    unpartitioned_mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker1.MakeRequestHeadersPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(1), true,
            ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY),
            GetRequestHeaders("GET", url2.scheme(), "/2"), nullptr));
    unpartitioned_mock_quic_data.AddRead(
        ASYNC, server_maker1.MakeResponseHeadersPacket(
                   3, GetNthClientInitiatedBidirectionalStreamId(1), false,
                   GetResponseHeaders("200"), nullptr));
    const char kRespData2[] = "2";
    unpartitioned_mock_quic_data.AddRead(
        ASYNC,
        server_maker1.Packet(4)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(1), true,
                            ConstructDataFrame(kRespData2))
            .Build());
    unpartitioned_mock_quic_data.AddWrite(
        SYNCHRONOUS, ConstructClientAckPacket(packet_num++, 4, 3));

    unpartitioned_mock_quic_data.AddWrite(
        SYNCHRONOUS,
        client_maker1.MakeRequestHeadersPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(2), true,
            ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY),
            GetRequestHeaders("GET", url3.scheme(), "/3"), nullptr));
    unpartitioned_mock_quic_data.AddRead(
        ASYNC, server_maker1.MakeResponseHeadersPacket(
                   5, GetNthClientInitiatedBidirectionalStreamId(2), false,
                   GetResponseHeaders("200"), nullptr));
    const char kRespData3[] = "3";
    unpartitioned_mock_quic_data.AddRead(
        ASYNC,
        server_maker1.Packet(6)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(2), true,
                            ConstructDataFrame(kRespData3))
            .Build());
    unpartitioned_mock_quic_data.AddWrite(
        SYNCHRONOUS, ConstructClientAckPacket(packet_num++, 6, 5));

    unpartitioned_mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);

    // Reads and writes for the partitioned case, where two sockets are used.

    MockQuicData partitioned_mock_quic_data1(version_);
    QuicTestPacketMaker client_maker2(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        /*client_priority_uses_incremental=*/true,
        /*use_priority_header=*/true);
    QuicTestPacketMaker server_maker2(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_SERVER,
        /*client_priority_uses_incremental=*/false,
        /*use_priority_header=*/false);

    int packet_num2 = 1;
    partitioned_mock_quic_data1.AddWrite(
        SYNCHRONOUS, client_maker2.MakeInitialSettingsPacket(packet_num2++));

    partitioned_mock_quic_data1.AddWrite(
        SYNCHRONOUS,
        client_maker2.MakeRequestHeadersPacket(
            packet_num2++, GetNthClientInitiatedBidirectionalStreamId(0), true,
            ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY),
            GetRequestHeaders("GET", url1.scheme(), "/1"), nullptr));
    partitioned_mock_quic_data1.AddRead(
        ASYNC, server_maker2.MakeResponseHeadersPacket(
                   1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                   GetResponseHeaders("200"), nullptr));
    partitioned_mock_quic_data1.AddRead(
        ASYNC,
        server_maker2.Packet(2)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0), true,
                            ConstructDataFrame(kRespData1))
            .Build());
    partitioned_mock_quic_data1.AddWrite(
        SYNCHRONOUS,
        client_maker2.Packet(packet_num2++).AddAckFrame(1, 2, 1).Build());

    partitioned_mock_quic_data1.AddWrite(
        SYNCHRONOUS,
        client_maker2.MakeRequestHeadersPacket(
            packet_num2++, GetNthClientInitiatedBidirectionalStreamId(1), true,
            ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY),
            GetRequestHeaders("GET", url3.scheme(), "/3"), nullptr));
    partitioned_mock_quic_data1.AddRead(
        ASYNC, server_maker2.MakeResponseHeadersPacket(
                   3, GetNthClientInitiatedBidirectionalStreamId(1), false,
                   GetResponseHeaders("200"), nullptr));
    partitioned_mock_quic_data1.AddRead(
        ASYNC,
        server_maker2.Packet(4)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(1), true,
                            ConstructDataFrame(kRespData3))
            .Build());
    partitioned_mock_quic_data1.AddWrite(
        SYNCHRONOUS,
        client_maker2.Packet(packet_num2++).AddAckFrame(1, 4, 3).Build());

    partitioned_mock_quic_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);

    MockQuicData partitioned_mock_quic_data2(version_);
    QuicTestPacketMaker client_maker3(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        /*client_priority_uses_incremental=*/true,
        /*use_priority_header=*/true);
    QuicTestPacketMaker server_maker3(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_SERVER,
        /*client_priority_uses_incremental=*/false,
        /*use_priority_header=*/false);

    int packet_num3 = 1;
    partitioned_mock_quic_data2.AddWrite(
        SYNCHRONOUS, client_maker3.MakeInitialSettingsPacket(packet_num3++));

    partitioned_mock_quic_data2.AddWrite(
        SYNCHRONOUS,
        client_maker3.MakeRequestHeadersPacket(
            packet_num3++, GetNthClientInitiatedBidirectionalStreamId(0), true,
            ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY),
            GetRequestHeaders("GET", url2.scheme(), "/2"), nullptr));
    partitioned_mock_quic_data2.AddRead(
        ASYNC, server_maker3.MakeResponseHeadersPacket(
                   1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                   GetResponseHeaders("200"), nullptr));
    partitioned_mock_quic_data2.AddRead(
        ASYNC,
        server_maker3.Packet(2)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0), true,
                            ConstructDataFrame(kRespData2))
            .Build());
    partitioned_mock_quic_data2.AddWrite(
        SYNCHRONOUS,
        client_maker3.Packet(packet_num3++).AddAckFrame(1, 2, 1).Build());

    partitioned_mock_quic_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);

    if (partition_connections) {
      partitioned_mock_quic_data1.AddSocketDataToFactory(&socket_factory_);
      partitioned_mock_quic_data2.AddSocketDataToFactory(&socket_factory_);
    } else {
      unpartitioned_mock_quic_data.AddSocketDataToFactory(&socket_factory_);
    }

    CreateSession();

    TestCompletionCallback callback;
    HttpRequestInfo request1;
    request1.method = "GET";
    request1.url = GURL(url1);
    request1.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    request1.network_isolation_key = network_isolation_key1;
    request1.network_anonymization_key = network_anonymization_key1;
    HttpNetworkTransaction trans1(LOWEST, session_.get());
    int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    std::string response_data1;
    EXPECT_THAT(ReadTransaction(&trans1, &response_data1), IsOk());
    EXPECT_EQ(kRespData1, response_data1);

    HttpRequestInfo request2;
    request2.method = "GET";
    request2.url = GURL(url2);
    request2.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    request2.network_isolation_key = network_isolation_key2;
    request2.network_anonymization_key = network_anonymization_key2;
    HttpNetworkTransaction trans2(LOWEST, session_.get());
    rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    std::string response_data2;
    EXPECT_THAT(ReadTransaction(&trans2, &response_data2), IsOk());
    EXPECT_EQ(kRespData2, response_data2);

    HttpRequestInfo request3;
    request3.method = "GET";
    request3.url = GURL(url3);
    request3.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    request3.network_isolation_key = network_isolation_key1;
    request3.network_anonymization_key = network_anonymization_key1;

    HttpNetworkTransaction trans3(LOWEST, session_.get());
    rv = trans3.Start(&request3, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    std::string response_data3;
    EXPECT_THAT(ReadTransaction(&trans3, &response_data3), IsOk());
    EXPECT_EQ(kRespData3, response_data3);

    if (partition_connections) {
      EXPECT_TRUE(partitioned_mock_quic_data1.AllReadDataConsumed());
      EXPECT_TRUE(partitioned_mock_quic_data1.AllWriteDataConsumed());
      EXPECT_TRUE(partitioned_mock_quic_data2.AllReadDataConsumed());
      EXPECT_TRUE(partitioned_mock_quic_data2.AllWriteDataConsumed());
    } else {
      EXPECT_TRUE(unpartitioned_mock_quic_data.AllReadDataConsumed());
      EXPECT_TRUE(unpartitioned_mock_quic_data.AllWriteDataConsumed());
    }
  }
}

// Test that two requests to the same origin over QUIC tunnels use different
// QUIC sessions if their NetworkIsolationKeys don't match, and
// kPartitionConnectionsByNetworkIsolationKey is enabled.
TEST_P(QuicNetworkTransactionTest, NetworkIsolationTunnel) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_params_.enable_quic = true;
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
              ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)})},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  const char kGetRequest[] =
      "GET / HTTP/1.1\r\n"
      "Host: mail.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  const char kGetResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  const char kRespData[] = "0123456789";

  std::unique_ptr<MockQuicData> mock_quic_data[2] = {
      std::make_unique<MockQuicData>(version_),
      std::make_unique<MockQuicData>(version_)};

  for (int index : {0, 1}) {
    QuicTestPacketMaker client_maker(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        true);
    QuicTestPacketMaker server_maker(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_SERVER,
        false);

    int packet_num = 1;
    mock_quic_data[index]->AddWrite(
        SYNCHRONOUS, client_maker.MakeInitialSettingsPacket(packet_num++));

    mock_quic_data[index]->AddWrite(
        SYNCHRONOUS,
        client_maker.MakePriorityPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
            quic::HttpStreamPriority::kDefaultUrgency));

    mock_quic_data[index]->AddWrite(
        SYNCHRONOUS,
        client_maker.MakeRequestHeadersPacket(
            packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), false,
            quic::HttpStreamPriority::kDefaultUrgency,
            ConnectRequestHeaders("mail.example.org:80"), nullptr, false));
    mock_quic_data[index]->AddRead(
        ASYNC, server_maker.MakeResponseHeadersPacket(
                   1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                   GetResponseHeaders("200"), nullptr));

    mock_quic_data[index]->AddWrite(
        SYNCHRONOUS,
        client_maker.Packet(packet_num++)
            .AddAckFrame(/*first_received=*/1, /*largest_received=*/1,
                         /*smallest_received=*/1)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                            false, ConstructDataFrame(kGetRequest))
            .Build());

    mock_quic_data[index]->AddRead(
        ASYNC,
        server_maker.Packet(2)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                            false, ConstructDataFrame(kGetResponse))
            .Build());
    mock_quic_data[index]->AddRead(
        SYNCHRONOUS,
        server_maker.Packet(3)
            .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                            false, ConstructDataFrame(kRespData))
            .Build());
    mock_quic_data[index]->AddWrite(
        SYNCHRONOUS,
        client_maker.Packet(packet_num++).AddAckFrame(1, 3, 2).Build());
    mock_quic_data[index]->AddRead(SYNCHRONOUS,
                                   ERR_IO_PENDING);  // No more data to read

    mock_quic_data[index]->AddSocketDataToFactory(&socket_factory_);
  }

  socket_factory_.AddSSLSocketD
```