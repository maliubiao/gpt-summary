Response:
The user wants to understand the functionality of the provided C++ code snippet from `http_stream_factory_unittest.cc`. They also want to know its relation to JavaScript, potential logical reasoning, common usage errors, and debugging steps. Finally, they are asking for a summary of this specific part of the code, as it's part 2 of 6.

Here's a breakdown of how to approach this:

1. **Identify the main purpose:** The code consists of several test cases (using `TEST_P`) for `HttpStreamFactory`. This means it's testing the functionality of the `HttpStreamFactory` class, which is responsible for creating HTTP streams.

2. **Analyze each test case individually:**  Understand what specific aspect of `HttpStreamFactory` each test is verifying. Look for keywords like "preconnect", "NetworkIsolationKey", "SecureDns", "proxy", "QUIC", "privacy mode", etc.

3. **Look for interactions with other components:** Notice the use of `HttpNetworkSession`, `ProxyResolutionService`, `ClientSocketPool`, `SpdySessionPool`, `QuicSessionPool`, etc. This gives context to the functionality being tested.

4. **Address the JavaScript relationship:**  Consider how the network stack interacts with the browser's rendering engine, which executes JavaScript. Preconnecting, managing proxies, and handling secure DNS directly impact how web pages load, which is initiated and controlled by JavaScript.

5. **Identify logical reasoning:**  Look for conditional logic (like the `if/else` based on feature flags) and how the tests set up specific scenarios and then assert expectations (using `EXPECT_EQ`, `ASSERT_THAT`, etc.).

6. **Think about user/programming errors:**  Consider common mistakes developers might make when configuring network settings or using the networking APIs.

7. **Outline debugging steps:** Trace how a user action in the browser (like navigating to a website) would eventually involve the `HttpStreamFactory`.

8. **Summarize the current code section:** Condense the functionalities observed in the analyzed test cases into a concise overview.

**Pre-computation/Pre-analysis:**

* **Preconnect Tests:**  These tests focus on verifying that pre-connections respect Network Isolation Keys and Secure DNS policies. The `HappyEyeballsV3` feature flag influences how these pre-connections are managed.
* **Proxy Tests:** These tests check how the factory handles proxy configurations, including marking bad proxies and the behavior during tunnel failures. The QUIC proxy test verifies bad QUIC proxies are also tracked.
* **Privacy Mode Test:** This confirms that privacy mode isolates socket connections into separate groups.
* **Secure DNS Test:** Similar to privacy mode, this verifies that different Secure DNS policies lead to separate socket pool groups.
* **Load State Test:** This simple test checks the load state during stream creation.
* **Basic HTTP Stream Request Test:** Verifies the creation of a basic HTTP stream.
* **Reprioritization Test:** Examines how prioritization works even after a stream is established.

By following these steps and considering the pre-analysis, we can construct a comprehensive answer to the user's request.
```cpp
                          true);
```

## 功能列举：

这段代码是 `net/http/http_stream_factory_unittest.cc` 文件的一部分，主要包含以下功能相关的测试用例：

1. **预连接 (Preconnect) 功能测试:**
   - 验证预连接是否使用了指定的 `NetworkAnonymizationKey`，以确保网络隔离。
   - 验证预连接是否使用了指定的安全 DNS (Secure DNS) 策略，例如禁用安全 DNS。
   - 测试在禁用 0-RTT 的情况下是否会使用预连接（针对 QUIC）。

2. **代理 (Proxy) 功能测试:**
   - 验证当连接代理失败时，代理会被添加到坏代理列表。
   - 测试当使用 HTTP 代理连接 HTTPS URL 且隧道连接失败时，是否不会回退到 DIRECT 连接。
   - 针对 QUIC 代理，测试当连接失败时，QUIC 代理是否会被标记为坏代理。

3. **隐私模式 (Privacy Mode) 功能测试:**
   - 验证在启用隐私模式时，会使用不同的 Socket Pool Group，以实现连接隔离。

4. **安全 DNS 功能测试:**
   - 验证当使用不同的安全 DNS 策略时，会使用不同的 Socket Pool Group。

5. **请求状态 (Load State) 查询测试:**
   - 测试在请求 HTTP 流的过程中，可以获取正确的加载状态。

6. **基本 HTTP 流请求测试:**
   - 验证可以成功请求一个基本的 HTTP 流。

7. **请求优先级 (Priority) 功能测试:**
   - 测试在流创建之后，仍然可以成功地重新设置请求的优先级。

## 与 JavaScript 功能的关系及举例说明：

这些测试用例直接或间接地关系到 JavaScript 发起的网络请求的性能和安全性。以下是一些例子：

* **预连接 (Preconnect):** 当 JavaScript 代码使用 `<link rel="preconnect" href="https://example.com">` 或 `fetch` API 手动发起预连接时，`HttpStreamFactory` 的预连接功能会被调用。这些测试确保了预连接的隔离性和安全性，避免了跨站点的资源加载问题。
   ```javascript
   // JavaScript 代码发起预连接
   const link = document.createElement('link');
   link.rel = 'preconnect';
   link.href = 'https://example.com';
   document.head.appendChild(link);

   // 或者使用 fetch API
   fetch('https://example.com', { mode: 'no-cors' });
   ```

* **代理 (Proxy):**  浏览器中的代理设置会影响 `HttpStreamFactory` 如何建立连接。这些测试保证了代理的正确处理，包括失败时的回退和对 QUIC 代理的支持。JavaScript 代码通常不需要直接操作代理设置，这些设置由浏览器或操作系统管理。

* **隐私模式 (Privacy Mode):** 当用户在浏览器中启用隐私模式（例如 Chrome 的隐身模式）时，这些测试确保了网络请求的隔离性，防止了跟踪和数据泄露。 JavaScript 代码无法直接感知或修改隐私模式，但其发起的请求会受到隐私模式的影响。

* **安全 DNS (Secure DNS):** 浏览器中配置的安全 DNS 设置会影响 `HttpStreamFactory` 的 DNS 查询行为。这些测试保证了安全 DNS 策略的正确应用，提升了 DNS 查询的安全性。JavaScript 代码无法直接控制安全 DNS，但其发起的请求会受到安全 DNS 的影响。

* **请求优先级 (Priority):** `fetch` API 允许设置请求的优先级 (`importance` 属性)。`HttpStreamFactory` 需要正确处理这些优先级设置，以优化资源加载顺序。
   ```javascript
   // JavaScript 使用 fetch 设置请求优先级
   fetch('https://example.com/image.png', { importance: 'high' });
   ```

## 逻辑推理及假设输入与输出：

**测试用例：`PreconnectNetworkIsolationKey`**

* **假设输入:**
    - 启用了 `kPartitionConnectionsByNetworkIsolationKey` 功能。
    - 两个不同的 `NetworkAnonymizationKey`，分别对应 `http://foo.test` 和 `http://bar.test`。
    - 对同一个 URL (`http://foo.test/`) 进行两次预连接，分别使用不同的 `NetworkAnonymizationKey`。

* **逻辑推理:**  由于启用了网络隔离，使用不同的 `NetworkAnonymizationKey` 进行预连接应该会创建不同的连接池组。

* **预期输出:**
    - 如果启用了 `features::kHappyEyeballsV3`，`CapturePreconnectHttpStreamPoolDelegate` 会记录两次预连接使用了不同的 `NetworkAnonymizationKey`。
    - 否则，`CapturePreconnectsTransportSocketPool` 会记录两次预连接使用了不同的 `NetworkAnonymizationKey`。

**测试用例：`JobNotifiesProxy`**

* **假设输入:**
    - 配置了一个包含多个代理的代理列表，其中第一个代理 `bad:99` 连接失败，第二个代理 `maybe:80` 连接成功。
    - 发起一个对 `http://www.google.com` 的 HTTP 请求。

* **逻辑推理:**  `HttpStreamFactory` 应该首先尝试连接 `bad:99`，连接失败后会尝试连接 `maybe:80`。连接失败的代理会被标记为坏代理。

* **预期输出:**
    - 请求最终通过第二个代理 `maybe:80` 成功。
    - `proxy_resolution_service()->proxy_retry_info()` 中会包含 `bad:99` 的重试信息，表明它已被标记为坏代理。

## 用户或编程常见的使用错误及举例说明：

* **错误配置代理导致连接失败:** 用户可能在操作系统或浏览器中配置了错误的代理地址或端口，导致 `HttpStreamFactory` 无法建立连接。
   ```
   // 假设用户配置了一个不存在的代理
   const char* kProxyString = "PROXY nonexistent:99;";
   ```
   在这种情况下，相关的测试用例（例如测试代理连接失败的用例）会模拟这种情况并验证 `HttpStreamFactory` 的处理逻辑。

* **误解预连接的作用域:** 开发者可能认为预连接可以跨越不同的 `NetworkAnonymizationKey` 或安全 DNS 策略复用连接。这些测试用例明确了预连接的隔离性，防止了这种误解。

* **不理解隐私模式对连接的影响:** 开发者可能在隐私模式下期望复用非隐私模式下的连接，这些测试用例验证了隐私模式下会使用独立的连接池组。

## 用户操作如何一步步的到达这里 (作为调试线索)：

1. **用户在浏览器地址栏输入 URL 并按下回车键，或者点击一个链接。**
2. **浏览器进程的 UI 线程接收到导航请求。**
3. **UI 线程通知网络进程发起网络请求。**
4. **网络进程的 URLRequestContext (或其子组件) 开始处理请求。**
5. **如果需要建立新的连接，`HttpStreamFactory` 会被调用来创建一个 HTTP 流。**
6. **根据请求的 URL、代理设置、安全 DNS 设置、隐私模式等信息，`HttpStreamFactory` 会选择合适的 Socket Pool 和连接参数。**
7. **如果需要预连接，`HttpStreamFactory` 会在后台尝试建立连接。**
8. **如果在连接过程中发生错误（例如代理连接失败），相关的错误处理逻辑会被触发，这可能会涉及到测试用例中模拟的场景。**
9. **调试时，开发者可以使用 Chrome 的 `net-internals` 工具 (chrome://net-internals/#http_stream_factory) 来查看 `HttpStreamFactory` 的状态、连接池信息、以及预连接尝试等。**
10. **如果启用了相关的 feature flag (`kHappyEyeballsV3`, `kPartitionConnectionsByNetworkIsolationKey`)，代码会执行相应的分支，这些分支的行为由对应的测试用例覆盖。**

## 功能归纳：

这段 `net/http/http_stream_factory_unittest.cc` 的代码片段主要测试了 `HttpStreamFactory` 在以下几个关键网络功能方面的正确性：

* **预连接的隔离性和策略执行:** 确保预连接尊重网络隔离键和安全 DNS 策略。
* **代理处理的鲁棒性:** 验证代理连接失败时的处理，包括标记坏代理和避免不必要的回退。
* **网络隔离机制的正确性:** 确保隐私模式和不同的安全 DNS 策略能够有效地隔离网络连接。
* **基本的 HTTP 流创建和请求优先级设置:** 验证 `HttpStreamFactory` 可以成功创建 HTTP 流并处理请求优先级。

总而言之，这部分测试用例旨在确保 `HttpStreamFactory` 能够安全、高效地管理 HTTP 连接，并正确地处理各种网络配置和用户设置。

Prompt: 
```
这是目录为net/http/http_stream_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
          SecureDnsPolicy::kAllow, session.get());
  };

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    auto delegate = std::make_unique<CapturePreconnectHttpStreamPoolDelegate>();
    CapturePreconnectHttpStreamPoolDelegate* delegate_ptr = delegate.get();
    session->http_stream_pool()->SetDelegateForTesting(std::move(delegate));
    DoPreconnect();
    EXPECT_EQ(-1, delegate_ptr->last_num_streams());
  } else {
    HttpNetworkSessionPeer peer(session.get());
    CommonConnectJobParams common_connect_job_params =
        session->CreateCommonConnectJobParams();
    std::unique_ptr<CapturePreconnectsTransportSocketPool>
        owned_transport_conn_pool =
            std::make_unique<CapturePreconnectsTransportSocketPool>(
                &common_connect_job_params);
    CapturePreconnectsTransportSocketPool* transport_conn_pool =
        owned_transport_conn_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                     std::move(owned_transport_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    DoPreconnect();
    EXPECT_EQ(-1, transport_conn_pool->last_num_streams());
  }
}

// Verify that preconnects use the specified NetworkAnonymizationKey.
TEST_P(HttpStreamFactoryTest, PreconnectNetworkIsolationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  const GURL kURL("http://foo.test/");
  const SchemefulSite kSiteFoo(GURL("http://foo.test"));
  const SchemefulSite kSiteBar(GURL("http://bar.test"));
  const auto kKey1 = NetworkAnonymizationKey::CreateSameSite(kSiteFoo);
  const auto kKey2 = NetworkAnonymizationKey::CreateSameSite(kSiteBar);
  auto DoPreconnect1 = [&] {
    PreconnectHelperForURL(1, kURL, kKey1, SecureDnsPolicy::kAllow,
                           session.get());
  };
  auto DoPreconnect2 = [&] {
    PreconnectHelperForURL(2, kURL, kKey2, SecureDnsPolicy::kAllow,
                           session.get());
  };

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    auto delegate = std::make_unique<CapturePreconnectHttpStreamPoolDelegate>();
    CapturePreconnectHttpStreamPoolDelegate* delegate_ptr = delegate.get();
    session->http_stream_pool()->SetDelegateForTesting(std::move(delegate));

    DoPreconnect1();
    EXPECT_EQ(1, delegate_ptr->last_num_streams());
    EXPECT_EQ(kKey1,
              delegate_ptr->last_stream_key().network_anonymization_key());

    DoPreconnect2();
    EXPECT_EQ(2, delegate_ptr->last_num_streams());
    EXPECT_EQ(kKey2,
              delegate_ptr->last_stream_key().network_anonymization_key());
  } else {
    HttpNetworkSessionPeer peer(session.get());
    CommonConnectJobParams common_connect_job_params =
        session->CreateCommonConnectJobParams();
    std::unique_ptr<CapturePreconnectsTransportSocketPool>
        owned_transport_conn_pool =
            std::make_unique<CapturePreconnectsTransportSocketPool>(
                &common_connect_job_params);
    CapturePreconnectsTransportSocketPool* transport_conn_pool =
        owned_transport_conn_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                     std::move(owned_transport_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    DoPreconnect1();
    EXPECT_EQ(1, transport_conn_pool->last_num_streams());
    EXPECT_EQ(kKey1,
              transport_conn_pool->last_group_id().network_anonymization_key());

    DoPreconnect2();
    EXPECT_EQ(2, transport_conn_pool->last_num_streams());
    EXPECT_EQ(kKey2,
              transport_conn_pool->last_group_id().network_anonymization_key());
  }
}

// Verify that preconnects use the specified Secure DNS Tag.
TEST_P(HttpStreamFactoryTest, PreconnectDisableSecureDns) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  const GURL kURL("http://foo.test/");
  const SchemefulSite kSiteFoo(GURL("http://foo.test"));
  const SchemefulSite kSiteBar(GURL("http://bar.test"));
  auto DoPreconnect1 = [&] {
    PreconnectHelperForURL(1, kURL, NetworkAnonymizationKey(),
                           SecureDnsPolicy::kAllow, session.get());
  };
  auto DoPreconnect2 = [&] {
    PreconnectHelperForURL(2, kURL, NetworkAnonymizationKey(),
                           SecureDnsPolicy::kDisable, session.get());
  };

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    auto delegate = std::make_unique<CapturePreconnectHttpStreamPoolDelegate>();
    CapturePreconnectHttpStreamPoolDelegate* delegate_ptr = delegate.get();
    session->http_stream_pool()->SetDelegateForTesting(std::move(delegate));

    DoPreconnect1();
    EXPECT_EQ(1, delegate_ptr->last_num_streams());
    EXPECT_EQ(SecureDnsPolicy::kAllow,
              delegate_ptr->last_stream_key().secure_dns_policy());

    DoPreconnect2();
    EXPECT_EQ(2, delegate_ptr->last_num_streams());
    EXPECT_EQ(SecureDnsPolicy::kDisable,
              delegate_ptr->last_stream_key().secure_dns_policy());
  } else {
    HttpNetworkSessionPeer peer(session.get());
    CommonConnectJobParams common_connect_job_params =
        session->CreateCommonConnectJobParams();
    std::unique_ptr<CapturePreconnectsTransportSocketPool>
        owned_transport_conn_pool =
            std::make_unique<CapturePreconnectsTransportSocketPool>(
                &common_connect_job_params);
    CapturePreconnectsTransportSocketPool* transport_conn_pool =
        owned_transport_conn_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                     std::move(owned_transport_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    DoPreconnect1();
    EXPECT_EQ(1, transport_conn_pool->last_num_streams());
    EXPECT_EQ(SecureDnsPolicy::kAllow,
              transport_conn_pool->last_group_id().secure_dns_policy());

    DoPreconnect2();
    EXPECT_EQ(2, transport_conn_pool->last_num_streams());
    EXPECT_EQ(SecureDnsPolicy::kDisable,
              transport_conn_pool->last_group_id().secure_dns_policy());
  }
}

TEST_P(HttpStreamFactoryTest, JobNotifiesProxy) {
  const char* kProxyString = "PROXY bad:99; PROXY maybe:80; DIRECT";
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          kProxyString, TRAFFIC_ANNOTATION_FOR_TESTS));

  // First connection attempt fails
  StaticSocketDataProvider socket_data1;
  socket_data1.set_connect_data(MockConnect(ASYNC, ERR_ADDRESS_UNREACHABLE));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data1);

  // Second connection attempt succeeds
  StaticSocketDataProvider socket_data2;
  socket_data2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data2);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream. It should succeed using the second proxy in the
  // list.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);

  // The proxy that failed should now be known to the proxy_resolution_service
  // as bad.
  const ProxyRetryInfoMap& retry_info =
      session->proxy_resolution_service()->proxy_retry_info();
  EXPECT_EQ(1u, retry_info.size());
  auto iter = retry_info.find(
      ProxyChain(ProxyUriToProxyServer("bad:99", ProxyServer::SCHEME_HTTP)));
  EXPECT_TRUE(iter != retry_info.end());
}

// This test requests a stream for an https:// URL using an HTTP proxy.
// The proxy will fail to establish a tunnel via connect, and the resolved
// proxy list includes a fallback to DIRECT.
//
// The expected behavior is that proxy fallback does NOT occur, even though the
// request might work using the fallback. This is a regression test for
// https://crbug.com/680837.
TEST_P(HttpStreamFactoryTest, NoProxyFallbackOnTunnelFail) {
  const char* kProxyString = "PROXY bad:99; DIRECT";
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          kProxyString, TRAFFIC_ANNOTATION_FOR_TESTS));

  // A 404 in response to a CONNECT will trigger
  // ERR_TUNNEL_CONNECTION_FAILED.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 404 Not Found\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  // Simulate a failure during CONNECT to bad:99.
  StaticSocketDataProvider socket_data1(data_reads, base::span<MockWrite>());
  socket_data1.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data1);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Request a stream for an https:// URL. The exact URL doesn't matter for
  // this test, since it mocks a failure immediately when establishing a
  // tunnel through the proxy.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);

  // The stream should have failed, since the proxy server failed to
  // establish a tunnel.
  ASSERT_THAT(requester.error_status(), IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // The proxy should NOT have been marked as bad.
  const ProxyRetryInfoMap& retry_info =
      session->proxy_resolution_service()->proxy_retry_info();
  EXPECT_EQ(0u, retry_info.size());
}

// List of errors that are used in the tests related to QUIC proxy.
const int quic_proxy_test_mock_errors[] = {
    ERR_PROXY_CONNECTION_FAILED,
    ERR_NAME_NOT_RESOLVED,
    ERR_ADDRESS_UNREACHABLE,
    ERR_CONNECTION_CLOSED,
    ERR_CONNECTION_TIMED_OUT,
    ERR_CONNECTION_RESET,
    ERR_CONNECTION_REFUSED,
    ERR_CONNECTION_ABORTED,
    ERR_TIMED_OUT,
    ERR_SOCKS_CONNECTION_FAILED,
    ERR_PROXY_CERTIFICATE_INVALID,
    ERR_QUIC_PROTOCOL_ERROR,
    ERR_QUIC_HANDSHAKE_FAILED,
    ERR_SSL_PROTOCOL_ERROR,
    ERR_MSG_TOO_BIG,
};

// Tests that a bad QUIC proxy is added to the list of bad proxies.
TEST_P(HttpStreamFactoryTest, QuicProxyMarkedAsBad) {
  for (int quic_proxy_test_mock_error : quic_proxy_test_mock_errors) {
    auto quic_proxy_chain =
        ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
            ProxyServer::SCHEME_QUIC, "bad", 99)});
    std::unique_ptr<ProxyResolutionService> proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
            {quic_proxy_chain, ProxyChain::Direct()},
            TRAFFIC_ANNOTATION_FOR_TESTS);

    HttpNetworkSessionParams session_params;
    session_params.enable_quic = true;

    HttpNetworkSessionContext session_context;
    SSLConfigServiceDefaults ssl_config_service;
    HttpServerProperties http_server_properties;
    MockClientSocketFactory socket_factory;
    session_context.client_socket_factory = &socket_factory;
    MockHostResolver host_resolver;
    session_context.host_resolver = &host_resolver;
    MockCertVerifier cert_verifier;
    session_context.cert_verifier = &cert_verifier;
    TransportSecurityState transport_security_state;
    session_context.transport_security_state = &transport_security_state;
    QuicContext quic_context;
    StaticHttpUserAgentSettings http_user_agent_settings("*", "test-ua");
    session_context.http_user_agent_settings = &http_user_agent_settings;
    session_context.proxy_resolution_service = proxy_resolution_service.get();
    session_context.ssl_config_service = &ssl_config_service;
    session_context.http_server_properties = &http_server_properties;
    session_context.quic_context = &quic_context;

    host_resolver.rules()->AddRule("www.google.com", "2.3.4.5");
    host_resolver.rules()->AddRule("bad", "1.2.3.4");

    auto session =
        std::make_unique<HttpNetworkSession>(session_params, session_context);
    session->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
        true);

    StaticSocketDataProvider socket_data1;
    socket_data1.set_connect_data(
        MockConnect(ASYNC, quic_proxy_test_mock_error));
    socket_factory.AddSocketDataProvider(&socket_data1);

    // Second connection attempt succeeds.
    StaticSocketDataProvider socket_data2;
    socket_data2.set_connect_data(MockConnect(ASYNC, OK));
    socket_factory.AddSocketDataProvider(&socket_data2);

    // Now request a stream. It should succeed using the second proxy in the
    // list.
    HttpRequestInfo request_info;
    request_info.method = "GET";
    request_info.url = GURL("http://www.google.com");
    request_info.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    StreamRequester requester(session.get());
    requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                   DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                   /*enable_ip_based_pooling=*/true,
                                   /*enable_alternative_services=*/true);

    // The proxy that failed should now be known to the
    // proxy_resolution_service as bad.
    const ProxyRetryInfoMap& retry_info =
        session->proxy_resolution_service()->proxy_retry_info();
    EXPECT_EQ(1u, retry_info.size()) << quic_proxy_test_mock_error;
    EXPECT_TRUE(requester.used_proxy_info().is_direct());

    auto iter = retry_info.find(quic_proxy_chain);
    EXPECT_TRUE(iter != retry_info.end()) << quic_proxy_test_mock_error;
  }
}

// BidirectionalStreamImpl::Delegate to wait until response headers are
// received.
class TestBidirectionalDelegate : public BidirectionalStreamImpl::Delegate {
 public:
  void WaitUntilDone() { loop_.Run(); }

  const quiche::HttpHeaderBlock& response_headers() const {
    return response_headers_;
  }

 private:
  void OnStreamReady(bool request_headers_sent) override {}
  void OnHeadersReceived(
      const quiche::HttpHeaderBlock& response_headers) override {
    response_headers_ = response_headers.Clone();
    loop_.Quit();
  }
  void OnDataRead(int bytes_read) override { NOTREACHED(); }
  void OnDataSent() override { NOTREACHED(); }
  void OnTrailersReceived(const quiche::HttpHeaderBlock& trailers) override {
    NOTREACHED();
  }
  void OnFailed(int error) override { NOTREACHED(); }
  base::RunLoop loop_;
  quiche::HttpHeaderBlock response_headers_;
};

struct QuicTestParams {
  QuicTestParams(quic::ParsedQuicVersion quic_version,
                 bool happy_eyeballs_v3_enabled)
      : quic_version(quic_version),
        happy_eyeballs_v3_enabled(happy_eyeballs_v3_enabled) {}

  quic::ParsedQuicVersion quic_version;
  bool happy_eyeballs_v3_enabled;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const QuicTestParams& p) {
  return base::StrCat(
      {ParsedQuicVersionToString(p.quic_version), "_",
       p.happy_eyeballs_v3_enabled ? "HEv3Enabled" : "HEv3Disabled"});
}

std::vector<QuicTestParams> GetTestParams() {
  std::vector<QuicTestParams> params;
  for (const auto& quic_version : AllSupportedQuicVersions()) {
    params.emplace_back(quic_version, /*happy_eyeballs_v3_enabled=*/true);
    params.emplace_back(quic_version, /*happy_eyeballs_v3_enabled=*/false);
  }
  return params;
}

}  // namespace

TEST_P(HttpStreamFactoryTest, UsePreConnectIfNoZeroRTT) {
  for (int num_streams = 1; num_streams < 3; ++num_streams) {
    GURL url = GURL("https://www.google.com");

    SpdySessionDependencies session_deps(
        ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
            {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
                ProxyServer::SCHEME_QUIC, "quic_proxy", 443)})},
            TRAFFIC_ANNOTATION_FOR_TESTS));

    // Setup params to disable preconnect, but QUIC doesn't 0RTT.
    HttpNetworkSessionParams session_params =
        SpdySessionDependencies::CreateSessionParams(&session_deps);
    session_params.enable_quic = true;

    // Set up QUIC as alternative_service.
    HttpServerProperties http_server_properties;
    const AlternativeService alternative_service(kProtoQUIC, url.host().c_str(),
                                                 url.IntPort());
    base::Time expiration = base::Time::Now() + base::Days(1);
    HostPortPair host_port_pair(alternative_service.host_port_pair());
    url::SchemeHostPort server("https", host_port_pair.host(),
                               host_port_pair.port());
    http_server_properties.SetQuicAlternativeService(
        server, NetworkAnonymizationKey(), alternative_service, expiration,
        DefaultSupportedQuicVersions());

    HttpNetworkSessionContext session_context =
        SpdySessionDependencies::CreateSessionContext(&session_deps);
    session_context.http_server_properties = &http_server_properties;

    auto session =
        std::make_unique<HttpNetworkSession>(session_params, session_context);
    HttpNetworkSessionPeer peer(session.get());
    ProxyChain proxy_chain =
        ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
            ProxyServer::SCHEME_QUIC, "quic_proxy", 443)});
    CommonConnectJobParams common_connect_job_params =
        session->CreateCommonConnectJobParams();
    auto http_proxy_pool =
        std::make_unique<CapturePreconnectsTransportSocketPool>(
            &common_connect_job_params);
    auto* http_proxy_pool_ptr = http_proxy_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(proxy_chain, std::move(http_proxy_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelperForURL(num_streams, url, NetworkAnonymizationKey(),
                           SecureDnsPolicy::kAllow, session.get());
    EXPECT_EQ(num_streams, http_proxy_pool_ptr->last_num_streams());
  }
}

namespace {

// Return count of distinct groups in given socket pool.
int GetSocketPoolGroupCount(ClientSocketPool* pool) {
  int count = 0;
  base::Value dict = pool->GetInfoAsValue("", "");
  EXPECT_TRUE(dict.is_dict());
  const base::Value::Dict* groups = dict.GetDict().FindDict("groups");
  if (groups) {
    count = groups->size();
  }
  return count;
}

int GetHttpStreamPoolGroupCount(HttpNetworkSession* session) {
  base::Value::Dict dict = session->http_stream_pool()->GetInfoAsValue();
  const base::Value::Dict* groups = dict.FindDict("groups");
  if (groups) {
    return groups->size();
  }
  return 0;
}

int GetPoolGroupCount(HttpNetworkSession* session,
                      HttpNetworkSession::SocketPoolType pool_type,
                      const ProxyChain& proxy_chain) {
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3) &&
      pool_type == HttpNetworkSession::NORMAL_SOCKET_POOL &&
      proxy_chain.is_direct()) {
    return GetHttpStreamPoolGroupCount(session);
  } else {
    return GetSocketPoolGroupCount(
        session->GetSocketPool(pool_type, proxy_chain));
  }
}

// Return count of distinct spdy sessions.
int GetSpdySessionCount(HttpNetworkSession* session) {
  std::unique_ptr<base::Value> value(
      session->spdy_session_pool()->SpdySessionPoolInfoToValue());
  if (!value || !value->is_list()) {
    return -1;
  }
  return value->GetList().size();
}

// Return count of sockets handed out by a given socket pool.
int GetHandedOutSocketCount(ClientSocketPool* pool) {
  base::Value dict = pool->GetInfoAsValue("", "");
  EXPECT_TRUE(dict.is_dict());
  return dict.GetDict().FindInt("handed_out_socket_count").value_or(-1);
}

int GetHttpStreamPoolHandedOutCount(HttpNetworkSession* session) {
  base::Value::Dict dict = session->http_stream_pool()->GetInfoAsValue();
  return dict.FindInt("handed_out_socket_count").value_or(-1);
}

int GetHandedOutCount(HttpNetworkSession* session,
                      HttpNetworkSession::SocketPoolType pool_type,
                      const ProxyChain& proxy_chain) {
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3) &&
      pool_type == HttpNetworkSession::NORMAL_SOCKET_POOL &&
      proxy_chain.is_direct()) {
    return GetHttpStreamPoolHandedOutCount(session);
  } else {
    return GetHandedOutSocketCount(
        session->GetSocketPool(pool_type, proxy_chain));
  }
}

// Return count of distinct QUIC sessions.
int GetQuicSessionCount(HttpNetworkSession* session) {
  base::Value dict(session->QuicInfoToValue());
  base::Value::List* session_list = dict.GetDict().FindList("sessions");
  if (!session_list) {
    return -1;
  }
  return session_list->size();
}

TEST_P(HttpStreamFactoryTest, PrivacyModeUsesDifferentSocketPoolGroup) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  StaticSocketDataProvider socket_data_1;
  socket_data_1.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_1);
  StaticSocketDataProvider socket_data_2;
  socket_data_2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_2);
  StaticSocketDataProvider socket_data_3;
  socket_data_3.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_3);

  SSLSocketDataProvider ssl_1(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_1);
  SSLSocketDataProvider ssl_2(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_2);
  SSLSocketDataProvider ssl_3(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_3);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));
  ClientSocketPool* ssl_pool = session->GetSocketPool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());

  auto GetGroupCount = [&] {
    if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
      return GetHttpStreamPoolGroupCount(session.get());
    } else {
      return GetSocketPoolGroupCount(ssl_pool);
    }
  };

  EXPECT_EQ(GetGroupCount(), 0);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.privacy_mode = PRIVACY_MODE_DISABLED;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  EXPECT_EQ(GetGroupCount(), 1);

  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  EXPECT_EQ(GetGroupCount(), 1);

  request_info.privacy_mode = PRIVACY_MODE_ENABLED;
  StreamRequester requester3(session.get());
  requester3.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  EXPECT_EQ(GetGroupCount(), 2);
}

TEST_P(HttpStreamFactoryTest, DisableSecureDnsUsesDifferentSocketPoolGroup) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  StaticSocketDataProvider socket_data_1;
  socket_data_1.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_1);
  StaticSocketDataProvider socket_data_2;
  socket_data_2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_2);
  StaticSocketDataProvider socket_data_3;
  socket_data_3.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_3);

  SSLSocketDataProvider ssl_1(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_1);
  SSLSocketDataProvider ssl_2(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_2);
  SSLSocketDataProvider ssl_3(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_3);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));
  ClientSocketPool* ssl_pool = session->GetSocketPool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());

  auto GetGroupCount = [&] {
    if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
      return GetHttpStreamPoolGroupCount(session.get());
    } else {
      return GetSocketPoolGroupCount(ssl_pool);
    }
  };

  EXPECT_EQ(GetGroupCount(), 0);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.privacy_mode = PRIVACY_MODE_DISABLED;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request_info.secure_dns_policy = SecureDnsPolicy::kAllow;

  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  EXPECT_EQ(SecureDnsPolicy::kAllow,
            session_deps.host_resolver->last_secure_dns_policy());
  EXPECT_EQ(GetGroupCount(), 1);

  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  EXPECT_EQ(SecureDnsPolicy::kAllow,
            session_deps.host_resolver->last_secure_dns_policy());
  EXPECT_EQ(GetGroupCount(), 1);

  request_info.secure_dns_policy = SecureDnsPolicy::kDisable;
  StreamRequester requester3(session.get());
  requester3.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);

  EXPECT_EQ(SecureDnsPolicy::kDisable,
            session_deps.host_resolver->last_secure_dns_policy());
  EXPECT_EQ(GetGroupCount(), 2);
}

TEST_P(HttpStreamFactoryTest, GetLoadState) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestStream(session->http_stream_factory(), request_info,
                          DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                          /*enable_ip_based_pooling=*/true,
                          /*enable_alternative_services=*/true);
  requester.MaybeWaitForSwitchesToHttpStreamPool();

  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, requester.request()->GetLoadState());

  requester.WaitForStream();
}

TEST_P(HttpStreamFactoryTest, RequestHttpStream) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

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
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

// Test the race of SetPriority versus stream completion where SetPriority may
// be called on an HttpStreamFactory::Job after the stream has been created by
// the job.
TEST_P(HttpStreamFactoryTest, ReprioritizeAfterStreamReceived) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());
  session_deps.host_resolver->set_synchronous_mode(true);

  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider socket_data(base::span_from_ref(mock_read),
                                       base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(SYNCHRONOUS, OK);
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
  EXPECT_EQ(0, GetSpdySessionCount(session.get()));
  requester.RequestStream(session->http_stream_factory(), request_info, LOWEST,
                          /*allowed_bad_certs=*/{},
                          /*enable_ip_based_pooling=*/true,
                          /*enable_alternative_services=*/
"""


```