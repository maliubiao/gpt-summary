Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger unit test file for Chromium's network stack, specifically focusing on `net/spdy/spdy_session_pool_unittest.cc`.

Here's a breakdown of the tasks:

1. **Identify the core functionality:**  Based on the test names and the operations performed (creating sessions, finding available sessions, simulating network changes), the code seems to be testing the `SpdySessionPool`'s behavior, particularly around session reuse (pooling) and its response to network events.

2. **Relate to JavaScript (if applicable):** Think about how network connections are managed in a browser context and if any of this logic directly manifests in JavaScript APIs or behavior.

3. **Analyze logical inference:**  Look for conditional logic and how inputs lead to specific outputs, like whether a session is reused or a new one is created.

4. **Identify potential user/programmer errors:** Consider scenarios where incorrect configuration or usage could lead to unexpected behavior.

5. **Explain user steps to reach this code:** Think about a user's interaction with a browser that would trigger the underlying network operations being tested here.

6. **Summarize the functionality:** Condense the findings into a concise summary for part 2 of the multi-part request.

**Constraint Checklist & Confidence Score:**

* Provide functionality: Yes.
* Javascript relation: Yes (though indirect).
* Javascript example: Yes.
* Logical inference: Yes.
* Input/Output examples: Yes.
* User/programming errors: Yes.
* User steps to reach: Yes.
* Summarize functionality: Yes.
* Part 2 of 3: Yes.

Confidence Score: 5/5

**Mental Sandbox:**

* The code heavily tests IP-based connection pooling. It sets up scenarios with hosts resolving to the same IP address and verifies if the `SpdySessionPool` correctly reuses existing connections.
* The tests involving `GoAwayOnChange` and `CloseOnIPAddressChanged` show how the pool handles network configuration changes (IP address, SSL config, certificates) and gracefully closes or drains sessions.
* The WebSocket tests verify that connection pooling works correctly when WebSocket connections are involved, particularly after the `SETTINGS` frame indicating WebSocket support is received.
* The final test with `RequestSessionWithNoSessions` explores the asynchronous creation of sessions when no suitable existing session is found.

**Key Functionalities to Highlight in the Summary:**

* IP-based connection pooling logic.
* Handling of network configuration changes and their impact on existing sessions.
* Interaction with WebSockets and how the connection pool adapts.
* Asynchronous session creation when no suitable session is available.

Strategizing complete. I will now proceed with generating the response based on these insights.
这是对 Chromium 网络栈中 `net/spdy/spdy_session_pool_unittest.cc` 文件部分代码的分析，主要关注 `SpdySessionPool` 的功能，特别是其连接池化行为以及对网络事件的响应。

**当前代码段的功能归纳：**

这段代码主要测试了 `SpdySessionPool` 的以下功能：

1. **基于 IP 地址的连接池化（IP Pooling）：**
   - 验证当多个域名解析到相同的 IP 地址时，`SpdySessionPool` 是否能够将新的连接请求复用到已存在的连接上。
   - 测试了在 DNS 解析结果中包含 ALPN（应用层协议协商）信息时，IP 池化是否能正确工作，特别是当 ALPN 匹配或不匹配时的情况。
   - 验证了禁用 IP 池化后，即使域名解析到相同的 IP，也不会复用连接。

2. **客户端证书对 IP 池化的影响：**
   - 测试了当使用客户端证书进行 SSL 连接时，IP 池化会被禁用，因为这类连接通常具有更强的身份绑定。

3. **网络配置变化对现有连接的影响：**
   - 测试了当网络 IP 地址发生变化时，`SpdySessionPool` 如何处理现有的 SPDY 会话。这包括优雅地关闭（GOAWAY）连接和立即关闭连接两种策略，可以通过 `go_away_on_ip_change` 配置项控制。
   - 模拟了 SSL 配置、证书数据库和证书验证器发生变化时，`SpdySessionPool` 如何关闭相关的会话。

4. **处理 GOAWAY 帧和关闭：**
   - 测试了当接收到服务器发送的 GOAWAY 帧时，`SpdySessionPool` 如何处理，并确保在连接关闭前处理完正在进行的请求。

5. **WebSocket 与 IP 池化的交互：**
   - 验证了当使用 WebSocket 时，IP 池化的逻辑是否正确。特别是，只有在 SPDY 会话接收到指示支持 WebSocket 的 SETTINGS 帧后，才会将该连接用于 WebSocket 请求的池化。

6. **请求会话但无可用会话的情况：**
   - 测试了当请求一个 SPDY 会话，但池中没有合适的可用会话时，`SpdySessionPool` 如何处理请求，并提供了回调机制来通知请求者会话是否可用。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接涉及 JavaScript，但它所测试的网络栈功能是浏览器执行 JavaScript 发起的网络请求的基础。

**举例说明：**

假设一个网页上的 JavaScript 代码需要同时从 `www.example.org` 和 `mail.example.org` 加载资源，而这两个域名在 DNS 中解析到相同的 IP 地址。

```javascript
// JavaScript 代码
fetch('https://www.example.org/resource1.js')
  .then(response => response.text())
  .then(data => console.log(data));

fetch('https://mail.example.org/resource2.css')
  .then(response => response.text())
  .then(data => console.log(data));
```

在这个场景下，这段 C++ 代码所测试的 `SpdySessionPool` 的 IP 池化功能将发挥作用。浏览器会首先为 `www.example.org` 创建一个 SPDY 连接。当 JavaScript 发起对 `mail.example.org` 的请求时，`SpdySessionPool` 会检测到其 IP 地址与已存在的连接相同，从而将第二个请求复用到第一个连接上，避免了建立新的 TCP 连接和 SSL 握手的开销，提高了页面加载速度。

**逻辑推理、假设输入与输出：**

**场景 1：IP 池化启用，相同 IP，无 ALPN**

* **假设输入：**
    - 两个不同的域名 `www.example.org` 和 `mail.example.org`。
    - 它们的 DNS 解析结果都指向相同的 IP 地址 `192.168.0.1:443`。
    - IP 池化在 `SpdySessionPool` 中启用。
    - 没有为这两个域名配置特定的 ALPN。
* **预期输出：**
    - 当为 `www.example.org` 创建第一个 SPDY 会话后，尝试为 `mail.example.org` 创建会话时，`SpdySessionPool` 会找到并复用已存在的会话。
    - `FindAvailableSession` 会返回相同的 `SpdySession` 对象。
    - NetLog 会记录 `HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION_FROM_IP_POOL` 事件。

**场景 2：IP 池化启用，相同 IP，ALPN 不匹配**

* **假设输入：**
    - 两个不同的域名 `www.example.org` 和 `mail.example.com`。
    - 它们的 DNS 解析结果都指向相同的 IP 地址 `192.168.0.1:443`。
    - IP 池化在 `SpdySessionPool` 中启用。
    - `www.example.org` 的 DNS 解析结果没有 ALPN 信息。
    - `mail.example.com` 的 DNS 解析结果包含 ALPN 信息，例如 `h3` (QUIC)，与 SPDY/HTTP2 不匹配。
* **预期输出：**
    - 当为 `www.example.org` 创建第一个 SPDY 会话后，尝试为 `mail.example.com` 创建会话时，`SpdySessionPool` 不会复用已存在的会话，因为 ALPN 不匹配。
    - `TryCreateAliasedSpdySession` 会返回 `false`。

**用户或编程常见的使用错误：**

1. **错误地假设 IP 池化总是会发生：** 开发者可能会错误地认为只要域名解析到相同的 IP 地址，连接就会被复用。但实际上，IP 池化受到多种因素影响，如是否启用了 IP 池化、是否存在客户端证书、ALPN 是否匹配等。如果依赖于错误的假设，可能会导致性能预期与实际不符。

2. **在需要独立会话的情况下依赖 IP 池化：** 有些应用场景可能需要为不同的域名维护独立的 HTTP/2 会话，例如出于安全或隔离的目的。如果在这种情况下依赖 IP 池化，可能会导致数据泄露或其他安全问题。

3. **在调试网络问题时忽略 IP 池化的影响：** 当调试网络请求问题时，开发者可能会忽略 IP 池化的存在，导致分析请求路径时产生困惑，因为多个看似独立的请求可能实际上共享同一个底层的 TCP 连接。

**用户操作到达此处的调试线索：**

一个用户执行以下操作时，可能会触发浏览器内部对 `SpdySessionPool` 的操作，从而到达这段测试代码所覆盖的逻辑：

1. **在浏览器地址栏中输入一个 HTTPS 网址（例如 `https://www.example.org`）。** 这会触发 DNS 解析，并可能导致创建一个新的 SPDY 会话。
2. **访问一个包含多个 HTTPS 资源的网页，这些资源来自不同的域名，但可能解析到相同的 IP 地址。** 浏览器会尝试复用已存在的 SPDY 连接以加载这些资源。
3. **在启用了客户端证书的情况下访问一个 HTTPS 网站。** 这会影响 IP 池化的行为。
4. **用户的网络 IP 地址发生变化（例如，从 Wi-Fi 切换到移动网络）。** 浏览器需要处理已存在的 SPDY 会话。
5. **浏览器接收到来自服务器的 GOAWAY 帧。** 这会触发 SPDY 会话的优雅关闭流程。
6. **使用开发者工具的网络面板查看网络请求。** 开发者可能会观察到连接的复用情况或连接关闭的原因，这些都与 `SpdySessionPool` 的行为相关。

总而言之，这段代码专注于测试 `SpdySessionPool` 在各种场景下的连接管理和池化策略，确保网络栈能够高效、安全地处理 HTTP/2 连接。

Prompt: 
```
这是目录为net/spdy/spdy_session_pool_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
ource());

  // The second host should pool to the existing connection.
  RecordingNetLogObserver net_log_observer;
  base::HistogramTester histogram_tester;
  EXPECT_TRUE(TryCreateAliasedSpdySession(spdy_session_pool_, test_hosts[1].key,
                                          test_hosts[1].iplist));
  histogram_tester.ExpectTotalCount("Net.SpdySessionGet", 1);

  base::WeakPtr<SpdySession> session1 =
      spdy_session_pool_->FindAvailableSession(
          test_hosts[1].key, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false,
          NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_EQ(session0.get(), session1.get());

  ASSERT_EQ(1u, net_log_observer.GetSize());
  histogram_tester.ExpectTotalCount("Net.SpdySessionGet", 2);

  // FindAvailableSession() should have logged a netlog event indicating IP
  // pooling.
  auto entry_list = net_log_observer.GetEntries();
  EXPECT_EQ(
      NetLogEventType::HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION_FROM_IP_POOL,
      entry_list[0].type);

  // Both FindAvailableSession() calls (including one from
  // TryCreateAliasedSpdySession) should log histogram entries indicating IP
  // pooling.
  histogram_tester.ExpectUniqueSample("Net.SpdySessionGet", 2, 2);
}

// Test IP pooling when the DNS responses have ALPNs.
TEST_F(SpdySessionPoolTest, IPPoolingDnsAlpn) {
  // Define two hosts with identical IP address.
  constexpr int kTestPort = 443;
  struct TestHosts {
    std::string name;
    std::vector<HostResolverEndpointResult> endpoints;
    SpdySessionKey key;
  } test_hosts[] = {{"www.example.org"},
                    {"mail.example.org"},
                    {"mail.example.com"},
                    {"example.test"}};

  const IPEndPoint kRightIP(*IPAddress::FromIPLiteral("192.168.0.1"),
                            kTestPort);
  const IPEndPoint kWrongIP(*IPAddress::FromIPLiteral("192.168.0.2"),
                            kTestPort);
  const std::string kRightALPN = "h2";
  const std::string kWrongALPN = "h3";

  // `test_hosts[0]` and `test_hosts[1]` resolve to the same IP address, without
  // any ALPN information.
  test_hosts[0].endpoints.emplace_back();
  test_hosts[0].endpoints[0].ip_endpoints = {kRightIP};
  test_hosts[1].endpoints.emplace_back();
  test_hosts[1].endpoints[0].ip_endpoints = {kRightIP};

  // `test_hosts[2]` resolves to the same IP address, but only via an
  // alternative endpoint with matching ALPN.
  test_hosts[2].endpoints.emplace_back();
  test_hosts[2].endpoints[0].ip_endpoints = {kRightIP};
  test_hosts[2].endpoints[0].metadata.supported_protocol_alpns = {kRightALPN};

  // `test_hosts[3]` resolves to the same IP address, but only via an
  // alternative endpoint with a mismatching ALPN.
  test_hosts[3].endpoints.resize(2);
  test_hosts[3].endpoints[0].ip_endpoints = {kRightIP};
  test_hosts[3].endpoints[0].metadata.supported_protocol_alpns = {kWrongALPN};
  test_hosts[3].endpoints[1].ip_endpoints = {kWrongIP};
  test_hosts[3].endpoints[1].metadata.supported_protocol_alpns = {kRightALPN};

  // Populate the HostResolver cache.
  session_deps_.host_resolver->set_synchronous_mode(true);
  for (auto& test_host : test_hosts) {
    session_deps_.host_resolver->rules()->AddRule(
        test_host.name,
        MockHostResolverBase::RuleResolver::RuleResult(test_host.endpoints));

    test_host.key = SpdySessionKey(
        HostPortPair(test_host.name, kTestPort), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
  }

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();

  CreateNetworkSession();

  // Open SpdySession to the first host.
  base::WeakPtr<SpdySession> session0 = CreateSpdySession(
      http_session_.get(), test_hosts[0].key, NetLogWithSource());

  // The second host should pool to the existing connection. Although the
  // addresses are not associated with ALPNs, the default connection flow for
  // HTTPS is compatible with HTTP/2.
  EXPECT_TRUE(TryCreateAliasedSpdySession(spdy_session_pool_, test_hosts[1].key,
                                          test_hosts[1].endpoints));
  base::WeakPtr<SpdySession> session1 =
      spdy_session_pool_->FindAvailableSession(
          test_hosts[1].key, /*enable_ip_based_pooling=*/true,
          /*is_websocket=*/false,
          NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_EQ(session0.get(), session1.get());

  // The third host should also pool to the existing connection.
  EXPECT_TRUE(TryCreateAliasedSpdySession(spdy_session_pool_, test_hosts[2].key,
                                          test_hosts[2].endpoints));
  base::WeakPtr<SpdySession> session2 =
      spdy_session_pool_->FindAvailableSession(
          test_hosts[2].key, /*enable_ip_based_pooling=*/true,
          /*is_websocket=*/false,
          NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_EQ(session0.get(), session2.get());

  // The fourth host should not pool. The only matching endpoint is specific to
  // QUIC.
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[3].key, test_hosts[3].endpoints));
}

TEST_F(SpdySessionPoolTest, IPPoolingDisabled) {
  // Define two hosts with identical IP address.
  constexpr int kTestPort = 443;
  struct TestHosts {
    std::string name;
    std::string iplist;
    SpdySessionKey key;
  } test_hosts[] = {
      {"www.example.org", "192.168.0.1"},
      {"mail.example.org", "192.168.0.1"},
  };

  // Populate the HostResolver cache.
  session_deps_.host_resolver->set_synchronous_mode(true);
  for (auto& test_host : test_hosts) {
    session_deps_.host_resolver->rules()->AddIPLiteralRule(
        test_host.name, test_host.iplist, std::string());

    test_host.key = SpdySessionKey(
        HostPortPair(test_host.name, kTestPort), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
  }

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();

  MockRead reads1[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  StaticSocketDataProvider data1(reads1, base::span<MockWrite>());
  MockConnect connect_data1(SYNCHRONOUS, OK);
  data1.set_connect_data(connect_data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  AddSSLSocketData();

  CreateNetworkSession();

  // Open SpdySession to the first host.
  base::WeakPtr<SpdySession> session0 = CreateSpdySession(
      http_session_.get(), test_hosts[0].key, NetLogWithSource());

  // |test_hosts[1]| should pool to the existing connection.
  EXPECT_TRUE(TryCreateAliasedSpdySession(spdy_session_pool_, test_hosts[1].key,
                                          test_hosts[1].iplist));
  base::WeakPtr<SpdySession> session1 =
      spdy_session_pool_->FindAvailableSession(
          test_hosts[1].key, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, NetLogWithSource());
  EXPECT_EQ(session0.get(), session1.get());

  // A request to the second host should not pool to the existing connection if
  // IP based pooling is disabled.
  session1 = spdy_session_pool_->FindAvailableSession(
      test_hosts[1].key, /* enable_ip_based_pooling = */ false,
      /* is_websocket = */ false, NetLogWithSource());
  EXPECT_FALSE(session1);

  // It should be possible to open a new SpdySession, even if a previous call to
  // FindAvailableSession() linked the second key to the first connection in the
  // IP pooled bucket of SpdySessionPool::available_session_map_.
  session1 = CreateSpdySessionWithIpBasedPoolingDisabled(
      http_session_.get(), test_hosts[1].key, NetLogWithSource());
  EXPECT_TRUE(session1);
  EXPECT_NE(session0.get(), session1.get());
}

// Verifies that an SSL connection with client authentication disables SPDY IP
// pooling.
TEST_F(SpdySessionPoolTest, IPPoolingClientCert) {
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert = X509Certificate::CreateFromBytes(webkit_der);
  ASSERT_TRUE(ssl.ssl_info.cert);
  ssl.ssl_info.client_cert_sent = true;
  ssl.next_proto = kProtoHTTP2;
  RunIPPoolingDisabledTest(&ssl);
}

namespace {
enum class ChangeType {
  kIpAddress = 0,
  kSSLConfig,
  kCertDatabase,
  kCertVerifier
};

class SpdySessionGoAwayOnChangeTest
    : public SpdySessionPoolTest,
      public ::testing::WithParamInterface<ChangeType> {
 public:
  void SetUp() override {
    SpdySessionPoolTest::SetUp();

    if (GetParam() == ChangeType::kIpAddress) {
      session_deps_.go_away_on_ip_change = true;
    }
  }

  void SimulateChange() {
    switch (GetParam()) {
      case ChangeType::kIpAddress:
        spdy_session_pool_->OnIPAddressChanged();
        break;
      case ChangeType::kSSLConfig:
        session_deps_.ssl_config_service->NotifySSLContextConfigChange();
        break;
      case ChangeType::kCertDatabase:
        // TODO(mattm): For more realistic testing this should call
        // `CertDatabase::GetInstance()->NotifyObserversCertDBChanged()`,
        // however that delivers notifications asynchronously, and running
        // the message loop to allow the notification to be delivered allows
        // other parts of the tested code to advance, breaking the test
        // expectations.
        spdy_session_pool_->OnSSLConfigChanged(
            SSLClientContext::SSLConfigChangeType::kCertDatabaseChanged);
        break;
      case ChangeType::kCertVerifier:
        session_deps_.cert_verifier->SimulateOnCertVerifierChanged();
        break;
    }
  }

  Error ExpectedNetError() const {
    switch (GetParam()) {
      case ChangeType::kIpAddress:
        return ERR_NETWORK_CHANGED;
      case ChangeType::kSSLConfig:
        return ERR_NETWORK_CHANGED;
      case ChangeType::kCertDatabase:
        return ERR_CERT_DATABASE_CHANGED;
      case ChangeType::kCertVerifier:
        return ERR_CERT_VERIFIER_CHANGED;
    }
  }
};
}  // namespace

// Construct a Pool with SpdySessions in various availability states. Simulate
// an IP address change. Ensure sessions gracefully shut down. Regression test
// for crbug.com/379469.
TEST_P(SpdySessionGoAwayOnChangeTest, GoAwayOnChange) {
  MockConnect connect_data(SYNCHRONOUS, OK);
  session_deps_.host_resolver->set_synchronous_mode(true);

  // This isn't testing anything having to do with SPDY frames; we
  // can ignore issues of how dependencies are set.  We default to
  // setting them (when doing the appropriate protocol) since that's
  // where we're eventually headed for all HTTP/2 connections.
  SpdyTestUtil spdy_util;

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  spdy::SpdySerializedFrame req(
      spdy_util.ConstructSpdyGet("http://www.example.org", 1, MEDIUM));
  MockWrite writes[] = {CreateMockWrite(req, 1)};

  StaticSocketDataProvider dataA(reads, writes);
  dataA.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&dataA);

  AddSSLSocketData();

  CreateNetworkSession();

  // Set up session A: Going away, but with an active stream.
  const std::string kTestHostA("www.example.org");
  HostPortPair test_host_port_pairA(kTestHostA, 80);
  SpdySessionKey keyA(test_host_port_pairA, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> sessionA =
      CreateSpdySession(http_session_.get(), keyA, NetLogWithSource());

  GURL urlA("http://www.example.org");
  base::WeakPtr<SpdyStream> spdy_streamA = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, sessionA, urlA, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegateA(spdy_streamA);
  spdy_streamA->SetDelegate(&delegateA);

  quiche::HttpHeaderBlock headers(
      spdy_util.ConstructGetHeaderBlock(urlA.spec()));
  spdy_streamA->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();  // Allow headers to write.
  EXPECT_TRUE(delegateA.send_headers_completed());

  sessionA->MakeUnavailable();
  EXPECT_TRUE(sessionA->IsGoingAway());
  EXPECT_FALSE(delegateA.StreamIsClosed());

  // Set up session B: Available, with a created stream.
  StaticSocketDataProvider dataB(reads, writes);
  dataB.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&dataB);

  AddSSLSocketData();

  const std::string kTestHostB("mail.example.org");
  HostPortPair test_host_port_pairB(kTestHostB, 80);
  SpdySessionKey keyB(test_host_port_pairB, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> sessionB =
      CreateSpdySession(http_session_.get(), keyB, NetLogWithSource());
  EXPECT_TRUE(sessionB->IsAvailable());

  GURL urlB("http://mail.example.org");
  base::WeakPtr<SpdyStream> spdy_streamB = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, sessionB, urlB, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegateB(spdy_streamB);
  spdy_streamB->SetDelegate(&delegateB);

  // Set up session C: Draining.
  StaticSocketDataProvider dataC(reads, writes);
  dataC.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&dataC);

  AddSSLSocketData();

  const std::string kTestHostC("mail.example.com");
  HostPortPair test_host_port_pairC(kTestHostC, 80);
  SpdySessionKey keyC(test_host_port_pairC, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> sessionC =
      CreateSpdySession(http_session_.get(), keyC, NetLogWithSource());

  sessionC->CloseSessionOnError(ERR_HTTP2_PROTOCOL_ERROR, "Error!");
  EXPECT_TRUE(sessionC->IsDraining());

  SimulateChange();

  EXPECT_TRUE(sessionA->IsGoingAway());
  EXPECT_TRUE(sessionB->IsDraining());
  EXPECT_TRUE(sessionC->IsDraining());

  EXPECT_EQ(1u,
            num_active_streams(sessionA));  // Active stream is still active.
  EXPECT_FALSE(delegateA.StreamIsClosed());

  EXPECT_TRUE(delegateB.StreamIsClosed());  // Created stream was closed.
  EXPECT_THAT(delegateB.WaitForClose(), IsError(ExpectedNetError()));

  sessionA->CloseSessionOnError(ERR_ABORTED, "Closing");
  sessionB->CloseSessionOnError(ERR_ABORTED, "Closing");

  EXPECT_TRUE(delegateA.StreamIsClosed());
  EXPECT_THAT(delegateA.WaitForClose(), IsError(ERR_ABORTED));
}

INSTANTIATE_TEST_SUITE_P(All,
                         SpdySessionGoAwayOnChangeTest,
                         testing::Values(ChangeType::kIpAddress,
                                         ChangeType::kSSLConfig,
                                         ChangeType::kCertDatabase,
                                         ChangeType::kCertVerifier));

// Construct a Pool with SpdySessions in various availability states. Simulate
// an IP address change. Ensure sessions gracefully shut down. Regression test
// for crbug.com/379469.
TEST_F(SpdySessionPoolTest, CloseOnIPAddressChanged) {
  MockConnect connect_data(SYNCHRONOUS, OK);
  session_deps_.host_resolver->set_synchronous_mode(true);

  // This isn't testing anything having to do with SPDY frames; we
  // can ignore issues of how dependencies are set.  We default to
  // setting them (when doing the appropriate protocol) since that's
  // where we're eventually headed for all HTTP/2 connections.
  SpdyTestUtil spdy_util;

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  spdy::SpdySerializedFrame req(
      spdy_util.ConstructSpdyGet("http://www.example.org", 1, MEDIUM));
  MockWrite writes[] = {CreateMockWrite(req, 1)};

  StaticSocketDataProvider dataA(reads, writes);
  dataA.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&dataA);

  AddSSLSocketData();

  session_deps_.go_away_on_ip_change = false;
  CreateNetworkSession();

  // Set up session A: Going away, but with an active stream.
  const std::string kTestHostA("www.example.org");
  HostPortPair test_host_port_pairA(kTestHostA, 80);
  SpdySessionKey keyA(test_host_port_pairA, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> sessionA =
      CreateSpdySession(http_session_.get(), keyA, NetLogWithSource());

  GURL urlA("http://www.example.org");
  base::WeakPtr<SpdyStream> spdy_streamA = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, sessionA, urlA, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegateA(spdy_streamA);
  spdy_streamA->SetDelegate(&delegateA);

  quiche::HttpHeaderBlock headers(
      spdy_util.ConstructGetHeaderBlock(urlA.spec()));
  spdy_streamA->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();  // Allow headers to write.
  EXPECT_TRUE(delegateA.send_headers_completed());

  sessionA->MakeUnavailable();
  EXPECT_TRUE(sessionA->IsGoingAway());
  EXPECT_FALSE(delegateA.StreamIsClosed());

  // Set up session B: Available, with a created stream.
  StaticSocketDataProvider dataB(reads, writes);
  dataB.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&dataB);

  AddSSLSocketData();

  const std::string kTestHostB("mail.example.org");
  HostPortPair test_host_port_pairB(kTestHostB, 80);
  SpdySessionKey keyB(test_host_port_pairB, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> sessionB =
      CreateSpdySession(http_session_.get(), keyB, NetLogWithSource());
  EXPECT_TRUE(sessionB->IsAvailable());

  GURL urlB("http://mail.example.org");
  base::WeakPtr<SpdyStream> spdy_streamB = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, sessionB, urlB, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegateB(spdy_streamB);
  spdy_streamB->SetDelegate(&delegateB);

  // Set up session C: Draining.
  StaticSocketDataProvider dataC(reads, writes);
  dataC.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&dataC);

  AddSSLSocketData();

  const std::string kTestHostC("mail.example.com");
  HostPortPair test_host_port_pairC(kTestHostC, 80);
  SpdySessionKey keyC(test_host_port_pairC, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> sessionC =
      CreateSpdySession(http_session_.get(), keyC, NetLogWithSource());

  sessionC->CloseSessionOnError(ERR_HTTP2_PROTOCOL_ERROR, "Error!");
  EXPECT_TRUE(sessionC->IsDraining());

  spdy_session_pool_->OnIPAddressChanged();

  EXPECT_TRUE(sessionA->IsDraining());
  EXPECT_TRUE(sessionB->IsDraining());
  EXPECT_TRUE(sessionC->IsDraining());

  // Both streams were closed with an error.
  EXPECT_TRUE(delegateA.StreamIsClosed());
  EXPECT_THAT(delegateA.WaitForClose(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_TRUE(delegateB.StreamIsClosed());
  EXPECT_THAT(delegateB.WaitForClose(), IsError(ERR_NETWORK_CHANGED));
}

// Regression test for https://crbug.com/789791.
TEST_F(SpdySessionPoolTest, HandleIPAddressChangeThenShutdown) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  SpdyTestUtil spdy_util;
  spdy::SpdySerializedFrame req(
      spdy_util.ConstructSpdyGet(kDefaultUrl, 1, MEDIUM));
  MockWrite writes[] = {CreateMockWrite(req, 1)};
  StaticSocketDataProvider data(reads, writes);

  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();

  CreateNetworkSession();

  const GURL url(kDefaultUrl);
  SpdySessionKey key(HostPortPair::FromURL(url), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> session =
      CreateSpdySession(http_session_.get(), key, NetLogWithSource());

  base::WeakPtr<SpdyStream> spdy_stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util.ConstructGetHeaderBlock(url.spec()));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(delegate.send_headers_completed());

  spdy_session_pool_->OnIPAddressChanged();

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN) || BUILDFLAG(IS_IOS)
  EXPECT_EQ(1u, num_active_streams(session));
  EXPECT_TRUE(session->IsGoingAway());
  EXPECT_FALSE(session->IsDraining());
#else
  EXPECT_EQ(0u, num_active_streams(session));
  EXPECT_FALSE(session->IsGoingAway());
  EXPECT_TRUE(session->IsDraining());
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN) || BUILDFLAG(IS_IOS)

  http_session_.reset();

  data.AllReadDataConsumed();
  data.AllWriteDataConsumed();
}

// Regression test for https://crbug.com/789791.
TEST_F(SpdySessionPoolTest, HandleGracefulGoawayThenShutdown) {
  SpdyTestUtil spdy_util;
  spdy::SpdySerializedFrame goaway(spdy_util.ConstructSpdyGoAway(
      0x7fffffff, spdy::ERROR_CODE_NO_ERROR, "Graceful shutdown."));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(goaway, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), MockRead(ASYNC, OK, 4)};
  spdy::SpdySerializedFrame req(
      spdy_util.ConstructSpdyGet(kDefaultUrl, 1, MEDIUM));
  MockWrite writes[] = {CreateMockWrite(req, 0)};
  SequencedSocketData data(reads, writes);

  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();

  CreateNetworkSession();

  const GURL url(kDefaultUrl);
  SpdySessionKey key(HostPortPair::FromURL(url), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> session =
      CreateSpdySession(http_session_.get(), key, NetLogWithSource());

  base::WeakPtr<SpdyStream> spdy_stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util.ConstructGetHeaderBlock(url.spec()));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Send headers.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(delegate.send_headers_completed());

  EXPECT_EQ(1u, num_active_streams(session));
  EXPECT_FALSE(session->IsGoingAway());
  EXPECT_FALSE(session->IsDraining());

  // Read GOAWAY.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, num_active_streams(session));
  EXPECT_TRUE(session->IsGoingAway());
  EXPECT_FALSE(session->IsDraining());

  http_session_.reset();

  data.AllReadDataConsumed();
  data.AllWriteDataConsumed();
}

TEST_F(SpdySessionPoolTest, IPConnectionPoolingWithWebSockets) {
  // Define two hosts with identical IP address.
  const int kTestPort = 443;
  struct TestHosts {
    std::string name;
    std::string iplist;
    SpdySessionKey key;
  } test_hosts[] = {
      {"www.example.org", "192.168.0.1"},
      {"mail.example.org", "192.168.0.1"},
  };

  // Populate the HostResolver cache.
  session_deps_.host_resolver->set_synchronous_mode(true);
  for (auto& test_host : test_hosts) {
    session_deps_.host_resolver->rules()->AddIPLiteralRule(
        test_host.name, test_host.iplist, std::string());

    test_host.key = SpdySessionKey(
        HostPortPair(test_host.name, kTestPort), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
  }

  SpdyTestUtil spdy_util;

  spdy::SpdySerializedFrame req(
      spdy_util.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame settings_ack(spdy_util.ConstructSpdySettingsAck());
  MockWrite writes[] = {CreateMockWrite(req, 0),
                        CreateMockWrite(settings_ack, 2)};

  spdy::SettingsMap settings;
  settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame resp(
      spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {CreateMockRead(settings_frame, 1),
                      CreateMockRead(resp, 3), CreateMockRead(body, 4),
                      MockRead(ASYNC, ERR_IO_PENDING, 5),
                      MockRead(ASYNC, 0, 6)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();
  CreateNetworkSession();

  // Create a connection to the first host.
  base::WeakPtr<SpdySession> session = CreateSpdySession(
      http_session_.get(), test_hosts[0].key, NetLogWithSource());

  // SpdySession does not support Websocket before SETTINGS frame is read.
  EXPECT_FALSE(session->support_websocket());
  NetLogWithSource net_log_with_source{
      NetLogWithSource::Make(NetLogSourceType::NONE)};
  // TryCreateAliasedSpdySession should not find |session| for either
  // SpdySessionKeys if |is_websocket| argument is set.
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[0].key, test_hosts[0].iplist,
      /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ true));
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[1].key, test_hosts[1].iplist,
      /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ true));

  // Start request that triggers reading the SETTINGS frame.
  const GURL url(kDefaultUrl);
  base::WeakPtr<SpdyStream> spdy_stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url, LOWEST, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util.ConstructGetHeaderBlock(url.spec()));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Now SpdySession has read the SETTINGS frame and thus supports Websocket.
  EXPECT_TRUE(session->support_websocket());

  // FindAvailableSession() on the first host should now find the existing
  // session with websockets enabled, and TryCreateAliasedSpdySession() should
  // now set up aliases for |session| for the second one.
  base::WeakPtr<SpdySession> result = spdy_session_pool_->FindAvailableSession(
      test_hosts[0].key, /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ true, net_log_with_source);
  EXPECT_EQ(session.get(), result.get());
  EXPECT_TRUE(TryCreateAliasedSpdySession(spdy_session_pool_, test_hosts[1].key,
                                          test_hosts[1].iplist,
                                          /* enable_ip_based_pooling = */ true,
                                          /* is_websocket = */ true));

  // FindAvailableSession() should return |session| for either SpdySessionKeys
  // when IP based pooling is enabled.
  result = spdy_session_pool_->FindAvailableSession(
      test_hosts[0].key, /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ true, net_log_with_source);
  EXPECT_EQ(session.get(), result.get());
  result = spdy_session_pool_->FindAvailableSession(
      test_hosts[1].key, /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ true, net_log_with_source);
  EXPECT_EQ(session.get(), result.get());

  // FindAvailableSession() should only return |session| for the first
  // SpdySessionKey when IP based pooling is disabled.
  result = spdy_session_pool_->FindAvailableSession(
      test_hosts[0].key, /* enable_ip_based_pooling = */ false,
      /* is_websocket = */ true, net_log_with_source);
  EXPECT_EQ(session.get(), result.get());
  result = spdy_session_pool_->FindAvailableSession(
      test_hosts[1].key, /* enable_ip_based_pooling = */ false,
      /* is_websocket = */ true, net_log_with_source);
  EXPECT_FALSE(result);

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

class TestOnRequestDeletedCallback {
 public:
  TestOnRequestDeletedCallback() = default;

  TestOnRequestDeletedCallback(const TestOnRequestDeletedCallback&) = delete;
  TestOnRequestDeletedCallback& operator=(const TestOnRequestDeletedCallback&) =
      delete;

  ~TestOnRequestDeletedCallback() = default;

  base::RepeatingClosure Callback() {
    return base::BindRepeating(&TestOnRequestDeletedCallback::OnRequestDeleted,
                               base::Unretained(this));
  }

  bool invoked() const { return invoked_; }

  void WaitUntilInvoked() { run_loop_.Run(); }

  void SetRequestDeletedCallback(base::OnceClosure request_deleted_callback) {
    DCHECK(!request_deleted_callback_);
    request_deleted_callback_ = std::move(request_deleted_callback);
  }

 private:
  void OnRequestDeleted() {
    EXPECT_FALSE(invoked_);
    invoked_ = true;
    if (request_deleted_callback_) {
      std::move(request_deleted_callback_).Run();
    }
    run_loop_.Quit();
  }

  bool invoked_ = false;
  base::RunLoop run_loop_;

  base::OnceClosure request_deleted_callback_;
};

class TestRequestDelegate
    : public SpdySessionPool::SpdySessionRequest::Delegate {
 public:
  TestRequestDelegate() = default;

  TestRequestDelegate(const TestRequestDelegate&) = delete;
  TestRequestDelegate& operator=(const TestRequestDelegate&) = delete;

  ~TestRequestDelegate() override = default;

  // SpdySessionPool::SpdySessionRequest::Delegate implementation:
  void OnSpdySessionAvailable(
      base::WeakPtr<SpdySession> spdy_session) override {}
};

TEST_F(SpdySessionPoolTest, RequestSessionWithNoSessions) {
  const SpdySessionKey kSessionKey(
      HostPortPair("foo.test", 443), PRIVACY_MODE_DISABLED,
      ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);

  CreateNetworkSession();

  // First request. Its request deleted callback should never be invoked.
  TestOnRequestDeletedCallback request_deleted_callback1;
  TestRequestDelegate request_delegate1;
  std::unique_ptr<SpdySessionPool::SpdySessionRequest> spdy_session_request1;
  bool is_first_request_for_session;
  EXPECT_FALSE(spdy_session_pool_->RequestSession(
      kS
"""


```