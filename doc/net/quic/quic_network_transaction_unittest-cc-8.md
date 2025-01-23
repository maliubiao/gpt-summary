Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The request asks for a summary of the functionality of `net/quic/quic_network_transaction_unittest.cc`, focusing on this specific portion (part 9 of 13). It also asks about relationships to JavaScript, logical reasoning with inputs/outputs, common usage errors, debugging steps, and a general summary.

2. **Initial Scan and Identify Key Elements:** Quickly read through the code, looking for:
    * `TEST_P` and `TEST` macros: These indicate individual test cases. The names of the tests are crucial for understanding their purpose.
    * Class names like `QuicNetworkTransactionTest` and `QuicNetworkTransactionWithDestinationTest`: These define the context for the tests.
    * Mock objects and data providers (`MockRead`, `StaticSocketDataProvider`, `MockQuicData`, `MockClientSocketFactory`):  These signal that the tests are simulating network interactions.
    * Assertions and expectations (`EXPECT_THAT`, `ASSERT_TRUE`, `EXPECT_EQ`): These show what the tests are verifying.
    * Specific function calls (`SendRequestAndExpectQuicResponse`, `SendRequestAndExpectHttpResponse`, `CreateSession`, `SetQuicAlternativeService`): These point to the main actions being tested.
    * Parameterized tests (`INSTANTIATE_TEST_SUITE_P`): Indicates tests that run with different configurations.
    * Feature flags (`base::test::ScopedFeatureList`): Shows tests that are conditional based on enabled/disabled features.
    * Proxy-related configurations (`ProxyChain`, `ConfiguredProxyResolutionService`).

3. **Analyze Individual Tests:** Go through each test case and determine its specific purpose:
    * `HostNotInAllowlist`:  The name suggests it's testing the behavior when a hostname is *not* in an allowed list.
    * Tests within `QuicNetworkTransactionWithDestinationTest`:
        * `InvalidCertificate`: Likely tests scenarios where the SSL certificate doesn't match the expected hostname. The `DIFFERENT` check suggests it might be related to alternative services.
        * `PoolIfCertificateValid`:  The name strongly indicates testing connection pooling when the certificate is valid for the target host.
        * `DoNotPoolIfCertificateInvalid`: The opposite of the previous test, focusing on scenarios where pooling should *not* occur due to an invalid certificate.
    * Tests within `QuicNetworkTransactionTest`:
        * `QuicProxyConnectHttpsServer`:  Clearly testing HTTPS connections through a QUIC proxy.
        * `QuicProxyConnectSpdyServer`: Similar to the above, but for HTTP/2 (SPDY) through a QUIC proxy.
        * `QuicProxyConnectQuicServer`: Testing HTTP/3 (QUIC) connections through a QUIC proxy.

4. **Identify Common Themes and Functionality:** Notice recurring patterns:
    * Setting up mock network environments.
    * Sending requests and verifying responses.
    * Testing alternative services and connection pooling.
    * Testing different proxy scenarios.
    * Using `QuicTestPacketMaker` to construct QUIC packets.
    * Checking for correct HTTP status codes, connection information, and data.

5. **Address Specific Questions from the Prompt:**

    * **Functionality Listing:**  Summarize the identified themes and the purpose of individual tests. Use clear, concise language.
    * **Relationship to JavaScript:**  Consider where network interactions initiated by JavaScript might interact with these lower-level networking components. Focus on browser APIs like `fetch` and `XMLHttpRequest` and how they rely on the network stack.
    * **Logical Reasoning (Input/Output):** For a simpler test case (like `HostNotInAllowlist`), define a hypothetical input (a request to a disallowed host) and the expected output (an HTTP response, not a QUIC connection). For more complex tests, the setup already implicitly defines the input (mock network data, request URLs), and the assertions define the expected output.
    * **Common Usage Errors:** Think about mistakes developers might make when dealing with QUIC or network configurations, such as misconfigured allowlists or incorrect certificate handling.
    * **User Operations/Debugging:** Trace how a user action (e.g., clicking a link) might lead to this code being executed. Emphasize the role of the network stack in handling requests. For debugging, highlight the use of network logs and how these tests could be used to isolate issues.
    * **Part 9 Summary:**  Synthesize the functionality covered in this specific section, focusing on the proxy tunneling scenarios and the continued exploration of connection pooling and alternative services.

6. **Refine and Organize:** Review the generated information for clarity, accuracy, and completeness. Organize the points logically and use formatting (like bullet points) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "These tests just check if QUIC works."  **Correction:**  Realize that the tests are much more specific, targeting aspects like allowlists, alternative services, certificate validation, and proxying.
* **Initial thought:**  "JavaScript doesn't directly interact with this C++ code." **Correction:**  Recognize that JavaScript uses browser APIs which *rely* on this underlying network stack. Frame the relationship in terms of how JavaScript initiates network requests that are then handled by this code.
* **Too much detail on individual packet structures:** **Correction:** Focus on the *purpose* of the packet construction rather than the bit-level details, unless the prompt specifically asks for it.
* **Overlapping summaries:** **Correction:** Ensure that the "Functionality" section and the "Part 9 Summary" provide distinct but related information, with the latter focusing specifically on the content of this particular code block.

By following this systematic approach, combining code analysis with an understanding of the request's nuances, a comprehensive and accurate response can be generated.这是 Chromium 网络栈源代码文件 `net/quic/quic_network_transaction_unittest.cc` 的第 9 部分，主要涵盖了以下功能：

**1. 主机不在允许列表中 (HostNotInAllowlist) 的测试：**

*   **功能:**  验证当请求的主机名不在预先配置的 QUIC 主机允许列表时，网络栈的行为。在这种情况下，即使服务器提供了 Alt-Svc (Alternative Service) 头部声明支持 QUIC，客户端也不会尝试使用 QUIC 连接，而是会回退到 HTTP/1.1。
*   **假设输入与输出:**
    *   **假设输入:**
        *   配置了一个 QUIC 主机允许列表，例如 `"mail.example.com"`。
        *   尝试连接到一个不在允许列表中的主机，例如 `"news.example.com"`。
        *   服务器对 `"news.example.com"` 的 HTTP/1.1 响应中包含了 Alt-Svc 头部，声明其支持 QUIC。
    *   **预期输出:**
        *   客户端会成功建立一个 HTTP/1.1 连接。
        *   客户端不会尝试建立 QUIC 连接。
        *   `SendRequestAndExpectHttpResponse` 函数会成功返回，表示收到了 HTTP/1.1 响应。
*   **与 Javascript 的关系:**  当 Javascript 代码通过 `fetch` 或 `XMLHttpRequest` 发起网络请求时，浏览器底层的网络栈会根据配置和服务器的响应来决定使用哪个协议。这个测试验证了当配置了 QUIC 允许列表时，网络栈如何处理不在列表中的主机，即使服务器声明支持 QUIC。
*   **用户或编程常见的使用错误:**  配置 QUIC 允许列表时，容易遗漏某些需要使用 QUIC 的域名，或者配置了错误的域名。这会导致即使目标服务器支持 QUIC，客户端也无法使用，从而可能影响性能。
*   **用户操作到达此处的步骤 (调试线索):**
    1. 用户在浏览器地址栏输入一个 URL，例如 `https://news.example.com`。
    2. 浏览器发起 DNS 查询，解析出 `news.example.com` 的 IP 地址。
    3. 浏览器网络栈检查是否允许对 `news.example.com` 使用 QUIC。如果配置了 QUIC 允许列表，并且 `news.example.com` 不在其中，则会跳过 QUIC 尝试。
    4. 浏览器发起与服务器的 TCP 连接 (如果需要，还包括 TLS 握手)。
    5. 浏览器发送 HTTP/1.1 请求。
    6. 服务器返回 HTTP/1.1 响应，其中可能包含 Alt-Svc 头部。
    7. 由于主机不在允许列表中，网络栈会忽略 Alt-Svc 头部中的 QUIC 信息，继续使用 HTTP/1.1。

**2. 使用目标地址测试 (QuicNetworkTransactionWithDestinationTest)：**

这个测试套件使用了参数化测试 (`::testing::WithParamInterface`)，允许使用不同的配置（例如不同的 QUIC 版本和目标类型）来运行相同的测试逻辑。这部分涵盖了以下几个关键测试用例：

*   **无效证书 (InvalidCertificate):**
    *   **功能:**  测试当连接到提供 QUIC 服务的服务器时，如果服务器提供的 SSL 证书与请求的原始主机名不匹配时，连接会失败。即使证书对备用服务的主机名有效，也无法建立连接。
    *   **假设输入与输出:**
        *   **假设输入:**
            *   请求的 URL 是 `https://mail.example.com/`。
            *   配置了 `mail.example.com` 的 QUIC 备用服务指向 `mail.example.org`。
            *   服务器提供的证书对 `mail.example.org` 有效，但对 `mail.example.com` 无效。
        *   **预期输出:**
            *   连接尝试会失败，并返回 `ERR_CONNECTION_REFUSED` 错误。
    *   **与 Javascript 的关系:** 当 Javascript 代码尝试访问一个使用了 QUIC 的站点，但服务器提供的证书有问题时，浏览器会阻止连接，这会反映在 Javascript 代码中 `fetch` 或 `XMLHttpRequest` 操作的失败。
    *   **用户或编程常见的使用错误:**  服务器配置了错误的 SSL 证书，导致证书的主机名与实际服务的主机名不匹配。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户在浏览器地址栏输入 `https://mail.example.com/`。
        2. 浏览器尝试建立与服务器的 QUIC 连接 (如果可用)。
        3. 在 TLS 握手过程中，浏览器验证服务器提供的证书。
        4. 由于证书对 `mail.example.com` 无效，验证失败。
        5. 连接被拒绝，浏览器显示错误页面或 Javascript 代码捕获到连接错误。

*   **如果证书有效则复用连接池 (PoolIfCertificateValid):**
    *   **功能:** 测试当第一个请求通过 QUIC 连接到备用服务后，如果第二个请求的目标地址与备用服务相同，并且服务器提供的证书对第二个请求的主机名也有效时，可以复用之前的 QUIC 连接。
    *   **假设输入与输出:**
        *   **假设输入:**
            *   第一个请求到 `https://mail.example.org/`，成功建立 QUIC 连接。
            *   第二个请求到 `https://news.example.org/`。
            *   `mail.example.org` 和 `news.example.org` 配置了相同的 QUIC 备用服务地址。
            *   服务器提供的证书对 `mail.example.org` 和 `news.example.org` 都有效。
        *   **预期输出:**
            *   第二个请求会复用之前建立的 QUIC 连接。
            *   `SendRequestAndExpectQuicResponse` 会成功返回两次。
    *   **与 Javascript 的关系:**  当 Javascript 代码连续请求来自相同 QUIC 服务提供商的不同域名时，如果满足条件，浏览器可以复用底层的 QUIC 连接，提高性能。
    *   **用户或编程常见的使用错误:**  无
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户访问一个网页，该网页首先加载 `https://mail.example.org/` 的资源。
        2. 浏览器建立 QUIC 连接。
        3. 网页稍后加载 `https://news.example.org/` 的资源。
        4. 由于配置和证书都匹配，浏览器会尝试复用之前的 QUIC 连接。

*   **如果证书无效则不复用连接池 (DoNotPoolIfCertificateInvalid):**
    *   **功能:**  测试当第一个请求通过 QUIC 连接到备用服务后，如果第二个请求的目标地址与备用服务相同，但服务器提供的证书对第二个请求的主机名无效时，不会复用之前的 QUIC 连接，而是会建立一个新的 QUIC 连接。
    *   **假设输入与输出:**
        *   **假设输入:**
            *   第一个请求到 `https://news.example.org/`，成功建立 QUIC 连接。
            *   第二个请求到 `https://mail.example.com/`。
            *   `news.example.org` 和 `mail.example.com` 配置了相同的 QUIC 备用服务地址。
            *   服务器提供的证书对 `news.example.org` 有效，但对 `mail.example.com` 无效。
        *   **预期输出:**
            *   第二个请求不会复用之前的 QUIC 连接，而是会建立一个新的 QUIC 连接。
            *   `SendRequestAndExpectQuicResponse` 会成功返回两次，但会使用不同的连接。
    *   **与 Javascript 的关系:**  如果 Javascript 代码请求的资源来自不同的域名，并且服务器提供的证书不匹配，浏览器不会复用 QUIC 连接，这可能会导致建立连接的开销增加。
    *   **用户或编程常见的使用错误:**  服务器配置了通配符证书，但没有覆盖所有需要使用 QUIC 的子域名，或者针对不同的域名使用了不同的证书。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户访问一个网页，该网页首先加载 `https://news.example.org/` 的资源。
        2. 浏览器建立 QUIC 连接。
        3. 网页稍后加载 `https://mail.example.com/` 的资源。
        4. 由于证书对 `mail.example.com` 无效，浏览器不会复用之前的 QUIC 连接，而是会尝试建立新的连接。

**3. 通过 QUIC 代理隧道进行连接的测试 (QuicNetworkTransactionTest):**

这部分测试了通过 QUIC 代理服务器连接到 HTTPS、HTTP/2 和 HTTP/3 服务器的场景。

*   **通过 QUIC 代理连接 HTTPS 服务器 (QuicProxyConnectHttpsServer):**
    *   **功能:**  测试通过 QUIC 代理服务器建立到目标 HTTPS 服务器的连接，并发送 HTTP/1.1 请求。
    *   **涉及的 QUIC 数据包:** 包含了建立连接的握手包，以及用于隧道传输 HTTP/1.1 请求和响应的数据包。
    *   **与 Javascript 的关系:**  当配置了 QUIC 代理时，Javascript 发起的 HTTPS 请求会被浏览器转发到 QUIC 代理服务器，然后再由代理服务器连接到目标服务器。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户在浏览器设置中配置了 QUIC 代理服务器。
        2. 用户访问一个 `https://mail.example.org/` 的 URL。
        3. 浏览器网络栈检测到配置了 QUIC 代理。
        4. 浏览器与 QUIC 代理服务器建立 QUIC 连接。
        5. 浏览器通过 QUIC 连接向代理服务器发送 CONNECT 请求，建立到 `mail.example.org:443` 的隧道。
        6. 浏览器通过建立的隧道发送 HTTP/1.1 请求。
        7. 代理服务器将请求转发到目标服务器，并将响应通过隧道返回给浏览器。

*   **通过 QUIC 代理连接 SPDY 服务器 (QuicProxyConnectSpdyServer):**
    *   **功能:**  测试通过 QUIC 代理服务器建立到目标 HTTP/2 (SPDY) 服务器的连接，并发送 HTTP/2 请求。
    *   **涉及的 QUIC 数据包:**  类似于 HTTPS 测试，但会包含 HTTP/2 帧。
    *   **与 Javascript 的关系:** 类似于 HTTPS 场景，但目标服务器使用 HTTP/2 协议。
    *   **用户操作到达此处的步骤 (调试线索):**  与 HTTPS 场景类似，只是目标服务器支持 HTTP/2。

*   **通过 QUIC 代理连接 QUIC 服务器 (QuicProxyConnectQuicServer):**
    *   **功能:**  测试通过 QUIC 代理服务器建立到目标 HTTP/3 (QUIC) 服务器的连接。这涉及到 MASQUE (Multiplexed Application Substrate over QUIC Encryption) 协议。
    *   **涉及的 QUIC 数据包:**  包含了与代理服务器和目标服务器的 QUIC 连接的握手包，以及使用 H3 Datagrams 封装的 HTTP/3 数据包。
    *   **与 Javascript 的关系:**  当配置了 QUIC 代理且目标服务器也支持 QUIC 时，浏览器可以使用 MASQUE 协议通过代理建立端到端的 QUIC 连接。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户在浏览器设置中配置了 QUIC 代理服务器。
        2. 用户访问一个 `https://mail.example.org/` 的 URL，且该服务器支持 QUIC。
        3. 浏览器网络栈检测到配置了 QUIC 代理，并尝试使用 MASQUE 协议。
        4. 浏览器与 QUIC 代理服务器建立 QUIC 连接。
        5. 浏览器通过 QUIC 连接向代理服务器发送 CONNECT UDP 请求，请求建立到目标服务器的 UDP 连接。
        6. 代理服务器建立到目标服务器的连接。
        7. 浏览器和目标服务器通过代理服务器的隧道进行 QUIC 通信。

**总结第 9 部分的功能:**

第 9 部分的测试主要关注 `net/quic/quic_network_transaction_unittest.cc` 中关于 **QUIC 连接管理和代理** 的功能。它涵盖了以下几个核心方面：

*   **QUIC 主机允许列表:** 验证了当目标主机不在允许列表中时，即使服务器声明支持 QUIC，客户端也会回退到 HTTP/1.1。
*   **基于目标地址的连接管理:**  测试了在有备用服务的情况下，如何根据目标地址和证书的有效性来决定是否复用 QUIC 连接。
*   **QUIC 代理隧道:** 详细测试了通过 QUIC 代理服务器连接到各种类型的后端服务器（HTTPS, HTTP/2, HTTP/3），特别是 HTTP/3 的测试中涉及到了 MASQUE 协议。

这些测试用例确保了 Chromium 网络栈在处理 QUIC 连接，特别是涉及到备用服务和代理时，能够正确地管理连接，保障安全性和性能。

### 提示词
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
pResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, HostNotInAllowlist) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  session_params_.quic_host_allowlist.insert("mail.example.com");

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectHttpResponse(kHttpRespData);
}

class QuicNetworkTransactionWithDestinationTest
    : public PlatformTest,
      public ::testing::WithParamInterface<PoolingTestParams>,
      public WithTaskEnvironment {
 protected:
  QuicNetworkTransactionWithDestinationTest()
      : version_(GetParam().version),
        supported_versions_(quic::test::SupportedVersions(version_)),
        destination_type_(GetParam().destination_type),
        ssl_config_service_(std::make_unique<SSLConfigServiceDefaults>()),
        proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        auth_handler_factory_(HttpAuthHandlerFactory::CreateDefault()),
        ssl_data_(ASYNC, OK) {
    std::vector<base::test::FeatureRef> enabled_features;
    std::vector<base::test::FeatureRef> disabled_features;
    if (GetParam().happy_eyeballs_v3_enabled) {
      enabled_features.emplace_back(features::kHappyEyeballsV3);
      // Disable AsyncQuicSession to simplify tests since HappyEyeballsV3
      // may attempt both the origin and alternative endpoint when
      // AsyncQuicSession is enabled.
      // TODO(crbug.com/346835898): Avoid disabling AsyncQuicSession.
      disabled_features.emplace_back(features::kAsyncQuicSession);
    } else {
      disabled_features.emplace_back(features::kHappyEyeballsV3);
    }
    feature_list_.InitWithFeatures(enabled_features, disabled_features);

    FLAGS_quic_enable_http3_grease_randomness = false;
  }

  void SetUp() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();

    HttpNetworkSessionParams session_params;
    session_params.enable_quic = true;
    // To simplify tests, we disable UseDnsHttpsSvcbAlpn feature. If this is
    // enabled, we need to prepare mock sockets for `dns_alpn_h3_job_`. Also
    // AsyncQuicSession feature makes it more complecated because it changes the
    // socket call order.
    session_params.use_dns_https_svcb_alpn = false;

    context_.params()->allow_remote_alt_svc = true;
    context_.params()->supported_versions = supported_versions_;

    HttpNetworkSessionContext session_context;

    context_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));

    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    session_context.quic_crypto_client_stream_factory =
        &crypto_client_stream_factory_;

    session_context.quic_context = &context_;
    session_context.client_socket_factory = &socket_factory_;
    session_context.host_resolver = &host_resolver_;
    session_context.cert_verifier = &cert_verifier_;
    session_context.transport_security_state = &transport_security_state_;
    session_context.socket_performance_watcher_factory =
        &test_socket_performance_watcher_factory_;
    session_context.ssl_config_service = ssl_config_service_.get();
    session_context.proxy_resolution_service = proxy_resolution_service_.get();
    session_context.http_auth_handler_factory = auth_handler_factory_.get();
    session_context.http_server_properties = &http_server_properties_;

    session_ =
        std::make_unique<HttpNetworkSession>(session_params, session_context);
    session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
        false);
  }

  void TearDown() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    // Empty the current queue.
    base::RunLoop().RunUntilIdle();
    PlatformTest::TearDown();
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
    session_.reset();
  }

  void SetQuicAlternativeService(const std::string& origin) {
    HostPortPair destination;
    switch (destination_type_) {
      case SAME_AS_FIRST:
        destination = HostPortPair(origin1_, 443);
        break;
      case SAME_AS_SECOND:
        destination = HostPortPair(origin2_, 443);
        break;
      case DIFFERENT:
        destination = HostPortPair(kDifferentHostname, 443);
        break;
    }
    AlternativeService alternative_service(kProtoQUIC, destination);
    base::Time expiration = base::Time::Now() + base::Days(1);
    http_server_properties_.SetQuicAlternativeService(
        url::SchemeHostPort("https", origin, 443), NetworkAnonymizationKey(),
        alternative_service, expiration, supported_versions_);
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructClientRequestHeadersPacket(uint64_t packet_number,
                                      quic::QuicStreamId stream_id,
                                      QuicTestPacketMaker* maker) {
    spdy::SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
    quiche::HttpHeaderBlock headers(
        maker->GetRequestHeaders("GET", "https", "/"));
    return maker->MakeRequestHeadersPacket(
        packet_number, stream_id, true, priority, std::move(headers), nullptr);
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructServerResponseHeadersPacket(uint64_t packet_number,
                                       quic::QuicStreamId stream_id,
                                       QuicTestPacketMaker* maker) {
    quiche::HttpHeaderBlock headers(maker->GetResponseHeaders("200"));
    return maker->MakeResponseHeadersPacket(packet_number, stream_id, false,
                                            std::move(headers), nullptr);
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructServerDataPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      QuicTestPacketMaker* maker) {
    return maker->Packet(packet_number)
        .AddStreamFrame(stream_id, true,
                        ConstructDataFrameForVersion("hello", version_))
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientAckPacket(
      uint64_t packet_number,
      uint64_t largest_received,
      uint64_t smallest_received,
      QuicTestPacketMaker* maker) {
    return maker->Packet(packet_number)
        .AddAckFrame(1, largest_received, smallest_received)
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructInitialSettingsPacket(
      uint64_t packet_number,
      QuicTestPacketMaker* maker) {
    return maker->MakeInitialSettingsPacket(packet_number);
  }

  void AddRefusedSocketData() {
    auto refused_data = std::make_unique<StaticSocketDataProvider>();
    MockConnect refused_connect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
    refused_data->set_connect_data(refused_connect);
    socket_factory_.AddSocketDataProvider(refused_data.get());
    static_socket_data_provider_vector_.push_back(std::move(refused_data));
  }

  void AddHangingSocketData() {
    auto hanging_data = std::make_unique<StaticSocketDataProvider>();
    MockConnect hanging_connect(SYNCHRONOUS, ERR_IO_PENDING);
    hanging_data->set_connect_data(hanging_connect);
    socket_factory_.AddSocketDataProvider(hanging_data.get());
    static_socket_data_provider_vector_.push_back(std::move(hanging_data));
    socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  }

  bool AllDataConsumed() {
    for (const auto& socket_data_ptr : static_socket_data_provider_vector_) {
      if (!socket_data_ptr->AllReadDataConsumed() ||
          !socket_data_ptr->AllWriteDataConsumed()) {
        return false;
      }
    }
    return true;
  }

  void SendRequestAndExpectQuicResponse(const std::string& host) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    HttpRequestInfo request;
    std::string url("https://");
    url.append(host);
    request.url = GURL(url);
    request.load_flags = 0;
    request.method = "GET";
    request.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    TestCompletionCallback callback;
    int rv = trans.Start(&request, callback.callback(), net_log_with_source_);
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    std::string response_data;
    ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
    EXPECT_EQ("hello", response_data);

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    ASSERT_TRUE(response->headers.get() != nullptr);
    EXPECT_EQ(kQuic200RespStatusLine, response->headers->GetStatusLine());
    EXPECT_TRUE(response->was_fetched_via_spdy);
    EXPECT_TRUE(response->was_alpn_negotiated);
    EXPECT_EQ(QuicHttpStream::ConnectionInfoFromQuicVersion(version_),
              response->connection_info);
    EXPECT_EQ(443, response->remote_endpoint.port());
  }

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  base::test::ScopedFeatureList feature_list_;
  quic::test::QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
  const quic::ParsedQuicVersion version_;
  quic::ParsedQuicVersionVector supported_versions_;
  DestinationType destination_type_;
  std::string origin1_;
  std::string origin2_;
  MockQuicContext context_;
  std::unique_ptr<HttpNetworkSession> session_;
  MockClientSocketFactory socket_factory_;
  MockHostResolver host_resolver_{/*default_result=*/MockHostResolverBase::
                                      RuleResolver::GetLocalhostResult()};
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  TestSocketPerformanceWatcherFactory test_socket_performance_watcher_factory_;
  std::unique_ptr<SSLConfigServiceDefaults> ssl_config_service_;
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service_;
  std::unique_ptr<HttpAuthHandlerFactory> auth_handler_factory_;
  HttpServerProperties http_server_properties_;
  NetLogWithSource net_log_with_source_{
      NetLogWithSource::Make(NetLogSourceType::NONE)};
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  std::vector<std::unique_ptr<StaticSocketDataProvider>>
      static_socket_data_provider_vector_;
  SSLSocketDataProvider ssl_data_;
};

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         QuicNetworkTransactionWithDestinationTest,
                         ::testing::ValuesIn(GetPoolingTestParams()),
                         ::testing::PrintToStringParamName());

// A single QUIC request fails because the certificate does not match the origin
// hostname, regardless of whether it matches the alternative service hostname.
TEST_P(QuicNetworkTransactionWithDestinationTest, InvalidCertificate) {
  if (destination_type_ == DIFFERENT) {
    return;
  }

  GURL url("https://mail.example.com/");
  origin1_ = url.host();

  // Not used for requests, but this provides a test case where the certificate
  // is valid for the hostname of the alternative service.
  origin2_ = "mail.example.org";

  SetQuicAlternativeService(origin1_);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_FALSE(cert->VerifyNameMatch(origin1_));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData mock_quic_data(version_);
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddRefusedSocketData();

  HttpRequestInfo request;
  request.url = url;
  request.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), net_log_with_source_);
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(AllDataConsumed());
}

// First request opens QUIC session to alternative service.  Second request
// pools to it, because destination matches and certificate is valid, even
// though quic::QuicServerId is different.
TEST_P(QuicNetworkTransactionWithDestinationTest, PoolIfCertificateValid) {
  origin1_ = "mail.example.org";
  origin2_ = "news.example.org";

  SetQuicAlternativeService(origin1_);
  SetQuicAlternativeService(origin2_);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch(origin1_));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_));
  ASSERT_FALSE(cert->VerifyNameMatch(kDifferentHostname));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicTestPacketMaker client_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin1_, quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true, /*use_priority_header=*/true);
  QuicTestPacketMaker server_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin1_, quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/false);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(
      SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++, &client_maker));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          &client_maker));
  mock_quic_data.AddRead(
      ASYNC,
      ConstructServerResponseHeadersPacket(
          1, GetNthClientInitiatedBidirectionalStreamId(0), &server_maker));
  mock_quic_data.AddRead(
      ASYNC,
      ConstructServerDataPacket(
          2, GetNthClientInitiatedBidirectionalStreamId(0), &server_maker));
  mock_quic_data.AddWrite(
      SYNCHRONOUS, ConstructClientAckPacket(packet_num++, 2, 1, &client_maker));

  client_maker.set_hostname(origin2_);
  server_maker.set_hostname(origin2_);

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(1),
          &client_maker));
  mock_quic_data.AddRead(
      ASYNC,
      ConstructServerResponseHeadersPacket(
          3, GetNthClientInitiatedBidirectionalStreamId(1), &server_maker));
  mock_quic_data.AddRead(
      ASYNC,
      ConstructServerDataPacket(
          4, GetNthClientInitiatedBidirectionalStreamId(1), &server_maker));
  mock_quic_data.AddWrite(
      SYNCHRONOUS, ConstructClientAckPacket(packet_num++, 4, 3, &client_maker));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingSocketData();
  AddHangingSocketData();

  auto quic_task_runner =
      base::MakeRefCounted<TestTaskRunner>(context_.mock_clock());
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner.get(),
                                                 context_.clock()));

  SendRequestAndExpectQuicResponse(origin1_);
  SendRequestAndExpectQuicResponse(origin2_);

  EXPECT_TRUE(AllDataConsumed());
}

// First request opens QUIC session to alternative service.  Second request does
// not pool to it, even though destination matches, because certificate is not
// valid.  Instead, a new QUIC session is opened to the same destination with a
// different quic::QuicServerId.
TEST_P(QuicNetworkTransactionWithDestinationTest,
       DoNotPoolIfCertificateInvalid) {
  origin1_ = "news.example.org";
  origin2_ = "mail.example.com";

  SetQuicAlternativeService(origin1_);
  SetQuicAlternativeService(origin2_);

  scoped_refptr<X509Certificate> cert1(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert1->VerifyNameMatch(origin1_));
  ASSERT_FALSE(cert1->VerifyNameMatch(origin2_));
  ASSERT_FALSE(cert1->VerifyNameMatch(kDifferentHostname));

  scoped_refptr<X509Certificate> cert2(
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem"));
  ASSERT_TRUE(cert2->VerifyNameMatch(origin2_));
  ASSERT_FALSE(cert2->VerifyNameMatch(kDifferentHostname));

  ProofVerifyDetailsChromium verify_details1;
  verify_details1.cert_verify_result.verified_cert = cert1;
  verify_details1.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert2;
  verify_details2.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  QuicTestPacketMaker client_maker1(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin1_, quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true, /*use_priority_header=*/true);
  QuicTestPacketMaker server_maker1(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin1_, quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/false);

  MockQuicData mock_quic_data1(version_);
  int packet_num = 1;
  mock_quic_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(
                                            packet_num++, &client_maker1));
  mock_quic_data1.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          &client_maker1));
  mock_quic_data1.AddRead(
      ASYNC,
      ConstructServerResponseHeadersPacket(
          1, GetNthClientInitiatedBidirectionalStreamId(0), &server_maker1));
  mock_quic_data1.AddRead(
      ASYNC,
      ConstructServerDataPacket(
          2, GetNthClientInitiatedBidirectionalStreamId(0), &server_maker1));
  mock_quic_data1.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckPacket(packet_num++, 2, 1, &client_maker1));
  mock_quic_data1.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data1.AddRead(ASYNC, 0);               // EOF

  mock_quic_data1.AddSocketDataToFactory(&socket_factory_);

  QuicTestPacketMaker client_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin2_, quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true, /*use_priority_header=*/true);
  QuicTestPacketMaker server_maker2(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), origin2_, quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/false);

  MockQuicData mock_quic_data2(version_);
  int packet_num2 = 1;
  mock_quic_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(
                                            packet_num2++, &client_maker2));
  mock_quic_data2.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num2++, GetNthClientInitiatedBidirectionalStreamId(0),
          &client_maker2));
  mock_quic_data2.AddRead(
      ASYNC,
      ConstructServerResponseHeadersPacket(
          1, GetNthClientInitiatedBidirectionalStreamId(0), &server_maker2));
  mock_quic_data2.AddRead(
      ASYNC,
      ConstructServerDataPacket(
          2, GetNthClientInitiatedBidirectionalStreamId(0), &server_maker2));
  mock_quic_data2.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckPacket(packet_num2++, 2, 1, &client_maker2));
  mock_quic_data2.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data2.AddRead(ASYNC, 0);               // EOF

  mock_quic_data2.AddSocketDataToFactory(&socket_factory_);

  SendRequestAndExpectQuicResponse(origin1_);
  SendRequestAndExpectQuicResponse(origin2_);

  EXPECT_TRUE(AllDataConsumed());
}

// Performs an HTTPS/1.1 request over QUIC proxy tunnel.
TEST_P(QuicNetworkTransactionTest, QuicProxyConnectHttpsServer) {
  DisablePriorityHeader();
  session_params_.enable_quic = true;

  const auto kQuicProxyChain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)});
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {kQuicProxyChain}, TRAFFIC_ANNOTATION_FOR_TESTS);

  QuicSocketDataProvider socket_data(version_);
  int packet_num = 1;
  socket_data
      .AddWrite("initial-settings",
                ConstructInitialSettingsPacket(packet_num++))
      .Sync();
  socket_data
      .AddWrite("priority",
                ConstructClientPriorityPacket(
                    packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
                    DEFAULT_PRIORITY))
      .Sync();
  socket_data
      .AddWrite("connect-request",
                ConstructClientRequestHeadersPacket(
                    packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
                    false, DEFAULT_PRIORITY,
                    ConnectRequestHeaders("mail.example.org:443"), false))
      .Sync();
  socket_data.AddRead("connect-response",
                      ConstructServerResponseHeadersPacket(
                          1, GetNthClientInitiatedBidirectionalStreamId(0),
                          false, GetResponseHeaders("200")));

  const char kGetRequest[] =
      "GET / HTTP/1.1\r\n"
      "Host: mail.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  socket_data
      .AddWrite("get-request",
                ConstructClientAckAndDataPacket(
                    packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
                    1, 1, false, ConstructDataFrame(kGetRequest)))
      .Sync();

  const char kGetResponse[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  const char kRespData[] = "0123456789";

  socket_data.AddRead("get-response",
                      ConstructServerDataPacket(
                          2, GetNthClientInitiatedBidirectionalStreamId(0),
                          false, ConstructDataFrame(kGetResponse)));

  socket_data
      .AddRead("response-data",
               ConstructServerDataPacket(
                   3, GetNthClientInitiatedBidirectionalStreamId(0), false,
                   ConstructDataFrame(kRespData)))
      .Sync();

  socket_data
      .AddWrite("response-ack", ConstructClientAckPacket(packet_num++, 3, 2))
      .Sync();

  socket_data
      .AddWrite(
          "qpack-cancel-rst",
          client_maker_->Packet(packet_num++)
              .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                              StreamCancellationQpackDecoderInstruction(0))
              .AddStopSendingFrame(
                  GetNthClientInitiatedBidirectionalStreamId(0),
                  quic::QUIC_STREAM_CANCELLED)
              .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                                 quic::QUIC_STREAM_CANCELLED)
              .Build())
      .Sync();

  socket_factory_.AddSocketDataProvider(&socket_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  request_.url = GURL("https://mail.example.org/");
  SendRequestAndExpectHttpResponseFromProxy(
      kRespData, kQuicProxyChain.First().GetPort(), kQuicProxyChain);

  // Causes MockSSLClientSocket to disconnect, which causes the underlying QUIC
  // proxy socket to disconnect.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();

  socket_data.RunUntilAllConsumed();
}

// Performs an HTTP/2 request over QUIC proxy tunnel.
TEST_P(QuicNetworkTransactionTest, QuicProxyConnectSpdyServer) {
  DisablePriorityHeader();
  session_params_.enable_quic = true;

  const auto kQuicProxyChain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)});
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {kQuicProxyChain}, TRAFFIC_ANNOTATION_FOR_TESTS);

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
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));

  SpdyTestUtil spdy_util(/*use_priority_header=*/true);

  spdy::SpdySerializedFrame get_frame =
      spdy_util.ConstructSpdyGet("https://mail.example.org/", 1, LOWEST);
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndDataPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), 1, 1,
          false, ConstructDataFrame({get_frame.data(), get_frame.size()})));
  spdy::SpdySerializedFrame resp_frame =
      spdy_util.ConstructSpdyGetReply(nullptr, 0, 1);
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 ConstructDataFrame({resp_frame.data(), resp_frame.size()})));

  const char kRespData[] = "0123456789";
  spdy::SpdySerializedFrame data_frame =
      spdy_util.ConstructSpdyDataFrame(1, kRespData, true);
  mock_quic_data.AddRead(
      SYNCHRONOUS,
      ConstructServerDataPacket(
          3, GetNthClientInitiatedBidirectionalStreamId(0), false,
          ConstructDataFrame({data_frame.data(), data_frame.size()})));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 3, 2));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  socket_factory_.AddSSLSocketDataProvider(&ssl_data);

  CreateSession();

  request_.url = GURL("https://mail.example.org/");
  SendRequestAndExpectSpdyResponseFromProxy(
      kRespData, kQuicProxyChain.First().GetPort(), kQuicProxyChain);

  // Causes MockSSLClientSocket to disconnect, which causes the underlying QUIC
  // proxy socket to disconnect.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

// Performs an HTTP/3 request over QUIC proxy tunnel.
TEST_P(QuicNetworkTransactionTest, QuicProxyConnectQuicServer) {
  DisablePriorityHeader();
  session_params_.enable_quic = true;

  const auto kQuicProxyChain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, "proxy.example.org", 70)});
  proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {kQuicProxyChain}, TRAFFIC_ANNOTATION_FOR_TESTS);

  QuicTestPacketMaker to_endpoint_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), "mail.example.org", quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true,
      /*use_priority_header=*/true);
  QuicTestPacketMaker from_endpoint_maker(
      version_,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), "mail.example.org", quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/true);

  QuicSocketDataProvider socket_data(version_);
  const char kRespData[] = "0123456789";
  int to_proxy_packet_num = 1;
  int from_proxy_packet_num = 1;
  int to_endpoint_packet_num = 1;
  int from_endpoint_packet_num = 1;
  socket_data
      .AddWrite("inital-client-settings",
                ConstructInitialSettingsPacket(to_proxy_packet_num++))
      .Sync();

  socket_data
      .AddWrite("connect-udp",
                ConstructConnectUdpRequestPacket(
                    to_proxy_packet_num++,
                    GetNthClientInitiatedBidirectionalStreamId(0),
                    "proxy.example.org:70",
                    "/.well-known/masque/udp/mail.example.org/443/", false))
      .Sync();

  socket_data
      .AddRead("inital-proxy-settings",
               server_maker_.MakeInitialSettingsPacket(from_proxy_packet_num++))
      .Sync();

  socket_data.AddRead("connect-udp-response",
                      ConstructServerResponseHeadersPacket(
                          from_proxy_packet_num++,
                          GetNthClientInitiatedBidirectionalStreamId(0), false,
                          GetResponseHeaders("200")));

  socket_data
      .AddWrite("ack-connect-udp-response",
                ConstructClientAckPacket(to_proxy_packet_num++,
                                         from_proxy_packet_num - 1,
                                         from_proxy_packet_num - 1))
      .Sync();

  socket_data
      .AddWrite("endpoint-initial-client-settings",
                client_maker_->Packet(to_proxy_packet_num++)
                    .AddMessageFrame(ConstructH3Datagram(
                        GetNthClientInitiatedBidirectionalStreamId(0), 0,
                        to_endpoint_maker.MakeInitialSettingsPacket(
                            to_endpoint_packet_num++)))
                    .Build())
      .Sync();

  socket_data
      .AddWrite(
          "get-request-to-ep",
          client_maker_->Packet(to_proxy_packet_num++)
              .AddMessageFrame(ConstructH3Datagram(
                  GetNthClientInitiatedBidirectionalStreamId(0), 0,
                  to_endpoint_maker.MakeRequestHeadersPacket(
                      to_endpoint_packet_num++,
                      GetNthClientInitiatedBidirectionalStreamId(0), true,
                      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY),
                      GetRequestHeaders("GET", "https", "/",
                                        &to_endpoint_maker),
                      nullptr,
                      /*should_include_priority_frame=*/true)))
              .Build())
```