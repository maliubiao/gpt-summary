Response:
The user wants to understand the functionality of the given C++ code file `http_stream_factory_unittest.cc`. They are particularly interested in:

1. **Functionality of the code:** What does this code do?
2. **Relationship with JavaScript:** Does this code interact with JavaScript? If so, how?
3. **Logic and Input/Output:** If the code performs logical operations, what are some example inputs and expected outputs?
4. **Common User Errors:** What are some typical mistakes users or programmers might make related to this code?
5. **User Interaction for Debugging:** How can a user's actions lead to this code being executed, especially for debugging purposes?
6. **Summary of Functionality:**  A concise summary of the code's purpose.

Based on the code, it appears to be a unit test file for `HttpStreamFactory`. The tests focus on verifying the behavior of the `HttpStreamFactory` in various scenarios, particularly related to:

* **SPDY and QUIC session management:** Testing how sessions are created, reused, and pooled.
* **IP Pooling:** Verifying that connections to the same IP address can share sessions, even with different hostnames or DNS aliases.
* **Alternative Services (Alt-Svc):** Checking how the factory handles and processes Alt-Svc headers to discover and use alternative protocols like HTTP/2 and QUIC.
* **DNS Aliases:** Ensuring that the factory correctly handles DNS aliases when deciding whether to reuse connections.
* **Happy Eyeballs V3:**  Testing the impact of the Happy Eyeballs V3 feature on connection grouping.

Here's a breakdown of how to address each of the user's requests:

**1. Functionality of the code:** Describe the purpose of the tests, focusing on the areas mentioned above.

**2. Relationship with JavaScript:** Explain that this C++ code is part of the browser's network stack and doesn't directly interact with JavaScript in the same way a webpage script does. However, the functionality tested *enables* features that JavaScript uses. Provide examples of JavaScript APIs that rely on the underlying network stack.

**3. Logic and Input/Output:**  For the IP pooling and Alt-Svc tests, create simple scenarios with:
    * **Input:**  Describe the setup, including the URLs being requested and the state of the `HttpNetworkSession`.
    * **Output:**  Specify the expected number of sessions created, whether sessions are reused, and the DNS aliases associated with the streams.

**4. Common User Errors:**  Think about scenarios where a developer might misconfigure server settings or use the network APIs incorrectly, leading to unexpected behavior related to session reuse or Alt-Svc.

**5. User Interaction for Debugging:** Describe the steps a user might take in a browser that would trigger network requests handled by `HttpStreamFactory`. Focus on actions that could lead to observing the behaviors being tested, such as visiting websites with different protocols or using developer tools.

**6. Summary of Functionality:**  Provide a concise summary that captures the main goals of the unit tests.
这是Chromium网络栈中 `net/http/http_stream_factory_unittest.cc` 文件的最后一部分，主要延续了之前部分的功能测试，侧重于 `HttpStreamFactory` 在特定场景下的行为验证，特别是关于 **IP 连接池化** 和 **Alternative Services (Alt-Svc)** 的处理。

**功能列举:**

1. **Spdy (HTTP/2) IP 连接池化与 DNS 别名:**
   - 测试当多个主机名解析到相同的 IP 地址时，`HttpStreamFactory` 是否能正确地重用已建立的 SPDY 会话。
   - 验证在 IP 连接池化场景下，DNS 别名（`dns_aliases`）是否被正确地关联到相应的 HTTP 流。
   - 涵盖了在启用和禁用 `HappyEyeballsV3` 特性时的不同行为。

2. **QUIC IP 连接池化与 DNS 别名:**
   - 类似于 SPDY 的测试，但针对 QUIC 协议。
   - 验证当多个主机名解析到相同的 IP 地址时，`HttpStreamFactory` 是否能正确地重用已建立的 QUIC 会话。
   - 确认 DNS 别名在 QUIC 连接池化中也能正确关联。

3. **处理 Alternative Services (Alt-Svc):**
   - 测试 `HttpStreamFactory` 如何解析和处理 `Alt-Svc` 响应头，以发现服务器支持的替代协议（如 HTTP/2 或 QUIC）。
   - 验证当接收到空的 `Alt-Svc` 头时，是否会清除已知的替代服务信息。
   - 测试 `clear` 指令是否能清除指定源的替代服务信息。
   - 验证对 QUIC over IETF (h3) 格式的 `Alt-Svc` 头的解析和处理。
   - 验证对 HTTP/2 (h2) 格式的 `Alt-Svc` 头的解析和处理。

**与 JavaScript 的关系:**

虽然此 C++ 代码本身不直接包含 JavaScript 代码，但它所测试的功能是浏览器网络栈的核心部分，**直接影响** JavaScript 中发起的网络请求的行为和性能。

**举例说明:**

当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起 HTTPS 请求时，`HttpStreamFactory` 负责：

1. **连接建立:**  如果服务器支持 HTTP/2 或 QUIC，并且在之前的交互中通过 `Alt-Svc` 头知晓了这些信息，`HttpStreamFactory` 可能会选择使用这些更高效的协议建立连接。
2. **连接复用:** 如果请求的目标主机与之前请求的主机解析到相同的 IP 地址，`HttpStreamFactory` 会尝试重用已建立的连接（SPDY 或 QUIC 会话）。

**假设输入与输出 (逻辑推理):**

**场景 1: SpdyIPPoolingWithDnsAliases**

* **假设输入:**
    * DNS 配置使得 `a.example.org`, `b.example.org`, `c.example.org` 都解析到 `127.0.0.1`。
    * `a.example.org` 有 DNS 别名 `alias1`, `alias2`。
    * `b.example.org` 有 DNS 别名 `b.com`, `b.org`, `b.net`。
    * `c.example.org` 没有额外的 DNS 别名。
    * 依次发起对 `https://a.example.org`, `https://b.example.org`, `https://c.example.org` 的请求。
* **预期输出:**
    * 只会建立一个底层的 SPDY 会话，因为它们解析到相同的 IP。
    * 每个请求的 `HttpStream` 对象会关联各自的 DNS 别名集合。

**场景 2: ProcessAlternativeServicesTest - ProcessAltSvcQuicIetf**

* **假设输入:**
    * 服务器响应头包含 `Alt-Svc: h3-29=":443", h3-Q050=":443", h3-Q043=":443"`。
* **预期输出:**
    * `HttpServerProperties` 将存储 `example.com:443` 支持 QUIC/h3，并记录支持的版本为 Draft 29 (h3-29)。由于代码中 `quic_context_.params()->supported_versions` 限制，其他版本不会被记录。

**用户或编程常见的使用错误:**

1. **服务器 `Alt-Svc` 配置错误:**  服务器管理员可能会错误地配置 `Alt-Svc` 头，例如指定了错误的端口号或协议名称，导致浏览器无法正确发现或使用替代服务。
   * **例子:**  `Alt-Svc: h2=":80"` (HTTPS 站点不应该在 80 端口提供 HTTP/2)。
2. **客户端网络配置问题:**  客户端的网络环境可能阻止连接到 `Alt-Svc` 头中指定的端口或协议，导致连接失败。
3. **中间代理干扰:**  一些中间代理可能会剥离或修改 `Alt-Svc` 头，导致客户端无法获取正确的替代服务信息。
4. **忽略 DNS 解析的影响:**  开发者可能没有意识到 IP 连接池化依赖于 DNS 解析结果，如果 DNS 配置不当，可能导致连接无法复用。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，例如 `https://a.example.org`。**
2. **浏览器首先进行 DNS 查询，解析 `a.example.org` 的 IP 地址。**
3. **浏览器
Prompt: 
```
这是目录为net/http/http_stream_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能

"""
IORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester4.stream_done());
  EXPECT_FALSE(requester4.websocket_stream());
  ASSERT_TRUE(requester4.stream());

  // Verify the session pool reused the second session.  This will fail unless
  // the session pool supports multiple sessions aliasing a single IP.
  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  expected_group_count =
      base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ? 4 : 2;
  EXPECT_EQ(
      expected_group_count,
      GetPoolGroupCount(session.get(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                        ProxyChain::Direct()));
  EXPECT_EQ(2, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
}

TEST_P(HttpStreamFactoryTest, SpdyIPPoolingWithDnsAliases) {
  SpdySessionDependencies session_deps;

  const std::set<std::string> kDnsAliasesA({"alias1", "alias2"});
  const std::set<std::string> kDnsAliasesB({"b.com", "b.org", "b.net"});
  const std::string kHostnameC("c.example.org");

  session_deps.host_resolver->rules()->AddIPLiteralRuleWithDnsAliases(
      "a.example.org", "127.0.0.1", kDnsAliasesA);
  session_deps.host_resolver->rules()->AddIPLiteralRuleWithDnsAliases(
      "b.example.org", "127.0.0.1", kDnsAliasesB);
  session_deps.host_resolver->rules()->AddIPLiteralRuleWithDnsAliases(
      "c.example.org", "127.0.0.1", /*dns_aliases=*/std::set<std::string>());

  // Prepare for an HTTPS connect.
  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  // Load cert for *.example.org
  ssl_socket_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Create three HttpRequestInfos, differing only in host name.
  // All three will resolve to 127.0.0.1 and hence be IP aliases.
  HttpRequestInfo request_info_a;
  request_info_a.method = "GET";
  request_info_a.url = GURL("https://a.example.org");
  request_info_a.privacy_mode = PRIVACY_MODE_DISABLED;
  request_info_a.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpRequestInfo request_info_b = request_info_a;
  HttpRequestInfo request_info_c = request_info_a;
  request_info_b.url = GURL("https://b.example.org");
  request_info_c.url = GURL("https://c.example.org");

  // Open one session.
  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info_a, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_FALSE(requester1.websocket_stream());
  ASSERT_TRUE(requester1.stream());
  EXPECT_EQ(kDnsAliasesA, requester1.stream()->GetDnsAliases());

  // Verify just one session created.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_EQ(1, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Open a session that IP aliases first session.
  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info_b, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester2.stream_done());
  EXPECT_FALSE(requester2.websocket_stream());
  ASSERT_TRUE(requester2.stream());
  EXPECT_EQ(kDnsAliasesB, requester2.stream()->GetDnsAliases());

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  // When HappyEyeballsV3 is enabled, we create separate groups based on the
  // destination, even when the underlying connections share the same session.
  int expected_group_count =
      base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ? 2 : 1;
  EXPECT_EQ(
      expected_group_count,
      GetPoolGroupCount(session.get(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                        ProxyChain::Direct()));
  EXPECT_EQ(1, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Open another session that IP aliases the first session.
  StreamRequester requester3(session.get());
  requester3.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info_c, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester3.stream_done());
  EXPECT_FALSE(requester3.websocket_stream());
  ASSERT_TRUE(requester3.stream());
  EXPECT_THAT(requester3.stream()->GetDnsAliases(), ElementsAre(kHostnameC));

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  expected_group_count =
      base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ? 3 : 1;
  EXPECT_EQ(
      expected_group_count,
      GetPoolGroupCount(session.get(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                        ProxyChain::Direct()));
  EXPECT_EQ(1, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Clear host resolver rules to ensure that cached values for DNS aliases
  // are used.
  session_deps.host_resolver->rules()->ClearRules();

  // Re-request the original resource using `request_info_a`, which had
  // non-default DNS aliases.
  StreamRequester requester4(session.get());
  requester4.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info_a, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester4.stream_done());
  EXPECT_FALSE(requester4.websocket_stream());
  ASSERT_TRUE(requester4.stream());
  EXPECT_EQ(kDnsAliasesA, requester4.stream()->GetDnsAliases());

  // Verify the session pool reused the first session and no new session is
  // created.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  expected_group_count =
      base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ? 3 : 1;
  EXPECT_EQ(
      expected_group_count,
      GetPoolGroupCount(session.get(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                        ProxyChain::Direct()));
  EXPECT_EQ(1, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Re-request a resource using `request_info_b`, which had non-default DNS
  // aliases.
  StreamRequester requester5(session.get());
  requester5.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info_b, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester5.stream_done());
  EXPECT_FALSE(requester5.websocket_stream());
  ASSERT_TRUE(requester5.stream());
  EXPECT_EQ(kDnsAliasesB, requester5.stream()->GetDnsAliases());

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  expected_group_count =
      base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ? 3 : 1;
  EXPECT_EQ(
      expected_group_count,
      GetPoolGroupCount(session.get(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                        ProxyChain::Direct()));
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Re-request a resource using `request_info_c`, which had only the default
  // DNS alias (the host name).
  StreamRequester requester6(session.get());
  requester6.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info_c, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester6.stream_done());
  EXPECT_FALSE(requester6.websocket_stream());
  ASSERT_TRUE(requester6.stream());
  EXPECT_THAT(requester6.stream()->GetDnsAliases(), ElementsAre(kHostnameC));

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  expected_group_count =
      base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ? 3 : 1;
  EXPECT_EQ(
      expected_group_count,
      GetPoolGroupCount(session.get(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                        ProxyChain::Direct()));
  EXPECT_EQ(1, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
}

TEST_P(HttpStreamFactoryBidirectionalQuicTest, QuicIPPoolingWithDnsAliases) {
  const GURL kUrlA("https://a.example.org");
  const GURL kUrlB("https://b.example.org");
  const GURL kUrlC("https://c.example.org");
  const std::set<std::string> kDnsAliasesA({"alias1", "alias2"});
  const std::set<std::string> kDnsAliasesB({"b.com", "b.org", "b.net"});

  host_resolver()->rules()->AddIPLiteralRuleWithDnsAliases(
      kUrlA.host(), "127.0.0.1", kDnsAliasesA);
  host_resolver()->rules()->AddIPLiteralRuleWithDnsAliases(
      kUrlB.host(), "127.0.0.1", kDnsAliasesB);
  host_resolver()->rules()->AddIPLiteralRuleWithDnsAliases(
      kUrlC.host(), "127.0.0.1",
      /*dns_aliases=*/std::set<std::string>());

  // Prepare mock QUIC data for a first session establishment.
  MockQuicData mock_quic_data(version());
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  size_t spdy_headers_frame_length;
  int packet_num = 1;
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_packet_maker().MakeInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_packet_maker().MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          /*fin=*/true, priority,
          client_packet_maker().GetRequestHeaders("GET", "https", "/"),
          &spdy_headers_frame_length));
  size_t spdy_response_headers_frame_length;
  mock_quic_data.AddRead(
      ASYNC, server_packet_maker().MakeResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0),
                 /*fin=*/true, server_packet_maker().GetResponseHeaders("200"),
                 &spdy_response_headers_frame_length));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory());

  // Add hanging data for http job.
  auto hanging_data = std::make_unique<StaticSocketDataProvider>();
  MockConnect hanging_connect(SYNCHRONOUS, ERR_IO_PENDING);
  hanging_data->set_connect_data(hanging_connect);
  socket_factory().AddSocketDataProvider(hanging_data.get());
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl_data);

  // Set up QUIC as alternative_service.
  Initialize();
  AddQuicAlternativeService(url::SchemeHostPort(kUrlA), kUrlA.host());
  AddQuicAlternativeService(url::SchemeHostPort(kUrlB), kUrlB.host());
  AddQuicAlternativeService(url::SchemeHostPort(kUrlC), kUrlC.host());

  // Create three HttpRequestInfos, differing only in host name.
  // All three will resolve to 127.0.0.1 and hence be IP aliases.
  HttpRequestInfo request_info_a;
  request_info_a.method = "GET";
  request_info_a.url = kUrlA;
  request_info_a.privacy_mode = PRIVACY_MODE_DISABLED;
  request_info_a.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpRequestInfo request_info_b = request_info_a;
  HttpRequestInfo request_info_c = request_info_a;
  request_info_b.url = kUrlB;
  request_info_c.url = kUrlC;

  // Open one session.
  StreamRequester requester1(session());
  requester1.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info_a, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_FALSE(requester1.websocket_stream());
  ASSERT_TRUE(requester1.stream());
  EXPECT_EQ(kDnsAliasesA, requester1.stream()->GetDnsAliases());

  // Verify just one session created.
  EXPECT_EQ(1, GetQuicSessionCount(session()));
  EXPECT_EQ(kProtoQUIC, requester1.request()->negotiated_protocol());

  // Create a request that will alias and reuse the first session.
  StreamRequester requester2(session());
  requester2.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info_b, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester2.stream_done());
  EXPECT_FALSE(requester2.websocket_stream());
  ASSERT_TRUE(requester2.stream());
  EXPECT_EQ(kDnsAliasesB, requester2.stream()->GetDnsAliases());

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(1, GetQuicSessionCount(session()));
  EXPECT_EQ(kProtoQUIC, requester2.request()->negotiated_protocol());

  // Create another request that will alias and reuse the first session.
  StreamRequester requester3(session());
  requester3.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info_c, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester3.stream_done());
  EXPECT_FALSE(requester3.websocket_stream());
  ASSERT_TRUE(requester3.stream());
  EXPECT_THAT(requester3.stream()->GetDnsAliases(), ElementsAre(kUrlC.host()));

  // Clear the host resolve rules to ensure that we are using cached info.
  host_resolver()->rules()->ClearRules();

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(1, GetQuicSessionCount(session()));
  EXPECT_EQ(kProtoQUIC, requester3.request()->negotiated_protocol());

  // Create a request that will reuse the first session.
  StreamRequester requester4(session());
  requester4.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info_a, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester4.stream_done());
  EXPECT_FALSE(requester4.websocket_stream());
  ASSERT_TRUE(requester4.stream());
  EXPECT_EQ(kDnsAliasesA, requester4.stream()->GetDnsAliases());

  // Verify the session pool reused the first session and no new session is
  // created.
  EXPECT_EQ(1, GetQuicSessionCount(session()));
  EXPECT_EQ(kProtoQUIC, requester4.request()->negotiated_protocol());

  // Create another request that will alias and reuse the first session.
  StreamRequester requester5(session());
  requester5.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info_b, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester5.stream_done());
  EXPECT_FALSE(requester5.websocket_stream());
  ASSERT_TRUE(requester5.stream());
  EXPECT_EQ(kDnsAliasesB, requester5.stream()->GetDnsAliases());

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(1, GetQuicSessionCount(session()));
  EXPECT_EQ(kProtoQUIC, requester5.request()->negotiated_protocol());

  // Create another request that will alias and reuse the first session.
  StreamRequester requester6(session());
  requester6.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info_c, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester6.stream_done());
  EXPECT_FALSE(requester6.websocket_stream());
  ASSERT_TRUE(requester6.stream());
  EXPECT_THAT(requester6.stream()->GetDnsAliases(), ElementsAre(kUrlC.host()));

  // Verify the session pool reused the first session and no new session is
  // created. This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(1, GetQuicSessionCount(session()));
  EXPECT_EQ(kProtoQUIC, requester6.request()->negotiated_protocol());
}

class ProcessAlternativeServicesTest : public TestWithTaskEnvironment {
 public:
  ProcessAlternativeServicesTest() {
    session_params_.enable_quic = true;

    session_context_.proxy_resolution_service = proxy_resolution_service_.get();
    session_context_.host_resolver = &host_resolver_;
    session_context_.cert_verifier = &cert_verifier_;
    session_context_.transport_security_state = &transport_security_state_;
    session_context_.client_socket_factory = &socket_factory_;
    session_context_.ssl_config_service = &ssl_config_service_;
    session_context_.http_user_agent_settings = &http_user_agent_settings_;
    session_context_.http_server_properties = &http_server_properties_;
    session_context_.quic_context = &quic_context_;
  }

 private:
  // Parameters passed in the NetworkSessionContext must outlive the
  // HttpNetworkSession.
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service_ =
      ConfiguredProxyResolutionService::CreateDirect();
  SSLConfigServiceDefaults ssl_config_service_;
  StaticHttpUserAgentSettings http_user_agent_settings_ = {"*", "test-ua"};
  MockClientSocketFactory socket_factory_;
  MockHostResolver host_resolver_;
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;

 protected:
  HttpServerProperties http_server_properties_;
  QuicContext quic_context_;
  HttpNetworkSessionParams session_params_;
  HttpNetworkSessionContext session_context_;
  std::unique_ptr<HttpNetworkSession> session_;
};

TEST_F(ProcessAlternativeServicesTest, ProcessEmptyAltSvc) {
  session_ =
      std::make_unique<HttpNetworkSession>(session_params_, session_context_);
  url::SchemeHostPort origin;
  NetworkAnonymizationKey network_anonymization_key;

  auto headers = base::MakeRefCounted<HttpResponseHeaders>("");

  session_->http_stream_factory()->ProcessAlternativeServices(
      session_.get(), network_anonymization_key, headers.get(), origin);

  AlternativeServiceInfoVector alternatives =
      http_server_properties_.GetAlternativeServiceInfos(
          origin, network_anonymization_key);
  EXPECT_TRUE(alternatives.empty());
}

TEST_F(ProcessAlternativeServicesTest, ProcessAltSvcClear) {
  session_ =
      std::make_unique<HttpNetworkSession>(session_params_, session_context_);
  url::SchemeHostPort origin(url::kHttpsScheme, "example.com", 443);

  auto network_anonymization_key = NetworkAnonymizationKey::CreateSameSite(
      SchemefulSite(GURL("https://example.com")));

  http_server_properties_.SetAlternativeServices(
      origin, network_anonymization_key,
      {AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          {kProtoQUIC, "", 443}, base::Time::Now() + base::Seconds(30),
          quic::AllSupportedVersions())});

  EXPECT_FALSE(
      http_server_properties_
          .GetAlternativeServiceInfos(origin, network_anonymization_key)
          .empty());

  auto headers = base::MakeRefCounted<HttpResponseHeaders>("");
  headers->AddHeader("alt-svc", "clear");

  session_->http_stream_factory()->ProcessAlternativeServices(
      session_.get(), network_anonymization_key, headers.get(), origin);

  AlternativeServiceInfoVector alternatives =
      http_server_properties_.GetAlternativeServiceInfos(
          origin, network_anonymization_key);
  EXPECT_TRUE(alternatives.empty());
}

TEST_F(ProcessAlternativeServicesTest, ProcessAltSvcQuicIetf) {
  quic_context_.params()->supported_versions = quic::AllSupportedVersions();
  session_ =
      std::make_unique<HttpNetworkSession>(session_params_, session_context_);
  url::SchemeHostPort origin(url::kHttpsScheme, "example.com", 443);

  auto network_anonymization_key = NetworkAnonymizationKey::CreateSameSite(
      SchemefulSite(GURL("https://example.com")));

  auto headers = base::MakeRefCounted<HttpResponseHeaders>("");
  headers->AddHeader("alt-svc",
                     "h3-29=\":443\","
                     "h3-Q050=\":443\","
                     "h3-Q043=\":443\"");

  session_->http_stream_factory()->ProcessAlternativeServices(
      session_.get(), network_anonymization_key, headers.get(), origin);

  quic::ParsedQuicVersionVector versions = {
      quic::ParsedQuicVersion::Draft29(),
  };
  AlternativeServiceInfoVector alternatives =
      http_server_properties_.GetAlternativeServiceInfos(
          origin, network_anonymization_key);
  ASSERT_EQ(versions.size(), alternatives.size());
  for (size_t i = 0; i < alternatives.size(); ++i) {
    EXPECT_EQ(kProtoQUIC, alternatives[i].protocol());
    EXPECT_EQ(HostPortPair("example.com", 443),
              alternatives[i].host_port_pair());
    EXPECT_EQ(1u, alternatives[i].advertised_versions().size());
    EXPECT_EQ(versions[i], alternatives[i].advertised_versions()[0]);
  }
}

TEST_F(ProcessAlternativeServicesTest, ProcessAltSvcHttp2) {
  quic_context_.params()->supported_versions = quic::AllSupportedVersions();
  session_ =
      std::make_unique<HttpNetworkSession>(session_params_, session_context_);
  url::SchemeHostPort origin(url::kHttpsScheme, "example.com", 443);

  auto network_anonymization_key = NetworkAnonymizationKey::CreateSameSite(
      SchemefulSite(GURL("https://example.com")));

  auto headers = base::MakeRefCounted<HttpResponseHeaders>("");
  headers->AddHeader("alt-svc", "h2=\"other.example.com:443\"");

  session_->http_stream_factory()->ProcessAlternativeServices(
      session_.get(), network_anonymization_key, headers.get(), origin);

  AlternativeServiceInfoVector alternatives =
      http_server_properties_.GetAlternativeServiceInfos(
          origin, network_anonymization_key);
  ASSERT_EQ(1u, alternatives.size());
  EXPECT_EQ(kProtoHTTP2, alternatives[0].protocol());
  EXPECT_EQ(HostPortPair("other.example.com", 443),
            alternatives[0].host_port_pair());
  EXPECT_EQ(0u, alternatives[0].advertised_versions().size());
}

}  // namespace

}  // namespace net::test

"""


```