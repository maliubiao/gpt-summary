Response:
The user wants a summary of the provided C++ code snippet, which is a unit test file for Chromium's networking stack, specifically for the `TransportClientSocketPool`.

I need to:
1. **Identify the main purpose of the code:** It tests the functionality of the `TransportClientSocketPool`.
2. **List the specific features being tested:**  The code includes tests for handling connection failures, authentication challenges over HTTP/2, HTTP tunnel redirects, and the usage of Network Anonymization Keys (NAK) in different proxy scenarios. It also tests the `HasActiveSocket` method and socket tagging.
3. **Check for JavaScript relevance:**  While the code itself is C++, it interacts with network requests, which are often initiated by JavaScript in a browser context.
4. **Identify logical deductions and provide examples:** Several tests involve setting up specific scenarios and asserting expected outcomes.
5. **Point out potential user or programming errors:**  The tests implicitly highlight scenarios that could lead to errors.
6. **Explain how a user might reach this code:**  This involves outlining the sequence of user actions that trigger the networking code being tested.
7. **Synthesize the information into a concise summary, as this is part 3 of 4.**

**Plan:**

1. Start with a high-level summary of the file's purpose.
2. Detail the functionalities tested in each test case.
3. Analyze the connection to JavaScript.
4. Extract assumptions, inputs, and outputs for the logical deductions.
5. Identify common user errors highlighted by the tests.
6. Describe user interactions that might lead to these code paths.
7. Consolidate the above points into a part 3 summary.
好的，这是 `net/socket/transport_client_socket_pool_unittest.cc` 文件的第三部分，它主要包含了以下功能测试：

**功能归纳：**

*   **处理连接失败的场景 (SpdyStream 销毁)：** 测试在高优先级请求创建 `SpdyStream` 后连接失败，导致 `SpdyStream` 被销毁，并且此失败会临时分配给低优先级请求时，不会发生空指针解引用的情况。
*   **处理 HTTP/2 代理认证挑战 (SpdyAuthOneConnectJobTwoRequests):** 测试在使用 HTTP/2 代理时，当收到代理认证挑战并且存在两个等待连接到 socket pool 的请求时，只有一个 `ConnectJob` 的情况下，代码能否正常处理，避免崩溃。
*   **处理 HTTP 隧道建立时的重定向 (HttpTunnelSetupRedirect):** 测试当通过 HTTP 代理建立隧道时，如果代理返回 302 重定向响应，`TransportClientSocketPool` 会如何处理。预期是会拒绝这种重定向，因为不信任 `CONNECT` 请求的 302 响应。
*   **测试网络匿名化密钥 (NetworkAnonymizationKey):**
    *   测试在没有代理的情况下，`TransportClientSocketPool` 如何使用 `NetworkAnonymizationKey` 进行 DNS 解析。
    *   测试在使用 HTTP 代理时，无论传入的 `NetworkAnonymizationKey` 如何，用于解析代理主机名的 `NetworkAnonymizationKey` 都是相同的临时密钥。
    *   测试在使用 HTTPS 代理时，无论传入的 `NetworkAnonymizationKey` 如何，用于解析代理主机名的 `NetworkAnonymizationKey` 都是相同的临时密钥。
    *   测试在使用 SOCKS4 代理时，用于解析目标主机名的 DNS 请求会使用传入的 `NetworkAnonymizationKey`，而用于解析代理主机名的 DNS 请求使用相同的临时密钥。
    *   测试在使用 SOCKS5 代理时，用于解析目标主机名的 DNS 请求会使用传入的 `NetworkAnonymizationKey`，而用于解析代理主机名的 DNS 请求使用相同的临时密钥。
*   **测试 `HasActiveSocket` 方法:** 测试 `HasActiveSocket` 方法在 socket pool 中是否存在活跃 socket 时的返回值是否正确，包括连接中、已连接、空闲等状态。
*   **测试 SocketTag 的应用 (Tag):** 测试传递给 `TransportClientSocketPool` 的 `SocketTag` 能否正确应用到返回的 socket 上，包括新建 socket 和复用 socket 的情况。

**与 JavaScript 的关系及举例说明：**

尽管这段代码是 C++，但它直接服务于网络请求的处理，而网络请求通常由 JavaScript 在浏览器环境中发起。

*   **发起 HTTPS 请求:** 当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求时，浏览器网络栈会使用 `TransportClientSocketPool` 来管理底层的 socket 连接。例如：
    ```javascript
    fetch('https://example.com/data');
    ```
*   **通过 HTTP 代理发起请求:** 如果用户配置了 HTTP 代理，当 JavaScript 发起网络请求时，`TransportClientSocketPool` 会负责建立到代理服务器的连接，并发送 `CONNECT` 请求建立隧道。
    ```javascript
    fetch('https://target.com/resource', {
      // ...
    });
    ```
*   **使用带有凭据的代理:** 如果代理需要身份验证，当 JavaScript 发起请求时，`TransportClientSocketPool` 可能会收到代理服务器返回的 407 状态码，并触发认证流程。
*   **涉及网络隔离的功能:** 如果浏览器启用了网络隔离功能，例如使用不同的 `NetworkAnonymizationKey`，当 JavaScript 发起请求时，`TransportClientSocketPool` 会使用相应的密钥来管理连接，确保不同上下文的请求使用不同的连接。

**逻辑推理、假设输入与输出：**

**示例 1：处理连接失败的场景 (SpdyStream 销毁)**

*   **假设输入:**
    1. 尝试连接到一个 HTTPS 站点 (`kEndpoint`)，使用 HTTP/2 协议。
    2. 第一次连接尝试在创建 `SpdyStream` 后失败（模拟网络错误）。
    3. 同时发起第二个到相同站点的低优先级连接请求。
*   **逻辑推理:**
    *   第一次连接失败会导致 `SpdyStream` 被销毁。
    *   因为连接失败，该连接的 `ConnectJob` 可能会被临时分配给第二个请求。
    *   代码需要确保在这个临时分配和随后的优先级调整过程中，不会因为 `SpdyStream` 已经被销毁而发生空指针解引用。
*   **预期输出:**
    *   第一个请求返回 `ERR_FAILED` 错误。
    *   第二个请求因为后续的模拟连接超时返回 `ERR_PROXY_CONNECTION_FAILED` 错误（这个是辅助验证，不是主要关注点）。
    *   程序不会崩溃。

**示例 2：测试网络匿名化密钥 (NetworkAnonymizationKeyHttpProxy)**

*   **假设输入:**
    1. 用户配置了一个 HTTP 代理 `"http://proxy.test"`。
    2. 发起两个到 `"bar.test"` 的 HTTP 请求。
    3. 这两个请求分别携带不同的 `NetworkAnonymizationKey` (`kNetworkAnonymizationKey1` 和 `kNetworkAnonymizationKey2`)。
*   **逻辑推理:**
    *   对于 HTTP 代理，用于解析代理服务器主机名的 DNS 查询应该使用相同的临时 `NetworkAnonymizationKey`，而不是请求携带的 NAK。
*   **预期输出:**
    *   `HostResolver` 会收到两个 DNS 查询请求，目标都是代理服务器的主机名 (`proxy.test`)。
    *   这两个 DNS 查询请求携带相同的临时 `NetworkAnonymizationKey`。

**用户或编程常见的使用错误：**

*   **在高优先级请求连接失败后，没有正确处理可能被销毁的资源：**  例如在 `SpdyStream` 已经被销毁的情况下，仍然尝试访问该对象，可能导致程序崩溃。这个测试 (SpdyStream 销毁) 就是为了防止这种情况发生。
*   **在处理代理认证挑战时，没有考虑到并发请求的情况：** 如果没有正确管理 `ConnectJob` 和等待连接的请求，可能会导致资源竞争或错误的状态。
*   **信任 HTTP `CONNECT` 请求的 302 重定向：**  `TransportClientSocketPool` 默认不信任这种重定向，因为存在安全风险。如果开发者错误地信任这种重定向，可能会导致安全漏洞。
*   **不理解 `NetworkAnonymizationKey` 在代理场景下的行为：** 开发者可能错误地认为在使用代理时，会直接使用请求携带的 `NetworkAnonymizationKey` 进行所有 DNS 查询，而实际上对于代理服务器的解析会使用临时密钥。
*   **没有正确设置或更新 `SocketTag`：**  如果开发者忘记在 socket 复用时更新 `SocketTag`，可能会导致流量统计错误或网络策略应用错误。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入一个 HTTPS 网址并访问 (例如：`https://example.com`)。** 这会触发一个需要建立安全连接的请求。
2. **如果用户设置了 HTTP 代理，浏览器会尝试通过代理连接到目标网站。** 这会涉及到发送 `CONNECT` 请求建立 HTTP 隧道。
3. **如果代理服务器返回 302 重定向响应 (不常见但可能发生)，`TransportClientSocketPool` 的代码会被调用来处理这个重定向。**
4. **如果代理服务器需要身份验证，并且返回 407 状态码，`TransportClientSocketPool` 会处理认证流程。**  在高并发场景下，可能会有多个请求同时等待连接，这时就会触发 `SpdyAuthOneConnectJobTwoRequests` 测试覆盖的代码路径。
5. **如果网络连接不稳定，或者服务器出现错误，可能会导致连接在 `SpdyStream` 创建后失败，触发 `SpdyStream` 销毁相关的代码路径。**
6. **浏览器可能会在不同的安全上下文下发起网络请求，例如来自不同的 iframe 或扩展程序。**  这会导致使用不同的 `NetworkAnonymizationKey`，`TransportClientSocketPool` 会根据这些密钥来隔离连接。
7. **开发者可能会使用 `chrome://net-internals` 工具来查看网络连接的状态，这会涉及到读取 `TransportClientSocketPool` 中维护的信息。**
8. **在 Android 系统上，当应用发起网络请求时，可能会设置 `SocketTag` 来进行流量统计或应用网络策略。**

希望以上解释能够帮助您理解这段代码的功能。

Prompt: 
```
这是目录为net/socket/transport_client_socket_pool_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
ill get an error after creating the SpdyStream.

  SpdyTestUtil spdy_util;
  spdy::SpdySerializedFrame connect(spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair::FromSchemeHostPort(kEndpoint)));

  MockWrite writes[] = {
      CreateMockWrite(connect, 0, ASYNC),
      MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_FAILED, 1),
  };

  SequencedSocketData socket_data(MockConnect(SYNCHRONOUS, OK), reads, writes);
  tagging_client_socket_factory_.AddSocketDataProvider(&socket_data);
  SSLSocketDataProvider ssl_data(SYNCHRONOUS, OK);
  ssl_data.next_proto = kProtoHTTP2;
  tagging_client_socket_factory_.AddSSLSocketDataProvider(&ssl_data);

  // Second connection also fails.  Not a vital part of this test, but allows
  // waiting for the second request to complete without too much extra code.
  SequencedSocketData socket_data2(
      MockConnect(SYNCHRONOUS, ERR_CONNECTION_TIMED_OUT),
      base::span<const MockRead>(), base::span<const MockWrite>());
  tagging_client_socket_factory_.AddSocketDataProvider(&socket_data2);
  SSLSocketDataProvider ssl_data2(SYNCHRONOUS, OK);
  tagging_client_socket_factory_.AddSSLSocketDataProvider(&ssl_data2);

  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

  ClientSocketPool::GroupId group_id(
      kEndpoint, PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);

  // Start the first connection attempt.
  TestCompletionCallback callback1;
  ClientSocketHandle handle1;
  int rv1 = handle1.Init(
      group_id, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, HIGHEST,
      SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
      callback1.callback(), ClientSocketPool::ProxyAuthCallback(), &pool,
      NetLogWithSource());
  ASSERT_THAT(rv1, IsError(ERR_IO_PENDING));

  // Create a second request with a lower priority.
  TestCompletionCallback callback2;
  ClientSocketHandle handle2;
  int rv2 = handle2.Init(
      group_id, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOWEST,
      SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
      callback2.callback(), ClientSocketPool::ProxyAuthCallback(), &pool,
      NetLogWithSource());
  ASSERT_THAT(rv2, IsError(ERR_IO_PENDING));

  // First connection fails after creating a SpdySession and a SpdyStream on
  // that session. The SpdyStream will be destroyed under the
  // SpdyProxyClientSocket. The failure will result in temporarily assigning the
  // failed ConnectJob to the second request, which results in an unneeded
  // reprioritization, which should not dereference the null SpdyStream.
  //
  // TODO(mmenke): Avoid that temporary reassignment.
  ASSERT_THAT(callback1.WaitForResult(), IsError(ERR_FAILED));

  // Second connection fails, getting a connection error.
  ASSERT_THAT(callback2.WaitForResult(), IsError(ERR_PROXY_CONNECTION_FAILED));
}

// Make sure there's no crash when an auth challenge is received over HTTP2
// and there are two pending Requests to the socket pool, with a single
// ConnectJob.
//
// See https://crbug.com/940848
TEST_F(TransportClientSocketPoolTest, SpdyAuthOneConnectJobTwoRequests) {
  const url::SchemeHostPort kEndpoint(url::kHttpsScheme,
                                      "unresolvable.host.name", 443);
  const HostPortPair kProxy("unresolvable.proxy.name", 443);

  session_deps_.host_resolver->set_synchronous_mode(true);

  // Create a socket pool which only allows a single connection at a time.
  TransportClientSocketPool pool(
      1, 1, kUnusedIdleSocketTimeout,
      ProxyUriToProxyChain("https://unresolvable.proxy.name",
                           /*default_scheme=*/ProxyServer::SCHEME_HTTP),
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  SpdyTestUtil spdy_util;
  spdy::SpdySerializedFrame connect(spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair::FromSchemeHostPort(kEndpoint)));

  MockWrite writes[] = {
      CreateMockWrite(connect, 0, ASYNC),
      MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 4),
  };

  // The proxy responds to the connect with a 407, and them an
  // ERROR_CODE_HTTP_1_1_REQUIRED.

  const char kAuthStatus[] = "407";
  const char* const kAuthChallenge[] = {
      "proxy-authenticate",
      "NTLM",
  };
  spdy::SpdySerializedFrame connect_auth_resp(spdy_util.ConstructSpdyReplyError(
      kAuthStatus, kAuthChallenge, std::size(kAuthChallenge) / 2, 1));
  spdy::SpdySerializedFrame reset(
      spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
  MockRead reads[] = {
      CreateMockRead(connect_auth_resp, 1, ASYNC),
      CreateMockRead(reset, 2, SYNCHRONOUS),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),
  };

  SequencedSocketData socket_data(MockConnect(SYNCHRONOUS, OK), reads, writes);
  tagging_client_socket_factory_.AddSocketDataProvider(&socket_data);
  SSLSocketDataProvider ssl_data(SYNCHRONOUS, OK);
  ssl_data.next_proto = kProtoHTTP2;
  tagging_client_socket_factory_.AddSSLSocketDataProvider(&ssl_data);

  // Second connection fails, and gets a different error.  Not a vital part of
  // this test, but allows waiting for the second request to complete without
  // too much extra code.
  SequencedSocketData socket_data2(
      MockConnect(SYNCHRONOUS, ERR_CONNECTION_TIMED_OUT),
      base::span<const MockRead>(), base::span<const MockWrite>());
  tagging_client_socket_factory_.AddSocketDataProvider(&socket_data2);
  SSLSocketDataProvider ssl_data2(SYNCHRONOUS, OK);
  tagging_client_socket_factory_.AddSSLSocketDataProvider(&ssl_data2);

  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

  ClientSocketPool::GroupId group_id(
      kEndpoint, PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);

  // Start the first connection attempt.
  TestCompletionCallback callback1;
  ClientSocketHandle handle1;
  base::RunLoop run_loop;
  int rv1 = handle1.Init(group_id, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS,
                         HIGHEST, SocketTag(),
                         ClientSocketPool::RespectLimits::ENABLED,
                         callback1.callback(),
                         base::BindLambdaForTesting(
                             [&](const HttpResponseInfo& response,
                                 HttpAuthController* auth_controller,
                                 base::OnceClosure restart_with_auth_callback) {
                               run_loop.Quit();
                             }),
                         &pool, NetLogWithSource());
  ASSERT_THAT(rv1, IsError(ERR_IO_PENDING));

  // Create a second request with a lower priority.
  TestCompletionCallback callback2;
  ClientSocketHandle handle2;
  int rv2 = handle2.Init(
      group_id, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOWEST,
      SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
      callback2.callback(), ClientSocketPool::ProxyAuthCallback(), &pool,
      NetLogWithSource());
  ASSERT_THAT(rv2, IsError(ERR_IO_PENDING));

  // The ConnectJob connection sees the auth challenge and HTTP2 error, which
  // causes the SpdySession to be destroyed, as well as the SpdyStream. Then the
  // ConnectJob is bound to the first request. Binding the request will result
  // in temporarily assigning the ConnectJob to the second request, which
  // results in an unneeded reprioritization, which should not dereference the
  // null SpdyStream.
  //
  // TODO(mmenke): Avoid that temporary reassignment.
  run_loop.Run();

  // Just tear down everything without continuing - there are other tests for
  // auth over HTTP2.
}

TEST_F(TransportClientSocketPoolTest, HttpTunnelSetupRedirect) {
  const url::SchemeHostPort kEndpoint(url::kHttpsScheme, "host.test", 443);

  const std::string kRedirectTarget = "https://some.other.host.test/";

  const std::string kResponseText =
      "HTTP/1.1 302 Found\r\n"
      "Location: " +
      kRedirectTarget +
      "\r\n"
      "Set-Cookie: foo=bar\r\n"
      "\r\n";

  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    for (bool use_https_proxy : {false, true}) {
      SCOPED_TRACE(use_https_proxy);

      TransportClientSocketPool proxy_pool(
          kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout,
          ProxyUriToProxyChain(
              use_https_proxy ? "https://proxy.test" : "http://proxy.test",
              /*default_scheme=*/ProxyServer::SCHEME_HTTP),
          /*is_for_websockets=*/false,
          tagging_common_connect_job_params_.get());

      MockWrite writes[] = {
          MockWrite(ASYNC, 0,
                    "CONNECT host.test:443 HTTP/1.1\r\n"
                    "Host: host.test:443\r\n"
                    "Proxy-Connection: keep-alive\r\n"
                    "User-Agent: test-ua\r\n\r\n"),
      };
      MockRead reads[] = {
          MockRead(ASYNC, 1, kResponseText.c_str()),
      };

      SequencedSocketData data(reads, writes);
      tagging_client_socket_factory_.AddSocketDataProvider(&data);
      SSLSocketDataProvider ssl(ASYNC, OK);
      tagging_client_socket_factory_.AddSSLSocketDataProvider(&ssl);

      ClientSocketHandle handle;
      TestCompletionCallback callback;

      scoped_refptr<ClientSocketPool::SocketParams> socket_params =
          base::MakeRefCounted<ClientSocketPool::SocketParams>(
              /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

      int rv = handle.Init(
          ClientSocketPool::GroupId(
              kEndpoint, PrivacyMode::PRIVACY_MODE_DISABLED,
              NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
              /*disable_cert_network_fetches=*/false),
          socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
          ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
          ClientSocketPool::ProxyAuthCallback(), &proxy_pool,
          NetLogWithSource());
      rv = callback.GetResult(rv);

      // We don't trust 302 responses to CONNECT.
      EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
      EXPECT_FALSE(handle.is_initialized());
    }
  }
}

TEST_F(TransportClientSocketPoolTest, NetworkAnonymizationKey) {
  const SchemefulSite kSite(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);
  const char kHost[] = "bar.test";

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_deps_.host_resolver->set_ondemand_mode(true);

  TransportClientSocketPool::GroupId group_id(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(group_id,
                  ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                  TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                  ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
                  ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                  NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, session_deps_.host_resolver->last_id());
  EXPECT_EQ(kHost, session_deps_.host_resolver->request_host(1));
  EXPECT_EQ(kNetworkAnonymizationKey,
            session_deps_.host_resolver->request_network_anonymization_key(1));
}

TEST_F(TransportClientSocketPoolTest, NetworkAnonymizationKeySsl) {
  const SchemefulSite kSite(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);
  const char kHost[] = "bar.test";

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_deps_.host_resolver->set_ondemand_mode(true);

  TransportClientSocketPool::GroupId group_id(
      url::SchemeHostPort(url::kHttpsScheme, kHost, 443),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_THAT(
      handle.Init(
          group_id,
          base::MakeRefCounted<ClientSocketPool::SocketParams>(
              /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>()),
          TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
          ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
          ClientSocketPool::ProxyAuthCallback(), pool_.get(),
          NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, session_deps_.host_resolver->last_id());
  EXPECT_EQ(kHost, session_deps_.host_resolver->request_host(1));
  EXPECT_EQ(kNetworkAnonymizationKey,
            session_deps_.host_resolver->request_network_anonymization_key(1));
}

// Test that, in the case of an HTTP proxy, the same transient
// NetworkAnonymizationKey is reused for resolving the proxy's host, regardless
// of input NAK.
TEST_F(TransportClientSocketPoolTest, NetworkAnonymizationKeyHttpProxy) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const char kHost[] = "bar.test";
  const ProxyChain kProxyChain = ProxyUriToProxyChain(
      "http://proxy.test", /*default_scheme=*/ProxyServer::SCHEME_HTTP);

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_deps_.host_resolver->set_ondemand_mode(true);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout, kProxyChain,
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  TransportClientSocketPool::GroupId group_id1(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey1,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_THAT(
      handle1.Init(group_id1,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  TransportClientSocketPool::GroupId group_id2(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey2,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_THAT(
      handle2.Init(group_id2,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  ASSERT_EQ(2u, session_deps_.host_resolver->last_id());
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(1));
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(2));
  EXPECT_TRUE(session_deps_.host_resolver->request_network_anonymization_key(1)
                  .IsTransient());
  EXPECT_EQ(session_deps_.host_resolver->request_network_anonymization_key(1),
            session_deps_.host_resolver->request_network_anonymization_key(2));
}

// Test that, in the case of an HTTPS proxy, the same transient
// NetworkAnonymizationKey is reused for resolving the proxy's host, regardless
// of input NAK.
TEST_F(TransportClientSocketPoolTest, NetworkAnonymizationKeyHttpsProxy) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const char kHost[] = "bar.test";
  const ProxyChain kProxyChain = ProxyUriToProxyChain(
      "https://proxy.test", /*default_scheme=*/ProxyServer::SCHEME_HTTP);

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_deps_.host_resolver->set_ondemand_mode(true);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout, kProxyChain,
      false /* is_for_websockets */, tagging_common_connect_job_params_.get());

  TransportClientSocketPool::GroupId group_id1(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey1,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_THAT(
      handle1.Init(group_id1,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  TransportClientSocketPool::GroupId group_id2(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey2,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_THAT(
      handle2.Init(group_id2,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  ASSERT_EQ(2u, session_deps_.host_resolver->last_id());
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(1));
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(2));
  EXPECT_TRUE(session_deps_.host_resolver->request_network_anonymization_key(1)
                  .IsTransient());
  EXPECT_EQ(session_deps_.host_resolver->request_network_anonymization_key(1),
            session_deps_.host_resolver->request_network_anonymization_key(2));
}

// Test that, in the case of a SOCKS5 proxy, the passed in
// NetworkAnonymizationKey is used for the destination DNS lookup, and the same
// transient NetworkAnonymizationKey is reused for resolving the proxy's host,
// regardless of input NAK.
TEST_F(TransportClientSocketPoolTest, NetworkAnonymizationKeySocks4Proxy) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const char kHost[] = "bar.test";
  const ProxyChain kProxyChain = ProxyUriToProxyChain(
      "socks4://proxy.test", /*default_scheme=*/ProxyServer::SCHEME_HTTP);

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_deps_.host_resolver->set_ondemand_mode(true);

  // Test will establish two connections, but never use them to transfer data,
  // since thet stall on the followup DNS lookups.
  StaticSocketDataProvider data1;
  data1.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  tagging_client_socket_factory_.AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2;
  data2.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  tagging_client_socket_factory_.AddSocketDataProvider(&data2);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout, kProxyChain,
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  TransportClientSocketPool::GroupId group_id1(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey1,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_THAT(
      handle1.Init(group_id1,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  TransportClientSocketPool::GroupId group_id2(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey2,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_THAT(
      handle2.Init(group_id2,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  // First two lookups are for the proxy's hostname, and should use the same
  // transient NAK.
  ASSERT_EQ(2u, session_deps_.host_resolver->last_id());
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(1));
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(2));
  EXPECT_TRUE(session_deps_.host_resolver->request_network_anonymization_key(1)
                  .IsTransient());
  EXPECT_EQ(session_deps_.host_resolver->request_network_anonymization_key(1),
            session_deps_.host_resolver->request_network_anonymization_key(2));

  // First two lookups completes, starting the next two, which should be for the
  // destination's hostname, and should use the passed in NAKs.
  session_deps_.host_resolver->ResolveNow(1);
  session_deps_.host_resolver->ResolveNow(2);
  ASSERT_EQ(4u, session_deps_.host_resolver->last_id());
  EXPECT_EQ(kHost, session_deps_.host_resolver->request_host(3));
  EXPECT_EQ(kNetworkAnonymizationKey1,
            session_deps_.host_resolver->request_network_anonymization_key(3));
  EXPECT_EQ(kHost, session_deps_.host_resolver->request_host(4));
  EXPECT_EQ(kNetworkAnonymizationKey2,
            session_deps_.host_resolver->request_network_anonymization_key(4));
}

// Test that, in the case of a SOCKS5 proxy, the same transient
// NetworkAnonymizationKey is reused for resolving the proxy's host, regardless
// of input NAK.
TEST_F(TransportClientSocketPoolTest, NetworkAnonymizationKeySocks5Proxy) {
  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const char kHost[] = "bar.test";
  const ProxyChain kProxyChain = ProxyUriToProxyChain(
      "socks5://proxy.test", /*default_scheme=*/ProxyServer::SCHEME_HTTP);

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_deps_.host_resolver->set_ondemand_mode(true);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout, kProxyChain,
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  TransportClientSocketPool::GroupId group_id1(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey1,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_THAT(
      handle1.Init(group_id1,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  TransportClientSocketPool::GroupId group_id2(
      url::SchemeHostPort(url::kHttpScheme, kHost, 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey2,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_THAT(
      handle2.Init(group_id2,
                   ClientSocketPool::SocketParams::CreateForHttpForTesting(),
                   TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  ASSERT_EQ(2u, session_deps_.host_resolver->last_id());
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(1));
  EXPECT_EQ(kProxyChain.First().host_port_pair().host(),
            session_deps_.host_resolver->request_host(2));
  EXPECT_TRUE(session_deps_.host_resolver->request_network_anonymization_key(1)
                  .IsTransient());
  EXPECT_EQ(session_deps_.host_resolver->request_network_anonymization_key(1),
            session_deps_.host_resolver->request_network_anonymization_key(2));
}

TEST_F(TransportClientSocketPoolTest, HasActiveSocket) {
  const url::SchemeHostPort kEndpoint1(url::kHttpScheme, "host1.test", 80);
  const url::SchemeHostPort kEndpoint2(url::kHttpScheme, "host2.test", 80);

  ClientSocketHandle handle;
  ClientSocketPool::GroupId group_id1(
      kEndpoint1, PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  ClientSocketPool::GroupId group_id2(
      kEndpoint2, PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);

  // HasActiveSocket() must return false before creating a socket.
  EXPECT_FALSE(pool_->HasActiveSocket(group_id1));

  TestCompletionCallback callback1;
  int rv1 =
      handle.Init(group_id1, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv1, IsError(ERR_IO_PENDING));

  // HasActiveSocket() must return true while connecting.
  EXPECT_TRUE(pool_->HasActiveSocket(group_id1));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  // HasActiveSocket() must return true after handed out.
  EXPECT_TRUE(pool_->HasActiveSocket(group_id1));
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());

  handle.Reset();

  // HasActiveSocket returns true for the idle socket.
  EXPECT_TRUE(pool_->HasActiveSocket(group_id1));
  // Now we should have 1 idle socket.
  EXPECT_EQ(1, pool_->IdleSocketCount());

  // HasActiveSocket() for group_id2 must still return false.
  EXPECT_FALSE(pool_->HasActiveSocket(group_id2));

  TestCompletionCallback callback2;
  int rv2 =
      handle.Init(group_id2, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv2, IsError(ERR_IO_PENDING));

  // HasActiveSocket(group_id2) must return true while connecting.
  EXPECT_TRUE(pool_->HasActiveSocket(group_id2));

  // HasActiveSocket(group_id1) must still return true.
  EXPECT_TRUE(pool_->HasActiveSocket(group_id2));

  // Close the sockets.
  pool_->FlushWithError(ERR_NETWORK_CHANGED, "Network changed");

  // HasActiveSocket() must return false after closing the socket.
  EXPECT_FALSE(pool_->HasActiveSocket(group_id1));
  EXPECT_FALSE(pool_->HasActiveSocket(group_id2));
}

// Test that SocketTag passed into TransportClientSocketPool is applied to
// returned sockets.
#if BUILDFLAG(IS_ANDROID)
TEST_F(TransportClientSocketPoolTest, Tag) {
  if (!CanGetTaggedBytes()) {
    DVLOG(0) << "Skipping test - GetTaggedBytes unsupported.";
    return;
  }

  // Start test server.
  EmbeddedTestServer test_server;
  test_server.AddDefaultHandlers(base::FilePath());
  ASSERT_TRUE(test_server.Start());

  ClientSocketHandle handle;
  int32_t tag_val1 = 0x12345678;
  SocketTag tag1(SocketTag::UNSET_UID, tag_val1);
  int32_t tag_val2 = 0x87654321;
  SocketTag tag2(getuid(), tag_val2);

  // Test socket is tagged before connected.
  uint64_t old_traffic = GetTaggedBytes(tag_val1);
  const ClientSocketPool::GroupId kGroupId(
      url::SchemeHostPort(test_server.base_url()),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  scoped_refptr<ClientSocketPool::SocketParams> params =
      ClientSocketPool::SocketParams::CreateForHttpForTesting();
  TestCompletionCallback callback;
  int rv =
      handle.Init(kGroupId, params, std::nullopt /* proxy_annotation_tag */,
                  LOW, tag1, ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_GT(GetTaggedBytes(tag_val1), old_traffic);

  // Test reused socket is retagged.
  StreamSocket* socket = handle.socket();
  handle.Reset();
  old_traffic = GetTaggedBytes(tag_val2);
  rv = handle.Init(kGroupId, params, std::nullopt /* proxy_annotation_tag */,
                   LOW, tag2, ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(handle.socket(), socket);
  const char kRequest[] = "GET / HTTP/1.0\n\n";
  scoped_refptr<IOBuffer> write_buffer =
      base::MakeRefCounted<StringIOBuffer>(kRequest);
  rv =
      handle.socket()->Write(write_buffer.get(), strlen(kRequest),
                             callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_EQ(static_cast<int>(strlen(kRequest)), callback.GetResult(rv));
  EXPECT_GT(GetTaggedBytes(tag_val2), old_traffic);
  // Disconnect socket to pr
"""


```