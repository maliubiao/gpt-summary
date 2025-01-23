Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. They are particularly interested in:

1. **General functionality:** What does this code do?
2. **Relationship to JavaScript:** Does this code interact with JavaScript, and if so, how?
3. **Logic and I/O:** Can we infer the logic based on the test setup and provide example inputs and outputs?
4. **Common user errors:** What mistakes might users or developers make that could lead to this code being executed?
5. **User steps to reach this code:** How does a user's interaction with the browser eventually lead to this part of the network stack?
6. **Context within the larger file:** This is part 10 of 34, so what is the overall theme or purpose of this section?

Let's break down the code:

* **Testing framework:** The code uses `TEST_P` which indicates it's part of a parameterized test suite in Google Test. The class `HttpNetworkTransactionTest` suggests that the tests are focused on the `HttpNetworkTransaction` class.
* **Focus on client certificate authentication:**  Several tests have names like `HttpsNestedProxyClientAuthCertNeeded...NoCrash`. This strongly suggests a focus on how the `HttpNetworkTransaction` handles scenarios where a proxy server or the destination server requests a client certificate during the SSL/TLS handshake.
* **Multi-proxy scenarios:** Many tests involve `ProxyChain` and multiple `ProxyServer` objects, indicating that the code is testing scenarios with multiple proxy servers in the chain.
* **SPDY/HTTP/2:** The code frequently uses `spdy::SpdySerializedFrame` and sets `ssl.next_proto = kProtoHTTP2`, indicating that these tests involve HTTP/2 connections, often over a proxy.
* **Error handling:**  The tests often check for specific errors like `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` and `ERR_CONNECTION_CLOSED`.
* **Mocking:** The code uses `MockWrite`, `MockRead`, `SequencedSocketData`, and `SSLSocketDataProvider` to simulate network interactions and SSL handshake behavior. This is typical in unit tests to control the environment and test specific conditions.
* **Session management:** The code creates and uses `HttpNetworkSession` objects, highlighting the interaction between transactions and sessions.

**Plan:**

1. Summarize the core functionality of the code based on the test names and the types of operations being mocked.
2. Address the JavaScript relationship (likely minimal, but worth mentioning).
3. Provide a simple example of the client certificate authentication flow, including the simulated inputs and the expected outcome.
4. Discuss potential user/developer errors.
5. Outline the user actions that could lead to these scenarios.
6. Summarize the function of this specific part of the test file.
这是一个C++源代码文件，属于Chromium网络栈的单元测试，专门用于测试 `net::HttpNetworkTransaction` 类的功能。 从提供的代码片段来看，这个文件的第10部分主要关注 `HttpNetworkTransaction` 如何处理 **HTTPS代理场景下需要客户端证书认证** 的情况，特别是涉及到多层代理时，以确保在这些复杂的场景下不会发生崩溃。

**功能归纳 (基于提供的代码片段):**

这一部分的主要功能是测试 `HttpNetworkTransaction` 在以下场景下的健壮性和正确性：

1. **直接连接的HTTPS服务器请求客户端证书:**  测试当目标HTTPS服务器直接请求客户端证书时，`HttpNetworkTransaction` 能否正确处理 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 错误，并且不会意外崩溃。
2. **多层HTTPS代理链中的第一个代理请求客户端证书:**  测试在多层HTTPS代理链中，当第一个代理服务器请求客户端证书时，`HttpNetworkTransaction` 能否正确处理该错误且不崩溃。
3. **多层HTTPS代理链中第一个代理请求客户端证书的不同方式:**  测试用不同的方法模拟第一个代理请求客户端证书的情况，确保 `HttpNetworkTransaction` 的处理一致。
4. **多层HTTPS代理链中在第一个CONNECT之后请求客户端证书:**  测试在通过第一个代理建立连接之后，第二个代理或者目标服务器请求客户端证书时，`HttpNetworkTransaction` 的行为，确保不会崩溃。
5. **多层HTTPS代理链中的第二个代理请求客户端证书:** 测试在多层HTTPS代理链中，当第二个代理服务器请求客户端证书时，`HttpNetworkTransaction` 能否正确处理且不崩溃。
6. **通过多层HTTPS代理链隧道连接的终端服务器请求客户端证书:** 测试当通过多层HTTPS代理建立隧道后，目标HTTPS服务器请求客户端证书时，`HttpNetworkTransaction` 的行为，确保其能正确处理且不崩溃。
7. **HTTPS代理场景下的SPDY GET请求与会话竞争:** 测试当一个会话比拥有它的事务更快完成（在主机名解析之前完成）时，事务是否会失败，这是一个回归测试。
8. **HTTPS代理场景下的SPDY GET请求与代理认证:** 测试通过需要代理认证的HTTPS代理发送SPDY GET请求时，`HttpNetworkTransaction` 如何处理 `407 Proxy Authentication Required` 响应，以及如何处理 `RestartWithAuth` 操作。
9. **通过HTTPS代理的SPDY CONNECT到HTTPS服务器 (SPDY -> HTTPS):** 测试通过HTTPS代理使用SPDY CONNECT方法连接到目标HTTPS服务器的场景。
10. **通过两层HTTPS代理的SPDY CONNECT到HTTPS服务器 (SPDY -> SPDY -> HTTPS):** 测试通过两层HTTPS代理使用SPDY CONNECT方法连接到目标HTTPS服务器的场景。

**与JavaScript的功能关系:**

`net::HttpNetworkTransaction` 本身是一个C++类，直接与JavaScript没有直接的交互。然而，它在Chromium浏览器中扮演着核心的网络请求处理角色。 当JavaScript发起一个网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）时，浏览器内核最终会调用到网络栈的C++代码来执行实际的网络操作。

**举例说明:**

假设一个网页上的JavaScript代码尝试访问 `https://www.example.org/`，并且浏览器配置了使用一个需要客户端证书认证的HTTPS代理服务器。

1. **JavaScript 发起请求:**
   ```javascript
   fetch('https://www.example.org/')
     .then(response => response.text())
     .then(data => console.log(data));
   ```

2. **浏览器处理:** 浏览器接收到这个请求，并根据配置确定需要通过HTTPS代理。

3. **`HttpNetworkTransaction` 的介入:**  浏览器会创建一个 `HttpNetworkTransaction` 对象来处理这个请求。

4. **代理连接和证书请求 (对应测试场景):** 在与代理服务器建立连接的过程中，代理服务器可能会返回一个指示需要客户端证书的错误，例如 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED`。  上面代码中的测试用例，特别是像 `HttpsNestedProxyClientAuthCertNeededFirstProxyNoCrash` 这样的测试，就是在模拟和验证 `HttpNetworkTransaction` 在接收到这种错误时的行为。

5. **证书选择 (用户交互):** 如果需要客户端证书，浏览器可能会弹出一个对话框让用户选择合适的证书。

6. **重试或失败:**  根据用户的选择或配置，`HttpNetworkTransaction` 可能会重试请求，或者返回一个错误给上层（最终可能会在JavaScript中通过 `fetch` API 的 `catch` 或 `then` 中的错误处理来捕获）。

**逻辑推理与假设输入输出:**

以 `HttpsNestedProxyClientAuthCertNeededFirstProxyNoCrash` 测试为例：

**假设输入:**

* **网络配置:** 配置了两个HTTPS代理 `proxy1.test:70` 和 `proxy2.test:71`。
* **模拟网络数据 (MockRead/MockWrite):**
    * 向第一个代理 (`proxy2.test`) 发送 SPDY CONNECT 请求。
    * 接收到来自第一个代理的 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 错误。
    * 接收到来自第一个代理的 SPDY GOAWAY 帧（模拟连接关闭）。
* **请求信息:**  一个访问 `https://www.example.org/` 的 GET 请求。

**预期输出:**

* `trans.Start()` 返回 `ERR_IO_PENDING`，表示异步操作正在进行。
* `callback.WaitForResult()` 返回 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED`。
* `trans.GetResponseInfo()->cert_request_info.get()` 返回 `nullptr`，因为在直接读取到 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 的情况下，没有可用的 `SSLCertRequestInfo`。
* **没有崩溃:** 最关键的预期是程序没有崩溃。

**用户或编程常见的使用错误:**

1. **错误的代理配置:** 用户可能配置了错误的代理服务器地址或端口，导致连接失败或认证错误。
2. **缺少客户端证书:** 当服务器或代理要求客户端证书时，如果用户没有安装或配置相应的证书，请求将会失败。
3. **证书过期或无效:**  使用的客户端证书可能已过期或被吊销。
4. **代理服务器配置错误:** 代理服务器自身可能没有正确配置客户端证书认证。
5. **代码中未处理证书请求:** 对于开发者来说，如果程序需要处理客户端证书，但没有实现相应的逻辑（例如，在接收到 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 后提示用户选择证书并重试），则会导致请求失败。

**用户操作到达此处的步骤 (调试线索):**

1. **用户尝试访问HTTPS网站:** 用户在浏览器地址栏输入一个 `https://` 开头的网址。
2. **浏览器检查代理配置:** 浏览器检查系统或应用程序的代理设置。
3. **使用HTTPS代理:** 如果配置了HTTPS代理，浏览器会尝试通过代理连接目标网站。
4. **代理要求客户端证书:**  在SSL/TLS握手过程中，代理服务器可能会发送一个 "Certificate Request" 消息，要求客户端提供证书。这在代码中被模拟为 `MockRead(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED, 1)`。
5. **`HttpNetworkTransaction` 处理:**  `HttpNetworkTransaction` 负责处理这个握手过程和可能出现的错误，例如客户端证书请求。
6. **触发测试场景:** 上述测试代码模拟了各种接收到客户端证书请求错误时的情景，用于验证 `HttpNetworkTransaction` 的正确行为。

**作为第10部分的功能归纳:**

作为整个测试文件（共34部分）的第10部分，这段代码的功能是 **深入测试 `HttpNetworkTransaction` 在复杂的HTTPS代理场景下，特别是在需要客户端证书认证时的错误处理和健壮性**。  它着重于确保在多层代理和不同的证书请求时机下，`HttpNetworkTransaction` 不会崩溃，并且能够正确地返回相应的错误信息。  这一部分可能紧随初始化和基本连接测试之后，开始涉及更复杂的代理和安全相关的场景。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
ame endpoint_connect(spdy_util_.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));

  spdy::SpdySerializedFrame spdy_response_go_away(
      spdy_util_.ConstructSpdyGoAway(0, spdy::ERROR_CODE_PROTOCOL_ERROR,
                                     "Error 110 reading from socket."));

  MockWrite spdy_writes[] = {
      CreateMockWrite(endpoint_connect, 0),
      CreateMockWrite(spdy_response_go_away, 2),
  };

  MockRead spdy_reads[] = {
      MockRead(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED, 1),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans.GetResponseInfo()->cert_request_info.get();
  // In the case of a read returning ERR_SSL_CLIENT_AUTH_CERT_NEEDED directly,
  // no `SSLCertRequestInfo` is available.
  EXPECT_FALSE(cert_request_info);
}

// Test that the first proxy server in a multi-proxy chain requesting a client
// auth cert doesn't cause a crash.
// TODO(crbug.com/40284947): Support client auth certificates for
// multi-proxy chains and then replace this test with a more robust one (for
// instance, a version of the AuthEverywhere test that uses a multi-proxy
// chain).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyClientAuthCertNeededFirstProxyNoCrash) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame spdy_response_go_away(
      spdy_util_.ConstructSpdyGoAway(0, spdy::ERROR_CODE_PROTOCOL_ERROR,
                                     "Error 110 reading from socket."));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(spdy_response_go_away, 2),
  };

  MockRead spdy_reads[] = {
      MockRead(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED, 1),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans.GetResponseInfo()->cert_request_info.get();
  // In the case of a read returning ERR_SSL_CLIENT_AUTH_CERT_NEEDED directly,
  // no `SSLCertRequestInfo` is available.
  EXPECT_FALSE(cert_request_info);
}

// Same as above but using a different method to request the client auth
// certificate.
// TODO(crbug.com/40284947): Support client auth certificates for
// multi-proxy chains and then replace this test with a more robust one (for
// instance, a version of the AuthEverywhere test that uses a multi-proxy
// chain).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyClientAuthCertNeededFirstProxyNoCrash2) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  StaticSocketDataProvider spdy_data{base::span<MockRead>(),
                                     base::span<MockWrite>()};
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  auto cert_request_info_proxy = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_proxy->host_and_port = kProxyServer1.host_port_pair();

  SSLSocketDataProvider ssl(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl.cert_request_info = cert_request_info_proxy;
  ssl.expected_send_client_cert = false;
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans.GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_TRUE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port, kProxyServer1.host_port_pair());
}

// Test that a read returning ERR_SSL_CLIENT_AUTH_CERT_NEEDED after the first
// CONNECT doesn't result in a crash when a multi-proxy chain is in use.
// TODO(crbug.com/40284947): Support client auth certificates for
// multi-proxy chains and then replace this test with a more robust one (for
// instance, a version of the AuthEverywhere test that uses a multi-proxy
// chain).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyClientAuthCertNeededAfterFirstConnectNoCrash2) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:80 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // request is calculated correctly.
  SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
  spdy::SpdySerializedFrame endpoint_connect(spdy_util2.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 80)));
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame spdy_response_go_away(
      spdy_util_.ConstructSpdyGoAway(0, spdy::ERROR_CODE_PROTOCOL_ERROR,
                                     "Error 110 reading from socket."));
  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(spdy_response_go_away, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      MockRead(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED, 4),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
  SSLCertRequestInfo* cert_request_info =
      trans.GetResponseInfo()->cert_request_info.get();
  EXPECT_FALSE(cert_request_info);
}

// Test that the second proxy server in a multi-proxy chain requesting a client
// auth cert doesn't cause a crash.
// TODO(crbug.com/40284947): Support client auth certificates for
// multi-proxy chains and then replace this test with a more robust one (for
// instance, a version of the AuthEverywhere test that uses a multi-proxy
// chain).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyClientAuthCertNeededSecondProxyNoCrash) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      /*extra_headers=*/nullptr, 0, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(rst, 2),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  auto cert_request_info_proxy = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_proxy->host_and_port = kProxyServer2.host_port_pair();

  SSLSocketDataProvider ssl2(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl2.cert_request_info = cert_request_info_proxy;
  ssl2.expected_send_client_cert = false;
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans.GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_TRUE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port, kProxyServer2.host_port_pair());
}

// Test that the endpoint requesting a client auth cert over a multi-proxy chain
// tunnel doesn't cause a crash.
// TODO(crbug.com/40284947): Support client auth certificates for
// multi-proxy chains and then replace this test with a more robust one (for
// instance, a version of the AuthEverywhere test that uses a multi-proxy
// chain).
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyClientAuthCertNeededEndpointNoCrash) {
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:443 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // CONNECT is calculated correctly.
  SpdyTestUtil new_spdy_util;
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));

  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_endpoint_connect(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect, 1));

  spdy::SpdySerializedFrame endpoint_connect_resp(
      new_spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame wrapped_endpoint_connect_resp(
      spdy_util_.ConstructWrappedSpdyFrame(endpoint_connect_resp, 1));

  spdy::SpdySerializedFrame rst(
      new_spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  spdy::SpdySerializedFrame wrapped_rst(
      spdy_util_.ConstructWrappedSpdyFrame(rst, 1));

  MockWrite spdy_writes[] = {
      CreateMockWrite(proxy2_connect, 0),
      CreateMockWrite(wrapped_endpoint_connect, 2),
      CreateMockWrite(wrapped_rst, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(proxy2_connect_resp, 1, ASYNC),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_endpoint_connect_resp, 4, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 6),
      MockRead(ASYNC, 0, 7),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  auto cert_request_info_origin = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_origin->host_and_port =
      HostPortPair("www.example.org", 443);

  SSLSocketDataProvider ssl3(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl3.cert_request_info = cert_request_info_origin;
  ssl3.expected_send_client_cert = false;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  spdy_data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  spdy_data.Resume();

  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans.GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_FALSE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port,
            HostPortPair("www.example.org", 443));
}

// Verifies that a session which races and wins against the owning transaction
// (completing prior to host resolution), doesn't fail the transaction.
// Regression test for crbug.com/334413.
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyGetWithSessionRace) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure SPDY proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Fetch http://www.example.org/ through the SPDY proxy.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("http://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(data, 2),
      MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Stall the hostname resolution begun by the transaction.
  session_deps_.host_resolver->set_ondemand_mode(true);

  int rv = trans.Start(&request, callback1.callback(), net_log_with_source);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Race a session to the proxy, which completes first.
  session_deps_.host_resolver->set_ondemand_mode(false);
  SpdySessionKey key(HostPortPair("proxy", 70), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kProxy, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/true);
  base::WeakPtr<SpdySession> spdy_session =
      CreateSpdySession(session.get(), key, net_log_with_source);

  // Unstall the resolution begun by the transaction.
  session_deps_.host_resolver->set_ondemand_mode(true);
  session_deps_.host_resolver->ResolveAllPending();

  EXPECT_FALSE(callback1.have_result());
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Test a SPDY GET through an HTTPS proxy that uses proxy auth.
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyGetWithProxyAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // The first request will be a bare GET, the second request will be a
  // GET with a Proxy-Authorization header.
  spdy_util_.set_default_url(request.url);
  spdy::SpdySerializedFrame req_get(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  const char* const kExtraAuthorizationHeaders[] = {"proxy-authorization",
                                                    "Basic Zm9vOmJhcg=="};
  spdy::SpdySerializedFrame req_get_authorization(spdy_util_.ConstructSpdyGet(
      kExtraAuthorizationHeaders, std::size(kExtraAuthorizationHeaders) / 2, 3,
      LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(req_get, 0),
      CreateMockWrite(req_get_authorization, 3),
  };

  // The first response is a 407 proxy authentication challenge, and the second
  // response will be a 200 response since the second request includes a valid
  // Authorization header.
  const char* const kExtraAuthenticationHeaders[] = {
      "proxy-authenticate", "Basic realm=\"MyRealm1\""};
  spdy::SpdySerializedFrame resp_authentication(
      spdy_util_.ConstructSpdyReplyError(
          "407", kExtraAuthenticationHeaders,
          std::size(kExtraAuthenticationHeaders) / 2, 1));
  spdy::SpdySerializedFrame body_authentication(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame resp_data(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body_data(
      spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp_authentication, 1),
      CreateMockRead(body_authentication, 2, SYNCHRONOUS),
      CreateMockRead(resp_data, 4),
      CreateMockRead(body_data, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* const response = trans.GetResponseInfo();

  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* const response_restart = trans.GetResponseInfo();

  ASSERT_TRUE(response_restart);
  ASSERT_TRUE(response_restart->headers);
  EXPECT_EQ(200, response_restart->headers->response_code());
  // The password prompt info should not be set.
  EXPECT_FALSE(response_restart->auth_challenge.has_value());
}

// Test a SPDY CONNECT through an HTTPS Proxy to an HTTPS (non-SPDY) Server
// (SPDY -> HTTPS).
TEST_P(HttpNetworkTransactionTest, HttpsProxySpdyConnectHttps) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://proxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to www.example.org:443 via SPDY
  spdy::SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via HTTP

  const char kGet[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructSpdyDataFrame(1, kGet, false));
  spdy::SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  const char kResp[] =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  spdy::SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructSpdyDataFrame(1, kResp, false));
  const char kRespData[] = "1234567890";
  spdy::SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructSpdyDataFrame(1, kRespData, false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect, 0),
      CreateMockWrite(wrapped_get, 2),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp, 1, ASYNC),
      CreateMockRead(wrapped_get_resp, 3, ASYNC),
      CreateMockRead(wrapped_body, 4, ASYNC),
      MockRead(ASYNC, 0, 5),
  };

  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kRespData, response_data);
}

// Test a SPDY CONNECT through two HTTPS (SPDY) proxies to an HTTPS (non-SPDY)
// server (SPDY -> SPDY -> HTTPS).
TEST_P(HttpNetworkTransactionTest, HttpsNestedProxySpdyConnectHttps) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure a nested proxy.
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  ProxyList proxy_list;
  proxy_list.AddProxyChain(kNestedProxyChain);
  ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          ProxyConfigWithAnnotation(proxy_config,
                                    TRAFFIC_ANNOTATION_FOR_TESTS));

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to proxy2.test:71 via SPDY.
  spdy::SpdySerializedFrame proxy2_connect(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      kProxyServer2.host_port_pair()));

  spdy::SpdySerializedFrame proxy2_connect_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // CONNECT to www.example.org:443 via SPDY.
  // Need to use a new `SpdyTestUtil()` so that the stream parent ID of this
  // CONNECT is calculated correctly.
  SpdyTestUtil new_spdy_util;
  spdy::SpdySerializedFrame endpoint_connect(new_spdy_util.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair("www.example.org", 443)));

  // Since this request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
```