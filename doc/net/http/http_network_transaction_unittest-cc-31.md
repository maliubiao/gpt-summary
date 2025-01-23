Response:
The user wants to understand the functionality of the given C++ code snippet from Chromium's network stack.
The code is a unit test file (`http_network_transaction_unittest.cc`) and this specific part (section 32 of 34) sets up and executes several test cases for `HttpNetworkTransaction`.

Here's a breakdown of how to address the user's request:

1. **General Functionality:** Describe the purpose of the code as setting up mock network interactions to test different scenarios related to HTTP network transactions. This includes handling authentication, client certificates, and network isolation.

2. **Relationship with Javascript:** Explain that while the underlying network stack is in C++, the behavior tested here directly affects how web browsers (which use Javascript) interact with the network. Provide examples of user actions in a browser that would trigger these network transactions.

3. **Logical Inference (Input/Output):** For each test case within the snippet, identify the setup (mock data providers) as the input and the assertions made on the `HttpNetworkTransaction` object as the output. Specifically, focus on the expected return values, response codes, and authentication challenges.

4. **Common User/Programming Errors:** Think about common mistakes users or developers might make that these tests help catch. For example, incorrect proxy configuration, missing client certificates, or incorrect handling of authentication challenges.

5. **User Operations & Debugging:** Describe the steps a user might take in a browser that would lead to the execution paths tested here. Also, suggest how a developer could use this test file as a debugging aid.

6. **Section Summary:**  Summarize the main focus of this particular section of the test file. It appears to be focused on more complex scenarios involving both proxy and origin authentication (both HTTP Basic and TLS client certificates) as well as network isolation.

**Mental Sandbox:**

* **Test Case 1 (ProxyTLSAndServerHTTPAuth):**  This test covers a scenario where the proxy requires a client certificate and the server requires HTTP Basic authentication. The code sets up mock data to simulate this flow, including retries with credentials.
* **Test Case 2 (ProxyHTTPAndServerTLSAuth):** This test is the reverse of the first one - the proxy requires HTTP Basic auth, and the server requires a client certificate. This highlights how the `HttpNetworkTransaction` handles these scenarios in different orders.
* **Test Case 3 (ClientCertSocketReuse):** This test focuses on optimization - ensuring that once a client certificate is provided for a host, subsequent requests to the same host can reuse the same connection without needing to provide the certificate again.
* **Test Case 4 (NetworkIsolation):**  This test examines the feature of partitioning network connections based on the `NetworkAnonymizationKey`. It sends requests with different keys and verifies that separate sockets are used when the feature is enabled.
* **Test Case 5 (NetworkIsolationH2):** Similar to the previous test, but specifically for HTTP/2 connections, both direct and via a proxy.
* **Test Case 6 (NetworkIsolationPreconnect):** This test focuses on how network isolation interacts with pre-established connections (preconnect).

Now, I can generate the detailed response based on this analysis.
这是文件 `net/http/http_network_transaction_unittest.cc` 的第 32 部分，共 34 部分。这个文件包含了 `HttpNetworkTransaction` 类的单元测试。`HttpNetworkTransaction` 是 Chromium 网络栈中负责执行单个 HTTP 请求的核心类。

**本部分（第 32 部分）的主要功能是测试 `HttpNetworkTransaction` 在涉及客户端证书认证、代理认证以及网络隔离等复杂场景下的行为。**

**具体功能分解：**

1. **`ProxyTLSAndServerHTTPAuth` 测试:**
   - **功能:** 测试代理服务器要求 TLS 客户端证书认证，而源服务器要求 HTTP 基本认证的场景。
   - **假设输入与输出:**
     - **假设输入:** 一个需要通过 HTTPS 代理访问 HTTPS 源站点的请求。代理首先要求客户端证书，然后通过连接，源站点返回 401 未授权，客户端提供 HTTP 基本认证凭据后请求成功。
     - **输出:** 测试验证 `HttpNetworkTransaction` 能正确处理代理的客户端证书请求 (`ERR_SSL_CLIENT_AUTH_CERT_NEEDED`)，并能记住并重试代理的 HTTP 基本认证。之后，当源站点也要求 HTTP 基本认证时，也能正确处理并完成请求。
   - **与 Javascript 的关系:** 当用户通过浏览器访问一个需要客户端证书和 HTTP 认证的站点时，浏览器的网络栈（包括这里的 `HttpNetworkTransaction`）会处理这些认证流程，最终让 Javascript 代码能够获取到网页内容。例如，用户访问一个企业内部网站，可能需要安装证书并输入用户名密码。
   - **用户/编程常见的使用错误:**
     - 用户未安装正确的客户端证书。
     - 用户输入错误的代理或源站点的用户名/密码。
     - 开发者在配置服务器时，认证方式配置错误。
   - **用户操作到达这里的步骤:**
     1. 用户在浏览器中输入一个需要客户端证书和 HTTP 认证的 HTTPS 网址。
     2. 浏览器配置了需要认证的 HTTPS 代理。
     3. 浏览器网络栈开始建立与代理的连接。
     4. 代理的 TLS 握手过程中，服务器请求客户端证书。
     5. `HttpNetworkTransaction` 接收到 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 错误。
     6. 用户（或证书管理器）选择证书并提供。
     7. 建立与代理的连接后，发送 `CONNECT` 请求。
     8. 代理返回 200 连接已建立。
     9. `HttpNetworkTransaction` 尝试向源站点发送请求。
     10. 源站点返回 401 未授权。
     11. `HttpNetworkTransaction` 接收到认证挑战。
     12. 用户输入用户名密码（或者浏览器缓存了凭据）。
     13. `HttpNetworkTransaction` 使用提供的凭据重试请求。
     14. 请求成功。

2. **`ProxyHTTPAndServerTLSAuth` 测试:**
   - **功能:** 测试代理服务器要求 HTTP 基本认证，而源服务器要求 TLS 客户端证书认证的场景。
   - **假设输入与输出:**
     - **假设输入:** 一个需要通过 HTTPS 代理访问 HTTPS 源站点的请求。代理首先返回 407 代理认证请求，客户端提供 HTTP 基本认证凭据后连接建立，源站点要求客户端证书，客户端提供证书后请求成功。
     - **输出:** 测试验证 `HttpNetworkTransaction` 能正确处理代理的 HTTP 基本认证请求，并能记住并重试。之后，当源站点也要求客户端证书时，也能正确处理并完成请求。
   - **与 Javascript 的关系:** 类似于上一个测试，只是认证顺序不同。用户可能需要先输入代理的用户名密码，再提供客户端证书才能访问目标网站。
   - **用户/编程常见的使用错误:** 与上一个测试类似，证书问题和认证凭据错误是常见的。
   - **用户操作到达这里的步骤:**  类似于上一个测试，只是代理认证发生在客户端证书请求之前。

3. **`ClientCertSocketReuse` 测试:**
   - **功能:** 测试在提供了客户端证书后，后续对同一主机的请求是否能重用已建立的连接。
   - **假设输入与输出:**
     - **假设输入:**  两个连续的 HTTPS 请求到同一个主机。第一个请求触发客户端证书请求，提供证书后请求成功。
     - **输出:** 测试验证第二个请求是否能够重用第一个请求建立的连接，而不需要再次提供客户端证书。这体现了连接池和客户端证书缓存的机制。
   - **与 Javascript 的关系:**  当用户在一个网站上提供了客户端证书后，刷新页面或访问该网站的其他 HTTPS 页面时，浏览器应该尽量避免再次提示用户选择证书，以提升用户体验。
   - **用户/编程常见的使用错误:**
     - 服务器配置不当，导致连接无法保持活跃。
     - 客户端证书配置错误，导致无法正确识别已提供的证书。
   - **用户操作到达这里的步骤:**
     1. 用户首次访问需要客户端证书的 HTTPS 网站。
     2. 提供客户端证书并成功访问。
     3. 用户在短时间内访问该网站的另一个 HTTPS 页面。
     4. 浏览器网络栈尝试重用已有的连接。

4. **`NetworkIsolation` 测试:**
   - **功能:** 测试网络隔离功能，即具有不同 `NetworkAnonymizationKey` 的请求是否会使用不同的 socket 连接。
   - **假设输入与输出:**
     - **假设输入:** 三个连续的 HTTP 请求到 `foo.test`，第一个和第三个请求具有相同的 `NetworkAnonymizationKey`，第二个请求具有不同的 `NetworkAnonymizationKey`。
     - **输出:**  如果启用了网络隔离特性 (`features::kPartitionConnectionsByNetworkIsolationKey`)，则期望第一个和第三个请求使用同一个 socket 连接，而第二个请求使用不同的 socket 连接。如果未启用，则所有请求都可能使用同一个 socket 连接。
   - **与 Javascript 的关系:**  网络隔离是 Chromium 为了增强隐私和安全而引入的功能，可以防止某些跨站点的追踪。当 Javascript 发起跨域请求时，浏览器会根据 `NetworkAnonymizationKey` (例如，基于 top-level site) 来决定是否重用已有的连接。
   - **用户/编程常见的使用错误:**
     - 开发者可能不理解网络隔离的原理，导致在需要隔离的场景下使用了相同的 `NetworkAnonymizationKey`。
     - 服务器端配置可能与客户端的网络隔离策略不兼容。
   - **用户操作到达这里的步骤:**
     1. 用户访问一个网站 (origin1)。
     2. 网站的 Javascript 代码发起一个到 `foo.test` 的请求。
     3. 用户访问另一个网站 (origin2)。
     4. 新网站的 Javascript 代码发起另一个到 `foo.test` 的请求。
     5. 用户再次访问第一个网站 (origin1)。
     6. 第一个网站的 Javascript 代码再次发起一个到 `foo.test` 的请求。

5. **`NetworkIsolationH2` 测试:**
   - **功能:** 与 `NetworkIsolation` 测试类似，但针对的是 HTTP/2 连接，包括直接的 HTTPS 请求和通过 HTTPS 代理的 HTTP 请求。
   - **假设输入与输出:**  与 `NetworkIsolation` 测试的逻辑相同，只是底层的传输协议是 HTTP/2。
   - **与 Javascript 的关系:**  与 `NetworkIsolation` 测试相同，只是测试了 HTTP/2 下的网络隔离行为。
   - **用户/编程常见的使用错误:**  与 `NetworkIsolation` 测试相同。
   - **用户操作到达这里的步骤:** 与 `NetworkIsolation` 测试相同，只是连接使用的是 HTTP/2 协议。

6. **`NetworkIsolationPreconnect` 测试:**
   - **功能:** 测试在启用了网络隔离功能的情况下，预连接（preconnect）的 socket 如何与具有不同 `NetworkAnonymizationKey` 的请求关联。
   - **假设输入与输出:**  首先预连接了两个 socket，分别对应不同的 `NetworkAnonymizationKey`。然后发起一个请求，测试该请求是否使用了正确的预连接 socket。
   - **与 Javascript 的关系:**  网站可以使用 `<link rel="preconnect" href="...">` 标签来预先建立与某些服务器的连接，以提高页面加载速度。这个测试验证了网络隔离功能是否能正确地将预连接的 socket 与后续具有相同 `NetworkAnonymizationKey` 的请求关联起来。
   - **用户/编程常见的使用错误:**
     - 开发者可能错误地预连接了不应该预连接的域名，或者预连接时没有考虑网络隔离的影响。
   - **用户操作到达这里的步骤:**
     1. 用户访问一个包含预连接指令的网站。
     2. 浏览器根据预连接指令建立与目标服务器的连接。
     3. 网站的 Javascript 代码发起一个请求，该请求的 `NetworkAnonymizationKey` 与之前预连接的某个 socket 匹配。

**总结第 32 部分的功能:**

这部分主要集中在测试 `HttpNetworkTransaction` 在处理复杂认证流程（客户端证书和代理/服务器的 HTTP 认证混合使用）以及网络隔离功能时的正确性。它验证了在这些复杂场景下，`HttpNetworkTransaction` 能够正确地发起连接、处理认证挑战、重用连接，并遵循网络隔离的策略。 这些测试确保了 Chromium 在面对需要客户端证书、代理认证以及启用网络隔离的情况下，能够安全且高效地处理网络请求。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第32部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
StaticSocketDataProvider data3(mock_reads3, mock_writes3);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy3);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin3);

  // The client responds to the origin client certificate request on a new
  // connection.
  SSLSocketDataProvider ssl_proxy4(ASYNC, OK);
  ssl_proxy4.expected_send_client_cert = true;
  ssl_proxy4.expected_client_cert = identity_proxy->certificate();
  std::vector<MockWrite> mock_writes4;
  std::vector<MockRead> mock_reads4;
  mock_writes4.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads4.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  SSLSocketDataProvider ssl_origin4(ASYNC, OK);
  ssl_origin4.expected_send_client_cert = true;
  ssl_origin4.expected_client_cert = identity_origin->certificate();
  // The client sends the origin HTTP request, which results in another HTTP
  // auth request and closed connection.
  mock_writes4.emplace_back(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n");
  mock_reads4.emplace_back(
      "HTTP/1.1 401 Unauthorized\r\n"
      "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"
      "Connection: close\r\n"
      "Content-Length: 0\r\n\r\n");
  StaticSocketDataProvider data4(mock_reads4, mock_writes4);
  session_deps_.socket_factory->AddSocketDataProvider(&data4);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy4);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin4);

  // The client retries with credentials on a new connection, and the request
  // finally succeeds.
  SSLSocketDataProvider ssl_proxy5(ASYNC, OK);
  ssl_proxy5.expected_send_client_cert = true;
  ssl_proxy5.expected_client_cert = identity_proxy->certificate();
  std::vector<MockWrite> mock_writes5;
  std::vector<MockRead> mock_reads5;
  mock_writes5.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads5.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  SSLSocketDataProvider ssl_origin5(ASYNC, OK);
  ssl_origin5.expected_send_client_cert = true;
  ssl_origin5.expected_client_cert = identity_origin->certificate();
  mock_writes5.emplace_back(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n"
      // Authenticate as user:pass.
      "Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
  mock_reads5.emplace_back(
      "HTTP/1.1 200 OK\r\n"
      "Connection: close\r\n"
      "Content-Length: 0\r\n\r\n");
  StaticSocketDataProvider data5(mock_reads5, mock_writes5);
  session_deps_.socket_factory->AddSocketDataProvider(&data5);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy5);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin5);

  // The client makes a second request. This needs yet another connection, but
  // all credentials are cached.
  SSLSocketDataProvider ssl_proxy6(ASYNC, OK);
  ssl_proxy6.expected_send_client_cert = true;
  ssl_proxy6.expected_client_cert = identity_proxy->certificate();
  std::vector<MockWrite> mock_writes6;
  std::vector<MockRead> mock_reads6;
  mock_writes6.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads6.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  SSLSocketDataProvider ssl_origin6(ASYNC, OK);
  ssl_origin6.expected_send_client_cert = true;
  ssl_origin6.expected_client_cert = identity_origin->certificate();
  mock_writes6.emplace_back(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n"
      // Authenticate as user:pass.
      "Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
  mock_reads6.emplace_back(
      "HTTP/1.1 200 OK\r\n"
      "Connection: close\r\n"
      "Content-Length: 0\r\n\r\n");
  StaticSocketDataProvider data6(mock_reads6, mock_writes6);
  session_deps_.socket_factory->AddSocketDataProvider(&data6);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy6);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin6);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Start the request.
  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = callback.GetResult(
      trans->Start(&request, callback.callback(), NetLogWithSource()));

  // Handle the proxy client certificate challenge.
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans->GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_TRUE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port,
            cert_request_info_proxy->host_and_port);
  rv = callback.GetResult(trans->RestartWithCertificate(
      identity_proxy->certificate(), identity_proxy->ssl_private_key(),
      callback.callback()));

  // Handle the proxy HTTP auth challenge.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(407, trans->GetResponseInfo()->headers->response_code());
  EXPECT_TRUE(
      CheckBasicSecureProxyAuth(trans->GetResponseInfo()->auth_challenge));
  rv = callback.GetResult(trans->RestartWithAuth(
      AuthCredentials(u"proxyuser", u"proxypass"), callback.callback()));

  // Handle the origin client certificate challenge.
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  cert_request_info = trans->GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_FALSE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port,
            cert_request_info_origin->host_and_port);
  rv = callback.GetResult(trans->RestartWithCertificate(
      identity_origin->certificate(), identity_origin->ssl_private_key(),
      callback.callback()));

  // Handle the origin HTTP auth challenge.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(401, trans->GetResponseInfo()->headers->response_code());
  EXPECT_TRUE(
      CheckBasicSecureServerAuth(trans->GetResponseInfo()->auth_challenge));
  rv = callback.GetResult(trans->RestartWithAuth(
      AuthCredentials(u"user", u"pass"), callback.callback()));

  // The request completes.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(200, trans->GetResponseInfo()->headers->response_code());

  // Make a second request. This time all credentials are cached.
  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  ASSERT_THAT(callback.GetResult(trans->Start(&request, callback.callback(),
                                              NetLogWithSource())),
              IsOk());
  EXPECT_EQ(200, trans->GetResponseInfo()->headers->response_code());
}

// Test the proxy requesting HTTP auth and the server requesting TLS client
// certificates. This is a regression test for https://crbug.com/946406.
TEST_P(HttpNetworkTransactionTest, ProxyHTTPAndServerTLSAuth) {
  // Note these hosts must match the CheckBasic*Auth() functions.
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request_info_origin = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info_origin->host_and_port =
      HostPortPair("www.example.org", 443);

  std::unique_ptr<FakeClientCertIdentity> identity_origin =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_2.pem", "client_2.pk8");
  ASSERT_TRUE(identity_origin);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // The client connects to the proxy. The handshake succeeds.
  SSLSocketDataProvider ssl_proxy1(ASYNC, OK);
  // The client attempts an HTTP CONNECT, but the proxy requests basic auth.
  std::vector<MockWrite> mock_writes1;
  std::vector<MockRead> mock_reads1;
  mock_writes1.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n");
  mock_reads1.emplace_back(
      "HTTP/1.1 407 Proxy Authentication Required\r\n"
      "Content-Length: 0\r\n"
      "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n");
  // The client retries with credentials, and the request finally succeeds.
  mock_writes1.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads1.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  // The origin requests client certificates.
  SSLSocketDataProvider ssl_origin1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_origin1.cert_request_info = cert_request_info_origin;
  StaticSocketDataProvider data1(mock_reads1, mock_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin1);

  // The client responds to the origin client certificate request on a new
  // connection.
  SSLSocketDataProvider ssl_proxy2(ASYNC, OK);
  std::vector<MockWrite> mock_writes2;
  std::vector<MockRead> mock_reads2;
  mock_writes2.emplace_back(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      // Authenticate as proxyuser:proxypass.
      "Proxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\n\r\n");
  mock_reads2.emplace_back("HTTP/1.1 200 Connection Established\r\n\r\n");
  SSLSocketDataProvider ssl_origin2(ASYNC, OK);
  ssl_origin2.expected_send_client_cert = true;
  ssl_origin2.expected_client_cert = identity_origin->certificate();
  // The client sends the origin HTTP request, which succeeds.
  mock_writes2.emplace_back(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n");
  mock_reads2.emplace_back(
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 0\r\n\r\n");
  StaticSocketDataProvider data2(mock_reads2, mock_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin2);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Start the request.
  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = callback.GetResult(
      trans->Start(&request, callback.callback(), NetLogWithSource()));

  // Handle the proxy HTTP auth challenge.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(407, trans->GetResponseInfo()->headers->response_code());
  EXPECT_TRUE(
      CheckBasicSecureProxyAuth(trans->GetResponseInfo()->auth_challenge));
  rv = callback.GetResult(trans->RestartWithAuth(
      AuthCredentials(u"proxyuser", u"proxypass"), callback.callback()));

  // Handle the origin client certificate challenge.
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  SSLCertRequestInfo* cert_request_info =
      trans->GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(cert_request_info);
  EXPECT_FALSE(cert_request_info->is_proxy);
  EXPECT_EQ(cert_request_info->host_and_port,
            cert_request_info_origin->host_and_port);
  rv = callback.GetResult(trans->RestartWithCertificate(
      identity_origin->certificate(), identity_origin->ssl_private_key(),
      callback.callback()));

  // The request completes.
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(200, trans->GetResponseInfo()->headers->response_code());
}

// Test that socket reuse works with client certificates.
TEST_P(HttpNetworkTransactionTest, ClientCertSocketReuse) {
  auto cert_request_info = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info->host_and_port = HostPortPair("www.example.org", 443);

  std::unique_ptr<FakeClientCertIdentity> identity =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_1.pem", "client_1.pk8");
  ASSERT_TRUE(identity);

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/a");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/b");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // The first connection results in a client certificate request.
  StaticSocketDataProvider data1;
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl1.cert_request_info = cert_request_info;
  ssl1.expected_send_client_cert = false;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);

  // The second connection succeeds and is usable for both requests.
  MockWrite mock_writes[] = {
      MockWrite("GET /a HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("GET /b HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead mock_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 0\r\n\r\n"),
  };
  StaticSocketDataProvider data2(mock_reads, mock_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.expected_send_client_cert = true;
  ssl2.expected_client_cert = identity->certificate();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Start the first request. It succeeds after providing client certificates.
  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  ASSERT_THAT(callback.GetResult(trans->Start(&request1, callback.callback(),
                                              NetLogWithSource())),
              IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  SSLCertRequestInfo* info = trans->GetResponseInfo()->cert_request_info.get();
  ASSERT_TRUE(info);
  EXPECT_FALSE(info->is_proxy);
  EXPECT_EQ(info->host_and_port, cert_request_info->host_and_port);

  ASSERT_THAT(callback.GetResult(trans->RestartWithCertificate(
                  identity->certificate(), identity->ssl_private_key(),
                  callback.callback())),
              IsOk());
  EXPECT_EQ(200, trans->GetResponseInfo()->headers->response_code());

  // Make the second request. It completes without requesting client
  // certificates.
  trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  ASSERT_THAT(callback.GetResult(trans->Start(&request2, callback.callback(),
                                              NetLogWithSource())),
              IsOk());
  EXPECT_EQ(200, trans->GetResponseInfo()->headers->response_code());
}

// Test for partitioning connections by NetworkAnonymizationKey. Runs 3 requests
// in sequence with two different NetworkAnonymizationKeys, the first and last
// have the same key, the second a different one. Checks that the requests are
// partitioned across sockets as expected.
TEST_P(HttpNetworkTransactionTest, NetworkIsolation) {
  const SchemefulSite kSite1(GURL("http://origin1/"));
  const SchemefulSite kSite2(GURL("http://origin2/"));
  const auto network_anonymization_key1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto network_anonymization_key2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  NetworkIsolationKey network_isolation_key1(kSite1, kSite1);
  NetworkIsolationKey network_isolation_key2(kSite2, kSite2);

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

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    // Reads and writes for the unpartitioned case, where only one socket is
    // used.

    const MockWrite kUnpartitionedWrites[] = {
        MockWrite("GET /1 HTTP/1.1\r\n"
                  "Host: foo.test\r\n"
                  "Connection: keep-alive\r\n\r\n"),
        MockWrite("GET /2 HTTP/1.1\r\n"
                  "Host: foo.test\r\n"
                  "Connection: keep-alive\r\n\r\n"),
        MockWrite("GET /3 HTTP/1.1\r\n"
                  "Host: foo.test\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    const MockRead kUnpartitionedReads[] = {
        MockRead("HTTP/1.1 200 OK\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Length: 1\r\n\r\n"
                 "1"),
        MockRead("HTTP/1.1 200 OK\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Length: 1\r\n\r\n"
                 "2"),
        MockRead("HTTP/1.1 200 OK\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Length: 1\r\n\r\n"
                 "3"),
    };

    StaticSocketDataProvider unpartitioned_data(kUnpartitionedReads,
                                                kUnpartitionedWrites);

    // Reads and writes for the partitioned case, where two sockets are used.

    const MockWrite kPartitionedWrites1[] = {
        MockWrite("GET /1 HTTP/1.1\r\n"
                  "Host: foo.test\r\n"
                  "Connection: keep-alive\r\n\r\n"),
        MockWrite("GET /3 HTTP/1.1\r\n"
                  "Host: foo.test\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    const MockRead kPartitionedReads1[] = {
        MockRead("HTTP/1.1 200 OK\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Length: 1\r\n\r\n"
                 "1"),
        MockRead("HTTP/1.1 200 OK\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Length: 1\r\n\r\n"
                 "3"),
    };

    const MockWrite kPartitionedWrites2[] = {
        MockWrite("GET /2 HTTP/1.1\r\n"
                  "Host: foo.test\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    const MockRead kPartitionedReads2[] = {
        MockRead("HTTP/1.1 200 OK\r\n"
                 "Connection: keep-alive\r\n"
                 "Content-Length: 1\r\n\r\n"
                 "2"),
    };

    StaticSocketDataProvider partitioned_data1(kPartitionedReads1,
                                               kPartitionedWrites1);
    StaticSocketDataProvider partitioned_data2(kPartitionedReads2,
                                               kPartitionedWrites2);

    if (partition_connections) {
      session_deps_.socket_factory->AddSocketDataProvider(&partitioned_data1);
      session_deps_.socket_factory->AddSocketDataProvider(&partitioned_data2);
    } else {
      session_deps_.socket_factory->AddSocketDataProvider(&unpartitioned_data);
    }

    TestCompletionCallback callback;
    HttpRequestInfo request1;
    request1.method = "GET";
    request1.url = GURL("http://foo.test/1");
    request1.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    request1.network_isolation_key = network_isolation_key1;
    request1.network_anonymization_key = network_anonymization_key1;
    auto trans1 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                           session.get());
    int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    std::string response_data1;
    EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
    EXPECT_EQ("1", response_data1);
    trans1.reset();

    HttpRequestInfo request2;
    request2.method = "GET";
    request2.url = GURL("http://foo.test/2");
    request2.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    request2.network_isolation_key = network_isolation_key2;
    request2.network_anonymization_key = network_anonymization_key2;
    auto trans2 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                           session.get());
    rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    std::string response_data2;
    EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
    EXPECT_EQ("2", response_data2);
    trans2.reset();

    HttpRequestInfo request3;
    request3.method = "GET";
    request3.url = GURL("http://foo.test/3");
    request3.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    request3.network_isolation_key = network_isolation_key1;
    request3.network_anonymization_key = network_anonymization_key1;
    auto trans3 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                           session.get());
    rv = trans3->Start(&request3, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    std::string response_data3;
    EXPECT_THAT(ReadTransaction(trans3.get(), &response_data3), IsOk());
    EXPECT_EQ("3", response_data3);
    trans3.reset();
  }
}

TEST_P(HttpNetworkTransactionTest, NetworkIsolationH2) {
  const SchemefulSite kSite1(GURL("http://origin1/"));
  const SchemefulSite kSite2(GURL("http://origin2/"));
  const auto network_anonymization_key1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto network_anonymization_key2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  NetworkIsolationKey network_isolation_key1(kSite1, kSite1);
  NetworkIsolationKey network_isolation_key2(kSite2, kSite2);

  // Whether to use an H2 proxy. When false, uses HTTPS H2 requests without a
  // proxy, when true, uses HTTP requests over an H2 proxy. It's unnecessary to
  // test tunneled HTTPS over an H2 proxy, since that path sets up H2 sessions
  // the same way as the HTTP over H2 proxy case.
  for (bool use_proxy : {false, true}) {
    SCOPED_TRACE(use_proxy);
    if (use_proxy) {
      session_deps_.proxy_resolution_service =
          ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
              "HTTPS proxy:443", TRAFFIC_ANNOTATION_FOR_TESTS);
    } else {
      session_deps_.proxy_resolution_service =
          ConfiguredProxyResolutionService::CreateDirect();
    }
    const char* url1 = nullptr;
    const char* url2 = nullptr;
    const char* url3 = nullptr;
    if (use_proxy) {
      url1 = "http://foo.test/1";
      url2 = "http://foo.test/2";
      url3 = "http://foo.test/3";
    } else {
      url1 = "https://foo.test/1";
      url2 = "https://foo.test/2";
      url3 = "https://foo.test/3";
    }

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

      std::unique_ptr<HttpNetworkSession> session(
          CreateSession(&session_deps_));

      // Reads and writes for the unpartitioned case, where only one socket is
      // used.

      SpdyTestUtil spdy_util(/*use_priority_header=*/true);
      spdy::SpdySerializedFrame unpartitioned_req1(
          spdy_util.ConstructSpdyGet(url1, 1, LOWEST));
      spdy::SpdySerializedFrame unpartitioned_response1(
          spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
      spdy::SpdySerializedFrame unpartitioned_body1(
          spdy_util.ConstructSpdyDataFrame(1, "1", true));
      spdy_util.UpdateWithStreamDestruction(1);

      spdy::SpdySerializedFrame unpartitioned_req2(
          spdy_util.ConstructSpdyGet(url2, 3, LOWEST));
      spdy::SpdySerializedFrame unpartitioned_response2(
          spdy_util.ConstructSpdyGetReply(nullptr, 0, 3));
      spdy::SpdySerializedFrame unpartitioned_body2(
          spdy_util.ConstructSpdyDataFrame(3, "2", true));
      spdy_util.UpdateWithStreamDestruction(3);

      spdy::SpdySerializedFrame unpartitioned_req3(
          spdy_util.ConstructSpdyGet(url3, 5, LOWEST));
      spdy::SpdySerializedFrame unpartitioned_response3(
          spdy_util.ConstructSpdyGetReply(nullptr, 0, 5));
      spdy::SpdySerializedFrame unpartitioned_body3(
          spdy_util.ConstructSpdyDataFrame(5, "3", true));

      const MockWrite kUnpartitionedWrites[] = {
          CreateMockWrite(unpartitioned_req1, 0),
          CreateMockWrite(unpartitioned_req2, 3),
          CreateMockWrite(unpartitioned_req3, 6),
      };

      const MockRead kUnpartitionedReads[] = {
          CreateMockRead(unpartitioned_response1, 1),
          CreateMockRead(unpartitioned_body1, 2),
          CreateMockRead(unpartitioned_response2, 4),
          CreateMockRead(unpartitioned_body2, 5),
          CreateMockRead(unpartitioned_response3, 7),
          CreateMockRead(unpartitioned_body3, 8),
          MockRead(SYNCHRONOUS, ERR_IO_PENDING, 9),
      };

      SequencedSocketData unpartitioned_data(kUnpartitionedReads,
                                             kUnpartitionedWrites);

      // Reads and writes for the partitioned case, where two sockets are used.

      SpdyTestUtil spdy_util2(/*use_priority_header=*/true);
      spdy::SpdySerializedFrame partitioned_req1(
          spdy_util2.ConstructSpdyGet(url1, 1, LOWEST));
      spdy::SpdySerializedFrame partitioned_response1(
          spdy_util2.ConstructSpdyGetReply(nullptr, 0, 1));
      spdy::SpdySerializedFrame partitioned_body1(
          spdy_util2.ConstructSpdyDataFrame(1, "1", true));
      spdy_util2.UpdateWithStreamDestruction(1);

      spdy::SpdySerializedFrame partitioned_req3(
          spdy_util2.ConstructSpdyGet(url3, 3, LOWEST));
      spdy::SpdySerializedFrame partitioned_response3(
          spdy_util2.ConstructSpdyGetReply(nullptr, 0, 3));
      spdy::SpdySerializedFrame partitioned_body3(
          spdy_util2.ConstructSpdyDataFrame(3, "3", true));

      const MockWrite kPartitionedWrites1[] = {
          CreateMockWrite(partitioned_req1, 0),
          CreateMockWrite(partitioned_req3, 3),
      };

      const MockRead kPartitionedReads1[] = {
          CreateMockRead(partitioned_response1, 1),
          CreateMockRead(partitioned_body1, 2),
          CreateMockRead(partitioned_response3, 4),
          CreateMockRead(partitioned_body3, 5),
          MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6),
      };

      SpdyTestUtil spdy_util3(/*use_priority_header=*/true);
      spdy::SpdySerializedFrame partitioned_req2(
          spdy_util3.ConstructSpdyGet(url2, 1, LOWEST));
      spdy::SpdySerializedFrame partitioned_response2(
          spdy_util3.ConstructSpdyGetReply(nullptr, 0, 1));
      spdy::SpdySerializedFrame partitioned_body2(
          spdy_util3.ConstructSpdyDataFrame(1, "2", true));

      const MockWrite kPartitionedWrites2[] = {
          CreateMockWrite(partitioned_req2, 0),
      };

      const MockRead kPartitionedReads2[] = {
          CreateMockRead(partitioned_response2, 1),
          CreateMockRead(partitioned_body2, 2),
          MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),
      };

      SequencedSocketData partitioned_data1(kPartitionedReads1,
                                            kPartitionedWrites1);
      SequencedSocketData partitioned_data2(kPartitionedReads2,
                                            kPartitionedWrites2);

      // No need to segment SSLDataProviders by whether or not partitioning is
      // enabled.
      SSLSocketDataProvider ssl_data1(ASYNC, OK);
      ssl_data1.next_proto = kProtoHTTP2;
      SSLSocketDataProvider ssl_data2(ASYNC, OK);
      ssl_data2.next_proto = kProtoHTTP2;

      if (partition_connections) {
        session_deps_.socket_factory->AddSocketDataProvider(&partitioned_data1);
        session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
        session_deps_.socket_factory->AddSocketDataProvider(&partitioned_data2);
        session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
      } else {
        session_deps_.socket_factory->AddSocketDataProvider(
            &unpartitioned_data);
        session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
      }

      TestCompletionCallback callback;
      HttpRequestInfo request1;
      request1.method = "GET";
      request1.url = GURL(url1);
      request1.traffic_annotation =
          MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
      request1.network_isolation_key = network_isolation_key1;
      request1.network_anonymization_key = network_anonymization_key1;

      auto trans1 =
          std::make_unique<HttpNetworkTransaction>(LOWEST, session.get());
      int rv =
          trans1->Start(&request1, callback.callback(), NetLogWithSource());
      EXPECT_THAT(callback.GetResult(rv), IsOk());
      std::string response_data1;
      EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
      EXPECT_EQ("1", response_data1);
      trans1.reset();

      HttpRequestInfo request2;
      request2.method = "GET";
      request2.url = GURL(url2);
      request2.traffic_annotation =
          MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
      request2.network_isolation_key = network_isolation_key2;
      request2.network_anonymization_key = network_anonymization_key2;
      auto trans2 =
          std::make_unique<HttpNetworkTransaction>(LOWEST, session.get());
      rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
      EXPECT_THAT(callback.GetResult(rv), IsOk());
      std::string response_data2;
      EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
      EXPECT_EQ("2", response_data2);
      trans2.reset();

      HttpRequestInfo request3;
      request3.method = "GET";
      request3.url = GURL(url3);
      request3.traffic_annotation =
          MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
      request3.network_isolation_key = network_isolation_key1;
      request3.network_anonymization_key = network_anonymization_key1;

      auto trans3 =
          std::make_unique<HttpNetworkTransaction>(LOWEST, session.get());
      rv = trans3->Start(&request3, callback.callback(), NetLogWithSource());
      EXPECT_THAT(callback.GetResult(rv), IsOk());
      std::string response_data3;
      EXPECT_THAT(ReadTransaction(trans3.get(), &response_data3), IsOk());
      EXPECT_EQ("3", response_data3);
      trans3.reset();
    }
  }
}

// Preconnect two sockets with different NetworkAnonymizationKeys when
// features::kPartitionConnectionsByNetworkIsolationKey is enabled. Then
// issue a request and make sure the correct socket is used. Loops three times,
// expecting to use the first preconnect, second preconnect, and neither.
TEST_P(HttpNetworkTransactionTest, NetworkIsolationPreconnect) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEn
```