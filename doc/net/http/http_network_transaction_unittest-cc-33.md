Response:
My thinking process to analyze the provided C++ code and answer the request goes through these stages:

1. **Understand the Core Purpose:**  I first recognize that this is a unit test file (`_unittest.cc`) for the `HttpNetworkTransaction` class in Chromium's networking stack. Unit tests are designed to verify the behavior of specific code units in isolation. Therefore, the primary function of this file is to test various aspects of how `HttpNetworkTransaction` handles HTTP requests and responses.

2. **Identify Key Components and Concepts:** I scan the code for recurring elements and important networking concepts. I see:
    * `HttpNetworkTransaction`: The central class being tested.
    * `HttpRequestInfo`:  Represents an outgoing HTTP request.
    * `HttpResponseInfo`: Represents an incoming HTTP response.
    * `HttpNetworkSession`:  Manages the overall HTTP session, including connection pooling.
    * `MockWrite` and `MockRead`:  Simulate network socket I/O for testing. These are crucial for controlling the server's "responses" and the client's "writes."
    * `SequencedSocketData`, `StaticSocketDataProvider`, `SSLSocketDataProvider`: Provide structured ways to define the mock network data.
    * `TestCompletionCallback`: Used for asynchronous operations in testing.
    * `ProxyInfo`, `ProxyChain`, `ProxyServer`: Related to proxy configurations and IP protection.
    * DNS aliases: A specific feature being tested.
    * IP Protection:  Another specific feature with associated headers.
    * `base::test::ScopedFeatureList`:  Used for enabling/disabling features during tests.

3. **Categorize the Tests:** I start to mentally group the tests based on the specific functionality they are testing. This helps in summarizing the file's purpose:
    * Basic request/response handling.
    * Client certificate authentication.
    * Handling long-lived connections.
    * DNS alias functionality.
    * Proxy configurations (direct, proxied, IP protection).
    * IP Protection header behavior.
    * Feature flag specific tests (like Happy Eyeballs V3).

4. **Analyze Individual Tests (Example):** I pick a representative test, like `RequestWithDnsAliases`, and break down its logic:
    * **Setup:** Creates an `HttpRequestInfo` object and sets up a host resolver rule with DNS aliases. It then creates an `HttpNetworkSession` and an `HttpNetworkTransaction`.
    * **Mock Data:** Defines `MockWrite` and `MockRead` arrays to simulate the client sending a request and the server responding.
    * **Execution:** Starts the transaction, waits for it to complete.
    * **Verification:**  Gets the `HttpResponseInfo` and checks if the `dns_aliases` field contains the expected aliases.

5. **Identify JavaScript Relevance:** I consider how these low-level networking details relate to JavaScript. Web browsers (where JavaScript runs) use the Chromium networking stack. Therefore, the behavior tested here directly affects how JavaScript code interacts with the network. For example:
    * When a JavaScript `fetch()` or `XMLHttpRequest` makes a request, the underlying `HttpNetworkTransaction` handles the actual HTTP communication.
    * DNS aliases configured on the server will be reflected in the `dns_aliases` of the response, which *could* be exposed through browser APIs (though direct exposure is less common).
    * Proxy configurations and IP protection directly impact how the browser connects to websites, and while JavaScript might not directly control these, it's subject to their effects.

6. **Construct Examples (Hypothetical Input/Output):**  For a test like `RequestWithDnsAliases`, I can imagine a simplified scenario:
    * **Input:**  A JavaScript `fetch("http://www.example.org/")` call. The host resolver is configured to map `www.example.org` to an IP with aliases `alias1` and `alias2`.
    * **Output:** The browser successfully retrieves the content from `www.example.org`. Internally, the `HttpResponseInfo` will contain the DNS aliases. While the JavaScript code might not directly see `response.dns_aliases`, this information could be used by the browser for internal purposes (e.g., connection pooling).

7. **Identify Potential User/Programming Errors:** I think about common mistakes developers make when dealing with networking:
    * Incorrect URLs.
    * Missing or incorrect headers.
    * Not handling asynchronous operations correctly (leading to race conditions or unhandled errors).
    * Misunderstanding proxy configurations.
    * Issues with SSL/TLS certificates.

8. **Trace User Actions (Debugging):** I consider how a user action might lead to this code being executed:
    * A user types a URL in the address bar and hits Enter.
    * A JavaScript application makes an HTTP request.
    * The browser needs to authenticate a user via a client certificate.
    * The browser is using a proxy server.
    * The browser is attempting to use IP Protection.

9. **Synthesize the Summary:** Finally, I synthesize all the information into a concise summary, focusing on the core function of the file (testing `HttpNetworkTransaction`) and the key areas it covers. I also note that it's the *last* of a series of test files, implying comprehensive coverage.

This iterative process of understanding the code's purpose, identifying key elements, categorizing tests, analyzing specifics, and then relating it to the broader context (JavaScript, user actions, debugging) allows me to generate a comprehensive and accurate answer to the request.
这是位于 `net/http/http_network_transaction_unittest.cc` 的 Chromium 网络栈源代码文件，它是 **第 34 部分，共 34 部分**，这意味着它是这个单元测试文件的最后一部分，很可能包含了一些特定或不太常见场景的测试。

**功能归纳:**

总的来说，这个文件的主要功能是 **测试 `HttpNetworkTransaction` 类的各种行为和功能**。`HttpNetworkTransaction` 是 Chromium 中负责执行单个 HTTP 请求的核心类。  由于这是最后一部分，它可能涵盖了以下几种类型的测试：

* **复杂的认证场景:**  例如，客户端证书认证，以及在认证后保持连接并进行后续请求。
* **DNS 别名处理:** 测试当 DNS 解析返回多个别名时，`HttpNetworkTransaction` 如何处理这些别名。
* **Proxy 相关功能:**  测试 `HttpNetworkTransaction` 如何处理各种代理配置，包括直接连接、普通代理和 IP 保护代理。
* **IP 保护 (IP Privacy) 功能:** 测试在启用 IP 保护功能时，请求头是否按照预期添加了 `IP-Protection` 标头。
* **Feature Flag 相关的测试:**  测试在特定 Feature Flag 开启或关闭时的行为差异，例如 Happy Eyeballs V3。

**具体功能列表 (基于代码片段):**

1. **客户端证书认证后的连接保持和后续请求:**
   - 测试在收到服务器的客户端证书请求后，`HttpNetworkTransaction` 如何使用提供的证书重新启动请求。
   - 测试在客户端证书认证完成后，连接是否可以被保持，并用于后续的请求 (例如 `/post-auth`)。

2. **处理 DNS 别名:**
   - 测试当主机名配置了 DNS 别名时，`HttpNetworkTransaction` 是否能正确连接到服务器。
   - 测试响应信息中是否正确记录了 DNS 别名。

3. **设置 Proxy 信息到响应中:**
   - 测试 `HttpNetworkTransaction::SetProxyInfoInResponse` 函数在不同代理场景下的行为：
     - 直接连接
     - 使用代理连接
     - 空的 `ProxyInfo`
     - IP 保护代理连接
     - IP 保护直接连接

4. **IP 保护请求头处理:**
   - 测试当请求通过 IP 保护代理发送时，是否添加了 `IP-Protection: 1` 请求头（在 Feature Flag 启用的情况下）。
   - 测试当 IP 保护功能禁用时，即使通过 IP 保护代理，也不会添加 `IP-Protection` 请求头。
   - 测试对于标记为 IP 保护的直接请求，不会添加 `IP-Protection` 请求头。
   - 测试当尝试通过 IP 保护代理失败后回退到直接连接时，不会添加 `IP-Protection` 请求头。

5. **Happy Eyeballs V3 功能测试:**
   - 测试在启用 Happy Eyeballs V3 功能时，`HttpNetworkTransaction` 的行为，例如成功切换到 HTTP Stream Pool。

**与 JavaScript 的关系及举例说明:**

虽然这个文件是 C++ 代码，但它测试的网络功能是 Web 浏览器（包括运行 JavaScript 的环境）的核心组成部分。  JavaScript 通过浏览器提供的 API (如 `fetch` 或 `XMLHttpRequest`) 发起网络请求，而底层的 `HttpNetworkTransaction` 负责处理这些请求的细节。

* **客户端证书认证:** 当一个网站要求客户端证书进行认证时，浏览器会提示用户选择证书。用户选择后，浏览器会将证书信息传递给底层的网络栈，`HttpNetworkTransaction` 的相关逻辑会被触发，使用证书重新发起请求。  JavaScript 代码可能感知到的是 `fetch` 或 `XMLHttpRequest` 的状态变化，例如从 pending 到 success。
    ```javascript
    // JavaScript 发起需要客户端证书的请求
    fetch('https://example.com/protected', {
      // ... 其他配置
    })
    .then(response => {
      console.log('请求成功', response);
    })
    .catch(error => {
      console.error('请求失败', error);
      // 如果需要客户端证书，可能会先收到一个认证相关的错误
    });
    ```

* **DNS 别名:** 虽然 JavaScript 代码通常不会直接访问 DNS 别名信息，但浏览器内部可能会使用这些信息来优化连接重用或进行其他决策。  例如，如果 `www.example.org` 和 `alias1` 指向同一个 IP，浏览器可能会尝试重用已有的连接。

* **Proxy 和 IP 保护:**  用户在浏览器设置中配置的代理服务器会影响所有通过浏览器发起的网络请求。IP 保护作为一种隐私保护技术，也会在网络层影响请求的发送方式。  JavaScript 代码无需关心这些底层细节，只需要像往常一样发起请求，浏览器会自动处理代理和 IP 保护的逻辑。

**逻辑推理、假设输入与输出:**

**测试用例: `RequestWithDnsAliases`**

* **假设输入:**
    * 一个 `HttpRequestInfo` 对象，请求 `http://www.example.org/`。
    * Host Resolver 配置了 `www.example.org` 解析到 `127.0.0.1`，并带有别名 `alias1` 和 `alias2`。
    * 模拟的服务器响应包含 HTTP 200 OK，Content-Type 和 Content-Length 等头部。
* **逻辑推理:** `HttpNetworkTransaction` 应该能够使用主域名 `www.example.org` 连接到服务器。当接收到响应后，`HttpResponseInfo` 对象应该记录下解析到的所有 DNS 别名。
* **预期输出:**
    * 请求成功完成 (返回 `OK`)。
    * `HttpResponseInfo` 对象的 `dns_aliases` 成员应该包含 "alias1", "alias2", "www.example.org" 这三个字符串。

**用户或编程常见的使用错误:**

* **未正确处理客户端证书认证失败:**  如果服务器要求客户端证书但用户没有提供或提供了错误的证书，`HttpNetworkTransaction` 会返回 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 错误。开发者需要捕获这个错误并引导用户选择正确的证书。
* **代理配置错误导致连接失败:** 用户或程序可能配置了错误的代理服务器地址或端口，导致 `HttpNetworkTransaction` 无法建立连接。常见的错误码包括 `ERR_PROXY_CONNECTION_FAILED` 等。
* **在需要 HTTPS 的情况下使用了 HTTP:**  如果网站强制使用 HTTPS，而 JavaScript 代码尝试使用 HTTP 发起请求，浏览器会阻止请求或自动升级到 HTTPS。
* **CORS 错误:**  虽然与 `HttpNetworkTransaction` 直接关联不大，但跨域请求 (CORS) 是 JavaScript 网络编程中常见的问题。服务器需要正确配置 CORS 头部，否则浏览器会阻止 JavaScript 代码访问响应内容。

**用户操作如何一步步到达这里 (调试线索):**

假设用户尝试访问一个需要客户端证书认证的 HTTPS 网站：

1. **用户在浏览器地址栏输入 URL 并回车。**
2. **浏览器解析 URL，发现是 HTTPS 协议。**
3. **浏览器尝试与服务器建立 TCP 连接。**
4. **在 TLS 握手过程中，服务器发送 `CertificateRequest` 消息，要求客户端提供证书。**
5. **Chromium 的网络栈接收到服务器的请求，`HttpNetworkTransaction` 意识到需要客户端证书。**
6. **浏览器的用户界面显示一个对话框，提示用户选择客户端证书。**
7. **用户选择一个证书并确认。**
8. **浏览器将用户选择的证书信息传递给 `HttpNetworkTransaction`。**
9. **`HttpNetworkTransaction` 使用提供的证书重新启动 TLS 握手和 HTTP 请求。**
10. **如果证书验证成功，服务器返回 HTTP 响应。**
11. **`HttpNetworkTransaction` 处理响应，并将数据传递给浏览器的渲染引擎。**

在调试客户端证书认证问题时，可以关注以下几点：

* **NetLog:**  Chromium 的 NetLog 可以记录详细的网络事件，包括 TLS 握手过程、证书选择等，可以帮助诊断问题。
* **抓包工具 (如 Wireshark):**  可以查看客户端和服务器之间的网络通信，确认是否正确发送了客户端证书。
* **浏览器开发者工具:**  "Security" 面板可以查看网站的证书信息和连接安全状态。

**总结 (针对第 34 部分):**

作为单元测试文件的最后一部分，这个文件着重于测试 `HttpNetworkTransaction` 类在一些更特定和复杂的场景下的行为，例如客户端证书认证后的连接保持、DNS 别名处理以及与 IP 保护代理相关的请求头处理。它还包含了针对特定 Feature Flag (如 Happy Eyeballs V3) 的测试。 这表明在整个 `http_network_transaction_unittest.cc` 文件中，测试的范围从基础的 HTTP 请求处理逐渐扩展到更高级和特定的网络功能。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第34部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
Connection: close\r\n"
               "Content-Length: 4\r\n\r\n"
               "auth"),
  };
  SequencedSocketData data_retry(kRetryReads, kRetryWrites);
  SSLSocketDataProvider ssl_retry(ASYNC, OK);
  ssl_retry.expected_send_client_cert = true;
  ssl_retry.expected_client_cert = identity->certificate();
  session_deps_.socket_factory->AddSocketDataProvider(&data_retry);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_retry);

  // /post-auth gets its own socket.
  const MockWrite kPostAuthWrites[] = {
      MockWrite(ASYNC, 0,
                "GET /post-auth HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kPostAuthReads[] = {
      MockRead(ASYNC, 1,
               "HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 9\r\n\r\n"
               "post-auth"),
  };
  SequencedSocketData data_post_auth(kPostAuthReads, kPostAuthWrites);
  SSLSocketDataProvider ssl_post_auth(ASYNC, OK);
  ssl_post_auth.expected_send_client_cert = true;
  ssl_post_auth.expected_client_cert = identity->certificate();
  session_deps_.socket_factory->AddSocketDataProvider(&data_post_auth);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_post_auth);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Start the two long-lived requests.
  TestCompletionCallback callback_long_lived;
  auto trans_long_lived =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans_long_lived->Start(
      &request_long_lived, callback_long_lived.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  data_long_lived.RunUntilPaused();

  TestCompletionCallback callback_long_lived_bar;
  auto trans_long_lived_bar =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans_long_lived_bar->Start(&request_long_lived_bar,
                                   callback_long_lived_bar.callback(),
                                   NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  data_bar.RunUntilPaused();

  // Request /auth. This gives a client certificate challenge.
  TestCompletionCallback callback_auth;
  auto trans_auth =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans_auth->Start(&request_auth, callback_auth.callback(),
                         NetLogWithSource());
  EXPECT_THAT(callback_auth.GetResult(rv),
              IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Make an unauthenticated request. This completes.
  TestCompletionCallback callback_unauth;
  auto trans_unauth =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans_unauth->Start(&request_unauth, callback_unauth.callback(),
                           NetLogWithSource());
  EXPECT_THAT(callback_unauth.GetResult(rv), IsOk());
  std::string response_unauth;
  EXPECT_THAT(ReadTransaction(trans_unauth.get(), &response_unauth), IsOk());
  EXPECT_EQ("unauth", response_unauth);
  trans_unauth.reset();

  // Complete the authenticated request.
  rv = trans_auth->RestartWithCertificate(identity->certificate(),
                                          identity->ssl_private_key(),
                                          callback_auth.callback());
  EXPECT_THAT(callback_auth.GetResult(rv), IsOk());
  std::string response_auth;
  EXPECT_THAT(ReadTransaction(trans_auth.get(), &response_auth), IsOk());
  EXPECT_EQ("auth", response_auth);
  trans_auth.reset();

  // Complete the long-lived requests.
  data_long_lived.Resume();
  EXPECT_THAT(callback_long_lived.GetResult(ERR_IO_PENDING), IsOk());
  std::string response_long_lived;
  EXPECT_THAT(ReadTransaction(trans_long_lived.get(), &response_long_lived),
              IsOk());
  EXPECT_EQ("long-lived", response_long_lived);
  trans_long_lived.reset();

  data_bar.Resume();
  EXPECT_THAT(callback_long_lived_bar.GetResult(ERR_IO_PENDING), IsOk());
  std::string response_long_lived_bar;
  EXPECT_THAT(
      ReadTransaction(trans_long_lived_bar.get(), &response_long_lived_bar),
      IsOk());
  EXPECT_EQ("long-lived", response_long_lived_bar);
  trans_long_lived_bar.reset();

  // Run the post-authentication requests.
  TestCompletionCallback callback_post_auth;
  auto trans_post_auth =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans_post_auth->Start(&request_post_auth, callback_post_auth.callback(),
                              NetLogWithSource());
  EXPECT_THAT(callback_post_auth.GetResult(rv), IsOk());
  std::string response_post_auth;
  EXPECT_THAT(ReadTransaction(trans_post_auth.get(), &response_post_auth),
              IsOk());
  EXPECT_EQ("post-auth", response_post_auth);
  trans_post_auth.reset();

  TestCompletionCallback callback_post_auth_bar;
  auto trans_post_auth_bar =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans_post_auth_bar->Start(&request_post_auth_bar,
                                  callback_post_auth_bar.callback(),
                                  NetLogWithSource());
  EXPECT_THAT(callback_post_auth_bar.GetResult(rv), IsOk());
  std::string response_post_auth_bar;
  EXPECT_THAT(
      ReadTransaction(trans_post_auth_bar.get(), &response_post_auth_bar),
      IsOk());
  EXPECT_EQ("post-auth", response_post_auth_bar);
  trans_post_auth_bar.reset();
}

TEST_P(HttpNetworkTransactionTest, RequestWithDnsAliases) {
  // Create a request.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Add a rule with DNS aliases to the host resolver.
  std::vector<std::string> aliases({"alias1", "alias2", "www.example.org"});
  session_deps_.host_resolver->rules()->AddIPLiteralRuleWithDnsAliases(
      "www.example.org", "127.0.0.1", std::move(aliases));

  // Create a HttpNetworkSession.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Create a transaction.
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Prepare the expected data to be written and read. The client should send
  // the request below.
  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // The server should respond with the following.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  TestCompletionCallback callback;

  // Start the transaction.
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Wait for completion.
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Get the response info.
  const HttpResponseInfo* response = trans.GetResponseInfo();

  // Verify that the alias list was stored in the response info as expected.
  ASSERT_TRUE(response);
  EXPECT_THAT(response->dns_aliases,
              testing::ElementsAre("alias1", "alias2", "www.example.org"));
}

TEST_P(HttpNetworkTransactionTest, RequestWithNoAdditionalDnsAliases) {
  // Create a request.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Add a rule without DNS aliases to the host resolver.
  session_deps_.host_resolver->rules()->AddRule("www.example.org", "127.0.0.1");

  // Create a HttpNetworkSession.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Create a transaction.
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Prepare the expected data to be written and read. The client should send
  // the request below.
  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // The server should respond with the following.
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  TestCompletionCallback callback;

  // Start the transaction.
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Wait for completion.
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Get the response info.
  const HttpResponseInfo* response = trans.GetResponseInfo();

  // Verify that the alias list was stored in the response info as expected.
  ASSERT_TRUE(response);
  EXPECT_THAT(response->dns_aliases, testing::ElementsAre("www.example.org"));
}

// Test behavior of SetProxyInfoInResponse with a direct connection.
TEST_P(HttpNetworkTransactionTest, SetProxyInfoInResponse_Direct) {
  ProxyInfo proxy_info;
  proxy_info.UseDirect();
  HttpResponseInfo response_info;
  HttpNetworkTransaction::SetProxyInfoInResponse(proxy_info, &response_info);
  EXPECT_EQ(response_info.WasFetchedViaProxy(), false);
  EXPECT_EQ(response_info.proxy_chain.is_for_ip_protection(), false);
  EXPECT_EQ(response_info.proxy_chain, ProxyChain::Direct());
}

// Test behavior of SetProxyInfoInResponse with a proxied connection.
TEST_P(HttpNetworkTransactionTest, SetProxyInfoInResponse_Proxied) {
  ProxyInfo proxy_info;
  ProxyChain proxy_chain =
      ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_HTTPS, "prx", 443);
  proxy_info.UseProxyChain(proxy_chain);
  HttpResponseInfo response_info;
  HttpNetworkTransaction::SetProxyInfoInResponse(proxy_info, &response_info);
  EXPECT_EQ(response_info.WasFetchedViaProxy(), true);
  EXPECT_EQ(response_info.proxy_chain.is_for_ip_protection(), false);
  EXPECT_EQ(response_info.proxy_chain, proxy_chain);
}

// Test behavior of SetProxyInfoInResponse with an empty ProxyInfo.
TEST_P(HttpNetworkTransactionTest, SetProxyInfoInResponse_Empty) {
  ProxyInfo empty_proxy_info;
  HttpResponseInfo response_info;
  HttpNetworkTransaction::SetProxyInfoInResponse(empty_proxy_info,
                                                 &response_info);
  EXPECT_EQ(response_info.WasFetchedViaProxy(), false);
  EXPECT_EQ(response_info.proxy_chain.is_for_ip_protection(), false);
  EXPECT_FALSE(response_info.proxy_chain.IsValid());
}

// Test behavior of SetProxyInfoInResponse with a proxied connection for IP
// protection.
TEST_P(HttpNetworkTransactionTest, SetProxyInfoInResponse_IpProtectionProxied) {
  ProxyInfo proxy_info;
  ProxyChain ip_protection_proxy_chain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_HTTPS, "prx", 443)});
  proxy_info.UseProxyChain(ip_protection_proxy_chain);
  HttpResponseInfo response_info;
  HttpNetworkTransaction::SetProxyInfoInResponse(proxy_info, &response_info);
  EXPECT_EQ(response_info.WasFetchedViaProxy(), true);
  EXPECT_EQ(response_info.proxy_chain.is_for_ip_protection(), true);
  EXPECT_EQ(response_info.proxy_chain, ip_protection_proxy_chain);
}

// Test behavior of SetProxyInfoInResponse with a direct connection for IP
// protection.
TEST_P(HttpNetworkTransactionTest, SetProxyInfoInResponse_IpProtectionDirect) {
  ProxyInfo proxy_info;
  const ProxyChain kIpProtectionDirectChain = ProxyChain::ForIpProtection({});
  proxy_info.UseProxyChain(kIpProtectionDirectChain);
  HttpResponseInfo response_info;
  HttpNetworkTransaction::SetProxyInfoInResponse(proxy_info, &response_info);
  EXPECT_EQ(response_info.WasFetchedViaProxy(), false);
  EXPECT_EQ(response_info.proxy_chain.is_for_ip_protection(), true);
  EXPECT_EQ(response_info.proxy_chain, kIpProtectionDirectChain);
}

class IpProtectionProxyDelegate : public TestProxyDelegate {
 public:
  IpProtectionProxyDelegate() {
    set_extra_header_name(HttpRequestHeaders::kAuthorization);
  }

  // ProxyDelegate implementation:
  void OnResolveProxy(const GURL& url,
                      const NetworkAnonymizationKey& network_anonymization_key,
                      const std::string& method,
                      const ProxyRetryInfoMap& proxy_retry_info,
                      ProxyInfo* result) override {
    ProxyList proxy_list;
    proxy_list.AddProxyChain(proxy_chain());

    // For IP Protection we always want to fallback to direct, so emulate the
    // behavior of NetworkServiceProxyDelegate where a direct chain will always
    // be added as the last ProxyList entry.
    if (!proxy_chain().is_direct()) {
      proxy_list.AddProxyChain(ProxyChain::Direct());
    }

    result->UseProxyList(proxy_list);
  }

  static std::string GetAuthorizationHeaderValue(
      const ProxyServer& proxy_server) {
    return GetExtraHeaderValue(proxy_server);
  }
};

// Test that for requests sent through an IP Protection proxy, the
// 'IP-Protection' header is sent as expected when the feature is enabled.
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyIpProtectionRequestHeaderAddedWhenEnabled) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kEnableIpProtectionProxy,
      {{features::kIpPrivacyAddHeaderToProxiedRequests.name, "true"}});

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({kProxyServer1, kProxyServer2});

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_delegate = std::make_unique<IpProtectionProxyDelegate>();
  auto* proxy_delegate = static_cast<IpProtectionProxyDelegate*>(
      session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(kNestedProxyChain);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const std::string kProxyServer1AuthHeaderValue =
      IpProtectionProxyDelegate::GetAuthorizationHeaderValue(kProxyServer1);
  const std::string kProxyServer2AuthHeaderValue =
      IpProtectionProxyDelegate::GetAuthorizationHeaderValue(kProxyServer2);

  const std::string kProxyServer2Connect = base::StringPrintf(
      "CONNECT proxy2.test:71 HTTP/1.1\r\n"
      "Host: proxy2.test:71\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "Authorization: %s\r\n\r\n",
      kProxyServer1AuthHeaderValue.c_str());
  const std::string kEndpointConnect = base::StringPrintf(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "Authorization: %s\r\n\r\n",
      kProxyServer2AuthHeaderValue.c_str());

  MockWrite data_writes[] = {
      MockWrite(kProxyServer2Connect.c_str()),
      MockWrite(kEndpointConnect.c_str()),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "IP-Protection: 1\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead("HTTP/1.1 200\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
}

// Test that for direct requests that are marked as being for IP Protection, the
// 'IP-Protection' header is not sent even when the feature is enabled. This
// test should be removed once `kIpPrivacyDirectOnly` is.
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyIpProtectionRequestHeaderNotAddedForIpProtectionDirect) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kEnableIpProtectionProxy,
      {{features::kIpPrivacyAddHeaderToProxiedRequests.name, "true"},
       {features::kIpPrivacyDirectOnly.name, "true"}});

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const auto kIpProtectionDirectChain =
      ProxyChain::ForIpProtection(std::vector<ProxyServer>());

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_delegate = std::make_unique<IpProtectionProxyDelegate>();
  auto* proxy_delegate = static_cast<IpProtectionProxyDelegate*>(
      session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(kIpProtectionDirectChain);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
}

// Test that for requests sent through an IP Protection proxy, the
// 'IP-Protection' header is not sent if the feature is disabled.
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyIpProtectionRequestHeaderNotAddedIfFeatureDisabled) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kEnableIpProtectionProxy,
      {{features::kIpPrivacyAddHeaderToProxiedRequests.name, "false"}});

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({kProxyServer1, kProxyServer2});

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_delegate = std::make_unique<IpProtectionProxyDelegate>();
  auto* proxy_delegate = static_cast<IpProtectionProxyDelegate*>(
      session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(kNestedProxyChain);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const std::string kProxyServer1AuthHeaderValue =
      IpProtectionProxyDelegate::GetAuthorizationHeaderValue(kProxyServer1);
  const std::string kProxyServer2AuthHeaderValue =
      IpProtectionProxyDelegate::GetAuthorizationHeaderValue(kProxyServer2);

  const std::string kProxyServer2Connect = base::StringPrintf(
      "CONNECT proxy2.test:71 HTTP/1.1\r\n"
      "Host: proxy2.test:71\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "Authorization: %s\r\n\r\n",
      kProxyServer1AuthHeaderValue.c_str());
  const std::string kEndpointConnect = base::StringPrintf(
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "Authorization: %s\r\n\r\n",
      kProxyServer2AuthHeaderValue.c_str());

  MockWrite data_writes[] = {
      MockWrite(kProxyServer2Connect.c_str()),
      MockWrite(kEndpointConnect.c_str()),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead("HTTP/1.1 200\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, data_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
}

// Test that for a request that fails to be sent through an IP Protection proxy,
// after we fallback to direct the 'IP-Protection' header is not added to the
// request headers.
TEST_P(HttpNetworkTransactionTest,
       HttpsNestedProxyIpProtectionRequestHeaderNotAddedAfterFallback) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kEnableIpProtectionProxy,
      {{features::kIpPrivacyAddHeaderToProxiedRequests.name, "true"}});
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 70)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 71)};
  ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({kProxyServer1, kProxyServer2});

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.proxy_delegate = std::make_unique<IpProtectionProxyDelegate>();
  auto* proxy_delegate = static_cast<IpProtectionProxyDelegate*>(
      session_deps_.proxy_delegate.get());
  proxy_delegate->set_proxy_chain(kNestedProxyChain);
  session_deps_.proxy_resolution_service->SetProxyDelegate(proxy_delegate);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const std::string kProxyServer1AuthHeaderValue =
      IpProtectionProxyDelegate::GetAuthorizationHeaderValue(kProxyServer1);

  const std::string kProxyServer2Connect = base::StringPrintf(
      "CONNECT proxy2.test:71 HTTP/1.1\r\n"
      "Host: proxy2.test:71\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "Authorization: %s\r\n\r\n",
      kProxyServer1AuthHeaderValue.c_str());

  MockWrite data_writes1[] = {
      MockWrite(kProxyServer2Connect.c_str()),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Not Authorized\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl1(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);

  // The proxy delegate should implement falling back to direct after an error,
  // and we don't expect any proxying or an IP Protection request header on the
  // GET.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(),
                       NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
}

// Tests specific to the HappyEyeballsV3 feature.
// TODO(crbug.com/346835898): Find ways to run more tests with the
// HappyEyeballsV3 feature enabled.
class HttpNetworkTransactionPoolTest : public HttpNetworkTransactionTest {
 public:
  HttpNetworkTransactionPoolTest() {
    feature_list_.InitAndEnableFeature(features::kHappyEyeballsV3);
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpNetworkTransactionPoolTest,
                         ::testing::ValuesIn(GetTestParams()));

TEST_P(HttpNetworkTransactionPoolTest, SwitchToHttpStreamPool) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("hello world", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads);
  EXPECT_EQ(reads_size, out.total_received_bytes);
  EXPECT_EQ(0u, out.connection_attempts.size());

  EXPECT_FALSE(out.remote_endpoint_after_start.address().empty());
}

}  // namespace net
```