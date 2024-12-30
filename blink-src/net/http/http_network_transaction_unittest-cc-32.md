Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's network stack. I need to analyze the code and identify its purpose. Specifically, I need to look for:

1. **Main functionalities:** What aspects of HTTP network transactions are being tested?
2. **Relationship to JavaScript:**  Does this code interact with JavaScript, and if so, how?
3. **Logical Inferences:** Are there any scenarios with defined inputs and expected outputs?
4. **Common Usage Errors:** What mistakes might users or programmers make that could lead to this code being executed?
5. **User Actions Leading Here:**  How does a user's interaction with the browser eventually trigger this code path?
6. **Overall Functionality (for the current snippet):**  What is the purpose of this specific part of the code?

Looking at the code, it appears to be focused on testing the behavior of `HttpNetworkTransaction` in various scenarios, especially related to connection reuse and SSL configurations. The `TEST_P` macros suggest these are parameterized tests. Key aspects being tested include:

* **Preconnect:** How `HttpNetworkTransaction` interacts with pre-established connections.
* **Network Isolation Keys and Network Anonymization Keys:**  Ensuring these keys are correctly used for connection partitioning, especially with SSL.
* **SSL Configuration Changes:**  Testing how `HttpNetworkTransaction` handles changes in SSL configuration, including during active transactions and pending connections.
* **Post-Handshake Client Certificates:** Verifying the correct behavior when a server requests a client certificate after the initial SSL handshake, particularly with existing sockets.

Now, let's address the specific points in the prompt:

* **Functionality:** The code tests various aspects of managing HTTP connections, including connection reuse (preconnect), network isolation, and handling dynamic SSL configuration changes.
* **Relationship to JavaScript:** This C++ code is part of the browser's network stack. While not directly JavaScript, it's crucial for handling network requests initiated by JavaScript. When a JavaScript makes an HTTP request (e.g., using `fetch` or `XMLHttpRequest`), this C++ code is responsible for carrying out the request.
* **Logical Inferences:** The tests set up specific scenarios with mock network responses. For example, the preconnect tests have different `TestCase` enums to simulate using the first preconnect, the second, or none. The SSL tests verify that connections are correctly isolated based on `NetworkAnonymizationKey`.
* **User/Programming Errors:**  A common programming error could be incorrectly setting the `NetworkIsolationKey` or `NetworkAnonymizationKey` when initiating a network request. This could lead to unexpected connection reuse or isolation behavior. Users might encounter errors if the website they are trying to access requires a client certificate, and the browser doesn't have the correct certificate configured.
* **User Actions:** A user navigating to a website, clicking a link, or a webpage making an AJAX request can all lead to the execution of this network code. Specifically, the post-handshake client certificate test might be triggered when a user accesses a resource protected by mutual TLS authentication.
* **Overall Functionality of this Part:** This specific snippet seems to be concluding the section on testing various aspects of `HttpNetworkTransaction`, particularly focusing on complex scenarios involving connection reuse with preconnects, network isolation with SSL, dynamic SSL configuration changes, and handling post-handshake client certificate requests.

Finally, the prompt mentions "This is the 33rd part,共34部分". This implies this is the penultimate section of a larger test suite for `net/http/http_network_transaction_unittest.cc`. The functionality of this part likely builds upon the concepts and tests covered in the preceding sections.
这是文件 `net/http/http_network_transaction_unittest.cc` 的一部分，主要功能是**测试 `HttpNetworkTransaction` 类的各种行为和功能**。`HttpNetworkTransaction` 是 Chromium 网络栈中负责执行单个 HTTP 请求的核心类。

**具体到这部分代码，它主要测试了以下功能:**

1. **预连接 (Preconnect) 的使用:**
   - 测试 `HttpNetworkTransaction` 是否能正确利用已经建立的预连接 (preconnect) 的 Socket。
   - 通过不同的 `TestCase` 枚举值 (`kUseFirstPreconnect`, `kUseSecondPreconnect`, `kDontUsePreconnect`)，模拟请求使用第一个预连接、第二个预连接或不使用预连接的情况。
   - 验证在不同的情况下，Socket 连接池中的空闲 Socket 数量是否符合预期。

2. **网络隔离键 (NetworkIsolationKey) 和网络匿名化键 (NetworkAnonymizationKey) 对 SSL 连接的影响:**
   - 测试当启用了 `kPartitionConnectionsByNetworkIsolationKey` 特性时，`NetworkAnonymizationKey` 是否被正确传递到 `SSLConfig`，从而实现基于不同源的 SSL 会话缓存隔离。
   - 通过创建来自不同源 (`kSite1`, `kSite2`) 的请求，并验证它们是否使用了不同的 SSL Socket 连接，来确保隔离生效。
   - 同时测试了通过代理服务器连接的情况，确保 `NetworkAnonymizationKey` 在代理场景下也能正确传递。

3. **SSL 配置更改 (SSLConfig Changed) 的处理:**
   - 测试 `HttpNetworkTransaction` 是否能正确处理 `SSLConfigService` 发出的 SSL 配置更改通知。
   - 验证即使在有活跃的 Socket 连接的情况下，新的请求也能使用更新后的 SSL 配置。
   - 测试了在事务处理过程中发生 SSL 配置更改的情况，确保新的请求会使用新的 Socket 和配置。
   - 还测试了在连接挂起 (pending connect) 状态下发生 SSL 配置更改的情况。

4. **处理服务器请求客户端证书 (Post-Handshake Client Cert) 的情况:**
   - 测试当服务器在 TLS 握手后通过 renegotiation 请求客户端证书时，`HttpNetworkTransaction` 能否正确处理。
   - 模拟在有正在使用的 Socket、空闲 Socket 以及连接到不同主机的 Socket 的情况下，接收到客户端证书请求的情况。
   - 验证在选择客户端证书后，新的请求能够正确建立连接，并且不会错误地使用之前的 Socket。

**与 JavaScript 的关系及举例说明:**

`HttpNetworkTransaction` 本身是用 C++ 编写的，不直接涉及 JavaScript 代码。然而，它在幕后处理了由 JavaScript 发起的网络请求。

**举例说明:**

当 JavaScript 代码使用 `fetch` API 发起一个 HTTPS 请求时：

```javascript
fetch('https://www.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. **用户操作/JavaScript 发起请求:**  JavaScript 的 `fetch` 调用会被浏览器内核接收。
2. **网络层处理:**  浏览器内核的网络层会创建一个 `HttpNetworkTransaction` 实例来处理这个请求。
3. **连接建立/重用:** 这部分代码测试了 `HttpNetworkTransaction` 如何选择或建立连接。例如，如果启用了预连接，并且到 `www.example.com` 的连接已经建立，`kUseFirstPreconnect` 的测试场景就模拟了这种情况。
4. **SSL 处理:** 如果是 HTTPS 请求，会涉及到 SSL 连接的建立。 `NetworkIsolationSSL` 和 `NetworkIsolationSSLProxy` 的测试场景确保了来自不同源的请求使用独立的 SSL 会话，防止信息泄露。
5. **SSL 配置:** 如果在请求过程中，浏览器接收到新的 SSL 配置（例如，通过管理员策略更新），`SSLConfigChangedDuringTransaction` 的测试场景就模拟了这种情况，确保后续的连接会使用新的配置。
6. **客户端证书:** 如果 `www.example.com` 要求客户端证书进行身份验证，`PostHandshakeClientCertWithSockets` 的测试场景就模拟了服务器在连接建立后请求客户端证书的情况，确保浏览器能正确处理并重试请求。
7. **请求发送和响应接收:**  `HttpNetworkTransaction` 负责发送 HTTP 请求头，接收服务器的响应头和响应体。
8. **数据返回给 JavaScript:**  接收到的数据最终会通过回调传递给 JavaScript 的 `fetch` API 的 `then` 方法。

**逻辑推理的假设输入与输出:**

**假设输入 (针对预连接测试):**

- 存在两个预连接，分别到 `http://origin1/` 和 `http://origin2/`。
- 发起一个到 `http://www.foo.com/` 的 HTTP 请求。
- `test_case` 为 `TestCase::kUseFirstPreconnect`。

**预期输出:**

- `HttpNetworkTransaction` 会复用与 `http://origin1/` 相关的预连接的 Socket（假设 `www.foo.com` 与 `origin1` 有某种关联，例如同站点）。
- Socket 连接池中的空闲 Socket 数量在请求结束后仍然是 2，因为其中一个预连接被使用，但另一个仍然空闲。

**假设输入 (针对 SSL 网络隔离测试):**

- 启用了 `kPartitionConnectionsByNetworkIsolationKey` 特性。
- 发起一个到 `https://foo.test/1` 的请求，其 `NetworkIsolationKey` 基于 `http://origin1/`。
- 发起一个到 `https://foo.test/2` 的请求，其 `NetworkIsolationKey` 基于 `http://origin2/`。

**预期输出:**

- 这两个请求会建立不同的 SSL 连接，即使它们连接到同一个主机 `foo.test`，因为它们的 `NetworkIsolationKey` 不同，导致使用了不同的 SSL 会话缓存。

**用户或编程常见的使用错误及举例说明:**

- **编程错误:** 在开发网络相关的应用程序时，错误地设置或忽略 `NetworkIsolationKey` 可能导致意外的连接共享或隔离行为，例如，原本应该隔离的请求使用了相同的连接，导致数据泄露。
- **用户错误:** 用户如果禁用了浏览器的某些安全特性，可能会影响到网络隔离的实现，虽然这不太可能直接导致这个单元测试失败，但会影响到实际运行时的行为。
- **配置错误:**  系统或网络配置不当，例如错误的代理设置，可能会导致连接失败或使用错误的 SSL 配置，虽然这更多是网络层面的问题，但 `HttpNetworkTransaction` 需要能够处理这些情况。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 `https://www.example.com` 并按下回车。**
2. **浏览器解析 URL，确定需要建立 HTTPS 连接。**
3. **浏览器检查是否已经有到 `www.example.com` 的可用连接 (包括预连接)。** 这部分代码的预连接测试就模拟了这种情况。
4. **如果需要建立新的连接，浏览器会根据当前的 SSL 配置进行连接。** `SSLConfigChanged` 相关的测试会模拟 SSL 配置更新的情况。
5. **如果服务器要求客户端证书，并且之前没有为此站点提供过证书，浏览器可能会弹出证书选择对话框。** `PostHandshakeClientCertWithSockets` 的测试模拟了服务器在连接建立后才请求证书的情况。
6. **网络栈创建 `HttpNetworkTransaction` 实例来处理请求。**
7. **`HttpNetworkTransaction` 负责发送请求，接收响应。**
8. **如果发生网络错误或 SSL 错误，`HttpNetworkTransaction` 会返回相应的错误码。**

在调试网络问题时，开发者可能会运行这些单元测试来验证网络栈的特定行为是否符合预期。例如，如果用户报告了与 SSL 证书或连接隔离相关的问题，开发者可能会关注 `NetworkIsolationSSL` 或 `PostHandshakeClientCertWithSockets` 相关的测试。

**归纳一下它的功能 (作为第 33 部分，共 34 部分):**

作为测试套件的倒数第二部分，这部分代码集中测试了 `HttpNetworkTransaction` 在**连接管理、SSL 安全性和动态配置变更**等方面的复杂场景下的行为。它涵盖了预连接的利用、基于网络隔离键的 SSL 连接隔离、SSL 配置的动态更新以及处理服务器的客户端证书请求等高级功能。 这部分测试可能旨在验证之前测试中未充分覆盖的边界情况和复杂交互，为最终的测试覆盖和稳定性提供保障。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第33部分，共34部分，请归纳一下它的功能

"""
ableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  enum class TestCase {
    kUseFirstPreconnect,
    kUseSecondPreconnect,
    kDontUsePreconnect,
  };

  const SchemefulSite kSite1(GURL("http://origin1/"));
  const SchemefulSite kSite2(GURL("http://origin2/"));
  const SchemefulSite kSite3(GURL("http://origin3/"));
  auto preconnect1_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  auto preconnect2_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  auto not_preconnected_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(kSite3);
  NetworkIsolationKey preconnect1_isolation_key(kSite1, kSite1);
  NetworkIsolationKey preconnect2_isolation_key(kSite2, kSite2);
  NetworkIsolationKey not_preconnected_isolation_key(kSite3, kSite3);
  // Test that only preconnects with
  for (TestCase test_case :
       {TestCase::kUseFirstPreconnect, TestCase::kUseSecondPreconnect,
        TestCase::kDontUsePreconnect}) {
    SpdySessionDependencies session_deps;
    // Make DNS lookups completely synchronously, so preconnects complete
    // immediately.
    session_deps.host_resolver->set_synchronous_mode(true);

    const MockWrite kMockWrites[] = {
        MockWrite(ASYNC, 0,
                  "GET / HTTP/1.1\r\n"
                  "Host: www.foo.com\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    const MockRead kMockReads[] = {
        MockRead(ASYNC, 1,
                 "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
                 "hello"),
    };

    // Used for the socket that will actually be used, which may or may not be
    // one of the preconnects
    SequencedSocketData used_socket_data(MockConnect(SYNCHRONOUS, OK),
                                         kMockReads, kMockWrites);

    // Used for the preconnects that won't actually be used.
    SequencedSocketData preconnect1_data(MockConnect(SYNCHRONOUS, OK),
                                         base::span<const MockRead>(),
                                         base::span<const MockWrite>());
    SequencedSocketData preconnect2_data(MockConnect(SYNCHRONOUS, OK),
                                         base::span<const MockRead>(),
                                         base::span<const MockWrite>());

    NetworkAnonymizationKey network_anonymization_key_for_request;
    NetworkIsolationKey network_isolation_key_for_request;

    switch (test_case) {
      case TestCase::kUseFirstPreconnect:
        session_deps.socket_factory->AddSocketDataProvider(&used_socket_data);
        session_deps.socket_factory->AddSocketDataProvider(&preconnect2_data);
        network_isolation_key_for_request = preconnect1_isolation_key;
        network_anonymization_key_for_request = preconnect1_anonymization_key;
        break;
      case TestCase::kUseSecondPreconnect:
        session_deps.socket_factory->AddSocketDataProvider(&preconnect1_data);
        session_deps.socket_factory->AddSocketDataProvider(&used_socket_data);
        network_isolation_key_for_request = preconnect2_isolation_key;
        network_anonymization_key_for_request = preconnect2_anonymization_key;
        break;
      case TestCase::kDontUsePreconnect:
        session_deps.socket_factory->AddSocketDataProvider(&preconnect1_data);
        session_deps.socket_factory->AddSocketDataProvider(&preconnect2_data);
        session_deps.socket_factory->AddSocketDataProvider(&used_socket_data);
        network_isolation_key_for_request = not_preconnected_isolation_key;
        network_anonymization_key_for_request =
            not_preconnected_anonymization_key;
        break;
    }

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps));

    // Preconnect sockets.
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.foo.com/");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    request.network_isolation_key = preconnect1_isolation_key;
    request.network_anonymization_key = preconnect1_anonymization_key;
    session->http_stream_factory()->PreconnectStreams(1, request);

    request.network_isolation_key = preconnect2_isolation_key;
    request.network_anonymization_key = preconnect2_anonymization_key;
    session->http_stream_factory()->PreconnectStreams(1, request);

    request.network_isolation_key = network_isolation_key_for_request;
    request.network_anonymization_key = network_anonymization_key_for_request;

    // Run until idle to ensure that preconnects complete.
    RunUntilIdle();
    EXPECT_EQ(2, GetIdleSocketCountInTransportSocketPool(session.get()));

    // Make the request.
    TestCompletionCallback callback;

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_EQ(200, response->headers->response_code());

    std::string response_data;
    rv = ReadTransaction(&trans, &response_data);
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ("hello", response_data);

    if (test_case != TestCase::kDontUsePreconnect) {
      EXPECT_EQ(2, GetIdleSocketCountInTransportSocketPool(session.get()));
    } else {
      EXPECT_EQ(3, GetIdleSocketCountInTransportSocketPool(session.get()));
    }
  }
}

// Test that the NetworkAnonymizationKey is passed down to SSLConfig so the
// session cache is isolated.
TEST_P(HttpNetworkTransactionTest, NetworkIsolationSSL) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  const SchemefulSite kSite1(GURL("http://origin1/"));
  const SchemefulSite kSite2(GURL("http://origin2/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // The server always sends Connection: close, so each request goes over a
  // distinct socket.

  const MockWrite kWrites1[] = {
      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n")};

  const MockRead kReads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: close\r\n"
               "Content-Length: 1\r\n\r\n"
               "1")};

  const MockWrite kWrites2[] = {
      MockWrite("GET /2 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n")};

  const MockRead kReads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: close\r\n"
               "Content-Length: 1\r\n\r\n"
               "2")};

  const MockWrite kWrites3[] = {
      MockWrite("GET /3 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n")};

  const MockRead kReads3[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: close\r\n"
               "Content-Length: 1\r\n\r\n"
               "3")};

  StaticSocketDataProvider data1(kReads1, kWrites1);
  StaticSocketDataProvider data2(kReads2, kWrites2);
  StaticSocketDataProvider data3(kReads3, kWrites3);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  SSLSocketDataProvider ssl_data1(ASYNC, OK);
  ssl_data1.expected_host_and_port = HostPortPair("foo.test", 443);
  ssl_data1.expected_network_anonymization_key = kNetworkAnonymizationKey1;
  SSLSocketDataProvider ssl_data2(ASYNC, OK);
  ssl_data2.expected_host_and_port = HostPortPair("foo.test", 443);
  ssl_data2.expected_network_anonymization_key = kNetworkAnonymizationKey2;
  SSLSocketDataProvider ssl_data3(ASYNC, OK);
  ssl_data3.expected_host_and_port = HostPortPair("foo.test", 443);
  ssl_data3.expected_network_anonymization_key = kNetworkAnonymizationKey1;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://foo.test/1");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request1.network_isolation_key = kNetworkIsolationKey1;
  request1.network_anonymization_key = kNetworkAnonymizationKey1;

  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("1", response_data1);
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://foo.test/2");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request2.network_isolation_key = kNetworkIsolationKey2;
  request2.network_anonymization_key = kNetworkAnonymizationKey2;
  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("2", response_data2);
  trans2.reset();

  HttpRequestInfo request3;
  request3.method = "GET";
  request3.url = GURL("https://foo.test/3");
  request3.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request3.network_isolation_key = kNetworkIsolationKey1;
  request3.network_anonymization_key = kNetworkAnonymizationKey1;
  auto trans3 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans3->Start(&request3, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data3;
  EXPECT_THAT(ReadTransaction(trans3.get(), &response_data3), IsOk());
  EXPECT_EQ("3", response_data3);
  trans3.reset();
}

// Test that the NetworkAnonymizationKey is passed down to SSLConfig so the
// session cache is isolated, for both origins and proxies.
TEST_P(HttpNetworkTransactionTest, NetworkIsolationSSLProxy) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  const SchemefulSite kSite1(GURL("http://origin1/"));
  const SchemefulSite kSite2(GURL("http://origin2/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Make both a tunneled and non-tunneled request.
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://foo.test/1");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request1.network_isolation_key = kNetworkIsolationKey1;
  request1.network_anonymization_key = kNetworkAnonymizationKey1;

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://foo.test/2");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request2.network_isolation_key = kNetworkIsolationKey2;
  request2.network_anonymization_key = kNetworkAnonymizationKey2;

  const MockWrite kWrites1[] = {MockWrite("CONNECT foo.test:443 HTTP/1.1\r\n"
                                          "Host: foo.test:443\r\n"
                                          "Proxy-Connection: keep-alive\r\n"
                                          "User-Agent: test-ua\r\n\r\n"),
                                MockWrite("GET /1 HTTP/1.1\r\n"
                                          "Host: foo.test\r\n"
                                          "Connection: keep-alive\r\n\r\n")};

  const MockRead kReads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: close\r\n"
               "Content-Length: 1\r\n\r\n"
               "1")};

  const MockWrite kWrites2[] = {
      MockWrite("GET http://foo.test/2 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n")};

  const MockRead kReads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: close\r\n"
               "Content-Length: 1\r\n\r\n"
               "2")};

  StaticSocketDataProvider data1(kReads1, kWrites1);
  StaticSocketDataProvider data2(kReads2, kWrites2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  SSLSocketDataProvider ssl_proxy1(ASYNC, OK);
  ssl_proxy1.expected_host_and_port = HostPortPair("myproxy", 70);
  ssl_proxy1.expected_network_anonymization_key = kNetworkAnonymizationKey1;
  SSLSocketDataProvider ssl_origin1(ASYNC, OK);
  ssl_origin1.expected_host_and_port = HostPortPair("foo.test", 443);
  ssl_origin1.expected_network_anonymization_key = kNetworkAnonymizationKey1;
  SSLSocketDataProvider ssl_proxy2(ASYNC, OK);
  ssl_proxy2.expected_host_and_port = HostPortPair("myproxy", 70);
  ssl_proxy2.expected_network_anonymization_key = kNetworkAnonymizationKey2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_origin1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_proxy2);

  TestCompletionCallback callback;
  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("1", response_data1);
  trans1.reset();

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("2", response_data2);
  trans2.reset();
}

// Test that SSLConfig changes from SSLConfigService are picked up even when
// there are live sockets.
TEST_P(HttpNetworkTransactionTest, SSLConfigChanged) {
  SSLContextConfig ssl_context_config;
  ssl_context_config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;
  auto ssl_config_service =
      std::make_unique<TestSSLConfigService>(ssl_context_config);
  TestSSLConfigService* ssl_config_service_raw = ssl_config_service.get();

  session_deps_.ssl_config_service = std::move(ssl_config_service);

  // Make three requests. Between the second and third, the SSL config will
  // change.
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://foo.test/1");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://foo.test/2");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request3;
  request3.method = "GET";
  request3.url = GURL("https://foo.test/3");
  request3.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const MockWrite kWrites1[] = {
      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("GET /2 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  const MockRead kReads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 1\r\n\r\n"
               "1"),
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 1\r\n\r\n"
               "2"),
  };

  // The third request goes on a different socket because the SSL config has
  // changed.
  const MockWrite kWrites2[] = {
      MockWrite("GET /3 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n")};

  const MockRead kReads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 1\r\n\r\n"
               "3")};

  StaticSocketDataProvider data1(kReads1, kWrites1);
  StaticSocketDataProvider data2(kReads2, kWrites2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  SSLSocketDataProvider ssl1(ASYNC, OK);
  ssl1.expected_ssl_version_max = SSL_PROTOCOL_VERSION_TLS1_3;
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.expected_ssl_version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  TestCompletionCallback callback;
  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("1", response_data1);
  trans1.reset();

  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("2", response_data2);
  trans2.reset();

  ssl_context_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ssl_config_service_raw->UpdateSSLConfigAndNotify(ssl_context_config);

  auto trans3 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans3->Start(&request3, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data3;
  EXPECT_THAT(ReadTransaction(trans3.get(), &response_data3), IsOk());
  EXPECT_EQ("3", response_data3);
  trans3.reset();
}

TEST_P(HttpNetworkTransactionTest, SSLConfigChangedDuringTransaction) {
  SSLContextConfig ssl_context_config;
  ssl_context_config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;
  auto ssl_config_service =
      std::make_unique<TestSSLConfigService>(ssl_context_config);
  TestSSLConfigService* ssl_config_service_raw = ssl_config_service.get();
  session_deps_.ssl_config_service = std::move(ssl_config_service);

  // First request will start connecting before SSLConfig change.
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://foo.test/1");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const MockWrite kWrites1[] = {
      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kReads1[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2,
               "HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 1\r\n\r\n"
               "1"),
  };

  // Second request will be after SSLConfig changes so it should be on a new
  // socket.
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://foo.test/2");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const MockWrite kWrites2[] = {
      MockWrite("GET /2 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n")};

  const MockRead kReads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 1\r\n\r\n"
               "2")};

  SequencedSocketData data1(kReads1, kWrites1);
  StaticSocketDataProvider data2(kReads2, kWrites2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  SSLSocketDataProvider ssl1(ASYNC, OK);
  // 1st request starts before config change, so should see the initial
  // SSLConfig.
  ssl1.expected_ssl_version_max = SSL_PROTOCOL_VERSION_TLS1_3;

  SSLSocketDataProvider ssl2(ASYNC, OK);
  // 2nd request should be made on a new socket after config change, so should
  // see the new SSLConfig.
  ssl2.expected_ssl_version_max = SSL_PROTOCOL_VERSION_TLS1_2;

  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  TestCompletionCallback callback1;
  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Wait for the first transaction to connect and start reading data.
  data1.RunUntilPaused();

  // Change network config.
  ssl_context_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ssl_config_service_raw->UpdateSSLConfigAndNotify(ssl_context_config);

  // Resume the first transaction reads.
  data1.Resume();
  EXPECT_THAT(callback1.GetResult(rv), IsOk());
  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("1", response_data1);
  trans1.reset();

  // Start 2nd transaction. Since the config was changed, it should use a new
  // socket.
  TestCompletionCallback callback2;
  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback2.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback2.GetResult(rv), IsOk());
  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("2", response_data2);
  trans2.reset();
}

TEST_P(HttpNetworkTransactionTest, SSLConfigChangedPendingConnect) {
  SSLContextConfig ssl_context_config;
  ssl_context_config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;
  auto ssl_config_service =
      std::make_unique<TestSSLConfigService>(ssl_context_config);
  TestSSLConfigService* ssl_config_service_raw = ssl_config_service.get();

  session_deps_.ssl_config_service = std::move(ssl_config_service);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://foo.test/1");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  const MockWrite kWrites1[] = {
      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kReads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 1\r\n\r\n"
               "1"),
  };

  StaticSocketDataProvider data1(kReads1, kWrites1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // Even though the transaction was created before the change, the connection
  // shouldn't happen until after the SSLConfig change, so expect that the
  // socket will be created with the new SSLConfig.
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.expected_ssl_version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  TestCompletionCallback callback;
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ssl_context_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ssl_config_service_raw->UpdateSSLConfigAndNotify(ssl_context_config);

  EXPECT_THAT(callback.GetResult(rv), IsOk());
  std::string response_data;
  EXPECT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("1", response_data);
  trans.reset();
}

// Test that HttpNetworkTransaction correctly handles existing sockets when the
// server requests a client certificate post-handshake (via a TLS
// renegotiation). This is a regression test for https://crbug.com/829184.
TEST_P(HttpNetworkTransactionTest, PostHandshakeClientCertWithSockets) {
  const MutableNetworkTrafficAnnotationTag kTrafficAnnotation(
      TRAFFIC_ANNOTATION_FOR_TESTS);

  auto cert_request_info = base::MakeRefCounted<SSLCertRequestInfo>();
  cert_request_info->host_and_port = HostPortPair("foo.test", 443);

  std::unique_ptr<FakeClientCertIdentity> identity =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_1.pem", "client_1.pk8");
  ASSERT_TRUE(identity);

  // This test will make several requests so that, when the client certificate
  // request comes in, we have a socket in use, an idle socket, and a socket for
  // an unrelated host.
  //
  // First, two long-lived requests which do not complete until after the client
  // certificate request. This arranges for sockets to be in use during the
  // request. They should not be interrupted.
  HttpRequestInfo request_long_lived;
  request_long_lived.method = "GET";
  request_long_lived.url = GURL("https://foo.test/long-lived");
  request_long_lived.traffic_annotation = kTrafficAnnotation;

  HttpRequestInfo request_long_lived_bar;
  request_long_lived_bar.method = "GET";
  request_long_lived_bar.url = GURL("https://bar.test/long-lived");
  request_long_lived_bar.traffic_annotation = kTrafficAnnotation;

  // Next, make a request that needs client certificates.
  HttpRequestInfo request_auth;
  request_auth.method = "GET";
  request_auth.url = GURL("https://foo.test/auth");
  request_auth.traffic_annotation = kTrafficAnnotation;

  // Before responding to the challenge, make a request to an unauthenticated
  // endpoint. This will result in an idle socket when the client certificate
  // challenge is resolved.
  HttpRequestInfo request_unauth;
  request_unauth.method = "GET";
  request_unauth.url = GURL("https://foo.test/unauth");
  request_unauth.traffic_annotation = kTrafficAnnotation;

  // After all the preceding requests complete, end with two additional requests
  // to ensure pre-authentication foo.test sockets are not used and bar.test
  // sockets are unaffected.
  HttpRequestInfo request_post_auth;
  request_post_auth.method = "GET";
  request_post_auth.url = GURL("https://foo.test/post-auth");
  request_post_auth.traffic_annotation = kTrafficAnnotation;

  HttpRequestInfo request_post_auth_bar;
  request_post_auth_bar.method = "GET";
  request_post_auth_bar.url = GURL("https://bar.test/post-auth");
  request_post_auth_bar.traffic_annotation = kTrafficAnnotation;

  // The sockets for /long-lived and /unauth complete their request but are
  // not allocated for /post-auth or /retry because SSL state has since changed.
  const MockWrite kLongLivedWrites[] = {
      MockWrite(ASYNC, 0,
                "GET /long-lived HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kLongLivedReads[] = {
      // Pause so /long-lived completes after the client presents client
      // certificates.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2,
               "HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 10\r\n\r\n"
               "long-lived"),
  };
  SequencedSocketData data_long_lived(kLongLivedReads, kLongLivedWrites);
  SSLSocketDataProvider ssl_long_lived(ASYNC, OK);
  session_deps_.socket_factory->AddSocketDataProvider(&data_long_lived);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_long_lived);

  // Requests for bar.test should be unaffected by foo.test and get allocated
  // a single socket.
  const MockWrite kBarWrites[] = {
      MockWrite(ASYNC, 0,
                "GET /long-lived HTTP/1.1\r\n"
                "Host: bar.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite(ASYNC, 3,
                "GET /post-auth HTTP/1.1\r\n"
                "Host: bar.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kBarReads[] = {
      // Pause on /long-lived so it completes after foo.test's authentication.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2,
               "HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 10\r\n\r\n"
               "long-lived"),
      MockRead(ASYNC, 4,
               "HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 9\r\n\r\n"
               "post-auth"),
  };
  SequencedSocketData data_bar(kBarReads, kBarWrites);
  SSLSocketDataProvider ssl_bar(ASYNC, OK);
  session_deps_.socket_factory->AddSocketDataProvider(&data_bar);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_bar);

  // Requesting /auth results in a post-handshake client certificate challenge.
  const MockWrite kAuthWrites[] = {
      MockWrite(ASYNC, 0,
                "GET /auth HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kAuthReads[] = {
      MockRead(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED, 1),
  };
  SequencedSocketData data_auth(kAuthReads, kAuthWrites);
  SSLSocketDataProvider ssl_auth(ASYNC, OK);
  ssl_auth.cert_request_info = cert_request_info;
  session_deps_.socket_factory->AddSocketDataProvider(&data_auth);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_auth);

  // Requesting /unauth completes.
  const MockWrite kUnauthWrites[] = {
      MockWrite(ASYNC, 0,
                "GET /unauth HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kUnauthReads[] = {
      MockRead(ASYNC, 1,
               "HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 6\r\n\r\n"
               "unauth"),
  };
  SequencedSocketData data_unauth(kUnauthReads, kUnauthWrites);
  SSLSocketDataProvider ssl_unauth(ASYNC, OK);
  session_deps_.socket_factory->AddSocketDataProvider(&data_unauth);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_unauth);

  // When the client certificate is selected, /auth is retried on a new
  // connection. In particular, it should not be retried on |data_unauth|,
  // which would not honor the new client certificate configuration.
  const MockWrite kRetryWrites[] = {
      MockWrite(ASYNC, 0,
                "GET /auth HTTP/1.1\r\n"
                "Host: foo.test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  const MockRead kRetryReads[] = {
      MockRead(ASYNC, 1,
               "HTTP/1.1 200 OK\r\n"
               // Close the connection so we test that /post-auth is not
               // allocated to |data_unauth| or |data_long_lived|.
               "
"""


```