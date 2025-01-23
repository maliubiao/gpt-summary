Response:
My thinking process to analyze the provided C++ code snippet and address the prompt's requirements goes like this:

1. **Understand the Core Functionality:**  The file name `http_network_transaction_unittest.cc` immediately tells me this is a unit test file for the `HttpNetworkTransaction` class in Chromium's networking stack. Unit tests aim to verify individual units of code in isolation. Therefore, the primary function is to test the behavior of `HttpNetworkTransaction` under various network conditions and scenarios.

2. **Identify Key Test Scenarios:** I scanned the code and noticed a pattern of `TEST_P` and `TEST` macros. These define individual test cases. I looked at the names of these tests to get a sense of what aspects of `HttpNetworkTransaction` are being tested. Key themes emerged:
    * **GroupId:**  Tests related to `GroupIdForHttpProxyConnections` and `GroupIdForSOCKSConnections` indicate testing how connections are grouped based on proxy configurations.
    * **Proxy Handling:** Tests like `ReconsiderProxyAfterFailedConnection` and `HTTPSViaProxyWithExtraData` are clearly testing different proxy scenarios.
    * **Error Handling:** Tests such as `RequestWriteError`, `ConnectionClosedAfterStartOfHeaders`, and `LargeContentLengthThenClose` focus on how the transaction handles various network errors and server responses.
    * **Authentication:** `DrainResetOK` and `ChangeAuthRealms` test the authentication and re-authentication mechanisms.
    * **Uploads:** `UploadFileSmallerThanLength` and `UploadUnreadableFile` check file upload functionality and error handling.
    * **Cancellations:** `CancelDuringInitRequestBody` tests how cancellations are handled during request body initialization.
    * **Alternative Services (Alt-Svc):** `IgnoreAltSvcWithInvalidCert` and `HonorAlternativeServiceHeader` test the handling of the `Alt-Svc` HTTP header.

3. **Analyze Specific Code Sections:**  For each test, I tried to understand the setup and assertions:
    * **`GroupId` Tests:** These tests set up specific proxy configurations and then initiate a transaction. The core assertion is checking the `last_group_id_received()` on the `CaptureGroupIdTransportSocketPool`. This tells me these tests are about verifying the correct grouping of connections based on proxy settings.
    * **Proxy Failure Test:** This test simulates a DNS failure to all proxies and asserts that the transaction eventually fails with `ERR_PROXY_CONNECTION_FAILED`.
    * **Error Tests:** These tests inject mock socket data with errors (like `ERR_CONNECTION_RESET`) and verify that the transaction reports the expected error.
    * **Authentication Tests:** These tests involve multiple requests and responses, simulating different authentication challenges and credentials. The assertions check the presence and content of `WWW-Authenticate` headers.
    * **Upload Tests:** These tests set up upload data streams and check for errors related to file changes or unreadable files.
    * **Alt-Svc Tests:** These tests check if the transaction correctly handles the `Alt-Svc` header, potentially ignoring it in case of certificate errors or correctly storing the information in `HttpServerProperties`.

4. **Address Specific Prompt Questions:**
    * **Functionality:** Based on the identified test scenarios, I summarized the main functionalities being tested: connection grouping, proxy handling, error management, authentication, uploads, cancellations, and alternative service handling.
    * **Relationship with JavaScript:** I considered how these network functionalities relate to the web browser environment where JavaScript operates. JavaScript uses APIs like `fetch()` or `XMLHttpRequest` which rely on the underlying network stack being tested here. I provided examples of how a JavaScript `fetch()` call would be affected by these underlying mechanisms (proxy settings, authentication, etc.).
    * **Logical Inference (Hypothetical Input/Output):** For the `GroupId` tests, I used the provided test data as input and explained the expected output (the `GroupId` being captured).
    * **User/Programming Errors:** I thought about common mistakes developers or users might make that would trigger the tested code. Examples included incorrect proxy settings, invalid credentials, trying to upload a modified file, or encountering server-side authentication changes.
    * **User Steps to Reach the Code:**  I outlined a sequence of user actions within a browser that would lead to the execution of the network code being tested, such as navigating to a website, using a proxy, encountering authentication prompts, or uploading files.
    * **Summary of Functionality (Part 20 of 34):** I focused on the tests within the provided snippet, which heavily emphasize connection grouping based on proxy types (HTTP and SOCKS).

5. **Structure and Refine:** Finally, I organized the information logically, using headings and bullet points for clarity. I tried to use precise language and avoid jargon where possible, while still accurately reflecting the technical nature of the code. I reviewed my response to ensure it addressed all parts of the prompt.

Essentially, my approach involved understanding the context of the code (unit testing), identifying the key functionalities being tested through the test names and code structure, analyzing the specific test logic, and then relating that back to the user's perspective and the broader web browser environment.
```cpp
    erties->GetAlternativeServiceInfos(
          test_server, kNetworkAnonymizationKey2)
          .empty());
}

}  // namespace net
```

这是 Chromium 网络栈中 `net/http/http_network_transaction_unittest.cc` 文件的第 20 部分（共 34 部分）。基于你提供的代码片段，我们可以归纳一下这部分的主要功能：

**主要功能归纳:**

这部分代码主要专注于测试 `HttpNetworkTransaction` 类在处理 **连接分组 (Connection Grouping)** 和 **代理 (Proxy)** 相关的逻辑。具体来说，它测试了以下几个方面：

1. **基于代理类型进行连接分组 (GroupId):**
   - 测试了通过 HTTP 代理连接时，`HttpNetworkTransaction` 如何确定连接的 `GroupId`。`GroupId` 用于连接池管理，确保在相同的安全上下文和代理配置下，连接可以被复用。
   - 测试了通过 SOCKS 代理连接时，`HttpNetworkTransaction` 如何确定连接的 `GroupId`。

2. **代理连接失败后的处理:**
   - 测试了当尝试连接代理失败时（例如，由于 DNS 解析失败），`HttpNetworkTransaction` 是否能够正确地处理错误，例如 `ERR_PROXY_CONNECTION_FAILED`。

3. **请求写入错误的处理:**
   - 测试了在向服务器写入请求时发生错误（例如，连接被重置 `ERR_CONNECTION_RESET`）时，`HttpNetworkTransaction` 的处理方式。

4. **在响应头开始后连接断开的处理:**
   - 测试了在接收到部分响应头后，连接意外断开的情况，验证 `HttpNetworkTransaction` 是否能正确处理并返回成功，但响应数据为空。

5. **在为认证重启而清空响应体时连接重置的处理:**
   - 测试了在需要进行 HTTP 认证时，如果服务器返回 401 并要求认证，客户端在清空旧的响应体时连接被重置的情况。验证 `HttpNetworkTransaction` 是否能正确处理并进行认证重启。

6. **通过代理连接 HTTPS，但代理发送额外数据的处理:**
   - 测试了通过 HTTP 代理连接 HTTPS 时，如果代理在发送 "200 Connected" 响应后发送了额外的无关数据，`HttpNetworkTransaction` 是否能正确处理并返回 `ERR_TUNNEL_CONNECTION_FAILED`。

7. **处理过大的 Content-Length 导致连接关闭的情况:**
   - 测试了服务器返回一个非常大的 `Content-Length`，但随后关闭连接的情况，验证 `HttpNetworkTransaction` 是否能正确检测到内容长度不匹配并返回 `ERR_CONTENT_LENGTH_MISMATCH`。

8. **处理上传文件大小小于声明长度的情况:**
   - 测试了在文件上传时，如果实际上传的文件大小小于请求头中声明的 `Content-Length`，`HttpNetworkTransaction` 是否能正确检测并返回 `ERR_UPLOAD_FILE_CHANGED`。

9. **处理无法读取的上传文件:**
   - 测试了尝试上传一个没有读取权限的文件时，`HttpNetworkTransaction` 是否能正确处理并返回 `ERR_ACCESS_DENIED`。

10. **在初始化请求体时取消请求:**
    - 测试了在 POST 请求中，当正在初始化请求体（例如读取文件内容）时取消请求，验证是否不会发生崩溃等问题。

11. **处理认证域 (Realm) 变化的情况:**
    - 测试了在 HTTP Basic 认证过程中，服务器返回不同的认证域 (Realm) 时，`HttpNetworkTransaction` 是否能够正确处理认证失败和缓存更新，并进行多次认证尝试。

12. **忽略带有无效证书的 Alt-Svc 头部:**
    - 测试了当 HTTPS 连接的服务器证书无效时，是否会忽略响应头中的 `Alt-Svc` 头部，避免尝试使用不可信的替代服务。

13. **处理有效的 Alt-Svc 头部:**
    - 测试了当 HTTPS 连接成功且证书有效时，是否能正确解析并存储响应头中的 `Alt-Svc` 头部信息，以便后续连接可以使用替代服务。

14. **在启用网络匿名化密钥 (Network Anonymization Key) 的情况下处理 Alt-Svc 头部:**
    - 测试了在启用了网络隔离功能（使用 `NetworkAnonymizationKey`）的情况下，是否能正确地为不同的 `NetworkAnonymizationKey` 存储和检索 `Alt-Svc` 信息。

**与 Javascript 的关系:**

这些测试覆盖的网络功能是 Web 浏览器中 Javascript 发起网络请求的基础。例如：

* **`fetch()` API 或 `XMLHttpRequest`:** 当 Javascript 代码使用这些 API 发起 HTTP 或 HTTPS 请求时，底层的 `HttpNetworkTransaction` 负责处理连接建立、代理协商、数据传输、错误处理和认证等过程。
* **Proxy 设置:** 用户在浏览器中配置的代理服务器信息，最终会影响 `HttpNetworkTransaction` 的行为，例如选择哪个代理服务器进行连接。
* **认证:** 当 Javascript 代码访问需要认证的资源时，`HttpNetworkTransaction` 会处理服务器返回的认证质询，并可能提示用户输入用户名和密码。
* **HSTS 和 Alt-Svc:**  `Alt-Svc` 头部信息被 `HttpNetworkTransaction` 处理后，可以指导浏览器在后续连接中使用更优的替代服务（例如 HTTP/2），这对于提升页面加载速度和用户体验至关重要。Javascript 代码无需直接处理 `Alt-Svc`，但能间接受益于其带来的性能提升。

**举例说明:**

* **代理:** 如果用户在浏览器中设置了 HTTP 代理 `http://proxy.example.com:8080`，当 Javascript 代码使用 `fetch('https://www.example.org')` 发起请求时，`GroupIdForHttpProxyConnections` 测试中涉及的逻辑会被触发，以确保连接能够正确地通过代理建立。
* **认证:** 如果 Javascript 代码尝试访问一个需要 Basic 认证的资源，例如 `fetch('http://secure.example.com')`，服务器返回 401 状态码和 `WWW-Authenticate` 头部，`DrainResetOK` 或 `ChangeAuthRealms` 测试中涉及的逻辑会被执行，来处理认证流程。
* **Alt-Svc:** 如果服务器 `https://www.example.org` 返回了 `Alt-Svc: h2="alt.example.org:443"` 头部，`HonorAlternativeServiceHeader` 测试中涉及的逻辑会被触发，浏览器会将这个信息存储起来，并在后续访问 `www.example.org` 时，尝试连接 `alt.example.org:443` 使用 HTTP/2 协议。

**逻辑推理 (假设输入与输出):**

以 `GroupIdForHttpProxyConnections` 中的一个测试用例为例：

* **假设输入:**
    * `test.proxy_chain`: "http://http_proxy:80" (使用 HTTP 代理)
    * `test.url`: "https://www.example.org/ssl_direct" (目标 URL 是 HTTPS)
* **逻辑推理:** 由于使用了 HTTP 代理连接 HTTPS，连接需要先建立到代理服务器的隧道。因此，`GroupId` 的计算应该基于代理服务器的 SchemeHostPort。
* **预期输出:**
    * `test.expected_group_id`: `ClientSocketPool::GroupId(url::SchemeHostPort(url::kHttpsScheme, "www.example.org", 443), PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(), SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false)`。  这里需要注意的是，虽然是通过 HTTP 代理，但最终的连接目标是 HTTPS，所以 `GroupId` 包含了目标 HTTPS 服务器的信息。

**用户或编程常见的使用错误:**

* **错误的代理配置:** 用户在浏览器中配置了错误的代理服务器地址或端口，会导致 `HttpNetworkTransaction` 连接代理失败，对应 `ReconsiderProxyAfterFailedConnection` 测试。
* **无效的用户名或密码:** 当访问需要认证的资源时，用户输入了错误的用户名或密码，会导致认证失败，触发类似 `ChangeAuthRealms` 测试中的场景。
* **上传文件被修改:** 程序员可能在上传文件后又修改了文件内容，导致实际上传的大小与声明的大小不一致，对应 `UploadFileSmallerThanLength` 测试。
* **尝试上传无权限文件:** 程序员尝试上传一个当前进程没有读取权限的文件，对应 `UploadUnreadableFile` 测试。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址，例如 `https://www.example.org`，并且浏览器配置了 HTTP 代理。**
2. **浏览器解析 URL，确定需要建立 HTTPS 连接。**
3. **由于配置了代理，浏览器会尝试通过配置的 HTTP 代理服务器建立连接。**  此时，`GroupIdForHttpProxyConnections` 测试中涉及的代码会被执行，以确定连接的 `GroupId`。
4. **`HttpNetworkTransaction` 对象被创建，用于处理这次请求。**
5. **如果代理连接建立成功，会发送 CONNECT 请求到代理服务器，建立 HTTPS 隧道。**
6. **如果代理服务器返回错误，例如 407 Proxy Authentication Required，则会涉及到认证相关的处理流程，对应 `DrainResetOK` 或 `ChangeAuthRealms` 测试。**
7. **如果代理服务器在建立隧道后发送了额外的垃圾数据，则会触发 `HTTPSViaProxyWithExtraData` 测试中涉及的错误处理逻辑.**
8. **如果服务器返回了 `Alt-Svc` 头部，并且证书有效，则 `HonorAlternativeServiceHeader` 测试中涉及的逻辑会被执行，将信息存储到 `HttpServerProperties` 中。**

通过查看网络请求的日志 (例如 Chrome 的 `chrome://net-export/`)，可以观察到连接建立、代理协商、认证等详细过程，从而定位到 `HttpNetworkTransaction` 相关的代码执行。

**总结这部分的功能:**

总而言之，这部分 `http_network_transaction_unittest.cc` 代码的主要功能是 **全面测试 `HttpNetworkTransaction` 类在各种代理配置和连接场景下的行为，包括连接分组、错误处理、认证流程以及对 Alt-Svc 等特性的支持**。这些测试对于确保 Chromium 网络栈在复杂的网络环境中稳定可靠地工作至关重要。

### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第20部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
stPort(url::kHttpsScheme, "www.example.org", 443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          true,
      },

      {
          "http_proxy",
          "https://host.with.alternate/direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpsScheme, "host.with.alternate",
                                  443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          true,
      },
  };

  for (const auto& test : tests) {
    session_deps_.proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedForTest(
            test.proxy_chain, TRAFFIC_ANNOTATION_FOR_TESTS);
    std::unique_ptr<HttpNetworkSession> session(
        SetupSessionForGroupIdTests(&session_deps_));

    HttpNetworkSessionPeer peer(session.get());

    ProxyChain proxy_chain(ProxyServer::SCHEME_HTTP,
                           HostPortPair("http_proxy", 80));
    auto http_proxy_pool = std::make_unique<CaptureGroupIdTransportSocketPool>(
        &dummy_connect_job_params_);
    auto* http_proxy_pool_ptr = http_proxy_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(proxy_chain, std::move(http_proxy_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    EXPECT_EQ(ERR_IO_PENDING,
              GroupIdTransactionHelper(test.url, session.get()));
    EXPECT_EQ(test.expected_group_id,
              http_proxy_pool_ptr->last_group_id_received());
  }
}

TEST_P(HttpNetworkTransactionTest, GroupIdForSOCKSConnections) {
  const GroupIdTest tests[] = {
      {
          "socks4://socks_proxy:1080",
          "http://www.example.org/socks4_direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "www.example.org", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          false,
      },
      {
          "socks5://socks_proxy:1080",
          "http://www.example.org/socks5_direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpScheme, "www.example.org", 80),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          false,
      },

      // SSL Tests
      {
          "socks4://socks_proxy:1080",
          "https://www.example.org/socks4_ssl",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpsScheme, "www.example.org", 443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          true,
      },
      {
          "socks5://socks_proxy:1080",
          "https://www.example.org/socks5_ssl",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpsScheme, "www.example.org", 443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          true,
      },

      {
          "socks4://socks_proxy:1080",
          "https://host.with.alternate/direct",
          ClientSocketPool::GroupId(
              url::SchemeHostPort(url::kHttpsScheme, "host.with.alternate",
                                  443),
              PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
              SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
          HttpStreamKey(),  // unused
          true,
      },
  };

  for (const auto& test : tests) {
    session_deps_.proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedForTest(
            test.proxy_chain, TRAFFIC_ANNOTATION_FOR_TESTS);
    std::unique_ptr<HttpNetworkSession> session(
        SetupSessionForGroupIdTests(&session_deps_));

    HttpNetworkSessionPeer peer(session.get());

    ProxyChain proxy_chain =
        ProxyUriToProxyChain(test.proxy_chain, ProxyServer::SCHEME_HTTP);
    ASSERT_TRUE(proxy_chain.IsValid());
    auto socks_conn_pool = std::make_unique<CaptureGroupIdTransportSocketPool>(
        &dummy_connect_job_params_);
    auto* socks_conn_pool_ptr = socks_conn_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(proxy_chain, std::move(socks_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    EXPECT_EQ(ERR_IO_PENDING,
              GroupIdTransactionHelper(test.url, session.get()));
    EXPECT_EQ(test.expected_group_id,
              socks_conn_pool_ptr->last_group_id_received());
  }
}

TEST_P(HttpNetworkTransactionTest, ReconsiderProxyAfterFailedConnection) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70;foobar:80", TRAFFIC_ANNOTATION_FOR_TESTS);

  // This simulates failure resolving all hostnames; that means we will fail
  // connecting to both proxies (myproxy:70 and foobar:80).
  session_deps_.host_resolver->rules()->AddSimulatedFailure("*");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_PROXY_CONNECTION_FAILED));
}

// Make sure we can handle an error when writing the request.
TEST_P(HttpNetworkTransactionTest, RequestWriteError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite write_failure[] = {
      MockWrite(ASYNC, ERR_CONNECTION_RESET),
  };
  StaticSocketDataProvider data(base::span<MockRead>(), write_failure);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_LT(0u, endpoint.address().size());
}

// Check that a connection closed after the start of the headers finishes ok.
TEST_P(HttpNetworkTransactionTest, ConnectionClosedAfterStartOfHeaders) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead data_reads[] = {
      MockRead("HTTP/1."),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_LT(0u, endpoint.address().size());
}

// Make sure that a dropped connection while draining the body for auth
// restart does the right thing.
TEST_P(HttpNetworkTransactionTest, DrainResetOK) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 14\r\n\r\n"),
      MockRead("Unauth"),
      MockRead(ASYNC, ERR_CONNECTION_RESET),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // After calling trans.RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// Test HTTPS connections going through a proxy that sends extra data.
TEST_P(HttpNetworkTransactionTest, HTTPSViaProxyWithExtraData) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  MockRead proxy_reads[] = {
      MockRead("HTTP/1.0 200 Connected\r\n\r\nExtra data"),
      MockRead(SYNCHRONOUS, OK)};

  StaticSocketDataProvider data(proxy_reads, base::span<MockWrite>());
  SSLSocketDataProvider ssl(ASYNC, OK);

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  session_deps_.socket_factory->ResetNextMockIndexes();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

TEST_P(HttpNetworkTransactionTest, LargeContentLengthThenClose) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\nContent-Length:6719476739\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_CONTENT_LENGTH_MISMATCH));
}

TEST_P(HttpNetworkTransactionTest, UploadFileSmallerThanLength) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file_path));
  const uint64_t kFakeSize = 100000;  // file is actually blank
  UploadFileElementReader::ScopedOverridingContentLengthForTests
      overriding_content_length(kFakeSize);

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file_path,
      0, std::numeric_limits<uint64_t>::max(), base::Time()));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/upload");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_UPLOAD_FILE_CHANGED));

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_FALSE(response->headers);

  base::DeleteFile(temp_file_path);
}

TEST_P(HttpNetworkTransactionTest, UploadUnreadableFile) {
  base::FilePath temp_file;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file));
  std::string temp_file_content("Unreadable file.");
  ASSERT_TRUE(base::WriteFile(temp_file, temp_file_content));
  ASSERT_TRUE(base::MakeFileUnreadable(temp_file));

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadFileElementReader>(
      base::SingleThreadTaskRunner::GetCurrentDefault().get(), temp_file, 0,
      std::numeric_limits<uint64_t>::max(), base::Time()));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/upload");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // If we try to upload an unreadable file, the transaction should fail.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_ACCESS_DENIED));

  base::DeleteFile(temp_file);
}

TEST_P(HttpNetworkTransactionTest, CancelDuringInitRequestBody) {
  class FakeUploadElementReader : public UploadElementReader {
   public:
    FakeUploadElementReader() = default;
    ~FakeUploadElementReader() override = default;

    CompletionOnceCallback TakeCallback() { return std::move(callback_); }

    // UploadElementReader overrides:
    int Init(CompletionOnceCallback callback) override {
      callback_ = std::move(callback);
      return ERR_IO_PENDING;
    }
    uint64_t GetContentLength() const override { return 0; }
    uint64_t BytesRemaining() const override { return 0; }
    int Read(IOBuffer* buf,
             int buf_length,
             CompletionOnceCallback callback) override {
      return ERR_FAILED;
    }

   private:
    CompletionOnceCallback callback_;
  };

  auto fake_reader = std::make_unique<FakeUploadElementReader>();
  auto* fake_reader_ptr = fake_reader.get();
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::move(fake_reader));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/upload");
  request.upload_data_stream = &upload_data_stream;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  // Transaction is pending on request body initialization.
  CompletionOnceCallback init_callback = fake_reader_ptr->TakeCallback();
  ASSERT_FALSE(init_callback.is_null());

  // Return Init()'s result after the transaction gets destroyed.
  trans.reset();
  std::move(init_callback).Run(OK);  // Should not crash.
}

// Tests that changes to Auth realms are treated like auth rejections.
TEST_P(HttpNetworkTransactionTest, ChangeAuthRealms) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // First transaction will request a resource and receive a Basic challenge
  // with realm="first_realm".
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"),
  };
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Unauthorized\r\n"
               "WWW-Authenticate: Basic realm=\"first_realm\"\r\n"
               "\r\n"),
  };

  // After calling trans.RestartWithAuth(), provide an Authentication header
  // for first_realm. The server will reject and provide a challenge with
  // second_realm.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zmlyc3Q6YmF6\r\n"
                "\r\n"),
  };
  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 401 Unauthorized\r\n"
               "WWW-Authenticate: Basic realm=\"second_realm\"\r\n"
               "\r\n"),
  };

  // This again fails, and goes back to first_realm. Make sure that the
  // entry is removed from cache.
  MockWrite data_writes3[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic c2Vjb25kOmZvdQ==\r\n"
                "\r\n"),
  };
  MockRead data_reads3[] = {
      MockRead("HTTP/1.1 401 Unauthorized\r\n"
               "WWW-Authenticate: Basic realm=\"first_realm\"\r\n"
               "\r\n"),
  };

  // Try one last time (with the correct password) and get the resource.
  MockWrite data_writes4[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zmlyc3Q6YmFy\r\n"
                "\r\n"),
  };
  MockRead data_reads4[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 5\r\n"
               "\r\n"
               "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  StaticSocketDataProvider data3(data_reads3, data_writes3);
  StaticSocketDataProvider data4(data_reads4, data_writes4);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
  session_deps_.socket_factory->AddSocketDataProvider(&data4);

  TestCompletionCallback callback1;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Issue the first request with Authorize headers. There should be a
  // password prompt for first_realm waiting to be filled in after the
  // transaction completes.
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  std::optional<AuthChallengeInfo> challenge = response->auth_challenge;
  ASSERT_TRUE(challenge);
  EXPECT_FALSE(challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", challenge->challenger.Serialize());
  EXPECT_EQ("first_realm", challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, challenge->scheme);

  // Issue the second request with an incorrect password. There should be a
  // password prompt for second_realm waiting to be filled in after the
  // transaction completes.
  TestCompletionCallback callback2;
  rv = trans.RestartWithAuth(AuthCredentials(kFirst, kBaz),
                             callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  challenge = response->auth_challenge;
  ASSERT_TRUE(challenge);
  EXPECT_FALSE(challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", challenge->challenger.Serialize());
  EXPECT_EQ("second_realm", challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, challenge->scheme);

  // Issue the third request with another incorrect password. There should be
  // a password prompt for first_realm waiting to be filled in. If the password
  // prompt is not present, it indicates that the HttpAuthCacheEntry for
  // first_realm was not correctly removed.
  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(kSecond, kFou),
                             callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  challenge = response->auth_challenge;
  ASSERT_TRUE(challenge);
  EXPECT_FALSE(challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", challenge->challenger.Serialize());
  EXPECT_EQ("first_realm", challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, challenge->scheme);

  // Issue the fourth request with the correct password and username.
  TestCompletionCallback callback4;
  rv = trans.RestartWithAuth(AuthCredentials(kFirst, kBar),
                             callback4.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback4.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge.has_value());
}

// Regression test for https://crbug.com/754395.
TEST_P(HttpNetworkTransactionTest, IgnoreAltSvcWithInvalidCert) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  ssl.ssl_info.cert_status = CERT_STATUS_COMMON_NAME_INVALID;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  url::SchemeHostPort test_server(request.url);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());
}

TEST_P(HttpNetworkTransactionTest, HonorAlternativeServiceHeader) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  url::SchemeHostPort test_server(request.url);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, NetworkAnonymizationKey())
          .empty());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties->GetAlternativeServiceInfos(
          test_server, NetworkAnonymizationKey());
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  AlternativeService alternative_service(kProtoHTTP2, "mail.example.org", 443);
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
}

TEST_P(HttpNetworkTransactionTest,
       HonorAlternativeServiceHeaderWithNetworkAnonymizationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  session_deps_.http_server_properties =
      std::make_unique<HttpServerProperties>();

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const net::NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const net::NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  request.network_isolation_key = kNetworkIsolationKey1;
  request.network_anonymization_key = kNetworkAnonymizationKey1;

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ASSERT_TRUE(ssl.ssl_info.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  url::SchemeHostPort test_server(request.url);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(test_server, kNetworkAnonymizationKey1)
          .empty());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_pr
```