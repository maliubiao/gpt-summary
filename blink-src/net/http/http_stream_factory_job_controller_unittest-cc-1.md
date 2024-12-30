Response:
My thinking process to answer the prompt goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided C++ code snippet, specifically focusing on its role in Chromium's network stack. It also asks about relationships with JavaScript, logical reasoning, common usage errors, and debugging. Finally, it explicitly states this is part 2 of a 9-part series and asks for a summary of *this specific part*.

2. **Initial Scan and Keyword Identification:** I quickly scanned the code, looking for key terms and patterns. I noticed:
    * `TEST_F`: Indicates this is a unit test file.
    * `JobControllerReconsiderProxyAfterErrorTest`:  This is the main test fixture name, strongly suggesting the core function being tested is how the `HttpStreamFactoryJobController` handles errors when connecting through proxies and reconsiders proxy choices.
    * `ReconsiderProxyAfterErrorHttpProxy`, `ReconsiderProxyAfterErrorHttpsProxy`, `ReconsiderProxyAfterFirstNestedProxyErrorHttps`, `ReconsiderProxyAfterSecondNestedProxyErrorHttps`:  These are individual test case names, highlighting different proxy configurations and error scenarios.
    * `ProxyResolutionService`, `ConfiguredProxyResolutionService`, `ProxyInfo`, `ProxyRetryInfoMap`:  These relate to proxy management and retry mechanisms.
    * `MockWrite`, `MockRead`, `StaticSocketDataProvider`, `SSLSocketDataProvider`: These indicate the use of mocking to simulate network behavior and errors.
    * `ERR_NAME_NOT_RESOLVED`, `ERR_ADDRESS_UNREACHABLE`, `ERR_CONNECTION_TIMED_OUT`, etc.: These are specific network error codes being tested.
    * Loops iterating through `dest_url` (HTTP and HTTPS) and `kRetriableErrors`: This shows systematic testing of various scenarios.
    * `ASSERT_TRUE`, `EXPECT_CALL`, `EXPECT_TRUE`, `EXPECT_THAT`:  These are Google Test assertions and matchers, confirming the testing nature of the code.
    * Code blocks simulating different `ErrorPhase`s: This shows detailed testing of where the error occurs in the connection process.

3. **Formulate the Core Functionality:** Based on the keywords and test structure, I concluded that this code tests the `HttpStreamFactoryJobController`'s ability to:
    * Detect and handle various network errors that can occur when connecting through HTTP and HTTPS proxies (including nested proxies).
    * Fallback to alternative proxy configurations (including DIRECT connections) when a proxy fails.
    * Remember and avoid failed proxies in subsequent requests (proxy retry mechanism).

4. **Address Specific Questions:**

    * **JavaScript Relationship:**  I considered how this relates to the browser. While the C++ code itself isn't JavaScript, the *outcomes* it tests are directly relevant to web browsing. A user in JavaScript might initiate a fetch request, and if the underlying network connection through a proxy fails, the logic tested here is what determines if the browser tries a different proxy or connects directly. I provided an example using `fetch()`.

    * **Logical Reasoning (Input/Output):** I thought about the test structure. The tests set up specific error scenarios (simulated using mocks) and then verify the *output*: whether the connection succeeds (eventually, after fallback) and whether the failing proxies are added to the retry list. I provided a simplified example of this.

    * **User/Programming Errors:** I considered common mistakes. Incorrect proxy settings are a major user-related issue. For programmers, misconfiguring the proxy resolution service or not handling network errors properly in their applications are potential pitfalls.

    * **User Operation to Reach the Code:** I traced the steps a user might take. Typing a URL, clicking a link, or a web app making a request are the starting points. The browser's network stack then handles proxy resolution and connection establishment, potentially reaching the code being tested if proxy errors occur.

5. **Synthesize the Summary (Part 2 Functionality):** The prompt specifically asked for a summary of *this part*. Therefore, the summary needed to focus on the proxy fallback and retry logic being tested in this specific code. I emphasized the different proxy configurations (HTTP, HTTPS, nested) and the various error scenarios covered.

6. **Review and Refine:** I reread my answer to ensure it was clear, concise, and accurately reflected the code's functionality. I checked if I had addressed all parts of the prompt. I made sure the language was appropriate for a technical explanation.

Essentially, my process involved understanding the context (unit testing), identifying the core functionality (proxy error handling and fallback), and then relating that functionality to the specific questions asked in the prompt. The test names and the error codes were strong clues to the code's purpose.
这是对位于 `net/http/http_stream_factory_job_controller_unittest.cc` 的 Chromium 网络栈源代码文件的第二部分的功能归纳。

**总而言之，这部分代码主要测试了 `HttpStreamFactoryJobController` 在通过 HTTP 和 HTTPS 代理连接时遇到错误后的代理回退和重试机制。它模拟了各种网络错误，并验证了在这些错误发生后，`JobController` 是否能够正确地尝试备用代理，最终回退到直连（DIRECT），并将失败的代理记录为不良，以便在后续请求中避免使用它们。**

**更具体地说，这部分代码测试了以下功能：**

* **HTTP 代理错误回退:**  当连接 HTTP 代理失败时，`JobController` 是否能尝试列表中的下一个代理（如果有），最终回退到直连。
* **HTTPS 代理错误回退:** 当连接 HTTPS 代理失败时，`JobController` 是否能尝试列表中的下一个代理（如果有），最终回退到直连。
* **嵌套代理错误回退 (HTTPS):** 当使用多层嵌套的 HTTPS 代理时，如果其中任何一层的代理连接失败，`JobController` 是否能够正确地回退到下一个可用的代理链或直连。测试分别针对了第一层和第二层代理的失败情况。
* **不同类型的可重试错误:** 代码针对多种可以安全重试的网络错误进行了测试，例如 DNS 解析失败 (`ERR_NAME_NOT_RESOLVED`)、连接超时 (`ERR_CONNECTION_TIMED_OUT`)、连接被拒绝 (`ERR_CONNECTION_REFUSED`)、SSL 协议错误 (`ERR_SSL_PROTOCOL_ERROR`) 等。
* **代理重试信息记录:** 验证在代理连接失败后，失败的代理信息是否会被记录到 `ProxyRetryInfoMap` 中，以便在后续请求中避免使用这些不良代理。
* **请求的成功完成:**  尽管中间经历了代理连接失败，最终的请求应该能够通过备用代理或直连成功完成。

**与 JavaScript 功能的关系：**

这部分 C++ 代码的功能直接影响着 JavaScript 中发起的网络请求的行为。当一个 JavaScript 使用 `fetch()` API 或 `XMLHttpRequest` 发起请求时，如果浏览器配置了代理，底层的网络栈（由这部分 C++ 代码组成）会负责处理与代理的连接。

**举例说明:**

假设一个 JavaScript 代码尝试通过配置的代理发送一个 GET 请求：

```javascript
fetch('https://www.example.com');
```

如果在浏览器的网络设置中配置了一个 HTTP 代理 `badproxy:99`，而这个代理由于网络问题暂时不可用（例如，连接超时），那么 `HttpStreamFactoryJobController` 的这部分代码就会发挥作用。它会尝试连接 `badproxy:99`，当连接失败并返回一个可重试的错误（比如 `ERR_CONNECTION_TIMED_OUT`）时，`JobController` 会根据代理配置尝试下一个代理（如果有），或者直接连接目标服务器（如果配置了直连作为最后的选项）。  这个过程对 JavaScript 代码来说是透明的，JavaScript 代码最终会收到请求成功或失败的响应，而不需要关心底层的代理切换逻辑。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 一个 `HttpRequestInfo` 对象，指定了请求方法 (GET)、URL (例如 `https://www.example.com`)。
2. 一个 `ConfiguredProxyResolutionService` 对象，配置了代理列表，例如 "HTTPS badproxy:99; HTTPS badfallbackproxy:98; DIRECT"。
3. 模拟的网络环境，使得 `badproxy:99` 和 `badfallbackproxy:98` 在连接时会返回特定的可重试错误（例如 `ERR_CONNECTION_TIMED_OUT`）。

**输出:**

1. `HttpStreamRequest::Delegate::OnStreamReadyImpl` 被调用，并传递一个 `ProxyInfo` 对象，其 `is_direct()` 方法返回 `true`，表明最终使用了直连。
2. `session_->proxy_resolution_service()->proxy_retry_info()` 返回的 `ProxyRetryInfoMap` 中包含了 `badproxy:99` 和 `badfallbackproxy:98` 的信息，表明这两个代理被标记为不良。

**用户或编程常见的使用错误:**

* **用户错误:**
    * **配置了不可用的代理:** 用户手动配置了一个已经失效或者网络连接不稳定的代理服务器。这部分代码虽然能处理这种情况并回退，但用户可能会经历连接延迟或错误提示。
    * **错误的代理配置:** 用户可能错误地配置了代理的协议、主机名或端口，导致连接失败。

* **编程错误:**
    * **PAC 脚本错误:** 如果代理配置是通过 PAC (Proxy Auto-Config) 脚本实现的，脚本中的逻辑错误可能导致选择了错误的代理或者在应该直连的时候选择了代理。
    * **未处理网络错误:** 虽然这部分代码处理了底层的代理回退，但应用程序开发者仍然需要处理更高层次的网络错误，例如请求超时、服务器返回错误状态码等。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 用户发起了一个网络请求。
2. **浏览器解析 URL 并确定请求类型:** 例如，这是一个 HTTPS 请求。
3. **浏览器查询代理设置:**  浏览器会检查用户的代理配置，可能包括手动配置的代理服务器或 PAC 脚本。
4. **如果配置了代理，`HttpStreamFactory` 创建 `HttpStreamFactoryImpl::JobController`:**  这个组件负责根据代理配置尝试建立连接。
5. **`JobController` 尝试连接第一个代理:** 例如，"HTTPS badproxy:99"。
6. **连接尝试失败并返回可重试错误:** 例如，由于 `badproxy:99` 服务器宕机，连接超时 (`ERR_CONNECTION_TIMED_OUT`)。
7. **`JobController` 根据错误类型和代理列表决定回退:** 这部分代码测试的就是这个回退逻辑。它会尝试下一个代理 "HTTPS badfallbackproxy:98"，如果也失败，最终会尝试直连。
8. **如果直连成功，请求完成:** 用户最终能够访问目标网站。
9. **失败的代理信息被记录:**  `badproxy:99` 和 `badfallbackproxy:98` 会被添加到不良代理列表中，在一段时间内避免使用。

在调试网络连接问题时，如果怀疑是代理的问题，可以检查浏览器的网络日志 (chrome://net-export/)，查看代理连接的尝试和失败信息，以及是否发生了代理回退。也可以通过禁用代理来排除代理引起的问题。

Prompt: 
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共9部分，请归纳一下它的功能

"""
he
      // HTTP/1.1 parser maps it to `ERR_EMPTY_RESPONSE` or
      // `ERR_RESPONSE_HEADERS_TRUNCATED` in most cases.
      //
      // TODO(davidben): Is omitting `ERR_EMPTY_RESPONSE` a bug in proxy error
      // handling?
      {ErrorPhase::kHostResolution, ERR_NAME_NOT_RESOLVED},
      {ErrorPhase::kTcpConnect, ERR_ADDRESS_UNREACHABLE},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_TIMED_OUT},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_RESET},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_ABORTED},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_REFUSED},
      {ErrorPhase::kTunnelRead, ERR_TIMED_OUT},
      {ErrorPhase::kTunnelRead, ERR_SSL_PROTOCOL_ERROR},
  };

  for (GURL dest_url :
       {GURL("http://www.example.com"), GURL("https://www.example.com")}) {
    SCOPED_TRACE(dest_url);

    for (const auto& mock_error : kRetriableErrors) {
      SCOPED_TRACE(ErrorToString(mock_error.error));

      CreateSessionDeps();

      std::unique_ptr<ConfiguredProxyResolutionService>
          proxy_resolution_service =
              ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
                  "PROXY badproxy:99; PROXY badfallbackproxy:98; DIRECT",
                  TRAFFIC_ANNOTATION_FOR_TESTS);
      auto test_proxy_delegate = std::make_unique<TestProxyDelegate>();
      test_proxy_delegate->set_extra_header_name("Foo");

      // Before starting the test, verify that there are no proxies marked as
      // bad.
      ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());

      constexpr char kBadProxyTunnelRequest[] =
          "CONNECT www.example.com:443 HTTP/1.1\r\n"
          "Host: www.example.com:443\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: badproxy:99\r\n\r\n";
      constexpr char kBadFallbackProxyTunnelRequest[] =
          "CONNECT www.example.com:443 HTTP/1.1\r\n"
          "Host: www.example.com:443\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: badfallbackproxy:98\r\n\r\n";
      const MockWrite kBadProxyTunnelWrites[] = {
          {ASYNC, kBadProxyTunnelRequest}};
      const MockWrite kBadFallbackProxyTunnelWrites[] = {
          {ASYNC, kBadFallbackProxyTunnelRequest}};
      std::vector<MockRead> reads;

      // Generate identical errors for both the main proxy and the fallback
      // proxy. No alternative job is created for either, so only need one data
      // provider for each, when the request makes it to the socket layer.
      std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job;
      std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job2;
      switch (mock_error.phase) {
        case ErrorPhase::kHostResolution:
          // Only ERR_NAME_NOT_RESOLVED can be returned by the mock host
          // resolver.
          DCHECK_EQ(ERR_NAME_NOT_RESOLVED, mock_error.error);
          session_deps_.host_resolver->rules()->AddSimulatedFailure("badproxy");
          session_deps_.host_resolver->rules()->AddSimulatedFailure(
              "badfallbackproxy");
          break;
        case ErrorPhase::kTcpConnect:
          socket_data_proxy_main_job =
              std::make_unique<StaticSocketDataProvider>();
          socket_data_proxy_main_job->set_connect_data(
              MockConnect(ASYNC, mock_error.error));
          socket_data_proxy_main_job2 =
              std::make_unique<StaticSocketDataProvider>();
          socket_data_proxy_main_job2->set_connect_data(
              MockConnect(ASYNC, mock_error.error));
          break;
        case ErrorPhase::kTunnelRead:
          // Tunnels aren't established for HTTP destinations.
          if (dest_url.SchemeIs(url::kHttpScheme)) {
            continue;
          }
          reads.emplace_back(ASYNC, mock_error.error);
          socket_data_proxy_main_job =
              std::make_unique<StaticSocketDataProvider>(reads,
                                                         kBadProxyTunnelWrites);
          socket_data_proxy_main_job2 =
              std::make_unique<StaticSocketDataProvider>(
                  reads, kBadFallbackProxyTunnelWrites);
          break;
      }

      if (socket_data_proxy_main_job) {
        session_deps_.socket_factory->AddSocketDataProvider(
            socket_data_proxy_main_job.get());
        session_deps_.socket_factory->AddSocketDataProvider(
            socket_data_proxy_main_job2.get());
      }

      // After both proxies fail, the request should fall back to using DIRECT,
      // and succeed.
      SSLSocketDataProvider ssl_data_first_request(ASYNC, OK);
      StaticSocketDataProvider socket_data_direct_first_request;
      socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
      session_deps_.socket_factory->AddSocketDataProvider(
          &socket_data_direct_first_request);
      // Only used in the HTTPS destination case, but harmless in the HTTP case.
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          &ssl_data_first_request);

      // Second request should use DIRECT, skipping the bad proxies, and
      // succeed.
      SSLSocketDataProvider ssl_data_second_request(ASYNC, OK);
      StaticSocketDataProvider socket_data_direct_second_request;
      socket_data_direct_second_request.set_connect_data(
          MockConnect(ASYNC, OK));
      session_deps_.socket_factory->AddSocketDataProvider(
          &socket_data_direct_second_request);
      // Only used in the HTTPS destination case, but harmless in the HTTP case.
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          &ssl_data_second_request);

      // Now request a stream. It should succeed using the DIRECT fallback proxy
      // option.
      HttpRequestInfo request_info;
      request_info.method = "GET";
      request_info.url = dest_url;
      Initialize(std::move(proxy_resolution_service),
                 std::move(test_proxy_delegate));

      // Start two requests. The first request should consume data from
      // |socket_data_proxy_main_job| and |socket_data_direct_first_request|.
      // The second request should consume data from
      // |socket_data_direct_second_request|.

      for (size_t i = 0; i < 2; ++i) {
        ProxyInfo used_proxy_info;
        EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
            .Times(1)
            .WillOnce(::testing::SaveArg<0>(&used_proxy_info));

        std::unique_ptr<HttpStreamRequest> request =
            CreateJobController(request_info);
        RunUntilIdle();

        // Verify that request was fetched without proxy.
        EXPECT_TRUE(used_proxy_info.is_direct());

        // The proxies that failed should now be known to the proxy service as
        // bad.
        const ProxyRetryInfoMap& retry_info =
            session_->proxy_resolution_service()->proxy_retry_info();
        ASSERT_THAT(retry_info, SizeIs(2));
        EXPECT_THAT(retry_info, Contains(Key(ProxyUriToProxyChain(
                                    "badproxy:99", ProxyServer::SCHEME_HTTP))));
        EXPECT_THAT(retry_info,
                    Contains(Key(ProxyUriToProxyChain(
                        "badfallbackproxy:98", ProxyServer::SCHEME_HTTP))));

        // The idle socket should have been added back to the socket pool. Close
        // it, so the next loop iteration creates a new socket instead of
        // reusing the idle one.
        auto* socket_pool = session_->GetSocketPool(
            HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());
        EXPECT_EQ(1, socket_pool->IdleSocketCount());
        socket_pool->CloseIdleSockets("Close socket reason");
      }
      EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
    }
  }
}

// Test proxy fallback logic in the case connecting through an HTTPS proxy.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       ReconsiderProxyAfterErrorHttpsProxy) {
  enum class ErrorPhase {
    kHostResolution,
    kTcpConnect,
    kProxySslHandshake,
    kTunnelRead,
  };

  const struct {
    ErrorPhase phase;
    Error error;
    // Each test case simulates a connection attempt through a proxy that fails
    // twice, followed by two connection attempts that succeed. For most cases,
    // this is done by having a connection attempt to the first proxy fail,
    // triggering fallback to a second proxy, which also fails, and then
    // fallback to the final (DIRECT) proxy option. However, SslConnectJobs have
    // their own try logic in certain cases. This value is true for those cases,
    // in which case there are two connection attempts to the first proxy, and
    // then the requests fall back to the second (DIRECT) proxy.
    bool triggers_ssl_connect_job_retry_logic = false;
  } kRetriableErrors[] = {
      // These largely correspond to the list of errors in
      // CanFalloverToNextProxy() which can occur with an HTTPS proxy.
      //
      // We omit `ERR_CONNECTION_CLOSED` because it is largely unreachable. The
      // HTTP/1.1 parser maps it to `ERR_EMPTY_RESPONSE` or
      // `ERR_RESPONSE_HEADERS_TRUNCATED` in most cases.
      //
      // TODO(davidben): Is omitting `ERR_EMPTY_RESPONSE` a bug in proxy error
      // handling?
      {ErrorPhase::kHostResolution, ERR_NAME_NOT_RESOLVED},
      {ErrorPhase::kTcpConnect, ERR_ADDRESS_UNREACHABLE},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_TIMED_OUT},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_RESET},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_ABORTED},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_REFUSED},
      {ErrorPhase::kProxySslHandshake, ERR_CERT_COMMON_NAME_INVALID},
      {ErrorPhase::kProxySslHandshake, ERR_SSL_PROTOCOL_ERROR,
       /*triggers_ssl_connect_job_retry_logic=*/true},
      {ErrorPhase::kTunnelRead, ERR_TIMED_OUT},
      {ErrorPhase::kTunnelRead, ERR_SSL_PROTOCOL_ERROR},
  };

  for (GURL dest_url :
       {GURL("http://www.example.com"), GURL("https://www.example.com")}) {
    SCOPED_TRACE(dest_url);

    for (const auto& mock_error : kRetriableErrors) {
      SCOPED_TRACE(ErrorToString(mock_error.error));

      CreateSessionDeps();

      std::unique_ptr<ConfiguredProxyResolutionService>
          proxy_resolution_service =
              ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
                  "HTTPS badproxy:99; HTTPS badfallbackproxy:98; DIRECT",
                  TRAFFIC_ANNOTATION_FOR_TESTS);
      if (mock_error.triggers_ssl_connect_job_retry_logic) {
        proxy_resolution_service =
            ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
                "HTTPS badproxy:99; DIRECT", TRAFFIC_ANNOTATION_FOR_TESTS);
      }
      auto test_proxy_delegate = std::make_unique<TestProxyDelegate>();
      test_proxy_delegate->set_extra_header_name("Foo");

      // Before starting the test, verify that there are no proxies marked as
      // bad.
      ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());

      constexpr char kBadProxyTunnelRequest[] =
          "CONNECT www.example.com:443 HTTP/1.1\r\n"
          "Host: www.example.com:443\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: https://badproxy:99\r\n\r\n";
      constexpr char kBadFallbackProxyTunnelRequest[] =
          "CONNECT www.example.com:443 HTTP/1.1\r\n"
          "Host: www.example.com:443\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: https://badfallbackproxy:98\r\n\r\n";
      const MockWrite kBadProxyTunnelWrites[] = {
          {ASYNC, kBadProxyTunnelRequest}};
      const MockWrite kBadFallbackProxyTunnelWrites[] = {
          {ASYNC, kBadFallbackProxyTunnelRequest}};
      std::vector<MockRead> reads;

      // Generate identical errors for both the main proxy and the fallback
      // proxy. No alternative job is created for either, so only need one data
      // provider for each, when the request makes it to the socket layer.
      std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job;
      std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job2;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job2;
      switch (mock_error.phase) {
        case ErrorPhase::kHostResolution:
          // Only ERR_NAME_NOT_RESOLVED can be returned by the mock host
          // resolver.
          DCHECK_EQ(ERR_NAME_NOT_RESOLVED, mock_error.error);
          session_deps_.host_resolver->rules()->AddSimulatedFailure("badproxy");
          session_deps_.host_resolver->rules()->AddSimulatedFailure(
              "badfallbackproxy");
          break;
        case ErrorPhase::kTcpConnect:
          socket_data_proxy_main_job =
              std::make_unique<StaticSocketDataProvider>();
          socket_data_proxy_main_job->set_connect_data(
              MockConnect(ASYNC, mock_error.error));
          socket_data_proxy_main_job2 =
              std::make_unique<StaticSocketDataProvider>();
          socket_data_proxy_main_job2->set_connect_data(
              MockConnect(ASYNC, mock_error.error));
          break;
        case ErrorPhase::kProxySslHandshake:
          socket_data_proxy_main_job =
              std::make_unique<StaticSocketDataProvider>();
          ssl_data_proxy_main_job =
              std::make_unique<SSLSocketDataProvider>(ASYNC, mock_error.error);
          socket_data_proxy_main_job2 =
              std::make_unique<StaticSocketDataProvider>();
          ssl_data_proxy_main_job2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, mock_error.error);
          break;
        case ErrorPhase::kTunnelRead:
          // Tunnels aren't established for HTTP destinations.
          if (dest_url.SchemeIs(url::kHttpScheme)) {
            continue;
          }
          reads.emplace_back(ASYNC, mock_error.error);
          socket_data_proxy_main_job =
              std::make_unique<StaticSocketDataProvider>(reads,
                                                         kBadProxyTunnelWrites);
          ssl_data_proxy_main_job =
              std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
          socket_data_proxy_main_job2 =
              std::make_unique<StaticSocketDataProvider>(
                  reads, mock_error.triggers_ssl_connect_job_retry_logic
                             ? kBadProxyTunnelWrites
                             : kBadFallbackProxyTunnelWrites);
          ssl_data_proxy_main_job2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
          break;
      }

      if (socket_data_proxy_main_job) {
        session_deps_.socket_factory->AddSocketDataProvider(
            socket_data_proxy_main_job.get());
        session_deps_.socket_factory->AddSocketDataProvider(
            socket_data_proxy_main_job2.get());
      }
      if (ssl_data_proxy_main_job) {
        session_deps_.socket_factory->AddSSLSocketDataProvider(
            ssl_data_proxy_main_job.get());
        session_deps_.socket_factory->AddSSLSocketDataProvider(
            ssl_data_proxy_main_job2.get());
      }

      // After both proxies fail, the request should fall back to using DIRECT,
      // and succeed.
      SSLSocketDataProvider ssl_data_first_request(ASYNC, OK);
      StaticSocketDataProvider socket_data_direct_first_request;
      socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
      session_deps_.socket_factory->AddSocketDataProvider(
          &socket_data_direct_first_request);
      // Only used in the HTTPS destination case, but harmless in the HTTP case.
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          &ssl_data_first_request);

      // Second request should use DIRECT, skipping the bad proxies, and
      // succeed.
      SSLSocketDataProvider ssl_data_second_request(ASYNC, OK);
      StaticSocketDataProvider socket_data_direct_second_request;
      socket_data_direct_second_request.set_connect_data(
          MockConnect(ASYNC, OK));
      session_deps_.socket_factory->AddSocketDataProvider(
          &socket_data_direct_second_request);
      // Only used in the HTTPS destination case, but harmless in the HTTP case.
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          &ssl_data_second_request);

      // Now request a stream. It should succeed using the DIRECT fallback proxy
      // option.
      HttpRequestInfo request_info;
      request_info.method = "GET";
      request_info.url = dest_url;

      Initialize(std::move(proxy_resolution_service),
                 std::move(test_proxy_delegate));

      // Start two requests. The first request should consume data from
      // |socket_data_proxy_main_job| and |socket_data_direct_first_request|.
      // The second request should consume data from
      // |socket_data_direct_second_request|.

      for (size_t i = 0; i < 2; ++i) {
        ProxyInfo used_proxy_info;
        EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
            .Times(1)
            .WillOnce(::testing::SaveArg<0>(&used_proxy_info));

        std::unique_ptr<HttpStreamRequest> request =
            CreateJobController(request_info);
        RunUntilIdle();

        // Verify that request was fetched without proxy.
        EXPECT_TRUE(used_proxy_info.is_direct());

        // The proxies that failed should now be known to the proxy service as
        // bad.
        const ProxyRetryInfoMap& retry_info =
            session_->proxy_resolution_service()->proxy_retry_info();
        if (!mock_error.triggers_ssl_connect_job_retry_logic) {
          ASSERT_THAT(retry_info, SizeIs(2));
          EXPECT_THAT(retry_info,
                      Contains(Key(ProxyUriToProxyChain(
                          "https://badproxy:99", ProxyServer::SCHEME_HTTP))));
          EXPECT_THAT(
              retry_info,
              Contains(Key(ProxyUriToProxyChain("https://badfallbackproxy:98",
                                                ProxyServer::SCHEME_HTTP))));
        } else {
          ASSERT_THAT(retry_info, SizeIs(1));
          EXPECT_THAT(retry_info,
                      Contains(Key(ProxyUriToProxyChain(
                          "https://badproxy:99", ProxyServer::SCHEME_HTTP))));
        }

        // The idle socket should have been added back to the socket pool. Close
        // it, so the next loop iteration creates a new socket instead of
        // reusing the idle one.
        auto* socket_pool = session_->GetSocketPool(
            HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());
        EXPECT_EQ(1, socket_pool->IdleSocketCount());
        socket_pool->CloseIdleSockets("Close socket reason");
      }
      EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
    }
  }
}

// Same as above but using a multi-proxy chain, with errors encountered by the
// first proxy server in the chain.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       ReconsiderProxyAfterFirstNestedProxyErrorHttps) {
  enum class ErrorPhase {
    kHostResolution,
    kTcpConnect,
    kProxySslHandshake,
    kTunnelRead,
  };

  const struct {
    ErrorPhase phase;
    Error error;
    // For a description of this field, see the corresponding struct member
    // comment in `ReconsiderProxyAfterErrorHttpsProxy`.
    bool triggers_ssl_connect_job_retry_logic = false;
  } kRetriableErrors[] = {
      // These largely correspond to the list of errors in
      // CanFalloverToNextProxy() which can occur with an HTTPS proxy.
      //
      // We omit `ERR_CONNECTION_CLOSED` because it is largely unreachable. The
      // HTTP/1.1 parser maps it to `ERR_EMPTY_RESPONSE` or
      // `ERR_RESPONSE_HEADERS_TRUNCATED` in most cases.
      //
      // TODO(davidben): Is omitting `ERR_EMPTY_RESPONSE` a bug in proxy error
      // handling?
      {ErrorPhase::kHostResolution, ERR_NAME_NOT_RESOLVED},
      {ErrorPhase::kTcpConnect, ERR_ADDRESS_UNREACHABLE},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_TIMED_OUT},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_RESET},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_ABORTED},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_REFUSED},
      {ErrorPhase::kProxySslHandshake, ERR_CERT_COMMON_NAME_INVALID},
      {ErrorPhase::kProxySslHandshake, ERR_SSL_PROTOCOL_ERROR,
       /*triggers_ssl_connect_job_retry_logic=*/true},
      {ErrorPhase::kTunnelRead, ERR_TIMED_OUT},
      {ErrorPhase::kTunnelRead, ERR_SSL_PROTOCOL_ERROR},
  };

  const ProxyServer kGoodProxyServer{ProxyServer::SCHEME_HTTPS,
                                     HostPortPair("goodproxyserver", 100)};
  const ProxyServer kBadProxyServer1{ProxyServer::SCHEME_HTTPS,
                                     HostPortPair("badproxyserver", 99)};
  const ProxyServer kBadProxyServer2{
      ProxyServer::SCHEME_HTTPS, HostPortPair("badfallbackproxyserver", 98)};
  const ProxyChain kNestedProxyChain1 =
      ProxyChain::ForIpProtection({{kBadProxyServer1, kGoodProxyServer}});
  const ProxyChain kNestedProxyChain2 =
      ProxyChain::ForIpProtection({{kBadProxyServer2, kGoodProxyServer}});

  for (GURL dest_url :
       {GURL("http://www.example.com"), GURL("https://www.example.com")}) {
    SCOPED_TRACE(dest_url);

    for (const auto& mock_error : kRetriableErrors) {
      SCOPED_TRACE(ErrorToString(mock_error.error));

      CreateSessionDeps();

      ProxyList proxy_list;
      proxy_list.AddProxyChain(kNestedProxyChain1);
      proxy_list.AddProxyChain(kNestedProxyChain2);
      proxy_list.AddProxyChain(ProxyChain::Direct());
      ProxyConfig proxy_config = ProxyConfig::CreateForTesting(proxy_list);

      std::unique_ptr<ConfiguredProxyResolutionService>
          proxy_resolution_service =
              ConfiguredProxyResolutionService::CreateFixedForTest(
                  ProxyConfigWithAnnotation(proxy_config,
                                            TRAFFIC_ANNOTATION_FOR_TESTS));

      if (mock_error.triggers_ssl_connect_job_retry_logic) {
        proxy_list.Clear();
        proxy_list.AddProxyChain(kNestedProxyChain1);
        proxy_list.AddProxyChain(ProxyChain::Direct());
        ProxyConfig proxy_config2 = ProxyConfig::CreateForTesting(proxy_list);

        proxy_resolution_service =
            ConfiguredProxyResolutionService::CreateFixedForTest(
                ProxyConfigWithAnnotation(proxy_config2,
                                          TRAFFIC_ANNOTATION_FOR_TESTS));
      }
      auto test_proxy_delegate = std::make_unique<TestProxyDelegate>();
      test_proxy_delegate->set_extra_header_name("Foo");

      // Before starting the test, verify that there are no proxies marked as
      // bad.
      ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());

      constexpr char kBadProxyServer1TunnelRequest[] =
          "CONNECT goodproxyserver:100 HTTP/1.1\r\n"
          "Host: goodproxyserver:100\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: https://badproxyserver:99\r\n\r\n";
      constexpr char kBadProxyServer2TunnelRequest[] =
          "CONNECT goodproxyserver:100 HTTP/1.1\r\n"
          "Host: goodproxyserver:100\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: https://badfallbackproxyserver:98\r\n\r\n";
      const MockWrite kBadProxyServer1TunnelWrites[] = {
          MockWrite(ASYNC, 0, kBadProxyServer1TunnelRequest)};
      const MockWrite kBadProxyServer2TunnelWrites[] = {
          MockWrite(ASYNC, 0, kBadProxyServer2TunnelRequest)};
      std::vector<MockRead> reads;

      // Generate identical errors for the first proxy server in both the main
      // proxy chain and the fallback proxy chain. No alternative job is created
      // for either, so only need one data provider for each, when the request
      // makes it to the socket layer.
      std::unique_ptr<SequencedSocketData> socket_data_proxy_main_job;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job;
      std::unique_ptr<SequencedSocketData> socket_data_proxy_main_job2;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job2;
      switch (mock_error.phase) {
        case ErrorPhase::kHostResolution:
          // Only ERR_NAME_NOT_RESOLVED can be returned by the mock host
          // resolver.
          DCHECK_EQ(ERR_NAME_NOT_RESOLVED, mock_error.error);
          session_deps_.host_resolver->rules()->AddSimulatedFailure(
              "badproxyserver");
          session_deps_.host_resolver->rules()->AddSimulatedFailure(
              "badfallbackproxyserver");
          break;
        case ErrorPhase::kTcpConnect:
          socket_data_proxy_main_job = std::make_unique<SequencedSocketData>();
          socket_data_proxy_main_job->set_connect_data(
              MockConnect(ASYNC, mock_error.error));
          socket_data_proxy_main_job2 = std::make_unique<SequencedSocketData>();
          socket_data_proxy_main_job2->set_connect_data(
              MockConnect(ASYNC, mock_error.error));
          break;
        case ErrorPhase::kProxySslHandshake:
          socket_data_proxy_main_job = std::make_unique<SequencedSocketData>();
          ssl_data_proxy_main_job =
              std::make_unique<SSLSocketDataProvider>(ASYNC, mock_error.error);
          socket_data_proxy_main_job2 = std::make_unique<SequencedSocketData>();
          ssl_data_proxy_main_job2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, mock_error.error);
          break;
        case ErrorPhase::kTunnelRead:
          // Note: Unlike for single-proxy chains, tunnels are established for
          // HTTP destinations when multi-proxy chains are in use, so simulate
          // tunnel read failures in all cases.
          reads.emplace_back(MockRead(ASYNC, mock_error.error, 1));
          socket_data_proxy_main_job = std::make_unique<SequencedSocketData>(
              reads, kBadProxyServer1TunnelWrites);
          ssl_data_proxy_main_job =
              std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
          socket_data_proxy_main_job2 = std::make_unique<SequencedSocketData>(
              reads, kBadProxyServer2TunnelWrites);
          ssl_data_proxy_main_job2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
          break;
      }

      if (socket_data_proxy_main_job) {
        session_deps_.socket_factory->AddSocketDataProvider(
            socket_data_proxy_main_job.get());
        session_deps_.socket_factory->AddSocketDataProvider(
            socket_data_proxy_main_job2.get());
      }
      if (ssl_data_proxy_main_job) {
        session_deps_.socket_factory->AddSSLSocketDataProvider(
            ssl_data_proxy_main_job.get());
        session_deps_.socket_factory->AddSSLSocketDataProvider(
            ssl_data_proxy_main_job2.get());
      }

      // After both proxy chains fail, the request should fall back to using
      // DIRECT, and succeed.
      SSLSocketDataProvider ssl_data_first_request(ASYNC, OK);
      StaticSocketDataProvider socket_data_direct_first_request;
      socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
      session_deps_.socket_factory->AddSocketDataProvider(
          &socket_data_direct_first_request);
      // Only used in the HTTPS destination case, but harmless in the HTTP case.
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          &ssl_data_first_request);

      // Second request should use DIRECT, skipping the bad proxies, and
      // succeed.
      SSLSocketDataProvider ssl_data_second_request(ASYNC, OK);
      StaticSocketDataProvider socket_data_direct_second_request;
      socket_data_direct_second_request.set_connect_data(
          MockConnect(ASYNC, OK));
      session_deps_.socket_factory->AddSocketDataProvider(
          &socket_data_direct_second_request);
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          &ssl_data_second_request);

      // Now request a stream. It should succeed using the DIRECT fallback proxy
      // option.
      HttpRequestInfo request_info;
      request_info.method = "GET";
      request_info.url = dest_url;

      Initialize(std::move(proxy_resolution_service),
                 std::move(test_proxy_delegate));

      // Start two requests. The first request should consume data from
      // `socket_data_proxy_main_job` and `socket_data_direct_first_request`.
      // The second request should consume data from
      // `socket_data_direct_second_request`.

      for (size_t i = 0; i < 2; ++i) {
        ProxyInfo used_proxy_info;
        EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
            .Times(1)
            .WillOnce(::testing::SaveArg<0>(&used_proxy_info));

        std::unique_ptr<HttpStreamRequest> request =
            CreateJobController(request_info);
        RunUntilIdle();

        // Verify that request was fetched without proxy.
        EXPECT_TRUE(used_proxy_info.is_direct());

        // The proxies that failed should now be known to the proxy service as
        // bad.
        const ProxyRetryInfoMap& retry_info =
            session_->proxy_resolution_service()->proxy_retry_info();
        if (!mock_error.triggers_ssl_connect_job_retry_logic) {
          ASSERT_THAT(retry_info, SizeIs(2));
          EXPECT_THAT(retry_info, Contains(Key(kNestedProxyChain1)));
          EXPECT_THAT(retry_info, Contains(Key(kNestedProxyChain2)));
        } else {
          ASSERT_THAT(retry_info, SizeIs(1));
          EXPECT_THAT(retry_info, Contains(Key(kNestedProxyChain1)));
        }

        // The idle socket should have been added back to the socket pool. Close
        // it, so the next loop iteration creates a new socket instead of
        // reusing the idle one.
        auto* socket_pool = session_->GetSocketPool(
            HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());
        EXPECT_EQ(1, socket_pool->IdleSocketCount());
        socket_pool->CloseIdleSockets("Close socket reason");
      }
      EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
    }
  }
}

// Same as above but using a multi-proxy chain, with errors encountered by the
// second proxy server in the chain.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       ReconsiderProxyAfterSecondNestedProxyErrorHttps) {
  enum class ErrorPhase {
    // Note: Skip the kHostResolution and kTcpConnect cases for this test since
    // those only make sense for connections to the first proxy server.
    kProxySslHandshake,
    kTunnelRead,
  };

  const struct {
    ErrorPhase phase;
    Error error;
    // For a description of this field, see the corresponding struct member
    // comment in `ReconsiderProxyAfterErrorHttpsProxy`.
    bool triggers_ssl_connect_job_retry_logic = false;
  } kRetriableErrors[] = {
      // These largely correspond to the list of errors in
      // CanFalloverToNextProxy() which can occur with an HTTPS proxy.
      //
      // We omit `ERR_CONNECTION_CLOSED` because it is largely unreachable. The
      // HTTP/1.1 parser maps it to `ERR_EMPTY_RESPONSE` or
      // `ERR_RESPONSE_HEADERS_TRUNCATED` in most cases.
      //
      // TODO(davidben): Is omitting `ERR_EMPTY_RESPONSE` a bug in proxy error
      // handling?
      {ErrorPhase::kProxySslHandshake, ERR_CERT_COMMON_NAME_INVALID},
      {ErrorPhase::kProxySslHandshake, ERR_SSL_PROTOCOL_ERROR,
       /*triggers_ssl_connect_job_retry_logic=*/true},
      {ErrorPhase::kTunnelRead, ERR_TIMED_OUT},
      {ErrorPhase::kTunnelRead, ERR_SSL_PROTOCOL_ERROR},
  };

  const ProxyServer kGoodProxyServer{ProxyServer::SCHEME_HTTPS,
                                     HostPortPair("goodproxyserver", 100)};
  const ProxyServer kBadProxyServer1{ProxyServer::SCHEME_HTTPS,
                                     HostPortPair("badproxyserver", 99)};
  const ProxyServer kBadProxyServer2{
      ProxyServer::SCHEME_HTTPS, HostPortPair("badfallbackproxyserver", 98)};
  const ProxyChain kNestedProxyChain1 =
      ProxyChain::ForIpProtection({{kGoodProxyServer, kBadProxyServer1}});
  const ProxyChain kNestedProxyChain2 =
      ProxyChain::ForIpProtection({{kGoodProxyServer, kBadProxyServer2}});

  for (GURL dest_url :
       {GURL("http://www.example.com"), GURL("https://www.example.com")}) {
    SCOPED_TRACE(dest_url);

    for (const auto& mock_error : kRetriableErrors) {
      SCOPED_TRACE(ErrorToString(mock_error.error));

      CreateSessionDeps();

      ProxyList proxy_list;
      proxy_list.AddProxyChain(kNestedProxyChain1);
      proxy_list.AddProxyChain(kNestedProxyChain2);
      proxy_list.AddProxyChain(P
"""


```