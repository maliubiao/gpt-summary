Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. The file is `net/http/http_stream_factory_job_controller_unittest.cc`.

Here's a breakdown of how to analyze the code and address the user's requests:

1. **Identify the Core Functionality:** The filename strongly suggests this is a unit test file for `HttpStreamFactoryJobController`. Unit tests verify the behavior of individual components in isolation. Looking at the test cases, they focus on scenarios involving proxy configurations, connection errors, and fallback mechanisms.

2. **Summarize the Main Purpose:** The primary function of this test file is to verify how the `HttpStreamFactoryJobController` handles different proxy configurations and connection errors, especially how it falls back to alternative proxy configurations (including DIRECT connections) when errors occur.

3. **Address Specific Questions:**

    * **Functionality Listing:** Extract the key functionalities demonstrated in the tests. These will revolve around proxy selection, error handling, retry mechanisms, and fallback strategies.
    * **Relationship to JavaScript:**  Consider how network requests are initiated in a browser. JavaScript uses APIs like `fetch` or `XMLHttpRequest`. These APIs eventually interact with the browser's network stack, which includes components like `HttpStreamFactoryJobController`. The connection is indirect but crucial.
    * **Logical Reasoning (Input/Output):**  For a test case, identify the initial proxy configuration (the input) and the expected outcome (the output) based on the simulated errors.
    * **User/Programming Errors:** Think about scenarios where incorrect proxy settings or network issues might lead the code under test to be executed.
    * **User Operations as Debugging Clues:** Trace how a user action (like accessing a website) might lead to the execution of this code, particularly when proxy issues are involved.
    * **Overall Functionality Summary (Part 3 of 9):**  Synthesize the understanding gained from this specific part of the code. Since it focuses on error handling and proxy fallback, that should be the core of the summary.

4. **Structure the Response:** Organize the findings into clear sections corresponding to the user's questions. Use code examples and clear explanations.

**Detailed Analysis of the Code Snippet:**

* **Test Fixture:** The code defines test fixtures like `JobControllerReconsiderProxyAfterErrorTest`. These set up the necessary environment for testing, including mock objects (like `MockHostResolver`, `MockClientSocketFactory`).
* **Test Cases:** Each `TEST_F` block represents a specific test scenario.
* **Proxy Configurations:** The tests configure different proxy setups using `ConfiguredProxyResolutionService`, including direct connections, single proxies, and multiple proxy chains.
* **Error Simulation:**  `MockConnect`, `SSLSocketDataProvider`, and `StaticSocketDataProvider` are used to simulate various network errors at different stages of the connection process (DNS resolution, TCP connection, SSL handshake, tunnel establishment).
* **Expected Outcomes:** The tests use `EXPECT_CALL` to assert the expected behavior, such as calling `OnStreamReadyImpl` with the correct proxy information or `OnStreamFailed` with the expected error code.
* **Retry and Fallback Logic:** The tests examine how the `HttpStreamFactoryJobController` marks bad proxies (using `proxy_retry_info`) and falls back to alternative proxy configurations (including DIRECT).
* **Specific Error Handling:**  Some tests focus on the handling of particular errors like `ERR_MSG_TOO_BIG` for different proxy types (QUIC vs. others).
* **SOCKS5 and QUIC Proxies:** Specific tests cover scenarios involving SOCKS5 and QUIC proxies.

**Pre-computation and Pre-analysis (Internal Thought Process):**

* **Recognize the Testing Context:** Immediately understand that this is *test code*, not the core implementation. The purpose is to *verify* the behavior of the `HttpStreamFactoryJobController`.
* **Identify Key Classes:**  Note the important classes involved: `HttpStreamFactoryJobController`, `ConfiguredProxyResolutionService`, `ProxyConfig`, `ProxyInfo`, `MockClientSocketFactory`, `SSLSocketDataProvider`, etc. Understanding their roles is crucial.
* **Focus on the "Why":**  For each test case, ask: "What specific scenario is being tested?" and "What behavior is being verified?".
* **Connect to Real-World Scenarios:** Think about how these test cases map to real browser behavior when dealing with proxies and network errors.

By following these steps, I can construct a comprehensive and accurate answer to the user's request.
这是`net/http/http_stream_factory_job_controller_unittest.cc`文件的第三部分，主要关注 `HttpStreamFactoryJobController` 在遇到连接错误时如何重新考虑代理（proxy reconsideration）和回退（fallback）逻辑。它涵盖了多种代理类型（HTTPS, SOCKS5, QUIC）和不同的错误场景。

**主要功能归纳：**

这部分代码主要测试了 `HttpStreamFactoryJobController` 在以下情况下的行为：

1. **代理连接失败时的回退机制：** 当通过某个代理连接目标服务器失败时，`HttpStreamFactoryJobController` 是否能够正确地尝试下一个可用的代理（包括 DIRECT 连接）。
2. **不同类型的代理：** 测试了 HTTPS 代理、SOCKS5 代理和 QUIC 代理在连接失败时的回退逻辑。
3. **不同阶段的连接错误：**  模拟了连接过程中的不同错误，例如 DNS 解析失败、TCP 连接失败、SSL 握手失败、隧道读取失败等，并验证 `HttpStreamFactoryJobController` 是否能够根据错误的性质进行回退。
4. **错误标记和重试：**  验证了当代理连接失败后，这些代理是否会被标记为“坏”代理，以便后续请求可以跳过它们。
5. **IP 保护代理：** 特别测试了 IP 保护代理在连接失败时的回退行为。
6. **`ERR_MSG_TOO_BIG` 的处理：**  测试了对于 QUIC 代理，`ERR_MSG_TOO_BIG` 错误会被认为是可重试的，会触发回退到 DIRECT 连接，而对于其他类型的代理则不会。
7. **没有备用 Job 时的行为：** 测试了在没有备用 Job 的情况下，主 Job 连接失败或成功时的通知机制。

**与 Javascript 的关系：**

这部分代码本身是用 C++ 编写的，直接与 Javascript 没有代码级别的交互。然而，它的功能直接影响了 web 浏览器中 Javascript 发起的网络请求的行为。

* **`fetch` API 和 `XMLHttpRequest`：** 当 Javascript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起网络请求时，浏览器的网络栈（包括 `HttpStreamFactoryJobController`）会处理这些请求。如果请求需要通过代理服务器，并且连接代理服务器失败，这里的逻辑将决定浏览器是否会尝试其他代理或直接连接。
* **用户体验：**  这部分代码的正确性直接影响了用户的网络体验。如果代理回退逻辑不正确，用户可能会遇到连接失败、网页加载缓慢等问题。

**举例说明：**

假设一个网页上的 Javascript 代码使用 `fetch` API 请求 `https://www.example.com`，并且用户的浏览器配置了以下代理顺序：

1. `HTTPS badproxy:99`
2. `DIRECT`

**场景 1：HTTPS 代理连接失败**

* **假设输入：**  `HttpStreamFactoryJobController` 尝试通过 `badproxy:99` 连接 `https://www.example.com`，但由于网络问题（例如代理服务器宕机）连接失败，返回 `ERR_CONNECTION_REFUSED`。
* **逻辑推理：**  根据代码中的测试用例（例如 `ReconsiderProxyAfterErrorHttpsProxy`），`HttpStreamFactoryJobController` 应该捕获到 `ERR_CONNECTION_REFUSED` 错误，并将 `badproxy:99` 标记为“坏”代理。
* **输出：**  `HttpStreamFactoryJobController` 会回退到下一个可用的代理，即 `DIRECT` 连接，并尝试直接连接 `https://www.example.com`。如果直接连接成功，Javascript 的 `fetch` API 会收到成功的响应。

**场景 2：SOCKS5 代理连接超时**

* **假设输入：**  浏览器配置了代理 `SOCKS5 badproxy:99`，Javascript 发起 HTTP 请求 `http://host:80/`。`HttpStreamFactoryJobController` 尝试连接 `badproxy:99`，但连接超时，返回 `ERR_CONNECTION_TIMED_OUT`。
* **逻辑推理：**  根据 `ReconsiderProxyAfterErrorSocks5Proxy` 测试用例，对于 SOCKS5 代理的连接超时错误，`HttpStreamFactoryJobController` 会认为该代理不可用。
* **输出：** 如果配置了其他备用代理或 DIRECT 连接，`HttpStreamFactoryJobController` 会尝试它们。如果最终回退到 DIRECT 连接成功，Javascript 的请求会成功。

**用户或编程常见的使用错误：**

1. **错误的代理配置：** 用户手动配置了无法连接或不存在的代理服务器地址和端口。这会导致 `HttpStreamFactoryJobController` 尝试连接时失败，并触发回退逻辑。
   * **示例：** 用户在浏览器设置中输入了 `HTTPS nonexist.proxy.com:8080`，但实际上这个代理服务器不存在或端口不正确。当浏览器尝试通过这个代理访问网页时，`HttpStreamFactoryJobController` 会遇到连接错误。
2. **网络问题：** 用户的网络环境存在问题，导致无法连接到代理服务器或目标服务器。例如，防火墙阻止了连接，或者用户的网络连接不稳定。
3. **PAC 脚本错误：** 如果使用了 PAC (Proxy Auto-Config) 脚本来自动配置代理，脚本中的逻辑错误可能导致浏览器选择错误的代理，从而导致连接失败。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中输入网址或点击链接：** 这是发起网络请求的起点。
2. **浏览器解析 URL 并确定需要请求的资源。**
3. **浏览器网络栈根据配置的代理设置（手动配置或 PAC 脚本）选择要使用的代理服务器。**
4. **`HttpStreamFactory` 创建 `HttpStreamRequest` 来请求连接。**
5. **`HttpStreamFactoryJobController` 负责管理连接尝试，包括通过代理服务器的连接。**
6. **`HttpStreamFactoryJobController` 尝试通过选定的代理服务器建立连接。**
7. **如果连接过程中发生错误（例如 TCP 连接失败、SSL 握手失败），这里的代码将被执行，判断是否需要回退到其他代理或 DIRECT 连接。**
8. **如果回退成功，会尝试通过新的代理或直接连接。**
9. **最终连接成功或失败，结果会传递回浏览器的其他组件，并最终影响网页的加载。**

**作为第 3 部分的功能归纳：**

这部分单元测试主要专注于验证 `HttpStreamFactoryJobController` 在遇到各种连接错误时，能否正确地执行代理回退逻辑，确保在代理不可用时，仍然能够尝试其他可用的连接方式（包括直接连接），从而提高网络请求的成功率和用户体验。它覆盖了多种代理类型和常见的连接错误场景，是网络栈健壮性的重要保障。

Prompt: 
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共9部分，请归纳一下它的功能

"""
roxyChain::Direct());
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
          "CONNECT badproxyserver:99 HTTP/1.1\r\n"
          "Host: badproxyserver:99\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: https://goodproxyserver:100\r\n\r\n";
      constexpr char kBadProxyServer2TunnelRequest[] =
          "CONNECT badfallbackproxyserver:98 HTTP/1.1\r\n"
          "Host: badfallbackproxyserver:98\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "User-Agent: test-ua\r\n"
          "Foo: https://goodproxyserver:100\r\n\r\n";
      const std::string kBadProxyServer1EndpointTunnelRequest =
          base::StringPrintf(
              "CONNECT %s HTTP/1.1\r\n"
              "Host: %s\r\n"
              "Proxy-Connection: keep-alive\r\n"
              "User-Agent: test-ua\r\n"
              "Foo: https://badproxyserver:99\r\n\r\n",
              HostPortPair::FromURL(dest_url).ToString().c_str(),
              HostPortPair::FromURL(dest_url).ToString().c_str());
      const std::string kBadProxyServer2EndpointTunnelRequest =
          base::StringPrintf(
              "CONNECT %s HTTP/1.1\r\n"
              "Host: %s\r\n"
              "Proxy-Connection: keep-alive\r\n"
              "User-Agent: test-ua\r\n"
              "Foo: https://badfallbackproxyserver:98\r\n\r\n",
              HostPortPair::FromURL(dest_url).ToString().c_str(),
              HostPortPair::FromURL(dest_url).ToString().c_str());
      const MockWrite kNestedProxyChain1TunnelWrites[] = {
          {ASYNC, kBadProxyServer1TunnelRequest},
          {ASYNC, kBadProxyServer1EndpointTunnelRequest.c_str()}};
      const MockWrite kNestedProxyChain2TunnelWrites[] = {
          {ASYNC, kBadProxyServer2TunnelRequest},
          {ASYNC, kBadProxyServer2EndpointTunnelRequest.c_str()}};

      std::vector<MockRead> reads = {
          MockRead(ASYNC, 1, "HTTP/1.1 200 Connection Established\r\n\r\n"),
      };

      // Generate identical errors for the second proxy server in both the main
      // proxy chain and the fallback proxy chain. No alternative job is created
      // for either, so only need one data provider for each, when the request
      // makes it to the socket layer.
      std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job_server1;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job_server2;
      std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job2;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job2_server1;
      std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job2_server2;

      ssl_data_proxy_main_job_server1 =
          std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
      ssl_data_proxy_main_job2_server1 =
          std::make_unique<SSLSocketDataProvider>(ASYNC, OK);

      switch (mock_error.phase) {
        case ErrorPhase::kProxySslHandshake:
          ssl_data_proxy_main_job_server2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, mock_error.error);
          ssl_data_proxy_main_job2_server2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, mock_error.error);
          break;
        case ErrorPhase::kTunnelRead:
          // Note: Unlike for single-proxy chains, tunnels are established for
          // HTTP destinations when multi-proxy chains are in use, so simulate
          // tunnel read failures in all cases.
          reads.emplace_back(ASYNC, mock_error.error);
          ssl_data_proxy_main_job_server2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
          ssl_data_proxy_main_job2_server2 =
              std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
          break;
      }
      socket_data_proxy_main_job = std::make_unique<StaticSocketDataProvider>(
          reads, kNestedProxyChain1TunnelWrites);
      socket_data_proxy_main_job2 = std::make_unique<StaticSocketDataProvider>(
          reads, mock_error.triggers_ssl_connect_job_retry_logic
                     ? kNestedProxyChain1TunnelWrites
                     : kNestedProxyChain2TunnelWrites);

      session_deps_.socket_factory->AddSocketDataProvider(
          socket_data_proxy_main_job.get());
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          ssl_data_proxy_main_job_server1.get());
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          ssl_data_proxy_main_job_server2.get());

      session_deps_.socket_factory->AddSocketDataProvider(
          socket_data_proxy_main_job2.get());
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          ssl_data_proxy_main_job2_server1.get());
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          ssl_data_proxy_main_job2_server2.get());

      // After both proxy chains fail, the request should fall back to using
      // DIRECT, and succeed.
      SSLSocketDataProvider ssl_data_first_request(ASYNC, OK);
      StaticSocketDataProvider socket_data_direct_first_request;
      socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
      session_deps_.socket_factory->AddSocketDataProvider(
          &socket_data_direct_first_request);
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

// Test proxy fallback logic for an IP Protection request.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       ReconsiderProxyForIpProtection) {
  GURL dest_url = GURL("https://www.example.com");

  CreateSessionDeps();

  std::unique_ptr<ConfiguredProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  auto test_proxy_delegate =
      std::make_unique<TestProxyDelegateForIpProtection>();

  // Before starting the test, verify that there are no proxies marked as
  // bad.
  ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());

  constexpr char kTunnelRequest[] =
      "CONNECT www.example.com:443 HTTP/1.1\r\n"
      "Host: www.example.com:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "Authorization: https://ip-pro:443\r\n\r\n";
  const MockWrite kTunnelWrites[] = {{ASYNC, kTunnelRequest}};
  std::vector<MockRead> reads;

  // Generate errors for the first proxy server.
  std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job;
  std::unique_ptr<SSLSocketDataProvider> ssl_data_proxy_main_job;
  reads.emplace_back(ASYNC, ERR_TUNNEL_CONNECTION_FAILED);
  socket_data_proxy_main_job =
      std::make_unique<StaticSocketDataProvider>(reads, kTunnelWrites);
  ssl_data_proxy_main_job = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);

  session_deps_.socket_factory->AddSocketDataProvider(
      socket_data_proxy_main_job.get());
  session_deps_.socket_factory->AddSSLSocketDataProvider(
      ssl_data_proxy_main_job.get());

  // After proxying fails, the request should fall back to using DIRECT, and
  // succeed.
  SSLSocketDataProvider ssl_data_first_request(ASYNC, OK);
  StaticSocketDataProvider socket_data_direct_first_request;
  socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(
      &socket_data_direct_first_request);
  session_deps_.socket_factory->AddSSLSocketDataProvider(
      &ssl_data_first_request);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = dest_url;

  Initialize(std::move(proxy_resolution_service),
             std::move(test_proxy_delegate));

  ProxyInfo used_proxy_info;
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
      .Times(1)
      .WillOnce(::testing::SaveArg<0>(&used_proxy_info));

  std::unique_ptr<HttpStreamRequest> request =
      CreateJobController(request_info);
  RunUntilIdle();

  // Verify that request was fetched without proxy.
  EXPECT_TRUE(used_proxy_info.is_direct());
}

// Test proxy fallback logic in the case connecting through socks5 proxy.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       ReconsiderProxyAfterErrorSocks5Proxy) {
  enum class ErrorPhase {
    kHostResolution,
    kTcpConnect,
    kTunnelRead,
  };

  const struct {
    ErrorPhase phase;
    Error error;
  } kRetriableErrors[] = {
      // These largely correspond to the list of errors in
      // CanFalloverToNextProxy() which can occur with an HTTPS proxy.
      //
      // Unlike HTTP/HTTPS proxies, SOCKS proxies are retried in response to
      // `ERR_CONNECTION_CLOSED`.
      {ErrorPhase::kHostResolution, ERR_NAME_NOT_RESOLVED},
      {ErrorPhase::kTcpConnect, ERR_ADDRESS_UNREACHABLE},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_TIMED_OUT},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_RESET},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_ABORTED},
      {ErrorPhase::kTcpConnect, ERR_CONNECTION_REFUSED},
      {ErrorPhase::kTunnelRead, ERR_TIMED_OUT},
      {ErrorPhase::kTunnelRead, ERR_CONNECTION_CLOSED},
  };

  // "host" on port 80 matches the kSOCK5GreetRequest.
  const GURL kDestUrl = GURL("http://host:80/");

  for (const auto& mock_error : kRetriableErrors) {
    SCOPED_TRACE(ErrorToString(mock_error.error));

    CreateSessionDeps();

    std::unique_ptr<ConfiguredProxyResolutionService> proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
            "SOCKS5 badproxy:99; SOCKS5 badfallbackproxy:98; DIRECT",
            TRAFFIC_ANNOTATION_FOR_TESTS);
    auto test_proxy_delegate = std::make_unique<TestProxyDelegate>();

    // Before starting the test, verify that there are no proxies marked as bad.
    ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());
    const MockWrite kTunnelWrites[] = {
        {ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength}};
    std::vector<MockRead> reads;

    // Generate identical errors for both the main proxy and the fallback proxy.
    // No alternative job is created for either, so only need one data provider
    // for each, when the request makes it to the socket layer.
    std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job;
    std::unique_ptr<StaticSocketDataProvider> socket_data_proxy_main_job2;
    switch (mock_error.phase) {
      case ErrorPhase::kHostResolution:
        // Only ERR_NAME_NOT_RESOLVED can be returned by the mock host resolver.
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
        reads.emplace_back(ASYNC, mock_error.error);
        socket_data_proxy_main_job =
            std::make_unique<StaticSocketDataProvider>(reads, kTunnelWrites);
        socket_data_proxy_main_job2 =
            std::make_unique<StaticSocketDataProvider>(reads, kTunnelWrites);
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
    StaticSocketDataProvider socket_data_direct_first_request;
    socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
    session_deps_.socket_factory->AddSocketDataProvider(
        &socket_data_direct_first_request);

    // Second request should use DIRECT, skipping the bad proxies, and succeed.
    StaticSocketDataProvider socket_data_direct_second_request;
    socket_data_direct_second_request.set_connect_data(MockConnect(ASYNC, OK));
    session_deps_.socket_factory->AddSocketDataProvider(
        &socket_data_direct_second_request);

    // Now request a stream. It should succeed using the DIRECT fallback proxy
    // option.
    HttpRequestInfo request_info;
    request_info.method = "GET";
    request_info.url = kDestUrl;

    Initialize(std::move(proxy_resolution_service),
               std::move(test_proxy_delegate));

    // Start two requests. The first request should consume data from
    // |socket_data_proxy_main_job| and |socket_data_direct_first_request|. The
    // second request should consume data from
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
      EXPECT_THAT(retry_info,
                  Contains(Key(ProxyUriToProxyChain(
                      "socks5://badproxy:99", ProxyServer::SCHEME_SOCKS5))));
      EXPECT_THAT(
          retry_info,
          Contains(Key(ProxyUriToProxyChain("socks5://badfallbackproxy:98",
                                            ProxyServer::SCHEME_SOCKS5))));

      // The idle socket should have been added back to the socket pool. Close
      // it, so the next loop iteration creates a new socket instead of reusing
      // the idle one.
      auto* socket_pool = session_->GetSocketPool(
          HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct());
      EXPECT_EQ(1, socket_pool->IdleSocketCount());
      socket_pool->CloseIdleSockets("Close socket reason");
    }
    EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  }
}

// Tests that ERR_MSG_TOO_BIG is retryable for QUIC proxy.
TEST_F(JobControllerReconsiderProxyAfterErrorTest, ReconsiderErrMsgTooBig) {
  auto quic_proxy_chain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, "bad", 99)});
  std::unique_ptr<ConfiguredProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {quic_proxy_chain, ProxyChain::Direct()},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  // Before starting the test, verify that there are no proxies marked as bad.
  ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());

  // Mock data for the QUIC proxy socket.
  StaticSocketDataProvider quic_proxy_socket;
  quic_proxy_socket.set_connect_data(MockConnect(ASYNC, ERR_MSG_TOO_BIG));
  session_deps_.socket_factory->AddSocketDataProvider(&quic_proxy_socket);

  // Mock data for DIRECT.
  StaticSocketDataProvider socket_data_direct;
  socket_data_direct.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(&socket_data_direct);

  // Now request a stream. It should fall back to DIRECT on ERR_MSG_TOO_BIG.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");

  Initialize(std::move(proxy_resolution_service));

  ProxyInfo used_proxy_info;
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
      .Times(1)
      .WillOnce(::testing::SaveArg<0>(&used_proxy_info));

  std::unique_ptr<HttpStreamRequest> request =
      CreateJobController(request_info);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(used_proxy_info.is_direct());
  const ProxyRetryInfoMap& retry_info =
      session_->proxy_resolution_service()->proxy_retry_info();
  EXPECT_THAT(retry_info, SizeIs(1));
  EXPECT_THAT(retry_info, Contains(Key(quic_proxy_chain)));

  request.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Test proxy fallback logic in the case connecting through a Quic proxy.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       ReconsiderProxyAfterErrorQuicProxy) {
  enum class ErrorPhase {
    kHostResolution,
    kProxySession,
    kUdpConnect,
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
    // bool triggers_ssl_connect_job_retry_logic = false;
  } kRetriableErrors[] = {
      {ErrorPhase::kHostResolution, ERR_NAME_NOT_RESOLVED},
      // Test that proxy session gets activated but then failed before
      // requesting the stream. The error is determined by
      // QuicChromiumClientSession::Handle::RequestStream.
      {ErrorPhase::kProxySession, ERR_CONNECTION_CLOSED},
      {ErrorPhase::kUdpConnect, ERR_ADDRESS_UNREACHABLE},
      {ErrorPhase::kUdpConnect, ERR_CONNECTION_TIMED_OUT},
      {ErrorPhase::kUdpConnect, ERR_CONNECTION_RESET},
      {ErrorPhase::kUdpConnect, ERR_CONNECTION_ABORTED},
      {ErrorPhase::kUdpConnect, ERR_CONNECTION_REFUSED},
      {ErrorPhase::kUdpConnect, ERR_QUIC_PROTOCOL_ERROR},
      {ErrorPhase::kUdpConnect, ERR_QUIC_HANDSHAKE_FAILED},
      {ErrorPhase::kUdpConnect, ERR_MSG_TOO_BIG},
  };
  // To use Quic proxy the destination must be HTTPS.
  GURL dest_url("https://www.example.com");

  url::SchemeHostPort proxy_server(url::kHttpsScheme, "badproxy", 99);
  url::SchemeHostPort proxy_server2(url::kHttpsScheme, "badfallbackproxy", 98);
  for (const auto& mock_error : kRetriableErrors) {
    SCOPED_TRACE(ErrorToString(mock_error.error));

    CreateSessionDeps();

    auto quic_proxy_chain =
        ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
            ProxyServer::SCHEME_QUIC, proxy_server.host(),
            proxy_server.port())});
    auto quic_proxy_chain2 =
        ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
            ProxyServer::SCHEME_QUIC, proxy_server2.host(),
            proxy_server2.port())});
    std::unique_ptr<ConfiguredProxyResolutionService> proxy_resolution_service =
        ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
            {quic_proxy_chain, quic_proxy_chain2, ProxyChain::Direct()},
            TRAFFIC_ANNOTATION_FOR_TESTS);
    auto test_proxy_delegate = std::make_unique<TestProxyDelegate>();

    // Before starting the test, verify that there are no proxies marked as
    // bad.
    ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());

    // Generate identical errors for both the main proxy and the fallback
    // proxy. No alternative job is created for either, so only need one data
    // provider for each, when the request makes it to the socket layer.
    std::unique_ptr<StaticSocketDataProvider> quic_proxy_socket_main_job;
    std::unique_ptr<StaticSocketDataProvider> quic_proxy_socket_main_job2;
    switch (mock_error.phase) {
      case ErrorPhase::kHostResolution:
        // Only ERR_NAME_NOT_RESOLVED can be returned by the mock host
        // resolver.
        DCHECK_EQ(ERR_NAME_NOT_RESOLVED, mock_error.error);
        session_deps_.host_resolver->rules()->AddSimulatedFailure("badproxy");
        session_deps_.host_resolver->rules()->AddSimulatedFailure(
            "badfallbackproxy");
        break;
      case ErrorPhase::kProxySession:
        quic_proxy_socket_main_job =
            std::make_unique<StaticSocketDataProvider>();
        quic_proxy_socket_main_job->set_connect_data(MockConnect(ASYNC, OK));
        quic_proxy_socket_main_job2 =
            std::make_unique<StaticSocketDataProvider>();
        quic_proxy_socket_main_job2->set_connect_data(MockConnect(ASYNC, OK));
        break;
      case ErrorPhase::kUdpConnect:
        quic_proxy_socket_main_job =
            std::make_unique<StaticSocketDataProvider>();
        quic_proxy_socket_main_job->set_connect_data(
            MockConnect(ASYNC, mock_error.error));
        quic_proxy_socket_main_job2 =
            std::make_unique<StaticSocketDataProvider>();
        quic_proxy_socket_main_job2->set_connect_data(
            MockConnect(ASYNC, mock_error.error));
        break;
    }

    // Mock data for the QUIC proxy socket.
    if (quic_proxy_socket_main_job) {
      session_deps_.socket_factory->AddSocketDataProvider(
          quic_proxy_socket_main_job.get());
      session_deps_.socket_factory->AddSocketDataProvider(
          quic_proxy_socket_main_job2.get());
    }

    SSLSocketDataProvider ssl_data_first_request(ASYNC, OK);
    StaticSocketDataProvider socket_data_direct_first_request;
    socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
    session_deps_.socket_factory->AddSocketDataProvider(
        &socket_data_direct_first_request);
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_data_first_request);

    // Second request should use DIRECT, skipping the bad proxies, and
    // succeed.
    SSLSocketDataProvider ssl_data_second_request(ASYNC, OK);
    StaticSocketDataProvider socket_data_direct_second_request;
    socket_data_direct_second_request.set_connect_data(MockConnect(ASYNC, OK));
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
               std::move(test_proxy_delegate),
               /*using_quic=*/true);
    if (mock_error.phase == ErrorPhase::kProxySession) {
      session_->quic_session_pool()->ActivateSessionForTesting(
          CreateMockQUICProxySession(proxy_server));
      session_->quic_session_pool()->ActivateSessionForTesting(
          CreateMockQUICProxySession(proxy_server2));
      ASSERT_EQ(mock_proxy_sessions_.size(), 2u);
    }

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
      // TODO(crbug.com/336318587): Verify the session key.
      crypto_client_stream_factory_.last_stream()
          ->NotifySessionOneRttKeyAvailable();
      RunUntilIdle();
      EXPECT_TRUE(used_proxy_info.is_direct());

      // The proxies that failed should now be known to the proxy service as
      // bad.
      const ProxyRetryInfoMap& retry_info =
          session_->proxy_resolution_service()->proxy_retry_info();
      ASSERT_THAT(retry_info, SizeIs(2));
      EXPECT_THAT(retry_info, Contains(Key(quic_proxy_chain)));
      EXPECT_THAT(retry_info, Contains(Key(quic_proxy_chain2)));

      // Quic connection does not create socket. So only check the sessions,
      // and close them. So that the next loop iteration won't reuse them.
      QuicSessionPool* quic_session_pool = session_->quic_session_pool();
      // Mock sessions must be removed from the vector before the session pool
      // destroys them to avoid dangling pointers.
      while (!mock_proxy_sessions_.empty()) {
        MockQuicChromiumClientSession* session = mock_proxy_sessions_.back();
        mock_proxy_sessions_.pop_back();
        quic_session_pool->DeactivateSessionForTesting(session);
      }
      EXPECT_EQ(1, quic_session_pool->CountActiveSessions());
      quic_session_pool->CloseAllSessions(OK, quic::QUIC_NO_ERROR);
    }
    EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  }
}

// Same as test above except that this is testing the retry behavior for
// non-QUIC proxy on ERR_MSG_TOO_BIG.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       DoNotReconsiderErrMsgTooBig) {
  std::unique_ptr<ConfiguredProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS badproxy:99; DIRECT", TRAFFIC_ANNOTATION_FOR_TESTS);

  // Before starting the test, verify that there are no proxies marked as bad.
  ASSERT_TRUE(proxy_resolution_service->proxy_retry_info().empty());

  // Mock data for the HTTPS proxy socket.
  static constexpr char kHttpConnect[] =
      "CONNECT www.example.com:443 HTTP/1.1\r\n"
      "Host: www.example.com:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n";
  const MockWrite kWrites[] = {{ASYNC, kHttpConnect}};
  const MockRead kReads[] = {{ASYNC, ERR_MSG_TOO_BIG}};
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  StaticSocketDataProvider https_proxy_socket(kReads, kWrites);
  https_proxy_socket.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(&https_proxy_socket);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  // Now request a stream. It should not fallback to DIRECT on ERR_MSG_TOO_BIG.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");

  Initialize(std::move(proxy_resolution_service));

  ProxyInfo used_proxy_info;
  EXPECT_CALL(request_delegate_, OnStreamFailed(ERR_MSG_TOO_BIG, _, _, _))
      .Times(1);

  std::unique_ptr<HttpStreamRequest> request =
      CreateJobController(request_info);
  base::RunLoop().RunUntilIdle();

  const ProxyRetryInfoMap& retry_info =
      session_->proxy_resolution_service()->proxy_retry_info();
  EXPECT_THAT(retry_info, SizeIs(0));

  request.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_P(HttpStreamFactoryJobControllerTest, OnStreamFailedWithNoAlternativeJob) {
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, ERR_FAILED));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  // There's no other alternative job. Thus when stream failed, it should
  // notify Request of the stream failure.
  EXPECT_CALL(request_delegate_, OnStreamFailed(ERR_FAILED, _, _, _)).Times(1);
  base::RunLoop().RunUntilIdle();
}

TEST_P(HttpStreamFactoryJobControllerTest, OnStreamReadyWithNoAlternativeJob) {
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  // There's no other alternative job. Thus when a stream is ready, it should
  // notify Request.
  EXPECT_TRUE(job_controller_->main_job());

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));
  base::RunLoop().RunUntilIdle();
}

// Test we cancel Jobs correctly when the Request is explicitly canceled
// before any Job is bound to Reques
"""


```