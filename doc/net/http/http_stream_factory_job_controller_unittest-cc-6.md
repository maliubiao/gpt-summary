Response:
The user wants to understand the functionality of the given C++ code file, which is a unit test for `HttpStreamFactory::JobController` in Chromium's network stack. I need to:

1. **Summarize the file's purpose:** It tests the behavior of `JobController`, a component responsible for managing the process of creating HTTP streams.
2. **Identify relationships with JavaScript:**  Consider if any functionality tested here directly impacts how JavaScript in web pages interacts with the network.
3. **Analyze logical reasoning:**  Examine the tests for any clear input/output patterns that demonstrate a specific logic flow.
4. **Point out potential user/programming errors:** Look for test cases that reveal common pitfalls in using the tested functionality.
5. **Explain user actions leading to this code:**  Describe the sequence of user interactions that would trigger the code being tested.
6. **Synthesize the overall function of this part (part 7 of 9):** Based on the code provided, determine the specific aspects of `JobController` being tested in this segment.

**Breakdown of the provided code:**

The code contains several test cases within the `HttpStreamFactoryJobControllerTest` and related classes. These tests seem to focus on:

* **Limiting concurrent HTTP/2 requests:** Tests scenarios where multiple requests are made to an HTTP/2 server, verifying that connections are throttled correctly.
* **Handling preconnects:** Checks how `JobController` manages pre-established connections.
* **Negotiating HTTP versions:**  Verifies the behavior when the first request negotiates HTTP/1.1, and subsequent requests might use HTTP/2.
* **Throttling for QUIC vs. TCP:**  Confirms that HTTP/2 throttling logic doesn't apply to QUIC connections.
* **Retrying misdirected requests:** Tests how `JobController` handles and potentially retries requests that might be misdirected.
* **Early preconnect limiting:** Examines a feature that limits the number of early preconnects.
* **Alternative Service handling:** Focuses on retrieving and selecting appropriate alternative services (like QUIC), including version negotiation.
* **DNS-HTTPS ALPN integration:** Includes tests related to using DNS to discover supported protocols (ALPN) for HTTPS connections.

**Planning the response:**

I will address each of the user's requests systematically, drawing examples and insights from the provided test cases.
这是 `net/http/http_stream_factory_job_controller_unittest.cc` 文件的第七部分，主要测试了 `HttpStreamFactory::JobController` 的以下功能：

**核心功能归纳（基于提供的代码片段）：**

* **限制并发的 HTTP/2 请求 (Throttling):**  这部分测试了 `JobController` 如何限制同时向同一 HTTP/2 服务器发起的请求数量。它模拟了多个请求同时发起的情况，并验证了只有有限数量的连接会被立即建立，其余的会被延迟。这有助于防止服务器过载。
* **处理请求取消:** 测试了当一个正在等待的 HTTP/2 请求被取消时，其他被延迟的请求能否被正常恢复并建立连接。
* **管理预连接 (Preconnects):** 验证了当发起多个预连接请求时，`JobController` 如何有效地复用连接，避免建立过多的冗余连接。特别是针对 HTTP/2 预连接进行了测试，确保即使有多个预连接请求，也只建立一个连接。
* **处理协议协商:** 测试了当第一个请求协商为 HTTP/1.1 时，后续请求如何处理，以及在支持 HTTP/2 的情况下，后续请求能否建立 HTTP/2 连接。
* **区分 QUIC 和 TCP 连接的节流:**  验证了 HTTP/2 的节流逻辑仅应用于基于 TCP 的连接，而不会影响 QUIC 连接。这意味着 QUIC 连接不会受到 HTTP/2 并发连接数的限制。
* **处理误导请求 (Misdirected Request):**  测试了在禁用 IP 基于的连接池和备用服务的情况下，`JobController` 如何处理可能被误导的请求。
* **限制早期预连接数量:**  测试了一个实验性功能，用于限制过早发起的预连接请求的数量，以优化资源利用。
* **获取备用服务信息 (Alternative Service Info):**  测试了 `JobController` 如何获取和处理服务器提供的备用服务信息，特别是针对 QUIC 协议，包括获取服务器支持的 QUIC 版本列表。
* **备用服务版本选择:**  测试了 `JobController` 如何根据服务器提供的备用服务信息（特别是 QUIC 协议版本）和客户端支持的版本，选择合适的 QUIC 版本进行连接。
* **QUIC 主机允许列表 (Host Allowlist):** 测试了当 `HttpNetworkSession` 设置了 QUIC 主机允许列表时，`JobController` 如何过滤备用服务信息，只考虑允许列表中的主机。
* **DNS-HTTPS ALPN 集成:**  这部分开始涉及到 DNS 查询返回 HTTPS 记录（包含 ALPN 信息）的场景，并测试 `JobController` 如何利用这些信息来建立连接。

**与 JavaScript 的关系及举例说明:**

虽然这个 C++ 代码本身不直接包含 JavaScript，但它所测试的网络栈功能直接影响着 JavaScript 在浏览器中的网络请求行为。

* **HTTP/2 并发限制:** 当 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发起多个请求到同一个 HTTP/2 网站时，`JobController` 的并发限制功能会起作用。如果请求数量超过了限制，后续的请求可能会被延迟，直到有可用的连接。这会影响 JavaScript 代码获取响应的延迟。

   **举例:** 假设 JavaScript 代码同时请求了多个图片资源：
   ```javascript
   fetch('https://example.com/image1.jpg');
   fetch('https://example.com/image2.jpg');
   fetch('https://example.com/image3.jpg');
   // ... 更多请求
   ```
   如果 `JobController` 限制了到 `example.com` 的 HTTP/2 并发连接数为 6，那么只有前 6 个请求会立即尝试建立连接，其他的请求可能会被延迟，直到前 6 个请求中有连接空闲出来。

* **备用服务 (QUIC):** 当网站支持 QUIC 协议并通过 HTTP 头部或 DNS 记录声明时，`JobController` 会尝试使用 QUIC 建立连接。如果成功，JavaScript 的 `fetch` 或 `XMLHttpRequest` 请求实际上是通过 QUIC 进行传输的，这通常能带来更低的延迟。

   **举例:** 用户访问一个支持 QUIC 的网站，JavaScript 代码发起一个 `fetch` 请求：
   ```javascript
   fetch('https://www.example.com/data.json');
   ```
   `JobController` 负责解析服务器提供的备用服务信息，如果发现支持 QUIC 并且客户端也支持，那么这个 `fetch` 请求就会尝试通过 QUIC 连接发送。

**逻辑推理、假设输入与输出:**

以 **`TEST_F(JobControllerLimitMultipleH2Requests, MultipleRequestsFirstRequestCanceled)`** 这个测试为例：

* **假设输入:**
    * `kNumRequests` 设置为某个大于 1 的值（例如 3）。
    * 第一个请求的 SocketData 被设置为 `ERR_IO_PENDING`，模拟连接建立过程中的等待。
    * 服务器支持 HTTP/2。
    * 在第一个请求完成连接之前，JavaScript (或浏览器内核) 取消了第一个请求。
* **逻辑推理:**  由于第一个请求被取消，`JobController` 应该释放为此请求保留的资源，并允许其他被延迟的 HTTP/2 请求开始建立连接。
* **预期输出:**
    * 除了第一个被取消的请求外，剩余的 `kNumRequests - 1` 个请求都应该成功建立连接并调用 `OnStreamReadyImpl`。
    * `HttpStreamFactoryPeer::IsJobControllerDeleted(factory_)` 最终应该为 `true`，表明 `JobController` 被正确清理。

**用户或编程常见的使用错误及举例说明:**

* **过多的预连接请求:**  开发者可能会错误地发起大量的预连接请求，期望加速后续的页面加载。然而，如果服务器没有足够的资源来处理这些预连接，或者客户端的网络环境不稳定，过多的预连接反而可能导致性能下降。`JobController` 的限制早期预连接数量的功能可以缓解这个问题。

   **举例:**  一个网站的开发者在页面加载时，尝试预连接 10 个不同的资源：
   ```javascript
   const preconnectLinks = [
       "https://cdn.example.com",
       "https://fonts.example.com",
       // ... 更多预连接
   ];
   preconnectLinks.forEach(url => {
       const link = document.createElement("link");
       link.rel = "preconnect";
       link.href = url;
       document.head.appendChild(link);
   });
   ```
   如果 `JobController` 启用了限制早期预连接的功能，并且设置了最大预连接数，那么可能只有部分预连接会被实际建立。

* **没有正确处理备用服务信息:**  开发者如果依赖于特定协议（例如 HTTP/2），但服务器实际通告了更优的备用服务（例如 QUIC），浏览器会优先尝试使用备用服务。如果开发者没有考虑到这种情况，可能会导致一些意外的行为或者依赖于特定协议的功能失效。

**用户操作如何一步步到达这里，作为调试线索:**

当用户在 Chrome 浏览器中执行以下操作时，可能会触发 `HttpStreamFactory::JobController` 的相关代码：

1. **在地址栏输入网址并访问一个 HTTPS 网站:**  这是最常见的场景。浏览器需要为该网站建立安全的 HTTP 连接。
2. **点击网页上的链接，导航到另一个 HTTPS 网站:**  与步骤 1 类似，需要建立新的连接。
3. **网页加载过程中，JavaScript 代码发起 `fetch` 或 `XMLHttpRequest` 请求获取资源:**  这些请求会通过 `HttpStreamFactory` 创建和管理网络流。
4. **用户在一个网站上进行多次操作，导致 JavaScript 发起多个并发请求:** 例如，滚动加载图片、异步提交表单等。
5. **用户访问一个支持 HTTP/2 或 QUIC 的网站:**  `JobController` 会尝试利用这些协议来优化连接。
6. **用户在设置中开启或关闭了某些网络相关的实验性功能:** 这可能会影响 `JobController` 的行为，例如限制早期预连接。

**作为调试线索:**  如果开发者在使用 Chromium 内核的浏览器或应用程序时遇到网络请求相关的问题，例如连接建立缓慢、请求被延迟、协议协商失败等，那么查看 `HttpStreamFactory::JobController` 相关的日志或进行断点调试，可以帮助理解连接是如何建立和管理的，以及是否存在节流、预连接限制或备用服务选择的问题。

**第七部分的功能总结:**

总而言之，这部分代码主要集中在测试 `HttpStreamFactory::JobController` 在处理并发 HTTP/2 请求、预连接、协议协商以及与 QUIC 等备用服务交互时的核心逻辑和限制机制。它确保了网络栈能够有效地管理连接资源，避免过载，并尽可能利用更优的网络协议来提升性能。同时，也测试了一些容错处理机制，例如在请求被取消时的行为。

Prompt: 
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共9部分，请归纳一下它的功能

"""
ovider> ssl_socket_data;
  // kNumRequests - 1 will resume themselves after a delay. There will be
  // kNumRequests - 1 sockets opened.
  for (int i = 0; i < kNumRequests - 1; i++) {
    // Only the first one needs a MockRead because subsequent sockets are
    // not used to establish a SpdySession.
    if (i == 0) {
      socket_data.emplace_back(reads, base::span<MockWrite>());
    } else {
      socket_data.emplace_back();
    }
    socket_data.back().set_connect_data(MockConnect(ASYNC, OK));
    session_deps_.socket_factory->AddSocketDataProvider(&socket_data.back());
    ssl_socket_data.emplace_back(ASYNC, OK);
    ssl_socket_data.back().next_proto = kProtoHTTP2;
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_socket_data.back());
  }
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, NetworkAnonymizationKey(), true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  for (int i = 0; i < kNumRequests; ++i) {
    request_delegates.push_back(
        std::make_unique<MockHttpStreamRequestDelegate>());
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, request_delegates[i].get(), session_.get(), &job_factory_,
        request_info, is_preconnect_, /*is_websocket=*/false,
        enable_ip_based_pooling_, enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    auto* job_controller_ptr = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
    auto request = job_controller_ptr->Start(
        request_delegates[i].get(), nullptr, net_log_with_source_,
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    EXPECT_TRUE(job_controller_ptr->main_job());
    EXPECT_FALSE(job_controller_ptr->alternative_job());
    requests.push_back(std::move(request));
  }

  for (int i = 0; i < kNumRequests; ++i) {
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _));
  }

  EXPECT_GT(GetPendingMainThreadTaskCount(), 0u);
  FastForwardBy(base::Milliseconds(HttpStreamFactory::Job::kHTTP2ThrottleMs));
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  requests.clear();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));

  EXPECT_TRUE(hangdata.AllReadDataConsumed());
  for (const auto& data : socket_data) {
    EXPECT_TRUE(data.AllReadDataConsumed());
    EXPECT_TRUE(data.AllWriteDataConsumed());
  }
}

TEST_F(JobControllerLimitMultipleH2Requests,
       MultipleRequestsFirstRequestCanceled) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  SequencedSocketData first_socket(reads, base::span<MockWrite>());
  first_socket.set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider first_ssl_data(ASYNC, OK);
  first_ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSocketDataProvider(&first_socket);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&first_ssl_data);
  std::list<SequencedSocketData> socket_data;
  std::list<SSLSocketDataProvider> ssl_socket_data;
  // kNumRequests - 1 will be resumed when the first request is canceled.
  for (int i = 0; i < kNumRequests - 1; i++) {
    socket_data.emplace_back();
    socket_data.back().set_connect_data(MockConnect(ASYNC, OK));
    session_deps_.socket_factory->AddSocketDataProvider(&socket_data.back());
    ssl_socket_data.emplace_back(ASYNC, OK);
    ssl_socket_data.back().next_proto = kProtoHTTP2;
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_socket_data.back());
  }

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, NetworkAnonymizationKey(), true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  for (int i = 0; i < kNumRequests; ++i) {
    request_delegates.emplace_back(
        std::make_unique<MockHttpStreamRequestDelegate>());
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, request_delegates[i].get(), session_.get(), &job_factory_,
        request_info, is_preconnect_, /*is_websocket=*/false,
        enable_ip_based_pooling_, enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    auto* job_controller_ptr = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
    auto request = job_controller_ptr->Start(
        request_delegates[i].get(), nullptr, net_log_with_source_,
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    EXPECT_TRUE(job_controller_ptr->main_job());
    EXPECT_FALSE(job_controller_ptr->alternative_job());
    requests.push_back(std::move(request));
  }
  // Cancel the first one.
  requests[0].reset();

  for (int i = 1; i < kNumRequests; ++i) {
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _));
  }
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  requests.clear();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));

  EXPECT_TRUE(first_socket.AllReadDataConsumed());
  for (const auto& data : socket_data) {
    EXPECT_TRUE(data.AllReadDataConsumed());
    EXPECT_TRUE(data.AllWriteDataConsumed());
  }
}

TEST_F(JobControllerLimitMultipleH2Requests, MultiplePreconnects) {
  // Make sure there is only one socket connect.
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  SetPreconnect();
  Initialize(request_info);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, NetworkAnonymizationKey(), true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  for (int i = 0; i < kNumRequests; ++i) {
    request_delegates.emplace_back(
        std::make_unique<MockHttpStreamRequestDelegate>());
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, request_delegates[i].get(), session_.get(), &job_factory_,
        request_info, is_preconnect_, /*is_websocket=*/false,
        enable_ip_based_pooling_, enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    auto* job_controller_ptr = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
    job_controller_ptr->Preconnect(1);
    EXPECT_TRUE(job_controller_ptr->main_job());
    EXPECT_FALSE(job_controller_ptr->alternative_job());
  }
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(JobControllerLimitMultipleH2Requests, H1NegotiatedForFirstRequest) {
  // First socket is an HTTP/1.1 socket.
  SequencedSocketData first_socket;
  first_socket.set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSocketDataProvider(&first_socket);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
  // Second socket is an HTTP/2 socket.
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  SequencedSocketData second_socket(reads, base::span<MockWrite>());
  second_socket.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(&second_socket);
  SSLSocketDataProvider second_ssl_data(ASYNC, OK);
  second_ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&second_ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, NetworkAnonymizationKey(), true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  for (int i = 0; i < 2; ++i) {
    request_delegates.emplace_back(
        std::make_unique<MockHttpStreamRequestDelegate>());
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, request_delegates[i].get(), session_.get(), &job_factory_,
        request_info, is_preconnect_, /*is_websocket=*/false,
        enable_ip_based_pooling_, enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    auto* job_controller_ptr = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
    auto request = job_controller_ptr->Start(
        request_delegates[i].get(), nullptr, net_log_with_source_,
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    EXPECT_TRUE(job_controller_ptr->main_job());
    EXPECT_FALSE(job_controller_ptr->alternative_job());
    requests.push_back(std::move(request));
  }

  for (int i = 0; i < 2; ++i) {
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _));
  }
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  requests.clear();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));

  EXPECT_TRUE(first_socket.AllReadDataConsumed());
  EXPECT_FALSE(second_socket.AllReadDataConsumed());
}

// Tests that HTTP/2 throttling logic only applies to non-QUIC jobs.
TEST_F(JobControllerLimitMultipleH2Requests, QuicJobNotThrottled) {
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  tcp_data_ =
      std::make_unique<SequencedSocketData>(reads, base::span<MockWrite>());

  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  url::SchemeHostPort server(request_info.url);
  // Sets server supports QUIC.
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // Sets server support HTTP/2.
  session_->http_server_properties()->SetSupportsSpdy(
      server, NetworkAnonymizationKey(), true);

  // Use default job factory so that Resume() is not mocked out.
  HttpStreamFactory::JobFactory default_job_factory;
  auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
      factory_, &request_delegate_, session_.get(), &default_job_factory,
      request_info, is_preconnect_, /*is_websocket=*/false,
      enable_ip_based_pooling_, enable_alternative_services_,
      delay_main_job_with_available_spdy_session_,
      /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
  auto* job_controller_ptr = job_controller.get();
  HttpStreamFactoryPeer::AddJobController(factory_, std::move(job_controller));
  request_ = job_controller_ptr->Start(
      &request_delegate_, nullptr, net_log_with_source_,
      HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller_ptr->main_job());
  EXPECT_TRUE(job_controller_ptr->alternative_job());
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));
  base::RunLoop().RunUntilIdle();
  auto entries = net_log_observer_.GetEntries();
  for (const auto& entry : entries) {
    ASSERT_NE(NetLogEventType::HTTP_STREAM_JOB_THROTTLED, entry.type);
  }
}

class HttpStreamFactoryJobControllerMisdirectedRequestRetry
    : public HttpStreamFactoryJobControllerTestBase,
      public ::testing::WithParamInterface<::testing::tuple<bool, bool>> {
 public:
  HttpStreamFactoryJobControllerMisdirectedRequestRetry()
      : HttpStreamFactoryJobControllerTestBase(
            /*dns_https_alpn_enabled=*/false,
            /*happy_eyeballs_v3_enabled=*/false) {}
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpStreamFactoryJobControllerMisdirectedRequestRetry,
                         ::testing::Combine(::testing::Bool(),
                                            ::testing::Bool()));

TEST_P(HttpStreamFactoryJobControllerMisdirectedRequestRetry,
       DisableIPBasedPoolingAndAlternativeServices) {
  const bool enable_ip_based_pooling = ::testing::get<0>(GetParam());
  const bool enable_alternative_services = ::testing::get<1>(GetParam());
  if (enable_alternative_services) {
    quic_data_ = std::make_unique<MockQuicData>(version_);
    quic_data_->AddConnect(SYNCHRONOUS, OK);
    quic_data_->AddWrite(SYNCHRONOUS,
                         client_maker_.MakeInitialSettingsPacket(1));
    quic_data_->AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  }
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  if (!enable_ip_based_pooling) {
    DisableIPBasedPooling();
  }
  if (!enable_alternative_services) {
    DisableAlternativeServices();
  }

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  if (enable_alternative_services) {
    EXPECT_TRUE(job_controller_->alternative_job());
  } else {
    EXPECT_FALSE(job_controller_->alternative_job());
  }

  // |main_job| succeeds and should report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));
  base::RunLoop().RunUntilIdle();
}

class HttpStreamFactoryJobControllerPreconnectTest
    : public HttpStreamFactoryJobControllerTestBase,
      public ::testing::WithParamInterface<bool> {
 protected:
  HttpStreamFactoryJobControllerPreconnectTest()
      : HttpStreamFactoryJobControllerTestBase(
            /*dns_https_alpn_enabled=*/false,
            /*happy_eyeballs_v3_enabled=*/false) {}

  void SetUp() override {
    if (!GetParam()) {
      scoped_feature_list_.InitFromCommandLine(std::string(),
                                               "LimitEarlyPreconnects");
    }
  }

  void Initialize() {
    session_deps_.http_server_properties =
        std::make_unique<HttpServerProperties>(
            std::make_unique<MockPrefDelegate>(), nullptr /* net_log */);
    session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    factory_ = session_->http_stream_factory();
    request_info_.method = "GET";
    request_info_.url = GURL("https://www.example.com");
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, &request_delegate_, session_.get(), &job_factory_,
        request_info_, /* is_preconnect = */ true,
        /* is_websocket = */ false,
        /* enable_ip_based_pooling = */ true,
        /* enable_alternative_services = */ true,
        /* delay_main_job_with_available_spdy_session = */ true,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    job_controller_ = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
  }

 protected:
  void Preconnect(int num_streams) {
    job_controller_->Preconnect(num_streams);
    // Only one job is started.
    EXPECT_TRUE(job_controller_->main_job());
    EXPECT_FALSE(job_controller_->alternative_job());
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
  HttpRequestInfo request_info_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpStreamFactoryJobControllerPreconnectTest,
                         ::testing::Bool());

TEST_P(HttpStreamFactoryJobControllerPreconnectTest, LimitEarlyPreconnects) {
  std::list<SequencedSocketData> providers;
  std::list<SSLSocketDataProvider> ssl_providers;
  const int kNumPreconects = 5;
  MockRead reads[] = {MockRead(ASYNC, OK)};
  // If experiment is not enabled, there are 5 socket connects.
  const size_t actual_num_connects = GetParam() ? 1 : kNumPreconects;
  for (size_t i = 0; i < actual_num_connects; ++i) {
    providers.emplace_back(reads, base::span<MockWrite>());
    session_deps_.socket_factory->AddSocketDataProvider(&providers.back());
    ssl_providers.emplace_back(ASYNC, OK);
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_providers.back());
  }
  Initialize();
  Preconnect(kNumPreconects);
  // If experiment is enabled, only 1 stream is requested.
  EXPECT_EQ((int)actual_num_connects, HttpStreamFactoryJobPeer::GetNumStreams(
                                          job_controller_->main_job()));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Test that GetAlternativeServiceInfoFor will include a list of advertised
// versions, which contains a version that is supported. Returns an empty list
// if advertised versions are missing in HttpServerProperties.
TEST_P(HttpStreamFactoryJobControllerTest, GetAlternativeServiceInfoFor) {
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  base::Time expiration = base::Time::Now() + base::Days(1);

  // Set alternative service with no advertised version.
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      quic::ParsedQuicVersionVector());

  // Simulate proxy resolution succeeding, after which
  // GetAlternativeServiceInfoFor can be called.
  JobControllerPeer::InitializeProxyInfo(job_controller_);

  AlternativeServiceInfo alt_svc_info =
      JobControllerPeer::GetAlternativeServiceInfoFor(
          job_controller_, request_info, &request_delegate_,
          HttpStreamRequest::HTTP_STREAM);
  // Verify that JobController get an empty list of supported QUIC versions.
  EXPECT_TRUE(alt_svc_info.advertised_versions().empty());

  // Set alternative service for the same server with the same list of versions
  // that is supported.
  quic::ParsedQuicVersionVector supported_versions =
      quic_context_.params()->supported_versions;
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      supported_versions);

  alt_svc_info = JobControllerPeer::GetAlternativeServiceInfoFor(
      job_controller_, request_info, &request_delegate_,
      HttpStreamRequest::HTTP_STREAM);
  std::sort(
      supported_versions.begin(), supported_versions.end(),
      [](const quic::ParsedQuicVersion& a, const quic::ParsedQuicVersion& b) {
        return a.transport_version < b.transport_version;
      });
  quic::ParsedQuicVersionVector advertised_versions =
      alt_svc_info.advertised_versions();
  std::sort(
      advertised_versions.begin(), advertised_versions.end(),
      [](const quic::ParsedQuicVersion& a, const quic::ParsedQuicVersion& b) {
        return a.transport_version < b.transport_version;
      });
  EXPECT_EQ(supported_versions, advertised_versions);

  quic::ParsedQuicVersion unsupported_version_1 =
      quic::ParsedQuicVersion::Unsupported();
  quic::ParsedQuicVersion unsupported_version_2 =
      quic::ParsedQuicVersion::Unsupported();
  for (const quic::ParsedQuicVersion& version : quic::AllSupportedVersions()) {
    if (base::Contains(supported_versions, version)) {
      continue;
    }
    if (unsupported_version_1 == quic::ParsedQuicVersion::Unsupported()) {
      unsupported_version_1 = version;
      continue;
    }
    unsupported_version_2 = version;
    break;
  }

  // Set alternative service for the same server with two QUIC versions:
  // - one unsupported version: |unsupported_version_1|,
  // - one supported version:
  // quic_context_.params()->supported_versions[0].
  quic::ParsedQuicVersionVector mixed_quic_versions = {
      unsupported_version_1, quic_context_.params()->supported_versions[0]};
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      mixed_quic_versions);

  alt_svc_info = JobControllerPeer::GetAlternativeServiceInfoFor(
      job_controller_, request_info, &request_delegate_,
      HttpStreamRequest::HTTP_STREAM);
  EXPECT_EQ(2u, alt_svc_info.advertised_versions().size());
  // Verify that JobController returns the list of versions specified in set.
  EXPECT_EQ(mixed_quic_versions, alt_svc_info.advertised_versions());

  // Set alternative service for the same server with two unsupported QUIC
  // versions: |unsupported_version_1|, |unsupported_version_2|.
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      {unsupported_version_1, unsupported_version_2});

  alt_svc_info = JobControllerPeer::GetAlternativeServiceInfoFor(
      job_controller_, request_info, &request_delegate_,
      HttpStreamRequest::HTTP_STREAM);
  // Verify that JobController returns no valid alternative service.
  EXPECT_EQ(kProtoUnknown, alt_svc_info.alternative_service().protocol);
  EXPECT_EQ(0u, alt_svc_info.advertised_versions().size());
}

void HttpStreamFactoryJobControllerTestBase::TestAltSvcVersionSelection(
    const std::string& alt_svc_header,
    const quic::ParsedQuicVersion& expected_version,
    const quic::ParsedQuicVersionVector& supported_versions) {
  quic_context_.params()->supported_versions = supported_versions;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://example.com");
  NetworkIsolationKey network_isolation_key(
      SchemefulSite(GURL("https://example.com")),
      SchemefulSite(GURL("https://example.com")));
  auto network_anonymization_key = NetworkAnonymizationKey::CreateSameSite(
      SchemefulSite(GURL("https://example.com")));
  request_info.network_isolation_key = network_isolation_key;
  request_info.network_anonymization_key = network_anonymization_key;

  Initialize(request_info);
  url::SchemeHostPort origin(request_info.url);
  auto headers = base::MakeRefCounted<HttpResponseHeaders>("");
  headers->AddHeader("alt-svc", alt_svc_header);
  session_->http_stream_factory()->ProcessAlternativeServices(
      session_.get(), network_anonymization_key, headers.get(), origin);
  // Simulate proxy resolution succeeding, after which
  // GetAlternativeServiceInfoFor can be called.
  JobControllerPeer::InitializeProxyInfo(job_controller_);
  AlternativeServiceInfo alt_svc_info =
      JobControllerPeer::GetAlternativeServiceInfoFor(
          job_controller_, request_info, &request_delegate_,
          HttpStreamRequest::HTTP_STREAM);
  quic::ParsedQuicVersionVector advertised_versions =
      alt_svc_info.advertised_versions();
  quic::ParsedQuicVersion selected_version =
      JobControllerPeer::SelectQuicVersion(job_controller_,
                                           advertised_versions);
  EXPECT_EQ(expected_version, selected_version)
      << alt_svc_info.ToString() << " "
      << quic::ParsedQuicVersionVectorToString(advertised_versions);
}

TEST_P(HttpStreamFactoryJobControllerTest,
       AltSvcVersionSelectionFindsFirstMatch) {
  TestAltSvcVersionSelection(
      "h3-Q050=\":443\"; ma=2592000,"
      "h3-Q049=\":443\"; ma=2592000,"
      "h3-Q048=\":443\"; ma=2592000,"
      "h3-Q046=\":443\"; ma=2592000,",
      quic::ParsedQuicVersion::Q046(), quic::AllSupportedVersions());
}

TEST_P(HttpStreamFactoryJobControllerTest,
       AltSvcVersionSelectionFindsFirstMatchInverse) {
  TestAltSvcVersionSelection(
      "h3-Q046=\":443\"; ma=2592000,"
      "h3-Q048=\":443\"; ma=2592000,"
      "h3-Q049=\":443\"; ma=2592000,",
      quic::ParsedQuicVersion::Q046(), quic::AllSupportedVersions());
}

TEST_P(HttpStreamFactoryJobControllerTest,
       AltSvcVersionSelectionWithInverseOrderingNewFormat) {
  // Server prefers Q046 but client prefers Q050.
  TestAltSvcVersionSelection(
      "h3-Q046=\":443\"; ma=2592000,"
      "h3-Q050=\":443\"; ma=2592000",
      quic::ParsedQuicVersion::Q046(),
      quic::ParsedQuicVersionVector{quic::ParsedQuicVersion::Q046()});
}

// Tests that if HttpNetworkSession has a non-empty QUIC host allowlist,
// then GetAlternativeServiceFor() will not return any QUIC alternative service
// that's not on the allowlist.
TEST_P(HttpStreamFactoryJobControllerTest, QuicHostAllowlist) {
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  // Set HttpNetworkSession's QUIC host allowlist to only have www.example.com
  HttpNetworkSessionPeer session_peer(session_.get());
  session_peer.params()->quic_host_allowlist.insert("www.example.com");
  quic_context_.params()->allow_remote_alt_svc = true;

  // Set alternative service for www.google.com to be www.example.com over QUIC.
  url::SchemeHostPort server(request_info.url);
  base::Time expiration = base::Time::Now() + base::Days(1);
  quic::ParsedQuicVersionVector supported_versions =
      quic_context_.params()->supported_versions;
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(),
      AlternativeService(kProtoQUIC, "www.example.com", 443), expiration,
      supported_versions);

  // Simulate proxy resolution succeeding, after which
  // GetAlternativeServiceInfoFor can be called.
  JobControllerPeer::InitializeProxyInfo(job_controller_);

  AlternativeServiceInfo alt_svc_info =
      JobControllerPeer::GetAlternativeServiceInfoFor(
          job_controller_, request_info, &request_delegate_,
          HttpStreamRequest::HTTP_STREAM);

  std::sort(
      supported_versions.begin(), supported_versions.end(),
      [](const quic::ParsedQuicVersion& a, const quic::ParsedQuicVersion& b) {
        return a.transport_version < b.transport_version;
      });
  quic::ParsedQuicVersionVector advertised_versions =
      alt_svc_info.advertised_versions();
  std::sort(
      advertised_versions.begin(), advertised_versions.end(),
      [](const quic::ParsedQuicVersion& a, const quic::ParsedQuicVersion& b) {
        return a.transport_version < b.transport_version;
      });
  EXPECT_EQ(kProtoQUIC, alt_svc_info.alternative_service().protocol);
  EXPECT_EQ(supported_versions, advertised_versions);

  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(),
      AlternativeService(kProtoQUIC, "www.example.org", 443), expiration,
      supported_versions);

  alt_svc_info = JobControllerPeer::GetAlternativeServiceInfoFor(
      job_controller_, request_info, &request_delegate_,
      HttpStreamRequest::HTTP_STREAM);

  EXPECT_EQ(kProtoUnknown, alt_svc_info.alternative_service().protocol);
  EXPECT_EQ(0u, alt_svc_info.advertised_versions().size());
}

// Tests specific to UseDnsHttpsAlpn feature.
class HttpStreamFactoryJobControllerDnsHttpsAlpnTest
    : public HttpStreamFactoryJobControllerTestBase {
 protected:
  explicit HttpStreamFactoryJobControllerDnsHttpsAlpnTest(
      std::vector<base::test::FeatureRef> enabled_features = {})
      : HttpStreamFactoryJobControllerTestBase(
            /*dns_https_alpn_enabled=*/true,
            /*happy_eyeballs_v3_enabled=*/false,
            std::move(enabled_features)) {}

  void SetUp() override { SkipCreatingJobController(); }

  void EnableOndemandHostResolver() {
    session_deps_.host_resolver->set_synchronous_mode(false);
    session_deps_.host_resolver->set_ondemand_mode(true);
  }

  HttpRequestInfo CreateTestHttpRequestInfo() {
    HttpRequestInfo request_info;
    request_info.method = "GET";
    request_info.url = GURL("https://www.example.org");
    return request_info;
  }

  void RegisterMockHttpsRecord() {
    HostResolverEndpointResult endpoint_result1;
    endpoint_result1.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
    endpoint_result1.metadata.supported_protocol_alpns = {
        quic::AlpnForVersion(version_)};

    HostResolverEndpointResult endpoint_result2;
    endpoint_result2.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};

    std::vector<HostResolverEndpointResult> endpoints;
    endpoints.push_back(endpoint_result1);
    endpoints.push_back(endpoint_result2);
    session_deps_.host_resolver->rules()->AddRule(
        "www.example.org",
        MockHostResolverBase::RuleResolver::RuleResult(
            std::move(endpoints),
            /*aliases=*/std::set<std::string>{"www.example.org"}));
  }

  void CreateJobController(const HttpRequestInfo& request_info) {
    CreateJobControllerImpl(&job_controller_, &request_delegate_, request_info);
  }

  std::unique_ptr<HttpStreamRequest> CreateJobControllerAndStart(
      const HttpRequestInfo& request_info) {
    return CreateJobControllerAndStartImpl(&job_controller_, &request_delegate_,
                                           request_info);
  }

  std::unique_ptr<HttpStreamRequest> CreateSecondJobControllerAndStart(
      const HttpRequestInfo& request_info) {
    return CreateJobControllerAndStartImpl(&job_controller2_,
                                           &request_delegate2_, request_info);
  }

  void PrepareForMainJob() { PrepareForMainJobImpl(&tcp_data_, &ssl_data_); }
  void PrepareForSecondMainJob() {
    PrepareForMainJobImpl(&tcp_data2_, &ssl_data2_);
  }

  void PrepareForFirstQuicJob() { PrepareForQuicJobImpl(&quic_data_); }
  void PrepareForSecondQuicJob() { PrepareForQuicJobImpl(&quic_data2_); }

  void PrepareForFirstQuicJobFailure() {
    PrepareForQuicJobFailureImpl(&quic_data_);
  }
  void PrepareForSecondQuicJobFailure() {
    PrepareForQuicJobFailureImpl(&quic_data2_);
  }

  void MakeMainJobSucceed(bool expect_stream_ready) {
    MakeMainJobSucceedImpl(request_delegate_, tcp_data_.get(),
                           expect_stream_ready);
  }

  void MakeSecondMainJobSucceed(bool expect_stream_ready) {
    MakeMainJobSucceedImpl(request_delegate2_, tcp_data2_.get(),
                           expect_stream_ready);
  }

  void MakeQuicJobSucceed(size_t index, bool expect_stream_ready) {
    base::RunLoop().RunUntilIdle();
    ASSERT_GT(crypto_client_stream_factory_.streams().size(), index);
    Mo
"""


```