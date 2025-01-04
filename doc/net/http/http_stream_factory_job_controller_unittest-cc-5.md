Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack.

Here's a breakdown of how to address the request:

1. **Identify the Core Functionality:** The code consists of several C++ unit tests within the `HttpStreamFactoryJobControllerTest` and `JobControllerLimitMultipleH2Requests` classes. These tests are designed to verify the behavior of the `HttpStreamFactory::JobController`, which manages the process of establishing HTTP connections.

2. **List Key Features Tested:**  Scan the test names and the assertions within the tests to identify the specific features being tested. This includes:
    * Resuming the main job after a delay.
    * Resuming the main job immediately when an alternative (QUIC) connection fails.
    * Preconnecting to hosts.
    * Handling preconnects to HTTP/2 servers (limiting connections).
    * Interaction of preconnects with Network Isolation Keys.
    * Not delaying the main job if a SPDY session is available.
    * How a SPDY session can interrupt a preconnect request.
    * Ensuring preconnect jobs don't block subsequent requests using IP-based pooling.
    * Throttling multiple simultaneous requests to a single HTTP/2 server.
    * Throttling behavior with Network Isolation Keys.
    * Handling scenarios where the initial connection hangs.

3. **Explain Relationship to JavaScript:** Consider how these low-level networking functionalities might impact JavaScript in a web browser. JavaScript initiates network requests, and these C++ components are responsible for the underlying connection management.

4. **Provide Logical Reasoning (Input/Output):**  Choose a representative test case and explain its setup, the expected actions, and the assertions that verify the correct outcome.

5. **Illustrate Common Usage Errors:** Think about what could go wrong from a developer's perspective or from the perspective of how the network might behave unexpectedly.

6. **Describe User Actions:** Trace back how a user's action in a browser could lead to the execution of this code. It generally starts with a user navigating to a webpage.

7. **Summarize Functionality (for part 6 of 9):**  Condense the key functionalities covered in the provided code into a concise summary. Since this is part 6, focus on the aspects covered in this specific snippet.

**Mental Sandbox:**

* **Resuming Main Job:** Imagine a scenario where a browser tries a faster connection method (like QUIC) but it's taking time. The test checks if the browser correctly schedules and then resumes the standard TCP connection attempt.
* **Preconnect:** Visualize a browser trying to establish connections in the background to speed up future navigation. The tests ensure this preconnection logic works efficiently, especially with HTTP/2.
* **Throttling:**  Think about a website with many resources. The tests verify that the browser limits the number of simultaneous connections to a single server to avoid overloading it.
* **JavaScript Connection:**  A JavaScript `fetch()` call triggers a network request. This C++ code manages how that request is handled at the connection level.

By following these steps and thinking through the scenarios, a comprehensive and accurate explanation can be generated.
这是 Chromium 网络栈中 `net/http/http_stream_factory_job_controller_unittest.cc` 文件的第六部分。根据提供的代码片段，我们可以归纳一下它的主要功能：

**主要功能归纳：**

这部分代码主要测试 `HttpStreamFactory::JobController` 在以下方面的行为和功能：

1. **主任务的恢复机制：**
   - 测试在一定延迟后恢复主连接任务的逻辑，尤其是在存在备用连接（例如 QUIC）尝试的情况下。
   - 测试当备用连接尝试失败时，立即恢复主连接任务的逻辑。
   - 验证在主任务被延迟的情况下，当存在可用的 SPDY 会话时，主任务不会被延迟。

2. **预连接 (Preconnect) 功能：**
   - 测试 `JobController` 的预连接功能，即在用户实际请求之前，提前与服务器建立连接。
   - 验证当预连接到支持 HTTP/2 的服务器时，只会建立一个连接，即使请求了多个流。
   - 测试预连接功能如何尊重 `NetworkIsolationKey`，确保在不同的网络隔离键下可以建立多个预连接。

3. **SPDY 会话对预连接的影响：**
   - 测试当预连接正在等待时，如果出现了可用的 SPDY 会话，预连接任务能够成功完成，而不需要自己建立新的连接。

4. **预连接任务对后续请求的影响：**
   - 测试预连接任务不会阻塞可以使用现有基于 IP 池化的 SPDY 会话的后续请求。即使预连接任务正在进行中（例如，连接被暂停），后续请求仍然可以利用已有的会话。

5. **限制到 HTTP/2 服务器的并发请求：**
   - 测试针对同一个 HTTP/2 服务器的并发请求数量限制机制。验证当并发请求超过限制时，后续的请求会被节流。
   - 测试 HTTP/2 并发请求限制如何尊重 `NetworkIsolationKey`，不同的网络隔离键可以有各自的并发请求限制。
   - 测试当第一个连接请求挂起时，后续的并发请求是否会被正确处理。

**与 JavaScript 的功能关系：**

虽然这段 C++ 代码本身不包含 JavaScript，但它所测试的网络栈功能直接影响着 JavaScript 在浏览器中的网络请求行为。

* **`fetch()` API 和 `XMLHttpRequest`：**  当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起 HTTP 请求时，Chromium 的网络栈会负责处理这些请求，包括建立连接、发送数据、接收数据等。`HttpStreamFactory::JobController` 就参与了管理这些连接的建立过程。
* **预连接提升页面加载速度：**  JavaScript 驱动的页面可能包含指向其他资源的链接。浏览器可以通过预连接到这些资源的服务器来提前建立连接，从而在用户真正点击链接或 JavaScript 发起请求时，可以更快地建立连接，提升页面加载速度。这段代码测试的预连接功能正是为了保证这一优化的正确性。
* **HTTP/2 的连接复用：**  HTTP/2 允许在同一个 TCP 连接上并发发送多个请求。这段代码测试的针对 HTTP/2 服务器的连接管理和并发限制，直接影响着 JavaScript 发起的多个请求如何高效地利用底层的连接。

**举例说明：**

假设一个网页包含多个图片资源，这些资源都托管在同一个支持 HTTP/2 的服务器上。当浏览器加载这个网页时，JavaScript 可能会并行地发起多个图片资源的请求。

* **功能：限制到 HTTP/2 服务器的并发请求**  这段代码测试了 Chromium 如何限制到同一个 HTTP/2 服务器的并发连接数。例如，如果服务器允许的最大并发流是 100，而 JavaScript 同时请求了 150 个资源，`JobController` 会将超出限制的 50 个请求放入队列中，等待之前的请求完成后再发送，避免服务器过载。

**逻辑推理，假设输入与输出：**

**场景：测试备用连接失败时立即恢复主连接任务**

* **假设输入：**
    * 用户访问 `https://www.google.com`。
    * 浏览器尝试使用 QUIC 协议（备用连接）。
    * QUIC 握手因某种原因失败（例如，模拟的 `quic_data.Resume()` 后返回 `ERR_FAILED`）。
    * 已经设置了延迟主连接任务的条件（例如，之前与该服务器的连接统计信息）。
* **预期输出：**
    * 在 QUIC 连接尝试失败后，主连接任务 (`job_factory_.main_job()`) 会立即被恢复 (`Resume()` 方法被调用)。
    * 最终会使用 TCP 连接来完成请求。

**用户或编程常见的使用错误：**

* **服务器配置错误导致 HTTP/2 连接问题：**  如果服务器配置了 HTTP/2 但存在问题（例如，证书不匹配、协议协商失败），浏览器可能会尝试建立 HTTP/2 连接但最终失败，然后回退到 HTTP/1.1。这段代码测试了在备用连接（如 QUIC）失败后，主连接（通常是 TCP）能够被正确恢复，保证请求最终可以完成。
* **开发者过度依赖预连接：**  虽然预连接可以提升性能，但如果开发者过度使用预连接，可能会导致不必要的资源消耗。这段代码测试了预连接的效率和限制，例如对 HTTP/2 服务器只建立一个连接，有助于避免资源浪费。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 `https://www.google.com` 并回车。**
2. **浏览器解析 URL，确定需要建立 HTTPS 连接。**
3. **浏览器检查本地缓存和协议协商信息，可能决定尝试 QUIC 连接作为备用方案。**
4. **`HttpStreamFactory` 创建 `JobController` 来管理连接建立过程。**
5. **`JobController` 同时启动主连接任务（TCP）和备用连接任务（QUIC）。**
6. **如果 QUIC 连接尝试失败（例如，服务器不支持或网络问题），这段测试代码覆盖的逻辑就会被触发。**
7. **`JobController` 会立即恢复主连接任务，尝试使用 TCP 建立连接。**
8. **最终，浏览器使用 TCP 连接与 `www.google.com` 建立连接，并获取网页内容。**

在调试网络连接问题时，如果发现连接建立过程有延迟或者备用连接尝试失败，可以关注 `HttpStreamFactory::JobController` 的行为，查看相关的日志信息，例如 `net_log_with_source_` 中记录的事件，以了解连接建立过程中发生了什么。

**总结一下这部分代码的功能：**

这是 `HttpStreamFactory::JobController` 单元测试的第六部分，主要关注以下功能：主连接任务的恢复机制（延迟恢复、备用连接失败时立即恢复、存在可用 SPDY 会话时不延迟），预连接功能及其对 HTTP/2 和 `NetworkIsolationKey` 的处理，SPDY 会话对预连接的影响，预连接任务对后续请求的影响（特别是基于 IP 池化的情况），以及对 HTTP/2 服务器的并发请求限制（包括对 `NetworkIsolationKey` 的尊重）。这些测试确保了 `JobController` 在各种场景下能够正确、高效地管理 HTTP 连接的建立。

Prompt: 
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共9部分，请归纳一下它的功能

"""
main_job_is_resumed(job_controller_));

  // Task to resume main job in 3 seconds should be posted.
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  FastForwardBy(kMaxDelayTimeForMainJob - base::Microseconds(1));
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  FastForwardBy(base::Microseconds(1));

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(JobControllerPeer::main_job_is_resumed(job_controller_));

  // Unpause mock quic data and run all remaining tasks. Alt-job  should fail
  // and be cleaned up.
  quic_data.Resume();
  FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(job_controller_->alternative_job());
}

// TODO(crbug.com/40649375): Disabled because the pending task count does
//                                  not match expectations.
TEST_P(HttpStreamFactoryJobControllerTest,
       DISABLED_ResumeMainJobImmediatelyOnStreamFailed) {
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  // handshake will fail asynchronously after mock data is unpaused.
  MockQuicData quic_data(version_);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause
  quic_data.AddRead(ASYNC, ERR_FAILED);
  quic_data.AddWrite(ASYNC, ERR_FAILED);
  quic_data.AddSocketDataToFactory(session_deps_.socket_factory.get());

  // Enable delayed TCP and set time delay for waiting job.
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);
  ServerNetworkStats stats1;
  stats1.srtt = base::Microseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")),
      NetworkAnonymizationKey(), stats1);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // This prevents handshake from immediately succeeding.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  // Main job is not blocked but hasn't resumed yet; it's scheduled to resume
  // in 15us.
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  EXPECT_FALSE(JobControllerPeer::main_job_is_resumed(job_controller_));

  // Task to resume main job in 15us should be posted.
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());

  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  FastForwardBy(base::Microseconds(1));

  // Now unpause the mock quic data to fail the alt job. This should immediately
  // resume the main job.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  quic_data.Resume();
  FastForwardBy(base::TimeDelta());

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_TRUE(JobControllerPeer::main_job_is_resumed(job_controller_));

  // Verify there is another task to resume main job with delay but should
  // not call Resume() on the main job as main job has been resumed.
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  FastForwardBy(base::Microseconds(15));

  FastForwardUntilNoTasksRemain();
}

TEST_P(HttpStreamFactoryJobControllerTest, PreconnectToHostWithValidAltSvc) {
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data_->AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  SetPreconnect();

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  job_controller_->Preconnect(1);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_EQ(HttpStreamFactory::PRECONNECT,
            job_controller_->main_job()->job_type());
  EXPECT_FALSE(job_controller_->alternative_job());

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// When preconnect to a H2 supported server, only 1 connection is opened.
TEST_P(HttpStreamFactoryJobControllerTest,
       PreconnectMultipleStreamsToH2Server) {
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SetPreconnect();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");
  Initialize(request_info);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, NetworkAnonymizationKey(), true);

  job_controller_->Preconnect(/*num_streams=*/5);
  // Only one job is started.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_EQ(HttpStreamFactory::PRECONNECT,
            job_controller_->main_job()->job_type());
  // There is only 1 connect even though multiple streams were requested.
  EXPECT_EQ(
      1, HttpStreamFactoryJobPeer::GetNumStreams(job_controller_->main_job()));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Check that the logic to only preconnect a single socket to servers with H2
// support respects NetworkIsolationKeys.
TEST_P(HttpStreamFactoryJobControllerTest,
       PreconnectMultipleStreamsToH2ServerWithNetworkIsolationKey) {
  base::test::ScopedFeatureList feature_list;
  // It's not strictly necessary to enable
  // `kPartitionConnectionsByNetworkIsolationKey`, but the second phase of the
  // test would only make 4 connections, reusing the first connection, without
  // it.
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Need to re-create HttpServerProperties after enabling the field trial,
  // since it caches the field trial value on construction.
  session_deps_.http_server_properties =
      std::make_unique<HttpServerProperties>();

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SetPreconnect();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");
  request_info.network_isolation_key = kNetworkIsolationKey1;
  request_info.network_anonymization_key = kNetworkAnonymizationKey1;
  Initialize(request_info);

  // Sets server support HTTP/2, using kNetworkIsolationKey.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, kNetworkAnonymizationKey1, true);

  job_controller_->Preconnect(/*num_streams=*/5);
  // Only one job is started.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_EQ(HttpStreamFactory::PRECONNECT,
            job_controller_->main_job()->job_type());
  // There is only 1 connect even though multiple streams were requested.
  EXPECT_EQ(
      1, HttpStreamFactoryJobPeer::GetNumStreams(job_controller_->main_job()));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));

  // Now try using two different NetworkIsolationKeys, one empty, one not, and
  // make sure that 5 sockets are preconnected with each one.
  std::vector<std::unique_ptr<SequencedSocketData>> socket_data;
  for (auto other_network_isolation_key :
       {NetworkIsolationKey(), kNetworkIsolationKey2}) {
    for (int i = 0; i < 5; ++i) {
      socket_data.emplace_back(std::make_unique<SequencedSocketData>(
          MockConnect(ASYNC, OK), base::span<const MockRead>(),
          base::span<const MockWrite>()));
      session_deps_.socket_factory->AddSocketDataProvider(
          socket_data.back().get());
    }

    request_info.network_isolation_key = other_network_isolation_key;
    request_info.network_anonymization_key =
        NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
            other_network_isolation_key);
    MockHttpStreamRequestDelegate request_delegate;
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, &request_delegate, session_.get(), &job_factory_,
        request_info, is_preconnect_, /*is_websocket=*/false,
        enable_ip_based_pooling_, enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    auto* job_controller_ptr = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
    job_controller_ptr->Preconnect(/*num_streams=*/5);
    // Five jobs should be started.
    EXPECT_TRUE(job_controller_ptr->main_job());
    EXPECT_FALSE(job_controller_ptr->alternative_job());
    EXPECT_EQ(HttpStreamFactory::PRECONNECT,
              job_controller_ptr->main_job()->job_type());
    EXPECT_EQ(5, HttpStreamFactoryJobPeer::GetNumStreams(
                     job_controller_ptr->main_job()));

    base::RunLoop().RunUntilIdle();
    EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  }
}

void HttpStreamFactoryJobControllerTestBase::
    TestDoNotDelayMainJobIfHasAvailableSpdySession(bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);

  SetNotDelayMainJobWithAvailableSpdySession();
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  // Put a SpdySession in the pool.
  HostPortPair host_port_pair("www.google.com", 443);
  SpdySessionKey key(host_port_pair, PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  std::ignore = CreateFakeSpdySession(session_->spdy_session_pool(), key);

  // Handshake will fail asynchronously after mock data is unpaused.
  MockQuicData quic_data(version_);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause
  quic_data.AddRead(ASYNC, ERR_FAILED);
  quic_data.AddWrite(ASYNC, ERR_FAILED);
  quic_data.AddSocketDataToFactory(session_deps_.socket_factory.get());

  // Enable delayed TCP and set time delay for waiting job.
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);
  ServerNetworkStats stats1;
  stats1.srtt = base::Milliseconds(100);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")),
      NetworkAnonymizationKey(), stats1);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // This prevents handshake from immediately succeeding.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  // The main job shouldn't have any delay since request can be sent on
  // available SPDY session. When QUIC session creation is async, the main job
  // should still be blocked as alt job has not succeeded or failed at least
  // once yet. Otherwise the main job should not be blocked
  EXPECT_EQ(job_controller_->get_main_job_wait_time_for_tests(),
            base::TimeDelta());
  if (async_quic_session) {
    EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));
    // The main job should have a SPDY session available.
    EXPECT_TRUE(job_controller_->main_job()->HasAvailableSpdySession());
    // Wait for QUIC session creation attempt to resume and unblock the main
    // job.
    FastForwardBy(base::Milliseconds(1));
    // Main job should still have no delay and should be unblocked now.
    EXPECT_EQ(job_controller_->get_main_job_wait_time_for_tests(),
              base::TimeDelta());
    EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  } else {
    EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
    EXPECT_TRUE(job_controller_->main_job()->HasAvailableSpdySession());
  }
}

TEST_P(HttpStreamFactoryJobControllerTest,
       DoNotDelayMainJobIfHasAvailableSpdySession) {
  TestDoNotDelayMainJobIfHasAvailableSpdySession(false);
}

TEST_P(HttpStreamFactoryJobControllerTest,
       DoNotDelayMainJobIfHasAvailableSpdySessionAsyncQuicSession) {
  TestDoNotDelayMainJobIfHasAvailableSpdySession(true);
}

// Check the case that while a preconnect is waiting in the H2 request queue,
// and a SPDY session appears, the job completes successfully.
TEST_P(HttpStreamFactoryJobControllerTest, SpdySessionInterruptsPreconnect) {
  // Make sure there is only one socket connect.
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  tcp_data_ = std::make_unique<SequencedSocketData>(reads, writes);
  // connect needs to be async, so the H2 session isn't created immediately.
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, NetworkAnonymizationKey(), true);

  // Start a non-preconnect request.
  std::unique_ptr<HttpStreamRequest> stream_request = job_controller_->Start(
      &request_delegate_, nullptr /* websocket_handshake_create_helper */,
      NetLogWithSource(), HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));

  // Create and start a preconnect request, which should start watching the
  // SpdySessionPool.
  MockHttpStreamRequestDelegate preconnect_request_delegate;
  auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
      factory_, &preconnect_request_delegate, session_.get(), &job_factory_,
      request_info, /*is_preconnect=*/true, /*is_websocket=*/false,
      enable_ip_based_pooling_, enable_alternative_services_,
      delay_main_job_with_available_spdy_session_,
      /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
  auto* job_controller_ptr = job_controller.get();
  HttpStreamFactoryPeer::AddJobController(factory_, std::move(job_controller));
  job_controller_ptr->Preconnect(1);
  EXPECT_TRUE(job_controller_ptr->main_job());
  EXPECT_FALSE(job_controller_ptr->alternative_job());

  // The non-preconnect request should create an H2 session, which the
  // preconnect then sees, and the preconnect request should complete and be
  // torn down without ever requesting a socket. If it did request a socket, the
  // test would fail since the mock socket factory would see an unexpected
  // socket request.
  base::RunLoop().RunUntilIdle();

  stream_request.reset();

  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));

  // Sanity check - make sure the SpdySession was created.
  base::WeakPtr<SpdySession> spdy_session =
      session_->spdy_session_pool()->FindAvailableSession(
          SpdySessionKey(HostPortPair::FromURL(request_info.url),
                         request_info.privacy_mode, ProxyChain::Direct(),
                         SessionUsage::kDestination, request_info.socket_tag,
                         request_info.network_anonymization_key,
                         request_info.secure_dns_policy,
                         /*disable_cert_verification_network_fetches=*/false),
          false /* enable_ip_based_pooling */, /*is_websocket=*/false,
          NetLogWithSource());
  EXPECT_TRUE(spdy_session);
}

// This test verifies that a preconnect job doesn't block subsequent requests
// which can use an existing IP based pooled SpdySession.
// This test uses "wildcard.pem" to support IpBasedPooling for *.example.org,
// and starts 3 requests:
//   [1] Normal non-preconnect request to www.example.org.
//   [2] Preconnect request to other.example.org. The connection is paused until
//       OnConnectComplete() is called in the end of the test.
//   [3] Normal non-preconnect request to other.example.org. This request must
//       succeed even while the preconnect request [2] is paused.
TEST_P(HttpStreamFactoryJobControllerTest,
       PreconnectJobDoesntBlockIpBasedPooling) {
  // Make sure that both "www.example.org" and "other.example.org" are pointing
  // to the same IP address.
  session_deps_.host_resolver->rules()->AddRule(
      "www.example.org", IPAddress::IPv4Localhost().ToString());
  session_deps_.host_resolver->rules()->AddRule(
      "other.example.org", IPAddress::IPv4Localhost().ToString());
  // Make |host_resolver| asynchronous to simulate the issue of
  // crbug.com/1320608.
  session_deps_.host_resolver->set_synchronous_mode(false);

  // This is used for the non-preconnect requests [1] and [3].
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  SequencedSocketData first_socket(reads, writes);
  first_socket.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(&first_socket);

  // This is used for the non-preconnect requests.
  SSLSocketDataProvider ssl_data1(ASYNC, OK);
  ssl_data1.next_proto = kProtoHTTP2;
  // "wildcard.pem" supports "*.example.org".
  ssl_data1.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);

  // This is used for the preconnect request.
  SequencedSocketData second_socket;
  // The connection is paused. And it will be completed with
  // ERR_CONNECTION_FAILED.
  second_socket.set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  session_deps_.socket_factory->AddSocketDataProvider(&second_socket);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org");
  Initialize(request_info);

  // Start a non-preconnect request [1].
  {
    std::unique_ptr<HttpStreamRequest> stream_request = job_controller_->Start(
        &request_delegate_,
        /*websocket_handshake_stream_create_helper=*/nullptr,
        NetLogWithSource(), HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    if (dns_https_alpn_enabled()) {
      EXPECT_CALL(*job_factory_.main_job(), Resume())
          .Times(1)
          .WillOnce([this]() { job_factory_.main_job()->DoResume(); });
    }
    base::RunLoop run_loop;
    EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
        .WillOnce([&run_loop]() { run_loop.Quit(); });
    run_loop.Run();
  }

  // Sanity check - make sure the SpdySession was created.
  {
    base::WeakPtr<SpdySession> spdy_session =
        session_->spdy_session_pool()->FindAvailableSession(
            SpdySessionKey(HostPortPair::FromURL(request_info.url),
                           request_info.privacy_mode, ProxyChain::Direct(),
                           SessionUsage::kDestination, request_info.socket_tag,
                           request_info.network_anonymization_key,
                           request_info.secure_dns_policy,
                           /*disable_cert_verification_network_fetches=*/false),
            /*enable_ip_based_pooling=*/false, /*is_websocket=*/false,
            NetLogWithSource());
    EXPECT_TRUE(spdy_session);
  }

  HttpRequestInfo other_request_info;
  other_request_info.method = "GET";
  other_request_info.url = GURL("https://other.example.org");

  // Create and start a preconnect request [2].
  MockHttpStreamRequestDelegate preconnect_request_delegate;
  auto preconnect_job_controller =
      std::make_unique<HttpStreamFactory::JobController>(
          factory_, &preconnect_request_delegate, session_.get(), &job_factory_,
          other_request_info, /*is_preconnect=*/true,
          /*is_websocket=*/false, /*enable_ip_based_pooling=*/true,
          enable_alternative_services_,
          delay_main_job_with_available_spdy_session_,
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
  auto* preconnect_job_controller_ptr = preconnect_job_controller.get();
  HttpStreamFactoryPeer::AddJobController(factory_,
                                          std::move(preconnect_job_controller));
  preconnect_job_controller_ptr->Preconnect(1);
  base::RunLoop().RunUntilIdle();

  // The SpdySession is available for IP based pooling when the host resolution
  // has finished.
  {
    const SpdySessionKey spdy_session_key = SpdySessionKey(
        HostPortPair::FromURL(other_request_info.url),
        other_request_info.privacy_mode, ProxyChain::Direct(),
        SessionUsage::kDestination, other_request_info.socket_tag,
        other_request_info.network_anonymization_key,
        other_request_info.secure_dns_policy,
        /*disable_cert_verification_network_fetches=*/false);
    EXPECT_FALSE(session_->spdy_session_pool()->FindAvailableSession(
        spdy_session_key, /*enable_ip_based_pooling=*/false,
        /*is_websocket=*/false, NetLogWithSource()));
    EXPECT_TRUE(session_->spdy_session_pool()->FindAvailableSession(
        spdy_session_key, /*enable_ip_based_pooling=*/true,
        /*is_websocket=*/false, NetLogWithSource()));
  }

  // Create and start a second non-preconnect request [3].
  {
    MockHttpStreamRequestDelegate request_delegate;
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, &request_delegate, session_.get(), &job_factory_,
        other_request_info, /*is_preconnect=*/false,
        /*is_websocket=*/false, /*enable_ip_based_pooling=*/true,
        enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    auto* job_controller_ptr = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
    std::unique_ptr<HttpStreamRequest> second_stream_request =
        job_controller_ptr->Start(
            &request_delegate,
            /*websocket_handshake_stream_create_helper=*/nullptr,
            NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
            DEFAULT_PRIORITY);

    base::RunLoop run_loop;
    EXPECT_CALL(request_delegate, OnStreamReadyImpl(_, _))
        .WillOnce([&run_loop]() { run_loop.Quit(); });
    run_loop.Run();
    second_stream_request.reset();
  }

  second_socket.socket()->OnConnectComplete(
      MockConnect(SYNCHRONOUS, ERR_CONNECTION_FAILED));
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  EXPECT_TRUE(first_socket.AllReadDataConsumed());
  EXPECT_TRUE(first_socket.AllWriteDataConsumed());
}

class JobControllerLimitMultipleH2Requests
    : public HttpStreamFactoryJobControllerTestBase {
 protected:
  JobControllerLimitMultipleH2Requests()
      : HttpStreamFactoryJobControllerTestBase(
            /*dns_https_alpn_enabled=*/false,
            /*happy_eyeballs_v3_enabled=*/false) {}
  const int kNumRequests = 5;
  void SetUp() override { SkipCreatingJobController(); }
};

TEST_F(JobControllerLimitMultipleH2Requests, MultipleRequests) {
  // Make sure there is only one socket connect.
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  tcp_data_ =
      std::make_unique<SequencedSocketData>(reads, base::span<MockWrite>());
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
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

  for (int i = 0; i < kNumRequests; ++i) {
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _));
  }

  base::RunLoop().RunUntilIdle();
  requests.clear();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  auto entries = net_log_observer_.GetEntries();
  size_t log_position = 0;
  for (int i = 0; i < kNumRequests - 1; ++i) {
    log_position = ExpectLogContainsSomewhereAfter(
        entries, log_position, NetLogEventType::HTTP_STREAM_JOB_THROTTLED,
        NetLogEventPhase::NONE);
  }
}

// Check that throttling simultaneous requests to a single H2 server respects
// NetworkIsolationKeys.
TEST_F(JobControllerLimitMultipleH2Requests,
       MultipleRequestsNetworkIsolationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Need to re-create HttpServerProperties after enabling the field trial,
  // since it caches the field trial value on construction.
  session_deps_.http_server_properties =
      std::make_unique<HttpServerProperties>();

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  tcp_data_ = std::make_unique<SequencedSocketData>(
      MockConnect(SYNCHRONOUS, ERR_IO_PENDING), base::span<MockRead>(),
      base::span<MockWrite>());
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(
      server, kNetworkAnonymizationKey1, true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  std::vector<std::unique_ptr<SequencedSocketData>> socket_data;
  for (int i = 0; i < kNumRequests; ++i) {
    // Shouldn't matter whether requests are interleaved by NetworkIsolationKey
    // or not.
    for (const auto& network_isolation_key :
         {NetworkIsolationKey(), kNetworkIsolationKey1,
          kNetworkIsolationKey2}) {
      request_info.network_isolation_key = network_isolation_key;
      request_info.network_anonymization_key =
          NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
              network_isolation_key);
      // For kNetworkIsolationKey1, all requests but the first will be
      // throttled.
      if (i == 0 || network_isolation_key != kNetworkIsolationKey1) {
        socket_data.emplace_back(std::make_unique<SequencedSocketData>(
            MockConnect(ASYNC, OK), base::span<const MockRead>(),
            base::span<const MockWrite>()));
        session_deps_.socket_factory->AddSocketDataProvider(
            socket_data.back().get());
      }
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
  }
  TransportClientSocketPool* socket_pool =
      reinterpret_cast<TransportClientSocketPool*>(session_->GetSocketPool(
          HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct()));
  ClientSocketPool::GroupId group_id0(
      url::SchemeHostPort(request_info.url), request_info.privacy_mode,
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);
  ClientSocketPool::GroupId group_id1(
      url::SchemeHostPort(request_info.url), request_info.privacy_mode,
      kNetworkAnonymizationKey1, SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);
  ClientSocketPool::GroupId group_id2(
      url::SchemeHostPort(request_info.url), request_info.privacy_mode,
      kNetworkAnonymizationKey2, SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);
  EXPECT_EQ(static_cast<uint32_t>(kNumRequests),
            socket_pool->NumConnectJobsInGroupForTesting(group_id0));
  EXPECT_EQ(1u, socket_pool->NumConnectJobsInGroupForTesting(group_id1));
  EXPECT_EQ(static_cast<uint32_t>(kNumRequests),
            socket_pool->NumConnectJobsInGroupForTesting(group_id2));
}

TEST_F(JobControllerLimitMultipleH2Requests, MultipleRequestsFirstRequestHang) {
  // First socket connect hang.
  SequencedSocketData hangdata;
  hangdata.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  session_deps_.socket_factory->AddSocketDataProvider(&hangdata);
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  std::list<SequencedSocketData> socket_data;
  std::list<SSLSocketDataPr
"""


```