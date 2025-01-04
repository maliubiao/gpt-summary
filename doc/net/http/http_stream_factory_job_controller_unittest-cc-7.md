Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `http_stream_factory_job_controller_unittest.cc` file.

I need to address the following points:

1. **Functionality:**  Summarize what this code does. It's a unit test file, so its primary function is to test the behavior of `HttpStreamFactory::JobController`.
2. **Relationship to JavaScript:** Determine if this C++ code interacts with JavaScript. Given its location in the network stack, direct interaction is unlikely, but I should consider potential indirect relationships (e.g., network requests initiated by JavaScript).
3. **Logical Reasoning (Input/Output):**  As this is a test file, I can infer input (test setup, configurations) and expected output (assertions about the state of the `JobController`). I should provide examples.
4. **Common Usage Errors:** Identify potential mistakes developers might make when working with or extending this code or the classes it tests.
5. **User Operation to Reach Here (Debugging):** Explain how a user action in the browser might lead to this code being executed.
6. **Part 8 of 9 - Overall Function:** Given this is part of a larger file, I should summarize the specific role of this section within the overall testing framework.

**Mental Sandbox:**

* **Functionality:** The code sets up various scenarios to test how `HttpStreamFactory::JobController` manages different types of connection attempts (main TCP, alternative protocols like QUIC, and DNS-based ALPN negotiation). It uses mock objects and data providers to simulate network conditions and verify expected behavior.
* **JavaScript:** JavaScript in a browser makes network requests. These requests eventually go through Chromium's network stack, potentially involving the `HttpStreamFactory` and its `JobController`. The connection is indirect – JavaScript *triggers* the network activity that this code tests.
* **Input/Output:**  A test case like `NoHttpsRecordSyncHostResolve` takes an initial state (no HSTS, synchronous DNS resolution) and expects a specific outcome (main job succeeds, DNS ALPN job fails). I can represent this as an input configuration and expected assertions.
* **Common Errors:**  Developers might introduce errors in test setup, incorrect assertions, or not fully simulating edge cases.
* **User Operation:** A user typing a URL and hitting Enter initiates a network request. If it's an HTTPS URL, the `HttpStreamFactory` will be involved.
* **Part 8:** This section focuses heavily on testing the interaction between the main TCP connection attempt and the DNS-based HTTPS ALPN (HTTP/3) connection attempt. It covers scenarios where one wins the race, where an active session exists, and how delays are handled based on network conditions.

**Confidence Score:** 5/5 - I have a good understanding of the request and the nature of the code.

**Plan of Action:**

1. Describe the core functionality of the unit test file and the specific component it tests.
2. Explain the indirect relationship with JavaScript via network requests. Provide an example.
3. Select a representative test case and illustrate its input (setup) and expected output (assertions).
4. Discuss common pitfalls in writing or extending such tests.
5. Outline the user actions that trigger network requests and how they might lead to this part of the code being executed.
6. Summarize the main focus of this particular section of the test file based on the included test cases.
这是 `net/http/http_stream_factory_job_controller_unittest.cc` 文件的第 8 部分，主要功能是测试 `HttpStreamFactory::JobController` 在处理 **DNS-based HTTPS ALPN (HTTP/3)**  相关的连接尝试时的行为。

**核心功能归纳 (基于提供的代码片段):**

这部分测试用例专注于以下场景：

* **DNS HTTPS Record 的存在与否:** 测试当目标主机存在或不存在 HTTPS DNS 记录时，`JobController` 如何创建和管理不同的连接尝试（主 TCP 连接和 DNS ALPN H3 连接）。
* **同步与异步主机名解析:**  测试在同步和异步主机名解析的情况下，`JobController` 如何启动和管理连接尝试。
* **QUIC 工作状态的影响:**  测试当网络已知支持 QUIC 时，`JobController` 是否会延迟主 TCP 连接的启动，以给 DNS ALPN H3 连接更多的时间完成。
* **已存在的会话的影响:** 测试当已经存在可用的 SpdySession 或 QuicSession 时，`JobController` 如何创建和管理新的连接尝试。特别是测试在存在可用会话的情况下，DNS ALPN H3 连接是否会被创建。
* **主连接和 DNS ALPN H3 连接的竞争:** 测试当主 TCP 连接和 DNS ALPN H3 连接同时进行时，哪一个先成功会如何影响另一个。
* **代理场景:** 测试在通过代理进行连接时，是否会创建 DNS ALPN H3 连接（通常代理场景下不会进行目标主机的 DNS 解析）。

**与 JavaScript 的关系 (间接):**

虽然这段 C++ 代码本身不包含 JavaScript，但它所测试的网络栈组件是 JavaScript 发起的网络请求的基础。

**举例说明:**

1. **用户在浏览器地址栏输入 `https://www.example.org` 并回车。**
2. **渲染进程中的 JavaScript 代码发起一个网络请求。**
3. **这个请求会被传递到网络进程。**
4. **网络进程中的 `HttpStreamFactory` 负责创建连接。**
5. **`HttpStreamFactory::JobController` 被创建来管理这个连接尝试。**
6. **如果启用了 DNS-based HTTPS ALPN，并且目标主机可能支持 HTTP/3，那么 `JobController` 可能会同时启动一个主 TCP 连接尝试和一个 DNS ALPN H3 连接尝试。**
7. **这段测试代码就是用来验证在各种条件下，`JobController` 是否按照预期的方式创建和管理这些连接尝试。**

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `HttpRequestInfo` 指示请求的 URL 是 `https://www.example.org/`.
* 测试运行在一个网络环境下，已知 QUIC 在当前网络上没有工作过 (`quic_session_pool->set_has_quic_ever_worked_on_current_network(false);`)。
* 目标主机存在 HTTPS DNS 记录。
* 主机名解析是异步的。

**预期输出 (基于 `MainJobNoDelayOnQuicNotWorkedNetworkAsyncHostResolve` 测试用例):**

1. `JobController` 会同时创建主 TCP 连接的 Job (`main_job_exists=true`) 和 DNS ALPN H3 连接的 Job (`dns_alpn_h3_job_exists=true`)。
2. 主 TCP 连接的 Job 最初会等待主机名解析完成 (`job_controller_->main_job()->is_waiting()` 为 true)。
3. 当 DNS ALPN H3 连接的 Job 完成主机名解析后，主 TCP 连接的 Job 会被立即恢复，不会因为 QUIC 在当前网络上没有工作过而延迟 (`job_controller_->main_job()->is_waiting()` 为 false)。
4. 最终 DNS ALPN H3 连接的 Job 成功，主 TCP 连接的 Job 被取消。

**用户或编程常见的使用错误:**

* **测试配置错误:** 在编写测试用例时，可能错误地配置了网络环境（例如，错误地设置了 QUIC 的工作状态），导致测试结果不准确。
* **断言错误:**  对 `JobController` 的状态或行为进行了错误的断言，导致即使代码有 bug，测试也可能通过。
* **未考虑所有场景:**  可能遗漏了一些重要的边界情况或特殊场景，导致 `JobController` 在这些情况下出现问题。例如，没有充分测试各种 DNS 解析结果的情况。
* **Mock 对象行为不当:**  Mock 对象（例如 `MockHttpStreamRequestDelegate`, `MockQuicData`) 的行为设置不当，无法真实模拟网络交互，导致测试失效。

**用户操作如何一步步到达这里 (调试线索):**

假设用户报告了一个 Chrome 浏览器无法连接到某个 HTTPS 网站的问题，并且怀疑是 HTTP/3 相关的问题。调试步骤可能如下：

1. **用户尝试访问该 HTTPS 网站。**
2. **Chrome 的网络栈开始尝试建立连接。**
3. **`HttpStreamFactory` 被调用来创建连接。**
4. **`HttpStreamFactory::JobController` 被创建来管理连接尝试。**
5. **如果启用了 DNS-based HTTPS ALPN，`JobController` 会尝试解析 HTTPS DNS 记录。**
6. **如果 HTTPS DNS 记录存在，`JobController` 会启动一个 DNS ALPN H3 连接尝试。**
7. **开发者可能会在 `HttpStreamFactory::JobController` 的代码中设置断点，或者查看网络日志 (chrome://net-export/)，以观察 `JobController` 的状态和行为。**
8. **如果怀疑是 `JobController` 的逻辑问题，开发者可能会参考或运行 `http_stream_factory_job_controller_unittest.cc` 中的相关测试用例，来验证 `JobController` 在类似场景下的行为是否符合预期。**
9. **例如，如果怀疑在 DNS 解析失败的情况下 `JobController` 的处理有问题，可以查看 `NoHttpsRecordSyncHostResolve` 或 `NoHttpsRecordAsyncHostResolveResumeMainWithoutDelay` 等测试用例。**

**作为第 8 部分的功能归纳:**

作为整个测试文件的一部分，这第 8 部分专注于 **全面测试 `HttpStreamFactory::JobController` 在 DNS-based HTTPS ALPN 场景下的连接管理逻辑。** 它覆盖了各种关键因素，如 DNS 记录的存在、主机名解析的方式、QUIC 的工作状态以及已存在会话的影响，旨在确保 `JobController` 在这些复杂情况下能够正确地创建、管理和协调不同的连接尝试，从而保证网络连接的稳定性和效率。 这部分特别关注主 TCP 连接和 DNS ALPN H3 连接之间的交互和竞争。

Prompt: 
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共9部分，请归纳一下它的功能

"""
ckCryptoClientStream* stream =
        crypto_client_stream_factory_.streams()[index].get();
    ASSERT_TRUE(stream);

    if (expect_stream_ready) {
      base::RunLoop run_loop;
      EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
          .Times(1)
          .WillOnce(Invoke([&run_loop]() { run_loop.Quit(); }));
      stream->NotifySessionOneRttKeyAvailable();
      run_loop.Run();
    } else {
      EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _)).Times(0);
      stream->NotifySessionOneRttKeyAvailable();
      base::RunLoop().RunUntilIdle();
    }
  }

  void CheckJobsStatus(bool main_job_exists,
                       bool alternative_job_exists,
                       bool dns_alpn_h3_job_exists,
                       const std::string& scoped_trace_message = "") {
    CheckJobsStatusImpl(job_controller_.get(), main_job_exists,
                        alternative_job_exists, dns_alpn_h3_job_exists,
                        scoped_trace_message);
  }

  void CheckSecondJobsStatus(bool main_job_exists,
                             bool alternative_job_exists,
                             bool dns_alpn_h3_job_exists,
                             const std::string& scoped_trace_message = "") {
    CheckJobsStatusImpl(job_controller2_.get(), main_job_exists,
                        alternative_job_exists, dns_alpn_h3_job_exists,
                        scoped_trace_message);
  }

  std::unique_ptr<QuicHttpStream> ConnectQuicHttpStream(
      bool alt_destination,
      bool require_dns_https_alpn) {
    NetErrorDetails net_error_details;
    QuicSessionRequest quic_request(session_->quic_session_pool());
    url::SchemeHostPort scheme_host_port(
        url::kHttpsScheme,
        alt_destination ? "alt.example.org" : "www.example.org", 443);
    std::optional<int> quic_request_result;

    CHECK_EQ(ERR_IO_PENDING,
             quic_request.Request(
                 scheme_host_port,
                 require_dns_https_alpn ? quic::ParsedQuicVersion::Unsupported()
                                        : version_,
                 ProxyChain::Direct(), TRAFFIC_ANNOTATION_FOR_TESTS,
                 /*http_user_agent_settings=*/nullptr,
                 SessionUsage::kDestination, PRIVACY_MODE_DISABLED,
                 DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
                 SecureDnsPolicy::kAllow, require_dns_https_alpn,
                 /*cert_verify_flags=*/0, GURL("https://www.example.org/"),
                 net_log_with_source_, &net_error_details,
                 MultiplexedSessionCreationInitiator::kUnknown,
                 base::BindLambdaForTesting([&](int result) {}),
                 base::BindLambdaForTesting([&quic_request_result](int result) {
                   quic_request_result = result;
                 })));
    base::RunLoop().RunUntilIdle();
    CHECK_EQ(1u, crypto_client_stream_factory_.streams().size());
    CHECK(crypto_client_stream_factory_.streams()[0]);
    crypto_client_stream_factory_.streams()[0]
        ->NotifySessionOneRttKeyAvailable();
    base::RunLoop().RunUntilIdle();
    CHECK(quic_request_result);
    CHECK_EQ(OK, *quic_request_result);

    std::unique_ptr<QuicChromiumClientSession::Handle> session =
        quic_request.ReleaseSessionHandle();
    std::set<std::string> dns_aliases =
        session->GetDnsAliasesForSessionKey(quic_request.session_key());
    auto stream = std::make_unique<QuicHttpStream>(std::move(session),
                                                   std::move(dns_aliases));
    return stream;
  }

  bool IsAlternativeServiceBroken(GURL& url) {
    return session_->http_server_properties()->IsAlternativeServiceBroken(
        AlternativeService(kProtoQUIC, HostPortPair::FromURL(url)),
        NetworkAnonymizationKey());
  }

  raw_ptr<HttpStreamFactory::JobController, AcrossTasksDanglingUntriaged>
      job_controller2_ = nullptr;

  MockHttpStreamRequestDelegate request_delegate2_;

 private:
  QuicTestPacketMaker CreateQuicTestPacketMakerForClient() {
    return QuicTestPacketMaker(version_,
                               quic::QuicUtils::CreateRandomConnectionId(
                                   quic_context_.random_generator()),
                               quic_context_.clock(), "www.example.org",
                               quic::Perspective::IS_CLIENT, false);
  }

  void CreateJobControllerImpl(
      raw_ptr<HttpStreamFactory::JobController, AcrossTasksDanglingUntriaged>*
          job_controller,
      MockHttpStreamRequestDelegate* request_delegate,
      const HttpRequestInfo& request_info) {
    auto controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, request_delegate, session_.get(), &default_job_factory_,
        request_info, is_preconnect_, /*is_websocket=*/false,
        enable_ip_based_pooling_, enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    *job_controller = controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_, std::move(controller));
  }

  std::unique_ptr<HttpStreamRequest> CreateJobControllerAndStartImpl(
      raw_ptr<HttpStreamFactory::JobController, AcrossTasksDanglingUntriaged>*
          job_controller,
      MockHttpStreamRequestDelegate* request_delegate,
      const HttpRequestInfo& request_info) {
    CreateJobControllerImpl(job_controller, request_delegate, request_info);
    return (*job_controller)
        ->Start(request_delegate, nullptr, net_log_with_source_,
                HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  }

  void PrepareForMainJobImpl(std::unique_ptr<SequencedSocketData>* tcp_data,
                             std::unique_ptr<SSLSocketDataProvider>* ssl_data) {
    *tcp_data = std::make_unique<SequencedSocketData>();
    (*tcp_data)->set_connect_data(
        MockConnect(ASYNC, ERR_IO_PENDING)); /* pause */
    (*ssl_data) = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    session_deps_.socket_factory->AddSSLSocketDataProvider(ssl_data->get());
  }

  void PrepareForQuicJobImpl(std::unique_ptr<MockQuicData>* quic_data) {
    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::COLD_START);
    *quic_data = std::make_unique<MockQuicData>(version_);
    (*quic_data)->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
    (*quic_data)
        ->AddWrite(
            SYNCHRONOUS,
            CreateQuicTestPacketMakerForClient().MakeInitialSettingsPacket(1));
  }

  void PrepareForQuicJobFailureImpl(std::unique_ptr<MockQuicData>* quic_data) {
    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::COLD_START);
    *quic_data = std::make_unique<MockQuicData>(version_);
    (*quic_data)->AddRead(ASYNC, ERR_IO_PENDING);  // Pause
    (*quic_data)->AddRead(ASYNC, ERR_FAILED);
  }

  void MakeMainJobSucceedImpl(MockHttpStreamRequestDelegate& request_delegate,
                              SequencedSocketData* tcp_data,
                              bool expect_stream_ready) {
    if (expect_stream_ready) {
      base::RunLoop run_loop;
      EXPECT_CALL(request_delegate, OnStreamReadyImpl(_, _))
          .Times(1)
          .WillOnce(Invoke([&run_loop]() { run_loop.Quit(); }));
      tcp_data->socket()->OnConnectComplete(MockConnect());
      run_loop.Run();
    } else {
      EXPECT_CALL(request_delegate, OnStreamReadyImpl(_, _)).Times(0);
      tcp_data->socket()->OnConnectComplete(MockConnect());
      base::RunLoop().RunUntilIdle();
    }
  }

  static void CheckJobsStatusImpl(
      HttpStreamFactory::JobController* job_controller,
      bool main_job_exists,
      bool alternative_job_exists,
      bool dns_alpn_h3_job_exists,
      const std::string& scoped_trace_message) {
    SCOPED_TRACE(scoped_trace_message);
    EXPECT_EQ(main_job_exists, !!job_controller->main_job());
    EXPECT_EQ(alternative_job_exists, !!job_controller->alternative_job());
    EXPECT_EQ(dns_alpn_h3_job_exists, !!job_controller->dns_alpn_h3_job());
  }

  // Use real Jobs so that Job::Resume() is not mocked out. When main job is
  // resumed it will use mock socket data.
  HttpStreamFactory::JobFactory default_job_factory_;

  // Used for man job connection.
  std::unique_ptr<SSLSocketDataProvider> ssl_data_;
  std::unique_ptr<SSLSocketDataProvider> ssl_data2_;
};

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       NoHttpsRecordSyncHostResolve) {
  PrepareForMainJob();
  Initialize(HttpRequestInfo());
  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  // The main job should be synchronously resumed, as host is resolved
  // synchronously.
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  base::RunLoop().RunUntilIdle();

  // |dns_alpn_h3_job| must fail when there is no valid supported alpn. And
  // must be deleted.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS ALPN job must be deleted.");

  base::HistogramTester histogram_tester;
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  // Net.AlternateProtocolUsage records
  // ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON, when only main job exists.
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON,
      1);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       NoHttpsRecordAsyncHostResolveResumeMainWithoutDelay) {
  EnableOndemandHostResolver();
  PrepareForMainJob();
  Initialize(HttpRequestInfo());

  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  // The main job should be resumed quickly after resolving the host.
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // Resolve the host resolve request from |dns_alpn_h3_job|.
  session_deps_.host_resolver->ResolveAllPending();
  base::RunLoop().RunUntilIdle();

  // |dns_alpn_h3_job| must fail when there is no valid supported alpn. And
  // must be deleted.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS ALPN job must be deleted.");
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  // The host resolve request from the main job must be resolved using the
  // cached result.
  EXPECT_TRUE(tcp_data_->socket());

  base::HistogramTester histogram_tester;
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  // Net.AlternateProtocolUsage records
  // ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON, when only main job exists.
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON,
      1);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       NoHttpsRecordAsyncHostResolveResumeMainWithoutDelayQuicWorkedNetwork) {
  EnableOndemandHostResolver();
  PrepareForMainJob();
  Initialize(HttpRequestInfo());

  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);

  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");
  // Main job must be waiting.
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // Resolve the host resolve request from |dns_alpn_h3_job|.
  session_deps_.host_resolver->ResolveAllPending();
  base::RunLoop().RunUntilIdle();

  // |dns_alpn_h3_job| must fail when there is no valid supported alpn. And
  // must be deleted.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS ALPN job must be deleted.");
  // The main job should be resumed quickly after resolving the host.
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  // The host resolve request from the main job must be resolved using the
  // cached result.
  EXPECT_TRUE(tcp_data_->socket());

  base::HistogramTester histogram_tester;
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  // Net.AlternateProtocolUsage records
  // ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON, when only main job exists.
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_UNSPECIFIED_REASON,
      1);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       MainJobNoDelayOnQuicNotWorkedNetworkSyncHostResolve) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();
  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");
  // `dns_alpn_h3_job` should not be waiting for dns host
  // resolution as that was resolved synchronously.
  EXPECT_FALSE(job_controller_->dns_alpn_h3_job()
                   ->expect_on_quic_host_resolution_for_tests());

  base::HistogramTester histogram_tester;
  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE, 1);

  // The success of |dns_alpn_h3_job| deletes |main_job|.
  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Main job must be deleted.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       MainJobNoDelayOnQuicNotWorkedNetworkAsyncHostResolve) {
  EnableOndemandHostResolver();
  PrepareForMainJob();
  PrepareForFirstQuicJob();
  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  // |main_job| is blocked until host resolves.
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // Resolve the host resolve request from |dns_alpn_h3_job|.
  session_deps_.host_resolver->ResolveAllPending();
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  base::RunLoop().RunUntilIdle();

  // |main_job| should have been resumed quickly because
  // |is_quic_known_to_work_on_current_network| is false for this test.
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());
  // |dns_alpn_h3_job| must not fail when there is a valid supported alpn.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Both main job and DNS ALPN job must be alive");

  base::HistogramTester histogram_tester;
  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE, 1);

  // The success of |dns_alpn_h3_job| deletes |main_job|.
  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Main job must be deleted.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       MainJobDelayOnQuicWorkedNetwork) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();
  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);

  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");
  base::RunLoop().RunUntilIdle();
  // |dns_alpn_h3_job| must not fail when there is a valid supported alpn.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Both main job and DNS ALPN job must be alive");

  // The main job should be waiting until kDefaultDelayMilliSecsForWaitingJob
  // amount of time has passed.
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(kDefaultDelayMilliSecsForWaitingJob - 1));
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(1));
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  base::HistogramTester histogram_tester;
  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_RACE, 1);

  // The success of |dns_alpn_h3_job| deletes |main_job|.
  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true, "Main job must be deleted.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Test that for a proxied session no DNS APLN H3 job is created (since we don't
// want to perform DNS resolution corresponding to requests that will be
// proxied).
TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       NoDnsAlpnH3JobForProxiedSession) {
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = std::make_unique<MockQuicData>(quic::ParsedQuicVersion::RFCv1());
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);

  Initialize(HttpRequestInfo());

  auto proxy_chain =
      ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
          ProxyServer::SCHEME_QUIC, "proxy", 99)});

  auto* test_proxy_delegate =
      static_cast<TestProxyDelegate*>(session_deps_.proxy_delegate.get());
  test_proxy_delegate->set_proxy_chain(proxy_chain);

  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS ALPN H3 job must not have been created.");

  base::RunLoop().RunUntilIdle();

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       MainJobSucceedsDnsAlpnH3JobSucceeds) {
  PrepareForMainJob();
  PrepareForFirstQuicJob();
  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());
  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());
  base::RunLoop().RunUntilIdle();

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");
  // |main_job| is not blocked, because the hostname is resolved synchronously
  // and |is_quic_known_to_work_on_current_network| is false for this test.
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  base::HistogramTester histogram_tester;
  // Make |main_job| succeed.
  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_MAIN_JOB_WON_RACE,
      1);

  // The success of |main_job| doesn't delete |dns_alpn_h3_job|.
  EXPECT_TRUE(job_controller_->dns_alpn_h3_job());

  // Make |dns_alpn_h3_job| complete.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       ActiveSessionAvailableForMainJob) {
  HttpRequestInfo request_info = CreateTestHttpRequestInfo();
  PrepareForFirstQuicJob();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  // Set |is_quic_known_to_work_on_current_network| flag so that
  // the delaying logic of main job would work when the main job is blocked.
  // Note: In this test, we don't need this because the main job is not blocked.
  // But we set here because we want to check that the main job is not blocked.
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);

  // Put a SpdySession in the pool.
  SpdySessionKey key(HostPortPair::FromURL(request_info.url),
                     PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  std::ignore = CreateFakeSpdySession(session_->spdy_session_pool(), key);

  request_ = CreateJobControllerAndStart(request_info);
  // |dns_alpn_h3_job| must be created even when an active session is
  // available for |main_job|.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  // Main job must not be waiting because an active session is available.
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  base::HistogramTester histogram_tester;
  // Run the message loop to make |main_job| succeed and status will be
  // reported to Request.
  {
    base::RunLoop run_loop;
    EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
        .Times(1)
        .WillOnce(Invoke([&run_loop]() { run_loop.Quit(); }));
    run_loop.Run();
  }
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage", ALTERNATE_PROTOCOL_USAGE_MAIN_JOB_WON_RACE,
      1);

  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "DNS ALPN job must be alive");

  // Make |dns_alpn_h3_job| succeed.
  MakeQuicJobSucceed(0, /*expect_stream_ready=*/false);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/false,
                  "DNS ALPN job must be deleted");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest, MainJobHasActiveSocket) {
  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  PrepareForMainJob();
  PrepareForSecondMainJob();

  PrepareForFirstQuicJobFailure();
  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  // Set |is_quic_known_to_work_on_current_network| flag so that
  // the delaying logic of main job would work when the main job is blocked.
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);

  request_ = CreateJobControllerAndStart(request_info);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and DNS ALPN job must be created.");

  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(kDefaultDelayMilliSecsForWaitingJob - 1));
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(1));
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  auto request2 = CreateSecondJobControllerAndStart(request_info);
  CheckSecondJobsStatus(
      /*main_job_exists=*/true, /*alternative_job_exists=*/false,
      /*dns_alpn_h3_job_exists=*/true,
      "Main job and DNS ALPN job must be created for the second request.");

  // When an active socket is available for the main job, the main job should
  // not be blocked.
  EXPECT_FALSE(job_controller2_->main_job()->is_waiting());

  quic_data_->Resume();
  base::RunLoop().RunUntilIdle();

  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  MakeSecondMainJobSucceed(/*expect_stream_ready=*/true);
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       MainJobHasActiveSocketAltSvcRegistered) {
  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  PrepareForMainJob();
  PrepareForSecondMainJob();

  PrepareForFirstQuicJobFailure();
  PrepareForSecondQuicJobFailure();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  // Set |is_quic_known_to_work_on_current_network| flag so that
  // the delaying logic of main job would work when the main job is blocked.
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "alt.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/true,
                  "All types of jobs are created");

  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(kDefaultDelayMilliSecsForWaitingJob - 1));
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(1));
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());

  auto request2 = CreateSecondJobControllerAndStart(request_info);
  CheckSecondJobsStatus(
      /*main_job_exists=*/true, /*alternative_job_exists=*/true,
      /*dns_alpn_h3_job_exists=*/true,
      "All types of jobs must be created for the second request.");

  // The main job should be waiting until kDefaultDelayMilliSecsForWaitingJob
  // amount of time has passed, when an alternative service was registered,
  // even when an active socket is available for the main job.
  // This is intended to switch to QUIC from TCP for the first connection
  // when the server supports Alt-Svc but doesn't support HTTP DNS records with
  // alpn.
  // Note: When QuicParams.delay_main_job_with_available_spdy_session is false,
  // main job is not blocked.
  EXPECT_TRUE(job_controller2_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(kDefaultDelayMilliSecsForWaitingJob - 1));
  EXPECT_TRUE(job_controller2_->main_job()->is_waiting());
  FastForwardBy(base::Milliseconds(1));
  EXPECT_FALSE(job_controller2_->main_job()->is_waiting());

  quic_data_->Resume();
  quic_data2_->Resume();
  base::RunLoop().RunUntilIdle();

  MakeMainJobSucceed(/*expect_stream_ready=*/true);
  MakeSecondMainJobSucceed(/*expect_stream_ready=*/true);
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       ActiveSessionAvailableForAltSvcJob) {
  PrepareForMainJob();
  RegisterMockHttpsRecord();

  HttpRequestInfo request_info = CreateTestHttpRequestInfo();

  PrepareForFirstQuicJob();

  Initialize(HttpRequestInfo());

  std::unique_ptr<QuicHttpStream> stream =
      ConnectQuicHttpStream(/*alt_destination=*/true,
                            /*require_dns_https_alpn=*/false);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, "alt.example.org", 443);
  SetAlternativeService(request_info, alternative_service);

  request_ = CreateJobControllerAndStart(request_info);

  // |dns_alpn_h3_job| must not be created when an active session is
  // available for |alternative_job|.
  CheckJobsStatus(/*main_job_exists=*/true, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/false,
                  "Main job and alternative job must be created.");

  base::HistogramTester histogram_tester;
  // Run the message loop to make |alternative_job| succeed and status will be
  // reported to Request.
  {
    base::RunLoop run_loop;
    EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
        .Times(1)
        .WillOnce(Invoke([&run_loop]() { run_loop.Quit(); }));
    run_loop.Run();
  }
  histogram_tester.ExpectUniqueSample("Net.AlternateProtocolUsage",
                                      ALTERNATE_PROTOCOL_USAGE_NO_RACE, 1);

  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/true,
                  /*dns_alpn_h3_job_exists=*/false,
                  "Main job must be deleted.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       ActiveSessionAvailableForDnsAlpnH3Job) {
  PrepareForFirstQuicJob();
  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  std::unique_ptr<QuicHttpStream> stream =
      ConnectQuicHttpStream(/*alt_destination=*/false,
                            /*require_dns_https_alpn=*/true);
  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job and alternative job must not be available.");

  base::HistogramTester histogram_tester;
  // Run the message loop to make |dns_alpn_h3_job| succeed and status will be
  // reported to Request.
  {
    base::RunLoop run_loop;
    EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
        .Times(1)
        .WillOnce(Invoke([&run_loop]() { run_loop.Quit(); }));
    run_loop.Run();
  }
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_WITHOUT_RACE, 1);
  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "DNS alpn H3 job must exist.");

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryJobControllerDnsHttpsAlpnTest,
       ActiveSessionAvailableForMainJobAndDnsAlpnH3Job) {
  HttpRequestInfo request_info = CreateTestHttpRequestInfo();
  PrepareForFirstQuicJob();

  RegisterMockHttpsRecord();

  Initialize(HttpRequestInfo());

  // Put a SpdySession in the pool.
  SpdySessionKey key(HostPortPair::FromURL(request_info.url),
                     PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  std::ignore = CreateFakeSpdySession(session_->spdy_session_pool(), key);

  std::unique_ptr<QuicHttpStream> stream =
      ConnectQuicHttpStream(/*alt_destination=*/false,
                            /*require_dns_https_alpn=*/true);
  request_ = CreateJobControllerAndStart(CreateTestHttpRequestInfo());

  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job_exists=*/false,
                  /*dns_alpn_h3_job_exists=*/true,
                  "Main job must not be available.");

  base::HistogramTester histogram_tester;
  // Run the message loop to make |dns_alpn_h3_job| succeed and status will be
  // reported to Request.
  {
    base::RunLoop run_loop;
    EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _))
        .Times(1)
        .WillOnce(Invoke([&run_loop]() { run_loop.Quit(); }));
    run_loop.Run();
  }
  histogram_tester.ExpectUniqueSample(
      "Net.AlternateProtocolUsage",
      ALTERNATE_PROTOCOL_USAGE_DNS_ALPN_H3_JOB_WON_WITHOUT_RACE, 1);

  CheckJobsStatus(/*main_job_exists=*/false, /*alternative_job
"""


```