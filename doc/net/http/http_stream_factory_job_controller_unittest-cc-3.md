Response:
The user wants a summary of the functionality of the provided C++ code, which is a unit test file for `HttpStreamFactoryJobController` in Chromium's network stack. I need to:

1. **Identify the core purpose of the tests:** What aspects of `HttpStreamFactoryJobController` are being tested?
2. **Summarize the functionality demonstrated by the tests.**
3. **Check for connections to JavaScript:** This seems unlikely given the nature of the code, but I need to explicitly state if there are none.
4. **Explain logical reasoning with input/output examples:**  For each test case, I can consider the setup as input and the assertions as the expected output.
5. **Identify common user/programming errors:**  The tests themselves don't directly expose user errors, but I can infer potential issues the code aims to prevent or handle.
6. **Describe the user journey to reach this code:**  This involves understanding the network request lifecycle in a browser.
7. **Provide a concise summary of the file's purpose.**

Based on the test names and the operations performed in the tests, it seems like `HttpStreamFactoryJobController` manages the lifecycle of multiple connection attempts (main TCP and alternative QUIC) for a single HTTP request. The tests cover scenarios like:

- Canceling jobs before binding.
- Not creating alternative jobs when QUIC versions are incompatible.
- Handling cases where QUIC was recently broken.
- Managing job failures and successes in different orders.
- Ensuring proper cleanup of resources.
- Verifying the correct session key is used.

Let's break down each point more specifically.
这是 `net/http/http_stream_factory_job_controller_unittest.cc` 文件（第 4 部分，共 9 部分）的功能归纳：

**总体功能：**

此文件包含了针对 `HttpStreamFactoryJobController` 类的单元测试。`HttpStreamFactoryJobController` 的主要职责是协调和管理为一个 HTTP 请求创建和连接到服务器的多个 "Job"（任务）。 这些 Job 可能包括尝试使用传统的 TCP 连接（主 Job）和使用替代协议（如 QUIC，作为替代 Job）进行连接。

**具体功能测试归纳：**

* **取消 Job：** 测试在连接绑定之前取消请求是否能正确取消所有相关的 Job，并确保 `JobController` 在完成后被删除。
* **不创建不支持的替代 Job：** 验证当服务器通告的替代服务（如 QUIC）版本与客户端不支持的任何版本都不匹配时，是否不会创建替代 Job。
* **处理最近断开的 QUIC 连接：** 测试在 QUIC 最近断开的情况下，是否会正确处理主 Job 的延迟和阻塞逻辑。
* **主 Job 和替代 Job 的失败处理：**  测试当主 Job 和替代 Job 都失败时，是否能正确报告错误，以及是否根据情况标记或不标记替代协议为断开。
* **主 Job 成功后替代 Job 的失败处理：** 测试当主 Job 成功建立连接后，替代 Job 失败时，是否会正确标记替代协议为断开，以及这种断开状态是否会在网络改变后清除。
* **替代 Job 成功后主 Job 的销毁：** 验证当替代 Job 成功建立连接后，主 Job 是否会被正确销毁。
* **替代 Job 成功但主 Job 被阻塞的情况：**  测试当替代 Job 成功时，即使主 Job 因为某些原因被阻塞，也能正确处理并销毁主 Job 和 `JobController`。
* **Spdy 会话 Key 的 Origin Host Port Pair：** 验证为 SPDY (HTTP/2) 会话创建的 Key 是否正确包含了原始的 host 和 port 信息。
* **孤立 Job 完成后的 Controller 销毁：** 测试当主 Job 完成后请求被取消，而替代 Job 随后完成时，`JobController` 能否被正确清理。
* **主 Job 失败后替代 Job 的成功处理：** 验证当主 Job 连接失败后，替代 Job 成功建立连接时，是否能正确处理，并且不会错误地标记替代协议为断开。
* **主 Job 成功后替代 Job 的成功处理：** 测试当主 Job 成功建立连接后，替代 Job 也成功建立连接的情况，以及是否会根据替代 Job 的网络重试情况正确标记替代协议为断开。

**与 JavaScript 的关系：**

这个文件是 C++ 代码，直接与 JavaScript 功能没有**直接**的关系。然而，它测试的网络栈组件是浏览器中负责处理网络请求的关键部分。当 JavaScript 代码发起一个 HTTP 或 HTTPS 请求时（例如使用 `fetch` API 或 `XMLHttpRequest`），底层的网络栈（包括 `HttpStreamFactoryJobController`）会参与到连接建立的过程中。

**举例说明：**

假设 JavaScript 代码发起一个针对 `https://www.google.com` 的请求：

```javascript
fetch('https://www.google.com')
  .then(response => {
    // 处理响应
  })
  .catch(error => {
    // 处理错误
  });
```

在这个请求的底层，`HttpStreamFactoryJobController` 可能会尝试建立到 `www.google.com` 的 TCP 连接（主 Job），同时如果配置允许，也会尝试建立 QUIC 连接（替代 Job）。这个单元测试文件中的测试就覆盖了 `HttpStreamFactoryJobController` 在各种场景下（例如 QUIC 可用或不可用，连接成功或失败）的行为，确保网络请求能正确建立连接并返回结果给 JavaScript 代码。

**逻辑推理与假设输入输出：**

以下以 `CancelJobsBeforeBinding` 测试为例：

* **假设输入：**
    * 请求的 URL 是 `https://www.google.com`。
    * 启用了 QUIC 替代协议。
    * 在连接建立完成之前取消了请求。
* **预期输出：**
    * 主 Job 和替代 Job 都被取消。
    * `HttpStreamFactoryJobController` 对象被删除。
    * 不会记录替代协议断开的信息。

**涉及用户或编程常见的使用错误：**

这个单元测试主要关注网络栈内部的逻辑，不太直接涉及用户的日常操作错误。但是，它可以帮助发现和预防以下编程或配置错误：

* **不正确的替代协议配置：** 测试确保在配置了不支持的 QUIC 版本时不会尝试创建连接，这可以防止由于错误配置导致的连接失败。
* **过早取消请求导致资源泄漏：** 测试确保在请求被取消时，相关的网络资源（如 socket 连接）能被正确释放，防止资源泄漏。
* **在网络状态变化时未正确更新连接状态：** 某些测试模拟了网络状态变化（例如，QUIC 断开），确保 `HttpStreamFactoryJobController` 能正确处理这些变化。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 `https://www.google.com` 并回车，或者点击了网页上的一个链接。**
2. **浏览器解析 URL，识别出需要建立 HTTPS 连接。**
3. **浏览器网络栈开始处理请求。`HttpStreamFactory` 负责创建用于连接服务器的 Job。**
4. **`HttpStreamFactory` 创建一个 `HttpStreamFactoryJobController` 对象来管理这个请求的连接尝试。**
5. **`HttpStreamFactoryJobController` 可能同时启动一个主 Job (TCP) 和一个替代 Job (QUIC)。**
6. **如果在连接建立过程中，用户点击了停止按钮或者导航到其他页面，请求可能会被取消。 这就可能触发 `CancelJobsBeforeBinding` 测试所覆盖的场景。**
7. **如果服务器通告了 QUIC 支持，但客户端不支持该版本，`DoNotCreateAltJobIfQuicVersionsUnsupported` 测试覆盖了这种情况。**
8. **如果 QUIC 连接尝试失败或者最近失败过，相关的测试会验证 `HttpStreamFactoryJobController` 的行为。**

因此，在调试网络连接问题时，如果涉及到 HTTPS 连接建立，特别是涉及到 QUIC 协议时，`HttpStreamFactoryJobController` 的行为是需要关注的重点。这个单元测试文件可以帮助开发者理解和验证这部分逻辑的正确性。

**总结其功能:**

总而言之，`net/http/http_stream_factory_job_controller_unittest.cc`（第 4 部分）主要测试了 `HttpStreamFactoryJobController` 类在各种网络连接场景下的行为，包括连接的建立、取消、失败和成功，以及如何处理替代协议和网络状态变化，目的是确保网络栈能够可靠地建立连接并处理各种异常情况。

### 提示词
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
t.
TEST_P(HttpStreamFactoryJobControllerTest, CancelJobsBeforeBinding) {
  // Use COLD_START to make the alt job pending.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED);

  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  // Reset the Request will cancel all the Jobs since there's no Job determined
  // to serve Request yet and JobController will notify the factory to delete
  // itself upon completion.
  request_.reset();
  // QuicSessionPool::Job::Request will not complete since the Jobs are
  // canceled, so there is no need to check if all read data was consumed.
  should_check_data_consumed_ = false;
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Test that the controller does not create alternative job when the advertised
// versions in AlternativeServiceInfo do not contain any version that is
// supported.
TEST_P(HttpStreamFactoryJobControllerTest,
       DoNotCreateAltJobIfQuicVersionsUnsupported) {
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      {quic::ParsedQuicVersion::Unsupported()});

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  request_.reset();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

void HttpStreamFactoryJobControllerTestBase::
    TestDoNotDelayMainJobIfQuicWasRecentlyBroken(bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      quic_context_.params()->supported_versions);

  // Enable QUIC but mark the alternative service as recently broken.
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);
  session_->http_server_properties()->MarkAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey());

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // The main job shouldn't have any delay since QUIC was recently broken. Main
  // job should still be blocked as alt job has not succeeded or failed at least
  // once yet.
  EXPECT_EQ(job_controller_->get_main_job_wait_time_for_tests(),
            base::TimeDelta());
  if (async_quic_session) {
    EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));
  } else {
    EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  }
  // Make |alternative_job| succeed.
  auto http_stream = std::make_unique<HttpBasicStream>(
      std::make_unique<ClientSocketHandle>(), false);
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, http_stream.get()));

  HttpStreamFactoryJobPeer::SetStream(job_factory_.alternative_job(),
                                      std::move(http_stream));
  job_controller_->OnStreamReady(job_factory_.alternative_job());

  base::RunLoop().RunUntilIdle();

  // Check that alternative job is bound while main job is destroyed.
  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  request_.reset();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_P(HttpStreamFactoryJobControllerTest,
       DoNotDelayMainJobIfQuicWasRecentlyBroken) {
  TestDoNotDelayMainJobIfQuicWasRecentlyBroken(false);
}

TEST_P(HttpStreamFactoryJobControllerTest,
       DoNotDelayMainJobIfQuicWasRecentlyBrokenAsyncQuicSession) {
  TestDoNotDelayMainJobIfQuicWasRecentlyBroken(true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestDelayMainJobAfterRecentlyBrokenQuicWasConfirmed(
        bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  base::Time expiration = base::Time::Now() + base::Days(1);
  session_->http_server_properties()->SetQuicAlternativeService(
      server, NetworkAnonymizationKey(), alternative_service, expiration,
      quic_context_.params()->supported_versions);

  // Enable QUIC but mark the alternative service as recently broken.
  QuicSessionPool* quic_session_pool = session_->quic_session_pool();
  quic_session_pool->set_has_quic_ever_worked_on_current_network(true);
  session_->http_server_properties()->MarkAlternativeServiceRecentlyBroken(
      alternative_service, NetworkAnonymizationKey());

  // Confirm the alt service.
  session_->http_server_properties()->ConfirmAlternativeService(
      alternative_service, NetworkAnonymizationKey());

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // The main job should wait and it should still be blocked because the new
  // QUIC session hasn't been created yet. The wait time should be greater than
  // 0.
  EXPECT_TRUE(job_controller_->ShouldWait(
      const_cast<HttpStreamFactory::Job*>(job_controller_->main_job())));
  if (async_quic_session) {
    EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));
  } else {
    EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  }
  EXPECT_GE(job_controller_->get_main_job_wait_time_for_tests(),
            base::TimeDelta());

  // Make |alternative_job| succeed.
  auto http_stream = std::make_unique<HttpBasicStream>(
      std::make_unique<ClientSocketHandle>(), false);
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, http_stream.get()));

  HttpStreamFactoryJobPeer::SetStream(job_factory_.alternative_job(),
                                      std::move(http_stream));
  job_controller_->OnStreamReady(job_factory_.alternative_job());

  base::RunLoop().RunUntilIdle();

  // Check that alternative job is bound while main job is destroyed.
  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  request_.reset();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_P(HttpStreamFactoryJobControllerTest,
       DelayMainJobAfterRecentlyBrokenQuicWasConfirmed) {
  TestDelayMainJobAfterRecentlyBrokenQuicWasConfirmed(false);
}

TEST_P(HttpStreamFactoryJobControllerTest,
       DelayMainJobAfterRecentlyBrokenQuicWasConfirmedAsyncQuicSession) {
  TestDelayMainJobAfterRecentlyBrokenQuicWasConfirmed(true);
}

void HttpStreamFactoryJobControllerTestBase::TestOnStreamFailedForBothJobs(
    bool alt_job_retried_on_non_default_network,
    bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddConnect(ASYNC, ERR_FAILED);
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(ASYNC, ERR_FAILED));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  if (alt_job_retried_on_non_default_network) {
    // Set the alt job as if it failed on the default network and is retired on
    // the alternate network.
    JobControllerPeer::SetAltJobFailedOnDefaultNetwork(job_controller_);
  }

  if (async_quic_session) {
    EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1).WillOnce([this]() {
      job_factory_.main_job()->DoResume();
    });
  }
  // The failure of second Job should be reported to Request as there's no more
  // pending Job to serve the Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(1);
  base::RunLoop().RunUntilIdle();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// This test verifies that the alternative service is not marked broken if both
// jobs fail, and the alternative job is not retried on the alternate network.
TEST_P(HttpStreamFactoryJobControllerTest,
       OnStreamFailedForBothJobsWithoutQuicRetry) {
  TestOnStreamFailedForBothJobs(false, false);
}

// This test verifies that the alternative service is not marked broken if both
// jobs fail, and the alternative job is retried on the alternate network.
TEST_P(HttpStreamFactoryJobControllerTest,
       OnStreamFailedForBothJobsWithQuicRetriedOnAlternateNetwork) {
  TestOnStreamFailedForBothJobs(true, false);
}

// This test verifies that the alternative service is not marked broken if both
// jobs fail, and the alternative job is not retried on the alternate network.
// This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       OnStreamFailedForBothJobsWithoutQuicRetryAsyncQuicSession) {
  TestOnStreamFailedForBothJobs(false, true);
}

// This test verifies that the alternative service is not marked broken if both
// jobs fail, and the alternative job is retried on the alternate network. This
// test uses asynchronous QUIC session creation.
TEST_P(
    HttpStreamFactoryJobControllerTest,
    OnStreamFailedForBothJobsWithQuicRetriedOnAlternateNetworkAsyncQuicSession) {
  TestOnStreamFailedForBothJobs(true, true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestAltJobFailsAfterMainJobSucceeded(
        bool alt_job_retried_on_non_default_network,
        bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(ASYNC, ERR_FAILED);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(SYNCHRONOUS, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  if (alt_job_retried_on_non_default_network) {
    // Set the alt job as if it failed on the default network and is retired on
    // the alternate network.
    JobControllerPeer::SetAltJobFailedOnDefaultNetwork(job_controller_);
  }

  if (async_quic_session) {
    EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1).WillOnce([this]() {
      job_factory_.main_job()->DoResume();
    });
  }
  // Main job succeeds, starts serving Request and it should report status
  // to Request. The alternative job will mark the main job complete and gets
  // orphaned.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));
  // JobController shouldn't report the status of second job as request
  // is already successfully served.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(0);

  base::RunLoop().RunUntilIdle();

  // Reset the request as it's been successfully served.
  request_.reset();
  base::RunLoop().RunUntilIdle();
  VerifyBrokenAlternateProtocolMapping(request_info, true);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));

  // Verify the brokenness is not cleared when the default network changes.
  session_->http_server_properties()->OnDefaultNetworkChanged();
  VerifyBrokenAlternateProtocolMapping(request_info, true);
}

// This test verifies that the alternative service is marked broken when the
// alternative job fails on default after the main job succeeded.  The
// brokenness should not be cleared when the default network changes.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobFailsOnDefaultNetworkAfterMainJobSucceeded) {
  TestAltJobFailsAfterMainJobSucceeded(false, false);
}

// This test verifies that the alternative service is marked broken when the
// alternative job fails on both networks after the main job succeeded.  The
// brokenness should not be cleared when the default network changes.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobFailsOnBothNetworksAfterMainJobSucceeded) {
  TestAltJobFailsAfterMainJobSucceeded(true, false);
}

// This test verifies that the alternative service is marked broken when the
// alternative job fails on default after the main job succeeded. The
// brokenness should not be cleared when the default network changes. This test
// uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobFailsOnDefaultNetworkAfterMainJobSucceededAsyncQuicSession) {
  TestAltJobFailsAfterMainJobSucceeded(false, true);
}

// This test verifies that the alternative service is marked broken when the
// alternative job fails on both networks after the main job succeeded.  The
// brokenness should not be cleared when the default network changes. This test
// uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobFailsOnBothNetworksAfterMainJobSucceededAsyncQuicSession) {
  TestAltJobFailsAfterMainJobSucceeded(true, true);
}

void HttpStreamFactoryJobControllerTestBase::TestAltJobSucceedsMainJobDestroyed(
    bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  // Use cold start and complete alt job manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  if (async_quic_session) {
    EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));
  } else {
    EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  }
  // Make |alternative_job| succeed.
  auto http_stream = std::make_unique<HttpBasicStream>(
      std::make_unique<ClientSocketHandle>(), false);
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, http_stream.get()));

  HttpStreamFactoryJobPeer::SetStream(job_factory_.alternative_job(),
                                      std::move(http_stream));
  job_controller_->OnStreamReady(job_factory_.alternative_job());

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  request_.reset();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Tests that when alt job succeeds, main job is destroyed.
TEST_P(HttpStreamFactoryJobControllerTest, AltJobSucceedsMainJobDestroyed) {
  TestAltJobSucceedsMainJobDestroyed(false);
}

// Tests that when alt job succeeds, main job is destroyed.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsMainJobDestroyedAsyncQuicSession) {
  TestAltJobSucceedsMainJobDestroyed(true);
}

// Tests that if alt job succeeds and main job is blocked, main job should be
// cancelled immediately. |request_| completion will clean up the JobController.
// Regression test for crbug.com/678768.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsMainJobBlockedControllerDestroyed) {
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data_->AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // |alternative_job| succeeds and should report status to |request_delegate_|.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Invoke OnRequestComplete() which should delete |job_controller_| from
  // |factory_|.
  request_.reset();
  // base::RunLoop().RunUntilIdle();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  // This fails without the fix for crbug.com/678768.
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_P(HttpStreamFactoryJobControllerTest,
       SpdySessionKeyHasOriginHostPortPair) {
  session_deps_.enable_http2_alternative_service = true;

  const char origin_host[] = "www.example.org";
  const uint16_t origin_port = 443;
  const char alternative_host[] = "mail.example.org";
  const uint16_t alternative_port = 123;

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url =
      GURL(base::StringPrintf("https://%s:%u", origin_host, origin_port));
  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoHTTP2, alternative_host,
                                         alternative_port);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  HostPortPair main_host_port_pair =
      HttpStreamFactoryJobPeer::GetSpdySessionKey(job_controller_->main_job())
          .host_port_pair();
  EXPECT_EQ(origin_host, main_host_port_pair.host());
  EXPECT_EQ(origin_port, main_host_port_pair.port());

  HostPortPair alternative_host_port_pair =
      HttpStreamFactoryJobPeer::GetSpdySessionKey(
          job_controller_->alternative_job())
          .host_port_pair();
  EXPECT_EQ(origin_host, alternative_host_port_pair.host());
  EXPECT_EQ(origin_port, alternative_host_port_pair.port());
}

void HttpStreamFactoryJobControllerTestBase::
    TestOrphanedJobCompletesControllerDestroyed(bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  // Use cold start and complete alt job manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  if (async_quic_session) {
    EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1).WillOnce([this]() {
      job_factory_.main_job()->DoResume();
    });
  }

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));

  // Complete main job now.
  base::RunLoop().RunUntilIdle();

  // Invoke OnRequestComplete() which should not delete |job_controller_| from
  // |factory_| because alt job is yet to finish.
  request_.reset();
  ASSERT_FALSE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Make |alternative_job| succeed.
  auto http_stream = std::make_unique<HttpBasicStream>(
      std::make_unique<ClientSocketHandle>(), false);
  HttpStreamFactoryJobPeer::SetStream(job_factory_.alternative_job(),
                                      std::move(http_stream));
  // This should not call request_delegate_::OnStreamReady.
  job_controller_->OnStreamReady(job_factory_.alternative_job());
  // Make sure that controller does not leak.
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Tests that if an orphaned job completes after |request_| is gone,
// JobController will be cleaned up.
TEST_P(HttpStreamFactoryJobControllerTest,
       OrphanedJobCompletesControllerDestroyed) {
  TestOrphanedJobCompletesControllerDestroyed(false);
}

// Tests that if an orphaned job completes after |request_| is gone,
// JobController will be cleaned up.
TEST_P(HttpStreamFactoryJobControllerTest,
       OrphanedJobCompletesControllerDestroyedAsyncQuicSession) {
  TestOrphanedJobCompletesControllerDestroyed(true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestAltJobSucceedsAfterMainJobFailed(
        bool alt_job_retried_on_non_default_network,
        bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  // Use cold start and complete alt job manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  // One failed TCP connect.
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, ERR_FAILED));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // |main_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(0);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  if (alt_job_retried_on_non_default_network) {
    // Set the alt job as if it failed on the default network and is retried on
    // the alternate network.
    JobControllerPeer::SetAltJobFailedOnDefaultNetwork(job_controller_);
  }

  // Make |alternative_job| succeed.
  auto http_stream = std::make_unique<HttpBasicStream>(
      std::make_unique<ClientSocketHandle>(), false);
  if (async_quic_session) {
    base::RunLoop run_loop;
    EXPECT_CALL(*job_factory_.main_job(), Resume())
        .Times(1)
        .WillOnce([&run_loop, this]() {
          run_loop.Quit();
          job_factory_.main_job()->DoResume();
        });
    run_loop.Run();
  }
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, http_stream.get()));

  HttpStreamFactoryJobPeer::SetStream(job_factory_.alternative_job(),
                                      std::move(http_stream));
  job_controller_->OnStreamReady(job_factory_.alternative_job());
  base::RunLoop().RunUntilIdle();
  // |alternative_job| succeeds and should report status to Request.
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// This test verifies that the alternative service is not mark broken if the
// alternative job succeeds on the default network after the main job failed.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsOnDefaultNetworkAfterMainJobFailed) {
  TestAltJobSucceedsAfterMainJobFailed(false, false);
}

// This test verifies that the alternative service is not mark broken if the
// alternative job succeeds on the alternate network after the main job failed.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsOnAlternateNetworkAfterMainJobFailed) {
  TestAltJobSucceedsAfterMainJobFailed(true, false);
}

// This test verifies that the alternative service is not mark broken if the
// alternative job succeeds on the default network after the main job failed.
// This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsOnDefaultNetworkAfterMainJobFailedAsyncQuicSession) {
  TestAltJobSucceedsAfterMainJobFailed(false, true);
}

// This test verifies that the alternative service is not mark broken if the
// alternative job succeeds on the alternate network after the main job failed.
// This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsOnAlternateNetworkAfterMainJobFailedAsyncQuicSession) {
  TestAltJobSucceedsAfterMainJobFailed(true, true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestAltJobSucceedsAfterMainJobSucceeded(
        bool alt_job_retried_on_non_default_network,
        bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  // Use cold start and complete alt job manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // |main_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(0);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  if (async_quic_session) {
    EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1).WillOnce([this]() {
      job_factory_.main_job()->DoResume();
    });
  }

  // Run the message loop to make |main_job| succeed and status will be
  // reported to Request.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));
  base::RunLoop().RunUntilIdle();
  VerifyBrokenAlternateProtocolMapping(request_info, false);

  if (alt_job_retried_on_non_default_network) {
    // Set the alt job as if it failed on the default network and is retired on
    // the alternate network.
    JobControllerPeer::SetAltJobFailedOnDefaultNetwork(job_controller_);
  }

  // Make |alternative_job| succeed.
  auto http_stream = std::make_unique<HttpBasicStream>(
      std::make_unique<ClientSocketHandle>(), false);

  HttpStreamFactoryJobPeer::SetStream(job_factory_.alternative_job(),
                                      std::move(http_stream));
  job_controller_->OnStreamReady(job_factory_.alternative_job());

  request_.reset();
  // If alt job was retried on the alternate network, the alternative service
  // should be marked broken until the default network changes.
  VerifyBrokenAlternateProtocolMapping(request_info,
                                       alt_job_retried_on_non_default_network);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  if (alt_job_retried_on_non_default_network) {
    // Verify the brokenness is cleared when the default network changes.
    session_->http_server_properties()->OnDefaultNetworkChanged();
    VerifyBrokenAlternateProtocolMapping(request_info, false);
  }
}

// This test verifies that the alternative service is not marked broken if the
// alternative job succeeds on the default network after the main job succeeded.
TEST_P(HttpStreamFactoryJobControllerTest,
```