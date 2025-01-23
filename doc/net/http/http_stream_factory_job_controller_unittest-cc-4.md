Response:
The user wants a summary of the provided C++ code file, focusing on its functionality within the Chromium network stack. Specifically, I need to:

1. **Describe the file's function:** What does this code do?
2. **Relate to JavaScript (if applicable):** Does this code interact with JavaScript? If so, how? Provide examples.
3. **Logical Reasoning (with examples):** Are there conditional logic flows?  Provide example inputs and expected outputs.
4. **Common Usage Errors:** What mistakes could developers make when using or interacting with this code?
5. **User Operation to Reach Here:**  How does a user's action in the browser lead to this code being executed?
6. **Overall Function (Summary):** Condense the purpose of the code.
7. **Part of a Whole:** Acknowledge that this is part 5 of 9.

Let's break down the code snippets to understand its purpose:

- The code defines a series of test cases within a C++ testing framework (likely Google Test).
- The tests are named `TEST_P(HttpStreamFactoryJobControllerTest, ...)` which suggests they are parameterized tests for a class named `HttpStreamFactoryJobControllerTest`.
- The test names and the helper function names (like `TestAltJobSucceedsAfterMainJobSucceeded`, `TestMainJobSucceedsAfterAltJobSucceeded`, etc.) clearly indicate the focus is on the interaction between a "main job" and an "alternative job" in the context of HTTP stream creation.
- The tests seem to cover scenarios where the main job and the alternative job succeed or fail in different orders and on different networks (default vs. alternate).
- The code also seems to handle cases involving QUIC (Quick UDP Internet Connections) as an alternative protocol, potentially with asynchronous session creation.
- There are checks for whether alternative services are marked as "broken" based on the outcomes of these jobs, and whether this "brokenness" is cleared under certain conditions (like network changes).
- Mocking frameworks are used (e.g., `MockQuicData`, `SequencedSocketData`, `MockConnect`, `MockCryptoClientStream`), which is standard practice for unit testing network components.
- The tests verify behavior using assertions like `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_CALL`.
- Histograms are used to track events (e.g., "Net.AlternateServiceFailed").
- There's a concept of "delayed TCP" and the code appears to test scenarios where the main job might be delayed based on past network performance.

**High-Level Understanding:** This code tests the logic within `HttpStreamFactoryJobController` regarding how it manages attempts to establish HTTP connections, including trying alternative protocols like QUIC. It focuses on the scenarios where a main connection attempt (likely TCP) is paired with an alternative connection attempt, and how the controller reacts to the success or failure of each. The tests also explore how the controller handles network changes and remembers whether an alternative service has previously failed.

**Relationship to JavaScript:** While this C++ code doesn't directly execute JavaScript, the decisions made here can impact the user experience in a web browser, which heavily relies on JavaScript. For example, if an alternative protocol like QUIC is marked as broken, the browser might not attempt to use it for subsequent requests from JavaScript, potentially affecting page load times.

**Logical Reasoning:** The tests explore various combinations of success and failure. For instance:

* **Input (Hypothetical Test):** Main TCP connection succeeds first.
* **Output:** Alternative QUIC connection is not attempted or its outcome doesn't negatively impact future QUIC attempts.

* **Input:** Main TCP connection fails, alternative QUIC connection succeeds.
* **Output:** Connection proceeds successfully using QUIC. The test checks if the alternative service is correctly marked as potentially broken on the *default* network if it succeeded on a non-default network after a failure on the default.

**Common Usage Errors (from a developer's perspective writing similar code):**

* **Incorrectly simulating network conditions:**  Not accurately mocking the success/failure codes of network operations.
* **Missing asynchronous behavior:** Not properly handling asynchronous operations, leading to race conditions in tests.
* **Incorrectly asserting outcomes:**  Asserting the wrong state or behavior based on the test scenario.
* **Not accounting for network changes:** Failing to test how the system reacts to network connectivity changes.

**User Operation to Reach Here:**

1. **User types a URL (e.g., `https://www.google.com`) in the browser address bar and presses Enter.**
2. **The browser's network stack starts the process of fetching the resource.**
3. **`HttpStreamFactory` is responsible for creating HTTP streams.**
4. **`HttpStreamFactoryJobController` is involved in managing the attempts to establish a connection, potentially trying multiple protocols (like TCP and QUIC) in parallel or sequentially.**
5. **The specific logic being tested here determines how the `HttpStreamFactoryJobController` reacts to the success or failure of these connection attempts and whether to mark alternative protocols as broken.**

**Summary of Function:**

This section of the `HttpStreamFactoryJobControllerTest` focuses on testing the logic that governs how the controller manages main (likely TCP) and alternative (like QUIC) connection attempts. It verifies how the controller handles success and failure scenarios for both types of connections, and how it tracks the "broken" status of alternative protocols, particularly in the context of network changes.

**Part of a Whole:**

This is part 5 of a 9-part series of tests for `HttpStreamFactoryJobController`, indicating that this component's functionality
### 提示词
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
AltJobSucceedsOnDefaultNetworkAfterMainJobSucceeded) {
  TestAltJobSucceedsAfterMainJobSucceeded(false, false);
}

// This test verifies that the alternative service is marked broken until the
// default network changes if the alternative job succeeds on the non-default
// network, which failed on the default network previously, after the main job
// succeeded.  The brokenness should be cleared when the default network
// changes.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsOnAlternateNetworkAfterMainJobSucceeded) {
  TestAltJobSucceedsAfterMainJobSucceeded(true, false);
}

// This test verifies that the alternative service is not marked broken if the
// alternative job succeeds on the default network after the main job succeeded.
// This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsOnDefaultNetworkAfterMainJobSucceededAsyncQuicSession) {
  TestAltJobSucceedsAfterMainJobSucceeded(false, true);
}

// This test verifies that the alternative service is marked broken until the
// default network changes if the alternative job succeeds on the non-default
// network, which failed on the default network previously, after the main job
// succeeded.  The brokenness should be cleared when the default network
// changes. This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       AltJobSucceedsOnAlternateNetworkAfterMainJobSucceededAsyncQuicSession) {
  TestAltJobSucceedsAfterMainJobSucceeded(true, true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestMainJobSucceedsAfterAltJobSucceeded(
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

  // Run message loop to make the main job succeed.
  base::RunLoop().RunUntilIdle();
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
// main job succeeds after the alternative job succeeded on the default network.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobSucceededOnDefaultNetwork) {
  TestMainJobSucceedsAfterAltJobSucceeded(false, false);
}

// This test verifies that the alternative service is marked broken until the
// default network changes if the main job succeeds after the alternative job
// succeeded on the non-default network, i.e., failed on the default network
// previously.  The brokenness should be cleared when the default network
// changes.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobSucceededOnAlternateNetwork) {
  TestMainJobSucceedsAfterAltJobSucceeded(true, false);
}

// This test verifies that the alternative service is not marked broken if the
// main job succeeds after the alternative job succeeded on the default network.
// This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobSucceededOnDefaultNetworkAsyncQuicSession) {
  TestMainJobSucceedsAfterAltJobSucceeded(false, true);
}

// This test verifies that the alternative service is marked broken until the
// default network changes if the main job succeeds after the alternative job
// succeeded on the non-default network, i.e., failed on the default network
// previously.  The brokenness should be cleared when the default network
// changes. This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobSucceededOnAlternateNetworkAsyncQuicSession) {
  TestMainJobSucceedsAfterAltJobSucceeded(true, true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestMainJobFailsAfterAltJobSucceeded(
        bool alt_job_retried_on_non_default_network,
        bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  // Use cold start and complete alt job manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

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

  // Run message loop to make the main job fail.
  base::RunLoop().RunUntilIdle();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// This test verifies that the alternative service is not marked broken if the
// main job fails after the alternative job succeeded on the default network.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobFailsAfterAltJobSucceededOnDefaultNetwork) {
  TestMainJobFailsAfterAltJobSucceeded(false, false);
}

// This test verifies that the alternative service is not marked broken if the
// main job fails after the alternative job succeeded on the non-default
// network, i.e., failed on the default network previously.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobFailsAfterAltJobSucceededOnAlternateNetwork) {
  TestMainJobFailsAfterAltJobSucceeded(true, false);
}

// This test verifies that the alternative service is not marked broken if the
// main job fails after the alternative job succeeded on the default network.
// This test uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobFailsAfterAltJobSucceededOnDefaultNetworkAsyncQuicSession) {
  TestMainJobFailsAfterAltJobSucceeded(false, true);
}

// This test verifies that the alternative service is not marked broken if the
// main job fails after the alternative job succeeded on the non-default
// network, i.e., failed on the default network previously. This test uses
// asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobFailsAfterAltJobSucceededOnAlternateNetworkAsyncQuicSession) {
  TestMainJobFailsAfterAltJobSucceeded(true, true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestMainJobSucceedsAfterAltJobFailed(
        bool alt_job_retried_on_non_default_network,
        bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddConnect(SYNCHRONOUS, ERR_FAILED);

  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  base::HistogramTester histogram_tester;
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

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(0);
  if (async_quic_session) {
    EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1).WillOnce([this]() {
      job_factory_.main_job()->DoResume();
    });
  }
  // |main_job| succeeds and should report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));

  if (alt_job_retried_on_non_default_network) {
    // Set the alt job as if it failed on the default network and is retired on
    // the alternate network.
    JobControllerPeer::SetAltJobFailedOnDefaultNetwork(job_controller_);
  }

  base::RunLoop().RunUntilIdle();

  request_.reset();
  // Verify that the alternate protocol is marked as broken.
  VerifyBrokenAlternateProtocolMapping(request_info, true);
  histogram_tester.ExpectUniqueSample("Net.AlternateServiceFailed", -ERR_FAILED,
                                      1);
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
  // Verify the brokenness is not cleared when the default network changes.
  session_->http_server_properties()->OnDefaultNetworkChanged();
  VerifyBrokenAlternateProtocolMapping(request_info, true);
}

// This test verifies that the alternative service will be marked broken when
// the alternative job fails on the default network and main job succeeds later.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobFailedOnDefaultNetwork) {
  TestMainJobSucceedsAfterAltJobFailed(false, false);
}

// This test verifies that the alternative service will be marked broken when
// the alternative job fails on both default and alternate networks and main job
// succeeds later.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobFailedOnBothNetworks) {
  TestMainJobSucceedsAfterAltJobFailed(true, false);
}

// This test verifies that the alternative service will be marked broken when
// the alternative job fails on the default network and main job succeeds later.
// This test uses asynchronous Quic session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobFailedOnDefaultNetworkAsyncQuicSession) {
  TestMainJobSucceedsAfterAltJobFailed(false, true);
}

// This test verifies that the alternative service will be marked broken when
// the alternative job fails on both default and alternate networks and main job
// succeeds later. This test uses asynchronous Quic session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterAltJobFailedOnBothNetworksAsyncQuicSession) {
  TestMainJobSucceedsAfterAltJobFailed(true, true);
}

void HttpStreamFactoryJobControllerTestBase::
    TestMainJobSucceedsAfterIgnoredError(int net_error,
                                         bool async_quic_session,
                                         bool expect_broken,
                                         std::string alternate_host) {
  SetAsyncQuicSession(async_quic_session);
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddConnect(SYNCHRONOUS, net_error);
  tcp_data_ = std::make_unique<SequencedSocketData>();
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  base::HistogramTester histogram_tester;

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  if (alternate_host.empty()) {
    alternate_host = server.host();
  }
  AlternativeService alternative_service(kProtoQUIC, alternate_host, 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(0);
  if (async_quic_session) {
    EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1).WillOnce([this]() {
      job_factory_.main_job()->DoResume();
    });
  }
  // |main_job| succeeds and should report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));
  base::RunLoop().RunUntilIdle();
  request_.reset();

  // Verify that the alternate protocol is not marked as broken.
  VerifyBrokenAlternateProtocolMapping(request_info, expect_broken);
  if (expect_broken) {
    histogram_tester.ExpectUniqueSample("Net.AlternateServiceFailed",
                                        -net_error, 1);
  }
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// Verifies that if the alternative job fails due to a connection change event,
// then the alternative service is not marked as broken.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterConnectionChanged) {
  TestMainJobSucceedsAfterIgnoredError(ERR_NETWORK_CHANGED, false);
}

// Verifies that if the alternative job fails due to a disconnected network,
// then the alternative service is not marked as broken.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterInternetDisconnected) {
  TestMainJobSucceedsAfterIgnoredError(ERR_INTERNET_DISCONNECTED, false);
}

// Verifies that if the alternative job fails due to a connection change event,
// then the alternative service is not marked as broken. This test uses
// asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterConnectionChangedAsyncQuicSession) {
  TestMainJobSucceedsAfterIgnoredError(ERR_NETWORK_CHANGED, true);
}

// Verifies that if the alternative job fails due to a disconnected network,
// then the alternative service is not marked as broken. This test uses
// asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterInternetDisconnectedAsyncQuicSession) {
  TestMainJobSucceedsAfterIgnoredError(ERR_INTERNET_DISCONNECTED, true);
}

// Verifies that if the alternative job fails due to a DNS failure,
// then the alternative service is not marked as broken.
TEST_P(HttpStreamFactoryJobControllerTest, MainJobSucceedsAfterDnsFailure) {
  TestMainJobSucceedsAfterIgnoredError(ERR_NAME_NOT_RESOLVED, false);
}

// Verifies that if the alternative job fails due to a DNS failure,
// then the alternative service is not marked as broken. This test uses
// asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterDnsFailureAsyncQuicSession) {
  TestMainJobSucceedsAfterIgnoredError(ERR_NAME_NOT_RESOLVED, true);
}

// Verifies that if the alternative job fails due to a DNS failure on a
// different name, then the alternative service is marked as broken.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterDnsFailureWithAlternateName) {
  TestMainJobSucceedsAfterIgnoredError(ERR_NAME_NOT_RESOLVED, false, true,
                                       "alternate.google.com");
}

// Verifies that if the alternative job fails due to a DNS failure on a
// different name, then the alternative service is marked as broken. This test
// uses asynchronous QUIC session creation.
TEST_P(HttpStreamFactoryJobControllerTest,
       MainJobSucceedsAfterDnsFailureWithAlternateNameAsyncQuicSession) {
  TestMainJobSucceedsAfterIgnoredError(ERR_NAME_NOT_RESOLVED, true, true,
                                       "alternate.google.com");
}

// Regression test for crbug/621069.
// Get load state after main job fails and before alternative job succeeds.
TEST_P(HttpStreamFactoryJobControllerTest, GetLoadStateAfterMainJobFailed) {
  // Use COLD_START to complete alt job manually.
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

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

  // |main_job| fails but should not report status to Request.
  // The alternative job will mark the main job complete.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(0);

  base::RunLoop().RunUntilIdle();

  // Controller should use alternative job to get load state.
  job_controller_->GetLoadState();

  // |alternative_job| succeeds and should report status to Request.
  auto http_stream = std::make_unique<HttpBasicStream>(
      std::make_unique<ClientSocketHandle>(), false);
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, http_stream.get()));

  HttpStreamFactoryJobPeer::SetStream(job_factory_.alternative_job(),
                                      std::move(http_stream));
  job_controller_->OnStreamReady(job_factory_.alternative_job());

  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

void HttpStreamFactoryJobControllerTestBase::TestResumeMainJobWhenAltJobStalls(
    bool async_quic_session) {
  SetAsyncQuicSession(async_quic_session);
  // Use COLD_START to stall alt job.
  quic_data_ = std::make_unique<MockQuicData>(version_);
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
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
  // Alt job is stalled and main job should complete successfully.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _));

  base::RunLoop().RunUntilIdle();
}

TEST_P(HttpStreamFactoryJobControllerTest, ResumeMainJobWhenAltJobStalls) {
  TestResumeMainJobWhenAltJobStalls(false);
}

TEST_P(HttpStreamFactoryJobControllerTest,
       ResumeMainJobWhenAltJobStallsAsyncQuicSession) {
  TestResumeMainJobWhenAltJobStalls(true);
}

TEST_P(HttpStreamFactoryJobControllerTest, InvalidPortForQuic) {
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  // Using a restricted port 101 for QUIC should fail and the alternative job
  // should post OnStreamFailedCall on the controller to resume the main job.
  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 101);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_factory_.main_job()->is_waiting());

  // Wait until OnStreamFailedCallback is executed on the alternative job.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  base::RunLoop().RunUntilIdle();
}

// Verifies that the main job is not resumed until after the alt job completes
// host resolution.
TEST_P(HttpStreamFactoryJobControllerTest, HostResolutionHang) {
  auto hanging_resolver = std::make_unique<MockHostResolver>();
  hanging_resolver->set_ondemand_mode(true);
  hanging_resolver->rules()->AddRule("www.google.com", "1.2.3.4");
  session_deps_.host_resolver = std::move(hanging_resolver);

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
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // Since the alt job has not finished host resolution, there should be no
  // delayed task posted to resume the main job.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  FastForwardBy(base::Microseconds(50));
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // Allow alt job host resolution to complete.
  session_deps_.host_resolver->ResolveAllPending();

  // Task to resume main job in 15 microseconds should be posted.
  EXPECT_NE(0u, GetPendingMainThreadTaskCount());
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  FastForwardBy(base::Microseconds(14));
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  FastForwardBy(base::Microseconds(1));

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Unpause mock quic data.
  // Will cause |alternative_job| to fail, but its failure should not be
  // reported to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _, _, _)).Times(0);
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  EXPECT_TRUE(JobControllerPeer::main_job_is_resumed(job_controller_));
  // OnStreamFailed will post a task to resume the main job immediately but
  // won't call Resume() on the main job since it's been resumed already.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  quic_data.Resume();
  FastForwardUntilNoTasksRemain();
  // Alt job should be cleaned up
  EXPECT_FALSE(job_controller_->alternative_job());
}

// Regression test for crbug.com/789560.
TEST_P(HttpStreamFactoryJobControllerTest, ResumeMainJobLaterCanceled) {
  std::unique_ptr<ConfiguredProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateDirect();
  ConfiguredProxyResolutionService* proxy_resolution_service_raw =
      proxy_resolution_service.get();
  session_deps_.proxy_resolution_service = std::move(proxy_resolution_service);

  // Using hanging resolver will cause the alternative job to hang indefinitely.
  session_deps_.alternate_host_resolver =
      std::make_unique<HangingHostResolver>();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

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

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  base::RunLoop run_loop;
  // The main job should be resumed without delay when alt job fails.
  EXPECT_CALL(*job_factory_.main_job(), Resume())
      .Times(1)
      .WillOnce(Invoke([&run_loop]() { run_loop.Quit(); }));
  job_controller_->OnStreamFailed(job_factory_.alternative_job(),
                                  ERR_QUIC_PROTOCOL_ERROR);
  FastForwardBy(base::Microseconds(0));
  run_loop.Run();
  EXPECT_FALSE(job_controller_->alternative_job());

  // Calling ForceReloadProxyConfig will cause the proxy configuration to
  // change. It will still be the direct connection but the configuration
  // version will be bumped. That is enough for the job controller to restart
  // the jobs.
  proxy_resolution_service_raw->ForceReloadProxyConfig();
  HttpStreamFactoryJobPeer::SetShouldReconsiderProxy(job_factory_.main_job());
  // Now the alt service is marked as broken (e.g. through a different request),
  // so only non-alt job is restarted.
  session_->http_server_properties()->MarkAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey());

  job_controller_->OnStreamFailed(job_factory_.main_job(), ERR_FAILED);
  // Jobs are restarted.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  // There shouldn't be any ResumeMainJobLater() delayed tasks.
  // This EXPECT_CALL will fail before crbug.com/789560 fix.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  FastForwardBy(base::Microseconds(15));

  EXPECT_TRUE(job_controller_->main_job());
  request_.reset();
}

// Test that main job is blocked for kMaxDelayTimeForMainJob(3s) if
// http_server_properties cached an inappropriate large srtt for the server,
// which would potentially delay the main job for a extremely long time in
// delayed tcp case.
TEST_P(HttpStreamFactoryJobControllerTest, DelayedTCPWithLargeSrtt) {
  // The max delay time should be in sync with .cc file.
  base::TimeDelta kMaxDelayTimeForMainJob = base::Seconds(3);

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
  stats1.srtt = base::Seconds(100);
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
  base::RunLoop().RunUntilIdle();
  // Main job is not blocked but hasn't resumed yet; it should resume in 3s.
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  EXPECT_FALSE(JobControllerPeer::
```