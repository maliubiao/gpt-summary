Response:
The user wants to understand the functionality of the provided C++ code snippet from `url_request_unittest.cc`. This is part 8 of 17, so I need to summarize the functionalities covered in this specific part. I also need to look for connections to Javascript, logical reasoning with input/output examples, common user/programming errors, and how a user might reach this code.

**Plan:**

1. **Analyze each test case:** Go through each `TEST_F` and determine the specific functionality it's testing.
2. **Summarize the functionalities:** Combine the functionalities of the individual test cases into a concise summary for part 8.
3. **Javascript Relationship:**  Look for any tests that implicitly or explicitly relate to how web requests are handled in a browser context (which often involves Javascript).
4. **Logical Reasoning (Input/Output):** Identify tests where the logic can be described with clear inputs and expected outputs.
5. **Common Errors:** Pinpoint tests that demonstrate potential mistakes users or developers might make when using the URLRequest API.
6. **User Journey (Debugging):** Think about the sequence of user actions that could lead to this code being executed during debugging.
```c++
ed_count());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, CancelOnDataReceived) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    d.set_cancel_in_received_data(true);

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_NE(0, d.received_bytes_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, CancelDuringEofRead) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    // This returns an empty response (With headers).
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    d.set_cancel_in_received_data(true);

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(0, d.received_bytes_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, CancelByDestroyingAfterStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    // The request will be implicitly canceled when it is destroyed. The
    // test delegate must not post a quit message when this happens because
    // this test doesn't actually have a message loop. The quit message would
    // get put on this thread's message queue and the next test would exit
    // early, causing problems.
    d.set_on_complete(base::DoNothing());
  }
  // expect things to just cleanup properly.

  // we won't actually get a received response here because we've never run the
  // message loop
  EXPECT_FALSE(d.received_data_before_response());
  EXPECT_EQ(0, d.bytes_received());
}

TEST_F(URLRequestTestHTTP, CancelWhileReadingFromCache) {
  ASSERT_TRUE(http_test_server()->Start());

  // populate cache
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/cachetime"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    d.RunUntilComplete();
    EXPECT_EQ(OK, d.request_status());
  }

  // cancel read from cache (see bug 990242)
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/cachetime"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    r->Cancel();
    d.RunUntilComplete();

    EXPECT_EQ(ERR_ABORTED, d.request_status());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_FALSE(d.received_data_before_response());
  }
}

TEST_F(URLRequestTestHTTP, PostTest) {
  ASSERT_TRUE(http_test_server()->Start());
  HTTPUploadDataOperationTest("POST");
}

TEST_F(URLRequestTestHTTP, PutTest) {
  ASSERT_TRUE(http_test_server()->Start());
  HTTPUploadDataOperationTest("PUT");
}

TEST_F(URLRequestTestHTTP, PostEmptyTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    ASSERT_EQ(1, d.response_started_count())
        << "request failed. Error: " << d.request_status();

    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_TRUE(d.data_received().empty());
  }
}

TEST_F(URLRequestTestHTTP, PostFileTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");

    base::FilePath dir;
    base::PathService::Get(base::DIR_EXE, &dir);
    base::SetCurrentDirectory(dir);

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;

    base::FilePath path;
    base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
    path = path.Append(kTestFilePath);
    path = path.Append(FILE_PATH_LITERAL("with-headers.html"));
    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(), path, 0,
        std::numeric_limits<uint64_t>::max(), base::Time()));
    r->set_upload(std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    std::optional<int64_t> size64 = base::GetFileSize(path);
    ASSERT_TRUE(size64.has_value());
    ASSERT_LE(size64.value(), std::numeric_limits<int>::max());
    int size = static_cast<int>(size64.value());
    auto buf = std::make_unique<char[]>(size);

    ASSERT_EQ(size, base::ReadFile(path, buf.get(), size));

    ASSERT_EQ(1, d.response_started_count())
        << "request failed. Error: " << d.request_status();

    EXPECT_FALSE(d.received_data_before_response());

    EXPECT_EQ(size, d.bytes_received());
    EXPECT_EQ(std::string(&buf[0], size), d.data_received());
  }
}

TEST_F(URLRequestTestHTTP, PostUnreadableFileTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;

    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(),
        base::FilePath(FILE_PATH_LITERAL(
            "c:\\path\\to\\non\\existant\\file.randomness.12345")),
        0, std::numeric_limits<uint64_t>::max(), base::Time()));
    r->set_upload(std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_TRUE(d.request_failed());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_EQ(ERR_FILE_NOT_FOUND, d.request_status());
  }
}

namespace {

// Adds a standard set of data to an upload for chunked upload integration
// tests.
void AddDataToUpload(ChunkedUploadDataStream::Writer* writer) {
  const auto append = [writer](std::string_view str, bool is_done) {
    writer->AppendData(base::as_byte_span(str), is_done);
  };
  append("a", false);
  append("bcd", false);
  append("this is a longer chunk than before.", false);
  append("\r\n\r\n", false);
  append("0", false);
  append("2323", true);
}

// Checks that the upload data added in AddChunksToUpload() was echoed back from
// the server.
void VerifyReceivedDataMatchesChunks(URLRequest* r, TestDelegate* d) {
  // This should match the chunks sent by AddChunksToUpload().
  const std::string expected_data =
      "abcdthis is a longer chunk than before.\r\n\r\n02323";

  ASSERT_EQ(1, d->response_started_count())
      << "request failed. Error: " << d->request_status();

  EXPECT_FALSE(d->received_data_before_response());

  EXPECT_EQ(expected_data.size(), static_cast<size_t>(d->bytes_received()));
  EXPECT_EQ(expected_data, d->data_received());
}

}  // namespace

TEST_F(URLRequestTestHTTP, TestPostChunkedDataBeforeStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    auto upload_data_stream = std::make_unique<ChunkedUploadDataStream>(0);
    std::unique_ptr<ChunkedUploadDataStream::Writer> writer =
        upload_data_stream->CreateWriter();
    r->set_upload(std::move(upload_data_stream));
    r->set_method("POST");
    AddDataToUpload(writer.get());
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    VerifyReceivedDataMatchesChunks(r.get(), &d);
  }
}

TEST_F(URLRequestTestHTTP, TestPostChunkedDataJustAfterStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    auto upload_data_stream = std::make_unique<ChunkedUploadDataStream>(0);
    std::unique_ptr<ChunkedUploadDataStream::Writer> writer =
        upload_data_stream->CreateWriter();
    r->set_upload(std::move(upload_data_stream));
    r->set_method("POST");
    r->Start();
    EXPECT_TRUE(r->is_pending());
    AddDataToUpload(writer.get());
    d.RunUntilComplete();

    VerifyReceivedDataMatchesChunks(r.get(), &d);
  }
}

TEST_F(URLRequestTestHTTP, TestPostChunkedDataAfterStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    auto upload_data_stream = std::make_unique<ChunkedUploadDataStream>(0);
    std::unique_ptr<ChunkedUploadDataStream::Writer> writer =
        upload_data_stream->CreateWriter();
    r->set_upload(std::move(upload_data_stream));
    r->set_method("POST");
    r->Start();
    EXPECT_TRUE(r->is_pending());

    // Pump messages until we start sending headers..
    base::RunLoop().RunUntilIdle();

    // And now wait for completion.
    base::RunLoop run_loop;
    d.set_on_complete(run_loop.QuitClosure());
    AddDataToUpload(writer.get());
    run_loop.Run();

    VerifyReceivedDataMatchesChunks(r.get(), &d);
  }
}

TEST_F(URLRequestTestHTTP, ResponseHeadersTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/with-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  const HttpResponseHeaders* headers = req->response_headers();

  // Simple sanity check that response_info() accesses the same data.
  EXPECT_EQ(headers, req->response_info().headers.get());

  EXPECT_EQ(headers->GetNormalizedHeader("cache-control"), "private");

  EXPECT_EQ(headers->GetNormalizedHeader("content-type"),
            "text/html; charset=ISO-8859-1");

  // The response has two "X-Multiple-Entries" headers.
  // This verifies our output has them concatenated together.
  EXPECT_EQ(headers->GetNormalizedHeader("x-multiple-entries"), "a, b");
}

// TODO(svaldez): iOS tests are flaky with EmbeddedTestServer and transport
// security state. (see http://crbug.com/550977).
#if !BUILDFLAG(IS_IOS)
TEST_F(URLRequestTestHTTP, ProcessSTS) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  std::string test_server_hostname = "a.test";
  https_test_server.SetCertHostnames({test_server_hostname});
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule(test_server_hostname,
                                  https_test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();
  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      https_test_server.GetURL(test_server_hostname, "/hsts-headers.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  TransportSecurityState* security_state = context->transport_security_state();
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;
  EXPECT_TRUE(
      security_state->GetDynamicSTSState(test_server_hostname, &sts_state));
  EXPECT_FALSE(
      security_state->GetDynamicPKPState(test_server_hostname, &pkp_state));
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_FALSE(pkp_state.include_subdomains);
#if BUILDFLAG(IS_ANDROID)
  // Android's CertVerifyProc does not (yet) handle pins.
#else
  EXPECT_FALSE(pkp_state.HasPublicKeyPins());
#endif
}

TEST_F(URLRequestTestHTTP, STSNotProcessedOnIP) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  // Make sure this test fails if the test server is changed to not
  // listen on an IP by default.
  ASSERT_TRUE(https_test_server.GetURL("/").HostIsIPAddress());
  std::string test_server_hostname = https_test_server.GetURL("/").host();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(default_context().CreateRequest(
      https_test_server.GetURL("/hsts-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();
  TransportSecurityState* security_state =
      default_context().transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_FALSE(
      security_state->GetDynamicSTSState(test_server_hostname, &sts_state));
}

TEST_F(URLRequestTestHTTP, STSNotProcessedOnLocalhost) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kIgnoreHSTSForLocalhost);
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  // Make sure this test fails if the test server is changed to not
  // use `localhost` as the hostname for CERT_COMMON_NAME_IS_DOMAIN.
  ASSERT_TRUE(net::IsLocalHostname(https_test_server.GetURL("/").host()));

  TestDelegate d;
  std::unique_ptr<URLRequest> request(default_context().CreateRequest(
      https_test_server.GetURL("/hsts-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();
  TransportSecurityState* security_state =
      default_context().transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_FALSE(security_state->GetDynamicSTSState("localhost", &sts_state));
}

TEST_F(URLRequestTestHTTP, STSProcessedOnLocalhostWhenFeatureDisabled) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndDisableFeature(
      net::features::kIgnoreHSTSForLocalhost);
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  // Make sure this test fails if the test server is changed to not
  // use `localhost` as the hostname for CERT_COMMON_NAME_IS_DOMAIN.
  ASSERT_TRUE(net::IsLocalHostname(https_test_server.GetURL("/").host()));

  TestDelegate d;
  std::unique_ptr<URLRequest> request(default_context().CreateRequest(
      https_test_server.GetURL("/hsts-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();
  TransportSecurityState* security_state =
      default_context().transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_TRUE(security_state->GetDynamicSTSState("localhost", &sts_state));
}

TEST_F(URLRequestTestHTTP, PKPBypassRecorded) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());

  // Set up a MockCertVerifier to be a local root that violates the pin
  scoped_refptr<X509Certificate> cert = https_test_server.GetCertificate();
  ASSERT_TRUE(cert);

  CertVerifyResult verify_result;
  verify_result.verified_cert = cert;
  verify_result.is_issued_by_known_root = false;
  HashValue hash;
  ASSERT_TRUE(
      hash.FromString("sha256/1111111111111111111111111111111111111111111="));
  verify_result.public_key_hashes.push_back(hash);
  auto cert_verifier = std::make_unique<MockCertVerifier>();
  cert_verifier->AddResultForCert(cert.get(), verify_result, OK);

  std::string test_server_hostname = "www.example.org";

  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCertVerifier(std::move(cert_verifier));
  auto context = context_builder->Build();
  context->transport_security_state()->EnableStaticPinsForTesting();
  context->transport_security_state()->SetPinningListAlwaysTimelyForTesting(
      true);

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      https_test_server.GetURL(test_server_hostname, "/simple.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->set_isolation_info(IsolationInfo::CreateTransient());
  request->Start();
  d.RunUntilComplete();

  // Check that the request succeeded and that PKP was bypassed.
  EXPECT_EQ(OK, d.request_status());
  TransportSecurityState::PKPState pkp_state;
  EXPECT_TRUE(context->transport_security_state()->GetStaticPKPState(
      test_server_hostname, &pkp_state));
  EXPECT_TRUE(pkp_state.HasPublicKeyPins());
  EXPECT_TRUE(request->ssl_info().pkp_bypassed);
}

TEST_F(URLRequestTestHTTP, ProcessSTSOnce) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  std::string test_server_hostname = "a.test";
  https_test_server.SetCertHostnames({test_server_hostname});
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule(test_server_hostname,
                                  https_test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      https_test_server.GetURL(test_server_hostname,
                               "/hsts-multiple-headers.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  // We should have set parameters from the first header, not the second.
  TransportSecurityState* security_state = context->transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_TRUE(
      security_state->GetDynamicSTSState(test_server_hostname, &sts_state));
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_FALSE(sts_state.include_subdomains);
}

#endif  // !BUILDFLAG(IS_IOS)

#if BUILDFLAG(ENABLE_REPORTING)

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_DontReportIfNetworkNotAccessed) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_test_server);
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/cachetime");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  // Populate the cache.
  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->set_isolation_info(isolation_info1_);
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(200, error.status_code);
  EXPECT_EQ(OK, error.type);

  request = context->CreateRequest(request_url, DEFAULT_PRIORITY, &d,
                                   TRAFFIC_ANNOTATION_FOR_TESTS);
  request->set_isolation_info(isolation_info1_);
  request->Start();
  d.RunUntilComplete();

  EXPECT_FALSE(request->response_info().network_accessed);
  EXPECT_TRUE(request->response_info().was_cached);
  // No additional NEL report was generated.
  EXPECT_EQ(1u, nel_service.errors().size());
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_BasicSuccess) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/simple.html");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(200, error.status_code);
  EXPECT_EQ(OK, error.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_BasicError) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_test_server);
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/close-socket");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(0, error.status_code);
  EXPECT_EQ(ERR_EMPTY_RESPONSE, error.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_Redirect) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/redirect-test.html");
  GURL redirect_url = https_test_server.GetURL("/with-headers.html");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(2u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error1 =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error1.uri);
  EXPECT_EQ(302, error1.status_code);
  EXPECT_EQ(OK, error1.type);
  const TestNetworkErrorLoggingService::RequestDetails& error2 =
      nel_service.errors()[1];
  EXPECT_EQ(redirect_url, error2.uri);
  EXPECT_EQ(200, error2.status_code);
  EXPECT_EQ(OK, error2.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_RedirectWithoutLocationHeader) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/308-without-location-header");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::
Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共17部分，请归纳一下它的功能

"""
ed_count());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, CancelOnDataReceived) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    d.set_cancel_in_received_data(true);

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_NE(0, d.received_bytes_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, CancelDuringEofRead) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    // This returns an empty response (With headers).
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    d.set_cancel_in_received_data(true);

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(0, d.received_bytes_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, CancelByDestroyingAfterStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    // The request will be implicitly canceled when it is destroyed. The
    // test delegate must not post a quit message when this happens because
    // this test doesn't actually have a message loop. The quit message would
    // get put on this thread's message queue and the next test would exit
    // early, causing problems.
    d.set_on_complete(base::DoNothing());
  }
  // expect things to just cleanup properly.

  // we won't actually get a received response here because we've never run the
  // message loop
  EXPECT_FALSE(d.received_data_before_response());
  EXPECT_EQ(0, d.bytes_received());
}

TEST_F(URLRequestTestHTTP, CancelWhileReadingFromCache) {
  ASSERT_TRUE(http_test_server()->Start());

  // populate cache
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/cachetime"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    d.RunUntilComplete();
    EXPECT_EQ(OK, d.request_status());
  }

  // cancel read from cache (see bug 990242)
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/cachetime"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    r->Cancel();
    d.RunUntilComplete();

    EXPECT_EQ(ERR_ABORTED, d.request_status());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_FALSE(d.received_data_before_response());
  }
}

TEST_F(URLRequestTestHTTP, PostTest) {
  ASSERT_TRUE(http_test_server()->Start());
  HTTPUploadDataOperationTest("POST");
}

TEST_F(URLRequestTestHTTP, PutTest) {
  ASSERT_TRUE(http_test_server()->Start());
  HTTPUploadDataOperationTest("PUT");
}

TEST_F(URLRequestTestHTTP, PostEmptyTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    ASSERT_EQ(1, d.response_started_count())
        << "request failed. Error: " << d.request_status();

    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_TRUE(d.data_received().empty());
  }
}

TEST_F(URLRequestTestHTTP, PostFileTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");

    base::FilePath dir;
    base::PathService::Get(base::DIR_EXE, &dir);
    base::SetCurrentDirectory(dir);

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;

    base::FilePath path;
    base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
    path = path.Append(kTestFilePath);
    path = path.Append(FILE_PATH_LITERAL("with-headers.html"));
    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(), path, 0,
        std::numeric_limits<uint64_t>::max(), base::Time()));
    r->set_upload(std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    std::optional<int64_t> size64 = base::GetFileSize(path);
    ASSERT_TRUE(size64.has_value());
    ASSERT_LE(size64.value(), std::numeric_limits<int>::max());
    int size = static_cast<int>(size64.value());
    auto buf = std::make_unique<char[]>(size);

    ASSERT_EQ(size, base::ReadFile(path, buf.get(), size));

    ASSERT_EQ(1, d.response_started_count())
        << "request failed. Error: " << d.request_status();

    EXPECT_FALSE(d.received_data_before_response());

    EXPECT_EQ(size, d.bytes_received());
    EXPECT_EQ(std::string(&buf[0], size), d.data_received());
  }
}

TEST_F(URLRequestTestHTTP, PostUnreadableFileTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;

    element_readers.push_back(std::make_unique<UploadFileElementReader>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(),
        base::FilePath(FILE_PATH_LITERAL(
            "c:\\path\\to\\non\\existant\\file.randomness.12345")),
        0, std::numeric_limits<uint64_t>::max(), base::Time()));
    r->set_upload(std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_TRUE(d.request_failed());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_EQ(ERR_FILE_NOT_FOUND, d.request_status());
  }
}

namespace {

// Adds a standard set of data to an upload for chunked upload integration
// tests.
void AddDataToUpload(ChunkedUploadDataStream::Writer* writer) {
  const auto append = [writer](std::string_view str, bool is_done) {
    writer->AppendData(base::as_byte_span(str), is_done);
  };
  append("a", false);
  append("bcd", false);
  append("this is a longer chunk than before.", false);
  append("\r\n\r\n", false);
  append("0", false);
  append("2323", true);
}

// Checks that the upload data added in AddChunksToUpload() was echoed back from
// the server.
void VerifyReceivedDataMatchesChunks(URLRequest* r, TestDelegate* d) {
  // This should match the chunks sent by AddChunksToUpload().
  const std::string expected_data =
      "abcdthis is a longer chunk than before.\r\n\r\n02323";

  ASSERT_EQ(1, d->response_started_count())
      << "request failed. Error: " << d->request_status();

  EXPECT_FALSE(d->received_data_before_response());

  EXPECT_EQ(expected_data.size(), static_cast<size_t>(d->bytes_received()));
  EXPECT_EQ(expected_data, d->data_received());
}

}  // namespace

TEST_F(URLRequestTestHTTP, TestPostChunkedDataBeforeStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    auto upload_data_stream = std::make_unique<ChunkedUploadDataStream>(0);
    std::unique_ptr<ChunkedUploadDataStream::Writer> writer =
        upload_data_stream->CreateWriter();
    r->set_upload(std::move(upload_data_stream));
    r->set_method("POST");
    AddDataToUpload(writer.get());
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    VerifyReceivedDataMatchesChunks(r.get(), &d);
  }
}

TEST_F(URLRequestTestHTTP, TestPostChunkedDataJustAfterStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    auto upload_data_stream = std::make_unique<ChunkedUploadDataStream>(0);
    std::unique_ptr<ChunkedUploadDataStream::Writer> writer =
        upload_data_stream->CreateWriter();
    r->set_upload(std::move(upload_data_stream));
    r->set_method("POST");
    r->Start();
    EXPECT_TRUE(r->is_pending());
    AddDataToUpload(writer.get());
    d.RunUntilComplete();

    VerifyReceivedDataMatchesChunks(r.get(), &d);
  }
}

TEST_F(URLRequestTestHTTP, TestPostChunkedDataAfterStart) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/echo"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    auto upload_data_stream = std::make_unique<ChunkedUploadDataStream>(0);
    std::unique_ptr<ChunkedUploadDataStream::Writer> writer =
        upload_data_stream->CreateWriter();
    r->set_upload(std::move(upload_data_stream));
    r->set_method("POST");
    r->Start();
    EXPECT_TRUE(r->is_pending());

    // Pump messages until we start sending headers..
    base::RunLoop().RunUntilIdle();

    // And now wait for completion.
    base::RunLoop run_loop;
    d.set_on_complete(run_loop.QuitClosure());
    AddDataToUpload(writer.get());
    run_loop.Run();

    VerifyReceivedDataMatchesChunks(r.get(), &d);
  }
}

TEST_F(URLRequestTestHTTP, ResponseHeadersTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/with-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  const HttpResponseHeaders* headers = req->response_headers();

  // Simple sanity check that response_info() accesses the same data.
  EXPECT_EQ(headers, req->response_info().headers.get());

  EXPECT_EQ(headers->GetNormalizedHeader("cache-control"), "private");

  EXPECT_EQ(headers->GetNormalizedHeader("content-type"),
            "text/html; charset=ISO-8859-1");

  // The response has two "X-Multiple-Entries" headers.
  // This verifies our output has them concatenated together.
  EXPECT_EQ(headers->GetNormalizedHeader("x-multiple-entries"), "a, b");
}

// TODO(svaldez): iOS tests are flaky with EmbeddedTestServer and transport
// security state. (see http://crbug.com/550977).
#if !BUILDFLAG(IS_IOS)
TEST_F(URLRequestTestHTTP, ProcessSTS) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  std::string test_server_hostname = "a.test";
  https_test_server.SetCertHostnames({test_server_hostname});
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule(test_server_hostname,
                                  https_test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();
  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      https_test_server.GetURL(test_server_hostname, "/hsts-headers.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  TransportSecurityState* security_state = context->transport_security_state();
  TransportSecurityState::STSState sts_state;
  TransportSecurityState::PKPState pkp_state;
  EXPECT_TRUE(
      security_state->GetDynamicSTSState(test_server_hostname, &sts_state));
  EXPECT_FALSE(
      security_state->GetDynamicPKPState(test_server_hostname, &pkp_state));
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_TRUE(sts_state.include_subdomains);
  EXPECT_FALSE(pkp_state.include_subdomains);
#if BUILDFLAG(IS_ANDROID)
  // Android's CertVerifyProc does not (yet) handle pins.
#else
  EXPECT_FALSE(pkp_state.HasPublicKeyPins());
#endif
}

TEST_F(URLRequestTestHTTP, STSNotProcessedOnIP) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  // Make sure this test fails if the test server is changed to not
  // listen on an IP by default.
  ASSERT_TRUE(https_test_server.GetURL("/").HostIsIPAddress());
  std::string test_server_hostname = https_test_server.GetURL("/").host();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(default_context().CreateRequest(
      https_test_server.GetURL("/hsts-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();
  TransportSecurityState* security_state =
      default_context().transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_FALSE(
      security_state->GetDynamicSTSState(test_server_hostname, &sts_state));
}

TEST_F(URLRequestTestHTTP, STSNotProcessedOnLocalhost) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kIgnoreHSTSForLocalhost);
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  // Make sure this test fails if the test server is changed to not
  // use `localhost` as the hostname for CERT_COMMON_NAME_IS_DOMAIN.
  ASSERT_TRUE(net::IsLocalHostname(https_test_server.GetURL("/").host()));

  TestDelegate d;
  std::unique_ptr<URLRequest> request(default_context().CreateRequest(
      https_test_server.GetURL("/hsts-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();
  TransportSecurityState* security_state =
      default_context().transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_FALSE(security_state->GetDynamicSTSState("localhost", &sts_state));
}

TEST_F(URLRequestTestHTTP, STSProcessedOnLocalhostWhenFeatureDisabled) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndDisableFeature(
      net::features::kIgnoreHSTSForLocalhost);
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  // Make sure this test fails if the test server is changed to not
  // use `localhost` as the hostname for CERT_COMMON_NAME_IS_DOMAIN.
  ASSERT_TRUE(net::IsLocalHostname(https_test_server.GetURL("/").host()));

  TestDelegate d;
  std::unique_ptr<URLRequest> request(default_context().CreateRequest(
      https_test_server.GetURL("/hsts-headers.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();
  TransportSecurityState* security_state =
      default_context().transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_TRUE(security_state->GetDynamicSTSState("localhost", &sts_state));
}

TEST_F(URLRequestTestHTTP, PKPBypassRecorded) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());

  // Set up a MockCertVerifier to be a local root that violates the pin
  scoped_refptr<X509Certificate> cert = https_test_server.GetCertificate();
  ASSERT_TRUE(cert);

  CertVerifyResult verify_result;
  verify_result.verified_cert = cert;
  verify_result.is_issued_by_known_root = false;
  HashValue hash;
  ASSERT_TRUE(
      hash.FromString("sha256/1111111111111111111111111111111111111111111="));
  verify_result.public_key_hashes.push_back(hash);
  auto cert_verifier = std::make_unique<MockCertVerifier>();
  cert_verifier->AddResultForCert(cert.get(), verify_result, OK);

  std::string test_server_hostname = "www.example.org";

  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCertVerifier(std::move(cert_verifier));
  auto context = context_builder->Build();
  context->transport_security_state()->EnableStaticPinsForTesting();
  context->transport_security_state()->SetPinningListAlwaysTimelyForTesting(
      true);

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      https_test_server.GetURL(test_server_hostname, "/simple.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->set_isolation_info(IsolationInfo::CreateTransient());
  request->Start();
  d.RunUntilComplete();

  // Check that the request succeeded and that PKP was bypassed.
  EXPECT_EQ(OK, d.request_status());
  TransportSecurityState::PKPState pkp_state;
  EXPECT_TRUE(context->transport_security_state()->GetStaticPKPState(
      test_server_hostname, &pkp_state));
  EXPECT_TRUE(pkp_state.HasPublicKeyPins());
  EXPECT_TRUE(request->ssl_info().pkp_bypassed);
}

TEST_F(URLRequestTestHTTP, ProcessSTSOnce) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  std::string test_server_hostname = "a.test";
  https_test_server.SetCertHostnames({test_server_hostname});
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule(test_server_hostname,
                                  https_test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      https_test_server.GetURL(test_server_hostname,
                               "/hsts-multiple-headers.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  // We should have set parameters from the first header, not the second.
  TransportSecurityState* security_state = context->transport_security_state();
  TransportSecurityState::STSState sts_state;
  EXPECT_TRUE(
      security_state->GetDynamicSTSState(test_server_hostname, &sts_state));
  EXPECT_EQ(TransportSecurityState::STSState::MODE_FORCE_HTTPS,
            sts_state.upgrade_mode);
  EXPECT_FALSE(sts_state.include_subdomains);
  EXPECT_FALSE(sts_state.include_subdomains);
}

#endif  // !BUILDFLAG(IS_IOS)

#if BUILDFLAG(ENABLE_REPORTING)

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_DontReportIfNetworkNotAccessed) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_test_server);
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/cachetime");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  // Populate the cache.
  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->set_isolation_info(isolation_info1_);
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(200, error.status_code);
  EXPECT_EQ(OK, error.type);

  request = context->CreateRequest(request_url, DEFAULT_PRIORITY, &d,
                                   TRAFFIC_ANNOTATION_FOR_TESTS);
  request->set_isolation_info(isolation_info1_);
  request->Start();
  d.RunUntilComplete();

  EXPECT_FALSE(request->response_info().network_accessed);
  EXPECT_TRUE(request->response_info().was_cached);
  // No additional NEL report was generated.
  EXPECT_EQ(1u, nel_service.errors().size());
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_BasicSuccess) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/simple.html");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(200, error.status_code);
  EXPECT_EQ(OK, error.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_BasicError) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_test_server);
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/close-socket");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(0, error.status_code);
  EXPECT_EQ(ERR_EMPTY_RESPONSE, error.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_Redirect) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/redirect-test.html");
  GURL redirect_url = https_test_server.GetURL("/with-headers.html");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(2u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error1 =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error1.uri);
  EXPECT_EQ(302, error1.status_code);
  EXPECT_EQ(OK, error1.type);
  const TestNetworkErrorLoggingService::RequestDetails& error2 =
      nel_service.errors()[1];
  EXPECT_EQ(redirect_url, error2.uri);
  EXPECT_EQ(200, error2.status_code);
  EXPECT_EQ(OK, error2.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_RedirectWithoutLocationHeader) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/308-without-location-header");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(308, error.status_code);
  // The body of the response was successfully read.
  EXPECT_EQ(OK, error.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_Auth) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_test_server);
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/auth-basic");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  d.set_credentials(AuthCredentials(kUser, kSecret));
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(2u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error1 =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error1.uri);
  EXPECT_EQ(401, error1.status_code);
  EXPECT_EQ(OK, error1.type);
  const TestNetworkErrorLoggingService::RequestDetails& error2 =
      nel_service.errors()[1];
  EXPECT_EQ(request_url, error2.uri);
  EXPECT_EQ(200, error2.status_code);
  EXPECT_EQ(OK, error2.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_304Response) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_test_server);
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/auth-basic");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  // populate the cache
  {
    TestDelegate d;
    d.set_credentials(AuthCredentials(kUser, kSecret));
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_isolation_info(isolation_info1_);
    r->Start();
    d.RunUntilComplete();
  }
  ASSERT_EQ(2u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error1 =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error1.uri);
  EXPECT_EQ(401, error1.status_code);
  EXPECT_EQ(OK, error1.type);
  const TestNetworkErrorLoggingService::RequestDetails& error2 =
      nel_service.errors()[1];
  EXPECT_EQ(request_url, error2.uri);
  EXPECT_EQ(200, error2.status_code);
  EXPECT_EQ(OK, error2.type);

  // repeat request with end-to-end validation.  since auth-basic results in a
  // cachable page, we expect this test to result in a 304.  in which case, the
  // response should be fetched from the cache.
  {
    TestDelegate d;
    d.set_credentials(AuthCredentials(kUser, kSecret));
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->SetLoadFlags(LOAD_VALIDATE_CACHE);
    r->set_isolation_info(isolation_info1_);
    r->Start();
    d.RunUntilComplete();

    // Should be the same cached document.
    EXPECT_TRUE(r->was_cached());
  }
  ASSERT_EQ(3u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error3 =
      nel_service.errors()[2];
  EXPECT_EQ(request_url, error3.uri);
  EXPECT_EQ(304, error3.status_code);
  EXPECT_EQ(OK, error3.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_CancelInResponseStarted) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/simple.html");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  d.set_cancel_in_response_started(true);
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(200, error.status_code);
  // Headers were received and the body should have been read but was not.
  EXPECT_EQ(ERR_ABORTED, error.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_CancelOnDataReceived) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath));
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/simple.html");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  d.set_cancel_in_received_data(true);
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(200, error.status_code);
  // Data was received but the body was not completely read.
  EXPECT_EQ(ERR_ABORTED, error.type);
}

TEST_F(URLRequestTestHTTP, NetworkErrorLogging_CancelRedirect) {
  EmbeddedTestServer https_test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  https_test_server.ServeFilesFromSourceDirectory(
      base::FilePath(kTestFilePath)
"""


```