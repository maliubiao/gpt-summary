Response:
The user wants to understand the functionality of a specific part of the Chromium network stack, located in `net/url_request/url_request_unittest.cc`. This is part 12 of 17.

My plan is to:
1. **Identify the primary focus of the provided code snippet.** This involves scanning the test names and the setup within the tests. It seems to focus on `ReferrerPolicy` and HTTPS-related functionalities like certificate handling and HSTS.
2. **Summarize the functionality based on the identified focus.**
3. **Check for JavaScript relevance.**  Referrer policies are relevant to how browsers handle navigation initiated by JavaScript, and HSTS interacts with how JavaScript can access secure resources.
4. **Provide examples illustrating the JavaScript connection.**
5. **Construct hypothetical input/output scenarios for the tests.**
6. **Identify potential user/programming errors.** This will likely relate to incorrect configurations or misunderstandings of referrer policies or HTTPS requirements.
7. **Describe the user actions that lead to this code being executed.** This will involve web browsing actions.
8. **Since this is part 12/17, summarize the specific functionality of this part.** This will be more granular than the overall file function.
```c++
eferrer);

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPToCrossOriginHTTP) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTP,
                                net::EmbeddedTestServer::TYPE_HTTP);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPSToSameOriginHTTPS) {
  InstantiateSameOriginServers(net::EmbeddedTestServer::TYPE_HTTPS);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer);

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPSToCrossOriginHTTPS) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTPS,
                                net::EmbeddedTestServer::TYPE_HTTPS);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPToHTTPS) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTP,
                                net::EmbeddedTestServer::TYPE_HTTPS);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPSToHTTP) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTPS,
                                net::EmbeddedTestServer::TYPE_HTTP);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      GURL());

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      GURL());

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin, though it should be
  // subsequently cleared during the downgrading redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), GURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

class HTTPSRequestTest : public TestWithTaskEnvironment {
 public:
  HTTPSRequestTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    default_context_ = context_builder->Build();
  }
  ~HTTPSRequestTest() override {
    SetTransportSecurityStateSourceForTesting(nullptr);
  }

  URLRequestContext& default_context() { return *default_context_; }

 private:
  std::unique_ptr<URLRequestContext> default_context_;
};

TEST_F(HTTPSRequestTest, HTTPSGetTest) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    CheckSSLInfo(r->ssl_info());
    EXPECT_EQ(test_server.host_port_pair().host(),
              r->GetResponseRemoteEndpoint().ToStringWithoutPort());
    EXPECT_EQ(test_server.host_port_pair().port(),
              r->GetResponseRemoteEndpoint().port());
  }
}

TEST_F(HTTPSRequestTest, HTTPSMismatchedTest) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_MISMATCHED_NAME);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  bool err_allowed = true;
  for (int i = 0; i < 2; i++, err_allowed = !err_allowed) {
    TestDelegate d;
    {
      d.set_allow_certificate_errors(err_allowed);
      std::unique_ptr<URLRequest> r(default_context().CreateRequest(
          test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
          TRAFFIC_ANNOTATION_FOR_TESTS));

      r->Start();
      EXPECT_TRUE(r->is_pending());

      d.RunUntilComplete();

      EXPECT_EQ(1, d.response_started_count());
      EXPECT_FALSE(d.received_data_before_response());
      EXPECT_TRUE(d.have_certificate_errors());
      if (err_allowed) {
        EXPECT_NE(0, d.bytes_received());
        CheckSSLInfo(r->ssl_info());
      } else {
        EXPECT_EQ(0, d.bytes_received());
      }
    }
  }
}

TEST_F(HTTPSRequestTest, HTTPSExpiredTest) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  // Iterate from false to true, just so that we do the opposite of the
  // previous test in order to increase test coverage.
  bool err_allowed = false;
  for (int i = 0; i < 2; i++, err_allowed = !err_allowed) {
    TestDelegate d;
    {
      d.set_allow_certificate_errors(err_allowed);
      std::unique_ptr<URLRequest> r(default_context().CreateRequest(
          test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
          TRAFFIC_ANNOTATION_FOR_TESTS));

      r->Start();
      EXPECT_TRUE(r->is_pending());

      d.RunUntilComplete();

      EXPECT_EQ(1, d.response_started_count());
      EXPECT_FALSE(d.received_data_before_response());
      EXPECT_TRUE(d.have_certificate_errors());
      if (err_allowed) {
        EXPECT_NE(0, d.bytes_received());
        CheckSSLInfo(r->ssl_info());
      } else {
        EXPECT_EQ(0, d.bytes_received());
      }
    }
  }
}

// A TestDelegate used to test that an appropriate net error code is provided
// when an SSL certificate error occurs.
class SSLNetErrorTestDelegate : public TestDelegate {
 public:
  void OnSSLCertificateError(URLRequest* request,
                             int net_error,
                             const SSLInfo& ssl_info,
                             bool fatal) override {
    net_error_ = net_error;
    on_ssl_certificate_error_called_ = true;
    TestDelegate::OnSSLCertificateError(request, net_error, ssl_info, fatal);
  }

  bool on_ssl_certificate_error_called() {
    return on_ssl_certificate_error_called_;
  }

  int net_error() { return net_error_; }

 private:
  bool on_ssl_certificate_error_called_ = false;
  int net_error_ = net::OK;
};

// Tests that the URLRequest::Delegate receives an appropriate net error code
// when an SSL certificate error occurs.
TEST_F(HTTPSRequestTest, SSLNetErrorReportedToDelegate) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  SSLNetErrorTestDelegate d;
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  r->Start();
  EXPECT_TRUE(r->is_pending());
  d.RunUntilComplete();

  EXPECT_TRUE(d.on_ssl_certificate_error_called());
  EXPECT_EQ(net::ERR_CERT_DATE_INVALID, d.net_error());
}

// TODO(svaldez): iOS tests are flaky with EmbeddedTestServer and transport
// security state. (see http://crbug.com/550977).
#if !BUILDFLAG(IS_IOS)
// This tests that a load of a domain with preloaded HSTS and HPKP with a
// certificate error sets the |certificate_errors_are_fatal| flag correctly.
// This flag will cause the interstitial to be fatal.
TEST_F(HTTPSRequestTest, HTTPSPreloadedHSTSTest) {
  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_MISMATCHED_NAME);
  test_server.ServeFilesFromSourceDirectory("net/data/ssl");
  ASSERT_TRUE(test_server.Start());

  // We require that the URL be hsts-hpkp-preloaded.test. This is a test domain
  // that has a preloaded HSTS+HPKP entry in the TransportSecurityState. This
  // means that we have to use a MockHostResolver in order to direct
  // hsts-hpkp-preloaded.test to the testserver.

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("hsts-hpkp-preloaded.test",
                                  test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> r(context->CreateRequest(
      GURL(base::StringPrintf("https://hsts-hpkp-preloaded.test:%d",
                              test_server.host_port_pair().port())),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  r->Start();
  EXPECT_TRUE(r->is_pending());

  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_FALSE(d.received_data_before_response());
  EXPECT_TRUE(d.have_certificate_errors());
  EXPECT_TRUE(d.certificate_errors_are_fatal());
}

// This tests that cached HTTPS page loads do not cause any updates to the
// TransportSecurityState.
TEST_F(HTTPSRequestTest, HTTPSErrorsNoClobberTSSTest) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  // The actual problem -- CERT_MISMATCHED_NAME in this case -- doesn't
  // matter. It just has to be any error.
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_MISMATCHED_NAME);
  test_server.ServeFilesFromSourceDirectory("net/data/ssl");
  ASSERT_TRUE(test_server.Start());

  // We require that the URL be hsts-hpkp-preloaded.test. This is a test domain
  // that has a preloaded HSTS+HPKP entry in the TransportSecurityState. This
  // means that we have to use a MockHostResolver in order to direct
  // hsts-hpkp-preloaded.test to the testserver.

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("hsts-hpkp-preloaded.test",
                                  test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();
  ASSERT_TRUE(context->transport_security_state());
  TransportSecurityState& transport_security_state =
      *context->transport_security_state();

  transport_security_state.EnableStaticPinsForTesting();
  transport_security_state.SetPinningListAlwaysTimelyForTesting(true);

  TransportSecurityState::STSState static_sts_state;
  TransportSecurityState::PKPState static_pkp_state;
  EXPECT_TRUE(transport_security_state.GetStaticSTSState(
      "hsts-hpkp-preloaded.test", &static_sts_state));
  EXPECT_TRUE(transport_security_state.GetStaticPKPState(
      "hsts-hpkp-preloaded.test", &static_pkp_state));

  TransportSecurityState::STSState dynamic_sts_state;
  TransportSecurityState::PKPState dynamic_pkp_state;
  EXPECT_FALSE(transport_security_state.GetDynamicSTSState(
      "hsts-hpkp-preloaded.test", &dynamic_sts_state));
  EXPECT_FALSE(transport_security_state.GetDynamicPKPState(
      "hsts-hpkp-preloaded.test", &dynamic_pkp_state));

  TestDelegate d;
  std::unique_ptr<URLRequest> r(context->CreateRequest(
      GURL(base::StringPrintf("https://hsts-hpkp-preloaded.test:%d",
                              test_server.host_port_pair().port())),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  r->Start();
  EXPECT_TRUE(r->is_pending());

  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_FALSE(d.received_data_before_response());
  EXPECT_TRUE(d.have_certificate_errors());
  EXPECT_TRUE(d.certificate_errors_are_fatal());

  // Get a fresh copy of the states, and check that they haven't changed.
  TransportSecurityState::STSState new_static_sts_state;
  TransportSecurityState::PKPState new_static_pkp_state;
  EXPECT_TRUE(transport_security_state.GetStaticSTSState(
      "hsts-hpkp-preloaded.test", &new_static_sts_state));
  EXPECT_TRUE(transport_security_state.GetStaticPKPState(
      "hsts-hpkp-preloaded.test", &new_static_pkp_state));
  TransportSecurityState::STSState new_dynamic_sts_state;
  TransportSecurityState::PKPState new_dynamic_pkp_state;
  EXPECT_FALSE(transport_security_state.GetDynamicSTSState(
      "hsts-hpkp-preloaded.test", &new_dynamic_pkp_state));
  EXPECT_FALSE(transport_security_state.GetDynamicPKPState(
      "hsts-hpkp-preloaded.test", &new_dynamic_pkp_state));

  EXPECT_EQ(new_static_sts_state.upgrade_mode, static_sts_state.upgrade_mode);
  EXPECT_EQ(new_static_sts_state.include_subdomains,
            static_sts_state.include_subdomains);
  EXPECT_EQ(new_static_pkp_state.include_subdomains,
            static_pkp_state.include_subdomains);
  EXPECT_EQ(new_static_pkp_state.spki_hashes, static_pkp_state.spki_hashes);
  EXPECT_EQ(new_static_pkp_state.bad_spki_hashes,
            static_pkp_state.bad_spki_hashes);
}

// Make sure HSTS preserves a POST request's method and body.
TEST_F(HTTPSRequestTest, HSTSPreservesPosts) {
  static const char kData[] = "hello world";

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  // Per spec, TransportSecurityState expects a domain name, rather than an IP
  // address, so a MockHostResolver is needed to redirect www.somewhere.com to
  // the EmbeddedTestServer.
  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("www.somewhere.com",
                                  test_server.GetIPLiteralString());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();
  ASSERT_TRUE(context->transport_security_state());
  TransportSecurityState& transport_security_state =
      *context->transport_security_state();
  // Force https for www.somewhere.com.
  base::Time expiry = base::Time::Now() + base::Days(1000);
  bool include_subdomains = false;
  transport_security_state.AddHSTS("www.somewhere.com", expiry,
                                   include_subdomains);

  TestDelegate d;
  // Navigating to https://www.somewhere.com instead of https://127.0.0.1 will
  // cause a certificate error. Ignore the error.
  d.set_allow_certificate_errors(true);

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      GURL(base::StringPrintf("http://www.somewhere.com:%d/echo",
                              test_server.host_port_pair().port())),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_method("POST");
  req->set_upload(CreateSimpleUploadData(base::byte_span_from_cstring(kData)));

  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ("https", req->url().scheme());
  EXPECT_EQ("POST", req->method());
  EXPECT_EQ(kData, d.data_received());

  LoadTimingInfo load_timing_info;
  network_delegate.GetLoadTimingInfoBeforeRedirect(&load_timing_info);
  // LoadTimingInfo of HSTS redirects is similar to that of network cache hits
  TestLoadTimingCacheHitNoNetwork(load_timing_info);
}

// Make sure that the CORS headers are added to cross-origin HSTS redirects.
TEST_F(HTTPSRequestTest, HSTSCrossOriginAddHeaders) {
  static const char kOriginHeaderValue[] = "http://www.example.com";

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.ServeFilesFromSourceDirectory("net/data/ssl");
  ASSERT_TRUE(test_server.Start());

  auto cert_verifier = std::make_unique<MockCertVerifier>();
  cert_verifier->set_default_result(OK);

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCertVerifier(std::move(cert_verifier));
  auto context = context_builder->Build();
  ASSERT_TRUE(context->transport_security_state());
  TransportSecurityState& transport_security_state =
      *context->transport_security_state();
  base::Time expiry = base::Time::Now() + base::Days(1);
  bool include_subdomains = false;
  transport_security_state.AddHSTS("example.net", expiry, include_subdomains);

  GURL hsts_http_url(base::StringPrintf("http://example.net:%d/somehstssite",
                                        test_server.host_port_pair().port()));
  GURL::Replacements replacements;
  replacements.SetSchemeStr("https");
  GURL hsts_https_url = hsts_http_url.ReplaceComponents(replacements);

  TestDelegate d;

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      hsts_http_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  // Set Origin header to simulate a cross-origin request.
  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Origin", kOriginHeaderValue);
  req->SetExtraRequestHeaders(request_headers);

  req->Start();
  d.RunUntilRedirect();

  EXPECT_EQ(1, d.received_redirect_count());

  const HttpResponseHeaders* headers = req->response_headers();
  std::string redirect_location;
  EXPECT_TRUE(
      headers->EnumerateHeader(nullptr, "Location", &redirect_location));
  EXPECT_EQ(hsts_https_url.spec(), redirect_location);

  std::string received_cors_header;
  EXPECT_TRUE(headers->EnumerateHeader(nullptr, "Access-Control-Allow-Origin",
                                       &received_cors_header));
  EXPECT_EQ(kOriginHeaderValue, received_cors_header);

  std::string received_corp_header;
  EXPECT_TRUE(headers->EnumerateHeader(nullptr, "Cross-Origin-Resource-Policy",
                                       &received_corp_header));
  EXPECT_EQ("Cross-Origin", received_corp_header);
}

namespace {

class SSLClientAuthTestDelegate : public TestDelegate {
 public:
  SSLClientAuthTestDelegate() { set_on_complete(base::DoNothing()); }
  void OnCertificateRequested(URLRequest* request,
                              SSLCertRequestInfo* cert_request_info) override {
    on_certificate_requested_count_++;
    std::move(on_certificate_requested_).Run();
  }
  void RunUntilCertificateRequested() {
    base::RunLoop run_loop;
    on_certificate_requested_ = run_loop.QuitClosure();
    run_loop.Run();
  }
  int on_certificate_requested_count() {
    return on_certificate_requested_count_;
  }

 private:
  int on_certificate_requested_count_ = 0;
  base::OnceClosure on_certificate_requested_;
};

class TestSSLPrivateKey : public SSLPrivateKey {
 public:
  explicit TestSSLPrivateKey(scoped_refptr<SSLPrivateKey> key)
      : key_(std::move(key)) {}

  void set_fail_signing(bool fail_signing) { fail_signing_ = fail_signing; }
  int sign_count() const { return sign_count_; }

  std::string GetProviderName() override { return key_->GetProviderName(); }
  std::vector<uint16_t> GetAlgorithmPreferences() override {
    return key_->GetAlgorithmPreferences();
  }
  void Sign(uint16_t algorithm,
            base::span<const uint8_t> input,
            SignCallback callback) override {
    sign_count_++;
    if (fail_signing_) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback),
                                    ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED,
                                    std::vector<uint8_t>()));
    } else {
      key_->Sign(algorithm, input, std::move(callback));
    }
  }

 private:
  ~TestSSLPrivateKey() override = default;

  scoped_refptr<SSLPrivateKey> key_;
  bool fail_signing_ = false;
  int sign_count_ = 0;
};

}  // namespace

// TODO(davidben): Test the rest of the code. Specifically,
// - Filtering which certificates to select.
// - Getting a certificate request in an SSL renegotiation sending the
//   HTTP request.
TEST_F(HTTPSRequestTest, ClientAuthNoCertificate) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  net::SSLServerConfig ssl_config;
  ssl_config.client_cert_type =
      SSLServerConfig::ClientCertType::OPTIONAL_CLIENT_CERT;
  test_server.SetSSLConfig(EmbeddedTestServer::
Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共17部分，请归纳一下它的功能

"""
eferrer);

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPToCrossOriginHTTP) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTP,
                                net::EmbeddedTestServer::TYPE_HTTP);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPSToSameOriginHTTPS) {
  InstantiateSameOriginServers(net::EmbeddedTestServer::TYPE_HTTPS);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer);

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPSToCrossOriginHTTPS) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTPS,
                                net::EmbeddedTestServer::TYPE_HTTPS);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPToHTTPS) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTP,
                                net::EmbeddedTestServer::TYPE_HTTPS);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

TEST_F(URLRequestTestReferrerPolicy, HTTPSToHTTP) {
  InstantiateCrossOriginServers(net::EmbeddedTestServer::TYPE_HTTPS,
                                net::EmbeddedTestServer::TYPE_HTTP);
  GURL referrer = origin_server()->GetURL("/path/to/file.html");

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      GURL());

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      GURL());

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      origin_server()->GetURL("/"));

  VerifyReferrerAfterRedirect(ReferrerPolicy::NEVER_CLEAR, referrer, referrer);

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin; thus this test case just
  // checks that this policy doesn't cause the referrer to change when following
  // a redirect.
  VerifyReferrerAfterRedirect(ReferrerPolicy::ORIGIN,
                              referrer.DeprecatedGetOriginAsURL(),
                              referrer.DeprecatedGetOriginAsURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
                              referrer, GURL());

  // The original referrer set on the request is expected to obey the referrer
  // policy and already be stripped to the origin, though it should be
  // subsequently cleared during the downgrading redirect.
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
      referrer.DeprecatedGetOriginAsURL(), GURL());

  VerifyReferrerAfterRedirect(ReferrerPolicy::NO_REFERRER, GURL(), GURL());
}

class HTTPSRequestTest : public TestWithTaskEnvironment {
 public:
  HTTPSRequestTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    default_context_ = context_builder->Build();
  }
  ~HTTPSRequestTest() override {
    SetTransportSecurityStateSourceForTesting(nullptr);
  }

  URLRequestContext& default_context() { return *default_context_; }

 private:
  std::unique_ptr<URLRequestContext> default_context_;
};

TEST_F(HTTPSRequestTest, HTTPSGetTest) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
    CheckSSLInfo(r->ssl_info());
    EXPECT_EQ(test_server.host_port_pair().host(),
              r->GetResponseRemoteEndpoint().ToStringWithoutPort());
    EXPECT_EQ(test_server.host_port_pair().port(),
              r->GetResponseRemoteEndpoint().port());
  }
}

TEST_F(HTTPSRequestTest, HTTPSMismatchedTest) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_MISMATCHED_NAME);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  bool err_allowed = true;
  for (int i = 0; i < 2; i++, err_allowed = !err_allowed) {
    TestDelegate d;
    {
      d.set_allow_certificate_errors(err_allowed);
      std::unique_ptr<URLRequest> r(default_context().CreateRequest(
          test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
          TRAFFIC_ANNOTATION_FOR_TESTS));

      r->Start();
      EXPECT_TRUE(r->is_pending());

      d.RunUntilComplete();

      EXPECT_EQ(1, d.response_started_count());
      EXPECT_FALSE(d.received_data_before_response());
      EXPECT_TRUE(d.have_certificate_errors());
      if (err_allowed) {
        EXPECT_NE(0, d.bytes_received());
        CheckSSLInfo(r->ssl_info());
      } else {
        EXPECT_EQ(0, d.bytes_received());
      }
    }
  }
}

TEST_F(HTTPSRequestTest, HTTPSExpiredTest) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  // Iterate from false to true, just so that we do the opposite of the
  // previous test in order to increase test coverage.
  bool err_allowed = false;
  for (int i = 0; i < 2; i++, err_allowed = !err_allowed) {
    TestDelegate d;
    {
      d.set_allow_certificate_errors(err_allowed);
      std::unique_ptr<URLRequest> r(default_context().CreateRequest(
          test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
          TRAFFIC_ANNOTATION_FOR_TESTS));

      r->Start();
      EXPECT_TRUE(r->is_pending());

      d.RunUntilComplete();

      EXPECT_EQ(1, d.response_started_count());
      EXPECT_FALSE(d.received_data_before_response());
      EXPECT_TRUE(d.have_certificate_errors());
      if (err_allowed) {
        EXPECT_NE(0, d.bytes_received());
        CheckSSLInfo(r->ssl_info());
      } else {
        EXPECT_EQ(0, d.bytes_received());
      }
    }
  }
}

// A TestDelegate used to test that an appropriate net error code is provided
// when an SSL certificate error occurs.
class SSLNetErrorTestDelegate : public TestDelegate {
 public:
  void OnSSLCertificateError(URLRequest* request,
                             int net_error,
                             const SSLInfo& ssl_info,
                             bool fatal) override {
    net_error_ = net_error;
    on_ssl_certificate_error_called_ = true;
    TestDelegate::OnSSLCertificateError(request, net_error, ssl_info, fatal);
  }

  bool on_ssl_certificate_error_called() {
    return on_ssl_certificate_error_called_;
  }

  int net_error() { return net_error_; }

 private:
  bool on_ssl_certificate_error_called_ = false;
  int net_error_ = net::OK;
};

// Tests that the URLRequest::Delegate receives an appropriate net error code
// when an SSL certificate error occurs.
TEST_F(HTTPSRequestTest, SSLNetErrorReportedToDelegate) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  SSLNetErrorTestDelegate d;
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  r->Start();
  EXPECT_TRUE(r->is_pending());
  d.RunUntilComplete();

  EXPECT_TRUE(d.on_ssl_certificate_error_called());
  EXPECT_EQ(net::ERR_CERT_DATE_INVALID, d.net_error());
}

// TODO(svaldez): iOS tests are flaky with EmbeddedTestServer and transport
// security state. (see http://crbug.com/550977).
#if !BUILDFLAG(IS_IOS)
// This tests that a load of a domain with preloaded HSTS and HPKP with a
// certificate error sets the |certificate_errors_are_fatal| flag correctly.
// This flag will cause the interstitial to be fatal.
TEST_F(HTTPSRequestTest, HTTPSPreloadedHSTSTest) {
  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_MISMATCHED_NAME);
  test_server.ServeFilesFromSourceDirectory("net/data/ssl");
  ASSERT_TRUE(test_server.Start());

  // We require that the URL be hsts-hpkp-preloaded.test. This is a test domain
  // that has a preloaded HSTS+HPKP entry in the TransportSecurityState. This
  // means that we have to use a MockHostResolver in order to direct
  // hsts-hpkp-preloaded.test to the testserver.

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("hsts-hpkp-preloaded.test",
                                  test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> r(context->CreateRequest(
      GURL(base::StringPrintf("https://hsts-hpkp-preloaded.test:%d",
                              test_server.host_port_pair().port())),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  r->Start();
  EXPECT_TRUE(r->is_pending());

  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_FALSE(d.received_data_before_response());
  EXPECT_TRUE(d.have_certificate_errors());
  EXPECT_TRUE(d.certificate_errors_are_fatal());
}

// This tests that cached HTTPS page loads do not cause any updates to the
// TransportSecurityState.
TEST_F(HTTPSRequestTest, HTTPSErrorsNoClobberTSSTest) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  // The actual problem -- CERT_MISMATCHED_NAME in this case -- doesn't
  // matter. It just has to be any error.
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_MISMATCHED_NAME);
  test_server.ServeFilesFromSourceDirectory("net/data/ssl");
  ASSERT_TRUE(test_server.Start());

  // We require that the URL be hsts-hpkp-preloaded.test. This is a test domain
  // that has a preloaded HSTS+HPKP entry in the TransportSecurityState. This
  // means that we have to use a MockHostResolver in order to direct
  // hsts-hpkp-preloaded.test to the testserver.

  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("hsts-hpkp-preloaded.test",
                                  test_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();
  ASSERT_TRUE(context->transport_security_state());
  TransportSecurityState& transport_security_state =
      *context->transport_security_state();

  transport_security_state.EnableStaticPinsForTesting();
  transport_security_state.SetPinningListAlwaysTimelyForTesting(true);

  TransportSecurityState::STSState static_sts_state;
  TransportSecurityState::PKPState static_pkp_state;
  EXPECT_TRUE(transport_security_state.GetStaticSTSState(
      "hsts-hpkp-preloaded.test", &static_sts_state));
  EXPECT_TRUE(transport_security_state.GetStaticPKPState(
      "hsts-hpkp-preloaded.test", &static_pkp_state));

  TransportSecurityState::STSState dynamic_sts_state;
  TransportSecurityState::PKPState dynamic_pkp_state;
  EXPECT_FALSE(transport_security_state.GetDynamicSTSState(
      "hsts-hpkp-preloaded.test", &dynamic_sts_state));
  EXPECT_FALSE(transport_security_state.GetDynamicPKPState(
      "hsts-hpkp-preloaded.test", &dynamic_pkp_state));

  TestDelegate d;
  std::unique_ptr<URLRequest> r(context->CreateRequest(
      GURL(base::StringPrintf("https://hsts-hpkp-preloaded.test:%d",
                              test_server.host_port_pair().port())),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  r->Start();
  EXPECT_TRUE(r->is_pending());

  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_FALSE(d.received_data_before_response());
  EXPECT_TRUE(d.have_certificate_errors());
  EXPECT_TRUE(d.certificate_errors_are_fatal());

  // Get a fresh copy of the states, and check that they haven't changed.
  TransportSecurityState::STSState new_static_sts_state;
  TransportSecurityState::PKPState new_static_pkp_state;
  EXPECT_TRUE(transport_security_state.GetStaticSTSState(
      "hsts-hpkp-preloaded.test", &new_static_sts_state));
  EXPECT_TRUE(transport_security_state.GetStaticPKPState(
      "hsts-hpkp-preloaded.test", &new_static_pkp_state));
  TransportSecurityState::STSState new_dynamic_sts_state;
  TransportSecurityState::PKPState new_dynamic_pkp_state;
  EXPECT_FALSE(transport_security_state.GetDynamicSTSState(
      "hsts-hpkp-preloaded.test", &new_dynamic_sts_state));
  EXPECT_FALSE(transport_security_state.GetDynamicPKPState(
      "hsts-hpkp-preloaded.test", &new_dynamic_pkp_state));

  EXPECT_EQ(new_static_sts_state.upgrade_mode, static_sts_state.upgrade_mode);
  EXPECT_EQ(new_static_sts_state.include_subdomains,
            static_sts_state.include_subdomains);
  EXPECT_EQ(new_static_pkp_state.include_subdomains,
            static_pkp_state.include_subdomains);
  EXPECT_EQ(new_static_pkp_state.spki_hashes, static_pkp_state.spki_hashes);
  EXPECT_EQ(new_static_pkp_state.bad_spki_hashes,
            static_pkp_state.bad_spki_hashes);
}

// Make sure HSTS preserves a POST request's method and body.
TEST_F(HTTPSRequestTest, HSTSPreservesPosts) {
  static const char kData[] = "hello world";

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  // Per spec, TransportSecurityState expects a domain name, rather than an IP
  // address, so a MockHostResolver is needed to redirect www.somewhere.com to
  // the EmbeddedTestServer.
  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("www.somewhere.com",
                                  test_server.GetIPLiteralString());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();
  ASSERT_TRUE(context->transport_security_state());
  TransportSecurityState& transport_security_state =
      *context->transport_security_state();
  // Force https for www.somewhere.com.
  base::Time expiry = base::Time::Now() + base::Days(1000);
  bool include_subdomains = false;
  transport_security_state.AddHSTS("www.somewhere.com", expiry,
                                   include_subdomains);

  TestDelegate d;
  // Navigating to https://www.somewhere.com instead of https://127.0.0.1 will
  // cause a certificate error.  Ignore the error.
  d.set_allow_certificate_errors(true);

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      GURL(base::StringPrintf("http://www.somewhere.com:%d/echo",
                              test_server.host_port_pair().port())),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_method("POST");
  req->set_upload(CreateSimpleUploadData(base::byte_span_from_cstring(kData)));

  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ("https", req->url().scheme());
  EXPECT_EQ("POST", req->method());
  EXPECT_EQ(kData, d.data_received());

  LoadTimingInfo load_timing_info;
  network_delegate.GetLoadTimingInfoBeforeRedirect(&load_timing_info);
  // LoadTimingInfo of HSTS redirects is similar to that of network cache hits
  TestLoadTimingCacheHitNoNetwork(load_timing_info);
}

// Make sure that the CORS headers are added to cross-origin HSTS redirects.
TEST_F(HTTPSRequestTest, HSTSCrossOriginAddHeaders) {
  static const char kOriginHeaderValue[] = "http://www.example.com";

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.ServeFilesFromSourceDirectory("net/data/ssl");
  ASSERT_TRUE(test_server.Start());

  auto cert_verifier = std::make_unique<MockCertVerifier>();
  cert_verifier->set_default_result(OK);

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCertVerifier(std::move(cert_verifier));
  auto context = context_builder->Build();
  ASSERT_TRUE(context->transport_security_state());
  TransportSecurityState& transport_security_state =
      *context->transport_security_state();
  base::Time expiry = base::Time::Now() + base::Days(1);
  bool include_subdomains = false;
  transport_security_state.AddHSTS("example.net", expiry, include_subdomains);

  GURL hsts_http_url(base::StringPrintf("http://example.net:%d/somehstssite",
                                        test_server.host_port_pair().port()));
  GURL::Replacements replacements;
  replacements.SetSchemeStr("https");
  GURL hsts_https_url = hsts_http_url.ReplaceComponents(replacements);

  TestDelegate d;

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      hsts_http_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  // Set Origin header to simulate a cross-origin request.
  HttpRequestHeaders request_headers;
  request_headers.SetHeader("Origin", kOriginHeaderValue);
  req->SetExtraRequestHeaders(request_headers);

  req->Start();
  d.RunUntilRedirect();

  EXPECT_EQ(1, d.received_redirect_count());

  const HttpResponseHeaders* headers = req->response_headers();
  std::string redirect_location;
  EXPECT_TRUE(
      headers->EnumerateHeader(nullptr, "Location", &redirect_location));
  EXPECT_EQ(hsts_https_url.spec(), redirect_location);

  std::string received_cors_header;
  EXPECT_TRUE(headers->EnumerateHeader(nullptr, "Access-Control-Allow-Origin",
                                       &received_cors_header));
  EXPECT_EQ(kOriginHeaderValue, received_cors_header);

  std::string received_corp_header;
  EXPECT_TRUE(headers->EnumerateHeader(nullptr, "Cross-Origin-Resource-Policy",
                                       &received_corp_header));
  EXPECT_EQ("Cross-Origin", received_corp_header);
}

namespace {

class SSLClientAuthTestDelegate : public TestDelegate {
 public:
  SSLClientAuthTestDelegate() { set_on_complete(base::DoNothing()); }
  void OnCertificateRequested(URLRequest* request,
                              SSLCertRequestInfo* cert_request_info) override {
    on_certificate_requested_count_++;
    std::move(on_certificate_requested_).Run();
  }
  void RunUntilCertificateRequested() {
    base::RunLoop run_loop;
    on_certificate_requested_ = run_loop.QuitClosure();
    run_loop.Run();
  }
  int on_certificate_requested_count() {
    return on_certificate_requested_count_;
  }

 private:
  int on_certificate_requested_count_ = 0;
  base::OnceClosure on_certificate_requested_;
};

class TestSSLPrivateKey : public SSLPrivateKey {
 public:
  explicit TestSSLPrivateKey(scoped_refptr<SSLPrivateKey> key)
      : key_(std::move(key)) {}

  void set_fail_signing(bool fail_signing) { fail_signing_ = fail_signing; }
  int sign_count() const { return sign_count_; }

  std::string GetProviderName() override { return key_->GetProviderName(); }
  std::vector<uint16_t> GetAlgorithmPreferences() override {
    return key_->GetAlgorithmPreferences();
  }
  void Sign(uint16_t algorithm,
            base::span<const uint8_t> input,
            SignCallback callback) override {
    sign_count_++;
    if (fail_signing_) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback),
                                    ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED,
                                    std::vector<uint8_t>()));
    } else {
      key_->Sign(algorithm, input, std::move(callback));
    }
  }

 private:
  ~TestSSLPrivateKey() override = default;

  scoped_refptr<SSLPrivateKey> key_;
  bool fail_signing_ = false;
  int sign_count_ = 0;
};

}  // namespace

// TODO(davidben): Test the rest of the code. Specifically,
// - Filtering which certificates to select.
// - Getting a certificate request in an SSL renegotiation sending the
//   HTTP request.
TEST_F(HTTPSRequestTest, ClientAuthNoCertificate) {
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  net::SSLServerConfig ssl_config;
  ssl_config.client_cert_type =
      SSLServerConfig::ClientCertType::OPTIONAL_CLIENT_CERT;
  test_server.SetSSLConfig(EmbeddedTestServer::CERT_OK, ssl_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  SSLClientAuthTestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilCertificateRequested();
    EXPECT_TRUE(r->is_pending());

    EXPECT_EQ(1, d.on_certificate_requested_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());

    // Send no certificate.
    // TODO(davidben): Get temporary client cert import (with keys) working on
    // all platforms so we can test sending a cert as well.
    r->ContinueWithCertificate(nullptr, nullptr);

    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());
  }
}

TEST_F(HTTPSRequestTest, ClientAuth) {
  std::unique_ptr<FakeClientCertIdentity> identity =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_1.pem", "client_1.pk8");
  ASSERT_TRUE(identity);
  scoped_refptr<TestSSLPrivateKey> private_key =
      base::MakeRefCounted<TestSSLPrivateKey>(identity->ssl_private_key());

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  net::SSLServerConfig ssl_config;
  ssl_config.client_cert_type =
      SSLServerConfig::ClientCertType::REQUIRE_CLIENT_CERT;
  test_server.SetSSLConfig(EmbeddedTestServer::CERT_OK, ssl_config);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  {
    SSLClientAuthTestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilCertificateRequested();
    EXPECT_TRUE(r->is_pending());

    EXPECT_EQ(1, d.on_certificate_requested_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(0, d.bytes_received());

    // Send a certificate.
    r->ContinueWithCertificate(identity->certificate(), private_key);

    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());

    // The private key should have been used.
    EXPECT_EQ(1, private_key->sign_count());
  }

  // Close all connections and clear the session cache to force a new handshake.
  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->CloseAllConnections(ERR_FAILED, "Very good reason");
  default_context()
      .http_transaction_factory()
      ->GetSession()
      ->ClearSSLSessionCache();

  // Connecting again should not call OnCertificateRequested. The identity is
  // taken from the client auth cache.
  {
    SSLClientAuthTestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        test_server.GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(0, d.on_certificate_requested_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_NE(0, d.bytes_received());

    // The private key should have been used.
    EXPECT_EQ(2, private_key->sign_count());
  }
}

// Test that private keys that fail to sign anything get evicted from the cache.
TEST_F(HTTPSRequestTest, ClientAuthFailSigning) {
  std::unique_ptr<FakeClientCertIdentity> identity =
      FakeClientCertIdentity::CreateFromCertAndKeyFiles(
          GetTestCertsDirectory(), "client_1.pem", "client_1.pk8");
  ASSERT_TRUE(identity);
  scoped_refptr<TestSSLPrivateKey> private_key =
      base::MakeRefCounted<TestSSLPrivateKey>(identity->ssl_private_key());
  private_key->set_fail_signing(true);

  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  net::SSLServerConfig ssl_config;
  ssl_config.client_cert_type =
      SSLServerConfig::Client
"""


```