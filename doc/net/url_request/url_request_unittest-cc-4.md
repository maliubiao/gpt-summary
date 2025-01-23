Response:
The user wants a summary of the functionality of a given code snippet from `net/url_request/url_request_unittest.cc`. They also want to know about its relation to JavaScript, examples of logical reasoning, common usage errors, and debugging steps. This is part 5 of 17.

**Plan:**

1. **High-level overview:**  The code snippet primarily tests the behavior of `URLRequest` in Chromium's network stack, focusing on cookie handling in various scenarios, especially with redirects and SameSite attributes.
2. **Specific functionalities:** Break down the tests into key areas like:
    - Setting SameSite cookies in different redirect scenarios (same-origin, same-site, cross-site, top-level, subresource).
    - Behavior of SameSite cookies when considering redirect chains.
    - Setting partitioned cookies and their behavior during redirects.
    - Handling of `__Secure-` cookie prefix.
    - Strict secure cookie settings.
    - Clock skew and timezone handling when setting cookies.
    - Preventing referrer overriding.
    - HTTP method changes during redirects.
    - Origin header behavior during redirects.
    - Upload data handling.
    - Proxy tunnel redirects.
3. **JavaScript relationship:** Explain how these functionalities relate to how JavaScript running in a browser interacts with cookies and makes network requests.
4. **Logical reasoning:** Identify instances where the code makes assertions based on expected behavior. Provide hypothetical inputs and expected outputs based on the test logic.
5. **Common usage errors:** Consider how developers might misuse the APIs being tested, leading to unexpected cookie behavior.
6. **Debugging steps:** Outline how a developer might arrive at this code during debugging, focusing on issues related to cookies and network requests.
7. **Part 5 context:** Note that this section focuses on cookie behavior during redirects and security-related cookie features.
```cpp
evel navigation request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict2=1;SameSite=Strict&Lax2=1;SameSite=Lax");
    GURL url = https_server.GetURL(kSameSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kMainFrame, kSameSiteOrigin,
        kSameSiteOrigin, kSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kSameSiteOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies can be set for a cross-site redirected
  // top-level navigation request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict3=1;SameSite=Strict&Lax3=1;SameSite=Lax");
    GURL url = https_server.GetURL(kCrossSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kMainFrame, kCrossSiteOrigin,
        kCrossSiteOrigin, kCrossSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kCrossSiteForCookies);
    req->set_initiator(kCrossSiteOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies can be set for a same-origin redirected
  // subresource request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict4=1;SameSite=Strict&Lax4=1;SameSite=Lax");
    GURL url =
        https_server.GetURL(kHost, "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies can be set for a same-site redirected
  // subresource request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict5=1;SameSite=Strict&Lax5=1;SameSite=Lax");
    GURL url = https_server.GetURL(kSameSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kSameSiteOrigin, kSameSiteOrigin,
        kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kSameSiteOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that (depending on whether redirect chains are considered) SameSite
  // cookies can/cannot be set for a cross-site redirected subresource request,
  // even if the site-for-cookies and initiator are same-site, ...
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict6=1;SameSite=Strict&Lax6=1;SameSite=Lax");
    GURL url = https_server.GetURL(kCrossSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += DoesCookieSameSiteConsiderRedirectChain() ? 0 : 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }
  // ... even if the initial URL is same-site.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict7=1;SameSite=Strict&Lax7=1;SameSite=Lax");
    GURL middle_url = https_server.GetURL(
        kCrossSiteHost, "/server-redirect?" + set_cookie_url.spec());
    GURL url =
        https_server.GetURL(kHost, "/server-redirect?" + middle_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += DoesCookieSameSiteConsiderRedirectChain() ? 0 : 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies may or may not be set for a cross-scheme
  // (same-registrable-domain) redirected subresource request, depending on the
  // status of Schemeful Same-Site and whether redirect chains are considered.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(features::kSchemefulSameSite);
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict8=1;SameSite=Strict&Lax8=1;SameSite=Lax");
    GURL url =
        http_server.GetURL(kHost, "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kOther, kHttpOrigin,
                              kHttpOrigin, kHttpSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kHttpSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(features::kSchemefulSameSite);
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict9=1;SameSite=Strict&Lax9=1;SameSite=Lax");
    GURL url =
        http_server.GetURL(kHost, "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kOther, kHttpOrigin,
                              kHttpOrigin, kHttpSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kHttpSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += DoesCookieSameSiteConsiderRedirectChain() ? 0 : 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }
}

INSTANTIATE_TEST_SUITE_P(/* no label */,
                         URLRequestSameSiteCookiesTest,
                         ::testing::Bool());

TEST_F(URLRequestTest, PartitionedCookiesRedirect) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  const std::string kHost = "a.test";
  const std::string kCrossSiteHost = "b.test";

  const GURL create_cookie_url = https_server.GetURL(kHost, "/");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(
      std::make_unique<CookieMonster>(nullptr, nullptr));
  auto context = context_builder->Build();
  auto& cm = *static_cast<CookieMonster*>(context->cookie_store());

  // Set partitioned cookie with same-site partitionkey.
  {
    auto same_site_partitioned_cookie = CanonicalCookie::CreateForTesting(
        create_cookie_url, "samesite_partitioned=1;Secure;Partitioned",
        base::Time::Now(), std::nullopt,
        CookiePartitionKey::FromURLForTesting(
            create_cookie_url,
            CookiePartitionKey::AncestorChainBit::kSameSite));
    ASSERT_TRUE(same_site_partitioned_cookie);
    ASSERT_TRUE(same_site_partitioned_cookie->IsPartitioned());
    base::test::TestFuture<CookieAccessResult> future;
    cm.SetCanonicalCookieAsync(
        std::move(same_site_partitioned_cookie), create_cookie_url,
        CookieOptions::MakeAllInclusive(), future.GetCallback());
    ASSERT_TRUE(future.Get().status.IsInclude());
  }

  // Set a partitioned cookie with a cross-site partition key.
  // In the redirect below from site B to A, this cookie's partition key is site
  // B it should not be sent in the redirected request.
  {
    auto cross_site_partitioned_cookie = CanonicalCookie::CreateForTesting(
        create_cookie_url, "xsite_partitioned=1;Secure;Partitioned",
        base::Time::Now(), std::nullopt,
        CookiePartitionKey::FromURLForTesting(
            https_server.GetURL(kCrossSiteHost, "/")));
    ASSERT_TRUE(cross_site_partitioned_cookie);
    ASSERT_TRUE(cross_site_partitioned_cookie->IsPartitioned());
    base::test::TestFuture<CookieAccessResult> future;
    cm.SetCanonicalCookieAsync(
        std::move(cross_site_partitioned_cookie), create_cookie_url,
        CookieOptions::MakeAllInclusive(), future.GetCallback());
    ASSERT_TRUE(future.Get().status.IsInclude());
  }

  const auto kCrossSiteOrigin =
      url::Origin::Create(https_server.GetURL(kCrossSiteHost, "/"));
  const auto kCrossSiteSiteForCookies =
      SiteForCookies::FromOrigin(kCrossSiteOrigin);

  // Test that when a request is redirected that the partitioned cookies
  // attached to the redirected request match the partition key of the new
  // request.
  TestDelegate d;
  GURL url = https_server.GetURL(
      kCrossSiteHost,
      "/server-redirect?" +
          https_server.GetURL(kHost, "/echoheader?Cookie").spec());
  std::unique_ptr<URLRequest> req = context->CreateRequest(
      url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS);
  req->set_isolation_info(IsolationInfo::Create(
      IsolationInfo::RequestType::kMainFrame, kCrossSiteOrigin,
      kCrossSiteOrigin, kCrossSiteSiteForCookies));
  req->set_first_party_url_policy(
      RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
  req->set_site_for_cookies(kCrossSiteSiteForCookies);
  req->set_initiator(kCrossSiteOrigin);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(2u, req->url_chain().size());
  EXPECT_NE(std::string::npos,
            d.data_received().find("samesite_partitioned=1"));
  EXPECT_EQ(std::string::npos, d.data_received().find("xsite_partitioned=1"));
}

// Tests that __Secure- cookies can't be set on non-secure origins.
TEST_F(URLRequestTest, SecureCookiePrefixOnNonsecureOrigin) {
  EmbeddedTestServer http_server;
  RegisterDefaultHandlers(&http_server);
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(http_server.Start());
  ASSERT_TRUE(https_server.Start());

  // Try to set a Secure __Secure- cookie on http://a.test (non-secure origin).
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        http_server.GetURL("a.test",
                           "/set-cookie?__Secure-nonsecure-origin=1;Secure&"
                           "cookienotsecure=1"),
        &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the __Secure- cookie was not set by checking cookies for
  // https://a.test (secure origin).
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("a.test", "/echoheader?Cookie"),
        &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(d.data_received().find("__Secure-nonsecure-origin=1"),
              std::string::npos);
    EXPECT_NE(d.data_received().find("cookienotsecure=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, SecureCookiePrefixNonsecure) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  // Try to set a non-Secure __Secure- cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("/set-cookie?__Secure-foo=1"),
        &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().set_cookie_count());
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie is not set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(d.data_received().find("__Secure-foo=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, SecureCookiePrefixSecure) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  // Try to set a Secure __Secure- cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        https_server.GetURL("/set-cookie?__Secure-bar=1;Secure"), &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_NE(d.data_received().find("__Secure-bar=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

// Tests that secure cookies can't be set on non-secure origins if strict secure
// cookies are enabled.
TEST_F(URLRequestTest, StrictSecureCookiesOnNonsecureOrigin) {
  EmbeddedTestServer http_server;
  RegisterDefaultHandlers(&http_server);
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(http_server.Start());
  ASSERT_TRUE(https_server.Start());

  // Try to set a Secure cookie and a non-Secure cookie from a nonsecure origin.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        http_server.GetURL("a.test",
                           "/set-cookie?nonsecure-origin=1;Secure&"
                           "cookienotsecure=1"),
        &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the Secure cookie was not set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("a.test", "/echoheader?Cookie"),
        &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(d.data_received().find("nonsecure-origin=1"), std::string::npos);
    EXPECT_NE(d.data_received().find("cookienotsecure=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

// FixedDateNetworkDelegate swaps out the server's HTTP Date response header
// value for the `fixed_date_` member.
class FixedDateNetworkDelegate : public TestNetworkDelegate {
 public:
  explicit FixedDateNetworkDelegate(std::string_view fixed_date)
      : fixed_date_(fixed_date) {}

  FixedDateNetworkDelegate(const FixedDateNetworkDelegate&) = delete;
  FixedDateNetworkDelegate& operator=(const FixedDateNetworkDelegate&) = delete;

  ~FixedDateNetworkDelegate() override = default;

  void set_fixed_date(std::string_view fixed_date) {
    fixed_date_ = static_cast<std::string>(fixed_date);
  }

  // NetworkDelegate implementation
  int OnHeadersReceived(
      URLRequest* request,
      CompletionOnceCallback callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      const IPEndPoint& endpoint,
      std::optional<GURL>* preserve_fragment_on_redirect_url) override;

 private:
  std::string fixed_date_;
};

int FixedDateNetworkDelegate::OnHeadersReceived(
    URLRequest* request,
    CompletionOnceCallback callback,
    const HttpResponseHeaders* original_response_headers,
    scoped_refptr<HttpResponseHeaders>* override_response_headers,
    const IPEndPoint& endpoint,
    std::optional<GURL>* preserve_fragment_on_redirect_url) {
  *override_response_headers = base::MakeRefCounted<HttpResponseHeaders>(
      original_response_headers->raw_headers());

  (*override_response_headers)->SetHeader("Date", fixed_date_);

  return TestNetworkDelegate::OnHeadersReceived(
      request, std::move(callback), original_response_headers,
      override_response_headers, endpoint, preserve_fragment_on_redirect_url);
}

// Test that cookie expiration times are adjusted for server/client clock
// skew and that we handle incorrect timezone specifier "UTC" in HTTP Date
// headers by defaulting to GMT. (crbug.com/135131)
TEST_F(URLRequestTest, AcceptClockSkewCookieWithWrongDateTimezone) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<FixedDateNetworkDelegate>("04-Jan-2004 04:09:25 UTC"));
  auto context = context_builder->Build();

  // Set up an expired cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context,
        test_server.GetURL(
            "/set-cookie?StillGood=1;expires=Mon,18-Apr-1977,22:50:13,GMT"),
        &d);
    req->Start();
    d.RunUntilComplete();
  }
  // Verify that the cookie is not set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context, test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("StillGood=1") == std::string::npos);
  }
  // Set up a cookie with clock skew and "UTC" HTTP Date timezone specifier.
  {
    TestDelegate d;
    network_delegate.set_fixed_date("18-Apr-1977 22:49:13 UTC");
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context,
        test_server.GetURL(
            "/set-cookie?StillGood=1;expires=Mon,18-Apr-1977,22:50:13,GMT"),
        &d);
    req->Start();
    d.RunUntilComplete();
  }
  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context, test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("StillGood=1") != std::string::npos);
  }
}

// Check that it is impossible to change the referrer in the extra headers of
// an URLRequest.
TEST_F(URLRequestTest, DoNotOverrideReferrer) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // If extra headers contain referer and the request contains a referer,
  // only the latter shall be respected.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetReferrer("http://foo.com/");

    HttpRequestHeaders headers;
    headers.SetHeader(HttpRequestHeaders::kReferer, "http://bar.com/");
    req->SetExtraRequestHeaders(headers);

    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ("http://foo.com/", d.data_received());
  }

  // If extra headers contain a referer but the request does not, no referer
  // shall be sent in the header.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    HttpRequestHeaders headers;
    headers.SetHeader(HttpRequestHeaders::kReferer, "http://bar.com/");
    req->SetExtraRequestHeaders(headers);
    req->SetLoadFlags(LOAD_VALIDATE_CACHE);

    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ("None", d.data_received());
  }
}

class URLRequestTestHTTP : public URLRequestTest {
 public:
  const url::Origin origin1_;
  const url::Origin origin2_;
  const IsolationInfo isolation_info1_;
  const IsolationInfo isolation_info2_;

  URLRequestTestHTTP()
      : origin1_(url::Origin::Create(GURL("https://foo.test/"))),
        origin2_(url::Origin::Create(GURL("https://bar.test/"))),
        isolation_info1_(IsolationInfo::CreateForInternalRequest(origin1_)),
        isolation_info2_(IsolationInfo::CreateForInternalRequest(origin2_)),
        test_server_(base::FilePath(kTestFilePath)) {
  }

 protected:
  // ProtocolHandler for the scheme that's unsafe to redirect to.
  class NET_EXPORT UnsafeRedirectProtocolHandler
      : public URLRequestJobFactory::ProtocolHandler {
   public:
    UnsafeRedirectProtocolHandler() = default;

    UnsafeRedirectProtocolHandler(const UnsafeRedirectProtocolHandler&) =
        delete;
    UnsafeRedirectProtocolHandler& operator=(
        const UnsafeRedirectProtocolHandler&) = delete;

    ~UnsafeRedirectProtocolHandler() override = default;

    // URLRequestJobFactory::ProtocolHandler implementation:

    std::unique_ptr<URLRequestJob> CreateJob(
        URLRequest* request) const override {
      NOTREACHED();
    }

    bool IsSafeRedirectTarget(const GURL& location) const override {
      return false;
    }
  };

  // URLRequestTest interface:
  void SetUpContextBuilder(URLRequestContextBuilder& builder) override {
    // Add support for an unsafe scheme to the default URLRequestContext.
    builder.SetProtocolHandler(
        "unsafe", std::make_unique<UnsafeRedirectProtocolHandler>());
  }

  // Requests |redirect_url|, which must return a HTTP 3xx redirect.
  // |request_method| is the method to use for the initial request.
  // |redirect_method| is the method that is expected to be used for the second
  // request, after redirection.
  // If |include_data| is true, data is uploaded with the request. The
  // response body is expected to match it exactly, if and only if
  // |request_method| == |redirect_method|.
  void HTTPRedirectMethodTest(const GURL& redirect_url,
                              const std::string& request_method,
                              const std::string& redirect_method,
                              bool include_data) {
    static const char kData[] = "hello world";
    TestDelegate d;
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(default_context(), redirect_url, &d);
    req->set_method(request_method);
    if (include_data) {
      req->set_upload(
          CreateSimpleUploadData(base::byte_span_from_cstring(kData)));
      HttpRequestHeaders headers;
      headers.SetHeader(HttpRequestHeaders::kContentLength,
                        base::NumberToString(std::size(kData) - 1));
      headers.SetHeader
### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
evel navigation request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict2=1;SameSite=Strict&Lax2=1;SameSite=Lax");
    GURL url = https_server.GetURL(kSameSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kMainFrame, kSameSiteOrigin,
        kSameSiteOrigin, kSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kSameSiteOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies can be set for a cross-site redirected
  // top-level navigation request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict3=1;SameSite=Strict&Lax3=1;SameSite=Lax");
    GURL url = https_server.GetURL(kCrossSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kMainFrame, kCrossSiteOrigin,
        kCrossSiteOrigin, kCrossSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kCrossSiteForCookies);
    req->set_initiator(kCrossSiteOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies can be set for a same-origin redirected
  // subresource request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict4=1;SameSite=Strict&Lax4=1;SameSite=Lax");
    GURL url =
        https_server.GetURL(kHost, "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies can be set for a same-site redirected
  // subresource request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict5=1;SameSite=Strict&Lax5=1;SameSite=Lax");
    GURL url = https_server.GetURL(kSameSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kSameSiteOrigin, kSameSiteOrigin,
        kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kSameSiteOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that (depending on whether redirect chains are considered) SameSite
  // cookies can/cannot be set for a cross-site redirected subresource request,
  // even if the site-for-cookies and initiator are same-site, ...
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict6=1;SameSite=Strict&Lax6=1;SameSite=Lax");
    GURL url = https_server.GetURL(kCrossSiteHost,
                                   "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += DoesCookieSameSiteConsiderRedirectChain() ? 0 : 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }
  // ... even if the initial URL is same-site.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict7=1;SameSite=Strict&Lax7=1;SameSite=Lax");
    GURL middle_url = https_server.GetURL(
        kCrossSiteHost, "/server-redirect?" + set_cookie_url.spec());
    GURL url =
        https_server.GetURL(kHost, "/server-redirect?" + middle_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += DoesCookieSameSiteConsiderRedirectChain() ? 0 : 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }

  // Verify that SameSite cookies may or may not be set for a cross-scheme
  // (same-registrable-domain) redirected subresource request, depending on the
  // status of Schemeful Same-Site and whether redirect chains are considered.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(features::kSchemefulSameSite);
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict8=1;SameSite=Strict&Lax8=1;SameSite=Lax");
    GURL url =
        http_server.GetURL(kHost, "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kOther, kHttpOrigin,
                              kHttpOrigin, kHttpSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kHttpSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(features::kSchemefulSameSite);
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict9=1;SameSite=Strict&Lax9=1;SameSite=Lax");
    GURL url =
        http_server.GetURL(kHost, "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kOther, kHttpOrigin,
                              kHttpOrigin, kHttpSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kHttpSiteForCookies);
    req->set_initiator(kOrigin);

    expected_cookies += DoesCookieSameSiteConsiderRedirectChain() ? 0 : 2;
    expected_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_set_cookie_count, network_delegate.set_cookie_count());
  }
}

INSTANTIATE_TEST_SUITE_P(/* no label */,
                         URLRequestSameSiteCookiesTest,
                         ::testing::Bool());

TEST_F(URLRequestTest, PartitionedCookiesRedirect) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  const std::string kHost = "a.test";
  const std::string kCrossSiteHost = "b.test";

  const GURL create_cookie_url = https_server.GetURL(kHost, "/");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(
      std::make_unique<CookieMonster>(nullptr, nullptr));
  auto context = context_builder->Build();
  auto& cm = *static_cast<CookieMonster*>(context->cookie_store());

  // Set partitioned cookie with same-site partitionkey.
  {
    auto same_site_partitioned_cookie = CanonicalCookie::CreateForTesting(
        create_cookie_url, "samesite_partitioned=1;Secure;Partitioned",
        base::Time::Now(), std::nullopt,
        CookiePartitionKey::FromURLForTesting(
            create_cookie_url,
            CookiePartitionKey::AncestorChainBit::kSameSite));
    ASSERT_TRUE(same_site_partitioned_cookie);
    ASSERT_TRUE(same_site_partitioned_cookie->IsPartitioned());
    base::test::TestFuture<CookieAccessResult> future;
    cm.SetCanonicalCookieAsync(
        std::move(same_site_partitioned_cookie), create_cookie_url,
        CookieOptions::MakeAllInclusive(), future.GetCallback());
    ASSERT_TRUE(future.Get().status.IsInclude());
  }

  // Set a partitioned cookie with a cross-site partition key.
  // In the redirect below from site B to A, this cookie's partition key is site
  // B it should not be sent in the redirected request.
  {
    auto cross_site_partitioned_cookie = CanonicalCookie::CreateForTesting(
        create_cookie_url, "xsite_partitioned=1;Secure;Partitioned",
        base::Time::Now(), std::nullopt,
        CookiePartitionKey::FromURLForTesting(
            https_server.GetURL(kCrossSiteHost, "/")));
    ASSERT_TRUE(cross_site_partitioned_cookie);
    ASSERT_TRUE(cross_site_partitioned_cookie->IsPartitioned());
    base::test::TestFuture<CookieAccessResult> future;
    cm.SetCanonicalCookieAsync(
        std::move(cross_site_partitioned_cookie), create_cookie_url,
        CookieOptions::MakeAllInclusive(), future.GetCallback());
    ASSERT_TRUE(future.Get().status.IsInclude());
  }

  const auto kCrossSiteOrigin =
      url::Origin::Create(https_server.GetURL(kCrossSiteHost, "/"));
  const auto kCrossSiteSiteForCookies =
      SiteForCookies::FromOrigin(kCrossSiteOrigin);

  // Test that when a request is redirected that the partitioned cookies
  // attached to the redirected request match the partition key of the new
  // request.
  TestDelegate d;
  GURL url = https_server.GetURL(
      kCrossSiteHost,
      "/server-redirect?" +
          https_server.GetURL(kHost, "/echoheader?Cookie").spec());
  std::unique_ptr<URLRequest> req = context->CreateRequest(
      url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS);
  req->set_isolation_info(IsolationInfo::Create(
      IsolationInfo::RequestType::kMainFrame, kCrossSiteOrigin,
      kCrossSiteOrigin, kCrossSiteSiteForCookies));
  req->set_first_party_url_policy(
      RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
  req->set_site_for_cookies(kCrossSiteSiteForCookies);
  req->set_initiator(kCrossSiteOrigin);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(2u, req->url_chain().size());
  EXPECT_NE(std::string::npos,
            d.data_received().find("samesite_partitioned=1"));
  EXPECT_EQ(std::string::npos, d.data_received().find("xsite_partitioned=1"));
}

// Tests that __Secure- cookies can't be set on non-secure origins.
TEST_F(URLRequestTest, SecureCookiePrefixOnNonsecureOrigin) {
  EmbeddedTestServer http_server;
  RegisterDefaultHandlers(&http_server);
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(http_server.Start());
  ASSERT_TRUE(https_server.Start());

  // Try to set a Secure __Secure- cookie on http://a.test (non-secure origin).
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        http_server.GetURL("a.test",
                           "/set-cookie?__Secure-nonsecure-origin=1;Secure&"
                           "cookienotsecure=1"),
        &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the __Secure- cookie was not set by checking cookies for
  // https://a.test (secure origin).
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("a.test", "/echoheader?Cookie"),
        &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(d.data_received().find("__Secure-nonsecure-origin=1"),
              std::string::npos);
    EXPECT_NE(d.data_received().find("cookienotsecure=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, SecureCookiePrefixNonsecure) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  // Try to set a non-Secure __Secure- cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("/set-cookie?__Secure-foo=1"),
        &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().set_cookie_count());
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie is not set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(d.data_received().find("__Secure-foo=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

TEST_F(URLRequestTest, SecureCookiePrefixSecure) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  // Try to set a Secure __Secure- cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        https_server.GetURL("/set-cookie?__Secure-bar=1;Secure"), &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_NE(d.data_received().find("__Secure-bar=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

// Tests that secure cookies can't be set on non-secure origins if strict secure
// cookies are enabled.
TEST_F(URLRequestTest, StrictSecureCookiesOnNonsecureOrigin) {
  EmbeddedTestServer http_server;
  RegisterDefaultHandlers(&http_server);
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(http_server.Start());
  ASSERT_TRUE(https_server.Start());

  // Try to set a Secure cookie and a non-Secure cookie from a nonsecure origin.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        http_server.GetURL("a.test",
                           "/set-cookie?nonsecure-origin=1;Secure&"
                           "cookienotsecure=1"),
        &d);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the Secure cookie was not set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(), https_server.GetURL("a.test", "/echoheader?Cookie"),
        &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(d.data_received().find("nonsecure-origin=1"), std::string::npos);
    EXPECT_NE(d.data_received().find("cookienotsecure=1"), std::string::npos);
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }
}

// FixedDateNetworkDelegate swaps out the server's HTTP Date response header
// value for the `fixed_date_` member.
class FixedDateNetworkDelegate : public TestNetworkDelegate {
 public:
  explicit FixedDateNetworkDelegate(std::string_view fixed_date)
      : fixed_date_(fixed_date) {}

  FixedDateNetworkDelegate(const FixedDateNetworkDelegate&) = delete;
  FixedDateNetworkDelegate& operator=(const FixedDateNetworkDelegate&) = delete;

  ~FixedDateNetworkDelegate() override = default;

  void set_fixed_date(std::string_view fixed_date) {
    fixed_date_ = static_cast<std::string>(fixed_date);
  }

  // NetworkDelegate implementation
  int OnHeadersReceived(
      URLRequest* request,
      CompletionOnceCallback callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      const IPEndPoint& endpoint,
      std::optional<GURL>* preserve_fragment_on_redirect_url) override;

 private:
  std::string fixed_date_;
};

int FixedDateNetworkDelegate::OnHeadersReceived(
    URLRequest* request,
    CompletionOnceCallback callback,
    const HttpResponseHeaders* original_response_headers,
    scoped_refptr<HttpResponseHeaders>* override_response_headers,
    const IPEndPoint& endpoint,
    std::optional<GURL>* preserve_fragment_on_redirect_url) {
  *override_response_headers = base::MakeRefCounted<HttpResponseHeaders>(
      original_response_headers->raw_headers());

  (*override_response_headers)->SetHeader("Date", fixed_date_);

  return TestNetworkDelegate::OnHeadersReceived(
      request, std::move(callback), original_response_headers,
      override_response_headers, endpoint, preserve_fragment_on_redirect_url);
}

// Test that cookie expiration times are adjusted for server/client clock
// skew and that we handle incorrect timezone specifier "UTC" in HTTP Date
// headers by defaulting to GMT. (crbug.com/135131)
TEST_F(URLRequestTest, AcceptClockSkewCookieWithWrongDateTimezone) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<FixedDateNetworkDelegate>("04-Jan-2004 04:09:25 UTC"));
  auto context = context_builder->Build();

  // Set up an expired cookie.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context,
        test_server.GetURL(
            "/set-cookie?StillGood=1;expires=Mon,18-Apr-1977,22:50:13,GMT"),
        &d);
    req->Start();
    d.RunUntilComplete();
  }
  // Verify that the cookie is not set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context, test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("StillGood=1") == std::string::npos);
  }
  // Set up a cookie with clock skew and "UTC" HTTP Date timezone specifier.
  {
    TestDelegate d;
    network_delegate.set_fixed_date("18-Apr-1977 22:49:13 UTC");
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context,
        test_server.GetURL(
            "/set-cookie?StillGood=1;expires=Mon,18-Apr-1977,22:50:13,GMT"),
        &d);
    req->Start();
    d.RunUntilComplete();
  }
  // Verify that the cookie is set.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        *context, test_server.GetURL("/echoheader?Cookie"), &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("StillGood=1") != std::string::npos);
  }
}

// Check that it is impossible to change the referrer in the extra headers of
// an URLRequest.
TEST_F(URLRequestTest, DoNotOverrideReferrer) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  // If extra headers contain referer and the request contains a referer,
  // only the latter shall be respected.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetReferrer("http://foo.com/");

    HttpRequestHeaders headers;
    headers.SetHeader(HttpRequestHeaders::kReferer, "http://bar.com/");
    req->SetExtraRequestHeaders(headers);

    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ("http://foo.com/", d.data_received());
  }

  // If extra headers contain a referer but the request does not, no referer
  // shall be sent in the header.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    HttpRequestHeaders headers;
    headers.SetHeader(HttpRequestHeaders::kReferer, "http://bar.com/");
    req->SetExtraRequestHeaders(headers);
    req->SetLoadFlags(LOAD_VALIDATE_CACHE);

    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ("None", d.data_received());
  }
}

class URLRequestTestHTTP : public URLRequestTest {
 public:
  const url::Origin origin1_;
  const url::Origin origin2_;
  const IsolationInfo isolation_info1_;
  const IsolationInfo isolation_info2_;

  URLRequestTestHTTP()
      : origin1_(url::Origin::Create(GURL("https://foo.test/"))),
        origin2_(url::Origin::Create(GURL("https://bar.test/"))),
        isolation_info1_(IsolationInfo::CreateForInternalRequest(origin1_)),
        isolation_info2_(IsolationInfo::CreateForInternalRequest(origin2_)),
        test_server_(base::FilePath(kTestFilePath)) {
  }

 protected:
  // ProtocolHandler for the scheme that's unsafe to redirect to.
  class NET_EXPORT UnsafeRedirectProtocolHandler
      : public URLRequestJobFactory::ProtocolHandler {
   public:
    UnsafeRedirectProtocolHandler() = default;

    UnsafeRedirectProtocolHandler(const UnsafeRedirectProtocolHandler&) =
        delete;
    UnsafeRedirectProtocolHandler& operator=(
        const UnsafeRedirectProtocolHandler&) = delete;

    ~UnsafeRedirectProtocolHandler() override = default;

    // URLRequestJobFactory::ProtocolHandler implementation:

    std::unique_ptr<URLRequestJob> CreateJob(
        URLRequest* request) const override {
      NOTREACHED();
    }

    bool IsSafeRedirectTarget(const GURL& location) const override {
      return false;
    }
  };

  // URLRequestTest interface:
  void SetUpContextBuilder(URLRequestContextBuilder& builder) override {
    // Add support for an unsafe scheme to the default URLRequestContext.
    builder.SetProtocolHandler(
        "unsafe", std::make_unique<UnsafeRedirectProtocolHandler>());
  }

  // Requests |redirect_url|, which must return a HTTP 3xx redirect.
  // |request_method| is the method to use for the initial request.
  // |redirect_method| is the method that is expected to be used for the second
  // request, after redirection.
  // If |include_data| is true, data is uploaded with the request.  The
  // response body is expected to match it exactly, if and only if
  // |request_method| == |redirect_method|.
  void HTTPRedirectMethodTest(const GURL& redirect_url,
                              const std::string& request_method,
                              const std::string& redirect_method,
                              bool include_data) {
    static const char kData[] = "hello world";
    TestDelegate d;
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(default_context(), redirect_url, &d);
    req->set_method(request_method);
    if (include_data) {
      req->set_upload(
          CreateSimpleUploadData(base::byte_span_from_cstring(kData)));
      HttpRequestHeaders headers;
      headers.SetHeader(HttpRequestHeaders::kContentLength,
                        base::NumberToString(std::size(kData) - 1));
      headers.SetHeader(HttpRequestHeaders::kContentType, "text/plain");
      req->SetExtraRequestHeaders(headers);
    }
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(redirect_method, req->method());
    EXPECT_EQ(OK, d.request_status());
    if (include_data) {
      if (request_method == redirect_method) {
        EXPECT_TRUE(req->extra_request_headers().HasHeader(
            HttpRequestHeaders::kContentLength));
        EXPECT_TRUE(req->extra_request_headers().HasHeader(
            HttpRequestHeaders::kContentType));
        EXPECT_EQ(kData, d.data_received());
      } else {
        EXPECT_FALSE(req->extra_request_headers().HasHeader(
            HttpRequestHeaders::kContentLength));
        EXPECT_FALSE(req->extra_request_headers().HasHeader(
            HttpRequestHeaders::kContentType));
        EXPECT_NE(kData, d.data_received());
      }
    }
    if (HasFailure())
      LOG(WARNING) << "Request method was: " << request_method;
  }

  // Requests |redirect_url|, which must return a HTTP 3xx redirect. It's also
  // used as the initial origin.
  // |request_method| is the method to use for the initial request.
  // |redirect_method| is the method that is expected to be used for the second
  // request, after redirection.
  // |expected_origin_value| is the expected value for the Origin header after
  // redirection. If empty, expects that there will be no Origin header.
  void HTTPRedirectOriginHeaderTest(const GURL& redirect_url,
                                    const std::string& request_method,
                                    const std::string& redirect_method,
                                    const std::string& expected_origin_value) {
    TestDelegate d;
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(default_context(), redirect_url, &d);
    req->set_method(request_method);
    req->SetExtraRequestHeaderByName(
        HttpRequestHeaders::kOrigin,
        redirect_url.DeprecatedGetOriginAsURL().spec(), false);
    req->Start();

    d.RunUntilComplete();

    EXPECT_EQ(redirect_method, req->method());
    // Note that there is no check for request success here because, for
    // purposes of testing, the request very well may fail. For example, if the
    // test redirects to an HTTPS server from an HTTP origin, thus it is cross
    // origin, there is not an HTTPS server in this unit test framework, so the
    // request would fail. However, that's fine, as long as the request headers
    // are in order and pass the checks below.
    if (expected_origin_value.empty()) {
      EXPECT_FALSE(
          req->extra_request_headers().HasHeader(HttpRequestHeaders::kOrigin));
    } else {
      EXPECT_EQ(expected_origin_value, req->extra_request_headers().GetHeader(
                                           HttpRequestHeaders::kOrigin));
    }
  }

  void HTTPUploadDataOperationTest(const std::string& method) {
    const int kMsgSize = 20000;  // multiple of 10
    const int kIterations = 50;
    auto uploadBytes = base::HeapArray<char>::Uninit(kMsgSize);
    char* ptr = uploadBytes.data();
    char marker = 'a';
    for (int idx = 0; idx < kMsgSize / 10; idx++) {
      memcpy(ptr, "----------", 10);
      ptr += 10;
      if (idx % 100 == 0) {
        ptr--;
        *ptr++ = marker;
        if (++marker > 'z')
          marker = 'a';
      }
    }

    for (int i = 0; i < kIterations; ++i) {
      TestDelegate d;
      std::unique_ptr<URLRequest> r(default_context().CreateRequest(
          test_server_.GetURL("/echo"), DEFAULT_PRIORITY, &d,
          TRAFFIC_ANNOTATION_FOR_TESTS));
      r->set_method(method);

      r->set_upload(
          CreateSimpleUploadData(base::as_bytes(uploadBytes.as_span())));

      r->Start();
      EXPECT_TRUE(r->is_pending());

      d.RunUntilComplete();

      ASSERT_EQ(1, d.response_started_count())
          << "request failed. Error: " << d.request_status();

      EXPECT_FALSE(d.received_data_before_response());
      EXPECT_EQ(base::as_string_view(uploadBytes.as_span()), d.data_received());
    }
  }

  HttpTestServer* http_test_server() { return &test_server_; }

 private:
  base::test::ScopedFeatureList feature_list_;

  HttpTestServer test_server_;
};

namespace {

std::unique_ptr<test_server::HttpResponse> HandleRedirectConnect(
    const test_server::HttpRequest& request) {
  if (request.headers.find("Host") == request.headers.end() ||
      request.headers.at("Host") != "www.redirect.com" ||
      request.method != test_server::METHOD_CONNECT) {
    return nullptr;
  }

  auto http_response = std::make_unique<test_server::BasicHttpResponse>();
  http_response->set_code(HTTP_FOUND);
  http_response->AddCustomHeader("Location",
                                 "http://www.destination.com/foo.js");
  return std::move(http_response);
}

}  // namespace

// In this unit test, we're using the HTTPTestServer as a proxy server and
// issuing a CONNECT request with the magic host name "www.redirect.com".
// The EmbeddedTestServer will return a 302 response, which we should not
// follow.
TEST_F(URLRequestTestHTTP, ProxyTunnelRedirectTest) {
  http_test_server()->RegisterRequestHandler(
      base::BindRepeating(&HandleRedirectConnect));
  ASSERT_TRUE(http_test_server()->Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService(
          http_test_server()->host_port_pair().ToString()));
  auto context = context_builder->Build();

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(context->CreateRequest(
        GURL("https://www.redirect.com/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    // The proxy chain should be set before failure.
    EXPECT_EQ(ProxyChain(ProxyServer::SCHEME_HTTP,
                         http_test_server()->host_port_pair()),
              r->proxy_chain());
    EXPECT_EQ(ERR_TUNNEL_CONNECTION_FAILED, d.request_status());
    EXPECT_EQ(1, d.response_started_count());
    // We should not have followed the redirect.
    EXPECT_EQ(0, d.received_redirect_count());
  }
}

// This is the same as the previous test, but chec
```