Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/url_request/url_request_unittest.cc`. They are also interested in any relationships with Javascript, logical reasoning with inputs and outputs, common user errors, and debugging tips.

**Functionality Breakdown:**

The code snippet consists of several test cases within the `URLRequestTest` and `URLRequestLoadTimingTest` classes. These test cases primarily focus on verifying the behavior of `URLRequest` in various scenarios, including:

1. **Referrer Policy Recording:** Tests if the `URLRequest` correctly records the referrer policy used for requests and reports it through histograms.
2. **Informative Referrer Recording:** Tests if the `URLRequest` correctly identifies and records whether a referrer contains an informative path or query, using histograms to track the results.
3. **Load Timing Information Injection and Verification:**  Uses a custom interceptor to inject specific `LoadTimingInfo` into `URLRequestJob` and verifies that the `URLRequest` correctly retrieves and maintains this information. It checks scenarios with and without proxy, with and without SSL/DNS times, and cases where connection times occur before the request start.
4. **Network Delegate Proxy Error Handling:** Simulates a proxy connection error and checks if the `URLRequest` and `NetworkDelegate` report the error correctly.
5. **DNS-based Scheme Upgrades (HTTP to HTTPS, WS to WSS):** Tests if the `URLRequest` automatically upgrades the scheme from HTTP to HTTPS or WS to WSS when the DNS record indicates that the domain is HTTPS-only. It checks both immediate and deferred redirects.
6. **No Scheme Upgrade When No HTTPS Record:** Verifies that the scheme is not upgraded if the DNS record does not indicate HTTPS-only.
7. **Secure DNS Policy Setting:** Tests if the `URLRequest`'s `SetSecureDnsPolicy` method correctly influences the Secure DNS policy used during host resolution.
8. **Request Completion for Empty Responses:** Checks if the `NetworkDelegate::NotifyCompleted` method is called correctly even for responses with no content.
9. **Setting Request Priority:** Tests if the `URLRequest`'s priority can be set correctly before and after starting the request.

**Relationship to Javascript:**

While this is C++ code, it tests the underlying network functionality that Javascript in web browsers relies on. For instance:

*   **Referrer Policy:** When a Javascript `fetch()` or `XMLHttpRequest` request is made, the browser uses the referrer policy (which this code tests) to decide what referrer information to send.
*   **Scheme Upgrades:** If a Javascript attempts to load an `http://` resource and the browser knows the site supports HTTPS (through mechanisms like HSTS or DNS records, as tested here), the browser might automatically upgrade the request to `https://`.
*   **Load Timing:** The Performance API in Javascript (`performance.getEntriesByType("resource")`) exposes timing information about network requests, some of which corresponds to the `LoadTimingInfo` being tested here.

**Logical Reasoning (Hypothetical Input/Output):**

*   **Test Case:** `RecordsReferrrerWithInformativePath`
    *   **Input:** A URLRequest to "http://google.com/" with a referrer set to "http://google.com/very-informative-path".
    *   **Output:** Histograms "Net.URLRequest.ReferrerHasInformativePath.SameOrigin" and "Net.URLRequest.ReferrerHasInformativePath.CrossOrigin" will record `true` with a count of 1.

**Common User/Programming Errors:**

*   **Incorrectly setting referrer policy:** Developers might set overly restrictive referrer policies that break functionalities on other websites. These tests ensure the correct interpretation and application of these policies.
*   **Assuming HTTP will always work:** Developers might not anticipate automatic HTTPS upgrades and might have issues if their servers don't support HTTPS when the browser expects it. The DNS upgrade tests highlight this.
*   **Misinterpreting Load Timing data:** Developers using the Performance API need to understand the different timing components. These tests ensure the accuracy of the underlying timing information.

**User Operation to Reach This Code (Debugging Context):**

Imagine a web developer is investigating why a particular network request is being redirected or why it's taking longer than expected. They might:

1. **Open Chrome DevTools:** Go to the "Network" tab.
2. **Observe a redirect:** See an HTTP request initially made to `http://example.com` being redirected to `https://example.com`.
3. **Investigate the redirect:** They might suspect the server is doing the redirect, but want to confirm if the browser itself initiated the upgrade.
4. **Look at request headers:** They might not see a server-initiated redirect in the initial request.
5. **Consider browser-initiated upgrades:** This might lead them to investigate Chromium's network stack behavior regarding automatic HTTPS upgrades based on DNS records.
6. **Search Chromium source:** They might search for "DNS HTTPS upgrade" or "ERR_DNS_NAME_HTTPS_ONLY" in the Chromium source code and find these unit tests in `url_request_unittest.cc`. These tests would give them insights into how this mechanism works.
7. **Examine Load Timing:** If the performance is the concern, the developer might inspect the "Timing" tab in DevTools, which relies on the `LoadTimingInfo` being tested here. If the timings are unexpected, they might investigate the Chromium source to understand how these timings are collected and whether there are edge cases (like early proxy resolution) that affect them.

**Summary of Functionality (Part 2):**

This section of `url_request_unittest.cc` focuses on testing the `URLRequest`'s behavior related to:

*   **Referrer handling:** Validating how referrer policies are applied and whether informative referrers are correctly identified and recorded.
*   **Load timing information:** Ensuring that `URLRequest` can correctly handle and expose detailed timing information, even in complex scenarios involving proxies, SSL, and socket reuse.
*   **Error handling related to proxies:**  Verifying the correct reporting of proxy connection errors.
*   **Automatic scheme upgrades:** Confirming the browser's ability to upgrade HTTP to HTTPS (and WS to WSS) based on DNS information.
*   **Secure DNS policy:** Checking that the Secure DNS policy can be set and affects host resolution.
*   **Handling empty responses:** Making sure responses without content are processed correctly.
*   **Setting request priority:** Validating the functionality of setting the request priority.

这是 `net/url_request/url_request_unittest.cc` 文件的第 2 部分，主要功能是测试 `URLRequest` 类的各种行为，特别是关于 **referrer policy、referrer 信息的记录、请求加载时序信息的处理、代理错误的处理以及基于 DNS 记录的协议升级**。

**功能归纳:**

1. **测试 Referrer Policy 的记录:** 验证 `URLRequest` 是否正确记录并上报请求的 referrer policy 到直方图。
2. **测试 Referrer 信息的记录:** 验证 `URLRequest` 是否能识别并记录 referrer URL 是否包含有意义的路径或查询参数，并将其记录到直方图中。
3. **测试请求加载时序信息的处理:**  通过自定义的 `URLRequestInterceptor` 注入特定的 `LoadTimingInfo`，然后验证 `URLRequest` 能否正确获取和维护这些信息。测试了正常情况、连接复用、使用代理以及连接建立时间早于请求开始时间等多种场景。
4. **测试网络代理错误的处理:** 模拟网络代理连接失败的情况，并验证 `URLRequest` 和 `NetworkDelegate` 是否能正确报告错误信息。
5. **测试基于 DNS 记录的协议升级:** 验证当 DNS 记录指示目标主机仅支持 HTTPS 时，`URLRequest` 是否能自动将 `http://` 请求升级为 `https://` 请求，以及将 `ws://` 请求升级为 `wss://` 请求。 包括了立即重定向和延迟重定向两种情况。
6. **测试当 DNS 记录不存在 HTTPS 信息时不进行协议升级:** 验证在没有 HTTPS DNS 记录的情况下，`URLRequest` 不会进行自动的协议升级。
7. **测试安全 DNS 策略的设置:** 验证可以通过 `URLRequest::SetSecureDnsPolicy` 方法设置安全 DNS 策略。
8. **测试空响应的处理:** 验证即使响应内容为空，`NetworkDelegate::NotifyCompleted` 也会被调用。
9. **测试设置请求优先级:** 验证 `URLRequest::SetPriority` 方法可以正确设置请求的优先级。

**与 Javascript 的关系举例:**

*   **Referrer Policy:** 当 Javascript 代码使用 `fetch()` 或 `XMLHttpRequest` 发起网络请求时，浏览器会根据设置的 referrer policy 决定发送哪些 referrer 信息。 这部分测试验证了 `URLRequest` 在 C++ 层面正确处理了这些策略。
    *   **例子:** Javascript 代码 `fetch('https://example.com', {referrerPolicy: 'no-referrer-when-downgrade'})`  的执行会触发 `URLRequest` 按照 `no-referrer-when-downgrade` 策略设置 referrer，相关的测试会验证这个过程在网络栈中的正确性。
*   **协议升级:** 当 Javascript 代码尝试访问一个 `http://` 资源，但浏览器通过 DNS 记录得知该站点支持 HTTPS 时，浏览器会自动将请求升级为 `https://`。 这部分测试验证了这种升级机制的正确性。
    *   **例子:** Javascript 代码 `window.location.href = 'http://foo.a.test'`，如果 `foo.a.test` 存在 HTTPS DNS 记录，则浏览器实际会发起 `https://foo.a.test` 的请求，这部分测试覆盖了这种场景。
*   **请求加载时序:**  Javascript 的 Performance API (例如 `performance.timing` 或 `performance.getEntriesByType('resource')`) 可以获取网络请求的详细时间信息，这些信息很大程度上来源于 `URLRequest` 中记录的 `LoadTimingInfo`。 这部分测试确保了这些底层时间信息的准确性。

**逻辑推理 (假设输入与输出):**

*   **测试用例:** `RecordsReferrrerWithInformativePath`
    *   **假设输入:**  创建一个访问 `http://google.com/` 的 `URLRequest`，并设置 referrer 为 `http://google.com/very-informative-path`。
    *   **预期输出:**  直方图 "Net.URLRequest.ReferrerHasInformativePath.SameOrigin" 和 "Net.URLRequest.ReferrerHasInformativePath.CrossOrigin" 的 `true` bucket 的计数都会增加 1。
*   **测试用例:** `DnsNameHttpsOnlyErrorCausesSchemeUpgrade`
    *   **假设输入:**  创建一个访问 `http://foo.a.test/defaultresponse` 的 `URLRequest`，并且 MockHostResolver 配置为当请求 `http://foo.a.test` 时返回 `ERR_DNS_NAME_HTTPS_ONLY`，请求 `https://foo.a.test` 时返回 IP 地址。
    *   **预期输出:**  `URLRequest` 的 URL 会被升级为 `https://foo.a.test/defaultresponse`，并且请求会成功完成，响应码为 200。

**用户或编程常见的使用错误举例说明:**

*   **Referrer Policy 设置错误:**  开发者可能会错误地配置 referrer policy，导致一些网站功能失效或者隐私泄露。例如，设置了过于严格的 `no-referrer` 策略可能会导致一些需要 referrer 信息的请求失败。 这部分测试确保了 `URLRequest` 能正确按照策略执行，有助于开发者理解和避免这些错误。
*   **误判 HTTP 可以访问:** 开发者可能没有考虑到浏览器会自动升级到 HTTPS 的情况，仍然假设 HTTP 可以正常访问，导致在某些配置下出现连接问题。例如，如果一个站点只配置了 HTTPS DNS 记录，但开发者仍然使用 HTTP 链接，则会被自动升级，如果服务器没有正确配置 HTTPS，则会出错。 这部分测试验证了这种升级行为。
*   **不理解请求加载时序:** 开发者在使用 Performance API 分析性能时，可能不理解各个时间点的含义，导致分析结果错误。 这部分测试确保了 `URLRequest` 记录的加载时序信息是准确的，帮助开发者更好地理解性能数据。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个用户报告说，在某个网站上点击一个 HTTP 链接后，浏览器没有加载 HTTP 内容，反而跳转到了 HTTPS，并且页面似乎空白。 作为开发者，进行调试的步骤可能如下：

1. **检查开发者工具的网络面板:** 查看请求的 URL，发现最初的 HTTP 请求被重定向到了 HTTPS。
2. **检查响应头:** 查看 HTTP 请求的响应头，看是否有服务器端的 301 或 302 重定向。 如果没有，则可能不是服务器发起的重定向。
3. **怀疑浏览器行为:** 考虑到浏览器可能会进行自动的 HTTPS 升级。
4. **查找相关 Chromium 代码:**  搜索 Chromium 源码，关键词可能包括 "HTTPS upgrade", "DNS HTTPS", "ERR_DNS_NAME_HTTPS_ONLY"。
5. **定位到 `url_request_unittest.cc`:** 可能会找到包含 `DnsNameHttpsOnlyErrorCausesSchemeUpgrade` 等测试用例的这段代码。
6. **阅读测试代码:**  通过阅读测试代码，开发者可以了解到浏览器在遇到 `ERR_DNS_NAME_HTTPS_ONLY` 错误时会将 HTTP 请求升级到 HTTPS，这解释了用户遇到的情况。 这表明问题可能在于该域名的 DNS 记录指示其仅支持 HTTPS。
7. **进一步排查 DNS 配置:**  开发者可以检查该域名的 DNS 配置，确认是否存在 HTTPS 记录，从而最终定位问题。

**总结:** 这部分代码通过一系列单元测试，详细地验证了 Chromium 网络栈中 `URLRequest` 类在处理 referrer 信息、请求加载时序、网络代理错误以及基于 DNS 的协议升级等关键功能时的正确性和健壮性，为理解浏览器网络行为提供了重要的参考。

Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共17部分，请归纳一下它的功能

"""
google.com");

  req->set_referrer_policy(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE);

  base::HistogramTester histograms;

  req->Start();
  d.RunUntilRedirect();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerPolicyForRequest.SameOrigin",
      static_cast<int>(
          ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE),
      1);
  req->FollowDeferredRedirect(/*removed_headers=*/std::nullopt,
                              /*modified_headers=*/std::nullopt);
  d.RunUntilComplete();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerPolicyForRequest.CrossOrigin",
      static_cast<int>(
          ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE),
      1);
}

TEST_F(URLRequestTest, RecordsReferrrerWithInformativePath) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto network_delegate = std::make_unique<BlockingNetworkDelegate>(
      BlockingNetworkDelegate::SYNCHRONOUS);
  network_delegate->set_cancel_request_with_policy_violating_referrer(true);
  network_delegate->set_redirect_url(GURL("http://redirect.com/"));
  context_builder->set_network_delegate(std::move(network_delegate));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://google.com/"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  // Since this referrer is much more informative than the initiating origin,
  // we should see the histograms' true buckets populated.
  req->SetReferrer("http://google.com/very-informative-path");

  base::HistogramTester histograms;

  req->Start();
  d.RunUntilRedirect();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerHasInformativePath.SameOrigin",
      /* Check the count of the "true" bucket in the boolean histogram. */ true,
      1);
  req->FollowDeferredRedirect(/*removed_headers=*/std::nullopt,
                              /*modified_headers=*/std::nullopt);
  d.RunUntilComplete();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerHasInformativePath.CrossOrigin", true, 1);
}

TEST_F(URLRequestTest, RecordsReferrerWithInformativeQuery) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto network_delegate = std::make_unique<BlockingNetworkDelegate>(
      BlockingNetworkDelegate::SYNCHRONOUS);
  network_delegate->set_cancel_request_with_policy_violating_referrer(true);
  network_delegate->set_redirect_url(GURL("http://redirect.com/"));
  context_builder->set_network_delegate(std::move(network_delegate));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://google.com/"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  // Since this referrer is much more informative than the initiating origin,
  // we should see the histograms' true buckets populated.
  req->SetReferrer("http://google.com/?very-informative-query");

  base::HistogramTester histograms;

  req->Start();
  d.RunUntilRedirect();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerHasInformativePath.SameOrigin",
      /* Check the count of the "true" bucket in the boolean histogram. */ true,
      1);
  req->FollowDeferredRedirect(/*removed_headers=*/std::nullopt,
                              /*modified_headers=*/std::nullopt);
  d.RunUntilComplete();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerHasInformativePath.CrossOrigin", true, 1);
}

TEST_F(URLRequestTest, RecordsReferrerWithoutInformativePathOrQuery) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto network_delegate = std::make_unique<BlockingNetworkDelegate>(
      BlockingNetworkDelegate::SYNCHRONOUS);
  network_delegate->set_cancel_request_with_policy_violating_referrer(false);
  network_delegate->set_redirect_url(GURL("http://origin.com/"));
  context_builder->set_network_delegate(std::move(network_delegate));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://google.com/"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));

  // Since this referrer _isn't_ more informative than the initiating origin,
  // we should see the histograms' false buckets populated.
  req->SetReferrer("http://origin.com");

  base::HistogramTester histograms;

  req->Start();
  d.RunUntilRedirect();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerHasInformativePath.CrossOrigin", false, 1);
  req->FollowDeferredRedirect(/*removed_headers=*/std::nullopt,
                              /*modified_headers=*/std::nullopt);
  d.RunUntilComplete();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerHasInformativePath.SameOrigin", false, 1);
}

// A URLRequestInterceptor that allows setting the LoadTimingInfo value of the
// URLRequestJobs it creates.
class URLRequestInterceptorWithLoadTimingInfo : public URLRequestInterceptor {
 public:
  // Static getters for canned response header and data strings.
  static std::string ok_data() { return URLRequestTestJob::test_data_1(); }

  static std::string ok_headers() { return URLRequestTestJob::test_headers(); }

  URLRequestInterceptorWithLoadTimingInfo() = default;
  ~URLRequestInterceptorWithLoadTimingInfo() override = default;

  // URLRequestInterceptor implementation:
  std::unique_ptr<URLRequestJob> MaybeInterceptRequest(
      URLRequest* request) const override {
    std::unique_ptr<URLRequestTestJob> job =
        std::make_unique<URLRequestTestJob>(request, ok_headers(), ok_data(),
                                            true);
    job->set_load_timing_info(main_request_load_timing_info_);
    return job;
  }

  void set_main_request_load_timing_info(
      const LoadTimingInfo& main_request_load_timing_info) {
    main_request_load_timing_info_ = main_request_load_timing_info;
  }

 private:
  mutable LoadTimingInfo main_request_load_timing_info_;
};

// These tests inject a MockURLRequestInterceptor
class URLRequestLoadTimingTest : public URLRequestTest {
 public:
  URLRequestLoadTimingTest() {
    std::unique_ptr<URLRequestInterceptorWithLoadTimingInfo> interceptor =
        std::make_unique<URLRequestInterceptorWithLoadTimingInfo>();
    interceptor_ = interceptor.get();
    URLRequestFilter::GetInstance()->AddHostnameInterceptor(
        "http", "test_intercept", std::move(interceptor));
  }

  ~URLRequestLoadTimingTest() override {
    URLRequestFilter::GetInstance()->ClearHandlers();
  }

  URLRequestInterceptorWithLoadTimingInfo* interceptor() const {
    return interceptor_;
  }

 private:
  raw_ptr<URLRequestInterceptorWithLoadTimingInfo, DanglingUntriaged>
      interceptor_;
};

// "Normal" LoadTimingInfo as returned by a job.  Everything is in order, not
// reused.  |connect_time_flags| is used to indicate if there should be dns
// or SSL times, and |used_proxy| is used for proxy times.
LoadTimingInfo NormalLoadTimingInfo(base::TimeTicks now,
                                    int connect_time_flags,
                                    bool used_proxy) {
  LoadTimingInfo load_timing;
  load_timing.socket_log_id = 1;

  if (used_proxy) {
    load_timing.proxy_resolve_start = now + base::Days(1);
    load_timing.proxy_resolve_end = now + base::Days(2);
  }

  LoadTimingInfo::ConnectTiming& connect_timing = load_timing.connect_timing;
  if (connect_time_flags & CONNECT_TIMING_HAS_DNS_TIMES) {
    connect_timing.domain_lookup_start = now + base::Days(3);
    connect_timing.domain_lookup_end = now + base::Days(4);
  }
  connect_timing.connect_start = now + base::Days(5);
  if (connect_time_flags & CONNECT_TIMING_HAS_SSL_TIMES) {
    connect_timing.ssl_start = now + base::Days(6);
    connect_timing.ssl_end = now + base::Days(7);
  }
  connect_timing.connect_end = now + base::Days(8);

  load_timing.send_start = now + base::Days(9);
  load_timing.send_end = now + base::Days(10);
  load_timing.receive_headers_start = now + base::Days(11);
  load_timing.receive_headers_end = now + base::Days(12);
  return load_timing;
}

// Same as above, but in the case of a reused socket.
LoadTimingInfo NormalLoadTimingInfoReused(base::TimeTicks now,
                                          bool used_proxy) {
  LoadTimingInfo load_timing;
  load_timing.socket_log_id = 1;
  load_timing.socket_reused = true;

  if (used_proxy) {
    load_timing.proxy_resolve_start = now + base::Days(1);
    load_timing.proxy_resolve_end = now + base::Days(2);
  }

  load_timing.send_start = now + base::Days(9);
  load_timing.send_end = now + base::Days(10);
  load_timing.receive_headers_start = now + base::Days(11);
  load_timing.receive_headers_end = now + base::Days(12);
  return load_timing;
}

LoadTimingInfo RunURLRequestInterceptorLoadTimingTest(
    const LoadTimingInfo& job_load_timing,
    const URLRequestContext& context,
    URLRequestInterceptorWithLoadTimingInfo* interceptor) {
  interceptor->set_main_request_load_timing_info(job_load_timing);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context.CreateRequest(GURL("http://test_intercept/foo"), DEFAULT_PRIORITY,
                            &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  LoadTimingInfo resulting_load_timing;
  req->GetLoadTimingInfo(&resulting_load_timing);

  // None of these should be modified by the URLRequest.
  EXPECT_EQ(job_load_timing.socket_reused, resulting_load_timing.socket_reused);
  EXPECT_EQ(job_load_timing.socket_log_id, resulting_load_timing.socket_log_id);
  EXPECT_EQ(job_load_timing.send_start, resulting_load_timing.send_start);
  EXPECT_EQ(job_load_timing.send_end, resulting_load_timing.send_end);
  EXPECT_EQ(job_load_timing.receive_headers_start,
            resulting_load_timing.receive_headers_start);
  EXPECT_EQ(job_load_timing.receive_headers_end,
            resulting_load_timing.receive_headers_end);
  EXPECT_EQ(job_load_timing.push_start, resulting_load_timing.push_start);
  EXPECT_EQ(job_load_timing.push_end, resulting_load_timing.push_end);

  return resulting_load_timing;
}

// Basic test that the intercept + load timing tests work.
TEST_F(URLRequestLoadTimingTest, InterceptLoadTiming) {
  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo job_load_timing =
      NormalLoadTimingInfo(now, CONNECT_TIMING_HAS_DNS_TIMES, false);

  LoadTimingInfo load_timing_result = RunURLRequestInterceptorLoadTimingTest(
      job_load_timing, default_context(), interceptor());

  // Nothing should have been changed by the URLRequest.
  EXPECT_EQ(job_load_timing.proxy_resolve_start,
            load_timing_result.proxy_resolve_start);
  EXPECT_EQ(job_load_timing.proxy_resolve_end,
            load_timing_result.proxy_resolve_end);
  EXPECT_EQ(job_load_timing.connect_timing.domain_lookup_start,
            load_timing_result.connect_timing.domain_lookup_start);
  EXPECT_EQ(job_load_timing.connect_timing.domain_lookup_end,
            load_timing_result.connect_timing.domain_lookup_end);
  EXPECT_EQ(job_load_timing.connect_timing.connect_start,
            load_timing_result.connect_timing.connect_start);
  EXPECT_EQ(job_load_timing.connect_timing.connect_end,
            load_timing_result.connect_timing.connect_end);
  EXPECT_EQ(job_load_timing.connect_timing.ssl_start,
            load_timing_result.connect_timing.ssl_start);
  EXPECT_EQ(job_load_timing.connect_timing.ssl_end,
            load_timing_result.connect_timing.ssl_end);

  // Redundant sanity check.
  TestLoadTimingNotReused(load_timing_result, CONNECT_TIMING_HAS_DNS_TIMES);
}

// Another basic test, with proxy and SSL times, but no DNS times.
TEST_F(URLRequestLoadTimingTest, InterceptLoadTimingProxy) {
  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo job_load_timing =
      NormalLoadTimingInfo(now, CONNECT_TIMING_HAS_SSL_TIMES, true);

  LoadTimingInfo load_timing_result = RunURLRequestInterceptorLoadTimingTest(
      job_load_timing, default_context(), interceptor());

  // Nothing should have been changed by the URLRequest.
  EXPECT_EQ(job_load_timing.proxy_resolve_start,
            load_timing_result.proxy_resolve_start);
  EXPECT_EQ(job_load_timing.proxy_resolve_end,
            load_timing_result.proxy_resolve_end);
  EXPECT_EQ(job_load_timing.connect_timing.domain_lookup_start,
            load_timing_result.connect_timing.domain_lookup_start);
  EXPECT_EQ(job_load_timing.connect_timing.domain_lookup_end,
            load_timing_result.connect_timing.domain_lookup_end);
  EXPECT_EQ(job_load_timing.connect_timing.connect_start,
            load_timing_result.connect_timing.connect_start);
  EXPECT_EQ(job_load_timing.connect_timing.connect_end,
            load_timing_result.connect_timing.connect_end);
  EXPECT_EQ(job_load_timing.connect_timing.ssl_start,
            load_timing_result.connect_timing.ssl_start);
  EXPECT_EQ(job_load_timing.connect_timing.ssl_end,
            load_timing_result.connect_timing.ssl_end);

  // Redundant sanity check.
  TestLoadTimingNotReusedWithProxy(load_timing_result,
                                   CONNECT_TIMING_HAS_SSL_TIMES);
}

// Make sure that URLRequest correctly adjusts proxy times when they're before
// |request_start|, due to already having a connected socket.  This happens in
// the case of reusing a SPDY session.  The connected socket is not considered
// reused in this test (May be a preconnect).
//
// To mix things up from the test above, assumes DNS times but no SSL times.
TEST_F(URLRequestLoadTimingTest, InterceptLoadTimingEarlyProxyResolution) {
  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo job_load_timing =
      NormalLoadTimingInfo(now, CONNECT_TIMING_HAS_DNS_TIMES, true);
  job_load_timing.proxy_resolve_start = now - base::Days(6);
  job_load_timing.proxy_resolve_end = now - base::Days(5);
  job_load_timing.connect_timing.domain_lookup_start = now - base::Days(4);
  job_load_timing.connect_timing.domain_lookup_end = now - base::Days(3);
  job_load_timing.connect_timing.connect_start = now - base::Days(2);
  job_load_timing.connect_timing.connect_end = now - base::Days(1);

  LoadTimingInfo load_timing_result = RunURLRequestInterceptorLoadTimingTest(
      job_load_timing, default_context(), interceptor());

  // Proxy times, connect times, and DNS times should all be replaced with
  // request_start.
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.proxy_resolve_start);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.proxy_resolve_end);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.domain_lookup_start);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.domain_lookup_end);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.connect_start);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.connect_end);

  // Other times should have been left null.
  TestLoadTimingNotReusedWithProxy(load_timing_result,
                                   CONNECT_TIMING_HAS_DNS_TIMES);
}

// Same as above, but in the reused case.
TEST_F(URLRequestLoadTimingTest,
       InterceptLoadTimingEarlyProxyResolutionReused) {
  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo job_load_timing = NormalLoadTimingInfoReused(now, true);
  job_load_timing.proxy_resolve_start = now - base::Days(4);
  job_load_timing.proxy_resolve_end = now - base::Days(3);

  LoadTimingInfo load_timing_result = RunURLRequestInterceptorLoadTimingTest(
      job_load_timing, default_context(), interceptor());

  // Proxy times and connect times should all be replaced with request_start.
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.proxy_resolve_start);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.proxy_resolve_end);

  // Other times should have been left null.
  TestLoadTimingReusedWithProxy(load_timing_result);
}

// Make sure that URLRequest correctly adjusts connect times when they're before
// |request_start|, due to reusing a connected socket.  The connected socket is
// not considered reused in this test (May be a preconnect).
//
// To mix things up, the request has SSL times, but no DNS times.
TEST_F(URLRequestLoadTimingTest, InterceptLoadTimingEarlyConnect) {
  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo job_load_timing =
      NormalLoadTimingInfo(now, CONNECT_TIMING_HAS_SSL_TIMES, false);
  job_load_timing.connect_timing.connect_start = now - base::Days(1);
  job_load_timing.connect_timing.ssl_start = now - base::Days(2);
  job_load_timing.connect_timing.ssl_end = now - base::Days(3);
  job_load_timing.connect_timing.connect_end = now - base::Days(4);

  LoadTimingInfo load_timing_result = RunURLRequestInterceptorLoadTimingTest(
      job_load_timing, default_context(), interceptor());

  // Connect times, and SSL times should be replaced with request_start.
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.connect_start);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.ssl_start);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.ssl_end);
  EXPECT_EQ(load_timing_result.request_start,
            load_timing_result.connect_timing.connect_end);

  // Other times should have been left null.
  TestLoadTimingNotReused(load_timing_result, CONNECT_TIMING_HAS_SSL_TIMES);
}

// Make sure that URLRequest correctly adjusts connect times when they're before
// |request_start|, due to reusing a connected socket in the case that there
// are also proxy times.  The connected socket is not considered reused in this
// test (May be a preconnect).
//
// In this test, there are no SSL or DNS times.
TEST_F(URLRequestLoadTimingTest, InterceptLoadTimingEarlyConnectWithProxy) {
  base::TimeTicks now = base::TimeTicks::Now();
  LoadTimingInfo job_load_timing =
      NormalLoadTimingInfo(now, CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY, true);
  job_load_timing.connect_timing.connect_start = now - base::Days(1);
  job_load_timing.connect_timing.connect_end = now - base::Days(2);

  LoadTimingInfo load_timing_result = RunURLRequestInterceptorLoadTimingTest(
      job_load_timing, default_context(), interceptor());

  // Connect times should be replaced with proxy_resolve_end.
  EXPECT_EQ(load_timing_result.proxy_resolve_end,
            load_timing_result.connect_timing.connect_start);
  EXPECT_EQ(load_timing_result.proxy_resolve_end,
            load_timing_result.connect_timing.connect_end);

  // Other times should have been left null.
  TestLoadTimingNotReusedWithProxy(load_timing_result,
                                   CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);
}

TEST_F(URLRequestTest, NetworkDelegateProxyError) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_proxy_resolution_service(
      CreateFixedProxyResolutionService("myproxy:70"));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddSimulatedTimeoutFailure("*");
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://example.com"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_method("GET");

  req->Start();
  d.RunUntilComplete();

  // Check we see a failed request.
  // The proxy chain should be set before failure.
  EXPECT_EQ(PacResultElementToProxyChain("PROXY myproxy:70"),
            req->proxy_chain());
  EXPECT_EQ(ERR_PROXY_CONNECTION_FAILED, d.request_status());
  EXPECT_THAT(req->response_info().resolve_error_info.error,
              IsError(ERR_DNS_TIMED_OUT));

  EXPECT_EQ(1, network_delegate.error_count());
  EXPECT_THAT(network_delegate.last_error(),
              IsError(ERR_PROXY_CONNECTION_FAILED));
  EXPECT_EQ(1, network_delegate.completed_requests());
}

// Test that when host resolution fails with `ERR_DNS_NAME_HTTPS_ONLY` for
// "http://" requests, scheme is upgraded to "https://".
TEST_F(URLRequestTest, DnsNameHttpsOnlyErrorCausesSchemeUpgrade) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  // Build an http URL that should be auto-upgraded to https.
  const std::string kHost = "foo.a.test";  // Covered by CERT_TEST_NAMES.
  const GURL https_url = https_server.GetURL(kHost, "/defaultresponse");
  GURL::Replacements replacements;
  replacements.SetSchemeStr(url::kHttpScheme);
  const GURL http_url = https_url.ReplaceComponents(replacements);

  // Return `ERR_DNS_NAME_HTTPS_ONLY` for "http://" requests and an address for
  // "https://" requests. This simulates the HostResolver behavior for a domain
  // with an HTTPS DNS record.
  auto host_resolver = std::make_unique<MockHostResolver>();
  MockHostResolverBase::RuleResolver::RuleKey unencrypted_resolve_key;
  unencrypted_resolve_key.scheme = url::kHttpScheme;
  unencrypted_resolve_key.hostname_pattern = kHost;
  host_resolver->rules()->AddRule(std::move(unencrypted_resolve_key),
                                  ERR_DNS_NAME_HTTPS_ONLY);
  MockHostResolverBase::RuleResolver::RuleKey encrypted_resolve_key;
  encrypted_resolve_key.scheme = url::kHttpsScheme;
  encrypted_resolve_key.hostname_pattern = kHost;
  host_resolver->rules()->AddRule(std::move(encrypted_resolve_key),
                                  https_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_FALSE(req->url().SchemeIsCryptographic());

  // Note that there is no http server running, so the request should fail or
  // hang if its scheme is not upgraded to https.
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(d.received_redirect_count(), 1);

  EXPECT_EQ(0, network_delegate.error_count());
  EXPECT_EQ(200, req->GetResponseCode());
  ASSERT_TRUE(req->response_headers());
  EXPECT_EQ(200, req->response_headers()->response_code());

  // Observe that the scheme has been upgraded to https.
  EXPECT_TRUE(req->url().SchemeIsCryptographic());
  EXPECT_TRUE(req->url().SchemeIs(url::kHttpsScheme));
}

// Test that DNS-based scheme upgrade supports deferred redirect.
TEST_F(URLRequestTest, DnsNameHttpsOnlyErrorCausesSchemeUpgradeDeferred) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  // Build an http URL that should be auto-upgraded to https.
  const std::string kHost = "foo.a.test";  // Covered by CERT_TEST_NAMES.
  const GURL https_url = https_server.GetURL(kHost, "/defaultresponse");
  GURL::Replacements replacements;
  replacements.SetSchemeStr(url::kHttpScheme);
  const GURL http_url = https_url.ReplaceComponents(replacements);

  // Return `ERR_DNS_NAME_HTTPS_ONLY` for "http://" requests and an address for
  // "https://" requests. This simulates the HostResolver behavior for a domain
  // with an HTTPS DNS record.
  auto host_resolver = std::make_unique<MockHostResolver>();
  MockHostResolverBase::RuleResolver::RuleKey unencrypted_resolve_key;
  unencrypted_resolve_key.scheme = url::kHttpScheme;
  unencrypted_resolve_key.hostname_pattern = kHost;
  host_resolver->rules()->AddRule(std::move(unencrypted_resolve_key),
                                  ERR_DNS_NAME_HTTPS_ONLY);
  MockHostResolverBase::RuleResolver::RuleKey encrypted_resolve_key;
  encrypted_resolve_key.scheme = url::kHttpsScheme;
  encrypted_resolve_key.hostname_pattern = kHost;
  host_resolver->rules()->AddRule(std::move(encrypted_resolve_key),
                                  https_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_FALSE(req->url().SchemeIsCryptographic());

  // Note that there is no http server running, so the request should fail or
  // hang if its scheme is not upgraded to https.
  req->Start();
  d.RunUntilRedirect();

  EXPECT_EQ(d.received_redirect_count(), 1);

  req->FollowDeferredRedirect(/*removed_headers=*/std::nullopt,
                              /*modified_headers=*/std::nullopt);
  d.RunUntilComplete();

  EXPECT_EQ(0, network_delegate.error_count());
  EXPECT_EQ(200, req->GetResponseCode());
  ASSERT_TRUE(req->response_headers());
  EXPECT_EQ(200, req->response_headers()->response_code());

  // Observe that the scheme has been upgraded to https.
  EXPECT_TRUE(req->url().SchemeIsCryptographic());
  EXPECT_TRUE(req->url().SchemeIs(url::kHttpsScheme));
}

#if BUILDFLAG(ENABLE_WEBSOCKETS)
// Test that requests with "ws" scheme are upgraded to "wss" when DNS
// indicates that the name is HTTPS-only.
TEST_F(URLRequestTest, DnsHttpsRecordPresentCausesWsSchemeUpgrade) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  // Build an http URL that should be auto-upgraded to https.
  const std::string kHost = "foo.a.test";  // Covered by CERT_TEST_NAMES.
  const GURL https_url = https_server.GetURL(kHost, "/defaultresponse");
  GURL::Replacements replacements;
  replacements.SetSchemeStr(url::kWsScheme);
  const GURL ws_url = https_url.ReplaceComponents(replacements);

  auto host_resolver = std::make_unique<MockHostResolver>();
  MockHostResolverBase::RuleResolver::RuleKey unencrypted_resolve_key;
  unencrypted_resolve_key.scheme = url::kHttpScheme;
  unencrypted_resolve_key.hostname_pattern = kHost;
  host_resolver->rules()->AddRule(std::move(unencrypted_resolve_key),
                                  ERR_DNS_NAME_HTTPS_ONLY);
  MockHostResolverBase::RuleResolver::RuleKey encrypted_resolve_key;
  encrypted_resolve_key.scheme = url::kHttpsScheme;
  encrypted_resolve_key.hostname_pattern = kHost;
  host_resolver->rules()->AddRule(std::move(encrypted_resolve_key),
                                  https_server.GetIPLiteralString());
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_host_resolver(std::move(host_resolver));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      ws_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS,
      /*is_for_websockets=*/true));
  EXPECT_FALSE(req->url().SchemeIsCryptographic());

  HttpRequestHeaders headers = WebSocketCommonTestHeaders();
  req->SetExtraRequestHeaders(headers);

  auto websocket_stream_create_helper =
      std::make_unique<TestWebSocketHandshakeStreamCreateHelper>();
  req->SetUserData(kWebSocketHandshakeUserDataKey,
                   std::move(websocket_stream_create_helper));

  // Note that there is no ws server running, so the request should fail or hang
  // if its scheme is not upgraded to wss.
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(d.received_redirect_count(), 1);

  // Expect failure because test server is not set up to provide websocket
  // responses.
  EXPECT_EQ(network_delegate.error_count(), 1);
  EXPECT_EQ(network_delegate.last_error(), ERR_INVALID_RESPONSE);

  // Observe that the scheme has been upgraded to wss.
  EXPECT_TRUE(req->url().SchemeIsCryptographic());
  EXPECT_TRUE(req->url().SchemeIs(url::kWssScheme));
}
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

TEST_F(URLRequestTest, DnsHttpsRecordAbsentNoSchemeUpgrade) {
  EmbeddedTestServer http_server(EmbeddedTestServer::TYPE_HTTP);
  RegisterDefaultHandlers(&http_server);
  ASSERT_TRUE(http_server.Start());

  // Build an http URL that should be auto-upgraded to https.
  const std::string kHost = "foo.a.test";  // Covered by CERT_TEST_NAMES.
  const GURL http_url = http_server.GetURL(kHost, "/defaultresponse");

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule(kHost, http_server.GetIPLiteralString());
  context_builder->set_host_resolver(std::move(host_resolver));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_FALSE(req->url().SchemeIsCryptographic());

  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(d.received_redirect_count(), 0);

  EXPECT_EQ(0, network_delegate.error_count());
  EXPECT_EQ(200, req->GetResponseCode());
  ASSERT_TRUE(req->response_headers());
  EXPECT_EQ(200, req->response_headers()->response_code());

  // Observe that the scheme has not been upgraded.
  EXPECT_EQ(http_url, req->url());
  EXPECT_FALSE(req->url().SchemeIsCryptographic());
  EXPECT_TRUE(req->url().SchemeIs(url::kHttpScheme));
}

TEST_F(URLRequestTest, SkipSecureDnsDisabledByDefault) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("example.com", "127.0.0.1");
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://example.com"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(SecureDnsPolicy::kAllow,
            static_cast<MockHostResolver*>(context->host_resolver())
                ->last_secure_dns_policy());
}

TEST_F(URLRequestTest, SkipSecureDnsEnabled) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddRule("example.com", "127.0.0.1");
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://example.com"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetSecureDnsPolicy(SecureDnsPolicy::kDisable);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(SecureDnsPolicy::kDisable,
            static_cast<MockHostResolver*>(context->host_resolver())
                ->last_secure_dns_policy());
}

// Make sure that NetworkDelegate::NotifyCompleted is called if
// content is empty.
TEST_F(URLRequestTest, RequestCompletionForEmptyResponse) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      test_server.GetURL("/nocontent"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();
  EXPECT_THAT(d.request_status(), IsOk());
  EXPECT_EQ(204, req->GetResponseCode());
  EXPECT_EQ("", d.data_received());
  EXPECT_EQ(1, default_network_delegate().completed_requests());
}

// Make sure that SetPriority actually sets the URLRequest's priority
// correctly, both before and after start.
TEST_F(URLRequestTest, SetPriorityBasic) {
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      GURL("http://test_intercept/foo"), DEFAULT_PRIORITY, &d,
"""


```