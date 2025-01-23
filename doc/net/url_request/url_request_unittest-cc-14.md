Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/url_request/url_request_unittest.cc`. I need to analyze the code and identify its purpose.

The code seems to be testing various functionalities of the `URLRequest` class, particularly focusing on:

1. **Certificate handling and HSTS (HTTP Strict Transport Security):**  It sets up a fake certificate verifier and tests how `URLRequest` behaves when encountering certificate errors and HSTS settings.
2. **Host resolution failures:** It checks if `URLRequest` correctly flags network access when host resolution fails.
3. **Request cancellation:** It tests the cancellation mechanism for `URLRequest` when a redirect job is involved.
4. **Request and response headers callbacks:** It verifies if callbacks for accessing raw request and response headers are invoked correctly, including cases with redirects and authentication retries.
5. **Upgrade-Insecure-Requests:** It tests the functionality that automatically upgrades insecure HTTP redirects to HTTPS.
6. **Socket tagging (Android specific):** It checks if `URLRequest` can be tagged for network traffic accounting on Android.
7. **TLS Early Data (0-RTT):** It tests scenarios involving TLS 1.3's early data feature.

Regarding the user's specific requests:

*   **Functionality listing:** I need to list the functionalities demonstrated in the code.
*   **Relation to Javascript:**  I need to determine if any of these functionalities have a direct counterpart or impact on Javascript within a web browser.
*   **Logical reasoning (input/output):** I need to identify test cases with clear setup (input) and expected behavior (output).
*   **User/programming errors:** I need to point out potential errors users or developers might make that these tests cover.
*   **User operation as a debugging clue:** I should explain how a user's action might lead to the execution of the tested code.
*   **Summary of functionality (part 15/17):** I need to provide a concise summary of the functionalities covered in this specific code snippet within the larger context of the file.

Based on the analysis of the code, the main functionalities covered in this part are related to **certificate handling with HSTS, host resolution failures, request cancellation, request/response headers callbacks, Upgrade-Insecure-Requests, socket tagging (Android), and TLS Early Data (0-RTT).**
这个`net/url_request/url_request_unittest.cc` 文件是 Chromium 网络栈的单元测试文件， 专门用于测试 `URLRequest` 类的各种功能。 你提供的代码片段是该文件的一部分，主要涵盖以下功能：

1. **测试服务器证书错误和 HSTS (HTTP Strict Transport Security) 的交互：**
    *   它创建了一个假的证书验证器 (`MockCertVerifier`)，并配置了针对特定主机名的验证结果。
    *   它模拟了以下几种情况：
        *   一个普通 HTTPS 网站的证书存在 `CERT_STATUS_AUTHORITY_INVALID` 错误，但不致命。
        *   一个预加载了 HSTS 的主机 (`kHSTSHost`) 的证书存在 `CERT_STATUS_AUTHORITY_INVALID` 错误，并且是致命的。
        *   一个已知被中间人攻击的主机 (`kHSTSSubdomainWithKnownInterception`) 的证书存在 `CERT_STATUS_REVOKED | CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED` 错误。
    *   它使用 `TransportSecurityState` 来启用 HSTS 并设置预加载的 HSTS 策略。
    *   它创建 `URLRequest` 来访问这些不同的主机，并验证请求是否失败，以及证书错误是否被正确标记为致命或非致命。

2. **测试主机名解析失败时的行为：**
    *   它创建了一个模拟的主机解析器 (`MockHostResolver`)，并配置为让所有主机解析超时。
    *   它创建一个 `URLRequest` 并尝试访问一个不存在的主机。
    *   它验证在主机解析失败后，`response_info().network_accessed` 被设置为 true，并且 `resolve_error_info.error` 被设置为 `ERR_DNS_TIMED_OUT`。

3. **测试 `URLRequest` 的取消功能，尤其是在涉及重定向任务时：**
    *   它创建一个 `URLRequest` 请求一个无效的域名。
    *   它创建了一个 `URLRequestRedirectJob`，模拟服务器返回一个重定向响应，但重定向的 URL 也不会被实际导航。
    *   它在请求开始后立即取消请求。
    *   它验证请求的状态是 `ERR_ABORTED`，并且没有收到任何重定向。

4. **测试请求头和响应头回调函数：**
    *   它创建 `URLRequest` 并设置了 `SetRequestHeadersCallback` 和 `SetResponseHeadersCallback`。
    *   它发送请求到测试服务器，并验证在请求发送后，请求头回调函数被调用，可以获取到原始的请求头。
    *   它验证响应头回调函数被调用，可以获取到原始的响应头。
    *   它测试了有缓存的情况，确保在从缓存中加载资源时，回调函数不会被调用。
    *   它测试了重定向的情况，验证在重定向发生时，请求头和响应头回调函数被调用，并且可以获取到重定向的请求和响应头。
    *   它测试了连接失败的情况，确保在连接失败时，回调函数不会被调用。
    *   它测试了需要进行身份验证重试的情况，验证在进行身份验证重试时，请求头和响应头回调函数会被多次调用，分别对应初始请求和重试请求。

5. **测试 `upgrade_if_insecure` 标志：**
    *   它创建一个从 HTTPS 网站重定向到 HTTP 网站的场景。
    *   它创建 `URLRequest` 并设置 `upgrade_if_insecure` 标志为 true。
    *   它验证重定向的 URL 被自动升级为 HTTPS。
    *   它测试了显式指定 80 端口的情况，验证端口被移除。
    *   它测试了非标准端口的情况，验证端口保持不变。
    *   它测试了 `upgrade_if_insecure` 标志为 false 的情况，验证重定向 URL 没有被升级。

6. **测试 Socket Tagging (仅限 Android 平台)：**
    *   它创建 `URLRequest` 并验证默认情况下没有设置 Socket Tag。
    *   它设置一个特定的 Socket Tag，并验证请求使用的 Socket Tag 与设置的值一致。
    *   它通过 `GetTaggedBytes` 检查网络流量是否按照设置的 Tag 值进行统计。

7. **测试 TLS Early Data (0-RTT)：**
    *   它创建了一个支持 TLS 1.3 Early Data 的 HTTPS 测试服务器。
    *   它创建 `URLRequest` 发送请求，并验证在首次连接时，`ssl_info().early_data_received` 为 false。
    *   它关闭连接并再次发送请求，利用 TLS 会话恢复，并验证 `ssl_info().early_data_received` 为 true，表明使用了 0-RTT。
    *   它测试了 POST 请求的情况，验证非幂等的 POST 请求不会使用 0-RTT。
    *   它测试了幂等的 POST 请求，验证可以正常使用 0-RTT。
    *   它测试了将 GET 请求标记为非幂等的情况，验证即使是 GET 请求也不会使用 0-RTT。

**与 Javascript 的关系：**

这些功能大部分在网络层的底层实现，Javascript 代码通常通过浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`) 来间接使用这些功能。

*   **证书错误和 HSTS:** 当 Javascript 发起 HTTPS 请求时，浏览器会进行证书验证和 HSTS 检查。如果发生证书错误或违反 HSTS 策略，浏览器可能会阻止请求，Javascript 代码会收到一个网络错误。
*   **主机名解析失败:** 当 Javascript 尝试访问一个无法解析的主机名时，`fetch` 或 `XMLHttpRequest` 会抛出一个错误，例如 `TypeError: Failed to fetch`.
*   **请求取消:**  Javascript 可以通过 `AbortController` 来取消 `fetch` 请求。
*   **请求头和响应头:** Javascript 可以通过 `fetch` API 的 `headers` 属性来访问请求和响应头，但无法直接访问原始的二进制格式。`SetRequestHeadersCallback` 和 `SetResponseHeadersCallback` 允许 Chromium 的内部组件在发送请求前和接收响应后访问和修改原始头信息。
*   **Upgrade-Insecure-Requests:** 当 HTML 页面包含 `<meta http-equiv="Upgrade-Insecure-Requests">` 标签时，浏览器会自动将页面内所有 HTTP 请求升级到 HTTPS。这与 `URLRequest` 的 `upgrade_if_insecure` 标志功能类似。
*   **Socket Tagging:**  这个功能主要用于 Android 平台进行网络流量统计，与 Javascript 的直接交互较少。
*   **TLS Early Data (0-RTT):** 这个功能可以提升 HTTPS 连接的性能。对于 Javascript 来说，使用 0-RTT 可以减少请求的延迟，从而提升网页加载速度，但 Javascript 代码本身不需要显式地处理 0-RTT。

**逻辑推理、假设输入与输出：**

**示例 1 (HSTS 测试):**

*   **假设输入:** 用户在浏览器中访问 `https://hsts.test/`，而 `hsts.test` 已经通过预加载列表或者之前的访问被设置为 HSTS 主机，并且当前的连接的证书存在 `CERT_STATUS_AUTHORITY_INVALID` 错误。
*   **预期输出:** `URLRequest` 会因为 HSTS 策略和证书错误而失败，`d.request_failed()` 返回 true，`d.certificate_errors_are_fatal()` 返回 true。浏览器会显示一个证书错误页面，阻止用户访问该网站。

**示例 2 (主机名解析失败):**

*   **假设输入:** Javascript 代码使用 `fetch('http://nonexistent.test/api')` 发起一个请求，而 `nonexistent.test` 无法被 DNS 解析。
*   **预期输出:**  `URLRequest` 在尝试解析 `nonexistent.test` 时会超时，`req->response_info().network_accessed` 会被设置为 true，`req->response_info().resolve_error_info.error` 会是 `ERR_DNS_TIMED_OUT`。`fetch` API 会返回一个 rejected Promise，并带有 `TypeError: Failed to fetch`.

**用户或编程常见的使用错误：**

1. **开发者错误配置 HSTS:**  如果开发者错误地将某个主机配置为 HSTS，即使该网站的 HTTPS 配置不正确，用户也可能无法通过 HTTP 访问该网站。测试代码中的 `ERR_CERT_AUTHORITY_INVALID` 就是模拟了这种情况。
2. **网络连接问题导致主机名解析失败:** 用户的网络连接不稳定或者 DNS 服务器出现问题，可能导致主机名解析失败。
3. **在重定向场景中错误地取消请求:** 开发者可能在收到重定向响应后，错误地过早取消了 `URLRequest`，导致请求无法完成。
4. **错误地使用请求头和响应头回调:** 开发者可能会在回调函数中执行耗时操作，影响网络请求的性能。
5. **不理解 `upgrade_if_insecure` 的作用:** 开发者可能不清楚 `upgrade_if_insecure` 标志的作用，导致在需要 HTTPS 的场景下仍然发送 HTTP 请求。
6. **Android 开发者错误地设置 Socket Tag:** Android 开发者可能设置了错误的 Socket Tag 值，导致网络流量统计不准确。
7. **期望所有 POST 请求都能使用 0-RTT:** 开发者可能错误地认为所有的 POST 请求都能利用 TLS 1.3 的 0-RTT 功能，而实际上只有幂等的 POST 请求才能使用。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入 `https://hsts.test/` (假设 `hsts.test` 是一个 HSTS 站点，但当前证书无效)。**
2. **浏览器网络栈开始创建 `URLRequest` 来请求该 URL。**
3. **网络栈的证书验证器会检查该站点的证书，发现存在 `CERT_STATUS_AUTHORITY_INVALID` 错误。**
4. **由于该站点是 HSTS 站点，`TransportSecurityState` 会告知 `URLRequest` 该错误是致命的。**
5. **`URLRequest` 会根据配置的 `MockCertVerifier` 的结果，设置相应的证书状态和错误码。**
6. **测试代码中的断言 (`ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`) 会验证 `URLRequest` 的行为是否符合预期。**

**总结 (第15部分功能归纳)：**

这部分代码主要测试了 `URLRequest` 在处理 **服务器证书错误与 HSTS 策略的交互、主机名解析失败、请求取消（尤其是涉及重定向时）、请求和响应头回调、Upgrade-Insecure-Requests 功能、Android 平台的 Socket Tagging 以及 TLS 1.3 的 Early Data (0-RTT)** 等方面的功能。这些测试确保了 `URLRequest` 能够正确处理各种网络场景，并为 Chromium 的网络安全性、性能和可靠性提供了保障。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第15部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
ASSERT_TRUE(filler_hash.FromString(
      "sha256/3333333333333333333333333333333333333333333="));

  CertVerifyResult fake_result;
  fake_result.verified_cert = cert;
  fake_result.is_issued_by_known_root = false;

  // Configure for the test server's default host.
  CertVerifyResult test_result = fake_result;
  test_result.public_key_hashes.push_back(filler_hash);
  test_result.cert_status |= CERT_STATUS_AUTHORITY_INVALID;
  cert_verifier->AddResultForCertAndHost(
      cert.get(), https_server.host_port_pair().host(), test_result,
      ERR_CERT_AUTHORITY_INVALID);

  // Configure for kHSTSHost.
  CertVerifyResult sts_base_result = fake_result;
  sts_base_result.public_key_hashes.push_back(filler_hash);
  sts_base_result.cert_status |= CERT_STATUS_AUTHORITY_INVALID;
  cert_verifier->AddResultForCertAndHost(cert.get(), kHSTSHost, sts_base_result,
                                         ERR_CERT_AUTHORITY_INVALID);

  // Configure for kHSTSSubdomainWithKnownInterception
  CertVerifyResult sts_sub_result = fake_result;
  SHA256HashValue root_hash;
  ASSERT_TRUE(GetTestRootCertSPKIHash(&root_hash));
  sts_sub_result.public_key_hashes.push_back(HashValue(root_hash));
  sts_sub_result.cert_status |=
      CERT_STATUS_REVOKED | CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED;
  cert_verifier->AddResultForCertAndHost(
      cert.get(), kHSTSSubdomainWithKnownInterception, sts_sub_result,
      ERR_CERT_KNOWN_INTERCEPTION_BLOCKED);

  // Configure the initial context.
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCertVerifier(std::move(cert_verifier));
  auto context = context_builder->Build();

  // Enable preloaded HSTS for |kHSTSHost|.
  ASSERT_TRUE(context->transport_security_state());
  TransportSecurityState& security_state = *context->transport_security_state();
  security_state.EnableStaticPinsForTesting();
  security_state.SetPinningListAlwaysTimelyForTesting(true);
  SetTransportSecurityStateSourceForTesting(&test_default::kHSTSSource);

  // Connect to the test server and see the certificate error flagged, but
  // not fatal.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(
        context->CreateRequest(https_server.GetURL("/"), DEFAULT_PRIORITY, &d,
                               TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_TRUE(d.request_failed());
    EXPECT_TRUE(d.have_certificate_errors());
    EXPECT_FALSE(d.certificate_errors_are_fatal());
    EXPECT_FALSE(req->ssl_info().cert_status &
                 CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED);
  }

  // Connect to kHSTSHost and see the certificate errors are flagged, and are
  // fatal.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_server.GetURL(kHSTSHost, "/"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_TRUE(d.request_failed());
    EXPECT_TRUE(d.have_certificate_errors());
    EXPECT_TRUE(d.certificate_errors_are_fatal());
    EXPECT_FALSE(req->ssl_info().cert_status &
                 CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED);
  }

  // Verify the connection fails as being a known interception root.
  {
    TestDelegate d;
    d.set_allow_certificate_errors(true);
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_server.GetURL(kHSTSSubdomainWithKnownInterception, "/"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.request_failed());
    EXPECT_TRUE(d.have_certificate_errors());
    EXPECT_FALSE(d.certificate_errors_are_fatal());
    EXPECT_EQ(ERR_CERT_KNOWN_INTERCEPTION_BLOCKED, d.certificate_net_error());
    EXPECT_TRUE(req->ssl_info().cert_status &
                CERT_STATUS_KNOWN_INTERCEPTION_BLOCKED);
  }
}
#endif  // !BUILDFLAG(IS_IOS)

TEST_F(URLRequestTest, NetworkAccessedSetOnHostResolutionFailure) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto host_resolver = std::make_unique<MockHostResolver>();
  host_resolver->rules()->AddSimulatedTimeoutFailure("*");
  context_builder->set_host_resolver(std::move(host_resolver));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      GURL("http://test_intercept/foo"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));

  EXPECT_FALSE(req->response_info().network_accessed);

  req->Start();
  d.RunUntilComplete();
  EXPECT_TRUE(req->response_info().network_accessed);
  EXPECT_THAT(req->response_info().resolve_error_info.error,
              IsError(ERR_DNS_TIMED_OUT));
}

// Test that URLRequest is canceled correctly.
// See http://crbug.com/508900
TEST_F(URLRequestTest, URLRequestRedirectJobCancelRequest) {
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      GURL("http://not-a-real-domain/"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));

  std::unique_ptr<URLRequestRedirectJob> job =
      std::make_unique<URLRequestRedirectJob>(
          req.get(), GURL("http://this-should-never-be-navigated-to/"),
          RedirectUtil::ResponseCode::REDIRECT_307_TEMPORARY_REDIRECT,
          "Jumbo shrimp");
  TestScopedURLInterceptor interceptor(req->url(), std::move(job));

  req->Start();
  req->Cancel();
  d.RunUntilComplete();
  EXPECT_EQ(ERR_ABORTED, d.request_status());
  EXPECT_EQ(0, d.received_redirect_count());
}

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
#define MAYBE_HeadersCallbacks DISABLED_HeadersCallbacks
#else
#define MAYBE_HeadersCallbacks HeadersCallbacks
#endif
TEST_F(URLRequestTestHTTP, MAYBE_HeadersCallbacks) {
  ASSERT_TRUE(http_test_server()->Start());
  GURL url(http_test_server()->GetURL("/cachetime"));
  TestDelegate delegate;
  HttpRequestHeaders extra_headers;
  extra_headers.SetHeader("X-Foo", "bar");

  {
    HttpRawRequestHeaders raw_req_headers;
    scoped_refptr<const HttpResponseHeaders> raw_resp_headers;

    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->SetExtraRequestHeaders(extra_headers);
    r->SetRequestHeadersCallback(base::BindRepeating(
        &HttpRawRequestHeaders::Assign, base::Unretained(&raw_req_headers)));
    r->SetResponseHeadersCallback(base::BindRepeating(
        [](scoped_refptr<const HttpResponseHeaders>* left,
           scoped_refptr<const HttpResponseHeaders> right) { *left = right; },
        base::Unretained(&raw_resp_headers)));
    r->set_isolation_info(isolation_info1_);
    r->Start();
    delegate.RunUntilComplete();
    EXPECT_FALSE(raw_req_headers.headers().empty());
    std::string value;
    EXPECT_TRUE(raw_req_headers.FindHeaderForTest("X-Foo", &value));
    EXPECT_EQ("bar", value);
    EXPECT_TRUE(raw_req_headers.FindHeaderForTest("Accept-Encoding", &value));
    EXPECT_EQ("gzip, deflate", value);
    EXPECT_TRUE(raw_req_headers.FindHeaderForTest("Connection", &value));
    EXPECT_TRUE(raw_req_headers.FindHeaderForTest("Host", &value));
    EXPECT_EQ("GET /cachetime HTTP/1.1\r\n", raw_req_headers.request_line());
    EXPECT_EQ(raw_resp_headers.get(), r->response_headers());
  }
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->SetExtraRequestHeaders(extra_headers);
    r->SetRequestHeadersCallback(base::BindRepeating([](HttpRawRequestHeaders) {
      FAIL() << "Callback should not be called unless request is sent";
    }));
    r->SetResponseHeadersCallback(
        base::BindRepeating([](scoped_refptr<const HttpResponseHeaders>) {
          FAIL() << "Callback should not be called unless request is sent";
        }));
    r->set_isolation_info(isolation_info1_);
    r->Start();
    delegate.RunUntilComplete();
    EXPECT_TRUE(r->was_cached());
  }
}

TEST_F(URLRequestTestHTTP, HeadersCallbacksWithRedirect) {
  ASSERT_TRUE(http_test_server()->Start());
  HttpRawRequestHeaders raw_req_headers;
  scoped_refptr<const HttpResponseHeaders> raw_resp_headers;

  TestDelegate delegate;
  HttpRequestHeaders extra_headers;
  extra_headers.SetHeader("X-Foo", "bar");
  GURL url(http_test_server()->GetURL("/redirect-test.html"));
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->SetExtraRequestHeaders(extra_headers);
  r->SetRequestHeadersCallback(base::BindRepeating(
      &HttpRawRequestHeaders::Assign, base::Unretained(&raw_req_headers)));
  r->SetResponseHeadersCallback(base::BindRepeating(
      [](scoped_refptr<const HttpResponseHeaders>* left,
         scoped_refptr<const HttpResponseHeaders> right) { *left = right; },
      base::Unretained(&raw_resp_headers)));
  r->Start();
  delegate.RunUntilRedirect();

  ASSERT_EQ(1, delegate.received_redirect_count());
  std::string value;
  EXPECT_TRUE(raw_req_headers.FindHeaderForTest("X-Foo", &value));
  EXPECT_EQ("bar", value);
  EXPECT_TRUE(raw_req_headers.FindHeaderForTest("Accept-Encoding", &value));
  EXPECT_EQ("gzip, deflate", value);
  EXPECT_EQ(1, delegate.received_redirect_count());
  EXPECT_EQ("GET /redirect-test.html HTTP/1.1\r\n",
            raw_req_headers.request_line());
  EXPECT_TRUE(raw_resp_headers->HasHeader("Location"));
  EXPECT_EQ(302, raw_resp_headers->response_code());
  EXPECT_EQ("Redirect", raw_resp_headers->GetStatusText());

  raw_req_headers = HttpRawRequestHeaders();
  raw_resp_headers = nullptr;
  r->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                            std::nullopt /* modified_headers */);
  delegate.RunUntilComplete();
  EXPECT_TRUE(raw_req_headers.FindHeaderForTest("X-Foo", &value));
  EXPECT_EQ("bar", value);
  EXPECT_TRUE(raw_req_headers.FindHeaderForTest("Accept-Encoding", &value));
  EXPECT_EQ("gzip, deflate", value);
  EXPECT_EQ("GET /with-headers.html HTTP/1.1\r\n",
            raw_req_headers.request_line());
  EXPECT_EQ(r->response_headers(), raw_resp_headers.get());
}

TEST_F(URLRequestTest, HeadersCallbacksConnectFailed) {
  TestDelegate request_delegate;

  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      GURL("http://127.0.0.1:9/"), DEFAULT_PRIORITY, &request_delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  r->SetRequestHeadersCallback(
      base::BindRepeating([](net::HttpRawRequestHeaders) {
        FAIL() << "Callback should not be called unless request is sent";
      }));
  r->SetResponseHeadersCallback(
      base::BindRepeating([](scoped_refptr<const net::HttpResponseHeaders>) {
        FAIL() << "Callback should not be called unless request is sent";
      }));
  r->Start();
  request_delegate.RunUntilComplete();
  EXPECT_FALSE(r->is_pending());
}

TEST_F(URLRequestTestHTTP, HeadersCallbacksAuthRetry) {
  ASSERT_TRUE(http_test_server()->Start());
  GURL url(http_test_server()->GetURL("/auth-basic"));

  TestDelegate delegate;

  delegate.set_credentials(AuthCredentials(kUser, kSecret));
  HttpRequestHeaders extra_headers;
  extra_headers.SetHeader("X-Foo", "bar");

  using ReqHeadersVector = std::vector<std::unique_ptr<HttpRawRequestHeaders>>;
  ReqHeadersVector raw_req_headers;

  using RespHeadersVector =
      std::vector<scoped_refptr<const HttpResponseHeaders>>;
  RespHeadersVector raw_resp_headers;

  auto req_headers_callback = base::BindRepeating(
      [](ReqHeadersVector* vec, HttpRawRequestHeaders headers) {
        vec->emplace_back(
            std::make_unique<HttpRawRequestHeaders>(std::move(headers)));
      },
      &raw_req_headers);
  auto resp_headers_callback = base::BindRepeating(
      [](RespHeadersVector* vec,
         scoped_refptr<const HttpResponseHeaders> headers) {
        vec->push_back(headers);
      },
      &raw_resp_headers);
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->SetExtraRequestHeaders(extra_headers);
  r->SetRequestHeadersCallback(req_headers_callback);
  r->SetResponseHeadersCallback(resp_headers_callback);
  r->set_isolation_info(isolation_info1_);
  r->Start();
  delegate.RunUntilComplete();
  EXPECT_FALSE(r->is_pending());
  ASSERT_EQ(raw_req_headers.size(), 2u);
  ASSERT_EQ(raw_resp_headers.size(), 2u);
  std::string value;
  EXPECT_FALSE(raw_req_headers[0]->FindHeaderForTest("Authorization", &value));
  EXPECT_TRUE(raw_req_headers[0]->FindHeaderForTest("X-Foo", &value));
  EXPECT_EQ("bar", value);
  EXPECT_TRUE(raw_req_headers[1]->FindHeaderForTest("Authorization", &value));
  EXPECT_TRUE(raw_req_headers[1]->FindHeaderForTest("X-Foo", &value));
  EXPECT_EQ("bar", value);
  EXPECT_EQ(raw_resp_headers[1], r->response_headers());
  EXPECT_NE(raw_resp_headers[0], raw_resp_headers[1]);
  EXPECT_EQ(401, raw_resp_headers[0]->response_code());
  EXPECT_EQ("Unauthorized", raw_resp_headers[0]->GetStatusText());

  std::unique_ptr<URLRequest> r2(default_context().CreateRequest(
      url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  r2->SetExtraRequestHeaders(extra_headers);
  r2->SetRequestHeadersCallback(req_headers_callback);
  r2->SetResponseHeadersCallback(resp_headers_callback);
  r2->SetLoadFlags(LOAD_VALIDATE_CACHE);
  r2->set_isolation_info(isolation_info1_);
  r2->Start();
  delegate.RunUntilComplete();
  EXPECT_FALSE(r2->is_pending());
  ASSERT_EQ(raw_req_headers.size(), 3u);
  ASSERT_EQ(raw_resp_headers.size(), 3u);
  EXPECT_TRUE(raw_req_headers[2]->FindHeaderForTest("If-None-Match", &value));
  EXPECT_NE(raw_resp_headers[2].get(), r2->response_headers());
  EXPECT_EQ(304, raw_resp_headers[2]->response_code());
  EXPECT_EQ("Not Modified", raw_resp_headers[2]->GetStatusText());
}

TEST_F(URLRequestTest, UpgradeIfInsecureFlagSet) {
  TestDelegate d;
  const GURL kOriginalUrl("https://original.test");
  const GURL kRedirectUrl("http://redirect.test");
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::SYNCHRONOUS));
  network_delegate.set_redirect_url(kRedirectUrl);
  auto context = context_builder->Build();

  std::unique_ptr<URLRequest> r(context->CreateRequest(
      kOriginalUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->set_upgrade_if_insecure(true);
  r->Start();
  d.RunUntilRedirect();
  GURL::Replacements replacements;
  // Check that the redirect URL was upgraded to HTTPS since upgrade_if_insecure
  // was set.
  replacements.SetSchemeStr("https");
  EXPECT_EQ(kRedirectUrl.ReplaceComponents(replacements),
            d.redirect_info().new_url);
  EXPECT_TRUE(d.redirect_info().insecure_scheme_was_upgraded);
}

TEST_F(URLRequestTest, UpgradeIfInsecureFlagSetExplicitPort80) {
  TestDelegate d;
  const GURL kOriginalUrl("https://original.test");
  const GURL kRedirectUrl("http://redirect.test:80");
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::SYNCHRONOUS));
  network_delegate.set_redirect_url(kRedirectUrl);
  auto context = context_builder->Build();

  std::unique_ptr<URLRequest> r(context->CreateRequest(
      kOriginalUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->set_upgrade_if_insecure(true);
  r->Start();
  d.RunUntilRedirect();
  GURL::Replacements replacements;
  // The URL host should have not been changed.
  EXPECT_EQ(d.redirect_info().new_url.host(), kRedirectUrl.host());
  // The scheme should now be https, and the effective port should now be 443.
  EXPECT_TRUE(d.redirect_info().new_url.SchemeIs("https"));
  EXPECT_EQ(d.redirect_info().new_url.EffectiveIntPort(), 443);
  EXPECT_TRUE(d.redirect_info().insecure_scheme_was_upgraded);
}

TEST_F(URLRequestTest, UpgradeIfInsecureFlagSetNonStandardPort) {
  TestDelegate d;
  const GURL kOriginalUrl("https://original.test");
  const GURL kRedirectUrl("http://redirect.test:1234");
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::SYNCHRONOUS));
  network_delegate.set_redirect_url(kRedirectUrl);
  auto context = context_builder->Build();

  std::unique_ptr<URLRequest> r(context->CreateRequest(
      kOriginalUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->set_upgrade_if_insecure(true);
  r->Start();
  d.RunUntilRedirect();
  GURL::Replacements replacements;
  // Check that the redirect URL was upgraded to HTTPS since upgrade_if_insecure
  // was set, nonstandard port should not have been modified.
  replacements.SetSchemeStr("https");
  EXPECT_EQ(kRedirectUrl.ReplaceComponents(replacements),
            d.redirect_info().new_url);
  EXPECT_TRUE(d.redirect_info().insecure_scheme_was_upgraded);
}

TEST_F(URLRequestTest, UpgradeIfInsecureFlagNotSet) {
  TestDelegate d;
  const GURL kOriginalUrl("https://original.test");
  const GURL kRedirectUrl("http://redirect.test");
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<BlockingNetworkDelegate>(
          BlockingNetworkDelegate::SYNCHRONOUS));
  network_delegate.set_redirect_url(kRedirectUrl);
  auto context = context_builder->Build();

  std::unique_ptr<URLRequest> r(context->CreateRequest(
      kOriginalUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->set_upgrade_if_insecure(false);
  r->Start();
  d.RunUntilRedirect();
  // The redirect URL should not be changed if the upgrade_if_insecure flag is
  // not set.
  EXPECT_EQ(kRedirectUrl, d.redirect_info().new_url);
  EXPECT_FALSE(d.redirect_info().insecure_scheme_was_upgraded);
}

// Test that URLRequests get properly tagged.
#if BUILDFLAG(IS_ANDROID)
TEST_F(URLRequestTestHTTP, TestTagging) {
  if (!CanGetTaggedBytes()) {
    DVLOG(0) << "Skipping test - GetTaggedBytes unsupported.";
    return;
  }

  ASSERT_TRUE(http_test_server()->Start());

  // The tag under which the system reports untagged traffic.
  static const int32_t UNTAGGED_TAG = 0;

  uint64_t old_traffic = GetTaggedBytes(UNTAGGED_TAG);

  // Untagged traffic should be tagged with tag UNTAGGED_TAG.
  TestDelegate delegate;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(SocketTag(), req->socket_tag());
  req->Start();
  delegate.RunUntilComplete();

  EXPECT_GT(GetTaggedBytes(UNTAGGED_TAG), old_traffic);

  int32_t tag_val1 = 0x12345678;
  SocketTag tag1(SocketTag::UNSET_UID, tag_val1);
  old_traffic = GetTaggedBytes(tag_val1);

  // Test specific tag value.
  req = default_context().CreateRequest(http_test_server()->GetURL("/"),
                                        DEFAULT_PRIORITY, &delegate,
                                        TRAFFIC_ANNOTATION_FOR_TESTS);
  req->set_socket_tag(tag1);
  EXPECT_EQ(tag1, req->socket_tag());
  req->Start();
  delegate.RunUntilComplete();

  EXPECT_GT(GetTaggedBytes(tag_val1), old_traffic);
}
#endif

namespace {

class ReadBufferingListener
    : public test_server::EmbeddedTestServerConnectionListener {
 public:
  ReadBufferingListener() = default;
  ~ReadBufferingListener() override = default;

  void BufferNextConnection(int buffer_size) { buffer_size_ = buffer_size; }

  std::unique_ptr<StreamSocket> AcceptedSocket(
      std::unique_ptr<StreamSocket> socket) override {
    if (!buffer_size_) {
      return socket;
    }
    auto wrapped =
        std::make_unique<ReadBufferingStreamSocket>(std::move(socket));
    wrapped->BufferNextRead(buffer_size_);
    // Do not buffer subsequent connections, which may be a 0-RTT retry.
    buffer_size_ = 0;
    return wrapped;
  }

  void ReadFromSocket(const StreamSocket& socket, int rv) override {}

 private:
  int buffer_size_ = 0;
};

// Provides a response to the 0RTT request indicating whether it was received
// as early data, sending HTTP_TOO_EARLY if enabled.
class ZeroRTTResponse : public test_server::BasicHttpResponse {
 public:
  ZeroRTTResponse(bool zero_rtt, bool send_too_early)
      : zero_rtt_(zero_rtt), send_too_early_(send_too_early) {}

  ZeroRTTResponse(const ZeroRTTResponse&) = delete;
  ZeroRTTResponse& operator=(const ZeroRTTResponse&) = delete;

  ~ZeroRTTResponse() override = default;

  void SendResponse(
      base::WeakPtr<test_server::HttpResponseDelegate> delegate) override {
    AddCustomHeader("Vary", "Early-Data");
    set_content_type("text/plain");
    AddCustomHeader("Cache-Control", "no-cache");
    if (zero_rtt_) {
      if (send_too_early_)
        set_code(HTTP_TOO_EARLY);
      set_content("1");
    } else {
      set_content("0");
    }

    // Since the EmbeddedTestServer doesn't keep the socket open by default,
    // it is explicitly kept alive to allow the remaining leg of the 0RTT
    // handshake to be received after the early data.
    delegate->SendResponseHeaders(code(), GetHttpReasonPhrase(code()),
                                  BuildHeaders());
    delegate->SendContents(content(), base::DoNothing());
  }

 private:
  bool zero_rtt_;
  bool send_too_early_;
};

std::unique_ptr<test_server::HttpResponse> HandleZeroRTTRequest(
    const test_server::HttpRequest& request) {
  DCHECK(request.ssl_info);

  if (request.GetURL().path() != "/zerortt")
    return nullptr;
  return std::make_unique<ZeroRTTResponse>(
      request.ssl_info->early_data_received, false);
}

}  // namespace

class HTTPSEarlyDataTest : public TestWithTaskEnvironment {
 public:
  HTTPSEarlyDataTest() : test_server_(net::EmbeddedTestServer::TYPE_HTTPS) {
    HttpNetworkSessionParams params;
    params.enable_early_data = true;

    auto cert_verifier = std::make_unique<MockCertVerifier>();
    cert_verifier->set_default_result(OK);

    SSLContextConfig config;
    config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;

    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_http_network_session_params(params);
    context_builder->SetCertVerifier(std::move(cert_verifier));
    context_builder->set_ssl_config_service(
        std::make_unique<TestSSLConfigService>(config));
    context_ = context_builder->Build();

    test_server_.SetSSLConfig(
        net::EmbeddedTestServer::CERT_OK,
        CreateSSLServerConfig(SSL_PROTOCOL_VERSION_TLS1_3));
    RegisterDefaultHandlers(&test_server_);
    test_server_.RegisterRequestHandler(
        base::BindRepeating(&HandleZeroRTTRequest));
    test_server_.SetConnectionListener(&listener_);
  }

  ~HTTPSEarlyDataTest() override = default;

  URLRequestContext& context() { return *context_; }

  static SSLServerConfig CreateSSLServerConfig(uint16_t version) {
    SSLServerConfig ssl_config;
    ssl_config.version_max = version;
    ssl_config.early_data_enabled = true;
    return ssl_config;
  }

  void ResetSSLConfig(net::EmbeddedTestServer::ServerCertificate cert,
                      uint16_t version) {
    SSLServerConfig ssl_config = CreateSSLServerConfig(version);
    test_server_.ResetSSLConfig(cert, ssl_config);
  }

 protected:
  std::unique_ptr<URLRequestContext> context_;

  ReadBufferingListener listener_;
  EmbeddedTestServer test_server_;
};

// TLSEarlyDataTest tests that we handle early data correctly.
TEST_F(HTTPSEarlyDataTest, TLSEarlyDataTest) {
  ASSERT_TRUE(test_server_.Start());
  context().http_transaction_factory()->GetSession()->ClearSSLSessionCache();

  // kParamSize must be larger than any ClientHello sent by the client, but
  // smaller than the maximum amount of early data allowed by the server.
  const int kParamSize = 4 * 1024;
  const GURL kUrl =
      test_server_.GetURL("/zerortt?" + std::string(kParamSize, 'a'));

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        kUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }

  context().http_transaction_factory()->GetSession()->CloseAllConnections(
      ERR_FAILED, "Very good reason");

  // 0-RTT inherently involves a race condition: if the server responds with the
  // ServerHello before the client sends the HTTP request (the client may be
  // busy verifying a certificate), the client will send data over 1-RTT keys
  // rather than 0-RTT.
  //
  // This test ensures 0-RTT is sent if relevant by making the test server wait
  // for both the ClientHello and 0-RTT HTTP request before responding. We use
  // a ReadBufferingStreamSocket and enable buffering for the 0-RTT request. The
  // buffer size must be larger than the ClientHello but smaller than the
  // ClientHello combined with the HTTP request.
  listener_.BufferNextConnection(kParamSize);

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        kUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be a single '1' in the resumed request, and
    // the handler should return "1".
    EXPECT_EQ("1", d.data_received());
  }
}

// TLSEarlyDataTest tests that we handle early data correctly for POST.
TEST_F(HTTPSEarlyDataTest, TLSEarlyDataPOSTTest) {
  ASSERT_TRUE(test_server_.Start());
  context().http_transaction_factory()->GetSession()->ClearSSLSessionCache();

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }

  context().http_transaction_factory()->GetSession()->CloseAllConnections(
      ERR_FAILED, "Very good reason");

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the request, since we don't
    // send POSTs over early data, and the handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }
}

// TLSEarlyDataTest tests that the 0-RTT is enabled for idempotent POST request.
TEST_F(HTTPSEarlyDataTest, TLSEarlyDataIdempotentPOSTTest) {
  ASSERT_TRUE(test_server_.Start());
  context().http_transaction_factory()->GetSession()->ClearSSLSessionCache();
  const int kParamSize = 4 * 1024;
  const GURL kUrl =
      test_server_.GetURL("/zerortt?" + std::string(kParamSize, 'a'));

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        kUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }

  context().http_transaction_factory()->GetSession()->CloseAllConnections(
      ERR_FAILED, "Very good reason");
  listener_.BufferNextConnection(kParamSize);

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        kUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_method("POST");
    r->SetIdempotency(net::IDEMPOTENT);
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be set since the request is set as an
    // idempotent POST request.
    EXPECT_EQ("1", d.data_received());
  }
}

// TLSEarlyDataTest tests that the 0-RTT is disabled for non-idempotent request.
TEST_F(HTTPSEarlyDataTest, TLSEarlyDataNonIdempotentRequestTest) {
  ASSERT_TRUE(test_server_.Start());
  context().http_transaction_factory()->GetSession()->ClearSSLSessionCache();

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }

  context().http_transaction_factory()->GetSession()->CloseAllConnections(
      ERR_FAILED, "Very good reason");

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    // Sets the GET request as not idempotent.
    r->SetIdempotency(net::NOT_IDEMPOTENT);
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request even
    // though it is a GET request, since the request is set as not idempotent.
    EXPECT_EQ("0", d.data_received());
  }
}

std::unique_ptr<test_server::HttpResponse> HandleTooEarly(
    bool* sent_425,
    const test_server::HttpRequest& request) {
  DCHECK(request.ssl_info);

  if (request.GetURL().path() != "/tooearly")
    return nullptr;
  if (request.ssl_info->early_data_received)
    *sent_425 = true;
  return std::make_unique<ZeroRTTResponse>(
      request.ssl_info->early_data_
```