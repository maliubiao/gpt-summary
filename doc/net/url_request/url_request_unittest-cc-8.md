Response:
The user wants to understand the functionality of the `net/url_request/url_request_unittest.cc` file in the Chromium project.

Here's a breakdown of how to address the request:

1. **Identify the core purpose:** Recognize that this is a unit test file for `URLRequest`.
2. **Analyze the test cases:**  Go through each `TEST_F` block and summarize what it's testing. Look for patterns or categories of tests (e.g., redirects, caching, authentication, error handling).
3. **Look for JavaScript relevance:**  Determine if any tested features directly interact with or are exposed to JavaScript. Think about things like CORS, cookies, redirects, and how web pages initiate network requests.
4. **Identify logical reasoning:**  Point out tests that involve setting up specific conditions and asserting expected outcomes based on network behavior.
5. **Spot user/programming errors:**  Look for tests that verify how the system handles invalid input or incorrect usage.
6. **Trace user actions (debugging):** Consider how a user's browser interaction might lead to the execution of the tested network code.
7. **Address the "part 9 of 17" instruction:**  Acknowledge this context and try to summarize the specific functionalities covered in this particular section of the tests.

**Mental Walkthrough of the Provided Code Snippet:**

* **Network Error Logging (NEL):**  A test case checks if NEL reports errors when a redirect is cancelled. This relates to browser reporting mechanisms.
* **Content-Type Normalization:** A test verifies how the system handles and parses Content-Type headers, which is crucial for proper web page rendering.
* **Redirects (Various scenarios):** Several tests focus on different aspects of redirects:
    * Redirecting to `file:` and `data:` URLs (should be blocked).
    * Restricting unsafe redirects.
    * Redirecting to invalid URLs.
    * Caching of redirects.
    * Network delegate forcing redirects (and its impact on caching).
    * Preserving URL fragments during redirects.
    * `URLRequestRedirectJob`.
* **Referrer Policy:** Tests examine how the `Referer` header is constructed and modified (e.g., removing user/pass, fragments, handling unsupported schemes, and capping length). This is related to privacy and security.
* **Cancelling and Deferring Redirects:** Tests cover scenarios where redirects are explicitly cancelled or deferred, which are important for control over the navigation flow.
* **Vary Header:** A test verifies how the `Vary` header affects caching behavior, crucial for efficient resource loading.
* **Basic Authentication:** Several tests cover different aspects of HTTP Basic Authentication: successful authentication, interaction with caching, and handling of `Set-Cookie` headers during authentication challenges.
* **IsolationInfo:** Tests check how `IsolationInfo` is updated during redirects, important for features like Site Isolation.
* **Network Anonymization Key:** A test explores how authentication caching interacts with the Network Anonymization Key.

Based on this analysis, I can now formulate the answer, addressing each point in the prompt.
这是 Chromium 网络栈中 `net/url_request/url_request_unittest.cc` 文件的第 9 部分（共 17 部分）。根据提供的代码片段，可以归纳出这部分的主要功能是**测试 `URLRequest` 类在 HTTP 重定向、缓存、身份验证和 referrer 处理方面的各种行为和边界情况**。

以下是更详细的功能列举和说明：

**功能列表:**

* **网络错误日志记录 (NEL) 和取消重定向:** 测试当启用 NEL 时，如果请求在接收到重定向时被取消，是否会记录相应的网络错误。
* **Content-Type 规范化:** 验证 `URLRequest` 能否正确解析和规范化 Content-Type 头部，提取出 MIME 类型和字符集。
* **非法 URL 重定向处理:** 测试 `URLRequest` 如何处理重定向到 `file:` 和 `data:` 协议的 URL，预期会失败。
* **限制不安全重定向:**  验证 `URLRequest` 是否会阻止重定向到不安全的协议（例如 `unsafe://`）。
* **重定向到无效 URL:** 测试 `URLRequest` 如何处理服务器返回的无效重定向 URL。
* **重定向缓存:**  验证重定向响应是否会被缓存，即使请求没有读取响应体。
* **NetworkDelegate 强制重定向和缓存:** 测试当 `NetworkDelegate` 强制重定向时，是否会阻止初始请求被缓存。
* **保留 URL 片段 (Fragment) 的重定向:** 测试 `URLRequest` 在重定向时是否能根据 `NetworkDelegate` 的配置保留原始 URL 的片段。
* **使用 `URLRequestRedirectJob` 进行重定向:** 测试使用 `URLRequestRedirectJob` 创建的重定向是否能正确执行，并且目标 URL 的片段不会被修改。
* **不支持的 Referrer 协议:** 测试当设置了不支持的 referrer 协议时，`Referer` 头部是否会被发送。
* **Referrer 中排除用户名密码:** 验证 `URLRequest` 在设置 `Referer` 头部时，是否会自动移除 URL 中的用户名和密码。
* **Referrer 中排除片段:**  验证 `URLRequest` 在设置 `Referer` 头部时，是否会自动移除 URL 中的片段。
* **先设置有效 Referrer 后设置空 Referrer:** 测试在设置过有效的 Referrer 后，再将其设置为空字符串，最终的 `Referer` 头部会是什么。
* **限制 Referer 头部长度:**  测试 `URLRequest` 是否会限制 `Referer` 头部的长度，如果超出限制，会发生什么。
* **取消重定向:** 测试在接收到重定向时取消请求会发生什么。
* **延迟重定向:** 测试 `URLRequest` 的延迟重定向功能，允许在接收到重定向响应后，稍后决定是否跟进重定向。
* **延迟重定向和修改头部:** 测试在延迟重定向时，可以修改或移除请求头部。
* **取消延迟重定向:** 测试在延迟重定向后取消请求会发生什么。
* **Vary 头部:** 测试 `Vary` 头部如何影响缓存行为。
* **Basic 认证:** 测试 `URLRequest` 如何处理 HTTP Basic 认证，包括缓存认证信息和使用缓存验证。
* **带 Cookie 的 Basic 认证:** 测试在 401 响应中包含 `Set-Cookie` 头部时，Cookie 是否会被设置，并在后续认证请求中发送。
* **带 Cookie 的 Basic 认证 (URL 中包含凭据):** 类似于上面的测试，但认证信息直接嵌入在 URL 中。
* **取消 Basic 认证:** 测试在收到认证质询后取消认证会发生什么，以及 Cookie 是否会被重复设置。
* **重定向时更新 IsolationInfo:** 测试当发生重定向时，`URLRequest` 的 `IsolationInfo` 是否会根据新的 URL 进行更新。
* **通过 NetworkAnonymizationKey 缓存认证:** 测试是否可以根据 `NetworkAnonymizationKey` 来区分缓存的 HTTP 认证信息。

**与 JavaScript 功能的关系及举例:**

这些测试的功能直接关系到浏览器如何处理网络请求，而这些请求通常是由 JavaScript 发起的。

* **重定向:**  当 JavaScript 使用 `window.location.href` 或 `<meta http-equiv="refresh">` 发起重定向时，`URLRequest` 的重定向处理逻辑会被调用。例如，如果 JavaScript 尝试重定向到一个 `file:` URL，`URLRequest` 会阻止，这会影响到网页的导航行为。
* **Content-Type:**  当浏览器接收到服务器响应时，`URLRequest` 解析的 Content-Type 信息会被传递给渲染引擎，JavaScript 可以通过 `XMLHttpRequest` 或 `fetch` API 获取响应的 `Content-Type`。错误的 Content-Type 处理可能导致 JavaScript 无法正确解析数据或浏览器无法正确渲染页面。
* **Referrer:** 当网页中的链接被点击或 JavaScript 发起新的请求时，浏览器会设置 `Referer` 头部。`URLRequest` 的 referrer 处理逻辑决定了 `Referer` 头部的具体内容，这关系到网站的来源跟踪和安全策略。例如，如果一个网站使用了不安全的 referrer 策略，可能导致敏感信息泄露。
* **缓存:**  JavaScript 发起的网络请求会受到浏览器缓存的影响。`URLRequest` 的缓存逻辑决定了哪些资源可以被缓存以及何时从缓存中加载。例如，`Vary` 头部的测试就直接关系到 JavaScript 如何利用浏览器缓存来优化性能。
* **认证:**  当网站需要用户认证时，浏览器会弹出认证对话框或使用存储的凭据。`URLRequest` 的 Basic 认证测试验证了浏览器如何处理认证质询和缓存认证信息。JavaScript 可以通过 `XMLHttpRequest` 或 `fetch` API 设置认证信息，但底层的处理逻辑仍然由 `URLRequest` 负责。

**逻辑推理、假设输入与输出:**

**示例 1:  限制不安全重定向测试**

* **假设输入:**  一个 HTTP 服务器，配置为将请求重定向到 `unsafe://here-there-be-dragons`。一个 `URLRequest` 对象请求该服务器上的初始 URL。
* **逻辑推理:** `URLRequest` 应该检测到重定向的目标是不安全的协议，并阻止重定向。
* **预期输出:** `d.request_status()` 的值为 `ERR_UNSAFE_REDIRECT`，`d.received_redirect_count()` 的值为 0。

**示例 2:  延迟重定向测试**

* **假设输入:** 一个 HTTP 服务器，配置为将请求重定向到一个包含 HTML 内容的页面。一个 `URLRequest` 对象请求该服务器上的初始 URL。
* **逻辑推理:**  调用 `RunUntilRedirect()` 会暂停请求，直到接收到重定向响应。然后调用 `FollowDeferredRedirect()` 会继续请求到最终的重定向目标。
* **预期输出:**  在 `RunUntilRedirect()` 后，`d.received_redirect_count()` 为 1。在 `FollowDeferredRedirect()` 并完成请求后，`d.request_status()` 为 `OK`，`d.data_received()` 包含重定向目标的 HTML 内容。

**用户或编程常见的使用错误:**

* **错误地假设 `file:` 或 `data:` URL 可以作为重定向目标:** 开发者可能会错误地配置服务器或使用 JavaScript 尝试将用户重定向到本地文件或 data URL，而这些操作通常是被浏览器禁止的出于安全考虑。
* **不理解 `Vary` 头部的影响:** 开发者可能没有正确配置 `Vary` 头部，导致浏览器缓存了错误的资源版本，或者没有充分利用缓存。
* **在设置 `Referer` 头部时包含敏感信息:** 开发者可能错误地使用包含用户名、密码或其它敏感信息的 URL 作为 referrer，导致信息泄露。
* **不当处理重定向:**  开发者可能没有考虑到重定向带来的性能影响或安全风险，例如过多的重定向或重定向到不信任的站点。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 URL 或点击一个链接。**
2. **如果服务器返回 HTTP 重定向响应 (3xx 状态码)，`URLRequest` 对象会处理重定向。**  相关的测试用例会模拟这种情况，例如 `TEST_F(URLRequestTestHTTP, CancelRedirect)`。
3. **用户可能会在需要身份验证的页面上触发认证流程。** 相关的测试用例会模拟这种情况，例如 `TEST_F(URLRequestTestHTTP, BasicAuth)`。
4. **JavaScript 代码可以使用 `XMLHttpRequest` 或 `fetch` API 发起网络请求，并可以设置请求头部 (包括 `Referer`)。** 相关的测试用例会模拟这种情况，例如 `TEST_F(URLRequestTestHTTP, UnsupportedReferrerScheme)`。
5. **浏览器会根据响应头部的 `Content-Type` 和缓存策略来处理响应。** 相关的测试用例会模拟这种情况，例如 `TEST_F(URLRequestTestHTTP, ContentTypeNormalizationTest)` 和 `TEST_F(URLRequestTestHTTP, VaryHeader)`。
6. **当网络请求发生错误或被取消时，`URLRequest` 对象会记录相应的状态。** 相关的测试用例会模拟这种情况，例如 `TEST_F(URLRequestTestHTTP, CancelRedirect)` 和 `TEST_F(URLRequestTestHTTP, RestrictUnsafeRedirect)`。

例如，对于 `TEST_F(URLRequestTestHTTP, CancelRedirect)`：

1. 用户在浏览器中访问一个 URL，该 URL 的服务器会返回一个重定向响应。
2. `URLRequest` 对象接收到重定向响应，并通知 `TestDelegate`。
3. `TestDelegate` 中的 `set_cancel_in_received_redirect(true)` 设置导致在接收到重定向时取消请求。
4. `URLRequest` 对象执行取消操作。
5. 测试断言验证请求状态为 `ERR_ABORTED`。

**归纳其功能 (作为第 9 部分):**

这部分测试主要集中在 **HTTP 协议特有的行为**，特别是 **重定向机制** 的各种场景，以及与 **缓存、身份验证和 referrer 处理** 相关的细节。它验证了 `URLRequest` 在处理这些 HTTP 特性时的正确性和健壮性，涵盖了正常情况、错误情况和边界情况。这部分测试确保了 Chromium 网络栈能够按照 HTTP 规范正确地处理网络请求，并提供预期的行为，对于保证浏览器的网络功能稳定性和安全性至关重要。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
);
  ASSERT_TRUE(https_test_server.Start());
  GURL request_url = https_test_server.GetURL("/redirect-test.html");

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_error_logging_enabled(true);
  auto& nel_service = *context_builder->SetNetworkErrorLoggingServiceForTesting(
      std::make_unique<TestNetworkErrorLoggingService>());
  auto context = context_builder->Build();

  TestDelegate d;
  d.set_cancel_in_received_redirect(true);
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  d.RunUntilComplete();

  ASSERT_EQ(1u, nel_service.errors().size());
  const TestNetworkErrorLoggingService::RequestDetails& error =
      nel_service.errors()[0];
  EXPECT_EQ(request_url, error.uri);
  EXPECT_EQ(302, error.status_code);
  // A valid HTTP response was received, even though the request was cancelled.
  EXPECT_EQ(OK, error.type);
}

#endif  // BUILDFLAG(ENABLE_REPORTING)

TEST_F(URLRequestTestHTTP, ContentTypeNormalizationTest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/content-type-normalization.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  std::string mime_type;
  req->GetMimeType(&mime_type);
  EXPECT_EQ("text/html", mime_type);

  std::string charset;
  req->GetCharset(&charset);
  EXPECT_EQ("utf-8", charset);
  req->Cancel();
}

TEST_F(URLRequestTestHTTP, FileRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/redirect-to-file.html"), DEFAULT_PRIORITY,
      &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(ERR_UNKNOWN_URL_SCHEME, d.request_status());
  EXPECT_EQ(1, d.received_redirect_count());
}

TEST_F(URLRequestTestHTTP, DataRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/redirect-to-data.html"), DEFAULT_PRIORITY,
      &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(ERR_UNKNOWN_URL_SCHEME, d.request_status());
  EXPECT_EQ(1, d.received_redirect_count());
}

TEST_F(URLRequestTestHTTP, RestrictUnsafeRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL(
          "/server-redirect?unsafe://here-there-be-dragons"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(ERR_UNSAFE_REDIRECT, d.request_status());

  // The redirect should have been rejected before reporting it to the
  // caller. See https://crbug.com/723796
  EXPECT_EQ(0, d.received_redirect_count());
}

// Test that redirects to invalid URLs are rejected. See
// https://crbug.com/462272.
TEST_F(URLRequestTestHTTP, RedirectToInvalidURL) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/redirect-to-invalid-url.html"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(1, d.response_started_count());
  EXPECT_EQ(ERR_INVALID_REDIRECT, d.request_status());

  // The redirect should have been rejected before reporting it to the caller.
  EXPECT_EQ(0, d.received_redirect_count());
}

// Make sure redirects are cached, despite not reading their bodies.
TEST_F(URLRequestTestHTTP, CacheRedirect) {
  ASSERT_TRUE(http_test_server()->Start());
  GURL redirect_url =
      http_test_server()->GetURL("/redirect302-to-echo-cacheable");

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        redirect_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(isolation_info1_);
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(1, d.received_redirect_count());
    EXPECT_EQ(http_test_server()->GetURL("/echo"), req->url());
  }

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        redirect_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(isolation_info1_);
    req->Start();
    d.RunUntilRedirect();

    EXPECT_EQ(1, d.received_redirect_count());
    EXPECT_EQ(0, d.response_started_count());
    EXPECT_TRUE(req->was_cached());

    req->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                                std::nullopt /* modified_headers */);
    d.RunUntilComplete();
    EXPECT_EQ(1, d.received_redirect_count());
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(http_test_server()->GetURL("/echo"), req->url());
  }
}

// Make sure a request isn't cached when a NetworkDelegate forces a redirect
// when the headers are read, since the body won't have been read.
TEST_F(URLRequestTestHTTP, NoCacheOnNetworkDelegateRedirect) {
  ASSERT_TRUE(http_test_server()->Start());
  // URL that is normally cached.
  GURL initial_url = http_test_server()->GetURL("/cachetime");

  {
    // Set up the TestNetworkDelegate tp force a redirect.
    GURL redirect_to_url = http_test_server()->GetURL("/echo");
    default_network_delegate().set_redirect_on_headers_received_url(
        redirect_to_url);

    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        initial_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(1, d.received_redirect_count());
    EXPECT_EQ(redirect_to_url, req->url());
  }

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        initial_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(OK, d.request_status());
    EXPECT_FALSE(req->was_cached());
    EXPECT_EQ(0, d.received_redirect_count());
    EXPECT_EQ(initial_url, req->url());
  }
}

// Check that |preserve_fragment_on_redirect_url| is respected.
TEST_F(URLRequestTestHTTP, PreserveFragmentOnRedirectUrl) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL original_url(http_test_server()->GetURL("/original#fragment1"));
  GURL preserve_fragement_url(http_test_server()->GetURL("/echo"));

  default_network_delegate().set_redirect_on_headers_received_url(
      preserve_fragement_url);
  default_network_delegate().set_preserve_fragment_on_redirect_url(
      preserve_fragement_url);

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2U, r->url_chain().size());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(original_url, r->original_url());
    EXPECT_EQ(preserve_fragement_url, r->url());
  }
}

// Check that |preserve_fragment_on_redirect_url| has no effect when it doesn't
// match the URL being redirected to.
TEST_F(URLRequestTestHTTP, PreserveFragmentOnRedirectUrlMismatch) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL original_url(http_test_server()->GetURL("/original#fragment1"));
  GURL preserve_fragement_url(http_test_server()->GetURL("/echo#fragment2"));
  GURL redirect_url(http_test_server()->GetURL("/echo"));
  GURL expected_url(http_test_server()->GetURL("/echo#fragment1"));

  default_network_delegate().set_redirect_on_headers_received_url(redirect_url);
  default_network_delegate().set_preserve_fragment_on_redirect_url(
      preserve_fragement_url);

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2U, r->url_chain().size());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(original_url, r->original_url());
    EXPECT_EQ(expected_url, r->url());
  }
}

// When a URLRequestRedirectJob is created, the redirection must be followed and
// the reference fragment of the target URL must not be modified.
TEST_F(URLRequestTestHTTP, RedirectJobWithReferenceFragment) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL original_url(
      http_test_server()->GetURL("/original#should-not-be-appended"));
  GURL redirect_url(http_test_server()->GetURL("/echo"));

  TestDelegate d;
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  std::unique_ptr<URLRequestRedirectJob> job =
      std::make_unique<URLRequestRedirectJob>(
          r.get(), redirect_url, RedirectUtil::ResponseCode::REDIRECT_302_FOUND,
          "Very Good Reason");
  TestScopedURLInterceptor interceptor(r->url(), std::move(job));

  r->Start();
  d.RunUntilComplete();

  EXPECT_EQ(OK, d.request_status());
  EXPECT_EQ(original_url, r->original_url());
  EXPECT_EQ(redirect_url, r->url());
}

TEST_F(URLRequestTestHTTP, UnsupportedReferrerScheme) {
  ASSERT_TRUE(http_test_server()->Start());

  const std::string referrer("foobar://totally.legit.referrer");
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetReferrer(referrer);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(std::string("None"), d.data_received());
}

TEST_F(URLRequestTestHTTP, NoUserPassInReferrer) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetReferrer("http://user:pass@foo.com/");
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(std::string("http://foo.com/"), d.data_received());
}

TEST_F(URLRequestTestHTTP, NoFragmentInReferrer) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetReferrer("http://foo.com/test#fragment");
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(std::string("http://foo.com/test"), d.data_received());
}

TEST_F(URLRequestTestHTTP, EmptyReferrerAfterValidReferrer) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetReferrer("http://foo.com/test#fragment");
  req->SetReferrer("");
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(std::string("None"), d.data_received());
}

TEST_F(URLRequestTestHTTP, CapRefererHeaderLength) {
  ASSERT_TRUE(http_test_server()->Start());

  // Verify that referrers over 4k are stripped to an origin, and referrers at
  // or under 4k are unmodified.
  {
    std::string original_header = "http://example.com/";
    original_header.resize(4097, 'a');

    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetReferrer(original_header);
    req->Start();
    d.RunUntilComplete();

    // The request's referrer will be stripped since (1) there will be a
    // mismatch between the request's referrer and the output of
    // URLRequestJob::ComputeReferrerForPolicy and (2) the delegate, when
    // offered the opportunity to cancel the request for this reason, will
    // decline.
    EXPECT_EQ("None", d.data_received());
  }
  {
    std::string original_header = "http://example.com/";
    original_header.resize(4096, 'a');

    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetReferrer(original_header);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(original_header, d.data_received());
  }
  {
    std::string original_header = "http://example.com/";
    original_header.resize(4095, 'a');

    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/echoheader?Referer"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetReferrer(original_header);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(original_header, d.data_received());
  }
}

TEST_F(URLRequestTestHTTP, CancelRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    d.set_cancel_in_received_redirect(true);
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/redirect-test.html"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, DeferredRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    GURL test_url(http_test_server()->GetURL("/redirect-test.html"));
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    req->Start();
    d.RunUntilRedirect();

    EXPECT_EQ(1, d.received_redirect_count());

    req->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                                std::nullopt /* modified_headers */);
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(OK, d.request_status());

    base::FilePath path;
    base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
    path = path.Append(kTestFilePath);
    path = path.Append(FILE_PATH_LITERAL("with-headers.html"));

    std::string contents;
    EXPECT_TRUE(base::ReadFileToString(path, &contents));
    EXPECT_EQ(contents, d.data_received());
  }
}

TEST_F(URLRequestTestHTTP, DeferredRedirect_ModifiedHeaders) {
  test_server::HttpRequest http_request;
  int num_observed_requests = 0;
  http_test_server()->RegisterRequestMonitor(
      base::BindLambdaForTesting([&](const test_server::HttpRequest& request) {
        http_request = request;
        ++num_observed_requests;
      }));
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    GURL test_url(http_test_server()->GetURL("/redirect-test.html"));
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    // Set initial headers for the request.
    req->SetExtraRequestHeaderByName("Header1", "Value1", true /* overwrite */);
    req->SetExtraRequestHeaderByName("Header2", "Value2", true /* overwrite */);

    req->Start();
    d.RunUntilRedirect();

    // Initial request should only have initial headers.
    EXPECT_EQ(1, d.received_redirect_count());
    EXPECT_EQ(1, num_observed_requests);
    EXPECT_EQ("Value1", http_request.headers["Header1"]);
    EXPECT_EQ("Value2", http_request.headers["Header2"]);
    EXPECT_EQ(0u, http_request.headers.count("Header3"));

    // Overwrite Header2 and add Header3.
    net::HttpRequestHeaders modified_headers;
    modified_headers.SetHeader("Header2", "");
    modified_headers.SetHeader("Header3", "Value3");

    req->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                                modified_headers);
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(OK, d.request_status());

    // Redirected request should also have modified headers.
    EXPECT_EQ(2, num_observed_requests);
    EXPECT_EQ("Value1", http_request.headers["Header1"]);
    EXPECT_EQ(1u, http_request.headers.count("Header2"));
    EXPECT_EQ("", http_request.headers["Header2"]);
    EXPECT_EQ("Value3", http_request.headers["Header3"]);
  }
}

TEST_F(URLRequestTestHTTP, DeferredRedirect_RemovedHeaders) {
  test_server::HttpRequest http_request;
  int num_observed_requests = 0;
  http_test_server()->RegisterRequestMonitor(
      base::BindLambdaForTesting([&](const test_server::HttpRequest& request) {
        http_request = request;
        ++num_observed_requests;
      }));
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    GURL test_url(http_test_server()->GetURL("/redirect-test.html"));
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    // Set initial headers for the request.
    req->SetExtraRequestHeaderByName("Header1", "Value1", true /* overwrite */);
    req->SetExtraRequestHeaderByName("Header2", "Value2", true /* overwrite */);

    req->Start();
    d.RunUntilRedirect();

    // Initial request should have initial headers.
    EXPECT_EQ(1, d.received_redirect_count());
    EXPECT_EQ(1, num_observed_requests);
    EXPECT_EQ("Value1", http_request.headers["Header1"]);
    EXPECT_EQ("Value2", http_request.headers["Header2"]);

    // Keep Header1 and remove Header2.
    std::vector<std::string> removed_headers({"Header2"});
    req->FollowDeferredRedirect(removed_headers,
                                std::nullopt /* modified_headers */);
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(OK, d.request_status());

    // Redirected request should have modified headers.
    EXPECT_EQ(2, num_observed_requests);
    EXPECT_EQ("Value1", http_request.headers["Header1"]);
    EXPECT_EQ(0u, http_request.headers.count("Header2"));
  }
}

TEST_F(URLRequestTestHTTP, CancelDeferredRedirect) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  {
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/redirect-test.html"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilRedirect();

    EXPECT_EQ(1, d.received_redirect_count());

    req->Cancel();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(0, d.bytes_received());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(ERR_ABORTED, d.request_status());
  }
}

TEST_F(URLRequestTestHTTP, VaryHeader) {
  ASSERT_TRUE(http_test_server()->Start());

  // Populate the cache.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/echoheadercache?foo"), DEFAULT_PRIORITY,
        &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    HttpRequestHeaders headers;
    headers.SetHeader("foo", "1");
    req->SetExtraRequestHeaders(headers);
    req->set_isolation_info(isolation_info1_);
    req->Start();
    d.RunUntilComplete();

    LoadTimingInfo load_timing_info;
    req->GetLoadTimingInfo(&load_timing_info);
    TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
  }

  // Expect a cache hit.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/echoheadercache?foo"), DEFAULT_PRIORITY,
        &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    HttpRequestHeaders headers;
    headers.SetHeader("foo", "1");
    req->SetExtraRequestHeaders(headers);
    req->set_isolation_info(isolation_info1_);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(req->was_cached());

    LoadTimingInfo load_timing_info;
    req->GetLoadTimingInfo(&load_timing_info);
    TestLoadTimingCacheHitNoNetwork(load_timing_info);
  }

  // Expect a cache miss.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/echoheadercache?foo"), DEFAULT_PRIORITY,
        &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    HttpRequestHeaders headers;
    headers.SetHeader("foo", "2");
    req->SetExtraRequestHeaders(headers);
    req->set_isolation_info(isolation_info1_);
    req->Start();
    d.RunUntilComplete();

    EXPECT_FALSE(req->was_cached());

    LoadTimingInfo load_timing_info;
    req->GetLoadTimingInfo(&load_timing_info);
    TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
  }
}

TEST_F(URLRequestTestHTTP, BasicAuth) {
  ASSERT_TRUE(http_test_server()->Start());

  // populate the cache
  {
    TestDelegate d;
    d.set_credentials(AuthCredentials(kUser, kSecret));

    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/auth-basic"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_isolation_info(isolation_info1_);
    r->Start();

    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("user/secret") != std::string::npos);
  }

  // repeat request with end-to-end validation.  since auth-basic results in a
  // cachable page, we expect this test to result in a 304.  in which case, the
  // response should be fetched from the cache.
  {
    TestDelegate d;
    d.set_credentials(AuthCredentials(kUser, kSecret));

    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/auth-basic"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->SetLoadFlags(LOAD_VALIDATE_CACHE);
    r->set_isolation_info(isolation_info1_);
    r->Start();

    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("user/secret") != std::string::npos);

    // Should be the same cached document.
    EXPECT_TRUE(r->was_cached());
  }
}

// Check that Set-Cookie headers in 401 responses are respected.
// http://crbug.com/6450
TEST_F(URLRequestTestHTTP, BasicAuthWithCookies) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL url_requiring_auth =
      http_test_server()->GetURL("/auth-basic?set-cookie-if-challenged");

  // Request a page that will give a 401 containing a Set-Cookie header.
  // Verify that when the transaction is restarted, it includes the new cookie.
  TestDelegate d;
  d.set_credentials(AuthCredentials(kUser, kSecret));

  std::unique_ptr<URLRequest> r =
      CreateFirstPartyRequest(default_context(), url_requiring_auth, &d);
  r->Start();

  d.RunUntilComplete();

  EXPECT_TRUE(d.data_received().find("user/secret") != std::string::npos);

  // Make sure we sent the cookie in the restarted transaction.
  EXPECT_TRUE(d.data_received().find("Cookie: got_challenged=true") !=
              std::string::npos);
}

// Same test as above, except this time the restart is initiated earlier
// (without user intervention since identity is embedded in the URL).
TEST_F(URLRequestTestHTTP, BasicAuthWithCredentialsWithCookies) {
  ASSERT_TRUE(http_test_server()->Start());
  GURL url_requiring_auth =
      http_test_server()->GetURL("/auth-basic?set-cookie-if-challenged");
  GURL::Replacements replacements;
  replacements.SetUsernameStr("user2");
  replacements.SetPasswordStr("secret");
  GURL url_with_identity = url_requiring_auth.ReplaceComponents(replacements);

  TestDelegate d;

  std::unique_ptr<URLRequest> r =
      CreateFirstPartyRequest(default_context(), url_with_identity, &d);
  r->Start();

  d.RunUntilComplete();

  EXPECT_TRUE(d.data_received().find("user2/secret") != std::string::npos);

  // Make sure we sent the cookie in the restarted transaction.
  EXPECT_TRUE(d.data_received().find("Cookie: got_challenged=true") !=
              std::string::npos);
}

TEST_F(URLRequestTestHTTP, BasicAuthWithCookiesCancelAuth) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL url_requiring_auth =
      http_test_server()->GetURL("/auth-basic?set-cookie-if-challenged");

  // Request a page that will give a 401 containing a Set-Cookie header.
  // Verify that cookies are set before credentials are provided, and then
  // cancelling auth does not result in setting the cookies again.
  TestDelegate d;

  EXPECT_TRUE(GetAllCookies(&default_context()).empty());

  std::unique_ptr<URLRequest> r =
      CreateFirstPartyRequest(default_context(), url_requiring_auth, &d);
  r->Start();
  d.RunUntilAuthRequired();

  // Cookie should have been set.
  EXPECT_EQ(1, default_network_delegate().set_cookie_count());
  CookieList cookies = GetAllCookies(&default_context());
  ASSERT_EQ(1u, cookies.size());
  EXPECT_EQ("got_challenged", cookies[0].Name());
  EXPECT_EQ("true", cookies[0].Value());

  // Delete cookie.
  default_context().cookie_store()->DeleteAllAsync(
      CookieStore::DeleteCallback());

  // Cancel auth and continue the request.
  r->CancelAuth();
  d.RunUntilComplete();
  ASSERT_TRUE(r->response_headers());
  EXPECT_EQ(401, r->response_headers()->response_code());

  // Cookie should not have been set again.
  EXPECT_TRUE(GetAllCookies(&default_context()).empty());
  EXPECT_EQ(1, default_network_delegate().set_cookie_count());
}

// Tests the IsolationInfo is updated approiately on redirect.
TEST_F(URLRequestTestHTTP, IsolationInfoUpdatedOnRedirect) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      net::features::kSplitCacheByNetworkIsolationKey);

  ASSERT_TRUE(http_test_server()->Start());

  GURL redirect_url =
      http_test_server()->GetURL("redirected.test", "/cachetime");
  GURL original_url = http_test_server()->GetURL(
      "original.test", "/server-redirect?" + redirect_url.spec());

  url::Origin original_origin = url::Origin::Create(original_url);
  url::Origin redirect_origin = url::Origin::Create(redirect_url);

  // Since transient IsolationInfos use opaque origins, need to create a single
  // consistent transient origin one for be used as the original and updated
  // info in the same test case.
  IsolationInfo transient_isolation_info = IsolationInfo::CreateTransient();

  const struct {
    IsolationInfo info_before_redirect;
    IsolationInfo expected_info_after_redirect;
  } kTestCases[] = {
      {IsolationInfo(), IsolationInfo()},
      {IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame,
                             original_origin, original_origin,
                             SiteForCookies()),
       IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame,
                             redirect_origin, redirect_origin,
                             SiteForCookies::FromOrigin(redirect_origin))},
      {IsolationInfo::Create(IsolationInfo::RequestType::kSubFrame,
                             original_origin, original_origin,
                             SiteForCookies::FromOrigin(original_origin)),
       IsolationInfo::Create(IsolationInfo::RequestType::kSubFrame,
                             original_origin, redirect_origin,
                             SiteForCookies::FromOrigin(original_origin))},
      {IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                             original_origin, original_origin,
                             SiteForCookies()),
       IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                             original_origin, original_origin,
                             SiteForCookies())},
      {transient_isolation_info, transient_isolation_info},
  };

  for (const auto& test_case : kTestCases) {
    // Populate the cache, using the expected final IsolationInfo.
    {
      TestDelegate d;

      std::unique_ptr<URLRequest> r(default_context().CreateRequest(
          redirect_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
      r->set_isolation_info(test_case.expected_info_after_redirect);
      r->Start();
      d.RunUntilComplete();
      EXPECT_THAT(d.request_status(), IsOk());
    }

    // Send a request using the initial IsolationInfo that should be redirected
    // to the cached url, and should use the cached entry if the NIK was
    // updated, except in the case the IsolationInfo's NIK was empty.
    {
      TestDelegate d;

      std::unique_ptr<URLRequest> r(default_context().CreateRequest(
          original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
      r->set_isolation_info(test_case.info_before_redirect);
      r->Start();
      d.RunUntilComplete();
      EXPECT_THAT(d.request_status(), IsOk());
      EXPECT_EQ(redirect_url, r->url());

      EXPECT_EQ(!test_case.expected_info_after_redirect.network_isolation_key()
                     .IsTransient(),
                r->was_cached());
      EXPECT_EQ(test_case.expected_info_after_redirect.request_type(),
                r->isolation_info().request_type());
      EXPECT_EQ(test_case.expected_info_after_redirect.top_frame_origin(),
                r->isolation_info().top_frame_origin());
      EXPECT_EQ(test_case.expected_info_after_redirect.frame_origin(),
                r->isolation_info().frame_origin());
      EXPECT_EQ(test_case.expected_info_after_redirect.network_isolation_key(),
                r->isolation_info().network_isolation_key());
      EXPECT_TRUE(test_case.expected_info_after_redirect.site_for_cookies()
                      .IsEquivalent(r->isolation_info().site_for_cookies()));
    }
  }
}

// Tests that |key_auth_cache_by_network_anonymization_key| is respected.
TEST_F(URLRequestTestHTTP, AuthWithNetworkAnonymizationKey) {
  ASSERT_TRUE(http_test_server()->Start());

  for (bool key_auth_cache_by_network_anonymization_key : {false, true}) {
    auto context_builder = CreateTestURLRequestContextBuilder();
    HttpNetworkSessionParams network_session_params;
    network_session_params
        .key_auth_cache_server_entries_by_network_anonymization_key =
        key_auth_cache_by_network_anonymization_key;
    context_builder->set_http_network_session_params(network_session_params);
    auto context = context_builder->Build();

    // Populate the auth cache using one NetworkAnonymizationKey.
    {
      TestDelegate d;
      GURL url(base::StringPrintf(
          "http://%s:%s@%s/auth-basic", base::UTF16ToASCII(kUser).c_str(),
          base::UTF16ToASCII(kSecret).c_str(),
          http_test_server()->host_port_pair().ToString().c_str()));

      std::unique_ptr<URLRequest> r(context->CreateRequest(
          url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
      r->SetLoadFlags(LOAD_BYPASS_CACHE);
      r->set_isolation_info(isolation_info1_);
      r->Start();

      d.RunUntilComplete();
      EXPECT_THAT(d.request_status(), IsOk());
      ASSERT_TRUE(r->response_headers());
      EXPECT_EQ(200, r->response_headers()->response_code());
      EXPECT_TRUE(d.data_received().find("user/secret") != std::string::npos);
    }

    // Make a request with another NetworkAnonymizationKey. This may or may not
    // use the cached auth credentials, depending on whether or not the
    // HttpAuthCache is configured to respect the NetworkAnonymizationKey.
    {
      TestDelegate d;

      std::unique_ptr<URLRequest> r(context->CreateRequest(
          http_test_server()->GetURL("/auth-basic"), DEFAULT_PRIORITY, &d,
          TRAFFIC_ANNOTATION_FOR_TESTS));
      r->SetLoadFlags(LOAD_BYPASS_CACHE);
      r->set_isolation_info(isolation_info2_);
      r->Start();

      d.RunUntilComplete();

      EXPECT_THAT(d.request_status(), IsOk());
      ASSERT_TRUE(r->response_headers());
      if (key_auth_cache_by_network_anonymization_key) {
        EXPECT_EQ(401, r->response_headers()->response_code());
      } else {
        EXPECT_EQ(200, r->response_headers()->response_code());
      }

      EXPECT_EQ(!key_auth_cache_by_network_anonymization_key,
                d.data_received().find("user/secret") != std::string::npos);
    }
  }
}

TEST_F(URLRequestTest, ReportCookieActivity) {
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());

  RecordingNetLogObserver net_log_observer;
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
```