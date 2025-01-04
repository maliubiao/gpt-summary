Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The request asks for an analysis of the given C++ code from Chromium's network stack. Specifically, it wants to know the functionality, relevance to JavaScript, logical inferences, common errors, debugging clues, and a summary of the section's purpose. The fact that it's part 11 of 17 suggests it's a subsection of a larger file.

2. **Initial Scan and Identification of Key Elements:**  Quickly read through the code, looking for recognizable patterns and keywords. Immediately, `TEST_F`, `ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_TRUE`, `GURL`, `URLRequest`, `TestDelegate`, `HttpRequestHeaders`, and the numerous calls to `http_test_server()->GetURL()` stand out. This strongly indicates a unit testing file for `URLRequest` functionality, particularly concerning HTTP redirects.

3. **Focus on `TEST_F`:** The `TEST_F` macro is the cornerstone of Google Test. Each `TEST_F` block defines an individual test case. The first argument, `URLRequestTestHTTP`, indicates the test fixture, providing context for the tests. The second argument is the specific test name (e.g., `Redirect302GetToGet`, `Redirect307Tests`).

4. **Identify the Subject of the Tests:**  The test names themselves are highly informative. They mention HTTP status codes (302, 307, 308), redirect behavior, HTTP methods (GET, POST, PUT, HEAD, OPTIONS), and header manipulation (Origin, Accept-Language, Accept-Encoding, User-Agent, Accept-Charset). This confirms that the primary focus of this code snippet is testing how `URLRequest` handles HTTP redirects and various HTTP headers.

5. **Analyze Individual Test Cases:**  Go through a few test cases in detail to understand their structure and purpose:
    * **`Redirect302GetToGet`:** Sets up an HTTP server, defines URLs that trigger 302 redirects, makes requests with different HTTP methods, and asserts that the redirect follows a GET request. The `HTTPRedirectMethodTest` and `HTTPRedirectOriginHeaderTest` helper functions are used to streamline the tests.
    * **`Redirect307Tests` and `Redirect308Tests`:** Similar to `Redirect302GetToGet`, but specifically test 307 and 308 redirects, noting the difference in method preservation.
    * **`NoRedirectOn308WithoutLocationHeader`:** Tests a specific edge case where a 308 response without a `Location` header *should not* be treated as a redirect.
    * **Header-related tests (`DefaultAcceptLanguage`, `EmptyAcceptLanguage`, `OverrideAcceptLanguage`, etc.):** These tests create `URLRequest` objects, sometimes with custom configurations (like `HttpUserAgentSettings`), and verify that the correct HTTP headers are being sent in the outgoing request.

6. **Look for Interactions with External Components:** Notice the use of `http_test_server()`. This signals reliance on a testing framework for simulating HTTP servers and responses. The `TestDelegate` class is also a common pattern in Chromium network tests for intercepting and verifying request events.

7. **Consider JavaScript Relevance:**  Think about how these low-level networking details relate to JavaScript. JavaScript in web browsers interacts with the network primarily through APIs like `fetch` and `XMLHttpRequest`. These APIs, under the hood, utilize the Chromium network stack. Therefore, the correctness of redirect handling and header management in this C++ code directly impacts how JavaScript network requests behave. Examples: A JavaScript `fetch` call might trigger a 302 redirect, and the behavior tested here determines if the subsequent request uses GET or preserves the original method. Similarly, the `Accept-Language` header set in the browser's settings (accessible by JavaScript) is handled by this code.

8. **Identify Potential Errors and Debugging Clues:**  Consider what could go wrong from a user or programmer's perspective. Users might encounter unexpected redirects or find that certain headers aren't being sent as expected. Programmers implementing network features in Chromium would use these tests to ensure their code correctly handles redirects and headers. The test setup itself (using a test server and delegates) provides debugging clues. If a test fails, it points to a problem in the corresponding `URLRequest` functionality.

9. **Infer Logical Relationships (Hypothetical Inputs and Outputs):** While the code is mostly testing pre-defined scenarios, consider some simple logical inferences. For instance, if a request with method POST encounters a 302 redirect, the output method will be GET. If a request has a specific `Accept-Language` header set, that's what the server will receive.

10. **Synthesize and Organize the Findings:**  Group the observations into the requested categories: functionality, JavaScript relevance, logical inferences, common errors, debugging clues, and summary.

11. **Focus on the "Part 11 of 17" Aspect:**  Since this is a section of a larger file, the functionality observed here likely represents one specific area of `URLRequest` testing. The broader file probably covers other aspects like caching, authentication, security, etc. The summary should reflect this focus.

12. **Refine and Elaborate:** Review the initial analysis and add more detail and specific examples where needed. Ensure the language is clear and addresses all parts of the prompt. For example, when explaining JavaScript relevance, provide concrete examples of JavaScript APIs that rely on this underlying code.

This systematic approach, starting with a high-level overview and then drilling down into specifics, allows for a comprehensive understanding of the code's purpose and its place within the larger Chromium project.
这个C++源代码文件 `url_request_unittest.cc`（第11部分，共17部分）是 Chromium 网络栈中用于测试 `URLRequest` 类的单元测试集合。 它专注于测试 `URLRequest` 在处理 **HTTP 重定向** 以及 **HTTP 头部** 方面的功能。

**核心功能归纳:**

1. **HTTP 重定向测试:**
   - 测试各种 HTTP 重定向状态码（302, 307, 308）的行为。
   - 验证不同 HTTP 方法（GET, POST, PUT, HEAD, OPTIONS）在重定向时的处理方式，例如是否会从 POST 转换为 GET。
   - 测试重定向时 `Origin` 头的处理，特别是跨域重定向时 `Origin` 头的变化（通常变为 "null"）。
   - 验证 308 重定向在没有 `Location` 头部时的行为（不应被视为重定向）。
   - 测试重定向时是否保留 URL 的 Fragment 部分 (`#fragment`).
   - 测试重定向时 Cookie 的处理，包括被 NetworkDelegate 过滤的情况。
   - 验证重定向时 `Site-For-Cookies` 和 `First-Party-URL` 的处理和更新策略。
   - 测试通过 `URLRequestRedirectJob` 拦截请求并模拟重定向的能力。

2. **HTTP 头部测试:**
   - 验证 `URLRequest` 发送的默认 HTTP 头部，例如 `Accept-Language`, `Accept-Encoding`, `User-Agent`。
   - 测试如何通过 `URLRequest` 的 API 或 `HttpRequestHeaders` 来覆盖默认的 HTTP 头部。
   - 验证在没有设置 `HttpUserAgentSettings` 时，相关头部是否被正确处理（例如，不发送 `Accept-Language`）。
   - 测试设置 `Accept-Charset` 头部。

3. **其他 `URLRequest` 功能测试:**
   - 测试在重定向后，后续请求的优先级是否能正确设置。
   - 模拟网络暂停状态，测试 `URLRequest` 在这种状态下的行为（预期会失败）。
   - 测试在创建 `HttpTransaction` 失败后，请求可以被取消，并且不会发送两次失败通知。
   - 验证是否正确记录了请求是否访问了网络（`response_info().network_accessed`）。
   - 测试 `LOAD_ONLY_FROM_CACHE` 标志是否会阻止网络访问。
   - 测试 `THROTTLED` 优先级的工作情况。
   - 检查接收到的原始 body 字节数（`GetRawBodyBytes()`），包括有内容编码的情况。
   - 测试 `NetworkDelegate::OnBeforeStartTransaction` 返回错误时的处理。
   - 测试 Referrer Policy 在重定向场景下的行为。

**与 JavaScript 功能的关系:**

`URLRequest` 是 Chromium 网络栈的核心组件，JavaScript 中发起的网络请求最终会通过它来执行。 因此，这个文件测试的功能直接影响 JavaScript 中网络请求的行为。

**举例说明:**

* **重定向:** 当 JavaScript 使用 `fetch` API 或 `XMLHttpRequest` 发起一个请求，服务器返回一个 302 重定向时，这个文件中的测试确保了浏览器会正确地发起一个新的 GET 请求到重定向的 URL（除非原始请求是 POST，且满足特定条件，可能会保持 POST 方法）。
  ```javascript
  // JavaScript 发起请求
  fetch('http://example.com/old-url'); // 假设服务器返回 302 到 http://example.com/new-url

  // 这个 C++ 文件中的测试会验证，浏览器内部的 URLRequest 是否会发起对 http://example.com/new-url 的 GET 请求。
  ```

* **HTTP 头部:**  JavaScript 可以通过 `fetch` API 的 `headers` 选项或 `XMLHttpRequest` 的 `setRequestHeader` 方法设置 HTTP 头部。 这个文件中的测试确保了这些头部会被正确地添加到 `URLRequest` 中并发送出去。
  ```javascript
  // JavaScript 设置 Accept-Language 头部
  fetch('http://example.com/api', {
    headers: {
      'Accept-Language': 'fr-FR'
    }
  });

  // 这个 C++ 文件中的 `OverrideAcceptLanguage` 测试会验证，当 JavaScript 设置了 'Accept-Language' 头部时，
  // URLRequest 不会再附加默认的语言设置。
  ```

**逻辑推理 (假设输入与输出):**

* **假设输入:** 一个 POST 请求到 `http://test.com/resource`，服务器返回 302 重定向到 `http://test.com/another-resource`。
* **预期输出:** `URLRequest` 在重定向后会发起一个 GET 请求到 `http://test.com/another-resource`。

* **假设输入:** 创建一个 `URLRequest` 并显式设置 `Accept-Language` 头部为 "es-ES"。
* **预期输出:**  发送到服务器的请求头中包含 `Accept-Language: es-ES`，即使浏览器有默认的语言设置。

**用户或编程常见的使用错误:**

* **用户错误:** 用户可能会遇到网页重定向错误，这可能与服务器配置错误或浏览器对重定向的处理不当有关。 这个文件中的测试可以帮助发现浏览器在处理重定向时的 bug。
* **编程错误 (Chromium 开发人员):**
    * 在修改 `URLRequest` 或相关的 HTTP 处理逻辑时，可能会意外引入重定向处理的 bug，例如 POST 请求没有正确转换为 GET。
    * 在添加新的 HTTP 头部处理逻辑时，可能会忘记处理覆盖默认头部的情况。
    * 没有正确处理各种重定向状态码的差异。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中输入一个 URL 或点击一个链接。**
2. **浏览器解析 URL，并创建一个 `URLRequest` 对象。**
3. **如果服务器返回一个 HTTP 重定向响应 (302, 307, 308 等)，`URLRequest` 会根据 HTTP 规范和其自身的逻辑来处理重定向。** 这个文件中的测试覆盖了这些重定向处理的各种场景。
4. **在处理重定向的过程中，可能会涉及到 HTTP 头部的修改和传递。** 例如，`Origin` 头部可能会被更新。
5. **如果用户通过 JavaScript 发起网络请求，`fetch` 或 `XMLHttpRequest` 最终会调用 Chromium 的网络栈，并使用 `URLRequest` 来执行请求。**
6. **当出现网络问题或行为不符合预期时，Chromium 开发人员可能会查看 `url_request_unittest.cc` 中的相关测试用例，以验证 `URLRequest` 的行为是否正确。** 如果测试失败，则表明 `URLRequest` 的实现存在问题。

**第 11 部分功能归纳:**

这第 11 部分的 `url_request_unittest.cc` 文件主要集中在测试 `URLRequest` 类在 **HTTP 重定向处理** 和 **HTTP 头部管理** 方面的功能。 它通过大量的单元测试用例，覆盖了各种重定向场景（不同的状态码、HTTP 方法、跨域与同域、Cookie 处理、头部设置等），以及各种 HTTP 头部（默认头部、覆盖头部、特定头部）。 这部分测试确保了 `URLRequest` 能够按照 HTTP 规范正确地处理重定向和管理 HTTP 头部，从而保证了 Chromium 浏览器网络请求的正确性和稳定性。

Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共17部分，请归纳一下它的功能

"""
tOriginHeaderTest(https_redirect_url, "OPTIONS", "GET",
                               std::string());
  HTTPRedirectOriginHeaderTest(url, "POST", "GET", std::string());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "POST", "GET",
                               std::string());
  HTTPRedirectOriginHeaderTest(url, "PUT", "GET", std::string());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "PUT", "GET", std::string());
}

TEST_F(URLRequestTestHTTP, Redirect307Tests) {
  ASSERT_TRUE(http_test_server()->Start());

  const GURL url = http_test_server()->GetURL("/redirect307-to-echo");
  const GURL https_redirect_url =
      http_test_server()->GetURL("/redirect307-to-https");

  HTTPRedirectMethodTest(url, "POST", "POST", true);
  HTTPRedirectMethodTest(url, "PUT", "PUT", true);
  HTTPRedirectMethodTest(url, "HEAD", "HEAD", false);

  HTTPRedirectOriginHeaderTest(url, "GET", "GET",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "GET", "GET", "null");
  HTTPRedirectOriginHeaderTest(url, "POST", "POST",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "POST", "POST", "null");
  HTTPRedirectOriginHeaderTest(url, "PUT", "PUT",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "PUT", "PUT", "null");
}

TEST_F(URLRequestTestHTTP, Redirect308Tests) {
  ASSERT_TRUE(http_test_server()->Start());

  const GURL url = http_test_server()->GetURL("/redirect308-to-echo");
  const GURL https_redirect_url =
      http_test_server()->GetURL("/redirect308-to-https");

  HTTPRedirectMethodTest(url, "POST", "POST", true);
  HTTPRedirectMethodTest(url, "PUT", "PUT", true);
  HTTPRedirectMethodTest(url, "HEAD", "HEAD", false);

  HTTPRedirectOriginHeaderTest(url, "GET", "GET",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "GET", "GET", "null");
  HTTPRedirectOriginHeaderTest(url, "POST", "POST",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "POST", "POST", "null");
  HTTPRedirectOriginHeaderTest(url, "PUT", "PUT",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "PUT", "PUT", "null");
}

// Make sure that 308 responses without bodies are not treated as redirects.
// Certain legacy apis that pre-date the response code expect this behavior
// (Like Google Drive).
TEST_F(URLRequestTestHTTP, NoRedirectOn308WithoutLocationHeader) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  const GURL url = http_test_server()->GetURL("/308-without-location-header");

  std::unique_ptr<URLRequest> request(default_context().CreateRequest(
      url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  request->Start();
  d.RunUntilComplete();
  EXPECT_EQ(OK, d.request_status());
  EXPECT_EQ(0, d.received_redirect_count());
  EXPECT_EQ(308, request->response_headers()->response_code());
  EXPECT_EQ("This is not a redirect.", d.data_received());
}

TEST_F(URLRequestTestHTTP, Redirect302PreserveReferenceFragment) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL original_url(
      http_test_server()->GetURL("/redirect302-to-echo#fragment"));
  GURL expected_url(http_test_server()->GetURL("/echo#fragment"));

  TestDelegate d;
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  r->Start();
  d.RunUntilComplete();

  EXPECT_EQ(2U, r->url_chain().size());
  EXPECT_EQ(OK, d.request_status());
  EXPECT_EQ(original_url, r->original_url());
  EXPECT_EQ(expected_url, r->url());
}

TEST_F(URLRequestTestHTTP, RedirectWithFilteredCookies) {
  ASSERT_TRUE(http_test_server()->Start());

  // FilteringTestNetworkDelegate filters by name, so the names of the two
  // cookies have to be the same. The values have been set to different strings
  // (the value of the server-redirect cookies is "true" and set-cookie is
  // "other") to differentiate between the two round trips.
  GURL redirect_to(
      http_test_server()->GetURL("/set-cookie?server-redirect=other"));

  GURL original_url(http_test_server()->GetURL("/server-redirect-with-cookie?" +
                                               redirect_to.spec()));

  GURL original_url_wo_cookie(
      http_test_server()->GetURL("/server-redirect?" + redirect_to.spec()));
  // Check maybe_stored_cookies on first round trip.
  {
    auto context_builder = CreateTestURLRequestContextBuilder();
    auto& filtering_network_delegate = *context_builder->set_network_delegate(
        std::make_unique<FilteringTestNetworkDelegate>());
    filtering_network_delegate.SetCookieFilter(
        "server-redirect");  // Filter the cookie server-redirect sets.
    auto context = context_builder->Build();

    TestDelegate delegate;
    std::unique_ptr<URLRequest> request =
        CreateFirstPartyRequest(*context, original_url, &delegate);

    request->Start();
    delegate.RunUntilRedirect();

    // Make sure it was blocked once.
    EXPECT_EQ(1, filtering_network_delegate.blocked_set_cookie_count());

    // The number of cookies blocked from the most recent round trip.
    ASSERT_EQ(1u, request->maybe_stored_cookies().size());
    EXPECT_EQ("server-redirect",
              request->maybe_stored_cookies().front().cookie->Name());
    EXPECT_EQ("true", request->maybe_stored_cookies().front().cookie->Value());
    EXPECT_TRUE(
        request->maybe_stored_cookies()
            .front()
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));

    // Check maybe_stored_cookies on second round trip (and clearing from the
    // first).
    request->FollowDeferredRedirect(std::nullopt, std::nullopt);
    delegate.RunUntilComplete();
    EXPECT_THAT(delegate.request_status(), IsOk());

    // There are DCHECKs in URLRequestHttpJob that would fail if
    // maybe_sent_cookies and maybe_stored_cookies we not cleared properly.

    // Make sure it was blocked twice.
    EXPECT_EQ(2, filtering_network_delegate.blocked_set_cookie_count());

    // The number of cookies blocked from the most recent round trip.
    ASSERT_EQ(1u, request->maybe_stored_cookies().size());
    EXPECT_EQ("server-redirect",
              request->maybe_stored_cookies().front().cookie->Name());
    EXPECT_EQ("other", request->maybe_stored_cookies().front().cookie->Value());
    EXPECT_TRUE(
        request->maybe_stored_cookies()
            .front()
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
  }

  // Check maybe_sent_cookies on first round trip.
  {
    auto context_builder = CreateTestURLRequestContextBuilder();
    auto& filtering_network_delegate = *context_builder->set_network_delegate(
        std::make_unique<FilteringTestNetworkDelegate>());
    filtering_network_delegate.set_block_annotate_cookies();
    context_builder->SetCookieStore(
        std::make_unique<CookieMonster>(nullptr, nullptr));
    auto context = context_builder->Build();

    auto* cm = static_cast<CookieMonster*>(context->cookie_store());
    auto another_cookie = CanonicalCookie::CreateForTesting(
        original_url, "another_cookie=true", base::Time::Now());
    cm->SetCanonicalCookieAsync(std::move(another_cookie), original_url,
                                net::CookieOptions::MakeAllInclusive(),
                                CookieStore::SetCookiesCallback());

    TestDelegate delegate;
    std::unique_ptr<URLRequest> request =
        CreateFirstPartyRequest(*context, original_url_wo_cookie, &delegate);
    request->Start();

    delegate.RunUntilRedirect();

    ASSERT_EQ(1u, request->maybe_sent_cookies().size());
    EXPECT_EQ("another_cookie",
              request->maybe_sent_cookies().front().cookie.Name());
    EXPECT_TRUE(
        request->maybe_sent_cookies()
            .front()
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));

    // Check maybe_sent_cookies on second round trip
    request->set_maybe_sent_cookies({});
    cm->DeleteAllAsync(CookieStore::DeleteCallback());
    auto one_more_cookie = CanonicalCookie::CreateForTesting(
        original_url_wo_cookie, "one_more_cookie=true", base::Time::Now());
    cm->SetCanonicalCookieAsync(std::move(one_more_cookie),
                                original_url_wo_cookie,
                                net::CookieOptions::MakeAllInclusive(),
                                CookieStore::SetCookiesCallback());

    request->FollowDeferredRedirect(std::nullopt, std::nullopt);
    delegate.RunUntilComplete();
    EXPECT_THAT(delegate.request_status(), IsOk());

    // There are DCHECKs in URLRequestHttpJob that would fail if
    // maybe_sent_cookies and maybe_stored_cookies we not cleared properly.

    EXPECT_EQ(2, filtering_network_delegate.blocked_annotate_cookies_count());

    // The number of cookies blocked from the most recent round trip.
    ASSERT_EQ(1u, request->maybe_sent_cookies().size());
    EXPECT_EQ("one_more_cookie",
              request->maybe_sent_cookies().front().cookie.Name());
    EXPECT_EQ("true", request->maybe_sent_cookies().front().cookie.Value());
    EXPECT_TRUE(
        request->maybe_sent_cookies()
            .front()
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
  }
}

TEST_F(URLRequestTestHTTP, RedirectPreserveFirstPartyURL) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL url(http_test_server()->GetURL("/redirect302-to-echo"));
  GURL first_party_url("http://example.com");

  TestDelegate d;
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->set_site_for_cookies(SiteForCookies::FromUrl(first_party_url));

  r->Start();
  d.RunUntilComplete();

  EXPECT_EQ(2U, r->url_chain().size());
  EXPECT_EQ(OK, d.request_status());
  EXPECT_TRUE(SiteForCookies::FromUrl(first_party_url)
                  .IsEquivalent(r->site_for_cookies()));
}

TEST_F(URLRequestTestHTTP, RedirectUpdateFirstPartyURL) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL url(http_test_server()->GetURL("/redirect302-to-echo"));
  GURL original_first_party_url("http://example.com");
  GURL expected_first_party_url(http_test_server()->GetURL("/echo"));

  TestDelegate d;

    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_site_for_cookies(SiteForCookies::FromUrl(original_first_party_url));
    r->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);

    r->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2U, r->url_chain().size());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_TRUE(SiteForCookies::FromUrl(expected_first_party_url)
                    .IsEquivalent(r->site_for_cookies()));
}

TEST_F(URLRequestTestHTTP, InterceptPost302RedirectGet) {
  ASSERT_TRUE(http_test_server()->Start());

  const char kData[] = "hello world";

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_method("POST");
  req->set_upload(CreateSimpleUploadData(base::byte_span_from_cstring(kData)));
  HttpRequestHeaders headers;
  headers.SetHeader(HttpRequestHeaders::kContentLength,
                    base::NumberToString(std::size(kData) - 1));
  req->SetExtraRequestHeaders(headers);

  std::unique_ptr<URLRequestRedirectJob> job =
      std::make_unique<URLRequestRedirectJob>(
          req.get(), http_test_server()->GetURL("/echo"),
          RedirectUtil::ResponseCode::REDIRECT_302_FOUND, "Very Good Reason");
  TestScopedURLInterceptor interceptor(req->url(), std::move(job));

  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ("GET", req->method());
}

TEST_F(URLRequestTestHTTP, InterceptPost307RedirectPost) {
  ASSERT_TRUE(http_test_server()->Start());

  const char kData[] = "hello world";

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/defaultresponse"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_method("POST");
  req->set_upload(CreateSimpleUploadData(base::byte_span_from_cstring(kData)));
  HttpRequestHeaders headers;
  headers.SetHeader(HttpRequestHeaders::kContentLength,
                    base::NumberToString(std::size(kData) - 1));
  req->SetExtraRequestHeaders(headers);

  std::unique_ptr<URLRequestRedirectJob> job =
      std::make_unique<URLRequestRedirectJob>(
          req.get(), http_test_server()->GetURL("/echo"),
          RedirectUtil::ResponseCode::REDIRECT_307_TEMPORARY_REDIRECT,
          "Very Good Reason");
  TestScopedURLInterceptor interceptor(req->url(), std::move(job));

  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ("POST", req->method());
  EXPECT_EQ(kData, d.data_received());
}

// Check that default A-L header is sent.
TEST_F(URLRequestTestHTTP, DefaultAcceptLanguage) {
  ASSERT_TRUE(http_test_server()->Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_http_user_agent_settings(
      std::make_unique<StaticHttpUserAgentSettings>("en", "test-ua"));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL("/echoheader?Accept-Language"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ("en", d.data_received());
}

// Check that an empty A-L header is not sent. http://crbug.com/77365.
TEST_F(URLRequestTestHTTP, EmptyAcceptLanguage) {
  ASSERT_TRUE(http_test_server()->Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_http_user_agent_settings(
      std::make_unique<StaticHttpUserAgentSettings>(std::string(), "test-ua"));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL("/echoheader?Accept-Language"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ("None", d.data_received());
}

// Check that if request overrides the A-L header, the default is not appended.
// See http://crbug.com/20894
TEST_F(URLRequestTestHTTP, OverrideAcceptLanguage) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Accept-Language"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  HttpRequestHeaders headers;
  headers.SetHeader(HttpRequestHeaders::kAcceptLanguage, "ru");
  req->SetExtraRequestHeaders(headers);
  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ(std::string("ru"), d.data_received());
}

// Check that default A-E header is sent.
TEST_F(URLRequestTestHTTP, DefaultAcceptEncoding) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Accept-Encoding"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  HttpRequestHeaders headers;
  req->SetExtraRequestHeaders(headers);
  req->Start();
  d.RunUntilComplete();
  EXPECT_TRUE(ContainsString(d.data_received(), "gzip"));
}

// Check that it's possible to override the default A-E header.
TEST_F(URLRequestTestHTTP, DefaultAcceptEncodingOverriden) {
  ASSERT_TRUE(http_test_server()->Start());

  struct {
    base::flat_set<net::SourceStream::SourceType> accepted_types;
    const char* expected_accept_encoding;
  } tests[] = {{{net::SourceStream::SourceType::TYPE_DEFLATE}, "deflate"},
               {{}, "None"},
               {{net::SourceStream::SourceType::TYPE_GZIP}, "gzip"},
               {{net::SourceStream::SourceType::TYPE_GZIP,
                 net::SourceStream::SourceType::TYPE_DEFLATE},
                "gzip, deflate"}};
  for (auto test : tests) {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        http_test_server()->GetURL("/echoheader?Accept-Encoding"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_accepted_stream_types(test.accepted_types);
    req->Start();
    d.RunUntilComplete();
    EXPECT_STRCASEEQ(d.data_received().c_str(), test.expected_accept_encoding);
  }
}

// Check that if request overrides the A-E header, the default is not appended.
// See http://crbug.com/47381
TEST_F(URLRequestTestHTTP, OverrideAcceptEncoding) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Accept-Encoding"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  HttpRequestHeaders headers;
  headers.SetHeader(HttpRequestHeaders::kAcceptEncoding, "identity");
  req->SetExtraRequestHeaders(headers);
  req->Start();
  d.RunUntilComplete();
  EXPECT_FALSE(ContainsString(d.data_received(), "gzip"));
  EXPECT_TRUE(ContainsString(d.data_received(), "identity"));
}

// Check that setting the A-C header sends the proper header.
TEST_F(URLRequestTestHTTP, SetAcceptCharset) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?Accept-Charset"),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  HttpRequestHeaders headers;
  headers.SetHeader(HttpRequestHeaders::kAcceptCharset, "koi-8r");
  req->SetExtraRequestHeaders(headers);
  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ(std::string("koi-8r"), d.data_received());
}

// Check that default User-Agent header is sent.
TEST_F(URLRequestTestHTTP, DefaultUserAgent) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?User-Agent"), DEFAULT_PRIORITY,
      &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ(default_context().http_user_agent_settings()->GetUserAgent(),
            d.data_received());
}

// Check that if request overrides the User-Agent header,
// the default is not appended.
// TODO(crbug.com/41225288) This test is flaky on iOS.
#if BUILDFLAG(IS_IOS)
#define MAYBE_OverrideUserAgent FLAKY_OverrideUserAgent
#else
#define MAYBE_OverrideUserAgent OverrideUserAgent
#endif
TEST_F(URLRequestTestHTTP, MAYBE_OverrideUserAgent) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/echoheader?User-Agent"), DEFAULT_PRIORITY,
      &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  HttpRequestHeaders headers;
  headers.SetHeader(HttpRequestHeaders::kUserAgent, "Lynx (textmode)");
  req->SetExtraRequestHeaders(headers);
  req->Start();
  d.RunUntilComplete();
  EXPECT_EQ(std::string("Lynx (textmode)"), d.data_received());
}

// Check that a NULL HttpUserAgentSettings causes the corresponding empty
// User-Agent header to be sent but does not send the Accept-Language and
// Accept-Charset headers.
TEST_F(URLRequestTestHTTP, EmptyHttpUserAgentSettings) {
  ASSERT_TRUE(http_test_server()->Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_http_user_agent_settings(nullptr);
  auto context = context_builder->Build();

  struct {
    const char* request;
    const char* expected_response;
  } tests[] = {{"/echoheader?Accept-Language", "None"},
               {"/echoheader?Accept-Charset", "None"},
               {"/echoheader?User-Agent", ""}};

  for (const auto& test : tests) {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        http_test_server()->GetURL(test.request), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(test.expected_response, d.data_received())
        << " Request = \"" << test.request << "\"";
  }
}

// Make sure that URLRequest passes on its priority updates to
// newly-created jobs after the first one.
TEST_F(URLRequestTestHTTP, SetSubsequentJobPriority) {
  GURL initial_url("http://foo.test/");
  GURL redirect_url("http://bar.test/");

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      initial_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(DEFAULT_PRIORITY, req->priority());

  std::unique_ptr<URLRequestRedirectJob> redirect_job =
      std::make_unique<URLRequestRedirectJob>(
          req.get(), redirect_url,
          RedirectUtil::ResponseCode::REDIRECT_302_FOUND, "Very Good Reason");
  auto interceptor = std::make_unique<TestScopedURLInterceptor>(
      initial_url, std::move(redirect_job));

  req->SetPriority(LOW);
  req->Start();
  EXPECT_TRUE(req->is_pending());
  d.RunUntilRedirect();
  interceptor.reset();

  RequestPriority job_priority;
  std::unique_ptr<URLRequestJob> job =
      std::make_unique<PriorityMonitoringURLRequestJob>(req.get(),
                                                        &job_priority);
  interceptor =
      std::make_unique<TestScopedURLInterceptor>(redirect_url, std::move(job));

  // Should trigger |job| to be started.
  req->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                              std::nullopt /* modified_headers */);
  d.RunUntilComplete();
  EXPECT_EQ(LOW, job_priority);
}

// Check that creating a network request while entering/exiting suspend mode
// fails as it should.  This is the only case where an HttpTransactionFactory
// does not return an HttpTransaction.
TEST_F(URLRequestTestHTTP, NetworkSuspendTest) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCreateHttpTransactionFactoryCallback(
      base::BindOnce([](HttpNetworkSession* session) {
        // Create a new HttpNetworkLayer that thinks it's suspended.
        auto network_layer = std::make_unique<HttpNetworkLayer>(session);
        network_layer->OnSuspend();
        std::unique_ptr<HttpTransactionFactory> factory =
            std::make_unique<HttpCache>(std::move(network_layer),
                                        HttpCache::DefaultBackend::InMemory(0));
        return factory;
      }));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://127.0.0.1/"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_TRUE(d.request_failed());
  EXPECT_EQ(ERR_NETWORK_IO_SUSPENDED, d.request_status());
}

namespace {

// HttpTransactionFactory that synchronously fails to create transactions.
class FailingHttpTransactionFactory : public HttpTransactionFactory {
 public:
  explicit FailingHttpTransactionFactory(HttpNetworkSession* network_session)
      : network_session_(network_session) {}

  FailingHttpTransactionFactory(const FailingHttpTransactionFactory&) = delete;
  FailingHttpTransactionFactory& operator=(
      const FailingHttpTransactionFactory&) = delete;

  ~FailingHttpTransactionFactory() override = default;

  // HttpTransactionFactory methods:
  int CreateTransaction(RequestPriority priority,
                        std::unique_ptr<HttpTransaction>* trans) override {
    return ERR_FAILED;
  }

  HttpCache* GetCache() override { return nullptr; }

  HttpNetworkSession* GetSession() override { return network_session_; }

 private:
  raw_ptr<HttpNetworkSession> network_session_;
};

}  // namespace

// Check that when a request that fails to create an HttpTransaction can be
// cancelled while the failure notification is pending, and doesn't send two
// failure notifications.
//
// This currently only happens when in suspend mode and there's no cache, but
// just use a special HttpTransactionFactory, to avoid depending on those
// behaviors.
TEST_F(URLRequestTestHTTP, NetworkCancelAfterCreateTransactionFailsTest) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCreateHttpTransactionFactoryCallback(
      base::BindOnce([](HttpNetworkSession* session) {
        std::unique_ptr<HttpTransactionFactory> factory =
            std::make_unique<FailingHttpTransactionFactory>(session);
        return factory;
      }));
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<TestNetworkDelegate>());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://127.0.0.1/"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  // Don't send cookies (Collecting cookies is asynchronous, and need request to
  // try to create an HttpNetworkTransaction synchronously on start).
  req->set_allow_credentials(false);
  req->Start();
  req->Cancel();
  d.RunUntilComplete();
  // Run pending error task, if there is one.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(d.request_failed());
  EXPECT_EQ(1, d.response_started_count());
  EXPECT_EQ(ERR_ABORTED, d.request_status());

  // NetworkDelegate should see the cancellation, but not the error.
  EXPECT_EQ(1, network_delegate.canceled_requests());
  EXPECT_EQ(0, network_delegate.error_count());
}

TEST_F(URLRequestTestHTTP, NetworkAccessedSetOnNetworkRequest) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  GURL test_url(http_test_server()->GetURL("/"));
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  req->Start();
  d.RunUntilComplete();

  EXPECT_TRUE(req->response_info().network_accessed);
}

TEST_F(URLRequestTestHTTP, NetworkAccessedClearOnCachedResponse) {
  ASSERT_TRUE(http_test_server()->Start());

  // Populate the cache.
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/cachetime"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_isolation_info(isolation_info1_);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(OK, d.request_status());
  EXPECT_TRUE(req->response_info().network_accessed);
  EXPECT_FALSE(req->response_info().was_cached);

  req = default_context().CreateRequest(
      http_test_server()->GetURL("/cachetime"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  req->set_isolation_info(isolation_info1_);
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(OK, d.request_status());
  EXPECT_FALSE(req->response_info().network_accessed);
  EXPECT_TRUE(req->response_info().was_cached);
}

TEST_F(URLRequestTestHTTP, NetworkAccessedClearOnLoadOnlyFromCache) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  GURL test_url(http_test_server()->GetURL("/"));
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetLoadFlags(LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION);

  req->Start();
  d.RunUntilComplete();

  EXPECT_FALSE(req->response_info().network_accessed);
}

// Test that a single job with a THROTTLED priority completes
// correctly in the absence of contention.
TEST_F(URLRequestTestHTTP, ThrottledPriority) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  GURL test_url(http_test_server()->GetURL("/"));
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      test_url, THROTTLED, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(OK, d.request_status());
}

TEST_F(URLRequestTestHTTP, RawBodyBytesNoContentEncoding) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/simple.html"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(5, req->GetRawBodyBytes());
}

TEST_F(URLRequestTestHTTP, RawBodyBytesGzipEncoding) {
  ASSERT_TRUE(http_test_server()->Start());

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/gzip-encoded"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(30, req->GetRawBodyBytes());
}

// Check that if NetworkDelegate::OnBeforeStartTransaction returns an error,
// the delegate isn't called back synchronously.
TEST_F(URLRequestTestHTTP, TesBeforeStartTransactionFails) {
  ASSERT_TRUE(http_test_server()->Start());
  default_network_delegate().set_before_start_transaction_fails();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->Start();
  DCHECK(!d.response_completed());
  d.RunUntilComplete();
  DCHECK(d.response_completed());
  EXPECT_EQ(ERR_FAILED, d.request_status());
}

class URLRequestTestReferrerPolicy : public URLRequestTest {
 public:
  URLRequestTestReferrerPolicy() = default;

  void InstantiateSameOriginServers(net::EmbeddedTestServer::Type type) {
    origin_server_ = std::make_unique<EmbeddedTestServer>(type);
    RegisterDefaultHandlers(origin_server_.get());
    ASSERT_TRUE(origin_server_->Start());
  }

  void InstantiateCrossOriginServers(net::EmbeddedTestServer::Type origin_type,
                                     net::EmbeddedTestServer::Type dest_type) {
    origin_server_ = std::make_unique<EmbeddedTestServer>(origin_type);
    RegisterDefaultHandlers(origin_server_.get());
    ASSERT_TRUE(origin_server_->Start());

    destination_server_ = std::make_unique<EmbeddedTestServer>(dest_type);
    RegisterDefaultHandlers(destination_server_.get());
    ASSERT_TRUE(destination_server_->Start());
  }

  void VerifyReferrerAfterRedirect(ReferrerPolicy policy,
                                   const GURL& referrer,
                                   const GURL& expected) {
    // Create and execute the request: we'll only have a |destination_server_|
    // if the origins are meant to be distinct. Otherwise, we'll use the
    // |origin_server_| for both endpoints.
    GURL destination_url =
        destination_server_ ? destination_server_->GetURL("/echoheader?Referer")
                            : origin_server_->GetURL("/echoheader?Referer");
    GURL origin_url =
        origin_server_->GetURL("/server-redirect?" + destination_url.spec());

    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        origin_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_referrer_policy(policy);
    req->SetReferrer(referrer.spec());
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(1, d.received_redirect_count());
    EXPECT_EQ(destination_url, req->url());
    EXPECT_EQ(OK, d.request_status());
    EXPECT_EQ(200, req->response_headers()->response_code());

    EXPECT_EQ(expected.spec(), req->referrer());
    if (expected.is_empty())
      EXPECT_EQ("None", d.data_received());
    else
      EXPECT_EQ(expected.spec(), d.data_received());
  }

  EmbeddedTestServer* origin_server() const { return origin_server_.get(); }

 private:
  std::unique_ptr<EmbeddedTestServer> origin_server_;
  std::unique_ptr<EmbeddedTestServer> destination_server_;
};

TEST_F(URLRequestTestReferrerPolicy, HTTPToSameOriginHTTP) {
  InstantiateSameOriginServers(net::EmbeddedTestServer::TYPE_HTTP);

  GURL referrer = origin_server()->GetURL("/path/to/file.html");
  VerifyReferrerAfterRedirect(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      referrer);

  VerifyReferrerAfterRedirect(
      ReferrerPolicy::ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN, referrer,
      r
"""


```