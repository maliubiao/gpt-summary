Response:
The user wants to understand the functionality of the Chromium source code file `net/url_request/url_request_unittest.cc`.
This is the 4th part of a 17-part explanation.
The focus of this part seems to be related to `SameSite` cookie behavior in different scenarios involving `URLRequest`.

Here's a breakdown of the user's requirements and how to address them:

1. **List the functions of the code:**  I need to analyze the code snippets provided and identify the core functionalities being tested. This mainly involves how `URLRequest` handles `SameSite` cookies in various situations.

2. **Explain the relation to JavaScript:** I need to consider how these functionalities might interact with JavaScript running in a web browser. This usually involves how JavaScript can set or access cookies.

3. **Provide examples for JavaScript interaction:** If a relation exists, I need to provide illustrative JavaScript code snippets.

4. **Give examples of logical reasoning (input/output):** For specific test cases, I can provide hypothetical inputs (e.g., request URL, cookie settings) and expected outputs (e.g., whether the cookie is sent or set).

5. **Illustrate common user/programming errors:** I need to identify potential mistakes users or developers might make related to `SameSite` cookies and `URLRequest`.

6. **Explain how user actions lead to this code (debugging):** I should describe a typical user interaction in a browser that would trigger the network requests being tested in this file.

7. **Summarize the functionality of this part:**  Condense the identified functionalities into a concise summary.

**Mental Sandbox Simulation:**

* **Code Analysis:** The code uses `EXPECT_EQ` and `EXPECT_NE` extensively, indicating unit tests. The tests revolve around `URLRequest` and how `SameSite` cookies are handled based on factors like request type (main frame, subframe), initiator origin, site for cookies, request method (GET, POST), and redirects.
* **JavaScript Relation:** JavaScript's `document.cookie` API and the `fetch` API are directly related to cookie behavior. The tests verify the underlying network stack's implementation that supports these JavaScript APIs.
* **Logical Reasoning:** For example, a test verifies that a `SameSite=Strict` cookie is not sent on a cross-site subresource request. Input: Cross-site subresource request, `SameSite=Strict` cookie. Output: Cookie not sent.
* **User Errors:** A common error is misunderstanding how `SameSite=Lax` works, particularly with cross-site form submissions.
* **User Path:** A user clicking a link or submitting a form triggers network requests, which are the subject of these tests. Redirects are also common user-driven navigation patterns.
* **Part Summary:** This specific part focuses on testing how `URLRequest` correctly handles `SameSite` cookies in direct requests and during redirects, considering factors like initiator, site for cookies, and request type.

Strategizing complete. I will now generate the response based on these insights.
这是 Chromium 网络栈中 `net/url_request/url_request_unittest.cc` 文件的第四部分，主要功能是 **测试 `URLRequest` 类在处理 `SameSite` cookie 时的各种场景和逻辑**。它涵盖了以下几个方面的测试：

**核心功能归纳:**

* **验证 `SameSite` cookie 的发送行为：**  测试在不同情况下（同源、同站、跨站请求，主框架导航、子资源请求，GET/POST 方法）`Strict` 和 `Lax` 属性的 `SameSite` cookie 是否会被发送。
* **验证 `SameSite` cookie 的设置行为：** 测试在不同情况下（同源、同站、跨站上下文，主框架导航、子资源请求）`Strict` 和 `Lax` 属性的 `SameSite` cookie 是否能够被成功设置。
* **验证重定向场景下的 `SameSite` cookie 处理：** 测试在发生重定向时，`SameSite` cookie 的发送和设置行为，包括同源、同站、跨站重定向，以及跨协议重定向。
* **测试特殊 scheme (如 `chrome://`) 对 `SameSite` cookie 的处理：**  验证对于 `chrome://` 这样的内部 scheme，`SameSite` cookie 的特殊处理逻辑，通常会忽略 `SameSite` 限制（如果目标是安全的）。

**与 JavaScript 功能的关系及举例说明：**

`URLRequest` 是 Chromium 网络栈的核心组件，负责发起网络请求。`SameSite` cookie 是 Web 标准，用于增强安全性，防止跨站请求伪造（CSRF）攻击。JavaScript 可以通过 `document.cookie` API 读取和设置 Cookie，并通过 `fetch` 或 `XMLHttpRequest` 发起网络请求。

这个文件中的测试直接关系到浏览器如何根据 `SameSite` 属性来决定是否在 JavaScript 发起的请求中包含 Cookie。

**举例说明：**

1. **JavaScript 发起跨站子资源请求，设置了 `SameSite=Strict` 的 Cookie 将不会被发送：**

   假设一个网站 `a.com` 设置了一个 `SameSite=Strict` 的 Cookie。在 `b.com` 的 JavaScript 中，通过 `fetch` 请求 `a.com` 的图片资源：

   ```javascript
   fetch('https://a.com/image.png');
   ```

   这个测试文件中的相关测试会验证在这种情况下，设置在 `a.com` 的 `SameSite=Strict` Cookie 不会被包含在发送给 `a.com` 的请求头中。

2. **JavaScript 发起同站主框架导航，设置了 `SameSite=Lax` 的 Cookie 将会被发送：**

   假设用户在 `a.com` 上，JavaScript 通过修改 `window.location.href` 跳转到 `sub.a.com` 的另一个页面：

   ```javascript
   window.location.href = 'https://sub.a.com/newpage';
   ```

   如果 `a.com` 设置了一个 `SameSite=Lax` 的 Cookie，这个测试文件中的相关测试会验证该 Cookie 是否会被包含在导航到 `sub.a.com` 的请求头中。

**逻辑推理的假设输入与输出：**

**假设输入：**

* **场景 1:**  一个从 `https://example.com` 发起的请求，目标 URL 是 `https://api.another.com/data`，请求方法是 `GET`。`https://example.com` 设置了一个名为 `my_strict_cookie`，属性为 `SameSite=Strict` 的 Cookie。
* **场景 2:**  一个用户在 `https://site1.com` 点击了一个链接，跳转到 `https://site1.com/page2`。`https://site1.com` 设置了一个名为 `my_lax_cookie`，属性为 `SameSite=Lax` 的 Cookie。
* **场景 3:**  一个从 `https://origin.com` 发起的请求，通过 `fetch` 请求 `https://target.com/api`，请求方法是 `POST`。`https://origin.com` 设置了一个名为 `my_lax_cookie`，属性为 `SameSite=Lax` 的 Cookie。

**输出：**

* **场景 1:**  `my_strict_cookie` **不会** 被包含在发送给 `https://api.another.com/data` 的请求头中。
* **场景 2:**  `my_lax_cookie` **会** 被包含在跳转到 `https://site1.com/page2` 的请求头中。
* **场景 3:**  `my_lax_cookie` **不会** 被包含在发送给 `https://target.com/api` 的请求头中（因为是 `POST` 请求）。

**涉及用户或编程常见的使用错误：**

1. **误解 `SameSite=Lax` 的适用场景：**  开发者可能认为 `SameSite=Lax` 的 Cookie 在所有跨站请求中都会发送，但实际上它只针对 "安全" 的 HTTP 方法（GET, HEAD, OPTIONS, TRACE, CONNECT）和顶级的导航请求。例如，使用 `POST` 方法提交跨站表单时，`SameSite=Lax` 的 Cookie 不会被发送，这可能会导致用户登录状态丢失或其他功能异常。

   **例子：** 用户在 `evil.com` 上填写表单，提交到 `good.com`。如果 `good.com` 有一个 `SameSite=Lax` 的会话 Cookie，这个 Cookie 不会被发送，导致 `good.com` 无法识别用户身份。

2. **在需要跨站请求时错误地使用了 `SameSite=Strict`：**  如果一个网站的某些功能依赖于跨站请求携带 Cookie（例如，嵌入在其他网站的图片或资源），设置了 `SameSite=Strict` 会阻止这些 Cookie 的发送，导致功能失效。

   **例子：**  一个 CDN 托管的图片资源，需要携带用户身份验证 Cookie。如果该 Cookie 设置了 `SameSite=Strict`，当其他网站引用该图片时，Cookie 不会被发送，可能导致图片加载失败或用户身份验证失败。

**用户操作如何一步步到达这里 (调试线索)：**

假设用户在使用 Chrome 浏览器浏览网页时遇到以下情况：

1. **用户点击了一个跨站链接：** 用户在 `a.com` 上点击了一个指向 `b.com` 的链接。浏览器会创建一个新的 `URLRequest` 来请求 `b.com` 的页面。这个请求会触发对 `SameSite` Cookie 规则的检查，决定是否包含 `a.com` 设置的 Cookie。

2. **用户提交了一个跨站表单：** 用户在 `a.com` 上填写了一个表单，并将数据提交到 `b.com`。浏览器会创建一个 `URLRequest` 来发送 `POST` 请求到 `b.com`。同样，会检查 `SameSite` Cookie 规则。

3. **网页上的 JavaScript 发起跨站请求：** 网页上的 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 向另一个域名发送请求。浏览器会创建一个 `URLRequest` 来处理这个 JavaScript 发起的请求，并根据 `SameSite` 规则决定是否携带 Cookie。

4. **发生重定向：** 用户访问一个 URL，服务器返回 HTTP 重定向响应，浏览器会创建一个新的 `URLRequest` 来请求重定向的目标 URL。在这个过程中，会再次评估 `SameSite` Cookie 的规则。

在上述任何一种用户操作导致浏览器发起网络请求时，Chromium 的网络栈会创建 `URLRequest` 对象，并执行相关的 Cookie 处理逻辑，这部分代码就是用来测试这些逻辑是否正确实现的。如果开发者在调试网络请求和 Cookie 时发现 `SameSite` Cookie 的行为与预期不符，他们可能会查看 `net/url_request/url_request_unittest.cc` 中的相关测试用例，以了解 Chromium 内部是如何处理这些情况的。

**本部分功能归纳 (作为第 4 部分):**

作为 17 个部分中的第 4 部分，这个代码片段主要专注于 **`URLRequest` 对 `SameSite` Cookie 的核心处理逻辑测试**。它深入测试了在各种基本场景下，`SameSite=Strict` 和 `SameSite=Lax` 的 Cookie 是否会被正确地发送和设置。这为后续更复杂的测试场景（例如涉及重定向、特殊 scheme）奠定了基础，并确保了 Chromium 对 `SameSite` Cookie 这一重要安全特性的正确实现。  可以理解为这是 `SameSite` Cookie 功能测试的 **基础核心用例部分**。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
);
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that neither cookie is not sent for cross-site requests.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(kCrossSiteForCookies);
    req->set_initiator(kCrossOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_EQ(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the lax cookie is sent for cross-site initiators when the
  // method is "safe" and the request is a main frame navigation.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kCrossOrigin);
    req->set_method("GET");
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that the lax cookie is sent for cross-site initiators when the
  // method is "safe" and the request is being forced to be considered as a
  // main frame navigation.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kCrossOrigin);
    req->set_method("GET");
    req->set_force_main_frame_for_same_site_cookies(true);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that neither cookie is sent for cross-site initiators when the
  // method is unsafe (e.g. POST), even if the request is a main frame
  // navigation.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kCrossOrigin);
    req->set_method("POST");
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_EQ(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());
  }

  // Verify that neither cookie is sent for cross-site initiators when the
  // method is safe and the site-for-cookies is same-site, but the request is
  // not a main frame navigation.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kSubFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kCrossOrigin);
    req->set_method("GET");
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_EQ(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
    EXPECT_EQ(0, default_network_delegate().blocked_annotate_cookies_count());
    EXPECT_EQ(0, default_network_delegate().blocked_set_cookie_count());

    // Check that the appropriate cookie inclusion status is set.
    ASSERT_EQ(2u, req->maybe_sent_cookies().size());
    CookieInclusionStatus expected_strict_status =
        CookieInclusionStatus::MakeFromReasonsForTesting(
            {CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT});
    CookieInclusionStatus expected_lax_status =
        CookieInclusionStatus::MakeFromReasonsForTesting(
            {CookieInclusionStatus::EXCLUDE_SAMESITE_LAX});
    EXPECT_EQ(expected_strict_status,
              req->maybe_sent_cookies()[0].access_result.status);
    EXPECT_EQ(expected_lax_status,
              req->maybe_sent_cookies()[1].access_result.status);
  }
}

TEST_P(URLRequestSameSiteCookiesTest, SameSiteCookies_Redirect) {
  EmbeddedTestServer http_server;
  RegisterDefaultHandlers(&http_server);
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(http_server.Start());
  ASSERT_TRUE(https_server.Start());

  const std::string kHost = "foo.a.test";
  const std::string kSameSiteHost = "bar.a.test";
  const std::string kCrossSiteHost = "b.test";
  const url::Origin kOrigin =
      url::Origin::Create(https_server.GetURL(kHost, "/"));
  const url::Origin kHttpOrigin =
      url::Origin::Create(http_server.GetURL(kHost, "/"));
  const url::Origin kSameSiteOrigin =
      url::Origin::Create(https_server.GetURL(kSameSiteHost, "/"));
  const url::Origin kCrossSiteOrigin =
      url::Origin::Create(https_server.GetURL(kCrossSiteHost, "/"));
  const SiteForCookies kSiteForCookies = SiteForCookies::FromOrigin(kOrigin);
  const SiteForCookies kHttpSiteForCookies =
      SiteForCookies::FromOrigin(kHttpOrigin);
  const SiteForCookies kCrossSiteForCookies =
      SiteForCookies::FromOrigin(kCrossSiteOrigin);

  // Set up two 'SameSite' cookies on foo.a.test
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req = CreateFirstPartyRequest(
        default_context(),
        https_server.GetURL(
            kHost,
            "/set-cookie?StrictSameSiteCookie=1;SameSite=Strict&"
            "LaxSameSiteCookie=1;SameSite=Lax"),
        &d);
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();
    ASSERT_EQ(2u, GetAllCookies(&default_context()).size());
  }

  // Verify that both cookies are sent for same-site, unredirected requests.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        https_server.GetURL(kHost, "/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(1u, req->url_chain().size());
    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }

  // Verify that both cookies are sent for a same-origin redirected top level
  // navigation.
  {
    TestDelegate d;
    GURL url = https_server.GetURL(
        kHost, "/server-redirect?" +
                   https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2u, req->url_chain().size());
    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }

  // Verify that both cookies are sent for a same-site redirected top level
  // navigation.
  {
    TestDelegate d;
    GURL url = https_server.GetURL(
        kSameSiteHost,
        "/server-redirect?" +
            https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kMainFrame, kSameSiteOrigin,
        kSameSiteOrigin, kSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2u, req->url_chain().size());
    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }

  // If redirect chains are considered:
  // Verify that the Strict cookie may or may not be sent for a cross-scheme
  // (same-registrable-domain) redirected top level navigation, depending on the
  // status of Schemeful Same-Site. The Lax cookie is sent regardless, because
  // this is a top-level navigation.
  //
  // If redirect chains are not considered:
  // Verify that both cookies are sent, because this is a top-level navigation.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(features::kSchemefulSameSite);
    TestDelegate d;
    GURL url = http_server.GetURL(
        kHost, "/server-redirect?" +
                   https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame,
                              kHttpOrigin, kHttpOrigin, kHttpSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kHttpSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2u, req->url_chain().size());
    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(features::kSchemefulSameSite);
    TestDelegate d;
    GURL url = http_server.GetURL(
        kHost, "/server-redirect?" +
                   https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame,
                              kHttpOrigin, kHttpOrigin, kHttpSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kHttpSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2u, req->url_chain().size());
    EXPECT_EQ(
        DoesCookieSameSiteConsiderRedirectChain(),
        std::string::npos == d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }

  // Verify that (depending on whether redirect chains are considered), the
  // Strict cookie is (not) sent for a cross-site redirected top level
  // navigation...
  {
    TestDelegate d;
    GURL url = https_server.GetURL(
        kCrossSiteHost,
        "/server-redirect?" +
            https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kMainFrame, kCrossSiteOrigin,
        kCrossSiteOrigin, kCrossSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kCrossSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2u, req->url_chain().size());
    EXPECT_EQ(
        DoesCookieSameSiteConsiderRedirectChain(),
        std::string::npos == d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }
  // ... even if the initial URL is same-site.
  {
    TestDelegate d;
    GURL middle_url = https_server.GetURL(
        kCrossSiteHost,
        "/server-redirect?" +
            https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    GURL url =
        https_server.GetURL(kHost, "/server-redirect?" + middle_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(3u, req->url_chain().size());
    EXPECT_EQ(
        DoesCookieSameSiteConsiderRedirectChain(),
        std::string::npos == d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }

  // Verify that (depending on whether redirect chains are considered), neither
  // (or both) SameSite cookie is sent for a cross-site redirected subresource
  // request...
  {
    TestDelegate d;
    GURL url = https_server.GetURL(
        kCrossSiteHost,
        "/server-redirect?" +
            https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(2u, req->url_chain().size());
    EXPECT_EQ(
        DoesCookieSameSiteConsiderRedirectChain(),
        std::string::npos == d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_EQ(
        DoesCookieSameSiteConsiderRedirectChain(),
        std::string::npos == d.data_received().find("LaxSameSiteCookie=1"));
  }
  // ... even if the initial URL is same-site.
  {
    TestDelegate d;
    GURL middle_url = https_server.GetURL(
        kCrossSiteHost,
        "/server-redirect?" +
            https_server.GetURL(kHost, "/echoheader?Cookie").spec());
    GURL url =
        https_server.GetURL(kHost, "/server-redirect?" + middle_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);
    req->Start();
    d.RunUntilComplete();

    EXPECT_EQ(3u, req->url_chain().size());
    EXPECT_EQ(
        DoesCookieSameSiteConsiderRedirectChain(),
        std::string::npos == d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_EQ(
        DoesCookieSameSiteConsiderRedirectChain(),
        std::string::npos == d.data_received().find("LaxSameSiteCookie=1"));
  }
}

TEST_P(URLRequestSameSiteCookiesTest, SettingSameSiteCookies) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  const std::string kHost = "example.test";
  const std::string kSubHost = "subdomain.example.test";
  const std::string kCrossHost = "cross-origin.test";
  const url::Origin kOrigin =
      url::Origin::Create(test_server.GetURL(kHost, "/"));
  const url::Origin kSubOrigin =
      url::Origin::Create(test_server.GetURL(kSubHost, "/"));
  const url::Origin kCrossOrigin =
      url::Origin::Create(test_server.GetURL(kCrossHost, "/"));
  const SiteForCookies kSiteForCookies = SiteForCookies::FromOrigin(kOrigin);
  const SiteForCookies kCrossSiteForCookies =
      SiteForCookies::FromOrigin(kCrossOrigin);

  int expected_cookies = 0;

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost,
                           "/set-cookie?Strict1=1;SameSite=Strict&"
                           "Lax1=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kOrigin);

    // 'SameSite' cookies are settable from strict same-site contexts
    // (same-origin site_for_cookies, same-origin initiator), so this request
    // should result in two cookies being set.
    expected_cookies += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_cookies, default_network_delegate().set_cookie_count());
  }

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost,
                           "/set-cookie?Strict2=1;SameSite=Strict&"
                           "Lax2=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kCrossOrigin);

    // 'SameSite' cookies are settable from lax same-site contexts (same-origin
    // site_for_cookies, cross-site initiator, main frame navigation), so this
    // request should result in two cookies being set.
    expected_cookies += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_cookies, default_network_delegate().set_cookie_count());
  }

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost,
                           "/set-cookie?Strict3=1;SameSite=Strict&"
                           "Lax3=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame,
                              kSubOrigin, kSubOrigin, kSiteForCookies));
    req->set_site_for_cookies(
        SiteForCookies::FromUrl(test_server.GetURL(kSubHost, "/")));
    req->set_initiator(kCrossOrigin);

    // 'SameSite' cookies are settable from lax same-site contexts (same-site
    // site_for_cookies, cross-site initiator, main frame navigation), so this
    // request should result in two cookies being set.
    expected_cookies += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_cookies, default_network_delegate().set_cookie_count());
  }

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost,
                           "/set-cookie?Strict4=1;SameSite=Strict&"
                           "Lax4=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(
        SiteForCookies::FromUrl(test_server.GetURL(kSubHost, "/")));

    // 'SameSite' cookies are settable from strict same-site contexts (same-site
    // site_for_cookies, no initiator), so this request should result in two
    // cookies being set.
    expected_cookies += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_cookies, default_network_delegate().set_cookie_count());
  }

  int expected_network_delegate_set_cookie_count;
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost,
                           "/set-cookie?Strict5=1;SameSite=Strict&"
                           "Lax5=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(kCrossSiteForCookies);
    req->set_initiator(kCrossOrigin);

    // 'SameSite' cookies are not settable from cross-site contexts, so this
    // should not result in any new cookies being set.
    expected_cookies += 0;
    // This counts the number of successful calls to CanSetCookie() when
    // attempting to set a cookie. The two cookies above were created and
    // attempted to be set, and were not rejected by the NetworkDelegate, so the
    // count here is 2 more than the number of cookies actually set.
    expected_network_delegate_set_cookie_count = expected_cookies + 2;

    req->Start();
    d.RunUntilComplete();
    // This counts the number of cookies actually set.
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_network_delegate_set_cookie_count,
              default_network_delegate().set_cookie_count());
  }

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost,
                           "/set-cookie?Strict6=1;SameSite=Strict&"
                           "Lax6=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kSubFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kCrossOrigin);

    // Same-site site-for-cookies, cross-site initiator, non main frame
    // navigation -> context is considered cross-site so no SameSite cookies are
    // set.
    expected_cookies += 0;
    // This counts the number of successful calls to CanSetCookie() when
    // attempting to set a cookie. The two cookies above were created and
    // attempted to be set, and were not rejected by the NetworkDelegate, so the
    // count here is 2 more than the number of cookies actually set.
    expected_network_delegate_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_network_delegate_set_cookie_count,
              default_network_delegate().set_cookie_count());

    // Check that the appropriate cookie inclusion status is set.
    ASSERT_EQ(2u, req->maybe_stored_cookies().size());
    CookieInclusionStatus expected_strict_status =
        CookieInclusionStatus::MakeFromReasonsForTesting(
            {CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT},
            {} /* warning_reasons */);
    CookieInclusionStatus expected_lax_status =
        CookieInclusionStatus::MakeFromReasonsForTesting(
            {CookieInclusionStatus::EXCLUDE_SAMESITE_LAX},
            {} /* warning_reasons */);
    EXPECT_EQ(expected_strict_status,
              req->maybe_stored_cookies()[0].access_result.status);
    EXPECT_EQ(expected_lax_status,
              req->maybe_stored_cookies()[1].access_result.status);
  }

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        test_server.GetURL(kHost,
                           "/set-cookie?Strict7=1;SameSite=Strict&"
                           "Lax7=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, kOrigin, kOrigin, kSiteForCookies));
    req->set_site_for_cookies(kSiteForCookies);
    req->set_initiator(kCrossOrigin);
    req->set_force_main_frame_for_same_site_cookies(true);

    // 'SameSite' cookies are settable from lax same-site contexts (same-origin
    // site_for_cookies, cross-site initiator, main frame navigation), so this
    // request should result in two cookies being set.
    expected_cookies += 2;
    expected_network_delegate_set_cookie_count += 2;

    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(expected_cookies,
              static_cast<int>(GetAllCookies(&default_context()).size()));
    EXPECT_EQ(expected_network_delegate_set_cookie_count,
              default_network_delegate().set_cookie_count());
  }
}

// Tests special chrome:// scheme that is supposed to always attach SameSite
// cookies if the requested site is secure.
TEST_P(URLRequestSameSiteCookiesTest, SameSiteCookiesSpecialScheme) {
  url::ScopedSchemeRegistryForTests scoped_registry;
  url::AddStandardScheme("chrome", url::SchemeType::SCHEME_WITH_HOST);

  EmbeddedTestServer https_test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&https_test_server);
  ASSERT_TRUE(https_test_server.Start());
  EmbeddedTestServer http_test_server(EmbeddedTestServer::TYPE_HTTP);
  RegisterDefaultHandlers(&http_test_server);
  ASSERT_TRUE(http_test_server.Start());
  ASSERT_NE(https_test_server.port(), http_test_server.port());
  // Both hostnames should be 127.0.0.1 (so that we can use the same set of
  // cookies on both, for convenience).
  ASSERT_EQ(https_test_server.host_port_pair().host(),
            http_test_server.host_port_pair().host());

  // Set up special schemes
  auto cad = std::make_unique<TestCookieAccessDelegate>();
  cad->SetIgnoreSameSiteRestrictionsScheme("chrome", true);
  auto cm = std::make_unique<CookieMonster>(nullptr, nullptr);
  cm->SetCookieAccessDelegate(std::move(cad));

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(std::move(cm));
  auto context = context_builder->Build();

  // SameSite cookies are not set for 'chrome' scheme if requested origin is not
  // secure.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        http_test_server.GetURL(
            "/set-cookie?StrictSameSiteCookie=1;SameSite=Strict&"
            "LaxSameSiteCookie=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(
        SiteForCookies::FromUrl(GURL("chrome://whatever/")));
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(0u, GetAllCookies(context.get()).size());
  }

  // But they are set for 'chrome' scheme if the requested origin is secure.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test_server.GetURL(
            "/set-cookie?StrictSameSiteCookie=1;SameSite=Strict&"
            "LaxSameSiteCookie=1;SameSite=Lax"),
        DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(
        SiteForCookies::FromUrl(GURL("chrome://whatever/")));
    req->Start();
    d.RunUntilComplete();
    CookieList cookies = GetAllCookies(context.get());
    EXPECT_EQ(2u, cookies.size());
  }

  // Verify that they are both sent when the site_for_cookies scheme is
  // 'chrome' and the requested origin is secure.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        https_test_server.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(
        SiteForCookies::FromUrl(GURL("chrome://whatever/")));
    req->Start();
    d.RunUntilComplete();
    EXPECT_NE(std::string::npos,
              d.data_received().find("StrictSameSiteCookie=1"));
    EXPECT_NE(std::string::npos, d.data_received().find("LaxSameSiteCookie=1"));
  }

  // Verify that they are not sent when the site_for_cookies scheme is
  // 'chrome' and the requested origin is not secure.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        http_test_server.GetURL("/echoheader?Cookie"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(
        SiteForCookies::FromUrl(GURL("chrome://whatever/")));
    req->Start();
    d.RunUntilComplete();
    EXPECT_EQ(std::string::npos,
              d.data_received().find("StrictSameSiteCookie"));
    EXPECT_EQ(std::string::npos, d.data_received().find("LaxSameSiteCookie"));
  }
}

TEST_P(URLRequestSameSiteCookiesTest, SettingSameSiteCookies_Redirect) {
  EmbeddedTestServer http_server;
  RegisterDefaultHandlers(&http_server);
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(http_server.Start());
  ASSERT_TRUE(https_server.Start());

  auto& network_delegate = default_network_delegate();

  const std::string kHost = "foo.a.test";
  const std::string kSameSiteHost = "bar.a.test";
  const std::string kCrossSiteHost = "b.test";
  const url::Origin kOrigin =
      url::Origin::Create(https_server.GetURL(kHost, "/"));
  const url::Origin kHttpOrigin =
      url::Origin::Create(http_server.GetURL(kHost, "/"));
  const url::Origin kSameSiteOrigin =
      url::Origin::Create(https_server.GetURL(kSameSiteHost, "/"));
  const url::Origin kCrossSiteOrigin =
      url::Origin::Create(https_server.GetURL(kCrossSiteHost, "/"));
  const SiteForCookies kSiteForCookies = SiteForCookies::FromOrigin(kOrigin);
  const SiteForCookies kHttpSiteForCookies =
      SiteForCookies::FromOrigin(kHttpOrigin);
  const SiteForCookies kCrossSiteForCookies =
      SiteForCookies::FromOrigin(kCrossSiteOrigin);

  int expected_cookies = 0;
  int expected_set_cookie_count = 0;

  // Verify that SameSite cookies can be set for a same-origin redirected
  // top-level navigation request.
  {
    TestDelegate d;
    GURL set_cookie_url = https_server.GetURL(
        kHost, "/set-cookie?Strict1=1;SameSite=Strict&Lax1=1;SameSite=Lax");
    GURL url =
        https_server.GetURL(kHost, "/server-redirect?" + set_cookie_url.spec());
    std::unique_ptr<URLRequest> req(default_context().CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_isolation_info(
        IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                              kOrigin, kSiteForCookies));
    req->set_first_party_url_policy(
        RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT);
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
  // top-l
```