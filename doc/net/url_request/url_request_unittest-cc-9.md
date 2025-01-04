Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/url_request/url_request_unittest.cc`. The code primarily focuses on testing the behavior of `URLRequest` with respect to cookies and authentication, especially in the context of redirects and user preferences blocking.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core functionality:** The code heavily utilizes `URLRequest`, `TestDelegate`, `HttpTestServer`, and `FilteringTestNetworkDelegate`. It sets up scenarios involving setting and getting cookies, and how these operations are affected by user preferences and network delegate settings. The tests also cover authentication challenges and redirects.

2. **Group related test cases:**  Notice the use of `TEST_F` to define individual test cases. Group similar tests together for a concise summary. For example, the tests related to cookie inclusion status warnings can be grouped. Similarly, tests for different redirect types (301, 302, 303) can be combined under a "redirect testing" umbrella.

3. **Explain the cookie-related tests:**  Focus on how the tests verify cookie blocking (both for storing and sending) based on user preferences and the `FilteringTestNetworkDelegate`. Highlight the use of `maybe_stored_cookies()` and `maybe_sent_cookies()` to inspect the cookie handling. Mention the role of `NetLog` in recording cookie inclusion status.

4. **Explain the authentication-related tests:**  Point out the tests involving `AuthChallenge` and how cookies are handled during the authentication process, especially when filtering is involved.

5. **Explain the redirect-related tests:** Emphasize how the tests examine the change in HTTP methods (e.g., POST to GET) and the handling of the `Origin` header during redirects. Categorize by redirect type (301, 302, 303).

6. **Look for JavaScript connections:**  While this code is C++, it interacts with HTTP headers and cookies, which are fundamental to web interactions involving JavaScript. JavaScript's `document.cookie` API and `fetch` API are directly related. Explain how these JavaScript features interact with the underlying network stack being tested.

7. **Construct example input and output:** For the cookie blocking tests, imagine a user has blocked a specific cookie. Demonstrate the expected behavior when a website tries to set or send that cookie. For redirects, illustrate how a POST request might be transformed into a GET request.

8. **Identify common user/programming errors:**  Think about mistakes developers might make when dealing with cookies or redirects. For cookies, incorrect path or domain settings are common. For redirects, not handling the change in HTTP method can lead to unexpected behavior.

9. **Explain how a user reaches this code (debugging context):**  Describe the high-level steps a user might take in a browser that would trigger this network stack code. Focus on actions that involve making HTTP requests, like visiting a website.

10. **Summarize the functionality (instruction #10):**  Provide a concise overview of the purpose of the code, highlighting its role in testing the network stack's handling of URL requests, especially concerning cookies, authentication, and redirects.

11. **Address the "part 10 of 17" instruction:**  Acknowledge this context and reiterate the focus of this specific part. This helps in understanding the scope of the current code within the larger project.

**Self-Correction/Refinement during thought process:**

* **Initial thought:**  Focus heavily on the C++ specifics of the testing framework.
* **Correction:** Shift focus to the *behavior* being tested, which is more relevant to the user's request. Explain the *what* and *why* rather than just the *how*.
* **Initial thought:**  JavaScript connection is weak, may not be worth mentioning.
* **Correction:**  Realize that cookies and HTTP headers are central to web development, and JavaScript interacts with them directly. Including this connection makes the explanation more complete.
* **Initial thought:**  The "debugging line" explanation could be very technical.
* **Correction:**  Keep the debugging explanation high-level and user-centric. Focus on the user actions that lead to the code being executed.

By following these steps, the detailed and informative response can be generated, addressing all aspects of the user's request.
这个文件 `net/url_request/url_request_unittest.cc` 是 Chromium 网络栈的单元测试文件，专门用于测试 `URLRequest` 类的各种功能。

**其核心功能可以归纳为：**

1. **测试 URLRequest 的基本功能:**  例如创建、启动、取消请求，获取响应状态、头部、数据等。虽然这段代码没有直接展示这些基础功能，但它是整个测试套件的一部分，其他部分会覆盖这些。

2. **测试 Cookie 的处理:** 这是这段代码的主要关注点。它测试了在 `URLRequest` 过程中 Cookie 的设置 (存储) 和发送行为，以及网络层如何根据各种策略（例如用户偏好、SameSite 属性）来决定是否允许这些操作。

3. **测试网络拦截 (Network Interception) 和过滤:**  通过 `FilteringTestNetworkDelegate`，可以模拟网络请求的拦截和修改，例如阻止某些 Cookie 的存储或发送，并验证 `URLRequest` 是否正确地报告了这些拦截行为。

4. **测试身份验证 (Authentication):**  代码中包含针对 HTTP Basic 认证的测试用例，验证 `URLRequest` 在需要身份验证时的行为，以及 Cookie 在认证过程中的处理。

5. **测试 HTTP 重定向 (HTTP Redirect):**  测试了不同类型的 HTTP 重定向 (301, 302, 303) 对请求方法 (例如 POST 转换为 GET) 和 `Origin` 请求头的影响。

6. **测试 NetLog 的记录:**  验证了 `URLRequest` 在处理 Cookie 时是否正确地将相关信息记录到 `NetLog` 中，这对于调试网络问题非常重要。

**与 JavaScript 功能的关系:**

`URLRequest` 是浏览器网络栈的核心组成部分，它负责发起和处理网络请求。JavaScript 通过浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`) 来发起网络请求，而这些 API 底层最终会调用 Chromium 的网络栈，包括 `URLRequest`。

**举例说明:**

* 当 JavaScript 代码执行 `fetch('https://example.com/api', {credentials: 'include'})` 时，浏览器会创建一个 `URLRequest` 对象来处理这个请求。
* 如果服务器在响应头中设置了 Cookie (`Set-Cookie`), 那么 `URLRequest` 的相关逻辑会处理这个 Cookie 的存储。这段测试代码就模拟了服务器设置 Cookie 的场景，并验证了网络栈是否正确地处理了这些 Cookie，例如 `not_stored_cookie` 因为用户偏好被阻止存储。
* 如果 JavaScript 发起的请求需要携带 Cookie，那么 `URLRequest` 的相关逻辑会负责读取并添加到请求头中。这段测试代码验证了哪些 Cookie 可以被发送，哪些会被阻止发送（例如 `stored_cookie` 被用户偏好阻止发送）。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **服务器响应头:** `Set-Cookie: not_stored_cookie=true;`
* **FilteringTestNetworkDelegate 配置:** 设置了阻止存储名为 "not_stored_cookie" 的 Cookie。

**预期输出:**

* `req->maybe_stored_cookies()` 将包含一个条目，指示尝试存储 "not_stored_cookie" 的操作，并且 `access_result.status` 会包含 `EXCLUDE_USER_PREFERENCES`，表明该 Cookie 由于用户偏好而被阻止存储。
* `NetLog` 中会记录相应的 Cookie 包含状态事件，说明 "not_stored_cookie" 因为用户偏好而被阻止存储。

**用户或编程常见的使用错误:**

* **Cookie 设置错误:**
    * **示例:**  服务器设置了 `Set-Cookie: mycookie=value; Path=/some/path`，而 JavaScript 代码尝试在路径 `/other/path` 下访问这个 Cookie，导致无法获取。这段测试代码验证了 Cookie 的路径匹配规则。
    * **调试线索:**  用户可能会发现在某个页面上设置的 Cookie 在另一个页面上无法读取。通过 `chrome://net-export/` 抓取网络日志，可以看到 Cookie 的 `inclusion_status`，如果是因为路径不匹配，会显示 `EXCLUDE_NOT_ON_PATH`。

* **SameSite 属性理解错误:**
    * **示例:**  开发者没有设置 `SameSite` 属性，期望在跨站请求中发送 Cookie，但由于浏览器默认的 SameSite 策略（Lax 或 Strict），Cookie 可能不会被发送。这段测试代码验证了 SameSite 策略的影响，例如 `unspecifiedsamesite` Cookie 在跨站上下文中被阻止。
    * **调试线索:**  用户在跨域访问时发现原本应该携带的 Cookie 没有发送。网络日志会显示 `EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX` 或 `EXCLUDE_SAMESITE_STRICT`。

* **HTTPS 上下文的 Secure 属性:**
    * **示例:**  在 HTTPS 网站上设置了 `Secure` 属性的 Cookie，但尝试在 HTTP 网站上发送，Cookie 会被阻止。这段测试代码虽然没有直接演示，但 `invalidsecure` 的测试暗示了对 Secure 属性的检查。
    * **调试线索:**  在 HTTP 页面上，之前在 HTTPS 页面设置的带 `Secure` 属性的 Cookie 没有发送。网络日志会显示 `EXCLUDE_SECURE_ONLY`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击了一个链接。**  这会触发浏览器发起一个网络请求。
2. **浏览器解析 URL，确定协议 (HTTP/HTTPS) 和目标服务器。**
3. **如果需要发送 Cookie，浏览器会根据 Cookie 的属性 (Domain, Path, Secure, HttpOnly, SameSite) 和当前请求的上下文 (域名，协议等) 决定哪些 Cookie 可以被发送。** 这部分逻辑对应了这段代码中测试 Cookie 发送的部分。
4. **浏览器创建一个 `URLRequest` 对象，并将请求信息 (URL, 头部, Cookie 等) 传递给它。**
5. **`URLRequest` 对象会通过网络栈与服务器建立连接，发送请求。**
6. **服务器返回响应，包含响应头和数据。**
7. **如果响应头中包含 `Set-Cookie`，`URLRequest` 的相关逻辑会解析并尝试存储这些 Cookie。** 这部分逻辑对应了这段代码中测试 Cookie 存储的部分。网络拦截器 (`FilteringTestNetworkDelegate`) 可以在这个过程中介入，模拟用户偏好或扩展程序的 Cookie 阻止行为。
8. **如果请求需要身份验证 (例如 HTTP Basic Auth)，`URLRequest` 会处理认证质询，并可能触发用户的身份验证提示。** 这部分对应了代码中关于身份验证的测试。
9. **如果服务器返回重定向响应 (301, 302, 303 等)，`URLRequest` 会根据重定向的状态码和头部信息，决定是否以及如何发起新的请求。** 这部分对应了代码中关于 HTTP 重定向的测试。
10. **最终，`URLRequest` 将接收到的数据传递给浏览器的渲染引擎或其他组件进行处理。**

**第 10 部分功能归纳:**

这段代码（作为第 10 部分）主要专注于测试 `URLRequest` 在处理 **Cookie 设置和发送** 时的行为，特别是在受到 **用户偏好阻止** 的情况下。它还测试了 **NetLog** 是否正确记录了 Cookie 的包含状态。此外，它还初步涉及了 **身份验证** 场景下 Cookie 的处理。  这部分是整个 `URLRequest` 测试套件中关于 Cookie 处理逻辑的一个重要组成部分。

Prompt: 
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共17部分，请归纳一下它的功能

"""
     std::make_unique<FilteringTestNetworkDelegate>());
  network_delegate.SetCookieFilter("not_stored_cookie");
  network_delegate.set_block_annotate_cookies();
  context_builder->set_net_log(net::NetLog::Get());
  auto context = context_builder->Build();
  // Make sure cookies blocked from being stored are caught, and those that are
  // accepted are reported as well.
  GURL set_cookie_test_url = test_server.GetURL(
      "/set-cookie?not_stored_cookie=true&"
      "stored_cookie=tasty"
      "&path_cookie=narrow;path=/"
      "set-cookie&partitioned_cookie=partitioned;path=/;partitioned;secure");
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(*context, set_cookie_test_url, &d);
    req->Start();
    d.RunUntilComplete();

    ASSERT_EQ(4u, req->maybe_stored_cookies().size());
    EXPECT_EQ("not_stored_cookie",
              req->maybe_stored_cookies()[0].cookie->Name());
    EXPECT_TRUE(req->maybe_stored_cookies()[0]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
    EXPECT_EQ("stored_cookie", req->maybe_stored_cookies()[1].cookie->Name());
    EXPECT_TRUE(
        req->maybe_stored_cookies()[1].access_result.status.IsInclude());
    EXPECT_EQ("stored_cookie", req->maybe_stored_cookies()[1].cookie->Name());
    EXPECT_TRUE(
        req->maybe_stored_cookies()[2].access_result.status.IsInclude());
    EXPECT_EQ("path_cookie", req->maybe_stored_cookies()[2].cookie->Name());
    EXPECT_TRUE(
        req->maybe_stored_cookies()[3].access_result.status.IsInclude());
    EXPECT_EQ("partitioned_cookie",
              req->maybe_stored_cookies()[3].cookie->Name());
    auto entries = net_log_observer.GetEntriesWithType(
        NetLogEventType::COOKIE_INCLUSION_STATUS);
    EXPECT_EQ(4u, entries.size());
    EXPECT_EQ("{\"domain\":\"" + set_cookie_test_url.host() +
                  R"x(","name":"not_stored_cookie","operation":"store",)x"
                  R"x("partition_key":"(none)","path":"/",)x"
                  R"x("status":"EXCLUDE_USER_PREFERENCES, )x"
                  R"x(DO_NOT_WARN, NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[0].params));
    EXPECT_EQ("{\"domain\":\"" + set_cookie_test_url.host() +
                  R"x(","name":"stored_cookie","operation":"store",)x"
                  R"x("partition_key":"(none)","path":"/",)x"
                  R"x("status":"INCLUDE, DO_NOT_WARN, NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[1].params));
    EXPECT_EQ("{\"domain\":\"" + set_cookie_test_url.host() +
                  R"x(","name":"path_cookie","operation":"store",)x"
                  R"x("partition_key":"(none)",)x"
                  R"x("path":"/set-cookie","status":"INCLUDE, DO_NOT_WARN, )x"
                  R"x(NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[2].params));
    EXPECT_EQ("{\"domain\":\"" + set_cookie_test_url.host() +
                  R"x(","name":"partitioned_cookie","operation":"store",)x"
                  R"x("partition_key":")x" +
                  set_cookie_test_url.scheme() + "://" +
                  set_cookie_test_url.host() +
                  ", same-site"
                  R"x(","path":"/","status":"INCLUDE, DO_NOT_WARN, )x"
                  R"x(NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[3].params));
    net_log_observer.Clear();
  }
  {
    TestDelegate d;
    // Make sure cookies blocked from being sent are caught.
    GURL test_url = test_server.GetURL("/echoheader?Cookie");
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(*context, test_url, &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("stored_cookie=tasty") ==
                std::string::npos);

    ASSERT_EQ(3u, req->maybe_sent_cookies().size());
    EXPECT_EQ("path_cookie", req->maybe_sent_cookies()[0].cookie.Name());
    EXPECT_TRUE(
        req->maybe_sent_cookies()[0]
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_NOT_ON_PATH,
                 net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
    EXPECT_EQ("stored_cookie", req->maybe_sent_cookies()[1].cookie.Name());
    EXPECT_TRUE(
        req->maybe_sent_cookies()[1]
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
    EXPECT_TRUE(
        req->maybe_sent_cookies()[2]
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
    auto entries = net_log_observer.GetEntriesWithType(
        NetLogEventType::COOKIE_INCLUSION_STATUS);
    EXPECT_EQ(3u, entries.size());
    EXPECT_EQ("{\"domain\":\"" + set_cookie_test_url.host() +
                  R"x(","name":"path_cookie","operation":"send",)x"
                  R"x("partition_key":"(none)","path":)x"
                  R"x("/set-cookie","status":"EXCLUDE_NOT_ON_PATH, )x"
                  R"x(EXCLUDE_USER_PREFERENCES, DO_NOT_WARN, NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[0].params));
    EXPECT_EQ("{\"domain\":\"" + set_cookie_test_url.host() +
                  R"x(","name":"stored_cookie","operation":"send",)x"
                  R"x("partition_key":"(none)","path":"/)x"
                  R"x(","status":"EXCLUDE_USER_PREFERENCES, DO_NOT_WARN, )x"
                  R"x(NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[1].params));
    EXPECT_EQ("{\"domain\":\"" + set_cookie_test_url.host() +
                  R"x(","name":"partitioned_cookie","operation":"send",)x"
                  R"x("partition_key":")x" +
                  set_cookie_test_url.scheme() + "://" +
                  set_cookie_test_url.host() +
                  ", same-site"
                  R"x(","path":"/)x"
                  R"x(","status":"EXCLUDE_USER_PREFERENCES, DO_NOT_WARN, )x"
                  R"x(NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[2].params));
    net_log_observer.Clear();
  }
  {
    TestDelegate d;
    // Ensure that the log does not contain cookie names when not set to collect
    // sensitive data.
    net_log_observer.SetObserverCaptureMode(NetLogCaptureMode::kDefault);

    GURL test_url = test_server.GetURL("/echoheader?Cookie");
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(*context, test_url, &d);
    req->Start();
    d.RunUntilComplete();

    auto entries = net_log_observer.GetEntriesWithType(
        NetLogEventType::COOKIE_INCLUSION_STATUS);
    EXPECT_EQ(3u, entries.size());

    // Ensure that the potentially-sensitive |name|, |domain|, and |path| fields
    // are omitted, but other fields are logged as expected.
    EXPECT_EQ(R"x({"operation":"send","partition_key":"(none)",)x"
              R"x("status":"EXCLUDE_NOT_ON_PATH, )x"
              R"x(EXCLUDE_USER_PREFERENCES, DO_NOT_WARN, NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[0].params));
    EXPECT_EQ(R"x({"operation":"send","partition_key":"(none)",)x"
              R"x("status":"EXCLUDE_USER_PREFERENCES, )x"
              R"x(DO_NOT_WARN, NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[1].params));
    EXPECT_EQ(R"x({"operation":"send","partition_key":")x" +
                  set_cookie_test_url.scheme() + "://" +
                  set_cookie_test_url.host() +
                  ", same-site"
                  R"x(","status":"EXCLUDE_USER_PREFERENCES, )x"
                  R"x(DO_NOT_WARN, NO_EXEMPTION"})x",
              SerializeNetLogValueToJson(entries[2].params));

    net_log_observer.Clear();
    net_log_observer.SetObserverCaptureMode(
        NetLogCaptureMode::kIncludeSensitive);
  }

  network_delegate.unset_block_annotate_cookies();
  {
    // Now with sending cookies re-enabled, it should actually be sent.
    TestDelegate d;
    GURL test_url = test_server.GetURL("/echoheader?Cookie");
    std::unique_ptr<URLRequest> req =
        CreateFirstPartyRequest(*context, test_url, &d);
    req->Start();
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("stored_cookie=tasty") !=
                std::string::npos);

    ASSERT_EQ(3u, req->maybe_sent_cookies().size());
    EXPECT_EQ("path_cookie", req->maybe_sent_cookies()[0].cookie.Name());
    EXPECT_TRUE(req->maybe_sent_cookies()[0]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {net::CookieInclusionStatus::EXCLUDE_NOT_ON_PATH}));
    EXPECT_EQ("stored_cookie", req->maybe_sent_cookies()[1].cookie.Name());
    EXPECT_TRUE(req->maybe_sent_cookies()[1].access_result.status.IsInclude());
    auto entries = net_log_observer.GetEntriesWithType(
        NetLogEventType::COOKIE_INCLUSION_STATUS);
    EXPECT_EQ(3u, entries.size());
    EXPECT_EQ(
        "{\"domain\":\"" + set_cookie_test_url.host() +
            R"x(","name":"path_cookie","operation":"send",)x"
            R"x("partition_key":"(none)","path":"/)x"
            R"x(set-cookie","status":"EXCLUDE_NOT_ON_PATH, DO_NOT_WARN, )x"
            R"x(NO_EXEMPTION"})x",
        SerializeNetLogValueToJson(entries[0].params));
    EXPECT_EQ(
        "{\"domain\":\"" + set_cookie_test_url.host() +
            R"x(","name":"stored_cookie","operation":"send",)x"
            R"x("partition_key":"(none)",)x"
            R"x("path":"/","status":"INCLUDE, DO_NOT_WARN, NO_EXEMPTION"})x",
        SerializeNetLogValueToJson(entries[1].params));
    EXPECT_EQ(
        "{\"domain\":\"" + set_cookie_test_url.host() +
            R"x(","name":"partitioned_cookie","operation":"send",)x"
            R"x("partition_key":")x" +
            set_cookie_test_url.scheme() + "://" + set_cookie_test_url.host() +
            ", same-site"
            R"x(","path":"/","status":"INCLUDE, DO_NOT_WARN, NO_EXEMPTION"})x",
        SerializeNetLogValueToJson(entries[2].params));
    net_log_observer.Clear();
  }
}

// Test that the SameSite-by-default CookieInclusionStatus warnings do not get
// set if the cookie would have been rejected for other reasons.
// Regression test for https://crbug.com/1027318.
TEST_F(URLRequestTest, NoCookieInclusionStatusWarningIfWouldBeExcludedAnyway) {
  HttpTestServer test_server;
  ASSERT_TRUE(test_server.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<FilteringTestNetworkDelegate>());
  network_delegate.SetCookieFilter("blockeduserpreference");
  context_builder->SetCookieStore(
      std::make_unique<CookieMonster>(nullptr, nullptr));
  auto context = context_builder->Build();
  auto& cm = *static_cast<CookieMonster*>(context->cookie_store());

  // Set cookies
  {
    // Attempt to set some cookies in a cross-site context without a SameSite
    // attribute. They should all be blocked. Only the one that would have been
    // included had it not been for the new SameSite features should have a
    // warning attached.
    TestDelegate d;
    GURL test_url = test_server.GetURL("this.example",
                                       "/set-cookie?blockeduserpreference=true&"
                                       "unspecifiedsamesite=1&"
                                       "invalidsecure=1;Secure");
    GURL cross_site_url = test_server.GetURL("other.example", "/");
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_site_for_cookies(
        net::SiteForCookies::FromUrl(cross_site_url));  // cross-site context
    req->Start();
    d.RunUntilComplete();

    ASSERT_EQ(3u, req->maybe_stored_cookies().size());

    // Cookie blocked by user preferences is not warned about.
    EXPECT_EQ("blockeduserpreference",
              req->maybe_stored_cookies()[0].cookie->Name());
    // It doesn't pick up the EXCLUDE_UNSPECIFIED_TREATED_AS_LAX because it
    // doesn't even make it to the cookie store (it is filtered out beforehand).
    EXPECT_TRUE(req->maybe_stored_cookies()[0]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
    EXPECT_FALSE(
        req->maybe_stored_cookies()[0].access_result.status.ShouldWarn());

    // Cookie that would be included had it not been for the new SameSite rules
    // is warned about.
    EXPECT_EQ("unspecifiedsamesite",
              req->maybe_stored_cookies()[1].cookie->Name());
    EXPECT_TRUE(req->maybe_stored_cookies()[1]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {CookieInclusionStatus::
                             EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX}));
    EXPECT_TRUE(req->maybe_stored_cookies()[1]
                    .access_result.status.HasExactlyWarningReasonsForTesting(
                        {CookieInclusionStatus::
                             WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT}));

    // Cookie that is blocked because of invalid Secure attribute is not warned
    // about.
    EXPECT_EQ("invalidsecure", req->maybe_stored_cookies()[2].cookie->Name());
    EXPECT_TRUE(req->maybe_stored_cookies()[2]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {CookieInclusionStatus::EXCLUDE_SECURE_ONLY,
                         CookieInclusionStatus::
                             EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX}));
    EXPECT_TRUE(req->maybe_stored_cookies()[2]
                    .access_result.status.HasExactlyWarningReasonsForTesting(
                        {CookieInclusionStatus::
                             WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME}));
  }

  // Get cookies (blocked by user preference)
  network_delegate.set_block_annotate_cookies();
  {
    GURL url = test_server.GetURL("/");
    auto cookie1 = CanonicalCookie::CreateForTesting(url, "cookienosamesite=1",
                                                     base::Time::Now());
    base::RunLoop run_loop;
    CookieAccessResult access_result;
    cm.SetCanonicalCookieAsync(
        std::move(cookie1), url, CookieOptions::MakeAllInclusive(),
        base::BindLambdaForTesting([&](CookieAccessResult result) {
          access_result = result;
          run_loop.Quit();
        }));
    run_loop.Run();
    EXPECT_TRUE(access_result.status.IsInclude());

    TestDelegate d;
    GURL test_url = test_server.GetURL("/echoheader?Cookie");
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    GURL cross_site_url = test_server.GetURL("other.example", "/");
    req->set_site_for_cookies(
        net::SiteForCookies::FromUrl(cross_site_url));  // cross-site context
    req->Start();
    d.RunUntilComplete();

    // No cookies were sent with the request because getting cookies is blocked.
    EXPECT_EQ("None", d.data_received());
    ASSERT_EQ(1u, req->maybe_sent_cookies().size());
    EXPECT_EQ("cookienosamesite", req->maybe_sent_cookies()[0].cookie.Name());
    EXPECT_TRUE(req->maybe_sent_cookies()[0]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {CookieInclusionStatus::EXCLUDE_USER_PREFERENCES,
                         CookieInclusionStatus::
                             EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX}));
    // Cookie should not be warned about because it was blocked because of user
    // preferences.
    EXPECT_FALSE(
        req->maybe_sent_cookies()[0].access_result.status.ShouldWarn());
  }
  network_delegate.unset_block_annotate_cookies();

  // Get cookies
  {
    GURL url = test_server.GetURL("/");
    auto cookie2 = CanonicalCookie::CreateForTesting(
        url, "cookiewithpath=1;path=/foo", base::Time::Now());
    base::RunLoop run_loop;
    // Note: cookie1 from the previous testcase is still in the cookie store.
    CookieAccessResult access_result;
    cm.SetCanonicalCookieAsync(
        std::move(cookie2), url, CookieOptions::MakeAllInclusive(),
        base::BindLambdaForTesting([&](CookieAccessResult result) {
          access_result = result;
          run_loop.Quit();
        }));
    run_loop.Run();
    EXPECT_TRUE(access_result.status.IsInclude());

    TestDelegate d;
    GURL test_url = test_server.GetURL("/echoheader?Cookie");
    std::unique_ptr<URLRequest> req(context->CreateRequest(
        test_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    GURL cross_site_url = test_server.GetURL("other.example", "/");
    req->set_site_for_cookies(
        net::SiteForCookies::FromUrl(cross_site_url));  // cross-site context
    req->Start();
    d.RunUntilComplete();

    // No cookies were sent with the request because they don't specify SameSite
    // and the request is cross-site.
    EXPECT_EQ("None", d.data_received());
    ASSERT_EQ(2u, req->maybe_sent_cookies().size());
    // Cookie excluded for other reasons is not warned about.
    // Note: this cookie is first because the cookies are sorted by path length
    // with longest first. See CookieSorter() in cookie_monster.cc.
    EXPECT_EQ("cookiewithpath", req->maybe_sent_cookies()[0].cookie.Name());
    EXPECT_TRUE(req->maybe_sent_cookies()[0]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {CookieInclusionStatus::EXCLUDE_NOT_ON_PATH,
                         CookieInclusionStatus::
                             EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX}));
    EXPECT_FALSE(
        req->maybe_sent_cookies()[0].access_result.status.ShouldWarn());
    // Cookie that was only blocked because of unspecified SameSite should be
    // warned about.
    EXPECT_EQ("cookienosamesite", req->maybe_sent_cookies()[1].cookie.Name());
    EXPECT_TRUE(req->maybe_sent_cookies()[1]
                    .access_result.status.HasExactlyExclusionReasonsForTesting(
                        {CookieInclusionStatus::
                             EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX}));
    EXPECT_TRUE(req->maybe_sent_cookies()[1]
                    .access_result.status.HasExactlyWarningReasonsForTesting(
                        {CookieInclusionStatus::
                             WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT}));
  }
}

TEST_F(URLRequestTestHTTP, AuthChallengeCancelCookieCollect) {
  ASSERT_TRUE(http_test_server()->Start());
  GURL url_requiring_auth =
      http_test_server()->GetURL("/auth-basic?set-cookie-if-challenged");

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto filtering_network_delegate =
      std::make_unique<FilteringTestNetworkDelegate>();
  filtering_network_delegate->SetCookieFilter("got_challenged");
  context_builder->set_network_delegate(std::move(filtering_network_delegate));
  auto context = context_builder->Build();

  TestDelegate delegate;

  std::unique_ptr<URLRequest> request =
      CreateFirstPartyRequest(*context, url_requiring_auth, &delegate);
  request->Start();

  delegate.RunUntilAuthRequired();
  ASSERT_EQ(1u, request->maybe_stored_cookies().size());
  EXPECT_TRUE(request->maybe_stored_cookies()[0]
                  .access_result.status.HasExactlyExclusionReasonsForTesting(
                      {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
  EXPECT_EQ("got_challenged=true",
            request->maybe_stored_cookies()[0].cookie_string);

  // This shouldn't DCHECK-fail.
  request->CancelAuth();
  delegate.RunUntilComplete();
}

TEST_F(URLRequestTestHTTP, AuthChallengeWithFilteredCookies) {
  ASSERT_TRUE(http_test_server()->Start());

  GURL url_requiring_auth =
      http_test_server()->GetURL("/auth-basic?set-cookie-if-challenged");
  GURL url_requiring_auth_wo_cookies =
      http_test_server()->GetURL("/auth-basic");
  // Check maybe_stored_cookies is populated first round trip, and cleared on
  // the second.
  {
    auto context_builder = CreateTestURLRequestContextBuilder();
    auto& filtering_network_delegate = *context_builder->set_network_delegate(
        std::make_unique<FilteringTestNetworkDelegate>());
    filtering_network_delegate.SetCookieFilter("got_challenged");
    auto context = context_builder->Build();

    TestDelegate delegate;

    std::unique_ptr<URLRequest> request =
        CreateFirstPartyRequest(*context, url_requiring_auth, &delegate);
    request->Start();

    delegate.RunUntilAuthRequired();
    // Make sure it was blocked once.
    EXPECT_EQ(1, filtering_network_delegate.blocked_set_cookie_count());

    // The number of cookies blocked from the most recent round trip.
    ASSERT_EQ(1u, request->maybe_stored_cookies().size());
    EXPECT_TRUE(
        request->maybe_stored_cookies()
            .front()
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));

    // Now check the second round trip
    request->SetAuth(AuthCredentials(kUser, kSecret));
    delegate.RunUntilComplete();
    EXPECT_THAT(delegate.request_status(), IsOk());

    // There are DCHECKs in URLRequestHttpJob that would fail if
    // maybe_sent_cookies and maybe_stored_cookies were not cleared properly.

    // Make sure the cookie was actually filtered and not sent.
    EXPECT_EQ(std::string::npos,
              delegate.data_received().find("Cookie: got_challenged=true"));

    // The number of cookies that most recent round trip tried to set.
    ASSERT_EQ(0u, request->maybe_stored_cookies().size());
  }

  // Check maybe_sent_cookies on first round trip (and cleared for the second).
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
        url_requiring_auth_wo_cookies, "another_cookie=true",
        base::Time::Now());
    cm->SetCanonicalCookieAsync(std::move(another_cookie),
                                url_requiring_auth_wo_cookies,
                                net::CookieOptions::MakeAllInclusive(),
                                CookieStore::SetCookiesCallback());

    TestDelegate delegate;

    std::unique_ptr<URLRequest> request = CreateFirstPartyRequest(
        *context, url_requiring_auth_wo_cookies, &delegate);
    request->Start();

    delegate.RunUntilAuthRequired();

    ASSERT_EQ(1u, request->maybe_sent_cookies().size());
    EXPECT_EQ("another_cookie",
              request->maybe_sent_cookies().front().cookie.Name());
    EXPECT_EQ("true", request->maybe_sent_cookies().front().cookie.Value());
    EXPECT_TRUE(
        request->maybe_sent_cookies()
            .front()
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));

    // Check maybe_sent_cookies on second roundtrip.
    request->set_maybe_sent_cookies({});
    cm->DeleteAllAsync(CookieStore::DeleteCallback());
    auto one_more_cookie = CanonicalCookie::CreateForTesting(
        url_requiring_auth_wo_cookies, "one_more_cookie=true",
        base::Time::Now());
    cm->SetCanonicalCookieAsync(std::move(one_more_cookie),
                                url_requiring_auth_wo_cookies,
                                net::CookieOptions::MakeAllInclusive(),
                                CookieStore::SetCookiesCallback());

    request->SetAuth(AuthCredentials(kUser, kSecret));
    delegate.RunUntilComplete();
    EXPECT_THAT(delegate.request_status(), IsOk());

    // There are DCHECKs in URLRequestHttpJob that would fail if
    // maybe_sent_cookies and maybe_stored_cookies were not cleared properly.

    // Make sure the cookie was actually filtered.
    EXPECT_EQ(std::string::npos,
              delegate.data_received().find("Cookie: one_more_cookie=true"));
    // got_challenged was set after the first request and blocked on the second,
    // so it should only have been blocked this time
    EXPECT_EQ(2, filtering_network_delegate.blocked_annotate_cookies_count());

    // // The number of cookies blocked from the most recent round trip.
    ASSERT_EQ(1u, request->maybe_sent_cookies().size());
    EXPECT_EQ("one_more_cookie",
              request->maybe_sent_cookies().front().cookie.Name());
    EXPECT_TRUE(
        request->maybe_sent_cookies()
            .front()
            .access_result.status.HasExactlyExclusionReasonsForTesting(
                {net::CookieInclusionStatus::EXCLUDE_USER_PREFERENCES}));
  }
}

// Tests that load timing works as expected with auth and the cache.
TEST_F(URLRequestTestHTTP, BasicAuthLoadTiming) {
  ASSERT_TRUE(http_test_server()->Start());

  // populate the cache
  {
    TestDelegate d;

    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        http_test_server()->GetURL("/auth-basic"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));
    r->set_isolation_info(isolation_info1_);
    r->Start();
    d.RunUntilAuthRequired();

    LoadTimingInfo load_timing_info_before_auth;
    r->GetLoadTimingInfo(&load_timing_info_before_auth);
    TestLoadTimingNotReused(load_timing_info_before_auth,
                            CONNECT_TIMING_HAS_DNS_TIMES);

    r->SetAuth(AuthCredentials(kUser, kSecret));
    d.RunUntilComplete();

    EXPECT_TRUE(d.data_received().find("user/secret") != std::string::npos);
    LoadTimingInfo load_timing_info;
    r->GetLoadTimingInfo(&load_timing_info);
    // The test server does not support keep alive sockets, so the second
    // request with auth should use a new socket.
    TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
    EXPECT_NE(load_timing_info_before_auth.socket_log_id,
              load_timing_info.socket_log_id);
    EXPECT_LE(load_timing_info_before_auth.receive_headers_end,
              load_timing_info.connect_timing.connect_start);
  }

  // Repeat request with end-to-end validation.  Since auth-basic results in a
  // cachable page, we expect this test to result in a 304.  In which case, the
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

    // Since there was a request that went over the wire, the load timing
    // information should include connection times.
    LoadTimingInfo load_timing_info;
    r->GetLoadTimingInfo(&load_timing_info);
    TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
  }
}

// In this test, we do a POST which the server will 302 redirect.
// The subsequent transaction should use GET, and should not send the
// Content-Type header.
// http://code.google.com/p/chromium/issues/detail?id=843
TEST_F(URLRequestTestHTTP, Post302RedirectGet) {
  ASSERT_TRUE(http_test_server()->Start());

  const char kData[] = "hello world";

  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      http_test_server()->GetURL("/redirect-to-echoall"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_method("POST");
  req->set_upload(CreateSimpleUploadData(base::byte_span_from_cstring(kData)));

  // Set headers (some of which are specific to the POST).
  HttpRequestHeaders headers;
  headers.SetHeader("Content-Type",
                    "multipart/form-data;"
                    "boundary=----WebKitFormBoundaryAADeAA+NAAWMAAwZ");
  headers.SetHeader("Accept",
                    "text/xml,application/xml,application/xhtml+xml,"
                    "text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5");
  headers.SetHeader("Accept-Language", "en-US,en");
  headers.SetHeader("Accept-Charset", "ISO-8859-1,*,utf-8");
  headers.SetHeader("Content-Length", "11");
  headers.SetHeader("Origin", "http://localhost:1337/");
  req->SetExtraRequestHeaders(headers);
  req->Start();
  d.RunUntilComplete();

  std::string mime_type;
  req->GetMimeType(&mime_type);
  EXPECT_EQ("text/html", mime_type);

  const std::string& data = d.data_received();

  // Check that the post-specific headers were stripped:
  EXPECT_FALSE(ContainsString(data, "Content-Length:"));
  EXPECT_FALSE(ContainsString(data, "Content-Type:"));
  EXPECT_FALSE(ContainsString(data, "Origin:"));

  // These extra request headers should not have been stripped.
  EXPECT_TRUE(ContainsString(data, "Accept:"));
  EXPECT_TRUE(ContainsString(data, "Accept-Language:"));
  EXPECT_TRUE(ContainsString(data, "Accept-Charset:"));
}

// The following tests check that we handle mutating the request for HTTP
// redirects as expected.
// See https://crbug.com/56373, https://crbug.com/102130, and
// https://crbug.com/465517.

TEST_F(URLRequestTestHTTP, Redirect301Tests) {
  ASSERT_TRUE(http_test_server()->Start());

  const GURL url = http_test_server()->GetURL("/redirect301-to-echo");
  const GURL https_redirect_url =
      http_test_server()->GetURL("/redirect301-to-https");

  HTTPRedirectMethodTest(url, "POST", "GET", true);
  HTTPRedirectMethodTest(url, "PUT", "PUT", true);
  HTTPRedirectMethodTest(url, "HEAD", "HEAD", false);

  HTTPRedirectOriginHeaderTest(url, "GET", "GET",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "GET", "GET", "null");
  HTTPRedirectOriginHeaderTest(url, "POST", "GET", std::string());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "POST", "GET",
                               std::string());
  HTTPRedirectOriginHeaderTest(url, "PUT", "PUT",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "PUT", "PUT", "null");
}

TEST_F(URLRequestTestHTTP, Redirect302Tests) {
  ASSERT_TRUE(http_test_server()->Start());

  const GURL url = http_test_server()->GetURL("/redirect302-to-echo");
  const GURL https_redirect_url =
      http_test_server()->GetURL("/redirect302-to-https");

  HTTPRedirectMethodTest(url, "POST", "GET", true);
  HTTPRedirectMethodTest(url, "PUT", "PUT", true);
  HTTPRedirectMethodTest(url, "HEAD", "HEAD", false);

  HTTPRedirectOriginHeaderTest(url, "GET", "GET",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "GET", "GET", "null");
  HTTPRedirectOriginHeaderTest(url, "POST", "GET", std::string());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "POST", "GET",
                               std::string());
  HTTPRedirectOriginHeaderTest(url, "PUT", "PUT",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "PUT", "PUT", "null");
}

TEST_F(URLRequestTestHTTP, Redirect303Tests) {
  ASSERT_TRUE(http_test_server()->Start());

  const GURL url = http_test_server()->GetURL("/redirect303-to-echo");
  const GURL https_redirect_url =
      http_test_server()->GetURL("/redirect303-to-https");

  HTTPRedirectMethodTest(url, "POST", "GET", true);
  HTTPRedirectMethodTest(url, "PUT", "GET", true);
  HTTPRedirectMethodTest(url, "HEAD", "HEAD", false);

  HTTPRedirectOriginHeaderTest(url, "DELETE", "GET", std::string());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "DELETE", "GET",
                               std::string());
  HTTPRedirectOriginHeaderTest(url, "GET", "GET",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "GET", "GET", "null");
  HTTPRedirectOriginHeaderTest(url, "HEAD", "HEAD",
                               url.DeprecatedGetOriginAsURL().spec());
  HTTPRedirectOriginHeaderTest(https_redirect_url, "HEAD", "HEAD", "null");
  HTTPRedirectOriginHeaderTest(url, "OPTIONS", "GET", std::string());
  HTTPRedirec
"""


```