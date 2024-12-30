Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the requested information.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `cookie_util_unittest.cc` file within the Chromium network stack. Specifically, we need to identify its purpose, its relationship to JavaScript (if any), its logic through examples, potential user/programmer errors it tests, and debugging context. Crucially, this is part 3 of a larger analysis, so we should also summarize the cumulative functionality.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code, looking for recognizable patterns and keywords. Things that immediately stand out are:

* **`TEST_P` and `TEST`:** This strongly suggests a unit testing file using Google Test. The `_P` indicates parameterized tests.
* **`CookieUtilComputeSameSiteContextTest` and `CookieUtilTest`:**  These test suite names clearly point to the core functionality being tested: `ComputeSameSiteContext`.
* **`ComputeSameSiteContextForScriptSet`, `ComputeSameSiteContextForResponse`, `ComputeSameSiteContextForSubresource`, `ComputeSameSiteContextForRequest`, `ComputeSameSiteContextForScriptGet`:** These are the specific functions being tested within `cookie_util`.
* **`SameSite`, `ContextType`, `SiteForCookies`, `url::Origin`, `GURL`:** These are data types and concepts related to cookie behavior and security, particularly the SameSite attribute.
* **`EXPECT_THAT`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`:** These are assertion macros from Google Test, confirming the testing nature of the code.
* **`kSiteUrl`, `kSecureSiteUrl`, `kCrossSiteUrl`, etc.:**  These look like predefined constants used for test cases.

**3. Deeper Dive into Functionality (Focusing on `ComputeSameSiteContext`):**

The core of the file is testing different scenarios for calculating the `SameSiteCookieContext`. This involves:

* **Input Parameters:**  The tests manipulate various input parameters to `ComputeSameSiteContext` functions:
    * Target URL (`url`)
    * Site-for-cookies (`site_for_cookies`)
    * Initiator Origin (`initiator`)
    * Whether it's a main frame navigation (`is_main_frame_navigation`)
    * URL chain (for redirects)
    * HTTP method (for requests)
    * Flag to ignore site-for-cookies (`force_ignore_site_for_cookies`)
* **Expected Output:** The tests use assertions to check if the calculated `SameSiteCookieContext` matches the expected value (`ContextType::SAME_SITE_LAX`, `ContextType::CROSS_SITE`, `ContextType::SAME_SITE_STRICT`).
* **Test Case Variations:** The parameterized tests (`TEST_P`) use boolean flags to cover different combinations of "consider redirect chain" and "schemeful same-site".
* **Specific Scenarios:**  There are tests dedicated to:
    * Script-initiated cookie setting/getting (`ForScriptSet`, `ForScriptGet`).
    * HTTP responses (`ForResponse`).
    * Subresource requests (`ForSubresource`).
    * Redirects (`ForResponse_Redirect`).
    * Ignoring site-for-cookies (`ForceIgnoreSiteForCookies`).
    * WebSocket schemes.
    * Schemeful site determination.

**4. Connecting to JavaScript:**

The presence of `ComputeSameSiteContextForScriptSet` and `ComputeSameSiteContextForScriptGet` immediately points to the relationship with JavaScript. JavaScript running on a web page can set and read cookies. The SameSite attribute is crucial for controlling when these actions are allowed in cross-site scenarios, mitigating CSRF attacks.

**5. Logic and Examples:**

To illustrate the logic, we need to select representative test cases and explain the expected input/output. The `ForResponse_Redirect` test is a good example of complex logic involving redirects. We can pick a specific sub-case and detail the assumptions and the resulting context type.

**6. User/Programmer Errors:**

Looking at the test cases and the purpose of SameSite cookies, potential errors become apparent:

* **Incorrectly assuming a cookie will be sent:** If a developer sets a `SameSite: Strict` cookie and then expects it to be sent on a cross-site subresource request, they will be mistaken.
* **Misunderstanding Lax behavior:** The subtleties of `SameSite: Lax` and its behavior on top-level navigations initiated by specific HTTP methods can lead to unexpected cookie behavior.
* **Forgetting about redirects:**  Redirects can change the effective site context, and developers might not always account for this.

**7. Debugging Context:**

To explain how a user might reach this code, we need to trace back from a user action:

* **User clicks a link:** This triggers a navigation, which might involve redirects and cookie sending.
* **JavaScript tries to access cookies:**  Scripts on a page might attempt to read or set cookies.
* **Subresource loading:** A page might load images, scripts, or stylesheets from other origins.

These actions lead to the browser's cookie management logic, which in turn uses functions like `ComputeSameSiteContext` to determine whether a cookie should be included in a request or if a set-cookie operation is allowed. When things go wrong, developers might use browser developer tools (Network tab, Application tab) to inspect cookie behavior and potentially trace issues to the SameSite logic.

**8. Part 3 Summary:**

Since this is part 3, we need to summarize the overall purpose of the file. It's about thoroughly testing the `ComputeSameSiteContext` function in various scenarios involving different URLs, site contexts, initiators, request types, and the influence of redirects and schemeful site determination.

**9. Iteration and Refinement:**

The initial analysis might not be perfectly structured. The process involves some iteration:

* **Clarifying explanations:** Making sure the connection to JavaScript is clear.
* **Choosing good examples:** Selecting test cases that best illustrate the logic.
* **Ensuring accuracy:** Double-checking the expected behavior in different SameSite scenarios.
* **Organizing the information:** Presenting the findings in a clear and logical manner, following the prompt's structure.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive response addressing all the points raised in the prompt. The key is to understand the core functionality being tested and then build out the explanations with concrete examples and connections to the broader web development context.
好的，让我们来分析一下 `net/cookies/cookie_util_unittest.cc` 文件的第三部分内容。

**第三部分功能归纳**

这部分代码主要集中在测试 `cookie_util::ComputeSameSiteContextForResponse` 函数在处理 **跨站点重定向** 时的行为，并测试 `cookie_util::ComputeSameSiteContextForSubresource` 以及 `ForceIgnoreSiteForCookies` 参数的影响。

**详细功能拆解**

1. **`TEST_P(CookieUtilComputeSameSiteContextTest, ForResponse_Redirect)`：测试跨站点重定向的 SameSite 上下文计算**

   - **目的:**  验证在发生 HTTP 重定向时，`ComputeSameSiteContextForResponse` 函数如何根据 URL 链、目标站点、发起者来计算 SameSite 上下文。
   - **核心逻辑:**
     - 它定义了一个包含多种场景的测试用例数组 `kTestCases`，这些场景涵盖了 URL 链、目标站点（SiteForCookies）和发起者是否同源的不同组合。
     - 对于每种组合，它预测了在考虑和不考虑重定向链的情况下，以及在主框架导航和非主框架导航时，预期的 `ContextType` 和 `ContextRedirectTypeBug1221316`。
     - 它使用不同的同源和跨域 URL 链、`SiteForCookies` 和发起者，调用 `ComputeSameSiteContextForResponse` 函数。
     - 使用 `EXPECT_THAT` 断言来验证实际计算出的 `ContextType` 和 `ContextRedirectTypeBug1221316` 是否与预期一致。
     - 重点测试了 `DoesSameSiteConsiderRedirectChain()` 这个配置项对计算结果的影响。

   **与 JavaScript 的关系：**

   - JavaScript 可以通过 `window.location.href` 等方式发起导航，或者通过 `fetch`、`XMLHttpRequest` 等 API 发起网络请求，这些请求可能会经历重定向。
   - 浏览器根据计算出的 SameSite 上下文来决定是否在这些跨站点重定向的请求中携带 Cookie，从而影响 JavaScript 代码对 Cookie 的访问。

   **逻辑推理（假设输入与输出）：**

   假设输入以下情况：
   - `url_chain`:  `["https://a.test/", "https://b.test/"]` (跨站点 URL 链)
   - `site_for_cookies`: `SiteForCookies::FromUrl(GURL("https://b.test/"))` (与最终 URL 同源)
   - `initiator`: `url::Origin::Create(GURL("https://a.test/"))` (与 URL 链的起始 URL 同源)
   - `is_main_frame_navigation`: `false`
   - `DoesSameSiteConsiderRedirectChain()`: `true`

   预期输出：
   - `ContextType`: `ContextType::CROSS_SITE`
   - `ContextRedirectTypeBug1221316`: `ContextRedirectTypeBug1221316::kPartialSameSiteRedirect`

   **用户或编程常见的使用错误：**

   - **错误地认为跨站点重定向后 Cookie 依然会被发送：**  如果开发者设置了 `SameSite: Strict` 或 `SameSite: Lax` 的 Cookie，并期望在跨站点重定向后的请求中依然能访问到这些 Cookie，可能会遇到问题。`ComputeSameSiteContextForResponse` 的测试正是为了确保浏览器在这种情况下能正确处理。
   - **没有考虑到重定向链的影响：** 有些开发者可能只关注最终的请求 URL 和目标站点，而忽略了重定向过程中发生的跨站点跳转，这可能导致对 Cookie 行为的误判。

   **用户操作如何到达这里（调试线索）：**

   1. 用户在浏览器中点击一个链接，或者在地址栏输入一个 URL。
   2. 该 URL 发起一个 HTTP 请求。
   3. 服务器返回一个 3xx 重定向响应，指示浏览器跳转到另一个 URL。
   4. 浏览器根据重定向响应，发起对新 URL 的请求。
   5. 在发起新的请求前，浏览器会调用 `cookie_util::ComputeSameSiteContextForResponse` 来确定是否应该携带 Cookie。
   6. 开发者在调试网络请求时，可能会发现 Cookie 没有被发送，从而深入到网络栈的代码进行分析，最终可能定位到 `cookie_util_unittest.cc` 中的相关测试用例，以理解浏览器是如何计算 SameSite 上下文的。

2. **`TEST_P(CookieUtilComputeSameSiteContextTest, ForSubresource)`：测试子资源请求的 SameSite 上下文计算**

   - **目的:** 验证 `ComputeSameSiteContextForSubresource` 函数在处理子资源请求（例如图片、CSS、JS 文件）时的 SameSite 上下文计算。
   - **核心逻辑:** 遍历同源 URL 和 `SiteForCookies` 的组合，期望子资源请求的上下文为 `ContextType::SAME_SITE_STRICT`。

   **与 JavaScript 的关系：**

   - 当 JavaScript 代码通过 `<img src="...">`、`<link href="...">`、`<script src="...">` 等标签加载跨站点的资源时，会触发子资源请求。
   - 浏览器会使用 `ComputeSameSiteContextForSubresource` 来判断是否应该携带 Cookie。

   **逻辑推理（假设输入与输出）：**

   假设输入：
   - `url`: `GURL("https://a.test/image.png")`
   - `site_for_cookies`: `SiteForCookies::FromUrl(GURL("https://a.test/"))`

   预期输出：
   - `ContextType`: `ContextType::SAME_SITE_STRICT`

3. **`TEST_P(CookieUtilComputeSameSiteContextTest, ForSubresource_SchemefulDowngrade)`：测试子资源请求的 Schemeful Downgrade 情况**

   - **目的:** 专门测试在子资源请求中，当 URL 和 `SiteForCookies` 的协议不同（例如 http 和 https）时，SameSite 上下文的计算结果。这涉及到 Schemeful Same-Site 的概念。

   **与 JavaScript 的关系：** 同上。

   **逻辑推理（假设输入与输出）：**

   假设输入：
   - `url`: `GURL("http://a.test/image.png")`
   - `site_for_cookies`: `SiteForCookies::FromUrl(GURL("https://a.test/"))`

   预期输出：
   - `SameSiteCookieContext`: `SameSiteCookieContext(ContextType::SAME_SITE_STRICT, ContextType::CROSS_SITE)`  （即使主机名相同，但由于协议不同，Schemeful 计算会认为是跨站点）

4. **`TEST_P(CookieUtilComputeSameSiteContextTest, ForSubresource_WebSocketSchemes)`：测试子资源请求的 WebSocket 协议情况**

   - **目的:** 测试 `ComputeSameSiteContextForSubresource` 函数在处理 `ws://` 和 `wss://` 协议的子资源请求时的行为，验证 WebSocket 协议与 HTTP/HTTPS 的同源性判断。

   **与 JavaScript 的关系：**

   - JavaScript 代码可以使用 `WebSocket` API 发起 WebSocket 连接。

   **逻辑推理（假设输入与输出）：**

   假设输入：
   - `url`: `GURL("wss://a.test/socket")`
   - `site_for_cookies`: `SiteForCookies::FromUrl(GURL("https://a.test/"))`

   预期输出：
   - `ContextType`: `ContextType::SAME_SITE_STRICT` (wss 和 https 被认为是 schemefully same-site)

5. **`TEST_P(CookieUtilComputeSameSiteContextTest, ForceIgnoreSiteForCookies)`：测试 `force_ignore_site_for_cookies` 参数**

   - **目的:**  验证 `force_ignore_site_for_cookies` 参数的作用，当设置为 `true` 时，应该忽略正常的 SameSite 计算逻辑，对于获取请求返回 `SAME_SITE_STRICT`，对于设置请求返回 `SAME_SITE_LAX`。
   - **核心逻辑:** 遍历各种请求类型（ScriptGet, ScriptSet, Request, Response, Subresource），设置 `force_ignore_site_for_cookies` 为 `true`，并断言返回的 `ContextType` 符合预期。

   **与 JavaScript 的关系：**

   - 这个参数会影响 JavaScript 发起的 Cookie 获取和设置操作的结果。

   **逻辑推理（假设输入与输出）：**

   假设输入（ScriptSet）：
   - `url`: `GURL("https://b.test/")`
   - `site_for_cookies`: `SiteForCookies::FromUrl(GURL("https://a.test/"))`
   - `force_ignore_site_for_cookies`: `true`

   预期输出：
   - `ContextType`: `ContextType::SAME_SITE_LAX`

**总结第三部分的功能**

总而言之，`net/cookies/cookie_util_unittest.cc` 文件的第三部分主要专注于以下几个方面的测试：

- **详细测试了跨站点重定向场景下 `ComputeSameSiteContextForResponse` 的行为**，涵盖了考虑和不考虑重定向链，以及主框架和非主框架导航的不同情况。这部分测试对于理解浏览器如何处理跨站点重定向时的 Cookie 策略至关重要。
- **验证了 `ComputeSameSiteContextForSubresource` 对于子资源请求的 SameSite 上下文计算**，并特别关注了 Schemeful Same-Site 和 WebSocket 协议的影响。
- **测试了 `force_ignore_site_for_cookies` 参数的Override 行为**，确保在需要强制忽略站点信息进行 Cookie 操作时，函数能够按预期工作。

这部分代码通过大量的测试用例，确保了 Cookie SameSite 策略在各种复杂场景下的正确性和一致性，对于维护 Chromium 网络栈的稳定性和安全性至关重要。

Prompt: 
```
这是目录为net/cookies/cookie_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
ithout_chain,
                      test_case.expected_context_type_for_main_frame_navigation,
                      test_case.expected_redirect_type_with_chain)))
              << UrlChainToString(url_chain) << " "
              << site_for_cookies.ToDebugString() << " "
              << (initiator ? initiator->Serialize() : "nullopt");
        }
      }
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForScriptSet) {
  for (const GURL& url : GetSameSiteUrls()) {
    for (const SiteForCookies& site_for_cookies :
         GetSameSiteSitesForCookies()) {
      // Same-site site-for-cookies -> it's same-site lax.
      // (Cross-site cases covered above in UrlAndSiteForCookiesCrossSite test.)
      EXPECT_THAT(
          cookie_util::ComputeSameSiteContextForScriptSet(
              url, site_for_cookies, false /* force_ignore_site_for_cookies */),
          ContextTypeIs(ContextType::SAME_SITE_LAX));
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForScriptSet_SchemefulDowngrade) {
  // Some test cases where the context is downgraded when computed schemefully.
  // (Should already be covered above, but just to be explicit.)
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_LAX,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForScriptSet(
                kSiteUrl, kSecureSiteForCookies,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_LAX,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForScriptSet(
                kSecureSiteUrl, kSiteForCookies,
                false /* force_ignore_site_for_cookies */));
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForScriptSet_WebSocketSchemes) {
  // wss/https and http/ws are considered the same for schemeful purposes.
  EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptSet(
                  kWssUrl, kSecureSiteForCookies,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_LAX));
  EXPECT_THAT(
      cookie_util::ComputeSameSiteContextForScriptSet(
          kWsUrl, kSiteForCookies, false /* force_ignore_site_for_cookies */),
      ContextTypeIs(ContextType::SAME_SITE_LAX));
}

// Test cases where the URL chain has 1 member (i.e. no redirects).
TEST_P(CookieUtilComputeSameSiteContextTest, ForResponse) {
  for (const GURL& url : GetSameSiteUrls()) {
    // Same-site site-for-cookies.
    // (Cross-site cases covered above in UrlAndSiteForCookiesCrossSite test.)
    for (const SiteForCookies& site_for_cookies :
         GetSameSiteSitesForCookies()) {
      // For main frame navigations, setting all SameSite cookies is allowed
      // regardless of initiator.
      for (const std::optional<url::Origin>& initiator : GetAllInitiators()) {
        if (!CanBeMainFrameNavigation(url, site_for_cookies))
          break;
        EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                        {url}, site_for_cookies, initiator,
                        true /* is_main_frame_navigation */,
                        false /* force_ignore_site_for_cookies */),
                    ContextTypeIs(ContextType::SAME_SITE_LAX));
      }

      // For non-main-frame-navigation requests, the context should be lax iff
      // the initiator is same-site, and cross-site otherwise.
      for (const std::optional<url::Origin>& initiator :
           GetSameSiteInitiators()) {
        EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                        {url}, site_for_cookies, initiator,
                        false /* is_main_frame_navigation */,
                        false /* force_ignore_site_for_cookies */),
                    ContextTypeIs(ContextType::SAME_SITE_LAX));
      }
      for (const std::optional<url::Origin>& initiator :
           GetCrossSiteInitiators()) {
        EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                        {url}, site_for_cookies, initiator,
                        false /* is_main_frame_navigation */,
                        false /* force_ignore_site_for_cookies */),
                    ContextTypeIs(ContextType::CROSS_SITE));
      }
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForResponse_SchemefulDowngrade) {
  // Some test cases where the context is downgraded when computed schemefully.
  // (Should already be covered above, but just to be explicit.)

  // URL and site-for-cookies are cross-scheme.
  // (If the URL and site-for-cookies are not schemefully same-site, this cannot
  // be a main frame navigation.)
  // With same-site initiator:
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_LAX,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForResponse(
                {kSiteUrl}, kSecureSiteForCookies, kSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_LAX,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForResponse(
                {kSecureSiteUrl}, kSiteForCookies, kSecureSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));
  // With cross-site initiator:
  EXPECT_EQ(SameSiteCookieContext(ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForResponse(
                {kSiteUrl}, kSecureSiteForCookies, kCrossSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForResponse(
                {kSecureSiteUrl}, kSiteForCookies, kCrossSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));

  // Schemefully same-site URL and site-for-cookies with cross-scheme
  // initiator.
  for (bool is_main_frame_navigation : {false, true}) {
    ContextType lax_if_main_frame = is_main_frame_navigation
                                        ? ContextType::SAME_SITE_LAX
                                        : ContextType::CROSS_SITE;
    EXPECT_EQ(
        SameSiteCookieContext(ContextType::SAME_SITE_LAX, lax_if_main_frame),
        cookie_util::ComputeSameSiteContextForResponse(
            {kSiteUrl}, kSiteForCookies, kSecureSiteInitiator,
            is_main_frame_navigation,
            false /* force_ignore_site_for_cookies */));
    EXPECT_EQ(
        SameSiteCookieContext(ContextType::SAME_SITE_LAX, lax_if_main_frame),
        cookie_util::ComputeSameSiteContextForResponse(
            {kSecureSiteUrl}, kSecureSiteForCookies, kSiteInitiator,
            is_main_frame_navigation,
            false /* force_ignore_site_for_cookies */));
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForResponse_WebSocketSchemes) {
  // wss/https and http/ws are considered the same for schemeful purposes.
  // (ws/wss requests cannot be main frame navigations.)

  // Same-site initiators.
  for (const std::optional<url::Origin>& initiator : GetSameSiteInitiators()) {
    EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                    {kWsUrl}, kSiteForCookies, initiator,
                    false /* is_main_frame_navigation */,
                    false /* force_ignore_site_for_cookies */),
                ContextTypeIs(ContextType::SAME_SITE_LAX));
  }
  // Cross-site initiators.
  for (const std::optional<url::Origin>& initiator : GetCrossSiteInitiators()) {
    EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                    {kWsUrl}, kSiteForCookies, initiator,
                    false /* is_main_frame_navigation */,
                    false /* force_ignore_site_for_cookies */),
                ContextTypeIs(ContextType::CROSS_SITE));
  }
}

// Test cases where the URL chain contains multiple members, where the last
// member (current request URL) is same-site to kSiteUrl. (Everything is listed
// as same-site or cross-site relative to kSiteUrl.)
TEST_P(CookieUtilComputeSameSiteContextTest, ForResponse_Redirect) {
  struct {
    bool url_chain_is_same_site;
    bool site_for_cookies_is_same_site;
    bool initiator_is_same_site;
    // These are the expected context types considering redirect chains:
    ContextType expected_context_type;  // for non-main-frame-nav requests.
    ContextType expected_context_type_for_main_frame_navigation;
    // These are the expected context types not considering redirect chains:
    ContextType expected_context_type_without_chain;
    ContextType expected_context_type_for_main_frame_navigation_without_chain;
    // The expected redirect type (only applicable for chains):
    ContextRedirectTypeBug1221316 expected_redirect_type_with_chain;
  } kTestCases[] = {
      // If the url chain is same-site, then the result is the same with or
      // without considering the redirect chain.
      {true, true, true, ContextType::SAME_SITE_LAX, ContextType::SAME_SITE_LAX,
       ContextType::SAME_SITE_LAX, ContextType::SAME_SITE_LAX,
       ContextRedirectTypeBug1221316::kAllSameSiteRedirect},
      {true, true, false, ContextType::CROSS_SITE, ContextType::SAME_SITE_LAX,
       ContextType::CROSS_SITE, ContextType::SAME_SITE_LAX,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {true, false, true, ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {true, false, false, ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      // If the url chain is cross-site, then the result will differ depending
      // on whether the redirect chain is considered, when the site-for-cookies
      // and initiator are both same-site.
      {false, true, true, ContextType::CROSS_SITE, ContextType::SAME_SITE_LAX,
       ContextType::SAME_SITE_LAX, ContextType::SAME_SITE_LAX,
       ContextRedirectTypeBug1221316::kPartialSameSiteRedirect},
      {false, true, false, ContextType::CROSS_SITE, ContextType::SAME_SITE_LAX,
       ContextType::CROSS_SITE, ContextType::SAME_SITE_LAX,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {false, false, true, ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {false, false, false, ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
  };
  for (const auto& test_case : kTestCases) {
    std::vector<std::vector<GURL>> url_chains =
        test_case.url_chain_is_same_site ? GetSameSiteUrlChains(kSiteUrl)
                                         : GetCrossSiteUrlChains(kSiteUrl);
    std::vector<SiteForCookies> sites_for_cookies =
        test_case.site_for_cookies_is_same_site ? GetSameSiteSitesForCookies()
                                                : GetCrossSiteSitesForCookies();
    std::vector<std::optional<url::Origin>> initiators =
        test_case.initiator_is_same_site ? GetSameSiteInitiators()
                                         : GetCrossSiteInitiators();
    ContextType expected_context_type =
        DoesSameSiteConsiderRedirectChain()
            ? test_case.expected_context_type
            : test_case.expected_context_type_without_chain;
    ContextType expected_context_type_for_main_frame_navigation =
        DoesSameSiteConsiderRedirectChain()
            ? test_case.expected_context_type_for_main_frame_navigation
            : test_case
                  .expected_context_type_for_main_frame_navigation_without_chain;
    for (const std::vector<GURL>& url_chain : url_chains) {
      for (const SiteForCookies& site_for_cookies : sites_for_cookies) {
        for (const std::optional<url::Origin>& initiator : initiators) {
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                          url_chain, site_for_cookies, initiator,
                          false /* is_main_frame_navigation */,
                          false /* force_ignore_site_for_cookies */),
                      AllOf(ContextTypeIs(expected_context_type),
                            // The 'method' field is kept empty because it's
                            // only used to check http_method_bug_1221316 which
                            // is always empty for responses.
                            CrossSiteRedirectMetadataCorrect(
                                HttpMethod::kUnset,
                                test_case.expected_context_type_without_chain,
                                test_case.expected_context_type,
                                test_case.expected_redirect_type_with_chain)))
              << UrlChainToString(url_chain) << " "
              << site_for_cookies.ToDebugString() << " "
              << (initiator ? initiator->Serialize() : "nullopt");
          if (!CanBeMainFrameNavigation(url_chain.back(), site_for_cookies))
            continue;
          EXPECT_THAT(
              cookie_util::ComputeSameSiteContextForResponse(
                  url_chain, site_for_cookies, initiator,
                  true /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */),
              AllOf(
                  ContextTypeIs(
                      expected_context_type_for_main_frame_navigation),
                  CrossSiteRedirectMetadataCorrect(
                      HttpMethod::kUnset,
                      test_case
                          .expected_context_type_for_main_frame_navigation_without_chain,
                      test_case.expected_context_type_for_main_frame_navigation,
                      test_case.expected_redirect_type_with_chain)))
              << UrlChainToString(url_chain) << " "
              << site_for_cookies.ToDebugString() << " "
              << (initiator ? initiator->Serialize() : "nullopt");
        }
      }
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForSubresource) {
  for (const GURL& url : GetSameSiteUrls()) {
    // Same-site site-for-cookies.
    // (Cross-site cases covered above in UrlAndSiteForCookiesCrossSite test.)
    for (const SiteForCookies& site_for_cookies :
         GetSameSiteSitesForCookies()) {
      EXPECT_THAT(
          cookie_util::ComputeSameSiteContextForSubresource(
              url, site_for_cookies, false /* force_ignore_site_for_cookies */),
          ContextTypeIs(ContextType::SAME_SITE_STRICT));
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest,
       ForSubresource_SchemefulDowngrade) {
  // Some test cases where the context is downgraded when computed schemefully.
  // (Should already be covered above, but just to be explicit.)
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForSubresource(
                kSiteUrl, kSecureSiteForCookies,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForSubresource(
                kSecureSiteUrl, kSiteForCookies,
                false /* force_ignore_site_for_cookies */));
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForSubresource_WebSocketSchemes) {
  // wss/https and http/ws are considered the same for schemeful purposes.
  EXPECT_THAT(cookie_util::ComputeSameSiteContextForSubresource(
                  kWssUrl, kSecureSiteForCookies,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_STRICT));
  EXPECT_THAT(
      cookie_util::ComputeSameSiteContextForSubresource(
          kWsUrl, kSiteForCookies, false /* force_ignore_site_for_cookies */),
      ContextTypeIs(ContextType::SAME_SITE_STRICT));
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForceIgnoreSiteForCookies) {
  // force_ignore_site_for_cookies overrides all checks and returns same-site
  // (STRICT for get or LAX for set).
  for (const GURL& url : GetAllUrls()) {
    for (const SiteForCookies& site_for_cookies : GetAllSitesForCookies()) {
      for (const std::optional<url::Origin>& initiator : GetAllInitiators()) {
        for (const std::string& method : {"GET", "POST", "PUT", "HEAD"}) {
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                          url, site_for_cookies, initiator,
                          true /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::SAME_SITE_STRICT));
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptSet(
                          url, site_for_cookies,
                          true /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::SAME_SITE_LAX));
          for (bool is_main_frame_navigation :
               IsMainFrameNavigationPossibleValues(url, site_for_cookies)) {
            EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                            method, {url}, site_for_cookies, initiator,
                            is_main_frame_navigation,
                            true /* force_ignore_site_for_cookies */),
                        ContextTypeIs(ContextType::SAME_SITE_STRICT));
            EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                            {url}, site_for_cookies, initiator,
                            is_main_frame_navigation,
                            true /* force_ignore_site_for_cookies */),
                        ContextTypeIs(ContextType::SAME_SITE_LAX));
            EXPECT_THAT(
                cookie_util::ComputeSameSiteContextForRequest(
                    method, {site_for_cookies.RepresentativeUrl(), url},
                    site_for_cookies, initiator, is_main_frame_navigation,
                    true /* force_ignore_site_for_cookies */),
                ContextTypeIs(ContextType::SAME_SITE_STRICT));
            EXPECT_THAT(
                cookie_util::ComputeSameSiteContextForResponse(
                    {site_for_cookies.RepresentativeUrl(), url},
                    site_for_cookies, initiator, is_main_frame_navigation,
                    true /* force_ignore_site_for_cookies */),
                ContextTypeIs(ContextType::SAME_SITE_LAX));
          }
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForSubresource(
                          url, site_for_cookies,
                          true /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::SAME_SITE_STRICT));
        }
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(/* no label */,
                         CookieUtilComputeSameSiteContextTest,
                         ::testing::Combine(::testing::Bool(),
                                            ::testing::Bool()));

TEST(CookieUtilTest, IsCookieAccessResultInclude) {
  EXPECT_FALSE(cookie_util::IsCookieAccessResultInclude(CookieAccessResult(
      CookieInclusionStatus(CookieInclusionStatus::EXCLUDE_UNKNOWN_ERROR))));

  EXPECT_TRUE(cookie_util::IsCookieAccessResultInclude(CookieAccessResult()));
}

}  // namespace

}  // namespace net

"""


```