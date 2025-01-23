Response:
The user wants to understand the functionality of a C++ unit test file for Chromium's network stack, specifically the `cookie_util_unittest.cc` file. The request focuses on the section of code provided, asking about its purpose, relationship to JavaScript, logical reasoning (with examples), potential user errors, debugging information, and a summary of its functions.

Here's a breakdown of the thought process to answer this request:

1. **Identify the Core Functionality:** The provided code snippet consists of several methods within a test fixture (`CookieUtilComputeSameSiteContextTest`). These methods return collections of different URL-related objects (`GURL`), site-related objects (`SiteForCookies`), and origin-related objects (`url::Origin`). The naming of these methods (e.g., `GetCrossSiteUrls`, `GetSameSiteSitesForCookies`, `GetSameSiteInitiators`) strongly suggests they are designed to generate sets of URLs, sites, and origins categorized by their "same-site" or "cross-site" relationship. The `GetSameSiteUrlChains` and `GetCrossSiteUrlChains` functions build upon this by creating redirect chains of URLs. The `CanBeMainFrameNavigation` and `IsMainFrameNavigationPossibleValues` methods deal with determining if a URL and site context can represent a main frame navigation. The constant definitions at the end provide concrete examples of URLs, sites, and origins used in testing.

2. **Connect to the Broader Context:**  Knowing this is `cookie_util_unittest.cc`, and seeing terms like "same-site," "cross-site," and "SiteForCookies," it's clear this code is instrumental in testing the logic for how Chromium handles cookies in different browsing contexts. This involves determining if a request or script access to a cookie is considered "same-site" or "cross-site," which is crucial for security and privacy features like the SameSite cookie attribute.

3. **Address the JavaScript Relationship:**  Cookies are heavily used in web development and are accessible via JavaScript. While the *C++ code itself* isn't directly executed by JavaScript, the *logic being tested* directly impacts how JavaScript can interact with cookies. For example, the SameSite attribute restricts JavaScript's ability to access cookies in cross-site contexts.

4. **Illustrate with Logical Reasoning (Input/Output):**  Choose a simple method, like `GetCrossSiteUrls()`. The "input" is the internal state of the test fixture (the predefined URLs). The "output" is a `std::vector<GURL>` containing URLs *different* from the ones returned by `GetSameSiteUrls()`. Specifically, based on the defined constants, `GetSameSiteUrls()` would likely return `kSiteUrl`, `kSiteUrlWithPath`, `kSecureSiteUrl`, `kSubdomainUrl`, and `kSecureSubdomainUrl`. Therefore, `GetCrossSiteUrls()` would return `kCrossSiteUrl` and `kSecureCrossSiteUrl`.

5. **Identify Potential User/Programming Errors:**  Since this is *test code*, direct user errors are less relevant. However, a *programmer* writing tests might make errors. A common mistake would be defining the "same-site" and "cross-site" constants incorrectly, leading to flawed test cases. For instance, if `kSubdomainUrl` was accidentally defined as `"http://anotherexample.test/"`, the `GetSameSiteUrls()` and `GetCrossSiteUrls()` methods would produce incorrect outputs, and the tests would fail or, worse, pass incorrectly.

6. **Explain User Operation and Debugging:**  To reach this code during debugging, a developer would be investigating cookie behavior in Chromium. They might be looking at how SameSite cookies are being handled, or why a particular cookie is being blocked or allowed in a specific scenario. The debugging steps would involve:
    * Setting breakpoints in the cookie handling code.
    * Tracing the execution flow when a cookie is being accessed or set.
    * Observing how the `ComputeSameSiteContextFor...` functions are being called with different URLs, sites, and initiators.
    * Examining the values returned by the methods in this test file to understand the expected inputs for those functions.

7. **Summarize the Functionality (for Part 2):** Concisely state the main purpose of the code section: generating various combinations of URLs, sites, and initiators, categorized by their same-site or cross-site relationship. Emphasize that this data is used for testing the SameSite cookie logic within Chromium.

By following these steps, the explanation provided in the initial prompt can be constructed, addressing all aspects of the user's request.
这是 `net/cookies/cookie_util_unittest.cc` 文件的一部分，它主要的功能是**为 `cookie_util` 相关的单元测试提供测试数据和辅助方法，特别是用于测试 SameSite Cookie 的上下文计算逻辑**。

让我们分解一下这部分代码的功能：

**1. 提供各种类型的 URLs：**

*   `GetCrossSiteUrls()`:  返回一个 `GURL` 向量，包含被认为是**跨站**的 URLs。它通过获取所有 URLs 并排除掉同站的 URLs 来实现。
    *   **逻辑推理：** 假设 `GetAllUrls()` 返回 {"http://example.test/", "http://notexample.test/"}， `GetSameSiteUrls()` 返回 {"http://example.test/"}，那么 `GetCrossSiteUrls()` 将返回 {"http://notexample.test/"}。
*   `GetSameSiteUrls()`: 返回一个 `GURL` 向量，包含被认为是**同站**的 URLs。
*   `GetAllUrls()`:  （在之前的代码片段中，这里被调用但未显示具体实现）通常会返回所有预定义的测试 URLs。

**2. 提供各种类型的 SiteForCookies：**

*   `GetAllSitesForCookies()`: 返回一个 `SiteForCookies` 向量，包含了各种类型的 `SiteForCookies` 对象，例如空值、同站、安全同站、跨站和安全跨站。
*   `GetSameSiteSitesForCookies()`: 返回一个 `SiteForCookies` 向量，包含被认为是**同站**的 `SiteForCookies` 对象。 如果是非 schemeful 的情况，会包含跨 scheme 的同站 `SiteForCookies`。
*   `GetCrossSiteSitesForCookies()`: 返回一个 `SiteForCookies` 向量，包含被认为是**跨站**的 `SiteForCookies` 对象。它通过获取所有 `SiteForCookies` 并排除掉同站的 `SiteForCookies` 来实现。

**3. 提供各种类型的 Initiator Origins：**

*   `GetAllInitiators()`: 返回一个 `url::Origin` 可选值的向量，包含了各种类型的发起者 Origin，例如浏览器发起、不透明 Origin、同站 Origin、跨站 Origin、子域名 Origin 等。
*   `GetSameSiteInitiators()`: 返回一个 `url::Origin` 可选值的向量，包含被认为是**同站**的发起者 Origin。 如果是非 schemeful 的情况，会包含跨 scheme 的同站 Origin。
*   `GetCrossSiteInitiators()`: 返回一个 `url::Origin` 可选值的向量，包含被认为是**跨站**的发起者 Origin。它通过获取所有发起者 Origin 并排除掉同站的发起者 Origin 来实现。

**4. 提供同站和跨站的重定向链：**

*   `GetSameSiteUrlChains(const GURL& url)`: 返回一个 `GURL` 向量的向量，表示以 `url` 结尾且完全是**同站**的重定向链。
    *   **逻辑推理：** 假设 `GetSameSiteUrls()` 返回 {"http://a.test/", "http://b.test/"}，且 `url` 为 "http://c.test/" (假设与 a.test 和 b.test 同站)，那么 `GetSameSiteUrlChains(url)` 可能会返回 {{"http://a.test/", "http://c.test/"}, {"http://b.test/", "http://c.test/"}, {"http://a.test/", "http://a.test/", "http://c.test/"}, {"http://b.test/", "http://a.test/", "http://c.test/"}, {"http://a.test/", "http://b.test/", "http://c.test/"}, {"http://b.test/", "http://b.test/", "http://c.test/"}}。
*   `GetCrossSiteUrlChains(const GURL& url)`: 返回一个 `GURL` 向量的向量，表示以 `url` 结尾且是**跨站**的重定向链。
    *   **逻辑推理：** 假设 `GetSameSiteUrls()` 返回 {"http://a.test/"}， `GetCrossSiteUrls()` 返回 {"http://x.test/"}，且 `url` 为 "http://b.test/" (假设与 a.test 同站)，那么 `GetCrossSiteUrlChains(url)` 可能会返回 {{"http://x.test/", "http://b.test/"}, {"http://x.test/", "http://a.test/", "http://b.test/"}, {"http://a.test/", "http://x.test/", "http://b.test/"}}。

**5. 判断是否可以作为主框架导航：**

*   `CanBeMainFrameNavigation(const GURL& url, const SiteForCookies& site_for_cookies)`:  判断给定的 URL 和 `SiteForCookies` 是否可以构成主框架导航。这通常涉及到检查 `SiteForCookies` 是否为空，或者是否与 URL 的来源是首方且 schemeful 模式一致，以及 URL 的 scheme 是否不是 WebSocket。
*   `IsMainFrameNavigationPossibleValues(const GURL& url, const SiteForCookies& site_for_cookies)`: 返回一个布尔值向量，表示是否可以作为主框架导航的可能值。如果 `CanBeMainFrameNavigation` 返回 true，则返回 `{false, true}`，否则返回 `{false}`。

**6. 定义用于测试的常量：**

*   定义了各种 `GURL` 常量，代表不同的 URLs，包括同站、跨站、安全、非安全、子域名和 WebSocket 等。
*   定义了各种 `SiteForCookies` 常量，分别代表空值、同站、安全同站、跨站和安全跨站的 `SiteForCookies` 对象。
*   定义了各种 `url::Origin` 可选值的常量，代表不同的发起者 Origin。

**与 JavaScript 的关系：**

这部分 C++ 代码本身不直接运行在 JavaScript 环境中。但是，它所测试的 `cookie_util` 模块的功能直接影响到 JavaScript 如何与 Cookies 交互。

*   **SameSite Cookie 属性:**  SameSite 属性会限制 JavaScript 在跨站请求中发送 Cookie。这些测试用例会验证 Chromium 是否正确地计算了请求的 SameSite 上下文，从而决定是否应该发送带有 SameSite 属性的 Cookie。
*   **`document.cookie` API:** JavaScript 可以使用 `document.cookie` API 来读取和设置 Cookie。Chromium 的 Cookie 管理逻辑（包括 SameSite 的处理）会影响到 JavaScript 能否成功地读取或设置 Cookie。
*   **Fetch API 和 XMLHttpRequest:** 当 JavaScript 使用 Fetch API 或 XMLHttpRequest 发起网络请求时，浏览器会根据 SameSite 策略来决定是否包含 Cookie。这些测试用例验证了 Chromium 在这些场景下的行为是否符合预期。

**用户或编程常见的使用错误示例：**

虽然这是测试代码，但它可以帮助发现和预防用户或编程中与 Cookie 相关的错误：

*   **用户错误：** 用户可能会错误地认为设置了 `SameSite=Strict` 的 Cookie 在所有情况下都不会被发送，但实际上在同站导航中仍然会被发送。这些测试可以验证这种行为的正确性。
*   **编程错误：**  开发者可能会错误地理解 SameSite 策略，例如认为在子域名之间设置了 `SameSite=Lax` 的 Cookie 一定会被发送，但如果涉及到跨 scheme 的情况，行为可能会有所不同。这些测试可以帮助验证不同情况下的行为。
*   **配置错误：** 服务器端在设置 Cookie 的时候，可能会错误地配置 SameSite 属性，导致 Cookie 在不应该发送的时候被发送，或者应该发送的时候没有发送。这些测试可以帮助验证 Chromium 对不同 SameSite 属性的解析和处理是否正确。

**用户操作如何一步步到达这里 (作为调试线索)：**

假设用户遇到了一个与 SameSite Cookie 相关的问题，例如一个设置了 `SameSite=Lax` 的 Cookie 在跨站 form 提交时没有被发送。作为开发者，调试的步骤可能如下：

1. **用户报告问题：** 用户反馈某个功能在跨站场景下无法正常工作，怀疑是 Cookie 没有被发送。
2. **开发者复现问题：** 开发者尝试复现用户操作，确认问题确实存在。
3. **网络请求分析：** 开发者使用浏览器开发者工具的网络面板，查看实际发送的网络请求头，确认 Cookie 是否被包含。
4. **Cookie 信息检查：** 开发者查看该 Cookie 的详细信息，包括其 SameSite 属性。
5. **代码审查：** 开发者查看设置 Cookie 的服务端代码和发起跨站请求的客户端代码。
6. **Chromium 源码调试：** 如果怀疑是 Chromium 的 SameSite 策略处理有问题，开发者可能会需要调试 Chromium 源码：
    *   设置断点在 `net/cookies/cookie_util.cc` 或相关的 Cookie 处理代码中。
    *   当浏览器尝试发送 Cookie 时，代码会执行到 `cookie_util::ComputeSameSiteContextForRequest` 等函数。
    *   开发者可以检查传递给这些函数的参数（例如请求的 URL、发起者的 Origin、目标站点的 `SiteForCookies`），以及这些测试用例中定义的常量值，来理解 Chromium 是如何计算 SameSite 上下文的。
    *   通过查看这些测试用例，开发者可以了解各种边界情况和预期的行为，从而判断实际行为是否符合预期。

**归纳一下它的功能 (第2部分)：**

这部分代码的主要功能是**为 Chromium 的 Cookie SameSite 上下文计算逻辑提供全面的、结构化的测试数据**。它定义了各种类型的 URLs、`SiteForCookies` 和发起者 Origin，并提供了便捷的方法来获取同站和跨站的组合，以及模拟重定向链。这些数据被用于编写单元测试，以验证 `cookie_util` 模块在各种场景下是否能正确判断 SameSite 上下文，从而确保 Chromium 的 Cookie 安全策略能够正确执行。 简单来说，它就像一个精心准备的测试数据集生成器，用于全面测试 Cookie 的 SameSite 相关功能。

### 提示词
```
这是目录为net/cookies/cookie_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
GetCrossSiteUrls() const {
    std::vector<GURL> cross_site_urls;
    std::vector<GURL> same_site_urls = GetSameSiteUrls();
    for (const GURL& url : GetAllUrls()) {
      if (!base::Contains(same_site_urls, url))
        cross_site_urls.push_back(url);
    }
    return cross_site_urls;
  }

  std::vector<SiteForCookies> GetAllSitesForCookies() const {
    return {kNullSiteForCookies, kSiteForCookies, kSecureSiteForCookies,
            kCrossSiteForCookies, kSecureCrossSiteForCookies};
  }

  std::vector<SiteForCookies> GetSameSiteSitesForCookies() const {
    std::vector<SiteForCookies> same_site_sfc = {kSiteForCookies};
    // If schemeless, the cross-scheme SFC is also same-site.
    if (!IsSchemeful())
      same_site_sfc.push_back(kSecureSiteForCookies);
    return same_site_sfc;
  }

  std::vector<SiteForCookies> GetCrossSiteSitesForCookies() const {
    std::vector<SiteForCookies> cross_site_sfc;
    std::vector<SiteForCookies> same_site_sfc = GetSameSiteSitesForCookies();
    for (const SiteForCookies& sfc : GetAllSitesForCookies()) {
      if (!base::Contains(same_site_sfc, sfc.RepresentativeUrl(),
                          &SiteForCookies::RepresentativeUrl)) {
        cross_site_sfc.push_back(sfc);
      }
    }
    return cross_site_sfc;
  }

  std::vector<std::optional<url::Origin>> GetAllInitiators() const {
    return {kBrowserInitiated,   kOpaqueInitiator,
            kSiteInitiator,      kSecureSiteInitiator,
            kCrossSiteInitiator, kSecureCrossSiteInitiator,
            kSubdomainInitiator, kSecureSubdomainInitiator,
            kUnrelatedInitiator};
  }

  std::vector<std::optional<url::Origin>> GetSameSiteInitiators() const {
    std::vector<std::optional<url::Origin>> same_site_initiators{
        kBrowserInitiated, kSiteInitiator, kSubdomainInitiator};
    // If schemeless, the cross-scheme origins are also same-site.
    if (!IsSchemeful()) {
      same_site_initiators.push_back(kSecureSiteInitiator);
      same_site_initiators.push_back(kSecureSubdomainInitiator);
    }
    return same_site_initiators;
  }

  std::vector<std::optional<url::Origin>> GetCrossSiteInitiators() const {
    std::vector<std::optional<url::Origin>> cross_site_initiators;
    std::vector<std::optional<url::Origin>> same_site_initiators =
        GetSameSiteInitiators();
    for (const std::optional<url::Origin>& initiator : GetAllInitiators()) {
      if (!base::Contains(same_site_initiators, initiator))
        cross_site_initiators.push_back(initiator);
    }
    return cross_site_initiators;
  }

  // Returns an assortment of redirect chains that end in `url` as the
  // current request URL, and are completely same-site. `url` is expected to be
  // same-site to kSiteUrl.
  std::vector<std::vector<GURL>> GetSameSiteUrlChains(const GURL& url) const {
    std::vector<std::vector<GURL>> same_site_url_chains;
    for (const GURL& same_site_url : GetSameSiteUrls()) {
      same_site_url_chains.push_back({same_site_url, url});
      for (const GURL& other_same_site_url : GetSameSiteUrls()) {
        same_site_url_chains.push_back(
            {other_same_site_url, same_site_url, url});
      }
    }
    return same_site_url_chains;
  }

  // Returns an assortment of redirect chains that end in `url` as the
  // current request URL, and are cross-site. `url` is expected to be same-site
  // to kSiteUrl.
  std::vector<std::vector<GURL>> GetCrossSiteUrlChains(const GURL& url) const {
    std::vector<std::vector<GURL>> cross_site_url_chains;
    for (const GURL& cross_site_url : GetCrossSiteUrls()) {
      cross_site_url_chains.push_back({cross_site_url, url});
      for (const GURL& same_site_url : GetSameSiteUrls()) {
        cross_site_url_chains.push_back({cross_site_url, same_site_url, url});
        cross_site_url_chains.push_back({same_site_url, cross_site_url, url});
      }
    }
    return cross_site_url_chains;
  }

  // Computes possible values of is_main_frame_navigation that are consistent
  // with the DCHECKs.
  bool CanBeMainFrameNavigation(const GURL& url,
                                const SiteForCookies& site_for_cookies) const {
    return (site_for_cookies.IsNull() ||
            site_for_cookies.IsFirstPartyWithSchemefulMode(url, true)) &&
           !url.SchemeIsWSOrWSS();
  }

  std::vector<bool> IsMainFrameNavigationPossibleValues(
      const GURL& url,
      const SiteForCookies& site_for_cookies) const {
    return CanBeMainFrameNavigation(url, site_for_cookies)
               ? std::vector<bool>{false, true}
               : std::vector<bool>{false};
  }

  // Request URL.
  const GURL kSiteUrl{"http://example.test/"};
  const GURL kSiteUrlWithPath{"http://example.test/path"};
  const GURL kSecureSiteUrl{"https://example.test/"};
  const GURL kCrossSiteUrl{"http://notexample.test/"};
  const GURL kSecureCrossSiteUrl{"https://notexample.test/"};
  const GURL kSubdomainUrl{"http://subdomain.example.test/"};
  const GURL kSecureSubdomainUrl{"https://subdomain.example.test/"};
  const GURL kWsUrl{"ws://example.test/"};
  const GURL kWssUrl{"wss://example.test/"};
  // Site for cookies.
  const SiteForCookies kNullSiteForCookies;
  const SiteForCookies kSiteForCookies = SiteForCookies::FromUrl(kSiteUrl);
  const SiteForCookies kSecureSiteForCookies =
      SiteForCookies::FromUrl(kSecureSiteUrl);
  const SiteForCookies kCrossSiteForCookies =
      SiteForCookies::FromUrl(kCrossSiteUrl);
  const SiteForCookies kSecureCrossSiteForCookies =
      SiteForCookies::FromUrl(kSecureCrossSiteUrl);
  // Initiator origin.
  const std::optional<url::Origin> kBrowserInitiated = std::nullopt;
  const std::optional<url::Origin> kOpaqueInitiator =
      std::make_optional(url::Origin());
  const std::optional<url::Origin> kSiteInitiator =
      std::make_optional(url::Origin::Create(kSiteUrl));
  const std::optional<url::Origin> kSecureSiteInitiator =
      std::make_optional(url::Origin::Create(kSecureSiteUrl));
  const std::optional<url::Origin> kCrossSiteInitiator =
      std::make_optional(url::Origin::Create(kCrossSiteUrl));
  const std::optional<url::Origin> kSecureCrossSiteInitiator =
      std::make_optional(url::Origin::Create(kSecureCrossSiteUrl));
  const std::optional<url::Origin> kSubdomainInitiator =
      std::make_optional(url::Origin::Create(kSubdomainUrl));
  const std::optional<url::Origin> kSecureSubdomainInitiator =
      std::make_optional(url::Origin::Create(kSecureSubdomainUrl));
  const std::optional<url::Origin> kUnrelatedInitiator =
      std::make_optional(url::Origin::Create(GURL("https://unrelated.test/")));

 protected:
  base::test::ScopedFeatureList feature_list_;
};

TEST_P(CookieUtilComputeSameSiteContextTest, UrlAndSiteForCookiesCrossSite) {
  // If the SiteForCookies and URL are cross-site, then the context is always
  // cross-site.
  for (const GURL& url : GetSameSiteUrls()) {
    for (const SiteForCookies& site_for_cookies :
         GetCrossSiteSitesForCookies()) {
      for (const std::optional<url::Origin>& initiator : GetAllInitiators()) {
        for (const std::string& method : {"GET", "POST", "PUT", "HEAD"}) {
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                          url, site_for_cookies, initiator,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptSet(
                          url, site_for_cookies,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));
          for (bool is_main_frame_navigation :
               IsMainFrameNavigationPossibleValues(url, site_for_cookies)) {
            EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                            method, {url}, site_for_cookies, initiator,
                            is_main_frame_navigation,
                            false /* force_ignore_site_for_cookies */),
                        ContextTypeIs(ContextType::CROSS_SITE));
            EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                            {url}, site_for_cookies, initiator,
                            is_main_frame_navigation,
                            false /* force_ignore_site_for_cookies */),
                        ContextTypeIs(ContextType::CROSS_SITE));
            // If the current request URL is cross-site to the site-for-cookies,
            // the request context is always cross-site even if the URL chain
            // contains members that are same-site to the site-for-cookies.
            EXPECT_THAT(
                cookie_util::ComputeSameSiteContextForRequest(
                    method, {site_for_cookies.RepresentativeUrl(), url},
                    site_for_cookies, initiator, is_main_frame_navigation,
                    false /* force_ignore_site_for_cookies */),
                ContextTypeIs(ContextType::CROSS_SITE));
            EXPECT_THAT(
                cookie_util::ComputeSameSiteContextForResponse(
                    {site_for_cookies.RepresentativeUrl(), url},
                    site_for_cookies, initiator, is_main_frame_navigation,
                    false /* force_ignore_site_for_cookies */),
                ContextTypeIs(ContextType::CROSS_SITE));
          }
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForSubresource(
                          url, site_for_cookies,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));
        }
      }
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, SiteForCookiesNotSchemefullySame) {
  // If the SiteForCookies is not schemefully_same, even if its value is
  // schemefully same-site, the schemeful context type will be cross-site.
  if (!IsSchemeful())
    return;

  std::vector<SiteForCookies> sites_for_cookies = GetAllSitesForCookies();
  for (SiteForCookies& sfc : sites_for_cookies) {
    sfc.SetSchemefullySameForTesting(false);
  }

  for (const GURL& url : GetSameSiteUrls()) {
    for (const SiteForCookies& site_for_cookies : sites_for_cookies) {
      for (const std::optional<url::Origin>& initiator : GetAllInitiators()) {
        for (const std::string& method : {"GET", "POST", "PUT", "HEAD"}) {
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                          url, site_for_cookies, initiator,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptSet(
                          url, site_for_cookies,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));

          // If the site-for-cookies isn't schemefully_same, this cannot be a
          // main frame navigation.
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                          method, {url}, site_for_cookies, initiator,
                          false /* is_main_frame_navigation */,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForResponse(
                          {url}, site_for_cookies, initiator,
                          false /* is_main_frame_navigation */,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));

          EXPECT_THAT(cookie_util::ComputeSameSiteContextForSubresource(
                          url, site_for_cookies,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));
        }
      }
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForScriptGet) {
  for (const GURL& url : GetSameSiteUrls()) {
    // Same-site site-for-cookies.
    // (Cross-site cases covered above in UrlAndSiteForCookiesCrossSite test.)
    for (const SiteForCookies& site_for_cookies :
         GetSameSiteSitesForCookies()) {
      // Cross-site initiator -> it's same-site lax.
      for (const std::optional<url::Origin>& initiator :
           GetCrossSiteInitiators()) {
        EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                        url, site_for_cookies, initiator,
                        false /* force_ignore_site_for_cookies */),
                    ContextTypeIs(ContextType::SAME_SITE_LAX));
      }

      // Same-site initiator -> it's same-site strict.
      for (const std::optional<url::Origin>& initiator :
           GetSameSiteInitiators()) {
        EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                        url, site_for_cookies, initiator,
                        false /* force_ignore_site_for_cookies */),
                    ContextTypeIs(ContextType::SAME_SITE_STRICT));
      }
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForScriptGet_SchemefulDowngrade) {
  // Some test cases where the context is downgraded when computed schemefully.
  // (Should already be covered above, but just to be explicit.)
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                  ContextType::SAME_SITE_LAX),
            cookie_util::ComputeSameSiteContextForScriptGet(
                kSiteUrl, kSiteForCookies, kSecureSiteInitiator,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                  ContextType::SAME_SITE_LAX),
            cookie_util::ComputeSameSiteContextForScriptGet(
                kSecureSiteUrl, kSecureSiteForCookies, kSiteInitiator,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_LAX,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForScriptGet(
                kSecureSiteUrl, kSiteForCookies, kCrossSiteInitiator,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_LAX,
                                  ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForScriptGet(
                kSiteUrl, kSecureSiteForCookies, kCrossSiteInitiator,
                false /* force_ignore_site_for_cookies */));
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForScriptGet_WebSocketSchemes) {
  // wss/https and http/ws are considered the same for schemeful purposes.
  EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                  kWssUrl, kSecureSiteForCookies, kSecureSiteInitiator,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_STRICT));
  EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                  kWssUrl, kSecureSiteForCookies, kSecureCrossSiteInitiator,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_LAX));

  EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                  kWsUrl, kSiteForCookies, kSiteInitiator,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_STRICT));
  EXPECT_THAT(cookie_util::ComputeSameSiteContextForScriptGet(
                  kWsUrl, kSiteForCookies, kCrossSiteInitiator,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_LAX));
}

// Test cases where the URL chain has 1 member (i.e. no redirects).
TEST_P(CookieUtilComputeSameSiteContextTest, ForRequest) {
  for (const GURL& url : GetSameSiteUrls()) {
    // Same-site site-for-cookies.
    // (Cross-site cases covered above in UrlAndSiteForCookiesCrossSite test.)
    for (const SiteForCookies& site_for_cookies :
         GetSameSiteSitesForCookies()) {
      // Same-Site initiator -> it's same-site strict.
      for (const std::optional<url::Origin>& initiator :
           GetSameSiteInitiators()) {
        for (const std::string& method : {"GET", "POST", "PUT", "HEAD"}) {
          for (bool is_main_frame_navigation :
               IsMainFrameNavigationPossibleValues(url, site_for_cookies)) {
            EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                            method, {url}, site_for_cookies, initiator,
                            is_main_frame_navigation,
                            false /* force_ignore_site_for_cookies */),
                        ContextTypeIs(ContextType::SAME_SITE_STRICT));
          }
        }
      }

      // Cross-Site initiator -> it's same-site lax iff the method is safe.
      for (const std::optional<url::Origin>& initiator :
           GetCrossSiteInitiators()) {
        // For main frame navigations, the context is Lax (or Lax-unsafe).
        for (const std::string& method : {"GET", "HEAD"}) {
          if (!CanBeMainFrameNavigation(url, site_for_cookies))
            break;
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                          method, {url}, site_for_cookies, initiator,
                          true /* is_main_frame_navigation */,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::SAME_SITE_LAX));
        }
        for (const std::string& method : {"POST", "PUT"}) {
          if (!CanBeMainFrameNavigation(url, site_for_cookies))
            break;
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                          method, {url}, site_for_cookies, initiator,
                          true /* is_main_frame_navigation */,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::SAME_SITE_LAX_METHOD_UNSAFE));
        }

        // For non-main-frame-navigation requests, the context should be
        // cross-site.
        for (const std::string& method : {"GET", "POST", "PUT", "HEAD"}) {
          EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                          method, {url}, site_for_cookies, initiator,
                          false /* is_main_frame_navigation */,
                          false /* force_ignore_site_for_cookies */),
                      ContextTypeIs(ContextType::CROSS_SITE));
        }
      }
    }
  }
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForRequest_SchemefulDowngrade) {
  // Some test cases where the context is downgraded when computed schemefully.
  // (Should already be covered above, but just to be explicit.)

  // Cross-scheme URL and site-for-cookies with (schemelessly) same-site
  // initiator.
  // (The request cannot be a main frame navigation if the site-for-cookies is
  // not schemefully same-site).
  for (const std::string& method : {"GET", "POST"}) {
    EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                    ContextType::CROSS_SITE),
              cookie_util::ComputeSameSiteContextForRequest(
                  method, {kSecureSiteUrl}, kSiteForCookies, kSiteInitiator,
                  false /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */));
    EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                    ContextType::CROSS_SITE),
              cookie_util::ComputeSameSiteContextForRequest(
                  method, {kSiteUrl}, kSecureSiteForCookies, kSiteInitiator,
                  false /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */));
  }

  // Schemefully same-site URL and site-for-cookies with cross-scheme
  // initiator.
  for (bool is_main_frame_navigation : {false, true}) {
    ContextType lax_if_main_frame = is_main_frame_navigation
                                        ? ContextType::SAME_SITE_LAX
                                        : ContextType::CROSS_SITE;
    ContextType lax_unsafe_if_main_frame =
        is_main_frame_navigation ? ContextType::SAME_SITE_LAX_METHOD_UNSAFE
                                 : ContextType::CROSS_SITE;

    EXPECT_EQ(
        SameSiteCookieContext(ContextType::SAME_SITE_STRICT, lax_if_main_frame),
        cookie_util::ComputeSameSiteContextForRequest(
            "GET", {kSecureSiteUrl}, kSecureSiteForCookies, kSiteInitiator,
            is_main_frame_navigation,
            false /* force_ignore_site_for_cookies */));
    EXPECT_EQ(
        SameSiteCookieContext(ContextType::SAME_SITE_STRICT, lax_if_main_frame),
        cookie_util::ComputeSameSiteContextForRequest(
            "GET", {kSiteUrl}, kSiteForCookies, kSecureSiteInitiator,
            is_main_frame_navigation,
            false /* force_ignore_site_for_cookies */));
    EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                    lax_unsafe_if_main_frame),
              cookie_util::ComputeSameSiteContextForRequest(
                  "POST", {kSecureSiteUrl}, kSecureSiteForCookies,
                  kSiteInitiator, is_main_frame_navigation,
                  false /* force_ignore_site_for_cookies */));
    EXPECT_EQ(SameSiteCookieContext(ContextType::SAME_SITE_STRICT,
                                    lax_unsafe_if_main_frame),
              cookie_util::ComputeSameSiteContextForRequest(
                  "POST", {kSiteUrl}, kSiteForCookies, kSecureSiteInitiator,
                  is_main_frame_navigation,
                  false /* force_ignore_site_for_cookies */));
  }

  // Cross-scheme URL and site-for-cookies with cross-site initiator.
  // (The request cannot be a main frame navigation if the site-for-cookies is
  // not schemefully same-site).
  EXPECT_EQ(SameSiteCookieContext(ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForRequest(
                "GET", {kSiteUrl}, kSecureSiteForCookies, kCrossSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForRequest(
                "GET", {kSecureSiteUrl}, kSiteForCookies, kCrossSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForRequest(
                "POST", {kSiteUrl}, kSecureSiteForCookies, kCrossSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));
  EXPECT_EQ(SameSiteCookieContext(ContextType::CROSS_SITE),
            cookie_util::ComputeSameSiteContextForRequest(
                "POST", {kSecureSiteUrl}, kSiteForCookies, kCrossSiteInitiator,
                false /* is_main_frame_navigation */,
                false /* force_ignore_site_for_cookies */));
}

TEST_P(CookieUtilComputeSameSiteContextTest, ForRequest_WebSocketSchemes) {
  // wss/https and http/ws are considered the same for schemeful purposes.
  // (ws/wss requests cannot be main frame navigations.)
  EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                  "GET", {kWssUrl}, kSecureSiteForCookies, kSecureSiteInitiator,
                  false /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_STRICT));
  EXPECT_THAT(
      cookie_util::ComputeSameSiteContextForRequest(
          "GET", {kWssUrl}, kSecureSiteForCookies, kSecureCrossSiteInitiator,
          false /* is_main_frame_navigation */,
          false /* force_ignore_site_for_cookies */),
      ContextTypeIs(ContextType::CROSS_SITE));

  EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                  "GET", {kWsUrl}, kSiteForCookies, kSiteInitiator,
                  false /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::SAME_SITE_STRICT));
  EXPECT_THAT(cookie_util::ComputeSameSiteContextForRequest(
                  "GET", {kWsUrl}, kSiteForCookies, kCrossSiteInitiator,
                  false /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */),
              ContextTypeIs(ContextType::CROSS_SITE));
}

// Test cases where the URL chain contains multiple members, where the last
// member (current request URL) is same-site to kSiteUrl. (Everything is listed
// as same-site or cross-site relative to kSiteUrl.)
TEST_P(CookieUtilComputeSameSiteContextTest, ForRequest_Redirect) {
  struct {
    std::string method;
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
      {"GET", true, true, true, ContextType::SAME_SITE_STRICT,
       ContextType::SAME_SITE_STRICT, ContextType::SAME_SITE_STRICT,
       ContextType::SAME_SITE_STRICT,
       ContextRedirectTypeBug1221316::kAllSameSiteRedirect},
      {"GET", true, true, false, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"GET", true, false, true, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"GET", true, false, false, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      // If the url chain is cross-site, then the result will differ depending
      // on whether the redirect chain is considered, when the site-for-cookies
      // and initiator are both same-site.
      {"GET", false, true, true, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX, ContextType::SAME_SITE_STRICT,
       ContextType::SAME_SITE_STRICT,
       ContextRedirectTypeBug1221316::kPartialSameSiteRedirect},
      {"GET", false, true, false, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"GET", false, false, true, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"GET", false, false, false, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      // If the url chain is same-site, then the result is the same with or
      // without considering the redirect chain.
      {"POST", true, true, true, ContextType::SAME_SITE_STRICT,
       ContextType::SAME_SITE_STRICT, ContextType::SAME_SITE_STRICT,
       ContextType::SAME_SITE_STRICT,
       ContextRedirectTypeBug1221316::kAllSameSiteRedirect},
      {"POST", true, true, false, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX_METHOD_UNSAFE, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX_METHOD_UNSAFE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"POST", true, false, true, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"POST", true, false, false, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      // If the url chain is cross-site, then the result will differ depending
      // on whether the redirect chain is considered, when the site-for-cookies
      // and initiator are both same-site.
      {"POST", false, true, true, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX_METHOD_UNSAFE, ContextType::SAME_SITE_STRICT,
       ContextType::SAME_SITE_STRICT,
       ContextRedirectTypeBug1221316::kPartialSameSiteRedirect},
      {"POST", false, true, false, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX_METHOD_UNSAFE, ContextType::CROSS_SITE,
       ContextType::SAME_SITE_LAX_METHOD_UNSAFE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"POST", false, false, true, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
       ContextRedirectTypeBug1221316::kCrossSiteRedirect},
      {"POST", false, false, false, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE, ContextType::CROSS_SITE,
       ContextType::CROSS_SITE,
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
          EXPECT_THAT(
              cookie_util::ComputeSameSiteContextForRequest(
                  test_case.method, url_chain, site_for_cookies, initiator,
                  false /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */),
              AllOf(ContextTypeIs(expected_context_type),
                    CrossSiteRedirectMetadataCorrect(
                        cookie_util::HttpMethodStringToEnum(test_case.method),
                        test_case.expected_context_type_without_chain,
                        test_case.expected_context_type,
                        test_case.expected_redirect_type_with_chain)))
              << UrlChainToString(url_chain) << " "
              << site_for_cookies.ToDebugString() << " "
              << (initiator ? initiator->Serialize() : "nullopt");
          if (!CanBeMainFrameNavigation(url_chain.back(), site_for_cookies))
            continue;
          EXPECT_THAT(
              cookie_util::ComputeSameSiteContextForRequest(
                  test_case.method, url_chain, site_for_cookies, initiator,
                  true /* is_main_frame_navigation */,
                  false /* force_ignore_site_for_cookies */),
              AllOf(
                  ContextTypeIs(
                      expected_context_type_for_main_frame_navigation),
                  CrossSiteRedirectMetadataCorrect(
                      cookie_util::HttpMethodStringToEnum(test_case.method),
                      test_case
                          .expected_context_type_for_main_frame_navigation_w
```