Response:
The user wants me to analyze a C++ unit test file for Chromium's network stack, specifically `canonical_cookie_unittest.cc`. They're asking about its functionality and its relationship to JavaScript, along with examples, error scenarios, debugging, and a summary of the provided code snippet.

Here's a breakdown of the thought process to address each point:

1. **Functionality:** The file name strongly suggests it's testing the `CanonicalCookie` class. Reading the code confirms this. The tests cover various aspects of `CanonicalCookie`, including:
    * Inclusion/exclusion logic based on request URLs and cookie attributes (domain, path, secure, HTTP-only, SameSite).
    * Interaction with features like Schemeful Same-Site, First-Party Partitioning, Scheme-Bound Cookies, and Port-Bound Cookies.
    * Handling of SameSite=None cookies and the Secure attribute.
    * Metrics related to cookie access.
    * Warnings and exclusions due to cross-site redirect downgrades and scheme/port mismatches.
    * Expiration time limits for insecure cookies.
    * Scenarios with multiple exclusion reasons.
    * Partial comparison of cookies.

2. **Relationship to JavaScript:** Cookies are fundamental to web development and are accessible and manipulated by JavaScript. The `CanonicalCookie` class in Chromium is the underlying C++ representation of these cookies. The connection is that the logic tested in this file directly impacts how JavaScript can read and write cookies in a browser environment.

3. **JavaScript Examples:**  To illustrate the connection, I need to provide JavaScript code that demonstrates scenarios tested in the C++ code. For example:
    * Setting a cookie with `SameSite=None` without the `Secure` attribute and showing how a modern browser (using the tested logic) would treat it.
    * Showing how first-party partitioned cookies work in a cross-site context.
    * Demonstrating the effect of scheme-bound and port-bound cookies (if enabled).

4. **Logical Reasoning (Hypothetical Input & Output):**  For the `IncludeForRequestURL` tests, the inputs are a `CanonicalCookie` object, a request URL, and `CookieOptions`. The output is a `CookieAccessResult`, which indicates whether the cookie should be included and why (inclusion status, exclusion reasons, warnings). I need to select specific test cases and clearly outline the inputs and the expected output based on the code's logic.

5. **User/Programming Errors:** Common mistakes when working with cookies include:
    * Setting `SameSite=None` without `Secure`.
    * Incorrectly setting the `Domain` attribute.
    * Forgetting the `Secure` attribute for sensitive data.
    * Not understanding SameSite behavior.
    * Issues with partitioned cookies in cross-site scenarios.

6. **User Operations & Debugging:**  To reach the code being tested, a user interacts with a website that sets or tries to access cookies. Debugging often involves examining the browser's developer tools (Network tab, Application tab) to inspect cookie headers and understand why a cookie is being blocked or not sent. The unit tests in this file simulate these browser behaviors and provide a way for developers to verify the correctness of the cookie handling logic.

7. **Function Summary of the Snippet:** The provided code snippet focuses on testing the `IncludeForRequestURL` method of the `CanonicalCookie` class. It checks how different cookie attributes (like `SameSite`, partitioning, and source scheme/port) and feature flags influence whether a cookie is included in a request for various access semantics (LEGACY, NONLEGACY, UNKNOWN). It also tests warnings related to cross-site redirect downgrades.

**Self-Correction/Refinement during thought process:**

* Initially, I might just list the test names as the functionality. However, that's too granular. I need to group them by the feature or aspect of `CanonicalCookie` they are testing.
* For the JavaScript examples, I need to ensure they are concise and directly relevant to the C++ code's functionality. Avoid overly complex examples.
* When describing user operations, I need to link them to the underlying cookie mechanisms being tested. Simply saying "visit a website" isn't enough; I need to explain how that relates to cookie setting and retrieval.
* For debugging, focusing on the developer tools is crucial as that's where developers would actually investigate cookie-related issues.

By following these steps and refining the answers, I can provide a comprehensive and helpful response to the user's request.
这个文件是Chromium网络栈中 `net/cookies/canonical_cookie_unittest.cc` 的一部分，它主要用于测试 `CanonicalCookie` 类的功能。`CanonicalCookie` 类是 Chromium 中表示和处理 HTTP Cookie 的核心类。

**功能归纳 (针对提供的代码片段):**

这部分代码主要集中在测试 `CanonicalCookie::IncludeForRequestURL` 方法的行为，该方法决定了一个 Cookie 是否应该包含在对特定 URL 的请求中。 具体来说，它测试了以下功能点：

1. **Schemeful Same-Site 功能的影响:**  测试在启用和禁用 `SchemefulSameSite` 功能时，Cookie 的包含行为如何变化。这涉及到具有相同站点但不同协议 (例如 `http://example.com` 和 `https://example.com`) 的请求。
2. **First-Party Partitioning 与跨站点上下文:** 测试在启用 First-Party Partitioning 的情况下，带有或不带有 Partition Key 的 Cookie 在跨站点上下文中是否会被包含。它还涉及到在非跨站点上下文中，Partitioned Cookie 的行为。
3. **SameSite=None 需要 Secure:** 验证 `SameSite=None` 属性的 Cookie 只有在请求 URL 是安全上下文 (HTTPS) 时才会被包含，除非使用 `LEGACY` 的访问语义。
4. **SameSite 属性的指标收集:**  测试在不同的 `SameSite` 上下文中 (`CROSS_SITE`, `SAME_SITE_LAX`, `SAME_SITE_STRICT`)，`SameSite` 属性对 Cookie 包含行为的影响，并验证是否记录了相关的指标。
5. **跨站点重定向降级警告:** 测试当请求由于跨站点重定向从更严格的 `SameSite` 上下文降级到更宽松的上下文时，是否会产生相应的警告。这与 `features::kCookieSameSiteConsidersRedirectChain` 功能有关。
6. **Scheme-Bound Cookie 的状态:** 测试在启用或禁用 `SchemeBoundCookies` 功能时，Cookie 的源 Scheme (HTTP 或 HTTPS) 是否与请求 URL 的 Scheme 匹配，以及不匹配时产生的警告或排除状态。
7. **Port-Bound Cookie 的状态:** 测试在启用或禁用 `PortBoundCookies` 功能时，Cookie 的源端口是否与请求 URL 的端口匹配，以及不匹配时产生的警告或排除状态。
8. **Domain Cookie 的端口匹配:** 验证域名 Cookie 是否可以匹配任何请求 URL 的端口，而主机名 Cookie 则需要端口完全匹配。
9. **不安全 Cookie 的过期时间限制:** 测试当启用 `TimeLimitedInsecureCookies` 功能时，不安全 (HTTP) Cookie 的过期时间是否会被限制在创建后 3 小时内。
10. **多种排除原因:** 测试当一个 Cookie 由于多个原因不被包含时，`IncludeForRequestURL` 方法会返回所有相关的排除原因。
11. **部分比较:** 测试 `CanonicalCookie` 对象的 `PartialCompare` 方法，该方法用于比较两个 Cookie 的部分属性 (例如名称、域、路径)，但不包括值。

**与 JavaScript 功能的关系:**

`CanonicalCookie` 类在 C++ 层处理 Cookie 的逻辑，而 JavaScript 通过 `document.cookie` API 与浏览器中的 Cookie 进行交互。  这部分 C++ 代码的测试直接影响了浏览器如何响应 JavaScript 对 Cookie 的操作。

**举例说明:**

* **SameSite=None 和 Secure:**  如果 JavaScript 代码尝试设置一个 `SameSite=None` 的 Cookie，但没有设置 `Secure` 属性，那么根据这里的测试，在启用了 `NONLEGACY` 或 `UNKNOWN` 访问语义的情况下，这个 Cookie 将不会在非 HTTPS 的请求中被发送。

   ```javascript
   // 在 HTTPS 页面上设置一个 SameSite=None 的 Cookie，但没有 Secure 属性
   document.cookie = "mycookie=value; SameSite=None";

   // 在另一个 HTTP 页面发起请求时，这个 Cookie 将不会被发送 (除非使用了 LEGACY 语义)。
   ```

* **First-Party Partitioning:** 如果一个网站设置了一个带有 First-Party Partition Key 的 Cookie，那么只有在完全相同的 top-level site 上发起的请求，这个 Cookie 才会被包含。 JavaScript 在设置 Cookie 时无法直接指定 Partition Key，这个逻辑由浏览器底层处理。

   ```javascript
   // 假设 www.example.com 设置了一个 Partitioned Cookie。
   document.cookie = "partitioned_cookie=value; SameSite=None; Secure";

   // 只有在 www.example.com 上发起的请求才会包含这个 cookie。
   // 在另一个网站 (例如 www.another.com) 上发起的请求不会包含。
   ```

* **Scheme-Bound Cookie (假设启用):** 如果一个 HTTPS 网站设置了一个 Scheme-Bound Cookie (虽然 JavaScript API 没有显式的 Scheme-Bound 属性)，那么这个 Cookie 将不会被发送到 HTTP 版本的相同站点。

   ```javascript
   // 在 https://www.example.com 上设置一个 Cookie (假设底层启用了 Scheme-Bound)
   document.cookie = "scheme_bound=value; Secure";

   // 当 JavaScript 向 http://www.example.com 发起请求时，这个 cookie 不会被发送。
   ```

**逻辑推理 (假设输入与输出):**

* **假设输入:**
    * 一个 `CanonicalCookie` 对象，其属性为 `name="test"`, `domain="example.com"`, `path="/"`, `secure=true`, `samesite=None`。
    * 请求 URL 为 `http://www.example.com/page.html`。
    * `CookieOptions` 没有特殊设置。
    * `CookieAccessParams` 使用 `CookieAccessSemantics::NONLEGACY`。

* **预期输出:**
    * `IncludeForRequestURL` 方法将返回一个 `CookieAccessResult`，其 `status` 包含 `CookieInclusionStatus::EXCLUDE_SAMESITE_NONE_INSECURE` 排除原因。

* **解释:** 因为 Cookie 的 `SameSite` 属性为 `None` 且 `secure` 为 `true`，根据现代浏览器行为 (由 `NONLEGACY` 语义控制)，它只应该在安全上下文 (HTTPS) 中发送。由于请求 URL 是 HTTP，因此 Cookie 不会被包含，并返回相应的排除原因。

**用户或编程常见的使用错误:**

* **忘记为 `SameSite=None` 的 Cookie 设置 `Secure` 属性:** 这是最常见的错误。开发者可能会设置 `SameSite=None` 以允许跨站点发送 Cookie，但忘记设置 `Secure` 属性，导致 Cookie 在 HTTPS 站点可以工作，但在 HTTP 站点无法工作。

   ```javascript
   // 错误的做法：在非 HTTPS 环境下，这个 Cookie 不会被发送
   document.cookie = "mycookie=value; SameSite=None";
   ```

* **错误地设置 `Domain` 属性:**  `Domain` 属性定义了 Cookie 可以被发送到的域。如果设置不当，例如设置为一个不存在的域或顶级域，Cookie 可能无法按预期工作。

   ```javascript
   // 错误的做法：Domain 设置为顶级域，通常会被浏览器阻止
   document.cookie = "mycookie=value; Domain=.com";
   ```

* **假设 Partitioned Cookie 在所有子域可用:**  Partitioned Cookie 的作用域限制于完全匹配的 top-level site，不会像普通 Cookie 那样在子域间共享。开发者可能错误地假设在子域中也能访问到 Partitioned Cookie。

* **不理解 SameSite 属性的影响:**  开发者可能不清楚 `SameSite=Lax` 和 `SameSite=Strict` 的具体行为，导致 Cookie 在某些跨站点请求中被意外阻止。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户访问一个网页:** 用户在浏览器中输入一个 URL 或点击一个链接。
2. **网页加载和资源请求:** 浏览器开始加载网页的 HTML、CSS、JavaScript 和其他资源。
3. **发起 HTTP 请求:**  在加载资源的过程中，浏览器会发起多个 HTTP 请求。
4. **Cookie 的包含判断:** 对于每个请求，浏览器需要决定哪些 Cookie 应该包含在 `Cookie` 请求头中。
5. **`CanonicalCookie::IncludeForRequestURL` 被调用:**  当浏览器需要判断一个特定的 Cookie 是否应该包含在当前请求中时，会创建或获取 `CanonicalCookie` 对象，并调用其 `IncludeForRequestURL` 方法。
6. **根据 Cookie 属性和请求上下文进行判断:** `IncludeForRequestURL` 方法会根据 Cookie 的 `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite` 属性，以及请求的 URL、是否是安全上下文、是否是跨站点请求等信息进行逻辑判断。
7. **返回包含或排除结果:** 方法返回一个 `CookieAccessResult`，指示 Cookie 是否应该被包含，以及任何相关的警告或排除原因。
8. **构建和发送 HTTP 请求:**  浏览器根据判断结果构建 HTTP 请求头，并将符合条件的 Cookie 添加到 `Cookie` 头中，然后发送请求。
9. **服务器处理请求:** 服务器接收到请求，并根据 `Cookie` 头中的信息进行相应的处理。

**调试线索:**

当开发者遇到 Cookie 相关问题时，例如 Cookie 没有被发送、设置失败等，可以通过以下步骤进行调试，这些步骤最终会指向 `CanonicalCookie` 相关的逻辑：

1. **打开浏览器的开发者工具:**  通常使用 F12 键打开。
2. **查看 Network (网络) 面板:**  检查发出的 HTTP 请求头，查看 `Cookie` 字段是否包含预期的 Cookie。如果缺少 Cookie，这可能意味着在 `IncludeForRequestURL` 阶段被排除了。
3. **查看 Application (应用) 面板:**  查看 Cookies 部分，检查当前域名下存储的 Cookie 信息，包括 `Name`, `Value`, `Domain`, `Path`, `Expires / Max-Age`, `Size`, `HttpOnly`, `Secure`, `SameSite`, `Priority` 等属性。检查这些属性是否设置正确。
4. **使用 `chrome://flags` 检查实验性功能:**  例如 `chrome://flags/#schemeful-same-site` 可以查看 `SchemefulSameSite` 功能是否启用。
5. **使用 `chrome://net-internals/#cookies` 查看更详细的 Cookie 信息:**  可以查看更底层的 Cookie 状态和操作。
6. **设置断点进行 C++ 代码调试:**  对于 Chromium 的开发者，可以在 `net/cookies/canonical_cookie.cc` 中设置断点，跟踪 `IncludeForRequestURL` 的执行过程，查看 Cookie 的属性和请求上下文，理解为什么 Cookie 被包含或排除。

**功能归纳 (提供的代码片段):**

总而言之，提供的代码片段主要用于测试 `CanonicalCookie::IncludeForRequestURL` 方法在各种场景下的行为，包括：

* **不同的 SameSite 配置和功能开关状态下的 Cookie 包含逻辑。**
* **First-Party Partitioning 对跨站点 Cookie 访问的影响。**
* **`SameSite=None` 属性对安全上下文的要求。**
* **由于跨站点重定向降级而产生的警告。**
* **Scheme-Bound 和 Port-Bound Cookie 的匹配规则。**
* **不安全 Cookie 的过期时间限制。**
* **当 Cookie 由于多种原因被排除时的状态报告。**

这些测试确保了 Chromium 在处理 HTTP Cookie 时符合最新的标准和安全最佳实践。

Prompt: 
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共9部分，请归纳一下它的功能

"""
 SchemefulIndependentCases();

    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::LEGACY,
                                        schemeful_disabled_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::NONLEGACY,
                                        schemeful_disabled_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::UNKNOWN,
                                        schemeful_disabled_test_cases);
  }
  {
    // Schemeful Same-Site enabled.
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(features::kSchemefulSameSite);

    SchemefulIndependentCases();

    // With LEGACY access the cases should act as if schemeful is disabled, even
    // when it's not.
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::LEGACY,
                                        schemeful_disabled_test_cases);

    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::NONLEGACY,
                                        schemeful_enabled_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::UNKNOWN,
                                        schemeful_enabled_test_cases);
  }
}

TEST(CanonicalCookieTest, TestFirstPartyPartitionedAndCrossSiteContext) {
  std::string histogram_name =
      "Cookie.FirstPartyPartitioned.HasCrossSiteAncestor";
  base::Time current_time = base::Time::Now();
  base::HistogramTester histogram_tester;
  GURL url("https://www.example.com");
  GURL url2("https://wwwnottheSame.com");
  CookieOptions options;

  auto make_cookie = [current_time](const auto& partition_key) {
    return CanonicalCookie::CreateUnsafeCookieForTesting(
        "A", "2", "www.example.com", "/test", current_time, base::Time(),
        base::Time(), base::Time(), true /*secure*/, true /*httponly*/,
        CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, partition_key);
  };

  auto no_partition_key_cookie = make_cookie(std::nullopt);
  auto partitioned_cookie =
      make_cookie(CookiePartitionKey::FromURLForTesting(GURL(url)));
  auto nonced_partition_key_cookie =
      make_cookie(CookiePartitionKey::FromURLForTesting(
          GURL(url), CookiePartitionKey::AncestorChainBit::kCrossSite,
          base::UnguessableToken::Create()));
  auto different_site_partition_key_cookie =
      make_cookie(CookiePartitionKey::FromURLForTesting(GURL(url2)));

  histogram_tester.ExpectBucketCount(histogram_name, true, 0);
  histogram_tester.ExpectBucketCount(histogram_name, false, 0);
  no_partition_key_cookie->IncludeForRequestURL(
      url, options,
      CookieAccessParams{CookieAccessSemantics::NONLEGACY, false});

  histogram_tester.ExpectBucketCount(histogram_name, true, 0);
  histogram_tester.ExpectBucketCount(histogram_name, false, 0);

  partitioned_cookie->IncludeForRequestURL(
      url, options,
      CookieAccessParams{CookieAccessSemantics::NONLEGACY, false});
  histogram_tester.ExpectBucketCount(histogram_name, true, 1);
  histogram_tester.ExpectBucketCount(histogram_name, false, 0);

  nonced_partition_key_cookie->IncludeForRequestURL(
      url, options,
      CookieAccessParams{CookieAccessSemantics::NONLEGACY, false});
  histogram_tester.ExpectBucketCount(histogram_name, true, 1);
  histogram_tester.ExpectBucketCount(histogram_name, false, 0);

  different_site_partition_key_cookie->IncludeForRequestURL(
      url, options,
      CookieAccessParams{CookieAccessSemantics::NONLEGACY, false});
  histogram_tester.ExpectBucketCount(histogram_name, true, 1);
  histogram_tester.ExpectBucketCount(histogram_name, false, 0);

  // Show that a cookie in a non-CROSS_SITE context registers as false.
  options.set_same_site_cookie_context(
      net::CookieOptions::SameSiteCookieContext(
          net::CookieOptions::SameSiteCookieContext::ContextType::
              SAME_SITE_LAX));

  partitioned_cookie->IncludeForRequestURL(
      url, options,
      CookieAccessParams{CookieAccessSemantics::NONLEGACY, false});
  histogram_tester.ExpectBucketCount(histogram_name, true, 1);
  histogram_tester.ExpectBucketCount(histogram_name, false, 1);
}
// Test that SameSite=None requires Secure.
TEST(CanonicalCookieTest, IncludeCookiesWithoutSameSiteMustBeSecure) {
  GURL url("https://www.example.com");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options;

  // Make a SameSite=None, *not* Secure cookie.
  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
      url, "A=2; SameSite=None", creation_time, server_time);
  ASSERT_TRUE(cookie.get());
  EXPECT_FALSE(cookie->SecureAttribute());
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cookie->SameSite());
  EXPECT_EQ(CookieEffectiveSameSite::NO_RESTRICTION,
            cookie->GetEffectiveSameSiteForTesting());

  // UKNOWN semantics results in modern behavior (requiring Secure).
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_SAMESITE_NONE_INSECURE}));

  // LEGACY semantics does not require Secure for SameSite=None cookies.
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{CookieAccessSemantics::LEGACY,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.IsInclude());

  // NONLEGACY semantics results in modern behavior (requiring Secure).
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{CookieAccessSemantics::NONLEGACY,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_SAMESITE_NONE_INSECURE}));
}

TEST(CanonicalCookieTest, IncludeForRequestURL_SameSiteNone_Metrics) {
  constexpr bool delegate_treats_url_as_trustworthy = false;
  const base::Time now = base::Time::Now();
  const auto make_cookie = [now](CookieSameSite same_site) {
    return CanonicalCookie::CreateUnsafeCookieForTesting(
        "A", "1", "www.example.com", "/test", now, base::Time(), base::Time(),
        base::Time(), true /* secure */, false /*httponly*/, same_site,
        COOKIE_PRIORITY_DEFAULT);
  };
  GURL url("https://www.example.com/test");

  const std::unique_ptr<CanonicalCookie> same_site_none_cookie =
      make_cookie(CookieSameSite::NO_RESTRICTION);
  const std::unique_ptr<CanonicalCookie> same_site_lax_cookie =
      make_cookie(CookieSameSite::LAX_MODE);
  const std::unique_ptr<CanonicalCookie> same_site_strict_cookie =
      make_cookie(CookieSameSite::STRICT_MODE);
  CookieOptions options;
  options.set_same_site_cookie_context(CookieOptions::SameSiteCookieContext(
      CookieOptions::SameSiteCookieContext::ContextType::CROSS_SITE));

  // Check that the most restrictive context is recognized and enforced.
  EXPECT_THAT(same_site_none_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(CookieInclusionStatus(), _, _, true));
  EXPECT_THAT(same_site_lax_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(Not(net::IsInclude()), _, _, true));
  EXPECT_THAT(same_site_strict_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(Not(net::IsInclude()), _, _, true));

  // Next: allow a SameSite=Lax cookie.
  options.set_same_site_cookie_context(CookieOptions::SameSiteCookieContext(
      CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX));
  EXPECT_THAT(same_site_none_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(CookieInclusionStatus(), _, _, true));
  EXPECT_THAT(same_site_lax_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(net::IsInclude(), _, _, true));
  EXPECT_THAT(same_site_strict_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(Not(net::IsInclude()), _, _, true));

  // Next: allow a SameSite=Strict cookie.
  options.set_same_site_cookie_context(CookieOptions::SameSiteCookieContext(
      CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT));
  EXPECT_THAT(same_site_none_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(CookieInclusionStatus(), _, _, true));
  EXPECT_THAT(same_site_strict_cookie->IncludeForRequestURL(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy)),
              MatchesCookieAccessResult(net::IsInclude(), _, _, true));
}

// Test that the CookieInclusionStatus warning for inclusion changed by
// cross-site redirect context downgrade is applied correctly.
TEST(CanonicalCookieTest, IncludeForRequestURL_RedirectDowngradeWarning) {
  using Context = CookieOptions::SameSiteCookieContext;
  using ContextType = Context::ContextType;

  Context::ContextMetadata strict_lax_downgrade_metadata,
      strict_cross_downgrade_metadata;
  strict_lax_downgrade_metadata.cross_site_redirect_downgrade =
      Context::ContextMetadata::ContextDowngradeType::kStrictToLax;
  strict_cross_downgrade_metadata.cross_site_redirect_downgrade =
      Context::ContextMetadata::ContextDowngradeType::kStrictToCross;

  // Because there are downgrades we need to set the HTTP method as well, since
  // some metrics code expects that. The actual method doesn't matter here.
  strict_lax_downgrade_metadata.http_method_bug_1221316 =
      Context::ContextMetadata::HttpMethod::kGet;
  strict_cross_downgrade_metadata.http_method_bug_1221316 =
      Context::ContextMetadata::HttpMethod::kGet;

  GURL url("https://www.example.test/test");
  GURL insecure_url("http://www.example.test/test");

  const struct {
    ContextType context_type;
    Context::ContextMetadata metadata;
    CookieSameSite samesite;
    bool expect_cross_site_redirect_warning;
  } kTestCases[] = {
      // Strict-to-lax downgrade.
      {ContextType::SAME_SITE_STRICT, strict_lax_downgrade_metadata,
       CookieSameSite::STRICT_MODE, true},
      {ContextType::SAME_SITE_LAX, strict_lax_downgrade_metadata,
       CookieSameSite::STRICT_MODE, true},
      {ContextType::SAME_SITE_STRICT, strict_lax_downgrade_metadata,
       CookieSameSite::LAX_MODE, false},
      {ContextType::SAME_SITE_LAX, strict_lax_downgrade_metadata,
       CookieSameSite::LAX_MODE, false},
      {ContextType::SAME_SITE_STRICT, strict_lax_downgrade_metadata,
       CookieSameSite::NO_RESTRICTION, false},
      {ContextType::SAME_SITE_LAX, strict_lax_downgrade_metadata,
       CookieSameSite::NO_RESTRICTION, false},

      // Strict-to-cross downgrade.
      {ContextType::SAME_SITE_STRICT, strict_cross_downgrade_metadata,
       CookieSameSite::STRICT_MODE, true},
      {ContextType::CROSS_SITE, strict_cross_downgrade_metadata,
       CookieSameSite::STRICT_MODE, true},
      {ContextType::SAME_SITE_STRICT, strict_cross_downgrade_metadata,
       CookieSameSite::LAX_MODE, true},
      {ContextType::CROSS_SITE, strict_cross_downgrade_metadata,
       CookieSameSite::LAX_MODE, true},
      {ContextType::SAME_SITE_STRICT, strict_cross_downgrade_metadata,
       CookieSameSite::NO_RESTRICTION, false},
      {ContextType::CROSS_SITE, strict_cross_downgrade_metadata,
       CookieSameSite::NO_RESTRICTION, false},
  };

  for (bool consider_redirects : {true, false}) {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatureState(
        features::kCookieSameSiteConsidersRedirectChain, consider_redirects);

    for (CookieAccessSemantics semantics :
         {CookieAccessSemantics::LEGACY, CookieAccessSemantics::NONLEGACY}) {
      // There are no downgrade warnings for undowngraded contexts.
      for (ContextType context_type :
           {ContextType::SAME_SITE_STRICT, ContextType::SAME_SITE_LAX,
            ContextType::SAME_SITE_LAX_METHOD_UNSAFE,
            ContextType::CROSS_SITE}) {
        for (CookieSameSite samesite :
             {CookieSameSite::UNSPECIFIED, CookieSameSite::NO_RESTRICTION,
              CookieSameSite::LAX_MODE, CookieSameSite::STRICT_MODE}) {
          std::unique_ptr<CanonicalCookie> cookie =
              CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "1", "www.example.test", "/test", base::Time::Now(),
                  base::Time(), base::Time(), base::Time(), /*secure=*/true,
                  /*httponly=*/false, samesite, COOKIE_PRIORITY_DEFAULT);

          CookieOptions options;
          options.set_same_site_cookie_context(Context(context_type));

          EXPECT_FALSE(
              cookie
                  ->IncludeForRequestURL(
                      url, options,
                      CookieAccessParams(
                          semantics,
                          /*delegate_treats_url_as_trustworthy=*/false))
                  .status.HasWarningReason(
                      CookieInclusionStatus::
                          WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION));
        }
      }

      for (const auto& test : kTestCases) {
        std::unique_ptr<CanonicalCookie> cookie =
            CanonicalCookie::CreateUnsafeCookieForTesting(
                "A", "1", "www.example.test", "/test", base::Time::Now(),
                base::Time(), base::Time(), base::Time(), /*secure=*/true,
                /*httponly=*/false, test.samesite, COOKIE_PRIORITY_DEFAULT);

        CookieOptions options;
        options.set_same_site_cookie_context(
            Context(test.context_type, test.context_type, test.metadata,
                    test.metadata));
        EXPECT_EQ(
            cookie
                ->IncludeForRequestURL(
                    url, options,
                    CookieAccessParams(
                        semantics,
                        /*delegate_treats_url_as_trustworthy=*/false))
                .status.HasWarningReason(
                    CookieInclusionStatus::
                        WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION),
            test.expect_cross_site_redirect_warning);

        // SameSite warnings not applied if other exclusion reasons apply (e.g.
        // non-https with Secure attribute).
        EXPECT_FALSE(
            cookie
                ->IncludeForRequestURL(
                    insecure_url, options,
                    CookieAccessParams(
                        semantics,
                        /*delegate_treats_url_as_trustworthy=*/false))
                .status.HasWarningReason(
                    CookieInclusionStatus::
                        WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION));
      }
    }
  }
}

// Test that the correct inclusion status is generated when a cookie's source
// scheme does(n't) match the url's.
TEST(CanonicalCookieTest, IncludeForRequestURL_SchemeBoundStatus) {
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options;
  options.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext::MakeInclusive());

  CookieAccessParams params(CookieAccessSemantics::UNKNOWN,
                            /*delegate_treats_url_as_trustworthy=*/false);
  CookieAccessParams trusted_params(
      CookieAccessSemantics::UNKNOWN,
      /*delegate_treats_url_as_trustworthy=*/true);

  GURL secure_url("https://www.example.test:123/");
  GURL insecure_url("http://www.example.test:123/");

  // Specify SameSite=Lax not because we care about SameSite in this test, but
  // rather to prevent warnings that SameSite isn't specified.
  auto secure_cookie = CanonicalCookie::CreateForTesting(
      secure_url, "secure=foobar; SameSite=Lax", creation_time, server_time);
  auto secure_attr_cookie = CanonicalCookie::CreateForTesting(
      secure_url, "secure=foobar; SameSite=Lax; Secure", creation_time,
      server_time);
  auto insecure_cookie = CanonicalCookie::CreateForTesting(
      insecure_url, "insecure=foobar; SameSite=Lax", creation_time,
      server_time);
  // Create a cookie with an unset scheme. This can happen if a cookie was
  // stored in the DB before we began recording source schemes.
  auto unset_cookie = CanonicalCookie::CreateForTesting(
      secure_url, "unset=foobar; SameSite=Lax", creation_time, server_time);
  unset_cookie->SetSourceScheme(CookieSourceScheme::kUnset);

  // When the feature is disabled we should have warnings.
  {
    base::test::ScopedFeatureList scope_feature_list;
    scope_feature_list.InitAndDisableFeature(
        features::kEnableSchemeBoundCookies);

    EXPECT_FALSE(
        secure_cookie->IncludeForRequestURL(secure_url, options, params)
            .status.ShouldWarn());

    EXPECT_TRUE(
        secure_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status.HasWarningReason(
                CookieInclusionStatus::WARN_SCHEME_MISMATCH));

    // If a cookie is already blocked due to the `Secure` attribute then we
    // don't bother warning.
    auto status =
        secure_attr_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status;
    EXPECT_TRUE(
        status.HasExclusionReason(CookieInclusionStatus::EXCLUDE_SECURE_ONLY));
    EXPECT_FALSE(status.ShouldWarn());

    EXPECT_FALSE(
        insecure_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status.ShouldWarn());

    EXPECT_TRUE(
        insecure_cookie->IncludeForRequestURL(secure_url, options, params)
            .status.HasWarningReason(
                CookieInclusionStatus::WARN_SCHEME_MISMATCH));

    // If a url is treated as trustworthy, then it's allowed to access cookies
    // with a secure source scheme.
    EXPECT_FALSE(
        secure_cookie
            ->IncludeForRequestURL(insecure_url, options, trusted_params)
            .status.ShouldWarn());

    // Cookies with an unset source scheme should match any url scheme.
    EXPECT_FALSE(unset_cookie->IncludeForRequestURL(secure_url, options, params)
                     .status.ShouldWarn());
    EXPECT_FALSE(
        unset_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status.ShouldWarn());
  }
  // When the feature is enabled we should have exclusions.
  {
    base::test::ScopedFeatureList scope_feature_list;
    scope_feature_list.InitAndEnableFeature(
        features::kEnableSchemeBoundCookies);

    EXPECT_TRUE(secure_cookie->IncludeForRequestURL(secure_url, options, params)
                    .status.IsInclude());

    EXPECT_TRUE(
        secure_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status.HasExclusionReason(
                CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH));

    // If a cookie is already blocked due to the `Secure` attribute then we
    // don't bother with our exclusion reason.
    auto status =
        secure_attr_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status;
    EXPECT_TRUE(
        status.HasExclusionReason(CookieInclusionStatus::EXCLUDE_SECURE_ONLY));
    EXPECT_FALSE(status.HasExclusionReason(
        CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH));

    EXPECT_TRUE(
        insecure_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status.IsInclude());

    EXPECT_TRUE(
        insecure_cookie->IncludeForRequestURL(secure_url, options, params)
            .status.HasExclusionReason(
                CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH));

    // If a url is treated as trustworthy, then it's allowed to access cookies
    // with a secure source scheme. But we should have a warning indicating
    // this.
    status = secure_cookie
                 ->IncludeForRequestURL(insecure_url, options, trusted_params)
                 .status;
    EXPECT_TRUE(status.IsInclude());
    EXPECT_TRUE(status.HasWarningReason(
        CookieInclusionStatus::WARN_SECURE_ACCESS_GRANTED_NON_CRYPTOGRAPHIC));

    // Cookies with an unset source scheme should match any url scheme.
    EXPECT_TRUE(unset_cookie->IncludeForRequestURL(secure_url, options, params)
                    .status.IsInclude());
    EXPECT_TRUE(
        unset_cookie->IncludeForRequestURL(insecure_url, options, params)
            .status.IsInclude());
  }
}

// Test that the correct inclusion status is generated when a cookie's source
// port does(n't) match the url's.
TEST(CanonicalCookieTest, IncludeForRequestURL_PortBoundStatus) {
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options;
  options.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext::MakeInclusive());

  CookieAccessParams params(CookieAccessSemantics::UNKNOWN,
                            /*delegate_treats_url_as_trustworthy=*/false);

  GURL url1("https://www.example.test:443/");
  GURL url2("https://www.example.test:123/");

  // Specify SameSite=Lax not because we care about SameSite in this test, but
  // rather to prevent warnings that SameSite isn't specified.
  auto cookie1 = CanonicalCookie::CreateForTesting(
      url1, "cookie=1; SameSite=Lax", creation_time, server_time);
  auto cookie2 = CanonicalCookie::CreateForTesting(
      url2, "cookie=2; SameSite=Lax", creation_time, server_time);

  // Create a cookie with an unspecified port. This can happen if a cookie was
  // stored in the DB before we began recording source ports.
  auto unspecified_cookie = CanonicalCookie::CreateForTesting(
      url2, "cookie=unspecified; SameSite=Lax", creation_time, server_time);
  unspecified_cookie->SetSourcePort(url::PORT_UNSPECIFIED);

  // When the feature is disabled we should have warnings.
  {
    base::test::ScopedFeatureList scope_feature_list;
    scope_feature_list.InitAndDisableFeature(features::kEnablePortBoundCookies);

    EXPECT_FALSE(cookie1->IncludeForRequestURL(url1, options, params)
                     .status.ShouldWarn());

    EXPECT_TRUE(cookie1->IncludeForRequestURL(url2, options, params)
                    .status.HasWarningReason(
                        CookieInclusionStatus::WARN_PORT_MISMATCH));

    // Cookies with an unspecified port should match any url port.
    EXPECT_FALSE(unspecified_cookie->IncludeForRequestURL(url1, options, params)
                     .status.ShouldWarn());
    EXPECT_FALSE(unspecified_cookie->IncludeForRequestURL(url2, options, params)
                     .status.ShouldWarn());
  }
  // When the feature is enabled we should have exclusions.
  {
    base::test::ScopedFeatureList scope_feature_list;
    scope_feature_list.InitAndEnableFeature(features::kEnablePortBoundCookies);

    EXPECT_TRUE(cookie1->IncludeForRequestURL(url1, options, params)
                    .status.IsInclude());

    EXPECT_TRUE(cookie1->IncludeForRequestURL(url2, options, params)
                    .status.HasExclusionReason(
                        CookieInclusionStatus::EXCLUDE_PORT_MISMATCH));

    // Cookies with an unspecified port should match any url port.
    EXPECT_TRUE(unspecified_cookie->IncludeForRequestURL(url1, options, params)
                    .status.IsInclude());
    EXPECT_TRUE(unspecified_cookie->IncludeForRequestURL(url2, options, params)
                    .status.IsInclude());
  }
}

// Test that domain cookies match any request url port.
TEST(CanonicalCookieTest, IncludeForRequestURL_DomainCookiesPortMatch) {
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options;
  options.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext::MakeInclusive());

  CookieAccessParams params(CookieAccessSemantics::UNKNOWN,
                            /*delegate_treats_url_as_trustworthy=*/false);

  GURL url1("https://www.example.test:443/");
  GURL url2("https://www.example.test:123/");

  // Specify SameSite=Lax not because we care about SameSite in this test, but
  // rather to prevent warnings that SameSite isn't specified.
  auto host_cookie = CanonicalCookie::CreateForTesting(
      url1, "cookie=hostonly; SameSite=Lax", creation_time, server_time);

  auto domain_cookie = CanonicalCookie::CreateForTesting(
      url1, "cookie=domain; SameSite=Lax; Domain=example.test", creation_time,
      server_time);

  // When the feature is disabled we shouldn't get any port mismatch warnings
  // for domain cookies.
  {
    base::test::ScopedFeatureList scope_feature_list;
    scope_feature_list.InitAndDisableFeature(features::kEnablePortBoundCookies);

    EXPECT_FALSE(host_cookie->IncludeForRequestURL(url1, options, params)
                     .status.ShouldWarn());

    EXPECT_FALSE(domain_cookie->IncludeForRequestURL(url1, options, params)
                     .status.ShouldWarn());

    EXPECT_TRUE(host_cookie->IncludeForRequestURL(url2, options, params)
                    .status.HasWarningReason(
                        CookieInclusionStatus::WARN_PORT_MISMATCH));

    EXPECT_FALSE(domain_cookie->IncludeForRequestURL(url2, options, params)
                     .status.ShouldWarn());
  }
  // When the feature is enabled domain cookies should match any url port.
  {
    base::test::ScopedFeatureList scope_feature_list;
    scope_feature_list.InitAndEnableFeature(features::kEnablePortBoundCookies);

    EXPECT_TRUE(host_cookie->IncludeForRequestURL(url1, options, params)
                    .status.IsInclude());

    EXPECT_TRUE(domain_cookie->IncludeForRequestURL(url1, options, params)
                    .status.IsInclude());

    EXPECT_TRUE(host_cookie->IncludeForRequestURL(url2, options, params)
                    .status.HasExclusionReason(
                        CookieInclusionStatus::EXCLUDE_PORT_MISMATCH));

    EXPECT_TRUE(domain_cookie->IncludeForRequestURL(url2, options, params)
                    .status.IsInclude());
  }
}

TEST(CanonicalCookieTest, InsecureCookiesExpiryTimeLimit) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now();
  base::Time future_date = creation_time + base::Days(1);
  {
    base::test::ScopedFeatureList scoped_feature_list;
    scoped_feature_list.InitWithFeatures(
        {features::kEnableSchemeBoundCookies,
         features::kTimeLimitedInsecureCookies},
        {});
    std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
        url, "A=1; expires=" + HttpUtil::TimeFormatHTTP(future_date),
        creation_time);
    ASSERT_TRUE(cookie);
    // With the feature enabled, expiration time should be limited to 3 hours
    // after creation. Equality check needs to have a second margin due to
    // microsecond rounding causing breakage.
    EXPECT_TRUE(((creation_time + base::Hours(3)) - cookie->ExpiryDate())
                    .FloorToMultiple(base::Seconds(1))
                    .is_zero());
  }
  {
    base::test::ScopedFeatureList scoped_feature_list;
    scoped_feature_list.InitWithFeatures(
        {features::kEnableSchemeBoundCookies},
        {features::kTimeLimitedInsecureCookies});
    std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
        url, "A=1; expires=" + HttpUtil::TimeFormatHTTP(future_date),
        creation_time);
    ASSERT_TRUE(cookie);
    // With the feature disabled, expiration time should not be limited.
    // Equality check needs to have a second margin due to microsecond rounding
    // causing breakage.
    EXPECT_TRUE((future_date - cookie->ExpiryDate())
                    .FloorToMultiple(base::Seconds(1))
                    .is_zero());
  }
}

TEST(CanonicalCookieTest, MultipleExclusionReasons) {
  GURL url("http://www.not-secure.com/foo");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options;
  options.set_exclude_httponly();
  options.set_same_site_cookie_context(CookieOptions::SameSiteCookieContext(
      CookieOptions::SameSiteCookieContext::ContextType::CROSS_SITE));

  // Test IncludeForRequestURL()
  // Note: This is a cookie that should never exist normally, because Create()
  // would weed it out.
  auto cookie1 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "name", "value", "other-domain.com", "/bar", creation_time, base::Time(),
      base::Time(), base::Time(), true /* secure */, true /* httponly */,
      CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT);
  EXPECT_THAT(
      cookie1->IncludeForRequestURL(
          url, options,
          CookieAccessParams{CookieAccessSemantics::UNKNOWN,
                             /*delegate_treats_url_as_trustworthy=*/false}),
      MatchesCookieAccessResult(
          CookieInclusionStatus::MakeFromReasonsForTesting({
              CookieInclusionStatus::EXCLUDE_HTTP_ONLY,
              CookieInclusionStatus::EXCLUDE_SECURE_ONLY,
              CookieInclusionStatus::EXCLUDE_DOMAIN_MISMATCH,
              CookieInclusionStatus::EXCLUDE_NOT_ON_PATH,
              CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT,
          }),
          _, _, false));

  // Test Create()
  CookieInclusionStatus create_status;
  auto cookie2 = CanonicalCookie::Create(
      url, "__Secure-notactuallysecure=value;Domain=some-other-domain.com",
      creation_time, server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &create_status);
  ASSERT_FALSE(cookie2);
  EXPECT_TRUE(create_status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX,
       CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Test IsSetPermittedInContext()
  auto cookie3 = CanonicalCookie::CreateForTesting(
      url, "name=value;HttpOnly;SameSite=Lax", creation_time, server_time);
  ASSERT_TRUE(cookie3);
  EXPECT_THAT(
      cookie3->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          CookieInclusionStatus::MakeFromReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_HTTP_ONLY,
               CookieInclusionStatus::EXCLUDE_SAMESITE_LAX}),
          _, _, false));
}

TEST(CanonicalCookieTest, PartialCompare) {
  GURL url("http://www.example.com");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      url, "a=b", creation_time, server_time));
  std::unique_ptr<CanonicalCookie> cookie_different_path(
      CanonicalCookie::CreateForTesting(url, "a=b; path=/foo", creation_time,
                                        server_time));
  std::unique_ptr<CanonicalCookie> cookie_different_value(
      CanonicalCookie::CreateForTesting(url, "a=c", creation_time,
                                        server_time));

  // Cookie is equivalent to itself.
  EXPECT_FALSE(cookie->PartialCompare(*cookie));

  // Changing the path affects the ordering.
  EXPECT_TRUE(cookie->PartialCompare(*cookie_different_path));
  EXPECT_FALSE(cookie_different_path->PartialCompare(*cookie));

  // Changing the value does not affect the ordering.
  EXPECT_FALSE(cookie->PartialCompare(*cookie_different_value
"""


```