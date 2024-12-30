Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The request asks for the *functionality* of the `canonical_cookie_unittest.cc` file within Chromium's network stack. It also asks about relationships to JavaScript, logical inferences, common errors, debugging clues, and a final summary.

2. **Identify the Core Subject:** The filename itself, `canonical_cookie_unittest.cc`, immediately tells us this file contains *unit tests* for the `CanonicalCookie` class. This is the central piece of information.

3. **Scan for Key Components:**  Quickly scan the code for keywords and patterns common in unit tests:
    * `#include`:  These tell us the dependencies. We see includes for `net/cookies/canonical_cookie.h`, `testing/gtest/include/gtest/gtest.h`, and various other Chromium-specific testing utilities. This reinforces that it's a test file.
    * `TEST(...)`: This is the core macro from Google Test (gtest) that defines individual test cases. Each `TEST` block focuses on a specific aspect of `CanonicalCookie`.
    * `EXPECT_...`:  These are assertion macros from gtest. They verify that certain conditions are met within the tests. `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT`, `EXPECT_NE`, etc., all perform different kinds of checks.
    * Variable names: Look for descriptive names that indicate what's being tested (e.g., `same_site_none_cookie`, `insecure_url`, `options`).
    * Comments: While not extensive in this snippet, comments can provide valuable hints about the test's purpose.

4. **Categorize the Tests:**  As you read through the `TEST` blocks, try to group them by the functionality they are testing. For example:
    * Tests related to `IsSetPermittedInContext`: This is a recurring theme, suggesting a key method for checking if a cookie can be set in a given context. Pay attention to the different scenarios being tested (same-site, cross-site, secure/insecure, redirects).
    * Tests related to cookie attributes:  Look for tests checking `Secure`, `HttpOnly`, `SameSite`, `PartitionKey`.
    * Tests related to cookie parsing/creation:  See tests using `CanonicalCookie::CreateUnsafeCookieForTesting` and `CanonicalCookie::FromStorage`.
    * Tests related to specific features:  Spot tests with feature flags like `kCookieSameSiteConsidersRedirectChain` and `kEnableSchemeBoundCookies`.
    * Tests related to edge cases or specific conditions:  Look for tests dealing with invalid sizes, hidden prefixes, etc.
    * Tests related to metrics/histograms: Notice tests using `base::HistogramTester`.

5. **Infer Functionality from Tests:**  Based on the categories of tests, you can infer the functionality of the `CanonicalCookie` class itself. For example, the numerous tests around `IsSetPermittedInContext` suggest that a core responsibility of `CanonicalCookie` is determining the permissibility of setting a cookie based on various factors. The tests around `Secure`, `HttpOnly`, and `SameSite` indicate that `CanonicalCookie` stores and uses these attributes for its logic.

6. **Consider the JavaScript Relationship:**  Think about how cookies are used in a web browser context. JavaScript interacts with cookies through the `document.cookie` API. While this C++ code *doesn't directly execute JavaScript*, it's responsible for *managing* the cookies that JavaScript interacts with. The tests involving `IsSetPermittedInContext` are directly relevant to whether a JavaScript `document.cookie = ...` operation will succeed or be blocked by the browser's security policy.

7. **Construct Logical Inferences (Input/Output):** For specific test cases, you can deduce the intended input and expected output. For instance, in the `IsSetPermitted_SameSiteNone_Metrics` test:
    * **Input:** A cookie with `SameSite=None`, `SameSite=Lax`, or `SameSite=Strict`, and a `CookieOptions` object specifying a same-site or cross-site context.
    * **Output:**  The `IsSetPermittedInContext` method returns a result indicating whether the cookie can be set, along with a status that might include warnings or exclusions.

8. **Identify Common Errors:** Based on the tests, think about potential user or developer errors. For example, the tests around `Secure` and `HttpOnly` highlight the importance of setting these attributes correctly for security. The `SameSite` tests point to potential issues with cross-site cookie sharing if `SameSite` is not configured properly.

9. **Trace User Actions (Debugging Clues):** Imagine how a user's interaction with a website could lead to the execution of this code. Setting a cookie via JavaScript, a server sending a `Set-Cookie` header, or a browser attempting to access stored cookies are all potential pathways. The tests around `IsSetPermittedInContext` are crucial for understanding *why* a cookie might be blocked in a particular scenario.

10. **Synthesize the Summary:**  Combine the identified functionalities into a concise summary. Emphasize the core purpose of the class and the role of the unit tests.

11. **Review and Refine:** Read through your analysis to ensure it's clear, accurate, and addresses all parts of the request. Make sure the examples are relevant and easy to understand. For instance, explicitly mentioning `document.cookie` clarifies the JavaScript relationship.

By following these steps, you can systematically analyze the C++ unit test file and extract the requested information, even without being an expert in the specific codebase. The key is to focus on the test structure, the assertions being made, and the names of the functions and variables involved.
这是文件 `net/cookies/canonical_cookie_unittest.cc` 的第 9 部分，也是最后一部分，它主要包含了一系列针对 `CanonicalCookie` 类的单元测试。综合前面 8 部分的内容，我们可以归纳出这个文件的主要功能是：

**核心功能：测试 `CanonicalCookie` 类的各种功能和逻辑。**

`CanonicalCookie` 类在 Chromium 网络栈中用于表示和操作 HTTP Cookie。这个单元测试文件的目标是验证 `CanonicalCookie` 类的各个方法是否按照预期工作，涵盖了 Cookie 的创建、属性设置、比较、权限检查等多个方面。

**具体测试的功能点包括（基于提供的代码片段和推断）：**

* **`IsSetPermittedInContext` 方法的测试:**
    * **SameSite 属性的影响:**  测试在不同的 `SameSite` 设置（`None`, `Lax`, `Strict`) 和不同的请求上下文（同站、跨站）下，Cookie 是否允许被设置。
    * **委托是否信任 URL 的影响:** 测试 `delegate_treats_url_as_trustworthy` 参数对 Cookie 设置权限的影响。
    * **重定向降级警告:** 测试在跨站点重定向导致上下文降级时，是否会正确发出警告 (`WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION`)。
* **Cookie 大小的限制:** 测试当 Cookie 的 name 或 value 超过一定大小时，`FromStorage` 方法是否仍然能够处理，并记录相关的直方图数据。
* **端口调整逻辑:** 测试 `GetAndAdjustPortForTrustworthyUrls` 方法在处理不同 scheme (http, https, ws, wss) 的 URL 时，是否能正确调整端口号，尤其是在可信来源的情况下。
* **隐藏前缀名称的识别:** 测试 `HasHiddenPrefixName` 方法是否能正确识别以 `__Secure-` 或 `__Host-` 开头的 Cookie 名称。
* **双下划线前缀名称的直方图记录:** 测试是否正确记录了以双下划线开头（但不是 `__Secure-` 或 `__Host-`）的 Cookie 名称。
* **是否为第三方分区 Cookie 的判断:** 测试 `IsThirdPartyPartitioned` 方法是否能正确判断一个 Cookie 是否是第三方分区 Cookie。
* **`IsSecure` 方法的测试:**  测试在启用或禁用 `kEnableSchemeBoundCookies` 特性时，`IsSecure` 方法是否能正确判断 Cookie 是否安全，包括检查 secure 属性和 source scheme。

**与 JavaScript 的关系:**

`CanonicalCookie` 类本身是 C++ 代码，不直接涉及 JavaScript 的执行。然而，它的功能与 JavaScript 密切相关，因为：

* **JavaScript 通过 `document.cookie` API 来读取、设置和删除 Cookie。**  `CanonicalCookie` 类负责管理这些 Cookie 的信息和状态。
* **`IsSetPermittedInContext` 方法的测试直接关系到浏览器如何判断是否允许 JavaScript 设置 Cookie。** 例如，如果一个 Cookie 设置了 `SameSite=Strict`，并且当前是跨站请求，那么 `IsSetPermittedInContext` 应该返回不允许设置，这会影响 JavaScript 调用 `document.cookie` 的结果。

**举例说明 JavaScript 关系:**

假设一个网站 `a.com` 设置了一个 Cookie：

```
Set-Cookie: mycookie=value; SameSite=Strict; Secure
```

然后，用户访问另一个网站 `b.com`，`b.com` 的页面中包含一个指向 `a.com` 的 `<img>` 标签。当浏览器尝试加载这个图片时，会发起一个对 `a.com` 的请求。

在 Chromium 的网络栈中，当处理这个请求时，会调用 `CanonicalCookie::IsSetPermittedInContext` 来判断是否应该发送 `a.com` 设置的 `mycookie`。由于 `mycookie` 设置了 `SameSite=Strict`，并且这是一个跨站请求（从 `b.com` 到 `a.com`），`IsSetPermittedInContext` 将返回不允许发送该 Cookie。

因此，尽管 JavaScript 没有直接参与 `CanonicalCookie` 的测试，但 `CanonicalCookie` 的行为直接决定了 JavaScript 操作 Cookie 的结果。

**逻辑推理、假设输入与输出:**

以 `TEST(CanonicalCookieTest, IsSetPermitted_SameSiteNone_Metrics)` 为例：

**假设输入:**

* 一个 `SameSite=None` 的 Cookie (`same_site_none_cookie`)
* 一个 `SameSite=Lax` 的 Cookie (`same_site_lax_cookie`)
* 一个 `SameSite=Strict` 的 Cookie (`same_site_strict_cookie`)
* 目标 URL `https://www.example.com/test`
* `CookieOptions` 对象，分别设置为：
    * `SameSiteCookieContext::ContextType::CROSS_SITE` (跨站上下文)
    * `SameSiteCookieContext::ContextType::SAME_SITE_LAX` (同站 Lax 上下文)
* `CookieAccessParams` 使用 `CookieAccessSemantics::LEGACY`

**预期输出:**

* **跨站上下文:**
    * `same_site_none_cookie`: 允许设置 (返回 `MatchesCookieAccessResult(CookieInclusionStatus(), _, _, true)`)
    * `same_site_lax_cookie`: 不允许设置 (返回 `MatchesCookieAccessResult(Not(net::IsInclude()), _, _, true)`)
    * `same_site_strict_cookie`: 不允许设置 (返回 `MatchesCookieAccessResult(Not(net::IsInclude()), _, _, true)`)
* **同站 Lax 上下文:**
    * `same_site_none_cookie`: 允许设置
    * `same_site_lax_cookie`: 允许设置 (返回 `MatchesCookieAccessResult(net::IsInclude(), _, _, true)`)
    * `same_site_strict_cookie`: 允许设置 (返回 `MatchesCookieAccessResult(net::IsInclude(), _, _, true)`)

**用户或编程常见的使用错误:**

* **未在 HTTPS 上设置 Secure Cookie:**  如果一个 Cookie 设置了 `Secure` 属性，但尝试在非 HTTPS 页面上设置，`IsSetPermittedInContext` 将返回不允许设置。这是为了防止中间人攻击。
    * **用户操作:**  访问一个 HTTP 网站，该网站尝试通过 JavaScript 或 `Set-Cookie` header 设置一个带有 `Secure` 属性的 Cookie。
    * **错误示例:**  `Set-Cookie: mycookie=value; Secure` 在 `http://example.com` 上设置会失败。
* **跨站请求中依赖 SameSite=Strict Cookie:** 开发者可能会错误地假设 `SameSite=Strict` 的 Cookie 在所有情况下都会发送，导致跨站功能失效。
    * **用户操作:**  在一个网站 `b.com` 上点击链接或提交表单到另一个网站 `a.com`，而 `a.com` 依赖于之前在 `a.com` 上设置的 `SameSite=Strict` 的 Cookie。
    * **错误示例:** 用户登录 `a.com` 后，访问 `b.com` 上的一个链接到 `a.com` 的功能，该功能依赖于登录状态的 Cookie，但由于 `SameSite=Strict`，Cookie 没有被发送，导致功能异常。
* **错误地假设所有浏览器都支持新的 Cookie 特性:**  例如，过分依赖 `SameSite=None; Secure` 而没有考虑到旧版本浏览器可能不支持，导致兼容性问题。

**用户操作如何一步步到达这里 (调试线索):**

当开发者在调试与 Cookie 相关的网络问题时，可能会逐步深入到 `CanonicalCookie` 类的相关代码：

1. **用户报告网站功能异常:** 用户反馈某个网站的登录状态丢失，或者某些跨站功能无法正常工作。
2. **开发者检查网络请求:** 使用浏览器的开发者工具 (Network tab) 查看请求头和响应头，特别是 `Cookie` 和 `Set-Cookie` header。
3. **检查 Cookie 的属性:**  查看 Cookie 的 `SameSite`, `Secure`, `HttpOnly` 等属性，判断是否配置正确。
4. **断点调试 Cookie 管理代码:** 如果怀疑是浏览器 Cookie 管理的问题，开发者可能会在 Chromium 的网络栈代码中设置断点，例如在 `CanonicalCookie::IsSetPermittedInContext` 或相关的 Cookie 设置/读取函数中。
5. **分析 `IsSetPermittedInContext` 的调用:**  通过断点信息，可以追踪是哪些因素导致 `IsSetPermittedInContext` 返回了特定的结果（允许或不允许设置），例如当前的请求上下文、Cookie 的 `SameSite` 属性等。
6. **查看单元测试:** 为了理解 `CanonicalCookie` 的行为和各种边界情况，开发者可能会查看 `canonical_cookie_unittest.cc` 文件中的相关测试用例，例如关于 `SameSite`、`Secure` 和跨站重定向的测试，来理解代码的预期行为。

**归纳其功能 (作为第 9 部分的总结):**

这个 `canonical_cookie_unittest.cc` 文件作为整个测试套件的最后一部分，其功能是**全面且细致地测试 `CanonicalCookie` 类的各种行为和逻辑**。它覆盖了 Cookie 的关键属性 (SameSite, Secure, HttpOnly)、不同的访问上下文 (同站、跨站)、以及一些特定的场景 (例如重定向降级、Cookie 大小限制、隐藏前缀等)。通过这些测试，可以确保 `CanonicalCookie` 类在处理 HTTP Cookie 时的正确性和可靠性，这对于保障 Web 安全和用户体验至关重要。 这些测试也为开发者提供了关于如何正确使用和理解 Cookie 行为的重要参考。

Prompt: 
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共9部分，请归纳一下它的功能

"""
chesCookieAccessResult(_, _, _, true));
          EXPECT_THAT(
              cookie->IsSetPermittedInContext(
                  insecure_url, options,
                  CookieAccessParams(access_semantics,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(_, _, _,
                                        delegate_treats_url_as_trustworthy));
          EXPECT_THAT(
              cookie->IsSetPermittedInContext(
                  localhost_url, options,
                  CookieAccessParams(access_semantics,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(_, _, _, true));
        }
      }
    }
  }
}

TEST(CanonicalCookieTest, IsSetPermitted_SameSiteNone_Metrics) {
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
  EXPECT_THAT(same_site_none_cookie->IsSetPermittedInContext(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(CookieInclusionStatus(), _, _, true));
  EXPECT_THAT(same_site_lax_cookie->IsSetPermittedInContext(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(Not(net::IsInclude()), _, _, true));
  EXPECT_THAT(same_site_strict_cookie->IsSetPermittedInContext(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(Not(net::IsInclude()), _, _, true));

  // Next: allow a SameSite=Lax or SameSite=Strict cookie.
  options.set_same_site_cookie_context(CookieOptions::SameSiteCookieContext(
      CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX));
  EXPECT_THAT(same_site_none_cookie->IsSetPermittedInContext(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(CookieInclusionStatus(), _, _, true));
  EXPECT_THAT(same_site_lax_cookie->IsSetPermittedInContext(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(net::IsInclude(), _, _, true));
  EXPECT_THAT(same_site_strict_cookie->IsSetPermittedInContext(
                  url, options,
                  CookieAccessParams(CookieAccessSemantics::LEGACY,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              MatchesCookieAccessResult(net::IsInclude(), _, _, true));
}

// Test that the CookieInclusionStatus warning for inclusion changed by
// cross-site redirect context downgrade is applied correctly.
TEST(CanonicalCookieTest, IsSetPermittedInContext_RedirectDowngradeWarning) {
  using Context = CookieOptions::SameSiteCookieContext;
  using ContextType = Context::ContextType;

  GURL url("https://www.example.test/test");
  GURL insecure_url("http://www.example.test/test");

  // Test cases to be used with a lax-to-cross context downgrade.
  const struct {
    ContextType context_type;
    CookieSameSite samesite;
    bool expect_cross_site_redirect_warning;
  } kTestCases[] = {
      {ContextType::SAME_SITE_LAX, CookieSameSite::STRICT_MODE, true},
      {ContextType::CROSS_SITE, CookieSameSite::STRICT_MODE, true},
      {ContextType::SAME_SITE_LAX, CookieSameSite::LAX_MODE, true},
      {ContextType::CROSS_SITE, CookieSameSite::LAX_MODE, true},
      {ContextType::SAME_SITE_LAX, CookieSameSite::NO_RESTRICTION, false},
      {ContextType::CROSS_SITE, CookieSameSite::NO_RESTRICTION, false},
  };

  for (bool consider_redirects : {true, false}) {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatureState(
        features::kCookieSameSiteConsidersRedirectChain, consider_redirects);

    for (CookieAccessSemantics semantics :
         {CookieAccessSemantics::LEGACY, CookieAccessSemantics::NONLEGACY}) {
      // There are no downgrade warnings for undowngraded contexts.
      for (ContextType context_type : {ContextType::SAME_SITE_LAX,
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
                  ->IsSetPermittedInContext(
                      url, options,
                      CookieAccessParams(
                          semantics,
                          /*delegate_treats_url_as_trustworthy=*/false),
                      kCookieableSchemes)
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

        Context::ContextMetadata lax_cross_downgrade_metadata;
        lax_cross_downgrade_metadata.cross_site_redirect_downgrade =
            Context::ContextMetadata::ContextDowngradeType::kLaxToCross;
        CookieOptions options;
        options.set_same_site_cookie_context(Context(
            test.context_type, test.context_type, lax_cross_downgrade_metadata,
            lax_cross_downgrade_metadata));

        EXPECT_EQ(
            cookie
                ->IsSetPermittedInContext(
                    url, options,
                    CookieAccessParams(
                        semantics,
                        /*delegate_treats_url_as_trustworthy=*/false),
                    kCookieableSchemes)
                .status.HasWarningReason(
                    CookieInclusionStatus::
                        WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION),
            test.expect_cross_site_redirect_warning);

        // SameSite warnings not applied if other exclusion reasons apply (e.g.
        // non-https with Secure attribute).
        EXPECT_FALSE(
            cookie
                ->IsSetPermittedInContext(
                    insecure_url, options,
                    CookieAccessParams(
                        semantics,
                        /*delegate_treats_url_as_trustworthy=*/false),
                    kCookieableSchemes)
                .status.HasWarningReason(
                    CookieInclusionStatus::
                        WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION));
      }
    }
  }
}

TEST(CanonicalCookieTest, TestIsCanonicalWithInvalidSizeHistograms) {
  base::HistogramTester histograms;
  const char kFromStorageWithValidLengthHistogram[] =
      "Cookie.FromStorageWithValidLength";
  const base::HistogramBase::Sample kInValid = 0;
  const base::HistogramBase::Sample kValid = 1;

  base::Time two_hours_ago = base::Time::Now() - base::Hours(2);
  base::Time one_hour_ago = base::Time::Now() - base::Hours(1);
  base::Time one_hour_from_now = base::Time::Now() + base::Hours(1);

  // Test a cookie that is canonical and valid size
  EXPECT_TRUE(CanonicalCookie::FromStorage(
      "A", "B", "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure, 87,
      CookieSourceType::kUnknown));

  histograms.ExpectBucketCount(kFromStorageWithValidLengthHistogram, kInValid,
                               0);
  histograms.ExpectBucketCount(kFromStorageWithValidLengthHistogram, kValid, 1);

  // Test loading a couple of cookies which are canonical but with an invalid
  // size
  const std::string kCookieBig(4096, 'a');
  EXPECT_TRUE(CanonicalCookie::FromStorage(
      kCookieBig, "B", "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure, 87,
      CookieSourceType::kUnknown));
  EXPECT_TRUE(CanonicalCookie::FromStorage(
      "A", kCookieBig, "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure, 87,
      CookieSourceType::kUnknown));

  histograms.ExpectBucketCount(kFromStorageWithValidLengthHistogram, kInValid,
                               2);
  histograms.ExpectBucketCount(kFromStorageWithValidLengthHistogram, kValid, 1);
}

TEST(CanonicalCookieTest, TestGetAndAdjustPortForTrustworthyUrls) {
  // GetAndAdjustPortForTrustworthyUrls assumes that http/ws schemes have a port
  // of 80 and https/wss schemes have a port of 443 by default. While extremely
  // unlikely to change, we may as well confirm that before we continue.
  std::string_view http_scheme(url::kHttpScheme);
  std::string_view https_scheme(url::kHttpsScheme);
  std::string_view ws_scheme(url::kWsScheme);
  std::string_view wss_scheme(url::kWssScheme);

  EXPECT_EQ(url::DefaultPortForScheme(http_scheme), 80);
  EXPECT_EQ(url::DefaultPortForScheme(ws_scheme), 80);
  EXPECT_EQ(url::DefaultPortForScheme(https_scheme), 443);
  EXPECT_EQ(url::DefaultPortForScheme(wss_scheme), 443);

  const GURL secure_http = GURL("https://example.com");
  const GURL secure_http_custom_port = GURL("https://example.com:123");
  const GURL secure_ws = GURL("wss://example.com");
  const GURL secure_ws_custom_port = GURL("wss://example.com:123");

  // Secure schemes shouldn't return a different port.
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(secure_http, true),
      443);
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(secure_http, false),
      443);
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(secure_ws, true),
      443);
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(secure_ws, false),
      443);
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                secure_http_custom_port, true),
            123);
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                secure_http_custom_port, false),
            123);
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                secure_ws_custom_port, true),
            123);
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                secure_ws_custom_port, false),
            123);

  const GURL insecure_http = GURL("http://example.com");
  const GURL insecure_ws = GURL("ws://example.com");

  // Insecure schemes with their default port should return 443 only when
  // trustworthy.
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(insecure_http, false),
      80);
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(insecure_ws, false),
      80);
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(insecure_http, true),
      443);
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(insecure_ws, true),
      443);

  const GURL insecure_http_custom_port = GURL("http://example.com:123");
  const GURL insecure_ws_custom_port = GURL("ws://example.com:123");

  // Insecure schemes with a non-default port should never return a different
  // port.
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                insecure_http_custom_port, false),
            123);
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                insecure_ws_custom_port, false),
            123);
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                insecure_http_custom_port, true),
            123);
  EXPECT_EQ(CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(
                insecure_ws_custom_port, true),
            123);

  // File schemes don't have a port component.
  const GURL insecure_file = GURL("file://example.com");
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(insecure_file, false),
      url::PORT_UNSPECIFIED);
  EXPECT_EQ(
      CanonicalCookie::GetAndAdjustPortForTrustworthyUrls(insecure_file, true),
      url::PORT_UNSPECIFIED);
}

TEST(CanonicalCookieTest, TestHasHiddenPrefixName) {
  const struct {
    const char* value;
    bool result;
  } kTestCases[] = {
      {"", false},
      {"  ", false},
      {"foobar=", false},
      {"foo=bar", false},
      {" \t ", false},
      {"\t", false},
      {"__Secure=-", false},
      {"__Secure=-abc", false},
      {"__Secur=e-abc", false},
      {"__Secureabc", false},
      {"__Host=-", false},
      {"__Host=-abc", false},
      {"__Hos=t-abc", false},
      {"_Host", false},
      {"a__Host-abc=123", false},
      {"a__Secure-abc=123", false},
      {"__Secure-abc", true},
      {"__Host-abc", true},
      {"   __Secure-abc", true},
      {"\t__Host-", true},
      {"__Host-=", true},
      {"__Host-=123", true},
      {"__host-=123", true},
      {"__HOST-=123", true},
      {"__HoSt-=123", true},
      {"__Host-abc=", true},
      {"__Host-abc=123", true},
      {" __Host-abc=123", true},
      {"    __Host-abc=", true},
      {"\t\t\t\t\t__Host-abc=123", true},
      {"\t __Host-abc=", true},
      {"__Secure-=", true},
      {"__Secure-=123", true},
      {"__secure-=123", true},
      {"__SECURE-=123", true},
      {"__SeCuRe-=123", true},
      {"__Secure-abc=", true},
      {"__Secure-abc=123", true},
      {" __Secure-abc=123", true},
      {"    __Secure-abc=", true},
      {"\t\t\t\t\t__Secure-abc=123", true},
      {"\t __Secure-abc=", true},
      {"__Secure-abc=123=d=4=fg=", true},
  };

  for (auto test_case : kTestCases) {
    EXPECT_EQ(CanonicalCookie::HasHiddenPrefixName(test_case.value),
              test_case.result)
        << test_case.value << " failed check";
  }
}

TEST(CanonicalCookieTest, TestDoubleUnderscorePrefixHistogram) {
  base::HistogramTester histograms;
  const char kDoubleUnderscorePrefixHistogram[] =
      "Cookie.DoubleUnderscorePrefixedName";

  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "__Secure-abc=123; Secure",
                                    base::Time::Now() /* Creation time */);

  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "__Host-abc=123; Secure; Path=/",
                                    base::Time::Now() /* Creation time */);

  // Cookie prefixes shouldn't count.
  histograms.ExpectTotalCount(kDoubleUnderscorePrefixHistogram, 2);
  histograms.ExpectBucketCount(kDoubleUnderscorePrefixHistogram, false, 2);

  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "f__oo=bar",
                                    base::Time::Now() /* Creation time */);

  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "foo=__bar",
                                    base::Time::Now() /* Creation time */);

  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "_foo=bar",
                                    base::Time::Now() /* Creation time */);

  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "_f_oo=bar",
                                    base::Time::Now() /* Creation time */);

  // These should be counted.
  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "__foo=bar",
                                    base::Time::Now() /* Creation time */);

  CanonicalCookie::CreateForTesting(GURL("https://www.example.com/"),
                                    "___foo=bar",
                                    base::Time::Now() /* Creation time */);

  histograms.ExpectTotalCount(kDoubleUnderscorePrefixHistogram, 8);
  histograms.ExpectBucketCount(kDoubleUnderscorePrefixHistogram, false, 6);
  histograms.ExpectBucketCount(kDoubleUnderscorePrefixHistogram, true, 2);
}

TEST(CanonicalCookieTest, IsThirdPartyPartitioned) {
  // Partitioned cookie in 3p context.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "x.y", "/foo/bar", base::Time(), base::Time(),
                  base::Time(), base::Time(), /*secure=*/true,
                  /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                  COOKIE_PRIORITY_LOW,
                  CookiePartitionKey::FromURLForTesting(
                      GURL("https://toplevelsite.com")))
                  ->IsThirdPartyPartitioned());

  // Partitioned cookie in 1p context.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "x.y", "/foo/bar", base::Time(), base::Time(),
                   base::Time(), base::Time(), /*secure=*/true,
                   /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                   COOKIE_PRIORITY_LOW,
                   CookiePartitionKey::FromURLForTesting(GURL("https://x.y")))
                   ->IsThirdPartyPartitioned());

  // Nonced-partitioned cookie should always be 3p context.
  auto partition_key_with_nonce =
      std::make_optional(CookiePartitionKey::FromURLForTesting(
          GURL("https://x.y"), CookiePartitionKey::AncestorChainBit::kCrossSite,
          base::UnguessableToken::Create()));
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "x.y", "/foo/bar", base::Time(), base::Time(),
                  base::Time(), base::Time(), /*secure=*/true,
                  /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                  COOKIE_PRIORITY_LOW, partition_key_with_nonce)
                  ->IsThirdPartyPartitioned());

  // Unpartitioned cookie.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "x.y", "/foo/bar", base::Time(), base::Time(),
                   base::Time(), base::Time(), /*secure=*/false,
                   /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
                   COOKIE_PRIORITY_LOW)
                   ->IsThirdPartyPartitioned());
}

// Tests that IsSecure returns true if a cookie's secure attribute is true
// OR if its source_scheme is kSecure when scheme binding is enabled.
TEST(CanonicalCookieTest, IsSecure) {
  auto create_cookie = [](bool secure_attribute,
                          CookieSourceScheme source_scheme) {
    return CanonicalCookie::CreateUnsafeCookieForTesting(
        "A", "B", "example.com", "/", base::Time(), base::Time(), base::Time(),
        base::Time(), secure_attribute, /*httponly=*/false,
        CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW,
        /*partition_key=*/std::nullopt, source_scheme, /*source_port=*/1234);
  };

  auto insecure_attr_unset_scheme =
      create_cookie(/*secure_attribute=*/false, CookieSourceScheme::kUnset);
  auto insecure_attr_insecure_scheme =
      create_cookie(/*secure_attribute=*/false, CookieSourceScheme::kNonSecure);
  auto insecure_attr_secure_scheme =
      create_cookie(/*secure_attribute=*/false, CookieSourceScheme::kSecure);

  auto secure_attr_unset_scheme =
      create_cookie(/*secure_attribute=*/true, CookieSourceScheme::kUnset);
  auto secure_attr_insecure_scheme =
      create_cookie(/*secure_attribute=*/true, CookieSourceScheme::kNonSecure);
  auto secure_attr_secure_scheme =
      create_cookie(/*secure_attribute=*/true, CookieSourceScheme::kSecure);

  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(features::kEnableSchemeBoundCookies);

    // When scheme binding is disabled only the secure attribute causes a return
    // value of true.

    EXPECT_FALSE(insecure_attr_unset_scheme->IsSecure());
    EXPECT_FALSE(insecure_attr_insecure_scheme->IsSecure());
    EXPECT_FALSE(insecure_attr_secure_scheme->IsSecure());

    EXPECT_TRUE(secure_attr_unset_scheme->IsSecure());
    EXPECT_TRUE(secure_attr_insecure_scheme->IsSecure());
    EXPECT_TRUE(secure_attr_secure_scheme->IsSecure());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(features::kEnableSchemeBoundCookies);

    // When scheme binding is enabled a kSecure scheme also causes a returns
    // value of true.

    EXPECT_FALSE(insecure_attr_unset_scheme->IsSecure());
    EXPECT_FALSE(insecure_attr_insecure_scheme->IsSecure());
    EXPECT_TRUE(insecure_attr_secure_scheme->IsSecure());

    EXPECT_TRUE(secure_attr_unset_scheme->IsSecure());
    EXPECT_TRUE(secure_attr_insecure_scheme->IsSecure());
    EXPECT_TRUE(secure_attr_secure_scheme->IsSecure());
  }
}

}  // namespace net

"""


```