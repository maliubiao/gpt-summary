Response:
My thinking process to answer the request went through these steps:

1. **Understanding the Core Task:** The main goal is to analyze a specific part of a Chromium source code file (`canonical_cookie_unittest.cc`) and explain its functionality, focusing on its relation to JavaScript, potential user errors, debugging, and its role within the larger file.

2. **Deconstructing the Request:** I broke down the request into key components:
    * **Functionality:** What does this specific code snippet do?
    * **JavaScript Relation:** How does this code relate to how cookies work in a web browser from a JavaScript perspective?
    * **Logical Reasoning (Input/Output):** What are the expected outcomes for different inputs?
    * **User/Programming Errors:** What mistakes can users or developers make related to this functionality?
    * **User Operation to Reach Here:** What steps would a user take to trigger this code?
    * **Debugging Clues:** How does this help in debugging cookie-related issues?
    * **Part 8 of 9 Summary:** What is the specific function of this section within the larger unit test file?

3. **Analyzing the Code Snippet:** I carefully read the provided code, looking for patterns and key elements. I noticed:
    * **`TEST(CanonicalCookieTest, ...)`:** This indicates the code is part of a unit test.
    * **`IsSetPermittedInContext`:** This function seems central to the tests, suggesting it checks if a cookie can be set in a given context.
    * **`CookieOptions`:**  This class likely represents various settings related to cookies (SameSite, Secure, etc.).
    * **`CookieAccessParams`:** This class likely defines the context in which a cookie is being accessed (semantics, trustworthiness).
    * **`MatchesCookieAccessResult`:** This appears to be a matcher used in the unit tests to verify the expected outcome of `IsSetPermittedInContext`.
    * **`CookieInclusionStatus`:** This enum/class represents the status of cookie inclusion (included, excluded, with reasons).
    * **Different `CookieSameSite` values:** The tests cover `NO_RESTRICTION`, `LAX_MODE`, `STRICT_MODE`, and `UNSPECIFIED`, indicating this section focuses on SameSite behavior.
    * **`kCookieableSchemes`:** This constant likely defines the valid schemes for which cookies can be set.
    * **`ScopedFeatureList`:** This is used to enable/disable features like `kSchemefulSameSite`, indicating tests for different configurations.

4. **Connecting to JavaScript:**  I considered how the tested logic manifests in a browser from a JavaScript developer's viewpoint:
    * The `document.cookie` API is the primary way JavaScript interacts with cookies.
    * Setting and accessing cookies via `document.cookie` is subject to the rules being tested here (Secure, HttpOnly, SameSite).

5. **Formulating Input/Output Examples:** Based on the code, I constructed scenarios to illustrate the logic:
    * Secure cookie on an insecure page.
    * HttpOnly cookie accessed by JavaScript.
    * SameSite cookies in different cross-site contexts.

6. **Identifying User/Programming Errors:**  I thought about common mistakes developers make with cookies:
    * Not setting the `Secure` flag for sensitive cookies.
    * Relying on JavaScript to access `HttpOnly` cookies.
    * Misunderstanding SameSite behavior and its impact on cross-site requests.

7. **Tracing User Operations:** I outlined the steps a user might take that would involve cookie setting and accessing, leading to the execution of the underlying code.

8. **Defining Debugging Value:** I explained how the tests in this file help debug cookie-related issues by verifying the correctness of the cookie setting logic under different conditions.

9. **Summarizing the Section's Function:**  I concluded that this specific part focuses on testing the `IsSetPermittedInContext` method, particularly concerning the `SameSite` attribute and its interaction with different browser configurations and access semantics. It builds upon earlier tests by focusing on `SameSite`.

10. **Structuring the Answer:** I organized the information into the requested categories, providing clear explanations and examples. I paid attention to the "Part 8 of 9" instruction and ensured the summary reflected the section's contribution to the overall test file. I used clear headings and bullet points for readability.

11. **Refinement and Language:**  I reviewed my answer for clarity, accuracy, and completeness, ensuring the language was precise and easy to understand. I tried to avoid jargon where possible or explain it briefly.

Essentially, I approached this as understanding a unit test – what is being tested, what are the different test cases, and what scenarios are being covered. Then, I connected that understanding back to the user and developer experience with cookies in a web browser.
好的，让我们来分析一下 `net/cookies/canonical_cookie_unittest.cc` 文件的这部分代码（第 8 部分）。

**功能归纳：**

这部分代码的主要功能是**测试 `CanonicalCookie::IsSetPermittedInContext()` 方法在各种 `SameSite` 策略下的行为**。它通过创建不同 `SameSite` 属性的 Cookie，并在不同的上下文 (`CookieOptions`) 中调用 `IsSetPermittedInContext()`，来验证 Cookie 是否允许被设置。

具体来说，它测试了以下几种 `SameSite` 策略：

* **`NO_RESTRICTION` (无限制):**  测试在跨站、同站 Lax 和同站 Strict 上下文中是否允许设置。
* **`LAX_MODE` (宽松模式):** 测试在跨站、同站 Lax 和同站 Strict 上下文中是否允许设置，并测试了 `SchemefulSameSite` 特性启用和禁用时的警告情况。
* **`STRICT_MODE` (严格模式):** 测试在跨站、同站 Lax 和同站 Strict 上下文中是否允许设置，并测试了 `SchemefulSameSite` 特性启用和禁用时的警告和排除情况，以及不同 `CookieAccessSemantics` 的影响。
* **`UNSPECIFIED` (未指定):** 测试在不同 `CookieAccessSemantics` 下，在跨站、同站 Lax 和同站 Strict 上下文中的行为，验证未指定的 `SameSite` 如何被解释（通常被视为 Lax）。

此外，代码还测试了：

* **`IsSetPermittedInContext` 方法传递已有的 `CookieAccessResult` 对象，验证警告信息是否能被正确链式传递。** 例如，当尝试设置一个路径属性过长的 Cookie 时，会产生警告。
* **`IsSetPermittedInContext` 方法返回的 `CookieEffectiveSameSite` 值是否符合预期。** 这表示 Cookie 的实际生效的 `SameSite` 策略，特别是对于 `UNSPECIFIED` 的情况。
* **在安全上下文（HTTPS）和非安全上下文（HTTP）下设置 Cookie 的权限。**
* **`delegate_treats_url_as_trustworthy` 参数对 Cookie 设置权限的影响。**

**与 JavaScript 的关系：**

这段代码直接测试了浏览器底层关于 Cookie 设置的逻辑，而这些逻辑直接影响 JavaScript 中 `document.cookie` API 的行为。

**举例说明：**

假设 JavaScript 代码尝试在一个跨站请求中设置一个 `SameSite=Lax` 的 Cookie：

```javascript
// 位于 https://example.com 的页面
fetch('https://another-example.com/api', {credentials: 'include'})
.then(() => {
  document.cookie = 'myCookie=value; SameSite=Lax';
});
```

这段代码最终会触发 Chromium 网络栈中类似 `CanonicalCookie::IsSetPermittedInContext()` 的逻辑。根据本部分测试的代码，我们可以推断：

* **假设输入：**
    * 尝试设置的 Cookie 的 `SameSite` 属性为 `Lax`。
    * 当前上下文是一个跨站请求（源站为 `https://example.com`，目标站为 `https://another-example.com`）。
    * `CookieAccessSemantics` 可能为 `UNKNOWN` 或 `NONLEGACY`（取决于浏览器的默认设置）。
* **预期输出：**
    * `IsSetPermittedInContext()` 将返回一个表示不允许设置的状态（`CookieInclusionStatus::EXCLUDE_SAMESITE_LAX`），因为跨站请求通常不允许设置 `SameSite=Lax` 的 Cookie。
    * 如果 `CookieAccessSemantics` 为 `LEGACY`，则可能允许设置。

**逻辑推理：**

代码中针对 `SameSite=Strict` 的测试用例：

```c++
EXPECT_THAT(
    cookie_same_site_strict->IsSetPermittedInContext(
        url, context_cross_site,
        CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                           false /* delegate_treats_url_as_trustworthy */
                           ),
        kCookieableSchemes),
    MatchesCookieAccessResult(
        CookieInclusionStatus::MakeFromReasonsForTesting(
            {CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT}),
        _, _, true));
```

* **假设输入：**
    * `cookie_same_site_strict` 是一个 `SameSite` 属性为 `STRICT_MODE` 的 Cookie。
    * `url` 是 Cookie 的域 (`http://www.example.com/test`)。
    * `context_cross_site` 表示当前的上下文是跨站的。
    * `CookieAccessParams` 使用 `UNKNOWN` 的语义。
* **预期输出：**
    * `IsSetPermittedInContext()` 将返回一个 `CookieAccessResult`，其中包含一个排除状态 `CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT`，表示由于 `SameSite=Strict` 的限制，该 Cookie 不允许在跨站上下文中设置。

**用户或编程常见的使用错误：**

* **用户错误：** 用户不太可能直接触发这个单元测试。但是，用户在浏览网页时，浏览器会根据这些规则来处理 Cookie。如果用户在一个不允许设置 `SameSite=Strict` Cookie 的跨站场景中期望设置 Cookie，就会遇到问题，例如某些功能无法正常工作。
* **编程错误：**
    * **开发者未能正确理解 `SameSite` 属性的作用。**  例如，开发者可能错误地认为设置了 `SameSite=Strict` 的 Cookie 可以在任何跨站请求中被发送，导致依赖该 Cookie 的功能在某些场景下失效。
    * **开发者在非 HTTPS 页面上设置了 `Secure` 属性的 Cookie。** 这部分代码虽然没有直接展示，但在其他部分的测试中会覆盖到，这会导致 Cookie 设置失败。
    * **JavaScript 尝试访问带有 `HttpOnly` 标志的 Cookie。** 这部分代码测试了 `IsSetPermittedInContext`，对于获取 Cookie 的权限也有类似的检查。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户访问一个网页 (例如 `https://example.com`)。**
2. **该网页中的 JavaScript 代码尝试通过 `document.cookie = 'mycookie=value; SameSite=Strict'` 设置一个 Cookie。**
3. **或者，用户访问的网页向另一个网站 (`https://another.example.com`) 发起请求，并且服务器尝试设置带有 `SameSite` 属性的 Cookie。**
4. **浏览器内核在处理 Cookie 设置请求时，会调用类似于 `CanonicalCookie::IsSetPermittedInContext()` 的函数。**
5. **该函数会根据 Cookie 的属性（如 `SameSite`、`Secure`、`HttpOnly`）、当前的上下文（例如请求的来源和目标站点、是否是安全上下文）以及其他策略进行检查。**
6. **如果 Cookie 不允许被设置，该函数会返回相应的状态，并且浏览器可能会阻止 Cookie 的设置或发出警告信息。**

作为调试线索，当开发者遇到 Cookie 设置或发送方面的问题时，可以：

* **查看浏览器的开发者工具 -> Application -> Cookies，检查 Cookie 的属性 (SameSite, Secure, HttpOnly)。**
* **查看 Network 面板，检查请求和响应头中的 `Set-Cookie` 和 `Cookie` 字段，了解 Cookie 的设置和发送情况。**
* **在开发者工具的 Console 中查看是否有关于 Cookie 的警告或错误信息。**
* **使用 Chrome 的 `chrome://net-internals/#cookies` 工具查看更详细的 Cookie 信息和事件。**
* **仔细检查代码中设置 Cookie 的逻辑，确保 `SameSite`、`Secure` 等属性设置符合预期。**

**第 8 部分的功能总结：**

总而言之，`net/cookies/canonical_cookie_unittest.cc` 文件的这部分（第 8 部分）专注于 **彻底测试 `CanonicalCookie::IsSetPermittedInContext()` 方法在各种 `SameSite` 策略和上下文条件下的正确性**。它模拟了各种场景，验证了浏览器底层 Cookie 设置逻辑的预期行为，这对于确保 Web 安全性和隐私至关重要。通过这些测试，可以确保浏览器能够正确地执行 `SameSite` 策略，防止某些跨站请求伪造 (CSRF) 攻击和其他安全风险。

Prompt: 
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共9部分，请归纳一下它的功能

"""
okieAccessResult(
          CookieInclusionStatus::MakeFromReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}),
          _, _, false));
  EXPECT_THAT(
      cookie_scriptable->IsSetPermittedInContext(
          url, context_network,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_scriptable->IsSetPermittedInContext(
          url, context_script,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));

  EXPECT_THAT(
      cookie_httponly->IsSetPermittedInContext(
          url, context_network,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_httponly->IsSetPermittedInContext(
          url, context_script,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          CookieInclusionStatus::MakeFromReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_HTTP_ONLY}),
          _, _, true));

  EXPECT_THAT(
      cookie_scriptable->IsSetPermittedInContext(
          GURL("https://www.badexample.com/test"), context_script,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          CookieInclusionStatus::MakeFromReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_DOMAIN_MISMATCH}),
          _, _, true));

  CookieOptions context_cross_site;
  CookieOptions context_same_site_lax;
  context_same_site_lax.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX));
  CookieOptions context_same_site_strict;
  context_same_site_strict.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT));

  CookieOptions context_same_site_strict_to_lax;
  context_same_site_strict_to_lax.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX));

  CookieOptions context_same_site_strict_to_cross;
  context_same_site_strict_to_cross.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
          CookieOptions::SameSiteCookieContext::ContextType::CROSS_SITE));

  CookieOptions context_same_site_lax_to_cross;
  context_same_site_lax_to_cross.set_same_site_cookie_context(
      CookieOptions::SameSiteCookieContext(
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX,
          CookieOptions::SameSiteCookieContext::ContextType::CROSS_SITE));

  {
    auto cookie_same_site_unrestricted =
        CanonicalCookie::CreateUnsafeCookieForTesting(
            "A", "2", "www.example.com", "/test", current_time, base::Time(),
            base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
            CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT);

    EXPECT_THAT(
        cookie_same_site_unrestricted->IsSetPermittedInContext(
            url, context_cross_site,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(IsInclude(), _, _, true));
    EXPECT_THAT(
        cookie_same_site_unrestricted->IsSetPermittedInContext(
            url, context_same_site_lax,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(IsInclude(), _, _, true));
    EXPECT_THAT(
        cookie_same_site_unrestricted->IsSetPermittedInContext(
            url, context_same_site_strict,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(IsInclude(), _, _, true));

    {
      // Schemeful Same-Site disabled.
      base::test::ScopedFeatureList feature_list;
      feature_list.InitAndDisableFeature(features::kSchemefulSameSite);

      EXPECT_THAT(
          cookie_same_site_unrestricted->IsSetPermittedInContext(
              url, context_same_site_strict_to_lax,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_unrestricted->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_unrestricted->IsSetPermittedInContext(
              url, context_same_site_lax_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
    }
    {
      // Schemeful Same-Site enabled.
      base::test::ScopedFeatureList feature_list;
      feature_list.InitAndEnableFeature(features::kSchemefulSameSite);

      EXPECT_THAT(
          cookie_same_site_unrestricted->IsSetPermittedInContext(
              url, context_same_site_strict_to_lax,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_unrestricted->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_unrestricted->IsSetPermittedInContext(
              url, context_same_site_lax_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
    }
  }

  {
    auto cookie_same_site_lax = CanonicalCookie::CreateUnsafeCookieForTesting(
        "A", "2", "www.example.com", "/test", current_time, base::Time(),
        base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
        CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT);

    EXPECT_THAT(
        cookie_same_site_lax->IsSetPermittedInContext(
            url, context_cross_site,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(
            CookieInclusionStatus::MakeFromReasonsForTesting(
                {CookieInclusionStatus::EXCLUDE_SAMESITE_LAX}),
            _, _, true));
    EXPECT_THAT(
        cookie_same_site_lax->IsSetPermittedInContext(
            url, context_same_site_lax,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(IsInclude(), _, _, true));
    EXPECT_THAT(
        cookie_same_site_lax->IsSetPermittedInContext(
            url, context_same_site_strict,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(IsInclude(), _, _, true));

    {
      // Schemeful Same-Site disabled.
      base::test::ScopedFeatureList feature_list;
      feature_list.InitAndDisableFeature(features::kSchemefulSameSite);

      EXPECT_THAT(
          cookie_same_site_lax->IsSetPermittedInContext(
              url, context_same_site_strict_to_lax,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_lax->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(),
                    HasWarningReason(
                        CookieInclusionStatus::
                            WARN_STRICT_CROSS_DOWNGRADE_LAX_SAMESITE)),
              _, _, true));
      EXPECT_THAT(
          cookie_same_site_lax->IsSetPermittedInContext(
              url, context_same_site_lax_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(
                  IsInclude(),
                  HasWarningReason(CookieInclusionStatus::
                                       WARN_LAX_CROSS_DOWNGRADE_LAX_SAMESITE)),
              _, _, true));
    }
    {
      // Schemeful Same-Site enabled.
      base::test::ScopedFeatureList feature_list;
      feature_list.InitAndEnableFeature(features::kSchemefulSameSite);

      EXPECT_THAT(
          cookie_same_site_lax->IsSetPermittedInContext(
              url, context_same_site_strict_to_lax,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_lax->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(Not(IsInclude()),
                    HasWarningReason(
                        CookieInclusionStatus::
                            WARN_STRICT_CROSS_DOWNGRADE_LAX_SAMESITE),
                    HasExclusionReason(
                        CookieInclusionStatus::EXCLUDE_SAMESITE_LAX)),
              _, _, true));
      EXPECT_THAT(
          cookie_same_site_lax->IsSetPermittedInContext(
              url, context_same_site_lax_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(Not(IsInclude()),
                    HasWarningReason(CookieInclusionStatus::
                                         WARN_LAX_CROSS_DOWNGRADE_LAX_SAMESITE),
                    HasExclusionReason(
                        CookieInclusionStatus::EXCLUDE_SAMESITE_LAX)),
              _, _, true));
    }
  }

  {
    auto cookie_same_site_strict =
        CanonicalCookie::CreateUnsafeCookieForTesting(
            "A", "2", "www.example.com", "/test", current_time, base::Time(),
            base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
            CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT);

    // TODO(morlovich): Do compatibility testing on whether set of strict in lax
    // context really should be accepted.
    EXPECT_THAT(
        cookie_same_site_strict->IsSetPermittedInContext(
            url, context_cross_site,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(
            CookieInclusionStatus::MakeFromReasonsForTesting(
                {CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT}),
            _, _, true));
    EXPECT_THAT(
        cookie_same_site_strict->IsSetPermittedInContext(
            url, context_same_site_lax,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(IsInclude(), _, _, true));
    EXPECT_THAT(
        cookie_same_site_strict->IsSetPermittedInContext(
            url, context_same_site_strict,
            CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                               false /* delegate_treats_url_as_trustworthy */
                               ),
            kCookieableSchemes),
        MatchesCookieAccessResult(IsInclude(), _, _, true));

    {
      // Schemeful Same-Site disabled.
      base::test::ScopedFeatureList feature_list;
      feature_list.InitAndDisableFeature(features::kSchemefulSameSite);

      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_strict_to_lax,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(),
                    HasWarningReason(
                        CookieInclusionStatus::
                            WARN_STRICT_CROSS_DOWNGRADE_STRICT_SAMESITE)),
              _, _, true));
      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_lax_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(),
                    HasWarningReason(
                        CookieInclusionStatus::
                            WARN_LAX_CROSS_DOWNGRADE_STRICT_SAMESITE)),
              _, _, true));
    }
    {
      // Schemeful Same-Site enabled.
      base::test::ScopedFeatureList feature_list;
      feature_list.InitAndEnableFeature(features::kSchemefulSameSite);

      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_strict_to_lax,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(IsInclude(), Not(HasSchemefulDowngradeWarning())), _, _,
              true));
      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(Not(IsInclude()),
                    HasWarningReason(
                        CookieInclusionStatus::
                            WARN_STRICT_CROSS_DOWNGRADE_STRICT_SAMESITE),
                    HasExclusionReason(
                        CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT)),
              _, _, true));
      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_lax_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(
              AllOf(Not(IsInclude()),
                    HasWarningReason(
                        CookieInclusionStatus::
                            WARN_LAX_CROSS_DOWNGRADE_STRICT_SAMESITE),
                    HasExclusionReason(
                        CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT)),
              _, _, true));
    }

    // Even with Schemeful Same-Site enabled, cookies semantics could change the
    // inclusion.
    {
      base::test::ScopedFeatureList feature_list;
      feature_list.InitAndEnableFeature(features::kSchemefulSameSite);

      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(Not(IsInclude()), _, _, true));
      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::NONLEGACY,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(Not(IsInclude()), _, _, true));
      // LEGACY semantics should allow cookies which Schemeful Same-Site would
      // normally block.
      EXPECT_THAT(
          cookie_same_site_strict->IsSetPermittedInContext(
              url, context_same_site_strict_to_cross,
              CookieAccessParams(CookieAccessSemantics::LEGACY,
                                 false /* delegate_treats_url_as_trustworthy */
                                 ),
              kCookieableSchemes),
          MatchesCookieAccessResult(IsInclude(), _, _, true));
    }
  }

  // Behavior of UNSPECIFIED depends on CookieAccessSemantics.
  auto cookie_same_site_unspecified =
      CanonicalCookie::CreateUnsafeCookieForTesting(
          "A", "2", "www.example.com", "/test", current_time, base::Time(),
          base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
          CookieSameSite::UNSPECIFIED, COOKIE_PRIORITY_DEFAULT);

  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_cross_site,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          HasExactlyExclusionReasonsForTesting(
              std::vector<CookieInclusionStatus::ExclusionReason>(
                  {CookieInclusionStatus::
                       EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX})),
          _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_same_site_lax,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_same_site_strict,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_cross_site,
          CookieAccessParams(CookieAccessSemantics::LEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_same_site_lax,
          CookieAccessParams(CookieAccessSemantics::LEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_same_site_strict,
          CookieAccessParams(CookieAccessSemantics::LEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_cross_site,
          CookieAccessParams(CookieAccessSemantics::NONLEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          HasExactlyExclusionReasonsForTesting(
              std::vector<CookieInclusionStatus::ExclusionReason>(
                  {CookieInclusionStatus::
                       EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX})),
          _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_same_site_lax,
          CookieAccessParams(CookieAccessSemantics::NONLEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));
  EXPECT_THAT(
      cookie_same_site_unspecified->IsSetPermittedInContext(
          url, context_same_site_strict,
          CookieAccessParams(CookieAccessSemantics::NONLEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(IsInclude(), _, _, true));

  // Test IsSetPermittedInContext successfully chains warnings by passing
  // in a CookieAccessResult and expecting the result to have a
  // WARN_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE
  CookieInclusionStatus status;
  std::string long_path(ParsedCookie::kMaxCookieAttributeValueSize, 'a');

  std::unique_ptr<CanonicalCookie> cookie_with_long_path =
      CanonicalCookie::Create(url, "A=B; Path=/" + long_path, current_time,
                              std::nullopt, std::nullopt,
                              CookieSourceType::kUnknown, &status);
  CookieAccessResult cookie_access_result(status);
  CookieOptions cookie_with_long_path_options;
  EXPECT_THAT(
      cookie_with_long_path->IsSetPermittedInContext(
          url, cookie_with_long_path_options,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes, cookie_access_result),
      MatchesCookieAccessResult(
          HasWarningReason(
              CookieInclusionStatus::WARN_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE),
          _, _, _));
}

TEST(CanonicalCookieTest, IsSetPermittedEffectiveSameSite) {
  GURL url("http://www.example.com/test");
  base::Time current_time = base::Time::Now();
  CookieOptions options;

  // Test IsSetPermitted CookieEffectiveSameSite for
  // CanonicalCookie with CookieSameSite::NO_RESTRICTION.
  auto cookie_no_restriction = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT);

  EXPECT_THAT(
      cookie_no_restriction->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(_, CookieEffectiveSameSite::NO_RESTRICTION, _,
                                false));

  // Test IsSetPermitted CookieEffectiveSameSite for
  // CanonicalCookie with CookieSameSite::LAX_MODE.
  auto cookie_lax = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT);

  EXPECT_THAT(
      cookie_lax->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(_, CookieEffectiveSameSite::LAX_MODE, _,
                                false));

  // Test IsSetPermitted CookieEffectiveSameSite for
  // CanonicalCookie with CookieSameSite::STRICT_MODE.
  auto cookie_strict = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
      CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT);

  EXPECT_THAT(
      cookie_strict->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(_, CookieEffectiveSameSite::STRICT_MODE, _,
                                false));

  // Test IsSetPermitted CookieEffectiveSameSite for
  // CanonicalCookie with CookieSameSite::UNSPECIFIED.
  base::Time creation_time = base::Time::Now() - (kLaxAllowUnsafeMaxAge * 4);
  auto cookie_old_unspecified = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", creation_time, base::Time(),
      base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
      CookieSameSite::UNSPECIFIED, COOKIE_PRIORITY_DEFAULT);
  auto cookie_unspecified = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
      CookieSameSite::UNSPECIFIED, COOKIE_PRIORITY_DEFAULT);

  EXPECT_THAT(
      cookie_old_unspecified->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(_, CookieEffectiveSameSite::LAX_MODE, _,
                                false));

  EXPECT_THAT(
      cookie_unspecified->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          _, CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE, _, false));

  EXPECT_THAT(
      cookie_unspecified->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::NONLEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          _, CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE, _, false));

  EXPECT_THAT(
      cookie_unspecified->IsSetPermittedInContext(
          url, options,
          CookieAccessParams(CookieAccessSemantics::LEGACY,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(_, CookieEffectiveSameSite::NO_RESTRICTION, _,
                                false));
}

TEST(CanonicalCookieTest, IsSetPermitted_AllowedToAccessSecureCookies) {
  GURL url("https://www.example.com/test");
  GURL insecure_url("http://www.example.com/test");
  GURL localhost_url("http://localhost/test");
  base::Time current_time = base::Time::Now();
  CookieOptions options;

  for (bool secure : {false, true}) {
    for (CookieSameSite same_site : {
             CookieSameSite::UNSPECIFIED,
             CookieSameSite::NO_RESTRICTION,
             CookieSameSite::LAX_MODE,
         }) {
      auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
          "A", "2", "www.example.com", "/test", current_time, base::Time(),
          base::Time(), base::Time(), secure, false /*httponly*/, same_site,
          COOKIE_PRIORITY_DEFAULT);

      for (bool delegate_treats_url_as_trustworthy : {false, true}) {
        for (CookieAccessSemantics access_semantics : {
                 CookieAccessSemantics::UNKNOWN,
                 CookieAccessSemantics::LEGACY,
                 CookieAccessSemantics::NONLEGACY,
             }) {
          EXPECT_THAT(
              cookie->IsSetPermittedInContext(
                  url, options,
                  CookieAccessParams(access_semantics,
                                     delegate_treats_url_as_trustworthy),
                  kCookieableSchemes),
              Mat
"""


```