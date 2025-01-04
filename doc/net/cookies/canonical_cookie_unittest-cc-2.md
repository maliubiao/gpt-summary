Response:
The user wants a summary of the functionality of the provided C++ code snippet from `canonical_cookie_unittest.cc`. They are particularly interested in:

1. **General Functionality:** What does this code test?
2. **Relationship to JavaScript:** Does this code interact with or relate to JavaScript functionality?
3. **Logic and Examples:** Can I provide examples of input and output based on the code's logic?
4. **Common Errors:** Are there common user or programming errors related to this code?
5. **User Journey (Debugging):** How might a user end up interacting with this code, providing debugging context?
6. **Part of a Larger Whole:** This is part 3 of 9, so what is the overall function this part contributes to?

Let's break down the code:

* **`IsEquivalent` Test:** Checks if two `CanonicalCookie` objects are considered equivalent based on specific criteria (domain, scheme, port).
* **`IsDomainMatch` Test:** Verifies if a cookie's domain matches a given hostname. It tests different domain specifications (host-only, with/without leading dot).
* **`IsOnPath` Test:** Checks if a given path is within the cookie's path.
* **`GetEffectiveSameSite` Test:**  Determines the effective SameSite policy of a cookie based on its declared `SameSite` attribute and access semantics. It considers factors like recency of creation.
* **`IncludeForRequestURL` Test:**  Simulates the process of deciding whether a cookie should be included in a request to a specific URL, considering various factors like domain, path, security, `HttpOnly` attribute, and SameSite policy.

**Plan:**

1. **Summarize the overall goal:**  This unit test file tests the functionality of the `CanonicalCookie` class.
2. **Explain each test case:**  Briefly describe what each `TEST` block is verifying.
3. **Address JavaScript interaction:** Discuss how cookies are accessed and manipulated by JavaScript, and how these tests ensure the C++ implementation behaves correctly.
4. **Provide input/output examples:**  For key tests like `IsDomainMatch` and `IncludeForRequestURL`, give concrete examples.
5. **Identify common errors:**  Highlight mistakes users might make regarding cookie attributes.
6. **Illustrate a debugging scenario:** Describe a user action that could lead to investigating cookie behavior.
7. **Contextualize within the larger file:**  Explain how these tests contribute to the overall robustness of the cookie handling in Chromium.
这是 `net/cookies/canonical_cookie_unittest.cc` 文件的第三部分，它主要专注于测试 `CanonicalCookie` 类的各种方法，以确保其在网络栈中正确处理和比较 Cookie。

**功能归纳：**

这部分代码的主要功能是**测试 `CanonicalCookie` 类的不同方法，用于判断 Cookie 的属性和适用性**。  具体来说，它测试了以下几个核心方面：

1. **`IsEquivalent()` 方法的正确性:**  判断两个 `CanonicalCookie` 对象是否在特定条件下被认为是等价的。
2. **`IsDomainMatch()` 方法的正确性:**  判断 Cookie 的域名是否与给定的主机名匹配。
3. **`IsOnPath()` 方法的正确性:**  判断给定的路径是否在 Cookie 的有效路径范围内。
4. **`GetEffectiveSameSite()` 方法的正确性:**  根据 Cookie 的 `SameSite` 属性和访问语义，计算出有效的 `SameSite` 策略。
5. **`IncludeForRequestURL()` 方法的正确性:**  判断 Cookie 是否应该被包含在对特定 URL 的请求中，考虑到各种因素，如域名、路径、安全属性、HttpOnly 属性和 SameSite 策略。

**与 JavaScript 的关系：**

`CanonicalCookie` 类是 Chromium 网络栈中表示和处理 Cookie 的核心类。虽然这段 C++ 代码本身不直接运行在 JavaScript 环境中，但它所测试的功能直接影响了 JavaScript 如何与 Cookie 交互。

* **JavaScript 可以通过 `document.cookie` API 读取、设置和删除 Cookie。**  当浏览器执行 JavaScript 代码并尝试访问或修改 Cookie 时，底层的 C++ 网络栈（包括 `CanonicalCookie` 类的逻辑）负责验证 Cookie 的属性，例如域名、路径、安全性和 `HttpOnly` 属性。
* **`SameSite` 属性直接影响 JavaScript 发起的跨站请求中 Cookie 的行为。**  这段代码测试了 `GetEffectiveSameSite()` 和 `IncludeForRequestURL()` 方法，确保了 Chromium 正确理解和执行 `SameSite` 策略，从而影响了 JavaScript 能否在跨站请求中发送 Cookie。

**举例说明：**

假设一个网站 `www.example.com` 设置了一个 Cookie：

```
Set-Cookie: mycookie=value; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict
```

* **JavaScript 尝试读取 Cookie (`document.cookie`):**  由于该 Cookie 设置了 `HttpOnly` 属性，这段 C++ 代码的逻辑会阻止 JavaScript 代码直接读取该 Cookie。 `IncludeForRequestURL()` 方法会考虑 `HttpOnly` 属性，确保它不会在非 HTTP 请求中被发送。
* **JavaScript 发起跨站请求到 `another.com`:** 由于该 Cookie 设置了 `SameSite=Strict`，`IncludeForRequestURL()` 方法会根据请求的上下文判断是否应该包含这个 Cookie。如果这是一个跨站请求，那么该 Cookie 将不会被包含。

**逻辑推理、假设输入与输出：**

**`IsDomainMatch()` 示例：**

* **假设输入 Cookie 域名:** `.example.com`
* **假设输入请求域名:** `sub.example.com`
* **预期输出:** `IsDomainMatch()` 返回 `true`，因为请求域名是 Cookie 域名的子域名。

* **假设输入 Cookie 域名:** `www.example.com` (无前导点)
* **假设输入请求域名:** `example.com`
* **预期输出:** `IsDomainMatch()` 返回 `false`，因为请求域名不是 Cookie 域名的子域名，且 Cookie 域名没有前导点表示可以匹配父域名。

**`IncludeForRequestURL()` 示例：**

* **假设 Cookie:** `mycookie=value; Domain=example.com; Path=/foo; Secure`
* **假设请求 URL:** `http://example.com/bar`
* **预期输出:** `IncludeForRequestURL()` 返回排除状态，原因是 `EXCLUDE_NOT_ON_PATH`，因为请求路径 `/bar` 不在 Cookie 的路径 `/foo` 下。

* **假设 Cookie:** `mycookie=value; Domain=example.com; Secure`
* **假设请求 URL:** `http://example.com`
* **预期输出:** `IncludeForRequestURL()` 返回排除状态，原因是 `EXCLUDE_SECURE_ONLY`，因为 Cookie 标记为 `Secure`，但请求 URL 使用的是非加密的 HTTP 协议。

**用户或编程常见的使用错误：**

1. **`Domain` 属性设置错误:**
   * **错误:** 设置 `Domain=sub.example.com` 的 Cookie，但期望它能被 `example.com` 的页面访问。
   * **`IsDomainMatch()` 测试会覆盖这种情况。**  如果 JavaScript 设置了错误的 `Domain` 属性，后续的请求可能无法携带预期的 Cookie。
2. **`Path` 属性设置过于严格:**
   * **错误:** 设置 `Path=/specific/path` 的 Cookie，但期望它能被 ` /specific/` 下的其他路径访问。
   * **`IsOnPath()` 测试会验证路径匹配逻辑。** 用户可能会错误地理解 `Path` 属性的作用范围。
3. **`Secure` 属性与非 HTTPS 访问冲突:**
   * **错误:** 设置了 `Secure` 属性的 Cookie，但尝试在 HTTP 页面上访问。
   * **`IncludeForRequestURL()` 会检测这种情况。**  开发者可能会忘记在生产环境中使用 HTTPS，导致 `Secure` Cookie 无法正常工作。
4. **`HttpOnly` 属性的误解:**
   * **错误:**  设置了 `HttpOnly` 的 Cookie，但期望能通过 JavaScript 读取它。
   * **相关测试会验证 JavaScript 无法访问 `HttpOnly` Cookie。**  开发者可能不理解 `HttpOnly` 的安全作用。
5. **`SameSite` 属性的理解偏差:**
   * **错误:**  设置了 `SameSite=Strict` 的 Cookie，但期望它能在所有跨站请求中发送。
   * **`GetEffectiveSameSite()` 和 `IncludeForRequestURL()` 中对 `SameSite` 的测试至关重要。** 开发者需要正确理解不同 `SameSite` 值的含义及其对跨站请求的影响。

**用户操作如何一步步到达这里（调试线索）：**

假设用户报告了网站的登录状态在跨域跳转后丢失的问题。作为开发人员，你可能会采取以下调试步骤：

1. **检查浏览器的开发者工具 (Network Tab):** 查看请求头中的 `Cookie`，确认登录相关的 Cookie 是否被发送。
2. **检查 `Set-Cookie` 响应头:**  确认登录 Cookie 的属性（`Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`）。
3. **如果发现 `SameSite` 设置为 `Strict` 或 `Lax`，并且这是一个跨站请求:**  这可能是导致问题的原因。
4. **查看 Chromium 的 Cookie 管理器 (chrome://settings/cookies/detail):**  确认 Cookie 的属性是否符合预期。
5. **阅读或调试 Chromium 源代码 (例如 `canonical_cookie_unittest.cc`):**  如果你需要深入理解 Chromium 如何处理 Cookie，或者需要验证特定的 Cookie 行为是否符合规范，你可能会查看相关的单元测试，例如这里的 `IncludeForRequestURL()` 测试，来了解 Chromium 如何判断 Cookie 是否应该被包含在请求中。你会看到各种测试用例模拟了不同的 `SameSite` 配置和请求场景。

**作为第 3 部分的功能归纳：**

总的来说，这第三部分专注于 **验证 `CanonicalCookie` 类中用于判断 Cookie 属性和适用性的核心逻辑**。 它确保了 Chromium 能够正确地根据 Cookie 的定义（域名、路径、安全性、HttpOnly、SameSite）来判断 Cookie 是否与给定的请求上下文匹配，这对于维护用户的会话状态、保护用户隐私和确保网站功能正常运行至关重要。 这部分测试是网络栈中 Cookie 处理逻辑正确性的基础保障。

Prompt: 
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共9部分，请归纳一下它的功能

"""
her_cookie));

    other_cookie = create_cookie(domain, http_scheme, 123);
    EXPECT_TRUE(domain_cookie->IsEquivalent(*other_cookie));

    // But not so for host cookies.
    other_cookie = create_cookie(host_only_domain, http_scheme, -1);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    other_cookie = create_cookie(host_only_domain, http_scheme, 123);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));

    // Different scheme and ports are not equivalent.
    other_cookie = create_cookie(domain, CookieSourceScheme::kSecure, 123);
    EXPECT_FALSE(domain_cookie->IsEquivalent(*other_cookie));

    other_cookie =
        create_cookie(host_only_domain, CookieSourceScheme::kSecure, 123);
    EXPECT_FALSE(host_cookie->IsEquivalent(*other_cookie));
  }
}

TEST(CanonicalCookieTest, IsDomainMatch) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      url, "A=2", creation_time, server_time));
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_TRUE(cookie->IsDomainMatch("www.example.com"));
  EXPECT_TRUE(cookie->IsDomainMatch("www.example.com"));
  EXPECT_FALSE(cookie->IsDomainMatch("foo.www.example.com"));
  EXPECT_FALSE(cookie->IsDomainMatch("www0.example.com"));
  EXPECT_FALSE(cookie->IsDomainMatch("example.com"));

  cookie = CanonicalCookie::CreateForTesting(url, "A=2; Domain=www.example.com",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie->IsDomainCookie());
  EXPECT_TRUE(cookie->IsDomainMatch("www.example.com"));
  EXPECT_TRUE(cookie->IsDomainMatch("www.example.com"));
  EXPECT_TRUE(cookie->IsDomainMatch("foo.www.example.com"));
  EXPECT_FALSE(cookie->IsDomainMatch("www0.example.com"));
  EXPECT_FALSE(cookie->IsDomainMatch("example.com"));

  cookie = CanonicalCookie::CreateForTesting(
      url, "A=2; Domain=.www.example.com", creation_time, server_time);
  EXPECT_TRUE(cookie->IsDomainMatch("www.example.com"));
  EXPECT_TRUE(cookie->IsDomainMatch("www.example.com"));
  EXPECT_TRUE(cookie->IsDomainMatch("foo.www.example.com"));
  EXPECT_FALSE(cookie->IsDomainMatch("www0.example.com"));
  EXPECT_FALSE(cookie->IsDomainMatch("example.com"));
}

TEST(CanonicalCookieTest, IsOnPath) {
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      GURL("http://www.example.com"), "A=2", creation_time, server_time));
  EXPECT_TRUE(cookie->IsOnPath("/"));
  EXPECT_TRUE(cookie->IsOnPath("/test"));
  EXPECT_TRUE(cookie->IsOnPath("/test/bar.html"));

  // Test the empty string edge case.
  EXPECT_FALSE(cookie->IsOnPath(std::string()));

  cookie = CanonicalCookie::CreateForTesting(
      GURL("http://www.example.com/test/foo.html"), "A=2", creation_time,
      server_time);
  EXPECT_FALSE(cookie->IsOnPath("/"));
  EXPECT_TRUE(cookie->IsOnPath("/test"));
  EXPECT_TRUE(cookie->IsOnPath("/test/bar.html"));
  EXPECT_TRUE(cookie->IsOnPath("/test/sample/bar.html"));
}

TEST(CanonicalCookieTest, GetEffectiveSameSite) {
  struct {
    CookieSameSite same_site;
    CookieEffectiveSameSite expected_effective_same_site;
    // nullopt for following members indicates same effective SameSite result
    // for all possible values.
    std::optional<CookieAccessSemantics> access_semantics = std::nullopt;
    std::optional<bool> is_cookie_recent = std::nullopt;
  } kTestCases[] = {
      // Explicitly specified SameSite always has the same effective SameSite
      // regardless of the access semantics.
      {CookieSameSite::NO_RESTRICTION, CookieEffectiveSameSite::NO_RESTRICTION},
      {CookieSameSite::LAX_MODE, CookieEffectiveSameSite::LAX_MODE},
      {CookieSameSite::STRICT_MODE, CookieEffectiveSameSite::STRICT_MODE},
      {CookieSameSite::NO_RESTRICTION, CookieEffectiveSameSite::NO_RESTRICTION},

      // UNSPECIFIED always maps to NO_RESTRICTION if LEGACY access semantics.
      {CookieSameSite::UNSPECIFIED, CookieEffectiveSameSite::NO_RESTRICTION,
       CookieAccessSemantics::LEGACY},

      // UNSPECIFIED with non-LEGACY access semantics depends on whether cookie
      // is recently created.
      {CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       CookieAccessSemantics::NONLEGACY, true},
      {CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       CookieAccessSemantics::UNKNOWN, true},
      {CookieSameSite::UNSPECIFIED, CookieEffectiveSameSite::LAX_MODE,
       CookieAccessSemantics::NONLEGACY, false},
      {CookieSameSite::UNSPECIFIED, CookieEffectiveSameSite::LAX_MODE,
       CookieAccessSemantics::UNKNOWN, false},
  };

  for (const auto& test : kTestCases) {
    std::vector<std::unique_ptr<CanonicalCookie>> cookies;

    base::Time now = base::Time::Now();
    base::Time recent_creation_time = now - (kLaxAllowUnsafeMaxAge / 4);
    base::Time not_recent_creation_time = now - (kLaxAllowUnsafeMaxAge * 4);
    base::Time expiry_time = now + (kLaxAllowUnsafeMaxAge / 4);

    if (!test.is_cookie_recent.has_value() || *test.is_cookie_recent) {
      // Recent session cookie.
      cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
          "A", "2", "example.test", "/", recent_creation_time, base::Time(),
          base::Time(), base::Time(), true /* secure */, false /* httponly */,
          test.same_site, COOKIE_PRIORITY_DEFAULT));
      // Recent persistent cookie.
      cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
          "A", "2", "example.test", "/", recent_creation_time, expiry_time,
          base::Time(), base::Time(), true /* secure */, false /* httponly */,
          test.same_site, COOKIE_PRIORITY_DEFAULT));
    }
    if (!test.is_cookie_recent.has_value() || !(*test.is_cookie_recent)) {
      // Not-recent session cookie.
      cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
          "A", "2", "example.test", "/", not_recent_creation_time, base::Time(),
          base::Time(), base::Time(), true /* secure */, false /* httponly */,
          test.same_site, COOKIE_PRIORITY_DEFAULT));
      // Not-recent persistent cookie.
      cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
          "A", "2", "example.test", "/", not_recent_creation_time, expiry_time,
          base::Time(), base::Time(), true /* secure */, false /* httponly */,
          test.same_site, COOKIE_PRIORITY_DEFAULT));
    }

    std::vector<CookieAccessSemantics> access_semantics = {
        CookieAccessSemantics::UNKNOWN, CookieAccessSemantics::LEGACY,
        CookieAccessSemantics::NONLEGACY};
    if (test.access_semantics.has_value())
      access_semantics = {*test.access_semantics};

    for (const auto& cookie : cookies) {
      for (const auto semantics : access_semantics) {
        EXPECT_EQ(test.expected_effective_same_site,
                  cookie->GetEffectiveSameSiteForTesting(semantics));
      }
    }
  }
}

TEST(CanonicalCookieTest, IncludeForRequestURL) {
  GURL url("http://www.example.com");
  base::Time creation_time = base::Time::Now();
  CookieOptions options = CookieOptions::MakeAllInclusive();
  std::optional<base::Time> server_time = std::nullopt;

  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      url, "A=2", creation_time, server_time));
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.IsInclude());
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              GURL("http://www.example.com/foo/bar"), options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.IsInclude());
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              GURL("https://www.example.com/foo/bar"), options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.IsInclude());
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              GURL("https://sub.example.com"), options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_DOMAIN_MISMATCH}));
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              GURL("https://sub.www.example.com"), options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_DOMAIN_MISMATCH}));
  // Test that cookie with a cookie path that does not match the url path are
  // not included.
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; Path=/foo/bar",
                                             creation_time, server_time);
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_NOT_ON_PATH}));
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              GURL("http://www.example.com/foo/bar/index.html"), options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.IsInclude());
  // Test that a secure cookie is not included for a non secure URL.
  GURL secure_url("https://www.example.com");
  cookie = CanonicalCookie::CreateForTesting(secure_url, "A=2; Secure",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie->SecureAttribute());
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              secure_url, options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.IsInclude());
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));

  // Test that a delegate can make an exception, however, and ask for a
  // non-secure URL to be treated as trustworthy... with a warning.
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; Secure", creation_time,
                                             server_time);
  ASSERT_TRUE(cookie);
  EXPECT_TRUE(cookie->SecureAttribute());
  CookieAccessResult result = cookie->IncludeForRequestURL(
      url, options,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/true});
  EXPECT_TRUE(result.status.IsInclude());
  EXPECT_TRUE(result.status.HasWarningReason(
      CookieInclusionStatus::WARN_SECURE_ACCESS_GRANTED_NON_CRYPTOGRAPHIC));

  // The same happens for localhost even w/o delegate intervention.
  GURL localhost_url("http://localhost/");
  cookie = CanonicalCookie::CreateForTesting(localhost_url, "A=2; Secure",
                                             creation_time, server_time);
  ASSERT_TRUE(cookie);
  EXPECT_TRUE(cookie->SecureAttribute());
  result = cookie->IncludeForRequestURL(
      localhost_url, options,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false});
  EXPECT_TRUE(result.status.IsInclude());
  EXPECT_TRUE(result.status.HasWarningReason(
      CookieInclusionStatus::WARN_SECURE_ACCESS_GRANTED_NON_CRYPTOGRAPHIC));

  // An unneeded exception doesn't add a warning, however.
  cookie = CanonicalCookie::CreateForTesting(secure_url, "A=2; Secure",
                                             creation_time, server_time);
  ASSERT_TRUE(cookie);
  EXPECT_TRUE(cookie->SecureAttribute());
  result = cookie->IncludeForRequestURL(
      secure_url, options,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/true});
  EXPECT_TRUE(result.status.IsInclude());
  EXPECT_FALSE(result.status.ShouldWarn());

  // Test that http only cookies are only included if the include httponly flag
  // is set on the cookie options.
  options.set_include_httponly();
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; HttpOnly",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie->IsHttpOnly());
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.IsInclude());
  options.set_exclude_httponly();
  EXPECT_TRUE(
      cookie
          ->IncludeForRequestURL(
              url, options,
              CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                                 /*delegate_treats_url_as_trustworthy=*/false})
          .status.HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_HTTP_ONLY}));
}

struct IncludeForRequestURLTestCase {
  std::string cookie_line;
  CookieSameSite expected_samesite;
  CookieEffectiveSameSite expected_effective_samesite;
  CookieOptions::SameSiteCookieContext request_options_samesite_context;
  CookieInclusionStatus expected_inclusion_status;
  base::TimeDelta creation_time_delta = base::TimeDelta();
};

void VerifyIncludeForRequestURLTestCases(
    CookieAccessSemantics access_semantics,
    std::vector<IncludeForRequestURLTestCase> test_cases) {
  GURL url("https://example.test");
  for (const auto& test : test_cases) {
    base::Time creation_time = base::Time::Now() - test.creation_time_delta;
    std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::CreateForTesting(
        url, test.cookie_line, creation_time, std::nullopt /* server_time */);
    EXPECT_EQ(test.expected_samesite, cookie->SameSite());

    CookieOptions request_options;
    request_options.set_same_site_cookie_context(
        test.request_options_samesite_context);

    EXPECT_THAT(
        cookie->IncludeForRequestURL(
            url, request_options,
            CookieAccessParams{access_semantics,
                               /*delegate_treats_url_as_trustworthy=*/false}),
        MatchesCookieAccessResult(test.expected_inclusion_status,
                                  test.expected_effective_samesite,
                                  access_semantics, true))
        << cookie->Name() << "=" << cookie->Value();
  }
}

TEST(CanonicalCookieTest, IncludeForRequestURLSameSite) {
  const base::TimeDelta kLongAge = kLaxAllowUnsafeMaxAge * 4;
  const base::TimeDelta kShortAge = kLaxAllowUnsafeMaxAge / 4;

  using SameSiteCookieContext = CookieOptions::SameSiteCookieContext;

  // Test cases that are the same regardless of feature status or access
  // semantics. For Schemeful Same-Site this means that the context downgrade is
  // a no-op (such as for NO_RESTRICTION cookies) or that there is no downgrade:
  std::vector<IncludeForRequestURLTestCase> common_test_cases = {
      // Strict cookies:
      {"Common=1;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus(CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT)},
      {"Common=2;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus(CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT)},
      {"Common=3;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus(CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT)},
      {"Common=4;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT),
       CookieInclusionStatus()},
      // Lax cookies:
      {"Common=5;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus(CookieInclusionStatus::EXCLUDE_SAMESITE_LAX)},
      {"Common=6;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus(CookieInclusionStatus::EXCLUDE_SAMESITE_LAX)},
      {"Common=7;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus()},
      {"Common=8;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT),
       CookieInclusionStatus()},
      // Lax cookies with downgrade:
      {"Common=9;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus()},
      // None and Secure cookies:
      {"Common=10;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus()},
      {"Common=11;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus()},
      {"Common=12;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus()},
      {"Common=13;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT),
       CookieInclusionStatus()},
      // Because NO_RESTRICTION cookies are always sent, the schemeful context
      // downgrades shouldn't matter.
      {"Common=14;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus()},
      {"Common=15;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus()},
      {"Common=16;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus()},
      {"Common=17;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX,
                             SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus()},
      {"Common=18;SameSite=None;Secure", CookieSameSite::NO_RESTRICTION,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE,
           SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus()},
  };

  // Test cases where the unspecified-SameSite cookie defaults to SameSite=None
  // due to LEGACY access semantics):
  std::vector<IncludeForRequestURLTestCase> default_none_test_cases = {
      {"DefaultNone=1", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::
                WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT})},
      {"DefaultNone=2", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::
                WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT})},

      {"DefaultNone=3", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus()},
      {"DefaultNone=4", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::NO_RESTRICTION,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT),
       CookieInclusionStatus()}};

  // Test cases where the unspecified-SameSite cookie defaults to SameSite=Lax:
  std::vector<IncludeForRequestURLTestCase> default_lax_test_cases = {
      // Unspecified recently-created cookies (with SameSite-by-default):
      {"DefaultLax=1", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus(
           CookieInclusionStatus::EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX,
           CookieInclusionStatus::WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT),
       kShortAge},
      {"DefaultLax=2", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::WARN_SAMESITE_UNSPECIFIED_LAX_ALLOW_UNSAFE}),
       kShortAge},
      {"DefaultLax=3", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus(), kShortAge},
      {"DefaultLax=4", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT),
       CookieInclusionStatus(), kShortAge},
      // Unspecified not-recently-created cookies (with SameSite-by-default):
      {"DefaultLax=5", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus(
           CookieInclusionStatus::EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX,
           CookieInclusionStatus::WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT),
       kLongAge},
      {"DefaultLax=6", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus(
           CookieInclusionStatus::EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX,
           CookieInclusionStatus::WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT),
       kLongAge},
      {"DefaultLax=7", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus(), kLongAge},
      {"DefaultLax=8", CookieSameSite::UNSPECIFIED,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT),
       CookieInclusionStatus(), kLongAge},
  };

  // Test cases that require LEGACY semantics or Schemeful Same-Site to be
  // disabled.
  std::vector<IncludeForRequestURLTestCase> schemeful_disabled_test_cases = {
      {"LEGACY_Schemeful=1;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::WARN_STRICT_LAX_DOWNGRADE_STRICT_SAMESITE})},
      {"LEGACY_Schemeful=2;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::
                WARN_STRICT_CROSS_DOWNGRADE_STRICT_SAMESITE})},
      {"LEGACY_Schemeful=3;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::
                WARN_STRICT_CROSS_DOWNGRADE_STRICT_SAMESITE})},
      {"LEGACY_Schemeful=4;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::WARN_STRICT_CROSS_DOWNGRADE_LAX_SAMESITE})},
      {"LEGACY_Schemeful=5;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::WARN_STRICT_CROSS_DOWNGRADE_LAX_SAMESITE})},
      {"LEGACY_Schemeful=6;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX,
                             SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           std::vector<CookieInclusionStatus::ExclusionReason>(),
           {CookieInclusionStatus::WARN_LAX_CROSS_DOWNGRADE_LAX_SAMESITE})},
  };

  // Test cases that require NONLEGACY or UNKNOWN semantics with Schemeful
  // Same-Site enabled
  std::vector<IncludeForRequestURLTestCase> schemeful_enabled_test_cases = {
      {"NONLEGACY_Schemeful=1;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           {CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT},
           {CookieInclusionStatus::WARN_STRICT_LAX_DOWNGRADE_STRICT_SAMESITE})},
      {"NONLEGACY_Schemeful=2;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           {CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT},
           {CookieInclusionStatus::
                WARN_STRICT_CROSS_DOWNGRADE_STRICT_SAMESITE})},
      {"NONLEGACY_Schemeful=3;SameSite=Strict", CookieSameSite::STRICT_MODE,
       CookieEffectiveSameSite::STRICT_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           {CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT},
           {CookieInclusionStatus::
                WARN_STRICT_CROSS_DOWNGRADE_STRICT_SAMESITE})},
      {"NONLEGACY_Schemeful=4;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::SAME_SITE_LAX_METHOD_UNSAFE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           {CookieInclusionStatus::EXCLUDE_SAMESITE_LAX},
           {CookieInclusionStatus::WARN_STRICT_CROSS_DOWNGRADE_LAX_SAMESITE})},
      {"NONLEGACY_Schemeful=5;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(
           SameSiteCookieContext::ContextType::SAME_SITE_STRICT,
           SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           {CookieInclusionStatus::EXCLUDE_SAMESITE_LAX},
           {CookieInclusionStatus::WARN_STRICT_CROSS_DOWNGRADE_LAX_SAMESITE})},
      {"NONLEGACY_Schemeful=6;SameSite=Lax", CookieSameSite::LAX_MODE,
       CookieEffectiveSameSite::LAX_MODE,
       SameSiteCookieContext(SameSiteCookieContext::ContextType::SAME_SITE_LAX,
                             SameSiteCookieContext::ContextType::CROSS_SITE),
       CookieInclusionStatus::MakeFromReasonsForTesting(
           {CookieInclusionStatus::EXCLUDE_SAMESITE_LAX},
           {CookieInclusionStatus::WARN_LAX_CROSS_DOWNGRADE_LAX_SAMESITE})},
  };

  auto SchemefulIndependentCases = [&]() {
    // Run the test cases that are independent of Schemeful Same-Site.
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::UNKNOWN,
                                        common_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::UNKNOWN,
                                        default_lax_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::LEGACY,
                                        common_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::LEGACY,
                                        default_none_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::NONLEGACY,
                                        common_test_cases);
    VerifyIncludeForRequestURLTestCases(CookieAccessSemantics::NONLEGACY,
                                        default_lax_test_cases);
  };

  {
    // Schemeful Same-Site disabled.
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(features::kSchemefulSameSite);

   
"""


```