Response:
My thinking process to analyze the given C++ code snippet and fulfill the request goes through these stages:

1. **Understanding the Goal:** The primary goal is to analyze a portion of a C++ unit test file for Chromium's network stack related to cookies. The analysis needs to cover functionality, relation to JavaScript, logical reasoning (input/output), common usage errors, debugging context, and a summary of the provided code.

2. **Identifying the Core Subject:** The filename `canonical_cookie_unittest.cc` and the code itself clearly indicate that this file contains unit tests for the `CanonicalCookie` class. The tests focus on the creation and validation of canonical cookies.

3. **Dissecting the Code - Test Case by Test Case:**  I go through each `TEST_F` or `TEST` block to understand its specific purpose. I look for:
    * **Function Under Test:** Which method of `CanonicalCookie` is being tested (e.g., `CreateSanitizedCookie`, `FromStorage`, `IsSetPermittedInContext`).
    * **Test Scenarios:** What are the different input variations being tested? This includes different URLs, cookie attributes (name, value, domain, path, secure, httponly, samesite, priority, partition key), and timestamps.
    * **Assertions:** What are the `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, and `EXPECT_THAT` statements checking? These reveal the expected behavior of the function under test for the given inputs.
    * **`CookieInclusionStatus`:** Pay close attention to how `CookieInclusionStatus` is used. It's crucial for understanding why a cookie creation might succeed or fail. The tests often check for specific exclusion reasons.

4. **Identifying Key Functionality:** Based on the test cases, I list the core functionalities being tested:
    * **`CreateSanitizedCookie`:** This is the primary function being tested. It's responsible for creating a `CanonicalCookie` object from provided parameters and sanitizing/validating them. The tests cover various valid and invalid cookie attribute combinations.
    * **Prefix Handling (`__Host-`, `__Secure-`):**  Several tests focus on how `CreateSanitizedCookie` handles cookie prefixes and the associated requirements (e.g., secure context, path="/", no domain).
    * **Partitioned Cookies:** Tests verify the creation and validation of partitioned cookies, which have stricter requirements.
    * **Domain Validation:** Tests check for valid and invalid domain formats.
    * **Length Limits:** Tests confirm that the code enforces RFC6265bis limits on cookie name, value, path, and domain lengths.
    * **`FromStorage`:** Tests the creation of `CanonicalCookie` objects from stored data, including source scheme and port. It also verifies handling of invalid data.
    * **`IsSetPermittedInContext`:**  Tests whether a cookie can be set in a given context (URL, script access, etc.).

5. **Relating to JavaScript:** I consider how cookies are used in a web browser and how JavaScript interacts with them:
    * **`document.cookie`:** This is the primary way JavaScript accesses cookies. The tests implicitly relate because they are validating the creation and attributes of cookies that JavaScript would eventually interact with.
    * **Security Considerations:**  The tests for `Secure`, `HttpOnly`, and `SameSite` flags directly relate to security features that affect JavaScript's ability to access cookies.

6. **Logical Reasoning (Input/Output Examples):** I choose representative test cases to illustrate the input parameters to `CreateSanitizedCookie` and the corresponding output (success/failure and the `CookieInclusionStatus`). This helps demonstrate the logic of the function.

7. **Common Usage Errors:** I think about common mistakes developers might make when setting cookies, based on the tested validation rules:
    * Forgetting `Secure` for `__Host-` cookies.
    * Setting an incorrect `Path` for `__Host-` cookies.
    * Specifying a `Domain` for a `__Host-` cookie.
    * Exceeding length limits for cookie attributes.

8. **Debugging Context (User Operations):** I trace back how a user action might lead to this cookie creation logic being executed:
    * A user visiting a website (HTTP request).
    * The server sending a `Set-Cookie` header.
    * The browser's network stack processing the header, which involves calling `CanonicalCookie::CreateSanitizedCookie`.
    * JavaScript trying to set a cookie via `document.cookie`.

9. **Summarizing the Section:** I review the tests in the provided code snippet and condense the main functionalities being tested in this specific part of the file.

10. **Iteration and Refinement:** I review my analysis to ensure accuracy, clarity, and completeness, addressing all parts of the prompt. I make sure the examples are clear and the explanations are easy to understand. For instance, initially, I might just list the tested functions, but then refine it to describe the specific *aspects* of those functions being tested (e.g., prefix handling, length limits). I also double-check that I've connected the C++ code back to potential JavaScript interactions.
好的，这是对提供的 Chromium 网络栈源代码文件 `net/cookies/canonical_cookie_unittest.cc` 第 7 部分功能的详细分析：

**功能归纳（针对提供的代码片段）：**

这个代码片段主要集中在 **`CanonicalCookie::CreateSanitizedCookie` 方法的各种测试用例**。它旨在验证该方法在处理各种合法和非法的 Cookie 属性组合时的行为，特别是关于以下方面的规则和限制：

* **`__Host-` 和 `__Secure-` 前缀：**  测试了带有这些前缀的 Cookie 的创建，以及它们对 `Secure` 属性、`Path` 属性和 `Domain` 属性的要求。
* **隐藏前缀：** 验证了尝试在 Cookie 值中隐藏这些前缀的情况是否会被正确拒绝。
* **Partitioned 属性：** 测试了带有 `Partitioned` 属性的 Cookie 的创建，并验证了它与 `__Host-` 前缀的关联以及其他属性的要求（如 `Secure` 和 `Path=/`，无 `Domain`）。
* **域名有效性：** 针对各种格式的域名（包括特殊字符和空字符串）进行了测试，以确保 `CreateSanitizedCookie` 能正确识别和拒绝无效域名。
* **长度限制：** 验证了 Cookie 的名称、值、Path 属性和 Domain 属性是否遵守 RFC6265bis 中规定的长度限制。
* **Source Scheme 和 Port：**  测试了当使用 `Create` 和 `CreateSanitizedCookie` 创建 Cookie 时，根据 URL 的安全性和是否指定 `Secure` 属性，`SourceScheme` 和 `SourcePort` 是否被正确设置。

**与 JavaScript 的关系：**

这段代码直接测试了浏览器底层处理 Cookie 的逻辑，这与 JavaScript 如何操作 Cookie 密切相关。

* **`document.cookie` 的行为：**  当 JavaScript 使用 `document.cookie` 设置 Cookie 时，浏览器最终会调用类似 `CanonicalCookie::CreateSanitizedCookie` 的方法来解析和验证 Cookie 字符串。这些测试确保了底层的验证逻辑与 JavaScript 预期的一致。例如，如果 JavaScript 尝试设置一个带有 `__Host-` 前缀但不是在安全上下文中的 Cookie，底层的验证逻辑（如测试所示）会拒绝它，JavaScript 设置 Cookie 的操作也会失败。
* **安全 Cookie 的限制：**  JavaScript 无法访问带有 `HttpOnly` 属性的 Cookie。这里对 `Secure` 属性的测试也与 JavaScript 在非 HTTPS 页面上无法设置或访问带有 `Secure` 属性的 Cookie 的行为相关。
* **SameSite 属性的影响：** 虽然这段代码没有直接测试 SameSite 属性对 JavaScript 访问的影响，但它测试了 `SameSite` 属性的解析和存储，这最终会影响浏览器在不同场景下是否会将 Cookie 发送给服务器，从而影响 JavaScript 发起的请求。

**举例说明：**

假设 JavaScript 代码尝试设置一个 Cookie：

```javascript
document.cookie = "__Host-mycookie=value; path=/; secure";
```

* **假设输入：**
    * `GURL`: 当前页面的 URL，例如 `https://www.example.com`
    * `cookie_string`: `__Host-mycookie=value; path=/; secure`
* **逻辑推理：** `CanonicalCookie::CreateSanitizedCookie` 会被调用来解析这个字符串。由于 URL 是 HTTPS，`__Host-` 前缀存在，`path` 是 `/`，并且设置了 `secure` 属性，根据测试用例，这个 Cookie 应该被成功创建。
* **预期输出：**  `CreateSanitizedCookie` 返回一个指向 `CanonicalCookie` 对象的指针，并且 `status.IsInclude()` 返回 `true`。

再例如，如果 JavaScript 尝试设置一个无效的 `__Host-` Cookie：

```javascript
document.cookie = "__Host-mycookie=value; path=/"; // 缺少 secure
```

* **假设输入：**
    * `GURL`: `https://www.example.com`
    * `cookie_string`: `__Host-mycookie=value; path=/`
* **逻辑推理：**  `CanonicalCookie::CreateSanitizedCookie` 会检查 `__Host-` Cookie 的要求。由于缺少 `secure` 属性，根据测试用例，这个 Cookie 会被拒绝。
* **预期输出：** `CreateSanitizedCookie` 返回 `nullptr`，并且 `status` 会包含 `CookieInclusionStatus::EXCLUDE_SECURE_ONLY` 的排除原因。

**用户或编程常见的使用错误：**

* **未能为 `__Host-` Cookie 设置 `Secure` 属性：**  用户（开发者）尝试在 HTTPS 上设置 `__Host-` Cookie，但忘记添加 `secure` 属性。这将导致 Cookie 被浏览器拒绝。
    * **例子：**  在 `https://example.com` 页面执行 `document.cookie = "__Host-mycookie=value; path=/";`
* **为 `__Host-` Cookie 设置了非根路径：**  用户尝试设置 `__Host-` Cookie，但将 `path` 设置为除 `/` 以外的其他值。
    * **例子：** 在 `https://example.com` 页面执行 `document.cookie = "__Host-mycookie=value; path=/subdir/";`
* **为 `__Host-` Cookie 设置了 `Domain` 属性：**  用户错误地为 `__Host-` Cookie 指定了 `Domain` 属性。
    * **例子：** 在 `https://example.com` 页面执行 `document.cookie = "__Host-mycookie=value; path=/; domain=example.com";`
* **Cookie 名称或值过长：**  用户尝试设置的 Cookie 的名称或值超过了浏览器允许的最大长度。
    * **例子：**  尝试设置一个非常长的 Cookie 值： `document.cookie = "mycookie=" + "a".repeat(5000) + ";";`
* **Path 或 Domain 属性值过长：** 用户设置的 Cookie 的 Path 或 Domain 属性值超过了允许的长度。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个网页 (例如 `https://www.example.com`)。**
2. **服务器在 HTTP 响应头中设置了 `Set-Cookie` 指令。** 例如：`Set-Cookie: __Host-mycookie=value; path=/; secure`
3. **浏览器的网络栈接收到这个响应头。**
4. **网络栈中的 Cookie 管理模块开始解析 `Set-Cookie` 指令。**
5. **`CanonicalCookie::CreateSanitizedCookie` 方法被调用，传入解析出的 Cookie 属性和来源 URL。**
6. **`CreateSanitizedCookie` 方法会执行各种验证，如本代码片段中的测试用例所示。**
7. **如果 Cookie 是合法的，它会被存储在浏览器的 Cookie 存储中。如果是非法的，会被拒绝，并通过 `CookieInclusionStatus` 记录拒绝原因。**

或者：

1. **网页上的 JavaScript 代码尝试设置 Cookie。** 例如：`document.cookie = "__Host-anothercookie=test; path=/; secure";`
2. **浏览器接收到 JavaScript 的设置 Cookie 请求。**
3. **浏览器内部会调用类似的 Cookie 创建和验证逻辑，最终也会涉及到 `CanonicalCookie::CreateSanitizedCookie` 或类似的方法。**
4. **如果 Cookie 验证失败，JavaScript 设置 Cookie 的操作可能不会生效，或者会在开发者工具中显示警告信息。**

因此，当开发者在调试 Cookie 相关问题时，例如发现 Cookie 没有被正确设置或发送，他们可能会查看浏览器的开发者工具 (Network 标签, Application 标签)，查看 `Set-Cookie` 响应头，或者检查 JavaScript 设置 Cookie 的代码。如果怀疑是 Cookie 格式问题，他们可能会深入研究浏览器 Cookie 相关的源代码，例如这里的 `canonical_cookie_unittest.cc`，来理解浏览器的具体验证逻辑。

总结来说，这段代码是 `CanonicalCookie::CreateSanitizedCookie` 方法的单元测试，它详细验证了该方法在处理各种 Cookie 属性组合时的正确性，特别是关于安全前缀、Partitioned 属性和长度限制等关键规则。这对于理解浏览器如何解析和验证 Cookie，以及如何避免常见的 Cookie 设置错误至关重要。

### 提示词
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
our_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  // Without __Host- prefix, this is a valid domain (not host) cookie.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", ".www.foo.com", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  // The __Host- prefix should not prevent otherwise-valid host cookies from
  // being accepted.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://127.0.0.1"), "A", "B", std::string(), "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://127.0.0.1"), "__Host-A", "B", std::string(), "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  // Host cookies should not specify domain unless it is an IP address that
  // matches the URL.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://127.0.0.1"), "A", "B", "127.0.0.1", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://127.0.0.1"), "__Host-A", "B", "127.0.0.1", "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  // Cookies with hidden prefixes should be rejected.

  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "", "__Host-A=B", "", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "", "__Host-A", "", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "", "__Secure-A=B", "", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "", "__Secure-A", "", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // While tricky, this aren't considered hidden prefixes and should succeed.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "__Host-A=B", "", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "__Secure-A=B", "", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  // Partitioned attribute requires __Host-.
  status = CookieInclusionStatus();
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", std::string(), "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true /*secure*/, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::optional<CookiePartitionKey>(CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite.com"))),
      &status));
  EXPECT_TRUE(status.IsInclude());
  // No __Host- prefix is still valid if the cookie still has Secure, Path=/,
  // and no Domain.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, true /*secure*/, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::optional<CookiePartitionKey>(CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite.com"))),
      &status));
  EXPECT_TRUE(status.IsInclude());
  status = CookieInclusionStatus();
  // Invalid: Not Secure.
  status = CookieInclusionStatus();
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, /*secure=*/false, /*http_only=*/false,
      CookieSameSite::LAX_MODE, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::optional<CookiePartitionKey>(CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite.com"))),
      &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PARTITIONED}));
  // Invalid: invalid Path.
  status = CookieInclusionStatus();
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foobar",
      two_hours_ago, one_hour_from_now, one_hour_ago, /*secure=*/true,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::optional<CookiePartitionKey>(CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite.com"))),
      &status));
  EXPECT_TRUE(status.IsInclude());
  // Domain attribute present is still valid.
  status = CookieInclusionStatus();
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", ".foo.com", "/", two_hours_ago,
      one_hour_from_now, one_hour_ago, /*secure=*/true, /*http_only=*/false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::optional<CookiePartitionKey>(CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite.com"))),
      &status));
  EXPECT_TRUE(status.IsInclude());

  status = CookieInclusionStatus();

  // Check that CreateSanitizedCookie can gracefully fail on inputs that would
  // crash cookie_util::GetCookieDomainWithString due to failing
  // DCHECKs. Specifically, GetCookieDomainWithString requires that if the
  // domain is empty or the URL's host matches the domain, then the URL's host
  // must pass DomainIsHostOnly; it must not begin with a period.
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://..."), "A", "B", "...", "/", base::Time(), base::Time(),
      base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://."), "A", "B", std::string(), "/", base::Time(),
      base::Time(), base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://.chromium.org"), "A", "B", ".chromium.org", "/",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Check that a file URL with an IPv6 host, and matching IPv6 domain, are
  // valid.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("file://[A::]"), "A", "B", "[A::]", "", base::Time(), base::Time(),
      base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  // On Windows, URLs beginning with two backslashes are considered file
  // URLs. On other platforms, they are invalid.
  auto double_backslash_ipv6_cookie = CanonicalCookie::CreateSanitizedCookie(
      GURL("\\\\[A::]"), "A", "B", "[A::]", "", base::Time(), base::Time(),
      base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status);
#if BUILDFLAG(IS_WIN)
  EXPECT_TRUE(double_backslash_ipv6_cookie);
  EXPECT_TRUE(double_backslash_ipv6_cookie->IsCanonical());
  EXPECT_TRUE(status.IsInclude());
#else
  EXPECT_FALSE(double_backslash_ipv6_cookie);
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
#endif

  // Confirm multiple error types can be set.
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL(""), "", "", "", "", base::Time(), base::Time(), base::Time::Now(),
      true /*secure*/, true /*httponly*/, CookieSameSite::STRICT_MODE,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_NO_COOKIE_CONTENT,
       CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE,
       CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Check that RFC6265bis name + value string length limits are enforced.
  std::string max_name(ParsedCookie::kMaxCookieNamePlusValueSize, 'a');
  std::string max_value(ParsedCookie::kMaxCookieNamePlusValueSize, 'b');
  std::string almost_max_name = max_name.substr(1, std::string::npos);
  std::string almost_max_value = max_value.substr(1, std::string::npos);

  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), max_name, "", std::string(), "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "", max_value, std::string(), "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), almost_max_name, "b", std::string(),
      "/foo", one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "a", almost_max_value, std::string(),
      "/foo", one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), max_name, "X", std::string(), "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_FALSE(cc);
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_NAME_VALUE_PAIR_EXCEEDS_MAX_SIZE}));

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "X", max_value, std::string(), "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_FALSE(cc);
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_NAME_VALUE_PAIR_EXCEEDS_MAX_SIZE}));

  // Check that the RFC6265bis attribute value size limits apply to the Path
  // attribute value.
  std::string almost_max_path(ParsedCookie::kMaxCookieAttributeValueSize - 1,
                              'c');
  std::string max_path = "/" + almost_max_path;
  std::string too_long_path = "/X" + almost_max_path;

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com" + max_path), "name", "value", std::string(),
      max_path, one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(max_path, cc->Path());
  EXPECT_TRUE(status.IsInclude());

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/path-attr-from-url/"), "name", "value",
      std::string(), too_long_path, one_hour_ago, one_hour_from_now,
      base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status);
  EXPECT_FALSE(cc);
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE}));

  // Check that length limits on the Path attribute value are not enforced
  // in the case where no Path attribute is specified and the path value is
  // implicitly set from the URL.
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com" + too_long_path + "/"), "name", "value",
      std::string(), std::string(), one_hour_ago, one_hour_from_now,
      base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(too_long_path, cc->Path());
  EXPECT_TRUE(status.IsInclude());

  // The Path attribute value gets URL-encoded, so ensure that the size
  // limit is enforced after this (to avoid setting cookies where the Path
  // attribute value would otherwise exceed the lengths specified in the
  // RFC).
  std::string expanding_path(ParsedCookie::kMaxCookieAttributeValueSize / 2,
                             '#');
  expanding_path = "/" + expanding_path;

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/path-attr-from-url/"), "name", "value",
      std::string(), expanding_path, one_hour_ago, one_hour_from_now,
      base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status);
  EXPECT_FALSE(cc);
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE}));

  // Check that the RFC6265bis attribute value size limits apply to the Domain
  // attribute value.
  std::string max_domain(ParsedCookie::kMaxCookieAttributeValueSize, 'd');
  max_domain.replace(ParsedCookie::kMaxCookieAttributeValueSize - 4, 4, ".com");
  std::string too_long_domain = "x" + max_domain;

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://" + max_domain + "/"), "name", "value", max_domain, "/",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(max_domain, cc->DomainWithoutDot());
  EXPECT_TRUE(status.IsInclude());
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.domain-from-url.com/"), "name", "value", too_long_domain,
      "/", one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_FALSE(cc);
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_ATTRIBUTE_VALUE_EXCEEDS_MAX_SIZE}));
  // Check that length limits on the Domain attribute value are not enforced
  // in the case where no Domain attribute is specified and the domain value
  // is implicitly set from the URL.
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://" + too_long_domain + "/"), "name", "value", std::string(),
      "/", one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(too_long_domain, cc->DomainWithoutDot());
  EXPECT_TRUE(status.IsInclude());
}

// Regression test for https://crbug.com/362535230.
TEST(CanonicalCookieTest, CreateSanitizedCookie_NoncanonicalDomain) {
  CookieInclusionStatus status;

  std::unique_ptr<CanonicalCookie> cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("foo://LOCALhost"), "name", "value", /*domain=*/"", /*path=*/"",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(status.IsInclude());
  ASSERT_TRUE(cc);
  EXPECT_TRUE(cc->IsCanonical());
  EXPECT_EQ(cc->Domain(), "localhost");
}

// Make sure that the source scheme and port are set correctly for cookies that
// are marked as "Secure".
TEST(CanonicalCookieTest, Create_SourceSchemePort) {
  GURL secure_url("https://example.com");
  GURL insecure_url("http://example.com");
  GURL insecure_url_custom_port("http://example.com:123");

  CookieInclusionStatus status;

  std::unique_ptr<CanonicalCookie> cc;

  // A secure url doesn't need "Secure" to have a source scheme of secure
  cc = CanonicalCookie::Create(secure_url, "a=b; SameSite=Lax",
                               base::Time::Now(), std::nullopt, std::nullopt,

                               CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 443);

  // But having "Secure" shouldn't change anything
  cc = CanonicalCookie::Create(secure_url, "a=b; SameSite=Lax; Secure",
                               base::Time::Now(), std::nullopt, std::nullopt,
                               CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_TRUE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 443);

  // An insecure url without "Secure" should get a non-secure source scheme and
  // a default port.
  cc = CanonicalCookie::Create(insecure_url, "a=b; SameSite=Lax",
                               base::Time::Now(), std::nullopt, std::nullopt,
                               CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kNonSecure);
  EXPECT_EQ(cc->SourcePort(), 80);

  // An insecure url with "Secure" should get a secure source scheme and
  // modified port. It should also get a warning that a secure source scheme was
  // tentatively allowed.
  cc = CanonicalCookie::Create(insecure_url, "a=b; SameSite=Lax; Secure",
                               base::Time::Now(), std::nullopt, std::nullopt,
                               CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(status.HasExactlyWarningReasonsForTesting(
      {CookieInclusionStatus::WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME}));
  EXPECT_TRUE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 443);

  // An insecure url with a non-default port without "Secure" should get a
  // non-secure source scheme and keep its port.
  cc = CanonicalCookie::Create(insecure_url_custom_port, "a=b; SameSite=Lax",
                               base::Time::Now(), std::nullopt, std::nullopt,
                               CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kNonSecure);
  EXPECT_EQ(cc->SourcePort(), 123);

  // An insecure url with a non-default port with "Secure" should get a secure
  // source scheme and keep its port. It should also get a warning that a secure
  // source scheme was tentatively allowed.
  cc = CanonicalCookie::Create(
      insecure_url_custom_port, "a=b; SameSite=Lax; Secure", base::Time::Now(),
      std::nullopt, std::nullopt, CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(status.HasExactlyWarningReasonsForTesting(
      {CookieInclusionStatus::WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME}));
  EXPECT_TRUE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 123);
}

// Make sure that the source scheme and port are set correctly for cookies that
// are marked as "Secure".
TEST(CanonicalCookieTest, CreateSanitizedCookie_SourceSchemePort) {
  GURL secure_url("https://example.com");
  GURL insecure_url("http://example.com");
  GURL insecure_url_custom_port("http://example.com:123");

  CookieInclusionStatus status;

  std::unique_ptr<CanonicalCookie> cc;

  // A secure url doesn't need "Secure" to have a source scheme of secure
  cc = CanonicalCookie::CreateSanitizedCookie(
      secure_url, "a", "b", "example.com", "", base::Time(), base::Time(),
      base::Time(), /*secure=*/false, /*http_only=*/false,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 443);

  // But having "Secure" shouldn't change anything
  cc = CanonicalCookie::CreateSanitizedCookie(
      secure_url, "a", "b", "example.com", "", base::Time(), base::Time(),
      base::Time(), /*secure=*/true, /*http_only=*/false,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_TRUE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 443);

  // An insecure url without "Secure" should get a non-secure source scheme and
  // a default port.
  cc = CanonicalCookie::CreateSanitizedCookie(
      insecure_url, "a", "b", "example.com", "", base::Time(), base::Time(),
      base::Time(), /*secure=*/false, /*http_only=*/false,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kNonSecure);
  EXPECT_EQ(cc->SourcePort(), 80);

  // An insecure url with "Secure" should get a secure source scheme and
  // modified port. It should also get a warning that a secure source scheme was
  // tentatively allowed.
  cc = CanonicalCookie::CreateSanitizedCookie(
      insecure_url, "a", "b", "example.com", "", base::Time(), base::Time(),
      base::Time(), /*secure=*/true, /*http_only=*/false,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(status.HasExactlyWarningReasonsForTesting(
      {CookieInclusionStatus::WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME}));
  EXPECT_TRUE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 443);

  // An insecure url with a non-default port without "Secure" should get a
  // non-secure source scheme and keep its port.
  cc = CanonicalCookie::CreateSanitizedCookie(
      insecure_url_custom_port, "a", "b", "example.com", "", base::Time(),
      base::Time(), base::Time(), /*secure=*/false, /*http_only=*/false,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(status.ShouldWarn());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kNonSecure);
  EXPECT_EQ(cc->SourcePort(), 123);

  // An insecure url with a non-default port with "Secure" should get a secure
  // source scheme and keep its port. It should also get a warning that a secure
  // source scheme was tentatively allowed.
  cc = CanonicalCookie::CreateSanitizedCookie(
      insecure_url_custom_port, "a", "b", "example.com", "", base::Time(),
      base::Time(), base::Time(), /*secure=*/true, /*http_only=*/false,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(status.HasExactlyWarningReasonsForTesting(
      {CookieInclusionStatus::WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME}));
  EXPECT_TRUE(cc->SecureAttribute());
  EXPECT_EQ(cc->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc->SourcePort(), 123);
}

TEST(CanonicalCookieTest, FromStorage) {
  base::Time two_hours_ago = base::Time::Now() - base::Hours(2);
  base::Time one_hour_ago = base::Time::Now() - base::Hours(1);
  base::Time one_hour_from_now = base::Time::Now() + base::Hours(1);

  std::unique_ptr<CanonicalCookie> cc = CanonicalCookie::FromStorage(
      "A", "B", "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure, 87,
      CookieSourceType::kUnknown);
  EXPECT_TRUE(cc);
  EXPECT_EQ("A", cc->Name());
  EXPECT_EQ("B", cc->Value());
  EXPECT_EQ("www.foo.com", cc->Domain());
  EXPECT_EQ("/bar", cc->Path());
  EXPECT_EQ(two_hours_ago, cc->CreationDate());
  EXPECT_EQ(one_hour_ago, cc->LastAccessDate());
  EXPECT_EQ(one_hour_from_now, cc->ExpiryDate());
  EXPECT_EQ(one_hour_ago, cc->LastUpdateDate());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_FALSE(cc->IsHttpOnly());
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cc->SameSite());
  EXPECT_EQ(COOKIE_PRIORITY_MEDIUM, cc->Priority());
  EXPECT_EQ(CookieSourceScheme::kSecure, cc->SourceScheme());
  EXPECT_FALSE(cc->IsDomainCookie());
  EXPECT_EQ(cc->SourcePort(), 87);

  // Should return nullptr when the cookie is not canonical.
  // In this case the cookie is not canonical because its name attribute
  // contains a newline character.
  EXPECT_FALSE(CanonicalCookie::FromStorage(
      "A\n", "B", "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure, 80,
      CookieSourceType::kUnknown));

  // If the port information gets corrupted out of the valid range
  // FromStorage() should result in a PORT_INVALID.
  std::unique_ptr<CanonicalCookie> cc2 = CanonicalCookie::FromStorage(
      "A", "B", "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure, 80000,
      CookieSourceType::kUnknown);

  EXPECT_EQ(cc2->SourcePort(), url::PORT_INVALID);

  // Test port edge cases: unspecified.
  std::unique_ptr<CanonicalCookie> cc3 = CanonicalCookie::FromStorage(
      "A", "B", "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure,
      url::PORT_UNSPECIFIED, CookieSourceType::kUnknown);
  EXPECT_EQ(cc3->SourcePort(), url::PORT_UNSPECIFIED);

  // Test port edge cases: invalid.
  std::unique_ptr<CanonicalCookie> cc4 = CanonicalCookie::FromStorage(
      "A", "B", "www.foo.com", "/bar", two_hours_ago, one_hour_from_now,
      one_hour_ago, one_hour_ago, false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, CookieSourceScheme::kSecure,
      url::PORT_INVALID, CookieSourceType::kUnknown);
  EXPECT_EQ(cc4->SourcePort(), url::PORT_INVALID);
}

TEST(CanonicalCookieTest, IsSetPermittedInContext) {
  GURL url("https://www.example.com/test");
  GURL insecure_url("http://www.example.com/test");
  base::Time current_time = base::Time::Now();

  auto cookie_scriptable = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), true /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT);
  auto cookie_httponly = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), true /*secure*/, true /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT);

  CookieOptions context_script;
  CookieOptions context_network;
  context_network.set_include_httponly();

  EXPECT_THAT(
      cookie_scriptable->IsSetPermittedInContext(
          GURL("file://foo/bar.txt"), context_network,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCookieAccessResult(
          CookieInclusionStatus::MakeFromReasonsForTesting({
              CookieInclusionStatus::EXCLUDE_NONCOOKIEABLE_SCHEME,
              CookieInclusionStatus::EXCLUDE_SECURE_ONLY,
              CookieInclusionStatus::EXCLUDE_DOMAIN_MISMATCH,
          }),
          _, _, false));

  EXPECT_THAT(
      cookie_scriptable->IsSetPermittedInContext(
          insecure_url, context_network,
          CookieAccessParams(CookieAccessSemantics::UNKNOWN,
                             false /* delegate_treats_url_as_trustworthy */
                             ),
          kCookieableSchemes),
      MatchesCo
```