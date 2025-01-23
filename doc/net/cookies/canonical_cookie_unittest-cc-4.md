Response:
The user wants a summary of the functionality of the provided C++ code snippet from `canonical_cookie_unittest.cc`. The summary should include:
1. **General Functionality:** What does this code do?
2. **Relationship to JavaScript:** Are there connections to how JavaScript interacts with cookies?
3. **Logic and Examples:** Provide examples with hypothetical inputs and outputs if there's logical reasoning in the code.
4. **Common Usage Errors:**  Point out potential mistakes users or programmers might make.
5. **User Journey (Debugging):** How might a user action lead to this code being executed (for debugging purposes)?
6. **Concise Summary:** A brief overview of the code's purpose.

Let's break down the code:

* **`TEST(CanonicalCookieTest, PartialCompare)`:**  This test checks the `PartialCompare` and `IsEquivalent` methods of `CanonicalCookie`. It seems to be verifying how cookies are compared based on essential attributes (name, domain, path).
* **`TEST(CanonicalCookieTest, SecureCookiePrefix)`:** This tests the behavior and validation of cookies with the `__Secure-` prefix. It checks if these cookies are correctly flagged as invalid if they are not secure or have other issues.
* **`TEST(CanonicalCookieTest, HostCookiePrefix)`:** Similar to the `SecureCookiePrefix` test, this focuses on cookies with the `__Host-` prefix and validates their specific requirements (secure, specific path, no domain attribute in most cases).
* **`TEST(CanonicalCookieTest, CanCreateSecureCookiesFromAnyScheme)`:** This confirms that the `CanonicalCookie::CreateForTesting` method can create cookies marked as secure even when the originating URL is HTTP (useful for testing scenarios).
* **`TEST(CanonicalCookieTest, IsCanonical)`:** This is a comprehensive test suite that verifies the `IsCanonical()` method. It checks various cookie attributes (name, value, domain, path) for validity against the cookie specification.

**Planning the response:**

1. **General Functionality:**  The core function is testing the `CanonicalCookie` class, specifically focusing on comparison, prefix handling (`__Secure-`, `__Host-`), and validation of cookie structure.
2. **JavaScript Relationship:**  JavaScript's `document.cookie` API is the primary way websites interact with cookies. The code tests the underlying logic that browsers use when parsing and validating cookies set by JavaScript.
3. **Logic and Examples:** For prefix tests, the input would be a cookie string and the output would be whether a `CanonicalCookie` object is successfully created and the `CookieInclusionStatus`. For `PartialCompare`, the input is two cookies, and the output is `true` or `false`. For `IsCanonical`, the input is a cookie string or individual attributes, and the output is `true` or `false`.
4. **Common Usage Errors:**  Incorrectly setting `__Secure-` cookies on non-HTTPS sites or not following `__Host-` cookie restrictions are common errors.
5. **User Journey:** A user visiting a website that sets cookies, or a developer manually setting cookies through developer tools, could trigger this code's logic during the cookie parsing and validation process within the browser.
6. **Concise Summary:** This code snippet tests the core functionalities of the `CanonicalCookie` class in Chromium's networking stack, particularly focusing on cookie comparison, secure/host prefix validation, and overall cookie canonicalization.

**Self-Correction/Refinement:**  Initially, I might focus too much on the low-level C++ details. However, the prompt asks for the *functionality* and its relation to JavaScript, implying a need for explanations accessible to someone familiar with web development concepts, not just C++ internals. I need to bridge the gap between the C++ test code and the user-facing aspects of cookies. Also, explicitly linking the tests to specific aspects of cookie behavior (like the requirements for `__Secure-` and `__Host-`) will be more helpful.
这是 `net/cookies/canonical_cookie_unittest.cc` 文件的一部分，主要功能是**测试 `CanonicalCookie` 类的各种特性和功能**。`CanonicalCookie` 类是 Chromium 网络栈中表示规范化 Cookie 的核心类。

**归纳一下这部分的功能：**

这部分代码主要集中在以下几个方面的测试：

1. **Cookie 的部分比较和等价性 (`PartialCompare`, `IsEquivalent`)**: 测试了在某些情况下，即使两个 Cookie 的某些属性不同，它们仍然可以被认为是“部分相等”或“等价”的逻辑。

2. **`__Secure-` 前缀的 Cookie 验证**:  测试了带有 `__Secure-` 前缀的 Cookie 的强制安全属性，例如：
    * 必须在安全（HTTPS）的上下文中设置。
    * 不能带有 `HttpOnly` 属性 (在某些情况下)。
    * 前缀大小写不敏感。
    * 只有前缀完全匹配时才生效。

3. **`__Host-` 前缀的 Cookie 验证**: 测试了带有 `__Host-` 前缀的 Cookie 的更严格的限制，例如：
    * 必须是安全的。
    * 必须从安全来源设置。
    * 不能设置 `Domain` 属性（除非是匹配 URL 的 IP 地址）。
    * `Path` 属性必须是 `/`。
    * 前缀大小写不敏感。
    * 只有前缀完全匹配时才生效。

4. **从任意 scheme 创建安全 Cookie**: 验证了即使创建 Cookie 的来源不是 HTTPS，也可以通过代码手动创建一个标记为安全的 Cookie 对象 (用于测试目的)。

5. **Cookie 的规范性 (`IsCanonical`)**:  通过大量的测试用例，验证了 `IsCanonical()` 方法是否能正确判断一个 Cookie 是否符合规范，涵盖了 Cookie 名称、值、域、路径等各种属性的合法性。

**与 JavaScript 功能的关系：**

这段代码测试的是浏览器底层处理 Cookie 的逻辑，这直接影响了 JavaScript 如何与 Cookie 交互。

* **`document.cookie` API:** 当 JavaScript 使用 `document.cookie` 设置 Cookie 时，浏览器会调用类似 `CanonicalCookie::Create` 的方法来解析和创建 Cookie 对象。这里的测试就验证了浏览器在解析和验证由 JavaScript 设置的带有 `__Secure-` 或 `__Host-` 前缀的 Cookie 时是否遵循了正确的规则。例如，如果 JavaScript 尝试在一个 HTTP 页面上设置一个 `__Secure-` Cookie，这段测试保证了浏览器会拒绝这个操作。

**举例说明：**

假设 JavaScript 代码尝试在 HTTPS 页面上设置一个 Cookie：

```javascript
document.cookie = "__Secure-MyCookie=value; Secure";
```

这段代码对应的底层逻辑就会涉及到 `CanonicalCookie::Create` 以及本段代码中 `TEST(CanonicalCookieTest, SecureCookiePrefix)` 的相关测试。如果该测试通过，则表示浏览器能够正确解析并创建这个安全的 Cookie。

假设 JavaScript 代码尝试在 HTTP 页面上设置一个 `__Secure-` Cookie：

```javascript
document.cookie = "__Secure-MyCookie=value; Secure";
```

根据 `TEST(CanonicalCookieTest, SecureCookiePrefix)` 中的测试，例如：

```c++
EXPECT_FALSE(CanonicalCookie::Create(http_url, "__Secure-A=B; Secure",
                                     creation_time, server_time,
                                     /*cookie_partition_key=*/std::nullopt,
                                     CookieSourceType::kUnknown, &status));
EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
    {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
```

这段测试会验证 `CanonicalCookie::Create` 是否会因为在非安全上下文中设置 `__Secure-` Cookie 而返回 `false`，并设置正确的排除原因。

**逻辑推理与假设输入输出：**

以 `TEST(CanonicalCookieTest, SecureCookiePrefix)` 中的一个测试用例为例：

**假设输入:**

* `https_url`: `https://www.example.test`
* `cookie_string`: `__Secure-A=B`
* 其他参数（创建时间等）

**预期输出:**

`CanonicalCookie::Create` 返回 `false`，并且 `status` 中包含 `CookieInclusionStatus::EXCLUDE_INVALID_PREFIX`，因为 `__Secure-` Cookie 必须带有 `Secure` 属性。

**假设输入:**

* `http_url`: `http://www.example.test`
* `cookie_string`: `__Secure-A=B; Secure`
* 其他参数

**预期输出:**

`CanonicalCookie::Create` 返回 `false`，并且 `status` 中包含 `CookieInclusionStatus::EXCLUDE_INVALID_PREFIX`，因为 `__Secure-` Cookie 只能在安全上下文中设置。

**用户或编程常见的使用错误：**

1. **在非 HTTPS 网站上设置 `__Secure-` Cookie:**  这是最常见的错误。开发者可能会忘记 `__Secure-` 前缀的强制安全要求，在 HTTP 页面尝试设置此类 Cookie，导致 Cookie 被浏览器拒绝。

   **例子：** 用户访问了一个 HTTP 网站 `http://example.com`，该网站的 JavaScript 尝试设置 `document.cookie = "__Secure-Token=abc; Secure";`。这段代码在 `CanonicalCookieTest.SecureCookiePrefix` 的相关测试中会被验证为无效。

2. **设置 `__Host-` Cookie 时不满足所有要求:**  例如，忘记设置 `Secure` 属性，或者设置了 `Domain` 属性，或者 `Path` 不是 `/`。

   **例子：** 用户访问了一个 HTTPS 网站 `https://example.com`，该网站的 JavaScript 尝试设置 `document.cookie = "__Host-Session=123";`。这段代码在 `CanonicalCookieTest.HostCookiePrefix` 的相关测试中会被验证为无效，因为它缺少 `Secure` 和 `Path=/` 属性。

3. **拼写错误的 Cookie 前缀:**  如果开发者不小心将 `__Secure-` 拼写成 `_Secure-` 或 `__Secure`，那么相关的安全限制将不会生效。测试用例中明确验证了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问网站:** 用户在浏览器地址栏输入网址或点击链接访问一个网站。
2. **网站响应:** 服务器返回 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 执行:** 浏览器加载并执行网页中的 JavaScript 代码。
4. **设置 Cookie:** JavaScript 代码调用 `document.cookie` API 尝试设置 Cookie，例如：`document.cookie = "mycookie=value";` 或带有前缀的 Cookie。
5. **Cookie 解析和验证:** 浏览器内核的网络栈接收到设置 Cookie 的指令，并调用 `CanonicalCookie::Create` 或类似的方法来解析 Cookie 字符串，并根据规则进行验证，这正是 `canonical_cookie_unittest.cc` 中测试的逻辑。
6. **`CanonicalCookieTest` 运行 (开发/测试阶段):**  当 Chromium 的开发者进行测试时，会运行 `canonical_cookie_unittest.cc` 中的测试用例，模拟各种 Cookie 设置场景，以确保 `CanonicalCookie` 类的行为符合预期。如果用户在实际使用中遇到 Cookie 相关的问题，开发者可以通过复现用户的操作，查看网络请求头和 Cookie 信息，并结合 `canonical_cookie_unittest.cc` 中的测试用例，来定位问题是否出在 Cookie 的解析和验证阶段。例如，如果一个 `__Secure-` Cookie 没有按预期工作，开发者可以查看是否是因为网站在非 HTTPS 环境下设置了该 Cookie，这与 `SecureCookiePrefix` 的测试用例直接相关。

总而言之，这段代码是 Chromium 中非常重要的测试代码，它确保了浏览器在处理各种类型的 Cookie 时，特别是带有 `__Secure-` 和 `__Host-` 前缀的 Cookie 时，能够严格遵守安全规范，从而保护用户的隐私和安全。

### 提示词
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
));
  EXPECT_FALSE(cookie_different_value->PartialCompare(*cookie));

  // Cookies identical for PartialCompare() are equivalent.
  EXPECT_TRUE(cookie->IsEquivalent(*cookie_different_value));
  EXPECT_TRUE(cookie->IsEquivalent(*cookie));
}

TEST(CanonicalCookieTest, SecureCookiePrefix) {
  GURL https_url("https://www.example.test");
  GURL http_url("http://www.example.test");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieInclusionStatus status;

  // A __Secure- cookie must be Secure.
  EXPECT_FALSE(CanonicalCookie::Create(https_url, "__Secure-A=B", creation_time,
                                       server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::Create(https_url, "__Secure-A=B; httponly",
                                       creation_time, server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  // (EXCLUDE_HTTP_ONLY would be fine, too)
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // Prefixes are case insensitive.
  EXPECT_FALSE(CanonicalCookie::CreateForTesting(https_url, "__secure-A=C;",
                                                 creation_time, server_time));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::CreateForTesting(https_url, "__SECURE-A=C;",
                                                 creation_time, server_time));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::CreateForTesting(https_url, "__SeCuRe-A=C;",
                                                 creation_time, server_time));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // A typoed prefix does not have to be Secure.
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__SecureA=B; Secure", creation_time, server_time));
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(https_url, "__SecureA=C;",
                                                creation_time, server_time));
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(https_url, "_Secure-A=C;",
                                                creation_time, server_time));
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(https_url, "Secure-A=C;",
                                                creation_time, server_time));

  // A __Secure- cookie can't be set on a non-secure origin.
  EXPECT_FALSE(CanonicalCookie::Create(http_url, "__Secure-A=B; Secure",
                                       creation_time, server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // Hidden __Secure- prefixes should be rejected.
  EXPECT_FALSE(CanonicalCookie::Create(https_url, "=__Secure-A=B; Secure",
                                       creation_time, server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::Create(https_url, "=__Secure-A; Secure",
                                       creation_time, server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // While tricky, this isn't considered hidden and is fine.
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "A=__Secure-A=B; Secure", creation_time, server_time));
}

TEST(CanonicalCookieTest, HostCookiePrefix) {
  GURL https_url("https://www.example.test");
  GURL http_url("http://www.example.test");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  std::string domain = https_url.host();
  CookieInclusionStatus status;

  // A __Host- cookie must be Secure.
  EXPECT_FALSE(CanonicalCookie::Create(https_url, "__Host-A=B;", creation_time,
                                       server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::Create(
      https_url, "__Host-A=B; Domain=" + domain + "; Path=/;", creation_time,
      server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__Host-A=B; Path=/; Secure;", creation_time, server_time));

  // A __Host- cookie must be set from a secure scheme.
  EXPECT_FALSE(CanonicalCookie::Create(
      http_url, "__Host-A=B; Domain=" + domain + "; Path=/; Secure;",
      creation_time, server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__Host-A=B; Path=/; Secure;", creation_time, server_time));

  // A __Host- cookie can't have a Domain.
  EXPECT_FALSE(CanonicalCookie::Create(
      https_url, "__Host-A=B; Domain=" + domain + "; Path=/; Secure;",
      creation_time, server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::Create(
      https_url, "__Host-A=B; Domain=" + domain + "; Secure;", creation_time,
      server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // A __Host- cookie may have a domain if it's an IP address that matches the
  // URL.
  EXPECT_TRUE(CanonicalCookie::Create(
      GURL("https://127.0.0.1"),
      "__Host-A=B; Domain=127.0.0.1; Path=/; Secure;", creation_time,
      server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  // A __Host- cookie with an IP address domain does not need the domain
  // attribute specified explicitly (just like a normal domain).
  EXPECT_TRUE(CanonicalCookie::Create(
      GURL("https://127.0.0.1"), "__Host-A=B; Domain=; Path=/; Secure;",
      creation_time, server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));

  // A __Host- cookie must have a Path of "/".
  EXPECT_FALSE(CanonicalCookie::Create(
      https_url, "__Host-A=B; Path=/foo; Secure;", creation_time, server_time,
      /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
      &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::Create(https_url, "__Host-A=B; Secure;",
                                       creation_time, server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__Host-A=B; Secure; Path=/;", creation_time, server_time));

  // Prefixes are case insensitive.
  EXPECT_FALSE(CanonicalCookie::Create(
      http_url, "__host-A=B; Domain=" + domain + "; Path=/;", creation_time,
      server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  EXPECT_FALSE(CanonicalCookie::Create(
      http_url, "__HOST-A=B; Domain=" + domain + "; Path=/;", creation_time,
      server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  EXPECT_FALSE(CanonicalCookie::Create(
      http_url, "__HoSt-A=B; Domain=" + domain + "; Path=/;", creation_time,
      server_time, /*cookie_partition_key=*/std::nullopt,
      CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // Rules don't apply for a typoed prefix.
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__HostA=B; Domain=" + domain + "; Secure;", creation_time,
      server_time));

  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "_Host-A=B; Domain=" + domain + "; Secure;", creation_time,
      server_time));

  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "Host-A=B; Domain=" + domain + "; Secure;", creation_time,
      server_time));

  // Hidden __Host- prefixes should be rejected.
  EXPECT_FALSE(CanonicalCookie::Create(
      https_url, "=__Host-A=B; Path=/; Secure;", creation_time, server_time,
      /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
      &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));
  EXPECT_FALSE(CanonicalCookie::Create(https_url, "=__Host-A; Path=/; Secure;",
                                       creation_time, server_time,
                                       /*cookie_partition_key=*/std::nullopt,
                                       CookieSourceType::kUnknown, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // While tricky, this isn't considered hidden and is fine.
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "A=__Host-A=B; Path=/; Secure;", creation_time, server_time));
}

TEST(CanonicalCookieTest, CanCreateSecureCookiesFromAnyScheme) {
  GURL http_url("http://www.example.com");
  GURL https_url("https://www.example.com");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  std::unique_ptr<CanonicalCookie> http_cookie_no_secure(
      CanonicalCookie::CreateForTesting(http_url, "a=b", creation_time,
                                        server_time));
  std::unique_ptr<CanonicalCookie> http_cookie_secure(
      CanonicalCookie::CreateForTesting(http_url, "a=b; Secure", creation_time,
                                        server_time));
  std::unique_ptr<CanonicalCookie> https_cookie_no_secure(
      CanonicalCookie::CreateForTesting(https_url, "a=b", creation_time,
                                        server_time));
  std::unique_ptr<CanonicalCookie> https_cookie_secure(
      CanonicalCookie::CreateForTesting(https_url, "a=b; Secure", creation_time,
                                        server_time));

  EXPECT_TRUE(http_cookie_no_secure.get());
  EXPECT_TRUE(http_cookie_secure.get());
  EXPECT_TRUE(https_cookie_no_secure.get());
  EXPECT_TRUE(https_cookie_secure.get());
}

TEST(CanonicalCookieTest, IsCanonical) {
  // Base correct template.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "x.y", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Newline in name.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A\n", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Carriage return in name.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A\r", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Null character in name.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   std::string("A\0Z", 3), "B", "x.y", "/path", base::Time(),
                   base::Time(), base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Name begins with whitespace.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   " A", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Name ends with whitespace.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A ", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Empty name.  (Note this is against the spec but compatible with other
  // browsers.)
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "", "B", "x.y", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Space in name
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A C", "B", "x.y", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Extra space suffixing name.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A ", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // '=' character in name.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A=", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Separator in name.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A;", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // '=' character in value.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B=", "x.y", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Separator in value.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B;", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Separator in domain.
  //
  // TODO(crbug.com/40256677): The character ';' is permitted in the URL
  // host. That makes IsCanonical() return true here. However, previously,
  // IsCanonical() used to false because ';' was a forbidden character. We need
  // to verify whether this change is acceptable or not.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", ";x.y", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Garbage in domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "@:&", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Space in domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "x.y ", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Empty domain.  (This is against cookie spec, but needed for Chrome's
  // out-of-spec use of cookies for extensions; see http://crbug.com/730633.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Path does not start with a "/".
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "x.y", "path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Empty path.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "x.y", "", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // "localhost" as domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "localhost", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // non-ASCII domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "\xC3\xA9xample.com", "/path", base::Time(),
                   base::Time(), base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // punycode domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "xn--xample-9ua.com", "/path", base::Time(),
                  base::Time(), base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Localhost IPv4 address as domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "127.0.0.1", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Simple IPv4 address as domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "1.2.3.4", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // period-prefixed IPv4 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", ".1.3.2.4", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // period-prefixed truncated IPv4 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", ".3.2.4", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // truncated IPv4 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "3.2.4", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Non-canonical IPv4 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "01.2.03.4", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Non-canonical IPv4 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "16843009", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Non-canonical IPv4 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "0x1010101", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Null IPv6 address as domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "[::]", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Localhost IPv6 address as domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "[::1]", "/path", base::Time(), base::Time(),
                  base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Fully speced IPv6 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "[2001:0DB8:AC10:FE01:0000:0000:0000:0000]",
                   "/path", base::Time(), base::Time(), base::Time(),
                   base::Time(), false, false, CookieSameSite::NO_RESTRICTION,
                   COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Zero abbreviated IPv6 address as domain.  Not canonical because of leading
  // zeros & uppercase hex letters.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "[2001:0DB8:AC10:FE01::]", "/path", base::Time(),
                   base::Time(), base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Zero prefixes removed IPv6 address as domain.  Not canoncial because of
  // uppercase hex letters.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "[2001:DB8:AC10:FE01::]", "/path", base::Time(),
                   base::Time(), base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Lowercased hex IPv6 address as domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "[2001:db8:ac10:fe01::]", "/path", base::Time(),
                  base::Time(), base::Time(), base::Time(), false, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Lowercased hex IPv6 address as domain for domain cookie.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", ".[2001:db8:ac10:fe01::]", "/path", base::Time(),
                   base::Time(), base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Incomplete lowercased hex IPv6 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "[2001:db8:ac10:fe01:]", "/path", base::Time(),
                   base::Time(), base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Missing square brackets in IPv6 address as domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "2606:2800:220:1:248:1893:25c8:1946", "/path",
                   base::Time(), base::Time(), base::Time(), base::Time(),
                   false, false, CookieSameSite::NO_RESTRICTION,
                   COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Properly formatted host cookie.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "__Host-A", "B", "x.y", "/", base::Time(), base::Time(),
                  base::Time(), base::Time(), true, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Insecure host cookie.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "__Host-A", "B", "x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Host cookie with non-null path.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "__Host-A", "B", "x.y", "/path", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Host cookie with empty domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "__Host-A", "B", "", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Host cookie with period prefixed domain.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "__Host-A", "B", ".x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Properly formatted secure cookie.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "__Secure-A", "B", "x.y", "/", base::Time(), base::Time(),
                  base::Time(), base::Time(), true, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  // Insecure secure cookie.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "__Secure-A", "B", "x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), false, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  // Partitioned attribute used correctly (__Host- prefix).
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "__Host-A", "B", "x.y", "/", base::Time(), base::Time(),
                  base::Time(), base::Time(), /*secure=*/true,
                  /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                  COOKIE_PRIORITY_LOW,
                  CookiePartitionKey::FromURLForTesting(
                      GURL("https://toplevelsite.com")))
                  ->IsCanonical());

  // Partitioned attribute with no __Host- prefix is still valid if it has
  // Secure, Path=/, and no Domain.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "x.y", "/", base::Time(), base::Time(),
                  base::Time(), base::Time(), /*secure=*/true,
                  /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                  COOKIE_PRIORITY_LOW,
                  CookiePartitionKey::FromURLForTesting(
                      GURL("https://toplevelsite.com")))
                  ->IsCanonical());

  // Partitioned attribute invalid, not Secure.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "A", "B", "x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), /*secure=*/false,
                   /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                   COOKIE_PRIORITY_LOW,
                   CookiePartitionKey::FromURLForTesting(
                       GURL("https://toplevelsite.com")))
                   ->IsCanonical());

  // Partitioned attribute is valid when Path != "/".
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", "x.y", "/foo/bar", base::Time(), base::Time(),
                  base::Time(), base::Time(), /*secure=*/true,
                  /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                  COOKIE_PRIORITY_LOW,
                  CookiePartitionKey::FromURLForTesting(
                      GURL("https://toplevelsite.com")))
                  ->IsCanonical());

  // Partitioned attribute is valid when Domain attribute also included.
  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "A", "B", ".x.y", "/", base::Time(), base::Time(),
                  base::Time(), base::Time(), /*secure=*/true,
                  /*httponly=*/false, CookieSameSite::UNSPECIFIED,
                  COOKIE_PRIORITY_LOW,
                  CookiePartitionKey::FromURLForTesting(
                      GURL("https://toplevelsite.com")))
                  ->IsCanonical());

  // Hidden cookie prefixes.
  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "", "__Secure-a=b", "x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "", "__Secure-a", "x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "", "__Host-a=b", "x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  EXPECT_FALSE(CanonicalCookie::CreateUnsafeCookieForTesting(
                   "", "__Host-a", "x.y", "/", base::Time(), base::Time(),
                   base::Time(), base::Time(), true, false,
                   CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                   ->IsCanonical());

  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
```