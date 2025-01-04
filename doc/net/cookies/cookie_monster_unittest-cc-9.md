Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Understanding the Goal:**

The request asks for a functional description of a Chromium networking stack source file (`cookie_monster_unittest.cc`), specifically focusing on its relationship with JavaScript, logical reasoning with examples, common user/programming errors, debugging context, and a final summary. The "Part 10 of 10" indicates a summarization aspect.

**2. Initial Code Scan and Identification of Key Areas:**

The first step is to quickly read through the code, noting recurring patterns and keywords. Here are some initial observations:

* **`TEST_F(CookieMonsterTest, ...)`:** This immediately signals that the file contains unit tests for a class named `CookieMonster`.
* **`cm->FilterCookiesWithOptions(...)`:** This suggests testing the cookie filtering logic of the `CookieMonster`.
* **`EXPECT_TRUE(...)`, `EXPECT_FALSE(...)`, `EXPECT_THAT(...)`:** These are standard testing assertions, confirming that the tests are verifying specific conditions.
* **`CanonicalCookie::CreateForTesting(...)`, `CanonicalCookie::CreateSanitizedCookie(...)`, `CanonicalCookie::CreateUnsafeCookieForTesting(...)`:**  These indicate the creation and manipulation of cookie objects for testing purposes.
* **`CookieOptions`, `CookieInclusionStatus`:** These suggest tests related to different cookie settings and the reasons for including or excluding cookies.
* **`WARN_SHADOWING_DOMAIN`, `WARN_SCHEME_MISMATCH`, `WARN_PORT_MISMATCH`, `EXCLUDE_PORT_MISMATCH`, `EXCLUDE_SCHEME_MISMATCH`:** These are specific warning and exclusion reasons, indicating the tests cover various cookie binding and security scenarios.
* **`scoped_feature_list`:** This points to testing with feature flags enabled or disabled.
* **Time manipulations (`base::Time::Now()`, `base::Days(...)`)**:  Suggests tests related to cookie expiration and creation times.
* **`SetCanonicalCookie(...)`, `SetAllCookies(...)`, `GetAllCookies(...)`:**  These are methods of the `CookieMonster` being tested, indicating actions like setting and retrieving cookies.
* **`FlushablePersistentStore`, `MockPersistentCookieStore`:**  Indicates interaction with cookie storage mechanisms, both real and mocked.

**3. Categorizing the Tests:**

Based on the initial scan, we can categorize the tests into logical groups:

* **Filtering with Options:** Tests involving `FilterCookiesWithOptions` and different `CookieOptions`. This seems to be a core functionality being tested.
* **Shadowing Domain Cookies:** Tests specifically focused on the `WARN_SHADOWING_DOMAIN` warning, including scenarios with and without scheme/port binding.
* **Cookie Creation and Update:** Tests involving setting and updating cookies, focusing on how creation and expiration dates are handled, particularly with older cookies.
* **Inclusion/Exclusion Reasons:** Tests verifying specific `CookieInclusionStatus` codes for warnings and exclusions.

**4. Analyzing Individual Test Cases (and Generalizing):**

Now, we examine individual test functions to understand the specific scenarios being tested. For example:

* **`FilterCookiesWithOptionsExcludesOriginCookiesWithPortBinding`**: This clearly tests the case where origin cookies with a different port are excluded when port binding is enabled. The assertions (`EXPECT_TRUE`) confirm the expected inclusion and exclusion lists and the reason for exclusion.
* **`FilterCookiesWithOptionsWarnShadowingDomains`**: This entire block focuses on testing the `WARN_SHADOWING_DOMAIN` logic. It systematically sets up different cookie combinations (origin vs. domain, order of creation, multiple domain cookies) and verifies whether the shadowing domain cookies receive the warning.

**5. Identifying Relationships to JavaScript:**

Cookies are a fundamental part of web interactions and are heavily used by JavaScript. The key connection points are:

* **JavaScript's `document.cookie` API:**  This is the primary way JavaScript interacts with cookies. The tests in this file are essentially verifying the underlying logic that supports this API.
* **HTTP Headers (`Set-Cookie`, `Cookie`):** While not directly in the JavaScript domain, the tests implicitly relate to how cookies are set and sent via HTTP headers, which JavaScript applications rely on.

**6. Constructing Examples (Input/Output, Usage Errors):**

Based on the understanding of the test scenarios, we can construct concrete examples:

* **Input/Output:** Choose a test case like the port binding exclusion. Define a specific input URL, cookie list, and expected included/excluded cookies and their statuses.
* **Usage Errors:** Think about common mistakes developers make when dealing with cookies, such as incorrect domain or path settings, forgetting secure flags, or misunderstanding cookie scope.

**7. Determining Debugging Relevance:**

Consider how these tests would help a developer debug cookie-related issues. The tests act as examples of correct behavior and can help isolate problems related to cookie filtering, inclusion/exclusion, and shadowing.

**8. Synthesizing the Summary:**

Finally, review all the observations and categorize them into a concise summary. Highlight the main purpose of the file (testing `CookieMonster`), the key functionalities tested (filtering, shadowing, creation/update), and the overall goal of ensuring correct and secure cookie handling. The "Part 10 of 10" aspect reinforces the need for a high-level overview.

**Self-Correction/Refinement During the Process:**

* **Initial Focus Might Be Too Narrow:**  Initially, one might focus too much on individual test cases. The key is to generalize and identify the broader functionalities being tested.
* **Overlooking JavaScript Connection:**  It's important to explicitly connect the low-level C++ code to the higher-level web technologies like JavaScript.
* **Not Enough Concrete Examples:**  Abstract descriptions are less helpful than concrete examples of inputs, outputs, and potential errors.
* **Debugging Context Needs Specificity:** Instead of saying "helps with debugging," provide concrete scenarios where these tests would be relevant during debugging.

By following these steps and continually refining the understanding, we can arrive at a comprehensive and accurate description of the provided code snippet.
好的，让我们来分析一下 `net/cookies/cookie_monster_unittest.cc` 文件中的代码片段，并根据你的要求进行解答。

**文件功能概述**

这个代码片段是 Chromium 网络栈中 `CookieMonster` 类的单元测试代码。`CookieMonster` 类负责管理浏览器的 Cookie。因此，这个代码片段的主要功能是：

1. **测试 `CookieMonster` 类的各种功能**，特别是关于 Cookie 的过滤、警告和管理逻辑。
2. **验证在不同场景下，`CookieMonster` 是否按照预期工作**，例如处理不同作用域（origin, domain）、不同安全级别（http, https）、以及各种 Cookie 属性（Domain, Path, Secure, HttpOnly, SameSite）的组合。
3. **测试与 Cookie 的创建、更新和过期相关的逻辑**，包括处理旧 Cookie 和更新现有 Cookie 的情况。

**与 JavaScript 的关系及举例**

`CookieMonster` 管理的 Cookie 是 Web 浏览器与 Web 服务器之间进行状态管理的重要机制，而 JavaScript 可以通过 `document.cookie` API 来访问和操作 Cookie。 因此，`CookieMonster` 的功能直接影响着 JavaScript 中 Cookie 的行为。

**举例说明：**

* **Cookie 的过滤和访问:**  `FilterCookiesWithOptions` 函数模拟了浏览器在特定 URL 下获取 Cookie 的过程。JavaScript 代码在访问 `document.cookie` 时，浏览器会调用类似 `CookieMonster` 的逻辑来决定哪些 Cookie 可以被返回。
    * **假设输入:**  一个页面 `https://www.foo.com/bar` 尝试读取 Cookie。`CookieMonster` 中存储了以下 Cookie：
        * 一个 origin Cookie: `foo1=origin` (针对 `https://www.foo.com`)
        * 一个 domain Cookie: `foo1=domain; Domain=.foo.com`
    * **输出:** `FilterCookiesWithOptions` 会返回包含这两个 Cookie 的列表 (在没有启用 Scheme/Port Binding 的情况下)。JavaScript 通过 `document.cookie` 可以访问到这两个 Cookie。
* **Domain Cookie 的警告:**  `FilterCookiesWithOptionsWarnShadowingDomains` 测试了当一个 Domain Cookie 覆盖了 Origin Cookie 时是否会产生警告。这与 JavaScript 的行为一致，因为浏览器通常会优先使用更具体的 Cookie (例如，Origin Cookie 比 Domain Cookie 更具体)。
    * **假设输入:**  `https://www.foo.com` 页面，存在以下 Cookie:
        * `foo1=origin` (针对 `https://www.foo.com`)
        * `foo1=domain; Domain=.foo.com`
    * **输出:**  `FilterCookiesWithOptions` 在返回 Domain Cookie 时，会标记 `WARN_SHADOWING_DOMAIN` 警告。虽然 JavaScript 仍然可以访问到 Domain Cookie，但在某些开发者工具中可能会显示此警告，提示存在潜在的混淆。

**逻辑推理、假设输入与输出**

让我们以 `FilterCookiesWithOptionsExcludesOriginCookiesWithPortBinding` 这个测试用例为例进行逻辑推理：

**假设输入：**

* **URL:** `https://www.foo.com` (端口默认为 443)
* **Cookie 列表：**
    * `port_origin_cookie1`:  `foo1=differentportorigin` (Source Port: 123,  Origin: `https://www.foo.com:123`)
    * `domain_cookie1`: `foo1=domain; Domain=.foo.com` (Domain: `.foo.com`)
* **CookieOptions:** 启用了 Port Binding (`kEnablePortBoundCookies`)

**逻辑推理：**

1. 由于启用了 Port Binding，只有与请求 URL 的端口完全匹配的 Origin Cookie 才会被包含。
2. `port_origin_cookie1` 的源端口 (123) 与请求 URL 的端口 (443) 不匹配。
3. 因此，`port_origin_cookie1` 将被排除。
4. `domain_cookie1` 的 Domain 属性匹配请求 URL 的域名，并且没有端口限制，因此将被包含。

**预期输出：**

* `included`: 包含 `domain_cookie1`
* `excluded`: 包含 `port_origin_cookie1`，并且其 `access_result.status` 中包含 `CookieInclusionStatus::EXCLUDE_PORT_MISMATCH`。

**用户或编程常见的使用错误**

* **Cookie 作用域设置错误：** 开发者可能错误地设置了 Cookie 的 `Domain` 或 `Path` 属性，导致 Cookie 无法在预期的页面上生效或被意外地发送到其他域名。
    * **例子：**  在 `https://www.example.com/app1` 设置了一个 Cookie `my_cookie=value`，但错误地将 `Domain` 设置为 `.wrong-domain.com`。 这会导致该 Cookie 无法在 `www.example.com` 下访问。
* **安全 Cookie 在非 HTTPS 上使用：** 设置了 `Secure` 标志的 Cookie 只能通过 HTTPS 连接发送。如果在非 HTTPS 页面尝试设置或访问此类 Cookie，可能会导致 Cookie 设置失败或无法发送。
    * **例子：** 在 `http://www.example.com` 上尝试设置一个带有 `Secure` 标志的 Cookie，浏览器通常会阻止这个操作。
* **对 HttpOnly Cookie 的误解：**  `HttpOnly` 标志阻止 JavaScript 访问 Cookie。 开发者可能错误地认为设置了 `HttpOnly` 的 Cookie 可以通过 `document.cookie` 访问。
    * **例子：** 设置了一个 `HttpOnly` 的 Cookie `session_id=123`。 尝试在 JavaScript 中通过 `document.cookie` 读取 `session_id` 将返回空字符串或不包含该 Cookie。
* **端口绑定带来的混淆：**  如果启用了 Port Binding，开发者可能会忘记 Origin Cookie 的端口限制，导致在不同端口的同源页面上 Cookie 无法共享。
    * **例子：**  在 `https://www.example.com:8080` 上设置了一个 Origin Cookie。 当用户访问 `https://www.example.com` (默认 443 端口) 时，该 Cookie 将不会被包含，这可能会让开发者感到困惑。

**用户操作如何到达这里作为调试线索**

当用户在浏览器中进行与 Cookie 相关的操作时，可能会触发 `CookieMonster` 中的代码。以下是一些用户操作可能导致执行到这些测试所覆盖的代码逻辑的步骤：

1. **用户访问一个网站：** 当用户在地址栏输入 URL 或点击链接访问一个网站时，浏览器会发起 HTTP 请求。服务器可能会在响应头中设置 `Set-Cookie`，这会导致 `CookieMonster` 接收并存储这些 Cookie。
2. **JavaScript 操作 Cookie：** 网页上的 JavaScript 代码可以使用 `document.cookie` API 来读取、设置或删除 Cookie。 这些操作会调用 `CookieMonster` 的相应方法。
3. **用户清除 Cookie：** 用户可以通过浏览器的设置清除 Cookie。 这会触发 `CookieMonster` 清除存储的 Cookie。
4. **浏览器发送 Cookie：** 当浏览器向服务器发送请求时，会根据请求的 URL 和已存储的 Cookie，调用 `CookieMonster` 的过滤逻辑，将相关的 Cookie 添加到请求头中的 `Cookie` 字段。

**调试线索：**

* 如果用户报告某个网站的 Cookie 没有按预期工作（例如，登录状态丢失，偏好设置没有保存），开发者可以检查浏览器的开发者工具中的 "Application" 或 "Storage" 选项卡下的 "Cookies" 部分，查看当前存储的 Cookie 以及它们的属性。
* 通过网络请求的抓包工具（如 Chrome 的 DevTools 的 "Network" 选项卡），开发者可以查看请求头中的 `Cookie` 字段和响应头中的 `Set-Cookie` 字段，了解 Cookie 的发送和接收情况。
* 如果怀疑是 Cookie 的过滤逻辑问题，可以仔细检查 Cookie 的 `Domain`、`Path`、`Secure` 等属性是否正确设置，以及浏览器是否启用了 Scheme/Port Binding 等特性。
* 这些单元测试用例本身就提供了很好的调试思路。例如，如果遇到 Domain Cookie 覆盖 Origin Cookie 的问题，可以参考 `FilterCookiesWithOptionsWarnShadowingDomains` 的测试场景。

**第 10 部分功能归纳**

作为第 10 部分，这段代码主要集中在以下功能的测试：

* **在特定场景下 Domain Cookie 是否会收到 "阴影（Shadowing）" 警告**，即当 Domain Cookie 可能会覆盖同名的 Origin Cookie 时。测试覆盖了启用和禁用 Scheme/Port Binding 的情况。
* **启用了 Port Binding 时，源端口不匹配的 Origin Cookie 如何被排除**，以及这是否会影响 Domain Cookie 的包含。
* **测试 Cookie 的创建和更新逻辑**，特别是针对从存储中读取的旧 Cookie 以及如何更新它们的创建和过期时间，并验证了浏览器的 Cookie 过期时间限制策略 (clamping) 的影响。

总而言之，这个代码片段是 `CookieMonster` 类的功能测试的最后一部分，着重测试了 Cookie 过滤的高级场景，以及 Cookie 的生命周期管理，确保 Chromium 的 Cookie 管理机制的正确性和健壮性。

Prompt: 
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共10部分，请归纳一下它的功能

"""
 Origin cookies that are excluded due to port binding don't affect domain
  // cookies.
  cookie_ptrs = {port_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*domain_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*port_origin_cookie1}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_PORT_MISMATCH}));
  reset();

  // Origin cookies that are excluded due to scheme and port binding don't
  // affect domain cookies.
  cookie_ptrs = {port_insecure_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {*domain_cookie1}));
  EXPECT_TRUE(CookieListsMatch(excluded, {*port_insecure_origin_cookie1}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH,
           CookieInclusionStatus::EXCLUDE_PORT_MISMATCH}));
  reset();
}

// Test that domain cookies which shadow origin cookies have warnings when
// scheme binding is disabled.
TEST_F(CookieMonsterTest, FilterCookiesWithOptionsWarnShadowingDomains) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieOptions options = CookieOptions::MakeAllInclusive();
  options.set_return_excluded_cookies();

  auto CookieListsMatch = [](const CookieAccessResultList& actual,
                             const std::vector<CanonicalCookie*>& expected) {
    if (actual.size() != expected.size()) {
      return false;
    }

    for (size_t i = 0; i < actual.size(); i++) {
      if (!actual[i].cookie.IsEquivalent(*expected[i])) {
        return false;
      }
    }

    return true;
  };

  // Confirms that of all the cookies in `actual` only the ones also in
  // `expected` have WARN_SHADOWING_DOMAIN.
  auto DomainCookiesHaveWarnings =
      [](const CookieAccessResultList& actual,
         const std::vector<CanonicalCookie>& expected) {
        std::map<CanonicalCookie, CookieInclusionStatus> cookie_result_map;
        for (const auto& cookie_result : actual) {
          cookie_result_map.insert(
              {cookie_result.cookie, cookie_result.access_result.status});
        }

        for (const auto& cookie : expected) {
          // This is a touch hacky but will always work because if the
          // cookie_result_map doesn't contain `cookie` it'll create a default
          // entry with an empty status which will always fail the check. I.e.:
          // return false.
          if (!cookie_result_map[cookie].HasWarningReason(
                  CookieInclusionStatus::WARN_SHADOWING_DOMAIN)) {
            return false;
          }

          // Remove cookies that were part of `expected`.
          cookie_result_map.erase(cookie);
        }

        // If any of the remaining cookies have the warning, return false.
        for (const auto& item : cookie_result_map) {
          if (item.second.HasWarningReason(
                  CookieInclusionStatus::WARN_SHADOWING_DOMAIN)) {
            return false;
          }
        }

        return true;
      };

  // We only apply warnings to shadowing domain cookies when scheme binding is
  // disabled.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures(
      {}, {net::features::kEnableSchemeBoundCookies,
           net::features::kEnablePortBoundCookies});

  std::vector<CanonicalCookie*> cookie_ptrs;
  CookieAccessResultList included;
  CookieAccessResultList excluded;

  auto reset = [&cookie_ptrs, &included, &excluded]() {
    cookie_ptrs.clear();
    included.clear();
    excluded.clear();
  };

  auto origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=origin", creation_time, server_time);
  auto origin_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo2=origin", creation_time, server_time);

  auto domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Shadowing domain cookie after the origin cookie.
  cookie_ptrs = {origin_cookie1.get(), origin_cookie2.get(),
                 domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {*domain_cookie1}));
  reset();

  // Shadowing domain cookie before the origin cookie.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {*domain_cookie1}));
  reset();

  auto domain_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo2=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Multiple different shadowing domain cookies.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), domain_cookie2.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(
      DomainCookiesHaveWarnings(included, {*domain_cookie1, *domain_cookie2}));
  reset();

  auto domain_cookie3 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo3=domain; Domain=" + https_www_foo_.domain(),
      creation_time, server_time);

  // Non-shadowing domain cookie shouldn't have a warning.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), domain_cookie2.get(),
                 domain_cookie3.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(
      DomainCookiesHaveWarnings(included, {*domain_cookie1, *domain_cookie2}));
  reset();

  auto sub_domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=subdomain; Domain=" + https_www_foo_.host(),
      creation_time, server_time);

  // If there are multiple domain cookies that shadow the same cookie, they
  // should all have a warning.
  cookie_ptrs = {domain_cookie1.get(), origin_cookie2.get(),
                 origin_cookie1.get(), sub_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(
      included, {*domain_cookie1, *sub_domain_cookie1}));
  reset();

  // Domain cookies may shadow each other.
  cookie_ptrs = {domain_cookie1.get(), sub_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  reset();

  auto path_origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=pathorigin; Path=/bar", creation_time,
      server_time);

  // Origin cookies on different paths may not be shadowed, even if the
  // origin cookie wouldn't be included on this request.
  cookie_ptrs = {path_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {domain_cookie1.get()}));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {*domain_cookie1}));
  reset();

  auto insecure_origin_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), "foo1=insecureorigin", creation_time, server_time);
  EXPECT_EQ(insecure_origin_cookie1->SourceScheme(),
            CookieSourceScheme::kNonSecure);

  // Origin cookies that have a warning for scheme binding don't affect domain
  // cookies.
  cookie_ptrs = {insecure_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  EXPECT_TRUE(included[0].access_result.status.HasWarningReason(
      CookieInclusionStatus::WARN_SCHEME_MISMATCH));
  reset();

  auto insecure_domain_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(),
      "foo1=insecuredomain; Domain=" + http_www_foo_.domain(), creation_time,
      server_time);

  // Domain cookies that are excluded due to scheme binding shouldn't also get a
  // shadow warning.
  cookie_ptrs = {origin_cookie1.get(), insecure_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  EXPECT_TRUE(
      included[1].access_result.status.HasExactlyWarningReasonsForTesting(
          {CookieInclusionStatus::WARN_SCHEME_MISMATCH}));
  reset();

  // If both domain and origin cookie have warnings due to scheme binding then
  // domain cookie shouldn't get shadowing warning.
  cookie_ptrs = {insecure_origin_cookie1.get(), insecure_domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  EXPECT_TRUE(included[0].access_result.status.HasWarningReason(
      CookieInclusionStatus::WARN_SCHEME_MISMATCH));
  EXPECT_TRUE(
      included[1].access_result.status.HasExactlyWarningReasonsForTesting(
          {CookieInclusionStatus::WARN_SCHEME_MISMATCH}));
  reset();

  cm->SetCookieAccessDelegate(std::make_unique<TestCookieAccessDelegate>());

  CookieURLHelper http_www_trustworthy =
      CookieURLHelper("http://www.trustworthysitefortestdelegate.example");
  CookieURLHelper https_www_trustworthy =
      CookieURLHelper("https://www.trustworthysitefortestdelegate.example");

  auto trust_origin_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_trustworthy.url(), "foo1=trustorigin", creation_time,
      server_time);

  auto secure_trust_domain_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_trustworthy.url(),
      "foo1=securetrustdomain; Domain=" + https_www_trustworthy.domain(),
      creation_time, server_time);
  auto secure_trust_domain_cookie2 = CanonicalCookie::CreateForTesting(
      https_www_trustworthy.url(),
      "foo2=securetrustdomain; Domain=" + https_www_trustworthy.domain(),
      creation_time, server_time);

  // Securely set domain cookie has warning when shadowing trustworthy-ly set
  // origin cookies.
  cookie_ptrs = {trust_origin_cookie1.get(), secure_trust_domain_cookie1.get(),
                 secure_trust_domain_cookie2.get()};
  cm->FilterCookiesWithOptions(http_www_trustworthy.url(), options,
                               &cookie_ptrs, &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(
      DomainCookiesHaveWarnings(included, {*secure_trust_domain_cookie1}));
  reset();

  auto trust_domain_cookie1 = CanonicalCookie::CreateForTesting(
      http_www_trustworthy.url(),
      "foo1=trustdomain; Domain=" + http_www_trustworthy.domain(),
      creation_time, server_time);
  auto trust_domain_cookie2 = CanonicalCookie::CreateForTesting(
      http_www_trustworthy.url(),
      "foo2=trustdomain; Domain=" + http_www_trustworthy.domain(),
      creation_time, server_time);
  auto secure_trust_origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_trustworthy.url(), "foo1=securetrustorigin", creation_time,
      server_time);

  // Trustworthy-ly set domain cookies are excluded when shadowing securely set
  // origin cookies.
  cookie_ptrs = {secure_trust_origin_cookie1.get(), trust_domain_cookie1.get(),
                 trust_domain_cookie2.get()};
  cm->FilterCookiesWithOptions(http_www_trustworthy.url(), options,
                               &cookie_ptrs, &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {*trust_domain_cookie1}));
  reset();

  auto port_origin_cookie1 = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "foo1=differentportorigin", creation_time,
      server_time);
  port_origin_cookie1->SetSourcePort(123);

  // Origin cookies that have warnings due to port binding don't affect domain
  // cookies.
  cookie_ptrs = {port_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  EXPECT_TRUE(included[0].access_result.status.HasWarningReason(
      CookieInclusionStatus::WARN_PORT_MISMATCH));
  reset();

  auto port_insecure_origin_cookie1 =
      std::make_unique<CanonicalCookie>(*insecure_origin_cookie1);
  port_insecure_origin_cookie1->SetSourcePort(123);

  // Origin cookies that have warnings due to scheme and port binding don't
  // affect domain cookies.
  cookie_ptrs = {port_insecure_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, cookie_ptrs));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  EXPECT_TRUE(
      included[0].access_result.status.HasExactlyWarningReasonsForTesting(
          {CookieInclusionStatus::WARN_SCHEME_MISMATCH,
           CookieInclusionStatus::WARN_PORT_MISMATCH}));
  reset();

  // Enable port binding to test with port exclusions.
  scoped_feature_list.Reset();
  scoped_feature_list.InitWithFeatures(
      {net::features::kEnablePortBoundCookies},
      {net::features::kEnableSchemeBoundCookies});

  // Origin cookies that are excluded due to port binding don't affect domain
  // cookies.
  cookie_ptrs = {port_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {domain_cookie1.get()}));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  EXPECT_TRUE(CookieListsMatch(excluded, {port_origin_cookie1.get()}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_PORT_MISMATCH}));
  reset();

  // Origin cookies that are excluded due to port binding and have a scheme
  // binding warning don't affect domain cookies.
  cookie_ptrs = {port_insecure_origin_cookie1.get(), domain_cookie1.get()};
  cm->FilterCookiesWithOptions(https_www_foo_.url(), options, &cookie_ptrs,
                               &included, &excluded);
  EXPECT_TRUE(CookieListsMatch(included, {domain_cookie1.get()}));
  EXPECT_TRUE(DomainCookiesHaveWarnings(included, {}));
  EXPECT_TRUE(CookieListsMatch(excluded, {port_insecure_origin_cookie1.get()}));
  EXPECT_TRUE(
      excluded[0].access_result.status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_PORT_MISMATCH}));
  EXPECT_TRUE(excluded[0].access_result.status.HasWarningReason(
      CookieInclusionStatus::WARN_SCHEME_MISMATCH));
  reset();
}

// This test sets a cookie (only checked using IsCanonicalForFromStorage)
// that's 300 days old and expires in 800 days. It checks that this cookie was
// stored, and then update it. It checks that the updated cookie has the
// creation and expiry dates expected.
TEST_F(CookieMonsterTest, FromStorageCookieCreated300DaysAgoThenUpdatedNow) {
  auto store = base::MakeRefCounted<FlushablePersistentStore>();
  auto cookie_monster =
      std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  cookie_monster->SetPersistSessionCookies(true);
  EXPECT_TRUE(GetAllCookies(cookie_monster.get()).empty());

  // Bypass IsCanonical and store a 300 day old cookie to bypass clamping.
  base::Time original_creation = base::Time::Now() - base::Days(300);
  base::Time original_expiry = original_creation + base::Days(800);
  CookieList list;
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "." + https_www_foo_.url().host(), "/", original_creation,
      original_expiry, base::Time(), base::Time(), true, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));
  EXPECT_TRUE(SetAllCookies(cookie_monster.get(), list));

  // Verify the cookie exists and was not clamped, even if clamping is on.
  EXPECT_THAT(GetAllCookies(cookie_monster.get()),
              ElementsAre(MatchesCookieNameValueCreationExpiry(
                  "A", "B", original_creation, original_expiry)));

  // Update the cookie without bypassing clamping.
  base::Time new_creation = base::Time::Now();
  base::Time new_expiry = new_creation + base::Days(800);
  EXPECT_TRUE(SetCanonicalCookie(
      cookie_monster.get(),
      CanonicalCookie::CreateSanitizedCookie(
          https_www_foo_.url(), "A", "B", https_www_foo_.url().host(), "/",
          new_creation, new_expiry, base::Time(), true, false,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
          /*status=*/nullptr),
      https_www_foo_.url(), false));
  EXPECT_THAT(
      GetAllCookies(cookie_monster.get()),
      ElementsAre(MatchesCookieNameValueCreationExpiry(
          "A", "B", original_creation, new_creation + base::Days(400))));
}

// This test sets a cookie (only checked using IsCanonicalForFromStorage)
// that's 500 days old and expires in 800 days. It checks that this cookie was
// stored, and then update it. It checks that the updated cookie has the
// creation and expiry dates expected.
TEST_F(CookieMonsterTest, FromStorageCookieCreated500DaysAgoThenUpdatedNow) {
  auto store = base::MakeRefCounted<FlushablePersistentStore>();
  auto cookie_monster =
      std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  cookie_monster->SetPersistSessionCookies(true);
  EXPECT_TRUE(GetAllCookies(cookie_monster.get()).empty());

  // Bypass IsCanonical and store a 500 day old cookie to bypass clamping.
  base::Time original_creation = base::Time::Now() - base::Days(500);
  base::Time original_expiry = original_creation + base::Days(800);
  CookieList list;
  list.push_back(*CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "." + https_www_foo_.url().host(), "/", original_creation,
      original_expiry, base::Time(), base::Time(), true, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));
  EXPECT_TRUE(SetAllCookies(cookie_monster.get(), list));

  // Verify the cookie exists and was not clamped, even if clamping is on.
  EXPECT_THAT(GetAllCookies(cookie_monster.get()),
              ElementsAre(MatchesCookieNameValueCreationExpiry(
                  "A", "B", original_creation, original_expiry)));

  // Update the cookie without bypassing clamping.
  base::Time new_creation = base::Time::Now();
  base::Time new_expiry = new_creation + base::Days(800);
  EXPECT_TRUE(SetCanonicalCookie(
      cookie_monster.get(),
      CanonicalCookie::CreateSanitizedCookie(
          https_www_foo_.url(), "A", "B", https_www_foo_.url().host(), "/",
          new_creation, new_expiry, base::Time(), true, false,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
          /*status=*/nullptr),
      https_www_foo_.url(), false));
  EXPECT_THAT(
      GetAllCookies(cookie_monster.get()),
      ElementsAre(MatchesCookieNameValueCreationExpiry(
          "A", "B", original_creation, new_creation + base::Days(400))));
}

// This test sets a cookie (checked using IsCanonical) that's 300 days old and
// expires in 800 days. It checks that this cookie was stored, and then update
// it. It checks that the updated cookie has the creation and expiry dates
// expected.
TEST_F(CookieMonsterTest, SanitizedCookieCreated300DaysAgoThenUpdatedNow) {
  auto store = base::MakeRefCounted<FlushablePersistentStore>();
  auto cookie_monster =
      std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  cookie_monster->SetPersistSessionCookies(true);
  EXPECT_TRUE(GetAllCookies(cookie_monster.get()).empty());

  // Store a 300 day old cookie without bypassing clamping.
  base::Time original_creation = base::Time::Now() - base::Days(300);
  base::Time original_expiry = original_creation + base::Days(800);
  EXPECT_TRUE(SetCanonicalCookie(
      cookie_monster.get(),
      CanonicalCookie::CreateSanitizedCookie(
          https_www_foo_.url(), "A", "B", https_www_foo_.url().host(), "/",
          original_creation, original_expiry, base::Time(), true, false,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
          /*status=*/nullptr),
      https_www_foo_.url(), false));
  EXPECT_THAT(
      GetAllCookies(cookie_monster.get()),
      ElementsAre(MatchesCookieNameValueCreationExpiry(
          "A", "B", original_creation, original_creation + base::Days(400))));

  // Update the cookie without bypassing clamping.
  base::Time new_creation = base::Time::Now();
  base::Time new_expiry = new_creation + base::Days(800);
  EXPECT_TRUE(SetCanonicalCookie(
      cookie_monster.get(),
      CanonicalCookie::CreateSanitizedCookie(
          https_www_foo_.url(), "A", "B", https_www_foo_.url().host(), "/",
          new_creation, new_expiry, base::Time(), true, false,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
          /*status=*/nullptr),
      https_www_foo_.url(), false));
  EXPECT_THAT(
      GetAllCookies(cookie_monster.get()),
      ElementsAre(MatchesCookieNameValueCreationExpiry(
          "A", "B", original_creation, new_creation + base::Days(400))));
}

// This test sets a cookie (checked using IsCanonical) that's 500 days old and
// expires in 800 days. It checks that this cookie was stored, and then update
// it. It checks that the updated cookie has the creation and expiry dates
// expected.
TEST_F(CookieMonsterTest, SanitizedCookieCreated500DaysAgoThenUpdatedNow) {
  auto store = base::MakeRefCounted<FlushablePersistentStore>();
  auto cookie_monster =
      std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());
  cookie_monster->SetPersistSessionCookies(true);
  EXPECT_TRUE(GetAllCookies(cookie_monster.get()).empty());

  // Store a 500 day old cookie without bypassing clamping.
  base::Time original_creation = base::Time::Now() - base::Days(500);
  base::Time original_expiry = original_creation + base::Days(800);
  EXPECT_TRUE(SetCanonicalCookie(
      cookie_monster.get(),
      CanonicalCookie::CreateSanitizedCookie(
          https_www_foo_.url(), "A", "B", https_www_foo_.url().host(), "/",
          original_creation, original_expiry, base::Time(), true, false,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
          /*status=*/nullptr),
      https_www_foo_.url(), false));
  EXPECT_TRUE(GetAllCookies(cookie_monster.get()).empty());

  // Update the cookie without bypassing clamping.
  base::Time new_creation = base::Time::Now();
  base::Time new_expiry = new_creation + base::Days(800);
  EXPECT_TRUE(SetCanonicalCookie(
      cookie_monster.get(),
      CanonicalCookie::CreateSanitizedCookie(
          https_www_foo_.url(), "A", "B", https_www_foo_.url().host(), "/",
          new_creation, new_expiry, base::Time(), true, false,
          CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
          /*status=*/nullptr),
      https_www_foo_.url(), false));
  EXPECT_THAT(GetAllCookies(cookie_monster.get()),
              ElementsAre(MatchesCookieNameValueCreationExpiry(
                  "A", "B", new_creation, new_creation + base::Days(400))));
}

INSTANTIATE_TEST_SUITE_P(/* no label */,
                         CookieMonsterTestPriorityGarbageCollectionObc,
                         testing::Combine(testing::Bool(), testing::Bool()));

INSTANTIATE_TEST_SUITE_P(/* no label */,
                         CookieMonsterTestGarbageCollectionObc,
                         testing::ValuesIn(std::vector<std::tuple<bool, bool>>{
                             {true, false},
                             {false, true},
                             {true, true}}));

}  // namespace net

"""


```