Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Understanding the Goal:**

The core request is to analyze a specific C++ source file (`canonical_cookie_unittest.cc`) from Chromium's network stack. The analysis should cover its functionality, relationship to JavaScript, logical reasoning (with examples), common user/programming errors, debugging context, and a summary of its purpose within a larger sequence of analysis.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code to identify key elements and patterns. I look for:

* **`#include` directives:** These point to dependencies and provide hints about the file's focus. Seeing `<gurl.h>`, `<base/time/time.h>`,  `"net/cookies/canonical_cookie.h"` strongly suggests this file is about testing cookie functionality. The presence of `<base/test/histogram_tester.h>` indicates testing of metrics and histograms.
* **`TEST()` macros:**  These are the clear indicators of unit tests. Each `TEST()` block focuses on testing a specific aspect of the `CanonicalCookie` class.
* **Function names within `TEST()`:** These give specific clues about what's being tested. Examples: `IsCanonical`, `TestSetCreationDate`, `TestPrefixHistograms`, `BuildCookieLine`, `CreateSanitizedCookie_Inputs`, `CreateSanitizedCookie_Logic`.
* **Assertions (e.g., `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`):** These are the core of the tests, verifying expected behavior.
* **Specific cookie-related terms:**  "Secure", "Host", "SameSite", "Path", "Domain", "HttpOnly", "Partitioned", "Priority".
* **Use of `base::Time`:**  Indicates testing of time-related cookie attributes.
* **Use of `GURL`:**  Suggests testing in the context of URLs.
* **Use of `CookieInclusionStatus`:**  Implies testing the conditions under which cookies are accepted or rejected.
* **Use of `base::HistogramTester`:** Points to testing of cookie-related metrics.

**3. Categorizing Functionality Based on Tests:**

Based on the function names within the `TEST()` macros, I can start categorizing the functionality being tested:

* **Basic Cookie Creation and Properties:** `IsCanonical`, `TestSetCreationDate`.
* **Cookie Prefix Handling:** `TestPrefixHistograms` (focusing on `__Secure-` and `__Host-`).
* **Non-ASCII Character Handling:** `TestHasNonASCIIHistograms`.
* **Cookie Line Construction:** `BuildCookieLine`, `BuildCookieAttributesLine`.
* **Sanitized Cookie Creation (Comprehensive):** `CreateSanitizedCookie_Inputs` (testing parameter passing) and `CreateSanitizedCookie_Logic` (testing validation and business logic).

**4. Analyzing Each Test Case in Detail:**

For each `TEST()` case, I examine the specific assertions and the setup to understand *what* is being tested and *how*. For instance:

* In `IsCanonical`, the code creates cookies with `__Secure-` and `__Host-` prefixes and checks if they are considered "canonical". This highlights the special requirements for these prefixes.
* In `TestPrefixHistograms`, the use of `HistogramTester` and `ExpectBucketCount` directly shows that the test is verifying that cookie prefix usage is being recorded in histograms for analysis.
* `CreateSanitizedCookie_Logic` is the most extensive, covering various scenarios of valid and invalid cookie attributes, domain matching, secure contexts, and the `CookieInclusionStatus`.

**5. Identifying Relationships to JavaScript:**

This requires connecting the C++ cookie handling logic to how JavaScript interacts with cookies. Key points:

* **`document.cookie`:**  This is the primary way JavaScript reads and writes cookies. The C++ code is responsible for *implementing* the underlying cookie storage and retrieval mechanisms that JavaScript relies on.
* **Cookie attributes:**  The attributes tested in the C++ code (e.g., `Secure`, `HttpOnly`, `SameSite`) directly correspond to attributes that can be set (or are implicitly set) when JavaScript manipulates cookies.
* **Security implications:** The tests for `__Secure-` and `__Host-` prefixes, as well as the `Secure` attribute, have direct security implications for web applications and how JavaScript can access cookies.

**6. Constructing Logical Reasoning Examples (Input/Output):**

For each significant test area, I create simple, illustrative examples:

* **`IsCanonical`:** Show a valid and an invalid case (e.g., missing `Secure` for `__Secure-`).
* **`CreateSanitizedCookie_Logic`:**  Demonstrate both successful creation and failure scenarios with clear reasons (e.g., invalid domain, missing `Secure`).

**7. Identifying Common User/Programming Errors:**

This involves thinking about how developers might misuse cookies and how the C++ code prevents or handles those errors:

* Incorrectly setting `Secure` for secure prefixes.
* Domain mismatches.
* Invalid path settings.
* Trying to set `__Host-` cookies with a domain.
* Issues with non-ASCII characters (though the code handles them, developers might not be aware of the implications).

**8. Tracing User Operations to the Code:**

This requires understanding the flow of how cookie-related actions in a browser lead to this C++ code:

* User visits a website.
* Server sends `Set-Cookie` headers.
* Browser's network stack parses these headers (this is where `CanonicalCookie::CreateForTesting` and `CanonicalCookie::CreateSanitizedCookie` are involved).
* JavaScript uses `document.cookie` to read or set cookies, which interacts with the browser's underlying cookie storage (managed by code like this).

**9. Summarizing Functionality (Part 6 of 9):**

Given that this is part 6 of 9, the summary should focus on the specific aspects covered in this file. It's primarily about the *correct construction and validation* of individual cookies, including security considerations and attribute handling. It sets the stage for broader cookie management and policy enforcement covered in other parts.

**10. Structuring the Response:**

Finally, the information needs to be organized logically, using clear headings and bullet points to enhance readability. The structure should follow the requirements of the prompt: functionality, JavaScript relationship, logical reasoning, user errors, debugging context, and summary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on individual test cases. **Correction:**  Group tests by the broader functionality they demonstrate.
* **Initial thought:** Provide highly technical C++ details. **Correction:** Explain concepts in a way that is accessible even to someone with limited C++ knowledge, focusing on the *what* and *why*.
* **Initial thought:**  Overlook the JavaScript connection. **Correction:**  Explicitly link the C++ code to JavaScript APIs and concepts.
* **Initial thought:**  Not provide enough concrete examples. **Correction:** Add specific input/output examples for the logical reasoning section.

By following this systematic approach, combining code analysis with an understanding of web technologies and common developer practices, it's possible to generate a comprehensive and informative response to the given prompt.这是对 `net/cookies/canonical_cookie_unittest.cc` 文件代码的第 6 部分分析，基于你提供的代码片段，我们可以归纳一下这部分代码的主要功能：

**核心功能：`CanonicalCookie` 类的单元测试，重点关注其创建、属性设置、以及与安全相关的特性。**

具体来说，这部分测试用例主要验证了以下几个方面的功能：

1. **`IsCanonical()` 方法的测试:**
   - 验证了带有 `__Secure-` 和 `__Host-` 前缀的 Cookie 在正确设置安全属性时（`Secure` 为 true）能够被认为是 "canonical" 的，即符合特定规范的。
   - 这表明了 `CanonicalCookie` 类在处理具有安全前缀的 Cookie 时会强制执行安全要求。

2. **`TestSetCreationDate()` 的测试:**
   - 验证了可以成功设置 Cookie 的创建日期，并且能够正确获取到设置后的日期。
   - 这确保了 `CanonicalCookie` 对象能够正确管理和存储创建时间信息。

3. **`TestPrefixHistograms()` 的测试:**
   - 测试了当创建带有 `__Secure-` 和 `__Host-` 前缀的 Cookie 时，会记录相应的直方图数据。
   - 这表明 Chromium 在监控和分析不同类型的 Cookie 前缀的使用情况，这对于了解网络行为和潜在的安全风险很有用。

4. **`TestHasNonASCIIHistograms()` 的测试:**
   - 测试了当 Cookie 的名称或值包含非 ASCII 字符时，会记录相应的直方图数据。
   - 这表明 Chromium 也在监控非 ASCII 字符在 Cookie 中的使用情况，这对于处理国际化和潜在的编码问题很重要。

5. **`BuildCookieLine()` 的测试:**
   - 验证了 `CanonicalCookie` 类能够将多个 `CanonicalCookie` 对象构建成一个符合 HTTP `Cookie` 请求头的字符串。
   - 测试了不同 Cookie 的组合，包括无名 Cookie、带有 `;` 分隔符的 Cookie，以及重复的 Cookie。
   - 特别指出，该方法不会重新排序或去重 Cookie，这需要调用者来保证。
   - 强调了即使生成的是 "invalid" 的 Cookie 行（例如，空名称但包含 `=` 的值），该方法也会按照规范生成。

6. **`BuildCookieAttributesLine()` 的测试:**
   - 验证了 `CanonicalCookie` 类能够将单个 `CanonicalCookie` 对象构建成一个包含所有属性的字符串，类似于 HTTP `Set-Cookie` 响应头的一部分。
   - 测试了包含不同属性的 Cookie，例如 `domain`, `path`, `secure`, `httponly`, `partitioned`, `samesite`。

7. **`CreateSanitizedCookie_Inputs()` 的测试:**
   - 验证了 `CreateSanitizedCookie` 方法能够正确地将输入的参数值反映到创建的 `CanonicalCookie` 对象中。
   - 测试了各种属性，包括名称、值、域、路径、创建日期、最后访问日期、过期日期、`secure`、`httponly`、`samesite`、`priority` 和 `partition_key`。

8. **`CreateSanitizedCookie_Logic()` 的测试:**
   - 这是这部分代码中最详尽的测试，验证了 `CreateSanitizedCookie` 方法在创建 Cookie 时的各种逻辑判断和限制：
     - **基本路径和域的校验:** 验证了路径和域名的基本匹配规则。
     - **`file://` 协议的处理:** 验证了对于 `file://` 协议的特殊处理，域名限制较少。
     - **非法属性的处理:** 验证了对于名称、值、域和路径中包含非法字符的 Cookie 会创建失败，并记录相应的排除原因。
     - **域名设置的逻辑:** 验证了带或不带前导点的域名设置，以及跨域设置的拒绝。
     - **`Secure` 属性与 URL 协议的匹配:**  验证了在 `http://` 站点设置 `secure` Cookie 会发出警告。
     - **创建日期和最后访问日期的冲突:** 验证了当创建日期为空但最后访问日期不为空时会创建失败。
     - **域名与 URL 不匹配的情况:** 验证了域名与当前 URL 不匹配时会创建失败。
     - **路径的转义:** 验证了路径中特殊字符会被正确转义。
     - **空名称和空值的处理:** 验证了空名称和空值的 Cookie 会创建失败。
     - **值中包含 `=` 的处理:** 验证了值中可以包含 `=`，即使名称为空。
     - **名称中包含 `=` 的处理:** 验证了名称中包含 `=` 会创建失败。
     - **`__Secure-` 前缀的要求:** 验证了带有 `__Secure-` 前缀的 Cookie 必须设置 `Secure` 属性为 true。
     - **`__Host-` 前缀的要求:** 验证了带有 `__Host-` 前缀的 Cookie 必须设置 `Secure` 属性为 true，路径必须为 `/`，且不能指定域。
     - **不带 `__Host-` 前缀的 Host Cookie:** 验证了不带 `__Host-` 前缀但未指定域名的 Cookie 是有效的 Host Cookie。

**与 JavaScript 的关系：**

这个文件中的测试主要关注的是浏览器底层网络栈中 Cookie 的 **解析、验证和表示**。它与 JavaScript 的功能关系密切，因为：

* **`document.cookie` API 的底层实现:** JavaScript 通过 `document.cookie` API 来读取、设置和管理 Cookie。`CanonicalCookie` 类及其相关的逻辑是浏览器处理这些操作的基础。当 JavaScript 设置一个 Cookie 时，浏览器会使用类似 `CreateSanitizedCookie` 这样的方法来验证和创建 `CanonicalCookie` 对象。
* **安全策略的执行:**  例如，对于 `__Secure-` 和 `__Host-` 前缀的强制要求，直接影响了 JavaScript 能否成功设置这些具有安全意义的 Cookie。如果 JavaScript 尝试在不满足安全条件的情况下设置这些 Cookie，底层的 `CanonicalCookie` 创建过程就会失败。

**JavaScript 举例说明：**

```javascript
// 尝试设置一个 __Secure- 前缀的 Cookie，但不使用 HTTPS
document.cookie = "__Secure-mycookie=value; path=/;"; // 这在非 HTTPS 站点上设置会失败，因为 CanonicalCookie 的校验

// 尝试设置一个 __Host- 前缀的 Cookie，并指定了域名
document.cookie = "__Host-mycookie=value; path=/; domain=example.com; secure"; // 这也会失败，因为 __Host- Cookie 不允许指定域名
```

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

* `url`: `https://www.example.com`
* `cookie_string`: `__Secure-test=value; path=/; secure`

**预期输出 1:**

* `CreateSanitizedCookie` 方法成功创建一个 `CanonicalCookie` 对象，其 `name` 为 `__Secure-test`，`value` 为 `value`，`path` 为 `/`，`secure` 为 `true`，`IsCanonical()` 返回 `true`。
* `TestPrefixHistograms` 会记录 `COOKIE_PREFIX_SECURE` 的计数增加。

**假设输入 2:**

* `url`: `http://www.example.com`
* `cookie_string`: `__Secure-test=value; path=/; secure`

**预期输出 2:**

* `CreateSanitizedCookie` 方法成功创建一个 `CanonicalCookie` 对象，但 `CookieInclusionStatus` 会包含一个警告 (`WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME`)，因为在非安全上下文设置了 `secure` 属性。尽管如此，由于某些历史原因，这个 Cookie 仍然可能被接受，但会受到限制。
* `IsCanonical()` 返回 `true`。
* `TestPrefixHistograms` 会记录 `COOKIE_PREFIX_SECURE` 的计数增加。

**假设输入 3:**

* `url`: `https://www.example.com`
* `cookie_string`: `__Host-test=value; path=/; domain=example.com; secure`

**预期输出 3:**

* `CreateSanitizedCookie` 方法创建失败，`CookieInclusionStatus` 会包含 `EXCLUDE_INVALID_PREFIX`，因为 `__Host-` 前缀的 Cookie 不允许指定域名。

**用户或编程常见的使用错误举例说明:**

1. **在非 HTTPS 站点上设置带有 `Secure` 属性的 Cookie：** 用户可能认为只要设置了 `Secure` 属性，Cookie 就一定是安全的，但如果当前页面不是通过 HTTPS 加载的，浏览器可能会拒绝设置或者发出警告。
   - **用户操作：** 访问一个 `http://` 开头的网站，JavaScript 代码尝试设置 `document.cookie = "mycookie=value; secure";`
   - **到达这里：** 当浏览器尝试存储这个 Cookie 时，`CreateSanitizedCookie` 会检查 URL 的协议和 Cookie 的 `Secure` 属性，发现不匹配，可能会设置 `CookieInclusionStatus` 的警告信息。

2. **错误地使用 `__Secure-` 或 `__Host-` 前缀：** 开发者可能不理解这些前缀的严格要求，错误地设置了 Cookie 的属性。
   - **用户操作：** 网站开发者编写 JavaScript 代码尝试设置 `document.cookie = "__Secure-mycookie=value; path=/;";` 在一个 `http://` 站点上。
   - **到达这里：** `CreateSanitizedCookie` 检测到 `__Secure-` 前缀，但 `secure` 属性为 false（或者当前上下文不是安全的），会设置 `CookieInclusionStatus` 的 `EXCLUDE_INVALID_PREFIX` 错误。

3. **设置 `__Host-` Cookie 时指定了域名或错误的路径：**  开发者可能想利用 `__Host-` 的安全性，但没有完全理解其限制。
   - **用户操作：** 网站开发者编写 JavaScript 代码尝试设置 `document.cookie = "__Host-mycookie=value; path=/foo; secure";`
   - **到达这里：** `CreateSanitizedCookie` 检测到 `__Host-` 前缀，但路径不是 `/`，会设置 `CookieInclusionStatus` 的 `EXCLUDE_INVALID_PREFIX` 错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

当开发者在 Chromium 内核中调试 Cookie 相关问题时，可能会设置断点在 `net/cookies/canonical_cookie_unittest.cc` 文件中的测试用例中，或者在 `net/cookies/canonical_cookie.cc` 文件中的实际实现代码中。

1. **开发者发现一个 Cookie 设置或行为异常的问题。** 例如，一个带有 `Secure` 属性的 Cookie 在 HTTPS 站点上应该能被设置，但实际上没有。
2. **开发者可能会首先查看浏览器的开发者工具中的 "Application" -> "Cookies" 部分，观察 Cookie 的实际状态。**
3. **为了深入了解问题，开发者可能会开始阅读 Chromium 的 Cookie 相关代码，或者搜索相关的错误信息和日志。**
4. **如果怀疑是 Cookie 的解析或验证过程有问题，开发者可能会在 `CanonicalCookie::CreateForTesting` 或 `CanonicalCookie::CreateSanitizedCookie` 等关键函数设置断点。**
5. **通过单步调试，开发者可以观察 Cookie 字符串是如何被解析的，各种属性是如何被提取和验证的，以及 `CookieInclusionStatus` 是如何被设置的。**
6. **`canonical_cookie_unittest.cc` 中的测试用例可以作为参考，帮助开发者理解代码的预期行为，并编写新的测试用例来复现和验证他们发现的问题。** 例如，如果发现 `__Host-` Cookie 的处理有问题，开发者可能会查看或修改 `CanonicalCookieTest.CreateSanitizedCookie_Logic` 中关于 `__Host-` 的测试用例。

**总结 (功能归纳):**

总而言之，`net/cookies/canonical_cookie_unittest.cc` 的这部分代码主要负责对 `CanonicalCookie` 类进行全面的单元测试，确保其能够正确地创建、解析、验证和存储 Cookie 信息，并且能够正确处理与安全相关的 Cookie 前缀 (`__Secure-`, `__Host-`) 和属性 (`Secure`). 这些测试覆盖了各种边界情况和错误场景，保证了 Chromium 在处理 Cookie 时的正确性和安全性。它直接关系到 JavaScript 中 `document.cookie` API 的行为，并且在调试 Cookie 相关问题时提供了重要的线索和参考。

### 提示词
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
"a", "__Secure-a=b", "x.y", "/", base::Time(), base::Time(),
                  base::Time(), base::Time(), true, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());

  EXPECT_TRUE(CanonicalCookie::CreateUnsafeCookieForTesting(
                  "a", "__Host-a=b", "x.y", "/", base::Time(), base::Time(),
                  base::Time(), base::Time(), true, false,
                  CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW)
                  ->IsCanonical());
}

TEST(CanonicalCookieTest, TestSetCreationDate) {
  auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "B", "x.y", "/path", base::Time(), base::Time(), base::Time(),
      base::Time(), false, false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_LOW);
  EXPECT_TRUE(cookie->CreationDate().is_null());

  base::Time now(base::Time::Now());
  cookie->SetCreationDate(now);
  EXPECT_EQ(now, cookie->CreationDate());
}

TEST(CanonicalCookieTest, TestPrefixHistograms) {
  base::HistogramTester histograms;
  const char kCookiePrefixHistogram[] = "Cookie.CookiePrefix";
  GURL https_url("https://www.example.test");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  EXPECT_FALSE(CanonicalCookie::CreateForTesting(https_url, "__Host-A=B;",
                                                 creation_time, server_time));

  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_HOST, 1);

  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__Host-A=B; Path=/; Secure", creation_time, server_time));
  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_HOST, 2);
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__HostA=B; Path=/; Secure", creation_time, server_time));
  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_HOST, 2);

  EXPECT_FALSE(CanonicalCookie::CreateForTesting(https_url, "__Secure-A=B;",
                                                 creation_time, server_time));

  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_SECURE, 1);
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__Secure-A=B; Path=/; Secure", creation_time, server_time));
  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_SECURE, 2);
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__SecureA=B; Path=/; Secure", creation_time, server_time));
  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_SECURE, 2);

  // Prefix case variants will also increment the histogram.
  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__SECURE-A=B; Path=/; Secure", creation_time, server_time));
  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_SECURE, 3);

  EXPECT_TRUE(CanonicalCookie::CreateForTesting(
      https_url, "__HOST-A=B; Path=/; Secure", creation_time, server_time));
  histograms.ExpectBucketCount(kCookiePrefixHistogram, COOKIE_PREFIX_HOST, 3);
}

TEST(CanonicalCookieTest, TestHasNonASCIIHistograms) {
  base::HistogramTester histograms;
  const char kCookieNonASCIINameHistogram[] = "Cookie.HasNonASCII.Name";
  const char kCookieNonASCIIValueHistogram[] = "Cookie.HasNonASCII.Value";
  const GURL test_url("https://www.example.test");
  int expected_name_true = 0;
  int expected_name_false = 0;
  int expected_value_true = 0;
  int expected_value_false = 0;

  auto create_for_test = [&](const std::string& name,
                             const std::string& value) {
    return CanonicalCookie::CreateForTesting(
        test_url, name + "=" + value, /*creation_time=*/base::Time::Now());
  };

  auto check_histograms = [&]() {
    histograms.ExpectBucketCount(kCookieNonASCIINameHistogram, true,
                                 expected_name_true);
    histograms.ExpectBucketCount(kCookieNonASCIINameHistogram, false,
                                 expected_name_false);
    histograms.ExpectBucketCount(kCookieNonASCIIValueHistogram, true,
                                 expected_value_true);
    histograms.ExpectBucketCount(kCookieNonASCIIValueHistogram, false,
                                 expected_value_false);
  };

  EXPECT_TRUE(create_for_test("foo", "bar"));
  expected_name_false++;
  expected_value_false++;
  check_histograms();

  EXPECT_TRUE(create_for_test("Uni\xf0\x9f\x8d\xaa", "bar"));
  expected_name_true++;
  expected_value_false++;
  check_histograms();

  EXPECT_TRUE(create_for_test("foo", "Uni\xf0\x9f\x8d\xaa"));
  expected_name_false++;
  expected_value_true++;
  check_histograms();

  EXPECT_TRUE(create_for_test("Uni\xf0\x9f\x8d\xaa", "Uni\xf0\x9f\x8d\xaa"));
  expected_name_true++;
  expected_value_true++;
  check_histograms();
}

TEST(CanonicalCookieTest, BuildCookieLine) {
  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  GURL url("https://example.com/");
  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  MatchCookieLineToVector("", cookies);

  cookies.push_back(
      CanonicalCookie::CreateForTesting(url, "A=B", now, server_time));
  MatchCookieLineToVector("A=B", cookies);
  // Nameless cookies are sent back without a prefixed '='.
  cookies.push_back(
      CanonicalCookie::CreateForTesting(url, "C", now, server_time));
  MatchCookieLineToVector("A=B; C", cookies);
  // Cookies separated by ';'.
  cookies.push_back(
      CanonicalCookie::CreateForTesting(url, "D=E", now, server_time));
  MatchCookieLineToVector("A=B; C; D=E", cookies);
  // BuildCookieLine doesn't reorder the list, it relies on the caller to do so.
  cookies.push_back(CanonicalCookie::CreateForTesting(
      url, "F=G", now - base::Seconds(1), server_time));
  MatchCookieLineToVector("A=B; C; D=E; F=G", cookies);
  // BuildCookieLine doesn't deduplicate.
  cookies.push_back(CanonicalCookie::CreateForTesting(
      url, "D=E", now - base::Seconds(2), server_time));
  MatchCookieLineToVector("A=B; C; D=E; F=G; D=E", cookies);
  // BuildCookieLine should match the spec in the case of an empty name with a
  // value containing an equal sign (even if it currently produces "invalid"
  // cookie lines).
  cookies.push_back(
      CanonicalCookie::CreateForTesting(url, "=H=I", now, server_time));
  MatchCookieLineToVector("A=B; C; D=E; F=G; D=E; H=I", cookies);
}

TEST(CanonicalCookieTest, BuildCookieAttributesLine) {
  std::unique_ptr<CanonicalCookie> cookie;
  GURL url("https://example.com/");
  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  cookie = CanonicalCookie::CreateForTesting(url, "A=B", now, server_time);
  EXPECT_EQ("A=B; domain=example.com; path=/",
            CanonicalCookie::BuildCookieAttributesLine(*cookie));
  // Nameless cookies are sent back without a prefixed '='.
  cookie = CanonicalCookie::CreateForTesting(url, "C", now, server_time);
  EXPECT_EQ("C; domain=example.com; path=/",
            CanonicalCookie::BuildCookieAttributesLine(*cookie));
  // BuildCookieAttributesLine should match the spec in the case of an empty
  // name with a value containing an equal sign (even if it currently produces
  // "invalid" cookie lines).
  cookie = CanonicalCookie::CreateForTesting(url, "=H=I", now, server_time);
  EXPECT_EQ("H=I; domain=example.com; path=/",
            CanonicalCookie::BuildCookieAttributesLine(*cookie));
  // BuildCookieAttributesLine should include all attributes.
  cookie = CanonicalCookie::CreateForTesting(
      url,
      "A=B; domain=.example.com; path=/; secure; "
      "httponly; partitioned; samesite=lax",
      now, server_time, CookiePartitionKey::FromURLForTesting(url));
  EXPECT_EQ(
      "A=B; domain=.example.com; path=/; secure; httponly; partitioned; "
      "samesite=lax",
      CanonicalCookie::BuildCookieAttributesLine(*cookie));
}

// Confirm that input arguments are reflected in the output cookie.
TEST(CanonicalCookieTest, CreateSanitizedCookie_Inputs) {
  base::Time two_hours_ago = base::Time::Now() - base::Hours(2);
  base::Time one_hour_ago = base::Time::Now() - base::Hours(1);
  base::Time one_hour_from_now = base::Time::Now() + base::Hours(1);
  CookieInclusionStatus status;
  std::unique_ptr<CanonicalCookie> cc;

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ("A", cc->Name());
  EXPECT_EQ("B", cc->Value());
  EXPECT_EQ("www.foo.com", cc->Domain());
  EXPECT_EQ("/foo", cc->Path());
  EXPECT_EQ(base::Time(), cc->CreationDate());
  EXPECT_EQ(base::Time(), cc->LastAccessDate());
  EXPECT_EQ(base::Time(), cc->ExpiryDate());
  EXPECT_FALSE(cc->SecureAttribute());
  EXPECT_FALSE(cc->IsHttpOnly());
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cc->SameSite());
  EXPECT_EQ(COOKIE_PRIORITY_MEDIUM, cc->Priority());
  EXPECT_FALSE(cc->IsPartitioned());
  EXPECT_FALSE(cc->IsDomainCookie());
  EXPECT_TRUE(status.IsInclude());

  // Creation date
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      two_hours_ago, base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(two_hours_ago, cc->CreationDate());
  EXPECT_TRUE(status.IsInclude());

  // Last access date
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      two_hours_ago, base::Time(), one_hour_ago, false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(one_hour_ago, cc->LastAccessDate());
  EXPECT_TRUE(status.IsInclude());

  // Expiry
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      base::Time(), one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(one_hour_from_now, cc->ExpiryDate());
  EXPECT_TRUE(status.IsInclude());

  // Secure
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), true /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(cc->SecureAttribute());
  EXPECT_TRUE(status.IsInclude());

  // Httponly
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      true /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(cc->IsHttpOnly());
  EXPECT_TRUE(status.IsInclude());

  // Same site
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(CookieSameSite::LAX_MODE, cc->SameSite());
  EXPECT_TRUE(status.IsInclude());

  // Priority
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW,
      std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_EQ(COOKIE_PRIORITY_LOW, cc->Priority());
  EXPECT_TRUE(status.IsInclude());

  // Domain cookie
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", "www.foo.com", "/foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(cc->IsDomainCookie());
  EXPECT_TRUE(status.IsInclude());

  // Partitioned
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", std::string(), "/",
      base::Time(), base::Time(), base::Time(), true /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_LOW,
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com")),
      &status);
  EXPECT_TRUE(cc);
  EXPECT_TRUE(cc->IsPartitioned());
  EXPECT_TRUE(status.IsInclude());
}

// Make sure sanitization and blocking of cookies works correctly.
TEST(CanonicalCookieTest, CreateSanitizedCookie_Logic) {
  base::Time two_hours_ago = base::Time::Now() - base::Hours(2);
  base::Time one_hour_ago = base::Time::Now() - base::Hours(1);
  base::Time one_hour_from_now = base::Time::Now() + base::Hours(1);
  CookieInclusionStatus status;

  // Simple path and domain variations.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", std::string(), "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/bar"), "C", "D", "www.foo.com", "/",
      two_hours_ago, base::Time(), one_hour_ago, false /*secure*/,
      true /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "E", "F", std::string(), std::string(),
      base::Time(), base::Time(), base::Time(), true /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());

  // Test the file:// protocol.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("file:///"), "A", "B", std::string(), "/foo", one_hour_ago,
      one_hour_from_now, base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("file:///home/user/foo.txt"), "A", "B", std::string(), "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("file:///home/user/foo.txt"), "A", "B", "home", "/foo", one_hour_ago,
      one_hour_from_now, base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Test that malformed attributes fail to set the cookie.
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), " A", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A;", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A=", "B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A\x07", "B", std::string(), "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", " B", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "\x0fZ", std::string(), "/foo",
      base::Time(), base::Time(), base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "B", "www.foo.com ", "/foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", "foo.ozzzzzzle", "/foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", std::string(), "foo",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "B", std::string(), "/foo ",
      base::Time(), base::Time(), base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", "%2Efoo.com", "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://domaintest.%E3%81%BF%E3%82%93%E3%81%AA"), "A", "B",
      "domaintest.%E3%81%BF%E3%82%93%E3%81%AA", "/foo", base::Time(),
      base::Time(), base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  std::unique_ptr<CanonicalCookie> cc;

  // Confirm that setting domain cookies with or without leading periods,
  // or on domains different from the URL's, functions correctly.
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", "www.foo.com", "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  ASSERT_TRUE(cc);
  EXPECT_TRUE(cc->IsDomainCookie());
  EXPECT_EQ(".www.foo.com", cc->Domain());
  EXPECT_TRUE(status.IsInclude());

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", ".www.foo.com", "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  ASSERT_TRUE(cc);
  EXPECT_TRUE(cc->IsDomainCookie());
  EXPECT_EQ(".www.foo.com", cc->Domain());
  EXPECT_TRUE(status.IsInclude());

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", ".foo.com", "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  ASSERT_TRUE(cc);
  EXPECT_TRUE(cc->IsDomainCookie());
  EXPECT_EQ(".foo.com", cc->Domain());
  EXPECT_TRUE(status.IsInclude());

  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com/foo"), "A", "B", ".www2.www.foo.com", "/foo",
      one_hour_ago, one_hour_from_now, base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_FALSE(cc);
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Secure/URL Scheme mismatch.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "B", std::string(), "/foo", base::Time(),
      base::Time(), base::Time(), /*secure=*/true,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(status.HasExactlyWarningReasonsForTesting(
      {CookieInclusionStatus::WARN_TENTATIVELY_ALLOWING_SECURE_SOURCE_SCHEME}));

  // Null creation date/non-null last access date conflict.
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "B", std::string(), "/foo", base::Time(),
      base::Time(), base::Time::Now(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_FAILURE_TO_STORE}));

  // Domain doesn't match URL
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "B", "www.bar.com", "/", base::Time(),
      base::Time(), base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Path with unusual characters escaped.
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "B", std::string(), "/foo\x7F",
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  ASSERT_TRUE(cc);
  EXPECT_EQ("/foo%7F", cc->Path());
  EXPECT_TRUE(status.IsInclude());

  // Ensure that all characters get escaped the same on all platforms. This is
  // also useful for visualizing which characters will actually be escaped.
  std::stringstream ss;
  ss << "/";
  for (uint8_t character = 0; character < 0xFF; character++) {
    // Skip any "terminating characters" that CreateSanitizedCookie does not
    // allow to be in `path`.
    if (character == '\0' || character == '\n' || character == '\r' ||
        character == ';') {
      continue;
    }
    ss << character;
  }
  ss << "\xFF";
  std::string initial(ss.str());
  std::string expected =
      "/%01%02%03%04%05%06%07%08%09%0B%0C%0E%0F%10%11%12%13%14%15%16%17%18%19%"
      "1A%1B%1C%1D%1E%1F%20!%22%23$%&'()*+,-./"
      "0123456789:%3C=%3E%3F@ABCDEFGHIJKLMNOPQRSTUVWXYZ[/"
      "]%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%7F%80%81%82%83%84%85%86%87%"
      "88%89%8A%8B%8C%8D%8E%8F%90%91%92%93%94%95%96%97%98%99%9A%9B%9C%9D%9E%9F%"
      "A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF%B0%B1%B2%B3%B4%B5%B6%B7%"
      "B8%B9%BA%BB%BC%BD%BE%BF%C0%C1%C2%C3%C4%C5%C6%C7%C8%C9%CA%CB%CC%CD%CE%CF%"
      "D0%D1%D2%D3%D4%D5%D6%D7%D8%D9%DA%DB%DC%DD%DE%DF%E0%E1%E2%E3%E4%E5%E6%E7%"
      "E8%E9%EA%EB%EC%ED%EE%EF%F0%F1%F2%F3%F4%F5%F6%F7%F8%F9%FA%FB%FC%FD%FE%FF";
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "A", "B", std::string(), initial,
      base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  ASSERT_TRUE(cc);
  EXPECT_EQ(expected, cc->Path());
  EXPECT_TRUE(status.IsInclude());

  // Empty name and value.
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "", "", std::string(), "/", base::Time(),
      base::Time(), base::Time(), false /*secure*/, false /*httponly*/,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_NO_COOKIE_CONTENT}));

  // Check that value can contain an equal sign, even when no name is present.
  // Note that in newer drafts of RFC6265bis, it is specified that a cookie with
  // an empty name and a value containing an equal sign should result in a
  // corresponding cookie line that omits the preceding equal sign. This means
  // that the cookie line won't be deserialized into the original cookie in this
  // case. For now, we'll test for compliance with the spec here, but we aim to
  // collect metrics and hopefully fix this in the spec (and then in
  // CanonicalCookie) at some point.
  // For reference, see: https://github.com/httpwg/http-extensions/pull/1592
  cc = CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "", "ambiguous=value", std::string(),
      std::string(), base::Time(), base::Time(), base::Time(), false /*secure*/,
      false /*httponly*/, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt /*partition_key*/, &status);
  EXPECT_TRUE(cc);
  std::vector<std::unique_ptr<CanonicalCookie>> cookies;
  cookies.push_back(std::move(cc));
  MatchCookieLineToVector("ambiguous=value", cookies);

  // Check that name can't contain an equal sign ("ambiguous=name=value" should
  // correctly be parsed as name: "ambiguous" and value "name=value", so
  // allowing this case would result in cookies that can't serialize correctly).
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("http://www.foo.com"), "ambiguous=name", "value", std::string(),
      std::string(), base::Time(), base::Time(), base::Time(), /*secure=*/false,
      /*http_only=*/false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      /*partition_key=*/std::nullopt, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DISALLOWED_CHARACTER}));

  // A __Secure- cookie must be Secure.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Secure-A", "B", ".www.foo.com", "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Secure-A", "B", ".www.foo.com", "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, false, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // A __Host- cookie must be Secure.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", std::string(), "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", std::string(), "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, false, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // A __Host- cookie must have path "/".
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", std::string(), "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", std::string(), "/foo",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // A __Host- cookie must not specify a domain.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", std::string(), "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "__Host-A", "B", ".www.foo.com", "/",
      two_hours_ago, one_hour_from_now, one_hour_ago, true, false,
      CookieSameSite::NO_RESTRICTION, CookiePriority::COOKIE_PRIORITY_DEFAULT,
      std::nullopt /*partition_key*/, &status));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PREFIX}));

  // Without __Host- prefix, this is a valid host cookie because it does not
  // specify a domain.
  EXPECT_TRUE(CanonicalCookie::CreateSanitizedCookie(
      GURL("https://www.foo.com"), "A", "B", std::string(), "/", two_hours_ago,
      one_h
```