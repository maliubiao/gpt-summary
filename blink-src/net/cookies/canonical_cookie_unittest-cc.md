Response:
The user wants to understand the functionality of the `canonical_cookie_unittest.cc` file in the Chromium network stack. They've provided the initial part of the file and want a summary of its purpose.

Here's a breakdown of how to approach this:

1. **Identify the core class being tested:** The file name and the `#include "net/cookies/canonical_cookie.h"` clearly indicate that this file contains unit tests for the `CanonicalCookie` class.

2. **Analyze the included headers:** These provide clues about the functionalities being tested:
    - `canonical_cookie.h`: The main class under test.
    - Various standard library headers (`memory`, `optional`, `string`, `vector`): Indicate the use of these fundamental data structures within `CanonicalCookie`.
    - `base/test/...`:  Headers from Chromium's base library for testing, like `histogram_tester` and `scoped_feature_list`, suggesting tests related to metrics and feature flags.
    - `base/time/time.h`: Implies testing involving cookie expiration and creation times.
    - `build/build_config.h`: Might be used for platform-specific testing (though not explicitly seen in this snippet).
    - `net/base/features.h`: Shows tests are likely dependent on Chromium feature flags.
    - `net/cookies/...`: Other cookie-related classes, suggesting tests involving interactions between `CanonicalCookie` and these.
    - `net/http/http_util.h`: Implies tests related to how cookies are used in HTTP contexts.
    - `testing/gmock/...` and `testing/gtest/...`:  The testing frameworks being used.
    - `url/gurl.h` and `url/third_party/mozilla/url_parse.h`:  Indicates testing around URL parsing and how it relates to cookies.

3. **Examine the test cases:** The `TEST(CanonicalCookieTest, ...)` blocks define individual test scenarios. By looking at the names of these tests (e.g., `Constructor`, `CreationCornerCases`, `Create`, `CreateInvalidUrl`, etc.), we can infer the aspects of `CanonicalCookie` being tested.

4. **Look for specific functionalities being tested within the tests:**  The code within each test case demonstrates how `CanonicalCookie` is used and what behaviors are being verified (e.g., setting and getting attributes, handling invalid inputs, checking inclusion statuses).

5. **Consider the structure of a unit test:**  Unit tests typically follow an "Arrange, Act, Assert" pattern. We can identify these parts within the test cases to understand what is being set up, what action is being performed (usually creating or manipulating a `CanonicalCookie` object), and what is being checked for correctness.

6. **Relate to potential JavaScript interactions (as requested):**  Cookies are fundamental to web development and heavily used by JavaScript. While this C++ code isn't *directly* JavaScript, it forms the underlying implementation. We can infer connections by considering how JavaScript interacts with cookies (e.g., setting cookies via `document.cookie`, the impact of attributes like `HttpOnly` and `SameSite`).

7. **Address the "logical reasoning" and "user errors" requests:** As we go through the test cases, think about:
    - What inputs would cause different outputs based on the logic being tested?
    - What common mistakes might developers make when dealing with cookies that these tests are designed to catch?

8. **Consider the debugging aspect:**  How would someone use these tests to understand why a cookie isn't behaving as expected?  The tests provide concrete examples of correct and incorrect usage.

**Self-Correction/Refinement:**

- Initially, I might focus too much on the individual test details. It's important to step back and summarize the overall purpose.
- I need to explicitly connect the C++ implementation to the *JavaScript* context where users primarily encounter cookies.
- When thinking about user errors, I should consider both the *server-side* (setting cookies with incorrect attributes) and the *client-side* (JavaScript expecting cookies to behave a certain way).
- I must ensure the summary answers the specific questions in the prompt.
这个 `canonical_cookie_unittest.cc` 文件的主要功能是**测试 `net::CanonicalCookie` 类的各种功能和行为**。`CanonicalCookie` 类是 Chromium 网络栈中表示一个规范化的 HTTP Cookie 的核心类。

以下是对其功能的更详细的归纳：

**核心功能：测试 `CanonicalCookie` 类的各种创建、属性和方法。**

* **构造函数测试 (`Constructor`)：**  验证 `CanonicalCookie` 类的构造函数能否正确地初始化对象的各种属性，例如名称、值、域、路径、安全标志、HttpOnly 标志、SameSite 属性、优先级、是否分区以及来源方案和端口。

* **创建的边缘情况测试 (`CreationCornerCases`)：** 检查在创建 Cookie 时可能出现的各种特殊情况，例如名称或值中包含空格或控制字符，以及 Cookie 大小超出限制的情况。这些测试验证了 `CanonicalCookie::Create` 方法的健壮性，以及它如何处理不合法的输入。

* **从字符串创建 Cookie 测试 (`Create`)：**  测试 `CanonicalCookie::CreateForTesting` 和 `CanonicalCookie::Create` 方法能否正确地从 HTTP 响应头中的 Set-Cookie 字符串中解析并创建 `CanonicalCookie` 对象。这包括测试各种 Cookie 属性，如 Secure、HttpOnly、SameSite 以及不同的端口。

* **处理无效 URL 创建 Cookie 的测试 (`CreateInvalidUrl`)：** 验证当提供的 URL 无效时，创建 Cookie 的操作是否会失败，并返回适当的状态。

* **创建主机 Cookie 的测试 (`CreateHostCookieFromString`)：** 确认当 Cookie 字符串中指定了空域时，是否能正确创建主机 Cookie。

* **处理非标准 SameSite 属性的测试 (`CreateNonStandardSameSite`)：** 测试当 Set-Cookie 头部包含非标准的 SameSite 值时，`CanonicalCookie` 如何处理。

* **跨站上下文创建 SameSite Cookie 的测试 (`CreateSameSiteInCrossSiteContexts`)：** 验证在不同的 SameSite 上下文中创建各种 SameSite 属性的 Cookie 的能力。

* **创建 HttpOnly Cookie 的测试 (`CreateHttpOnly`)：**  测试能否正确地创建带有 HttpOnly 属性的 Cookie。

* **创建带有无效域的 Cookie 的测试 (`CreateWithInvalidDomain`)：** 验证当提供的域与 URL 的域不匹配时，创建 Cookie 的操作是否会失败。

* **从公共后缀创建 Cookie 的测试 (`CreateFromPublicSuffix`)：**  测试当尝试从公共后缀（如 .com 或 co.uk）创建 Cookie 时的行为，包括主机 Cookie 和域 Cookie 的情况。

* **创建带有非 ASCII 域的 Cookie 的测试 (`CreateWithNonASCIIDomain`)：** 验证在启用或禁用特定 Feature Flag 的情况下，如何处理包含非 ASCII 字符的 Cookie 域。

* **创建域为 IP 地址的 Cookie 的测试 (`CreateWithDomainAsIP`)：** 测试当 Cookie 的域属性设置为 IP 地址时，创建 Cookie 的行为，包括 IPv4 和 IPv6 地址的各种格式。

* **创建分区 Cookie 的测试 (`CreateWithPartitioned`)：** 验证如何创建和解析带有 `Partitioned` 属性的 Cookie，包括各种有效和无效的组合，以及与 `__Host-` 前缀的关联。

**与 JavaScript 的关系：**

`CanonicalCookie` 类虽然是用 C++ 实现的，但它直接关系到 JavaScript 如何在浏览器中操作 Cookie。

* **`HttpOnly` 属性:**  如果在 HTTP 响应头中设置了 `HttpOnly` 属性，那么 JavaScript 将无法通过 `document.cookie` 访问这个 Cookie。 `CanonicalCookie` 的相关测试 (`CreateHttpOnly`) 验证了这种属性的正确解析和存储，从而间接地影响了 JavaScript 的行为。

* **`SameSite` 属性:**  `SameSite` 属性控制 Cookie 是否应该随跨站点请求发送。`CanonicalCookie` 的相关测试 (`CreateNonStandardSameSite`, `CreateSameSiteInCrossSiteContexts`) 验证了该属性的解析，而浏览器的 Cookie 管理器会根据这个属性来决定是否将 Cookie 发送给服务器。这直接影响了 JavaScript 发起的跨站点请求的行为。

* **`Secure` 属性:** 只有在 HTTPS 连接下，带有 `Secure` 属性的 Cookie 才会被发送。`CanonicalCookie` 的测试验证了该属性的解析，确保浏览器在处理安全上下文时能正确应用这个限制。

* **`Partitioned` 属性:**  分区 Cookie 旨在提高隐私性，将 Cookie 限制在顶级站点的上下文中。`CanonicalCookie` 的测试 (`CreateWithPartitioned`) 验证了该属性的解析和关联的密钥生成，这直接影响了浏览器如何存储和检索这些 Cookie，从而影响到 JavaScript 对 Cookie 的访问和使用。

**逻辑推理、假设输入与输出：**

例如，在 `CreateWithInvalidDomain` 测试中：

* **假设输入:**  一个 URL 为 `http://www.example.com/test/foo.html`，以及一个 Cookie 字符串 `A=2; Domain=wrongdomain.com`。
* **逻辑推理:**  Cookie 的域属性 `wrongdomain.com` 与请求的域 `www.example.com` 不匹配。根据 Cookie 的规范，这样的 Cookie 应该被拒绝。
* **预期输出:** `CanonicalCookie::Create` 方法应该返回 `nullptr`，并且 `CookieInclusionStatus` 应该包含 `EXCLUDE_INVALID_DOMAIN` 的排除原因。

**用户或编程常见的使用错误：**

* **设置了错误的域 (`CreateWithInvalidDomain`)：** 开发者可能会错误地为 Cookie 设置一个不属于当前域的域。例如，在 `www.example.com` 下设置 `Domain=google.com` 的 Cookie。这会导致浏览器拒绝存储该 Cookie。

* **在非 HTTPS 连接下设置了 `Secure` Cookie：** 用户可能在 HTTP 页面上尝试设置带有 `Secure` 属性的 Cookie。虽然 Cookie 对象可能被创建，但浏览器可能不会存储或发送这个 Cookie，除非后续的请求是通过 HTTPS 发起的。

* **对 `HttpOnly` Cookie 进行 JavaScript 访问：** 开发者可能会尝试使用 JavaScript 的 `document.cookie` 来读取一个设置了 `HttpOnly` 属性的 Cookie。这将失败，因为浏览器会阻止 JavaScript 访问这类 Cookie，以提高安全性。

* **对分区 Cookie 的理解和使用不当：**  开发者可能不了解分区 Cookie 的工作原理，或者在不合适的场景下使用分区 Cookie，导致 Cookie 无法在预期的站点间共享。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个网页。**
2. **服务器在 HTTP 响应头中设置了一个或多个 Cookie，使用 `Set-Cookie` 头部。**
3. **浏览器的网络栈接收到这些 `Set-Cookie` 头部。**
4. **网络栈的代码会调用 `CanonicalCookie::Create` 或类似的方法来解析这些字符串，并尝试创建一个 `CanonicalCookie` 对象。**
5. **如果 `Set-Cookie` 头部包含的属性不合法（例如，无效的域，非法的字符），`CanonicalCookie::Create` 可能会返回 `nullptr`，并且设置相应的 `CookieInclusionStatus`。**
6. **在调试过程中，开发者可能会查看网络请求的头部信息，发现设置的 Cookie 没有生效。**
7. **为了理解原因，开发者可能会阅读 `canonical_cookie_unittest.cc` 中的测试用例，来了解 `CanonicalCookie` 类是如何处理各种 Cookie 属性和异常情况的。**
8. **通过查看相关的测试用例（例如 `CreateWithInvalidDomain`），开发者可以理解为什么他们尝试设置的特定 Cookie 被浏览器拒绝了。**

**总结：**

`canonical_cookie_unittest.cc` 是一个至关重要的测试文件，它通过大量的单元测试，保证了 `CanonicalCookie` 类作为 Chromium 网络栈中 Cookie 处理的核心组件的正确性和健壮性。这些测试覆盖了 Cookie 的创建、属性解析、各种边缘情况和异常情况的处理，以及与特定安全和隐私属性（如 `HttpOnly`、`SameSite` 和 `Partitioned`）相关的行为。理解这个文件的功能有助于开发者理解 Chromium 如何处理 Cookie，并为调试 Cookie 相关的问题提供重要的线索。

Prompt: 
```
这是目录为net/cookies/canonical_cookie_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共9部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/canonical_cookie.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/cookies/canonical_cookie_test_helpers.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_options.h"
#include "net/cookies/cookie_partition_key.h"
#include "net/cookies/parsed_cookie.h"
#include "net/http/http_util.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/third_party/mozilla/url_parse.h"

namespace net {

namespace {
const std::vector<std::string> kCookieableSchemes = {"http", "https", "ws",
                                                     "wss"};

// Helper for testing BuildCookieLine
void MatchCookieLineToVector(
    const std::string& line,
    const std::vector<std::unique_ptr<CanonicalCookie>>& cookies) {
  std::vector<CanonicalCookie> list;
  for (const auto& cookie : cookies)
    list.push_back(*cookie);
  EXPECT_EQ(line, CanonicalCookie::BuildCookieLine(list));
}

}  // namespace

using testing::_;
using testing::AllOf;
using testing::Eq;
using testing::Not;
using testing::Property;

TEST(CanonicalCookieTest, Constructor) {
  base::Time current_time = base::Time::Now();

  // CreateUnsafeCookieForTesting just forwards to the constructor.
  auto cookie1 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", "www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), false, false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT, std::nullopt, CookieSourceScheme::kSecure, 443);
  EXPECT_EQ("A", cookie1->Name());
  EXPECT_EQ("2", cookie1->Value());
  EXPECT_EQ("www.example.com", cookie1->Domain());
  EXPECT_EQ("/test", cookie1->Path());
  EXPECT_FALSE(cookie1->SecureAttribute());
  EXPECT_FALSE(cookie1->IsHttpOnly());
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cookie1->SameSite());
  EXPECT_EQ(CookiePriority::COOKIE_PRIORITY_DEFAULT, cookie1->Priority());
  EXPECT_FALSE(cookie1->IsPartitioned());
  EXPECT_EQ(cookie1->SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cookie1->SourcePort(), 443);

  auto cookie2 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", ".www.example.com", "/", current_time, base::Time(),
      base::Time(), base::Time(), false, false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT,
      CookiePartitionKey::FromURLForTesting(GURL("https://foo.com")),
      CookieSourceScheme::kNonSecure, 65536);
  EXPECT_EQ("A", cookie2->Name());
  EXPECT_EQ("2", cookie2->Value());
  EXPECT_EQ(".www.example.com", cookie2->Domain());
  EXPECT_EQ("/", cookie2->Path());
  EXPECT_FALSE(cookie2->SecureAttribute());
  EXPECT_FALSE(cookie2->IsHttpOnly());
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cookie2->SameSite());
  EXPECT_EQ(CookiePriority::COOKIE_PRIORITY_DEFAULT, cookie2->Priority());
  EXPECT_TRUE(cookie2->IsPartitioned());
  EXPECT_EQ(cookie2->SourceScheme(), CookieSourceScheme::kNonSecure);
  // Because the port can be set explicitly in the constructor its value can be
  // independent of the other parameters. In this case, test that an out of
  // range port is kept out of range.
  EXPECT_EQ(cookie2->SourcePort(), 65536);

  // Set Secure to true but don't specify source_scheme or port.
  auto cookie3 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", ".www.example.com", "/", current_time, base::Time(),
      base::Time(), base::Time(), true /* secure */, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT);
  EXPECT_TRUE(cookie3->SecureAttribute());
  EXPECT_EQ(cookie3->SourceScheme(), CookieSourceScheme::kUnset);
  EXPECT_EQ(cookie3->SourcePort(), url::PORT_UNSPECIFIED);

  auto cookie4 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", ".www.example.com", "/test", current_time, base::Time(),
      base::Time(), base::Time(), false, false, CookieSameSite::NO_RESTRICTION,
      COOKIE_PRIORITY_DEFAULT);
  EXPECT_EQ("A", cookie4->Name());
  EXPECT_EQ("2", cookie4->Value());
  EXPECT_EQ(".www.example.com", cookie4->Domain());
  EXPECT_EQ("/test", cookie4->Path());
  EXPECT_FALSE(cookie4->SecureAttribute());
  EXPECT_FALSE(cookie4->IsHttpOnly());
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cookie4->SameSite());
  EXPECT_FALSE(cookie4->IsPartitioned());
  EXPECT_EQ(cookie4->SourceScheme(), CookieSourceScheme::kUnset);
  EXPECT_EQ(cookie4->SourcePort(), url::PORT_UNSPECIFIED);

  // Test some port edge cases: unspecified.
  auto cookie5 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", ".www.example.com", "/", current_time, base::Time(),
      base::Time(), base::Time(), true /* secure */, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
      CookieSourceScheme::kUnset, url::PORT_UNSPECIFIED);
  EXPECT_EQ(cookie5->SourcePort(), url::PORT_UNSPECIFIED);

  // Test some port edge cases: invalid.
  auto cookie6 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "A", "2", ".www.example.com", "/", current_time, base::Time(),
      base::Time(), base::Time(), true /* secure */, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT, std::nullopt,
      CookieSourceScheme::kUnset, url::PORT_INVALID);
  EXPECT_EQ(cookie6->SourcePort(), url::PORT_INVALID);
}

TEST(CanonicalCookieTest, CreationCornerCases) {
  base::Time creation_time = base::Time::Now();
  std::unique_ptr<CanonicalCookie> cookie;
  std::optional<base::Time> server_time = std::nullopt;

  // Space in name.
  cookie = CanonicalCookie::CreateForTesting(
      GURL("http://www.example.com/test/foo.html"), "A C=2", creation_time,
      server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_EQ("A C", cookie->Name());

  // Semicolon in path.
  cookie = CanonicalCookie::CreateForTesting(GURL("http://fool/;/"), "*",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie.get());

  // Control characters in name or value.
  CookieInclusionStatus status;
  cookie = CanonicalCookie::Create(GURL("http://www.example.com/test/foo.html"),
                                   "\b=foo", creation_time, server_time,
                                   /*cookie_partition_key=*/std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_FALSE(cookie.get());
  EXPECT_TRUE(status.HasExclusionReason(
      CookieInclusionStatus::ExclusionReason::EXCLUDE_DISALLOWED_CHARACTER));
  cookie = CanonicalCookie::Create(GURL("http://www.example.com/test/foo.html"),
                                   "bar=\b", creation_time, server_time,
                                   /*cookie_partition_key=*/std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_FALSE(cookie.get());
  EXPECT_TRUE(status.HasExclusionReason(
      CookieInclusionStatus::ExclusionReason::EXCLUDE_DISALLOWED_CHARACTER));

  // The ParsedCookie constructor unit tests cover many edge cases related to
  // invalid sizes when parsing a cookie line, and since CanonicalCookie::Create
  // creates a ParsedCookie immediately, there's no point in replicating all
  // of those tests here.  We should test that the corresponding ExclusionReason
  // gets passed back correctly, though.
  std::string too_long_value(ParsedCookie::kMaxCookieNamePlusValueSize + 1,
                             'a');

  cookie = CanonicalCookie::Create(GURL("http://www.example.com/test/foo.html"),
                                   too_long_value, creation_time, server_time,
                                   /*cookie_partition_key=*/std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_FALSE(cookie.get());
  EXPECT_TRUE(
      status.HasExclusionReason(CookieInclusionStatus::ExclusionReason::
                                    EXCLUDE_NAME_VALUE_PAIR_EXCEEDS_MAX_SIZE));
}

TEST(CanonicalCookieTest, Create) {
  // Test creating cookies from a cookie string.
  GURL url("http://www.example.com/test/foo.html");
  GURL https_url("https://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      url, "A=2", creation_time, server_time));
  EXPECT_EQ("A", cookie->Name());
  EXPECT_EQ("2", cookie->Value());
  EXPECT_EQ("www.example.com", cookie->Domain());
  EXPECT_EQ("/test", cookie->Path());
  EXPECT_FALSE(cookie->SecureAttribute());
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kNonSecure);
  EXPECT_EQ(cookie->SourcePort(), 80);

  GURL url2("http://www.foo.com");
  cookie = CanonicalCookie::CreateForTesting(url2, "B=1", creation_time,
                                             server_time);
  EXPECT_EQ("B", cookie->Name());
  EXPECT_EQ("1", cookie->Value());
  EXPECT_EQ("www.foo.com", cookie->Domain());
  EXPECT_EQ("/", cookie->Path());
  EXPECT_FALSE(cookie->SecureAttribute());
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kNonSecure);
  EXPECT_EQ(cookie->SourcePort(), 80);

  // Test creating secure cookies. Secure scheme is not checked upon creation,
  // so a URL of any scheme can create a Secure cookie.
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; Secure", creation_time,
                                             server_time);
  EXPECT_TRUE(cookie->SecureAttribute());

  cookie = CanonicalCookie::CreateForTesting(https_url, "A=2; Secure",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie->SecureAttribute());

  GURL url3("https://www.foo.com");
  cookie = CanonicalCookie::CreateForTesting(url3, "A=2; Secure", creation_time,
                                             server_time);
  EXPECT_TRUE(cookie->SecureAttribute());
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kSecure);

  cookie = CanonicalCookie::CreateForTesting(url3, "A=2", creation_time,
                                             server_time);
  EXPECT_FALSE(cookie->SecureAttribute());
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kSecure);

  // Test creating cookie from localhost URL.
  cookie = CanonicalCookie::CreateForTesting(GURL("http://localhost/path"),
                                             "A=2", creation_time, server_time);
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kNonSecure);

  cookie = CanonicalCookie::CreateForTesting(GURL("http://127.0.0.1/path"),
                                             "A=2", creation_time, server_time);
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kNonSecure);

  cookie = CanonicalCookie::CreateForTesting(GURL("http://[::1]/path"), "A=2",
                                             creation_time, server_time);
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kNonSecure);

  cookie = CanonicalCookie::CreateForTesting(GURL("https://localhost/path"),
                                             "A=2", creation_time, server_time);
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kSecure);

  cookie = CanonicalCookie::CreateForTesting(GURL("https://127.0.0.1/path"),
                                             "A=2", creation_time, server_time);
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kSecure);

  cookie = CanonicalCookie::CreateForTesting(GURL("https://[::1]/path"), "A=2",
                                             creation_time, server_time);
  EXPECT_EQ(cookie->SourceScheme(), CookieSourceScheme::kSecure);

  // Test creating http only cookies. HttpOnly is not checked upon creation.
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; HttpOnly",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie->IsHttpOnly());

  cookie = CanonicalCookie::CreateForTesting(url, "A=2; HttpOnly",
                                             creation_time, server_time);
  EXPECT_TRUE(cookie->IsHttpOnly());

  // Test creating SameSite cookies. SameSite is not checked upon creation.
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=Strict",
                                             creation_time, server_time);
  ASSERT_TRUE(cookie.get());
  EXPECT_EQ(CookieSameSite::STRICT_MODE, cookie->SameSite());
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=Lax",
                                             creation_time, server_time);
  ASSERT_TRUE(cookie.get());
  EXPECT_EQ(CookieSameSite::LAX_MODE, cookie->SameSite());
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=Extended",
                                             creation_time, server_time);
  ASSERT_TRUE(cookie.get());
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, cookie->SameSite());
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=None",
                                             creation_time, server_time);
  ASSERT_TRUE(cookie.get());
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cookie->SameSite());
  cookie =
      CanonicalCookie::CreateForTesting(url, "A=2", creation_time, server_time);
  ASSERT_TRUE(cookie.get());
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, cookie->SameSite());

  // Test creating cookies with different ports.
  cookie = CanonicalCookie::CreateForTesting(GURL("http://www.foo.com"), "B=1",
                                             creation_time, server_time);
  EXPECT_EQ(cookie->SourcePort(), 80);

  cookie = CanonicalCookie::CreateForTesting(GURL("http://www.foo.com:81"),
                                             "B=1", creation_time, server_time);
  EXPECT_EQ(cookie->SourcePort(), 81);

  cookie = CanonicalCookie::CreateForTesting(GURL("https://www.foo.com"), "B=1",
                                             creation_time, server_time);
  EXPECT_EQ(cookie->SourcePort(), 443);

  cookie = CanonicalCookie::CreateForTesting(GURL("https://www.foo.com:1234"),
                                             "B=1", creation_time, server_time);
  EXPECT_EQ(cookie->SourcePort(), 1234);

  cookie = CanonicalCookie::CreateForTesting(GURL("http://www.foo.com:443"),
                                             "B=1", creation_time, server_time);
  EXPECT_EQ(cookie->SourcePort(), 443);

  // An invalid port leads to an invalid GURL, which causes cookie creation
  // to fail.
  CookieInclusionStatus status;
  cookie = CanonicalCookie::Create(GURL("http://www.foo.com:70000"), "B=1",
                                   creation_time, server_time,
                                   /*cookie_partition_key=*/std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_FALSE(cookie.get());
  EXPECT_TRUE(status.HasExclusionReason(
      CookieInclusionStatus::ExclusionReason::EXCLUDE_FAILURE_TO_STORE));
}

TEST(CanonicalCookieTest, CreateInvalidUrl) {
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieInclusionStatus status;
  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::Create(
      GURL("http://.127.0.0.1/path"), "A=2", creation_time, server_time,
      /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
      &status);
  EXPECT_FALSE(cookie.get());
  EXPECT_TRUE(status.HasExclusionReason(
      CookieInclusionStatus::ExclusionReason::EXCLUDE_FAILURE_TO_STORE));
}

// Test that a cookie string with an empty domain attribute generates a
// canonical host cookie.
TEST(CanonicalCookieTest, CreateHostCookieFromString) {
  // Create a new canonical host cookie via empty string domain in the
  // cookie_line.
  GURL url("http://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  std::unique_ptr<CanonicalCookie> cookie(CanonicalCookie::CreateForTesting(
      url, "A=2; domain=; Secure", creation_time, server_time,
      std::nullopt /*cookie_partition_key*/));
  EXPECT_EQ("www.example.com", cookie->Domain());
  EXPECT_TRUE(cookie->IsHostCookie());
}

TEST(CanonicalCookieTest, CreateNonStandardSameSite) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time now = base::Time::Now();
  std::unique_ptr<CanonicalCookie> cookie;
  std::optional<base::Time> server_time = std::nullopt;

  // Non-standard value for the SameSite attribute.
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=NonStandard",
                                             now, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, cookie->SameSite());

  // Omit value for the SameSite attribute.
  cookie =
      CanonicalCookie::CreateForTesting(url, "A=2; SameSite", now, server_time);
  EXPECT_TRUE(cookie.get());
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, cookie->SameSite());
}

TEST(CanonicalCookieTest, CreateSameSiteInCrossSiteContexts) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time now = base::Time::Now();
  std::unique_ptr<CanonicalCookie> cookie;
  std::optional<base::Time> server_time = std::nullopt;

  // A cookie can be created from any SameSiteContext regardless of SameSite
  // value (it is upon setting the cookie that the SameSiteContext comes into
  // effect).
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=Strict", now,
                                             server_time);
  EXPECT_TRUE(cookie.get());
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=Lax", now,
                                             server_time);
  EXPECT_TRUE(cookie.get());
  cookie = CanonicalCookie::CreateForTesting(url, "A=2; SameSite=None", now,
                                             server_time);
  EXPECT_TRUE(cookie.get());
  cookie = CanonicalCookie::CreateForTesting(url, "A=2;", now, server_time);
  EXPECT_TRUE(cookie.get());
}

TEST(CanonicalCookieTest, CreateHttpOnly) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieInclusionStatus status;

  // An HttpOnly cookie can be created.
  std::unique_ptr<CanonicalCookie> cookie =
      CanonicalCookie::Create(url, "A=2; HttpOnly", now, server_time,
                              /*cookie_partition_key=*/std::nullopt,
                              CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cookie->IsHttpOnly());
  EXPECT_TRUE(status.IsInclude());
}

TEST(CanonicalCookieTest, CreateWithInvalidDomain) {
  GURL url("http://www.example.com/test/foo.html");
  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieInclusionStatus status;

  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::Create(
      url, "A=2; Domain=wrongdomain.com", now, server_time,
      /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
      &status);
  EXPECT_EQ(nullptr, cookie.get());
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
}

// Creating a cookie for an eTLD is possible, but it must match the hostname and
// be a host cookie.
TEST(CanonicalCookieTest, CreateFromPublicSuffix) {
  GURL url("http://com/path");
  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieInclusionStatus status;

  // Host cookie can be created for an eTLD.
  std::unique_ptr<CanonicalCookie> cookie =
      CanonicalCookie::Create(url, "A=2", now, server_time, std::nullopt,
                              CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_EQ("com", cookie->Domain());

  // Attempting to create a domain cookie still yields a valid cookie, but only
  // if the domain attribute is the same as the URL's host, and it becomes a
  // host cookie only.
  cookie = CanonicalCookie::Create(url, "A=2; domain=com", now, server_time,
                                   std::nullopt, CookieSourceType::kUnknown,
                                   &status);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_EQ("com", cookie->Domain());

  // Same thing if the domain attribute is specified with a dot.
  cookie = CanonicalCookie::Create(url, "A=2; domain=.com", now, server_time,
                                   std::nullopt, CookieSourceType::kUnknown,
                                   &status);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_EQ("com", cookie->Domain());

  // Capitalization is ok because everything is canonicalized.
  cookie = CanonicalCookie::Create(url, "A=2; domain=CoM", now, server_time,
                                   std::nullopt, CookieSourceType::kUnknown,
                                   &status);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_EQ("com", cookie->Domain());

  // Test an eTLD that is more than one label.
  // If the domain attribute minus any leading dot is the same as the url's
  // host, allow it to become a host cookie.
  GURL multilabel_url = GURL("http://co.uk/path");
  cookie = CanonicalCookie::Create(multilabel_url, "A=2", now, server_time,
                                   std::nullopt, CookieSourceType::kUnknown,
                                   &status);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_EQ("co.uk", cookie->Domain());

  cookie = CanonicalCookie::Create(multilabel_url, "A=2; domain=co.uk", now,
                                   server_time, std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_EQ("co.uk", cookie->Domain());

  cookie = CanonicalCookie::Create(multilabel_url, "A=2; domain=.co.uk", now,
                                   server_time, std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsHostCookie());
  EXPECT_EQ("co.uk", cookie->Domain());

  // Don't allow setting a domain cookie from a public suffix for a superdomain.
  cookie = CanonicalCookie::Create(multilabel_url, "A=2; domain=uk", now,
                                   server_time, std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_EQ(nullptr, cookie.get());
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  cookie = CanonicalCookie::Create(multilabel_url, "A=2; domain=.uk", now,
                                   server_time, std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_EQ(nullptr, cookie.get());
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Don't allow setting a domain cookie for an unrelated domain.
  cookie = CanonicalCookie::Create(multilabel_url, "A=2; domain=foo.com", now,
                                   server_time, std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_EQ(nullptr, cookie.get());
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));

  // Don't allow setting a domain cookie for some other domain with no
  // registrable domain.
  cookie = CanonicalCookie::Create(multilabel_url, "A=2; domain=com", now,
                                   server_time, std::nullopt,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_EQ(nullptr, cookie.get());
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
}

TEST(CanonicalCookieTest, CreateWithNonASCIIDomain) {
  GURL url("http://www.xn--xample-9ua.com/test/foo.html");
  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;

  // Test with feature flag enabled.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndEnableFeature(features::kCookieDomainRejectNonASCII);
    CookieInclusionStatus status;

    // Test that non-ascii characters are rejected.
    std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::Create(
        url, "A=1; Domain=\xC3\xA9xample.com", now, server_time,
        /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
        &status);
    EXPECT_EQ(nullptr, cookie.get());
    EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
        {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN,
         CookieInclusionStatus::EXCLUDE_DOMAIN_NON_ASCII}));
    EXPECT_FALSE(
        status.HasWarningReason(CookieInclusionStatus::WARN_DOMAIN_NON_ASCII));
  }

  // Test with feature flag disabled.
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitAndDisableFeature(features::kCookieDomainRejectNonASCII);
    CookieInclusionStatus status2;

    std::unique_ptr<CanonicalCookie> cookie2 = CanonicalCookie::Create(
        url, "A=2; Domain=\xC3\xA9xample.com", now, server_time,
        /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
        &status2);

    EXPECT_TRUE(cookie2.get());
    EXPECT_TRUE(status2.IsInclude());
    EXPECT_TRUE(
        status2.HasWarningReason(CookieInclusionStatus::WARN_DOMAIN_NON_ASCII));
  }

  // Test that regular ascii punycode still works.
  CookieInclusionStatus status3;
  std::unique_ptr<CanonicalCookie> cookie3 = CanonicalCookie::Create(
      url, "A=3; Domain=xn--xample-9ua.com", now, server_time,
      /*cookie_partition_key=*/std::nullopt, CookieSourceType::kUnknown,
      &status3);
  EXPECT_TRUE(cookie3.get());
  EXPECT_TRUE(status3.IsInclude());
  EXPECT_FALSE(
      status3.HasWarningReason(CookieInclusionStatus::WARN_DOMAIN_NON_ASCII));
}

TEST(CanonicalCookieTest, CreateWithDomainAsIP) {
  GURL url("http://1.1.1.1");
  GURL url6("http://[2606:2800:220:1:248:1893:25c8:1946]");

  base::Time now = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  CookieInclusionStatus status;

  const struct {
    const GURL url;
    const std::string cookie_line;
    const bool expectedResult;
  } kTests[] = {
      {url, "d=1;Domain=1.1.1.1;", true},
      {url, "dd=1;Domain=.1.1.1.1;", true},
      {url, "ds=1;Domain=1.1.1;", false},
      {url, "dsd=1;Domain=.1.1.1;", false},
      {url, "dx=1;Domain=0x01.0x1.0x1.0x1;", false},
      {url, "dxd=1;Domain=.0x01.0x1.0x1.0x1;", false},
      {url, "do=1;Domain=0001.0001.0001.0001;", false},
      {url, "d10=1;Domain=16843009;", false},
      {url, "d16=value;Domain=0x1010101;", false},
      {url, "d8=1;Domain=0100200401;", false},
      {url, "dm=1;Domain=00001.0x01.1.001;", false},
      {url6, "d1ipv6=1;Domain=[2606:2800:220:1:248:1893:25c8:1946];", true},
      {url6, "dd1ipv6=1;Domain=.[2606:2800:220:1:248:1893:25c8:1946];", true},
      {url6, "dc1ipv6=1;Domain=[2606:2800:220:1:248:1893:25C8:1946];", true},
      {url6, "d2ipv6=1;Domain=2606:2800:220:1:248:1893:25c8:1946;", false},
      {url6, "dd2ipv6=1;Domain=.2606:2800:220:1:248:1893:25c8:1946;", false},
      {url6, "dc2ipv6=1;Domain=2606:2800:220:1:248:1893:25C8:1946;", false},
  };

  for (const auto& test : kTests) {
    std::unique_ptr<CanonicalCookie> cookie =
        CanonicalCookie::Create(test.url, test.cookie_line, now, server_time,
                                /*cookie_partition_key=*/std::nullopt,
                                CookieSourceType::kUnknown, &status);
    if (test.expectedResult) {
      ASSERT_TRUE(cookie.get());
      EXPECT_EQ(test.url.host(), cookie->Domain());
    } else {
      EXPECT_EQ(nullptr, cookie.get());
      EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
          {CookieInclusionStatus::EXCLUDE_INVALID_DOMAIN}));
    }
  }
}

TEST(CanonicalCookieTest, CreateWithPartitioned) {
  GURL url("https://www.example.com/test/foo.html");
  base::Time creation_time = base::Time::Now();
  std::optional<base::Time> server_time = std::nullopt;
  auto partition_key =
      CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"));
  CookieInclusionStatus status;

  // Valid Partitioned attribute
  std::unique_ptr<CanonicalCookie> cookie = CanonicalCookie::Create(
      url, "__Host-A=2; Partitioned; Path=/; Secure", creation_time,
      server_time, partition_key, CookieSourceType::kUnknown, &status);
  ASSERT_TRUE(cookie.get());
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->SecureAttribute());
  EXPECT_TRUE(cookie->IsPartitioned());
  EXPECT_EQ(partition_key, cookie->PartitionKey());
  EXPECT_EQ(CookieSameSite::UNSPECIFIED, cookie->SameSite());

  // Create() without Partitioned in the cookie line should not result in a
  // partitioned cookie.
  status = CookieInclusionStatus();
  cookie = CanonicalCookie::Create(url, "__Host-A=2; Path=/; Secure",
                                   creation_time, server_time, partition_key,
                                   CookieSourceType::kUnknown, &status);
  ASSERT_TRUE(cookie.get());
  EXPECT_TRUE(status.IsInclude());
  EXPECT_FALSE(cookie->IsPartitioned());
  EXPECT_FALSE(cookie->PartitionKey());

  // Partitioned cookies with no __Host- prefix are still valid if they still
  // have Secure, Path=/, and no Domain.
  status = CookieInclusionStatus();
  cookie = CanonicalCookie::Create(url, "A=2; Partitioned; Path=/; Secure",
                                   creation_time, server_time, partition_key,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsPartitioned());
  EXPECT_EQ(partition_key, cookie->PartitionKey());

  // Invalid Partitioned attribute: No Secure attribute.
  status = CookieInclusionStatus();
  cookie = CanonicalCookie::Create(url, "A=2; Partitioned; Path=/",
                                   creation_time, server_time, partition_key,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_FALSE(cookie.get());
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_INVALID_PARTITIONED}));

  // Partitioned attribute: No Path attribute.
  status = CookieInclusionStatus();
  cookie = CanonicalCookie::Create(url, "A=2; Partitioned; Secure",
                                   creation_time, server_time, partition_key,
                                   CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsPartitioned());
  EXPECT_EQ(partition_key, cookie->PartitionKey());

  // Partitioned attribute: Path attribute not equal to "/".
  status = CookieInclusionStatus();
  cookie = CanonicalCookie::Create(
      url, "A=2; Partitioned; Path=/foobar; Secure", creation_time, server_time,
      partition_key, CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsPartitioned());
  EXPECT_EQ(partition_key, cookie->PartitionKey());

  // Partitioned attribute: Domain cookie.
  status = CookieInclusionStatus();
  cookie = CanonicalCookie::Create(
      url, "A=2; Partitioned; Path=/; Secure; Domain=example.com",
      creation_time, server_time, partition_key, CookieSourceType::kUnknown,
      &status);
  EXPECT_TRUE(cookie.get());
  LOG(ERROR) << status;
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsPartitioned());
  EXPECT_EQ(partition_key, cookie->PartitionKey());

  // No Partitioned attribute but with a nonce.
  status = CookieInclusionStatus();
  auto partition_key_with_nonce =
      std::make_optional(CookiePartitionKey::FromURLForTesting(
          GURL("https://toplevelsite.com"),
          CookiePartitionKey::AncestorChainBit::kCrossSite,
          base::UnguessableToken::Create()));
  cookie = CanonicalCookie::Create(
      url, "__Host-A=2; Path=/; Secure", creation_time, server_time,
      partition_key_with_nonce, CookieSourceType::kUnknown, &status);
  EXPECT_TRUE(cookie.get());
  EXPECT_TRUE(status.IsInclude());
  EXPECT_TRUE(cookie->IsPartitioned());
  EXPECT_EQ(partition_key_with_nonce, cookie->PartitionKey());
}

TEST(CanonicalCookieTest, CreateWithPartitioned_Localhost) {
  GURL url("http://localhost:8000/foo/ba
"""


```