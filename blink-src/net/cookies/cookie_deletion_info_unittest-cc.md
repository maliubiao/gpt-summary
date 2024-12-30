Response:
My thought process for analyzing the C++ unittest file `cookie_deletion_info_unittest.cc` goes like this:

1. **Understand the Purpose of Unit Tests:**  I first recognize that this is a *unittest* file. Unit tests are designed to isolate and verify the functionality of small, individual units of code. In this case, the unit being tested is likely related to the `CookieDeletionInfo` class.

2. **Identify the Class Under Test:**  The `#include "net/cookies/cookie_deletion_info.h"` directive clearly indicates that the core class being tested is `CookieDeletionInfo`.

3. **Examine the Test Structure:**  I scan the file for `TEST()` macros. Each `TEST()` represents a specific test case focusing on a particular aspect of `CookieDeletionInfo`. The naming convention of the tests (e.g., `TimeRangeValues`, `TimeRangeContains`, `CookieDeletionInfoMatchSessionControl`) provides clues about what each test intends to verify.

4. **Analyze Individual Test Cases:**  For each `TEST()`:
    * **Identify the Feature Being Tested:**  What specific functionality or attribute of `CookieDeletionInfo` is this test case exercising?  For example, `TimeRangeValues` tests the setting and getting of time ranges, `CookieDeletionInfoMatchHost` tests matching cookies based on the host, and so on.
    * **Understand the Setup:** How is the test environment being prepared? This often involves creating instances of `CookieDeletionInfo`, `CanonicalCookie`, and setting their properties.
    * **Determine the Assertions:** What are the `EXPECT_EQ`, `EXPECT_TRUE`, and `EXPECT_FALSE` calls checking? These are the core of the test, verifying the expected behavior. I pay close attention to the expected outcomes for different input scenarios.
    * **Look for Edge Cases and Boundary Conditions:** Are there tests for default values, minimum/maximum values, or scenarios where inputs might be unexpected? The `TimeRangeContains` test with various start and end times is a good example of this.

5. **Infer the Functionality of `CookieDeletionInfo`:** Based on the tests, I start to piece together the purpose of the `CookieDeletionInfo` class. It seems to be a structure that holds criteria for determining whether a cookie should be deleted. These criteria include:
    * Time range (creation time)
    * Session vs. persistent cookies
    * Host/domain
    * Cookie name
    * Cookie value
    * URL
    * Domain lists (inclusion and exclusion)
    * Cookie partition key

6. **Consider the Relationship to JavaScript:** I think about how cookie deletion might be triggered in a browser. JavaScript can manipulate cookies using the `document.cookie` API. While this C++ code doesn't directly execute JavaScript, it's part of the browser's internal logic that *enforces* cookie policies, including deletion. Therefore, user actions in JavaScript (like setting an expiring cookie or a browser clearing cookies) could indirectly lead to this C++ code being invoked.

7. **Identify Potential User/Programming Errors:** I consider how developers might misuse cookie deletion features. For instance, a user might intend to delete cookies for a specific domain but accidentally provide an incorrect domain. A programmer might set up deletion criteria that are too broad or too narrow, leading to unintended consequences.

8. **Trace User Operations:** I imagine the steps a user might take that would eventually trigger the cookie deletion logic. This often involves browser settings, extensions, or website actions that interact with cookies.

9. **Look for Logical Reasoning and Assumptions:**  The tests themselves provide examples of logical reasoning. I analyze the input values for `CookieDeletionInfo` and `CanonicalCookie` and the expected `Matches()` results to understand the underlying logic. For instance, the `TimeRangeContains` tests explicitly explore the behavior at the boundaries of the time ranges.

10. **Synthesize the Findings:** Finally, I organize my observations into a coherent summary, addressing each point in the prompt (functionality, JavaScript relationship, logical reasoning, user errors, debugging clues). I provide concrete examples from the code to support my explanations.

By following these steps, I can systematically analyze the unittest file and derive a comprehensive understanding of the functionality and purpose of the `CookieDeletionInfo` class within the Chromium network stack.
这个文件 `net/cookies/cookie_deletion_info_unittest.cc` 是 Chromium 网络栈中用于测试 `CookieDeletionInfo` 类的单元测试文件。它的主要功能是验证 `CookieDeletionInfo` 类的各种方法和功能是否按照预期工作。

以下是它的功能的具体列表，以及与 JavaScript 的关系、逻辑推理、用户/编程错误和调试线索的说明：

**功能列举:**

1. **测试 `CookieDeletionInfo::TimeRange` 的功能:**
   - 测试 `TimeRange` 的默认构造函数和带参数的构造函数能否正确初始化 `start` 和 `end` 时间。
   - 测试 `TimeRange` 的 `SetStart` 和 `SetEnd` 方法能否正确设置开始和结束时间。
   - 测试 `TimeRange` 的 `Contains` 方法，判断给定时间是否在 `TimeRange` 内。涵盖了各种边界情况，例如只有开始时间、只有结束时间、开始时间和结束时间都存在以及开始时间等于结束时间的情况。

2. **测试 `CookieDeletionInfo::Matches` 方法的各种匹配条件:**
   - **`session_control` (会话控制):** 测试根据是否为会话 cookie (`expiration` 为空) 或持久 cookie (`expiration` 不为空) 进行匹配。
   - **`host` (主机名):** 测试根据 cookie 的 domain 属性是否与 `CookieDeletionInfo` 中设置的 `host` 完全匹配（只匹配 host cookie，不匹配 domain cookie）。
   - **`name` (cookie 名称):** 测试根据 cookie 的名称是否与 `CookieDeletionInfo` 中设置的 `name` 匹配。
   - **`value_for_testing` (cookie 值):** 测试根据 cookie 的值是否与 `CookieDeletionInfo` 中设置的 `value_for_testing` 匹配。请注意，`value_for_testing` 的命名暗示这可能主要用于测试目的，实际生产环境中可能不会直接使用 cookie 的值进行删除判断。
   - **`url` (URL):** 测试根据给定的 URL 是否与 cookie 的 domain 和 path 匹配。同时测试了 secure cookie 在 http 协议下的匹配情况，以及 `delegate_treats_url_as_trustworthy` 参数的影响。
   - **`domains_and_ips_to_delete` (要删除的域名和 IP 地址列表):** 测试是否根据提供的域名或 IP 地址列表匹配 cookie 的 domain。
   - **`domains_and_ips_to_ignore` (要忽略的域名和 IP 地址列表):** 测试是否根据提供的域名或 IP 地址列表排除 cookie 的 domain。同时测试了 `domains_and_ips_to_delete` 和 `domains_and_ips_to_ignore` 同时存在时的匹配逻辑。
   - **`CookieAccessSemantics` (Cookie 访问语义):** 测试 `Matches` 方法在不同的 `CookieAccessSemantics` 下的行为，验证其是否能正确匹配。
   - **`cookie_partition_key_collection` (Cookie 分区键集合):** 测试根据 CookiePartitionKey 进行匹配。涵盖了空集合、包含特定键的集合、包含多个键的集合以及包含所有键的情况。
   - **`partitioned_state_only` (仅限分区状态):** 测试是否仅匹配分区 cookie 或排除未分区的 cookie。

**与 JavaScript 的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能直接影响到浏览器如何处理 JavaScript 操作的 Cookie。

* **`document.cookie` API:** JavaScript 可以使用 `document.cookie` API 来读取、设置和删除 Cookie。 当 JavaScript 代码试图删除一个 Cookie 时（通常是通过设置一个过期时间为过去的 Cookie），浏览器的网络栈会调用相应的 C++ 代码来执行删除操作。 `CookieDeletionInfo` 就是在删除过程中用于描述删除条件的关键数据结构。

**举例说明:**

假设一个网页上的 JavaScript 代码执行了以下操作来删除名为 `myCookie` 的 cookie：

```javascript
document.cookie = "myCookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
```

当浏览器处理这个 JavaScript 操作时，底层的 C++ 代码可能会创建一个 `CookieDeletionInfo` 对象，并设置相应的属性，例如 `name` 为 `"myCookie"`，`url` 为当前页面的 URL，以及一个表示过期时间的 `TimeRange`。然后，cookie 管理器会使用这个 `CookieDeletionInfo` 对象来查找并删除匹配的 Cookie。

**逻辑推理及假设输入与输出:**

**假设输入 1:**

* `CookieDeletionInfo` 对象:
    * `session_control`: `CookieDeletionInfo::SessionControl::PERSISTENT_COOKIES`
* `CanonicalCookie` 对象 (持久 cookie):
    * `expiration`:  某个未来的时间点

**输出 1:** `delete_info.Matches(*persistent_cookie, ...)` 返回 `true`。

**假设输入 2:**

* `CookieDeletionInfo` 对象:
    * `host`: `"thehost.hosting.com"`
* `CanonicalCookie` 对象 (domain cookie):
    * `domain`: `".example.com"`

**输出 2:** `delete_info.Matches(*domain_cookie, ...)` 返回 `false`。 (因为 host 匹配只针对 host cookie)

**假设输入 3:**

* `CookieDeletionInfo` 对象:
    * `url`: `GURL("https://www.example.com/path")`
* `CanonicalCookie` 对象:
    * `domain`: `"www.example.com"`
    * `path`: `"/path"`
    * `secure`: `true`

**输出 3:** `delete_info.Matches(*cookie, ...)` 返回 `true`。

**涉及用户或编程常见的使用错误及举例说明:**

1. **用户错误:** 用户在浏览器设置中清除 Cookie 时，可能会选择错误的选项，例如清除了所有 Cookie 而不仅仅是某个特定网站的 Cookie。 这会导致浏览器内部创建一个更宽泛的 `CookieDeletionInfo` 对象，可能匹配到用户不想删除的 Cookie。

2. **编程错误 (JavaScript):**  前端开发者在使用 JavaScript 删除 Cookie 时，忘记设置 `path` 属性。例如：

   ```javascript
   document.cookie = "myCookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC;";
   ```

   如果原始 Cookie 设置了特定的 `path`，那么上述代码可能无法删除该 Cookie，因为浏览器会认为这是一个不同的 Cookie。  这种情况下，底层的 C++ 代码在进行匹配时，会因为 `path` 不一致而无法找到目标 Cookie。

3. **编程错误 (C++):**  在 Chromium 内部开发中，如果错误地配置了 `CookieDeletionInfo` 对象的属性，例如设置了错误的 `host` 或 `domain` 列表，可能会导致意外的 Cookie 删除或无法删除目标 Cookie。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器设置中点击 "清除浏览数据":**
   - 用户打开 Chrome 设置，找到 "隐私设置和安全性"，然后点击 "清除浏览数据"。
   - 在弹出的对话框中，用户选择 "Cookie 及其他网站数据"。
   - 用户可以选择清除所有 Cookie，或者选择一个时间范围。如果选择特定网站的 Cookie，浏览器会根据用户选择的网站生成相应的 `CookieDeletionInfo` 对象，其中 `domains_and_ips_to_delete` 可能会包含用户选择的域名。

2. **用户访问一个设置了 Cookie 的网站:**
   - 当用户访问一个网站时，网站可能会通过 HTTP 响应头或 JavaScript 的 `document.cookie` API 设置 Cookie。
   - 这些 Cookie 会被浏览器存储起来。

3. **JavaScript 代码尝试删除 Cookie:**
   - 网页上的 JavaScript 代码可能会尝试删除 Cookie，例如在用户登出时。
   - 这会导致浏览器内部创建 `CookieDeletionInfo` 对象，并设置相应的名称、域、路径和过期时间等属性。

4. **浏览器扩展或 API 调用:**
   - 浏览器扩展程序可能会使用 Chrome 提供的 API (例如 `chrome.cookies.remove`) 来删除 Cookie。
   - 这些 API 调用最终也会转化为对底层 C++ Cookie 管理代码的调用，并使用 `CookieDeletionInfo` 来描述要删除的 Cookie。

**调试线索:**

当开发者需要调试 Cookie 删除相关的问题时，可以关注以下几点：

* **查看 `CookieDeletionInfo` 对象的属性:** 使用调试器 (例如 gdb) 可以查看 `CookieDeletionInfo` 对象的各个属性值，例如 `session_control`, `host`, `name`, `url`, `domains_and_ips_to_delete` 等，以确定删除操作的条件是什么。
* **断点在 `CookieDeletionInfo::Matches` 方法:**  在 `CookieDeletionInfo::Matches` 方法中设置断点，可以观察当尝试删除某个 Cookie 时，该方法是如何被调用的，以及传入的 `CanonicalCookie` 对象和 `CookieAccessParams` 是什么，从而判断匹配过程是否符合预期。
* **日志输出:**  在 Chromium 的 Cookie 管理模块中可能会有相关的日志输出，可以帮助开发者了解 Cookie 的创建、访问和删除过程。搜索包含 "CookieDeletionInfo" 或相关字段的日志可能会提供有用的信息。
* **网络请求:**  使用开发者工具的网络面板可以查看 HTTP 请求头中的 `Set-Cookie` 和 `Cookie` 字段，了解 Cookie 的设置和发送情况，这有助于理解 Cookie 的属性和作用域，从而更好地理解删除行为。

总而言之，`net/cookies/cookie_deletion_info_unittest.cc` 文件通过各种测试用例，确保 `CookieDeletionInfo` 类能够正确地描述 Cookie 删除的条件，并且其 `Matches` 方法能够按照这些条件准确地判断哪些 Cookie 应该被删除。这对于维护浏览器 Cookie 功能的正确性和安全性至关重要。

Prompt: 
```
这是目录为net/cookies/cookie_deletion_info_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_deletion_info.h"

#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

using TimeRange = CookieDeletionInfo::TimeRange;

TEST(CookieDeletionInfoTest, TimeRangeValues) {
  TimeRange range;
  EXPECT_EQ(base::Time(), range.start());
  EXPECT_EQ(base::Time(), range.end());

  const base::Time kTestStart = base::Time::FromSecondsSinceUnixEpoch(1000);
  const base::Time kTestEnd = base::Time::FromSecondsSinceUnixEpoch(10000);

  EXPECT_EQ(kTestStart, TimeRange(kTestStart, base::Time()).start());
  EXPECT_EQ(base::Time(), TimeRange(kTestStart, base::Time()).end());

  EXPECT_EQ(kTestStart, TimeRange(kTestStart, kTestEnd).start());
  EXPECT_EQ(kTestEnd, TimeRange(kTestStart, kTestEnd).end());

  TimeRange range2;
  range2.SetStart(kTestStart);
  EXPECT_EQ(kTestStart, range2.start());
  EXPECT_EQ(base::Time(), range2.end());
  range2.SetEnd(kTestEnd);
  EXPECT_EQ(kTestStart, range2.start());
  EXPECT_EQ(kTestEnd, range2.end());
}

TEST(CookieDeletionInfoTest, TimeRangeContains) {
  // Default TimeRange matches all time values.
  TimeRange range;
  EXPECT_TRUE(range.Contains(base::Time::Now()));
  EXPECT_TRUE(range.Contains(base::Time::Max()));

  // With a start, but no end.
  const double kTestMinEpoch = 1000;
  range.SetStart(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch));
  EXPECT_FALSE(range.Contains(base::Time::Min()));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch - 1)));
  EXPECT_TRUE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch)));
  EXPECT_TRUE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch + 1)));
  EXPECT_TRUE(range.Contains(base::Time::Max()));

  // With an end, but no start.
  const double kTestMaxEpoch = 10000000;
  range = TimeRange();
  range.SetEnd(base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch));
  EXPECT_TRUE(range.Contains(base::Time::Min()));
  EXPECT_TRUE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch - 1)));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch)));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch + 1)));
  EXPECT_FALSE(range.Contains(base::Time::Max()));

  // With both a start and an end.
  range.SetStart(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch));
  EXPECT_FALSE(range.Contains(base::Time::Min()));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch - 1)));
  EXPECT_TRUE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch)));
  EXPECT_TRUE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch + 1)));
  EXPECT_TRUE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch - 1)));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch)));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch + 1)));
  EXPECT_FALSE(range.Contains(base::Time::Max()));

  // And where start==end.
  range = TimeRange(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch),
                    base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch));
  EXPECT_FALSE(range.Contains(base::Time::Min()));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch - 1)));
  EXPECT_TRUE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch)));
  EXPECT_FALSE(
      range.Contains(base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch + 1)));
}

TEST(CookieDeletionInfoTest, CookieDeletionInfoMatchSessionControl) {
  auto persistent_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "persistent-cookie", "persistent-value", "persistent-domain",
      "persistent-path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  auto session_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "session-cookie", "session-value", "session-domain", "session-path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  EXPECT_TRUE(delete_info.Matches(
      *persistent_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      *session_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  delete_info.session_control =
      CookieDeletionInfo::SessionControl::PERSISTENT_COOKIES;
  EXPECT_TRUE(delete_info.Matches(
      *persistent_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      *session_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  delete_info.session_control =
      CookieDeletionInfo::SessionControl::SESSION_COOKIES;
  EXPECT_FALSE(delete_info.Matches(
      *persistent_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      *session_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
}

TEST(CookieDeletionInfoTest, CookieDeletionInfoMatchHost) {
  auto domain_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "domain-cookie", "domain-cookie-value",
      /*domain=*/".example.com", "/path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  auto host_cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "host-cookie", "host-cookie-value",
      /*domain=*/"thehost.hosting.com", "/path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  EXPECT_TRUE(domain_cookie->IsDomainCookie());
  EXPECT_TRUE(host_cookie->IsHostCookie());

  CookieDeletionInfo delete_info;
  EXPECT_TRUE(delete_info.Matches(
      *domain_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      *host_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  delete_info.host = "thehost.hosting.com";
  EXPECT_FALSE(delete_info.Matches(
      *domain_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      *host_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  delete_info.host = "otherhost.hosting.com";
  EXPECT_FALSE(delete_info.Matches(
      *domain_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      *host_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  delete_info.host = "thehost.otherhosting.com";
  EXPECT_FALSE(delete_info.Matches(
      *domain_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      *host_cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
}

TEST(CookieDeletionInfoTest, CookieDeletionInfoMatchName) {
  auto cookie1 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "cookie1-name", "cookie1-value",
      /*domain=*/".example.com", "/path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);
  auto cookie2 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "cookie2-name", "cookie2-value",
      /*domain=*/".example.com", "/path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  delete_info.name = "cookie1-name";
  EXPECT_TRUE(delete_info.Matches(
      *cookie1,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      *cookie2,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
}

TEST(CookieDeletionInfoTest, CookieDeletionInfoMatchValue) {
  auto cookie1 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "cookie1-name", "cookie1-value",
      /*domain=*/".example.com", "/path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);
  auto cookie2 = CanonicalCookie::CreateUnsafeCookieForTesting(
      "cookie2-name", "cookie2-value",
      /*domain=*/".example.com", "/path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  delete_info.value_for_testing = "cookie2-value";
  EXPECT_FALSE(delete_info.Matches(
      *cookie1,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      *cookie2,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
}

TEST(CookieDeletionInfoTest, CookieDeletionInfoMatchUrl) {
  auto cookie = CanonicalCookie::CreateUnsafeCookieForTesting(
      "cookie-name", "cookie-value",
      /*domain=*/"www.example.com", "/path",
      /*creation=*/base::Time::Now(),
      /*expiration=*/base::Time::Max(),
      /*last_access=*/base::Time::Now(),
      /*last_update=*/base::Time::Now(),
      /*secure=*/true,
      /*httponly=*/false, CookieSameSite::NO_RESTRICTION,
      CookiePriority::COOKIE_PRIORITY_DEFAULT);

  CookieDeletionInfo delete_info;
  delete_info.url = GURL("https://www.example.com/path");
  EXPECT_TRUE(delete_info.Matches(
      *cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  delete_info.url = GURL("https://www.example.com/another/path");
  EXPECT_FALSE(delete_info.Matches(
      *cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  delete_info.url = GURL("http://www.example.com/path");
  // Secure cookie on http:// URL -> no match.
  EXPECT_FALSE(delete_info.Matches(
      *cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  // Secure cookie on http:// URL, but delegate says treat is as trustworhy ->
  // match.
  EXPECT_TRUE(delete_info.Matches(
      *cookie,
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/true}));
}

TEST(CookieDeletionInfoTest, CookieDeletionInfoDomainMatchesDomain) {
  CookieDeletionInfo delete_info;

  const double kTestMinEpoch = 1000;
  const double kTestMaxEpoch = 10000000;
  delete_info.creation_range.SetStart(
      base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch));
  delete_info.creation_range.SetEnd(
      base::Time::FromSecondsSinceUnixEpoch(kTestMaxEpoch));

  auto create_cookie = [kTestMinEpoch](std::string cookie_domain) {
    return *CanonicalCookie::CreateUnsafeCookieForTesting(
        /*name=*/"test-cookie",
        /*value=*/"cookie-value", cookie_domain,
        /*path=*/"cookie/path",
        /*creation=*/base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch + 1),
        /*expiration=*/base::Time::Max(),
        /*last_access=*/
        base::Time::FromSecondsSinceUnixEpoch(kTestMinEpoch + 1),
        /*last_update=*/base::Time::Now(),
        /*secure=*/true,
        /*httponly=*/false,
        /*same_site=*/CookieSameSite::NO_RESTRICTION,
        /*priority=*/CookiePriority::COOKIE_PRIORITY_DEFAULT);
  };

  // by default empty domain list and default match action will match.
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("example.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  const char kExtensionHostname[] = "mgndgikekgjfcpckkfioiadnlibdjbkf";

  // Only using the inclusion list because this is only testing
  // DomainMatchesDomainSet and not CookieDeletionInfo::Matches.
  delete_info.domains_and_ips_to_delete =
      std::set<std::string>({"example.com", "another.com", "192.168.0.1"});
  EXPECT_TRUE(delete_info.Matches(
      create_cookie(".example.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("example.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      create_cookie(".another.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("192.168.0.1"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie(".nomatch.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie("192.168.0.2"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie(kExtensionHostname),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
}

TEST(CookieDeletionInfoTest, CookieDeletionInfoMatchesDomainList) {
  CookieDeletionInfo delete_info;

  auto create_cookie = [](std::string cookie_domain) {
    return *CanonicalCookie::CreateUnsafeCookieForTesting(
        /*name=*/"test-cookie",
        /*value=*/"cookie-value", cookie_domain,
        /*path=*/"cookie/path",
        /*creation=*/base::Time::Now(),
        /*expiration=*/base::Time::Max(),
        /*last_access=*/base::Time::Now(),
        /*last_update=*/base::Time::Now(),
        /*secure=*/false,
        /*httponly=*/false,
        /*same_site=*/CookieSameSite::NO_RESTRICTION,
        /*priority=*/CookiePriority::COOKIE_PRIORITY_DEFAULT);
  };

  // With two empty lists (default) should match any domain.
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("anything.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  // With only an "to_delete" list.
  delete_info.domains_and_ips_to_delete = {"includea.com", "includeb.com"};
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("includea.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("includeb.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie("anything.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  // With only an "to_ignore" list.
  delete_info.domains_and_ips_to_delete.reset();
  delete_info.domains_and_ips_to_ignore = {"exclude.com"};
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("anything.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie("exclude.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  // Now with both lists populated.
  //
  // +----------------------+
  // | to_delete            |  outside.com
  // |                      |
  // |  left.com  +---------------------+
  // |            | mid.com | to_ignore |
  // |            |         |           |
  // +------------|---------+           |
  //              |           right.com |
  //              |                     |
  //              +---------------------+
  delete_info.domains_and_ips_to_delete = {"left.com", "mid.com"};
  delete_info.domains_and_ips_to_ignore = {"mid.com", "right.com"};

  EXPECT_TRUE(delete_info.Matches(
      create_cookie("left.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie("mid.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie("right.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_FALSE(delete_info.Matches(
      create_cookie("outside.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  // An empty list of deleted domains shouldn't delete anything.
  delete_info.domains_and_ips_to_delete = std::set<std::string>();
  delete_info.domains_and_ips_to_ignore.reset();
  EXPECT_FALSE(delete_info.Matches(
      create_cookie("outside.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));

  // An empty list of ignored domains should delete everything.
  delete_info.domains_and_ips_to_delete.reset();
  delete_info.domains_and_ips_to_ignore = std::set<std::string>();
  EXPECT_TRUE(delete_info.Matches(
      create_cookie("inside.com"),
      CookieAccessParams{net::CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
}

// Test that Matches() works regardless of the cookie access semantics (because
// the IncludeForRequestURL call uses CookieOptions::MakeAllInclusive).
TEST(CookieDeletionInfoTest, MatchesWithCookieAccessSemantics) {
  // Cookie with unspecified SameSite.
  auto cookie = CanonicalCookie::CreateForTesting(
      GURL("https://www.example.com"), "cookie=1", base::Time::Now(),
      /*server_time=*/std::nullopt,
      /*cookie_partition_key=*/std::nullopt);

  CookieDeletionInfo delete_info;
  delete_info.url = GURL("https://www.example.com/path");
  EXPECT_TRUE(delete_info.Matches(
      *cookie,
      CookieAccessParams{CookieAccessSemantics::UNKNOWN,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      *cookie,
      CookieAccessParams{CookieAccessSemantics::LEGACY,
                         /*delegate_treats_url_as_trustworthy=*/false}));
  EXPECT_TRUE(delete_info.Matches(
      *cookie,
      CookieAccessParams{CookieAccessSemantics::NONLEGACY,
                         /*delegate_treats_url_as_trustworthy=*/false}));
}

TEST(CookieDeletionInfoTest, MatchesCookiePartitionKeyCollection) {
  const CookiePartitionKey kPartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://www.foo.com"));
  const CookiePartitionKey kOtherPartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://www.bar.com"));
  const CookiePartitionKeyCollection kEmptyCollection;
  const CookiePartitionKeyCollection kSingletonCollection(kPartitionKey);
  const CookiePartitionKeyCollection kMultipleKeysCollection(
      {kPartitionKey, kOtherPartitionKey});
  const CookiePartitionKeyCollection kAllKeysCollection =
      CookiePartitionKeyCollection::ContainsAll();
  const std::optional<CookiePartitionKey> kPartitionKeyOpt =
      std::make_optional(kPartitionKey);
  const CookiePartitionKeyCollection kOtherKeySingletonCollection(
      kOtherPartitionKey);

  struct TestCase {
    const std::string desc;
    const CookiePartitionKeyCollection filter_cookie_partition_key_collection;
    const std::optional<CookiePartitionKey> cookie_partition_key;
    bool expects_match;
  } test_cases[] = {
      // Unpartitioned cookie always matches
      {"Unpartitioned empty collection", kEmptyCollection, std::nullopt, true},
      {"Unpartitioned singleton collection", kSingletonCollection, std::nullopt,
       true},
      {"Unpartitioned multiple keys", kMultipleKeysCollection, std::nullopt,
       true},
      {"Unpartitioned all keys", kAllKeysCollection, std::nullopt, true},
      // Partitioned cookie only matches collections which contain its partition
      // key.
      {"Partitioned empty collection", kEmptyCollection, kPartitionKeyOpt,
       false},
      {"Partitioned singleton collection", kSingletonCollection,
       kPartitionKeyOpt, true},
      {"Partitioned multiple keys", kMultipleKeysCollection, kPartitionKeyOpt,
       true},
      {"Partitioned all keys", kAllKeysCollection, kPartitionKeyOpt, true},
      {"Partitioned mismatched keys", kOtherKeySingletonCollection,
       kPartitionKeyOpt, false},
  };

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.desc);
    auto cookie = CanonicalCookie::CreateForTesting(
        GURL("https://www.example.com"),
        "__Host-foo=bar; Secure; Path=/; Partitioned", base::Time::Now(),
        /*server_time=*/std::nullopt, test_case.cookie_partition_key);
    CookieDeletionInfo delete_info;
    delete_info.cookie_partition_key_collection =
        test_case.filter_cookie_partition_key_collection;
    EXPECT_EQ(test_case.expects_match,
              delete_info.Matches(
                  *cookie, CookieAccessParams{
                               net::CookieAccessSemantics::UNKNOWN,
                               /*delegate_treats_url_as_trustworthy=*/false}));
  }
}

TEST(CookieDeletionInfoTest, MatchesExcludeUnpartitionedCookies) {
  struct TestCase {
    const std::string desc;
    const std::optional<CookiePartitionKey> cookie_partition_key;
    bool partitioned_state_only;
    bool expects_match;
  } test_cases[] = {
      {"Unpartitioned cookie not excluded", std::nullopt, false, true},
      {"Unpartitioned cookie excluded", std::nullopt, true, false},
      {"Partitioned cookie when unpartitioned not excluded",
       CookiePartitionKey::FromURLForTesting(GURL("https://foo.com")), false,
       true},
      {"Partitioned cookie when unpartitioned excluded",
       CookiePartitionKey::FromURLForTesting(GURL("https://foo.com")), true,
       true},
      {"Nonced partitioned cookie when unpartitioned not excluded",
       CookiePartitionKey::FromURLForTesting(
           GURL("https://foo.com"),
           CookiePartitionKey::AncestorChainBit::kCrossSite,
           base::UnguessableToken::Create()),
       false, true},
      {"Nonced partitioned cookie when unpartitioned excluded",
       CookiePartitionKey::FromURLForTesting(
           GURL("https://foo.com"),
           CookiePartitionKey::AncestorChainBit::kCrossSite,
           base::UnguessableToken::Create()),
       true, true},
  };

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.desc);
    auto cookie = CanonicalCookie::CreateForTesting(
        GURL("https://www.example.com"),
        "__Host-foo=bar; Secure; Path=/; Partitioned", base::Time::Now(),
        /*server_time=*/std::nullopt, test_case.cookie_partition_key);
    CookieDeletionInfo delete_info;
    delete_info.partitioned_state_only = test_case.partitioned_state_only;
    EXPECT_EQ(test_case.expects_match,
              delete_info.Matches(
                  *cookie, CookieAccessParams{
                               net::CookieAccessSemantics::UNKNOWN,
                               /*delegate_treats_url_as_trustworthy=*/false}));
  }
}

}  // namespace net

"""

```