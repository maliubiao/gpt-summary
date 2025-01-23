Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code (`cookie_monster_unittest.cc`), highlighting its relationship to JavaScript, explaining logical inferences with examples, pointing out potential user/programming errors, outlining user steps to reach this code, and finally, summarizing the functions in this first part of a larger file.

2. **Initial Skim for High-Level Functionality:** I quickly read through the code, looking for keywords and patterns. I notice:
    * `#include` statements indicating dependencies (like `<string>`, `<vector>`, `"net/cookies/cookie_monster.h"`). This immediately tells me the file is related to cookie management in the Chromium networking stack.
    * `namespace net { ... }` suggesting it's part of the `net` namespace.
    * `TEST_F` and `INSTANTIATE_TYPED_TEST_SUITE_P` hinting at unit testing. The file's name also confirms this (`_unittest.cc`).
    * Assertions like `EXPECT_TRUE`, `EXPECT_EQ`, `DCHECK`.
    * Code manipulating cookies (creating, setting, getting, deleting).

3. **Identify Core Purpose:** Based on the filename and initial skim, the primary function of this file is to **unit test the `CookieMonster` class**. `CookieMonster` is the central class responsible for managing cookies in Chromium's network stack.

4. **Analyze Specific Features and Relationships:**  I re-read the code more carefully, looking for specific functionalities and connections to the request's prompts:

    * **JavaScript Interaction:** I look for any direct interaction with JavaScript. While this C++ code *tests* cookie functionality, it doesn't *execute* within a JavaScript environment. The connection is that `CookieMonster` is *used by* the browser (which includes the JavaScript engine) to manage cookies set and accessed by web pages. I need to articulate this indirect relationship and provide examples of how JavaScript uses cookies (e.g., `document.cookie`).

    * **Logical Inferences and Examples:** I look for test cases that demonstrate specific logic. The `MATCHER_P` macros are good examples of defining specific matching logic for cookies. The test functions themselves (e.g., `GetAllCookiesForURLWithOptions`, `SetCookieWithCreationTime`) imply underlying logic. I need to choose a few representative examples, provide hypothetical inputs (like a specific cookie string and URL), and explain the expected output (whether the cookie is set, retrieved, etc.).

    * **User/Programming Errors:** I consider common mistakes related to cookies. These include:
        * Setting invalid cookie syntax.
        * Not understanding cookie attributes (domain, path, secure, HTTP-only, SameSite).
        * Conflicting cookie settings.
        * Timezone issues with expiration dates.

    * **User Steps to Reach Here (Debugging):** I think about how a developer might end up looking at this code. This usually involves:
        * Discovering a bug related to cookies.
        * Using debugging tools to trace cookie behavior.
        * Examining the network stack's cookie handling implementation.

5. **Structure the Answer:**  I organize the findings according to the request's categories:

    * **Overall Function:** State that it's a unit test file for `CookieMonster`.
    * **JavaScript Relationship:** Explain the indirect relationship and give JavaScript examples.
    * **Logical Inference Examples:**  Choose specific test functions or matchers and illustrate with hypothetical inputs and outputs.
    * **User/Programming Errors:** List common mistakes with brief explanations.
    * **User Steps (Debugging):** Describe a typical debugging scenario.
    * **Part 1 Summary:** Reiterate the main function of testing `CookieMonster` and mention the types of tests included (basic operations, options, change notifications).

6. **Refine and Elaborate:** I review my draft to ensure clarity, accuracy, and completeness. I add details where needed, such as explaining the purpose of the included headers or the meaning of the test macros. I make sure the examples are concrete and easy to understand. I specifically address the "Part 1" constraint by focusing on the functionalities evident in the provided snippet. I acknowledge that this is only a portion of the file and that later parts likely contain more specific test cases.

7. **Self-Correction/Improvements during the Process:**

    * **Initial thought:** Maybe focus on individual functions. **Correction:** Realized the core is *testing* the whole `CookieMonster` class, so the focus should be on the testing framework and the functionalities being tested.
    * **Concern:**  Not seeing direct JavaScript interaction. **Correction:**  Clarified the *indirect* relationship and provided relevant JavaScript examples of cookie usage that the `CookieMonster` supports.
    * **Wish:** To have more context from later parts. **Correction:** Acknowledged the limitation of only having the first part and focused the summary accordingly.

By following these steps, I arrive at a comprehensive and well-structured answer that directly addresses all aspects of the request.
好的，让我们来分析一下 `net/cookies/cookie_monster_unittest.cc` 这个 Chromium 网络栈的源代码文件的前一部分。

**功能归纳（第 1 部分）:**

这个文件的主要功能是为 `net::CookieMonster` 类编写 **单元测试**。`CookieMonster` 是 Chromium 网络栈中负责管理 HTTP Cookie 的核心类。  因此，这个单元测试文件的目的是验证 `CookieMonster` 类的各种功能是否按照预期工作，包括：

* **基本 Cookie 操作:**  测试 Cookie 的设置（Set）、获取（Get）、删除（Delete）等基本操作。
* **Cookie 属性处理:** 验证 `CookieMonster` 是否能正确处理 Cookie 的各种属性，例如：
    * **Domain (域):**  确保 Cookie 能正确地应用于指定的域及其子域。
    * **Path (路径):** 确保 Cookie 能正确地应用于指定的路径及其子路径。
    * **Secure (安全):**  验证安全 Cookie 是否只能通过 HTTPS 连接访问。
    * **HttpOnly (仅 HTTP):** 验证仅 HTTP Cookie 是否不能被 JavaScript 访问。
    * **SameSite (同站):** 验证 SameSite 属性的 Lax、Strict 和 None 模式是否按预期工作。
    * **Expires/Max-Age (过期时间):**  测试 Cookie 的过期机制。
    * **Priority (优先级):** 验证 Cookie 的优先级设置和在资源竞争时的处理。
    * **Partitioned (分区):** 测试 Partitioned Cookie 的相关功能。
* **Cookie 选项:**  测试使用 `CookieOptions` 控制 Cookie 的获取和设置行为，例如：
    * `include_httponly`：是否包含 HttpOnly Cookie。
    * `same_site_cookie_context`：指定同站 Cookie 的上下文。
    * `partition_key`：指定 Cookie 的分区键。
* **Cookie 变更通知:**  测试 `CookieMonster` 在 Cookie 发生变化时是否能正确地发出通知。
* **存储机制:**  虽然这里没有直接涉及存储的实现细节，但测试隐含地验证了 `CookieMonster` 与底层 `CookieStore` 的交互。
* **性能和限制:**  测试与 Cookie 数量和大小相关的限制，以及相应的清理策略（Garbage Collection）。

**与 JavaScript 功能的关系以及举例说明:**

`CookieMonster` 管理的 HTTP Cookie 是 Web 开发中 JavaScript 可以通过 `document.cookie` API 进行访问和操作的。  虽然这个 C++ 单元测试文件本身不包含 JavaScript 代码，但它测试的功能直接影响 JavaScript 对 Cookie 的行为。

**举例说明:**

假设 `CookieMonster` 中处理 `HttpOnly` 属性的逻辑有缺陷，导致 `HttpOnly` Cookie 可以被 JavaScript 访问。 这个单元测试文件中应该包含类似的测试用例来捕捉这个错误：

```c++
TEST_F(CookieMonsterTest, HttpOnlyCookieNotAccessibleByJavaScript) {
  auto cm = GetTestCookieMonster();
  GURL url("http://example.com");
  std::string cookie_line = "test_http_only=value; HttpOnly";
  SetCookie(cm.get(), url, cookie_line);

  // 尝试用 JavaScript 方式获取 Cookie (模拟)
  CookieOptions options;
  options.set_include_httponly(); // 即使设置了包含 HttpOnly，JavaScript 也应该无法访问

  CookieList cookies = GetAllCookiesForURLWithOptions(cm.get(), url, options);
  // 预期 HttpOnly Cookie 不应该出现在这里
  EXPECT_TRUE(cookies.empty());
}
```

在这个例子中，虽然测试代码是 C++，但它验证了 `HttpOnly` 属性的功能，这个功能直接关系到 JavaScript 的行为。 如果测试通过，则表明 JavaScript 无法通过 `document.cookie` 访问该 Cookie。

**逻辑推理的假设输入与输出:**

**假设输入:**

* **API 调用:** `cm->SetCanonicalCookieAsync(canonical_cookie, url, cookie_options, callback)`，其中 `canonical_cookie` 表示一个已解析好的 `CanonicalCookie` 对象，包含了 Cookie 的名称、值、域、路径、过期时间等属性。 `url` 是设置 Cookie 的来源 URL。 `cookie_options` 指定了设置 Cookie 的选项。
* **`canonical_cookie` 内容:**  假设我们要设置一个名为 "my_cookie"，值为 "test_value"，域为 ".example.com"，路径为 "/"，且永不过期的 Cookie。
* **`url`:**  `http://www.example.com`
* **`cookie_options`:** 使用默认选项。

**逻辑推理:** `CookieMonster` 会根据 `canonical_cookie` 的属性，检查是否满足设置 Cookie 的各种规则（例如域匹配、路径匹配等）。由于域和路径都匹配，且没有其他阻止设置的因素，`CookieMonster` 应该接受并存储这个 Cookie。

**预期输出:**

* **操作结果:** 设置 Cookie 的异步操作成功完成。
* **Cookie 存储状态:** `CookieMonster` 的内部存储中应该包含一个名称为 "my_cookie"，值为 "test_value"，域为 ".example.com"，路径为 "/" 的 Cookie。
* **后续获取:** 如果后续调用 `cm->GetCookieListWithOptionsAsync()` 且 URL 匹配（例如 `http://sub.example.com`），则应该能获取到这个 Cookie。

**用户或编程常见的使用错误举例说明:**

1. **错误设置 Cookie 的域 (Domain):**

   * **错误代码 (JavaScript 示例):**
     ```javascript
     document.cookie = "my_cookie=value; domain=example.com"; // 缺少前导点
     ```
   * **问题:**  `CookieMonster` (以及浏览器) 通常要求域以点号开头（`.example.com`）来表示这是一个域 Cookie，可以应用于所有子域。 缺少前导点可能导致 Cookie 被视为仅适用于 `example.com` 这个主机名。

2. **在 HTTPS 页面设置不安全的 Cookie:**

   * **错误代码 (JavaScript 示例):**
     ```javascript
     document.cookie = "my_cookie=value"; // 在 HTTPS 页面上设置，但没有 Secure 属性
     ```
   * **问题:**  在 HTTPS 页面上设置 Cookie 时，如果没有明确指定 `Secure` 属性，现代浏览器通常会阻止设置，或者将其行为视为 `Secure`。  `CookieMonster` 的测试应该验证这种行为。

3. **设置超出浏览器限制的 Cookie 数量或大小:**

   * **错误场景:**  程序尝试为一个特定的域设置大量 Cookie，或者单个 Cookie 的大小超过了浏览器的限制。
   * **结果:** `CookieMonster` 的垃圾回收机制会被触发，可能会删除一些旧的或低优先级的 Cookie。  单元测试会验证这种清理行为是否正确。

**用户操作如何一步步到达这里作为调试线索:**

假设用户遇到了一个与网站 Cookie 相关的问题，例如：

1. **用户报告网站功能异常:** 用户在使用某个网站时，发现登录状态丢失，或者某些个性化设置没有生效。
2. **开发者开始调试:** 开发者怀疑是 Cookie 出了问题。
3. **检查浏览器 Cookie:** 开发者使用浏览器开发者工具（如 Chrome DevTools）的 "Application" 面板查看网站的 Cookie。
4. **发现异常 Cookie 或缺少 Cookie:**  可能发现 Cookie 的值不正确，或者某些预期的 Cookie 不存在。
5. **追踪 Cookie 的设置和读取:** 开发者可能会使用 DevTools 的 "Network" 面板查看网络请求的 Header，特别是 `Set-Cookie` 和 `Cookie` Header，来了解 Cookie 是如何设置和发送的。
6. **查看 Chromium 源代码 (如果需要深入分析):** 如果问题涉及到浏览器底层的 Cookie 管理逻辑，开发者可能会查看 Chromium 的源代码，比如 `net/cookies/cookie_monster.cc` 和 `net/cookies/cookie_monster_unittest.cc`。
7. **定位到相关的单元测试:**  如果开发者怀疑是 `CookieMonster` 的某个特定功能有问题，他们可能会在单元测试文件中查找相关的测试用例，例如与 `HttpOnly`、`Secure` 属性或域匹配相关的测试。
8. **运行单元测试或添加调试日志:**  为了验证他们的假设，开发者可能会运行相关的单元测试，或者在 `CookieMonster` 的代码中添加调试日志，来观察 Cookie 的设置、获取和删除过程。

因此，用户最初报告的网站功能异常，经过一系列的调试步骤，可能会最终引导开发者深入到 `net/cookies/cookie_monster_unittest.cc` 这样的单元测试文件中，来理解和排查问题。

希望以上分析能够帮助你理解 `net/cookies/cookie_monster_unittest.cc` 文件（第一部分）的功能和相关概念。

### 提示词
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/cookies/cookie_monster.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/containers/queue.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_samples.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/mock_callback.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_future.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "cookie_partition_key.h"
#include "net/base/features.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/canonical_cookie_test_helpers.h"
#include "net/cookies/cookie_change_dispatcher.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_monster_store_test.h"  // For CookieStore mock
#include "net/cookies/cookie_partition_key.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_store_change_unittest.h"
#include "net/cookies/cookie_store_test_callbacks.h"
#include "net/cookies/cookie_store_test_helpers.h"
#include "net/cookies/cookie_store_unittest.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/parsed_cookie.h"
#include "net/cookies/test_cookie_access_delegate.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_constants.h"

namespace net {

using base::Time;
using CookieDeletionInfo = net::CookieDeletionInfo;

namespace {

using testing::ElementsAre;

// False means 'less than or equal', so we test both ways for full equal.
MATCHER_P(CookieEquals, expected, "") {
  return !(arg.FullCompare(expected) || expected.FullCompare(arg));
}

MATCHER_P2(MatchesCookieNameDomain, name, domain, "") {
  return testing::ExplainMatchResult(
      testing::AllOf(testing::Property(&net::CanonicalCookie::Name, name),
                     testing::Property(&net::CanonicalCookie::Domain, domain)),
      arg, result_listener);
}

MATCHER_P4(MatchesCookieNameValueCreationExpiry,
           name,
           value,
           creation,
           expiry,
           "") {
  return testing::ExplainMatchResult(
      testing::AllOf(
          testing::Property(&net::CanonicalCookie::Name, name),
          testing::Property(&net::CanonicalCookie::Value, value),
          testing::Property(&net::CanonicalCookie::CreationDate, creation),
          // We need a margin of error when testing the ExpiryDate as, if
          // clamped, it is set relative to the current time.
          testing::Property(&net::CanonicalCookie::ExpiryDate,
                            testing::Gt(expiry - base::Minutes(1))),
          testing::Property(&net::CanonicalCookie::ExpiryDate,
                            testing::Lt(expiry + base::Minutes(1)))),
      arg, result_listener);
}

const char kTopLevelDomainPlus1[] = "http://www.harvard.edu";
const char kTopLevelDomainPlus2[] = "http://www.math.harvard.edu";
const char kTopLevelDomainPlus2Secure[] = "https://www.math.harvard.edu";
const char kTopLevelDomainPlus3[] = "http://www.bourbaki.math.harvard.edu";
const char kOtherDomain[] = "http://www.mit.edu";

struct CookieMonsterTestTraits {
  static std::unique_ptr<CookieStore> Create() {
    return std::make_unique<CookieMonster>(nullptr /* store */,
                                           nullptr /* netlog */);
  }

  static void DeliverChangeNotifications() { base::RunLoop().RunUntilIdle(); }

  static const bool supports_http_only = true;
  static const bool supports_non_dotted_domains = true;
  static const bool preserves_trailing_dots = true;
  static const bool filters_schemes = true;
  static const bool has_path_prefix_bug = false;
  static const bool forbids_setting_empty_name = false;
  static const bool supports_global_cookie_tracking = true;
  static const bool supports_url_cookie_tracking = true;
  static const bool supports_named_cookie_tracking = true;
  static const bool supports_multiple_tracking_callbacks = true;
  static const bool has_exact_change_cause = true;
  static const bool has_exact_change_ordering = true;
  static const int creation_time_granularity_in_ms = 0;
  static const bool supports_cookie_access_semantics = true;
  static const bool supports_partitioned_cookies = true;
};

INSTANTIATE_TYPED_TEST_SUITE_P(CookieMonster,
                               CookieStoreTest,
                               CookieMonsterTestTraits);
INSTANTIATE_TYPED_TEST_SUITE_P(CookieMonster,
                               CookieStoreChangeGlobalTest,
                               CookieMonsterTestTraits);
INSTANTIATE_TYPED_TEST_SUITE_P(CookieMonster,
                               CookieStoreChangeUrlTest,
                               CookieMonsterTestTraits);
INSTANTIATE_TYPED_TEST_SUITE_P(CookieMonster,
                               CookieStoreChangeNamedTest,
                               CookieMonsterTestTraits);

template <typename T>
class CookieMonsterTestBase : public CookieStoreTest<T> {
 public:
  using CookieStoreTest<T>::SetCookie;

 protected:
  using CookieStoreTest<T>::http_www_foo_;
  using CookieStoreTest<T>::https_www_foo_;

  CookieList GetAllCookiesForURLWithOptions(
      CookieMonster* cm,
      const GURL& url,
      const CookieOptions& options,
      const CookiePartitionKeyCollection& cookie_partition_key_collection =
          CookiePartitionKeyCollection()) {
    DCHECK(cm);
    GetCookieListCallback callback;
    cm->GetCookieListWithOptionsAsync(
        url, options, cookie_partition_key_collection, callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.cookies();
  }

  CookieList GetAllCookies(CookieMonster* cm) {
    DCHECK(cm);
    GetAllCookiesCallback callback;
    cm->GetAllCookiesAsync(callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.cookies();
  }

  CookieAccessResultList GetExcludedCookiesForURLWithOptions(
      CookieMonster* cm,
      const GURL& url,
      const CookieOptions& options,
      const CookiePartitionKeyCollection& cookie_partition_key_collection =
          CookiePartitionKeyCollection()) {
    DCHECK(cm);
    GetCookieListCallback callback;
    cm->GetCookieListWithOptionsAsync(
        url, options, cookie_partition_key_collection, callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.excluded_cookies();
  }

  bool SetAllCookies(CookieMonster* cm, const CookieList& list) {
    DCHECK(cm);
    ResultSavingCookieCallback<CookieAccessResult> callback;
    cm->SetAllCookiesAsync(list, callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.result().status.IsInclude();
  }

  bool SetCookieWithCreationTime(
      CookieMonster* cm,
      const GURL& url,
      const std::string& cookie_line,
      base::Time creation_time,
      std::optional<CookiePartitionKey> cookie_partition_key = std::nullopt) {
    DCHECK(cm);
    DCHECK(!creation_time.is_null());
    ResultSavingCookieCallback<CookieAccessResult> callback;
    cm->SetCanonicalCookieAsync(
        CanonicalCookie::CreateForTesting(url, cookie_line, creation_time,
                                          std::nullopt /* server_time */,
                                          cookie_partition_key),
        url, CookieOptions::MakeAllInclusive(), callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.result().status.IsInclude();
  }

  uint32_t DeleteAllCreatedInTimeRange(CookieMonster* cm,
                                       const TimeRange& creation_range) {
    DCHECK(cm);
    ResultSavingCookieCallback<uint32_t> callback;
    cm->DeleteAllCreatedInTimeRangeAsync(creation_range,
                                         callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.result();
  }

  uint32_t DeleteAllMatchingInfo(CookieMonster* cm,
                                 CookieDeletionInfo delete_info) {
    DCHECK(cm);
    ResultSavingCookieCallback<uint32_t> callback;
    cm->DeleteAllMatchingInfoAsync(std::move(delete_info),
                                   callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.result();
  }

  uint32_t DeleteMatchingCookies(CookieMonster* cm,
                                 CookieStore::DeletePredicate predicate) {
    DCHECK(cm);
    ResultSavingCookieCallback<uint32_t> callback;
    cm->DeleteMatchingCookiesAsync(std::move(predicate),
                                   callback.MakeCallback());
    callback.WaitUntilDone();
    return callback.result();
  }

  // Helper for PredicateSeesAllCookies test; repopulates CM with same layout
  // each time. Returns the time which is strictly greater than any creation
  // time which was passed to created cookies.
  base::Time PopulateCmForPredicateCheck(CookieMonster* cm) {
    std::string url_top_level_domain_plus_1(GURL(kTopLevelDomainPlus1).host());
    std::string url_top_level_domain_plus_2(GURL(kTopLevelDomainPlus2).host());
    std::string url_top_level_domain_plus_3(GURL(kTopLevelDomainPlus3).host());
    std::string url_top_level_domain_secure(
        GURL(kTopLevelDomainPlus2Secure).host());
    std::string url_other(GURL(kOtherDomain).host());

    this->DeleteAll(cm);

    // Static population for probe:
    //    * Three levels of domain cookie (.b.a, .c.b.a, .d.c.b.a)
    //    * Three levels of host cookie (w.b.a, w.c.b.a, w.d.c.b.a)
    //    * http_only cookie (w.c.b.a)
    //    * same_site cookie (w.c.b.a)
    //    * Two secure cookies (.c.b.a, w.c.b.a)
    //    * Two domain path cookies (.c.b.a/dir1, .c.b.a/dir1/dir2)
    //    * Two host path cookies (w.c.b.a/dir1, w.c.b.a/dir1/dir2)

    std::vector<std::unique_ptr<CanonicalCookie>> cookies;
    const base::Time now = base::Time::Now();

    // Domain cookies
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "dom_1", "A", ".harvard.edu", "/", now, base::Time(), base::Time(),
        base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "dom_2", "B", ".math.harvard.edu", "/", now, base::Time(), base::Time(),
        base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "dom_3", "C", ".bourbaki.math.harvard.edu", "/", now, base::Time(),
        base::Time(), base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));

    // Host cookies
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "host_1", "A", url_top_level_domain_plus_1, "/", now, base::Time(),
        base::Time(), base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "host_2", "B", url_top_level_domain_plus_2, "/", now, base::Time(),
        base::Time(), base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "host_3", "C", url_top_level_domain_plus_3, "/", now, base::Time(),
        base::Time(), base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));

    // http_only cookie
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "httpo_check", "A", url_top_level_domain_plus_2, "/", now, base::Time(),
        base::Time(), base::Time(), false, true, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));

    // same-site cookie
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "same_site_check", "A", url_top_level_domain_plus_2, "/", now,
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT));

    // Secure cookies
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "sec_dom", "A", ".math.harvard.edu", "/", now, base::Time(),
        base::Time(), base::Time(), true, false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "sec_host", "B", url_top_level_domain_plus_2, "/", now, base::Time(),
        base::Time(), base::Time(), true, false, CookieSameSite::NO_RESTRICTION,
        COOKIE_PRIORITY_DEFAULT));

    // Domain path cookies
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "dom_path_1", "A", ".math.harvard.edu", "/dir1", now, base::Time(),
        base::Time(), base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "dom_path_2", "B", ".math.harvard.edu", "/dir1/dir2", now, base::Time(),
        base::Time(), base::Time(), false, false, CookieSameSite::LAX_MODE,
        COOKIE_PRIORITY_DEFAULT));

    // Host path cookies
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "host_path_1", "A", url_top_level_domain_plus_2, "/dir1", now,
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "host_path_2", "B", url_top_level_domain_plus_2, "/dir1/dir2", now,
        base::Time(), base::Time(), base::Time(), false, false,
        CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT));

    // Partitioned cookies
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "__Host-pc_1", "A", url_top_level_domain_secure, "/", now, base::Time(),
        base::Time(), base::Time(), true, false, CookieSameSite::NO_RESTRICTION,
        CookiePriority::COOKIE_PRIORITY_DEFAULT,
        CookiePartitionKey::FromURLForTesting(GURL(kTopLevelDomainPlus1))));
    cookies.push_back(CanonicalCookie::CreateUnsafeCookieForTesting(
        "__Host-pc_2", "B", url_top_level_domain_secure, "/", now, base::Time(),
        base::Time(), base::Time(), true, false, CookieSameSite::NO_RESTRICTION,
        CookiePriority::COOKIE_PRIORITY_DEFAULT,
        CookiePartitionKey::FromURLForTesting(GURL(kTopLevelDomainPlus1))));

    for (auto& cookie : cookies) {
      GURL source_url = cookie_util::SimulatedCookieSource(
          *cookie, cookie->SecureAttribute() ? "https" : "http");
      EXPECT_TRUE(this->SetCanonicalCookie(cm, std::move(cookie), source_url,
                                           true /* modify_httponly */));
    }

    EXPECT_EQ(cookies.size(), this->GetAllCookies(cm).size());
    return now + base::Milliseconds(100);
  }

  Time GetFirstCookieAccessDate(CookieMonster* cm) {
    const CookieList all_cookies(this->GetAllCookies(cm));
    return all_cookies.front().LastAccessDate();
  }

  bool FindAndDeleteCookie(CookieMonster* cm,
                           const std::string& domain,
                           const std::string& name) {
    CookieList cookies = this->GetAllCookies(cm);
    for (auto& cookie : cookies)
      if (cookie.Domain() == domain && cookie.Name() == name)
        return this->DeleteCanonicalCookie(cm, cookie);
    return false;
  }

  void TestHostGarbageCollectHelper() {
    int domain_max_cookies = CookieMonster::kDomainMaxCookies;
    int domain_purge_cookies = CookieMonster::kDomainPurgeCookies;
    const int more_than_enough_cookies = domain_max_cookies + 10;
    // Add a bunch of cookies on a single host, should purge them.
    {
      auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
      for (int i = 0; i < more_than_enough_cookies; ++i) {
        std::string cookie = base::StringPrintf("a%03d=b", i);
        EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), cookie));
        std::string cookies = this->GetCookies(cm.get(), http_www_foo_.url());
        // Make sure we find it in the cookies.
        EXPECT_NE(cookies.find(cookie), std::string::npos);
        // Count the number of cookies.
        EXPECT_LE(base::ranges::count(cookies, '='), domain_max_cookies);
      }
    }

    // Add a bunch of cookies on multiple hosts within a single eTLD.
    // Should keep at least kDomainMaxCookies - kDomainPurgeCookies
    // between them.  We shouldn't go above kDomainMaxCookies for both together.
    GURL url_google_specific(http_www_foo_.Format("http://www.gmail.%D"));
    {
      auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
      for (int i = 0; i < more_than_enough_cookies; ++i) {
        std::string cookie_general = base::StringPrintf("a%03d=b", i);
        EXPECT_TRUE(SetCookie(cm.get(), http_www_foo_.url(), cookie_general));
        std::string cookie_specific = base::StringPrintf("c%03d=b", i);
        EXPECT_TRUE(SetCookie(cm.get(), url_google_specific, cookie_specific));
        std::string cookies_general =
            this->GetCookies(cm.get(), http_www_foo_.url());
        EXPECT_NE(cookies_general.find(cookie_general), std::string::npos);
        std::string cookies_specific =
            this->GetCookies(cm.get(), url_google_specific);
        EXPECT_NE(cookies_specific.find(cookie_specific), std::string::npos);
        EXPECT_LE((base::ranges::count(cookies_general, '=') +
                   base::ranges::count(cookies_specific, '=')),
                  domain_max_cookies);
      }
      // After all this, there should be at least
      // kDomainMaxCookies - kDomainPurgeCookies for both URLs.
      std::string cookies_general =
          this->GetCookies(cm.get(), http_www_foo_.url());
      std::string cookies_specific =
          this->GetCookies(cm.get(), url_google_specific);
      int total_cookies = (base::ranges::count(cookies_general, '=') +
                           base::ranges::count(cookies_specific, '='));
      EXPECT_GE(total_cookies, domain_max_cookies - domain_purge_cookies);
      EXPECT_LE(total_cookies, domain_max_cookies);
    }

    // Test histogram for the number of registrable domains affected by domain
    // purge.
    {
      auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
      GURL url;
      for (int domain_num = 0; domain_num < 3; ++domain_num) {
        url = GURL(base::StringPrintf("http://domain%d.test", domain_num));
        for (int i = 0; i < more_than_enough_cookies; ++i) {
          std::string cookie = base::StringPrintf("a%03d=b", i);
          EXPECT_TRUE(SetCookie(cm.get(), url, cookie));
          std::string cookies = this->GetCookies(cm.get(), url);
          // Make sure we find it in the cookies.
          EXPECT_NE(cookies.find(cookie), std::string::npos);
          // Count the number of cookies.
          EXPECT_LE(base::ranges::count(cookies, '='), domain_max_cookies);
        }
      }

      // Triggering eviction again for a previously affected registrable domain
      // does not increment the histogram.
      for (int i = 0; i < domain_purge_cookies * 2; ++i) {
        // Add some extra cookies (different names than before).
        std::string cookie = base::StringPrintf("b%03d=b", i);
        EXPECT_TRUE(SetCookie(cm.get(), url, cookie));
        std::string cookies = this->GetCookies(cm.get(), url);
        // Make sure we find it in the cookies.
        EXPECT_NE(cookies.find(cookie), std::string::npos);
        // Count the number of cookies.
        EXPECT_LE(base::ranges::count(cookies, '='), domain_max_cookies);
      }
    }
  }

  CookiePriority CharToPriority(char ch) {
    switch (ch) {
      case 'L':
        return COOKIE_PRIORITY_LOW;
      case 'M':
        return COOKIE_PRIORITY_MEDIUM;
      case 'H':
        return COOKIE_PRIORITY_HIGH;
    }
    NOTREACHED();
  }

  // Instantiates a CookieMonster, adds multiple cookies (to http_www_foo_)
  // with priorities specified by |coded_priority_str|, and tests priority-aware
  // domain cookie eviction.
  //
  // Example: |coded_priority_string| of "2MN 3LS MN 4HN" specifies sequential
  // (i.e., from least- to most-recently accessed) insertion of 2
  // medium-priority non-secure cookies, 3 low-priority secure cookies, 1
  // medium-priority non-secure cookie, and 4 high-priority non-secure cookies.
  //
  // Within each priority, only the least-accessed cookies should be evicted.
  // Thus, to describe expected suriving cookies, it suffices to specify the
  // expected population of surviving cookies per priority, i.e.,
  // |expected_low_count|, |expected_medium_count|, and |expected_high_count|.
  void TestPriorityCookieCase(CookieMonster* cm,
                              const std::string& coded_priority_str,
                              size_t expected_low_count,
                              size_t expected_medium_count,
                              size_t expected_high_count,
                              size_t expected_nonsecure,
                              size_t expected_secure) {
    SCOPED_TRACE(coded_priority_str);
    this->DeleteAll(cm);
    int next_cookie_id = 0;
    // A list of cookie IDs, indexed by secure status, then by priority.
    std::vector<int> id_list[2][3];
    // A list of all the cookies stored, along with their properties.
    std::vector<std::pair<bool, CookiePriority>> cookie_data;

    // Parse |coded_priority_str| and add cookies.
    for (const std::string& token :
         base::SplitString(coded_priority_str, " ", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_ALL)) {
      DCHECK(!token.empty());

      bool is_secure = token.back() == 'S';

      // The second-to-last character is the priority. Grab and discard it.
      CookiePriority priority = CharToPriority(token[token.size() - 2]);

      // Discard the security status and priority tokens. The rest of the string
      // (possibly empty) specifies repetition.
      int rep = 1;
      if (!token.empty()) {
        bool result = base::StringToInt(
            base::MakeStringPiece(token.begin(), token.end() - 2), &rep);
        DCHECK(result);
      }
      for (; rep > 0; --rep, ++next_cookie_id) {
        std::string cookie =
            base::StringPrintf("a%d=b;priority=%s;%s", next_cookie_id,
                               CookiePriorityToString(priority).c_str(),
                               is_secure ? "secure" : "");

        EXPECT_TRUE(SetCookie(
            cm, is_secure ? https_www_foo_.url() : http_www_foo_.url(),
            cookie));
        cookie_data.emplace_back(is_secure, priority);
        id_list[is_secure][priority].push_back(next_cookie_id);
      }
    }

    int num_cookies = static_cast<int>(cookie_data.size());
    // A list of cookie IDs, indexed by secure status, then by priority.
    std::vector<int> surviving_id_list[2][3];

    // Parse the list of cookies
    std::string cookie_str = this->GetCookies(cm, https_www_foo_.url());
    // If any part of OBC is active then we also need to query the insecure url
    // and combine the resulting strings.
    if (cookie_util::IsOriginBoundCookiesPartiallyEnabled()) {
      std::string cookie_str_insecure =
          this->GetCookies(cm, http_www_foo_.url());

      std::vector<std::string_view> to_be_combined;
      // The cookie strings may be empty, only add them to our vector if
      // they're not. Otherwise we'll get an extra separator added which is bad.
      if (!cookie_str.empty()) {
        to_be_combined.push_back(cookie_str);
      }
      if (!cookie_str_insecure.empty()) {
        to_be_combined.push_back(cookie_str_insecure);
      }

      cookie_str = base::JoinString(to_be_combined, /*separator=*/"; ");
    }

    size_t num_nonsecure = 0;
    size_t num_secure = 0;
    for (const std::string& token : base::SplitString(
             cookie_str, ";", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
      // Assuming *it is "a#=b", so extract and parse "#" portion.
      int id = -1;
      bool result = base::StringToInt(
          base::MakeStringPiece(token.begin() + 1, token.end() - 2), &id);
      DCHECK(result);
      DCHECK_GE(id, 0);
      DCHECK_LT(id, num_cookies);
      surviving_id_list[cookie_data[id].first][cookie_data[id].second]
          .push_back(id);
      if (cookie_data[id].first)
        num_secure += 1;
      else
        num_nonsecure += 1;
    }

    EXPECT_EQ(expected_nonsecure, num_nonsecure);
    EXPECT_EQ(expected_secure, num_secure);

    // Validate each priority.
    size_t expected_count[3] = {expected_low_count, expected_medium_count,
                                expected_high_count};
    for (int i = 0; i < 3; ++i) {
      size_t num_for_priority =
          surviving_id_list[0][i].size() + surviving_id_list[1][i].size();
      EXPECT_EQ(expected_count[i], num_for_priority);
      // Verify that the remaining cookies are the most recent among those
      // with the same priorities.
      if (expected_count[i] == num_for_priority) {
        // Non-secure:
        std::sort(surviving_id_list[0][i].begin(),
                  surviving_id_list[0][i].end());
        EXPECT_TRUE(std::equal(
            surviving_id_list[0][i].begin(), surviving_id_list[0][i].end(),
            id_list[0][i].end() - surviving_id_list[0][i].size()));

        // Secure:
        std::sort(surviving_id_list[1][i].begin(),
                  surviving_id_list[1][i].end());
        EXPECT_TRUE(std::equal(
            surviving_id_list[1][i].begin(), surviving_id_list[1][i].end(),
            id_list[1][i].end() - surviving_id_list[1][i].size()));
      }
    }
  }

  // Represents a number of cookies to create, if they are Secure cookies, and
  // a url to add them to.
  struct CookiesEntry {
    size_t num_cookies;
    bool is_secure;
  };
  // A number of secure and a number of non-secure alternative hosts to create
  // for testing.
  typedef std::pair<size_t, size_t> AltHosts;
  // Takes an array of CookieEntries which specify the number, type, and order
  // of cookies to create. Cookies are created in the order they appear in
  // cookie_entries. The value of cookie_entries[x].num_cookies specifies how
  // many cookies of that type to create consecutively, while if
  // cookie_entries[x].is_secure is |true|, those cookies will be marked as
  // Secure.
  void TestSecureCookieEviction(base::span<const CookiesEntry> cookie_entries,
                                size_t expected_secure_cookies,
                                size_t expected_non_secure_cookies,
                                const AltHosts* alt_host_entries) {
    std::unique_ptr<CookieMonster> cm;

    if (alt_host_entries == nullptr) {
      cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
    } else {
      // When generating all of these cookies on alternate hosts, they need to
      // be all older than the max "safe" date for GC, which is currently 30
      // days, so we set them to 60.
      cm = CreateMonsterFromStoreForGC(
          alt_host_entries->first, alt_host_entries->first,
          alt_host_entries->second, alt_host_entries->second, 60);
    }

    int next_cookie_id = 0;
    for (const auto& cookie_entry : cookie_entries) {
      for (size_t j = 0; j < cookie_entry.num_cookies; j++) {
        std::string cookie;
        if (cookie_entry.is_secure)
          cookie = base::StringPrintf("a%d=b; Secure", next_cookie_id);
        else
          cookie = base::StringPrintf("a%d=b", next_cookie_id);
        EXPECT_TRUE(SetCookie(cm.get(), https_www_foo_.url(), cookie));
        ++next_cookie_id;
      }
    }

    CookieList cookies = this->GetAllCookies(cm.get());
    EXPECT_EQ(expected_secure_cookies + expected_non_secure_cookies,
              cookies.size());
    size_t total_secure_cookies = 0;
    size_t total_non_secure_cookies = 0;
    for (const auto& cookie : cookies) {
      if (cookie.SecureAttribute()) {
        ++total_secure_cookies;
      } else {
        ++total_non_secure_cookies;
      }
    }

    EXPECT_EQ(expected_secure_cookies, total_secure_cookies);
    EXPECT_EQ(expected_non_secure_cookies, total_non_secure_cookies);
  }

  void TestPriorityAwareGarbageCollectHelperNonSecure() {
    // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
    DCHECK_EQ(180U, CookieMonster::kDomainMaxCookies);
    DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                        CookieMonster::kDomainPurgeCookies);

    auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());
    // Key:
    // Round 1 => LN; round 2 => LS; round 3 => MN.
    // Round 4 => HN; round 5 => MS; round 6 => HS

    // Each test case adds 181 cookies, so 31 cookies are evicted.
    // Cookie same priority, repeated for each priority.
    TestPriorityCookieCase(cm.get(), "181LN", 150U, 0U, 0U, 150U, 0U);
    TestPriorityCookieCase(cm.get(), "181MN", 0U, 150U, 0U, 150U, 0U);
    TestPriorityCookieCase(cm.get(), "181HN", 0U, 0U, 150U, 150U, 0U);

    // Pairwise scenarios.
    // Round 1 => none; round2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "10HN 171MN", 0U, 140U, 10U, 150U, 0U);
    // Round 1 => 10L; round2 => 21M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "141MN 40LN", 30U, 120U, 0U, 150U, 0U);
    // Round 1 => none; round2 => 30M; round 3 => 1H.
    TestPriorityCookieCase(cm.get(), "101HN 80MN", 0U, 50U, 100U, 150U, 0U);

    // For {low, medium} priorities right on quota, different orders.
    // Round 1 => 1L; round 2 => none, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "31LN 50MN 100HN", 30U, 50U, 70U, 150U,
                           0U);
    // Round 1 => none; round 2 => 1M, round3 => 30H.
    TestPriorityCookieCase(cm.get(), "51MN 100HN 30LN", 30U, 50U, 70U, 150U,
                           0U);
    // Round 1 => none; round 2 => none; round3 => 31H.
    TestPriorityCookieCase(cm.get(), "101HN 50MN 30LN", 30U, 50U, 70U, 150U,
                           0U);

    // Round 1 => 10L; round 2 => 10M; round3 => 11H.
    TestPriorityCookieCase(cm.get(), "81HN 60MN 40LN", 30U, 50U, 70U, 150U, 0U);

    // More complex scenarios.
    // Round 1 => 10L; round 2 => 10M; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "21HN 60MN 40LN 60HN", 30U, 50U, 70U, 150U,
                           0U);
    // Round 1 => 10L; round 2 => 21M; round 3 => 0H.
    TestPriorityCookieCase(cm.get(), "11HN 10MN 20LN 110MN 20LN 10HN", 30U, 99U,
                           21U, 150U, 0U);
    // Round 1 => none; round 2 => none; round 3 => 31H.
    TestPriorityCookieCase(cm.get(), "11LN 10MN 140HN 10MN 10LN", 21U, 20U,
                           109U, 150U, 0U);
    // Round 1 => none; round 2 => 21M; round 3 => 10H.
    TestPriorityCookieCase(cm.get(), "11MN 10HN 10LN 60MN 90HN", 10U, 50U, 90U,
                           150U, 0U);
    // Round 1 => none; round 2 => 31M; round 3 => none.
    TestPriorityCookieCase(cm.get(), "11MN 10HN 10LN 90MN 60HN", 10U, 70U, 70U,
                           150U, 0U);

    // Round 1 => 20L; round 2 => 0; round 3 => 11H
    TestPriorityCookieCase(cm.get(), "50LN 131HN", 30U, 0U, 120U, 150U, 0U);
    // Round 1 => 20L; round 2 => 0; round 3 => 11H
    TestPriorityCookieCase(cm.get(), "131HN 50LN", 30U, 0U, 120U, 150U, 0U);
    // Round 1 => 20L; round 2 => none; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "50HN 50LN 81HN", 30U, 0U, 120U, 150U, 0U);
    // Round 1 => 20L; round 2 => none; round 3 => 11H.
    TestPriorityCookieCase(cm.get(), "81HN 50LN 50HN", 30U, 0U, 120U, 150U, 0U);
  }

  void TestPriorityAwareGarbageCollectHelperSecure() {
    // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
    DCHECK_
```