Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding: The Big Picture**

The file name `session_inclusion_rules_unittest.cc` immediately suggests this code is testing the functionality of something called `SessionInclusionRules`. The `.cc` extension confirms it's C++ source code. The `unittest` suffix signals that it's part of a unit testing framework, likely Google Test (given the `#include "testing/gtest/include/gtest/gtest.h"`). Therefore, the core task is to understand how `SessionInclusionRules` works by examining its tests.

**2. Examining Includes and Namespaces:**

The `#include` directives give hints about the dependencies and concepts involved:

* `"net/device_bound_sessions/session_inclusion_rules.h"`: This is the header file for the class being tested. We'll need to mentally (or actually, if we had the source) refer to its definition.
* `<initializer_list>`:  Suggests the tests will be working with lists of test cases.
* `"base/strings/string_util.h"`:  Likely used for string manipulation, maybe for constructing test case descriptions.
* `"net/base/registry_controlled_domains/registry_controlled_domain.h"`:  Indicates that domain name analysis (like eTLD+1) is a key aspect of `SessionInclusionRules`.
* `"net/device_bound_sessions/proto/storage.pb.h"`: Shows that `SessionInclusionRules` can be serialized to and from a Protocol Buffer, which is used for data storage and transfer.
* `"testing/gtest/include/gtest/gtest.h"`:  Confirms the use of Google Test.
* `"url/gurl.h"` and `"url/origin.h"`:  Crucially important. `SessionInclusionRules` clearly deals with URLs and origins.

The `namespace net::device_bound_sessions` tells us the module this code belongs to.

**3. Dissecting the Test Structure:**

The file is organized into several `TEST` blocks. Each `TEST` focuses on a specific aspect of `SessionInclusionRules`. This is good practice in unit testing. Looking at the test names gives a good overview of the functionality being tested:

* `DefaultConstructorMatchesNothing`
* `DefaultIncludeOriginMayNotIncludeSite`
* `DefaultIncludeOriginThoughMayIncludeSite`
* `IncludeSiteAttemptedButNotAllowed`
* `IncludeSite`
* `AddUrlRuleToOriginOnly`
* `AddUrlRuleToOriginThatMayIncludeSite`
* `AddUrlRuleToRulesIncludingSite`
* `UrlRuleParsing`
* `UrlRuleParsingTopLevelDomain`
* `UrlRuleParsingIPv4Address`
* `UrlRuleParsingIPv6Address`
* `NonstandardPort`
* `ToFromProto`
* `FailCreateFromInvalidProto`

These names provide a high-level understanding of the features being tested.

**4. Analyzing Helper Functions and Structures:**

The code defines helper structures (`EvaluateUrlTestCase`, `AddUrlRuleTestCase`) and functions (`CheckEvaluateUrlTestCases`, `CheckAddUrlRuleTestCases`). These are designed to make the tests more readable and less repetitive.

* `EvaluateUrlTestCase`: Holds a URL string and the expected `InclusionResult`.
* `AddUrlRuleTestCase`: Holds a rule type, host pattern, path prefix, and whether adding the rule is expected to succeed.
* `CheckEvaluateUrlTestCases`: Takes a `SessionInclusionRules` object and a list of `EvaluateUrlTestCase`s, then iterates through them, calling `EvaluateRequestUrl` and asserting the result.
* `CheckAddUrlRuleTestCases`: Does the same for adding URL rules using `AddUrlRuleIfValid`.

The `ASSERT_DOMAIN_AND_REGISTRY` macro is also important, ensuring the domain and registry extraction is working as expected.

**5. Deep Dive into Individual Tests:**

Now, we go through each test, understanding what it's testing and how:

* **Tests about default behavior:**  These check how `SessionInclusionRules` behaves when no specific rules are added. They highlight the difference between including just an origin versus including an entire site.
* **Tests about `SetIncludeSite`:** These focus on the ability to include all subdomains of a given domain (the "site").
* **Tests about `AddUrlRuleIfValid`:** These are crucial for understanding how specific inclusion/exclusion rules can be added based on host patterns and path prefixes. They also test the validation logic for these rules.
* **Tests about URL rule parsing:** These specifically verify the constraints on the format of host patterns when adding rules (wildcards, TLDs, IP addresses, etc.).
* **`NonstandardPort` test:**  This highlights a specific edge case and potential pitfall related to port numbers.
* **`ToFromProto` and `FailCreateFromInvalidProto`:** These test the serialization and deserialization functionality, ensuring data can be saved and loaded correctly.

**6. Identifying Key Concepts and Functionality:**

By analyzing the tests, we can infer the core functionality of `SessionInclusionRules`:

* **Origin-based inclusion:** By default, it seems to only include requests originating from the exact origin it was initialized with.
* **Site-based inclusion:** The `SetIncludeSite` method allows including all subdomains within the same registrable domain.
* **URL-based rules:**  The ability to add specific include or exclude rules based on host patterns and path prefixes.
* **Validation of URL rules:**  Constraints on the format of host patterns.
* **Serialization:** The ability to save and load the inclusion rules.

**7. Relating to JavaScript (if applicable):**

The connection to JavaScript would come if this `SessionInclusionRules` logic is used in the browser's networking stack to make decisions about when to send certain credentials or session identifiers. A JavaScript API might interact with this C++ logic indirectly. For example, a website might use a JavaScript API to request that the browser persist a device-bound session, and the C++ code would use `SessionInclusionRules` to determine the scope of that session.

**8. Inferring Logic and Edge Cases:**

The tests reveal implicit logic:

* **Specificity of rules:**  More specific rules (added later) can override less specific ones.
* **Validation rules for host patterns:**  Restrictions on wildcards, special characters, and domain formats.
* **Handling of different domain types:**  eTLDs, subdomains, IP addresses.

**9. Considering User/Programming Errors:**

The tests themselves highlight potential errors, such as:

* Trying to include a site when initialized with a subdomain.
* Providing invalid host patterns when adding rules.
* Not understanding the implications of `include_site` on port numbers.

**10. Thinking about User Actions (Debugging):**

To reach this code during debugging, a user might:

* Visit a website that utilizes device-bound sessions.
* The browser's networking stack would evaluate the request URL against the stored `SessionInclusionRules`.
* If there's a problem (e.g., a session isn't being used when expected), a developer might investigate the `SessionInclusionRules` and how they were configured.

By following this structured approach, we can systematically understand the purpose, functionality, and implications of a C++ unittest file even without prior knowledge of the specific codebase. The key is to leverage the information provided by file names, includes, test names, and the structure of the tests themselves.
这个 C++ 源代码文件 `session_inclusion_rules_unittest.cc` 是 Chromium 网络栈中 `net/device_bound_sessions/session_inclusion_rules.h` 头文件中定义的 `SessionInclusionRules` 类的单元测试。它的主要功能是 **验证 `SessionInclusionRules` 类的各种行为和逻辑是否正确**。

以下是该文件更详细的功能分解：

**1. 测试 `SessionInclusionRules` 的构造和默认行为:**

* 测试默认构造函数创建的 `SessionInclusionRules` 对象是否不匹配任何 URL。
* 测试使用 Origin 构造的 `SessionInclusionRules` 对象如何基于 Origin 进行匹配，并区分是否包含整个站点 (通过 `SetIncludeSite`)。

**2. 测试 `EvaluateRequestUrl` 方法:**

* 验证 `EvaluateRequestUrl` 方法根据已配置的规则（默认的 Origin 匹配或通过 `SetIncludeSite` 包含站点）判断给定的 URL 是否应该包含在会话中。
* 覆盖了各种 URL 场景，例如：相同 Origin、相同站点的不同子域名、不同的协议、不同的端口、无关的站点等。

**3. 测试 `AddUrlRuleIfValid` 方法:**

* 验证 `AddUrlRuleIfValid` 方法能否正确地添加基于主机名模式和路径前缀的包含或排除规则。
* 测试了各种有效和无效的规则模式，包括：
    * 针对特定主机名和路径的规则。
    * 针对 Origin 的规则限制。
    * 针对整个站点的规则。
    * 无效的 host_pattern 和 path_prefix。
    * 针对顶级域名 (TLD) 和 IP 地址的规则。
* 验证添加规则的优先级和覆盖逻辑。

**4. 测试 URL 规则的解析和验证:**

* 详细测试了 `AddUrlRuleIfValid` 方法对主机名模式的解析和验证逻辑，包括：
    * 空字符串和空白字符串。
    * 非法的字符。
    * 星号通配符的使用限制（只能作为前缀，且后面必须跟一个点，不能用于顶级域名）。
    * 不允许跨站点的规则。
    * 对 IPv4 和 IPv6 地址的支持和限制。
    * 对非标准端口的处理。

**5. 测试 `SetIncludeSite` 方法:**

* 验证 `SetIncludeSite` 方法设置是否包含整个站点，以及这如何影响 `EvaluateRequestUrl` 的结果。
* 测试在不同的 Origin 初始化情况下调用 `SetIncludeSite` 的效果。

**6. 测试与 Protocol Buffer 的序列化和反序列化:**

* 测试 `ToProto` 方法能否将 `SessionInclusionRules` 对象序列化为 Protocol Buffer 消息。
* 测试 `CreateFromProto` 方法能否从 Protocol Buffer 消息成功地反序列化出 `SessionInclusionRules` 对象。
* 覆盖了反序列化失败的各种场景，例如：缺少必要的字段、Origin 无效等。

**与 JavaScript 的关系:**

虽然这个 C++ 代码本身不直接涉及 JavaScript 代码，但 `SessionInclusionRules` 的功能会影响到浏览器中 JavaScript 的行为，特别是与网络请求和会话管理相关的 API。

**举例说明:**

假设一个网站 `https://example.com` 使用了 Device Bound Sessions。浏览器内部会使用 `SessionInclusionRules` 来决定哪些请求应该携带与该会话关联的凭据（例如，客户端证书）。

* **JavaScript 发起请求:** 网站的 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个到 `https://sub.example.com/api/data` 的请求。
* **`SessionInclusionRules` 评估:** 浏览器会使用与 `https://example.com` 关联的 `SessionInclusionRules` 对象来评估这个请求的 URL。
* **规则匹配:**
    * 如果 `SessionInclusionRules` 默认只包含 Origin (`https://example.com`)，那么这个请求将不会被包含，因为它不是完全相同的 Origin。
    * 如果 `SessionInclusionRules` 调用了 `SetIncludeSite(true)`，那么这个请求将被包含，因为 `sub.example.com` 是 `example.com` 的子域名。
    * 如果 `SessionInclusionRules` 添加了规则 `AddUrlRuleIfValid(Result::kInclude, "sub.example.com", "/api/")`，那么这个请求也会被包含。
* **结果:** 根据 `SessionInclusionRules` 的评估结果，浏览器会决定是否在请求头中包含 Device Bound Session 的相关信息。

**逻辑推理、假设输入与输出:**

**假设输入:**

* 一个 `SessionInclusionRules` 对象，其构造函数使用了 Origin `https://example.com`。
* 调用了 `inclusion_rules.SetIncludeSite(true)`。
* 调用了 `inclusion_rules.AddUrlRuleIfValid(Result::kExclude, "blocked.example.com", "/")`。
* 评估以下 URL:
    * `https://example.com/page`
    * `https://sub.example.com/data`
    * `https://blocked.example.com/info`
    * `https://other.com/api`

**输出:**

* `inclusion_rules.EvaluateRequestUrl(GURL("https://example.com/page"))` -> `Result::kInclude` (与 Origin 相同，且包含站点)
* `inclusion_rules.EvaluateRequestUrl(GURL("https://sub.example.com/data"))` -> `Result::kInclude` (在包含的站点内)
* `inclusion_rules.EvaluateRequestUrl(GURL("https://blocked.example.com/info"))` -> `Result::kExclude` (被显式规则排除)
* `inclusion_rules.EvaluateRequestUrl(GURL("https://other.com/api"))` -> `Result::kExclude` (不在包含的站点内)

**用户或编程常见的使用错误:**

1. **错误的理解 Origin 和 Site 的区别:**  用户可能期望默认情况下包含整个站点，但实际上只包含 Origin，需要显式调用 `SetIncludeSite(true)`。
   * **示例:**  开发者创建了一个 `SessionInclusionRules` 对象，使用了 `https://app.example.com` 作为 Origin，但希望来自 `https://api.example.com` 的请求也被包含，却没有调用 `SetIncludeSite(true)`。

2. **添加了无效的 URL 规则:** 用户可能使用了错误的 host_pattern 或 path_prefix 格式，导致规则添加失败或行为不符合预期。
   * **示例:** 尝试添加规则 `AddUrlRuleIfValid(Result::kInclude, "*.example.com", "/")`，这是无效的，因为通配符不能用于顶级域名。

3. **忽略了规则的优先级:** 用户可能添加了多个相互冲突的规则，但没有理解后添加的规则会覆盖之前添加的规则。
   * **示例:** 先添加了排除规则 `AddUrlRuleIfValid(Result::kExclude, "api.example.com", "/")`，然后又添加了包含规则 `AddUrlRuleIfValid(Result::kInclude, "*.example.com", "/")`。后者会覆盖前者。

4. **在非根域名上尝试 `SetIncludeSite(true)`:**  如果使用子域名 (例如 `https://sub.example.com`) 创建 `SessionInclusionRules` 对象并尝试调用 `SetIncludeSite(true)`，这个调用不会有任何效果，因为只有使用根域名 (eTLD+1，例如 `https://example.com`) 创建的对象才能包含整个站点。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户遇到与 Device Bound Sessions 相关的问题:**  例如，用户在一个网站上登录后，跳转到另一个子域名或相关网站时，会话信息丢失，需要重新登录。

2. **开发者开始调试网络请求:** 使用 Chrome 的开发者工具 (DevTools) 的 "Network" 标签，查看请求头，发现预期的 Device Bound Session 凭据没有被发送。

3. **怀疑 `SessionInclusionRules` 配置错误:**  开发者可能会查看与该网站相关的 Device Bound Session 的配置，包括 `SessionInclusionRules` 的设置。

4. **查看源代码或日志:** 开发者可能会查看 Chromium 的源代码，特别是 `net/device_bound_sessions` 目录下的相关文件，来理解 `SessionInclusionRules` 的工作原理和配置方式。他们可能会断点调试到 `EvaluateRequestUrl` 方法，查看是哪些规则导致了请求被排除。

5. **检查 `SessionInclusionRules` 的创建和配置:** 开发者会检查在什么地方创建了 `SessionInclusionRules` 对象，使用了哪个 Origin，是否调用了 `SetIncludeSite`，以及添加了哪些 URL 规则。

6. **分析 URL 规则:** 开发者会仔细分析已添加的 URL 规则，检查是否存在错误或遗漏，导致目标请求的 URL 没有被正确包含。

7. **测试和验证:** 开发者可能会修改 `SessionInclusionRules` 的配置（如果可以），或者编写类似的单元测试来验证他们的理解和修复方案。

总而言之，`session_inclusion_rules_unittest.cc` 是确保 Chromium 网络栈中 Device Bound Sessions 功能正确性的关键组成部分，它通过详尽的测试用例覆盖了 `SessionInclusionRules` 类的各种行为，帮助开发者理解和调试相关问题。

Prompt: 
```
这是目录为net/device_bound_sessions/session_inclusion_rules_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/device_bound_sessions/session_inclusion_rules.h"

#include <initializer_list>

#include "base/strings/string_util.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/device_bound_sessions/proto/storage.pb.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net::device_bound_sessions {

namespace {

using Result = SessionInclusionRules::InclusionResult;

// These tests depend on the registry_controlled_domains code, so assert ahead
// of time that the eTLD+1 is what we expect, for clarity and to avoid confusing
// test failures.
#define ASSERT_DOMAIN_AND_REGISTRY(origin, expected_domain_and_registry)      \
  {                                                                           \
    ASSERT_EQ(                                                                \
        registry_controlled_domains::GetDomainAndRegistry(                    \
            origin, registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES), \
        expected_domain_and_registry)                                         \
        << "Unexpected domain and registry.";                                 \
  }

struct EvaluateUrlTestCase {
  const char* url;
  Result expected_result;
};

void CheckEvaluateUrlTestCases(
    const SessionInclusionRules& inclusion_rules,
    std::initializer_list<EvaluateUrlTestCase> test_cases) {
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.url);
    EXPECT_EQ(inclusion_rules.EvaluateRequestUrl(GURL(test_case.url)),
              test_case.expected_result);
  }
}

struct AddUrlRuleTestCase {
  Result rule_type;
  const char* host_pattern;
  const char* path_prefix;
  bool expected_is_added;
};

void CheckAddUrlRuleTestCases(
    SessionInclusionRules& inclusion_rules,
    std::initializer_list<AddUrlRuleTestCase> test_cases) {
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(base::JoinString(
        {test_case.host_pattern, test_case.path_prefix}, ", "));
    bool is_added = inclusion_rules.AddUrlRuleIfValid(
        test_case.rule_type, test_case.host_pattern, test_case.path_prefix);
    EXPECT_EQ(is_added, test_case.expected_is_added);
  }
}

TEST(SessionInclusionRulesTest, DefaultConstructorMatchesNothing) {
  SessionInclusionRules inclusion_rules;
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  EXPECT_EQ(Result::kExclude,
            inclusion_rules.EvaluateRequestUrl(GURL("https://origin.test")));
  EXPECT_EQ(Result::kExclude, inclusion_rules.EvaluateRequestUrl(GURL()));
}

TEST(SessionInclusionRulesTest, DefaultIncludeOriginMayNotIncludeSite) {
  url::Origin subdomain_origin =
      url::Origin::Create(GURL("https://some.site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(subdomain_origin, "site.test");

  SessionInclusionRules inclusion_rules{subdomain_origin};
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  CheckEvaluateUrlTestCases(
      inclusion_rules, {// URL not valid.
                        {"", Result::kExclude},
                        // Origins match.
                        {"https://some.site.test", Result::kInclude},
                        // Path is allowed.
                        {"https://some.site.test/path", Result::kInclude},
                        // Not same scheme.
                        {"http://some.site.test", Result::kExclude},
                        // Not same host (same-site subdomain).
                        {"https://some.other.site.test", Result::kExclude},
                        // Not same host (superdomain).
                        {"https://site.test", Result::kExclude},
                        // Unrelated site.
                        {"https://unrelated.test", Result::kExclude},
                        // Not same port.
                        {"https://some.site.test:8888", Result::kExclude}});
}

TEST(SessionInclusionRulesTest, DefaultIncludeOriginThoughMayIncludeSite) {
  url::Origin root_site_origin = url::Origin::Create(GURL("https://site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(root_site_origin, "site.test");

  SessionInclusionRules inclusion_rules{root_site_origin};
  EXPECT_TRUE(inclusion_rules.may_include_site_for_testing());

  // All expectations are as above. Even though including the site is allowed,
  // because the origin's host is its root eTLD+1, it is still limited to a
  // default origin inclusion_rules because it did not set include_site.
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {// URL not valid.
                             {"", Result::kExclude},
                             // Origins match.
                             {"https://site.test", Result::kInclude},
                             // Path is allowed.
                             {"https://site.test/path", Result::kInclude},
                             // Not same scheme.
                             {"http://site.test", Result::kExclude},
                             // Not same host (same-site subdomain).
                             {"https://other.site.test", Result::kExclude},
                             // Not same host (superdomain).
                             {"https://test", Result::kExclude},
                             // Unrelated site.
                             {"https://unrelated.test", Result::kExclude},
                             // Not same port.
                             {"https://site.test:8888", Result::kExclude}});
}

TEST(SessionInclusionRulesTest, IncludeSiteAttemptedButNotAllowed) {
  url::Origin subdomain_origin =
      url::Origin::Create(GURL("https://some.site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(subdomain_origin, "site.test");

  SessionInclusionRules inclusion_rules{subdomain_origin};
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  // Only the origin is included.
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {{"https://some.site.test", Result::kInclude},
                             {"https://other.site.test", Result::kExclude}});

  // This shouldn't do anything.
  inclusion_rules.SetIncludeSite(true);
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  // Still only the origin is included.
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {{"https://some.site.test", Result::kInclude},
                             {"https://other.site.test", Result::kExclude}});
}

TEST(SessionInclusionRulesTest, IncludeSite) {
  url::Origin root_site_origin = url::Origin::Create(GURL("https://site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(root_site_origin, "site.test");

  SessionInclusionRules inclusion_rules{root_site_origin};
  EXPECT_TRUE(inclusion_rules.may_include_site_for_testing());

  inclusion_rules.SetIncludeSite(true);

  CheckEvaluateUrlTestCases(
      inclusion_rules, {// URL not valid.
                        {"", Result::kExclude},
                        // Origins match.
                        {"https://site.test", Result::kInclude},
                        // Path is allowed.
                        {"https://site.test/path", Result::kInclude},
                        // Not same scheme (site is schemeful).
                        {"http://site.test", Result::kExclude},
                        // Same-site subdomain is allowed.
                        {"https://some.site.test", Result::kInclude},
                        {"https://some.other.site.test", Result::kInclude},
                        // Not same host (superdomain).
                        {"https://test", Result::kExclude},
                        // Unrelated site.
                        {"https://unrelated.test", Result::kExclude},
                        // Other port is allowed because whole site is included.
                        {"https://site.test:8888", Result::kInclude}});
}

TEST(SessionInclusionRulesTest, AddUrlRuleToOriginOnly) {
  url::Origin subdomain_origin =
      url::Origin::Create(GURL("https://some.site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(subdomain_origin, "site.test");

  SessionInclusionRules inclusion_rules{subdomain_origin};
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  // Only the origin is allowed, since the setting origin is not the root
  // eTLD+1. The only acceptable rules are limited to the origin/same host.
  CheckAddUrlRuleTestCases(
      inclusion_rules,
      {// Host pattern equals origin's host. Path is valid.
       {Result::kExclude, "some.site.test", "/static", true},
       // Add an opposite rule to check later.
       {Result::kInclude, "some.site.test", "/static/included", true},
       // Path not valid.
       {Result::kExclude, "some.site.test", "NotAPath", false},
       // Other host patterns not accepted.
       {Result::kExclude, "*.site.test", "/", false},
       {Result::kExclude, "unrelated.test", "/", false},
       {Result::kExclude, "site.test", "/", false},
       {Result::kExclude, "other.site.test", "/", false},
       {Result::kExclude, "https://some.site.test", "/", false},
       {Result::kExclude, "some.site.test:443", "/", false}});

  EXPECT_EQ(inclusion_rules.num_url_rules_for_testing(), 2u);

  CheckEvaluateUrlTestCases(
      inclusion_rules,
      {// Matches the rule.
       {"https://some.site.test/static", Result::kExclude},
       // A path under the rule's path prefix is subject to the rule.
       {"https://some.site.test/static/some/thing", Result::kExclude},
       // These do not match the rule, so are subject to the basic rules (the
       // origin).
       {"https://some.site.test/staticcccccccc", Result::kInclude},
       {"https://other.site.test/static", Result::kExclude},
       // The more recently added rule wins out.
       {"https://some.site.test/static/included", Result::kInclude}});

  // Note that what matters is when the rule was added, not how specific the URL
  // path prefix is. Let's add another rule now to show that.
  EXPECT_TRUE(inclusion_rules.AddUrlRuleIfValid(Result::kExclude,
                                                "some.site.test", "/"));
  EXPECT_EQ(Result::kExclude, inclusion_rules.EvaluateRequestUrl(GURL(
                                  "https://some.site.test/static/included")));
}

TEST(SessionInclusionRulesTest, AddUrlRuleToOriginThatMayIncludeSite) {
  url::Origin root_site_origin = url::Origin::Create(GURL("https://site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(root_site_origin, "site.test");

  SessionInclusionRules inclusion_rules{root_site_origin};
  EXPECT_TRUE(inclusion_rules.may_include_site_for_testing());

  // Without any rules yet, the basic rules is just the origin, because
  // include_site was not set.
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {{"https://site.test/static", Result::kInclude},
                             {"https://other.site.test", Result::kExclude}});

  // Since the origin's host is the root eTLD+1, it is allowed to set rules that
  // affect URLs other than the setting origin (but still within the site).
  CheckAddUrlRuleTestCases(inclusion_rules,
                           {{Result::kExclude, "excluded.site.test", "/", true},
                            {Result::kInclude, "included.site.test", "/", true},
                            {Result::kExclude, "site.test", "/static", true},
                            // Rules outside of the site are not allowed.
                            {Result::kExclude, "unrelated.test", "/", false}});

  EXPECT_EQ(inclusion_rules.num_url_rules_for_testing(), 3u);

  CheckEvaluateUrlTestCases(inclusion_rules,
                            {// Path is excluded by rule.
                             {"https://site.test/static", Result::kExclude},
                             // Rule excludes URL explicitly.
                             {"https://excluded.site.test", Result::kExclude},
                             // Rule includes URL explicitly.
                             {"https://included.site.test", Result::kInclude},
                             // Rule does not apply to wrong scheme.
                             {"http://included.site.test", Result::kExclude},
                             // No rules applies to these URLs, so the basic
                             // rules (origin) applies.
                             {"https://other.site.test", Result::kExclude},
                             {"https://site.test/stuff", Result::kInclude}});
}

TEST(SessionInclusionRulesTest, AddUrlRuleToRulesIncludingSite) {
  url::Origin root_site_origin = url::Origin::Create(GURL("https://site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(root_site_origin, "site.test");

  SessionInclusionRules inclusion_rules{root_site_origin};
  EXPECT_TRUE(inclusion_rules.may_include_site_for_testing());

  inclusion_rules.SetIncludeSite(true);

  // Without any rules yet, the basic rules is the site.
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {{"https://site.test/static", Result::kInclude},
                             {"https://other.site.test", Result::kInclude}});

  // Since the origin's host is the root eTLD+1, it is allowed to set rules that
  // affect URLs other than the setting origin (but still within the site).
  CheckAddUrlRuleTestCases(inclusion_rules,
                           {{Result::kExclude, "excluded.site.test", "/", true},
                            {Result::kInclude, "included.site.test", "/", true},
                            {Result::kExclude, "site.test", "/static", true},
                            // Rules outside of the site are not allowed.
                            {Result::kExclude, "unrelated.test", "/", false}});

  EXPECT_EQ(inclusion_rules.num_url_rules_for_testing(), 3u);

  CheckEvaluateUrlTestCases(
      inclusion_rules,
      {// Path is excluded by rule.
       {"https://site.test/static", Result::kExclude},
       // Rule excludes URL explicitly.
       {"https://excluded.site.test", Result::kExclude},
       // Rule includes URL explicitly.
       {"https://included.site.test", Result::kInclude},
       // Rule does not apply to wrong scheme.
       {"http://included.site.test", Result::kExclude},
       // No rule applies to these URLs, so the basic rules (site) applies.
       {"https://other.site.test", Result::kInclude},
       {"https://site.test/stuff", Result::kInclude}});

  // Note that the rules are independent of "include_site", so even if that is
  // "revoked" the rules still work the same way.
  inclusion_rules.SetIncludeSite(false);
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {// Path is excluded by rule.
                             {"https://site.test/static", Result::kExclude},
                             // Rule excludes URL explicitly.
                             {"https://excluded.site.test", Result::kExclude},
                             // Rule includes URL explicitly.
                             {"https://included.site.test", Result::kInclude},
                             // No rules applies to these URLs, so the basic
                             // rules (which is now the origin) applies.
                             {"https://other.site.test", Result::kExclude},
                             {"https://site.test/stuff", Result::kInclude}});
}

TEST(SessionInclusionRulesTest, UrlRuleParsing) {
  url::Origin root_site_origin = url::Origin::Create(GURL("https://site.test"));

  ASSERT_DOMAIN_AND_REGISTRY(root_site_origin, "site.test");

  // Use the most permissive type of inclusion_rules, to hit the interesting
  // edge cases.
  SessionInclusionRules inclusion_rules{root_site_origin};
  EXPECT_TRUE(inclusion_rules.may_include_site_for_testing());

  CheckAddUrlRuleTestCases(
      inclusion_rules,
      {// Empty host pattern not permitted.
       {Result::kExclude, "", "/", false},
       // Host pattern that is only whitespace is not permitted.
       {Result::kExclude, " ", "/", false},
       // Forbidden characters in host_pattern.
       {Result::kExclude, "https://site.test", "/", false},
       {Result::kExclude, "site.test:8888", "/", false},
       {Result::kExclude, "site.test,other.test", "/", false},
       // Non-IPv6-allowable characters within the brackets.
       {Result::kExclude, "[*.:abcd::3:4:ff]", "/", false},
       {Result::kExclude, "[1:ab+cd::3:4:ff]", "/", false},
       {Result::kExclude, "[[1:abcd::3:4:ff]]", "/", false},
       // Internal wildcard characters are forbidden in the host pattern.
       {Result::kExclude, "sub.*.site.test", "/", false},
       // Multiple wildcard characters are forbidden in the host pattern.
       {Result::kExclude, "*.sub.*.site.test", "/", false},
       // Wildcard must be followed by a dot.
       {Result::kExclude, "*site.test", "/", false},
       // Wildcard must be followed by a non-eTLD.
       {Result::kExclude, "*.com", "/", false},
       // Other sites are not allowed.
       {Result::kExclude, "unrelated.site", "/", false},
       // Other hosts with no registrable domain are not allowed.
       {Result::kExclude, "4.31.198.44", "/", false},
       {Result::kExclude, "[1:abcd::3:4:ff]", "/", false},
       {Result::kExclude, "co.uk", "/", false},
       {Result::kExclude, "com", "/", false}});
}

TEST(SessionInclusionRulesTest, UrlRuleParsingTopLevelDomain) {
  url::Origin tld_origin = url::Origin::Create(GURL("https://com"));

  ASSERT_DOMAIN_AND_REGISTRY(tld_origin, "");

  SessionInclusionRules inclusion_rules{tld_origin};
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  CheckAddUrlRuleTestCases(
      inclusion_rules,
      {// Exact host is allowed.
       {Result::kExclude, "com", "/", true},
       // Wildcards are not permitted.
       {Result::kExclude, "*.com", "/", false},
       // Other hosts with no registrable domain are not allowed.
       {Result::kExclude, "4.31.198.44", "/", false},
       {Result::kExclude, "[1:abcd::3:4:ff]", "/", false},
       {Result::kExclude, "co.uk", "/", false}});
}

TEST(SessionInclusionRulesTest, UrlRuleParsingIPv4Address) {
  url::Origin ip_origin = url::Origin::Create(GURL("https://4.31.198.44"));

  ASSERT_DOMAIN_AND_REGISTRY(ip_origin, "");

  SessionInclusionRules inclusion_rules{ip_origin};
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  CheckAddUrlRuleTestCases(
      inclusion_rules,
      {// Exact host is allowed.
       {Result::kExclude, "4.31.198.44", "/", true},
       // Wildcards are not permitted.
       {Result::kExclude, "*.31.198.44", "/", false},
       {Result::kExclude, "*.4.31.198.44", "/", false},
       // Other hosts with no registrable domain are not allowed.
       {Result::kExclude, "[1:abcd::3:4:ff]", "/", false},
       {Result::kExclude, "co.uk", "/", false},
       {Result::kExclude, "com", "/", false}});
}

TEST(SessionInclusionRulesTest, UrlRuleParsingIPv6Address) {
  url::Origin ipv6_origin =
      url::Origin::Create(GURL("https://[1:abcd::3:4:ff]"));

  ASSERT_DOMAIN_AND_REGISTRY(ipv6_origin, "");

  SessionInclusionRules inclusion_rules{ipv6_origin};
  EXPECT_FALSE(inclusion_rules.may_include_site_for_testing());

  CheckAddUrlRuleTestCases(
      inclusion_rules,
      {// Exact host is allowed.
       {Result::kExclude, "[1:abcd::3:4:ff]", "/", true},
       // Wildcards are not permitted.
       {Result::kExclude, "*.[1:abcd::3:4:ff]", "/", false},
       // Brackets mismatched.
       {Result::kExclude, "[1:abcd::3:4:ff", "/", false},
       {Result::kExclude, "1:abcd::3:4:ff]", "/", false},
       // Non-IPv6-allowable characters within the brackets.
       {Result::kExclude, "[*.:abcd::3:4:ff]", "/", false},
       {Result::kExclude, "[1:ab+cd::3:4:ff]", "/", false},
       {Result::kExclude, "[[1:abcd::3:4:ff]]", "/", false},
       // Other hosts with no registrable domain are not allowed.
       {Result::kExclude, "4.31.198.44", "/", false},
       {Result::kExclude, "co.uk", "/", false},
       {Result::kExclude, "com", "/", false}});
}

// This test is more to document the current behavior than anything else. We may
// discover a need for more comprehensive support for port numbers in the
// future, in which case:
// TODO(chlily): Support port numbers in URL rules.
TEST(SessionInclusionRulesTest, NonstandardPort) {
  url::Origin nonstandard_port_origin =
      url::Origin::Create(GURL("https://site.test:8888"));

  ASSERT_DOMAIN_AND_REGISTRY(nonstandard_port_origin, "site.test");

  SessionInclusionRules inclusion_rules{nonstandard_port_origin};
  EXPECT_TRUE(inclusion_rules.may_include_site_for_testing());

  // Without any URL rules, the default origin rule allows only the same origin.
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {{"https://site.test", Result::kExclude},
                             {"https://site.test:8888", Result::kInclude},
                             {"https://other.site.test", Result::kExclude}});

  // If we include_site, then same-site URLs regardless of port number are
  // included.
  inclusion_rules.SetIncludeSite(true);
  CheckEvaluateUrlTestCases(inclusion_rules,
                            {{"https://site.test", Result::kInclude},
                             {"https://site.test:8888", Result::kInclude},
                             {"https://site.test:1234", Result::kInclude},
                             {"https://other.site.test", Result::kInclude}});

  // However, adding URL rules to an inclusion_rules based on such an origin may
  // lead to unintuitive outcomes. It is not possible to specify a rule that
  // applies to the same origin as the setting origin if the setting origin has
  // a nonstandard port.
  CheckAddUrlRuleTestCases(
      inclusion_rules,
      {// The pattern is rejected due to the colon, despite being the
       // same origin.
       {Result::kExclude, "site.test:8888", "/", false},
       // A rule with the same host without port specified is accepted.
       // This rule applies to any URL with the specified host.
       {Result::kExclude, "site.test", "/", true},
       // Any explicitly specified port is rejected (due to the colon),
       // even if it's the standard one.
       {Result::kExclude, "site.test:443", "/", false}});

  EXPECT_EQ(inclusion_rules.num_url_rules_for_testing(), 1u);

  CheckEvaluateUrlTestCases(
      inclusion_rules,
      {// This is same-origin but gets caught in the "site.test" rule because
       // the rule didn't specify a port.
       {"https://site.test:8888", Result::kExclude},
       // This is same-site but gets caught in the "site.test" rule because
       // the rule didn't specify a port.
       {"https://site.test:1234", Result::kExclude},
       // Same-site is included by basic rules.
       {"https://other.site.test", Result::kInclude},
       // Also excluded explicitly by rule.
       {"https://site.test", Result::kExclude},
       {"https://site.test:443", Result::kExclude}});
}

TEST(SessionInclusionRulesTest, ToFromProto) {
  // Create a valid SessionInclusionRules object with default inclusion rule and
  // a couple of additional URL rules.
  url::Origin root_site_origin = url::Origin::Create(GURL("https://site.test"));
  ASSERT_DOMAIN_AND_REGISTRY(root_site_origin, "site.test");

  SessionInclusionRules inclusion_rules{root_site_origin};
  EXPECT_TRUE(inclusion_rules.may_include_site_for_testing());
  inclusion_rules.SetIncludeSite(true);
  EXPECT_TRUE(inclusion_rules.AddUrlRuleIfValid(Result::kExclude,
                                                "excluded.site.test", "/"));
  EXPECT_TRUE(inclusion_rules.AddUrlRuleIfValid(Result::kInclude,
                                                "included.site.test", "/"));

  // Create a corresponding proto object and validate.
  proto::SessionInclusionRules proto = inclusion_rules.ToProto();
  EXPECT_EQ(root_site_origin.Serialize(), proto.origin());
  EXPECT_TRUE(proto.do_include_site());
  ASSERT_EQ(proto.url_rules().size(), 2);
  {
    const auto& rule = proto.url_rules(0);
    EXPECT_EQ(rule.rule_type(), proto::RuleType::EXCLUDE);
    EXPECT_EQ(rule.host_matcher_rule(), "excluded.site.test");
    EXPECT_EQ(rule.path_prefix(), "/");
  }
  {
    const auto& rule = proto.url_rules(1);
    EXPECT_EQ(rule.rule_type(), proto::RuleType::INCLUDE);
    EXPECT_EQ(rule.host_matcher_rule(), "included.site.test");
    EXPECT_EQ(rule.path_prefix(), "/");
  }

  // Create a SessionInclusionRules object from the proto and verify
  // that it is the same as the original.
  std::unique_ptr<SessionInclusionRules> restored_inclusion_rules =
      SessionInclusionRules::CreateFromProto(proto);
  ASSERT_TRUE(restored_inclusion_rules != nullptr);
  EXPECT_EQ(*restored_inclusion_rules, inclusion_rules);
}

TEST(SessionInclusionRulesTest, FailCreateFromInvalidProto) {
  // Empty proto.
  {
    proto::SessionInclusionRules proto;
    EXPECT_FALSE(SessionInclusionRules::CreateFromProto(proto));
  }
  // Opaque origin.
  {
    proto::SessionInclusionRules proto;
    proto.set_origin("about:blank");
    proto.set_do_include_site(false);
    EXPECT_FALSE(SessionInclusionRules::CreateFromProto(proto));
  }
  // Create a fully populated proto.
  url::Origin root_site_origin = url::Origin::Create(GURL("https://site.test"));
  SessionInclusionRules inclusion_rules{root_site_origin};
  inclusion_rules.SetIncludeSite(true);
  inclusion_rules.AddUrlRuleIfValid(Result::kExclude, "excluded.site.test",
                                    "/");
  inclusion_rules.AddUrlRuleIfValid(Result::kInclude, "included.site.test",
                                    "/");
  proto::SessionInclusionRules proto = inclusion_rules.ToProto();

  // Test for missing proto fields by clearing the fields one at a time.
  {
    proto::SessionInclusionRules p(proto);
    p.clear_origin();
    EXPECT_FALSE(SessionInclusionRules::CreateFromProto(p));
  }
  {
    proto::SessionInclusionRules p(proto);
    p.clear_do_include_site();
    EXPECT_FALSE(SessionInclusionRules::CreateFromProto(p));
  }
  // URL rules with missing parameters.
  {
    proto::SessionInclusionRules p(proto);
    p.mutable_url_rules(0)->clear_rule_type();
    EXPECT_FALSE(SessionInclusionRules::CreateFromProto(p));
  }
  {
    proto::SessionInclusionRules p(proto);
    p.mutable_url_rules(0)->clear_host_matcher_rule();
    EXPECT_FALSE(SessionInclusionRules::CreateFromProto(p));
  }
  {
    proto::SessionInclusionRules p(proto);
    p.mutable_url_rules(0)->clear_path_prefix();
    EXPECT_FALSE(SessionInclusionRules::CreateFromProto(p));
  }
}

}  // namespace

}  // namespace net::device_bound_sessions

"""

```