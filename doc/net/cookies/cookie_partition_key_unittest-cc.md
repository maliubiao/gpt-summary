Response:
Let's break down the request and the provided code to formulate a comprehensive answer.

**1. Understanding the Goal:**

The request asks for an analysis of `cookie_partition_key_unittest.cc`. The key aspects to cover are:

* **Functionality:** What does this code do?
* **Relationship to JavaScript:**  How does this connect to client-side scripting?
* **Logical Reasoning (Input/Output):** Can we predict behavior based on inputs?
* **Common Usage Errors:** What mistakes might developers make?
* **User Steps to Reach This Code (Debugging):** How does user interaction relate to this low-level component?

**2. Analyzing the Code Structure:**

* **Includes:** The file includes standard C++ headers (`string`, `tuple`) and Chromium-specific headers (`base/test/scoped_feature_list.h`, `net/...`). This immediately tells us it's a testing file within the Chromium networking stack.
* **Namespace:** It's within the `net` namespace, further confirming its place.
* **Test Fixture:** The `CookiePartitionKeyTest` class uses Google Test (`testing::TestWithParam`). The parameterization with `bool` suggests it's testing different scenarios based on a boolean feature flag.
* **Test Cases:**  The file contains multiple `TEST_P` macros, each representing a different test scenario for the `CookiePartitionKey` class. The names of these tests (`TestFromStorage`, `TestFromUntrustedInput`, `Serialization`, etc.) give strong hints about the aspects of `CookiePartitionKey` being tested.
* **Helper Functions/Data Structures:**  The use of `struct`s like the anonymous ones in `TestFromStorage` and `TestFromUntrustedInput`, and the `Output` struct in `Serialization`, indicates structured test case definitions.
* **Feature Flag:** The `scoped_feature_list_` and `AncestorChainBitEnabled()` relate to a feature flag, suggesting the behavior of `CookiePartitionKey` might be conditional.
* **`kDisablePartitionedCookiesSwitch`:** The checks for this command-line switch are important for understanding how cookie partitioning can be disabled.

**3. Deconstructing the Functionality (Test by Test):**

* **`TestFromStorage`:** Tests the `FromStorage` static method of `CookiePartitionKey`. This likely relates to how partition keys are loaded from persistent storage (like disk). The inputs are a top-level site and a boolean indicating third-party context.
* **`TestFromUntrustedInput`:** Tests `FromUntrustedInput`. This likely handles creating partition keys from data that might not be strictly validated, such as input from web content.
* **`Serialization`:**  Tests the `Serialize` and (implicitly) deserialization of `CookiePartitionKey`. This is critical for storing and retrieving partition keys.
* **`FromNetworkIsolationKey`:**  Tests creating a `CookiePartitionKey` from a `NetworkIsolationKey`. This highlights the relationship between network isolation and cookie partitioning. The parameters (`SiteForCookies`, `request_site`, `main_frame_navigation`) are crucial for understanding the nuances of this creation.
* **`FromWire`:**  Tests creation from "wire" data, likely representing how partition keys are transmitted or stored in a serialized form.
* **`FromStorageKeyComponents`:**  Similar to `FromStorage`, but likely testing a lower-level component-based creation method.
* **`FromScript`:** Tests the `FromScript` static method, which appears to create a special partition key when initiated from JavaScript.
* **`IsSerializeable`:** Tests the `IsSerializeable` method, indicating whether a given partition key can be serialized.
* **`Equality` and `Equality_WithAncestorChain`, `Equality_WithNonce`:** These test the equality operator (`==`) and inequality operator (`!=`) for `CookiePartitionKey` objects, taking into account different properties like ancestor chain bit and nonce.
* **`Localhost`:** A specific test case focusing on how partition keys are handled for `localhost`.

**4. Connecting to JavaScript:**

The `FromScript` test is the most direct link. The name itself strongly suggests that JavaScript can trigger the creation of a `CookiePartitionKey`. The test verifies that keys created this way have an opaque site and are considered third-party.

**5. Logical Reasoning (Input/Output):**

For each test case, I can identify the inputs (e.g., top-level site string, boolean flags, `NetworkIsolationKey` objects) and the expected output (an `optional<CookiePartitionKey>` or a serialized representation). I can then attempt to trace the logic within the `CookiePartitionKey` class (even without seeing its source) based on the test assertions.

**6. Common Usage Errors:**

Based on the test cases, potential errors include:

* Providing invalid top-level site URLs.
* Incorrectly setting the "third-party" flag or ancestor chain bit.
* Not handling the possibility of a missing or invalid partition key (represented by `std::nullopt`).
* Misunderstanding the conditions under which a nonce is included in the partition key.

**7. User Steps (Debugging):**

This is the most speculative part, as it involves mapping user actions to low-level code. I need to think about scenarios where cookie partitioning comes into play:

* **Navigation:** A user navigates between different websites (cross-site navigation).
* **Iframes:** A website embeds content from another domain in an iframe.
* **Subresources:** A website loads images, scripts, or stylesheets from another domain.
* **JavaScript `document.cookie`:** JavaScript on a page attempts to set or read cookies.

By connecting these user actions to the concepts tested in the unit test (e.g., `FromStorage` for loading existing cookies, `FromUntrustedInput` for setting cookies via JavaScript, `FromNetworkIsolationKey` for network requests), I can construct a plausible sequence of events.

**8. Iteration and Refinement:**

As I go through each test case, I refine my understanding of the `CookiePartitionKey`'s behavior. The feature flag testing is important – the behavior might differ depending on whether the `kAncestorChainBitEnabledInPartitionedCookies` feature is enabled. The handling of the `kDisablePartitionedCookiesSwitch` is another critical aspect.

By following this thought process, I can systematically analyze the code and generate a comprehensive and informative answer that addresses all parts of the request.
这个文件 `net/cookies/cookie_partition_key_unittest.cc` 是 Chromium 网络栈中用于测试 `net::CookiePartitionKey` 类的单元测试文件。它的主要功能是验证 `CookiePartitionKey` 类的各种方法和行为是否符合预期。

以下是该文件功能的详细列举：

**主要功能:**

1. **测试 `CookiePartitionKey` 的创建:**
   - 测试从存储中加载 `CookiePartitionKey` (`FromStorage`)。
   - 测试从不可信的输入（例如，可能来自网络或配置）创建 `CookiePartitionKey` (`FromUntrustedInput`)。
   - 测试从 `NetworkIsolationKey` 创建 `CookiePartitionKey` (`FromNetworkIsolationKey`)。这涉及到网络隔离和 Cookie 分区的关系。
   - 测试从“网络”表示形式创建 `CookiePartitionKey` (`FromWire`)。
   - 测试从存储键的组成部分创建 `CookiePartitionKey` (`FromStorageKeyComponents`)。
   - 测试从脚本（JavaScript）创建 `CookiePartitionKey` (`FromScript`)。

2. **测试 `CookiePartitionKey` 的序列化和反序列化:**
   - 测试将 `CookiePartitionKey` 序列化为字符串表示 (`Serialize`)，并验证其正确性。

3. **测试 `CookiePartitionKey` 的属性和方法:**
   - 测试判断 `CookiePartitionKey` 是否可序列化 (`IsSerializeable`)。
   - 测试 `CookiePartitionKey` 的相等性比较运算符 (`==`, `!=`)，包括考虑不同的属性，如 Top Level Site、是否是第三方、以及 Nonce（一个随机值）。
   - 验证 `CookiePartitionKey` 的 `IsThirdParty()` 方法是否返回正确的结果。

4. **测试在不同场景下的 `CookiePartitionKey` 创建:**
   - 测试在启用和禁用 Partitioned Cookies 功能标志时的行为。
   - 测试针对不同类型的 URL（例如，`https`, `file`）创建 `CookiePartitionKey`。
   - 测试在存在或不存在 Nonce 的情况下创建 `CookiePartitionKey`。
   - 测试在主框架导航和非主框架导航时的行为差异。
   - 测试针对 `localhost` 的特殊处理。

**与 JavaScript 的关系及举例说明:**

该文件通过 `TEST_P(CookiePartitionKeyTest, FromScript)` 测试了从 JavaScript 创建 `CookiePartitionKey` 的功能。  当 JavaScript 代码尝试访问或设置 Partitioned Cookies 时，浏览器需要创建一个与当前上下文关联的 `CookiePartitionKey`。

**举例说明:**

假设一个网页 `https://example.com` 嵌入了一个来自 `https://widget.com` 的 iframe。  如果 iframe 中的 JavaScript 代码尝试访问或设置 Cookie，浏览器会调用 `CookiePartitionKey::FromScript()` 来创建一个与这个 iframe 上下文相关的 `CookiePartitionKey`。

在这个测试中，`CookiePartitionKey::FromScript()` 创建的 `CookiePartitionKey` 具有以下特点：

- `from_script()` 返回 `true`，表示它是从脚本创建的。
- `site()` 返回一个 opaque origin，这意味着它与特定的 URL 无关，而是与创建它的脚本上下文相关联。
- `IsThirdParty()` 返回 `true`，因为从 iframe 脚本创建的 Cookie 通常被认为是第三方 Cookie。

**假设输入与输出 (逻辑推理):**

以下是一些测试用例的假设输入和输出示例：

**测试 `FromStorage`:**

* **假设输入:** `top_level_site = "https://toplevelsite.com"`, `third_party = true`
* **预期输出:**  `CookiePartitionKey` 对象，其 `site()` 为 `https://toplevelsite.com`，并且 `IsThirdParty()` 为 `true`。

* **假设输入:** `top_level_site = ""`, `third_party = true`
* **预期输出:**  `CookiePartitionKey` 对象，其 `site()` 为空，表示没有分区。

**测试 `FromUntrustedInput`:**

* **假设输入:** `top_level_site = "https://toplevelsite.com"`, `has_cross_site_ancestor = true`
* **预期输出:** `CookiePartitionKey` 对象，其 `site()` 为 `https://toplevelsite.com`，并且 `IsThirdParty()` 为 `true`。

* **假设输入:** `top_level_site = "invalid_site"`, `has_cross_site_ancestor = false`
* **预期输出:**  一个表示创建失败的 `base::expected` 对象。

**测试 `Serialization`:**

* **假设输入:** `CookiePartitionKey` 对象，其 `site()` 为 `https://toplevelsite.com`，并且是第三方。
* **预期输出:** 序列化后的字符串，例如 `"https://toplevelsite.com|1"` (具体的序列化格式可能会有变化)。

**涉及用户或编程常见的使用错误:**

1. **错误地理解 Cookie 的 SameSite 属性和 Partition Key 的关系:**  开发者可能会错误地认为设置了 `SameSite=None` 的 Cookie 就不需要 Partition Key。但实际上，即使是 `SameSite=None` 的 Cookie，在某些情况下也需要 Partition Key 进行隔离。

2. **在不应该提供 Top Level Site 的情况下提供了:** 当从脚本创建 Partition Key 时，不应该提供具体的 Top Level Site URL，因为它是与脚本的执行上下文相关的。错误地提供具体的 URL 可能会导致意外的行为。

3. **在跨域场景下错误地假设 Cookie 的可访问性:**  开发者可能会假设在所有子域名之间或者在相关的域名之间，没有 Partition Key 的 Cookie 是可以共享的。但启用 Partitioned Cookies 后，即使是同一个顶级域名下的不同站点，其 Cookie 也会被隔离。

4. **忘记处理 Partition Key 为空的情况:** 在某些场景下，可能没有 Partition Key。开发者需要妥善处理这种情况，避免出现空指针或其他错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一些可能导致代码执行到 `net/cookies/cookie_partition_key_unittest.cc` 中相关逻辑的用户操作序列：

1. **跨站导航:**
   - 用户在浏览器中访问 `https://example.com`。
   - `https://example.com` 的页面包含一个链接到 `https://another-site.com`。
   - 用户点击了这个链接。
   - 浏览器在尝试加载 `https://another-site.com` 的页面时，需要决定如何处理 Cookie。
   - 如果启用了 Partitioned Cookies，浏览器会检查与 `https://another-site.com` 关联的 Cookie 是否有 Partition Key。
   - 这个过程可能会涉及到从存储中加载 Cookie，即 `CookiePartitionKey::FromStorage` 的相关逻辑。

2. **嵌入第三方内容 (iframe):**
   - 用户访问 `https://main-site.com`。
   - `https://main-site.com` 的页面中嵌入了一个来自 `https://widget-site.com` 的 iframe。
   - iframe 中的 JavaScript 代码尝试设置或读取 Cookie（例如，使用 `document.cookie`）。
   - 浏览器会调用 `CookiePartitionKey::FromScript()` 来为这个 iframe 创建一个 Partition Key。

3. **通过 JavaScript 发起跨域请求:**
   - 用户访问 `https://user-site.com`。
   - 页面上的 JavaScript 代码使用 `fetch` 或 `XMLHttpRequest` 向 `https://api-server.com` 发起请求，并且 `credentials: 'include'`。
   - 浏览器在发送请求时，需要确定哪些 Cookie 可以包含在请求头中。
   - 如果启用了 Partitioned Cookies，浏览器会考虑目标 URL (`https://api-server.com`) 以及发起请求的页面的 Partition Key。

4. **浏览器启动和加载已存在的 Cookie:**
   - 用户启动浏览器。
   - 浏览器会加载之前存储的 Cookie 信息。
   - 加载 Cookie 的过程中，会涉及到读取 Cookie 的 Partition Key 信息，这会触发 `CookiePartitionKey::FromStorage` 的相关逻辑。

**作为调试线索:**

当开发者在调试与 Cookie 分区相关的问题时，可以利用这些信息来设置断点或添加日志：

- 在 `CookiePartitionKey::FromStorage` 中设置断点，可以观察 Cookie 是如何从存储中加载的，以及 Partition Key 是如何确定的。
- 在 `CookiePartitionKey::FromScript` 中设置断点，可以了解在哪些情况下会从 JavaScript 创建 Partition Key。
- 查看网络请求的 Cookie 头，可以确认请求中是否包含了 Partitioned Cookies，以及它们的 Partition Key 是什么。
- 使用 Chrome 的开发者工具 (DevTools) 的 "Application" 标签下的 "Cookies" 面板，可以查看当前网站的 Cookie 及其 Partition Key 信息。

通过理解这些用户操作和代码逻辑之间的联系，开发者可以更有效地诊断和解决与 Cookie 分区相关的问题。

### 提示词
```
这是目录为net/cookies/cookie_partition_key_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_partition_key.h"

#include <string>
#include <tuple>

#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_switches.h"
#include "net/cookies/site_for_cookies.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

using enum CookiePartitionKey::AncestorChainBit;

class CookiePartitionKeyTest : public testing::TestWithParam<bool> {
 protected:
  // testing::Test
  void SetUp() override {
    scoped_feature_list_.InitWithFeatureState(
        features::kAncestorChainBitEnabledInPartitionedCookies,
        AncestorChainBitEnabled());
  }

  bool AncestorChainBitEnabled() { return GetParam(); }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

INSTANTIATE_TEST_SUITE_P(/* no label */,
                         CookiePartitionKeyTest,
                         ::testing::Bool());

TEST_P(CookiePartitionKeyTest, TestFromStorage) {
  struct {
    const std::string top_level_site;
    bool third_party;
    const std::optional<CookiePartitionKey> expected_output;
  } cases[] = {
      {/*empty site*/
       "", true, CookiePartitionKey::FromURLForTesting(GURL(""))},
      /*invalid site*/
      {"Invalid", true, std::nullopt},
      /*malformed site*/
      {"https://toplevelsite.com/", true, std::nullopt},
      /*valid site: cross site*/
      {"https://toplevelsite.com", true,
       CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"))},
      /*valid site: same site*/
      {"https://toplevelsite.com", false,
       CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"),
                                             kSameSite)}};
  for (const auto& tc : cases) {
    base::expected<std::optional<CookiePartitionKey>, std::string> got =
        CookiePartitionKey::FromStorage(tc.top_level_site, tc.third_party);
    EXPECT_EQ(got.has_value(), tc.expected_output.has_value());
    if (!tc.top_level_site.empty() && tc.expected_output.has_value()) {
      ASSERT_TRUE(got.has_value()) << "Expected result to have value.";
      EXPECT_EQ(got.value()->IsThirdParty(), tc.third_party);
    }
  }

  {
    base::CommandLine::ForCurrentProcess()->AppendSwitch(
        kDisablePartitionedCookiesSwitch);
    EXPECT_FALSE(
        CookiePartitionKey::FromStorage("https://toplevelsite.com",
                                        /*has_cross_site_ancestor=*/true)
            .has_value());
  }
}

TEST_P(CookiePartitionKeyTest, TestFromUntrustedInput) {
  const std::string kFullURL = "https://subdomain.toplevelsite.com/index.html";
  const std::string kValidSite = "https://toplevelsite.com";
  struct Output {
    bool third_party;
  };
  struct {
    std::string top_level_site;
    CookiePartitionKey::AncestorChainBit has_cross_site_ancestor;
    std::optional<Output> expected_output;
  } cases[] = {
      {/*empty site*/
       "", kCrossSite, std::nullopt},
      {/*empty site : same site ancestor*/
       "", kSameSite, std::nullopt},
      {/*valid site*/
       kValidSite, kCrossSite, Output{true}},
      {/*valid site: same site ancestor*/
       kValidSite, kSameSite, Output{false}},
      {/*valid site with extra slash: same site ancestor*/
       kValidSite + "/", kSameSite, Output{false}},
      {/*invalid site (missing scheme)*/
       "toplevelsite.com", kCrossSite, std::nullopt},
      {/*invalid site (missing scheme): same site ancestor*/
       "toplevelsite.com", kSameSite, std::nullopt},
      {/*invalid site*/
       "abc123foobar!!", kCrossSite, std::nullopt},
      {/*invalid site: same site ancestor*/
       "abc123foobar!!", kSameSite, std::nullopt},
  };

  for (const auto& tc : cases) {
    base::expected<CookiePartitionKey, std::string> got =
        CookiePartitionKey::FromUntrustedInput(
            tc.top_level_site, tc.has_cross_site_ancestor == kCrossSite);
    EXPECT_EQ(got.has_value(), tc.expected_output.has_value());
    if (tc.expected_output.has_value()) {
      EXPECT_EQ(got->site().Serialize(), kValidSite);
      EXPECT_EQ(got->IsThirdParty(), tc.expected_output->third_party);
    }
  }

  {
    base::CommandLine::ForCurrentProcess()->AppendSwitch(
        kDisablePartitionedCookiesSwitch);
    EXPECT_FALSE(
        CookiePartitionKey::FromUntrustedInput("https://toplevelsite.com",
                                               /*has_cross_site_ancestor=*/true)
            .has_value());
  }
}

TEST_P(CookiePartitionKeyTest, Serialization) {
  base::UnguessableToken nonce = base::UnguessableToken::Create();
  struct Output {
    std::string top_level_site;
    bool cross_site;
  };
  struct {
    std::optional<CookiePartitionKey> input;
    std::optional<Output> expected_output;
  } cases[] = {
      // No partition key
      {std::nullopt, Output{kEmptyCookiePartitionKey, true}},
      // Partition key present
      {CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com")),
       Output{"https://toplevelsite.com", true}},
      // Local file URL
      {CookiePartitionKey::FromURLForTesting(GURL("file:///path/to/file.txt")),
       Output{"file://", true}},
      // File URL with host
      {CookiePartitionKey::FromURLForTesting(
           GURL("file://toplevelsite.com/path/to/file.pdf")),
       Output{"file://toplevelsite.com", true}},
      // Opaque origin
      {CookiePartitionKey::FromURLForTesting(GURL()), std::nullopt},
      // AncestorChain::kSameSite
      {CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"),
                                             kSameSite, std::nullopt),
       Output{"https://toplevelsite.com", false}},
      // AncestorChain::kCrossSite
      {CookiePartitionKey::FromURLForTesting(GURL("https://toplevelsite.com"),
                                             kCrossSite, std::nullopt),
       Output{"https://toplevelsite.com", true}},
      // With nonce
      {CookiePartitionKey::FromNetworkIsolationKey(
           NetworkIsolationKey(SchemefulSite(GURL("https://toplevelsite.com")),
                               SchemefulSite(GURL("https://cookiesite.com")),
                               nonce),
           SiteForCookies::FromUrl(GURL::EmptyGURL()),
           SchemefulSite(GURL("https://toplevelsite.com")),
           /*main_frame_navigation=*/false),
       std::nullopt},
      // Same site no nonce from NIK
      {CookiePartitionKey::FromNetworkIsolationKey(
           NetworkIsolationKey(SchemefulSite(GURL("https://toplevelsite.com")),
                               SchemefulSite(GURL("https://toplevelsite.com"))),
           SiteForCookies::FromUrl(GURL("https://toplevelsite.com")),
           SchemefulSite(GURL("https://toplevelsite.com")),
           /*main_frame_navigation=*/false),
       Output{"https://toplevelsite.com", false}},
      // Different request_site results in cross site ancestor
      {CookiePartitionKey::FromNetworkIsolationKey(
           NetworkIsolationKey(SchemefulSite(GURL("https://toplevelsite.com")),
                               SchemefulSite(GURL("https://toplevelsite.com"))),
           SiteForCookies::FromUrl(GURL("https://toplevelsite.com")),
           SchemefulSite(GURL("https://differentOrigin.com")),
           /*main_frame_navigation=*/false),
       Output{"https://toplevelsite.com", true}},
      // Different request_site but main_frame_navigation=true results in same
      // site ancestor
      {CookiePartitionKey::FromNetworkIsolationKey(
           NetworkIsolationKey(SchemefulSite(GURL("https://toplevelsite.com")),
                               SchemefulSite(GURL("https://toplevelsite.com"))),
           SiteForCookies::FromUrl(GURL("https://toplevelsite.com")),
           SchemefulSite(GURL("https://differentOrigin.com")),
           /*main_frame_navigation=*/true),
       Output{"https://toplevelsite.com", false}},
      // Different request_site  and null site_for_cookies but
      // main_frame_navigation=true results in same
      // site ancestor
      {CookiePartitionKey::FromNetworkIsolationKey(
           NetworkIsolationKey(SchemefulSite(GURL("https://toplevelsite.com")),
                               SchemefulSite(GURL("https://toplevelsite.com"))),
           SiteForCookies::FromUrl(GURL()),
           SchemefulSite(GURL("https://differentOrigin.com")),
           /*main_frame_navigation=*/true),
       Output{"https://toplevelsite.com", false}},
      // Same site with nonce from NIK
      {CookiePartitionKey::FromNetworkIsolationKey(
           NetworkIsolationKey(SchemefulSite(GURL("https://toplevelsite.com")),
                               SchemefulSite(GURL("https://toplevelsite.com")),
                               nonce),
           SiteForCookies::FromUrl(GURL("https://toplevelsite.com")),
           SchemefulSite(GURL("https://toplevelsite.com")),
           /*main_frame_navigation=*/false),
       std::nullopt},
      // Invalid partition key
      {std::make_optional(
           CookiePartitionKey::FromURLForTesting(GURL("abc123foobar!!"))),
       std::nullopt},
  };

  for (const auto& tc : cases) {
    base::expected<CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        got = CookiePartitionKey::Serialize(tc.input);

    EXPECT_EQ(tc.expected_output.has_value(), got.has_value());
    if (got.has_value()) {
      EXPECT_EQ(tc.expected_output->top_level_site, got->TopLevelSite());
      EXPECT_EQ(tc.expected_output->cross_site, got->has_cross_site_ancestor());
    }
  }
}

TEST_P(CookiePartitionKeyTest, FromNetworkIsolationKey) {
  const SchemefulSite kTopLevelSite =
      SchemefulSite(GURL("https://toplevelsite.com"));
  const SchemefulSite kCookieSite =
      SchemefulSite(GURL("https://cookiesite.com"));
  const base::UnguessableToken kNonce = base::UnguessableToken::Create();

  struct TestCase {
    const std::string desc;
    const NetworkIsolationKey network_isolation_key;
    const std::optional<CookiePartitionKey> expected;
    const SiteForCookies site_for_cookies;
    const SchemefulSite request_site;
    const bool main_frame_navigation;
  } test_cases[] = {
      {"Empty", NetworkIsolationKey(), std::nullopt,
       SiteForCookies::FromUrl(GURL::EmptyGURL()), SchemefulSite(GURL("")),
       /*main_frame_navigation=*/false},
      {"WithTopLevelSite", NetworkIsolationKey(kTopLevelSite, kCookieSite),
       CookiePartitionKey::FromURLForTesting(kTopLevelSite.GetURL()),
       SiteForCookies::FromUrl(GURL::EmptyGURL()), SchemefulSite(kTopLevelSite),
       /*main_frame_navigation=*/false},
      {"WithNonce", NetworkIsolationKey(kTopLevelSite, kCookieSite, kNonce),
       CookiePartitionKey::FromURLForTesting(kCookieSite.GetURL(), kCrossSite,
                                             kNonce),
       SiteForCookies::FromUrl(GURL::EmptyGURL()), SchemefulSite(kTopLevelSite),
       /*main_frame_navigation=*/false},
      {"WithCrossSiteAncestorSameSite",
       NetworkIsolationKey(kTopLevelSite, kTopLevelSite),
       CookiePartitionKey::FromURLForTesting(kTopLevelSite.GetURL(), kSameSite,
                                             std::nullopt),
       SiteForCookies::FromUrl(GURL(kTopLevelSite.GetURL())),
       SchemefulSite(kTopLevelSite), /*main_frame_navigation=*/false},
      {"Nonced first party NIK results in kCrossSite partition key",
       NetworkIsolationKey(kTopLevelSite, kTopLevelSite, kNonce),
       CookiePartitionKey::FromURLForTesting(kTopLevelSite.GetURL(), kCrossSite,
                                             kNonce),
       SiteForCookies::FromUrl(GURL(kTopLevelSite.GetURL())),
       SchemefulSite(kTopLevelSite), /*main_frame_navigation=*/false},
      {"WithCrossSiteAncestorNotSameSite",
       NetworkIsolationKey(kTopLevelSite, kTopLevelSite),
       CookiePartitionKey::FromURLForTesting(kTopLevelSite.GetURL(), kCrossSite,
                                             std::nullopt),
       SiteForCookies::FromUrl(GURL::EmptyGURL()), kCookieSite,
       /*main_frame_navigation=*/false},
      {"TestMainFrameNavigationParam",
       NetworkIsolationKey(kTopLevelSite, kTopLevelSite),
       CookiePartitionKey::FromURLForTesting(kTopLevelSite.GetURL(), kSameSite,
                                             std::nullopt),
       SiteForCookies::FromUrl(GURL(kTopLevelSite.GetURL())),
       SchemefulSite(kCookieSite), /*main_frame_navigation=*/true},
      {"PresenceOfNonceTakesPriorityOverMainFrameNavigation",
       NetworkIsolationKey(kTopLevelSite, kTopLevelSite, kNonce),
       CookiePartitionKey::FromURLForTesting(kTopLevelSite.GetURL(), kCrossSite,
                                             kNonce),
       SiteForCookies::FromUrl(GURL(kTopLevelSite.GetURL())),
       SchemefulSite(kTopLevelSite), /*main_frame_navigation=*/true},
  };

  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatureState(
      features::kAncestorChainBitEnabledInPartitionedCookies,
      AncestorChainBitEnabled());

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.desc);

    std::optional<CookiePartitionKey> got =
        CookiePartitionKey::FromNetworkIsolationKey(
            test_case.network_isolation_key, test_case.site_for_cookies,
            test_case.request_site, test_case.main_frame_navigation);

    EXPECT_EQ(test_case.expected, got);
    if (got) {
      EXPECT_EQ(test_case.network_isolation_key.GetNonce(), got->nonce());
    }
  }
}

TEST_P(CookiePartitionKeyTest, FromWire) {
  struct TestCase {
    const GURL url;
    const std::optional<base::UnguessableToken> nonce;
    const CookiePartitionKey::AncestorChainBit ancestor_chain_bit;
  } test_cases[] = {
      {GURL("https://foo.com"), std::nullopt, kCrossSite},
      {GURL("https://foo.com"), std::nullopt, kSameSite},
      {GURL(), std::nullopt, kCrossSite},
      {GURL("https://foo.com"), base::UnguessableToken::Create(), kCrossSite}};

  for (const auto& test_case : test_cases) {
    auto want = CookiePartitionKey::FromURLForTesting(
        test_case.url, test_case.ancestor_chain_bit, test_case.nonce);
    auto got = CookiePartitionKey::FromWire(
        want.site(), want.IsThirdParty() ? kCrossSite : kSameSite,
        want.nonce());
    EXPECT_EQ(want, got);
    EXPECT_FALSE(got.from_script());
  }
}

TEST_P(CookiePartitionKeyTest, FromStorageKeyComponents) {
  struct TestCase {
    const GURL url;
    const std::optional<base::UnguessableToken> nonce = std::nullopt;
    const CookiePartitionKey::AncestorChainBit ancestor_chain_bit;
  } test_cases[] = {
      {GURL("https://foo.com"), std::nullopt, kCrossSite},
      {GURL("https://foo.com"), std::nullopt, kSameSite},
      {GURL(), std::nullopt, kCrossSite},
      {GURL("https://foo.com"), base::UnguessableToken::Create(), kCrossSite}};

  for (const auto& test_case : test_cases) {
    auto want = CookiePartitionKey::FromURLForTesting(
        test_case.url, test_case.ancestor_chain_bit, test_case.nonce);
    std::optional<CookiePartitionKey> got =
        CookiePartitionKey::FromStorageKeyComponents(
            want.site(), want.IsThirdParty() ? kCrossSite : kSameSite,
            want.nonce());
    EXPECT_EQ(got, want);
  }
}

TEST_P(CookiePartitionKeyTest, FromScript) {
  auto key = CookiePartitionKey::FromScript();
  EXPECT_TRUE(key);
  EXPECT_TRUE(key->from_script());
  EXPECT_TRUE(key->site().opaque());
  EXPECT_TRUE(key->IsThirdParty());

  auto key2 = CookiePartitionKey::FromScript();
  EXPECT_TRUE(key2);
  EXPECT_TRUE(key2->from_script());
  EXPECT_TRUE(key2->site().opaque());
  EXPECT_TRUE(key2->IsThirdParty());

  // The keys should not be equal because they get created with different opaque
  // sites. Test both the '==' and '!=' operators here.
  EXPECT_FALSE(key == key2);
  EXPECT_TRUE(key != key2);
}

TEST_P(CookiePartitionKeyTest, IsSerializeable) {
  EXPECT_FALSE(CookiePartitionKey::FromURLForTesting(GURL()).IsSerializeable());
  EXPECT_TRUE(
      CookiePartitionKey::FromURLForTesting(GURL("https://www.example.com"))
          .IsSerializeable());
}

TEST_P(CookiePartitionKeyTest, Equality) {
  // Same eTLD+1 but different scheme are not equal.
  EXPECT_NE(CookiePartitionKey::FromURLForTesting(GURL("https://foo.com")),
            CookiePartitionKey::FromURLForTesting(GURL("http://foo.com")));

  // Different subdomains of the same site are equal.
  EXPECT_EQ(CookiePartitionKey::FromURLForTesting(GURL("https://a.foo.com")),
            CookiePartitionKey::FromURLForTesting(GURL("https://b.foo.com")));
}

TEST_P(CookiePartitionKeyTest, Equality_WithAncestorChain) {
  CookiePartitionKey key1 = CookiePartitionKey::FromURLForTesting(
      GURL("https://foo.com"), kSameSite, std::nullopt);
  CookiePartitionKey key2 = CookiePartitionKey::FromURLForTesting(
      GURL("https://foo.com"), kCrossSite, std::nullopt);

  EXPECT_EQ((key1 == key2), !AncestorChainBitEnabled());
  EXPECT_EQ(key1, CookiePartitionKey::FromURLForTesting(
                      GURL("https://foo.com"), kSameSite, std::nullopt));
}

TEST_P(CookiePartitionKeyTest, Equality_WithNonce) {
  SchemefulSite top_level_site =
      SchemefulSite(GURL("https://toplevelsite.com"));
  SchemefulSite frame_site = SchemefulSite(GURL("https://cookiesite.com"));
  base::UnguessableToken nonce1 = base::UnguessableToken::Create();
  base::UnguessableToken nonce2 = base::UnguessableToken::Create();
  EXPECT_NE(nonce1, nonce2);
  auto key1 = CookiePartitionKey::FromNetworkIsolationKey(
      NetworkIsolationKey(top_level_site, frame_site, nonce1), SiteForCookies(),
      top_level_site, /*main_frame_navigation=*/false);
  EXPECT_TRUE(key1.has_value());

  auto key2 = CookiePartitionKey::FromNetworkIsolationKey(
      NetworkIsolationKey(top_level_site, frame_site, nonce2), SiteForCookies(),
      top_level_site, /*main_frame_navigation=*/false);
  EXPECT_TRUE(key1.has_value() && key2.has_value());
  EXPECT_NE(key1, key2);

  auto key3 = CookiePartitionKey::FromNetworkIsolationKey(
      NetworkIsolationKey(top_level_site, frame_site, nonce1), SiteForCookies(),
      top_level_site, /*main_frame_navigation=*/false);
  EXPECT_EQ(key1, key3);
  // Confirm that nonce is evaluated before main_frame_navigation
  auto key4 = CookiePartitionKey::FromNetworkIsolationKey(
      NetworkIsolationKey(top_level_site, frame_site, nonce1), SiteForCookies(),
      top_level_site, /*main_frame_navigation=*/true);
  EXPECT_EQ(key1, key4);
  auto unnonced_key = CookiePartitionKey::FromNetworkIsolationKey(
      NetworkIsolationKey(top_level_site, frame_site), SiteForCookies(),
      frame_site, /*main_frame_navigation=*/false);
  EXPECT_NE(key1, unnonced_key);
}

TEST_P(CookiePartitionKeyTest, Localhost) {
  SchemefulSite top_level_site(GURL("https://localhost:8000"));

  auto key = CookiePartitionKey::FromNetworkIsolationKey(
      NetworkIsolationKey(top_level_site, top_level_site), SiteForCookies(),
      top_level_site, /*main_frame_navigation=*/false);
  EXPECT_TRUE(key.has_value());

  SchemefulSite frame_site(GURL("https://cookiesite.com"));
  key = CookiePartitionKey::FromNetworkIsolationKey(
      NetworkIsolationKey(top_level_site, frame_site), SiteForCookies(),
      top_level_site, /*main_frame_navigation=*/false);
  EXPECT_TRUE(key.has_value());
}

}  // namespace net
```