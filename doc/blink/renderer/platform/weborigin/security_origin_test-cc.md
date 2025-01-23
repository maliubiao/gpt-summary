Response:
The user wants me to analyze a C++ source code file related to `SecurityOrigin` in the Chromium Blink engine. I need to identify the file's functionalities and explain its relevance to web technologies like JavaScript, HTML, and CSS. I also need to illustrate logical inferences with examples, discuss common usage errors, and finally, provide a summary of the file's purpose based on the provided first part of the code.

Here's a breakdown of the analysis process:

1. **Identify Core Functionality:**  The file name `security_origin_test.cc` strongly suggests this is a unit test file for the `SecurityOrigin` class. I will scan the code for `TEST_F` macros which confirm this. The tests within will reveal the specific functionalities being tested.

2. **Relate to Web Technologies:**  `SecurityOrigin` is a fundamental concept in web security. It defines the context in which scripts execute and resources are accessed. I will look for tests that demonstrate how `SecurityOrigin` relates to concepts like:
    * **Same-origin policy:** Tests involving `IsSameOriginWith` and `CanAccess`.
    * **Cross-origin requests:** Tests involving `CanRequest` and the origin access allow/block lists.
    * **URLs and their components:** Tests related to creating `SecurityOrigin` from different types of URLs and verifying their components (scheme, host, port).
    * **Opaque origins:** Tests related to the behavior of opaque origins (e.g., for `data:` URLs or `blob:` URLs).

3. **Illustrate Logic with Examples:** For tests that involve logical conditions (e.g., `CanAccess`), I will construct hypothetical input URLs/origins and predict the expected boolean output.

4. **Highlight Common Usage Errors:**  I will think about common mistakes developers might make when dealing with security origins, such as:
    * Incorrectly assuming two origins are the same.
    * Misunderstanding the implications of opaque origins.
    * Not properly configuring cross-origin resource sharing (CORS), which is related to origin checks.

5. **Summarize Functionality:**  Based on the analysis of the tests, I will synthesize a concise summary of the purpose of `security_origin_test.cc`.

**Detailed Analysis of the Provided Code (Part 1):**

* **Includes:** The file includes headers related to `SecurityOrigin`, URLs (`KURL`, `GURL`), testing (`gtest`), and network functionalities. This reinforces the idea that the file is testing the `SecurityOrigin` class's interaction with URLs and network concepts.
* **Test Fixture:** The `SecurityOriginTest` class sets up a test environment and provides a `TearDown` method to clear origin access lists, indicating that some tests modify global state.
* **Basic Origin Creation and Comparison:** Tests like `ValidPortsCreateTupleOrigins` verify the creation of non-opaque origins based on scheme, host, and port. Tests like `LocalAccess` and `CanAccess` check basic same-origin and cross-origin access scenarios, including the effect of blocking local access.
* **Opaque Origins:** Tests like `OpaquenessPropagatesToBlobUrls` and `OpaqueOriginIsSameOriginWith` focus on the specific behavior of opaque origins, which are crucial for the security of certain URL types.
* **Cross-Origin Request Handling:** The `CanRequest` tests, along with those involving `AllowListedAccess` and `BlockListedAccess`, are central to testing how `SecurityOrigin` enforces cross-origin request restrictions and how these can be modified via allow/block lists. The `PunycodeNotUnicode` test highlights how these lists handle internationalized domain names.
* **URL Parsing and Conversion:**  The `CreateFromTuple` and `UrlOriginConversions` tests verify the correct creation of `SecurityOrigin` objects from different URL representations and the conversion between `blink::SecurityOrigin` and `url::Origin`.
* **Domain Handling:** Tests like `EffectiveDomain` and `EffectiveDomainSetFromDom` examine how the effective domain of an origin is determined and can be modified.
* **Token for Fast Check:** The `ToTokenForFastCheck` test suggests an optimization mechanism based on a string representation of the origin.
* **Isolated Copies:** The `OpaqueIsolatedCopy` test checks the behavior of copying opaque origins.
* **Edge Cases:**  The `EdgeCases` test addresses specific scenarios like setting the domain to "null" and the impact of blocking local access.
* **Registrable Domain:** The `RegistrableDomain` test verifies the extraction of the registrable domain from an origin.
* **More `IsSameOriginWith` Tests:** The final `IsSameOriginWith` test block provides a series of specific examples to thoroughly test this core functionality.

Based on this analysis, I can now generate the response.
这是目录为 `blink/renderer/platform/weborigin/security_origin_test.cc` 的 Chromium Blink 引擎源代码文件的第一部分，主要功能是**对 `blink::SecurityOrigin` 类的各项功能进行单元测试**。

`SecurityOrigin` 类是 Blink 引擎中用于表示安全源的关键类，它在 Web 安全模型中起着至关重要的作用，例如同源策略（Same-Origin Policy）。这个测试文件通过各种测试用例来验证 `SecurityOrigin` 类的行为是否符合预期。

**与 javascript, html, css 的功能的关系以及举例说明:**

`SecurityOrigin` 的概念直接关系到浏览器如何执行 JavaScript 代码、加载 HTML 文档和应用 CSS 样式，因为同源策略是这些技术安全运作的基础。

* **JavaScript:**
    * **功能关系:** JavaScript 的跨域请求（例如使用 `fetch` 或 `XMLHttpRequest`）会受到同源策略的限制。`SecurityOrigin` 决定了哪些源的脚本可以相互访问资源。
    * **举例说明:**
        * **假设输入:** 一个网页 `https://example.com/index.html` 包含一个 JavaScript 脚本，试图请求 `https://api.example.com/data`。
        * **输出:** 由于 `https://example.com` 和 `https://api.example.com` 的 origin (scheme, host, port) 不同，如果没有配置 CORS（跨域资源共享），浏览器会阻止 JavaScript 发起该请求，这背后的判断逻辑就与 `SecurityOrigin` 的比较有关。`security_origin_test.cc` 中的 `CanRequest` 相关测试就在验证这种跨域请求的限制。
* **HTML:**
    * **功能关系:** HTML 中的 `<iframe>` 标签、`<script>` 标签的 `src` 属性、`<img>` 标签的 `src` 属性等，在加载外部资源时，浏览器会检查这些资源的源是否与当前文档的源相同，这由 `SecurityOrigin` 决定。
    * **举例说明:**
        * **假设输入:** 一个网页 `https://mydomain.com/page.html` 尝试嵌入一个来自 `https://otherdomain.com/resource.js` 的脚本。
        * **输出:** 浏览器会检查这两个 URL 的 origin。如果不同，且没有设置 CORS，脚本的执行可能会被阻止。`security_origin_test.cc` 中的 `IsSameOriginWith` 测试验证了不同 origin 的判断。
* **CSS:**
    * **功能关系:** CSS 中的 `@font-face` 规则、`background-image` 属性等，在加载外部字体或图片资源时，同样会受到同源策略的约束。
    * **举例说明:**
        * **假设输入:** 一个网页 `http://site.net/style.css` 中包含 `@font-face { src: url('https://cdn.net/font.woff'); }`。
        * **输出:** 浏览器会比较 `http://site.net` 和 `https://cdn.net` 的 origin。如果不同，且服务端没有设置正确的 CORS 头，字体资源可能无法加载。虽然这个文件本身没有直接测试 CSS 加载，但它测试了 `SecurityOrigin` 的基本比较和访问控制，这些是 CSS 资源加载安全的基础。

**逻辑推理的假设输入与输出:**

* **`TEST_F(SecurityOriginTest, CanAccess)`:**
    * **假设输入:**  `origin1` 是 `https://foobar.com`，`origin2` 是 `https://foobar.com`。
    * **输出:** `origin1->CanAccess(origin2.get())` 和 `origin2->CanAccess(origin1.get())` 都为 `true` (同源可以访问)。
    * **假设输入:** `origin1` 是 `https://foobar.com`，`origin2` 是 `https://bazbar.com`。
    * **输出:** `origin1->CanAccess(origin2.get())` 和 `origin2->CanAccess(origin1.get())` 都为 `false` (不同源不能直接访问)。

* **`TEST_F(SecurityOriginTest, CanRequest)`:**
    * **假设输入:** `origin` 是 `https://foobar.com`，`url` 是 `https://foobar.com/path`。
    * **输出:** `origin->CanRequest(url)` 为 `true` (同源可以发起请求)。
    * **假设输入:** `origin` 是 `https://foobar.com`，`url` 是 `https://bazbar.com/path`。
    * **输出:** `origin->CanRequest(url)` 为 `false` (不同源不能直接发起请求)。

**涉及用户或者编程常见的使用错误举例说明:**

* **误认为 `http://example.com` 和 `https://example.com` 是同源的。**  这是因为用户可能只关注域名，而忽略了协议。`SecurityOrigin` 的比较会考虑协议，因此这两个 origin 是不同的。测试用例如 `IsSameOriginWith` 中有明确的测试来验证这一点。
* **在开发时，没有意识到跨域请求会被阻止。** 开发者可能会在本地开发环境中工作正常，因为文件协议的限制较少，但部署到服务器后，由于同源策略的限制，跨域请求失败。理解 `SecurityOrigin` 的概念和浏览器的同源策略对于避免这类问题至关重要。
* **错误地配置 Origin Access Allow/Block List。**  例如，使用 `AllowSubdomains` 时，可能会意外地允许访问到不希望开放的子域名。`security_origin_test.cc` 中关于 `CanRequestWithAllowListedAccess` 和 `CannotRequestWithBlockListedAccess` 的测试展示了这些列表的作用和优先级，帮助开发者理解其行为。

**归纳一下它的功能 (第 1 部分):**

总而言之，`blink/renderer/platform/weborigin/security_origin_test.cc` (第一部分) 的主要功能是**系统地测试 `blink::SecurityOrigin` 类的核心功能，包括创建、比较、判断是否可以访问、判断是否可以发起请求等**。 这些测试覆盖了同源策略的基本概念，并验证了 `SecurityOrigin` 在处理不同类型的 URL、opaque origin 以及 Origin Access Allow/Block List 时的行为。 这对于确保 Blink 引擎正确地实施 Web 安全模型至关重要。

### 提示词
```
这是目录为blink/renderer/platform/weborigin/security_origin_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

#include <stdint.h>

#include <string_view>

#include "base/test/scoped_command_line.h"
#include "base/unguessable_token.h"
#include "net/base/url_util.h"
#include "services/network/public/cpp/is_potentially_trustworthy_unittest.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/network/public/mojom/cors.mojom-blink.h"
#include "services/network/public/mojom/cors_origin_pattern.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/blob/blob_url.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_operators.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "url/gurl.h"
#include "url/origin_abstract_tests.h"
#include "url/url_util.h"

namespace blink {

const uint16_t kMaxAllowedPort = UINT16_MAX;

class SecurityOriginTest : public testing::Test {
 protected:
  void TearDown() override { SecurityPolicy::ClearOriginAccessList(); }

  const std::optional<url::Origin::Nonce>& GetNonceForOrigin(
      const SecurityOrigin& origin) {
    return origin.nonce_if_opaque_;
  }

  const base::UnguessableToken* GetNonceForSerializationForOrigin(
      const SecurityOrigin& origin) {
    return origin.GetNonceForSerialization();
  }
};

TEST_F(SecurityOriginTest, ValidPortsCreateTupleOrigins) {
  uint16_t ports[] = {0, 80, 443, 5000, kMaxAllowedPort};

  for (size_t i = 0; i < std::size(ports); ++i) {
    scoped_refptr<const SecurityOrigin> origin =
        SecurityOrigin::CreateFromValidTuple("http", "example.com", ports[i]);
    EXPECT_FALSE(origin->IsOpaque())
        << "Port " << ports[i] << " should have generated a tuple origin.";
  }
}

TEST_F(SecurityOriginTest, LocalAccess) {
  scoped_refptr<SecurityOrigin> file1 =
      SecurityOrigin::CreateFromString("file:///etc/passwd");
  scoped_refptr<const SecurityOrigin> file2 =
      SecurityOrigin::CreateFromString("file:///etc/shadow");

  EXPECT_TRUE(file1->IsSameOriginWith(file1.get()));
  EXPECT_TRUE(file1->IsSameOriginWith(file2.get()));
  EXPECT_TRUE(file2->IsSameOriginWith(file1.get()));

  EXPECT_TRUE(file1->CanAccess(file1.get()));
  EXPECT_TRUE(file1->CanAccess(file2.get()));
  EXPECT_TRUE(file2->CanAccess(file1.get()));

  // Block |file1|'s access to local origins. It should now be same-origin
  // with itself, but shouldn't have access to |file2|.
  file1->BlockLocalAccessFromLocalOrigin();
  EXPECT_TRUE(file1->IsSameOriginWith(file1.get()));
  EXPECT_FALSE(file1->IsSameOriginWith(file2.get()));
  EXPECT_FALSE(file2->IsSameOriginWith(file1.get()));

  EXPECT_TRUE(file1->CanAccess(file1.get()));
  EXPECT_FALSE(file1->CanAccess(file2.get()));
  EXPECT_FALSE(file2->CanAccess(file1.get()));
}

TEST_F(SecurityOriginTest, IsNullURLSecure) {
  EXPECT_FALSE(network::IsUrlPotentiallyTrustworthy(GURL(NullURL())));
}

TEST_F(SecurityOriginTest, CanAccess) {
  struct TestCase {
    bool can_access;
    const char* origin1;
    const char* origin2;
  };

  TestCase tests[] = {
      {true, "https://foobar.com", "https://foobar.com"},
      {false, "https://foobar.com", "https://bazbar.com"},
      {true, "file://localhost/", "file://localhost/"},
      {false, "file:///", "file://localhost/"},
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    scoped_refptr<const SecurityOrigin> origin1 =
        SecurityOrigin::CreateFromString(tests[i].origin1);
    scoped_refptr<const SecurityOrigin> origin2 =
        SecurityOrigin::CreateFromString(tests[i].origin2);
    EXPECT_EQ(tests[i].can_access, origin1->CanAccess(origin2.get()));
    EXPECT_EQ(tests[i].can_access, origin2->CanAccess(origin1.get()));
    EXPECT_FALSE(origin1->DeriveNewOpaqueOrigin()->CanAccess(origin1.get()));
    EXPECT_FALSE(origin2->DeriveNewOpaqueOrigin()->CanAccess(origin1.get()));
    EXPECT_FALSE(origin1->DeriveNewOpaqueOrigin()->CanAccess(origin2.get()));
    EXPECT_FALSE(origin2->DeriveNewOpaqueOrigin()->CanAccess(origin2.get()));
    EXPECT_FALSE(origin2->CanAccess(origin1->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(origin2->CanAccess(origin1->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(origin1->CanAccess(origin2->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(origin2->CanAccess(origin2->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(origin1->DeriveNewOpaqueOrigin()->CanAccess(
        origin1->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(origin2->DeriveNewOpaqueOrigin()->CanAccess(
        origin2->DeriveNewOpaqueOrigin().get()));
  }
}

TEST_F(SecurityOriginTest, CanAccessDetail) {
  struct TestCase {
    SecurityOrigin::AccessResultDomainDetail expected;
    const char* origin1;
    const char* domain1;
    const char* origin2;
    const char* domain2;
  };

  TestCase tests[] = {
      // Actually cross-origin origins
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotSet,
       "https://example.com", nullptr, "https://not-example.com", nullptr},
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotRelevant,
       "https://example.com", "example.com", "https://not-example.com",
       nullptr},
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotRelevant,
       "https://example.com", nullptr, "https://not-example.com",
       "not-example.com"},
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotRelevant,
       "https://example.com", "example.com", "https://not-example.com",
       "not-example.com"},

      // Same-origin origins
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotSet,
       "https://example.com", nullptr, "https://example.com", nullptr},
      {SecurityOrigin::AccessResultDomainDetail::kDomainSetByOnlyOneOrigin,
       "https://example.com", "example.com", "https://example.com", nullptr},
      {SecurityOrigin::AccessResultDomainDetail::kDomainSetByOnlyOneOrigin,
       "https://example.com", nullptr, "https://example.com", "example.com"},
      {SecurityOrigin::AccessResultDomainDetail::kDomainMismatch,
       "https://www.example.com", "www.example.com", "https://www.example.com",
       "example.com"},
      {SecurityOrigin::AccessResultDomainDetail::kDomainMatchUnnecessary,
       "https://example.com", "example.com", "https://example.com",
       "example.com"},

      // Same-origin-domain origins
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotSet,
       "https://a.example.com", nullptr, "https://b.example.com", nullptr},
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotRelevant,
       "https://a.example.com", "example.com", "https://b.example.com",
       nullptr},
      {SecurityOrigin::AccessResultDomainDetail::kDomainNotRelevant,
       "https://a.example.com", nullptr, "https://b.example.com",
       "example.com"},
      {SecurityOrigin::AccessResultDomainDetail::kDomainMatchNecessary,
       "https://a.example.com", "example.com", "https://b.example.com",
       "example.com"},
  };

  for (TestCase test : tests) {
    SCOPED_TRACE(testing::Message()
                 << "\nOrigin 1: `" << test.origin1 << "` ("
                 << (test.domain1 ? test.domain1 : "") << ") \n"
                 << "Origin 2: `" << test.origin2 << "` ("
                 << (test.domain2 ? test.domain2 : "") << ")\n");
    scoped_refptr<SecurityOrigin> origin1 =
        SecurityOrigin::CreateFromString(test.origin1);
    if (test.domain1)
      origin1->SetDomainFromDOM(test.domain1);
    scoped_refptr<SecurityOrigin> origin2 =
        SecurityOrigin::CreateFromString(test.origin2);
    if (test.domain2)
      origin2->SetDomainFromDOM(test.domain2);
    SecurityOrigin::AccessResultDomainDetail detail;
    origin1->CanAccess(origin2.get(), detail);
    EXPECT_EQ(test.expected, detail);
    origin2->CanAccess(origin1.get(), detail);
    EXPECT_EQ(test.expected, detail);
  }
}

TEST_F(SecurityOriginTest, CanRequest) {
  struct TestCase {
    bool can_request;
    const char* origin;
    const char* url;
  };

  TestCase tests[] = {
      {true, "https://foobar.com", "https://foobar.com"},
      {false, "https://foobar.com", "https://bazbar.com"},
  };

  for (size_t i = 0; i < std::size(tests); ++i) {
    scoped_refptr<const SecurityOrigin> origin =
        SecurityOrigin::CreateFromString(tests[i].origin);
    blink::KURL url(tests[i].url);
    EXPECT_EQ(tests[i].can_request, origin->CanRequest(url));
  }
}

TEST_F(SecurityOriginTest, CanRequestWithAllowListedAccess) {
  scoped_refptr<const SecurityOrigin> origin =
      SecurityOrigin::CreateFromString("https://chromium.org");
  const blink::KURL url("https://example.com");

  EXPECT_FALSE(origin->CanRequest(url));
  // Adding the url to the access allowlist should allow the request.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kDisallowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kMediumPriority);
  EXPECT_TRUE(origin->CanRequest(url));
}

TEST_F(SecurityOriginTest, CannotRequestWithBlockListedAccess) {
  scoped_refptr<const SecurityOrigin> origin =
      SecurityOrigin::CreateFromString("https://chromium.org");
  const blink::KURL allowed_url("https://test.example.com");
  const blink::KURL blocked_url("https://example.com");

  // BlockList that is more or same specificity wins.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *origin, "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kDisallowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kLowPriority);
  // Block since example.com is on the allowlist & blocklist.
  EXPECT_FALSE(origin->CanRequest(blocked_url));
  // Allow since *.example.com is on the allowlist but not the blocklist.
  EXPECT_TRUE(origin->CanRequest(allowed_url));
}

TEST_F(SecurityOriginTest, CanRequestWithMoreSpecificAllowList) {
  scoped_refptr<const SecurityOrigin> origin =
      SecurityOrigin::CreateFromString("https://chromium.org");
  const blink::KURL allowed_url("https://test.example.com");
  const blink::KURL blocked_url("https://example.com");

  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "test.example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kMediumPriority);
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *origin, "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kLowPriority);
  // Allow since test.example.com (allowlist) has a higher priority than
  // *.example.com (blocklist).
  EXPECT_TRUE(origin->CanRequest(allowed_url));
  // Block since example.com isn't on the allowlist.
  EXPECT_FALSE(origin->CanRequest(blocked_url));
}

TEST_F(SecurityOriginTest, CanRequestWithPortSpecificAllowList) {
  scoped_refptr<const SecurityOrigin> origin =
      SecurityOrigin::CreateFromString("https://chromium.org");
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "test1.example.com", 443,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowOnlySpecifiedPort,
      network::mojom::CorsOriginAccessMatchPriority::kMediumPriority);
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "test2.example.com", 444,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowOnlySpecifiedPort,
      network::mojom::CorsOriginAccessMatchPriority::kMediumPriority);

  EXPECT_TRUE(origin->CanRequest(blink::KURL("https://test1.example.com")));
  EXPECT_TRUE(origin->CanRequest(blink::KURL("https://test1.example.com:443")));
  EXPECT_FALSE(origin->CanRequest(blink::KURL("https://test1.example.com:43")));

  EXPECT_FALSE(origin->CanRequest(blink::KURL("https://test2.example.com")));
  EXPECT_FALSE(origin->CanRequest(blink::KURL("https://test2.example.com:44")));
  EXPECT_TRUE(origin->CanRequest(blink::KURL("https://test2.example.com:444")));
}

TEST_F(SecurityOriginTest, PunycodeNotUnicode) {
  scoped_refptr<const SecurityOrigin> origin =
      SecurityOrigin::CreateFromString("https://chromium.org");
  const blink::KURL unicode_url("https://☃.net/");
  const blink::KURL punycode_url("https://xn--n3h.net/");

  // Sanity check: Origin blocked by default.
  EXPECT_FALSE(origin->CanRequest(punycode_url));
  EXPECT_FALSE(origin->CanRequest(unicode_url));

  // Verify unicode origin can not be allowlisted.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "☃.net",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kMediumPriority);
  EXPECT_FALSE(origin->CanRequest(punycode_url));
  EXPECT_FALSE(origin->CanRequest(unicode_url));

  // Verify punycode allowlist only affects punycode URLs.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "xn--n3h.net",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kMediumPriority);
  EXPECT_TRUE(origin->CanRequest(punycode_url));
  EXPECT_FALSE(origin->CanRequest(unicode_url));

  // Clear enterprise policy allow/block lists.
  SecurityPolicy::ClearOriginAccessListForOrigin(*origin);

  EXPECT_FALSE(origin->CanRequest(punycode_url));
  EXPECT_FALSE(origin->CanRequest(unicode_url));

  // Simulate <all_urls> being in the extension permissions.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *origin, "https", "",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);

  EXPECT_TRUE(origin->CanRequest(punycode_url));
  EXPECT_FALSE(origin->CanRequest(unicode_url));

  // Verify unicode origin can not be blocklisted.
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *origin, "https", "☃.net",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kLowPriority);
  EXPECT_TRUE(origin->CanRequest(punycode_url));
  EXPECT_FALSE(origin->CanRequest(unicode_url));

  // Verify punycode blocklist only affects punycode URLs.
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *origin, "https", "xn--n3h.net",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kLowPriority);
  EXPECT_FALSE(origin->CanRequest(punycode_url));
  EXPECT_FALSE(origin->CanRequest(unicode_url));
}

TEST_F(SecurityOriginTest, CreateFromTuple) {
  struct TestCase {
    const char* scheme;
    const char* host;
    uint16_t port;
    const char* origin;
  } cases[] = {
      {"http", "example.com", 80, "http://example.com"},
      {"http", "example.com", 0, "http://example.com:0"},
      {"http", "example.com", 81, "http://example.com:81"},
      {"https", "example.com", 443, "https://example.com"},
      {"https", "example.com", 444, "https://example.com:444"},
      {"file", "", 0, "file://"},
      {"file", "example.com", 0, "file://"},
  };

  for (const auto& test : cases) {
    scoped_refptr<const SecurityOrigin> origin =
        SecurityOrigin::CreateFromValidTuple(test.scheme, test.host, test.port);
    EXPECT_EQ(test.origin, origin->ToString()) << test.origin;
  }
}

TEST_F(SecurityOriginTest, OpaquenessPropagatesToBlobUrls) {
  struct TestCase {
    const char* url;
    bool expected_opaqueness;
    const char* expected_origin_string;
  } cases[]{
      {"", true, "null"},
      {"null", true, "null"},
      {"data:text/plain,hello_world", true, "null"},
      {"file:///path", false, "file://"},
      {"filesystem:http://host/filesystem-path", false, "http://host"},
      {"filesystem:file:///filesystem-path", false, "file://"},
      {"filesystem:null/filesystem-path", true, "null"},
      {"blob:http://host/blob-id", false, "http://host"},
      {"blob:file:///blob-id", false, "file://"},
      {"blob:null/blob-id", true, "null"},
  };

  for (const TestCase& test : cases) {
    scoped_refptr<const SecurityOrigin> origin =
        SecurityOrigin::CreateFromString(test.url);
    EXPECT_EQ(test.expected_opaqueness, origin->IsOpaque());
    EXPECT_EQ(test.expected_origin_string, origin->ToString());

    KURL blob_url = BlobURL::CreatePublicURL(origin.get());
    scoped_refptr<const SecurityOrigin> blob_url_origin =
        SecurityOrigin::Create(blob_url);
    EXPECT_EQ(blob_url_origin->IsOpaque(), origin->IsOpaque());
    EXPECT_EQ(blob_url_origin->ToString(), origin->ToString());
    EXPECT_EQ(blob_url_origin->ToRawString(), origin->ToRawString());
  }
}

TEST_F(SecurityOriginTest, OpaqueOriginIsSameOriginWith) {
  scoped_refptr<const SecurityOrigin> opaque_origin =
      SecurityOrigin::CreateUniqueOpaque();
  scoped_refptr<const SecurityOrigin> tuple_origin =
      SecurityOrigin::CreateFromString("http://example.com");

  EXPECT_TRUE(opaque_origin->IsSameOriginWith(opaque_origin.get()));
  EXPECT_FALSE(SecurityOrigin::CreateUniqueOpaque()->IsSameOriginWith(
      opaque_origin.get()));
  EXPECT_FALSE(tuple_origin->IsSameOriginWith(opaque_origin.get()));
  EXPECT_FALSE(opaque_origin->IsSameOriginWith(tuple_origin.get()));
}

TEST_F(SecurityOriginTest, CanonicalizeHost) {
  struct TestCase {
    const char* host;
    const char* canonical_output;
    bool expected_success;
  } cases[] = {
      {"", "", true},
      {"example.test", "example.test", true},
      {"EXAMPLE.TEST", "example.test", true},
      {"eXaMpLe.TeSt/path", "example.test%2Fpath", false},
      {",", ",", true},
      {"💩", "xn--ls8h", true},
      {"[]", "[]", false},
      {"%yo", "%25yo", false},
  };

  for (const TestCase& test : cases) {
    SCOPED_TRACE(testing::Message() << "raw host: '" << test.host << "'");
    String host = String::FromUTF8(test.host);
    bool success = false;
    String canonical_host =
        SecurityOrigin::CanonicalizeSpecialHost(host, &success);
    EXPECT_EQ(test.canonical_output, canonical_host);
    EXPECT_EQ(test.expected_success, success);
  }
}

TEST_F(SecurityOriginTest, UrlOriginConversions) {
  url::ScopedSchemeRegistryForTests scoped_registry;
  url::AddNoAccessScheme("no-access");
  url::AddLocalScheme("nonstandard-but-local");
  struct TestCases {
    const char* const url;
    const char* const scheme;
    const char* const host;
    uint16_t port;
    bool opaque = false;
  } cases[] = {
      // Nonstandard scheme registered as local scheme
      {"nonstandard-but-local:really?really", "nonstandard-but-local", "", 0},

      // IP Addresses
      {"http://192.168.9.1/", "http", "192.168.9.1", 80},
      {"http://[2001:db8::1]/", "http", "[2001:db8::1]", 80},

      // Punycode
      {"http://☃.net/", "http", "xn--n3h.net", 80},
      {"blob:http://☃.net/", "http", "xn--n3h.net", 80},

      // Generic URLs
      {"http://example.com/", "http", "example.com", 80},
      {"http://example.com:123/", "http", "example.com", 123},
      {"https://example.com/", "https", "example.com", 443},
      {"https://example.com:123/", "https", "example.com", 123},
      {"http://user:pass@example.com/", "http", "example.com", 80},
      {"http://example.com:123/?query", "http", "example.com", 123},
      {"https://example.com/#1234", "https", "example.com", 443},
      {"https://u:p@example.com:123/?query#1234", "https", "example.com", 123},
      {"https://example.com:0/", "https", "example.com", 0},

      // Nonstandard schemes.
      {"unrecognized-scheme://localhost/", "", "", 0, true},
      {"mailto:localhost/", "", "", 0, true},
      {"about:blank", "", "", 0, true},

      // Custom no-access scheme.
      {"no-access:blah", "", "", 0, true},

      // Registered URLs
      {"ftp://example.com/", "ftp", "example.com", 21},
      {"ws://example.com/", "ws", "example.com", 80},
      {"wss://example.com/", "wss", "example.com", 443},

      // file: URLs
      {"file:///etc/passwd", "file", "", 0},
      {"file://example.com/etc/passwd", "file", "example.com", 0},

      // Filesystem:
      {"filesystem:http://example.com/type/", "http", "example.com", 80},
      {"filesystem:http://example.com:123/type/", "http", "example.com", 123},
      {"filesystem:https://example.com/type/", "https", "example.com", 443},
      {"filesystem:https://example.com:123/type/", "https", "example.com", 123},

      // Blob:
      {"blob:http://example.com/guid-goes-here", "http", "example.com", 80},
      {"blob:http://example.com:123/guid-goes-here", "http", "example.com",
       123},
      {"blob:https://example.com/guid-goes-here", "https", "example.com", 443},
      {"blob:http://u:p@example.com/guid-goes-here", "http", "example.com", 80},
  };

  for (const auto& test_case : cases) {
    SCOPED_TRACE(test_case.url);
    GURL gurl(test_case.url);
    KURL kurl(String::FromUTF8(test_case.url));
    EXPECT_TRUE(gurl.is_valid());
    EXPECT_TRUE(kurl.IsValid());
    url::Origin origin_via_gurl = url::Origin::Create(gurl);
    scoped_refptr<const SecurityOrigin> security_origin_via_kurl =
        SecurityOrigin::Create(kurl);
    EXPECT_EQ(origin_via_gurl.scheme(), test_case.scheme);

    // Test CreateFromUrlOrigin
    scoped_refptr<const SecurityOrigin> security_origin_via_gurl =
        SecurityOrigin::CreateFromUrlOrigin(origin_via_gurl);
    EXPECT_EQ(test_case.scheme, security_origin_via_gurl->Protocol());
    EXPECT_EQ(test_case.scheme, security_origin_via_kurl->Protocol());
    EXPECT_EQ(test_case.host, security_origin_via_gurl->Host());
    EXPECT_EQ(test_case.host, security_origin_via_kurl->Host());
    EXPECT_EQ(test_case.port, security_origin_via_gurl->Port());
    EXPECT_EQ(test_case.port, security_origin_via_kurl->Port());
    EXPECT_EQ(test_case.opaque, security_origin_via_gurl->IsOpaque());
    EXPECT_EQ(test_case.opaque, security_origin_via_kurl->IsOpaque());
    EXPECT_EQ(!test_case.opaque, security_origin_via_kurl->IsSameOriginWith(
                                     security_origin_via_gurl.get()));
    EXPECT_EQ(!test_case.opaque, security_origin_via_gurl->IsSameOriginWith(
                                     security_origin_via_kurl.get()));

    if (!test_case.opaque) {
      scoped_refptr<const SecurityOrigin> security_origin =
          SecurityOrigin::CreateFromValidTuple(test_case.scheme, test_case.host,
                                               test_case.port);
      EXPECT_TRUE(
          security_origin->IsSameOriginWith(security_origin_via_gurl.get()));
      EXPECT_TRUE(
          security_origin->IsSameOriginWith(security_origin_via_kurl.get()));
      EXPECT_TRUE(
          security_origin_via_gurl->IsSameOriginWith(security_origin.get()));
      EXPECT_TRUE(
          security_origin_via_kurl->IsSameOriginWith(security_origin.get()));
    }

    // Test ToUrlOrigin
    url::Origin origin_roundtrip_via_kurl =
        security_origin_via_kurl->ToUrlOrigin();
    url::Origin origin_roundtrip_via_gurl =
        security_origin_via_gurl->ToUrlOrigin();

    EXPECT_EQ(test_case.opaque, origin_roundtrip_via_kurl.opaque());
    EXPECT_EQ(test_case.opaque, origin_roundtrip_via_gurl.opaque());
    EXPECT_EQ(origin_roundtrip_via_gurl, origin_via_gurl);
    if (!test_case.opaque) {
      EXPECT_EQ(origin_via_gurl, origin_roundtrip_via_kurl);
      EXPECT_EQ(origin_roundtrip_via_kurl, origin_roundtrip_via_gurl);
    }
  }
}

TEST_F(SecurityOriginTest, InvalidWrappedUrls) {
  const char* kTestCases[] = {
      "blob:filesystem:ws:b/.",
      "blob:filesystem:ftp://a/b",
      "filesystem:filesystem:http://example.org:88/foo/bar",
      "blob:blob:file://localhost/foo/bar",
  };

  for (const char* test_url : kTestCases) {
    scoped_refptr<SecurityOrigin> target_origin =
        SecurityOrigin::CreateFromString(test_url);
    EXPECT_TRUE(target_origin->IsOpaque())
        << test_url << " is not opaque as a blink::SecurityOrigin";
    url::Origin origin = target_origin->ToUrlOrigin();
    EXPECT_TRUE(origin.opaque())
        << test_url << " is not opaque as a url::Origin";
  }
}

TEST_F(SecurityOriginTest, EffectiveDomain) {
  constexpr struct {
    const char* expected_effective_domain;
    const char* origin;
  } kTestCases[] = {
      {NULL, ""},
      {NULL, "null"},
      {"", "file://"},
      {"127.0.0.1", "https://127.0.0.1"},
      {"[::1]", "https://[::1]"},
      {"example.com", "file://example.com/foo"},
      {"example.com", "http://example.com"},
      {"example.com", "http://example.com:80"},
      {"example.com", "https://example.com"},
      {"suborigin.example.com", "https://suborigin.example.com"},
  };

  for (const auto& test : kTestCases) {
    scoped_refptr<const SecurityOrigin> origin =
        SecurityOrigin::CreateFromString(test.origin);
    if (test.expected_effective_domain) {
      EXPECT_EQ(test.expected_effective_domain, origin->Domain());
    } else {
      EXPECT_TRUE(origin->Domain().empty());
    }
  }
}

TEST_F(SecurityOriginTest, EffectiveDomainSetFromDom) {
  constexpr struct {
    const char* domain_set_from_dom;
    const char* expected_effective_domain;
    const char* origin;
  } kDomainTestCases[] = {
      {"example.com", "example.com", "http://www.suborigin.example.com"}};

  for (const auto& test : kDomainTestCases) {
    scoped_refptr<SecurityOrigin> origin =
        SecurityOrigin::CreateFromString(test.origin);
    origin->SetDomainFromDOM(test.domain_set_from_dom);
    EXPECT_EQ(test.expected_effective_domain, origin->Domain());
  }
}

TEST_F(SecurityOriginTest, ToTokenForFastCheck) {
  base::UnguessableToken agent_cluster_id = base::UnguessableToken::Create();
  constexpr struct {
    const char* url;
    const char* token;
  } kTestCases[] = {
      {"", nullptr},
      {"null", nullptr},
      {"data:text/plain,hello, world", nullptr},
      {"http://example.org/foo/bar", "http://example.org"},
      {"http://example.org:8080/foo/bar", "http://example.org:8080"},
      {"https://example.org:443/foo/bar", "https://example.org"},
      {"https://example.org:444/foo/bar", "https://example.org:444"},
      {"file:///foo/bar", "file://"},
      {"file://localhost/foo/bar", "file://localhost"},
      {"filesystem:http://example.org:88/foo/bar", "http://example.org:88"},
      // Somehow the host part in the inner URL is dropped.
      // See https://crbug.com/867914 for details.
      {"filesystem:file://localhost/foo/bar", "file://"},
      {"blob:http://example.org:88/foo/bar", "http://example.org:88"},
      {"blob:file://localhost/foo/bar", "file://localhost"},
  };

  for (const auto& test : kTestCases) {
    SCOPED_TRACE(test.url);
    scoped_refptr<SecurityOrigin> origin =
        SecurityOrigin::CreateFromString(test.url)->GetOriginForAgentCluster(
            agent_cluster_id);
    String expected_token;
    if (test.token)
      expected_token = test.token + String(agent_cluster_id.ToString().c_str());
    EXPECT_EQ(expected_token, origin->ToTokenForFastCheck()) << expected_token;
  }
}

TEST_F(SecurityOriginTest, OpaqueIsolatedCopy) {
  scoped_refptr<const SecurityOrigin> origin =
      SecurityOrigin::CreateUniqueOpaque();
  scoped_refptr<const SecurityOrigin> copied = origin->IsolatedCopy();
  EXPECT_TRUE(origin->CanAccess(copied.get()));
  EXPECT_TRUE(origin->IsSameOriginWith(copied.get()));
  EXPECT_EQ(WTF::GetHash(origin), WTF::GetHash(copied));
  EXPECT_TRUE(
      HashTraits<scoped_refptr<const SecurityOrigin>>::Equal(origin, copied));
}

TEST_F(SecurityOriginTest, EdgeCases) {
  scoped_refptr<SecurityOrigin> nulled_domain =
      SecurityOrigin::CreateFromString("http://localhost");
  nulled_domain->SetDomainFromDOM("null");
  EXPECT_TRUE(nulled_domain->CanAccess(nulled_domain.get()));

  scoped_refptr<SecurityOrigin> local =
      SecurityOrigin::CreateFromString("file:///foo/bar");
  local->BlockLocalAccessFromLocalOrigin();
  EXPECT_TRUE(local->IsSameOriginWith(local.get()));
}

TEST_F(SecurityOriginTest, RegistrableDomain) {
  scoped_refptr<SecurityOrigin> opaque = SecurityOrigin::CreateUniqueOpaque();
  EXPECT_TRUE(opaque->RegistrableDomain().IsNull());

  scoped_refptr<SecurityOrigin> ip_address =
      SecurityOrigin::CreateFromString("http://0.0.0.0");
  EXPECT_TRUE(ip_address->RegistrableDomain().IsNull());

  scoped_refptr<SecurityOrigin> public_suffix =
      SecurityOrigin::CreateFromString("http://com");
  EXPECT_TRUE(public_suffix->RegistrableDomain().IsNull());

  scoped_refptr<SecurityOrigin> registrable =
      SecurityOrigin::CreateFromString("http://example.com");
  EXPECT_EQ(String("example.com"), registrable->RegistrableDomain());

  scoped_refptr<SecurityOrigin> subdomain =
      SecurityOrigin::CreateFromString("http://foo.example.com");
  EXPECT_EQ(String("example.com"), subdomain->RegistrableDomain());
}

TEST_F(SecurityOriginTest, IsSameOriginWith) {
  struct TestCase {
    bool same_origin;
    const char* a;
    const char* b;
  } tests[] = {{true, "https://a.com", "https://a.com"},

               // Schemes
               {false, "https://a.com", "http://a.com"},

               // Hosts
               {false, "https://a.com", "https://not-a.com"},
               {false, "https://a.com", "https://sub.a.com"},

               // Ports
               {true, "https://a.com", "https://a.com:443"},
               {false, "https://a.com", "https://a.com:444"},
               {false, "https://a.com:442", "https://a.com:443"},

               // Opaque
               {false, "data:text/html,whatever", "data:text/html,whatever"}};

  for (const auto& test : tests) {
    SCOPED_TRACE(testing:
```