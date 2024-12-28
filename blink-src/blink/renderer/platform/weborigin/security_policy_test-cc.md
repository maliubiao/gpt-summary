Response:
Let's break down the thought process to analyze the provided C++ test file.

1. **Identify the Core Subject:** The filename `security_policy_test.cc` and the included header `security_policy.h` immediately tell us this file tests the `SecurityPolicy` class in the Chromium Blink engine. This class likely deals with web security aspects.

2. **Scan for Key Functionality Areas:**  Look at the `TEST` macros. Each `TEST` function focuses on a specific aspect of `SecurityPolicy`. A quick scan reveals these areas:
    * Referrer generation (`GenerateReferrer`, `EmptyReferrerForUnauthorizedScheme`, `GenerateReferrerRespectsReferrerSchemesRegistry`, `ShouldHideReferrerRespectsReferrerSchemesRegistry`, `GenerateReferrerTruncatesLongUrl`, `ReferrerForCustomScheme`)
    * Referrer policy parsing (`ReferrerPolicyFromHeaderValue`, `ReferrerPolicyToAndFromString`)
    * Trustworthiness of origins (`TrustworthySafelist`)
    * Origin access control (`IsOriginAccessAllowed`, `IsOriginAccessAllowedWildCard`, `IsOriginAccessAllowedWithBlockListEntry`, `ClearOriginAccessList`, `ClearOriginAccessListForOrigin`, `IsOriginAccessAllowedPriority`)

3. **Analyze Each Function Group in Detail:**

    * **Referrer Generation:**
        * **Purpose:** Tests how the browser determines the `Referer` header sent with requests. This is critical for privacy and security.
        * **Relationships to Web Technologies:** Directly impacts HTTP requests initiated by JavaScript (e.g., `fetch`, `XMLHttpRequest`), HTML elements (e.g., `<a>`, `<img>`), and CSS (e.g., background images).
        * **Logic and Examples:** The `GenerateReferrer` test uses a struct `TestCase` to define various combinations of referrer policy, referrer URL, destination URL, and expected output. This is a good example of table-driven testing. Consider specific test cases like HTTP->HTTPS (downgrade), same-origin, cross-origin, and different referrer policies. Pay attention to `kReducedReferrerGranularity` feature flag, as this affects the default policy. The `GenerateReferrerTruncatesLongUrl` test specifically addresses URL length limitations.
        * **User/Programming Errors:**  Incorrectly assuming the referrer will *always* be sent, not understanding the different referrer policies and their implications for privacy and functionality. For instance, using `kNoReferrerWhenDowngrade` might lead to unexpected behavior when navigating from HTTPS to HTTP.

    * **Referrer Policy Parsing:**
        * **Purpose:** Tests the parsing of the `Referrer-Policy` HTTP header.
        * **Relationships to Web Technologies:**  Directly related to HTTP headers sent by servers, which control the browser's referrer behavior.
        * **Logic and Examples:**  `ReferrerPolicyFromHeaderValue` tests parsing different header values, including valid and invalid ones. `ReferrerPolicyToAndFromString` tests the round-trip conversion between the enum representation and the string representation.
        * **User/Programming Errors:**  Typos in the `Referrer-Policy` header on the server-side will lead to the browser using the default policy.

    * **Trustworthy Origins:**
        * **Purpose:** Tests the mechanism for marking certain origins as "potentially trustworthy," which affects features like secure contexts.
        * **Relationships to Web Technologies:**  Crucial for features requiring secure contexts, such as Service Workers, Web Authentication, and potentially certain JavaScript APIs.
        * **Logic and Examples:** The tests demonstrate how the `--unsafely-treat-insecure-origin-as-secure` command-line switch can override the default trustworthiness determination. The tests also consider cases involving `blob:` and `filesystem:` URLs, which have inner origins.
        * **User/Programming Errors:**  Developing features that require secure contexts without ensuring the hosting origin is trustworthy.

    * **Origin Access Control (CORS-like):**
        * **Purpose:** Tests the `SecurityPolicy`'s ability to manage cross-origin access permissions, similar to but potentially preceding or extending standard CORS.
        * **Relationships to Web Technologies:** Directly related to JavaScript's cross-origin requests (e.g., `fetch`, `XMLHttpRequest`), font loading, and other resource requests.
        * **Logic and Examples:** The tests cover adding allow and block list entries, wildcard matching, subdomain matching, and the priority of block lists over allow lists.
        * **User/Programming Errors:**  Incorrectly configuring the origin access lists, leading to either security vulnerabilities (allowing too much access) or broken functionality (blocking necessary access). Confusing this mechanism with standard CORS headers (though they likely interact).

4. **Identify Assumptions and Inferences:** When analyzing the code, I make assumptions based on common software engineering practices and web security principles. For instance, I assume:
    * Test files aim for comprehensive coverage of the tested class's functionality.
    * The test names are indicative of the functionality being tested.
    * The included headers provide context about the dependencies and purpose of the code.

5. **Structure the Output:** Organize the findings logically, grouping related functionalities together. Use clear headings and bullet points for readability. Provide concrete examples to illustrate the relationships with web technologies and potential errors.

6. **Refine and Review:** After the initial analysis, review the output for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. For instance, initially, I might just say "related to JavaScript requests," but refining it with examples like `fetch` and `XMLHttpRequest` makes it more concrete. Also, double-check the logic of the test cases and their expected outputs.

By following this systematic approach, we can effectively analyze the C++ test file and extract its key functionalities, relationships to web technologies, and potential pitfalls.
这个文件 `blink/renderer/platform/weborigin/security_policy_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `SecurityPolicy` 类的单元测试文件。它的主要功能是验证 `SecurityPolicy` 类的各种安全策略相关的功能是否按预期工作。

以下是该文件测试的主要功能以及与 JavaScript, HTML, CSS 的关系和示例：

**核心功能测试:**

1. **Referrer 生成 (`GenerateReferrer`):**
   - **功能:** 测试在不同场景下，根据不同的 Referrer Policy（引用策略），`SecurityPolicy::GenerateReferrer` 函数是否能正确生成 Referrer URL。
   - **与 JavaScript, HTML, CSS 的关系:** 当浏览器发起请求（例如，通过 JavaScript 的 `fetch` 或 `XMLHttpRequest`，HTML 的 `<a>`, `<img>`, `<link>` 标签，或 CSS 中引用的资源），浏览器需要决定是否发送 `Referer` 请求头以及发送什么内容。`SecurityPolicy` 负责根据当前页面的策略和目标页面的安全级别来决定。
   - **示例:**
     - **假设输入:**
       - Referrer Policy: `network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade`
       - 当前页面 URL: `https://example.com/page.html`
       - 目标页面 URL: `http://anotherexample.com/image.png`
     - **预期输出:** Referrer 为空 (`""`)，因为从 HTTPS 降级到 HTTP，且策略为 `kNoReferrerWhenDowngrade`。
     - **用户/编程常见错误:**  开发者可能不理解不同的 Referrer Policy 的含义，导致在某些场景下 Referrer 信息泄露（例如从 HTTPS 链接到 HTTP），或者在需要 Referrer 的情况下被阻止发送。

2. **不允许 scheme 的 Referrer (`EmptyReferrerForUnauthorizedScheme`):**
   - **功能:** 测试当 Referrer 的 URL scheme 不被允许发送 Referrer 时，`SecurityPolicy::GenerateReferrer` 是否返回空字符串。
   - **与 JavaScript, HTML, CSS 的关系:**  例如，从 `chrome://` 这样的内部页面链接到外部网站，通常不应该发送 Referrer。
   - **示例:**
     - **假设输入:**
       - Referrer Policy: `network::mojom::ReferrerPolicy::kAlways`
       - 当前页面 URL: `http://example.com/`
       - Referrer URL: `chrome://settings/`
     - **预期输出:** Referrer 为空 (`""`)。

3. **尊重 Referrer Scheme 注册表 (`GenerateReferrerRespectsReferrerSchemesRegistry`, `ShouldHideReferrerRespectsReferrerSchemesRegistry`):**
   - **功能:** 测试 `SecurityPolicy` 是否考虑了 `SchemeRegistry` 中注册的允许作为 Referrer 的 URL schemes。
   - **与 JavaScript, HTML, CSS 的关系:**  允许开发者自定义哪些 scheme 可以作为 Referrer 发送。
   - **示例:**  可以注册一个自定义的 scheme (例如 `myapp://`)，并测试从这个 scheme 的页面链接到其他页面时，Referrer 是否按照策略发送。

4. **隐藏 Referrer (`ShouldHideReferrer`):**
   - **功能:** 测试在某些情况下，是否应该完全隐藏 Referrer。
   - **与 JavaScript, HTML, CSS 的关系:**  例如，从 HTTPS 页面链接到 HTTP 页面，默认情况下会隐藏 Referrer。

5. **截断过长的 URL (`GenerateReferrerTruncatesLongUrl`):**
   - **功能:** 测试当 Referrer URL 过长时，`SecurityPolicy` 是否会将其截断到 origin。
   - **与 JavaScript, HTML, CSS 的关系:**  避免发送过长的 Referrer，这可能导致性能问题或安全风险。
   - **示例:**
     - **假设输入:**  一个超过 4096 字符的 HTTPS Referrer URL。
     - **预期输出:** Referrer 被截断到其 origin (例如，`https://example.com/`)。

6. **Referrer Policy 从 Header 值解析 (`ReferrerPolicyFromHeaderValue`):**
   - **功能:** 测试 `SecurityPolicy::ReferrerPolicyFromHeaderValue` 函数能否正确解析 HTTP 响应头中的 `Referrer-Policy` 值。
   - **与 JavaScript, HTML, CSS 的关系:**  服务器可以通过 `Referrer-Policy` header 控制客户端如何发送 Referrer。
   - **示例:**
     - **假设输入:**  HTTP 响应头中包含 `Referrer-Policy: origin-when-cross-origin`。
     - **预期输出:**  `network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin`。
     - **用户/编程常见错误:**  服务器配置错误的 `Referrer-Policy` header，导致客户端的 Referrer 行为不符合预期。

7. **Referrer Policy 与字符串之间的转换 (`ReferrerPolicyToAndFromString`):**
   - **功能:** 测试 `SecurityPolicy` 提供的将 `ReferrerPolicy` 枚举值转换为字符串以及从字符串转换为枚举值的功能。

8. **Trustworthy 安全列表 (`TrustworthySafelist`):**
   - **功能:** 测试允许将非安全的 origin 列入安全列表，使其被认为是 potentially trustworthy 的机制。
   - **与 JavaScript, HTML, CSS 的关系:**  某些 Web API（例如 Service Workers）只能在 potentially trustworthy 的 origin 下运行。这个测试涉及到如何通过命令行参数来模拟将 insecure 的 origin 视为 secure 的情况。
   - **示例:**
     - **假设输入:**  运行 Chromium 并使用命令行参数 `--unsafely-treat-insecure-origin-as-secure=http://example.com`。
     - **预期输出:**  `SecurityOrigin::CreateFromString("http://example.com")->IsPotentiallyTrustworthy()` 返回 `true`。
     - **用户/编程常见错误:**  依赖需要 secure context 的 API，但在非 secure 的环境中运行，导致功能无法正常工作。

9. **Origin 访问控制列表 (`IsOriginAccessAllowed`, `AddOriginAccessAllowListEntry`, `ClearOriginAccessList` 等):**
   - **功能:** 测试 `SecurityPolicy` 中用于管理跨域访问权限的功能，类似于 CORS (Cross-Origin Resource Sharing) 的机制。
   - **与 JavaScript, HTML, CSS 的关系:**  控制一个 origin 的页面是否可以访问另一个 origin 的资源，这直接影响到 JavaScript 发起的跨域请求、字体加载等。
   - **示例:**
     - **假设输入:**  添加一个允许 `https://chromium.org` 访问 `https://example.com` 的规则。
     - **预期输出:** `SecurityPolicy::IsOriginAccessAllowed(SecurityOrigin::CreateFromString("https://chromium.org"), SecurityOrigin::CreateFromString("https://example.com"))` 返回 `true`。
     - **用户/编程常见错误:**  没有正确配置跨域访问权限，导致 JavaScript 跨域请求被阻止。

10. **自定义 Scheme 的 Referrer 处理 (`ReferrerForCustomScheme`):**
    - **功能:** 测试对于自定义的 URL scheme，`SecurityPolicy` 是否能正确处理 Referrer。
    - **与 JavaScript, HTML, CSS 的关系:** 允许开发者使用自定义的 URL scheme，并确保 Referrer 策略能够正确应用。

**逻辑推理示例:**

在 `GenerateReferrer` 测试中，很多测试用例都涉及逻辑推理。例如：

- **假设输入:** Referrer Policy 为 `kNoReferrerWhenDowngrade`，当前页面是 HTTPS，目标页面是 HTTP。
- **推理:** 由于存在降级（从 HTTPS 到 HTTP），且策略是不降级时才发送 Referrer，所以 Referrer 应该为空。
- **预期输出:** Referrer 为空。

**用户或编程常见的使用错误示例:**

- **不理解 Referrer Policy 的含义:** 开发者可能错误地认为设置了 `Referrer-Policy: origin` 就总能发送 Origin 作为 Referrer，但当从 HTTPS 链接到 HTTP 时，即使设置了 `origin`，根据浏览器的默认行为，Referrer 仍然可能为空。
- **跨域访问配置错误:**  开发者可能会忘记在服务器端设置正确的 CORS 头，或者在测试环境中没有正确配置 Origin 访问列表，导致跨域请求失败。
- **依赖 insecure context 的 API:**  开发者可能在 HTTP 页面上尝试使用 Service Workers 或其他需要 secure context 的 API，导致功能无法使用。

总而言之，`security_policy_test.cc` 是一个非常重要的测试文件，它确保了 Blink 引擎在处理各种安全策略时行为正确，从而保障用户的浏览安全和网站的功能正常运行。它涵盖了 Referrer 控制、跨域访问控制以及安全上下文等方面，这些都与 JavaScript, HTML, CSS 的行为息息相关。

Prompt: 
```
这是目录为blink/renderer/platform/weborigin/security_policy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/weborigin/security_policy.h"

#include "base/test/scoped_command_line.h"
#include "base/test/scoped_feature_list.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/network/public/mojom/cors.mojom-blink.h"
#include "services/network/public/mojom/cors_origin_pattern.mojom-blink.h"
#include "services/network/public/mojom/referrer_policy.mojom-shared.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/referrer_utils.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "url/url_canon.h"
#include "url/url_util.h"

namespace blink {

TEST(SecurityPolicyTest, EmptyReferrerForUnauthorizedScheme) {
  const KURL example_http_url = KURL("http://example.com/");
  EXPECT_TRUE(String() == SecurityPolicy::GenerateReferrer(
                              network::mojom::ReferrerPolicy::kAlways,
                              example_http_url,
                              String::FromUTF8("chrome://somepage/"))
                              .referrer);
}

TEST(SecurityPolicyTest, GenerateReferrerRespectsReferrerSchemesRegistry) {
  const KURL example_http_url = KURL("http://example.com/");
  const String foobar_url = String::FromUTF8("foobar://somepage/");
  const String foobar_scheme = String::FromUTF8("foobar");

  EXPECT_EQ(String(), SecurityPolicy::GenerateReferrer(
                          network::mojom::ReferrerPolicy::kAlways,
                          example_http_url, foobar_url)
                          .referrer);
  SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(foobar_scheme);
  EXPECT_EQ(foobar_url, SecurityPolicy::GenerateReferrer(
                            network::mojom::ReferrerPolicy::kAlways,
                            example_http_url, foobar_url)
                            .referrer);
  SchemeRegistry::RemoveURLSchemeAsAllowedForReferrer(foobar_scheme);
}

TEST(SecurityPolicyTest, ShouldHideReferrerRespectsReferrerSchemesRegistry) {
  const KURL example_http_url = KURL("http://example.com/");
  const KURL foobar_url = KURL("foobar://somepage/");
  const String foobar_scheme = String::FromUTF8("foobar");

  EXPECT_TRUE(SecurityPolicy::ShouldHideReferrer(example_http_url, foobar_url));
  SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(foobar_scheme);
  EXPECT_FALSE(
      SecurityPolicy::ShouldHideReferrer(example_http_url, foobar_url));
  SchemeRegistry::RemoveURLSchemeAsAllowedForReferrer(foobar_scheme);
}

TEST(SecurityPolicyTest, GenerateReferrer) {
  struct TestCase {
    network::mojom::ReferrerPolicy policy;
    const char* referrer;
    const char* destination;
    const char* expected;
  };

  const char kInsecureURLA[] = "http://a.test/path/to/file.html";
  const char kInsecureURLB[] = "http://b.test/path/to/file.html";
  const char kInsecureOriginA[] = "http://a.test/";

  const char kSecureURLA[] = "https://a.test/path/to/file.html";
  const char kSecureURLB[] = "https://b.test/path/to/file.html";
  const char kSecureOriginA[] = "https://a.test/";

  const char kBlobURL[] =
      "blob:http://a.test/b3aae9c8-7f90-440d-8d7c-43aa20d72fde";
  const char kFilesystemURL[] = "filesystem:http://a.test/path/t/file.html";
  const char kInvalidURL[] = "not-a-valid-url";
  const char kEmptyURL[] = "";

  bool reduced_granularity =
      base::FeatureList::IsEnabled(features::kReducedReferrerGranularity);

  TestCase inputs[] = {
      // HTTP -> HTTP: Same Origin
      {network::mojom::ReferrerPolicy::kAlways, kInsecureURLA, kInsecureURLA,
       kInsecureURLA},
      {network::mojom::ReferrerPolicy::kDefault, kInsecureURLA, kInsecureURLA,
       kInsecureURLA},
      {network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade, kInsecureURLA,
       kInsecureURLA, kInsecureURLA},
      {network::mojom::ReferrerPolicy::kNever, kInsecureURLA, kInsecureURLA,
       nullptr},
      {network::mojom::ReferrerPolicy::kOrigin, kInsecureURLA, kInsecureURLA,
       kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, kInsecureURLA,
       kInsecureURLA, kInsecureURLA},
      {network::mojom::ReferrerPolicy::kSameOrigin, kInsecureURLA,
       kInsecureURLA, kInsecureURLA},
      {network::mojom::ReferrerPolicy::kStrictOrigin, kInsecureURLA,
       kInsecureURLA, kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin,
       kInsecureURLA, kInsecureURLA, kInsecureURLA},

      // HTTP -> HTTP: Cross Origin
      {network::mojom::ReferrerPolicy::kAlways, kInsecureURLA, kInsecureURLB,
       kInsecureURLA},
      {network::mojom::ReferrerPolicy::kDefault, kInsecureURLA, kInsecureURLB,
       reduced_granularity ? kInsecureOriginA : kInsecureURLA},
      {network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade, kInsecureURLA,
       kInsecureURLB, kInsecureURLA},
      {network::mojom::ReferrerPolicy::kNever, kInsecureURLA, kInsecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kOrigin, kInsecureURLA, kInsecureURLB,
       kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, kInsecureURLA,
       kInsecureURLB, kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kSameOrigin, kInsecureURLA,
       kInsecureURLB, nullptr},
      {network::mojom::ReferrerPolicy::kSameOrigin, kInsecureURLB,
       kFilesystemURL, nullptr},
      {network::mojom::ReferrerPolicy::kSameOrigin, kInsecureURLB, kBlobURL,
       nullptr},
      {network::mojom::ReferrerPolicy::kStrictOrigin, kInsecureURLA,
       kInsecureURLB, kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin,
       kInsecureURLA, kInsecureURLB, kInsecureOriginA},

      // HTTPS -> HTTPS: Same Origin
      {network::mojom::ReferrerPolicy::kAlways, kSecureURLA, kSecureURLA,
       kSecureURLA},
      {network::mojom::ReferrerPolicy::kDefault, kSecureURLA, kSecureURLA,
       kSecureURLA},
      {network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade, kSecureURLA,
       kSecureURLA, kSecureURLA},
      {network::mojom::ReferrerPolicy::kNever, kSecureURLA, kSecureURLA,
       nullptr},
      {network::mojom::ReferrerPolicy::kOrigin, kSecureURLA, kSecureURLA,
       kSecureOriginA},
      {network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, kSecureURLA,
       kSecureURLA, kSecureURLA},
      {network::mojom::ReferrerPolicy::kSameOrigin, kSecureURLA, kSecureURLA,
       kSecureURLA},
      {network::mojom::ReferrerPolicy::kStrictOrigin, kSecureURLA, kSecureURLA,
       kSecureOriginA},
      {network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin,
       kSecureURLA, kSecureURLA, kSecureURLA},

      // HTTPS -> HTTPS: Cross Origin
      {network::mojom::ReferrerPolicy::kAlways, kSecureURLA, kSecureURLB,
       kSecureURLA},
      {network::mojom::ReferrerPolicy::kDefault, kSecureURLA, kSecureURLB,
       reduced_granularity ? kSecureOriginA : kSecureURLA},
      {network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade, kSecureURLA,
       kSecureURLB, kSecureURLA},
      {network::mojom::ReferrerPolicy::kNever, kSecureURLA, kSecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kOrigin, kSecureURLA, kSecureURLB,
       kSecureOriginA},
      {network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, kSecureURLA,
       kSecureURLB, kSecureOriginA},
      {network::mojom::ReferrerPolicy::kSameOrigin, kSecureURLA, kSecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kStrictOrigin, kSecureURLA, kSecureURLB,
       kSecureOriginA},
      {network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin,
       kSecureURLA, kSecureURLB, kSecureOriginA},

      // HTTP -> HTTPS
      {network::mojom::ReferrerPolicy::kAlways, kInsecureURLA, kSecureURLB,
       kInsecureURLA},
      {network::mojom::ReferrerPolicy::kDefault, kInsecureURLA, kSecureURLB,
       reduced_granularity ? kInsecureOriginA : kInsecureURLA},
      {network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade, kInsecureURLA,
       kSecureURLB, kInsecureURLA},
      {network::mojom::ReferrerPolicy::kNever, kInsecureURLA, kSecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kOrigin, kInsecureURLA, kSecureURLB,
       kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, kInsecureURLA,
       kSecureURLB, kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kSameOrigin, kInsecureURLA, kSecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kStrictOrigin, kInsecureURLA,
       kSecureURLB, kInsecureOriginA},
      {network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin,
       kInsecureURLA, kSecureURLB, kInsecureOriginA},

      // HTTPS -> HTTP
      {network::mojom::ReferrerPolicy::kAlways, kSecureURLA, kInsecureURLB,
       kSecureURLA},
      {network::mojom::ReferrerPolicy::kDefault, kSecureURLA, kInsecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade, kSecureURLA,
       kInsecureURLB, nullptr},
      {network::mojom::ReferrerPolicy::kNever, kSecureURLA, kInsecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kOrigin, kSecureURLA, kInsecureURLB,
       kSecureOriginA},
      {network::mojom::ReferrerPolicy::kOriginWhenCrossOrigin, kSecureURLA,
       kSecureURLB, kSecureOriginA},
      {network::mojom::ReferrerPolicy::kSameOrigin, kSecureURLA, kInsecureURLB,
       nullptr},
      {network::mojom::ReferrerPolicy::kStrictOrigin, kSecureURLA,
       kInsecureURLB, nullptr},
      {network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin,
       kSecureURLA, kInsecureURLB, nullptr},

      // blob, filesystem, and invalid URL handling
      {network::mojom::ReferrerPolicy::kAlways, kInsecureURLA, kBlobURL,
       kInsecureURLA},
      {network::mojom::ReferrerPolicy::kAlways, kBlobURL, kInsecureURLA,
       nullptr},
      {network::mojom::ReferrerPolicy::kAlways, kInsecureURLA, kFilesystemURL,
       kInsecureURLA},
      {network::mojom::ReferrerPolicy::kAlways, kFilesystemURL, kInsecureURLA,
       nullptr},
      {network::mojom::ReferrerPolicy::kAlways, kInsecureURLA, kInvalidURL,
       kInsecureURLA},
      {network::mojom::ReferrerPolicy::kAlways, kInvalidURL, kInsecureURLA,
       nullptr},
      {network::mojom::ReferrerPolicy::kAlways, kEmptyURL, kInsecureURLA,
       nullptr},
  };

  for (TestCase test : inputs) {
    KURL destination(test.destination);
    Referrer result = SecurityPolicy::GenerateReferrer(
        test.policy, destination, String::FromUTF8(test.referrer));
    if (test.expected) {
      EXPECT_EQ(String::FromUTF8(test.expected), result.referrer)
          << "'" << test.referrer << "' to '" << test.destination
          << "' with policy=" << static_cast<int>(test.policy)
          << " should have been '" << test.expected << "': was '"
          << result.referrer.Utf8() << "'.";
    } else {
      EXPECT_TRUE(result.referrer.empty())
          << "'" << test.referrer << "' to '" << test.destination
          << "' should have been empty: was '" << result.referrer.Utf8()
          << "'.";
    }

    network::mojom::ReferrerPolicy expected_policy = test.policy;
    if (expected_policy == network::mojom::ReferrerPolicy::kDefault) {
      if (reduced_granularity) {
        expected_policy =
            network::mojom::ReferrerPolicy::kStrictOriginWhenCrossOrigin;
      } else {
        expected_policy =
            network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade;
      }
    }
    EXPECT_EQ(expected_policy, result.referrer_policy);
  }
}

TEST(SecurityPolicyTest, GenerateReferrerTruncatesLongUrl) {
  char buffer[4097];
  std::fill_n(std::begin(buffer), 4097, 'a');

  String base = "https://a.com/";
  String string_with_4096 =
      base + String(base::span(buffer).first(4096 - base.length()));
  ASSERT_EQ(string_with_4096.length(), 4096u);

  network::mojom::ReferrerPolicy kAlways =
      network::mojom::ReferrerPolicy::kAlways;
  EXPECT_EQ(SecurityPolicy::GenerateReferrer(
                kAlways, KURL("https://destination.example"), string_with_4096)
                .referrer,
            string_with_4096);

  String string_with_4097 =
      base + String(base::span(buffer).first(4097 - base.length()));
  ASSERT_EQ(string_with_4097.length(), 4097u);
  EXPECT_EQ(SecurityPolicy::GenerateReferrer(
                kAlways, KURL("https://destination.example"), string_with_4097)
                .referrer,
            "https://a.com/");

  // Since refs get stripped from outgoing referrers prior to the "if the length
  // is greater than 4096, strip the referrer to its origin" check, a
  // referrer with length > 4096 due to its path should not get stripped to its
  // outgoing origin.
  String string_with_4097_because_of_long_ref =
      base + "path#" +
      String(base::span(buffer).first(4097 - 5 - base.length()));
  ASSERT_EQ(string_with_4097_because_of_long_ref.length(), 4097u);
  EXPECT_EQ(SecurityPolicy::GenerateReferrer(
                kAlways, KURL("https://destination.example"),
                string_with_4097_because_of_long_ref)
                .referrer,
            "https://a.com/path");
}

TEST(SecurityPolicyTest, ReferrerPolicyFromHeaderValue) {
  struct TestCase {
    const char* header;
    bool is_valid;
    ReferrerPolicyLegacyKeywordsSupport keywords;
    network::mojom::ReferrerPolicy expected_policy;
  };

  TestCase inputs[] = {
      {"origin", true, kDoNotSupportReferrerPolicyLegacyKeywords,
       network::mojom::ReferrerPolicy::kOrigin},
      {"none", true, kSupportReferrerPolicyLegacyKeywords,
       network::mojom::ReferrerPolicy::kNever},
      {"none", false, kDoNotSupportReferrerPolicyLegacyKeywords,
       network::mojom::ReferrerPolicy::kDefault},
      {"foo", false, kDoNotSupportReferrerPolicyLegacyKeywords,
       network::mojom::ReferrerPolicy::kDefault},
      {"origin, foo", true, kDoNotSupportReferrerPolicyLegacyKeywords,
       network::mojom::ReferrerPolicy::kOrigin},
      {"origin, foo-bar", true, kDoNotSupportReferrerPolicyLegacyKeywords,
       network::mojom::ReferrerPolicy::kOrigin},
      {"origin, foo bar", false, kDoNotSupportReferrerPolicyLegacyKeywords,
       network::mojom::ReferrerPolicy::kDefault},
  };

  for (TestCase test : inputs) {
    network::mojom::ReferrerPolicy actual_policy =
        network::mojom::ReferrerPolicy::kDefault;
    EXPECT_EQ(test.is_valid, SecurityPolicy::ReferrerPolicyFromHeaderValue(
                                 test.header, test.keywords, &actual_policy));
    if (test.is_valid)
      EXPECT_EQ(test.expected_policy, actual_policy);
  }
}

TEST(SecurityPolicyTest, TrustworthySafelist) {
  const char* insecure_urls[] = {
      "http://a.test/path/to/file.html", "http://b.test/path/to/file.html",
      "blob:http://c.test/b3aae9c8-7f90-440d-8d7c-43aa20d72fde",
      "filesystem:http://d.test/path/t/file.html",
  };

  for (const char* url : insecure_urls) {
    scoped_refptr<const SecurityOrigin> origin =
        SecurityOrigin::CreateFromString(url);
    EXPECT_FALSE(origin->IsPotentiallyTrustworthy());

    {
      base::test::ScopedCommandLine scoped_command_line;
      base::CommandLine* command_line =
          scoped_command_line.GetProcessCommandLine();
      command_line->AppendSwitchASCII(
          network::switches::kUnsafelyTreatInsecureOriginAsSecure,
          origin->ToString().Latin1());
      network::SecureOriginAllowlist::GetInstance().ResetForTesting();
      EXPECT_TRUE(origin->IsPotentiallyTrustworthy());
    }
  }

  // Tests that adding URLs that have inner-urls to the safelist
  // takes effect on the origins of the inner-urls (and vice versa).
  struct TestCase {
    const char* url;
    const char* another_url_in_origin;
  };
  TestCase insecure_urls_with_inner_origin[] = {
      {"blob:http://e.test/b3aae9c8-7f90-440d-8d7c-43aa20d72fde",
       "http://e.test/foo.html"},
      {"filesystem:http://f.test/path/t/file.html", "http://f.test/bar.html"},
      {"http://g.test/foo.html",
       "blob:http://g.test/b3aae9c8-7f90-440d-8d7c-43aa20d72fde"},
      {"http://h.test/bar.html", "filesystem:http://h.test/path/t/file.html"},
  };
  for (const TestCase& test : insecure_urls_with_inner_origin) {
    // Actually origins of both URLs should be same.
    scoped_refptr<const SecurityOrigin> origin1 =
        SecurityOrigin::CreateFromString(test.url);
    scoped_refptr<const SecurityOrigin> origin2 =
        SecurityOrigin::CreateFromString(test.another_url_in_origin);

    EXPECT_FALSE(origin1->IsPotentiallyTrustworthy());
    EXPECT_FALSE(origin2->IsPotentiallyTrustworthy());
    {
      base::test::ScopedCommandLine scoped_command_line;
      base::CommandLine* command_line =
          scoped_command_line.GetProcessCommandLine();
      command_line->AppendSwitchASCII(
          network::switches::kUnsafelyTreatInsecureOriginAsSecure,
          origin1->ToString().Latin1());
      network::SecureOriginAllowlist::GetInstance().ResetForTesting();
      EXPECT_TRUE(origin1->IsPotentiallyTrustworthy());
      EXPECT_TRUE(origin2->IsPotentiallyTrustworthy());
    }
  }
}

TEST(SecurityPolicyTest, ReferrerPolicyToAndFromString) {
  const char* policies[] = {"no-referrer",
                            "unsafe-url",
                            "origin",
                            "origin-when-cross-origin",
                            "same-origin",
                            "strict-origin",
                            "strict-origin-when-cross-origin",
                            "no-referrer-when-downgrade"};

  for (const char* policy : policies) {
    network::mojom::ReferrerPolicy result =
        network::mojom::ReferrerPolicy::kDefault;
    EXPECT_TRUE(SecurityPolicy::ReferrerPolicyFromString(
        policy, kDoNotSupportReferrerPolicyLegacyKeywords, &result));
    String string_result = SecurityPolicy::ReferrerPolicyAsString(result);
    EXPECT_EQ(string_result, policy);
  }
}

class SecurityPolicyAccessTest : public testing::Test {
 public:
  SecurityPolicyAccessTest() = default;
  SecurityPolicyAccessTest(const SecurityPolicyAccessTest&) = delete;
  SecurityPolicyAccessTest& operator=(const SecurityPolicyAccessTest&) = delete;
  ~SecurityPolicyAccessTest() override = default;

  void SetUp() override {
    https_example_origin_ =
        SecurityOrigin::CreateFromString("https://example.com");
    https_sub_example_origin_ =
        SecurityOrigin::CreateFromString("https://sub.example.com");
    http_example_origin_ =
        SecurityOrigin::CreateFromString("http://example.com");
    https_chromium_origin_ =
        SecurityOrigin::CreateFromString("https://chromium.org");
    https_google_origin_ =
        SecurityOrigin::CreateFromString("https://google.com");
  }

  void TearDown() override { SecurityPolicy::ClearOriginAccessList(); }

  const SecurityOrigin* https_example_origin() const {
    return https_example_origin_.get();
  }
  const SecurityOrigin* https_sub_example_origin() const {
    return https_sub_example_origin_.get();
  }
  const SecurityOrigin* http_example_origin() const {
    return http_example_origin_.get();
  }
  const SecurityOrigin* https_chromium_origin() const {
    return https_chromium_origin_.get();
  }
  const SecurityOrigin* https_google_origin() const {
    return https_google_origin_.get();
  }

 private:
  scoped_refptr<const SecurityOrigin> https_example_origin_;
  scoped_refptr<const SecurityOrigin> https_sub_example_origin_;
  scoped_refptr<const SecurityOrigin> http_example_origin_;
  scoped_refptr<const SecurityOrigin> https_chromium_origin_;
  scoped_refptr<const SecurityOrigin> https_google_origin_;
};

// TODO(toyoshim): Simplify origin access related tests since all we need here
// is to check think wrapper functions to the network::cors::OriginAccessList.
TEST_F(SecurityPolicyAccessTest, IsOriginAccessAllowed) {
  // By default, no access should be allowed.
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     https_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     http_example_origin()));

  // Adding access for https://example.com should work, but should not grant
  // access to subdomains or other schemes.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kDisallowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                    https_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     http_example_origin()));

  // Clearing the map should revoke all special access.
  SecurityPolicy::ClearOriginAccessList();
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     https_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     http_example_origin()));

  // Adding an entry that matches subdomains should grant access to any
  // subdomains.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                    https_example_origin()));
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     http_example_origin()));
}

TEST_F(SecurityPolicyAccessTest, IsOriginAccessAllowedWildCard) {
  // An empty domain that matches subdomains results in matching every domain.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                    https_example_origin()));
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                    https_google_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     http_example_origin()));
}

TEST_F(SecurityPolicyAccessTest, IsOriginAccessAllowedWithBlockListEntry) {
  // The block list takes priority over the allow list.
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *https_chromium_origin(), "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kDisallowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);

  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     https_example_origin()));
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
}

TEST_F(SecurityPolicyAccessTest,
       IsOriginAccessAllowedWildcardWithBlockListEntry) {
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *https_chromium_origin(), "https", "google.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kDisallowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);

  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                    https_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     https_google_origin()));
}

TEST_F(SecurityPolicyAccessTest, ClearOriginAccessListForOrigin) {
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "google.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_example_origin(), "https", "google.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kDefaultPriority);

  SecurityPolicy::ClearOriginAccessListForOrigin(*https_chromium_origin());

  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     https_example_origin()));
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(https_chromium_origin(),
                                                     https_google_origin()));
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(https_example_origin(),
                                                    https_google_origin()));
}

TEST_F(SecurityPolicyAccessTest, IsOriginAccessAllowedPriority) {
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "sub.example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kDisallowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kLowPriority);
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
  SecurityPolicy::AddOriginAccessBlockListEntry(
      *https_chromium_origin(), "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kMediumPriority);
  EXPECT_FALSE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
  SecurityPolicy::AddOriginAccessAllowListEntry(
      *https_chromium_origin(), "https", "example.com",
      /*destination_port=*/0,
      network::mojom::CorsDomainMatchMode::kAllowSubdomains,
      network::mojom::CorsPortMatchMode::kAllowAnyPort,
      network::mojom::CorsOriginAccessMatchPriority::kHighPriority);
  EXPECT_TRUE(SecurityPolicy::IsOriginAccessAllowed(
      https_chromium_origin(), https_sub_example_origin()));
}

// Test that referrers for custom hierarchical (standard) schemes are correctly
// handled by the new policy. (For instance, this covers android-app://.)
TEST(SecurityPolicyTest, ReferrerForCustomScheme) {
  url::ScopedSchemeRegistryForTests scoped_registry;
  const char kCustomStandardScheme[] = "my-new-scheme";
  url::AddStandardScheme(kCustomStandardScheme, url::SCHEME_WITH_HOST);
  SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(kCustomStandardScheme);

  String kFullReferrer = "my-new-scheme://com.foo.me/this-should-be-truncated";
  String kTruncatedReferrer = "my-new-scheme://com.foo.me/";

  // The default policy of strict-origin-when-cross-origin should truncate the
  // referrer.
  EXPECT_EQ(SecurityPolicy::GenerateReferrer(
                network::mojom::ReferrerPolicy::kDefault,
                KURL("https://www.example.com/"), kFullReferrer)
                .referrer,
            kTruncatedReferrer);

  // no-referrer-when-downgrade shouldn't truncate the referrer.
  EXPECT_EQ(SecurityPolicy::GenerateReferrer(
                network::mojom::ReferrerPolicy::kNoReferrerWhenDowngrade,
                KURL("https://www.example.com/"), kFullReferrer)
                .referrer,
            kFullReferrer);
}

}  // namespace blink

"""

```