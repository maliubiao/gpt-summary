Response:
The user is asking for a breakdown of the C++ source code file `source_list_directive_test.cc`. I need to identify its purpose, its relation to web technologies like JavaScript, HTML, and CSS, provide examples of logical reasoning within the code, and highlight common usage errors related to the tested functionality.

**Plan:**

1. **Identify the core purpose:** The file is a unit test file for `SourceListDirective`.
2. **Explain `SourceListDirective`'s function:** This likely deals with parsing and matching source lists within Content Security Policy (CSP) directives.
3. **Relate to web technologies:** CSP directly impacts how browsers handle resources (scripts, styles, etc.), so explain this connection to JavaScript, HTML, and CSS.
4. **Illustrate logical reasoning:** Analyze test cases to understand the input (CSP directive strings) and expected output (whether a given URL or resource is allowed).
5. **Identify potential user/programming errors:**  Focus on mistakes users might make when defining CSP or how developers could misuse the related APIs.
这个C++源代码文件 `source_list_directive_test.cc` 是 Chromium Blink 引擎的一部分，它的主要功能是**测试 `SourceListDirective` 类的功能**。`SourceListDirective` 类负责处理内容安全策略 (CSP) 中指令的值，这些值是一个允许的资源来源列表。

**具体功能解释：**

1. **解析源列表指令:**  测试代码模拟了解析各种形式的 CSP 源列表指令，例如 `script-src`, `style-src`, `img-src` 等。它使用 `ParseSourceList` 函数将指令名称和值解析成 `network::mojom::blink::CSPSourceListPtr` 对象，该对象表示解析后的源列表。

2. **匹配源:**  核心功能是测试 `CSPSourceListAllows` 函数，该函数判断给定的源（`network::mojom::blink::CSPSource` 对象，通常由 URL 转换而来）是否被已解析的源列表所允许。测试覆盖了各种匹配模式：
    *   `'none'`:  不允许任何来源。
    *   `'strict-dynamic'`: 启用严格动态策略。
    *   `'unsafe-hashes'`: 允许使用哈希值匹配内联脚本和样式。
    *   `*`: 允许任何来源（除了某些特殊协议如 `data:`, `blob:` 等）。
    *   `'self'`:  只允许与文档自身来源相同的来源。
    *   `blob:`:  允许 `blob:` 类型的 URL。
    *   明确的 URL 列表：例如 `http://example1.com/foo/ https://example2.com/`。
    *   通配符匹配：例如 `http://example1.com:*/foo/`, `https://*.example2.com/bar/`。

3. **测试特殊关键字:**  测试代码还针对 CSP 中特殊的关键字进行测试，例如：
    *   `'unsafe-inline'`:  允许内联 JavaScript 和 CSS。测试了 `CSPSourceListAllowAllInline` 函数，该函数判断源列表中是否包含 `'unsafe-inline'`。
    *   `'nonce-'`:  允许带有特定 nonce 值的内联脚本和样式。测试了 `CSPSourceListAllowNonce` 函数。

4. **测试 `isNone` 和 `isSelf`:** 测试了 `CSPSourceListIsNone` 和 `CSPSourceListIsSelf` 函数，分别用于判断源列表是否只包含 `'none'` 或 `'self'`。

5. **测试 URL 基础匹配:** 测试了 `CSPSourceListAllowsURLBasedMatching` 函数，该函数判断源列表是否包含基于 URL 的匹配规则（例如，明确的 URL 或通配符）。

6. **测试主机名和端口解析:** 测试了主机名中是否允许使用通配符 `*` 以及端口号的解析。

7. **测试重定向匹配:** 测试了在发生重定向时，源列表的匹配行为。

**与 JavaScript, HTML, CSS 的关系：**

CSP 是一种 Web 安全机制，旨在减少和报告跨站脚本 (XSS) 攻击。它通过 HTTP 头部或 HTML 的 `<meta>` 标签声明。`SourceListDirective` 类处理的源列表指令直接影响浏览器如何加载和执行 JavaScript、渲染 CSS 以及加载其他资源。

*   **JavaScript:** `script-src` 指令控制浏览器可以执行哪些来源的 JavaScript 代码。测试代码模拟了各种 `script-src` 指令的匹配规则，例如：
    *   `script-src 'self'`：只允许加载与当前页面来源相同的 JavaScript 文件。
    *   `script-src 'unsafe-inline'`：允许执行页面中直接嵌入的 `<script>` 标签内的 JavaScript 代码。**这是一个潜在的安全风险，通常不建议使用。**
    *   `script-src https://example.com`：只允许加载来自 `https://example.com` 的 JavaScript 文件。
    *   `script-src 'nonce-xyz'`：只允许执行带有 `nonce="xyz"` 属性的 `<script>` 标签内的 JavaScript 代码。
    *   `script-src 'strict-dynamic'`：配合 `require-trusted-types-for` 或 `trusted-types` 指令使用，限制动态创建的脚本。

*   **CSS:** `style-src` 指令控制浏览器可以应用哪些来源的 CSS 样式。测试代码与 JavaScript 类似，模拟了各种 `style-src` 指令的匹配规则：
    *   `style-src 'self'`：只允许加载与当前页面来源相同的 CSS 文件。
    *   `style-src 'unsafe-inline'`：允许应用页面中直接嵌入的 `<style>` 标签内的 CSS 代码以及 style 属性定义的样式。**这是一个潜在的安全风险，通常不建议使用。**
    *   `style-src https://example.com`：只允许加载来自 `https://example.com` 的 CSS 文件。
    *   `style-src 'nonce-xyz'`：只允许应用带有 `nonce="xyz"` 属性的 `<style>` 标签内的 CSS 代码。
    *   `style-src 'strict-dynamic'`：配合 `require-trusted-types-for` 或 `trusted-types` 指令使用，限制动态创建的样式。

*   **HTML:** 其他 CSP 指令也与 HTML 相关，例如：
    *   `img-src`：控制可以加载哪些来源的图片。
    *   `frame-src` 或 `child-src`：控制可以嵌入哪些来源的 `<iframe>` 或 worker。
    *   `form-action`：控制表单可以提交到哪些来源。

**逻辑推理的假设输入与输出：**

以下是一些测试用例中体现的逻辑推理示例：

**假设输入 1:**

*   **CSP 指令:** `script-src 'self' https://example.com`
*   **尝试加载的脚本 URL:** `https://example.com/script.js`

**输出 1:** 允许加载 (`true`)，因为 `https://example.com` 在 `script-src` 指令中被明确允许。

**假设输入 2:**

*   **CSP 指令:** `script-src 'self' https://example.com`
*   **尝试加载的脚本 URL:** `https://another-domain.com/script.js`

**输出 2:** 禁止加载 (`false`)，因为 `https://another-domain.com` 不在 `script-src` 指令允许的来源列表中。

**假设输入 3:**

*   **CSP 指令:** `script-src 'none'`
*   **尝试加载的脚本 URL:** 任何 URL，例如 `https://example.com/script.js`

**输出 3:** 禁止加载 (`false`)，因为 `'none'` 表示不允许加载任何外部脚本。

**假设输入 4:**

*   **CSP 指令:** `script-src *`
*   **尝试加载的脚本 URL:** `http://any-domain.com/script.js`

**输出 4:** 允许加载 (`true`)，因为 `*` 表示允许来自任何来源的脚本。

**涉及用户或者编程常见的使用错误：**

1. **错误地使用 `'unsafe-inline'` 或 `'unsafe-eval'`：**  这是最常见的错误，虽然允许内联脚本和动态代码执行很方便，但会显著降低安全性，容易遭受 XSS 攻击。开发者应该尽可能避免使用，并考虑使用 `nonce-` 或 `hash-` 来允许特定的内联代码。

    *   **错误示例:**  在生产环境中设置 `script-src 'unsafe-inline';`

2. **CSP 指令过于宽松：** 使用 `*` 允许所有来源可能引入安全风险。应该尽可能明确指定允许的来源。

    *   **错误示例:**  `img-src *;`  允许加载任何来源的图片，可能导致跟踪或其他安全问题。

3. **CSP 指令配置错误导致网站功能失效：** 如果 CSP 配置过于严格，可能会意外阻止合法资源的加载，导致网站功能异常。

    *   **错误示例:** 设置了 `script-src 'self'`，但忘记允许 CDN 上的 JavaScript 库，导致网站依赖这些库的功能失效。

4. **混淆使用 `http:` 和 `https:`：** 如果网站使用 HTTPS，CSP 指令中应该尽可能使用 `https:` 来源，避免混合内容警告。

    *   **错误示例:**  HTTPS 网站的 CSP 中设置 `script-src http://example.com`，浏览器会阻止加载 `http://example.com` 的脚本。

5. **忘记为内联脚本或样式添加 `nonce` 或 `hash`：** 如果没有使用 `'unsafe-inline'`，并且有内联脚本或样式，必须使用 `nonce` 或 `hash` 将其列入白名单。

    *   **错误示例:** 设置了 `script-src 'nonce-xyz'`, 但是 `<script>` 标签没有 `nonce="xyz"` 属性。

6. **对重定向的处理不当：**  理解 CSP 如何处理重定向很重要。例如，如果 `script-src` 只允许原始请求的域名，重定向到另一个域名可能会被阻止。

7. **不理解 `'strict-dynamic'` 的工作原理：**  `'strict-dynamic'` 需要与受信任的类型策略配合使用，如果使用不当，可能不会达到预期的安全效果。

总而言之，`source_list_directive_test.cc` 文件通过大量的单元测试用例，验证了 Chromium Blink 引擎在解析和匹配 CSP 源列表指令时的正确性，这对于确保 Web 安全至关重要。 理解这些测试用例有助于开发者更好地理解 CSP 的工作原理，并避免常见的配置错误。

Prompt: 
```
这是目录为blink/renderer/core/frame/csp/source_list_directive_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/csp/source_list_directive.h"

#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/csp/csp_source.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

namespace {

network::mojom::blink::CSPSourceListPtr ParseSourceList(
    const String& directive_name,
    const String& directive_value) {
  Vector<network::mojom::blink::ContentSecurityPolicyPtr> parsed =
      ParseContentSecurityPolicies(
          directive_name + " " + directive_value,
          network::mojom::blink::ContentSecurityPolicyType::kEnforce,
          network::mojom::blink::ContentSecurityPolicySource::kHTTP,
          KURL("https://example.test"));
  return std::move(
      parsed[0]
          ->directives
          .find(ContentSecurityPolicy::GetDirectiveType(directive_name))
          ->value);
}

}  // namespace

class SourceListDirectiveTest : public testing::Test {
 protected:
  void SetUp() override {
    self_source = network::mojom::blink::CSPSource::New("https", "example.test",
                                                        443, "", false, false);
  }

  network::mojom::blink::CSPSourcePtr self_source;
};

TEST_F(SourceListDirectiveTest, BasicMatchingNone) {
  KURL base;
  String sources = "'none'";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);
  ASSERT_TRUE(source_list);

  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "http://example.com/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "https://example.test/")));
}

TEST_F(SourceListDirectiveTest, BasicMatchingStrictDynamic) {
  String sources = "'strict-dynamic'";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_TRUE(source_list->allow_dynamic);
}

TEST_F(SourceListDirectiveTest, BasicMatchingUnsafeHashes) {
  String sources = "'unsafe-hashes'";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_TRUE(source_list->allow_unsafe_hashes);
}

TEST_F(SourceListDirectiveTest, BasicMatchingStar) {
  KURL base;
  String sources = "*";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "http://example.com/")),
            CSPCheckResult::Allowed());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "https://example.com/")),
            CSPCheckResult::Allowed());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "http://example.com/bar")),
            CSPCheckResult::Allowed());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "http://foo.example.com/")),
            CSPCheckResult::Allowed());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "http://foo.example.com/bar")),
            CSPCheckResult::Allowed());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "ftp://example.com/")),
            base::FeatureList::IsEnabled(
                network::features::kCspStopMatchingWildcardDirectivesToFtp)
                ? CSPCheckResult::Blocked()
                : CSPCheckResult::AllowedOnlyIfWildcardMatchesFtp());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "ws://example.com/")),
            CSPCheckResult::AllowedOnlyIfWildcardMatchesWs());

  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "data:https://example.test/")),
            CSPCheckResult::Blocked());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "blob:https://example.test/")),
            CSPCheckResult::Blocked());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "filesystem:https://example.test/")),
            CSPCheckResult::Blocked());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "file:///etc/hosts")),
            CSPCheckResult::Blocked());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL(base, "applewebdata://example.test/")),
            CSPCheckResult::Blocked());
}

TEST_F(SourceListDirectiveTest, BasicMatchingStarPlusExplicitFtpWs) {
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", "* ftp: ws:");

  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL("ftp://example.com/")),
            CSPCheckResult::Allowed());
  EXPECT_EQ(CSPSourceListAllows(*source_list, *self_source,
                                KURL("ws://example.com/")),
            CSPCheckResult::Allowed());
}

TEST_F(SourceListDirectiveTest, StarallowsSelf) {
  KURL base;
  String sources = "*";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  auto self_origin =
      network::mojom::blink::CSPSource::New("file", "", -1, "", false, false);
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_origin,
                                  KURL(base, "file:///etc/hosts")));

  // The other results are the same as above:
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_origin,
                                  KURL(base, "http://example.com/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_origin,
                                  KURL(base, "https://example.com/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_origin,
                                  KURL(base, "http://example.com/bar")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_origin,
                                  KURL(base, "http://foo.example.com/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_origin,
                                  KURL(base, "http://foo.example.com/bar")));

  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_origin,
                                   KURL(base, "data:https://example.test/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_origin,
                                   KURL(base, "blob:https://example.test/")));
  EXPECT_FALSE(
      CSPSourceListAllows(*source_list, *self_origin,
                          KURL(base, "filesystem:https://example.test/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_origin,
                                   KURL(base, "applewebdata://example.test/")));
}

TEST_F(SourceListDirectiveTest, BasicMatchingSelf) {
  KURL base;
  String sources = "'self'";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "http://example.com/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "https://not-example.com/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "https://example.test/")));
}

TEST_F(SourceListDirectiveTest, BlobMatchingBlob) {
  KURL base;
  String sources = "blob:";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "https://example.test/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "blob:https://example.test/")));
}

TEST_F(SourceListDirectiveTest, BasicMatching) {
  KURL base;
  String sources = "http://example1.com:8000/foo/ https://example2.com/";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "http://example1.com:8000/foo/")));
  EXPECT_TRUE(
      CSPSourceListAllows(*source_list, *self_source,
                          KURL(base, "http://example1.com:8000/foo/bar")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "https://example2.com/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "https://example2.com/foo/")));

  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "https://not-example.com/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "http://example1.com/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "https://example1.com/foo")));
  EXPECT_FALSE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "http://example1.com:9000/foo/")));
  EXPECT_FALSE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "http://example1.com:8000/FOO/")));
}

TEST_F(SourceListDirectiveTest, WildcardMatching) {
  KURL base;
  String sources =
      "http://example1.com:*/foo/ https://*.example2.com/bar/ http://*.test/";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "http://example1.com/foo/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "http://example1.com:8000/foo/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "http://example1.com:9000/foo/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "https://foo.example2.com/bar/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "http://foo.test/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "http://foo.bar.test/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "https://example1.com/foo/")));
  EXPECT_TRUE(
      CSPSourceListAllows(*source_list, *self_source,
                          KURL(base, "https://example1.com:8000/foo/")));
  EXPECT_TRUE(
      CSPSourceListAllows(*source_list, *self_source,
                          KURL(base, "https://example1.com:9000/foo/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "https://foo.test/")));
  EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                  KURL(base, "https://foo.bar.test/")));

  EXPECT_FALSE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "https://example1.com:8000/foo")));
  EXPECT_FALSE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "https://example2.com:8000/bar")));
  EXPECT_FALSE(
      CSPSourceListAllows(*source_list, *self_source,
                          KURL(base, "https://foo.example2.com:8000/bar")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "https://example2.foo.com/bar")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "http://foo.test.bar/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "https://example2.com/bar/")));
  EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                   KURL(base, "http://test/")));
}

TEST_F(SourceListDirectiveTest, RedirectMatching) {
  KURL base;
  String sources = "http://example1.com/foo/ http://example2.com/bar/";
  network::mojom::blink::CSPSourceListPtr source_list =
      ParseSourceList("script-src", sources);

  EXPECT_TRUE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "http://example1.com/foo/"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_TRUE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "http://example1.com/bar/"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_TRUE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "http://example2.com/bar/"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_TRUE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "http://example2.com/foo/"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_TRUE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "https://example1.com/foo/"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_TRUE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "https://example1.com/bar/"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));

  EXPECT_FALSE(CSPSourceListAllows(
      *source_list, *self_source, KURL(base, "http://example3.com/foo/"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));
}

TEST_F(SourceListDirectiveTest, AllowAllInline) {
  struct TestCase {
    String sources;
    bool expected;
  } cases[] = {
      // List does not contain 'unsafe-inline'.
      {"http://example1.com/foo/", false},
      {"'sha512-321cba'", false},
      {"'nonce-yay'", false},
      {"'strict-dynamic'", false},
      {"'sha512-321cba' http://example1.com/foo/", false},
      {"http://example1.com/foo/ 'sha512-321cba'", false},
      {"http://example1.com/foo/ 'nonce-yay'", false},
      {"'sha512-321cba' 'nonce-yay'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'nonce-yay'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'nonce-yay'", false},
      {" 'sha512-321cba' 'nonce-yay' 'strict-dynamic'", false},
      // List contains 'unsafe-inline'.
      {"'unsafe-inline'", true},
      {"'self' 'unsafe-inline'", true},
      {"'unsafe-inline' http://example1.com/foo/", true},
      {"'sha512-321cba' 'unsafe-inline'", false},
      {"'nonce-yay' 'unsafe-inline'", false},
      {"'strict-dynamic' 'unsafe-inline' 'nonce-yay'", false},
      {"'sha512-321cba' http://example1.com/foo/ 'unsafe-inline'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'unsafe-inline'", false},
      {"http://example1.com/foo/ 'nonce-yay' 'unsafe-inline'", false},
      {"'sha512-321cba' 'nonce-yay' 'unsafe-inline'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'unsafe-inline' 'nonce-yay'",
       false},
      {"http://example1.com/foo/ 'sha512-321cba' 'nonce-yay' 'unsafe-inline'",
       false},
      {" 'sha512-321cba' 'unsafe-inline' 'nonce-yay' 'strict-dynamic'", false},
  };

  using network::mojom::blink::CSPDirectiveName;

  // Script-src and style-src differently handle presence of 'strict-dynamic'.
  network::mojom::blink::CSPSourceListPtr script_src =
      ParseSourceList("script-src", "'strict-dynamic' 'unsafe-inline'");
  EXPECT_FALSE(CSPSourceListAllowAllInline(
      CSPDirectiveName::ScriptSrc, ContentSecurityPolicy::InlineType::kScript,
      *script_src));

  network::mojom::blink::CSPSourceListPtr style_src =
      ParseSourceList("style-src", "'strict-dynamic' 'unsafe-inline'");
  EXPECT_TRUE(CSPSourceListAllowAllInline(
      CSPDirectiveName::StyleSrc, ContentSecurityPolicy::InlineType::kStyle,
      *style_src));

  for (const auto& test : cases) {
    script_src = ParseSourceList("script-src", test.sources);
    EXPECT_EQ(CSPSourceListAllowAllInline(
                  CSPDirectiveName::ScriptSrc,
                  ContentSecurityPolicy::InlineType::kScript, *script_src),
              test.expected);

    style_src = ParseSourceList("style-src", test.sources);
    EXPECT_EQ(CSPSourceListAllowAllInline(
                  CSPDirectiveName::StyleSrc,
                  ContentSecurityPolicy::InlineType::kStyle, *style_src),
              test.expected);

    // If source list doesn't have a valid type, it must not allow all inline.
    network::mojom::blink::CSPSourceListPtr img_src =
        ParseSourceList("img-src", test.sources);
    EXPECT_FALSE(CSPSourceListAllowAllInline(
        CSPDirectiveName::ImgSrc, ContentSecurityPolicy::InlineType::kScript,
        *img_src));
  }
}

TEST_F(SourceListDirectiveTest, IsNone) {
  struct TestCase {
    String sources;
    bool expected;
  } cases[] = {
      // Source list is 'none'.
      {"'none'", true},
      {"", true},
      {"   ", true},
      // Source list is not 'none'.
      {"http://example1.com/foo/", false},
      {"'sha512-321cba'", false},
      {"'nonce-yay'", false},
      {"'strict-dynamic'", false},
      {"'sha512-321cba' http://example1.com/foo/", false},
      {"http://example1.com/foo/ 'sha512-321cba'", false},
      {"http://example1.com/foo/ 'nonce-yay'", false},
      {"'none' 'sha512-321cba' http://example1.com/foo/", false},
      {"'none' http://example1.com/foo/ 'sha512-321cba'", false},
      {"'none' http://example1.com/foo/ 'nonce-yay'", false},
      {"'sha512-321cba' 'nonce-yay'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'nonce-yay'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'nonce-yay'", false},
      {" 'sha512-321cba' 'nonce-yay' 'strict-dynamic'", false},
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(test.sources);
    network::mojom::blink::CSPSourceListPtr script_src =
        ParseSourceList("script-src", test.sources);
    EXPECT_EQ(CSPSourceListIsNone(*script_src), test.expected);

    network::mojom::blink::CSPSourceListPtr form_action =
        ParseSourceList("form-action", test.sources);
    EXPECT_EQ(CSPSourceListIsNone(*form_action), test.expected);

    network::mojom::blink::CSPSourceListPtr frame_src =
        ParseSourceList("frame-src", test.sources);
    EXPECT_EQ(CSPSourceListIsNone(*frame_src), test.expected);
  }
}

TEST_F(SourceListDirectiveTest, IsSelf) {
  struct TestCase {
    String sources;
    bool expected;
  } cases[] = {
      // Source list is 'self'.
      {"'self'", true},
      {"'self' 'none'", true},

      // Source list is not 'self'.
      {"'none'", false},
      {"http://example1.com/foo/", false},
      {"'sha512-321cba'", false},
      {"'nonce-yay'", false},
      {"'strict-dynamic'", false},
      {"'sha512-321cba' http://example1.com/foo/", false},
      {"http://example1.com/foo/ 'sha512-321cba'", false},
      {"http://example1.com/foo/ 'nonce-yay'", false},
      {"'self' 'sha512-321cba' http://example1.com/foo/", false},
      {"'self' http://example1.com/foo/ 'sha512-321cba'", false},
      {"'self' http://example1.com/foo/ 'nonce-yay'", false},
      {"'sha512-321cba' 'nonce-yay'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'nonce-yay'", false},
      {"http://example1.com/foo/ 'sha512-321cba' 'nonce-yay'", false},
      {" 'sha512-321cba' 'nonce-yay' 'strict-dynamic'", false},
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(test.sources);
    network::mojom::blink::CSPSourceListPtr script_src =
        ParseSourceList("script-src", test.sources);
    EXPECT_EQ(CSPSourceListIsSelf(*script_src), test.expected);

    network::mojom::blink::CSPSourceListPtr form_action =
        ParseSourceList("form-action", test.sources);
    EXPECT_EQ(CSPSourceListIsSelf(*form_action), test.expected);

    network::mojom::blink::CSPSourceListPtr frame_src =
        ParseSourceList("frame-src", test.sources);
    EXPECT_EQ(CSPSourceListIsSelf(*frame_src), test.expected);
  }
}

TEST_F(SourceListDirectiveTest, AllowsURLBasedMatching) {
  struct TestCase {
    String sources;
    bool expected;
  } cases[] = {
      // No URL-based matching.
      {"'none'", false},
      {"'sha256-abcdefg'", false},
      {"'nonce-abc'", false},
      {"'nonce-abce' 'sha256-abcdefg'", false},

      // Strict-dynamic.
      {"'sha256-abcdefg' 'strict-dynamic'", false},
      {"'nonce-abce' 'strict-dynamic'", false},
      {"'nonce-abce' 'sha256-abcdefg' 'strict-dynamic'", false},
      {"'sha256-abcdefg' 'strict-dynamic' https:", false},
      {"'nonce-abce' 'strict-dynamic' http://example.test", false},
      {"'nonce-abce' 'sha256-abcdefg' 'strict-dynamic' *://example.test",
       false},

      // URL-based.
      {"*", true},
      {"'self'", true},
      {"http:", true},
      {"http: https:", true},
      {"http: 'none'", true},
      {"http: https: 'none'", true},
      {"'sha256-abcdefg' https://example.test", true},
      {"'nonce-abc' https://example.test", true},
      {"'nonce-abce' 'sha256-abcdefg' https://example.test", true},
      {"'sha256-abcdefg' https://example.test 'none'", true},
      {"'nonce-abc' https://example.test 'none'", true},
      {"'nonce-abce' 'sha256-abcdefg' https://example.test 'none'", true},

  };

  for (const auto& test : cases) {
    SCOPED_TRACE(test.sources);
    network::mojom::blink::CSPSourceListPtr script_src =
        ParseSourceList("script-src", test.sources);
    EXPECT_EQ(CSPSourceListAllowsURLBasedMatching(*script_src), test.expected);

    network::mojom::blink::CSPSourceListPtr form_action =
        ParseSourceList("form-action", test.sources);
    EXPECT_EQ(CSPSourceListAllowsURLBasedMatching(*form_action), test.expected);

    network::mojom::blink::CSPSourceListPtr frame_src =
        ParseSourceList("frame-src", test.sources);
    EXPECT_EQ(CSPSourceListAllowsURLBasedMatching(*frame_src), test.expected);
  }
}

TEST_F(SourceListDirectiveTest, ParseSourceListHost) {
  struct TestCase {
    String sources;
    bool expected;
  } cases[] = {
      // Wildcard.
      {"*", true},
      {"*.", false},
      {"*.a", true},
      {"a.*.a", false},
      {"a.*", false},

      // Dots.
      {"a.b.c", true},
      {"a.b.", true},
      {".b.c", false},
      {"a..c", false},

      // Valid/Invalid characters.
      {"az09-", true},
      {"+", false},
  };

  for (const auto& test : cases) {
    network::mojom::blink::CSPSourceListPtr parsed =
        ParseSourceList("default-src", test.sources);
    EXPECT_EQ(CSPSourceListIsNone(*parsed), !test.expected)
        << "ParseSourceList failed to parse: " << test.sources;
  }
}

TEST_F(SourceListDirectiveTest, ParsePort) {
  struct TestCase {
    String sources;
    bool valid;
    int expected_port;
  } cases[] = {
      {"example.com", true, url::PORT_UNSPECIFIED},
      {"example.com:80", true, 80},
      {"http://example.com:80", true, 80},
      {"https://example.com:80", true, 80},
      {"https://example.com:90/path", true, 90},

      {"http://example.com:", false},
      {"https://example.com:/", false},
      {"http://example.com:/path", false},
  };

  for (const auto& test : cases) {
    network::mojom::blink::CSPSourceListPtr parsed =
        ParseSourceList("default-src", test.sources);
    EXPECT_EQ(CSPSourceListIsNone(*parsed), !test.valid)
        << "ParseSourceList failed to parse: " << test.sources;
    if (test.valid) {
      ASSERT_EQ(1u, parsed->sources.size());
      EXPECT_EQ(test.expected_port, parsed->sources[0]->port);
    }
  }
}

TEST_F(SourceListDirectiveTest, AllowHostWildcard) {
  KURL base;
  // When the host-part is "*", the port must still be checked.
  // See crbug.com/682673.
  {
    String sources = "http://*:111";
    network::mojom::blink::CSPSourceListPtr source_list =
        ParseSourceList("default-src", sources);
    EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                    KURL(base, "http://a.com:111")));
    EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                     KURL(base, "http://a.com:222")));
  }
  // When the host-part is "*", the path must still be checked.
  // See crbug.com/682673.
  {
    String sources = "http://*/welcome.html";
    network::mojom::blink::CSPSourceListPtr source_list =
        ParseSourceList("default-src", sources);
    EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                    KURL(base, "http://a.com/welcome.html")));
    EXPECT_FALSE(CSPSourceListAllows(*source_list, *self_source,
                                     KURL(base, "http://a.com/passwords.txt")));
  }
  // When the host-part is "*" and the expression-source is not "*", then every
  // host are allowed. See crbug.com/682673.
  {
    String sources = "http://*";
    network::mojom::blink::CSPSourceListPtr source_list =
        ParseSourceList("default-src", sources);
    EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                    KURL(base, "http://a.com")));
  }
}

TEST_F(SourceListDirectiveTest, AllowHostMixedCase) {
  KURL base;
  // Non-wildcard sources should match hosts case-insensitively.
  {
    String sources = "http://ExAmPle.com";
    network::mojom::blink::CSPSourceListPtr source_list =
        ParseSourceList("default-src", sources);
    EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                    KURL(base, "http://example.com")));
  }
  // Wildcard sources should match hosts case-insensitively.
  {
    String sources = "http://*.ExAmPle.com";
    network::mojom::blink::CSPSourceListPtr source_list =
        ParseSourceList("default-src", sources);
    EXPECT_TRUE(CSPSourceListAllows(*source_list, *self_source,
                                    KURL(base, "http://www.example.com")));
  }
}

TEST_F(SourceListDirectiveTest, AllowNonce) {
  struct TestCase {
    const char* directive_value;
    const char* nonce;
    bool expected;
  } cases[] = {
      {"'self'", "yay", false},
      {"'self'", "boo", false},
      {"'nonce-yay'", "yay", true},
      {"'nonce-yay'", "boo", false},
      {"'nonce-yay' 'nonce-boo'", "yay", true},
      {"'nonce-yay' 'nonce-boo'", "boo", true},
  };

  for (const auto& test : cases) {
    network::mojom::blink::CSPSourceListPtr source_list =
        ParseSourceList("script-src", test.directive_value);
    EXPECT_EQ(test.expected, CSPSourceListAllowNonce(*source_list, test.nonce));
    // Empty/null strings are always not present.
    EXPECT_FALSE(CSPSourceListAllowNonce(*source_list, ""));
    EXPECT_FALSE(CSPSourceListAllowNonce(*source_list, String()));
  }
}

}  // namespace blink

"""

```