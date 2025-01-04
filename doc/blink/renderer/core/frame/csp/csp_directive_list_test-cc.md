Response:
The user wants to understand the functionality of the `csp_directive_list_test.cc` file in the Chromium Blink engine. I need to analyze the provided code and identify its purpose.

Based on the file name and the included headers (`csp_directive_list.h`, `content_security_policy.h`), it's clear this file contains unit tests for the Content Security Policy (CSP) directive list functionality.

Here's a breakdown of what the tests seem to cover:

1. **Parsing and Representation:** Tests if the CSP directives are parsed correctly and stored in the `ContentSecurityPolicy` object. Specifically, the `Header` test checks the parsing of the header value.

2. **Nonce Matching:** Tests the `'nonce-'` source expression, ensuring that scripts with the correct nonce are allowed. This relates to both Javascript execution and inline `<script>` tags in HTML.

3. **Source Allowlisting:** Tests the basic mechanism of allowing scripts and other resources from specific origins. This is fundamental to CSP and directly impacts Javascript, CSS, images, and other web content loaded by HTML.

4. **Hash Matching (SRI):** Tests the `'sha256-'`, `'sha384-'`, and `'sha512-'` source expressions, verifying that resources with matching integrity hashes are allowed. This is important for the security of external Javascript and CSS files referenced in HTML.

5. **Directive Fallbacks:**  Tests how different CSP directives fall back to other directives (e.g., `script-src-elem` falling back to `script-src` and then `default-src`). This is crucial for understanding how CSP policies are applied.

6. **`worker-src` Directive:** Tests the `worker-src` directive, which controls the sources from which web workers and shared workers can be loaded. This directly affects Javascript functionality.

7. **`child-src` Fallback (deprecated):** Tests the older behavior where `worker-src` could fallback to `child-src`. This highlights the evolution of CSP.

8. **Operative Directive Resolution:** Tests the logic for determining the "operative" directive for a given resource type, taking into account fallbacks.

9. **Reporting:** Tests the `report-uri` and `report-to` directives, which allow developers to specify endpoints where CSP violations should be reported.

10. **Reasonable Object Restriction:**  Tests a heuristic to determine if the CSP policy provides a sufficient level of protection against potentially harmful objects. This relates to the `<object>` element in HTML.

Based on this, I can now formulate a summary of the file's functionality, relating it to Javascript, HTML, and CSS where appropriate, and providing examples. I also need to consider potential user errors.
这是对 `blink/renderer/core/frame/csp/csp_directive_list_test.cc` 文件功能的归纳总结。

**功能归纳:**

该文件是 Chromium Blink 引擎中用于测试 Content Security Policy (CSP) 指令列表 (`CSPDirectiveList`) 功能的单元测试文件。它主要验证以下方面的功能：

1. **CSP Header 的解析和存储:**  测试 CSP 策略字符串是否能被正确解析并存储到 `ContentSecurityPolicy` 对象中，包括策略头部的原始字符串。
2. **`nonce` 值的匹配:** 测试 CSP 中 `'nonce-'` 关键字的功能，验证是否能正确识别带有匹配 `nonce` 值的内联脚本。
3. **来源白名单 (`script-src`, `style-src` 等):** 测试 CSP 中基于来源的白名单机制，验证是否能正确允许或阻止从特定来源加载的资源（例如脚本、样式）。
4. **完整性校验 (`sha256`, `sha384`, `sha512`):** 测试 Subresource Integrity (SRI) 功能，验证是否能正确校验资源的哈希值，允许加载具有匹配哈希值的资源。
5. **指令回退机制:** 测试某些 CSP 指令在未指定时，是否会回退到其他指令 (例如 `script-src-elem` 回退到 `script-src`，再回退到 `default-src`)。
6. **`worker-src` 指令:** 测试 `worker-src` 指令的功能，验证是否能正确控制 Web Workers 和 Shared Workers 的加载来源。
7. **`child-src` 指令的兼容性 (已废弃):**  测试 `worker-src` 指令不存在时，是否会回退到 `child-src` 指令（这是一个临时的兼容性行为）。
8. **有效指令的确定:** 测试在给定资源类型的情况下，如何确定最终生效的 CSP 指令，包括指令回退的情况。
9. **报告端点的解析:** 测试 `report-uri` 和 `report-to` 指令的解析，验证是否能正确提取用于报告 CSP 违规的 URL 或组名。
10. **对象资源的合理限制:** 测试一种启发式方法，用于判断 CSP 策略是否对 `<object>` 元素提供了足够的安全限制。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

该文件测试的 CSP 功能直接关系到 JavaScript, HTML, 和 CSS 的安全加载和执行。

* **JavaScript:**
    * **`script-src 'self'`:**  允许加载与当前页面同源的 JavaScript 文件。
        * **HTML 示例:** `<script src="/js/app.js"></script>` (如果 `/js/app.js` 与当前页面同源则允许)。
    * **`script-src 'nonce-abcdefg'`:**  只允许带有 `nonce="abcdefg"` 属性的内联脚本执行。
        * **HTML 示例:** `<script nonce="abcdefg">console.log('hello');</script>`
    * **`require-sri-for script`:**  要求所有通过 `<script>` 标签加载的外部 JavaScript 文件都必须带有 `integrity` 属性。
        * **HTML 示例:** `<script src="https://example.com/script.js" integrity="sha384-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"></script>`
* **HTML:**
    * **`object-src 'none'`:**  禁止加载任何插件内容 (例如 `<object>`, `<embed>`, `<applet>`)。
        * **HTML 示例:**  以下代码会被阻止执行： `<object data="plugin.swf"></object>`
    * **`frame-ancestors 'self'`:**  只允许当前域名下的页面嵌入当前页面为 `<iframe>`。
        * **HTML 示例:** 其他域名下的页面使用 `<iframe>` 嵌入当前页面会被阻止。
* **CSS:**
    * **`style-src 'self'`:** 允许加载与当前页面同源的 CSS 文件以及 `<style>` 标签中的内联样式。
        * **HTML 示例:** `<link rel="stylesheet" href="/css/style.css">` (如果 `/css/style.css` 与当前页面同源则允许)。
    * **`style-src 'unsafe-inline'`:** 允许页面中的内联 `<style>` 标签和 HTML 元素的 `style` 属性中的样式。  (通常不推荐使用，因为它会降低安全性)。
        * **HTML 示例:** `<style>body { background-color: red; }</style>`  或  `<div style="color: blue;"></div>`

**逻辑推理、假设输入与输出:**

假设有以下测试用例：

**假设输入:**

* **CSP 策略字符串:** `"script-src 'self' 'nonce-testnonce' https://trusted.com"`
* **尝试加载的脚本 URL:** `"https://untrusted.com/script.js"`
* **尝试加载的内联脚本的 nonce 值:** `"testnonce"`
* **尝试加载的同源脚本 URL:** `"/js/app.js"`
* **尝试加载的信任域名脚本 URL:** `"https://trusted.com/script.js"`

**逻辑推理:**

1. `script-src 'self'` 允许加载同源脚本。
2. `script-src 'nonce-testnonce'` 允许加载 `nonce` 值为 `testnonce` 的内联脚本。
3. `script-src https://trusted.com` 允许加载来自 `https://trusted.com` 的脚本。

**假设输出:**

* 加载 `"https://untrusted.com/script.js"` **应该被阻止**。
* 执行 `nonce` 值为 `"testnonce"` 的内联脚本 **应该被允许**。
* 加载 `"/js/app.js"` **应该被允许** (假设与当前页面同源)。
* 加载 `"https://trusted.com/script.js"` **应该被允许**。

**用户或编程常见的使用错误及举例说明:**

1. **配置过于宽松:** 使用 `script-src *` 或 `default-src *` 会允许加载来自任何来源的资源，完全绕过了 CSP 的安全保护。
    * **错误示例:**  `Content-Security-Policy: script-src *;`
2. **忘记添加 `'self'`:**  如果只设置了 `script-src https://trusted.com`，而没有 `'self'`，则会导致同源的脚本也无法加载。
    * **错误示例:** `Content-Security-Policy: script-src https://trusted.com;` (会导致同域名下的脚本加载失败)
3. **`nonce` 值不匹配:** 在 CSP 中指定了 `nonce` 值，但在 HTML 脚本标签中使用了错误的 `nonce` 值或没有添加 `nonce` 属性。
    * **错误示例:**
        * **CSP Header:** `Content-Security-Policy: script-src 'nonce-mysecret'`
        * **HTML:** `<script nonce="wrongsecret">console.log('hello');</script>` (此脚本会被阻止执行)
4. **混淆 `report-uri` 和 `report-to`:**  `report-uri` 已经过时，应该使用 `report-to` 并配合 `Reporting-Endpoints` HTTP 头来配置报告。
    * **错误示例:** 同时使用 `report-uri` 和 `report-to`，可能导致报告行为不符合预期。
5. **拼写错误或语法错误:**  CSP 指令或关键字的拼写错误会导致策略失效或行为异常。
    * **错误示例:** `Content-Security-Policy: script-src 'self', https://trusted.com` (逗号应该替换为分号)。

**这是第1部分，共2部分，请归纳一下它的功能:**

作为第 1 部分，此代码文件主要负责 **构建和测试 `CSPDirectiveList` 类的核心功能，特别是针对资源加载控制方面的策略指令的解析和执行逻辑验证。**  它侧重于验证 CSP 如何根据配置的指令（如 `script-src`、`style-src`、`nonce`、SRI 等）来决定是否允许加载特定类型的资源。它不涉及更高级的 CSP 功能，例如报告机制的完整测试或与浏览器其他组件的集成测试。

Prompt: 
```
这是目录为blink/renderer/core/frame/csp/csp_directive_list_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/csp/csp_directive_list.h"

#include <optional>
#include <string>

#include "base/memory/scoped_refptr.h"
#include "base/test/scoped_feature_list.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/csp/test_util.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/subresource_integrity.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/reporting_disposition.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_operators.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

using network::mojom::ContentSecurityPolicySource;
using network::mojom::ContentSecurityPolicyType;

class CSPDirectiveListTest : public testing::Test {
 public:
  void SetUp() override {
    scoped_feature_list_.InitWithFeatures({network::features::kReporting}, {});
  }

  network::mojom::blink::ContentSecurityPolicyPtr CreateList(
      const String& list,
      ContentSecurityPolicyType type,
      ContentSecurityPolicySource source = ContentSecurityPolicySource::kHTTP) {
    Vector<network::mojom::blink::ContentSecurityPolicyPtr> parsed =
        ParseContentSecurityPolicies(list, type, source,
                                     KURL("https://example.test/index.html"));
    return std::move(parsed[0]);
  }

 protected:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(CSPDirectiveListTest, Header) {
  struct TestCase {
    const char* list;
    const char* expected;
  } cases[] = {{"script-src 'self'", "script-src 'self'"},
               {"  script-src 'self'  ", "script-src 'self'"},
               {"\t\tscript-src 'self'", "script-src 'self'"},
               {"script-src 'self' \t", "script-src 'self'"}};

  for (const auto& test : cases) {
    network::mojom::blink::ContentSecurityPolicyPtr directive_list =
        CreateList(test.list, ContentSecurityPolicyType::kReport);
    EXPECT_EQ(test.expected, directive_list->header->header_value);
    directive_list = CreateList(test.list, ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(test.expected, directive_list->header->header_value);
  }
}

TEST_F(CSPDirectiveListTest, IsMatchingNoncePresent) {
  struct TestCase {
    const char* list;
    const char* nonce;
    bool expected;
  } cases[] = {
      {"script-src 'self'", "yay", false},
      {"script-src 'self'", "boo", false},
      {"script-src 'nonce-yay'", "yay", true},
      {"script-src 'nonce-yay'", "boo", false},
      {"script-src 'nonce-yay' 'nonce-boo'", "yay", true},
      {"script-src 'nonce-yay' 'nonce-boo'", "boo", true},

      // Falls back to 'default-src'
      {"default-src 'nonce-yay'", "yay", true},
      {"default-src 'nonce-yay'", "boo", false},
      {"default-src 'nonce-boo'; script-src 'nonce-yay'", "yay", true},
      {"default-src 'nonce-boo'; script-src 'nonce-yay'", "boo", false},

      // Unrelated directives do not affect result
      {"style-src 'nonce-yay'; default-src 'none'", "yay", false},
      {"style-src 'nonce-yay'; default-src 'none'", "boo", false},
      {"script-src-attr 'nonce-yay'; default-src 'none'", "yay", false},

      // Script-src-elem falls back on script-src and then default-src.
      {"script-src 'nonce-yay'", "yay", true},
      {"script-src 'nonce-yay'; default-src 'nonce-boo'", "yay", true},
      {"script-src 'nonce-boo'; default-src 'nonce-yay'", "yay", false},
      {"script-src-elem 'nonce-yay'; script-src 'nonce-boo'; default-src "
       "'nonce-boo'",
       "yay", true},
      {"default-src 'nonce-yay'", "yay", true},

      {"script-src-attr 'nonce-yay'; script-src 'nonce-boo'; default-src "
       "'nonce-foo'",
       "yay", false},
      {"script-src-attr 'nonce-yay'; script-src 'nonce-boo'; default-src "
       "'nonce-foo'",
       "boo", true},
      {"script-src-attr 'nonce-yay'; script-src 'nonce-boo'; default-src "
       "'nonce-foo'",
       "foo", false},
  };

  ContentSecurityPolicy* context =
      MakeGarbageCollected<ContentSecurityPolicy>();
  TestCSPDelegate* test_delegate = MakeGarbageCollected<TestCSPDelegate>();
  context->BindToDelegate(*test_delegate);

  KURL blocked_url = KURL("https://blocked.com");
  for (const auto& test : cases) {
    for (auto reporting_disposition : {ReportingDisposition::kSuppressReporting,
                                       ReportingDisposition::kReport}) {
      // Report-only
      network::mojom::blink::ContentSecurityPolicyPtr directive_list =
          CreateList(test.list, ContentSecurityPolicyType::kReport);

      EXPECT_TRUE(CSPDirectiveListAllowFromSource(
          *directive_list, context, CSPDirectiveName::ScriptSrcElem,
          blocked_url, blocked_url,
          ResourceRequest::RedirectStatus::kNoRedirect, reporting_disposition,
          test.nonce));

      // Enforce
      directive_list =
          CreateList(test.list, ContentSecurityPolicyType::kEnforce);
      EXPECT_EQ(CSPCheckResult(test.expected),
                CSPDirectiveListAllowFromSource(
                    *directive_list, context, CSPDirectiveName::ScriptSrcElem,
                    blocked_url, blocked_url,
                    ResourceRequest::RedirectStatus::kNoRedirect,
                    reporting_disposition, test.nonce));
    }
  }
}

TEST_F(CSPDirectiveListTest, AllowScriptFromSourceNoNonce) {
  struct TestCase {
    const char* list;
    const char* url;
    bool expected;
  } cases[] = {
      {"script-src https://example.com", "https://example.com/script.js", true},
      {"script-src https://example.com/", "https://example.com/script.js",
       true},
      {"script-src https://example.com/",
       "https://example.com/script/script.js", true},
      {"script-src https://example.com/script", "https://example.com/script.js",
       false},
      {"script-src https://example.com/script",
       "https://example.com/script/script.js", false},
      {"script-src https://example.com/script/",
       "https://example.com/script.js", false},
      {"script-src https://example.com/script/",
       "https://example.com/script/script.js", true},
      {"script-src https://example.com", "https://not.example.com/script.js",
       false},
      {"script-src https://*.example.com", "https://not.example.com/script.js",
       true},
      {"script-src https://*.example.com", "https://example.com/script.js",
       false},

      // Falls back to default-src:
      {"default-src https://example.com", "https://example.com/script.js",
       true},
      {"default-src https://example.com/", "https://example.com/script.js",
       true},
      {"default-src https://example.com/",
       "https://example.com/script/script.js", true},
      {"default-src https://example.com/script",
       "https://example.com/script.js", false},
      {"default-src https://example.com/script",
       "https://example.com/script/script.js", false},
      {"default-src https://example.com/script/",
       "https://example.com/script.js", false},
      {"default-src https://example.com/script/",
       "https://example.com/script/script.js", true},
      {"default-src https://example.com", "https://not.example.com/script.js",
       false},
      {"default-src https://*.example.com", "https://not.example.com/script.js",
       true},
      {"default-src https://*.example.com", "https://example.com/script.js",
       false},
  };

  ContentSecurityPolicy* context =
      MakeGarbageCollected<ContentSecurityPolicy>();
  TestCSPDelegate* test_delegate = MakeGarbageCollected<TestCSPDelegate>();
  context->BindToDelegate(*test_delegate);

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message()
                 << "List: `" << test.list << "`, URL: `" << test.url << "`");
    const KURL script_src(test.url);

    // Report-only
    network::mojom::blink::ContentSecurityPolicyPtr directive_list =
        CreateList(test.list, ContentSecurityPolicyType::kReport);
    EXPECT_TRUE(CSPDirectiveListAllowFromSource(
        *directive_list, context, CSPDirectiveName::ScriptSrcElem, script_src,
        script_src, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kSuppressReporting, String(),
        IntegrityMetadataSet(), kParserInserted));

    // Enforce
    directive_list = CreateList(test.list, ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(CSPCheckResult(test.expected),
              CSPDirectiveListAllowFromSource(
                  *directive_list, context, CSPDirectiveName::ScriptSrcElem,
                  script_src, script_src,
                  ResourceRequest::RedirectStatus::kNoRedirect,
                  ReportingDisposition::kSuppressReporting, String(),
                  IntegrityMetadataSet(), kParserInserted));
  }
}

TEST_F(CSPDirectiveListTest, AllowFromSourceWithNonce) {
  struct TestCase {
    const char* list;
    const char* url;
    const char* nonce;
    bool expected;
  } cases[] = {
      // Doesn't affect lists without nonces:
      {"https://example.com", "https://example.com/file", "yay", true},
      {"https://example.com", "https://example.com/file", "boo", true},
      {"https://example.com", "https://example.com/file", "", true},
      {"https://example.com", "https://not.example.com/file", "yay", false},
      {"https://example.com", "https://not.example.com/file", "boo", false},
      {"https://example.com", "https://not.example.com/file", "", false},

      // Doesn't affect URLs that match the allowlist.
      {"https://example.com 'nonce-yay'", "https://example.com/file", "yay",
       true},
      {"https://example.com 'nonce-yay'", "https://example.com/file", "boo",
       true},
      {"https://example.com 'nonce-yay'", "https://example.com/file", "", true},

      // Does affect URLs that don't.
      {"https://example.com 'nonce-yay'", "https://not.example.com/file", "yay",
       true},
      {"https://example.com 'nonce-yay'", "https://not.example.com/file", "boo",
       false},
      {"https://example.com 'nonce-yay'", "https://not.example.com/file", "",
       false},
  };

  ContentSecurityPolicy* context =
      MakeGarbageCollected<ContentSecurityPolicy>();
  TestCSPDelegate* test_delegate = MakeGarbageCollected<TestCSPDelegate>();
  context->BindToDelegate(*test_delegate);

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message()
                 << "List: `" << test.list << "`, URL: `" << test.url << "`");
    const KURL resource(test.url);

    // Report-only 'script-src'
    network::mojom::blink::ContentSecurityPolicyPtr directive_list = CreateList(
        String("script-src ") + test.list, ContentSecurityPolicyType::kReport);
    EXPECT_TRUE(CSPDirectiveListAllowFromSource(
        *directive_list, context, CSPDirectiveName::ScriptSrcElem, resource,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kSuppressReporting, String(test.nonce),
        IntegrityMetadataSet(), kParserInserted));

    // Enforce 'script-src'
    directive_list = CreateList(String("script-src ") + test.list,
                                ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(
        CSPCheckResult(test.expected),
        CSPDirectiveListAllowFromSource(
            *directive_list, context, CSPDirectiveName::ScriptSrcElem, resource,
            resource, ResourceRequest::RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting, String(test.nonce),
            IntegrityMetadataSet(), kParserInserted));

    // Report-only 'style-src'
    directive_list = CreateList(String("style-src ") + test.list,
                                ContentSecurityPolicyType::kReport);
    EXPECT_TRUE(CSPDirectiveListAllowFromSource(
        *directive_list, context, CSPDirectiveName::StyleSrcElem, resource,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kSuppressReporting, String(test.nonce)));

    // Enforce 'style-src'
    directive_list = CreateList(String("style-src ") + test.list,
                                ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(
        CSPCheckResult(test.expected),
        CSPDirectiveListAllowFromSource(
            *directive_list, context, CSPDirectiveName::StyleSrcElem, resource,
            resource, ResourceRequest::RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting, String(test.nonce)));

    // Report-only 'style-src'
    directive_list = CreateList(String("default-src ") + test.list,
                                ContentSecurityPolicyType::kReport);
    EXPECT_TRUE(CSPDirectiveListAllowFromSource(
        *directive_list, context, CSPDirectiveName::ScriptSrcElem, resource,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kSuppressReporting, String(test.nonce)));
    EXPECT_TRUE(CSPDirectiveListAllowFromSource(
        *directive_list, context, CSPDirectiveName::StyleSrcElem, resource,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kSuppressReporting, String(test.nonce)));

    // Enforce 'style-src'
    directive_list = CreateList(String("default-src ") + test.list,
                                ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(
        CSPCheckResult(test.expected),
        CSPDirectiveListAllowFromSource(
            *directive_list, context, CSPDirectiveName::ScriptSrcElem, resource,
            resource, ResourceRequest::RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting, String(test.nonce),
            IntegrityMetadataSet(), kParserInserted));
    EXPECT_EQ(
        CSPCheckResult(test.expected),
        CSPDirectiveListAllowFromSource(
            *directive_list, context, CSPDirectiveName::StyleSrcElem, resource,
            resource, ResourceRequest::RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting, String(test.nonce)));
  }
}

TEST_F(CSPDirectiveListTest, AllowScriptFromSourceWithHash) {
  struct TestCase {
    const char* list;
    const char* url;
    const char* integrity;
    bool expected;
  } cases[] = {
      // Doesn't affect lists without hashes.
      {"https://example.com", "https://example.com/file", "sha256-yay", true},
      {"https://example.com", "https://example.com/file", "sha256-boo", true},
      {"https://example.com", "https://example.com/file", "", true},
      {"https://example.com", "https://not.example.com/file", "sha256-yay",
       false},
      {"https://example.com", "https://not.example.com/file", "sha256-boo",
       false},
      {"https://example.com", "https://not.example.com/file", "", false},

      // Doesn't affect URLs that match the allowlist.
      {"https://example.com 'sha256-yay'", "https://example.com/file",
       "sha256-yay", true},
      {"https://example.com 'sha256-yay'", "https://example.com/file",
       "sha256-boo", true},
      {"https://example.com 'sha256-yay'", "https://example.com/file", "",
       true},

      // Does affect URLs that don't match the allowlist.
      {"https://example.com 'sha256-yay'", "https://not.example.com/file",
       "sha256-yay", true},
      {"https://example.com 'sha256-yay'", "https://not.example.com/file",
       "sha256-boo", false},
      {"https://example.com 'sha256-yay'", "https://not.example.com/file", "",
       false},

      // Both algorithm and digest must match.
      {"'sha256-yay'", "https://a.com/file", "sha384-yay", false},

      // Sha-1 is not supported, but -384 and -512 are.
      {"'sha1-yay'", "https://a.com/file", "sha1-yay", false},
      {"'sha384-yay'", "https://a.com/file", "sha384-yay", true},
      {"'sha512-yay'", "https://a.com/file", "sha512-yay", true},

      // Unknown (or future) hash algorithms don't work.
      {"'asdf256-yay'", "https://a.com/file", "asdf256-yay", false},

      // But they also don't interfere.
      {"'sha256-yay'", "https://a.com/file", "sha256-yay asdf256-boo", true},

      // Additional allowlisted hashes in the CSP don't interfere.
      {"'sha256-yay' 'sha384-boo'", "https://a.com/file", "sha256-yay", true},
      {"'sha256-yay' 'sha384-boo'", "https://a.com/file", "sha384-boo", true},

      // All integrity hashes must appear in the CSP (and match).
      {"'sha256-yay'", "https://a.com/file", "sha256-yay sha384-boo", false},
      {"'sha384-boo'", "https://a.com/file", "sha256-yay sha384-boo", false},
      {"'sha256-yay' 'sha384-boo'", "https://a.com/file",
       "sha256-yay sha384-yay", false},
      {"'sha256-yay' 'sha384-boo'", "https://a.com/file",
       "sha256-boo sha384-boo", false},
      {"'sha256-yay' 'sha384-boo'", "https://a.com/file",
       "sha256-yay sha384-boo", true},

      // At least one integrity hash must be present.
      {"'sha256-yay'", "https://a.com/file", "", false},
  };

  ContentSecurityPolicy* context =
      MakeGarbageCollected<ContentSecurityPolicy>();
  TestCSPDelegate* test_delegate = MakeGarbageCollected<TestCSPDelegate>();
  context->BindToDelegate(*test_delegate);

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message()
                 << "List: `" << test.list << "`, URL: `" << test.url
                 << "`, Integrity: `" << test.integrity << "`");
    const KURL resource(test.url);

    IntegrityMetadataSet integrity_metadata;
    SubresourceIntegrity::ParseIntegrityAttribute(
        test.integrity, SubresourceIntegrity::IntegrityFeatures::kDefault,
        integrity_metadata);

    // Report-only 'script-src'
    network::mojom::blink::ContentSecurityPolicyPtr directive_list = CreateList(
        String("script-src ") + test.list, ContentSecurityPolicyType::kReport);
    EXPECT_TRUE(CSPDirectiveListAllowFromSource(
        *directive_list, context, CSPDirectiveName::ScriptSrcElem, resource,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kSuppressReporting, String(), integrity_metadata,
        kParserInserted));

    // Enforce 'script-src'
    directive_list = CreateList(String("script-src ") + test.list,
                                ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(
        CSPCheckResult(test.expected),
        CSPDirectiveListAllowFromSource(
            *directive_list, context, CSPDirectiveName::ScriptSrcElem, resource,
            resource, ResourceRequest::RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting, String(),
            integrity_metadata, kParserInserted));
  }
}

TEST_F(CSPDirectiveListTest, WorkerSrc) {
  struct TestCase {
    const char* list;
    bool allowed;
  } cases[] = {
      {"worker-src 'none'", false},
      {"worker-src http://not.example.test", false},
      {"worker-src https://example.test", true},
      {"default-src *; worker-src 'none'", false},
      {"default-src *; worker-src http://not.example.test", false},
      {"default-src *; worker-src https://example.test", true},
      {"script-src *; worker-src 'none'", false},
      {"script-src *; worker-src http://not.example.test", false},
      {"script-src *; worker-src https://example.test", true},
      {"default-src *; script-src *; worker-src 'none'", false},
      {"default-src *; script-src *; worker-src http://not.example.test",
       false},
      {"default-src *; script-src *; worker-src https://example.test", true},

      // Fallback to script-src.
      {"script-src 'none'", false},
      {"script-src http://not.example.test", false},
      {"script-src https://example.test", true},
      {"default-src *; script-src 'none'", false},
      {"default-src *; script-src http://not.example.test", false},
      {"default-src *; script-src https://example.test", true},

      // Fallback to default-src.
      {"default-src 'none'", false},
      {"default-src http://not.example.test", false},
      {"default-src https://example.test", true},
  };

  ContentSecurityPolicy* context =
      MakeGarbageCollected<ContentSecurityPolicy>();
  TestCSPDelegate* test_delegate = MakeGarbageCollected<TestCSPDelegate>();
  context->BindToDelegate(*test_delegate);

  for (const auto& test : cases) {
    SCOPED_TRACE(test.list);
    const KURL resource("https://example.test/worker.js");
    network::mojom::blink::ContentSecurityPolicyPtr directive_list =
        CreateList(test.list, ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(
        CSPCheckResult(test.allowed),
        CSPDirectiveListAllowFromSource(
            *directive_list, context, CSPDirectiveName::WorkerSrc, resource,
            resource, ResourceRequest::RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting));
  }
}

TEST_F(CSPDirectiveListTest, WorkerSrcChildSrcFallback) {
  // TODO(mkwst): Remove this test once we remove the temporary fallback
  // behavior. https://crbug.com/662930
  struct TestCase {
    const char* list;
    bool allowed;
  } cases[] = {
      // When 'worker-src' is not present, 'child-src' can allow a worker when
      // present.
      {"child-src https://example.test", true},
      {"child-src https://not-example.test", false},
      {"script-src https://example.test", true},
      {"script-src https://not-example.test", false},
      {"child-src https://example.test; script-src https://example.test", true},
      {"child-src https://example.test; script-src https://not-example.test",
       true},
      {"child-src https://not-example.test; script-src https://example.test",
       false},
      {"child-src https://not-example.test; script-src "
       "https://not-example.test",
       false},

      // If 'worker-src' is present, 'child-src' will not allow a worker.
      {"worker-src https://example.test; child-src https://example.test", true},
      {"worker-src https://example.test; child-src https://not-example.test",
       true},
      {"worker-src https://not-example.test; child-src https://example.test",
       false},
      {"worker-src https://not-example.test; child-src "
       "https://not-example.test",
       false},
  };

  ContentSecurityPolicy* context =
      MakeGarbageCollected<ContentSecurityPolicy>();
  TestCSPDelegate* test_delegate = MakeGarbageCollected<TestCSPDelegate>();
  context->BindToDelegate(*test_delegate);

  for (const auto& test : cases) {
    SCOPED_TRACE(test.list);
    const KURL resource("https://example.test/worker.js");
    network::mojom::blink::ContentSecurityPolicyPtr directive_list =
        CreateList(test.list, ContentSecurityPolicyType::kEnforce);
    EXPECT_EQ(
        CSPCheckResult(test.allowed),
        CSPDirectiveListAllowFromSource(
            *directive_list, context, CSPDirectiveName::WorkerSrc, resource,
            resource, ResourceRequest::RedirectStatus::kNoRedirect,
            ReportingDisposition::kSuppressReporting));
  }
}

TEST_F(CSPDirectiveListTest, OperativeDirectiveGivenType) {
  struct TestCase {
    CSPDirectiveName directive;
    Vector<CSPDirectiveName> fallback_list;
  } cases[] = {
      // Directives with default directive.
      {CSPDirectiveName::ChildSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::ConnectSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::FontSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::ImgSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::ManifestSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::MediaSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::ObjectSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::ScriptSrc, {CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::StyleSrc, {CSPDirectiveName::DefaultSrc}},
      // Directives with no default directive.
      {CSPDirectiveName::BaseURI, {}},
      {CSPDirectiveName::DefaultSrc, {}},
      {CSPDirectiveName::FrameAncestors, {}},
      {CSPDirectiveName::FormAction, {}},
      // Directive with multiple default directives.
      {CSPDirectiveName::ScriptSrcAttr,
       {CSPDirectiveName::ScriptSrc, CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::ScriptSrcElem,
       {CSPDirectiveName::ScriptSrc, CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::FrameSrc,
       {CSPDirectiveName::ChildSrc, CSPDirectiveName::DefaultSrc}},
      {CSPDirectiveName::WorkerSrc,
       {CSPDirectiveName::ChildSrc, CSPDirectiveName::ScriptSrc,
        CSPDirectiveName::DefaultSrc}},
  };

  std::stringstream all_directives;
  for (const auto& test : cases) {
    const char* name = ContentSecurityPolicy::GetDirectiveName(test.directive);
    all_directives << name << " http://" << name << ".com; ";
  }

  network::mojom::blink::ContentSecurityPolicyPtr empty =
      CreateList("nonexistent-directive", ContentSecurityPolicyType::kEnforce);

  std::string directive_string;
  network::mojom::blink::ContentSecurityPolicyPtr directive_list;
  // Initial set-up.
  for (auto& test : cases) {
    // With an empty directive list the returned directive should always be
    // null.
    EXPECT_FALSE(
        CSPDirectiveListOperativeDirective(*empty, test.directive).source_list);

    // Add the directive itself as it should be the first one to be returned.
    test.fallback_list.push_front(test.directive);

    // Start the tests with all directives present.
    directive_string = all_directives.str();

    while (!test.fallback_list.empty()) {
      directive_list = CreateList(directive_string.c_str(),
                                  ContentSecurityPolicyType::kEnforce);

      CSPOperativeDirective operative_directive =
          CSPDirectiveListOperativeDirective(*directive_list, test.directive);

      // We should have an actual directive returned here.
      EXPECT_TRUE(operative_directive.source_list);

      // The OperativeDirective should be first one in the fallback chain.
      EXPECT_EQ(test.fallback_list.front(), operative_directive.type);

      // Remove the first directive in the fallback chain from the directive
      // list and continue by testing that the next one is returned until we
      // have no more directives in the fallback list.
      const char* current_directive_name =
          ContentSecurityPolicy::GetDirectiveName(test.fallback_list.front());

      std::stringstream current_directive;
      current_directive << current_directive_name << " http://"
                        << current_directive_name << ".com; ";

      size_t index = directive_string.find(current_directive.str());
      directive_string.replace(index, current_directive.str().size(), "");

      test.fallback_list.erase(test.fallback_list.begin());
    }

    // After we have checked and removed all the directives in the fallback
    // chain we should ensure that there is no unexpected directive outside of
    // the fallback chain that is returned.
    directive_list = CreateList(directive_string.c_str(),
                                ContentSecurityPolicyType::kEnforce);
    EXPECT_FALSE(
        CSPDirectiveListOperativeDirective(*directive_list, test.directive)
            .source_list);
  }
}

TEST_F(CSPDirectiveListTest, ReportEndpointsProperlyParsed) {
  struct TestCase {
    const char* policy;
    ContentSecurityPolicySource header_source;
    Vector<String> expected_endpoints;
    bool expected_use_reporting_api;
  } cases[] = {
      {"script-src 'self';", ContentSecurityPolicySource::kHTTP, {}, false},
      {"script-src 'self'; report-uri https://example.com",
       ContentSecurityPolicySource::kHTTP,
       {"https://example.com/"},
       false},
      {"script-src 'self'; report-uri https://example.com "
       "https://example2.com",
       ContentSecurityPolicySource::kHTTP,
       {"https://example.com/", "https://example2.com/"},
       false},
      {"script-src 'self'; report-uri https://example.com "
       "http://example2.com /relative/path",
       // Mixed Content report-uri endpoint is ignored.
       ContentSecurityPolicySource::kHTTP,
       {"https://example.com/", "https://example.test/relative/path"},
       false},
      {"script-src 'self'; report-uri https://example.com",
       ContentSecurityPolicySource::kMeta,
       {},
       false},
      {"script-src 'self'; report-to group",
       ContentSecurityPolicySource::kHTTP,
       {"group"},
       true},
      // report-to supersedes report-uri
      {"script-src 'self'; report-to group; report-uri https://example.com",
       ContentSecurityPolicySource::kHTTP,
       {"group"},
       true},
      {"script-src 'self'; report-to group",
       ContentSecurityPolicySource::kMeta,
       {"group"},
       true},
      {"script-src 'self'; report-to group group2",
       ContentSecurityPolicySource::kHTTP,
       // Only the first report-to endpoint is used. The other ones are ignored.
       {"group"},
       true},
      {"script-src 'self'; report-to group; report-to group2;",
       ContentSecurityPolicySource::kHTTP,
       {"group"},
       true},
      {"script-src 'self'; report-to group; report-uri https://example.com; "
       "report-to group2",
       ContentSecurityPolicySource::kHTTP,
       {"group"},
       true},
      {"script-src 'self'; report-uri https://example.com; report-to group; "
       "report-to group2",
       ContentSecurityPolicySource::kHTTP,
       {"group"},
       true},
      {"script-src 'self'; report-uri https://example.com "
       "https://example2.com; report-to group",
       ContentSecurityPolicySource::kHTTP,
       {"group"},
       true},
      {"script-src 'self'; report-uri https://example.com; report-to group; "
       "report-uri https://example.com",
       ContentSecurityPolicySource::kHTTP,
       {"group"},
       true},
  };

  for (const auto& test : cases) {
    // Test both enforce and report, there should not be a difference
    for (const auto& header_type : {ContentSecurityPolicyType::kEnforce,
                                    ContentSecurityPolicyType::kReport}) {
      network::mojom::blink::ContentSecurityPolicyPtr directive_list =
          CreateList(test.policy, header_type, test.header_source);

      EXPECT_EQ(directive_list->use_reporting_api,
                test.expected_use_reporting_api);
      EXPECT_EQ(directive_list->report_endpoints.size(),
                test.expected_endpoints.size());

      for (const String& endpoint : test.expected_endpoints) {
        EXPECT_TRUE(directive_list->report_endpoints.Contains(endpoint));
      }
      for (const String& endpoint : directive_list->report_endpoints) {
        EXPECT_TRUE(test.expected_endpoints.Contains(endpoint));
      }
    }
  }
}

TEST_F(CSPDirectiveListTest, ReasonableObjectRestriction) {
  struct TestCase {
    const char* list;
    bool expected;
  } cases[] = {// Insufficient restriction!
               {"img-src *", false},
               {"object-src *", false},
               {"object-src https://very.safe.test/", false},
               {"object-src https:", false},
               {"script-src *", false},
               {"script-src https://very.safe.test/", false},
               {"script-src https:", false},
               {"script-src 'none'; object-src *", false},
               {"script-src 'none'; object-src https://very.safe.test/", false},
               {"script-src 'none'; object-src https:", false},

               // Sufficient restrictions!
               {"default-src 'none'", true},
               {"object-src 'none'", true},
               {"object-src 'none'; script-src 'unsafe-inline'", true},
               {"object-src 'none'; script-src *", true}};

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message() << "List: `" << test.list << "`");
    network::mojom::blink::ContentSecurityPolicyPtr directive_list =
        CreateList(test.list, ContentSecurityPolicyType::kReport);
    EXPECT_EQ(test.expected,
              CSPDirectiveListIsObjectRestrictionReasonable(*dir
"""


```