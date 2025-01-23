Response:
The user wants a summary of the functionality of the given C++ source code file. They are particularly interested in how it relates to Javascript, HTML, and CSS. They also want examples of logical reasoning with inputs and outputs, and common user or programming errors. Finally, they want an overall summary of the file's purpose.

**Plan:**

1. **Identify the core purpose:**  The file is a test suite for the `ContentSecurityPolicy` class in the Chromium Blink engine.
2. **Summarize the key functionalities tested:**  The tests cover parsing CSP headers, applying different CSP directives (like `script-src`, `img-src`, `connect-src`, `object-src`, `sandbox`, `upgrade-insecure-requests`), handling `nonce` values, and the interaction between different policies.
3. **Relate to Javascript, HTML, and CSS:** CSP is directly related to these technologies by controlling the sources from which scripts, stylesheets, images, and other resources can be loaded, as well as restricting inline script and style execution.
4. **Provide examples of logical reasoning:**  Demonstrate how a CSP directive should block or allow a specific resource based on the policy.
5. **Illustrate common errors:**  Highlight mistakes in CSP syntax or misunderstandings of how policies are applied.
6. **Formulate the summary:** Concisely state the file's main objective and the scope of its tests.
这是`blink/renderer/core/frame/csp/content_security_policy_test.cc`文件的第一部分，其主要功能是**测试 Blink 引擎中 `ContentSecurityPolicy` 类的各种功能**。`ContentSecurityPolicy` 负责处理网页内容安全策略 (CSP)，这是一个重要的安全机制，用于减少跨站脚本攻击 (XSS) 等安全风险。

**功能归纳:**

这部分代码主要测试了以下 `ContentSecurityPolicy` 类的功能：

1. **解析 `InsecureRequestPolicy` 指令:**  测试了 `upgrade-insecure-requests` 和 `block-all-mixed-content` 这两个 CSP 指令的解析和应用，这两个指令与处理 HTTPS 和混合内容有关。
2. **添加和合并多个策略 (`AddPolicies`)**:  测试了如何添加多个 CSP 策略，以及这些策略如何共同作用。
3. **检查策略是否激活连接限制 (`IsActiveForConnections`)**:  测试了当 CSP 包含 `connect-src` 或 `default-src` 指令时，是否会激活连接限制。
4. **处理 `<meta>` 标签中的 `sandbox` 指令**:  测试了从 HTML `<meta>` 标签中解析到的 CSP 策略中，`sandbox` 指令是否会被正确忽略。
5. **测试 `object-src` 指令**:  测试了 `object-src` 指令对 `<object>` 和 `<embed>` 标签以及插件加载的影响。
6. **测试 `connect-src` 指令**:  测试了 `connect-src` 指令对各种网络请求类型（如 XMLHttpRequest, Fetch, Beacon 等）的影响。
7. **测试 `nonce` (一次性随机数) 机制**:  测试了在单个和多个 CSP 策略下，使用 `nonce` 允许内联脚本和外部脚本资源加载的功能。
8. **获取 CSP 指令类型 (`GetDirectiveType`)**:  测试了根据指令名称获取对应枚举类型的函数。
9. **测试在绕过 CSP 的情况下允许请求 (`RequestsAllowedWhenBypassingCSP`)**:  测试了当特定协议被标记为允许绕过 CSP 时，请求是否会被允许。
10. **测试在绕过 CSP 的情况下允许文件系统访问 (`FilesystemAllowedWhenBypassingCSP`)**:  测试了文件系统协议是否可以被标记为允许绕过 CSP。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

CSP 与 JavaScript, HTML, CSS 的功能紧密相关，因为它直接控制了这些技术在网页中的行为，以增强安全性。

* **JavaScript:**
    * **`script-src` 指令:**  控制可以加载和执行 JavaScript 代码的来源。例如，`script-src 'self'` 只允许从同源加载 JavaScript。
    * **`nonce` 机制:**  允许在 CSP 中指定一个一次性使用的随机数，然后在 HTML 的 `<script>` 标签中通过 `nonce` 属性匹配，从而允许特定的内联脚本执行。
        * **假设输入:**  CSP 头为 `script-src 'nonce-abcdefg'`, HTML 中有 `<script nonce="abcdefg">alert('hello');</script>`。
        * **输出:**  该内联脚本将被允许执行。
        * **常见使用错误:**  开发者在 CSP 中指定了 `nonce` 值，但忘记在 HTML 标签中添加对应的 `nonce` 属性，导致脚本被阻止执行。
    * **`unsafe-inline` 关键字 (已被 `nonce` 或 `hash` 取代):**  允许执行页面内的内联 JavaScript 代码。如果 CSP 中不包含 `'unsafe-inline'` 且没有有效的 `nonce` 或 `hash`，则内联脚本将被阻止。
* **HTML:**
    * **`<meta>` 标签中的 CSP:**  允许在 HTML 文档的 `<meta>` 标签中设置 CSP。但这有一些限制，例如 `sandbox` 指令会被忽略。
    * **`object-src` 指令:**  控制可以加载的插件（如 Flash）的来源，对应 HTML 中的 `<object>` 和 `<embed>` 标签。例如，`object-src 'none'` 会阻止所有插件的加载。
    * **`base-uri` 指令:**  限制文档中可以使用 `<base>` 元素指定的 URL。
    * **`form-action` 指令:**  限制表单可以提交到的 URL。
    * **`frame-ancestors` 指令:**  限制网页可以被嵌入到哪些其他网页的 `<iframe>` 中。
    * **`frame-src` 和 `child-src` 指令:**  控制可以加载到 `<iframe>` 和 Worker 中的内容的来源。
* **CSS:**
    * **`style-src` 指令:**  控制可以加载 CSS 样式表的来源。例如，`style-src https://example.com` 只允许从 `https://example.com` 加载 CSS。
    * **`nonce` 机制:**  类似于 JavaScript，可以用于允许特定的内联 CSS 样式。
        * **假设输入:**  CSP 头为 `style-src 'nonce-12345'`, HTML 中有 `<style nonce="12345">body { background-color: red; }</style>`。
        * **输出:**  该内联样式将被应用。
        * **常见使用错误:**  在 CSP 中使用了 `nonce`，但在 `<style>` 标签中忘记添加 `nonce` 属性。
    * **`unsafe-inline` 关键字 (已被 `nonce` 或 `hash` 取代):**  允许页面内的内联 CSS 样式。

**逻辑推理举例:**

* **假设输入:**
    * CSP 策略: `script-src 'self' https://trusted.example.com`
    * 尝试加载的脚本 URL: `https://untrusted.example.com/script.js`
* **输出:**  脚本加载将被阻止，并且可能在控制台中产生 CSP 违规报告。
* **推理:**  CSP 策略明确只允许从同源 (`'self'`) 或 `https://trusted.example.com` 加载脚本，`https://untrusted.example.com/script.js` 不在允许的列表中。

* **假设输入:**
    * CSP 策略: `img-src *`
    * 尝试加载的图片 URL: `http://anywhere.com/image.png`
* **输出:**  图片加载将被允许。
* **推理:**  `img-src *` 允许从任何来源加载图片。

**涉及的用户或编程常见使用错误举例:**

1. **CSP 策略过于严格导致网页功能失效:**  例如，设置了 `default-src 'none'` 但没有明确允许加载必要的资源（如图片、脚本、样式），导致网页显示不正常。
2. **CSP 策略语法错误:**  例如，指令之间缺少分号分隔，或者使用了不正确的关键字，导致整个策略或部分策略失效。
3. **混淆 `upgrade-insecure-requests` 和 `block-all-mixed-content`:**  开发者可能错误地认为这两个指令的功能完全相同。`upgrade-insecure-requests` 是将不安全的 HTTP 请求升级到 HTTPS，而 `block-all-mixed-content` 是阻止加载任何不安全的 HTTP 子资源。
4. **忘记为内联脚本或样式添加正确的 `nonce` 或 `hash` 值:**  导致这些内联代码被 CSP 阻止执行或应用。
5. **在 Report-Only 模式下误以为策略会阻止资源加载:**  Report-Only 模式下的 CSP 策略不会阻止资源的加载，只会生成违规报告。开发者需要在 Enforce 模式下才能真正阻止不符合策略的资源。
6. **不理解不同 CSP 指令的作用域:**  例如，认为 `default-src` 可以替代所有其他的资源类型指令，但实际上某些指令（如 `script-src`, `img-src`）更具体，会覆盖 `default-src` 的设置。

总而言之，`content_security_policy_test.cc` 的这一部分主要关注于测试 `ContentSecurityPolicy` 类解析和应用各种基本 CSP 指令的能力，以及它与网页中 JavaScript, HTML 和 CSS 元素交互时的行为。它通过各种测试用例来验证 CSP 功能的正确性，为 Chromium 浏览器的安全机制提供了保障。

### 提示词
```
这是目录为blink/renderer/core/frame/csp/content_security_policy_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"

#include "base/test/scoped_feature_list.h"
#include "base/test/with_feature_override.h"
#include "services/network/public/cpp/features.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/security_context/insecure_request_policy.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_init.h"
#include "third_party/blink/renderer/core/frame/csp/csp_directive_list.h"
#include "third_party/blink/renderer/core/frame/csp/test_util.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/crypto.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/integrity_metadata.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/network/content_security_policy_parsers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {

namespace {

using network::mojom::ContentSecurityPolicySource;
using network::mojom::ContentSecurityPolicyType;
using testing::Contains;
using testing::SizeIs;

}  // namespace

class ContentSecurityPolicyTest : public testing::Test {
 public:
  ContentSecurityPolicyTest()
      : csp(MakeGarbageCollected<ContentSecurityPolicy>()),
        secure_url("https://example.test/index.html"),
        secure_origin(SecurityOrigin::Create(secure_url)) {}
  ~ContentSecurityPolicyTest() override {
    execution_context->NotifyContextDestroyed();
  }

 protected:
  void SetUp() override { CreateExecutionContext(); }

  void CreateExecutionContext() {
    if (execution_context)
      execution_context->NotifyContextDestroyed();
    execution_context = MakeGarbageCollected<NullExecutionContext>();
    execution_context->SetUpSecurityContextForTesting();
    execution_context->GetSecurityContext().SetSecurityOriginForTesting(
        secure_origin);
  }

  test::TaskEnvironment task_environment;
  Persistent<ContentSecurityPolicy> csp;
  KURL secure_url;
  scoped_refptr<SecurityOrigin> secure_origin;
  Persistent<NullExecutionContext> execution_context;
};

TEST_F(ContentSecurityPolicyTest, ParseInsecureRequestPolicy) {
  struct TestCase {
    const char* header;
    mojom::blink::InsecureRequestPolicy expected_policy;
  } cases[] = {
      {"default-src 'none'",
       mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone},
      {"upgrade-insecure-requests",
       mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests},
      {"block-all-mixed-content",
       mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent},
      {"upgrade-insecure-requests; block-all-mixed-content",
       mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests |
           mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent},
      {"upgrade-insecure-requests, block-all-mixed-content",
       mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests |
           mojom::blink::InsecureRequestPolicy::kBlockAllMixedContent}};

  // Enforced
  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message()
                 << "[Enforce] Header: `" << test.header << "`");
    csp = MakeGarbageCollected<ContentSecurityPolicy>();
    csp->AddPolicies(ParseContentSecurityPolicies(
        test.header, ContentSecurityPolicyType::kEnforce,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_EQ(test.expected_policy, csp->GetInsecureRequestPolicy());

    auto dummy = std::make_unique<DummyPageHolder>();
    dummy->GetDocument().SetURL(secure_url);
    auto& security_context =
        dummy->GetFrame().DomWindow()->GetSecurityContext();
    security_context.SetSecurityOriginForTesting(secure_origin);

    csp->BindToDelegate(
        dummy->GetFrame().DomWindow()->GetContentSecurityPolicyDelegate());
    EXPECT_EQ(test.expected_policy,
              security_context.GetInsecureRequestPolicy());
    bool expect_upgrade =
        (test.expected_policy &
         mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests) !=
        mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone;
    EXPECT_EQ(
        expect_upgrade,
        security_context.InsecureNavigationsToUpgrade().Contains(
            dummy->GetDocument().Url().Host().ToString().Impl()->GetHash()));
  }

  // Report-Only
  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message()
                 << "[Report-Only] Header: `" << test.header << "`");
    csp = MakeGarbageCollected<ContentSecurityPolicy>();
    csp->AddPolicies(ParseContentSecurityPolicies(
        test.header, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_EQ(mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone,
              csp->GetInsecureRequestPolicy());

    CreateExecutionContext();
    execution_context->GetSecurityContext().SetSecurityOrigin(secure_origin);
    csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
    EXPECT_EQ(
        mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone,
        execution_context->GetSecurityContext().GetInsecureRequestPolicy());
    EXPECT_FALSE(execution_context->GetSecurityContext()
                     .InsecureNavigationsToUpgrade()
                     .Contains(secure_origin->Host().Impl()->GetHash()));
  }
}

MATCHER_P(HasSubstr, s, "") {
  return arg.Contains(s);
}

TEST_F(ContentSecurityPolicyTest, AddPolicies) {
  csp->AddPolicies(ParseContentSecurityPolicies(
      "script-src 'none'", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  csp->AddPolicies(ParseContentSecurityPolicies(
      "img-src http://example.com", ContentSecurityPolicyType::kReport,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  const KURL example_url("http://example.com");
  const KURL not_example_url("http://not-example.com");

  auto* csp2 = MakeGarbageCollected<ContentSecurityPolicy>();
  TestCSPDelegate* test_delegate = MakeGarbageCollected<TestCSPDelegate>();
  csp2->BindToDelegate(*test_delegate);
  csp2->AddPolicies(mojo::Clone(csp->GetParsedPolicies()));

  EXPECT_TRUE(csp2->AllowScriptFromSource(
      example_url, String(), IntegrityMetadataSet(), kParserInserted,
      example_url, ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kReport,
      ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly));
  EXPECT_THAT(
      test_delegate->console_messages(),
      Contains(HasSubstr("Refused to load the script 'http://example.com/'")));

  test_delegate->console_messages().clear();
  EXPECT_TRUE(csp2->AllowImageFromSource(
      example_url, example_url, ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kReport,
      ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly));
  EXPECT_THAT(test_delegate->console_messages(), SizeIs(0));

  test_delegate->console_messages().clear();
  EXPECT_TRUE(csp2->AllowImageFromSource(
      not_example_url, not_example_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kReport,
      ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly));
  EXPECT_THAT(test_delegate->console_messages(),
              Contains(HasSubstr(
                  "Refused to load the image 'http://not-example.com/'")));
}

TEST_F(ContentSecurityPolicyTest, IsActiveForConnectionsWithConnectSrc) {
  EXPECT_FALSE(csp->IsActiveForConnections());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "connect-src 'none';", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_TRUE(csp->IsActiveForConnections());
}

TEST_F(ContentSecurityPolicyTest, IsActiveForConnectionsWithDefaultSrc) {
  EXPECT_FALSE(csp->IsActiveForConnections());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "default-src 'none';", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_TRUE(csp->IsActiveForConnections());
}

// Tests that sandbox directives are discarded from policies
// delivered in <meta> elements.
TEST_F(ContentSecurityPolicyTest, SandboxInMeta) {
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  EXPECT_EQ(network::mojom::blink::WebSandboxFlags::kNone,
            csp->GetSandboxMask());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "sandbox;", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kMeta, *secure_origin));
  EXPECT_EQ(network::mojom::blink::WebSandboxFlags::kNone,
            csp->GetSandboxMask());
  execution_context->GetSecurityContext().SetSandboxFlags(
      network::mojom::blink::WebSandboxFlags::kAll);
  csp->AddPolicies(ParseContentSecurityPolicies(
      "sandbox;", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));
  EXPECT_EQ(network::mojom::blink::WebSandboxFlags::kAll,
            csp->GetSandboxMask());
}

// Tests that object-src directives are applied to a request to load a
// plugin, but not to subresource requests that the plugin itself
// makes. https://crbug.com/603952
TEST_F(ContentSecurityPolicyTest, ObjectSrc) {
  const KURL url("https://example.test");
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "object-src 'none';", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kMeta, *secure_origin));
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::OBJECT,
                                 network::mojom::RequestDestination::kEmpty,
                                 url, String(), IntegrityMetadataSet(),
                                 kParserInserted, url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::EMBED,
                                 network::mojom::RequestDestination::kEmbed,
                                 url, String(), IntegrityMetadataSet(),
                                 kParserInserted, url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));
  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::PLUGIN,
                                network::mojom::RequestDestination::kEmpty, url,
                                String(), IntegrityMetadataSet(),
                                kParserInserted, url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));
}

TEST_F(ContentSecurityPolicyTest, ConnectSrc) {
  const KURL url("https://example.test");
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "connect-src 'none';", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kMeta, *secure_origin));
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::SUBRESOURCE,
                                 network::mojom::RequestDestination::kEmpty,
                                 url, String(), IntegrityMetadataSet(),
                                 kParserInserted, url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(
      csp->AllowRequest(mojom::blink::RequestContextType::XML_HTTP_REQUEST,
                        network::mojom::RequestDestination::kEmpty, url,
                        String(), IntegrityMetadataSet(), kParserInserted, url,
                        ResourceRequest::RedirectStatus::kNoRedirect,
                        ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::BEACON,
                                 network::mojom::RequestDestination::kEmpty,
                                 url, String(), IntegrityMetadataSet(),
                                 kParserInserted, url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));
  EXPECT_FALSE(csp->AllowRequest(mojom::blink::RequestContextType::FETCH,
                                 network::mojom::RequestDestination::kEmpty,
                                 url, String(), IntegrityMetadataSet(),
                                 kParserInserted, url,
                                 ResourceRequest::RedirectStatus::kNoRedirect,
                                 ReportingDisposition::kSuppressReporting));
  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::PLUGIN,
                                network::mojom::RequestDestination::kEmpty, url,
                                String(), IntegrityMetadataSet(),
                                kParserInserted, url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));
}

TEST_F(ContentSecurityPolicyTest, NonceSinglePolicy) {
  struct TestCase {
    const char* policy;
    const char* url;
    const char* nonce;
    bool allowed;
  } cases[] = {
      {"script-src 'nonce-yay'", "https://example.com/js", "", false},
      {"script-src 'nonce-yay'", "https://example.com/js", "yay", true},
      {"script-src https://example.com", "https://example.com/js", "", true},
      {"script-src https://example.com", "https://example.com/js", "yay", true},
      {"script-src https://example.com 'nonce-yay'",
       "https://not.example.com/js", "", false},
      {"script-src https://example.com 'nonce-yay'",
       "https://not.example.com/js", "yay", true},
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message()
                 << "Policy: `" << test.policy << "`, URL: `" << test.url
                 << "`, Nonce: `" << test.nonce << "`");
    const KURL resource(test.url);

    unsigned expected_reports = test.allowed ? 0u : 1u;

    // Single enforce-mode policy should match `test.expected`:
    Persistent<ContentSecurityPolicy> policy =
        MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(
        execution_context->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy, ContentSecurityPolicyType::kEnforce,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_EQ(test.allowed,
              policy->AllowScriptFromSource(
                  resource, String(test.nonce), IntegrityMetadataSet(),
                  kParserInserted, resource,
                  ResourceRequest::RedirectStatus::kNoRedirect));
    // If this is expected to generate a violation, we should have sent a
    // report.
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());

    // Single report-mode policy should always be `true`:
    policy = MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(
        execution_context->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_TRUE(policy->AllowScriptFromSource(
        resource, String(test.nonce), IntegrityMetadataSet(), kParserInserted,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kReport,
        ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly));
    // If this is expected to generate a violation, we should have sent a
    // report, even though we don't deny access in `allowScriptFromSource`:
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());
  }
}

TEST_F(ContentSecurityPolicyTest, NonceInline) {
  struct TestCase {
    const char* policy;
    const char* nonce;
    bool allowed;
  } cases[] = {
      {"'unsafe-inline'", "", true},
      {"'unsafe-inline'", "yay", true},
      {"'nonce-yay'", "", false},
      {"'nonce-yay'", "yay", true},
      {"'unsafe-inline' 'nonce-yay'", "", false},
      {"'unsafe-inline' 'nonce-yay'", "yay", true},
  };

  String context_url;
  String content;
  OrdinalNumber context_line = OrdinalNumber::First();

  // We need document for HTMLScriptElement tests.
  auto dummy = std::make_unique<DummyPageHolder>();
  auto* window = dummy->GetFrame().DomWindow();
  window->GetSecurityContext().SetSecurityOriginForTesting(secure_origin);

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message() << "Policy: `" << test.policy
                                    << "`, Nonce: `" << test.nonce << "`");

    unsigned expected_reports = test.allowed ? 0u : 1u;
    auto* element = MakeGarbageCollected<HTMLScriptElement>(
        *window->document(), CreateElementFlags());

    // Enforce 'script-src'
    Persistent<ContentSecurityPolicy> policy =
        MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(window->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        String("script-src ") + test.policy,
        ContentSecurityPolicyType::kEnforce, ContentSecurityPolicySource::kHTTP,
        *secure_origin));
    EXPECT_EQ(test.allowed,
              policy->AllowInline(ContentSecurityPolicy::InlineType::kScript,
                                  element, content, String(test.nonce),
                                  context_url, context_line));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());

    // Enforce 'style-src'
    policy = MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(window->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        String("style-src ") + test.policy, ContentSecurityPolicyType::kEnforce,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_EQ(test.allowed,
              policy->AllowInline(ContentSecurityPolicy::InlineType::kStyle,
                                  element, content, String(test.nonce),
                                  context_url, context_line));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());

    // Report 'script-src'
    policy = MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(window->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        String("script-src ") + test.policy, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_TRUE(policy->AllowInline(ContentSecurityPolicy::InlineType::kScript,
                                    element, content, String(test.nonce),
                                    context_url, context_line));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());

    // Report 'style-src'
    policy = MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(window->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        String("style-src ") + test.policy, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_TRUE(policy->AllowInline(ContentSecurityPolicy::InlineType::kStyle,
                                    element, content, String(test.nonce),
                                    context_url, context_line));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());
  }
}

TEST_F(ContentSecurityPolicyTest, NonceMultiplePolicy) {
  struct TestCase {
    const char* policy1;
    const char* policy2;
    const char* url;
    const char* nonce;
    bool allowed1;
    bool allowed2;
  } cases[] = {
      // Passes both:
      {"script-src 'nonce-yay'", "script-src 'nonce-yay'",
       "https://example.com/js", "yay", true, true},
      {"script-src https://example.com", "script-src 'nonce-yay'",
       "https://example.com/js", "yay", true, true},
      {"script-src 'nonce-yay'", "script-src https://example.com",
       "https://example.com/js", "yay", true, true},
      {"script-src https://example.com 'nonce-yay'",
       "script-src https://example.com 'nonce-yay'", "https://example.com/js",
       "yay", true, true},
      {"script-src https://example.com 'nonce-yay'",
       "script-src https://example.com 'nonce-yay'", "https://example.com/js",
       "", true, true},
      {"script-src https://example.com",
       "script-src https://example.com 'nonce-yay'", "https://example.com/js",
       "yay", true, true},
      {"script-src https://example.com 'nonce-yay'",
       "script-src https://example.com", "https://example.com/js", "yay", true,
       true},

      // Fails one:
      {"script-src 'nonce-yay'", "script-src https://example.com",
       "https://example.com/js", "", false, true},
      {"script-src 'nonce-yay'", "script-src 'none'", "https://example.com/js",
       "yay", true, false},
      {"script-src 'nonce-yay'", "script-src https://not.example.com",
       "https://example.com/js", "yay", true, false},

      // Fails both:
      {"script-src 'nonce-yay'", "script-src https://example.com",
       "https://not.example.com/js", "", false, false},
      {"script-src https://example.com", "script-src 'nonce-yay'",
       "https://not.example.com/js", "", false, false},
      {"script-src 'nonce-yay'", "script-src 'none'",
       "https://not.example.com/js", "boo", false, false},
      {"script-src 'nonce-yay'", "script-src https://not.example.com",
       "https://example.com/js", "", false, false},
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(testing::Message() << "Policy: `" << test.policy1 << "`/`"
                                    << test.policy2 << "`, URL: `" << test.url
                                    << "`, Nonce: `" << test.nonce << "`");
    const KURL resource(test.url);

    unsigned expected_reports =
        test.allowed1 != test.allowed2 ? 1u : (test.allowed1 ? 0u : 2u);

    // Enforce / Report
    Persistent<ContentSecurityPolicy> policy =
        MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(
        execution_context->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy1, ContentSecurityPolicyType::kEnforce,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy2, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_EQ(test.allowed1,
              policy->AllowScriptFromSource(
                  resource, String(test.nonce), IntegrityMetadataSet(),
                  kParserInserted, resource,
                  ResourceRequest::RedirectStatus::kNoRedirect,
                  ReportingDisposition::kReport,
                  ContentSecurityPolicy::CheckHeaderType::kCheckEnforce));
    EXPECT_TRUE(policy->AllowScriptFromSource(
        resource, String(test.nonce), IntegrityMetadataSet(), kParserInserted,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kReport,
        ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());

    // Report / Enforce
    policy = MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(
        execution_context->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy1, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy2, ContentSecurityPolicyType::kEnforce,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_TRUE(policy->AllowScriptFromSource(
        resource, String(test.nonce), IntegrityMetadataSet(), kParserInserted,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kReport,
        ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly));
    EXPECT_EQ(test.allowed2,
              policy->AllowScriptFromSource(
                  resource, String(test.nonce), IntegrityMetadataSet(),
                  kParserInserted, resource,
                  ResourceRequest::RedirectStatus::kNoRedirect,
                  ReportingDisposition::kReport,
                  ContentSecurityPolicy::CheckHeaderType::kCheckEnforce));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());

    // Enforce / Enforce
    policy = MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(
        execution_context->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy1, ContentSecurityPolicyType::kEnforce,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy2, ContentSecurityPolicyType::kEnforce,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_EQ(test.allowed1 && test.allowed2,
              policy->AllowScriptFromSource(
                  resource, String(test.nonce), IntegrityMetadataSet(),
                  kParserInserted, resource,
                  ResourceRequest::RedirectStatus::kNoRedirect,
                  ReportingDisposition::kReport,
                  ContentSecurityPolicy::CheckHeaderType::kCheckEnforce));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());

    // Report / Report
    policy = MakeGarbageCollected<ContentSecurityPolicy>();
    policy->BindToDelegate(
        execution_context->GetContentSecurityPolicyDelegate());
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy1, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    policy->AddPolicies(ParseContentSecurityPolicies(
        test.policy2, ContentSecurityPolicyType::kReport,
        ContentSecurityPolicySource::kHTTP, *secure_origin));
    EXPECT_TRUE(policy->AllowScriptFromSource(
        resource, String(test.nonce), IntegrityMetadataSet(), kParserInserted,
        resource, ResourceRequest::RedirectStatus::kNoRedirect,
        ReportingDisposition::kReport,
        ContentSecurityPolicy::CheckHeaderType::kCheckReportOnly));
    EXPECT_EQ(expected_reports, policy->violation_reports_sent_.size());
  }
}

TEST_F(ContentSecurityPolicyTest, DirectiveType) {
  struct TestCase {
    CSPDirectiveName type;
    const String& name;
  } cases[] = {
      {CSPDirectiveName::BaseURI, "base-uri"},
      {CSPDirectiveName::BlockAllMixedContent, "block-all-mixed-content"},
      {CSPDirectiveName::ChildSrc, "child-src"},
      {CSPDirectiveName::ConnectSrc, "connect-src"},
      {CSPDirectiveName::DefaultSrc, "default-src"},
      {CSPDirectiveName::FencedFrameSrc, "fenced-frame-src"},
      {CSPDirectiveName::FrameAncestors, "frame-ancestors"},
      {CSPDirectiveName::FrameSrc, "frame-src"},
      {CSPDirectiveName::FontSrc, "font-src"},
      {CSPDirectiveName::FormAction, "form-action"},
      {CSPDirectiveName::ImgSrc, "img-src"},
      {CSPDirectiveName::ManifestSrc, "manifest-src"},
      {CSPDirectiveName::MediaSrc, "media-src"},
      {CSPDirectiveName::ObjectSrc, "object-src"},
      {CSPDirectiveName::ReportURI, "report-uri"},
      {CSPDirectiveName::Sandbox, "sandbox"},
      {CSPDirectiveName::ScriptSrc, "script-src"},
      {CSPDirectiveName::ScriptSrcAttr, "script-src-attr"},
      {CSPDirectiveName::ScriptSrcElem, "script-src-elem"},
      {CSPDirectiveName::StyleSrc, "style-src"},
      {CSPDirectiveName::StyleSrcAttr, "style-src-attr"},
      {CSPDirectiveName::StyleSrcElem, "style-src-elem"},
      {CSPDirectiveName::UpgradeInsecureRequests, "upgrade-insecure-requests"},
      {CSPDirectiveName::WorkerSrc, "worker-src"},
  };

  EXPECT_EQ(CSPDirectiveName::Unknown,
            ContentSecurityPolicy::GetDirectiveType("random"));

  for (const auto& test : cases) {
    const String& name_from_type =
        ContentSecurityPolicy::GetDirectiveName(test.type);
    CSPDirectiveName type_from_name =
        ContentSecurityPolicy::GetDirectiveType(test.name);
    EXPECT_EQ(name_from_type, test.name);
    EXPECT_EQ(type_from_name, test.type);
    EXPECT_EQ(test.type,
              ContentSecurityPolicy::GetDirectiveType(name_from_type));
    EXPECT_EQ(test.name,
              ContentSecurityPolicy::GetDirectiveName(type_from_name));
  }
}

TEST_F(ContentSecurityPolicyTest, RequestsAllowedWhenBypassingCSP) {
  const KURL base;
  CreateExecutionContext();
  execution_context->GetSecurityContext().SetSecurityOrigin(
      secure_origin);                     // https://example.com
  execution_context->SetURL(secure_url);  // https://example.com
  csp->BindToDelegate(execution_context->GetContentSecurityPolicyDelegate());
  csp->AddPolicies(ParseContentSecurityPolicies(
      "default-src https://example.com", ContentSecurityPolicyType::kEnforce,
      ContentSecurityPolicySource::kHTTP, *secure_origin));

  const KURL example_url("https://example.com/");
  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::OBJECT,
                                network::mojom::RequestDestination::kEmpty,
                                example_url, String(), IntegrityMetadataSet(),
                                kParserInserted, example_url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));

  const KURL not_example_url("https://not-example.com/");
  EXPECT_FALSE(csp->AllowRequest(
      mojom::blink::RequestContextType::OBJECT,
      network::mojom::RequestDestination::kEmpty, not_example_url, String(),
      IntegrityMetadataSet(), kParserInserted, not_example_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));

  // Register "https" as bypassing CSP, which should now bypass it entirely
  SchemeRegistry::RegisterURLSchemeAsBypassingContentSecurityPolicy("https");

  EXPECT_TRUE(csp->AllowRequest(mojom::blink::RequestContextType::OBJECT,
                                network::mojom::RequestDestination::kEmpty,
                                example_url, String(), IntegrityMetadataSet(),
                                kParserInserted, example_url,
                                ResourceRequest::RedirectStatus::kNoRedirect,
                                ReportingDisposition::kSuppressReporting));

  EXPECT_TRUE(csp->AllowRequest(
      mojom::blink::RequestContextType::OBJECT,
      network::mojom::RequestDestination::kEmpty, not_example_url, String(),
      IntegrityMetadataSet(), kParserInserted, not_example_url,
      ResourceRequest::RedirectStatus::kNoRedirect,
      ReportingDisposition::kSuppressReporting));

  SchemeRegistry::RemoveURLSchemeRegisteredAsBypassingContentSecurityPolicy(
      "https");
}
TEST_F(ContentSecurityPolicyTest, FilesystemAllowedWhenBypassingCSP) {
  const KURL base;
  CreateExecutionContext();
  execution_context->GetSecurityContext().SetSecurityOrigin(
      secure_origin);                     // https://example.com
  execution_context->SetURL(se
```