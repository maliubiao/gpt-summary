Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive explanation.

1. **Understand the Goal:** The primary goal is to understand the purpose of `document_policy_sim_test.cc` within the Chromium Blink rendering engine. The prompt specifically asks for functionality, relationships to web technologies (HTML, CSS, JavaScript), logical inferences, common errors, and debugging context.

2. **Identify Key Elements:** The first step is to scan the code for important keywords and structures. These stand out:
    * `#include`:  Indicates dependencies. Look for Blink-specific headers like `permissions_policy`, `frame`, `testing`, and platform-related ones.
    * `namespace blink`:  Confirms this is Blink-specific code.
    * `class DocumentPolicySimTest : public SimTest`:  Establishes the class under examination and its base class. `SimTest` strongly suggests this is a simulation test environment.
    * `TEST_F(DocumentPolicySimTest, ...)`:  These are the individual test cases. The names of the test cases are highly informative about what's being tested.
    * `SimRequest`: This class is used to simulate HTTP requests and responses, crucial for testing how document policies interact with network loading.
    * HTTP header names like `Document-Policy`, `Require-Document-Policy`, `Document-Policy-Report-Only`.
    * HTML elements like `<iframe>` and the `policy` attribute.
    * `ConsoleMessages()`:  Indicates tests for console logging, which is relevant to developer feedback.
    * `histogram_tester`:  Points to tests involving metrics and usage tracking.
    * `IsFeatureEnabled()`, `IsUseCounted()`:  Suggests testing the activation and usage of document policy features.

3. **Analyze Individual Test Cases:**  The core of understanding the file lies in analyzing each test case. For each one:
    * **Read the Test Name:**  This is the most direct clue to the test's purpose. For example, `DocumentPolicyNegotiationNoEffectWhenFlagNotSet` clearly states what it's verifying.
    * **Examine the Setup:** Look at how `SimRequest` is used to define HTTP headers and the content loaded (often via `LoadURL` and `Complete`).
    * **Identify Assertions (EXPECT_*):** These are the criteria used to determine if the test passes or fails. Focus on what properties are being checked (e.g., console messages, URL, feature enabled status, histogram counts).
    * **Infer the Functionality:** Based on the setup and assertions, deduce what aspect of document policy is being tested.

4. **Connect to Web Technologies:**  As you analyze the test cases, actively look for connections to HTML, CSS, and JavaScript features:
    * **HTML:**  The presence of `<iframe>` and the `policy` attribute directly links to HTML's structure and attributes. The tests simulate how document policies apply to embedded frames.
    * **CSS:** While not directly tested in this file, document policies can *influence* CSS behavior indirectly by controlling which features are allowed. For instance, if a policy disallows a certain JavaScript API that manipulates styles, CSS rendering might be affected.
    * **JavaScript:** Many document policies restrict JavaScript behavior (e.g., `sync-xhr`). The tests verify how these restrictions are enforced, often through checks on whether certain features are enabled or by observing console errors that JavaScript might trigger.

5. **Identify Logical Inferences:** Some tests imply logical relationships:
    * If `Require-Document-Policy` is set but incompatible, the iframe load should be blocked.
    * If `Document-Policy` has a parsing error, a console message should be generated.
    * Usage counters should be incremented when document policy features are used.

6. **Consider User/Programming Errors:** Think about how developers might misuse or misunderstand document policies based on the tests:
    * Incorrectly formatted header values.
    * Conflicting policies between parent and child frames.
    * Expecting `Require-Document-Policy` to apply to the current document.

7. **Trace User Operations (Debugging):**  Imagine a user browsing a website and encountering a document policy issue. How would a developer arrive at this test file during debugging?
    * A user reports an unexpected behavior (e.g., an iframe not loading).
    * The developer inspects the browser console and sees document policy-related errors.
    * The developer examines the network requests and responses, noticing the `Document-Policy` or `Require-Document-Policy` headers.
    * To understand the engine's behavior, they might search the Chromium codebase for "DocumentPolicy" or related terms, eventually finding these simulation tests to see how the policy is *supposed* to work.

8. **Structure the Explanation:**  Organize the findings into clear sections as requested by the prompt:
    * Functionality overview.
    * Relationships with web technologies (with examples).
    * Logical inferences (with input/output examples).
    * Common errors (with examples).
    * Debugging context.

9. **Refine and Elaborate:** After the initial analysis, go back and add more detail and clarity. For instance, when discussing the connection to JavaScript, explain *how* document policies restrict JavaScript. For debugging, elaborate on the steps a developer might take.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about HTTP headers."  **Correction:** Realize it also covers the HTML `policy` attribute and internal Blink mechanisms for enforcing policies.
* **Initial thought:** "The tests are simple." **Correction:** Recognize the complexity lies in understanding the *interactions* between different headers, attributes, and the underlying Blink implementation.
* **Stuck on a test case:**  If a test case isn't immediately clear, break it down line by line and consult the Blink documentation or related code if necessary.
* **Missing a connection:** Actively prompt yourself: "How does this relate to what a web developer would do?" or "What user action could trigger this code path?"

By following these steps, and continually refining the understanding through careful examination and connection to broader web development concepts, a comprehensive and accurate explanation can be generated.
这个C++文件 `document_policy_sim_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件，专门用于测试**文档策略 (Document Policy)** 功能。它使用模拟环境 (SimTest) 来验证在不同场景下文档策略的行为和效果。

以下是该文件的详细功能分解：

**主要功能:**

1. **测试文档策略的解析和应用:** 该文件测试 Blink 引擎如何解析 `Document-Policy`、`Require-Document-Policy` 和 `Document-Policy-Report-Only` HTTP 头部，以及 HTML 元素的 `policy` 属性。它验证了策略是否被正确识别和应用到文档及其子框架上。

2. **测试文档策略协商 (Document Policy Negotiation):**  该文件测试当启用 `DocumentPolicyNegotiation` 功能时，`Require-Document-Policy` 头部和 iframe 的 `policy` 属性如何协同工作来决定是否加载子框架。它验证了当要求的策略与提供的策略不兼容时，子框架是否会被阻止加载。

3. **测试文档策略违规时的行为:**  该文件测试当文档策略被违反时，Blink 引擎会采取什么措施，例如：
    * 在控制台中输出错误信息。
    * 将违规文档的 origin 替换为 opaque origin。
    * 记录相应的用户行为统计 (Use Counter)。

4. **测试文档策略相关的用户行为统计 (Use Counters):**  该文件使用 `base::HistogramTester` 来验证与文档策略相关的各种用户行为是否被正确记录，例如：
    * 使用了 `Document-Policy` 头部。
    * 使用了 `Document-Policy-Report-Only` 头部。
    * 使用了 `Require-Document-Policy` 头部。
    * 使用了 iframe 的 `policy` 属性。
    * 文档策略被强制执行。
    * 文档策略仅用于报告。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

文档策略直接影响 JavaScript 和 HTML 的行为，间接影响 CSS。

* **HTML:**
    * **`<iframe>` 元素的 `policy` 属性:** 该测试文件验证了如何使用 `policy` 属性在 HTML 中为 iframe 指定文档策略。例如：
      ```html
      <iframe src="https://example.com/foo.html" policy="force-load-at-top=?0"></iframe>
      ```
      这个例子表示，对于加载的 `foo.html` 文档，`force-load-at-top` 特性被设置为禁用 (`?0`)。

* **JavaScript:**
    * 文档策略可以限制某些 JavaScript API 的使用。例如，测试用例中涉及的 `sync-xhr`  文档策略特性控制是否允许在文档中使用同步的 XMLHttpRequest 请求。如果一个文档的策略禁止 `sync-xhr`，那么在 JavaScript 中调用 `XMLHttpRequest` 的同步方法将会失败或者触发一个错误。

* **CSS:**
    * 文档策略本身不直接控制 CSS 属性，但它可以限制某些可能影响 CSS 行为的 JavaScript 功能。例如，如果一个策略禁止使用某些 JavaScript API 来动态修改样式，那么 CSS 的动态效果可能会受到影响。

**逻辑推理及假设输入与输出:**

**假设输入 1:**

* 主文档的 HTTP 头部包含 `Require-Document-Policy: sync-xhr=?0`。
* 子 iframe 的 HTTP 头部包含 `Document-Policy: sync-xhr`。

**预期输出 1:**

* 子 iframe 的加载将被阻止，因为主文档要求禁用 `sync-xhr`，而子文档声明启用 `sync-xhr`，策略不兼容。
* 控制台会输出一个错误信息，指示文档策略冲突。
* `mojom::WebFeature::kDocumentPolicyCausedPageUnload` 这个 Use Counter 会被记录。

**假设输入 2:**

* 主文档的 HTTP 头部包含 `Document-Policy: force-load-at-top`。
* HTML 中包含一个 iframe： `<iframe src="https://example.com/foo.html"></iframe>`。
* `DocumentPolicyNegotiation` 功能未启用。

**预期输出 2:**

* 子 iframe 将正常加载，即使其自身没有声明任何文档策略。
* 主文档的 `force-load-at-top` 策略不会影响子 iframe，因为策略协商未启用。

**涉及用户或编程常见的使用错误:**

1. **HTTP 头部拼写错误或格式错误:**  用户可能会错误地拼写 `Document-Policy` 或提供错误的策略指令格式，导致策略无法被正确解析。
   * **例子:**  `Document-Polcy: sync-xhr` (拼写错误) 或 `Document-Policy: sync-xhr=false` (正确的语法是 `sync-xhr=?0`)。
   * **测试用例:** `ReportDocumentPolicyHeaderParsingError` 和 `ReportRequireDocumentPolicyHeaderParsingError` 测试了这种情况，当头部解析错误时，控制台会输出错误信息。

2. **在不兼容的情况下期望 `Require-Document-Policy` 阻止主文档加载:**  `Require-Document-Policy` 主要用于约束子框架，它不会阻止设置该头部的文档自身加载。
   * **测试用例:** `RequireDocumentPolicyHeaderShouldNotAffectCurrentDocument` 验证了这一点。

3. **误解策略继承和覆盖规则:** 用户可能不清楚父文档的策略如何影响子文档，以及子文档如何覆盖或继承父文档的策略。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个包含文档策略的网页:** 用户在浏览器中输入 URL 或点击链接，访问一个服务器返回了包含 `Document-Policy`、`Require-Document-Policy` 或 `Document-Policy-Report-Only` HTTP 头的网页。

2. **浏览器解析 HTTP 响应头:**  浏览器接收到服务器的响应后，会解析 HTTP 头部，包括文档策略相关的头部。

3. **Blink 引擎处理文档策略:**  Blink 引擎的相应模块（即 `blink/renderer/core/permissions_policy/` 下的组件）会解析这些策略指令。

4. **遇到 iframe 或其他子资源:** 如果页面包含 iframe 或其他需要加载的子资源，Blink 引擎会检查主文档的 `Require-Document-Policy` 和子资源的 `Document-Policy` 以及 iframe 标签的 `policy` 属性，来决定是否允许加载。

5. **发生策略冲突或违规:**  如果策略之间存在冲突（例如，主文档要求禁用某个特性，而子文档或 iframe 声明启用），或者页面上的 JavaScript 代码违反了当前的文档策略，就会触发相应的处理逻辑。

6. **控制台输出错误信息或记录用户行为:**  如果发生策略违规，Blink 引擎可能会在浏览器的开发者工具控制台中输出错误信息。同时，相关的用户行为统计信息会被记录。

**作为调试线索，开发者可能会：**

* **检查 Network 面板:**  查看 HTTP 响应头，确认服务器是否返回了预期的文档策略头部。
* **检查 Console 面板:**  查看是否有文档策略相关的错误或警告信息。
* **使用 `chrome://policy`:**  查看浏览器实际应用的策略（可能受到企业策略等影响）。
* **阅读 Blink 源代码:**  如果需要深入了解文档策略的处理逻辑，开发者可能会查看 `blink/renderer/core/permissions_policy/` 目录下的源代码，包括 `document_policy_sim_test.cc`，来理解各种场景下的预期行为和测试覆盖范围。

总而言之，`document_policy_sim_test.cc` 是一个关键的测试文件，它确保了 Chromium Blink 引擎能够正确地解析、应用和执行文档策略，从而保证了 Web 页面的安全性和功能的一致性。通过模拟各种场景，它可以帮助开发者验证文档策略功能的正确性，并提供调试线索来定位与文档策略相关的问题。

Prompt: 
```
这是目录为blink/renderer/core/permissions_policy/document_policy_sim_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/permissions_policy/policy_disposition.mojom-blink.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/permissions_policy/policy_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

class DocumentPolicySimTest : public SimTest {
 public:
  DocumentPolicySimTest() { ResetAvailableDocumentPolicyFeaturesForTest(); }

 private:
  ScopedDocumentPolicyNegotiationForTest scoped_document_policy_negotiation_{
      true};
};

// When runtime feature DocumentPolicyNegotiation is not enabled, specifying
// Require-Document-Policy HTTP header and policy attribute on iframe should
// have no effect, i.e. document load should not be blocked even if the required
// policy and incoming policy are incompatible. Document-Policy header should
// function as normal.
TEST_F(DocumentPolicySimTest, DocumentPolicyNegotiationNoEffectWhenFlagNotSet) {
  ScopedDocumentPolicyNegotiationForTest sdpn(false);
  ResetAvailableDocumentPolicyFeaturesForTest();

  SimRequest::Params main_params;
  main_params.response_http_headers = {
      {"Require-Document-Policy", "force-load-at-top=?0"}};

  SimRequest::Params iframe_params;
  iframe_params.response_http_headers = {
      {"Document-Policy", "force-load-at-top"}};

  SimRequest main_resource("https://example.com", "text/html", main_params);
  SimRequest iframe_resource("https://example.com/foo.html", "text/html",
                             iframe_params);

  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe
      src="https://example.com/foo.html"
      policy="force-load-at-top=?0">
    </iframe>
  )");

  iframe_resource.Finish();
  auto* child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* child_window = child_frame->GetFrame()->DomWindow();
  auto& console_messages = static_cast<frame_test_helpers::TestWebFrameClient*>(
                               child_frame->Client())
                               ->ConsoleMessages();

  // Should not receive a console error message caused by document policy
  // violation blocking document load.
  EXPECT_TRUE(console_messages.empty());

  EXPECT_EQ(child_window->Url(), KURL("https://example.com/foo.html"));

  EXPECT_FALSE(child_window->document()->IsUseCounted(
      mojom::WebFeature::kDocumentPolicyCausedPageUnload));

  // force-load-at-top should be set to false in main document.
  EXPECT_FALSE(Window().IsFeatureEnabled(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop));

  // force-load-at-top should be set to true in child document.
  EXPECT_TRUE(child_window->IsFeatureEnabled(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop));
}

TEST_F(DocumentPolicySimTest, ReportDocumentPolicyHeaderParsingError) {
  SimRequest::Params params;
  params.response_http_headers = {{"Document-Policy", "bad-feature-name"}};
  SimRequest main_resource("https://example.com", "text/html", params);
  LoadURL("https://example.com");
  main_resource.Finish();

  EXPECT_EQ(ConsoleMessages().size(), 1u);
  EXPECT_TRUE(
      ConsoleMessages().front().StartsWith("Document-Policy HTTP header:"));
}

TEST_F(DocumentPolicySimTest, ReportRequireDocumentPolicyHeaderParsingError) {
  SimRequest::Params params;
  params.response_http_headers = {
      {"Require-Document-Policy", "bad-feature-name"}};
  SimRequest main_resource("https://example.com", "text/html", params);
  LoadURL("https://example.com");
  main_resource.Finish();

  EXPECT_EQ(ConsoleMessages().size(), 1u);
  EXPECT_TRUE(ConsoleMessages().front().StartsWith(
      "Require-Document-Policy HTTP header:"));
}

TEST_F(DocumentPolicySimTest, ReportErrorWhenDocumentPolicyIncompatible) {
  SimRequest::Params params;
  params.response_http_headers = {{"Document-Policy", "force-load-at-top"}};

  SimRequest main_resource("https://example.com", "text/html");
  SimRequest iframe_resource("https://example.com/foo.html", "text/html",
                             params);

  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe
      src="https://example.com/foo.html"
      policy="force-load-at-top=?0">
    </iframe>
  )");

  // When blocked by document policy, the document should be filled in with an
  // empty response, with Finish called on |navigation_body_loader| already.
  // If Finish was not called on the loader, because the document was not
  // blocked, this test will fail by crashing here.
  iframe_resource.Finish(true /* body_loader_finished */);

  auto* child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* child_document = child_frame->GetFrame()->GetDocument();

  // Should console log a error message.
  auto& console_messages = static_cast<frame_test_helpers::TestWebFrameClient*>(
                               child_frame->Client())
                               ->ConsoleMessages();

  ASSERT_EQ(console_messages.size(), 1u);
  EXPECT_TRUE(console_messages.front().Contains("document policy"));

  // Should replace the document's origin with an opaque origin.
  EXPECT_EQ(child_document->Url(), SecurityOrigin::UrlWithUniqueOpaqueOrigin());

  EXPECT_TRUE(child_document->IsUseCounted(
      mojom::WebFeature::kDocumentPolicyCausedPageUnload));
}

// HTTP header Require-Document-Policy should only take effect on subtree of
// current document, but not on current document.
TEST_F(DocumentPolicySimTest,
       RequireDocumentPolicyHeaderShouldNotAffectCurrentDocument) {
  SimRequest::Params params;
  params.response_http_headers = {{"Require-Document-Policy", "sync-xhr=?0"},
                                  {"Document-Policy", "force-load-at-top"}};

  SimRequest main_resource("https://example.com", "text/html", params);
  LoadURL("https://example.com");
  // If document is blocked by document policy because of incompatible document
  // policy, this test will fail by crashing here.
  main_resource.Finish();
}

TEST_F(DocumentPolicySimTest, DocumentPolicyHeaderHistogramTest) {
  base::HistogramTester histogram_tester;

  SimRequest::Params params;
  params.response_http_headers = {
      {"Document-Policy", "force-load-at-top, sync-xhr"}};

  SimRequest main_resource("https://example.com", "text/html", params);
  LoadURL("https://example.com");
  main_resource.Finish();

  histogram_tester.ExpectTotalCount("Blink.UseCounter.DocumentPolicy.Header",
                                    2);
  histogram_tester.ExpectBucketCount("Blink.UseCounter.DocumentPolicy.Header",
                                     3 /* kForceLoadAtTop */, 1);
  histogram_tester.ExpectBucketCount("Blink.UseCounter.DocumentPolicy.Header",
                                     12 /* kSyncXHR */, 1);
}

TEST_F(DocumentPolicySimTest, DocumentPolicyPolicyAttributeHistogramTest) {
  base::HistogramTester histogram_tester;

  SimRequest main_resource("https://example.com", "text/html");
  LoadURL("https://example.com");

  // Same feature should only be reported once in a document despite its
  // occurrence.
  main_resource.Complete(R"(
    <iframe policy="force-load-at-top"></iframe>
    <iframe policy="force-load-at-top=?0"></iframe>
    <iframe
      policy="force-load-at-top,sync-xhr=?0">
    </iframe>
  )");

  histogram_tester.ExpectTotalCount(
      "Blink.UseCounter.DocumentPolicy.PolicyAttribute", 2);
  histogram_tester.ExpectBucketCount(
      "Blink.UseCounter.DocumentPolicy.PolicyAttribute",
      3 /* kForceLoadAtTop */, 1);
  histogram_tester.ExpectBucketCount(
      "Blink.UseCounter.DocumentPolicy.PolicyAttribute", 12 /* kSyncXHR */, 1);
}

TEST_F(DocumentPolicySimTest, DocumentPolicyEnforcedReportHistogramTest) {
  base::HistogramTester histogram_tester;

  SimRequest main_resource("https://example.com", "text/html");
  LoadURL("https://example.com");
  main_resource.Finish();

  Window().ReportDocumentPolicyViolation(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop,
      mojom::blink::PolicyDisposition::kEnforce,
      "first fragment scroll violation");

  histogram_tester.ExpectTotalCount("Blink.UseCounter.DocumentPolicy.Enforced",
                                    1);
  histogram_tester.ExpectBucketCount("Blink.UseCounter.DocumentPolicy.Enforced",
                                     3 /* kForceLoadAtTop */, 1);

  // Multiple reports should be recorded multiple times.
  Window().ReportDocumentPolicyViolation(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop,
      mojom::blink::PolicyDisposition::kEnforce,
      "second fragment scroll violation");

  histogram_tester.ExpectTotalCount("Blink.UseCounter.DocumentPolicy.Enforced",
                                    2);
  histogram_tester.ExpectBucketCount("Blink.UseCounter.DocumentPolicy.Enforced",
                                     3 /* kForceLoadAtTop */, 2);
}

TEST_F(DocumentPolicySimTest, DocumentPolicyReportOnlyReportHistogramTest) {
  base::HistogramTester histogram_tester;

  SimRequest::Params params;
  params.response_http_headers = {
      {"Document-Policy-Report-Only", "force-load-at-top"}};
  SimRequest main_resource("https://example.com", "text/html", params);

  LoadURL("https://example.com");
  main_resource.Finish();

  Window().ReportDocumentPolicyViolation(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop,
      mojom::blink::PolicyDisposition::kReport,
      "first fragment scroll violation");

  histogram_tester.ExpectTotalCount(
      "Blink.UseCounter.DocumentPolicy.ReportOnly", 1);
  histogram_tester.ExpectBucketCount(
      "Blink.UseCounter.DocumentPolicy.ReportOnly", 3 /* kForceLoadAtTop */, 1);

  // Multiple reports should be recorded multiple times.
  Window().ReportDocumentPolicyViolation(
      mojom::blink::DocumentPolicyFeature::kForceLoadAtTop,
      mojom::blink::PolicyDisposition::kReport,
      "second fragment scroll violation");

  histogram_tester.ExpectTotalCount(
      "Blink.UseCounter.DocumentPolicy.ReportOnly", 2);
  histogram_tester.ExpectBucketCount(
      "Blink.UseCounter.DocumentPolicy.ReportOnly", 3 /* kForceLoadAtTop */, 2);
}

class DocumentPolicyHeaderUseCounterTest
    : public DocumentPolicySimTest,
      public testing::WithParamInterface<std::tuple<bool, bool, bool>> {};

TEST_P(DocumentPolicyHeaderUseCounterTest, ShouldObserveUseCounterUpdate) {
  bool has_document_policy_header, has_report_only_header, has_require_header;
  std::tie(has_document_policy_header, has_report_only_header,
           has_require_header) = GetParam();

  SimRequest::Params params;
  if (has_document_policy_header) {
    params.response_http_headers.insert("Document-Policy", "sync-xhr=?0");
  }
  if (has_report_only_header) {
    params.response_http_headers.insert("Document-Policy-Report-Only",
                                        "sync-xhr=?0");
  }
  if (has_require_header) {
    params.response_http_headers.insert("Require-Document-Policy",
                                        "sync-xhr=?0");
  }
  SimRequest main_resource("https://example.com", "text/html", params);
  LoadURL("https://example.com");
  main_resource.Complete();

  EXPECT_EQ(
      GetDocument().IsUseCounted(mojom::WebFeature::kDocumentPolicyHeader),
      has_document_policy_header);
  EXPECT_EQ(GetDocument().IsUseCounted(
                mojom::WebFeature::kDocumentPolicyReportOnlyHeader),
            has_report_only_header);
  EXPECT_EQ(GetDocument().IsUseCounted(
                mojom::WebFeature::kRequireDocumentPolicyHeader),
            has_require_header);
}

INSTANTIATE_TEST_SUITE_P(DocumentPolicyHeaderValues,
                         DocumentPolicyHeaderUseCounterTest,
                         ::testing::Combine(::testing::Bool(),
                                            ::testing::Bool(),
                                            ::testing::Bool()));

TEST_F(DocumentPolicySimTest,
       DocumentPolicyIframePolicyAttributeUseCounterTest) {
  SimRequest main_resource("https://example.com", "text/html");
  SimRequest::Params iframe_params;
  iframe_params.response_http_headers = {{"Document-Policy", "sync-xhr=?0"}};
  SimRequest iframe_resource("https://example.com/foo.html", "text/html",
                             iframe_params);
  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe
      src="https://example.com/foo.html"
      policy="sync-xhr=?0"
    ></iframe>
  )");
  iframe_resource.Finish();

  EXPECT_TRUE(GetDocument().IsUseCounted(
      mojom::WebFeature::kDocumentPolicyIframePolicyAttribute));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(mojom::WebFeature::kRequiredDocumentPolicy));

  auto* child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* child_document = child_frame->GetFrame()->GetDocument();

  EXPECT_FALSE(child_document->IsUseCounted(
      mojom::WebFeature::kDocumentPolicyIframePolicyAttribute));
  EXPECT_TRUE(
      child_document->IsUseCounted(mojom::WebFeature::kRequiredDocumentPolicy));
}

TEST_F(DocumentPolicySimTest, RequiredDocumentPolicyUseCounterTest) {
  SimRequest::Params main_frame_params;
  main_frame_params.response_http_headers = {
      {"Require-Document-Policy", "sync-xhr=?0"}};
  SimRequest main_resource("https://example.com", "text/html",
                           main_frame_params);

  SimRequest::Params iframe_params;
  iframe_params.response_http_headers = {{"Document-Policy", "sync-xhr=?0"}};
  SimRequest iframe_resource("https://example.com/foo.html", "text/html",
                             iframe_params);

  LoadURL("https://example.com");
  main_resource.Complete(R"(
    <iframe src="https://example.com/foo.html"></iframe>
  )");
  iframe_resource.Finish();

  EXPECT_FALSE(GetDocument().IsUseCounted(
      mojom::WebFeature::kDocumentPolicyIframePolicyAttribute));
  EXPECT_FALSE(
      GetDocument().IsUseCounted(mojom::WebFeature::kRequiredDocumentPolicy));

  auto* child_frame = To<WebLocalFrameImpl>(MainFrame().FirstChild());
  auto* child_document = child_frame->GetFrame()->GetDocument();

  EXPECT_FALSE(child_document->IsUseCounted(
      mojom::WebFeature::kDocumentPolicyIframePolicyAttribute));
  EXPECT_TRUE(
      child_document->IsUseCounted(mojom::WebFeature::kRequiredDocumentPolicy));
}

}  // namespace blink

"""

```