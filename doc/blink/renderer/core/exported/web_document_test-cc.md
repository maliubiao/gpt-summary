Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding - What is the Goal?**

The core task is to understand the functionality of `web_document_test.cc`. The file name strongly suggests it's a test suite for the `WebDocument` interface within the Blink rendering engine. The `#include` statements confirm this, showing dependencies on testing frameworks (`gtest`), core Blink classes (`WebDocument`, `Document`), and utility functions.

**2. High-Level Functionality Identification:**

By skimming the code and looking at the test case names (the `TEST_F` macros), I can quickly identify the main areas being tested:

* **Style Sheet Manipulation:**  `InsertAndRemoveStyleSheet` clearly tests the ability to dynamically add and remove CSS rules.
* **Origin Trials:** `OriginTrialDisabled` and `OriginTrialEnabled` are about verifying the behavior of origin trials, a mechanism to enable experimental web platform features.
* **First-Party Context:** The `WebDocumentFirstPartyTest` class and its tests (`Empty`, `NestedOriginA`, etc.) focus on how the browser determines if a document is in a first-party context, which is crucial for security and privacy (especially cookies).

**3. Detailed Analysis of Each Test Case:**

For each test case, I'd perform the following steps:

* **Understand the Setup:**  What does the `LoadURL` (or the specific loading methods in `WebDocumentFirstPartyTest`) do?  It's likely loading a specific HTML file into a test environment.
* **Identify Key Actions:** What are the core functions being called on the `WebDocument` object (`web_doc`) or the underlying `Document` object (`core_doc`)?  Examples: `InsertStyleSheet`, `RemoveInsertedStyleSheet`, `IsOriginTrialsSampleAPIEnabled`, `SiteForCookies`, `TopFrameOrigin`.
* **Analyze Assertions:** What are the `ASSERT_EQ`, `EXPECT_TRUE`, and `EXPECT_FALSE` statements checking?  These reveal the expected behavior of the functions under test.
* **Connect to Web Technologies:** How does this test relate to JavaScript, HTML, and CSS?  For example, inserting a stylesheet directly manipulates the CSSOM. First-party checks are essential for how JavaScript interacts with cookies and storage.

**4. Connecting to Web Technologies (Specific Examples):**

* **`InsertAndRemoveStyleSheet`:**
    * **CSS:** Directly inserts a CSS rule (`body { color: green }`).
    * **HTML:** Affects the rendering of HTML elements (the `body` in this case).
    * **JavaScript (Indirect):**  While not directly involved in *this* test, in a real web page, JavaScript could use methods like `document.styleSheets` or `element.style` to achieve similar effects. This test verifies the underlying mechanism.
* **Origin Trials:**
    * **JavaScript:**  Origin trials make experimental features available to JavaScript code. The `IsOriginTrialsSampleAPIEnabled` check confirms this.
    * **HTML (Indirect):** Origin trial tokens are often included in `<meta>` tags in the HTML. This test simulates the presence or absence of such a token.
* **First-Party Tests:**
    * **HTML:**  The tests load different HTML structures (nested iframes, different origins).
    * **JavaScript (Indirect):**  The concepts of same-origin policy and first-party/third-party context are fundamental to JavaScript security and how scripts from different domains can interact. These tests verify the underlying logic that determines these relationships.
    * **Cookies:** The `SiteForCookies` tests directly relate to how the browser determines which cookies to send with requests.

**5. Logic Inference and Assumptions:**

When analyzing the first-party tests, especially those with nested iframes, some logical deductions are necessary:

* **Assumption:** The test setup correctly simulates loading pages with different origins.
* **Inference:** The `SiteForCookies` and `TopFrameOrigin` properties are crucial for determining the security context of a document. Different embedding scenarios (same origin, cross-origin) lead to different values for these properties.

**6. Identifying Potential User Errors:**

Thinking about how developers might use these features incorrectly is important:

* **Incorrectly Assuming Synchronous Style Application:** The `InsertAndRemoveStyleSheet` test highlights that inserting/removing stylesheets is not immediately applied. Developers might make changes and expect them to be visible instantly.
* **Misunderstanding Origin Trial Scope:** Developers might incorrectly assume an origin trial applies to all subdomains or across different protocols (HTTP vs. HTTPS).
* **Cross-Origin Issues:** Developers might not fully grasp the implications of the same-origin policy when embedding content from different domains, leading to unexpected behavior with cookies, storage, and JavaScript access.

**7. Debugging Scenario:**

To understand how a user might end up in the code being tested, consider a scenario like investigating why a dynamically added stylesheet isn't being applied correctly:

1. **User Action:** A website user performs an action that triggers JavaScript code to insert a new stylesheet (e.g., changing a theme).
2. **Problem:** The visual change doesn't happen immediately.
3. **Developer Debugging:** The developer might use browser developer tools to inspect the DOM and CSSOM. They might then step through their JavaScript code, potentially noticing that the stylesheet was inserted but hasn't been applied.
4. **Hypothesis:**  The developer might suspect an issue with how Blink handles dynamic stylesheet insertion.
5. **Relevance of this Test:** The `InsertAndRemoveStyleSheet` test in `web_document_test.cc` verifies the asynchronous nature of stylesheet application and could provide insights into the expected behavior. The developer might even look at this test code to understand how Blink's internal APIs are used.

**Self-Correction/Refinement:**

During the analysis, I might realize I've made an incorrect assumption. For example, initially, I might think `SiteForCookies` is solely based on the document's origin. However, the tests with secure and insecure contexts demonstrate that the parent frame's security context also plays a role. This would require adjusting my understanding and explanations. Similarly, understanding the purpose of `schemefully_same` requires careful examination of the related tests.
这个文件 `blink/renderer/core/exported/web_document_test.cc` 是 Chromium Blink 引擎中的一个 **单元测试文件**。它的主要功能是 **测试 `blink::WebDocument` 接口的功能和行为**。`WebDocument` 是 Blink 引擎提供给外部（比如 Chromium Content 层）用于操作和访问文档的核心接口。

让我们详细列举一下它的功能，并分析它与 JavaScript, HTML, CSS 的关系，逻辑推理，常见错误以及调试线索：

**功能列举：**

1. **测试插入和移除样式表:**  `TEST_F(WebDocumentTest, InsertAndRemoveStyleSheet)` 测试了通过 `WebDocument::InsertStyleSheet()` 方法动态插入 CSS 样式表，以及通过 `WebDocument::RemoveInsertedStyleSheet()` 方法移除这些动态插入的样式表的功能。它验证了样式表插入和移除后，文档的样式是否会正确更新。

2. **测试 Origin Trial 功能是否生效:** `TEST_F(WebDocumentTest, OriginTrialDisabled)` 和 `TEST_F(WebDocumentTest, OriginTrialEnabled)` 测试了 Origin Trial (源试用) 功能。Origin Trial 是一种让开发者在生产环境中试用实验性 Web 平台特性的机制。测试用例分别验证了在没有 Origin Trial Token 和有有效 Origin Trial Token 的情况下，相关的 API 是否被启用。

3. **测试文档的第一方上下文 (First-Party Context):** `class WebDocumentFirstPartyTest` 及其相关的测试用例（例如 `TEST_F(WebDocumentFirstPartyTest, Empty)`, `TEST_F(WebDocumentFirstPartyTest, NestedOriginA)`, 等等）专注于测试 Blink 如何判断一个文档是否处于第一方上下文中。这对于安全性和隐私至关重要，特别是涉及到 Cookie 和存储的访问控制。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**
    * **插入和移除样式表:**  `InsertAndRemoveStyleSheet` 测试直接操作了 CSS 样式表。它使用 CSS 语法字符串 `"body { color: green }"` 来插入样式。这模拟了 JavaScript 中使用 `document.styleSheets` 或创建 `<style>` 元素并设置其内容来动态添加 CSS 的场景。
    * **样式计算:** 测试验证了插入和移除样式表后，文档中元素的计算样式是否会更新。例如，它检查了 `body` 元素的颜色是否从默认值变为绿色，然后再变回默认值。

* **HTML:**
    * **文档结构:**  测试用例通过加载不同的 HTML 文件 (`about:blank`, `simple_div.html`, 包含 iframe 的 HTML 文件等) 来模拟不同的文档结构。
    * **元素访问:**  测试代码会获取 HTML 元素 (例如 `core_doc->body()`) 并检查其样式。
    * **iframe:** `WebDocumentFirstPartyTest` 中的许多测试用例涉及到 iframe，用来测试不同 origin 的嵌套文档的 first-party 上下文判断。

* **JavaScript:**
    * **Origin Trials:** Origin Trial 允许 JavaScript 代码使用实验性的 API。测试用例 `OriginTrialEnabled` 验证了在启用 Origin Trial 的情况下，JavaScript 可以访问相应的 API (`WebOriginTrials::IsOriginTrialsSampleAPIEnabled`).
    * **文档操作:** 虽然这个测试文件本身不包含 JavaScript 代码，但它测试的 `WebDocument` 接口是 JavaScript 与浏览器渲染引擎交互的关键入口点。JavaScript 可以通过 `document` 对象（在 Blink 内部对应 `WebDocument`）来操作 DOM、CSSOM 等。

**逻辑推理 (假设输入与输出)：**

* **`InsertAndRemoveStyleSheet`:**
    * **假设输入:** 一个空白的 HTML 文档。
    * **操作:** 插入 CSS 规则 `"body { color: green }"`，然后移除它。
    * **预期输出:** 在插入后，`body` 元素的计算颜色为绿色；移除后，颜色恢复为默认值（黑色）。

* **`OriginTrialEnabled`:**
    * **假设输入:** 一个包含有效 Origin Trial meta 标签的 HTML 文件，例如：
      ```html
      <!DOCTYPE html>
      <html>
      <head>
          <meta http-equiv="origin-trial" content="YOUR_TRIAL_TOKEN">
      </head>
      <body>
          <div>Hello</div>
      </body>
      </html>
      ```
    * **操作:** 加载该 HTML 文件。
    * **预期输出:** `WebOriginTrials::IsOriginTrialsSampleAPIEnabled(&web_doc)` 返回 `true`。

* **`WebDocumentFirstPartyTest, NestedOriginAInOriginB`:**
    * **假设输入:**  一个 origin 为 `http://example.test:0/` 的 HTML 文件 (A)，其中包含一个 iframe，其 `src` 指向 origin 为 `http://not-example.test:0/` 的 HTML 文件 (B)，而 iframe B 中又包含一个 origin 为 `http://example.test:0/` 的 HTML 文件 (A)。
    * **操作:** 加载主 HTML 文件 A。
    * **预期输出:**
        * 主文档 (TopDocument) 的 `SiteForCookies` 与自身 origin 匹配。
        * 第一个 iframe (NestedDocument, origin B) 的 `SiteForCookies` 为 null (因为是跨域)。
        * 第二个 iframe (NestedNestedDocument, origin A) 的 `SiteForCookies` 也为 null (因为它被包含在跨域的 iframe 中)。
        * 所有文档的 `TopFrameOrigin` 都指向最顶层框架的 origin (A)。

**用户或编程常见的使用错误：**

* **未调用 `UpdateStyleAndLayoutTree()` 导致样式未立即生效:**  `InsertAndRemoveStyleSheet` 测试中明确指出，`InsertStyleSheet` 和 `RemoveInsertedStyleSheet` 不会同步触发样式重计算。开发者可能会错误地认为插入或移除样式后，页面会立即更新。他们需要显式调用某些触发布局更新的方法 (例如，通过修改 DOM 或访问布局相关的属性) 或者等待浏览器的下一次渲染周期。
* **Origin Trial Token 配置错误:**  开发者可能会在 HTML 中配置错误的 Origin Trial Token，导致实验性功能无法正确启用。
* **对 First-Party 上下文的误解:** 开发者可能不清楚浏览器如何判断 First-Party 上下文，导致在跨域 iframe 中出现意外的 Cookie 或存储访问限制。例如，他们可能认为只要是同一个顶级域名下的不同子域名就一定是 First-Party，但实际情况可能更复杂，需要考虑协议、端口等。
* **在异步操作后假设样式已更新:**  如果通过 JavaScript 异步地修改样式，开发者可能会在异步操作的回调函数中立即访问元素的计算样式，但此时样式可能尚未更新。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在使用一个网页时遇到了动态添加的样式没有立即生效的问题：

1. **用户操作:** 用户点击了一个按钮，或者触发了某个事件。
2. **JavaScript 执行:**  网页的 JavaScript 代码响应用户操作，调用了类似 `document.createElement('style')` 并设置了 CSS 规则，然后将其添加到 DOM 中。或者使用了类似 `element.style.property = value` 的方式修改样式。
3. **问题发生:** 用户期望页面立即发生视觉变化，但实际并没有。
4. **开发者介入调试:**
   * **查看开发者工具:** 开发者打开浏览器的开发者工具，检查元素的 computed style，发现样式规则确实被添加进去了。
   * **断点调试 JavaScript:** 开发者在 JavaScript 代码中设置断点，确认样式修改的代码被执行了。
   * **怀疑渲染流程:** 开发者开始怀疑浏览器的渲染流程，猜测可能是样式计算或布局更新没有及时发生。
   * **搜索相关资料:** 开发者可能会搜索 "CSS 样式不立即生效" 等关键词，了解到样式更新是异步的，可能需要手动触发布局。
   * **查看 Blink 源代码 (作为高级开发者或引擎开发者):** 如果开发者是 Chromium 或 Blink 的贡献者，或者需要深入理解渲染机制，他们可能会查看 Blink 相关的源代码，例如 `web_document_test.cc`，以了解 `WebDocument::InsertStyleSheet` 的行为和测试用例，从而更好地理解问题的本质和解决方案。`InsertAndRemoveStyleSheet` 测试用例会明确指出插入样式表不会立即触发同步的样式重计算，这会是一个重要的调试线索。

**总结：**

`web_document_test.cc` 是一个至关重要的测试文件，它确保了 `WebDocument` 接口的核心功能（包括样式表操作和 First-Party 上下文判断）的正确性。理解这个文件的内容可以帮助开发者更好地理解浏览器渲染引擎的工作原理，避免常见的错误，并为解决与文档操作、样式和安全相关的 Bug 提供调试线索。

### 提示词
```
这是目录为blink/renderer/core/exported/web_document_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/web/web_document.h"

#include <algorithm>
#include <string>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/origin_trials/scoped_test_origin_trial_policy.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/public/web/web_origin_trials.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

using blink::frame_test_helpers::WebViewHelper;
using blink::url_test_helpers::ToKURL;

const char kDefaultOrigin[] = "https://example.test/";
const char kOriginTrialTestFilePath[] = "origin-trial-enabled.html";
const char kNoOriginTrialTestFilePath[] = "simple_div.html";

class WebDocumentTest : public testing::Test {
 protected:
  static void SetUpTestSuite();

  void LoadURL(const std::string& url);
  Document* TopDocument() const;
  WebDocument TopWebDocument() const;

  test::TaskEnvironment task_environment_;
  WebViewHelper web_view_helper_;
};

void WebDocumentTest::SetUpTestSuite() {
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(std::string(kDefaultOrigin) + kNoOriginTrialTestFilePath),
      test::CoreTestDataPath(kNoOriginTrialTestFilePath));
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(std::string(kDefaultOrigin) + kOriginTrialTestFilePath),
      test::CoreTestDataPath(kOriginTrialTestFilePath));
}

void WebDocumentTest::LoadURL(const std::string& url) {
  web_view_helper_.InitializeAndLoad(url);
}

Document* WebDocumentTest::TopDocument() const {
  return To<LocalFrame>(web_view_helper_.GetWebView()->GetPage()->MainFrame())
      ->GetDocument();
}

WebDocument WebDocumentTest::TopWebDocument() const {
  return web_view_helper_.LocalMainFrame()->GetDocument();
}

TEST_F(WebDocumentTest, InsertAndRemoveStyleSheet) {
  LoadURL("about:blank");

  WebDocument web_doc = TopWebDocument();
  Document* core_doc = TopDocument();

  unsigned start_count = core_doc->GetStyleEngine().StyleForElementCount();

  WebStyleSheetKey style_sheet_key =
      web_doc.InsertStyleSheet("body { color: green }");

  // Check insertStyleSheet did not cause a synchronous style recalc.
  unsigned element_count =
      core_doc->GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  HTMLElement* body_element = core_doc->body();
  DCHECK(body_element);

  const ComputedStyle& style_before_insertion =
      body_element->ComputedStyleRef();

  // Inserted style sheet not yet applied.
  ASSERT_EQ(Color(0, 0, 0), style_before_insertion.VisitedDependentColor(
                                GetCSSPropertyColor()));

  // Apply inserted style sheet.
  core_doc->UpdateStyleAndLayoutTree();

  const ComputedStyle& style_after_insertion = body_element->ComputedStyleRef();

  // Inserted style sheet applied.
  ASSERT_EQ(Color(0, 128, 0),
            style_after_insertion.VisitedDependentColor(GetCSSPropertyColor()));

  start_count = core_doc->GetStyleEngine().StyleForElementCount();

  // Check RemoveInsertedStyleSheet did not cause a synchronous style recalc.
  web_doc.RemoveInsertedStyleSheet(style_sheet_key);
  element_count =
      core_doc->GetStyleEngine().StyleForElementCount() - start_count;
  ASSERT_EQ(0U, element_count);

  const ComputedStyle& style_before_removing = body_element->ComputedStyleRef();

  // Removed style sheet not yet applied.
  ASSERT_EQ(Color(0, 128, 0),
            style_before_removing.VisitedDependentColor(GetCSSPropertyColor()));

  // Apply removed style sheet.
  core_doc->UpdateStyleAndLayoutTree();

  const ComputedStyle& style_after_removing = body_element->ComputedStyleRef();
  ASSERT_EQ(Color(0, 0, 0),
            style_after_removing.VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(WebDocumentTest, OriginTrialDisabled) {
  blink::ScopedTestOriginTrialPolicy policy;

  // Load a document with no origin trial token.
  LoadURL(std::string(kDefaultOrigin) + kNoOriginTrialTestFilePath);
  WebDocument web_doc = TopWebDocument();
  EXPECT_FALSE(WebOriginTrials::IsOriginTrialsSampleAPIEnabled(&web_doc));
  EXPECT_FALSE(
      blink::WebRuntimeFeatures::IsOriginTrialsSampleAPIEnabledByRuntimeFlag());
}

TEST_F(WebDocumentTest, OriginTrialEnabled) {
  blink::ScopedTestOriginTrialPolicy policy;
  // Load a document with a valid origin trial token for the test trial.
  LoadURL(std::string(kDefaultOrigin) + kOriginTrialTestFilePath);
  WebDocument web_doc = TopWebDocument();
  // Verify the runtime feature is only enabled by the origin trial, not also by
  // the static flag.
  EXPECT_TRUE(WebOriginTrials::IsOriginTrialsSampleAPIEnabled(&web_doc));
  EXPECT_FALSE(
      blink::WebRuntimeFeatures::IsOriginTrialsSampleAPIEnabledByRuntimeFlag());
  // Ensure that other runtime features with origin trial configured are not
  // also enabled.
  EXPECT_FALSE(
      WebOriginTrials::IsOriginTrialsSampleAPIDeprecationEnabled(&web_doc));
  EXPECT_FALSE(WebRuntimeFeatures::
                   IsOriginTrialsSampleAPIDeprecationEnabledByRuntimeFlag());
}

namespace {

const char* g_base_url_origin_a = "http://example.test:0/";
const char* g_base_url_origin_sub_a = "http://subdomain.example.test:0/";
const char* g_base_url_origin_secure_a = "https://example.test:0/";
const char* g_base_url_origin_b = "http://not-example.test:0/";
const char* g_empty_file = "first_party/empty.html";
const char* g_nested_data = "first_party/nested-data.html";
const char* g_nested_origin_a = "first_party/nested-originA.html";
const char* g_nested_origin_sub_a = "first_party/nested-originSubA.html";
const char* g_nested_origin_secure_a = "first_party/nested-originSecureA.html";
const char* g_nested_origin_a_in_origin_a =
    "first_party/nested-originA-in-originA.html";
const char* g_nested_origin_a_in_origin_b =
    "first_party/nested-originA-in-originB.html";
const char* g_nested_origin_b = "first_party/nested-originB.html";
const char* g_nested_origin_b_in_origin_a =
    "first_party/nested-originB-in-originA.html";
const char* g_nested_origin_b_in_origin_b =
    "first_party/nested-originB-in-originB.html";
const char* g_nested_src_doc = "first_party/nested-srcdoc.html";

KURL ToFile(const char* file) {
  return ToKURL(std::string("file:///") + file);
}

KURL ToOriginA(const char* file) {
  return ToKURL(std::string(g_base_url_origin_a) + file);
}

KURL ToOriginSubA(const char* file) {
  return ToKURL(std::string(g_base_url_origin_sub_a) + file);
}

KURL ToOriginSecureA(const char* file) {
  return ToKURL(std::string(g_base_url_origin_secure_a) + file);
}

KURL ToOriginB(const char* file) {
  return ToKURL(std::string(g_base_url_origin_b) + file);
}

void RegisterMockedURLLoad(const KURL& url, const char* path) {
  url_test_helpers::RegisterMockedURLLoad(url, test::CoreTestDataPath(path));
}

}  // anonymous namespace

class WebDocumentFirstPartyTest : public WebDocumentTest {
 public:
  static void SetUpTestSuite();

 protected:
  void Load(const char*);
  Document* NestedDocument() const;
  Document* NestedNestedDocument() const;
};

void WebDocumentFirstPartyTest::SetUpTestSuite() {
  RegisterMockedURLLoad(ToOriginA(g_empty_file), g_empty_file);
  RegisterMockedURLLoad(ToOriginA(g_nested_data), g_nested_data);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_a), g_nested_origin_a);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_sub_a),
                        g_nested_origin_sub_a);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_secure_a),
                        g_nested_origin_secure_a);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_a_in_origin_a),
                        g_nested_origin_a_in_origin_a);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_a_in_origin_b),
                        g_nested_origin_a_in_origin_b);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_b), g_nested_origin_b);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_b_in_origin_a),
                        g_nested_origin_b_in_origin_a);
  RegisterMockedURLLoad(ToOriginA(g_nested_origin_b_in_origin_b),
                        g_nested_origin_b_in_origin_b);
  RegisterMockedURLLoad(ToOriginA(g_nested_src_doc), g_nested_src_doc);
  RegisterMockedURLLoad(ToOriginSubA(g_empty_file), g_empty_file);
  RegisterMockedURLLoad(ToOriginSecureA(g_empty_file), g_empty_file);
  RegisterMockedURLLoad(ToOriginB(g_empty_file), g_empty_file);
  RegisterMockedURLLoad(ToOriginB(g_nested_origin_a), g_nested_origin_a);
  RegisterMockedURLLoad(ToOriginB(g_nested_origin_b), g_nested_origin_b);

  RegisterMockedURLLoad(ToFile(g_nested_origin_a), g_nested_origin_a);
}

void WebDocumentFirstPartyTest::Load(const char* file) {
  web_view_helper_.InitializeAndLoad(std::string(g_base_url_origin_a) + file);
}

Document* WebDocumentFirstPartyTest::NestedDocument() const {
  return To<LocalFrame>(web_view_helper_.GetWebView()
                            ->GetPage()
                            ->MainFrame()
                            ->Tree()
                            .FirstChild())
      ->GetDocument();
}

Document* WebDocumentFirstPartyTest::NestedNestedDocument() const {
  return To<LocalFrame>(web_view_helper_.GetWebView()
                            ->GetPage()
                            ->MainFrame()
                            ->Tree()
                            .FirstChild()
                            ->Tree()
                            .FirstChild())
      ->GetDocument();
}

bool OriginsEqual(const char* path,
                  scoped_refptr<const SecurityOrigin> origin) {
  return SecurityOrigin::Create(ToOriginA(path))
      ->IsSameOriginWith(origin.get());
}

bool SiteForCookiesEqual(const char* path,
                         const net::SiteForCookies& site_for_cookies) {
  KURL ref_url = ToOriginA(path);
  ref_url.SetPort(80);  // url::Origin takes exception with :0.
  return net::SiteForCookies::FromUrl(GURL(ref_url))
      .IsEquivalent(site_for_cookies);
}

TEST_F(WebDocumentFirstPartyTest, Empty) {
  Load(g_empty_file);

  ASSERT_TRUE(
      SiteForCookiesEqual(g_empty_file, TopDocument()->SiteForCookies()));
  ASSERT_TRUE(OriginsEqual(g_empty_file, TopDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, EmptySandbox) {
  web_view_helper_.Initialize();
  WebLocalFrameImpl* frame = web_view_helper_.GetWebView()->MainFrameImpl();
  auto params =
      WebNavigationParams::CreateWithEmptyHTMLForTesting(KURL("https://a.com"));
  MockPolicyContainerHost mock_policy_container_host;
  params->policy_container = std::make_unique<blink::WebPolicyContainer>(
      blink::WebPolicyContainerPolicies(),
      mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
  params->policy_container->policies.sandbox_flags =
      network::mojom::blink::WebSandboxFlags::kAll;
  frame->CommitNavigation(std::move(params), nullptr /* extra_data */);
  frame_test_helpers::PumpPendingRequestsForFrameToLoad(frame);

  ASSERT_TRUE(TopDocument()->TopFrameOrigin()->IsOpaque())
      << TopDocument()->TopFrameOrigin()->ToUrlOrigin().GetDebugString();
  ASSERT_TRUE(TopDocument()->SiteForCookies().IsNull());
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginA) {
  Load(g_nested_origin_a);

  ASSERT_TRUE(
      SiteForCookiesEqual(g_nested_origin_a, TopDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a,
                                  NestedDocument()->SiteForCookies()));

  ASSERT_TRUE(OriginsEqual(g_nested_origin_a, TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(
      OriginsEqual(g_nested_origin_a, NestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginASchemefulSiteForCookies) {
  Load(g_nested_origin_a);

  // TopDocument is same scheme with itself so expect true.
  ASSERT_TRUE(TopDocument()->SiteForCookies().schemefully_same());
  // NestedDocument is same scheme with TopDocument so expect true.
  ASSERT_TRUE(NestedDocument()->SiteForCookies().schemefully_same());
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginSubA) {
  Load(g_nested_origin_sub_a);

  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_sub_a,
                                  TopDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_sub_a,
                                  NestedDocument()->SiteForCookies()));

  ASSERT_TRUE(
      OriginsEqual(g_nested_origin_sub_a, TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(
      OriginsEqual(g_nested_origin_sub_a, NestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginSecureA) {
  Load(g_nested_origin_secure_a);

  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_secure_a,
                                  TopDocument()->SiteForCookies()));
  // Since NestedDocument is secure, and the parent is insecure, its
  // SiteForCookies will be null and therefore will not match.
  ASSERT_FALSE(SiteForCookiesEqual(g_nested_origin_secure_a,
                                   NestedDocument()->SiteForCookies()));
  // However its site shouldn't be opaque
  ASSERT_FALSE(NestedDocument()->SiteForCookies().site().opaque());

  ASSERT_TRUE(
      OriginsEqual(g_nested_origin_secure_a, TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_secure_a,
                           NestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginSecureASchemefulSiteForCookies) {
  Load(g_nested_origin_secure_a);

  // TopDocument is same scheme with itself so expect true.
  ASSERT_TRUE(TopDocument()->SiteForCookies().schemefully_same());

  // Since NestedDocument is secure, and the parent is insecure, the scheme will
  // differ.
  ASSERT_FALSE(NestedDocument()->SiteForCookies().schemefully_same());
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginAInOriginA) {
  Load(g_nested_origin_a_in_origin_a);

  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a_in_origin_a,
                                  TopDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a_in_origin_a,
                                  NestedDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a_in_origin_a,
                                  NestedNestedDocument()->SiteForCookies()));

  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_a,
                           TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_a,
                           NestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginAInOriginB) {
  Load(g_nested_origin_a_in_origin_b);

  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a_in_origin_b,
                                  TopDocument()->SiteForCookies()));
  ASSERT_TRUE(NestedDocument()->SiteForCookies().IsNull());
  ASSERT_TRUE(NestedNestedDocument()->SiteForCookies().IsNull());

  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_b,
                           TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_b,
                           NestedDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_b,
                           NestedNestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginB) {
  Load(g_nested_origin_b);

  ASSERT_TRUE(
      SiteForCookiesEqual(g_nested_origin_b, TopDocument()->SiteForCookies()));
  ASSERT_TRUE(NestedDocument()->SiteForCookies().IsNull());

  ASSERT_TRUE(OriginsEqual(g_nested_origin_b, TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(
      OriginsEqual(g_nested_origin_b, NestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginBInOriginA) {
  Load(g_nested_origin_b_in_origin_a);

  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_b_in_origin_a,
                                  TopDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_b_in_origin_a,
                                  NestedDocument()->SiteForCookies()));
  ASSERT_TRUE(NestedNestedDocument()->SiteForCookies().IsNull());

  ASSERT_TRUE(OriginsEqual(g_nested_origin_b_in_origin_a,
                           TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_b_in_origin_a,
                           NestedDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_b_in_origin_a,
                           NestedNestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedOriginBInOriginB) {
  Load(g_nested_origin_b_in_origin_b);

  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_b_in_origin_b,
                                  TopDocument()->SiteForCookies()));
  ASSERT_TRUE(NestedDocument()->SiteForCookies().IsNull());
  ASSERT_TRUE(NestedNestedDocument()->SiteForCookies().IsNull());

  ASSERT_TRUE(OriginsEqual(g_nested_origin_b_in_origin_b,
                           TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_b_in_origin_b,
                           NestedDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_b_in_origin_b,
                           NestedNestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedSrcdoc) {
  Load(g_nested_src_doc);

  ASSERT_TRUE(
      SiteForCookiesEqual(g_nested_src_doc, TopDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_src_doc,
                                  NestedDocument()->SiteForCookies()));

  ASSERT_TRUE(OriginsEqual(g_nested_src_doc, TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(
      OriginsEqual(g_nested_src_doc, NestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, NestedData) {
  Load(g_nested_data);

  ASSERT_TRUE(
      SiteForCookiesEqual(g_nested_data, TopDocument()->SiteForCookies()));
  ASSERT_TRUE(NestedDocument()->SiteForCookies().IsNull());

  ASSERT_TRUE(OriginsEqual(g_nested_data, TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_data, NestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest,
       NestedOriginAInOriginBWithFirstPartyOverride) {
  Load(g_nested_origin_a_in_origin_b);

#if DCHECK_IS_ON()
  // TODO(crbug.com/1329535): Remove if threaded preload scanner doesn't launch.
  // This is needed because the preload scanner creates a thread when loading a
  // page.
  WTF::SetIsBeforeThreadCreatedForTest();
#endif
  SchemeRegistry::RegisterURLSchemeAsFirstPartyWhenTopLevel("http");

  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a_in_origin_b,
                                  TopDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a_in_origin_b,
                                  NestedDocument()->SiteForCookies()));
  ASSERT_TRUE(SiteForCookiesEqual(g_nested_origin_a_in_origin_b,
                                  NestedNestedDocument()->SiteForCookies()));

  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_b,
                           TopDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_b,
                           NestedDocument()->TopFrameOrigin()));
  ASSERT_TRUE(OriginsEqual(g_nested_origin_a_in_origin_b,
                           NestedNestedDocument()->TopFrameOrigin()));
}

TEST_F(WebDocumentFirstPartyTest, FileScheme) {
  web_view_helper_.InitializeAndLoad(std::string("file:///") +
                                     g_nested_origin_a);

  net::SiteForCookies top_site_for_cookies = TopDocument()->SiteForCookies();
  EXPECT_EQ("file", top_site_for_cookies.scheme());
  EXPECT_EQ("", top_site_for_cookies.registrable_domain());

  // Nested a.com is 3rd-party to file://
  EXPECT_TRUE(NestedDocument()->SiteForCookies().IsNull());
}

}  // namespace blink
```