Response:
The user wants me to analyze the provided C++ source code file (`document_test.cc`) from the Chromium Blink engine. Specifically, I need to:

1. **Summarize its functionality:** What does this test file do?
2. **Relate it to web technologies (JavaScript, HTML, CSS):** How does it test features related to these technologies? Provide examples.
3. **Provide logical reasoning with input/output examples:**  If the tests involve specific logic, demonstrate with hypothetical inputs and outputs.
4. **Identify common user/programming errors:** What mistakes might developers or users make that these tests are designed to catch?
5. **Explain how a user operation might lead to this code:**  What user actions in a browser might trigger the functionality being tested here?
6. **Indicate this is the first part of a three-part response.**

Let's break down the code snippet to address these points.

**Code Analysis:**

The file `document_test.cc` is a test file for the `Document` class in the Blink rendering engine. The include statements at the top provide strong clues about the areas being tested:

* **`#include "third_party/blink/renderer/core/dom/document.h"`**:  This is the core under test.
* **Testing Frameworks:** `#include "testing/gmock/include/gmock/gmock.h"`, `#include "testing/gtest/include/gtest/gtest.h"` indicate the use of Google Mock and Google Test for writing unit tests.
* **DOM-related headers:** Includes for `DocumentFragment`, `DOMException`, `DOMImplementation`, `Node`, `Range`, `Text`, `Element`, etc., suggest tests for DOM manipulation and interaction.
* **CSS-related headers:**  `MediaQueryListListener`, `MediaQueryMatcher` point to tests related to CSS media queries.
* **Frame-related headers:** Includes for `LocalDOMWindow`, `LocalFrameView`, `WebLocalFrameImpl` suggest tests involving the browser's frame structure.
* **HTML-related headers:**  `HTMLFormElement`, `HTMLInputElement`, `HTMLDialogElement`, `HTMLHeadElement`, `HTMLIFrameElement`, `HTMLLinkElement` indicate tests for specific HTML elements and their behavior.
* **Loader-related headers:** `DocumentLoader` suggests tests related to document loading.
* **Event Handling (implied):** While not explicitly included in this snippet, DOM manipulation often involves event handling, so it's likely tested.

**Planning the Response:**

I will organize the response according to the user's requests:

1. **Functionality Summary:** Start by stating that this file contains unit tests for the `Document` class in Blink. It focuses on testing various aspects of the DOM, document lifecycle, and interactions with other parts of the rendering engine.

2. **Relationship to Web Technologies:**
   * **HTML:**  Give examples of tests that manipulate HTML elements (creation, insertion, removal, attribute modification). Reference specific HTML elements mentioned in the includes (e.g., `iframe`, `link`, `div`, `span`).
   * **CSS:** Discuss tests related to CSS media queries, style updates, and how they affect the document. Mention the `MediaQueryListListener`.
   * **JavaScript:** Explain that while this is a C++ test file, the tested functionalities are often exposed and manipulated via JavaScript APIs. Provide examples of JavaScript actions that would trigger the underlying C++ code being tested (e.g., `document.createElement()`, `element.appendChild()`, accessing `document.documentElement.offsetWidth`).

3. **Logical Reasoning with Input/Output:**  Choose a specific test case from the code (e.g., the `LinkManifest` test) and illustrate the logic with example inputs (different `link` elements in the `<head>`) and expected outputs (`GetDocument().LinkManifest()` returning the correct link).

4. **Common Errors:**  Think about what can go wrong when developers work with the DOM:
   * Incorrectly manipulating the DOM, leading to unexpected behavior.
   * Issues with event handling.
   * Problems with CSS selectors and applying styles.
   * Errors in handling asynchronous operations related to document loading.

5. **User Operations and Debugging:** Describe user actions that would interact with the `Document` object:
   * Loading a web page.
   * Interacting with elements (clicking, typing).
   * Resizing the browser window (triggering media queries).
   * Using browser developer tools to inspect the DOM. Explain how a developer debugging an issue related to the DOM might end up looking at the C++ code being tested here (understanding the underlying implementation).

6. **Part 1 Summary:**  Reiterate that this part has focused on providing a general overview of the file's purpose and its connection to web technologies.

Now, let's generate the response following this plan.
这是 `blink/renderer/core/dom/document_test.cc` 文件的第一部分，它是一个 C++ 文件，属于 Chromium Blink 引擎的渲染模块。从代码内容来看，它的主要功能是**对 `blink::Document` 类进行单元测试**。

更具体地说，这个测试文件旨在验证 `Document` 类的各种功能和行为是否符合预期。它包含了多个独立的测试用例 (使用 Google Test 框架)，涵盖了 `Document` 类的不同方面，例如：

**功能归纳:**

* **DOM 树操作:** 测试文档的 DOM 树结构和操作，例如创建和移除节点、添加子节点、查找元素等。
* **文档属性和方法:** 测试 `Document` 类的各种属性（如 `URL`、`linkManifest`、`styleVersion`）和方法（如 `createRangeAdjustedToTreeScope`、`startPrinting`、`setMediaFeatureEvaluated`）。
* **生命周期管理:** 测试文档的生命周期事件和处理，例如文档的创建、关闭等。
* **与其他模块的交互:** 测试 `Document` 类与其他 Blink 引擎模块的交互，例如 CSS 样式计算、媒体查询处理、Frame 管理等。
* **同步突变观察器 (SynchronousMutationObserver):**  测试当 DOM 发生变化时，`Document` 如何通知注册的同步突变观察器。
* **打印功能:** 测试文档的打印相关功能，例如调整页面大小和布局。
* **安全策略 (implied):**  虽然在这个片段中没有直接体现，但测试 `Document` 可能会涉及到安全策略相关的方面。
* **特性检测 (Feature Detection):**  测试与特定 Web 平台特性相关的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`Document` 类是 Web 浏览器中最重要的概念之一，它代表了加载到窗口中的网页。因此，`document_test.cc` 中测试的许多功能都直接关系到 JavaScript, HTML, 和 CSS 的功能：

* **HTML:**
    * **功能关系:** `Document` 对象是 HTML 文档的根节点，负责管理和维护 HTML 结构。测试用例会创建和操作 HTML 元素（例如 `<div>`, `<span>`, `<iframe>`, `<link>` 等），验证 `Document` 对这些元素的操作是否正确。
    * **举例说明:**
        * `GetDocument().body()->setInnerHTML("<div>Hello</div>");`  这个测试片段模拟了 JavaScript 代码 `document.body.innerHTML = "<div>Hello</div>";`，测试 `Document` 如何处理 HTML 内容的设置。
        * `GetDocument().createElement('iframe');` (虽然是 C++ 代码，但对应 JavaScript 的 `document.createElement('iframe')`)，测试 `Document` 创建 HTML 元素的能力。
        * 测试 `GetDocument().LinkManifest()`  验证了 `Document` 如何根据 `<link rel="manifest">` 标签来确定 manifest 文件的 URL，这与 HTML 结构直接相关。

* **CSS:**
    * **功能关系:** `Document` 对象负责管理和应用 CSS 样式。测试用例会验证 `Document` 如何处理 CSS 规则的变化、媒体查询的匹配以及样式的更新。
    * **举例说明:**
        * `TEST_F(DocumentTest, StyleVersion)` 测试了当修改元素的 class 属性导致 CSS 样式变化时，`Document` 的 `StyleVersion` 是否会更新，这反映了 `Document` 对 CSS 变化的感知。
        * `TEST_F(DocumentTest, PrintRelayout)` 测试了媒体查询在打印场景下的应用，验证了 `Document` 如何根据媒体查询调整页面布局，这与 CSS 的 `@media` 规则密切相关。
        * `TEST_F(DocumentTest, MediaFeatureEvaluated)` 测试了 `Document` 如何记录媒体特性是否已被评估，这与 CSS 媒体查询的求值过程相关。

* **JavaScript:**
    * **功能关系:** JavaScript 代码通过 `document` 对象来访问和操作 HTML DOM 和 CSSOM (CSS Object Model)。`document_test.cc` 测试的许多 C++ 功能是 JavaScript API 的底层实现。
    * **举例说明:**
        * `document.createElement('div')`, `element.appendChild()`, `element.remove()` 等 JavaScript 代码的底层逻辑会在 `Document` 类的 C++ 代码中实现，而 `document_test.cc` 正是测试这些底层实现的正确性。
        * `document.querySelector('select')` 等 JavaScript 方法的实现也会在 `Document` 类中，`TEST_F(DocumentTest, CreateRangeAdjustedToTreeScopeWithPositionInShadowTree)` 间接测试了与元素查找相关的功能。
        * `document.body.normalize()` 的底层实现在 `Document` 中，`TEST_F(DocumentTest, SynchronousMutationNotifierMergeTextNodes)` 测试了 `normalize()` 方法触发的同步突变事件。

**逻辑推理 (假设输入与输出):**

以 `TEST_F(DocumentTest, LinkManifest)` 为例：

* **假设输入:**
  ```html
  <head>
    <link rel="stylesheet" href="style.css">
    <link rel="manifest" href="app.webmanifest">
  </head>
  ```
* **逻辑推理:**  `Document::LinkManifest()` 方法应该在解析 HTML 时找到 `<link rel="manifest" href="app.webmanifest">` 这个标签，并返回指向该元素的指针。
* **输出:** `GetDocument().LinkManifest()` 的返回值应该是指向 `<link rel="manifest" href="app.webmanifest">` 元素的指针。

再例如 `TEST_F(DocumentTest, StyleVersion)`：

* **假设输入:**
  ```html
  <style> .a { color: red; } </style>
  <div id="myDiv"></div>
  ```
  JavaScript 代码执行 `document.getElementById('myDiv').className = 'a';`
* **逻辑推理:**  当元素的 class 属性发生变化，导致应用的 CSS 规则也发生变化时，`Document` 的 `StyleVersion` 应该会递增。
* **输出:** 在设置 `className` 之前获取的 `GetDocument().StyleVersion()`  应该小于设置之后获取的 `GetDocument().StyleVersion()`。

**用户或编程常见的使用错误及举例说明:**

虽然这是底层 C++ 测试，但它间接反映了用户或开发者在使用 Web 技术时可能犯的错误：

* **DOM 操作错误:**
    * **错误:** 在 JavaScript 中错误地添加或删除 DOM 节点，导致页面结构混乱或出现错误。
    * **`document_test.cc` 中的体现:** 测试用例会模拟各种 DOM 操作（添加、删除、移动节点），确保 `Document` 对象在这些操作后能维持正确的 DOM 树状态，这可以帮助发现 Blink 引擎在处理非法 DOM 操作时的错误，从而避免用户代码出现类似问题。
* **CSS 规则错误:**
    * **错误:**  编写错误的 CSS 选择器或规则，导致样式没有正确应用或出现意外的效果。
    * **`document_test.cc` 中的体现:**  测试用例会通过修改元素的属性来触发 CSS 样式的重新计算，验证 `Document` 能正确处理 CSS 变化，这可以帮助发现 Blink 引擎在 CSS 样式计算方面的错误，从而确保即使开发者编写了一些边界情况的 CSS，也能得到预期的结果。
* **异步操作处理不当:** (虽然这个片段没有直接体现，但在其他 `document_test.cc` 的部分可能存在)
    * **错误:** 在 JavaScript 中进行异步操作（例如加载外部资源），但没有正确处理回调或 Promise，导致程序逻辑错误。
    * **`document_test.cc` 的潜在体现:**  可能会有测试用例模拟资源加载失败或延迟的情况，验证 `Document` 对象在这些异步场景下的行为是否正确。

**用户操作如何一步步的到达这里 (调试线索):**

当用户在浏览器中执行以下操作时，可能会触发 `blink::Document` 相关的代码执行，进而可能需要查看 `document_test.cc` 来进行调试：

1. **加载网页:** 当用户在地址栏输入 URL 或点击链接时，浏览器会解析 HTML 内容，创建 `Document` 对象，并构建 DOM 树。如果在构建过程中出现问题，开发者可能需要查看 `Document` 相关的代码。
2. **JavaScript 动态修改页面:** 用户与网页交互（例如点击按钮、输入文本），触发 JavaScript 代码修改 DOM 结构或 CSS 样式。如果修改后出现异常行为，开发者可能需要调试 `Document` 如何处理这些修改。
3. **使用浏览器开发者工具:** 开发者可以使用浏览器开发者工具检查 DOM 树、查看元素样式、执行 JavaScript 代码等。这些操作都会与 `Document` 对象进行交互。
4. **打印网页:** 用户点击打印按钮，浏览器会进入打印预览模式，`Document` 对象会参与页面布局和渲染的调整。如果打印效果不符合预期，开发者可能需要查看 `Document` 相关的打印代码。
5. **浏览器扩展或插件操作 DOM:**  浏览器扩展或插件可能会修改网页的 DOM 结构，如果出现问题，开发者可能需要查看 `Document` 如何处理这些外部修改。

**作为调试线索，当发现以下问题时，可能会需要查看 `document_test.cc`：**

* **DOM 结构异常:** 网页元素的层次结构不正确，元素丢失或位置错误。
* **样式应用错误:**  CSS 样式没有按预期应用，或者应用了错误的样式。
* **JavaScript 脚本错误:** JavaScript 代码在操作 DOM 或 CSS 时出现异常。
* **打印预览或打印输出错误:** 页面布局在打印时出现问题。
* **与特定 Web 平台特性相关的问题:**  例如，与 Manifest 文件处理、Service Worker 注册等相关的问题。

开发者如果怀疑 `blink::Document` 类的实现存在 bug，或者需要理解 `Document` 在特定场景下的行为，就会查看 `document_test.cc` 中的测试用例，了解其设计和预期行为，并通过运行相关的测试来验证代码的正确性。

**这是第1部分，共3部分，请归纳一下它的功能:**

总而言之，`blink/renderer/core/dom/document_test.cc` 的第一部分主要功能是**为 `blink::Document` 类提供基础的单元测试**，验证其核心的 DOM 管理、属性操作、生命周期管理以及与 HTML、CSS 交互等方面的功能是否正确。这些测试用例为确保 Blink 引擎中 `Document` 类的稳定性和可靠性提供了重要的保障。

### 提示词
```
这是目录为blink/renderer/core/dom/document_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (c) 2014, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/dom/document.h"

#include <algorithm>
#include <memory>

#include "base/time/time.h"
#include "build/build_config.h"
#include "components/ukm/test_ukm_recorder.h"
#include "services/network/public/mojom/referrer_policy.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/permissions_policy/document_policy_features.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/mojom/permissions_policy/permissions_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/renderer/bindings/core/v8/isolated_world_csp.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/css/media_query_list_listener.h"
#include "third_party/blink/renderer/core/css/media_query_matcher.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/dom_implementation.h"
#include "third_party/blink/renderer/core/dom/node_with_index.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/scripted_animation_controller.h"
#include "third_party/blink/renderer/core/dom/synchronous_mutation_observer.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/reporting_context.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_test_helpers.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/validation_message_client.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/mock_policy_container_host.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "url/url_util.h"

namespace blink {

using network::mojom::ContentSecurityPolicySource;
using network::mojom::ContentSecurityPolicyType;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::IsEmpty;

class DocumentTest : public PageTestBase {
 public:
  static void SimulateTrustTokenQueryAnswererConnectionError(
      Document* document) {
    document->TrustTokenQueryAnswererConnectionError();
  }

 protected:
  void TearDown() override {
    ThreadState::Current()->CollectAllGarbageForTesting();
    PageTestBase::TearDown();
  }

  void SetHtmlInnerHTML(const char*);

  // Note: callers must mock any urls that are referred to in `html_content`,
  // with the exception of foo.html, which can be assumed to be defined by this
  // function.
  // Note: callers must not use double-quotes in the `html_content` string,
  // since that will conflict with the srcdoc attribute assignment in the
  // javascript below.
  enum SandboxState { kIsSandboxed, kIsNotSandboxed };
  enum UseCountedExpectation { kIsUseCounted, kIsNotUseCounted };
  void NavigateSrcdocMaybeSandboxed(
      const String& base_url,
      const std::string& html_content,
      const SandboxState sandbox_state,
      const UseCountedExpectation use_counted_expectation) {
    WebURL mocked_mainframe_url =
        url_test_helpers::RegisterMockedURLLoadFromBase(
            base_url, test::CoreTestDataPath(),
            WebString::FromUTF8("foo.html"));

    frame_test_helpers::WebViewHelper web_view_helper;
    // Load a non-about:blank simple mainframe page.
    web_view_helper.InitializeAndLoad(mocked_mainframe_url.GetString().Utf8());

    WebLocalFrame* main_frame = web_view_helper.LocalMainFrame();
    const char js_template[] =
        R"( javascript:
            var frm = document.createElement('iframe');
            %s
            frm.srcdoc = "%s";
            document.body.appendChild(frm);
        )";
    frame_test_helpers::LoadFrame(
        main_frame,
        base::StringPrintf(
            js_template,
            sandbox_state == kIsSandboxed ? "frm.sandbox = '';" : "",
            html_content.c_str()));
    EXPECT_NE(nullptr, main_frame->FirstChild());
    WebLocalFrame* iframe = main_frame->FirstChild()->ToWebLocalFrame();

    Document* srcdoc_document = iframe->GetDocument();
    KURL url("about:srcdoc");
    EXPECT_EQ(url, srcdoc_document->Url());
    switch (use_counted_expectation) {
      case kIsUseCounted:
        EXPECT_TRUE(srcdoc_document->IsUseCounted(
            WebFeature::kSandboxedSrcdocFrameResolvesRelativeURL));
        break;
      case kIsNotUseCounted:
        EXPECT_FALSE(srcdoc_document->IsUseCounted(
            WebFeature::kSandboxedSrcdocFrameResolvesRelativeURL));
    }
    url_test_helpers::RegisterMockedURLUnregister(mocked_mainframe_url);
  }

  void NavigateWithSandbox(const KURL& url) {
    auto params = WebNavigationParams::CreateWithEmptyHTMLForTesting(url);
    MockPolicyContainerHost mock_policy_container_host;
    params->policy_container = std::make_unique<blink::WebPolicyContainer>(
        blink::WebPolicyContainerPolicies(),
        mock_policy_container_host.BindNewEndpointAndPassDedicatedRemote());
    params->policy_container->policies.sandbox_flags =
        network::mojom::blink::WebSandboxFlags::kAll;
    GetFrame().Loader().CommitNavigation(std::move(params),
                                         /*extra_data=*/nullptr);
    test::RunPendingTasks();
    ASSERT_EQ(url.GetString(), GetDocument().Url().GetString());
  }
};

void DocumentTest::SetHtmlInnerHTML(const char* html_content) {
  GetDocument().documentElement()->setInnerHTML(String::FromUTF8(html_content));
  UpdateAllLifecyclePhasesForTest();
}

class DocumentSimTest : public SimTest {};

namespace {

class TestSynchronousMutationObserver
    : public GarbageCollected<TestSynchronousMutationObserver>,
      public SynchronousMutationObserver {
 public:
  struct MergeTextNodesRecord : GarbageCollected<MergeTextNodesRecord> {
    Member<const Text> node_;
    Member<Node> node_to_be_removed_;
    unsigned offset_ = 0;

    MergeTextNodesRecord(const Text* node,
                         const NodeWithIndex& node_with_index,
                         unsigned offset)
        : node_(node),
          node_to_be_removed_(node_with_index.GetNode()),
          offset_(offset) {}

    void Trace(Visitor* visitor) const {
      visitor->Trace(node_);
      visitor->Trace(node_to_be_removed_);
    }
  };

  struct UpdateCharacterDataRecord
      : GarbageCollected<UpdateCharacterDataRecord> {
    Member<CharacterData> node_;
    unsigned offset_ = 0;
    unsigned old_length_ = 0;
    unsigned new_length_ = 0;

    UpdateCharacterDataRecord(CharacterData* node,
                              unsigned offset,
                              unsigned old_length,
                              unsigned new_length)
        : node_(node),
          offset_(offset),
          old_length_(old_length),
          new_length_(new_length) {}

    void Trace(Visitor* visitor) const { visitor->Trace(node_); }
  };

  explicit TestSynchronousMutationObserver(Document&);
  TestSynchronousMutationObserver(const TestSynchronousMutationObserver&) =
      delete;
  TestSynchronousMutationObserver& operator=(
      const TestSynchronousMutationObserver&) = delete;
  virtual ~TestSynchronousMutationObserver() = default;

  int CountContextDestroyedCalled() const {
    return on_document_shutdown_called_counter_;
  }

  const HeapVector<Member<const ContainerNode>>& ChildrenChangedNodes() const {
    return children_changed_nodes_;
  }

  const HeapVector<Member<MergeTextNodesRecord>>& MergeTextNodesRecords()
      const {
    return merge_text_nodes_records_;
  }

  const HeapVector<Member<const Node>>& MoveTreeToNewDocumentNodes() const {
    return move_tree_to_new_document_nodes_;
  }

  const HeapVector<Member<ContainerNode>>& RemovedChildrenNodes() const {
    return removed_children_nodes_;
  }

  const HeapVector<Member<Node>>& RemovedNodes() const {
    return removed_nodes_;
  }

  const HeapVector<Member<const Text>>& SplitTextNodes() const {
    return split_text_nodes_;
  }

  const HeapVector<Member<UpdateCharacterDataRecord>>&
  UpdatedCharacterDataRecords() const {
    return updated_character_data_records_;
  }

  void Trace(Visitor*) const override;

 private:
  // Implement |SynchronousMutationObserver| member functions.
  void ContextDestroyed() final;
  void DidChangeChildren(const ContainerNode&,
                         const ContainerNode::ChildrenChange&) final;
  void DidMergeTextNodes(const Text&, const NodeWithIndex&, unsigned) final;
  void DidMoveTreeToNewDocument(const Node& root) final;
  void DidSplitTextNode(const Text&) final;
  void DidUpdateCharacterData(CharacterData*,
                              unsigned offset,
                              unsigned old_length,
                              unsigned new_length) final;
  void NodeChildrenWillBeRemoved(ContainerNode&) final;
  void NodeWillBeRemoved(Node&) final;

  int on_document_shutdown_called_counter_ = 0;
  HeapVector<Member<const ContainerNode>> children_changed_nodes_;
  HeapVector<Member<MergeTextNodesRecord>> merge_text_nodes_records_;
  HeapVector<Member<const Node>> move_tree_to_new_document_nodes_;
  HeapVector<Member<ContainerNode>> removed_children_nodes_;
  HeapVector<Member<Node>> removed_nodes_;
  HeapVector<Member<const Text>> split_text_nodes_;
  HeapVector<Member<UpdateCharacterDataRecord>> updated_character_data_records_;
};

TestSynchronousMutationObserver::TestSynchronousMutationObserver(
    Document& document) {
  SetDocument(&document);
}

void TestSynchronousMutationObserver::ContextDestroyed() {
  ++on_document_shutdown_called_counter_;
}

void TestSynchronousMutationObserver::DidChangeChildren(
    const ContainerNode& container,
    const ContainerNode::ChildrenChange&) {
  children_changed_nodes_.push_back(&container);
}

void TestSynchronousMutationObserver::DidMergeTextNodes(
    const Text& node,
    const NodeWithIndex& node_with_index,
    unsigned offset) {
  merge_text_nodes_records_.push_back(
      MakeGarbageCollected<MergeTextNodesRecord>(&node, node_with_index,
                                                 offset));
}

void TestSynchronousMutationObserver::DidMoveTreeToNewDocument(
    const Node& root) {
  move_tree_to_new_document_nodes_.push_back(&root);
}

void TestSynchronousMutationObserver::DidSplitTextNode(const Text& node) {
  split_text_nodes_.push_back(&node);
}

void TestSynchronousMutationObserver::DidUpdateCharacterData(
    CharacterData* character_data,
    unsigned offset,
    unsigned old_length,
    unsigned new_length) {
  updated_character_data_records_.push_back(
      MakeGarbageCollected<UpdateCharacterDataRecord>(character_data, offset,
                                                      old_length, new_length));
}

void TestSynchronousMutationObserver::NodeChildrenWillBeRemoved(
    ContainerNode& container) {
  removed_children_nodes_.push_back(&container);
}

void TestSynchronousMutationObserver::NodeWillBeRemoved(Node& node) {
  removed_nodes_.push_back(&node);
}

void TestSynchronousMutationObserver::Trace(Visitor* visitor) const {
  visitor->Trace(children_changed_nodes_);
  visitor->Trace(merge_text_nodes_records_);
  visitor->Trace(move_tree_to_new_document_nodes_);
  visitor->Trace(removed_children_nodes_);
  visitor->Trace(removed_nodes_);
  visitor->Trace(split_text_nodes_);
  visitor->Trace(updated_character_data_records_);
  SynchronousMutationObserver::Trace(visitor);
}

class MockDocumentValidationMessageClient
    : public GarbageCollected<MockDocumentValidationMessageClient>,
      public ValidationMessageClient {
 public:
  MockDocumentValidationMessageClient() { Reset(); }
  void Reset() {
    show_validation_message_was_called = false;
    document_detached_was_called = false;
  }
  bool show_validation_message_was_called;
  bool document_detached_was_called;

  // ValidationMessageClient functions.
  void ShowValidationMessage(Element& anchor,
                             const String& main_message,
                             TextDirection,
                             const String& sub_message,
                             TextDirection) override {
    show_validation_message_was_called = true;
  }
  void HideValidationMessage(const Element& anchor) override {}
  bool IsValidationMessageVisible(const Element& anchor) override {
    return true;
  }
  void DocumentDetached(const Document&) override {
    document_detached_was_called = true;
  }
  void DidChangeFocusTo(const Element*) override {}
  void WillBeDestroyed() override {}

  // virtual void Trace(Visitor* visitor) const {
  // ValidationMessageClient::trace(visitor); }
};

class PrefersColorSchemeTestListener final : public MediaQueryListListener {
 public:
  void NotifyMediaQueryChanged() override { notified_ = true; }
  bool IsNotified() const { return notified_; }

 private:
  bool notified_ = false;
};

bool IsDOMException(ScriptState* script_state,
                    ScriptValue value,
                    DOMExceptionCode code) {
  auto* dom_exception =
      V8DOMException::ToWrappable(script_state->GetIsolate(), value.V8Value());
  if (!dom_exception)
    return false;

  // Unfortunately, it's not enough to check |dom_exception->code() == code|,
  // as DOMException::code is only populated for the DOMExceptionCodes with
  // "legacy code" numeric values.
  return dom_exception->name() == DOMException(code).name();
}
}  // anonymous namespace

TEST_F(DocumentTest, CreateRangeAdjustedToTreeScopeWithPositionInShadowTree) {
  GetDocument().body()->setInnerHTML("<div><select><option>012</option></div>");
  Element* const select_element =
      GetDocument().QuerySelector(AtomicString("select"));
  const Position& position =
      Position(*select_element->UserAgentShadowRoot(),
               select_element->UserAgentShadowRoot()->CountChildren());
  Range* const range =
      Document::CreateRangeAdjustedToTreeScope(GetDocument(), position);
  EXPECT_EQ(range->startContainer(), select_element->parentNode());
  EXPECT_EQ(static_cast<unsigned>(range->startOffset()),
            select_element->NodeIndex());
  EXPECT_TRUE(range->collapsed());
}

TEST_F(DocumentTest, DomTreeVersionForRemoval) {
  // ContainerNode::CollectChildrenAndRemoveFromOldParentWithCheck assumes this
  // behavior.
  Document& doc = GetDocument();
  {
    DocumentFragment* fragment = DocumentFragment::Create(doc);
    fragment->appendChild(
        MakeGarbageCollected<Element>(html_names::kDivTag, &doc));
    fragment->appendChild(
        MakeGarbageCollected<Element>(html_names::kSpanTag, &doc));
    uint64_t original_version = doc.DomTreeVersion();
    fragment->RemoveChildren();
    EXPECT_EQ(original_version + 1, doc.DomTreeVersion())
        << "RemoveChildren() should increase DomTreeVersion by 1.";
  }

  {
    DocumentFragment* fragment = DocumentFragment::Create(doc);
    Node* child = MakeGarbageCollected<Element>(html_names::kDivTag, &doc);
    child->appendChild(
        MakeGarbageCollected<Element>(html_names::kSpanTag, &doc));
    fragment->appendChild(child);
    uint64_t original_version = doc.DomTreeVersion();
    fragment->removeChild(child);
    EXPECT_EQ(original_version + 1, doc.DomTreeVersion())
        << "removeChild() should increase DomTreeVersion by 1.";
  }
}

// This tests that we properly resize and re-layout pages for printing in the
// presence of media queries effecting elements in a subtree layout boundary
TEST_F(DocumentTest, PrintRelayout) {
  SetHtmlInnerHTML(R"HTML(
    <style>
        div {
            width: 100px;
            height: 100px;
            overflow: hidden;
        }
        span {
            width: 50px;
            height: 50px;
        }
        @media screen {
            span {
                width: 20px;
            }
        }
    </style>
    <p><div><span></span></div></p>
  )HTML");
  gfx::SizeF page_size(400, 400);
  float maximum_shrink_ratio = 1.6;

  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size),
                                          maximum_shrink_ratio);
  EXPECT_EQ(GetDocument().documentElement()->OffsetWidth(), 400);
  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(GetDocument().documentElement()->OffsetWidth(), 800);
}

// This tests whether we properly set the bits for indicating if a media feature
// has been evaluated.
TEST_F(DocumentTest, MediaFeatureEvaluated) {
  GetDocument().SetMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kForcedColors));
  for (int i = 0; i < 64; i++) {
    if (i == static_cast<int>(
                 IdentifiableSurface::MediaFeatureName::kForcedColors)) {
      EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(i));
    } else {
      EXPECT_FALSE(GetDocument().WasMediaFeatureEvaluated(i));
    }
  }
  GetDocument().SetMediaFeatureEvaluated(
      static_cast<int>(IdentifiableSurface::MediaFeatureName::kAnyHover));
  for (int i = 0; i < 64; i++) {
    if ((i == static_cast<int>(
                  IdentifiableSurface::MediaFeatureName::kForcedColors)) ||
        (i ==
         static_cast<int>(IdentifiableSurface::MediaFeatureName::kAnyHover))) {
      EXPECT_TRUE(GetDocument().WasMediaFeatureEvaluated(i));
    } else {
      EXPECT_FALSE(GetDocument().WasMediaFeatureEvaluated(i));
    }
  }
}

// This test checks that Documunt::linkManifest() returns a value conform to the
// specification.
TEST_F(DocumentTest, LinkManifest) {
  // Test the default result.
  EXPECT_EQ(nullptr, GetDocument().LinkManifest());

  // Check that we use the first manifest with <link rel=manifest>
  auto* link = MakeGarbageCollected<HTMLLinkElement>(GetDocument(),
                                                     CreateElementFlags());
  link->setAttribute(blink::html_names::kRelAttr, AtomicString("manifest"));
  link->setAttribute(blink::html_names::kHrefAttr, AtomicString("foo.json"));
  GetDocument().head()->AppendChild(link);
  EXPECT_EQ(link, GetDocument().LinkManifest());

  auto* link2 = MakeGarbageCollected<HTMLLinkElement>(GetDocument(),
                                                      CreateElementFlags());
  link2->setAttribute(blink::html_names::kRelAttr, AtomicString("manifest"));
  link2->setAttribute(blink::html_names::kHrefAttr, AtomicString("bar.json"));
  GetDocument().head()->InsertBefore(link2, link);
  EXPECT_EQ(link2, GetDocument().LinkManifest());
  GetDocument().head()->AppendChild(link2);
  EXPECT_EQ(link, GetDocument().LinkManifest());

  // Check that crazy URLs are accepted.
  link->setAttribute(blink::html_names::kHrefAttr,
                     AtomicString("http:foo.json"));
  EXPECT_EQ(link, GetDocument().LinkManifest());

  // Check that empty URLs are accepted.
  link->setAttribute(blink::html_names::kHrefAttr, g_empty_atom);
  EXPECT_EQ(link, GetDocument().LinkManifest());

  // Check that URLs from different origins are accepted.
  link->setAttribute(blink::html_names::kHrefAttr,
                     AtomicString("http://example.org/manifest.json"));
  EXPECT_EQ(link, GetDocument().LinkManifest());
  link->setAttribute(blink::html_names::kHrefAttr,
                     AtomicString("http://foo.example.org/manifest.json"));
  EXPECT_EQ(link, GetDocument().LinkManifest());
  link->setAttribute(blink::html_names::kHrefAttr,
                     AtomicString("http://foo.bar/manifest.json"));
  EXPECT_EQ(link, GetDocument().LinkManifest());

  // More than one token in @rel is accepted.
  link->setAttribute(blink::html_names::kRelAttr,
                     AtomicString("foo bar manifest"));
  EXPECT_EQ(link, GetDocument().LinkManifest());

  // Such as spaces around the token.
  link->setAttribute(blink::html_names::kRelAttr, AtomicString(" manifest "));
  EXPECT_EQ(link, GetDocument().LinkManifest());

  // Check that rel=manifest actually matters.
  link->setAttribute(blink::html_names::kRelAttr, g_empty_atom);
  EXPECT_EQ(link2, GetDocument().LinkManifest());
  link->setAttribute(blink::html_names::kRelAttr, AtomicString("manifest"));

  // Check that link outside of the <head> are ignored.
  GetDocument().head()->RemoveChild(link);
  GetDocument().head()->RemoveChild(link2);
  EXPECT_EQ(nullptr, GetDocument().LinkManifest());
  GetDocument().body()->AppendChild(link);
  EXPECT_EQ(nullptr, GetDocument().LinkManifest());
  GetDocument().head()->AppendChild(link);
  GetDocument().head()->AppendChild(link2);

  // Check that some attribute values do not have an effect.
  link->setAttribute(blink::html_names::kCrossoriginAttr,
                     AtomicString("use-credentials"));
  EXPECT_EQ(link, GetDocument().LinkManifest());
  link->setAttribute(blink::html_names::kHreflangAttr, AtomicString("klingon"));
  EXPECT_EQ(link, GetDocument().LinkManifest());
  link->setAttribute(blink::html_names::kTypeAttr, AtomicString("image/gif"));
  EXPECT_EQ(link, GetDocument().LinkManifest());
  link->setAttribute(blink::html_names::kSizesAttr, AtomicString("16x16"));
  EXPECT_EQ(link, GetDocument().LinkManifest());
  link->setAttribute(blink::html_names::kMediaAttr, AtomicString("print"));
  EXPECT_EQ(link, GetDocument().LinkManifest());
}

TEST_F(DocumentTest, StyleVersion) {
  SetHtmlInnerHTML(R"HTML(
    <style>
        .a * { color: green }
        .b .c { color: green }
    </style>
    <div id='x'><span class='c'></span></div>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("x"));
  EXPECT_TRUE(element);

  uint64_t previous_style_version = GetDocument().StyleVersion();
  element->setAttribute(blink::html_names::kClassAttr,
                        AtomicString("notfound"));
  EXPECT_EQ(previous_style_version, GetDocument().StyleVersion());

  UpdateAllLifecyclePhasesForTest();

  previous_style_version = GetDocument().StyleVersion();
  element->setAttribute(blink::html_names::kClassAttr, AtomicString("a"));
  EXPECT_NE(previous_style_version, GetDocument().StyleVersion());

  UpdateAllLifecyclePhasesForTest();

  previous_style_version = GetDocument().StyleVersion();
  element->setAttribute(blink::html_names::kClassAttr, AtomicString("a b"));
  EXPECT_NE(previous_style_version, GetDocument().StyleVersion());
}

TEST_F(DocumentTest, SynchronousMutationNotifier) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());

  EXPECT_EQ(GetDocument(), observer.GetDocument());
  EXPECT_EQ(0, observer.CountContextDestroyedCalled());

  Element* div_node = GetDocument().CreateRawElement(html_names::kDivTag);
  GetDocument().body()->AppendChild(div_node);

  Element* bold_node = GetDocument().CreateRawElement(html_names::kBTag);
  div_node->AppendChild(bold_node);

  Element* italic_node = GetDocument().CreateRawElement(html_names::kITag);
  div_node->AppendChild(italic_node);

  Node* text_node = GetDocument().createTextNode("0123456789");
  bold_node->AppendChild(text_node);
  EXPECT_TRUE(observer.RemovedNodes().empty());

  text_node->remove();
  ASSERT_EQ(1u, observer.RemovedNodes().size());
  EXPECT_EQ(text_node, observer.RemovedNodes()[0]);

  div_node->RemoveChildren();
  EXPECT_EQ(1u, observer.RemovedNodes().size())
      << "ContainerNode::removeChildren() doesn't call nodeWillBeRemoved()";
  ASSERT_EQ(1u, observer.RemovedChildrenNodes().size());
  EXPECT_EQ(div_node, observer.RemovedChildrenNodes()[0]);

  GetDocument().Shutdown();
  EXPECT_EQ(nullptr, observer.GetDocument());
  EXPECT_EQ(1, observer.CountContextDestroyedCalled());
}

TEST_F(DocumentTest, SynchronousMutationNotifieAppendChild) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());
  GetDocument().body()->AppendChild(GetDocument().createTextNode("a123456789"));
  ASSERT_EQ(1u, observer.ChildrenChangedNodes().size());
  EXPECT_EQ(GetDocument().body(), observer.ChildrenChangedNodes()[0]);
}

TEST_F(DocumentTest, SynchronousMutationNotifieInsertBefore) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());
  GetDocument().documentElement()->InsertBefore(
      GetDocument().createTextNode("a123456789"), GetDocument().body());
  ASSERT_EQ(1u, observer.ChildrenChangedNodes().size());
  EXPECT_EQ(GetDocument().documentElement(),
            observer.ChildrenChangedNodes()[0]);
}

TEST_F(DocumentTest, SynchronousMutationNotifierMergeTextNodes) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());

  Text* merge_sample_a = GetDocument().createTextNode("a123456789");
  GetDocument().body()->AppendChild(merge_sample_a);

  Text* merge_sample_b = GetDocument().createTextNode("b123456789");
  GetDocument().body()->AppendChild(merge_sample_b);

  EXPECT_EQ(0u, observer.MergeTextNodesRecords().size());
  GetDocument().body()->normalize();

  ASSERT_EQ(1u, observer.MergeTextNodesRecords().size());
  EXPECT_EQ(merge_sample_a, observer.MergeTextNodesRecords()[0]->node_);
  EXPECT_EQ(merge_sample_b,
            observer.MergeTextNodesRecords()[0]->node_to_be_removed_);
  EXPECT_EQ(10u, observer.MergeTextNodesRecords()[0]->offset_);
}

TEST_F(DocumentTest, SynchronousMutationNotifierMoveTreeToNewDocument) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());

  Node* move_sample = GetDocument().CreateRawElement(html_names::kDivTag);
  move_sample->appendChild(GetDocument().createTextNode("a123"));
  move_sample->appendChild(GetDocument().createTextNode("b456"));
  GetDocument().body()->AppendChild(move_sample);

  ScopedNullExecutionContext execution_context;
  Document& another_document =
      *Document::CreateForTest(execution_context.GetExecutionContext());
  another_document.AppendChild(move_sample);

  EXPECT_EQ(1u, observer.MoveTreeToNewDocumentNodes().size());
  EXPECT_EQ(move_sample, observer.MoveTreeToNewDocumentNodes()[0]);
}

TEST_F(DocumentTest, SynchronousMutationNotifieRemoveChild) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());
  GetDocument().documentElement()->RemoveChild(GetDocument().body());
  ASSERT_EQ(1u, observer.ChildrenChangedNodes().size());
  EXPECT_EQ(GetDocument().documentElement(),
            observer.ChildrenChangedNodes()[0]);
}

TEST_F(DocumentTest, SynchronousMutationNotifieReplaceChild) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());
  Element* const replaced_node = GetDocument().body();
  GetDocument().documentElement()->ReplaceChild(
      GetDocument().CreateRawElement(html_names::kDivTag),
      GetDocument().body());
  ASSERT_EQ(2u, observer.ChildrenChangedNodes().size());
  EXPECT_EQ(GetDocument().documentElement(),
            observer.ChildrenChangedNodes()[0]);
  EXPECT_EQ(GetDocument().documentElement(),
            observer.ChildrenChangedNodes()[1]);

  ASSERT_EQ(1u, observer.RemovedNodes().size());
  EXPECT_EQ(replaced_node, observer.RemovedNodes()[0]);
}

TEST_F(DocumentTest, SynchronousMutationNotifierSplitTextNode) {
  V8TestingScope scope;
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());

  Text* split_sample = GetDocument().createTextNode("0123456789");
  GetDocument().body()->AppendChild(split_sample);

  split_sample->splitText(4, ASSERT_NO_EXCEPTION);
  ASSERT_EQ(1u, observer.SplitTextNodes().size());
  EXPECT_EQ(split_sample, observer.SplitTextNodes()[0]);
}

TEST_F(DocumentTest, SynchronousMutationNotifierUpdateCharacterData) {
  auto& observer =
      *MakeGarbageCollected<TestSynchronousMutationObserver>(GetDocument());

  Text* append_sample = GetDocument().createTextNode("a123456789");
  GetDocument().body()->AppendChild(append_sample);

  Text* delete_sample = GetDocument().createTextNode("b123456789");
  GetDocument().body()->AppendChild(delete_sample);

  Text* insert_sample = GetDocument().createTextNode("c123456789");
  GetDocument().body()->AppendChild(insert_sample);

  Text* replace_sample = GetDocument().createTextNode("c123456789");
  GetDocument().body()->AppendChild(replace_sample);

  EXPECT_EQ(0u, observer.UpdatedCharacterDataRecords().size());

  append_sample->appendData("abc");
  ASSERT_EQ(1u, observer.UpdatedCharacterDataRecords().size());
  EXPECT_EQ(append_sample, observer.UpdatedCharacterDataRecords()[0]->node_);
  EXPECT_EQ(10u, observer.UpdatedCharacterDataRecords()[0]->offset_);
  EXPECT_EQ(0u, observer.UpdatedCharacterDataRecords()[0]->old_length_);
  EXPECT_EQ(3u, observer.UpdatedCharacterDataRecords()[0]->new_length_);

  delete_sample->deleteData(3, 4, ASSERT_NO_EXCEPTION);
  ASSERT_EQ(2u, observer.UpdatedCharacterDataRecords().size());
  EXPECT_EQ(delete_sample, observer.
```