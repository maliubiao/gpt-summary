Response:
Let's break down the thought process to analyze the provided C++ test file.

1. **Understand the Goal:** The primary goal is to analyze a specific Chromium Blink engine source file (`ax_object_cache_test.cc`) and explain its functionality, relate it to web technologies (JavaScript, HTML, CSS), provide examples, explore potential user/programming errors, and describe how a user might trigger this code.

2. **Initial Scan and Keyword Spotting:**  Quickly skim the code for key terms and patterns. Words like "test," "Accessibility," "AXObjectCache," "IsARIAWidget," "Histogram," "ViewTransition," "PseudoElement,"  "HTML," and function names like `SetBodyInnerHTML`, `GetElementById`, `DeferTreeUpdate` stand out. The presence of `TEST_F` strongly indicates unit tests. Includes like `<gtest/gtest.h>` confirm this.

3. **Identify the Core Functionality:** The filename `ax_object_cache_test.cc` and the presence of `AXObjectCache` strongly suggest this file tests the `AXObjectCache` class. Accessibility-related terms confirm this. The core functionality being tested likely involves how Blink's accessibility tree (represented by `AXObject`s) is managed and updated.

4. **Analyze Individual Tests:** Examine each `TEST_F` block:

    * **`IsARIAWidget`:**  This test checks a function related to ARIA attributes and whether elements are considered "widgets" for accessibility purposes. It uses HTML snippets and `EXPECT_TRUE`/`EXPECT_FALSE` to verify the behavior based on roles and ARIA attributes. This directly links to HTML and ARIA concepts.

    * **`HistogramTest`:** This test focuses on performance metrics. It manipulates the `AXObjectCache` and uses `base::HistogramTester` to verify that specific histograms related to snapshotting and incremental updates are recorded correctly. While not directly tied to HTML/CSS rendering, it's about the efficiency of the accessibility tree generation process, which is triggered by changes in the DOM (HTML/CSS).

    * **`RemoveReferencesToAXID`:** This test deals with internal management of `AXObject` IDs, specifically related to fixed or sticky positioned elements. It demonstrates how the cache handles removing references. This is more about internal implementation details but can be triggered by HTML/CSS positioning.

    * **`PauseUpdatesAfterMaxNumberQueued`:** This test explores the mechanism to prevent excessive accessibility updates. It uses a mock object to simulate rapid changes and verifies that updates are paused after a certain threshold. This relates to performance optimization when dealing with dynamic content changes driven by JavaScript or DOM manipulation.

    * **`UpdateAXForAllDocumentsAfterPausedUpdates`:** This test checks the recovery mechanism after updates have been paused. It ensures that a full update can be triggered. This is also related to performance and ensuring consistency.

    * **`AXViewTransitionTest`:** This test focuses on the interaction between accessibility and View Transitions (a newer web platform feature). It examines whether pseudo-elements created during view transitions are considered relevant for accessibility. This directly relates to CSS (view-transition-name) and JavaScript (the View Transitions API).

    * **`AccessibilityEnabledLaterTest`:** This test explores the scenario where accessibility is enabled after the initial page load. It specifically tests if CSS anchor positioning works correctly in this situation. This connects to CSS anchor properties.

5. **Relate to JavaScript, HTML, CSS:**  For each test, think about how user actions or web technologies would interact with the tested functionality:

    * **HTML:**  The structure of the page, elements, attributes (especially `role` and ARIA attributes), and IDs are directly used in the tests.
    * **CSS:**  Styling, especially properties like `position: fixed`, `view-transition-name`, and anchor positioning properties, influence the accessibility tree and are tested.
    * **JavaScript:** While not explicitly using JavaScript *code* within the tests, the tests simulate scenarios where JavaScript might dynamically modify the DOM, triggering accessibility updates. The `AXViewTransitionTest` directly uses the JavaScript View Transitions API.

6. **Logical Reasoning and Examples:** For tests involving specific logic (like `IsARIAWidget`), create hypothetical inputs (HTML snippets) and predict the outputs (the boolean result of the tested function).

7. **Identify Potential Errors:** Think about what could go wrong in web development that would expose issues tested by this code:

    * Incorrect use of ARIA attributes.
    * Performance problems with frequent DOM updates.
    * Issues with accessibility not being correctly initialized.
    * Unexpected behavior with newer features like View Transitions.

8. **Trace User Actions:**  Consider how a user's interaction with a web page could lead to the execution of this code:

    * Loading a page with ARIA attributes.
    * Interacting with interactive elements (buttons, etc.).
    * Dynamic content updates on a page.
    * Using browser developer tools to inspect accessibility information.
    * Navigating between pages using View Transitions.
    * Enabling accessibility features in the operating system *after* a page has loaded.

9. **Structure the Explanation:** Organize the findings into clear sections as requested by the prompt:

    * Functionality of the file.
    * Relationship to JavaScript, HTML, CSS with examples.
    * Logical reasoning with input/output.
    * Common user/programming errors.
    * User actions as debugging clues.

10. **Refine and Review:**  Read through the explanation, ensuring clarity, accuracy, and completeness. Check that the examples are relevant and easy to understand. Make sure the language is precise and avoids jargon where possible.

By following this systematic process, one can thoroughly analyze and explain the purpose and relevance of a complex source code file like `ax_object_cache_test.cc`.
这个文件 `blink/renderer/modules/accessibility/ax_object_cache_test.cc` 是 Chromium Blink 引擎中负责测试 `AXObjectCache` 类的代码。 `AXObjectCache` 是 Blink 中负责管理和维护 accessibility 树（也称为辅助功能树）的核心组件。辅助功能树是网页内容的结构化表示，用于向辅助技术（如屏幕阅读器）提供信息，使残障人士能够访问网页内容。

**主要功能：**

1. **测试 `AXObjectCache` 的核心功能:** 该文件包含了多个单元测试，用于验证 `AXObjectCache` 的各种功能是否正常工作。这包括：
    * **判断元素是否为 ARIA 部件:**  `IsARIAWidget` 测试用例检查了 `AXObjectCache::IsInsideFocusableElementOrARIAWidget` 函数，该函数用于判断一个元素是否是可聚焦元素或具有 ARIA widget 角色。
    * **性能指标记录:** `HistogramTest` 测试用例验证了在创建和更新辅助功能树时，是否正确记录了性能指标（例如，快照和增量更新的耗时）。
    * **管理固定或粘性定位元素的引用:** `RemoveReferencesToAXID` 测试用例检查了 `AXObjectCache` 如何管理对固定（`position: fixed`）或粘性（`position: sticky`）定位元素的引用，以确保在元素被移除时清理相应的缓存。
    * **限制辅助功能更新的频率:** `PauseUpdatesAfterMaxNumberQueued` 和 `UpdateAXForAllDocumentsAfterPausedUpdates` 测试用例验证了 `AXObjectCache` 如何处理大量的辅助功能更新请求，防止性能问题，并在暂停更新后能够恢复并完成更新。
    * **与 View Transitions 的交互:** `AXViewTransitionTest` 测试用例测试了在发生 View Transitions (视图过渡) 时，辅助功能树的更新情况，特别是对于 View Transitions 创建的伪元素是否被正确处理。
    * **延迟启用辅助功能的情况:** `AccessibilityEnabledLaterTest` 测试用例检查了在页面加载后才启用辅助功能的情况下，`AXObjectCache` 是否能正确建立辅助功能树，例如处理 CSS 锚点定位。

**与 JavaScript, HTML, CSS 的关系：**

`AXObjectCache` 的功能与 JavaScript, HTML, CSS 密切相关，因为它负责将这些技术所描述的网页内容转化为辅助技术可以理解的结构化信息。

* **HTML:**
    * **结构和语义:** `AXObjectCache` 解析 HTML 结构，例如 `<div>`, `<span>`, `<button>` 等元素，并根据元素的语义和属性创建 `AXObject` 对象。
    * **ARIA 属性:**  `AXObjectCache` 识别和处理 ARIA (Accessible Rich Internet Applications) 属性，如 `role`, `aria-label`, `aria-selected`, `aria-haspopup` 等，这些属性增强了 HTML 的可访问性。例如，`IsARIAWidget` 测试用例就演示了如何通过 `role="button"` 将一个 `<span>` 元素标记为按钮，使其在辅助功能树中被识别为交互式控件。
    * **元素 ID:**  测试用例中经常使用 `getElementById` 来获取 HTML 元素，并基于这些元素创建 `AXObject` 进行测试。例如，`RemoveReferencesToAXID` 使用了具有 `id="f"` 的 `<div>` 元素来测试固定定位元素的处理。

    **举例:**  `IsARIAWidget` 测试中，HTML 代码定义了不同类型的 `<span>` 元素，有些带有 `role` 属性，有些带有 ARIA 属性，测试用例通过 `AXObjectCache::IsInsideFocusableElementOrARIAWidget` 函数来判断这些元素是否被认为是 ARIA 部件。

* **CSS:**
    * **视觉呈现和语义的区分:** `AXObjectCache` 需要区分元素的视觉呈现（由 CSS 控制）和其语义角色。例如，一个 `<div>` 元素可能通过 CSS 看上去像一个按钮，但除非它具有相应的 ARIA `role` 属性，否则在辅助功能树中不会被识别为按钮。
    * **定位属性:** `RemoveReferencesToAXID` 测试用例涉及 `position: fixed` 属性。`AXObjectCache` 需要跟踪固定定位的元素，因为它们在滚动时保持在屏幕上的固定位置，这对于辅助技术理解页面布局很重要。
    * **View Transitions:** `AXViewTransitionTest` 测试了与 CSS View Transitions 的交互。当页面内容发生变化且使用了 View Transitions 时，会创建一些特殊的伪元素（如 `::view-transition`, `::view-transition-group` 等）。测试用例验证了这些伪元素在辅助功能树中的相关性。
    * **CSS 锚点定位:** `AccessibilityEnabledLaterTest` 测试了 CSS 锚点定位 (`anchor-name`, `position-anchor`)，验证了即使在辅助功能稍后启用的情况下，`AXObjectCache` 也能正确建立锚点关系。

    **举例:** `AXViewTransitionTest` 测试中，CSS 代码定义了一个具有 `view-transition-name` 属性的 `<div>` 元素。当发生视图过渡时，会创建与该名称相关的伪元素，测试用例验证了 `AXObjectCacheImpl::IsRelevantPseudoElement` 函数对于这些伪元素的返回值。

* **JavaScript:**
    * **动态 DOM 操作:** JavaScript 可以动态地修改 DOM 结构和属性。`AXObjectCache` 需要监听这些变化并更新辅助功能树。虽然这个测试文件本身不直接执行 JavaScript 代码，但其测试的场景模拟了 JavaScript 动态修改 DOM 后 `AXObjectCache` 的行为。
    * **View Transitions API:**  `AXViewTransitionTest` 使用了 JavaScript 的 View Transitions API (`document.startViewTransition`) 来触发视图过渡，并观察 `AXObjectCache` 的行为。

    **举例:** `AXViewTransitionTest` 中，JavaScript 代码调用了 `ViewTransitionSupplement::startViewTransition` 来启动视图过渡。测试用例随后检查了与此次过渡相关的辅助功能树的状态。

**逻辑推理 (假设输入与输出):**

* **假设输入 (对于 `IsARIAWidget` 测试):**
    ```html
    <span id="mySpan" role="checkbox"></span>
    ```
* **预期输出:** `AXObjectCache::IsInsideFocusableElementOrARIAWidget` 函数对于 `id="mySpan"` 的元素应该返回 `true`，因为该元素具有 `role="checkbox"`，这是一个 ARIA widget 角色。

* **假设输入 (对于 `RemoveReferencesToAXID` 测试):**
    ```html
    <div id="fixedDiv" style="position: fixed;"></div>
    <p id="normalPara"></p>
    ```
* **操作:**  先获取 `fixedDiv` 的 `AXObject`，然后调用 `GetBoundsInFrameCoordinates()`，这将导致 `fixedDiv` 的 AXID 被添加到 `fixed_or_sticky_node_ids_` 集合中。接着，分别对 `normalPara` 和 `fixedDiv` 的 `AXObject` 调用 `RemoveReferencesToAXID`。
* **预期输出:**  在移除 `normalPara` 的引用后，`fixed_or_sticky_node_ids_` 的大小不变。在移除 `fixedDiv` 的引用后，`fixed_or_sticky_node_ids_` 的大小减 1。

**用户或编程常见的使用错误：**

1. **不正确或遗漏 ARIA 属性:** 开发者可能忘记为交互式元素添加合适的 ARIA `role` 属性，或者使用了错误的 ARIA 属性值。这会导致辅助技术无法正确理解元素的用途。
    * **错误示例:**  使用 `<div>` 元素作为按钮，但没有添加 `role="button"` 属性。`IsARIAWidget` 测试会覆盖这种情况，确保只有添加了正确 `role` 的元素才被识别为 widget。

2. **动态更新 DOM 后未触发辅助功能树更新:**  开发者可能使用 JavaScript 动态修改了 DOM 结构或属性，但没有采取措施通知辅助功能树进行更新。这会导致辅助技术呈现过时的信息。
    * **错误示例:**  使用 JavaScript 添加了一个新的交互式元素，但没有触发 `AXObjectCache` 的更新。`PauseUpdatesAfterMaxNumberQueued` 和 `UpdateAXForAllDocumentsAfterPausedUpdates` 测试确保了即使有大量的更新请求，系统也能正确处理。

3. **过度依赖视觉呈现而忽略语义:** 开发者可能仅通过 CSS 使元素看起来像某个类型的控件，但没有在 HTML 中使用正确的语义标签或 ARIA 属性。
    * **错误示例:**  使用 `<span>` 元素并使用 CSS 使其看起来像一个复选框，但没有添加 `role="checkbox"` 或使用 `<input type="checkbox">`。

**用户操作如何一步步到达这里 (作为调试线索)：**

假设开发者在调试一个与网页辅助功能相关的问题，例如屏幕阅读器没有正确识别页面上的某个元素。以下是一些可能的步骤，导致他们查看 `ax_object_cache_test.cc`：

1. **用户报告辅助功能问题:** 用户反馈使用屏幕阅读器浏览网页时，遇到了问题，例如某个按钮没有被正确识别，或者动态更新的内容没有被播报。

2. **开发者开始调试:** 开发者开始检查网页的 HTML 结构和 ARIA 属性，确保它们是正确的。

3. **怀疑是 Blink 引擎的辅助功能实现问题:** 如果 HTML 和 ARIA 看起来没问题，开发者可能会怀疑是浏览器引擎（Blink）的辅助功能实现存在问题，特别是 `AXObjectCache` 是否正确地构建了辅助功能树。

4. **搜索相关代码:** 开发者可能会在 Chromium 源代码中搜索与辅助功能、`AXObjectCache` 相关的代码，从而找到 `blink/renderer/modules/accessibility/ax_object_cache.cc`（实现）和 `blink/renderer/modules/accessibility/ax_object_cache_test.cc`（测试）。

5. **查看测试用例:**  开发者会查看 `ax_object_cache_test.cc` 中的测试用例，以了解 `AXObjectCache` 的预期行为以及如何进行测试。例如，如果问题与 ARIA 角色有关，开发者可能会查看 `IsARIAWidget` 测试用例，了解 Blink 如何判断一个元素是否是 ARIA widget。

6. **运行或修改测试用例:** 开发者可能会尝试运行相关的测试用例，以验证 `AXObjectCache` 在特定场景下的行为。如果需要，他们可能会修改测试用例以复现用户报告的问题，或者添加新的测试用例来覆盖新的场景。

7. **分析测试结果和代码:** 通过分析测试结果和 `AXObjectCache` 的源代码，开发者可以深入了解辅助功能树的构建和更新过程，从而找到问题的根源。

总而言之，`ax_object_cache_test.cc` 是 Blink 引擎中至关重要的测试文件，它通过大量的单元测试确保了 `AXObjectCache` 这一核心辅助功能组件的正确性和稳定性，直接关系到网页内容的可访问性。开发者可以通过查看和运行这些测试用例来理解 `AXObjectCache` 的工作原理，并排查与辅助功能相关的问题。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"

#include <vector>

#include "base/test/metrics/histogram_tester.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_view_transition_callback.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/testing/mock_function_scope.h"
#include "third_party/blink/renderer/core/view_transition/dom_view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/testing/accessibility_test.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

// TODO(nektar): Break test up into multiple tests.
TEST_F(AccessibilityTest, IsARIAWidget) {
  String test_content =
      "<body>"
      "<span id=\"plain\">plain</span><br>"
      "<span id=\"button\" role=\"button\">button</span><br>"
      "<span id=\"button-parent\" "
      "role=\"button\"><span>button-parent</span></span><br>"
      "<span id=\"button-caps\" role=\"BUTTON\">button-caps</span><br>"
      "<span id=\"button-second\" role=\"another-role "
      "button\">button-second</span><br>"
      "<span id=\"aria-bogus\" aria-bogus=\"bogus\">aria-bogus</span><br>"
      "<span id=\"aria-selected\" aria-selected>aria-selected</span><br>"
      "<span id=\"haspopup\" "
      "aria-haspopup=\"true\">aria-haspopup-true</span><br>"
      "<div id=\"focusable\" tabindex=\"1\">focusable</div><br>"
      "<div tabindex=\"2\"><div "
      "id=\"focusable-parent\">focusable-parent</div></div><br>"
      "</body>";

  SetBodyInnerHTML(test_content);
  Element* root(GetDocument().documentElement());
  EXPECT_FALSE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("plain"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("button"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("button-parent"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("button-caps"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("button-second"))));
  EXPECT_FALSE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("aria-bogus"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("aria-selected"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("haspopup"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("focusable"))));
  EXPECT_TRUE(AXObjectCache::IsInsideFocusableElementOrARIAWidget(
      *root->getElementById(AtomicString("focusable-parent"))));
}

TEST_F(AccessibilityTest, HistogramTest) {
  SetBodyInnerHTML("<body><button>Press Me</button></body>");

  auto& cache = GetAXObjectCache();
  cache.SetAXMode(ui::kAXModeBasic);

  // No logs initially.
  base::HistogramTester histogram_tester;
  histogram_tester.ExpectTotalCount(
      "Accessibility.Performance.AXObjectCacheImpl.Snapshot", 0);
  histogram_tester.ExpectTotalCount(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental", 0);
  histogram_tester.ExpectTotalCount(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.Float", 0);
  histogram_tester.ExpectTotalCount(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.Int", 0);
  histogram_tester.ExpectTotalCount(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.HTML", 0);
  histogram_tester.ExpectTotalCount(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.String", 0);

  {
    ui::AXTreeUpdate response;
    ScopedFreezeAXCache freeze(cache);
    cache.SerializeEntireTree(/* max_node_count */ 1000,
                              base::TimeDelta::FiniteMax(), &response);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Snapshot", 1);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental", 0);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.Float", 0);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.Int", 0);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.HTML", 0);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.String", 0);
  }

  {
    std::vector<ui::AXTreeUpdate> updates;
    std::vector<ui::AXEvent> events;
    bool had_end_of_test_event = true;
    bool had_load_complete_messages = true;
    ScopedFreezeAXCache freeze(cache);
    cache.GetUpdatesAndEventsForSerialization(
        updates, events, had_end_of_test_event, had_load_complete_messages);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Snapshot", 1);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental", 1);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.Float", 1);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.Int", 1);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.HTML", 1);
    histogram_tester.ExpectTotalCount(
        "Accessibility.Performance.AXObjectCacheImpl.Incremental.String", 1);
  }
}

TEST_F(AccessibilityTest, RemoveReferencesToAXID) {
  auto& cache = GetAXObjectCache();
  SetBodyInnerHTML(R"HTML(
      <div id="f" style="position:fixed">aaa</div>
      <h2 id="h">Heading</h2>)HTML");
  AXObject* fixed = GetAXObjectByElementId("f");
  // GetBoundsInFrameCoordinates() updates fixed_or_sticky_node_ids_.
  fixed->GetBoundsInFrameCoordinates();
  EXPECT_EQ(1u, cache.fixed_or_sticky_node_ids_.size());

  // RemoveReferencesToAXID() on node that is not fixed or sticky should not
  // affect fixed_or_sticky_node_ids_.
  cache.RemoveReferencesToAXID(GetAXObjectByElementId("h")->AXObjectID());
  EXPECT_EQ(1u, cache.fixed_or_sticky_node_ids_.size());

  // RemoveReferencesToAXID() on node that fixed should affect
  // fixed_or_sticky_node_ids_.
  cache.RemoveReferencesToAXID(GetAXObjectByElementId("f")->AXObjectID());
  EXPECT_EQ(0u, cache.fixed_or_sticky_node_ids_.size());
}

class MockAXObject : public AXObject {
 public:
  explicit MockAXObject(AXObjectCacheImpl& ax_object_cache)
      : AXObject(ax_object_cache) {}
  static unsigned num_children_changed_calls_;

  void ChildrenChangedWithCleanLayout() final { num_children_changed_calls_++; }
  Document* GetDocument() const final { return &AXObjectCache().GetDocument(); }
  void AddChildren() final {}
  ax::mojom::blink::Role NativeRoleIgnoringAria() const override {
    return ax::mojom::blink::Role::kUnknown;
  }
};

unsigned MockAXObject::num_children_changed_calls_ = 0;

TEST_F(AccessibilityTest, PauseUpdatesAfterMaxNumberQueued) {
  auto& document = GetDocument();
  auto* ax_object_cache =
      To<AXObjectCacheImpl>(document.ExistingAXObjectCache());
  DCHECK(ax_object_cache);

  wtf_size_t max_updates = 10;
  ax_object_cache->SetMaxPendingUpdatesForTesting(max_updates);

  MockAXObject* ax_obj = MakeGarbageCollected<MockAXObject>(*ax_object_cache);
  ax_object_cache->AssociateAXID(ax_obj);
  for (unsigned i = 0; i < max_updates + 1; i++) {
    ax_object_cache->DeferTreeUpdate(
        AXObjectCacheImpl::TreeUpdateReason::kChildrenChanged, ax_obj);
  }
  ax_object_cache->ProcessCleanLayoutCallbacks(document);

  ASSERT_EQ(0u, MockAXObject::num_children_changed_calls_);
}

TEST_F(AccessibilityTest, UpdateAXForAllDocumentsAfterPausedUpdates) {
  auto& document = GetDocument();
  auto* ax_object_cache =
      To<AXObjectCacheImpl>(document.ExistingAXObjectCache());
  DCHECK(ax_object_cache);

  wtf_size_t max_updates = 1;
  ax_object_cache->SetMaxPendingUpdatesForTesting(max_updates);

  UpdateAllLifecyclePhasesForTest();
  AXObject* root = ax_object_cache->Root();
  // Queue one update too many.
  ax_object_cache->DeferTreeUpdate(
      AXObjectCacheImpl::TreeUpdateReason::kChildrenChanged, root);
  ax_object_cache->DeferTreeUpdate(
      AXObjectCacheImpl::TreeUpdateReason::kChildrenChanged, root);

  ax_object_cache->UpdateAXForAllDocuments();
  ScopedFreezeAXCache freeze(*ax_object_cache);
  CHECK(!root->NeedsToUpdateCachedValues());
}

class AXViewTransitionTest : public testing::Test {
 public:
  AXViewTransitionTest() {}

  void SetUp() override {
    web_view_helper_ = std::make_unique<frame_test_helpers::WebViewHelper>();
    web_view_helper_->Initialize();
    web_view_helper_->Resize(gfx::Size(200, 200));
  }

  void TearDown() override { web_view_helper_.reset(); }

  Document& GetDocument() {
    return *web_view_helper_->GetWebView()
                ->MainFrameImpl()
                ->GetFrame()
                ->GetDocument();
  }

  void UpdateAllLifecyclePhasesAndFinishDirectives() {
    UpdateAllLifecyclePhasesForTest();
    for (auto& callback :
         LayerTreeHost()->TakeViewTransitionCallbacksForTesting()) {
      std::move(callback).Run({});
    }
  }

  cc::LayerTreeHost* LayerTreeHost() {
    return web_view_helper_->LocalMainFrame()
        ->FrameWidgetImpl()
        ->LayerTreeHostForTesting();
  }

  void SetHtmlInnerHTML(const String& content) {
    GetDocument().body()->setInnerHTML(content);
    UpdateAllLifecyclePhasesForTest();
  }

  void UpdateAllLifecyclePhasesForTest() {
    web_view_helper_->GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

  using State = ViewTransition::State;

  State GetState(DOMViewTransition* transition) const {
    return transition->GetViewTransitionForTest()->state_;
  }

 protected:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<frame_test_helpers::WebViewHelper> web_view_helper_;
};

TEST_F(AXViewTransitionTest, TransitionPseudoNotRelevant) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .shared {
        width: 100px;
        height: 100px;
        view-transition-name: shared;
        contain: layout;
        background: green;
      }
    </style>
    <div id=target class=shared></div>
  )HTML");

  auto* script_state = ToScriptStateForMainWorld(GetDocument().GetFrame());
  ScriptState::Scope scope(script_state);

  MockFunctionScope funcs(script_state);
  auto* view_transition_callback = V8ViewTransitionCallback::Create(
      funcs.ExpectCall()->ToV8Function(script_state));

  auto* transition = ViewTransitionSupplement::startViewTransition(
      script_state, GetDocument(), view_transition_callback,
      ASSERT_NO_EXCEPTION);

  ScriptPromiseTester finish_tester(script_state,
                                    transition->finished(script_state));

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(GetState(transition), State::kCapturing);

  UpdateAllLifecyclePhasesAndFinishDirectives();
  EXPECT_EQ(GetState(transition), State::kDOMCallbackRunning);

  // We should have a start request from the async callback passed to start()
  // resolving.
  test::RunPendingTasks();
  UpdateAllLifecyclePhasesAndFinishDirectives();

  // We should have a transition pseudo
  auto* transition_pseudo = GetDocument().documentElement()->GetPseudoElement(
      kPseudoIdViewTransition);
  ASSERT_TRUE(transition_pseudo);
  auto* container_pseudo = transition_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionGroup, AtomicString("shared"));
  ASSERT_TRUE(container_pseudo);
  auto* image_wrapper_pseudo = container_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, AtomicString("shared"));
  ASSERT_TRUE(image_wrapper_pseudo);
  auto* incoming_image_pseudo = image_wrapper_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionNew, AtomicString("shared"));
  ASSERT_TRUE(incoming_image_pseudo);
  auto* outgoing_image_pseudo = image_wrapper_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionOld, AtomicString("shared"));
  ASSERT_TRUE(outgoing_image_pseudo);

  ASSERT_TRUE(transition_pseudo->GetLayoutObject());
  ASSERT_TRUE(container_pseudo->GetLayoutObject());
  ASSERT_TRUE(image_wrapper_pseudo->GetLayoutObject());
  ASSERT_TRUE(incoming_image_pseudo->GetLayoutObject());
  ASSERT_TRUE(outgoing_image_pseudo->GetLayoutObject());

  EXPECT_FALSE(AXObjectCacheImpl::IsRelevantPseudoElement(*transition_pseudo));
  EXPECT_FALSE(AXObjectCacheImpl::IsRelevantPseudoElement(*container_pseudo));
  EXPECT_FALSE(
      AXObjectCacheImpl::IsRelevantPseudoElement(*image_wrapper_pseudo));
  EXPECT_FALSE(
      AXObjectCacheImpl::IsRelevantPseudoElement(*incoming_image_pseudo));
  EXPECT_FALSE(
      AXObjectCacheImpl::IsRelevantPseudoElement(*outgoing_image_pseudo));
}

class AccessibilityEnabledLaterTest : public AccessibilityTest {
  USING_FAST_MALLOC(AccessibilityEnabledLaterTest);

 public:
  AccessibilityEnabledLaterTest(LocalFrameClient* local_frame_client = nullptr)
      : AccessibilityTest(local_frame_client) {}

  void SetUp() override { RenderingTest::SetUp(); }

  void EnableAccessibility() {
    ax_context_ =
        std::make_unique<AXContext>(GetDocument(), ui::kAXModeComplete);
  }
};

TEST_F(AccessibilityEnabledLaterTest, CSSAnchorPositioning) {
  SetHtmlInnerHTML(R"HTML(
    <style>
      .anchor {
        anchor-name: --anchor-el;
       }
      .anchored-notice {
        position: absolute;
        position-anchor: --anchor-el;
        bottom: anchor(top);
        right: anchor(right);
      }
    </style>
    <body>
      <button id="1" class="anchor">
        <p>anchor</p>
      </button>
      <div id="2" class="anchored-notice">
        <p>positioned element tethered to the top-right of the anchor at bottom-right</p>
      </div>
    </body>
  )HTML");

  // Turning on a11y later should still set anchor relationships correctly.
  UpdateAllLifecyclePhasesForTest();
  DCHECK(!GetDocument().ExistingAXObjectCache());
  DCHECK(GetElementById("1")
             ->GetComputedStyle()
             ->AnchorName()
             ->GetNames()[0]
             ->GetName() == "--anchor-el");
  DCHECK(GetElementById("2")->GetComputedStyle()->PositionAnchor()->GetName() ==
         "--anchor-el");

  EnableAccessibility();
  AXObject* anchor = GetAXObjectByElementId("1");
  AXObject* positioned_object = GetAXObjectByElementId("2");
  EXPECT_EQ(GetAXObjectCache().GetPositionedObjectForAnchor(anchor),
            positioned_object);
  EXPECT_EQ(GetAXObjectCache().GetAnchorForPositionedObject(positioned_object),
            anchor);
}

}  // namespace blink
```