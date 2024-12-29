Response:
The user is asking for a summary of the functionality of the C++ source code file `ax_object_test.cc`. This file is part of the Chromium Blink rendering engine and is located in the `accessibility` module.

Based on the file name and the included headers (`gtest/gtest.h`, `third_party/blink/renderer/modules/accessibility/ax_object.h`, `ui/accessibility/ax_node_data.h`, etc.), I can infer that this file contains **unit tests for the `AXObject` class**. `AXObject` is a core class in Blink's accessibility implementation, representing an accessible node in the accessibility tree.

The tests likely cover various aspects of `AXObject`'s behavior, including:

* **Tree structure and navigation:** How `AXObject`s are related to each other (parent, children, siblings) and how to traverse the accessibility tree.
* **Properties and attributes:** Testing the correct interpretation of HTML attributes and their reflection in the `AXObject`'s properties (e.g., `contenteditable`, `aria-hidden`, `lang`).
* **Role determination:** How the accessible role of an element is determined and represented by the `AXObject`.
* **Ignored nodes:** How nodes marked as inaccessible are handled in the tree.
* **Editable content:**  Testing the logic for identifying editable elements and their associated text content.
* **Inline text boxes:** Handling of inline text content and the corresponding `InlineTextBox` objects.
* **Comparison operators:** Testing the functionality of comparison operators for `AXObject` instances.

I need to analyze the provided code snippets to confirm these assumptions and provide specific examples for each functionality, along with connections to HTML, CSS, and JavaScript where applicable. I also need to consider potential user errors and debugging scenarios.```
功能归纳：

blink/renderer/modules/accessibility/ax_object_test.cc 文件是 Chromium Blink 引擎中用于测试 `AXObject` 类的单元测试文件。它的主要功能是验证 `AXObject` 类的各种方法和属性是否按预期工作，以确保 Blink 的可访问性功能正确实现。

具体来说，从提供的代码片段来看，这个测试文件主要关注以下功能点：

1. **获取最近的元素 (GetClosestElement):**  测试 `AXObject` 如何找到其对应的最近的 HTML 元素，包括处理伪元素的情况。
2. **判断是否可编辑 (IsEditable):**  测试 `AXObject` 如何判断一个节点及其包含的文本内容是否可编辑，并区分不同类型的可编辑状态 (例如，文本输入框、文本域、`contenteditable` 属性)。
3. **判断是否被忽略 (IsIgnored):**  测试 `AXObject` 如何判断一个节点是否被从可访问性树中忽略，以及在节点被移除 (detached) 后的状态。
4. **访问未忽略的子节点 (UnignoredChildren):** 测试 `AXObject` 如何访问其未被可访问性树忽略的子节点。
5. **基本的树形结构导航 (SimpleTreeNavigation):** 测试 `AXObject` 在可访问性树中的基本导航方法，例如获取第一个/最后一个子节点、上一个/下一个兄弟节点等，包括处理被忽略的节点。
6. **`lang` 属性的影响 (LangAttrInteresting, LangAttrInterestingHidden):** 测试 HTML 的 `lang` 属性如何影响可访问性树的结构，即使元素被 `aria-hidden` 隐藏。
7. **带有被忽略容器的树形结构导航 (TreeNavigationWithIgnoredContainer):** 测试在可访问性树中包含被忽略的容器节点时，`AXObject` 的导航方法是否正确。
8. **带有连续元素的树形结构导航 (TreeNavigationWithContinuations):** 测试处理 HTML 中由于块级元素插入行内元素而产生的连续元素时，`AXObject` 的导航行为。
9. **带有内联文本框的树形结构导航 (TreeNavigationWithInlineTextBoxes):** 测试 `AXObject` 如何处理内联文本框，并验证父子关系。
10. **`AXObject` 的比较运算符 (AXObjectComparisonOperators):** 测试 `AXObject` 的比较运算符是否按预期工作。
11. **`AXObject` 的未忽略祖先迭代器 (AXObjectUnignoredAncestorsIterator):** 测试遍历 `AXObject` 未被忽略的祖先节点的功能。
12. **获取 HTML 锚元素的 URL (AxNodeObjectContainsHtmlAnchorElementUrl):** (部分代码未完整提供，但从命名推断) 测试 `AXObject` 是否能正确获取 HTML 锚元素的 URL。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  测试文件通过设置 `SetBodyInnerHTML()` 来创建不同的 HTML 结构，以此来测试 `AXObject` 如何解析和表示这些 HTML 元素及其属性。
    * **例子:**  `SetBodyInnerHTML(R"HTML(<button id="button">button</button>)HTML");` 这行代码在测试中创建了一个简单的按钮元素，用于后续的 `AXObject` 操作。
    * **例子:** `SetBodyInnerHTML(R"HTML(<input type="text" id="input" value="Test">)HTML");` 创建了一个文本输入框，用于测试 `IsEditable` 相关的功能。
    * **例子:** `<div role="textbox" contenteditable="true" id="outerContenteditable">`  HTML 的 `role` 和 `contenteditable` 属性直接影响着 `AXObject` 的角色和可编辑状态，测试会验证这些属性是否被正确识别。
* **CSS:**  CSS 可以影响元素的渲染和布局，间接影响可访问性树的结构。例如，伪元素是通过 CSS 定义的，测试用例 `GetClosestElementSearchesAmongAncestors`  就涉及到了 CSS 的 `::before` 伪元素。
    * **例子:**  `SetBodyInnerHTML(R"HTML(<style>button::before{content: "Content";}</style><button id="button">button</button>)HTML");`  这段代码创建了一个带有 `::before` 伪元素的按钮，测试会验证对于伪元素产生的 `AXObject` 如何找到其最近的元素。
* **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，但它测试的是 Blink 引擎的可访问性功能，这些功能最终会暴露给 JavaScript，供辅助技术 (例如屏幕阅读器) 通过 Accessibility APIs (如 ARIA) 来访问网页内容。
    * **例子:**  JavaScript 可以动态地修改 HTML 结构和属性 (例如通过 `setAttribute` 修改 `aria-hidden` 或 `contenteditable`)，这些修改会触发 Blink 重新构建可访问性树。此测试文件验证了 Blink 在这些情况下 `AXObject` 的行为是否正确，从而保证了 JavaScript 操作对可访问性的影响符合预期。

**逻辑推理的假设输入与输出:**

* **假设输入 (针对 `IsEditableInTextField` 测试):**  HTML 代码 `<input type="text" id="input" value="Test">`
* **预期输出:**
    * `GetAXObjectByElementId("input")->IsEditable()` 应该返回 `true`。
    * `GetAXObjectByElementId("input")->FirstChildIncludingIgnored()->UnignoredChildAt(0)->IsEditable()` 应该返回 `true` (文本节点也应该被认为是可编辑的)。
    * `GetAXObjectByElementId("input")->IsMultiline()` 应该返回 `false`。
    * `GetAXObjectByElementId("input")->HasContentEditableAttributeSet()` 应该返回 `false`。

* **假设输入 (针对 `GetClosestElementSearchesAmongAncestors` 测试):** HTML 代码 `<style>button::before{content: "Content";}</style><button id="button">button</button>`
* **预期输出:**
    * `button->DeepestFirstChildIncludingIgnored()->ParentObject()->GetClosestElement()` 应该返回与 `button->GetElement()->GetPseudoElement(kPseudoIdBefore)` 相同的 `Element` 指针 (伪元素对应的 `AXObject` 应该能找到其关联的宿主元素)。

**涉及用户或编程常见的使用错误:**

* **错误地使用 `contenteditable` 属性:**  例如，将 `contenteditable="true"` 应用于 `<input type="text">` 元素。虽然技术上有效，但这是一种不常见的用法，可能会导致辅助技术产生非预期的行为。测试用例 `IsEditableInTextFieldWithContentEditableTrue` 就涵盖了这种情况。
* **错误地理解 `aria-hidden` 的作用:**  开发者可能会错误地认为 `aria-hidden="true"` 会完全从 DOM 中移除元素。实际上，它只是将其从可访问性树中移除。测试用例 `LangAttrInterestingHidden` 展示了即使元素被 `aria-hidden` 隐藏，某些具有语义意义的属性 (如 `lang`) 仍然会影响可访问性树的结构。
* **不正确的 ARIA 角色使用:**  例如，在语义不合适的元素上使用 ARIA 角色。虽然测试用例中没有直接体现，但 `AXObject` 的角色判断逻辑是基于 HTML 语义和 ARIA 属性的，错误的 ARIA 使用会导致 `AXObject` 的角色不正确，辅助技术可能会误解元素的功能。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户与网页交互:** 用户通过鼠标点击、键盘输入等操作与网页上的元素进行交互。
2. **浏览器事件处理:** 用户的交互触发浏览器事件 (例如 `click`, `keydown`)。
3. **渲染引擎处理:** 渲染引擎 (Blink) 接收到这些事件，并进行相应的处理，例如更新 DOM 树、触发 JavaScript 代码等。
4. **可访问性树更新:** 当 DOM 树发生变化 (例如，元素被添加、删除或属性被修改) 时，Blink 的可访问性模块会更新可访问性树。
5. **`AXObject` 创建和更新:**  `AXObjectCacheImpl` 负责创建和管理 `AXObject` 实例，它会根据 DOM 树的结构和元素的属性来创建或更新相应的 `AXObject`。
6. **辅助技术访问:** 屏幕阅读器等辅助技术通过操作系统的 Accessibility APIs (例如 Windows 上的 UI Automation, macOS 上的 Accessibility API) 来访问可访问性树中的信息。
7. **调试线索:** 如果辅助技术报告了网页可访问性方面的问题，开发者可以通过以下步骤进行调试，并可能最终涉及到 `ax_object_test.cc` 中的测试用例：
    * **检查 HTML 结构和 ARIA 属性:**  确认 HTML 结构是否语义化，ARIA 属性是否正确使用。
    * **使用浏览器的辅助功能检查工具:**  Chrome 开发者工具的 "Accessibility" 面板可以查看网页的可访问性树，帮助开发者理解辅助技术是如何理解网页结构的。
    * **阅读辅助技术日志:**  一些辅助技术会提供详细的日志，记录它们如何解析和解释网页内容。
    * **单步调试 Blink 引擎代码:**  在开发环境下，开发者可以单步调试 Blink 引擎的代码，例如 `AXObject::IsEditable()` 等方法，来理解可访问性信息的计算过程。`ax_object_test.cc` 中的测试用例可以作为参考，帮助理解特定功能的预期行为，并验证代码的正确性。如果怀疑某个 `AXObject` 的行为不正确，可以查看是否有相关的测试用例覆盖了这种情况，或者编写新的测试用例来重现和修复问题。

总而言之，`ax_object_test.cc` 是确保 Chromium Blink 引擎可访问性功能正确性的重要组成部分，它通过一系列单元测试来验证 `AXObject` 类的行为，涵盖了从基本的树形结构到复杂的属性和状态判断等多个方面，为开发者提供了调试和理解 Blink 可访问性实现的线索。
```
Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_object.h"

#include <memory>

#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/testing/accessibility_test.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "ui/accessibility/ax_action_data.h"
#include "ui/accessibility/ax_mode.h"
#include "ui/accessibility/ax_node_data.h"
#include "ui/accessibility/ax_tree_id.h"

namespace blink {
namespace test {

using testing::Each;
using testing::Property;
using testing::SafeMatcherCast;

TEST_F(AccessibilityTest, GetClosestElementChecksStartingNode) {
  SetBodyInnerHTML(R"HTML(<button id="button">button</button>)HTML");

  const AXObject* button = GetAXObjectByElementId("button");
  ASSERT_NE(nullptr, button);
  const Element* closestElement = button->GetClosestElement();
  ASSERT_NE(nullptr, closestElement);

  EXPECT_TRUE(closestElement == button->GetElement());
}

TEST_F(AccessibilityTest, GetClosestElementSearchesAmongAncestors) {
  SetBodyInnerHTML(R"HTML(
        <style>
        button::before{
            content: "Content";
        }
        </style>
        <button id="button">button</button>
      )HTML");

  AXObject* button = GetAXObjectByElementId("button");
  button->LoadInlineTextBoxes();
  // Guaranteed to have no element since this should be the AX node created from
  // pseudo element content
  const AXObject* nodeWithNoElement =
      button->DeepestFirstChildIncludingIgnored()->ParentObject();
  ASSERT_EQ(nullptr, nodeWithNoElement->GetElement());

  EXPECT_EQ(nodeWithNoElement->GetClosestElement(),
            button->GetElement()->GetPseudoElement(kPseudoIdBefore));
}

TEST_F(AccessibilityTest, IsEditableInTextField) {
  SetBodyInnerHTML(R"HTML(
      <input type="text" id="input" value="Test">
      <textarea id="textarea">
        Test
      </textarea>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, input);
  const AXObject* input_text =
      input->FirstChildIncludingIgnored()->UnignoredChildAt(0);
  ASSERT_NE(nullptr, input_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText, input_text->RoleValue());
  const AXObject* textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, textarea);
  const AXObject* textarea_text =
      textarea->FirstChildIncludingIgnored()->UnignoredChildAt(0);
  ASSERT_NE(nullptr, textarea_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText, textarea_text->RoleValue());

  EXPECT_FALSE(root->IsEditable());
  EXPECT_TRUE(input->IsEditable());
  EXPECT_TRUE(input_text->IsEditable());
  EXPECT_TRUE(textarea->IsEditable());
  EXPECT_TRUE(textarea_text->IsEditable());

  EXPECT_FALSE(root->IsEditableRoot());
  EXPECT_FALSE(input->IsEditableRoot());
  EXPECT_FALSE(input_text->IsEditableRoot());
  EXPECT_FALSE(textarea->IsEditableRoot());
  EXPECT_FALSE(textarea_text->IsEditableRoot());

  EXPECT_FALSE(root->HasContentEditableAttributeSet());
  EXPECT_FALSE(input->HasContentEditableAttributeSet());
  EXPECT_FALSE(input_text->HasContentEditableAttributeSet());
  EXPECT_FALSE(textarea->HasContentEditableAttributeSet());
  EXPECT_FALSE(textarea_text->HasContentEditableAttributeSet());

  EXPECT_FALSE(root->IsMultiline());
  EXPECT_FALSE(input->IsMultiline());
  EXPECT_FALSE(input_text->IsMultiline());
  EXPECT_TRUE(textarea->IsMultiline());
  EXPECT_FALSE(textarea_text->IsMultiline());

  EXPECT_FALSE(root->IsRichlyEditable());
  EXPECT_FALSE(input->IsRichlyEditable());
  EXPECT_FALSE(input_text->IsRichlyEditable());
  EXPECT_FALSE(textarea->IsRichlyEditable());
  EXPECT_FALSE(textarea_text->IsRichlyEditable());
}

TEST_F(AccessibilityTest, IsEditableInTextFieldWithContentEditableTrue) {
  SetBodyInnerHTML(R"HTML(
      <!-- This is technically an authoring error, but we should still handle
           it correctly. -->
      <input type="text" id="input" value="Test" contenteditable="true">
      <textarea id="textarea" contenteditable="true">
        Test
      </textarea>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, input);
  const AXObject* input_text =
      input->FirstChildIncludingIgnored()->UnignoredChildAt(0);
  ASSERT_NE(nullptr, input_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText, input_text->RoleValue());
  const AXObject* textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, textarea);
  const AXObject* textarea_text =
      textarea->FirstChildIncludingIgnored()->UnignoredChildAt(0);
  ASSERT_NE(nullptr, textarea_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText, textarea_text->RoleValue());

  EXPECT_FALSE(root->IsEditable());
  EXPECT_TRUE(input->IsEditable());
  EXPECT_TRUE(input_text->IsEditable());
  EXPECT_TRUE(textarea->IsEditable());
  EXPECT_TRUE(textarea_text->IsEditable());

  EXPECT_FALSE(root->IsEditableRoot());
  EXPECT_FALSE(input->IsEditableRoot());
  EXPECT_FALSE(input_text->IsEditableRoot());
  EXPECT_FALSE(textarea->IsEditableRoot());
  EXPECT_FALSE(textarea_text->IsEditableRoot());

  EXPECT_FALSE(root->HasContentEditableAttributeSet());
  EXPECT_TRUE(input->HasContentEditableAttributeSet());
  EXPECT_FALSE(input_text->HasContentEditableAttributeSet());
  EXPECT_TRUE(textarea->HasContentEditableAttributeSet());
  EXPECT_FALSE(textarea_text->HasContentEditableAttributeSet());

  EXPECT_FALSE(root->IsMultiline());
  EXPECT_FALSE(input->IsMultiline());
  EXPECT_FALSE(input_text->IsMultiline());
  EXPECT_TRUE(textarea->IsMultiline());
  EXPECT_FALSE(textarea_text->IsMultiline());

  EXPECT_FALSE(root->IsRichlyEditable());
  EXPECT_FALSE(input->IsRichlyEditable());
  EXPECT_FALSE(input_text->IsRichlyEditable());
  EXPECT_FALSE(textarea->IsRichlyEditable());
  EXPECT_FALSE(textarea_text->IsRichlyEditable());
}

TEST_F(AccessibilityTest, IsEditableInContentEditable) {
  // On purpose, also add the textbox role to ensure that it won't affect the
  // contenteditable state.
  SetBodyInnerHTML(R"HTML(
      <div role="textbox" contenteditable="true" id="outerContenteditable">
        Test
        <div contenteditable="plaintext-only" id="innerContenteditable">
          Test
        </div>
      </div>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* outer_contenteditable =
      GetAXObjectByElementId("outerContenteditable");
  ASSERT_NE(nullptr, outer_contenteditable);
  const AXObject* outer_contenteditable_text =
      outer_contenteditable->UnignoredChildAt(0);
  ASSERT_NE(nullptr, outer_contenteditable_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText,
            outer_contenteditable_text->RoleValue());
  const AXObject* inner_contenteditable =
      GetAXObjectByElementId("innerContenteditable");
  ASSERT_NE(nullptr, inner_contenteditable);
  const AXObject* inner_contenteditable_text =
      inner_contenteditable->UnignoredChildAt(0);
  ASSERT_NE(nullptr, inner_contenteditable_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText,
            inner_contenteditable_text->RoleValue());

  EXPECT_FALSE(root->IsEditable());
  EXPECT_TRUE(outer_contenteditable->IsEditable());
  EXPECT_TRUE(outer_contenteditable_text->IsEditable());
  EXPECT_TRUE(inner_contenteditable->IsEditable());
  EXPECT_TRUE(inner_contenteditable_text->IsEditable());

  EXPECT_FALSE(root->IsEditableRoot());
  EXPECT_TRUE(outer_contenteditable->IsEditableRoot());
  EXPECT_FALSE(outer_contenteditable_text->IsEditableRoot());
  EXPECT_TRUE(inner_contenteditable->IsEditableRoot());
  EXPECT_FALSE(inner_contenteditable_text->IsEditableRoot());

  EXPECT_FALSE(root->HasContentEditableAttributeSet());
  EXPECT_TRUE(outer_contenteditable->HasContentEditableAttributeSet());
  EXPECT_FALSE(outer_contenteditable_text->HasContentEditableAttributeSet());
  EXPECT_TRUE(inner_contenteditable->HasContentEditableAttributeSet());
  EXPECT_FALSE(inner_contenteditable_text->HasContentEditableAttributeSet());

  EXPECT_FALSE(root->IsMultiline());
  EXPECT_TRUE(outer_contenteditable->IsMultiline());
  EXPECT_FALSE(outer_contenteditable_text->IsMultiline());
  EXPECT_TRUE(inner_contenteditable->IsMultiline());
  EXPECT_FALSE(inner_contenteditable_text->IsMultiline());

  EXPECT_FALSE(root->IsRichlyEditable());
  EXPECT_TRUE(outer_contenteditable->IsRichlyEditable());
  EXPECT_TRUE(outer_contenteditable_text->IsRichlyEditable());
  // contenteditable="plaintext-only".
  EXPECT_FALSE(inner_contenteditable->IsRichlyEditable());
  EXPECT_FALSE(inner_contenteditable_text->IsRichlyEditable());
}

TEST_F(AccessibilityTest, IsEditableInCanvasFallback) {
  SetBodyInnerHTML(R"HTML(
      <canvas id="canvas" width="300" height="300">
        <input id="input" value="Test">
        <div contenteditable="true" id="outerContenteditable">
          Test
          <div contenteditable="plaintext-only" id="innerContenteditable">
            Test
          </div>
        </div>
      </canvas>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* canvas = GetAXObjectByElementId("canvas");
  ASSERT_NE(nullptr, canvas);
  const AXObject* input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, input);
  const AXObject* input_text =
      input->FirstChildIncludingIgnored()->UnignoredChildAt(0);
  ASSERT_NE(nullptr, input_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText, input_text->RoleValue());
  const AXObject* outer_contenteditable =
      GetAXObjectByElementId("outerContenteditable");
  ASSERT_NE(nullptr, outer_contenteditable);
  const AXObject* outer_contenteditable_text =
      outer_contenteditable->UnignoredChildAt(0);
  ASSERT_NE(nullptr, outer_contenteditable_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText,
            outer_contenteditable_text->RoleValue());
  const AXObject* inner_contenteditable =
      GetAXObjectByElementId("innerContenteditable");
  ASSERT_NE(nullptr, inner_contenteditable);
  const AXObject* inner_contenteditable_text =
      inner_contenteditable->UnignoredChildAt(0);
  ASSERT_NE(nullptr, inner_contenteditable_text);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText,
            inner_contenteditable_text->RoleValue());

  EXPECT_FALSE(root->IsEditable());
  EXPECT_FALSE(canvas->IsEditable());
  EXPECT_TRUE(input->IsEditable());
  EXPECT_TRUE(input_text->IsEditable());
  EXPECT_TRUE(outer_contenteditable->IsEditable());
  EXPECT_TRUE(outer_contenteditable_text->IsEditable());
  EXPECT_TRUE(inner_contenteditable->IsEditable());
  EXPECT_TRUE(inner_contenteditable_text->IsEditable());

  EXPECT_FALSE(root->IsEditableRoot());
  EXPECT_FALSE(canvas->IsEditableRoot());
  EXPECT_FALSE(input->IsEditableRoot());
  EXPECT_FALSE(input_text->IsEditableRoot());
  EXPECT_TRUE(outer_contenteditable->IsEditableRoot());
  EXPECT_FALSE(outer_contenteditable_text->IsEditableRoot());
  EXPECT_TRUE(inner_contenteditable->IsEditableRoot());
  EXPECT_FALSE(inner_contenteditable_text->IsEditableRoot());

  EXPECT_FALSE(root->HasContentEditableAttributeSet());
  EXPECT_FALSE(canvas->HasContentEditableAttributeSet());
  EXPECT_FALSE(input->HasContentEditableAttributeSet());
  EXPECT_FALSE(input_text->HasContentEditableAttributeSet());
  EXPECT_TRUE(outer_contenteditable->HasContentEditableAttributeSet());
  EXPECT_FALSE(outer_contenteditable_text->HasContentEditableAttributeSet());
  EXPECT_TRUE(inner_contenteditable->HasContentEditableAttributeSet());
  EXPECT_FALSE(inner_contenteditable_text->HasContentEditableAttributeSet());

  EXPECT_FALSE(root->IsMultiline());
  EXPECT_FALSE(canvas->IsMultiline());
  EXPECT_FALSE(input->IsMultiline());
  EXPECT_FALSE(input_text->IsMultiline());
  EXPECT_TRUE(outer_contenteditable->IsMultiline());
  EXPECT_FALSE(outer_contenteditable_text->IsMultiline());
  EXPECT_TRUE(inner_contenteditable->IsMultiline());
  EXPECT_FALSE(inner_contenteditable_text->IsMultiline());

  EXPECT_FALSE(root->IsRichlyEditable());
  EXPECT_FALSE(canvas->IsRichlyEditable());
  EXPECT_FALSE(input->IsRichlyEditable());
  EXPECT_FALSE(input_text->IsRichlyEditable());
  EXPECT_TRUE(outer_contenteditable->IsRichlyEditable());
  EXPECT_TRUE(outer_contenteditable_text->IsRichlyEditable());
  EXPECT_FALSE(inner_contenteditable->IsRichlyEditable());
  EXPECT_FALSE(inner_contenteditable_text->IsRichlyEditable());
}

TEST_F(AccessibilityTest, DetachedIsIgnored) {
  SetBodyInnerHTML(R"HTML(<button id="button">button</button>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  AXObject* button = GetAXObjectByElementId("button");
  ASSERT_NE(nullptr, button);

  EXPECT_FALSE(button->IsDetached());
  EXPECT_FALSE(button->IsIgnored());
  GetAXObjectCache().Remove(button->GetNode());
  EXPECT_TRUE(button->IsDetached());
  EXPECT_TRUE(button->IsIgnored());
  EXPECT_FALSE(button->IsIgnoredButIncludedInTree());
}

TEST_F(AccessibilityTest, UnignoredChildren) {
  SetBodyInnerHTML(R"HTML(This is a test with
                   <p role="presentation">
                     ignored objects
                   </p>
                   <p>
                     which are at multiple
                   </p>
                   <p role="presentation">
                     <p role="presentation">
                       depth levels
                     </p>
                     in the accessibility tree.
                   </p>)HTML");

  const AXObject* ax_body = GetAXRootObject()->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_body);

  ASSERT_EQ(5, ax_body->UnignoredChildCount());
  EXPECT_EQ(ax::mojom::blink::Role::kStaticText,
            ax_body->UnignoredChildAt(0)->RoleValue());
  EXPECT_EQ("This is a test with",
            ax_body->UnignoredChildAt(0)->ComputedName());
  EXPECT_EQ(ax::mojom::blink::Role::kStaticText,
            ax_body->UnignoredChildAt(1)->RoleValue());
  EXPECT_EQ("ignored objects", ax_body->UnignoredChildAt(1)->ComputedName());
  EXPECT_EQ(ax::mojom::blink::Role::kParagraph,
            ax_body->UnignoredChildAt(2)->RoleValue());
  EXPECT_EQ(ax::mojom::blink::Role::kStaticText,
            ax_body->UnignoredChildAt(3)->RoleValue());
  EXPECT_EQ("depth levels", ax_body->UnignoredChildAt(3)->ComputedName());
  EXPECT_EQ(ax::mojom::blink::Role::kStaticText,
            ax_body->UnignoredChildAt(4)->RoleValue());
  EXPECT_EQ("in the accessibility tree.",
            ax_body->UnignoredChildAt(4)->ComputedName());
}

TEST_F(AccessibilityTest, SimpleTreeNavigation) {
  SetBodyInnerHTML(R"HTML(<input id="input" type="text" value="value">
                   <div id="ignored_a" aria-hidden="true" lang="en-US"></div>
                   <p id="paragraph">hello<br id="br">there</p>
                   <span id="ignored_b" aria-hidden="true" lang="fr-CA"></span>
                   <button id="button">button</button>)HTML");

  AXObject* body = GetAXBodyObject();
  ASSERT_NE(nullptr, body);
  body->LoadInlineTextBoxes();
  const AXObject* input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, input);
  ASSERT_NE(nullptr, GetAXObjectByElementId("ignored_a"));
  ASSERT_TRUE(GetAXObjectByElementId("ignored_a")->IsIgnored());
  const AXObject* paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, paragraph);
  const AXObject* br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, br);
  ASSERT_NE(nullptr, GetAXObjectByElementId("ignored_b"));
  ASSERT_TRUE(GetAXObjectByElementId("ignored_b")->IsIgnored());
  const AXObject* button = GetAXObjectByElementId("button");
  ASSERT_NE(nullptr, button);

  EXPECT_EQ(input, body->FirstChildIncludingIgnored());
  EXPECT_EQ(button, body->LastChildIncludingIgnored());

  ASSERT_NE(nullptr, paragraph->FirstChildIncludingIgnored());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            paragraph->FirstChildIncludingIgnored()->RoleValue());
  ASSERT_NE(nullptr, paragraph->LastChildIncludingIgnored());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            paragraph->LastChildIncludingIgnored()->RoleValue());
  ASSERT_NE(nullptr, paragraph->FirstChildIncludingIgnored()->ParentObject());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            paragraph->DeepestFirstChildIncludingIgnored()
                ->ParentObject()
                ->RoleValue());
  ASSERT_NE(nullptr,
            paragraph->DeepestLastChildIncludingIgnored()->ParentObject());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            paragraph->DeepestLastChildIncludingIgnored()
                ->ParentObject()
                ->RoleValue());

  EXPECT_EQ(paragraph->PreviousSiblingIncludingIgnored(),
            GetAXObjectByElementId("ignored_a"));
  EXPECT_EQ(GetAXObjectByElementId("ignored_a"),
            input->NextSiblingIncludingIgnored());
  ASSERT_NE(nullptr, br->NextSiblingIncludingIgnored());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            br->NextSiblingIncludingIgnored()->RoleValue());
  ASSERT_NE(nullptr, br->PreviousSiblingIncludingIgnored());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            br->PreviousSiblingIncludingIgnored()->RoleValue());

  EXPECT_EQ(paragraph->UnignoredPreviousSibling(), input);
  EXPECT_EQ(paragraph, input->UnignoredNextSibling());
  ASSERT_NE(nullptr, br->UnignoredNextSibling());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            br->UnignoredNextSibling()->RoleValue());
  ASSERT_NE(nullptr, br->UnignoredPreviousSibling());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            br->UnignoredPreviousSibling()->RoleValue());

  ASSERT_NE(nullptr, button->FirstChildIncludingIgnored());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            button->FirstChildIncludingIgnored()->RoleValue());
  ASSERT_NE(nullptr, button->LastChildIncludingIgnored());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            button->LastChildIncludingIgnored()->RoleValue());
  ASSERT_NE(nullptr,
            button->DeepestFirstChildIncludingIgnored()->ParentObject());
  EXPECT_EQ(ax::mojom::Role::kStaticText,
            paragraph->DeepestFirstChildIncludingIgnored()
                ->ParentObject()
                ->RoleValue());
}

TEST_F(AccessibilityTest, LangAttrInteresting) {
  SetBodyInnerHTML(R"HTML(
      <div id="A"><span>some text</span></div>
      <div id="B"><span lang='en'>some text</span></div>
      )HTML");

  const AXObject* obj_a = GetAXObjectByElementId("A");
  ASSERT_NE(nullptr, obj_a);
  ASSERT_EQ(obj_a->ChildCountIncludingIgnored(), 1);

  // A.span will be excluded from tree as it isn't semantically interesting.
  // Instead its kStaticText child will be promoted.
  const AXObject* span_1 = obj_a->ChildAtIncludingIgnored(0);
  ASSERT_NE(nullptr, span_1);
  EXPECT_EQ(ax::mojom::Role::kStaticText, span_1->RoleValue());

  const AXObject* obj_b = GetAXObjectByElementId("B");
  ASSERT_NE(nullptr, obj_b);
  ASSERT_EQ(obj_b->ChildCountIncludingIgnored(), 1);

  // B.span will be present as the lang attribute is semantically interesting.
  const AXObject* span_2 = obj_b->ChildAtIncludingIgnored(0);
  ASSERT_NE(nullptr, span_2);
  EXPECT_EQ(ax::mojom::Role::kGenericContainer, span_2->RoleValue());
}

TEST_F(AccessibilityTest, LangAttrInterestingHidden) {
  SetBodyInnerHTML(R"HTML(
      <div id="A"><span lang='en' aria-hidden='true'>some text</span></div>
      )HTML");

  const AXObject* obj_a = GetAXObjectByElementId("A");
  ASSERT_NE(nullptr, obj_a);
  ASSERT_EQ(obj_a->ChildCountIncludingIgnored(), 1);

  // A.span will be present as the lang attribute is semantically interesting.
  const AXObject* span_1 = obj_a->ChildAtIncludingIgnored(0);
  ASSERT_NE(nullptr, span_1);
  EXPECT_EQ(ax::mojom::Role::kGenericContainer, span_1->RoleValue());
  EXPECT_TRUE(span_1->IsIgnoredButIncludedInTree());
}

TEST_F(AccessibilityTest, TreeNavigationWithIgnoredContainer) {
  // Setup the following tree :
  // ++A
  // ++IGNORED
  // ++++B
  // ++C
  // So that nodes [A, B, C] are siblings
  SetBodyInnerHTML(R"HTML(
      <p id="A">some text</p>
      <div>
        <p id="B">nested text</p>
      </div>
      <p id="C">more text</p>
      )HTML");

  AXObject* root = GetAXRootObject();
  root->LoadInlineTextBoxes();
  const AXObject* body = GetAXBodyObject();
  ASSERT_EQ(3, body->ChildCountIncludingIgnored());
  ASSERT_EQ(1, body->ChildAtIncludingIgnored(1)->ChildCountIncludingIgnored());

  ASSERT_FALSE(root->IsIgnored());
  ASSERT_TRUE(body->IsIgnored());
  const AXObject* obj_a = GetAXObjectByElementId("A");
  ASSERT_NE(nullptr, obj_a);
  ASSERT_FALSE(obj_a->IsIgnored());
  const AXObject* obj_a_text = obj_a->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, obj_a_text);
  EXPECT_EQ(ax::mojom::Role::kStaticText, obj_a_text->RoleValue());
  const AXObject* obj_b = GetAXObjectByElementId("B");
  ASSERT_NE(nullptr, obj_b);
  ASSERT_FALSE(obj_b->IsIgnored());
  const AXObject* obj_b_text = obj_b->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, obj_b_text);
  EXPECT_EQ(ax::mojom::Role::kStaticText, obj_b_text->RoleValue());
  const AXObject* obj_c = GetAXObjectByElementId("C");
  ASSERT_NE(nullptr, obj_c);
  ASSERT_FALSE(obj_c->IsIgnored());
  const AXObject* obj_c_text = obj_c->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, obj_c_text);
  EXPECT_EQ(ax::mojom::Role::kStaticText, obj_c_text->RoleValue());
  const AXObject* obj_ignored = body->ChildAtIncludingIgnored(1);
  ASSERT_NE(nullptr, obj_ignored);
  ASSERT_TRUE(obj_ignored->IsIgnored());

  EXPECT_EQ(root, obj_a->ParentObjectUnignored());
  EXPECT_EQ(body, obj_a->ParentObjectIncludedInTree());
  EXPECT_EQ(root, obj_b->ParentObjectUnignored());
  EXPECT_EQ(obj_ignored, obj_b->ParentObjectIncludedInTree());
  EXPECT_EQ(root, obj_c->ParentObjectUnignored());
  EXPECT_EQ(body, obj_c->ParentObjectIncludedInTree());

  EXPECT_EQ(obj_b, obj_ignored->FirstChildIncludingIgnored());

  EXPECT_EQ(nullptr, obj_a->PreviousSiblingIncludingIgnored());
  EXPECT_EQ(nullptr, obj_a->UnignoredPreviousSibling());
  EXPECT_EQ(obj_ignored, obj_a->NextSiblingIncludingIgnored());
  EXPECT_EQ(obj_b, obj_a->UnignoredNextSibling());

  EXPECT_EQ(body, obj_a->PreviousInPreOrderIncludingIgnored());
  EXPECT_EQ(root, obj_a->UnignoredPreviousInPreOrder());
  EXPECT_EQ(obj_a_text, obj_a->NextInPreOrderIncludingIgnored());
  EXPECT_EQ(obj_a_text, obj_a->UnignoredNextInPreOrder());

  EXPECT_EQ(nullptr, obj_b->PreviousSiblingIncludingIgnored());
  EXPECT_EQ(obj_a, obj_b->UnignoredPreviousSibling());
  EXPECT_EQ(nullptr, obj_b->NextSiblingIncludingIgnored());
  EXPECT_EQ(obj_c, obj_b->UnignoredNextSibling());

  EXPECT_EQ(obj_ignored, obj_b->PreviousInPreOrderIncludingIgnored());
  EXPECT_EQ(obj_a_text, obj_b->UnignoredPreviousInPreOrder()->ParentObject());
  EXPECT_EQ(obj_b_text, obj_b->NextInPreOrderIncludingIgnored());
  EXPECT_EQ(obj_b_text, obj_b->UnignoredNextInPreOrder());

  EXPECT_EQ(obj_ignored, obj_c->PreviousSiblingIncludingIgnored());
  EXPECT_EQ(obj_b, obj_c->UnignoredPreviousSibling());
  EXPECT_EQ(nullptr, obj_c->NextSiblingIncludingIgnored());
  EXPECT_EQ(nullptr, obj_c->UnignoredNextSibling());

  EXPECT_EQ(
      obj_b_text,
      obj_c->PreviousInPreOrderIncludingIgnored()->ParentObjectUnignored());
  EXPECT_EQ(obj_b_text,
            obj_c->UnignoredPreviousInPreOrder()->ParentObjectUnignored());
  EXPECT_EQ(obj_c_text, obj_c->NextInPreOrderIncludingIgnored());
  EXPECT_EQ(obj_c_text, obj_c->UnignoredNextInPreOrder());
}

TEST_F(AccessibilityTest, TreeNavigationWithContinuations) {
  // Continuations found in the layout tree should not appear in the
  // accessibility tree. For example, the following accessibility tree should
  // result from the following HTML.
  //
  // WebArea
  // ++HTMLElement
  // ++++BodyElement
  // ++++++Link
  // ++++++++StaticText "Before block element."
  // ++++++++GenericContainer
  // ++++++++++Paragraph
  // ++++++++++++StaticText "Inside block element."
  // ++++++++StaticText "After block element."
  SetBodyInnerHTML(R"HTML(
      <a id="link" href="#">
        Before block element.
        <div id="div">
          <p id="paragraph">
            Inside block element.
          </p>
        </div>
        After block element.
      </a>
      )HTML");

  const AXObject* ax_root = GetAXRootObject();
  ASSERT_NE(nullptr, ax_root);
  const AXObject* ax_body = GetAXBodyObject();
  ASSERT_NE(nullptr, ax_body);
  const AXObject* ax_link = GetAXObjectByElementId("link");
  ASSERT_NE(nullptr, ax_link);
  const AXObject* ax_text_before = ax_link->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text_before);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text_before->RoleValue());
  ASSERT_FALSE(ax_text_before->IsIgnored());
  const AXObject* ax_div = GetAXObjectByElementId("div");
  ASSERT_NE(nullptr, ax_div);
  const AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  const AXObject* ax_text_inside = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text_inside);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text_inside->RoleValue());
  ASSERT_FALSE(ax_text_inside->IsIgnored());
  const AXObject* ax_text_after = ax_link->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text_after);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text_after->RoleValue());
  ASSERT_FALSE(ax_text_after->IsIgnored());

  //
  // Test parent / child relationships individually. This is easier to debug
  // than printing the whole accessibility tree as a string and comparing with
  // an expected tree.
  //

  // BlockInInline changes |ax_body| not to be ignored. See the design doc at
  // crbug.com/716930 for more details.
  EXPECT_EQ(ax_body, ax_link->ParentObjectUnignored());
  EXPECT_EQ(ax_body, ax_link->ParentObjectIncludedInTree());

  EXPECT_EQ(ax_link, ax_text_before->ParentObjectUnignored());
  EXPECT_EQ(ax_link, ax_text_before->ParentObjectIncludedInTree());
  EXPECT_EQ(ax_link, ax_div->ParentObjectUnignored());
  EXPECT_EQ(ax_link, ax_div->ParentObjectIncludedInTree());
  EXPECT_EQ(ax_link, ax_text_after->ParentObjectUnignored());
  EXPECT_EQ(ax_link, ax_text_after->ParentObjectIncludedInTree());

  EXPECT_EQ(ax_div, ax_link->ChildAtIncludingIgnored(1));
  EXPECT_EQ(ax_div, ax_link->UnignoredChildAt(1));

  EXPECT_EQ(nullptr, ax_text_before->PreviousSiblingIncludingIgnored());
  EXPECT_EQ(nullptr, ax_text_before->UnignoredPreviousSibling());
  EXPECT_EQ(ax_div, ax_text_before->NextSiblingIncludingIgnored());
  EXPECT_EQ(ax_div, ax_text_before->UnignoredNextSibling());
  EXPECT_EQ(ax_div, ax_text_after->PreviousSiblingIncludingIgnored());
  EXPECT_EQ(ax_div, ax_text_after->UnignoredPreviousSibling());
  EXPECT_EQ(nullptr, ax_text_after->NextSiblingIncludingIgnored());
  EXPECT_EQ(nullptr, ax_text_after->UnignoredNextSibling());

  EXPECT_EQ(ax_paragraph, ax_div->ChildAtIncludingIgnored(0));
  EXPECT_EQ(ax_paragraph, ax_div->UnignoredChildAt(0));

  EXPECT_EQ(ax_div, ax_paragraph->ParentObjectUnignored());
  EXPECT_EQ(ax_div, ax_paragraph->ParentObjectIncludedInTree());
  EXPECT_EQ(ax_paragraph, ax_text_inside->ParentObjectUnignored());
  EXPECT_EQ(ax_paragraph, ax_text_inside->ParentObjectIncludedInTree());
}

TEST_F(AccessibilityTest, TreeNavigationWithInlineTextBoxes) {
  SetBodyInnerHTML(R"HTML(
      Before paragraph element.
      <p id="paragraph">
        Inside paragraph element.
      </p>
      After paragraph element.
      )HTML");

  AXObject* ax_root = GetAXRootObject();
  ASSERT_NE(nullptr, ax_root);
  ax_root->LoadInlineTextBoxes();

  const AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  const AXObject* ax_text_inside = ax_paragraph->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text_inside);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text_inside->RoleValue());
  const AXObject* ax_text_before = ax_paragraph->UnignoredPreviousSibling();
  ASSERT_NE(nullptr, ax_text_before);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText, ax_text_before->RoleValue());
  const AXObject* ax_text_after = ax_paragraph->UnignoredNextSibling();
  ASSERT_NE(nullptr, ax_text_after);
  ASSERT_EQ(ax::mojom::blink::Role::kStaticText, ax_text_after->RoleValue());

  //
  // Verify parent / child relationships between static text and inline text
  // boxes.
  //

  EXPECT_EQ(1, ax_text_before->ChildCountIncludingIgnored());
  EXPECT_EQ(1, ax_text_before->UnignoredChildCount());
  const AXObject* ax_inline_before =
      ax_text_before->FirstChildIncludingIgnored();
  EXPECT_EQ(ax::mojom::blink::Role::kInlineTextBox,
            ax_inline_before->RoleValue());
  EXPECT_EQ(ax_text_before, ax_inline_before->ParentObjectIncludedInTree());
  EXPECT_EQ(ax_text_before, ax_inline_before->ParentObjectUnignored());

  EXPECT_EQ(1, ax_text_inside->ChildCountIncludingIgnored());
  EXPECT_EQ(1, ax_text_inside->UnignoredChildCount());
  const AXObject* ax_inline_inside =
      ax_text_inside->FirstChildIncludingIgnored();
  EXPECT_EQ(ax::mojom::blink::Role::kInlineTextBox,
            ax_inline_inside->RoleValue());
  EXPECT_EQ(ax_text_inside, ax_inline_inside->ParentObjectIncludedInTree());
  EXPECT_EQ(ax_text_inside, ax_inline_inside->ParentObjectUnignored());

  EXPECT_EQ(1, ax_text_after->ChildCountIncludingIgnored());
  EXPECT_EQ(1, ax_text_after->UnignoredChildCount());
  const AXObject* ax_inline_after = ax_text_after->FirstChildIncludingIgnored();
  EXPECT_EQ(ax::mojom::blink::Role::kInlineTextBox,
            ax_inline_after->RoleValue());
  EXPECT_EQ(ax_text_after, ax_inline_after->ParentObjectIncludedInTree());
  EXPECT_EQ(ax_text_after, ax_inline_after->ParentObjectUnignored());
}

TEST_F(AccessibilityTest, AXObjectComparisonOperators) {
  SetBodyInnerHTML(R"HTML(<input id="input" type="text" value="value">
                   <p id="paragraph">hello<br id="br">there</p>
                   <button id="button">button</button>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, input);
  const AXObject* paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, paragraph);
  const AXObject* br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, br);
  const AXObject* button = GetAXObjectByElementId("button");
  ASSERT_NE(nullptr, button);

  EXPECT_TRUE(*root == *root);
  EXPECT_FALSE(*root != *root);
  EXPECT_FALSE(*root < *root);
  EXPECT_TRUE(*root <= *root);
  EXPECT_FALSE(*root > *root);
  EXPECT_TRUE(*root >= *root);

  EXPECT_TRUE(*input > *root);
  EXPECT_TRUE(*input >= *root);
  EXPECT_FALSE(*input < *root);
  EXPECT_FALSE(*input <= *root);

  EXPECT_TRUE(*input != *root);
  EXPECT_TRUE(*input < *paragraph);
  EXPECT_TRUE(*br > *input);
  EXPECT_TRUE(*paragraph < *br);
  EXPECT_TRUE(*br >= *paragraph);

  EXPECT_TRUE(*paragraph < *button);
  EXPECT_TRUE(*button > *br);
  EXPECT_FALSE(*button < *button);
  EXPECT_TRUE(*button <= *button);
  EXPECT_TRUE(*button >= *button);
  EXPECT_FALSE(*button > *button);
}

TEST_F(AccessibilityTest, AXObjectUnignoredAncestorsIterator) {
  SetBodyInnerHTML(
      R"HTML(<p id="paragraph"><b role="none" id="bold"><br id="br"></b></p>)HTML");

  AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  AXObject* paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, paragraph);
  AXObject* bold = GetAXObjectByElementId("bold");
  ASSERT_NE(nullptr, bold);
  AXObject* br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, br->RoleValue());

  AXObject::AncestorsIterator iter = br->UnignoredAncestorsBegin();
  EXPECT_EQ(*paragraph, *iter);
  EXPECT_EQ(ax::mojom::Role::kParagraph, iter->RoleValue());
  EXPECT_EQ(*root, *++iter);
  EXPECT_EQ(*root, *iter++);
  EXPECT_EQ(br->UnignoredAncestorsEnd(), ++iter);
}

TEST_F(AccessibilityTest, AxNodeObjectContainsHtmlAnchorElementUrl) {
  SetBodyInnerHTML(R"HTML(<a id="anchor" href="http://test.com">link</a>)HTML");

  const AXObject* root = GetAXRootObject();
  ASSERT_NE(nullptr, root);
  const AXObject* anchor = GetAXObjectByElementId("anchor");
  ASSERT_NE(nullptr, anchor);

  // Passing a malformed string to KURL returns an empty URL, so verify the
  // AXObject's URL is 
"""


```