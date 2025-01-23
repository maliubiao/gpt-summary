Response:
The user wants a summary of the functionality of the provided C++ code file, which is a test file for accessibility selection in the Chromium Blink engine.

Here's a plan:
1. Identify the main purpose of the file based on its name and included headers.
2. Analyze the test cases to understand the specific functionalities being tested.
3. Relate the functionalities to web technologies like JavaScript, HTML, and CSS if applicable.
4. Determine if any test cases involve logical reasoning and provide example inputs and outputs.
5. Identify potential user or programming errors that the tests might be uncovering.
6. Explain how a user's actions could lead to this code being executed as part of debugging.
7. Finally, summarize the overall functionality of the file.
这是 `blink/renderer/modules/accessibility/ax_selection_test.cc` 文件的第一部分，主要功能是 **测试 Blink 渲染引擎中关于可访问性 (Accessibility) 选择 (Selection) 的相关功能**。  它使用 Google Test 框架来验证 `AXSelection` 类的各种方法和行为是否符合预期。

**与 JavaScript, HTML, CSS 的功能关系：**

这个测试文件直接测试了与用户在网页上进行文本或元素选择相关的底层机制，而这些选择通常是通过 JavaScript API（如 `document.getSelection()`) 或用户的鼠标/键盘操作在 HTML 结构和 CSS 样式渲染出的页面上发生的。

* **JavaScript:**
    * **例子：** 在 `FromCurrentSelection` 测试中，JavaScript 代码被用来模拟用户在页面上进行选择的操作：
        ```javascript
        let text1 = document.querySelectorAll('p')[0].firstChild;
        let paragraph2 = document.querySelectorAll('p')[1];
        let range = document.createRange();
        range.setStart(text1, 3);
        range.setEnd(paragraph2, 1);
        let selection = getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
        ```
        这个 JavaScript 代码创建了一个 Range 对象，并将其设置为选择的范围，然后使用 `getSelection()` API 将其应用到当前的选择。`ax_selection_test.cc` 中的代码会读取这个选择，并验证 `AXSelection::FromCurrentSelection` 方法是否能正确地将其转换为可访问性树中的表示。
    * **关系：** 测试验证了当 JavaScript 修改页面选择时，`AXSelection` 能否正确反映这些变化。
* **HTML:**
    * **例子：**  所有测试用例都使用 `SetBodyInnerHTML()` 来设置 HTML 内容，作为测试的基础。例如：
        ```html
        <p id="paragraph1">Hello.</p>
        <p id="paragraph2">How are you?</p>
        ```
        这个 HTML 结构定义了页面上的文本内容和元素，这些是用户可能进行选择的对象。
    * **关系：** 测试验证了 `AXSelection` 如何处理不同 HTML 结构中的选择，例如跨越段落、在文本节点内部、跨越 `<br>` 标签等。
* **CSS:**
    * **例子：** 在 `SetSelectionInDisplayNone` 测试中，使用了 `style="display:none"` 来隐藏元素。
        ```html
        <p id="hidden1" style="display:none">Display:none 1.</p>
        ```
    * **关系：** 测试验证了 `AXSelection` 如何处理被 CSS 隐藏的元素，以及在创建可访问性选择时是否会考虑这些元素的因素。例如，测试了当选择的起始或结束点位于 `display:none` 的元素内部时，`AXSelection` 如何调整选择范围。

**逻辑推理与假设输入/输出：**

* **例子：** `FromCurrentSelection` 测试就是一个逻辑推理的例子。
    * **假设输入：**  JavaScript 代码设置了一个从 "Hello." 的 "l" 字符（偏移量 3）开始，到 "How are you?" 的段落节点（子节点索引 1）结束的选择。
    * **逻辑推理：** `AXSelection::FromCurrentSelection` 应该能够将这个 DOM 选择转换为 `AXSelection` 对象，其中：
        * Anchor (起始点) 应该是一个文本位置，位于 "Hello." 的可访问性对象中，偏移量为 3。
        * Focus (结束点) 应该是一个容器位置，位于 "How are you?" 的可访问性对象中，子节点索引为 1。
    * **预期输出：** 测试断言验证了 `ax_selection.Anchor()` 和 `ax_selection.Focus()` 的属性值是否与预期一致。`GetSelectionText(ax_selection)` 的输出也验证了选择覆盖的文本范围。

**用户或编程常见的使用错误：**

* **用户错误：** 用户可能会尝试选择屏幕上不可见的元素（例如，`display: none` 的元素）。`SetSelectionInDisplayNone` 测试就模拟了这种情况，并验证了 `AXSelection` 在处理这类选择时的行为，例如扩展或收缩选择到可见的边界。
* **编程错误：** 开发者在编写 JavaScript 代码时，可能会错误地设置选择的起始或结束节点，或者计算错误的偏移量。`ax_selection_test.cc` 中的测试可以帮助发现 `AXSelection` 在处理这些不合理的输入时的鲁棒性。例如，如果 `AXSelection::FromSelection` 没有正确处理起始或结束点位于已忽略的元素中的情况，测试将会失败。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中打开一个网页。**
2. **用户使用鼠标拖拽或键盘快捷键（如 Shift + 方向键）在网页上选择文本或元素。** 这会触发浏览器底层的选择机制，并更新 DOM 树中的 Selection 对象。
3. **如果启用了辅助功能（例如，使用了屏幕阅读器），或者某些代码需要获取当前的选择信息以进行进一步处理（例如，复制粘贴功能），Blink 渲染引擎会创建或更新可访问性树 (Accessibility Tree)。**
4. **`AXSelection::FromCurrentSelection(GetDocument())` 或类似的方法会被调用，以将当前的 DOM 选择转换为 `AXSelection` 对象。** 这个对象是可访问性 API 的一部分，用于向辅助技术描述当前的选择状态。
5. **在调试过程中，开发者可能会在 `AXSelection::FromCurrentSelection` 或其相关的代码中设置断点，以检查当用户进行选择操作时，`AXSelection` 对象是如何创建和更新的。**  `ax_selection_test.cc` 文件中的测试用例就是为了模拟各种用户选择场景，并验证 `AXSelection` 相关的逻辑是否正确。

**功能归纳（第 1 部分）：**

总而言之，`ax_selection_test.cc` 的第一部分主要测试了 `AXSelection` 类 **从当前的 DOM 选择中创建 `AXSelection` 对象的能力**，以及 **清除当前选择** 和 **取消选择操作** 的功能。 它还测试了 **设置 `AXSelection` 对象并将其应用到 DOM 树** 的基本情况，包括在文本节点内部、跨越多行文本框以及跨越换行符的选择。  此外，它还初步测试了当选择的端点位于被 CSS 隐藏的元素时，`AXSelection` 的处理方式。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_selection_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/ax_selection.h"

#include <string>

#include "base/logging.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_focus_options.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_paragraph_element.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_position.h"
#include "third_party/blink/renderer/modules/accessibility/testing/accessibility_selection_test.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {
namespace test {

//
// Basic tests.
//

TEST_F(AccessibilitySelectionTest, FromCurrentSelection) {
  GetPage().GetSettings().SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph1">Hello.</p>
      <p id="paragraph2">How are you?</p>
      )HTML");

  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      let text1 = document.querySelectorAll('p')[0].firstChild;
      let paragraph2 = document.querySelectorAll('p')[1];
      let range = document.createRange();
      range.setStart(text1, 3);
      range.setEnd(paragraph2, 1);
      let selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);

  const AXObject* ax_static_text_1 =
      GetAXObjectByElementId("paragraph1")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text_1);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text_1->RoleValue());
  const AXObject* ax_paragraph_2 = GetAXObjectByElementId("paragraph2");
  ASSERT_NE(nullptr, ax_paragraph_2);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph_2->RoleValue());

  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  ASSERT_TRUE(ax_selection.IsValid());

  ASSERT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_static_text_1, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(3, ax_selection.Anchor().TextOffset());

  ASSERT_FALSE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_paragraph_2, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(1, ax_selection.Focus().ChildIndex());

  EXPECT_EQ(
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: Hel^lo.>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: How are you?>\n|",
      GetSelectionText(ax_selection));
}

TEST_F(AccessibilitySelectionTest, FromCurrentSelectionSelectAll) {
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph1">Hello.</p>
      <p id="paragraph2">How are you?</p>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());
  Selection().SelectAll(SetSelectionBy::kUser);
  UpdateAllLifecyclePhasesForTest();
  ASSERT_NE(nullptr, GetAXRootObject());

  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  ASSERT_TRUE(ax_selection.IsValid());

  ASSERT_FALSE(ax_selection.Anchor().IsTextPosition());

  AXObject* html_object = GetAXRootObject()->ChildAtIncludingIgnored(0);
  ASSERT_NE(nullptr, html_object);
  EXPECT_EQ(html_object, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(0, ax_selection.Anchor().ChildIndex());

  ASSERT_FALSE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(html_object, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(html_object->ChildCountIncludingIgnored(),
            ax_selection.Focus().ChildIndex());

  EXPECT_EQ(
      "++<GenericContainer>\n"
      "^++++<GenericContainer>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: Hello.>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: How are you?>\n|",
      GetSelectionText(ax_selection));
}

TEST_F(AccessibilitySelectionTest, ClearCurrentSelection) {
  GetPage().GetSettings().SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
      <p>Hello.</p>
      <p>How are you?</p>
      )HTML");

  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      let text1 = document.querySelectorAll('p')[0].firstChild;
      let paragraph2 = document.querySelectorAll('p')[1];
      let range = document.createRange();
      range.setStart(text1, 3);
      range.setEnd(paragraph2, 1);
      let selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  SelectionInDOMTree selection = Selection().GetSelectionInDOMTree();
  ASSERT_FALSE(selection.IsNone());

  AXSelection::ClearCurrentSelection(GetDocument());
  selection = Selection().GetSelectionInDOMTree();
  EXPECT_TRUE(selection.IsNone());

  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  EXPECT_FALSE(ax_selection.IsValid());
  EXPECT_EQ("", GetSelectionText(ax_selection));
}

TEST_F(AccessibilitySelectionTest, CancelSelect) {
  GetPage().GetSettings().SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph1">Hello.</p>
      <p id="paragraph2">How are you?</p>
      )HTML");

  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      document.addEventListener("selectstart", (e) => {
        e.preventDefault();
      }, false);
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  const AXObject* ax_static_text_1 =
      GetAXObjectByElementId("paragraph1")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text_1);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text_1->RoleValue());
  const AXObject* ax_paragraph_2 = GetAXObjectByElementId("paragraph2");
  ASSERT_NE(nullptr, ax_paragraph_2);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph_2->RoleValue());

  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder
          .SetAnchor(
              AXPosition::CreatePositionInTextObject(*ax_static_text_1, 3))
          .SetFocus(AXPosition::CreateLastPositionInObject(*ax_paragraph_2))
          .Build();

  EXPECT_FALSE(ax_selection.Select()) << "The operation has been cancelled.";
  EXPECT_TRUE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  GetDocument().RemoveAllEventListeners();

  EXPECT_TRUE(ax_selection.Select()) << "The operation should now go through.";
  EXPECT_FALSE(Selection().GetSelectionInDOMTree().IsNone());
  EXPECT_EQ(
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: Hel^lo.>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: How are you?>\n|",
      GetSelectionText(AXSelection::FromCurrentSelection(GetDocument())));
}

TEST_F(AccessibilitySelectionTest, DocumentRangeMatchesSelection) {
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph1">Hello.</p>
      <p id="paragraph2">How are you?</p>
      )HTML");

  const AXObject* ax_static_text_1 =
      GetAXObjectByElementId("paragraph1")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text_1);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text_1->RoleValue());
  const AXObject* ax_paragraph_2 = GetAXObjectByElementId("paragraph2");
  ASSERT_NE(nullptr, ax_paragraph_2);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph_2->RoleValue());

  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder
          .SetAnchor(
              AXPosition::CreatePositionInTextObject(*ax_static_text_1, 3))
          .SetFocus(AXPosition::CreateLastPositionInObject(*ax_paragraph_2))
          .Build();
  EXPECT_TRUE(ax_selection.Select());
  ASSERT_FALSE(Selection().GetSelectionInDOMTree().IsNone());
  ASSERT_NE(nullptr, Selection().DocumentCachedRange());
  EXPECT_EQ(String("lo.\n      How are you?"),
            Selection().DocumentCachedRange()->toString());
}

TEST_F(AccessibilitySelectionTest, SetSelectionInText) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");

  const Node* text =
      GetDocument().QuerySelector(AtomicString("p"))->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());

  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_base =
      AXPosition::CreatePositionInTextObject(*ax_static_text, 3);
  const auto ax_extent = AXPosition::CreatePositionAfterObject(*ax_static_text);

  AXSelection::Builder builder;
  const AXSelection ax_selection =
      builder.SetAnchor(ax_base).SetFocus(ax_extent).Build();
  const SelectionInDOMTree dom_selection = ax_selection.AsSelection();
  EXPECT_EQ(text, dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(3, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(text, dom_selection.Focus().AnchorNode());
  EXPECT_EQ(5, dom_selection.Focus().OffsetInContainerNode());
  EXPECT_EQ(
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: Hel^lo|>\n",
      GetSelectionText(ax_selection));
}

TEST_F(AccessibilitySelectionTest, SetSelectionInMultilineTextarea) {
// On Android we use an ifdef to disable inline text boxes.
#if !BUILDFLAG(IS_ANDROID)
  ui::AXMode mode(ui::kAXModeComplete);
  mode.set_mode(ui::AXMode::kInlineTextBoxes, true);
  ax_context_->SetAXMode(mode);
  GetAXObjectCache().MarkDocumentDirty();
  GetAXObjectCache().UpdateAXForAllDocuments();

  LoadAhem();

  SetBodyInnerHTML(R"HTML(
    <textarea id="txt" style="width:80px; height:81px; font-family: Ahem; font-size: 4;">hello text go blue</textarea>
    )HTML");
  // This HTML generates the following ax tree:
  // id#=13 rootWebArea
  // ++id#=14 genericContainer
  // ++++id#=15 genericContainer
  // ++++++id#=16 textField
  // ++++++++id#=17 genericContainer
  // ++++++++++id#=18 staticText name='hello text go blue<newline>'
  // ++++++++++++id#=20 inlineTextBox name='hello'
  // ++++++++++++id#=22 inlineTextBox name='text'
  // ++++++++++++id#=22 inlineTextBox name='go'
  // ++++++++++++id#=22 inlineTextBox name='blue'

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  textarea->Focus(FocusOptions::Create());
  ASSERT_TRUE(textarea->IsFocusedElementInDocument());

  const AXObject* ax_textarea = GetAXObjectByElementId("txt");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  AXObject* ax_inline_text_box = ax_textarea->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax_inline_text_box->RoleValue(),
            ax::mojom::Role::kGenericContainer);

  ax_inline_text_box = ax_inline_text_box->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax_inline_text_box->ComputedName(), "hello text go blue");
  ASSERT_EQ(ax_inline_text_box->RoleValue(), ax::mojom::Role::kStaticText);

  ax_inline_text_box = ax_inline_text_box->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax_inline_text_box->ComputedName(), "hello");
  ASSERT_EQ(ax_inline_text_box->RoleValue(), ax::mojom::Role::kInlineTextBox);

  ax_inline_text_box = ax_inline_text_box->NextSiblingIncludingIgnored()
                           ->NextSiblingIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax_inline_text_box->RoleValue(), ax::mojom::Role::kInlineTextBox);
  ASSERT_EQ(ax_inline_text_box->ComputedName(), "text");

  ax_inline_text_box = ax_inline_text_box->NextSiblingIncludingIgnored()
                           ->NextSiblingIncludingIgnored();
  ASSERT_NE(nullptr, ax_inline_text_box);
  ASSERT_EQ(ax_inline_text_box->RoleValue(), ax::mojom::Role::kInlineTextBox);
  ASSERT_EQ(ax_inline_text_box->ComputedName(), "go");

  const auto ax_base =
      AXPosition::CreatePositionInTextObject(*ax_inline_text_box, 0);
  const auto ax_extent =
      AXPosition::CreatePositionInTextObject(*ax_inline_text_box, 2);

  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(ax_base).SetFocus(ax_extent).Build();

  EXPECT_TRUE(ax_selection.Select());

  // Even though the selection is set to offsets 0,4 "text" in the inline text
  // box, the selection needs to end up in offsets 12,16 on the whole textarea
  // so that "text" is the selection.
  EXPECT_EQ(11u, ToTextControl(*textarea).selectionStart());
  EXPECT_EQ(13u, ToTextControl(*textarea).selectionEnd());
#endif  // !BUILDFLAG(IS_ANDROID)
}

TEST_F(AccessibilitySelectionTest, SetSelectionInTextWithWhiteSpace) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">     Hello</p>)HTML");

  const Node* text =
      GetDocument().QuerySelector(AtomicString("p"))->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());

  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  const auto ax_base =
      AXPosition::CreatePositionInTextObject(*ax_static_text, 3);
  const auto ax_extent = AXPosition::CreatePositionAfterObject(*ax_static_text);

  AXSelection::Builder builder;
  const AXSelection ax_selection =
      builder.SetAnchor(ax_base).SetFocus(ax_extent).Build();
  const SelectionInDOMTree dom_selection = ax_selection.AsSelection();
  EXPECT_EQ(text, dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(8, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(text, dom_selection.Focus().AnchorNode());
  EXPECT_EQ(10, dom_selection.Focus().OffsetInContainerNode());
  EXPECT_EQ(
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: Hel^lo|>\n",
      GetSelectionText(ax_selection));
}

TEST_F(AccessibilitySelectionTest, SetSelectionAcrossLineBreak) {
  SetBodyInnerHTML(R"HTML(
      <p id="paragraph">Hello<br id="br">How are you.</p>
      )HTML");

  const Node* paragraph = GetDocument().QuerySelector(AtomicString("p"));
  ASSERT_NE(nullptr, paragraph);
  ASSERT_TRUE(IsA<HTMLParagraphElement>(paragraph));
  const Node* br = GetDocument().QuerySelector(AtomicString("br"));
  ASSERT_NE(nullptr, br);
  ASSERT_TRUE(IsA<HTMLBRElement>(br));
  const Node* line2 =
      GetDocument().QuerySelector(AtomicString("p"))->lastChild();
  ASSERT_NE(nullptr, line2);
  ASSERT_TRUE(line2->IsTextNode());

  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_line2 =
      GetAXObjectByElementId("paragraph")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_line2);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_line2->RoleValue());

  const auto ax_base = AXPosition::CreatePositionBeforeObject(*ax_br);
  const auto ax_extent = AXPosition::CreatePositionInTextObject(*ax_line2, 0);

  AXSelection::Builder builder;
  const AXSelection ax_selection =
      builder.SetAnchor(ax_base).SetFocus(ax_extent).Build();
  const SelectionInDOMTree dom_selection = ax_selection.AsSelection();
  EXPECT_EQ(paragraph, dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(1, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(line2, dom_selection.Focus().AnchorNode());
  EXPECT_EQ(0, dom_selection.Focus().OffsetInContainerNode());

  // The selection anchor marker '^' should be before the line break and the
  // selection focus marker '|' should be after it.
  EXPECT_EQ(
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: Hello>\n"
      "^++++++++<LineBreak: \n>\n"
      "|++++++++<StaticText: |How are you.>\n",
      GetSelectionText(ax_selection));
}

TEST_F(AccessibilitySelectionTest, SetSelectionAcrossLineBreakInEditableText) {
  SetBodyInnerHTML(R"HTML(
      <p contenteditable id="paragraph">Hello<br id="br">How are you.</p>
      )HTML");

  const Node* paragraph = GetDocument().QuerySelector(AtomicString("p"));
  ASSERT_NE(nullptr, paragraph);
  ASSERT_TRUE(IsA<HTMLParagraphElement>(paragraph));
  const Node* br = GetDocument().QuerySelector(AtomicString("br"));
  ASSERT_NE(nullptr, br);
  ASSERT_TRUE(IsA<HTMLBRElement>(br));
  const Node* line2 =
      GetDocument().QuerySelector(AtomicString("p"))->lastChild();
  ASSERT_NE(nullptr, line2);
  ASSERT_TRUE(line2->IsTextNode());

  const AXObject* ax_br = GetAXObjectByElementId("br");
  ASSERT_NE(nullptr, ax_br);
  ASSERT_EQ(ax::mojom::Role::kLineBreak, ax_br->RoleValue());
  const AXObject* ax_line2 =
      GetAXObjectByElementId("paragraph")->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_line2);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_line2->RoleValue());

  const auto ax_base = AXPosition::CreatePositionBeforeObject(*ax_br);
  // In the case of text objects, the deep equivalent position should always be
  // returned, i.e. a text position before the first character.
  const auto ax_extent = AXPosition::CreatePositionBeforeObject(*ax_line2);

  AXSelection::Builder builder;
  const AXSelection ax_selection =
      builder.SetAnchor(ax_base).SetFocus(ax_extent).Build();
  const SelectionInDOMTree dom_selection = ax_selection.AsSelection();
  EXPECT_EQ(paragraph, dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(1, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(line2, dom_selection.Focus().AnchorNode());
  EXPECT_EQ(0, dom_selection.Focus().OffsetInContainerNode());

  // The selection anchor marker '^' should be before the line break and the
  // selection focus marker '|' should be after it.
  EXPECT_EQ(
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Paragraph>\n"
      "++++++++<StaticText: Hello>\n"
      "^++++++++<LineBreak: \n>\n"
      "|++++++++<StaticText: |How are you.>\n",
      GetSelectionText(ax_selection));
}

//
// Get selection tests.
// Retrieving a selection with endpoints which have corresponding ignored
// objects in the accessibility tree, e.g. which are display:none, should shrink
// or extend the |AXSelection| to valid endpoints.
// Note: aria-describedby adds hidden target subtrees to the a11y tree as
// "ignored but included in tree".
//

TEST_F(AccessibilitySelectionTest, SetSelectionInDisplayNone) {
  SetBodyInnerHTML(R"HTML(
      <div id="main" role="main" aria-describedby="hidden1 hidden2">
        <p id="beforeHidden">Before display:none.</p>
        <p id="hidden1" style="display:none">Display:none 1.</p>
        <p id="betweenHidden">In between two display:none elements.</p>
        <p id="hidden2" style="display:none">Display:none 2.</p>
        <p id="afterHidden">After display:none.</p>
      </div>
      )HTML");

  const Node* hidden_1 = GetElementById("hidden1");
  ASSERT_NE(nullptr, hidden_1);
  const Node* hidden_2 = GetElementById("hidden2");
  ASSERT_NE(nullptr, hidden_2);

  const AXObject* ax_main = GetAXObjectByElementId("main");
  ASSERT_NE(nullptr, ax_main);
  ASSERT_EQ(ax::mojom::Role::kMain, ax_main->RoleValue());
  const AXObject* ax_before = GetAXObjectByElementId("beforeHidden");
  ASSERT_NE(nullptr, ax_before);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_before->RoleValue());
  const AXObject* ax_hidden1 = GetAXObjectByElementId("hidden1");
  ASSERT_NE(nullptr, ax_hidden1);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_hidden1->RoleValue());
  ASSERT_TRUE(ax_hidden1->IsIgnored());
  ASSERT_TRUE(ax_hidden1->IsIncludedInTree());
  const AXObject* ax_hidden1_text = ax_hidden1->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_hidden1_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_hidden1_text->RoleValue());
  ASSERT_TRUE(ax_hidden1_text->IsIgnored());
  ASSERT_TRUE(ax_hidden1_text->IsIncludedInTree());
  const AXObject* ax_between = GetAXObjectByElementId("betweenHidden");
  ASSERT_NE(nullptr, ax_between);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_between->RoleValue());
  const AXObject* ax_hidden2 = GetAXObjectByElementId("hidden2");
  ASSERT_NE(nullptr, ax_hidden2);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_hidden2->RoleValue());
  ASSERT_TRUE(ax_hidden2->IsIgnored());
  ASSERT_TRUE(ax_hidden2->IsIncludedInTree());
  const AXObject* ax_hidden2_text = ax_hidden2->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_hidden2_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_hidden2_text->RoleValue());
  ASSERT_TRUE(ax_hidden2_text->IsIgnored());
  ASSERT_TRUE(ax_hidden2_text->IsIncludedInTree());
  const AXObject* ax_after = GetAXObjectByElementId("afterHidden");
  ASSERT_NE(nullptr, ax_after);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_after->RoleValue());

  const auto hidden_1_first = Position::FirstPositionInNode(*hidden_1);
  const auto hidden_2_first = Position::FirstPositionInNode(*hidden_2);
  const auto selection = SelectionInDOMTree::Builder()
                             .SetBaseAndExtent(hidden_1_first, hidden_2_first)
                             .Build();

  const auto ax_selection_shrink = AXSelection::FromSelection(
      selection, AXSelectionBehavior::kShrinkToValidRange);
  const auto ax_selection_extend = AXSelection::FromSelection(
      selection, AXSelectionBehavior::kExtendToValidRange);

  // The "display: none" content is included in the AXTree as an ignored node,
  // so shrunk selection should include those AXObjects. The tree in the browser
  // process also includes those ignored nodes, and the position will be
  // adjusted according to AXPosition rules; in particular, a position anchored
  // before a text node is explicitly moved to before the first character of the
  // text object.
  ASSERT_TRUE(ax_selection_shrink.Anchor().IsTextPosition());
  EXPECT_EQ(ax_hidden1_text, ax_selection_shrink.Anchor().ContainerObject());
  EXPECT_EQ(0, ax_selection_shrink.Anchor().TextOffset());
  ASSERT_TRUE(ax_selection_shrink.Focus().IsTextPosition());
  EXPECT_EQ(ax_hidden2_text, ax_selection_shrink.Focus().ContainerObject());
  EXPECT_EQ(0, ax_selection_shrink.Focus().TextOffset());

  // The extended selection should start in the "display: none" content because
  // they are included in the AXTree. Similarly to above, the position will be
  // adjusted to point to the first character of the text object.
  ASSERT_TRUE(ax_selection_extend.Anchor().IsTextPosition());
  EXPECT_EQ(ax_hidden1_text, ax_selection_extend.Anchor().ContainerObject());
  EXPECT_EQ(0, ax_selection_extend.Anchor().TextOffset());
  ASSERT_TRUE(ax_selection_extend.Focus().IsTextPosition());
  EXPECT_EQ(ax_hidden2_text, ax_selection_extend.Focus().ContainerObject());
  EXPECT_EQ(0, ax_selection_extend.Focus().TextOffset());

  // Even though the two AX selections have different anchors and foci, the text
  // selected in the accessibility tree should not differ, because any
  // differences in the equivalent DOM selections concern elements that are
  // display:none. However, the AX selections should still differ if converted
  // to DOM selections.
  const std::string selection_text(
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Main>\n"
      "++++++++<Paragraph>\n"
      "++++++++++<StaticText: Before display:none.>\n"
      "++++++++<Paragraph>\n"
      "^++++++++++<StaticText: ^Display:none 1.>\n"
      "++++++++<Paragraph>\n"
      "++++++++++<StaticText: In between two display:none elements.>\n"
      "++++++++<Paragraph>\n"
      "|++++++++++<StaticText: |Display:none 2.>\n"
      "++++++++<Paragraph>\n"
      "++++++++++<StaticText: After display:none.>\n");
  EXPECT_EQ(selection_text, GetSelectionText(ax_selection_shrink));
  EXPECT_EQ(selection_text, GetSelectionText(ax_selection_extend));
}

//
// Set selection tests.
// Setting the selection from an |AXSelection| that has endpoints which are not
// present in the layout tree should shrink or extend the selection to visible
// endpoints.
//

TEST_F(AccessibilitySelectionTest, SetSelectionAroundListBullet) {
  SetBodyInnerHTML(R"HTML(
      <div role="main">
        <ul>
          <li id="item1">Item 1.</li>
          <li id="item2">Item 2.</li>
        </ul>
      </div>
      )HTML");

  const Node* item_1 = GetElementById("item1");
  ASSERT_NE(nullptr, item_1);
  ASSERT_FALSE(item_1->IsTextNode());
  const Node* text_1 = item_1->firstChild();
  ASSERT_NE(nullptr, text_1);
  ASSERT_TRUE(text_1->IsTextNode());
  const Node* item_2 = GetElementById("item2");
  ASSERT_NE(nullptr, item_2);
  ASSERT_FALSE(item_2->IsTextNode());
  const Node* text_2 = item_2->firstChild();
  ASSERT_NE(nullptr, text_2);
  ASSERT_TRUE(text_2->IsTextNode());

  const AXObject* ax_item_1 = GetAXObjectByElementId("item1");
  ASSERT_NE(nullptr, ax_item_1);
  ASSERT_EQ(ax::mojom::Role::kListItem, ax_item_1->RoleValue());
  const AXObject* ax_bullet_1 = ax_item_1->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_bullet_1);
  ASSERT_EQ(ax::mojom::Role::kListMarker, ax_bullet_1->RoleValue());
  const AXObject* ax_item_2 = GetAXObjectByElementId("item2");
  ASSERT_NE(nullptr, ax_item_2);
  ASSERT_EQ(ax::mojom::Role::kListItem, ax_item_2->RoleValue());
  const AXObject* ax_text_2 = ax_item_2->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text_2);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text_2->RoleValue());

  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreateFirstPositionInObject(*ax_bullet_1))
          .SetFocus(AXPosition::CreateLastPositionInObject(*ax_text_2))
          .Build();

  // The list bullet is not included in the DOM tree. Shrinking the
  // |AXSelection| should skip over it by creating an anchor before the first
  // child of the first <li>, i.e. the text node containing the text "Item 1.".
  // This should be further optimized to a text position at the start of the
  // text object inside the first <li>.
  ax_selection.Select(AXSelectionBehavior::kShrinkToValidRange);
  const SelectionInDOMTree shrunk_selection =
      Selection().GetSelectionInDOMTree();

  EXPECT_EQ(text_1, shrunk_selection.Anchor().AnchorNode());
  ASSERT_TRUE(shrunk_selection.Anchor().IsOffsetInAnchor());
  EXPECT_EQ(0, shrunk_selection.Anchor().OffsetInContainerNode());
  ASSERT_TRUE(shrunk_selection.Focus().IsOffsetInAnchor());
  EXPECT_EQ(text_2, shrunk_selection.Focus().AnchorNode());
  EXPECT_EQ(7, shrunk_selection.Focus().OffsetInContainerNode());

  // The list bullet is not included in the DOM tree. Extending the
  // |AXSelection| should move the anchor to before the first <li>.
  ax_selection.Select(AXSelectionBehavior::kExtendToValidRange);
  const SelectionInDOMTree extended_selection =
      Selection().GetSelectionInDOMTree();

  ASSERT_TRUE(extended_selection.Anchor().IsOffsetInAnchor());
  EXPECT_EQ(item_1->parentNode(), extended_selection.Anchor().AnchorNode());
  EXPECT_EQ(static_cast<int>(item_1->NodeIndex()),
            extended_selection.Anchor().OffsetInContainerNode());
  ASSERT_TRUE(extended_selection.Focus().IsOffsetInAnchor());
  EXPECT_EQ(text_2, extended_selection.Focus().AnchorNode());
  EXPECT_EQ(7, extended_selection.Focus().OffsetInContainerNode());

  std::string expectations;
  expectations =
      "++<GenericContainer>\n"
      "++++<GenericContainer>\n"
      "++++++<Main>\n"
      "++++++++<List>\n"
      "++++++++++<ListItem>\n"
      "++++++++++++<ListMarker: \xE2\x80\xA2 >\n"
      "^++++++++++++++<StaticText: ^\xE2\x80\xA2 >\n"
      "++++++++++++<StaticText: Item 1.>\n"
      "++++++++++<ListItem>\n"
      "++++++++++++<ListMarker: \xE2\x80\xA2 >\n"
      "++++++++++++++<StaticText: \xE2\x80\xA2 >\n"
      "++++++++++++<StaticText: Item 2.|>\n";

  // The |AXSelection| should remain unaffected by any shrinking and should
  // include both list bullets.
  EXPECT_EQ(expectations, GetSelectionText(ax_selection));
}

//
// Tests that involve selection inside, outside, and spanning text controls.
//

TEST_F(AccessibilitySelectionTest, FromCurrentSelectionInTextField) {
  GetPage().GetSettings().SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
      <input id="input" value="Inside text field.">
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      let input = document.querySelector('input');
      input.focus();
      input.selectionStart = 0;
      input.selectionEnd = input.value.length;
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  const Element* input = GetDocument().QuerySelector(AtomicString("input"));
  ASSERT_NE(nullptr, input);
  ASSERT_TRUE(IsTextControl(input));

  const AXObject* ax_input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, ax_input);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_input->RoleValue());

  const auto ax_selection =
      AXSelection::FromCurrentSelection(ToTextControl(*input));
  ASSERT_TRUE(ax_selection.IsValid());

  ASSERT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_input, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(0, ax_selection.Anchor().TextOffset());
  EXPECT_EQ(TextAffinity::kDownstream, ax_selection.Anchor().Affinity());
  ASSERT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_input, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(18, ax_selection.Focus().TextOffset());
  EXPECT_EQ(TextAffinity::kDownstream, ax_selection.Focus().Affinity());
}

TEST_F(AccessibilitySelectionTest, FromCurrentSelectionInTextarea) {
  GetPage().GetSettings().SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
      <textarea id="textarea">
        Inside
        textarea
        field.
      </textarea>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      let textarea = document.querySelector('textarea');
      textarea.focus();
      textarea.selectionStart = 0;
      textarea.selectionEnd = textarea.textLength;
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  const Element* textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));

  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  const
```