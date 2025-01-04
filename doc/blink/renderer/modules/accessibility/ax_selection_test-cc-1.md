Response:
The user wants a summary of the functionality of the provided C++ code snippet from `ax_selection_test.cc`. This code snippet contains a series of tests related to accessibility selections, primarily focusing on text fields and textareas.

Here's a breakdown of the logic involved:

1. **Identify the core purpose:** The file tests the `AXSelection` class, which represents an accessibility selection.

2. **Analyze each test case:**  Each `TEST_F` function focuses on a specific scenario for creating or manipulating accessibility selections. Key aspects to note are:
    - The type of element being tested (input, textarea, contenteditable).
    - How the selection is being created or modified (using `FromCurrentSelection`, `AXSelection::Builder`, JavaScript manipulation of the DOM selection).
    - The specific scenarios being tested (e.g., selection with affinity, collapsed selections, selections spanning line breaks).
    - The assertions being made (e.g., validating the anchor and focus points of the accessibility selection, checking the DOM selection).

3. **Look for connections to web technologies:** Identify how the tests interact with HTML (structure of the DOM), JavaScript (for manipulating the DOM and selection), and implicitly CSS (via the `style` attribute, though not directly tested for its effect on selection).

4. **Extract assumptions and potential errors:**  Note where the tests rely on specific DOM structures or user interactions. Consider scenarios where these assumptions might be violated, leading to errors.

5. **Trace user actions:** Think about how a user might interact with a webpage to trigger the scenarios being tested (e.g., typing in a text field, using keyboard shortcuts to select text).

6. **Synthesize the information into a concise summary:** Combine the observations from the individual test cases into a high-level description of the file's overall purpose.
这是 `blink/renderer/modules/accessibility/ax_selection_test.cc` 文件的第二部分内容，延续了第一部分的功能，主要集中在测试 **`AXSelection` 类** 的功能，特别是与 **`<textarea>` 元素** 相关的操作，并涵盖了一些更复杂的情况。

以下是这段代码的功能归纳：

**主要功能：**

这段代码主要测试了 `AXSelection` 类与 `<textarea>` 元素交互的各种场景，包括：

1. **从当前 DOM 选择创建 `AXSelection` 对象：**  测试了在 `<textarea>` 元素中存在用户选择时，如何通过 `AXSelection::FromCurrentSelection` 方法创建一个与之对应的 `AXSelection` 对象，并验证其锚点（Anchor）和焦点（Focus）的位置、偏移量（TextOffset）和文本方向性（Affinity）。

2. **处理 `<textarea>` 中的文本方向性（Affinity）：** 重点测试了当用户在 `<textarea>` 中进行选择时，`AXSelection` 对象如何正确地反映选择的文本方向性，即使底层 DOM 选择可能具有不同的方向性。

3. **处理 `<textarea>` 中折叠的选择和文本方向性：**  测试了当 `<textarea>` 中的选择是折叠的（即光标位置）时，`AXSelection` 对象如何正确地反映文本方向性。

4. **清除文本字段和文本区域的当前选择：**  测试了 `AXSelection::ClearCurrentSelection` 方法是否能够正确清除 `<input type="text">` 和 `<textarea>` 元素中的用户选择。

5. **通过 `AXSelection::Builder` 创建并设置 `<textarea>` 的选择：**
   - 测试了如何使用 `AXSelection::Builder` 创建一个 `AXSelection` 对象，并将其应用于 `<textarea>` 元素，模拟向前和向后选择的情况。
   - 验证了设置后的 `<textarea>` 的 `selectionStart`、`selectionEnd` 和 `selectionDirection` 属性是否与预期的 `AXSelection` 对象一致。

6. **选择整个 `<textarea>` 的内容：** 测试了如何创建一个 `AXSelection` 对象来选中整个 `<textarea>` 元素，即使该元素没有焦点。这涉及到使用 `AXPosition::CreatePositionBeforeObject` 和 `AXPosition::CreatePositionAfterObject` 来定义选择的边界。

7. **选择 `<textarea>` 中的每个连续字符：** 测试了如何通过 `AXSelection` 对象逐步选择 `<textarea>` 中的每个字符，包括向前和向后选择。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** 代码中通过 `SetBodyInnerHTML` 方法动态创建包含 `<textarea>` 元素的 HTML 结构，用于测试 `AXSelection` 与这些元素的关系。例如：
  ```cpp
  SetBodyInnerHTML(R"HTML(
      <textarea id="textarea">
        Inside
        textarea
        field.
      </textarea>
      )HTML");
  ```
* **JavaScript:** 虽然这段代码本身是 C++，但它模拟了用户与网页的交互，例如通过设置焦点和修改选择范围来模拟用户操作。在某些测试中，为了更精确地控制选择行为（特别是涉及文本方向性时），代码使用了 Blink 内部的 DOM 选择 API，这在实际应用中可以通过 JavaScript 的 `Selection` API 实现。
* **CSS:** 代码中偶尔会使用 `style` 属性来设置元素的样式，例如 `style="font-family: monospace; width: 15ch;"`，但这主要是为了控制元素的布局以便于测试，而不是直接测试 CSS 与 `AXSelection` 的交互。

**逻辑推理、假设输入与输出：**

以下是一个基于代码片段的逻辑推理示例：

**假设输入：**

1. 一个包含 `<textarea id="textarea">Some text.</textarea>` 的 HTML 结构。
2. 用户通过鼠标或键盘在 "Some text." 中选择了 "me t" 这部分文本。

**测试场景：** `TEST_F(AccessibilitySelectionTest, FromCurrentSelectionInTextarea)`

**代码逻辑：**

1. 通过 `GetDocument().QuerySelector(AtomicString("textarea"))` 获取 `<textarea>` 元素。
2. 通过 `ToTextControl(*textarea)` 将其转换为 `TextControlElement`。
3. 使用 `AXSelection::FromCurrentSelection(ToTextControl(*textarea))`  尝试从当前的 DOM 选择创建一个 `AXSelection` 对象。

**预期输出：**

* `ax_selection.IsValid()` 应该为 `true`，表示成功创建了 `AXSelection` 对象。
* `ax_selection.Anchor().ContainerObject()` 应该指向表示 `<textarea>` 的 `AXObject`。
* `ax_selection.Anchor().TextOffset()` 应该为 2 (对应 "me t" 中 "m" 的起始位置)。
* `ax_selection.Focus().ContainerObject()` 应该指向表示 `<textarea>` 的 `AXObject`。
* `ax_selection.Focus().TextOffset()` 应该为 6 (对应 "me t" 中 "t" 的结束位置之后)。

**用户或编程常见的使用错误：**

1. **假设 DOM 结构始终不变：** 测试代码依赖于特定的 HTML 结构。如果 HTML 结构发生变化（例如，`<textarea>` 的 ID 改变），测试可能会失败。
2. **错误地设置或获取选择范围：** 在使用 JavaScript 操作选择范围时，`selectionStart` 和 `selectionEnd` 的设置错误可能导致 `AXSelection` 对象无法正确反映用户的选择。例如，将 `selectionEnd` 设置在 `selectionStart` 之前会导致无效的选择。
3. **忽略文本方向性：** 在处理双向文本或复杂的文本输入时，忽略文本方向性可能导致 `AXSelection` 对象的锚点和焦点位置错误。

**用户操作如何一步步到达这里 (作为调试线索)：**

对于 `TEST_F(AccessibilitySelectionTest, FromCurrentSelectionInTextarea)` 这个测试，用户操作步骤可能如下：

1. **加载包含 `<textarea>` 元素的网页。**
2. **用户点击 `<textarea>` 元素，使其获得焦点。**
3. **用户通过鼠标拖拽或按住 Shift 键并移动光标，在 `<textarea>` 中选中一段文本，例如 "Inside"。**
4. **辅助功能 API (如 MSAA, UIA)  可能会请求获取当前的选择信息。**
5. **Blink 引擎会调用 `AXSelection::FromCurrentSelection` 方法，根据当前的 DOM 选择状态创建一个 `AXSelection` 对象，以便向辅助功能 API 提供选择信息。**

这段测试代码模拟了上述过程中的最后一步，验证 Blink 引擎是否能正确地将 DOM 选择转换为 `AXSelection` 对象。

**归纳一下它的功能 (第2部分)：**

这部分代码主要专注于测试 `AXSelection` 类与 `<textarea>` 元素的交互，涵盖了创建、读取、清除和设置 `<textarea>` 元素的可访问性选择的各种场景，并特别关注了文本方向性（Affinity）的处理。它确保了 Blink 引擎能够正确地将用户的 DOM 选择反映到可访问性 API 中，从而帮助屏幕阅读器等辅助技术理解和操作 `<textarea>` 元素中的文本。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_selection_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
 auto ax_selection =
      AXSelection::FromCurrentSelection(ToTextControl(*textarea));
  ASSERT_TRUE(ax_selection.IsValid());

  ASSERT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_textarea, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(0, ax_selection.Anchor().TextOffset());
  EXPECT_EQ(TextAffinity::kDownstream, ax_selection.Anchor().Affinity());
  ASSERT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_textarea, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(53, ax_selection.Focus().TextOffset());
  EXPECT_EQ(TextAffinity::kDownstream, ax_selection.Focus().Affinity());
}

TEST_F(AccessibilitySelectionTest, FromCurrentSelectionInTextareaWithAffinity) {
  // Even though the base of the selection in this test is at a position with an
  // upstream affinity, only a downstream affinity should be exposed, because an
  // upstream affinity is currently exposed in core editing only when the
  // selection is caret.
  SetBodyInnerHTML(R"HTML(
      <textarea id="textarea"
          rows="2" cols="15"
          style="font-family: monospace; width: 15ch;">
        InsideTextareaField.
      </textarea>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  const TextControlElement& text_control = ToTextControl(*textarea);

  // This test should only be testing accessibility code. Ordinarily we should
  // be setting up the test using Javascript in order to avoid depending on the
  // internal implementation of DOM selection. However, the only way I found to
  // get an upstream affinity is to send the "end" key which might be unreliable
  // on certain platforms, so we modify the selection using Blink internal
  // functions instead.
  textarea->Focus();
  Selection().Modify(SelectionModifyAlteration::kMove,
                     SelectionModifyDirection::kBackward,
                     TextGranularity::kDocumentBoundary, SetSelectionBy::kUser);
  Selection().Modify(SelectionModifyAlteration::kExtend,
                     SelectionModifyDirection::kForward,
                     TextGranularity::kLineBoundary, SetSelectionBy::kUser);
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(TextAffinity::kDownstream, text_control.Selection().Affinity());

  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  const auto ax_selection = AXSelection::FromCurrentSelection(text_control);
  ASSERT_TRUE(ax_selection.IsValid());

  EXPECT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_textarea, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(0, ax_selection.Anchor().TextOffset());
  EXPECT_EQ(TextAffinity::kDownstream, ax_selection.Anchor().Affinity());
  EXPECT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_textarea, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(8, ax_selection.Focus().TextOffset());
  EXPECT_EQ(TextAffinity::kDownstream, ax_selection.Focus().Affinity());
}

TEST_F(AccessibilitySelectionTest,
       FromCurrentSelectionInTextareaWithCollapsedSelectionAndAffinity) {
  SetBodyInnerHTML(R"HTML(
      <textarea id="textarea"
          rows="2" cols="15"
          style="font-family: monospace; width: 15ch;">
        InsideTextareaField.
      </textarea>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  const TextControlElement& text_control = ToTextControl(*textarea);

  // This test should only be testing accessibility code. Ordinarily we should
  // be setting up the test using Javascript in order to avoid depending on the
  // internal implementation of DOM selection. However, the only way I found to
  // get an upstream affinity is to send the "end" key which might be unreliable
  // on certain platforms, so we modify the selection using Blink internal
  // functions instead.
  textarea->Focus();
  Selection().Modify(SelectionModifyAlteration::kMove,
                     SelectionModifyDirection::kBackward,
                     TextGranularity::kDocumentBoundary, SetSelectionBy::kUser);
  Selection().Modify(SelectionModifyAlteration::kMove,
                     SelectionModifyDirection::kForward,
                     TextGranularity::kLineBoundary, SetSelectionBy::kUser);
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(TextAffinity::kUpstream, text_control.Selection().Affinity());

  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  const auto ax_selection = AXSelection::FromCurrentSelection(text_control);
  ASSERT_TRUE(ax_selection.IsValid());

  EXPECT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_textarea, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(8, ax_selection.Anchor().TextOffset());
  EXPECT_EQ(TextAffinity::kUpstream, ax_selection.Anchor().Affinity());
  EXPECT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_textarea, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(8, ax_selection.Focus().TextOffset());
  EXPECT_EQ(TextAffinity::kUpstream, ax_selection.Focus().Affinity());
}

TEST_F(AccessibilitySelectionTest,
       FromCurrentSelectionInContentEditableWithSoftLineBreaks) {
  GetPage().GetSettings().SetScriptEnabled(true);
  SetBodyInnerHTML(R"HTML(
      <div id="contenteditable" role="textbox" contenteditable
          style="max-width: 5px; overflow-wrap: normal;">
        Inside contenteditable field.
      </div>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  // We want to select all the text in the content editable, but not the
  // editable itself.
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      const contenteditable = document.querySelector('div[contenteditable]');
      contenteditable.focus();
      const firstLine = contenteditable.firstChild;
      const lastLine = contenteditable.lastChild;
      const range = document.createRange();
      range.setStart(firstLine, 0);
      range.setEnd(lastLine, lastLine.nodeValue.length);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  const AXObject* ax_contenteditable =
      GetAXObjectByElementId("contenteditable");
  ASSERT_NE(nullptr, ax_contenteditable);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_contenteditable->RoleValue());
  const AXObject* ax_static_text =
      ax_contenteditable->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  // Guard against the structure of the accessibility tree unexpectedly
  // changing, causing a hard to debug test failure.
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue())
      << "A content editable with only text inside it should have static text "
         "children.";
  // Guard against both ComputedName().length() and selection extent offset
  // returning 0.
  ASSERT_LT(0u, ax_static_text->ComputedName().length());

  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  ASSERT_TRUE(ax_selection.IsValid());

  ASSERT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(0, ax_selection.Anchor().TextOffset());
  ASSERT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(ax_static_text->ComputedName().length(),
            static_cast<unsigned>(ax_selection.Focus().TextOffset()));
}

TEST_F(AccessibilitySelectionTest,
       FromCurrentSelectionInContentEditableSelectFirstSoftLineBreak) {
  GetPage().GetSettings().SetScriptEnabled(true);
  // There should be no white space between the opening tag of the content
  // editable and the text inside it, otherwise selection offsets would be
  // wrong.
  SetBodyInnerHTML(R"HTML(
      <div id="contenteditable" role="textbox" contenteditable
          style="max-width: 5px; overflow-wrap: normal;">Line one.
      </div>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      const contenteditable = document.querySelector('div[contenteditable]');
      contenteditable.focus();
      const text = contenteditable.firstChild;
      const range = document.createRange();
      range.setStart(text, 4);
      range.setEnd(text, 4);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      selection.modify('extend', 'forward', 'character');
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  const AXObject* ax_contenteditable =
      GetAXObjectByElementId("contenteditable");
  ASSERT_NE(nullptr, ax_contenteditable);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_contenteditable->RoleValue());
  const AXObject* ax_static_text =
      ax_contenteditable->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  // Guard against the structure of the accessibility tree unexpectedly
  // changing, causing a hard to debug test failure.
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue())
      << "A content editable with only text inside it should have static text "
         "children.";

  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  ASSERT_TRUE(ax_selection.IsValid());

  ASSERT_TRUE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(4, ax_selection.Anchor().TextOffset());
  ASSERT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_static_text, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(5, ax_selection.Focus().TextOffset());
}

TEST_F(AccessibilitySelectionTest,
       FromCurrentSelectionInContentEditableSelectFirstHardLineBreak) {
  GetPage().GetSettings().SetScriptEnabled(true);
  // There should be no white space between the opening tag of the content
  // editable and the text inside it, otherwise selection offsets would be
  // wrong.
  SetBodyInnerHTML(R"HTML(
      <div id="contenteditable" role="textbox" contenteditable
          style="max-width: 5px; overflow-wrap: normal;">Inside<br>contenteditable.
      </div>
      )HTML");

  ASSERT_FALSE(AXSelection::FromCurrentSelection(GetDocument()).IsValid());

  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      const contenteditable = document.querySelector('div[contenteditable]');
      contenteditable.focus();
      const firstLine = contenteditable.firstChild;
      const range = document.createRange();
      range.setStart(firstLine, 6);
      range.setEnd(firstLine, 6);
      const selection = getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      selection.modify('extend', 'forward', 'character');
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  const AXObject* ax_contenteditable =
      GetAXObjectByElementId("contenteditable");
  ASSERT_NE(nullptr, ax_contenteditable);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_contenteditable->RoleValue());
  ASSERT_EQ(3, ax_contenteditable->UnignoredChildCount())
      << "The content editable should have two lines with a line break between "
         "them.";
  const AXObject* ax_static_text_2 = ax_contenteditable->UnignoredChildAt(2);
  ASSERT_NE(nullptr, ax_static_text_2);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text_2->RoleValue());

  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  ASSERT_TRUE(ax_selection.IsValid());

  ASSERT_FALSE(ax_selection.Anchor().IsTextPosition());
  EXPECT_EQ(ax_contenteditable, ax_selection.Anchor().ContainerObject());
  EXPECT_EQ(1, ax_selection.Anchor().ChildIndex());
  ASSERT_TRUE(ax_selection.Focus().IsTextPosition());
  EXPECT_EQ(ax_static_text_2, ax_selection.Focus().ContainerObject());
  EXPECT_EQ(0, ax_selection.Focus().TextOffset());
}

TEST_F(AccessibilitySelectionTest, ClearCurrentSelectionInTextField) {
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
      input.selectionEnd = input.textLength;
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

TEST_F(AccessibilitySelectionTest, ClearCurrentSelectionInTextarea) {
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

  SelectionInDOMTree selection = Selection().GetSelectionInDOMTree();
  ASSERT_FALSE(selection.IsNone());

  AXSelection::ClearCurrentSelection(GetDocument());
  selection = Selection().GetSelectionInDOMTree();
  EXPECT_TRUE(selection.IsNone());

  const auto ax_selection = AXSelection::FromCurrentSelection(GetDocument());
  EXPECT_FALSE(ax_selection.IsValid());
  EXPECT_EQ("", GetSelectionText(ax_selection));
}

TEST_F(AccessibilitySelectionTest, ForwardSelectionInTextField) {
  SetBodyInnerHTML(R"HTML(
      <input id="input" value="Inside text field.">
      )HTML");

  Element* const input = GetDocument().QuerySelector(AtomicString("input"));
  ASSERT_NE(nullptr, input);
  ASSERT_TRUE(IsTextControl(input));
  input->Focus(FocusOptions::Create());
  ASSERT_TRUE(input->IsFocusedElementInDocument());

  const AXObject* ax_input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, ax_input);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_input->RoleValue());

  // Forward selection.
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreateFirstPositionInObject(*ax_input))
          .SetFocus(AXPosition::CreateLastPositionInObject(*ax_input))
          .Build();

  EXPECT_TRUE(ax_selection.Select());

  EXPECT_EQ(0u, ToTextControl(*input).selectionStart());
  EXPECT_EQ(18u, ToTextControl(*input).selectionEnd());
  EXPECT_EQ("forward", ToTextControl(*input).selectionDirection());

  // Ensure that the selection that was just set could be successfully
  // retrieved.
  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  const auto ax_current_selection =
      AXSelection::FromCurrentSelection(ToTextControl(*input));
  EXPECT_EQ(ax_selection, ax_current_selection);
}

TEST_F(AccessibilitySelectionTest, BackwardSelectionInTextField) {
  SetBodyInnerHTML(R"HTML(
      <input id="input" value="Inside text field.">
      )HTML");

  Element* const input = GetDocument().QuerySelector(AtomicString("input"));
  ASSERT_NE(nullptr, input);
  ASSERT_TRUE(IsTextControl(input));
  input->Focus(FocusOptions::Create());
  ASSERT_TRUE(input->IsFocusedElementInDocument());

  const AXObject* ax_input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, ax_input);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_input->RoleValue());

  // Backward selection.
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreatePositionInTextObject(*ax_input, 10))
          .SetFocus(AXPosition::CreatePositionInTextObject(*ax_input, 3))
          .Build();

  EXPECT_TRUE(ax_selection.Select());

  EXPECT_EQ(3u, ToTextControl(*input).selectionStart());
  EXPECT_EQ(10u, ToTextControl(*input).selectionEnd());
  EXPECT_EQ("backward", ToTextControl(*input).selectionDirection());

  // Ensure that the selection that was just set could be successfully
  // retrieved.
  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  const auto ax_current_selection =
      AXSelection::FromCurrentSelection(ToTextControl(*input));
  EXPECT_EQ(ax_selection, ax_current_selection);
}

TEST_F(AccessibilitySelectionTest, SelectingTheWholeOfTheTextField) {
  SetBodyInnerHTML(R"HTML(
      <p id="before">Before text field.</p>
      <input id="input" value="Inside text field.">
      <p id="after">After text field.</p>
      )HTML");

  Element* const input = GetDocument().QuerySelector(AtomicString("input"));
  ASSERT_NE(nullptr, input);
  ASSERT_TRUE(IsTextControl(input));
  ASSERT_TRUE(ToTextControl(*input).SetSelectionRange(
      3u, 10u, kSelectionHasBackwardDirection));

  const AXObject* ax_before = GetAXObjectByElementId("before");
  ASSERT_NE(nullptr, ax_before);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_before->RoleValue());
  const AXObject* ax_input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, ax_input);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_input->RoleValue());

  // Light tree only selection. Selects the whole of the text field.
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreatePositionBeforeObject(*ax_before))
          .SetFocus(AXPosition::CreatePositionAfterObject(*ax_input))
          .Build();

  EXPECT_TRUE(ax_selection.Select());

  const SelectionInDOMTree dom_selection = Selection().GetSelectionInDOMTree();
  EXPECT_EQ(GetDocument().body(), dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(1, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(GetElementById("before"),
            dom_selection.Anchor().ComputeNodeAfterPosition());
  EXPECT_EQ(GetDocument().body(), dom_selection.Focus().AnchorNode());
  EXPECT_EQ(5, dom_selection.Focus().OffsetInContainerNode());
  EXPECT_EQ(GetElementById("after"),
            dom_selection.Focus().ComputeNodeAfterPosition());

  // The selection in the text field should remain unchanged because the field
  // is not focused.
  EXPECT_EQ(3u, ToTextControl(*input).selectionStart());
  EXPECT_EQ(10u, ToTextControl(*input).selectionEnd());
  EXPECT_EQ("backward", ToTextControl(*input).selectionDirection());
}

TEST_F(AccessibilitySelectionTest, SelectEachConsecutiveCharacterInTextField) {
  SetBodyInnerHTML(R"HTML(
      <input id="input" value="Inside text field.">
      )HTML");

  Element* const input = GetDocument().QuerySelector(AtomicString("input"));
  ASSERT_NE(nullptr, input);
  ASSERT_TRUE(IsTextControl(input));
  TextControlElement& text_control = ToTextControl(*input);
  ASSERT_LE(1u, text_control.InnerEditorValue().length());

  const AXObject* ax_input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, ax_input);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_input->RoleValue());

  for (unsigned int i = 0; i < text_control.InnerEditorValue().length() - 1;
       ++i) {
    GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder.SetAnchor(AXPosition::CreatePositionInTextObject(*ax_input, i))
            .SetFocus(AXPosition::CreatePositionInTextObject(*ax_input, i + 1))
            .Build();

    testing::Message message;
    message << "While selecting forward character "
            << static_cast<char>(text_control.InnerEditorValue()[i])
            << " at position " << i << " in text field.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    EXPECT_EQ(i, text_control.selectionStart());
    EXPECT_EQ(i + 1, text_control.selectionEnd());
    EXPECT_EQ("forward", text_control.selectionDirection());
  }

  for (unsigned int i = text_control.InnerEditorValue().length(); i > 0; --i) {
    GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder.SetAnchor(AXPosition::CreatePositionInTextObject(*ax_input, i))
            .SetFocus(AXPosition::CreatePositionInTextObject(*ax_input, i - 1))
            .Build();

    testing::Message message;
    message << "While selecting backward character "
            << static_cast<char>(text_control.InnerEditorValue()[i])
            << " at position " << i << " in text field.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    EXPECT_EQ(i - 1, text_control.selectionStart());
    EXPECT_EQ(i, text_control.selectionEnd());
    EXPECT_EQ("backward", text_control.selectionDirection());
  }
}

TEST_F(AccessibilitySelectionTest,
       SelectEachConsecutiveCharacterInEmailFieldWithInvalidAddress) {
  GetPage().GetSettings().SetScriptEnabled(true);
  String valid_email = "valid@example.com";
  SetBodyInnerHTML(R"HTML(
      <input id="input" type="email" value=)HTML" +
                   valid_email + R"HTML(>
      )HTML");

  // Add three spaces to the start of the address to make it invalid.
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  ASSERT_NE(nullptr, script_element);
  script_element->setTextContent(R"SCRIPT(
      let input = document.querySelector('input');
      input.focus();
      input.value = input.value.padStart(3, ' ');
      input.selectionStart = 0;
      input.selectionEnd = input.value.length;
      )SCRIPT");
  GetDocument().body()->AppendChild(script_element);
  UpdateAllLifecyclePhasesForTest();

  Element* const input = GetDocument().QuerySelector(AtomicString("input"));
  ASSERT_NE(nullptr, input);
  ASSERT_TRUE(IsTextControl(input));
  TextControlElement& text_control = ToTextControl(*input);
  // The "value" attribute should not contain the extra spaces.
  ASSERT_EQ(valid_email.length(), text_control.Value().length());

  const AXObject* ax_input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, ax_input);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_input->RoleValue());

  // The address can still be navigated using cursor left / right, even though
  // it's invalid.
  for (unsigned int i = 0; i < text_control.InnerEditorValue().length() - 1;
       ++i) {
    GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder.SetAnchor(AXPosition::CreatePositionInTextObject(*ax_input, i))
            .SetFocus(AXPosition::CreatePositionInTextObject(*ax_input, i + 1))
            .Build();

    testing::Message message;
    message << "While selecting forward character "
            << static_cast<char>(text_control.InnerEditorValue()[i])
            << " at position " << i << " in text field.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    EXPECT_EQ(i, text_control.selectionStart());
    EXPECT_EQ(i + 1, text_control.selectionEnd());
    EXPECT_EQ("forward", text_control.selectionDirection());
  }

  for (unsigned int i = text_control.InnerEditorValue().length(); i > 0; --i) {
    GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder.SetAnchor(AXPosition::CreatePositionInTextObject(*ax_input, i))
            .SetFocus(AXPosition::CreatePositionInTextObject(*ax_input, i - 1))
            .Build();

    testing::Message message;
    message << "While selecting backward character "
            << static_cast<char>(text_control.InnerEditorValue()[i])
            << " at position " << i << " in text field.";
    SCOPED_TRACE(message);
    EXPECT_TRUE(ax_selection.Select());

    EXPECT_EQ(i - 1, text_control.selectionStart());
    EXPECT_EQ(i, text_control.selectionEnd());
    EXPECT_EQ("backward", text_control.selectionDirection());
  }
}

TEST_F(AccessibilitySelectionTest, InvalidSelectionInTextField) {
  SetBodyInnerHTML(R"HTML(
      <p id="before">Before text field.</p>
      <input id="input" value="Inside text field.">
      <p id="after">After text field.</p>
      )HTML");

  Element* const input = GetDocument().QuerySelector(AtomicString("input"));
  ASSERT_NE(nullptr, input);
  ASSERT_TRUE(IsTextControl(input));
  ASSERT_TRUE(ToTextControl(*input).SetSelectionRange(
      3u, 10u, kSelectionHasBackwardDirection));

  const AXObject* ax_before = GetAXObjectByElementId("before");
  ASSERT_NE(nullptr, ax_before);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_before->RoleValue());
  const AXObject* ax_input = GetAXObjectByElementId("input");
  ASSERT_NE(nullptr, ax_input);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_input->RoleValue());
  const AXObject* ax_after = GetAXObjectByElementId("after");
  ASSERT_NE(nullptr, ax_after);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_after->RoleValue());

  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  {
    // Light tree only selection. Selects the whole of the text field.
    AXSelection::Builder builder;
    AXSelection ax_selection =
        builder.SetAnchor(AXPosition::CreatePositionBeforeObject(*ax_before))
            .SetFocus(AXPosition::CreatePositionAfterObject(*ax_input))
            .Build();
    ax_selection.Select();
  }

  // Invalid selection because it crosses a user agent shadow tree boundary.
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreatePositionInTextObject(*ax_input, 0))
          .SetFocus(AXPosition::CreatePositionBeforeObject(*ax_after))
          .Build();

  EXPECT_FALSE(ax_selection.IsValid());

  // The selection in the light DOM should remain unchanged.
  const SelectionInDOMTree dom_selection = Selection().GetSelectionInDOMTree();
  EXPECT_EQ(GetDocument().body(), dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(1, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(GetElementById("before"),
            dom_selection.Anchor().ComputeNodeAfterPosition());
  EXPECT_EQ(GetDocument().body(), dom_selection.Focus().AnchorNode());
  EXPECT_EQ(5, dom_selection.Focus().OffsetInContainerNode());
  EXPECT_EQ(GetElementById("after"),
            dom_selection.Focus().ComputeNodeAfterPosition());

  // The selection in the text field should remain unchanged because the field
  // is not focused.
  EXPECT_EQ(3u, ToTextControl(*input).selectionStart());
  EXPECT_EQ(10u, ToTextControl(*input).selectionEnd());
  EXPECT_EQ("backward", ToTextControl(*input).selectionDirection());
}

TEST_F(AccessibilitySelectionTest, ForwardSelectionInTextarea) {
  SetBodyInnerHTML(R"HTML(
      <textarea id="textarea">
        Inside
        textarea
        field.
      </textarea>
      )HTML");

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  textarea->Focus(FocusOptions::Create());
  ASSERT_TRUE(textarea->IsFocusedElementInDocument());

  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  // Forward selection.
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreateFirstPositionInObject(*ax_textarea))
          .SetFocus(AXPosition::CreateLastPositionInObject(*ax_textarea))
          .Build();

  EXPECT_TRUE(ax_selection.Select());

  EXPECT_EQ(0u, ToTextControl(*textarea).selectionStart());
  EXPECT_EQ(53u, ToTextControl(*textarea).selectionEnd());
  EXPECT_EQ("forward", ToTextControl(*textarea).selectionDirection());

  // Ensure that the selection that was just set could be successfully
  // retrieved.
  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  const auto ax_current_selection =
      AXSelection::FromCurrentSelection(ToTextControl(*textarea));
  EXPECT_EQ(ax_selection, ax_current_selection);
}

TEST_F(AccessibilitySelectionTest, BackwardSelectionInTextarea) {
  SetBodyInnerHTML(R"HTML(
      <textarea id="textarea">
        Inside
        textarea
        field.
      </textarea>
      )HTML");

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  textarea->Focus(FocusOptions::Create());
  ASSERT_TRUE(textarea->IsFocusedElementInDocument());

  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  // Backward selection.
  AXSelection::Builder builder;
  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  AXSelection ax_selection =
      builder
          .SetAnchor(AXPosition::CreatePositionInTextObject(*ax_textarea, 10))
          .SetFocus(AXPosition::CreatePositionInTextObject(*ax_textarea, 3))
          .Build();

  EXPECT_TRUE(ax_selection.Select());

  EXPECT_EQ(3u, ToTextControl(*textarea).selectionStart());
  EXPECT_EQ(10u, ToTextControl(*textarea).selectionEnd());
  EXPECT_EQ("backward", ToTextControl(*textarea).selectionDirection());

  // Ensure that the selection that was just set could be successfully
  // retrieved.
  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  const auto ax_current_selection =
      AXSelection::FromCurrentSelection(ToTextControl(*textarea));
  EXPECT_EQ(ax_selection, ax_current_selection);
}

TEST_F(AccessibilitySelectionTest, SelectTheWholeOfTheTextarea) {
  SetBodyInnerHTML(R"HTML(
      <p id="before">Before textarea field.</p>
      <textarea id="textarea">
        Inside
        textarea
        field.
      </textarea>
      <p id="after">After textarea field.</p>
      )HTML");

  Element* const textarea =
      GetDocument().QuerySelector(AtomicString("textarea"));
  ASSERT_NE(nullptr, textarea);
  ASSERT_TRUE(IsTextControl(textarea));
  ASSERT_TRUE(ToTextControl(*textarea).SetSelectionRange(
      3u, 10u, kSelectionHasBackwardDirection));

  const AXObject* ax_before = GetAXObjectByElementId("before");
  ASSERT_NE(nullptr, ax_before);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_before->RoleValue());
  const AXObject* ax_textarea = GetAXObjectByElementId("textarea");
  ASSERT_NE(nullptr, ax_textarea);
  ASSERT_EQ(ax::mojom::Role::kTextField, ax_textarea->RoleValue());

  // Light tree only selection. Selects the whole of the textarea field.
  GetDocument().ExistingAXObjectCache()->UpdateAXForAllDocuments();
  AXSelection::Builder builder;
  AXSelection ax_selection =
      builder.SetAnchor(AXPosition::CreatePositionBeforeObject(*ax_before))
          .SetFocus(AXPosition::CreatePositionAfterObject(*ax_textarea))
          .Build();

  EXPECT_TRUE(ax_selection.Select());

  const SelectionInDOMTree dom_selection = Selection().GetSelectionInDOMTree();
  EXPECT_EQ(GetDocument().body(), dom_selection.Anchor().AnchorNode());
  EXPECT_EQ(1, dom_selection.Anchor().OffsetInContainerNode());
  EXPECT_EQ(GetElementById("before"),
            dom_selection.Anchor().ComputeNodeAfterPosition());
  EXPECT_EQ(GetDocument().body(), dom_selection.Focus().AnchorNode());
  EXPECT_EQ(5, dom_selection.Focus().OffsetInContainerNo
"""


```