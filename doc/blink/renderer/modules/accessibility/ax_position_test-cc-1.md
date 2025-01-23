Response:
The user wants me to summarize the functionality of the provided C++ code snippet. This code is a part of the Chromium Blink engine and is located in the `ax_position_test.cc` file within the `accessibility` module. It seems to be a test suite for the `AXPosition` class, which likely deals with representing positions within the accessibility tree.

Here's a plan:
1. Identify the core purpose of the test file by examining the test names and the operations performed within each test.
2. Determine if and how the tested functionality relates to Javascript, HTML, and CSS.
3. Analyze the logical flow within the tests, looking for assumed inputs (HTML structures) and expected outputs (assertions about `AXPosition` properties).
4. Consider potential user or programming errors that the tests might be designed to prevent or highlight.
5. Infer the user actions that could lead to the code being executed (primarily for debugging).
6. Finally, summarize the overall functionality of the provided code snippet.
这个C++代码片段是 `blink/renderer/modules/accessibility/ax_position_test.cc` 文件的一部分，它主要功能是**测试 `AXPosition` 类的各种功能，特别是它与 DOM (Document Object Model) 中 `Position` 之间的相互转换，以及在各种不同的 DOM 结构和 Accessibility 树结构下 `AXPosition` 的行为**。

以下是对代码功能的归纳和说明：

**功能归纳:**

* **测试 `AXPosition` 与 DOM `Position` 的相互转换:**  验证在不同情况下，DOM 中的一个 `Position` 对象能否正确地转换为 `AXPosition` 对象，反之亦然。
* **测试文本节点内的 `AXPosition`:**  验证在文本节点中，`AXPosition` 是否能够正确表示文本偏移量 (text offset)。
* **测试 `AXPosition` 的亲和性 (affinity):** 验证在行尾或行首等边界情况下，`AXPosition` 能否正确处理亲和性（向上游或下游）。
* **测试在 HTML 标签 (label) 中的 `AXPosition`:**
    * 当 label 与表单控件关联时，测试 `AXPosition` 如何处理 label 元素及其文本内容，特别是当 label 在 accessibility 树中被忽略时的情况。
* **测试在被忽略的元素中的 `AXPosition`:**  验证 `AXPosition` 如何处理 `display: none` 或 `hidden` 属性的元素，这些元素通常会被 accessibility 树忽略，但可能仍然存在于 DOM 中。
* **测试在 `aria-hidden` 元素中的 `AXPosition`:** 验证 `AXPosition` 如何处理通过 `aria-hidden="true"` 隐藏的元素，这些元素在 DOM 中存在，但在 accessibility 树中被忽略。
* **测试在 Canvas 元素中的 `AXPosition`:** 验证 `AXPosition` 如何处理 Canvas 元素的 fallback 内容，这些内容可能存在于 accessibility 树中，但不在布局树中。
* **测试在列表标记 (list marker) 前后的 `AXPosition`:** 验证 `AXPosition` 如何处理列表项的标记，这些标记在 accessibility 树中存在，但不在 DOM 中直接对应元素。
* **测试在 CSS content (::before, ::after) 中的 `AXPosition` (Disabled):**  这个测试被禁用了，但它的目的是测试 `AXPosition` 如何处理通过 CSS 的 `::before` 和 `::after` 生成的内容，这些内容存在于 accessibility 树中，但不在 DOM 中。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 方法设置 HTML 结构作为测试的输入。例如：
    * `<p id="paragraph">Hello</p>`：测试文本节点内的位置。
    * `<label id="label" for="input">Label text.</label><input id="input">`：测试 label 元素中的位置。
    * `<div id="hidden" hidden>Hidden.</div>`：测试隐藏元素中的位置。
    * `<canvas id="canvas1">Fallback text</canvas>`：测试 Canvas 元素的 fallback 内容。
* **CSS:** 虽然这个代码片段本身不直接操作 CSS，但它测试的场景涉及到 CSS 的影响，例如：
    * `display: none` 或 `hidden` 属性会导致元素被 accessibility 树忽略。
    * CSS 的 `::before` 和 `::after` 伪元素会生成内容，这些内容会出现在 accessibility 树中。 (尽管相关的测试被禁用了)
* **Javascript:**  虽然这个测试是用 C++ 编写的，但它测试的功能是与浏览器如何将网页内容（HTML, CSS）呈现给辅助技术 (例如屏幕阅读器) 相关的。 Javascript 可以动态修改 DOM 结构和 CSS 样式，这些修改会影响 accessibility 树的结构，进而影响 `AXPosition` 的行为。 例如，Javascript 可以动态添加或删除元素，改变元素的 `hidden` 属性或 CSS 的 `display` 属性，从而改变 accessibility 树的结构，这些改变会影响 `AXPosition` 如何定位元素和文本。

**逻辑推理及假设输入与输出:**

以下是一个示例：

**假设输入 (HTML):**
```html
<p id="paragraph">Hello</p>
```

**测试代码:**
```c++
TEST_F(AccessibilityTest, PositionInTextWithAffinity) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  // ...
  const auto ax_position = AXPosition::CreatePositionInTextObject(
      *ax_static_text, 3, TextAffinity::kUpstream);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(TextAffinity::kUpstream, position.Affinity());
}
```

**逻辑推理:**

1. `SetBodyInnerHTML` 设置了包含一个 `<p>` 元素的 HTML。
2. `GetElementById` 获取了该 `<p>` 元素。
3. `firstChild()` 获取了 `<p>` 元素内的文本节点 "Hello"。
4. `GetAXObjectByElementId` 获取了 `<p>` 元素对应的 accessibility 对象。
5. `AXPosition::CreatePositionInTextObject` 创建了一个指向文本对象，偏移量为 3，亲和性为 `kUpstream` 的 `AXPosition`。这意味着它指向 "Hell**o**" 中的 "o" 之前的位置，并且偏向上游（左边）。
6. `ax_position.ToPositionWithAffinity()` 将 `AXPosition` 转换回 DOM `Position`。
7. `EXPECT_EQ(TextAffinity::kUpstream, position.Affinity());` 断言转换回的 DOM `Position` 的亲和性仍然是 `kUpstream`。

**输出 (期望结果):**  `EXPECT_EQ` 断言成功，表明 `AXPosition` 成功保留了亲和性信息。

**用户或编程常见的使用错误举例说明:**

* **错误地假设 DOM `Position` 和 `AXPosition` 一一对应:**  例如，在处理 `aria-hidden` 的元素时，DOM 中位于 `aria-hidden` 元素内部的 `Position` 转换为 `AXPosition` 时，会调整到最近的可访问元素。 用户或程序员可能会错误地认为转换后的 `AXPosition` 仍然指向被隐藏元素内部。
* **忽略亲和性:** 在处理文本边界时，例如行尾和行首，如果忽略 `AXPosition` 的亲和性，可能会导致光标位置不符合预期。例如，用户可能期望光标在某行的末尾，但由于亲和性设置错误，光标可能被放置到下一行的开头。
* **在 accessibility 树被忽略的元素中进行定位:** 程序员可能会尝试通过 DOM 操作获取一个被 accessibility 树忽略的元素的位置，并将其转换为 `AXPosition`，然后期望这个 `AXPosition` 能在 accessibility 树中找到对应的位置。但实际上，`AXPosition` 会被调整到最近的可访问节点。

**用户操作如何一步步到达这里，作为调试线索:**

这种情况通常发生在开发者进行 accessibility 相关的开发或调试时。步骤可能如下：

1. **用户操作网页:** 用户可能正在浏览网页，与页面元素进行交互，例如点击、输入等。
2. **辅助技术介入:** 如果用户使用了屏幕阅读器等辅助技术，这些技术会通过浏览器的 accessibility API 获取页面的信息。
3. **Accessibility API 调用:** 辅助技术可能会调用浏览器的 accessibility API 来获取特定元素的位置信息。这可能涉及到将屏幕坐标或焦点位置转换为 accessibility 树中的位置。
4. **Blink 引擎处理:**  Blink 引擎会接收到这些 API 调用，并需要将这些请求转换为对内部数据结构的查询，例如 accessibility 树。
5. **`AXPosition` 的使用:**  当需要表示 accessibility 树中的一个特定位置时，Blink 引擎会使用 `AXPosition` 类。
6. **`AXPosition` 与 DOM `Position` 的转换:**  在某些情况下，可能需要将 DOM 中的 `Position` 转换为 `AXPosition`，或者反过来。例如，当用户通过鼠标或键盘选择一段文本时，浏览器需要将 DOM 中的选区信息转换为 accessibility 树中的位置信息。
7. **触发测试:** 在开发或修改相关代码时，开发者会运行 `ax_position_test.cc` 中的测试用例，以确保 `AXPosition` 类的功能在各种场景下都能正常工作。如果测试失败，开发者可以通过调试来追踪问题，查看在特定 HTML 结构下，DOM `Position` 是如何转换为 `AXPosition` 的。

**总结功能 (针对提供的代码片段):**

提供的代码片段主要集中在测试 `AXPosition` 类在处理 **文本内容** 和 **HTML 标签 (特别是 label 元素)** 时的行为。它验证了 `AXPosition` 与 DOM `Position` 之间的正确转换，以及在处理文本偏移量和亲和性时的准确性。 此外，它还测试了在 label 元素被 accessibility 树忽略时，`AXPosition` 的行为。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_position_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
node child of the second tspan containing "world"
  text = GetElementById("tspan")->firstChild();
  ASSERT_NE(nullptr, text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_EQ(5U, text->textContent().length());
  EXPECT_EQ("world", text->textContent().Utf8());

  // If we didn't adjust for isolate characters, the accessible text offset
  // would be 12 instead of 4.
  const Position position_at_d(*text, 4);
  const auto ax_position_at_d = AXPosition::FromPosition(position_at_d);
  EXPECT_TRUE(ax_position_at_d.IsTextPosition());
  EXPECT_EQ(4, ax_position_at_d.TextOffset());

  // Check the text node containing "!"
  text = GetElementById("text")->lastChild();
  ASSERT_NE(nullptr, text);
  EXPECT_TRUE(text->IsTextNode());
  EXPECT_EQ(1U, text->textContent().length());
  EXPECT_EQ("!", text->textContent().Utf8());

  const Position position_at_end(*text, 1);
  const auto ax_position_at_end = AXPosition::FromPosition(position_at_end);
  EXPECT_TRUE(ax_position_at_end.IsTextPosition());
  EXPECT_EQ(1, ax_position_at_end.TextOffset());
}

//
// Test affinity.
// We need to distinguish between the caret at the end of one line and the
// beginning of the next.
//

TEST_F(AccessibilityTest, PositionInTextWithAffinity) {
  SetBodyInnerHTML(R"HTML(<p id="paragraph">Hello</p>)HTML");
  const Node* text = GetElementById("paragraph")->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const AXObject* ax_static_text =
      GetAXObjectByElementId("paragraph")->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_static_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_static_text->RoleValue());

  // Converting from AX to DOM positions should maintain affinity.
  const auto ax_position = AXPosition::CreatePositionInTextObject(
      *ax_static_text, 3, TextAffinity::kUpstream);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(TextAffinity::kUpstream, position.Affinity());

  // Converting from DOM to AX positions should maintain affinity.
  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(TextAffinity::kUpstream, ax_position.Affinity());
}

//
// Test converting to and from accessibility positions with offsets in HTML
// labels. HTML labels are ignored in the accessibility tree when associated
// with checkboxes and radio buttons.
//

TEST_F(AccessibilityTest, PositionInHTMLLabel) {
  SetBodyInnerHTML(R"HTML(
      <label id="label" for="input">
        Label text.
      </label>
      <p id="paragraph">Intervening paragraph.</p>
      <input id="input">
      )HTML");

  const Node* label = GetElementById("label");
  ASSERT_NE(nullptr, label);
  const Node* label_text = label->firstChild();
  ASSERT_NE(nullptr, label_text);
  ASSERT_TRUE(label_text->IsTextNode());
  const Node* paragraph = GetElementById("paragraph");
  ASSERT_NE(nullptr, paragraph);

  const AXObject* ax_body = GetAXBodyObject();
  ASSERT_NE(nullptr, ax_body);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_body->RoleValue());

  const AXObject* ax_label = GetAXObjectByElementId("label");
  ASSERT_NE(nullptr, ax_label);
  ASSERT_FALSE(ax_label->IsIgnored());
  const AXObject* ax_label_text = ax_label->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_label_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_label_text->RoleValue());
  const AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());

  const auto position_before_label = Position::BeforeNode(*label);
  const auto ax_position_before_label =
      AXPosition::FromPosition(position_before_label, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_FALSE(ax_position_before_label.IsTextPosition());
  EXPECT_EQ(ax_body, ax_position_before_label.ContainerObject());
  EXPECT_EQ(0, ax_position_before_label.ChildIndex());
  EXPECT_EQ(ax_label, ax_position_before_label.ChildAfterTreePosition());

  const auto position_before_text = Position::BeforeNode(*label_text);
  const auto position_in_text = Position::FirstPositionInNode(*label_text);
  const auto position_after_label = Position::AfterNode(*label);
  for (const auto& position :
       {position_before_text, position_in_text, position_after_label}) {
    const auto ax_position =
        AXPosition::FromPosition(position, TextAffinity::kDownstream,
                                 AXPositionAdjustmentBehavior::kMoveLeft);
    EXPECT_TRUE(ax_position.IsTextPosition());
    EXPECT_EQ(ax_label_text, ax_position.ContainerObject());
    EXPECT_EQ(nullptr, ax_position.ChildAfterTreePosition());
  }
  const auto position_before_paragraph = Position::BeforeNode(*paragraph);
  const auto ax_position_before_paragraph = AXPosition::FromPosition(
      position_before_paragraph, TextAffinity::kDownstream,
      AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_FALSE(ax_position_before_paragraph.IsTextPosition());
  EXPECT_EQ(ax_body, ax_position_before_paragraph.ContainerObject());
  EXPECT_EQ(1, ax_position_before_paragraph.ChildIndex());
  EXPECT_EQ(ax_paragraph,
            ax_position_before_paragraph.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, PositionInHTMLLabelIgnored) {
  SetBodyInnerHTML(R"HTML(
      <label id="label" for="input">
        Label text.
      </label>
      <p id="paragraph">Intervening paragraph.</p>
      <input id="input" type="checkbox" checked>
      )HTML");

  // For reference, this is the accessibility tree generated:
  // rootWebArea
  // ++genericContainer ignored
  // ++++genericContainer ignored
  // ++++++labelText ignored
  // ++++++++staticText ignored name='Label text.'
  // ++++++paragraph
  // ++++++++staticText name='Intervening paragraph.'
  // ++++++++++inlineTextBox name='Intervening paragraph.'
  // ++++++checkBox focusable name='Label text.'

  const Node* label = GetElementById("label");
  ASSERT_NE(nullptr, label);
  const Node* label_text = label->firstChild();
  ASSERT_NE(nullptr, label_text);
  ASSERT_TRUE(label_text->IsTextNode());
  const Node* paragraph = GetElementById("paragraph");
  ASSERT_NE(nullptr, paragraph);

  const AXObject* ax_body = GetAXBodyObject();
  ASSERT_NE(nullptr, ax_body);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_body->RoleValue());

  // The HTML label element should be ignored.
  const AXObject* ax_label = GetAXObjectByElementId("label");
  ASSERT_NE(nullptr, ax_label);
  ASSERT_TRUE(ax_label->IsIgnored());
  const AXObject* ax_label_text = ax_label->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_label_text);
  ASSERT_TRUE(ax_label_text->IsIgnored());
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_label_text->RoleValue());
  const AXObject* ax_paragraph = GetAXObjectByElementId("paragraph");
  ASSERT_NE(nullptr, ax_paragraph);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_paragraph->RoleValue());

  // The label element produces an ignored, but included node in the
  // accessibility tree. The position is set right before it.
  const auto position_before = Position::BeforeNode(*label);
  const auto ax_position_before =
      AXPosition::FromPosition(position_before, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_FALSE(ax_position_before.IsTextPosition());
  EXPECT_EQ(ax_body, ax_position_before.ContainerObject());
  EXPECT_EQ(0, ax_position_before.ChildIndex());
  EXPECT_EQ(ax_label, ax_position_before.ChildAfterTreePosition());

  const auto position_from_ax_before =
      ax_position_before.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument().body(), position_from_ax_before.AnchorNode());
  EXPECT_EQ(1, position_from_ax_before.GetPosition().OffsetInContainerNode());
  EXPECT_EQ(label,
            position_from_ax_before.GetPosition().ComputeNodeAfterPosition());

  // A position anchored before a text node is explicitly moved to before the
  // first character of the text object. That's why these two positions are
  // effectively the same.
  const auto position_before_text = Position::BeforeNode(*label_text);
  const auto position_in_text = Position::FirstPositionInNode(*label_text);

  // This position points to the empty text node between the label and the
  // paragraph. That's invalid so it's moved the closest node to the left
  // (because we used AXPositionAdjustmentBehavior::kMoveLeft), landing in the
  // last character of the label text.
  const auto position_after = Position::AfterNode(*label);

  for (const auto& position :
       {position_before_text, position_in_text, position_after}) {
    const auto ax_position =
        AXPosition::FromPosition(position, TextAffinity::kDownstream,
                                 AXPositionAdjustmentBehavior::kMoveLeft);
    EXPECT_TRUE(ax_position.IsTextPosition());
    EXPECT_EQ(ax_label_text, ax_position.ContainerObject());
    EXPECT_EQ(nullptr, ax_position.ChildAfterTreePosition());

    const auto position_from_ax = ax_position.ToPositionWithAffinity();
    EXPECT_EQ(label_text, position_from_ax.AnchorNode());
    EXPECT_EQ(nullptr,
              position_from_ax.GetPosition().ComputeNodeAfterPosition());

    if (position == position_after) {
      // this position excludes whitespace
      EXPECT_EQ(11, ax_position.TextOffset());
      // this position includes the whitespace before "Label text."
      EXPECT_EQ(20, position_from_ax.GetPosition().OffsetInContainerNode());
    } else {
      // this position excludes whitespace
      EXPECT_EQ(0, ax_position.TextOffset());
      // this position includes the whitespace before "Label text."
      EXPECT_EQ(9, position_from_ax.GetPosition().OffsetInContainerNode());
    }
  }
}

//
// Objects with "display: none" or the "hidden" attribute are accessibility
// ignored.
//

TEST_F(AccessibilityTest, PositionInIgnoredObject) {
  // Note: aria-describedby adds hidden target subtrees to the a11y tree as
  // "ignored but included in tree".
  SetBodyInnerHTML(R"HTML(
      <div id="hidden" hidden aria-describedby="hidden">Hidden.</div><p id="visible">Visible.</p>
      )HTML");

  const Node* hidden = GetElementById("hidden");
  ASSERT_NE(nullptr, hidden);
  const Node* visible = GetElementById("visible");
  ASSERT_NE(nullptr, visible);

  const AXObject* ax_root = GetAXRootObject();
  ASSERT_NE(nullptr, ax_root);
  ASSERT_EQ(ax::mojom::Role::kRootWebArea, ax_root->RoleValue());
  ASSERT_EQ(1, ax_root->ChildCountIncludingIgnored());

  const AXObject* ax_html = ax_root->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_html);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_html->RoleValue());
  ASSERT_EQ(1, ax_html->ChildCountIncludingIgnored());

  const AXObject* ax_body = GetAXBodyObject();
  ASSERT_NE(nullptr, ax_body);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_body->RoleValue());
  ASSERT_EQ(2, ax_body->ChildCountIncludingIgnored());

  const AXObject* ax_hidden = GetAXObjectByElementId("hidden");
  ASSERT_NE(nullptr, ax_hidden);
  ASSERT_EQ(ax::mojom::Role::kGenericContainer, ax_hidden->RoleValue());
  ASSERT_TRUE(ax_hidden->IsIgnoredButIncludedInTree());

  const AXObject* ax_visible = GetAXObjectByElementId("visible");
  ASSERT_NE(nullptr, ax_visible);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_visible->RoleValue());

  // The fact that there is a hidden object before |visible| should not affect
  // setting a position before it.
  const auto ax_position_before_visible =
      AXPosition::CreatePositionBeforeObject(*ax_visible);
  const auto position_before_visible =
      ax_position_before_visible.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument().body(), position_before_visible.AnchorNode());
  EXPECT_EQ(2, position_before_visible.GetPosition().OffsetInContainerNode());
  EXPECT_EQ(visible,
            position_before_visible.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_before_visible_from_dom =
      AXPosition::FromPosition(position_before_visible);
  EXPECT_EQ(ax_position_before_visible, ax_position_before_visible_from_dom);
  EXPECT_EQ(ax_visible,
            ax_position_before_visible_from_dom.ChildAfterTreePosition());

  // A position at the beginning of the body will appear to be before the hidden
  // element in the DOM.
  const auto ax_position_first =
      AXPosition::CreateFirstPositionInObject(*ax_root);
  const auto position_first = ax_position_first.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument(), position_first.AnchorNode());
  EXPECT_TRUE(position_first.GetPosition().IsBeforeChildren());

  EXPECT_EQ(GetDocument().documentElement(),
            position_first.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_first_from_dom =
      AXPosition::FromPosition(position_first);
  EXPECT_EQ(ax_position_first, ax_position_first_from_dom);

  EXPECT_EQ(ax_html, ax_position_first_from_dom.ChildAfterTreePosition());

  // A DOM position before |hidden| should convert to an accessibility position
  // before |hidden| because the node is ignored but included in the tree.
  const auto position_before = Position::BeforeNode(*hidden);
  const auto ax_position_before_from_dom =
      AXPosition::FromPosition(position_before);
  EXPECT_EQ(ax_body, ax_position_before_from_dom.ContainerObject());
  EXPECT_EQ(0, ax_position_before_from_dom.ChildIndex());
  EXPECT_EQ(ax_hidden, ax_position_before_from_dom.ChildAfterTreePosition());

  // A DOM position after |hidden| should convert to an accessibility position
  // before |visible|.
  const auto position_after = Position::AfterNode(*hidden);
  const auto ax_position_after_from_dom =
      AXPosition::FromPosition(position_after);
  EXPECT_EQ(ax_body, ax_position_after_from_dom.ContainerObject());
  EXPECT_EQ(1, ax_position_after_from_dom.ChildIndex());
  EXPECT_EQ(ax_visible, ax_position_after_from_dom.ChildAfterTreePosition());
}

//
// Aria-hidden can cause things in the DOM to be hidden from accessibility.
//

TEST_F(AccessibilityTest, BeforePositionInARIAHiddenShouldNotSkipARIAHidden) {
  // Note: aria-describedby adds hidden target subtrees to the a11y tree as
  // "ignored but included in tree".
  SetBodyInnerHTML(R"HTML(
      <div role="main" id="container" aria-describedby="ariaHidden">
        <p id="before">Before aria-hidden.</p>
        <p id="ariaHidden" aria-hidden="true">Aria-hidden.</p>
        <p id="after">After aria-hidden.</p>
      </div>
      )HTML");

  const Node* container = GetElementById("container");
  ASSERT_NE(nullptr, container);
  const Node* after = GetElementById("after");
  ASSERT_NE(nullptr, after);
  const Node* hidden = GetElementById("ariaHidden");
  ASSERT_NE(nullptr, hidden);

  const AXObject* ax_before = GetAXObjectByElementId("before");
  ASSERT_NE(nullptr, ax_before);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_before->RoleValue());
  const AXObject* ax_after = GetAXObjectByElementId("after");
  ASSERT_NE(nullptr, ax_after);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_after->RoleValue());
  const AXObject* ax_hidden = GetAXObjectByElementId("ariaHidden");
  ASSERT_NE(nullptr, ax_hidden);
  ASSERT_TRUE(ax_hidden->IsIgnored());

  const auto ax_position = AXPosition::CreatePositionAfterObject(*ax_before);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(container, position.AnchorNode());
  EXPECT_EQ(3, position.GetPosition().OffsetInContainerNode());
  EXPECT_EQ(hidden, position.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(ax_hidden, ax_position_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest,
       PreviousPositionAfterARIAHiddenShouldNotSkipARIAHidden) {
  // Note: aria-describedby adds hidden target subtrees to the a11y tree as
  // "ignored but included in tree".
  SetBodyInnerHTML(R"HTML(
      <p id="before">Before aria-hidden.</p>
      <p id="ariaHidden" aria-describedby="ariaHidden" aria-hidden="true">Aria-hidden.</p>
      <p id="after">After aria-hidden.</p>
      )HTML");

  const Node* hidden = GetElementById("ariaHidden");
  ASSERT_NE(nullptr, hidden);
  ASSERT_NE(nullptr, hidden->firstChild());
  const Node* after = GetElementById("after");
  ASSERT_NE(nullptr, after);

  const AXObject* ax_after = GetAXObjectByElementId("after");
  ASSERT_NE(nullptr, ax_after);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_after->RoleValue());
  ASSERT_NE(nullptr, GetAXObjectByElementId("ariaHidden"));
  ASSERT_TRUE(GetAXObjectByElementId("ariaHidden")->IsIgnored());

  const auto ax_position = AXPosition::CreatePositionBeforeObject(*ax_after);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(GetDocument().body(), position.AnchorNode());
  EXPECT_EQ(5, position.GetPosition().OffsetInContainerNode());
  EXPECT_EQ(after, position.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(ax_after, ax_position_from_dom.ChildAfterTreePosition());

  const auto ax_position_previous = ax_position.CreatePreviousPosition();
  const auto position_previous = ax_position_previous.ToPositionWithAffinity();
  EXPECT_EQ(hidden->firstChild(), position_previous.AnchorNode());
  EXPECT_EQ(12, position_previous.GetPosition().OffsetInContainerNode());
  EXPECT_EQ(nullptr,
            position_previous.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_previous_from_dom =
      AXPosition::FromPosition(position_previous);
  EXPECT_EQ(ax_position_previous, ax_position_previous_from_dom);
  EXPECT_EQ(nullptr, ax_position_previous_from_dom.ChildAfterTreePosition());
}

TEST_F(AccessibilityTest, FromPositionInARIAHidden) {
  // Note: aria-describedby adds hidden target subtrees to the a11y tree as
  // "ignored but included in tree".
  SetBodyInnerHTML(R"HTML(
      <div role="main" id="container">
        <p id="before">Before aria-hidden.</p>
        <p id="ariaHidden" aria-describedby="ariaHidden" aria-hidden="true">Aria-hidden.</p>
        <p id="after">After aria-hidden.</p>
      </div>
      )HTML");

  const Node* hidden = GetElementById("ariaHidden");
  ASSERT_NE(nullptr, hidden);

  const AXObject* ax_container = GetAXObjectByElementId("container");
  ASSERT_NE(nullptr, ax_container);
  ASSERT_EQ(ax::mojom::Role::kMain, ax_container->RoleValue());
  ASSERT_EQ(3, ax_container->ChildCountIncludingIgnored());
  const AXObject* ax_before = GetAXObjectByElementId("before");
  ASSERT_NE(nullptr, ax_before);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_before->RoleValue());
  const AXObject* ax_after = GetAXObjectByElementId("after");
  ASSERT_NE(nullptr, ax_after);
  ASSERT_EQ(ax::mojom::Role::kParagraph, ax_after->RoleValue());
  const AXObject* ax_hidden = GetAXObjectByElementId("ariaHidden");
  ASSERT_NE(nullptr, ax_hidden);
  ASSERT_TRUE(ax_hidden->IsIgnored());

  const auto position_first = Position::FirstPositionInNode(*hidden);
  // Since "ax_hidden" has a static text child, the AXPosition should move to an
  // equivalent position on the static text child.
  auto ax_position_left =
      AXPosition::FromPosition(position_first, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_TRUE(ax_position_left.IsValid());
  EXPECT_TRUE(ax_position_left.IsTextPosition());
  EXPECT_EQ(ax_hidden->FirstChildIncludingIgnored(),
            ax_position_left.ContainerObject());
  EXPECT_EQ(0, ax_position_left.TextOffset());

  // In this case, the adjustment behavior should not affect the outcome because
  // there is an equivalent AXPosition in the static text child.
  auto ax_position_right =
      AXPosition::FromPosition(position_first, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveRight);
  EXPECT_TRUE(ax_position_right.IsValid());
  EXPECT_TRUE(ax_position_right.IsTextPosition());
  EXPECT_EQ(ax_hidden->FirstChildIncludingIgnored(),
            ax_position_right.ContainerObject());
  EXPECT_EQ(0, ax_position_right.TextOffset());

  const auto position_before = Position::BeforeNode(*hidden);
  ax_position_left =
      AXPosition::FromPosition(position_before, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_TRUE(ax_position_left.IsValid());
  EXPECT_FALSE(ax_position_left.IsTextPosition());
  EXPECT_EQ(ax_container, ax_position_left.ContainerObject());
  EXPECT_EQ(1, ax_position_left.ChildIndex());
  EXPECT_EQ(ax_hidden, ax_position_left.ChildAfterTreePosition());

  // Since an AXPosition before "ax_hidden" is valid, i.e. it does not need to
  // be adjusted, then adjustment behavior should not make a difference in the
  // outcome.
  ax_position_right =
      AXPosition::FromPosition(position_before, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveRight);
  EXPECT_TRUE(ax_position_right.IsValid());
  EXPECT_FALSE(ax_position_right.IsTextPosition());
  EXPECT_EQ(ax_container, ax_position_right.ContainerObject());
  EXPECT_EQ(1, ax_position_right.ChildIndex());
  EXPECT_EQ(ax_hidden, ax_position_right.ChildAfterTreePosition());

  // The DOM node right after "hidden" is accessibility ignored, so we should
  // see an adjustment in the relevant direction.
  const auto position_after = Position::AfterNode(*hidden);
  ax_position_left =
      AXPosition::FromPosition(position_after, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_TRUE(ax_position_left.IsValid());
  EXPECT_TRUE(ax_position_left.IsTextPosition());
  EXPECT_EQ(ax_hidden->FirstChildIncludingIgnored(),
            ax_position_left.ContainerObject());
  EXPECT_EQ(12, ax_position_left.TextOffset());

  ax_position_right =
      AXPosition::FromPosition(position_after, TextAffinity::kDownstream,
                               AXPositionAdjustmentBehavior::kMoveRight);
  EXPECT_TRUE(ax_position_right.IsValid());
  EXPECT_FALSE(ax_position_right.IsTextPosition());
  EXPECT_EQ(ax_container, ax_position_right.ContainerObject());
  EXPECT_EQ(2, ax_position_right.ChildIndex());
  EXPECT_EQ(ax_after, ax_position_right.ChildAfterTreePosition());
}

//
// Canvas fallback can cause things to be in the accessibility tree that are not
// in the layout tree.
//

TEST_F(AccessibilityTest, PositionInCanvas) {
  SetBodyInnerHTML(R"HTML(
      <canvas id="canvas1" width="100" height="100">Fallback text</canvas>
      <canvas id="canvas2" width="100" height="100">
      <button id="button">Fallback button</button>
    </canvas>
    )HTML");

  const Node* canvas_1 = GetElementById("canvas1");
  ASSERT_NE(nullptr, canvas_1);
  const Node* text = canvas_1->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());
  const Node* canvas_2 = GetElementById("canvas2");
  ASSERT_NE(nullptr, canvas_2);
  const Node* button = GetElementById("button");
  ASSERT_NE(nullptr, button);

  const AXObject* ax_canvas_1 = GetAXObjectByElementId("canvas1");
  ASSERT_NE(nullptr, ax_canvas_1);
  ASSERT_EQ(ax::mojom::Role::kCanvas, ax_canvas_1->RoleValue());
  const AXObject* ax_text = ax_canvas_1->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text->RoleValue());
  const AXObject* ax_canvas_2 = GetAXObjectByElementId("canvas2");
  ASSERT_NE(nullptr, ax_canvas_2);
  ASSERT_EQ(ax::mojom::Role::kCanvas, ax_canvas_2->RoleValue());
  const AXObject* ax_button = GetAXObjectByElementId("button");
  ASSERT_NE(nullptr, ax_button);
  ASSERT_EQ(ax::mojom::Role::kButton, ax_button->RoleValue());

  // The first child of "canvas1" is a text object. Creating a "before children"
  // position in this canvas should return the equivalent text position anchored
  // to before the first character of the text object.
  const auto ax_position_1 =
      AXPosition::CreateFirstPositionInObject(*ax_canvas_1);
  EXPECT_TRUE(ax_position_1.IsTextPosition());
  EXPECT_EQ(ax_text, ax_position_1.ContainerObject());
  EXPECT_EQ(0, ax_position_1.TextOffset());

  const auto position_1 = ax_position_1.ToPositionWithAffinity();
  EXPECT_EQ(text, position_1.AnchorNode());
  EXPECT_TRUE(position_1.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position_1.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom_1 = AXPosition::FromPosition(position_1);
  EXPECT_EQ(ax_position_1, ax_position_from_dom_1);

  const auto ax_position_2 = AXPosition::CreatePositionBeforeObject(*ax_text);
  EXPECT_TRUE(ax_position_2.IsTextPosition());
  EXPECT_EQ(ax_text, ax_position_2.ContainerObject());
  EXPECT_EQ(0, ax_position_2.TextOffset());

  const auto position_2 = ax_position_2.ToPositionWithAffinity();
  EXPECT_EQ(text, position_2.AnchorNode());
  EXPECT_EQ(0, position_2.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom_2 = AXPosition::FromPosition(position_2);
  EXPECT_EQ(ax_position_2, ax_position_from_dom_2);

  const auto ax_position_3 =
      AXPosition::CreateLastPositionInObject(*ax_canvas_2);
  EXPECT_FALSE(ax_position_3.IsTextPosition());
  EXPECT_EQ(ax_canvas_2, ax_position_3.ContainerObject());
  EXPECT_EQ(1, ax_position_3.ChildIndex());
  EXPECT_EQ(nullptr, ax_position_3.ChildAfterTreePosition());

  const auto position_3 = ax_position_3.ToPositionWithAffinity();
  EXPECT_EQ(canvas_2, position_3.AnchorNode());
  // There is a line break between the start of the canvas and the button.
  EXPECT_EQ(2, position_3.GetPosition().ComputeOffsetInContainerNode());

  const auto ax_position_from_dom_3 = AXPosition::FromPosition(position_3);
  EXPECT_EQ(ax_position_3, ax_position_from_dom_3);

  const auto ax_position_4 = AXPosition::CreatePositionBeforeObject(*ax_button);
  EXPECT_FALSE(ax_position_4.IsTextPosition());
  EXPECT_EQ(ax_canvas_2, ax_position_4.ContainerObject());
  EXPECT_EQ(0, ax_position_4.ChildIndex());
  EXPECT_EQ(ax_button, ax_position_4.ChildAfterTreePosition());

  const auto position_4 = ax_position_4.ToPositionWithAffinity();
  EXPECT_EQ(canvas_2, position_4.AnchorNode());
  // There is a line break between the start of the canvas and the button.
  EXPECT_EQ(1, position_4.GetPosition().ComputeOffsetInContainerNode());
  EXPECT_EQ(button, position_4.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_from_dom_4 = AXPosition::FromPosition(position_4);
  EXPECT_EQ(ax_position_4, ax_position_from_dom_4);
}

//
// Some layout objects, e.g. list bullets and CSS::before/after content, appear
// in the accessibility tree but are not present in the DOM.
//

TEST_F(AccessibilityTest, PositionBeforeListMarker) {
  SetBodyInnerHTML(R"HTML(
      <ul id="list">
        <li id="listItem">Item.</li>
      </ul>
      )HTML");

  const Node* list = GetElementById("list");
  ASSERT_NE(nullptr, list);
  const Node* item = GetElementById("listItem");
  ASSERT_NE(nullptr, item);
  const Node* text = item->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());

  const AXObject* ax_item = GetAXObjectByElementId("listItem");
  ASSERT_NE(nullptr, ax_item);
  ASSERT_EQ(ax::mojom::Role::kListItem, ax_item->RoleValue());
  ASSERT_EQ(2, ax_item->ChildCountIncludingIgnored());
  const AXObject* ax_marker = ax_item->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_marker);
  ASSERT_EQ(ax::mojom::Role::kListMarker, ax_marker->RoleValue());

  //
  // Test adjusting invalid DOM positions to the left.
  //

  const auto ax_position_1 = AXPosition::CreateFirstPositionInObject(*ax_item);
  EXPECT_EQ(ax_item, ax_position_1.ContainerObject());
  EXPECT_FALSE(ax_position_1.IsTextPosition());
  EXPECT_EQ(0, ax_position_1.ChildIndex());
  EXPECT_EQ(ax_marker, ax_position_1.ChildAfterTreePosition());

  const auto position_1 = ax_position_1.ToPositionWithAffinity(
      AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_EQ(list, position_1.AnchorNode());
  // There is a line break between the start of the list and the first item.
  EXPECT_EQ(1, position_1.GetPosition().OffsetInContainerNode());
  EXPECT_EQ(item, position_1.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_from_dom_1 = AXPosition::FromPosition(position_1);
  EXPECT_EQ(
      ax_position_1.AsValidDOMPosition(AXPositionAdjustmentBehavior::kMoveLeft),
      ax_position_from_dom_1);
  EXPECT_EQ(ax_item, ax_position_from_dom_1.ChildAfterTreePosition());

  const auto ax_position_2 = AXPosition::CreatePositionBeforeObject(*ax_marker);
  EXPECT_EQ(ax_item, ax_position_2.ContainerObject());
  EXPECT_FALSE(ax_position_2.IsTextPosition());
  EXPECT_EQ(0, ax_position_2.ChildIndex());
  EXPECT_EQ(ax_marker, ax_position_2.ChildAfterTreePosition());

  const auto position_2 = ax_position_2.ToPositionWithAffinity(
      AXPositionAdjustmentBehavior::kMoveLeft);
  EXPECT_EQ(list, position_2.AnchorNode());
  // There is a line break between the start of the list and the first item.
  EXPECT_EQ(1, position_2.GetPosition().OffsetInContainerNode());
  EXPECT_EQ(item, position_2.GetPosition().ComputeNodeAfterPosition());

  const auto ax_position_from_dom_2 = AXPosition::FromPosition(position_2);
  EXPECT_EQ(
      ax_position_2.AsValidDOMPosition(AXPositionAdjustmentBehavior::kMoveLeft),
      ax_position_from_dom_2);
  EXPECT_EQ(ax_item, ax_position_from_dom_2.ChildAfterTreePosition());

  //
  // Test adjusting the same invalid positions to the right.
  //

  const auto position_3 = ax_position_1.ToPositionWithAffinity(
      AXPositionAdjustmentBehavior::kMoveRight);
  EXPECT_EQ(text, position_3.AnchorNode());
  EXPECT_TRUE(position_3.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position_3.GetPosition().OffsetInContainerNode());

  const auto position_4 = ax_position_2.ToPositionWithAffinity(
      AXPositionAdjustmentBehavior::kMoveRight);
  EXPECT_EQ(text, position_4.AnchorNode());
  EXPECT_TRUE(position_4.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position_4.GetPosition().OffsetInContainerNode());
}

TEST_F(AccessibilityTest, PositionAfterListMarker) {
  SetBodyInnerHTML(R"HTML(
      <ol>
        <li id="listItem">Item.</li>
      </ol>
      )HTML");

  const Node* item = GetElementById("listItem");
  ASSERT_NE(nullptr, item);
  const Node* text = item->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_TRUE(text->IsTextNode());

  const AXObject* ax_item = GetAXObjectByElementId("listItem");
  ASSERT_NE(nullptr, ax_item);
  ASSERT_EQ(ax::mojom::Role::kListItem, ax_item->RoleValue());
  ASSERT_EQ(2, ax_item->ChildCountIncludingIgnored());
  const AXObject* ax_marker = ax_item->FirstChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_marker);
  ASSERT_EQ(ax::mojom::Role::kListMarker, ax_marker->RoleValue());
  const AXObject* ax_text = ax_item->LastChildIncludingIgnored();
  ASSERT_NE(nullptr, ax_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text->RoleValue());

  const auto ax_position = AXPosition::CreatePositionAfterObject(*ax_marker);
  const auto position = ax_position.ToPositionWithAffinity();
  EXPECT_EQ(text, position.AnchorNode());
  EXPECT_TRUE(position.GetPosition().IsOffsetInAnchor());
  EXPECT_EQ(0, position.GetPosition().OffsetInContainerNode());

  const auto ax_position_from_dom = AXPosition::FromPosition(position);
  EXPECT_EQ(ax_position, ax_position_from_dom);
  EXPECT_EQ(ax_text, ax_position_from_dom.ContainerObject());
  EXPECT_TRUE(ax_position_from_dom.IsTextPosition());
  EXPECT_EQ(0, ax_position_from_dom.TextOffset());
}

// TODO(nektar) Fix test to work with ignored containers of pseudo content.
TEST_F(AccessibilityTest, DISABLED_PositionInCSSContent) {
  SetBodyInnerHTML(kCSSBeforeAndAfter);

  const Node* quote = GetElementById("quote");
  ASSERT_NE(nullptr, quote);
  // CSS text nodes are not in the DOM tree.
  const Node* text = quote->firstChild();
  ASSERT_NE(nullptr, text);
  ASSERT_FALSE(text->IsPseudoElement());
  ASSERT_TRUE(text->IsTextNode());

  const AXObject* ax_quote = GetAXObjectByElementId("quote");
  ASSERT_NE(nullptr, ax_quote);
  ASSERT_TRUE(ax_quote->IsIgnored());
  const AXObject* ax_quote_parent = ax_quote->ParentObjectUnignored();
  ASSERT_NE(nullptr, ax_quote_parent);
  ASSERT_EQ(4, ax_quote_parent->UnignoredChildCount());
  const AXObject* ax_css_before = ax_quote_parent->UnignoredChildAt(0);
  ASSERT_NE(nullptr, ax_css_before);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_css_before->RoleValue());
  const AXObject* ax_text = ax_quote_parent->UnignoredChildAt(1);
  ASSERT_NE(nullptr, ax_text);
  ASSERT_EQ(ax::mojom::Role::kStaticText, ax_text->RoleValue());
  const AXObject* ax_css_after = ax_quote_parent->UnignoredChildAt(2);
  ASSERT_NE(nullptr, ax_css_after);
  ASSERT_EQ(ax
```