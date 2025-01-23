Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is the second part of a three-part file.

The code consists of a series of C++ unit tests for a class or function named `LocalCaretRectOfPosition`. These tests seem to verify the correct calculation of the caret position (a small visual marker indicating where text input will occur) in various scenarios.

Specifically, based on the test names and code:

- It tests caret positioning after line breaks (`<br>`, `\n`) in different contexts like plain text, `<pre>` elements, and `<textarea>` elements.
- It tests caret positioning around collapsed whitespace.
- It tests caret positioning within Shadow DOM structures.
- It tests caret positioning next to images.
- It tests caret positioning in different bidirectional text scenarios (LTR and RTL).
- It tests caret positioning in multi-column layouts.
- It tests caret positioning with `unicode-bidi: plaintext`.
- It tests caret positioning when an element has a non-leaf child.
- It tests caret positioning in bidirectional text containing images.
- It tests caret positioning within or around non-editable content (using `contenteditable="false"`).
- It tests caret positioning within `<option>` elements with `display: contents`.
- It tests caret positioning within elements using `text-combine-upright`.

Since this is part 2 of 3, I should focus on summarizing the functionality *demonstrated in this specific part*.
这是 blink 渲染引擎中 `local_caret_rect_test.cc` 文件的第二个代码片段，它主要功能是**测试在各种复杂文本布局和编辑场景下，光标（caret）位置的计算是否正确**。 这些测试用例验证了 `LocalCaretRectOfPosition` 函数在不同 HTML 结构、CSS 样式和文本内容下的行为。

**功能归纳：**

这个代码片段中的测试用例主要关注以下几个方面的光标位置计算：

1. **处理换行符：** 测试在 `<br>` 标签和 `<pre>` 标签内的换行符后，光标的正确位置。包括在 `<textarea>` 元素内部处理换行的情况。
2. **处理空格折叠：** 测试当多个连续空格被折叠成一个空格显示时，光标的正确位置。
3. **处理 Shadow DOM：** 测试在使用了 Shadow DOM 的情况下，光标在主 DOM 树和扁平树中的位置计算是否一致。
4. **处理图片元素：** 测试光标在图片元素前后的位置计算。
5. **处理不同方向的文本 (BiDi)：** 测试在从左到右 (LTR) 和从右到左 (RTL) 的文本混合情况下，光标的正确位置，包括在 `<bdo>` 标签内的文本。
6. **处理修剪后的换行符：** 测试在 `<div>` 元素中，换行符后光标的位置。
7. **处理多列布局：** 测试在 CSS 多列布局中，光标在不同列中的位置。
8. **处理 `unicode-bidi: plaintext`：** 测试设置了 `unicode-bidi: plaintext` 属性的元素中光标的位置。
9. **处理没有叶子子节点的元素：** 测试光标在一个包含 `<br>` 标签和一个带有 `border-left` 样式的 `<span>` 标签的 `<div>` 元素中的位置。
10. **处理包含图片的双向文本：** 测试在 RTL 文本中包含图片时，光标在图片前后的位置。
11. **处理不可编辑内容：** 测试光标在 `contenteditable="false"` 元素开始和结束位置的计算，包括嵌套在可编辑容器内的情况。这包括在普通 DOM 树和扁平树中的测试。
12. **处理带有折叠空格的不可编辑内容：**  测试不可编辑元素前后有空格时，光标的位置。
13. **处理包含 SVG 的不可编辑内容：** 测试不可编辑元素包含 SVG 时，光标的位置。
14. **处理 `display: contents` 的 `<option>` 元素：** 测试当 `<option>` 元素设置了 `display: contents` 时，光标位置的计算。
15. **处理 `text-combine-upright`：** 测试在使用了 `text-combine-upright` 属性（用于垂直排版中合并字符）的元素中，光标的正确位置。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **HTML:** 测试用例通过 `SetBodyContent` 和 `SetBodyInnerHTML` 设置不同的 HTML 结构，例如包含 `<br>`, `<pre>`, `<textarea>`, `<span>`, `<img>`, `<bdo>`, `<meter>`, `<div>`, `<option>`, `<tcy>` 等元素。这些元素是构成网页内容的基础。
* **CSS:**  测试用例通过 `InsertStyleElement` 插入 CSS 样式，例如 `font`, `width`, `column-count`, `unicode-bidi`, `border-left`, `vertical-align`, `display`, `writing-mode`, `text-combine-upright` 等。这些样式会影响元素的布局和渲染，从而影响光标的位置。
* **JavaScript (间接关系):**  虽然这个测试文件本身是 C++ 代码，但它测试的功能直接关系到用户在网页上进行文本编辑时的光标行为。当用户使用 JavaScript 操作 DOM 或修改样式时，最终会影响到光标的位置。例如，JavaScript 可以动态地插入或删除元素，或者修改元素的 CSS 样式，这些操作都需要浏览器引擎正确计算光标位置。

**逻辑推理的假设输入与输出举例：**

**假设输入:**
```html
<pre style='font: 10px/10px Ahem;'>foo\n\n</pre>
```
光标可能位于 'o' 后面，换行符后面或者最后。

**对应的 `PositionWithAffinity` 输入：**
* `PositionWithAffinity(Position(foo, 3), TextAffinity::kDownstream)` (在 'o' 之后)
* `PositionWithAffinity(Position(foo, 4), TextAffinity::kDownstream)` (第一个换行符之后)
* `PositionWithAffinity(Position(foo, 5), TextAffinity::kDownstream)` (第二个换行符之后)

**预期输出 (基于测试代码):**
* `LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10))`
* `LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 10, 1, 10))`
* `LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 10, 1, 10))`

**用户或编程常见的使用错误举例：**

* **用户操作错误：** 用户在 `<textarea>` 中输入文本，并敲击回车键换行。如果浏览器的光标位置计算有误，用户可能会发现光标跳到了错误的位置，导致输入混乱。
* **编程错误：**  开发者在实现富文本编辑器等功能时，可能会尝试手动设置或获取光标位置。如果浏览器引擎的光标位置计算不准确，开发者获取到的光标信息可能会是错误的，导致基于光标位置的操作出现偏差。例如，一个在光标位置插入特定元素的 JavaScript 代码，如果光标位置错误，就会插入到错误的地方。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户打开一个包含可编辑区域的网页。** 例如，一个包含 `<textarea>` 元素或者设置了 `contenteditable` 属性的 `<div>` 元素的页面。
2. **用户在可编辑区域内进行输入。**  例如，输入文本、按下回车键换行、粘贴内容等。
3. **当用户进行这些操作时，浏览器引擎需要计算光标的当前位置，以便正确地渲染光标，并确定用户下一步输入的内容应该插入到哪里。**
4. **如果光标位置计算出现错误，用户可能会观察到光标跳跃、文本插入位置错误等异常行为。**
5. **为了调试这些问题，开发者可能会查看浏览器引擎的源代码，尤其是负责光标位置计算的部分，例如 `LocalCaretRectOfPosition` 函数以及相关的测试用例。**  这些测试用例正是用来验证在各种用户操作场景下，光标位置计算的正确性的。例如，开发者可能会特别关注与换行、空格、富文本编辑等相关的测试用例，以定位问题所在。

总而言之，这个代码片段通过大量的测试用例，确保了 blink 引擎在各种复杂的文本布局和编辑场景下，能够准确地计算光标的位置，从而为用户提供流畅和符合预期的编辑体验。

### 提示词
```
这是目录为blink/renderer/core/editing/local_caret_rect_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ctOfPosition(PositionWithAffinity(
          Position::AfterNode(*first_br), TextAffinity::kDownstream)));
  EXPECT_EQ(
      LocalCaretRect(second_br->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
      LocalCaretRectOfPosition(PositionWithAffinity(
          Position::AfterNode(*second_br), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, AfterLineBreakInPre) {
  LoadAhem();
  SetBodyContent("<pre style='font: 10px/10px Ahem;'>foo\n\n</pre>");
  const Node* pre = GetDocument().body()->firstChild();
  const Node* foo = pre->firstChild();
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 4), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 5), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, AfterLineBreakInPre2) {
  LoadAhem();
  // This test case simulates the rendering of the inner editor of
  // <textarea>foo\n</textarea> without using text control element.
  SetBodyContent("<pre style='font: 10px/10px Ahem;'>foo\n<br></pre>");
  const Node* pre = GetDocument().body()->firstChild();
  const Node* foo = pre->firstChild();
  const Node* br = foo->nextSibling();
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(br->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 4), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(br->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(*br), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, AfterLineBreakTextArea) {
  LoadAhem();
  SetBodyContent("<textarea style='font: 10px/10px Ahem; '>foo\n\n</textarea>");
  const auto* textarea = ToTextControl(GetDocument().body()->firstChild());
  const Node* inner_text = textarea->InnerEditorElement()->firstChild();
  EXPECT_EQ(
      LocalCaretRect(inner_text->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
      LocalCaretRectOfPosition(PositionWithAffinity(
          Position(inner_text, 3), TextAffinity::kDownstream)));
  EXPECT_EQ(
      LocalCaretRect(inner_text->GetLayoutObject(), PhysicalRect(0, 10, 1, 10)),
      LocalCaretRectOfPosition(PositionWithAffinity(
          Position(inner_text, 4), TextAffinity::kDownstream)));
  const Node* hidden_br = inner_text->nextSibling();
  EXPECT_EQ(
      LocalCaretRect(hidden_br->GetLayoutObject(), PhysicalRect(0, 20, 1, 10)),
      LocalCaretRectOfPosition(PositionWithAffinity(
          Position(inner_text, 5), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, CollapsedSpace) {
  LoadAhem();
  SetBodyContent(
      "<div style='font: 10px/10px Ahem;'>"
      "<span>foo</span><span>  </span></div>");
  const Node* first_span = GetDocument().body()->firstChild()->firstChild();
  const Node* foo = first_span->firstChild();
  const Node* second_span = first_span->nextSibling();
  const Node* white_spaces = second_span->firstChild();
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(foo, 3), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position::AfterNode(*foo), TextAffinity::kDownstream)));
  // TODO(yoichio): Following should return valid rect: crbug.com/812535.
  EXPECT_EQ(
      LocalCaretRect(first_span->GetLayoutObject(), PhysicalRect(0, 0, 0, 0)),
      LocalCaretRectOfPosition(
          PositionWithAffinity(Position::LastPositionInNode(*first_span),
                               TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(white_spaces, 0), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(white_spaces, 1), TextAffinity::kDownstream)));
  EXPECT_EQ(LocalCaretRect(foo->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(
                Position(white_spaces, 2), TextAffinity::kDownstream)));
}

TEST_F(LocalCaretRectTest, AbsoluteCaretBoundsOfWithShadowDOM) {
  const char* body_content =
      "<p id='host'><b slot='#one' id='one'>11</b><b name='#two' "
      "id='two'>22</b></p>";
  const char* shadow_content =
      "<div><slot name=#two></slot><slot name=#one></slot></div>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* body = GetDocument().body();
  Element* one = body->QuerySelector(AtomicString("#one"));

  gfx::Rect bounds_in_dom_tree = AbsoluteCaretBoundsOf(
      CreateVisiblePosition(Position(one, 0)).ToPositionWithAffinity());
  gfx::Rect bounds_in_flat_tree =
      AbsoluteCaretBoundsOf(CreateVisiblePosition(PositionInFlatTree(one, 0))
                                .ToPositionWithAffinity());

  EXPECT_FALSE(bounds_in_dom_tree.IsEmpty());
  EXPECT_EQ(bounds_in_dom_tree, bounds_in_flat_tree);
}

// Repro case of crbug.com/680428
TEST_F(LocalCaretRectTest, AbsoluteSelectionBoundsOfWithImage) {
  SetBodyContent("<div>foo<img></div>");

  Node* node = GetDocument().QuerySelector(AtomicString("img"));
  gfx::Rect rect = AbsoluteSelectionBoundsOf(VisiblePosition::Create(
      PositionWithAffinity(Position::LastPositionInNode(*node))));
  EXPECT_FALSE(rect.IsEmpty());
}

static std::pair<PhysicalRect, PhysicalRect> GetPhysicalRects(
    const Position& caret) {
  const PositionWithAffinity position(caret);
  const PhysicalRect& position_rect = LocalCaretRectOfPosition(position).rect;
  const PositionWithAffinity visible_position(
      CreateVisiblePosition(position).DeepEquivalent());
  const PhysicalRect& visible_position_rect =
      LocalCaretRectOfPosition(visible_position).rect;
  return {position_rect, visible_position_rect};
}

TEST_F(LocalCaretRectTest, AfterLineBreakInPreBlockLTRLineLTR) {
  LoadAhem();
  InsertStyleElement("pre{ font: 10px/10px Ahem; width: 300px }");
  const Position& caret =
      SetCaretTextToBody("<pre dir='ltr'>foo\n|<bdo dir='ltr'>abc</bdo></pre>");
  auto [position_rect, visible_position_rect] = GetPhysicalRects(caret);
  EXPECT_EQ(PhysicalRect(0, 10, 1, 10), position_rect);
  EXPECT_EQ(PhysicalRect(0, 10, 1, 10), visible_position_rect);
}

TEST_F(LocalCaretRectTest, AfterLineBreakInPreBlockLTRLineRTL) {
  LoadAhem();
  InsertStyleElement("pre{ font: 10px/10px Ahem; width: 300px }");
  const Position& caret =
      SetCaretTextToBody("<pre dir='ltr'>foo\n|<bdo dir='rtl'>abc</bdo></pre>");
  auto [position_rect, visible_position_rect] = GetPhysicalRects(caret);
  EXPECT_EQ(PhysicalRect(0, 10, 1, 10), position_rect);
  EXPECT_EQ(PhysicalRect(0, 10, 1, 10), visible_position_rect);
}

TEST_F(LocalCaretRectTest, AfterLineBreakInPreBlockRTLLineLTR) {
  LoadAhem();
  InsertStyleElement("pre{ font: 10px/10px Ahem; width: 300px }");
  const Position& caret =
      SetCaretTextToBody("<pre dir='rtl'>foo\n|<bdo dir='ltr'>abc</bdo></pre>");
  auto [position_rect, visible_position_rect] = GetPhysicalRects(caret);
  EXPECT_EQ(PhysicalRect(299, 10, 1, 10), position_rect);
  EXPECT_EQ(PhysicalRect(299, 10, 1, 10), visible_position_rect);
}

TEST_F(LocalCaretRectTest, AfterLineBreakInPreBlockRTLLineRTL) {
  LoadAhem();
  InsertStyleElement("pre{ font: 10px/10px Ahem; width: 300px }");
  const Position& caret =
      SetCaretTextToBody("<pre dir='rtl'>foo\n|<bdo dir='rtl'>abc</bdo></pre>");
  auto [position_rect, visible_position_rect] = GetPhysicalRects(caret);
  EXPECT_EQ(PhysicalRect(299, 10, 1, 10), position_rect);
  EXPECT_EQ(PhysicalRect(299, 10, 1, 10), visible_position_rect);
}

// crbug.com/834686
TEST_F(LocalCaretRectTest, AfterTrimedLineBreak) {
  LoadAhem();
  InsertStyleElement("body { font: 10px/10px Ahem; width: 300px }");
  const Position& caret = SetCaretTextToBody("<div>foo\n|</div>");
  auto [position_rect, visible_position_rect] = GetPhysicalRects(caret);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10), position_rect);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10), visible_position_rect);
}

// See also CaretPositionTest.MultiColumnSingleText
TEST_F(LocalCaretRectTest, MultiColumnSingleText) {
  LoadAhem();
  InsertStyleElement(
      "div { font: 10px/15px Ahem; column-count: 3; width: 20ch; }");
  SetBodyInnerHTML("<div id=target>abc def ghi jkl mno pqr</div>");
  // This HTML is rendered as:
  //    abc ghi mno
  //    def jkl
  const auto& target = *GetElementById("target");
  const Text& text = *To<Text>(target.firstChild());

  // Note: Legacy layout caret rect is in stitch coordinate space == as if
  // columns are laid out vertically.
  // NG caret rect is in relative to containing box fragment.

  // "abc " in column 1
  EXPECT_EQ(PhysicalRect(0, 2, 1, 10),
            LocalCaretRectOf(Position(text, 0)).rect);
  EXPECT_EQ(PhysicalRect(10, 2, 1, 10),
            LocalCaretRectOf(Position(text, 1)).rect);
  EXPECT_EQ(PhysicalRect(20, 2, 1, 10),
            LocalCaretRectOf(Position(text, 2)).rect);
  EXPECT_EQ(PhysicalRect(30, 2, 1, 10),
            LocalCaretRectOf(Position(text, 3)).rect);

  // "def " in column 1
  EXPECT_EQ(PhysicalRect(0, 17, 1, 10),
            LocalCaretRectOf(Position(text, 4)).rect);
  EXPECT_EQ(PhysicalRect(10, 17, 1, 10),
            LocalCaretRectOf(Position(text, 5)).rect);
  EXPECT_EQ(PhysicalRect(20, 17, 1, 10),
            LocalCaretRectOf(Position(text, 6)).rect);
  EXPECT_EQ(PhysicalRect(30, 17, 1, 10),
            LocalCaretRectOf(Position(text, 7)).rect);

  // "ghi " in column 2
  EXPECT_EQ(PhysicalRect(0, 2, 1, 10),
            LocalCaretRectOf(Position(text, 8)).rect);
  EXPECT_EQ(PhysicalRect(10, 2, 1, 10),
            LocalCaretRectOf(Position(text, 9)).rect);
  EXPECT_EQ(PhysicalRect(20, 2, 1, 10),
            LocalCaretRectOf(Position(text, 10)).rect);
  EXPECT_EQ(PhysicalRect(30, 2, 1, 10),
            LocalCaretRectOf(Position(text, 11)).rect);

  // "jkl " in column 2
  EXPECT_EQ(PhysicalRect(0, 17, 1, 10),
            LocalCaretRectOf(Position(text, 12)).rect);
  EXPECT_EQ(PhysicalRect(10, 17, 1, 10),
            LocalCaretRectOf(Position(text, 13)).rect);
  EXPECT_EQ(PhysicalRect(20, 17, 1, 10),
            LocalCaretRectOf(Position(text, 14)).rect);
  EXPECT_EQ(PhysicalRect(30, 17, 1, 10),
            LocalCaretRectOf(Position(text, 15)).rect);

  // "mno " in column 3
  EXPECT_EQ(PhysicalRect(0, 2, 1, 10),
            LocalCaretRectOf(Position(text, 16)).rect);
  EXPECT_EQ(PhysicalRect(10, 2, 1, 10),
            LocalCaretRectOf(Position(text, 17)).rect);
  EXPECT_EQ(PhysicalRect(20, 2, 1, 10),
            LocalCaretRectOf(Position(text, 18)).rect);
  EXPECT_EQ(PhysicalRect(30, 2, 1, 10),
            LocalCaretRectOf(Position(text, 19)).rect);

  // "pqr" in column 3
  EXPECT_EQ(PhysicalRect(0, 17, 1, 10),
            LocalCaretRectOf(Position(text, 20)).rect);
  EXPECT_EQ(PhysicalRect(10, 17, 1, 10),
            LocalCaretRectOf(Position(text, 21)).rect);
  EXPECT_EQ(PhysicalRect(20, 17, 1, 10),
            LocalCaretRectOf(Position(text, 22)).rect);
  EXPECT_EQ(PhysicalRect(30, 17, 1, 10),
            LocalCaretRectOf(Position(text, 23)).rect);
}

TEST_F(LocalCaretRectTest, UnicodeBidiPlaintextWithDifferentBlockDirection) {
  LoadAhem();
  InsertStyleElement("div { font: 10px/10px Ahem; unicode-bidi: plaintext }");
  const Position position = SetCaretTextToBody("<div dir='rtl'>|abc</div>");
  const PhysicalRect caret_rect =
      LocalCaretRectOfPosition(PositionWithAffinity(position)).rect;
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10), caret_rect);
}

// http://crbug.com/835779
TEST_F(LocalCaretRectTest, NextLineWithoutLeafChild) {
  LoadAhem();
  InsertStyleElement("div { font: 10px/10px Ahem; width: 30px }");
  SetBodyContent(
      "<div>"
      "<br>"
      "<span style=\"border-left: 50px solid\"></span>"
      "foo"
      "</div>");

  const Element& br = *GetDocument().QuerySelector(AtomicString("br"));
  EXPECT_EQ(
      PhysicalRect(50, 10, 1, 10),
      LocalCaretRectOfPosition(PositionWithAffinity(Position::AfterNode(br)))
          .rect);
}

TEST_F(LocalCaretRectTest, BidiTextWithImage) {
  LoadAhem();
  InsertStyleElement(
      "div { font: 10px/10px Ahem; width: 30px }"
      "img { width: 10px; height: 10px; vertical-align: bottom }");
  SetBodyContent("<div dir=rtl>X<img id=image>Y</div>");
  const Element& image = *GetElementById("image");
  const LayoutObject* image_layout = image.GetLayoutObject();
  const LayoutObject* text_before = image.previousSibling()->GetLayoutObject();
  EXPECT_EQ(LocalCaretRect(text_before, PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOfPosition(
                PositionWithAffinity(Position::BeforeNode(image))));
  EXPECT_EQ(LocalCaretRect(image_layout, PhysicalRect(9, 0, 1, 10)),
            LocalCaretRectOfPosition(
                PositionWithAffinity(Position::AfterNode(image))));
}

// https://crbug.com/876044
TEST_F(LocalCaretRectTest, RtlMeterNoCrash) {
  SetBodyContent("foo<meter dir=rtl></meter>");
  const Position position = Position::LastPositionInNode(*GetDocument().body());
  // Shouldn't crash inside
  const LocalCaretRect local_caret_rect =
      LocalCaretRectOfPosition(PositionWithAffinity(position));
  EXPECT_EQ(
      GetDocument().QuerySelector(AtomicString("meter"))->GetLayoutObject(),
      local_caret_rect.layout_object);
}

// https://crbug.com/883044
TEST_F(LocalCaretRectTest, AfterCollapsedWhiteSpaceInRTLText) {
  LoadAhem();
  InsertStyleElement(
      "bdo { display: block; font: 10px/10px Ahem; width: 100px }");
  const Position position =
      SetCaretTextToBody("<bdo dir=rtl>AAA  |BBB<span>CCC</span></bdo>");
  const Node* text = position.AnchorNode();
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(60, 0, 1, 10)),
            LocalCaretRectOfPosition(
                PositionWithAffinity(position, TextAffinity::kDownstream)));
}

// https://crbug.com/936988
TEST_F(LocalCaretRectTest, AfterIneditableInline) {
  LoadAhem();
  InsertStyleElement("div { font: 10px/10px Ahem }");
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">foo</span></div>");
  const Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Node* text = div->firstChild()->firstChild();

  const Position position = Position::LastPositionInNode(*div);
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(30, 0, 1, 10)),
            LocalCaretRectOfPosition(PositionWithAffinity(position)));
}

// http://crbug.com/688015
TEST_F(LocalCaretRectTest, LocalCaretAtBeginningOfNonEditable) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding-left: 10px; font: 10px/10px Ahem }"
      "span { padding-left: 15px }");
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">foo</span></div>");
  const Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Element* span = To<Element>(div->firstChild());
  const Node* text = span->firstChild();

  const Position& position = Position::FirstPositionInNode(*div);
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(25, 0, 1, 10)),
            LocalCaretRectOf(position, kCanCrossEditingBoundary));
  EXPECT_EQ(LocalCaretRect(span->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOf(position, kCannotCrossEditingBoundary));
}

// http://crbug.com/1456664
TEST_F(LocalCaretRectTest,
       LocalCaretAtBeginningOfNonEditableWithCollapsedWhitespace) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding-left: 10px; font: 10px/10px Ahem }"
      "span { padding-left: 15px }");
  // Note the space before the span!
  SetBodyContent(
      "<div contenteditable> <span contenteditable=\"false\">foo</span></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Element* span = div->firstElementChild();
  const Node* text = span->firstChild();

  const Position& position = Position::FirstPositionInNode(*div);
  EXPECT_EQ(LocalCaretRect(text->GetLayoutObject(), PhysicalRect(25, 0, 1, 10)),
            LocalCaretRectOf(position, kCanCrossEditingBoundary));
  EXPECT_EQ(LocalCaretRect(span->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOf(position, kCannotCrossEditingBoundary));
}

// http://crbug.com/1384470
TEST_F(LocalCaretRectTest, LocalCaretAtBeginningOfNonEditableWithSvg) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding-left: 10px; font: 10px/10px Ahem }"
      "span { padding-left: 15px }"
      "svg { vertical-align: text-bottom; }");
  // Note the space before the span!
  SetBodyContent(
      "<div contenteditable> <span contenteditable=\"false\">"
      "<svg width=\"30\" height=\"10\"></svg></span></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Element* span = div->firstElementChild();

  const Position& position = Position::FirstPositionInNode(*div);
  // TODO(abotella): Should be (0, 0), with the svg as the layout object.
  EXPECT_EQ(LocalCaretRect(div->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOf(position, kCanCrossEditingBoundary));
  EXPECT_EQ(LocalCaretRect(span->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
            LocalCaretRectOf(position, kCannotCrossEditingBoundary));
}

// http://crbug.com/688015
TEST_F(LocalCaretRectTest, LocalCaretAtBeginningOfNonEditableInFlatTree) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding-left: 10px; font: 10px/10px Ahem }"
      "span { padding-left: 15px }");
  const char* body_content =
      "<div contenteditable><div id='host'>"
      "<span slot='#one'>foo1</span><span>foo3</span></div></div>";
  const char* shadow_content =
      "<slot name=#one></slot>"
      "<span contenteditable='false' id='foo2'>foo2</span>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");
  const Element* target = GetDocument().getElementById(AtomicString("host"));
  const Element* foo1_span = To<Element>(target->firstChild());
  const Node* foo1 = foo1_span->firstChild();

  const Position& position = Position::FirstPositionInNode(*target);
  EXPECT_EQ(LocalCaretRect(foo1->GetLayoutObject(), PhysicalRect(25, 0, 1, 10)),
            LocalCaretRectOf(position, kCanCrossEditingBoundary));
  // TODO(abotella): The layout object should probably be |foo1_span|'s.
  // TODO(abotella): We should avoid using LayoutBox::LocalCaretRect in
  // LayoutNG.
  EXPECT_EQ(
      LocalCaretRect(target->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
      LocalCaretRectOf(position, kCannotCrossEditingBoundary));

  const PositionInFlatTree& position_in_flat_tree =
      PositionInFlatTree::FirstPositionInNode(*target);
  EXPECT_EQ(LocalCaretRect(foo1->GetLayoutObject(), PhysicalRect(25, 0, 1, 10)),
            LocalCaretRectOfPosition(
                PositionInFlatTreeWithAffinity(position_in_flat_tree),
                kCanCrossEditingBoundary));
  // TODO(abotella): The layout object should probably be |foo1_span|'s.
  // TODO(abotella): We should avoid using LayoutBox::LocalCaretRect in
  // LayoutNG.
  EXPECT_EQ(
      LocalCaretRect(target->GetLayoutObject(), PhysicalRect(10, 0, 1, 10)),
      LocalCaretRectOfPosition(
          PositionInFlatTreeWithAffinity(position_in_flat_tree),
          kCannotCrossEditingBoundary));
}

// http://crbug.com/688015
TEST_F(LocalCaretRectTest, LocalCaretAtEndOfNonEditable) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding: 10px; font: 10px/10px Ahem }"
      "span { padding: 15px }");
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">foo</span></div>");
  const Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Element* span = To<Element>(div->firstChild());
  const Node* text = span->firstChild();

  const Position& position = Position::LastPositionInNode(*div);
  EXPECT_EQ(
      LocalCaretRect(text->GetLayoutObject(), PhysicalRect(55, 10, 1, 10)),
      LocalCaretRectOf(position, kCanCrossEditingBoundary));
  EXPECT_EQ(
      LocalCaretRect(span->GetLayoutObject(), PhysicalRect(69, 10, 1, 10)),
      LocalCaretRectOf(position, kCannotCrossEditingBoundary));
}

// http://crbug.com/1456664
TEST_F(LocalCaretRectTest,
       LocalCaretAtEndOfNonEditableWithCollapsedWhitespace) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding: 10px; font: 10px/10px Ahem }"
      "span { padding: 15px }");
  // Note the space after the span!
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">foo</span> </div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Element* span = To<Element>(div->firstChild());
  const Node* text = span->firstChild();

  const Position& position = Position::LastPositionInNode(*div);
  EXPECT_EQ(
      LocalCaretRect(text->GetLayoutObject(), PhysicalRect(55, 10, 1, 10)),
      LocalCaretRectOf(position, kCanCrossEditingBoundary));
  EXPECT_EQ(
      LocalCaretRect(span->GetLayoutObject(), PhysicalRect(69, 10, 1, 10)),
      LocalCaretRectOf(position, kCannotCrossEditingBoundary));
}

// http://crbug.com/1384470
TEST_F(LocalCaretRectTest, LocalCaretAtEndOfNonEditableWithSvg) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding: 10px; font: 10px/10px Ahem }"
      "span { padding: 15px }"
      "svg { vertical-align: text-bottom; }");
  // Note the space after the span!
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">"
      "<svg width=\"30\" height=\"10\"></svg></span> </div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Element* span = To<Element>(div->firstChild());
  const Element* svg = To<Element>(span->firstChild());

  const Position& position = Position::LastPositionInNode(*div);
  EXPECT_EQ(LocalCaretRect(svg->GetLayoutObject(), PhysicalRect(29, 0, 1, 10)),
            LocalCaretRectOf(position, kCanCrossEditingBoundary));
  EXPECT_EQ(
      LocalCaretRect(span->GetLayoutObject(), PhysicalRect(69, 10, 1, 10)),
      LocalCaretRectOf(position, kCannotCrossEditingBoundary));
}

// http://crbug.com/688015
TEST_F(LocalCaretRectTest, LocalCaretAtEndOfNonEditableInFlatTree) {
  LoadAhem();
  InsertStyleElement(
      "div { width: 70px; padding: 10px; font: 10px/10px Ahem }"
      "span { padding: 15px }");
  const char* body_content =
      "<div contenteditable><div id='host'>"
      "<span slot='#one'>foo1</span><span>foo3</span></div></div>";
  const char* shadow_content =
      "<slot name=#one></slot>"
      "<span contenteditable='false' id='foo2'>foo2</span>";
  SetBodyContent(body_content);
  auto* shadow_root = SetShadowContent(shadow_content, "host");
  const Element* target = GetDocument().getElementById(AtomicString("host"));
  const Element* foo2_span = shadow_root->getElementById(AtomicString("foo2"));
  const Node* foo2 = foo2_span->firstChild();

  const Position& position = Position::LastPositionInNode(*target);
  // The old code had a bug that the caret inline offset was greater than the
  // inline size of `target`.  The inline size of `target` is 10px + 70px + 10px
  // => 90px, and the caret should be between 10 to 80.
  PhysicalRect expected = RuntimeEnabledFeatures::SidewaysWritingModesEnabled()
                              ? PhysicalRect(79, 10, 1, 10)
                              : PhysicalRect(99, 10, 1, 10);
  // TODO(abotella): The coordinates should be (50, 20) and the layout object
  // should probably be |foo2|'s.
  // TODO(abotella): We should avoid using LayoutBox::LocalCaretRect in
  // LayoutNG.
  EXPECT_EQ(LocalCaretRect(target->GetLayoutObject(), expected),
            LocalCaretRectOf(position, kCanCrossEditingBoundary));
  // TODO(abotella): The coordinates should be (49, 20) and the layout object
  // should probably be |foo2_span|'s.
  // TODO(abotella): We should avoid using LayoutBox::LocalCaretRect in
  // LayoutNG.
  EXPECT_EQ(LocalCaretRect(target->GetLayoutObject(), expected),
            LocalCaretRectOf(position, kCannotCrossEditingBoundary));

  const PositionInFlatTree& position_in_flat_tree =
      PositionInFlatTree::LastPositionInNode(*target);
  EXPECT_EQ(
      LocalCaretRect(foo2->GetLayoutObject(), PhysicalRect(50, 20, 1, 10)),
      LocalCaretRectOfPosition(
          PositionInFlatTreeWithAffinity(position_in_flat_tree),
          kCanCrossEditingBoundary));
  // 50 rather than 49 and a |foo2|'s layout object rather than |foo2_span|'s
  // because |foo2_span| is a culled inline. This is probably fine, because
  // the 1px difference isn't appreciable in practice.
  EXPECT_EQ(
      LocalCaretRect(foo2->GetLayoutObject(), PhysicalRect(50, 20, 1, 10)),
      LocalCaretRectOfPosition(
          PositionInFlatTreeWithAffinity(position_in_flat_tree),
          kCannotCrossEditingBoundary));
}

// http://crbug.com/688015
TEST_F(LocalCaretRectTest, AbsoluteCaretAtEndOfNonEditable) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 5px; }"
      "div { width: 70px; padding-left: 10px; font: 10px/10px Ahem }"
      "span { padding-left: 15px }");
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">foo</span></div>");

  const Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Position& position = Position::LastPositionInNode(*div);
  EXPECT_EQ("60,5 1x10", AbsoluteCaretBoundsOf(PositionWithAffinity(position),
                                               kCanCrossEditingBoundary)
                             .ToString());
  EXPECT_EQ("59,5 1x10", AbsoluteCaretBoundsOf(PositionWithAffinity(position),
                                               kCannotCrossEditingBoundary)
                             .ToString());
}

// http://crbug.com/688015
TEST_F(LocalCaretRectTest, AbsoluteCaretAtBeginningOfNonEditable) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 5px; }"
      "div { width: 70px; padding-left: 10px; font: 10px/10px Ahem }"
      "span { padding-left: 15px }");
  SetBodyContent(
      "<div contenteditable><span contenteditable=\"false\">foo</span></div>");

  const Element* div = GetDocument().QuerySelector(AtomicString("div"));
  const Position& position = Position::FirstPositionInNode(*div);
  EXPECT_EQ("30,5 1x10", AbsoluteCaretBoundsOf(PositionWithAffinity(position),
                                               kCanCrossEditingBoundary)
                             .ToString());
  EXPECT_EQ("15,5 1x10", AbsoluteCaretBoundsOf(PositionWithAffinity(position),
                                               kCannotCrossEditingBoundary)
                             .ToString());
}

// https://crbug.com/1155399
TEST_F(LocalCaretRectTest, OptionWithDisplayContents) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 10px/10px Ahem; width: 300px }"
      "option { display: contents; }");
  SetBodyContent("<option>a</option>");
  const Element* body = GetDocument().body();
  const Element* option = GetDocument().QuerySelector(AtomicString("option"));
  LocalCaretRect empty;
  LocalCaretRect start(body->GetLayoutObject(), PhysicalRect(0, 0, 1, 10));
  LocalCaretRect end(body->GetLayoutObject(), PhysicalRect(299, 0, 1, 10));

  // LocalCaretRectOfPosition shouldn't crash
  for (const Position& p : {Position::BeforeNode(*body), Position(body, 0)})
    EXPECT_EQ(start, LocalCaretRectOfPosition(PositionWithAffinity(p)));
  for (const Position& p :
       {Position::BeforeNode(*option), Position(option, 0), Position(option, 1),
        Position::LastPositionInNode(*option), Position::AfterNode(*option)})
    EXPECT_EQ(empty, LocalCaretRectOfPosition(PositionWithAffinity(p)));
  for (const Position& p :
       {Position(body, 1), Position::LastPositionInNode(*body),
        Position::AfterNode(*body)})
    EXPECT_EQ(end, LocalCaretRectOfPosition(PositionWithAffinity(p)));
}

TEST_F(LocalCaretRectTest, TextCombineOneTextNode) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "  font: 100px/110px Ahem;"
      "  writing-mode: vertical-rl;"
      "}"
      "tcy { text-combine-upright: all; }");
  SetBodyInnerHTML("<div>a<tcy id=target>01234</tcy>b</div>");
  //   LayoutBlockFlow {HTML} at (0,0) size 800x600
  //     LayoutBlockFlow {BODY} at (8,8) size 784x584
  //       LayoutBlockFlow {DIV} at (0,0) size 110x300
  //         LayoutText {#text} at (5,0) size 100x100
  //           text run at (5,0) width 100: "a"
  //         LayoutInline {TCY} at (5,100) size 100x100
  //           LayoutTextCombine (anonymous) at (5,100) size 100x100
  //             LayoutText {#text} at (-5,0) size 110x100
  //               text run at (0,0) width 500: "01234"
  //         LayoutText {#text} at (5,200) size 100x100
  //           text run at (5,200) width 100: "b"
  const auto& target = *GetElementById("target");
  const auto& text_a = *To<Text>(target.previousSibling());
  const auto& text_01234 = *To<Text>(target.firstChild());
  const auto& text_b = *To<Text>(target.nextSibling());

  // text_a
  EXPECT_EQ(
      LocalCaretRect(text_a.GetLayoutObject(), PhysicalRect(5, 0, 100, 1)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_a, 0))));
  EXPECT_EQ(
      LocalCaretRect(text_a.GetLayoutObject(), PhysicalRect(5, 100, 100, 1)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_a, 1))));

  // text_01234
  EXPECT_EQ(
      LocalCaretRect(text_01234.GetLayoutObject(), PhysicalRect(0, 0, 1, 100)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_01234, 0))));
  EXPECT_EQ(
      LocalCaretRect(text_01234.GetLayoutObject(), PhysicalRect(17, 0, 1, 100)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_01234, 1))));
  EXPECT_EQ(
      LocalCaretRect(text_01234.GetLayoutObject(), PhysicalRect(39, 0, 1, 100)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_01234, 2))));
  EXPECT_EQ(
      LocalCaretRect(text_01234.GetLayoutObject(), PhysicalRect(61, 0, 1, 100)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_01234, 3))));
  EXPECT_EQ(
      LocalCaretRect(text_01234.GetLayoutObject(), PhysicalRect(83, 0, 1, 100)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_01234, 4))));
  EXPECT_EQ(
      LocalCaretRect(text_01234.GetLayoutObject(), PhysicalRect(99, 0, 1, 100)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_01234, 5))));

  // text_b
  EXPECT_EQ(
      LocalCaretRect(text_b.GetLayoutObject(), PhysicalRect(5, 200, 100, 1)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_b, 0))));
  EXPECT_EQ(
      LocalCaretRect(text_b.GetLayoutObject(), PhysicalRect(5, 299, 100, 1)),
      LocalCaretRectOfPosition(PositionWithAffinity(Position(text_b, 1))));
}

TEST_F(LocalCaretRectTest, TextCombineTwoTextNodes) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "  font: 100px/110px Ahem;"
      "  writing-mode: vertical-rl;"
      "}"
      "tcy { text-combine-upright: all; }");
  SetBodyInnerHTML("<div>a<tcy id=target>012<!-- -->34</tcy>b</div>");
  //   LayoutBlockFlow {HTML} at (0,0) size 800x600
  //     LayoutBlockFlow {BODY} at (8,8) size 784x584
  //       LayoutBlockFlow {DIV} at (0,0) size 110x300
  //         LayoutText {#text} at (5,0) size 100x100
  //           text run at (5,0) width 100: "a"
  //         LayoutInline {TCY} at (5,100) size 100x100
  //           LayoutTextCombine (anonymous) at (5,100) size 100x100
  //             LayoutText {#text} at (-5,0) size 66x100
  //               text run at (0,0) width 300: "012"
  //             LayoutText {#text} at (61,0) size 44x100
  //               text run at (300,0) width 200: "34"
  //         LayoutText {#text} at (5,200) size 100x100
  //           text run at (5,200) width 100: "b"
  const auto& target = *GetElementById("target");
  const auto& text_a = *To<Text>(target.previousSibling());
  const auto& text_012 = *To<Text>(target.firstC
```