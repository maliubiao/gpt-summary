Response:
The user wants to understand the functionality of the provided C++ code snippet from `visible_units_test.cc`. This file seems to contain unit tests for the "visible units" feature in the Blink rendering engine. I need to:

1. **Summarize the functionality of the code:** Identify the primary purpose of the tests.
2. **Relate to web technologies:** Explain how the tested functionalities relate to JavaScript, HTML, and CSS.
3. **Provide examples with input/output:** Illustrate the logic of specific tests with hypothetical input and expected output.
4. **Illustrate potential errors:** Describe common user or programming errors that these tests might help prevent.
5. **Explain the user journey:** Describe how a user's interaction with a web page might trigger the code being tested.
6. **Consolidate the findings:**  Summarize the overall function of the provided code.

Let's break down the code section by section to understand what it's testing:

* **`RendersInDifferentPosition` tests:** These tests likely check if two DOM positions are visually distinct on the rendered page. This is influenced by layout and styling.
* **`renderedOffset` test:**  This probably verifies if the rendered positions of elements are correctly calculated, considering layout.
* **`startOfDocument` test:** This focuses on finding the visual start of the document, potentially considering shadow DOM.
* **`endsOfNodeAreVisuallyDistinctPositions` tests:**  These tests check if the beginning and end of a node are visually separate, even with invisible or empty children.
* **`canonicalizationWithCollapsedSpaceAndIsolatedCombiningCharacter` test:** This test addresses how whitespace and special characters are handled in terms of cursor positioning.
* **`MostForwardCaretPositionWithInvisibleFirstLetter` test:** This checks how the caret (text cursor) behaves when the first letter of an element is hidden using CSS.
* **`MostBackwardOrForwardCaretPositionWithBrInOptgroup` test:**  This tests caret movement around `<br>` tags within `<optgroup>` elements.
* **`SnapBackwardWithZeroWidthSpace` and `SnapForwardWithZeroWidthSpace` tests:** These test how the caret moves backward and forward when encountering zero-width spaces (`\u200B`) and `<wbr>` (word break opportunity) elements.
* **`SnapForwardWithImg`, `SnapForwardWithInput`, `SnapForwardWithSelect`, `SnapForwardWithTableAndImages` tests:** These test how the caret moves forward when encountering different types of HTML elements like images, input fields, select dropdowns, and tables with images.
* **`FirstRectForRangeHorizontal`, `FirstRectForRangeHorizontalWrap`, `FirstRectForRangeVertical`, `FirstRectForRangeVerticalWrap` tests:** These tests calculate the bounding rectangle of a selected text range, considering horizontal and vertical writing modes and wrapping.

Now, let's formulate the answers based on these observations.
好的，这是对提供的C++代码片段（`visible_units_test.cc`的第二部分）的功能归纳：

**核心功能：测试 Blink 引擎中关于“可见单元”（Visible Units）的相关功能。**

更具体地说，这部分代码专注于测试以下几个与在网页上定位和操作光标（caret）相关的场景：

1. **判断 DOM 节点的不同位置是否在渲染上视觉可见地不同 (RendersInDifferentPosition):**
   - 测试即使两个 DOM 位置在逻辑上相邻，它们是否由于布局对象（LayoutObject）的不同而呈现为视觉上的分离。例如，一个行内元素后紧跟一个块级元素。
   - 测试具有不同布局对象的锚点（anchor）后的位置是否视觉可见地不同。
   - 考虑空白字符被折叠的情况，即使它们在 DOM 中存在，也不会产生视觉上的分隔。

2. **判断元素的渲染偏移 (renderedOffset):**
   - 测试在 `contenteditable` 元素中，不同子元素的起始位置是否被正确地渲染为视觉上的不同位置。

3. **获取文档的起始位置 (startOfDocument):**
   - 测试如何获取文档的视觉起始位置，包括在存在 Shadow DOM 的情况下。
   - 验证从文档中任意位置调用 `StartOfDocument` 是否都能返回正确的起始位置。

4. **判断节点的起始和结束位置是否在视觉上不同 (endsOfNodeAreVisuallyDistinctPositions):**
   - 测试某些特殊情况下，即使子节点不可见（例如，通过 `<script>` 标签）或为空布局对象，父节点的起始和结束位置是否仍然被认为是视觉上不同的。这通常与可编辑区域的光标定位有关。

5. **处理折叠的空格和组合字符 (canonicalizationWithCollapsedSpaceAndIsolatedCombiningCharacter):**
   - 测试在包含前导空格和组合字符的文本中，规范化位置后的结果是否正确。这涉及到光标应该定位在哪个字符之后。

6. **处理被隐藏的首字母 (MostForwardCaretPositionWithInvisibleFirstLetter):**
   - 测试当元素的第一个字母通过 CSS 设置为 `visibility:hidden` 时，光标的最靠前位置是否正确。

7. **处理 `<optgroup>` 中的 `<br>` 标签 (MostBackwardOrForwardCaretPositionWithBrInOptgroup):**
   - 测试在 `<optgroup>` 元素中遇到 `<br>` 标签时，光标向前或向后移动的行为是否符合预期。

8. **在零宽空格和 `<wbr>` 标签之间的光标移动 (SnapBackwardWithZeroWidthSpace, SnapForwardWithZeroWidthSpace):**
   - 测试光标在遇到零宽空格 (`\u200B`) 和 `<wbr>`（软换行）标签时，向前或向后“吸附”（snap）的行为。目标是确保光标不会停留在这些不可见或仅用于提示换行的位置。

9. **在各种 HTML 元素之间的光标向前移动 (SnapForwardWithImg, SnapForwardWithInput, SnapForwardWithSelect, SnapForwardWithTableAndImages):**
   - 测试光标在遇到 `<img>`、`<input>`、`<select>` 和包含图片的 `<table>` 等元素时，向前移动到正确位置的行为。这涉及到如何跨越这些非文本节点进行光标定位。

10. **获取选区范围的第一个可见矩形 (FirstRectForRangeHorizontal, FirstRectForRangeHorizontalWrap, FirstRectForRangeVertical, FirstRectForRangeVerticalWrap):**
    - 测试如何计算给定选区范围的第一个可见矩形的位置和大小。
    - 涵盖了水平和垂直书写模式，以及文本换行的情况。

**与 JavaScript, HTML, CSS 的关系：**

这些测试直接关联到用户在网页上进行文本编辑和光标操作时的行为，而这些行为是由 JavaScript 代码控制，基于 HTML 结构和 CSS 样式渲染出来的。

* **HTML:** 测试中使用了大量的 HTML 结构来模拟各种场景，例如包含 `<span>`、`<p>`、`<div>`、`<button>`、`<input>`、`<select>`、`<table>`、`<img>` 等元素的结构。
* **CSS:** 测试中会通过 `InsertStyleElement` 插入 CSS 样式，例如设置 `visibility:hidden` 来测试隐藏元素对光标定位的影响，或者设置 `writing-mode` 和 `inline-size` 来测试不同书写模式和文本换行下的选区矩形计算。
* **JavaScript:** 虽然测试本身是用 C++ 编写的，但它模拟了 JavaScript 可能触发的操作，例如通过 `document.designMode = 'on'` 开启可编辑模式，以及光标移动和文本选择等用户行为。JavaScript 代码会依赖这些底层 Blink 引擎提供的“可见单元”功能来实现精确的光标控制和文本操作。

**逻辑推理、假设输入与输出：**

例如，对于 `SnapForwardWithZeroWidthSpace` 测试：

* **假设输入：**  HTML 内容为 `<p>ab|<wbr></p>`，光标位置在 `b` 之后，`<wbr>` 之前。
* **预期输出：** 光标向前移动后的 HTML 状态为 `<p>ab<wbr>|</p>`。测试的目的是验证光标不会停留在 `<wbr>` 标签内部或之前。

对于 `FirstRectForRangeHorizontalWrap` 测试：

* **假设输入：** HTML 内容为 `<div>^abc def|</div>`，CSS 样式设置了 `inline-size:60px`，导致 "def" 换行显示。选区范围是从 "a" 的开头到 "f" 的结尾。
* **预期输出：** 计算出的第一个可见矩形应该对应 "abc " 这部分，因为选区是从这里开始的，并且由于换行，"def" 在下一行。 预期的矩形可能是 `gfx::Rect(8, 8, 59, 20)`（假设字体大小为 20px，边距为 8px）。

**用户或编程常见的使用错误：**

* **光标定位不准确：** 在复杂的 HTML 结构中，如果没有正确处理不可见元素、零宽空格等，JavaScript 代码可能会将光标错误地定位在用户不可见或不期望的位置。例如，用户可能希望光标在两个单词之间，但由于零宽空格的存在，光标可能停留在零宽空格的位置，导致后续输入出现问题。
* **选区范围计算错误：** JavaScript 代码在获取或设置选区范围时，如果没有考虑到不同的渲染模式和特殊字符，可能会导致选取的文本范围与用户期望的不一致。例如，在垂直书写模式下，如果没有正确计算，可能会导致选取的矩形区域错误。
* **可编辑区域的光标跳跃：** 在 `contenteditable` 元素中，如果对可见单元的处理不当，可能会导致用户在编辑时，光标在不同的元素之间意外跳跃。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户打开一个网页：** 网页包含各种 HTML 元素、CSS 样式和可能的 JavaScript 代码。
2. **用户与网页进行交互：**
   - **文本编辑：** 用户可能在一个 `contenteditable` 的 `<div>` 或 `<textarea>` 中输入或删除文本。
   - **光标移动：** 用户可能使用键盘上的方向键或鼠标点击来移动光标。
   - **文本选择：** 用户可能拖动鼠标或使用 Shift + 方向键来选择一段文本。
3. **浏览器渲染引擎处理用户操作：** 当用户进行这些操作时，浏览器的渲染引擎（Blink）需要根据当前的 DOM 结构和 CSS 样式来确定光标的准确位置和选区的范围。
4. **调用“可见单元”相关的功能：**  在处理光标移动和选区计算时，Blink 引擎内部会调用 `visible_units_test.cc` 中测试的那些函数，例如 `RendersInDifferentPosition`、`StartOfDocument`、`MostForwardCaretPosition` 和 `FirstRectForRange` 等。
5. **测试覆盖代码逻辑：** `visible_units_test.cc` 中的这些测试用例旨在覆盖各种可能的场景，确保这些核心功能在各种复杂的网页结构和样式下都能正常工作，从而保证用户交互的流畅性和准确性。

**总结归纳：**

这段 `visible_units_test.cc` 代码的主要功能是**全面测试 Blink 引擎中用于处理网页上可见文本单元和光标定位的核心逻辑。** 它涵盖了判断不同位置的视觉可见性、获取文档起始位置、处理特殊字符和不可见元素对光标的影响、以及计算选区范围等关键功能。通过这些测试，可以确保用户在网页上进行文本编辑和光标操作时，其行为符合预期，并且各种复杂的 HTML 结构和 CSS 样式不会导致光标定位或选区计算的错误。 这些测试对于保证 Chromium 浏览器的文本编辑和用户交互的质量至关重要。

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_units_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
PECT_TRUE(RendersInDifferentPosition(Position::LastPositionInNode(*one),
                                         Position(two, 0)))
      << "two doesn't have layout object";
}

TEST_F(VisibleUnitsTest,
       rendersInDifferentPositionAfterAnchorWithDifferentLayoutObjects) {
  const char* body_content =
      "<p><span id=one>11</span><span id=two>  </span></p>";
  SetBodyContent(body_content);
  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));

  EXPECT_FALSE(RendersInDifferentPosition(Position::LastPositionInNode(*one),
                                          Position(two, 0)));
  EXPECT_FALSE(RendersInDifferentPosition(Position::LastPositionInNode(*one),
                                          Position(two, 1)))
      << "width of two is zero since contents is collapsed whitespaces";
}

TEST_F(VisibleUnitsTest, renderedOffset) {
  const char* body_content =
      "<div contenteditable><span id='sample1'>1</span><span "
      "id='sample2'>22</span></div>";
  SetBodyContent(body_content);
  Element* sample1 = GetDocument().getElementById(AtomicString("sample1"));
  Element* sample2 = GetDocument().getElementById(AtomicString("sample2"));

  EXPECT_FALSE(
      RendersInDifferentPosition(Position::AfterNode(*sample1->firstChild()),
                                 Position(sample2->firstChild(), 0)));
  EXPECT_FALSE(RendersInDifferentPosition(
      Position::LastPositionInNode(*sample1->firstChild()),
      Position(sample2->firstChild(), 0)));
}

TEST_F(VisibleUnitsTest, startOfDocument) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></span>";
  const char* shadow_content =
      "<p><slot name='#two'></slot></p><p><slot name=#one></slot></p>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();

  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(StartOfDocument(Position(*one, 0)))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 0),
            CreateVisiblePosition(StartOfDocument(PositionInFlatTree(*one, 0)))
                .DeepEquivalent());

  EXPECT_EQ(Position(one, 0),
            CreateVisiblePosition(StartOfDocument(Position(*two, 1)))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(two, 0),
            CreateVisiblePosition(StartOfDocument(PositionInFlatTree(*two, 1)))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsTest,
       endsOfNodeAreVisuallyDistinctPositionsWithInvisibleChild) {
  // Repro case of crbug.com/582247
  const char* body_content =
      "<button> </button><script>document.designMode = 'on'</script>";
  SetBodyContent(body_content);

  Node* button = GetDocument().QuerySelector(AtomicString("button"));
  EXPECT_TRUE(EndsOfNodeAreVisuallyDistinctPositions(button));
}

TEST_F(VisibleUnitsTest,
       endsOfNodeAreVisuallyDistinctPositionsWithEmptyLayoutChild) {
  // Repro case of crbug.com/584030
  const char* body_content =
      "<button><rt><script>document.designMode = 'on'</script></rt></button>";
  SetBodyContent(body_content);

  Node* button = GetDocument().QuerySelector(AtomicString("button"));
  EXPECT_TRUE(EndsOfNodeAreVisuallyDistinctPositions(button));
}

// Regression test for crbug.com/675429
TEST_F(VisibleUnitsTest,
       canonicalizationWithCollapsedSpaceAndIsolatedCombiningCharacter) {
  SetBodyContent("<p>  &#x20E3;</p>");  // Leading space is necessary

  Node* paragraph = GetDocument().QuerySelector(AtomicString("p"));
  Node* text = paragraph->firstChild();
  Position start = CanonicalPositionOf(Position::BeforeNode(*paragraph));
  EXPECT_EQ(Position(text, 2), start);
}

TEST_F(VisibleUnitsTest, MostForwardCaretPositionWithInvisibleFirstLetter) {
  InsertStyleElement("div::first-letter{visibility:hidden}");
  // Use special syntax to set input position DIV@0
  const Position position = SetCaretTextToBody("<div><!--|-->foo</div>");
  const Node* foo =
      GetDocument().QuerySelector(AtomicString("div"))->firstChild();
  EXPECT_EQ(Position(foo, 1), MostForwardCaretPosition(position));
}

// Regression test for crbug.com/1172091
TEST_F(VisibleUnitsTest, MostBackwardOrForwardCaretPositionWithBrInOptgroup) {
  SetBodyContent("<optgroup><br></optgroup>");
  Node* br = GetDocument().QuerySelector(AtomicString("br"));
  const Position& before = Position::BeforeNode(*br);
  EXPECT_EQ(before, MostBackwardCaretPosition(before));
  EXPECT_EQ(before, MostForwardCaretPosition(before));
  const Position& after = Position::AfterNode(*br);
  EXPECT_EQ(after, MostBackwardCaretPosition(after));
  EXPECT_EQ(after, MostForwardCaretPosition(after));
}

// http://crbug.com/1134470
TEST_F(VisibleUnitsTest, SnapBackwardWithZeroWidthSpace) {
  // Note: We should skip <wbr> otherwise caret stops before/after <wbr>.

  EXPECT_EQ("<p>ab|<wbr></p>", TestSnapBackward("<p>ab<wbr>|</p>"));
  EXPECT_EQ("<p>ab\u200B|</p>", TestSnapBackward("<p>ab\u200B|</p>"));
  EXPECT_EQ("<p>ab<!-- -->\u200B|</p>",
            TestSnapBackward("<p>ab<!-- -->\u200B|</p>"));

  EXPECT_EQ("<p>ab|<wbr><wbr></p>", TestSnapBackward("<p>ab<wbr><wbr>|</p>"));
  EXPECT_EQ("<p>ab\u200B\u200B|</p>",
            TestSnapBackward("<p>ab\u200B\u200B|</p>"));

  EXPECT_EQ("<p>ab|<wbr>cd</p>", TestSnapBackward("<p>ab<wbr>|cd</p>"));
  EXPECT_EQ("<p>ab\u200B|cd</p>", TestSnapBackward("<p>ab\u200B|cd</p>"));

  EXPECT_EQ("<p>ab|<wbr><wbr>cd</p>",
            TestSnapBackward("<p>ab<wbr><wbr>|cd</p>"));
  EXPECT_EQ("<p>ab\u200B\u200B|cd</p>",
            TestSnapBackward("<p>ab\u200B\u200B|cd</p>"));
}
TEST_F(VisibleUnitsTest, SnapForwardWithImg) {
  SetBodyContent("<img>");
  const auto& body = *GetDocument().body();
  const auto& img = *GetDocument().QuerySelector(AtomicString("img"));

  EXPECT_EQ(Position::BeforeNode(img),
            MostForwardCaretPosition(Position::FirstPositionInNode(body)));
  EXPECT_EQ(Position::BeforeNode(img),
            MostForwardCaretPosition(Position(body, 0)));
  EXPECT_EQ(Position::BeforeNode(img),
            MostForwardCaretPosition(Position::BeforeNode(img)));
  EXPECT_EQ(Position::BeforeNode(img),
            MostForwardCaretPosition(Position(img, 0)));
  EXPECT_EQ(Position::AfterNode(img),
            MostForwardCaretPosition(Position::LastPositionInNode(img)));
  EXPECT_EQ(Position::AfterNode(img),
            MostForwardCaretPosition(Position::AfterNode(img)));
}

TEST_F(VisibleUnitsTest, SnapForwardWithInput) {
  SetBodyContent("<input>");
  const auto& body = *GetDocument().body();
  const auto& input = *GetDocument().QuerySelector(AtomicString("input"));

  EXPECT_EQ(Position::BeforeNode(input),
            MostForwardCaretPosition(Position::FirstPositionInNode(body)));
  EXPECT_EQ(Position::BeforeNode(input),
            MostForwardCaretPosition(Position(body, 0)));
  EXPECT_EQ(Position::BeforeNode(input),
            MostForwardCaretPosition(Position::BeforeNode(input)));
  EXPECT_EQ(Position::BeforeNode(input),
            MostForwardCaretPosition(Position::FirstPositionInNode(input)));
  EXPECT_EQ(Position::BeforeNode(input),
            MostForwardCaretPosition(Position(input, 0)));
  EXPECT_EQ(Position::AfterNode(input),
            MostForwardCaretPosition(Position::LastPositionInNode(input)));
  EXPECT_EQ(Position::AfterNode(input),
            MostForwardCaretPosition(Position::AfterNode(input)));
}

TEST_F(VisibleUnitsTest, SnapForwardWithSelect) {
  SetBodyContent(
      "<select><option>1</option><option>2</option><option>3</option></"
      "select>");
  const auto& body = *GetDocument().body();
  const auto& select = *GetDocument().QuerySelector(AtomicString("select"));

  EXPECT_EQ(Position::BeforeNode(select),
            MostForwardCaretPosition(Position(body, 0)));
  EXPECT_EQ(Position::BeforeNode(select),
            MostForwardCaretPosition(Position::FirstPositionInNode(body)));
  EXPECT_EQ(Position::BeforeNode(select),
            MostForwardCaretPosition(Position::BeforeNode(select)));
  EXPECT_EQ(Position::BeforeNode(select),
            MostForwardCaretPosition(Position::FirstPositionInNode(select)));
  EXPECT_EQ(Position::BeforeNode(select),
            MostForwardCaretPosition(Position(select, 0)));

  // The internal version of `MostForwardCaretPosition()` is called with
  // `PositionInFlatTree(slot, 1)` and it scans at end of `<select>` then
  // returns `PositionInFlatTree(slot, 1)` and converts to
  // `Position(select, 1)`.
  EXPECT_EQ(Position(select, 1), MostForwardCaretPosition(Position(select, 1)));
  EXPECT_EQ(Position(select, 2), MostForwardCaretPosition(Position(select, 2)));
  EXPECT_EQ(Position::AfterNode(select),
            MostForwardCaretPosition(Position(select, 3)));
  EXPECT_EQ(Position::AfterNode(select),
            MostForwardCaretPosition(Position::LastPositionInNode(select)));
  EXPECT_EQ(Position::AfterNode(select),
            MostForwardCaretPosition(Position::AfterNode(select)));

  // Flat tree is
  //  <select>
  //    <div>""</div>
  //    <slot><option>1</option><option>2</option></slot>
  //  </select>
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(PositionInFlatTree(body, 0)));
  EXPECT_EQ(
      PositionInFlatTree::BeforeNode(select),
      MostForwardCaretPosition(PositionInFlatTree::FirstPositionInNode(body)));
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(PositionInFlatTree::BeforeNode(select)));

  // Note: `PositionIterator::DeprecatedComputePosition()` returns
  // `BeforeNode(<select>)` for <select>@n where n is 0 to 3, because
  // `EditingIgnoresContent(<select>)` is true.
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(
                PositionInFlatTree::FirstPositionInNode(select)));
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(PositionInFlatTree(select, 0)));
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(PositionInFlatTree(select, 1)));
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(PositionInFlatTree(select, 2)));
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(PositionInFlatTree(select, 3)));
  EXPECT_EQ(PositionInFlatTree::BeforeNode(select),
            MostForwardCaretPosition(PositionInFlatTree(select, 4)));
  EXPECT_EQ(PositionInFlatTree::AfterNode(select),
            MostForwardCaretPosition(PositionInFlatTree(select, 5)));

  EXPECT_EQ(
      PositionInFlatTree::AfterNode(select),
      MostForwardCaretPosition(PositionInFlatTree::LastPositionInNode(select)));
  EXPECT_EQ(PositionInFlatTree::AfterNode(select),
            MostForwardCaretPosition(PositionInFlatTree::AfterNode(select)));
}

// From ReplaceSelectionCommandTest.TableAndImages)
TEST_F(VisibleUnitsTest, SnapForwardWithTableAndImages) {
  SetBodyContent("<table> <tbody></tbody> </table>");
  const auto& table = *GetDocument().QuerySelector(AtomicString("table"));
  const auto& body = *GetDocument().body();
  auto& tbody = *GetDocument().QuerySelector(AtomicString("tbody"));
  auto& img1 = *GetDocument().CreateRawElement(html_names::kImgTag);
  tbody.AppendChild(&img1);
  auto& img2 = *GetDocument().CreateRawElement(html_names::kImgTag);
  tbody.AppendChild(&img2);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(Position(body, 0), MostForwardCaretPosition(Position(body, 0)));
  EXPECT_EQ(Position(body, 0),
            MostForwardCaretPosition(Position::FirstPositionInNode(body)));
  EXPECT_EQ(Position(table, 0),
            MostForwardCaretPosition(Position::BeforeNode(table)));
  EXPECT_EQ(Position(table, 0),
            MostForwardCaretPosition(Position::FirstPositionInNode(table)));
  EXPECT_EQ(Position(table, 0), MostForwardCaretPosition(Position(table, 0)));
  EXPECT_EQ(Position(table, 1), MostForwardCaretPosition(Position(table, 1)));
  EXPECT_EQ(Position::BeforeNode(img1),
            MostForwardCaretPosition(Position::BeforeNode(tbody)));
  EXPECT_EQ(Position::BeforeNode(img1),
            MostForwardCaretPosition(Position(tbody, 0)));
  EXPECT_EQ(Position::BeforeNode(img1),
            MostForwardCaretPosition(Position::FirstPositionInNode(tbody)));
  EXPECT_EQ(Position::BeforeNode(img2),
            MostForwardCaretPosition(Position(tbody, 1)));
  EXPECT_EQ(Position::LastPositionInNode(tbody),
            MostForwardCaretPosition(Position(tbody, 2)));
  EXPECT_EQ(Position::LastPositionInNode(tbody),
            MostForwardCaretPosition(Position::LastPositionInNode(tbody)));
  EXPECT_EQ(Position::LastPositionInNode(tbody),
            MostForwardCaretPosition(Position::AfterNode(tbody)));
  EXPECT_EQ(Position(table, 2), MostForwardCaretPosition(Position(table, 2)));
  EXPECT_EQ(Position::LastPositionInNode(table),
            MostForwardCaretPosition(Position(table, 3)));
  EXPECT_EQ(Position::LastPositionInNode(table),
            MostForwardCaretPosition(Position::LastPositionInNode(table)));
  EXPECT_EQ(Position::LastPositionInNode(table),
            MostForwardCaretPosition(Position::AfterNode(table)));
}

// http://crbug.com/1134470
TEST_F(VisibleUnitsTest, SnapForwardWithZeroWidthSpace) {
  // Note: We should skip <wbr> otherwise caret stops before/after <wbr>.

  EXPECT_EQ("<p>ab<wbr></p>", TestSnapForward("<p>ab|<wbr></p>"))
      << "We get <wbr>@0";
  EXPECT_EQ("<p>ab|\u200B</p>", TestSnapForward("<p>ab|\u200B</p>"));
  EXPECT_EQ("<p>ab<!-- -->|\u200B</p>",
            TestSnapForward("<p>ab<!-- -->|\u200B</p>"));

  EXPECT_EQ("<p>ab<wbr><wbr></p>", TestSnapForward("<p>ab|<wbr><wbr></p>"))
      << "We get <wbr>@0";
  EXPECT_EQ("<p>ab|\u200B\u200B</p>",
            TestSnapForward("<p>ab|\u200B\u200B</p>"));

  EXPECT_EQ("<p>ab<wbr>|cd</p>", TestSnapForward("<p>ab|<wbr>cd</p>"));
  EXPECT_EQ("<p>ab|\u200Bcd</p>", TestSnapForward("<p>ab|\u200Bcd</p>"));

  EXPECT_EQ("<p>ab<wbr><wbr>|cd</p>",
            TestSnapForward("<p>ab|<wbr><wbr>cd</p>"));
  EXPECT_EQ("<p>ab|\u200B\u200Bcd</p>",
            TestSnapForward("<p>ab|\u200B\u200Bcd</p>"));
}

TEST_F(VisibleUnitsTest, FirstRectForRangeHorizontal) {
  LoadAhem();
  InsertStyleElement("div { font:20px/20px Ahem;}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<div>^abcdef|</div>");
  const gfx::Rect rect = FirstRectForRange(selection.ComputeRange());
  EXPECT_EQ(gfx::Rect(8, 8, 120, 20), rect);
}

TEST_F(VisibleUnitsTest, FirstRectForRangeHorizontalWrap) {
  LoadAhem();
  InsertStyleElement("div { font:20px/20px Ahem; inline-size:60px;}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<div>^abc def|</div>");
  const gfx::Rect rect = FirstRectForRange(selection.ComputeRange());
  EXPECT_EQ(gfx::Rect(8, 8, 59, 20), rect);
}

TEST_F(VisibleUnitsTest, FirstRectForRangeVertical) {
  LoadAhem();
  InsertStyleElement("div { writing-mode:vertical-rl; font:20px/20px Ahem;}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<div>^abcdef|</div>");
  const gfx::Rect rect = FirstRectForRange(selection.ComputeRange());
  EXPECT_EQ(gfx::Rect(8, 8, 20, 119), rect);
}

TEST_F(VisibleUnitsTest, FirstRectForRangeVerticalWrap) {
  LoadAhem();
  InsertStyleElement(
      "div { writing-mode:vertical-rl; font:20px/20px Ahem; "
      "inline-size:60px;}");
  const SelectionInDOMTree selection =
      SetSelectionTextToBody("<div>^abc def|</div>");
  const gfx::Rect rect = FirstRectForRange(selection.ComputeRange());
  EXPECT_EQ(gfx::Rect(28, 8, 20, 59), rect);
}

}  // namespace visible_units_test
}  // namespace blink

"""


```