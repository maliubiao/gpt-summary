Response:
My thinking process to address the request for analyzing the `visible_units_test.cc` file went something like this:

1. **Understand the Goal:** The core request is to understand the *purpose* of this test file. What is it testing?  This immediately points towards the name "visible_units."

2. **Identify Key Data Structures and Functions:** I scanned the initial code block for recurring terms and important function calls. I noticed:
    * `VisiblePosition`, `VisiblePositionInFlatTree`:  These are central concepts related to how positions within the document are *actually* rendered and perceived, considering things like line breaks, visibility, etc.
    * `PositionWithAffinity`, `PositionInFlatTreeWithAffinity`, `Position`:  These seem to be lower-level representations of positions, possibly more tied to the underlying DOM structure.
    * `CanonicalPositionOf`:  This function likely deals with normalizing or simplifying positions, potentially removing ambiguities.
    * `EditingTestBase`:  This indicates the file is part of a testing framework specifically for editing-related functionalities.
    * `TEST_F`:  This is the standard Google Test macro for defining test cases.
    * Function names like `CharacterAfter`, `CharacterBefore`, `EndOfDocument`, `MostBackwardCaretPosition`, `MostForwardCaretPosition`, `NextPositionOf`, `PreviousPositionOf`: These clearly suggest the file is testing how to move through the document in various units (characters, words, lines, etc.) from a user's perspective.

3. **Infer the Overall Functionality:** Based on the keywords and function names, I concluded that `visible_units_test.cc` is responsible for testing the logic that determines what is "visible" to the user when editing a document in Blink. This involves understanding how to move the caret (the text insertion point) forward and backward by different units, taking into account various factors like element visibility, shadow DOM, and editable boundaries.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The tests heavily rely on creating and manipulating HTML structures (`<div>`, `<p>`, `<span>`, `<input>`, `<svg>`, etc.). The concept of editable content (`contenteditable`) is prominent. Shadow DOM is also a key aspect, using `<slot>` elements.
    * **CSS:** CSS is mentioned in the context of `:first-letter` pseudo-elements and `display: none`, indicating that the visibility and rendering of elements are crucial to the tests.
    * **JavaScript:** While the C++ code itself isn't JavaScript, the functionality being tested directly impacts how JavaScript interacts with the document for editing. For example, JavaScript's selection API and caret manipulation depend on the logic tested here.

5. **Consider Logic and Examples:**  I looked at specific test cases to understand the underlying logic:
    * `caretMinOffset`:  Testing the starting position within a text node.
    * `characterAfter`/`characterBefore`:  Verifying correct character retrieval across DOM and shadow DOM boundaries.
    * `CanonicalPositionOf`:  Illustrating how positions are normalized, especially around empty elements or special elements like `<input>`.
    * `mostBackwardCaretPosition`/`mostForwardCaretPosition`: Testing caret movement, including scenarios with `:first-letter` and SVG elements.
    * `nextPositionOf`/`previousPositionOf`:  Testing movement between elements and across shadow DOM boundaries.
    * Tests involving `contenteditable`:  Focusing on how editing boundaries affect caret movement.

6. **Identify Potential User/Programming Errors:** Based on the tested functionalities, I thought about common issues:
    * Incorrect caret placement when dealing with complex element structures (especially with shadow DOM).
    * Unexpected behavior when moving the caret across `contenteditable` boundaries.
    * Issues with selecting or navigating around non-visible content (`display: none`).
    * Difficulty in precisely positioning the caret programmatically using JavaScript if the underlying "visible units" logic is flawed.

7. **Trace User Actions (Debugging):** I imagined a user interacting with a web page and how those actions might lead to the code being executed:
    * Typing text.
    * Using arrow keys to navigate.
    * Selecting text with the mouse.
    * Using browser features like "go to beginning/end of line."
    * Interacting with form fields.

8. **Structure the Summary:**  Finally, I organized the information into logical categories (Core Functionality, Relationship to Web Technologies, Logic and Examples, Potential Errors, Debugging Clues) to provide a comprehensive overview. The request specifically asked for a summary of functionality for Part 1, which I provided at the end.

By following these steps, I could systematically analyze the code and provide a detailed explanation of its purpose and context. The key was to start with the name of the file and the obvious clues within the code itself and then progressively build a more complete picture.
这是 `blink/renderer/core/editing/visible_units_test.cc` 文件的第一部分，主要功能是**测试 Blink 引擎中与“可见单元”相关的编辑功能**。  可见单元指的是用户在编辑文本时感知到的逻辑单位，例如字符、单词、行等，这些单位可能因为渲染、样式、Shadow DOM 等因素与 DOM 树的结构不完全一致。

**归纳其功能如下：**

1. **定义辅助函数:**
   - `PositionWithAffinityInDOMTree`, `CreateVisiblePositionInDOMTree`, `PositionWithAffinityInFlatTree`, `CreateVisiblePositionInFlatTree`: 这些函数用于在 DOM 树和扁平树（考虑 Shadow DOM）中创建带有方向性的位置信息 (`PositionWithAffinity`) 和可见位置信息 (`VisiblePosition`)，方便在测试中使用。

2. **建立测试基类:**
   - `VisibleUnitsTest` 继承自 `EditingTestBase`，提供了用于进行编辑功能测试的基础设施，例如设置和获取 body 内容、设置光标位置等。
   - `TestSnapBackward` 和 `TestSnapForward` 是 `VisibleUnitsTest` 中的辅助函数，用于测试将光标向后或向前移动到最远的有效位置。

3. **测试各种与可见单元相关的核心功能:**
   - **`CaretMinOffset`:** 测试获取可插入符的最小偏移量，考虑了 `:first-letter` 伪元素的影响。
   - **`CharacterAfter` 和 `CharacterBefore`:** 测试获取给定可见位置之后和之前的字符，需要考虑 Shadow DOM 的影响，分别在 DOM 树和扁平树中进行测试。
   - **`CanonicalPositionOf`:** 测试将给定的位置规范化到一个“典型”的位置，这对于处理空元素、HTML 元素、以及跨 block flow 元素的情况非常重要。
   - **`EndOfDocument`:** 测试获取文档末尾的可见位置，同样需要考虑 DOM 树和扁平树。
   - **`AdjustForwardPositionToAvoidCrossingEditingBoundariesNestedEditable`:** 测试在嵌套的可编辑区域中，如何调整光标位置以避免跨越编辑边界。
   - **`isEndOfEditableOrNonEditableContent`:** 测试判断给定可见位置是否在一个可编辑或不可编辑内容的末尾，包括 `<input>` 元素的情况。
   - **`IsVisuallyEquivalentCandidate`:** 测试判断给定的位置是否是视觉上等价的候选位置，排除了像 `<html>` 或 `<body>` 这样的容器元素。
   - **`mostBackwardCaretPosition` 和 `mostForwardCaretPosition`:** 测试获取给定位置最向前和最向后的有效光标位置，包括处理 `:first-letter` 伪元素和 SVG 元素的情况。
   - **`NextPositionOf` 和 `PreviousPositionOf`:** 测试获取给定可见位置的下一个和上一个可见位置，需要考虑 Shadow DOM 和表格等复杂结构。
   - **`rendersInDifferentPosition`:** 测试判断两个位置是否渲染在不同的视觉位置。

**它与 JavaScript, HTML, CSS 的功能的关系:**

这个测试文件直接测试的是 Blink 引擎的 C++ 代码，但其测试的功能与 JavaScript, HTML, CSS 息息相关：

* **HTML:**  测试用例中大量使用了 HTML 元素（如 `<p>`, `<div>`, `<span>`, `<input>`, `<b>`, `<slot>`, `<svg>`) 来构建各种文档结构。这些结构是浏览器渲染和用户交互的基础。测试验证了在这些结构中，可见单元的计算是否正确。
* **CSS:**  测试中使用了 CSS 样式（例如 `:first-letter`, `display: none`, `font-size`, `user-select: none`）来影响元素的渲染和可见性。测试验证了这些样式是否被正确地考虑在可见单元的计算中。例如，`:first-letter` 会影响字符的起始位置，`display: none` 会导致元素不可见，从而影响光标的移动。
* **JavaScript:** 虽然测试本身是用 C++ 编写的，但它测试的功能是 JavaScript 编辑 API 的基础。JavaScript 可以通过 Selection API 获取和设置光标位置，这些 API 的底层实现依赖于 `VisiblePosition` 等概念。例如，当 JavaScript 代码执行 `window.getSelection().collapseToStart()` 时，引擎需要使用类似 `MostBackwardCaretPosition` 的逻辑来确定光标应该移动到的位置。

**逻辑推理、假设输入与输出示例:**

以 `TEST_F(VisibleUnitsTest, characterAfter)` 为例：

**假设输入:**

```html
<p id='host'><b slot='#one' id='one'>1</b><b slot='#two' id='two'>22</b></p><b id='three'>333</b>
```
Shadow DOM for `#host`:
```html
<b id='four'>4444</b><slot name='#two'></slot><slot name=#one></slot><b id='five'>5555</b>
```

1. **输入:**  `CreateVisiblePositionInDOMTree(*one->firstChild(), 1)` (DOM 树中，`<b>1</b>` 元素的文本节点的偏移量为 1，即在 '1' 之后)
   **输出:** `0` (因为在 DOM 树中， '1' 之后没有其他字符了)

2. **输入:** `CreateVisiblePositionInFlatTree(*one->firstChild(), 1)` (扁平树中，`<b>1</b>` 元素的文本节点的偏移量为 1)
   **输出:** `'5'` (在扁平树中，'1' 之后是 Shadow DOM 中的 `<b>5555</b>` 的 '5')

3. **输入:** `CreateVisiblePositionInDOMTree(*two->firstChild(), 2)` (DOM 树中，`<b>22</b>` 元素的文本节点的偏移量为 2)
   **输出:** `'1'` (在 DOM 树中， '2' 之后是宿主元素 `<p>` 中的第一个 `<b>` 元素的 '1')

4. **输入:** `CreateVisiblePositionInFlatTree(*two->firstChild(), 2)` (扁平树中，`<b>22</b>` 元素的文本节点的偏移量为 2)
   **输出:** `'1'` (在扁平树中， '2' 之后是 slot 插入的第一个 `<b>` 元素的 '1')

**用户或编程常见的使用错误举例:**

* **假设开发者错误地认为 DOM 树的结构直接对应用户的视觉感知。**  例如，开发者可能直接使用 DOM API 来移动光标，而没有考虑到 Shadow DOM 的存在，导致光标移动到错误的位置。`visible_units_test.cc` 中的测试用例可以帮助发现这类错误。例如，对 `CharacterAfter` 的扁平树测试就突出了 DOM 树和用户视觉感知之间的差异。
* **假设用户在包含不可见内容（`display: none`）的区域中尝试移动光标。** 如果引擎的可见单元逻辑有缺陷，光标可能会意外地停留在或跳过不可见内容。`visible_units_test.cc` 中可能会有针对这种情况的测试用例（虽然这段代码中没有直接看到，但在后续部分很可能存在）。

**用户操作如何一步步到达这里（调试线索）:**

1. **用户在网页的某个可编辑区域输入文本。** 这会触发浏览器的编辑逻辑。
2. **用户使用键盘上的方向键（左、右、上、下）来移动光标。**  这些操作会调用 Blink 引擎中负责光标移动的代码，其中就包括了确定下一个或上一个可见位置的逻辑（例如 `NextPositionOf`, `PreviousPositionOf`）。
3. **用户使用鼠标在文本中点击，设置光标位置。** 这也会触发引擎计算点击位置对应的 `VisiblePosition`。
4. **用户进行文本选择操作（拖拽鼠标或使用 Shift + 方向键）。**  选择操作依赖于引擎正确地确定选择范围的起始和结束可见位置。
5. **开发者使用 JavaScript 的 Selection API（例如 `window.getSelection()`, `selection.collapse()`, `selection.extend()`) 来操作光标或选择范围。**  这些 JavaScript API 的底层实现会调用 Blink 引擎的 C++ 代码，包括 `visible_units.h` 中定义的函数，而 `visible_units_test.cc` 正是对这些 C++ 函数进行测试。

例如，当用户在一个包含 Shadow DOM 的可编辑区域中按下向右箭头键时，浏览器的事件处理机制会将该事件传递给 Blink 引擎。引擎会根据当前光标位置，调用 `NextPositionOf` 函数来确定下一个可见位置。这个 `NextPositionOf` 函数的实现就需要考虑到 Shadow DOM 的边界，确保光标能够正确地跨越 Shadow DOM 组件。`visible_units_test.cc` 中针对 Shadow DOM 的测试用例，例如 `characterAfter` 和 `nextPositionOf` 的测试，就是为了验证这部分逻辑的正确性。

总而言之，`visible_units_test.cc` 的第一部分定义了测试框架和一些基础测试用例，用于验证 Blink 引擎在处理与用户感知到的文本编辑单元相关的核心逻辑的正确性，这些逻辑直接影响着用户在网页上的编辑体验，并为 JavaScript 编辑 API 提供了基础。

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_units_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"

namespace blink {
namespace visible_units_test {

PositionWithAffinity PositionWithAffinityInDOMTree(
    Node& anchor,
    int offset,
    TextAffinity affinity = TextAffinity::kDownstream) {
  return PositionWithAffinity(CanonicalPositionOf(Position(&anchor, offset)),
                              affinity);
}

VisiblePosition CreateVisiblePositionInDOMTree(
    Node& anchor,
    int offset,
    TextAffinity affinity = TextAffinity::kDownstream) {
  return CreateVisiblePosition(Position(&anchor, offset), affinity);
}

PositionInFlatTreeWithAffinity PositionWithAffinityInFlatTree(
    Node& anchor,
    int offset,
    TextAffinity affinity = TextAffinity::kDownstream) {
  return PositionInFlatTreeWithAffinity(
      CanonicalPositionOf(PositionInFlatTree(&anchor, offset)), affinity);
}

VisiblePositionInFlatTree CreateVisiblePositionInFlatTree(
    Node& anchor,
    int offset,
    TextAffinity affinity = TextAffinity::kDownstream) {
  return CreateVisiblePosition(PositionInFlatTree(&anchor, offset), affinity);
}

class VisibleUnitsTest : public EditingTestBase {
 protected:
  std::string TestSnapBackward(
      const std::string& selection_text,
      EditingBoundaryCrossingRule rule = kCannotCrossEditingBoundary) {
    const Position position = SetCaretTextToBody(selection_text);
    return GetCaretTextFromBody(MostBackwardCaretPosition(position, rule));
  }

  std::string TestSnapForward(
      const std::string& selection_text,
      EditingBoundaryCrossingRule rule = kCannotCrossEditingBoundary) {
    const Position position = SetCaretTextToBody(selection_text);
    return GetCaretTextFromBody(MostForwardCaretPosition(position, rule));
  }
};

TEST_F(VisibleUnitsTest, caretMinOffset) {
  const char* body_content = "<p id=one>one</p>";
  SetBodyContent(body_content);

  Element* one = GetDocument().getElementById(AtomicString("one"));

  EXPECT_EQ(0, CaretMinOffset(one->firstChild()));
}

TEST_F(VisibleUnitsTest, caretMinOffsetWithFirstLetter) {
  const char* body_content =
      "<style>#one:first-letter { font-size: 200%; }</style><p id=one>one</p>";
  SetBodyContent(body_content);

  Element* one = GetDocument().getElementById(AtomicString("one"));

  EXPECT_EQ(0, CaretMinOffset(one->firstChild()));
}

TEST_F(VisibleUnitsTest, characterAfter) {
  const char* body_content =
      "<p id='host'><b slot='#one' id='one'>1</b><b slot='#two' "
      "id='two'>22</b></p><b "
      "id='three'>333</b>";
  const char* shadow_content =
      "<b id='four'>4444</b><slot name='#two'></slot><slot name=#one></slot><b "
      "id='five'>5555</b>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));

  EXPECT_EQ(
      0, CharacterAfter(CreateVisiblePositionInDOMTree(*one->firstChild(), 1)));
  EXPECT_EQ('5', CharacterAfter(
                     CreateVisiblePositionInFlatTree(*one->firstChild(), 1)));

  EXPECT_EQ('1', CharacterAfter(
                     CreateVisiblePositionInDOMTree(*two->firstChild(), 2)));
  EXPECT_EQ('1', CharacterAfter(
                     CreateVisiblePositionInFlatTree(*two->firstChild(), 2)));
}

// http://crbug.com/1176202
TEST_F(VisibleUnitsTest, CanonicalPositionOfWithBefore) {
  LoadAhem();
  InsertStyleElement(
      "body { font: 10px/15px Ahem; }"
      "b::before { content: '\\u200B'");
  // |LayoutInline::PhysicalLinesBoundingBox()| for <span></span> returns
  //    LayoutNG: (0,0)+(0x10)
  //    Legacy:   (0,0)+(0x0)
  //  because we don't cull empty <span> in LayoutNG.
  SetBodyContent("<div contenteditable id=target><span></span><b></b></div>");
  Element& target = *GetElementById("target");

  EXPECT_EQ(Position(target, 0), CanonicalPositionOf(Position(target, 0)));
  EXPECT_EQ(Position(target, 0), CanonicalPositionOf(Position(target, 1)));
  EXPECT_EQ(Position(target, 0), CanonicalPositionOf(Position(target, 2)));
}

TEST_F(VisibleUnitsTest, canonicalPositionOfWithHTMLHtmlElement) {
  const char* body_content =
      "<html><div id=one contenteditable>1</div><span id=two "
      "contenteditable=false>22</span><span id=three "
      "contenteditable=false>333</span><span id=four "
      "contenteditable=false>333</span></html>";
  SetBodyContent(body_content);

  Node* one = GetDocument().QuerySelector(AtomicString("#one"));
  Node* two = GetDocument().QuerySelector(AtomicString("#two"));
  Node* three = GetDocument().QuerySelector(AtomicString("#three"));
  Node* four = GetDocument().QuerySelector(AtomicString("#four"));
  Element* html = GetDocument().CreateRawElement(html_names::kHTMLTag);
  // Move two, three and four into second html element.
  html->AppendChild(two);
  html->AppendChild(three);
  html->AppendChild(four);
  one->appendChild(html);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(Position(),
            CanonicalPositionOf(Position(GetDocument().documentElement(), 0)));

  EXPECT_EQ(Position(one->firstChild(), 0),
            CanonicalPositionOf(Position(one, 0)));
  EXPECT_EQ(Position(one->firstChild(), 1),
            CanonicalPositionOf(Position(one, 1)));

  EXPECT_EQ(Position(one->firstChild(), 0),
            CanonicalPositionOf(Position(one->firstChild(), 0)));
  EXPECT_EQ(Position(one->firstChild(), 1),
            CanonicalPositionOf(Position(one->firstChild(), 1)));

  EXPECT_EQ(Position(html, 0), CanonicalPositionOf(Position(html, 0)));
  EXPECT_EQ(Position(html, 1), CanonicalPositionOf(Position(html, 1)));
  EXPECT_EQ(Position(html, 2), CanonicalPositionOf(Position(html, 2)));

  EXPECT_EQ(Position(two->firstChild(), 0),
            CanonicalPositionOf(Position(two, 0)));
  EXPECT_EQ(Position(two->firstChild(), 2),
            CanonicalPositionOf(Position(two, 1)));
}

// For http://crbug.com/695317
TEST_F(VisibleUnitsTest, canonicalPositionOfWithInputElement) {
  SetBodyContent("<input>123");
  Element* const input = GetDocument().QuerySelector(AtomicString("input"));

  EXPECT_EQ(Position::BeforeNode(*input),
            CanonicalPositionOf(Position::FirstPositionInNode(
                *GetDocument().documentElement())));

  EXPECT_EQ(PositionInFlatTree::BeforeNode(*input),
            CanonicalPositionOf(PositionInFlatTree::FirstPositionInNode(
                *GetDocument().documentElement())));
}

// http://crbug.com/1116214
TEST_F(VisibleUnitsTest, canonicalPositionOfWithCrossBlockFlowlement) {
  const char* body_content =
      "<div id=one>line1<span>X</span><div>line2</div></div>"
      "<div id=two>line3"
      "<span style='user-select: none'>X</span><div>line4</div></div>"
      "<div id=three>line5"
      "<span style='user-select: none'>X</span>333<div>line6</div></div>";
  SetBodyContent(body_content);

  UpdateAllLifecyclePhasesForTest();

  Element* const one = GetDocument().QuerySelector(AtomicString("#one"));
  Element* const two = GetDocument().QuerySelector(AtomicString("#two"));
  Element* const three = GetDocument().QuerySelector(AtomicString("#three"));
  Element* const one_span = one->QuerySelector(AtomicString("span"));
  Element* const two_span = two->QuerySelector(AtomicString("span"));
  Element* const three_span = three->QuerySelector(AtomicString("span"));
  Position one_text_pos(one_span->firstChild(), 1);
  Position two_text_pos(two_span->firstChild(), 1);
  Position three_text_pos(three_span->firstChild(), 1);

  EXPECT_EQ(one_text_pos, CanonicalPositionOf(one_text_pos));

  EXPECT_EQ(Position::LastPositionInNode(*two->firstChild()),
            CanonicalPositionOf(two_text_pos));

  EXPECT_EQ(Position(*three->lastChild()->previousSibling(), 0),
            CanonicalPositionOf(three_text_pos));
}

TEST_F(VisibleUnitsTest, characterBefore) {
  const char* body_content =
      "<p id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></p><b id=three>333</b>";
  const char* shadow_content =
      "<b id=four>4444</b><slot name='#two'></slot><slot name=#one></slot><b "
      "id=five>5555</b>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();

  EXPECT_EQ('2', CharacterBefore(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_EQ('2', CharacterBefore(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_EQ('1', CharacterBefore(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_EQ('1', CharacterBefore(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_EQ(0, CharacterBefore(CreateVisiblePositionInDOMTree(*two, 0)));
  EXPECT_EQ('4', CharacterBefore(CreateVisiblePositionInFlatTree(*two, 0)));

  EXPECT_EQ(0, CharacterBefore(CreateVisiblePositionInDOMTree(*five, 0)));
  EXPECT_EQ('1', CharacterBefore(CreateVisiblePositionInFlatTree(*five, 0)));
}

TEST_F(VisibleUnitsTest, endOfDocument) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></span>";
  const char* shadow_content =
      "<p><slot name='#two'></slot></p><p><slot name=#one></slot></p>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));

  EXPECT_EQ(Position(two->firstChild(), 2),
            EndOfDocument(CreateVisiblePositionInDOMTree(*one->firstChild(), 0))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(one->firstChild(), 1),
      EndOfDocument(CreateVisiblePositionInFlatTree(*one->firstChild(), 0))
          .DeepEquivalent());

  EXPECT_EQ(Position(two->firstChild(), 2),
            EndOfDocument(CreateVisiblePositionInDOMTree(*two->firstChild(), 1))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(one->firstChild(), 1),
      EndOfDocument(CreateVisiblePositionInFlatTree(*two->firstChild(), 1))
          .DeepEquivalent());
}

TEST_F(VisibleUnitsTest,
       AdjustForwardPositionToAvoidCrossingEditingBoundariesNestedEditable) {
  const SelectionInDOMTree& selection = SetSelectionTextToBody(
      "<div contenteditable>"
      "abc"
      "<span contenteditable=\"false\">A^BC</span>"
      "d|ef"
      "</div>");
  const PositionWithAffinity& result =
      AdjustForwardPositionToAvoidCrossingEditingBoundaries(
          PositionWithAffinity(selection.Focus()), selection.Anchor());
  ASSERT_TRUE(result.IsNotNull());
  EXPECT_EQ(
      "<div contenteditable>"
      "abc"
      "<span contenteditable=\"false\">ABC|</span>"
      "def"
      "</div>",
      GetCaretTextFromBody(result.GetPosition()));
  EXPECT_EQ(TextAffinity::kDownstream, result.Affinity());
}

TEST_F(VisibleUnitsTest, isEndOfEditableOrNonEditableContent) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one contenteditable>1</b><b slot='#two' "
      "id=two>22</b></span>";
  const char* shadow_content =
      "<slot name='#two'></slot></p><p><slot name='#one'></slot>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));

  EXPECT_FALSE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInDOMTree(*one->firstChild(), 1)));
  EXPECT_TRUE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInFlatTree(*one->firstChild(), 1)));

  EXPECT_TRUE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInDOMTree(*two->firstChild(), 2)));
  EXPECT_FALSE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInFlatTree(*two->firstChild(), 2)));
}

TEST_F(VisibleUnitsTest, isEndOfEditableOrNonEditableContentWithInput) {
  const char* body_content = "<input id=sample value=ab>cde";
  SetBodyContent(body_content);

  Node* text =
      ToTextControl(GetDocument().getElementById(AtomicString("sample")))
          ->InnerEditorElement()
          ->firstChild();

  EXPECT_FALSE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInDOMTree(*text, 0)));
  EXPECT_FALSE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInFlatTree(*text, 0)));

  EXPECT_FALSE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInDOMTree(*text, 1)));
  EXPECT_FALSE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInFlatTree(*text, 1)));

  EXPECT_TRUE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInDOMTree(*text, 2)));
  EXPECT_TRUE(IsEndOfEditableOrNonEditableContent(
      CreateVisiblePositionInFlatTree(*text, 2)));
}

TEST_F(VisibleUnitsTest, IsVisuallyEquivalentCandidateWithHTMLHtmlElement) {
  const char* body_content =
      "<html><div id=one contenteditable>1</div><span id=two "
      "contenteditable=false>22</span><span id=three "
      "contenteditable=false>333</span><span id=four "
      "contenteditable=false>333</span></html>";
  SetBodyContent(body_content);

  Node* one = GetDocument().QuerySelector(AtomicString("#one"));
  Node* two = GetDocument().QuerySelector(AtomicString("#two"));
  Node* three = GetDocument().QuerySelector(AtomicString("#three"));
  Node* four = GetDocument().QuerySelector(AtomicString("#four"));
  Element* html = GetDocument().CreateRawElement(html_names::kHTMLTag);
  // Move two, three and four into second html element.
  html->AppendChild(two);
  html->AppendChild(three);
  html->AppendChild(four);
  one->appendChild(html);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(
      Position(GetDocument().documentElement(), 0)));

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(one, 0)));
  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(one, 1)));

  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(one->firstChild(), 0)));
  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(one->firstChild(), 1)));

  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(html, 0)));
  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(html, 1)));
  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(html, 2)));

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(two, 0)));
  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(two, 1)));
}

TEST_F(VisibleUnitsTest, isVisuallyEquivalentCandidateWithHTMLBodyElement) {
  const char* body_content =
      "<div id=one contenteditable>1</div><span id=two "
      "contenteditable=false>22</span><span id=three "
      "contenteditable=false>333</span><span id=four "
      "contenteditable=false>333</span>";
  SetBodyContent(body_content);

  Node* one = GetDocument().QuerySelector(AtomicString("#one"));
  Node* two = GetDocument().QuerySelector(AtomicString("#two"));
  Node* three = GetDocument().QuerySelector(AtomicString("#three"));
  Node* four = GetDocument().QuerySelector(AtomicString("#four"));
  Element* body = GetDocument().CreateRawElement(html_names::kBodyTag);
  Element* empty_body = GetDocument().CreateRawElement(html_names::kBodyTag);
  Element* div = GetDocument().CreateRawElement(html_names::kDivTag);
  Element* br = GetDocument().CreateRawElement(html_names::kBrTag);
  empty_body->appendChild(div);
  empty_body->appendChild(br);
  one->appendChild(empty_body);
  // Move two, three and four into second body element.
  body->appendChild(two);
  body->AppendChild(three);
  body->AppendChild(four);
  one->appendChild(body);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(
      Position(GetDocument().documentElement(), 0)));

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(one, 0)));
  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(one, 1)));

  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(one->firstChild(), 0)));
  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(one->firstChild(), 1)));

  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(body, 0)));
  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(body, 1)));
  EXPECT_TRUE(IsVisuallyEquivalentCandidate(Position(body, 2)));

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(two, 0)));
  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(two, 1)));

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(empty_body, 0)));
  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(empty_body, 1)));
}

TEST_F(VisibleUnitsTest, isVisuallyEquivalentCandidateWithDocument) {
  UpdateAllLifecyclePhasesForTest();

  EXPECT_FALSE(IsVisuallyEquivalentCandidate(Position(&GetDocument(), 0)));
}

TEST_F(VisibleUnitsTest, mostBackwardCaretPositionAfterAnchor) {
  const char* body_content =
      "<p id='host'><b id='one'>1</b></p><b id='two'>22</b>";
  const char* shadow_content =
      "<b id='two'>22</b><slot name='#one'></slot><b id='three'>333</b>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* host = GetDocument().getElementById(AtomicString("host"));

  EXPECT_EQ(Position::LastPositionInNode(*host),
            MostForwardCaretPosition(Position::AfterNode(*host)));
  EXPECT_EQ(PositionInFlatTree::LastPositionInNode(*host),
            MostForwardCaretPosition(PositionInFlatTree::AfterNode(*host)));
}

TEST_F(VisibleUnitsTest, mostBackwardCaretPositionFirstLetter) {
  // Note: first-letter pseudo element contains letter and punctuations.
  const char* body_content =
      "<style>p:first-letter {color:red;}</style><p id=sample> (2)45 </p>";
  SetBodyContent(body_content);

  Node* sample =
      GetDocument().getElementById(AtomicString("sample"))->firstChild();

  EXPECT_EQ(Position(sample->parentNode(), 0),
            MostBackwardCaretPosition(Position(sample, 0)));
  EXPECT_EQ(Position(sample->parentNode(), 0),
            MostBackwardCaretPosition(Position(sample, 1)));
  EXPECT_EQ(Position(sample, 2),
            MostBackwardCaretPosition(Position(sample, 2)));
  EXPECT_EQ(Position(sample, 3),
            MostBackwardCaretPosition(Position(sample, 3)));
  EXPECT_EQ(Position(sample, 4),
            MostBackwardCaretPosition(Position(sample, 4)));
  EXPECT_EQ(Position(sample, 5),
            MostBackwardCaretPosition(Position(sample, 5)));
  EXPECT_EQ(Position(sample, 6),
            MostBackwardCaretPosition(Position(sample, 6)));
  EXPECT_EQ(Position(sample, 6),
            MostBackwardCaretPosition(Position(sample, 7)));
  EXPECT_EQ(Position(sample, 6),
            MostBackwardCaretPosition(
                Position::LastPositionInNode(*sample->parentNode())));
  EXPECT_EQ(
      Position(sample, 6),
      MostBackwardCaretPosition(Position::AfterNode(*sample->parentNode())));
  EXPECT_EQ(Position::LastPositionInNode(*GetDocument().body()),
            MostBackwardCaretPosition(
                Position::LastPositionInNode(*GetDocument().body())));
}

TEST_F(VisibleUnitsTest, mostBackwardCaretPositionFirstLetterSplit) {
  V8TestingScope scope;

  const char* body_content =
      "<style>p:first-letter {color:red;}</style><p id=sample>abc</p>";
  SetBodyContent(body_content);

  Node* sample = GetDocument().getElementById(AtomicString("sample"));
  Node* first_letter = sample->firstChild();
  // Split "abc" into "a" "bc"
  auto* remaining = To<Text>(first_letter)->splitText(1, ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(Position(sample, 0),
            MostBackwardCaretPosition(Position(first_letter, 0)));
  EXPECT_EQ(Position(first_letter, 1),
            MostBackwardCaretPosition(Position(first_letter, 1)));
  EXPECT_EQ(Position(first_letter, 1),
            MostBackwardCaretPosition(Position(remaining, 0)));
  EXPECT_EQ(Position(remaining, 1),
            MostBackwardCaretPosition(Position(remaining, 1)));
  EXPECT_EQ(Position(remaining, 2),
            MostBackwardCaretPosition(Position(remaining, 2)));
  EXPECT_EQ(Position(remaining, 2),
            MostBackwardCaretPosition(Position::LastPositionInNode(*sample)));
  EXPECT_EQ(Position(remaining, 2),
            MostBackwardCaretPosition(Position::AfterNode(*sample)));
}

TEST_F(VisibleUnitsTest, mostForwardCaretPositionAfterAnchor) {
  const char* body_content = "<p id='host'><b id='one'>1</b></p>";
  const char* shadow_content =
      "<b id='two'>22</b><slot name='#one'></slot><b id='three'>333</b>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");
  UpdateAllLifecyclePhasesForTest();

  Element* host = GetDocument().getElementById(AtomicString("host"));
  Element* three = shadow_root->getElementById(AtomicString("three"));

  EXPECT_EQ(Position::AfterNode(*host),
            MostBackwardCaretPosition(Position::AfterNode(*host)));
  EXPECT_EQ(PositionInFlatTree(three->firstChild(), 3),
            MostBackwardCaretPosition(PositionInFlatTree::AfterNode(*host)));
}

// http://crbug.com/1348816
TEST_F(VisibleUnitsTest, MostBackwardCaretPositionBeforeSvg) {
  EXPECT_EQ(
      "<div>A<svg><foreignObject height=\"10\" width=\"20\">| "
      "Z</foreignObject></svg></div>",
      TestSnapBackward("<div>A<svg><foreignObject height=10 width=20> "
                       "|Z</foreignObject></svg></div>"));
}

// http://crbug.com/1348816
TEST_F(VisibleUnitsTest, MostForwardCaretPositionBeforeSvg) {
  EXPECT_EQ(
      "<div>A|<svg><foreignObject height=\"10\" width=\"20\"> "
      "Z</foreignObject></svg></div>",
      TestSnapForward("<div>A|<svg><foreignObject height=10 width=20> "
                      "Z</foreignObject></svg></div>"));

  EXPECT_EQ(
      "<div>A<svg><foreignObject height=\"10\" width=\"20\"> "
      "|Z</foreignObject></svg></div>",
      TestSnapForward("<div>A<svg><foreignObject height=10 width=20>| "
                      "Z</foreignObject></svg></div>"));
}

TEST_F(VisibleUnitsTest, mostForwardCaretPositionFirstLetter) {
  // Note: first-letter pseudo element contains letter and punctuations.
  const char* body_content =
      "<style>p:first-letter {color:red;}</style><p id=sample> (2)45 </p>";
  SetBodyContent(body_content);

  Node* sample =
      GetDocument().getElementById(AtomicString("sample"))->firstChild();

  EXPECT_EQ(Position(GetDocument().body(), 0),
            MostForwardCaretPosition(
                Position::FirstPositionInNode(*GetDocument().body())));
  EXPECT_EQ(
      Position(sample, 1),
      MostForwardCaretPosition(Position::BeforeNode(*sample->parentNode())));
  EXPECT_EQ(Position(sample, 1),
            MostForwardCaretPosition(
                Position::FirstPositionInNode(*sample->parentNode())));
  EXPECT_EQ(Position(sample, 1), MostForwardCaretPosition(Position(sample, 0)));
  EXPECT_EQ(Position(sample, 1), MostForwardCaretPosition(Position(sample, 1)));
  EXPECT_EQ(Position(sample, 2), MostForwardCaretPosition(Position(sample, 2)));
  EXPECT_EQ(Position(sample, 3), MostForwardCaretPosition(Position(sample, 3)));
  EXPECT_EQ(Position(sample, 4), MostForwardCaretPosition(Position(sample, 4)));
  EXPECT_EQ(Position(sample, 5), MostForwardCaretPosition(Position(sample, 5)));
  EXPECT_EQ(Position(sample, 7), MostForwardCaretPosition(Position(sample, 6)));
  EXPECT_EQ(Position(sample, 7), MostForwardCaretPosition(Position(sample, 7)));
}

TEST_F(VisibleUnitsTest, nextPositionOf) {
  const char* body_content =
      "<b id=zero>0</b><p id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></p><b "
      "id=three>333</b>";
  const char* shadow_content =
      "<b id=four>4444</b><slot name='#two'></slot><slot name=#one></slot><b "
      "id=five>55555</b>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Element* zero = GetDocument().getElementById(AtomicString("zero"));
  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));
  Element* three = GetDocument().getElementById(AtomicString("three"));
  Element* four = shadow_root->getElementById(AtomicString("four"));
  Element* five = shadow_root->getElementById(AtomicString("five"));

  EXPECT_EQ(Position(two->firstChild(), 2),
            NextPositionOf(CreateVisiblePosition(Position(zero, 1)))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(four->firstChild(), 0),
            NextPositionOf(CreateVisiblePosition(PositionInFlatTree(zero, 1)))
                .DeepEquivalent());

  EXPECT_EQ(Position(three->firstChild(), 0),
            NextPositionOf(CreateVisiblePosition(Position(one, 0),
                                                 TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one->firstChild(), 1),
            NextPositionOf(CreateVisiblePosition(PositionInFlatTree(one, 0)))
                .DeepEquivalent());

  EXPECT_EQ(Position(two->firstChild(), 0),
            NextPositionOf(CreateVisiblePosition(Position(one, 1),
                                                 TextAffinity::kUpstream))
                .DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(five->firstChild(), 1),
            NextPositionOf(CreateVisiblePosition(PositionInFlatTree(one, 1)))
                .DeepEquivalent());

  EXPECT_EQ(
      Position(three->firstChild(), 0),
      NextPositionOf(CreateVisiblePosition(Position(two, 1))).DeepEquivalent());
  EXPECT_EQ(PositionInFlatTree(one->firstChild(), 1),
            NextPositionOf(CreateVisiblePosition(PositionInFlatTree(two, 1)))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsTest, nextPositionOfTable) {
  SetBodyContent("<table id='table'></table>");
  Element* table = GetDocument().getElementById(AtomicString("table"));
  // Couldn't include the <br> in the HTML above since the parser would have
  // messed up the structure in the DOM.
  table->setInnerHTML("<br>", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhasesForTest();

  Position position(table, 0);
  Position next =
      NextPositionOf(CreateVisiblePosition(position)).DeepEquivalent();
  EXPECT_NE(position, next);
  EXPECT_NE(MostBackwardCaretPosition(position),
            MostBackwardCaretPosition(next));
  EXPECT_NE(MostForwardCaretPosition(position), MostForwardCaretPosition(next));
}

TEST_F(VisibleUnitsTest, previousPositionOf) {
  const char* body_content =
      "<b id=zero>0</b><p id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></p><b id=three>333</b>";
  const char* shadow_content =
      "<b id=four>4444</b><slot name='#two'></slot><slot name=#one></slot><b "
      "id=five>55555</b>";
  SetBodyContent(body_content);
  ShadowRoot* shadow_root = SetShadowContent(shadow_content, "host");

  Node* zero = GetDocument().getElementById(AtomicString("zero"))->firstChild();
  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();
  Node* four = shadow_root->getElementById(AtomicString("four"))->firstChild();
  Node* five = shadow_root->getElementById(AtomicString("five"))->firstChild();

  EXPECT_EQ(Position(zero, 0),
            PreviousPositionOf(CreateVisiblePosition(Position(zero, 1)))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(zero, 0),
      PreviousPositionOf(CreateVisiblePosition(PositionInFlatTree(zero, 1)))
          .DeepEquivalent());

  EXPECT_EQ(Position(two, 1),
            PreviousPositionOf(CreateVisiblePosition(Position(one, 0)))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 1),
      PreviousPositionOf(CreateVisiblePosition(PositionInFlatTree(one, 0)))
          .DeepEquivalent());

  EXPECT_EQ(Position(two, 2),
            PreviousPositionOf(CreateVisiblePosition(Position(one, 1)))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two, 2),
      PreviousPositionOf(CreateVisiblePosition(PositionInFlatTree(one, 1)))
          .DeepEquivalent());

  EXPECT_EQ(Position(one, 1),
            PreviousPositionOf(CreateVisiblePosition(Position(two, 0)))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(four, 3),
      PreviousPositionOf(CreateVisiblePosition(PositionInFlatTree(two, 0)))
          .DeepEquivalent());

  // DOM tree to shadow tree
  EXPECT_EQ(Position(two, 2),
            PreviousPositionOf(CreateVisiblePosition(Position(three, 0)))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(five, 5),
      PreviousPositionOf(CreateVisiblePosition(PositionInFlatTree(three, 0)))
          .DeepEquivalent());

  // Shadow tree to DOM tree
  EXPECT_EQ(Position(),
            PreviousPositionOf(CreateVisiblePosition(Position(four, 0)))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(zero, 1),
      PreviousPositionOf(CreateVisiblePosition(PositionInFlatTree(four, 0)))
          .DeepEquivalent());

  // Note: Canonicalization maps (five, 0) to (five, 0) in DOM tree and
  // (one, 1) in flat tree.
  EXPECT_EQ(Position(five, 0),
            PreviousPositionOf(CreateVisiblePosition(Position(five, 1)))
                .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(one, 1),
      PreviousPositionOf(CreateVisiblePosition(PositionInFlatTree(five, 1)))
          .DeepEquivalent());
}

TEST_F(VisibleUnitsTest, previousPositionOfOneCharPerLine) {
  const char* body_content =
      "<div id=sample style='font-size: 500px'>A&#x714a;&#xfa67;</div>";
  SetBodyContent(body_content);

  Node* sample =
      GetDocument().getElementById(AtomicString("sample"))->firstChild();

  // In case of each line has one character, VisiblePosition are:
  // [C,Dn]   [C,Up]  [B, Dn]   [B, Up]
  //  A        A       A         A|
  //  B        B|     |B         B
  // |C        C       C         C
  EXPECT_EQ(PositionWithAffinity(Position(sample, 1)),
            PreviousPositionOf(CreateVisiblePosition(Position(sample, 2)))
                .ToPositionWithAffinity());
  EXPECT_EQ(PositionWithAffinity(Position(sample, 1)),
            PreviousPositionOf(CreateVisiblePosition(Position(sample, 2),
                                                     TextAffinity::kUpstream))
                .ToPositionWithAffinity());
}

TEST_F(VisibleUnitsTest, previousPositionOfNoPreviousPosition) {
  SetBodyContent(
      "<span contenteditable='true'>"
      "<span> </span>"
      " "  // This whitespace causes no previous position.
      "<div id='anchor'> bar</div>"
      "</span>");
  const Position position(
      GetDocument().getElementById(AtomicString("anchor"))->firstChild(), 1);
  EXPECT_EQ(
      Position(),
      PreviousPositionOf(CreateVisiblePosition(position)).DeepEquivalent());
}

TEST_F(VisibleUnitsTest, rendersInDifferentPositionAfterAnchor) {
  const char* body_content = "<p id='sample'>00</p>";
  SetBodyContent(body_content);
  Element* sample = GetDocument().getElementById(AtomicString("sample"));

  EXPECT_FALSE(RendersInDifferentPosition(Position(), Position()));
  EXPECT_FALSE(
      RendersInDifferentPosition(Position(), Position::AfterNode(*sample)))
      << "if one of position is null, the reuslt is false.";
  EXPECT_FALSE(RendersInDifferentPosition(Position::AfterNode(*sample),
                                          Position(sample, 1)));
  EXPECT_FALSE(RendersInDifferentPosition(Position::LastPositionInNode(*sample),
                                          Position(sample, 1)));
}

TEST_F(VisibleUnitsTest, rendersInDifferentPositionAfterAnchorWithHidden) {
  const char* body_content =
      "<p><span id=one>11</span><span id=two style='display:none'>  "
      "</span></p>";
  SetBodyContent(body_content);
  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));

  EX
"""


```