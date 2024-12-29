Response:
The user wants a summary of the provided C++ code file. The file is named `hit_testing_bidi_test.cc` and is located within the Chromium Blink engine's source code. The request asks for the file's functionality and its relationship to web technologies (JavaScript, HTML, CSS). It also asks for logical reasoning examples with inputs and outputs, common user/programming errors, and how a user might reach this code (debugging perspective). Finally, it explicitly states this is part 1 of 6 and asks for a summary of this part.

Based on the file name and the included headers (`document.h`, `ephemeral_range.h`, `position_with_affinity.h`, `editing_test_base.h`, `text_affinity.h`), it appears this file contains tests related to **hit testing** in the context of **bidirectional text**.

Let's break down the elements:

1. **Functionality:** The core functionality is to test how the engine determines the correct text position (caret position) when a user clicks or interacts with text that has mixed left-to-right (LTR) and right-to-left (RTL) directionality. This is crucial for correct text editing and cursor placement.

2. **Relationship to JavaScript, HTML, CSS:**
    *   **HTML:** The tests manipulate HTML structures, specifically using the `dir` attribute to control text direction (`<div dir=ltr>`, `<bdo dir=rtl>`).
    *   **CSS:** The tests use CSS to style the text (setting font and width) to control layout and make hit testing predictable. The `LoadAhem()` call suggests the use of a test font.
    *   **JavaScript:** While this specific file is C++, the functionality it tests is directly exposed to JavaScript through the browser's API. For example, `document.caretRangeFromPoint(x, y)` is a JavaScript API that relies on the hit-testing logic being tested here.

3. **Logical Reasoning (Hypothetical Input/Output):** The tests themselves provide clear input (HTML structure, coordinates) and expected output (caret position). Each `TEST_F` function represents a test case with a specific scenario.

4. **User/Programming Errors:**
    *   **User Error:** Clicking in unexpected places in bidi text, leading to incorrect cursor placement if the hit-testing logic is flawed.
    *   **Programming Error:** Incorrectly implementing the hit-testing algorithm for bidi text, failing to account for the visual vs. logical ordering of characters.

5. **User Operation to Reach Here (Debugging):** A developer debugging cursor placement issues in bidi text might step through the `caretRangeFromPoint` implementation, eventually reaching the hit-testing logic covered by these tests.

6. **Summary of Part 1:** This part of the file focuses on testing hit-testing scenarios within `ltr` (left-to-right) and `rtl` (right-to-left) blocks, often involving nested `<bdo>` elements to explicitly control the base direction of text segments. The tests cover edge cases such as clicking at the beginning or end of lines and within different directionality segments.

Based on this analysis, I can now formulate the response.
这个C++源代码文件 `hit_testing_bidi_test.cc` 的功能是 **测试 Blink 渲染引擎在处理双向文本 (bidirectional text, bidi) 时，进行命中测试 (hit testing) 的准确性**。

具体来说，它测试了 `Document::caretRangeFromPoint(x, y)` 这个方法，该方法用于 **根据给定的屏幕坐标 (x, y) 确定光标应该放置的位置 (返回一个 EphemeralRange 对象)**。这个测试文件特别关注双向文本的场景，即文本中同时包含从左到右和从右到左书写的文字。

**与 JavaScript, HTML, CSS 的关系:**

*   **HTML:** 该测试文件直接使用 HTML 结构来创建测试场景。例如，`<div dir=ltr><bdo dir=rtl>ABC</bdo>def</div>`  这样的 HTML 代码片段被用来模拟包含从左到右的 `div` 元素和内部从右到左的 `<bdo>` 元素的文本。`dir` 属性用于设置文本的方向性。
*   **CSS:**  测试用例中使用了 CSS 来控制元素的样式，例如 `InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");`  设置了 `div` 元素的字体和宽度。这对于精确计算元素的位置和大小，从而进行准确的命中测试至关重要。`Ahem` 通常是一个用于测试的固定宽度的字体。
*   **JavaScript:** 虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的功能 (`document.caretRangeFromPoint`) 是 **JavaScript 中可用的 Web API**。  在 JavaScript 中，开发者可以使用 `document.caretRangeFromPoint(x, y)` 来获取用户点击位置的光标信息，这个 C++ 测试文件就是在验证 Blink 引擎正确实现了这个 API 在双向文本场景下的行为。

**逻辑推理 (假设输入与输出):**

假设有以下 HTML 结构和 CSS 样式：

**输入 HTML:** `<div dir=ltr><bdo dir=rtl>ABC</bdo>def</div>`
**输入 CSS:** `div {font: 10px/10px Ahem; width: 300px}`

**测试用例:** `InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOfOneRunWithBaseRunEnd`

*   **假设输入:** 用户点击屏幕上的一个点，该点的 x 坐标略小于 `div` 元素的左边缘，y 坐标在 `div` 元素的文本行内。 根据代码：
    *   `int x = div->OffsetLeft() - 3;`  (x 坐标略微偏左)
    *   `int y = div->OffsetTop() + 5;`  (y 坐标在文本行中间)
*   **预期输出:**  `GetDocument().caretRangeFromPoint(x, y)` 应该返回一个 `EphemeralRange` 对象，表示光标应该放置在 `<bdo dir=rtl>ABC</bdo>` 这个从右向左文本的开头，也就是 "A" 的左侧。
*   **代码验证:** `EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">|ABC</bdo>def</div>", GetCaretTextFromBody(result.StartPosition()));` 这行代码验证了返回的光标位置是否符合预期，"|" 表示光标位置。

**涉及用户或者编程常见的使用错误:**

*   **用户错误:** 用户在编辑双向文本时，可能会因为文本方向的切换而导致光标位置的跳跃或不符合预期。例如，在一个从左到右的段落中包含一段从右到左的文字，用户可能难以准确点击到他们想要插入或删除字符的位置。如果命中测试逻辑有缺陷，就会加剧这种困扰。
*   **编程错误:** 在实现文本编辑器或富文本编辑器的过程中，如果开发者没有正确处理双向文本的逻辑，可能会导致光标定位、选区绘制等问题。例如，简单地按照字符在字符串中的顺序来处理光标移动，而不考虑其视觉顺序，就会在双向文本中产生错误。这个测试文件就是在帮助开发者确保 Blink 引擎的底层处理是正确的。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问包含双向文本的网页。** 例如，一个网页可能包含阿拉伯语或希伯来语等从右到左书写的文字，或者在英文句子中穿插了这些文字。
2. **用户尝试在这些双向文本中进行编辑操作。**  例如，用户点击文本的某个位置插入新的字符，或者尝试选中一段文字进行复制或删除。
3. **浏览器接收到用户的鼠标点击事件。** 浏览器需要确定用户点击的具体位置，这会涉及到坐标的计算。
4. **浏览器调用 `document.caretRangeFromPoint(x, y)` (或类似的内部函数)。**  浏览器会根据用户点击的屏幕坐标 (x, y) 调用 Blink 引擎的相应方法来确定光标应该放置在哪里。
5. **Blink 引擎执行命中测试逻辑。**  `hit_testing_bidi_test.cc`  中测试的正是这部分逻辑。Blink 引擎会分析用户点击位置附近的 DOM 结构、文本内容和方向性信息，来判断最合适的插入点。
6. **如果命中测试逻辑有错误，可能会导致光标放置在错误的位置。**  开发者在调试这类问题时，可能会需要深入到 Blink 引擎的源代码中，查看 `editing/hit_testing_bidi_test.cc` 这类测试文件，了解各种双向文本场景下的预期行为，并逐步调试相关的 C++ 代码，例如 `PositionForPoint()` 方法的实现。

**归纳一下它的功能 (第1部分):**

这部分代码的主要功能是 **针对各种简单的双向文本布局场景，测试 `Document::caretRangeFromPoint` 方法在 LTR (从左到右) 和 RTL (从右到左) 容器中进行命中测试时的光标定位是否正确。**  它包含了多个独立的测试用例，每个用例都设置了特定的 HTML 结构（包含 `<bdo>` 元素来模拟不同的文本方向）和点击坐标，并验证了在这些坐标下，光标是否被正确地放置在预期的位置。 这些测试用例是记录行为的，可能不一定反映最终期望的行为，但它们是理解 Blink 引擎如何处理双向文本命中测试的重要基础。

Prompt: 
```
这是目录为blink/renderer/core/editing/hit_testing_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/document.h"

#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"

namespace blink {

class HitTestingBidiTest : public EditingTestBase {};

// This file contains script-generated tests for PositionForPoint()
// that are related to bidirectional text. The test cases are only for
// behavior recording purposes, and do not necessarily reflect the
// correct/desired behavior.

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual: |C B A d e f
  // Bidi:    1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo>def</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">|ABC</bdo>def</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual: |C B A d e f
  // Bidi:    1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo>def</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">|ABC</bdo>def</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  d e f C B A|
  // Bidi:    0 0 0 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>def<bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">def<bdo dir=\"rtl\">ABC|</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  d e f C B A|
  // Bidi:    0 0 0 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>def<bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">def<bdo dir=\"rtl\">ABC|</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOfOneRun) {
  // Visual: |C B A
  // Bidi:    1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">|ABC</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOfOneRun) {
  // Visual: |C B A
  // Bidi:    1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">|ABC</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOfOneRun) {
  // Visual:  C B A|
  // Bidi:    1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">ABC|</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfRightEdgeOfOneRun) {
  // Visual:  C B A|
  // Bidi:    1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">ABC|</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  d e f|C B A g h i
  // Bidi:    0 0 0 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>def<bdo dir=rtl>ABC</bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">def|<bdo dir=\"rtl\">ABC</bdo>ghi</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  d e f|C B A g h i
  // Bidi:    0 0 0 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>def<bdo dir=rtl>ABC</bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">def<bdo dir=\"rtl\">|ABC</bdo>ghi</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  g h i C B A|d e f
  // Bidi:    0 0 0 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>ghi<bdo dir=rtl>ABC</bdo>def</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">ghi<bdo dir=\"rtl\">ABC|</bdo>def</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  g h i C B A|d e f
  // Bidi:    0 0 0 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>ghi<bdo dir=rtl>ABC</bdo>def</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">ghi<bdo dir=\"rtl\">ABC</bdo>|def</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOfOneRun) {
  // Visual:  d e f|C B A
  // Bidi:    0 0 0 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>def<bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">def|<bdo dir=\"rtl\">ABC</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockLtrBaseRunRightSideOfLeftEdgeOfOneRun) {
  // Visual:  d e f|C B A
  // Bidi:    0 0 0 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr>def<bdo dir=rtl>ABC</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\">def<bdo dir=\"rtl\">|ABC</bdo></div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockLtrBaseRunLeftSideOfRightEdgeOfOneRun) {
  // Visual:  C B A|d e f
  // Bidi:    1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo>def</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">ABC|</bdo>def</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockLtrBaseRunRightSideOfRightEdgeOfOneRun) {
  // Visual:  C B A|d e f
  // Bidi:    1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent("<div dir=ltr><bdo dir=rtl>ABC</bdo>def</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ("<div dir=\"ltr\"><bdo dir=\"rtl\">ABC</bdo>|def</div>",
            GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  F E D|a b c I H G
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  F E D|a b c I H G
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  I H G a b c|F E D
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  I H G a b c|F E D
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOfOneRun) {
  // Visual:  F E D|a b c
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockRtlBaseRunRightSideOfLeftEdgeOfOneRun) {
  // Visual:  F E D|a b c
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockRtlBaseRunLeftSideOfRightEdgeOfOneRun) {
  // Visual:  a b c|F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InLtrBlockRtlBaseRunRightSideOfRightEdgeOfOneRun) {
  // Visual:  a b c|F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual: |a b c F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual: |a b c F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  F E D a b c|
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  F E D a b c|
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOfOneRun) {
  // Visual: |a b c
  // Bidi:    2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOfOneRun) {
  // Visual: |a b c
  // Bidi:    2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOfOneRun) {
  // Visual:  a b c|
  // Bidi:    2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfRightEdgeOfOneRun) {
  // Visual:  a b c|
  // Bidi:    2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  d e f|C B A g h i
  // Bidi:    2 2 2 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  d e f|C B A g h i
  // Bidi:    2 2 2 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  g h i C B A|d e f
  // Bidi:    2 2 2 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  g h i C B A|d e f
  // Bidi:    2 2 2 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOfOneRun) {
  // Visual:  d e f|C B A
  // Bidi:    2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockLtrBaseRunRightSideOfLeftEdgeOfOneRun) {
  // Visual:  d e f|C B A
  // Bidi:    2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockLtrBaseRunLeftSideOfRightEdgeOfOneRun) {
  // Visual:  C B A|d e f
  // Bidi:    3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockLtrBaseRunRightSideOfRightEdgeOfOneRun) {
  // Visual:  C B A|d e f
  // Bidi:    3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  F E D|a b c I H G
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI<bdo "
      "dir=\"ltr\">abc</bdo>|DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfLeftEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  F E D|a b c I H G
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 
"""


```