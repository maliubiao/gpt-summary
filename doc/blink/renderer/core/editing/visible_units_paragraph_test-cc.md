Response:
The user wants to understand the functionality of the C++ source code file `visible_units_paragraph_test.cc`. I need to analyze the code and explain its purpose, its relation to web technologies, provide examples of its logic, highlight potential user errors, and describe how a user might trigger this code.

**Plan:**

1. **Identify the core purpose:** The filename and the test cases strongly suggest it's for testing paragraph-related functions in the Blink rendering engine.
2. **Explain the functionalities:**  Focus on the test cases and the helper functions defined within the class. The test cases cover `EndOfParagraph`, `IsEndOfParagraph`, and `IsStartOfParagraph`, and `StartOfNextParagraph`.
3. **Relate to web technologies:** Explain how these functions are relevant to text editing and manipulation in web browsers, linking them to JavaScript, HTML, and CSS concepts.
4. **Provide examples:**  Use the provided test cases as examples of input and expected output.
5. **Identify potential user errors:** Think about scenarios where incorrect usage or unexpected behavior could occur from a user's perspective.
6. **Describe the user journey:** Explain how user actions in a browser could lead to the execution of this code during text editing operations.
## 对 blink/renderer/core/editing/visible_units_paragraph_test.cc 的功能分析

这个 C++ 文件 `visible_units_paragraph_test.cc` 是 Chromium Blink 引擎中负责 **文本编辑** 模块的一个 **测试文件**。它的主要功能是 **测试与段落相关的文本单元（visible units）操作的正确性**。

具体来说，它测试了以下几个关键功能：

*   **EndOfParagraph(VisiblePosition)**:  给定一个可视位置（`VisiblePosition`），确定该位置所在段落的结尾位置。
*   **IsEndOfParagraph(VisiblePosition)**:  判断给定的可视位置是否是其所在段落的结尾。
*   **IsStartOfParagraph(VisiblePosition)**: 判断给定的可视位置是否是其所在段落的起始位置。
*   **StartOfNextParagraph(VisiblePosition)**: 给定一个可视位置，确定下一个段落的起始位置。

这个测试文件使用了 Google Test 框架 (`TEST_F`) 来定义和执行各种测试用例，涵盖了不同场景下的段落边界判断。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件虽然是用 C++ 编写的，但它测试的功能直接关系到用户在浏览器中与网页进行文本交互时的行为，因此与 JavaScript, HTML, 和 CSS 都有着密切的关系。

*   **HTML:**  HTML 定义了网页的结构，包括段落元素（如 `<p>` 标签）和可能影响段落划分的其他元素（如 `<div>`, `<br>`, `<pre>` 等）。测试用例中使用了 `SetBodyContent` 方法来设置 HTML 内容，模拟不同的网页结构，例如包含 `<div>`, `<pre>` 元素以及带有 `::first-letter` 伪类的元素。

    *   **例子:**  测试用例 `endOfParagraphSimple` 中设置了 HTML 内容 `<div id=sample>1ab\nde</div>`，它测试了在简单的 `div` 元素中，换行符 `\n` 如何影响段落的结尾判断。

*   **CSS:** CSS 用于控制网页的样式和布局，一些 CSS 属性会影响文本的渲染和段落的划分。例如，`display` 属性可以改变元素的呈现方式，`::first-letter` 伪类可以为段落的首字母添加样式。

    *   **例子:** 测试用例 `endOfParagraphFirstLetter` 和 `endOfParagraphFirstLetterPre` 使用了带有 `::first-letter` 伪类的 CSS 样式，测试了首字母样式是否会影响段落结尾的判断。 `StartOfNextParagraphAfterTableCell` 测试了 `display: table-cell` 属性对段落划分的影响。

*   **JavaScript:**  JavaScript 可以通过 DOM API 来操作网页的结构和内容，包括获取和设置文本内容，以及移动光标位置。  虽然这个测试文件本身不涉及 JavaScript 代码，但它测试的 C++ 函数是 JavaScript 文本编辑 API 的底层实现基础。 当 JavaScript 代码需要获取或设置段落的起始或结束位置时，或者在用户进行文本选择、光标移动等操作时，底层的 C++ 代码会被调用。

    *   **例子:**  当 JavaScript 代码使用 `Selection` API 中的方法来选中一个段落，或者使用 `setCaretRange` 方法将光标移动到段落的开头或结尾时，Blink 引擎会调用相应的 C++ 函数，而这个测试文件就是用来验证这些 C++ 函数的正确性。

**逻辑推理与假设输入输出:**

测试用例本身就包含了逻辑推理和假设输入输出。每个 `TEST_F` 函数都设置了一个特定的 HTML 结构作为输入，然后针对不同的可视位置调用被测试的函数，并使用 `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_LT`, `EXPECT_LE` 等断言来验证输出是否符合预期。

例如，对于 `endOfParagraphSimple` 测试用例：

*   **假设输入:**  HTML 内容为 `<div id=sample>1ab\nde</div>`。
*   **逻辑推理:**  换行符 `\n` 会将文本分隔成不同的段落。对于 `CreateVisiblePositionInDOMTree(*text, offset)`，当 `offset` 小于换行符的位置 (3) 时，段落的结尾应该是换行符之后的位置，即文本的末尾 (offset 6)。
*   **预期输出:**  无论起始的可视位置在哪里 (offset 0 到 6)，`EndOfParagraph` 函数都应该返回文本的末尾位置 (Position(text, 6))。

**用户或编程常见的使用错误及举例说明:**

虽然这个测试文件是针对 Blink 引擎内部的，但它可以帮助理解在用户或编程中可能出现的与段落操作相关的错误：

*   **错误理解段落的边界:** 用户可能认为一个 `<br>` 标签会创建一个新的段落，但实际上在 HTML 中，`<br>` 只是一个换行符，不会像 `<p>` 或 `<div>` 那样创建新的段落结构。编程时，如果错误地基于 `<br>` 来判断段落边界，可能会导致意外的结果。

    *   **例子:**  如果在 JavaScript 中，开发者错误地认为 `<br>` 后的内容是新段落的开始，并基于此进行光标移动或文本选择操作，那么可能会得到不准确的位置信息。这个测试文件中的用例会验证 Blink 引擎是否正确处理了 `<br>` 标签的情况。

*   **忽略 CSS 样式的影响:**  某些 CSS 样式（如 `display: block`, `display: table-row-group` 等）会强制元素形成新的块级格式化上下文，从而影响段落的划分。开发者在进行文本编辑相关的操作时，需要考虑 CSS 样式可能带来的影响。

    *   **例子:**  如果一个 `<span>` 元素设置了 `display: block`，那么它实际上会表现得像一个块级元素，可能被 Blink 引擎视为一个独立的段落边界。如果开发者没有意识到这一点，可能会在处理段落边界时出现错误。`StartOfNextParagraphAfterTableCell` 这个测试用例就体现了 `display` 属性对段落边界的影响。

*   **在 Shadow DOM 中处理段落边界:** Shadow DOM 引入了新的 DOM 结构，可能会影响段落边界的判断。开发者在处理包含 Shadow DOM 的内容时，需要注意 Shadow DOM 的边界。

    *   **例子:**  `endOfParagraphShadow` 和 `isEndOfParagraph` 等测试用例专门测试了在包含 Shadow DOM 的情况下，段落边界的判断是否正确。如果开发者在 JavaScript 中没有正确处理 Shadow DOM 的边界，可能会在进行文本编辑操作时遇到问题。

**用户操作如何一步步到达这里 (作为调试线索):**

当用户在浏览器中进行以下操作时，可能会触发与此测试文件相关的代码逻辑：

1. **在可编辑区域输入文本:**  用户在一个 `contenteditable` 属性设置为 `true` 的元素中输入文本，Blink 引擎需要实时更新文本内容和光标位置，这会涉及到段落边界的判断。
2. **使用键盘移动光标 (方向键):**  当用户按下方向键（向上、向下）在文本中移动光标时，Blink 引擎需要根据当前的段落结构来计算下一个或上一个可视位置。
3. **使用鼠标进行文本选择:**  当用户拖动鼠标选择一段文本时，Blink 引擎需要确定选择范围的起始和结束位置，这涉及到段落的起始和结束位置的判断。
4. **使用快捷键进行文本操作:**  例如，使用 Ctrl+Left/Right (或 Option+Left/Right) 按单词或段落移动光标，或者使用 Shift+方向键进行文本选择时，Blink 引擎会调用相应的函数来确定移动或选择的范围。
5. **在表单元素中输入文本:**  在 `<textarea>` 或 `<input type="text">` 等表单元素中输入文本也会触发类似的逻辑。
6. **通过 JavaScript 操作文本:**  当 JavaScript 代码使用 Selection API 或 Range API 来获取、设置或修改文本内容时，底层也会调用 Blink 引擎的文本编辑相关功能。

**调试线索:**

如果开发者在 Chromium 的 Blink 引擎中进行文本编辑相关的开发或调试，并且怀疑段落边界判断存在问题，他们可能会：

1. **运行 `visible_units_paragraph_test.cc` 中的特定测试用例:**  如果问题与特定 HTML 结构或 CSS 样式相关，可以直接运行相应的测试用例来验证 Blink 引擎的行为。
2. **在 Blink 引擎的源代码中设置断点:**  在 `visible_units.cc` 文件中与段落相关的函数（如 `EndOfParagraph`, `IsEndOfParagraph`, `StartOfParagraph` 等）中设置断点，跟踪代码的执行流程，查看在特定用户操作下，这些函数是如何被调用和计算的。
3. **使用 Chromium 的 DevTools 进行调试:**   যদিও этот тестовый файл не запускается непосредственно через DevTools, понимание того, как пользовательские действия приводят к вызову этого кода, помогает разработчикам использовать DevTools для анализа DOM-структуры, CSS-стилей и JavaScript-кода, которые могут влиять на поведение функций, протестированных в этом файле.
4. **查看 Layout 树:**  Blink 引擎的 Layout 阶段会根据 DOM 树和 CSS 样式构建 Layout 树，理解 Layout 树的结构有助于理解段落是如何被划分和渲染的。

总而言之，`visible_units_paragraph_test.cc` 是 Blink 引擎中确保文本编辑功能正确性的重要组成部分，它直接关系到用户在浏览器中进行文本交互时的体验。通过各种测试用例，它验证了 Blink 引擎在不同场景下对段落边界的判断是否符合预期。

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_units_paragraph_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"

namespace blink {

class VisibleUnitsParagraphTest : public EditingTestBase {
 protected:
  static PositionWithAffinity PositionWithAffinityInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return PositionWithAffinity(CanonicalPositionOf(Position(&anchor, offset)),
                                affinity);
  }

  static VisiblePosition CreateVisiblePositionInDOMTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(Position(&anchor, offset), affinity);
  }

  static PositionInFlatTreeWithAffinity PositionWithAffinityInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return PositionInFlatTreeWithAffinity(
        CanonicalPositionOf(PositionInFlatTree(&anchor, offset)), affinity);
  }

  static VisiblePositionInFlatTree CreateVisiblePositionInFlatTree(
      Node& anchor,
      int offset,
      TextAffinity affinity = TextAffinity::kDownstream) {
    return CreateVisiblePosition(PositionInFlatTree(&anchor, offset), affinity);
  }
};

TEST_F(VisibleUnitsParagraphTest, endOfParagraphFirstLetter) {
  SetBodyContent(
      "<style>div::first-letter { color: red }</style><div "
      "id=sample>1ab\nde</div>");

  Node* sample = GetDocument().getElementById(AtomicString("sample"));
  Node* text = sample->firstChild();

  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 0))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 1))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 2))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 3))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 4))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 5))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 6))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, endOfParagraphFirstLetterPre) {
  SetBodyContent(
      "<style>pre::first-letter { color: red }</style><pre "
      "id=sample>1ab\nde</pre>");

  Node* sample = GetDocument().getElementById(AtomicString("sample"));
  Node* text = sample->firstChild();

  EXPECT_EQ(Position(text, 3),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 0))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 3),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 1))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 3),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 2))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 3))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 4))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 5))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 6))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, endOfParagraphShadow) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></span><b id=three>333</b>";
  const char* shadow_content =
      "<p><slot name=#two></slot></p><p><slot name=#one></slot></p>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Element* one = GetDocument().getElementById(AtomicString("one"));
  Element* two = GetDocument().getElementById(AtomicString("two"));
  Element* three = GetDocument().getElementById(AtomicString("three"));

  EXPECT_EQ(
      Position(three->firstChild(), 3),
      EndOfParagraph(CreateVisiblePositionInDOMTree(*one->firstChild(), 1))
          .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(one->firstChild(), 1),
      EndOfParagraph(CreateVisiblePositionInFlatTree(*one->firstChild(), 1))
          .DeepEquivalent());

  EXPECT_EQ(
      Position(three->firstChild(), 3),
      EndOfParagraph(CreateVisiblePositionInDOMTree(*two->firstChild(), 2))
          .DeepEquivalent());
  EXPECT_EQ(
      PositionInFlatTree(two->firstChild(), 2),
      EndOfParagraph(CreateVisiblePositionInFlatTree(*two->firstChild(), 2))
          .DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, endOfParagraphSimple) {
  SetBodyContent("<div id=sample>1ab\nde</div>");

  Node* sample = GetDocument().getElementById(AtomicString("sample"));
  Node* text = sample->firstChild();

  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 0))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 1))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 2))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 3))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 4))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 5))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 6))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, endOfParagraphSimplePre) {
  SetBodyContent("<pre id=sample>1ab\nde</pre>");

  Node* sample = GetDocument().getElementById(AtomicString("sample"));
  Node* text = sample->firstChild();

  EXPECT_EQ(Position(text, 3),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 0))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 3),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 1))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 3),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 2))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 3),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 3))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 4))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 5))
                .DeepEquivalent());
  EXPECT_EQ(Position(text, 6),
            EndOfParagraph(CreateVisiblePositionInDOMTree(*text, 6))
                .DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, isEndOfParagraph) {
  const char* body_content =
      "<span id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></span><b id=three>333</b>";
  const char* shadow_content =
      "<p><slot name=#two></slot></p><p><slot name=#one></slot></p>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();

  EXPECT_FALSE(IsEndOfParagraph(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_FALSE(IsEndOfParagraph(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsEndOfParagraph(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_TRUE(IsEndOfParagraph(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_FALSE(IsEndOfParagraph(CreateVisiblePositionInDOMTree(*two, 2)));
  EXPECT_TRUE(IsEndOfParagraph(CreateVisiblePositionInFlatTree(*two, 2)));

  EXPECT_FALSE(IsEndOfParagraph(CreateVisiblePositionInDOMTree(*three, 0)));
  EXPECT_FALSE(IsEndOfParagraph(CreateVisiblePositionInFlatTree(*three, 0)));

  EXPECT_TRUE(IsEndOfParagraph(CreateVisiblePositionInDOMTree(*three, 3)));
  EXPECT_TRUE(IsEndOfParagraph(CreateVisiblePositionInFlatTree(*three, 3)));
}

TEST_F(VisibleUnitsParagraphTest, isStartOfParagraph) {
  const char* body_content =
      "<b id=zero>0</b><span id=host><b slot='#one' id=one>1</b><b slot='#two' "
      "id=two>22</b></span><b id=three>333</b>";
  const char* shadow_content =
      "<p><slot name=#two></slot></p><p><slot name=#one></slot></p>";
  SetBodyContent(body_content);
  SetShadowContent(shadow_content, "host");

  Node* zero = GetDocument().getElementById(AtomicString("zero"))->firstChild();
  Node* one = GetDocument().getElementById(AtomicString("one"))->firstChild();
  Node* two = GetDocument().getElementById(AtomicString("two"))->firstChild();
  Node* three =
      GetDocument().getElementById(AtomicString("three"))->firstChild();

  EXPECT_TRUE(IsStartOfParagraph(CreateVisiblePositionInDOMTree(*zero, 0)));
  EXPECT_TRUE(IsStartOfParagraph(CreateVisiblePositionInFlatTree(*zero, 0)));

  EXPECT_FALSE(IsStartOfParagraph(CreateVisiblePositionInDOMTree(*one, 0)));
  EXPECT_TRUE(IsStartOfParagraph(CreateVisiblePositionInFlatTree(*one, 0)));

  EXPECT_FALSE(IsStartOfParagraph(CreateVisiblePositionInDOMTree(*one, 1)));
  EXPECT_FALSE(IsStartOfParagraph(CreateVisiblePositionInFlatTree(*one, 1)));

  EXPECT_FALSE(IsStartOfParagraph(CreateVisiblePositionInDOMTree(*two, 0)));
  EXPECT_TRUE(IsStartOfParagraph(CreateVisiblePositionInFlatTree(*two, 0)));

  EXPECT_FALSE(IsStartOfParagraph(CreateVisiblePositionInDOMTree(*three, 0)));
  EXPECT_TRUE(IsStartOfParagraph(CreateVisiblePositionInFlatTree(*three, 0)));
}

TEST_F(VisibleUnitsParagraphTest, StartOfNextParagraphAfterTableCell) {
  SetBodyContent(
      "<input style='display: table-cell' type='file' "
      "maxlength='100'><select>");

  const Position& input =
      Position::BeforeNode(*GetDocument().QuerySelector(AtomicString("input")));
  const Position& select = Position::BeforeNode(
      *GetDocument().QuerySelector(AtomicString("select")));

  const VisiblePosition& input_position = CreateVisiblePosition(input);
  const VisiblePosition& after_input =
      VisiblePosition::AfterNode(*input.AnchorNode());
  const VisiblePosition& select_position = CreateVisiblePosition(select);

  const VisiblePosition& next_paragraph = StartOfNextParagraph(input_position);
  EXPECT_LT(input_position.DeepEquivalent(), next_paragraph.DeepEquivalent());
  EXPECT_LE(after_input.DeepEquivalent(), next_paragraph.DeepEquivalent());
  EXPECT_EQ(select_position.DeepEquivalent(), next_paragraph.DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest,
       endOfParagraphWithDifferentUpAndDownVisiblePositions) {
  InsertStyleElement("span, div { display: inline-block; width: 50vw; }");
  SetBodyContent("x<span></span><div></div>");

  const Position& text_end =
      Position::LastPositionInNode(*GetDocument().body()->firstChild());
  const Position& before_div =
      Position::BeforeNode(*GetDocument().QuerySelector(AtomicString("div")));
  const VisiblePosition& upstream =
      CreateVisiblePosition(before_div, TextAffinity::kUpstream);
  const VisiblePosition& downstream =
      CreateVisiblePosition(before_div, TextAffinity::kDownstream);
  EXPECT_LT(upstream.DeepEquivalent(), downstream.DeepEquivalent());
  EXPECT_EQ(text_end, upstream.DeepEquivalent());
  EXPECT_EQ(before_div, downstream.DeepEquivalent());

  // The end of paragraph of a position shouldn't precede it (bug 1179113).
  const VisiblePosition& end_of_paragraph = EndOfParagraph(downstream);
  EXPECT_LE(downstream.DeepEquivalent(), end_of_paragraph.DeepEquivalent());

  // In in this case they are equal.
  EXPECT_EQ(downstream.DeepEquivalent(), end_of_paragraph.DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, endOfParagraphCannotBeBeforePosition) {
  SetBodyContent(
      "<span contenteditable>x<br contenteditable=false>"
      "<br contenteditable=false></span>");
  Element* span = GetDocument().QuerySelector(AtomicString("span"));
  const Position& p1 = Position(span, 2);
  const Position& p2 = Position::LastPositionInNode(*span);
  const Position& p3 = Position::AfterNode(*span);
  const VisiblePosition& vp1 = CreateVisiblePosition(p1);
  const VisiblePosition& vp2 = CreateVisiblePosition(p2);
  const VisiblePosition& vp3 = CreateVisiblePosition(p3);

  // The anchor should still be the span after the VisiblePosition
  // normalization, or the test would become useless.
  EXPECT_EQ(p1, vp1.DeepEquivalent());
  EXPECT_EQ(p2, vp2.DeepEquivalent());
  EXPECT_EQ(vp2.DeepEquivalent(), vp3.DeepEquivalent());

  // No need to test vp3 since it's equal to vp2.
  const VisiblePosition& end1 = EndOfParagraph(vp1);
  const VisiblePosition& end2 = EndOfParagraph(vp2);

  // EndOfParagraph() iterates nodes starting from the span, and "x"@1 would be
  // a suitable candidate. But it's skipped because it precedes the positions.
  EXPECT_LE(vp1.DeepEquivalent(), end1.DeepEquivalent());
  EXPECT_LE(vp2.DeepEquivalent(), end2.DeepEquivalent());

  // Test the actual values.
  EXPECT_EQ(p1, end1.DeepEquivalent());
  EXPECT_EQ(p2, end2.DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, endOfParagraphCannotCrossEditingRoot) {
  SetBodyContent(
      "<div><span contenteditable id=span>this </span>"
      "<a contenteditable=false>link</a>"
      "<span contenteditable> after</span></div>");

  Element* span = GetElementById("span");
  const Position& p1 = Position(span->firstChild(), 2);
  const Position& p2 = Position(span->firstChild(), 5);
  const VisiblePosition& vp1 = CreateVisiblePosition(p1);
  const VisiblePosition& vp2 = CreateVisiblePosition(p2);

  EXPECT_EQ(p1, vp1.DeepEquivalent());
  EXPECT_EQ(p2, vp2.DeepEquivalent());

  const VisiblePosition& end1 = EndOfParagraph(vp1);
  const VisiblePosition& end2 = EndOfParagraph(
      vp1, EditingBoundaryCrossingRule::kCanSkipOverEditingBoundary);

  EXPECT_LE(vp1.DeepEquivalent(), end1.DeepEquivalent());
  EXPECT_LE(vp1.DeepEquivalent(), end2.DeepEquivalent());

  EXPECT_EQ(p2, end1.DeepEquivalent());
  EXPECT_EQ(p2, end2.DeepEquivalent());
}

TEST_F(VisibleUnitsParagraphTest, startOfParagraphCannotBeAfterPosition) {
  SetBodyContent(
      "<span contenteditable><br contenteditable=false>"
      "<br contenteditable=false>x</span>");
  Element* span = GetDocument().QuerySelector(AtomicString("span"));
  const Position& p1 = Position(span, 1);
  const Position& p2 = Position::FirstPositionInNode(*span);
  const Position& p3 = Position::BeforeNode(*span);
  const VisiblePosition& vp1 = CreateVisiblePosition(p1);
  const VisiblePosition& vp2 = CreateVisiblePosition(p2);
  const VisiblePosition& vp3 = CreateVisiblePosition(p3);

  // The anchor should still be the span after the VisiblePosition
  // normalization, or the test would become useless.
  EXPECT_EQ(p1, vp1.DeepEquivalent());
  EXPECT_EQ(p2, vp2.DeepEquivalent());
  EXPECT_EQ(vp2.DeepEquivalent(), vp3.DeepEquivalent());

  // No need to test vp3 since it's equal to vp2.
  const VisiblePosition& start1 = StartOfParagraph(vp1);
  const VisiblePosition& start2 = StartOfParagraph(vp2);

  // StartOfParagraph() iterates nodes in post order starting from the span, and
  // "x"@0 would be a suitable candidate. But it's skipped because it's after
  // the positions.
  EXPECT_LE(start1.DeepEquivalent(), vp1.DeepEquivalent());
  EXPECT_LE(start2.DeepEquivalent(), vp2.DeepEquivalent());

  // Test the actual values.
  EXPECT_EQ(p1, start1.DeepEquivalent());
  EXPECT_EQ(p2, start2.DeepEquivalent());
}

}  // namespace blink

"""

```