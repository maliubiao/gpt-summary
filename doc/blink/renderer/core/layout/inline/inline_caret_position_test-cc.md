Response:
The user wants to understand the functionality of the given C++ source code file `inline_caret_position_test.cc`. I need to analyze the code and:

1. **Identify its primary purpose:** Based on the file name and content, it seems to be a unit test file for `InlineCaretPosition` functionality.
2. **Explain its relationship to web technologies:** Determine if the tested functionality has any relevance to JavaScript, HTML, or CSS.
3. **Provide examples with assumptions:** If the code involves logical reasoning, I should create hypothetical inputs and their expected outputs.
4. **Highlight potential user or programming errors:**  Point out any common mistakes the code might be testing for or preventing.

Let's break down the code:

- **Includes:** The file includes headers related to editing, layout, and testing within the Blink rendering engine. This confirms it's a testing file.
- **Test Fixture:**  `InlineCaretPositionTest` inherits from `RenderingTest`, indicating it's a unit test that renders HTML content.
- **Setup:** `SetUp()` loads Ahem font, which is often used in layout tests for consistent rendering.
- **Helper Functions:**
    - `SetInlineFormattingContext`: Creates HTML with a specified structure and styling, setting up the test environment.
    - `ComputeInlineCaretPosition`: The core function being tested. It calculates the caret position within an inline context.
    - `FragmentOf`: Creates an `InlineCursor` for a given node.
- **Test Macros:** `TEST_CARET` is a macro to simplify assertions about the computed caret position.
- **Individual Test Cases:** Each `TEST_F` function tests a specific scenario for caret positioning. These test cases provide the best insight into the functionality being tested. They cover scenarios like:
    - Caret position after a span element.
    - Caret position in a single line of text.
    - Caret position at soft hyphens and line wraps.
    - Caret position at forced line breaks (`<br>`).
    - Caret position in empty lines.
    - Caret position around images.
    - Caret position in multi-column layouts.
    - Caret position with zero-width spaces.
    - Caret position with `::before` pseudo-elements.
    - Caret position within bidirectional content (`<bdo>`).
    - Handling of `<area>` elements.

**Relationship to Web Technologies:**

- **HTML:** The tests manipulate HTML structures (divs, spans, bdo, br, img, area) to set up different layout scenarios.
- **CSS:**  CSS properties like `width`, `word-break`, `text-direction`, `font-size`, `column-count`, `white-space`, `line-break`, `overflow-wrap`, and `display` are used to control the rendering and trigger specific caret positioning behaviors.
- **JavaScript:** While this specific file doesn't directly involve JavaScript, the correct calculation of caret positions is crucial for JavaScript-based text editing and manipulation within web pages. When a user interacts with a text field or editable area, JavaScript often relies on these underlying layout calculations to determine where the cursor should be placed or where selections start and end.

**Logical Reasoning and Examples:**

The core logic lies within the `ComputeInlineCaretPosition` function (not shown in the provided code but being tested). The tests verify this logic. Let's take an example:

**Test Case:** `InlineCaretPositionInOneLineOfText`

**Assumed Input:**
- HTML: `<div id='t'>foo</div>`
- Container width: 3px
- Target offset: `1`
- Text Affinity: `TextAffinity::kDownstream`

**Logical Reasoning:** The code simulates placing the caret at offset 1 within the text "foo". `TextAffinity::kDownstream` suggests the caret should lean towards the character at that offset.

**Expected Output:**
- `caret.cursor`:  Points to the text node containing "foo".
- `caret.position_type`: `kAtTextOffset` (the caret is within a text node).
- `caret.text_offset`: `1`

**User or Programming Errors:**

- **Incorrectly Handling Line Breaks:**  The tests for `<br>` and soft line wraps highlight potential errors in how a rendering engine might position the caret at the transition between lines. A common mistake could be placing the caret on the wrong line or at the incorrect offset after a line break.
- **Bidirectional Text Issues:** The tests with `<bdo>` (bidirectional override) are crucial for handling languages that read from right to left. Errors could occur in calculating the visual position of the caret in mixed-direction text.
- **Zero-Width Space Handling:** The tests with zero-width spaces (U+200B) and soft hyphens (U+00AD) ensure that these special characters don't cause unexpected caret positioning behavior. A mistake could be counting or rendering these characters incorrectly, leading to misplaced carets.
- **Pseudo-element Interaction:** The `InlineBlockBeforeContent` test verifies that pseudo-elements like `::before` don't interfere with the caret positioning within the actual content of the element. A potential error would be the caret being placed inside or adjacent to the pseudo-element's generated content incorrectly.
- **Handling of Non-Text Elements:** The tests with `<img>` and `<area>` elements ensure the caret can be positioned correctly before and after these non-text inline elements. A common error would be failing to place the caret at valid positions around these elements.
这个文件 `inline_caret_position_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件。它的主要功能是测试 `blink::ComputeInlineCaretPosition` 函数的正确性。这个函数负责计算在给定的内联布局上下文中，特定偏移量处的内联光标（caret）位置。

以下是更详细的解释，并结合了与 JavaScript, HTML, CSS 的关系以及逻辑推理和常见错误：

**功能列表:**

1. **测试 `ComputeInlineCaretPosition` 函数:** 这是核心功能。该函数接收一个内联布局上下文、一个偏移量和一个文本亲和性（TextAffinity），并返回一个 `InlineCaretPosition` 对象，描述了在该位置的光标信息。
2. **验证不同场景下的光标位置:**  测试覆盖了各种内联布局场景，例如：
    * 单行文本中的不同位置
    * 软连字符（soft hyphen）
    * 软换行（soft line wrap）
    * 强制换行符 `<br>`
    * 空行
    * 图片 `<img>`
    * 多列布局
    * 零宽度空格
    * 使用 `::before` 伪元素的场景
    * 双向文本 `<bdo>`
    * 特殊元素 `<area>`

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 函数创建各种 HTML 结构，例如 `<div>`, `<span>`, `<b>`, `<br>`, `<img>`, `<bdo>`, `<area>`。这些 HTML 结构定义了内联元素的布局方式，是测试 `ComputeInlineCaretPosition` 函数的基础。
    * **举例:**  测试用例会创建类似 `<div>foo<b>bar</b></div>` 这样的 HTML 结构，然后测试光标在 "foo" 之后、"bar" 之前或者 "bar" 之后的位置。
* **CSS:** 测试用例使用 `InsertStyleElement` 函数插入 CSS 样式，例如设置 `width` 来触发换行，设置 `text-direction` 来测试双向文本，设置 `column-count` 来测试多列布局。这些 CSS 属性直接影响内联元素的布局，进而影响光标的位置计算。
    * **举例:** 使用 `width: 3px;` 可以强制 "foobar" 发生软换行，测试光标在 "foo" 结尾和 "bar" 开头的位置。 使用 `direction: rtl;` 可以测试在从右到左的文本中光标的位置。
* **JavaScript:** 虽然这个测试文件本身不包含 JavaScript 代码，但 `ComputeInlineCaretPosition` 函数的正确性对于 JavaScript 编辑器和富文本编辑器等功能至关重要。JavaScript 代码经常需要获取或设置光标的位置，而 `ComputeInlineCaretPosition` 提供的正是底层布局信息。
    * **举例:** 当用户在 `contenteditable` 的 `div` 中点击时，浏览器需要使用类似 `ComputeInlineCaretPosition` 的机制来确定光标应该放置在哪个文本节点的哪个偏移量处。

**逻辑推理与假设输入/输出:**

每个 `TEST_F` 函数都包含了一系列的假设输入和预期的输出。 `TEST_CARET` 宏用于断言计算出的 `InlineCaretPosition` 是否符合预期。

**举例 (基于 `InlineCaretPositionInOneLineOfText` 测试):**

**假设输入:**

* **HTML:** `<div id='t'>foo</div>`
* **CSS:** `body { font: 10px/10px Ahem;  }` (影响文本的渲染大小)
* **偏移量 (offset):** 1
* **文本亲和性 (affinity):** `TextAffinity::kDownstream`

**逻辑推理:**

1. 代码将 HTML 渲染成内联布局。
2. 光标的偏移量为 1，意味着它位于字符 'o' 的前面。
3. `TextAffinity::kDownstream` 表示光标倾向于该偏移量之后的字符。

**预期输出:**

* `caret.cursor`: 指向包含文本 "foo" 的 `LayoutText` 对象。
* `caret.position_type`: `InlineCaretPositionType::kAtTextOffset` (表示光标位于文本节点的某个偏移量处)。
* `caret.text_offset`: `std::optional<unsigned>(1)` (表示光标位于文本节点内的偏移量 1 处)。

**用户或编程常见的使用错误:**

这个测试文件主要用于防止 Blink 引擎自身在处理内联光标位置时出现错误。但理解这些测试用例也能帮助开发者避免与光标处理相关的常见错误：

* **错误地假设光标总是位于字符之间:**  光标也可能位于元素的开头或结尾，例如在 `<img>` 元素之前或之后。测试用例 `InlineCaretPositionInOneLineOfImage` 就验证了这种情况。
* **忽略软换行和强制换行的影响:**  在进行文本处理时，需要考虑到文本可能因为容器宽度而发生软换行，或者包含显式的换行符 `<br>`。错误地处理这些情况可能导致光标位置计算错误。测试用例 `InlineCaretPositionAtSoftLineWrap` 和 `InlineCaretPositionAtForcedLineBreak` 就覆盖了这些场景。
* **未考虑双向文本的影响:** 在处理包含从右到左文本的场景时，需要特别注意光标的视觉位置和逻辑位置的对应关系。测试用例 `InlineBoxesLTR` 和 `InlineBoxesRTL` 验证了在双向文本中光标位置的计算。
* **不理解零宽度字符的影响:**  零宽度空格等特殊字符虽然在视觉上不可见，但它们仍然会影响光标的位置。测试用例 `ZeroWidthSpace` 确保了引擎能够正确处理这些字符。
* **假设所有内联元素都包含文本:**  内联元素也可能是 `<img>` 或其他非文本元素。在处理光标位置时，需要区分这些不同类型的内联元素。

总而言之，`inline_caret_position_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够准确地计算各种内联布局场景下的光标位置，这对于实现可靠的文本编辑和用户交互功能至关重要。理解这些测试用例也能帮助开发者更好地理解浏览器是如何处理光标位置的，从而避免在开发 Web 应用时出现相关错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_caret_position_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/inline_caret_position.h"

#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class InlineCaretPositionTest : public RenderingTest {
 public:
  void SetUp() override {
    RenderingTest::SetUp();
    LoadAhem();
  }

 protected:
  void SetInlineFormattingContext(const char* id,
                                  const char* html,
                                  unsigned width,
                                  TextDirection dir = TextDirection::kLtr,
                                  const char* style = nullptr) {
    InsertStyleElement(
        "body { font: 10px/10px Ahem;  }"
        "bdo { display:block; }");
    const char* pattern =
        dir == TextDirection::kLtr
            ? "<div id='%s' style='width: %u0px; %s'>%s</div>"
            : "<bdo dir=rtl id='%s' style='width: %u0px; %s'>%s</bdo>";
    SetBodyInnerHTML(String::Format(
        pattern, id, width, style ? style : "word-break: break-all", html));
    container_ = GetElementById(id);
    DCHECK(container_);
    context_ = To<LayoutBlockFlow>(container_->GetLayoutObject());
    DCHECK(context_);
    DCHECK(context_->IsLayoutNGObject());
  }

  InlineCaretPosition ComputeInlineCaretPosition(unsigned offset,
                                                 TextAffinity affinity) const {
    return blink::ComputeInlineCaretPosition(*context_, offset, affinity);
  }

  InlineCursor FragmentOf(const Node* node) const {
    InlineCursor cursor;
    cursor.MoveTo(*node->GetLayoutObject());
    return cursor;
  }

  Persistent<Element> container_;
  Persistent<const LayoutBlockFlow> context_;
};

#define TEST_CARET(caret, fragment_, type_, offset_)                         \
  {                                                                          \
    EXPECT_EQ(caret.cursor, fragment_);                                      \
    EXPECT_EQ(caret.position_type, InlineCaretPositionType::type_);          \
    EXPECT_EQ(caret.text_offset, offset_) << caret.text_offset.value_or(-1); \
  }

TEST_F(InlineCaretPositionTest, AfterSpan) {
  InsertStyleElement("b { background-color: yellow; }");
  SetBodyInnerHTML("<div><b id=target>ABC</b></div>");
  const auto& target = *GetElementById("target");

  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position::AfterNode(target))),
             FragmentOf(&target), kAfterBox, std::nullopt);
}

TEST_F(InlineCaretPositionTest, AfterSpanCulled) {
  SetBodyInnerHTML("<div><b id=target>ABC</b></div>");
  const auto& target = *GetElementById("target");

  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position::AfterNode(target))),
             FragmentOf(target.firstChild()), kAtTextOffset,
             std::optional<unsigned>(3));
}

TEST_F(InlineCaretPositionTest, InlineCaretPositionInOneLineOfText) {
  SetInlineFormattingContext("t", "foo", 3);
  const Node* text = container_->firstChild();
  const InlineCursor& text_fragment = FragmentOf(text);

  // Beginning of line
  TEST_CARET(ComputeInlineCaretPosition(0, TextAffinity::kDownstream),
             text_fragment, kAtTextOffset, std::optional<unsigned>(0));
  TEST_CARET(ComputeInlineCaretPosition(0, TextAffinity::kUpstream),
             text_fragment, kAtTextOffset, std::optional<unsigned>(0));

  // Middle in the line
  TEST_CARET(ComputeInlineCaretPosition(1, TextAffinity::kDownstream),
             text_fragment, kAtTextOffset, std::optional<unsigned>(1));
  TEST_CARET(ComputeInlineCaretPosition(1, TextAffinity::kUpstream),
             text_fragment, kAtTextOffset, std::optional<unsigned>(1));

  // End of line
  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kDownstream),
             text_fragment, kAtTextOffset, std::optional<unsigned>(3));
  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kUpstream),
             text_fragment, kAtTextOffset, std::optional<unsigned>(3));
}

// For http://crbug.com/1021993
// We should not call |InlineCursor::CurrentBidiLevel()| for soft hyphen
TEST_F(InlineCaretPositionTest, InlineCaretPositionAtSoftHyphen) {
  // We have three fragment "foo\u00AD", "\u2010", "bar"
  SetInlineFormattingContext("t", "foo&shy;bar", 3, TextDirection::kLtr, "");
  const LayoutText& text =
      *To<Text>(container_->firstChild())->GetLayoutObject();
  InlineCursor cursor;
  cursor.MoveTo(text);
  const InlineCursor foo_fragment = cursor;

  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kDownstream),
             foo_fragment, kAtTextOffset, std::optional<unsigned>(4));
  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kUpstream),
             foo_fragment, kAtTextOffset, std::optional<unsigned>(4));
}

TEST_F(InlineCaretPositionTest, InlineCaretPositionAtSoftLineWrap) {
  SetInlineFormattingContext("t", "foobar", 3);
  const LayoutText& text =
      *To<Text>(container_->firstChild())->GetLayoutObject();
  InlineCursor cursor;
  cursor.MoveTo(text);
  const InlineCursor foo_fragment = cursor;
  cursor.MoveToNextForSameLayoutObject();
  const InlineCursor bar_fragment = cursor;

  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kDownstream),
             bar_fragment, kAtTextOffset, std::optional<unsigned>(3));
  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kUpstream),
             foo_fragment, kAtTextOffset, std::optional<unsigned>(3));
}

TEST_F(InlineCaretPositionTest, InlineCaretPositionAtSoftLineWrapWithSpace) {
  SetInlineFormattingContext("t", "foo bar", 3);
  const LayoutText& text =
      *To<Text>(container_->firstChild())->GetLayoutObject();
  InlineCursor cursor;
  cursor.MoveTo(text);
  const InlineCursor foo_fragment = cursor;
  cursor.MoveToNextForSameLayoutObject();
  const InlineCursor bar_fragment = cursor;

  // Before the space
  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kDownstream),
             foo_fragment, kAtTextOffset, std::optional<unsigned>(3));
  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kUpstream),
             foo_fragment, kAtTextOffset, std::optional<unsigned>(3));

  // After the space
  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kDownstream),
             bar_fragment, kAtTextOffset, std::optional<unsigned>(4));
  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kUpstream),
             bar_fragment, kAtTextOffset, std::optional<unsigned>(4));
}

TEST_F(InlineCaretPositionTest, InlineCaretPositionAtForcedLineBreak) {
  SetInlineFormattingContext("t", "foo<br>bar", 3);
  const Node* foo = container_->firstChild();
  const Node* br = foo->nextSibling();
  const Node* bar = br->nextSibling();
  const InlineCursor& foo_fragment = FragmentOf(foo);
  const InlineCursor& bar_fragment = FragmentOf(bar);

  // Before the BR
  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kDownstream),
             foo_fragment, kAtTextOffset, std::optional<unsigned>(3));
  TEST_CARET(ComputeInlineCaretPosition(3, TextAffinity::kUpstream),
             foo_fragment, kAtTextOffset, std::optional<unsigned>(3));

  // After the BR
  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kDownstream),
             bar_fragment, kAtTextOffset, std::optional<unsigned>(4));
  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kUpstream),
             bar_fragment, kAtTextOffset, std::optional<unsigned>(4));
}

TEST_F(InlineCaretPositionTest, InlineCaretPositionAtEmptyLine) {
  SetInlineFormattingContext("f", "foo<br><br>bar", 3);
  const Node* foo = container_->firstChild();
  const Node* br1 = foo->nextSibling();
  const Node* br2 = br1->nextSibling();
  const InlineCursor& br2_fragment = FragmentOf(br2);

  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kDownstream),
             br2_fragment, kAtTextOffset, std::optional<unsigned>(4));
  TEST_CARET(ComputeInlineCaretPosition(4, TextAffinity::kUpstream),
             br2_fragment, kAtTextOffset, std::optional<unsigned>(4));
}

TEST_F(InlineCaretPositionTest, InlineCaretPositionInOneLineOfImage) {
  SetInlineFormattingContext("t", "<img>", 3);
  const Node* img = container_->firstChild();
  const InlineCursor& img_fragment = FragmentOf(img);

  // Before the image
  TEST_CARET(ComputeInlineCaretPosition(0, TextAffinity::kDownstream),
             img_fragment, kBeforeBox, std::nullopt);
  TEST_CARET(ComputeInlineCaretPosition(0, TextAffinity::kUpstream),
             img_fragment, kBeforeBox, std::nullopt);

  // After the image
  TEST_CARET(ComputeInlineCaretPosition(1, TextAffinity::kDownstream),
             img_fragment, kAfterBox, std::nullopt);
  TEST_CARET(ComputeInlineCaretPosition(1, TextAffinity::kUpstream),
             img_fragment, kAfterBox, std::nullopt);
}

TEST_F(InlineCaretPositionTest,
       InlineCaretPositionAtSoftLineWrapBetweenImages) {
  SetInlineFormattingContext("t",
                             "<img id=img1><img id=img2>"
                             "<style>img{width: 1em; height: 1em}</style>",
                             1);
  const Node* img1 = container_->firstChild();
  const Node* img2 = img1->nextSibling();
  const InlineCursor& img1_fragment = FragmentOf(img1);
  const InlineCursor& img2_fragment = FragmentOf(img2);

  TEST_CARET(ComputeInlineCaretPosition(1, TextAffinity::kDownstream),
             img2_fragment, kBeforeBox, std::nullopt);
  TEST_CARET(ComputeInlineCaretPosition(1, TextAffinity::kUpstream),
             img1_fragment, kAfterBox, std::nullopt);
}

TEST_F(InlineCaretPositionTest,
       InlineCaretPositionAtSoftLineWrapBetweenMultipleTextNodes) {
  SetInlineFormattingContext("t",
                             "<span>A</span>"
                             "<span>B</span>"
                             "<span id=span-c>C</span>"
                             "<span id=span-d>D</span>"
                             "<span>E</span>"
                             "<span>F</span>",
                             3);
  const Node* text_c = GetElementById("span-c")->firstChild();
  const Node* text_d = GetElementById("span-d")->firstChild();
  const InlineCursor& fragment_c = FragmentOf(text_c);
  const InlineCursor& fragment_d = FragmentOf(text_d);

  const Position wrap_position(text_c, 1);
  const OffsetMapping& mapping = *OffsetMapping::GetFor(wrap_position);
  const unsigned wrap_offset = *mapping.GetTextContentOffset(wrap_position);

  TEST_CARET(ComputeInlineCaretPosition(wrap_offset, TextAffinity::kUpstream),
             fragment_c, kAtTextOffset, std::optional<unsigned>(wrap_offset));
  TEST_CARET(ComputeInlineCaretPosition(wrap_offset, TextAffinity::kDownstream),
             fragment_d, kAtTextOffset, std::optional<unsigned>(wrap_offset));
}

TEST_F(InlineCaretPositionTest,
       InlineCaretPositionAtSoftLineWrapBetweenMultipleTextNodesRtl) {
  SetInlineFormattingContext("t",
                             "<span>A</span>"
                             "<span>B</span>"
                             "<span id=span-c>C</span>"
                             "<span id=span-d>D</span>"
                             "<span>E</span>"
                             "<span>F</span>",
                             3, TextDirection::kRtl);
  const Node* text_c = GetElementById("span-c")->firstChild();
  const Node* text_d = GetElementById("span-d")->firstChild();
  const InlineCursor& fragment_c = FragmentOf(text_c);
  const InlineCursor& fragment_d = FragmentOf(text_d);

  const Position wrap_position(text_c, 1);
  const OffsetMapping& mapping = *OffsetMapping::GetFor(wrap_position);
  const unsigned wrap_offset = *mapping.GetTextContentOffset(wrap_position);

  TEST_CARET(ComputeInlineCaretPosition(wrap_offset, TextAffinity::kUpstream),
             fragment_c, kAtTextOffset, std::optional<unsigned>(wrap_offset));
  TEST_CARET(ComputeInlineCaretPosition(wrap_offset, TextAffinity::kDownstream),
             fragment_d, kAtTextOffset, std::optional<unsigned>(wrap_offset));
}

TEST_F(InlineCaretPositionTest,
       InlineCaretPositionAtSoftLineWrapBetweenDeepTextNodes) {
  SetInlineFormattingContext(
      "t",
      "<style>span {border: 1px solid black}</style>"
      "<span>A</span>"
      "<span>B</span>"
      "<span id=span-c>C</span>"
      "<span id=span-d>D</span>"
      "<span>E</span>"
      "<span>F</span>",
      4);  // Wider space to allow border and 3 characters
  const Node* text_c = GetElementById("span-c")->firstChild();
  const Node* text_d = GetElementById("span-d")->firstChild();
  const InlineCursor& fragment_c = FragmentOf(text_c);
  const InlineCursor& fragment_d = FragmentOf(text_d);

  const Position wrap_position(text_c, 1);
  const OffsetMapping& mapping = *OffsetMapping::GetFor(wrap_position);
  const unsigned wrap_offset = *mapping.GetTextContentOffset(wrap_position);

  TEST_CARET(ComputeInlineCaretPosition(wrap_offset, TextAffinity::kUpstream),
             fragment_c, kAtTextOffset, std::optional<unsigned>(wrap_offset));
  TEST_CARET(ComputeInlineCaretPosition(wrap_offset, TextAffinity::kDownstream),
             fragment_d, kAtTextOffset, std::optional<unsigned>(wrap_offset));
}

TEST_F(InlineCaretPositionTest, GeneratedZeroWidthSpace) {
  LoadAhem();
  InsertStyleElement(
      "p { font: 10px/1 Ahem; }"
      "p { width: 4ch; white-space: pre-wrap;");
  // We have ZWS before "abc" due by "pre-wrap".
  // text content is
  //    [0..3] "   "
  //    [4] ZWS
  //    [5..8] "abcd"
  SetBodyInnerHTML("<p id=t>    abcd</p>");
  const Text& text = To<Text>(*GetElementById("t")->firstChild());
  const Position after_zws(text, 4);  // before "a".

  InlineCursor cursor;
  cursor.MoveTo(*text.GetLayoutObject());

  ASSERT_EQ(TextOffsetRange(0, 4), cursor.Current().TextOffset());
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(after_zws, TextAffinity::kUpstream)),
             cursor, kAtTextOffset, std::optional<unsigned>(4));

  cursor.MoveToNextForSameLayoutObject();
  ASSERT_EQ(TextOffsetRange(5, 9), cursor.Current().TextOffset());
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(after_zws, TextAffinity::kDownstream)),
             cursor, kAtTextOffset, std::optional<unsigned>(5));
}

// See also ParameterizedLocalCaretRectTest.MultiColumnSingleText
TEST_F(InlineCaretPositionTest, MultiColumnSingleText) {
  LoadAhem();
  InsertStyleElement(
      "div { font: 10px/15px Ahem; column-count: 3; width: 20ch; }");
  SetBodyInnerHTML("<div id=target>abc def ghi jkl mno pqr</div>");
  // This HTML is rendered as:
  //    abc ghi mno
  //    def jkl
  const auto& target = *GetElementById("target");
  const Text& text = *To<Text>(target.firstChild());

  InlineCursor cursor;
  cursor.MoveTo(*text.GetLayoutObject());

  // "abc " in column 1
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 0))),
             cursor, kAtTextOffset, std::optional<unsigned>(0));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 1))),
             cursor, kAtTextOffset, std::optional<unsigned>(1));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 2))),
             cursor, kAtTextOffset, std::optional<unsigned>(2));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 3))),
             cursor, kAtTextOffset, std::optional<unsigned>(3));
  cursor.MoveToNextForSameLayoutObject();

  // "def " in column 1
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 4))),
             cursor, kAtTextOffset, std::optional<unsigned>(4));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 5))),
             cursor, kAtTextOffset, std::optional<unsigned>(5));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 6))),
             cursor, kAtTextOffset, std::optional<unsigned>(6));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 7))),
             cursor, kAtTextOffset, std::optional<unsigned>(7));
  cursor.MoveToNextForSameLayoutObject();

  // "ghi " in column 2
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 8))),
             cursor, kAtTextOffset, std::optional<unsigned>(8));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 9))),
             cursor, kAtTextOffset, std::optional<unsigned>(9));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 10))),
             cursor, kAtTextOffset, std::optional<unsigned>(10));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 11))),
             cursor, kAtTextOffset, std::optional<unsigned>(11));
  cursor.MoveToNextForSameLayoutObject();

  // "jkl " in column 2
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 12))),
             cursor, kAtTextOffset, std::optional<unsigned>(12));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 13))),
             cursor, kAtTextOffset, std::optional<unsigned>(13));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 14))),
             cursor, kAtTextOffset, std::optional<unsigned>(14));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 15))),
             cursor, kAtTextOffset, std::optional<unsigned>(15));
  cursor.MoveToNextForSameLayoutObject();

  // "mno " in column 3
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 16))),
             cursor, kAtTextOffset, std::optional<unsigned>(16));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 17))),
             cursor, kAtTextOffset, std::optional<unsigned>(17));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 18))),
             cursor, kAtTextOffset, std::optional<unsigned>(18));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 19))),
             cursor, kAtTextOffset, std::optional<unsigned>(19));
  cursor.MoveToNextForSameLayoutObject();

  // "pqr" in column 3
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 20))),
             cursor, kAtTextOffset, std::optional<unsigned>(20));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 21))),
             cursor, kAtTextOffset, std::optional<unsigned>(21));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 22))),
             cursor, kAtTextOffset, std::optional<unsigned>(22));
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(text, 23))),
             cursor, kAtTextOffset, std::optional<unsigned>(23));
  cursor.MoveToNextForSameLayoutObject();
}

// http://crbug.com/1183269
// See also InlineCaretPositionTest.InlineCaretPositionAtSoftLineWrap
TEST_F(InlineCaretPositionTest, SoftLineWrap) {
  LoadAhem();
  InsertStyleElement(
      "p { font: 10px/1 Ahem; }"
      "p { width: 4ch;");
  // Note: "contenteditable" adds
  //    line-break: after-white-space;
  //    overflow-wrap: break-word;
  SetBodyInnerHTML("<p id=t contenteditable>abc xyz</p>");
  const Text& text = To<Text>(*GetElementById("t")->firstChild());
  const Position before_xyz(text, 4);  // before "w".

  InlineCursor cursor;
  cursor.MoveTo(*text.GetLayoutObject());

  // Note: upstream/downstream before "xyz" are in different line.

  ASSERT_EQ(TextOffsetRange(0, 3), cursor.Current().TextOffset());
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(before_xyz, TextAffinity::kUpstream)),
             cursor, kAtTextOffset, std::optional<unsigned>(3));

  cursor.MoveToNextForSameLayoutObject();
  ASSERT_EQ(TextOffsetRange(4, 7), cursor.Current().TextOffset());
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(before_xyz, TextAffinity::kDownstream)),
             cursor, kAtTextOffset, std::optional<unsigned>(4));
}

TEST_F(InlineCaretPositionTest, ZeroWidthSpace) {
  LoadAhem();
  InsertStyleElement(
      "p { font: 10px/1 Ahem; }"
      "p { width: 4ch;");
  // dom and text content is
  //    [0..3] "abcd"
  //    [4] ZWS
  //    [5..8] "wxyz"
  SetBodyInnerHTML("<p id=t>abcd&#x200B;wxyz</p>");
  const Text& text = To<Text>(*GetElementById("t")->firstChild());
  const Position after_zws(text, 5);  // before "w".

  InlineCursor cursor;
  cursor.MoveTo(*text.GetLayoutObject());

  ASSERT_EQ(TextOffsetRange(0, 5), cursor.Current().TextOffset());
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(after_zws, TextAffinity::kUpstream)),
             cursor, kAtTextOffset, std::optional<unsigned>(4));

  cursor.MoveToNextForSameLayoutObject();
  ASSERT_EQ(TextOffsetRange(5, 9), cursor.Current().TextOffset());
  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(after_zws, TextAffinity::kDownstream)),
             cursor, kAtTextOffset, std::optional<unsigned>(5));
}

TEST_F(InlineCaretPositionTest, InlineBlockBeforeContent) {
  SetInlineFormattingContext(
      "t",
      "<style>span::before{display:inline-block; content:'foo'}</style>"
      "<span id=span>bar</span>",
      100);  // Line width doesn't matter here.
  const Node* text = GetElementById("span")->firstChild();
  const InlineCursor& text_fragment = FragmentOf(text);

  // Test caret position of "|bar", which shouldn't be affected by ::before
  const Position position(text, 0);
  const OffsetMapping& mapping = *OffsetMapping::GetFor(position);
  const unsigned text_offset = *mapping.GetTextContentOffset(position);

  TEST_CARET(ComputeInlineCaretPosition(text_offset, TextAffinity::kDownstream),
             text_fragment, kAtTextOffset,
             std::optional<unsigned>(text_offset));
}

TEST_F(InlineCaretPositionTest, InlineBoxesLTR) {
  SetBodyInnerHTML(
      "<div dir=ltr>"
      "<bdo id=box1 dir=ltr>ABCD</bdo>"
      "<bdo id=box2 dir=ltr style='font-size: 150%'>EFG</bdo></div>");

  // text_content:
  //    [0] U+2068 FIRST STRONG ISOLATE
  //    [1] U+202D LEFT-TO_RIGHT_OVERRIDE
  //    [2:5] "ABCD"
  //    [6] U+202C POP DIRECTIONAL FORMATTING
  //    [7] U+2069 POP DIRECTIONAL ISOLATE
  //    [8] U+2068 FIRST STRONG ISOLATE
  //    [9] U+202D LEFT-TO_RIGHT_OVERRIDE
  //    [10:12] "EFG"
  //    [13] U+202C POP DIRECTIONAL FORMATTING
  //    [14] U+2069 POP DIRECTIONAL ISOLATE
  // For details on injected codes, see:
  // https://drafts.csswg.org/css-writing-modes-3/#bidi-control-codes-injection-table
  const Node& box1 = *GetElementById("box1")->firstChild();
  const Node& box2 = *GetElementById("box1")->firstChild();

  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(box1, 4))),
             FragmentOf(&box1), kAtTextOffset, std::optional<unsigned>(6));

  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(box2, 0))),
             FragmentOf(&box2), kAtTextOffset, std::optional<unsigned>(2));
}

TEST_F(InlineCaretPositionTest, InlineBoxesRTL) {
  SetBodyInnerHTML(
      "<div dir=rtl>"
      "<bdo id=box1 dir=rtl>ABCD</bdo>"
      "<bdo id=box2 dir=rtl style='font-size: 150%'>EFG</bdo></div>");

  // text_content:
  //    [0] U+2068 FIRST STRONG ISOLATE
  //    [1] U+202E RIGHT-TO_LEFT _OVERRIDE
  //    [2:5] "ABCD"
  //    [6] U+202C POP DIRECTIONAL FORMATTING
  //    [7] U+2069 POP DIRECTIONAL ISOLATE
  //    [8] U+2068 FIRST STRONG ISOLATE
  //    [9] U+202E RIGHT-TO_LEFT _OVERRIDE
  //    [10:12] "EFG"
  //    [13] U+202C POP DIRECTIONAL FORMATTING
  //    [14] U+2069 POP DIRECTIONAL ISOLATE
  // For details on injected codes, see:
  // https://drafts.csswg.org/css-writing-modes-3/#bidi-control-codes-injection-table
  const Node& box1 = *GetElementById("box1")->firstChild();
  const Node& box2 = *GetElementById("box1")->firstChild();

  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(box1, 4))),
             FragmentOf(&box1), kAtTextOffset, std::optional<unsigned>(6));

  TEST_CARET(blink::ComputeInlineCaretPosition(
                 PositionWithAffinity(Position(box2, 0))),
             FragmentOf(&box2), kAtTextOffset, std::optional<unsigned>(2));
}

// https://crbug.com/1340236
TEST_F(InlineCaretPositionTest, BeforeOrAfterInlineAreaElement) {
  SetBodyInnerHTML("<area id=area>");

  const Node& area = *GetElementById("area");
  const PositionWithAffinity position1(Position::AfterNode(area));
  // DCHECK failure or crash happens here.
  blink::ComputeInlineCaretPosition(position1);

  const PositionWithAffinity position2(Position::BeforeNode(area));
  // DCHECK failure or crash happens here.
  blink::ComputeInlineCaretPosition(position2);
}

}  // namespace blink

"""

```