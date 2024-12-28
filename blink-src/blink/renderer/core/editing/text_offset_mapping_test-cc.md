Response:
Let's break down the thought process for analyzing this C++ test file and generating the detailed explanation.

1. **Understand the Goal:** The core request is to analyze the functionality of `text_offset_mapping_test.cc` within the Chromium Blink engine, focusing on its purpose, relation to web technologies, logic, potential errors, and debugging context.

2. **Initial Scan and Keyword Recognition:**  Quickly read through the code, noting key classes and functions:
    * `TextOffsetMapping` (the class being tested)
    * `EditingTestBase` (the test framework)
    * `ComputeTextOffset`, `GetRange`, `GetPositionBefore`, `GetPositionAfter` (test methods)
    * `PositionInFlatTree`, `SelectionInFlatTree` (data structures related to document structure and selection)
    *  Mentions of HTML elements like `<p>`, `<b>`, `<div>`, `<table>`, `<ruby>`, `<input>`, `<select>`, `<svg>`, `<img>`.
    *  References to CSS concepts like `float`, `display: inline-block`, `::first-letter`, `columns`, `position: fixed/absolute/relative`.

3. **Identify the Core Functionality Under Test:** The name of the file and the core class being tested, `TextOffsetMapping`, strongly suggest that the primary function is about mapping between different representations of text offsets within a web page's structure. The test methods provide clues about *how* this mapping is being tested.

4. **Analyze Individual Test Methods:**  Examine what each test method does and what assertions it makes:

    * **`ComputeTextOffset`:** Takes HTML with a caret (`|`) as input, runs the `ComputeTextOffset` method of `TextOffsetMapping`, and asserts the output string with a `|` indicating the computed offset. This tells us it's testing the ability to find the correct character offset within a logical text string, considering the presence of HTML tags.

    * **`GetRange`:** Takes HTML as input, gets a `PositionInFlatTree`, and then uses `TextOffsetMapping` to determine a *range* of text. The output format `^...|` suggests it's testing how `TextOffsetMapping` identifies the boundaries of a text segment.

    * **`GetPositionBefore` and `GetPositionAfter`:** Take HTML and an offset, use `TextOffsetMapping` to find the logical position *before* or *after* that offset, and then visually represent that position with a `|`.

5. **Infer the Purpose of `TextOffsetMapping`:** Based on the tests, we can deduce that `TextOffsetMapping` is responsible for:
    * **Abstracting away the complexity of HTML structure:** It presents a flat text representation of potentially nested HTML content.
    * **Mapping between DOM positions and flat text offsets:**  It can take a position within the DOM tree and find the corresponding character offset in the flat text representation, and vice-versa (implied by `GetPositionBefore/After`).
    * **Identifying the boundaries of "inline content":** The `InlineContents` inner class suggests it deals with contiguous runs of text and inline elements.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**

    * **HTML:** The tests heavily use HTML snippets as input, demonstrating how `TextOffsetMapping` handles different HTML structures.
    * **CSS:** Several tests use `InsertStyleElement` to apply CSS styles. This indicates that `TextOffsetMapping` needs to consider the visual layout effects of CSS (like floats, inline-block, positioning, `::first-letter`, multicolumn) when mapping offsets.
    * **JavaScript (Indirectly):** While the test is in C++, the functionality it tests is crucial for JavaScript's interaction with the document. JavaScript APIs for selecting text, moving the cursor, and manipulating text rely on a consistent understanding of text offsets.

7. **Illustrate with Examples:** For each web technology, provide concrete examples from the test code that demonstrate the connection. For example, the `ComputeTextOffsetWithFloat` test directly shows how floating elements affect the logical text order.

8. **Analyze Logic and Provide Input/Output Examples:** Choose representative test cases and explain the underlying logic. For `ComputeTextOffset`, explain how it skips over HTML tags. For `GetRange`, describe how it identifies the boundaries of inline content, especially around block-level elements.

9. **Identify Potential User/Programming Errors:** Think about how incorrect assumptions or usage of related APIs might lead to issues:
    * **Incorrect offset calculations:** A developer might manually try to calculate offsets without considering the effects of HTML and CSS, leading to errors when using APIs that rely on accurate offsets.
    * **Misunderstanding how selections work across different element types:** Not being aware of how block and inline elements influence selection boundaries.

10. **Explain User Actions and Debugging:** Consider how a user's actions in a browser could trigger the code being tested:
    * **Typing:**  Inserting text triggers updates to the document structure, requiring accurate offset mapping for cursor positioning.
    * **Selecting text:** Dragging the mouse or using keyboard shortcuts relies on the browser's ability to define a text range, which involves offset calculations.
    * **Copying and pasting:**  The browser needs to determine the correct text content and its boundaries.
    * **Using JavaScript to manipulate text:**  JavaScript selection APIs internally use concepts similar to what `TextOffsetMapping` provides.

11. **Structure the Explanation:** Organize the information logically with clear headings and bullet points to make it easy to read and understand. Start with a high-level summary and then delve into specifics.

12. **Refine and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation. Ensure the examples are relevant and illustrative. For instance, the initial explanation might not explicitly link the "flat tree" concept to how the offsets are computed; adding that detail during review would improve clarity.
这个文件 `text_offset_mapping_test.cc` 是 Chromium Blink 渲染引擎中的一个 C++ 单元测试文件。它的主要功能是 **测试 `TextOffsetMapping` 类的各种功能**。`TextOffsetMapping` 类负责在复杂的 HTML 结构中，将 DOM 树中的位置（Position）映射到线性文本的偏移量（offset），以及反过来进行映射。

下面详细列举其功能，并说明与 JavaScript, HTML, CSS 的关系：

**1. 核心功能：测试 `TextOffsetMapping` 类的偏移量计算和范围获取**

* **`ComputeTextOffset(const std::string& selection_text)`:**
    * **功能:**  接收一个包含光标位置（用 `|` 表示）的 HTML 字符串，创建一个 `TextOffsetMapping` 对象，并计算光标位置在 `TextOffsetMapping` 生成的线性文本中的偏移量。
    * **与 HTML 的关系:**  该方法直接解析 HTML 字符串，理解 HTML 标签的结构，并将其转换为一个线性的文本表示。例如，HTML 标签本身不会被计入文本偏移量。
    * **与 CSS 的关系:**  某些 CSS 属性，如 `float` 和 `display: inline-block` 会影响元素的布局和文本的逻辑顺序。`ComputeTextOffset` 的测试用例会考虑这些 CSS 属性的影响。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** `<p>abc|def</p>`
        * **输出:** `abc|def` (光标在 "c" 和 "d" 之间，偏移量为 3)
        * **假设输入:** `<p>a<b>bc|</b>def</p>`
        * **输出:** `abc|def` (光标在 "c" 之后，偏移量为 3，忽略 `<b>` 标签)
        * **假设输入 (带 `float`):** `<p>a<b>BCD</b>|e</p>` (假设 `b { float:right; }`)
        * **输出:** `aBCDe|` (光标在 "D" 之后，偏移量为 4，考虑 `float` 带来的文本顺序变化)

* **`GetRange(const std::string& selection_text)` 和其他 `GetRange` 重载:**
    * **功能:** 接收一个包含光标位置的 HTML 字符串或一个 `PositionInFlatTree` 对象，使用 `TextOffsetMapping` 类获取包含该位置的最小范围的文本。通常用 `^` 和 `|` 标记范围的开始和结束。
    * **与 HTML 的关系:**  用于测试在各种复杂的 HTML 结构下，如何确定一个文本范围。例如，如何处理跨越不同 HTML 元素的范围，以及如何处理块级元素和行内元素。
    * **与 CSS 的关系:**  CSS 的布局属性会影响范围的确定。例如，块级元素会定义一个独立的范围。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** `<div><p>abc</p>d|ef<p>ghi</p></div>`
        * **输出:** `<div><p>abc</p>^def|<p>ghi</p></div>` (光标在匿名块中，范围包含整个匿名块)
        * **假设输入:** `<p>abc<b>de|f</b>ghi</p>`
        * **输出:** `<p>abc<b>^def|</b>ghi</p>` (范围包含 `<b>` 标签内的文本)

* **`GetPositionBefore(const std::string& html_text, int offset)` 和 `GetPositionAfter(const std::string& html_text, int offset)`:**
    * **功能:** 接收一个 HTML 字符串和一个文本偏移量，使用 `TextOffsetMapping` 类计算在该偏移量之前或之后的 DOM 树中的位置，并用光标 `|` 标记。
    * **与 HTML 的关系:**  用于测试从线性文本偏移量反向映射回 DOM 树位置的能力。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入 (GetPositionBefore):** `"  012  456  "`, `offset = 4`
        * **输出:** `"  012|  456  "` (偏移量 4 对应空格之前)
        * **假设输入 (GetPositionAfter):** `"  012  456  "`, `offset = 4`
        * **输出:** `"  012 | 456  "` (偏移量 4 对应空格之后)

**2. 涉及的用户或编程常见的使用错误 (作为调试线索)**

虽然这个文件本身是测试代码，但它可以帮助理解和调试与文本编辑相关的错误：

* **光标位置错误:** 用户在编辑器中看到的光标位置与程序内部计算的偏移量不一致。这可能是由于 HTML 结构复杂，或者 CSS 样式影响了文本的渲染顺序。`TextOffsetMapping` 的测试用例覆盖了各种复杂的场景，有助于发现和修复这类错误。
    * **例如:** 在包含 `float` 元素的文本中，用户看到的文本顺序可能与 DOM 树的顺序不同，直接使用 DOM API 计算偏移量可能会出错。`TextOffsetMapping` 需要正确处理这种情况。
* **范围选择错误:** 用户选择的文本范围与程序理解的范围不一致。这可能是由于块级元素、行内元素、以及各种 CSS 属性的影响。`GetRange` 的测试用例可以帮助验证范围选择逻辑的正确性。
    * **例如:**  选择跨越块级元素的文本时，范围应该如何定义？`TextOffsetMapping` 需要确保在这种情况下返回合理的范围。
* **程序错误地处理了不可见字符或 HTML 标签:**  在计算偏移量或范围时，程序可能会错误地将某些不可见字符或 HTML 标签计入或排除。`TextOffsetMapping` 的测试用例会检查这种情况。

**3. 用户操作如何一步步到达这里 (作为调试线索)**

当用户在浏览器中进行以下操作时，可能会触发与 `TextOffsetMapping` 相关的代码：

1. **用户在可编辑区域键入文本:**
   * 当用户输入字符时，浏览器需要确定光标的正确位置，以便插入新字符。这涉及到将屏幕上的位置映射到 DOM 树中的位置，并计算插入点的偏移量。
   * `ComputeTextOffset` 和 `GetPositionAfter` 等功能在这里会被用到。

2. **用户使用鼠标或键盘选择文本:**
   * 当用户拖动鼠标或使用 Shift + 方向键选择文本时，浏览器需要计算选择范围的起始和结束位置。
   * `GetRange` 功能会被用来确定选择的文本范围，需要考虑各种 HTML 和 CSS 布局的影响。

3. **用户移动光标 (使用方向键或点击):**
   * 当用户移动光标时，浏览器需要更新光标在 DOM 树中的位置。
   * `GetPositionBefore` 和 `GetPositionAfter` 可以用于辅助确定移动后的新位置。

4. **用户进行复制/粘贴操作:**
   * 复制操作需要确定选中文本的准确范围和内容。
   * 粘贴操作需要在光标位置插入文本，同样需要计算偏移量。

5. **JavaScript 代码操作文本内容或光标位置:**
   * JavaScript 代码可以使用 `Selection` 和 `Range` API 来获取或设置选区。这些 API 的底层实现可能依赖于类似 `TextOffsetMapping` 的机制来处理复杂的 HTML 结构。

**调试线索:**

如果开发者在调试与文本编辑相关的问题时，例如：

* 光标跳动不正常
* 选择范围错误
* 复制粘贴内容错误

可以考虑以下步骤，这些步骤与 `text_offset_mapping_test.cc` 的功能相关：

1. **检查光标所在的 DOM 节点和偏移量:** 使用浏览器的开发者工具查看当前光标的位置（例如，通过 `document.getSelection().anchorNode` 和 `document.getSelection().anchorOffset`）。
2. **分析周围的 HTML 结构和 CSS 样式:**  查看光标周围的 HTML 标签和应用的 CSS 样式，特别是影响布局的属性，如 `float`, `display`, `position` 等。
3. **思考 `TextOffsetMapping` 需要如何处理这种情况:**  考虑 `TextOffsetMapping` 在将 DOM 位置映射到文本偏移量时，会如何处理这些 HTML 和 CSS。
4. **参考 `text_offset_mapping_test.cc` 中的相关测试用例:**  查找与当前遇到的 HTML 结构或 CSS 样式类似的测试用例，看是否已经有测试覆盖了这种情况，以及期望的行为是什么。
5. **编写新的测试用例 (如果需要):** 如果发现 `TextOffsetMapping` 没有正确处理某种情况，可以编写新的测试用例来复现问题，并驱动修复。

总而言之，`text_offset_mapping_test.cc` 是一个用于验证 Blink 引擎中处理文本偏移量和范围的核心组件的测试文件。它与 JavaScript, HTML, CSS 紧密相关，因为它的目标是正确地理解和操作在这些技术构建的复杂网页中的文本。理解这个测试文件的功能有助于理解浏览器如何处理文本编辑相关的用户操作，并为调试相关问题提供线索。

Prompt: 
```
这是目录为blink/renderer/core/editing/text_offset_mapping_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/text_offset_mapping.h"

#include <string>

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

using ::testing::ElementsAre;

class TextOffsetMappingTest : public EditingTestBase {
 protected:
  TextOffsetMappingTest() = default;

  std::string ComputeTextOffset(const std::string& selection_text) {
    const PositionInFlatTree position =
        ToPositionInFlatTree(SetCaretTextToBody(selection_text));
    TextOffsetMapping mapping(GetInlineContents(position));
    const String text = mapping.GetText();
    const int offset = mapping.ComputeTextOffset(position);
    StringBuilder builder;
    builder.Append(text.Left(offset));
    builder.Append('|');
    builder.Append(text.Substring(offset));
    return builder.ToString().Utf8();
  }

  std::string GetRange(const std::string& selection_text) {
    return GetRange(ToPositionInFlatTree(SetCaretTextToBody(selection_text)));
  }

  std::string GetRange(const PositionInFlatTree& position) {
    return GetRange(GetInlineContents(position));
  }

  std::string GetRange(const TextOffsetMapping::InlineContents& contents) {
    TextOffsetMapping mapping(contents);
    return GetSelectionTextInFlatTreeFromBody(
        SelectionInFlatTree::Builder()
            .SetBaseAndExtent(mapping.GetRange())
            .Build());
  }

  std::string GetPositionBefore(const std::string& html_text, int offset) {
    SetBodyContent(html_text);
    TextOffsetMapping mapping(GetInlineContents(
        PositionInFlatTree(*GetDocument().body()->firstChild(), 0)));
    return GetSelectionTextInFlatTreeFromBody(
        SelectionInFlatTree::Builder()
            .Collapse(mapping.GetPositionBefore(offset))
            .Build());
  }

  std::string GetPositionAfter(const std::string& html_text, int offset) {
    SetBodyContent(html_text);
    TextOffsetMapping mapping(GetInlineContents(
        PositionInFlatTree(*GetDocument().body()->firstChild(), 0)));
    return GetSelectionTextInFlatTreeFromBody(
        SelectionInFlatTree::Builder()
            .Collapse(mapping.GetPositionAfter(offset))
            .Build());
  }

 private:
  static TextOffsetMapping::InlineContents GetInlineContents(
      const PositionInFlatTree& position) {
    const TextOffsetMapping::InlineContents inline_contents =
        TextOffsetMapping::FindForwardInlineContents(position);
    DCHECK(inline_contents.IsNotNull()) << position;
    return inline_contents;
  }
};

TEST_F(TextOffsetMappingTest, ComputeTextOffsetBasic) {
  EXPECT_EQ("|(1) abc def", ComputeTextOffset("<p>| (1) abc def</p>"));
  EXPECT_EQ("|(1) abc def", ComputeTextOffset("<p> |(1) abc def</p>"));
  EXPECT_EQ("(|1) abc def", ComputeTextOffset("<p> (|1) abc def</p>"));
  EXPECT_EQ("(1|) abc def", ComputeTextOffset("<p> (1|) abc def</p>"));
  EXPECT_EQ("(1)| abc def", ComputeTextOffset("<p> (1)| abc def</p>"));
  EXPECT_EQ("(1) |abc def", ComputeTextOffset("<p> (1) |abc def</p>"));
  EXPECT_EQ("(1) a|bc def", ComputeTextOffset("<p> (1) a|bc def</p>"));
  EXPECT_EQ("(1) ab|c def", ComputeTextOffset("<p> (1) ab|c def</p>"));
  EXPECT_EQ("(1) abc| def", ComputeTextOffset("<p> (1) abc| def</p>"));
  EXPECT_EQ("(1) abc |def", ComputeTextOffset("<p> (1) abc |def</p>"));
  EXPECT_EQ("(1) abc d|ef", ComputeTextOffset("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("(1) abc de|f", ComputeTextOffset("<p> (1) abc de|f</p>"));
  EXPECT_EQ("(1) abc def|", ComputeTextOffset("<p> (1) abc def|</p>"));
}

TEST_F(TextOffsetMappingTest, ComputeTextOffsetWithFirstLetter) {
  InsertStyleElement("p::first-letter {font-size:200%;}");
  // Expectation should be as same as |ComputeTextOffsetBasic|
  EXPECT_EQ("|(1) abc def", ComputeTextOffset("<p>| (1) abc def</p>"));
  EXPECT_EQ("|(1) abc def", ComputeTextOffset("<p> |(1) abc def</p>"));
  EXPECT_EQ("(|1) abc def", ComputeTextOffset("<p> (|1) abc def</p>"));
  EXPECT_EQ("(1|) abc def", ComputeTextOffset("<p> (1|) abc def</p>"));
  EXPECT_EQ("(1)| abc def", ComputeTextOffset("<p> (1)| abc def</p>"));
  EXPECT_EQ("(1) |abc def", ComputeTextOffset("<p> (1) |abc def</p>"));
  EXPECT_EQ("(1) a|bc def", ComputeTextOffset("<p> (1) a|bc def</p>"));
  EXPECT_EQ("(1) ab|c def", ComputeTextOffset("<p> (1) ab|c def</p>"));
  EXPECT_EQ("(1) abc| def", ComputeTextOffset("<p> (1) abc| def</p>"));
  EXPECT_EQ("(1) abc |def", ComputeTextOffset("<p> (1) abc |def</p>"));
  EXPECT_EQ("(1) abc d|ef", ComputeTextOffset("<p> (1) abc d|ef</p>"));
  EXPECT_EQ("(1) abc de|f", ComputeTextOffset("<p> (1) abc de|f</p>"));
  EXPECT_EQ("(1) abc def|", ComputeTextOffset("<p> (1) abc def|</p>"));
}

TEST_F(TextOffsetMappingTest, ComputeTextOffsetWithFloat) {
  InsertStyleElement("b { float:right; }");
  EXPECT_EQ("|aBCDe", ComputeTextOffset("<p>|a<b>BCD</b>e</p>"));
  EXPECT_EQ("a|BCDe", ComputeTextOffset("<p>a|<b>BCD</b>e</p>"));
  EXPECT_EQ("|BCD", ComputeTextOffset("<p>a<b>|BCD</b>e</p>"));
  EXPECT_EQ("B|CD", ComputeTextOffset("<p>a<b>B|CD</b>e</p>"));
  EXPECT_EQ("BC|D", ComputeTextOffset("<p>a<b>BC|D</b>e</p>"));
  EXPECT_EQ("BCD|", ComputeTextOffset("<p>a<b>BCD|</b>e</p>"));
  EXPECT_EQ("aBCD|e", ComputeTextOffset("<p>a<b>BCD</b>|e</p>"));
  EXPECT_EQ("aBCDe|", ComputeTextOffset("<p>a<b>BCD</b>e|</p>"));
}

TEST_F(TextOffsetMappingTest, ComputeTextOffsetWithInlineBlock) {
  InsertStyleElement("b { display:inline-block; }");
  EXPECT_EQ("|aBCDe", ComputeTextOffset("<p>|a<b>BCD</b>e</p>"));
  EXPECT_EQ("a|BCDe", ComputeTextOffset("<p>a|<b>BCD</b>e</p>"));
  EXPECT_EQ("a|BCDe", ComputeTextOffset("<p>a<b>|BCD</b>e</p>"));
  EXPECT_EQ("aB|CDe", ComputeTextOffset("<p>a<b>B|CD</b>e</p>"));
  EXPECT_EQ("aBC|De", ComputeTextOffset("<p>a<b>BC|D</b>e</p>"));
  EXPECT_EQ("aBCD|e", ComputeTextOffset("<p>a<b>BCD|</b>e</p>"));
  EXPECT_EQ("aBCD|e", ComputeTextOffset("<p>a<b>BCD</b>|e</p>"));
  EXPECT_EQ("aBCDe|", ComputeTextOffset("<p>a<b>BCD</b>e|</p>"));
}

TEST_F(TextOffsetMappingTest, RangeOfAnonymousBlock) {
  EXPECT_EQ("<div><p>abc</p>^def|<p>ghi</p></div>",
            GetRange("<div><p>abc</p>d|ef<p>ghi</p></div>"));
}

TEST_F(TextOffsetMappingTest, RangeOfBlockOnInlineBlock) {
  // display:inline-block doesn't introduce block.
  EXPECT_EQ("^abc<p style=\"display:inline\">def<br>ghi</p>xyz|",
            GetRange("|abc<p style=display:inline>def<br>ghi</p>xyz"));
  EXPECT_EQ("^abc<p style=\"display:inline\">def<br>ghi</p>xyz|",
            GetRange("abc<p style=display:inline>|def<br>ghi</p>xyz"));
}

TEST_F(TextOffsetMappingTest, RangeOfBlockWithAnonymousBlock) {
  // "abc" and "xyz" are in anonymous block.

  // Range is "abc"
  EXPECT_EQ("^abc|<p>def</p>xyz", GetRange("|abc<p>def</p>xyz"));
  EXPECT_EQ("^abc|<p>def</p>xyz", GetRange("a|bc<p>def</p>xyz"));

  // Range is "def"
  EXPECT_EQ("abc<p>^def|</p>xyz", GetRange("abc<p>|def</p>xyz"));
  EXPECT_EQ("abc<p>^def|</p>xyz", GetRange("abc<p>d|ef</p>xyz"));

  // Range is "xyz"
  EXPECT_EQ("abc<p>def</p>^xyz|", GetRange("abc<p>def</p>|xyz"));
  EXPECT_EQ("abc<p>def</p>^xyz|", GetRange("abc<p>def</p>xyz|"));
}

TEST_F(TextOffsetMappingTest, RangeOfBlockWithBR) {
  EXPECT_EQ("^abc<br>xyz|", GetRange("abc|<br>xyz"))
      << "BR doesn't affect block";
}

TEST_F(TextOffsetMappingTest, RangeOfBlockWithPRE) {
  // "\n" doesn't affect block.
  EXPECT_EQ("<pre>^abc\ndef\nghi\n|</pre>",
            GetRange("<pre>|abc\ndef\nghi\n</pre>"));
  EXPECT_EQ("<pre>^abc\ndef\nghi\n|</pre>",
            GetRange("<pre>abc\n|def\nghi\n</pre>"));
  EXPECT_EQ("<pre>^abc\ndef\nghi\n|</pre>",
            GetRange("<pre>abc\ndef\n|ghi\n</pre>"));
  EXPECT_EQ("<pre>^abc\ndef\nghi\n|</pre>",
            GetRange("<pre>abc\ndef\nghi\n|</pre>"));
}

TEST_F(TextOffsetMappingTest, RangeOfBlockWithRUBY) {
  const char* whole_text_selected = "^<ruby>abc<rt>123|</rt></ruby>";
  EXPECT_EQ(whole_text_selected, GetRange("<ruby>|abc<rt>123</rt></ruby>"));
  EXPECT_EQ(whole_text_selected, GetRange("<ruby>abc<rt>1|23</rt></ruby>"));
}

// http://crbug.com/1124584
TEST_F(TextOffsetMappingTest, RangeOfBlockWithRubyAsBlock) {
  const char* whole_text_selected = "<ruby>^abc<rt>XYZ|</rt></ruby>";
  InsertStyleElement("ruby { display: block; }");
  EXPECT_EQ(whole_text_selected, GetRange("|<ruby>abc<rt>XYZ</rt></ruby>"));
  EXPECT_EQ(whole_text_selected, GetRange("<ruby>|abc<rt>XYZ</rt></ruby>"));
  EXPECT_EQ(whole_text_selected, GetRange("<ruby>abc<rt>|XYZ</rt></ruby>"));
}

TEST_F(TextOffsetMappingTest, RangeOfBlockWithRubyAsInlineBlock) {
  const char* whole_text_selected = "^<ruby>abc<rt>XYZ|</rt></ruby>";
  InsertStyleElement("ruby { display: inline-block; }");
  EXPECT_EQ(whole_text_selected, GetRange("|<ruby>abc<rt>XYZ</rt></ruby>"));
  EXPECT_EQ(whole_text_selected, GetRange("<ruby>|abc<rt>XYZ</rt></ruby>"));
  EXPECT_EQ(whole_text_selected, GetRange("<ruby>abc<rt>|XYZ</rt></ruby>"));
}

TEST_F(TextOffsetMappingTest, RangeOfBlockWithRUBYandBR) {
  const char* whole_text_selected =
      "^<ruby>abc<br>def<rt>123<br>456|</rt></ruby>";
  EXPECT_EQ(whole_text_selected,
            GetRange("<ruby>|abc<br>def<rt>123<br>456</rt></ruby>"))
      << "RT(LayoutRubyColumn) is a block";
  EXPECT_EQ(whole_text_selected,
            GetRange("<ruby>abc<br>def<rt>123|<br>456</rt></ruby>"))
      << "RUBY introduce LayoutRuleBase for 'abc'";
}

TEST_F(TextOffsetMappingTest, RangeOfBlockWithTABLE) {
  EXPECT_EQ("^abc|<table><tbody><tr><td>one</td></tr></tbody></table>xyz",
            GetRange("|abc<table><tr><td>one</td></tr></table>xyz"))
      << "Before TABLE";
  EXPECT_EQ("abc<table><tbody><tr><td>^one|</td></tr></tbody></table>xyz",
            GetRange("abc<table><tr><td>o|ne</td></tr></table>xyz"))
      << "In TD";
  EXPECT_EQ("abc<table><tbody><tr><td>one</td></tr></tbody></table>^xyz|",
            GetRange("abc<table><tr><td>one</td></tr></table>x|yz"))
      << "After TABLE";
}

// |InlineContents| can represent an empty block.
// See LinkSelectionClickEventsTest.SingleAndDoubleClickWillBeHandled
TEST_F(TextOffsetMappingTest, RangeOfEmptyBlock) {
  const PositionInFlatTree position = ToPositionInFlatTree(
      SetSelectionTextToBody(
          "<div><p>abc</p><p id='target'>|</p><p>ghi</p></div>")
          .Anchor());
  const LayoutObject* const target_layout_object =
      GetDocument().getElementById(AtomicString("target"))->GetLayoutObject();
  const TextOffsetMapping::InlineContents inline_contents =
      TextOffsetMapping::FindForwardInlineContents(position);
  ASSERT_TRUE(inline_contents.IsNotNull());
  EXPECT_EQ(target_layout_object, inline_contents.GetEmptyBlock());
  EXPECT_EQ(inline_contents,
            TextOffsetMapping::FindBackwardInlineContents(position));
}

// http://crbug.com/900906
TEST_F(TextOffsetMappingTest, AnonymousBlockFlowWrapperForFloatPseudo) {
  InsertStyleElement("table::after{content:close-quote;float:right;}");
  const PositionInFlatTree position =
      ToPositionInFlatTree(SetCaretTextToBody("<table></table>|foo"));
  const TextOffsetMapping::InlineContents inline_contents =
      TextOffsetMapping::FindBackwardInlineContents(position);
  ASSERT_TRUE(inline_contents.IsNotNull());
  const TextOffsetMapping::InlineContents previous_contents =
      TextOffsetMapping::InlineContents::PreviousOf(inline_contents);
  EXPECT_TRUE(previous_contents.IsNull());
}

// http://crbug.com/1324970
TEST_F(TextOffsetMappingTest, BlockInInlineWithAbsolute) {
  InsertStyleElement("a { position:absolute; } #t { position: relative; }");
  const PositionInFlatTree position = ToPositionInFlatTree(
      SetCaretTextToBody("<div id=t><i><p><a></a></p></i> </div><p>|ab</p>"));

  Vector<String> results;
  for (const auto contents : TextOffsetMapping::BackwardRangeOf(position))
    results.push_back(GetRange(contents));

  ElementsAre("<div id=\"t\"><i><p><a></a></p></i> </div><p>^ab|</p>",
              "<div id=\"t\"><i><p><a></a></p></i>^ |</div><p>ab</p>",
              "<div id=\"t\">^<i><p><a></a></p></i>| </div><p>ab</p>");
}

TEST_F(TextOffsetMappingTest, ForwardRangesWithTextControl) {
  // InlineContents for positions outside text control should cover the entire
  // containing block.
  const PositionInFlatTree outside_position = ToPositionInFlatTree(
      SetCaretTextToBody("foo<!--|--><input value=\"bla\">bar"));
  const TextOffsetMapping::InlineContents outside_contents =
      TextOffsetMapping::FindForwardInlineContents(outside_position);
  EXPECT_EQ("^foo<input value=\"bla\"><div>bla</div></input>bar|",
            GetRange(outside_contents));

  // InlineContents for positions inside text control should not escape the text
  // control in forward iteration.
  const Element* input = GetDocument().QuerySelector(AtomicString("input"));
  const PositionInFlatTree inside_first =
      PositionInFlatTree::FirstPositionInNode(*input);
  const TextOffsetMapping::InlineContents inside_contents =
      TextOffsetMapping::FindForwardInlineContents(inside_first);
  EXPECT_EQ("foo<input value=\"bla\"><div>^bla|</div></input>bar",
            GetRange(inside_contents));
  EXPECT_TRUE(
      TextOffsetMapping::InlineContents::NextOf(inside_contents).IsNull());

  const PositionInFlatTree inside_last =
      PositionInFlatTree::LastPositionInNode(*input);
  EXPECT_TRUE(
      TextOffsetMapping::FindForwardInlineContents(inside_last).IsNull());
}

TEST_F(TextOffsetMappingTest, BackwardRangesWithTextControl) {
  // InlineContents for positions outside text control should cover the entire
  // containing block.
  const PositionInFlatTree outside_position = ToPositionInFlatTree(
      SetCaretTextToBody("foo<input value=\"bla\"><!--|-->bar"));
  const TextOffsetMapping::InlineContents outside_contents =
      TextOffsetMapping::FindBackwardInlineContents(outside_position);
  EXPECT_EQ("^foo<input value=\"bla\"><div>bla</div></input>bar|",
            GetRange(outside_contents));

  // InlineContents for positions inside text control should not escape the text
  // control in backward iteration.
  const Element* input = GetDocument().QuerySelector(AtomicString("input"));
  const PositionInFlatTree inside_last =
      PositionInFlatTree::LastPositionInNode(*input);
  const TextOffsetMapping::InlineContents inside_contents =
      TextOffsetMapping::FindBackwardInlineContents(inside_last);
  EXPECT_EQ("foo<input value=\"bla\"><div>^bla|</div></input>bar",
            GetRange(inside_contents));
  EXPECT_TRUE(
      TextOffsetMapping::InlineContents::PreviousOf(inside_contents).IsNull());

  const PositionInFlatTree inside_first =
      PositionInFlatTree::FirstPositionInNode(*input);
  EXPECT_TRUE(
      TextOffsetMapping::FindBackwardInlineContents(inside_first).IsNull());
}

// http://crbug.com/1295233
TEST_F(TextOffsetMappingTest, RangeWithBlockInInline) {
  EXPECT_EQ("<div><p>ab</p><b><p>cd</p></b>^yz|</div>",
            GetRange("<div><p>ab</p><b><p>cd</p></b>|yz</div>"));
}

// http://crbug.com/832497
TEST_F(TextOffsetMappingTest, RangeWithCollapsedWhitespace) {
  // Whitespaces after <div> is collapsed.
  EXPECT_EQ(" <div> ^<a></a>|</div>", GetRange("| <div> <a></a></div>"));
}

// http://crbug.com//832055
TEST_F(TextOffsetMappingTest, RangeWithMulticol) {
  InsertStyleElement("div { columns: 3 100px; }");
  EXPECT_EQ("<div>^<b>foo|</b></div>", GetRange("<div><b>foo|</b></div>"));
}

// http://crbug.com/832101
TEST_F(TextOffsetMappingTest, RangeWithNestedFloat) {
  InsertStyleElement("b, i { float: right; }");
  // Note: Legacy: BODY is inline, NG: BODY is block.
  EXPECT_EQ("<b>abc <i>^def|</i> ghi</b>xyz",
            GetRange("<b>abc <i>d|ef</i> ghi</b>xyz"));
}

// http://crbug.com/40711666
TEST_F(TextOffsetMappingTest, RangeWithFloatingListItem) {
  InsertStyleElement("li { float: left; margin-right: 40px; }");
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>|First</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>F|irst</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>Fir|st</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>Firs|t</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>First|</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>|Second</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>S|econd</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Se|cond</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Sec|ond</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Seco|nd</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Secon|d</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Second|</li></ul>"));
}

TEST_F(TextOffsetMappingTest, RangeWithListItem) {
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>|First</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>F|irst</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>Fir|st</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>Firs|t</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>^First|</li><li>Second</li></ul>",
            GetRange("<ul><li>First|</li><li>Second</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>|Second</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>S|econd</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Se|cond</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Sec|ond</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Seco|nd</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Secon|d</li></ul>"));
  EXPECT_EQ("<ul><li>First</li><li>^Second|</li></ul>",
            GetRange("<ul><li>First</li><li>Second|</li></ul>"));
}

TEST_F(TextOffsetMappingTest, RangeWithNestedInlineBlock) {
  InsertStyleElement("b, i { display: inline-block; }");
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("|<b>a <i>b</i> d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>|a <i>b</i> d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a| <i>b</i> d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a |<i>b</i> d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a <i>|b</i> d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a <i>b|</i> d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a <i>b</i>| d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a <i>b</i> |d</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a <i>b</i> d|</b>e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a <i>b</i> d</b>|e"));
  EXPECT_EQ("^<b>a <i>b</i> d</b>e|", GetRange("<b>a <i>b</i> d</b>e|"));
}

TEST_F(TextOffsetMappingTest, RangeWithInlineBlockBlock) {
  InsertStyleElement("b { display:inline-block; }");
  // TODO(editing-dev): We should have "^a<b>b|<p>"
  EXPECT_EQ("^a<b>b<p>c</p>d</b>e|", GetRange("|a<b>b<p>c</p>d</b>e"));
  EXPECT_EQ("^a<b>b<p>c</p>d</b>e|", GetRange("a|<b>b<p>c</p>d</b>e"));
  EXPECT_EQ("a<b>^b|<p>c</p>d</b>e", GetRange("a<b>|b<p>c</p>d</b>e"));
  EXPECT_EQ("a<b>^b|<p>c</p>d</b>e", GetRange("a<b>b|<p>c</p>d</b>e"));
  EXPECT_EQ("a<b>b<p>^c|</p>d</b>e", GetRange("a<b>b<p>|c</p>d</b>e"));
  EXPECT_EQ("a<b>b<p>^c|</p>d</b>e", GetRange("a<b>b<p>c|</p>d</b>e"));
  EXPECT_EQ("a<b>b<p>c</p>^d|</b>e", GetRange("a<b>b<p>c</p>|d</b>e"));
  EXPECT_EQ("^a<b>b<p>c</p>d</b>e|", GetRange("a<b>b<p>c</p>d</b>|e"));
  EXPECT_EQ("^a<b>b<p>c</p>d</b>e|", GetRange("a<b>b<p>c</p>d</b>e|"));
}

TEST_F(TextOffsetMappingTest, RangeWithInlineBlockBlocks) {
  InsertStyleElement("b { display:inline-block; }");
  // TODO(editing-dev): We should have "^a|"
  EXPECT_EQ("^a<b><p>b</p><p>c</p></b>d|",
            GetRange("|a<b><p>b</p><p>c</p></b>d"));
  EXPECT_EQ("^a<b><p>b</p><p>c</p></b>d|",
            GetRange("a|<b><p>b</p><p>c</p></b>d"));
  EXPECT_EQ("a<b><p>^b|</p><p>c</p></b>d",
            GetRange("a<b>|<p>b</p><p>c</p></b>d"));
  EXPECT_EQ("a<b><p>^b|</p><p>c</p></b>d",
            GetRange("a<b><p>|b</p><p>c</p></b>d"));
  EXPECT_EQ("a<b><p>^b|</p><p>c</p></b>d",
            GetRange("a<b><p>b|</p><p>c</p></b>d"));
  EXPECT_EQ("a<b><p>b</p><p>^c|</p></b>d",
            GetRange("a<b><p>b</p>|<p>c</p></b>d"));
  EXPECT_EQ("a<b><p>b</p><p>^c|</p></b>d",
            GetRange("a<b><p>b</p><p>|c</p></b>d"));
  EXPECT_EQ("a<b><p>b</p><p>^c|</p></b>d",
            GetRange("a<b><p>b</p><p>c|</p></b>d"));
  EXPECT_EQ("^a<b><p>b</p><p>c</p></b>d|",
            GetRange("a<b><p>b</p><p>c</p>|</b>d"));
  EXPECT_EQ("^a<b><p>b</p><p>c</p></b>d|",
            GetRange("a<b><p>b</p><p>c</p></b>|d"));
  EXPECT_EQ("^a<b><p>b</p><p>c</p></b>d|",
            GetRange("a<b><p>b</p><p>c</p></b>d|"));
}

// http://crbug.com/832101
TEST_F(TextOffsetMappingTest, RangeWithNestedPosition) {
  InsertStyleElement("b, i { position: fixed; }");
  EXPECT_EQ("<b>abc <i>^def|</i> ghi</b>xyz",
            GetRange("<b>abc <i>d|ef</i> ghi</b>xyz"));
}

// http://crbug.com/834623
TEST_F(TextOffsetMappingTest, RangeWithSelect1) {
  SetBodyContent("<select></select>foo");
  Element* select = GetDocument().QuerySelector(AtomicString("select"));
  const auto& expected_outer =
      "^<select>"
      "<div aria-hidden=\"true\"></div>"
      "<slot id=\"select-options\"></slot>"
      "<slot id=\"select-button\"></slot>"
      "<div popover=\"auto\" pseudo=\"picker(select)\">"
      "<slot id=\"select-popover-options\"></slot>"
      "</div>"
      "<div popover=\"manual\" pseudo=\"-internal-select-autofill-preview\">"
      "<div pseudo=\"-internal-select-autofill-preview-text\"></div>"
      "</div>"
      "</select>foo|";
  const auto& expected_inner =
      "<select>"
      "<div aria-hidden=\"true\">^|</div>"
      "<slot id=\"select-options\"></slot>"
      "<slot id=\"select-button\"></slot>"
      "<div popover=\"auto\" pseudo=\"picker(select)\">"
      "<slot id=\"select-popover-options\"></slot>"
      "</div>"
      "<div popover=\"manual\" pseudo=\"-internal-select-autofill-preview\">"
      "<div pseudo=\"-internal-select-autofill-preview-text\"></div>"
      "</div>"
      "</select>foo";
  EXPECT_EQ(expected_outer, GetRange(PositionInFlatTree::BeforeNode(*select)));
  EXPECT_EQ(expected_inner, GetRange(PositionInFlatTree(select, 0)));
  EXPECT_EQ(expected_outer, GetRange(PositionInFlatTree::AfterNode(*select)));
}

TEST_F(TextOffsetMappingTest, RangeWithSelect2) {
  SetBodyContent("<select>bar</select>foo");
  Element* select = GetDocument().QuerySelector(AtomicString("select"));
  const auto& expected_outer =
      "^<select>"
      "<div aria-hidden=\"true\"></div>"
      "<slot id=\"select-options\"></slot>"
      "<slot id=\"select-button\"></slot>"
      "<div popover=\"auto\" pseudo=\"picker(select)\">"
      "<slot id=\"select-popover-options\"></slot>"
      "</div>"
      "<div popover=\"manual\" pseudo=\"-internal-select-autofill-preview\">"
      "<div pseudo=\"-internal-select-autofill-preview-text\"></div>"
      "</div>"
      "</select>foo|";
  const auto& expected_inner =
      "<select>"
      "<div aria-hidden=\"true\">^|</div>"
      "<slot id=\"select-options\"></slot>"
      "<slot id=\"select-button\"></slot>"
      "<div popover=\"auto\" pseudo=\"picker(select)\">"
      "<slot id=\"select-popover-options\"></slot>"
      "</div>"
      "<div popover=\"manual\" pseudo=\"-internal-select-autofill-preview\">"
      "<div pseudo=\"-internal-select-autofill-preview-text\"></div>"
      "</div>"
      "</select>foo";
  EXPECT_EQ(expected_outer, GetRange(PositionInFlatTree::BeforeNode(*select)));
  EXPECT_EQ(expected_inner, GetRange(PositionInFlatTree(select, 0)));
  EXPECT_EQ(expected_outer, GetRange(PositionInFlatTree(select, 1)));
  EXPECT_EQ(expected_outer, GetRange(PositionInFlatTree::AfterNode(*select)));
}

// http://crbug.com//832350
TEST_F(TextOffsetMappingTest, RangeWithShadowDOM) {
  EXPECT_EQ("<div><slot>^abc|</slot></div>",
            GetRange("<div>"
                     "<template data-mode='open'><slot></slot></template>"
                     "|abc"
                     "</div>"));
}

// http://crbug.com/1262589
TEST_F(TextOffsetMappingTest, RangeWithSvgUse) {
  SetBodyContent(R"HTML(
<svg id="svg1"><symbol id="foo"><circle cx=1 cy=1 r=1 /></symbol></svg>
<div id="div1"><svg><use href="#foo"></svg>&#32;</div>
<div id="div2">xyz</div>
)HTML");
  const auto& div1 = *GetElementById("div1");
  const auto& div2 = *GetElementById("div2");

  const TextOffsetMapping::InlineContents& div1_contents =
      TextOffsetMapping::FindForwardInlineContents(
          PositionInFlatTree::FirstPositionInNode(div1));
  EXPECT_EQ(div1.firstChild()->GetLayoutObject(),
            div1_contents.FirstLayoutObject());
  EXPECT_EQ(div1.lastChild()->GetLayoutObject(),
            div1_contents.LastLayoutObject());

  const TextOffsetMapping::InlineContents& div2_contents =
      TextOffsetMapping::InlineContents::NextOf(div1_contents);
  EXPECT_EQ(div2.firstChild()->GetLayoutObject(),
            div2_contents.FirstLayoutObject());
  EXPECT_EQ(div2.lastChild()->GetLayoutObject(),
            div2_contents.LastLayoutObject());
}

TEST_F(TextOffsetMappingTest, GetPositionBefore) {
  EXPECT_EQ("  |012  456  ", GetPositionBefore("  012  456  ", 0));
  EXPECT_EQ("  0|12  456  ", GetPositionBefore("  012  456  ", 1));
  EXPECT_EQ("  01|2  456  ", GetPositionBefore("  012  456  ", 2));
  EXPECT_EQ("  012|  456  ", GetPositionBefore("  012  456  ", 3));
  EXPECT_EQ("  012  |456  ", GetPositionBefore("  012  456  ", 4));
  EXPECT_EQ("  012  4|56  ", GetPositionBefore("  012  456  ", 5));
  EXPECT_EQ("  012  45|6  ", GetPositionBefore("  012  456  ", 6));
  EXPECT_EQ("  012  456|  ", GetPositionBefore("  012  456  ", 7));
  // We hit DCHECK for offset 8, because we walk on "012 456".
}

TEST_F(TextOffsetMappingTest, GetPositionAfter) {
  EXPECT_EQ("  0|12  456  ", GetPositionAfter("  012  456  ", 0));
  EXPECT_EQ("  01|2  456  ", GetPositionAfter("  012  456  ", 1));
  EXPECT_EQ("  012|  456  ", GetPositionAfter("  012  456  ", 2));
  EXPECT_EQ("  012 | 456  ", GetPositionAfter("  012  456  ", 3));
  EXPECT_EQ("  012  4|56  ", GetPositionAfter("  012  456  ", 4));
  EXPECT_EQ("  012  45|6  ", GetPositionAfter("  012  456  ", 5));
  EXPECT_EQ("  012  456|  ", GetPositionAfter("  012  456  ", 6));
  EXPECT_EQ("  012  456  |", GetPositionAfter("  012  456  ", 7));
  // We hit DCHECK for offset 8, because we walk on "012 456".
}

// https://crbug.com/903723
TEST_F(TextOffsetMappingTest, InlineContentsWithDocumentBoundary) {
  InsertStyleElement("*{position:fixed}");
  SetBodyContent("");
  const PositionInFlatTree position =
      PositionInFlatTree::FirstPositionInNode(*GetDocument().body());
  const TextOffsetMapping::InlineContents inline_contents =
      TextOffsetMapping::FindForwardInlineContents(position);
  EXPECT_TRUE(inline_contents.IsNotNull());
  // Should not crash when previous/next iteration reaches document boundary.
  EXPECT_TRUE(
      TextOffsetMapping::InlineContents::PreviousOf(inline_contents).IsNull());
  EXPECT_TRUE(
      TextOffsetMapping::InlineContents::NextOf(inline_contents).IsNull());
}

// https://crbug.com/1224206
TEST_F(TextOffsetMappingTest, ComputeTextOffsetWithBrokenImage) {
  SetBodyContent("A<img alt='X'>B<div>C</div>D");
  Element* img = GetDocument().QuerySelector(AtomicString("img"));
  To<HTMLImageElement>(img)->EnsureCollapsedOrFallbackContent();
  UpdateAllLifecyclePhasesForTest();
  ShadowRoot* shadow = img->UserAgentShadowRoot();
  DCHECK(shadow);
  const Element* alt_img =
      shadow->getElementById(AtomicString("alttext-image"));
  DCHECK(alt_img);

  const PositionInFlatTree position = PositionInFlatTree::BeforeNode(*alt_img);
  for (const TextOffsetMapping::InlineContents& inline_contents :
       {TextOffsetMapping::FindForwardInlineContents(position),
        TextOffsetMapping::FindBackwardInlineContents(position)}) {
    const TextOffsetMapping mapping(inline_contents);
    const String text = mapping.GetText();
    const unsigned offset = mapping.ComputeTextOffset(position);
    EXPECT_LE(offset, text.length());
    EXPECT_EQ("A,B", text);
    EXPECT_EQ(2u, offset);
  }
}

}  // namespace blink

"""

```