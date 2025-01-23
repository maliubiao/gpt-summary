Response:
The user wants to understand the functionality of the provided C++ code file, which is part of the Chromium Blink engine. This file appears to contain unit tests related to the concept of "visible units" and "lines" within the context of text editing.

Here's a breakdown of the thought process to analyze the code and generate the response:

1. **Identify the Core Purpose:** The file name `visible_units_line_test.cc` strongly suggests that the tests focus on how the engine defines and handles the start and end of lines, considering factors like word wrapping, bidirectional text, and different HTML elements.

2. **Analyze the Test Structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` function represents a specific scenario being tested. The names of these functions (`EndOfLine...`, `StartOfLine...`, `InSameLine...`) clearly indicate what aspect of line handling is being verified.

3. **Examine the Test Assertions:**  The core of each test lies in the `EXPECT_EQ` calls. These compare the *expected* outcome (a string representing the HTML with a caret `|` at the expected position) with the *actual* outcome of functions like `TestEndOfLine`, `TestStartOfLine`, and `InSameLine`.

4. **Infer Functionality from Test Names and Assertions:**
    * **`EndOfLine` Tests:** These tests verify the correct identification of the end of a visible line, considering soft line wraps due to CSS properties like `width` and `word-break`, and the presence of `bdo` (bidirectional override) elements.
    * **`StartOfLine` Tests:**  Similar to `EndOfLine`, but focusing on the beginning of a visible line.
    * **`LogicalEndOfLine` Tests:**  This seems to test a "logical" end of the line, potentially disregarding some visual line breaks, especially in editable content.
    * **`InSameLine` Tests:**  These tests check if two positions within the document are considered to be on the same visible line, taking into account factors like `contenteditable` boundaries, zero-width spaces, and inline-block elements.

5. **Identify Relationships to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The tests directly manipulate and examine HTML structures (paragraphs, divs, spans, bdo, br). The caret position is represented within HTML strings.
    * **CSS:** CSS properties like `width`, `word-break`, `white-space`, `direction`, `display`, `text-overflow` are used to control the layout and line breaking behavior being tested. The `LoadAhem()` function suggests the use of a specific font for predictable layout.
    * **JavaScript:** While this specific file doesn't contain JavaScript, the underlying functionality being tested is crucial for JavaScript-based text editing and manipulation in web browsers. JavaScript APIs would rely on these core line-breaking concepts.

6. **Look for Logic and Assumptions:** The tests implicitly assume that the `TestEndOfLine`, `TestStartOfLine`, and `InSameLine` helper functions correctly simulate user interactions and return the expected caret positions or boolean values. The different test cases explore various combinations of HTML structure and CSS styling.

7. **Consider User/Programming Errors:** Incorrectly applying CSS properties (e.g., setting a very small `width` with `white-space: nowrap`) can lead to unexpected line breaking behavior and make it harder for users to predict where lines will break. In programming, misunderstanding how the browser defines a "line" can lead to errors when manipulating text ranges or implementing text editors.

8. **Deduce User Operations (Debugging Clues):**  To reach the code being tested, a user would likely be interacting with a web page containing text and potentially editable regions. The specific scenarios tested (bidirectional text, soft line breaks, inline-block elements) suggest that issues in these areas could lead to bugs related to cursor movement, text selection, and line navigation.

9. **Address the "Part 2" Request and Summarize:** The request explicitly asks for a summary of the file's functionality. This involves synthesizing the observations from the previous steps into a concise description.

**Self-Correction/Refinement During the Thought Process:**

* **Initial thought:** Maybe the tests are directly manipulating the layout engine.
* **Correction:**  The tests seem to be higher-level, focusing on the *observable* behavior of line breaking rather than internal layout details. The use of helper functions like `TestEndOfLine` abstract away the low-level details.
* **Initial thought:** The tests are only about visual lines.
* **Refinement:** The presence of `LogicalEndOfLine` suggests that there's a distinction between visual and logical line breaks, especially in editable content.
* **Initial thought:**  JavaScript is directly involved in these tests.
* **Correction:** While the *functionality* is used by JavaScript, this specific C++ file contains the underlying unit tests for the Blink engine's core logic.

By following these steps, we can arrive at a comprehensive understanding of the `visible_units_line_test.cc` file and generate the detailed explanation requested by the user.
这是 blink/renderer/core/editing/visible_units_line_test.cc 文件的第二部分，延续了第一部分的测试用例。它主要的功能是 **测试在 Blink 渲染引擎中，对于“行”的概念在各种复杂情况下的定义和识别，特别是针对文本编辑相关的操作。**  这些测试覆盖了如何判断一个“行”的开始和结束位置，以及判断两个位置是否在同一“行”上。

**归纳一下它的功能：**

这部分测试用例主要集中在以下几个方面：

* **软换行（Soft Line Wrap）的场景：**  测试在由于 CSS 样式（例如 `width` 和 `word-break`）导致的软换行情况下，`EndOfLine` 和 `LogicalEndOfLine` 函数的正确行为。`LogicalEndOfLine` 似乎更关注内容的逻辑结构，而 `EndOfLine` 更贴近视觉上的行尾。
* **`InSameLine` 函数的测试：**  测试在各种复杂情况下（例如空的可编辑 `div`，混合编辑性，生成的零宽度空格，软换行，实际的零宽度空格，`inline-block` 元素）判断两个文本位置是否在同一可见行上的能力。
* **处理空的 `<br>` 标签：** 测试在包含多个连续 `<br>` 标签造成空行的情况下，`StartOfLine` 函数的正确行为。
* **双向文本（Bidi）的处理：**  测试在包含不同 `dir` 属性的元素（例如 `<bdo>`）时，`StartOfLine` 和 `EndOfLine` 函数如何正确识别行的开始和结束。
* **相对定位元素的影响：** 测试具有相对定位的元素是否会影响 `StartOfLine` 的判断。
* **`text-overflow: ellipsis` 的场景：** 测试当文本溢出并显示省略号时，`StartOfLine` 和 `EndOfLine` 如何处理。
* **`text-overflow: scroll` 和 RTL 的结合：** 测试特定情况下 `StartOfLine` 是否会崩溃。
* **更复杂的双向文本重排序场景：** 测试在更复杂的双向文本结构中，`InSameLine` 函数是否能够正常工作。

**与 JavaScript, HTML, CSS 的功能关系：**

这个文件直接测试的是 Blink 引擎内部 C++ 代码的逻辑，这些逻辑是实现浏览器文本编辑功能的基础。它与 JavaScript, HTML, CSS 的关系体现在：

* **HTML 结构：** 测试用例中使用的输入和期望输出都是 HTML 片段，展示了各种 HTML 元素（例如 `<p>`, `<div>`, `<span>`, `<bdo>`, `<br>`) 对行尾和行开始判断的影响。
    * **举例：** `<p>a|b <b>cd</b> <b>ef</b></p>`  这个 HTML 片段测试了在包含 `<b>` 标签的情况下，光标位于 `b` 后面时，`EndOfLine` 函数是否能正确找到行尾。
* **CSS 样式：**  测试用例通过 `InsertStyleElement` 函数动态插入 CSS 样式，来模拟不同的布局和渲染情况，例如 `width`, `word-break`, `white-space`, `direction`, `display`, `text-overflow` 等。这些 CSS 属性直接影响文本的换行和显示方式。
    * **举例：**  `InsertStyleElement("div { font: 10px/1 Ahem; width: 3ch; word-break: break-all; }");` 这段 CSS 代码设置了 `div` 的宽度和断词方式，用于测试软换行的情况。
* **JavaScript 交互：**  虽然这个文件本身不是 JavaScript 代码，但 Blink 引擎的这些底层逻辑会被 JavaScript API 所使用。例如，当 JavaScript 代码需要获取光标所在行的范围、移动光标到行首或行尾时，就需要依赖这些 C++ 函数的正确实现。
    * **概念举例：** JavaScript 的 `Selection` API 和 `Range` API 的操作，例如 `getRangeAt()`, `collapse()`, `setStart()` 和 `setEnd()` 等，其底层的行和位置的计算就依赖于这里测试的逻辑。

**逻辑推理、假设输入与输出：**

大多数测试用例都清晰地展示了假设输入和期望输出。

* **假设输入：** 一个包含特定 HTML 结构和 CSS 样式的字符串，其中 `|` 表示光标的起始位置。
* **输出：**  期望的 HTML 字符串，其中 `|` 表示 `EndOfLine` 或 `StartOfLine` 函数计算出的行尾或行首位置。对于 `InSameLine` 函数，输出是 `true` 或 `false`。

**用户或编程常见的使用错误：**

* **错误理解软换行的边界：** 用户可能会认为在空格处一定会换行，但 CSS 的 `word-break` 属性可能会改变这种行为。程序员在处理文本时，如果没有考虑到软换行的可能性，可能会导致光标移动或文本选择的错误。
    * **举例：** 在 `EndOfLineWithSoftLineWrap3` 测试中，不同的 `width` 和 `word-break` 设置会导致不同的换行结果。用户可能期望光标在空格前，但实际可能在空格后。
* **忽略双向文本的影响：** 在处理包含阿拉伯语或希伯来语等 RTL 文本的页面时，如果没有考虑到双向文本的特性，可能会导致光标移动和文本选择的混乱。
    * **举例：** 多个测试用例涉及到 `<bdo>` 标签和 `dir` 属性，说明了双向文本对行边界判断的重要性。用户可能会觉得光标应该向左移动，但由于 RTL 的影响，实际可能需要向右移动到逻辑上的行首。
* **不理解 `contenteditable` 的边界：** 可编辑区域会形成独立的编辑上下文。用户或程序员可能会错误地认为可以跨越 `contenteditable` 边界进行行操作，但 `InSameLine` 的测试用例表明，编辑性边界会影响行的判断。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **网页包含文本内容，可能包含各种 HTML 元素和 CSS 样式，也可能包含可编辑区域。**
3. **用户与文本进行交互，例如：**
    * **使用键盘上的 Home 或 End 键尝试将光标移动到行首或行尾。**  这会触发 Blink 引擎调用相应的逻辑来计算行首和行尾。
    * **使用方向键左右移动光标。**  在软换行、双向文本等复杂情况下，引擎需要正确判断下一个或上一个可见的位置。
    * **进行文本选择操作（拖拽鼠标或按住 Shift 键并使用方向键）。**  引擎需要确定选区的起始和结束位置，这涉及到判断哪些位置在同一行。
    * **在可编辑区域输入或删除文本。** 引擎需要维护光标的正确位置，并可能触发重新布局和换行。
4. **在这些用户操作的过程中，如果 Blink 引擎在计算行首、行尾或判断两个位置是否在同一行时出现错误，就可能触发这个测试文件中正在测试的边界情况。**

**调试线索：** 如果用户报告了光标移动、文本选择或行操作相关的 bug，开发者可能会：

* **重现用户的操作步骤。**
* **检查网页的 HTML 结构和 CSS 样式，特别关注可能影响布局和换行的属性（如 `width`, `word-break`, `white-space`, `direction`, `display`）。**
* **如果涉及到可编辑区域，检查 `contenteditable` 属性的使用。**
* **考虑文本内容是否包含特殊字符，例如零宽度空格或双向文本。**
* **在 Blink 引擎的源代码中，设置断点到 `VisibleUnits::StartOfLine`, `VisibleUnits::EndOfLine` 或 `VisibleUnits::InSameLine` 等函数，查看在特定场景下的计算过程。**
* **参考这个测试文件中的测试用例，看是否已经覆盖了类似的场景，或者需要添加新的测试用例来覆盖这个 bug。**

总而言之，`visible_units_line_test.cc` 的第二部分深入测试了 Blink 引擎在处理各种复杂的文本布局和编辑场景时，对“行”的理解和操作的正确性，这对于保证用户在浏览器中的文本编辑体验至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/visible_units_line_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
> <b>ef|</b></p>",
            TestEndOfLine("<p>a|b <b>cd</b> <b>ef</b></p>"));
  EXPECT_EQ(
      "<p><bdo dir=\"rtl\">ab <b>cd</b> <b>ef|</b></bdo></p>",
      TestEndOfLine("<p><bdo dir=\"rtl\">a|b <b>cd</b> <b>ef</b></bdo></p>"));
  EXPECT_EQ("<p dir=\"rtl\">ab <b>cd</b> <b>ef|</b></p>",
            TestEndOfLine("<p dir=\"rtl\">a|b <b>cd</b> <b>ef</b></p>"));
  EXPECT_EQ(
      "<p dir=\"rtl\"><bdo dir=\"rtl\">ab <b>cd</b> <b>ef|</b></bdo></p>",
      TestEndOfLine(
          "<p dir=\"rtl\"><bdo dir=\"rtl\">a|b <b>cd</b> <b>ef</b></bdo></p>"));
}

TEST_F(VisibleUnitsLineTest, EndOfLineWithSoftLineWrap3) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "font: 10px/1 Ahem; width: 3ch; word-break: break-all; }");

  EXPECT_EQ("<div>abc|def</div>", TestEndOfLine("<div>|abcdef</div>"));
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">abc|def</bdo></div>",
      TestEndOfLine("<div dir=\"rtl\"><bdo dir=\"rtl\">|abcdef</bdo></div>"));

  // Note: Both legacy and NG layout don't have text boxes for spaces cause
  // soft line wrap.
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestEndOfLine("<div>|abc def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestEndOfLine("<div>ab|c def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestEndOfLine("<div>abc| def ghi</div>"));
  EXPECT_EQ("<div>abc def| ghi</div>",
            TestEndOfLine("<div>abc |def ghi</div>"));

  EXPECT_EQ("<div dir=\"rtl\"><bdo dir=\"rtl\">abc| def ghi</bdo></div>",
            TestEndOfLine(
                "<div dir=\"rtl\"><bdo dir=\"rtl\">|abc def ghi</bdo></div>"));
  EXPECT_EQ("<div dir=\"rtl\"><bdo dir=\"rtl\">abc| def ghi</bdo></div>",
            TestEndOfLine(
                "<div dir=\"rtl\"><bdo dir=\"rtl\">ab|c def ghi</bdo></div>"));
  EXPECT_EQ("<div dir=\"rtl\"><bdo dir=\"rtl\">abc| def ghi</bdo></div>",
            TestEndOfLine(
                "<div dir=\"rtl\"><bdo dir=\"rtl\">abc| def ghi</bdo></div>"));
  EXPECT_EQ("<div dir=\"rtl\"><bdo dir=\"rtl\">abc def| ghi</bdo></div>",
            TestEndOfLine(
                "<div dir=\"rtl\"><bdo dir=\"rtl\">abc |def ghi</bdo></div>"));

  // On content editable, caret is after a space.
  // Note: Legacy layout has text boxes at end of line for space cause soft line
  // wrap for editable text, e.g.
  //   LayoutText {#text} at (10,9) size 18x32
  //     text run at (10,9) width 18: "abc"
  //     text run at (28,9) width 0: " "
  //     text run at (10,19) width 18: "def"
  //     text run at (28,19) width 0: " "
  //     text run at (10,29) width 18: "ghi"
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestEndOfLine("<div contenteditable>|abc def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestEndOfLine("<div contenteditable>ab|c def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestEndOfLine("<div contenteditable>abc| def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc def |ghi</div>",
            TestEndOfLine("<div contenteditable>abc |def ghi</div>"));
}

TEST_F(VisibleUnitsLineTest, EndOfLineWithSoftLineWrap4) {
  LoadAhem();
  InsertStyleElement("div { font: 10px/1 Ahem; width: 4ch; }");

  EXPECT_EQ("<div>abc| def ghi</div>",
            TestEndOfLine("<div>|abc def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestEndOfLine("<div>ab|c def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestEndOfLine("<div>abc| def ghi</div>"));
  EXPECT_EQ("<div>abc def| ghi</div>",
            TestEndOfLine("<div>abc |def ghi</div>"));

  // On content editable, caret is after a space.
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestEndOfLine("<div contenteditable>|abc def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestEndOfLine("<div contenteditable>ab|c def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestEndOfLine("<div contenteditable>abc| def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc def |ghi</div>",
            TestEndOfLine("<div contenteditable>abc |def ghi</div>"));
}

// http://crbug.com/1169583
TEST_F(VisibleUnitsLineTest, EndOfLineWithWhiteSpacePre) {
  LoadAhem();
  InsertStyleElement("p { font: 10px/1 Ahem; white-space: pre; }");

  EXPECT_EQ("<p dir=\"ltr\"><bdo dir=\"ltr\">ABC DEF|\nGHI JKL</bdo></p>",
            TestEndOfLine(
                "<p dir=\"ltr\"><bdo dir=\"ltr\">ABC| DEF\nGHI JKL</bdo></p>"))
      << "LTR LTR";
  EXPECT_EQ("<p dir=\"ltr\"><bdo dir=\"rtl\">ABC DEF|\nGHI JKL</bdo></p>",
            TestEndOfLine(
                "<p dir=\"ltr\"><bdo dir=\"rtl\">ABC| DEF\nGHI JKL</bdo></p>"))
      << "LTR RTL";
  EXPECT_EQ("<p dir=\"rtl\"><bdo dir=\"ltr\">ABC DEF|\nGHI JKL</bdo></p>",
            TestEndOfLine(
                "<p dir=\"rtl\"><bdo dir=\"ltr\">ABC| DEF\nGHI JKL</bdo></p>"))
      << "RTL LTR";
  EXPECT_EQ("<p dir=\"rtl\"><bdo dir=\"rtl\">ABC DEF|\nGHI JKL</bdo></p>",
            TestEndOfLine(
                "<p dir=\"rtl\"><bdo dir=\"rtl\">ABC| DEF\nGHI JKL</bdo></p>"))
      << "RTL RTL";
}

TEST_F(VisibleUnitsLineTest, LogicalEndOfLineWithSoftLineWrap3) {
  LoadAhem();
  InsertStyleElement(
      "div {"
      "font: 10px/1 Ahem; width: 3ch; word-break: break-all; }");

  EXPECT_EQ("<div>abc|def</div>", TestLogicalEndOfLine("<div>|abcdef</div>"));
  EXPECT_EQ("<div dir=\"rtl\"><bdo dir=\"rtl\">abc|def</bdo></div>",
            TestLogicalEndOfLine(
                "<div dir=\"rtl\"><bdo dir=\"rtl\">|abcdef</bdo></div>"));

  EXPECT_EQ("<div>abc| def ghi</div>",
            TestLogicalEndOfLine("<div>|abc def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestLogicalEndOfLine("<div>ab|c def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestLogicalEndOfLine("<div>abc| def ghi</div>"));
  EXPECT_EQ("<div>abc def| ghi</div>",
            TestLogicalEndOfLine("<div>abc |def ghi</div>"));

  // On content editable, caret is after a space.
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>|abc def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>ab|c def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>abc| def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc def |ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>abc |def ghi</div>"));
}

TEST_F(VisibleUnitsLineTest, LogicalEndOfLineWithSoftLineWrap4) {
  LoadAhem();
  InsertStyleElement("div { font: 10px/1 Ahem; width: 4ch; }");

  EXPECT_EQ("<div>abc| def ghi</div>",
            TestLogicalEndOfLine("<div>|abc def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestLogicalEndOfLine("<div>ab|c def ghi</div>"));
  EXPECT_EQ("<div>abc| def ghi</div>",
            TestLogicalEndOfLine("<div>abc| def ghi</div>"));
  EXPECT_EQ("<div>abc def| ghi</div>",
            TestLogicalEndOfLine("<div>abc |def ghi</div>"));

  // On content editable, caret is after a space.
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>|abc def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>ab|c def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc |def ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>abc| def ghi</div>"));
  EXPECT_EQ("<div contenteditable>abc def |ghi</div>",
            TestLogicalEndOfLine("<div contenteditable>abc |def ghi</div>"));
}

TEST_F(VisibleUnitsLineTest, InSameLineSkippingEmptyEditableDiv) {
  // This test records the InSameLine() results in
  // editing/selection/skip-over-contenteditable.html
  SetBodyContent(
      "<p id=foo>foo</p>"
      "<div contenteditable></div>"
      "<p id=bar>bar</p>");
  const Node* const foo = GetElementById("foo")->firstChild();
  const Node* const bar = GetElementById("bar")->firstChild();

  EXPECT_TRUE(InSameLine(
      PositionWithAffinity(Position(foo, 3), TextAffinity::kDownstream),
      PositionWithAffinity(Position(foo, 3), TextAffinity::kUpstream)));
  EXPECT_FALSE(InSameLine(
      PositionWithAffinity(Position(bar, 0), TextAffinity::kDownstream),
      PositionWithAffinity(Position(foo, 3), TextAffinity::kDownstream)));
  EXPECT_TRUE(InSameLine(
      PositionWithAffinity(Position(bar, 3), TextAffinity::kDownstream),
      PositionWithAffinity(Position(bar, 3), TextAffinity::kUpstream)));
  EXPECT_FALSE(InSameLine(
      PositionWithAffinity(Position(foo, 0), TextAffinity::kDownstream),
      PositionWithAffinity(Position(bar, 0), TextAffinity::kDownstream)));
}

TEST_F(VisibleUnitsLineTest, InSameLineWithMixedEditability) {
  SelectionInDOMTree selection =
      SetSelectionTextToBody("<span contenteditable>f^oo</span>b|ar");

  PositionWithAffinity position1(selection.Anchor());
  PositionWithAffinity position2(selection.Focus());
  // "Same line" is restricted by editability boundaries.
  EXPECT_FALSE(InSameLine(position1, position2));
}

TEST_F(VisibleUnitsLineTest, InSameLineWithGeneratedZeroWidthSpace) {
  LoadAhem();
  InsertStyleElement(
      "p { font: 10px/1 Ahem; }"
      "p { width: 4ch; white-space: pre-wrap;");
  // We have ZWS before "abc" due by "pre-wrap".
  const Position& after_zws = SetCaretTextToBody("<p id=t>    |abcd</p>");
  const PositionWithAffinity after_zws_down =
      PositionWithAffinity(after_zws, TextAffinity::kDownstream);
  const PositionWithAffinity after_zws_up =
      PositionWithAffinity(after_zws, TextAffinity::kUpstream);

  EXPECT_EQ(
      PositionWithAffinity(Position(*GetElementById("t")->firstChild(), 8),
                           TextAffinity::kUpstream),
      EndOfLine(after_zws_down));
  EXPECT_EQ(after_zws_up, EndOfLine(after_zws_up));
  EXPECT_FALSE(InSameLine(after_zws_up, after_zws_down));
}

// http://crbug.com/1183269
TEST_F(VisibleUnitsLineTest, InSameLineWithSoftLineWrap) {
  LoadAhem();
  InsertStyleElement(
      "p { font: 10px/1 Ahem; }"
      "p { width: 3ch; }");
  // Note: "contenteditable" adds
  //    line-break: after-white-space;
  //    overflow-wrap: break-word;
  const SelectionInDOMTree& selection =
      SetSelectionTextToBody("<p contenteditable id=t>abc |xyz</p>");
  EXPECT_FALSE(InSameLine(
      PositionWithAffinity(selection.Anchor(), TextAffinity::kUpstream),
      PositionWithAffinity(selection.Anchor(), TextAffinity::kDownstream)));
}

TEST_F(VisibleUnitsLineTest, InSameLineWithZeroWidthSpace) {
  LoadAhem();
  InsertStyleElement(
      "p { font: 10px/1 Ahem; }"
      "p { width: 4ch; }");
  const SelectionInDOMTree& selection =
      SetSelectionTextToBody("<p id=t>abcd^\u200B|wxyz</p>");

  const Position& after_zws = selection.Focus();
  const PositionWithAffinity after_zws_down =
      PositionWithAffinity(after_zws, TextAffinity::kDownstream);
  const PositionWithAffinity after_zws_up =
      PositionWithAffinity(after_zws, TextAffinity::kUpstream);

  const Position& before_zws = selection.Anchor();
  const PositionWithAffinity before_zws_down =
      PositionWithAffinity(before_zws, TextAffinity::kDownstream);
  const PositionWithAffinity before_zws_up =
      PositionWithAffinity(before_zws, TextAffinity::kUpstream);

  EXPECT_EQ(
      PositionWithAffinity(Position(*GetElementById("t")->firstChild(), 9),
                           TextAffinity::kUpstream),
      EndOfLine(after_zws_down));
  EXPECT_EQ(after_zws_up, EndOfLine(after_zws_up));
  EXPECT_FALSE(InSameLine(after_zws_up, after_zws_down));

  EXPECT_EQ(after_zws_up, EndOfLine(before_zws_down));
  EXPECT_EQ(after_zws_up, EndOfLine(before_zws_up));
  EXPECT_TRUE(InSameLine(before_zws_up, before_zws_down));
}

// https://issues.chromium.org/issues/41497469
TEST_F(VisibleUnitsLineTest, InSameLineWithInlineBlock) {
  SetBodyContent(
      "<span id=one>start</span>"
      "<span id=two style='display: inline-block;'>test</span>"
      "<span id=three>end</span>");

  const PositionWithAffinity position =
      PositionWithAffinity(Position(*GetElementById("two")->firstChild(), 0),
                           TextAffinity::kUpstream);
  EXPECT_TRUE(InSameLine(
      position,
      PositionWithAffinity(Position(*GetElementById("one")->firstChild(), 0),
                           TextAffinity::kUpstream)));
  EXPECT_TRUE(InSameLine(
      position,
      PositionWithAffinity(Position(*GetElementById("three")->firstChild(), 0),
                           TextAffinity::kUpstream)));
}

// http://crbug.com/1358235
TEST_F(VisibleUnitsLineTest, StartOfLineBeforeEmptyLine) {
  LoadAhem();
  InsertStyleElement("p { font: 30px/3 Ahem; }");

  EXPECT_EQ("<p dir=\"ltr\">abc<br>|<br>xyz<br></p>",
            TestStartOfLine("<p dir=\"ltr\">abc<br>|<br>xyz<br></p>"));
  EXPECT_EQ("<p dir=\"ltr\">abc<br><br>|<br>xyz<br></p>",
            TestStartOfLine("<p dir=\"ltr\">abc<br><br>|<br>xyz<br></p>"));
  EXPECT_EQ("<p dir=\"ltr\">abc<br>|<br><br>xyz<br></p>",
            TestStartOfLine("<p dir=\"ltr\">abc<br>|<br><br>xyz<br></p>"));

  EXPECT_EQ("<p dir=\"rtl\">abc<br>|<br>xyz<br></p>",
            TestStartOfLine("<p dir=\"rtl\">abc<br>|<br>xyz<br></p>"));
  EXPECT_EQ("<p dir=\"rtl\">abc<br>|<br><br>xyz<br></p>",
            TestStartOfLine("<p dir=\"rtl\">abc<br>|<br><br>xyz<br></p>"));
  EXPECT_EQ("<p dir=\"rtl\">abc<br><br>|<br>xyz<br></p>",
            TestStartOfLine("<p dir=\"rtl\">abc<br><br>|<br>xyz<br></p>"));
}

TEST_F(VisibleUnitsLineTest, StartOfLineWithBidi) {
  LoadAhem();
  InsertStyleElement("p { font: 30px/3 Ahem; }");

  EXPECT_EQ(
      "<p dir=\"ltr\"><bdo dir=\"ltr\">|abc xyz</bdo></p>",
      TestStartOfLine("<p dir=\"ltr\"><bdo dir=\"ltr\">abc |xyz</bdo></p>"))
      << "LTR LTR";
  EXPECT_EQ(
      "<p dir=\"ltr\"><bdo dir=\"rtl\">|abc xyz</bdo></p>",
      TestStartOfLine("<p dir=\"ltr\"><bdo dir=\"rtl\">abc |xyz</bdo></p>"))
      << "LTR RTL";
  EXPECT_EQ(
      "<p dir=\"rtl\"><bdo dir=\"ltr\">|abc xyz</bdo></p>",
      TestStartOfLine("<p dir=\"rtl\"><bdo dir=\"ltr\">abc |xyz</bdo></p>"))
      << "RTL LTR";
  EXPECT_EQ(
      "<p dir=\"rtl\"><bdo dir=\"rtl\">|abc xyz</bdo></p>",
      TestStartOfLine("<p dir=\"rtl\"><bdo dir=\"rtl\">abc |xyz</bdo></p>"))
      << "RTL RTL";
}

TEST_F(VisibleUnitsLineTest, StartOfLineWithPositionRelative) {
  LoadAhem();
  InsertStyleElement(
      "b { position:relative; left: -100px; }"
      "p { font: 30px/3 Ahem; }");

  EXPECT_EQ("<p><b>|abc</b> xyz</p>", TestStartOfLine("<p><b>abc</b> |xyz</p>"))
      << "LTR-LTR";
  EXPECT_EQ("<p dir=\"rtl\"><b>|abc</b> xyz</p>",
            TestStartOfLine("<p dir=\"rtl\"><b>abc</b> |xyz</p>"))
      << "RTL-LTR";
  EXPECT_EQ("<p><bdo dir=\"rtl\"><b>|abc</b> xyz</bdo></p>",
            TestStartOfLine("<p><bdo dir=\"rtl\"><b>abc</b> |xyz</bdo></p>"))
      << "LTR-RTL";
  EXPECT_EQ("<p dir=\"rtl\"><bdo dir=\"rtl\"><b>|abc</b> xyz</bdo></p>",
            TestStartOfLine(
                "<p dir=\"rtl\"><bdo  dir=\"rtl\"><b>abc</b> |xyz</bdo></p>"))
      << "RTL-RTL";
}

// https://crbug.com/947462
TEST_F(VisibleUnitsLineTest, TextOverflowEllipsis1) {
  LoadAhem();
  InsertStyleElement(R"HTML(
    div {
      width: 40px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font: 10px/10px Ahem;
    })HTML");
  SetBodyContent("<div>foo foo</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Node* text = div->firstChild();
  EXPECT_EQ(
      Position(text, 0),
      StartOfLine(CreateVisiblePositionInDOMTree(*text, 6)).DeepEquivalent());
  EXPECT_EQ(
      Position(text, 7),
      EndOfLine(CreateVisiblePositionInDOMTree(*text, 6)).DeepEquivalent());
}

// https://crbug.com/1177753
TEST_F(VisibleUnitsLineTest, TextOverflowEllipsis2) {
  InsertStyleElement(R"HTML(
    div {
      overflow: scroll;
      text-overflow: ellipsis;
      white-space: nowrap;
      width: 50px;
      direction: rtl;
    }
    span {
      display: inline-block;
      width: 75px; /* Something bigger than 50px */
    })HTML");
  SetBodyContent("<div><span>x</span>&#x20;</div>");
  Element* span = GetDocument().QuerySelector(AtomicString("span"));

  // Should not crash
  const PositionWithAffinity& start_of_line =
      StartOfLine(PositionWithAffinity(Position(span, 1)));

  EXPECT_EQ(PositionWithAffinity(Position::BeforeNode(*span)), start_of_line);
}

// https://crbug.com/1181451
TEST_F(VisibleUnitsLineTest, InSameLineWithBidiReordering) {
  InsertStyleElement("div { display: inline-block; width: 75% }");
  SetBodyContent(
      "<span dir='rtl'>"
      "<span dir='ltr'>a&#x20;</span>&#x20;"
      "<div></div><div></div>"
      "</span>");
  Element* span = GetDocument().QuerySelector(AtomicString("span > span"));
  PositionWithAffinity p1(Position(span->nextSibling(), 0));
  PositionWithAffinity p2(Position(span->firstChild(), 2));

  // Should not crash.
  EXPECT_EQ(true, InSameLine(p1, p2));
}

}  // namespace blink
```