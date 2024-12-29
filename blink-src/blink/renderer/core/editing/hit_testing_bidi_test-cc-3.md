Response:
The user wants to understand the functionality of the `hit_testing_bidi_test.cc` file in the Chromium Blink engine. This is part 4 of a 6-part analysis. The request asks for:

1. **Functionality:** What does the file do?
2. **Relationship to web technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and examples:**  If there's logic, provide input and output examples.
4. **Common errors:** What mistakes might users or programmers make?
5. **User interaction:** How does a user's action lead to this code being executed (debugging context)?
6. **Summary of functionality (for this part):**  Based on the provided code snippet.

Let's break down the provided code:

* **`TEST_F(HitTestingBidiTest, ...)`:**  These are test cases within a C++ testing framework. The `HitTestingBidiTest` class likely sets up the environment for testing bidirectional text hit testing.
* **`LoadAhem()`:** This function likely loads a specific font (Ahem) that helps with predictable text rendering for testing.
* **`InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}")`:** This inserts a CSS style rule that affects `div` elements. It sets the font and width, crucial for layout and hit testing.
* **`SetBodyContent(...)`:** This sets the HTML content of the page's `body`. The content includes `div` elements with `dir` attributes (for directionality - left-to-right or right-to-left) and `<bdo>` elements (for bidirectional override).
* **`GetDocument().QuerySelector(AtomicString("div"))`:** This uses a CSS selector to find the `div` element in the document. This is very similar to JavaScript's `document.querySelector()`.
* **`div->OffsetLeft()`, `div->OffsetTop()`:** These get the position of the `div` element relative to its offset parent. This is analogous to JavaScript's `element.offsetLeft` and `element.offsetTop`.
* **`int x = ...`, `int y = ...`:** These calculate specific coordinates within the `div` element.
* **`GetDocument().caretRangeFromPoint(x, y)`:** This is the core functionality being tested. It takes coordinates and determines the caret position (insertion point) in the text at that point.
* **`EXPECT_TRUE(result.IsNotNull())`, `EXPECT_TRUE(result.IsCollapsed())`:** These are assertions in the testing framework. They check if the returned caret range is valid and if it's a single point (not a selection).
* **`EXPECT_EQ(..., GetCaretTextFromBody(result.StartPosition()))`:** This compares the expected HTML string with a caret indicator (`|`) to the actual position returned by `caretRangeFromPoint`. The `GetCaretTextFromBody` function likely helps to format the HTML for easy comparison.

Based on these observations, the file focuses on testing the accuracy of hit testing in scenarios involving bidirectional text. It simulates mouse clicks (or touch events) at specific coordinates and verifies that the correct caret position is returned, considering the complexities introduced by right-to-left and left-to-right text mixing.

**Functionality Summary for this Part:** This part of the `hit_testing_bidi_test.cc` file contains a series of test cases specifically designed to verify the correctness of caret positioning (hit testing) within HTML content that includes nested bidirectional elements (`<bdo>`). These tests cover various scenarios with different text directions (LTR and RTL), nested levels, and click positions relative to the edges of text runs. The tests check if clicking at specific coordinates results in the caret being placed at the expected location within the potentially complex bidirectional text layout.
这是文件 `blink/renderer/core/editing/hit_testing_bidi_test.cc` 的第 4 部分，专注于测试在具有嵌套双向文本（Bidi）元素的 HTML 结构中进行精确命中测试（hit testing）的功能。命中测试指的是确定用户在屏幕上点击或触摸的坐标对应于哪个文档元素或文本位置。

**它的功能归纳如下：**

这部分代码继续测试当 HTML 结构中存在多层嵌套的 `<bdo>` 元素（用于显式地定义文本方向）时，`caretRangeFromPoint` 方法是否能准确地返回指定屏幕坐标处的插入符（caret）位置。

具体来说，这部分测试用例涵盖了以下情景：

* **在 LTR (Left-to-Right) 块级元素中，存在 RTL (Right-to-Left) 的基础文本运行，并且有三层嵌套的文本运行。**
    * 测试点击位置在嵌套文本运行的左边缘和右边缘的情况。
* **在 RTL 块级元素中，存在 RTL 或 LTR 的基础文本运行，并且有三层嵌套的文本运行。**
    * 测试点击位置在嵌套文本运行的左边缘和右边缘的情况。
    * 区分了基础文本运行结束的情况（即基础文本运行是整个嵌套结构的开头或结尾）。
* **与第 3 部分类似，也测试了点击位置非常靠近行边界的情况。**
* **引入了四层嵌套的 `<bdo>` 元素进行测试。**

**与 JavaScript, HTML, CSS 的功能关系：**

* **HTML:**  测试用例中通过 `SetBodyContent` 设置了包含 `<div>` 和 `<bdo>` 元素的 HTML 结构。`dir` 属性用于设置文本方向，`<bdo>` 元素则用于强制覆盖默认的 Bidi 算法。这些都是 HTML 中处理国际化文本的关键元素。
* **CSS:**  `InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}")`  插入了 CSS 样式，设置了 `div` 元素的字体和宽度。这影响了文本的渲染和布局，从而直接影响命中测试的结果。不同的字体和宽度会导致字符占据不同的物理空间，命中测试需要考虑到这些因素。
* **JavaScript:** 虽然这个 C++ 文件本身不是 JavaScript 代码，但它测试的 `caretRangeFromPoint` 方法是 Web API 的一部分，在 JavaScript 中也可以调用 `document.caretRangeFromPoint(x, y)` 来获取指定坐标的插入符位置。这个功能常用于实现富文本编辑器、自定义选择功能等。

**逻辑推理与假设输入输出：**

假设输入：

* **HTML 结构：**  例如 `<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>`
* **CSS 样式：**  `div {font: 10px/10px Ahem; width: 300px}`
* **点击坐标 (x, y)：**  例如 `x = div->OffsetLeft() + 33; y = div->OffsetTop() + 5;`

逻辑推理：

代码会根据 HTML 结构、CSS 样式以及提供的坐标，计算出该坐标对应的文本位置。由于涉及到双向文本，计算会比较复杂，需要考虑文本的阅读顺序和视觉呈现顺序。`caretRangeFromPoint` 方法会根据 Bidi 算法和布局信息，返回一个 `EphemeralRange` 对象，该对象描述了插入符的位置。

假设输出：

对于上述输入，其中一个测试用例的期望输出是：

```
"<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
"dir=\"rtl\">DEF<bdo "
"dir=\"ltr\">|abc</bdo></bdo>ghi</bdo>JKL</bdo></div>"
```

这里的 `|` 符号表示计算出的插入符位置。这意味着当用户点击的坐标落在 "a" 字符的左侧时，`caretRangeFromPoint` 能够准确地将插入符定位到 "a" 字符之前。

**用户或编程常见的使用错误：**

* **HTML 结构错误地嵌套或使用了错误的 `dir` 属性。**  例如，可能忘记闭合 `<bdo>` 标签，或者在应该使用 `rtl` 的地方使用了 `ltr`，反之亦然。这会导致 Bidi 算法无法正确解析文本方向，从而导致 `caretRangeFromPoint` 返回错误的位置。
* **CSS 样式影响了文本布局，但开发者没有考虑到这一点进行命中测试。** 例如，如果设置了 `letter-spacing` 或 `word-spacing`，字符之间的间距会发生变化，需要确保测试坐标能够准确落在目标字符的范围内。
* **假设所有文本都是从左到右的，没有考虑到国际化和本地化。**  在处理包含阿拉伯语、希伯来语等 RTL 语言的文本时，必须使用正确的 HTML 属性和 CSS 样式来确保文本的正确显示和交互。忽略这一点会导致命中测试等功能出现问题。
* **在进行命中测试时，没有考虑到浏览器的渲染机制和 Bidi 算法的复杂性。** 开发者可能简单地假设点击位置落在某个字符的几何中心就对应于该字符，但在 Bidi 文本中，视觉顺序和逻辑顺序可能不同，需要更精确的计算。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器中打开一个包含复杂 Bidi 文本的网页。**  例如，网页中可能包含阿拉伯语和英语混合的内容，并使用了 `<bdo>` 元素来强制某些文本片段的显示方向。
2. **用户尝试在这些 Bidi 文本中进行编辑操作，例如点击以插入光标。**
3. **浏览器接收到用户的点击事件，并需要确定用户点击的确切文本位置。**  这是通过调用底层的命中测试机制来实现的，其中就包括了 `caretRangeFromPoint` 方法。
4. **如果代码中存在与 Bidi 相关的错误，或者浏览器对 Bidi 文本的处理有缺陷，用户可能会发现点击后光标并没有落在期望的位置。**  例如，用户点击一个阿拉伯语单词的开头，但光标却出现在了该单词的末尾。
5. **开发者为了调试这个问题，可能会查看 Blink 引擎的源代码，特别是 `blink/renderer/core/editing/` 目录下的相关文件，例如 `hit_testing_bidi_test.cc`。**
6. **开发者可以运行这些测试用例，模拟用户操作，并观察测试是否失败。**  失败的测试用例可以帮助开发者定位问题所在的具体场景和代码逻辑。
7. **通过分析测试用例的输入（HTML 结构、CSS 样式、点击坐标）和期望输出（光标位置），开发者可以逐步理解 Bidi 文本处理的复杂性，并修复 `caretRangeFromPoint` 方法中的错误。**

**总结本部分的功能：**

这部分 `hit_testing_bidi_test.cc` 文件的功能是**系统地测试在各种复杂的嵌套 Bidi 文本场景下，`caretRangeFromPoint` 方法能否准确地将屏幕坐标转换为文档中的插入符位置**。它通过大量的测试用例覆盖了不同的文本方向组合、嵌套层级和点击位置，确保了 Blink 引擎在处理双向文本时的命中测试功能的正确性和可靠性。这是保证用户在编辑包含多种语言文本的网页时能够获得良好体验的关键。

Prompt: 
```
这是目录为blink/renderer/core/editing/hit_testing_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
h: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>ghi</bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  g h i F E D a b c|L K J
  // Bidi:    2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc|</bdo>DEF</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  g h i F E D a b c|L K J
  // Bidi:    2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\">ghi|<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc</bdo>DEF</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual: |a b c F E D g h i L K J
  // Bidi:    4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc|</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual: |a b c F E D g h i L K J
  // Bidi:    4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc|</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  L K J g h i F E D a b c|
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryRightSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  L K J g h i F E D a b c|
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual: |a b c F E D g h i
  // Bidi:    4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc|</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual: |a b c F E D g h i
  // Bidi:    4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc|</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  g h i F E D a b c|
  // Bidi:    2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  g h i F E D a b c|
  // Bidi:    2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  j k l|C B A d e f I H G m n o
  // Bidi:    2 2 2 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>mno</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\">GHI|<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo>mno</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  j k l|C B A d e f I H G m n o
  // Bidi:    2 2 2 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>mno</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo>mno</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  m n o I H G d e f C B A|j k l
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>mno<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">mno<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockLtrBaseRunRightSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  m n o I H G d e f C B A|j k l
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>mno<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">mno<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>|GHI</bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  j k l|C B A d e f I H G
  // Bidi:    2 2 2 5 5 5 4 4 4 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\">GHI|<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  j k l|C B A d e f I H G
  // Bidi:    2 2 2 5 5 5 4 4 4 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  I H G d e f C B A|j k l
  // Bidi:    3 3 3 4 4 4 5 5 5 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  I H G d e f C B A|j k l
  // Bidi:    3 3 3 4 4 4 5 5 5 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>|GHI</bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  L K J|a b c F E D g h i O N M
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo>ghi</bdo>|JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  L K J|a b c F E D g h i O N M
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo>ghi</bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  O N M g h i F E D a b c|L K J
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo></bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockRtlBaseRunRightSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  O N M g h i F E D a b c|L K J
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL|<bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc</bdo>DEF</bdo></bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  L K J|a b c F E D g h i
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo>ghi</bdo>|JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  L K J|a b c F E D g h i
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo>ghi</bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  g h i F E D a b c|L K J
  // Bidi:    2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  g h i F E D a b c|L K J
  // Bidi:    2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL|<bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc</bdo>DEF</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual: |a b c F E D g h i L K J m n o
  // Bidi:    4 4 4 3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>ghi</bdo></bdo>mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual: |a b c F E D g h i L K J m n o
  // Bidi:    4 4 4 3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>ghi</bdo></bdo>mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  m n o L K J g h i F E D a b c|
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 147;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno<bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc|</bdo>DEF</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryRightSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  m n o L K J g h i F E D a b c|
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 153;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno<bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc|</bdo>DEF</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOffourNestedRuns) {
  // Visual: |a b c F E D g h i L K J
  // Bidi:    4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">|abc</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOffourNestedRuns) {
  // Visual: |a b c F E D g h i L K J
  // Bidi:    4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">|abc</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOffourNestedRuns) {
  // Visual:  L K J g h i F E D a b c|
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc|</bdo>DEF</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfRightEdgeOffourNestedRuns) {
  // Visual:  L K J g h i F E D a b c|
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4
  LoadAhem();
  InsertStyleElement("di
"""


```