Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium file. This is part 2 of a 6-part series, so I need to focus on summarizing the functionality of this specific part.

The code consists of a series of C++ test functions within a test fixture named `HitTestingBidiTest`. Each test function follows a similar pattern:

1. **Setup:** Loads a font (`LoadAhem()`), inserts some CSS to set font and width for a `div` element, and sets the HTML content of the body. The HTML content includes a `div` with specific `dir` and nested `<bdo>` tags to create bidirectional text scenarios.

2. **Action:** Selects the `div` element using `querySelector`, calculates the left edge of the text content, defines `x` and `y` coordinates, and then calls `GetDocument().caretRangeFromPoint(x, y)` to get the caret position based on the given coordinates.

3. **Assertion:** Checks if the returned `EphemeralRange` is not null and is collapsed (meaning it's a caret). Then, it compares the expected caret position with the actual caret position obtained using `GetCaretTextFromBody(result.StartPosition())`.

Therefore, the main functionality of this code snippet is to **test the accuracy of hit-testing in bidirectional text scenarios**. It simulates mouse clicks (or similar input methods) at specific coordinates and verifies that the caret is placed at the correct logical position within the potentially complex bidirectional text.

Let's break down the specific tests within this part:

- **Focus on RTL blocks and nested runs:** Many tests involve `dir=rtl` on the `div` or `<bdo>` elements, indicating Right-to-Left text direction. The `<bdo>` tag is explicitly used to control the bidi algorithm.
- **Specific edge cases:** The test names explicitly mention "LeftSideOfLeftEdge", "RightSideOfLeftEdge", "LeftSideOfRightEdge", and "RightSideOfRightEdge" of text runs. This highlights the focus on testing the boundaries between different text runs and their hit-testing behavior.
- **Line boundaries:** Some tests include "AtLineBoundary" in their names, suggesting they are specifically testing scenarios where the click occurs at the edge of a line box.
- **Nested runs:**  Many tests involve "twoNestedRuns", meaning there are nested `<bdo>` elements, creating more complex bidirectional layouts.
- **Base run end:**  The phrase "WithBaseRunEnd" appears in some test names. This likely refers to the outermost `<bdo>` element and the behavior when hitting near its boundaries.

Considering the request to summarize the *functionality of this part*, I will focus on these key aspects.
这是 `blink/renderer/core/editing/hit_testing_bidi_test.cc` 文件的第 2 部分，它延续了第 1 部分的功能，主要用于测试在**双向文本 (Bidi)** 环境下，**点击测试 (Hit Testing)** 的准确性。

**本部分的功能可以归纳为：**

**继续测试在不同双向文本布局下，鼠标点击位置到光标位置的映射是否正确。**  这些测试用例涵盖了更复杂的 Bidi 场景，包括：

* **RTL 容器内的 RTL 基本走向文本，并包含 LTR 的内嵌文本。**  测试点击在内嵌 LTR 文本边缘时的光标定位。
* **Ltr 容器内不同 Bidi 走向的嵌套文本。** 测试点击在嵌套文本边缘或行首尾时的光标定位。
* **测试在行首尾边界进行点击时，光标是否能正确放置在逻辑位置。**

**与 JavaScript, HTML, CSS 的功能关系：**

这个测试文件直接关系到浏览器引擎如何解析和渲染包含双向文本的 HTML 内容，并响应用户的鼠标点击事件。

* **HTML:**  测试用例中使用了 `<div>` 元素和 `<bdo>` 元素。
    * `dir` 属性用于设置元素的文本方向 (`ltr` 或 `rtl`)。
    * `<bdo>` (Bi-Directional Override) 元素用于强制指定元素的文本方向，忽略默认的双向算法。
* **CSS:**  测试用例中使用了 CSS 来设置 `div` 元素的 `font` 和 `width` 属性。字体大小和宽度会影响文本的布局，从而影响点击测试的结果。
* **JavaScript:**  虽然这个 C++ 文件本身不是 JavaScript 代码，但它测试的功能直接影响到 JavaScript API 的行为，例如 `document.caretRangeFromPoint(x, y)`。这个 JavaScript 方法允许开发者根据屏幕坐标获取对应的光标位置，而这个 C++ 测试文件正是为了验证这个 API 在 Bidi 环境下的准确性。

**举例说明：**

假设 HTML 结构如下：

```html
<div dir="rtl"><bdo dir="rtl">DEF<bdo dir="ltr">abc</bdo>GHI</bdo></div>
```

对应的 CSS 为：

```css
div { font: 10px/10px Ahem; width: 300px; }
```

在 `InRtlBlockRtlBaseRunLeftSideOfRightEdgeOfOneRunWithBaseRunEnd` 这个测试中：

* **假设输入 (模拟用户点击):**  在视觉上 "abc" 的右边缘的左侧一点。
* **预期输出 (光标位置):**  光标应该放置在 "abc" 的末尾，即 `...abc|...`

这个测试验证了即使在 RTL 的容器中，包含 LTR 的内嵌文本，点击在视觉右边缘的左侧也能正确映射到逻辑上的 LTR 文本的末尾。

**逻辑推理与假设输入输出：**

以 `InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd` 测试为例：

* **假设输入 HTML:** `<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo>ghi</div>`
* **视觉渲染:** |a b c F E D g h i (假设从左到右)
* **Bidi 走向:** 2 2 2 1 1 1 0 0 0 (数字代表不同的 Bidi 水平)
* **假设输入点击坐标 (x, y):**  非常接近 `div` 的左边缘，在行首。
* **逻辑推理:** 由于点击位置非常接近行首，且文本的起始方向是 LTR，即使内部有 RTL 的 `<bdo>` 元素，光标也应该放在整个文本的最开始。
* **预期输出 (光标位置):**  光标应该放置在整个字符串的最前面，即 `|<div dir="ltr">...`。

**用户或编程常见的使用错误：**

* **HTML 结构错误导致 Bidi 解析不符合预期：**  例如，忘记设置 `dir` 属性，或者 `<bdo>` 标签嵌套错误，可能导致文本渲染顺序混乱。用户可能会发现光标点击的位置和实际光标出现的位置不一致。
* **CSS 样式影响文本布局，导致点击测试失败：**  例如，不正确的 `width` 设置可能导致文本换行，使得原本设计在同一行的点击位置落到下一行，导致测试失败。程序员在编写测试时需要精确计算坐标。
* **JavaScript 中错误地假设 Bidi 文本的行为：**  开发者可能会错误地认为字符串的索引和视觉位置一一对应，这在 Bidi 文本中是不成立的。例如，反向迭代字符串可能会得到非预期的结果。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器中访问了一个包含复杂双向文本的网页。**
2. **网页的 HTML 结构中使用了 `dir="rtl"` 和 `<bdo>` 标签来控制文本方向。**
3. **用户尝试在这些双向文本中进行编辑，例如点击鼠标来选择或插入光标。**
4. **如果浏览器引擎在处理双向文本的点击测试时存在 bug，用户可能会发现点击的位置和光标实际出现的位置不一致。** 例如，在一段 RTL 文本中点击视觉上的左边，光标可能出现在右边，或者在一个包含 LTR 内嵌文本的 RTL 块中，点击在 LTR 文本的边缘时，光标没有正确放置。
5. **为了调试这个问题，Chromium 开发者可能会运行 `hit_testing_bidi_test.cc` 中的相关测试用例。**  通过这些测试，开发者可以重现用户遇到的问题，并逐步分析是哪个环节出现了错误，例如是布局计算错误，还是点击位置到光标位置的映射逻辑错误。每个测试用例都模拟了特定的 HTML 结构、CSS 样式和点击位置，帮助开发者隔离和定位问题。

**本部分的功能归纳：**

作为 `blink/renderer/core/editing/hit_testing_bidi_test.cc` 的第 2 部分，其核心功能是**扩展了对双向文本点击测试的覆盖范围，针对更复杂的嵌套结构和行边界情况进行验证，确保在各种 Bidi 场景下，用户的鼠标点击能够准确地映射到预期的光标位置。** 这些测试对于保证富文本编辑器等需要精确光标控制的应用在处理多语言内容时的正确性至关重要。

Prompt: 
```
这是目录为blink/renderer/core/editing/hit_testing_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI<bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  I H G a b c|F E D
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfRightEdgeOfOneRunWithBaseRunEnd) {
  // Visual:  I H G a b c|F E D
  // Bidi:    1 1 1 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">DEF|<bdo "
      "dir=\"ltr\">abc</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOfOneRun) {
  // Visual:  F E D|a b c
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc</bdo>|DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockRtlBaseRunRightSideOfLeftEdgeOfOneRun) {
  // Visual:  F E D|a b c
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockRtlBaseRunLeftSideOfRightEdgeOfOneRun) {
  // Visual:  a b c|F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest, InRtlBlockRtlBaseRunRightSideOfRightEdgeOfOneRun) {
  // Visual:  a b c|F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">DEF|<bdo "
      "dir=\"ltr\">abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual: |a b c F E D g h i
  // Bidi:    2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>ghi</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual: |a b c F E D g h i
  // Bidi:    2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>ghi</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  g h i F E D a b c|
  // Bidi:    0 0 0 1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>ghi<bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">ghi<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryRightSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  g h i F E D a b c|
  // Bidi:    0 0 0 1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>ghi<bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">ghi<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOftwoNestedRuns) {
  // Visual: |a b c F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOftwoNestedRuns) {
  // Visual: |a b c F E D
  // Bidi:    2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  F E D a b c|
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  F E D a b c|
  // Bidi:    1 1 1 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  g h i|a b c F E D j k l
  // Bidi:    0 0 0 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>ghi<bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">ghi|<bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo>jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  g h i|a b c F E D j k l
  // Bidi:    0 0 0 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>ghi<bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">ghi<bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  j k l F E D a b c|g h i
  // Bidi:    0 0 0 1 1 1 2 2 2 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo>ghi</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  j k l F E D a b c|g h i
  // Bidi:    0 0 0 1 1 1 2 2 2 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc</bdo>DEF</bdo>|ghi</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  g h i|a b c F E D
  // Bidi:    0 0 0 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>ghi<bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">ghi|<bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  g h i|a b c F E D
  // Bidi:    0 0 0 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>ghi<bdo dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">ghi<bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  F E D a b c|g h i
  // Bidi:    1 1 1 2 2 2 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo>ghi</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  F E D a b c|g h i
  // Bidi:    1 1 1 2 2 2 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo>ghi</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc</bdo>DEF</bdo>|ghi</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  I H G|C B A d e f L K J
  // Bidi:    1 1 1 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>|def</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  I H G|C B A d e f L K J
  // Bidi:    1 1 1 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  L K J d e f C B A|I H G
  // Bidi:    1 1 1 2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  L K J d e f C B A|I H G
  // Bidi:    1 1 1 2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\">def|<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  I H G|C B A d e f
  // Bidi:    1 1 1 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>|def</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  I H G|C B A d e f
  // Bidi:    1 1 1 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  d e f C B A|I H G
  // Bidi:    2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  d e f C B A|I H G
  // Bidi:    2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\">def|<bdo "
      "dir=\"rtl\">ABC</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual: |C B A d e f I H G
  // Bidi:    3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual: |C B A d e f I H G
  // Bidi:    3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  I H G d e f C B A|
  // Bidi:    1 1 1 2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryRightSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  I H G d e f C B A|
  // Bidi:    1 1 1 2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOftwoNestedRuns) {
  // Visual: |C B A d e f
  // Bidi:    3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOftwoNestedRuns) {
  // Visual: |C B A d e f
  // Bidi:    3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  d e f C B A|
  // Bidi:    2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  d e f C B A|
  // Bidi:    2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  g h i|a b c F E D j k l
  // Bidi:    2 2 2 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT
"""


```