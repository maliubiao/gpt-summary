Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. The code is part of the Chromium Blink engine and resides in a file named `hit_testing_bidi_test.cc`. The name suggests it's related to hit testing and bidirectional text.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The code consists of multiple test cases within a test fixture `HitTestingBidiTest`. Each test case seems to set up a specific HTML structure involving bidirectional text (`<bdo>` tag) and then performs a hit test using `GetDocument().caretRangeFromPoint(x, y)`. The core purpose is to verify that the hit test returns the correct caret position within complex bidirectional text scenarios.

2. **Analyze the Test Case Structure:**  Each test case follows a similar pattern:
    * `LoadAhem()`: Likely loads a specific font for consistent rendering.
    * `InsertStyleElement(...)`: Adds CSS to define the width of the container.
    * `SetBodyContent(...)`: Creates the HTML structure with `<bdo>` elements and text. The `dir` attribute is used to control the directionality of the text.
    * `GetDocument().QuerySelector(...)`:  Selects the main `div` element.
    * Calculation of `x` and `y`:  Determines the coordinates for the hit test, usually offset from the `div`'s position. The offsets are carefully chosen to target specific locations within the text.
    * `GetDocument().caretRangeFromPoint(x, y)`: This is the key function being tested. It takes screen coordinates and returns the caret position.
    * `EXPECT_TRUE(result.IsNotNull())`: Checks if the hit test returned a valid result.
    * `EXPECT_TRUE(result.IsCollapsed())`: Verifies that the result is a single point (caret).
    * `EXPECT_EQ(..., GetCaretTextFromBody(result.StartPosition()))`: This is the core assertion. It compares the expected HTML with a caret marker (`|`) at the correct position with the actual caret position returned by the hit test.

3. **Infer the Purpose of the Tests:**  The tests cover various scenarios of nested `<bdo>` elements with different `dir` attributes (LTR and RTL). The test names are descriptive and indicate the specific scenario being tested, such as "InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd". This detailed naming suggests a focus on edge cases and specific boundary conditions within bidirectional text layouts.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The tests directly manipulate HTML structure using the `<bdo>` tag for controlling text direction. The `dir` attribute is crucial.
    * **CSS:** CSS is used to set the width of the containing `div`, which influences the layout and how bidirectional text is rendered across lines (though most of these tests seem to be single-line scenarios). The `Ahem` font is used for consistent pixel measurements.
    * **JavaScript (Indirectly):** While the tests are in C++, the functionality being tested (`caretRangeFromPoint`) is part of the DOM API, which is heavily used by JavaScript for manipulating web pages. JavaScript can call methods like `document.caretRangeFromPoint()` to get the caret position.

5. **Identify Potential User/Programming Errors:**
    * Incorrectly specifying `dir` attributes can lead to unexpected text rendering and caret positioning.
    * Assuming a linear progression of text when dealing with bidirectional content can lead to errors in calculations or assumptions about where the caret should be.
    * Issues with font rendering or character widths can affect the accuracy of hit testing.

6. **Explain User Interaction:** A user interaction leading to this code being executed would involve a user clicking within a text area on a web page that contains bidirectional text. The browser's rendering engine (Blink in this case) would need to determine the precise caret position based on the click coordinates, which is what these tests are validating.

7. **Address the "Part 5 of 6" Instruction:** This part of the file focuses on testing scenarios with four nested `<bdo>` elements.

8. **Formulate the Summary:** Combine the observations into a concise summary covering the functionality, relationships to web technologies, logical reasoning, potential errors, user interaction, and the specific focus of this part of the file.
这是第5部分，它延续了前一部分的测试，专注于 `HitTestingBidiTest` 这个测试套件中，关于双向文本（Bidi）的点击测试用例。

**功能归纳:**

这部分代码的功能是**测试在包含四层嵌套的 `<bdo>` 元素（用于控制双向文本方向）的HTML结构中，通过鼠标点击坐标 (`caretRangeFromPoint`) 确定光标位置的准确性。**  测试覆盖了各种情况，包括：

* **容器的 `dir` 属性:** `ltr` (从左到右) 和 `rtl` (从右到左)。
* **最外层 `<bdo>` 元素的 `dir` 属性 (Base Run):** `ltr` 和 `rtl`。
* **点击位置:**  针对每个文本片段的左边缘和右边缘的左侧和右侧进行点击。
* **是否在行边界:**  针对 `rtl` 容器，测试点击在逻辑行首和行尾附近的情况。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **HTML:** 这部分测试的核心在于 HTML 结构，特别是 `<bdo>` 标签和 `dir` 属性。`<bdo>` 标签用于强制覆盖默认的文本方向，这在处理混合语言文本（例如，英语和阿拉伯语）时非常有用。
    * **举例:** `<div dir=ltr><bdo dir=rtl>abc</bdo>def</div>`  在这个例子中，`abc` 会以从右到左的方式渲染，而 `def` 会以从左到右的方式渲染。
* **CSS:**  CSS 用于设置容器的宽度 (`width: 300px`) 和字体 (`font: 10px/10px Ahem`)。设置宽度是为了确保测试在特定的布局下进行，字体 `Ahem` 是一个特殊的字体，其所有字符的宽度都相同，这有助于精确的像素计算。
    * **举例:** `div { font: 10px/10px Ahem; width: 300px; }` 这段 CSS 确保了 `div` 元素的渲染行为在不同平台上的一致性。
* **JavaScript:** 虽然这段代码是 C++ 写的，但它测试的是浏览器引擎的功能，这些功能最终会被 JavaScript API 暴露出来。例如，JavaScript 中的 `document.caretRangeFromPoint(x, y)` 方法的功能就与这里测试的 C++ 代码密切相关。
    * **举例:** 一个 JavaScript 脚本可能会监听用户的鼠标点击事件，并使用 `document.caretRangeFromPoint(event.clientX, event.clientY)` 来获取用户点击位置的光标信息。

**逻辑推理 (假设输入与输出):**

假设输入以下 HTML 和点击坐标：

**假设输入:**

* **HTML:** `<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo></div>`
* **CSS:** `div {font: 10px/10px Ahem; width: 300px}`
* **点击坐标:** `x = div->OffsetLeft() + 123`, `y = div->OffsetTop() + 5` (对应 "abc" 文本的中间位置附近)

**逻辑推理:**

由于 `Ahem` 字体的字符宽度是固定的 10px，并且文本方向复杂，引擎需要根据 Bidi 算法来确定点击位置对应的逻辑光标位置。在这种情况下，点击在 "abc" 的中间，应该将光标放置在 "abc" 的末尾。

**预期输出:**

* 光标应该位于 "abc" 之后，即 `abc|DEF` 的位置。
* `result.IsNotNull()` 应该为 `true`。
* `result.IsCollapsed()` 应该为 `true`。
* `GetCaretTextFromBody(result.StartPosition())` 应该返回 `<div dir="ltr"><bdo dir="rtl"><bdo dir="ltr">ghi<bdo dir="rtl"><bdo dir="ltr">abc|</bdo>DEF</bdo></bdo>JKL</bdo></div>`。

**涉及用户或编程常见的使用错误:**

* **用户错误:** 用户在阅读或编辑双向文本时，可能会因为文本的视觉顺序和逻辑顺序不一致而感到困惑，导致点击位置与预期光标位置不符。例如，在一个从右到左的段落中嵌入了一段从左到右的文字，用户可能会错误地估计光标应该出现的位置。
* **编程错误:** 开发者在处理双向文本时，容易犯的错误包括：
    * **未正确设置 `dir` 属性:**  忘记在需要控制方向的元素上设置 `dir="rtl"` 或 `dir="ltr"`。
    * **假设文本是线性的:**  在处理光标移动、文本选择等操作时，没有考虑到双向文本的逻辑顺序，导致操作不符合预期。
    * **忽略 Unicode Bidi 算法:**  没有理解浏览器是如何根据 Unicode Bidi 算法来处理文本方向的，导致对渲染结果的误判。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个包含复杂双向文本的网页。** 这个网页可能包含阿拉伯语、希伯来语等从右到左的语言，并可能混合了英语等从左到右的语言。
2. **用户尝试在特定位置插入或编辑文本。**  他们可能会将鼠标光标移动到他们想要操作的位置并点击。
3. **浏览器接收到鼠标点击事件，并需要确定用户想要将光标放在哪个逻辑位置。**
4. **浏览器引擎 (Blink) 调用 `document.caretRangeFromPoint(x, y)` 或其内部实现。**  `x` 和 `y` 是相对于视口的点击坐标。
5. **`HitTestingBidiTest` 中的测试用例模拟了这一过程。**  它们预先设置了特定的 HTML 结构和点击坐标，然后断言 `caretRangeFromPoint` 返回的光标位置是否正确。
6. **如果测试失败，说明在处理特定类型的双向文本布局时，光标定位可能存在 bug。** 这将为开发者提供调试线索，让他们能够深入研究相关的 Bidi 算法实现和布局代码。

**总结本部分的功能:**

这部分测试用例专门用于验证 Blink 引擎在处理具有四层嵌套 `<bdo>` 元素的复杂双向文本布局时，通过鼠标点击进行光标定位的功能是否正确。它覆盖了多种不同的文本方向组合和点击位置，旨在确保在各种复杂的 Bidi 场景下，用户交互能够得到准确的响应。

### 提示词
```
这是目录为blink/renderer/core/editing/hit_testing_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
v {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 123;
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
       InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  m n o|a b c F E D g h i L K J p q r
  // Bidi:    0 0 0 4 4 4 3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo>pqr</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno|<bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc</bdo></bdo>ghi</bdo></bdo>pqr</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  m n o|a b c F E D g h i L K J p q r
  // Bidi:    0 0 0 4 4 4 3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo>pqr</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno<bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>ghi</bdo></bdo>pqr</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  p q r L K J g h i F E D a b c|m n o
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>pqr<bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 147;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">pqr<bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></bdo>JKL</bdo>mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  p q r L K J g h i F E D a b c|m n o
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>pqr<bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 153;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">pqr<bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc</bdo>DEF</bdo></bdo>JKL</bdo>|mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  m n o|a b c F E D g h i L K J
  // Bidi:    0 0 0 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno|<bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  m n o|a b c F E D g h i L K J
  // Bidi:    0 0 0 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno<bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">|abc</bdo></bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfRightEdgeOffourNestedRuns) {
  // Visual:  L K J g h i F E D a b c|m n o
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc|</bdo>DEF</bdo></bdo>JKL</bdo>mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfRightEdgeOffourNestedRuns) {
  // Visual:  L K J g h i F E D a b c|m n o
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc</bdo>DEF</bdo></bdo>JKL</bdo>|mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  O N M|C B A d e f I H G j k l R Q P
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>PQR<bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">PQR<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo>|jkl</bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  O N M|C B A d e f I H G j k l R Q P
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>PQR<bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">PQR<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  R Q P j k l I H G d e f C B A|O N M
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 147;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  R Q P j k l I H G d e f C B A|O N M
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 153;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\">jkl|<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  O N M|C B A d e f I H G j k l
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo>|jkl</bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  O N M|C B A d e f I H G j k l
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfRightEdgeOffourNestedRuns) {
  // Visual:  j k l I H G d e f C B A|O N M
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfRightEdgeOffourNestedRuns) {
  // Visual:  j k l I H G d e f C B A|O N M
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\">jkl|<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual: |C B A d e f I H G j k l O N M
  // Bidi:    5 5 5 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual: |C B A d e f I H G j k l O N M
  // Bidi:    5 5 5 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  O N M j k l I H G d e f C B A|
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 5 5 5
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 147;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InRtlBlockAtLineBoundaryRightSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  O N M j k l I H G d e f C B A|
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 5 5 5
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 153;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfLeftEdgeOffourNestedRuns) {
  // Visual: |C B A d e f I H G j k l
  // Bidi:    5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfLeftEdgeOffourNestedRuns) {
  // Visual: |C B A d e f I H G j k l
  // Bidi:    5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryLeftSideOfRightEdgeOffourNestedRuns) {
  // Visual:  j k l I H G d e f C B A|
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockAtLineBoundaryRightSideOfRightEdgeOffourNestedRuns) {
  // Visual:  j k l I H G d e f C B A|
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  m n o|a b c F E D g h i L K J p q r
  // Bidi:    2 2 2 6 6 6 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>mno<bdo dir=rtl>JKL<bdo "
      "dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo>pqr</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">mno<bdo "
      "dir=\"rtl\">JKL|<bdo dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo>ghi</bdo></bdo>pqr</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  m n o|a b c F E D g h i L K J p q r
  // Bidi:    2 2 2 6 6 6 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>mno<bdo dir=rtl>JKL<bdo "
      "dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo>pqr</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">mno<bdo "
      "dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo>ghi</bdo></bdo>pqr</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  p q r L K J g h i F E D a b c|m n o
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 6 6 6 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>pqr<bdo dir=rtl><bdo "
      "dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 147;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">pqr<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  p q r L K J g h i F E D a b c|m n o
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 6 6 6 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>pqr<bdo dir=rtl><bdo "
      "dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 153;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">pqr<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc</bdo>DEF</bdo></bdo>|JKL</bdo>mno</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  m n o|a b c F E D g h i L K J
  // Bidi:    2 2 2 6 6 6 5 5 5 4 4 4 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>mno<bdo dir=rtl>JKL<bdo "
      "dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">mno<bdo "
      "dir=\"rtl\">JKL|<bdo dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo>ghi</bdo></bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  m n o|a b c F E D g h i L K J
  // Bidi:    2 2 2 6 6 6 5 5 5 4 4 4 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>mno<bdo dir=rtl>JKL<bdo "
      "dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo></bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">mno<bdo "
      "dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc|</bdo></bdo>ghi</bdo></bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfRightEdgeOffourNestedRuns) {
  // Visual:  L K J g h i F E D a b c|m n o
  // Bidi:    3 3 3 4 4 4 5 5 5 6 6 6 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">|abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfRightEdgeOffourNestedRuns) {
  // Visual:  L K J g h i F E D a b c|m n o
  // Bidi:    3 3 3 4 4 4 5 5 5 6 6 6 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>JKL</bdo>mno</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo dir=\"rtl\"><bdo "
      "dir=\"ltr\">abc</bdo>DEF</bdo></
```