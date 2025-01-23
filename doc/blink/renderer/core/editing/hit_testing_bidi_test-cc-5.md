Response:
The user wants to understand the functionality of the provided C++ code snippet from `hit_testing_bidi_test.cc`. This file appears to contain unit tests for hit testing in bidirectional text scenarios within the Blink rendering engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename `hit_testing_bidi_test.cc` immediately suggests that the code is about testing how the browser engine determines the location of a click (hit) within text that has both left-to-right (LTR) and right-to-left (RTL) elements. The `Bidi` part confirms it deals with bidirectional text.

2. **Analyze the structure:** The code consists of multiple `TEST_F` blocks within a namespace `blink`. This is a standard Google Test structure for defining individual test cases. Each test case has a descriptive name indicating the specific scenario being tested.

3. **Examine individual test cases:**  Each test case follows a similar pattern:
    * `LoadAhem()`: Likely loads a specific font for consistent text rendering across different systems.
    * `InsertStyleElement(...)`:  Injects CSS to control the appearance of the tested element (in this case, setting font and width).
    * `SetBodyContent(...)`: Sets the HTML content of the page body, which includes `<div>` elements with `dir` and `<bdo>` attributes to simulate bidirectional text.
    * `GetDocument().QuerySelector(...)`: Selects the target `<div>` element.
    * Calculating `x` and `y`: These lines calculate the coordinates for the simulated click, taking into account the element's position, width, and text length. This is crucial for pinpointing specific locations within the text.
    * `GetDocument().caretRangeFromPoint(x, y)`:  This is the core function being tested. It simulates a click at the calculated (x, y) coordinates and returns the text range (caret position) where the click occurred.
    * `EXPECT_TRUE(...)`: Assertions to verify the outcome of the test. `IsNotNull()` checks if a valid range was returned, `IsCollapsed()` checks if it's a single point (caret), and `EXPECT_EQ(...)` compares the expected caret position with the actual result. `GetCaretTextFromBody(...)` likely formats the HTML to visually represent the caret position.

4. **Infer the overall function:** The tests aim to verify that given a specific HTML structure with bidirectional text and a simulated click at certain coordinates, the `caretRangeFromPoint` function correctly identifies the corresponding position within the text. The variety of test names suggests comprehensive testing of edge cases, especially around the boundaries of nested bidirectional elements.

5. **Connect to web technologies (JavaScript, HTML, CSS):**
    * **HTML:** The `dir` attribute on `<div>` and `<bdo>` elements directly controls the text direction, which is the fundamental aspect being tested. The structure of nested elements also plays a crucial role.
    * **CSS:** The `font` and `width` styles are used to control the visual layout and ensure accurate coordinate calculations for the hit test. Different font sizes or element widths would change the pixel positions.
    * **JavaScript:** Although not directly used in this *specific* code snippet, the functionality being tested (hit testing and caret positioning) is fundamental to how JavaScript interacts with the DOM to handle user input (like clicks and text selection). For example, a JavaScript event listener might trigger actions based on where the user clicks, and the browser's hit-testing mechanism determines that location.

6. **Identify logical reasoning and examples:** The tests involve a clear logical flow: set up a specific bidirectional text scenario, simulate a click at precise coordinates, and verify the resulting caret position. The examples are embedded within the tests themselves through the `SetBodyContent` and the expected output in `EXPECT_EQ`. The visual comments within the tests (e.g., "Visual:  O N M|...") provide a manual verification of the expected layout and caret position.

7. **Consider user/programming errors:** A common error would be incorrect calculation of the `x` and `y` coordinates in manual hit-testing or when trying to programmatically determine the caret position. The tests themselves help prevent errors in the underlying hit-testing logic within the browser engine. Another error could be a misunderstanding of how the `dir` and `<bdo>` elements affect text layout, leading to incorrect expectations about where the caret should be.

8. **Trace user interaction:**  A user interacting with a webpage might click on a piece of text. The browser then uses the hit-testing mechanism (which these tests verify) to determine the exact location of the click within the text content. This information is crucial for actions like setting the text cursor, selecting text, or triggering JavaScript events associated with that text. The tests simulate this process by programmatically providing the coordinates.

9. **Summarize the functionality (for part 6):**  Since this is part 6 of 6, the final summary should consolidate the key points discussed in the previous steps, emphasizing that the code provides comprehensive unit testing for the browser's ability to accurately determine the caret position within complex bidirectional text scenarios when a user clicks at a specific point.

By following these steps, we can generate a comprehensive and accurate description of the provided code snippet.
这是目录为 `blink/renderer/core/editing/hit_testing_bidi_test.cc` 的 Chromium Blink 引擎源代码文件。根据其文件名和内容，我们可以归纳出以下功能：

**主要功能：对双向文本（Bidi）的点击测试进行单元测试。**

这个文件包含了一系列单元测试，用于验证 Blink 引擎在处理包含从右到左（RTL）和从左到右（LTR）混合文本的场景下，准确判断用户点击位置（hit testing）的能力。这些测试主要关注以下方面：

* **光标定位的准确性：** 当用户点击双向文本时，测试确保引擎能够正确地将光标放置在预期的位置。
* **处理不同的双向嵌套结构：** 测试覆盖了各种复杂的双向文本嵌套情况，例如在 RTL 容器中包含 LTR 文本，以及多层嵌套的情况。
* **边界情况处理：** 测试特别关注点击文本边缘时的行为，包括左边缘和右边缘，以及在不同的双向运行（run）边界上的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件直接关联到 HTML 和 CSS 中用于处理双向文本的特性。虽然不直接涉及 JavaScript 代码，但它测试的功能是 JavaScript 与 DOM 交互的基础。

* **HTML:**
    * **`dir` 属性:** 测试中大量使用了 `dir="rtl"` 和 `dir="ltr"` 属性来定义元素的文本方向。例如，`<div dir=rtl>` 表示这个 div 元素的内容方向是从右到左的。
    * **`<bdo>` 元素:** `<bdo>` 元素（Bi-Directional Override）用于强制改变其包含文本的方向，无论周围文本的方向如何。测试中使用了 `<bdo dir=rtl>` 和 `<bdo dir=ltr>` 来创建复杂的双向文本结构。
    * **示例:**
        ```html
        <div dir=rtl>右到左文本 <bdo dir=ltr>强制从左到右文本</bdo> 又回到右到左文本</div>
        ```
* **CSS:**
    * **文本方向相关属性:** 虽然在这个测试文件中没有直接展示 CSS 代码，但测试依赖于 Blink 引擎对 CSS 文本方向相关属性（如 `direction`）的解析和应用。测试中通过 `InsertStyleElement` 插入了 CSS 代码来设置字体和宽度，这影响了文本的布局和点击位置的计算。
    * **示例:**
        ```css
        div {
          direction: rtl;
        }
        ```
* **JavaScript:**
    * **`document.caretRangeFromPoint(x, y)`:** 这是测试的核心。这个 JavaScript API 用于获取指定坐标 (x, y) 处的光标范围（CaretRange）。测试通过模拟点击事件的坐标，验证该 API 在双向文本场景下的行为是否正确。
    * **用户交互:** 当用户在网页上点击文本时，浏览器内部会使用类似 `caretRangeFromPoint` 的机制来确定点击位置，并将光标移动到那里。这个测试确保了这个过程在双向文本下也能正确工作。

**逻辑推理及假设输入与输出：**

每个 `TEST_F` 函数都代表一个独立的测试用例。我们可以通过分析一个用例来理解其逻辑推理：

**测试用例示例:** `InRtlBlockLtrBaseRunLeftSideOfRightEdgeOfTwoNestedRuns`

**假设输入:**

* **HTML 结构:** `<div dir=rtl><bdo dir=ltr>ABC</bdo>DEF</div>`
* **CSS 样式:** `div {font: 10px/10px Ahem; width: 300px}` （假设 `Ahem` 字体每个字符宽度为 10px）
* **模拟点击坐标 (x, y):**  计算出的坐标位于 "C" 和 "D" 之间，非常靠近 "C" 的右边缘。 具体计算方式如下：
    * `div->OffsetLeft()`: 获取 div 元素左上角的横坐标。
    * `300 - div->textContent().length() * 10`: 计算文本内容左侧的起始横坐标（因为是 RTL 容器）。文本长度是 6，每个字符 10px，所以是 300 - 60 = 240。
    * `x = text_left + 30`:  在文本起始位置的基础上加上 30px，对应 "ABC" 三个字符的宽度。

**逻辑推理:**

1. HTML 结构定义了一个 RTL 的 `div` 元素，其中包含一个 LTR 的 `<bdo>` 元素，后面跟着一些 LTR 文本。
2. 视觉上，文本会呈现为 "CBA DEF"。
3. 测试的目标是验证当点击发生在 "C" 和 "D" 之间的右边缘时，光标是否会正确地定位在 "C" 的后面。

**预期输出:**

* `result.IsNotNull()`: 返回的 `EphemeralRange` 对象不为空。
* `result.IsCollapsed()`: 返回的范围是折叠的，表示一个光标位置。
* `GetCaretTextFromBody(result.StartPosition())` 的结果是： `<div dir=\"rtl\"><bdo dir=\"ltr\">ABC|</bdo>DEF</div>`。竖线 `|` 表示光标的位置。

**涉及用户或者编程常见的使用错误及举例说明：**

* **对双向文本的渲染方式理解不足：** 开发者可能不清楚浏览器如何根据 `dir` 和 `<bdo>` 属性渲染双向文本，导致在手动计算或测试时出现偏差。 例如，他们可能错误地认为在 RTL 容器中，文本总是从最右边开始排列。
* **坐标计算错误：** 在进行类似点击测试或模拟用户操作时，手动计算坐标容易出错，尤其是在涉及到元素偏移、滚动条等因素时。测试用例中的坐标计算展示了如何精确地确定点击位置。
* **忽略嵌套的文本方向：**  在复杂的嵌套结构中，忘记考虑内层元素的文本方向可能导致错误的假设。例如，在一个 RTL 的 `div` 中嵌套一个 LTR 的 `<bdo>`，其内部文本的排列方式会反转。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个包含双向文本的网页。**
2. **用户将鼠标指针移动到该文本区域。**
3. **用户点击文本中的某个位置。**

当用户执行上述操作时，浏览器内部会进行以下步骤（与测试用例模拟的过程类似）：

1. **获取鼠标点击的屏幕坐标 (x, y)。**
2. **将屏幕坐标转换为相对于文档的坐标。**
3. **根据坐标，在 DOM 树中查找被点击的元素。**
4. **对于文本节点，使用 hit testing 算法（该测试文件验证的核心）来确定点击发生在文本的哪个精确位置。** 这需要考虑文本的渲染方式，包括双向文本的处理。
5. **根据点击位置，设置光标的位置或进行文本选择。**

作为调试线索，如果用户报告在双向文本中点击时，光标位置不正确或选择行为异常，开发人员可以参考这些单元测试用例，尝试重现问题，并利用这些测试用例提供的场景进行调试，验证 Blink 引擎在特定情况下的 hit testing 行为是否符合预期。

**第6部分，共6部分的功能归纳：**

作为该系列测试的最后一部分，这部分的功能仍然是 **验证 Blink 引擎在处理复杂嵌套的从右到左（RTL）文本块时，进行点击测试的准确性**。 具体来说，这部分测试用例：

* **关注 `dir=rtl` 的 `div` 元素作为最外层容器的情况。**
* **测试在 RTL 容器中，基本文本运行方向也是 RTL 的场景。**
* **深入测试了四层嵌套 `<bdo>` 元素的情况，进一步增加了双向文本的复杂性。**
* **涵盖了点击发生在不同嵌套层级边界的情况，包括嵌套元素内部的左边缘和右边缘。**
* **通过精确计算点击坐标，模拟用户在特定视觉位置的点击，并验证光标是否定位到预期的逻辑位置。**

总而言之，整个 `hit_testing_bidi_test.cc` 文件旨在确保 Chromium Blink 引擎能够正确处理各种双向文本布局，并为用户提供一致且准确的点击交互体验。这部分作为最后一部分，可能涵盖了之前测试中未覆盖到的更复杂的边界情况和嵌套场景，是对整个双向文本点击测试的补充和完善。

### 提示词
```
这是目录为blink/renderer/core/editing/hit_testing_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
bdo>|JKL</bdo>mno</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  O N M|C B A d e f I H G j k l R Q P
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>PQR<bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">PQR<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo>jkl</bdo>|MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfLeftEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  O N M|C B A d e f I H G j k l R Q P
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>PQR<bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">PQR<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  R Q P j k l I H G d e f C B A|O N M
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 147;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfRightEdgeOffourNestedRunsWithBaseRunEnd) {
  // Visual:  R Q P j k l I H G d e f C B A|O N M
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 153;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO|<bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>GHI</bdo></bdo>PQR</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  O N M|C B A d e f I H G j k l
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo>jkl</bdo>|MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfLeftEdgeOffourNestedRuns) {
  // Visual:  O N M|C B A d e f I H G j k l
  // Bidi:    1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>GHI<bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo></bdo>jkl</bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfRightEdgeOffourNestedRuns) {
  // Visual:  j k l I H G d e f C B A|O N M
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfRightEdgeOffourNestedRuns) {
  // Visual:  j k l I H G d e f C B A|O N M
  // Bidi:    2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">MNO|<bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>GHI</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

}  // namespace blink
```