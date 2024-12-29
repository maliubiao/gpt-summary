Response:
The user wants to understand the functionality of the `hit_testing_bidi_test.cc` file in the Chromium Blink engine.

I need to:
1. **Identify the core function:** Based on the file name and the provided code snippets, it's clearly about testing hit testing logic in the context of bidirectional text.
2. **Explain the relationship to web technologies:** Hit testing is crucial for user interaction with HTML elements, particularly text. This involves correctly determining which character or position is clicked, even with complex bidirectional text layouts. This relates to JavaScript's ability to get cursor positions and selection ranges, and how the browser renders text influenced by HTML's `dir` attribute and CSS's `direction` property.
3. **Infer the testing methodology:** The code uses `TEST_F` which indicates it's a Google Test framework test suite. Each test case sets up specific HTML content with bidirectional text, simulates a mouse click at a certain coordinate, and verifies the resulting caret position.
4. **Provide examples:** I can give examples of how the `dir` attribute on HTML elements like `<div>` and `<bdo>` influence the visual order of text and how this file tests whether hit testing correctly handles these cases.
5. **Explain user errors:** A common user error related to bidirectional text is incorrect or missing `dir` attributes, leading to unexpected text rendering and cursor behavior. This file ensures the browser handles these scenarios correctly.
6. **Describe the user journey:**  A user interacts with a webpage by moving the mouse and clicking. The browser then uses hit testing to determine the target of the click. In the case of bidirectional text, this process is more complex.
7. **Summarize the functionality for this specific part:** This section focuses on testing hit testing within nested bidirectional text runs, particularly examining edge cases where the click occurs right at the boundary between runs.
这是 `blink/renderer/core/editing/hit_testing_bidi_test.cc` 文件第 3 部分的内容，其主要功能是**测试在包含双向文本（BiDi）的复杂布局中进行精确点击位置（hit testing）的能力**。

更具体地说，这部分测试集中在以下场景：

* **嵌套的 BiDi 文本段落：**  测试用例创建了包含多层嵌套 `<bdo>` 标签的 `<div>` 元素。`<bdo>` 标签允许显式地控制文本的方向，这使得可以创建复杂的从左到右 (LTR) 和从右到左 (RTL) 的混合文本布局。
* **精确的点击位置模拟：** 每个测试用例都模拟了在特定坐标 (x, y) 的点击。这些坐标被精确地计算出来，以落在嵌套文本段落的特定边缘：
    * `LeftSideOfLeftEdge`: 点击发生在文本段落的最左边边缘的左侧。
    * `RightSideOfLeftEdge`: 点击发生在文本段落的最左边边缘的右侧。
    * `LeftSideOfRightEdge`: 点击发生在文本段落的最右边边缘的左侧。
    * `RightSideOfRightEdge`: 点击发生在文本段落的最右边边缘的右侧。
* **不同基准文本方向：** 测试用例涵盖了两种主要的基准文本方向：
    * `LtrBaseRun`:  最外层的文本方向是从左到右。
    * `RtlBaseRun`:  最外层的文本方向是从右到左。
* **包含和不包含基准文本段落结尾的情况：**  一些测试用例的文本内容包含了 `<bdo>` 标签的结束标记，另一些则没有，以测试不同情况下的边界处理。
* **验证光标位置：** 每个测试用例都断言（使用 `EXPECT_TRUE` 和 `EXPECT_EQ`）点击后光标的最终位置。`GetCaretTextFromBody(result.StartPosition())` 方法用于获取包含当前光标位置的 HTML 字符串，并与预期的字符串进行比较。

**与 Javascript, HTML, CSS 的关系：**

* **HTML:**  这些测试用例大量使用了 HTML 的 `dir` 属性，特别是应用于 `<div>` 和 `<bdo>` 标签。`dir="rtl"` 表示从右到左的文本方向，`dir="ltr"` 表示从左到右的文本方向。`<bdo>` 标签会覆盖其父元素的默认文本方向。
    * **举例:**  `<div dir="rtl"><bdo dir="ltr">abc</bdo></div>`  这段 HTML 会先从右到左渲染 `<div>` 的上下文，但是 `<bdo>` 内部的 "abc" 会强制从左到右渲染，因此视觉上可能显示为 "cba"。
* **CSS:**  测试用例使用了 CSS 来设置字体 (`font: 10px/10px Ahem;`) 和 `<div>` 的宽度 (`width: 300px`)。这些 CSS 属性影响了文本的布局和每个字符的宽度，从而影响了点击位置的计算。
    * **举例:** `width: 300px` 确保了 `<div>` 元素有明确的宽度，以便测试可以针对特定的像素坐标进行点击模拟。字体大小影响了每个字符的像素宽度，这在计算点击位置对应的字符偏移量时至关重要。
* **Javascript:** 虽然这个测试文件本身是用 C++ 编写的，但它测试的功能直接影响了 Javascript 与页面交互的能力。Javascript 可以通过例如 `document.caretRangeFromPoint(x, y)` 方法来获取给定坐标上的光标位置，而这个方法内部的实现就依赖于这里测试的 hit testing 逻辑。
    * **假设输入:** 用户在浏览器中运行的 Javascript 代码调用 `document.caretRangeFromPoint(100, 50)`。
    * **输出:**  浏览器引擎（包括 Blink）会使用 hit testing 逻辑来确定坐标 (100, 50) 落在页面的哪个位置，特别是在有 BiDi 文本的情况下，需要考虑文本的视觉顺序和逻辑顺序，最终返回一个表示该位置的 `Range` 对象。

**逻辑推理的假设输入与输出:**

假设我们有以下 HTML 结构和 CSS：

**HTML:**
```html
<div dir="rtl"><bdo dir="ltr">ghi<bdo dir="rtl">DEF</bdo>jkl</bdo></div>
```

**CSS:**
```css
div { font: 10px/10px Ahem; width: 300px; }
```

**假设输入:** 用户鼠标点击的坐标为 `x = text_left + 33`, `y = div->OffsetTop() + 5`，其中 `text_left` 是考虑到 RTL 布局后计算出的文本左边缘位置。根据测试用例的逻辑，这个 `x` 坐标应该落在 "ghi" 和 "DEF" 之间。

**预期输出:** `GetDocument().caretRangeFromPoint(x, y)` 应该返回一个 `EphemeralRange` 对象，其起始位置对应于 "ghi" 之后，"DEF" 之前的光标位置。`GetCaretTextFromBody(result.StartPosition())` 应该返回类似于以下字符串：

```
"<div dir=\"rtl\"><bdo dir=\"ltr\">ghi|<bdo dir=\"rtl\">DEF</bdo>jkl</bdo></div>"
```

**用户或编程常见的使用错误:**

* **忘记设置 `dir` 属性:** 用户在创建包含 RTL 文本的网页时，可能会忘记在相关的 HTML 元素上设置 `dir="rtl"`。这会导致浏览器按照默认的 LTR 顺序渲染文本，从而出现显示错误和光标定位问题。例如，如果用户想显示 "مرحبا العالم" (阿拉伯语的 "Hello World")，但不设置 `dir="rtl"`，浏览器可能会将其显示为 "العالم مرحبا"。
* **过度或不必要的 `<bdo>` 使用:**  虽然 `<bdo>` 提供了精确控制文本方向的能力，但过度使用可能会使 HTML 结构复杂且难以维护。开发者应该根据实际需要使用，并考虑使用更高级的 CSS 属性，例如 `unicode-bidi` 和 `direction`，来实现更灵活的 BiDi 控制。
* **假设字符宽度一致:**  开发者可能会错误地假设所有字符的宽度都相同，从而在计算点击位置时出现偏差。实际上，不同字体和字符的宽度可能有所不同，特别是对于非拉丁字符。这个测试文件使用 Ahem 字体，这是一个等宽字体，但在实际场景中，引擎需要处理变宽字体的情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户加载包含 BiDi 文本的网页：** 用户在浏览器中打开一个包含阿拉伯语、希伯来语或其他需要从右到左渲染的文本的网页。该网页的 HTML 结构可能包含 `dir` 属性和 `<bdo>` 标签来控制文本方向。
2. **用户尝试在文本中进行编辑或选择：** 用户点击鼠标或者按下方向键，试图在 BiDi 文本中插入光标或选择一段文本。
3. **浏览器接收到鼠标事件：** 操作系统将用户的鼠标点击事件传递给浏览器。
4. **浏览器进行 hit testing：** 浏览器需要确定用户点击的具体位置对应于哪个文本节点和哪个字符偏移量。对于 BiDi 文本，这个过程比较复杂，因为视觉顺序和逻辑顺序可能不同。`blink/renderer/core/editing/HitTestingBidi::ClosestPositionInBidiRun` 等函数会被调用，这些函数内部的逻辑就是这个测试文件所要验证的。
5. **`document.caretRangeFromPoint` 或相关内部方法被调用：**  浏览器内部会调用类似 `document.caretRangeFromPoint` 的方法（或者更底层的 C++ 实现）来将屏幕坐标转换为文本中的位置。
6. **测试用例模拟的场景：**  `hit_testing_bidi_test.cc` 文件中的测试用例模拟了步骤 4 和 5 的过程，通过给定特定的坐标和 HTML 结构，来验证 hit testing 算法在各种 BiDi 场景下的正确性。
7. **调试线索：** 如果在实际网页中，用户发现光标定位不准确或者选择行为异常，开发者可以参考这个测试文件中的用例，分析是否是由于 BiDi 文本处理不当引起的。可以检查 HTML 结构中 `dir` 属性和 `<bdo>` 标签的使用是否正确，并可以使用浏览器的开发者工具来查看元素的渲染顺序和布局信息。如果怀疑是 Blink 引擎的 bug，可以尝试复现测试用例中的场景，并修改测试用例来定位问题。

**归纳一下它的功能 (第 3 部分):**

这部分 `hit_testing_bidi_test.cc` 的功能是**专门测试 Blink 引擎在处理包含嵌套 BiDi 文本段落时，进行精确点击位置判断的能力，尤其关注点击发生在不同 BiDi 文本段落边缘的情况**。它通过模拟各种复杂的 HTML 结构和点击坐标，验证引擎能否正确地将屏幕坐标映射到文本内容中的光标位置。这些测试覆盖了从左到右和从右到左的基准文本方向，以及包含或不包含基准文本段落结尾的不同场景，确保了浏览器在处理复杂的双向文本布局时，用户交互的准确性和一致性。

Prompt: 
```
这是目录为blink/renderer/core/editing/hit_testing_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\">DEF|<bdo dir=\"ltr\">abc</bdo></bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  g h i|a b c F E D j k l
  // Bidi:    2 2 2 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>jkl</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc|</bdo></bdo>jkl</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  j k l F E D a b c|g h i
  // Bidi:    2 2 2 3 3 3 4 4 4 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  j k l F E D a b c|g h i
  // Bidi:    2 2 2 3 3 3 4 4 4 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">jkl<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc</bdo>|DEF</bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  g h i|a b c F E D
  // Bidi:    2 2 2 4 4 4 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\">DEF|<bdo dir=\"ltr\">abc</bdo></bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  g h i|a b c F E D
  // Bidi:    2 2 2 4 4 4 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\">DEF<bdo dir=\"ltr\">abc|</bdo></bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunLeftSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  F E D a b c|g h i
  // Bidi:    3 3 3 4 4 4 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">|abc</bdo>DEF</bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockLtrBaseRunRightSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  F E D a b c|g h i
  // Bidi:    3 3 3 4 4 4 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc</bdo>|DEF</bdo>ghi</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  I H G|C B A d e f L K J
  // Bidi:    1 1 1 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo>|GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfLeftEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  I H G|C B A d e f L K J
  // Bidi:    1 1 1 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  L K J d e f C B A|I H G
  // Bidi:    1 1 1 2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfRightEdgeOftwoNestedRunsWithBaseRunEnd) {
  // Visual:  L K J d e f C B A|I H G
  // Bidi:    1 1 1 2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI|<bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  I H G|C B A d e f
  // Bidi:    1 1 1 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo>|GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfLeftEdgeOftwoNestedRuns) {
  // Visual:  I H G|C B A d e f
  // Bidi:    1 1 1 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC|</bdo>def</bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunLeftSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  d e f C B A|I H G
  // Bidi:    2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 57;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">|ABC</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InRtlBlockRtlBaseRunRightSideOfRightEdgeOftwoNestedRuns) {
  // Visual:  d e f C B A|I H G
  // Bidi:    2 2 2 3 3 3 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int text_left = div->OffsetLeft() + 300 - div->textContent().length() * 10;
  int x = text_left + 63;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"rtl\"><bdo dir=\"rtl\">GHI|<bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual: |C B A d e f I H G j k l
  // Bidi:    3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo>jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual: |C B A d e f I H G j k l
  // Bidi:    3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo>jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  j k l I H G d e f C B A|
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl<bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockAtLineBoundaryRightSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  j k l I H G d e f C B A|
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl<bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual: |C B A d e f I H G
  // Bidi:    3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() - 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual: |C B A d e f I H G
  // Bidi:    3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 3;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryLeftSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  I H G d e f C B A|
  // Bidi:    1 1 1 2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockAtLineBoundaryRightSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  I H G d e f C B A|
  // Bidi:    1 1 1 2 2 2 3 3 3
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  j k l|C B A d e f I H G m n o
  // Bidi:    0 0 0 3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl|<bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo>mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  j k l|C B A d e f I H G m n o
  // Bidi:    0 0 0 3 3 3 2 2 2 1 1 1 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo>mno</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl<bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo>mno</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  m n o I H G d e f C B A|j k l
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno<bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo>jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockLtrBaseRunRightSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  m n o I H G d e f C B A|j k l
  // Bidi:    0 0 0 1 1 1 2 2 2 3 3 3 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>mno<bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">mno<bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>GHI</bdo>|jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  j k l|C B A d e f I H G
  // Bidi:    0 0 0 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl|<bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  j k l|C B A d e f I H G
  // Bidi:    0 0 0 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr>jkl<bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\">jkl<bdo dir=\"rtl\">GHI<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">|ABC</bdo>def</bdo></bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunLeftSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  I H G d e f C B A|j k l
  // Bidi:    1 1 1 2 2 2 3 3 3 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 87;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC|</bdo></bdo>GHI</bdo>jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockLtrBaseRunRightSideOfRightEdgeOfthreeNestedRuns) {
  // Visual:  I H G d e f C B A|j k l
  // Bidi:    1 1 1 2 2 2 3 3 3 0 0 0
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>GHI</bdo>jkl</div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 93;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\">def<bdo "
      "dir=\"rtl\">ABC</bdo></bdo>GHI</bdo>|jkl</div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  L K J|a b c F E D g h i O N M
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo>|ghi</bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfLeftEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  L K J|a b c F E D g h i O N M
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 33;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">MNO<bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">|abc</bdo></bdo>ghi</bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  O N M g h i F E D a b c|L K J
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 117;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\">ghi<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc|</bdo>DEF</bdo></bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(
    HitTestingBidiTest,
    InLtrBlockRtlBaseRunRightSideOfRightEdgeOfthreeNestedRunsWithBaseRunEnd) {
  // Visual:  O N M g h i F E D a b c|L K J
  // Bidi:    1 1 1 2 2 2 3 3 3 4 4 4 1 1 1
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo>MNO</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 123;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\">JKL<bdo dir=\"ltr\">ghi|<bdo "
      "dir=\"rtl\"><bdo dir=\"ltr\">abc</bdo>DEF</bdo></bdo>MNO</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunLeftSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  L K J|a b c F E D g h i
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  SetBodyContent(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo>ghi</bdo>JKL</bdo></div>");
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  int x = div->OffsetLeft() + 27;
  int y = div->OffsetTop() + 5;
  const EphemeralRange result(GetDocument().caretRangeFromPoint(x, y));
  EXPECT_TRUE(result.IsNotNull());
  EXPECT_TRUE(result.IsCollapsed());
  EXPECT_EQ(
      "<div dir=\"ltr\"><bdo dir=\"rtl\"><bdo dir=\"ltr\"><bdo "
      "dir=\"rtl\">DEF<bdo "
      "dir=\"ltr\">abc</bdo></bdo>|ghi</bdo>JKL</bdo></div>",
      GetCaretTextFromBody(result.StartPosition()));
}

TEST_F(HitTestingBidiTest,
       InLtrBlockRtlBaseRunRightSideOfLeftEdgeOfthreeNestedRuns) {
  // Visual:  L K J|a b c F E D g h i
  // Bidi:    1 1 1 4 4 4 3 3 3 2 2 2
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; widt
"""


```