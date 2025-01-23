Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code appears to be a series of unit tests for a function called `LocalCaretRectOfPosition`. The tests seem to focus on the positioning of the text caret (the blinking cursor) in HTML content that involves bidirectional text (text that reads from left-to-right and right-to-left).

Here's a plan:
1. **Identify the core functionality:** The code tests the position of the caret in various bidirectional text scenarios.
2. **Explain the relationship to web technologies:** Bidirectional text is important for supporting languages like Arabic and Hebrew in HTML, CSS, and JavaScript.
3. **Infer the logic:** The tests manipulate HTML structure with `dir` attributes and check the resulting caret position.
4. **Identify potential user errors:**  Incorrectly using `dir` attributes can lead to unexpected caret behavior.
5. **Describe the user journey:**  A user editing text in a web page with bidirectional content triggers this code.
6. **Summarize the functionality:**  The code tests the correct calculation of the caret's position in complex bidirectional text layouts.
这是对C++代码片段的功能总结，该代码片段是针对 Chromium Blink 引擎中 `LocalCaretRectOfPosition` 函数的单元测试。这个函数用于计算在具有双向文本 (BiDi) 的复杂布局中，光标（caret）的物理矩形位置。

**功能归纳:**

该代码片段的主要功能是 **测试在不同双向文本排列和嵌套情况下，光标位置计算的准确性**。它通过创建包含不同 `dir` 属性的 HTML 结构，然后在特定位置设置光标，并验证 `LocalCaretRectOfPosition` 函数返回的物理矩形是否符合预期。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML (`dir` 属性):**  这些测试大量使用了 HTML 的 `dir` 属性，该属性用于指定元素内文本的方向。`dir="rtl"` 表示从右到左，`dir="ltr"` 表示从左到右。`<b>` 和 `<bdo>` 标签也被用于创建具有特定方向性的文本段。
    * **举例:** `<div dir="rtl">` 定义了一个从右到左的文本块。 `<bdo dir="ltr">`  强制其包含的文本按从左到右的方向显示，即使其父元素的 `dir` 属性是 `rtl`。
* **CSS (布局和字体):** 测试中使用了 CSS 样式来设置字体 (`Ahem`) 和容器宽度，这影响了文本的渲染和光标的位置。
    * **举例:** `InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");` 设置了用于测试的 div 元素的字体和宽度，确保测试结果的可预测性。
* **JavaScript (间接关系):** 虽然这段代码是 C++ 编写的单元测试，但它测试的功能直接影响到用户在网页上使用 JavaScript 进行文本编辑时的光标行为。当用户通过 JavaScript 操作 DOM 或输入文本时，浏览器需要正确计算光标的位置，而 `LocalCaretRectOfPosition` 函数就是这个计算过程的一部分。

**逻辑推理 (假设输入与输出):**

这些测试的逻辑是基于对 BiDi 算法的理解。BiDi 算法决定了在混合了从左到右和从右到左文本时，文本是如何视觉上排序的。

* **假设输入:**
    * 包含不同 `dir` 属性嵌套的 HTML 字符串，例如 `<div dir=rtl><bdo dir=ltr>abc|</bdo>DEF</div>`。
    * 一个指定光标位置的 `Position` 对象，通常位于文本节点中的特定字符之后或之前。
    * `TextAffinity::kDownstream` 或其他表示光标吸附性的值。
* **预期输出:**
    * 一个 `PhysicalRect` 对象，表示光标在页面上的物理位置 (x, y, width, height)。例如 `PhysicalRect(270, 0, 1, 10)` 表示光标的左上角坐标是 (270, 0)，宽度是 1 像素，高度是 10 像素。

**用户或编程常见的使用错误:**

* **`dir` 属性使用不当:** 开发者可能会错误地使用 `dir` 属性，导致 BiDi 文本显示或光标定位不正确。
    * **举例:**  在一段从右到左的文本中，忘记为嵌入的英文段落设置 `dir="ltr"`，会导致英文文本也从右向左排列。
* **嵌套方向性上下文理解不足:**  BiDi 规则在嵌套元素中可能会变得复杂。开发者可能难以预测在多层嵌套的 `dir` 属性影响下，文本的最终视觉顺序和光标位置。
    * **举例:**  在一个 `dir="rtl"` 的 `div` 中嵌套一个 `bdo dir="ltr"`，再嵌套一个 `bdo dir="rtl"`，需要仔细考虑每一层方向性的影响。
* **忽略 `bdo` 标签的作用:**  `bdo` (bidirectional override) 标签会强制文本按指定的方向显示，忽略周围的 BiDi 上下文。不理解 `bdo` 的作用可能导致布局混乱。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户在支持 BiDi 文本的网页上进行文本编辑:**  用户可能正在输入或修改包含阿拉伯语、希伯来语等从右到左书写语言，或者包含混合了从左到右和从右到左语言的文本。
2. **光标移动或文本插入/删除:**  当用户移动光标 (通过键盘方向键、鼠标点击等) 或进行文本插入/删除操作时，浏览器需要重新计算光标的准确位置。
3. **浏览器引擎触发布局和渲染:**  用户的操作会触发浏览器引擎的布局和渲染过程。
4. **`LocalCaretRectOfPosition` 函数被调用:**  在布局过程中，为了确定光标的视觉位置，浏览器引擎会调用 `LocalCaretRectOfPosition` 函数，传入当前光标的逻辑位置和相关上下文信息。
5. **该函数根据 BiDi 规则和布局信息计算光标的物理矩形:**  这个函数会考虑文本的方向性、字符宽度、行高等因素，计算出光标在屏幕上的精确位置和大小。
6. **单元测试验证计算结果的正确性:**  `local_caret_rect_bidi_test.cc` 文件中的单元测试正是为了确保 `LocalCaretRectOfPosition` 函数在各种复杂的 BiDi 场景下都能正确计算光标位置，从而保证用户编辑体验的准确性。

**总结来说，这个代码片段是 Blink 引擎中一个重要的单元测试文件，用于验证在处理双向文本时，光标位置计算逻辑的正确性，这直接关系到用户在网页上编辑混合方向文本时的体验。**

### 提示词
```
这是目录为blink/renderer/core/editing/local_caret_rect_bidi_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
"dir=rtl>ABC|</bdo></bdo></bdo>jkl</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(180, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunAfterFourNestedRuns) {
  // Sample: J K L g h i D E F a b c|m n o
  // Bidi:   3 3 3 4 4 4 5 5 5 6 6 6 2 2 2
  // Visual:|g h i a b c F E D L K J m n o
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo "
      "dir=rtl>DEF<bdo dir=ltr>abc</bdo></bdo></bdo></bdo>|mno</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(150, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunAfterFourNestedRunsAtDeepPosition) {
  // Sample: J K L g h i D E F a b c|m n o
  // Bidi:   3 3 3 4 4 4 5 5 5 6 6 6 2 2 2
  // Visual:|g h i a b c F E D L K J m n o
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo "
      "dir=rtl>DEF<bdo dir=ltr>abc|</bdo></bdo></bdo></bdo>mno</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(180, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunBeforeRtlRunTouchingLineBoundary) {
  // Sample: d e f|A B C
  // Bidi:   2 2 2 3 3 3
  // Visual: d e f C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>def|<bdo dir=rtl>ABC</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunBeforeRtlRun) {
  // Sample: d e f|A B C g h i
  // Bidi:   2 2 2 3 3 3 2 2 2
  // Visual: d e f C B A|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>def|<bdo dir=rtl>ABC</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunBeforeRtlRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: d e f|A B C
  // Bidi:   2 2 2 3 3 3
  // Visual: d e f C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>def<bdo dir=rtl>|ABC</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunBeforeRtlRunAtDeepPosition) {
  // Sample: d e f|A B C g h i
  // Bidi:   2 2 2 3 3 3 2 2 2
  // Visual: d e f C B A|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>def<bdo dir=rtl>|ABC</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunBeforeTwoNestedRuns) {
  // Sample: g h i|a b c D E F
  // Bidi:   2 2 2 4 4 4 3 3 3
  // Visual: g h i F E D a b c|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>ghi|<bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunBeforeTwoNestedRunsAtDeepPosition) {
  // Sample: g h i|a b c D E F
  // Bidi:   2 2 2 4 4 4 3 3 3
  // Visual: g h i F E D a b c|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunBeforeThreeNestedRuns) {
  // Sample: j k l|A B C d e f G H I
  // Bidi:   2 2 2 5 5 5 4 4 4 3 3 3
  // Visual: j k l I H G C B A d e f|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>jkl|<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo>GHI</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunBeforeThreeNestedRunsAtDeepPosition) {
  // Sample: j k l|A B C d e f G H I
  // Bidi:   2 2 2 5 5 5 4 4 4 3 3 3
  // Visual: j k l I H G C B A d e f|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>|ABC</bdo>def</bdo>GHI</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLtrBaseRunBeforeFourNestedRuns) {
  // Sample: m n o|a b c D E F g h i J K L
  // Bidi:   2 2 2 6 6 6 5 5 5 4 4 4 3 3 3
  // Visual: m n o L K J F E D a b c|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>mno|<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl><bdo dir=ltr>abc</bdo>DEF</bdo>ghi</bdo>JKL</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLtrBaseRunBeforeFourNestedRunsAtDeepPosition) {
  // Sample: m n o|a b c D E F g h i J K L
  // Bidi:   2 2 2 6 6 6 5 5 5 4 4 4 3 3 3
  // Visual: m n o L K J F E D a b c|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr>mno<bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl><bdo dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo>JKL</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunAfterLtrRunTouchingLineBoundary) {
  // Sample: a b c|D E F
  // Bidi:   2 2 2 1 1 1
  // Visual: F E D|a b c
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc</bdo>|DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunAfterLtrRun) {
  // Sample: G H I a b c|D E F
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: F E D|a b c I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>abc</bdo>|DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunAfterLtrRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: a b c|D E F
  // Bidi:   2 2 2 1 1 1
  // Visual: F E D|a b c
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>abc|</bdo>DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunAfterLtrRunAtDeepPosition) {
  // Sample: G H I a b c|D E F
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: F E D|a b c I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr>abc|</bdo>DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunAfterTwoNestedRuns) {
  // Sample: d e f A B C|G H I
  // Bidi:   2 2 2 3 3 3 1 1 1
  // Visual: I H G|d e f C B A
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC</bdo></bdo>|GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunAfterTwoNestedRunsAtDeepPosition) {
  // Sample: d e f A B C|G H I
  // Bidi:   2 2 2 3 3 3 1 1 1
  // Visual: I H G|d e f C B A
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>def<bdo "
      "dir=rtl>ABC|</bdo></bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunAfterThreeNestedRuns) {
  // Sample: g h i D E F a b c|J K L
  // Bidi:   2 2 2 3 3 3 4 4 4 1 1 1
  // Visual: L K J|g h i a b c F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc</bdo></bdo></bdo>|JKL</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(210, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunAfterThreeNestedRunsAtDeepPosition) {
  // Sample: g h i D E F a b c|J K L
  // Bidi:   2 2 2 3 3 3 4 4 4 1 1 1
  // Visual: L K J|g h i a b c F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo></bdo>JKL</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunAfterFourNestedRuns) {
  // Sample: j k l G H I d e f A B C|M N O
  // Bidi:   2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  // Visual: O N M|j k l d e f C B A I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr>def<bdo dir=rtl>ABC</bdo></bdo></bdo></bdo>|MNO</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(180, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunAfterFourNestedRunsAtDeepPosition) {
  // Sample: j k l G H I d e f A B C|M N O
  // Bidi:   2 2 2 3 3 3 4 4 4 5 5 5 1 1 1
  // Visual: O N M|j k l d e f C B A I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo "
      "dir=ltr>def<bdo dir=rtl>ABC|</bdo></bdo></bdo></bdo>MNO</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(210, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunBeforeLtrRunTouchingLineBoundary) {
  // Sample: D E F|a b c
  // Bidi:   1 1 1 2 2 2
  // Visual: a b c|F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>DEF|<bdo dir=ltr>abc</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunBeforeLtrRun) {
  // Sample: D E F|a b c G H I
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: I H G a b c|F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>DEF|<bdo dir=ltr>abc</bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunBeforeLtrRunTouchingLineBoundaryAtDeepPosition) {
  // Sample: D E F|a b c
  // Bidi:   1 1 1 2 2 2
  // Visual: a b c|F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>|abc</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunBeforeLtrRunAtDeepPosition) {
  // Sample: D E F|a b c G H I
  // Bidi:   1 1 1 2 2 2 1 1 1
  // Visual: I H G a b c|F E D
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>DEF<bdo dir=ltr>|abc</bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunBeforeTwoNestedRuns) {
  // Sample: G H I|A B C d e f
  // Bidi:   1 1 1 3 3 3 2 2 2
  // Visual: C B A d e f|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>GHI|<bdo dir=ltr><bdo "
      "dir=rtl>ABC</bdo>def</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunBeforeTwoNestedRunsAtDeepPosition) {
  // Sample: G H I|A B C d e f
  // Bidi:   1 1 1 3 3 3 2 2 2
  // Visual: C B A d e f|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>GHI<bdo dir=ltr><bdo "
      "dir=rtl>|ABC</bdo>def</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunBeforeThreeNestedRuns) {
  // Sample: J K L|a b c D E F g h i
  // Bidi:   1 1 1 4 4 4 3 3 3 2 2 2
  // Visual: F E D a b c|g h i L K J
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>JKL|<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunBeforeThreeNestedRunsAtDeepPosition) {
  // Sample: J K L|a b c D E F g h i
  // Bidi:   1 1 1 4 4 4 3 3 3 2 2 2
  // Visual: F E D a b c|g h i L K J
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>JKL<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockRtlBaseRunBeforeFourNestedRuns) {
  // Sample: M N O|A B C d e f G H I j k l
  // Bidi:   1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  // Visual: I H G C B A d e f|j k l O N M
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>MNO|<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr><bdo dir=rtl>ABC</bdo>def</bdo>GHI</bdo>jkl</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(270, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockRtlBaseRunBeforeFourNestedRunsAtDeepPosition) {
  // Sample: M N O|A B C d e f G H I j k l
  // Bidi:   1 1 1 5 5 5 4 4 4 3 3 3 2 2 2
  // Visual: I H G C B A d e f|j k l O N M
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=rtl>MNO<bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr><bdo dir=rtl>|ABC</bdo>def</bdo>GHI</bdo>jkl</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(240, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineBeginLtrBaseRunWithTwoNestedRuns) {
  // Sample:|A B C d e f
  // Bidi:   1 1 1 0 0 0
  // Visual:|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl>|ABC</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLineBeginLtrBaseRunWithThreeNestedRuns) {
  // Sample:|a b c D E F g h i
  // Bidi:   2 2 2 1 1 1 0 0 0
  // Visual:|F E D a b c g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLineBeginLtrBaseRunWithFourNestedRuns) {
  // Sample:|A B C d e f G H I j k l
  // Bidi:   3 3 3 2 2 2 1 1 1 0 0 0
  // Visual: I H G|C B A d e f j k l
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>|ABC</bdo>def</bdo>GHI</bdo>jkl</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineEndLtrBaseRunWithTwoNestedRuns) {
  // Sample: d e f A B C|
  // Bidi:   0 0 0 1 1 1
  // Visual: d e f C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>def<bdo dir=rtl>ABC|</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineEndLtrBaseRunWithThreeNestedRuns) {
  // Sample: g h i D E F a b c|
  // Bidi:   0 0 0 1 1 1 2 2 2
  // Visual: g h i a b c F E D|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineEndLtrBaseRunWithFourNestedRuns) {
  // Sample: j k l G H I d e f A B C|
  // Bidi:   0 0 0 1 1 1 2 2 2 3 3 3
  // Visual: j k l d e f C B A|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=ltr>jkl<bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC|</bdo></bdo></bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineBeginWithRtlRunOnly) {
  // Sample:|A B C
  // Bidi:   1 1 1
  // Visual:|C B A
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position =
      SetCaretTextToBody("<div dir=ltr><bdo dir=rtl>|ABC</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineBeginRtlBaseRunWithTwoNestedRuns) {
  // Sample:|a b c D E F
  // Bidi:   2 2 2 1 1 1
  // Visual:|F E D a b c
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr>|abc</bdo>DEF</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(0, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLineBeginRtlBaseRunWithThreeNestedRuns) {
  // Sample:|A B C d e f G H I
  // Bidi:   3 3 3 2 2 2 1 1 1
  // Visual: I H G|C B A d e f
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo "
      "dir=rtl>|ABC</bdo>def</bdo>GHI</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InLtrBlockLineBeginRtlBaseRunWithFourNestedRuns) {
  // Sample:|a b c D E F g h i J K L
  // Bidi:   4 4 4 3 3 3 2 2 2 1 1 1
  // Visual: L K J|F E D a b c g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo>JKL</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineEndWithRtlRunOnly) {
  // Sample: A B C|
  // Bidi:   1 1 1
  // Visual: C B A|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position =
      SetCaretTextToBody("<div dir=ltr><bdo dir=rtl>ABC|</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(30, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineEndRtlBaseRunWithTwoNestedRuns) {
  // Sample: D E F a b c|
  // Bidi:   1 1 1 2 2 2
  // Visual: a b c F E D|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>DEF<bdo dir=ltr>abc|</bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineEndRtlBaseRunWithThreeNestedRuns) {
  // Sample: G H I d e f A B C|
  // Bidi:   1 1 1 2 2 2 3 3 3
  // Visual: d e f C B A|I H G
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>GHI<bdo dir=ltr>def<bdo "
      "dir=rtl>ABC|</bdo></bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(60, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InLtrBlockLineEndRtlBaseRunWithFourNestedRuns) {
  // Sample: J K L g h i D E F a b c|
  // Bidi:   1 1 1 2 2 2 3 3 3 4 4 4
  // Visual: g h i a b c F E D|L K J
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=ltr><bdo dir=rtl>JKL<bdo dir=ltr>ghi<bdo dir=rtl>DEF<bdo "
      "dir=ltr>abc|</bdo></bdo></bdo></bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(90, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLineBeginWithLtrRunOnly) {
  // Sample:|a b c
  // Bidi:   2 2 2
  // Visual: a b c|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position =
      SetCaretTextToBody("<div dir=rtl><bdo dir=ltr>|abc</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest, InRtlBlockLineBeginLtrBaseRunWithTwoNestedRuns) {
  // Sample:|A B C d e f
  // Bidi:   3 3 3 2 2 2
  // Visual: C B A d e f|
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl>|ABC</bdo>def</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
                                                    TextAffinity::kDownstream);
  EXPECT_EQ(PhysicalRect(299, 0, 1, 10),
            LocalCaretRectOfPosition(position_with_affinity).rect);
}

TEST_F(LocalCaretRectBidiTest,
       InRtlBlockLineBeginLtrBaseRunWithThreeNestedRuns) {
  // Sample:|a b c D E F g h i
  // Bidi:   4 4 4 3 3 3 2 2 2
  // Visual: F E D a b c|g h i
  LoadAhem();
  InsertStyleElement("div {font: 10px/10px Ahem; width: 300px}");
  const Position position = SetCaretTextToBody(
      "<div dir=rtl><bdo dir=ltr><bdo dir=rtl><bdo "
      "dir=ltr>|abc</bdo>DEF</bdo>ghi</bdo></div>");
  const PositionWithAffinity position_with_affinity(position,
```