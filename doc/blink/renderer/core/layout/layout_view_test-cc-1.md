Response:
The user wants to understand the functionality of the provided C++ code snippet from `layout_view_test.cc`. This file is part of the Chromium Blink engine and is specifically designed for testing the `LayoutView` class's hit testing functionality.

Here's a breakdown of the thought process to address the request:

1. **Identify the core purpose:** The filename and the test names (`HitTest...`) clearly indicate that this code tests the hit testing mechanism within the Blink layout engine. Hit testing is the process of determining which element on a webpage is located at a specific coordinate.

2. **Analyze the structure:** The code consists of multiple `TEST_P` blocks. Each block sets up a specific HTML structure and then uses `GetLayoutView().HitTest()` to simulate mouse clicks at different coordinates. The `EXPECT_EQ` macros are used to assert the expected results of the hit test (the inner node, the local point within that node, and the text position).

3. **Relate to web technologies:** Hit testing is fundamental to how users interact with web pages. It's directly related to:
    * **JavaScript:** Event listeners rely on hit testing to know which element triggered an event (e.g., `onclick`).
    * **HTML:** The structure of the HTML determines the layout of elements, which in turn influences hit testing results.
    * **CSS:** CSS properties like `position`, `width`, `height`, `margin`, `padding`, `overflow`, and `writing-mode` directly affect the visual layout and, consequently, the hit testing behavior.

4. **Explain with examples:** For each web technology, provide concrete examples from the code snippet that illustrate the relationship. For example, the use of `<div>`, `<span>`, and `<input>` demonstrates HTML structure. The `style` attributes and `<style>` tags showcase CSS. The test assertions indirectly demonstrate how JavaScript event handling would rely on the outcomes of these hit tests.

5. **Address logical reasoning and assumptions:** Each `TEST_P` block inherently involves logical reasoning. The tests assume a specific layout based on the provided HTML and CSS, then predict the hit test results for various input coordinates. Present a clear input (coordinates) and output (hit element, local point, text position) example for one of the test cases. Highlight how different browser behaviors (Android/Windows/ChromeOS vs. others) can lead to variations in expected output.

6. **Identify potential user/programming errors:**  Focus on common mistakes related to HTML and CSS that would lead to unexpected hit testing behavior. Examples include overlapping elements without proper z-index, incorrect positioning, and misunderstanding how scrolling affects coordinates.

7. **Summarize the overall function (for part 2):**  Combine the findings into a concise summary that reiterates the core purpose of the code and its role in the Blink rendering engine.

8. **Review and refine:** Read through the generated response to ensure clarity, accuracy, and completeness. Make sure the examples are easy to understand and directly relate to the code snippet. For instance,  initially, I considered explaining the underlying C++ implementation details of `HitTest`, but decided against it as the focus is on the *functionality* and its relation to web technologies, not the internal implementation. I also made sure to clearly separate the explanations for JavaScript, HTML, and CSS. The examples of logical reasoning were chosen to cover different scenarios within the provided code.

By following these steps, I could generate a comprehensive explanation of the provided C++ code and its significance in the context of web technologies.
这是 `blink/renderer/core/layout/layout_view_test.cc` 文件的第二部分，延续了第一部分的功能介绍。总体来说，这个文件的主要功能是**测试 Blink 渲染引擎中 `LayoutView` 类的 hit testing 功能。**  Hit testing 是指确定用户在屏幕上的某个点点击时，命中了哪个网页元素。

**归纳一下它的功能：**

这部分测试用例继续验证 `LayoutView::HitTest` 方法在各种复杂布局场景下的正确性，包括：

* **垂直方向从右到左 (vertical-rl) 的书写模式：**  测试在这种排版模式下，hit testing 是否能正确识别被点击的元素和对应的文本位置。
* **根元素采用垂直方向书写模式：**  测试当整个文档的根元素使用 `writing-mode: vertical-rl` 时，hit testing 的行为，特别是坐标的转换和边界情况的处理。
* **伪元素 (::after) 的 hit testing：**  测试点击块级元素和行内元素 `::after` 伪元素时的命中结果，包括有 margin 的情况。
* **带有滚动条的块级和行内子元素的 hit testing：**  测试当点击发生在可滚动容器的子元素上时，`scrollTo` 偏移量是否会影响 hit testing 的结果。
* **包含文本和输入框的从右到左 (rtl) 布局：**  测试在 `direction: rtl` 的布局中，hit testing 如何处理文本节点和输入框元素，特别关注文本位置的确定。
* **文本组合 (text-combine-upright)：** 测试当文本使用 `text-combine-upright` 属性进行组合显示时，hit testing 是否能正确识别单个组合字符的文本位置。

**与 JavaScript, HTML, CSS 的功能关系及举例说明：**

如同第一部分，这部分测试用例的功能与 JavaScript, HTML, 和 CSS 都有着密切的关系：

* **HTML:**  测试用例通过 `SetBodyInnerHTML` 设置不同的 HTML 结构，例如包含 `<div>`, `<span>`, `<input>`, `<br>`, `<wbr>` 等元素，以及带有 `id` 属性的元素，以便在测试中进行定位。这些 HTML 结构定义了网页的基本内容和元素的层级关系，是 hit testing 的基础。
    * **举例:** `<div id="div" style="...">...</div>` 创建了一个带有特定样式和 id 的 div 元素，用于后续的 hit testing。

* **CSS:** 测试用例使用 `<style>` 标签或者 `InsertStyleElement` 方法插入 CSS 样式，来控制元素的布局、尺寸、位置、书写模式、滚动行为等。这些 CSS 属性直接影响元素的渲染结果，并决定了 hit testing 的行为。
    * **举例:** `style="position: relative; font: 10px/10px Ahem; top: 100px; left: 50px; width: 200px; height: 80px; writing-mode: vertical-rl"`  定义了一个 div 元素的定位、字体和垂直书写模式，这些都会影响点击该元素时命中的位置。
    * **举例:** `p::after { content: 'XY' }`  定义了一个段落元素的伪元素，测试点击该伪元素时的命中情况。

* **JavaScript:** 虽然这个测试文件本身是 C++ 代码，但它测试的 hit testing 功能是 JavaScript 事件处理的基础。当用户在浏览器中点击一个元素时，浏览器内部会进行 hit testing 来确定哪个元素被点击，然后 JavaScript 的事件监听器才能正确地响应这个点击事件。例如，如果一个 `<div>` 元素绑定了 `onclick` 事件，浏览器需要通过 hit testing 来判断用户点击的位置是否在该 `<div>` 元素的范围内。
    * **隐式举例:**  `GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(61, 101)), result);`  这个 C++ 代码模拟了用户在坐标 (61, 101) 进行点击，而测试的目标是验证在这个点击位置，哪个 HTML 元素应该被命中。这与 JavaScript 事件处理的底层机制是一致的。

**逻辑推理与假设输入输出：**

每个 `TEST_P` 函数都包含一系列的逻辑推理，根据预设的 HTML 结构和 CSS 样式，以及给定的点击坐标，推断出应该命中的元素、局部坐标以及文本位置。

**举例 (来自 `HitTestVerticalRL` 测试用例):**

* **假设输入:** 点击发生在物理坐标 `(51, 101)`。
* **HTML/CSS 上下文:**  一个 `div` 元素，位于 `top: 100px; left: 50px;`，并且使用了 `writing-mode: vertical-rl`。  该 `div` 内部包含两个 `span` 元素。
* **逻辑推理:**  由于 `div` 的左上角坐标是 (50, 100)，点击坐标 (51, 101) 位于 `div` 元素的内部。由于书写模式是垂直从右到左，所以 (51, 101) 对应于 `div` 内部的左上角。
* **预期输出:**
    * `result.InnerNode()` 应该是 `div` 元素。
    * `result.LocalPoint()` 应该是 `PhysicalOffset(1, 1)`，相对于 `div` 元素的局部坐标。
    * `result.GetPosition()` 应该指向 `span1` 元素的起始位置，具体位置会根据不同的平台而有所差异。

**涉及用户或者编程常见的使用错误及举例说明：**

* **CSS 定位错误导致元素重叠，hit testing 结果不符合预期:**  如果开发者使用了错误的 CSS `position` 属性或 `z-index` 值，导致元素在视觉上重叠，用户点击时可能会命中错误的元素。
    * **举例:**  两个 `div` 元素拥有相同的绝对定位，并且完全重叠。用户点击重叠区域时，如果没有适当的 `z-index` 设置，hit testing 的结果可能不稳定，取决于元素在 HTML 结构中的顺序。

* **不理解 `writing-mode` 对 hit testing 的影响:**  开发者可能不清楚 `writing-mode: vertical-rl` 会改变元素的排版方向，导致在垂直书写模式下，对点击位置的理解出现偏差。
    * **举例:**  一个 `div` 使用了 `writing-mode: vertical-rl`，开发者仍然按照从左到右的逻辑来判断点击位置，可能会认为点击左上角会命中某个特定的文本，但实际由于垂直排版，命中的可能是另一部分内容。

* **忽略滚动偏移对坐标的影响:**  当元素存在滚动条时，元素的局部坐标是相对于滚动容器的内容区域的，而不是相对于滚动容器的边框。开发者在进行手动 hit testing 或计算时，需要考虑滚动偏移的影响。
    * **举例:**  一个带有滚动条的 `div`，开发者想判断点击 `div` 的左上角是否会命中某个子元素，如果没有考虑 `div` 的滚动偏移，可能会得到错误的结论。

总之，这个测试文件的第二部分继续深入测试了 Blink 引擎在处理复杂布局和文本排版时的 hit testing 能力，确保浏览器能准确响应用户的点击操作，这对于网页的交互性和用户体验至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
= HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(61, 101)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(11, 1), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Bottom-left corner (outside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 181)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(51, 181), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 3), TextAffinity::kUpstream),
            result.GetPosition());

  // Bottom-left corner (inside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 179)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 79), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 3), TextAffinity::kUpstream),
            result.GetPosition());

  // Top-left corner of span2.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(81, 151)), result);
  EXPECT_EQ(text2, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(31, 51), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 0), TextAffinity::kDownstream),
            result.GetPosition());
}

TEST_P(LayoutViewHitTestTest, HitTestVerticalRL) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id="div" style="position: relative; font: 10px/10px Ahem;
        top: 100px; left: 50px; width: 200px; height: 80px;
        writing-mode: vertical-rl">
      <span id="span1">ABCDE</span><span id="span2"
          style="position: relative; left: -30px">XYZ</span>
    </div>
  )HTML");

  // (50, 100)         (250, 100)
  //   |------------------|
  //   |                 A|
  //   |                 B|
  //   |                 C|
  //   |                 D|
  //   |                 E|
  //   |              X   |
  //   |              Y   |
  //   |              Z   |
  //   |------------------|
  // (50, 180)         (250, 180)
  auto* div = GetElementById("div");
  auto* text1 = GetElementById("span1")->firstChild();
  auto* text2 = GetElementById("span2")->firstChild();

  HitTestResult result;
  // In body, but not in any descendants.
  // XXX1
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(1, 1)), result);
  EXPECT_EQ(GetDocument().body(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 1), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-left corner of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 101)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 1), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-right corner (outside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(251, 101)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(251, 101), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Top-right corner (inside) of div and span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(249, 101)), result);
  EXPECT_EQ(text1, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(199, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Bottom-right corner (inside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(249, 149)), result);
  EXPECT_EQ(text1, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(199, 49), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 5), TextAffinity::kUpstream),
            result.GetPosition());

  // Bottom-right corner (outside) of span1 but inside of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(249, 151)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(199, 51), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Bottom-left corner (outside) of div.
  // XXX2
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 181)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(51, 181), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text2, 3), TextAffinity::kUpstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Bottom-left corner (inside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 179)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 79), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text2, 3), TextAffinity::kUpstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Bottom-left corner (outside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(241, 151)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(191, 51), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Top-right corner (inside) of span2.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(219, 151)), result);
  EXPECT_EQ(text2, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(169, 51), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 0), TextAffinity::kDownstream),
            result.GetPosition());
}

TEST_P(LayoutViewHitTestTest, HitTestVerticalRLRoot) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>
      html { writing-mode: vertical-rl; }
      body { margin: 0 }
    </style>
    <div id="div" style="font: 10px/10px Ahem; width: 200px; height: 80px">
      <span id="span">ABCDE</span>
    </div>
  )HTML");

  // (0,0)     (600, 0)         (800, 0)
  // +----...----+---------------+
  // |           |              A|
  // |           |              B|
  // |           |              C|
  // |           |     (div)    D|
  // | (screen)  |              E|
  // |           |               |
  // |           |               |
  // |           +---------------+ (800, 80)
  // |       (600, 80)           |
  // .                           .
  // +----...--------------------+ (800, 600)

  auto* div = GetElementById("div");
  auto* text = GetElementById("span")->firstChild();
  HitTestResult result;
  // Not in any element. Should fallback to documentElement.
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(1, 1)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(-599, 1), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text, 5), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-left corner (inside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(601, 1)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 1), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text, 5), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-right corner (outside) of div. Should fallback to documentElement.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(801, 1)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(201, 1), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text, 0), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-right corner (inside) of div and span.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(799, 1)), result);
  EXPECT_EQ(text, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(199, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Bottom-right corner (outside) of span1 but inside of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(799, 51)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(199, 51), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text, 5), TextAffinity::kUpstream),
            result.GetPosition());

  // Bottom-left corner (outside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(599, 81)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(-1, 81), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text, 5), TextAffinity::kUpstream)
          : PositionWithAffinity(Position(text, 5), TextAffinity::kDownstream),
      result.GetPosition());
}

// http://crbug.com/1164974
TEST_P(LayoutViewHitTestTest, PseudoElementAfterBlock) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/15px Ahem; }"
      "p::after { content: 'XY' }");
  SetBodyInnerHTML("<div><p id=target>ab</p></div>");
  const auto& text_ab = *To<Text>(GetElementById("target")->firstChild());
  // In legacy layout, this position comes from |LayoutBlock::PositionBox()|
  // for mac/unix, or |LayoutObject::FindPosition()| on
  // android/windows/chromeos.
  const auto expected = PositionWithAffinity(
      IsAndroidOrWindowsOrChromeOSEditingBehavior() ? Position(text_ab, 2)
                                                    : Position(text_ab, 0),
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? TextAffinity::kUpstream
          : TextAffinity::kDownstream);

  EXPECT_EQ(expected, HitTest(20, 5)) << "after ab";
  EXPECT_EQ(expected, HitTest(25, 5)) << "at X";
  EXPECT_EQ(expected, HitTest(35, 5)) << "at Y";
  EXPECT_EQ(expected, HitTest(40, 5)) << "after Y";
  EXPECT_EQ(expected, HitTest(50, 5)) << "after XY";
}

// http://crbug.com/1043471
TEST_P(LayoutViewHitTestTest, PseudoElementAfterInline) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#cd::after { content: 'XYZ'; margin-left: 100px; }");
  SetBodyInnerHTML("<div id=ab>ab<span id=cd>cd</span></div>");
  const auto& text_ab = *To<Text>(GetElementById("ab")->firstChild());
  const auto& text_cd = *To<Text>(GetElementById("cd")->lastChild());

  EXPECT_EQ(PositionWithAffinity(Position(text_ab, 0)), HitTest(5, 5));
  // Because of hit testing at "b", position should be |kDownstream|.
  EXPECT_EQ(
      PositionWithAffinity(Position(text_ab, 1), TextAffinity::kDownstream),
      HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(text_cd, 0)), HitTest(25, 5));
  // Because of hit testing at "d", position should be |kDownstream|.
  EXPECT_EQ(
      PositionWithAffinity(Position(text_cd, 1), TextAffinity::kDownstream),
      HitTest(35, 5));
  // Because of hit testing at right of <span cd>, result position should be
  // |kUpstream|.
  EXPECT_EQ(PositionWithAffinity(Position(text_cd, 2), TextAffinity::kUpstream),
            HitTest(45, 5));
  EXPECT_EQ(PositionWithAffinity(Position(text_cd, 2), TextAffinity::kUpstream),
            HitTest(55, 5));
  EXPECT_EQ(PositionWithAffinity(Position(text_cd, 2), TextAffinity::kUpstream),
            HitTest(65, 5));
}

TEST_P(LayoutViewHitTestTest, PseudoElementAfterBlockWithMargin) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/15px Ahem; }"
      "p::after { content: 'XY'; margin-left: 10px;}");
  SetBodyInnerHTML("<div><p id=target>ab</p></div>");
  const auto& text_ab = *To<Text>(GetElementById("target")->firstChild());
  // In legacy layout, this position comes from |LayoutBlock::PositionBox()|
  // for mac/unix, or |LayoutObject::FindPosition()| on
  // android/windows/chromeos.
  const auto expected = PositionWithAffinity(
      IsAndroidOrWindowsOrChromeOSEditingBehavior() ? Position(text_ab, 2)
                                                    : Position(text_ab, 0),
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? TextAffinity::kUpstream
          : TextAffinity::kDownstream);

  EXPECT_EQ(expected, HitTest(20, 5)) << "after ab";
  EXPECT_EQ(expected, HitTest(25, 5)) << "at margin-left";
  EXPECT_EQ(expected, HitTest(30, 5)) << "before X";
  EXPECT_EQ(expected, HitTest(35, 5)) << "at X";
  EXPECT_EQ(expected, HitTest(45, 5)) << "at Y";
  EXPECT_EQ(expected, HitTest(50, 5)) << "after Y";
  EXPECT_EQ(expected, HitTest(55, 5)) << "after XY";
}

// http://crbug.com/1268782
TEST_P(LayoutViewHitTestTest, ScrolledBlockChildren) {
  LoadAhem();
  InsertStyleElement(R"CSS(
    body {
      margin: 0px;
      font: 10px/15px Ahem;
    }
    #sample { height: 60px; overflow: scroll; }
  )CSS");
  SetBodyInnerHTML(
      "<div id=sample>"
      "0<br>1<br>2<br><b id=four>4</b><br><b id=five>5</b><br>"
      "<div id=x>X</div>"
      "<b id=six>6</b><br>7<br>8<br>9<br>"
      "</div>");

  Element& sample = *GetElementById("sample");
  sample.scrollTo(0, 45);

  const auto& text_4 = *To<Text>(GetElementById("four")->firstChild());
  const auto& text_5 = *To<Text>(GetElementById("five")->firstChild());
  const auto& text_6 = *To<Text>(GetElementById("six")->firstChild());
  const auto& text_x = *To<Text>(GetElementById("x")->firstChild());

  EXPECT_EQ(PositionWithAffinity(Position(text_4, 1), TextAffinity::kUpstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(text_5, 1), TextAffinity::kUpstream),
            HitTest(15, 15));
  EXPECT_EQ(PositionWithAffinity(Position(text_5, 1), TextAffinity::kUpstream),
            HitTest(15, 25));
  EXPECT_EQ(PositionWithAffinity(Position(text_x, 1), TextAffinity::kUpstream),
            HitTest(15, 35));
  EXPECT_EQ(PositionWithAffinity(Position(text_6, 1), TextAffinity::kUpstream),
            HitTest(15, 45));
  EXPECT_EQ(PositionWithAffinity(Position(text_6, 1), TextAffinity::kUpstream),
            HitTest(15, 55));
}

// See also "editing/selection/click-in-padding-with-multiple-line-boxes.html"
TEST_P(LayoutViewHitTestTest, ScrolledInlineChildren) {
  LoadAhem();
  InsertStyleElement(R"CSS(
    body {
      margin: 0px;
      font: 10px/15px Ahem;
    }
    #sample {
      overflow: scroll;
      padding-bottom: 10px;
      padding-top: 10px;
      white-space: nowrap;
      width: 60px;
    }
  )CSS");
  SetBodyInnerHTML("<div id=sample>012345678</div>");

  Element& sample = *GetElementById("sample");
  sample.scrollTo(20, 0);

  const auto& text = *To<Text>(sample.firstChild());

  if (IsAndroidOrWindowsOrChromeOSEditingBehavior()) {
    EXPECT_EQ(PositionWithAffinity(Position(text, 2)), HitTest(5, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 2)), HitTest(5, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 2)), HitTest(5, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 3)), HitTest(15, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 3)), HitTest(15, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 3)), HitTest(15, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 4)), HitTest(25, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 4)), HitTest(25, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 4)), HitTest(25, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 5)), HitTest(35, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 5)), HitTest(35, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 5)), HitTest(35, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 6)), HitTest(45, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 6)), HitTest(45, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 6)), HitTest(45, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 7)), HitTest(55, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 7)), HitTest(55, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 7)), HitTest(55, 25));
  } else {
    EXPECT_EQ(PositionWithAffinity(Position(text, 0)), HitTest(5, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 2)), HitTest(5, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 9)), HitTest(5, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 0)), HitTest(15, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 3)), HitTest(15, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 9)), HitTest(15, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 0)), HitTest(25, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 4)), HitTest(25, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 9)), HitTest(25, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 0)), HitTest(35, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 5)), HitTest(35, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 9)), HitTest(35, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 0)), HitTest(45, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 6)), HitTest(45, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 9)), HitTest(45, 25));

    EXPECT_EQ(PositionWithAffinity(Position(text, 0)), HitTest(55, 5));
    EXPECT_EQ(PositionWithAffinity(Position(text, 7)), HitTest(55, 15));
    EXPECT_EQ(PositionWithAffinity(Position(text, 9)), HitTest(55, 25));
  }
}

TEST_P(LayoutViewHitTestTest, TextAndInputsWithRtlDirection) {
  LoadAhem();
  InsertStyleElement(R"CSS(
    body {
      margin: 0 auto 0 0;
      direction: rtl;
      width: 200px;
      font: 50px/1 Ahem;
    }
    input {
      width: 100px;
      height: 50px;
      box-sizing: border-box;
      vertical-align: top;
    }
  )CSS");
  SetBodyInnerHTML("ab<input><input>cd");

  Element* body = GetDocument().body();
  Node* text_ab = body->firstChild();
  Node* input_1 = text_ab->nextSibling();
  Node* input_2 = input_1->nextSibling();
  Node* text_cd = input_2->nextSibling();
  Node* shadow_div_1 = input_1->GetShadowRoot()->firstChild();
  Node* shadow_div_2 = input_2->GetShadowRoot()->firstChild();
  TextAffinity downstream_if_ng = TextAffinity::kDownstream;

  // Note: This is a crash test. The expectations only reflect the current
  // behavior, which may change.
  for (int y : {0, 25, 49}) {
    for (int x : {0, 25}) {
      EXPECT_EQ(PositionWithAffinity(Position::AfterNode(*input_1),
                                     TextAffinity::kUpstream),
                HitTest(x, y));
    }
    for (int x : {26, 50, 75}) {
      EXPECT_EQ(PositionWithAffinity(Position(text_ab, 1), downstream_if_ng),
                HitTest(x, y));
    }
    for (int x : {76, 99}) {
      EXPECT_EQ(
          PositionWithAffinity(Position(text_ab, 2), TextAffinity::kUpstream),
          HitTest(x, y));
    }
    for (int x : {100, 125, 150, 175, 199}) {
      EXPECT_EQ(PositionWithAffinity(Position(shadow_div_1, 0)), HitTest(x, y));
    }
    EXPECT_EQ(PositionWithAffinity(Position::AfterNode(*input_1)),
              HitTest(200, y));
  }
  for (int y : {50, 75, 99}) {
    for (int x : {0, 25, 50, 75, 99}) {
      EXPECT_EQ(PositionWithAffinity(Position(shadow_div_2, 0)), HitTest(x, y));
    }
    for (int x : {100, 125}) {
      EXPECT_EQ(PositionWithAffinity(Position(text_cd, 0)), HitTest(x, y));
    }
    for (int x : {126, 150, 175}) {
      EXPECT_EQ(PositionWithAffinity(Position(text_cd, 1), downstream_if_ng),
                HitTest(x, y));
    }
    for (int x : {176, 200}) {
      EXPECT_EQ(PositionWithAffinity(Position::BeforeNode(*input_2)),
                HitTest(x, y));
    }
  }
  if (IsAndroidOrWindowsOrChromeOSEditingBehavior()) {
    for (int x : {0, 25, 50, 75, 99}) {
      EXPECT_EQ(PositionWithAffinity(Position::AfterNode(*input_2)),
                HitTest(x, 100));
    }
    for (int x : {100, 125}) {
      EXPECT_EQ(PositionWithAffinity(Position(text_cd, 0)), HitTest(x, 100));
    }
    for (int x : {126, 150, 175}) {
      EXPECT_EQ(PositionWithAffinity(Position(text_cd, 1), downstream_if_ng),
                HitTest(x, 100));
    }
    for (int x : {176, 200}) {
      EXPECT_EQ(PositionWithAffinity(Position::BeforeNode(*input_2)),
                HitTest(x, 100));
    }
  } else {
    for (int x : {0, 25, 50, 75, 100, 125, 150, 175, 200}) {
      EXPECT_EQ(PositionWithAffinity(Position::AfterNode(*input_2)),
                HitTest(x, 100));
    }
  }
}

TEST_P(LayoutViewHitTestTest, TextCombineOneTextNode) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div>a<c id=target>01234</c>b</div>");
  //  LayoutBlockFlow {HTML} at (0,0) size 800x600
  //    LayoutBlockFlow {BODY} at (0,0) size 800x600
  //      LayoutBlockFlow {DIV} at (0,0) size 110x300
  //        LayoutText {#text} at (5,0) size 100x100
  //          text run at (5,0) width 100: "a"
  //        LayoutInline {C} at (5,100) size 100x100
  //          LayoutTextCombine (anonymous) at (5,100) size 100x100
  //            LayoutText {#text} at (-5,0) size 110x100
  //              text run at (0,0) width 500: "01234"
  //        LayoutText {#text} at (5,200) size 100x100
  //          text run at (5,200) width 100: "b"
  const auto& target = *GetElementById("target");
  const auto& text_01234 = *To<Text>(target.firstChild());
  const auto& text_a = *To<Text>(target.previousSibling());
  const auto& text_b = *To<Text>(target.nextSibling());

  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 0)), HitTest(0, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 0)), HitTest(10, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 1)), HitTest(20, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 1)), HitTest(30, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 2)), HitTest(40, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 2)), HitTest(50, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 3)), HitTest(60, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 3)), HitTest(70, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 4)), HitTest(80, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_01234, 4)), HitTest(90, 150));
  EXPECT_EQ(
      PositionWithAffinity(Position(text_01234, 5), TextAffinity::kUpstream),
      HitTest(100, 150));
  // TODO(yosin): should be text_01234@5
  if (IsAndroidOrWindowsOrChromeOSEditingBehavior()) {
    EXPECT_EQ(PositionWithAffinity(Position(text_b, 0)), HitTest(110, 150));
    EXPECT_EQ(PositionWithAffinity(Position(text_b, 0)), HitTest(120, 150));
  } else {
    EXPECT_EQ(PositionWithAffinity(Position(text_a, 0)), HitTest(110, 150));
    EXPECT_EQ(PositionWithAffinity(Position(text_a, 0)), HitTest(120, 150));
  }
}

TEST_P(LayoutViewHitTestTest, TextCombineTwoTextNodes) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 100px/110px Ahem; }"
      "c { text-combine-upright: all; }"
      "div { writing-mode: vertical-rl; }");
  SetBodyInnerHTML("<div>a<c id=target>012<wbr>34</c>b</div>");
  //   LayoutBlockFlow {HTML} at (0,0) size 800x600
  //     LayoutBlockFlow {BODY} at (0,0) size 800x600
  //       LayoutBlockFlow {DIV} at (0,0) size 110x300
  //         LayoutText {#text} at (5,0) size 100x100
  //           text run at (5,0) width 100: "a"
  //         LayoutInline {C} at (5,100) size 100x100
  //           LayoutTextCombine (anonymous) at (5,100) size 100x100
  //             LayoutText {#text} at (-5,0) size 66x100
  //               text run at (0,0) width 300: "012"
  //             LayoutWordBreak {WBR} at (61,0) size 0x100
  //               text run at (300,0) width 0: "\x{200B}"
  //             LayoutText {#text} at (61,0) size 44x100
  //               text run at (300,0) width 200: "34"
  //         LayoutInline {B} at (5,200) size 100x100
  //           LayoutText {#text} at (5,200) size 100x100
  //             text run at (5,200) width 100: "b"
  //   const auto& target = *GetElementById("target");
  const auto& target = *GetElementById("target");
  const auto& text_012 = *To<Text>(target.firstChild());
  const auto& text_34 = *To<Text>(target.lastChild());
  const auto& text_a = *To<Text>(target.previousSibling());
  const auto& text_b = *To<Text>(target.nextSibling());

  EXPECT_EQ(PositionWithAffinity(Position(text_012, 0)), HitTest(0, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 0)), HitTest(10, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 1)), HitTest(20, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 1)), HitTest(30, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 2)), HitTest(40, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_012, 2)), HitTest(50, 150));
  EXPECT_EQ(
      PositionWithAffinity(Position(text_012, 3), TextAffinity::kUpstream),
      HitTest(60, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_34, 0)), HitTest(70, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_34, 1)), HitTest(80, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_34, 1)), HitTest(90, 150));
  EXPECT_EQ(PositionWithAffinity(Position(text_34, 2), TextAffinity::kUpstream),
            HitTest(100, 150));
  // TODO(yosin): should be text_012@5
  if (IsAndroidOrWindowsOrChromeOSEditingBehavior()) {
    EXPECT_EQ(PositionWithAffinity(Position(text_b, 0)), HitTest(110, 150));
    EXPECT_EQ(PositionWithAffinity(Position(text_b, 0)), HitTest(120, 150));
  } else {
    EXPECT_EQ(PositionWithAffinity(Position(text_a, 0)), HitTest(110, 150));
    EXPECT_EQ(PositionWithAffinity(Position(text_a, 0)), HitTest(120, 150));
  }
}

}  // namespace blink

"""


```