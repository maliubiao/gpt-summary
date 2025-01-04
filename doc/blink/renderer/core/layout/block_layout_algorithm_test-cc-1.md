Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a test file for the Chromium Blink engine. The file path `blink/renderer/core/layout/block_layout_algorithm_test.cc` strongly suggests it tests the block layout algorithm.

Here's a breakdown of the request and how to approach it:

1. **Overall Functionality:** Identify the primary purpose of the code. Given the file name and the content, it's clear this code tests different aspects of the block layout algorithm in Blink.

2. **Relationship to Web Technologies (JavaScript, HTML, CSS):** Look for code that simulates or directly tests how HTML elements with CSS styles are laid out. Examples include setting HTML content, applying styles, and then verifying the resulting positions and sizes of elements.

3. **Logical Reasoning (Input/Output):** Analyze individual test cases. Each `TEST_F` function represents a specific scenario being tested. Identify the setup (HTML and CSS), the assertion being made (`EXPECT_EQ`, `EXPECT_THAT`), and infer the intended input and output of the layout algorithm for that scenario.

4. **Common User/Programming Errors:** Consider what kinds of layout issues developers might encounter. The tests often cover edge cases or specific behaviors that might lead to unexpected results if not handled correctly by the layout algorithm.

5. **Part 2 of 3:** Acknowledge this and provide a summary based on the provided code *only*. Don't speculate about what might be in the other parts.

**Mental Walkthrough of the Code Snippet:**

* **Float Positioning and Interaction:** The first set of tests revolves around how elements interact with floats. It tests scenarios involving margins, absolute positioning, and inflow elements around floats. The `run_test` function likely sets up different margin configurations.

* **New Formatting Contexts and Auto Margins:** The `NewFormattingContextAutoMargins` test focuses on how auto margins are resolved within a new formatting context, particularly when floats are involved.

* **Border and Padding:** The `BorderAndPadding` test verifies that the layout algorithm correctly includes borders and padding when calculating an element's size and positions child elements within the content box.

* **Percentage Sizing:** The `PercentageResolutionSize` test checks how percentage-based widths are calculated relative to the parent container.

* **Auto Margins (Simple Case):** The `AutoMargin` test provides a basic verification of auto margin behavior.

* **Floats in Nested Empty Blocks:** The `PositionFloatInsideEmptyBlocks` test deals with the positioning of floats within nested empty divs, focusing on margin collapsing.

* **Comprehensive Float Positioning:** The `PositionFloatFragments` test explores more complex scenarios involving multiple left and right floats and regular block elements.

* **`clear` Property:** The `PositionFragmentsWithClear` test specifically targets the behavior of the `clear` CSS property with different values (`none`, `right`, `left`, `both`).

* **Min/Max Content Size:** Several tests (`ComputeMinMaxContent`, `ComputeMinMaxContentFloats`, etc.) focus on calculating the intrinsic minimum and maximum content sizes of elements, including cases with floats and new formatting contexts.

* **Shrink-to-Fit:** The `ShrinkToFit` test checks the behavior of the layout algorithm when an element needs to shrink to fit its content.

* **Empty Blocks in New BFC:** The `PositionEmptyBlocksInNewBfc` test examines how empty blocks and floats are positioned within a block formatting context created by `overflow: hidden`.

* **Clearance and Intruding Floats:** The `PositionBlocksWithClearanceAndIntrudingFloats` test combines `clear` with the interaction of floats.

* **Fragmentation:** The final set of tests (`NoFragmentation`, `SimpleFragmentation`, `InnerChildrenFragmentation`, `InnerFormattingContextChildrenFragmentation`) introduces the concept of fragmentation, likely related to CSS fragmentation properties (like those used in paged media or multicolumn layouts). It checks how elements and their children are split across fragmentation boundaries.

By analyzing these individual tests, we can build a comprehensive summary of the code's functionality.
这个代码片段主要关注 **CSS 浮动 (float) 和 clear 属性** 对块级元素布局的影响，以及一些 **新的格式化上下文 (new formatting context)** 的相关测试。它继续验证 `blink/renderer/core/layout/block_layout_algorithm_test.cc` 文件的功能，专注于块级布局算法的特定方面。

以下是代码片段功能的归纳：

**1. 浮动元素交互测试 (Continuation):**

* **假设输入:**  一系列包含浮动元素 (`#float`) 和其他块级元素 (`#zero`, `#abs`, `#inflow`) 的 HTML 结构，并设置了不同的 `margin` 值。
* **逻辑推理:**  测试代码推断了在存在浮动元素时，不同 `margin` 值（包括正负值）如何影响 `#zero`, `#abs`, `#inflow` 元素的垂直位置。特别是关注了“margin strut”的概念，它用来处理与浮动元素相邻的元素的 margin collapse 情况。
* **输出:** `EXPECT_EQ` 断言验证了 `#zero`, `#abs`, `#inflow` 元素最终的 `PhysicalLocation().top` 值是否符合预期。例如，当 `#zero` 的 margin strut 解析为负值时，它会被调整到浮动元素的下方（clearance）。

**2. 新的格式化上下文与自动 margin:**

* **功能:**  测试当块级元素创建一个新的格式化上下文 (通过 `display: flow-root` 或 `overflow: hidden` 等属性) 时，自动 margin ( `margin-left: auto`, `margin-right: auto`) 如何在其内部生效。
* **涉及 CSS:**  `display: flow-root`, `overflow: hidden`, `margin-left`, `margin-right`, `direction: rtl`。
* **假设输入:**  包含一个设置了 `display: flow-root` 的容器 `#container`，其中包含一个浮动元素 `#float` 和多个设置了不同自动 margin 的 `#newfc` 元素。
* **输出:** `EXPECT_EQ(expectation, DumpFragmentTree(fragment))`  断言生成的布局片段树 (fragment tree) 的结构和位置是否与预期一致。这验证了自动 margin 在新的格式化上下文中正确地分配剩余空间。

**3. 边框 (border) 和内边距 (padding) 的计算:**

* **功能:**  验证块级元素的尺寸是否正确包含了 `border` 和 `padding`，并且子元素被正确地定位在父元素的 content box 内。
* **涉及 CSS:** `width`, `height`, `border-style`, `border-width`, `padding`。
* **假设输入:**  一个包含边框和内边距的 `#div1` 元素，其中包含一个子元素 `#div2`。
* **输出:** `EXPECT_EQ` 断言验证了 `#div1` 的宽度和高度包含了边框和内边距，并且 `#div2` 的偏移量 (`PhysicalOffset`) 相对于 `#div1` 的 content box 是正确的。

**4. 百分比尺寸解析:**

* **功能:** 测试块级元素使用百分比宽度时，相对于其包含块的宽度是否能正确解析。
* **涉及 CSS:** `width` (百分比单位)。
* **假设输入:**  一个设置了固定宽度和内边距的容器 `#container`，其中包含一个设置了百分比宽度的子元素 `#div1`。
* **输出:** `EXPECT_EQ` 断言验证了 `#div1` 的最终宽度是否等于容器内容宽度的相应百分比。

**5. 自动 margin 的简单情况:**

* **功能:**  验证自动 margin 在一个简单的块级元素上的基本行为，使其在容器中水平居中。
* **涉及 CSS:** `width`, `margin-left: auto`, `margin-right: auto`, `padding-left`。
* **假设输入:**  一个设置了自动 margin 的 `#first` 元素包含在一个设置了宽度和内边距的容器 `#container` 中。
* **输出:** `EXPECT_EQ` 断言验证了 `#first` 元素的偏移量 (`child_offset.left`) 是否使其在容器中居中。

**6. 嵌套空块中的浮动元素定位:**

* **功能:**  测试浮动元素在嵌套的空块级元素中是否能被正确地定位。
* **涉及 CSS:** `float`, `margin`, `padding`。
* **假设输入:**  一个包含嵌套的空 `div` 元素 (`#empty1`, `#empty2`) 的容器，其中包含左右浮动的元素 (`#left-float`, `#right-float`)。
* **输出:** `EXPECT_THAT` 断言验证了浮动元素及其父元素在布局片段树中的偏移量是否符合预期，包括 margin collapse 的处理。

**7. 浮动元素片段定位:**

* **功能:**  测试左浮动、右浮动和普通块级元素在容器中是否能被正确地定位。
* **涉及 CSS:** `float`, `width`, `height`, `margin`, `background-color`。
* **假设输入:**  一个包含多个不同浮动方式和尺寸的块级元素的容器 `#container`。
* **输出:** `EXPECT_EQ` 和 `EXPECT_THAT` 断言验证了每个元素在布局片段树中的偏移量 (`OffsetTop`, `OffsetLeft`) 是否正确。

**8. `clear` 属性测试:**

* **功能:**  验证 `clear` CSS 属性的不同值 (`none`, `right`, `left`, `both`) 是否能正确地影响元素相对于浮动元素的位置。
* **涉及 CSS:** `float`, `clear`, `margin`, `height`, `width`, `background-color`。
* **假设输入:**  一个包含浮动元素 (`#float-left`, `#float-right`) 和设置了不同 `clear` 值的块级元素 (`#clearance`, `#adjoining-clearance`) 的容器 `#container`。
* **输出:** `EXPECT_EQ` 断言验证了在应用不同 `clear` 值后，相关元素的偏移量 (`clerance_offset`, `block_offset`, `adjoining_clearance_offset`) 是否符合预期，即元素是否能正确地“清除”浮动。

**9. 计算最小/最大内容尺寸:**

* **功能:**  测试布局算法是否能正确计算块级元素的最小内容尺寸 (min-content size) 和最大内容尺寸 (max-content size)。
* **涉及 CSS:** `width`, `float`, `display: flex`, `margin-left`。
* **假设输入:**  包含不同宽度子元素的容器，包括包含浮动元素和新的格式化上下文的场景。
* **输出:** `EXPECT_EQ` 断言验证了计算出的 `MinMaxSizes` 结构体的 `min_size` 和 `max_size` 属性是否正确。

**10. 收缩到适应内容 (Shrink-to-Fit):**

* **功能:**  测试当块级元素的宽度被限制为自动 (`auto`) 时，布局算法是否能使其宽度收缩到适应其内容。
* **涉及 CSS:** `width`。
* **假设输入:**  一个包含不同宽度子元素的容器 `#container`。
* **输出:** `EXPECT_EQ` 断言验证了容器的最终宽度是否等于其内容所需的最小宽度。

**11. 新 BFC 中的空块定位:**

* **功能:**  测试在建立新的块级格式化上下文 (BFC) 的块级元素内部，空块元素和浮动元素是否能被正确地定位。
* **涉及 CSS:** `overflow: hidden`, `margin`, `float`, `width`, `height`, `background`。
* **假设输入:**  一个设置了 `overflow: hidden` 的容器 `#container`，包含一个浮动元素和两个空块元素。
* **输出:** `EXPECT_THAT` 断言验证了空块元素的偏移量相对于容器是否正确。

**12. 清除浮动与侵入浮动元素的定位:**

* **功能:**  测试具有 `clear` 属性的块级元素在存在侵入性浮动元素的情况下是否能被正确地定位。
* **涉及 CSS:** `float`, `clear`, `margin`, `height`, `width`, `outline`。
* **假设输入:**  包含左右浮动元素和设置了 `clear` 属性的块级元素的 HTML 结构。
* **输出:** `EXPECT_THAT` 断言验证了设置了 `clear` 属性的块级元素的偏移量是否考虑了浮动元素的影响。

**13. 无碎片化 (No Fragmentation):**

* **功能:**  测试当块级元素的高度没有达到碎片化线的阈值时，是否不会被分割成多个片段。
* **涉及 CSS:** `width`, `height`。
* **假设输入:**  一个高度小于可用碎片空间 `#container` 的块级元素。
* **输出:** `EXPECT_EQ` 断言验证了生成的布局片段只有一个，并且没有 `BreakToken`，表示没有发生碎片化。

**14. 简单碎片化 (Simple Fragmentation):**

* **功能:**  测试当块级元素的高度超过碎片化线的阈值时，是否会被分割成多个片段。
* **涉及 CSS:** `width`, `height`。
* **假设输入:**  一个高度大于可用碎片空间 `#container` 的块级元素。
* **输出:** `EXPECT_EQ` 断言验证了生成的第一个布局片段的高度等于可用碎片空间，并且有一个 `BreakToken`，表示发生了碎片化。随后的布局片段的高度为剩余部分，并且没有 `BreakToken`。

**15. 内部子元素碎片化 (Inner Children Fragmentation):**

* **功能:**  测试在同一个块级格式化上下文中的子元素是否会在达到碎片化线时被正确地分割到不同的片段中。
* **涉及 CSS:** `width`, `padding-top`, `height`, `margin-bottom`, `margin-top`。
* **假设输入:**  一个包含两个子元素的容器，其总高度超过可用碎片空间。
* **输出:** `EXPECT_EQ` 断言验证了每个布局片段的大小，以及子元素在不同片段中的偏移量是否正确。

**16. 内部格式化上下文子元素碎片化 (Inner Formatting Context Children Fragmentation):**

* **功能:**  测试建立新的格式化上下文的子元素是否能被正确地碎片化。
* **涉及 CSS:** `width`, `padding-top`, `height`, `margin-bottom`, `margin-top`, `contain: paint`。
* **假设输入:**  一个包含两个建立新的格式化上下文的子元素的容器，其总高度超过可用碎片空间。
* **输出:**  (代码片段未完整提供，但推测会进行类似的断言) 验证建立新的格式化上下文的子元素在碎片化时的行为是否正确。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:** 代码通过 `SetBodyInnerHTML` 函数动态创建 HTML 结构，例如创建包含不同 `div` 元素的结构来测试浮动和 clear 的效果。
* **CSS:** 代码片段中大量的 CSS 属性被用来设置元素的样式，例如 `width`, `height`, `float`, `clear`, `margin`, `padding`, `display`, `overflow` 等，这些属性直接影响着布局算法的计算结果。例如，测试 `clear: left` 时，代码会动态修改元素的样式。
* **JavaScript:** 虽然这段 C++ 代码本身不是 JavaScript，但它是 Blink 引擎的一部分，负责渲染网页。JavaScript 可以通过修改 DOM 结构和 CSS 样式来触发这些布局算法的运行。例如，一个 JavaScript 动画可能会改变元素的位置，从而触发重新布局，而这个测试文件中的代码就是用来确保这些重新布局的计算是正确的。

**用户或编程常见的使用错误举例:**

* **不理解 margin collapse:**  开发者可能不清楚相邻元素的 margin 会发生 collapse，导致布局结果与预期不符。测试代码中关于 margin strut 的部分就涵盖了这类情况。
* **错误地使用 `clear` 属性:** 开发者可能不清楚 `clear` 属性只对垂直方向的浮动产生影响，或者不理解 `clear: both` 的效果。测试代码通过不同 `clear` 值的场景来验证其行为。
* **忘记新的格式化上下文的影响:**  开发者可能忽略了 `overflow: hidden` 或 `display: flow-root` 等属性会创建新的格式化上下文，从而影响内部元素的布局，例如自动 margin 的分配。`NewFormattingContextAutoMargins` 测试就针对这种情况。
* **百分比宽度相对于错误的包含块:** 开发者可能错误地认为百分比宽度是相对于视口或其他元素的，而实际上它是相对于最近的块级包含块的 content box 的宽度。 `PercentageResolutionSize` 测试确保了百分比宽度的正确解析。

总而言之，这个代码片段是 Chromium Blink 引擎中用于测试块级布局算法正确性的重要组成部分，它涵盖了浮动、clear、新的格式化上下文以及碎片化等关键的布局特性。 这些测试确保了浏览器能够按照 CSS 规范正确地渲染网页。

Prompt: 
```
这是目录为blink/renderer/core/layout/block_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
 Length::Fixed(0),
      /* #inflow margin-top */ Length::Fixed(0));

  // #zero, #abs, #inflow should all be positioned at the float.
  EXPECT_EQ(LayoutUnit(50), zero->PhysicalLocation().top);
  EXPECT_EQ(LayoutUnit(50), abs->PhysicalLocation().top);
  EXPECT_EQ(LayoutUnit(50), inflow->PhysicalLocation().top);

  // A margin strut which resolves to -50 (-70 + 20) adjusts the position of
  // #zero to the float clearance.
  run_test(
      /* #zero-top margin-bottom */ Length::Fixed(0),
      /* #zero-inner margin-top */ Length::Fixed(-60),
      /* #zero-inner margin-bottom */ Length::Fixed(20),
      /* #zero margin-bottom */ Length::Fixed(-70),
      /* #inflow margin-top */ Length::Fixed(50));

  // #zero is placed at the float, the margin strut is at:
  // 90 = (50 - (-60 + 20)).
  EXPECT_EQ(LayoutUnit(50), zero->PhysicalLocation().top);

  // #abs estimates its position with the margin strut:
  // 40 = (90 + (-70 + 20)).
  EXPECT_EQ(LayoutUnit(40), abs->PhysicalLocation().top);

  // #inflow has similar behavior to #abs, but includes its margin.
  // 70 = (90 + (-70 + 50))
  EXPECT_EQ(LayoutUnit(70), inflow->PhysicalLocation().top);

  // A margin strut which resolves to 60 (-10 + 70) means that #zero doesn't
  // get adjusted to clear the float, and we have normal behavior.
  //
  // NOTE: This case below has wildly different results on different browsers,
  // we may have to change the behavior here in the future for web compat.
  run_test(
      /* #zero-top margin-bottom */ Length::Fixed(0),
      /* #zero-inner margin-top */ Length::Fixed(70),
      /* #zero-inner margin-bottom */ Length::Fixed(-10),
      /* #zero margin-bottom */ Length::Fixed(-20),
      /* #inflow margin-top */ Length::Fixed(80));

  // #zero is placed at 60 (-10 + 70).
  EXPECT_EQ(LayoutUnit(60), zero->PhysicalLocation().top);

  // #abs estimates its position with the margin strut:
  // 50 = (0 + (-20 + 70)).
  EXPECT_EQ(LayoutUnit(50), abs->PhysicalLocation().top);

  // #inflow has similar behavior to #abs, but includes its margin.
  // 60 = (0 + (-20 + 80))
  EXPECT_EQ(LayoutUnit(60), inflow->PhysicalLocation().top);

  // #zero-top produces a margin which needs to be ignored, as #zero is
  // affected by clearance, it needs to have layout performed again, starting
  // with an empty margin strut.
  run_test(
      /* #zero-top margin-bottom */ Length::Fixed(30),
      /* #zero-inner margin-top */ Length::Fixed(20),
      /* #zero-inner margin-bottom */ Length::Fixed(-10),
      /* #zero margin-bottom */ Length::Fixed(0),
      /* #inflow margin-top */ Length::Fixed(25));

  // #zero is placed at the float, the margin strut is at:
  // 40 = (50 - (-10 + 20)).
  EXPECT_EQ(LayoutUnit(50), zero->PhysicalLocation().top);

  // The margin strut is now disjoint, this is placed at:
  // 55 = (40 + (-10 + 25))
  EXPECT_EQ(LayoutUnit(55), inflow->PhysicalLocation().top);
}

// Tests that when auto margins are applied to a new formatting context, they
// are applied within the layout opportunity.
TEST_F(BlockLayoutAlgorithmTest, NewFormattingContextAutoMargins) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #container { width: 200px; direction: rtl; display: flow-root; }
        #float { width: 100px; height: 60px; background: hotpink; float: left; }
        #newfc { direction: rtl; width: 50px; height: 20px; background: green; overflow: hidden; }
      </style>
      <div id="container">
        <div id="float"></div>
        <div id="newfc" style="margin-right: auto;"></div>
        <div id="newfc" style="margin-left: auto; margin-right: auto;"></div>
        <div id="newfc" style="margin-left: auto;"></div>
      </div>
    )HTML");

  const auto* fragment =
      &To<PhysicalBoxFragment>(GetLayoutBoxByElementId("container")
                                   ->GetSingleCachedLayoutResult()
                                   ->GetPhysicalFragment());

  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:200x60
    offset:0,0 size:100x60
    offset:100,0 size:50x20
    offset:125,20 size:50x20
    offset:150,40 size:50x20
)DUMP";
  EXPECT_EQ(expectation, DumpFragmentTree(fragment));
}

// Verifies that a box's size includes its borders and padding, and that
// children are positioned inside the content box.
TEST_F(BlockLayoutAlgorithmTest, BorderAndPadding) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #div1 {
        width: 100px;
        height: 100px;
        border-style: solid;
        border-width: 1px 2px 3px 4px;
        padding: 5px 6px 7px 8px;
      }
    </style>
    <div id="container">
      <div id="div1">
         <div id="div2"></div>
      </div>
    </div>
  )HTML");
  const int kWidth = 100;
  const int kHeight = 100;
  const int kBorderTop = 1;
  const int kBorderRight = 2;
  const int kBorderBottom = 3;
  const int kBorderLeft = 4;
  const int kPaddingTop = 5;
  const int kPaddingRight = 6;
  const int kPaddingBottom = 7;
  const int kPaddingLeft = 8;

  BlockNode container(GetLayoutBoxByElementId("container"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize));

  const PhysicalBoxFragment* fragment =
      RunBlockLayoutAlgorithm(container, space);

  ASSERT_EQ(fragment->Children().size(), 1UL);

  // div1
  const PhysicalFragment* child = fragment->Children()[0].get();
  EXPECT_EQ(kBorderLeft + kPaddingLeft + kWidth + kPaddingRight + kBorderRight,
            child->Size().width);
  EXPECT_EQ(kBorderTop + kPaddingTop + kHeight + kPaddingBottom + kBorderBottom,
            child->Size().height);

  ASSERT_TRUE(child->IsBox());
  ASSERT_EQ(static_cast<const PhysicalBoxFragment*>(child)->Children().size(),
            1UL);

  PhysicalOffset div2_offset =
      static_cast<const PhysicalBoxFragment*>(child)->Children()[0].Offset();
  EXPECT_EQ(kBorderTop + kPaddingTop, div2_offset.top);
  EXPECT_EQ(kBorderLeft + kPaddingLeft, div2_offset.left);
}

TEST_F(BlockLayoutAlgorithmTest, PercentageResolutionSize) {
  SetBodyInnerHTML(R"HTML(
    <div id="container" style="width: 30px; padding-left: 10px">
      <div id="div1" style="width: 40%"></div>
    </div>
  )HTML");
  const int kPaddingLeft = 10;
  const int kWidth = 30;

  BlockNode container(GetLayoutBoxByElementId("container"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), kIndefiniteSize));
  const PhysicalBoxFragment* fragment =
      RunBlockLayoutAlgorithm(container, space);

  EXPECT_EQ(LayoutUnit(kWidth + kPaddingLeft), fragment->Size().width);
  EXPECT_EQ(PhysicalFragment::kFragmentBox, fragment->Type());
  ASSERT_EQ(fragment->Children().size(), 1UL);

  const PhysicalFragment* child = fragment->Children()[0].get();
  EXPECT_EQ(LayoutUnit(12), child->Size().width);
}

// A very simple auto margin case. We rely on the tests in length_utils_test
// for the more complex cases; just make sure we handle auto at all here.
TEST_F(BlockLayoutAlgorithmTest, AutoMargin) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #first { width: 10px; margin-left: auto; margin-right: auto; }
    </style>
    <div id="container" style="width: 30px; padding-left: 10px">
      <div id="first">
      </div>
    </div>
  )HTML");
  const int kPaddingLeft = 10;
  const int kWidth = 30;
  const int kChildWidth = 10;

  BlockNode container(GetLayoutBoxByElementId("container"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), kIndefiniteSize));
  const PhysicalBoxFragment* fragment =
      RunBlockLayoutAlgorithm(container, space);

  EXPECT_EQ(LayoutUnit(kWidth + kPaddingLeft), fragment->Size().width);
  EXPECT_EQ(PhysicalFragment::kFragmentBox, fragment->Type());
  ASSERT_EQ(1UL, fragment->Children().size());

  const PhysicalFragment* child = fragment->Children()[0].get();
  PhysicalOffset child_offset = fragment->Children()[0].Offset();
  EXPECT_EQ(LayoutUnit(kChildWidth), child->Size().width);
  EXPECT_EQ(LayoutUnit(kPaddingLeft + 10), child_offset.left);
  EXPECT_EQ(LayoutUnit(0), child_offset.top);
}

// Verifies that floats can be correctly positioned if they are inside of nested
// empty blocks.
TEST_F(BlockLayoutAlgorithmTest, PositionFloatInsideEmptyBlocks) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #container {
          height: 300px;
          width: 300px;
          outline: blue solid;
        }
        #empty1 {
          margin: 20px;
          padding: 0 20px;
        }
        #empty2 {
          margin: 15px;
          padding: 0 15px;
        }
        #left-float {
          float: left;
          height: 5px;
          width: 5px;
          padding: 10px;
          margin: 10px;
          background-color: green;
        }
        #right-float {
          float: right;
          height: 15px;
          width: 15px;
          margin: 15px 10px;
          background-color: red;
        }
      </style>
      <div id='container'>
        <div id='empty1'>
          <div id='empty2'>
            <div id='left-float'></div>
            <div id='right-float'></div>
          </div>
        </div>
      </div>
    )HTML");

  const auto* fragment = GetHtmlPhysicalFragment();
  const auto* body_fragment =
      To<PhysicalBoxFragment>(fragment->Children()[0].get());
  PhysicalOffset body_offset = fragment->Children()[0].Offset();
  FragmentChildIterator iterator(body_fragment);
  // 20 = std::max(empty1's margin, empty2's margin, body's margin)
  int body_top_offset = 20;
  EXPECT_THAT(body_offset.top, LayoutUnit(body_top_offset));
  ASSERT_EQ(1UL, body_fragment->Children().size());

  const auto* container_fragment = iterator.NextChild();
  ASSERT_EQ(1UL, container_fragment->Children().size());

  iterator.SetParent(container_fragment);
  PhysicalOffset offset;
  const auto* empty1_fragment = iterator.NextChild(&offset);
  // 0, vertical margins got collapsed
  EXPECT_THAT(offset.top, LayoutUnit());
  // 20 empty1's margin
  EXPECT_THAT(offset.left, LayoutUnit(20));
  ASSERT_EQ(empty1_fragment->Children().size(), 1UL);

  iterator.SetParent(empty1_fragment);
  const auto* empty2_fragment = iterator.NextChild(&offset);
  // 0, vertical margins got collapsed
  EXPECT_THAT(LayoutUnit(), offset.top);
  // 35 = empty1's padding(20) + empty2's padding(15)
  EXPECT_THAT(offset.left, LayoutUnit(35));

  offset = empty2_fragment->Children()[0].offset;
  // inline 25 = left float's margin(10) + empty2's padding(15).
  // block 10 = left float's margin
  EXPECT_THAT(offset, PhysicalOffset(25, 10));

  offset = empty2_fragment->Children()[1].offset;
  // inline offset 140 = right float's margin(10) + right float offset(140)
  // block offset 15 = right float's margin
  LayoutUnit right_float_offset = LayoutUnit(140);
  EXPECT_THAT(offset, PhysicalOffset(LayoutUnit(10) + right_float_offset,
                                     LayoutUnit(15)));

  // ** Verify layout tree **
  Element* left_float = GetElementById("left-float");
  // 88 = body's margin(8) +
  // empty1's padding and margin + empty2's padding and margins + float's
  // padding
  EXPECT_THAT(left_float->OffsetLeft(), 88);
  // 30 = body_top_offset(collapsed margins result) + float's padding
  EXPECT_THAT(left_float->OffsetTop(), body_top_offset + 10);
}

// Verifies that left/right floating and regular blocks can be positioned
// correctly by the algorithm.
TEST_F(BlockLayoutAlgorithmTest, PositionFloatFragments) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #container {
          height: 200px;
          width: 200px;
        }
        #left-float {
          background-color: red;
          float: left;
          height: 30px;
          width: 30px;
        }
        #left-wide-float {
          background-color: greenyellow;
          float: left;
          height: 30px;
          width: 180px;
        }
        #regular {
          width: 40px;
          height: 40px;
          background-color: green;
        }
        #right-float {
          background-color: cyan;
          float: right;
          width: 50px;
          height: 50px;
        }
        #left-float-with-margin {
          background-color: black;
          float: left;
          height: 120px;
          margin: 10px;
          width: 120px;
        }
      </style>
      <div id='container'>
        <div id='left-float'></div>
        <div id='left-wide-float'></div>
        <div id='regular'></div>
        <div id='right-float'></div>
        <div id='left-float-with-margin'></div>
      </div>
      )HTML");

  const auto* fragment = GetHtmlPhysicalFragment();

  // ** Verify LayoutNG fragments and the list of positioned floats **
  ASSERT_EQ(1UL, fragment->Children().size());
  const auto* body_fragment =
      To<PhysicalBoxFragment>(fragment->Children()[0].get());
  PhysicalOffset body_offset = fragment->Children()[0].Offset();
  EXPECT_THAT(LayoutUnit(8), body_offset.top);

  FragmentChildIterator iterator(body_fragment);
  const auto* container_fragment = iterator.NextChild();
  ASSERT_EQ(5UL, container_fragment->Children().size());

  // ** Verify layout tree **
  Element* left_float = GetElementById("left-float");
  // 8 = body's margin-top
  EXPECT_EQ(8, left_float->OffsetTop());

  iterator.SetParent(container_fragment);
  PhysicalOffset offset;
  iterator.NextChild(&offset);
  EXPECT_THAT(LayoutUnit(), offset.top);

  Element* left_wide_float = GetElementById("left-wide-float");
  // left-wide-float is positioned right below left-float as it's too wide.
  // 38 = left_float_block_offset 8 +
  //      left-float's height 30
  EXPECT_EQ(38, left_wide_float->OffsetTop());

  iterator.NextChild(&offset);
  // 30 = left-float's height.
  EXPECT_THAT(LayoutUnit(30), offset.top);

  Element* regular = GetElementById("regular");
  // regular_block_offset = body's margin-top 8
  EXPECT_EQ(8, regular->OffsetTop());

  iterator.NextChild(&offset);
  EXPECT_THAT(LayoutUnit(), offset.top);

  Element* right_float = GetElementById("right-float");
  // 158 = body's margin-left 8 + container's width 200 - right_float's width 50
  // it's positioned right after our left_wide_float
  // 68 = left_wide_float_block_offset 38 + left-wide-float's height 30
  EXPECT_EQ(158, right_float->OffsetLeft());
  EXPECT_EQ(68, right_float->OffsetTop());

  iterator.NextChild(&offset);
  // 60 = right_float_block_offset(68) - body's margin(8)
  EXPECT_THAT(LayoutUnit(60), offset.top);
  // 150 = right_float_inline_offset(158) - body's margin(8)
  EXPECT_THAT(LayoutUnit(150), offset.left);

  Element* left_float_with_margin = GetElementById("left-float-with-margin");
  // 18 = body's margin(8) + left-float-with-margin's margin(10)
  EXPECT_EQ(18, left_float_with_margin->OffsetLeft());
  // 78 = left_wide_float_block_offset 38 + left-wide-float's height 30 +
  //      left-float-with-margin's margin(10)
  EXPECT_EQ(78, left_float_with_margin->OffsetTop());

  iterator.NextChild(&offset);
  // 70 = left_float_with_margin_block_offset(78) - body's margin(8)
  EXPECT_THAT(LayoutUnit(70), offset.top);
  // 10 = left_float_with_margin_inline_offset(18) - body's margin(8)
  EXPECT_THAT(LayoutUnit(10), offset.left);
}

// Verifies that NG block layout algorithm respects "clear" CSS property.
TEST_F(BlockLayoutAlgorithmTest, PositionFragmentsWithClear) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #container {
          height: 200px;
          width: 200px;
        }
        #float-left {
          background-color: red;
          float: left;
          height: 30px;
          width: 30px;
        }
        #float-right {
          background-color: blue;
          float: right;
          height: 170px;
          width: 40px;
        }
        #clearance {
          background-color: yellow;
          height: 60px;
          width: 60px;
          margin: 20px;
        }
        #block {
          margin: 40px;
          background-color: black;
          height: 60px;
          width: 60px;
        }
        #adjoining-clearance {
          background-color: green;
          clear: left;
          height: 20px;
          width: 20px;
          margin: 30px;
        }
      </style>
      <div id='container'>
        <div id='float-left'></div>
        <div id='float-right'></div>
        <div id='clearance'></div>
        <div id='block'></div>
        <div id='adjoining-clearance'></div>
      </div>
    )HTML");

  PhysicalOffset clerance_offset;
  PhysicalOffset body_offset;
  PhysicalOffset container_offset;
  PhysicalOffset block_offset;
  PhysicalOffset adjoining_clearance_offset;
  auto run_with_clearance = [&](EClear clear_value) {
    UpdateStyleForElement(
        GetElementById("clearance"),
        [&](ComputedStyleBuilder& builder) { builder.SetClear(clear_value); });
    const auto* fragment = GetHtmlPhysicalFragment();
    ASSERT_EQ(1UL, fragment->Children().size());
    const auto* body_fragment =
        To<PhysicalBoxFragment>(fragment->Children()[0].get());
    body_offset = fragment->Children()[0].Offset();
    const auto* container_fragment =
        To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
    ASSERT_EQ(5UL, container_fragment->Children().size());
    container_offset = body_fragment->Children()[0].Offset();
    clerance_offset = container_fragment->Children()[2].Offset();
    block_offset = container_fragment->Children()[3].Offset();
    adjoining_clearance_offset = container_fragment->Children()[4].Offset();
  };

  // clear: none
  run_with_clearance(EClear::kNone);
  // 20 = std::max(body's margin 8, clearance's margins 20)
  EXPECT_EQ(LayoutUnit(20), body_offset.top);
  EXPECT_EQ(LayoutUnit(0), container_offset.top);
  // 0 = collapsed margins
  EXPECT_EQ(LayoutUnit(0), clerance_offset.top);
  // 100 = clearance's height 60 +
  //       std::max(clearance's margins 20, block's margins 40)
  EXPECT_EQ(LayoutUnit(100), block_offset.top);
  // 200 = 100 + block's height 60 + max(adjoining_clearance's margins 30,
  //                                     block's margins 40)
  EXPECT_EQ(LayoutUnit(200), adjoining_clearance_offset.top);

  // clear: right
  run_with_clearance(EClear::kRight);
  // 8 = body's margin. This doesn't collapse its margins with 'clearance' block
  // as it's not an adjoining block to body.
  EXPECT_EQ(LayoutUnit(8), body_offset.top);
  EXPECT_EQ(LayoutUnit(0), container_offset.top);
  // 170 = float-right's height
  EXPECT_EQ(LayoutUnit(170), clerance_offset.top);
  // 270 = float-right's height + clearance's height 60 +
  //       max(clearance's margin 20, block margin 40)
  EXPECT_EQ(LayoutUnit(270), block_offset.top);
  // 370 = block's offset 270 + block's height 60 +
  //       std::max(block's margin 40, adjoining_clearance's margin 30)
  EXPECT_EQ(LayoutUnit(370), adjoining_clearance_offset.top);

  // clear: left
  run_with_clearance(EClear::kLeft);
  // 8 = body's margin. This doesn't collapse its margins with 'clearance' block
  // as it's not an adjoining block to body.
  EXPECT_EQ(LayoutUnit(8), body_offset.top);
  EXPECT_EQ(LayoutUnit(0), container_offset.top);
  // 30 = float_left's height
  EXPECT_EQ(LayoutUnit(30), clerance_offset.top);
  // 130 = float_left's height + clearance's height 60 +
  //       max(clearance's margin 20, block margin 40)
  EXPECT_EQ(LayoutUnit(130), block_offset.top);
  // 230 = block's offset 130 + block's height 60 +
  //       std::max(block's margin 40, adjoining_clearance's margin 30)
  EXPECT_EQ(LayoutUnit(230), adjoining_clearance_offset.top);

  // clear: both
  // same as clear: right
  run_with_clearance(EClear::kBoth);
  EXPECT_EQ(LayoutUnit(8), body_offset.top);
  EXPECT_EQ(LayoutUnit(0), container_offset.top);
  EXPECT_EQ(LayoutUnit(170), clerance_offset.top);
  EXPECT_EQ(LayoutUnit(270), block_offset.top);
  EXPECT_EQ(LayoutUnit(370), adjoining_clearance_offset.top);
}

// Verifies that we compute the right min and max-content size.
TEST_F(BlockLayoutAlgorithmTest, ComputeMinMaxContent) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div id="first-child" style="width: 20px"></div>
      <div id="second-child" style="width: 30px"></div>
    </div>
  )HTML");

  const int kSecondChildWidth = 30;

  BlockNode container(GetLayoutBoxByElementId("container"));

  MinMaxSizes sizes = RunComputeMinMaxSizes(container);
  EXPECT_EQ(kSecondChildWidth, sizes.min_size);
  EXPECT_EQ(kSecondChildWidth, sizes.max_size);
}

TEST_F(BlockLayoutAlgorithmTest, ComputeMinMaxContentFloats) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #f1 { float: left; width: 20px; }
      #f2 { float: left; width: 30px; }
      #f3 { float: right; width: 40px; }
    </style>
    <div id="container">
      <div id="f1"></div>
      <div id="f2"></div>
      <div id="f3"></div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));

  MinMaxSizes sizes = RunComputeMinMaxSizes(container);
  EXPECT_EQ(LayoutUnit(40), sizes.min_size);
  EXPECT_EQ(LayoutUnit(90), sizes.max_size);
}

TEST_F(BlockLayoutAlgorithmTest, ComputeMinMaxContentFloatsClearance) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #f1 { float: left; width: 20px; }
      #f2 { float: left; width: 30px; }
      #f3 { float: right; width: 40px; clear: left; }
    </style>
    <div id="container">
      <div id="f1"></div>
      <div id="f2"></div>
      <div id="f3"></div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));

  MinMaxSizes sizes = RunComputeMinMaxSizes(container);
  EXPECT_EQ(LayoutUnit(40), sizes.min_size);
  EXPECT_EQ(LayoutUnit(50), sizes.max_size);
}

TEST_F(BlockLayoutAlgorithmTest, ComputeMinMaxContentNewFormattingContext) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #f1 { float: left; width: 20px; }
      #f2 { float: left; width: 30px; }
      #fc { display: flex; width: 40px; margin-left: 60px; }
    </style>
    <div id="container">
      <div id="f1"></div>
      <div id="f2"></div>
      <div id="fc"></div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));

  MinMaxSizes sizes = RunComputeMinMaxSizes(container);
  EXPECT_EQ(LayoutUnit(100), sizes.min_size);
  EXPECT_EQ(LayoutUnit(100), sizes.max_size);
}

TEST_F(BlockLayoutAlgorithmTest,
       ComputeMinMaxContentNewFormattingContextNegativeMargins) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #f1 { float: left; width: 20px; }
      #f2 { float: left; width: 30px; }
      #fc { display: flex; width: 40px; margin-left: -20px; }
    </style>
    <div id="container">
      <div id="f1"></div>
      <div id="f2"></div>
      <div id="fc"></div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));

  MinMaxSizes sizes = RunComputeMinMaxSizes(container);
  EXPECT_EQ(LayoutUnit(30), sizes.min_size);
  EXPECT_EQ(LayoutUnit(70), sizes.max_size);
}

TEST_F(BlockLayoutAlgorithmTest,
       ComputeMinMaxContentSingleNewFormattingContextNegativeMargins) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fc { display: flex; width: 20px; margin-left: -40px; }
    </style>
    <div id="container">
      <div id="fc"></div>
    </div>
  )HTML");

  BlockNode container(GetLayoutBoxByElementId("container"));

  MinMaxSizes sizes = RunComputeMinMaxSizes(container);
  EXPECT_EQ(LayoutUnit(), sizes.min_size);
  EXPECT_EQ(LayoutUnit(), sizes.max_size);
}

// Tests that we correctly handle shrink-to-fit
TEST_F(BlockLayoutAlgorithmTest, ShrinkToFit) {
  SetBodyInnerHTML(R"HTML(
    <div id="container">
      <div id="first-child" style="width: 20px"></div>
      <div id="second-child" style="width: 30px"></div>
    </div>
  )HTML");
  const int kWidthChild2 = 30;

  BlockNode container(GetLayoutBoxByElementId("container"));

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ false);
  const PhysicalBoxFragment* fragment =
      RunBlockLayoutAlgorithm(container, space);

  EXPECT_EQ(LayoutUnit(kWidthChild2), fragment->Size().width);
}

// Verifies that we position empty blocks and floats correctly inside of the
// block that establishes new BFC.
TEST_F(BlockLayoutAlgorithmTest, PositionEmptyBlocksInNewBfc) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #container {
        overflow: hidden;
      }
      #empty-block1 {
        margin: 8px;
      }
      #left-float {
        float: left;
        background: red;
        height: 20px;
        width: 10px;
        margin: 15px;
      }
      #empty-block2 {
        margin-top: 50px;
      }
    </style>
    <div id="container">
      <div id="left-float"></div>
      <div id="empty-block1"></div>
      <div id="empty-block2"></div>
    </div>
  )HTML");

  const auto* html_fragment = GetHtmlPhysicalFragment();
  auto* body_fragment =
      To<PhysicalBoxFragment>(html_fragment->Children()[0].get());
  auto* container_fragment =
      To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
  PhysicalOffset empty_block1_offset =
      container_fragment->Children()[1].Offset();
  // empty-block1's margin == 8
  EXPECT_THAT(empty_block1_offset, PhysicalOffset(8, 8));

  PhysicalOffset empty_block2_offset =
      container_fragment->Children()[2].Offset();
  // empty-block2's margin == 50
  EXPECT_THAT(empty_block2_offset, PhysicalOffset(0, 50));
}

// Verifies that we can correctly position blocks with clearance and
// intruding floats.
TEST_F(BlockLayoutAlgorithmTest,
       PositionBlocksWithClearanceAndIntrudingFloats) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    body { margin: 80px; }
    #left-float {
      background: green;
      float: left;
      width: 50px;
      height: 50px;
    }
    #right-float {
      background: red;
      float: right;
      margin: 0 80px 0 10px;
      width: 50px;
      height: 80px;
    }
    #block1 {
      outline: purple solid;
      height: 30px;
      margin: 130px 0 20px 0;
    }
    #zero {
     margin-top: 30px;
    }
    #container-clear {
      clear: left;
      outline: orange solid;
    }
    #clears-right {
      clear: right;
      height: 20px;
      background: lightblue;
    }
    </style>

    <div id="left-float"></div>
    <div id="right-float"></div>
    <div id="block1"></div>
    <div id="container-clear">
      <div id="zero"></div>
      <div id="clears-right"></div>
    </div>
  )HTML");

  const auto* html_fragment = GetHtmlPhysicalFragment();
  auto* body_fragment =
      To<PhysicalBoxFragment>(html_fragment->Children()[0].get());
  ASSERT_EQ(4UL, body_fragment->Children().size());

  // Verify #container-clear block
  auto* container_clear_fragment =
      To<PhysicalBoxFragment>(body_fragment->Children()[3].get());
  PhysicalOffset container_clear_offset = body_fragment->Children()[3].Offset();
  // 60 = block1's height 30 + std::max(block1's margin 20, zero's margin 30)
  EXPECT_THAT(PhysicalOffset(0, 60), container_clear_offset);
  Element* container_clear = GetElementById("container-clear");
  // 190 = block1's margin 130 + block1's height 30 +
  //       std::max(block1's margin 20, zero's margin 30)
  EXPECT_THAT(container_clear->OffsetTop(), 190);

  // Verify #clears-right block
  ASSERT_EQ(2UL, container_clear_fragment->Children().size());
  PhysicalOffset clears_right_offset =
      container_clear_fragment->Children()[1].Offset();
  // 20 = right-float's block end offset (130 + 80) -
  //      container_clear->offsetTop() 190
  EXPECT_THAT(PhysicalOffset(0, 20), clears_right_offset);
}

// Tests that a block won't fragment if it doesn't reach the fragmentation line.
TEST_F(BlockLayoutAlgorithmTest, NoFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #container {
          width: 150px;
          height: 200px;
        }
      </style>
      <div id='container'></div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  // We should only have one 150x200 fragment with no fragmentation.
  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(150, 200), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());
}

// Tests that a block will fragment if it reaches the fragmentation line.
TEST_F(BlockLayoutAlgorithmTest, SimpleFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #container {
          width: 150px;
          height: 300px;
        }
      </style>
      <div id='container'></div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(150, 200), fragment->Size());
  EXPECT_TRUE(fragment->GetBreakToken());

  fragment = RunBlockLayoutAlgorithm(node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(150, 100), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());
}

// Tests that children inside the same block formatting context fragment when
// reaching a fragmentation line.
TEST_F(BlockLayoutAlgorithmTest, InnerChildrenFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #container {
          width: 150px;
          padding-top: 20px;
        }
        #child1 {
          height: 200px;
          margin-bottom: 20px;
        }
        #child2 {
          height: 100px;
          margin-top: 20px;
        }
      </style>
      <div id='container'>
        <div id='child1'></div>
        <div id='child2'></div>
      </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(150, 200), fragment->Size());
  EXPECT_TRUE(fragment->GetBreakToken());

  FragmentChildIterator iterator(To<PhysicalBoxFragment>(fragment));
  PhysicalOffset offset;
  const PhysicalBoxFragment* child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(150, 180), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 20), offset);

  EXPECT_FALSE(iterator.NextChild());

  fragment = RunBlockLayoutAlgorithm(node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(150, 140), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());

  iterator.SetParent(To<PhysicalBoxFragment>(fragment));
  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(150, 20), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 0), offset);

  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(150, 100), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 40), offset);

  EXPECT_FALSE(iterator.NextChild());
}

// Tests that children which establish new formatting contexts fragment
// correctly.
TEST_F(BlockLayoutAlgorithmTest, InnerFormattingContextChildrenFragmentation) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #container {
          width: 150px;
          padding-top: 20px;
        }
        #child1 {
          height: 200px;
          margin-bottom: 20px;
          contain: paint;
        }
        #child2 {
          height: 100px;
          margin-top: 20px;
          contain: paint;
        }
      </style>
      <div id='container'>
        <div id='child1'></div>
        <div id='child2'></div>
      </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(200);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(L
"""


```