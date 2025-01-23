Response:
The user is asking for a summary of the functionality of the provided C++ code, which is a test file for the fieldset layout algorithm in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `fieldset_layout_algorithm_test.cc` and the `TEST_F` macros clearly indicate this is a test file. The `FieldsetLayoutAlgorithmTest` fixture name further reinforces that it's specifically testing the layout algorithm for `<fieldset>` elements.

2. **Analyze the test cases:** Go through each `TEST_F` function and understand what aspect of the fieldset layout it's verifying. Look for keywords in the test names and the HTML/CSS setup. Examples:
    * `Basic`: Likely testing the fundamental layout without special conditions.
    * `Legend`: Focused on the `<legend>` element.
    * `Fragmentation`: Deals with how the fieldset is split across page breaks or container boundaries.
    * `Overflow`: Checks how content exceeding the fieldset's bounds is handled.
    * `NegativeMargin`: Tests the interaction of negative margins within the fieldset.
    * `BreakInsideAvoid`, `BreakBeforeAvoid`, `BreakAfterAvoid`:  Verifies the behavior of CSS `break-*` properties on fieldset elements and their children.
    * `LargeBorder`, `SmallLegend`: Examines scenarios involving borders and legends of different sizes, particularly in fragmentation contexts.

3. **Relate to web technologies:** Connect the C++ tests to the corresponding HTML elements (`<fieldset>`, `<legend>`, `<div>`), CSS properties (e.g., `margin`, `border`, `padding`, `width`, `height`, `break-inside`, `break-before`, `break-after`, `columns`), and JavaScript (implicitly through the testing framework setting up the DOM).

4. **Identify assumptions and outputs:**  For tests involving fragmentation, the `kFragmentainerSpaceAvailable` variable and the `DumpFragmentTree` output are key. The tests often set up specific HTML structures and then compare the actual layout output (`dump`) against an expected output (`expectation`). This demonstrates the input (HTML/CSS) and the expected output (fragment tree).

5. **Look for common errors:** Tests involving negative margins and `break-*` properties often highlight potential developer misunderstandings or unexpected behavior in edge cases. Think about how developers might misuse these features.

6. **Structure the summary:** Organize the findings logically. Start with the overall purpose, then delve into specific areas like basic layout, legend handling, fragmentation, and break properties. Provide concrete examples linking the tests to HTML, CSS, and JavaScript concepts.

7. **Address the "Part 2" instruction:**  Since this is the second part, focus on summarizing the functionality *of this specific code snippet*. Avoid repeating information from a hypothetical "Part 1".

8. **Refine and clarify:** Ensure the language is clear and concise, avoiding jargon where possible. Provide specific examples rather than vague generalizations. For instance, instead of saying "tests legend layout," specify "tests how the `<legend>` element is positioned and sized within the `<fieldset>`."

**(Self-Correction Example during the process):**  Initially, I might have just said "tests fragmentation."  However, reviewing the tests more carefully reveals different fragmentation scenarios: with legend overflow, with negative margins, and with large borders. Therefore, a more precise summary would mention these specific cases. Similarly, for break properties, simply saying "tests break properties" is less informative than listing the specific `break-inside`, `break-before`, and `break-after` properties being tested.
这个C++代码文件 `fieldset_layout_algorithm_test.cc` 是 Chromium Blink 引擎的一部分，专门用于测试 `<fieldset>` 元素的布局算法。  它属于 LayoutNG 布局引擎的测试范畴。

**归纳一下它的功能 (基于提供的第二部分代码):**

这部分代码主要关注 `<fieldset>` 及其内部 `<legend>` 元素在**分片 (fragmentation)** 场景下的布局行为。 分片是指当内容需要跨越页面边界、多列布局的列边界或者其他容器边界时，如何将元素分割成多个片段进行显示。

具体来说，这部分测试用例涵盖了以下功能：

* **测试 `<legend>` 元素内容溢出时的分片行为:**  验证当 `<legend>` 元素内的子元素超出其自身高度时，`<fieldset>` 如何进行分片。
* **测试带有负 margin 的 `<fieldset>` 内容的分片行为:**  检查当 `<fieldset>` 的子元素具有负的 `margin-top` 时，分片是如何处理的，特别是 `<legend>` 元素和内容之间的关系。
* **测试 `<legend>` 元素自身内容溢出时的布局:** 验证当 `<legend>` 内部的元素超出 `<legend>` 的尺寸时，布局如何展现，以及是否会影响 `<fieldset>` 的整体布局。
* **测试 `<fieldset>` 内容溢出时的分片行为:** 检验当 `<fieldset>` 的主体内容超出其自身高度时，如何进行分片。
* **测试 CSS 的 `break-inside: avoid` 属性对 `<fieldset>` 内容的影响:**  验证当 `<fieldset>` 的子元素设置了 `break-inside: avoid` 时，布局引擎是否会避免在该元素内部进行分片。
* **测试 `break-inside: avoid` 属性应用于较高的块级元素:**  测试当一个 `break-inside: avoid` 的元素高度超过剩余空间时，布局引擎如何处理，以及是否会避免无限循环分片。
* **测试 `break-inside: avoid` 属性对 `<legend>` 元素的影响:** 验证当 `<legend>` 元素设置了 `break-inside: avoid` 时，是否会阻止在 `<legend>` 内部进行分片。
* **测试 CSS 的 `break-before: avoid` 属性对 `<fieldset>` 内容的影响:** 验证当 `<fieldset>` 的子元素设置了 `break-before: avoid` 时，布局引擎是否会避免在该元素之前进行分片。
* **测试 `break-before: avoid` 属性对 `<legend>` 元素的影响:**  测试当 `<legend>` 元素设置了 `break-before: avoid` 时，是否会阻止在该 `<legend>` 之前进行分片。
* **测试 CSS 的 `break-after: avoid` 属性对 `<fieldset>` 内容的影响:** 验证当 `<fieldset>` 的子元素设置了 `break-after: avoid` 时，布局引擎是否会避免在该元素之后进行分片。
* **测试 `break-after: avoid` 属性对 `<legend>` 元素的影响:**  测试当 `<legend>` 元素设置了 `break-after: avoid` 时，是否会阻止在该 `<legend>` 之后进行分片。
* **测试 margin-bottom 超出分片容器末端时的处理:** 验证当一个元素的 `margin-bottom` 导致其在当前分片容器中无法完全容纳时，布局引擎如何在下一个分片容器中处理该元素的起始位置和 margin。
* **测试带有大 border 和小 legend 的 `<fieldset>` 的分片:**  检验当 `<fieldset>` 拥有较大的边框，而 `<legend>` 尺寸较小时，布局引擎如何进行分片，特别是边框是否会溢出分片容器。
* **测试 legend 较小且位于首个分片容器内的 `<fieldset>` 的分片:**  验证当 `<legend>` 足够小可以容纳在首个分片容器内时，布局引擎如何调整其位置，并处理后续的分片。
* **测试 legend 不超出 border 的 `<fieldset>` 的分片:**  检验当 `<legend>` 没有超出 `<fieldset>` 的起始边框时，布局引擎在分片时是否会优先在 `<fieldset>` 之前断开，而不是在其子元素之前断开。
* **测试带有 break 的小 legend 和大 border 的 `<fieldset>` 的分片:**  验证当 `<legend>` 具有较小的尺寸和 `margin-top`，且 `<fieldset>` 具有较大边框时，布局引擎如何进行分片。

总而言之，这部分测试代码专注于验证 `<fieldset>` 元素在各种复杂的分片场景下的布局正确性，包括 `<legend>` 元素的影响，以及 CSS `break-*` 属性的约束。它通过设定不同的 HTML 结构和 CSS 样式，然后对比实际的布局结果（通过 `DumpFragmentTree` 输出）与预期的结果来确保布局算法的正确性。

### 提示词
```
这是目录为blink/renderer/core/layout/forms/fieldset_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
offset:10,0 size:100x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests fragmentation when a legend's child content overflows.
TEST_F(FieldsetLayoutAlgorithmTest, LegendFragmentationWithOverflow) {
  SetBodyInnerHTML(R"HTML(
      <style>
        fieldset, legend { margin:0; border:none; padding:0; }
      </style>
      <fieldset id="fieldset">
        <legend style="height:30px;">
          <div style="width:55px; height:150px;"></div>
        </legend>
        <div style="width:44px; height:150px;"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:55x30
      offset:0,0 size:55x150
    offset:0,30 size:1000x70
      offset:0,0 size:44x70
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x80
    offset:0,0 size:1000x80
      offset:0,0 size:44x80
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that fragmentation works as expected when the fieldset content has a
// negative margin block start.
TEST_F(FieldsetLayoutAlgorithmTest,
       LegendAndContentFragmentationNegativeMargin) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #fieldset {
          border:none; margin:0; padding:0px; width: 150px; height: 100px;
        }
        #legend {
          padding:0px; margin:0; width: 50px; height: 100px;
        }
        #child {
          margin-top: -20px; width: 100px; height: 40px;
        }
      </style>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
        <div id="child"></div>
      </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:150x100
    offset:0,0 size:50x100
    offset:0,100 size:150x0
      offset:0,-20 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:150x0
    offset:0,0 size:150x0
      offset:0,0 size:100x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, OverflowedLegend) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px; height: 100px;
      }
      #legend {
        padding:0px; margin:0px;
      }
    </style>
    <fieldset id="fieldset">
      <legend id="legend" style="width:75%; height:60px;">
        <div id="grandchild1" style="width:50px; height:120px;"></div>
        <div id="grandchild2" style="width:40px; height:20px;"></div>
      </legend>
      <div id="child" style="width:85%; height:10px;"></div>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_FALSE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x100
    offset:0,0 size:75x60
      offset:0,0 size:50x120
      offset:0,120 size:40x20
    offset:0,60 size:100x40
      offset:0,0 size:85x10
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, OverflowedFieldsetContent) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px; height: 100px;
      }
      #legend {
        padding:0px; margin:0px;
      }
    </style>
    <fieldset id="fieldset">
      <legend id="legend" style="width:75%; height:10px;">
        <div style="width:50px; height:220px;"></div>
      </legend>
      <div style="width:85%; height:10px;"></div>
      <div id="child" style="width:65%; height:10px;">
        <div style="width:51px; height:220px;"></div>
      </div>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x100
    offset:0,0 size:75x10
      offset:0,0 size:50x220
    offset:0,10 size:100x90
      offset:0,0 size:85x10
      offset:0,10 size:65x10
        offset:0,0 size:51x80
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x0
    offset:0,0 size:100x0
      offset:0,0 size:65x0
        offset:0,0 size:51x100
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x0
    offset:0,0 size:100x0
      offset:0,0 size:65x0
        offset:0,0 size:51x40
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, BreakInsideAvoid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px; height: 100px;
      }
    </style>
     <fieldset id="fieldset">
      <div style="width:10px; height:50px;"></div>
      <div style="break-inside:avoid; width:20px; height:70px;"></div>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x100
    offset:0,0 size:100x100
      offset:0,0 size:10x50
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x0
    offset:0,0 size:100x0
      offset:0,0 size:20x70
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, BreakInsideAvoidTallBlock) {
  // The block that has break-inside:avoid is too tall to fit in one
  // fragmentainer. So a break is unavoidable. Let's check that:
  // 1. The block is still shifted to the start of the next fragmentainer
  // 2. We give up shifting it any further (would cause infinite an loop)
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px; height: 100px;
      }
    </style>
     <fieldset id="fieldset">
      <div style="width:10px; height:50px;"></div>
      <div style="break-inside:avoid; width:20px; height:170px;"></div>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x100
    offset:0,0 size:100x100
      offset:0,0 size:10x50
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x0
    offset:0,0 size:100x0
      offset:0,0 size:20x100
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x0
    offset:0,0 size:100x0
      offset:0,0 size:20x70
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, LegendBreakInsideAvoid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px; height: 50px;
      }
      #legend {
        padding:0px; margin:0px;
      }
    </style>
    <div id="container">
      <div style="width:20px; height:50px;"></div>
      <fieldset id="fieldset">
        <legend id="legend" style="break-inside:avoid; width:10px; height:60px;">
        </legend>
      </fieldset>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:20x50
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x60
    offset:0,0 size:100x60
      offset:0,0 size:10x60
      offset:0,60 size:100x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, BreakBeforeAvoid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px;
      }
    </style>
    <div id="container">
      <div style="width:20px; height:50px;"></div>
      <fieldset id="fieldset">
        <div style="width:10px; height:25px;"></div>
        <div style="width:30px; height:25px;"></div>
        <div style="break-before:avoid; width:15px; height:25px;"></div>
      </fieldset>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:20x50
    offset:0,50 size:100x50
      offset:0,0 size:100x50
        offset:0,0 size:10x25
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x50
    offset:0,0 size:100x50
      offset:0,0 size:100x50
        offset:0,0 size:30x25
        offset:0,25 size:15x25
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, LegendBreakBeforeAvoid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:10px solid; margin:0; padding:0px; width: 100px;
      }
      #legend {
        padding:0px; margin:10px; width:10px; height:25px;
      }
    </style>
    <div id="container">
      <div style="width:20px; height:90px;"></div>
      <fieldset id="fieldset">
        <legend id="legend" style="break-before:avoid;"></legend>
      </fieldset>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:20x90
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x45
    offset:0,0 size:120x45
      offset:20,0 size:10x25
      offset:10,35 size:100x0
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, BreakAfterAvoid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #multicol {
        columns:2; column-gap:0; column-fill:auto; width: 200px;
        height: 100px;
      }
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px; height:50px;
      }
    </style>
    <div id="container">
      <div id="multicol">
        <div style="width:20px; height:50px;"></div>
        <fieldset id="fieldset">
          <div style="width:10px; height:25px;"></div>
          <div style="break-after:avoid; width:30px; height:25px;"></div>
          <div style="width:15px; height:25px; break-after:column;"></div>
          <div style="width:12px; height:25px;"></div>
        </fieldset>
      </div>
    </div>
  )HTML");

  String dump = DumpFragmentTree(GetElementById("container"));
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:200x100
      offset:0,0 size:100x100
        offset:0,0 size:20x50
        offset:0,50 size:100x50
          offset:0,0 size:100x50
            offset:0,0 size:10x25
      offset:100,0 size:100x100
        offset:0,0 size:100x0
          offset:0,0 size:100x0
            offset:0,0 size:30x25
            offset:0,25 size:15x25
      offset:200,0 size:100x100
        offset:0,0 size:100x0
          offset:0,0 size:100x0
            offset:0,0 size:12x25
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, LegendBreakAfterAvoid) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:0px solid; margin:0; padding:0px; width: 100px;
      }
      #legend {
        padding:0px; margin:0px; width:10px; height:50px;
      }
    </style>
    <div id="container">
      <div style="width:20px; height:50px;"></div>
      <fieldset id="fieldset">
        <legend id="legend" style="break-after:avoid;"></legend>
        <div style="width:15px; height:25px;"></div>
      </fieldset>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x100
    offset:0,0 size:20x50
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:1000x75
    offset:0,0 size:100x75
      offset:0,0 size:10x50
      offset:0,50 size:100x25
        offset:0,0 size:15x25
)DUMP";
  EXPECT_EQ(expectation, dump);
}

TEST_F(FieldsetLayoutAlgorithmTest, MarginBottomPastEndOfFragmentainer) {
  // A block whose border box would start past the end of the current
  // fragmentainer should start exactly at the start of the next fragmentainer,
  // discarding what's left of the margin.
  // https://www.w3.org/TR/css-break-3/#break-margins
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset {
        border:none; margin:0; padding:0px; width: 100px; height: 100px;
      }
      #legend {
        padding:0px; margin:0px;
      }
    </style>
     <fieldset id="fieldset">
      <legend id="legend" style="margin-bottom:20px; height:90px;"></legend>
      <div style="width:20px; height:20px;"></div>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x110
    offset:0,0 size:0x90
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:100x0
    offset:0,0 size:100x0
      offset:0,0 size:20x20
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a large border and a small legend fragment
// correctly. Since we don't allow breaking inside borders, they will overflow
// fragmentainers.
TEST_F(FieldsetLayoutAlgorithmTest, SmallLegendLargeBorderFragmentation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset { margin:0; border:60px solid; padding:0px; width:100px;
                  height:10px; }
      #legend { padding:0; width:10px; height:50px; }
    </style>
    <fieldset id="fieldset">
      <legend id="legend"></legend>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(40);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x60
    offset:60,5 size:10x50
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x10
    offset:60,0 size:100x10
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a large border and a small legend fragment
// correctly. In this case, the legend block offset is adjusted because the
// legend fits inside the first fragment.
TEST_F(FieldsetLayoutAlgorithmTest, SmallerLegendLargeBorderFragmentation) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset { margin:0; border:60px solid; padding:0px; width:100px;
                  height:10px; }
      #legend { padding:0; width:10px; height:5px; }
    </style>
    <fieldset id="fieldset">
      <legend id="legend"></legend>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(40);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x60
    offset:60,27.5 size:10x5
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x10
    offset:60,0 size:100x10
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a large border and a small legend fragment
// correctly. In this case, since the legend doesn't stick below the block-start
// border, there's no class C breakpoint before the fieldset contents.
// Therefore, prefer breaking before the fieldset to breaking before the child
// DIV.
TEST_F(FieldsetLayoutAlgorithmTest, SmallerLegendLargeBorderFragmentation2) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset { margin:0; border:30px solid; padding:0px; width:100px; }
      #legend { padding:0; width:10px; height:5px; }
    </style>
    <div id="container" style="width:300px;">
      <div style="width:33px; height:70px;"></div>
      <fieldset id="fieldset">
        <legend id="legend"></legend>
        <div style="width:44px; height:30px; break-inside:avoid;"></div>
      </fieldset>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(100);

  BlockNode node(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:300x100
    offset:0,0 size:33x70
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunBlockLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  EXPECT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:300x90
    offset:0,0 size:160x90
      offset:30,12.5 size:10x5
      offset:30,30 size:100x30
        offset:0,0 size:44x30
)DUMP";
  EXPECT_EQ(expectation, dump);
}

// Tests that a fieldset with a large border and a small legend fragment
// correctly.
TEST_F(FieldsetLayoutAlgorithmTest, SmallerLegendLargeBorderWithBreak) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #fieldset { margin:0; border:60px solid; padding:0px; width:100px;
                  height:10px; }
      #legend { padding:0; width:10px; height:5px; margin-top:16px; }
    </style>
    <fieldset id="fieldset">
      <legend id="legend"></legend>
    </fieldset>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(40);

  BlockNode node(GetLayoutBoxByElementId("fieldset"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment =
      BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(node, space);
  ASSERT_TRUE(fragment->GetBreakToken());

  String dump = DumpFragmentTree(fragment);
  String expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x60
    offset:60,27.5 size:10x5
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_TRUE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x10
    offset:60,0 size:100x10
)DUMP";
  EXPECT_EQ(expectation, dump);

  fragment = BaseLayoutAlgorithmTest::RunFieldsetLayoutAlgorithm(
      node, space, fragment->GetBreakToken());
  ASSERT_FALSE(fragment->GetBreakToken());

  dump = DumpFragmentTree(fragment);
  expectation = R"DUMP(.:: LayoutNG Physical Fragment Tree ::.
  offset:unplaced size:220x60
)DUMP";
  EXPECT_EQ(expectation, dump);
}

}  // anonymous namespace
}  // namespace blink
```