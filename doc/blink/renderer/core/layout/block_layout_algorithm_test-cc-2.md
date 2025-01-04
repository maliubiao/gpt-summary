Response:
The user wants a summary of the functionality of the given C++ code snippet, which is a test file for the block layout algorithm in the Chromium Blink engine. I need to identify the main purpose of the tests and provide examples of how the tests relate to web technologies like HTML and CSS. I also need to point out any logical reasoning used in the tests, provide examples of potential user errors, and summarize the overall functionality.

**Plan:**

1. **Identify the Core Functionality:** The file tests the `BlockLayoutAlgorithm`.
2. **Analyze Individual Tests:**  Break down each `TEST_F` function to understand what aspect of block layout it's testing.
3. **Relate to HTML/CSS:** For each test, identify the corresponding HTML structure and CSS styles being used.
4. **Identify Logical Reasoning:** Look for assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`) that verify the output of the algorithm based on the input. Identify the assumed inputs (HTML/CSS) and the expected outputs (fragment sizes, offsets, break tokens).
5. **Consider User/Programming Errors:** Think about what mistakes a web developer might make in their HTML/CSS that these tests implicitly cover.
6. **Summarize the Functionality:** Combine the observations to provide a concise summary of the file's purpose.
这是对`blink/renderer/core/layout/block_layout_algorithm_test.cc` 文件中部分测试用例的归纳总结。这些测试用例主要关注 **块布局算法在处理分片（fragmentation）和浮动（float）元素时的行为**。

**功能归纳：**

这部分测试用例主要验证了 `BlockLayoutAlgorithm` 在以下场景中的正确性：

1. **容器高度不足时子元素的分片：** 测试了当容器的高度不足以容纳所有子元素时，子元素如何被分割成多个片段。
2. **浮动元素的分片：**  测试了浮动元素在父容器空间不足时如何被分割成多个片段，并考虑了与父容器书写模式相同的浮动元素的分片。
3. **浮动元素与正交书写模式：** 测试了当浮动元素的书写模式与父容器不同时，是否会发生分片。
4. **零高度容器内的浮动元素分片：**  测试了零高度的块容器内部的浮动元素是否能够正确分片。
5. **新的 Formatting Context 块的定位和边距折叠：** 测试了当新的 Formatting Context 块与浮动元素相邻时，其定位是否正确，以及边距是否按预期折叠。
6. **新的 Formatting Context 块避开浮动元素：** 测试了新的 Formatting Context 块是否能够正确地避开之前的浮动元素。
7. **负外边距导致元素超出容器边缘：** 测试了负外边距导致元素部分超出容器边缘时的布局计算。
8. **新的 Formatting Context 的第一个子元素为零尺寸块：** 测试了新的 Formatting Context 中，当第一个或多个子元素尺寸为零时的布局情况。
9. **在 Legacy 布局中的 Root Fragment 偏移：** 测试了在旧的布局模型中嵌套新的布局模型时，Root Fragment 的偏移量是否正确（这个测试被注释掉了，可能存在问题或待实现）。
10. **处理 Ruby 文本的崩溃问题：** 测试了特定的 Ruby 文本结构是否会导致布局引擎崩溃。
11. **处理文本控件占位符的崩溃问题：** 测试了特定的文本输入框及其占位符的样式是否会导致布局引擎崩溃。

**与 JavaScript, HTML, CSS 的关系举例说明：**

*   **HTML 结构：** 测试用例中使用了 HTML 结构来定义布局的元素和层级关系，例如 `div` 元素作为容器和子元素。
    ```html
    <div id='container'>
      <div id='child1'></div>
      <div id='child2'></div>
    </div>
    ```
*   **CSS 样式：** 测试用例通过 CSS 样式来控制元素的尺寸、定位、浮动和分片行为。例如，设置 `width`、`height`、`float`、`margin`、`padding` 等属性。
    ```css
    #container {
      width: 150px;
      padding-top: 20px;
      height: 50px;
    }
    #child1 {
      height: 200px;
      margin-bottom: 20px;
    }
    ```
*   **JavaScript (间接)：** 虽然测试用例本身是 C++ 代码，但它模拟了浏览器引擎在渲染 HTML 和 CSS 时进行布局计算的过程。JavaScript 动态修改 DOM 结构或 CSS 样式后，会触发重新布局，这些测试用例保证了重新布局的正确性。

**逻辑推理、假设输入与输出：**

以下以 `InnerChildrenFragmentationSmallHeight` 测试用例为例：

*   **假设输入 (HTML/CSS):**
    ```html
    <!DOCTYPE html>
    <style>
      #container {
        width: 150px;
        padding-top: 20px;
        height: 50px;
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
    ```
    片段容器可用空间 `kFragmentainerSpaceAvailable` 为 200px。
*   **逻辑推理:** 容器高度为 50px，加上 `padding-top: 20px`，实际内容高度为 30px。第一个子元素 `#child1` 的高度为 200px，加上 `margin-bottom: 20px`，共占据 220px。由于容器高度不足，`#child1` 将会被分片。第一个片段的高度将是容器的可用内容高度加上 padding，即 30px + 20px = 50px。 但是 `#child1` 本身的高度大于容器高度，所以第一个片段的高度会是 `#child1` 可以容纳在容器内的部分，加上 padding-top，也就是 20px + 一部分 `#child1` 的高度。
*   **预期输出:**
    *   第一个片段 (容器): 尺寸为 `PhysicalSize(150, 70)` (容器自身高度 50px + padding-top 20px)，并且有 `BreakToken` 表示需要分片。
    *   第一个子片段 (`#child1`): 尺寸为 `PhysicalSize(150, 180)` (其自身高度 200px)，偏移量为 `PhysicalOffset(0, 20)` (padding-top)。
    *   第二个片段 (容器): 尺寸为 `PhysicalSize(150, 0)`，没有 `BreakToken`。
    *   第二个子片段 (`#child1`): 尺寸为 `PhysicalSize(150, 20)`，偏移量为 `PhysicalOffset(0, 0)`。
    *   第三个子片段 (`#child2`): 尺寸为 `PhysicalSize(150, 100)`，偏移量为 `PhysicalOffset(0, 40)` (`#child1` 分片后剩余空间 + `#child2` 的 `margin-top`)。

**用户或编程常见的使用错误举例说明：**

*   **过度依赖容器的高度来限制子元素：** 用户可能期望通过设置容器的固定高度来“裁剪”超出容器的子元素，但如果没有正确理解分片机制，可能会导致意外的布局结果，尤其是在子元素设置了较大的 margin 时。例如，在 `InnerChildrenFragmentationSmallHeight` 的例子中，用户可能期望看到容器只有 50px 高，但由于子元素的高度和 margin，实际布局会发生分片。
*   **不理解浮动元素的影响：** 开发者可能没有充分考虑到浮动元素会脱离正常的文档流，从而影响后续元素的布局。例如，在测试 `NewFcBlockWithAdjoiningFloatCollapsesMargins` 中，如果开发者不理解浮动元素的存在会影响后续块级元素的定位和边距折叠，可能会得到意外的布局结果。
*   **错误地假设负 margin 的行为：**  开发者可能不清楚负 margin 会导致元素重叠或超出其父容器的边界，如 `ZeroBlockSizeAboveEdge` 所示。

**总结：**

这部分测试用例集中验证了 Blink 引擎的块布局算法在处理内容溢出、浮动元素以及新的 Formatting Context 时的布局计算逻辑，特别是关于元素分片和定位的正确性。这些测试覆盖了多种复杂的布局场景，确保了浏览器在渲染各种 HTML 和 CSS 结构时的行为符合预期，并能有效地预防由不合理的 CSS 样式或动态 DOM 操作导致的布局错误和崩溃问题。

Prompt: 
```
这是目录为blink/renderer/core/layout/block_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
ayoutUnit(1000), kIndefiniteSize),
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

// Tests that children inside a block container will fragment if the container
// doesn't reach the fragmentation line.
TEST_F(BlockLayoutAlgorithmTest, InnerChildrenFragmentationSmallHeight) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        #container {
          width: 150px;
          padding-top: 20px;
          height: 50px;
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
  EXPECT_EQ(PhysicalSize(150, 70), fragment->Size());
  EXPECT_TRUE(fragment->GetBreakToken());

  FragmentChildIterator iterator(To<PhysicalBoxFragment>(fragment));
  PhysicalOffset offset;
  const PhysicalBoxFragment* child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(150, 180), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 20), offset);

  EXPECT_FALSE(iterator.NextChild());

  fragment = RunBlockLayoutAlgorithm(node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(150, 0), fragment->Size());
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

// Tests that float children fragment correctly inside a parallel flow.
TEST_F(BlockLayoutAlgorithmTest, DISABLED_FloatFragmentationParallelFlows) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        width: 150px;
        height: 50px;
        display: flow-root;
      }
      #float1 {
        width: 50px;
        height: 200px;
        float: left;
      }
      #float2 {
        width: 75px;
        height: 250px;
        float: right;
        margin: 10px;
      }
    </style>
    <div id='container'>
      <div id='float1'></div>
      <div id='float2'></div>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(150);

  BlockNode node(To<LayoutBlockFlow>(GetLayoutObjectByElementId("container")));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(150, 50), fragment->Size());
  EXPECT_TRUE(fragment->GetBreakToken());

  FragmentChildIterator iterator(To<PhysicalBoxFragment>(fragment));

  // First fragment of float1.
  PhysicalOffset offset;
  const auto* child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(50, 150), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 0), offset);

  // First fragment of float2.
  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(75, 150), child->Size());
  EXPECT_EQ(PhysicalOffset(65, 10), offset);

  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  fragment = RunBlockLayoutAlgorithm(node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(150, 0), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());

  iterator.SetParent(To<PhysicalBoxFragment>(fragment));

  // Second fragment of float1.
  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(50, 50), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 0), offset);

  // Second fragment of float2.
  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(75, 100), child->Size());
  EXPECT_EQ(PhysicalOffset(65, 0), offset);
}

// Tests that float children don't fragment if they aren't in the same writing
// mode as their parent.
TEST_F(BlockLayoutAlgorithmTest, FloatFragmentationOrthogonalFlows) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        width: 150px;
        height: 60px;
        display: flow-root;
      }
      #float1 {
        width: 100px;
        height: 50px;
        float: left;
      }
      #float2 {
        width: 60px;
        height: 200px;
        float: right;
        writing-mode: vertical-rl;
      }
    </style>
    <div id='container'>
      <div id='float1'></div>
      <div id='float2'></div>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(150);

  BlockNode node(To<LayoutBlockFlow>(GetLayoutObjectByElementId("container")));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true, kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(150, 60), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());

  const auto* float2 = fragment->Children()[1].fragment.Get();

  // float2 should only have one fragment.
  EXPECT_EQ(PhysicalSize(60, 200), float2->Size());
  ASSERT_TRUE(float2->IsBox());
  const BreakToken* break_token =
      To<PhysicalBoxFragment>(float2)->GetBreakToken();
  EXPECT_FALSE(break_token);
}

// Tests that a float child inside a zero height block fragments correctly.
TEST_F(BlockLayoutAlgorithmTest, DISABLED_FloatFragmentationZeroHeight) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        width: 150px;
        height: 50px;
        display: flow-root;
      }
      #float {
        width: 75px;
        height: 200px;
        float: left;
        margin: 10px;
      }
    </style>
    <div id='container'>
      <div id='zero'>
        <div id='float'></div>
      </div>
    </div>
  )HTML");

  LayoutUnit kFragmentainerSpaceAvailable(150);

  BlockNode node(To<LayoutBlockFlow>(GetLayoutObjectByElementId("container")));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(150, 50), fragment->Size());
  EXPECT_TRUE(fragment->GetBreakToken());

  FragmentChildIterator iterator(To<PhysicalBoxFragment>(fragment));
  const auto* child = iterator.NextChild();

  // First fragment of float.
  iterator.SetParent(child);
  PhysicalOffset offset;
  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(75, 150), child->Size());
  EXPECT_EQ(PhysicalOffset(10, 10), offset);

  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      node.CreatesNewFormattingContext(), kFragmentainerSpaceAvailable);

  fragment = RunBlockLayoutAlgorithm(node, space, fragment->GetBreakToken());
  EXPECT_EQ(PhysicalSize(150, 0), fragment->Size());
  ASSERT_FALSE(fragment->GetBreakToken());

  iterator.SetParent(To<PhysicalBoxFragment>(fragment));
  child = iterator.NextChild();

  // Second fragment of float.
  iterator.SetParent(child);
  child = iterator.NextChild();
  EXPECT_EQ(PhysicalSize(75, 50), child->Size());
  // TODO(ikilpatrick): Don't include the block-start margin of a float which
  // has fragmented.
  // EXPECT_EQ(PhysicalOffset(10, 0),
  // child->Offset());
}

// Verifies that we correctly position a new FC block with the Layout
// Opportunity iterator.
TEST_F(BlockLayoutAlgorithmTest, NewFcBlockWithAdjoiningFloatCollapsesMargins) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        width: 200px; outline: solid purple 1px;
      }
      #float {
        float: left; width: 100px; height: 30px; background: red;
      }
      #new-fc {
        contain: paint; margin-top: 20px; background: purple;
        height: 50px;
      }
    </style>
    <div id="container">
      <div id="float"></div>
      <div id="new-fc"></div>
    </div>
  )HTML");

  PhysicalOffset body_offset;
  PhysicalOffset new_fc_offset;

  auto run_test = [&](const Length& block_width) {
    UpdateStyleForElement(
        GetElementById("new-fc"),
        [&](ComputedStyleBuilder& builder) { builder.SetWidth(block_width); });
    const auto* fragment = GetHtmlPhysicalFragment();
    ASSERT_EQ(1UL, fragment->Children().size());
    const auto* body_fragment =
        To<PhysicalBoxFragment>(fragment->Children()[0].get());
    const auto* container_fragment =
        To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
    ASSERT_EQ(2UL, container_fragment->Children().size());
    body_offset = fragment->Children()[0].Offset();
    new_fc_offset = container_fragment->Children()[1].Offset();
  };

  // #new-fc is small enough to fit on the same line with #float.
  run_test(Length::Fixed(80));
  // 100 = float's width, 0 = no margin collapsing
  EXPECT_THAT(new_fc_offset, PhysicalOffset(100, 0));
  // 8 = body's margins, 20 = new-fc's margin top(20) collapses with
  // body's margin(8)
  EXPECT_THAT(body_offset, PhysicalOffset(8, 20));

  // #new-fc is too wide to be positioned on the same line with #float
  run_test(Length::Fixed(120));
  // 30 = #float's height
  EXPECT_THAT(new_fc_offset, PhysicalOffset(0, 30));
  // 8 = body's margins, no margin collapsing
  EXPECT_THAT(body_offset, PhysicalOffset(8, 8));
}

TEST_F(BlockLayoutAlgorithmTest, NewFcAvoidsFloats) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        width: 200px;
      }
      #float {
        float: left; width: 100px; height: 30px; background: red;
      }
      #fc {
        width: 150px; height: 120px; display: flow-root;
      }
    </style>
    <div id="container">
      <div id="float"></div>
      <div id="fc"></div>
    </div>
  )HTML");

  BlockNode node(To<LayoutBlockFlow>(GetLayoutObjectByElementId("container")));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize));

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(200, 150), fragment->Size());

  FragmentChildIterator iterator(To<PhysicalBoxFragment>(fragment));

  PhysicalOffset offset;
  const PhysicalBoxFragment* child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(100, 30), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 0), offset);

  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(150, 120), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 30), offset);
}

TEST_F(BlockLayoutAlgorithmTest, ZeroBlockSizeAboveEdge) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container { width: 200px; display: flow-root; }
      #inflow { width: 50px; height: 50px; background: red; margin-top: -70px; }
      #zero { width: 70px; margin: 10px 0 30px 0; }
    </style>
    <div id="container">
      <div id="inflow"></div>
      <div id="zero"></div>
    </div>
  )HTML");

  BlockNode node(To<LayoutBlockFlow>(GetLayoutObjectByElementId("container")));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(200, 10), fragment->Size());

  FragmentChildIterator iterator(To<PhysicalBoxFragment>(fragment));

  PhysicalOffset offset;
  const PhysicalBoxFragment* child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(50, 50), child->Size());
  EXPECT_EQ(PhysicalOffset(0, -70), offset);

  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(70, 0), child->Size());
  EXPECT_EQ(PhysicalOffset(0, -10), offset);
}

TEST_F(BlockLayoutAlgorithmTest, NewFcFirstChildIsZeroBlockSize) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      #container { width: 200px; display: flow-root; }
      #zero1 { width: 50px; margin-top: -30px; margin-bottom: 10px; }
      #zero2 { width: 70px; margin-top: 20px; margin-bottom: -40px; }
      #inflow { width: 90px; height: 20px; margin-top: 30px; }
    </style>
    <div id="container">
      <div id="zero1"></div>
      <div id="zero2"></div>
      <div id="inflow"></div>
    </div>
  )HTML");

  BlockNode node(To<LayoutBlockFlow>(GetLayoutObjectByElementId("container")));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(1000), kIndefiniteSize),
      /* stretch_inline_size_if_auto */ true,
      /* is_new_formatting_context */ true);

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(node, space);
  EXPECT_EQ(PhysicalSize(200, 10), fragment->Size());

  FragmentChildIterator iterator(To<PhysicalBoxFragment>(fragment));

  PhysicalOffset offset;
  const PhysicalBoxFragment* child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(50, 0), child->Size());
  EXPECT_EQ(PhysicalOffset(0, -30), offset);

  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(70, 0), child->Size());
  EXPECT_EQ(PhysicalOffset(0, -10), offset);

  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(90, 20), child->Size());
  EXPECT_EQ(PhysicalOffset(0, -10), offset);
}

// This test assumes that tables are not yet implemented in LayoutNG.
TEST_F(BlockLayoutAlgorithmTest, RootFragmentOffsetInsideLegacy) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div style="display:table-cell;">
      <div id="innerNGRoot" style="margin-top:10px; margin-left:20px;"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const LayoutObject* innerNGRoot = GetLayoutObjectByElementId("innerNGRoot");

  ASSERT_TRUE(innerNGRoot->IsLayoutNGObject());
  const PhysicalBoxFragment* fragment =
      CurrentFragmentFor(To<LayoutBlockFlow>(innerNGRoot));

  ASSERT_TRUE(fragment);
  // TODO(crbug.com/781241: Re-enable when we calculate inline offset at
  // the right time.
  // EXPECT_EQ(PhysicalOffset(20, 10), fragment->Offset());
}

TEST_F(BlockLayoutAlgorithmTest, LayoutRubyTextCrash) {
  // crbug.com/1102186. This test passes if no DCHECK failure.
  SetBodyInnerHTML(R"HTML(
    <ruby>base<rt style="writing-mode:vertical-rl">annotation</ruby>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
}

TEST_F(BlockLayoutAlgorithmTest, HandleTextControlPlaceholderCrash) {
  // crbug.com/1209025 and crbug.com/1342608. This test passes if no crash.
  SetBodyInnerHTML(R"HTML(
<style>
input::first-line {
 color: red;
}
#num::-webkit-textfield-decoration-container {
 position: absolute;
}
</style>
<input id="i1" readonly>
<input id="num" type="number" placeholder="foo">)HTML");
  UpdateAllLifecyclePhasesForTest();
  auto* input = GetElementById("i1");
  input->setAttribute(html_names::kPlaceholderAttr, AtomicString("z"));
  UpdateAllLifecyclePhasesForTest();
}

}  // namespace
}  // namespace blink

"""


```