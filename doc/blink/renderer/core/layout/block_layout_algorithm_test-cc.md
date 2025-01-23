Response:
My thinking process to answer the request about `block_layout_algorithm_test.cc` went through these stages:

1. **Understanding the Core Request:** The main goal is to analyze the provided C++ test file and describe its function, relating it to web technologies (HTML, CSS, JavaScript) and common errors. The prompt explicitly asks for a summary of its functionality in this first part.

2. **Initial Scan and Keyword Recognition:** I quickly scanned the code for recognizable keywords and patterns:
    * `#include`:  Indicates dependencies, revealing the tested class (`block_layout_algorithm.h`) and testing frameworks (`gmock`, `core_unit_test_helper`).
    * `namespace blink`:  Confirms this is part of the Chromium Blink rendering engine.
    * `class BlockLayoutAlgorithmTest : public BaseLayoutAlgorithmTest`: Establishes this as a test fixture, inheriting from a base class.
    * `TEST_F`:  Identifies individual test cases.
    * `SetBodyInnerHTML`:  Suggests the tests manipulate the HTML structure.
    * `style="...`": Indicates manipulation of CSS styles.
    * `GetElementById`, `getElementsByTagName`: DOM manipulation.
    * `ConstraintSpace`, `BlockNode`, `PhysicalBoxFragment`, `LayoutResult`:  Core layout concepts being tested.
    * `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_THAT`:  Assertion macros for verifying test outcomes.
    * Specific test names like `FixedSize`, `Caching`, `MinInlineSizeCaching`, `CollapsingMarginsCase*`: Hint at the specific layout features being tested.

3. **Inferring the Primary Function:** Based on the included headers and test names, it became clear that this file tests the `BlockLayoutAlgorithm` class. This algorithm is a crucial part of Blink's layout engine, responsible for positioning and sizing block-level elements.

4. **Connecting to Web Technologies:** I then connected the C++ code and layout concepts to the corresponding web technologies:
    * **HTML:** The `SetBodyInnerHTML` function directly manipulates the HTML structure that the layout engine processes. The test cases create specific HTML structures to trigger different layout scenarios.
    * **CSS:** The `style` attributes and `UpdateStyleForElement` function demonstrate how CSS properties (like `width`, `height`, `margin`, `padding`, `float`, `position`, `writing-mode`, `clear`, etc.) affect the block layout. The tests verify that the `BlockLayoutAlgorithm` correctly interprets these styles.
    * **JavaScript:** While this specific test file doesn't *directly* involve JavaScript, it's essential to recognize that the layout engine is the underlying mechanism that makes JavaScript-driven DOM manipulations and style changes visible on the web page. Changes made by JavaScript would eventually trigger the `BlockLayoutAlgorithm`.

5. **Analyzing Test Cases for Specific Features:** I examined the individual test cases to understand which specific functionalities of the `BlockLayoutAlgorithm` are being tested:
    * **`FixedSize`:** Tests basic width and height calculations.
    * **`Caching`:**  Verifies the layout caching mechanism for performance optimization.
    * **`MinInlineSizeCaching`:** Focuses on caching related to `min-width`.
    * **`PercentageBlockSizeQuirkDescendantsCaching`:**  Tests a specific quirk in how percentage heights are handled.
    * **`LineOffsetCaching`:** Checks caching behavior related to block formatting context offsets.
    * **`LayoutBlockChildren`:**  Tests the layout of child elements within a block.
    * **`LayoutBlockChildrenWithWritingMode`:**  Focuses on layout with different `writing-mode` values.
    * **`CollapsingMarginsCase*`:**  A significant portion of the tests is dedicated to verifying the complex rules of CSS margin collapsing.

6. **Considering Logical Inference and Assumptions:** Although the prompt asked for assumptions, the tests are designed to be deterministic. The "inputs" are the HTML and CSS, and the "outputs" are the calculated sizes and positions of elements, verified by the `EXPECT_*` macros. There's less "inference" and more direct testing of expected behavior. However, one could *infer* the underlying layout rules being validated by the test scenarios.

7. **Identifying Potential User/Programming Errors:** Based on the tested scenarios, I considered common errors developers might make:
    * **Incorrectly assuming margin collapsing behavior:** The numerous `CollapsingMarginsCase*` tests highlight how nuanced this CSS feature is, and developers often misunderstand it.
    * **Forgetting about layout caching:**  Modifying styles or content without triggering a layout invalidation can lead to unexpected results if the developer doesn't understand how the browser optimizes rendering.
    * **Misunderstanding percentage height resolution:** The `PercentageBlockSizeQuirkDescendantsCaching` test points to a specific area where developers might encounter unexpected behavior.
    * **Issues with `writing-mode` interaction:** The test cases involving `writing-mode` suggest that this is an area where layout can become complex.
    * **Problems with `float` and `clear`:** The tests on collapsing margins with floats demonstrate the interplay between these properties.

8. **Structuring the Answer:** I organized my findings into clear sections as requested by the prompt:
    * **Functionality:**  A high-level description of the file's purpose.
    * **Relationship to Web Technologies:**  Specific examples of how the tests relate to HTML, CSS, and JavaScript.
    * **Logical Inference (though minimal here):**  A discussion of the direct input/output nature of the tests.
    * **Common Errors:** Examples of mistakes developers might make related to the tested features.
    * **Summary of Functionality (for Part 1):** A concise recap of the file's main purpose.

9. **Refinement and Language:** I reviewed and refined my answer to ensure clarity, accuracy, and adherence to the prompt's instructions. I used precise terminology related to web development and the Blink rendering engine.

By following these steps, I aimed to provide a comprehensive and informative answer that addresses all aspects of the request. The process involved understanding the code's structure, its purpose within the larger context of a browser engine, and its connection to the technologies used to build web pages.
```
文件功能概要（第 1 部分）：

`block_layout_algorithm_test.cc` 文件是 Chromium Blink 引擎中用于测试 `BlockLayoutAlgorithm` 类的单元测试文件。 `BlockLayoutAlgorithm` 负责处理块级盒子的布局计算。 这个测试文件包含了各种测试用例，用于验证 `BlockLayoutAlgorithm` 在不同场景下的布局行为是否正确，包括：

* **基本的尺寸计算:** 例如固定尺寸的盒子。
* **布局缓存机制:**  验证布局结果在相同或相似的约束条件下能否被正确缓存和复用，以提高性能。
* **最小/最大尺寸计算:** 测试 `BlockLayoutAlgorithm` 计算元素最小和最大尺寸的能力。
* **包含不同书写模式子元素的布局:** 验证父元素和子元素具有不同 `writing-mode` 时的布局。
* **外边距折叠:**  这是 CSS 布局中一个重要的概念，该文件包含大量测试用例来验证各种外边距折叠场景是否按照 CSS 规范工作，包括与浮动元素、不同书写模式、以及空元素相关的折叠。
* **带有 clear 属性的元素的布局:** 验证 `clear` 属性对元素定位的影响。

与 javascript, html, css 的功能关系及举例说明：

这个测试文件直接测试的是 Blink 引擎的 C++ 代码，但它所测试的逻辑与 HTML 结构和 CSS 样式密切相关。 最终，这些测试确保了浏览器能够正确地渲染由 HTML 和 CSS 定义的网页。

* **HTML:** 测试用例通过 `SetBodyInnerHTML` 设置 HTML 结构，模拟不同的布局场景。例如：
    ```c++
    SetBodyInnerHTML(R"HTML(
      <div id="box" style="width:30px; height:40px"></div>
    )HTML");
    ```
    这个 HTML 代码片段创建了一个 `div` 元素，用于测试固定尺寸的布局。

* **CSS:** 测试用例通过内联样式或 `<style>` 标签设置 CSS 属性，来定义元素的尺寸、外边距、浮动、定位等。例如：
    ```c++
    SetBodyInnerHTML(R"HTML(
      <div id="container" style="width: 30px">
        <div style="height: 20px"></div>
        <div style="height: 30px; margin-top: 5px; margin-bottom: 20px"></div>
      </div>
    )HTML");
    ```
    这里，CSS 属性 `width`, `height`, `margin-top`, `margin-bottom` 被用来创建特定的布局场景，并验证 `BlockLayoutAlgorithm` 是否正确处理了这些属性。  外边距折叠的测试用例更是大量使用不同的 margin 值组合来测试其行为。

* **Javascript:** 虽然这个测试文件本身不包含 JavaScript 代码，但它所测试的布局算法是 JavaScript 代码操作 DOM 和 CSSOM 后浏览器渲染页面的基础。 JavaScript 可以动态地修改元素的样式和结构，这些修改最终会触发布局计算。 这个测试文件保证了即使在 JavaScript 操作之后，布局仍然是正确的。 例如，一个 JavaScript 脚本可能修改一个元素的 `width` 属性，那么 `BlockLayoutAlgorithm` 就需要根据新的宽度重新计算布局，而这个测试文件中的 `FixedSize` 等测试用例就验证了这种基本情况。

逻辑推理的假设输入与输出：

**假设输入 (针对 `FixedSize` 测试用例):**

* HTML 结构: `<div id="box" style="width:30px; height:40px"></div>`
* `ConstraintSpace` 设置了可用的宽度为 100px，高度为无限大。

**逻辑推理:**  `BlockLayoutAlgorithm` 会解析 `div#box` 的内联样式，发现其宽度为 30px，高度为 40px。由于约束空间足够大，且没有其他影响布局的因素（例如浮动，定位），该元素将按照其指定的尺寸进行布局。

**预期输出:**

* `PhysicalBoxFragment` 的尺寸为宽度 30px，高度 40px。

**假设输入 (针对 `CollapsingMarginsCase2WithFloats` 的部分):**

* HTML 结构和 CSS 样式如代码所示，包含多个带有不同 margin 值的 div 元素，以及浮动元素。
* `ConstraintSpace` 提供了足够的空间进行布局。

**逻辑推理:** `BlockLayoutAlgorithm` 需要根据 CSS 的外边距折叠规则来计算相邻元素之间的最终外边距。例如，`#first-child` 的 `margin-bottom` 是 20px，`#second-child` 的 `margin-top` 是 10px。根据外边距折叠规则，它们之间的最终外边距将是 `max(20px, 10px) = 20px`。同时，浮动元素的存在会影响外边距折叠的行为。

**预期输出:**

* 各个 `PhysicalBoxFragment` 的偏移量 (Offset) 和尺寸 (Size) 将反映外边距折叠的结果，例如 `#second-child` 的顶部偏移量会考虑到与 `#first-child` 的外边距折叠。

用户或编程常见的使用错误举例说明：

* **误解外边距折叠:** 开发者可能会错误地认为相邻块级元素的上下外边距会相加，而不是折叠。例如，他们可能期望两个上下相邻的 `div`，各自设置了 20px 的外边距，它们之间的距离是 40px，但实际上可能是 20px。  `CollapsingMarginsCase*` 系列的测试就覆盖了这些容易出错的场景。

* **忘记清除浮动导致布局混乱:**  当父元素只包含浮动子元素时，如果没有正确地清除浮动，父元素的高度可能会塌陷。虽然这个测试文件不直接测试浮动清除，但它测试了浮动元素在块级布局中的定位，这与浮动清除密切相关。

* **不理解百分比高度的计算方式:**  百分比高度是相对于包含块的高度计算的，如果包含块的高度没有显式指定或者不是确定的值，百分比高度可能不会生效。`PercentageBlockSizeQuirkDescendantsCaching` 测试就涉及到这种场景。

* **修改样式后未触发重排:**  在 JavaScript 中修改了元素的样式，但如果浏览器没有正确地识别到需要重新布局，页面可能不会立即更新。虽然这个测试文件不直接测试 JavaScript 交互，但它验证了布局算法本身在不同约束条件下的正确性，是确保重排后布局正确的基石。

总结功能 (第 1 部分)：

总而言之，`block_layout_algorithm_test.cc` 的主要功能是 **系统地测试 Blink 引擎中负责块级元素布局的核心算法 `BlockLayoutAlgorithm` 的正确性**。它通过创建各种模拟的 HTML 结构和 CSS 样式场景，并断言布局结果是否符合预期，从而确保浏览器能够准确地渲染网页内容。测试涵盖了基本的尺寸计算、复杂的布局特性（如外边距折叠和浮动），以及性能优化相关的缓存机制。 这对于保证浏览器渲染的稳定性和一致性至关重要。
```
### 提示词
```
这是目录为blink/renderer/core/layout/block_layout_algorithm_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/tag_collection.h"
#include "third_party/blink/renderer/core/layout/base_layout_algorithm_test.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_fragment.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {
namespace {

using testing::ElementsAre;
using testing::Pointee;

class BlockLayoutAlgorithmTest : public BaseLayoutAlgorithmTest {
 protected:
  void SetUp() override { BaseLayoutAlgorithmTest::SetUp(); }

  const PhysicalBoxFragment* GetHtmlPhysicalFragment() const {
    const auto* layout_box =
        To<LayoutBox>(GetDocument()
                          .getElementsByTagName(AtomicString("html"))
                          ->item(0)
                          ->GetLayoutObject());
    return To<PhysicalBoxFragment>(
        &layout_box->GetSingleCachedLayoutResult()->GetPhysicalFragment());
  }

  MinMaxSizes RunComputeMinMaxSizes(BlockNode node) {
    // The constraint space is not used for min/max computation, but we need
    // it to create the algorithm.
    ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        LogicalSize(LayoutUnit(), LayoutUnit()));
    FragmentGeometry fragment_geometry = CalculateInitialFragmentGeometry(
        space, node, /* break_token */ nullptr, /* is_intrinsic */ true);

    BlockLayoutAlgorithm algorithm({node, fragment_geometry, space});
    return algorithm.ComputeMinMaxSizes(MinMaxSizesFloatInput()).sizes;
  }

  const LayoutResult* RunCachedLayoutResult(const ConstraintSpace& space,
                                            const BlockNode& node) {
    LayoutCacheStatus cache_status;
    std::optional<FragmentGeometry> initial_fragment_geometry;
    return To<LayoutBlockFlow>(node.GetLayoutBox())
        ->CachedLayoutResult(space, nullptr, nullptr, nullptr,
                             &initial_fragment_geometry, &cache_status);
  }

  String DumpFragmentTree(const PhysicalBoxFragment* fragment) {
    PhysicalFragment::DumpFlags flags =
        PhysicalFragment::DumpHeaderText | PhysicalFragment::DumpSubtree |
        PhysicalFragment::DumpIndentation | PhysicalFragment::DumpOffset |
        PhysicalFragment::DumpSize;

    return fragment->DumpFragmentTree(flags);
  }

  template <typename UpdateFunc>
  void UpdateStyleForElement(Element* element, const UpdateFunc& update) {
    auto* layout_object = element->GetLayoutObject();
    ComputedStyleBuilder builder(layout_object->StyleRef());
    update(builder);
    layout_object->SetStyle(builder.TakeStyle(),
                            LayoutObject::ApplyStyleChanges::kNo);
    layout_object->SetNeedsLayout("");
    UpdateAllLifecyclePhasesForTest();
  }
};

TEST_F(BlockLayoutAlgorithmTest, FixedSize) {
  SetBodyInnerHTML(R"HTML(
    <div id="box" style="width:30px; height:40px"></div>
  )HTML");

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), kIndefiniteSize));

  BlockNode box(GetLayoutBoxByElementId("box"));

  const PhysicalBoxFragment* fragment = RunBlockLayoutAlgorithm(box, space);

  EXPECT_EQ(PhysicalSize(30, 40), fragment->Size());
}

TEST_F(BlockLayoutAlgorithmTest, Caching) {
  // The inner element exists so that "simplified" layout logic isn't invoked.
  SetBodyInnerHTML(R"HTML(
    <div id="box" style="width:30px; height:40%;">
      <div style="height: 100%;"></div>
    </div>
  )HTML");

  AdvanceToLayoutPhase();
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)));

  auto* block_flow = To<LayoutBlockFlow>(GetLayoutObjectByElementId("box"));
  BlockNode node(block_flow);

  const LayoutResult* result = node.Layout(space, nullptr);
  EXPECT_EQ(PhysicalSize(30, 40), result->GetPhysicalFragment().Size());

  // Test pointer-equal constraint space.
  result = RunCachedLayoutResult(space, node);
  EXPECT_NE(result, nullptr);

  // Test identical, but not pointer-equal, constraint space.
  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)));
  result = RunCachedLayoutResult(space, node);
  EXPECT_NE(result, nullptr);

  // Test different constraint space.
  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(200), LayoutUnit(100)));
  result = RunCachedLayoutResult(space, node);
  EXPECT_NE(result, nullptr);

  // Test a different constraint space that will actually result in a different
  // sized fragment.
  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(200), LayoutUnit(200)));
  result = RunCachedLayoutResult(space, node);
  EXPECT_EQ(result, nullptr);

  // Test layout invalidation
  block_flow->SetNeedsLayout("");
  result = RunCachedLayoutResult(space, node);
  EXPECT_EQ(result, nullptr);
}

TEST_F(BlockLayoutAlgorithmTest, MinInlineSizeCaching) {
  SetBodyInnerHTML(R"HTML(
    <div id="box" style="min-width:30%; width: 10px; height:40px;"></div>
  )HTML");

  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)));

  auto* block_flow = To<LayoutBlockFlow>(GetLayoutObjectByElementId("box"));
  BlockNode node(block_flow);

  const LayoutResult* result = node.Layout(space, nullptr);
  EXPECT_EQ(PhysicalSize(30, 40), result->GetPhysicalFragment().Size());

  // Test pointer-equal constraint space.
  result = RunCachedLayoutResult(space, node);
  EXPECT_NE(result, nullptr);

  // Test identical, but not pointer-equal, constraint space.
  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(100)));
  result = RunCachedLayoutResult(space, node);
  EXPECT_NE(result, nullptr);

  // Test different constraint space.
  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), LayoutUnit(200)));
  result = RunCachedLayoutResult(space, node);
  EXPECT_NE(result, nullptr);

  // Test a different constraint space that will actually result in a different
  // size.
  space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(200), LayoutUnit(100)));
  result = RunCachedLayoutResult(space, node);
  EXPECT_EQ(result, nullptr);
}

TEST_F(BlockLayoutAlgorithmTest, PercentageBlockSizeQuirkDescendantsCaching) {
  // Quirks mode triggers the interesting parent-child %-resolution behavior.
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);

  SetBodyInnerHTML(R"HTML(
    <div id="container" style="display: flow-root; width: 100px; height: 100px;">
      <div id="box1"></div>
      <div id="box2">
        <div style="height: 20px;"></div>
        <div style="height: 20px;"></div>
      </div>
      <div id="box3">
        <div style="height: 20px;"></div>
        <div style="height: 50%;"></div>
      </div>
      <div id="box4">
        <div style="height: 20px;"></div>
        <div style="display: flex;"></div>
      </div>
      <div id="box5">
        <div style="height: 20px;"></div>
        <div style="display: flex; height: 50%;"></div>
      </div>
      <div id="box6" style="position: relative;">
        <div style="position: absolute; width: 10px; height: 100%;"></div>
      </div>
      <div id="box7">
        <img />
      </div>
      <div id="box8">
        <img style="height: 100%;" />
      </div>
    </div>
  )HTML");

  auto create_space = [&](auto size) -> ConstraintSpace {
    ConstraintSpaceBuilder builder(
        WritingMode::kHorizontalTb,
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        /* is_new_formatting_context */ false);
    builder.SetAvailableSize(size);
    builder.SetPercentageResolutionSize(size);
    builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
    return builder.ToConstraintSpace();
  };

  ConstraintSpace space100 =
      create_space(LogicalSize(LayoutUnit(100), LayoutUnit(100)));
  ConstraintSpace space200 =
      create_space(LogicalSize(LayoutUnit(100), LayoutUnit(200)));

  auto run_test = [&](auto id) -> const LayoutResult* {
    // Grab the box under test.
    auto* box = To<LayoutBlockFlow>(GetLayoutObjectByElementId(id));
    BlockNode node(box);

    // Check that we have a cache hit with space100.
    const LayoutResult* result = RunCachedLayoutResult(space100, node);
    EXPECT_NE(result, nullptr);

    // Return the result of the cache with space200.
    return RunCachedLayoutResult(space200, node);
  };

  // Test 1: No descendants.
  EXPECT_NE(run_test("box1"), nullptr);

  // Test 2: No %-height descendants.
  EXPECT_NE(run_test("box2"), nullptr);

  // Test 3: A %-height descendant.
  EXPECT_EQ(run_test("box3"), nullptr);

  // Test 4: A flexbox (legacy descendant), which doesn't use the quirks mode
  // behavior.
  EXPECT_NE(run_test("box4"), nullptr);

  // Test 5: A flexbox (legacy descendant), which doesn't use the quirks mode
  // behavior, but is %-sized.
  EXPECT_EQ(run_test("box5"), nullptr);

  // Test 6: An OOF positioned descentant which has a %-height, should not
  // count as a percentage descendant.
  EXPECT_NE(run_test("box6"), nullptr);

  // Test 7: A replaced element (legacy descendant), shouldn't use the quirks
  // mode behavior.
  EXPECT_NE(run_test("box7"), nullptr);

  // Test 8: A replaced element (legacy descendant), shouldn't use the quirks
  // mode behavior, but is %-sized.
  EXPECT_EQ(run_test("box8"), nullptr);
}

TEST_F(BlockLayoutAlgorithmTest, LineOffsetCaching) {
  SetBodyInnerHTML(R"HTML(
    <div id="container" style="display: flow-root; width: 300px; height: 100px;">
      <div id="box1" style="width: 100px; margin: 0 auto 0 auto;"></div>
    </div>
  )HTML");

  auto create_space = [&](auto size, auto bfc_offset) -> ConstraintSpace {
    ConstraintSpaceBuilder builder(
        WritingMode::kHorizontalTb,
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        /* is_new_formatting_context */ false);
    builder.SetAvailableSize(size);
    builder.SetPercentageResolutionSize(size);
    builder.SetBfcOffset(bfc_offset);
    return builder.ToConstraintSpace();
  };

  ConstraintSpace space200 =
      create_space(LogicalSize(LayoutUnit(300), LayoutUnit(100)),
                   BfcOffset(LayoutUnit(50), LayoutUnit()));

  const LayoutResult* result = nullptr;
  auto* box1 = To<LayoutBlockFlow>(GetLayoutObjectByElementId("box1"));

  // Ensure we get a cached layout result, even if our BFC line-offset changed.
  result = RunCachedLayoutResult(space200, BlockNode(box1));
  EXPECT_NE(result, nullptr);
}

// Verifies that two children are laid out with the correct size and position.
TEST_F(BlockLayoutAlgorithmTest, LayoutBlockChildren) {
  SetBodyInnerHTML(R"HTML(
    <div id="container" style="width: 30px">
      <div style="height: 20px">
      </div>
      <div style="height: 30px; margin-top: 5px; margin-bottom: 20px">
      </div>
    </div>
  )HTML");
  const int kWidth = 30;
  const int kHeight1 = 20;
  const int kHeight2 = 30;
  const int kMarginTop = 5;

  BlockNode container(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(100), kIndefiniteSize));

  const PhysicalBoxFragment* fragment =
      RunBlockLayoutAlgorithm(container, space);

  EXPECT_EQ(LayoutUnit(kWidth), fragment->Size().width);
  EXPECT_EQ(LayoutUnit(kHeight1 + kHeight2 + kMarginTop),
            fragment->Size().height);
  EXPECT_EQ(PhysicalFragment::kFragmentBox, fragment->Type());
  ASSERT_EQ(fragment->Children().size(), 2UL);

  const PhysicalFragmentLink& first_child = fragment->Children()[0];
  EXPECT_EQ(kHeight1, first_child->Size().height);
  EXPECT_EQ(0, first_child.Offset().top);

  const PhysicalFragmentLink& second_child = fragment->Children()[1];
  EXPECT_EQ(kHeight2, second_child->Size().height);
  EXPECT_EQ(kHeight1 + kMarginTop, second_child.Offset().top);
}

// Verifies that a child is laid out correctly if it's writing mode is different
// from the parent's one.
TEST_F(BlockLayoutAlgorithmTest, LayoutBlockChildrenWithWritingMode) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #div2 {
        width: 50px;
        height: 50px;
        margin-left: 100px;
        writing-mode: horizontal-tb;
      }
    </style>
    <div id="container">
      <div id="div1" style="writing-mode: vertical-lr;">
        <div id="div2">
        </div>
      </div>
    </div>
  )HTML");
  const int kHeight = 50;
  const int kMarginLeft = 100;

  BlockNode container(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(500), LayoutUnit(500)));
  const PhysicalBoxFragment* fragment =
      RunBlockLayoutAlgorithm(container, space);

  const PhysicalFragmentLink& child = fragment->Children()[0];
  const PhysicalFragmentLink& child2 =
      static_cast<const PhysicalBoxFragment*>(child.get())->Children()[0];

  EXPECT_EQ(kHeight, child2->Size().height);
  EXPECT_EQ(0, child2.Offset().top);
  EXPECT_EQ(kMarginLeft, child2.Offset().left);
}

// Verifies that floats are positioned at the top of the first child that can
// determine its position after margins collapsed.
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsCase1WithFloats) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #container {
          height: 200px;
          width: 200px;
          margin-top: 10px;
          padding: 0 7px;
          background-color: red;
        }
        #first-child {
          margin-top: 20px;
          height: 10px;
          background-color: blue;
        }
        #float-child-left {
          float: left;
          height: 10px;
          width: 10px;
          padding: 10px;
          margin: 10px;
          background-color: green;
        }
        #float-child-right {
          float: right;
          height: 30px;
          width: 30px;
          background-color: pink;
        }
      </style>
      <div id='container'>
        <div id='float-child-left'></div>
        <div id='float-child-right'></div>
        <div id='first-child'></div>
      </div>
    )HTML");

  const auto* fragment = GetHtmlPhysicalFragment();
  ASSERT_EQ(fragment->Children().size(), 1UL);

  PhysicalOffset body_offset = fragment->Children()[0].Offset();
  auto* body_fragment = To<PhysicalBoxFragment>(fragment->Children()[0].get());
  // 20 = max(first child's margin top, containers's margin top)
  int body_top_offset = 20;
  EXPECT_THAT(LayoutUnit(body_top_offset), body_offset.top);
  // 8 = body's margin
  int body_left_offset = 8;
  EXPECT_THAT(LayoutUnit(body_left_offset), body_offset.left);
  ASSERT_EQ(1UL, body_fragment->Children().size());

  auto* container_fragment =
      To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
  PhysicalOffset container_offset = body_fragment->Children()[0].Offset();

  // 0 = collapsed with body's margin
  EXPECT_THAT(LayoutUnit(0), container_offset.top);
  ASSERT_EQ(3UL, container_fragment->Children().size());

  PhysicalOffset child_offset = container_fragment->Children()[2].Offset();

  // 0 = collapsed with container's margin
  EXPECT_THAT(LayoutUnit(0), child_offset.top);
}

// Verifies the collapsing margins case for the next pairs:
// - bottom margin of box and top margin of its next in-flow following sibling.
// - top and bottom margins of a box that does not establish a new block
//   formatting context and that has zero computed 'min-height', zero or 'auto'
//   computed 'height', and no in-flow children
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsCase2WithFloats) {
  SetBodyInnerHTML(R"HTML(
      <style>
      #first-child {
        background-color: red;
        height: 50px;
        margin-bottom: 20px;
      }
      #float-between-empties {
        background-color: green;
        float: left;
        height: 30px;
        width: 30px;
      }
      #float-between-nonempties {
        background-color: lightgreen;
        float: left;
        height: 40px;
        width: 40px;
      }
      #float-top-align {
        background-color: seagreen;
        float: left;
        height: 50px;
        width: 50px;
      }
      #second-child {
        background-color: blue;
        height: 50px;
        margin-top: 10px;
      }
      </style>
      <div id='first-child'>
        <div id='empty1' style='margin-bottom: -15px'></div>
        <div id='float-between-empties'></div>
        <div id='empty2'></div>
      </div>
      <div id='float-between-nonempties'></div>
      <div id='second-child'>
        <div id='float-top-align'></div>
        <div id='empty3'></div>
        <div id='empty4' style='margin-top: -30px'></div>
      </div>
      <div id='empty5'></div>
    )HTML");

  const auto* fragment = GetHtmlPhysicalFragment();
  auto* body_fragment = To<PhysicalBoxFragment>(fragment->Children()[0].get());
  PhysicalOffset body_offset = fragment->Children()[0].Offset();
  // -7 = empty1's margin(-15) + body's margin(8)
  EXPECT_THAT(LayoutUnit(-7), body_offset.top);
  ASSERT_EQ(4UL, body_fragment->Children().size());

  FragmentChildIterator iterator(body_fragment);
  PhysicalOffset offset;
  iterator.NextChild(&offset);
  EXPECT_THAT(LayoutUnit(), offset.top);

  iterator.NextChild(&offset);
  // 70 = first_child's height(50) + first child's margin-bottom(20)
  EXPECT_THAT(offset.top, LayoutUnit(70));
  EXPECT_THAT(offset.left, LayoutUnit(0));

  iterator.NextChild(&offset);
  // 40 = first_child's height(50) - margin's collapsing result(10)
  EXPECT_THAT(LayoutUnit(40), offset.top);

  iterator.NextChild(&offset);
  // 90 = first_child's height(50) + collapsed margins(-10) +
  // second child's height(50)
  EXPECT_THAT(LayoutUnit(90), offset.top);

  // ** Verify layout tree **
  Element* first_child = GetElementById("first-child");
  // -7 = body_top_offset
  EXPECT_EQ(-7, first_child->OffsetTop());
}

// Verifies the collapsing margins case for the next pair:
// - bottom margin of a last in-flow child and bottom margin of its parent if
//   the parent has 'auto' computed height
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsCase3) {
  SetBodyInnerHTML(R"HTML(
      <style>
       #container {
         margin-bottom: 20px;
       }
       #child {
         margin-bottom: 200px;
         height: 50px;
       }
      </style>
      <div id='container'>
        <div id='child'></div>
      </div>
    )HTML");

  const PhysicalBoxFragment* body_fragment = nullptr;
  const PhysicalBoxFragment* container_fragment = nullptr;
  const PhysicalBoxFragment* child_fragment = nullptr;
  const PhysicalBoxFragment* fragment = nullptr;
  auto run_test = [&](const Length& container_height) {
    UpdateStyleForElement(GetElementById("container"),
                          [&](ComputedStyleBuilder& builder) {
                            builder.SetHeight(container_height);
                          });
    fragment = GetHtmlPhysicalFragment();
    ASSERT_EQ(1UL, fragment->Children().size());
    body_fragment = To<PhysicalBoxFragment>(fragment->Children()[0].get());
    container_fragment =
        To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
    ASSERT_EQ(1UL, container_fragment->Children().size());
    child_fragment =
        To<PhysicalBoxFragment>(container_fragment->Children()[0].get());
  };

  // height == auto
  run_test(Length::Auto());
  // Margins are collapsed with the result 200 = std::max(20, 200)
  // The fragment size 258 == body's margin 8 + child's height 50 + 200
  EXPECT_EQ(PhysicalSize(800, 258), fragment->Size());

  // height == fixed
  run_test(Length::Fixed(50));
  // Margins are not collapsed, so fragment still has margins == 20.
  // The fragment size 78 == body's margin 8 + child's height 50 + 20
  EXPECT_EQ(PhysicalSize(800, 78), fragment->Size());
}

// Verifies that 2 adjoining margins are not collapsed if there is padding or
// border that separates them.
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsCase4) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #container {
          margin: 30px 0px;
          width: 200px;
        }
        #child {
         margin: 200px 0px;
          height: 50px;
          background-color: blue;
        }
      </style>
      <div id='container'>
        <div id='child'></div>
      </div>
    )HTML");

  PhysicalOffset body_offset;
  PhysicalOffset container_offset;
  PhysicalOffset child_offset;
  const PhysicalBoxFragment* fragment = nullptr;
  auto run_test = [&](const Length& container_padding_top) {
    UpdateStyleForElement(GetElementById("container"),
                          [&](ComputedStyleBuilder& builder) {
                            builder.SetPaddingTop(container_padding_top);
                          });
    fragment = GetHtmlPhysicalFragment();
    ASSERT_EQ(1UL, fragment->Children().size());
    const auto* body_fragment =
        To<PhysicalBoxFragment>(fragment->Children()[0].get());
    body_offset = fragment->Children()[0].Offset();
    const auto* container_fragment =
        To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
    container_offset = body_fragment->Children()[0].Offset();
    ASSERT_EQ(1UL, container_fragment->Children().size());
    child_offset = container_fragment->Children()[0].Offset();
  };

  // with padding
  run_test(Length::Fixed(20));
  // 500 = child's height 50 + 2xmargin 400 + paddint-top 20 +
  // container's margin 30
  EXPECT_EQ(PhysicalSize(800, 500), fragment->Size());
  // 30 = max(body's margin 8, container margin 30)
  EXPECT_EQ(LayoutUnit(30), body_offset.top);
  // 220 = container's padding top 20 + child's margin
  EXPECT_EQ(LayoutUnit(220), child_offset.top);

  // without padding
  run_test(Length::Fixed(0));
  // 450 = 2xmax(body's margin 8, container's margin 30, child's margin 200) +
  //       child's height 50
  EXPECT_EQ(PhysicalSize(800, 450), fragment->Size());
  // 200 = (body's margin 8, container's margin 30, child's margin 200)
  EXPECT_EQ(LayoutUnit(200), body_offset.top);
  // 0 = collapsed margins
  EXPECT_EQ(LayoutUnit(0), child_offset.top);
}

// Verifies that margins of 2 adjoining blocks with different writing modes
// get collapsed.
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsCase5) {
  SetBodyInnerHTML(R"HTML(
      <style>
        #container {
          margin-top: 10px;
          writing-mode: vertical-lr;
        }
        #vertical {
          margin-right: 90px;
          background-color: red;
          height: 70px;
          width: 30px;
        }
        #horizontal {
         background-color: blue;
          margin-left: 100px;
          writing-mode: horizontal-tb;
          height: 60px;
          width: 30px;
        }
      </style>
      <div id='container'>
        <div id='vertical'></div>
        <div id='horizontal'></div>
      </div>
    )HTML");
  const auto* fragment = GetHtmlPhysicalFragment();

  // body
  auto* body_fragment = To<PhysicalBoxFragment>(fragment->Children()[0].get());
  PhysicalOffset body_offset = fragment->Children()[0].Offset();
  // 10 = std::max(body's margin 8, container's margin top)
  int body_top_offset = 10;
  EXPECT_THAT(body_offset.top, LayoutUnit(body_top_offset));
  int body_left_offset = 8;
  EXPECT_THAT(body_offset.left, LayoutUnit(body_left_offset));

  // height = 70. std::max(vertical height's 70, horizontal's height's 60)
  ASSERT_EQ(PhysicalSize(784, 70), body_fragment->Size());
  ASSERT_EQ(1UL, body_fragment->Children().size());

  // container
  auto* container_fragment =
      To<PhysicalBoxFragment>(body_fragment->Children()[0].get());
  PhysicalOffset container_offset = body_fragment->Children()[0].Offset();
  // Container's margins are collapsed with body's fragment.
  EXPECT_THAT(container_offset.top, LayoutUnit());
  EXPECT_THAT(container_offset.left, LayoutUnit());
  ASSERT_EQ(2UL, container_fragment->Children().size());

  // vertical
  PhysicalOffset vertical_offset = container_fragment->Children()[0].Offset();
  EXPECT_THAT(vertical_offset.top, LayoutUnit());
  EXPECT_THAT(vertical_offset.left, LayoutUnit());

  // horizontal
  PhysicalOffset orizontal_offset = container_fragment->Children()[1].Offset();
  EXPECT_THAT(orizontal_offset.top, LayoutUnit());
  // 130 = vertical's width 30 +
  //       std::max(vertical's margin right 90, horizontal's margin-left 100)
  EXPECT_THAT(orizontal_offset.left, LayoutUnit(130));
}

// Verifies that margins collapsing logic works with Layout Inline.
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsWithText) {
  SetBodyInnerHTML(R"HTML(
      <!DOCTYPE html>
      <style>
        body {
          margin: 10px;
        }
        p {
          margin: 20px;
        }
      </style>
      <p>Some text</p>
    )HTML");
  const auto* html_fragment = GetHtmlPhysicalFragment();

  const auto* body_fragment =
      To<PhysicalBoxFragment>(html_fragment->Children()[0].get());
  PhysicalOffset body_offset = html_fragment->Children()[0].Offset();
  // 20 = std::max(body's margin, p's margin)
  EXPECT_THAT(body_offset, PhysicalOffset(10, 20));

  PhysicalOffset p_offset = body_fragment->Children()[0].Offset();
  // Collapsed margins with result = 0.
  EXPECT_THAT(p_offset, PhysicalOffset(20, 0));
}

// Verifies that the margin strut of a child with a different writing mode does
// not get used in the collapsing margins calculation.
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsCase6) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #div1 {
        margin-bottom: 10px;
        width: 10px;
        height: 60px;
        writing-mode: vertical-rl;
      }
      #div2 { margin-left: -20px; width: 10px; }
      #div3 { margin-top: 40px; height: 60px; }
    </style>
    <div id="container" style="width:500px;height:500px">
      <div id="div1">
         <div id="div2">vertical</div>
      </div>
      <div id="div3"></div>
    </div>
  )HTML");
  const int kHeight = 60;
  const int kMarginBottom = 10;
  const int kMarginTop = 40;

  BlockNode container(GetLayoutBoxByElementId("container"));
  ConstraintSpace space = ConstructBlockLayoutTestConstraintSpace(
      {WritingMode::kHorizontalTb, TextDirection::kLtr},
      LogicalSize(LayoutUnit(500), LayoutUnit(500)));
  const PhysicalBoxFragment* fragment =
      RunBlockLayoutAlgorithm(container, space);

  ASSERT_EQ(fragment->Children().size(), 2UL);

  const PhysicalFragment* child1 = fragment->Children()[0].get();
  PhysicalOffset child1_offset = fragment->Children()[0].Offset();
  EXPECT_EQ(0, child1_offset.top);
  EXPECT_EQ(kHeight, child1->Size().height);

  PhysicalOffset child2_offset = fragment->Children()[1].Offset();
  EXPECT_EQ(kHeight + std::max(kMarginBottom, kMarginTop), child2_offset.top);
}

// Verifies that a child with clearance - which does nothing - still shifts its
// parent's offset.
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsCase7) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      outline: solid purple 1px;
      width: 200px;
    }
    #zero {
      outline: solid red 1px;
      margin-top: 10px;
    }
    #float {
      background: yellow;
      float: right;
      width: 20px;
      height: 20px;
    }
    #inflow {
      background: blue;
      clear: left;
      height: 20px;
      margin-top: 20px;
    }
    </style>
    <div id="zero">
      <div id="float"></div>
    </div>
    <div id="inflow"></div>
  )HTML");

  const auto* fragment = GetHtmlPhysicalFragment();
  FragmentChildIterator iterator(fragment);

  // body
  PhysicalOffset offset;
  const PhysicalBoxFragment* child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(200, 20), child->Size());
  EXPECT_EQ(PhysicalOffset(8, 20), offset);

  // #zero
  iterator.SetParent(child);
  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(200, 0), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 0), offset);

  // #inflow
  child = iterator.NextChild(&offset);
  EXPECT_EQ(PhysicalSize(200, 20), child->Size());
  EXPECT_EQ(PhysicalOffset(0, 0), offset);
}

// An empty block level element (with margins collapsing through it) has
// non-trivial behavior with margins collapsing.
TEST_F(BlockLayoutAlgorithmTest, CollapsingMarginsEmptyBlockWithClearance) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      position: relative;
      outline: solid purple 1px;
      display: flow-root;
      width: 200px;
    }
    #float {
      background: orange;
      float: left;
      width: 50px;
      height: 50px;
    }
    #zero {
      outline: solid red 1px;
      clear: left;
    }
    #abs {
      background: cyan;
      position: absolute;
      width: 20px;
      height: 20px;
    }
    #inflow {
      background: green;
      height: 20px;
    }
    </style>
    <div id="float"></div>
    <div id="zero-top"></div>
    <div id="zero">
      <!-- This exists to produce complex margin struts. -->
      <div id="zero-inner"></div>
    </div>
    <div id="abs"></div>
    <div id="inflow"></div>
  )HTML");

  const LayoutBlockFlow* zero;
  const LayoutBlockFlow* abs;
  const LayoutBlockFlow* inflow;
  auto run_test = [&](const Length& zero_top_margin_bottom,
                      const Length& zero_inner_margin_top,
                      const Length& zero_inner_margin_bottom,
                      const Length& zero_margin_bottom,
                      const Length& inflow_margin_top) {
    // Set the style of the elements we care about.
    UpdateStyleForElement(GetElementById("zero-top"),
                          [&](ComputedStyleBuilder& builder) {
                            builder.SetMarginBottom(zero_top_margin_bottom);
                          });
    UpdateStyleForElement(GetElementById("zero-inner"),
                          [&](ComputedStyleBuilder& builder) {
                            builder.SetMarginTop(zero_inner_margin_top);
                            builder.SetMarginBottom(zero_inner_margin_bottom);
                          });
    UpdateStyleForElement(GetElementById("zero"),
                          [&](ComputedStyleBuilder& builder) {
                            builder.SetMarginBottom(zero_margin_bottom);
                          });
    UpdateStyleForElement(GetElementById("inflow"),
                          [&](ComputedStyleBuilder& builder) {
                            builder.SetMarginTop(inflow_margin_top);
                          });
    UpdateAllLifecyclePhasesForTest();

    LayoutBlockFlow* child;
    // #float
    child = To<LayoutBlockFlow>(GetLayoutObjectByElementId("float"));
    EXPECT_EQ(PhysicalSize(LayoutUnit(50), LayoutUnit(50)), child->Size());
    EXPECT_EQ(PhysicalOffset(0, 0), child->PhysicalLocation());

    // We need to manually test the position of #zero, #abs, #inflow.
    zero = To<LayoutBlockFlow>(GetLayoutObjectByElementId("zero"));
    inflow = To<LayoutBlockFlow>(GetLayoutObjectByElementId("inflow"));
    abs = To<LayoutBlockFlow>(GetLayoutObjectByElementId("abs"));
  };

  // Base case of no margins.
  run_test(
      /* #zero-top margin-bottom */ Length::Fixed(0),
      /* #zero-inner margin-top */ Length::Fixed(0),
      /* #zero-inner margin-bottom */ Length::Fixed(0),
      /* #zero margin-bottom */
```