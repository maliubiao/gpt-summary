Response:
My thinking process to analyze the `length_utils_test.cc` file went something like this:

1. **Understand the File's Purpose:** The filename ends with `_test.cc`, strongly indicating this is a unit test file. It's located in a `layout` subdirectory, suggesting it tests layout-related functionalities. The `length_utils` part of the name pinpoints the specific area being tested: utilities for handling lengths in CSS.

2. **Scan the Includes:** The included headers provide crucial context:
    * `length_utils.h`: This is the header file for the code being tested.
    * `testing/gtest/include/gtest/gtest.h`:  Confirms this uses the Google Test framework.
    * Headers related to `css`, `layout`, `style`, and `geometry`: These tell us the tests deal with CSS properties (like `width`, `height`, `padding`, `margin`), layout concepts (like `BlockNode`, `ConstraintSpace`), styling (`ComputedStyle`), and geometric calculations (`LayoutUnit`, `Length`).
    * `core_unit_test_helper.h`, `task_environment.h`: These are Blink-specific testing utilities.

3. **Identify Key Classes and Functions Under Test:**  The test file defines a class `LengthUtilsTest`. Within its methods, I see calls to functions like `ResolveMainInlineLength`, `ResolveMinInlineLength`, `ResolveMaxInlineLength`, `ResolveMainBlockLength`, `ComputeInlineSizeForFragment`, `ComputeBlockSizeForFragment`, `ComputePhysicalMargins`, `ComputeBordersForTest`, `ComputePadding`, `ResolveInlineAutoMargins`, `ResolveUsedColumnInlineSize`, `ResolveUsedColumnCount`, and `InlineSizeFromAspectRatio`. These are the core functions in `length_utils.h` that are being validated.

4. **Analyze Individual Test Cases:**  I then examined each `TEST_F` block to understand what specific scenarios are being tested:
    * **`TestResolveInlineLength`:** Tests resolving various `Length` types (`percent`, `fixed`, `stretch`, `min-content`, `max-content`, `fit-content`) for inline dimensions. The `ConstraintSpace` setup indicates it's dealing with layout context.
    * **`TestIndefiniteResolveInlineLength`:** Focuses on how lengths are resolved when available space is indefinite (indicated by negative values in `ConstructConstraintSpace`).
    * **`TestResolveBlockLength`:** Similar to `TestResolveInlineLength` but for block dimensions.
    * **`TestComputeContentContribution`:**  Tests how `min-content` and `max-content` are calculated, considering factors like padding and `box-sizing`. It uses actual HTML elements for testing.
    * **`TestComputeInlineSizeForFragment` and `TestComputeBlockSizeForFragment`:** These are more comprehensive tests of how inline and block sizes are computed for layout fragments, taking into account percentages, fixed values, `fill-available`, `calc()`, `min-width`, `max-width`, margins, padding, and `box-sizing`.
    * **`TestIndefinitePercentages`:**  Specifically checks how percentage-based heights are handled when the containing block's height is indefinite.
    * **`ComputeReplacedSizeSvgNoScaling`:**  Likely a regression test to ensure SVG elements without explicit scaling don't cause issues.
    * **`TestMargins`, `TestBorders`, `TestPadding`:** Test the computation of margin, border, and padding sizes based on different `Length` types and writing modes.
    * **`TestAutoMargins`:**  Verifies how `auto` margins are resolved to center content.
    * **`TestColumnWidthAndCount`:**  Tests the logic for calculating column widths and counts in multi-column layouts.
    * **`AspectRatio`:**  Tests the calculation of inline size based on the `aspect-ratio` CSS property.

5. **Identify Relationships to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The test uses `SetBodyInnerHTML` to create DOM elements, directly relating to HTML structure. The IDs used in the HTML (`test1`, `test2`, etc.) are used to target specific layout objects.
    * **CSS:** The `style` attributes within the HTML snippets and the `ComputedStyleBuilder` directly correspond to CSS properties. The tests validate how these CSS properties influence layout calculations. Examples include `width`, `height`, `padding`, `margin`, `box-sizing`, `min-width`, `max-width`, `aspect-ratio`, `-webkit-fill-available`, and `calc()`.
    * **JavaScript:** While this specific test file doesn't directly execute JavaScript, the layout engine is responsible for rendering web pages that include JavaScript. JavaScript can dynamically modify CSS styles, and these tests ensure that the layout calculations are correct regardless of how the styles are applied. Specifically, JavaScript could be used to change the `width`, `height`, or other layout-related properties, and the layout engine needs to handle these changes correctly.

6. **Infer Logical Reasoning and Assumptions:** The tests make assumptions about how CSS properties should be interpreted. For example, the tests for percentage-based lengths assume a specific containing block size. The tests for `min-content` and `max-content` imply a certain understanding of how these keywords affect the intrinsic sizing of elements. The `DCHECK_IS_ON()` block highlights an internal assertion that should fail under certain conditions (likely invalid input).

7. **Identify Potential User/Programming Errors:** The tests implicitly demonstrate common errors:
    * **Incorrect percentage calculations:**  Forgetting that percentages are relative to a containing block.
    * **Misunderstanding `box-sizing`:** Not realizing how `border-box` includes padding and border in the element's total size.
    * **Conflicting constraints:** Setting `min-width` and `max-width` that create impossible scenarios.
    * **Using length units incorrectly:**  Applying block-related lengths to inline properties or vice versa.
    * **Assuming indefinite sizes work like definite sizes:**  The tests for indefinite sizes highlight that certain calculations behave differently when the available space is unknown.

8. **Structure the Output:** Finally, I organized my findings into the requested categories: functionality, relationships to web technologies, logical reasoning, and common errors, providing specific examples from the code.
这个C++源代码文件 `length_utils_test.cc` 是 Chromium Blink 引擎的一部分，它的主要功能是 **测试 `length_utils.h` 中定义的与 CSS 长度值解析和计算相关的实用工具函数 (utility functions)**。

更具体地说，它测试了在布局 (layout) 过程中如何将各种 CSS 长度单位 (如像素、百分比、`auto`、`min-content`、`max-content`、`fit-content` 等) 解析为实际的布局单位 (LayoutUnit)。

下面详细列举其功能，并根据要求进行说明：

**1. 功能列举:**

* **测试长度解析函数:**
    * `ResolveMainInlineLength`: 测试解析元素主轴（通常是水平方向）的内联尺寸。
    * `ResolveMinInlineLength`: 测试解析元素最小内联尺寸。
    * `ResolveMaxInlineLength`: 测试解析元素最大内联尺寸。
    * `ResolveMainBlockLength`: 测试解析元素主轴（通常是垂直方向）的块状尺寸。
* **测试片段尺寸计算函数:**
    * `ComputeInlineSizeForFragment`: 测试计算布局片段的内联尺寸。
    * `ComputeBlockSizeForFragment`: 测试计算布局片段的块状尺寸。
* **测试内容贡献计算函数:**
    * `ComputeMinAndMaxContentContributionForTest`: 测试计算元素的最小和最大内容贡献 (这会影响 `min-content` 和 `max-content` 的计算)。
* **测试边距、边框和内边距计算函数:**
    * `ComputePhysicalMargins`: 测试计算元素的物理边距 (考虑书写模式和方向)。
    * `ComputeBordersForTest`: 测试计算元素的边框尺寸。
    * `ComputePadding`: 测试计算元素的内边距尺寸。
* **测试自动边距解析函数:**
    * `ResolveInlineAutoMargins`: 测试解析内联方向的自动边距。
* **测试多列布局相关函数:**
    * `ResolveUsedColumnInlineSize`: 测试计算多列布局中使用的列宽。
    * `ResolveUsedColumnCount`: 测试计算多列布局中使用的列数。
* **测试宽高比计算函数:**
    * `InlineSizeFromAspectRatio`: 测试根据宽高比和块状尺寸计算内联尺寸。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接关联到 **CSS** 的功能，因为它测试的是 CSS 长度值的解析和计算。这些长度值在 HTML 中通过 `style` 属性或外部 CSS 文件进行声明，最终由浏览器的布局引擎 (Blink) 进行解析和应用。 JavaScript 可以动态修改元素的 CSS 样式，从而间接地影响这些长度值的计算。

* **CSS 长度单位的解析:**  测试文件模拟了浏览器解析各种 CSS 长度单位的过程。例如：
    * `Length::Percent(30)` 对应 CSS 中的 `30%`。
    * `Length::Fixed(150)` 对应 CSS 中的 `150px`。
    * `Length::Stretch()` 对应 CSS 中的 `auto` (在某些上下文中)。
    * `Length::MinContent()` 对应 CSS 中的 `min-content`。
    * `Length::MaxContent()` 对应 CSS 中的 `max-content`。
    * `Length::FitContent()` 对应 CSS 中的 `fit-content`。
    * `-webkit-fill-available` 对应 CSS 中的 `fill-available` (WebKit/Blink 特有)。
    * `calc(100px + 10%)` 对应 CSS 中的 `calc()` 函数。

    **举例:** `TEST_F(LengthUtilsTest, TestResolveInlineLength)` 测试了对于 CSS 属性 `width: 30%;`，在容器宽度为 200px 的情况下，`ResolveMainInlineLength` 函数是否能正确计算出 60px。

* **CSS 盒模型 (Box Model) 的计算:** 测试文件中的 `ComputeInlineSizeForFragment` 和 `ComputeBlockSizeForFragment` 函数模拟了浏览器如何根据元素的 `width`、`height`、`padding`、`border` 和 `box-sizing` 属性计算最终的尺寸。

    **举例:** `TEST_F(LengthUtilsTestWithNode, TestComputeInlineSizeForFragment)` 中，设置了各种带有不同 `width`、`padding` 和 `box-sizing` 属性的 HTML `div` 元素，并测试 `ComputeInlineSizeForFragment` 函数是否能正确计算它们的内联尺寸。例如，对于 `<div id="test10" style="width:100px; padding-left:50px; margin-right:20px;"></div>`，测试会验证其计算出的内联尺寸是否为 150px (100px + 50px)。

* **CSS 多列布局 (Multi-column Layout):** `TEST_F(LengthUtilsTest, TestColumnWidthAndCount)` 测试了与 CSS `column-width` 和 `column-count` 属性相关的计算。

    **举例:** `EXPECT_EQ(3, GetUsedColumnCount(0, 100, 0, 300));` 测试了当 `column-count` 为 `auto` (用 0 表示)，`column-width` 为 `100px`，容器宽度为 `300px` 时，是否能正确计算出列数为 3。

* **CSS 宽高比 (Aspect Ratio):** `TEST_F(LengthUtilsTest, AspectRatio)` 测试了与 CSS `aspect-ratio` 属性相关的计算。

    **举例:** `EXPECT_EQ(LayoutUnit(50), ComputeBlockSizeForFragment(node, ConstructConstraintSpace(200, 300), LayoutUnit(), LayoutUnit(100)));` 测试了当元素 `width` 为 `100px`，`aspect-ratio` 为 `2/1` 时，是否能正确计算出 `height` 为 `50px`。

**3. 逻辑推理的假设输入与输出:**

测试文件中的每个 `TEST_F` 函数都包含了一系列的测试用例，每个用例都隐含了假设的输入和预期的输出。

**示例 1 (来自 `TestResolveInlineLength`):**

* **假设输入:**
    * `length`: `Length::Percent(30)` (对应 CSS `width: 30%`)
    * `constraint_space`: 一个描述容器约束的空间，其中内联尺寸 (inline_size) 为 200。
* **逻辑推理:** 百分比长度是相对于容器的尺寸计算的，所以 30% 的 200 应该是 60。
* **预期输出:** `LayoutUnit(60)`

**示例 2 (来自 `TestComputeInlineSizeForFragment`):**

* **假设输入:**
    * 一个代表 `<div id="test10" style="width:100px; padding-left:50px; margin-right:20px;"></div>` 的 `BlockNode` 对象。
    * `constraint_space`:  一个描述容器约束的空间，内联尺寸为 200。
* **逻辑推理:**  元素的内联尺寸应该等于 `width` 加上 `padding-left`。 `margin-right` 不影响元素的自身尺寸。
* **预期输出:** `LayoutUnit(150)`

**示例 3 (来自 `TestColumnWidthAndCount`):**

* **假设输入:**
    * `computed_column_count`: 0 (表示 `auto`)
    * `computed_column_width`: 100
    * `used_column_gap`: 0
    * `available_inline_size`: 300
* **逻辑推理:**  在没有指定列数的情况下，会根据可用的空间和指定的列宽来计算列数。300 / 100 = 3。
* **预期输出:** `3` (通过 `GetUsedColumnCount` 函数返回)

**4. 涉及用户或编程常见的使用错误:**

测试文件通过测试各种场景，也间接地揭示了用户或编程中常见的关于 CSS 长度值使用的错误：

* **混淆百分比长度的参照对象:**  `TestResolveInlineLength` 和 `TestResolveBlockLength` 验证了百分比长度是相对于包含块的尺寸计算的。用户可能会错误地认为百分比是相对于元素自身或其他元素的尺寸。
* **不理解 `box-sizing` 属性:** `TestComputeInlineSizeForFragment` 和 `TestComputeBlockSizeForFragment` 中关于 `box-sizing: border-box;` 的测试用例，展示了当使用 `border-box` 时，元素的 `width` 和 `height` 包含了 `padding` 和 `border`。用户可能会错误地认为设置了 `width: 100px; padding: 10px;` 的元素宽度仍然是 100px，而忽略了 `padding` 的影响。
* **对 `auto` 值的误解:** 测试了 `auto` 在不同上下文中的行为，例如自动边距 (`TestAutoMargins`) 和自动列宽/列数 (`TestColumnWidthAndCount`)。用户可能会错误地认为 `auto` 总是意味着 0 或 100%。
* **错误地使用 `min-content`、`max-content` 和 `fit-content`:** `TestResolveInlineLength` 测试了这些关键字的行为。用户可能不清楚这些关键字是如何根据内容来确定元素尺寸的。
* **在无限约束下使用百分比:** `TEST_F(LengthUtilsTestWithNode, TestIndefinitePercentages)` 展示了在父元素尺寸未定义的情况下，百分比高度可能无法解析。用户可能会错误地认为百分比高度总是能生效。
* **在 `calc()` 中使用不兼容的单位或进行无效的计算:** 虽然这个测试文件没有直接测试 `calc()` 的所有可能性，但它使用了 `calc()` 作为一种长度值输入，暗示了正确使用 `calc()` 的重要性。用户可能会在 `calc()` 中混合不兼容的单位（例如，像素和百分比在某些情况下无法直接相加）或进行无效的数学运算。
* **忘记考虑边距的影响:**  虽然边距不影响元素的自身尺寸，但会影响元素在布局中的位置和与其他元素的关系。测试文件通过 `ComputePhysicalMargins` 验证了边距的计算。用户在布局时可能会忽略边距的影响，导致元素位置不符合预期。

总而言之，`length_utils_test.cc` 是一个重要的测试文件，用于确保 Blink 引擎能正确地解析和计算 CSS 长度值，这对于正确渲染网页至关重要。它涵盖了各种 CSS 长度单位、盒模型属性以及相关的布局概念，并通过大量的测试用例来验证其实现的正确性。

Prompt: 
```
这是目录为blink/renderer/core/layout/length_utils_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/length_utils.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/geometry/calculation_value.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

static ConstraintSpace ConstructConstraintSpace(
    int inline_size,
    int block_size,
    bool fixed_inline = false,
    bool fixed_block = false,
    WritingMode writing_mode = WritingMode::kHorizontalTb) {
  LogicalSize size = {LayoutUnit(inline_size), LayoutUnit(block_size)};

  ConstraintSpaceBuilder builder(writing_mode,
                                 {writing_mode, TextDirection::kLtr},
                                 /* is_new_fc */ false);
  builder.SetAvailableSize(size);
  builder.SetPercentageResolutionSize(size);
  builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
  builder.SetIsFixedInlineSize(fixed_inline);
  builder.SetIsFixedBlockSize(fixed_block);
  return builder.ToConstraintSpace();
}

class LengthUtilsTest : public testing::Test {
 protected:
  void SetUp() override {
    initial_style_ = ComputedStyle::GetInitialStyleSingleton();
  }

  LayoutUnit ResolveMainInlineLength(
      const Length& length,
      const std::optional<MinMaxSizes>& sizes = std::nullopt,
      ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300)) {
    return ::blink::ResolveMainInlineLength(
        constraint_space, *initial_style_, /* border_padding */ BoxStrut(),
        [&](SizeType) -> MinMaxSizesResult {
          return {*sizes, /* depends_on_block_constraints */ false};
        },
        length, /* auto_length */ nullptr);
  }

  LayoutUnit ResolveMinInlineLength(
      const Length& length,
      const std::optional<MinMaxSizes>& sizes = std::nullopt,
      ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300)) {
    return ::blink::ResolveMinInlineLength(
        constraint_space, *initial_style_, /* border_padding */ BoxStrut(),
        [&](SizeType) -> MinMaxSizesResult {
          return {*sizes, /* depends_on_block_constraints */ false};
        },
        length);
  }

  LayoutUnit ResolveMaxInlineLength(
      const Length& length,
      const std::optional<MinMaxSizes>& sizes = std::nullopt,
      ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300)) {
    return ::blink::ResolveMaxInlineLength(
        constraint_space, *initial_style_, /* border_padding */ BoxStrut(),
        [&](SizeType) -> MinMaxSizesResult {
          return {*sizes, /* depends_on_block_constraints */ false};
        },
        length);
  }

  LayoutUnit ResolveMainBlockLength(const Length& length,
                                    LayoutUnit content_size = LayoutUnit()) {
    ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300);
    return ::blink::ResolveMainBlockLength(constraint_space, *initial_style_,
                                           /* border_padding */ BoxStrut(),
                                           length, /* auto_length */ nullptr,
                                           content_size);
  }

  Persistent<const ComputedStyle> initial_style_;
  test::TaskEnvironment task_environment_;
};

class LengthUtilsTestWithNode : public RenderingTest {
 public:
  LayoutUnit ComputeInlineSizeForFragment(
      const BlockNode& node,
      ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300),
      const MinMaxSizes& sizes = MinMaxSizes()) {
    BoxStrut border_padding = ComputeBorders(constraint_space, node) +
                              ComputePadding(constraint_space, node.Style());
    return ::blink::ComputeInlineSizeForFragment(constraint_space, node,
                                                 border_padding, &sizes);
  }

  LayoutUnit ComputeBlockSizeForFragment(
      const BlockNode& node,
      ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300),
      LayoutUnit content_size = LayoutUnit(),
      LayoutUnit inline_size = kIndefiniteSize) {
    BoxStrut border_padding = ComputeBorders(constraint_space, node) +
                              ComputePadding(constraint_space, node.Style());
    return ::blink::ComputeBlockSizeForFragment(
        constraint_space, node, border_padding, content_size, inline_size);
  }
};

TEST_F(LengthUtilsTest, TestResolveInlineLength) {
  EXPECT_EQ(LayoutUnit(60), ResolveMainInlineLength(Length::Percent(30)));
  EXPECT_EQ(LayoutUnit(150), ResolveMainInlineLength(Length::Fixed(150)));
  EXPECT_EQ(LayoutUnit(200), ResolveMainInlineLength(Length::Stretch()));

  MinMaxSizes sizes;
  sizes.min_size = LayoutUnit(30);
  sizes.max_size = LayoutUnit(40);
  EXPECT_EQ(LayoutUnit(30),
            ResolveMainInlineLength(Length::MinContent(), sizes));
  EXPECT_EQ(LayoutUnit(40),
            ResolveMainInlineLength(Length::MaxContent(), sizes));
  EXPECT_EQ(LayoutUnit(40),
            ResolveMainInlineLength(Length::FitContent(), sizes));
  sizes.max_size = LayoutUnit(800);
  EXPECT_EQ(LayoutUnit(200),
            ResolveMainInlineLength(Length::FitContent(), sizes));

#if DCHECK_IS_ON()
  // This should fail a DCHECK.
  EXPECT_DEATH_IF_SUPPORTED(ResolveMainInlineLength(Length::FitContent()), "");
#endif
}

TEST_F(LengthUtilsTest, TestIndefiniteResolveInlineLength) {
  const ConstraintSpace space = ConstructConstraintSpace(-1, -1);

  EXPECT_EQ(LayoutUnit(0),
            ResolveMinInlineLength(Length::Auto(), std::nullopt, space));
  EXPECT_EQ(LayoutUnit::Max(),
            ResolveMaxInlineLength(Length::Percent(30), std::nullopt, space));
  EXPECT_EQ(LayoutUnit::Max(),
            ResolveMaxInlineLength(Length::Stretch(), std::nullopt, space));
}

TEST_F(LengthUtilsTest, TestResolveBlockLength) {
  EXPECT_EQ(LayoutUnit(90), ResolveMainBlockLength(Length::Percent(30)));
  EXPECT_EQ(LayoutUnit(150), ResolveMainBlockLength(Length::Fixed(150)));
  EXPECT_EQ(LayoutUnit(300), ResolveMainBlockLength(Length::Stretch()));
}

TEST_F(LengthUtilsTestWithNode, TestComputeContentContribution) {
  SetBodyInnerHTML(R"HTML(
    <div id="test1" style="width:30%;"></div>
    <div id="test2" style="width:-webkit-fill-available;"></div>
    <div id="test3" style="width:150px;"></div>
    <div id="test4" style="width:auto;"></div>
    <div id="test5" style="width:auto; padding-left:400px;"></div>
    <div id="test6" style="width:calc(100px + 10%);"></div>
    <div id="test7" style="max-width:35px;"></div>
    <div id="test8" style="min-width:80px; max-width: 35px"></div>
    <div id="test9" style="width:100px; padding-left:50px;"></div>
    <div id="test10" style="width:100px; padding-left:50px; box-sizing:border-box;"></div>
    <div id="test11" style="width:100px; padding-left:400px; box-sizing:border-box;"></div>
    <div id="test12" style="width:min-content; padding-left:400px; box-sizing:border-box;"></div>
    <div id="test13" style="width:100px; max-width:max-content; padding-left:400px; box-sizing:border-box;"></div>
    <div id="test14" style="width:100px; max-width:max-content; box-sizing:border-box;"></div>
  )HTML");

  MinMaxSizes sizes = {LayoutUnit(30), LayoutUnit(40)};
  const auto space =
      ConstraintSpaceBuilder(WritingMode::kHorizontalTb,
                             {WritingMode::kHorizontalTb, TextDirection::kLtr},
                             /* is_new_fc */ false)
          .ToConstraintSpace();

  MinMaxSizes expected = sizes;
  BlockNode node(To<LayoutBox>(GetLayoutObjectByElementId("test1")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test2")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));

  expected = MinMaxSizes{LayoutUnit(150), LayoutUnit(150)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test3")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));

  expected = sizes;
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test4")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));

  expected = MinMaxSizes{LayoutUnit(430), LayoutUnit(440)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test5")));
  auto sizes_padding400 = sizes;
  sizes_padding400 += LayoutUnit(400);
  EXPECT_EQ(expected,
            ComputeMinAndMaxContentContributionForTest(
                WritingMode::kHorizontalTb, node, space, sizes_padding400));

  expected = MinMaxSizes{LayoutUnit(30), LayoutUnit(40)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test6")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));

  expected = MinMaxSizes{LayoutUnit(30), LayoutUnit(35)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test7")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));

  expected = MinMaxSizes{LayoutUnit(80), LayoutUnit(80)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test8")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));

  expected = MinMaxSizes{LayoutUnit(150), LayoutUnit(150)};
  auto sizes_padding50 = sizes;
  sizes_padding50 += LayoutUnit(50);
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test9")));
  EXPECT_EQ(expected,
            ComputeMinAndMaxContentContributionForTest(
                WritingMode::kHorizontalTb, node, space, sizes_padding50));

  expected = MinMaxSizes{LayoutUnit(100), LayoutUnit(100)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test10")));
  EXPECT_EQ(expected,
            ComputeMinAndMaxContentContributionForTest(
                WritingMode::kHorizontalTb, node, space, sizes_padding50));

  // Content size should never be below zero, even with box-sizing: border-box
  // and a large padding...
  expected = MinMaxSizes{LayoutUnit(400), LayoutUnit(400)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test11")));
  EXPECT_EQ(expected,
            ComputeMinAndMaxContentContributionForTest(
                WritingMode::kHorizontalTb, node, space, sizes_padding400));

  expected.min_size = expected.max_size = sizes.min_size + LayoutUnit(400);
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test12")));
  EXPECT_EQ(expected,
            ComputeMinAndMaxContentContributionForTest(
                WritingMode::kHorizontalTb, node, space, sizes_padding400));

  // Due to padding and box-sizing, width computes to 400px and max-width to
  // 440px, so the result is 400.
  expected = MinMaxSizes{LayoutUnit(400), LayoutUnit(400)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test13")));
  EXPECT_EQ(expected,
            ComputeMinAndMaxContentContributionForTest(
                WritingMode::kHorizontalTb, node, space, sizes_padding400));

  expected = MinMaxSizes{LayoutUnit(40), LayoutUnit(40)};
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test14")));
  EXPECT_EQ(expected, ComputeMinAndMaxContentContributionForTest(
                          WritingMode::kHorizontalTb, node, space, sizes));
}

TEST_F(LengthUtilsTestWithNode, TestComputeInlineSizeForFragment) {
  SetBodyInnerHTML(R"HTML(
    <div id="test1" style="width:30%;"></div>
    <div id="test2" style="width:-webkit-fill-available;"></div>
    <div id="test3" style="width:150px;"></div>
    <div id="test4" style="width:auto;"></div>
    <div id="test5" style="width:calc(100px - 10%);"></div>
    <div id="test6" style="width:150px;"></div>
    <div id="test7" style="width:200px; max-width:80%;"></div>
    <div id="test8" style="min-width:80%; width:100px; max-width:80%;"></div>
    <div id="test9" style="margin-right:20px;"></div>
    <div id="test10" style="width:100px; padding-left:50px; margin-right:20px;"></div>
    <div id="test11" style="width:100px; padding-left:50px; margin-right:20px; box-sizing:border-box;"></div>
    <div id="test12" style="width:100px; padding-left:400px; margin-right:20px; box-sizing:border-box;"></div>
    <div id="test13" style="width:-webkit-fill-available; padding-left:400px; margin-right:20px; box-sizing:border-box;"></div>
    <div id="test14" style="width:min-content; padding-left:400px; margin-right:20px; box-sizing:border-box;"></div>
    <div id="test15" style="width:100px; max-width:max-content; padding-left:400px; margin-right:20px; box-sizing:border-box;"></div>
    <div id="test16" style="width:100px; max-width:max-content; margin-right:20px; box-sizing:border-box;"></div>
  )HTML");

  MinMaxSizes sizes = {LayoutUnit(30), LayoutUnit(40)};

  BlockNode node(To<LayoutBox>(GetLayoutObjectByElementId("test1")));
  EXPECT_EQ(LayoutUnit(60), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test2")));
  EXPECT_EQ(LayoutUnit(200), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test3")));
  EXPECT_EQ(LayoutUnit(150), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test4")));
  EXPECT_EQ(LayoutUnit(200), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test5")));
  EXPECT_EQ(LayoutUnit(80), ComputeInlineSizeForFragment(node));

  ConstraintSpace constraint_space =
      ConstructConstraintSpace(120, 120, true, true);
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test6")));
  EXPECT_EQ(LayoutUnit(120),
            ComputeInlineSizeForFragment(node, constraint_space));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test7")));
  EXPECT_EQ(LayoutUnit(160), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test8")));
  EXPECT_EQ(LayoutUnit(160), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test9")));
  EXPECT_EQ(LayoutUnit(180), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test10")));
  EXPECT_EQ(LayoutUnit(150), ComputeInlineSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test11")));
  EXPECT_EQ(LayoutUnit(100), ComputeInlineSizeForFragment(node));

  // Content size should never be below zero, even with box-sizing: border-box
  // and a large padding...
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test12")));
  EXPECT_EQ(LayoutUnit(400), ComputeInlineSizeForFragment(node));
  auto sizes_padding400 = sizes;
  sizes_padding400 += LayoutUnit(400);

  // ...and the same goes for fill-available with a large padding.
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test13")));
  EXPECT_EQ(LayoutUnit(400), ComputeInlineSizeForFragment(node));

  constraint_space = ConstructConstraintSpace(120, 140);
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test14")));
  EXPECT_EQ(LayoutUnit(430), ComputeInlineSizeForFragment(
                                 node, constraint_space, sizes_padding400));

  //  Due to padding and box-sizing, width computes to 400px and max-width to
  //  440px, so the result is 400.
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test15")));
  EXPECT_EQ(LayoutUnit(400), ComputeInlineSizeForFragment(
                                 node, constraint_space, sizes_padding400));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test16")));
  EXPECT_EQ(LayoutUnit(40),
            ComputeInlineSizeForFragment(node, constraint_space, sizes));
}

TEST_F(LengthUtilsTestWithNode, TestComputeBlockSizeForFragment) {
  SetBodyInnerHTML(R"HTML(
    <div id="test1" style="height:30%;"></div>
    <div id="test2" style="height:-webkit-fill-available;"></div>
    <div id="test3" style="height:150px;"></div>
    <div id="test4" style="height:auto;"></div>
    <div id="test5" style="height:calc(100px - 10%);"></div>
    <div id="test6" style="height:150px;"></div>
    <div id="test7" style="height:300px; max-height:80%;"></div>
    <div id="test8" style="min-height:80%; height:100px; max-height:80%;"></div>
    <div id="test9" style="height:-webkit-fill-available; margin-top:20px;"></div>
    <div id="test10" style="height:100px; padding-bottom:50px;"></div>
    <div id="test11" style="height:100px; padding-bottom:50px; box-sizing:border-box;"></div>
    <div id="test12" style="height:100px; padding-bottom:400px; box-sizing:border-box;"></div>
    <div id="test13" style="height:-webkit-fill-available; padding-bottom:400px; box-sizing:border-box;"></div>
    <div id="test14" style="width:100px; aspect-ratio:2/1;"></div>
    <div id="test15" style="width:100px; aspect-ratio:2/1; padding-right:10px; padding-bottom:20px;"></div>
    <div id="test16" style="width:100px; aspect-ratio:2/1; padding-right:10px; padding-bottom:20px; box-sizing:border-box;"></div>
  )HTML");

  BlockNode node(To<LayoutBox>(GetLayoutObjectByElementId("test1")));
  EXPECT_EQ(LayoutUnit(90), ComputeBlockSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test2")));
  EXPECT_EQ(LayoutUnit(300), ComputeBlockSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test3")));
  EXPECT_EQ(LayoutUnit(150), ComputeBlockSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test4")));
  EXPECT_EQ(LayoutUnit(0), ComputeBlockSizeForFragment(node));

  ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300);
  EXPECT_EQ(LayoutUnit(120), ComputeBlockSizeForFragment(node, constraint_space,
                                                         LayoutUnit(120)));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test5")));
  EXPECT_EQ(LayoutUnit(70), ComputeBlockSizeForFragment(node));

  constraint_space = ConstructConstraintSpace(200, 200, true, true);
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test6")));
  EXPECT_EQ(LayoutUnit(200),
            ComputeBlockSizeForFragment(node, constraint_space));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test7")));
  EXPECT_EQ(LayoutUnit(240), ComputeBlockSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test8")));
  EXPECT_EQ(LayoutUnit(240), ComputeBlockSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test9")));
  EXPECT_EQ(LayoutUnit(280), ComputeBlockSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test10")));
  EXPECT_EQ(LayoutUnit(150), ComputeBlockSizeForFragment(node));

  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test11")));
  EXPECT_EQ(LayoutUnit(100), ComputeBlockSizeForFragment(node));

  // Content size should never be below zero, even with box-sizing: border-box
  // and a large padding...
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test12")));
  EXPECT_EQ(LayoutUnit(400), ComputeBlockSizeForFragment(node));

  // ...and the same goes for fill-available with a large padding.
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test13")));
  EXPECT_EQ(LayoutUnit(400), ComputeBlockSizeForFragment(node));

  // Now check aspect-ratio.
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test14")));
  EXPECT_EQ(LayoutUnit(50), ComputeBlockSizeForFragment(
                                node, ConstructConstraintSpace(200, 300),
                                LayoutUnit(), LayoutUnit(100)));

  // Default box-sizing
  // Should be (100 - 10) / 2 + 20 = 65.
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test15")));
  EXPECT_EQ(LayoutUnit(65), ComputeBlockSizeForFragment(
                                node, ConstructConstraintSpace(200, 300),
                                LayoutUnit(20), LayoutUnit(100)));

  // With box-sizing: border-box, should be 50.
  node = BlockNode(To<LayoutBox>(GetLayoutObjectByElementId("test16")));
  EXPECT_EQ(LayoutUnit(50), ComputeBlockSizeForFragment(
                                node, ConstructConstraintSpace(200, 300),
                                LayoutUnit(20), LayoutUnit(100)));
}

TEST_F(LengthUtilsTestWithNode, TestIndefinitePercentages) {
  SetBodyInnerHTML(R"HTML(
    <div id="test" style="min-height:20px; height:20%;"></div>
  )HTML");

  BlockNode node(To<LayoutBox>(GetLayoutObjectByElementId("test")));
  EXPECT_EQ(kIndefiniteSize,
            ComputeBlockSizeForFragment(node, ConstructConstraintSpace(200, -1),
                                        LayoutUnit(-1)));
  EXPECT_EQ(LayoutUnit(20),
            ComputeBlockSizeForFragment(node, ConstructConstraintSpace(200, -1),
                                        LayoutUnit(10)));
  EXPECT_EQ(LayoutUnit(120),
            ComputeBlockSizeForFragment(node, ConstructConstraintSpace(200, -1),
                                        LayoutUnit(120)));
}

TEST_F(LengthUtilsTestWithNode, ComputeReplacedSizeSvgNoScaling) {
  SetBodyInnerHTML(R"HTML(
<style>
svg {
  width: 100%;
  margin-left: 9223372036854775807in;
}
span {
  display: inline-flex;
}
</style>
<span><svg></svg></span>)HTML");
  // Pass if no DCHECK failures in BlockNode::FinishLayout().
}

TEST_F(LengthUtilsTest, TestMargins) {
  ComputedStyleBuilder builder(*initial_style_);
  builder.SetMarginTop(Length::Percent(10));
  builder.SetMarginRight(Length::Fixed(52));
  builder.SetMarginBottom(Length::Auto());
  builder.SetMarginLeft(Length::Percent(11));
  const ComputedStyle* style = builder.TakeStyle();

  ConstraintSpace constraint_space = ConstructConstraintSpace(200, 300);

  PhysicalBoxStrut margins = ComputePhysicalMargins(constraint_space, *style);

  EXPECT_EQ(LayoutUnit(20), margins.top);
  EXPECT_EQ(LayoutUnit(52), margins.right);
  EXPECT_EQ(LayoutUnit(), margins.bottom);
  EXPECT_EQ(LayoutUnit(22), margins.left);
}

TEST_F(LengthUtilsTest, TestBorders) {
  ComputedStyleBuilder builder(*initial_style_);
  builder.SetBorderTopWidth(1);
  builder.SetBorderRightWidth(2);
  builder.SetBorderBottomWidth(3);
  builder.SetBorderLeftWidth(4);
  builder.SetBorderTopStyle(EBorderStyle::kSolid);
  builder.SetBorderRightStyle(EBorderStyle::kSolid);
  builder.SetBorderBottomStyle(EBorderStyle::kSolid);
  builder.SetBorderLeftStyle(EBorderStyle::kSolid);
  builder.SetWritingMode(WritingMode::kVerticalLr);
  const ComputedStyle* style = builder.TakeStyle();

  BoxStrut borders = ComputeBordersForTest(*style);

  EXPECT_EQ(LayoutUnit(4), borders.block_start);
  EXPECT_EQ(LayoutUnit(3), borders.inline_end);
  EXPECT_EQ(LayoutUnit(2), borders.block_end);
  EXPECT_EQ(LayoutUnit(1), borders.inline_start);
}

TEST_F(LengthUtilsTest, TestPadding) {
  ComputedStyleBuilder builder(*initial_style_);
  builder.SetPaddingTop(Length::Percent(10));
  builder.SetPaddingRight(Length::Fixed(52));
  builder.SetPaddingBottom(Length::Auto());
  builder.SetPaddingLeft(Length::Percent(11));
  builder.SetWritingMode(WritingMode::kVerticalRl);
  const ComputedStyle* style = builder.TakeStyle();

  ConstraintSpace constraint_space = ConstructConstraintSpace(
      200, 300, false, false, WritingMode::kVerticalRl);

  BoxStrut padding = ComputePadding(constraint_space, *style);

  EXPECT_EQ(LayoutUnit(52), padding.block_start);
  EXPECT_EQ(LayoutUnit(), padding.inline_end);
  EXPECT_EQ(LayoutUnit(22), padding.block_end);
  EXPECT_EQ(LayoutUnit(20), padding.inline_start);
}

TEST_F(LengthUtilsTest, TestAutoMargins) {
  ComputedStyleBuilder builder(*initial_style_);
  builder.SetMarginRight(Length::Auto());
  builder.SetMarginLeft(Length::Auto());
  const ComputedStyle* style = builder.TakeStyle();

  LayoutUnit kInlineSize(150);
  LayoutUnit kAvailableInlineSize(200);

  BoxStrut margins;
  ResolveInlineAutoMargins(*style, *style, kAvailableInlineSize, kInlineSize,
                           &margins);

  EXPECT_EQ(LayoutUnit(), margins.block_start);
  EXPECT_EQ(LayoutUnit(), margins.block_end);
  EXPECT_EQ(LayoutUnit(25), margins.inline_start);
  EXPECT_EQ(LayoutUnit(25), margins.inline_end);

  builder = ComputedStyleBuilder(*style);
  builder.SetMarginLeft(Length::Fixed(0));
  style = builder.TakeStyle();
  margins = BoxStrut();
  ResolveInlineAutoMargins(*style, *style, kAvailableInlineSize, kInlineSize,
                           &margins);
  EXPECT_EQ(LayoutUnit(0), margins.inline_start);
  EXPECT_EQ(LayoutUnit(50), margins.inline_end);

  builder = ComputedStyleBuilder(*style);
  builder.SetMarginLeft(Length::Auto());
  builder.SetMarginRight(Length::Fixed(0));
  style = builder.TakeStyle();
  margins = BoxStrut();
  ResolveInlineAutoMargins(*style, *style, kAvailableInlineSize, kInlineSize,
                           &margins);
  EXPECT_EQ(LayoutUnit(50), margins.inline_start);
  EXPECT_EQ(LayoutUnit(0), margins.inline_end);

  // Test that we don't end up with negative "auto" margins when the box is too
  // big.
  builder = ComputedStyleBuilder(*style);
  builder.SetMarginLeft(Length::Auto());
  builder.SetMarginRight(Length::Fixed(5000));
  style = builder.TakeStyle();
  margins = BoxStrut();
  margins.inline_end = LayoutUnit(5000);
  ResolveInlineAutoMargins(*style, *style, kAvailableInlineSize, kInlineSize,
                           &margins);
  EXPECT_EQ(LayoutUnit(0), margins.inline_start);
  EXPECT_EQ(LayoutUnit(5000), margins.inline_end);
}

// Simple wrappers that don't use LayoutUnit(). Their only purpose is to make
// the tests below humanly readable (to make the expectation expressions fit on
// one line each). Passing 0 for column width or column count means "auto".
int GetUsedColumnWidth(int computed_column_count,
                       int computed_column_width,
                       int used_column_gap,
                       int available_inline_size) {
  LayoutUnit column_width(computed_column_width);
  if (!computed_column_width)
    column_width = LayoutUnit(kIndefiniteSize);
  return ResolveUsedColumnInlineSize(computed_column_count, column_width,
                                     LayoutUnit(used_column_gap),
                                     LayoutUnit(available_inline_size))
      .ToInt();
}
int GetUsedColumnCount(int computed_column_count,
                       int computed_column_width,
                       int used_column_gap,
                       int available_inline_size) {
  LayoutUnit column_width(computed_column_width);
  if (!computed_column_width)
    column_width = LayoutUnit(kIndefiniteSize);
  return ResolveUsedColumnCount(computed_column_count, column_width,
                                LayoutUnit(used_column_gap),
                                LayoutUnit(available_inline_size));
}

TEST_F(LengthUtilsTest, TestColumnWidthAndCount) {
  EXPECT_EQ(100, GetUsedColumnWidth(0, 100, 0, 300));
  EXPECT_EQ(3, GetUsedColumnCount(0, 100, 0, 300));
  EXPECT_EQ(150, GetUsedColumnWidth(0, 101, 0, 300));
  EXPECT_EQ(2, GetUsedColumnCount(0, 101, 0, 300));
  EXPECT_EQ(300, GetUsedColumnWidth(0, 151, 0, 300));
  EXPECT_EQ(1, GetUsedColumnCount(0, 151, 0, 300));
  EXPECT_EQ(300, GetUsedColumnWidth(0, 1000, 0, 300));
  EXPECT_EQ(1, GetUsedColumnCount(0, 1000, 0, 300));

  EXPECT_EQ(100, GetUsedColumnWidth(0, 100, 10, 320));
  EXPECT_EQ(3, GetUsedColumnCount(0, 100, 10, 320));
  EXPECT_EQ(150, GetUsedColumnWidth(0, 101, 10, 310));
  EXPECT_EQ(2, GetUsedColumnCount(0, 101, 10, 310));
  EXPECT_EQ(300, GetUsedColumnWidth(0, 151, 10, 300));
  EXPECT_EQ(1, GetUsedColumnCount(0, 151, 10, 300));
  EXPECT_EQ(300, GetUsedColumnWidth(0, 1000, 10, 300));
  EXPECT_EQ(1, GetUsedColumnCount(0, 1000, 10, 300));

  EXPECT_EQ(125, GetUsedColumnWidth(4, 0, 0, 500));
  EXPECT_EQ(4, GetUsedColumnCount(4, 0, 0, 500));
  EXPECT_EQ(125, GetUsedColumnWidth(4, 100, 0, 500));
  EXPECT_EQ(4, GetUsedColumnCount(4, 100, 0, 500));
  EXPECT_EQ(100, GetUsedColumnWidth(6, 100, 0, 500));
  EXPECT_EQ(5, GetUsedColumnCount(6, 100, 0, 500));
  EXPECT_EQ(100, GetUsedColumnWidth(0, 100, 0, 500));
  EXPECT_EQ(5, GetUsedColumnCount(0, 100, 0, 500));

  EXPECT_EQ(125, GetUsedColumnWidth(4, 0, 10, 530));
  EXPECT_EQ(4, GetUsedColumnCount(4, 0, 10, 530));
  EXPECT_EQ(125, GetUsedColumnWidth(4, 100, 10, 530));
  EXPECT_EQ(4, GetUsedColumnCount(4, 100, 10, 530));
  EXPECT_EQ(100, GetUsedColumnWidth(6, 100, 10, 540));
  EXPECT_EQ(5, GetUsedColumnCount(6, 100, 10, 540));
  EXPECT_EQ(100, GetUsedColumnWidth(0, 100, 10, 540));
  EXPECT_EQ(5, GetUsedColumnCount(0, 100, 10, 540));

  EXPECT_EQ(0, GetUsedColumnWidth(3, 0, 10, 10));
  EXPECT_EQ(3, GetUsedColumnCount(3, 0, 10, 10));
}

LayoutUnit ComputeInlineSize(LogicalSize aspect_ratio, LayoutUnit block_size) {
  return InlineSizeFromAspectRatio(BoxStrut(), aspect_ratio,
                                   EBoxSizing::kBorderBox, block_size);
}
TEST_F(LengthUtilsTest, AspectRatio) {
  EXPECT_EQ(LayoutUnit(8000),
            ComputeInlineSize(LogicalSize(8000, 8000), LayoutUnit(8000)));
  EXPECT_EQ(LayoutUnit(1),
            ComputeInlineSize(LogicalSize(1, 10000), LayoutUnit(10000)));
  EXPECT_EQ(LayoutUnit(4),
            ComputeInlineSize(LogicalSize(1, 1000000), LayoutUnit(4000000)));
  EXPECT_EQ(LayoutUnit(0),
            ComputeInlineSize(LogicalSize(3, 5000000), LayoutUnit(5)));
  // The literals are 8 million, 20 million, 10 million, 4 million.
  EXPECT_EQ(
      LayoutUnit(8000000),
      ComputeInlineSize(LogicalSize(20000000, 10000000), LayoutUnit(4000000)));
  // If you specify an aspect ratio of 10000:1 with a large block size,
  // LayoutUnit saturates.
  EXPECT_EQ(LayoutUnit::Max(),
            ComputeInlineSize(LogicalSize(10000, 1), LayoutUnit(10000)));
}

}  // namespace
}  // namespace blink

"""

```