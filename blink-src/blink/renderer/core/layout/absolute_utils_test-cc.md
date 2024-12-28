Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding - What is this?**

The first step is recognizing that this is a C++ test file (`.cc`) within the Chromium/Blink project. The file path `blink/renderer/core/layout/absolute_utils_test.cc` is highly informative. It tells us:

* **`blink`**:  Part of the Blink rendering engine.
* **`renderer`**: Deals with rendering the web page.
* **`core`**:  Core functionality of the rendering engine.
* **`layout`**: Specifically related to the layout process (how elements are positioned and sized).
* **`absolute_utils_test.cc`**:  This is a test file (`_test.cc`) for utilities related to absolutely positioned elements.

**2. Core Functionality - What does it test?**

The `#include` statements give clues:

* `#include "third_party/blink/renderer/core/layout/absolute_utils.h"`: This is the header file for the code being tested. It suggests the file tests functions within `absolute_utils.h`.
* Other includes (`block_node.h`, `constraint_space_builder.h`, etc.) indicate the types of objects the tested functions interact with. These are fundamental layout concepts.

The class name `AbsoluteUtilsTest` reinforces the idea that it's testing utilities for absolute positioning.

**3. Identifying Test Cases (Functions starting with `TEST_F`)**

Scanning for `TEST_F(AbsoluteUtilsTest, ...)` reveals the individual test cases:

* `Horizontal`:  Likely tests horizontal positioning of absolutely positioned elements.
* `Vertical`:  Likely tests vertical positioning.
* `CenterStaticPosition`:  Tests handling of `static-position: center`.
* `MinMax`: Tests how `min-width`, `max-width`, `min-height`, and `max-height` are handled.

**4. Analyzing Individual Test Cases - How are they structured?**

Let's take `Horizontal` as an example:

* **Setup:**  The `SetUp()` method configures the HTML with an absolutely positioned element (`#target`). It also sets up default styles.
* **Helper Functions:**  `SetHorizontalStyle()` simplifies setting CSS properties related to horizontal positioning. This makes the tests more readable.
* **Core Logic:** Inside the `Horizontal` test, there are multiple calls to `ComputeOutOfFlowInlineDimensions()`. This is a key function being tested. The arguments to this function provide valuable information:
    * `BlockNode node(element_->GetLayoutBox())`:  Represents the absolutely positioned element.
    * `ltr_space_`, `rtl_space_`: Represent the containing block's constraint space (available width/height, writing direction).
    * `ltr_border_padding`, `rtl_border_padding`:  Pre-calculated border and padding.
    * `static_position`:  Represents the initial, non-positioned location of the element.
    * `{WritingMode::kHorizontalTb, TextDirection::kLtr}`:  The writing direction of the *containing block*.
    * `&dimensions`:  A struct to hold the computed layout information (size and position).
* **Assertions:** `EXPECT_EQ()` is used to verify the computed dimensions against expected values. The comments often explain the expected calculation based on the CSS properties.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS)**

* **HTML:** The `SetBodyInnerHTML()` method directly manipulates the HTML structure. The tests are based on an absolutely positioned `<div>`.
* **CSS:** The `SetHorizontalStyle()` and `SetVerticalStyle()` functions set CSS properties like `left`, `right`, `width`, `top`, `bottom`, `height`, `margin-*`, `writing-mode`, and `box-sizing`. These are core CSS properties affecting layout.
* **JavaScript (Indirect):** While there's no explicit JavaScript in the test, the code being tested *powers* the layout engine, which is what makes JavaScript manipulation of styles effective. Changes to styles via JavaScript would eventually trigger the kind of layout calculations being tested here.

**6. Identifying Logic and Assumptions**

The comments within the test cases often reveal the underlying logic. For example, in the `Horizontal` test, the comments show the formulas used to calculate expected margin values based on available space and other properties.

Assumptions are implicit in the test setup. For instance, the test assumes a specific initial state of the document and the layout tree.

**7. Identifying Potential User/Programming Errors**

By testing various combinations of CSS properties (e.g., setting `left` and `right` simultaneously, or using `auto` values), the tests implicitly cover scenarios where developers might make mistakes in their CSS. For example, setting conflicting values for `left` and `right` will have a defined behavior that these tests verify.

**8. Structuring the Answer**

Finally, the information needs to be organized into a clear and understandable answer. This involves:

* **Summarizing the main purpose.**
* **Listing key functionalities.**
* **Providing concrete examples of relationships to HTML, CSS, and JavaScript.**
* **Illustrating logical reasoning with assumptions and input/output examples.**
* **Giving examples of common errors the tests help prevent.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just tests some layout stuff."
* **Refinement:** "No, it specifically tests *absolute positioning* and how different CSS properties interact in that context."
* **Initial thought:** "The tests just set some styles and check the output."
* **Refinement:** "They are testing the *edge cases* and the *rules* the browser follows when calculating the position and size of absolutely positioned elements under various constraints (like available space, writing direction, and `auto` values)."

By following this systematic approach, we can effectively analyze and explain the functionality of a complex source code file like the one provided.
这个C++文件 `absolute_utils_test.cc` 是 Chromium Blink 渲染引擎的一部分，它的主要**功能是测试 `absolute_utils.h` 中定义的用于处理绝对定位元素的实用函数 (utility functions)**。  这些实用函数负责计算绝对定位元素在不同情况下的尺寸和位置。

更具体地说，这个测试文件通过创建各种场景，设置不同的 CSS 属性，然后调用 `absolute_utils.h` 中的函数来计算绝对定位元素的布局属性，并验证计算结果是否符合预期。

**它与 JavaScript, HTML, CSS 的功能有密切关系，因为绝对定位是 Web 开发中常用的 CSS 定位机制。**

**关系举例说明：**

1. **HTML:**  测试用例中通过 `SetBodyInnerHTML()` 方法动态创建包含一个绝对定位元素的 HTML 结构。例如：
   ```html
   <div id=target>
     <!-- ... -->
   </div>
   ```
   这个 HTML 结构定义了被测试的绝对定位元素。

2. **CSS:** 测试用例通过 `SetHorizontalStyle()` 和 `SetVerticalStyle()` 方法来设置被测试元素的 CSS 属性，这些属性直接影响绝对定位元素的布局。常见的 CSS 属性包括：
   * `position: absolute;` (在 setup 中预设)
   * `left`, `right`, `top`, `bottom`: 定义元素相对于其包含块边缘的偏移。
   * `width`, `height`: 定义元素的尺寸。
   * `margin-left`, `margin-right`, `margin-top`, `margin-bottom`: 定义元素的外边距。
   * `writing-mode`: 定义文本的书写方向，影响水平和垂直方向的解释。
   * `box-sizing`: 定义元素的尺寸计算方式（`content-box` 或 `border-box`）。
   * `min-width`, `max-width`, `min-height`, `max-height`: 定义元素的最小和最大尺寸。
   * `contain: size`:  影响尺寸约束。
   * `contain-intrinsic-size`:  指定元素的固有尺寸。

   例如，一个测试用例可能会设置如下 CSS 属性：
   ```css
   #target {
     position: absolute;
     left: 5px;
     top: auto;
     width: 160px;
     height: auto;
     right: 13px;
   }
   ```
   测试文件会模拟这种 CSS 配置，并验证 `absolute_utils.h` 中的函数是否能正确计算出元素的最终位置和尺寸。

3. **JavaScript:**  虽然这个测试文件本身是 C++ 代码，并不直接包含 JavaScript，但它测试的 `absolute_utils.h` 中的代码是 Web 浏览器渲染引擎的一部分，负责解析和应用 CSS 样式。当 JavaScript 代码通过 DOM API 修改元素的样式（例如 `element.style.left = '10px'`) 时，最终会触发渲染引擎重新计算布局，而 `absolute_utils.h` 中的函数就会参与到这个计算过程中。因此，这个测试文件间接地与 JavaScript 的功能相关。

**逻辑推理与假设输入输出举例：**

考虑 `TEST_F(AbsoluteUtilsTest, Horizontal)` 中的一个测试用例：

```c++
  // Rule 4: left is auto.
  SetHorizontalStyle("auto", "7px", "160px", "15px", "13px");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 5 + 7 + 160 + 15 + 13
  EXPECT_EQ(5 + 7, dimensions.inset.inline_start);
```

**假设输入:**

* 绝对定位元素的 CSS 属性：`left: auto; margin-left: 7px; width: 160px; margin-right: 15px; right: 13px;`
* 包含块的可用宽度 (`ltr_space_.AvailableSize().width`): 200px
* 元素的边框和内边距 (`ltr_border_padding`): 根据 setup 中的定义计算得到，水平方向上为 9px (左边框) + 17px (右边框) + 11px (左内边距) + 19px (右内边距) = 56px。
* `static_position`: 默认的静态位置。

**逻辑推理:**

根据 CSS 规范中关于绝对定位元素的水平方向布局计算规则，当 `left` 为 `auto` 时，其值会被计算为使元素满足以下等式：

`margin-left` + `border-left-width` + `padding-left` + `width` + `padding-right` + `border-right-width` + `margin-right` + `left` = 包含块的可用宽度 - `right`

将已知值代入：

`7px` + `9px` + `11px` + `160px` + `19px` + `17px` + `15px` + `left` = `200px` - `13px`

`238px` + `left` = `187px`

`left` = `187px` - `238px` = `-51px`  *(这里推导有误，应使用未加边框内边距的宽度)*

让我们重新考虑，在计算 `ComputeOutOfFlowInlineDimensions` 时，边框和内边距已经被考虑进去了。  根据 CSS 规范，当 `left` 为 `auto` 时，公式为：

`left` = `available-width` - `right` - `margin-left` - `border-left-width` - `padding-left` - `width` - `padding-right` - `border-right-width` - `margin-right`

或者更简洁地，考虑到 `border_padding` 已经包含边框和内边距：

`left` = `available-width` - `right` - `margin-left` - `content-width` - `margin-right`

但是，当 `left` 为 `auto` 时，实际的计算逻辑是：

`left` = `static_position.inline_offset` + `margin-left`

由于 `static_position` 默认为 `0`，所以 `left` 的有效值是 `margin-left`。

让我们回到测试代码中的注释 `// 200 = 5 + 7 + 160 + 15 + 13`。这里的 `5` 代表计算出的 `left` 值。这意味着：

`200` (可用宽度) = `left` + `margin-left` + `border-left` + `padding-left` + `width` + `padding-right` + `border-right` + `margin-right` + `right`

`200` = `left` + `7` + `9` + `11` + `160` + `19` + `17` + `15` + `13`

`200` = `left` + `251`

`left` = `-51`  *(这里依然存在理解上的偏差)*

正确的理解是，当 `left` 为 `auto` 时，会根据其他属性计算出来。测试代码验证的是在特定情况下 `left` 的计算结果是否等于 `5px`。  让我们看 `dimensions.inset.inline_start`，它对应于计算出的 `left` 值（考虑了书写方向）。

在 LTR 模式下，`inline_start` 对应于 `left`。 测试期望 `dimensions.inset.inline_start` 等于 `5 + 7 = 12`。  这意味着，当 `left` 为 `auto` 时，计算出的有效 `left` 值是 `5px`。 这是因为 CSS 布局引擎会根据其他约束来确定 `auto` 值的具体含义。

**预期输出:**

根据测试用例，预期的 `dimensions.inset.inline_start` 的值是 `5 + 7 = 12`。 这意味着当 `left` 为 `auto` 时，在给定的其他 CSS 属性和包含块约束下，计算出的有效 `left` 值是 `5px`。

**用户或编程常见的使用错误举例：**

1. **同时设置 `left` 和 `right` 且两者都不是 `auto`：**  用户可能会错误地同时指定 `left` 和 `right` 的具体数值，期望元素能同时满足这两个约束。然而，CSS 规范定义了在这种情况下如何解析，通常会忽略其中一个值（在 LTR 模式下，`left` 优先）。测试用例覆盖了这种情况，确保 Blink 引擎按照规范处理。

   ```c++
   SetHorizontalStyle("10px", "auto", "auto", "auto", "20px");
   ComputeOutOfFlowInlineDimensions( /* ... */ );
   // 测试会验证在这种情况下 width 的计算方式。
   ```

2. **忘记设置 `position: absolute`：** 如果用户忘记设置 `position: absolute;`，`left`, `right`, `top`, `bottom` 等属性将不会按照绝对定位的方式工作，而是按照静态或相对定位的方式工作。虽然这个测试文件主要关注绝对定位，但理解不同定位方式之间的区别是避免此类错误的关键。

3. **对 `auto` 值的理解偏差：**  `auto` 值的含义在不同的 CSS 属性中有所不同。例如，对于绝对定位元素的水平属性，如果 `width` 为 `auto`，则其宽度由内容决定。如果 `left` 为 `auto`，其值会根据其他属性计算得出。用户可能对 `auto` 的工作方式存在误解，导致布局不如预期。测试用例通过各种 `auto` 值的组合来验证 Blink 引擎的实现是否符合规范。

4. **忽略边距和边框的影响：**  在计算绝对定位元素的最终位置和尺寸时，需要考虑边距、边框和内边距。用户可能在手动计算时忽略这些因素，导致布局错误。测试用例通过设置不同的边框和内边距来验证计算的正确性。

总而言之，`absolute_utils_test.cc` 是一个重要的测试文件，它确保了 Blink 渲染引擎能够正确处理绝对定位元素的布局计算，这对于实现符合 Web 标准的浏览器至关重要。它涵盖了各种 CSS 属性组合和场景，有助于发现和防止潜在的布局错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/absolute_utils_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/absolute_utils.h"

#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/geometry/static_position.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {
namespace {

class AbsoluteUtilsTest : public RenderingTest {
 public:
  AbsoluteUtilsTest()
      : ltr_space_(CreateConstraintSpace(
            {WritingMode::kHorizontalTb, TextDirection::kLtr})),
        rtl_space_(CreateConstraintSpace(
            {WritingMode::kHorizontalTb, TextDirection::kRtl})),
        vlr_space_(CreateConstraintSpace(
            {WritingMode::kVerticalLr, TextDirection::kLtr})),
        vrl_space_(CreateConstraintSpace(
            {WritingMode::kVerticalRl, TextDirection::kLtr})) {}

 protected:
  ConstraintSpace CreateConstraintSpace(
      WritingDirectionMode writing_direction) {
    ConstraintSpaceBuilder builder(WritingMode::kHorizontalTb,
                                   writing_direction,
                                   /* is_new_fc */ true);
    builder.SetAvailableSize({LayoutUnit(200), LayoutUnit(300)});
    return builder.ToConstraintSpace();
  }

  void SetUp() override {
    RenderingTest::SetUp();
    SetBodyInnerHTML(R"HTML(
      <style>
        #target {
          position: absolute;
          border: solid;
          border-width: 9px 17px 17px 9px;
          padding: 11px 19px 19px 11px;
        }
      </style>
      <div id=target>
        <!-- Use a compressible element to simulate min/max sizes of {0, N} -->
        <textarea style="width: 100%; height: 88px;">
          xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        </div>
      </div>
    )HTML");
    RunDocumentLifecycle();

    element_ = GetElementById("target");
  }

  void SetHorizontalStyle(const String& left,
                          const String& margin_left,
                          const String& width,
                          const String& margin_right,
                          const String& right,
                          const String& writing_mode = "horizontal-tb",
                          const String& box_sizing = "border-box") {
    element_->SetInlineStyleProperty(CSSPropertyID::kLeft, left);
    element_->SetInlineStyleProperty(CSSPropertyID::kMarginLeft, margin_left);
    element_->SetInlineStyleProperty(CSSPropertyID::kWidth, width);
    element_->SetInlineStyleProperty(CSSPropertyID::kMarginRight, margin_right);
    element_->SetInlineStyleProperty(CSSPropertyID::kRight, right);
    element_->SetInlineStyleProperty(CSSPropertyID::kWritingMode, writing_mode);
    element_->SetInlineStyleProperty(CSSPropertyID::kBoxSizing, box_sizing);
    RunDocumentLifecycle();
  }

  void SetVerticalStyle(const String& top,
                        const String& margin_top,
                        const String& height,
                        const String& margin_bottom,
                        const String& bottom,
                        const String& writing_mode = "horizontal-tb",
                        const String& box_sizing = "border-box") {
    element_->SetInlineStyleProperty(CSSPropertyID::kTop, top);
    element_->SetInlineStyleProperty(CSSPropertyID::kMarginTop, margin_top);
    element_->SetInlineStyleProperty(CSSPropertyID::kHeight, height);
    element_->SetInlineStyleProperty(CSSPropertyID::kMarginBottom,
                                     margin_bottom);
    element_->SetInlineStyleProperty(CSSPropertyID::kBottom, bottom);
    element_->SetInlineStyleProperty(CSSPropertyID::kWritingMode, writing_mode);
    element_->SetInlineStyleProperty(CSSPropertyID::kBoxSizing, box_sizing);
    RunDocumentLifecycle();
  }

  void ComputeOutOfFlowInlineDimensions(
      const BlockNode& node,
      const ConstraintSpace& space,
      const BoxStrut& border_padding,
      const LogicalStaticPosition& static_position,
      const WritingDirectionMode container_writing_direction,
      LogicalOofDimensions* dimensions) {
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kStyleClean);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInPerformLayout);
    WritingModeConverter container_converter(
        container_writing_direction,
        ToPhysicalSize(space.AvailableSize(),
                       container_writing_direction.GetWritingMode()));
    LogicalAnchorQuery* anchor_query =
        MakeGarbageCollected<LogicalAnchorQuery>();
    AnchorEvaluatorImpl anchor_evaluator(
        *node.GetLayoutBox(), *anchor_query,
        /* implicit_anchor */ nullptr, container_converter,
        /* self_writing_direction */
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        /* offset_to_padding_box */
        PhysicalOffset(),
        /* available_size */
        PhysicalSize());
    WritingDirectionMode self_writing_direction =
        node.Style().GetWritingDirection();
    const LogicalOofInsets insets =
        ComputeOutOfFlowInsets(node.Style(), space.AvailableSize(),
                               LogicalAlignment(), self_writing_direction);
    const InsetModifiedContainingBlock imcb =
        ComputeInsetModifiedContainingBlock(
            node, space.AvailableSize(), LogicalAlignment(), insets,
            static_position, container_writing_direction,
            node.Style().GetWritingDirection());
    ComputeOofInlineDimensions(
        node, node.Style(), space, imcb, LogicalAnchorCenterPosition(),
        LogicalAlignment(), border_padding, std::nullopt, BoxStrut(),
        container_writing_direction, dimensions);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kAfterPerformLayout);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kLayoutClean);
  }

  void ComputeOutOfFlowBlockDimensions(
      const BlockNode& node,
      const ConstraintSpace& space,
      const BoxStrut& border_padding,
      const LogicalStaticPosition& static_position,
      const WritingDirectionMode container_writing_direction,
      LogicalOofDimensions* dimensions) {
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kStyleClean);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInPerformLayout);
    WritingModeConverter container_converter(
        container_writing_direction,
        ToPhysicalSize(space.AvailableSize(),
                       container_writing_direction.GetWritingMode()));
    LogicalAnchorQuery* anchor_query =
        MakeGarbageCollected<LogicalAnchorQuery>();
    AnchorEvaluatorImpl anchor_evaluator(
        *node.GetLayoutBox(), *anchor_query,
        /* implicit_anchor */ nullptr, container_converter,
        /* self_writing_direction */
        {WritingMode::kHorizontalTb, TextDirection::kLtr},
        /* offset_to_padding_box */
        PhysicalOffset(),
        /* available_size */
        PhysicalSize());
    WritingDirectionMode self_writing_direction =
        node.Style().GetWritingDirection();
    const LogicalOofInsets insets =
        ComputeOutOfFlowInsets(node.Style(), space.AvailableSize(),
                               LogicalAlignment(), self_writing_direction);
    const InsetModifiedContainingBlock imcb =
        ComputeInsetModifiedContainingBlock(
            node, space.AvailableSize(), LogicalAlignment(), insets,
            static_position, container_writing_direction,
            node.Style().GetWritingDirection());
    ComputeOofBlockDimensions(node, node.Style(), space, imcb,
                              LogicalAnchorCenterPosition(), LogicalAlignment(),
                              border_padding, std::nullopt, BoxStrut(),
                              container_writing_direction, dimensions);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kAfterPerformLayout);
    GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kLayoutClean);
  }

  Persistent<Element> element_;
  ConstraintSpace ltr_space_;
  ConstraintSpace rtl_space_;
  ConstraintSpace vlr_space_;
  ConstraintSpace vrl_space_;
};

TEST_F(AbsoluteUtilsTest, Horizontal) {
  BlockNode node(element_->GetLayoutBox());
  element_->SetInlineStyleProperty(CSSPropertyID::kContain, "size");
  element_->SetInlineStyleProperty(CSSPropertyID::kContainIntrinsicSize,
                                   "60px 4px");

  BoxStrut ltr_border_padding = ComputeBorders(ltr_space_, node) +
                                ComputePadding(ltr_space_, node.Style());
  BoxStrut rtl_border_padding = ComputeBorders(rtl_space_, node) +
                                ComputePadding(rtl_space_, node.Style());
  BoxStrut vlr_border_padding = ComputeBorders(vlr_space_, node) +
                                ComputePadding(vlr_space_, node.Style());
  BoxStrut vrl_border_padding = ComputeBorders(vrl_space_, node) +
                                ComputePadding(vrl_space_, node.Style());

  LogicalStaticPosition static_position = {{LayoutUnit(), LayoutUnit()},
                                           LogicalStaticPosition::kInlineStart,
                                           LogicalStaticPosition::kBlockStart};
  // Same as regular static position, but with the inline-end edge.
  LogicalStaticPosition static_position_inline_end = {
      {LayoutUnit(), LayoutUnit()},
      LogicalStaticPosition::kInlineEnd,
      LogicalStaticPosition::kBlockStart};

  LogicalOofDimensions dimensions;

  // All auto => width is content, left is 0.
  SetHorizontalStyle("auto", "auto", "auto", "auto", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(116, dimensions.size.inline_size);
  EXPECT_EQ(0, dimensions.inset.inline_start);

  // All auto => width is content, static_position is right
  SetHorizontalStyle("auto", "auto", "auto", "auto", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position_inline_end,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(116, dimensions.size.inline_size);
  EXPECT_EQ(200, dimensions.inset.inline_end);

  // All auto + RTL.
  SetHorizontalStyle("auto", "auto", "auto", "auto", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, rtl_space_, rtl_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(116, dimensions.size.inline_size);
  // 200 = 0 + 0 + 116 + 84 + 0
  EXPECT_EQ(84, dimensions.inset.inline_end);

  // left, right, and left are known, compute margins.
  SetHorizontalStyle("5px", "auto", "160px", "auto", "13px");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 5 + 11 + 160 + 11 + 13
  EXPECT_EQ(16, dimensions.inset.inline_start);
  EXPECT_EQ(24, dimensions.inset.inline_end);

  // left, right, and left are known, compute margins, writing mode vertical_lr.
  SetHorizontalStyle("5px", "auto", "160px", "auto", "13px", "vertical-lr");
  ComputeOutOfFlowBlockDimensions(
      node, vlr_space_, vlr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(16, dimensions.inset.block_start);
  EXPECT_EQ(24, dimensions.inset.block_end);

  // left, right, and left are known, compute margins, writing mode vertical_rl.
  SetHorizontalStyle("5px", "auto", "160px", "auto", "13px", "vertical-rl");
  ComputeOutOfFlowBlockDimensions(
      node, vrl_space_, vrl_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(16, dimensions.inset.block_end);
  EXPECT_EQ(24, dimensions.inset.block_start);

  // left, right, and width are known, not enough space for margins LTR.
  SetHorizontalStyle("5px", "auto", "200px", "auto", "13px");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(5, dimensions.inset.inline_start);
  EXPECT_EQ(-5, dimensions.inset.inline_end);

  // left, right, and left are known, not enough space for margins RTL.
  SetHorizontalStyle("5px", "auto", "200px", "auto", "13px");
  ComputeOutOfFlowInlineDimensions(
      node, rtl_space_, rtl_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kRtl}, &dimensions);
  EXPECT_EQ(-13, dimensions.inset.inline_start);
  EXPECT_EQ(13, dimensions.inset.inline_end);

  // Rule 1 left and width are auto.
  SetHorizontalStyle("auto", "7px", "auto", "15px", "13px");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(116, dimensions.size.inline_size);

  // Rule 2 left and right are auto LTR.
  SetHorizontalStyle("auto", "7px", "160px", "15px", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 0 + 7 + 160 + 15 + 18
  EXPECT_EQ(0 + 7, dimensions.inset.inline_start);
  EXPECT_EQ(15 + 18, dimensions.inset.inline_end);

  // Rule 2 left and right are auto RTL.
  SetHorizontalStyle("auto", "7px", "160px", "15px", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, rtl_space_, rtl_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kRtl}, &dimensions);
  // 200 = 0 + 7 + 160 + 15 + 18
  EXPECT_EQ(0 + 7, dimensions.inset.inline_start);
  EXPECT_EQ(15 + 18, dimensions.inset.inline_end);

  // Rule 3 width and right are auto.
  SetHorizontalStyle("5px", "7px", "auto", "15px", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 5 + 7 + 116 + 15 + 57
  EXPECT_EQ(116, dimensions.size.inline_size);
  EXPECT_EQ(15 + 57, dimensions.inset.inline_end);

  // Rule 4: left is auto.
  SetHorizontalStyle("auto", "7px", "160px", "15px", "13px");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 5 + 7 + 160 + 15 + 13
  EXPECT_EQ(5 + 7, dimensions.inset.inline_start);

  // Rule 4: left is auto, "box-sizing: content-box".
  SetHorizontalStyle("auto", "7px", "104px", "15px", "13px", "horizontal-tb",
                     "content-box");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 5 + 7 + 160 + 15 + 13
  EXPECT_EQ(5 + 7, dimensions.inset.inline_start);

  // Rule 5: right is auto.
  SetHorizontalStyle("5px", "7px", "160px", "15px", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 5 + 7 + 160 + 15 + 13
  EXPECT_EQ(15 + 13, dimensions.inset.inline_end);

  // Rule 6: width is auto.
  SetHorizontalStyle("5px", "7px", "auto", "15px", "13px");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 200 = 5 + 7 + 160 + 15 + 13
  EXPECT_EQ(160, dimensions.size.inline_size);
}

TEST_F(AbsoluteUtilsTest, Vertical) {
  element_->SetInlineStyleProperty(CSSPropertyID::kContain, "size");
  element_->SetInlineStyleProperty(CSSPropertyID::kContainIntrinsicSize,
                                   "60px 4px");

  BlockNode node(element_->GetLayoutBox());

  BoxStrut ltr_border_padding = ComputeBorders(ltr_space_, node) +
                                ComputePadding(ltr_space_, node.Style());
  BoxStrut vlr_border_padding = ComputeBorders(vlr_space_, node) +
                                ComputePadding(vlr_space_, node.Style());
  BoxStrut vrl_border_padding = ComputeBorders(vrl_space_, node) +
                                ComputePadding(vrl_space_, node.Style());

  LogicalStaticPosition static_position = {{LayoutUnit(), LayoutUnit()},
                                           LogicalStaticPosition::kInlineStart,
                                           LogicalStaticPosition::kBlockStart};
  LogicalStaticPosition static_position_block_end = {
      {LayoutUnit(), LayoutUnit()},
      LogicalStaticPosition::kInlineStart,
      LogicalStaticPosition::kBlockEnd};

  LogicalOofDimensions dimensions;

  // Set inline-dimensions in-case any block dimensions require it.
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);

  // All auto, compute margins.
  SetVerticalStyle("auto", "auto", "auto", "auto", "auto");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(60, dimensions.size.block_size);
  EXPECT_EQ(0, dimensions.inset.block_start);

  // All auto, static position bottom.
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position_block_end,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(300, dimensions.inset.block_end);

  // If top, bottom, and height are known, compute margins.
  SetVerticalStyle("5px", "auto", "260px", "auto", "13px");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 300 = 5 + 11 + 260 + 11 + 13
  EXPECT_EQ(5 + 11, dimensions.inset.block_start);
  EXPECT_EQ(11 + 13, dimensions.inset.block_end);

  // If top, bottom, and height are known, "writing-mode: vertical-lr".
  SetVerticalStyle("5px", "auto", "260px", "auto", "13px", "vertical-lr");
  ComputeOutOfFlowInlineDimensions(
      node, vlr_space_, vlr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 300 = 5 + 11 + 260 + 11 + 13
  EXPECT_EQ(5 + 11, dimensions.inset.inline_start);
  EXPECT_EQ(11 + 13, dimensions.inset.inline_end);

  // If top, bottom, and height are known, "writing-mode: vertical-rl".
  SetVerticalStyle("5px", "auto", "260px", "auto", "13px", "vertical-rl");
  ComputeOutOfFlowInlineDimensions(
      node, vrl_space_, vrl_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 300 = 5 + 11 + 260 + 11 + 13
  EXPECT_EQ(5 + 11, dimensions.inset.inline_start);
  EXPECT_EQ(11 + 13, dimensions.inset.inline_end);

  // If top, bottom, and height are known, negative auto margins.
  SetVerticalStyle("5px", "auto", "300px", "auto", "13px");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 300 = 5 + (-9) + 300 + (-9) + 13
  EXPECT_EQ(5 - 9, dimensions.inset.block_start);
  EXPECT_EQ(-9 + 13, dimensions.inset.block_end);

  // Rule 1: top and height are unknown.
  SetVerticalStyle("auto", "7px", "auto", "15px", "13px");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(60, dimensions.size.block_size);

  // Rule 2: top and bottom are unknown.
  SetVerticalStyle("auto", "7px", "260px", "15px", "auto");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 300 = 0 + 7 + 260 + 15 + 18
  EXPECT_EQ(0 + 7, dimensions.inset.block_start);
  EXPECT_EQ(15 + 18, dimensions.inset.block_end);

  // Rule 3: height and bottom are unknown.
  SetVerticalStyle("5px", "7px", "auto", "15px", "auto");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(60, dimensions.size.block_size);

  // Rule 4: top is unknown.
  SetVerticalStyle("auto", "7px", "260px", "15px", "13px");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  // 300 = 5 + 7 + 260 + 15 + 13
  EXPECT_EQ(5 + 7, dimensions.inset.block_start);

  // Rule 5: bottom is unknown.
  SetVerticalStyle("5px", "7px", "260px", "15px", "auto");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(260, dimensions.size.block_size);
}

TEST_F(AbsoluteUtilsTest, CenterStaticPosition) {
  BlockNode node(element_->GetLayoutBox());
  LogicalStaticPosition static_position = {{LayoutUnit(150), LayoutUnit(200)},
                                           LogicalStaticPosition::kInlineCenter,
                                           LogicalStaticPosition::kBlockCenter};

  SetHorizontalStyle("auto", "auto", "auto", "auto", "auto");
  SetVerticalStyle("auto", "auto", "auto", "auto", "auto");

  BoxStrut border_padding;
  LogicalOofDimensions dimensions;

  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(100, dimensions.size.inline_size);
  EXPECT_EQ(100, dimensions.inset.inline_start);
  EXPECT_EQ(0, dimensions.inset.inline_end);

  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kRtl}, &dimensions);
  EXPECT_EQ(100, dimensions.size.inline_size);
  EXPECT_EQ(100, dimensions.inset.inline_start);
  EXPECT_EQ(0, dimensions.inset.inline_end);

  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(150, dimensions.size.block_size);
  EXPECT_EQ(125, dimensions.inset.block_start);
  EXPECT_EQ(25, dimensions.inset.block_end);
}

TEST_F(AbsoluteUtilsTest, MinMax) {
  element_->SetInlineStyleProperty(CSSPropertyID::kMinWidth, "70px");
  element_->SetInlineStyleProperty(CSSPropertyID::kMaxWidth, "150px");
  element_->SetInlineStyleProperty(CSSPropertyID::kMinHeight, "70px");
  element_->SetInlineStyleProperty(CSSPropertyID::kMaxHeight, "150px");
  element_->SetInlineStyleProperty(CSSPropertyID::kContain, "size");

  BlockNode node(element_->GetLayoutBox());

  BoxStrut ltr_border_padding = ComputeBorders(ltr_space_, node) +
                                ComputePadding(ltr_space_, node.Style());

  LogicalStaticPosition static_position = {{LayoutUnit(), LayoutUnit()},
                                           LogicalStaticPosition::kInlineStart,
                                           LogicalStaticPosition::kBlockStart};

  LogicalOofDimensions dimensions;

  // WIDTH TESTS

  // width < min gets set to min.
  SetHorizontalStyle("auto", "auto", "5px", "auto", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(70, dimensions.size.inline_size);

  // width > max gets set to max.
  SetHorizontalStyle("auto", "auto", "200px", "auto", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(150, dimensions.size.inline_size);

  // Unspecified width becomes min_max, gets clamped to min.
  SetHorizontalStyle("auto", "auto", "auto", "auto", "auto");
  ComputeOutOfFlowInlineDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(70, dimensions.size.inline_size);

  // HEIGHT TESTS

  // height < min gets set to min.
  SetVerticalStyle("auto", "auto", "5px", "auto", "auto");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(70, dimensions.size.block_size);

  // height > max gets set to max.
  SetVerticalStyle("auto", "auto", "200px", "auto", "auto");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(150, dimensions.size.block_size);

  // // Unspecified height becomes estimated, gets clamped to min.
  SetVerticalStyle("auto", "auto", "auto", "auto", "auto");
  ComputeOutOfFlowBlockDimensions(
      node, ltr_space_, ltr_border_padding, static_position,
      {WritingMode::kHorizontalTb, TextDirection::kLtr}, &dimensions);
  EXPECT_EQ(70, dimensions.size.block_size);
}

}  // namespace
}  // namespace blink

"""

```