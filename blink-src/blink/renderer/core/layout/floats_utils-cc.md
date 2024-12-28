Response:
The user wants a breakdown of the `floats_utils.cc` file in the Chromium Blink engine. I need to identify its functionalities, explain its relationship with web technologies like JavaScript, HTML, and CSS, provide examples with hypothetical input and output for logical deductions, and illustrate common usage errors.

Here's a plan:

1. **Identify Core Functionalities:** Analyze the code to determine the primary purposes of the functions and data structures defined in the file. Keywords like "ExclusionSpace," "UnpositionedFloat," "PositionedFloat," "LayoutOpportunity," "fragmentation," and "clearance" are strong indicators.

2. **Relate to Web Technologies:** Explain how the identified functionalities impact the rendering of web pages based on HTML structure, CSS styling (especially the `float` and `clear` properties, `shape-outside`), and how JavaScript might indirectly trigger these layout calculations.

3. **Logical Deduction Examples:** Choose specific functions and demonstrate their behavior with hypothetical inputs and expected outputs. Focus on functions that involve calculations or decision-making.

4. **Common Usage Errors:**  Think about how incorrect CSS or HTML could lead to unexpected behavior related to floats, which this file might be handling. Consider scenarios that developers frequently encounter.
好的，让我们来分析一下 `blink/renderer/core/layout/floats_utils.cc` 这个文件。

**功能概述:**

这个文件主要负责处理 HTML 浮动元素（`float` 属性）的布局计算和定位。其核心目标是在一个布局上下文中确定浮动元素应该放置在哪里，并考虑与其他元素（包括其他浮动元素和非浮动块级元素）的相互作用。它涉及到以下关键方面：

1. **查找浮动元素的布局机会 (Layout Opportunity):**  确定在给定的约束条件下，浮动元素可以占据的空间。这需要考虑已有的浮动元素、清除 (clear) 属性、外边距等因素。
2. **创建浮动元素的约束空间 (Constraint Space):**  为浮动元素创建特定的布局约束，例如可用宽度、是否进行分片 (fragmentation) 等。
3. **计算浮动元素的最终位置 (Positioning):**  根据找到的布局机会和计算出的外边距等信息，最终确定浮动元素在布局上下文中的位置。
4. **管理排除区域 (Exclusion Area):**  浮动元素会创建排除区域，影响后续内容的布局。这个文件负责创建和管理这些排除区域。
5. **处理分片 (Fragmentation):**  当浮动元素跨越分片容器（例如多列布局或分页内容）时，需要特殊处理。
6. **遵守顶部边缘对齐规则 (Top Edge Alignment Rule):**  确保浮动元素的顶部不会高于文档源顺序中更早出现的块级元素或浮动元素。
7. **处理 `shape-outside` 属性:**  如果浮动元素设置了 `shape-outside` 属性，该文件会创建相应的排除形状数据。

**与 JavaScript, HTML, CSS 的关系:**

这个文件直接服务于 CSS 的 `float` 和 `clear` 属性，以及 `shape-outside` 属性的实现。

* **HTML:** HTML 结构定义了哪些元素是浮动元素。例如：

```html
<div style="width: 100px; height: 100px; float: left;">浮动元素</div>
<div>跟随在浮动元素后面的内容</div>
```

`floats_utils.cc` 的代码会处理像上面这样的浮动元素。

* **CSS:**  CSS 样式（尤其是 `float`、`clear`、`margin` 和 `shape-outside`）是 `floats_utils.cc` 计算布局的关键输入。

    * **`float` 属性:**  决定元素是否浮动以及浮动的方向 (`left` 或 `right`)。`PositionFloat` 函数会根据 `float` 的值来确定浮动元素应该放置在哪一侧。
    * **`clear` 属性:**  指定元素是否可以出现在之前的浮动元素的旁边。`FindLayoutOpportunityForFloat` 函数会考虑 `clear` 属性来确定浮动元素的起始位置。例如：

    ```css
    .clear-left { clear: left; }
    ```

    如果一个元素设置了 `clear: left;`，那么它的顶部边缘会被下推到所有之前的左浮动元素的下方。

    * **`margin` 属性:** 浮动元素的外边距会影响其占据的空间和与其他元素的距离。`ComputeMarginsFor` 函数计算浮动元素的外边距。
    * **`shape-outside` 属性:** 定义了浮动元素周围内容可以环绕的非矩形区域。`CreateExclusionShapeData` 函数负责处理 `shape-outside` 的相关逻辑。例如：

    ```css
    .shaped {
      float: left;
      width: 100px;
      height: 100px;
      shape-outside: circle(50%);
    }
    ```

* **JavaScript:** JavaScript 通常不会直接调用 `floats_utils.cc` 中的函数。然而，JavaScript 可以通过修改元素的 CSS 样式（例如改变 `float` 属性）或 HTML 结构（添加或删除浮动元素）来间接地触发 `floats_utils.cc` 中的布局计算。例如，通过 JavaScript 动态地添加一个 `float: left;` 的元素，会导致浏览器重新计算布局，从而调用到 `floats_utils.cc` 中的代码。

**逻辑推理的假设输入与输出示例:**

考虑 `FindLayoutOpportunityForFloat` 函数。

**假设输入:**

* `unpositioned_float`:  一个待定位的左浮动元素，宽度为 50px，外边距左 10px，上 10px。其 `origin_bfc_offset` 为 (0, 0)。
* `exclusion_space`: 当前布局上下文的排除空间信息，包含一个已存在的左浮动元素，其外边距盒子的范围是 (0, 0) 到 (100, 100)。
* `fragment_margins`:  当前分片的边距，假设为 0。
* `inline_size`: 当前可用行内空间，假设为 500px。

**逻辑推理:**

1. **调整到顶部边缘对齐规则:** `AdjustToTopEdgeAlignmentRule` 会检查新的浮动元素的顶部是否高于已有的浮动元素。在本例中，`origin_bfc_offset.block_offset` (0) 不小于 `exclusion_space.LastFloatBlockStart()` (0)，所以不需要调整。
2. **考虑 `clear` 属性:**  假设新的浮动元素没有设置 `clear` 属性。`exclusion_space.ClearanceOffset` 返回 0。`exclusion_space.InitialLetterClearanceOffset` 也返回 0。因此 `clearance_offset` 为 0。
3. **查找布局机会:** `exclusion_space.FindLayoutOpportunity` 会尝试找到一个宽度至少为 `unpositioned_float.available_size.inline_size` (50px) + `fragment_margins.InlineSum()` (0) = 50px 的空间，起始位置从 `adjusted_origin_point` (0, 0) 开始。 由于已有的左浮动元素占据了 (0, 0) 到 (100, 100) 的空间，新的左浮动元素会被放置在其右侧。

**可能的输出:**

`LayoutOpportunity` 结构体，其 `rect` 成员可能为：

```
BfcRect {
  start_offset: BfcOffset { line_offset: 100, block_offset: 0 },
  end_offset: BfcOffset { line_offset: 160, block_offset: 100 } // 100 + 50 + 10
}
```

这个输出表明找到的布局机会从水平偏移 100px 开始，这是前一个浮动元素的右边缘。

**用户或编程常见的使用错误:**

1. **忘记清除浮动导致布局混乱:**  这是最常见的错误。如果父元素没有明确的高度，并且其所有子元素都是浮动的，那么父元素的高度可能会塌陷，导致后续元素布局异常。

   ```html
   <div style="border: 1px solid black;">
     <div style="float: left; width: 50px; height: 50px; background-color: red;"></div>
     <div style="float: left; width: 50px; height: 50px; background-color: blue;"></div>
   </div>
   <p>这段文字可能会向上移动到浮动元素的区域。</p>
   ```

   **解决方法:**  可以使用多种方法清除浮动，例如：
   * 在父元素末尾添加一个空的 `div` 并设置 `clear: both;`。
   * 使用 CSS 的 `overflow: auto;` 或 `overflow: hidden;` 给父元素创建新的块级格式化上下文 (BFC)。
   * 使用 CSS 的 `::after` 伪元素清除浮动。

2. **过度依赖浮动进行布局:**  虽然浮动是 CSS 布局的重要组成部分，但过度依赖浮动来实现复杂的布局可能会导致代码难以维护和理解。现代 CSS 布局技术，如 Flexbox 和 Grid，在很多情况下是更好的选择。

3. **误解 `clear` 属性的作用:**  `clear` 属性只阻止元素的**顶部边缘**出现在之前的浮动元素的旁边。它不会影响元素的内容是否环绕浮动元素。

   ```html
   <div style="float: left; width: 100px; height: 50px; background-color: yellow;"></div>
   <p style="clear: left;">这段文字的顶部会出现在浮动元素下方，但文字内容可能会环绕浮动元素。</p>
   ```

4. **`shape-outside` 的使用限制:**  `shape-outside` 只能应用于浮动元素。如果尝试将其应用于非浮动元素，它将不会生效。

5. **与 `margin-collapsing` 的混淆:**  浮动元素不会与其父元素或相邻的非浮动元素发生外边距折叠。开发者可能会错误地期望浮动元素的外边距会与周围元素的外边距合并。

总而言之，`floats_utils.cc` 是 Chromium Blink 引擎中一个至关重要的文件，它负责处理 CSS 浮动布局的核心逻辑，确保网页能够按照预期的方式渲染浮动元素，并与其他元素正确交互。理解其功能有助于我们更好地理解浏览器如何解析和呈现网页。

Prompt: 
```
这是目录为blink/renderer/core/layout/floats_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/floats_utils.h"

#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/fragment_builder.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/layout/min_max_sizes.h"
#include "third_party/blink/renderer/core/layout/physical_fragment.h"
#include "third_party/blink/renderer/core/layout/positioned_float.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/unpositioned_float.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {
namespace {

// Adjusts the provided offset to the top edge alignment rule.
// Top edge alignment rule: the outer top of a floating box may not be higher
// than the outer top of any block or floated box generated by an element
// earlier in the source document.
BfcOffset AdjustToTopEdgeAlignmentRule(const ExclusionSpace& exclusion_space,
                                       const BfcOffset& offset) {
  BfcOffset adjusted_offset = offset;
  adjusted_offset.block_offset = std::max(
      adjusted_offset.block_offset, exclusion_space.LastFloatBlockStart());

  return adjusted_offset;
}

LayoutOpportunity FindLayoutOpportunityForFloat(
    const UnpositionedFloat& unpositioned_float,
    const ExclusionSpace& exclusion_space,
    const BoxStrut& fragment_margins,
    LayoutUnit inline_size) {
  BfcOffset adjusted_origin_point = AdjustToTopEdgeAlignmentRule(
      exclusion_space, unpositioned_float.origin_bfc_offset);

  const TextDirection direction = unpositioned_float.parent_space.Direction();
  const EClear clear_type = unpositioned_float.ClearType(direction);
  const EFloat float_type = unpositioned_float.node.Style().Floating(direction);
  const LayoutUnit clearance_offset =
      std::max({exclusion_space.ClearanceOffset(clear_type),
                exclusion_space.InitialLetterClearanceOffset(float_type)});

  AdjustToClearance(clearance_offset, &adjusted_origin_point);

  return exclusion_space.FindLayoutOpportunity(
      adjusted_origin_point, unpositioned_float.available_size.inline_size,
      inline_size + fragment_margins.InlineSum() /* minimum_inline_size */);
}

// Creates a constraint space for an unpositioned float. origin_block_offset
// should only be set when we want to fragmentation to occur.
ConstraintSpace CreateConstraintSpaceForFloat(
    const UnpositionedFloat& unpositioned_float,
    std::optional<LayoutUnit> origin_block_offset = std::nullopt,
    std::optional<BoxStrut> margins = std::nullopt) {
  const ComputedStyle& style = unpositioned_float.node.Style();
  const ConstraintSpace& parent_space = unpositioned_float.parent_space;
  ConstraintSpaceBuilder builder(parent_space, style.GetWritingDirection(),
                                 /* is_new_fc */ true);
  SetOrthogonalFallbackInlineSizeIfNeeded(unpositioned_float.parent_style,
                                          unpositioned_float.node, &builder);
  builder.SetIsPaintedAtomically(true);
  builder.SetIsHiddenForPaint(unpositioned_float.is_hidden_for_paint);

  if (origin_block_offset) {
    DCHECK(margins);
    DCHECK(parent_space.HasBlockFragmentation());
    DCHECK_EQ(style.GetWritingMode(), parent_space.GetWritingMode());

    SetupSpaceBuilderForFragmentation(
        parent_space, unpositioned_float.node,
        unpositioned_float.fragmentainer_block_offset + *origin_block_offset,
        unpositioned_float.fragmentainer_block_size,
        /*requires_content_before_breaking=*/false, &builder);

    // For other node types, what matters is whether the block-start border edge
    // is at the fragmentainer start, but for floats, it's the block start
    // *margin* edge, since float margins are unbreakable and are never
    // truncated.
    LayoutUnit margin_edge_offset =
        unpositioned_float.fragmentainer_block_offset + *origin_block_offset -
        margins->block_start;
    if (margin_edge_offset <= LayoutUnit())
      builder.SetIsAtFragmentainerStart();
  } else {
    builder.SetFragmentationType(FragmentationType::kFragmentNone);
  }

  builder.SetAvailableSize(unpositioned_float.available_size);
  builder.SetPercentageResolutionSize(unpositioned_float.percentage_size);
  builder.SetReplacedPercentageResolutionSize(
      unpositioned_float.replaced_percentage_size);
  return builder.ToConstraintSpace();
}

ExclusionShapeData* CreateExclusionShapeData(
    const BoxStrut& margins,
    const UnpositionedFloat& unpositioned_float) {
  const LayoutBox* layout_box = unpositioned_float.node.GetLayoutBox();
  DCHECK(layout_box->GetShapeOutsideInfo());
  const ConstraintSpace& parent_space = unpositioned_float.parent_space;
  TextDirection direction = parent_space.Direction();

  // We make the margins on the shape-data relative to line-left/line-right.
  BoxStrut new_margins(margins.LineLeft(direction),
                       margins.LineRight(direction), margins.block_start,
                       margins.block_end);
  BoxStrut shape_insets;

  const ComputedStyle& style = unpositioned_float.node.Style();
  switch (style.ShapeOutside()->CssBox()) {
    case CSSBoxType::kMissing:
    case CSSBoxType::kMargin:
      shape_insets -= new_margins;
      break;
    case CSSBoxType::kBorder:
      break;
    case CSSBoxType::kPadding:
    case CSSBoxType::kContent:
      const ConstraintSpace space =
          CreateConstraintSpaceForFloat(unpositioned_float);
      BoxStrut strut = ComputeBorders(space, unpositioned_float.node);
      if (style.ShapeOutside()->CssBox() == CSSBoxType::kContent)
        strut += ComputePadding(space, style);
      // |TextDirection::kLtr| is used as this is line relative.
      shape_insets = strut.ConvertToPhysical(style.GetWritingDirection())
                         .ConvertToLogical({parent_space.GetWritingMode(),
                                            TextDirection::kLtr});
      break;
  }

  return MakeGarbageCollected<ExclusionShapeData>(layout_box, new_margins,
                                                  shape_insets);
}

// Creates an exclusion from the fragment that will be placed in the provided
// layout opportunity.
const ExclusionArea* CreateExclusionArea(
    const LogicalFragment& fragment,
    const BfcOffset& float_margin_bfc_offset,
    const BoxStrut& margins,
    const UnpositionedFloat& unpositioned_float,
    EFloat type) {
  BfcOffset start_offset = float_margin_bfc_offset;
  BfcOffset end_offset(
      start_offset.line_offset +
          (fragment.InlineSize() + margins.InlineSum()).ClampNegativeToZero(),
      start_offset.block_offset +
          (fragment.BlockSize() + margins.BlockSum()).ClampNegativeToZero());

  ExclusionShapeData* shape_data =
      unpositioned_float.node.GetLayoutBox()->GetShapeOutsideInfo()
          ? CreateExclusionShapeData(margins, unpositioned_float)
          : nullptr;

  return ExclusionArea::Create(BfcRect(start_offset, end_offset), type,
                               unpositioned_float.is_hidden_for_paint,
                               std::move(shape_data));
}

// Performs layout on a float, without fragmentation, and stores the result on
// the UnpositionedFloat data-structure.
void LayoutFloatWithoutFragmentation(UnpositionedFloat* unpositioned_float) {
  if (unpositioned_float->layout_result)
    return;

  const ConstraintSpace space =
      CreateConstraintSpaceForFloat(*unpositioned_float);

  // Pass in the break token if one exists. This can happen when we relayout
  // without fragmentation to handle clipping. We still want to look at the
  // break token so that layout is resumed correctly. See
  // InvolvedInBlockFragmentation() in fragmentation_utils.h for more details.
  unpositioned_float->layout_result =
      unpositioned_float->node.Layout(space, unpositioned_float->token);
  unpositioned_float->margins =
      ComputeMarginsFor(space, unpositioned_float->node.Style(),
                        unpositioned_float->parent_space);
}

}  // namespace

LayoutUnit ComputeMarginBoxInlineSizeForUnpositionedFloat(
    UnpositionedFloat* unpositioned_float) {
  DCHECK(unpositioned_float);

  LayoutFloatWithoutFragmentation(unpositioned_float);
  DCHECK(unpositioned_float->layout_result);

  const auto& fragment =
      unpositioned_float->layout_result->GetPhysicalFragment();
  DCHECK(!fragment.GetBreakToken());

  const ConstraintSpace& parent_space = unpositioned_float->parent_space;

  return (LogicalFragment(parent_space.GetWritingDirection(), fragment)
              .InlineSize() +
          unpositioned_float->margins.InlineSum())
      .ClampNegativeToZero();
}

PositionedFloat PositionFloat(UnpositionedFloat* unpositioned_float,
                              ExclusionSpace* exclusion_space) {
  DCHECK(unpositioned_float);
  const ConstraintSpace& parent_space = unpositioned_float->parent_space;
  BlockNode node = unpositioned_float->node;
  bool is_same_writing_mode =
      node.Style().GetWritingMode() == parent_space.GetWritingMode();

  bool is_fragmentable =
      is_same_writing_mode && parent_space.HasBlockFragmentation();

  const LayoutResult* layout_result = nullptr;
  BoxStrut fragment_margins;
  LayoutOpportunity opportunity;
  LayoutUnit fragmentainer_block_size =
      unpositioned_float->fragmentainer_block_size;
  bool need_break_before = false;

  if (!is_fragmentable) {
    // We may be able to re-use the fragment from when we calculated the
    // inline-size, if there is no block fragmentation.
    LayoutFloatWithoutFragmentation(unpositioned_float);
    layout_result = unpositioned_float->layout_result;
    fragment_margins = unpositioned_float->margins;

    LogicalFragment float_fragment(parent_space.GetWritingDirection(),
                                   layout_result->GetPhysicalFragment());

    // Find a layout opportunity that will fit our float.
    opportunity = FindLayoutOpportunityForFloat(
        *unpositioned_float, *exclusion_space, fragment_margins,
        float_fragment.InlineSize());
  } else {
    fragment_margins = ComputeMarginsFor(
        node.Style(), unpositioned_float->percentage_size.inline_size,
        parent_space.GetWritingDirection());
    AdjustMarginsForFragmentation(unpositioned_float->token, &fragment_margins);

    // When fragmenting, we need to set the block-offset of the node before
    // laying it out. This is a float, and in order to calculate its offset, we
    // first need to know its inline-size.

    LayoutUnit fragmentainer_delta;
    bool optimistically_placed = false;
    if (unpositioned_float->layout_result) {
      // We have already laid out the float to find its inline-size.
      LogicalFragment float_fragment(
          parent_space.GetWritingDirection(),
          unpositioned_float->layout_result->GetPhysicalFragment());
      // We can find a layout opportunity and set the fragmentainer offset right
      // away.
      opportunity = FindLayoutOpportunityForFloat(
          *unpositioned_float, *exclusion_space, fragment_margins,
          float_fragment.InlineSize());
      fragmentainer_delta = opportunity.rect.start_offset.block_offset +
                            fragment_margins.block_start;
    } else {
      // If we don't know the inline-size yet, we'll estimate the offset to be
      // the one we'd get if the float isn't affected by any other floats in the
      // block formatting context. If this turns out to be wrong, we'll need to
      // lay out again.
      fragmentainer_delta = unpositioned_float->origin_bfc_offset.block_offset +
                            fragment_margins.block_start;
      optimistically_placed = true;
    }

    bool is_at_fragmentainer_start;
    do {
      ConstraintSpace space = CreateConstraintSpaceForFloat(
          *unpositioned_float,
          fragmentainer_delta - parent_space.ExpectedBfcBlockOffset(),
          fragment_margins);

      is_at_fragmentainer_start = space.IsAtFragmentainerStart();

      layout_result = node.Layout(space, unpositioned_float->token);
      DCHECK_EQ(layout_result->Status(), LayoutResult::kSuccess);

      // If we knew the right block-offset up front, we're done.
      if (!optimistically_placed)
        break;

      LogicalFragment float_fragment(parent_space.GetWritingDirection(),
                                     layout_result->GetPhysicalFragment());

      // Find a layout opportunity that will fit our float, and see if our
      // initial estimate was correct.
      opportunity = FindLayoutOpportunityForFloat(
          *unpositioned_float, *exclusion_space, fragment_margins,
          float_fragment.InlineSize());

      LayoutUnit new_fragmentainer_delta =
          opportunity.rect.start_offset.block_offset +
          fragment_margins.block_start;

      // We can only stay where we are, or go down.
      DCHECK_LE(fragmentainer_delta, new_fragmentainer_delta);

      if (fragmentainer_delta < new_fragmentainer_delta) {
        // The float got pushed down. We need to lay out again.
        fragmentainer_delta = new_fragmentainer_delta;
        optimistically_placed = false;
        continue;
      }
      break;
    } while (true);

    // Note that we don't check if we're at a valid class A, B or C breakpoint
    // (we only check that we're not at the start of the fragmentainer (in which
    // case breaking typically wouldn't eliminate the unappealing break inside
    // the float)). While no other browsers do this either, we should consider
    // doing this in the future. But for now, don't let the float affect the
    // appeal of breaking inside this container.
    //
    // If we're past the fragmentainer start, we can consider breaking before
    // this float. Otherwise we cannot, or there'd be no content
    // progression. The common fragmentation machinery assumes that margins can
    // collapse with fragmentainer boundaries, but this isn't the case for
    // floats. We don't allow float margins to collapse with anything, nor be
    // split into multiple fragmentainers. Hence this additional check. Note
    // that we might want to reconsider this behavior, since browsers disagree
    // (what we do now is relatively similar to legacy Blink, though). Should we
    // split a margin in cases where it helps prevent fragmentainer overflow?
    // Should we always split them if they occur at fragmentainer boundaries? Or
    // even allow them to collapse with the fragmentainer boundary? Exact
    // behavior is currently unspecified.
    if (!is_at_fragmentainer_start) {
      LayoutUnit fragmentainer_block_offset =
          unpositioned_float->FragmentainerOffsetAtBfc() +
          opportunity.rect.start_offset.block_offset +
          fragment_margins.block_start;
      const auto* break_token = To<BlockBreakToken>(
          layout_result->GetPhysicalFragment().GetBreakToken());
      bool is_at_block_end = !break_token || break_token->IsAtBlockEnd();
      if (!is_at_block_end) {
        // We need to resume in the next fragmentainer (or even push the whole
        // thing there), which means that there'll be no block-end margin here.
        fragment_margins.block_end = LayoutUnit();
      }

      if (!MovePastBreakpoint(parent_space, node, *layout_result,
                              fragmentainer_block_offset,
                              fragmentainer_block_size, kBreakAppealPerfect,
                              /*builder=*/nullptr)) {
        need_break_before = true;
      } else if (is_at_block_end &&
                 parent_space.HasKnownFragmentainerBlockSize()) {
        LogicalFragment float_fragment(parent_space.GetWritingDirection(),
                                       layout_result->GetPhysicalFragment());
        LayoutUnit outer_block_end = fragmentainer_block_offset +
                                     float_fragment.BlockSize() +
                                     fragment_margins.block_end;
        if (outer_block_end > fragmentainer_block_size &&
            !IsBreakInside(unpositioned_float->token)) {
          // Avoid breaking inside the block-end margin of a float. They are not
          // to collapse with the fragmentainer boundary, unlike margins on
          // regular boxes.
          need_break_before = true;
        }
      }
    }
  }

  const auto& physical_fragment =
      To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());
  LogicalFragment float_fragment(parent_space.GetWritingDirection(),
                                 physical_fragment);

  // Calculate the float's margin box BFC offset.
  BfcOffset float_margin_bfc_offset = opportunity.rect.start_offset;
  if (unpositioned_float->IsLineRight(parent_space.Direction())) {
    LayoutUnit float_margin_box_inline_size =
        float_fragment.InlineSize() + fragment_margins.InlineSum();
    float_margin_bfc_offset.line_offset +=
        (opportunity.rect.InlineSize() - float_margin_box_inline_size);
  }

  if (parent_space.HasBlockFragmentation() && !need_break_before &&
      !IsBreakInside(unpositioned_float->token) &&
      exclusion_space->NeedsBreakBeforeFloat(
          unpositioned_float->ClearType(parent_space.Direction())))
    need_break_before = true;

  // Add the float as an exclusion.
  const auto float_type = node.Style().Floating(parent_space.Direction());
  if (need_break_before) {
    // Create a special exclusion past everything, so that the container(s) may
    // grow to encompass the floats, if appropriate.
    BfcOffset past_everything(LayoutUnit(),
                              unpositioned_float->FragmentainerSpaceLeft() +
                                  parent_space.ExpectedBfcBlockOffset());
    const ExclusionArea* exclusion = ExclusionArea::Create(
        BfcRect(past_everything, past_everything), float_type,
        unpositioned_float->is_hidden_for_paint);
    exclusion_space->Add(std::move(exclusion));

    // Also specify that there will be a fragmentainer break before this
    // float. This means that we cannot add any more floats to the current
    // fragmentainer (a float cannot start above any preceding float), and it
    // may also affect clearance.
    exclusion_space->SetHasBreakBeforeFloat(float_type);
  } else {
    const ExclusionArea* exclusion =
        CreateExclusionArea(float_fragment, float_margin_bfc_offset,
                            fragment_margins, *unpositioned_float, float_type);
    exclusion_space->Add(std::move(exclusion));

    // If the float broke inside and will continue to take up layout space in
    // the next fragmentainer, it means that we cannot fit any subsequent
    // content that wants clearance past this float.
    if (const BlockBreakToken* break_token =
            physical_fragment.GetBreakToken()) {
      if (!break_token->IsAtBlockEnd())
        exclusion_space->SetHasBreakInsideFloat(float_type);
    }
  }

  // Adjust the float's bfc_offset to its border-box (instead of margin-box).
  BfcOffset float_bfc_offset(
      float_margin_bfc_offset.line_offset +
          fragment_margins.LineLeft(parent_space.Direction()),
      float_margin_bfc_offset.block_offset + fragment_margins.block_start);

  const BlockBreakToken* break_before_token = nullptr;
  if (need_break_before) {
    break_before_token =
        BlockBreakToken::CreateBreakBefore(node, /* is_forced_break */ false);
  }

  LayoutUnit minimum_space_shortage;
  if (break_before_token || physical_fragment.GetBreakToken()) {
    // Broke before or inside the float.
    if (parent_space.HasKnownFragmentainerBlockSize() &&
        parent_space.BlockFragmentationType() == kFragmentColumn) {
      LayoutUnit fragmentainer_block_offset =
          unpositioned_float->FragmentainerOffsetAtBfc() +
          float_bfc_offset.block_offset;
      minimum_space_shortage = CalculateSpaceShortage(
          parent_space, layout_result, fragmentainer_block_offset,
          fragmentainer_block_size);
    }
  }

  return PositionedFloat(layout_result, break_before_token, float_bfc_offset,
                         minimum_space_shortage);
}

}  // namespace blink

"""

```