Response:
Let's break down the thought process for analyzing the `fieldset_layout_algorithm.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the code, its relation to web technologies, logical inferences, and potential errors. This requires understanding what the code *does* and *why*.

2. **Identify the Core Component:** The filename itself, `fieldset_layout_algorithm.cc`, immediately points to the core functionality: laying out `<fieldset>` elements. The class `FieldsetLayoutAlgorithm` confirms this.

3. **Deconstruct the Code (Top-Down):**  Start with the overall structure and key methods.

    * **Includes:**  These give hints about dependencies and related concepts (layout, forms, fragmentation, etc.). `third_party/blink/renderer/core/layout/...` indicates it's part of Blink's layout engine.

    * **Namespace:** `blink` and the anonymous namespace help organize the code.

    * **Enums and Helper Functions:**  The `LegendBlockAlignment` enum and `ComputeLegendBlockAlignment` function suggest how the `<legend>` element within the `<fieldset>` is positioned. This is an early indication of a key responsibility of this algorithm.

    * **Constructor:**  Initialization of member variables like `writing_direction_`, `consumed_block_size_`, and `border_box_size_` is important for understanding the context and state of the layout process. The `DCHECK` reinforces assumptions.

    * **`Layout()`:** This is the main entry point for the layout process. The comments within are crucial. They highlight the two-part process: laying out the `<legend>` and the fieldset content. The handling of scrollbars and padding differently for `<fieldset>` compared to regular blocks is a key takeaway. The mention of fragmentation also points to a significant aspect.

    * **`LayoutChildren()`:** This method further breaks down the child layout process, specifically handling the `<legend>` and the anonymous content box. The interaction with `BreakToken` and fragmentation is evident.

    * **`LayoutLegend()`:** This function details how the `<legend>` element is positioned and sized within the `<fieldset>`. The comments referencing the HTML specification are valuable.

    * **`LayoutFieldsetContent()`:** This handles the layout of the actual content within the `<fieldset>`. It considers fragmentation, block size limitations, and interaction with `BreakToken`.

    * **`FragmentainerSpaceAvailable()` and `ConsumeRemainingFragmentainerSpace()`:** These functions are relevant to fragmentation and how remaining space is handled.

    * **`ComputeMinMaxSizes()`:**  This deals with calculating the minimum and maximum sizes of the `<fieldset>`, taking into account the `<legend>` and content, and considering size containment.

    * **`CreateConstraintSpaceForLegend()` and `CreateConstraintSpaceForFieldsetContent()`:** These functions are about setting up the layout constraints for the child elements. The comments about percentage padding are important.

4. **Identify Key Responsibilities and Relationships:** Based on the code and comments, the core functions of `FieldsetLayoutAlgorithm` are:

    * **Handling the unique layout of `<fieldset>`:**  Specifically, how it treats the `<legend>` differently from normal content.
    * **Positioning the `<legend>`:**  Using `text-align` and margins, and centering it over the border.
    * **Laying out the fieldset content:**  Within an anonymous box, applying padding and scrollbars.
    * **Supporting block fragmentation:** Handling breaks within the `<fieldset>`.
    * **Calculating intrinsic sizes:** Determining the minimum and maximum dimensions.
    * **Respecting CSS properties:**  `text-align`, margins, padding, borders, etc.

5. **Connect to Web Technologies:**  Explicitly link the code's functionality to HTML, CSS, and JavaScript (where applicable).

    * **HTML:**  The `<fieldset>` and `<legend>` elements are directly addressed.
    * **CSS:**  Properties like `text-align`, `margin`, `padding`, `border`, `width`, `height`, and `box-sizing` are relevant. The concept of "size containment" is a CSS feature.
    * **JavaScript:** While this specific file doesn't *directly* interact with JS, the layout engine as a whole responds to changes triggered by JS modifications to the DOM and CSS.

6. **Infer Logical Relationships (Input/Output):** Consider how different inputs (HTML structure, CSS styles, available space) would affect the output (the position and size of the `<fieldset>` and its children). This is where hypothetical examples are useful.

7. **Identify Potential User/Developer Errors:** Think about common mistakes developers might make when using `<fieldset>` and how this code might be involved. Incorrect CSS, unexpected layout behavior, and fragmentation issues are good starting points.

8. **Structure the Answer:** Organize the findings logically, starting with a high-level overview and then diving into specifics. Use clear headings and bullet points for readability. Provide code snippets (where relevant) and illustrative examples.

9. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any missing points or areas that could be explained better. For example, initially, I might not have emphasized the anonymous content box enough, and a review would prompt me to add more detail about it.

By following this structured approach, breaking down the code into manageable parts, and connecting it back to the broader web development context, a comprehensive and accurate answer can be constructed.
好的，这是对`blink/renderer/core/layout/forms/fieldset_layout_algorithm.cc` 文件功能的详细解释：

**文件功能总览**

`fieldset_layout_algorithm.cc` 文件实现了 Chromium Blink 渲染引擎中用于布局 `<fieldset>` 元素及其内部 `<legend>` 元素的布局算法。  它负责确定 `<fieldset>` 容器及其子元素的尺寸和位置，并处理与分块（fragmentation）相关的逻辑。

**核心功能分解**

1. **`<fieldset>` 容器的特殊布局处理:**
   - `<fieldset>` 元素在布局上有一些特殊之处，特别是与它的 `<legend>` 子元素有关。
   - 此文件中的算法负责处理这些特殊性，例如 `<legend>` 元素不会像普通子元素那样影响 `<fieldset>` 的内边距（padding）和滚动条。
   - `<fieldset>` 的内边距和滚动条实际上应用于一个匿名的子内容盒子。

2. **`<legend>` 元素的布局:**
   - 算法负责定位和布局 `<legend>` 元素。
   - `<legend>` 元素可以根据 `text-align` 属性和自动边距在 `<fieldset>` 的起始边框内对齐。
   - 算法会计算 `<legend>` 的尺寸，并将其放置在 `<fieldset>` 边框的起始位置。
   - 特殊情况下，当 `<legend>` 的高度足够高时，它可能会影响 `<fieldset>` 起始边框的绘制方式，使其中心与 `<legend>` 的边框盒子的中心对齐。

3. **匿名内容盒子的布局:**
   - `<fieldset>` 内部的实际内容（除去 `<legend>`）被放置在一个匿名的子盒子中。
   - 此算法负责创建和布局这个匿名盒子，并将 `<fieldset>` 的内边距、滚动条等应用于这个匿名盒子。

4. **处理块级分块 (Block Fragmentation):**
   - 算法支持 `<fieldset>` 元素参与块级分块，这在分页打印或多列布局等场景下会用到。
   - 它会创建和管理 `FieldsetBreakTokenData` 来跟踪分块状态。
   - 算法会判断是否需要在 `<fieldset>` 内部进行分块，并生成相应的布局片段 (fragments)。

5. **计算最小和最大尺寸:**
   - 算法实现了 `ComputeMinMaxSizes` 方法，用于计算 `<fieldset>` 元素的最小和最大内联尺寸 (inline-size)。
   - 在计算过程中，会考虑 `<legend>` 和内容的影响，并区分是否启用了尺寸包含 (size containment)。

6. **创建约束空间 (Constraint Space):**
   - 算法定义了 `CreateConstraintSpaceForLegend` 和 `CreateConstraintSpaceForFieldsetContent` 方法，用于为 `<legend>` 元素和匿名的内容盒子创建布局约束空间。
   - 约束空间包含了布局所需的各种信息，例如可用尺寸、百分比解析尺寸、书写方向等。

**与 JavaScript, HTML, CSS 的关系及举例说明**

- **HTML:**  此文件直接处理 HTML 中的 `<fieldset>` 和 `<legend>` 元素。
   - **示例:** 当浏览器解析到以下 HTML 代码时，`FieldsetLayoutAlgorithm` 会被调用来布局 `<fieldset>` 及其 `<legend>`。
     ```html
     <fieldset>
       <legend>个人信息</legend>
       <label for="name">姓名:</label>
       <input type="text" id="name"><br><br>
       <label for="email">邮箱:</label>
       <input type="email" id="email">
     </fieldset>
     ```

- **CSS:**  CSS 样式会直接影响 `<fieldset>` 和 `<legend>` 的布局。
   - **示例 (text-align):**  `<legend>` 的 `text-align` 属性决定了它在 `<fieldset>` 起始边框内的水平对齐方式。
     ```css
     legend {
       text-align: center; /* 将 legend 居中对齐 */
     }
     ```
     `ComputeLegendBlockAlignment` 函数会根据 `<legend>` 和 `<fieldset>` 的样式计算出 `<legend>` 的块级对齐方式。
   - **示例 (margin):** `<legend>` 的 `margin` 属性可以用来调整其在 `<fieldset>` 中的位置。自动边距 (`auto`) 会参与 `<legend>` 的居中对齐计算。
     ```css
     legend {
       margin-left: auto;
       margin-right: auto; /* 将 legend 水平居中 */
     }
     ```
   - **示例 (padding, border):**  虽然 `<fieldset>` 本身的 `padding` 和 `border` 看似应用于自身，但实际上，这些样式会应用于内部的匿名内容盒子。
   - **示例 (box-sizing):** `box-sizing` 属性会影响 `<fieldset>` 和 `<legend>` 的尺寸计算方式。

- **JavaScript:**  JavaScript 可以动态地修改 `<fieldset>` 和 `<legend>` 的样式或结构，从而触发重新布局，间接地与此文件产生关系。
   - **示例:** JavaScript 可以修改 `<legend>` 的 `textContent`，导致其尺寸变化，从而触发 `FieldsetLayoutAlgorithm` 重新计算布局。
     ```javascript
     const legend = document.querySelector('legend');
     legend.textContent = '新的标题';
     ```

**逻辑推理、假设输入与输出**

**假设输入:**

```html
<fieldset style="border: 1px solid black; padding: 10px;">
  <legend style="text-align: center; margin-left: auto; margin-right: auto;">标题</legend>
  <div>内容</div>
</fieldset>
```

**逻辑推理:**

1. `FieldsetLayoutAlgorithm` 会被调用来布局 `<fieldset>`。
2. `ComputeLegendBlockAlignment` 会根据 `legend` 的 `text-align: center` 和 `margin-left: auto; margin-right: auto;` 计算出 `<legend>` 应该居中对齐。
3. `<legend>` 会首先被布局，其宽度根据内容和样式确定，高度也相应计算出来。
4. `<legend>` 会被放置在 `<fieldset>` 起始边框的上方居中位置。
5. 一个匿名的盒子会被创建来包含 `<div>内容</div>`。
6. `<fieldset>` 的 `padding: 10px;` 会应用于这个匿名盒子。
7. `<div>内容</div>` 会在匿名盒子内部进行布局。
8. `<fieldset>` 的最终高度会包裹 `<legend>` 和匿名内容盒子。

**假设输出 (简化的尺寸和位置关系):**

- `<legend>` 的位置：水平居中于 `<fieldset>` 的上边框之上。
- 匿名内容盒子的内边距：上、下、左、右各 10px。
- 匿名内容盒子包含 "内容"。
- `<fieldset>` 的整体尺寸会包含边框、 `<legend>` 的高度和匿名内容盒子的高度（包括内边距）。

**用户或编程常见的使用错误及举例说明**

1. **错误地假设 `<fieldset>` 的内边距直接应用于自身:** 开发者可能会认为设置 `<fieldset>` 的 `padding` 会直接影响 `<fieldset>` 容器本身，但实际上它影响的是内部的匿名内容盒子。
   ```css
   /* 错误的做法：可能期望 legend 也受到 padding 的影响 */
   fieldset {
     padding: 20px;
   }
   ```
   在这种情况下，`<legend>` 的位置不会受到 `<fieldset>` 的 `padding` 影响。

2. **不理解 `<legend>` 的定位机制:** 开发者可能不清楚 `<legend>` 是如何相对于 `<fieldset>` 定位的，导致布局不符合预期。例如，尝试使用 `position: absolute` 或 `float` 来定位 `<legend>` 可能会产生意想不到的结果，因为它的布局方式很特殊。

3. **在分块上下文中错误地预期 `<fieldset>` 的行为:** 当 `<fieldset>` 参与分块时，开发者可能没有考虑到 `<legend>` 的处理方式和分块点的选择，导致布局在分页或多列布局中出现问题。例如，期望 `<legend>` 和 `<fieldset>` 的内容始终在同一个分块中，但不一定总是如此。

4. **过度依赖默认样式:** 浏览器对 `<fieldset>` 和 `<legend>` 有默认样式。开发者如果没有清除或覆盖这些默认样式，可能会导致跨浏览器的一致性问题或布局上的困扰。

**总结**

`fieldset_layout_algorithm.cc` 是 Blink 渲染引擎中一个关键的文件，专门负责 `<fieldset>` 及其 `<legend>` 元素的布局。它处理了这些元素特有的布局规则，包括 `<legend>` 的定位、匿名内容盒子的创建以及块级分块的支持。理解此文件的功能有助于开发者更好地理解和调试涉及 `<fieldset>` 的网页布局问题。

Prompt: 
```
这是目录为blink/renderer/core/layout/forms/fieldset_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/forms/fieldset_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/forms/fieldset_break_token_data.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"

namespace blink {

namespace {

enum class LegendBlockAlignment {
  kStart,
  kCenter,
  kEnd,
};

// Legends aren't inline-level. Yet they may be aligned within the fieldset
// block-start border using the text-align property (in addition to using auto
// margins).
inline LegendBlockAlignment ComputeLegendBlockAlignment(
    const ComputedStyle& legend_style,
    const ComputedStyle& fieldset_style) {
  bool start_auto =
      legend_style.MarginInlineStartUsing(fieldset_style).IsAuto();
  bool end_auto = legend_style.MarginInlineEndUsing(fieldset_style).IsAuto();
  if (start_auto || end_auto) {
    if (start_auto) {
      return end_auto ? LegendBlockAlignment::kCenter
                      : LegendBlockAlignment::kEnd;
    }
    return LegendBlockAlignment::kStart;
  }
  const bool is_ltr = fieldset_style.IsLeftToRightDirection();
  switch (legend_style.GetTextAlign()) {
    case ETextAlign::kLeft:
      return is_ltr ? LegendBlockAlignment::kStart : LegendBlockAlignment::kEnd;
    case ETextAlign::kRight:
      return is_ltr ? LegendBlockAlignment::kEnd : LegendBlockAlignment::kStart;
    case ETextAlign::kCenter:
      return LegendBlockAlignment::kCenter;
    default:
      return LegendBlockAlignment::kStart;
  }
}

}  // namespace

FieldsetLayoutAlgorithm::FieldsetLayoutAlgorithm(
    const LayoutAlgorithmParams& params)
    : LayoutAlgorithm(params),
      writing_direction_(GetConstraintSpace().GetWritingDirection()),
      consumed_block_size_(GetBreakToken()
                               ? GetBreakToken()->ConsumedBlockSize()
                               : LayoutUnit()) {
  DCHECK(params.fragment_geometry.scrollbar.IsEmpty());
  border_box_size_ = container_builder_.InitialBorderBoxSize();
}

const LayoutResult* FieldsetLayoutAlgorithm::Layout() {
  // Layout of a fieldset container consists of two parts: Create a child
  // fragment for the rendered legend (if any), and create a child fragment for
  // the fieldset contents anonymous box (if any).
  // Fieldset scrollbars and padding will not be applied to the fieldset
  // container itself, but rather to the fieldset contents anonymous child box.
  // The reason for this is that the rendered legend shouldn't be part of the
  // scrollport; the legend is essentially a part of the block-start border,
  // and should not scroll along with the actual fieldset contents. Since
  // scrollbars are handled by the anonymous child box, and since padding is
  // inside the scrollport, padding also needs to be handled by the anonymous
  // child.
  if (ShouldIncludeBlockStartBorderPadding(container_builder_)) {
    intrinsic_block_size_ = Borders().block_start;
  }

  if (InvolvedInBlockFragmentation(container_builder_)) {
    container_builder_.SetBreakTokenData(
        MakeGarbageCollected<FieldsetBreakTokenData>(
            container_builder_.GetBreakTokenData()));
  }

  BreakStatus break_status = LayoutChildren();
  if (break_status == BreakStatus::kNeedsEarlierBreak) {
    // We need to abort the layout. No fragment will be generated.
    return container_builder_.Abort(LayoutResult::kNeedsEarlierBreak);
  }

  intrinsic_block_size_ =
      ClampIntrinsicBlockSize(GetConstraintSpace(), Node(), GetBreakToken(),
                              Borders() + Scrollbar() + Padding(),
                              intrinsic_block_size_ + Borders().block_end);

  // Recompute the block-axis size now that we know our content size.
  border_box_size_.block_size =
      ComputeBlockSizeForFragment(GetConstraintSpace(), Node(), BorderPadding(),
                                  intrinsic_block_size_ + consumed_block_size_,
                                  border_box_size_.inline_size);

  // The above computation utility knows nothing about fieldset weirdness. The
  // legend may eat from the available content box block size. Make room for
  // that if necessary.
  // Note that in size containment, we have to consider sizing as if we have no
  // contents, with the conjecture being that legend is part of the contents.
  // Thus, only do this adjustment if we do not contain size.
  if (!Node().ShouldApplyBlockSizeContainment()) {
    border_box_size_.block_size =
        std::max(border_box_size_.block_size, minimum_border_box_block_size_);
  }

  // TODO(almaher): end border and padding may overflow the parent
  // fragmentainer, and we should avoid that.
  LayoutUnit all_fragments_block_size = border_box_size_.block_size;

  container_builder_.SetIntrinsicBlockSize(intrinsic_block_size_);
  container_builder_.SetFragmentsTotalBlockSize(all_fragments_block_size);
  container_builder_.SetIsFieldsetContainer();

  if (InvolvedInBlockFragmentation(container_builder_)) [[unlikely]] {
    BreakStatus status = FinishFragmentation(&container_builder_);
    if (status == BreakStatus::kNeedsEarlierBreak) {
      // If we found a good break somewhere inside this block, re-layout and
      // break at that location.
      return RelayoutAndBreakEarlier<FieldsetLayoutAlgorithm>(
          container_builder_.GetEarlyBreak());
    } else if (status == BreakStatus::kDisableFragmentation) {
      return RelayoutWithoutFragmentation<FieldsetLayoutAlgorithm>();
    }
    DCHECK_EQ(status, BreakStatus::kContinue);
  } else {
#if DCHECK_IS_ON()
    // If we're not participating in a fragmentation context, no block
    // fragmentation related fields should have been set.
    container_builder_.CheckNoBlockFragmentation();
#endif
  }

  container_builder_.HandleOofsAndSpecialDescendants();

  const auto& style = Style();
  if (style.LogicalHeight().MayHavePercentDependence() ||
      style.LogicalMinHeight().MayHavePercentDependence() ||
      style.LogicalMaxHeight().MayHavePercentDependence()) {
    // The height of the fieldset content box depends on the percent-height of
    // the fieldset. So we should assume the fieldset has a percent-height
    // descendant.
    container_builder_.SetHasDescendantThatDependsOnPercentageBlockSize();
  }

  return container_builder_.ToBoxFragment();
}

BreakStatus FieldsetLayoutAlgorithm::LayoutChildren() {
  const BlockBreakToken* content_break_token = nullptr;
  bool has_seen_all_children = false;
  if (const auto* token = GetBreakToken()) {
    const auto child_tokens = token->ChildBreakTokens();
    if (base::checked_cast<wtf_size_t>(child_tokens.size())) {
      const BlockBreakToken* child_token =
          To<BlockBreakToken>(child_tokens[0].Get());
      if (child_token) {
        DCHECK(!child_token->InputNode().IsRenderedLegend());
        content_break_token = child_token;
      }
      // There shouldn't be any additional break tokens.
      DCHECK_EQ(child_tokens.size(), 1u);
    }
    if (token->HasSeenAllChildren()) {
      container_builder_.SetHasSeenAllChildren();
      has_seen_all_children = true;
    }
  }

  LogicalSize adjusted_padding_box_size =
      ShrinkLogicalSize(border_box_size_, Borders());

  BlockNode legend = Node().GetRenderedLegend();
  if (legend) {
    if (!IsBreakInside(GetBreakToken())) {
      LayoutLegend(legend);
    }
    LayoutUnit legend_size_contribution;
    if (IsBreakInside(GetBreakToken())) {
      const auto* token_data =
          To<FieldsetBreakTokenData>(GetBreakToken()->TokenData());
      legend_size_contribution = token_data->legend_block_size_contribution;
    } else {
      // We're at the first fragment. The current layout position
      // (intrinsic_block_size_) is at the outer block-end edge of the legend
      // or just after the block-start border, whichever is larger.
      legend_size_contribution = intrinsic_block_size_ - Borders().block_start;
    }

    if (InvolvedInBlockFragmentation(container_builder_)) {
      auto* token_data =
          To<FieldsetBreakTokenData>(container_builder_.GetBreakTokenData());
      token_data->legend_block_size_contribution = legend_size_contribution;
    }

    if (adjusted_padding_box_size.block_size != kIndefiniteSize) {
      DCHECK_NE(border_box_size_.block_size, kIndefiniteSize);
      adjusted_padding_box_size.block_size = std::max(
          adjusted_padding_box_size.block_size - legend_size_contribution,
          Padding().BlockSum());
    }

    // The legend may eat from the available content box block size. Calculate
    // the minimum block size needed to encompass the legend.
    if (!Node().ShouldApplyBlockSizeContainment()) {
      minimum_border_box_block_size_ =
          BorderPadding().BlockSum() + legend_size_contribution;
    }
  }

  // Proceed with normal fieldset children (excluding the rendered legend). They
  // all live inside an anonymous child box of the fieldset container.
  if (content_break_token || !has_seen_all_children) {
    BlockNode fieldset_content = Node().GetFieldsetContent();
    DCHECK(fieldset_content);
    BreakStatus break_status =
        LayoutFieldsetContent(fieldset_content, content_break_token,
                              adjusted_padding_box_size, !!legend);
    if (break_status == BreakStatus::kNeedsEarlierBreak) {
      return break_status;
    }
  }

  return BreakStatus::kContinue;
}

void FieldsetLayoutAlgorithm::LayoutLegend(BlockNode& legend) {
  // Lay out the legend. While the fieldset container normally ignores its
  // padding, the legend is laid out within what would have been the content
  // box had the fieldset been a regular block with no weirdness.
  LogicalSize percentage_size = CalculateChildPercentageSize(
      GetConstraintSpace(), Node(), ChildAvailableSize());
  BoxStrut legend_margins =
      ComputeMarginsFor(legend.Style(), percentage_size.inline_size,
                        GetConstraintSpace().GetWritingDirection());

  auto legend_space = CreateConstraintSpaceForLegend(
      legend, ChildAvailableSize(), percentage_size);
  const LayoutResult* result = legend.Layout(legend_space, GetBreakToken());

  // Legends are monolithic, so abortions are not expected.
  DCHECK_EQ(result->Status(), LayoutResult::kSuccess);

  const auto& physical_fragment = result->GetPhysicalFragment();

  LayoutUnit legend_border_box_block_size =
      LogicalFragment(writing_direction_, physical_fragment).BlockSize();
  LayoutUnit legend_margin_box_block_size = legend_margins.block_start +
                                            legend_border_box_block_size +
                                            legend_margins.block_end;

  LayoutUnit space_left = Borders().block_start - legend_border_box_block_size;
  LayoutUnit block_offset;
  if (space_left > LayoutUnit()) {
    // https://html.spec.whatwg.org/C/#the-fieldset-and-legend-elements
    // * The element is expected to be positioned in the block-flow direction
    //   such that its border box is centered over the border on the
    //   block-start side of the fieldset element.
    block_offset += space_left / 2;
  }
  // If the border is smaller than the block end offset of the legend margin
  // box, intrinsic_block_size_ should now be based on the the block end
  // offset of the legend margin box instead of the border.
  LayoutUnit legend_margin_end_offset =
      block_offset + legend_margin_box_block_size - legend_margins.block_start;
  if (legend_margin_end_offset > Borders().block_start)
    intrinsic_block_size_ = legend_margin_end_offset;

  // If the margin box of the legend is at least as tall as the fieldset
  // block-start border width, it will start at the block-start border edge
  // of the fieldset. As a paint effect, the block-start border will be
  // pushed so that the center of the border will be flush with the center
  // of the border-box of the legend.

  LayoutUnit legend_border_box_inline_size =
      LogicalFragment(writing_direction_, result->GetPhysicalFragment())
          .InlineSize();

  // Padding is mostly ignored for the fieldset container, but rather set on the
  // anonymous fieldset content wrapper child (which is reflected in the
  // BorderScrollbarPadding() of the builders). However, legends should honor
  // it. Scrollbars should never occur at the inline-start, so no need to add
  // that.
  LayoutUnit legend_inline_start =
      Borders().inline_start + Scrollbar().inline_start +
      Padding().inline_start + legend_margins.inline_start;

  const LayoutUnit available_space =
      ChildAvailableSize().inline_size - legend_border_box_inline_size;
  if (available_space > LayoutUnit()) {
    auto alignment = ComputeLegendBlockAlignment(legend.Style(), Style());
    if (alignment == LegendBlockAlignment::kCenter)
      legend_inline_start += available_space / 2;
    else if (alignment == LegendBlockAlignment::kEnd)
      legend_inline_start += available_space - legend_margins.inline_end;
  }

  LogicalOffset legend_offset = {legend_inline_start, block_offset};

  container_builder_.AddResult(*result, legend_offset);
}

BreakStatus FieldsetLayoutAlgorithm::LayoutFieldsetContent(
    BlockNode& fieldset_content,
    const BlockBreakToken* content_break_token,
    LogicalSize adjusted_padding_box_size,
    bool has_legend) {
  const EarlyBreak* early_break_in_child = nullptr;
  if (early_break_) [[unlikely]] {
    if (IsEarlyBreakTarget(*early_break_, container_builder_,
                           fieldset_content)) {
      container_builder_.AddBreakBeforeChild(fieldset_content,
                                             kBreakAppealPerfect,
                                             /* is_forced_break */ false);
      ConsumeRemainingFragmentainerSpace();
      return BreakStatus::kContinue;
    } else {
      early_break_in_child =
          EnterEarlyBreakInChild(fieldset_content, *early_break_);
    }
  }

  const LayoutResult* result = nullptr;
  bool is_past_end = GetBreakToken() && GetBreakToken()->IsAtBlockEnd();

  LayoutUnit max_content_block_size = LayoutUnit::Max();
  if (adjusted_padding_box_size.block_size == kIndefiniteSize) {
    max_content_block_size = ResolveInitialMaxBlockLength(
        GetConstraintSpace(), Style(), BorderPadding(),
        Style().LogicalMaxHeight());
  }

  // If we are past the block-end and had previously laid out the content with a
  // block-size limitation, skip the normal layout call and apply the block-size
  // limitation for all future fragments.
  if (!is_past_end || max_content_block_size == LayoutUnit::Max()) {
    auto child_space = CreateConstraintSpaceForFieldsetContent(
        fieldset_content, adjusted_padding_box_size, intrinsic_block_size_);
    result = fieldset_content.Layout(child_space, content_break_token,
                                     early_break_in_child);
  }

  // If the following conditions meet, the content should be laid out with
  // a block-size limitation:
  // - The FIELDSET block-size is indefinite.
  // - It has max-block-size.
  // - The intrinsic block-size of the content is larger than the
  //   max-block-size.
  if (max_content_block_size != LayoutUnit::Max() &&
      (!result || result->Status() == LayoutResult::kSuccess)) {
    DCHECK_EQ(adjusted_padding_box_size.block_size, kIndefiniteSize);
    if (max_content_block_size > Padding().BlockSum()) {
      // intrinsic_block_size_ is
      // max(Borders().block_start, legend margin box block size).
      max_content_block_size =
          std::max(max_content_block_size -
                       (intrinsic_block_size_ + Borders().block_end),
                   Padding().BlockSum());
    }

    if (result) {
      const auto& fragment = result->GetPhysicalFragment();
      LayoutUnit total_block_size =
          LogicalFragment(writing_direction_, fragment).BlockSize();
      if (content_break_token)
        total_block_size += content_break_token->ConsumedBlockSize();
      if (total_block_size >= max_content_block_size)
        result = nullptr;
    } else {
      DCHECK(is_past_end);
    }

    if (!result) {
      adjusted_padding_box_size.block_size = max_content_block_size;
      auto adjusted_child_space = CreateConstraintSpaceForFieldsetContent(
          fieldset_content, adjusted_padding_box_size, intrinsic_block_size_);
      result = fieldset_content.Layout(
          adjusted_child_space, content_break_token, early_break_in_child);
    }
  }
  DCHECK(result);

  BreakStatus break_status = BreakStatus::kContinue;
  if (GetConstraintSpace().HasBlockFragmentation() && !early_break_) {
    break_status = BreakBeforeChildIfNeeded(
        fieldset_content, *result,
        FragmentainerOffsetForChildren() + intrinsic_block_size_,
        /*has_container_separation=*/false);
  }

  if (break_status == BreakStatus::kContinue) {
    DCHECK_EQ(result->Status(), LayoutResult::kSuccess);
    LogicalOffset offset(Borders().inline_start, intrinsic_block_size_);
    container_builder_.AddResult(*result, offset);

    const auto& fragment =
        To<PhysicalBoxFragment>(result->GetPhysicalFragment());
    if (auto first_baseline = fragment.FirstBaseline()) {
      container_builder_.SetFirstBaseline(offset.block_offset +
                                          *first_baseline);
    }
    if (auto last_baseline = fragment.LastBaseline())
      container_builder_.SetLastBaseline(offset.block_offset + *last_baseline);
    if (fragment.UseLastBaselineForInlineBaseline())
      container_builder_.SetUseLastBaselineForInlineBaseline();

    intrinsic_block_size_ +=
        LogicalFragment(writing_direction_, fragment).BlockSize();
    container_builder_.SetHasSeenAllChildren();
  } else if (break_status == BreakStatus::kBrokeBefore) {
    ConsumeRemainingFragmentainerSpace();
  }

  return break_status;
}

LayoutUnit FieldsetLayoutAlgorithm::FragmentainerSpaceAvailable() const {
  // The legend may have extended past the end of the fragmentainer. Clamp to
  // zero if this is the case.
  return std::max(LayoutUnit(),
                  FragmentainerSpaceLeftForChildren() - intrinsic_block_size_);
}

void FieldsetLayoutAlgorithm::ConsumeRemainingFragmentainerSpace() {
  if (GetConstraintSpace().HasKnownFragmentainerBlockSize()) {
    // The remaining part of the fragmentainer (the unusable space for child
    // content, due to the break) should still be occupied by this container.
    intrinsic_block_size_ += FragmentainerSpaceAvailable();
  }
}

MinMaxSizesResult FieldsetLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  MinMaxSizesResult result;

  bool has_inline_size_containment = Node().ShouldApplyInlineSizeContainment();
  if (has_inline_size_containment) {
    // Size containment does not consider the legend for sizing.
    //
    // Add borders, scrollbar and padding separately, since padding for most
    // purposes are ignored on fieldset containers, and are therefore not
    // included in BorderScrollbarPadding().
    std::optional<MinMaxSizesResult> result_without_children =
        CalculateMinMaxSizesIgnoringChildren(
            Node(), Borders() + Scrollbar() + Padding());
    if (result_without_children)
      return *result_without_children;
  } else {
    if (BlockNode legend = Node().GetRenderedLegend()) {
      MinMaxConstraintSpaceBuilder builder(GetConstraintSpace(), Style(),
                                           legend,
                                           /* is_new_fc */ true);
      builder.SetAvailableBlockSize(kIndefiniteSize);
      const auto space = builder.ToConstraintSpace();

      result = ComputeMinAndMaxContentContribution(Style(), legend, space);
      result.sizes +=
          ComputeMarginsFor(space, legend.Style(), GetConstraintSpace())
              .InlineSum();
    }
  }

  // The fieldset content includes the fieldset padding (and any scrollbars),
  // while the legend is a regular child and doesn't. We may have a fieldset
  // without any content or legend, so add the padding here, on the outside.
  result.sizes += ComputePadding(GetConstraintSpace(), Style()).InlineSum();

  // Size containment does not consider the content for sizing.
  if (!has_inline_size_containment) {
    BlockNode content = Node().GetFieldsetContent();
    DCHECK(content);
    MinMaxConstraintSpaceBuilder builder(GetConstraintSpace(), Style(), content,
                                         /* is_new_fc */ true);
    builder.SetAvailableBlockSize(kIndefiniteSize);
    const auto space = builder.ToConstraintSpace();

    MinMaxSizesResult content_result =
        ComputeMinAndMaxContentContribution(Style(), content, space);
    content_result.sizes +=
        ComputeMarginsFor(space, content.Style(), GetConstraintSpace())
            .InlineSum();
    result.sizes.Encompass(content_result.sizes);
    result.depends_on_block_constraints |=
        content_result.depends_on_block_constraints;
  }

  result.sizes += ComputeBorders(GetConstraintSpace(), Node()).InlineSum();
  return result;
}

const ConstraintSpace FieldsetLayoutAlgorithm::CreateConstraintSpaceForLegend(
    BlockNode legend,
    LogicalSize available_size,
    LogicalSize percentage_size) {
  ConstraintSpaceBuilder builder(GetConstraintSpace(),
                                 legend.Style().GetWritingDirection(),
                                 /* is_new_fc */ true);
  SetOrthogonalFallbackInlineSizeIfNeeded(Style(), legend, &builder);

  builder.SetAvailableSize(available_size);
  builder.SetPercentageResolutionSize(percentage_size);
  return builder.ToConstraintSpace();
}

const ConstraintSpace
FieldsetLayoutAlgorithm::CreateConstraintSpaceForFieldsetContent(
    BlockNode fieldset_content,
    LogicalSize padding_box_size,
    LayoutUnit block_offset) {
  DCHECK(fieldset_content.CreatesNewFormattingContext());
  ConstraintSpaceBuilder builder(GetConstraintSpace(),
                                 fieldset_content.Style().GetWritingDirection(),
                                 /* is_new_fc */ true);
  builder.SetAvailableSize(padding_box_size);
  builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
  // We pass the container's PercentageResolutionSize because percentage
  // padding for the fieldset content should be computed as they are in
  // the container.
  //
  // https://html.spec.whatwg.org/C/#anonymous-fieldset-content-box
  // > * For the purpose of calculating percentage padding, act as if the
  // >   padding was calculated for the fieldset element.
  builder.SetPercentageResolutionSize(
      GetConstraintSpace().PercentageResolutionSize());
  builder.SetIsFixedBlockSize(padding_box_size.block_size != kIndefiniteSize);
  builder.SetBaselineAlgorithmType(
      GetConstraintSpace().GetBaselineAlgorithmType());

  if (GetConstraintSpace().HasBlockFragmentation()) {
    SetupSpaceBuilderForFragmentation(container_builder_, fieldset_content,
                                      block_offset, &builder);
  }
  return builder.ToConstraintSpace();
}

}  // namespace blink

"""

```