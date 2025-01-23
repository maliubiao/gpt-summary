Response:
My thought process for analyzing the provided C++ code snippet went something like this:

1. **Identify the Core Purpose:** The filename `absolute_utils.cc` immediately suggests the file deals with utilities related to absolutely positioned elements in the Blink rendering engine. The initial `#include` statements reinforce this by including layout-related headers like `block_node.h`, `box_fragment_builder.h`, and style-related headers like `computed_style.h`.

2. **Scan for Key Concepts:** I looked for recurring terms and function names. "IMCB" (Inset Modified Containing Block), "static position," "alignment," "insets," and "margins" appear frequently, pointing towards the core functionalities.

3. **Deconstruct the `Compute...` Functions:**  I focused on the function names starting with `Compute`. These functions likely encapsulate the primary logic:
    * `ComputeUnclampedIMCBInOneAxis`:  This seems to handle calculating the IMCB along a single axis, considering available space, insets, static position, and alignment. The "Unclamped" part suggests it's an intermediate step.
    * `ComputeUnclampedIMCB`: This function calls `ComputeUnclampedIMCBInOneAxis` for both inline and block axes, indicating it calculates the complete unclamped IMCB.
    * `ComputeMargins`: This function deals with resolving the final margin values, considering auto margins and the available space within the IMCB.
    * `ComputeInsets`: This function calculates the final insets (distances from the containing block's edges), taking into account margins, alignment, and potentially anchor points.
    * `ComputeOutOfFlowInsets`: This seems to calculate the initial out-of-flow insets based on CSS properties like `top`, `right`, `bottom`, and `left`.
    * `ComputeAlignment`: This function determines the alignment properties based on CSS styles like `align-self` and `justify-self`.
    * `ComputeAnchorCenterPosition`: This handles the specific case of `anchor-center`, calculating its position.
    * `ComputeInsetModifiedContainingBlock`: This function likely brings together the unclamped IMCB calculation and applies clamping (ensuring the size isn't negative or exceeds the container size).
    * `ComputeIMCBForPositionFallback`: This seems to be a variation for fallback scenarios.
    * `ComputeOofInlineDimensions`: This calculates the inline (horizontal) dimensions of an out-of-flow element, considering constraints, margins, and insets.
    * `ComputeOofBlockDimensions`: This (partially shown) calculates the block (vertical) dimensions of an out-of-flow element.

4. **Identify Relationships to CSS, HTML, and JavaScript:**
    * **CSS:** The functions directly relate to CSS properties that control the layout of absolutely positioned elements: `top`, `right`, `bottom`, `left`, `margin`, `align-self`, `justify-self`, `position: absolute`, `anchor-center`. The code manipulates these properties to determine the final position and size.
    * **HTML:** While the code itself doesn't directly parse HTML, it operates on the *results* of HTML parsing (the DOM tree represented by `BlockNode`). The styles applied to HTML elements drive the calculations in this code.
    * **JavaScript:** JavaScript can dynamically modify the CSS styles of elements. Changes made by JavaScript that affect the positioning properties will trigger re-calculations using the logic within this file.

5. **Look for Logic and Assumptions:** The code uses conditional logic ( `if`, `switch`) based on different CSS property values and layout states. It makes assumptions about the input data (e.g., `available_size` is often not indefinite). The use of `DCHECK` suggests internal consistency checks.

6. **Consider Potential Errors:** I thought about common mistakes developers might make when working with absolutely positioned elements, such as:
    * Forgetting to set a containing block with `position: relative` or similar.
    * Conflicting positioning properties (e.g., setting both `left` and `right`).
    * Incorrectly assuming how `auto` margins behave.
    * Not understanding the impact of writing modes and direction.

7. **Synthesize a Summary:** Based on the analysis, I could then formulate a summary focusing on the core function of calculating the position and size of absolutely positioned elements, the key factors involved (IMCB, static position, alignment, insets, margins), and the relationship to web technologies. I also included the aspects of logical reasoning and potential user errors.

8. **Address the "Part 1" Constraint:** Knowing this was part 1, I focused on the core mechanics and avoided delving deeply into the specifics of the block dimension calculation (since it was cut off). I aimed for a general overview of the file's primary responsibilities.
这是 Chromium Blink 引擎源代码文件 `absolute_utils.cc` 的第一部分。根据其内容，我们可以归纳出它的主要功能是：

**核心功能：计算绝对定位元素的布局属性**

这个文件包含了一系列工具函数，用于计算绝对定位（`position: absolute` 或 `position: fixed`）元素的最终位置和尺寸。这些计算考虑了多种因素，包括：

* **包含块（Containing Block）:** 绝对定位元素的定位参考对象。
* **插入修改的包含块 (Inset Modified Containing Block - IMCB):**  根据 `top`, `right`, `bottom`, `left` 属性以及对齐方式调整后的包含块。
* **静态位置（Static Position）:**  如果绝对定位元素没有指定定位属性，或者某些定位属性为 `auto` 时，会参考其在正常流中的位置。
* **偏移量 (Offsets):** `top`, `right`, `bottom`, `left` 属性指定的偏移量。
* **外边距 (Margins):**  绝对定位元素的外边距，可以设置为 `auto` 以实现居中等效果。
* **对齐 (Alignment):**  `align-self` 和 `justify-self` 属性控制元素在其包含块内的对齐方式。
* **书写模式和方向 (Writing Mode and Direction):**  影响逻辑属性（如 `inline-start` 和 `block-start`）到物理属性（如 `top` 和 `left`）的转换。
* **锚点中心 (Anchor Center):** `anchor-center` 属性允许指定一个锚点，元素会以该点为中心进行定位。

**与 JavaScript, HTML, CSS 的关系：**

这个文件中的代码直接实现了 CSS 中关于绝对定位元素布局的规范。

* **CSS:**
    * **`position: absolute` / `position: fixed`:**  这个文件处理的就是这些定位属性的元素的布局计算。
    * **`top`, `right`, `bottom`, `left`:**  `ComputeOutOfFlowInsets` 函数就直接处理这些属性的值，将其转换为逻辑偏移量。
    * **`margin-top`, `margin-right`, `margin-bottom`, `margin-left` (以及逻辑属性 `margin-inline-start`, `margin-inline-end`, `margin-block-start`, `margin-block-end`):** `ComputeMargins` 函数负责解析和计算外边距，特别是处理 `auto` 值的情况。
    * **`align-self`, `justify-self`:** `ComputeAlignment` 函数根据这些属性的值来确定元素的对齐方式，影响 IMCB 的计算。
    * **`writing-mode`, `direction`:** 这些属性影响了逻辑属性到物理属性的转换，在整个计算过程中都被考虑在内。例如，`GetAlignmentInsetBias` 函数就考虑了书写方向。
    * **`anchor-center`:** `ComputeAnchorCenterPosition` 函数专门处理 `anchor-center` 属性，计算锚点的位置。

* **HTML:**
    * 虽然这个文件本身不直接解析 HTML，但它操作的是由 HTML 结构构建的 DOM 树中的元素 (`BlockNode`)。绝对定位的 HTML 元素的最终布局是由这里面的代码决定的。

* **JavaScript:**
    * JavaScript 可以动态地修改元素的 CSS 样式，包括定位属性和对齐属性等。当 JavaScript 修改了这些属性后，Blink 渲染引擎会重新运行布局计算，而 `absolute_utils.cc` 中的函数就会被调用来计算元素的新位置。

**逻辑推理示例 (假设输入与输出):**

假设有一个 `div` 元素，其 CSS 样式如下：

```css
.absolute-box {
  position: absolute;
  top: 10px;
  left: 20px;
  width: 100px;
  height: 50px;
}
```

并且它的包含块的尺寸是 300px x 200px。

* **假设输入:**
    * `available_size`:  `LogicalSize(300px, 200px)` (包含块的尺寸)
    * `insets`: `LogicalOofInsets(Length(10px), std::nullopt, Length(20px), std::nullopt)` (对应 `top: 10px`, `left: 20px`)
    * `static_position`:  假设为默认值
    * 其他样式属性也会被传递进来

* **逻辑推理 (Simplified):** `ComputeUnclampedIMCBInOneAxis` 和相关的函数会根据 `top` 和 `left` 的值，以及包含块的尺寸，计算出 IMCB 的起始位置。 由于 `right` 和 `bottom` 为 `auto`，并且没有指定对齐方式，IMCB 的尺寸会基于 `top` 和 `left` 展开。

* **假设输出 (部分):**
    * `imcb.block_start`: `10px`
    * `imcb.inline_start`: `20px`

**用户或编程常见的使用错误示例：**

1. **忘记设置包含块的 `position` 属性:** 如果绝对定位元素的父元素没有设置 `position: relative`, `absolute` 或 `fixed`，那么该绝对定位元素会相对于初始包含块（通常是 `<html>` 元素）进行定位，这可能不是用户期望的结果。

   ```html
   <div style="/* position: relative; 缺少这一行 */">
     <div style="position: absolute; top: 10px; left: 20px;">This is absolute</div>
   </div>
   ```

2. **同时设置冲突的定位属性:** 同时设置 `left` 和 `right`，或者 `top` 和 `bottom`，并且它们的总和与包含块的尺寸不匹配，可能会导致布局的混乱或者 `auto` 值的解析不符合预期。

   ```css
   .absolute-box {
     position: absolute;
     left: 10px;
     right: 20px; /* 可能会导致宽度计算上的困惑 */
     width: auto;
   }
   ```

**功能归纳 (基于第一部分):**

`absolute_utils.cc` 的第一部分主要负责计算绝对定位元素的 **插入修改的包含块 (IMCB)** 和初步的 **偏移量 (Insets)**。它涵盖了处理基本的定位属性 (`top`, `right`, `bottom`, `left`)，并开始考虑对齐属性 (`align-self`, `justify-self`) 和书写模式对布局的影响。 这一部分的核心是确定绝对定位元素在其包含块内的可用空间和起始位置，为后续计算元素的最终尺寸和精确定位打下基础。它也处理了 `anchor-center` 属性的初步计算。

### 提示词
```
这是目录为blink/renderer/core/layout/absolute_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/absolute_utils.h"

#include <algorithm>

#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/static_position.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"

namespace blink {

namespace {

using InsetBias = InsetModifiedContainingBlock::InsetBias;

inline InsetBias GetStaticPositionInsetBias(
    LogicalStaticPosition::InlineEdge inline_edge) {
  switch (inline_edge) {
    case LogicalStaticPosition::InlineEdge::kInlineStart:
      return InsetBias::kStart;
    case LogicalStaticPosition::InlineEdge::kInlineCenter:
      return InsetBias::kEqual;
    case LogicalStaticPosition::InlineEdge::kInlineEnd:
      return InsetBias::kEnd;
  }
}

inline InsetBias GetStaticPositionInsetBias(
    LogicalStaticPosition::BlockEdge block_edge) {
  switch (block_edge) {
    case LogicalStaticPosition::BlockEdge::kBlockStart:
      return InsetBias::kStart;
    case LogicalStaticPosition::BlockEdge::kBlockCenter:
      return InsetBias::kEqual;
    case LogicalStaticPosition::BlockEdge::kBlockEnd:
      return InsetBias::kEnd;
  }
}

InsetBias GetAlignmentInsetBias(
    const StyleSelfAlignmentData& alignment,
    WritingDirectionMode container_writing_direction,
    WritingDirectionMode self_writing_direction,
    bool is_justify_axis,
    std::optional<InsetBias>* out_safe_inset_bias,
    std::optional<InsetBias>* out_default_inset_bias) {
  // `alignment` is in the writing-direction of the containing-block, vs. the
  // inset-bias which is relative to the writing-direction of the candidate.
  const LogicalToLogical bias(
      self_writing_direction, container_writing_direction, InsetBias::kStart,
      InsetBias::kEnd, InsetBias::kStart, InsetBias::kEnd);

  if (alignment.Overflow() == OverflowAlignment::kSafe) {
    *out_safe_inset_bias =
        is_justify_axis ? bias.InlineStart() : bias.BlockStart();
  }
  if (alignment.Overflow() == OverflowAlignment::kDefault &&
      alignment.GetPosition() != ItemPosition::kNormal) {
    *out_default_inset_bias =
        is_justify_axis ? bias.InlineStart() : bias.BlockStart();
  }

  switch (alignment.GetPosition()) {
    case ItemPosition::kStart:
    case ItemPosition::kFlexStart:
    case ItemPosition::kBaseline:
    case ItemPosition::kStretch:
    case ItemPosition::kNormal:
      return is_justify_axis ? bias.InlineStart() : bias.BlockStart();
    case ItemPosition::kAnchorCenter:
    case ItemPosition::kCenter:
      return InsetBias::kEqual;
    case ItemPosition::kEnd:
    case ItemPosition::kFlexEnd:
    case ItemPosition::kLastBaseline:
      return is_justify_axis ? bias.InlineEnd() : bias.BlockEnd();
    case ItemPosition::kSelfStart:
      return InsetBias::kStart;
    case ItemPosition::kSelfEnd:
      return InsetBias::kEnd;
    case ItemPosition::kLeft:
      DCHECK(is_justify_axis);
      return container_writing_direction.IsLtr() ? bias.InlineStart()
                                                 : bias.InlineEnd();
    case ItemPosition::kRight:
      DCHECK(is_justify_axis);
      return container_writing_direction.IsRtl() ? bias.InlineStart()
                                                 : bias.InlineEnd();
    case ItemPosition::kLegacy:
    case ItemPosition::kAuto:
      NOTREACHED();
  }
}

void ResizeIMCBInOneAxis(const InsetBias inset_bias,
                         const LayoutUnit amount,
                         LayoutUnit* inset_start,
                         LayoutUnit* inset_end) {
  switch (inset_bias) {
    case InsetBias::kStart:
      *inset_end += amount;
      break;
    case InsetBias::kEnd:
      *inset_start += amount;
      break;
    case InsetBias::kEqual:
      *inset_start += amount / 2;
      *inset_end += amount / 2;
      break;
  }
}

// Computes the inset modified containing block in one axis, accounting for
// insets and the static-position.
void ComputeUnclampedIMCBInOneAxis(
    const LayoutUnit available_size,
    const std::optional<LayoutUnit>& inset_start,
    const std::optional<LayoutUnit>& inset_end,
    const LayoutUnit static_position_offset,
    InsetBias static_position_inset_bias,
    InsetBias alignment_inset_bias,
    const std::optional<InsetBias>& safe_inset_bias,
    const std::optional<InsetBias>& default_inset_bias,
    LayoutUnit* imcb_start_out,
    LayoutUnit* imcb_end_out,
    InsetBias* imcb_inset_bias_out,
    std::optional<InsetBias>* safe_inset_bias_out,
    std::optional<InsetBias>* default_inset_bias_out) {
  DCHECK_NE(available_size, kIndefiniteSize);
  if (!inset_start && !inset_end) {
    // If both our insets are auto, the available-space is defined by the
    // static-position.
    switch (static_position_inset_bias) {
      case InsetBias::kStart:
        // The available-space for the start static-position "grows" towards the
        // end edge.
        // |      *----------->|
        *imcb_start_out = static_position_offset;
        *imcb_end_out = LayoutUnit();
        break;
      case InsetBias::kEqual: {
        // The available-space for the center static-position "grows" towards
        // both edges (equally), and stops when it hits the first one.
        // |<-----*----->      |
        const LayoutUnit half_size = std::min(
            static_position_offset, available_size - static_position_offset);
        *imcb_start_out = static_position_offset - half_size;
        *imcb_end_out = available_size - static_position_offset - half_size;
        break;
      }
      case InsetBias::kEnd:
        // The available-space for the end static-position "grows" towards the
        // start edge.
        // |<-----*            |
        *imcb_end_out = available_size - static_position_offset;
        *imcb_start_out = LayoutUnit();
        break;
    }
    *imcb_inset_bias_out = static_position_inset_bias;
  } else {
    // Otherwise we just resolve auto to 0.
    *imcb_start_out = inset_start.value_or(LayoutUnit());
    *imcb_end_out = inset_end.value_or(LayoutUnit());

    if (!inset_start.has_value() || !inset_end.has_value()) {
      // In the case that only one inset is auto, that is the weaker inset;
      *imcb_inset_bias_out =
          inset_start.has_value() ? InsetBias::kStart : InsetBias::kEnd;
    } else {
      // Both insets were set - use the alignment bias (defaults to the "start"
      // edge of the containing block if we have normal alignment).
      *imcb_inset_bias_out = alignment_inset_bias;
      *safe_inset_bias_out = safe_inset_bias;
      *default_inset_bias_out = default_inset_bias;
    }
  }
}

InsetModifiedContainingBlock ComputeUnclampedIMCB(
    const LogicalSize& available_size,
    const LogicalAlignment& alignment,
    const LogicalOofInsets& insets,
    const LogicalStaticPosition& static_position,
    const ComputedStyle& style,
    WritingDirectionMode container_writing_direction,
    WritingDirectionMode self_writing_direction) {
  InsetModifiedContainingBlock imcb;
  imcb.available_size = available_size;
  imcb.has_auto_inline_inset = !insets.inline_start || !insets.inline_end;
  imcb.has_auto_block_inset = !insets.block_start || !insets.block_end;

  const bool is_parallel =
      IsParallelWritingMode(container_writing_direction.GetWritingMode(),
                            self_writing_direction.GetWritingMode());

  std::optional<InsetBias> inline_safe_inset_bias;
  std::optional<InsetBias> inline_default_inset_bias;
  const auto inline_alignment_inset_bias = GetAlignmentInsetBias(
      alignment.inline_alignment, container_writing_direction,
      self_writing_direction,
      /* is_justify_axis */ is_parallel, &inline_safe_inset_bias,
      &inline_default_inset_bias);
  std::optional<InsetBias> block_safe_inset_bias;
  std::optional<InsetBias> block_default_inset_bias;
  const auto block_alignment_inset_bias =
      GetAlignmentInsetBias(alignment.block_alignment,
                            container_writing_direction, self_writing_direction,
                            /* is_justify_axis */ !is_parallel,
                            &block_safe_inset_bias, &block_default_inset_bias);

  ComputeUnclampedIMCBInOneAxis(
      available_size.inline_size, insets.inline_start, insets.inline_end,
      static_position.offset.inline_offset,
      GetStaticPositionInsetBias(static_position.inline_edge),
      inline_alignment_inset_bias, inline_safe_inset_bias,
      inline_default_inset_bias, &imcb.inline_start, &imcb.inline_end,
      &imcb.inline_inset_bias, &imcb.inline_safe_inset_bias,
      &imcb.inline_default_inset_bias);
  ComputeUnclampedIMCBInOneAxis(
      available_size.block_size, insets.block_start, insets.block_end,
      static_position.offset.block_offset,
      GetStaticPositionInsetBias(static_position.block_edge),
      block_alignment_inset_bias, block_safe_inset_bias,
      block_default_inset_bias, &imcb.block_start, &imcb.block_end,
      &imcb.block_inset_bias, &imcb.block_safe_inset_bias,
      &imcb.block_default_inset_bias);
  return imcb;
}

// Absolutize margin values to pixels and resolve any auto margins.
// https://drafts.csswg.org/css-position-3/#abspos-margins
bool ComputeMargins(LogicalSize margin_percentage_resolution_size,
                    const LayoutUnit imcb_size,
                    const Length& margin_start_length,
                    const Length& margin_end_length,
                    const LayoutUnit size,
                    bool has_auto_inset,
                    bool is_start_dominant,
                    bool is_block_direction,
                    LayoutUnit* margin_start_out,
                    LayoutUnit* margin_end_out) {
  std::optional<LayoutUnit> margin_start;
  if (!margin_start_length.IsAuto()) {
    margin_start = MinimumValueForLength(
        margin_start_length, margin_percentage_resolution_size.inline_size);
  }
  std::optional<LayoutUnit> margin_end;
  if (!margin_end_length.IsAuto()) {
    margin_end = MinimumValueForLength(
        margin_end_length, margin_percentage_resolution_size.inline_size);
  }

  const bool apply_auto_margins =
      !has_auto_inset && (!margin_start || !margin_end);

  // Solving the equation:
  // |margin_start| + |size| + |margin_end| = |imcb_size|
  if (apply_auto_margins) {
    // "If left, right, and width are not auto:"
    // Compute margins.
    const LayoutUnit free_space = imcb_size - size -
                                  margin_start.value_or(LayoutUnit()) -
                                  margin_end.value_or(LayoutUnit());

    if (!margin_start && !margin_end) {
      // When both margins are auto.
      if (free_space > LayoutUnit() || is_block_direction) {
        margin_start = free_space / 2;
        margin_end = free_space - *margin_start;
      } else {
        // Margins are negative.
        if (is_start_dominant) {
          margin_start = LayoutUnit();
          margin_end = free_space;
        } else {
          margin_start = free_space;
          margin_end = LayoutUnit();
        }
      }
    } else if (!margin_start) {
      margin_start = free_space;
    } else if (!margin_end) {
      margin_end = free_space;
    }
  }

  // Set any unknown margins, auto margins with any auto inset resolve to zero.
  *margin_start_out = margin_start.value_or(LayoutUnit());
  *margin_end_out = margin_end.value_or(LayoutUnit());

  return apply_auto_margins;
}

// Align the margin box within the inset-modified containing block as defined by
// its self-alignment properties.
// https://drafts.csswg.org/css-position-3/#abspos-layout
void ComputeInsets(const LayoutUnit available_size,
                   const LayoutUnit container_start,
                   const LayoutUnit container_end,
                   const LayoutUnit original_imcb_start,
                   const LayoutUnit original_imcb_end,
                   const InsetBias imcb_inset_bias,
                   const std::optional<InsetBias>& safe_inset_bias,
                   const std::optional<InsetBias>& default_inset_bias,
                   const LayoutUnit margin_start,
                   const LayoutUnit margin_end,
                   const LayoutUnit size,
                   const std::optional<LayoutUnit>& anchor_center_offset,
                   LayoutUnit* inset_start_out,
                   LayoutUnit* inset_end_out) {
  DCHECK_NE(available_size, kIndefiniteSize);

  LayoutUnit imcb_start = original_imcb_start;
  LayoutUnit imcb_end = original_imcb_end;

  // First if we have a valid anchor-center position, adjust the offsets so
  // that it is centered on that point.
  //
  // At this stage it doesn't matter what the resulting free-space is, just
  // that if we have safe alignment, we bias towards the safe inset.
  if (anchor_center_offset) {
    const LayoutUnit half_size =
        (safe_inset_bias.value_or(InsetBias::kStart) == InsetBias::kStart)
            ? *anchor_center_offset - imcb_start
            : available_size - *anchor_center_offset - imcb_end;
    imcb_start = *anchor_center_offset - half_size;
    imcb_end = available_size - *anchor_center_offset - half_size;
  }

  // Determine the free-space. If we have safe alignment specified, e.g.
  // "justify-self: safe start", clamp the free-space to zero and bias towards
  // the safe edge (may be end if RTL for example).
  LayoutUnit free_space =
      available_size - imcb_start - imcb_end - margin_start - size - margin_end;
  InsetBias bias = imcb_inset_bias;
  bool apply_safe_bias = safe_inset_bias && free_space < LayoutUnit();
  if (apply_safe_bias) {
    free_space = LayoutUnit();
    bias = *safe_inset_bias;
  }

  // Move the weaker inset edge to consume all the free space, so that:
  // `imcb_start` + `margin_start` + `size` + `margin_end` + `imcb_end` =
  // `available_size`
  ResizeIMCBInOneAxis(bias, free_space, &imcb_start, &imcb_end);

  // Finally consider the default alignment overflow behavior if applicable.
  // This only applies when both insets are specified, and we have non-normal
  // alignment.
  //
  // This will take the element, and shift it to be within the bounds of the
  // containing-block. It will prioritize the edge specified by
  // `default_inset_bias`.
  if (default_inset_bias && !apply_safe_bias) {
    // If the insets shifted the IMCB outside the containing-block, we consider
    // that to be the safe edge.
    auto adjust_start = [&]() {
      const LayoutUnit safe_start =
          std::min(original_imcb_start, -container_start);
      if (imcb_start < safe_start) {
        imcb_end += (imcb_start - safe_start);
        imcb_start = safe_start;
      }
    };
    auto adjust_end = [&]() {
      const LayoutUnit safe_end = std::min(original_imcb_end, -container_end);
      if (imcb_end < safe_end) {
        imcb_start += (imcb_end - safe_end);
        imcb_end = safe_end;
      }
    };
    if (*default_inset_bias == InsetBias::kStart) {
      adjust_end();
      adjust_start();
    } else {
      adjust_start();
      adjust_end();
    }
  }

  *inset_start_out = imcb_start + margin_start;
  *inset_end_out = imcb_end + margin_end;
}

bool CanComputeBlockSizeWithoutLayout(
    const BlockNode& node,
    WritingDirectionMode container_writing_direction,
    ItemPosition block_alignment_position,
    bool has_auto_block_inset,
    bool has_inline_size) {
  // Tables (even with an explicit size) apply a min-content constraint.
  if (node.IsTable()) {
    return false;
  }
  // Replaced elements always have their size computed ahead of time.
  if (node.IsReplaced()) {
    return true;
  }
  const auto& style = node.Style();
  if (style.LogicalHeight().HasContentOrIntrinsic() ||
      style.LogicalMinHeight().HasContentOrIntrinsic() ||
      style.LogicalMaxHeight().HasContentOrIntrinsic()) {
    return false;
  }
  if (style.LogicalHeight().HasAuto()) {
    // Any 'auto' inset will trigger fit-content.
    if (has_auto_block_inset) {
      return false;
    }
    // Check for an explicit stretch.
    if (block_alignment_position == ItemPosition::kStretch) {
      return true;
    }
    // Non-normal alignment will trigger fit-content.
    if (block_alignment_position != ItemPosition::kNormal) {
      return false;
    }
    // An aspect-ratio (with a definite inline-size) will trigger fit-content.
    if (!style.AspectRatio().IsAuto() && has_inline_size) {
      return false;
    }
  }
  return true;
}

}  // namespace

LogicalOofInsets ComputeOutOfFlowInsets(
    const ComputedStyle& style,
    const LogicalSize& available_logical_size,
    const LogicalAlignment& alignment,
    WritingDirectionMode self_writing_direction) {
  bool force_x_insets_to_zero = false;
  bool force_y_insets_to_zero = false;
  std::optional<PositionAreaOffsets> offsets = style.PositionAreaOffsets();
  if (offsets.has_value()) {
    force_x_insets_to_zero = force_y_insets_to_zero = true;
  }
  if (alignment.inline_alignment.GetPosition() == ItemPosition::kAnchorCenter) {
    if (self_writing_direction.IsHorizontal()) {
      force_x_insets_to_zero = true;
    } else {
      force_y_insets_to_zero = true;
    }
  }
  if (alignment.block_alignment.GetPosition() == ItemPosition::kAnchorCenter) {
    if (self_writing_direction.IsHorizontal()) {
      force_y_insets_to_zero = true;
    } else {
      force_x_insets_to_zero = true;
    }
  }

  // Compute in physical, because anchors may be in different `writing-mode` or
  // `direction`.
  const PhysicalSize available_size = ToPhysicalSize(
      available_logical_size, self_writing_direction.GetWritingMode());
  std::optional<LayoutUnit> left;
  if (const Length& left_length = style.Left(); !left_length.IsAuto()) {
    left = MinimumValueForLength(left_length, available_size.width);
  } else if (force_x_insets_to_zero) {
    left = LayoutUnit();
  }
  std::optional<LayoutUnit> right;
  if (const Length& right_length = style.Right(); !right_length.IsAuto()) {
    right = MinimumValueForLength(right_length, available_size.width);
  } else if (force_x_insets_to_zero) {
    right = LayoutUnit();
  }

  std::optional<LayoutUnit> top;
  if (const Length& top_length = style.Top(); !top_length.IsAuto()) {
    top = MinimumValueForLength(top_length, available_size.height);
  } else if (force_y_insets_to_zero) {
    top = LayoutUnit();
  }
  std::optional<LayoutUnit> bottom;
  if (const Length& bottom_length = style.Bottom(); !bottom_length.IsAuto()) {
    bottom = MinimumValueForLength(bottom_length, available_size.height);
  } else if (force_y_insets_to_zero) {
    bottom = LayoutUnit();
  }

  // Convert the physical insets to logical.
  PhysicalToLogical<std::optional<LayoutUnit>&> insets(
      self_writing_direction, top, right, bottom, left);
  return {insets.InlineStart(), insets.InlineEnd(), insets.BlockStart(),
          insets.BlockEnd()};
}

LogicalAlignment ComputeAlignment(
    const ComputedStyle& style,
    bool is_containing_block_scrollable,
    WritingDirectionMode container_writing_direction,
    WritingDirectionMode self_writing_direction) {
  StyleSelfAlignmentData align_normal_behavior(ItemPosition::kNormal,
                                               OverflowAlignment::kDefault);
  StyleSelfAlignmentData justify_normal_behavior(ItemPosition::kNormal,
                                                 OverflowAlignment::kDefault);
  const PositionArea position_area = style.GetPositionArea().ToPhysical(
      container_writing_direction, self_writing_direction);
  if (!position_area.IsNone()) {
    std::tie(align_normal_behavior, justify_normal_behavior) =
        position_area.AlignJustifySelfFromPhysical(
            container_writing_direction, is_containing_block_scrollable);
  }
  const bool is_parallel =
      IsParallelWritingMode(container_writing_direction.GetWritingMode(),
                            self_writing_direction.GetWritingMode());
  return is_parallel
             ? LogicalAlignment{style.ResolvedJustifySelf(
                                    justify_normal_behavior),
                                style.ResolvedAlignSelf(align_normal_behavior)}
             : LogicalAlignment{
                   style.ResolvedAlignSelf(align_normal_behavior),
                   style.ResolvedJustifySelf(justify_normal_behavior)};
}

LogicalAnchorCenterPosition ComputeAnchorCenterPosition(
    const ComputedStyle& style,
    const LogicalAlignment& alignment,
    WritingDirectionMode writing_direction,
    LogicalSize available_logical_size) {
  // Compute in physical, because anchors may be in different writing-mode.
  const ItemPosition inline_position = alignment.inline_alignment.GetPosition();
  const ItemPosition block_position = alignment.block_alignment.GetPosition();

  const bool has_anchor_center_in_x =
      writing_direction.IsHorizontal()
          ? inline_position == ItemPosition::kAnchorCenter
          : block_position == ItemPosition::kAnchorCenter;
  const bool has_anchor_center_in_y =
      writing_direction.IsHorizontal()
          ? block_position == ItemPosition::kAnchorCenter
          : inline_position == ItemPosition::kAnchorCenter;

  const PhysicalSize available_size = ToPhysicalSize(
      available_logical_size, writing_direction.GetWritingMode());
  std::optional<LayoutUnit> left;
  std::optional<LayoutUnit> top;
  std::optional<LayoutUnit> right;
  std::optional<LayoutUnit> bottom;
  if (style.AnchorCenterOffset().has_value()) {
    if (has_anchor_center_in_x) {
      left = style.AnchorCenterOffset()->left;
      if (left) {
        right = available_size.width - *left;
      }
    }
    if (has_anchor_center_in_y) {
      top = style.AnchorCenterOffset()->top;
      if (top) {
        bottom = available_size.height - *top;
      }
    }
  }

  // Convert result back to logical against `writing_direction`.
  PhysicalToLogical converter(writing_direction, top, right, bottom, left);
  return LogicalAnchorCenterPosition{converter.InlineStart(),
                                     converter.BlockStart()};
}

InsetModifiedContainingBlock ComputeInsetModifiedContainingBlock(
    const BlockNode& node,
    const LogicalSize& available_size,
    const LogicalAlignment& alignment,
    const LogicalOofInsets& insets,
    const LogicalStaticPosition& static_position,
    WritingDirectionMode container_writing_direction,
    WritingDirectionMode self_writing_direction) {
  InsetModifiedContainingBlock imcb = ComputeUnclampedIMCB(
      available_size, alignment, insets, static_position, node.Style(),
      container_writing_direction, self_writing_direction);
  // Clamp any negative size to 0.
  if (imcb.InlineSize() < LayoutUnit()) {
    ResizeIMCBInOneAxis(imcb.inline_inset_bias, imcb.InlineSize(),
                        &imcb.inline_start, &imcb.inline_end);
  }
  if (imcb.BlockSize() < LayoutUnit()) {
    ResizeIMCBInOneAxis(imcb.block_inset_bias, imcb.BlockSize(),
                        &imcb.block_start, &imcb.block_end);
  }
  if (node.IsTable()) {
    // Tables should not be larger than the container.
    if (imcb.InlineSize() > available_size.inline_size) {
      ResizeIMCBInOneAxis(imcb.inline_inset_bias,
                          imcb.InlineSize() - available_size.inline_size,
                          &imcb.inline_start, &imcb.inline_end);
    }
    if (imcb.BlockSize() > available_size.block_size) {
      ResizeIMCBInOneAxis(imcb.block_inset_bias,
                          imcb.BlockSize() - available_size.block_size,
                          &imcb.block_start, &imcb.block_end);
    }
  }
  return imcb;
}

InsetModifiedContainingBlock ComputeIMCBForPositionFallback(
    const LogicalSize& available_size,
    const LogicalAlignment& alignment,
    const LogicalOofInsets& insets,
    const LogicalStaticPosition& static_position,
    const ComputedStyle& style,
    WritingDirectionMode container_writing_direction,
    WritingDirectionMode self_writing_direction) {
  return ComputeUnclampedIMCB(
      available_size, alignment, insets, static_position, style,
      container_writing_direction, self_writing_direction);
}

bool ComputeOofInlineDimensions(
    const BlockNode& node,
    const ComputedStyle& style,
    const ConstraintSpace& space,
    const InsetModifiedContainingBlock& imcb,
    const LogicalAnchorCenterPosition& anchor_center_position,
    const LogicalAlignment& alignment,
    const BoxStrut& border_padding,
    const std::optional<LogicalSize>& replaced_size,
    const BoxStrut& container_insets,
    WritingDirectionMode container_writing_direction,
    LogicalOofDimensions* dimensions) {
  DCHECK(dimensions);
  DCHECK_GE(imcb.InlineSize(), LayoutUnit());

  const auto alignment_position = alignment.inline_alignment.GetPosition();
  const auto block_alignment_position = alignment.block_alignment.GetPosition();

  bool depends_on_min_max_sizes = false;
  const bool can_compute_block_size_without_layout =
      CanComputeBlockSizeWithoutLayout(node, container_writing_direction,
                                       block_alignment_position,
                                       imcb.has_auto_block_inset,
                                       /* has_inline_size */ false);

  auto MinMaxSizesFunc = [&](SizeType type) -> MinMaxSizesResult {
    DCHECK(!node.IsReplaced());

    // Mark the inline calculations as being dependent on min/max sizes.
    depends_on_min_max_sizes = true;

    // If we can't compute our block-size without layout, we can use the
    // provided space to determine our min/max sizes.
    if (!can_compute_block_size_without_layout)
      return node.ComputeMinMaxSizes(style.GetWritingMode(), type, space);

    // Compute our block-size if we haven't already.
    if (dimensions->size.block_size == kIndefiniteSize) {
      ComputeOofBlockDimensions(
          node, style, space, imcb, anchor_center_position, alignment,
          border_padding,
          /* replaced_size */ std::nullopt, container_insets,
          container_writing_direction, dimensions);
    }

    // Create a new space, setting the fixed block-size.
    ConstraintSpaceBuilder builder(style.GetWritingMode(),
                                   style.GetWritingDirection(),
                                   /* is_new_fc */ true);
    builder.SetAvailableSize(
        {space.AvailableSize().inline_size, dimensions->size.block_size});
    builder.SetIsFixedBlockSize(true);
    builder.SetPercentageResolutionSize(space.PercentageResolutionSize());
    return node.ComputeMinMaxSizes(style.GetWritingMode(), type,
                                   builder.ToConstraintSpace());
  };

  LayoutUnit inline_size;
  if (replaced_size) {
    DCHECK(node.IsReplaced());
    inline_size = replaced_size->inline_size;
  } else {
    const Length& main_inline_length = style.LogicalWidth();

    const bool is_implicit_stretch =
        !imcb.has_auto_inline_inset &&
        alignment_position == ItemPosition::kNormal;
    const bool is_explicit_stretch =
        !imcb.has_auto_inline_inset &&
        alignment_position == ItemPosition::kStretch;
    const bool is_stretch = is_implicit_stretch || is_explicit_stretch;

    // If our block constraint is strong/explicit.
    const bool is_block_explicit =
        !style.LogicalHeight().HasAuto() ||
        (!imcb.has_auto_block_inset &&
         block_alignment_position == ItemPosition::kStretch);

    // Determine how "auto" should resolve.
    bool apply_automatic_min_size = false;
    const Length& auto_length = ([&]() {
      // Tables always shrink-to-fit unless explicitly asked to stretch.
      if (node.IsTable()) {
        return is_explicit_stretch ? Length::Stretch() : Length::FitContent();
      }
      // We'd like to apply the aspect-ratio.
      // The aspect-ratio applies from the block-axis if we can compute our
      // block-size without invoking layout, and either:
      //  - We aren't stretching our auto inline-size.
      //  - We are stretching our auto inline-size, but the block-size has a
      //    stronger (explicit) constraint, e.g:
      //    "height:10px" or "align-self:stretch".
      if (!style.AspectRatio().IsAuto() &&
          can_compute_block_size_without_layout &&
          (!is_stretch || (is_implicit_stretch && is_block_explicit))) {
        // See if we should apply the automatic minimum size.
        if (style.OverflowInlineDirection() == EOverflow::kVisible) {
          apply_automatic_min_size = true;
        }
        return Length::FitContent();
      }
      return is_stretch ? Length::Stretch() : Length::FitContent();
    })();

    const LayoutUnit main_inline_size = ResolveMainInlineLength(
        space, style, border_padding, MinMaxSizesFunc, main_inline_length,
        &auto_length, imcb.InlineSize());
    const MinMaxSizes min_max_inline_sizes = ComputeMinMaxInlineSizes(
        space, node, border_padding,
        apply_automatic_min_size ? &Length::MinIntrinsic() : nullptr,
        MinMaxSizesFunc, TransferredSizesMode::kNormal, imcb.InlineSize());

    inline_size = min_max_inline_sizes.ClampSizeToMinAndMax(main_inline_size);
  }

  dimensions->size.inline_size = inline_size;

  // Determines if the "start" sides of margins match.
  const bool is_margin_start_dominant =
      LogicalToLogical(container_writing_direction, style.GetWritingDirection(),
                       /* inline_start */ true, /* inline_end */ false,
                       /* block_start */ true, /* block_end */ false)
          .InlineStart();

  // Determines if this is the block axis in the containing block.
  const bool is_block_direction = !IsParallelWritingMode(
      container_writing_direction.GetWritingMode(), style.GetWritingMode());

  const bool applied_auto_margins = ComputeMargins(
      space.MarginPaddingPercentageResolutionSize(), imcb.InlineSize(),
      style.MarginInlineStart(), style.MarginInlineEnd(), inline_size,
      imcb.has_auto_inline_inset, is_margin_start_dominant, is_block_direction,
      &dimensions->margins.inline_start, &dimensions->margins.inline_end);

  if (applied_auto_margins) {
    dimensions->inset.inline_start =
        imcb.inline_start + dimensions->margins.inline_start;
    dimensions->inset.inline_end =
        imcb.inline_end + dimensions->margins.inline_end;
  } else {
    ComputeInsets(
        space.AvailableSize().inline_size, container_insets.inline_start,
        container_insets.inline_end, imcb.inline_start, imcb.inline_end,
        imcb.inline_inset_bias, imcb.inline_safe_inset_bias,
        imcb.inline_default_inset_bias, dimensions->margins.inline_start,
        dimensions->margins.inline_end, inline_size,
        anchor_center_position.inline_offset, &dimensions->inset.inline_start,
        &dimensions->inset.inline_end);
  }

  return depends_on_min_max_sizes;
}

const LayoutResult* ComputeOofBlockDimensions(
    const BlockNode& node,
    const ComputedStyle& style,
    const ConstraintSpace& space,
    const InsetModifiedContainingBlock& imcb,
    const LogicalAnchorCenterPosition& anchor_center_position,
    const LogicalAlignment& alignment,
    const BoxStrut& border_padding,
    const std::optional<LogicalSize>& replaced_size,
    const BoxStrut& container_insets,
    WritingDirectionMode container_writing_direction,
    LogicalOofDimensions* dimensions) {
  DCHECK(dimensions);
  DCHECK_GE(imcb.BlockSize(), LayoutUnit());

  const auto alignment_position = alignment.block_alignment.GetPosition();

  const LayoutResult* result = nullptr;
  LayoutUnit block_size;
  if (replaced_size) {
    DCHECK(node.IsReplaced());
    block_size = replaced_size->block_size;
  } else if (CanComputeBlockSizeWithoutLayout(
                 node, container_writing_direction, alignment_position,
                 imcb.has_auto_block_inset,
                 /* has_inline_size */ dimensions->size.inline_size !=
                     kIndefiniteSize)) {
    DCHECK(!node.IsTable());

    // Nothing depends on our intrinsic-size, so we can safely use the initial
    // variant of these functions.
    const LayoutUnit main_block_size = ResolveMainBlockLength(
        space, style, border_padding, style.LogicalHeight(), &Length::Stretch(),
        kIndefiniteSize, imcb.BlockSize());
    const MinMaxSizes min_max_block
```