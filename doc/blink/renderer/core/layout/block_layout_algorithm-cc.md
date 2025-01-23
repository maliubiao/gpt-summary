Response:
The user wants me to analyze the provided C++ source code file, which is part of the Chromium Blink rendering engine. The file is `block_layout_algorithm.cc` and is responsible for the block layout algorithm.

Here's a plan to address the request:

1. **Identify the core function:** The filename clearly indicates the file implements the block layout algorithm.
2. **List key responsibilities based on included headers and code snippets:**  Look for hints about specific tasks like handling floats, clears, margins, line breaking, multi-column layout, and interactions with inline elements.
3. **Relate to web technologies:** Explain how the algorithm's functions directly impact the rendering of HTML, CSS, and indirectly, JavaScript interactions.
4. **Provide concrete examples:** Illustrate the connection to HTML/CSS with simple examples and predict how the algorithm would behave.
5. **Discuss potential errors:** Identify common mistakes developers might make that this algorithm needs to handle.
6. **Summarize the functionality:**  Condense the findings into a concise summary for Part 1 of the request.
这是对 `blink/renderer/core/layout/block_layout_algorithm.cc` 文件功能的归纳总结（第 1 部分）：

**主要功能归纳:**

`block_layout_algorithm.cc` 文件的核心功能是实现了 **块级盒子的布局算法**。 它负责确定块级盒子（例如 `<div>`, `<p>`, `<h1>` 等）及其子元素的尺寸和位置。  这个算法是浏览器渲染引擎中至关重要的一部分，因为它直接影响着网页内容的最终呈现方式。

**详细功能点 (基于提供的代码片段):**

1. **处理块级子元素的布局:**  该算法遍历块级容器的子元素，并递归地调用布局算法来确定每个子元素的大小和位置。 它考虑了子元素是块级还是内联。

2. **处理内联子元素的布局:** 当遇到内联子元素时，该算法会使用 `InlineNode` 对象进行布局，这涉及构建行盒 (line boxes) 并处理文本的换行等。

3. **处理浮动元素 (Floats):** 算法需要考虑浮动元素对周围内容的影响，包括如何为非浮动内容腾出空间，以及如何处理 `clear` 属性。

4. **处理 `clear` 属性:**  `clear` 属性用于控制元素是否可以与之前的浮动元素相邻。该算法会根据 `clear` 的值调整元素的起始位置，确保它出现在浮动元素的下方或两侧。

5. **计算最小和最大尺寸:**  `ComputeMinMaxSizes` 函数用于计算块级盒子在不同情况下的最小和最大内容尺寸，这对于处理弹性布局、自动布局等至关重要。

6. **处理外边距 (Margins):** 算法需要计算和应用元素的 margin，包括处理外边距折叠 (margin collapsing) 的情况。

7. **处理多列布局 (Multi-column Layout):**  代码中提到了 `LayoutMultiColumnFlowThread`，表明该算法也参与处理多列布局，确保内容正确地分布在各个列中。

8. **处理列表标记 (List Markers):**  对于列表项，算法会处理列表标记 (`<li>` 的圆点或数字) 的布局。

9. **处理文本框裁剪 (`text-box-trim`):**  新引入的 `text-box-trim` CSS 属性允许裁剪文本框周围的空白。该算法包含了处理这一特性的逻辑。

10. **处理换行 (Breaks):**  算法需要决定在何处进行换行，尤其是在分页或多列布局中。 它使用 `BreakToken` 和 `EarlyBreak` 等概念来管理换行信息。

11. **处理约束空间 (Constraint Space):** 布局算法在一个约束空间中工作，这个空间定义了可用的尺寸和其他限制。算法需要根据约束空间来布局元素。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `block_layout_algorithm.cc` 负责渲染 HTML 结构中定义的块级元素。 例如，当你创建一个 `<div>` 元素时，这个算法会决定它在页面上的位置和大小。
    ```html
    <div>这是一个块级元素</div>
    ```

* **CSS:** CSS 样式规则直接影响块级布局算法的行为。 例如：
    * **`width` 和 `height`:**  CSS 的 `width` 和 `height` 属性直接决定了块级盒子的尺寸，算法会根据这些值进行布局。
        ```css
        .box {
          width: 200px;
          height: 100px;
        }
        ```
    * **`margin`:** CSS 的 `margin` 属性定义了元素周围的空白，算法在布局时会考虑这些外边距。
        ```css
        .box {
          margin: 10px;
        }
        ```
    * **`float`:** CSS 的 `float` 属性会让元素浮动到一侧，算法会处理浮动元素周围内容的环绕。
        ```css
        .float-left {
          float: left;
        }
        ```
    * **`clear`:** CSS 的 `clear` 属性控制元素是否可以与浮动元素相邻，算法会根据 `clear` 的值进行调整。
        ```css
        .clear-both {
          clear: both;
        }
        ```
    * **`text-align`:**  CSS 的 `text-align` 属性（尤其是 `-webkit-` 前缀的）会影响块级容器内内联内容的对齐方式，算法中 `WebkitTextAlignAndJustifySelfOffset` 函数处理了这种情况。
        ```css
        .container {
          text-align: -webkit-center;
        }
        ```
    * **`columns`:** CSS 的 `columns` 属性用于创建多列布局，算法中的相关逻辑会处理元素的分布。
        ```css
        .multicolumn {
          columns: 3;
        }
        ```
    * **`text-box-trim`:** CSS 的 `text-box-trim` 属性直接触发了算法中 `should_text_box_trim_node_start_` 和 `should_text_box_trim_node_end_` 等标志的设置和逻辑执行。
        ```css
        .trimmed {
          text-box-trim: end;
        }
        ```

* **JavaScript:** JavaScript 可以动态修改 HTML 结构和 CSS 样式。 当 JavaScript 更改了影响布局的属性时，会触发浏览器的重排 (reflow)，从而导致 `block_layout_algorithm.cc` 中的代码重新执行。例如，通过 JavaScript 改变一个元素的 `width` 或 `display` 属性。
    ```javascript
    document.querySelector('.box').style.width = '300px';
    ```

**逻辑推理的假设输入与输出:**

**假设输入:**

* 一个 `<div>` 元素，包含一个 `<p>` 子元素和一个 `<span>` 子元素。
* CSS 样式如下:
    ```css
    .container { width: 500px; }
    p { margin-bottom: 20px; }
    span { float: left; width: 100px; height: 50px; background-color: lightblue; }
    ```

**预期输出 (部分):**

* `<div>` 元素的宽度将被设置为 500px。
* `<span>` 元素将浮动到左侧，宽度 100px，高度 50px，背景色为浅蓝色。
* `<p>` 元素会出现在 `<span>` 元素的下方，因为 `<span>` 元素是浮动的。
* `<p>` 元素的底部外边距为 20px，会在其下方产生额外的空间。

**用户或编程常见的使用错误举例:**

1. **忘记清除浮动:**  如果一个容器内部包含浮动元素，但没有采取措施（例如使用 `overflow: auto` 或 clearfix 技术）来清除浮动，可能会导致容器的高度塌陷，这不是 `block_layout_algorithm.cc` 的错误，而是 CSS 使用不当。

2. **过度依赖绝对定位:**  过度使用 `position: absolute` 可能会导致元素脱离正常的文档流，使得布局难以预测和维护。`block_layout_algorithm.cc` 主要处理文档流内的布局。

3. **对块级和内联元素的理解偏差:**  不理解块级元素和内联元素之间的差异，例如块级元素默认占据一行，可能导致布局上的困惑。

4. **不理解外边距折叠:**  在某些情况下，相邻块级元素的垂直外边距会发生折叠，只保留较大的外边距值。不理解这一机制可能导致布局上的意外。

5. **`text-box-trim` 使用不当:**  错误地预期 `text-box-trim` 在所有情况下都能移除所有空白，而忽略了其在分段上下文中的限制，或者忘记了 `box-decoration-break: clone` 会影响其行为。

**总结:**

`block_layout_algorithm.cc` 是 Chromium Blink 引擎中负责块级元素布局的核心组件。它解析 CSS 样式，处理各种布局相关的属性（如尺寸、外边距、浮动、清除等），并确定块级盒子及其子元素在页面上的最终位置和大小。它的功能直接关联到 HTML 结构的渲染和 CSS 样式的应用，是网页呈现的关键环节。

### 提示词
```
这是目录为blink/renderer/core/layout/block_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/block_layout_algorithm.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <utility>

#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/layout/block_child_iterator.h"
#include "third_party/blink/renderer/core/layout/block_layout_algorithm_utils.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/column_spanner_path.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/early_break.h"
#include "third_party/blink/renderer/core/layout/floats_utils.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/inline/ruby_utils.h"
#include "third_party/blink/renderer/core/layout/layout_multi_column_flow_thread.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/legacy_layout_tree_walking.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/list/unpositioned_list_marker.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/positioned_float.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/table/table_layout_utils.h"
#include "third_party/blink/renderer/core/layout/unpositioned_float.h"
#include "third_party/blink/renderer/core/mathml/mathml_element.h"
#include "third_party/blink/renderer/core/mathml/mathml_table_cell_element.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {
namespace {

bool HasLineEvenIfEmpty(LayoutBox* box) {
  // Note: We should reduce calling |LayoutBlock::HasLineIfEmpty()|, because
  // it calls slow function |IsRootEditableElement()|.
  LayoutBlockFlow* const block_flow = DynamicTo<LayoutBlockFlow>(box);
  if (!block_flow)
    return false;
  // Note: |block_flow->NeedsCollectInline()| is true after removing all
  // children from block[1].
  // [1] editing/inserting/insert_after_delete.html
  if (!GetLayoutObjectForFirstChildNode(block_flow)) {
    // Note: |block_flow->ChildrenInline()| can be both true or false:
    //  - true: just after construction, <div></div>
    //  - true: one of child is inline them remove all, <div>abc</div>
    //  - false: all children are block then remove all, <div><p></p></div>
    return block_flow->HasLineIfEmpty();
  }
  if (AreNGBlockFlowChildrenInline(block_flow)) {
    return block_flow->HasLineIfEmpty() &&
           InlineNode(block_flow).IsBlockLevel();
  }
  if (const auto* const flow_thread = block_flow->MultiColumnFlowThread()) {
    DCHECK(!flow_thread->ChildrenInline());
    for (const auto* child = flow_thread->FirstChild(); child;
         child = child->NextSibling()) {
      if (child->IsInline()) {
        // Note: |LayoutOutsideListMarker| is out-of-flow for the tree
        // building purpose in |LayoutBlockFlow::AddChild()|.
        // |MultiColumnRenderingTest.ListItem| reaches here.
        DCHECK(child->IsLayoutOutsideListMarker()) << child;
        return false;
      }
      if (!child->IsFloatingOrOutOfFlowPositioned()) {
        // We reach here when we have in-flow child.
        // <div style="columns: 3"><div style="float:left"><div></div></div>
        return false;
      }
    }
    // There are no children or all children are floating or out of flow
    // positioned.
    return block_flow->HasLineIfEmpty();
  }
  return false;
}

inline bool IsLastInflowChild(const LayoutBox& box) {
  for (const LayoutObject* next = box.NextSibling(); next;
       next = next->NextSibling()) {
    if (!next->IsFloatingOrOutOfFlowPositioned()) {
      return false;
    }
  }
  return true;
}

inline const LayoutResult* LayoutBlockChild(
    const ConstraintSpace& space,
    const BreakToken* break_token,
    const EarlyBreak* early_break,
    const ColumnSpannerPath* column_spanner_path,
    BlockNode* node) {
  const EarlyBreak* early_break_in_child = nullptr;
  if (early_break) [[unlikely]] {
    early_break_in_child = EnterEarlyBreakInChild(*node, *early_break);
  }
  column_spanner_path = FollowColumnSpannerPath(column_spanner_path, *node);
  return node->Layout(space, To<BlockBreakToken>(break_token),
                      early_break_in_child, column_spanner_path);
}

inline const LayoutResult* LayoutInflow(
    const ConstraintSpace& space,
    const BreakToken* break_token,
    const EarlyBreak* early_break,
    const ColumnSpannerPath* column_spanner_path,
    LayoutInputNode* node,
    InlineChildLayoutContext* context) {
  if (auto* inline_node = DynamicTo<InlineNode>(node)) {
    return inline_node->Layout(space, break_token, column_spanner_path,
                               context);
  }
  return LayoutBlockChild(space, break_token, early_break, column_spanner_path,
                          To<BlockNode>(node));
}

AdjoiningObjectTypes ToAdjoiningObjectTypes(EClear clear) {
  switch (clear) {
    default:
      NOTREACHED();
    case EClear::kNone:
      return kAdjoiningNone;
    case EClear::kLeft:
      return kAdjoiningFloatLeft;
    case EClear::kRight:
      return kAdjoiningFloatRight;
    case EClear::kBoth:
      return kAdjoiningFloatBoth;
  };
}

// Return true if a child is to be cleared past adjoining floats. These are
// floats that would otherwise (if 'clear' were 'none') be pulled down by the
// BFC block offset of the child. If the child is to clear floats, though, we
// obviously need separate the child from the floats and move it past them,
// since that's what clearance is all about. This means that if we have any such
// floats to clear, we know for sure that we get clearance, even before layout.
inline bool HasClearancePastAdjoiningFloats(
    AdjoiningObjectTypes adjoining_object_types,
    const ComputedStyle& child_style,
    const ComputedStyle& cb_style) {
  return ToAdjoiningObjectTypes(child_style.Clear(cb_style)) &
         adjoining_object_types;
}

// Adjust BFC block offset for clearance, if applicable. Return true of
// clearance was applied.
//
// Clearance applies either when the BFC block offset calculated simply isn't
// past all relevant floats, *or* when we have already determined that we're
// directly preceded by clearance.
//
// The latter is the case when we need to force ourselves past floats that would
// otherwise be adjoining, were it not for the predetermined clearance.
// Clearance inhibits margin collapsing and acts as spacing before the
// block-start margin of the child. It needs to be exactly what takes the
// block-start border edge of the cleared block adjacent to the block-end outer
// edge of the "bottommost" relevant float.
//
// We cannot reliably calculate the actual clearance amount at this point,
// because 1) this block right here may actually be a descendant of the block
// that is to be cleared, and 2) we may not yet have separated the margin before
// and after the clearance. None of this matters, though, because we know where
// to place this block if clearance applies: exactly at the ConstraintSpace's
// ClearanceOffset().
bool ApplyClearance(const ConstraintSpace& constraint_space,
                    LayoutUnit* bfc_block_offset) {
  if (constraint_space.HasClearanceOffset() &&
      *bfc_block_offset < constraint_space.ClearanceOffset()) {
    *bfc_block_offset = constraint_space.ClearanceOffset();
    return true;
  }
  return false;
}

LayoutUnit LogicalFromBfcLineOffset(LayoutUnit child_bfc_line_offset,
                                    LayoutUnit parent_bfc_line_offset,
                                    LayoutUnit child_inline_size,
                                    LayoutUnit parent_inline_size,
                                    TextDirection direction) {
  // We need to respect the current text direction to calculate the logical
  // offset correctly.
  LayoutUnit relative_line_offset =
      child_bfc_line_offset - parent_bfc_line_offset;

  LayoutUnit inline_offset =
      direction == TextDirection::kLtr
          ? relative_line_offset
          : parent_inline_size - relative_line_offset - child_inline_size;

  return inline_offset;
}

LogicalOffset LogicalFromBfcOffsets(const BfcOffset& child_bfc_offset,
                                    const BfcOffset& parent_bfc_offset,
                                    LayoutUnit child_inline_size,
                                    LayoutUnit parent_inline_size,
                                    TextDirection direction) {
  LayoutUnit inline_offset = LogicalFromBfcLineOffset(
      child_bfc_offset.line_offset, parent_bfc_offset.line_offset,
      child_inline_size, parent_inline_size, direction);

  return {inline_offset,
          child_bfc_offset.block_offset - parent_bfc_offset.block_offset};
}

ItemPosition WebkitTextToItemPosition(ETextAlign text_align) {
  switch (text_align) {
    case ETextAlign::kWebkitLeft:
      return ItemPosition::kLeft;
    case ETextAlign::kWebkitCenter:
      return ItemPosition::kCenter;
    case ETextAlign::kWebkitRight:
      return ItemPosition::kRight;
    default:
      // Ignore non -webkit- values.
      return ItemPosition::kNormal;
  }
}

// Handle text-align:-webkit-* and justify-self.
template <typename ChildInlineSizeFunc>
LayoutUnit WebkitTextAlignAndJustifySelfOffset(
    const ComputedStyle& child_style,
    const ComputedStyle& style,
    LayoutUnit available_space,
    const BoxStrut& margins,
    const ChildInlineSizeFunc& child_inline_size_func) {
  DCHECK(!child_style.MarginInlineStartUsing(style).IsAuto());
  DCHECK(!child_style.MarginInlineEndUsing(style).IsAuto());

  const StyleSelfAlignmentData alignment_data = child_style.ResolvedJustifySelf(
      {ItemPosition::kNormal, OverflowAlignment::kDefault}, &style);
  ItemPosition justify_self = alignment_data.GetPosition();
  OverflowAlignment safe = OverflowAlignment::kSafe;
  if (RuntimeEnabledFeatures::LayoutJustifySelfForBlocksEnabled() &&
      justify_self != ItemPosition::kNormal) {
    safe = alignment_data.Overflow();
  } else {
    justify_self = WebkitTextToItemPosition(style.GetTextAlign());
  }
  auto FreeSpace = [&]() -> LayoutUnit {
    const LayoutUnit free_space =
        available_space - child_inline_size_func() - margins.InlineSum();
    return safe == OverflowAlignment::kSafe ? free_space.ClampNegativeToZero()
                                            : free_space;
  };

  auto self_start_end_converter = [&]() -> LogicalToLogical<LayoutUnit> {
    const LayoutUnit free_space = FreeSpace();
    return LogicalToLogical<LayoutUnit>(
        child_style.GetWritingDirection(), style.GetWritingDirection(),
        /* inline_start */ LayoutUnit(), /* inline_end */ free_space,
        /* block_start */ LayoutUnit(), /* block_end */ free_space);
  };

  bool is_rtl = IsRtl(style.Direction());
  switch (justify_self) {
    case ItemPosition::kLeft:
      return is_rtl ? FreeSpace() : LayoutUnit();
    case ItemPosition::kCenter:
      return FreeSpace() / 2;
    case ItemPosition::kRight:
      return is_rtl ? LayoutUnit() : FreeSpace();
    case ItemPosition::kFlexStart:
    case ItemPosition::kStart:
      return LayoutUnit();
    case ItemPosition::kFlexEnd:
    case ItemPosition::kEnd:
      return FreeSpace();
    case ItemPosition::kSelfStart:
      return self_start_end_converter().InlineStart();
    case ItemPosition::kSelfEnd:
      return self_start_end_converter().InlineEnd();
    default:
      return LayoutUnit();
  }
}

}  // namespace

BlockLayoutAlgorithm::BlockLayoutAlgorithm(const LayoutAlgorithmParams& params)
    : LayoutAlgorithm(params),
      previous_result_(params.previous_result),
      column_spanner_path_(params.column_spanner_path),
      line_clamp_data_(params.space.GetLineClampData()),
      fit_all_lines_(false),
      is_resuming_(IsBreakInside(params.break_token)),
      abort_when_bfc_block_offset_updated_(false),
      has_break_opportunity_before_next_child_(false),
      should_text_box_trim_node_start_(
          params.space.ShouldTextBoxTrimNodeStart()),
      should_text_box_trim_node_end_(params.space.ShouldTextBoxTrimNodeEnd()),
      should_text_box_trim_fragmentainer_start_(
          params.space.ShouldTextBoxTrimFragmentainerStart()),
      should_text_box_trim_fragmentainer_end_(
          params.space.ShouldTextBoxTrimFragmentainerEnd()) {
  container_builder_.SetExclusionSpace(params.space.GetExclusionSpace());

  child_percentage_size_ = CalculateChildPercentageSize(
      GetConstraintSpace(), Node(), ChildAvailableSize());
  replaced_child_percentage_size_ = CalculateReplacedChildPercentageSize(
      GetConstraintSpace(), Node(), ChildAvailableSize(),
      BorderScrollbarPadding(), BorderPadding());

  // If |this| is a list item, keep track of the unpositioned list marker in
  // |container_builder_|.
  if (const BlockNode marker_node = Node().ListMarkerBlockNodeIfListItem()) {
    if (ShouldPlaceUnpositionedListMarker() &&
        !marker_node.ListMarkerOccupiesWholeLine() &&
        (!GetBreakToken() || GetBreakToken()->HasUnpositionedListMarker())) {
      container_builder_.SetUnpositionedListMarker(
          UnpositionedListMarker(marker_node));
    }
  }

  // Disable text box trimming if there's intervening border / padding.
  if (should_text_box_trim_node_start_ &&
      BorderPadding().block_start != LayoutUnit()) {
    should_text_box_trim_node_start_ = false;
  }
  if (should_text_box_trim_node_end_ &&
      BorderPadding().block_end != LayoutUnit()) {
    should_text_box_trim_node_end_ = false;
  }

  // Initialize `text-box-trim` flags from the `ComputedStyle`.
  const ComputedStyle& style = Node().Style();
  if (style.TextBoxTrim() != ETextBoxTrim::kNone) [[unlikely]] {
    should_text_box_trim_node_start_ |= style.ShouldTextBoxTrimStart();
    should_text_box_trim_node_end_ |= style.ShouldTextBoxTrimEnd();

    // Unless box-decoration-break is 'clone', box trimming specified inside a
    // fragmentation context will not apply at fragmentainer breaks in that
    // fragmentation context. Additionally, this is always disabled for
    // pagination, since our implementation is not able to paint outside the
    // page area.
    if (!GetConstraintSpace().HasBlockFragmentation() ||
        GetConstraintSpace().IsPaginated()) {
      should_text_box_trim_fragmentainer_start_ = false;
      should_text_box_trim_fragmentainer_end_ = false;
    } else {
      // Should only trim block-start at fragmentainer start if this node is
      // resumed after a break.
      if (IsBreakInside(GetBreakToken())) {
        should_text_box_trim_fragmentainer_start_ |=
            should_text_box_trim_node_start_;
      } else {
        should_text_box_trim_fragmentainer_start_ = false;
      }

      should_text_box_trim_fragmentainer_end_ |= should_text_box_trim_node_end_;

      if (!GetConstraintSpace().IsAnonymous() &&
          style.BoxDecorationBreak() != EBoxDecorationBreak::kClone) {
        should_text_box_trim_fragmentainer_start_ &=
            !style.ShouldTextBoxTrimStart();
        should_text_box_trim_fragmentainer_end_ &=
            !style.ShouldTextBoxTrimEnd();
      }
    }
  }
}

// Define the destructor here, so that we can forward-declare more in the
// header.
BlockLayoutAlgorithm::~BlockLayoutAlgorithm() = default;

void BlockLayoutAlgorithm::SetupRelayoutData(
    const BlockLayoutAlgorithm& previous,
    RelayoutType relayout_type) {
  LayoutAlgorithm::SetupRelayoutData(previous, relayout_type);

  column_spanner_path_ = previous.column_spanner_path_;

  if (relayout_type == kRelayoutIgnoringLineClamp) {
    line_clamp_data_.data.state = LineClampData::kDontTruncate;
  } else if (relayout_type == kRelayoutWithLineClampBlockSize) {
    line_clamp_data_.data.state = LineClampData::kClampByLines;
    line_clamp_data_.data.lines_until_clamp =
        line_clamp_data_.initial_lines_until_clamp =
            previous.line_clamp_data_.data.lines_until_clamp;
  } else if (previous.line_clamp_data_.data.state ==
             LineClampData::kClampByLines) {
    line_clamp_data_.data.state = LineClampData::kClampByLines;
    line_clamp_data_.data.lines_until_clamp =
        line_clamp_data_.initial_lines_until_clamp =
            previous.line_clamp_data_.initial_lines_until_clamp;
  } else if (previous.line_clamp_data_.data.state ==
             LineClampData::kDontTruncate) {
    line_clamp_data_.data.state = LineClampData::kDontTruncate;
  }

  if (relayout_type == kRelayoutForTextBoxTrim) {
    DCHECK(previous.last_non_empty_inflow_child_);
    // If there is at least one non-empty inflow child, re-layout by applying
    // the `text-box-trim: end` to the `last_non_empty_inflow_child_`.
    override_text_box_trim_end_child_ = previous.last_non_empty_inflow_child_;
    override_text_box_trim_end_break_token_ =
        previous.last_non_empty_break_token_;
  } else {
    override_text_box_trim_end_child_ =
        previous.override_text_box_trim_end_child_;
    override_text_box_trim_end_break_token_ =
        previous.override_text_box_trim_end_break_token_;
    should_text_box_trim_node_end_ = previous.should_text_box_trim_node_end_;

    if (relayout_mode_ & kRelayoutForTextBoxTrim) {
      // Text box end trimming was done in a previous relayout pass. Make sure
      // that it's re-applied.
      override_text_box_trim_end_child_ =
          previous.override_text_box_trim_end_child_;
      override_text_box_trim_end_break_token_ =
          previous.override_text_box_trim_end_break_token_;
    }
  }
}

void BlockLayoutAlgorithm::SetBoxType(PhysicalFragment::BoxType type) {
  container_builder_.SetBoxType(type);
}

MinMaxSizesResult BlockLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput& float_input) {
  if (auto result =
          CalculateMinMaxSizesIgnoringChildren(node_, BorderScrollbarPadding()))
    return *result;

  MinMaxSizes sizes;
  bool depends_on_block_constraints = false;

  const TextDirection direction = Style().Direction();
  LayoutUnit float_left_inline_size = float_input.float_left_inline_size;
  LayoutUnit float_right_inline_size = float_input.float_right_inline_size;

  for (LayoutInputNode child = Node().FirstChild(); child;
       child = child.NextSibling()) {
    // We don't check IsRubyText() here intentionally. RubyText width should
    // affect this width.
    if (child.IsOutOfFlowPositioned() ||
        (child.IsColumnSpanAll() && GetConstraintSpace().IsInColumnBfc())) {
      continue;
    }

    if (child.IsTextControlPlaceholder()) {
      if (Style().ApplyControlFixedSize(Node().GetDOMNode())) {
        continue;
      }
    }

    const ComputedStyle& child_style = child.Style();
    const EClear child_clear = child_style.Clear(Style());
    bool child_is_new_fc = child.CreatesNewFormattingContext();

    // Conceptually floats and a single new-FC would just get positioned on a
    // single "line". If there is a float/new-FC with clearance, this creates a
    // new "line", resetting the appropriate float size trackers.
    //
    // Both of the float size trackers get reset for anything that isn't a float
    // (inflow and new-FC) at the end of the loop, as this creates a new "line".
    if (child.IsFloating() || child_is_new_fc) {
      LayoutUnit float_inline_size =
          float_left_inline_size + float_right_inline_size;

      if (child_clear != EClear::kNone)
        sizes.max_size = std::max(sizes.max_size, float_inline_size);

      if (child_clear == EClear::kBoth || child_clear == EClear::kLeft)
        float_left_inline_size = LayoutUnit();

      if (child_clear == EClear::kBoth || child_clear == EClear::kRight)
        float_right_inline_size = LayoutUnit();
    }

    MinMaxSizesFloatInput child_float_input;
    if (child.IsInline() || child.IsAnonymousBlock()) {
      child_float_input.float_left_inline_size = float_left_inline_size;
      child_float_input.float_right_inline_size = float_right_inline_size;
    }

    MinMaxConstraintSpaceBuilder builder(GetConstraintSpace(), Style(), child,
                                         child_is_new_fc);
    builder.SetAvailableBlockSize(ChildAvailableSize().block_size);
    builder.SetPercentageResolutionBlockSize(child_percentage_size_.block_size);
    builder.SetReplacedPercentageResolutionBlockSize(
        replaced_child_percentage_size_.block_size);
    const auto space = builder.ToConstraintSpace();

    MinMaxSizesResult child_result;
    if (child.IsInline()) {
      // From |BlockLayoutAlgorithm| perspective, we can handle |InlineNode|
      // almost the same as |BlockNode|, because an |InlineNode| includes
      // all inline nodes following |child| and their descendants, and produces
      // an anonymous box that contains all line boxes.
      // |NextSibling| returns the next block sibling, or nullptr, skipping all
      // following inline siblings and descendants.
      child_result = To<InlineNode>(child).ComputeMinMaxSizes(
          Style().GetWritingMode(), space, child_float_input);
    } else {
      child_result = ComputeMinAndMaxContentContribution(
          Style(), To<BlockNode>(child), space, child_float_input);
    }
    DCHECK_LE(child_result.sizes.min_size, child_result.sizes.max_size)
        << child.ToString();

    // Determine the max inline contribution of the child.
    BoxStrut margins =
        child.IsInline()
            ? BoxStrut()
            : ComputeMarginsFor(space, child_style, GetConstraintSpace());
    LayoutUnit max_inline_contribution;

    if (child.IsFloating()) {
      // A float adds to its inline size to the current "line". The new max
      // inline contribution is just the sum of all the floats on that "line".
      LayoutUnit float_inline_size =
          child_result.sizes.max_size + margins.InlineSum();

      // float_inline_size is negative when the float is completely outside of
      // the content area, by e.g., negative margins. Such floats do not affect
      // the content size.
      if (float_inline_size > 0) {
        if (child_style.Floating(Style()) == EFloat::kLeft)
          float_left_inline_size += float_inline_size;
        else
          float_right_inline_size += float_inline_size;
      }

      max_inline_contribution =
          float_left_inline_size + float_right_inline_size;
    } else if (child_is_new_fc) {
      // As floats are line relative, we perform the margin calculations in the
      // line relative coordinate system as well.
      LayoutUnit margin_line_left = margins.LineLeft(direction);
      LayoutUnit margin_line_right = margins.LineRight(direction);

      // line_left_inset and line_right_inset are the "distance" from their
      // respective edges of the parent that the new-FC would take. If the
      // margin is positive the inset is just whichever of the floats inline
      // size and margin is larger, and if negative it just subtracts from the
      // float inline size.
      LayoutUnit line_left_inset =
          margin_line_left > LayoutUnit()
              ? std::max(float_left_inline_size, margin_line_left)
              : float_left_inline_size + margin_line_left;

      LayoutUnit line_right_inset =
          margin_line_right > LayoutUnit()
              ? std::max(float_right_inline_size, margin_line_right)
              : float_right_inline_size + margin_line_right;

      // The order of operations is important here.
      // If child_result.sizes.max_size is saturated, adding the insets
      // sequentially can result in an DCHECK.
      max_inline_contribution =
          child_result.sizes.max_size + (line_left_inset + line_right_inset);
    } else {
      // This is just a standard inflow child.
      max_inline_contribution =
          child_result.sizes.max_size + margins.InlineSum();
    }
    sizes.max_size = std::max(sizes.max_size, max_inline_contribution);

    // The min inline contribution just assumes that floats are all on their own
    // "line".
    LayoutUnit min_inline_contribution =
        child_result.sizes.min_size + margins.InlineSum();
    sizes.min_size = std::max(sizes.min_size, min_inline_contribution);

    depends_on_block_constraints |= child_result.depends_on_block_constraints;

    // Anything that isn't a float will create a new "line" resetting the float
    // size trackers.
    if (!child.IsFloating()) {
      float_left_inline_size = LayoutUnit();
      float_right_inline_size = LayoutUnit();
    }
  }

  DCHECK_GE(sizes.min_size, LayoutUnit());
  DCHECK_LE(sizes.min_size, sizes.max_size) << Node().ToString();

  sizes += BorderScrollbarPadding().InlineSum();
  return MinMaxSizesResult(sizes, depends_on_block_constraints);
}

LogicalOffset BlockLayoutAlgorithm::CalculateLogicalOffset(
    const LogicalFragment& fragment,
    LayoutUnit child_bfc_line_offset,
    const std::optional<LayoutUnit>& child_bfc_block_offset) {
  LayoutUnit inline_size = container_builder_.InlineSize();
  TextDirection direction = GetConstraintSpace().Direction();

  if (child_bfc_block_offset && container_builder_.BfcBlockOffset()) {
    return LogicalFromBfcOffsets(
        {child_bfc_line_offset, *child_bfc_block_offset}, ContainerBfcOffset(),
        fragment.InlineSize(), inline_size, direction);
  }

  LayoutUnit inline_offset = LogicalFromBfcLineOffset(
      child_bfc_line_offset, container_builder_.BfcLineOffset(),
      fragment.InlineSize(), inline_size, direction);

  // If we've reached here, either the parent, or the child don't have a BFC
  // block-offset yet. Children in this situation are always placed at a
  // logical block-offset of zero.
  return {inline_offset, LayoutUnit()};
}

const LayoutResult* BlockLayoutAlgorithm::Layout() {
  const LayoutResult* result = nullptr;
  // Inline children require an inline child layout context to be
  // passed between siblings. We want to stack-allocate that one, but
  // only on demand, as it's quite big.
  InlineNode inline_child(nullptr);
  if (Node().IsInlineFormattingContextRoot(&inline_child)) {
    result = LayoutInlineChild(inline_child);
  } else {
    result = Layout(nullptr);
  }

  if (result->Status() == LayoutResult::kSuccess) {
    return result;
  }

  // To reduce stack usage, handle non-successful results in a separate
  // function.
  return HandleNonsuccessfulLayoutResult(result);
}

NOINLINE const LayoutResult*
BlockLayoutAlgorithm::HandleNonsuccessfulLayoutResult(
    const LayoutResult* result) {
  DCHECK_NE(result->Status(), LayoutResult::kSuccess);
  switch (result->Status()) {
    case LayoutResult::kNeedsEarlierBreak: {
      // If we found a good break somewhere inside this block, re-layout and
      // break at that location.
      DCHECK(result->GetEarlyBreak());
      return RelayoutAndBreakEarlier<BlockLayoutAlgorithm>(
          *result->GetEarlyBreak());
    }
    case LayoutResult::kNeedsLineClampRelayout:
      if (line_clamp_data_.data.state == LineClampData::kClampByLines) {
        return RelayoutIgnoringLineClamp();
      }
      if (GetConstraintSpace().IsNewFormattingContext()) {
        return RelayoutWithLineClampBlockSize(result->LinesUntilClamp());
      }
      // Propagate the error upwards until we reach the BFC root.
      return result;
    case LayoutResult::kDisableFragmentation:
      DCHECK(GetConstraintSpace().HasBlockFragmentation());
      return RelayoutWithoutFragmentation<BlockLayoutAlgorithm>();
    case LayoutResult::kTextBoxTrimEndDidNotApply:
      return RelayoutForTextBoxTrimEnd();
    default:
      return result;
  }
}

NOINLINE const LayoutResult* BlockLayoutAlgorithm::LayoutInlineChild(
    const InlineNode& node) {
  const TextWrapStyle wrap = node.Style().GetTextWrapStyle();
  if (wrap == TextWrapStyle::kPretty) [[unlikely]] {
    UseCounter::Count(node.GetDocument(), WebFeature::kTextWrapPretty);
    if (!node.IsScoreLineBreakDisabled()) {
      return LayoutWithOptimalInlineChildLayoutContext<kMaxLinesForOptimal>(
          node);
    }
  } else if (wrap == TextWrapStyle::kBalance) [[unlikely]] {
    UseCounter::Count(node.GetDocument(), WebFeature::kTextWrapBalance);
    if (!node.IsScoreLineBreakDisabled()) {
      return LayoutWithOptimalInlineChildLayoutContext<kMaxLinesForBalance>(
          node);
    }
  } else {
    DCHECK(ShouldWrapLineGreedy(wrap));
  }

  SimpleInlineChildLayoutContext context(node, &container_builder_);
  return Layout(&context);
}

template <wtf_size_t capacity>
NOINLINE const LayoutResult*
BlockLayoutAlgorithm::LayoutWithOptimalInlineChildLayoutContext(
    const InlineNode& child) {
  OptimalInlineChildLayoutContext<capacity> context(child, &container_builder_);
  const LayoutResult* result = Layout(&context);
  return result;
}

NOINLINE const LayoutResult* BlockLayoutAlgorithm::RelayoutIgnoringLineClamp() {
  DCHECK_EQ(line_clamp_data_.data.state, LineClampData::kClampByLines);
  return Relayout<BlockLayoutAlgorithm>(kRelayoutIgnoringLineClamp);
}

NOINLINE const LayoutResult*
BlockLayoutAlgorithm::RelayoutWithLineClampBlockSize(int lines_until_clamp) {
  DCHECK_EQ(line_clamp_data_.data.state,
            LineClampData::kMeasureLinesUntilBfcOffset);
  line_clamp_data_.data.lines_until_clamp = std::max(1, lines_until_clamp);
  return Relayout<BlockLayoutAlgorithm>(kRelayoutWithLineClampBlockSize);
}

NOINLINE const LayoutResult* BlockLayoutAlgorithm::RelayoutForTextBoxTrimEnd() {
  DCHECK(last_non_empty_inflow_child_);
  return Relayout<BlockLayoutAlgorithm>(kRelayoutForTextBoxTrim);
}

inline const LayoutResult* BlockLayoutAlgorithm::Layout(
    InlineChildLayoutContext* inline_child_layout_context) {
  DCHECK_EQ(!!inline_child_layout_context,
            Node().IsInlineFormattingContextRoot());
  container_builder_.SetIsInlineFormattingContext(inline_child_layout_context);

  // If this node has a column spanner inside, we'll force it to stay within the
  // current fragmentation flow, so that it doesn't establish a parallel flow,
  // even if it might have content that overflows into the next fragmentainer.
  // This way we'll prevent content that comes after the spanner from being laid
  // out *before* it.
  if (column_spanner_path_) {
    container_builder_.SetShouldForceSameFragmentationFlow();
  }

  const auto& constraint_space = GetConstraintSpace();
  container_builder_.SetBfcLineOffset(
      constraint_space.GetBfcOffset().line_offset);

  if (auto adjoining_object_types =
          constraint_space.GetAdjoiningObjectTypes()) {
    DCHECK(!constraint_space.IsNewFormattingContext());
    DCHECK(!container_builder_.BfcBlockOffset());

    // If there were preceding adjoining objects, they will be affected when the
    // BFC block-offset gets resolved or updated. We then need to roll back and
    // re-layout those objects with the new BFC block-offset, once the BFC
    // block-offset is updated.
    abort_when_bfc_block_offset_updated_ = true;

    container_builder_.SetAdjoiningObjectTypes(adjoining_object_types);
  } else if (constraint_space.HasBlockFragmentation()) {
    // The offset from the block-start of the fragmentainer is part of the
    // constraint space, so if this offset changes, we need to abort.
    abort_when_bfc_block_offset_updated_ = true;
  }

  if (Style().HasAutoStandardLineClamp()) {
    if (!line_clamp_data_.data.IsLineClampContext()) {
      LayoutUnit clamp_bfc_offset = ChildAvailableSize().block_size;
      if (clamp_bfc_offset == kIndefiniteSize) {
        const MinMaxSizes sizes = ComputeInitialMinMaxBlockSizes(
            constraint_space, Node(), BorderPadding());
        if (sizes.max_size != LayoutUnit::Max()) {
          clamp_bfc_offset =
              (si
```