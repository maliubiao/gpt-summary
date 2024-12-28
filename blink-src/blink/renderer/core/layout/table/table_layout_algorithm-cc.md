Response:
My thinking process to analyze the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for the functionality of the code, its relationship to web technologies (HTML, CSS, JavaScript), potential logic, and common user/programming errors, all within the context of the first part of a three-part file. The crucial final request for summarization is key.

2. **Identify the Core Class:** The filename `table_layout_algorithm.cc` and the repeated use of `TableLayoutAlgorithm` strongly suggest this class is central. The presence of `Layout` and `ComputeMinMaxSizes` methods reinforces this, indicating it's involved in the layout process.

3. **Analyze Includes:** The `#include` directives provide valuable clues about the responsibilities of the class:
    * **Layout-related:**  `BlockBreakToken`, `ConstraintSpaceBuilder`, `LayoutResult`, `LogicalBoxFragment`, `PhysicalBoxFragment`, `SpaceUtils`, etc., clearly point to layout management.
    * **Table-specific:** `LayoutTable`, `LayoutTableCaption`, `LayoutTableCell`, `LayoutTableColumn`, `LayoutTableSection`, `TableBorders`, `TableBreakTokenData`, `TableChildIterator`, `TableConstraintSpaceData`, `TableFragmentData`, `TableLayoutUtils`, `TableNode`, `TableTypes`. This confirms the class deals with the layout of HTML tables.
    * **General Blink/Rendering:**  `ComputedStyle`, `WritingModeConverter`, `TextAutosizer`, `MathLayoutUtils`, `MathML`, etc., indicate interaction with the broader rendering engine.

4. **Examine Key Methods and Data Structures:**
    * **`ComputeCaptionConstraint`:**  Deals with calculating constraints for table captions, considering their min/max sizes.
    * **`CreateCaptionConstraintSpace`:**  Sets up the constraint space specifically for captions, handling available size and fragmentation.
    * **`LayoutCaption`:**  Performs the actual layout of a caption, resolving margins.
    * **`ComputeCaptionMargins`:** Calculates caption margins *before* layout.
    * **`ComputeCaptionFragments`:** Orchestrates the layout of all captions.
    * **`ComputeUndistributableTableSpace`:** Calculates space occupied by borders and spacing between columns.
    * **`ComputeEmptyTableInlineSize`:**  Handles the case where a table has no content.
    * **`ComputeAssignableTableInlineSize`:**  Calculates the available width for content after accounting for fixed elements.
    * **`ComputeLocationsFromColumns`:** Determines the position and size of each column.
    * **`CreateConstraintSpaceData`:**  Creates a data structure holding layout information about the table.
    * **`ColumnGeometriesBuilder`:**  Collects and sorts information about column geometry for painting.
    * **`ComputeTableSizeFromColumns`:** Calculates the total width of the table based on its columns.
    * **`BeginTableBoxLayout` and `EndTableBoxLayout`:** Manage the block-size calculation for the table grid.
    * **`ComputeTableInlineSize`:** The main function to determine the table's width.
    * **`ComputeCaptionBlockSize`:** Calculates the total height of the captions.
    * **`SetupRelayoutData`:**  Handles data transfer during relayout.
    * **`Layout`:** The core layout method, orchestrating the entire table layout process.
    * **`ComputeMinMaxSizes`:** Calculates the minimum and maximum intrinsic sizes of the table.

5. **Identify Relationships with Web Technologies:**
    * **HTML:** The code directly manipulates the layout of elements like `<table>`, `<caption>`, `<tr>`, `<td>`, `<th>`, `<colgroup>`, and `<col>`.
    * **CSS:** The code heavily relies on `ComputedStyle` to access CSS properties like `width`, `min-width`, `border-spacing`, `border-collapse`, margins, padding, and `table-layout`. The logic reflects the CSS table layout algorithm.
    * **JavaScript:** While this specific file is C++, its output and the layout it produces directly affect how JavaScript interacts with the DOM and how web pages are rendered. For instance, JavaScript might read the dimensions calculated by this code.

6. **Look for Logic and Assumptions:**
    * **Fixed vs. Auto Layout:** The code distinguishes between `fixed` and auto table layout algorithms, implementing different logic for each.
    * **Column Distribution:**  The code calculates how available space is distributed among columns, considering fixed widths, percentage widths, and auto widths.
    * **Caption Handling:**  Captions are treated specially, influencing table width and block size.
    * **Border Collapse:** The code accounts for the `border-collapse` property.
    * **Fragmentation:**  The code considers block fragmentation, especially for captions.

7. **Consider Potential Errors:**
    * **CSS Conflicts:** Incorrect or conflicting CSS rules can lead to unexpected layout results. For instance, specifying conflicting widths on columns in a fixed layout table.
    * **Infinite Loops (though less likely here):**  In complex layout scenarios, especially with dynamic content, there's a theoretical risk of infinite layout calculations, although the Blink engine has safeguards.
    * **Incorrect Percentage Resolution:**  Misunderstanding how percentage widths are resolved against container sizes can lead to layout issues.

8. **Structure the Summary:** Organize the findings into clear categories: core functionality, web technology relationships, logic and assumptions, and potential errors. Keep in mind the request for a *summary* for this first part.

9. **Refine and Iterate:** Review the analysis to ensure accuracy and completeness, given the provided code. Make sure the examples are relevant and easy to understand. For the "assumptions and logic" part, focus on the key algorithms and decisions the code seems to be making.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive and well-structured answer that addresses all aspects of the request. The key is to move from the general (file and class names) to the specific (methods and data structures), and then connect the technical details back to the broader context of web development.
好的，我们来分析一下 `blink/renderer/core/layout/table/table_layout_algorithm.cc` 文件的第一部分代码的功能。

**核心功能归纳:**

这段代码是 Chromium Blink 引擎中负责**HTML表格布局计算**的核心部分。它定义了 `TableLayoutAlgorithm` 类，该类专门用于计算 `<table>` 元素的尺寸和其中各个子元素（如 `<caption>`, `<tr>`, `<td>`, `<th>`, `<colgroup>`, `<col>`) 的位置和大小。

**更详细的功能点:**

1. **计算表格的内联尺寸 (宽度):**  `ComputeTableInlineSize` 函数负责计算表格的最终宽度。这个计算过程考虑了多种因素，包括：
    * **CSS 样式:**  读取表格的 `width`, `min-width`, `border-spacing`, `border-collapse`,  以及子元素的样式。
    * **表格布局算法:**  区分 `fixed` 和 `auto` 布局算法，并应用相应的计算逻辑。
    * **列约束:**  利用 `TableTypes::Columns` 来获取和处理 `<col>` 和 `<colgroup>` 定义的列宽度约束。
    * **表格标题 (Caption):**  `ComputeCaptionConstraint` 计算标题的最小和最大内联尺寸，影响表格的整体宽度。
    * **不可分配空间:** 计算表格边框、内边距和列间距占用的不可分配空间。
    * **空表格处理:**  `ComputeEmptyTableInlineSize` 处理没有内容的表格的宽度计算。
    * **列的位置和尺寸:** `ComputeLocationsFromColumns` 根据计算出的列宽，确定每列的起始位置和宽度。

2. **计算表格标题的块状尺寸 (高度):** `ComputeCaptionBlockSize` 函数负责计算所有表格标题的总高度。它会调用 `ComputeCaptionFragments` 来布局标题并累加其高度。

3. **处理表格的重排 (Relayout):** `SetupRelayoutData` 函数用于在表格需要重新布局时传递相关数据。它区分了不同的重排类型，例如 `kRelayoutAsLastTableBox`，这在处理跨页或跨列容器的表格时很重要。

4. **执行表格布局 (Layout):** `Layout` 函数是核心的布局执行函数。它按照以下步骤进行布局计算：
    * **获取样式和子元素:** 获取表格的样式信息和子元素（标题、列、行、单元格等）。
    * **计算内联约束:**  如同 `ComputeTableInlineSize`，计算影响表格宽度的约束。
    * **分配可分配宽度:** 将计算出的可分配宽度分配给各个列。
    * **计算列的位置:**  确定每列在表格中的确切位置。
    * **布局标题:** 调用 `ComputeCaptionFragments` 布局表格标题。
    * **计算行高:**  `ComputeRows` 函数（在后续部分）负责计算表格行的块状尺寸。
    * **生成布局片段 (Fragment):** `GenerateFragment` 函数（在后续部分）根据计算结果生成最终的布局信息。
    * **处理布局状态:**  检查布局结果的状态，例如是否需要作为最后一个表格盒进行重排，或者是否需要提前中断布局。

5. **计算最小和最大尺寸:** `ComputeMinMaxSizes` 函数计算表格的最小和最大内联尺寸，这对于弹性布局和容器查询等功能至关重要。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 该代码直接处理 HTML 表格元素 (`<table>`, `<caption>`, `<tr>`, `<td>`, `<th>`, `<colgroup>`, `<col>`) 的布局。例如，代码中的 `TableGroupedChildren grouped_children(Node());`  会根据 HTML 结构将表格的子元素分组。

* **CSS:**  代码大量使用 `ComputedStyle` 来获取元素的 CSS 属性，例如：
    * `table.Style().IsFixedTableLayout()`:  检查 CSS 的 `table-layout` 属性是否为 `fixed`。
    * `table.Style().TableBorderSpacing()`: 获取 CSS 的 `border-spacing` 属性值。
    * `caption.Style().GetWritingDirection()`: 获取标题的文字方向。
    * 代码中的各种 margin 计算都依赖于 CSS 的 margin 属性。

* **JavaScript:** 虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它计算出的布局结果会影响 JavaScript 与页面元素的交互。例如：
    * 当 JavaScript 需要获取表格或单元格的尺寸和位置时（例如使用 `getBoundingClientRect()`），它获取的就是这段 C++ 代码计算出的结果。
    * JavaScript 可以通过修改 CSS 样式（例如改变表格的宽度或列的宽度）来触发这段 C++ 代码重新计算布局。

**逻辑推理的假设输入与输出:**

假设有以下 HTML 和 CSS：

**HTML:**
```html
<table>
  <caption>我的表格</caption>
  <colgroup>
    <col style="width: 100px;">
    <col>
  </colgroup>
  <tr>
    <td>单元格 1</td>
    <td>单元格 2</td>
  </tr>
</table>
```

**CSS:**
```css
table {
  border-collapse: collapse;
  border-spacing: 0;
}
```

**假设输入（在 `ComputeTableInlineSize` 函数中）：**

* `table`： 代表上述 HTML `<table>` 元素的 `LayoutTable` 对象。
* `space`： 包含父容器提供的约束信息，例如可用宽度。
* `table_border_padding`： 根据 CSS 计算出的表格边框和内边距。

**推导过程 (简化):**

1. 代码会识别出 `table-layout` 为 `auto` (默认)。
2. `ComputeCaptionConstraint` 会计算标题 "我的表格" 的最小和最大宽度。
3. `Node().GetColumnConstraints()` 会读取 `<col>` 元素的 `width: 100px;`，并将其作为第一列的固定宽度约束。第二列没有明确的宽度，会被视为自动宽度。
4. `ComputeUndistributableTableSpace` 会计算由于 `border-collapse: collapse;` 和 `border-spacing: 0;` 导致的不可分配空间为 0。
5. `ComputeAssignableTableInlineSize` 会根据可用宽度和列的约束，计算出表格的可分配宽度。例如，如果父容器宽度足够大，第二列可能会分配到剩余的空间。
6. `SynchronizeAssignableTableInlineSizeAndColumns` 会最终确定每列的宽度，第一列为 100px，第二列的宽度取决于可分配的空间。
7. `ComputeLocationsFromColumns` 会计算出每列的起始位置。

**可能的输出（`ComputeTableInlineSize` 函数的返回值）：**

假设父容器宽度足够大，例如 500px，那么表格的最终宽度可能为：`100px (第一列) + 剩余空间 (例如 150px) = 250px` 再加上可能的边框和内边距。  具体的数值取决于 Blink 引擎内部的精确计算。

**用户或编程常见的使用错误举例:**

1. **忘记设置表格宽度导致意外的布局:** 用户可能没有为表格或其列设置足够的宽度，导致内容溢出或表格宽度过小。
   ```html
   <table>
     <tr><td>非常非常长的文本，没有设置表格或列宽</td></tr>
   </table>
   ```

2. **固定布局下，列宽总和超过表格宽度:** 在 `table-layout: fixed;` 的情况下，如果用户设置的列宽度总和超过了表格的宽度，可能会导致某些列被挤压或内容被截断。
   ```html
   <table style="width: 200px; table-layout: fixed;">
     <colgroup>
       <col style="width: 150px;">
       <col style="width: 100px;">
     </colgroup>
     <tr><td>...</td><td>...</td></tr>
   </table>
   ```

3. **混淆 `border-collapse` 和 `border-spacing`:**  用户可能不理解这两个属性的区别，导致边框和间距出现意外的效果。例如，在 `border-collapse: collapse;` 时设置 `border-spacing` 是无效的。

4. **过度依赖百分比宽度而没有合适的父容器:** 如果表格或列的宽度设置为百分比，但其父容器的宽度没有明确定义或太小，会导致布局不符合预期。

**这段代码的功能总结:**

这段 `table_layout_algorithm.cc` 文件的第一部分主要负责 HTML 表格**宽度**和**标题高度**的计算，这是表格布局算法的关键步骤。它深入解析 CSS 样式，考虑各种约束条件，并为后续的行布局和最终的渲染片段生成奠定基础。它体现了浏览器引擎如何根据 HTML 结构和 CSS 样式规则来精确地确定表格的尺寸。

Prompt: 
```
这是目录为blink/renderer/core/layout/table/table_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/table/table_layout_algorithm.h"

#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/mathml/math_layout_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/space_utils.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_caption.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column_visitor.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/core/layout/table/table_borders.h"
#include "third_party/blink/renderer/core/layout/table/table_break_token_data.h"
#include "third_party/blink/renderer/core/layout/table/table_child_iterator.h"
#include "third_party/blink/renderer/core/layout/table/table_constraint_space_data.h"
#include "third_party/blink/renderer/core/layout/table/table_fragment_data.h"
#include "third_party/blink/renderer/core/layout/table/table_layout_utils.h"
#include "third_party/blink/renderer/core/layout/table/table_node.h"
#include "third_party/blink/renderer/core/layout/text_autosizer.h"
#include "third_party/blink/renderer/core/mathml/mathml_element.h"
#include "third_party/blink/renderer/core/mathml_names.h"

namespace blink {

namespace {

TableTypes::Caption ComputeCaptionConstraint(
    const ConstraintSpace& table_space,
    const ComputedStyle& table_style,
    const TableGroupedChildren& grouped_children) {
  // Caption inline size constraints.
  TableTypes::Caption caption_min_max;
  for (const BlockNode& caption : grouped_children.captions) {
    // Caption %-block-sizes are treated as auto, as there isn't a reasonable
    // block-size to resolve against.
    MinMaxConstraintSpaceBuilder builder(table_space, table_style, caption,
                                         /* is_new_fc */ true);
    builder.SetAvailableBlockSize(kIndefiniteSize);
    const auto space = builder.ToConstraintSpace();

    MinMaxSizes min_max_sizes =
        ComputeMinAndMaxContentContribution(table_style, caption, space).sizes;
    min_max_sizes +=
        ComputeMarginsFor(space, caption.Style(), table_space).InlineSum();
    caption_min_max.Encompass(min_max_sizes);
  }
  return caption_min_max;
}

ConstraintSpace CreateCaptionConstraintSpace(
    const ConstraintSpace& table_constraint_space,
    const ComputedStyle& table_style,
    const BlockNode& caption,
    LogicalSize available_size,
    std::optional<LayoutUnit> block_offset = std::nullopt) {
  ConstraintSpaceBuilder builder(table_constraint_space,
                                 caption.Style().GetWritingDirection(),
                                 /* is_new_fc */ true);
  SetOrthogonalFallbackInlineSizeIfNeeded(table_style, caption, &builder);
  builder.SetAvailableSize(available_size);
  builder.SetPercentageResolutionSize(available_size);
  builder.SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);

  // If a block-offset is specified, it means that table captions are laid out
  // as part of normal table child layout (rather than in initial table
  // block-size calculation). That is normally only necessary if block
  // fragmentation is enabled, but may also occur if block fragmentation *was*
  // enabled for previous fragments, but is disabled for this fragment, because
  // of overflow clipping.
  if (block_offset && table_constraint_space.HasBlockFragmentation()) {
    SetupSpaceBuilderForFragmentation(
        table_constraint_space, caption,
        table_constraint_space.FragmentainerOffset() + *block_offset,
        table_constraint_space.FragmentainerBlockSize(),
        /*requires_content_before_breaking=*/false, &builder);
  }

  return builder.ToConstraintSpace();
}

TableLayoutAlgorithm::CaptionResult LayoutCaption(
    const ConstraintSpace& table_constraint_space,
    const ComputedStyle& table_style,
    LayoutUnit table_inline_size,
    const ConstraintSpace& caption_constraint_space,
    const BlockNode& caption,
    BoxStrut margins,
    const BlockBreakToken* break_token = nullptr,
    const EarlyBreak* early_break = nullptr) {
  const LayoutResult* layout_result =
      caption.Layout(caption_constraint_space, break_token, early_break);
  DCHECK_EQ(layout_result->Status(), LayoutResult::kSuccess);

  LogicalFragment fragment(table_constraint_space.GetWritingDirection(),
                           layout_result->GetPhysicalFragment());
  ResolveInlineAutoMargins(caption.Style(), table_style, table_inline_size,
                           fragment.InlineSize(), &margins);

  return {caption, layout_result, margins};
}

// Compute the margins of a caption as best as we can before layout (we need to
// lay out before we can resolve auto inline-margins). Remember that captions
// aren't actually inside the table, so its the *border-box* size of the table
// that matters here (not the content-box) when it comes to resolving
// percentages.
BoxStrut ComputeCaptionMargins(
    const ConstraintSpace& table_constraint_space,
    const BlockNode& caption,
    LayoutUnit table_border_box_inline_size,
    const BlockBreakToken* caption_break_token = nullptr) {
  BoxStrut margins =
      ComputeMarginsFor(caption.Style(), table_border_box_inline_size,
                        table_constraint_space.GetWritingDirection());
  AdjustMarginsForFragmentation(caption_break_token, &margins);
  return margins;
}

void ComputeCaptionFragments(
    const BoxFragmentBuilder& table_builder,
    const ComputedStyle& table_style,
    const TableGroupedChildren& grouped_children,
    HeapVector<TableLayoutAlgorithm::CaptionResult>* captions,
    LayoutUnit& captions_block_size) {
  const ConstraintSpace& table_constraint_space =
      table_builder.GetConstraintSpace();
  const LayoutUnit table_inline_size = table_builder.InlineSize();
  const LogicalSize available_size = {table_inline_size, kIndefiniteSize};
  for (BlockNode caption : grouped_children.captions) {
    BoxStrut margins = ComputeCaptionMargins(table_constraint_space, caption,
                                             table_inline_size);
    ConstraintSpace caption_constraint_space = CreateCaptionConstraintSpace(
        table_constraint_space, table_style, caption, available_size);

    // If we are discarding the results (compute-only) and we are after layout
    // (|!NeedsLayout|), or if we are in block fragmentation, make sure not to
    // update the cached layout results. If we are block fragmented, a node may
    // generate multiple fragments, so make sure that we keep the fragments
    // generated and stored in the actual layout pass.
    //
    // TODO(mstensho): We can remove this if we only perform this operation once
    // per table node (and e.g. store the table data in the break tokens).
    std::optional<DisableLayoutSideEffectsScope> disable_side_effects;
    if ((!captions && !caption.GetLayoutBox()->NeedsLayout()) ||
        InvolvedInBlockFragmentation(table_builder)) {
      disable_side_effects.emplace();
    }

    TableLayoutAlgorithm::CaptionResult caption_result =
        LayoutCaption(table_constraint_space, table_style, table_inline_size,
                      caption_constraint_space, caption, margins);
    LogicalFragment fragment(
        table_constraint_space.GetWritingDirection(),
        caption_result.layout_result->GetPhysicalFragment());
    captions_block_size +=
        fragment.BlockSize() + caption_result.margins.BlockSum();
    if (captions)
      captions->push_back(caption_result);
  }
}

LayoutUnit ComputeUndistributableTableSpace(
    const TableTypes::Columns& column_constraints,
    LayoutUnit inline_table_border_padding,
    LayoutUnit inline_border_spacing) {
  unsigned inline_space_count = 2;
  bool is_first_column = true;
  for (const TableTypes::Column& column : column_constraints.data) {
    if (!column.is_mergeable) {
      if (is_first_column)
        is_first_column = false;
      else
        inline_space_count++;
    }
  }

  return inline_table_border_padding +
         inline_space_count * inline_border_spacing;
}

// Empty table sizes have been a source of many inconsistencies
// between browsers.
LayoutUnit ComputeEmptyTableInlineSize(
    const ConstraintSpace& space,
    const ComputedStyle& table_style,
    const LayoutUnit assignable_table_inline_size,
    const LayoutUnit undistributable_space,
    const TableTypes::Caption& caption_constraint,
    const BoxStrut& table_border_padding,
    const bool has_collapsed_borders) {
  // If table has a css inline size, use that.
  // TODO(https://crbug.com/313072): Should these IsAuto calls handle
  // intrinsic sizing keywords or calc-size() differently, e.g., by using
  // HasAutoOrContentOrIntrinsic rather than just HasAuto?
  if (space.IsFixedInlineSize() || space.IsInlineAutoBehaviorStretch() ||
      !table_style.LogicalWidth().IsAuto() ||
      !table_style.LogicalMinWidth().IsAuto()) {
    return assignable_table_inline_size + undistributable_space;
  }
  // If there is a caption, it defines table wrapper inline size.
  if (caption_constraint.min_size) {
    return std::max(caption_constraint.min_size,
                    table_border_padding.InlineSum());
  }
  // Table is defined by its border/padding.
  if (has_collapsed_borders)
    return LayoutUnit();

  return assignable_table_inline_size + table_border_padding.InlineSum();
}

// standard: https://www.w3.org/TR/css-tables-3/#computing-the-table-width
LayoutUnit ComputeAssignableTableInlineSize(
    const TableNode& table,
    const ConstraintSpace& space,
    const TableTypes::Columns& column_constraints,
    const TableTypes::Caption& caption_constraint,
    const LayoutUnit undistributable_space,
    const BoxStrut& table_border_padding,
    const bool is_fixed_layout) {
  if (space.IsFixedInlineSize()) {
    return (space.AvailableSize().inline_size - undistributable_space)
        .ClampNegativeToZero();
  }

  const MinMaxSizes grid_min_max = ComputeGridInlineMinMax(
      table, column_constraints, undistributable_space, is_fixed_layout,
      /* is_layout_pass */ true);

  // Standard: "used width of the table".
  LayoutUnit used_table_inline_size = ComputeUsedInlineSizeForTableFragment(
      space, table, table_border_padding, grid_min_max);

  // |ComputeUsedInlineSizeForTableFragment| returns a value >= GRIDMIN because
  // of the |grid_min_max| parameter above.
  DCHECK_GE(used_table_inline_size, grid_min_max.min_size);

  // Don't allow the inline-size to go below the caption min-size.
  used_table_inline_size =
      std::max(used_table_inline_size, caption_constraint.min_size);

  // Standard: The assignable table width is the "used width of the table"
  // minus the total horizontal border spacing.
  const LayoutUnit assignable_table_inline_size =
      used_table_inline_size - undistributable_space;
  DCHECK_GE(assignable_table_inline_size, LayoutUnit());

  return assignable_table_inline_size;
}

// If |shrink_collapsed| is true, collapsed columns have zero width.
void ComputeLocationsFromColumns(const TableTypes::Columns& column_constraints,
                                 const Vector<LayoutUnit>& column_sizes,
                                 LayoutUnit inline_border_spacing,
                                 bool shrink_collapsed,
                                 Vector<TableColumnLocation>* column_locations,
                                 bool* has_collapsed_columns) {
  *has_collapsed_columns = false;
  column_locations->resize(column_constraints.data.size());
  if (column_locations->empty())
    return;
  bool is_first_non_collpased_column = true;
  LayoutUnit column_offset = inline_border_spacing;
  for (wtf_size_t i = 0; i < column_constraints.data.size(); ++i) {
    auto& column_location = (*column_locations)[i];
    auto& column_constraint = column_constraints.data[i];
    *has_collapsed_columns |= column_constraint.is_collapsed;
    if (column_constraints.data[i].is_mergeable &&
        (column_sizes[i] == kIndefiniteSize ||
         column_sizes[i] == LayoutUnit())) {
      // Empty mergeable columns are treated as collapsed.
      column_location.offset = column_offset;
      column_location.size = LayoutUnit();
      column_location.is_collapsed = true;
    } else if (shrink_collapsed && column_constraint.is_collapsed) {
      column_location.offset = column_offset;
      column_location.size = LayoutUnit();
      column_location.is_collapsed = true;
    } else {
      if (is_first_non_collpased_column)
        is_first_non_collpased_column = false;
      else
        column_offset += inline_border_spacing;
      column_location.offset = column_offset;
      column_location.size =
          column_sizes[i] != kIndefiniteSize ? column_sizes[i] : LayoutUnit();
      column_location.is_collapsed = false;
      column_offset += column_location.size;
    }
  }
}

scoped_refptr<const TableConstraintSpaceData> CreateConstraintSpaceData(
    const ComputedStyle& style,
    const Vector<TableColumnLocation>& column_locations,
    const TableTypes::Sections& sections,
    const TableTypes::Rows& rows,
    const TableTypes::CellBlockConstraints& cell_block_constraints,
    const LogicalSize& border_spacing) {
  // TODO(https://crbug.com/313072): These should probably use
  // HasAutoOrContentOrIntrinsic rather than just HasAuto.
  bool is_table_block_size_specified = !style.LogicalHeight().HasAuto();
  scoped_refptr<TableConstraintSpaceData> data =
      base::MakeRefCounted<TableConstraintSpaceData>();
  data->table_writing_direction = style.GetWritingDirection();
  data->table_border_spacing = border_spacing;
  data->is_table_block_size_specified = is_table_block_size_specified;
  data->has_collapsed_borders =
      style.BorderCollapse() == EBorderCollapse::kCollapse;
  data->column_locations = column_locations;

  data->sections.reserve(sections.size());
  for (const auto& section : sections)
    data->sections.emplace_back(section.start_row, section.row_count);
  data->rows.reserve(rows.size());
  for (const auto& row : rows) {
    data->rows.emplace_back(row.block_size, row.start_cell_index,
                            row.cell_count, row.baseline, row.is_collapsed);
  }
  data->cells.reserve(cell_block_constraints.size());
  // Traversing from section is necessary to limit cell's rowspan to the
  // section. The cell does not know what section it is in.
  for (const auto& section : sections) {
    for (wtf_size_t row_index = section.start_row;
         row_index < section.start_row + section.row_count; ++row_index) {
      const auto& row = rows[row_index];
      for (wtf_size_t cell_index = row.start_cell_index;
           cell_index < row.start_cell_index + row.cell_count; ++cell_index) {
        const auto& cell_block_constraint = cell_block_constraints[cell_index];
        const auto [cell_block_size, is_initial_block_size_indefinite] =
            ComputeCellBlockSize(cell_block_constraint, rows, row_index,
                                 border_spacing, is_table_block_size_specified);

        LayoutUnit rowspan_block_size =
            cell_block_constraint.effective_rowspan > 1 ? cell_block_size
                                                        : kIndefiniteSize;

        data->cells.emplace_back(
            cell_block_constraint.borders, rowspan_block_size,
            cell_block_constraint.column_index,
            is_initial_block_size_indefinite,
            cell_block_constraint
                .has_descendant_that_depends_on_percentage_block_size);
      }
    }
  }
  return data;
}

// Columns do not generate fragments.
// Column geometry is needed for painting, and is stored
// in TableFragmentData. Geometry data is also copied
// back to LayoutObject.
class ColumnGeometriesBuilder {
  STACK_ALLOCATED();

 public:
  void VisitCol(const LayoutInputNode& col,
                wtf_size_t start_column_index,
                wtf_size_t span) {
    wtf_size_t end_column_index = start_column_index + span - 1;
    DCHECK_LE(end_column_index, column_locations.size() - 1);
    LayoutUnit column_inline_size = column_locations[end_column_index].offset +
                                    column_locations[end_column_index].size -
                                    column_locations[start_column_index].offset;

    column_geometries.emplace_back(start_column_index, span,
                                   column_locations[start_column_index].offset -
                                       column_locations[0].offset,
                                   column_inline_size, col);
  }

  void EnterColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index) {}

  void LeaveColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index,
                     wtf_size_t span,
                     bool has_children) {
    if (span == 0)
      return;
    wtf_size_t last_column_index = start_column_index + span - 1;
    LayoutUnit colgroup_size = column_locations[last_column_index].offset +
                               column_locations[last_column_index].size -
                               column_locations[start_column_index].offset;

    column_geometries.emplace_back(start_column_index, span,
                                   column_locations[start_column_index].offset -
                                       column_locations[0].offset,
                                   colgroup_size, colgroup);
  }

  void Sort() {
    // Geometries need to be sorted because this must be true:
    // - parent COLGROUP must come before child COLs.
    // - child COLs are in ascending order.
    std::sort(column_geometries.begin(), column_geometries.end(),
              [](const TableFragmentData::ColumnGeometry& a,
                 const TableFragmentData::ColumnGeometry& b) {
                if (a.node.IsTableCol() && b.node.IsTableCol()) {
                  return a.start_column < b.start_column;
                }
                if (a.node.IsTableColgroup()) {
                  if (b.node.IsTableColgroup())
                    return a.start_column < b.start_column;
                  if (a.start_column <= b.start_column &&
                      (a.start_column + a.span) > b.start_column) {
                    return true;
                  }
                  return a.start_column < b.start_column;
                } else {
                  DCHECK(b.node.IsTableColgroup());
                  if (b.start_column <= a.start_column &&
                      (b.start_column + b.span) > a.start_column) {
                    return false;
                  }
                  return b.start_column >= a.start_column;
                }
              });

    wtf_size_t column_idx = 0;
    for (const auto& col : column_geometries) {
      To<LayoutTableColumn>(col.node.GetLayoutBox())
          ->SetColumnIndex(column_idx);
      column_idx++;
    }
  }

  ColumnGeometriesBuilder(const Vector<TableColumnLocation>& column_locations,
                          LayoutUnit table_column_block_size)
      : column_locations(column_locations),
        table_column_block_size(table_column_block_size) {}
  TableFragmentData::ColumnGeometries column_geometries;
  const Vector<TableColumnLocation>& column_locations;
  const LayoutUnit table_column_block_size;
};

LayoutUnit ComputeTableSizeFromColumns(
    const Vector<TableColumnLocation>& column_locations,
    const BoxStrut& table_border_padding,
    const LogicalSize& border_spacing) {
  return column_locations.back().offset + column_locations.back().size +
         table_border_padding.InlineSum() + border_spacing.inline_size;
}

// Border-box block extent of what CSS calls the "table box" [1]
// (i.e. everything except for captions).
//
// [1] https://www.w3.org/TR/CSS22/tables.html#model
struct TableBoxExtent {
  LayoutUnit start;
  LayoutUnit end;
};

// Call when beginning layout of the table box (typically right before laying
// out the first section).
TableBoxExtent BeginTableBoxLayout(
    LayoutUnit block_start_border_edge,
    LayoutUnit table_border_padding_block_start) {
  return {block_start_border_edge,
          block_start_border_edge + table_border_padding_block_start};
}

// Call when done with layout of the table box (typically right after having
// laid out the last table section).
LayoutUnit EndTableBoxLayout(LayoutUnit table_border_padding_block_end,
                             LayoutUnit border_spacing_after_last_section,
                             LayoutUnit minimal_table_grid_block_size,
                             TableBoxExtent* extent,
                             LayoutUnit* grid_block_size_inflation) {
  DCHECK_LE(extent->start, extent->end);
  extent->end +=
      border_spacing_after_last_section + table_border_padding_block_end;
  LayoutUnit sections_total_size = extent->end - extent->start;
  LayoutUnit grid_block_size =
      std::max(sections_total_size, minimal_table_grid_block_size);
  extent->end = extent->start + grid_block_size;

  // Record how much minimal_table_grid_block_size inflated the grid
  // block-size. This should be excluded from intrinsic block-size.
  *grid_block_size_inflation = grid_block_size - sections_total_size;

  return extent->end;
}

}  // namespace

LayoutUnit TableLayoutAlgorithm::ComputeTableInlineSize(
    const TableNode& table,
    const ConstraintSpace& space,
    const BoxStrut& table_border_padding) {
  const bool is_fixed_layout = table.Style().IsFixedTableLayout();
  // Tables need autosizer.
  std::optional<TextAutosizer::TableLayoutScope> text_autosizer;
  if (!is_fixed_layout)
    text_autosizer.emplace(To<LayoutTable>(table.GetLayoutBox()));

  const LogicalSize border_spacing = table.Style().TableBorderSpacing();
  TableGroupedChildren grouped_children(table);
  const TableBorders* table_borders = table.GetTableBorders();

  // Compute min/max inline constraints.
  const scoped_refptr<const TableTypes::Columns> column_constraints =
      table.GetColumnConstraints(grouped_children, table_border_padding);

  const TableTypes::Caption caption_constraint =
      ComputeCaptionConstraint(space, table.Style(), grouped_children);

  const LayoutUnit undistributable_space = ComputeUndistributableTableSpace(
      *column_constraints, table_border_padding.InlineSum(),
      border_spacing.inline_size);

  const LayoutUnit assignable_table_inline_size =
      ComputeAssignableTableInlineSize(
          table, space, *column_constraints, caption_constraint,
          undistributable_space, table_border_padding, is_fixed_layout);
  if (column_constraints->data.empty()) {
    return ComputeEmptyTableInlineSize(
        space, table.Style(), assignable_table_inline_size,
        undistributable_space, caption_constraint, table_border_padding,
        table_borders->IsCollapsed());
  }

  const Vector<LayoutUnit> column_sizes =
      SynchronizeAssignableTableInlineSizeAndColumns(
          assignable_table_inline_size, is_fixed_layout, *column_constraints);

  // Final inline size must depend on column locations, because columns can be
  // hidden.
  Vector<TableColumnLocation> column_locations;
  bool has_collapsed_columns;
  ComputeLocationsFromColumns(
      *column_constraints, column_sizes, border_spacing.inline_size,
      /* collapse_columns */ true, &column_locations, &has_collapsed_columns);
  return std::max(ComputeTableSizeFromColumns(
                      column_locations, table_border_padding, border_spacing),
                  caption_constraint.min_size);
}

LayoutUnit TableLayoutAlgorithm::ComputeCaptionBlockSize() {
  TableGroupedChildren grouped_children(Node());
  LayoutUnit captions_block_size;
  ComputeCaptionFragments(container_builder_, Node().Style(), grouped_children,
                          /* captions */ nullptr, captions_block_size);
  return captions_block_size;
}

void TableLayoutAlgorithm::SetupRelayoutData(
    const TableLayoutAlgorithm& previous,
    RelayoutType relayout_type) {
  LayoutAlgorithm::SetupRelayoutData(previous, relayout_type);

  if (relayout_type == kRelayoutAsLastTableBox) {
    is_known_to_be_last_table_box_ = true;
  } else {
    is_known_to_be_last_table_box_ = previous.is_known_to_be_last_table_box_;
  }
}

const LayoutResult* TableLayoutAlgorithm::Layout() {
  if (is_known_to_be_last_table_box_) {
    // This is the last table box fragment. Shouldn't reserve space for cloned
    // block-end box decorations.
    container_builder_.SetShouldCloneBoxEndDecorations(false);
    // And since this is the last table box fragment, be sure *not* to break
    // before any trailing decorations (even if that would cause it to overflow
    // the fragmentainer).
    container_builder_.SetShouldPreventBreakBeforeBlockEndDecorations(true);
  }

  const bool is_fixed_layout = Style().IsFixedTableLayout();
  const LogicalSize border_spacing = Style().TableBorderSpacing();
  TableGroupedChildren grouped_children(Node());
  const TableBorders* table_borders = Node().GetTableBorders();
  DCHECK(table_borders);
  const BoxStrut border_padding = container_builder_.BorderPadding();

  // Algorithm:
  // - Compute inline constraints.
  // - Redistribute assignble table inline size to inline constraints.
  // - Compute column locations.
  // - Compute row block sizes.
  // - Generate fragment.
  const scoped_refptr<const TableTypes::Columns> column_constraints =
      Node().GetColumnConstraints(grouped_children, border_padding);
  const TableTypes::Caption caption_constraint =
      ComputeCaptionConstraint(GetConstraintSpace(), Style(), grouped_children);
  // Compute assignable table inline size.
  // Standard: https://www.w3.org/TR/css-tables-3/#width-distribution
  const LayoutUnit undistributable_space = ComputeUndistributableTableSpace(
      *column_constraints, border_padding.InlineSum(),
      border_spacing.inline_size);

  const LayoutUnit assignable_table_inline_size =
      ComputeAssignableTableInlineSize(
          Node(), GetConstraintSpace(), *column_constraints, caption_constraint,
          undistributable_space, border_padding, is_fixed_layout);

  // Distribute assignable table width.
  const Vector<LayoutUnit> column_sizes =
      SynchronizeAssignableTableInlineSizeAndColumns(
          assignable_table_inline_size, is_fixed_layout, *column_constraints);

  Vector<TableColumnLocation> column_locations;
  bool has_collapsed_columns;
  ComputeLocationsFromColumns(
      *column_constraints, column_sizes, border_spacing.inline_size,
      /* shrink_collapsed */ false, &column_locations, &has_collapsed_columns);

  LayoutUnit table_inline_size_before_collapse;
  const bool is_grid_empty = column_locations.empty();
  if (is_grid_empty) {
    table_inline_size_before_collapse = ComputeEmptyTableInlineSize(
        GetConstraintSpace(), Style(), assignable_table_inline_size,
        undistributable_space, caption_constraint, border_padding,
        table_borders->IsCollapsed());
  } else {
    table_inline_size_before_collapse = ComputeTableSizeFromColumns(
        column_locations, border_padding, border_spacing);
  }

  // Before we can determine the block-size of the sections/rows, we need to
  // layout all of our captions.
  //
  // The block-size taken by the captions, *subtracts* from the available
  // block-size given to the table-grid.
  HeapVector<CaptionResult> captions;
  LayoutUnit captions_block_size;
  ComputeCaptionFragments(container_builder_, Style(), grouped_children,
                          &captions, captions_block_size);

  TableTypes::Rows rows;
  TableTypes::CellBlockConstraints cell_block_constraints;
  TableTypes::Sections sections;
  LayoutUnit minimal_table_grid_block_size;
  ComputeRows(table_inline_size_before_collapse - border_padding.InlineSum(),
              grouped_children, column_locations, *table_borders,
              border_spacing, border_padding, captions_block_size, &rows,
              &cell_block_constraints, &sections,
              &minimal_table_grid_block_size);

  if (has_collapsed_columns) {
    ComputeLocationsFromColumns(
        *column_constraints, column_sizes, border_spacing.inline_size,
        /* shrink_collapsed */ true, &column_locations, &has_collapsed_columns);
  }
#if DCHECK_IS_ON()
  // To avoid number rounding issues, instead of comparing sizes
  // equality, we check whether sizes differ in less than a pixel.
  if (!has_collapsed_columns) {
    // Columns define table whose inline size equals InitialFragmentGeometry.
    DCHECK_LT(
        (table_inline_size_before_collapse - container_builder_.InlineSize())
            .Abs(),
        LayoutUnit(1));
  } else if (GetConstraintSpace().IsFixedInlineSize()) {
    // Collapsed columns + fixed inline size: columns define table whose
    // inline size is less or equal InitialFragmentGeometry.
    LayoutUnit table_inline_size =
        std::max(ComputeTableSizeFromColumns(column_locations, border_padding,
                                             border_spacing),
                 caption_constraint.min_size);
    DCHECK_LE(table_inline_size, container_builder_.InlineSize());
  } else {
    LayoutUnit table_inline_size =
        std::max(ComputeTableSizeFromColumns(column_locations, border_padding,
                                             border_spacing),
                 caption_constraint.min_size);
    DCHECK_LT((table_inline_size - container_builder_.InlineSize()).Abs(),
              LayoutUnit(1));
  }
#endif

  const LayoutResult* result = GenerateFragment(
      container_builder_.InlineSize(), minimal_table_grid_block_size,
      grouped_children, column_locations, rows, cell_block_constraints,
      sections, captions, *table_borders,
      is_grid_empty ? LogicalSize() : border_spacing);

  if (result->Status() == LayoutResult::kNeedsRelayoutAsLastTableBox) {
    DCHECK(!is_known_to_be_last_table_box_);
    return Relayout<TableLayoutAlgorithm>(kRelayoutAsLastTableBox);
  }
  if (result->Status() == LayoutResult::kNeedsEarlierBreak) {
    // We shouldn't insert early-breaks when we're relaying out as the last
    // table-box fragment. That should take place *first*.
    DCHECK(!is_known_to_be_last_table_box_);

    return RelayoutAndBreakEarlier<TableLayoutAlgorithm>(
        *result->GetEarlyBreak());
  }

  return result;
}

MinMaxSizesResult TableLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  const bool is_fixed_layout = Style().IsFixedTableLayout();
  // Tables need autosizer.
  std::optional<TextAutosizer::TableLayoutScope> text_autosizer;
  if (!is_fixed_layout)
    text_autosizer.emplace(To<LayoutTable>(Node().GetLayoutBox()));

  const LogicalSize border_spacing = Style().TableBorderSpacing();
  const BoxStrut border_padding = container_builder_.BorderPadding();
  TableGroupedChildren grouped_children(Node());

  const scoped_refptr<const TableTypes::Columns> column_constraints =
      Node().GetColumnConstraints(grouped_children, border_padding);
  const TableTypes::Caption caption_constraint =
      ComputeCaptionConstraint(GetConstraintSpace(), Style(), grouped_children);

  const LayoutUnit undistributable_space = ComputeUndistributableTableSpace(
      *column_constraints, border_padding.InlineSum(),
      border_spacing.inline_size);

  const MinMaxSizes grid_min_max = ComputeGridInlineMinMax(
      Node(), *column_constraints, undistributable_space, is_fixed_layout,
      /* is_layout_pass */ false);

  MinMaxSizes min_max{
      std::max(grid_min_max.min_size, caption_constraint.min_size),
      std::max(grid_min_max.max_size, caption_constraint.min_size)};

  if (is_fixed_layout && Style().LogicalWidth().HasPercent()) {
    min_max.max_size = TableTypes::kTableMaxInlineSize;
  }
  DCHECK_LE(min_max.min_size, min_max.max_size);
  
"""


```