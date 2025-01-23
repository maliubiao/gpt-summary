Response:
The user wants a summary of the functionality of the `table_layout_utils.cc` file in the Chromium Blink engine. They also want to know the relationships with Javascript, HTML, and CSS, examples of logical reasoning with inputs and outputs, and common user/programming errors.

**Plan:**

1. **High-level purpose:** Identify the main goal of this file based on its name and included headers. It's likely related to calculating layout properties for HTML tables.
2. **Function-level analysis:** Go through the defined functions and try to understand their individual roles in the table layout process.
3. **Relationship with web technologies:**  Connect the functions to HTML table elements, CSS properties that affect table layout, and how JavaScript might interact.
4. **Logical reasoning:** Select a few functions and create hypothetical input scenarios and their expected output.
5. **Common errors:** Think about typical mistakes developers make when working with HTML tables and how this code might be involved in handling or preventing them.
6. **Summarize:** Provide a concise overview of the file's purpose based on the above analysis.
这是对 `blink/renderer/core/layout/table/table_layout_utils.cc` 文件（第一部分）的功能归纳：

**核心功能：**

这个文件包含了一系列用于计算和处理 HTML 表格布局的实用工具函数。它的主要职责是收集、计算和分配表格中列和行的尺寸约束，以确定最终的布局。

**具体功能点：**

1. **列约束处理:**
    *   **`EnsureDistributableColumnExists`**:  确保在跨多列的单元格中，至少有一列被标记为可分配剩余空间的（非 `mergeable`）。这对于避免空间分配不均，以及处理 `visibility: collapse` 的列的情况很重要。
    *   **`ApplyCellConstraintsToColumnConstraints`**: 将单元格的内联尺寸约束（例如，`width` 属性）应用到列的约束上。这包括：
        *   调整列的数量以适应单元格的需求。
        *   标记需要保持独立的列（`is_mergeable = false`）。
        *   将单元格的 `min-width` 和 `max-width` 等属性信息合并到对应的列约束中。
        *   处理跨列单元格的约束分配。
        *   处理列的百分比宽度，并确保总百分比不超过 100%。
    *   **`ColumnConstraintsBuilder` 和 `ComputeColumnElementConstraints`**: 处理 `<colgroup>` 和 `<col>` 元素定义的列约束。它们负责提取 CSS 样式中定义的宽度信息，并将其应用于相应的列。
2. **行约束处理:**
    *   **`ComputeMinimumRowBlockSize`**: 计算表格行的最小块级尺寸（例如，`height`），考虑了单元格的内容、边框、内边距、以及 `rowspan` 属性。
        *   它会模拟单元格的布局过程，获取单元格的实际尺寸。
        *   它会处理单元格的百分比高度和固定高度。
        *   它还会处理 `rowspan` 单元格，并将相关信息存储起来供后续使用。
        *   它还考虑了单元格的基线位置。
3. **内联约束处理 (针对 `<colgroup>`, `<col>`, `<td>`, `<th>`):**
    *   **`ComputeSectionInlineConstraints`**:  遍历表格的 `<tbody>`, `<thead>`, `<tfoot>` 等部分，收集其中单元格的内联尺寸约束。
        *   它会跟踪跨列单元格的位置和尺寸。
        *   它会处理单元格的边框、内边距以及 CSS 宽度属性。
        *   它会区分单列单元格和跨列单元格，分别处理它们的约束。
4. **尺寸分配算法:**
    *   **`DistributeInlineSizeToComputedInlineSizeAuto`**:  实现表格列宽的分配算法，用于 `table-layout: auto` 的表格。
        *   它根据列的 `min-width`、`max-width`、百分比宽度和是否是固定宽度列等信息，将可用的内联空间分配给各个列。
        *   它模拟了 CSS 表格规范中定义的宽度分配步骤，包括不同的 "猜测" 阶段 (Min Guess, Percentage Guess, Specified Guess, Max Guess)。
        *   它处理了各种情况，例如目标宽度小于最小宽度总和、介于不同 "猜测" 阶段的宽度等。

**与 Javascript, HTML, CSS 的关系：**

*   **HTML:** 该文件处理的是 HTML 表格元素（`<table>`, `<tr>`, `<td>`, `<th>`, `<colgroup>`, `<col>`) 的布局计算。例如，`ComputeMinimumRowBlockSize` 遍历 `<tr>` 元素下的 `<td>`/`<th>` 元素来计算行高。`ComputeColumnElementConstraints` 处理 `<colgroup>` 和 `<col>` 元素。
*   **CSS:**  该文件大量使用了 CSS 属性来计算布局。例如：
    *   `width`, `height`: 用于计算单元格和列的尺寸。
    *   `border`, `padding`:  `ComputeMinimumRowBlockSize` 和 `ComputeSectionInlineConstraints` 使用这些属性来计算单元格的边框和内边距。
    *   `table-layout`: `DistributeInlineSizeToComputedInlineSizeAuto`  只在 `table-layout: auto` 的情况下使用。
    *   `visibility: collapse`: `EnsureDistributableColumnExists` 会考虑这种属性。
    *   `colspan`, `rowspan`:  `ComputeMinimumRowBlockSize` 和 `ComputeSectionInlineConstraints` 会处理这些属性。
    *   `box-sizing`:  `ComputeMinimumRowBlockSize` 在计算单元格高度时会考虑 `border-box` 模式。
    *   `writing-mode`: 影响布局方向，在多个函数中作为参数传递。
*   **Javascript:**  虽然这个 C++ 文件本身不直接与 Javascript 交互，但 Javascript 可以通过 DOM API 修改 HTML 结构和 CSS 样式，从而间接地影响这里的布局计算。例如，通过 Javascript 动态添加或删除表格行/列，或者修改单元格的 `width` 属性，都会导致 Blink 引擎重新进行布局计算，并调用这个文件中的函数。

**逻辑推理的假设输入与输出：**

**示例 1: `EnsureDistributableColumnExists`**

*   **假设输入:**
    *   `start_column_index = 1`
    *   `span = 3`
    *   `column_constraints`: 一个包含 5 列的 `TableTypes::Columns` 结构，其中第 2、3、4 列的 `is_collapsed` 属性为 `true`，其他为 `false`。

*   **预期输出:** `column_constraints` 中索引为 1 的列（即原始的第 2 列）的 `is_mergeable` 属性会被设置为 `false`。即使它本身是 `collapsed` 的，但为了确保空间分配，也会被标记为不可合并。

**示例 2: `ComputeMinimumRowBlockSize`**

*   **假设输入:**
    *   一个包含一个表格行的 `BlockNode`，该行包含两个单元格。
    *   第一个单元格内容较少，没有设置高度。
    *   第二个单元格内容很多，自动撑开高度为 50px。
    *   表格没有设置固定的 `table-layout`。

*   **预期输出:** `ComputeMinimumRowBlockSize` 返回的 `TableTypes::Row` 结构的 `row_block_size` 字段的值至少为 50px（加上可能的边框和内边距），以容纳内容最多的单元格。

**用户或编程常见的使用错误举例：**

1. **CSS 冲突导致意外的表格布局:** 用户可能设置了相互冲突的 CSS 属性，例如同时设置了列的固定宽度和表格的百分比宽度，导致浏览器需要解决这些冲突，最终布局可能不是用户期望的。这个文件中的代码会按照 CSS 规范的优先级和规则来处理这些冲突。
2. **误用 `visibility: collapse` 导致列合并问题:** 如果用户将某些列设置为 `visibility: collapse`，但没有考虑到跨列单元格的影响，可能会导致列合并的行为不符合预期。`EnsureDistributableColumnExists` 的存在是为了帮助解决这类问题。
3. **JavaScript 动态修改表格结构后未触发重新布局:**  开发者可能使用 JavaScript 动态地修改了表格的 DOM 结构或 CSS 样式，但没有确保浏览器触发重新布局。这会导致页面显示与实际 DOM 结构不符。Blink 引擎会在 DOM 更改后自动标记需要重新布局的元素。
4. **过度依赖百分比宽度而忽略内容撑开:** 用户可能过度依赖百分比宽度来定义表格列宽，但如果单元格内容过多，可能会导致内容溢出或者表格布局错乱。`DistributeInlineSizeToComputedInlineSizeAuto` 试图在百分比宽度和内容所需的最小宽度之间找到平衡。
5. **不理解 `table-layout: fixed` 和 `auto` 的区别:**  用户可能不清楚这两种布局算法的区别，导致使用了错误的 `table-layout` 值，使得表格布局不符合预期。这个文件中的不同函数针对这两种布局模式有不同的处理逻辑。

**功能归纳:**

`table_layout_utils.cc` (第一部分) 的主要功能是为 Blink 引擎提供了一组用于计算 HTML 表格布局中列和行的尺寸约束的底层工具。它负责收集来自 HTML 结构和 CSS 样式的各种约束信息，并进行初步的处理和调整，为后续的最终布局计算奠定基础。这部分代码关注于理解和转换开发者在 HTML 和 CSS 中定义的意图，并将其转化为引擎可以理解和处理的数值信息。

### 提示词
```
这是目录为blink/renderer/core/layout/table/table_layout_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/table/table_layout_utils.h"

#include "third_party/blink/renderer/core/layout/block_layout_algorithm_utils.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/box_fragment_builder.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/disable_layout_side_effects_scope.h"
#include "third_party/blink/renderer/core/layout/fragmentation_utils.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_size.h"
#include "third_party/blink/renderer/core/layout/layout_result.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_column_visitor.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_section.h"
#include "third_party/blink/renderer/core/layout/table/table_borders.h"
#include "third_party/blink/renderer/core/layout/table/table_node.h"

namespace blink {

namespace {

// We cannot distribute space to mergeable columns. Mark at least one of the
// spanned columns as distributable (i.e. non-mergeable).
//
// We'll mark the first (non-collapsed) column as non-mergeable. We should only
// merge adjacent columns that have no cells that start there.
//
// Example:
//
//             +------------------------+------------------------+
//             |          cell          |         cell           |
//    row 1    |       colspan 2        |       colspan 2        |
//             |                        |                        |
//             +------------+-----------+-----------+------------+
//             |    cell    |         cell          |   cell     |
//    row 2    | colspan 1  |       colspan 2       | colspan 1  |
//             |            |                       |            |
//             +------------+-----------------------+------------+
//
//   columns   |  column 1  |  column 2 | column 3  |  column 4  |
//
// No columns should be merged here, as there are no columns that has no cell
// starting there. We want all four columns to receive some space, or
// distribution would be uneven.
//
// Another interesting problem being solved here is the interaction between
// collapsed (visibility:collapse) and mergeable columns. We need to find the
// first column that isn't collapsed and mark it as non-mergeable. Otherwise the
// entire cell might merge into the first column, and collapse, and the whole
// cell would be hidden if the first column is collapsed.
//
// If all columns spanned actually collapse, the first column will be marked as
// non-meargeable.
void EnsureDistributableColumnExists(wtf_size_t start_column_index,
                                     wtf_size_t span,
                                     TableTypes::Columns* column_constraints) {
  DCHECK_LT(start_column_index, column_constraints->data.size());
  DCHECK_GT(span, 1u);

  wtf_size_t effective_span =
      std::min(span, column_constraints->data.size() - start_column_index);
  TableTypes::Column* start_column =
      &column_constraints->data[start_column_index];
  TableTypes::Column* end_column = start_column + effective_span;
  for (TableTypes::Column* column = start_column; column != end_column;
       ++column) {
    if (!column->is_collapsed) {
      column->is_mergeable = false;
      return;
    }
  }
  // We didn't find any non-collapsed column. Mark the first one as
  // non-mergeable.
  start_column->is_mergeable = false;
}

// Applies cell/wide cell constraints to columns.
// Guarantees columns min/max widths have non-empty values.
void ApplyCellConstraintsToColumnConstraints(
    const TableTypes::CellInlineConstraints& cell_constraints,
    LayoutUnit inline_border_spacing,
    bool is_fixed_layout,
    TableTypes::ColspanCells* colspan_cell_constraints,
    TableTypes::Columns* column_constraints) {
  // Satisfy prerequisites for cell merging:

  if (column_constraints->data.size() < cell_constraints.size()) {
    // Column constraint must exist for each cell.
    TableTypes::Column default_column;
    default_column.is_table_fixed = is_fixed_layout;
    default_column.is_mergeable = !is_fixed_layout;
    wtf_size_t column_count =
        cell_constraints.size() - column_constraints->data.size();
    // Must loop because WTF::Vector does not support resize with default value.
    for (wtf_size_t i = 0; i < column_count; ++i)
      column_constraints->data.push_back(default_column);
    DCHECK_EQ(column_constraints->data.size(), cell_constraints.size());

  } else if (column_constraints->data.size() > cell_constraints.size()) {
    // Trim mergeable columns off the end.
    wtf_size_t last_non_merged_column = column_constraints->data.size() - 1;
    while (last_non_merged_column + 1 > cell_constraints.size() &&
           column_constraints->data[last_non_merged_column].is_mergeable) {
      --last_non_merged_column;
    }
    column_constraints->data.resize(last_non_merged_column + 1);
    DCHECK_GE(column_constraints->data.size(), cell_constraints.size());
  }
  // Make sure there exists a non-mergeable column for each colspanned cell.
  for (const TableTypes::ColspanCell& colspan_cell :
       *colspan_cell_constraints) {
    EnsureDistributableColumnExists(colspan_cell.start_column,
                                    colspan_cell.span, column_constraints);
  }

  // Distribute cell constraints to column constraints.
  for (wtf_size_t i = 0; i < cell_constraints.size(); ++i) {
    column_constraints->data[i].Encompass(cell_constraints[i]);
  }

  // Wide cell constraints are sorted by span length/starting column.
  auto colspan_cell_less_than = [](const TableTypes::ColspanCell& lhs,
                                   const TableTypes::ColspanCell& rhs) {
    if (lhs.span == rhs.span)
      return lhs.start_column < rhs.start_column;
    return lhs.span < rhs.span;
  };
  std::stable_sort(colspan_cell_constraints->begin(),
                   colspan_cell_constraints->end(), colspan_cell_less_than);

  DistributeColspanCellsToColumns(*colspan_cell_constraints,
                                  inline_border_spacing, is_fixed_layout,
                                  column_constraints);

  // Column total percentage inline-size is clamped to 100%.
  // Auto tables: max(0, 100% minus the sum of percentages of all
  //   prior columns in the table)
  // Fixed tables: scale all percentage columns so that total percentage
  //   is 100%.
  float total_percentage = 0;
  for (TableTypes::Column& column : column_constraints->data) {
    if (column.percent) {
      if (!is_fixed_layout && (*column.percent + total_percentage > 100.0))
        column.percent = 100 - total_percentage;
      total_percentage += *column.percent;
    }
    // A column may have no min/max inline-sizes if there are no cells in this
    // column. E.g. a cell has a large colspan which no other cell belongs to.
    column.min_inline_size = column.min_inline_size.value_or(LayoutUnit());
    column.max_inline_size = column.max_inline_size.value_or(LayoutUnit());
  }

  if (is_fixed_layout && total_percentage > 100.0) {
    for (TableTypes::Column& column : column_constraints->data) {
      if (column.percent)
        column.percent = *column.percent * 100 / total_percentage;
    }
  }
}

template <typename RowCountFunc>
TableTypes::Row ComputeMinimumRowBlockSize(
    const RowCountFunc& row_count_func,
    const BlockNode& row,
    const LayoutUnit cell_percentage_inline_size,
    const bool is_table_block_size_specified,
    const Vector<TableColumnLocation>& column_locations,
    const TableBorders& table_borders,
    wtf_size_t start_row_index,
    wtf_size_t row_index,
    wtf_size_t section_index,
    bool is_section_collapsed,
    TableTypes::CellBlockConstraints* cell_block_constraints,
    TableTypes::RowspanCells* rowspan_cells,
    ColspanCellTabulator* colspan_cell_tabulator) {
  const WritingDirectionMode table_writing_direction =
      row.Style().GetWritingDirection();
  const bool has_collapsed_borders = table_borders.IsCollapsed();

  // TODO(layout-ng) Scrollbars should be frozen when computing row sizes.
  // This cannot be done today, because fragments with frozen scrollbars
  // will be cached. Needs to be fixed in NG framework.

  LayoutUnit max_cell_block_size;
  std::optional<float> row_percent;
  bool is_constrained = false;
  bool has_rowspan_start = false;
  wtf_size_t start_cell_index = cell_block_constraints->size();
  RowBaselineTabulator row_baseline_tabulator;

  // Gather block sizes of all cells.
  for (BlockNode cell = To<BlockNode>(row.FirstChild()); cell;
       cell = To<BlockNode>(cell.NextSibling())) {
    colspan_cell_tabulator->FindNextFreeColumn();
    const ComputedStyle& cell_style = cell.Style();
    const auto cell_writing_direction = cell_style.GetWritingDirection();
    const BoxStrut cell_borders = table_borders.CellBorder(
        cell, row_index, colspan_cell_tabulator->CurrentColumn(), section_index,
        table_writing_direction);

    // Clamp the rowspan if it exceeds the total section row-count.
    wtf_size_t effective_rowspan = cell.TableCellRowspan();
    if (effective_rowspan > 1) {
      const wtf_size_t max_rows =
          row_count_func() - (row_index - start_row_index);
      effective_rowspan = std::min(max_rows, effective_rowspan);
    }

    ConstraintSpaceBuilder space_builder(
        table_writing_direction.GetWritingMode(), cell_writing_direction,
        /* is_new_fc */ true);

    // We want these values to match the "layout" pass as close as possible.
    SetupTableCellConstraintSpaceBuilder(
        table_writing_direction, cell, cell_borders, column_locations,
        /* cell_block_size */ kIndefiniteSize, cell_percentage_inline_size,
        /* alignment_baseline */ std::nullopt,
        colspan_cell_tabulator->CurrentColumn(),
        /* is_initial_block_size_indefinite */ true,
        is_table_block_size_specified, has_collapsed_borders,
        LayoutResultCacheSlot::kMeasure, &space_builder);

    const auto cell_space = space_builder.ToConstraintSpace();
    const LayoutResult* layout_result = cell.Layout(cell_space);

    const LogicalBoxFragment fragment(
        table_writing_direction,
        To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment()));
    const Length& cell_specified_block_length =
        IsParallelWritingMode(table_writing_direction.GetWritingMode(),
                              cell_style.GetWritingMode())
            ? cell_style.LogicalHeight()
            : cell_style.LogicalWidth();

    bool has_descendant_that_depends_on_percentage_block_size =
        layout_result->HasDescendantThatDependsOnPercentageBlockSize();
    bool has_effective_rowspan = effective_rowspan > 1;

    TableTypes::CellBlockConstraint cell_block_constraint = {
        fragment.BlockSize(),
        cell_borders,
        colspan_cell_tabulator->CurrentColumn(),
        effective_rowspan,
        cell_specified_block_length.IsFixed(),
        has_descendant_that_depends_on_percentage_block_size};
    colspan_cell_tabulator->ProcessCell(cell);
    cell_block_constraints->push_back(cell_block_constraint);
    is_constrained |=
        cell_block_constraint.is_constrained && !has_effective_rowspan;
    row_baseline_tabulator.ProcessCell(
        fragment, ComputeContentAlignmentForTableCell(cell_style),
        has_effective_rowspan,
        has_descendant_that_depends_on_percentage_block_size);

    // Compute cell's css block size.
    std::optional<LayoutUnit> cell_css_block_size;
    std::optional<float> cell_css_percent;

    // TODO(1105272) Handle cell_specified_block_length.IsCalculated()
    if (cell_specified_block_length.IsPercent()) {
      cell_css_percent = cell_specified_block_length.Percent();
    } else if (cell_specified_block_length.IsFixed()) {
      // NOTE: Ignore min/max-height for determining the |cell_css_block_size|.
      BoxStrut cell_padding = ComputePadding(cell_space, cell_style);
      BoxStrut border_padding = cell_borders + cell_padding;
      // https://quirks.spec.whatwg.org/#the-table-cell-height-box-sizing-quirk
      if (cell.GetDocument().InQuirksMode() ||
          cell_style.BoxSizing() == EBoxSizing::kBorderBox) {
        cell_css_block_size =
            std::max(border_padding.BlockSum(),
                     LayoutUnit(cell_specified_block_length.Value()));
      } else {
        cell_css_block_size = border_padding.BlockSum() +
                              LayoutUnit(cell_specified_block_length.Value());
      }
    }

    if (!has_effective_rowspan) {
      if (cell_css_block_size || cell_css_percent)
        is_constrained = true;
      if (cell_css_percent)
        row_percent = std::max(row_percent.value_or(0), *cell_css_percent);
      // Cell's block layout ignores CSS block size properties. Row must use it
      // to compute it's minimum block size.
      max_cell_block_size =
          std::max({max_cell_block_size, cell_block_constraint.min_block_size,
                    cell_css_block_size.value_or(LayoutUnit())});
    } else {
      has_rowspan_start = true;
      LayoutUnit min_block_size = cell_block_constraint.min_block_size;
      if (cell_css_block_size)
        min_block_size = std::max(min_block_size, *cell_css_block_size);
      rowspan_cells->push_back(TableTypes::RowspanCell{
          row_index, effective_rowspan, min_block_size});
    }
  }

  // Apply row's CSS block size.
  const Length& row_specified_block_length = row.Style().LogicalHeight();
  if (row_specified_block_length.IsPercent()) {
    is_constrained = true;
    row_percent =
        std::max(row_percent.value_or(0), row_specified_block_length.Percent());
  } else if (row_specified_block_length.IsFixed()) {
    is_constrained = true;
    max_cell_block_size = std::max(
        LayoutUnit(row_specified_block_length.Value()), max_cell_block_size);
  }

  const LayoutUnit row_block_size =
      row_baseline_tabulator.ComputeRowBlockSize(max_cell_block_size);
  std::optional<LayoutUnit> row_baseline;
  if (!row_baseline_tabulator.BaselineDependsOnPercentageBlockDescendant())
    row_baseline = row_baseline_tabulator.ComputeBaseline(row_block_size);

  return TableTypes::Row{
      row_block_size,
      start_cell_index,
      cell_block_constraints->size() - start_cell_index,
      row_baseline,
      row_percent,
      is_constrained,
      has_rowspan_start,
      /* is_collapsed */ is_section_collapsed ||
          row.Style().Visibility() == EVisibility::kCollapse};
}

// Computes inline constraints for COLGROUP/COLs.
class ColumnConstraintsBuilder {
 public:
  void VisitCol(const LayoutInputNode& column,
                wtf_size_t start_column_index,
                wtf_size_t span) {
    // COL creates SPAN constraints. Its width is col css width, or enclosing
    // colgroup css width.
    TableTypes::Column col_constraint =
        TableTypes::CreateColumn(column.Style(),
                                 !is_fixed_layout_ && colgroup_constraint_
                                     ? colgroup_constraint_->max_inline_size
                                     : std::nullopt,
                                 is_fixed_layout_);
    for (wtf_size_t i = 0; i < span; ++i)
      column_constraints_->data.push_back(col_constraint);
    column.GetLayoutBox()->ClearNeedsLayout();
  }

  void EnterColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index) {
    colgroup_constraint_ = TableTypes::CreateColumn(
        colgroup.Style(), std::nullopt, is_fixed_layout_);
  }

  void LeaveColgroup(const LayoutInputNode& colgroup,
                     wtf_size_t start_column_index,
                     wtf_size_t span,
                     bool has_children) {
    if (!has_children) {
      for (wtf_size_t i = 0; i < span; ++i)
        column_constraints_->data.push_back(*colgroup_constraint_);
    }
    colgroup_constraint_.reset();
    colgroup.GetLayoutBox()->ClearNeedsLayout();
    To<LayoutTableColumn>(colgroup.GetLayoutBox())
        ->ClearNeedsLayoutForChildren();
  }

  ColumnConstraintsBuilder(TableTypes::Columns* column_constraints,
                           bool is_fixed_layout)
      : column_constraints_(column_constraints),
        is_fixed_layout_(is_fixed_layout) {}

 private:
  TableTypes::Columns* column_constraints_;
  bool is_fixed_layout_;
  std::optional<TableTypes::Column> colgroup_constraint_;
};

// Computes constraints specified on column elements.
void ComputeColumnElementConstraints(const HeapVector<BlockNode>& columns,
                                     bool is_fixed_layout,
                                     TableTypes::Columns* column_constraints) {
  ColumnConstraintsBuilder constraints_builder(column_constraints,
                                               is_fixed_layout);
  // |table_column_count| is UINT_MAX because columns will get trimmed later.
  VisitLayoutTableColumn(columns, UINT_MAX, &constraints_builder);
}

void ComputeSectionInlineConstraints(
    const BlockNode& section,
    bool is_fixed_layout,
    bool is_first_section,
    WritingDirectionMode table_writing_direction,
    const TableBorders& table_borders,
    wtf_size_t section_index,
    wtf_size_t* row_index,
    TableTypes::CellInlineConstraints* cell_inline_constraints,
    TableTypes::ColspanCells* colspan_cell_inline_constraints) {
  ColspanCellTabulator colspan_cell_tabulator;
  bool is_first_row = true;
  for (BlockNode row = To<BlockNode>(section.FirstChild()); row;
       row = To<BlockNode>(row.NextSibling())) {
    colspan_cell_tabulator.StartRow();

    // Gather constraints for each cell, and merge them into
    // CellInlineConstraints.
    for (BlockNode cell = To<BlockNode>(row.FirstChild()); cell;
         cell = To<BlockNode>(cell.NextSibling())) {
      colspan_cell_tabulator.FindNextFreeColumn();
      wtf_size_t colspan = cell.TableCellColspan();

      bool ignore_because_of_fixed_layout =
          is_fixed_layout && (!is_first_section || !is_first_row);

      wtf_size_t max_column = ComputeMaxColumn(
          colspan_cell_tabulator.CurrentColumn(), colspan, is_fixed_layout);
      if (max_column >= cell_inline_constraints->size())
        cell_inline_constraints->Grow(max_column);
      if (!ignore_because_of_fixed_layout) {
        BoxStrut cell_border = table_borders.CellBorder(
            cell, *row_index, colspan_cell_tabulator.CurrentColumn(),
            section_index, table_writing_direction);
        BoxStrut cell_padding = table_borders.CellPaddingForMeasure(
            cell.Style(), table_writing_direction);
        TableTypes::CellInlineConstraint cell_constraint =
            TableTypes::CreateCellInlineConstraint(
                cell, table_writing_direction, is_fixed_layout, cell_border,
                cell_padding);
        if (colspan == 1) {
          std::optional<TableTypes::CellInlineConstraint>& constraint =
              (*cell_inline_constraints)[colspan_cell_tabulator
                                             .CurrentColumn()];
          // Standard cell, update final column inline size values.
          if (constraint.has_value()) {
            constraint->Encompass(cell_constraint);
          } else {
            constraint = cell_constraint;
          }
        } else {
          colspan_cell_inline_constraints->emplace_back(
              cell_constraint, colspan_cell_tabulator.CurrentColumn(), colspan);
        }
      }
      colspan_cell_tabulator.ProcessCell(cell);
    }
    is_first_row = false;
    *row_index += 1;
    colspan_cell_tabulator.EndRow();
  }
}

// Implements spec distribution algorithm:
// https://www.w3.org/TR/css-tables-3/#width-distribution-algorithm
// |treat_target_size_as_constrained| constrained target can grow fixed-width
// columns. unconstrained target cannot grow fixed-width columns beyond
// specified size.
Vector<LayoutUnit> DistributeInlineSizeToComputedInlineSizeAuto(
    LayoutUnit target_inline_size,
    const TableTypes::Column* start_column,
    const TableTypes::Column* end_column,
    const bool treat_target_size_as_constrained) {
  unsigned all_columns_count = 0;
  unsigned percent_columns_count = 0;
  unsigned fixed_columns_count = 0;
  unsigned auto_columns_count = 0;
  // What guesses mean is described in table specification.
  // https://www.w3.org/TR/css-tables-3/#width-distribution-algorithm
  enum { kMinGuess, kPercentageGuess, kSpecifiedGuess, kMaxGuess, kAboveMax };
  // sizes are collected for all guesses except kAboveMax
  LayoutUnit guess_sizes[kAboveMax];
  LayoutUnit guess_size_total_increases[kAboveMax];
  float total_percent = 0.0f;
  LayoutUnit total_auto_max_inline_size;
  LayoutUnit total_fixed_max_inline_size;

  for (const TableTypes::Column* column = start_column; column != end_column;
       ++column) {
    all_columns_count++;
    DCHECK(column->min_inline_size);
    DCHECK(column->max_inline_size);

    // Mergeable columns are ignored.
    if (column->is_mergeable) {
      continue;
    }

    if (column->percent) {
      percent_columns_count++;
      total_percent += *column->percent;
      LayoutUnit percent_inline_size =
          column->ResolvePercentInlineSize(target_inline_size);
      guess_sizes[kMinGuess] += *column->min_inline_size;
      guess_sizes[kPercentageGuess] += percent_inline_size;
      guess_sizes[kSpecifiedGuess] += percent_inline_size;
      guess_sizes[kMaxGuess] += percent_inline_size;
      guess_size_total_increases[kPercentageGuess] +=
          percent_inline_size - *column->min_inline_size;
    } else if (column->is_constrained) {  // Fixed column
      fixed_columns_count++;
      total_fixed_max_inline_size += *column->max_inline_size;
      guess_sizes[kMinGuess] += *column->min_inline_size;
      guess_sizes[kPercentageGuess] += *column->min_inline_size;
      guess_sizes[kSpecifiedGuess] += *column->max_inline_size;
      guess_sizes[kMaxGuess] += *column->max_inline_size;
      guess_size_total_increases[kSpecifiedGuess] +=
          *column->max_inline_size - *column->min_inline_size;
    } else {  // Auto column
      auto_columns_count++;
      total_auto_max_inline_size += *column->max_inline_size;
      guess_sizes[kMinGuess] += *column->min_inline_size;
      guess_sizes[kPercentageGuess] += *column->min_inline_size;
      guess_sizes[kSpecifiedGuess] += *column->min_inline_size;
      guess_sizes[kMaxGuess] += *column->max_inline_size;
      guess_size_total_increases[kMaxGuess] +=
          *column->max_inline_size - *column->min_inline_size;
    }
  }

  Vector<LayoutUnit> computed_sizes;
  computed_sizes.resize(all_columns_count);

  // Distributing inline sizes can never cause cells to be < min_inline_size.
  // Target inline size must be wider than sum of min inline sizes.
  // This is always true for assignable_table_inline_size, but not for
  // colspan_cells.
  target_inline_size = std::max(target_inline_size, guess_sizes[kMinGuess]);

  unsigned starting_guess = kAboveMax;
  for (unsigned i = kMinGuess; i != kAboveMax; ++i) {
    if (guess_sizes[i] >= target_inline_size) {
      starting_guess = i;
      break;
    }
  }

  switch (starting_guess) {
    case kMinGuess: {
      // All columns are their min inline-size.
      LayoutUnit* computed_size = computed_sizes.data();
      for (const TableTypes::Column* column = start_column;
           column != end_column; ++column, ++computed_size) {
        if (column->is_mergeable) {
          continue;
        }
        *computed_size = column->min_inline_size.value_or(LayoutUnit());
      }
    } break;
    case kPercentageGuess: {
      // Percent columns grow in proportion to difference between their
      // percentage size and their minimum size.
      LayoutUnit percent_inline_size_increase =
          guess_size_total_increases[kPercentageGuess];
      LayoutUnit distributable_inline_size =
          target_inline_size - guess_sizes[kMinGuess];
      LayoutUnit remaining_deficit = distributable_inline_size;
      LayoutUnit* computed_size = computed_sizes.data();
      LayoutUnit* last_computed_size = nullptr;
      for (const TableTypes::Column* column = start_column;
           column != end_column; ++column, ++computed_size) {
        if (column->is_mergeable) {
          continue;
        }
        if (column->percent) {
          last_computed_size = computed_size;
          LayoutUnit percent_inline_size =
              column->ResolvePercentInlineSize(target_inline_size);
          LayoutUnit column_inline_size_increase =
              percent_inline_size - *column->min_inline_size;
          LayoutUnit delta;
          if (percent_inline_size_increase > LayoutUnit()) {
            delta = distributable_inline_size.MulDiv(
                column_inline_size_increase, percent_inline_size_increase);
          } else {
            delta = distributable_inline_size / percent_columns_count;
          }
          remaining_deficit -= delta;
          *computed_size = *column->min_inline_size + delta;
        } else {
          // Auto/Fixed columns get their min inline-size.
          *computed_size = *column->min_inline_size;
        }
      }
      if (remaining_deficit != LayoutUnit()) {
        DCHECK(last_computed_size);
        *last_computed_size += remaining_deficit;
      }
    } break;
    case kSpecifiedGuess: {
      // Fixed columns grow, auto gets min, percent gets %max.
      LayoutUnit fixed_inline_size_increase =
          guess_size_total_increases[kSpecifiedGuess];
      LayoutUnit distributable_inline_size =
          target_inline_size - guess_sizes[kPercentageGuess];
      LayoutUnit remaining_deficit = distributable_inline_size;
      LayoutUnit* last_computed_size = nullptr;
      LayoutUnit* computed_size = computed_sizes.data();
      for (const TableTypes::Column* column = start_column;
           column != end_column; ++column, ++computed_size) {
        if (column->is_mergeable) {
          continue;
        }
        if (column->percent) {
          *computed_size = column->ResolvePercentInlineSize(target_inline_size);
        } else if (column->is_constrained) {
          last_computed_size = computed_size;
          LayoutUnit column_inline_size_increase =
              *column->max_inline_size - *column->min_inline_size;
          LayoutUnit delta;
          if (fixed_inline_size_increase > LayoutUnit()) {
            delta = distributable_inline_size.MulDiv(
                column_inline_size_increase, fixed_inline_size_increase);
          } else {
            delta = distributable_inline_size / fixed_columns_count;
          }
          remaining_deficit -= delta;
          *computed_size = *column->min_inline_size + delta;
        } else {
          *computed_size = *column->min_inline_size;
        }
      }
      if (remaining_deficit != LayoutUnit()) {
        DCHECK(last_computed_size);
        *last_computed_size += remaining_deficit;
      }
    } break;
    case kMaxGuess: {
      // Auto columns grow, fixed gets max, percent gets %max.
      LayoutUnit auto_inline_size_increase =
          guess_size_total_increases[kMaxGuess];
      LayoutUnit distributable_inline_size =
          target_inline_size - guess_sizes[kSpecifiedGuess];
      // When the inline-sizes match exactly, this usually means that table
      // inline-size is auto, and that columns should be wide enough to
      // accommodate content without wrapping.
      // Instead of using the distributing math to compute final column
      // inline-size, we use the max inline-size. Using distributing math can
      // cause rounding errors, and unintended line wrap.
      bool is_exact_match = target_inline_size == guess_sizes[kMaxGuess];
      LayoutUnit remaining_deficit =
          is_exact_match ? LayoutUnit() : distributable_inline_size;
      LayoutUnit* last_computed_size = nullptr;
      LayoutUnit* computed_size = computed_sizes.data();
      for (const TableTypes::Column* column = start_column;
           column != end_column; ++column, ++computed_size) {
        if (column->is_mergeable) {
          continue;
        }
        if (column->percent) {
          *computed_size = column->ResolvePercentInlineSize(target_inline_size);
        } else if (column->is_constrained || is_exact_match) {
          *computed_size = *column->max_inline_size;
        } else {
          last_computed_size = computed_size;
          LayoutUnit column_inline_size_increase =
              *column->max_inline_size - *column->min_inline_size;
          LayoutUnit delta;
          if (auto_inline_size_increase > LayoutUnit()) {
            delta = distributable_inline_size.MulDiv(
                column_inline_size_increase, auto_inline_size_increase);
          } else {
            delta = distributable_inline_size / auto_columns_count;
          }
          remaining_deficit -= delta;
          *computed_size = *column->min_inline_size + delta;
        }
      }
      if (remaining_deficit != LayoutUnit()) {
        DCHECK(last_computed_size);
        *last_computed_size += remaining_deficit;
      }
    } break;
    case kAboveMax: {
      LayoutUnit distributable_inline_size =
          target_inline_size - guess_sizes[kMaxGuess];
      if (auto_columns_count > 0) {
        // Grow auto columns if available.
        LayoutUnit remaining_deficit = distributable_inline_size;
        LayoutUnit* last_computed_size = nullptr;
        LayoutUnit* computed_size = computed_sizes.data();
        for (const TableTypes::Column* column = start_column;
             column != end_column; ++column, ++computed_size) {
          if (column->is_mergeable) {
            continue;
          }
          if (column->percent) {
            *computed_size =
                column->ResolvePercentInlineSize(target_inline_size);
          } else if (column->is_constrained) {
            *computed_size = *column->max_inline_size;
          } else {
            last_computed_size = computed_size;
            LayoutUnit delta;
            if (total_auto_max_inline_size > LayoutUnit()) {
              delta = distributable_inline_size.MulDiv(
                  *column->max_inline_size, total_auto_max_inline_size);
            } else {
              delta = distributable_inline_size / auto_columns_count;
            }
            remaining_deficit -= delta;
            *computed_size = *column->max_inline_size + delta;
          }
        }
        if (remaining_deficit != LayoutUnit()) {
          DCHECK(last_computed_size);
          *last_computed_size += remaining_deficit;
        }
      } else if (fixed_columns_count > 0 && treat_target_size_as_constrained) {
        // Grow fixed columns if available.
        LayoutUnit remaining_deficit = distributable_inline_size;
        LayoutUnit* last_computed_size = nullptr;
        LayoutUnit* computed_size = computed_sizes.data();
        for (const TableTypes::Column* column = start_column;
             column != end_column; ++column, ++computed_size) {
          if (column->is_mergeable) {
            continue;
          }
          if (column->percent) {
            *computed_size =
                column->ResolvePercentInlineSize(target_inline_size);
          } else if (column->is_constrained) {
            last_computed_size = computed_size;
            LayoutUnit delta;
            if (total_fixed_max_inline_size > LayoutUnit()) {
              delta = distributable_inline_size.MulDiv(
                  *column->max_inline_size, total_fixed_max_inline_size);
            } else {
              delta = distributable_inline_size / fixed_columns_count;
            }
            remaining_deficit -= delta;
            *computed_size = *column->max_inline_size + delta;
          } else {
            NOTREACHED();
          }
        }
        if (remaining_deficit != LayoutUnit()) {
```