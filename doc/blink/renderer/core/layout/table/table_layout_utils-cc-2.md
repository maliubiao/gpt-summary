Response:
The user wants to understand the functionality of the `table_layout_utils.cc` file in the Chromium Blink engine. I need to go through the code and identify its main purpose and the individual functions. I also need to explain the relationship to web technologies like JavaScript, HTML, and CSS, provide examples for assumptions and potential user/developer errors. Finally, I need to summarize the overall functionality of the code.

Here's a breakdown of how I'll approach this:

1. **Identify Core Functionality:**  Scan the code for keywords and function names that suggest the main tasks performed by the file. It seems to be heavily involved in calculating and distributing sizes related to table layout (columns, rows, cells, sections).

2. **Analyze Individual Functions:**  Go through each function and determine its specific role in the table layout process.

3. **Relate to Web Technologies:**
    * **HTML:**  How does this code relate to the structure of HTML tables (e.g., `<table>`, `<tr>`, `<td>`, `<th>`, `<thead>`, `<tbody>`, `<tfoot>`)?
    * **CSS:** How does this code relate to CSS properties that affect table layout (e.g., `width`, `height`, `border-spacing`, `empty-cells`, `vertical-align`, `table-layout`)?
    * **JavaScript:**  While this C++ code doesn't directly interact with JavaScript, how do the layout calculations eventually impact what a JavaScript developer might see or interact with (e.g., getting element dimensions)?

4. **Develop Hypothetical Inputs and Outputs:** For some key functions, imagine sample input values and predict the expected output. This will help illustrate the logic.

5. **Identify Potential Errors:** Think about common mistakes developers or users might make when creating tables or styling them that this code handles or could be affected by.

6. **Address the "Part 3" Request:**  Since this is the last of a multi-part response, I need to ensure this summary is comprehensive and integrates with the knowledge likely built up in the previous parts.

7. **Structure the Response:** Organize the findings into clear sections addressing each part of the user's request.
好的，这是 `blink/renderer/core/layout/table/table_layout_utils.cc` 文件的第三部分内容的功能归纳：

**总功能归纳：**

这部分代码主要负责表格布局的**后期调整和尺寸分配**，尤其关注于处理跨列（colspan）、跨行（rowspan）的单元格以及表格分段（sections）的尺寸分配。它在表格的最终布局阶段，根据之前计算的约束和特性，对表格的列宽、行高以及分段高度进行最终的调整和分配，以确保表格按照 CSS 规范正确渲染。

**具体功能分解：**

1. **`FinalizeTableCellLayout` 函数:**
   - **功能:** 最终确定表格单元格的布局属性。
   - **与 CSS 的关系:**
     - 处理 `empty-cells: hide` 属性，根据单元格是否为空且边框未折叠来决定是否隐藏单元格。
     - 处理 `vertical-align` 属性，根据属性值（如 `baseline`, `top`, `middle`, `bottom` 等）调整单元格内子元素在垂直方向上的位置。
     - 处理表格边框折叠 (`border-collapse: collapse`) 的情况，设置 `HasCollapsedBorders` 标记。
   - **假设输入与输出:**
     - **假设输入:** 一个 `BoxFragmentBuilder` 对象，其中包含单元格的样式信息（例如 `empty-cells: hide`, `vertical-align: baseline`），以及单元格是否包含子元素的信息。
     - **输出:**  `BoxFragmentBuilder` 对象被修改，`IsHiddenForPaint` 标志被设置（如果需要隐藏），子元素的位置可能被调整。
   - **用户或编程常见错误:**
     - 错误地认为设置了 `empty-cells: hide` 就可以隐藏所有空的单元格，但没有考虑到边框折叠的情况。如果边框折叠，`empty-cells: hide` 不会生效。

2. **`ColspanCellTabulator` 类及其方法:**
   - **功能:** 管理跨列单元格，在行布局时跟踪哪些列被跨列单元格占用，以便后续单元格能找到下一个可用的列位置。
   - **假设输入与输出:**
     - **`StartRow()`:**  开始处理新的一行，将当前列重置为 0。
     - **`ProcessCell(const BlockNode& cell)`:** 处理一个单元格，如果该单元格是跨列的，则记录其起始列和跨越的列数。
     - **`FindNextFreeColumn()`:**  查找当前可用的下一个空闲列。如果当前列被之前的跨列单元格占用，则将当前列移动到跨列单元格结束之后。
     - **`EndRow()`:**  结束当前行的处理，减少所有记录的跨列单元格的剩余行数，并移除已完成跨越的单元格。
   - **与 HTML 的关系:**  与 `colspan` 属性直接相关。
   - **用户或编程常见错误:**
     - 手动计算跨列单元格的位置，导致与浏览器的自动布局不一致。

3. **`RowBaselineTabulator` 类及其方法:**
   - **功能:** 用于计算基于基线的行高。它跟踪当前行中基线最高的单元格，并以此来确定行的基线和最小高度。
   - **与 CSS 的关系:**  与 `vertical-align: baseline` 属性直接相关。
   - **假设输入与输出:**
     - **`ProcessCell(...)`:** 处理一个单元格，如果单元格的垂直对齐方式是基线，则记录其基线位置，并更新当前行的最大上升高度和下降高度。
     - **`ComputeRowBlockSize(const LayoutUnit max_cell_block_size)`:** 根据计算出的最大上升和下降高度，以及行内最大单元格高度，计算行的最终高度。
     - **`ComputeBaseline(const LayoutUnit row_block_size)`:**  计算行的基线位置。
   - **用户或编程常见错误:**
     - 对基线对齐的理解不足，导致预期和实际的垂直对齐效果不符。例如，认为所有单元格的文字都会在同一条线上，但实际上基线是相对于单元格的内容区域而言的。

4. **`ComputeGridInlineMinMax` 函数:**
   - **功能:** 计算表格网格的最小和最大内联尺寸（宽度）。它考虑了列约束（最小宽度、最大宽度、百分比宽度）以及不可分配的空间。
   - **与 CSS 的关系:**  与表格和列的宽度属性 (`width`) 以及 `table-layout: fixed` 相关。
   - **假设输入与输出:**
     - **假设输入:** `TableNode` 对象，包含列约束信息的 `column_constraints`，以及其他布局相关的参数。
     - **输出:**  一个 `MinMaxSizes` 对象，包含表格的最小和最大内联尺寸。

5. **`DistributeColspanCellsToColumns` 函数:**
   - **功能:** 将跨列单元格的需求分配到列约束中，影响列的最小和最大宽度。
   - **与 HTML 的关系:** 与 `colspan` 属性相关。

6. **`SynchronizeAssignableTableInlineSizeAndColumns` 函数:**
   - **功能:** 同步可分配的表格内联尺寸和列的计算内联尺寸。确保表格的总宽度与所有列宽之和一致。
   - **与 CSS 的关系:** 与表格的 `width` 属性和 `table-layout` 属性相关。

7. **`DistributeRowspanCellToRows` 函数:**
   - **功能:** 将跨行单元格的最小高度需求分配到行约束中，影响行的最小高度。
   - **与 HTML 的关系:** 与 `rowspan` 属性相关。

8. **`DistributeSectionFixedBlockSizeToRows` 函数:**
   - **功能:** 将表格分段的固定高度分配到行。

9. **`DistributeTableBlockSizeToSections` 函数:**
   - **功能:** 将表格的总块级尺寸（高度）分配到各个表格分段（thead, tbody, tfoot）。它会考虑分段的最小高度、百分比高度以及自动高度的情况，并根据一定的优先级规则进行分配。
   - **与 HTML 的关系:**  与 `<table>`, `<thead>`, `<tbody>`, `<tfoot>` 标签以及它们的 `height` 属性相关。
   - **假设输入与输出:**
     - **假设输入:** 表格边框间距、表格总高度、表格分段信息（`sections`）、行信息（`rows`）。
     - **输出:**  修改 `sections` 中每个分段的块级尺寸，并根据新的分段尺寸更新 `rows` 中受影响行的块级尺寸。

**用户或编程常见错误示例：**

- **表格高度分配错误:**  用户可能期望通过设置 `<table>` 的 `height` 属性来精确控制所有行的总高度，但实际上，浏览器会根据内容和各个分段的约束进行分配，`<table>` 的 `height` 更像是一个目标高度。
- **分段高度冲突:**  用户可能同时为 `<thead>`, `<tbody>`, `<tfoot>` 设置了百分比高度，但它们的总和超过 100%，导致浏览器需要根据规则进行调整，最终结果可能不符合预期。
- **跨行/跨列单元格影响布局:**  用户可能没有充分考虑到跨行/跨列单元格对其他单元格尺寸和位置的影响，导致布局混乱。

总而言之，这部分代码是 Blink 引擎表格布局机制中非常核心的部分，它负责将抽象的布局约束转化为具体的尺寸和位置，确保 HTML 表格能够按照 CSS 规范正确地渲染在浏览器中。

Prompt: 
```
这是目录为blink/renderer/core/layout/table/table_layout_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
ck_size,
          block_border_spacing, section_fixed_block_size, rows);
      section_block_size = section_fixed_block_size;
    }
  }
  sections->push_back(
      TableTypes::CreateSection(section, start_row, current_row - start_row,
                                section_block_size, treat_section_as_tbody));
}

void FinalizeTableCellLayout(LayoutUnit unconstrained_intrinsic_block_size,
                             BoxFragmentBuilder* builder) {
  const BlockNode& node = builder->Node();
  const auto& space = builder->GetConstraintSpace();
  const bool has_inflow_children = !builder->Children().empty();

  // Hide table-cells if:
  //  - They are within a collapsed column(s). These are already marked as
  //    hidden for paint in the constraint space, and don't need to be marked
  //    again in the fragment builder.
  //  - They have "empty-cells: hide", non-collapsed borders, and no children.
  if (!space.IsHiddenForPaint()) {
    builder->SetIsHiddenForPaint(space.HideTableCellIfEmpty() &&
                                 !has_inflow_children);
  }
  builder->SetHasCollapsedBorders(space.IsTableCellWithCollapsedBorders());
  builder->SetIsTablePart();
  builder->SetTableCellColumnIndex(space.TableCellColumnIndex());

  // If we're resuming after a break, there'll be no alignment, since the
  // fragment will start at the block-start edge of the fragmentainer then.
  if (IsBreakInside(builder->PreviousBreakToken()))
    return;

  LayoutUnit free_space =
      builder->FragmentBlockSize() - unconstrained_intrinsic_block_size;
  BlockContentAlignment alignment = ComputeContentAlignmentForTableCell(
      builder->Style(), &builder->Node().GetDocument());
  if (alignment == BlockContentAlignment::kSafeCenter ||
      alignment == BlockContentAlignment::kSafeEnd) {
    free_space = free_space.ClampNegativeToZero();
  }
  switch (alignment) {
    case BlockContentAlignment::kStart:
      // Nothing to do.
      break;
    case BlockContentAlignment::kBaseline:
      // Table-cells (with baseline vertical alignment) always produce a
      // first/last baseline of their end-content edge (even if the content
      // doesn't have any baselines).
      if (!builder->FirstBaseline() || node.ShouldApplyLayoutContainment()) {
        builder->SetBaselines(unconstrained_intrinsic_block_size -
                              builder->BorderScrollbarPadding().block_end);
      }

      // Only adjust if we have *inflow* children. If we only have
      // OOF-positioned children don't align them to the alignment baseline.
      if (has_inflow_children) {
        if (auto alignment_baseline = space.TableCellAlignmentBaseline()) {
          builder->MoveChildrenInBlockDirection(*alignment_baseline -
                                                *builder->FirstBaseline());
        }
      }
      break;
    case BlockContentAlignment::kSafeCenter:
    case BlockContentAlignment::kUnsafeCenter:
      builder->MoveChildrenInBlockDirection(free_space / 2);
      break;
    case BlockContentAlignment::kSafeEnd:
    case BlockContentAlignment::kUnsafeEnd:
      builder->MoveChildrenInBlockDirection(free_space);
      break;
  }
}

void ColspanCellTabulator::StartRow() {
  current_column_ = 0;
}

// Remove colspanned cells that are not spanning any more rows.
void ColspanCellTabulator::EndRow() {
  for (wtf_size_t i = 0; i < colspanned_cells_.size();) {
    colspanned_cells_[i].remaining_rows--;
    if (colspanned_cells_[i].remaining_rows == 0)
      colspanned_cells_.EraseAt(i);
    else
      ++i;
  }
  std::sort(colspanned_cells_.begin(), colspanned_cells_.end(),
            [](const ColspanCellTabulator::Cell& a,
               const ColspanCellTabulator::Cell& b) {
              return a.column_start < b.column_start;
            });
}

// Advance current column to position not occupied by colspanned cells.
void ColspanCellTabulator::FindNextFreeColumn() {
  for (const Cell& colspanned_cell : colspanned_cells_) {
    if (colspanned_cell.column_start <= current_column_ &&
        colspanned_cell.column_start + colspanned_cell.span > current_column_) {
      current_column_ = colspanned_cell.column_start + colspanned_cell.span;
    }
  }
}

void ColspanCellTabulator::ProcessCell(const BlockNode& cell) {
  wtf_size_t colspan = cell.TableCellColspan();
  wtf_size_t rowspan = cell.TableCellRowspan();
  if (rowspan > 1)
    colspanned_cells_.emplace_back(current_column_, colspan, rowspan);
  current_column_ += colspan;
}

void RowBaselineTabulator::ProcessCell(
    const LogicalBoxFragment& fragment,
    BlockContentAlignment align,
    const bool is_rowspanned,
    const bool descendant_depends_on_percentage_block_size) {
  if (align == BlockContentAlignment::kBaseline &&
      fragment.HasDescendantsForTablePart() && fragment.FirstBaseline()) {
    max_cell_baseline_depends_on_percentage_block_descendant_ |=
        descendant_depends_on_percentage_block_size;
    const LayoutUnit cell_baseline = *fragment.FirstBaseline();
    max_cell_ascent_ =
        std::max(max_cell_ascent_.value_or(LayoutUnit::Min()), cell_baseline);
    if (is_rowspanned) {
      if (!max_cell_descent_)
        max_cell_descent_ = LayoutUnit();
    } else {
      max_cell_descent_ =
          std::max(max_cell_descent_.value_or(LayoutUnit::Min()),
                   fragment.BlockSize() - cell_baseline);
    }
  }

  // https://www.w3.org/TR/css-tables-3/#row-layout "If there is no such
  // line box or table-row, the baseline is the bottom of content edge of
  // the cell box."
  if (!max_cell_ascent_) {
    fallback_cell_depends_on_percentage_block_descendant_ |=
        descendant_depends_on_percentage_block_size;
    const LayoutUnit cell_block_end_border_padding =
        fragment.Padding().block_end + fragment.Borders().block_end;
    fallback_cell_descent_ =
        std::min(fallback_cell_descent_.value_or(LayoutUnit::Max()),
                 cell_block_end_border_padding);
  }
}

LayoutUnit RowBaselineTabulator::ComputeRowBlockSize(
    const LayoutUnit max_cell_block_size) {
  if (max_cell_ascent_) {
    return std::max(max_cell_block_size,
                    *max_cell_ascent_ + *max_cell_descent_);
  }
  return max_cell_block_size;
}

LayoutUnit RowBaselineTabulator::ComputeBaseline(
    const LayoutUnit row_block_size) {
  if (max_cell_ascent_)
    return *max_cell_ascent_;
  if (fallback_cell_descent_)
    return (row_block_size - *fallback_cell_descent_).ClampNegativeToZero();
  // Empty row's baseline is top.
  return LayoutUnit();
}

bool RowBaselineTabulator::BaselineDependsOnPercentageBlockDescendant() {
  if (max_cell_ascent_)
    return max_cell_baseline_depends_on_percentage_block_descendant_;
  if (fallback_cell_descent_)
    return fallback_cell_depends_on_percentage_block_descendant_;
  return false;
}

MinMaxSizes ComputeGridInlineMinMax(
    const TableNode& node,
    const TableTypes::Columns& column_constraints,
    LayoutUnit undistributable_space,
    bool is_fixed_layout,
    bool is_layout_pass) {
  MinMaxSizes min_max;
  // https://www.w3.org/TR/css-tables-3/#computing-the-table-width
  // Compute standard GRID_MIN/GRID_MAX. They are sum of column_constraints.
  //
  // Standard does not specify how to handle percentages.
  // "a percentage represents a constraint on the column's inline size, which a
  // UA should try to satisfy"
  // Percentages cannot be resolved into pixels because size of containing
  // block is unknown. Instead, percentages are used to enforce following
  // constraints:
  // 1) Column min inline size and percentage imply that total inline sum must
  // be large enough to fit the column. Mathematically, column with
  // min_inline_size of X, and percentage Y% implies that the
  // total inline sum MINSUM must satisfy: MINSUM * Y% >= X.
  // 2) Let T% be sum of all percentages. Let M be sum of min_inline_sizes of
  // all non-percentage columns. Total min size sum MINSUM must satisfy:
  // T% * MINSUM + M = MINSUM.

  // Minimum total size estimate based on column's min_inline_size and percent.
  LayoutUnit percent_max_size_estimate;
  // Sum of max_inline_sizes of non-percentage columns.
  LayoutUnit non_percent_max_size_sum;
  float percent_sum = 0;
  for (const TableTypes::Column& column : column_constraints.data) {
    if (column.min_inline_size) {
      // In fixed layout, constrained cells minimum inline size is their
      // maximum.
      if (is_fixed_layout && column.IsFixed()) {
        min_max.min_size += *column.max_inline_size;
      } else {
        min_max.min_size += *column.min_inline_size;
      }
      if (column.percent && *column.percent > 0) {
        if (*column.max_inline_size > LayoutUnit()) {
          LayoutUnit estimate = LayoutUnit(
              100 / *column.percent *
              (*column.max_inline_size - column.percent_border_padding));
          percent_max_size_estimate =
              std::max(percent_max_size_estimate, estimate);
        }
      } else {
        non_percent_max_size_sum += *column.max_inline_size;
      }
    }
    if (column.max_inline_size) {
      min_max.max_size += *column.max_inline_size;
    }
    if (column.percent) {
      percent_sum += *column.percent;
    }
  }
  // Floating point math can cause total sum to be slightly above 100%.
  DCHECK_LE(percent_sum, 100.5f);
  percent_sum = std::min(percent_sum, 100.0f);

  // Table max inline size constraint can be computed from the total column
  // percentage combined with max_inline_size of non-percent columns.
  if (percent_sum > 0 && node.AllowColumnPercentages(is_layout_pass)) {
    LayoutUnit size_from_percent_and_fixed;
    DCHECK_GE(percent_sum, 0.0f);
    if (non_percent_max_size_sum != LayoutUnit()) {
      if (percent_sum == 100.0f) {
        size_from_percent_and_fixed = TableTypes::kTableMaxInlineSize;
      } else {
        size_from_percent_and_fixed =
            LayoutUnit((100 / (100 - percent_sum)) * non_percent_max_size_sum);
      }
    }
    min_max.max_size = std::max(min_max.max_size, size_from_percent_and_fixed);
    min_max.max_size = std::max(min_max.max_size, percent_max_size_estimate);
  }

  min_max.max_size = std::max(min_max.min_size, min_max.max_size);
  min_max += undistributable_space;
  return min_max;
}

void DistributeColspanCellsToColumns(
    const TableTypes::ColspanCells& colspan_cells,
    LayoutUnit inline_border_spacing,
    bool is_fixed_layout,
    TableTypes::Columns* column_constraints) {
  for (const TableTypes::ColspanCell& colspan_cell : colspan_cells) {
    // Clipped colspanned cells can end up having a span of 1 (which is not
    // wide).
    DCHECK_GT(colspan_cell.span, 1u);

    if (is_fixed_layout) {
      DistributeColspanCellToColumnsFixed(colspan_cell, inline_border_spacing,
                                          column_constraints);
    } else {
      DistributeColspanCellToColumnsAuto(colspan_cell, inline_border_spacing,
                                         column_constraints);
    }
  }
}

// Standard: https://www.w3.org/TR/css-tables-3/#width-distribution-algorithm
// After synchroniziation, assignable table inline size and sum of column
// final inline sizes will be equal.
Vector<LayoutUnit> SynchronizeAssignableTableInlineSizeAndColumns(
    LayoutUnit assignable_table_inline_size,
    bool is_fixed_layout,
    const TableTypes::Columns& column_constraints) {
  if (column_constraints.data.empty()) {
    return Vector<LayoutUnit>();
  }
  if (is_fixed_layout) {
    return SynchronizeAssignableTableInlineSizeAndColumnsFixed(
        assignable_table_inline_size, column_constraints);
  } else {
    const TableTypes::Column* start_column = &column_constraints.data[0];
    const TableTypes::Column* end_column =
        start_column + column_constraints.data.size();
    return DistributeInlineSizeToComputedInlineSizeAuto(
        assignable_table_inline_size, start_column, end_column,
        /* treat_target_size_as_constrained */ true);
  }
}

void DistributeRowspanCellToRows(const TableTypes::RowspanCell& rowspan_cell,
                                 LayoutUnit border_block_spacing,
                                 TableTypes::Rows* rows) {
  DCHECK_GT(rowspan_cell.effective_rowspan, 1u);
  DistributeExcessBlockSizeToRows(rowspan_cell.start_row,
                                  rowspan_cell.effective_rowspan,
                                  rowspan_cell.min_block_size,
                                  /* is_rowspan_distribution */ true,
                                  border_block_spacing, kIndefiniteSize, rows);
}

// Legacy code ignores section block size.
void DistributeSectionFixedBlockSizeToRows(
    const wtf_size_t start_row,
    const wtf_size_t rowspan,
    LayoutUnit section_fixed_block_size,
    LayoutUnit border_block_spacing,
    LayoutUnit percentage_resolution_block_size,
    TableTypes::Rows* rows) {
  DistributeExcessBlockSizeToRows(start_row, rowspan, section_fixed_block_size,
                                  /* is_rowspan_distribution */ false,
                                  border_block_spacing,
                                  percentage_resolution_block_size, rows);
}

void DistributeTableBlockSizeToSections(LayoutUnit border_block_spacing,
                                        LayoutUnit table_block_size,
                                        TableTypes::Sections* sections,
                                        TableTypes::Rows* rows) {
  if (sections->empty()) {
    return;
  }

  // Determine the table's block-size which we can distribute into.
  const LayoutUnit undistributable_space =
      (sections->size() + 1) * border_block_spacing;
  const LayoutUnit distributable_table_block_size =
      (table_block_size - undistributable_space).ClampNegativeToZero();

  auto ComputePercentageSize = [&distributable_table_block_size](
                                   auto& section) {
    DCHECK(section.percent.has_value());
    return std::max(
        section.block_size,
        LayoutUnit(*section.percent * distributable_table_block_size / 100));
  };

  LayoutUnit minimum_size_guess;
  LayoutUnit percent_size_guess;
  bool has_tbody = false;

  Vector<wtf_size_t> auto_sections;
  Vector<wtf_size_t> fixed_sections;
  Vector<wtf_size_t> percent_sections;
  Vector<wtf_size_t> tbody_auto_sections;
  Vector<wtf_size_t> tbody_fixed_sections;
  Vector<wtf_size_t> tbody_percent_sections;

  LayoutUnit auto_sections_size;
  LayoutUnit fixed_sections_size;
  LayoutUnit percent_sections_size;
  LayoutUnit tbody_auto_sections_size;
  LayoutUnit tbody_fixed_sections_size;
  LayoutUnit tbody_percent_sections_size;

  // Collect all our different section types.
  for (wtf_size_t index = 0u; index < sections->size(); ++index) {
    const auto& section = sections->at(index);
    minimum_size_guess += section.block_size;
    percent_size_guess +=
        section.percent ? ComputePercentageSize(section) : section.block_size;
    has_tbody |= section.is_tbody;

    if (section.percent) {
      percent_sections.push_back(index);
      if (section.is_tbody) {
        tbody_percent_sections.push_back(index);
      }
    } else if (section.is_constrained) {
      fixed_sections.push_back(index);
      fixed_sections_size += section.block_size;
      if (section.is_tbody) {
        tbody_fixed_sections.push_back(index);
        tbody_fixed_sections_size += section.block_size;
      }
    } else {
      auto_sections.push_back(index);
      auto_sections_size += section.block_size;
      if (section.is_tbody) {
        tbody_auto_sections.push_back(index);
        tbody_auto_sections_size += section.block_size;
      }
    }
  }

  // If the sections minimum size is greater than the distributable size -
  // there isn't any free space to distribute into.
  if (distributable_table_block_size <= minimum_size_guess) {
    return;
  }

  // Grow the (all) the percent sections up to what the percent specifies, and
  // in proportion to the *difference* between their percent size, and their
  // minimum size. E.g.
  //
  // <table style="height: 100px;">
  //   <tbody style="height: 50%;"></tbody>
  // </table>
  // The above <tbody> will grow to 50px.
  //
  // <table style="height: 100px;">
  //   <thead style="height: 50%;"></thead>
  //   <tbody style="height: 50%;"><td style="height: 60px;"></td></tbody>
  //   <tfoot style="height: 50%;"></tfoot>
  // </table>
  // The sections will be [20px, 60px, 20px]. The <tbody> doesn't grow as its
  // hit its minimum, remaining space distributed according to their percent.
  if (!percent_sections.empty() && percent_size_guess > minimum_size_guess) {
    const LayoutUnit distributable_size =
        std::min(percent_size_guess, distributable_table_block_size) -
        minimum_size_guess;
    DCHECK_GE(distributable_size, LayoutUnit());
    const LayoutUnit percent_minimum_difference =
        percent_size_guess - minimum_size_guess;

    LayoutUnit remaining_deficit = distributable_size;
    for (auto& index : percent_sections) {
      auto& section = sections->at(index);
      LayoutUnit delta = distributable_size.MulDiv(
          ComputePercentageSize(section) - section.block_size,
          percent_minimum_difference);
      section.block_size += delta;
      section.needs_redistribution = true;
      remaining_deficit -= delta;
      minimum_size_guess += delta;
      percent_sections_size += section.block_size;
      if (section.is_tbody) {
        tbody_percent_sections_size += section.block_size;
      }
    }
    auto& last_section = sections->at(percent_sections.back());
    last_section.block_size += remaining_deficit;
    DCHECK_GE(last_section.block_size, LayoutUnit());
    percent_sections_size += remaining_deficit;
    minimum_size_guess += remaining_deficit;
    if (last_section.is_tbody) {
      tbody_percent_sections_size += remaining_deficit;
    }
  }

  // Decide which sections to grow, we prefer any <tbody>-like sections over
  // headers/footers. Then in order:
  //  - auto sections.
  //  - fixed sections.
  //  - percent sections.
  Vector<wtf_size_t>* sections_to_grow;
  LayoutUnit sections_size;
  if (has_tbody) {
    if (!tbody_auto_sections.empty()) {
      sections_to_grow = &tbody_auto_sections;
      sections_size = tbody_auto_sections_size;
    } else if (!tbody_fixed_sections.empty()) {
      sections_to_grow = &tbody_fixed_sections;
      sections_size = tbody_fixed_sections_size;
    } else {
      DCHECK(!tbody_percent_sections.empty());
      sections_to_grow = &tbody_percent_sections;
      sections_size = tbody_percent_sections_size;
    }
  } else {
    if (!auto_sections.empty()) {
      sections_to_grow = &auto_sections;
      sections_size = auto_sections_size;
    } else if (!fixed_sections.empty()) {
      sections_to_grow = &fixed_sections;
      sections_size = fixed_sections_size;
    } else {
      DCHECK(!percent_sections.empty());
      sections_to_grow = &percent_sections;
      sections_size = percent_sections_size;
    }
  }

  // Distribute remaining size, evenly across the sections.
  LayoutUnit distributable_size =
      distributable_table_block_size - minimum_size_guess;
  if (distributable_size > LayoutUnit()) {
    LayoutUnit remaining_deficit = distributable_size;
    for (auto& index : *sections_to_grow) {
      auto& section = sections->at(index);
      LayoutUnit delta;
      if (sections_size > LayoutUnit()) {
        delta = distributable_size.MulDiv(section.block_size, sections_size);
      } else {
        delta = distributable_size / sections_to_grow->size();
      }
      section.block_size += delta;
      section.needs_redistribution = true;
      remaining_deficit -= delta;
    }
    auto& last_section = sections->at(sections_to_grow->back());
    last_section.block_size += remaining_deficit;
    DCHECK_GE(last_section.block_size, LayoutUnit());
  }

  // Propagate new section sizes to rows.
  for (TableTypes::Section& section : *sections) {
    if (!section.needs_redistribution) {
      continue;
    }
    DistributeExcessBlockSizeToRows(
        section.start_row, section.row_count, section.block_size,
        /* is_rowspan_distribution */ false, border_block_spacing,
        section.block_size, rows);
  }
}

}  // namespace blink

"""


```