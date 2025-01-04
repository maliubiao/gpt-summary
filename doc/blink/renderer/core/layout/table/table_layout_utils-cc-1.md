Response:
The user wants a summary of the provided C++ code snippet from Chromium's Blink rendering engine. This code is part of the table layout logic. I need to identify the key functionalities within this specific chunk of code. It seems to focus on:

1. **Distributing inline size to table columns:** This includes handling fixed, percentage, and auto-sized columns.
2. **Synchronizing assignable table inline size:** This likely deals with reconciling target inline sizes with column constraints.
3. **Distributing colspan cell sizes to columns:**  This seems to handle how the width of cells spanning multiple columns affects the column widths in both fixed and auto layouts.
4. **Distributing excess block size to table rows:**  This involves allocating extra vertical space to rows based on their properties (percentage, fixed, auto, empty, rowspan).

I will go through each function and summarize its role, noting any connections to HTML, CSS, or Javascript. I'll also look for logical deductions and potential usage errors.
这是 `blink/renderer/core/layout/table/table_layout_utils.cc` 文件的第二部分，主要包含以下功能：

**核心功能： 负责表格布局中列宽和行高的分配和调整，以满足 CSS 样式和内容的需求。**

**具体功能分解：**

1. **`DistributeInlineSizeToComputedInlineSizeAuto` 函数的功能归纳：**
   - **功能：** 在自动表格布局中，将可分配的内联尺寸（宽度）分配给指定的列范围。
   - **分配策略：**
     - 优先分配给具有最小内联尺寸约束的列。
     - 剩余空间根据列的类型（固定、百分比、自动）进行分配。
     - 百分比列根据其百分比值按比例分配。
     - 自动列平分剩余空间。
   - **假设输入与输出：**
     - **假设输入：**
       - `target_inline_size`: 可分配的总宽度，例如 500px。
       - `start_column`:  指向列约束数组中起始列的指针。
       - `end_column`: 指向列约束数组中结束列的指针。
       - `treat_target_size_as_constrained`: 布尔值，指示是否将目标尺寸视为硬性约束。
       - 列约束数组，包含每列的最小/最大宽度、百分比等信息。
     - **可能输出：**
       - 一个 `Vector<LayoutUnit>`，包含计算出的每列的宽度。例如 `[100px, 150px, 250px]`.
   - **与 CSS 的关系：** 该函数直接影响表格列的最终渲染宽度，对应于 CSS 中 `width` 属性以及百分比宽度设置。
     - **举例：**  如果一个表格的宽度设置为 100%，并且其中一列设置了 `width: 50%`，这个函数会根据父容器的宽度计算出该列的实际像素宽度。
   - **逻辑推理：** 该函数首先处理具有最小宽度约束的列，确保它们至少获得所需的宽度。然后，根据剩余空间的多少以及列的类型，采用不同的分配策略。
   - **用户或编程常见的使用错误：**  如果 CSS 中表格总宽度不足以容纳所有列的最小宽度，该函数会尽力满足最小宽度约束，可能会导致表格溢出父容器。

2. **`SynchronizeAssignableTableInlineSizeAndColumnsFixed` 函数的功能归纳：**
   - **功能：**  在固定表格布局中，同步可分配的表格内联尺寸与列的固定宽度约束。
   - **分配策略：**
     - 优先分配给固定宽度的列，根据目标尺寸进行缩放。
     - 其次分配给百分比列，同样根据剩余空间进行缩放。
     - 最后分配给自动列和零宽度约束的列，平分剩余空间。
   - **假设输入与输出：**
     - **假设输入：**
       - `target_inline_size`: 目标表格宽度，例如 600px。
       - `column_constraints`: 包含列约束信息的 `TableTypes::Columns` 对象。
     - **可能输出：**
       - 一个 `Vector<LayoutUnit>`，包含计算出的每列的宽度。例如 `[150px, 200px, 250px]`.
   - **与 CSS 的关系：**  该函数处理 `table-layout: fixed` 时的列宽计算，直接影响设置了固定宽度 (`width: 100px`) 或百分比宽度的列的渲染。
     - **举例：** 如果一个 `table-layout: fixed` 的表格目标宽度是 800px，并且其中一列设置了 `width: 200px`，该函数会确保该列的宽度尽可能接近 200px。
   - **逻辑推理：** 固定布局下，列宽更多地依赖于显式设置。该函数尝试在目标宽度内尽可能满足固定和百分比列的宽度，剩余空间分配给自动列。
   - **用户或编程常见的使用错误：** 在 `table-layout: fixed` 下，如果列的固定宽度之和超过了表格的宽度，超出部分可能会被截断或隐藏，这可能不是用户期望的效果。

3. **`DistributeColspanCellToColumnsFixed` 函数的功能归纳：**
   - **功能：** 在固定表格布局中，将跨列单元格（colspan）的宽度约束分配到其跨越的列上。
   - **分配策略：**
     - 将单元格的最小和最大宽度约束平均分配给其跨越的非合并列。
     - 将单元格的百分比宽度约束平均分配给其跨越的自动列。
   - **假设输入与输出：**
     - **假设输入：**
       - `colspan_cell`:  包含跨列单元格信息的 `TableTypes::ColspanCell` 对象，包括起始列、跨越列数、宽度约束等。
       - `inline_border_spacing`: 表格的水平边框间距。
       - `column_constraints`: 指向列约束的指针。
     - **影响输出：** 修改 `column_constraints` 中相关列的 `min_inline_size`、`max_inline_size` 和 `percent` 属性。
   - **与 CSS 的关系：**  该函数处理 `colspan` 属性对列宽的影响，确保跨列单元格能够占据其应有的宽度。
     - **举例：** 如果一个跨越 3 列的单元格设置了 `width: 300px`，在固定布局下，这个函数会尝试将这 300px 分配到这三列上。
   - **逻辑推理：** 该函数简单地将跨列单元格的宽度约束均分到其所跨越的列上，这符合固定布局下对列宽的显式控制。
   - **用户或编程常见的使用错误：** 如果跨列单元格的约束与列的现有约束冲突，可能会导致意外的列宽调整。

4. **`DistributeColspanCellToColumnsAuto` 函数的功能归纳：**
   - **功能：** 在自动表格布局中，将跨列单元格的宽度约束分配到其跨越的列上。
   - **分配策略：**
     - 如果跨列单元格有百分比宽度，则将其按比例分配到非百分比列上。
     - 将单元格的最小宽度约束使用标准的自动分配算法 (`DistributeInlineSizeToComputedInlineSizeAuto`) 分配。
     - 将单元格的最大宽度约束使用标准的自动分配算法分配。
   - **假设输入与输出：**
     - **假设输入：**
       - `colspan_cell`:  包含跨列单元格信息的 `TableTypes::ColspanCell` 对象。
       - `inline_border_spacing`: 表格的水平边框间距。
       - `column_constraints`: 指向列约束的指针。
     - **影响输出：** 修改 `column_constraints` 中相关列的 `min_inline_size`、`max_inline_size` 和 `percent` 属性。
   - **与 CSS 的关系：**  处理自动布局下 `colspan` 对列宽的影响，与固定布局的分配策略不同。
     - **举例：** 在自动布局下，一个跨越 2 列并设置了 `width: 60%` 的单元格，该函数会将这 60% 的宽度分配到这两列上，可能不是均分。
   - **逻辑推理：** 自动布局更灵活，该函数会根据现有列的属性和单元格的约束，更智能地分配宽度。
   - **用户或编程常见的使用错误：** 自动布局的宽度分配可能不如固定布局那样直观，特别是当存在跨列单元格时，用户可能会对最终的列宽感到困惑。

5. **`DistributeExcessBlockSizeToRows` 函数的功能归纳：**
   - **功能：** 将表格、节、行和跨行单元格中多余的块尺寸（高度）分配给行。
   - **分配策略：**
     - 优先分配给具有百分比高度的行，不超过其百分比高度。
     - 其次分配给具有起始跨行的行。
     - 然后按比例分配给无约束的非空行。
     - 接着分配给空行（如果所有行都是空行或者非空行都有约束）。
     - 最后按比例分配给所有非空行。
   - **假设输入与输出：**
     - **假设输入：**
       - `start_row_index`: 分配的起始行索引。
       - `row_count`:  要分配的行数。
       - `desired_block_size`: 期望的总高度。
       - 其他参数包括是否是跨行分配、边框间距、百分比解析高度以及行约束数组。
     - **影响输出：** 修改 `rows` 数组中相关行的 `block_size` 属性。
   - **与 CSS 的关系：**  该函数处理表格的高度分配，涉及到 `height` 属性、百分比高度、以及 `rowspan` 属性的影响。
     - **举例：** 如果一个表格设置了 `height: 500px`，并且其中一行设置了 `height: 20%`，这个函数会计算出该行的实际高度，并将剩余空间分配给其他行。
   - **逻辑推理：**  行高的分配是一个复杂的过程，需要考虑多种因素，该函数实现了 W3C 规范中描述的分配算法。
   - **用户或编程常见的使用错误：** 百分比行高的计算依赖于父元素的明确高度，如果父元素的高度未定义或为 auto，百分比行高可能不会生效。

总而言之，这段代码是 Chromium Blink 引擎中负责表格布局计算的关键部分，它实现了复杂的逻辑来确定表格中列的宽度和行的高度，以符合 HTML 结构和 CSS 样式规则。它在浏览器渲染表格时起着至关重要的作用。

Prompt: 
```
这是目录为blink/renderer/core/layout/table/table_layout_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
    DCHECK(last_computed_size);
          *last_computed_size += remaining_deficit;
        }
      } else if (percent_columns_count > 0) {
        // All remaining columns are percent.
        // They grow to max(col minimum, %ge size) + additional size
        // proportional to column percent.
        LayoutUnit remaining_deficit = distributable_inline_size;
        LayoutUnit* last_computed_size = nullptr;
        LayoutUnit* computed_size = computed_sizes.data();
        for (const TableTypes::Column* column = start_column;
             column != end_column; ++column, ++computed_size) {
          if (column->is_mergeable || !column->percent) {
            continue;
          }
          last_computed_size = computed_size;
          LayoutUnit percent_inline_size =
              column->ResolvePercentInlineSize(target_inline_size);
          LayoutUnit delta;
          if (total_percent != 0.0f) {
            delta = LayoutUnit(distributable_inline_size * *column->percent /
                               total_percent);
          } else {
            delta = distributable_inline_size / percent_columns_count;
          }
          remaining_deficit -= delta;
          *computed_size = percent_inline_size + delta;
        }
        if (remaining_deficit != LayoutUnit() && last_computed_size) {
          *last_computed_size += remaining_deficit;
        }
      }
    }
  }
  return computed_sizes;
}

Vector<LayoutUnit> SynchronizeAssignableTableInlineSizeAndColumnsFixed(
    LayoutUnit target_inline_size,
    const TableTypes::Columns& column_constraints) {
  unsigned all_columns_count = 0;
  unsigned percent_columns_count = 0;
  unsigned auto_columns_count = 0;
  unsigned fixed_columns_count = 0;
  unsigned zero_inline_size_constrained_colums_count = 0;

  auto TreatAsFixed = [](const TableTypes::Column& column) {
    // Columns of width 0 are treated as auto by all browsers.
    return column.IsFixed() && column.max_inline_size != LayoutUnit();
  };

  auto IsZeroInlineSizeConstrained = [](const TableTypes::Column& column) {
    // Columns of width 0 are treated as auto by all browsers.
    return column.is_constrained && column.max_inline_size == LayoutUnit();
  };

  LayoutUnit total_percent_inline_size;
  LayoutUnit total_auto_max_inline_size;
  LayoutUnit total_fixed_inline_size;
  LayoutUnit assigned_inline_size;
  Vector<LayoutUnit> column_sizes;
  column_sizes.resize(column_constraints.data.size());
  for (const TableTypes::Column& column : column_constraints.data) {
    all_columns_count++;
    if (column.percent) {
      percent_columns_count++;
      total_percent_inline_size +=
          column.ResolvePercentInlineSize(target_inline_size);
    } else if (TreatAsFixed(column)) {
      fixed_columns_count++;
      total_fixed_inline_size += column.max_inline_size.value_or(LayoutUnit());
    } else if (IsZeroInlineSizeConstrained(column)) {
      zero_inline_size_constrained_colums_count++;
    } else {
      auto_columns_count++;
      total_auto_max_inline_size +=
          column.max_inline_size.value_or(LayoutUnit());
    }
  }

  LayoutUnit* last_column_size = nullptr;
  // Distribute to fixed columns.
  if (fixed_columns_count > 0) {
    float scale = 1.0f;
    bool scale_available = true;
    LayoutUnit target_fixed_size =
        (target_inline_size - total_percent_inline_size).ClampNegativeToZero();
    bool scale_up =
        total_fixed_inline_size < target_fixed_size && auto_columns_count == 0;
    // Fixed columns grow if there are no auto columns. They fill up space not
    // taken up by percentage columns.
    bool scale_down = total_fixed_inline_size > target_inline_size;
    if (scale_up || scale_down) {
      if (total_fixed_inline_size != LayoutUnit()) {
        scale = target_fixed_size.ToFloat() / total_fixed_inline_size;
      } else {
        scale_available = false;
      }
    }
    LayoutUnit* column_size = column_sizes.data();
    for (auto column = column_constraints.data.begin();
         column != column_constraints.data.end(); ++column, ++column_size) {
      if (!TreatAsFixed(*column)) {
        continue;
      }
      last_column_size = column_size;
      if (scale_available) {
        *column_size =
            LayoutUnit(scale * column->max_inline_size.value_or(LayoutUnit()));
      } else {
        DCHECK_EQ(fixed_columns_count, all_columns_count);
        *column_size =
            LayoutUnit(target_inline_size.ToFloat() / fixed_columns_count);
      }
      assigned_inline_size += *column_size;
    }
  }
  if (assigned_inline_size >= target_inline_size) {
    return column_sizes;
  }
  // Distribute to percent columns.
  if (percent_columns_count > 0) {
    float scale = 1.0f;
    bool scale_available = true;
    // Percent columns only grow if there are no auto columns.
    bool scale_up = total_percent_inline_size <
                        (target_inline_size - assigned_inline_size) &&
                    auto_columns_count == 0;
    bool scale_down =
        total_percent_inline_size > (target_inline_size - assigned_inline_size);
    if (scale_up || scale_down) {
      if (total_percent_inline_size != LayoutUnit()) {
        scale = (target_inline_size - assigned_inline_size).ToFloat() /
                total_percent_inline_size;
      } else {
        scale_available = false;
      }
    }
    LayoutUnit* column_size = column_sizes.data();
    for (auto column = column_constraints.data.begin();
         column != column_constraints.data.end(); ++column, ++column_size) {
      if (!column->percent) {
        continue;
      }
      last_column_size = column_size;
      if (scale_available) {
        *column_size = LayoutUnit(
            scale * column->ResolvePercentInlineSize(target_inline_size));
      } else {
        *column_size =
            LayoutUnit((target_inline_size - assigned_inline_size).ToFloat() /
                       percent_columns_count);
      }
      assigned_inline_size += *column_size;
    }
  }
  // Distribute to auto, and zero inline size columns.
  LayoutUnit distributing_inline_size =
      target_inline_size - assigned_inline_size;
  LayoutUnit* column_size = column_sizes.data();

  bool distribute_zero_inline_size =
      zero_inline_size_constrained_colums_count == all_columns_count;

  for (auto column = column_constraints.data.begin();
       column != column_constraints.data.end(); ++column, ++column_size) {
    if (column->percent || TreatAsFixed(*column)) {
      continue;
    }
    // Zero-width columns only grow if all columns are zero-width.
    if (IsZeroInlineSizeConstrained(*column) && !distribute_zero_inline_size) {
      continue;
    }

    last_column_size = column_size;
    *column_size =
        LayoutUnit(distributing_inline_size /
                   float(distribute_zero_inline_size
                             ? zero_inline_size_constrained_colums_count
                             : auto_columns_count));
    assigned_inline_size += *column_size;
  }
  LayoutUnit delta = target_inline_size - assigned_inline_size;
  DCHECK(last_column_size);
  *last_column_size += delta;

  return column_sizes;
}

void DistributeColspanCellToColumnsFixed(
    const TableTypes::ColspanCell& colspan_cell,
    LayoutUnit inline_border_spacing,
    TableTypes::Columns* column_constraints) {
  // Fixed layout does not merge columns.
  DCHECK_LE(colspan_cell.span,
            column_constraints->data.size() - colspan_cell.start_column);
  TableTypes::Column* start_column =
      &column_constraints->data[colspan_cell.start_column];
  TableTypes::Column* end_column = start_column + colspan_cell.span;
  DCHECK_NE(start_column, end_column);

  // Inline sizes for redistribution exclude border spacing.
  LayoutUnit total_inner_border_spacing;
  unsigned effective_span = 0;
  bool is_first_column = true;
  for (TableTypes::Column* column = start_column; column != end_column;
       ++column) {
    if (column->is_mergeable) {
      continue;
    }
    ++effective_span;
    if (!is_first_column) {
      total_inner_border_spacing += inline_border_spacing;
    } else {
      is_first_column = false;
    }
  }
  LayoutUnit colspan_cell_min_inline_size;
  LayoutUnit colspan_cell_max_inline_size;
  // Colspanned cells only distribute min inline size if constrained.
  if (colspan_cell.cell_inline_constraint.is_constrained) {
    colspan_cell_min_inline_size =
        (colspan_cell.cell_inline_constraint.min_inline_size -
         total_inner_border_spacing)
            .ClampNegativeToZero();
  }
  colspan_cell_max_inline_size =
      (colspan_cell.cell_inline_constraint.max_inline_size -
       total_inner_border_spacing)
          .ClampNegativeToZero();

  // Distribute min/max evenly between all cells.
  LayoutUnit rounding_error_min_inline_size = colspan_cell_min_inline_size;
  LayoutUnit rounding_error_max_inline_size = colspan_cell_max_inline_size;

  LayoutUnit new_min_size = LayoutUnit(colspan_cell_min_inline_size /
                                       static_cast<float>(effective_span));
  LayoutUnit new_max_size = LayoutUnit(colspan_cell_max_inline_size /
                                       static_cast<float>(effective_span));
  std::optional<float> new_percent;
  if (colspan_cell.cell_inline_constraint.percent) {
    new_percent = *colspan_cell.cell_inline_constraint.percent / effective_span;
  }

  TableTypes::Column* last_column = nullptr;
  for (TableTypes::Column* column = start_column; column < end_column;
       ++column) {
    if (column->is_mergeable) {
      continue;
    }
    last_column = column;
    rounding_error_min_inline_size -= new_min_size;
    rounding_error_max_inline_size -= new_max_size;

    if (!column->min_inline_size) {
      column->is_constrained |=
          colspan_cell.cell_inline_constraint.is_constrained;
      column->min_inline_size = new_min_size;
    }
    if (!column->max_inline_size) {
      column->is_constrained |=
          colspan_cell.cell_inline_constraint.is_constrained;
      column->max_inline_size = new_max_size;
    }
    // Percentages only get distributed over auto columns.
    if (!column->percent && !column->is_constrained && new_percent) {
      column->percent = *new_percent;
    }
  }
  DCHECK(last_column);
  last_column->min_inline_size =
      *last_column->min_inline_size + rounding_error_min_inline_size;
  last_column->max_inline_size =
      *last_column->max_inline_size + rounding_error_max_inline_size;
}

void DistributeColspanCellToColumnsAuto(
    const TableTypes::ColspanCell& colspan_cell,
    LayoutUnit inline_border_spacing,
    TableTypes::Columns* column_constraints) {
  if (column_constraints->data.empty()) {
    return;
  }
  unsigned effective_span =
      std::min(colspan_cell.span,
               column_constraints->data.size() - colspan_cell.start_column);
  TableTypes::Column* start_column =
      &column_constraints->data[colspan_cell.start_column];
  TableTypes::Column* end_column = start_column + effective_span;

  // Inline sizes for redistribution exclude border spacing.
  LayoutUnit total_inner_border_spacing;
  bool is_first_column = true;
  for (TableTypes::Column* column = start_column; column != end_column;
       ++column) {
    if (!column->is_mergeable) {
      if (!is_first_column) {
        total_inner_border_spacing += inline_border_spacing;
      } else {
        is_first_column = false;
      }
    }
  }

  LayoutUnit colspan_cell_min_inline_size =
      (colspan_cell.cell_inline_constraint.min_inline_size -
       total_inner_border_spacing)
          .ClampNegativeToZero();
  LayoutUnit colspan_cell_max_inline_size =
      (colspan_cell.cell_inline_constraint.max_inline_size -
       total_inner_border_spacing)
          .ClampNegativeToZero();
  std::optional<float> colspan_cell_percent =
      colspan_cell.cell_inline_constraint.percent;

  if (colspan_cell_percent.has_value()) {
    float columns_percent = 0.0f;
    unsigned all_columns_count = 0;
    unsigned percent_columns_count = 0;
    unsigned nonpercent_columns_count = 0;
    LayoutUnit nonpercent_columns_max_inline_size;
    for (TableTypes::Column* column = start_column; column != end_column;
         ++column) {
      if (!column->max_inline_size) {
        column->max_inline_size = LayoutUnit();
      }
      if (!column->min_inline_size) {
        column->min_inline_size = LayoutUnit();
      }
      if (column->is_mergeable) {
        continue;
      }
      all_columns_count++;
      if (column->percent) {
        percent_columns_count++;
        columns_percent += *column->percent;
      } else {
        nonpercent_columns_count++;
        nonpercent_columns_max_inline_size += *column->max_inline_size;
      }
    }
    float surplus_percent = *colspan_cell_percent - columns_percent;
    if (surplus_percent > 0.0f && all_columns_count > percent_columns_count) {
      // Distribute surplus percent to non-percent columns in proportion to
      // max_inline_size.
      for (TableTypes::Column* column = start_column; column != end_column;
           ++column) {
        if (column->percent || column->is_mergeable) {
          continue;
        }
        float column_percent;
        if (nonpercent_columns_max_inline_size != LayoutUnit()) {
          // Column percentage is proportional to its max_inline_size.
          column_percent = surplus_percent *
                           column->max_inline_size.value_or(LayoutUnit()) /
                           nonpercent_columns_max_inline_size;
        } else {
          // Distribute evenly instead.
          // Legacy difference: Legacy forces max_inline_size to be at least
          // 1px.
          column_percent = surplus_percent / nonpercent_columns_count;
        }
        column->percent = column_percent;
      }
    }
  }

  // TODO(atotic) See crbug.com/531752 for discussion about differences
  // between FF/Chrome.
  // Minimum inline size gets distributed with standard distribution algorithm.
  for (TableTypes::Column* column = start_column; column != end_column;
       ++column) {
    if (!column->min_inline_size) {
      column->min_inline_size = LayoutUnit();
    }
    if (!column->max_inline_size) {
      column->max_inline_size = LayoutUnit();
    }
  }
  Vector<LayoutUnit> computed_sizes =
      DistributeInlineSizeToComputedInlineSizeAuto(
          colspan_cell_min_inline_size, start_column, end_column, true);
  LayoutUnit* computed_size = computed_sizes.data();
  for (TableTypes::Column* column = start_column; column != end_column;
       ++column, ++computed_size) {
    column->min_inline_size =
        std::max(*column->min_inline_size, *computed_size);
  }
  computed_sizes = DistributeInlineSizeToComputedInlineSizeAuto(
      colspan_cell_max_inline_size, start_column,
      end_column, /* treat_target_size_as_constrained */
      colspan_cell.cell_inline_constraint.is_constrained);
  computed_size = computed_sizes.data();
  for (TableTypes::Column* column = start_column; column != end_column;
       ++column, ++computed_size) {
    column->max_inline_size =
        std::max(std::max(*column->min_inline_size, *column->max_inline_size),
                 *computed_size);
  }
}

// Handles distribution of excess block size from: table, sections,
// rows, and rowspanned cells, to rows.
// Rowspanned cells distribute with slight differences from
// general distribution algorithm.
void DistributeExcessBlockSizeToRows(
    const wtf_size_t start_row_index,
    const wtf_size_t row_count,
    LayoutUnit desired_block_size,
    bool is_rowspan_distribution,
    LayoutUnit border_block_spacing,
    LayoutUnit percentage_resolution_block_size,
    TableTypes::Rows* rows) {
  DCHECK_GE(desired_block_size, LayoutUnit());
  // This algorithm has not been defined by the standard in 2019.
  // Discussion at https://github.com/w3c/csswg-drafts/issues/4418
  if (row_count == 0) {
    return;
  }

  const wtf_size_t end_row_index = start_row_index + row_count;
  DCHECK_LE(end_row_index, rows->size());

  auto RowBlockSizeDeficit = [&percentage_resolution_block_size](
                                 const TableTypes::Row& row) {
    DCHECK_NE(percentage_resolution_block_size, kIndefiniteSize);
    DCHECK(row.percent);
    return (LayoutUnit(*row.percent * percentage_resolution_block_size / 100) -
            row.block_size)
        .ClampNegativeToZero();
  };

  Vector<wtf_size_t> rows_with_originating_rowspan;
  Vector<wtf_size_t> percent_rows_with_deficit;
  Vector<wtf_size_t> unconstrained_non_empty_rows;
  Vector<wtf_size_t> empty_rows;
  Vector<wtf_size_t> non_empty_rows;
  Vector<wtf_size_t> unconstrained_empty_rows;
  unsigned constrained_non_empty_row_count = 0;

  LayoutUnit total_block_size;
  LayoutUnit percent_block_size_deficit;
  LayoutUnit unconstrained_non_empty_row_block_size;

  for (auto index = start_row_index; index < end_row_index; ++index) {
    const auto& row = rows->at(index);
    total_block_size += row.block_size;

    // Rowspans are treated specially only during rowspan distribution.
    bool is_row_with_originating_rowspan = is_rowspan_distribution &&
                                           index != start_row_index &&
                                           row.has_rowspan_start;
    if (is_row_with_originating_rowspan) {
      rows_with_originating_rowspan.push_back(index);
    }

    bool is_row_empty = row.block_size == LayoutUnit();

    if (row.percent && *row.percent != 0 &&
        percentage_resolution_block_size != kIndefiniteSize) {
      LayoutUnit deficit = RowBlockSizeDeficit(row);
      if (deficit != LayoutUnit()) {
        percent_rows_with_deficit.push_back(index);
        percent_block_size_deficit += deficit;
        is_row_empty = false;
      }
    }

    // Only consider percent rows that resolve as constrained.
    const bool is_row_constrained =
        row.is_constrained &&
        (!row.percent || percentage_resolution_block_size != kIndefiniteSize);

    if (is_row_empty) {
      empty_rows.push_back(index);
      if (!is_row_constrained) {
        unconstrained_empty_rows.push_back(index);
      }
    } else {
      non_empty_rows.push_back(index);
      if (is_row_constrained) {
        constrained_non_empty_row_count++;
      } else {
        unconstrained_non_empty_rows.push_back(index);
        unconstrained_non_empty_row_block_size += row.block_size;
      }
    }
  }

  LayoutUnit distributable_block_size =
      (desired_block_size - border_block_spacing * (row_count - 1)) -
      total_block_size;
  if (distributable_block_size <= LayoutUnit()) {
    return;
  }

  // Step 1: percentage rows grow to no more than their percentage size.
  if (!percent_rows_with_deficit.empty()) {
    // Don't distribute more than the percent block-size deficit.
    LayoutUnit percent_distributable_block_size =
        std::min(percent_block_size_deficit, distributable_block_size);

    LayoutUnit remaining_deficit = percent_distributable_block_size;
    for (auto& index : percent_rows_with_deficit) {
      auto& row = rows->at(index);
      LayoutUnit delta = percent_distributable_block_size.MulDiv(
          RowBlockSizeDeficit(row), percent_block_size_deficit);
      row.block_size += delta;
      total_block_size += delta;
      distributable_block_size -= delta;
      remaining_deficit -= delta;
    }
    auto& last_row = rows->at(percent_rows_with_deficit.back());
    last_row.block_size += remaining_deficit;
    distributable_block_size -= remaining_deficit;
    DCHECK_GE(last_row.block_size, LayoutUnit());

    // Rounding may cause us to distribute more than the distributable size.
    if (distributable_block_size <= LayoutUnit()) {
      return;
    }
  }

  // Step 2: Distribute to rows that have an originating rowspan.
  if (!rows_with_originating_rowspan.empty()) {
    LayoutUnit remaining_deficit = distributable_block_size;
    for (auto& index : rows_with_originating_rowspan) {
      auto& row = rows->at(index);
      LayoutUnit delta =
          distributable_block_size / rows_with_originating_rowspan.size();
      row.block_size += delta;
      remaining_deficit -= delta;
    }
    auto& last_row = rows->at(rows_with_originating_rowspan.back());
    last_row.block_size += remaining_deficit;
    last_row.block_size = std::max(last_row.block_size, LayoutUnit());
    return;
  }

  // Step 3: "unconstrained non-empty rows" grow in proportion to current
  // block size.
  if (!unconstrained_non_empty_rows.empty()) {
    LayoutUnit remaining_deficit = distributable_block_size;
    for (auto& index : unconstrained_non_empty_rows) {
      auto& row = rows->at(index);
      LayoutUnit delta = distributable_block_size.MulDiv(
          row.block_size, unconstrained_non_empty_row_block_size);
      row.block_size += delta;
      remaining_deficit -= delta;
    }
    auto& last_row = rows->at(unconstrained_non_empty_rows.back());
    last_row.block_size += remaining_deficit;
    DCHECK_GE(last_row.block_size, LayoutUnit());
    return;
  }

  // Step 4: Empty row distribution
  // At this point all rows are empty and/or constrained.
  if (!empty_rows.empty()) {
    const bool has_only_empty_rows = empty_rows.size() == row_count;
    if (is_rowspan_distribution) {
      // If we are doing a rowspan distribution, *and* only have empty rows,
      // distribute everything to the last empty row.
      if (has_only_empty_rows) {
        rows->at(empty_rows.back()).block_size += distributable_block_size;
        return;
      }
    } else if (has_only_empty_rows ||
               (empty_rows.size() + constrained_non_empty_row_count ==
                row_count)) {
      // Grow empty rows if either of these is true:
      // - All rows are empty.
      // - Non-empty rows are all constrained.
      LayoutUnit remaining_deficit = distributable_block_size;
      // If there are constrained and unconstrained empty rows, only
      // the unconstrained rows grow.
      Vector<wtf_size_t>& rows_to_grow = !unconstrained_empty_rows.empty()
                                             ? unconstrained_empty_rows
                                             : empty_rows;
      for (auto& index : rows_to_grow) {
        auto& row = rows->at(index);
        LayoutUnit delta = distributable_block_size / rows_to_grow.size();
        row.block_size = delta;
        remaining_deficit -= delta;
      }
      auto& last_row = rows->at(rows_to_grow.back());
      last_row.block_size += remaining_deficit;
      DCHECK_GE(last_row.block_size, LayoutUnit());
      return;
    }
  }

  // Step 5: Grow non-empty rows in proportion to current block size.
  // It grows constrained, and unconstrained rows.
  if (!non_empty_rows.empty()) {
    LayoutUnit remaining_deficit = distributable_block_size;
    for (auto& index : non_empty_rows) {
      auto& row = rows->at(index);
      LayoutUnit delta =
          distributable_block_size.MulDiv(row.block_size, total_block_size);
      row.block_size += delta;
      remaining_deficit -= delta;
    }
    auto& last_row = rows->at(non_empty_rows.back());
    last_row.block_size += remaining_deficit;
    DCHECK_GE(last_row.block_size, LayoutUnit());
  }
}

}  // namespace

CellBlockSizeData ComputeCellBlockSize(
    const TableTypes::CellBlockConstraint& cell_block_constraint,
    const TableTypes::Rows& rows,
    wtf_size_t row_index,
    const LogicalSize& border_spacing,
    bool is_table_block_size_specified) {
  // NOTE: Confusingly rowspanned cells originating from a collapsed-row also
  // have no block-size.
  LayoutUnit cell_block_size;
  if (!rows[row_index].is_collapsed) {
    for (wtf_size_t i = 0; i < cell_block_constraint.effective_rowspan; ++i) {
      if (rows[row_index + i].is_collapsed)
        continue;
      cell_block_size += rows[row_index + i].block_size;
      if (i != 0)
        cell_block_size += border_spacing.block_size;
    }
  }

  bool has_grown = cell_block_size > cell_block_constraint.min_block_size;

  // Our initial block-size is definite if this cell has a fixed block-size,
  // or we have grown and the table has a specified block-size.
  bool is_initial_block_size_definite =
      cell_block_constraint.is_constrained ||
      (has_grown && is_table_block_size_specified);

  return {cell_block_size, !is_initial_block_size_definite};
}

void SetupTableCellConstraintSpaceBuilder(
    const WritingDirectionMode table_writing_direction,
    const BlockNode cell,
    const BoxStrut& cell_borders,
    const Vector<TableColumnLocation>& column_locations,
    LayoutUnit cell_block_size,
    LayoutUnit percentage_inline_size,
    std::optional<LayoutUnit> alignment_baseline,
    wtf_size_t start_column,
    bool is_initial_block_size_indefinite,
    bool is_table_block_size_specified,
    bool has_collapsed_borders,
    LayoutResultCacheSlot cache_slot,
    ConstraintSpaceBuilder* builder) {
  const auto& cell_style = cell.Style();
  const auto table_writing_mode = table_writing_direction.GetWritingMode();
  const wtf_size_t end_column = std::min(
      start_column + cell.TableCellColspan() - 1, column_locations.size() - 1);
  const LayoutUnit cell_inline_size = column_locations[end_column].offset +
                                      column_locations[end_column].size -
                                      column_locations[start_column].offset;

  // A table-cell is hidden if all the columns it spans are collapsed.
  const bool is_hidden_for_paint = [&]() -> bool {
    for (wtf_size_t column = start_column; column <= end_column; ++column) {
      if (!column_locations[column].is_collapsed)
        return false;
    }
    return true;
  }();

  builder->SetIsTableCell(true);

  if (!IsParallelWritingMode(table_writing_mode, cell_style.GetWritingMode())) {
    const PhysicalSize icb_size = cell.InitialContainingBlockSize();
    builder->SetOrthogonalFallbackInlineSize(
        table_writing_direction.IsHorizontal() ? icb_size.height
                                               : icb_size.width);
  }

  builder->SetAvailableSize({cell_inline_size, cell_block_size});
  builder->SetIsFixedInlineSize(true);
  if (cell_block_size != kIndefiniteSize)
    builder->SetIsFixedBlockSize(true);
  builder->SetIsInitialBlockSizeIndefinite(is_initial_block_size_indefinite);

  // https://www.w3.org/TR/css-tables-3/#computing-the-table-height
  // "the computed height (if definite, percentages being considered 0px)"
  builder->SetPercentageResolutionSize(
      {percentage_inline_size, kIndefiniteSize});

  builder->SetTableCellBorders(cell_borders, cell_style.GetWritingDirection(),
                               table_writing_direction);
  builder->SetTableCellAlignmentBaseline(alignment_baseline);
  builder->SetTableCellColumnIndex(start_column);
  builder->SetIsRestrictedBlockSizeTableCell(
      is_table_block_size_specified || cell_style.LogicalHeight().IsFixed());
  builder->SetIsHiddenForPaint(is_hidden_for_paint);
  builder->SetIsTableCellWithCollapsedBorders(has_collapsed_borders);
  builder->SetHideTableCellIfEmpty(
      !has_collapsed_borders && cell_style.EmptyCells() == EEmptyCells::kHide);
  builder->SetCacheSlot(cache_slot);
}

// Computes maximum possible number of non-mergeable columns.
wtf_size_t ComputeMaximumNonMergeableColumnCount(
    const HeapVector<BlockNode>& columns,
    bool is_fixed_layout) {
  // Build column constraints.
  scoped_refptr<TableTypes::Columns> column_constraints =
      base::MakeRefCounted<TableTypes::Columns>();
  ColumnConstraintsBuilder constraints_builder(column_constraints.get(),
                                               is_fixed_layout);
  VisitLayoutTableColumn(columns, UINT_MAX, &constraints_builder);
  // Find last non-mergeable column.
  if (column_constraints->data.size() == 0)
    return 0;
  wtf_size_t column_index = column_constraints->data.size() - 1;
  while (column_index > 0 &&
         column_constraints->data[column_index].is_mergeable) {
    --column_index;
  }
  if (column_index == 0 && column_constraints->data[0].is_mergeable)
    return 0;
  return column_index + 1;
}

scoped_refptr<TableTypes::Columns> ComputeColumnConstraints(
    const BlockNode& table,
    const TableGroupedChildren& grouped_children,
    const TableBorders& table_borders,
    const BoxStrut& border_padding) {
  const auto& table_style = table.Style();
  bool is_fixed_layout = table_style.IsFixedTableLayout();

  TableTypes::CellInlineConstraints cell_inline_constraints;
  TableTypes::ColspanCells colspan_cell_constraints;

  scoped_refptr<TableTypes::Columns> column_constraints =
      base::MakeRefCounted<TableTypes::Columns>();
  ComputeColumnElementConstraints(grouped_children.columns, is_fixed_layout,
                                  column_constraints.get());

  // Collect section constraints
  bool is_first_section = true;
  wtf_size_t row_index = 0;
  wtf_size_t section_index = 0;
  for (BlockNode section : grouped_children) {
    if (!section.IsEmptyTableSection()) {
      ComputeSectionInlineConstraints(
          section, is_fixed_layout, is_first_section,
          table_style.GetWritingDirection(), table_borders, section_index,
          &row_index, &cell_inline_constraints, &colspan_cell_constraints);
      is_first_section = false;
    }
    section_index++;
  }
  ApplyCellConstraintsToColumnConstraints(
      cell_inline_constraints, table_style.TableBorderSpacing().inline_size,
      is_fixed_layout, &colspan_cell_constraints, column_constraints.get());

  return column_constraints;
}

void ComputeSectionMinimumRowBlockSizes(
    const BlockNode& section,
    const LayoutUnit cell_percentage_inline_size,
    const bool is_table_block_size_specified,
    const Vector<TableColumnLocation>& column_locations,
    const TableBorders& table_borders,
    const LayoutUnit block_border_spacing,
    wtf_size_t section_index,
    bool treat_section_as_tbody,
    TableTypes::Sections* sections,
    TableTypes::Rows* rows,
    TableTypes::CellBlockConstraints* cell_block_constraints) {
  // In rare circumstances we need to know the total row count before we've
  // visited all them (for computing effective rowspans). We don't want to
  // perform this unnecessarily.
  std::optional<wtf_size_t> row_count;
  auto RowCountFunc = [&]() -> wtf_size_t {
    if (!row_count) {
      row_count = 0;
      for (BlockNode row = To<BlockNode>(section.FirstChild()); row;
           row = To<BlockNode>(row.NextSibling())) {
        (*row_count)++;
      }
    }

    return *row_count;
  };

  wtf_size_t start_row = rows->size();
  wtf_size_t current_row = start_row;
  TableTypes::RowspanCells rowspan_cells;
  LayoutUnit section_block_size;
  // Used to compute column index.
  ColspanCellTabulator colspan_cell_tabulator;
  // total_row_percent must be under 100%
  float total_row_percent = 0;
  // Get minimum block size of each row.
  for (BlockNode row = To<BlockNode>(section.FirstChild()); row;
       row = To<BlockNode>(row.NextSibling())) {
    colspan_cell_tabulator.StartRow();
    TableTypes::Row row_constraint = ComputeMinimumRowBlockSize(
        RowCountFunc, row, cell_percentage_inline_size,
        is_table_block_size_specified, column_locations, table_borders,
        start_row, current_row++, section_index,
        /* is_section_collapsed */ section.Style().Visibility() ==
            EVisibility::kCollapse,
        cell_block_constraints, &rowspan_cells, &colspan_cell_tabulator);
    if (row_constraint.percent.has_value()) {
      row_constraint.percent =
          std::min(100.0f - total_row_percent, *row_constraint.percent);
      total_row_percent += *row_constraint.percent;
    }
    rows->push_back(row_constraint);
    section_block_size += row_constraint.block_size;
    colspan_cell_tabulator.EndRow();
  }

  // Redistribute rowspanned cell block sizes.
  std::stable_sort(rowspan_cells.begin(), rowspan_cells.end());
  for (const auto& rowspan_cell : rowspan_cells) {
    DistributeRowspanCellToRows(rowspan_cell, block_border_spacing, rows);
  }

  const wtf_size_t block_spacing_count =
      current_row == start_row ? 0 : current_row - start_row - 1;
  const LayoutUnit border_spacing_total =
      block_border_spacing * block_spacing_count;
  section_block_size += border_spacing_total;

  // Redistribute section's css block size.
  const Length& section_specified_block_length =
      section.Style().LogicalHeight();
  // TODO(1105272) Handle section_specified_block_length.IsCalculated()
  if (section_specified_block_length.IsFixed()) {
    LayoutUnit section_fixed_block_size =
        LayoutUnit(section_specified_block_length.Value());
    if (section_fixed_block_size > section_block_size) {
      DistributeSectionFixedBlockSizeToRows(
          start_row, current_row - start_row, section_fixed_blo
"""


```