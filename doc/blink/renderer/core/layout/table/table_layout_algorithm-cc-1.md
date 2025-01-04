Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine, specifically the `TableLayoutAlgorithm::ComputeRows` and `TableLayoutAlgorithm::GenerateFragment` methods.

I need to:

1. **Summarize the functionality of `ComputeRows`:** This method seems to calculate the block size of table rows and sections based on various factors like CSS properties, available space, and whether the table is being broken across pages/regions.

2. **Summarize the functionality of `GenerateFragment`:** This method appears to be responsible for generating layout fragments for the table, including captions, sections, and handling pagination/fragmentation.

3. **Identify relationships with HTML, CSS, and JavaScript:**  I need to explain how these functions relate to the rendering of HTML tables styled with CSS. JavaScript might be involved indirectly through dynamic manipulation of the table structure or styles.

4. **Provide examples with hypothetical inputs and outputs for logical deductions:** For `ComputeRows`, I can consider a table with a fixed height and demonstrate how the row heights are calculated. For `GenerateFragment`, I can think about how it might handle a table that spans multiple pages.

5. **Illustrate common user/programming errors:**  These could be related to incorrect CSS settings or misunderstandings about how table layout works.

6. **Synthesize a concise summary of the functionality of this part of the code.**
好的，这是对代码片段的功能归纳：

**功能归纳:**

这段代码实现了 `TableLayoutAlgorithm` 类中用于计算表格行高和生成表格布局片段的关键部分。

**`ComputeRows` 方法的功能：**

1. **计算最小行块大小:**  根据表格内容（行和单元格）计算表格的最小高度 (`total_table_min_block_size_`)。这考虑了单元格的内容、内边距、边框间距等因素。
2. **处理分页/分栏的断点信息:**  如果存在断点信息 (`TableBreakTokenData`)，则从断点信息中恢复之前计算的行、单元格约束和分节信息，以便在分页或分栏后继续布局。
3. **考虑表格的 CSS 块大小:**
    -  如果表格的 CSS `height` 属性为 `auto` 且所在的包含块大小不确定，则表格的块大小也为不确定 (`kIndefiniteSize`)，这通常发生在 flexbox 布局中，表格的高度取决于其内容。
    - 否则，尝试解析表格的 `min-height` 属性。如果 `min-height` 被指定为一个具体的值，或者可以解析为一个具体的值，则会使用这个值作为表格的最小高度。
    - 根据可用的块大小（减去标题的高度）计算表格的 CSS 块大小。
4. **重新分配表格块大小:** 如果 CSS 指定了具体的表格块大小，并且该大小大于表格的最小高度，则会将多余的空间重新分配到各个表格分节和行中。
5. **处理折叠的行:** 对于设置了 `visibility: collapse` 的行，将其块大小设置为 0，并相应地减少表格的最小高度。

**`GenerateFragment` 方法的功能：**

1. **生成表格的布局片段:** 这是生成表格在渲染树中实际布局信息的核心方法。它负责将表格的内容（标题、分节等）放置到正确的坐标，并考虑分页、分栏等因素。
2. **处理分页/分栏的断点信息:**  如果存在断点信息，则从断点处恢复布局，包括已消耗的块大小、溢出等信息。
3. **处理表格标题:** 根据标题的位置 (`caption-side`)，将标题的布局结果添加到片段中。
4. **处理表格分节 (thead, tbody, tfoot):**
    - 遍历表格的分节，并为每个分节创建一个约束空间 (`ConstraintSpace`)，这个空间定义了分节内可用的尺寸和布局约束。
    - **处理重复的表头和表尾:**  检测并处理需要在每页或每栏重复显示的表头 (`thead`) 和表尾 (`tfoot`)。这需要判断表头/表尾的大小是否小于容器的某个比例，以及 `break-inside` 属性是否允许避免分页/分栏。
    - 根据是否需要重复显示，调用 `LayoutRepeatableRoot` 或 `Layout` 方法来布局分节。
5. **处理容器的分页/分栏:**  在布局每个子元素后，检查是否需要进行分页或分栏，并在必要时插入断点。
6. **计算表格盒子的范围:**  记录表格内容占据的块状范围 (`table_box_extent`)，这对于后续的布局和渲染至关重要。
7. **处理表格的基线:**  记录表格的首行基线和末行基线。
8. **处理 `visibility: collapse` 的行:**  在生成片段时，跳过 `visibility: collapse` 的行。
9. **生成最终的布局结果:** 将所有子元素的布局结果（包括位置和尺寸）添加到容器构建器 (`container_builder_`) 中，并返回最终的布局结果 (`LayoutResult`).

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  代码处理的是 HTML 表格元素 (`<table>`, `<caption>`, `<thead>`, `<tbody>`, `<tfoot>`, `<tr>`, `<td>`, `<th>`) 的布局。例如，`grouped_children` 包含了对这些 HTML 元素的组织结构信息。
* **CSS:** 代码大量使用了从 CSS 样式中获取的属性来决定布局。
    * **`height`, `min-height`:**  在 `ComputeRows` 中，CSS 的 `height` 和 `min-height` 属性影响表格的块大小计算。例如，如果 CSS 设置了 `table { height: 200px; }`，那么 `css_table_block_size` 将会被设置为 200px。
    * **`caption-side`:** 在 `GenerateFragment` 中，CSS 的 `caption-side` 属性决定了标题是显示在表格上方还是下方。
    * **`border-spacing`:** `border_spacing` 变量代表 CSS 的 `border-spacing` 属性，影响单元格之间的间距。
    * **`border-collapse`:** `table_borders.IsCollapsed()` 反映了 CSS 的 `border-collapse` 属性，决定边框是否合并。
    * **`break-inside`:** 在处理重复表头/表尾时，会检查 CSS 的 `break-inside` 属性，以判断是否允许在表头/表尾内部进行分页/分栏。
    * **`visibility: collapse`:** 代码会检查行的 `visibility` 属性是否为 `collapse`，并相应地处理行的块大小。
* **JavaScript:**  JavaScript 通常不直接参与 Blink 引擎的布局计算，但可以通过以下方式间接影响：
    * **DOM 操作:** JavaScript 可以动态地添加、删除或修改表格的 HTML 结构，这会导致重新进行布局计算。例如，使用 JavaScript 向表格中添加一行新的 `<tr>` 元素，会导致 `ComputeRows` 和 `GenerateFragment` 重新执行。
    * **修改 CSS 样式:** JavaScript 可以修改表格的 CSS 样式，例如通过修改 `style` 属性或操作 CSS 类，从而影响布局。例如，JavaScript 可以动态地修改表格的 `height` 属性，这将直接影响 `ComputeRows` 的计算结果。

**逻辑推理的假设输入与输出举例:**

**`ComputeRows` 的例子：**

**假设输入:**

* 一个包含三行的 `<tbody>` 元素。
* 每行的高度由其内容决定，分别是 20px, 30px, 25px。
* `border-spacing` 设置为 5px。
* 表格的 CSS `min-height` 没有设置或为 `auto`。

**逻辑推理:**

1. `ComputeSectionMinimumRowBlockSizes` 会计算每行的最小高度。
2. `total_table_min_block_size_` 初始为 0。
3. 遍历每行，累加行高和行间距：
   - 第一行后：`total_table_min_block_size_` = 20px + 5px = 25px
   - 第二行后：`total_table_min_block_size_` = 25px + 30px + 5px = 60px
   - 第三行后：`total_table_min_block_size_` = 60px + 25px = 85px
4. 由于 `min-height` 为 `auto`，且没有更大的 CSS 块大小被指定，最终 `*minimal_table_grid_block_size` 将接近 `total_table_min_block_size_`，即 85px。

**假设输入（包含固定高度的表格）：**

* 同上的 `<tbody>` 元素和行高。
* 表格的 CSS 设置了 `height: 150px;`。
* `border-spacing` 设置为 5px。

**逻辑推理:**

1. 计算出的 `total_table_min_block_size_` 仍然是 85px。
2. `css_table_block_size` 将被设置为 150px。
3. `distributable_block_size` = max(0, 150px - (可能的边框和内边距之和)) - 85px。
4. 如果有可分配的空间，`DistributeTableBlockSizeToSections` 将会把剩余的空间分配给表格的分节和行。

**`GenerateFragment` 的例子：**

**假设输入:**

* 一个包含表头 (`<thead>`) 和表体 (`<tbody>`) 的表格。
* 表头的高度计算后为 40px。
* 表体的初始 `child_block_offset` 为 0。
* `border-spacing.block_size` 为 5px。

**逻辑推理:**

1. 布局表头时，`child_block_offset` 会加上 `BlockStartBorderPadding()` (可能是表格的上边框和内边距)，然后加上可能的 `border_spacing_before_first_section`。
2. 表头布局完成后，其高度为 40px。
3. 布局表体时，如果表头不是第一个分节，`collapsible_border_spacing` 将会是 `border_spacing.block_size` (5px)。
4. 表体的 `child_block_offset` 将会是之前表头的偏移量加上表头的高度，再加上 `collapsible_border_spacing`，即  `初始偏移 + 表头上边框内边距 + border_spacing + 40px + 5px`。

**用户或编程常见的使用错误举例:**

1. **CSS 冲突或优先级问题:** 用户可能设置了相互冲突的 CSS 属性，导致表格布局不符合预期。例如，同时设置了 `height` 和 `max-height`，或者在不同的 CSS 规则中对同一表格元素设置了不同的高度值。
2. **误解 `border-collapse` 的作用:**  用户可能不理解 `border-collapse: collapse;` 和 `border-collapse: separate;` 的区别，导致边框的显示方式与预期不符。例如，在 `collapse` 模式下，设置单元格的边框间距 (`border-spacing`) 将不起作用。
3. **忘记设置必要的 CSS 属性:**  用户可能忘记为表格或其子元素设置必要的 CSS 属性，例如宽度、高度、对齐方式等，导致浏览器使用默认值，从而产生不期望的布局结果。
4. **JavaScript 动态修改导致布局混乱:**  过度或不当的 JavaScript DOM 操作可能会导致表格的布局在每次更新后都发生变化，甚至出现布局错误。例如，频繁地添加或删除表格行，而没有考虑到性能和布局的影响。
5. **误用 `visibility: collapse`:** 用户可能错误地使用 `visibility: collapse` 来隐藏行，期望它像 `display: none` 一样不占用空间，但实际上 `collapse` 只是隐藏了行，仍然会影响表格的布局。
6. **在嵌套表格中出现意外布局:**  复杂的嵌套表格结构可能会导致布局问题，尤其是在涉及边框合并、百分比宽度等方面。用户可能需要在 CSS 中仔细控制每个表格的布局属性。

总而言之，这段代码负责实现 Blink 引擎中表格布局的核心逻辑，它深入地处理了 HTML 表格结构和 CSS 样式，并考虑了复杂的分页和分栏场景。理解这段代码有助于深入了解浏览器如何渲染和布局 HTML 表格。

Prompt: 
```
这是目录为blink/renderer/core/layout/table/table_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
return MinMaxSizesResult{min_max,
                           /* depends_on_block_constraints */ false};
}

void TableLayoutAlgorithm::ComputeRows(
    const LayoutUnit table_grid_inline_size,
    const TableGroupedChildren& grouped_children,
    const Vector<TableColumnLocation>& column_locations,
    const TableBorders& table_borders,
    const LogicalSize& border_spacing,
    const BoxStrut& table_border_padding,
    const LayoutUnit captions_block_size,
    TableTypes::Rows* rows,
    TableTypes::CellBlockConstraints* cell_block_constraints,
    TableTypes::Sections* sections,
    LayoutUnit* minimal_table_grid_block_size) {
  DCHECK_EQ(rows->size(), 0u);
  DCHECK_EQ(cell_block_constraints->size(), 0u);

  const TableBreakTokenData* table_break_data = nullptr;
  if (GetBreakToken()) {
    table_break_data =
        DynamicTo<TableBreakTokenData>(GetBreakToken()->TokenData());
  }
  if (table_break_data) {
    DCHECK(IsBreakInside(GetBreakToken()));
    *rows = table_break_data->rows;
    *cell_block_constraints = table_break_data->cell_block_constraints;
    *sections = table_break_data->sections;
    total_table_min_block_size_ = table_break_data->total_table_min_block_size;
  } else {
    DCHECK_EQ(total_table_min_block_size_, LayoutUnit());
    const bool is_table_block_size_specified =
        !Style().LogicalHeight().IsAuto();
    wtf_size_t section_index = 0;
    for (auto it = grouped_children.begin(); it != grouped_children.end();
         ++it) {
      ComputeSectionMinimumRowBlockSizes(
          *it, table_grid_inline_size, is_table_block_size_specified,
          column_locations, table_borders, border_spacing.block_size,
          section_index++, it.TreatAsTBody(), sections, rows,
          cell_block_constraints);
      total_table_min_block_size_ += sections->back().block_size;
    }
  }

  const ConstraintSpace& space = GetConstraintSpace();

  LayoutUnit css_table_block_size;
  if (space.IsInitialBlockSizeIndefinite() && !space.IsFixedBlockSize()) {
    // We get here when a flexbox wants to use the table's intrinsic height as
    // an input to the flex algorithm.
    css_table_block_size = kIndefiniteSize;
  } else {
    // If we can correctly resolve our min-block-size we want to distribute
    // sections/rows into this space. Pass a definite intrinsic block-size into
    // |ComputeBlockSizeForFragment| to force it to resolve.
    //
    // NOTE: We use `ResolveMainBlockLength` for resolving `min_length` so that
    // it will resolve to `kIndefiniteSize` if unresolvable.
    const Length& min_length = Style().LogicalMinHeight();
    const LayoutUnit intrinsic_block_size =
        min_length.HasAuto() ||
                ResolveMainBlockLength(space, Style(), table_border_padding,
                                       min_length, /* auto_length */ nullptr,
                                       kIndefiniteSize) == kIndefiniteSize
            ? kIndefiniteSize
            : table_border_padding.BlockSum();

    LayoutUnit override_available_block_size = kIndefiniteSize;
    if (space.AvailableSize().block_size != kIndefiniteSize) {
      override_available_block_size =
          (space.AvailableSize().block_size - captions_block_size)
              .ClampNegativeToZero();
    }

    css_table_block_size = ComputeBlockSizeForFragment(
        space, Node(), table_border_padding, intrinsic_block_size,
        table_grid_inline_size, override_available_block_size);
  }
  // In quirks mode, empty tables ignore any specified block-size.
  const bool is_empty_quirks_mode_table =
      Node().GetDocument().InQuirksMode() &&
      grouped_children.begin() == grouped_children.end();

  // Redistribute CSS table block size if necessary.
  if (css_table_block_size != kIndefiniteSize && !is_empty_quirks_mode_table) {
    *minimal_table_grid_block_size = css_table_block_size;
    LayoutUnit distributable_block_size = std::max(
        LayoutUnit(), css_table_block_size - table_border_padding.BlockSum());
    if (distributable_block_size > total_table_min_block_size_) {
      DistributeTableBlockSizeToSections(
          border_spacing.block_size, distributable_block_size, sections, rows);
    }
  }

  for (auto& row : *rows) {
    if (!row.is_collapsed)
      continue;

    // Collapsed rows get zero block-size, and shrink the minimum table size.
    // TODO(ikilpatrick): As written |minimal_table_grid_block_size| can go
    // negative. Investigate.
    if (*minimal_table_grid_block_size != LayoutUnit()) {
      *minimal_table_grid_block_size -= row.block_size;
      if (rows->size() > 1)
        *minimal_table_grid_block_size -= border_spacing.block_size;
    }
    row.block_size = LayoutUnit();
  }
}

// Method also sets LogicalWidth/Height on columns.
void TableLayoutAlgorithm::ComputeTableSpecificFragmentData(
    const TableGroupedChildren& grouped_children,
    const Vector<TableColumnLocation>& column_locations,
    const TableTypes::Rows& rows,
    const TableBorders& table_borders,
    const LogicalRect& table_grid_rect,
    const LayoutUnit table_grid_block_size) {
  container_builder_.SetTableGridRect(table_grid_rect);
  container_builder_.SetTableColumnCount(column_locations.size());
  container_builder_.SetHasCollapsedBorders(table_borders.IsCollapsed());
  // Column geometries.
  if (grouped_children.columns.size() > 0) {
    ColumnGeometriesBuilder geometry_builder(column_locations,
                                             table_grid_block_size);
    VisitLayoutTableColumn(grouped_children.columns, column_locations.size(),
                           &geometry_builder);
    geometry_builder.Sort();
    container_builder_.SetTableColumnGeometries(
        geometry_builder.column_geometries);
  }
  // Collapsed borders.
  if (!table_borders.IsEmpty()) {
    std::unique_ptr<TableFragmentData::CollapsedBordersGeometry>
        fragment_borders_geometry =
            std::make_unique<TableFragmentData::CollapsedBordersGeometry>();
    for (const auto& column : column_locations)
      fragment_borders_geometry->columns.push_back(column.offset);
    DCHECK_NE(column_locations.size(), 0u);
    fragment_borders_geometry->columns.push_back(
        column_locations.back().offset + column_locations.back().size);

    // Ensure the dimensions of table_borders and fragment_borders_geometry are
    // consistent.
    DCHECK_LE(table_borders.EdgesPerRow() / 2,
              fragment_borders_geometry->columns.size());

    container_builder_.SetTableCollapsedBorders(table_borders);
    container_builder_.SetTableCollapsedBordersGeometry(
        std::move(fragment_borders_geometry));
  }
}

// Generated fragment structure
// +---- table wrapper fragment ----+
// |     top caption fragments      |
// |     table border/padding       |
// |       block_spacing            |
// |         section                |
// |       block_spacing            |
// |         section                |
// |       block_spacing            |
// |     table border/padding       |
// |     bottom caption fragments   |
// +--------------------------------+
const LayoutResult* TableLayoutAlgorithm::GenerateFragment(
    const LayoutUnit table_inline_size,
    LayoutUnit minimal_table_grid_block_size,
    const TableGroupedChildren& grouped_children,
    const Vector<TableColumnLocation>& column_locations,
    const TableTypes::Rows& rows,
    const TableTypes::CellBlockConstraints& cell_block_constraints,
    const TableTypes::Sections& sections,
    const HeapVector<CaptionResult>& captions,
    const TableBorders& table_borders,
    const LogicalSize& border_spacing) {
  const TableBreakTokenData* incoming_table_break_data = nullptr;
  LogicalBoxSides border_padding_sides_to_include;
  const auto& constraint_space = GetConstraintSpace();
  const LayoutUnit fragmentainer_space_at_start =
      FragmentainerSpaceLeftForChildren();
  LayoutUnit previously_consumed_block_size;
  LayoutUnit previously_consumed_table_box_block_size;

  // border-spacing that is to be added before the first table section (if any)
  // in this fragment. We will omit this when resuming table box layout in a
  // subsequent fragment.
  LayoutUnit border_spacing_before_first_section = border_spacing.block_size;

  LayoutUnit monolithic_overflow;
  bool is_past_table_box = false;
  if (GetBreakToken()) {
    previously_consumed_block_size = GetBreakToken()->ConsumedBlockSize();
    monolithic_overflow = GetBreakToken()->MonolithicOverflow();
    incoming_table_break_data =
        DynamicTo<TableBreakTokenData>(GetBreakToken()->TokenData());
    if (incoming_table_break_data) {
      previously_consumed_table_box_block_size =
          incoming_table_break_data->consumed_table_box_block_size;
      minimal_table_grid_block_size -=
          incoming_table_break_data->consumed_table_box_block_size;
      is_past_table_box = incoming_table_break_data->is_past_table_box;
      if (incoming_table_break_data->has_entered_table_box) {
        // The block-start border won't be in this fragment when resuming in the
        // slicing box decoration break model (and also not in the cloning
        // model, if we're already past the table box (and just dealing with
        // bottom captions, essentially)).
        if (Style().BoxDecorationBreak() == EBoxDecorationBreak::kSlice ||
            is_past_table_box) {
          border_padding_sides_to_include.block_start = false;
        }
        border_spacing_before_first_section = LayoutUnit();
      }
      if (is_past_table_box)
        border_padding_sides_to_include.block_end = false;
    }
  }

  const auto table_writing_direction = Style().GetWritingDirection();
  scoped_refptr<const TableConstraintSpaceData> constraint_space_data =
      CreateConstraintSpaceData(Style(), column_locations, sections, rows,
                                cell_block_constraints, border_spacing);

  const BoxStrut border_padding = container_builder_.BorderScrollbarPadding();
  const bool has_collapsed_borders = table_borders.IsCollapsed();

  // The current layout position.
  LayoutUnit child_block_offset;

  // border-spacing to add after the last table section in this fragment. We may
  // want to omit it in some cases, in which case it will be set to 0.
  LayoutUnit border_spacing_after_last_section;

  bool has_container_separation = false;

  auto AddCaptionResult = [&](const CaptionResult& caption,
                              LayoutUnit* block_offset) -> void {
    *block_offset += caption.margins.block_start;
    container_builder_.AddResult(
        *caption.layout_result,
        LogicalOffset(caption.margins.inline_start, *block_offset),
        caption.margins);

    *block_offset +=
        LogicalFragment(table_writing_direction,
                        caption.layout_result->GetPhysicalFragment())
            .BlockSize() +
        caption.margins.block_end;
  };

  // We have already laid out the captions, in order to calculate the table grid
  // size. We can re-use these results now, unless we're in block fragmentation.
  // In that case we need to lay them out again now, so that they fragment and
  // resume properly.
  const bool relayout_captions =
      InvolvedInBlockFragmentation(container_builder_);

  // Add all the top captions.
  if (!relayout_captions) {
    for (const auto& caption : captions) {
      if (caption.node.Style().CaptionSide() == ECaptionSide::kTop)
        AddCaptionResult(caption, &child_block_offset);
    }
  }

  // Section setup.
  const LayoutUnit section_available_inline_size =
      (table_inline_size - border_padding.InlineSum() -
       border_spacing.inline_size * 2)
          .ClampNegativeToZero();

  enum ESectionRepeatMode { kNotRepeated, kMayRepeatAgain, kRepeatedLast };

  auto CreateSectionConstraintSpace = [&table_writing_direction,
                                       &section_available_inline_size,
                                       &constraint_space_data, &sections, this](
                                          const BlockNode& section,
                                          LayoutUnit fragmentainer_block_offset,
                                          wtf_size_t section_index,
                                          LayoutUnit reserved_space,
                                          ESectionRepeatMode repeat_mode) {
    ConstraintSpaceBuilder section_space_builder(
        GetConstraintSpace(), table_writing_direction, /* is_new_fc */ true);

    LogicalSize available_size = {section_available_inline_size,
                                  kIndefiniteSize};

    // Sections without rows can receive redistributed height from the table.
    if (constraint_space_data->sections[section_index].row_count == 0) {
      section_space_builder.SetIsFixedBlockSize(true);
      available_size.block_size = sections[section_index].block_size;
    }

    section_space_builder.SetAvailableSize(available_size);
    section_space_builder.SetIsFixedInlineSize(true);
    section_space_builder.SetPercentageResolutionSize(
        {section_available_inline_size, kIndefiniteSize});
    section_space_builder.SetTableSectionData(constraint_space_data,
                                              section_index);

    if (repeat_mode != kNotRepeated) {
      section_space_builder.SetShouldRepeat(repeat_mode == kMayRepeatAgain);
      section_space_builder.SetIsInsideRepeatableContent(true);
      section_space_builder.SetShouldPropagateChildBreakValues(false);
    } else if (GetConstraintSpace().HasBlockFragmentation()) {
      // Note that, with fragmentainer_block_offset, we pretend that any
      // repeated table header isn't there (since it doesn't really participate
      // in block fragmentation anyway), so that the block-offset right after
      // such a header will be at 0, as far as block fragmentation is concerned.
      // This way the fragmentation engine will refuse to insert a break before
      // having made some content progress (even if the first piece of content
      // doesn't fit).
      SetupSpaceBuilderForFragmentation(container_builder_, section,
                                        fragmentainer_block_offset,
                                        &section_space_builder);

      // Reserve space for any repeated header / footer.
      if (GetConstraintSpace().HasKnownFragmentainerBlockSize()) {
        section_space_builder.ReserveSpaceInFragmentainer(reserved_space);
      }
    }

    return section_space_builder.ToConstraintSpace();
  };

  auto BlockStartBorderPadding = [&border_padding,
                                  &border_padding_sides_to_include]() {
    if (border_padding_sides_to_include.block_start)
      return border_padding.block_start;
    return LayoutUnit();
  };

  const LayoutUnit section_inline_offset =
      border_padding.inline_start + border_spacing.inline_size;

  std::optional<TableBoxExtent> table_box_extent;
  std::optional<LayoutUnit> first_baseline;
  std::optional<LayoutUnit> last_baseline;

  bool has_repeated_header = false;
  bool has_pending_repeated_footer = false;
  LayoutUnit repeated_footer_block_size;

  // Before fragmented layout we need to go through the table's children, to
  // look for repeatable headers and footers. This is especially important for
  // footers, since we need to reserve space for it after any preceding
  // non-repeated sections (typically tbody). We'll only repeat headers /
  // footers if we're not already inside repeatable content, though. See
  // crbug.com/1352931 for more details. Furthermore, we cannot repeat content
  // if side-effects are disabled, as that machinery depends on updating and
  // reading the physical fragments vector of the LayoutBox.
  if (!GetConstraintSpace().IsInsideRepeatableContent() &&
      !DisableLayoutSideEffectsScope::IsDisabled() &&
      (grouped_children.header || grouped_children.footer)) {
    LayoutUnit max_section_block_size =
        GetConstraintSpace().FragmentainerBlockSize() / 4;
    TableChildIterator child_iterator(grouped_children, GetBreakToken());
    for (auto entry = child_iterator.NextChild();
         BlockNode child = entry.GetNode();
         entry = child_iterator.NextChild()) {
      if (child != grouped_children.header && child != grouped_children.footer)
        continue;

      const BlockBreakToken* child_break_token = entry.GetBreakToken();
      // If we've already broken inside the section, it's not going to repeat,
      // but rather perform regular fragmentation.
      if (IsBreakInside(child_break_token))
        continue;

      LayoutUnit block_size = sections[entry.GetSectionIndex()].block_size;

      // Unless we have already decided to repeat in a previous fragment, check
      // if the block-size of the section is acceptable.
      if (!child_break_token || !child_break_token->IsRepeated()) {
        DCHECK(!child_break_token || child_break_token->IsBreakBefore());

        // If this isn't the first fragment for the table box, and the section
        // didn't repeat in the previous fragment, it doesn't make sense to
        // start repeating now. If this is a header, we may already have
        // finished (non-repeated) layout. If this is a footer, we have already
        // laid out at least one fragment without it.
        if (incoming_table_break_data &&
            incoming_table_break_data->has_entered_table_box)
          continue;

        // Headers and footers may be repeated if their block-size is one
        // quarter or less than that of the fragmentainer, AND 'break-inside'
        // has an applicable avoid* value. Being repeated means that the section
        // is monolithic, and nothing inside can break.
        //
        // See https://www.w3.org/TR/css-tables-3/#repeated-headers
        //
        // We will never make the decision to start repeating if we're in an
        // initial column balancing pass (we have no idea about the block-size
        // of the fragmentainer, so that would be impossible), but we will
        // continue repeating if we previously decided to do so in a previous
        // layout pass, for a previous fragment.
        if (!GetConstraintSpace().HasKnownFragmentainerBlockSize() ||
            block_size > max_section_block_size) {
          continue;
        }

        if (!IsAvoidBreakValue(GetConstraintSpace(),
                               child.Style().BreakInside())) {
          continue;
        }
      }

      if (child == grouped_children.header) {
        has_repeated_header = true;
      } else {
        DCHECK_EQ(child, grouped_children.footer);
        has_pending_repeated_footer = true;

        // We need to reserve space for the repeated footer at the end of the
        // fragmentainer.
        repeated_footer_block_size =
            block_size + border_spacing.block_size +
            (has_collapsed_borders ? border_padding.block_end : LayoutUnit());
      }
    }
  }

  bool has_entered_non_repeated_section = false;
  if (monolithic_overflow) {
    // If the page was overflowed by monolithic content (inside the table) on a
    // previous page, it has to mean that we've already entered a non-repeated
    // section, since those are the only ones that can cause fragmentation
    // overflow.
    has_entered_non_repeated_section = true;
  }

  LayoutUnit grid_block_size_inflation;
  LayoutUnit repeated_header_block_size;
  bool broke_inside = false;
  bool has_ended_table_box_layout = false;
  TableChildIterator child_iterator(grouped_children, GetBreakToken());
  // Generate section fragments; and also caption fragments, if we need to
  // regenerate them (block fragmentation).
  for (auto entry = child_iterator.NextChild();
       BlockNode child = entry.GetNode(); entry = child_iterator.NextChild()) {
    DCHECK(child.IsTableCaption() || child.IsTableSection());

    const EarlyBreak* early_break_in_child = nullptr;
    if (early_break_) [[unlikely]] {
      if (IsEarlyBreakTarget(*early_break_, container_builder_, child)) {
        container_builder_.AddBreakBeforeChild(child, kBreakAppealPerfect,
                                               /* is_forced_break */ false);
        broke_inside = true;

        if (child == grouped_children.footer)
          has_pending_repeated_footer = false;

        break;
      }
      early_break_in_child = EnterEarlyBreakInChild(child, *early_break_);
    }

    const BlockBreakToken* child_break_token = entry.GetBreakToken();
    const LayoutResult* child_result;
    std::optional<LayoutUnit> offset_before_repeated_header;
    LayoutUnit child_inline_offset;

    // Captions allow margins.
    LayoutUnit child_block_start_margin;
    LayoutUnit child_block_end_margin;

    std::optional<TableBoxExtent> new_table_box_extent;
    bool is_repeated_section = false;
    bool has_overlapping_repeated_header = false;

    if (child.IsTableCaption()) {
      if (!relayout_captions)
        continue;
      if (child.Style().CaptionSide() == ECaptionSide::kBottom &&
          !is_past_table_box) {
        DCHECK(!has_ended_table_box_layout);
        // We found the first bottom caption, which means that we're done with
        // all the sections (if any). We need to calculate the grid size now, so
        // that we set the block-offset for the caption correctly.
        if (!table_box_extent) {
          // There was no section to kick off "table box" extent
          // calculation. Do it now.
          table_box_extent = BeginTableBoxLayout(child_block_offset,
                                                 BlockStartBorderPadding());
        }

        child_block_offset = EndTableBoxLayout(
            border_padding.block_end, border_spacing_after_last_section,
            minimal_table_grid_block_size, &(*table_box_extent),
            &grid_block_size_inflation);
        has_ended_table_box_layout = true;

        // We're done with the table box if it fits inside the fragmentainer.
        is_past_table_box =
            !constraint_space.HasKnownFragmentainerBlockSize() ||
            table_box_extent->end <= fragmentainer_space_at_start;
      }

      LogicalSize available_size(container_builder_.InlineSize(),
                                 kIndefiniteSize);
      BoxStrut margins = ComputeCaptionMargins(constraint_space, child,
                                               container_builder_.InlineSize(),
                                               child_break_token);
      child_block_start_margin = margins.block_start;
      child_block_end_margin = margins.block_end;

      ConstraintSpace child_space = CreateCaptionConstraintSpace(
          constraint_space, Style(), child, available_size,
          child_block_offset + child_block_start_margin);
      CaptionResult caption = LayoutCaption(
          constraint_space, Style(), container_builder_.InlineSize(),
          child_space, child, margins, child_break_token, early_break_in_child);
      DCHECK_EQ(caption.layout_result->Status(), LayoutResult::kSuccess);
      child_result = caption.layout_result;
      child_inline_offset = caption.margins.inline_start;

      // Captions don't need to worry about repeated sections.
      repeated_header_block_size = LayoutUnit();
    } else {
      DCHECK(child.IsTableSection());
      LayoutUnit collapsible_border_spacing;
      if (table_box_extent) {
        // This is not the first section. Just add border-spacing.
        collapsible_border_spacing = border_spacing.block_size;
      } else {
        // Entering the first section in this fragment. This is where the "table
        // box" starts.
        new_table_box_extent =
            BeginTableBoxLayout(child_block_offset, BlockStartBorderPadding());
        child_block_offset += BlockStartBorderPadding();

        // We need to lay the section out before we can tell whether it should
        // be preceded by border-spacing (if there is nothing inside, it should
        // be omitted).
        collapsible_border_spacing = border_spacing_before_first_section;
      }

      LayoutUnit offset_for_childless_section = child_block_offset;

      bool may_repeat_again = false;
      if (child == grouped_children.header) {
        if (has_repeated_header) {
          is_repeated_section = true;
          // Unless we've already been at the end, we cannot tell whether this
          // is the last time the header will repeat. We will tentatively have
          // to make it repeatable. If this turns out to be wrong, because we
          // reach the end in this fragment, we need to abort and relayout.
          may_repeat_again = !is_known_to_be_last_table_box_;

          // We need to measure the block-size of the repeated header, because
          // this is something we have to subtract from available fragmentainer
          // block-size, AND fragmentainer block-offset, when laying out
          // non-repeated content (i.e. regular sections).
          offset_before_repeated_header.emplace(child_block_offset);

          if (monolithic_overflow) {
            // There's monolithic content from previous pages in the way, but we
            // still want to place the table header at the block-start. In
            // addition to this (probably) making sense, our implementation
            // requires it. Once we have decided to repeat a table section, we
            // need to be consistent about it. Take the header "out of flow",
            // and just restore the block-offset back to
            // offset_before_repeated_header afterwards.
            child_block_offset = -monolithic_overflow;
            has_overlapping_repeated_header = true;
          }

          // A header will share its collapsed border with the block-start of
          // the table. However when repeated it will draw the whole border
          // itself. We need to reserve additional space at the block-start for
          // this additional border space.
          if (has_collapsed_borders &&
              !border_padding_sides_to_include.block_start)
            child_block_offset += border_padding.block_start;
        }
      } else if (child == grouped_children.footer) {
        if (has_pending_repeated_footer) {
          is_repeated_section = true;
          // For footers it's easier, though. Since we got all the way to the
          // footer during layout, this means that this will be the last time
          // the footer is repeated. We can finish it right away, unless we have
          // a repeated header as well (which means that we're going to
          // relayout).
          has_pending_repeated_footer = false;
          may_repeat_again =
              !is_known_to_be_last_table_box_ && has_repeated_header;
        }
      }

      child_block_offset += collapsible_border_spacing;

      ESectionRepeatMode repeat_mode = kNotRepeated;
      if (is_repeated_section)
        repeat_mode = may_repeat_again ? kMayRepeatAgain : kRepeatedLast;

      LayoutUnit reserved_space;
      if (repeat_mode == kNotRepeated) {
        reserved_space =
            repeated_header_block_size + repeated_footer_block_size;
      }

      ConstraintSpace child_space = CreateSectionConstraintSpace(
          child, child_block_offset - repeated_header_block_size,
          entry.GetSectionIndex(), reserved_space, repeat_mode);
      if (is_repeated_section) {
        child_result =
            child.LayoutRepeatableRoot(child_space, child_break_token);
      } else {
        child_result =
            child.Layout(child_space, child_break_token, early_break_in_child);
      }
      child_inline_offset = section_inline_offset;

      border_spacing_after_last_section = border_spacing.block_size;
      if (To<PhysicalBoxFragment>(child_result->GetPhysicalFragment())
              .HasDescendantsForTablePart()) {
        // We want to add border-spacing after this section, but not if the
        // current fragment is past the block-end of the section. This might
        // happen if there are overflowing descendants, and this section should
        // just create an zero-sized fragment.
        if (child_break_token && child_break_token->IsAtBlockEnd())
          border_spacing_after_last_section = LayoutUnit();
      } else {
        // There were no children inside. Omit the border-spacing previously
        // added. Note that we should ideally re-lay out now if we're
        // block-fragmented and ran out of space (the section may have had a
        // non-zero block-size, for instance), since that would mean that we've
        // used less space than actually turned out to be available. However,
        // nobody will probably notice, and besides, our "empty section
        // handling" isn't identical to other engines anyway.
        child_block_offset = offset_for_childless_section;
      }
    }
    if (constraint_space.HasBlockFragmentation() &&
        (!child_break_token || !is_repeated_section)) {
      LayoutUnit fragmentainer_block_offset =
          FragmentainerOffsetForChildren() + child_block_start_margin +
          child_block_offset - repeated_header_block_size;
      BreakStatus break_status = BreakBeforeChildIfNeeded(
          child, *child_result, fragmentainer_block_offset,
          has_container_separation);
      if (break_status == BreakStatus::kNeedsEarlierBreak) {
        return container_builder_.Abort(LayoutResult::kNeedsEarlierBreak);
      }
      if (break_status == BreakStatus::kBrokeBefore) {
        broke_inside = true;
        break;
      }
      DCHECK_EQ(break_status, BreakStatus::kContinue);
    }

    const auto& physical_fragment =
        To<PhysicalBoxFragment>(child_result->GetPhysicalFragment());
    LogicalBoxFragment fragment(table_writing_direction, physical_fragment);
    if (child.IsTableSection()) {
      if (!is_repeated_section) {
        has_entered_non_repeated_section = true;
      }
      if (!first_baseline) {
        if (const auto& section_first_baseline = fragment.FirstBaseline())
          first_baseline = child_block_offset + *section_first_baseline;
      }
      if (const auto& section_last_baseline = fragment.LastBaseline())
        last_baseline = child_block_offset + *section_last_baseline;
    }

    child_block_offset += child_block_start_margin;
    container_builder_.AddResult(
        *child_result, LogicalOffset(child_inline_offset, child_block_offset));
    child_block_offset += fragment.BlockSize() + child_block_end_margin;

    if (child.IsTableSection()) {
      if (offset_before_repeated_header) {
        repeated_header_block_size = child_block_offset -
                                     *offset_before_repeated_header +
                                     border_spacing.block_size;

        if (has_overlapping_repeated_header) {
          // The header was taken "out of flow" and placed on top of monolithic
          // content. Now make sure that the offset is past the monolithic
          // overflow again (AND past the header).
          child_block_offset =
              std::max(child_block_offset, *offset_before_repeated_header);
        }
      }

      if (new_table_box_extent) {
        // The first section was added successfully. We're officially inside the
        // table box!
        DCHECK(!table_box_extent);
        table_box_extent = new_table_box_extent;
      }
      // Update the "table box" extent, now that we're past one section.
      table_box_extent->end = child_block_offset;
    } else if (child.Style().CaptionSide() == ECaptionSide::kBottom) {
      // We've successfully added bottom caption content, so we're past the
      // table box.
      is_past_table_box = true;
    }

    if (constraint_space.HasBlockFragmentation()) {
      if (!has_container_separation)
        has_container_separation = !is_repeated_section;
      if (container_builder_.HasInflowChildBreakInside()) {
        broke_inside = true;
        break;
      }
    }
  }

  if (!table_box_extent && !is_past_table_box && !broke_inside) {
    // We're not past the table box, we didn't break inside, but there was no
    // section to kick off "table box" extent calculation. Do it now.
    table_box_extent =
        BeginTableBoxLayout(child_block_offset, BlockStartBorderPadding());
  }

  bool table_box_will_continue =
      table_box_extent && !is_past_table_box && broke_inside;

  if (has_pending_repeated_footer && table_box_extent) {
    DCHECK(table_box_will_continue);
    // We broke before we got to the footer. Add it now. Before doing that,
    // though, also insert break tokens for the sections that we didn't get to
    // (if any), so that things will be resumed correctly when laying out the
    // next table fragment (inserting a break token for the repeated footer
  
"""


```