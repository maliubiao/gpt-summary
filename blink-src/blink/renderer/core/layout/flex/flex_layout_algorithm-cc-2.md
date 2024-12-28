Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. The request specifically asks to identify:

1. **Functionality:** What does this code do?
2. **Relation to web technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and I/O:**  If there's logic, what are potential inputs and outputs?
4. **Common errors:** What are typical mistakes users or programmers might make?
5. **Overall function:** A concise summary of the code's purpose.

This is the third of four parts, indicating a larger context within the `flex_layout_algorithm.cc` file.

Let's break down the provided code snippet:

*   It iterates through flex items within a flex container.
*   It handles line breaks and fragmentation.
*   It deals with early breaks (likely for pagination or similar features).
*   It calculates and adjusts offsets for items and lines.
*   It considers `break-before`, `break-inside` CSS properties.
*   It interacts with a `container_builder_` to record layout information.
*   It updates intrinsic block sizes.
*   It manages baseline calculations for text alignment.
*   It handles relayout scenarios due to row cross-size changes.
*   It calls `Layout` on individual flex items.
*   It interacts with `BreakBeforeChildIfNeeded` and `BreakBeforeRowIfNeeded` functions, suggesting it manages how items and rows break across fragmentainers.
*   It considers column layout specifically.

**Plan:**

1. **Summarize core function:** The code is responsible for the main layout logic within a flex container, handling item placement, breaks, and fragmentation.
2. **Connect to web technologies:**
    *   **CSS:**  Directly relates to CSS flexbox properties (`display: flex`, `flex-direction`, `flex-wrap`, `break-before`, `break-inside`, `align-items`, `align-content`).
    *   **HTML:** The layout algorithm operates on the structure of HTML elements marked as flex containers and their children (flex items).
    *   **JavaScript:**  While this code isn't directly JavaScript, the layout calculated here is what JavaScript layout-related APIs (like `getBoundingClientRect`) would report. Changes in CSS or HTML manipulated by JavaScript would trigger this layout code.
3. **Hypothesize inputs and outputs:**
    *   **Input:**  Flex items (their dimensions, styles, break properties), available space, current break state, early break information.
    *   **Output:** Updated offsets of flex items, indication of breaks, updated intrinsic sizes.
4. **Identify common errors:**  Focus on CSS flexbox usage errors that might lead to unexpected behavior this code handles.
5. **Summarize the snippet's role:** This part of the code specifically deals with iterating through flex items, applying break rules, and calculating their positions within a potentially fragmented flex container.
这是`FlexLayoutAlgorithm`类中处理 flex 布局的核心逻辑的一部分，专注于在分片（fragmentation）上下文中迭代和定位 flex 项目。它在布局过程中考虑了各种断点、早期中断、以及由于分片而产生的尺寸调整。

以下是其功能的归纳：

**功能归纳：**

1. **迭代处理 Flex 项目：**  这段代码是主循环，负责遍历 flex 容器中的每一个 flex 项目（由 `item_iterator` 管理）。它会考虑项目或行之前是否需要断开。
2. **处理分片和断点：** 核心功能是处理 flex 容器在分片环境下的布局。它检查项目和行的断点（`break-before`, `break-inside` CSS 属性），并根据这些断点调整项目的位置和容器的布局。
3. **管理早期中断（Early Breaks）：** 代码支持“早期中断”机制，这通常用于分页或多栏布局等场景。它会检查是否存在针对当前项目的早期中断目标，如果找到，则会提前结束当前分片的布局。
4. **调整项目偏移：**  根据断点情况（包括 forced breaks），代码会精确地调整每个 flex 项目在其所在行或列中的偏移量 (`offset`)，以及行的偏移调整 (`line_output.item_offset_adjustment`)，以确保在分片后项目正确排列。
5. **处理跨轴尺寸调整：** 当由于分片导致行的高度（对于行主轴）或列的宽度（对于列主轴）需要调整时，这段代码会记录和应用这些调整，并可能触发重新布局。
6. **处理 `min-block-size`：**  它考虑了 `min-block-size` 属性是否应该包含元素的固有尺寸。
7. **调用子元素的布局：**  对于每个 flex 项目，它调用 `flex_item->ng_input_node.Layout()` 来进行子元素的实际布局。
8. **处理子元素的断点：**  在子元素布局之后，它会检查子元素是否产生了断点，并根据需要提前结束当前分片的布局。
9. **累积固有尺寸：** 它会累积 flex 容器的固有块尺寸 (`intrinsic_block_size_`)。
10. **记录布局结果：**  使用 `container_builder_` 记录每个 flex 项目的布局结果和偏移量。
11. **计算基线：** 它使用 `baseline_accumulator` 来计算 flex 容器的第一个和最后一个基线，用于文本对齐。
12. **处理列布局的特殊情况：**  对于列主轴的 flex 容器，代码会处理列间的断点和尺寸调整。

**与 JavaScript, HTML, CSS 的关系：**

*   **CSS:**
    *   **`display: flex` 或 `display: inline-flex`:**  这段代码是 flex 布局算法的一部分，当一个 HTML 元素的 CSS `display` 属性被设置为 `flex` 或 `inline-flex` 时会被激活。
    *   **`flex-direction`:**  决定了主轴的方向，影响着代码中对行和列的处理逻辑（`is_column_` 变量）。
    *   **`flex-wrap`:**  决定了项目是否可以换行，影响多行/多列布局的处理。
    *   **`break-before`, `break-inside`:** 代码直接检查这些 CSS 属性的值（通过 `item_break_token` 和 `GetBreakToken()`），并据此决定是否需要断开。
    *   **`min-block-size`:** 代码中 `MinBlockSizeShouldEncompassIntrinsicSize` 函数与这个 CSS 属性相关。
    *   **`box-decoration-break: clone`:**  代码中处理了当子元素的 `box-decoration-break` 属性为 `clone` 时的情况，这会影响分片时的边框和内边距的渲染。
*   **HTML:**
    *   这段代码处理的是 HTML 元素及其子元素的布局。HTML 的结构定义了 flex 容器和 flex 项目之间的父子关系，这是布局算法的基础。
*   **JavaScript:**
    *   虽然这段 C++ 代码本身不是 JavaScript，但 JavaScript 可以通过 DOM API 操作 HTML 结构和 CSS 样式。当 JavaScript 修改了影响 flex 布局的属性时，会触发 Blink 引擎重新运行布局算法，包括这段代码。
    *   JavaScript 可以使用 `getBoundingClientRect()` 等方法获取元素最终的布局位置和尺寸，这些信息正是由这样的布局算法计算出来的。

**逻辑推理的假设输入与输出：**

**假设输入：**

*   一个 `display: flex` 的 div 容器，`flex-direction: row`，`flex-wrap: wrap`。
*   容器内有多个子 div 元素，其中一个子元素设置了 `break-before: page;`。
*   容器的可用空间有限，需要分片。

**预期输出：**

*   代码会识别出设置了 `break-before: page;` 的子元素。
*   在布局到该子元素之前，如果当前分片还有空间，代码会继续布局之前的元素。
*   当遇到该子元素时，代码会标记一个断点，指示需要在该元素之前开始一个新的分片。
*   该子元素会成为新分片的第一个元素。
*   后续元素的布局会在新分片中进行。
*   `container_builder_` 会记录这些断点信息，以便后续的渲染过程可以正确地分片内容。

**用户或编程常见的使用错误：**

1. **不理解 `break-before` 和 `break-inside` 的作用域：** 开发者可能会错误地认为在 flex 容器上设置 `break-before` 会影响其内部的项目，但实际上这些属性主要应用于 block 级别的元素。在 flex 项目上使用这些属性会影响 flex 项目自身。
    *   **示例：**  在一个 `flex-direction: row` 的容器中，开发者可能错误地在容器上设置 `break-after: always;`，期望每行结束后都分页，但这不会直接起作用。应该在容器内的 flex 项目上设置。
2. **混淆分片容器和普通容器的布局：**  开发者可能不理解在分片容器中，布局的约束和行为与普通容器有所不同，例如尺寸的计算和断点的处理。
3. **过度依赖 JavaScript 来实现分页或分栏：**  虽然 JavaScript 可以操作样式来实现类似的效果，但理解 CSS 的分片属性（如 `break-before` 等）可以直接让浏览器处理分片，可能更高效且符合标准。
4. **忽略了 `box-decoration-break` 对分片的影响：**  当使用边框、内边距或阴影时，`box-decoration-break: clone;` 会导致这些装饰在每个分片中重复绘制，开发者可能没有考虑到这一点。

总而言之，这段代码是 Chromium Blink 引擎中负责处理复杂 flex 布局场景的关键部分，特别是在需要考虑内容分片和各种断点规则的情况下。它确保了在不同分片中 flex 项目的正确排列和尺寸计算，并与 CSS 的 flexbox 和分片特性紧密相关。

Prompt: 
```
这是目录为blink/renderer/core/layout/flex/flex_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
ator(Style());
  bool broke_before_row =
      *break_before_row != FlexBreakTokenData::kNotBreakBeforeRow;
  for (auto entry = item_iterator.NextItem(broke_before_row);
       NGFlexItem* flex_item = entry.flex_item;
       entry = item_iterator.NextItem(broke_before_row)) {
    wtf_size_t flex_item_idx = entry.flex_item_idx;
    wtf_size_t flex_line_idx = entry.flex_line_idx;
    NGFlexLine& line_output = (*flex_line_outputs)[flex_line_idx];
    const auto* item_break_token = To<BlockBreakToken>(entry.token);
    bool last_item_in_line = flex_item_idx == line_output.line_items.size() - 1;

    bool is_first_line = flex_line_idx == 0;
    bool is_last_line = flex_line_idx == flex_line_outputs->size() - 1;

    // A child break in a parallel flow doesn't affect whether we should
    // break here or not. But if the break happened in the same flow, we'll now
    // just finish layout of the fragment. No more siblings should be processed.
    if (!is_column_) {
      if (flex_line_idx != 0 &&
          has_inflow_child_break_inside_line[flex_line_idx - 1])
        break;
    } else {
      // If we are relaying out as a result of an early break, and we have early
      // breaks for more than one column, they will be stored in
      // |additional_early_breaks_|. Keep |early_break_| consistent with that of
      // the current column.
      if (additional_early_breaks_ &&
          flex_line_idx < additional_early_breaks_->size())
        early_break_ = (*additional_early_breaks_)[flex_line_idx];
      else if (early_break_ && flex_line_idx != 0)
        early_break_ = nullptr;

      if (has_inflow_child_break_inside_line[flex_line_idx]) {
        if (!last_item_in_line)
          item_iterator.NextLine();
        continue;
      }
    }

    LayoutUnit row_block_offset =
        !is_column_ ? line_output.cross_axis_offset : LayoutUnit();
    LogicalOffset original_offset =
        flex_item->offset.ToLogicalOffset(is_column_);
    LogicalOffset offset = original_offset;

    // If a row or item broke before, subsequent items and lines need to be
    // adjusted by the expansion amount.
    LayoutUnit individual_item_adjustment;
    if (item_break_token && item_break_token->IsBreakBefore()) {
      if (item_break_token->IsForcedBreak()) {
        // We had previously updated the adjustment to subtract out the total
        // consumed block size up to the break. Now add the total consumed
        // block size in the previous fragmentainer to get the total amount
        // the item or row expanded by. This allows for things like margins
        // and alignment offsets to not get sliced by a forced break.
        line_output.item_offset_adjustment += offset_in_stitched_container;
      } else if (!is_column_ && flex_item_idx == 0 && broke_before_row) {
        // If this is the first time we are handling a break before a row,
        // adjust the offset of items in the row to accommodate the break. The
        // following cases need to be considered:
        //
        // 1. If we are not the first line in the container, and the previous
        // sibling row overflowed the fragmentainer in the block axis, flex
        // items in the current row should be adjusted upward in the block
        // direction to account for the overflowed content.
        //
        // 2. Otherwise, the current row gap should be decreased by the amount
        // of extra space in the previous fragmentainer remaining after the
        // block-end of the previous row. The reason being that we should not
        // clamp row gaps between breaks, similarly to how flex item margins are
        // handled during fragmentation.
        //
        // 3. If the entire row gap was accounted for in the previous
        // fragmentainer, the block-offsets of the flex items in the current row
        // will need to be adjusted downward in the block direction to
        // accommodate the extra space consumed by the container.
        if (*break_before_row == FlexBreakTokenData::kAtStartOfBreakBeforeRow) {
          // Calculate the amount of space remaining in the previous
          // fragmentainer after the block-end of the previous flex row, if any.
          LayoutUnit previous_row_end =
              is_first_line
                  ? LayoutUnit()
                  : (*flex_line_outputs)[flex_line_idx - 1].LineCrossEnd();
          LayoutUnit previous_fragmentainer_unused_space =
              (offset_in_stitched_container - previous_row_end)
                  .ClampNegativeToZero();

          // If there was any remaining space after the previous flex line,
          // determine how much of the row gap was consumed in the previous
          // fragmentainer, if any.
          LayoutUnit consumed_row_gap;
          if (previous_fragmentainer_unused_space) {
            LayoutUnit total_row_block_offset =
                row_block_offset + line_output.item_offset_adjustment;
            LayoutUnit row_gap = total_row_block_offset - previous_row_end;
            DCHECK_GE(row_gap, LayoutUnit());
            consumed_row_gap =
                std::min(row_gap, previous_fragmentainer_unused_space);
          }

          // Adjust the item offsets to account for any overflow or consumed row
          // gap in the previous fragmentainer.
          LayoutUnit row_adjustment = offset_in_stitched_container -
                                      previous_row_end - consumed_row_gap;
          line_output.item_offset_adjustment += row_adjustment;
        }
      } else {
        LayoutUnit total_item_block_offset =
            offset.block_offset + line_output.item_offset_adjustment;
        individual_item_adjustment =
            (offset_in_stitched_container - total_item_block_offset)
                .ClampNegativeToZero();
        // For items in a row, the offset adjustment due to a break before
        // should only apply to the item itself and not to the entire row.
        if (is_column_) {
          line_output.item_offset_adjustment += individual_item_adjustment;
        }
      }
    }

    if (IsBreakInside(item_break_token)) {
      offset.block_offset = BorderScrollbarPadding().block_start;
    } else if (IsBreakInside(GetBreakToken())) {
      // Convert block offsets from stitched coordinate system offsets to being
      // relative to the current fragment. Include space taken up by any cloned
      // block-start decorations (i.e. exclude it from the adjustment).
      LayoutUnit offset_adjustment = offset_in_stitched_container -
                                     line_output.item_offset_adjustment -
                                     BorderScrollbarPadding().block_start;

      offset.block_offset -= offset_adjustment;
      if (!is_column_) {
        offset.block_offset += individual_item_adjustment;
        row_block_offset -= offset_adjustment;
      }
    }

    const EarlyBreak* early_break_in_child = nullptr;
    if (early_break_) [[unlikely]] {
      if (!is_column_)
        container_builder_.SetLineCount(flex_line_idx);
      if (IsEarlyBreakTarget(*early_break_, container_builder_,
                             flex_item->ng_input_node)) {
        container_builder_.AddBreakBeforeChild(flex_item->ng_input_node,
                                               kBreakAppealPerfect,
                                               /* is_forced_break */ false);
        if (early_break_->Type() == EarlyBreak::kLine) {
          *break_before_row = FlexBreakTokenData::kAtStartOfBreakBeforeRow;
        }
        ConsumeRemainingFragmentainerSpace(offset_in_stitched_container,
                                           &line_output);
        // For column flex containers, continue to the next column. For rows,
        // continue until we've processed all items in the current row.
        has_inflow_child_break_inside_line[flex_line_idx] = true;
        if (is_column_) {
          if (!last_item_in_line)
            item_iterator.NextLine();
        } else if (last_item_in_line) {
          DCHECK_EQ(status, LayoutResult::kSuccess);
          break;
        }
        last_line_idx_to_process_first_child_ = flex_line_idx;
        continue;
      } else {
        early_break_in_child =
            EnterEarlyBreakInChild(flex_item->ng_input_node, *early_break_);
      }
    }

    // If we are re-laying out one or more rows with an updated cross-size,
    // adjust the row info to reflect this change (but only if this is the first
    // time we are processing the current row in this layout pass).
    if (cross_size_adjustments_) [[unlikely]] {
      DCHECK(!is_column_);
      // Maps don't allow keys of 0, so adjust the index by 1.
      if (cross_size_adjustments_->Contains(flex_line_idx + 1) &&
          (last_line_idx_to_process_first_child_ == kNotFound ||
           last_line_idx_to_process_first_child_ < flex_line_idx)) {
        LayoutUnit row_block_size_adjustment =
            cross_size_adjustments_->find(flex_line_idx + 1)->value;
        line_output.line_cross_size += row_block_size_adjustment;

        // Adjust any subsequent row offsets to reflect the current row's new
        // size.
        AdjustOffsetForNextLine(flex_line_outputs, flex_line_idx,
                                row_block_size_adjustment);
      }
    }

    std::optional<LayoutUnit> line_cross_size_for_stretch =
        DoesItemStretch(flex_item->ng_input_node)
            ? std::optional<LayoutUnit>(line_output.line_cross_size)
            : std::nullopt;

    // If an item broke, its offset may have expanded (as the result of a
    // current or previous break before), in which case, we shouldn't expand by
    // the total line cross size. Otherwise, we would continue to expand the row
    // past the block-size of its items.
    if (line_cross_size_for_stretch && !is_column_ && item_break_token) {
      LayoutUnit updated_cross_size_for_stretch =
          line_cross_size_for_stretch.value();
      updated_cross_size_for_stretch -=
          offset_in_stitched_container -
          (original_offset.block_offset + line_output.item_offset_adjustment) -
          item_break_token->ConsumedBlockSize();

      line_cross_size_for_stretch = updated_cross_size_for_stretch;
    }

    const bool min_block_size_should_encompass_intrinsic_size =
        MinBlockSizeShouldEncompassIntrinsicSize(*flex_item);
    ConstraintSpace child_space = BuildSpaceForLayout(
        flex_item->ng_input_node, flex_item->main_axis_final_size,
        flex_item->is_initial_block_size_indefinite,
        /* override_inline_size */ std::nullopt, line_cross_size_for_stretch,
        offset.block_offset, min_block_size_should_encompass_intrinsic_size);
    const LayoutResult* layout_result = flex_item->ng_input_node.Layout(
        child_space, item_break_token, early_break_in_child);

    BreakStatus break_status = BreakStatus::kContinue;
    FlexColumnBreakInfo* current_column_break_info = nullptr;
    if (!early_break_ && GetConstraintSpace().HasBlockFragmentation()) {
      bool has_container_separation = false;
      if (!is_column_) {
        has_container_separation =
            offset.block_offset > row_block_offset &&
            (!item_break_token || (broke_before_row && flex_item_idx == 0 &&
                                   item_break_token->IsBreakBefore()));
        // Don't attempt to break before a row if the fist item is resuming
        // layout. In which case, the row should be resuming layout, as well.
        if (flex_item_idx == 0 &&
            (!item_break_token ||
             (item_break_token->IsBreakBefore() && broke_before_row))) {
          // Rows have no layout result, so if the row breaks before, we
          // will break before the first item in the row instead.
          bool row_container_separation = has_processed_first_line_;
          bool is_first_for_row = !item_break_token || broke_before_row;
          BreakStatus row_break_status = BreakBeforeRowIfNeeded(
              line_output, row_block_offset,
              (*row_break_between_outputs)[flex_line_idx], flex_line_idx,
              flex_item->ng_input_node, row_container_separation,
              is_first_for_row);
          if (row_break_status == BreakStatus::kBrokeBefore) {
            ConsumeRemainingFragmentainerSpace(offset_in_stitched_container,
                                               &line_output);
            if (broke_before_row) {
              *break_before_row =
                  FlexBreakTokenData::kPastStartOfBreakBeforeRow;
            } else {
              *break_before_row = FlexBreakTokenData::kAtStartOfBreakBeforeRow;
            }
            DCHECK_EQ(status, LayoutResult::kSuccess);
            break;
          }
          *break_before_row = FlexBreakTokenData::kNotBreakBeforeRow;
          if (row_break_status == BreakStatus::kNeedsEarlierBreak) {
            status = LayoutResult::kNeedsEarlierBreak;
            break;
          }
          DCHECK_EQ(row_break_status, BreakStatus::kContinue);
        }
      } else {
        has_container_separation =
            !item_break_token &&
            ((last_line_idx_to_process_first_child_ != kNotFound &&
              last_line_idx_to_process_first_child_ >= flex_line_idx) ||
             offset.block_offset > LayoutUnit());

        // We may switch back and forth between columns, so we need to make sure
        // to use the break-after for the current column.
        if (flex_line_outputs->size() > 1) {
          current_column_break_info = &column_break_info[flex_line_idx];
          container_builder_.SetPreviousBreakAfter(
              current_column_break_info->break_after);
        }
      }
      break_status = BreakBeforeChildIfNeeded(
          flex_item->ng_input_node, *layout_result,
          FragmentainerOffsetForChildren() + offset.block_offset,
          has_container_separation, !is_column_, current_column_break_info);

      if (current_column_break_info) {
        current_column_break_info->break_after =
            container_builder_.PreviousBreakAfter();
      }
    }

    if (break_status == BreakStatus::kNeedsEarlierBreak) {
      if (current_column_break_info) {
        DCHECK(is_column_);
        DCHECK(current_column_break_info->early_break);
        if (!needs_earlier_break_in_column) {
          needs_earlier_break_in_column = true;
          container_builder_.SetEarlyBreak(
              current_column_break_info->early_break);
        }
        // Keep track of the early breaks for each column.
        AddColumnEarlyBreak(current_column_break_info->early_break,
                            flex_line_idx);
        if (!last_item_in_line)
          item_iterator.NextLine();
        continue;
      }
      status = LayoutResult::kNeedsEarlierBreak;
      break;
    }

    if (break_status == BreakStatus::kBrokeBefore) {
      ConsumeRemainingFragmentainerSpace(offset_in_stitched_container,
                                         &line_output,
                                         current_column_break_info);
      // For column flex containers, continue to the next column. For rows,
      // continue until we've processed all items in the current row.
      has_inflow_child_break_inside_line[flex_line_idx] = true;
      if (is_column_) {
        if (!last_item_in_line)
          item_iterator.NextLine();
      } else if (last_item_in_line) {
        DCHECK_EQ(status, LayoutResult::kSuccess);
        break;
      }
      last_line_idx_to_process_first_child_ = flex_line_idx;
      continue;
    }

    const auto& physical_fragment =
        To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());

    LogicalBoxFragment fragment(GetConstraintSpace().GetWritingDirection(),
                                physical_fragment);

    bool is_at_block_end = !physical_fragment.GetBreakToken() ||
                           physical_fragment.GetBreakToken()->IsAtBlockEnd();
    LayoutUnit item_block_end = offset.block_offset + fragment.BlockSize();
    if (is_at_block_end) {
      // Only add the block-end margin if the item has reached the end of its
      // content. Then re-set it to avoid adding it more than once.
      item_block_end += flex_item->margin_block_end;
      flex_item->margin_block_end = LayoutUnit();
    } else {
      has_inflow_child_break_inside_line[flex_line_idx] = true;
    }

    // This item may have expanded due to fragmentation. Record how large the
    // shift was (if any). Only do this if the item has completed layout.
    if (is_column_) {
      LayoutUnit cloned_block_decorations;
      if (!is_at_block_end &&
          flex_item->ng_input_node.Style().BoxDecorationBreak() ==
              EBoxDecorationBreak::kClone) {
        cloned_block_decorations = fragment.BoxDecorations().BlockSum();
      }

      // Cloned box decorations grow the border-box size of the flex item. In
      // flex layout, the main-axis size of a flex item is fixed (in the
      // constraint space). Make sure that this fixed size remains correct, by
      // adding cloned box decorations from each fragment.
      flex_item->main_axis_final_size += cloned_block_decorations;

      flex_item->total_remaining_block_size -=
          fragment.BlockSize() - cloned_block_decorations;
      if (flex_item->total_remaining_block_size < LayoutUnit() &&
          !physical_fragment.GetBreakToken()) {
        LayoutUnit expansion = -flex_item->total_remaining_block_size;
        line_output.item_offset_adjustment += expansion;
      }
    } else if (!cross_size_adjustments_ &&
               !flex_item
                    ->has_descendant_that_depends_on_percentage_block_size) {
      // For rows, keep track of any expansion past the block-end of each
      // row so that we can re-run layout with the new row block-size.
      //
      // Include any cloned block-start box decorations. The line offset is in
      // the imaginary stitched container that we would have had had we not been
      // fragmented, and now we won't actual layout offsets for the current
      // fragment.
      LayoutUnit cloned_block_start_decoration =
          ClonedBlockStartDecoration(container_builder_);

      LayoutUnit line_block_end = line_output.LineCrossEnd() -
                                  offset_in_stitched_container +
                                  cloned_block_start_decoration;
      if (line_block_end <= fragmentainer_space &&
          line_block_end >= LayoutUnit() &&
          offset_in_stitched_container != LayoutUnit::Max()) {
        LayoutUnit item_expansion;
        if (is_at_block_end) {
          item_expansion = item_block_end - line_block_end;
        } else {
          // We can't use the size of the fragment, as we don't
          // know how large the subsequent fragments will be (and how much
          // they'll expand the row).
          //
          // Instead of using the size of the fragment, expand the row to the
          // rest of the fragmentainer, with an additional epsilon. This epsilon
          // will ensure that we continue layout for children in this row in
          // the next fragmentainer. Without it we'd drop those subsequent
          // fragments.
          item_expansion = (fragmentainer_space - line_block_end).AddEpsilon();
        }

        // If the item expanded past the row, adjust any subsequent row offsets
        // to reflect the expansion.
        if (item_expansion > LayoutUnit()) {
          // Maps don't allow keys of 0, so adjust the index by 1.
          if (row_cross_size_updates_.empty() ||
              !row_cross_size_updates_.Contains(flex_line_idx + 1)) {
            row_cross_size_updates_.insert(flex_line_idx + 1, item_expansion);
            AdjustOffsetForNextLine(flex_line_outputs, flex_line_idx,
                                    item_expansion);
          } else {
            auto it = row_cross_size_updates_.find(flex_line_idx + 1);
            CHECK_NE(it, row_cross_size_updates_.end(),
                     base::NotFatalUntil::M130);
            if (item_expansion > it->value) {
              AdjustOffsetForNextLine(flex_line_outputs, flex_line_idx,
                                      item_expansion - it->value);
              it->value = item_expansion;
            }
          }
        }
      }
    }

    if (current_column_break_info) {
      DCHECK(is_column_);
      current_column_break_info->column_intrinsic_block_size =
          std::max(item_block_end,
                   current_column_break_info->column_intrinsic_block_size);
    }

    intrinsic_block_size_ = std::max(item_block_end, intrinsic_block_size_);
    container_builder_.AddResult(*layout_result, offset);
    if (current_column_break_info) {
      current_column_break_info->break_after =
          container_builder_.PreviousBreakAfter();
    }
    baseline_accumulator.AccumulateItem(fragment, offset.block_offset,
                                        is_first_line, is_last_line);
    if (last_item_in_line) {
      if (!has_inflow_child_break_inside_line[flex_line_idx])
        line_output.has_seen_all_children = true;
      if (!has_processed_first_line_)
        has_processed_first_line_ = true;

      if (!physical_fragment.GetBreakToken() ||
          line_output.has_seen_all_children) {
        if (flex_line_idx < flex_line_outputs->size() - 1 && !is_column_ &&
            !item_iterator.HasMoreBreakTokens()) {
          // Add the offset adjustment of the current row to the next row so
          // that its items can also be adjusted by previous item expansion.
          // Only do this when the current row has completed layout and
          // the next row hasn't started layout yet.
          (*flex_line_outputs)[flex_line_idx + 1].item_offset_adjustment +=
              line_output.item_offset_adjustment;
        }
      }
    }
    last_line_idx_to_process_first_child_ = flex_line_idx;
  }

  if (needs_earlier_break_in_column ||
      status == LayoutResult::kNeedsEarlierBreak) {
    return LayoutResult::kNeedsEarlierBreak;
  }

  if (!row_cross_size_updates_.empty()) {
    DCHECK(!is_column_);
    return LayoutResult::kNeedsRelayoutWithRowCrossSizeChanges;
  }

  if (!container_builder_.HasInflowChildBreakInside() &&
      !item_iterator.NextItem(broke_before_row).flex_item) {
    container_builder_.SetHasSeenAllChildren();
  }

  if (auto first_baseline = baseline_accumulator.FirstBaseline())
    container_builder_.SetFirstBaseline(*first_baseline);
  if (auto last_baseline = baseline_accumulator.LastBaseline())
    container_builder_.SetLastBaseline(*last_baseline);

  // Update the |total_intrinsic_block_size_| in case things expanded.
  total_intrinsic_block_size_ =
      std::max(total_intrinsic_block_size_,
               intrinsic_block_size_ + previously_consumed_block_size);

  return status;
}

LayoutResult::EStatus FlexLayoutAlgorithm::PropagateFlexItemInfo(
    FlexItem* flex_item,
    wtf_size_t flex_line_idx,
    LogicalOffset offset,
    PhysicalSize fragment_size) {
  DCHECK(flex_item);
  LayoutResult::EStatus status = LayoutResult::kSuccess;

  if (layout_info_for_devtools_) [[unlikely]] {
    // If this is a "devtools layout", execution speed isn't critical but we
    // have to not adversely affect execution speed of a regular layout.
    PhysicalRect item_rect;
    item_rect.size = fragment_size;

    LogicalSize logical_flexbox_size =
        LogicalSize(container_builder_.InlineSize(), total_block_size_);
    PhysicalSize flexbox_size = ToPhysicalSize(
        logical_flexbox_size, GetConstraintSpace().GetWritingMode());
    item_rect.offset =
        offset.ConvertToPhysical(GetConstraintSpace().GetWritingDirection(),
                                 flexbox_size, item_rect.size);
    // devtools uses margin box.
    item_rect.Expand(flex_item->physical_margins_);
    DCHECK_GE(layout_info_for_devtools_->lines.size(), 1u);
    DevtoolsFlexInfo::Item item(
        item_rect, flex_item->MarginBoxAscent(
                       flex_item->Alignment() == ItemPosition::kLastBaseline,
                       Style().FlexWrap() == EFlexWrap::kWrapReverse));
    layout_info_for_devtools_->lines[flex_line_idx].items.push_back(item);
  }

  // Detect if the flex-item had its scrollbar state change. If so we need
  // to relayout as the input to the flex algorithm is incorrect.
  if (!ignore_child_scrollbar_changes_) {
    if (flex_item->scrollbars_ !=
        ComputeScrollbarsForNonAnonymous(flex_item->ng_input_node_))
      status = LayoutResult::kNeedsRelayoutWithNoChildScrollbarChanges;

    // The flex-item scrollbars may not have changed, but an descendant's
    // scrollbars might have causing the min/max sizes to be incorrect.
    if (flex_item->depends_on_min_max_sizes_ &&
        flex_item->ng_input_node_.GetLayoutBox()->IntrinsicLogicalWidthsDirty())
      status = LayoutResult::kNeedsRelayoutWithNoChildScrollbarChanges;
  } else {
    DCHECK_EQ(flex_item->scrollbars_,
              ComputeScrollbarsForNonAnonymous(flex_item->ng_input_node_));
  }
  return status;
}

MinMaxSizesResult
FlexLayoutAlgorithm::ComputeMinMaxSizeOfMultilineColumnContainer() {
  UseCounter::Count(Node().GetDocument(),
                    WebFeature::kFlexNewColumnWrapIntrinsicSize);
  MinMaxSizes min_max_sizes;
  // The algorithm for determining the max-content width of a column-wrap
  // container is simply: Run layout on the container but give the items an
  // overridden available size, equal to the largest max-content width of any
  // item, when they are laid out. The container's max-content width is then
  // the farthest outer inline-end point of all the items.
  HeapVector<NGFlexLine> flex_line_outputs;
  PlaceFlexItems(&flex_line_outputs, /* oof_children */ nullptr,
                 /* is_computing_multiline_column_intrinsic_size */ true);
  min_max_sizes.min_size = largest_min_content_contribution_;
  if (!flex_line_outputs.empty()) {
    for (const auto& line : flex_line_outputs) {
      min_max_sizes.max_size += line.line_cross_size;
    }
    min_max_sizes.max_size +=
        (flex_line_outputs.size() - 1) * algorithm_.gap_between_lines_;
  }

  DCHECK_GE(min_max_sizes.min_size, 0);
  DCHECK_LE(min_max_sizes.min_size, min_max_sizes.max_size);

  min_max_sizes += BorderScrollbarPadding().InlineSum();

  // This always depends on block constraints because if block constraints
  // change, this flexbox could get a different number of columns.
  return {min_max_sizes, /* depends_on_block_constraints */ true};
}

MinMaxSizesResult FlexLayoutAlgorithm::ComputeMinMaxSizeOfRowContainerV3() {
  MinMaxSizes container_sizes;
  bool depends_on_block_constraints = false;

  // The intrinsic sizing algorithm uses lots of geometry and values from each
  // item (e.g. flex base size, used minimum and maximum sizes including
  // automatic minimum sizing), so re-use |ConstructAndAppendFlexItems| from the
  // layout algorithm, which calculates all that.
  // TODO(dgrogan): As an optimization, We can drop the call to
  // ComputeMinMaxSizes in |ConstructAndAppendFlexItems| during this phase if
  // the flex basis is not definite.
  ConstructAndAppendFlexItems(Phase::kRowIntrinsicSize);

  LayoutUnit largest_outer_min_content_contribution;
  for (const FlexItem& item : algorithm_.all_items_) {
    const BlockNode& child = item.ng_input_node_;

    const ConstraintSpace space = BuildSpaceForIntrinsicInlineSize(child);
    MinMaxSizesResult min_max_content_contributions =
        ComputeMinAndMaxContentContribution(Style(), child, space);
    depends_on_block_constraints |=
        min_max_content_contributions.depends_on_block_constraints;

    MinMaxSizes item_final_contribution;
    const ComputedStyle& child_style = *item.style_;
    const LayoutUnit flex_base_size_border_box =
        item.flex_base_content_size_ + item.main_axis_border_padding_;
    const LayoutUnit hypothetical_main_size_border_box =
        item.hypothetical_main_content_size_ + item.main_axis_border_padding_;

    if (algorithm_.IsMultiline()) {
      const LayoutUnit main_axis_margins =
          is_horizontal_flow_ ? item.physical_margins_.HorizontalSum()
                              : item.physical_margins_.VerticalSum();
      largest_outer_min_content_contribution = std::max(
          largest_outer_min_content_contribution,
          min_max_content_contributions.sizes.min_size + main_axis_margins);
    } else {
      const LayoutUnit min_contribution =
          min_max_content_contributions.sizes.min_size;
      const bool cant_move = (min_contribution > flex_base_size_border_box &&
                              child_style.ResolvedFlexGrow(Style()) == 0.f) ||
                             (min_contribution < flex_base_size_border_box &&
                              child_style.ResolvedFlexShrink(Style()) == 0.f);
      if (cant_move && !item.is_used_flex_basis_indefinite_) {
        item_final_contribution.min_size = hypothetical_main_size_border_box;
      } else {
        item_final_contribution.min_size = min_contribution;
      }
    }

    const LayoutUnit max_contribution =
        min_max_content_contributions.sizes.max_size;
    const bool cant_move = (max_contribution > flex_base_size_border_box &&
                            child_style.ResolvedFlexGrow(Style()) == 0.f) ||
                           (max_contribution < flex_base_size_border_box &&
                            child_style.ResolvedFlexShrink(Style()) == 0.f);
    if (cant_move && !item.is_used_flex_basis_indefinite_) {
      item_final_contribution.max_size = hypothetical_main_size_border_box;
    } else {
      item_final_contribution.max_size = max_contribution;
    }

    container_sizes += item_final_contribution;

    const LayoutUnit main_axis_margins =
        is_horizontal_flow_ ? item.physical_margins_.HorizontalSum()
                            : item.physical_margins_.VerticalSum();
    container_sizes += main_axis_margins;
  }

  if (algorithm_.NumItems() > 0) {
    const LayoutUnit gap_inline_size =
        (algorithm_.NumItems() - 1) * algorithm_.gap_between_items_;
    if (algorithm_.IsMultiline()) {
      container_sizes.min_size = largest_outer_min_content_contribution;
      container_sizes.max_size += gap_inline_size;
    } else {
      DCHECK_EQ(largest_outer_min_content_contribution, LayoutUnit())
          << "largest_outer_min_content_contribution is not filled in for "
             "singleline containers.";
      container_sizes += gap_inline_size;
    }
  }

  // Handle potential weirdness caused by items' negative margins.
#if DCHECK_IS_ON()
  if (container_sizes.max_size < container_sizes.min_size) {
    DCHECK(algorithm_.IsMultiline())
        << container_sizes
        << " multiline row containers might have max < min due to negative "
           "margins, but singleline containers cannot.";
  }
#endif
  container_sizes.max_size =
      std::max(container_sizes.max_size, container_sizes.min_size);
  container_sizes.Encompass(LayoutUnit());

  container_sizes += BorderScrollbarPadding().InlineSum();
  return MinMaxSizesResult(container_sizes, depends_on_block_constraints);
}

MinMaxSizesResult FlexLayoutAlgorithm::ComputeMinMaxSizes(
    const MinMaxSizesFloatInput&) {
  if (auto result = CalculateMinMaxSizesIgnoringChildren(
          Node(), BorderScrollbarPadding()))
    return *result;

  if (is_column_ && algorithm_.IsMultiline()) {
    return ComputeMinMaxSizeOfMultilineColumnContainer();
  }

  if (RuntimeEnabledFeatures::LayoutFlexNewRowAlgorithmV3Enabled() &&
      !is_column_) {
    return ComputeMinMaxSizeOfRowContainerV3();
  }

  MinMaxSizes sizes;
  bool depends_on_block_constraints = false;

  int number_of_items = 0;
  FlexChildIterator iterator(Node());
  for (BlockNode child = iterator.NextChild(); child;
       child = iterator.NextChild()) {
    if (child.IsOutOfFlowPositioned())
      continue;
    number_of_items++;

    const ConstraintSpace space = BuildSpaceForIntrinsicInlineSize(child);
    MinMaxSizesResult child_result =
        ComputeMinAndMaxContentContribution(Style(), child, space);
    BoxStrut child_margins =
        ComputeMarginsFor(space, child.Style(), GetConstraintSpace());
    child_result.sizes += child_margins.InlineSum();

    depends_on_block_constraints |= child_result.depends_on_block_constraints;
    if (is_column_) {
      sizes.min_size = std::max(sizes.min_size, child_result.sizes.min_size);
      sizes.max_size = std::max(sizes.max_size, child_result.sizes.max_size);
    } else {
      sizes.max_size += child_result.sizes.max_size;
      if (algorithm_.IsMultiline()) {
        sizes.min_size = std::max(sizes.min_size, child_result.sizes.min_size);
      } else {
        sizes.min_size += child_result.
"""


```