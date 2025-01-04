Response:
The user wants a summary of the functionality of the provided C++ code snippet from `column_layout_algorithm.cc`. The snippet focuses on laying out columns within a multicol container.

Here's a breakdown of how to arrive at the summary:

1. **Identify the core loop:** The code has a `do...while(true)` loop responsible for laying out columns. This loop continues until a specific condition is met (e.g., balancing is done, a spanner is encountered).

2. **Track key variables:**  Observe variables like `new_columns`, `column_inline_offset`, `row_offset`, `actual_column_count`, `column_break_token`, and `balance_columns`. These variables directly relate to the process of creating and positioning columns.

3. **Understand the conditions for breaking the loop:** The `break` statements within the loop indicate when the column layout for the current row is considered complete. These conditions involve checking for balanced columns, reaching the `used_column_count_`, or encountering a column spanner.

4. **Recognize interactions with other layout components:** Notice calls to `result->MinimalSpaceShortage()`, `FragmentedOofData::HasOutOfFlowPositionedFragmentainerDescendants()`, `OutOfFlowLayoutPart`, and `LayoutSpanner`. These highlight the interaction with out-of-flow elements and column spanners.

5. **Focus on the balancing logic:**  The code clearly deals with `balance_columns`. Observe how it adjusts `column_size.block_size` and retries layout if the initial column height isn't satisfactory.

6. **Identify handling of fragmentation:** The code checks for `GetConstraintSpace().HasBlockFragmentation()` and uses `FragmentainerSpaceLeftForChildren()`, indicating its awareness of being inside a larger fragmentation context.

7. **Note the "stretching" mechanism:** The code attempts to increase `column_size.block_size` if the columns are not tall enough during balancing.

8. **Consider edge cases and optimizations:**  The code deals with scenarios like empty fragmentainers and the interaction between forced breaks and balancing.

9. **Synthesize the information:** Combine the observations into a concise description of the code's purpose. Highlight the main actions performed within the loop, the conditions that influence the layout process, and the interactions with other parts of the layout engine.
这段代码是 `ColumnLayoutAlgorithm` 类中 `LayoutRow` 方法的一部分，其主要功能是**负责在多列布局中布局一行的列**。它会循环创建和放置列片段，直到满足特定的停止条件。

更具体地说，这段代码做了以下几件事：

1. **循环创建列片段:** 它在一个 `do...while` 循环中不断尝试创建新的列片段 (`LayoutResult`).
2. **处理列的块大小:**  它会考虑外层分段容器的可用空间，以及是否需要进行列平衡，来确定列的块大小 (`column_size.block_size`). 特别地，如果外层有剩余空间，它可能会推迟创建软换行符，以便在下一个外层分段容器中获得更多空间。
3. **处理超出流定位的后代:**  它会检查是否存在超出流定位的后代，并根据情况调整列的块大小，以避免出现问题。
4. **处理列平衡:** 如果启用了列平衡 (`balance_columns`)，它会在第一遍布局后检查列的高度是否令人满意，如果不满意，则会尝试拉伸列的高度并重新布局。
5. **处理强制换行:** 它会记录强制换行的次数 (`forced_break_count`)，这会影响列平衡的决策。
6. **处理列跨越 (spanner):** 它会检测当前列是否是列跨越元素的父元素 (`result->GetColumnSpannerPath()`)，如果是，则会停止当前行的列布局。
7. **处理分段:**  它会考虑自身是否处于外层分段上下文 (`may_resume_in_next_outer_fragmentainer`, `may_have_more_space_in_next_outer_fragmentainer`)，并根据外层分段容器的剩余空间来决定是否继续创建列。
8. **与 `OutOfFlowLayoutPart` 交互:**  如果存在超出流定位的后代，它会调用 `OutOfFlowLayoutPart` 来确定这些后代是否会影响列平衡。
9. **更新最小空间短缺:** 它会跟踪所需的最小额外空间 (`minimal_space_shortage`)。
10. **处理嵌套分段:** 如果处于嵌套的块分段中，并且列因为内容过高而溢出，它可能会尝试重新布局，强制列的高度来包含溢出内容。
11. **在列平衡时传播空间短缺:** 如果在嵌套的列平衡中遇到空间短缺，它会将这个短缺传播到外层的多列容器。
12. **在完成布局后处理:**  在完成一行的列布局后，它会将列片段添加到片段构建器 (`container_builder_`)，并处理列表标记的定位和基线的传播。
13. **处理空片段:** 它会检查是否创建了一个空的片段容器，并进行相应的处理。

**与 Javascript, HTML, CSS 的关系举例说明:**

* **CSS: `column-count`, `column-width`, `column-gap`, `break-inside`, `break-before`, `break-after`, `span`:**  这段代码的逻辑直接对应于这些 CSS 属性的实现。例如：
    * `used_column_count_` 对应于 `column-count` 的值。
    * 代码中对列块大小的计算和约束，与 `column-width` 和容器的可用空间有关。
    * 对 `result->HasForcedBreak()` 的判断以及对 `column_break_token` 的处理，与 `break-before` 和 `break-after: always` 等属性有关。
    * 对 `result->GetColumnSpannerPath()` 的判断，对应于 `span: all` 属性。
* **HTML: 元素的结构和内容:** 这段代码处理的是 HTML 元素在多列布局下的渲染。元素的类型、内容多少会影响列的创建和大小。例如，一个包含大量文本的 `<div>` 元素可能会被分割到多个列中。
* **Javascript: 动态修改样式:** Javascript 可以动态地修改影响多列布局的 CSS 属性，例如改变 `column-count` 的值。当这种情况发生时，blink 引擎会重新运行布局算法，包括这段代码，以反映新的样式。

**逻辑推理的假设输入与输出:**

**假设输入:**

* `next_column_token`: `nullptr` (表示这是该行的第一个列)
* `minimum_column_block_size`: `std::nullopt` (没有强制的最小列高度)
* `margin_strut`: 一个空的 `MarginStrut` 对象
* `used_column_count_`: 3 (期望有 3 列)
* 容器内包含一些文本内容，可以被分割到多个列中。

**可能输出:**

* `result`: 指向最后一个创建的列片段的 `LayoutResult` 的指针。
* `new_columns`: 一个包含多个 `NewColumn` 对象的 `std::vector`，每个对象代表一个列片段及其偏移量。数量可能小于 `used_column_count_`，如果内容不足以填充所有列，或者遇到了列跨越元素。
* `intrinsic_block_size_`: 更新后的多列容器的内部块大小。
* `margin_strut`: 可能会被更新。

**涉及用户或者编程常见的使用错误举例说明:**

1. **CSS 设置了不合理的列宽度和列数:** 用户可能设置了 `column-width` 和 `column-count`，导致在容器宽度不足的情况下无法正确布局。例如，容器宽度为 300px，设置 `column-count: 3` 和 `column-width: 150px`，会导致溢出。
2. **使用了会导致无限循环的 CSS 属性组合:**  虽然这段代码本身不太可能直接导致无限循环，但在更高级别的布局逻辑中，错误的 CSS 属性组合可能会导致布局震荡。例如，一个元素的尺寸依赖于其子元素的尺寸，而子元素的尺寸又依赖于该元素的尺寸。
3. **动态添加内容导致频繁的重排:**  在 Javascript 中频繁地向多列容器中添加内容，会导致浏览器频繁地重新运行布局算法，包括这段代码，从而影响性能。
4. **错误理解 `break-inside: avoid` 的作用范围:** 用户可能期望 `break-inside: avoid` 能阻止元素在列之间分割，但如果元素本身就比列的宽度大，则该属性无效。

**归纳一下它的功能:**

这段代码的核心功能是**在多列布局中，根据可用的空间、CSS 属性和内容，迭代地创建和定位一行的列片段，并处理列平衡、超出流定位元素以及分段等复杂情况。**  它确保了多列布局能够按照 CSS 规范正确地渲染内容。

Prompt: 
```
这是目录为blink/renderer/core/layout/column_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
       // trouble for out-of-flow positioned descendants that extend past the
        // end of in-flow content, which benefit from "full" column block-size.
        intrinsic_block_size_contribution =
            std::min(intrinsic_block_size_contribution,
                     result->BlockSizeForFragmentation());
        shrink_to_fit_column_block_size = false;
      }

      if (!has_oof_fragmentainer_descendants && balance_columns &&
          FragmentedOofData::HasOutOfFlowPositionedFragmentainerDescendants(
              column)) {
        has_oof_fragmentainer_descendants = true;
      }

      // Add the new column fragment to the list, but don't commit anything to
      // the fragment builder until we know whether these are the final columns.
      LogicalOffset logical_offset(column_inline_offset, row_offset);
      new_columns.emplace_back(result, logical_offset);

      std::optional<LayoutUnit> space_shortage = result->MinimalSpaceShortage();
      UpdateMinimalSpaceShortage(space_shortage, &minimal_space_shortage);
      actual_column_count++;

      if (result->GetColumnSpannerPath()) {
        is_empty_spanner_parent = result->IsEmptySpannerParent();
        break;
      }

      has_violating_break |= result->GetBreakAppeal() != kBreakAppealPerfect;
      column_inline_offset += column_inline_progression_;

      if (result->HasForcedBreak())
        forced_break_count++;

      column_break_token = column.GetBreakToken();

      // If we're participating in an outer fragmentation context, we'll only
      // allow as many columns as the used value of column-count, so that we
      // don't overflow in the inline direction. There's one important
      // exception: If we have determined that this is going to be the last
      // fragment for this multicol container in the outer fragmentation
      // context, we'll just allow as many columns as needed (and let them
      // overflow in the inline direction, if necessary). We're not going to
      // progress into a next outer fragmentainer if the (remaining part of the)
      // multicol container fits block-wise in the current outer fragmentainer.
      if (may_resume_in_next_outer_fragmentainer && column_break_token &&
          actual_column_count >= used_column_count_)
        break;

      if (may_have_more_space_in_next_outer_fragmentainer) {
        // If the outer fragmentainer already has content progress (before this
        // row), we are in a situation where there may be more space for us
        // (block-size) in the next outer fragmentainer. This means that it may
        // be possible to avoid suboptimal breaks if we push content to a column
        // row in the next outer fragmentainer. Therefore, avoid breaks with
        // lower appeal than what we've seen so far. Anything that would cause
        // "too severe" breaking violations will be pushed to the next outer
        // fragmentainer.
        min_break_appeal =
            std::min(min_break_appeal.value_or(kBreakAppealPerfect),
                     result->GetBreakAppeal());

        LayoutUnit block_end_overflow =
            LogicalBoxFragment(GetConstraintSpace().GetWritingDirection(),
                               column)
                .BlockEndScrollableOverflow();
        if (row_offset + block_end_overflow >
            FragmentainerSpaceLeftForChildren()) {
          if (GetConstraintSpace().IsInsideBalancedColumns() &&
              !container_builder_.IsInitialColumnBalancingPass()) {
            container_builder_.PropagateSpaceShortage(minimal_space_shortage);
          }
          if (!minimum_column_block_size &&
              block_end_overflow > column_size.block_size) {
            // We're inside nested block fragmentation, and the column was
            // overflowed by content taller than what there is room for in the
            // outer fragmentainer. Try row layout again, but this time force
            // the columns to be this tall as well, to encompass overflow. It's
            // generally undesirable to overflow the outer fragmentainer, but
            // it's up to the parent algorithms to decide.
            DCHECK_GT(block_end_overflow, LayoutUnit());
            minimum_column_block_size = block_end_overflow;
            // TODO(mstensho): Consider refactoring this, rather than calling
            // ourselves recursively.
            return LayoutRow(next_column_token, minimum_column_block_size,
                             margin_strut);
          }
        }
      }
    } while (column_break_token);

    if (!balance_columns) {
      if (result->GetColumnSpannerPath()) {
        // We always have to balance columns preceding a spanner, so if we
        // didn't do that initially, switch over to column balancing mode now,
        // and lay out again.
        balance_columns = true;
        new_columns.clear();
        column_size.block_size = ResolveColumnAutoBlockSize(
            column_size, row_offset, available_outer_space, next_column_token,
            balance_columns);
        continue;
      }

      // Balancing not enabled. We're done.
      break;
    }

    // Any OOFs contained within this multicol get laid out once all columns
    // complete layout. However, OOFs should affect column balancing. Pass the
    // current set of columns into OutOfFlowLayoutPart to determine if OOF
    // layout will affect column balancing in any way (without actually adding
    // the OOF results to the builder - this will be handled at a later point).
    if (has_oof_fragmentainer_descendants) {
      // If, for example, the columns get split by a column spanner, the offset
      // of an OOF's containing block will be relative to the first
      // fragmentainer in the first row. However, we are only concerned about
      // the current row of columns, so we should adjust the containing block
      // offsets to be relative to the first column in the current row.
      LayoutUnit containing_block_adjustment = -TotalColumnBlockSize();

      OutOfFlowLayoutPart::ColumnBalancingInfo column_balancing_info;
      FragmentBuilder::ChildrenVector columns;
      for (wtf_size_t i = 0; i < new_columns.size(); i++) {
        auto& new_column = new_columns[i];
        columns.push_back(
            LogicalFragmentLink{&new_column.Fragment(), new_column.offset});

        // Because the current set of columns haven't been added to the builder
        // yet, any OOF descendants won't have been propagated up yet. Instead,
        // propagate any OOF descendants up to |column_balancing_info| so that
        // they can be passed into OutOfFlowLayoutPart (without affecting the
        // builder).
        container_builder_.PropagateOOFFragmentainerDescendants(
            new_column.Fragment(), new_column.offset,
            /* relative_offset */ LogicalOffset(), containing_block_adjustment,
            /* containing_block */ nullptr,
            /* fixedpos_containing_block */ nullptr,
            &column_balancing_info.out_of_flow_fragmentainer_descendants);
      }
      DCHECK(column_balancing_info.HasOutOfFlowFragmentainerDescendants());

      OutOfFlowLayoutPart oof_part(&container_builder_);
      oof_part.SetColumnBalancingInfo(&column_balancing_info, &columns);
      oof_part.HandleFragmentation();
      actual_column_count += column_balancing_info.num_new_columns;
      if (column_balancing_info.minimal_space_shortage > LayoutUnit()) {
        UpdateMinimalSpaceShortage(column_balancing_info.minimal_space_shortage,
                                   &minimal_space_shortage);
      }
      if (!has_violating_break)
        has_violating_break = column_balancing_info.has_violating_break;
    }

    // We're balancing columns. Check if the column block-size that we laid out
    // with was satisfactory. If not, stretch and retry, if possible.
    //
    // If we didn't break at any undesirable location and actual column count
    // wasn't larger than what we have room for, we're done IF we're also out of
    // content (no break token; in nested multicol situations there are cases
    // where we only allow as many columns as we have room for, as additional
    // columns normally need to continue in the next outer fragmentainer). If we
    // have made the columns tall enough to bump into a spanner, it also means
    // we need to stop to lay out the spanner(s), and resume column layout
    // afterwards.
    if (!has_violating_break && actual_column_count <= used_column_count_ &&
        (!column_break_token || result->GetColumnSpannerPath())) {
      break;
    }

    // Attempt to stretch the columns.
    LayoutUnit new_column_block_size;
    if (used_column_count_ <= forced_break_count + 1) {
      // If we have no soft break opportunities (because forced breaks cause too
      // many breaks already), there's no stretch amount that could prevent the
      // columns from overflowing. Give up, unless we're nested inside another
      // fragmentation context, in which case we'll stretch the columns to take
      // up all the space inside the multicol container fragment. A box is
      // required to use all the remaining fragmentainer space when something
      // inside breaks; see https://www.w3.org/TR/css-break-3/#box-splitting
      if (!is_constrained_by_outer_fragmentation_context_)
        break;
      // We'll get properly constrained right below. Rely on that, rather than
      // calculating the exact amount here (we could check the available outer
      // fragmentainer size and subtract the row offset and stuff, but that's
      // duplicated logic). We'll use as much as we're allowed to.
      new_column_block_size = LayoutUnit::Max();
    } else {
      new_column_block_size = column_size.block_size;
      if (minimal_space_shortage > LayoutUnit())
        new_column_block_size += minimal_space_shortage;
    }
    new_column_block_size = ConstrainColumnBlockSize(
        new_column_block_size, row_offset, available_outer_space);

    // Give up if we cannot get taller columns. The multicol container may have
    // a specified block-size preventing taller columns, for instance.
    DCHECK_GE(new_column_block_size, column_size.block_size);
    if (new_column_block_size <= column_size.block_size) {
      if (GetConstraintSpace().IsInsideBalancedColumns()) {
        // If we're doing nested column balancing, propagate any space shortage
        // to the outer multicol container, so that the outer multicol container
        // can attempt to stretch, so that this inner one may fit as well.
        if (!container_builder_.IsInitialColumnBalancingPass())
          container_builder_.PropagateSpaceShortage(minimal_space_shortage);
      }
      break;
    }

    // Remove column fragments and re-attempt layout with taller columns.
    new_columns.clear();
    column_size.block_size = new_column_block_size;
  } while (true);

  if (GetConstraintSpace().HasBlockFragmentation() &&
      row_offset > LayoutUnit()) {
    // If we have container separation, breaking before this row is fine.
    LayoutUnit fragmentainer_block_offset =
        FragmentainerOffsetForChildren() + row_offset;
    // TODO(layout-dev): Consider adjusting break appeal based on the preceding
    // column spanner (if any), e.g. if it has break-after:avoid, so that we can
    // support early-breaks.
    if (!MovePastBreakpoint(*result, fragmentainer_block_offset,
                            kBreakAppealPerfect)) {
      // This row didn't fit nicely in the outer fragmentation context. Breaking
      // before is better.
      if (!next_column_token) {
        // We haven't made any progress in the fragmentation context at all, but
        // when there's preceding initial multicol border/padding, we may want
        // to insert a last-resort break here.
        container_builder_.AddBreakBeforeChild(Node(), kBreakAppealLastResort,
                                               /* is_forced_break */ false);
      }
      return nullptr;
    }
  }

  // If we just have one empty fragmentainer, we need to keep the trailing
  // margin from any previous column spanner, and also make sure that we don't
  // incorrectly consider this to be a class A breakpoint. A fragmentainer may
  // end up empty if there's no in-flow content at all inside the multicol
  // container, if the multicol container starts with a spanner, or if the
  // only in-flow content is empty as a result of a nested OOF positioned
  // element whose containing block lives outside this multicol.
  //
  // If the size of the fragment is non-zero, we shouldn't consider it to be
  // empty (even if there's nothing inside). This happens with contenteditable,
  // which in some cases makes room for a line box that isn't there.
  bool is_empty =
      !column_size.block_size && new_columns.size() == 1 &&
      (new_columns[0].Fragment().Children().empty() || is_empty_spanner_parent);

  if (!is_empty) {
    has_processed_first_child_ = true;
    container_builder_.SetPreviousBreakAfter(EBreakBetween::kAuto);

    const auto& first_column =
        To<PhysicalBoxFragment>(new_columns[0].Fragment());

    // Only the first column in a row may attempt to place any unpositioned
    // list-item. This matches the behavior in Gecko, and also to some extent
    // with how baselines are propagated inside a multicol container.
    AttemptToPositionListMarker(first_column, row_offset);

    // We're adding a row with content. We can update the intrinsic block-size
    // (which will also be used as layout position for subsequent content), and
    // reset the margin strut (it has already been incorporated into the
    // offset).
    intrinsic_block_size_ = row_offset + intrinsic_block_size_contribution;
    *margin_strut = MarginStrut();
  }

  Element* element = To<Element>(Node().EnclosingDOMNode());
  StyleEngine::AttachScrollMarkersScope scope(
      Node().GetDocument().GetStyleEngine());

  wtf_size_t num_columns = 0u;
  // Commit all column fragments to the fragment builder.
  for (auto result_with_offset : new_columns) {
    const PhysicalBoxFragment& column = result_with_offset.Fragment();
    container_builder_.AddChild(column, result_with_offset.offset);
    PropagateBaselineFromChild(column, result_with_offset.offset.block_offset);

    // Create a ::column pseudo element, and, if needed, also a
    // ::column::scroll-marker pseudo element child of ::column.
    LogicalRect column_logical_rect(result_with_offset.offset, column_size);
    const WritingModeConverter converter(
        GetConstraintSpace().GetWritingDirection(),
        LogicalSize(ChildAvailableSize().inline_size, column_block_size_));
    ColumnPseudoElement* column_pseudo =
        element->CreateColumnPseudoElementIfNeeded(
            num_columns, converter.ToPhysical(column_logical_rect));
    num_columns += column_pseudo != nullptr;
    if (column_pseudo &&
        column_pseudo->GetComputedStyle()->GetScrollSnapAlign() !=
            cc::ScrollSnapAlign()) {
      container_builder_.AddSnapAreaForColumn(column_pseudo);
    }
  }

  if (min_break_appeal)
    container_builder_.ClampBreakAppeal(*min_break_appeal);

  return result;
}

BreakStatus ColumnLayoutAlgorithm::LayoutSpanner(
    BlockNode spanner_node,
    const BlockBreakToken* break_token,
    MarginStrut* margin_strut) {
  spanner_path_ = nullptr;
  const ComputedStyle& spanner_style = spanner_node.Style();
  BoxStrut margins =
      ComputeMarginsFor(spanner_style, ChildAvailableSize().inline_size,
                        GetConstraintSpace().GetWritingDirection());
  AdjustMarginsForFragmentation(break_token, &margins);

  // Collapse the block-start margin of this spanner with the block-end margin
  // of an immediately preceding spanner, if any.
  margin_strut->Append(margins.block_start, /* is_quirky */ false);

  LayoutUnit block_offset = intrinsic_block_size_ + margin_strut->Sum();
  auto spanner_space =
      CreateConstraintSpaceForSpanner(spanner_node, block_offset);

  const EarlyBreak* early_break_in_child = nullptr;
  if (early_break_) [[unlikely]] {
    early_break_in_child = EnterEarlyBreakInChild(spanner_node, *early_break_);
  }

  auto* result =
      spanner_node.Layout(spanner_space, break_token, early_break_in_child);

  if (GetConstraintSpace().HasBlockFragmentation() && !early_break_) {
    // We're nested inside another fragmentation context. Examine this break
    // point, and determine whether we should break.

    LayoutUnit fragmentainer_block_offset =
        FragmentainerOffsetForChildren() + block_offset;

    BreakStatus break_status = BreakBeforeChildIfNeeded(
        spanner_node, *result, fragmentainer_block_offset,
        has_processed_first_child_);

    if (break_status != BreakStatus::kContinue) {
      // We need to break, either before the spanner, or even earlier.
      return break_status;
    }
  }

  const auto& spanner_fragment =
      To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  LogicalFragment logical_fragment(GetConstraintSpace().GetWritingDirection(),
                                   spanner_fragment);

  ResolveInlineAutoMargins(spanner_style, Style(),
                           ChildAvailableSize().inline_size,
                           logical_fragment.InlineSize(), &margins);

  LogicalOffset offset(
      BorderScrollbarPadding().inline_start + margins.inline_start,
      block_offset);
  container_builder_.AddResult(*result, offset);

  // According to the spec, the first spanner that has a baseline contributes
  // with its baseline to the multicol container. This is in contrast to column
  // content, where only the first column may contribute with a baseline.
  PropagateBaselineFromChild(spanner_fragment, offset.block_offset);

  AttemptToPositionListMarker(spanner_fragment, block_offset);

  *margin_strut = MarginStrut();
  margin_strut->Append(margins.block_end, /* is_quirky */ false);

  intrinsic_block_size_ = offset.block_offset + logical_fragment.BlockSize();
  has_processed_first_child_ = true;

  return BreakStatus::kContinue;
}

void ColumnLayoutAlgorithm::AttemptToPositionListMarker(
    const PhysicalBoxFragment& child_fragment,
    LayoutUnit block_offset) {
  const auto marker = container_builder_.GetUnpositionedListMarker();
  if (!marker)
    return;
  DCHECK(Node().IsListItem());

  FontBaseline baseline_type = Style().GetFontBaseline();
  auto baseline = marker.ContentAlignmentBaseline(
      GetConstraintSpace(), baseline_type, child_fragment);
  if (!baseline)
    return;

  const LayoutResult* layout_result = marker.Layout(
      GetConstraintSpace(), container_builder_.Style(), baseline_type);
  DCHECK(layout_result);

  // TODO(layout-dev): AddToBox() may increase the specified block-offset, which
  // is bad, since it means that we may need to refragment. For now we'll just
  // ignore the adjustment (which is also bad, of course).
  marker.AddToBox(GetConstraintSpace(), baseline_type, child_fragment,
                  BorderScrollbarPadding(), *layout_result, *baseline,
                  &block_offset, &container_builder_);

  container_builder_.ClearUnpositionedListMarker();
}

void ColumnLayoutAlgorithm::PositionAnyUnclaimedListMarker() {
  if (!Node().IsListItem())
    return;
  const auto marker = container_builder_.GetUnpositionedListMarker();
  if (!marker)
    return;

  // Lay out the list marker.
  FontBaseline baseline_type = Style().GetFontBaseline();
  const LayoutResult* layout_result =
      marker.Layout(GetConstraintSpace(), Style(), baseline_type);
  DCHECK(layout_result);
  // Position the list marker without aligning with line boxes.
  marker.AddToBoxWithoutLineBoxes(GetConstraintSpace(), baseline_type,
                                  *layout_result, &container_builder_,
                                  &intrinsic_block_size_);
  container_builder_.ClearUnpositionedListMarker();
}

void ColumnLayoutAlgorithm::PropagateBaselineFromChild(
    const PhysicalBoxFragment& child,
    LayoutUnit block_offset) {
  LogicalBoxFragment fragment(GetConstraintSpace().GetWritingDirection(),
                              child);

  // The first-baseline is the highest first-baseline of all fragments.
  if (auto first_baseline = fragment.FirstBaseline()) {
    LayoutUnit baseline = std::min(
        block_offset + *first_baseline,
        container_builder_.FirstBaseline().value_or(LayoutUnit::Max()));
    container_builder_.SetFirstBaseline(baseline);
  }

  // The last-baseline is the lowest last-baseline of all fragments.
  if (auto last_baseline = fragment.LastBaseline()) {
    LayoutUnit baseline =
        std::max(block_offset + *last_baseline,
                 container_builder_.LastBaseline().value_or(LayoutUnit::Min()));
    container_builder_.SetLastBaseline(baseline);
  }
  container_builder_.SetUseLastBaselineForInlineBaseline();
}

LayoutUnit ColumnLayoutAlgorithm::ResolveColumnAutoBlockSize(
    const LogicalSize& column_size,
    LayoutUnit row_offset,
    LayoutUnit available_outer_space,
    const BlockBreakToken* child_break_token,
    bool balance_columns) {
  spanner_path_ = nullptr;
  return ResolveColumnAutoBlockSizeInternal(column_size, row_offset,
                                            available_outer_space,
                                            child_break_token, balance_columns);
}

LayoutUnit ColumnLayoutAlgorithm::ResolveColumnAutoBlockSizeInternal(
    const LogicalSize& column_size,
    LayoutUnit row_offset,
    LayoutUnit available_outer_space,
    const BlockBreakToken* child_break_token,
    bool balance_columns) {
  // To calculate a balanced column size for one row of columns, we need to
  // figure out how tall our content is. To do that we need to lay out. Create a
  // special constraint space for column balancing, without allowing soft
  // breaks. It will make us lay out all the multicol content as one single tall
  // strip (unless there are forced breaks). When we're done with this layout
  // pass, we can examine the result and calculate an ideal column block-size.
  ConstraintSpace space = CreateConstraintSpaceForBalancing(column_size);
  FragmentGeometry fragment_geometry =
      CalculateInitialFragmentGeometry(space, Node(), GetBreakToken());

  // A run of content without explicit (forced) breaks; i.e. the content portion
  // between two explicit breaks, between fragmentation context start and an
  // explicit break, between an explicit break and fragmentation context end,
  // or, in cases when there are no explicit breaks at all: between
  // fragmentation context start and end. We need to know where the explicit
  // breaks are, in order to figure out where the implicit breaks will end up,
  // so that we get the columns properly balanced. A content run starts out as
  // representing one single column, and we'll add as many additional implicit
  // breaks as needed into the content runs that are the tallest ones
  // (ColumnBlockSize()).
  struct ContentRun {
    ContentRun(LayoutUnit content_block_size)
        : content_block_size(content_block_size) {}

    // Return the column block-size that this content run would require,
    // considering the implicit breaks we have assumed so far.
    LayoutUnit ColumnBlockSize() const {
      // Some extra care is required for the division here. We want the
      // resulting LayoutUnit value to be large enough to prevent overflowing
      // columns. Use floating point to get higher precision than
      // LayoutUnit. Then convert it to a LayoutUnit, but round it up to the
      // nearest value that LayoutUnit is able to represent.
      return LayoutUnit::FromFloatCeil(
          float(content_block_size) / float(implicit_breaks_assumed_count + 1));
    }

    LayoutUnit content_block_size;

    // The number of implicit breaks assumed to exist in this content run.
    int implicit_breaks_assumed_count = 0;
  };

  class ContentRuns final {
   public:
    // When we have "inserted" (assumed) enough implicit column breaks, this
    // method returns the block-size of the tallest column.
    LayoutUnit TallestColumnBlockSize() const {
      return TallestRun()->ColumnBlockSize();
    }

    LayoutUnit TallestContentBlockSize() const {
      return tallest_content_block_size_;
    }

    void AddRun(LayoutUnit content_block_size) {
      runs_.emplace_back(content_block_size);
      tallest_content_block_size_ =
          std::max(tallest_content_block_size_, content_block_size);
    }

    void DistributeImplicitBreaks(int used_column_count) {
      for (int columns_found = runs_.size(); columns_found < used_column_count;
           ++columns_found) {
        // The tallest content run (with all assumed implicit breaks added so
        // far taken into account) is where we assume the next implicit break.
        ++TallestRun()->implicit_breaks_assumed_count;
      }
    }

   private:
    ContentRun* TallestRun() const {
      DCHECK(!runs_.empty());
      auto const it = std::max_element(
          runs_.begin(), runs_.end(),
          [](const ContentRun& run1, const ContentRun& run2) {
            return run1.ColumnBlockSize() < run2.ColumnBlockSize();
          });
      CHECK(it != runs_.end(), base::NotFatalUntil::M130);
      return const_cast<ContentRun*>(&*it);
    }

    Vector<ContentRun, 1> runs_;
    LayoutUnit tallest_content_block_size_;
  };

  // First split into content runs at explicit (forced) breaks.
  ContentRuns content_runs;
  const BlockBreakToken* break_token = child_break_token;
  tallest_unbreakable_block_size_ = LayoutUnit();
  int forced_break_count = 0;
  do {
    LayoutAlgorithmParams params(Node(), fragment_geometry, space, break_token);
    params.column_spanner_path = spanner_path_;
    BlockLayoutAlgorithm balancing_algorithm(params);
    balancing_algorithm.SetBoxType(PhysicalFragment::kColumnBox);
    const LayoutResult* result = balancing_algorithm.Layout();

    // This algorithm should never abort.
    DCHECK_EQ(result->Status(), LayoutResult::kSuccess);

    const auto& fragment =
        To<PhysicalBoxFragment>(result->GetPhysicalFragment());

    // Add a content run, as long as we have soft break opportunities. Ignore
    // content that's doomed to end up in overflowing columns (because of too
    // many forced breaks).
    if (forced_break_count < used_column_count_) {
      LayoutUnit column_block_size = BlockSizeForFragmentation(
          *result, GetConstraintSpace().GetWritingDirection());

      // Encompass the block-size of the (single-strip column) fragment, to
      // account for any trailing margins. We let them affect the column
      // block-size, for compatibility reasons, if nothing else. The initial
      // column balancing pass (i.e. here) is our opportunity to do that fairly
      // easily. But note that this doesn't guarantee that no margins will ever
      // get truncated. To avoid that we'd need to add some sort of mechanism
      // that is invoked in *every* column balancing layout pass, where we'd
      // essentially have to treat every margin as unbreakable (which kind of
      // sounds both bad and difficult).
      //
      // We might want to revisit this approach, if it's worth it: Maybe it's
      // better to not make any room at all for margins that might end up
      // getting truncated. After all, they don't really require any space, so
      // what we're doing currently might be seen as unnecessary (and slightly
      // unpredictable) column over-stretching.
      LogicalFragment logical_fragment(
          GetConstraintSpace().GetWritingDirection(), fragment);
      column_block_size =
          std::max(column_block_size, logical_fragment.BlockSize());
      content_runs.AddRun(column_block_size);
    }

    tallest_unbreakable_block_size_ = std::max(
        tallest_unbreakable_block_size_, result->TallestUnbreakableBlockSize());

    // Stop when we reach a spanner. That's where this row of columns will end.
    // When laying out a row of columns, we'll pass in the spanner path, so that
    // the block layout algorithms can tell whether a node contains the spanner.
    if (const auto* spanner_path = result->GetColumnSpannerPath()) {
      bool knew_about_spanner = !!spanner_path_;
      spanner_path_ = spanner_path;
      if (forced_break_count && !knew_about_spanner) {
        // We may incorrectly have entered parallel flows, because we didn't
        // know about the spanner. Try again.
        return ResolveColumnAutoBlockSizeInternal(
            column_size, row_offset, available_outer_space, child_break_token,
            balance_columns);
      }
      break;
    }

    if (result->HasForcedBreak())
      forced_break_count++;

    break_token = fragment.GetBreakToken();
  } while (break_token);

  if (GetConstraintSpace().IsInitialColumnBalancingPass()) {
    // Nested column balancing. Our outer fragmentation context is in its
    // initial balancing pass, so it also wants to know the largest unbreakable
    // block-size.
    container_builder_.PropagateTallestUnbreakableBlockSize(
        tallest_unbreakable_block_size_);
  }

  // We now have an estimated minimal block-size for the columns. Roughly
  // speaking, this is the block-size that the columns will need if we are
  // allowed to break freely at any offset. This is normally not the case,
  // though, since there will typically be unbreakable pieces of content, such
  // as replaced content, lines of text, and other things. We need to actually
  // lay out into columns to figure out if they are tall enough or not (and
  // stretch and retry if not). Also honor {,min-,max-}block-size properties
  // before returning, and also try to not become shorter than the tallest piece
  // of unbreakable content.
  if (tallest_unbreakable_block_size_ >=
      content_runs.TallestContentBlockSize()) {
    return ConstrainColumnBlockSize(tallest_unbreakable_block_size_, row_offset,
                                    available_outer_space);
  }

  if (balance_columns) {
    // We should create as many columns as specified by column-count.
    content_runs.DistributeImplicitBreaks(used_column_count_);
  }
  return ConstrainColumnBlockSize(content_runs.TallestColumnBlockSize(),
                                  row_offset, available_outer_space);
}

// Constrain a balanced column block size to not overflow the multicol
// container.
LayoutUnit ColumnLayoutAlgorithm::ConstrainColumnBlockSize(
    LayoutUnit size,
    LayoutUnit row_offset,
    LayoutUnit available_outer_space) const {
  // Avoid becoming shorter than the tallest piece of unbreakable content.
  size = std::max(size, tallest_unbreakable_block_size_);

  if (is_constrained_by_outer_fragmentation_context_) {
    // Don't become too tall to fit in the outer fragmentation context.
    size = std::min(size, available_outer_space.ClampNegativeToZero());
  }

  const ConstraintSpace& space = GetConstraintSpace();
  const ComputedStyle& style = Style();

  // Table-cell sizing is special. The aspects of specified block-size (and its
  // min/max variants) that are actually honored by table cells is taken care of
  // in the table layout algorithm. A constraint space with fixed block-size
  // will be passed from the table layout algorithm if necessary. Leave it
  // alone.
  if (space.IsTableCell()) {
    return size;
  }

  // The {,min-,max-}block-size properties are specified on the multicol
  // container, but here we're calculating the column block sizes inside the
  // multicol container, which isn't exactly the same. We may shrink the column
  // block size here, but we'll never stretch them, because the value passed is
  // the perfect balanced block size. Making it taller would only disrupt the
  // balanced output, for no reason. The only thing we need to worry about here
  // is to not overflow the multicol container.
  //
  // First of all we need to convert the size to a value that can be compared
  // against the resolved properties on the multicol container. That means that
  // we have to convert the value from content-box to border-box.
  LayoutUnit extra = BorderScrollbarPadding().BlockSum();
  size += extra;

  LayoutUnit max = ResolveInitialMaxBlockLength(space, style, BorderPadding(),
                                                style.LogicalMaxHeight());
  LayoutUnit extent = kIndefiniteSize;

  const Length& block_length = style.LogicalHeight();
  const Length& auto_length = space.IsBlockAutoBehaviorStretch()
                                  ? Length::Stretch()
                                  : Length::FitContent();

  extent = ResolveMainBlockLength(space, style, BorderPadding(), block_length,
                           
"""


```